//! Unsafe Block & Function Detector
//!
//! Uses syn AST visitor to walk the entire file and identify:
//! - `unsafe { ... }` expression blocks
//! - `unsafe fn name(...)` function declarations
//! - `unsafe impl Trait for T` trait implementation blocks
//! - `union` type declarations
//! - inline `asm!` / `global_asm!` macro invocations
//!
//! For each finding it records the enclosing function, line number,
//! code snippet, and checks for a `// SAFETY:` justification comment.

use crate::metrics::UnsafeMetrics;
use crate::report::{GeigerFinding, GeigerSeverity, UnsafeCategory};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct UnsafeDetector;

impl UnsafeDetector {
    pub fn new() -> Self {
        Self
    }

    /// Walk the syn AST and collect all unsafe-related findings.
    pub fn detect_unsafe_blocks(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut UnsafeMetrics,
    ) -> Vec<GeigerFinding> {
        let mut visitor = UnsafeVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            current_fn: None,
        };

        visitor.visit_file(syntax_tree);

        // Update metrics
        for f in &visitor.findings {
            match f.category {
                UnsafeCategory::UnsafeBlock => metrics.unsafe_blocks += 1,
                UnsafeCategory::UnsafeFunction => metrics.unsafe_functions += 1,
                UnsafeCategory::UnsafeTrait => metrics.unsafe_traits += 1,
                UnsafeCategory::UnionType => metrics.union_types += 1,
                UnsafeCategory::InlineAssembly => metrics.asm_blocks += 1,
                _ => {}
            }
        }

        visitor.findings
    }
}

impl Default for UnsafeDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── helpers ────────────────────────────────────────────────────────────

fn line_number_of(content: &str, target_line_text: &str) -> usize {
    for (idx, line) in content.lines().enumerate() {
        if line.contains(target_line_text) {
            return idx + 1;
        }
    }
    1
}

fn snippet_at(content: &str, line_1based: usize) -> String {
    content
        .lines()
        .nth(line_1based.saturating_sub(1))
        .map(|l| format!("{}: {}", line_1based, l))
        .unwrap_or_default()
}

fn safety_comment_near(content: &str, line_1based: usize) -> Option<String> {
    // Look at the 3 lines above the target for a // SAFETY: comment
    let lines: Vec<&str> = content.lines().collect();
    let start = line_1based.saturating_sub(4);
    let end = line_1based.saturating_sub(1);
    for i in start..end {
        if let Some(l) = lines.get(i) {
            let trimmed = l.trim();
            if trimmed.starts_with("// SAFETY:") || trimmed.starts_with("/// SAFETY:") {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn fingerprint(file: &str, line: usize, cat: &UnsafeCategory) -> String {
    let mut h = Sha256::new();
    h.update(file.as_bytes());
    h.update(line.to_string().as_bytes());
    h.update(cat.label().as_bytes());
    hex::encode(h.finalize())
}

// ─── visitor ────────────────────────────────────────────────────────────

struct UnsafeVisitor {
    file_path: String,
    content: String,
    findings: Vec<GeigerFinding>,
    current_fn: Option<String>,
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    // Track function context
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let fn_name = node.sig.ident.to_string();

        // Detect `unsafe fn`
        if node.sig.unsafety.is_some() {
            let line = line_number_of(&self.content, &format!("unsafe fn {}", fn_name));
            let snip = snippet_at(&self.content, line);
            let justification = safety_comment_near(&self.content, line);
            let fp = fingerprint(&self.file_path, line, &UnsafeCategory::UnsafeFunction);

            let severity = if justification.is_some() {
                GeigerSeverity::Medium
            } else {
                GeigerSeverity::High
            };

            self.findings.push(GeigerFinding {
                id: format!("GEI-UFUNC-{}", &fp[..8]),
                category: UnsafeCategory::UnsafeFunction,
                severity,
                file_path: self.file_path.clone(),
                line_number: line,
                function_name: Some(fn_name.clone()),
                description: format!(
                    "Unsafe function '{}' bypasses Rust's safety guarantees. \
                     Callers must uphold invariants manually, making it a \
                     high-risk surface in auditable Solana code.",
                    fn_name,
                ),
                unsafe_code_snippet: snip,
                risk_explanation: "Unsafe functions propagate unsafety to every call-site. \
                    A single incorrect caller can cause UB, memory corruption, or \
                    exploitable state."
                    .into(),
                fix_recommendation: "Wrap the unsafe internals in a safe public API \
                    that validates all preconditions. Document invariants with \
                    `// SAFETY:` comments."
                    .into(),
                cwe: UnsafeCategory::UnsafeFunction.cwe().into(),
                fingerprint: fp,
                justification_comment: justification,
            });
        }

        let prev = self.current_fn.take();
        self.current_fn = Some(fn_name);
        syn::visit::visit_item_fn(self, node);
        self.current_fn = prev;
    }

    // Detect `unsafe { ... }` expression blocks
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        let search = "unsafe {";
        let line = line_number_of(&self.content, search);
        let snip = snippet_at(&self.content, line);
        let justification = safety_comment_near(&self.content, line);
        let fp = fingerprint(&self.file_path, line, &UnsafeCategory::UnsafeBlock);

        let has_solana_specific = snip.contains("invoke")
            || snip.contains("sol_memcpy")
            || snip.contains("sol_memset")
            || snip.contains("AccountInfo")
            || snip.contains("from_raw_parts");

        let severity = match (has_solana_specific, justification.is_some()) {
            (true, false) => GeigerSeverity::Critical,
            (true, true) => GeigerSeverity::High,
            (false, false) => GeigerSeverity::High,
            (false, true) => GeigerSeverity::Medium,
        };

        let fn_ctx = self.current_fn.clone().unwrap_or("(top-level)".into());

        self.findings.push(GeigerFinding {
            id: format!("GEI-UBLK-{}", &fp[..8]),
            category: UnsafeCategory::UnsafeBlock,
            severity,
            file_path: self.file_path.clone(),
            line_number: line,
            function_name: Some(fn_ctx.clone()),
            description: format!(
                "Unsafe block in function '{}' disables borrow-checker and \
                 type-safety protections. {}",
                fn_ctx,
                if has_solana_specific {
                    "This block touches Solana runtime primitives, amplifying \
                     the blast radius of any memory error."
                } else {
                    "Any bug inside this block can cause undefined behavior."
                }
            ),
            unsafe_code_snippet: snip,
            risk_explanation: "Unsafe blocks opt out of Rust's safety model. \
                In Solana programs, a single UB can be weaponized to drain \
                program vaults or forge account state."
                .into(),
            fix_recommendation: "Minimize the scope of the unsafe block to the \
                smallest possible expression. Add a `// SAFETY:` comment \
                explaining why each operation is sound."
                .into(),
            cwe: UnsafeCategory::UnsafeBlock.cwe().into(),
            fingerprint: fp,
            justification_comment: justification,
        });

        syn::visit::visit_expr_unsafe(self, node);
    }

    // Detect `unsafe impl SomeTrait for T`
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.unsafety.is_some() {
            let trait_name = node
                .trait_
                .as_ref()
                .map(|(_, path, _)| {
                    path.segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::")
                })
                .unwrap_or_else(|| "(anonymous)".into());

            let search = "unsafe impl";
            let line = line_number_of(&self.content, search);
            let snip = snippet_at(&self.content, line);
            let justification = safety_comment_near(&self.content, line);
            let fp = fingerprint(&self.file_path, line, &UnsafeCategory::UnsafeTrait);

            self.findings.push(GeigerFinding {
                id: format!("GEI-UTRT-{}", &fp[..8]),
                category: UnsafeCategory::UnsafeTrait,
                severity: GeigerSeverity::High,
                file_path: self.file_path.clone(),
                line_number: line,
                function_name: None,
                description: format!(
                    "Unsafe trait implementation '{}'. The implementer asserts \
                     invariants the compiler cannot verify.",
                    trait_name,
                ),
                unsafe_code_snippet: snip,
                risk_explanation: "Unsafe trait impls are contracts between the \
                    implementor and consumers. A broken invariant propagates \
                    unsafety across the crate."
                    .into(),
                fix_recommendation: "Verify that all trait safety requirements \
                    are satisfied. Add `// SAFETY:` comments per method. \
                    Consider if a safe abstraction is possible."
                    .into(),
                cwe: UnsafeCategory::UnsafeTrait.cwe().into(),
                fingerprint: fp,
                justification_comment: justification,
            });
        }

        syn::visit::visit_item_impl(self, node);
    }

    // Detect `union` types
    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        let name = node.ident.to_string();
        let line = line_number_of(&self.content, &format!("union {}", name));
        let snip = snippet_at(&self.content, line);
        let fp = fingerprint(&self.file_path, line, &UnsafeCategory::UnionType);

        self.findings.push(GeigerFinding {
            id: format!("GEI-UNION-{}", &fp[..8]),
            category: UnsafeCategory::UnionType,
            severity: GeigerSeverity::High,
            file_path: self.file_path.clone(),
            line_number: line,
            function_name: None,
            description: format!(
                "Union type '{}' allows reinterpreting memory without type \
                 checks. Reading the wrong variant is instant UB.",
                name,
            ),
            unsafe_code_snippet: snip,
            risk_explanation: "Unions in Rust are inherently unsafe to read. \
                An attacker who controls which variant is written can \
                exploit a misread as a type confusion vulnerability."
                .into(),
            fix_recommendation: "Replace with an enum if possible. If the \
                union is required for FFI, wrap access in a safe API that \
                tracks the active variant."
                .into(),
            cwe: UnsafeCategory::UnionType.cwe().into(),
            fingerprint: fp,
            justification_comment: None,
        });

        syn::visit::visit_item_union(self, node);
    }

    // Detect asm!() and global_asm!() invocations
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let macro_name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();

        if macro_name == "asm" || macro_name == "global_asm" {
            let line = line_number_of(&self.content, &format!("{}!", macro_name));
            let snip = snippet_at(&self.content, line);
            let fp = fingerprint(&self.file_path, line, &UnsafeCategory::InlineAssembly);

            self.findings.push(GeigerFinding {
                id: format!("GEI-ASM-{}", &fp[..8]),
                category: UnsafeCategory::InlineAssembly,
                severity: GeigerSeverity::Critical,
                file_path: self.file_path.clone(),
                line_number: line,
                function_name: self.current_fn.clone(),
                description: format!(
                    "Inline assembly macro '{0}!' detected. Assembly bypasses \
                     all Rust safety checks and is extremely difficult to audit.",
                    macro_name,
                ),
                unsafe_code_snippet: snip,
                risk_explanation: "Inline assembly operates outside the Rust \
                    abstract machine. It can corrupt registers, violate ABI \
                    contracts, and introduce architecture-specific UB."
                    .into(),
                fix_recommendation: "Replace with safe Rust intrinsics or \
                    well-tested FFI wrappers. If asm is unavoidable, add \
                    exhaustive `// SAFETY:` documentation and unit tests."
                    .into(),
                cwe: UnsafeCategory::InlineAssembly.cwe().into(),
                fingerprint: fp,
                justification_comment: safety_comment_near(&self.content, line),
            });
        }

        syn::visit::visit_macro(self, node);
    }
}
