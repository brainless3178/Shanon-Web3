//! FFI (Foreign Function Interface) Analyzer
//!
//! Detects `extern "C"` blocks, `extern "C" fn` declarations, and
//! `#[link]` or `#[no_mangle]` attributes that expose or consume
//! foreign code boundaries. FFI is the most common source of memory
//! safety violations in audited Solana programs because the compiler
//! cannot verify contracts across the language boundary.

use crate::metrics::UnsafeMetrics;
use crate::report::{GeigerFinding, GeigerSeverity, UnsafeCategory};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct FFIAnalyzer;

impl FFIAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_ffi(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut UnsafeMetrics,
    ) -> Vec<GeigerFinding> {
        let mut visitor = FFIVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
        };

        visitor.visit_file(syntax_tree);

        // Also do regex-based detection for patterns the AST pass can miss
        visitor.regex_scan();

        metrics.ffi_calls += visitor.findings.len();
        visitor.findings
    }
}

impl Default for FFIAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ───────────────────────────────────────────────────────────────────────

fn fp(file: &str, line: usize, tag: &str) -> String {
    let mut h = Sha256::new();
    h.update(file.as_bytes());
    h.update(line.to_string().as_bytes());
    h.update(tag.as_bytes());
    hex::encode(h.finalize())
}

fn snippet_at(content: &str, line: usize) -> String {
    content
        .lines()
        .nth(line.saturating_sub(1))
        .map(|l| format!("{}: {}", line, l))
        .unwrap_or_default()
}

struct FFIVisitor {
    file_path: String,
    content: String,
    findings: Vec<GeigerFinding>,
}

impl<'ast> Visit<'ast> for FFIVisitor {
    /// Detect `extern "C" { ... }` foreign blocks
    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let abi_name = node
            .abi
            .name
            .as_ref()
            .map(|n| n.value())
            .unwrap_or_else(|| "C".into());

        let line = self.find_line(&format!("extern \"{}\"", abi_name));
        let snip = snippet_at(&self.content, line);
        let hash = fp(&self.file_path, line, "ffi-block");

        let fn_count = node.items.len();

        self.findings.push(GeigerFinding {
            id: format!("GEI-FFI-{}", &hash[..8]),
            category: UnsafeCategory::FFICall,
            severity: GeigerSeverity::Critical,
            file_path: self.file_path.clone(),
            line_number: line,
            function_name: None,
            description: format!(
                "Foreign function block (ABI: \"{}\") declares {} symbol(s). \
                 Every call into this block is implicitly unsafe and cannot \
                 be verified by the Rust compiler.",
                abi_name, fn_count,
            ),
            unsafe_code_snippet: snip,
            risk_explanation: format!(
                "extern \"{}\" functions bypass Rust's type system and \
                 borrow checker. Incorrect argument types, lifetimes, or \
                 calling conventions can corrupt the BPF runtime stack \
                 on Solana validators.",
                abi_name,
            ),
            fix_recommendation: "Wrap each foreign function in a safe Rust \
                shim that validates arguments and return values. Use \
                `#[repr(C)]` structs and document ABI contracts."
                .into(),
            cwe: UnsafeCategory::FFICall.cwe().into(),
            fingerprint: hash,
            justification_comment: None,
        });

        syn::visit::visit_item_foreign_mod(self, node);
    }

    /// Detect `#[no_mangle] pub extern "C" fn ...`
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let has_no_mangle = node.attrs.iter().any(|a| a.path().is_ident("no_mangle"));
        let has_extern = node.sig.abi.is_some();

        if has_no_mangle || has_extern {
            let fn_name = node.sig.ident.to_string();
            let line = self.find_line(&fn_name);
            let snip = snippet_at(&self.content, line);
            let hash = fp(&self.file_path, line, "ffi-fn");

            let severity = if has_no_mangle && has_extern {
                GeigerSeverity::Critical
            } else {
                GeigerSeverity::High
            };

            self.findings.push(GeigerFinding {
                id: format!("GEI-FFIFN-{}", &hash[..8]),
                category: UnsafeCategory::FFICall,
                severity,
                file_path: self.file_path.clone(),
                line_number: line,
                function_name: Some(fn_name.clone()),
                description: format!(
                    "Function '{}' is exported across the FFI boundary{}{}. \
                     It is callable from C, BPF loader, or other untrusted contexts.",
                    fn_name,
                    if has_no_mangle {
                        " with #[no_mangle]"
                    } else {
                        ""
                    },
                    if has_extern { " and extern ABI" } else { "" },
                ),
                unsafe_code_snippet: snip,
                risk_explanation: "Functions exposed via FFI can be called with \
                    arbitrary arguments. In Solana, the BPF entrypoint is an \
                    FFI boundary — incorrect validation here is a root-cause \
                    of many historic exploits."
                    .into(),
                fix_recommendation: "Validate all pointer arguments for alignment \
                    and null. Bounds-check buffer lengths. Prefer \
                    `entrypoint!()` macro over raw `#[no_mangle]`."
                    .into(),
                cwe: UnsafeCategory::FFICall.cwe().into(),
                fingerprint: hash,
                justification_comment: None,
            });
        }

        syn::visit::visit_item_fn(self, node);
    }
}

impl FFIVisitor {
    fn find_line(&self, needle: &str) -> usize {
        for (i, line) in self.content.lines().enumerate() {
            if line.contains(needle) {
                return i + 1;
            }
        }
        1
    }

    /// Catch patterns that syn doesn't surface easily
    fn regex_scan(&mut self) {
        let patterns: &[(&str, &str, GeigerSeverity)] = &[
            (r#"#\[link\("#, "Dynamic library link attribute (#[link]) — loads native .so/.dll at runtime", GeigerSeverity::Critical),
            (r#"#\[link_name"#, "Symbol renaming (#[link_name]) — remaps to a C symbol, bypassing Rust name resolution", GeigerSeverity::High),
            (r#"extern\s+\"system\""#, "System ABI extern block — platform-dependent calling convention", GeigerSeverity::High),
        ];

        for (pattern, desc, severity) in patterns {
            let re = match regex::Regex::new(pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for (idx, line) in self.content.lines().enumerate() {
                if re.is_match(line) {
                    let line_num = idx + 1;
                    let hash = fp(&self.file_path, line_num, pattern);
                    self.findings.push(GeigerFinding {
                        id: format!("GEI-FFIRX-{}", &hash[..8]),
                        category: UnsafeCategory::FFICall,
                        severity: *severity,
                        file_path: self.file_path.clone(),
                        line_number: line_num,
                        function_name: None,
                        description: desc.to_string(),
                        unsafe_code_snippet: format!("{}: {}", line_num, line),
                        risk_explanation: "FFI attributes alter linker behavior and \
                            expose the program to native-code trust boundaries."
                            .into(),
                        fix_recommendation: "Audit the linked library for memory safety. \
                            Prefer pure-Rust alternatives where available."
                            .into(),
                        cwe: UnsafeCategory::FFICall.cwe().into(),
                        fingerprint: hash,
                        justification_comment: None,
                    });
                }
            }
        }
    }
}
