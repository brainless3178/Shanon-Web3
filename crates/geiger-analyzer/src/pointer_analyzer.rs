//! Raw Pointer Analyzer
//!
//! Scans source code for raw pointer declarations (`*const T`, `*mut T`),
//! unsafe dereferences (`*ptr`), pointer arithmetic (`ptr.add()`, `ptr.offset()`),
//! null pointer patterns, and slice-from-raw-parts constructions.
//!
//! Raw pointers are the single largest class of memory-safety bugs in
//! production Solana programs because they are used extensively in the
//! `solana_program` runtime for zero-copy deserialization.

use crate::metrics::UnsafeMetrics;
use crate::report::{GeigerFinding, GeigerSeverity, UnsafeCategory};
use sha2::{Digest, Sha256};

pub struct PointerAnalyzer;

/// Each regex pattern, its category, severity, description template, and
/// risk/fix text.
struct RawPtrRule {
    regex: &'static str,
    category: UnsafeCategory,
    severity: GeigerSeverity,
    desc: &'static str,
    risk: &'static str,
    fix: &'static str,
}

static RULES: &[RawPtrRule] = &[
    RawPtrRule {
        regex: r"\*const\s+\w+",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::High,
        desc: "Raw immutable pointer (*const T) detected. \
               Dereferencing requires unsafe and bypasses borrow rules.",
        risk: "Raw const pointers can alias mutable references, \
               violating Rust's aliasing model and enabling data races.",
        fix: "Use references (&T) or Pin<&T> unless FFI requires \
              a raw pointer. Wrap in NonNull for null-safety.",
    },
    RawPtrRule {
        regex: r"\*mut\s+\w+",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::Critical,
        desc: "Raw mutable pointer (*mut T) detected. This can \
               alias any data and modify it without borrow checking.",
        risk: "A *mut pointer can write to any memory location, \
               enabling arbitrary state corruption in Solana accounts.",
        fix: "Replace with &mut T behind a safe API. If unavoidable, \
              document aliasing constraints with // SAFETY: comments.",
    },
    RawPtrRule {
        regex: r"\.as_ptr\(\)",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::Medium,
        desc: "Conversion to raw pointer via .as_ptr(). The resulting \
               pointer is only valid while the source is alive.",
        risk: "use-after-free if the source (Vec, slice, String) is \
               dropped while the raw pointer is still in use.",
        fix: "Ensure the source outlives all uses of the pointer. \
              Prefer passing slices directly.",
    },
    RawPtrRule {
        regex: r"\.as_mut_ptr\(\)",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::High,
        desc: "Conversion to raw mutable pointer via .as_mut_ptr(). \
               Can invalidate existing references.",
        risk: "Mutable pointer aliases break Rust's exclusivity \
               guarantee, leading to undefined behavior.",
        fix: "Limit scope; do not hold any &/&mut references while \
              the raw pointer is live.",
    },
    RawPtrRule {
        regex: r"\.offset\(",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::Critical,
        desc: "Pointer arithmetic via .offset(). Out-of-bounds \
               offset is instant undefined behavior.",
        risk: "An attacker-controlled offset can read/write \
               arbitrary memory in the BPF VM, enabling account \
               data forgery.",
        fix: "Use checked indexing on slices instead. If offset \
              is required, bounds-check against known allocation size.",
    },
    RawPtrRule {
        regex: r"\.add\(",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::High,
        desc: "Pointer advance via .add(). Same risks as .offset() \
               but unsigned.",
        risk: "Unsigned wrapping can silently wrap past allocation \
               boundaries in the BPF address space.",
        fix: "Prefer slice indexing. Guard with explicit bounds \
              check before calling .add().",
    },
    RawPtrRule {
        regex: r"from_raw_parts(_mut)?\(",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::Critical,
        desc: "slice::from_raw_parts — constructs a slice from a \
               raw pointer and length. This is the most common root \
               cause of Solana zero-copy deserialization bugs.",
        risk: "Incorrect length or misaligned pointer creates a \
               slice that reads garbage or crosses account boundaries.",
        fix: "Validate pointer alignment with .is_aligned(). \
              Assert that len ≤ remaining allocation. Use \
              bytemuck::try_from_bytes for safe zero-copy.",
    },
    RawPtrRule {
        regex: r"null\(\)|null_mut\(\)",
        category: UnsafeCategory::RawPointer,
        severity: GeigerSeverity::Medium,
        desc: "Null pointer construction. Dereferencing a null \
               pointer is undefined behavior.",
        risk: "If a null raw pointer is later dereferenced inside \
               an unsafe block, the BPF VM will abort the tx.",
        fix: "Use Option<NonNull<T>> to encode nullability in the \
              type system.",
    },
    RawPtrRule {
        regex: r"ptr::read(_volatile)?\(",
        category: UnsafeCategory::UnsafeDeref,
        severity: GeigerSeverity::High,
        desc: "ptr::read — performs a bitwise copy from a raw \
               pointer without checking validity.",
        risk: "Reading uninitialized or dangling memory yields \
               garbage that can pass downstream validation.",
        fix: "Ensure the pointer is valid, aligned, and initialized \
              before calling ptr::read.",
    },
    RawPtrRule {
        regex: r"ptr::write(_volatile)?\(",
        category: UnsafeCategory::UnsafeDeref,
        severity: GeigerSeverity::Critical,
        desc: "ptr::write — writes to a raw pointer location. \
               This can overwrite any account data.",
        risk: "An attacker who controls the destination pointer \
               can overwrite authority fields, token balances, \
               or program state.",
        fix: "Verify write destination is within the expected \
              account data range. Use typed struct writes instead.",
    },
];

impl PointerAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_pointers(
        &self,
        file_path: &str,
        _syntax_tree: &syn::File,
        content: &str,
        metrics: &mut UnsafeMetrics,
    ) -> Vec<GeigerFinding> {
        let mut findings = Vec::new();

        for rule in RULES {
            let re = match regex::Regex::new(rule.regex) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for (idx, line) in content.lines().enumerate() {
                // Skip comments
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                    continue;
                }

                if re.is_match(line) {
                    let line_num = idx + 1;
                    let hash = self.fingerprint(file_path, line_num, rule.regex);

                    metrics.raw_pointers += 1;

                    findings.push(GeigerFinding {
                        id: format!("GEI-PTR-{}", &hash[..8]),
                        category: rule.category,
                        severity: rule.severity,
                        file_path: file_path.to_string(),
                        line_number: line_num,
                        function_name: None,
                        description: rule.desc.to_string(),
                        unsafe_code_snippet: format!("{}: {}", line_num, line),
                        risk_explanation: rule.risk.to_string(),
                        fix_recommendation: rule.fix.to_string(),
                        cwe: rule.category.cwe().into(),
                        fingerprint: hash,
                        justification_comment: self.find_safety_comment(content, line_num),
                    });
                }
            }
        }

        findings
    }

    fn find_safety_comment(&self, content: &str, line: usize) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();
        for i in line.saturating_sub(4)..line.saturating_sub(1) {
            if let Some(l) = lines.get(i) {
                let t = l.trim();
                if t.starts_with("// SAFETY:") || t.starts_with("/// SAFETY:") {
                    return Some(t.to_string());
                }
            }
        }
        None
    }

    fn fingerprint(&self, file: &str, line: usize, tag: &str) -> String {
        let mut h = Sha256::new();
        h.update(file.as_bytes());
        h.update(line.to_string().as_bytes());
        h.update(tag.as_bytes());
        hex::encode(h.finalize())
    }
}

impl Default for PointerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
