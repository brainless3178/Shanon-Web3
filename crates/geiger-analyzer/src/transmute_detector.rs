//! Transmute & Unsafe Cast Detector
//!
//! `std::mem::transmute` reinterprets the bit pattern of a value as a
//! completely different type.  It is the nuclear option of type coercion
//! and the #1 cause of type-confusion exploits in Rust.
//!
//! This module also catches related patterns:
//! - `transmute_copy`
//! - `MaybeUninit::assume_init`
//! - `from_raw` (Box, Arc, Rc, Vec, String)
//! - `as` casts between pointer types
//! - Zeroed memory usage (`MaybeUninit::zeroed().assume_init()`)

use crate::metrics::UnsafeMetrics;
use crate::report::{GeigerFinding, GeigerSeverity, UnsafeCategory};
use sha2::{Digest, Sha256};

pub struct TransmuteDetector;

struct TransmuteRule {
    regex: &'static str,
    severity: GeigerSeverity,
    desc: &'static str,
    risk: &'static str,
    fix: &'static str,
}

static TRANSMUTE_RULES: &[TransmuteRule] = &[
    TransmuteRule {
        regex: r"transmute\s*[:<(]",
        severity: GeigerSeverity::Critical,
        desc: "std::mem::transmute — reinterprets the bits of one type as \
               another with zero validation. Wrong source/target layout causes \
               instant undefined behavior.",
        risk: "In Solana programs, transmute is used to cast raw account data \
               into typed structs. An attacker who forges account data of the \
               wrong layout can corrupt the resulting struct fields (e.g. \
               authority pubkey, token amount, nonce).",
        fix: "Replace with bytemuck::try_from_bytes or \
              borsh::BorshDeserialize. If transmute is truly needed, assert \
              size_of::<Src>() == size_of::<Dst>() at compile time and \
              document the layout contract.",
    },
    TransmuteRule {
        regex: r"transmute_copy\s*[:<(]",
        severity: GeigerSeverity::Critical,
        desc: "std::mem::transmute_copy — like transmute but copies bytes \
               first. Allows transmuting between differently-sized types, \
               which is even more dangerous.",
        risk: "Size mismatch leads to partial reads or buffer overruns. \
               High-performance Solana serializers sometimes use this to \
               avoid allocation, but a single mistake leaks stack memory.",
        fix: "Use bytemuck::pod_read_unaligned or borsh deserialization. \
              Avoid transmute_copy entirely if possible.",
    },
    TransmuteRule {
        regex: r"assume_init\s*\(",
        severity: GeigerSeverity::Critical,
        desc: "MaybeUninit::assume_init — asserts that uninitialized memory \
               has been fully initialized. Calling this too early reads \
               garbage.",
        risk: "Uninitialized reads are UB. The optimizer may delete \
               subsequent checks, leading to silent corruption that only \
               manifests under specific validator configurations.",
        fix: "Use MaybeUninit::write() to initialize. After all fields are \
              written, call .assume_init() only once. Consider \
              MaybeUninit::zeroed() for types where zero is valid.",
    },
    TransmuteRule {
        regex: r"from_raw\s*\(",
        severity: GeigerSeverity::High,
        desc: "Constructing an owned type from a raw pointer (Box::from_raw, \
               Vec::from_raw_parts, etc.). The caller is responsible for \
               allocation validity and uniqueness.",
        risk: "Double-free or use-after-free if the raw pointer was already \
               owned by another container. In Solana, this can cause the \
               validator to crash or corrupt account state.",
        fix: "Prefer into_raw/from_raw round-trips within the same scope. \
              Document the ownership transfer with // SAFETY: comments.",
    },
    TransmuteRule {
        regex: r"into_raw\s*\(",
        severity: GeigerSeverity::Medium,
        desc: "Converting an owned value into a raw pointer (Box::into_raw, \
               Arc::into_raw). The pointer must eventually be reconstituted \
               or leaked.",
        risk: "Memory leak if the raw pointer is never passed back to \
               from_raw. In long-running Solana programs this is usually \
               harmless but can mask bugs.",
        fix: "Pair every into_raw with a corresponding from_raw. Track the \
              raw pointer lifetime explicitly.",
    },
    TransmuteRule {
        regex: r"zeroed\s*\(\)\s*\.\s*assume_init",
        severity: GeigerSeverity::High,
        desc: "MaybeUninit::zeroed().assume_init() — creates a zero-filled \
               value. Only valid for types where all-zeros is a valid bit \
               pattern (e.g. integers, arrays of integers).",
        risk: "All-zero is NOT valid for booleans (must be 0 or 1), enums, \
               references, or NonNull types. Solana Pubkey is safe (32 zero \
               bytes), but most custom structs are not.",
        fix: "Use bytemuck::Zeroable derive to statically prove the type \
              is safe to zero-initialize.",
    },
    TransmuteRule {
        regex: r"\bas\s+\*(?:const|mut)\s",
        severity: GeigerSeverity::High,
        desc: "Reference-to-raw-pointer cast via `as *const/*mut`. This is \
               safe by itself but signals intent to dereference unsafely.",
        risk: "The resulting pointer can outlive the reference, leading to \
               dangling pointer access.",
        fix: "Keep the raw pointer's lifetime strictly within the borrow \
              scope of the reference.",
    },
];

impl TransmuteDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_transmute(
        &self,
        file_path: &str,
        _syntax_tree: &syn::File,
        content: &str,
        metrics: &mut UnsafeMetrics,
    ) -> Vec<GeigerFinding> {
        let mut findings = Vec::new();

        for rule in TRANSMUTE_RULES {
            let re = match regex::Regex::new(rule.regex) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with("*")
                {
                    continue;
                }

                if re.is_match(line) {
                    let line_num = idx + 1;
                    let hash = self.fingerprint(file_path, line_num, rule.regex);

                    metrics.transmute_calls += 1;

                    findings.push(GeigerFinding {
                        id: format!("GEI-XMUT-{}", &hash[..8]),
                        category: UnsafeCategory::TransmuteCall,
                        severity: rule.severity,
                        file_path: file_path.to_string(),
                        line_number: line_num,
                        function_name: None,
                        description: rule.desc.to_string(),
                        unsafe_code_snippet: format!("{}: {}", line_num, line),
                        risk_explanation: rule.risk.to_string(),
                        fix_recommendation: rule.fix.to_string(),
                        cwe: UnsafeCategory::TransmuteCall.cwe().into(),
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

impl Default for TransmuteDetector {
    fn default() -> Self {
        Self::new()
    }
}
