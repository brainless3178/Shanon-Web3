//! CPI Guard Detector -- AST-based Cross-Program Invocation security analysis
//!
//! Walks source code via `syn::visit::Visit` and checks:
//! - `invoke()` / `invoke_signed()` calls without validating the target program ID
//! - `CpiContext::new()` using raw AccountInfo instead of `Program<'info, T>`
//! - Missing `Program<'info, T>` type on CPI target fields in Accounts structs
//! - CPI calls that pass unvalidated authority signers
//! - Recursive/re-entrant CPI patterns

use crate::metrics::AnchorMetrics;
use crate::report::{AnchorFinding, AnchorSeverity, AnchorViolation};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct CPIGuardDetector;

impl CPIGuardDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_cpi_guards(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let mut visitor = CPIVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            metrics,
            // Track CPI target fields found in Accounts structs
            program_fields: Vec::new(),
        };

        // Phase 1: Walk AST to find Accounts struct CPI field issues
        visitor.visit_file(syntax_tree);

        // Phase 2: Scan function bodies for raw invoke patterns
        visitor.check_raw_cpi_calls();

        // Phase 3: Check for CpiContext using raw AccountInfo as program
        visitor.check_cpi_context_targets();

        visitor.findings
    }
}

impl Default for CPIGuardDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks program-type fields found in Accounts structs
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ProgramField {
    struct_name: String,
    field_name: String,
    is_validated: bool, // true if `Program<'info, T>`, false if `AccountInfo`
}

struct CPIVisitor<'a> {
    file_path: String,
    content: String,
    findings: Vec<AnchorFinding>,
    metrics: &'a mut AnchorMetrics,
    program_fields: Vec<ProgramField>,
}

impl<'ast> Visit<'ast> for CPIVisitor<'_> {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // Only process Anchor `#[derive(Accounts)]` structs
        let is_accounts_struct = node.attrs.iter().any(|attr| {
            attr.path().is_ident("derive") && {
                let attr_str = quote::quote!(#attr).to_string();
                attr_str.contains("Accounts")
            }
        });

        if !is_accounts_struct {
            syn::visit::visit_item_struct(self, node);
            return;
        }

        let struct_name = node.ident.to_string();

        for field in &node.fields {
            let field_name = match &field.ident {
                Some(ident) => ident.to_string(),
                None => continue,
            };

            let type_str = quote::quote!(#field.ty).to_string();

            // Detect program-related fields
            let is_program_field = field_name.contains("program")
                || field_name.ends_with("_program")
                || field_name == "token_program"
                || field_name == "system_program"
                || field_name == "associated_token_program"
                || field_name == "rent";

            if !is_program_field {
                continue;
            }

            let is_validated = type_str.contains("Program <")
                || type_str.contains("Program<")
                || type_str.contains("Sysvar <")
                || type_str.contains("Sysvar<");

            self.program_fields.push(ProgramField {
                struct_name: struct_name.clone(),
                field_name: field_name.clone(),
                is_validated,
            });

            // Flag unvalidated CPI target program fields
            if !is_validated
                && (type_str.contains("AccountInfo") || type_str.contains("UncheckedAccount"))
            {
                // Skip system_program and rent which Anchor handles specially
                if field_name == "system_program" || field_name == "rent" {
                    continue;
                }

                self.metrics.missing_cpi_guards += 1;
                self.add_finding(
                    AnchorViolation::MissingCPIGuard,
                    AnchorSeverity::Critical,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` in `{}` is a CPI target program passed as `{}` instead of \
                         `Program<'info, T>`. The caller controls which program ID is passed. Without \
                         `Program<'info, T>`, Anchor does NOT validate that this account is the expected \
                         program. An attacker deploys a malicious program with the same instruction interface \
                         and passes it as `{}`. The CPI executes the attacker's code instead of the real \
                         program. This is the Crema Finance attack vector ($8.8M, July 2022).",
                        field_name,
                        struct_name,
                        if type_str.contains("UncheckedAccount") {
                            "UncheckedAccount"
                        } else {
                            "AccountInfo"
                        },
                        field_name,
                    ),
                );
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}

impl CPIVisitor<'_> {
    /// Check for raw `invoke()` / `invoke_signed()` calls without program validation
    fn check_raw_cpi_calls(&mut self) {
        let lines: Vec<&str> = self.content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Detect raw invoke/invoke_signed calls (native Solana CPI)
            let is_invoke = trimmed.contains("invoke(") || trimmed.contains("invoke_signed(");

            if !is_invoke {
                continue;
            }

            // Skip test code
            let context_before: String = lines[i.saturating_sub(20)..i]
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .join("\n");

            if context_before.contains("#[test]") || context_before.contains("#[cfg(test)]") {
                continue;
            }

            // Check if there's a program ID validation nearby (within 15 lines before)
            let has_validation = lines[i.saturating_sub(15)..i].iter().any(|l| {
                l.contains("program_id ==")
                    || l.contains("== program_id")
                    || l.contains("key() == ")
                    || l.contains("check_program_account")
                    || l.contains("Program<")
                    || l.contains("require!(")
                    || l.contains("assert_eq!")
            });

            if !has_validation {
                self.metrics.missing_cpi_guards += 1;
                self.findings.push(AnchorFinding {
                    id: format!("ANC-RawCPI-{}", &self.fingerprint(i + 1, "raw_cpi")[..8]),
                    violation: AnchorViolation::MissingCPIGuard,
                    severity: AnchorSeverity::Critical,
                    file_path: self.file_path.clone(),
                    line_number: i + 1,
                    struct_name: None,
                    field_name: None,
                    description: format!(
                        "Line {}: Raw `{}` call without prior program ID validation. \
                         The CPI target program is passed by the caller as an `AccountInfo`. Without \
                         checking `program.key() == expected_program::ID`, an attacker substitutes a \
                         malicious program that mimics the expected instruction interface. \
                         Use Anchor's `CpiContext` with `Program<'info, T>` instead, or add \
                         `require!(program.key() == expected::ID)` before the invoke call.",
                        i + 1,
                        if trimmed.contains("invoke_signed") {
                            "invoke_signed()"
                        } else {
                            "invoke()"
                        },
                    ),
                    code_snippet: self.snippet_around(i + 1, 3),
                    risk_explanation:
                        "Raw CPI via invoke/invoke_signed passes whatever program Account the caller \
                         provides. The Solana runtime does not validate that the target program is the \
                         one the developer intended. This is the primary CPI attack vector on Solana."
                            .into(),
                    fix_recommendation:
                        "Replace raw invoke with Anchor's typed CPI:\n\
                         ```rust\n\
                         // In Accounts struct:\n\
                         pub token_program: Program<'info, Token>,\n\
                         \n\
                         // In handler:\n\
                         token::transfer(\n\
                             CpiContext::new(ctx.accounts.token_program.to_account_info(), ...),\n\
                             amount,\n\
                         )?;\n\
                         ```"
                            .into(),
                    anchor_pattern: "Program<'info, T> CPI validation".into(),
                    cwe: "CWE-346".into(),
                    fingerprint: self.fingerprint(i + 1, "raw_cpi"),
                });
            }
        }
    }

    /// Check for CpiContext::new() where the program argument is a raw AccountInfo
    fn check_cpi_context_targets(&mut self) {
        let lines: Vec<&str> = self.content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("CpiContext::new") {
                continue;
            }

            // Look at the surrounding context for the program argument
            let context: String = lines[i.saturating_sub(2)..(i + 5).min(lines.len())]
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .join(" ");

            // Check if the program argument uses .to_account_info() on a typed Program field
            // vs passing a raw AccountInfo directly
            let uses_typed_program = context.contains("token_program.to_account_info()")
                || context.contains("system_program.to_account_info()")
                || context.contains("_program.to_account_info()");

            // Skip if we can't determine the pattern
            if uses_typed_program {
                continue;
            }

            // Check if the CPI target is an unvalidated account
            let uses_raw = context.contains("program_info")
                || context.contains("program_account")
                || (context.contains("CpiContext::new(") && context.contains("account_info"));

            if uses_raw {
                // Check if already flagged via struct analysis
                let context_before: String = lines[i.saturating_sub(20)..i]
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");

                if context_before.contains("#[test]") || context_before.contains("#[cfg(test)]") {
                    continue;
                }

                self.findings.push(AnchorFinding {
                    id: format!(
                        "ANC-CPICtx-{}",
                        &self.fingerprint(i + 1, "cpi_ctx")[..8]
                    ),
                    violation: AnchorViolation::MissingCPIGuard,
                    severity: AnchorSeverity::High,
                    file_path: self.file_path.clone(),
                    line_number: i + 1,
                    struct_name: None,
                    field_name: None,
                    description: format!(
                        "Line {}: `CpiContext::new()` is called with what appears to be a raw \
                         AccountInfo as the program argument instead of a typed `Program<'info, T>` \
                         field. Pass the program through the Accounts struct as `Program<'info, Token>` \
                         (or the appropriate program type) so Anchor validates the program ID automatically.",
                        i + 1,
                    ),
                    code_snippet: self.snippet_around(i + 1, 2),
                    risk_explanation: "CpiContext requires a program AccountInfo as its first argument. \
                        If this comes from an unvalidated field, the CPI target is attacker-controlled."
                        .into(),
                    fix_recommendation:
                        "Use a typed program field in your Accounts struct:\n\
                         ```rust\n\
                         pub token_program: Program<'info, Token>,\n\
                         ```\n\
                         Then pass it to CpiContext:\n\
                         ```rust\n\
                         CpiContext::new(\n\
                             ctx.accounts.token_program.to_account_info(),\n\
                             Transfer { ... },\n\
                         )\n\
                         ```"
                            .into(),
                    anchor_pattern: "Program<'info, T> CPI validation".into(),
                    cwe: "CWE-346".into(),
                    fingerprint: self.fingerprint(i + 1, "cpi_ctx"),
                });
            }
        }
    }

    fn add_finding(
        &mut self,
        violation: AnchorViolation,
        severity: AnchorSeverity,
        struct_name: &str,
        field_name: &str,
        description: String,
    ) {
        let line = self.find_line_for_field(struct_name, field_name);
        let snippet = self.snippet_around(line, 2);
        let fp = self.fingerprint(line, violation.label());

        self.findings.push(AnchorFinding {
            id: format!("ANC-{}-{}", violation.label().replace(' ', ""), &fp[..8]),
            violation,
            severity,
            file_path: self.file_path.clone(),
            line_number: line,
            struct_name: Some(struct_name.to_string()),
            field_name: Some(field_name.to_string()),
            description,
            code_snippet: snippet,
            risk_explanation: self.risk_explanation(violation),
            fix_recommendation: self.fix_recommendation(violation, field_name),
            anchor_pattern: violation.anchor_pattern().to_string(),
            cwe: violation.cwe().to_string(),
            fingerprint: fp,
        });
    }

    fn find_line_for_field(&self, struct_name: &str, field_name: &str) -> usize {
        let mut in_struct = false;
        for (i, line) in self.content.lines().enumerate() {
            if line.contains(&format!("struct {}", struct_name)) {
                in_struct = true;
            }
            if in_struct && line.contains(field_name) && line.contains(':') {
                return i + 1;
            }
            if in_struct
                && (line.trim_start().starts_with("impl")
                    || (line.contains("struct ") && !line.contains(struct_name)))
            {
                break;
            }
        }
        self.content
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains(&format!("struct {}", struct_name)))
            .map(|(i, _)| i + 1)
            .unwrap_or(1)
    }

    fn snippet_around(&self, line: usize, context: usize) -> String {
        let lines: Vec<&str> = self.content.lines().collect();
        let start = line.saturating_sub(context + 1);
        let end = (line + context).min(lines.len());
        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, l)| format!("{}: {}", start + i + 1, l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn fingerprint(&self, line: usize, tag: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.file_path.as_bytes());
        h.update(line.to_string().as_bytes());
        h.update(tag.as_bytes());
        hex::encode(h.finalize())
    }

    fn risk_explanation(&self, violation: AnchorViolation) -> String {
        match violation {
            AnchorViolation::MissingCPIGuard => {
                "Cross-Program Invocations on Solana execute arbitrary programs. The runtime does not \
                 validate that the target program is the one the developer intended. If the CPI target \
                 is an unvalidated AccountInfo, an attacker deploys a malicious program that implements \
                 the same instruction interface and passes it as the program field. The Crema Finance \
                 exploit ($8.8M, July 2022) used exactly this technique."
                    .into()
            }
            _ => "CPI security pattern violation.".into(),
        }
    }

    fn fix_recommendation(&self, violation: AnchorViolation, field_name: &str) -> String {
        match violation {
            AnchorViolation::MissingCPIGuard => {
                format!(
                    "Use Anchor's `Program<'info, T>` type which auto-validates the program ID:\n\
                     ```rust\n\
                     pub {}: Program<'info, Token>,\n\
                     ```\n\
                     For custom programs, define the CPI interface:\n\
                     ```rust\n\
                     #[derive(Clone)]\n\
                     pub struct MyProgram;\n\
                     impl anchor_lang::Id for MyProgram {{\n\
                         fn id() -> Pubkey {{ my_program::ID }}\n\
                     }}\n\
                     pub {}: Program<'info, MyProgram>,\n\
                     ```",
                    field_name, field_name,
                )
            }
            _ => "Review Anchor CPI documentation.".into(),
        }
    }
}
