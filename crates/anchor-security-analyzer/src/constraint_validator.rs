//! Account Constraint Validator
//!
//! Validates #[account(...)] attribute constraints in Anchor programs.
//! Walks `#[derive(Accounts)]` structs via `syn::visit::Visit` and checks:
//! - Missing owner constraints on data accounts (field uses raw AccountInfo instead of Account<T>)
//! - Weak constraint expressions lacking custom error codes
//! - `init` without `space` allocation
//! - `init_if_needed` reinitialization attack surface
//! - `close` without proper destination

use crate::metrics::AnchorMetrics;
use crate::report::{AnchorFinding, AnchorSeverity, AnchorViolation};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct ConstraintValidator;

impl ConstraintValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_constraints(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let mut visitor = ConstraintVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            metrics,
        };

        visitor.visit_file(syntax_tree);
        visitor.findings
    }
}

impl Default for ConstraintValidator {
    fn default() -> Self {
        Self::new()
    }
}

struct ConstraintVisitor<'a> {
    file_path: String,
    content: String,
    findings: Vec<AnchorFinding>,
    metrics: &'a mut AnchorMetrics,
}

impl<'ast> Visit<'ast> for ConstraintVisitor<'_> {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // Check if this is an Anchor Accounts struct
        let has_accounts_derive = node.attrs.iter().any(|attr| {
            attr.path().is_ident("derive") && {
                let attr_str = quote::quote!(#attr).to_string();
                attr_str.contains("Accounts")
            }
        });

        if !has_accounts_derive {
            syn::visit::visit_item_struct(self, node);
            return;
        }

        self.metrics.total_account_structs += 1;
        let struct_name = node.ident.to_string();

        // Check each field for proper constraints
        for field in &node.fields {
            let field_name = field
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default();

            let type_str = quote::quote!(#field.ty).to_string();

            // Check for account attributes
            let has_account_attr = field
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("account"));

            if !has_account_attr {
                continue;
            }

            // Extract constraint content from ALL #[account(...)] attributes
            let constraint_str: String = field
                .attrs
                .iter()
                .filter(|attr| attr.path().is_ident("account"))
                .map(|attr| quote::quote!(#attr).to_string())
                .collect::<Vec<_>>()
                .join(" ");

            // Check for missing owner check.
            // Only flag if the field uses raw AccountInfo or UncheckedAccount (not Account<T>
            // which auto-validates ownership). `quote!` tokenizes generics with spaces, so
            // check for both `Account <` and `Account<`.
            let uses_typed_account = type_str.contains("Account <")
                || type_str.contains("Account<")
                || type_str.contains("Program <")
                || type_str.contains("Program<")
                || type_str.contains("Signer")
                || type_str.contains("Sysvar")
                || type_str.contains("SystemAccount");

            if field_name.contains("account") && !field_name.contains("system")
                && !constraint_str.contains("owner")
                && !uses_typed_account
            {
                self.metrics.missing_owner_checks += 1;
                self.add_finding(
                    AnchorViolation::MissingOwnerCheck,
                    AnchorSeverity::High,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` uses raw AccountInfo without owner validation. \
                         Use `Account<'info, T>` which automatically validates `T::owner == program_id`, \
                         or add `#[account(owner = program_id)]` if you must use AccountInfo.",
                        field_name
                    ),
                );
            }

            // Check for weak constraints -- constraint without custom error (@ErrorCode)
            if constraint_str.contains("constraint =") && !constraint_str.contains("@") {
                self.metrics.weak_constraints += 1;
                self.add_finding(
                    AnchorViolation::WeakConstraint,
                    AnchorSeverity::Medium,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` uses `constraint = ...` without a custom error code (`@ ErrorCode::X`). \
                         Constraints without custom errors emit a generic `ConstraintRaw` error, making it \
                         difficult to diagnose failures in production and in CI/CD tests.",
                        field_name
                    ),
                );
            }

            // Check for init without space.
            // IMPORTANT: exclude `init_if_needed` -- it will be handled separately.
            let uses_init = constraint_str.contains("init")
                && !constraint_str.contains("init_if_needed");

            if uses_init && !constraint_str.contains("space") {
                self.add_finding(
                    AnchorViolation::MissingSpaceCalculation,
                    AnchorSeverity::High,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` uses `#[account(init)]` without `space = ...`. Anchor will \
                         allocate 0 bytes for the account data, causing the transaction to fail at \
                         runtime when the program tries to serialize state into it. Use \
                         `space = 8 + std::mem::size_of::<T>()` (8 bytes = Anchor discriminator).",
                        field_name
                    ),
                );
            }

            // Check for init_if_needed (reinitialization risk)
            if constraint_str.contains("init_if_needed") {
                self.metrics.reinit_vulnerabilities += 1;
                self.add_finding(
                    AnchorViolation::ReinitializationVulnerability,
                    AnchorSeverity::Critical,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` uses `init_if_needed` which allows any caller to reinitialize \
                         an existing account, resetting its state. This was the attack vector in \
                         multiple Anchor program exploits. If reinitialization is intended, add an \
                         explicit `is_initialized` flag check in the instruction handler. Otherwise, \
                         replace with `init` and handle the \"already initialized\" case separately.",
                        field_name
                    ),
                );
            }

            // Check for close without destination validation
            if constraint_str.contains("close") {
                self.metrics.custom_constraint_count += 1;
                // Check if the close destination is validated via has_one
                if !constraint_str.contains("has_one") {
                    self.metrics.missing_close_guards += 1;
                    self.add_finding(
                        AnchorViolation::MissingCloseGuard,
                        AnchorSeverity::High,
                        &struct_name,
                        &field_name,
                        format!(
                            "Field `{}` uses `close = <destination>` without `has_one` on the parent \
                             account. The lamports from the closed account flow to the destination, but \
                             without `has_one`, an attacker could close the account and redirect funds \
                             to an arbitrary wallet. Add `has_one = <authority>` to bind the close \
                             operation to the authorized party.",
                            field_name
                        ),
                    );
                }
            }

            // Track custom constraints for metrics
            if constraint_str.contains("constraint =") {
                self.metrics.custom_constraint_count += 1;
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}

impl ConstraintVisitor<'_> {
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
            risk_explanation: self.get_risk_explanation(violation),
            fix_recommendation: self.get_fix_recommendation(violation, field_name),
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

    fn get_risk_explanation(&self, violation: AnchorViolation) -> String {
        match violation {
            AnchorViolation::MissingOwnerCheck => {
                "Without owner validation, an attacker passes an account owned by a different program. \
                 The account data is deserialized using your program's struct layout, but the data was \
                 written by a different program with a different schema. This is a type confusion attack \
                 (CWE-843) that can corrupt program state.".into()
            }
            AnchorViolation::WeakConstraint => {
                "Constraints without custom error codes emit a generic `ConstraintRaw` error (0x7d3). \
                 This makes debugging difficult -- when a transaction fails, the error message gives \
                 no indication of WHICH constraint failed or WHY.".into()
            }
            AnchorViolation::MissingSpaceCalculation => {
                "Anchor's `init` constraint allocates a new account via a system program CPI. The \
                 `space` parameter specifies how many bytes to allocate. Without it, the account has \
                 0 data bytes, which causes serialization to fail at runtime.".into()
            }
            AnchorViolation::ReinitializationVulnerability => {
                "`init_if_needed` creates the account if it doesn't exist, or skips initialization \
                 if it does. However, an attacker can close the account (draining its lamports to 0), \
                 then call the instruction again. The runtime garbage collects zero-lamport accounts \
                 at the end of the slot, so the next call sees the account as uninitialized and \
                 creates it fresh -- effectively resetting all state.".into()
            }
            AnchorViolation::MissingCloseGuard => {
                "The `close` constraint transfers all lamports from the account to a destination, \
                 then zeroes the data and sets the discriminator to the CLOSED flag. Without `has_one` \
                 binding, any caller can close the account and redirect funds.".into()
            }
            _ => "Anchor security pattern violation detected.".into(),
        }
    }

    fn get_fix_recommendation(&self, violation: AnchorViolation, field_name: &str) -> String {
        match violation {
            AnchorViolation::MissingOwnerCheck => {
                format!(
                    "Use `Account<'info, T>` which auto-validates ownership:\n\
                     ```rust\n\
                     pub {}: Account<'info, MyState>,\n\
                     ```\n\
                     Or add explicit owner check:\n\
                     ```rust\n\
                     #[account(owner = crate::ID)]\n\
                     pub {}: AccountInfo<'info>,\n\
                     ```",
                    field_name, field_name,
                )
            }
            AnchorViolation::WeakConstraint => {
                format!(
                    "Add a custom error code:\n\
                     ```rust\n\
                     #[account(constraint = check_condition() @ ErrorCode::InvalidState)]\n\
                     pub {}: Account<'info, T>,\n\
                     ```",
                    field_name,
                )
            }
            AnchorViolation::MissingSpaceCalculation => {
                format!(
                    "Add space calculation (8 = Anchor discriminator):\n\
                     ```rust\n\
                     #[account(init, payer = user, space = 8 + std::mem::size_of::<T>())]\n\
                     pub {}: Account<'info, T>,\n\
                     ```",
                    field_name,
                )
            }
            AnchorViolation::ReinitializationVulnerability => {
                format!(
                    "Replace `init_if_needed` with `init` and handle existing accounts:\n\
                     ```rust\n\
                     #[account(init, payer = user, space = 8 + T::LEN)]\n\
                     pub {}: Account<'info, T>,\n\
                     ```\n\
                     If re-creation is intended, use an explicit `is_initialized` flag.",
                    field_name,
                )
            }
            AnchorViolation::MissingCloseGuard => {
                format!(
                    "Bind close to a validated authority:\n\
                     ```rust\n\
                     #[account(mut, close = authority, has_one = authority)]\n\
                     pub {}: Account<'info, T>,\n\
                     ```",
                    field_name,
                )
            }
            _ => "Review Anchor documentation for best practices.".into(),
        }
    }
}
