//! Signer Checker -- AST-based signer constraint validation
//!
//! Walks `#[derive(Accounts)]` structs via `syn::visit::Visit` and checks:
//! - Authority/admin/owner fields that use raw `AccountInfo` instead of `Signer<'info>`
//! - Authority fields missing `#[account(signer)]` or `has_one = authority`
//! - `UncheckedAccount` used for privileged role fields
//! - Fields named `*_authority` without corresponding signer enforcement

use crate::metrics::AnchorMetrics;
use crate::report::{AnchorFinding, AnchorSeverity, AnchorViolation};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct SignerChecker;

impl SignerChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn check_signers(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let mut visitor = SignerVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            metrics,
        };

        visitor.visit_file(syntax_tree);
        visitor.findings
    }
}

impl Default for SignerChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Privileged role name patterns that require signer enforcement
const PRIVILEGED_NAMES: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "manager",
    "operator",
    "governance",
    "guardian",
    "multisig",
    "payer",
    "fee_authority",
    "update_authority",
    "withdraw_authority",
    "close_authority",
    "freeze_authority",
    "mint_authority",
];

struct SignerVisitor<'a> {
    file_path: String,
    content: String,
    findings: Vec<AnchorFinding>,
    metrics: &'a mut AnchorMetrics,
}

impl<'ast> Visit<'ast> for SignerVisitor<'_> {
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

        // Collect all field names in this struct for has_one cross-reference checking
        let all_field_names: Vec<String> = node
            .fields
            .iter()
            .filter_map(|f| f.ident.as_ref().map(|i| i.to_string()))
            .collect();

        for field in &node.fields {
            let field_name = match &field.ident {
                Some(ident) => ident.to_string(),
                None => continue,
            };

            // Extract the type as a string for analysis
            let type_str = quote::quote!(#field.ty).to_string();

            // Extract #[account(...)] attribute content if present
            let account_attr_str = field
                .attrs
                .iter()
                .filter(|attr| attr.path().is_ident("account"))
                .map(|attr| quote::quote!(#attr).to_string())
                .collect::<Vec<_>>()
                .join(" ");

            let is_privileged = PRIVILEGED_NAMES
                .iter()
                .any(|name| field_name == *name || field_name.ends_with(&format!("_{}", name)));

            if !is_privileged {
                continue;
            }

            // Check 1: Raw AccountInfo used for privileged role without Signer type
            let uses_raw_account_info = type_str.contains("AccountInfo")
                && !type_str.contains("Signer")
                && !type_str.contains("Account <");

            let uses_unchecked = type_str.contains("UncheckedAccount");

            let has_signer_constraint = account_attr_str.contains("signer")
                || type_str.contains("Signer <")
                || type_str.contains("Signer<");

            if (uses_raw_account_info || uses_unchecked) && !has_signer_constraint {
                self.metrics.missing_signer_checks += 1;
                self.add_finding(
                    AnchorViolation::MissingSignerCheck,
                    AnchorSeverity::Critical,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` in `{}` is a privileged role ({}) using `{}` without signer enforcement. \
                         The Solana runtime does not check `is_signer` unless the program explicitly validates it. \
                         An attacker can pass any pubkey as `{}` and execute privileged operations. \
                         Use `Signer<'info>` instead of `AccountInfo<'info>`, or add `#[account(signer)]`.",
                        field_name,
                        struct_name,
                        if uses_unchecked { "UncheckedAccount" } else { "raw AccountInfo" },
                        if uses_unchecked { "UncheckedAccount" } else { "AccountInfo" },
                        field_name,
                    ),
                );
            }

            // Check 2: Privileged field exists but no has_one cross-reference on any state account
            // This checks that some other account in the struct validates the relationship
            if has_signer_constraint {
                let has_one_ref = all_field_names.iter().any(|other_field| {
                    if *other_field == field_name {
                        return false;
                    }
                    // Check if any other field's account attr references this field via has_one
                    node.fields.iter().any(|f| {
                        let other_name = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                        if other_name == field_name {
                            return false;
                        }
                        let other_attr = f
                            .attrs
                            .iter()
                            .filter(|a| a.path().is_ident("account"))
                            .map(|a| quote::quote!(#a).to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        other_attr.contains(&format!("has_one = {}", field_name))
                    })
                });

                if !has_one_ref && !account_attr_str.contains("has_one") {
                    // The signer is validated as a signer but no state account
                    // cross-references it via has_one. This means ANY valid signer
                    // can call this instruction, not just the authorized one.
                    self.add_finding(
                        AnchorViolation::MissingHasOne,
                        AnchorSeverity::High,
                        &struct_name,
                        &field_name,
                        format!(
                            "Field `{}` in `{}` is a `Signer` but no state account in this struct uses \
                             `#[account(has_one = {})]` to verify ownership. This means ANY valid wallet \
                             can call this instruction as the `{}`. Add `has_one = {}` to the relevant \
                             state/vault/pool account to bind the signer to stored authority.",
                            field_name, struct_name, field_name, field_name, field_name,
                        ),
                    );
                }
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}

impl SignerVisitor<'_> {
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
            if in_struct && line.contains(field_name) && line.contains(":") {
                return i + 1;
            }
            // Rough heuristic: if we hit the next struct or impl, stop
            if in_struct && (line.trim_start().starts_with("impl") || (line.contains("struct ") && !line.contains(struct_name))) {
                break;
            }
        }
        // Fallback: find the struct line
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
            AnchorViolation::MissingSignerCheck => {
                "Without signer validation, the Solana runtime allows any account to be passed in the \
                 authority position. An attacker constructs a transaction with their own pubkey as the \
                 authority field and the runtime will not reject it. This is the most common Solana \
                 vulnerability pattern -- the Wormhole bridge exploit ($320M) was caused by a missing \
                 signer check on the guardian set update."
                    .into()
            }
            AnchorViolation::MissingHasOne => {
                "A Signer constraint only proves that the wallet signed the transaction. It does NOT \
                 prove the signer is the authorized authority for a specific account. Without `has_one`, \
                 any wallet that signs can act as the authority. The `has_one` constraint makes Anchor \
                 compare `state_account.authority == signer.key()` during deserialization."
                    .into()
            }
            _ => "Anchor security pattern violation detected.".into(),
        }
    }

    fn fix_recommendation(&self, violation: AnchorViolation, field_name: &str) -> String {
        match violation {
            AnchorViolation::MissingSignerCheck => {
                format!(
                    "Replace `AccountInfo<'info>` with `Signer<'info>`:\n\
                     ```rust\n\
                     pub {}: Signer<'info>,\n\
                     ```\n\
                     Or add the signer constraint:\n\
                     ```rust\n\
                     #[account(signer)]\n\
                     pub {}: AccountInfo<'info>,\n\
                     ```",
                    field_name, field_name,
                )
            }
            AnchorViolation::MissingHasOne => {
                format!(
                    "Add `has_one = {}` to the state account that stores this authority:\n\
                     ```rust\n\
                     #[account(mut, has_one = {} @ ErrorCode::Unauthorized)]\n\
                     pub vault: Account<'info, VaultState>,\n\
                     ```",
                    field_name, field_name,
                )
            }
            _ => "Review Anchor documentation for best practices.".into(),
        }
    }
}
