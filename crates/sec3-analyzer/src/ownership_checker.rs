//! **Ownership Checker** — detects accounts used without verifying that
//! `account.owner == expected_program_id`.
//!
//! In Anchor programs, using raw `AccountInfo` without an explicit
//! `owner` constraint means an attacker can substitute an account owned
//! by a different program, leading to full privilege escalation.
//!
//! Detection strategy:
//! 1. Walk every `#[derive(Accounts)]` struct.
//! 2. For each field typed as `AccountInfo<'info>`, check whether
//!    the field carries an `#[account(owner = ...)]` attribute or a
//!    `/// CHECK:` doc comment with owner justification.
//! 3. Fields typed as `Account<'info, T>`, `Program<'info, T>`, or
//!    `Signer<'info>` are implicitly owner-checked by Anchor, so they
//!    are skipped.

use crate::report::{Sec3Category, Sec3Finding, Sec3Severity};
use crate::utils;
use std::path::Path;

/// Scan all Rust source files under `program_path` for missing owner checks.
pub fn scan(program_path: &Path) -> Vec<Sec3Finding> {
    let mut findings = Vec::new();

    for (file_path, content) in utils::collect_rust_sources(program_path) {
        scan_file(&file_path, &content, &mut findings);
    }

    findings
}

fn scan_file(file_path: &str, content: &str, findings: &mut Vec<Sec3Finding>) {
    let syntax = match syn::parse_file(content) {
        Ok(f) => f,
        Err(_) => return,
    };

    for item in &syntax.items {
        if let syn::Item::Struct(s) = item {
            // Only look at #[derive(Accounts)] structs
            if !utils::has_derive(&s.attrs, "Accounts") {
                continue;
            }

            let instruction_name = utils::infer_instruction_name(&s.ident.to_string());

            if let syn::Fields::Named(ref fields) = s.fields {
                for field in &fields.named {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map(|i| i.to_string())
                        .unwrap_or_default();

                    let ty_str = utils::type_to_string(&field.ty);

                    // Only flag raw AccountInfo — typed wrappers are auto-checked by Anchor
                    let is_raw_account_info = ty_str.contains("AccountInfo")
                        && !ty_str.contains("Account<")
                        && !ty_str.contains("Program<")
                        && !ty_str.contains("Signer<")
                        && !ty_str.contains("SystemAccount<")
                        && !ty_str.contains("UncheckedAccount<");

                    if !is_raw_account_info {
                        // Also flag UncheckedAccount without owner constraint
                        if ty_str.contains("UncheckedAccount<") {
                            let has_owner =
                                utils::field_has_account_attr_key(&field.attrs, "owner");
                            let has_check_doc = utils::has_check_doc_comment(&field.attrs, "owner");

                            if !has_owner && !has_check_doc {
                                let line = utils::span_start_line(content, field);
                                findings.push(Sec3Finding {
                                    id: utils::generate_finding_id("SEC3", &Sec3Category::MissingOwnerCheck, file_path, line),
                                    category: Sec3Category::MissingOwnerCheck,
                                    severity: Sec3Severity::High,
                                    file_path: file_path.to_string(),
                                    line_number: line,
                                    instruction: instruction_name.clone(),
                                    account_name: Some(field_name.clone()),
                                    description: format!(
                                        "UncheckedAccount '{}' in instruction '{}' lacks an `owner` constraint — \
                                         an attacker can substitute an account owned by a different program, \
                                         bypassing authorization logic entirely.",
                                        field_name, instruction_name,
                                    ),
                                    fix_recommendation: format!(
                                        "Add `#[account(owner = <expected_program>::ID)]` to '{}', or replace \
                                         with `Account<'info, T>` for automatic Anchor deserialization + owner check.",
                                        field_name,
                                    ),
                                    cwe: Sec3Category::MissingOwnerCheck.cwe().to_string(),
                                    fingerprint: utils::fingerprint(&Sec3Category::MissingOwnerCheck, file_path, line, &instruction_name),
                                    source_snippet: utils::extract_snippet(content, line),
                                    fix_diff: Some(format!(
                                        "--- a/{fp}\n+++ b/{fp}\n@@ -{ln},1 +{ln},2 @@\n \
                                         /// CHECK: validated in instruction handler\n+\
                                         #[account(owner = crate::ID)]\n pub {name}: UncheckedAccount<'info>,",
                                        fp = file_path, ln = line, name = field_name,
                                    )),
                                });
                            }
                        }
                        continue;
                    }

                    // Check for owner constraint in #[account(...)] attributes
                    let has_owner_constraint =
                        utils::field_has_account_attr_key(&field.attrs, "owner");
                    // Check for /// CHECK: documentation mentioning owner
                    let has_check_doc = utils::has_check_doc_comment(&field.attrs, "owner");

                    if !has_owner_constraint && !has_check_doc {
                        let line = utils::span_start_line(content, field);
                        findings.push(Sec3Finding {
                            id: utils::generate_finding_id("SEC3", &Sec3Category::MissingOwnerCheck, file_path, line),
                            category: Sec3Category::MissingOwnerCheck,
                            severity: Sec3Severity::Critical,
                            file_path: file_path.to_string(),
                            line_number: line,
                            instruction: instruction_name.clone(),
                            account_name: Some(field_name.clone()),
                            description: format!(
                                "Raw AccountInfo '{}' in instruction '{}' is not validated against any \
                                 expected program owner. An attacker can pass an account from an arbitrary \
                                 program, gaining full control over instruction logic. This is the #1 \
                                 root cause of Solana exploits (see: Wormhole $320M, Cashio $48M).",
                                field_name, instruction_name,
                            ),
                            fix_recommendation: format!(
                                "Replace raw `AccountInfo` with a typed Anchor wrapper:\n\
                                 • `Account<'info, MyState>` — automatic owner + deserialization check\n\
                                 • `Program<'info, System>` — for known programs\n\
                                 • Or add `#[account(owner = <program>::ID)]` constraint to '{}'.",
                                field_name,
                            ),
                            cwe: Sec3Category::MissingOwnerCheck.cwe().to_string(),
                            fingerprint: utils::fingerprint(&Sec3Category::MissingOwnerCheck, file_path, line, &instruction_name),
                            source_snippet: utils::extract_snippet(content, line),
                            fix_diff: Some(format!(
                                "--- a/{fp}\n+++ b/{fp}\n@@ -{ln},1 +{ln},1 @@\n-\
                                 pub {name}: AccountInfo<'info>,\n+\
                                 pub {name}: Account<'info, ExpectedAccountType>,",
                                fp = file_path, ln = line, name = field_name,
                            )),
                        });
                    }
                }
            }
        }
    }
}
