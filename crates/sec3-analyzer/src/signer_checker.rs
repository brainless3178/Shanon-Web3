//! **Signer Validation Checker** — detects instructions that mutate state
//! without verifying that a required authority account is a signer.
//!
//! Missing signer checks allow any user to invoke privileged operations such
//! as withdrawals, parameter updates, or admin functions. Sec3/Soteria flags:
//!
//! 1. `#[derive(Accounts)]` fields named like authorities (`authority`,
//!    `admin`, `owner`, `governance`, `payer`, `creator`) that are NOT
//!    typed as `Signer<'info>` and do NOT carry `#[account(signer)]`.
//! 2. Instruction handlers that call `.transfer()`, `.close()`, or write
//!    to `mut` accounts but have no signer among their account inputs.

use crate::report::{Sec3Category, Sec3Finding, Sec3Severity};
use crate::utils;
use std::path::Path;

const AUTHORITY_NAMES: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "governance",
    "governor",
    "payer",
    "creator",
    "manager",
    "operator",
    "multisig",
    "signer",
    "fee_payer",
    "update_authority",
    "mint_authority",
    "freeze_authority",
    "close_authority",
    "withdraw_authority",
    "vault_authority",
    "pool_authority",
    "dao_authority",
];

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
            if !utils::has_derive(&s.attrs, "Accounts") {
                continue;
            }

            let instruction_name = utils::infer_instruction_name(&s.ident.to_string());
            let mut has_any_signer = false;
            let mut has_mut_account = false;
            let mut authority_fields: Vec<(String, usize, bool)> = Vec::new(); // (name, line, is_signer)

            if let syn::Fields::Named(ref fields) = s.fields {
                for field in &fields.named {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    let ty_str = utils::type_to_string(&field.ty);
                    let line = utils::span_start_line(content, field);

                    // Check if this field is a signer
                    let is_signer_type = ty_str.contains("Signer<");
                    let has_signer_constraint =
                        utils::field_has_account_attr_key(&field.attrs, "signer");
                    let is_signer = is_signer_type || has_signer_constraint;

                    if is_signer {
                        has_any_signer = true;
                    }

                    // Check if this is a mutable account
                    let has_mut_constraint = utils::field_has_account_attr_key(&field.attrs, "mut");
                    if has_mut_constraint || ty_str.contains("mut") {
                        has_mut_account = true;
                    }

                    // Check if this is an authority-like field
                    let lower_name = field_name.to_lowercase();
                    let is_authority = AUTHORITY_NAMES.iter().any(|a| lower_name.contains(a));

                    if is_authority {
                        authority_fields.push((field_name.clone(), line, is_signer));

                        if !is_signer {
                            findings.push(Sec3Finding {
                                id: utils::generate_finding_id("SEC3", &Sec3Category::MissingSignerCheck, file_path, line),
                                category: Sec3Category::MissingSignerCheck,
                                severity: Sec3Severity::Critical,
                                file_path: file_path.to_string(),
                                line_number: line,
                                instruction: instruction_name.clone(),
                                account_name: Some(field_name.clone()),
                                description: format!(
                                    "Authority-like account '{}' in instruction '{}' is not enforced as \
                                     a signer. Without signer validation, any wallet can invoke this \
                                     instruction pretending to be the authority — enabling unauthorized \
                                     withdrawals, parameter changes, or governance attacks.",
                                    field_name, instruction_name,
                                ),
                                fix_recommendation: format!(
                                    "Change the type of '{}' to `Signer<'info>`, or add \
                                     `#[account(signer)]` constraint. For multi-sig authorities, \
                                     add `constraint = authority.is_signer @ ErrorCode::Unauthorized`.",
                                    field_name,
                                ),
                                cwe: Sec3Category::MissingSignerCheck.cwe().to_string(),
                                fingerprint: utils::fingerprint(&Sec3Category::MissingSignerCheck, file_path, line, &instruction_name),
                                source_snippet: utils::extract_snippet(content, line),
                                fix_diff: Some(format!(
                                    "--- a/{fp}\n+++ b/{fp}\n@@ -{ln},1 +{ln},1 @@\n-\
                                     pub {name}: AccountInfo<'info>,\n+\
                                     pub {name}: Signer<'info>,",
                                    fp = file_path, ln = line, name = field_name,
                                )),
                            });
                        }
                    }
                }
            }

            // Also flag instructions that mutate state but have zero signers
            if has_mut_account && !has_any_signer && authority_fields.is_empty() {
                let line = utils::struct_line(content, s);
                findings.push(Sec3Finding {
                    id: utils::generate_finding_id(
                        "SEC3",
                        &Sec3Category::MissingSignerCheck,
                        file_path,
                        line,
                    ),
                    category: Sec3Category::MissingSignerCheck,
                    severity: Sec3Severity::High,
                    file_path: file_path.to_string(),
                    line_number: line,
                    instruction: instruction_name.clone(),
                    account_name: None,
                    description: format!(
                        "Instruction '{}' modifies mutable accounts but contains no `Signer` \
                         field — any user can invoke this instruction and mutate state. \
                         Even if the instruction is intended to be permissionless, consider \
                         adding a fee-payer signer for DoS protection.",
                        instruction_name,
                    ),
                    fix_recommendation: format!(
                        "Add a `pub authority: Signer<'info>` field to the accounts struct \
                         for '{}', and validate it against expected authority stored in \
                         program state.",
                        instruction_name,
                    ),
                    cwe: Sec3Category::MissingSignerCheck.cwe().to_string(),
                    fingerprint: utils::fingerprint(
                        &Sec3Category::MissingSignerCheck,
                        file_path,
                        line,
                        &instruction_name,
                    ),
                    source_snippet: None,
                    fix_diff: None,
                });
            }
        }
    }
}
