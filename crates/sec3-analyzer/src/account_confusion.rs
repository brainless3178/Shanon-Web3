//! **Account Confusion Detector** — flags raw `AccountInfo` usage where a
//! typed Anchor wrapper (`Account<T>`, `Program<T>`, `Signer<T>`) would
//! enforce deserialization + owner validation automatically.
//!
//! Account confusion (CWE-345) is the most exploited vulnerability class on
//! Solana. An attacker can substitute a look-alike account from a different
//! program, and if the instruction handler reads fields by byte offset
//! without type validation, the attacker controls the data interpretation.
//!
//! **Sec3/Soteria rule**: Every `AccountInfo<'info>` in a `#[derive(Accounts)]`
//! struct without a corresponding `/// CHECK:` documentation + constraint
//! is flagged.

use crate::report::{Sec3Category, Sec3Finding, Sec3Severity};
use crate::utils;
use std::path::Path;

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

            if let syn::Fields::Named(ref fields) = s.fields {
                for field in &fields.named {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    let ty_str = utils::type_to_string(&field.ty);

                    // Flag raw AccountInfo without CHECK doc
                    if ty_str.contains("AccountInfo") && !ty_str.contains("Account<") {
                        let has_check = utils::has_any_check_doc(&field.attrs);
                        let has_constraints = utils::field_has_any_account_constraint(&field.attrs);

                        if !has_check && !has_constraints {
                            let line = utils::span_start_line(content, field);

                            findings.push(Sec3Finding {
                                id: utils::generate_finding_id("SEC3", &Sec3Category::AccountConfusion, file_path, line),
                                category: Sec3Category::AccountConfusion,
                                severity: Sec3Severity::Critical,
                                file_path: file_path.to_string(),
                                line_number: line,
                                instruction: instruction_name.clone(),
                                account_name: Some(field_name.clone()),
                                description: format!(
                                    "Raw `AccountInfo<'info>` field '{}' in '{}' has no `/// CHECK:` \
                                     documentation and no Anchor constraints. Anchor will not validate \
                                     the account type, owner, or data layout — any account can be \
                                     substituted. This is the primary vector for account confusion \
                                     attacks (Cashio $48M exploit, Wormhole $320M exploit).",
                                    field_name, instruction_name,
                                ),
                                fix_recommendation: "Replace `AccountInfo<'info>` with a typed Anchor wrapper:\n\
                                     • `Account<'info, MyData>` — validates owner + deserializes data\n\
                                     • `Program<'info, MyProgram>` — validates program ID\n\
                                     • `Signer<'info>` — validates is_signer flag\n\
                                     • `SystemAccount<'info>` — validates System Program ownership\n\
                                     If raw access is truly needed, add `/// CHECK: <justification>` \
                                     documenting why this is safe.".to_string(),
                                cwe: Sec3Category::AccountConfusion.cwe().to_string(),
                                fingerprint: utils::fingerprint(&Sec3Category::AccountConfusion, file_path, line, &instruction_name),
                                source_snippet: utils::extract_snippet(content, line),
                                fix_diff: Some(format!(
                                    "--- a/{fp}\n+++ b/{fp}\n@@ -{ln},1 +{ln},1 @@\n-\
                                     pub {name}: AccountInfo<'info>,\n+\
                                     pub {name}: Account<'info, ValidatedType>,",
                                    fp = file_path, ln = line, name = field_name,
                                )),
                            });
                        }
                    }

                    // Flag UncheckedAccount without CHECK doc — this is Anchor's "I know
                    // what I'm doing" escape hatch, but Sec3 still flags it
                    if ty_str.contains("UncheckedAccount<") {
                        let has_check = utils::has_any_check_doc(&field.attrs);

                        if !has_check {
                            let line = utils::span_start_line(content, field);

                            findings.push(Sec3Finding {
                                id: utils::generate_finding_id("SEC3", &Sec3Category::AccountConfusion, file_path, line),
                                category: Sec3Category::AccountConfusion,
                                severity: Sec3Severity::High,
                                file_path: file_path.to_string(),
                                line_number: line,
                                instruction: instruction_name.clone(),
                                account_name: Some(field_name.clone()),
                                description: format!(
                                    "`UncheckedAccount<'info>` field '{}' in '{}' is missing the \
                                     required `/// CHECK:` documentation. Anchor will compile this \
                                     but the account is not validated — an attacker can pass any \
                                     account data.",
                                    field_name, instruction_name,
                                ),
                                fix_recommendation: format!(
                                    "Add `/// CHECK: <reason why this is safe>` documentation \
                                     above the '{}' field, or replace with a typed `Account<'info, T>`.",
                                    field_name,
                                ),
                                cwe: Sec3Category::AccountConfusion.cwe().to_string(),
                                fingerprint: utils::fingerprint(&Sec3Category::AccountConfusion, file_path, line, &instruction_name),
                                source_snippet: utils::extract_snippet(content, line),
                                fix_diff: None,
                            });
                        }
                    }
                }
            }
        }
    }
}
