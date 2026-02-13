//! **Close Account Analyzer** — detects unsafe account closure patterns.
//!
//! When closing a Solana account, the program must:
//! 1. Transfer **all** lamports to the recipient.
//! 2. Zero the account data (or assign to System Program).
//! 3. Verify only the rightful authority can close the account.
//!
//! Failure to do so allows "close-account drain" attacks where an attacker
//! reuses a closed account's address to siphon remaining lamports, or
//! reads stale data from a "zombie" account.
//!
//! Sec3 detects:
//! - `close` constraint without `has_one` authority validation.
//! - Manual lamport manipulation without zeroing data.
//! - `init_if_needed` combined with `close` (re-init after close).

use crate::report::{Sec3Category, Sec3Finding, Sec3Severity};
use crate::utils;
use std::path::Path;

pub fn scan(program_path: &Path) -> Vec<Sec3Finding> {
    let mut findings = Vec::new();

    for (file_path, content) in utils::collect_rust_sources(program_path) {
        scan_file_ast(&file_path, &content, &mut findings);
        scan_file_patterns(&file_path, &content, &mut findings);
    }

    findings
}

/// AST-based detection for Anchor `close` constraints.
fn scan_file_ast(file_path: &str, content: &str, findings: &mut Vec<Sec3Finding>) {
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
            let mut has_close_field = false;
            let mut has_init_if_needed = false;

            if let syn::Fields::Named(ref fields) = s.fields {
                for field in &fields.named {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    let attrs_text = utils::attrs_to_string(&field.attrs);

                    // Check for init_if_needed
                    if attrs_text.contains("init_if_needed") {
                        has_init_if_needed = true;

                        let line = utils::span_start_line(content, field);
                        findings.push(Sec3Finding {
                            id: utils::generate_finding_id("SEC3", &Sec3Category::ReInitialization, file_path, line),
                            category: Sec3Category::ReInitialization,
                            severity: Sec3Severity::High,
                            file_path: file_path.to_string(),
                            line_number: line,
                            instruction: instruction_name.clone(),
                            account_name: Some(field_name.clone()),
                            description: format!(
                                "Account '{}' in instruction '{}' uses `init_if_needed` — this allows \
                                 re-initialization of an already-initialized account, potentially \
                                 overwriting critical state data (authority, balances, configuration). \
                                 An attacker who can close and re-initialize an account can reset \
                                 vault balances or change authorities.",
                                field_name, instruction_name,
                            ),
                            fix_recommendation: format!(
                                "Replace `init_if_needed` with `init` for '{}' and handle the \
                                 already-initialized case explicitly. Use a boolean `is_initialized` \
                                 field in the account data to prevent re-initialization.",
                                field_name,
                            ),
                            cwe: Sec3Category::ReInitialization.cwe().to_string(),
                            fingerprint: utils::fingerprint(&Sec3Category::ReInitialization, file_path, line, &instruction_name),
                            source_snippet: utils::extract_snippet(content, line),
                            fix_diff: None,
                        });
                    }

                    // Check for close constraint
                    if attrs_text.contains("close") && attrs_text.contains("=") {
                        has_close_field = true;

                        // Check if close has authority validation
                        let has_authority = attrs_text.contains("has_one")
                            || attrs_text.contains("constraint")
                            || attrs_text.contains("authority");

                        if !has_authority {
                            let line = utils::span_start_line(content, field);
                            findings.push(Sec3Finding {
                                id: utils::generate_finding_id("SEC3", &Sec3Category::CloseAccountDrain, file_path, line),
                                category: Sec3Category::CloseAccountDrain,
                                severity: Sec3Severity::High,
                                file_path: file_path.to_string(),
                                line_number: line,
                                instruction: instruction_name.clone(),
                                account_name: Some(field_name.clone()),
                                description: format!(
                                    "Account '{}' has a `close` constraint in instruction '{}' but \
                                     no `has_one` or `constraint` validating who can close it. Any \
                                     user can close this account and claim its lamport balance.",
                                    field_name, instruction_name,
                                ),
                                fix_recommendation: format!(
                                    "Add `has_one = authority` to '{}' to ensure only the authorized \
                                     user can close the account and receive the lamport refund.",
                                    field_name,
                                ),
                                cwe: Sec3Category::CloseAccountDrain.cwe().to_string(),
                                fingerprint: utils::fingerprint(&Sec3Category::CloseAccountDrain, file_path, line, &instruction_name),
                                source_snippet: utils::extract_snippet(content, line),
                                fix_diff: None,
                            });
                        }
                    }
                }
            }

            // Combined init_if_needed + close is extremely dangerous
            if has_init_if_needed && has_close_field {
                let line = utils::struct_line(content, s);
                findings.push(Sec3Finding {
                    id: utils::generate_finding_id(
                        "SEC3",
                        &Sec3Category::CloseAccountDrain,
                        file_path,
                        line,
                    ),
                    category: Sec3Category::CloseAccountDrain,
                    severity: Sec3Severity::Critical,
                    file_path: file_path.to_string(),
                    line_number: line,
                    instruction: instruction_name.clone(),
                    account_name: None,
                    description: format!(
                        "Instruction '{}' combines `init_if_needed` with `close` — this creates \
                         a Close-Reinit attack vector where an attacker can repeatedly close \
                         and reinitialize the account in a loop, draining lamports or resetting \
                         state each iteration.",
                        instruction_name,
                    ),
                    fix_recommendation:
                        "Separate initialization and closure into distinct instructions with \
                         independent authority checks. Never allow both `init_if_needed` and \
                         `close` on the same account in the same instruction."
                            .to_string(),
                    cwe: Sec3Category::CloseAccountDrain.cwe().to_string(),
                    fingerprint: utils::fingerprint(
                        &Sec3Category::CloseAccountDrain,
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

/// Pattern-based detection for manual lamport manipulation without data zeroing.
fn scan_file_patterns(file_path: &str, content: &str, findings: &mut Vec<Sec3Finding>) {
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = idx + 1;

        // Detect manual lamport draining without zeroing data
        if (trimmed.contains("lamports.borrow_mut()")
            || trimmed.contains("try_borrow_mut_lamports"))
            && trimmed.contains("= 0")
        {
            // Look ahead for data zeroing
            let has_data_zero = lines.iter().skip(idx).take(10).any(|l| {
                let lt = l.trim();
                lt.contains("data.borrow_mut()") && lt.contains("fill(0)")
                    || lt.contains("assign(&system_program::ID)")
                    || lt.contains("realloc(0")
            });

            if !has_data_zero {
                let fn_name = find_enclosing_fn(&lines, idx);
                findings.push(Sec3Finding {
                    id: utils::generate_finding_id(
                        "SEC3",
                        &Sec3Category::CloseAccountDrain,
                        file_path,
                        line_num,
                    ),
                    category: Sec3Category::CloseAccountDrain,
                    severity: Sec3Severity::High,
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    instruction: fn_name,
                    account_name: None,
                    description: format!(
                        "Account lamports zeroed at line {} without clearing account data. \
                         The account becomes a 'zombie' — the runtime may garbage-collect it, \
                         but within the same transaction it can still be read with stale data, \
                         enabling type confusion or replay attacks.",
                        line_num,
                    ),
                    fix_recommendation: "After zeroing lamports, also zero account data:\n\
                         `account.data.borrow_mut().fill(0);`\n\
                         Or use Anchor's `close` constraint which handles this automatically."
                        .to_string(),
                    cwe: Sec3Category::CloseAccountDrain.cwe().to_string(),
                    fingerprint: utils::fingerprint(
                        &Sec3Category::CloseAccountDrain,
                        file_path,
                        line_num,
                        "manual_close",
                    ),
                    source_snippet: Some(trimmed.to_string()),
                    fix_diff: None,
                });
            }
        }
    }
}

fn find_enclosing_fn(lines: &[&str], line_idx: usize) -> String {
    for i in (0..=line_idx).rev() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") {
            if let Some(name_start) = trimmed.find("fn ") {
                let after_fn = &trimmed[name_start + 3..];
                if let Some(paren) = after_fn.find('(') {
                    return after_fn[..paren].trim().to_string();
                }
            }
        }
    }
    "unknown".to_string()
}
