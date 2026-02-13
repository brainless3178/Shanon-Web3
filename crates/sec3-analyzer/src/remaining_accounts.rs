//! **Remaining Accounts Analyzer** — detects unsafe usage of
//! `ctx.remaining_accounts` without proper validation.
//!
//! Remaining accounts are an escape hatch that bypasses all Anchor validation.
//! Programs that iterate over `remaining_accounts` without checking owner,
//! signer status, or data layout are vulnerable to account injection attacks.

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
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = idx + 1;

        if trimmed.contains("remaining_accounts") {
            // Check if there's validation nearby (±15 lines)
            let has_validation = check_remaining_accounts_validation(&lines, idx);

            if !has_validation {
                let fn_name = find_enclosing_fn(&lines, idx);
                findings.push(Sec3Finding {
                    id: utils::generate_finding_id(
                        "SEC3",
                        &Sec3Category::UncheckedRemainingAccounts,
                        file_path,
                        line_num,
                    ),
                    category: Sec3Category::UncheckedRemainingAccounts,
                    severity: Sec3Severity::High,
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    instruction: fn_name,
                    account_name: None,
                    description: format!(
                        "`remaining_accounts` accessed at line {} without visible validation. \
                         Remaining accounts bypass Anchor's automatic validation — an attacker \
                         can inject arbitrary accounts to manipulate instruction logic, substitute \
                         token accounts, or inject malicious program IDs for CPI.",
                        line_num,
                    ),
                    fix_recommendation: "Validate each remaining account before use:\n\
                         • Check owner: `require!(acc.owner == &expected_program_id)`\n\
                         • Check key: `require_keys_eq!(acc.key(), expected_key)`\n\
                         • Deserialize with type check: `Account::<TokenAccount>::try_from(acc)?`\n\
                         • Or move accounts into the Anchor `#[derive(Accounts)]` struct"
                        .to_string(),
                    cwe: Sec3Category::UncheckedRemainingAccounts.cwe().to_string(),
                    fingerprint: utils::fingerprint(
                        &Sec3Category::UncheckedRemainingAccounts,
                        file_path,
                        line_num,
                        "remaining_accounts",
                    ),
                    source_snippet: Some(trimmed.to_string()),
                    fix_diff: None,
                });
            }
        }
    }
}

fn check_remaining_accounts_validation(lines: &[&str], access_line: usize) -> bool {
    let start = access_line.saturating_sub(5);
    let end = (access_line + 15).min(lines.len());

    for line in lines.iter().take(end).skip(start) {
        let lt = line.to_lowercase();
        if lt.contains(".owner")
            && (lt.contains("require") || lt.contains("assert") || lt.contains("=="))
            || lt.contains("try_from(")
            || lt.contains("try_deserialize")
            || lt.contains("require_keys_eq!")
            || lt.contains("key() ==")
            || lt.contains("is_signer") && lt.contains("require")
            || lt.contains("account::try_from")
        {
            return true;
        }
    }
    false
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
