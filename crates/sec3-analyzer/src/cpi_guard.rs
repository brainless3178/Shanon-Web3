//! **CPI Guard** — detects unsafe cross-program invocations.
//!
//! An Arbitrary CPI vulnerability (CWE-94) allows an attacker to redirect a
//! cross-program invocation to a program they control, executing arbitrary logic
//! with the calling program's authority. Sec3 flags:
//!
//! 1. `invoke()` / `invoke_signed()` calls where the program ID account is not
//!    validated against a known constant.
//! 2. CPI calls using `AccountInfo` for the program without `Program<T>` typing.
//! 3. Missing program ID assertions before CPI dispatch.

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

    for (line_idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_num = line_idx + 1;

        // Detect raw invoke / invoke_signed without program ID validation
        let is_invoke = trimmed.contains("invoke(") || trimmed.contains("invoke_signed(");
        let is_solana_invoke = trimmed.contains("solana_program::program::invoke")
            || trimmed.contains("program::invoke");

        if is_invoke || is_solana_invoke {
            // Look backward for program ID validation within 10 lines
            let has_program_check = check_nearby_program_validation(&lines, line_idx);

            if !has_program_check {
                let fn_name = find_enclosing_function(&lines, line_idx);

                findings.push(Sec3Finding {
                    id: utils::generate_finding_id("SEC3", &Sec3Category::ArbitraryCPI, file_path, line_num),
                    category: Sec3Category::ArbitraryCPI,
                    severity: Sec3Severity::Critical,
                    file_path: file_path.to_string(),
                    line_number: line_num,
                    instruction: fn_name,
                    account_name: None,
                    description: format!(
                        "Unguarded CPI call at line {} — the target program ID is not validated \
                         against a known constant before `invoke()` / `invoke_signed()`. An attacker \
                         can substitute their own program, executing arbitrary logic with the \
                         caller's PDA authority. This is the attack vector used in the Wormhole \
                         exploit ($320M).",
                        line_num,
                    ),
                    fix_recommendation:
                        "Validate the program ID before invoking:\n\
                         • Use `Program<'info, TokenProgram>` in Anchor accounts struct\n\
                         • Or add `require_keys_eq!(program.key(), expected_program::ID)`\n\
                         • Or use `CpiContext::new(program.to_account_info(), ...)` with typed program"
                        .to_string(),
                    cwe: Sec3Category::ArbitraryCPI.cwe().to_string(),
                    fingerprint: utils::fingerprint(
                        &Sec3Category::ArbitraryCPI, file_path, line_num, "invoke",
                    ),
                    source_snippet: Some(trimmed.to_string()),
                    fix_diff: None,
                });
            }
        }

        // Detect CpiContext with untyped program account
        if trimmed.contains("CpiContext::new") && trimmed.contains("account_info") {
            let fn_name = find_enclosing_function(&lines, line_idx);

            findings.push(Sec3Finding {
                id: utils::generate_finding_id(
                    "SEC3",
                    &Sec3Category::ArbitraryCPI,
                    file_path,
                    line_num,
                ),
                category: Sec3Category::ArbitraryCPI,
                severity: Sec3Severity::High,
                file_path: file_path.to_string(),
                line_number: line_num,
                instruction: fn_name,
                account_name: None,
                description: format!(
                    "CPI context at line {} uses raw `AccountInfo` for the program — \
                     the target program is not type-checked by Anchor. Use `Program<'info, T>` \
                     in the accounts struct to enforce compile-time program ID validation.",
                    line_num,
                ),
                fix_recommendation:
                    "Replace the program `AccountInfo` with `Program<'info, TokenProgram>` \
                     or equivalent typed wrapper in the Anchor accounts struct."
                        .to_string(),
                cwe: Sec3Category::ArbitraryCPI.cwe().to_string(),
                fingerprint: utils::fingerprint(
                    &Sec3Category::ArbitraryCPI,
                    file_path,
                    line_num,
                    "cpi_context",
                ),
                source_snippet: Some(trimmed.to_string()),
                fix_diff: None,
            });
        }
    }
}

/// Check if there is a program ID validation within ±10 lines of the invoke call.
fn check_nearby_program_validation(lines: &[&str], invoke_line: usize) -> bool {
    let start = invoke_line.saturating_sub(10);
    let end = (invoke_line + 5).min(lines.len());

    for line in lines.iter().take(end).skip(start) {
        let line = line.to_lowercase();
        if line.contains("require_keys_eq!") && line.contains("program")
            || line.contains("assert_eq!") && line.contains("key()")
            || line.contains("program::id()")
            || line.contains("::id()") && line.contains("assert")
            || line.contains("program<'info")
        {
            return true;
        }
    }
    false
}

/// Find the enclosing function name for a given line index.
fn find_enclosing_function(lines: &[&str], line_idx: usize) -> String {
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
