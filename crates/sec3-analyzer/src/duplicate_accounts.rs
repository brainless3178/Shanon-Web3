//! **Duplicate Mutable Accounts Detector** — flags instructions where the
//! same account can be passed for two distinct mutable parameters.
//!
//! If an instruction takes two `mut` accounts (e.g., `source` and `destination`)
//! without an explicit `constraint = source.key() != destination.key()` check,
//! an attacker can pass the **same** account for both. This can lead to:
//! - Double-counting balances (self-transfer inflates total)
//! - State corruption from aliased mutable references
//!
//! CWE-362: Concurrent Execution Using Shared Resource.

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
            let mut mut_accounts: Vec<(String, usize)> = Vec::new();

            if let syn::Fields::Named(ref fields) = s.fields {
                // Collect all mutable accounts
                for field in &fields.named {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    let attrs_text = utils::attrs_to_string(&field.attrs);
                    let ty_str = utils::type_to_string(&field.ty);

                    let is_mut = attrs_text.contains("mut") && !attrs_text.contains("immut");
                    let is_account_type = ty_str.contains("Account<")
                        || ty_str.contains("AccountInfo")
                        || ty_str.contains("UncheckedAccount<");

                    if is_mut && is_account_type {
                        let line = utils::span_start_line(content, field);
                        mut_accounts.push((field_name, line));
                    }
                }

                // Check for constraint ensuring distinct keys between mut pairs
                if mut_accounts.len() >= 2 {
                    let all_constraints: String = fields
                        .named
                        .iter()
                        .map(|f| utils::attrs_to_string(&f.attrs))
                        .collect::<Vec<_>>()
                        .join(" ");

                    for i in 0..mut_accounts.len() {
                        for j in (i + 1)..mut_accounts.len() {
                            let (ref name_a, _) = mut_accounts[i];
                            let (ref name_b, line_b) = mut_accounts[j];

                            // Check if there's a key-inequality constraint
                            let has_distinct_check = all_constraints
                                .contains(&format!("{}.key() != {}.key()", name_a, name_b))
                                || all_constraints
                                    .contains(&format!("{}.key() != {}.key()", name_b, name_a))
                                || all_constraints.contains(&format!(
                                    "require_keys_neq!({}, {})",
                                    name_a, name_b
                                ))
                                || all_constraints.contains(&format!(
                                    "require_keys_neq!({}, {})",
                                    name_b, name_a
                                ));

                            // Check if they are semantically related (source/dest, from/to, etc.)
                            let are_related = are_semantically_related(name_a, name_b);

                            if !has_distinct_check && are_related {
                                findings.push(Sec3Finding {
                                    id: utils::generate_finding_id("SEC3", &Sec3Category::DuplicateMutableAccounts, file_path, line_b),
                                    category: Sec3Category::DuplicateMutableAccounts,
                                    severity: Sec3Severity::High,
                                    file_path: file_path.to_string(),
                                    line_number: line_b,
                                    instruction: instruction_name.clone(),
                                    account_name: Some(format!("{} / {}", name_a, name_b)),
                                    description: format!(
                                        "Mutable accounts '{}' and '{}' in instruction '{}' have no \
                                         constraint ensuring they are distinct. An attacker can pass \
                                         the same account for both parameters, causing double-counting \
                                         or state corruption through aliased mutable references.",
                                        name_a, name_b, instruction_name,
                                    ),
                                    fix_recommendation: format!(
                                        "Add a constraint ensuring distinct accounts:\n\
                                         `#[account(constraint = {}.key() != {}.key() @ \
                                         ErrorCode::DuplicateAccounts)]`",
                                        name_a, name_b,
                                    ),
                                    cwe: Sec3Category::DuplicateMutableAccounts.cwe().to_string(),
                                    fingerprint: utils::fingerprint(
                                        &Sec3Category::DuplicateMutableAccounts, file_path, line_b, &instruction_name,
                                    ),
                                    source_snippet: None,
                                    fix_diff: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Check if two field names are semantically related (source/dest pairs).
fn are_semantically_related(a: &str, b: &str) -> bool {
    let pairs = [
        ("source", "destination"),
        ("source", "dest"),
        ("from", "to"),
        ("sender", "receiver"),
        ("sender", "recipient"),
        ("input", "output"),
        ("user", "vault"),
        ("deposit", "withdraw"),
        ("token_a", "token_b"),
        ("base", "quote"),
        ("pool", "user"),
    ];

    let la = a.to_lowercase();
    let lb = b.to_lowercase();

    for (pa, pb) in &pairs {
        if (la.contains(pa) && lb.contains(pb)) || (la.contains(pb) && lb.contains(pa)) {
            return true;
        }
    }

    // Same base name with _a/_b suffix or _1/_2
    let stripped_a =
        la.trim_end_matches(|c: char| c == 'a' || c == 'b' || c.is_numeric() || c == '_');
    let stripped_b =
        lb.trim_end_matches(|c: char| c == 'a' || c == 'b' || c.is_numeric() || c == '_');
    if !stripped_a.is_empty() && stripped_a == stripped_b && la != lb {
        return true;
    }

    false
}
