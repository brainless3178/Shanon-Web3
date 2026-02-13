//! **PDA Validator** — detects insecure Program Derived Address (PDA) usage.
//!
//! PDA vulnerabilities include:
//! - Seeds that lack sufficient entropy (e.g., single static seed) allowing
//!   cross-user collisions.
//! - Missing canonical bump validation (`bump = <field>` without `seeds::program`).
//! - Seeds using mutable or attacker-controlled data.
//! - Missing `seeds` constraint on accounts expected to be PDAs.

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

                    let attrs_text = utils::attrs_to_string(&field.attrs);
                    let has_seeds = attrs_text.contains("seeds");
                    let has_bump = attrs_text.contains("bump");
                    let has_init = attrs_text.contains("init");

                    // Check for PDA-like names without seeds constraint
                    let is_pda_name = field_name.contains("pda")
                        || field_name.contains("vault")
                        || field_name.contains("pool")
                        || field_name.contains("config")
                        || field_name.contains("state")
                        || field_name.contains("escrow")
                        || field_name.contains("treasury");

                    let ty_str = utils::type_to_string(&field.ty);
                    let is_typed_account = ty_str.contains("Account<");

                    if has_seeds {
                        // Check for insufficient seed entropy
                        let seed_count = count_seeds(&attrs_text);

                        if seed_count <= 1 && !attrs_text.contains("b\"") {
                            let line = utils::span_start_line(content, field);
                            findings.push(Sec3Finding {
                                id: utils::generate_finding_id("SEC3", &Sec3Category::InsecurePDADerivation, file_path, line),
                                category: Sec3Category::InsecurePDADerivation,
                                severity: Sec3Severity::High,
                                file_path: file_path.to_string(),
                                line_number: line,
                                instruction: instruction_name.clone(),
                                account_name: Some(field_name.clone()),
                                description: format!(
                                    "PDA '{}' in instruction '{}' derives from only {} seed(s). \
                                     Insufficient seed entropy allows different users or contexts \
                                     to collide on the same PDA address, potentially accessing \
                                     each other's state data.",
                                    field_name, instruction_name, seed_count,
                                ),
                                fix_recommendation: format!(
                                    "Add user-specific seeds to the PDA derivation for '{}'. \
                                     Example: `seeds = [b\"vault\", user.key().as_ref()]` to ensure \
                                     per-user address isolation.",
                                    field_name,
                                ),
                                cwe: Sec3Category::InsecurePDADerivation.cwe().to_string(),
                                fingerprint: utils::fingerprint(&Sec3Category::InsecurePDADerivation, file_path, line, &instruction_name),
                                source_snippet: utils::extract_snippet(content, line),
                                fix_diff: None,
                            });
                        }

                        // Check for seeds without bump (non-canonical PDA)
                        if !has_bump && !has_init {
                            let line = utils::span_start_line(content, field);
                            findings.push(Sec3Finding {
                                id: utils::generate_finding_id(
                                    "SEC3",
                                    &Sec3Category::InsecurePDADerivation,
                                    file_path,
                                    line,
                                ),
                                category: Sec3Category::InsecurePDADerivation,
                                severity: Sec3Severity::Medium,
                                file_path: file_path.to_string(),
                                line_number: line,
                                instruction: instruction_name.clone(),
                                account_name: Some(field_name.clone()),
                                description: format!(
                                    "PDA '{}' in instruction '{}' has `seeds` but no `bump` — \
                                     Anchor will try to find_program_address at runtime, which is \
                                     expensive (costs ~1500 CU per attempt). Store the bump in the \
                                     account data for deterministic derivation.",
                                    field_name, instruction_name,
                                ),
                                fix_recommendation: format!(
                                    "Add `bump = {name}.bump` to the constraint (requires storing \
                                     the bump in account data), or `bump` alone to let Anchor \
                                     derive it.",
                                    name = field_name,
                                ),
                                cwe: Sec3Category::InsecurePDADerivation.cwe().to_string(),
                                fingerprint: utils::fingerprint(
                                    &Sec3Category::InsecurePDADerivation,
                                    file_path,
                                    line,
                                    &instruction_name,
                                ),
                                source_snippet: utils::extract_snippet(content, line),
                                fix_diff: None,
                            });
                        }
                    } else if is_pda_name && is_typed_account && !has_seeds {
                        // PDA-named account without seeds validation
                        let line = utils::span_start_line(content, field);
                        findings.push(Sec3Finding {
                            id: utils::generate_finding_id("SEC3", &Sec3Category::InsecurePDADerivation, file_path, line),
                            category: Sec3Category::InsecurePDADerivation,
                            severity: Sec3Severity::High,
                            file_path: file_path.to_string(),
                            line_number: line,
                            instruction: instruction_name.clone(),
                            account_name: Some(field_name.clone()),
                            description: format!(
                                "Account '{}' in instruction '{}' appears to be a PDA (by naming \
                                 convention) but has no `seeds` constraint — Anchor will not verify \
                                 the account was derived from the expected seeds. An attacker can \
                                 pass a PDA from a different seed set or program.",
                                field_name, instruction_name,
                            ),
                            fix_recommendation: format!(
                                "Add `#[account(seeds = [b\"expected_seed\", ...], bump)]` to \
                                 '{}' to enforce PDA address derivation at runtime.",
                                field_name,
                            ),
                            cwe: Sec3Category::InsecurePDADerivation.cwe().to_string(),
                            fingerprint: utils::fingerprint(&Sec3Category::InsecurePDADerivation, file_path, line, &instruction_name),
                            source_snippet: utils::extract_snippet(content, line),
                            fix_diff: None,
                        });
                    }
                }
            }
        }
    }
}

/// Count the number of seed expressions in a `seeds = [...]` constraint.
fn count_seeds(attrs_text: &str) -> usize {
    if let Some(seeds_start) = attrs_text.find("seeds") {
        let after_seeds = &attrs_text[seeds_start..];
        if let Some(bracket_start) = after_seeds.find('[') {
            if let Some(bracket_end) = after_seeds[bracket_start..].find(']') {
                let seeds_content = &after_seeds[bracket_start + 1..bracket_start + bracket_end];
                // Count comma-separated seeds
                return seeds_content
                    .split(',')
                    .filter(|s| !s.trim().is_empty())
                    .count();
            }
        }
    }
    0
}
