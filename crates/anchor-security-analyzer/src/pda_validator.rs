//! PDA Validator -- AST-based Program Derived Address validation
//!
//! Walks `#[derive(Accounts)]` structs via `syn::visit::Visit` and checks:
//! - `seeds = [...]` without `bump` (non-canonical PDA derivation)
//! - `seeds` with hardcoded bump value instead of stored bump
//! - PDA accounts missing `seeds` constraint entirely when the type suggests PDA usage
//! - `find_program_address` calls without storing/checking the canonical bump
//! - Low-entropy seed patterns (no user/mint discriminator in seeds)

use crate::metrics::AnchorMetrics;
use crate::report::{AnchorFinding, AnchorSeverity, AnchorViolation};
use sha2::{Digest, Sha256};
use syn::visit::Visit;

pub struct PDAValidator;

impl PDAValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_pda(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
        metrics: &mut AnchorMetrics,
    ) -> Vec<AnchorFinding> {
        let mut visitor = PDAVisitor {
            file_path: file_path.to_string(),
            content: content.to_string(),
            findings: Vec::new(),
            metrics,
        };

        visitor.visit_file(syntax_tree);

        // Second pass: check function bodies for raw find_program_address without bump storage
        visitor.check_raw_pda_derivation();

        visitor.findings
    }
}

impl Default for PDAValidator {
    fn default() -> Self {
        Self::new()
    }
}

struct PDAVisitor<'a> {
    file_path: String,
    content: String,
    findings: Vec<AnchorFinding>,
    metrics: &'a mut AnchorMetrics,
}

impl<'ast> Visit<'ast> for PDAVisitor<'_> {
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

        for field in &node.fields {
            let field_name = match &field.ident {
                Some(ident) => ident.to_string(),
                None => continue,
            };

            let type_str = quote::quote!(#field.ty).to_string();

            // Collect all #[account(...)] attributes for this field
            let account_attrs: Vec<String> = field
                .attrs
                .iter()
                .filter(|attr| attr.path().is_ident("account"))
                .map(|attr| quote::quote!(#attr).to_string())
                .collect();

            let combined_attrs = account_attrs.join(" ");

            let has_seeds = combined_attrs.contains("seeds");
            let has_bump = combined_attrs.contains("bump");
            let has_init = combined_attrs.contains("init");

            // Check 1: seeds without bump -- non-canonical PDA
            if has_seeds && !has_bump {
                self.metrics.missing_pda_validation += 1;
                self.add_finding(
                    AnchorViolation::MissingBumpValidation,
                    AnchorSeverity::Critical,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` in `{}` uses `seeds = [...]` without `bump`. Anchor derives the PDA \
                         using `Pubkey::find_program_address()` which returns the canonical bump (the highest \
                         valid bump value 0-255). Without `bump` in the constraint, Anchor does not validate \
                         that the account's address matches the canonical derivation. An attacker can compute \
                         a non-canonical PDA (using a lower bump) at a different address and pass it as `{}`. \
                         This creates a separate account that bypasses uniqueness assumptions.",
                        field_name, struct_name, field_name,
                    ),
                );
            }

            // Check 2: seeds with hardcoded bump value (e.g., bump = 254) instead of stored bump
            if has_seeds && has_bump {
                // Check for hardcoded numeric bump values
                let bump_re = regex::Regex::new(r"bump\s*=\s*\d+").unwrap();
                if bump_re.is_match(&combined_attrs) {
                    self.add_finding(
                        AnchorViolation::MissingBumpValidation,
                        AnchorSeverity::High,
                        &struct_name,
                        &field_name,
                        format!(
                            "Field `{}` in `{}` uses a hardcoded bump value in `seeds` derivation. \
                             Hardcoded bumps are fragile: if the canonical bump changes (e.g., due to seed \
                             changes), this instruction silently derives a different address. Store the bump \
                             in the account data during `init` and reference it: `bump = account.bump`.",
                            field_name, struct_name,
                        ),
                    );
                }
            }

            // Check 3: Account type suggests PDA but no seeds constraint
            // Types like Account<'info, T> where T is a custom state are typically PDAs
            let is_pda_candidate = type_str.contains("Account <")
                && !type_str.contains("TokenAccount")
                && !type_str.contains("Mint")
                && !type_str.contains("SystemProgram")
                && !type_str.contains("Token")
                && !type_str.contains("Rent")
                && !type_str.contains("Clock");

            if is_pda_candidate && !has_seeds && has_init {
                self.metrics.missing_pda_validation += 1;
                self.add_finding(
                    AnchorViolation::MissingPDAValidation,
                    AnchorSeverity::High,
                    &struct_name,
                    &field_name,
                    format!(
                        "Field `{}` in `{}` uses `#[account(init)]` on a custom Account type without `seeds` \
                         derivation. If this account should be unique per user/mint/pool, it MUST be a PDA \
                         with appropriate seeds. Without seeds, the account address is determined by the \
                         caller's keypair, meaning:\n\
                         - No uniqueness enforcement (two callers can create separate accounts)\n\
                         - No deterministic address derivation (other instructions can't find it)\n\
                         Add `seeds = [b\"prefix\", user.key().as_ref()], bump` for per-user PDAs.",
                        field_name, struct_name,
                    ),
                );
            }

            // Check 4: Low-entropy seeds (only static seeds, no dynamic component)
            if has_seeds {
                // Check if seeds only contain string literals (b"...") and no dynamic refs
                let seeds_section = combined_attrs
                    .find("seeds")
                    .map(|start| &combined_attrs[start..])
                    .unwrap_or("");

                let has_dynamic_seed = seeds_section.contains(".key()")
                    || seeds_section.contains("as_ref()")
                    || seeds_section.contains(".to_le_bytes()")
                    || seeds_section.contains("& [");

                let has_static_seed = seeds_section.contains("b\"");

                if has_static_seed && !has_dynamic_seed {
                    self.add_finding(
                        AnchorViolation::MissingPDAValidation,
                        AnchorSeverity::Medium,
                        &struct_name,
                        &field_name,
                        format!(
                            "Field `{}` in `{}` derives a PDA using only static seeds (string literals). \
                             This creates a single global PDA shared by all users. If this account should be \
                             per-user, per-pool, or per-mint, include dynamic seeds like \
                             `user.key().as_ref()` or `mint.key().as_ref()` to partition the address space.",
                            field_name, struct_name,
                        ),
                    );
                }
            }
        }

        syn::visit::visit_item_struct(self, node);
    }
}

impl PDAVisitor<'_> {
    /// Check for raw `Pubkey::find_program_address` calls without bump storage
    fn check_raw_pda_derivation(&mut self) {
        for (i, line) in self.content.lines().enumerate() {
            if line.contains("find_program_address") {
                // Check if the result's bump (second tuple element) is stored
                let next_lines: String = self
                    .content
                    .lines()
                    .skip(i)
                    .take(5)
                    .collect::<Vec<_>>()
                    .join(" ");

                let stores_bump = next_lines.contains(".1")
                    || next_lines.contains("bump")
                    || next_lines.contains("_bump")
                    || next_lines.contains(", b)");

                if !stores_bump {
                    self.findings.push(AnchorFinding {
                        id: format!("ANC-RawPDA-{}", &self.fingerprint(i + 1, "raw_pda")[..8]),
                        violation: AnchorViolation::MissingBumpValidation,
                        severity: AnchorSeverity::High,
                        file_path: self.file_path.clone(),
                        line_number: i + 1,
                        struct_name: None,
                        field_name: None,
                        description: format!(
                            "Line {}: `Pubkey::find_program_address()` is called but the canonical bump \
                             (the `.1` return value) is not stored or used. The bump must be stored in \
                             account data to ensure future instructions can re-derive the same canonical \
                             address. Without storing the bump, instructions either re-derive it every time \
                             (wasting ~1500 compute units) or use a hardcoded value (fragile).",
                            i + 1,
                        ),
                        code_snippet: self.snippet_around(i + 1, 2),
                        risk_explanation: "PDA bump must be stored during account initialization and \
                            reused in subsequent instructions to ensure canonical address derivation."
                            .into(),
                        fix_recommendation:
                            "Store the bump during init:\n\
                             ```rust\n\
                             let (pda, bump) = Pubkey::find_program_address(&[seeds], program_id);\n\
                             account.bump = bump; // Store in account data\n\
                             ```\n\
                             Or use Anchor's built-in bump handling:\n\
                             ```rust\n\
                             #[account(init, seeds = [...], bump, payer = user, space = 8 + T::LEN)]\n\
                             ```"
                            .into(),
                        anchor_pattern: "seeds + bump derivation".into(),
                        cwe: "CWE-20".into(),
                        fingerprint: self.fingerprint(i + 1, "raw_pda"),
                    });
                }
            }
        }
    }

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

    fn risk_explanation(&self, violation: AnchorViolation) -> String {
        match violation {
            AnchorViolation::MissingBumpValidation => {
                "PDAs are derived deterministically from seeds and a bump value. The canonical bump \
                 is the highest value (0-255) that produces a valid off-curve point. Non-canonical bumps \
                 produce valid but different addresses. If bump is not validated, an attacker can use a \
                 non-canonical bump to create a second account at a different address, bypassing \
                 uniqueness assumptions and potentially double-claiming rewards or draining pools."
                    .into()
            }
            AnchorViolation::MissingPDAValidation => {
                "Without PDA seed derivation, account addresses are not deterministic. Other instructions \
                 cannot reliably locate the account, and there is no on-chain enforcement that the account \
                 belongs to a specific user, mint, or pool. This breaks composability and opens the door \
                 for account substitution attacks."
                    .into()
            }
            _ => "PDA security pattern violation.".into(),
        }
    }

    fn fix_recommendation(&self, violation: AnchorViolation, field_name: &str) -> String {
        match violation {
            AnchorViolation::MissingBumpValidation => {
                format!(
                    "Add `bump` to the seeds constraint and store it in the account:\n\
                     ```rust\n\
                     #[account(\n\
                         seeds = [b\"vault\", user.key().as_ref()],\n\
                         bump = {field}.bump,  // Use stored bump\n\
                     )]\n\
                     pub {field}: Account<'info, VaultState>,\n\
                     ```\n\
                     During init, Anchor auto-stores the canonical bump when you add `bump` to the constraint.",
                    field = field_name,
                )
            }
            AnchorViolation::MissingPDAValidation => {
                format!(
                    "Add seed derivation to create a deterministic, per-user PDA:\n\
                     ```rust\n\
                     #[account(\n\
                         init,\n\
                         seeds = [b\"state\", user.key().as_ref()],\n\
                         bump,\n\
                         payer = user,\n\
                         space = 8 + std::mem::size_of::<StateAccount>(),\n\
                     )]\n\
                     pub {field}: Account<'info, StateAccount>,\n\
                     ```",
                    field = field_name,
                )
            }
            _ => "Review Anchor PDA documentation.".into(),
        }
    }
}
