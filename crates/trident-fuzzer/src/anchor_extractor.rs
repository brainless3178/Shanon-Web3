//! Anchor Program Model Extractor
//!
//! Parses Solana Anchor program source code to extract a structured model
//! of instructions, accounts, constraints, and PDA derivations — the
//! prerequisite for Trident fuzz harness generation.

use serde::{Deserialize, Serialize};
use syn::{visit::Visit, Attribute, Fields, File, ItemFn, ItemStruct};
use tracing::debug;

// ─── Extractor ───────────────────────────────────────────────────────────────

/// Extracts an `AnchorProgramModel` from Anchor Rust source code.
pub struct AnchorExtractor {
    _private: (),
}

impl AnchorExtractor {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Extract Anchor instructions, accounts, and constraints from source.
    pub fn extract_from_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<AnchorProgramModel, String> {
        let file: File =
            syn::parse_file(source).map_err(|e| format!("Failed to parse {}: {}", filename, e))?;

        let mut visitor = AnchorVisitor {
            filename: filename.to_string(),
            _source: source.to_string(),
            model: AnchorProgramModel::default(),
        };

        visitor.visit_file(&file);

        Ok(visitor.model)
    }
}

impl Default for AnchorExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AST Visitor ─────────────────────────────────────────────────────────────

struct AnchorVisitor {
    filename: String,
    _source: String,
    model: AnchorProgramModel,
}

impl<'ast> Visit<'ast> for AnchorVisitor {
    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        // Detect Anchor account context structs: #[derive(Accounts)]
        let is_accounts_struct = item.attrs.iter().any(|attr| {
            if attr.path().is_ident("derive") {
                let tokens = attr
                    .meta
                    .require_list()
                    .ok()
                    .map(|list| list.tokens.to_string());
                if let Some(t) = tokens {
                    return t.contains("Accounts");
                }
            }
            false
        });

        if is_accounts_struct {
            self.extract_accounts_struct(item);
        }

        // Detect Anchor state/account data structs: #[account]
        let is_account_data = item
            .attrs
            .iter()
            .any(|attr| attr.path().is_ident("account"));
        if is_account_data {
            self.extract_account_data(item);
        }

        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        // Functions inside #[program] module are instructions
        // We detect by naming convention and presence of Context<> parameter
        let fn_name = item.sig.ident.to_string();

        let has_context_param = item.sig.inputs.iter().any(|arg| {
            let arg_str = quote::quote!(#arg).to_string();
            arg_str.contains("Context")
        });

        if has_context_param {
            let body_str = quote::quote!(#item).to_string();
            let has_arithmetic = body_str.contains('+')
                || body_str.contains('-')
                || body_str.contains('*')
                || body_str.contains('/');

            let uses_checked_math = body_str.contains("checked_add")
                || body_str.contains("checked_sub")
                || body_str.contains("checked_mul")
                || body_str.contains("checked_div")
                || body_str.contains("saturating_add")
                || body_str.contains("saturating_sub");

            let has_cpi = body_str.contains("invoke") || body_str.contains("CpiContext");

            let validates_cpi_program_id = body_str.contains("require_keys_eq")
                || body_str.contains("program_id")
                || (has_cpi && body_str.contains("program.key()"));

            let has_transfer = body_str.contains("transfer")
                || body_str.contains("lamports")
                || body_str.contains("token::transfer");

            let instruction = AnchorInstruction {
                name: fn_name.clone(),
                source_file: self.filename.clone(),
                accounts: Vec::new(), // filled by struct extraction
                has_arithmetic,
                uses_checked_math,
                has_cpi,
                validates_cpi_program_id,
                has_transfer,
                parameters: self.extract_parameters(item),
            };

            self.model.instructions.push(instruction);
        }

        syn::visit::visit_item_fn(self, item);
    }
}

impl AnchorVisitor {
    /// Extract accounts from an Anchor `#[derive(Accounts)]` struct.
    fn extract_accounts_struct(&mut self, item: &ItemStruct) {
        let struct_name = item.ident.to_string();

        if let Fields::Named(ref fields) = item.fields {
            for field in &fields.named {
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();

                let field_type = quote::quote!(#field.ty).to_string().replace(" ", "");

                // Extract constraints from #[account(...)] attributes
                let constraints = self.extract_constraints(&field.attrs);

                let is_signer = field_type.contains("Signer")
                    || constraints
                        .iter()
                        .any(|c| matches!(c, AnchorConstraint::Signer));

                let is_mut = constraints
                    .iter()
                    .any(|c| matches!(c, AnchorConstraint::Mut));

                let account_type = if field_type.contains("Account<") {
                    // Extract inner type: Account<'info, TokenAccount> -> TokenAccount
                    let inner = field_type
                        .split(',')
                        .nth(1)
                        .unwrap_or(&field_type)
                        .trim_end_matches('>')
                        .trim()
                        .to_string();
                    inner
                } else if field_type.contains("Signer") {
                    "Signer".to_string()
                } else if field_type.contains("SystemAccount") {
                    "SystemAccount".to_string()
                } else if field_type.contains("Program") {
                    "Program".to_string()
                } else if field_type.contains("UncheckedAccount")
                    || field_type.contains("AccountInfo")
                {
                    "AccountInfo".to_string()
                } else {
                    field_type.clone()
                };

                let account = AnchorAccount {
                    name: field_name.clone(),
                    account_type,
                    raw_type: field_type,
                    is_signer,
                    is_mut,
                    constraints: constraints.clone(),
                    context_struct: struct_name.clone(),
                };

                self.model.accounts.push(account.clone());

                // Extract PDA derivations from seeds constraint
                for constraint in &constraints {
                    if let AnchorConstraint::Seeds(seeds) = constraint {
                        self.model.pda_derivations.push(PdaDerivation {
                            account_name: field_name.clone(),
                            seeds: seeds.clone(),
                            instruction: struct_name.clone(),
                            bump_seed: constraints
                                .iter()
                                .any(|c| matches!(c, AnchorConstraint::Bump(_))),
                        });
                    }
                }
            }
        }
    }

    /// Extract Anchor account data struct (token layout, state schema).
    fn extract_account_data(&mut self, item: &ItemStruct) {
        let struct_name = item.ident.to_string();
        if let Fields::Named(ref fields) = item.fields {
            let field_names: Vec<String> = fields
                .named
                .iter()
                .filter_map(|f| f.ident.as_ref().map(|i| i.to_string()))
                .collect();

            debug!(
                "Trident: Found account data struct '{}' with fields: {:?}",
                struct_name, field_names
            );
        }
    }

    /// Extract `#[account(...)]` constraints from field attributes.
    fn extract_constraints(&self, attrs: &[Attribute]) -> Vec<AnchorConstraint> {
        let mut constraints = Vec::new();

        for attr in attrs {
            if !attr.path().is_ident("account") {
                continue;
            }

            let tokens = match attr.meta.require_list() {
                Ok(list) => list.tokens.to_string(),
                Err(_) => continue,
            };

            let lower = tokens.to_lowercase();

            if lower.contains("init_if_needed") {
                constraints.push(AnchorConstraint::InitIfNeeded);
            } else if lower.contains("init") {
                constraints.push(AnchorConstraint::Init);
            }

            if lower.contains("mut") {
                constraints.push(AnchorConstraint::Mut);
            }

            if lower.contains("signer") {
                constraints.push(AnchorConstraint::Signer);
            }

            if lower.contains("has_one") {
                let field = tokens
                    .split("has_one")
                    .nth(1)
                    .and_then(|s| s.split(|c: char| !c.is_alphanumeric() && c != '_').nth(1))
                    .unwrap_or("unknown")
                    .to_string();
                constraints.push(AnchorConstraint::HasOne(field));
            }

            if lower.contains("close") {
                let target = tokens
                    .split("close")
                    .nth(1)
                    .and_then(|s| s.split(|c: char| !c.is_alphanumeric() && c != '_').nth(1))
                    .unwrap_or("unknown")
                    .to_string();
                constraints.push(AnchorConstraint::Close(target));
            }

            if lower.contains("seeds") {
                // Extract seed expressions
                let seeds = self.parse_seeds(&tokens);
                constraints.push(AnchorConstraint::Seeds(seeds));
            }

            if lower.contains("bump") {
                let bump_field = tokens
                    .split("bump")
                    .nth(1)
                    .and_then(|s| s.split(|c: char| !c.is_alphanumeric() && c != '_').nth(1))
                    .map(|s| s.to_string());
                constraints.push(AnchorConstraint::Bump(bump_field));
            }

            if lower.contains("constraint") || lower.contains("require") {
                constraints.push(AnchorConstraint::Custom(tokens.clone()));
            }

            if lower.contains("token::mint") || lower.contains("token::authority") {
                constraints.push(AnchorConstraint::TokenConstraint(tokens.clone()));
            }

            if lower.contains("associated_token") {
                constraints.push(AnchorConstraint::AssociatedToken);
            }
        }

        constraints
    }

    /// Parse seeds from `seeds = [b"...", user.key().as_ref()]` expressions.
    fn parse_seeds(&self, tokens: &str) -> Vec<String> {
        let mut seeds = Vec::new();

        if let Some(start) = tokens.find("seeds") {
            let after = &tokens[start..];
            if let Some(bracket_start) = after.find('[') {
                if let Some(bracket_end) = after.find(']') {
                    let seed_content = &after[bracket_start + 1..bracket_end];
                    for seed in seed_content.split(',') {
                        let trimmed = seed.trim().to_string();
                        if !trimmed.is_empty() {
                            seeds.push(trimmed);
                        }
                    }
                }
            }
        }

        seeds
    }

    /// Extract function parameters (excluding Context<>).
    fn extract_parameters(&self, item: &ItemFn) -> Vec<(String, String)> {
        let mut params = Vec::new();

        for arg in &item.sig.inputs {
            let arg_str = quote::quote!(#arg).to_string();
            if arg_str.contains("Context") || arg_str.contains("self") {
                continue;
            }
            // Parse "name: Type" pattern
            let parts: Vec<&str> = arg_str.splitn(2, ':').collect();
            if parts.len() == 2 {
                params.push((parts[0].trim().to_string(), parts[1].trim().to_string()));
            }
        }

        params
    }
}

// ─── Data Model ──────────────────────────────────────────────────────────────

/// Complete model of an Anchor program, extracted from source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnchorProgramModel {
    /// Program name (from `declare_id!()` or directory name)
    pub program_name: String,
    /// All discovered instructions
    pub instructions: Vec<AnchorInstruction>,
    /// All account fields from `#[derive(Accounts)]` structs
    pub accounts: Vec<AnchorAccount>,
    /// PDA derivation metadata
    pub pda_derivations: Vec<PdaDerivation>,
}

impl AnchorProgramModel {
    /// Merge another partial model into this one.
    pub fn merge(&mut self, other: AnchorProgramModel) {
        self.instructions.extend(other.instructions);
        self.accounts.extend(other.accounts);
        self.pda_derivations.extend(other.pda_derivations);
        if self.program_name.is_empty() && !other.program_name.is_empty() {
            self.program_name = other.program_name;
        }
    }
}

/// An Anchor instruction (handler function).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorInstruction {
    pub name: String,
    pub source_file: String,
    pub accounts: Vec<AnchorAccount>,
    pub has_arithmetic: bool,
    pub uses_checked_math: bool,
    pub has_cpi: bool,
    pub validates_cpi_program_id: bool,
    pub has_transfer: bool,
    pub parameters: Vec<(String, String)>,
}

/// An Anchor account field within a Derive(Accounts) struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorAccount {
    pub name: String,
    pub account_type: String,
    pub raw_type: String,
    pub is_signer: bool,
    pub is_mut: bool,
    pub constraints: Vec<AnchorConstraint>,
    pub context_struct: String,
}

/// Anchor constraint on an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnchorConstraint {
    Init,
    InitIfNeeded,
    Mut,
    Signer,
    HasOne(String),
    Close(String),
    Seeds(Vec<String>),
    Bump(Option<String>),
    Custom(String),
    TokenConstraint(String),
    AssociatedToken,
}

/// PDA derivation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdaDerivation {
    pub account_name: String,
    pub seeds: Vec<String>,
    pub instruction: String,
    pub bump_seed: bool,
}
