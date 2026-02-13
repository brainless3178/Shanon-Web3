//! Solana Account Invariant Generator
//!
//! Generates Solana-specific invariants by analyzing Anchor program structures.
//! Understands `#[account]`, `#[derive(Accounts)]`, Anchor constraints, and
//! common Solana patterns like PDA derivation, token accounts, and vault patterns.

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use syn::{Item, ItemStruct};

/// Generates Solana-specific account invariants from parsed source code.
pub struct SolanaInvariantGenerator;

impl SolanaInvariantGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate invariants from a single source file.
    pub fn generate_from_source(
        &self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<SolanaAccountInvariant>, crate::KaniError> {
        let file = syn::parse_file(source)
            .map_err(|e| crate::KaniError::ParseError(format!("{}: {}", filename, e)))?;

        let mut invariants = Vec::new();
        self.analyze_items(&file.items, filename, &mut invariants);
        Ok(invariants)
    }

    fn analyze_items(
        &self,
        items: &[Item],
        filename: &str,
        invariants: &mut Vec<SolanaAccountInvariant>,
    ) {
        for item in items {
            match item {
                Item::Struct(item_struct) => {
                    // Check for #[account] attribute (Anchor state account)
                    if self.is_anchor_account(item_struct) {
                        let inv = self.generate_account_invariant(item_struct, filename);
                        if !inv.constraints.is_empty() {
                            invariants.push(inv);
                        }
                    }

                    // Check for #[derive(Accounts)] (instruction context)
                    if self.is_accounts_context(item_struct) {
                        let inv = self.generate_context_invariant(item_struct, filename);
                        if !inv.constraints.is_empty() {
                            invariants.push(inv);
                        }
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        self.analyze_items(items, filename, invariants);
                    }
                }
                _ => {}
            }
        }
    }

    /// Generate invariants for an #[account] struct (Anchor state account).
    fn generate_account_invariant(
        &self,
        item_struct: &ItemStruct,
        filename: &str,
    ) -> SolanaAccountInvariant {
        let name = item_struct.ident.to_string();
        let mut fields = Vec::new();
        let mut constraints = Vec::new();
        let mut violations = Vec::new();

        // Extract fields and their types
        if let syn::Fields::Named(named) = &item_struct.fields {
            for field in &named.named {
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let field_type = field.ty.to_token_stream().to_string();

                fields.push((field_name.clone(), field_type.clone()));

                // Generate field-specific invariants
                self.generate_field_invariants(
                    &field_name,
                    &field_type,
                    &mut constraints,
                    &mut violations,
                );
            }
        }

        // Generate struct-level invariants
        self.generate_struct_level_invariants(&name, &fields, &mut constraints, &mut violations);

        SolanaAccountInvariant {
            account_name: name,
            source_file: filename.to_string(),
            fields,
            constraints,
            violations,
            account_type: AccountType::State,
        }
    }

    /// Generate invariants for a #[derive(Accounts)] context struct.
    fn generate_context_invariant(
        &self,
        item_struct: &ItemStruct,
        filename: &str,
    ) -> SolanaAccountInvariant {
        let name = item_struct.ident.to_string();
        let mut fields = Vec::new();
        let mut constraints = Vec::new();
        let mut violations = Vec::new();

        if let syn::Fields::Named(named) = &item_struct.fields {
            for field in &named.named {
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_default();
                let field_type = field.ty.to_token_stream().to_string();
                let attrs_str = field
                    .attrs
                    .iter()
                    .map(|a| a.to_token_stream().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");

                fields.push((field_name.clone(), field_type.clone()));

                // Analyze Anchor account constraints
                self.analyze_anchor_constraints(
                    &field_name,
                    &field_type,
                    &attrs_str,
                    &mut constraints,
                    &mut violations,
                );
            }
        }

        SolanaAccountInvariant {
            account_name: name,
            source_file: filename.to_string(),
            fields,
            constraints,
            violations,
            account_type: AccountType::InstructionContext,
        }
    }

    /// Generate field-level invariants based on type and naming.
    fn generate_field_invariants(
        &self,
        name: &str,
        field_type: &str,
        constraints: &mut Vec<String>,
        _violations: &mut Vec<String>,
    ) {
        // Balance fields must be non-negative (always true for unsigned, but checked for conservation)
        if name.contains("balance") || name.contains("amount") || name.contains("supply") {
            if field_type.contains("u64") || field_type.contains("u128") {
                constraints.push(format!(
                    "account.{name} <= u64::MAX / 2  /* Prevent overflow in arithmetic with {name} */"
                ));
            }
            if field_type.contains("i64") || field_type.contains("i128") {
                constraints.push(format!(
                    "account.{name} >= 0  /* Balance cannot be negative */"
                ));
            }
        }

        // Authority/admin fields must be a valid Pubkey
        if (name.contains("authority") || name.contains("admin") || name.contains("owner"))
            && field_type.contains("Pubkey") {
                constraints.push(format!(
                    "account.{name} != Pubkey::default()  /* Authority must be set to a real address */"
                ));
            }

        // Bump seed fields must be valid
        if name.contains("bump") {
            constraints.push(format!(
                "account.{name} <= 255  /* PDA bump must be in valid range */"
            ));
        }

        // Timestamp fields
        if (name.contains("timestamp") || name.contains("created_at") || name.contains("updated_at"))
            && (field_type.contains("i64") || field_type.contains("u64")) {
                constraints.push(format!(
                    "account.{name} > 0  /* Timestamp must be initialized */"
                ));
            }

        // Decimals fields
        if name == "decimals" {
            constraints.push(format!(
                "account.{name} <= 18  /* Token decimals must be reasonable */"
            ));
        }

        // Fee fields (basis points)
        if name.contains("fee") && (name.contains("bps") || name.contains("basis")) {
            constraints.push(format!(
                "account.{name} <= 10000  /* Fee in basis points must be <= 100% */"
            ));
        }

        // Ratio/percentage fields
        if (name.contains("ratio") || name.contains("percentage") || name.contains("rate"))
            && field_type.contains("u64") {
                constraints.push(format!(
                    "account.{name} <= 10000  /* Ratio/percentage must be bounded */"
                ));
            }
    }

    /// Generate struct-level invariants.
    fn generate_struct_level_invariants(
        &self,
        struct_name: &str,
        fields: &[(String, String)],
        constraints: &mut Vec<String>,
        violations: &mut Vec<String>,
    ) {
        // Check for balance pairs (e.g., total_supply == sum of individual balances)
        let balance_fields: Vec<&str> = fields
            .iter()
            .filter(|(name, _)| {
                name.contains("balance")
                    || name.contains("amount")
                    || name.contains("supply")
                    || name.contains("total")
            })
            .map(|(name, _)| name.as_str())
            .collect();

        if balance_fields.len() >= 2 {
            // If there's a "total" field and individual fields, assert conservation
            let total_field = balance_fields.iter().find(|f| f.contains("total"));
            let other_fields: Vec<&&str> = balance_fields
                .iter()
                .filter(|f| !f.contains("total"))
                .collect();

            if let Some(total) = total_field {
                if !other_fields.is_empty() {
                    let sum_expr = other_fields
                        .iter()
                        .map(|f| format!("account.{}", f))
                        .collect::<Vec<_>>()
                        .join(" + ");
                    constraints.push(format!(
                        "account.{total} >= {sum_expr}  /* Total must be >= sum of parts */"
                    ));
                }
            }
        }

        // Check for authority field — account must have an owner
        let has_authority = fields.iter().any(|(name, _)| {
            name.contains("authority") || name.contains("admin") || name.contains("owner")
        });

        if !has_authority {
            violations.push(format!(
                "Account '{}' has no authority/owner field — state may be unguarded",
                struct_name
            ));
        }

        // Check for discriminator support (Anchor adds this automatically, but custom programs may not)
        let _has_discriminator = fields
            .iter()
            .any(|(name, _)| name.contains("discriminator"));
        // Anchor handles this automatically, so no violation needed for Anchor programs
    }

    /// Analyze Anchor account constraints from field attributes.
    fn analyze_anchor_constraints(
        &self,
        field_name: &str,
        field_type: &str,
        attrs_str: &str,
        constraints: &mut Vec<String>,
        violations: &mut Vec<String>,
    ) {
        // Check for Signer constraint
        if field_type.contains("Signer") {
            constraints.push(format!(
                "{field_name}.is_signer == true  /* Anchor Signer type enforces signer check */"
            ));
        }

        // Check for mut constraint on mutable accounts
        if attrs_str.contains("mut") {
            constraints.push(format!(
                "{field_name} is writable  /* Account marked as mutable */"
            ));
        }

        // Check for has_one constraint
        if attrs_str.contains("has_one") {
            constraints.push(format!(
                "{field_name} has_one constraint enforced  /* Ownership/relationship validated */"
            ));
        }

        // Check for seeds/PDA constraint
        if attrs_str.contains("seeds") {
            constraints.push(format!(
                "{field_name} PDA validated via seeds  /* PDA derivation checked */"
            ));
        }

        // Check for init constraint
        if attrs_str.contains("init") {
            constraints.push(format!(
                "{field_name} initialized atomically  /* Account creation validated */"
            ));
        }

        // Check for constraint expression
        if attrs_str.contains("constraint") {
            constraints.push(format!(
                "{field_name} custom constraint active  /* User-defined constraint applied */"
            ));
        }

        // Detect potential issues

        // Token accounts without associated constraint
        if (field_type.contains("TokenAccount") || field_type.contains("Account<'_, TokenAccount>"))
            && !attrs_str.contains("associated_token") && !attrs_str.contains("token ::") {
                violations.push(format!(
                    "Token account '{}' may lack association constraint — token substitution attack possible",
                    field_name
                ));
            }

        // Mutable accounts without ownership check
        if attrs_str.contains("mut")
            && !attrs_str.contains("has_one")
            && !attrs_str.contains("constraint")
            && !field_type.contains("Signer") && !field_type.contains("SystemProgram") {
                violations.push(format!(
                    "Mutable account '{}' lacks has_one or constraint — unauthorized mutation possible",
                    field_name
                ));
            }

        // Unchecked accounts
        if (field_type.contains("UncheckedAccount") || field_type.contains("AccountInfo"))
            && !attrs_str.contains("CHECK") && !attrs_str.contains("constraint") {
                violations.push(format!(
                    "Unchecked account '{}' has no safety documentation — account confusion attack possible",
                    field_name
                ));
            }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    fn is_anchor_account(&self, item_struct: &ItemStruct) -> bool {
        item_struct.attrs.iter().any(|attr| {
            let s = attr.to_token_stream().to_string();
            s.contains("#[account") && !s.contains("Accounts")
        })
    }

    fn is_accounts_context(&self, item_struct: &ItemStruct) -> bool {
        item_struct.attrs.iter().any(|attr| {
            let s = attr.to_token_stream().to_string();
            s.contains("Accounts") || s.contains("derive(Accounts)")
        })
    }
}

impl Default for SolanaInvariantGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// A Solana account invariant with all its constraints and potential violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaAccountInvariant {
    /// Account struct name
    pub account_name: String,
    /// Source file
    pub source_file: String,
    /// Field names and types
    pub fields: Vec<(String, String)>,
    /// Constraints that must hold
    pub constraints: Vec<String>,
    /// Detected violations / missing checks
    pub violations: Vec<String>,
    /// Type of account (state vs instruction context)
    pub account_type: AccountType,
}

/// Type of Solana account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccountType {
    /// State account (`#[account]`)
    State,
    /// Instruction context (#[derive(Accounts)])
    InstructionContext,
}
