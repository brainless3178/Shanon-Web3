//! Invariant Extractor
//!
//! Deeply parses Solana/Anchor Rust source using the `syn` crate to extract
//! program invariants that should hold across all states. These invariants
//! are then turned into Kani proof harnesses.

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use syn::{File, Item, ItemFn};

/// Extracts invariants from Solana program source code via AST analysis.
pub struct InvariantExtractor {
    /// Tracks seen function names to avoid duplicate invariants
    seen_functions: HashSet<String>,
    /// Mapping from account struct name → fields (name, type, attributes)
    account_schemas: HashMap<String, Vec<(String, String, String)>>,
}

impl InvariantExtractor {
    pub fn new() -> Self {
        Self {
            seen_functions: HashSet::new(),
            account_schemas: HashMap::new(),
        }
    }

    /// Extract invariants from a Rust source file.
    pub fn extract_from_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<ExtractedInvariant>, crate::KaniError> {
        let file = syn::parse_file(source)
            .map_err(|e| crate::KaniError::ParseError(format!("{}: {}", filename, e)))?;

        let mut invariants = Vec::new();

        // Phase 1: Collect account schemas
        self.collect_account_schemas(&file);

        // Phase 2: Extract function-level invariants
        self.extract_function_invariants(&file, filename, &mut invariants);

        // Phase 3: Extract struct-level invariants
        self.extract_struct_invariants(&file, filename, &mut invariants);

        // Phase 4: Extract impl-block invariants
        self.extract_impl_invariants(&file, filename, &mut invariants);

        Ok(invariants)
    }

    /// Collect all account struct definitions.
    fn collect_account_schemas(&mut self, file: &File) {
        for item in &file.items {
            if let Item::Struct(item_struct) = item {
                let has_account_attr = item_struct.attrs.iter().any(|attr| {
                    let path_str = attr.path().to_token_stream().to_string();
                    path_str.contains("account") || path_str.contains("Account")
                });

                let has_derive_accounts = item_struct.attrs.iter().any(|attr| {
                    let full = attr.to_token_stream().to_string();
                    full.contains("Accounts") || full.contains("account")
                });

                if has_account_attr || has_derive_accounts {
                    let name = item_struct.ident.to_string();
                    let fields: Vec<(String, String, String)> =
                        if let syn::Fields::Named(named) = &item_struct.fields {
                            named
                                .named
                                .iter()
                                .filter_map(|f| {
                                    f.ident.as_ref().map(|id| {
                                        let attrs_str = f.attrs.iter()
                                            .map(|a| a.to_token_stream().to_string())
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        (id.to_string(), f.ty.to_token_stream().to_string(), attrs_str)
                                    })
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                    self.account_schemas.insert(name, fields);
                }
            }

            // Also descend into modules
            if let Item::Mod(item_mod) = item {
                if let Some((_, items)) = &item_mod.content {
                    let inner_file = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: items.clone(),
                    };
                    self.collect_account_schemas(&inner_file);
                }
            }
        }
    }

    /// Extract invariants from functions in the AST.
    fn extract_function_invariants(
        &mut self,
        file: &File,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        for item in &file.items {
            match item {
                Item::Fn(func) => {
                    self.analyze_function(func, filename, invariants);
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        let inner_file = File {
                            shebang: None,
                            attrs: Vec::new(),
                            items: items.clone(),
                        };
                        self.extract_function_invariants(&inner_file, filename, invariants);
                    }
                }
                Item::Impl(item_impl) => {
                    for impl_item in &item_impl.items {
                        if let syn::ImplItem::Fn(method) = impl_item {
                            let func_code = method.to_token_stream().to_string();
                            let func_name = method.sig.ident.to_string();

                            // Create a synthetic ItemFn for analysis
                            self.analyze_method_code(&func_name, &func_code, filename, invariants);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Look up the `#[derive(Accounts)]` struct named in a `Context<T>` parameter
    /// and return (has_signer, has_owner, has_pda) based on struct-level constraints.
    fn lookup_struct_signals(&self, text: &str) -> (bool, bool, bool) {
        use once_cell::sync::Lazy;
        static CONTEXT_RE: Lazy<regex::Regex> = Lazy::new(|| {
            // Handles `Context<T>`, `Context<'info, T>`, and quote! spaced variants
            regex::Regex::new(r"Context\s*<\s*(?:'\s*\w+\s*,\s*)?([A-Z]\w*)").unwrap()
        });

        let mut has_signer = false;
        let mut has_owner = false;
        let mut has_pda = false;

        if let Some(caps) = CONTEXT_RE.captures(text) {
            let struct_name = caps.get(1).unwrap().as_str();
            if let Some(fields) = self.account_schemas.get(struct_name) {
                for (_field_name, field_type, field_attrs) in fields {
                    if field_type.contains("Signer")
                        || field_attrs.contains("signer")
                        || field_attrs.contains("has_one")
                        || field_attrs.contains("constraint")
                    {
                        has_signer = true;
                    }
                    if field_type.contains("Account <")
                        || field_type.contains("Account<")
                        || field_attrs.contains("has_one")
                        || field_attrs.contains("owner")
                        || field_attrs.contains("constraint")
                    {
                        has_owner = true;
                    }
                    if field_attrs.contains("seeds")
                        || field_attrs.contains("bump")
                    {
                        has_pda = true;
                    }
                }
            }
        }

        (has_signer, has_owner, has_pda)
    }

    /// Check struct constraints from a parsed function.
    fn check_struct_constraints(&self, func: &ItemFn) -> (bool, bool, bool) {
        for arg in &func.sig.inputs {
            let arg_str = arg.to_token_stream().to_string();
            let signals = self.lookup_struct_signals(&arg_str);
            if signals.0 || signals.1 || signals.2 {
                return signals;
            }
        }
        (false, false, false)
    }

    /// Check struct constraints from a code string (for impl methods).
    fn check_struct_constraints_from_code(&self, func_code: &str) -> (bool, bool, bool) {
        self.lookup_struct_signals(func_code)
    }

    /// Analyze a single function for invariant patterns.
    fn analyze_function(
        &mut self,
        func: &ItemFn,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        let func_name = func.sig.ident.to_string();
        let func_code = func.to_token_stream().to_string();
        let line_number = func.sig.ident.span().start().line;

        if self.seen_functions.contains(&func_name) {
            return;
        }
        self.seen_functions.insert(func_name.clone());

        // Check for Context<T> parameter (Anchor instruction handler)
        let is_instruction = func.sig.inputs.iter().any(|arg| {
            let arg_str = arg.to_token_stream().to_string();
            arg_str.contains("Context")
        });

        // Detect arithmetic patterns
        let has_unchecked_arith = Self::detect_unchecked_arithmetic(&func_code);
        let has_checked_arith = Self::detect_checked_arithmetic(&func_code);

        if has_unchecked_arith {
            invariants.push(ExtractedInvariant {
                name: format!("{}_arithmetic_safety", func_name),
                kind: InvariantKind::ArithmeticBounds,
                expression: format!(
                    "All arithmetic in '{}' must not overflow/underflow at u64 boundary",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: has_checked_arith,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: if has_checked_arith { 3 } else { 5 },
                confidence: if has_unchecked_arith && !has_checked_arith {
                    95
                } else {
                    60
                },
                related_accounts: Vec::new(),
            });
        }

        // Detect signer/authority patterns — check BOTH function body AND associated struct
        let (struct_has_signer, struct_has_owner, struct_has_pda) = self.check_struct_constraints(func);
        let has_signer_check = Self::detect_signer_check(&func_code) || struct_has_signer;

        if is_instruction && !has_signer_check {
            invariants.push(ExtractedInvariant {
                name: format!("{}_access_control", func_name),
                kind: InvariantKind::AccessControl,
                expression: format!(
                    "Instruction '{}' must validate signer/authority before state mutation",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 5,
                confidence: 90,
                related_accounts: Vec::new(),
            });
        }

        // Detect owner check patterns — check BOTH function body AND associated struct
        let has_owner_check = Self::detect_owner_check(&func_code) || struct_has_owner;

        if is_instruction && !has_owner_check {
            invariants.push(ExtractedInvariant {
                name: format!("{}_account_ownership", func_name),
                kind: InvariantKind::AccountOwnership,
                expression: format!(
                    "Instruction '{}' must verify account ownership before access",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check: false,
                has_owner_check,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 4,
                confidence: 85,
                related_accounts: Vec::new(),
            });
        }

        // Detect PDA validation — check BOTH function body AND associated struct
        let has_pda_check = Self::detect_pda_validation(&func_code) || struct_has_pda;
        let uses_pda = func_code.contains("find_program_address")
            || func_code.contains("create_program_address")
            || func_code.contains("seeds")
            || func_code.contains("bump");

        if uses_pda && !has_pda_check {
            invariants.push(ExtractedInvariant {
                name: format!("{}_pda_validation", func_name),
                kind: InvariantKind::PdaValidation,
                expression: format!(
                    "PDA seeds in '{}' must be validated to prevent substitution",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: has_pda_check,
                severity: 4,
                confidence: 80,
                related_accounts: Vec::new(),
            });
        }

        // Detect balance-related operations for conservation invariants
        let modifies_balance = func_code.contains("balance")
            || func_code.contains("amount")
            || func_code.contains("lamports")
            || func_code.contains("transfer")
            || func_code.contains("mint_to")
            || func_code.contains("burn");

        if modifies_balance && is_instruction {
            invariants.push(ExtractedInvariant {
                name: format!("{}_balance_conservation", func_name),
                kind: InvariantKind::BalanceConservation,
                expression: format!(
                    "Token/SOL balance changes in '{}' must conserve total supply (no creation from nothing)",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: has_checked_arith,
                has_signer_check,
                has_owner_check,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 5,
                confidence: 75,
                related_accounts: Vec::new(),
            });
        }

        // Detect state transition patterns
        let has_state_enum = func_code.contains("State::")
            || func_code.contains("Status::")
            || func_code.contains("state =")
            || func_code.contains("status =");

        if has_state_enum && is_instruction {
            invariants.push(ExtractedInvariant {
                name: format!("{}_state_transition", func_name),
                kind: InvariantKind::StateTransition,
                expression: format!(
                    "State transitions in '{}' must follow valid FSM (no illegal transitions)",
                    func_name
                ),
                source_location: format!("{}:{}", filename, line_number),
                function_name: func_name.clone(),
                has_checked_math: false,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: 4,
                confidence: 70,
                related_accounts: Vec::new(),
            });
        }
    }

    /// Analyze a method's code string.
    fn analyze_method_code(
        &mut self,
        func_name: &str,
        func_code: &str,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        if self.seen_functions.contains(func_name) {
            return;
        }
        self.seen_functions.insert(func_name.to_string());

        let is_instruction = func_code.contains("Context");
        let has_unchecked = Self::detect_unchecked_arithmetic(func_code);
        let has_checked = Self::detect_checked_arithmetic(func_code);

        if has_unchecked {
            invariants.push(ExtractedInvariant {
                name: format!("{}_arithmetic_safety", func_name),
                kind: InvariantKind::ArithmeticBounds,
                expression: format!(
                    "All arithmetic in '{}' must not overflow/underflow",
                    func_name
                ),
                source_location: format!("{}:method", filename),
                function_name: func_name.to_string(),
                has_checked_math: has_checked,
                has_signer_check: false,
                has_owner_check: false,
                has_bounds_check: false,
                has_pda_seeds_check: false,
                severity: if has_checked { 3 } else { 5 },
                confidence: if has_unchecked && !has_checked {
                    95
                } else {
                    60
                },
                related_accounts: Vec::new(),
            });
        }

        if is_instruction {
            let (struct_signer, _struct_owner, _struct_pda) = self.check_struct_constraints_from_code(func_code);
            let has_signer = Self::detect_signer_check(func_code) || struct_signer;
            if !has_signer {
                invariants.push(ExtractedInvariant {
                    name: format!("{}_access_control", func_name),
                    kind: InvariantKind::AccessControl,
                    expression: format!("Instruction '{}' requires signer validation", func_name),
                    source_location: format!("{}:method", filename),
                    function_name: func_name.to_string(),
                    has_checked_math: false,
                    has_signer_check: has_signer,
                    has_owner_check: false,
                    has_bounds_check: false,
                    has_pda_seeds_check: false,
                    severity: 5,
                    confidence: 90,
                    related_accounts: Vec::new(),
                });
            }
        }
    }

    /// Extract struct-level invariants from #[account] structs.
    #[allow(clippy::only_used_in_recursion)]
    fn extract_struct_invariants(
        &self,
        file: &File,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        for item in &file.items {
            if let Item::Struct(item_struct) = item {
                let _struct_code = item_struct.to_token_stream().to_string();
                let struct_name = item_struct.ident.to_string();
                let line_number = item_struct.ident.span().start().line;

                let is_account = item_struct.attrs.iter().any(|a| {
                    let s = a.to_token_stream().to_string();
                    s.contains("account") || s.contains("Account")
                });

                if !is_account {
                    continue;
                }

                // Check if account struct has balance/amount fields
                let mut balance_fields = Vec::new();
                let mut account_fields = Vec::new();

                if let syn::Fields::Named(named) = &item_struct.fields {
                    for field in &named.named {
                        let field_name = field
                            .ident
                            .as_ref()
                            .map(|i| i.to_string())
                            .unwrap_or_default();
                        let field_type = field.ty.to_token_stream().to_string();

                        if field_name.contains("balance")
                            || field_name.contains("amount")
                            || field_name.contains("supply")
                            || field_name.contains("total")
                        {
                            balance_fields.push(field_name.clone());
                        }

                        if field_type.contains("Pubkey") || field_type.contains("AccountInfo") {
                            account_fields.push(field_name.clone());
                        }
                    }
                }

                if !balance_fields.is_empty() {
                    invariants.push(ExtractedInvariant {
                        name: format!("{}_balance_fields_bounded", struct_name),
                        kind: InvariantKind::BoundsCheck,
                        expression: format!(
                            "Account '{}' balance fields ({}) must be within valid range [0, u64::MAX]",
                            struct_name,
                            balance_fields.join(", ")
                        ),
                        source_location: format!("{}:{}", filename, line_number),
                        function_name: struct_name.clone(),
                        has_checked_math: false,
                        has_signer_check: false,
                        has_owner_check: false,
                        has_bounds_check: true,
                        has_pda_seeds_check: false,
                        severity: 3,
                        confidence: 95,
                        related_accounts: account_fields.clone(),
                    });
                }
            }

            if let Item::Mod(item_mod) = item {
                if let Some((_, items)) = &item_mod.content {
                    let inner_file = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: items.clone(),
                    };
                    self.extract_struct_invariants(&inner_file, filename, invariants);
                }
            }
        }
    }

    /// Extract invariants from impl blocks.
    fn extract_impl_invariants(
        &self,
        file: &File,
        filename: &str,
        invariants: &mut Vec<ExtractedInvariant>,
    ) {
        for item in &file.items {
            if let Item::Impl(item_impl) = item {
                let impl_type = item_impl.self_ty.to_token_stream().to_string();

                for impl_item in &item_impl.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        let method_name = method.sig.ident.to_string();
                        let method_code = method.to_token_stream().to_string();

                        // Check for `require!` or `assert!` within methods
                        let constraint_count = method_code.matches("require!").count()
                            + method_code.matches("require_keys_eq!").count()
                            + method_code.matches("assert!").count()
                            + method_code.matches("assert_eq!").count();

                        if constraint_count > 0 {
                            invariants.push(ExtractedInvariant {
                                name: format!("{}_{}_constraints", impl_type, method_name),
                                kind: InvariantKind::BoundsCheck,
                                expression: format!(
                                    "{} constraints in {}.{} must hold in all execution paths",
                                    constraint_count, impl_type, method_name
                                ),
                                source_location: format!("{}:impl", filename),
                                function_name: method_name.clone(),
                                has_checked_math: false,
                                has_signer_check: false,
                                has_owner_check: false,
                                has_bounds_check: true,
                                has_pda_seeds_check: false,
                                severity: 3,
                                confidence: 85,
                                related_accounts: Vec::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    // ─── Detection Helpers ────────────────────────────────────────────────

    /// Detect unchecked arithmetic (raw +, -, *, /).
    fn detect_unchecked_arithmetic(code: &str) -> bool {
        // Look for patterns like `a + b`, `x - y`, etc. that are NOT inside checked calls
        let has_raw_ops = code.contains(" + ")
            || code.contains(" - ")
            || code.contains(" * ")
            || code.contains(" / ");

        let has_assignment_ops = code.contains("+= ")
            || code.contains("-= ")
            || code.contains("*= ")
            || code.contains("/= ");

        (has_raw_ops || has_assignment_ops) && !Self::detect_checked_arithmetic(code)
    }

    /// Detect checked arithmetic calls.
    fn detect_checked_arithmetic(code: &str) -> bool {
        code.contains("checked_add")
            || code.contains("checked_sub")
            || code.contains("checked_mul")
            || code.contains("checked_div")
            || code.contains("saturating_add")
            || code.contains("saturating_sub")
            || code.contains("saturating_mul")
            || code.contains("overflowing_add")
            || code.contains("overflowing_sub")
    }

    /// Detect signer/authority checks.
    fn detect_signer_check(code: &str) -> bool {
        code.contains("is_signer")
            || code.contains("Signer")
            || code.contains("has_one")
            || code.contains("constraint")
            || code.contains("require_keys_eq!")
            || code.contains("account(signer")
            || code.contains("authority")
            || code.contains(".key()")
    }

    /// Detect account owner checks.
    fn detect_owner_check(code: &str) -> bool {
        code.contains("owner")
            || code.contains("Owner")
            || code.contains("has_one")
            || code.contains("constraint")
            || code.contains("Account<") // Anchor Account<> wrapper validates owner
    }

    /// Detect PDA validation.
    fn detect_pda_validation(code: &str) -> bool {
        code.contains("find_program_address")
            || code.contains("create_program_address")
            || code.contains("seeds =")
            || code.contains("bump =")
            || code.contains("account(seeds")
    }
}

impl Default for InvariantExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// An invariant extracted from program source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedInvariant {
    /// Human-readable invariant name
    pub name: String,
    /// Category of invariant
    pub kind: InvariantKind,
    /// Formal or semi-formal invariant expression
    pub expression: String,
    /// Source file and line
    pub source_location: String,
    /// Function containing this invariant
    pub function_name: String,
    // ─── Detection flags ─────
    pub has_checked_math: bool,
    pub has_signer_check: bool,
    pub has_owner_check: bool,
    pub has_bounds_check: bool,
    pub has_pda_seeds_check: bool,
    /// Severity (1-5)
    pub severity: u8,
    /// Confidence percentage (0-100)
    pub confidence: u8,
    /// Related account names
    pub related_accounts: Vec<String>,
}

/// Categories of invariants that Kani can verify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantKind {
    /// Arithmetic operations must not overflow/underflow
    ArithmeticBounds,
    /// Token/SOL balances must be conserved
    BalanceConservation,
    /// Only authorized signers can mutate state
    AccessControl,
    /// Account ownership must match expected program
    AccountOwnership,
    /// State machine transitions must be valid
    StateTransition,
    /// Values must be within protocol-defined limits
    BoundsCheck,
    /// PDA seeds must be properly validated
    PdaValidation,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build an InvariantExtractor with pre-populated account_schemas.
    fn extractor_with_schemas(schemas: Vec<(&str, Vec<(&str, &str, &str)>)>) -> InvariantExtractor {
        let mut ext = InvariantExtractor::new();
        for (name, fields) in schemas {
            ext.account_schemas.insert(
                name.to_string(),
                fields
                    .into_iter()
                    .map(|(n, t, a)| (n.to_string(), t.to_string(), a.to_string()))
                    .collect(),
            );
        }
        ext
    }

    // ─── lookup_struct_signals: regex parsing ─────────────────────────

    #[test]
    fn test_lookup_parses_context_with_lifetime() {
        let ext = extractor_with_schemas(vec![(
            "UpdatePauser",
            vec![("admin", "Signer<'info>", "")],
        )]);
        // Standard Anchor pattern: Context<'info, T>
        let (signer, _owner, _pda) = ext.lookup_struct_signals("ctx : Context < 'info , UpdatePauser >");
        assert!(signer, "Should detect Signer from Context<'info, UpdatePauser>");
    }

    #[test]
    fn test_lookup_parses_context_without_lifetime() {
        let ext = extractor_with_schemas(vec![(
            "Initialize",
            vec![("authority", "Signer<'info>", "")],
        )]);
        // Simplified pattern: Context<T>
        let (signer, _owner, _pda) = ext.lookup_struct_signals("ctx: Context<Initialize>");
        assert!(signer, "Should detect Signer from Context<Initialize>");
    }

    #[test]
    fn test_lookup_parses_quote_spaced_context() {
        let ext = extractor_with_schemas(vec![(
            "Transfer",
            vec![("from_authority", "Signer < 'info >", "")],
        )]);
        // quote! output often has extra spaces
        let (signer, _owner, _pda) = ext.lookup_struct_signals("ctx : Context < 'info , Transfer >");
        assert!(signer, "Should handle quote!-style spacing in Context<'info, T>");
    }

    // ─── lookup_struct_signals: Signer suppression ───────────────────

    #[test]
    fn test_signer_field_suppresses() {
        let ext = extractor_with_schemas(vec![(
            "DisableAttester",
            vec![
                ("attester_manager", "Signer<'info>", ""),
                ("message_transmitter", "Account<'info, MessageTransmitter>", ""),
            ],
        )]);
        let (signer, owner, _pda) = ext.lookup_struct_signals("ctx: Context<'info, DisableAttester>");
        assert!(signer, "Signer<'info> field should set has_signer=true");
        assert!(owner, "Account<> field should set has_owner=true");
    }

    #[test]
    fn test_signer_attr_suppresses() {
        let ext = extractor_with_schemas(vec![(
            "CloseVault",
            vec![("admin", "AccountInfo<'info>", "#[account(signer)]")],
        )]);
        let (signer, _, _) = ext.lookup_struct_signals("ctx: Context<'info, CloseVault>");
        assert!(signer, "#[account(signer)] attr should set has_signer=true");
    }

    // ─── lookup_struct_signals: has_one suppression ──────────────────

    #[test]
    fn test_has_one_constraint_suppresses() {
        let ext = extractor_with_schemas(vec![(
            "TransferOwnership",
            vec![
                ("owner", "AccountInfo<'info>", "#[account(has_one = authority)]"),
                ("authority", "AccountInfo<'info>", ""),
            ],
        )]);
        let (signer, owner, _) = ext.lookup_struct_signals("ctx: Context<'info, TransferOwnership>");
        assert!(signer, "has_one constraint should set has_signer=true");
        assert!(owner, "has_one constraint should set has_owner=true");
    }

    #[test]
    fn test_constraint_attr_suppresses() {
        let ext = extractor_with_schemas(vec![(
            "UpdateConfig",
            vec![(
                "config",
                "Account<'info, Config>",
                "#[account(mut, constraint = config.admin == admin.key())]",
            )],
        )]);
        let (signer, owner, _) = ext.lookup_struct_signals("ctx: Context<'info, UpdateConfig>");
        assert!(signer, "constraint= attr should set has_signer=true");
        assert!(owner, "constraint= attr should set has_owner=true");
    }

    // ─── lookup_struct_signals: PDA / seeds suppression ──────────────

    #[test]
    fn test_seeds_constraint_sets_pda() {
        let ext = extractor_with_schemas(vec![(
            "ReceiveMessage",
            vec![(
                "used_nonces",
                "Account<'info, UsedNonces>",
                "#[account(seeds = [b\"used_nonces\", domain.to_le_bytes().as_ref()], bump)]",
            )],
        )]);
        let (_, _, pda) = ext.lookup_struct_signals("ctx: Context<'info, ReceiveMessage>");
        assert!(pda, "seeds= attr should set has_pda=true");
    }

    #[test]
    fn test_bump_attr_sets_pda() {
        let ext = extractor_with_schemas(vec![(
            "InitVault",
            vec![("vault", "Account<'info, Vault>", "#[account(init, bump)]")],
        )]);
        let (_, _, pda) = ext.lookup_struct_signals("ctx: Context<'info, InitVault>");
        assert!(pda, "bump attr should set has_pda=true");
    }

    // ─── lookup_struct_signals: negative cases ───────────────────────

    #[test]
    fn test_struct_not_in_schemas_returns_false() {
        let ext = extractor_with_schemas(vec![]);
        let (signer, owner, pda) = ext.lookup_struct_signals("ctx: Context<'info, Unknown>");
        assert!(!signer && !owner && !pda, "Unknown struct should return all false");
    }

    #[test]
    fn test_no_context_param_returns_false() {
        let ext = extractor_with_schemas(vec![(
            "Withdraw",
            vec![("auth", "Signer<'info>", "")],
        )]);
        let (signer, owner, pda) = ext.lookup_struct_signals("amount: u64, bump: u8");
        assert!(!signer && !owner && !pda, "No Context<T> in text should return all false");
    }

    #[test]
    fn test_struct_with_no_constraints_returns_false() {
        let ext = extractor_with_schemas(vec![(
            "ReadOnly",
            vec![
                ("clock", "Sysvar<'info, Clock>", ""),
                ("system_program", "Program<'info, System>", ""),
            ],
        )]);
        let (signer, owner, pda) = ext.lookup_struct_signals("ctx: Context<'info, ReadOnly>");
        // No Signer<>, no has_one, no Account<>, no seeds
        assert!(!signer, "Sysvar/Program fields should not trigger signer");
        assert!(!owner, "Sysvar/Program fields should not trigger owner");
        assert!(!pda, "No seeds/bump should not trigger pda");
    }

    // ─── lookup_struct_signals: combined signals ─────────────────────

    #[test]
    fn test_all_three_signals_detected() {
        let ext = extractor_with_schemas(vec![(
            "ComplexInstruction",
            vec![
                ("admin", "Signer<'info>", ""),
                ("vault", "Account<'info, Vault>", "#[account(has_one = admin)]"),
                ("pda_account", "Account<'info, PdaData>", "#[account(seeds = [b\"pda\"], bump)]"),
            ],
        )]);
        let (signer, owner, pda) = ext.lookup_struct_signals("ctx: Context<'info, ComplexInstruction>");
        assert!(signer, "Should detect signer from Signer field");
        assert!(owner, "Should detect owner from Account<> + has_one");
        assert!(pda, "Should detect PDA from seeds/bump");
    }

    // ─── Integration: extract_from_source end-to-end ─────────────────

    #[test]
    fn test_extract_suppresses_signer_finding_for_anchor_handler() {
        let source = r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct UpdatePauser<'info> {
                #[account(mut, has_one = pauser)]
                pub message_transmitter: Account<'info, MessageTransmitter>,
                pub pauser: Signer<'info>,
            }

            pub fn update_pauser(ctx: Context<'info, UpdatePauser>, new_pauser: Pubkey) -> Result<()> {
                ctx.accounts.message_transmitter.pauser = new_pauser;
                Ok(())
            }

            #[account]
            pub struct MessageTransmitter {
                pub pauser: Pubkey,
            }
        "#;

        let mut extractor = InvariantExtractor::new();
        let invariants = extractor.extract_from_source(source, "lib.rs").unwrap();

        // The update_pauser handler should NOT produce an AccessControl finding
        // because its UpdatePauser struct has Signer<'info> and has_one
        let access_control_findings: Vec<_> = invariants
            .iter()
            .filter(|i| i.kind == InvariantKind::AccessControl && i.function_name == "update_pauser")
            .collect();

        assert!(
            access_control_findings.is_empty(),
            "update_pauser has Signer + has_one — should NOT produce AccessControl finding, but got: {:?}",
            access_control_findings
        );
    }

    #[test]
    fn test_extract_flags_handler_without_signer() {
        let source = r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct UnsafeWithdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                /// CHECK: not validated
                pub destination: AccountInfo<'info>,
            }

            pub fn withdraw(ctx: Context<'info, UnsafeWithdraw>, amount: u64) -> Result<()> {
                let vault = &mut ctx.accounts.vault;
                vault.balance -= amount;
                Ok(())
            }

            #[account]
            pub struct Vault {
                pub balance: u64,
            }
        "#;

        let mut extractor = InvariantExtractor::new();
        let invariants = extractor.extract_from_source(source, "lib.rs").unwrap();

        // withdraw has no Signer, no has_one, no constraint — SHOULD produce AccessControl finding
        let access_control_findings: Vec<_> = invariants
            .iter()
            .filter(|i| i.kind == InvariantKind::AccessControl && i.function_name == "withdraw")
            .collect();

        assert!(
            !access_control_findings.is_empty(),
            "withdraw has no signer check — SHOULD produce AccessControl finding"
        );
    }

    #[test]
    fn test_extract_suppresses_owner_finding_for_anchor_accounts() {
        let source = r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct TransferOwnership<'info> {
                #[account(mut, has_one = owner)]
                pub config: Account<'info, Config>,
                pub owner: Signer<'info>,
            }

            pub fn transfer_ownership(ctx: Context<'info, TransferOwnership>, new_owner: Pubkey) -> Result<()> {
                ctx.accounts.config.owner = new_owner;
                Ok(())
            }

            #[account]
            pub struct Config {
                pub owner: Pubkey,
            }
        "#;

        let mut extractor = InvariantExtractor::new();
        let invariants = extractor.extract_from_source(source, "lib.rs").unwrap();

        // Should NOT produce AccountOwnership finding (Account<> + has_one present)
        let ownership_findings: Vec<_> = invariants
            .iter()
            .filter(|i| i.kind == InvariantKind::AccountOwnership && i.function_name == "transfer_ownership")
            .collect();

        assert!(
            ownership_findings.is_empty(),
            "transfer_ownership has Account<> + has_one — should NOT produce AccountOwnership finding, but got: {:?}",
            ownership_findings
        );
    }
}

#[cfg(test)]
mod tests_extra {
    use super::*;

    fn extractor_with_schemas(schemas: Vec<(&str, Vec<(&str, &str, &str)>)>) -> InvariantExtractor {
        let mut ext = InvariantExtractor::new();
        for (name, fields) in schemas {
            ext.account_schemas.insert(
                name.to_string(),
                fields
                    .into_iter()
                    .map(|(n, t, a)| (n.to_string(), t.to_string(), a.to_string()))
                    .collect(),
            );
        }
        ext
    }

    #[test]
    fn test_check_struct_constraints_from_code_with_method() {
        let ext = extractor_with_schemas(vec![(
            "Deposit",
            vec![
                ("depositor", "Signer<'info>", ""),
                ("vault", "Account<'info, Vault>", "#[account(has_one = depositor)]"),
            ],
        )]);
        let method_code = "fn process_deposit(ctx: Context<'info, Deposit>, amount: u64) -> Result<()> { Ok(()) }";
        let (signer, owner, _pda) = ext.check_struct_constraints_from_code(method_code);
        assert!(signer, "check_struct_constraints_from_code should detect Signer from method code");
        assert!(owner, "check_struct_constraints_from_code should detect owner from Account<> + has_one");
    }

    #[test]
    fn test_extract_suppresses_with_standard_anchor_context() {
        let source = r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Deposit<'info> {
                #[account(mut, has_one = authority)]
                pub vault: Account<'info, Vault>,
                pub authority: Signer<'info>,
            }

            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                ctx.accounts.vault.balance += amount;
                Ok(())
            }

            #[account]
            pub struct Vault {
                pub balance: u64,
                pub authority: Pubkey,
            }
        "#;

        let mut extractor = InvariantExtractor::new();
        let invariants = extractor.extract_from_source(source, "lib.rs").unwrap();

        let access_findings: Vec<_> = invariants
            .iter()
            .filter(|i| i.kind == InvariantKind::AccessControl && i.function_name == "deposit")
            .collect();

        assert!(
            access_findings.is_empty(),
            "deposit with Context<Deposit> (no lifetime) and Signer + has_one should NOT produce AccessControl finding, but got: {:?}",
            access_findings
        );
    }
}
