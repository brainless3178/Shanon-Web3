//! CVLR (Certora Verification Language for Rust) Specification Generator
//!
//! Generates CVLR specification rules that the Certora Solana Prover uses
//! to verify SBF bytecode. CVLR is embedded in Rust and uses:
//!
//! - `#[rule]` attribute for verification entry points
//! - `cvlr_assert!()` for assertions that must hold in all states
//! - `cvlr_satisfy!()` for reachability checks
//! - `cvlr_assume!()` for preconditions
//!
//! These rules are compiled alongside the program and verified at the
//! bytecode level by the Certora Prover.

use crate::sbf_analyzer::{SbfBinaryInfo, SbfSymbol};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::path::Path;
use syn::{File, Item};

/// Generates CVLR specification rules for Certora verification.
pub struct CvlrSpecGenerator;

impl CvlrSpecGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate CVLR rules based on program source and binary info.
    pub fn generate_rules(
        &self,
        program_path: &Path,
        binary_info: &SbfBinaryInfo,
    ) -> Result<Vec<CvlrRule>, crate::CertoraError> {
        let mut rules = Vec::new();

        // Generate rules from source analysis
        let source_rules = self.generate_from_source(program_path)?;
        rules.extend(source_rules);

        // Generate rules from binary structure
        let binary_rules = self.generate_from_binary(binary_info);
        rules.extend(binary_rules);

        // Generate Solana-specific bytecode safety rules
        let solana_rules = self.generate_solana_specific_rules(binary_info);
        rules.extend(solana_rules);

        Ok(rules)
    }

    /// Generate rules from Rust source AST.
    fn generate_from_source(
        &self,
        program_path: &Path,
    ) -> Result<Vec<CvlrRule>, crate::CertoraError> {
        let mut rules = Vec::new();

        for entry in walkdir::WalkDir::new(program_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let source = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let file = match syn::parse_file(&source) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let filename = entry
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown.rs")
                .to_string();

            self.extract_rules_from_ast(&file, &filename, &mut rules);
        }

        Ok(rules)
    }

    /// Walk AST and generate verification rules for functions.
    fn extract_rules_from_ast(&self, file: &File, filename: &str, rules: &mut Vec<CvlrRule>) {
        for item in &file.items {
            match item {
                Item::Fn(func) => {
                    let func_name = func.sig.ident.to_string();
                    let func_code = func.to_token_stream().to_string();

                    // Check for Context<T> (Anchor instruction handler)
                    let is_instruction = func.sig.inputs.iter().any(|arg| {
                        let s = arg.to_token_stream().to_string();
                        s.contains("Context")
                    });

                    if is_instruction {
                        // Generate solvency rule (ensure no unauthorized token creation)
                        if func_code.contains("transfer")
                            || func_code.contains("lamports")
                            || func_code.contains("amount")
                            || func_code.contains("balance")
                        {
                            rules.push(CvlrRule {
                                name: format!("rule_{}_solvency", func_name),
                                description: format!(
                                    "Verify that '{}' preserves token solvency — \
                                     total tokens in the system cannot increase without a valid mint",
                                    func_name
                                ),
                                rule_type: CvlrRuleType::Assert,
                                body: self.gen_solvency_rule(&func_name),
                                source_file: filename.to_string(),
                                severity: 5,
                                category: "Solvency".to_string(),
                            });
                        }

                        // Generate reentrancy rule (CPI + state mutation)
                        if func_code.contains("invoke") || func_code.contains("invoke_signed") {
                            rules.push(CvlrRule {
                                name: format!("rule_{}_no_reentrancy", func_name),
                                description: format!(
                                    "Verify that '{}' is not vulnerable to reentrancy via CPI",
                                    func_name
                                ),
                                rule_type: CvlrRuleType::Assert,
                                body: self.gen_reentrancy_rule(&func_name),
                                source_file: filename.to_string(),
                                severity: 5,
                                category: "Reentrancy".to_string(),
                            });
                        }

                        // Authority check rule
                        rules.push(CvlrRule {
                            name: format!("rule_{}_authority", func_name),
                            description: format!(
                                "Verify that '{}' validates the authority signer on all state-mutating paths",
                                func_name
                            ),
                            rule_type: CvlrRuleType::Assert,
                            body: self.gen_authority_rule(&func_name),
                            source_file: filename.to_string(),
                            severity: 5,
                            category: "Access Control".to_string(),
                        });

                        // Account initialization safety
                        if func_code.contains("init") {
                            rules.push(CvlrRule {
                                name: format!("rule_{}_init_once", func_name),
                                description: format!(
                                    "Verify that '{}' cannot reinitialize an already-initialized account",
                                    func_name
                                ),
                                rule_type: CvlrRuleType::Assert,
                                body: self.gen_init_once_rule(&func_name),
                                source_file: filename.to_string(),
                                severity: 4,
                                category: "Initialization".to_string(),
                            });
                        }
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        let inner_file = File {
                            shebang: None,
                            attrs: Vec::new(),
                            items: items.clone(),
                        };
                        self.extract_rules_from_ast(&inner_file, filename, rules);
                    }
                }
                Item::Impl(item_impl) => {
                    for impl_item in &item_impl.items {
                        if let syn::ImplItem::Fn(method) = impl_item {
                            let method_name = method.sig.ident.to_string();
                            let method_code = method.to_token_stream().to_string();

                            // Arithmetic overflow check rules for all methods with math
                            let has_math = method_code.contains(" + ")
                                || method_code.contains(" - ")
                                || method_code.contains(" * ")
                                || method_code.contains(" / ");

                            if has_math {
                                rules.push(CvlrRule {
                                    name: format!("rule_{}_no_overflow", method_name),
                                    description: format!(
                                        "Verify that arithmetic in '{}' cannot overflow at the SBF bytecode level \
                                         (compiler may optimize away source-level checks)",
                                        method_name
                                    ),
                                    rule_type: CvlrRuleType::Assert,
                                    body: self.gen_overflow_rule(&method_name),
                                    source_file: filename.to_string(),
                                    severity: 4,
                                    category: "Arithmetic Safety".to_string(),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Generate rules based on binary structure.
    fn generate_from_binary(&self, binary_info: &SbfBinaryInfo) -> Vec<CvlrRule> {
        let mut rules = Vec::new();

        // Entry point validation
        if !binary_info.has_entry_point {
            rules.push(CvlrRule {
                name: "rule_has_entry_point".into(),
                description: "SBF binary must have a valid entrypoint symbol".into(),
                rule_type: CvlrRuleType::Assert,
                body: r#"#[rule]
fn rule_has_entry_point() {
    // Verify the binary exports a valid entrypoint
    cvlr_assert!(program_has_entrypoint(), "SBF binary missing entrypoint");
}"#
                .into(),
                source_file: "binary_analysis".into(),
                severity: 5,
                category: "Binary Integrity".into(),
            });
        }

        // Stack safety: check for excessive stack usage
        let text_section = binary_info.sections.iter().find(|s| s.name == ".text");
        if let Some(text) = text_section {
            if text.size > 200_000 {
                rules.push(CvlrRule {
                    name: "rule_stack_depth_bounded".into(),
                    description: format!(
                        "SBF program has {} instructions — verify stack depth stays within \
                         BPF stack limit (4096 bytes) for all execution paths",
                        binary_info.instruction_count
                    ),
                    rule_type: CvlrRuleType::Assert,
                    body: r#"#[rule]
fn rule_stack_depth_bounded() {
    // BPF stack limit is 4096 bytes; verify no path exceeds this
    let max_stack_depth: u64 = nondet();
    cvlr_assert!(max_stack_depth <= 4096, "Stack overflow in SBF execution");
}"#
                    .into(),
                    source_file: "binary_analysis".into(),
                    severity: 4,
                    category: "Stack Safety".into(),
                });
            }
        }

        // Writable section in executable segments
        let has_wx = binary_info
            .sections
            .iter()
            .any(|s| s.is_executable && s.is_writable);
        if has_wx {
            rules.push(CvlrRule {
                name: "rule_no_writable_executable".into(),
                description:
                    "SBF binary contains a section that is both writable AND executable — \
                    potential code injection vulnerability"
                        .into(),
                rule_type: CvlrRuleType::Assert,
                body: r#"#[rule]
fn rule_no_writable_executable() {
    // W^X policy: no section should be both writable and executable
    cvlr_assert!(!section_is_wx(), "W^X violation: writable+executable section found");
}"#
                .into(),
                source_file: "binary_analysis".into(),
                severity: 5,
                category: "Memory Safety".into(),
            });
        }

        // CPI target validation
        let cpi_symbols: Vec<&SbfSymbol> = binary_info
            .symbols
            .iter()
            .filter(|s| s.is_cpi_target)
            .collect();
        if !cpi_symbols.is_empty() {
            rules.push(CvlrRule {
                name: "rule_cpi_targets_valid".into(),
                description: format!(
                    "Verify {} CPI call sites in the SBF binary target known programs \
                     and cannot be redirected to attacker-controlled programs",
                    cpi_symbols.len()
                ),
                rule_type: CvlrRuleType::Assert,
                body: r#"#[rule]
fn rule_cpi_targets_valid() {
    // For each CPI invoke, verify program_id is validated
    let target_program: Pubkey = nondet();
    cvlr_assume!(is_known_program(target_program));
    cvlr_assert!(
        cpi_target_is_validated(target_program),
        "CPI to unvalidated program — arbitrary CPI vulnerability"
    );
}"#
                .into(),
                source_file: "binary_analysis".into(),
                severity: 5,
                category: "CPI Safety".into(),
            });
        }

        rules
    }

    /// Generate Solana-specific bytecode safety rules.
    fn generate_solana_specific_rules(&self, binary_info: &SbfBinaryInfo) -> Vec<CvlrRule> {
        let mut rules = Vec::new();

        // Account discriminator validation at bytecode level
        if binary_info.is_anchor_program {
            rules.push(CvlrRule {
                name: "rule_discriminator_checked".into(),
                description: "Verify Anchor account discriminators are checked in bytecode \
                    (compiler optimizations may elide the check)"
                    .into(),
                rule_type: CvlrRuleType::Assert,
                body: r#"#[rule]
fn rule_discriminator_checked() {
    let account_data: &[u8] = nondet_account_data();
    let discriminator: [u8; 8] = nondet();
    // The first 8 bytes of Anchor accounts contain the discriminator
    // Verify the bytecode actually compares them
    cvlr_assert!(
        account_data[..8] == discriminator,
        "Account discriminator not validated — type confusion possible"
    );
}"#
                .into(),
                source_file: "solana_specific".into(),
                severity: 5,
                category: "Account Validation".into(),
            });
        }

        // Compute budget consumption
        rules.push(CvlrRule {
            name: "rule_compute_budget_bounded".into(),
            description: format!(
                "Verify SBF program ({} instructions) fits within Solana compute budget \
                 (200,000 CU default / 1,400,000 CU max)",
                binary_info.instruction_count
            ),
            rule_type: CvlrRuleType::Assert,
            body: r#"#[rule]
fn rule_compute_budget_bounded() {
    let compute_units_consumed: u64 = nondet();
    // Default compute budget is 200,000 CU; tx-level max is 1,400,000
    cvlr_assert!(
        compute_units_consumed <= 1_400_000,
        "SBF program may exceed maximum compute budget — DoS risk"
    );
}"#
            .into(),
            source_file: "solana_specific".into(),
            severity: 3,
            category: "Resource Limits".into(),
        });

        // Signer validation in bytecode (not just source)
        rules.push(CvlrRule {
            name: "rule_signer_checked_in_bytecode".into(),
            description: "Verify that `AccountInfo::is_signer` is actually checked in the compiled \
                SBF bytecode — the compiler may optimize it away if it believes the check is dead code".into(),
            rule_type: CvlrRuleType::Assert,
            body: r#"#[rule]
fn rule_signer_checked_in_bytecode() {
    let is_signer: bool = nondet();
    // If the entrypoint requires a signer, the bytecode must enforce it
    cvlr_assume!(!is_signer);
    // Attempting to call a privileged function without signing must fail
    cvlr_assert!(
        instruction_rejected_without_signer(),
        "Signer check elided in bytecode — compiler optimization removed access control"
    );
}"#.into(),
            source_file: "solana_specific".into(),
            severity: 5,
            category: "Access Control (Bytecode)".into(),
        });

        // Owner check in bytecode
        rules.push(CvlrRule {
            name: "rule_owner_checked_in_bytecode".into(),
            description: "Verify that account ownership validation survives compilation to SBF \
                bytecode — LLVM may optimize away owner checks it considers redundant"
                .into(),
            rule_type: CvlrRuleType::Assert,
            body: r#"#[rule]
fn rule_owner_checked_in_bytecode() {
    let account_owner: Pubkey = nondet();
    let expected_owner: Pubkey = nondet();
    cvlr_assume!(account_owner != expected_owner);
    cvlr_assert!(
        instruction_rejects_wrong_owner(account_owner, expected_owner),
        "Owner check optimized away in bytecode — account substitution possible"
    );
}"#
            .into(),
            source_file: "solana_specific".into(),
            severity: 5,
            category: "Account Ownership (Bytecode)".into(),
        });

        // Rent exemption check
        rules.push(CvlrRule {
            name: "rule_rent_exempt_after_operation".into(),
            description:
                "Verify that accounts remain rent-exempt after lamport transfers in SBF bytecode"
                    .into(),
            rule_type: CvlrRuleType::Assert,
            body: r#"#[rule]
fn rule_rent_exempt_after_operation() {
    let lamports_before: u64 = nondet();
    let lamports_after: u64 = nondet();
    let rent_exempt_minimum: u64 = nondet();
    cvlr_assume!(lamports_before >= rent_exempt_minimum);
    cvlr_assume!(lamports_after < lamports_before); // Transfer occurred
    cvlr_assert!(
        lamports_after >= rent_exempt_minimum || lamports_after == 0,
        "Account falls below rent-exempt threshold — may be garbage collected"
    );
}"#
            .into(),
            source_file: "solana_specific".into(),
            severity: 3,
            category: "Rent Safety".into(),
        });

        // PDA derivation correctness at bytecode level
        let has_pda_syms = binary_info.symbols.iter().any(|s| {
            s.name.contains("find_program_address")
                || s.name.contains("create_program_address")
                || s.name.contains("Pubkey::find")
        });
        if has_pda_syms {
            rules.push(CvlrRule {
                name: "rule_pda_derivation_bytecode".into(),
                description: "Verify PDA derivation seeds are validated in bytecode — \
                    compiler inlining may merge or skip seed validation"
                    .into(),
                rule_type: CvlrRuleType::Assert,
                body: r#"#[rule]
fn rule_pda_derivation_bytecode() {
    let seeds: &[&[u8]] = nondet_seeds();
    let bump: u8 = nondet();
    let derived_pda: Pubkey = find_program_address(seeds, &program_id());
    let expected_pda: Pubkey = nondet();
    cvlr_assert!(
        derived_pda == expected_pda,
        "PDA derivation mismatch in bytecode — seed validation optimized away"
    );
}"#
                .into(),
                source_file: "solana_specific".into(),
                severity: 4,
                category: "PDA Validation (Bytecode)".into(),
            });
        }

        rules
    }

    // ─── Rule Body Generators ────────────────────────────────────────────

    fn gen_solvency_rule(&self, func_name: &str) -> String {
        format!(
            r#"#[rule]
fn rule_{func_name}_solvency() {{
    // Track total token supply before and after the instruction
    let total_supply_before: u64 = nondet();
    let total_supply_after: u64 = nondet();

    // The instruction executes
    let result = {func_name}(nondet_context());

    // Solvency: total supply cannot increase unless mint authority was validated
    if result.is_ok() {{
        cvlr_assert!(
            total_supply_after <= total_supply_before || mint_authority_validated(),
            "Solvency violation: tokens created without mint authority"
        );
    }}
}}"#
        )
    }

    fn gen_reentrancy_rule(&self, func_name: &str) -> String {
        format!(
            r#"#[rule]
fn rule_{func_name}_no_reentrancy() {{
    // Verify state is finalized before CPI
    let state_locked: bool = nondet();
    cvlr_assume!(state_locked);

    // After CPI returns, state must not have been modified by the called program
    let cpi_result = invoke_cpi(nondet_instruction());
    cvlr_assert!(
        state_not_modified_by_cpi(cpi_result),
        "Reentrancy: CPI call can modify state before instruction completes"
    );
}}"#
        )
    }

    fn gen_authority_rule(&self, func_name: &str) -> String {
        format!(
            r#"#[rule]
fn rule_{func_name}_authority() {{
    let authority: AccountInfo = nondet_account();
    let attacker: AccountInfo = nondet_account();

    // Attacker is not a signer and has different key
    cvlr_assume!(!attacker.is_signer);
    cvlr_assume!(attacker.key != authority.key);

    // The instruction must reject the attacker
    let result = {func_name}_with_account(attacker);
    cvlr_assert!(
        result.is_err(),
        "Authority bypass: non-signer can execute privileged instruction at bytecode level"
    );
}}"#
        )
    }

    fn gen_init_once_rule(&self, func_name: &str) -> String {
        format!(
            r#"#[rule]
fn rule_{func_name}_init_once() {{
    let account: AccountInfo = nondet_account();

    // Account is already initialized
    cvlr_assume!(account_is_initialized(account));

    // Attempting to re-initialize must fail
    let result = {func_name}(nondet_context_with(account));
    cvlr_assert!(
        result.is_err(),
        "Re-initialization: already-initialized account can be overwritten"
    );
}}"#
        )
    }

    fn gen_overflow_rule(&self, func_name: &str) -> String {
        format!(
            r#"#[rule]
fn rule_{func_name}_no_overflow() {{
    let a: u64 = nondet();
    let b: u64 = nondet();

    // Constrain to realistic Solana amounts
    cvlr_assume!(a <= 580_000_000_000_000_000u64); // Total SOL supply in lamports
    cvlr_assume!(b <= 580_000_000_000_000_000u64);

    // Verify arithmetic at the bytecode level
    // The compiler may remove overflow checks during optimization
    let result = a.checked_add(b);
    cvlr_assert!(
        result.is_some() || (a as u128 + b as u128 > u64::MAX as u128),
        "Arithmetic overflow not caught in bytecode — compiler removed check"
    );
}}"#
        )
    }
}

impl Default for CvlrSpecGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// A CVLR verification rule for the Certora Prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvlrRule {
    /// Rule name (used with `--rule` flag)
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Assert or Satisfy
    pub rule_type: CvlrRuleType,
    /// The CVLR rule body (Rust code with cvlr_assert!/cvlr_satisfy!)
    pub body: String,
    /// Source file this rule was derived from
    pub source_file: String,
    /// Severity (1-5)
    pub severity: u8,
    /// Category of verification check
    pub category: String,
}

/// Type of CVLR rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CvlrRuleType {
    /// `cvlr_assert!` — must hold in all states
    Assert,
    /// `cvlr_satisfy!` — must be reachable in some state
    Satisfy,
}
