//! - **Full Ledger Simulation**: Trident simulates the entire Solana ledger state
//!   (accounts, PDAs, token mints, CPIs) — not just individual functions.
//! - **Stateful Fuzzing**: Inputs are generated based on critical account state
//!   changes, catching bugs that isolated unit tests miss.
//! - **Anchor-Native**: Tightly integrated with Anchor's account model and macros.
//! - **Property-Based Testing**: Compare account states before and after execution.
//! - **Flow-Based Sequences**: Combine multiple instructions into realistic
//!   transaction patterns that model real user behaviour.
//!
//! ## Integration Pipeline
//!
//! 1. **Extract**: Parse Anchor program source to discover accounts, instructions,
//!    constraints, and PDAs.
//! 2. **Generate**: Automatically produce Trident fuzz test harnesses:
//!    - `#[init]` transactions for program initialization
//!    - `#[flow]` sequences for multi-instruction attack patterns
//!    - Property invariant checks (balance conservation, access control, etc.)
//! 3. **Execute**: Invoke `trident fuzz run` (or built-in SVM simulation) to
//!    execute thousands of random transaction sequences against the program.
//! 4. **Detect**: Analyse execution traces for panics, constraint violations,
//!    unexpected state mutations, and invariant failures.
//! 5. **Report**: Aggregate findings into a structured `TridentFuzzReport` that
//!    integrates seamlessly with the audit pipeline.
//!
//! ## Vulnerability Categories
//!
//! | Category | Description |
//! |----------|-------------|
//! | AccountConfusion | Wrong account substitution bypasses checks |
//! | ArithmeticOverflow | Unchecked math leads to token inflation |
//! | MissingSigner | Transaction accepted without required signer |
//! | ReInitialization | Account re-initialized to attacker-controlled state |
//! | PDASeedCollision | Derived addresses collide across users/pools |
//! | CPIReentrancy | Cross-program invocation re-enters mutably |
//! | UnauthorizedWithdrawal | Funds drained without proper authorization |
//! | StateCorruption | Discriminator / data layout corruption |
//! | ConstraintBypass | Anchor constraint circumvented via crafted input |
//! | CloseAccountDrain | Lamport drain via account closing race |

pub mod anchor_extractor;
pub mod crash_analyzer;
pub mod fuzz_executor;
pub mod harness_generator;
pub mod report;

use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

pub use anchor_extractor::{
    AnchorAccount, AnchorConstraint, AnchorInstruction, AnchorProgramModel, PdaDerivation,
};
pub use crash_analyzer::{CrashAnalyzer, CrashCategory, CrashReport};
pub use fuzz_executor::{TridentConfig, TridentExecutor};
pub use harness_generator::TridentHarnessGenerator;
pub use report::{TridentFinding, TridentFuzzReport, TridentSeverity};

// ─── Main Fuzzer ─────────────────────────────────────────────────────────────

/// Top-level Trident fuzzing orchestrator.
///
/// Orchestrates: source extraction → harness generation → fuzz execution →
/// crash analysis → report generation.
#[allow(dead_code)]
pub struct TridentFuzzer {
    config: TridentConfig,
    extractor: anchor_extractor::AnchorExtractor,
    generator: TridentHarnessGenerator,
    executor: TridentExecutor,
    crash_analyzer: CrashAnalyzer,
}

impl TridentFuzzer {
    /// Create a fuzzer with default configuration.
    pub fn new() -> Self {
        let config = TridentConfig::default();
        Self {
            extractor: anchor_extractor::AnchorExtractor::new(),
            generator: TridentHarnessGenerator::new(),
            executor: TridentExecutor::new(config.clone()),
            crash_analyzer: CrashAnalyzer::new(),
            config,
        }
    }

    /// Create a fuzzer with custom configuration.
    pub fn with_config(config: TridentConfig) -> Self {
        Self {
            extractor: anchor_extractor::AnchorExtractor::new(),
            generator: TridentHarnessGenerator::new(),
            executor: TridentExecutor::new(config.clone()),
            crash_analyzer: CrashAnalyzer::new(),
            config,
        }
    }

    /// Run the full Trident fuzzing pipeline on a Solana program directory.
    ///
    /// Pipeline:
    /// 1. Extract Anchor program model from source
    /// 2. Generate fuzz harnesses and property invariants
    /// 3. Execute fuzz campaign (Trident CLI or built-in SVM simulation)
    /// 4. Analyse crashes and invariant violations
    /// 5. Build structured report
    pub fn fuzz_program(&mut self, program_path: &Path) -> Result<TridentFuzzReport, TridentError> {
        let start = std::time::Instant::now();
        info!(
            "Trident: Starting stateful fuzz campaign for {:?}",
            program_path
        );

        // Phase 1: Extract Anchor program model
        let model = self.extract_program_model(program_path)?;
        info!(
            "Trident: Extracted {} instructions, {} accounts, {} PDAs from program",
            model.instructions.len(),
            model.accounts.len(),
            model.pda_derivations.len(),
        );

        // Phase 2: Generate fuzz harnesses
        let harness_dir = self.generate_harnesses(&model, program_path)?;
        info!("Trident: Generated fuzz harnesses in {:?}", harness_dir);

        // Phase 3: Execute fuzz campaign
        let execution_result = self
            .executor
            .run_fuzz_campaign(&harness_dir, program_path, &model);

        // Phase 4: Analyse crashes
        let crashes = match &execution_result {
            Ok(raw_results) => {
                info!(
                    "Trident: Fuzz campaign completed — {} iterations, {} crashes, {} invariant violations",
                    raw_results.total_iterations,
                    raw_results.crashes.len(),
                    raw_results.invariant_violations.len(),
                );
                self.crash_analyzer.analyze_all(raw_results, &model)
            }
            Err(e) => {
                warn!(
                    "Trident: CLI execution unavailable ({}), running offline analysis",
                    e
                );
                self.run_offline_analysis(&model)
            }
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Phase 5: Build report
        let findings: Vec<TridentFinding> = crashes.iter().map(|c| c.to_finding()).collect();

        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, TridentSeverity::Critical))
            .count();
        let high_count = findings
            .iter()
            .filter(|f| matches!(f.severity, TridentSeverity::High))
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| matches!(f.severity, TridentSeverity::Medium))
            .count();
        let low_count = findings
            .iter()
            .filter(|f| matches!(f.severity, TridentSeverity::Low))
            .count();

        let (total_iterations, total_crashes, coverage_pct) = match &execution_result {
            Ok(r) => (r.total_iterations, r.crashes.len(), r.branch_coverage_pct),
            Err(_) => (0, crashes.len(), 0.0),
        };

        let report = TridentFuzzReport {
            program_path: program_path.to_path_buf(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            program_model: model,
            findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            total_iterations,
            total_crashes,
            branch_coverage_pct: coverage_pct,
            harness_path: Some(harness_dir),
            trident_version: self.executor.detect_trident_version(),
            analysis_duration_ms: elapsed_ms,
            trident_backend: if self.executor.is_trident_available() {
                "Trident CLI (trident-fuzz + SVM)".to_string()
            } else {
                "Offline Static Fuzzing Analysis (Trident CLI not installed)".to_string()
            },
        };

        info!(
            "Trident: Fuzz campaign complete in {}ms — {} findings ({} critical, {} high)",
            elapsed_ms,
            report.findings.len(),
            critical_count,
            high_count,
        );

        Ok(report)
    }

    // ─── Internal Methods ────────────────────────────────────────────────────

    /// Extract the Anchor program model from source code.
    fn extract_program_model(
        &mut self,
        program_path: &Path,
    ) -> Result<AnchorProgramModel, TridentError> {
        let mut model = AnchorProgramModel::default();

        for entry in walkdir::WalkDir::new(program_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(path)
                    .map_err(|e| TridentError::IoError(format!("Cannot read {:?}: {}", path, e)))?;

                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown.rs")
                    .to_string();

                match self.extractor.extract_from_source(&source, &filename) {
                    Ok(partial_model) => model.merge(partial_model),
                    Err(e) => {
                        debug!("Trident: Skipping {:?}: {}", path, e);
                    }
                }
            }
        }

        if model.instructions.is_empty() && model.accounts.is_empty() {
            return Err(TridentError::NoProgramFound(format!(
                "No Anchor instructions or accounts found in {:?}",
                program_path
            )));
        }

        Ok(model)
    }

    /// Generate Trident fuzz harness files.
    fn generate_harnesses(
        &self,
        model: &AnchorProgramModel,
        program_path: &Path,
    ) -> Result<PathBuf, TridentError> {
        let harness_dir = program_path.join("trident_fuzz");
        std::fs::create_dir_all(&harness_dir)
            .map_err(|e| TridentError::IoError(format!("Cannot create harness dir: {}", e)))?;

        // Generate the main fuzz test file
        let main_harness = self.generator.generate_fuzz_test(model);
        let main_path = harness_dir.join("fuzz_test.rs");
        std::fs::write(&main_path, &main_harness)
            .map_err(|e| TridentError::IoError(format!("Cannot write fuzz test: {}", e)))?;
        info!("Trident: Generated main fuzz test: {:?}", main_path);

        // Generate property invariant checks
        let invariants = self.generator.generate_invariant_checks(model);
        let inv_path = harness_dir.join("invariants.rs");
        std::fs::write(&inv_path, &invariants)
            .map_err(|e| TridentError::IoError(format!("Cannot write invariants: {}", e)))?;
        info!("Trident: Generated invariant checks: {:?}", inv_path);

        // Generate flow sequences (multi-instruction attack patterns)
        let flows = self.generator.generate_flow_sequences(model);
        let flow_path = harness_dir.join("attack_flows.rs");
        std::fs::write(&flow_path, &flows)
            .map_err(|e| TridentError::IoError(format!("Cannot write flows: {}", e)))?;
        info!("Trident: Generated attack flow sequences: {:?}", flow_path);

        // Generate a Cargo.toml for the harness crate
        let cargo_toml = self.generator.generate_cargo_toml(model, program_path);
        std::fs::write(harness_dir.join("Cargo.toml"), cargo_toml)
            .map_err(|e| TridentError::IoError(format!("Cannot write Cargo.toml: {}", e)))?;

        Ok(harness_dir)
    }

    /// Run offline analysis when `trident` CLI is not available.
    ///
    /// Performs static analysis of the extracted Anchor program model to
    /// identify potential fuzzing targets (missing constraints, unchecked
    /// accounts, arithmetic without checked math, etc.) without actually
    /// running the fuzzer.
    fn run_offline_analysis(&self, model: &AnchorProgramModel) -> Vec<CrashReport> {
        let mut reports = Vec::new();

        // Check for missing signer constraints
        for ix in &model.instructions {
            let has_authority_account = ix.accounts.iter().any(|a| {
                a.name.contains("authority") || a.name.contains("admin") || a.name.contains("owner")
            });
            let has_signer_constraint = ix.accounts.iter().any(|a| a.is_signer);

            if has_authority_account && !has_signer_constraint {
                reports.push(CrashReport {
                    category: CrashCategory::MissingSigner,
                    instruction: ix.name.clone(),
                    description: format!(
                        "Instruction '{}' has authority-like account without signer constraint — \
                         fuzzing would likely find unsigned transaction acceptance",
                        ix.name,
                    ),
                    severity: TridentSeverity::Critical,
                    triggering_input: None,
                    state_diff: None,
                    stack_trace: None,
                    iteration: 0,
                    accounts_involved: ix.accounts.iter().map(|a| a.name.clone()).collect(),
                    property_violated: Some("access_control".into()),
                    fix_recommendation: format!(
                        "Add `#[account(signer)]` or use `Signer<'info>` type for authority account in '{}'",
                        ix.name,
                    ),
                });
            }
        }

        // Check for re-initialization vulnerabilities
        for ix in &model.instructions {
            let is_init = ix.name.contains("init") || ix.name.contains("create");
            let has_init_guard = ix.accounts.iter().any(|a| {
                a.constraints
                    .iter()
                    .any(|c| matches!(c, AnchorConstraint::Init | AnchorConstraint::InitIfNeeded))
            });

            if is_init && !has_init_guard {
                reports.push(CrashReport {
                    category: CrashCategory::ReInitialization,
                    instruction: ix.name.clone(),
                    description: format!(
                        "Instruction '{}' appears to be an initializer but lacks `init` constraint — \
                         stateful fuzzing would test re-initialization attack",
                        ix.name,
                    ),
                    severity: TridentSeverity::High,
                    triggering_input: None,
                    state_diff: None,
                    stack_trace: None,
                    iteration: 0,
                    accounts_involved: ix.accounts.iter().map(|a| a.name.clone()).collect(),
                    property_violated: Some("initialization_safety".into()),
                    fix_recommendation: format!(
                        "Use `#[account(init, ...)]` with proper space and payer in '{}'",
                        ix.name,
                    ),
                });
            }
        }

        // Check for unchecked accounts (AccountInfo without constraints)
        for ix in &model.instructions {
            for account in &ix.accounts {
                if account.account_type == "AccountInfo" && account.constraints.is_empty() {
                    let is_dangerous = !account.name.contains("system_program")
                        && !account.name.contains("rent")
                        && !account.name.contains("clock");

                    if is_dangerous {
                        reports.push(CrashReport {
                            category: CrashCategory::AccountConfusion,
                            instruction: ix.name.clone(),
                            description: format!(
                                "Unchecked AccountInfo '{}' in '{}' — Trident would test account \
                                 substitution attacks with thousands of random account permutations",
                                account.name, ix.name,
                            ),
                            severity: TridentSeverity::High,
                            triggering_input: None,
                            state_diff: None,
                            stack_trace: None,
                            iteration: 0,
                            accounts_involved: vec![account.name.clone()],
                            property_violated: Some("account_validation".into()),
                            fix_recommendation: format!(
                                "Replace `AccountInfo` with typed account (e.g., `Account<'info, T>`) \
                                 or add `/// CHECK:` documentation with validation in handler for '{}'",
                                account.name,
                            ),
                        });
                    }
                }
            }
        }

        // Check for PDA seed collision potential
        for pda in &model.pda_derivations {
            if pda.seeds.len() <= 1 {
                reports.push(CrashReport {
                    category: CrashCategory::PDASeedCollision,
                    instruction: pda.instruction.clone(),
                    description: format!(
                        "PDA '{}' derived with {} seed(s) — low-entropy derivation increases \
                         collision risk under stateful fuzzing",
                        pda.account_name,
                        pda.seeds.len(),
                    ),
                    severity: TridentSeverity::Medium,
                    triggering_input: None,
                    state_diff: None,
                    stack_trace: None,
                    iteration: 0,
                    accounts_involved: vec![pda.account_name.clone()],
                    property_violated: Some("pda_uniqueness".into()),
                    fix_recommendation: format!(
                        "Add user-specific or instruction-specific seeds to '{}' PDA derivation \
                         to prevent cross-user collisions",
                        pda.account_name,
                    ),
                });
            }
        }

        // Check for arithmetic without checked math
        for ix in &model.instructions {
            if ix.has_arithmetic && !ix.uses_checked_math {
                reports.push(CrashReport {
                    category: CrashCategory::ArithmeticOverflow,
                    instruction: ix.name.clone(),
                    description: format!(
                        "Instruction '{}' performs arithmetic without checked math — \
                         Trident's random input generation would likely trigger overflow/underflow",
                        ix.name,
                    ),
                    severity: TridentSeverity::High,
                    triggering_input: Some(
                        "u64::MAX, u64::MAX (Trident would generate boundary values)".into(),
                    ),
                    state_diff: None,
                    stack_trace: None,
                    iteration: 0,
                    accounts_involved: ix.accounts.iter().map(|a| a.name.clone()).collect(),
                    property_violated: Some("arithmetic_safety".into()),
                    fix_recommendation: format!(
                        "Replace `+`, `-`, `*` with `.checked_add()`, `.checked_sub()`, \
                         `.checked_mul()` in '{}' or use Anchor's `checked_math!` macro",
                        ix.name,
                    ),
                });
            }
        }

        // Check for CPI without ownership verification
        for ix in &model.instructions {
            if ix.has_cpi && !ix.validates_cpi_program_id {
                reports.push(CrashReport {
                    category: CrashCategory::CPIReentrancy,
                    instruction: ix.name.clone(),
                    description: format!(
                        "Instruction '{}' performs CPI without validating target program ID — \
                         Trident's cross-program fuzzing would test with malicious programs",
                        ix.name,
                    ),
                    severity: TridentSeverity::Critical,
                    triggering_input: None,
                    state_diff: None,
                    stack_trace: None,
                    iteration: 0,
                    accounts_involved: ix.accounts.iter().map(|a| a.name.clone()).collect(),
                    property_violated: Some("cpi_safety".into()),
                    fix_recommendation: format!(
                        "Validate CPI target program ID against expected value in '{}' \
                         (e.g., `require_keys_eq!(ctx.accounts.target_program.key(), expected_id)`)",
                        ix.name,
                    ),
                });
            }
        }

        // Check for close-account lamport drain
        for ix in &model.instructions {
            let is_close = ix.name.contains("close")
                || ix.name.contains("delete")
                || ix.name.contains("remove");
            let has_close_constraint = ix.accounts.iter().any(|a| {
                a.constraints
                    .iter()
                    .any(|c| matches!(c, AnchorConstraint::Close(_)))
            });

            if is_close && !has_close_constraint {
                reports.push(CrashReport {
                    category: CrashCategory::CloseAccountDrain,
                    instruction: ix.name.clone(),
                    description: format!(
                        "Instruction '{}' appears to close an account but lacks `close` constraint — \
                         fuzzing would test lamport drain via manual closing logic",
                        ix.name,
                    ),
                    severity: TridentSeverity::High,
                    triggering_input: None,
                    state_diff: None,
                    stack_trace: None,
                    iteration: 0,
                    accounts_involved: ix.accounts.iter().map(|a| a.name.clone()).collect(),
                    property_violated: Some("close_account_safety".into()),
                    fix_recommendation: format!(
                        "Use `#[account(close = destination)]` Anchor constraint in '{}' \
                         to safely transfer lamports and zero the account",
                        ix.name,
                    ),
                });
            }
        }

        reports
    }
}

impl Default for TridentFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TridentError {
    #[error("IO error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Trident execution error: {0}")]
    ExecutionError(String),

    #[error("Harness generation error: {0}")]
    HarnessError(String),

    #[error("No program found: {0}")]
    NoProgramFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = TridentFuzzer::new();
        assert!(!fuzzer.executor.is_trident_available());
    }

    #[test]
    fn test_fuzzer_default() {
        let fuzzer = TridentFuzzer::default();
        assert!(!fuzzer.executor.is_trident_available());
    }

    #[test]
    fn test_offline_analysis_empty_model() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel::default();
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(reports.is_empty());
    }

    #[test]
    fn test_offline_analysis_missing_signer() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel {
            instructions: vec![AnchorInstruction {
                name: "withdraw".to_string(),
                accounts: vec![AnchorAccount {
                    name: "authority".to_string(),
                    account_type: "AccountInfo".to_string(),
                    raw_type: "AccountInfo<'info>".to_string(),
                    is_signer: false,
                    is_mut: true,
                    constraints: vec![],
                    context_struct: "Withdraw".to_string(),
                }],
                source_file: "lib.rs".to_string(),
                has_arithmetic: false,
                uses_checked_math: false,
                has_cpi: false,
                validates_cpi_program_id: false,
                has_transfer: false,
                parameters: vec![],
            }],
            ..AnchorProgramModel::default()
        };
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(!reports.is_empty());
        assert!(reports
            .iter()
            .any(|r| matches!(r.category, CrashCategory::MissingSigner)));
    }

    #[test]
    fn test_offline_analysis_unchecked_arithmetic() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel {
            instructions: vec![AnchorInstruction {
                name: "deposit".to_string(),
                accounts: vec![],
                source_file: "lib.rs".to_string(),
                has_arithmetic: true,
                uses_checked_math: false,
                has_cpi: false,
                validates_cpi_program_id: false,
                has_transfer: false,
                parameters: vec![],
            }],
            ..AnchorProgramModel::default()
        };
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(reports
            .iter()
            .any(|r| matches!(r.category, CrashCategory::ArithmeticOverflow)));
    }

    #[test]
    fn test_offline_analysis_safe_arithmetic() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel {
            instructions: vec![AnchorInstruction {
                name: "deposit".to_string(),
                accounts: vec![],
                source_file: "lib.rs".to_string(),
                has_arithmetic: true,
                uses_checked_math: true,
                has_cpi: false,
                validates_cpi_program_id: false,
                has_transfer: false,
                parameters: vec![],
            }],
            ..AnchorProgramModel::default()
        };
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(!reports
            .iter()
            .any(|r| matches!(r.category, CrashCategory::ArithmeticOverflow)));
    }

    #[test]
    fn test_offline_analysis_unchecked_cpi() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel {
            instructions: vec![AnchorInstruction {
                name: "transfer".to_string(),
                accounts: vec![],
                source_file: "lib.rs".to_string(),
                has_arithmetic: false,
                uses_checked_math: false,
                has_cpi: true,
                validates_cpi_program_id: false,
                has_transfer: false,
                parameters: vec![],
            }],
            ..AnchorProgramModel::default()
        };
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(reports
            .iter()
            .any(|r| matches!(r.category, CrashCategory::CPIReentrancy)));
    }

    #[test]
    fn test_offline_analysis_low_entropy_pda() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel {
            pda_derivations: vec![PdaDerivation {
                account_name: "vault".to_string(),
                instruction: "init".to_string(),
                seeds: vec!["vault".to_string()],
                bump_seed: true,
            }],
            ..AnchorProgramModel::default()
        };
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(reports
            .iter()
            .any(|r| matches!(r.category, CrashCategory::PDASeedCollision)));
    }

    #[test]
    fn test_offline_analysis_unchecked_account_info() {
        let fuzzer = TridentFuzzer::new();
        let model = AnchorProgramModel {
            instructions: vec![AnchorInstruction {
                name: "process".to_string(),
                accounts: vec![AnchorAccount {
                    name: "target".to_string(),
                    account_type: "AccountInfo".to_string(),
                    raw_type: "AccountInfo<'info>".to_string(),
                    is_signer: false,
                    is_mut: false,
                    constraints: vec![],
                    context_struct: "Process".to_string(),
                }],
                source_file: "lib.rs".to_string(),
                has_arithmetic: false,
                uses_checked_math: false,
                has_cpi: false,
                validates_cpi_program_id: false,
                has_transfer: false,
                parameters: vec![],
            }],
            ..AnchorProgramModel::default()
        };
        let reports = fuzzer.run_offline_analysis(&model);
        assert!(reports
            .iter()
            .any(|r| matches!(r.category, CrashCategory::AccountConfusion)));
    }

    #[test]
    fn test_error_display() {
        let err = TridentError::IoError("io fail".to_string());
        assert!(err.to_string().contains("io fail"));
        let err = TridentError::NoProgramFound("missing".to_string());
        assert!(err.to_string().contains("missing"));
        let err = TridentError::HarnessError("bad harness".to_string());
        assert!(err.to_string().contains("bad harness"));
    }
}
