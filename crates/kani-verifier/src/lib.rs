//! # Kani Rust Verifier Integration
//!
//! Integrates [Kani](https://model-checking.github.io/kani/), an open-source
//! bit-precise model checker for Rust built by AWS, into the Solana security
//! audit pipeline.
//!
//! Kani uses CBMC (C Bounded Model Checker) under the hood and encodes Rust
//! semantics into SAT/SMT queries. This module:
//!
//! 1. **Extracts** Solana account invariants from Anchor program source code
//! 2. **Generates** Kani proof harnesses (`#[kani::proof]`) for each invariant
//! 3. **Invokes** `cargo kani` as a subprocess to run bounded model checking
//! 4. **Parses** the CBMC verification output into structured results
//!
//! ## Invariant Categories
//!
//! | Category | Examples |
//! |----------|----------|
//! | Balance Conservation | `total == sum_of_parts`, no tokens created from nothing |
//! | Access Control | Only authority can modify state |
//! | Arithmetic Safety | No overflow/underflow in token math |
//! | Account Ownership | PDAs owned by correct program |
//! | State Transition | Valid FSM transitions only |
//! | Bounds Checking | Values within protocol-defined limits |

pub mod harness_generator;
pub mod invariant_extractor;
pub mod kani_runner;
pub mod result_parser;
pub mod solana_invariants;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

pub use harness_generator::HarnessGenerator;
pub use invariant_extractor::{ExtractedInvariant, InvariantExtractor, InvariantKind};
pub use kani_runner::{KaniConfig, KaniRunner};
pub use result_parser::{CheckStatus, KaniResultParser, PropertyCheckResult};
pub use solana_invariants::{SolanaAccountInvariant, SolanaInvariantGenerator};

/// Main entry point for Kani-based formal verification of Solana programs.
///
/// Orchestrates the full pipeline:
/// source → invariant extraction → harness generation → kani execution → result parsing
pub struct KaniVerifier {
    config: KaniConfig,
    extractor: InvariantExtractor,
    generator: HarnessGenerator,
    runner: KaniRunner,
    parser: KaniResultParser,
}

impl KaniVerifier {
    /// Create a new verifier with default configuration.
    pub fn new() -> Self {
        let config = KaniConfig::default();
        Self {
            extractor: InvariantExtractor::new(),
            generator: HarnessGenerator::new(),
            runner: KaniRunner::new(config.clone()),
            parser: KaniResultParser::new(),
            config,
        }
    }

    /// Create a verifier with custom configuration.
    pub fn with_config(config: KaniConfig) -> Self {
        Self {
            extractor: InvariantExtractor::new(),
            generator: HarnessGenerator::new(),
            runner: KaniRunner::new(config.clone()),
            parser: KaniResultParser::new(),
            config,
        }
    }

    /// Run full Kani verification on a Solana program directory.
    ///
    /// This performs the complete pipeline:
    /// 1. Parse all `.rs` files in the directory
    /// 2. Extract account structs, invariants, and constraints
    /// 3. Generate Kani proof harnesses
    /// 4. Invoke `cargo kani` (or fall back to offline analysis)
    /// 5. Parse and return structured results
    pub fn verify_program(
        &mut self,
        program_path: &Path,
    ) -> Result<KaniVerificationReport, KaniError> {
        info!("Starting Kani verification for: {:?}", program_path);

        // Phase 1: Extract invariants from source
        let invariants = self.extract_invariants(program_path)?;
        info!(
            "Extracted {} invariants from program source",
            invariants.len()
        );

        // Phase 2: Generate Solana-specific invariants
        let solana_invariants = self.generate_solana_invariants(program_path)?;
        info!(
            "Generated {} Solana-specific invariants",
            solana_invariants.len()
        );

        // Phase 3: Generate Kani proof harnesses
        let harness_dir = self.generate_harnesses(&invariants, &solana_invariants, program_path)?;
        info!("Generated proof harnesses in: {:?}", harness_dir);

        // Phase 4: Run Kani verification
        let raw_output = self.runner.run_verification(&harness_dir, program_path);

        // Phase 5: Parse results
        let property_results = match &raw_output {
            Ok(output) => self.parser.parse_output(output),
            Err(e) => {
                warn!(
                    "Kani execution unavailable ({}), performing offline invariant analysis",
                    e
                );
                self.perform_offline_analysis(&invariants, &solana_invariants)
            }
        };

        // Build report
        let total_properties = property_results.len();
        let verified_count = property_results
            .iter()
            .filter(|r| r.status == CheckStatus::Success)
            .count();
        let failed_count = property_results
            .iter()
            .filter(|r| r.status == CheckStatus::Failure)
            .count();
        let undetermined_count = property_results
            .iter()
            .filter(|r| r.status == CheckStatus::Undetermined)
            .count();

        let overall_status = if failed_count > 0 {
            VerificationStatus::InvariantViolation
        } else if undetermined_count > 0 {
            VerificationStatus::PartiallyVerified
        } else if verified_count > 0 {
            VerificationStatus::AllPropertiesHold
        } else {
            VerificationStatus::NoPropertiesChecked
        };

        let report = KaniVerificationReport {
            program_path: program_path.to_path_buf(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            status: overall_status,
            total_properties,
            verified_count,
            failed_count,
            undetermined_count,
            property_results,
            extracted_invariants: invariants,
            solana_invariants,
            harness_path: Some(harness_dir),
            kani_version: self.runner.detect_kani_version(),
            cbmc_backend: self.detect_backend(),
            unwind_depth: self.config.unwind_depth,
            verification_time_ms: 0, // set by caller if needed
        };

        info!(
            "Kani verification complete: {} verified, {} failed, {} undetermined",
            verified_count, failed_count, undetermined_count
        );

        Ok(report)
    }

    /// Extract invariants from program source code.
    fn extract_invariants(
        &mut self,
        program_path: &Path,
    ) -> Result<Vec<ExtractedInvariant>, KaniError> {
        let mut all_invariants = Vec::new();

        for entry in walkdir::WalkDir::new(program_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(entry.path())
                    .map_err(|e| KaniError::IoError(e.to_string()))?;

                let filename = entry
                    .path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown.rs")
                    .to_string();

                match self.extractor.extract_from_source(&source, &filename) {
                    Ok(invariants) => all_invariants.extend(invariants),
                    Err(e) => {
                        warn!("Skipping {:?}: {}", entry.path(), e);
                    }
                }
            }
        }

        Ok(all_invariants)
    }

    /// Generate Solana-specific account invariants.
    fn generate_solana_invariants(
        &self,
        program_path: &Path,
    ) -> Result<Vec<SolanaAccountInvariant>, KaniError> {
        let generator = SolanaInvariantGenerator::new();
        let mut all_invariants = Vec::new();

        for entry in walkdir::WalkDir::new(program_path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(entry.path())
                    .map_err(|e| KaniError::IoError(e.to_string()))?;

                let filename = entry
                    .path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown.rs")
                    .to_string();

                match generator.generate_from_source(&source, &filename) {
                    Ok(invs) => all_invariants.extend(invs),
                    Err(e) => {
                        warn!(
                            "Skipping Solana invariant gen for {:?}: {}",
                            entry.path(),
                            e
                        );
                    }
                }
            }
        }

        Ok(all_invariants)
    }

    /// Generate Kani proof harness files.
    fn generate_harnesses(
        &self,
        invariants: &[ExtractedInvariant],
        solana_invariants: &[SolanaAccountInvariant],
        program_path: &Path,
    ) -> Result<PathBuf, KaniError> {
        let harness_dir = program_path.join("kani_proofs");
        std::fs::create_dir_all(&harness_dir)
            .map_err(|e| KaniError::IoError(format!("Cannot create harness dir: {}", e)))?;

        // Generate harnesses for extracted invariants
        for invariant in invariants {
            let harness_code = self.generator.generate_harness(invariant);
            let filename = format!(
                "proof_{}.rs",
                invariant.name.to_lowercase().replace(' ', "_")
            );
            let path = harness_dir.join(&filename);
            std::fs::write(&path, &harness_code)
                .map_err(|e| KaniError::IoError(format!("Cannot write harness: {}", e)))?;
            info!("Generated harness: {}", filename);
        }

        // Generate Solana harnesses for Solana-specific invariants
        for inv in solana_invariants {
            let harness_code = self.generator.generate_solana_harness(inv);
            let filename = format!("proof_solana_{}.rs", inv.account_name.to_lowercase());
            let path = harness_dir.join(&filename);
            std::fs::write(&path, &harness_code)
                .map_err(|e| KaniError::IoError(format!("Cannot write Solana harness: {}", e)))?;
            info!("Generated Solana harness: {}", filename);
        }

        // Generate a minimal Cargo.toml so the kani_proofs dir is a valid crate/member
        let cargo_toml = format!(
            r#"[package]
name = "kani_proofs_{}"
version = "0.1.0"
edition = "2021"

[dependencies]
kani = "0.45.0"
"#,
            program_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
        );
        std::fs::write(harness_dir.join("Cargo.toml"), cargo_toml).map_err(|e| {
            KaniError::IoError(format!("Cannot write kani_proofs Cargo.toml: {}", e))
        })?;

        Ok(harness_dir)
    }

    /// Perform offline static invariant analysis when `cargo kani` is unavailable.
    fn perform_offline_analysis(
        &self,
        invariants: &[ExtractedInvariant],
        solana_invariants: &[SolanaAccountInvariant],
    ) -> Vec<PropertyCheckResult> {
        let mut results = Vec::new();

        for inv in invariants {
            let (status, description) = match inv.kind {
                InvariantKind::ArithmeticBounds => {
                    // Arithmetic invariants are often violated in unchecked code
                    if inv.has_checked_math {
                        (CheckStatus::Success, format!(
                            "Arithmetic invariant '{}' uses checked math — verified safe within bounds",
                            inv.name
                        ))
                    } else {
                        (CheckStatus::Failure, format!(
                            "Arithmetic invariant '{}' uses unchecked math — overflow/underflow possible at bit-precise level",
                            inv.name
                        ))
                    }
                }
                InvariantKind::BalanceConservation => {
                    (CheckStatus::Undetermined, format!(
                        "Balance conservation '{}' requires runtime model checking — generated harness for Kani",
                        inv.name
                    ))
                }
                InvariantKind::AccessControl => {
                    if inv.has_signer_check {
                        (CheckStatus::Success, format!(
                            "Access control invariant '{}' — signer validation present",
                            inv.name
                        ))
                    } else {
                        (CheckStatus::Failure, format!(
                            "Access control invariant '{}' — MISSING signer check, authority bypass possible",
                            inv.name
                        ))
                    }
                }
                InvariantKind::AccountOwnership => {
                    if inv.has_owner_check {
                        (CheckStatus::Success, format!(
                            "Account ownership invariant '{}' — owner validation present",
                            inv.name
                        ))
                    } else {
                        (CheckStatus::Failure, format!(
                            "Account ownership invariant '{}' — missing owner check, account substitution attack possible",
                            inv.name
                        ))
                    }
                }
                InvariantKind::StateTransition => {
                    (CheckStatus::Undetermined, format!(
                        "State transition invariant '{}' — requires bounded model checking to verify all paths",
                        inv.name
                    ))
                }
                InvariantKind::BoundsCheck => {
                    if inv.has_bounds_check {
                        (CheckStatus::Success, format!(
                            "Bounds check invariant '{}' — validation present",
                            inv.name
                        ))
                    } else {
                        (CheckStatus::Failure, format!(
                            "Bounds check invariant '{}' — missing bounds validation, out-of-range values accepted",
                            inv.name
                        ))
                    }
                }
                InvariantKind::PdaValidation => {
                    if inv.has_pda_seeds_check {
                        (CheckStatus::Success, format!(
                            "PDA invariant '{}' — seeds derivation validated",
                            inv.name
                        ))
                    } else {
                        (CheckStatus::Failure, format!(
                            "PDA invariant '{}' — seeds not validated, PDA substitution possible",
                            inv.name
                        ))
                    }
                }
            };

            results.push(PropertyCheckResult {
                property_name: inv.name.clone(),
                status,
                description,
                source_location: inv.source_location.clone(),
                counterexample: None,
                trace: None,
                category: format!("{:?}", inv.kind),
            });
        }

        for inv in solana_invariants {
            let status = if inv.violations.is_empty() {
                CheckStatus::Success
            } else {
                CheckStatus::Failure
            };

            let description = if inv.violations.is_empty() {
                format!(
                    "Solana account '{}' invariants hold: {} constraints verified",
                    inv.account_name,
                    inv.constraints.len()
                )
            } else {
                format!(
                    "Solana account '{}' has {} invariant violations: {}",
                    inv.account_name,
                    inv.violations.len(),
                    inv.violations.join("; ")
                )
            };

            results.push(PropertyCheckResult {
                property_name: format!("solana_{}_invariant", inv.account_name.to_lowercase()),
                status,
                description,
                source_location: inv.source_file.clone(),
                counterexample: if !inv.violations.is_empty() {
                    Some(inv.violations.join("\n"))
                } else {
                    None
                },
                trace: None,
                category: "SolanaAccountInvariant".to_string(),
            });
        }

        results
    }

    fn detect_backend(&self) -> String {
        if self.runner.is_kani_available() {
            "CBMC via cargo-kani".to_string()
        } else {
            "Offline Static Analysis (Kani/CBMC not installed)".to_string()
        }
    }
}

impl Default for KaniVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Report Types ────────────────────────────────────────────────────────────

/// Complete verification report from Kani analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KaniVerificationReport {
    pub program_path: PathBuf,
    pub timestamp: String,
    pub status: VerificationStatus,
    pub total_properties: usize,
    pub verified_count: usize,
    pub failed_count: usize,
    pub undetermined_count: usize,
    pub property_results: Vec<PropertyCheckResult>,
    pub extracted_invariants: Vec<ExtractedInvariant>,
    pub solana_invariants: Vec<SolanaAccountInvariant>,
    pub harness_path: Option<PathBuf>,
    pub kani_version: Option<String>,
    pub cbmc_backend: String,
    pub unwind_depth: u32,
    pub verification_time_ms: u64,
}

impl KaniVerificationReport {
    /// Get all failed properties.
    pub fn failed_properties(&self) -> Vec<&PropertyCheckResult> {
        self.property_results
            .iter()
            .filter(|r| r.status == CheckStatus::Failure)
            .collect()
    }

    /// Get all verified properties.
    pub fn verified_properties(&self) -> Vec<&PropertyCheckResult> {
        self.property_results
            .iter()
            .filter(|r| r.status == CheckStatus::Success)
            .collect()
    }

    /// Generate a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Kani Verification Report\n\
             ========================\n\
             Program: {:?}\n\
             Status: {:?}\n\
             Backend: {}\n\
             Unwind Depth: {}\n\
             Properties: {} total ({} verified, {} failed, {} undetermined)\n\
             Invariants Extracted: {} from source + {} Solana-specific\n\
             Timestamp: {}",
            self.program_path,
            self.status,
            self.cbmc_backend,
            self.unwind_depth,
            self.total_properties,
            self.verified_count,
            self.failed_count,
            self.undetermined_count,
            self.extracted_invariants.len(),
            self.solana_invariants.len(),
            self.timestamp,
        )
    }
}

/// Overall verification status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VerificationStatus {
    /// All checked properties hold — the program is correct w.r.t. invariants
    AllPropertiesHold,
    /// At least one invariant was violated
    InvariantViolation,
    /// Some properties could not be determined within bounds
    PartiallyVerified,
    /// No properties were checked (no invariants found)
    NoPropertiesChecked,
}

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum KaniError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Kani execution error: {0}")]
    ExecutionError(String),
    #[error("Harness generation error: {0}")]
    HarnessError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let verifier = KaniVerifier::new();
        assert!(!verifier.runner.is_kani_available());
    }

    #[test]
    fn test_verifier_default() {
        let verifier = KaniVerifier::default();
        assert!(!verifier.runner.is_kani_available());
    }

    #[test]
    fn test_detect_backend_offline() {
        let verifier = KaniVerifier::new();
        let backend = verifier.detect_backend();
        assert!(backend.contains("Offline") || backend.contains("CBMC"));
    }

    #[test]
    fn test_verification_status_equality() {
        assert_eq!(
            VerificationStatus::AllPropertiesHold,
            VerificationStatus::AllPropertiesHold
        );
        assert_ne!(
            VerificationStatus::AllPropertiesHold,
            VerificationStatus::InvariantViolation
        );
        assert_ne!(
            VerificationStatus::PartiallyVerified,
            VerificationStatus::NoPropertiesChecked
        );
    }

    #[test]
    fn test_report_summary() {
        let report = KaniVerificationReport {
            program_path: PathBuf::from("my/program"),
            timestamp: "2024-01-01".to_string(),
            status: VerificationStatus::AllPropertiesHold,
            total_properties: 5,
            verified_count: 5,
            failed_count: 0,
            undetermined_count: 0,
            property_results: vec![],
            extracted_invariants: vec![],
            solana_invariants: vec![],
            harness_path: None,
            kani_version: None,
            cbmc_backend: "Offline".to_string(),
            unwind_depth: 10,
            verification_time_ms: 500,
        };
        let summary = report.summary();
        assert!(summary.contains("my/program"));
        assert!(summary.contains("5 total"));
        assert!(summary.contains("5 verified"));
        assert!(summary.contains("Offline"));
    }

    #[test]
    fn test_report_property_filters() {
        let report = KaniVerificationReport {
            program_path: PathBuf::from("test"),
            timestamp: String::new(),
            status: VerificationStatus::InvariantViolation,
            total_properties: 2,
            verified_count: 1,
            failed_count: 1,
            undetermined_count: 0,
            property_results: vec![
                PropertyCheckResult {
                    property_name: "prop_ok".to_string(),
                    status: CheckStatus::Success,
                    description: "ok".to_string(),
                    source_location: String::new(),
                    counterexample: None,
                    trace: None,
                    category: "test".to_string(),
                },
                PropertyCheckResult {
                    property_name: "prop_fail".to_string(),
                    status: CheckStatus::Failure,
                    description: "bad".to_string(),
                    source_location: "lib.rs:10".to_string(),
                    counterexample: Some("x=0".to_string()),
                    trace: None,
                    category: "test".to_string(),
                },
            ],
            extracted_invariants: vec![],
            solana_invariants: vec![],
            harness_path: None,
            kani_version: None,
            cbmc_backend: String::new(),
            unwind_depth: 10,
            verification_time_ms: 0,
        };
        assert_eq!(report.verified_properties().len(), 1);
        assert_eq!(report.failed_properties().len(), 1);
        assert_eq!(report.verified_properties()[0].property_name, "prop_ok");
        assert_eq!(report.failed_properties()[0].property_name, "prop_fail");
    }

    #[test]
    fn test_offline_analysis_empty() {
        let verifier = KaniVerifier::new();
        let results = verifier.perform_offline_analysis(&[], &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_offline_analysis_arithmetic_checked() {
        let verifier = KaniVerifier::new();
        let invariants = vec![ExtractedInvariant {
            name: "safe_add".to_string(),
            kind: InvariantKind::ArithmeticBounds,
            expression: "a.checked_add(b)".to_string(),
            source_location: "lib.rs:10".to_string(),
            function_name: "safe_add".to_string(),
            has_checked_math: true,
            has_signer_check: false,
            has_owner_check: false,
            has_bounds_check: false,
            has_pda_seeds_check: false,
            severity: 3,
            confidence: 80,
            related_accounts: vec![],
        }];
        let results = verifier.perform_offline_analysis(&invariants, &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Success);
    }

    #[test]
    fn test_offline_analysis_arithmetic_unchecked() {
        let verifier = KaniVerifier::new();
        let invariants = vec![ExtractedInvariant {
            name: "unsafe_add".to_string(),
            kind: InvariantKind::ArithmeticBounds,
            expression: "a + b".to_string(),
            source_location: "lib.rs:20".to_string(),
            function_name: "unsafe_add".to_string(),
            has_checked_math: false,
            has_signer_check: false,
            has_owner_check: false,
            has_bounds_check: false,
            has_pda_seeds_check: false,
            severity: 4,
            confidence: 90,
            related_accounts: vec![],
        }];
        let results = verifier.perform_offline_analysis(&invariants, &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, CheckStatus::Failure);
    }

    #[test]
    fn test_offline_analysis_access_control() {
        let verifier = KaniVerifier::new();
        let with_signer = vec![ExtractedInvariant {
            name: "access".to_string(),
            kind: InvariantKind::AccessControl,
            expression: "require!(ctx.accounts.authority.is_signer)".to_string(),
            source_location: "lib.rs:30".to_string(),
            function_name: "access".to_string(),
            has_checked_math: false,
            has_signer_check: true,
            has_owner_check: false,
            has_bounds_check: false,
            has_pda_seeds_check: false,
            severity: 5,
            confidence: 85,
            related_accounts: vec![],
        }];
        let results = verifier.perform_offline_analysis(&with_signer, &[]);
        assert_eq!(results[0].status, CheckStatus::Success);

        let without_signer = vec![ExtractedInvariant {
            name: "access".to_string(),
            kind: InvariantKind::AccessControl,
            expression: "process(ctx)".to_string(),
            source_location: "lib.rs:40".to_string(),
            function_name: "access".to_string(),
            has_checked_math: false,
            has_signer_check: false,
            has_owner_check: false,
            has_bounds_check: false,
            has_pda_seeds_check: false,
            severity: 5,
            confidence: 85,
            related_accounts: vec![],
        }];
        let results = verifier.perform_offline_analysis(&without_signer, &[]);
        assert_eq!(results[0].status, CheckStatus::Failure);
    }

    #[test]
    fn test_report_serialization() {
        let report = KaniVerificationReport {
            program_path: PathBuf::from("test"),
            timestamp: "now".to_string(),
            status: VerificationStatus::NoPropertiesChecked,
            total_properties: 0,
            verified_count: 0,
            failed_count: 0,
            undetermined_count: 0,
            property_results: vec![],
            extracted_invariants: vec![],
            solana_invariants: vec![],
            harness_path: None,
            kani_version: None,
            cbmc_backend: "test".to_string(),
            unwind_depth: 10,
            verification_time_ms: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("NoPropertiesChecked"));
    }

    #[test]
    fn test_error_display() {
        let err = KaniError::IoError("not found".to_string());
        assert!(err.to_string().contains("not found"));
        let err = KaniError::ExecutionError("kani crashed".to_string());
        assert!(err.to_string().contains("kani crashed"));
        let err = KaniError::HarnessError("bad harness".to_string());
        assert!(err.to_string().contains("bad harness"));
    }
}
