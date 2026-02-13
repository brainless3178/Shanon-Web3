//! # Certora Solana Prover Integration
//!
//! Integrates the [Certora Solana Prover](https://docs.certora.com/en/latest/docs/solana/index.html),
//! a formal verification tool that operates directly on **SBF (Solana Binary Format)** bytecode.
//!
//! ## Why SBF-level verification?
//!
//! Source-code analysis (Kani, static analysis) operates on Rust AST and catches
//! logic bugs visible in source. However, the Solana compiler toolchain
//! (`cargo build-sbf`) can introduce bugs during:
//!
//! - LLVM optimizations (dead code elimination, reordering)
//! - BPF code generation (register allocation, stack management)
//! - Linking (cross-crate inlining, monomorphization)
//!
//! The Certora Solana Prover catches these by verifying the **actual deployed bytecode**.
//!
//! ## Pipeline
//!
//! 1. **Build** the Solana program via `cargo build-sbf` to produce `.so` files
//! 2. **Generate** CVLR (Certora Verification Language for Rust) specification rules
//! 3. **Build `.conf`** configuration for the Certora Prover
//! 4. **Invoke** `certoraSolanaProver` or `cargo certora-sbf` subprocess
//! 5. **Parse** verification results (PASSED/FAILED/TIMEOUT per rule)
//! 6. **Offline fallback**: Direct SBF binary analysis when cloud prover is unavailable
//!
//! ## Integration point
//!
//! This runs **after** source-code analysis (ProgramAnalyzer, Kani) as a
//! post-compilation validation step, before deployment.

pub mod bytecode_patterns;
pub mod certora_runner;
pub mod config_builder;
pub mod result_parser;
pub mod sbf_analyzer;
pub mod spec_generator;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

pub use bytecode_patterns::{BytecodePatternScanner, BytecodeVulnerability};
pub use certora_runner::{CertoraConfig, CertoraRunner};
pub use config_builder::CertoraConfBuilder;
pub use result_parser::{CertoraResultParser, RuleStatus, RuleVerificationResult};
pub use sbf_analyzer::{SbfAnalyzer, SbfBinaryInfo, SbfVulnerability};
pub use spec_generator::{CvlrRule, CvlrSpecGenerator};

/// Main entry point for Certora-based SBF bytecode verification.
///
/// Orchestrates the full pipeline:
/// source → build SBF → generate specs → run Certora → parse results
///
/// Falls back to direct SBF binary pattern analysis when the Certora
/// cloud prover is unavailable.
pub struct CertoraVerifier {
    config: CertoraConfig,
    sbf_analyzer: SbfAnalyzer,
    spec_generator: CvlrSpecGenerator,
    runner: CertoraRunner,
    parser: CertoraResultParser,
    pattern_scanner: BytecodePatternScanner,
}

impl CertoraVerifier {
    pub fn new() -> Self {
        let config = CertoraConfig::default();
        Self {
            sbf_analyzer: SbfAnalyzer::new(),
            spec_generator: CvlrSpecGenerator::new(),
            runner: CertoraRunner::new(config.clone()),
            parser: CertoraResultParser::new(),
            pattern_scanner: BytecodePatternScanner::new(),
            config,
        }
    }

    pub fn with_config(config: CertoraConfig) -> Self {
        Self {
            sbf_analyzer: SbfAnalyzer::new(),
            spec_generator: CvlrSpecGenerator::new(),
            runner: CertoraRunner::new(config.clone()),
            parser: CertoraResultParser::new(),
            pattern_scanner: BytecodePatternScanner::new(),
            config,
        }
    }

    /// Run full Certora verification on a Solana program.
    ///
    /// 1. Build the program to SBF bytecode (`.so`)
    /// 2. Analyze the binary for structural properties
    /// 3. Generate CVLR specification rules
    /// 4. Run Certora Prover (or offline analysis)
    /// 5. Return structured report
    pub fn verify_program(
        &mut self,
        program_path: &Path,
    ) -> Result<CertoraVerificationReport, CertoraError> {
        info!(
            "Starting Certora SBF bytecode verification for: {:?}",
            program_path
        );
        let start_time = std::time::Instant::now();

        // Phase 1: Build to SBF bytecode
        let sbf_path = self.build_sbf(program_path)?;
        info!("SBF binary built: {:?}", sbf_path);

        // Phase 2: Analyze the SBF binary
        let binary_info = self.sbf_analyzer.analyze_binary(&sbf_path)?;
        info!(
            "SBF binary analysis: {} bytes, {} sections, {} symbols",
            binary_info.file_size,
            binary_info.sections.len(),
            binary_info.symbols.len()
        );

        // Phase 3: Generate CVLR specification rules
        let spec_rules = self
            .spec_generator
            .generate_rules(program_path, &binary_info)?;
        info!("Generated {} CVLR verification rules", spec_rules.len());

        // Phase 4: Run bytecode pattern analysis (always runs — no external deps)
        let bytecode_vulns = self.pattern_scanner.scan_binary(&sbf_path)?;
        info!(
            "Bytecode pattern scan found {} potential issues",
            bytecode_vulns.len()
        );

        // Phase 5: Build config and run Certora Prover (if available)
        let certora_results = if self.runner.is_certora_available() {
            info!("Certora Prover available — running cloud verification...");
            let conf_path = self.build_config(program_path, &sbf_path, &spec_rules)?;
            match self.runner.run_verification(&conf_path) {
                Ok(raw_output) => {
                    info!("Certora verification complete");
                    self.parser.parse_output(&raw_output)
                }
                Err(e) => {
                    warn!("Certora cloud verification failed: {}", e);
                    Vec::new()
                }
            }
        } else {
            warn!("certoraSolanaProver not installed — using offline SBF analysis");
            Vec::new()
        };

        // Phase 6: Aggregate results
        let mut all_results = certora_results;

        // Convert bytecode vulnerabilities to rule verification results
        for vuln in &bytecode_vulns {
            all_results.push(RuleVerificationResult {
                rule_name: format!("sbf_pattern_{}", vuln.pattern_id),
                status: RuleStatus::Failed,
                description: vuln.description.clone(),
                counterexample: vuln.details.clone(),
                source_location: vuln.offset.map(|o| format!("SBF offset 0x{:x}", o)),
                severity: vuln.severity,
                category: format!("SBF Bytecode: {}", vuln.category),
            });
        }

        let total_rules = all_results.len();
        let passed = all_results
            .iter()
            .filter(|r| r.status == RuleStatus::Passed)
            .count();
        let failed = all_results
            .iter()
            .filter(|r| r.status == RuleStatus::Failed)
            .count();
        let timeout = all_results
            .iter()
            .filter(|r| r.status == RuleStatus::Timeout)
            .count();
        let sanity_failed = all_results
            .iter()
            .filter(|r| r.status == RuleStatus::SanityFailed)
            .count();

        let overall_status = if failed > 0 {
            SbfVerificationStatus::ViolationsFound
        } else if timeout > 0 || sanity_failed > 0 {
            SbfVerificationStatus::PartiallyVerified
        } else if passed > 0 {
            SbfVerificationStatus::AllRulesPass
        } else {
            SbfVerificationStatus::NoRulesChecked
        };

        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        let report = CertoraVerificationReport {
            program_path: program_path.to_path_buf(),
            sbf_binary_path: Some(sbf_path),
            binary_info: Some(binary_info),
            timestamp: chrono::Utc::now().to_rfc3339(),
            status: overall_status,
            total_rules,
            passed_count: passed,
            failed_count: failed,
            timeout_count: timeout,
            sanity_failed_count: sanity_failed,
            rule_results: all_results,
            bytecode_vulnerabilities: bytecode_vulns,
            certora_version: self.runner.detect_certora_version(),
            prover_backend: self.detect_backend(),
            verification_time_ms: elapsed_ms,
        };

        info!(
            "Certora verification complete in {}ms: {} passed, {} failed, {} timeout",
            elapsed_ms, passed, failed, timeout
        );

        Ok(report)
    }

    /// Build the Solana program to SBF bytecode.
    fn build_sbf(&self, program_path: &Path) -> Result<PathBuf, CertoraError> {
        // Look for existing .so files first
        let target_dir = program_path.join("target").join("deploy");
        if target_dir.exists() {
            for entry in walkdir::WalkDir::new(&target_dir)
                .max_depth(2)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("so") {
                    info!("Found existing SBF binary: {:?}", entry.path());
                    return Ok(entry.path().to_path_buf());
                }
            }
        }

        // Also check target/sbf-solana-solana/release
        let sbf_dir = program_path
            .join("target")
            .join("sbf-solana-solana")
            .join("release");
        if sbf_dir.exists() {
            for entry in walkdir::WalkDir::new(&sbf_dir)
                .max_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("so") {
                    return Ok(entry.path().to_path_buf());
                }
            }
        }

        // Try to build using cargo build-sbf
        info!("No pre-built SBF binary found, running cargo build-sbf...");
        let output = std::process::Command::new("cargo")
            .arg("build-sbf")
            .current_dir(program_path)
            .output()
            .map_err(|e| {
                CertoraError::BuildError(format!(
                    "Failed to invoke cargo build-sbf: {}. Install via: solana-install init",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CertoraError::BuildError(format!(
                "cargo build-sbf failed: {}",
                stderr
            )));
        }

        // Find the built .so
        let target_dir = program_path.join("target").join("deploy");
        for entry in walkdir::WalkDir::new(&target_dir)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("so") {
                return Ok(entry.path().to_path_buf());
            }
        }

        Err(CertoraError::BuildError(
            "No .so file found after cargo build-sbf".to_string(),
        ))
    }

    /// Build the Certora `.conf` configuration file.
    fn build_config(
        &self,
        program_path: &Path,
        sbf_path: &Path,
        rules: &[CvlrRule],
    ) -> Result<PathBuf, CertoraError> {
        let builder = CertoraConfBuilder::new();
        builder.build(program_path, sbf_path, rules, &self.config)
    }

    fn detect_backend(&self) -> String {
        if self.runner.is_certora_available() {
            "Certora Solana Prover (Cloud)".to_string()
        } else {
            "Offline SBF Binary Analysis (Certora Prover not installed)".to_string()
        }
    }
}

impl Default for CertoraVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Report Types ────────────────────────────────────────────────────────────

/// Complete verification report from Certora SBF analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertoraVerificationReport {
    pub program_path: PathBuf,
    pub sbf_binary_path: Option<PathBuf>,
    pub binary_info: Option<SbfBinaryInfo>,
    pub timestamp: String,
    pub status: SbfVerificationStatus,
    pub total_rules: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub timeout_count: usize,
    pub sanity_failed_count: usize,
    pub rule_results: Vec<RuleVerificationResult>,
    pub bytecode_vulnerabilities: Vec<BytecodeVulnerability>,
    pub certora_version: Option<String>,
    pub prover_backend: String,
    pub verification_time_ms: u64,
}

impl CertoraVerificationReport {
    pub fn failed_rules(&self) -> Vec<&RuleVerificationResult> {
        self.rule_results
            .iter()
            .filter(|r| r.status == RuleStatus::Failed)
            .collect()
    }

    pub fn passed_rules(&self) -> Vec<&RuleVerificationResult> {
        self.rule_results
            .iter()
            .filter(|r| r.status == RuleStatus::Passed)
            .collect()
    }

    pub fn summary(&self) -> String {
        format!(
            "Certora SBF Verification Report\n\
             ================================\n\
             Program: {:?}\n\
             SBF Binary: {:?}\n\
             Status: {:?}\n\
             Backend: {}\n\
             Rules: {} total ({} passed, {} failed, {} timeout)\n\
             Bytecode Issues: {}\n\
             Duration: {}ms\n\
             Timestamp: {}",
            self.program_path,
            self.sbf_binary_path,
            self.status,
            self.prover_backend,
            self.total_rules,
            self.passed_count,
            self.failed_count,
            self.timeout_count,
            self.bytecode_vulnerabilities.len(),
            self.verification_time_ms,
            self.timestamp,
        )
    }
}

/// Overall bytecode verification status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SbfVerificationStatus {
    /// All CVLR rules pass — bytecode is correct w.r.t. specs
    AllRulesPass,
    /// At least one rule failed — bytecode violates specification
    ViolationsFound,
    /// Some rules passed, some timed out or had sanity issues
    PartiallyVerified,
    /// No rules were checked
    NoRulesChecked,
}

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CertoraError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("SBF build error: {0}")]
    BuildError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Certora execution error: {0}")]
    ExecutionError(String),
    #[error("Specification generation error: {0}")]
    SpecError(String),
    #[error("Binary analysis error: {0}")]
    BinaryError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let verifier = CertoraVerifier::new();
        assert!(!verifier.runner.is_certora_available());
    }

    #[test]
    fn test_verifier_default() {
        let verifier = CertoraVerifier::default();
        assert!(!verifier.runner.is_certora_available());
    }

    #[test]
    fn test_detect_backend_offline() {
        let verifier = CertoraVerifier::new();
        let backend = verifier.detect_backend();
        assert!(backend.contains("Offline") || backend.contains("Cloud"));
    }

    #[test]
    fn test_verification_status_equality() {
        assert_eq!(
            SbfVerificationStatus::AllRulesPass,
            SbfVerificationStatus::AllRulesPass
        );
        assert_ne!(
            SbfVerificationStatus::AllRulesPass,
            SbfVerificationStatus::ViolationsFound
        );
        assert_ne!(
            SbfVerificationStatus::PartiallyVerified,
            SbfVerificationStatus::NoRulesChecked
        );
    }

    #[test]
    fn test_report_summary() {
        let report = CertoraVerificationReport {
            program_path: PathBuf::from("test/program"),
            sbf_binary_path: None,
            binary_info: None,
            timestamp: "2024-01-01".to_string(),
            status: SbfVerificationStatus::NoRulesChecked,
            total_rules: 0,
            passed_count: 0,
            failed_count: 0,
            timeout_count: 0,
            sanity_failed_count: 0,
            rule_results: vec![],
            bytecode_vulnerabilities: vec![],
            certora_version: None,
            prover_backend: "Offline".to_string(),
            verification_time_ms: 100,
        };
        let summary = report.summary();
        assert!(summary.contains("test/program"));
        assert!(summary.contains("Offline"));
        assert!(summary.contains("100ms"));
    }

    #[test]
    fn test_report_empty_rule_filters() {
        let report = CertoraVerificationReport {
            program_path: PathBuf::from("test"),
            sbf_binary_path: None,
            binary_info: None,
            timestamp: String::new(),
            status: SbfVerificationStatus::NoRulesChecked,
            total_rules: 0,
            passed_count: 0,
            failed_count: 0,
            timeout_count: 0,
            sanity_failed_count: 0,
            rule_results: vec![],
            bytecode_vulnerabilities: vec![],
            certora_version: None,
            prover_backend: String::new(),
            verification_time_ms: 0,
        };
        assert!(report.failed_rules().is_empty());
        assert!(report.passed_rules().is_empty());
    }

    #[test]
    fn test_report_rule_filters() {
        let report = CertoraVerificationReport {
            program_path: PathBuf::from("test"),
            sbf_binary_path: None,
            binary_info: None,
            timestamp: String::new(),
            status: SbfVerificationStatus::ViolationsFound,
            total_rules: 3,
            passed_count: 1,
            failed_count: 1,
            timeout_count: 1,
            sanity_failed_count: 0,
            rule_results: vec![
                RuleVerificationResult {
                    rule_name: "rule_pass".to_string(),
                    status: RuleStatus::Passed,
                    description: "passed".to_string(),
                    counterexample: None,
                    source_location: None,
                    severity: 1,
                    category: "test".to_string(),
                },
                RuleVerificationResult {
                    rule_name: "rule_fail".to_string(),
                    status: RuleStatus::Failed,
                    description: "failed".to_string(),
                    counterexample: Some("counter".to_string()),
                    source_location: None,
                    severity: 5,
                    category: "test".to_string(),
                },
                RuleVerificationResult {
                    rule_name: "rule_timeout".to_string(),
                    status: RuleStatus::Timeout,
                    description: "timed out".to_string(),
                    counterexample: None,
                    source_location: None,
                    severity: 3,
                    category: "test".to_string(),
                },
            ],
            bytecode_vulnerabilities: vec![],
            certora_version: None,
            prover_backend: String::new(),
            verification_time_ms: 0,
        };
        assert_eq!(report.passed_rules().len(), 1);
        assert_eq!(report.failed_rules().len(), 1);
        assert_eq!(report.passed_rules()[0].rule_name, "rule_pass");
        assert_eq!(report.failed_rules()[0].rule_name, "rule_fail");
    }

    #[test]
    fn test_report_serialization() {
        let report = CertoraVerificationReport {
            program_path: PathBuf::from("test"),
            sbf_binary_path: None,
            binary_info: None,
            timestamp: "now".to_string(),
            status: SbfVerificationStatus::AllRulesPass,
            total_rules: 0,
            passed_count: 0,
            failed_count: 0,
            timeout_count: 0,
            sanity_failed_count: 0,
            rule_results: vec![],
            bytecode_vulnerabilities: vec![],
            certora_version: None,
            prover_backend: "test".to_string(),
            verification_time_ms: 0,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("AllRulesPass"));
    }

    #[test]
    fn test_error_display() {
        let err = CertoraError::IoError("file not found".to_string());
        assert!(err.to_string().contains("file not found"));
        let err = CertoraError::BuildError("build failed".to_string());
        assert!(err.to_string().contains("build failed"));
        let err = CertoraError::BinaryError("bad binary".to_string());
        assert!(err.to_string().contains("bad binary"));
    }
}
