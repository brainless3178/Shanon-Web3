//! # Sec3 (formerly Soteria) Advanced Static Analyzer
//!
//! Enterprise-grade static analysis engine for Solana Anchor programs,
//! implementing the industry-standard vulnerability taxonomy covering:
//!
//! - **Missing Owner Checks** (CWE-284) — accounts used without program ownership verification
//! - **Integer Overflow/Underflow** (CWE-190) — unchecked arithmetic in release builds
//! - **Account Type Confusion** (CWE-345) — raw `AccountInfo` without typed Anchor wrappers
//! - **Missing Signer Validation** (CWE-287) — authority accounts not enforced as signers
//! - **Duplicate Mutable Accounts** (CWE-362) — same account for two mutable params
//! - **Arbitrary CPI** (CWE-94) — cross-program invocations without program ID verification
//! - **Insecure PDA Derivation** (CWE-330) — insufficient seed entropy, missing bump validation
//! - **Close Account Drain** (CWE-672) — unsafe account closure without data zeroing
//! - **Re-Initialization** (CWE-665) — `init_if_needed` enabling state reset attacks
//! - **Unchecked Remaining Accounts** (CWE-20) — `ctx.remaining_accounts` without validation
//!
//! ## Architecture
//!
//! Each vulnerability category has a dedicated detector module that operates on
//! the `syn` AST of Rust source files. The main `Sec3Analyzer` orchestrates all
//! detectors, deduplicates findings, and assembles the final `Sec3AnalysisReport`.
//!
//! ## Pipeline
//!
//! ```text
//! Source Files → syn AST → Detectors (parallel) → Deduplication → Checklist → Report
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use sec3_analyzer::{Sec3Analyzer, Sec3Config};
//! use std::path::Path;
//!
//! let config = Sec3Config::default();
//! let mut analyzer = Sec3Analyzer::with_config(config);
//! let report = analyzer.analyze_program(Path::new("./my-program")).unwrap();
//!
//! println!("Findings: {}", report.findings.len());
//! println!("Critical: {}", report.critical_count);
//! ```

pub mod account_confusion;
pub mod close_account;
pub mod cpi_guard;
pub mod duplicate_accounts;
pub mod integer_analyzer;
pub mod ownership_checker;
pub mod pda_validator;
pub mod remaining_accounts;
pub mod report;
pub mod signer_checker;
pub mod utils;

pub use report::{Sec3AnalysisReport, Sec3Category, Sec3Finding, Sec3Severity};

use std::path::Path;
use tracing::{info, warn};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Sec3 analyzer configuration.
#[derive(Debug, Clone)]
pub struct Sec3Config {
    /// Enable owner check detection.
    pub check_ownership: bool,
    /// Enable integer overflow detection.
    pub check_integer_safety: bool,
    /// Enable account confusion detection.
    pub check_account_confusion: bool,
    /// Enable signer validation detection.
    pub check_signer_validation: bool,
    /// Enable duplicate mutable accounts detection.
    pub check_duplicate_accounts: bool,
    /// Enable CPI safety detection.
    pub check_cpi_safety: bool,
    /// Enable PDA validation detection.
    pub check_pda_security: bool,
    /// Enable close account drain detection.
    pub check_close_accounts: bool,
    /// Enable remaining accounts detection.
    pub check_remaining_accounts: bool,
    /// Maximum number of files to scan (0 = unlimited).
    pub max_files: usize,
    /// Maximum file size in bytes to parse (skip huge generated files).
    pub max_file_size: usize,
}

impl Default for Sec3Config {
    fn default() -> Self {
        Self {
            check_ownership: true,
            check_integer_safety: true,
            check_account_confusion: true,
            check_signer_validation: true,
            check_duplicate_accounts: true,
            check_cpi_safety: true,
            check_pda_security: true,
            check_close_accounts: true,
            check_remaining_accounts: true,
            max_files: 0,
            max_file_size: 500_000, // 500KB
        }
    }
}

// ─── Error Type ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Sec3Error {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("No Rust source files found in: {0}")]
    NoSourceFiles(String),

    #[error("Parse error in {0}: {1}")]
    ParseError(String, String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// ─── Main Analyzer ──────────────────────────────────────────────────────────

/// Sec3 (Soteria) static analysis engine.
///
/// Orchestrates all vulnerability detectors across a Solana program's source
/// tree and produces a unified `Sec3AnalysisReport`.
pub struct Sec3Analyzer {
    config: Sec3Config,
}

impl Sec3Analyzer {
    /// Create with default configuration (all checks enabled).
    pub fn new() -> Self {
        Self {
            config: Sec3Config::default(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: Sec3Config) -> Self {
        Self { config }
    }

    /// Run the full Sec3 analysis pipeline on a Solana program directory.
    ///
    /// This is the main entry point consumed by the audit pipeline.
    pub fn analyze_program(
        &mut self,
        program_path: &Path,
    ) -> Result<Sec3AnalysisReport, Sec3Error> {
        let start = std::time::Instant::now();

        // Resolve to src/ directory if it exists
        let source_path = if program_path.join("src").exists() {
            program_path.join("src")
        } else {
            program_path.to_path_buf()
        };

        info!(
            "Sec3 (Soteria) static analysis starting on: {:?}",
            program_path,
        );

        // Pre-flight: verify source files exist
        let sources = utils::collect_rust_sources(&source_path);
        if sources.is_empty() {
            // Try parent directory
            let alt_sources = utils::collect_rust_sources(program_path);
            if alt_sources.is_empty() {
                warn!("No Rust source files found, attempting expanded search...");
                return self.run_expanded_search(program_path);
            }
        }

        let files_scanned = sources.len();
        let lines_scanned: usize = sources.iter().map(|(_, c)| c.lines().count()).sum();

        info!(
            "Scanning {} files ({} lines of code)",
            files_scanned, lines_scanned
        );

        // ─── Run all enabled detectors ──────────────────────────────────────

        let mut all_findings: Vec<Sec3Finding> = Vec::new();

        // 1. Ownership checks
        if self.config.check_ownership {
            info!("Running ownership checker...");
            let findings = ownership_checker::scan(program_path);
            info!("  → {} ownership findings", findings.len());
            all_findings.extend(findings);
        }

        // 2. Integer safety
        if self.config.check_integer_safety {
            info!("Running integer safety analyzer...");
            let findings = integer_analyzer::scan(program_path);
            info!("  → {} integer safety findings", findings.len());
            all_findings.extend(findings);
        }

        // 3. Account confusion
        if self.config.check_account_confusion {
            info!("Running account confusion detector...");
            let findings = account_confusion::scan(program_path);
            info!("  → {} account confusion findings", findings.len());
            all_findings.extend(findings);
        }

        // 4. Signer validation
        if self.config.check_signer_validation {
            info!("Running signer validation checker...");
            let findings = signer_checker::scan(program_path);
            info!("  → {} signer validation findings", findings.len());
            all_findings.extend(findings);
        }

        // 5. Duplicate mutable accounts
        if self.config.check_duplicate_accounts {
            info!("Running duplicate mutable accounts detector...");
            let findings = duplicate_accounts::scan(program_path);
            info!("  → {} duplicate accounts findings", findings.len());
            all_findings.extend(findings);
        }

        // 6. CPI safety
        if self.config.check_cpi_safety {
            info!("Running CPI guard...");
            let findings = cpi_guard::scan(program_path);
            info!("  → {} CPI safety findings", findings.len());
            all_findings.extend(findings);
        }

        // 7. PDA security
        if self.config.check_pda_security {
            info!("Running PDA validator...");
            let findings = pda_validator::scan(program_path);
            info!("  → {} PDA security findings", findings.len());
            all_findings.extend(findings);
        }

        // 8. Close account drain
        if self.config.check_close_accounts {
            info!("Running close account analyzer...");
            let findings = close_account::scan(program_path);
            info!("  → {} close account findings", findings.len());
            all_findings.extend(findings);
        }

        // 9. Remaining accounts
        if self.config.check_remaining_accounts {
            info!("Running remaining accounts analyzer...");
            let findings = remaining_accounts::scan(program_path);
            info!("  → {} remaining accounts findings", findings.len());
            all_findings.extend(findings);
        }

        // ─── Deduplication ──────────────────────────────────────────────────

        deduplicate_findings(&mut all_findings);

        // ─── Count by severity ──────────────────────────────────────────────

        let critical_count = all_findings
            .iter()
            .filter(|f| f.severity == Sec3Severity::Critical)
            .count();
        let high_count = all_findings
            .iter()
            .filter(|f| f.severity == Sec3Severity::High)
            .count();
        let medium_count = all_findings
            .iter()
            .filter(|f| f.severity == Sec3Severity::Medium)
            .count();
        let low_count = all_findings
            .iter()
            .filter(|f| f.severity == Sec3Severity::Low)
            .count();
        let info_count = all_findings
            .iter()
            .filter(|f| f.severity == Sec3Severity::Info)
            .count();

        // ─── Instruction/account counting ───────────────────────────────────

        let instructions: std::collections::HashSet<_> =
            all_findings.iter().map(|f| f.instruction.clone()).collect();
        let accounts: std::collections::HashSet<_> = all_findings
            .iter()
            .filter_map(|f| f.account_name.clone())
            .collect();

        // ─── Security Checklist ─────────────────────────────────────────────

        let checklist_results = build_checklist(&all_findings);

        let elapsed = start.elapsed();
        info!(
            "Sec3 analysis complete in {:.2}s: {} findings ({} critical, {} high, {} medium)",
            elapsed.as_secs_f64(),
            all_findings.len(),
            critical_count,
            high_count,
            medium_count,
        );

        Ok(Sec3AnalysisReport {
            program_path: program_path.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: all_findings,
            files_scanned,
            lines_scanned,
            instructions_analysed: instructions.len(),
            accounts_analysed: accounts.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            checklist_results,
            engine_version: "sec3-soteria-2.1.0".to_string(),
        })
    }

    /// Expanded search — scan parent directories and `programs/` subdirectories.
    fn run_expanded_search(
        &mut self,
        program_path: &Path,
    ) -> Result<Sec3AnalysisReport, Sec3Error> {
        let programs_dir = program_path.join("programs");
        if programs_dir.exists() {
            info!("Found programs/ directory, scanning sub-programs...");

            let mut all_findings = Vec::new();
            let mut total_files = 0;
            let mut total_lines = 0;

            for entry in std::fs::read_dir(&programs_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let sub_path = entry.path();
                    let sources = utils::collect_rust_sources(&sub_path);
                    total_files += sources.len();
                    total_lines += sources
                        .iter()
                        .map(|(_, c)| c.lines().count())
                        .sum::<usize>();

                    if self.config.check_ownership {
                        all_findings.extend(ownership_checker::scan(&sub_path));
                    }
                    if self.config.check_integer_safety {
                        all_findings.extend(integer_analyzer::scan(&sub_path));
                    }
                    if self.config.check_account_confusion {
                        all_findings.extend(account_confusion::scan(&sub_path));
                    }
                    if self.config.check_signer_validation {
                        all_findings.extend(signer_checker::scan(&sub_path));
                    }
                    if self.config.check_duplicate_accounts {
                        all_findings.extend(duplicate_accounts::scan(&sub_path));
                    }
                    if self.config.check_cpi_safety {
                        all_findings.extend(cpi_guard::scan(&sub_path));
                    }
                    if self.config.check_pda_security {
                        all_findings.extend(pda_validator::scan(&sub_path));
                    }
                    if self.config.check_close_accounts {
                        all_findings.extend(close_account::scan(&sub_path));
                    }
                    if self.config.check_remaining_accounts {
                        all_findings.extend(remaining_accounts::scan(&sub_path));
                    }
                }
            }

            deduplicate_findings(&mut all_findings);

            let critical_count = all_findings
                .iter()
                .filter(|f| f.severity == Sec3Severity::Critical)
                .count();
            let high_count = all_findings
                .iter()
                .filter(|f| f.severity == Sec3Severity::High)
                .count();
            let medium_count = all_findings
                .iter()
                .filter(|f| f.severity == Sec3Severity::Medium)
                .count();
            let low_count = all_findings
                .iter()
                .filter(|f| f.severity == Sec3Severity::Low)
                .count();
            let info_count = all_findings
                .iter()
                .filter(|f| f.severity == Sec3Severity::Info)
                .count();

            let instructions: std::collections::HashSet<_> =
                all_findings.iter().map(|f| f.instruction.clone()).collect();
            let accounts: std::collections::HashSet<_> = all_findings
                .iter()
                .filter_map(|f| f.account_name.clone())
                .collect();

            let checklist_results = build_checklist(&all_findings);

            return Ok(Sec3AnalysisReport {
                program_path: program_path.to_string_lossy().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                findings: all_findings,
                files_scanned: total_files,
                lines_scanned: total_lines,
                instructions_analysed: instructions.len(),
                accounts_analysed: accounts.len(),
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count,
                checklist_results,
                engine_version: "sec3-soteria-2.1.0".to_string(),
            });
        }

        // Return empty report
        Ok(Sec3AnalysisReport {
            program_path: program_path.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: Vec::new(),
            files_scanned: 0,
            lines_scanned: 0,
            instructions_analysed: 0,
            accounts_analysed: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            checklist_results: build_checklist(&[]),
            engine_version: "sec3-soteria-2.1.0".to_string(),
        })
    }
}

impl Default for Sec3Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Sec3Config::default();
        assert!(config.check_ownership);
        assert!(config.check_integer_safety);
        assert!(config.check_account_confusion);
        assert!(config.check_signer_validation);
        assert!(config.check_duplicate_accounts);
        assert!(config.check_cpi_safety);
        assert!(config.check_pda_security);
        assert!(config.check_close_accounts);
        assert!(config.check_remaining_accounts);
        assert_eq!(config.max_files, 0);
        assert_eq!(config.max_file_size, 500_000);
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = Sec3Analyzer::new();
        assert!(analyzer.config.check_ownership);
    }

    #[test]
    fn test_analyzer_default() {
        let analyzer = Sec3Analyzer::default();
        assert!(analyzer.config.check_signer_validation);
    }

    #[test]
    fn test_analyzer_with_config() {
        let mut config = Sec3Config::default();
        config.check_ownership = false;
        config.check_cpi_safety = false;
        let analyzer = Sec3Analyzer::with_config(config);
        assert!(!analyzer.config.check_ownership);
        assert!(!analyzer.config.check_cpi_safety);
        assert!(analyzer.config.check_integer_safety);
    }

    #[test]
    fn test_build_checklist_empty_findings() {
        let checklist = build_checklist(&[]);
        assert_eq!(checklist.len(), 10);
        for (_, passed) in &checklist {
            assert!(passed, "All checks should pass with no findings");
        }
    }

    #[test]
    fn test_build_checklist_labels() {
        let checklist = build_checklist(&[]);
        let labels: Vec<&str> = checklist.iter().map(|(l, _)| l.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("owner validation")));
        assert!(labels.iter().any(|l| l.contains("checked operations")));
        assert!(labels.iter().any(|l| l.contains("signer")));
        assert!(labels.iter().any(|l| l.contains("PDA")));
        assert!(labels.iter().any(|l| l.contains("CPI")));
    }

    #[test]
    fn test_deduplicate_findings() {
        let finding = Sec3Finding {
            id: "SEC3-TEST0001".to_string(),
            category: Sec3Category::MissingOwnerCheck,
            severity: Sec3Severity::High,
            file_path: "lib.rs".to_string(),
            line_number: 42,
            instruction: "deposit".to_string(),
            account_name: Some("vault".to_string()),
            description: "test finding".to_string(),
            fix_recommendation: "fix it".to_string(),
            cwe: "CWE-284".to_string(),
            fingerprint: "abc123".to_string(),
            source_snippet: None,
            fix_diff: None,
        };
        let mut findings = vec![finding.clone(), finding.clone(), finding];
        assert_eq!(findings.len(), 3);
        deduplicate_findings(&mut findings);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_analyze_empty_path() {
        let mut analyzer = Sec3Analyzer::new();
        let result = analyzer.analyze_program(std::path::Path::new("/nonexistent/path"));
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.files_scanned, 0);
    }

    #[test]
    fn test_error_display() {
        let err = Sec3Error::NoSourceFiles("test".to_string());
        assert!(err.to_string().contains("test"));
        let err = Sec3Error::ConfigError("bad config".to_string());
        assert!(err.to_string().contains("bad config"));
    }
}

// ─── Deduplication ──────────────────────────────────────────────────────────

/// Remove duplicate findings based on fingerprint.
fn deduplicate_findings(findings: &mut Vec<Sec3Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.fingerprint.clone()));
}

// ─── Security Checklist ─────────────────────────────────────────────────────

/// Build the Sec3/Soteria security checklist based on analysis findings.
///
/// This checklist summarises whether key security properties hold across
/// the entire program.
fn build_checklist(findings: &[Sec3Finding]) -> Vec<(String, bool)> {
    let has = |cat: Sec3Category| findings.iter().any(|f| f.category == cat);

    vec![
        (
            "All accounts have owner validation".to_string(),
            !has(Sec3Category::MissingOwnerCheck),
        ),
        (
            "All arithmetic uses checked operations".to_string(),
            !has(Sec3Category::IntegerOverflow),
        ),
        (
            "No raw AccountInfo without CHECK doc".to_string(),
            !has(Sec3Category::AccountConfusion),
        ),
        (
            "All authority accounts enforce signer".to_string(),
            !has(Sec3Category::MissingSignerCheck),
        ),
        (
            "No duplicate mutable account risks".to_string(),
            !has(Sec3Category::DuplicateMutableAccounts),
        ),
        (
            "All CPIs validate program ID".to_string(),
            !has(Sec3Category::ArbitraryCPI),
        ),
        (
            "PDA derivations have sufficient entropy".to_string(),
            !has(Sec3Category::InsecurePDADerivation),
        ),
        (
            "Account closures properly guarded".to_string(),
            !has(Sec3Category::CloseAccountDrain),
        ),
        (
            "No re-initialization via init_if_needed".to_string(),
            !has(Sec3Category::ReInitialization),
        ),
        (
            "remaining_accounts properly validated".to_string(),
            !has(Sec3Category::UncheckedRemainingAccounts),
        ),
    ]
}
