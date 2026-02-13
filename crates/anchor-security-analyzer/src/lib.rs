//! # Anchor Framework Security Analyzer
//!
//! Static analysis for Anchor-based Solana programs. Checks constraint correctness,
//! signer/owner validation, PDA seeds, CPI safety, Token-2022 hooks, reinit guards,
//! and close-account patterns.

pub mod constraint_validator;
pub mod cpi_guard_detector;
pub mod metrics;
pub mod pda_validator;
pub mod report;
pub mod signer_checker;
pub mod token_hook_analyzer;

use constraint_validator::ConstraintValidator;
use cpi_guard_detector::CPIGuardDetector;
use metrics::AnchorMetrics;
use pda_validator::PDAValidator;
use report::{AnchorAnalysisReport, AnchorFinding, AnchorSeverity};
use signer_checker::SignerChecker;
use token_hook_analyzer::TokenHookAnalyzer;

use std::fs;
use std::path::Path;
use tracing::{info, warn};
use walkdir::WalkDir;

/// Config flags for which checks to run
#[derive(Debug, Clone)]
pub struct AnchorConfig {
    /// account constraint validation
    pub check_constraints: bool,
    /// signer enforcement checks
    pub check_signers: bool,
    /// PDA seed/bump validation
    pub check_pda: bool,
    /// CPI guard detection
    pub check_cpi_guards: bool,
    /// Token-2022 hook validation
    pub check_token_hooks: bool,
    /// reinit guard checks
    pub check_reinit: bool,
    /// skip files larger than this
    pub max_file_size: usize,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            check_constraints: true,
            check_signers: true,
            check_pda: true,
            check_cpi_guards: true,
            check_token_hooks: true,
            check_reinit: true,
            max_file_size: 1_000_000,
        }
    }
}

/// Main analyzer — parses Anchor programs and runs security checks
pub struct AnchorSecurityAnalyzer {
    config: AnchorConfig,
    constraint_validator: ConstraintValidator,
    signer_checker: SignerChecker,
    pda_validator: PDAValidator,
    cpi_guard_detector: CPIGuardDetector,
    token_hook_analyzer: TokenHookAnalyzer,
}

impl AnchorSecurityAnalyzer {
    /// Default config
    pub fn new() -> Self {
        Self::with_config(AnchorConfig::default())
    }

    /// Custom config
    pub fn with_config(config: AnchorConfig) -> Self {
        info!("Initializing Anchor Framework security analyzer...");

        Self {
            constraint_validator: ConstraintValidator::new(),
            signer_checker: SignerChecker::new(),
            pda_validator: PDAValidator::new(),
            cpi_guard_detector: CPIGuardDetector::new(),
            token_hook_analyzer: TokenHookAnalyzer::new(),
            config,
        }
    }

    /// Run all enabled checks against a program directory
    pub fn analyze_program(&mut self, program_path: &Path) -> Result<AnchorAnalysisReport, String> {
        info!("Anchor analyzer scanning program at: {:?}", program_path);

        let start_time = std::time::Instant::now();
        let mut findings = Vec::new();
        let mut metrics = AnchorMetrics::new();

        // bail early for non-Anchor programs
        if !self.is_anchor_program(program_path)? {
            warn!("Not an Anchor program — skipping Anchor-specific checks");
            return Ok(AnchorAnalysisReport {
                program_path: program_path.to_string_lossy().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                is_anchor_program: false,
                anchor_version: None,
                findings: Vec::new(),
                metrics,
                files_scanned: 0,
                lines_scanned: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                anchor_security_score: 100,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                engine_version: "anchor-security-analyzer-1.0.0".to_string(),
            });
        }

        let anchor_version = self.detect_anchor_version(program_path)?;
        info!("Detected Anchor version: {}", anchor_version);

        // gather .rs files
        let source_files = self.collect_source_files(program_path)?;
        info!(
            "Anchor analyzer scanning {} source files",
            source_files.len()
        );

        if source_files.is_empty() {
            return Err("No Rust source files found".to_string());
        }

        let mut total_lines = 0;

        // run each analysis phase per file
        for (file_path, content) in &source_files {
            total_lines += content.lines().count();

            // parse AST
            let syntax_tree = match syn::parse_file(content) {
                Ok(tree) => tree,
                Err(e) => {
                    warn!("Failed to parse {}: {}", file_path, e);
                    continue;
                }
            };

            // 1: constraints
            if self.config.check_constraints {
                let constraint_findings = self.constraint_validator.validate_constraints(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(constraint_findings);
            }

            // 2: signers
            if self.config.check_signers {
                let signer_findings = self.signer_checker.check_signers(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(signer_findings);
            }

            // 3: PDA seeds
            if self.config.check_pda {
                let pda_findings =
                    self.pda_validator
                        .validate_pda(file_path, &syntax_tree, content, &mut metrics);
                findings.extend(pda_findings);
            }

            // 4: CPI guards
            if self.config.check_cpi_guards {
                let cpi_findings = self.cpi_guard_detector.detect_cpi_guards(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(cpi_findings);
            }

            // 5: Token-2022 hooks
            if self.config.check_token_hooks {
                let hook_findings = self.token_hook_analyzer.analyze_hooks(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(hook_findings);
            }
        }

        // dedup: multiple analyzers can flag the same field
        {
            let mut seen_fingerprints = std::collections::HashSet::new();
            findings.retain(|f| seen_fingerprints.insert(f.fingerprint.clone()));
        }

        // score: higher is better
        let anchor_security_score = self.calculate_security_score(&metrics, &findings);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // tally severity levels
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, AnchorSeverity::Critical))
            .count();
        let high_count = findings
            .iter()
            .filter(|f| matches!(f.severity, AnchorSeverity::High))
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| matches!(f.severity, AnchorSeverity::Medium))
            .count();
        let low_count = findings
            .iter()
            .filter(|f| matches!(f.severity, AnchorSeverity::Low))
            .count();

        info!(
            "Anchor analysis complete: {} violations found ({} critical, {} high) in {}ms. Security score: {}/100",
            findings.len(), critical_count, high_count, execution_time_ms, anchor_security_score
        );

        Ok(AnchorAnalysisReport {
            program_path: program_path.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            is_anchor_program: true,
            anchor_version: Some(anchor_version),
            findings,
            metrics,
            files_scanned: source_files.len(),
            lines_scanned: total_lines,
            critical_count,
            high_count,
            medium_count,
            low_count,
            anchor_security_score,
            execution_time_ms,
            engine_version: "anchor-security-analyzer-1.0.0".to_string(),
        })
    }

    /// Check Cargo.toml for anchor-lang dep
    fn is_anchor_program(&self, program_path: &Path) -> Result<bool, String> {
        let cargo_toml = program_path.join("Cargo.toml");
        if !cargo_toml.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(&cargo_toml)
            .map_err(|e| format!("Failed to read Cargo.toml: {}", e))?;

        Ok(content.contains("anchor-lang") || content.contains("anchor-spl"))
    }

    /// Extract version from Cargo.toml
    fn detect_anchor_version(&self, program_path: &Path) -> Result<String, String> {
        let cargo_toml = program_path.join("Cargo.toml");
        let content = fs::read_to_string(&cargo_toml)
            .map_err(|e| format!("Failed to read Cargo.toml: {}", e))?;

        // extract version string
        let re = regex::Regex::new(r#"anchor-lang.*version\s*=\s*"([^"]+)""#).unwrap();
        if let Some(cap) = re.captures(&content) {
            return Ok(cap[1].to_string());
        }

        Ok("unknown".to_string())
    }

    /// Walk program dir for .rs files
    fn collect_source_files(&self, program_path: &Path) -> Result<Vec<(String, String)>, String> {
        let mut files = Vec::new();

        let search_paths = vec![
            program_path.join("src"),
            program_path.join("programs"),
            program_path.to_path_buf(),
        ];

        for search_path in search_paths {
            if !search_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&search_path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                if let Some(ext) = path.extension() {
                    if ext != "rs" {
                        continue;
                    }
                }

                let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
                if metadata.len() > self.config.max_file_size as u64 {
                    warn!("Skipping large file: {:?} ({} bytes)", path, metadata.len());
                    continue;
                }

                let content = fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read {:?}: {}", path, e))?;

                files.push((path.to_string_lossy().to_string(), content));
            }
        }

        Ok(files)
    }

    /// Score based on missing patterns and finding severity
    fn calculate_security_score(&self, metrics: &AnchorMetrics, findings: &[AnchorFinding]) -> u8 {
        let mut score = 100.0;

        // penalty for missing patterns
        score -= (metrics.missing_signer_checks as f64) * 15.0;
        score -= (metrics.missing_owner_checks as f64) * 12.0;
        score -= (metrics.missing_pda_validation as f64) * 10.0;
        score -= (metrics.missing_cpi_guards as f64) * 18.0;
        score -= (metrics.weak_constraints as f64) * 8.0;
        score -= (metrics.reinit_vulnerabilities as f64) * 20.0;
        score -= (metrics.missing_close_guards as f64) * 10.0;

        // bonus for advanced features
        score += (metrics.token_hook_implementations as f64) * 5.0;
        score += (metrics.custom_constraint_count as f64) * 2.0;

        // per-finding penalties
        for finding in findings {
            match finding.severity {
                AnchorSeverity::Critical => score -= 5.0,
                AnchorSeverity::High => score -= 3.0,
                AnchorSeverity::Medium => score -= 1.0,
                AnchorSeverity::Low => score -= 0.5,
            }
        }

        score.clamp(0.0, 100.0) as u8
    }
}

impl Default for AnchorSecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_analyzer_creation() {
        let analyzer = AnchorSecurityAnalyzer::new();
        assert!(analyzer.config.check_constraints);
    }

    #[test]
    fn test_custom_config() {
        let config = AnchorConfig {
            check_constraints: false,
            ..Default::default()
        };
        let analyzer = AnchorSecurityAnalyzer::with_config(config);
        assert!(!analyzer.config.check_constraints);
    }
}
