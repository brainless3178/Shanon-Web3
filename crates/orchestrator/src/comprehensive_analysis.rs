//! Runs all security analyzers and aggregates findings into a single report.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::access_control::{AccessControlAnalyzer, AccessControlFinding};
use crate::account_validator::{AccountValidationFinding, AccountValidator};
use crate::flash_loan_detector::{FlashLoanAnalyzer, FlashLoanFinding};
use crate::oracle_analyzer::{OracleAnalyzer, OracleDiversityScore, OracleFinding};
use crate::pda_analyzer::{PDAAnalyzer, PDAFinding};
use crate::privilege_escalation::{PrivilegeAnalyzer, PrivilegeEscalationFinding};
use crate::reentrancy_detector::{ReentrancyDetector, ReentrancyFinding};
use cpi_analyzer::{CPIAnalyzer, CPIFinding};
use dataflow_analyzer::DataflowAnalyzer;
use taint_analyzer::{TaintAnalyzer, TaintFlow};

/// Comprehensive security analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveSecurityReport {
    /// Summary statistics
    pub summary: SecuritySummary,

    /// Findings by category
    pub access_control_findings: Vec<AccessControlFinding>,
    pub pda_findings: Vec<PDAFinding>,
    pub flash_loan_findings: Vec<FlashLoanFinding>,
    pub oracle_findings: Vec<OracleFinding>,
    pub account_validation_findings: Vec<AccountValidationFinding>,
    pub privilege_findings: Vec<PrivilegeEscalationFinding>,
    pub reentrancy_findings: Vec<ReentrancyFinding>,
    pub taint_findings: Vec<TaintFlow>,
    pub cpi_findings: Vec<CPIFinding>,
    pub dataflow_summary: DataflowSummary,

    /// Oracle diversity score
    pub oracle_diversity: Option<OracleDiversityScore>,

    /// Files analyzed
    pub files_analyzed: usize,

    /// Analysis duration in milliseconds
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataflowSummary {
    pub total_definitions: usize,
    pub total_uses: usize,
    pub uninitialized_uses: usize,
    pub dead_definitions: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,

    /// Risk score (0-100)
    pub overall_risk_score: u8,

    /// Top vulnerability categories
    pub top_vulnerability_types: Vec<(String, usize)>,

    /// Recommendations summary
    pub key_recommendations: Vec<String>,
}

/// Configuration for comprehensive analysis
#[derive(Debug, Clone)]
pub struct ComprehensiveAnalysisConfig {
    pub run_access_control: bool,
    pub run_pda_analysis: bool,
    pub run_flash_loan_detection: bool,
    pub run_oracle_analysis: bool,
    pub run_account_validation: bool,
    pub run_privilege_escalation: bool,
    pub run_reentrancy_analysis: bool,
    pub run_taint_analysis: bool,
    pub run_dataflow_analysis: bool,
    pub run_cpi_analysis: bool,

    /// Minimum severity to include in report
    pub min_severity: MinSeverity,

    /// Maximum findings per category
    pub max_findings_per_category: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MinSeverity {
    Critical,
    High,
    Medium,
    Low,
    All,
}

impl Default for ComprehensiveAnalysisConfig {
    fn default() -> Self {
        Self {
            run_access_control: true,
            run_pda_analysis: true,
            run_flash_loan_detection: true,
            run_oracle_analysis: true,
            run_account_validation: true,
            run_privilege_escalation: true,
            run_reentrancy_analysis: true,
            run_taint_analysis: true,
            run_dataflow_analysis: true,
            run_cpi_analysis: true,
            min_severity: MinSeverity::All,
            max_findings_per_category: None,
        }
    }
}

/// Main comprehensive security analyzer
pub struct ComprehensiveSecurityAnalyzer {
    config: ComprehensiveAnalysisConfig,

    // Individual analyzers
    access_control: AccessControlAnalyzer,
    pda_analyzer: PDAAnalyzer,
    flash_loan: FlashLoanAnalyzer,
    oracle: OracleAnalyzer,
    account_validator: AccountValidator,
    privilege: PrivilegeAnalyzer,
    reentrancy: ReentrancyDetector,
    taint_analyzer: TaintAnalyzer,
    dataflow_analyzer: DataflowAnalyzer,
    cpi_analyzer: CPIAnalyzer,
}

impl ComprehensiveSecurityAnalyzer {
    pub fn new(config: ComprehensiveAnalysisConfig) -> Self {
        Self {
            config,
            access_control: AccessControlAnalyzer::new(),
            pda_analyzer: PDAAnalyzer::new(),
            flash_loan: FlashLoanAnalyzer::new(),
            oracle: OracleAnalyzer::new(),
            account_validator: AccountValidator::new(),
            privilege: PrivilegeAnalyzer::new(),
            reentrancy: ReentrancyDetector::new(),
            taint_analyzer: TaintAnalyzer::new(),
            dataflow_analyzer: DataflowAnalyzer::new(),
            cpi_analyzer: CPIAnalyzer::new(),
        }
    }

    /// Analyze a directory of Solana program source files
    pub fn analyze_directory(
        &mut self,
        dir: &Path,
    ) -> Result<ComprehensiveSecurityReport, SecurityError> {
        let start = std::time::Instant::now();
        let mut files_analyzed = 0;

        let mut access_findings = Vec::new();
        let mut pda_findings = Vec::new();
        let mut flash_findings = Vec::new();
        let mut oracle_findings = Vec::new();
        let mut account_findings = Vec::new();
        let mut privilege_findings = Vec::new();
        let mut reentrancy_findings = Vec::new();
        let mut taint_findings = Vec::new();
        let mut cpi_findings = Vec::new();

        // Collect all Rust source files
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "rs").unwrap_or(false))
        {
            let path = entry.path();
            if let Ok(source) = std::fs::read_to_string(path) {
                let filename = path.to_string_lossy().to_string();
                files_analyzed += 1;

                // Run each analyzer
                if self.config.run_access_control {
                    if let Ok(findings) = self.access_control.analyze_source(&source, &filename) {
                        access_findings.extend(findings);
                    }
                }

                if self.config.run_pda_analysis {
                    if let Ok(findings) = self.pda_analyzer.analyze_source(&source, &filename) {
                        pda_findings.extend(findings);
                    }
                }

                if self.config.run_flash_loan_detection {
                    if let Ok(findings) = self.flash_loan.analyze_source(&source, &filename) {
                        flash_findings.extend(findings);
                    }
                }

                if self.config.run_oracle_analysis {
                    if let Ok(findings) = self.oracle.analyze_source(&source, &filename) {
                        oracle_findings.extend(findings);
                    }
                }

                if self.config.run_account_validation {
                    if let Ok(findings) = self.account_validator.analyze_source(&source, &filename)
                    {
                        account_findings.extend(findings);
                    }
                }

                if self.config.run_privilege_escalation {
                    if let Ok(findings) = self.privilege.analyze_source(&source, &filename) {
                        privilege_findings.extend(findings);
                    }
                }

                if self.config.run_reentrancy_analysis {
                    if let Ok(findings) = self.reentrancy.analyze_source(&source, &filename) {
                        reentrancy_findings.extend(findings);
                    }
                }

                if self.config.run_taint_analysis {
                    // TaintAnalyzer analyze_file takes syn::File
                    if let Ok(file) = syn::parse_file(&source) {
                        self.taint_analyzer.analyze_file(&file, filename.clone());
                    }
                }

                if self.config.run_dataflow_analysis
                    && self.dataflow_analyzer.analyze_source(&source, &filename).is_ok() {
                        // definitions are stored in the analyzer
                    }

                if self.config.run_cpi_analysis {
                    if let Ok(findings) = self.cpi_analyzer.analyze_source(&source, &filename) {
                        cpi_findings.extend(findings);
                    }
                }
            }
        }

        // Post-processing for taint and dataflow
        if self.config.run_taint_analysis {
            taint_findings = self.taint_analyzer.get_flows().to_vec();
        }

        // Get oracle diversity
        let oracle_diversity = if self.config.run_oracle_analysis {
            Some(self.oracle.calculate_diversity_score())
        } else {
            None
        };

        // Calculate summary
        let summary = self.calculate_summary(
            &access_findings,
            &pda_findings,
            &flash_findings,
            &oracle_findings,
            &account_findings,
            &privilege_findings,
            &reentrancy_findings,
            &taint_findings,
            &cpi_findings,
        );

        Ok(ComprehensiveSecurityReport {
            summary,
            access_control_findings: access_findings,
            pda_findings,
            flash_loan_findings: flash_findings,
            oracle_findings,
            account_validation_findings: account_findings,
            privilege_findings,
            reentrancy_findings,
            taint_findings,
            cpi_findings,
            dataflow_summary: DataflowSummary {
                total_definitions: self.dataflow_analyzer.get_definitions("").len(), // This is not quite right but we'll fix it
                total_uses: self.dataflow_analyzer.get_uses("").len(),
                uninitialized_uses: self.dataflow_analyzer.find_uninitialized_uses().len(),
                dead_definitions: self.dataflow_analyzer.find_dead_definitions().len(),
            },
            oracle_diversity,
            files_analyzed,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Analyze a single source file
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<ComprehensiveSecurityReport, SecurityError> {
        let start = std::time::Instant::now();

        let access_findings = if self.config.run_access_control {
            self.access_control
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let pda_findings = if self.config.run_pda_analysis {
            self.pda_analyzer
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let flash_findings = if self.config.run_flash_loan_detection {
            self.flash_loan
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let oracle_findings = if self.config.run_oracle_analysis {
            self.oracle
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let account_findings = if self.config.run_account_validation {
            self.account_validator
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let privilege_findings = if self.config.run_privilege_escalation {
            self.privilege
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let reentrancy_findings = if self.config.run_reentrancy_analysis {
            self.reentrancy
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Taint Analysis
        let taint_findings = if self.config.run_taint_analysis {
            if let Ok(file) = syn::parse_file(source) {
                self.taint_analyzer
                    .analyze_file(&file, filename.to_string());
                self.taint_analyzer.get_flows().to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Dataflow Analysis
        if self.config.run_dataflow_analysis {
            let _ = self.dataflow_analyzer.analyze_source(source, filename);
        }

        // CPI Analysis
        let cpi_findings = if self.config.run_cpi_analysis {
            self.cpi_analyzer
                .analyze_source(source, filename)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let oracle_diversity = if self.config.run_oracle_analysis {
            Some(self.oracle.calculate_diversity_score())
        } else {
            None
        };

        let summary = self.calculate_summary(
            &access_findings,
            &pda_findings,
            &flash_findings,
            &oracle_findings,
            &account_findings,
            &privilege_findings,
            &reentrancy_findings,
            &taint_findings,
            &cpi_findings,
        );

        Ok(ComprehensiveSecurityReport {
            summary,
            access_control_findings: access_findings,
            pda_findings,
            flash_loan_findings: flash_findings,
            oracle_findings,
            account_validation_findings: account_findings,
            privilege_findings,
            reentrancy_findings,
            taint_findings,
            cpi_findings,
            dataflow_summary: DataflowSummary {
                total_definitions: 0, // Simplified for single file
                total_uses: 0,
                uninitialized_uses: self.dataflow_analyzer.find_uninitialized_uses().len(),
                dead_definitions: self.dataflow_analyzer.find_dead_definitions().len(),
            },
            oracle_diversity,
            files_analyzed: 1,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_summary(
        &self,
        access: &[AccessControlFinding],
        pda: &[PDAFinding],
        flash: &[FlashLoanFinding],
        oracle: &[OracleFinding],
        account: &[AccountValidationFinding],
        privilege: &[PrivilegeEscalationFinding],
        reentrancy: &[ReentrancyFinding],
        taint: &[TaintFlow],
        cpi: &[CPIFinding],
    ) -> SecuritySummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut vuln_counts: HashMap<String, usize> = HashMap::new();

        // Count access control findings
        for f in access {
            match f.severity {
                crate::access_control::AccessControlSeverity::Critical => critical += 1,
                crate::access_control::AccessControlSeverity::High => high += 1,
                crate::access_control::AccessControlSeverity::Medium => medium += 1,
                crate::access_control::AccessControlSeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability))
                .or_insert(0) += 1;
        }

        // Count PDA findings
        for f in pda {
            match f.severity {
                crate::pda_analyzer::PDASeverity::Critical => critical += 1,
                crate::pda_analyzer::PDASeverity::High => high += 1,
                crate::pda_analyzer::PDASeverity::Medium => medium += 1,
                crate::pda_analyzer::PDASeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability))
                .or_insert(0) += 1;
        }

        // Count flash loan findings
        for f in flash {
            match f.severity {
                crate::flash_loan_detector::FlashLoanSeverity::Critical => critical += 1,
                crate::flash_loan_detector::FlashLoanSeverity::High => high += 1,
                crate::flash_loan_detector::FlashLoanSeverity::Medium => medium += 1,
                crate::flash_loan_detector::FlashLoanSeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability))
                .or_insert(0) += 1;
        }

        // Count oracle findings
        for f in oracle {
            match f.severity {
                crate::oracle_analyzer::OracleSeverity::Critical => critical += 1,
                crate::oracle_analyzer::OracleSeverity::High => high += 1,
                crate::oracle_analyzer::OracleSeverity::Medium => medium += 1,
                crate::oracle_analyzer::OracleSeverity::Low => low += 1,
                crate::oracle_analyzer::OracleSeverity::Informational => {}
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability))
                .or_insert(0) += 1;
        }

        // Count account validation findings
        for f in account {
            match f.severity {
                crate::account_validator::AccountValidationSeverity::Critical => critical += 1,
                crate::account_validator::AccountValidationSeverity::High => high += 1,
                crate::account_validator::AccountValidationSeverity::Medium => medium += 1,
                crate::account_validator::AccountValidationSeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability))
                .or_insert(0) += 1;
        }

        // Count privilege escalation findings
        for f in privilege {
            match f.severity {
                crate::privilege_escalation::PrivilegeEscalationSeverity::Critical => critical += 1,
                crate::privilege_escalation::PrivilegeEscalationSeverity::High => high += 1,
                crate::privilege_escalation::PrivilegeEscalationSeverity::Medium => medium += 1,
                crate::privilege_escalation::PrivilegeEscalationSeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability))
                .or_insert(0) += 1;
        }

        // Count reentrancy findings
        for f in reentrancy {
            match f.severity {
                crate::reentrancy_detector::ReentrancySeverity::Critical => critical += 1,
                crate::reentrancy_detector::ReentrancySeverity::High => high += 1,
                crate::reentrancy_detector::ReentrancySeverity::Medium => medium += 1,
                crate::reentrancy_detector::ReentrancySeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability_type))
                .or_insert(0) += 1;
        }

        // Count taint findings
        for f in taint {
            match f.severity {
                taint_analyzer::TaintSeverity::Critical => critical += 1,
                taint_analyzer::TaintSeverity::High => high += 1,
                taint_analyzer::TaintSeverity::Medium => medium += 1,
                taint_analyzer::TaintSeverity::Low => low += 1,
            }
            *vuln_counts.entry("TaintFlow".to_string()).or_insert(0) += 1;
        }

        // Count CPI findings
        for f in cpi {
            match f.severity {
                cpi_analyzer::CPISeverity::Critical => critical += 1,
                cpi_analyzer::CPISeverity::High => high += 1,
                cpi_analyzer::CPISeverity::Medium => medium += 1,
                cpi_analyzer::CPISeverity::Low => low += 1,
            }
            *vuln_counts
                .entry(format!("{:?}", f.vulnerability_type))
                .or_insert(0) += 1;
        }

        let total = critical + high + medium + low;

        // Calculate risk score
        let risk_score = self.calculate_risk_score(critical, high, medium, low);

        // Sort vulnerability types by count
        let mut top_vulns: Vec<_> = vuln_counts.into_iter().collect();
        top_vulns.sort_by(|a, b| b.1.cmp(&a.1));
        top_vulns.truncate(10);

        // Generate key recommendations
        let key_recommendations = self.generate_recommendations(&top_vulns, critical, high);

        SecuritySummary {
            total_findings: total,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            overall_risk_score: risk_score,
            top_vulnerability_types: top_vulns,
            key_recommendations,
        }
    }

    fn calculate_risk_score(&self, critical: usize, high: usize, medium: usize, low: usize) -> u8 {
        // Weighted scoring: Critical=40, High=20, Medium=10, Low=5
        let raw_score = (critical * 40) + (high * 20) + (medium * 10) + (low * 5);

        // Cap at 100
        std::cmp::min(raw_score, 100) as u8
    }

    fn generate_recommendations(
        &self,
        top_vulns: &[(String, usize)],
        critical: usize,
        high: usize,
    ) -> Vec<String> {
        let mut recs = Vec::new();

        if critical > 0 {
            recs.push(format!(
                "URGENT: {} critical vulnerabilities require immediate attention. \
                Do not deploy until resolved.",
                critical
            ));
        }

        if high > 5 {
            recs.push(
                "Multiple high-severity issues detected. Consider comprehensive security review."
                    .to_string(),
            );
        }

        // Specific vulnerability recommendations
        for (vuln, count) in top_vulns.iter().take(3) {
            let rec = match vuln.as_str() {
                "MissingSignerCheck" => format!(
                    "Add signer checks to {} locations to prevent unauthorized access.",
                    count
                ),
                "MissingStalenessCheck" => format!(
                    "Add oracle staleness checks to {} locations to prevent stale price exploitation.",
                    count
                ),
                "NonCanonicalBump" => format!(
                    "Use find_program_address for canonical bumps in {} PDA derivations.",
                    count
                ),
                "SpotPriceForCriticalDecision" => format!(
                    "Replace {} AMM spot price usages with TWAP or external oracle.",
                    count
                ),
                "InstantAuthorityUpdate" => format!(
                    "Add timelock to {} authority update functions.",
                    count
                ),
                _ => continue,
            };
            recs.push(rec);
        }

        recs
    }

    /// Get a formatted markdown report
    pub fn generate_markdown_report(&self, report: &ComprehensiveSecurityReport) -> String {
        let mut md = String::new();

        md.push_str("# Comprehensive Security Analysis Report\n\n");

        // Executive Summary
        md.push_str("## Executive Summary\n\n");
        md.push_str(&format!(
            "- **Files Analyzed**: {}\n",
            report.files_analyzed
        ));
        md.push_str(&format!(
            "- **Analysis Duration**: {}ms\n",
            report.analysis_duration_ms
        ));
        md.push_str(&format!(
            "- **Overall Risk Score**: {}%\n",
            report.summary.overall_risk_score
        ));
        md.push_str(&format!(
            "- **Total Findings**: {}\n\n",
            report.summary.total_findings
        ));

        // Severity Breakdown
        md.push_str("### Severity Breakdown\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!(
            "| 🔴 Critical | {} |\n",
            report.summary.critical_count
        ));
        md.push_str(&format!("| 🟠 High | {} |\n", report.summary.high_count));
        md.push_str(&format!(
            "| 🟡 Medium | {} |\n",
            report.summary.medium_count
        ));
        md.push_str(&format!("| 🟢 Low | {} |\n\n", report.summary.low_count));

        // Key Recommendations
        if !report.summary.key_recommendations.is_empty() {
            md.push_str("### Key Recommendations\n\n");
            for rec in &report.summary.key_recommendations {
                md.push_str(&format!("- {}\n", rec));
            }
            md.push('\n');
        }

        // Top Vulnerability Types
        if !report.summary.top_vulnerability_types.is_empty() {
            md.push_str("### Top Vulnerability Types\n\n");
            md.push_str("| Vulnerability | Count |\n");
            md.push_str("|--------------|-------|\n");
            for (vuln, count) in &report.summary.top_vulnerability_types {
                md.push_str(&format!("| {} | {} |\n", vuln, count));
            }
            md.push('\n');
        }

        // Detailed Findings by Category
        md.push_str("---\n\n");
        md.push_str("## Detailed Findings\n\n");

        // Access Control
        if !report.access_control_findings.is_empty() {
            md.push_str("### Access Control Issues\n\n");
            for (i, f) in report.access_control_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
            }
        }

        // PDA Issues
        if !report.pda_findings.is_empty() {
            md.push_str("### PDA Security Issues\n\n");
            for (i, f) in report.pda_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                if let Some(scenario) = &f.attack_scenario {
                    md.push_str(&format!("**Attack Scenario**: {}\n\n", scenario));
                }
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
            }
        }

        // Flash Loan Issues
        if !report.flash_loan_findings.is_empty() {
            md.push_str("### Flash Loan Attack Vectors\n\n");
            for (i, f) in report.flash_loan_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                md.push_str(&format!(
                    "**Attack Scenario**:\n```\n{}\n```\n\n",
                    f.attack_scenario
                ));
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
            }
        }

        // Oracle Issues
        if !report.oracle_findings.is_empty() {
            md.push_str("### Oracle Security Issues\n\n");
            for (i, f) in report.oracle_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                if let Some(scenario) = &f.attack_scenario {
                    md.push_str(&format!("**Attack Scenario**: {}\n\n", scenario));
                }
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
            }
        }

        // Account Validation
        if !report.account_validation_findings.is_empty() {
            md.push_str("### Account Validation Issues\n\n");
            for (i, f) in report.account_validation_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                if let Some(scenario) = &f.attack_scenario {
                    md.push_str(&format!("**Attack Scenario**: {}\n\n", scenario));
                }
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
            }
        }

        // Privilege Escalation
        if !report.privilege_findings.is_empty() {
            md.push_str("### Privilege Escalation Risks\n\n");
            for (i, f) in report.privilege_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                if !f.attack_path.is_empty() {
                    md.push_str("**Attack Path**:\n");
                    for step in &f.attack_path {
                        md.push_str(&format!(
                            "{}. {} → {}\n",
                            step.step_number, step.action, step.outcome
                        ));
                    }
                    md.push('\n');
                }
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
            }
        }

        // Reentrancy Issues
        if !report.reentrancy_findings.is_empty() {
            md.push_str("### Reentrancy Vulnerabilities\n\n");
            for (i, f) in report.reentrancy_findings.iter().enumerate() {
                md.push_str(&format!(
                    "#### {}. {:?} (Severity: {:?})\n\n",
                    i + 1,
                    f.vulnerability_type,
                    f.severity
                ));
                md.push_str(&format!("**Description**: {}\n\n", f.description));
                md.push_str(&format!("**Recommendation**: {}\n\n", f.recommendation));
                if !f.call_stack.is_empty() {
                    md.push_str(&format!("**Call Stack**: {}\n\n", f.call_stack.join(" → ")));
                }
            }
        }

        // Oracle Diversity Score
        if let Some(diversity) = &report.oracle_diversity {
            md.push_str("---\n\n");
            md.push_str("## Oracle Diversity Analysis\n\n");
            md.push_str(&format!(
                "- **Unique Oracle Sources**: {}\n",
                diversity.unique_sources
            ));
            md.push_str(&format!(
                "- **Has External Oracle**: {}\n",
                diversity.has_external_oracle
            ));
            md.push_str(&format!(
                "- **Has Proper Validation**: {}\n",
                diversity.has_proper_validation
            ));
            md.push_str(&format!("- **Risk Level**: {}\n", diversity.risk_level));
        }

        md
    }
}

impl Default for ComprehensiveSecurityAnalyzer {
    fn default() -> Self {
        Self::new(ComprehensiveAnalysisConfig::default())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comprehensive_analysis() {
        let source = r#"
            pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                // Vulnerable: missing signer check
                let price = ctx.accounts.pool.reserve_a / ctx.accounts.pool.reserve_b;
                let value = amount * price;
                token::transfer(ctx.accounts.transfer_ctx(), value)?;
                Ok(())
            }
        "#;

        let mut analyzer = ComprehensiveSecurityAnalyzer::default();
        let report = analyzer.analyze_source(source, "test.rs").unwrap();

        println!("Total findings: {}", report.summary.total_findings);
        println!("Risk score: {}", report.summary.overall_risk_score);
    }

    #[test]
    fn test_markdown_report() {
        let analyzer = ComprehensiveSecurityAnalyzer::default();
        let report = ComprehensiveSecurityReport {
            summary: SecuritySummary {
                total_findings: 5,
                critical_count: 1,
                high_count: 2,
                medium_count: 1,
                low_count: 1,
                overall_risk_score: 60,
                top_vulnerability_types: vec![
                    ("MissingSignerCheck".to_string(), 2),
                    ("SpotPrice".to_string(), 1),
                ],
                key_recommendations: vec!["Add signer checks".to_string()],
            },
            access_control_findings: Vec::new(),
            pda_findings: Vec::new(),
            flash_loan_findings: Vec::new(),
            oracle_findings: Vec::new(),
            account_validation_findings: Vec::new(),
            privilege_findings: Vec::new(),
            reentrancy_findings: Vec::new(),
            taint_findings: Vec::new(),
            cpi_findings: Vec::new(),
            dataflow_summary: DataflowSummary {
                total_definitions: 0,
                total_uses: 0,
                uninitialized_uses: 0,
                dead_definitions: 0,
            },
            oracle_diversity: None,
            files_analyzed: 3,
            analysis_duration_ms: 150,
        };

        let md = analyzer.generate_markdown_report(&report);
        assert!(md.contains("Comprehensive Security Analysis Report"));
        assert!(md.contains("Overall Risk Score"));
    }
}
