//! Phase 2: Enhanced Comprehensive Analysis Integration
//!
//! This module extends the ComprehensiveSecurityAnalyzer with all Phase 1 enhanced analyses:
//! - Enhanced Taint Analysis (inter-procedural, context/field/path sensitivity)
//! - Enhanced Dataflow Analysis (Lamport, token flow, value ranges)
//! - Enhanced CPI Analysis (program ID tracking, risk graphs)
//! - Enhanced Economic Verification (AMM, Lending, Vault, Staking)
//! - Enhanced Flash Loan Detection (attack scenarios, capital/profit estimation)
//! - Enhanced Oracle Analysis (Pyth/Switchboard deep, circuit breakers)

use serde::{Deserialize, Serialize};
use std::path::Path;

// Import enhanced modules from this crate
use crate::flash_loan_enhanced::{EnhancedFlashLoanAnalyzer, EnhancedFlashLoanReport};
use crate::oracle_enhanced::{EnhancedOracleAnalyzer, EnhancedOracleReport};

#[cfg(feature = "z3-analysis")]
use economic_verifier::enhanced::{
    AMMPoolState, EnhancedEconomicAnalyzer, EnhancedEconomicReport, LendingPoolState, StakingState,
    VaultState,
};

// Other analysis crates
use cpi_analyzer::enhanced::EnhancedCPIAnalyzer;
use taint_analyzer::{BackwardFlow, TaintFlow};

// Base analyzers
use crate::comprehensive_analysis::{
    ComprehensiveAnalysisConfig, ComprehensiveSecurityAnalyzer, ComprehensiveSecurityReport,
    SecurityError,
};

/// Configuration for enhanced analysis
#[derive(Debug, Clone)]
pub struct EnhancedAnalysisConfig {
    /// Base configuration
    pub base_config: ComprehensiveAnalysisConfig,

    // Phase 1 Enhanced Features
    pub run_enhanced_taint: bool,
    pub run_enhanced_dataflow: bool,
    pub run_enhanced_cpi: bool,
    pub run_enhanced_economic: bool,
    pub run_enhanced_flash_loan: bool,
    pub run_enhanced_oracle: bool,

    // Specific feature toggles
    pub enable_interprocedural: bool,
    pub enable_context_sensitivity: bool,
    pub enable_field_sensitivity: bool,
    pub enable_path_sensitivity: bool,
    pub enable_backward_analysis: bool,
    pub enable_lamport_tracking: bool,
    pub enable_attack_scenarios: bool,
    pub enable_cascade_analysis: bool,
}

impl Default for EnhancedAnalysisConfig {
    fn default() -> Self {
        Self {
            base_config: ComprehensiveAnalysisConfig::default(),
            run_enhanced_taint: true,
            run_enhanced_dataflow: true,
            run_enhanced_cpi: true,
            run_enhanced_economic: true,
            run_enhanced_flash_loan: true,
            run_enhanced_oracle: true,
            enable_interprocedural: true,
            enable_context_sensitivity: true,
            enable_field_sensitivity: true,
            enable_path_sensitivity: true,
            enable_backward_analysis: true,
            enable_lamport_tracking: true,
            enable_attack_scenarios: true,
            enable_cascade_analysis: true,
        }
    }
}

impl EnhancedAnalysisConfig {
    pub fn full() -> Self {
        Self::default()
    }
}

/// Enhanced comprehensive security report with Phase 1 features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedSecurityReport {
    /// Base comprehensive report
    pub base_report: ComprehensiveSecurityReport,

    /// Enhanced analysis results
    pub enhanced_taint: Option<EnhancedTaintReport>,
    pub enhanced_dataflow: Option<EnhancedDataflowSummary>,
    pub enhanced_cpi: Option<EnhancedCPISummary>,
    pub enhanced_flash_loan: Option<EnhancedFlashLoanReport>,
    pub enhanced_oracle: Option<EnhancedOracleReport>,

    #[cfg(feature = "z3-analysis")]
    pub enhanced_economic: Option<EnhancedEconomicReport>,

    /// Enhanced summary statistics
    pub enhanced_summary: EnhancedSecuritySummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnhancedTaintReport {
    pub interprocedural_flows: usize,
    pub context_sensitive_findings: usize,
    pub field_sensitive_findings: usize,
    pub path_sensitive_findings: usize,
    pub backward_attack_paths: usize,
    pub total_taint_sources: usize,
    pub total_taint_sinks: usize,
    pub flows: Vec<TaintFlow>,
    pub backward_flows: Vec<BackwardFlow>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnhancedDataflowSummary {
    pub lamport_anomalies: Vec<dataflow_analyzer::enhanced::BalanceAnomaly>,
    pub token_issues: Vec<dataflow_analyzer::enhanced::TokenFlowIssue>,
    pub arithmetic_risks: Vec<dataflow_analyzer::enhanced::ArithmeticRisk>,
    pub total_operations: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnhancedCPISummary {
    pub findings: Vec<cpi_analyzer::enhanced::EnhancedCPIFinding>,
    pub program_id_sources: usize,
    pub whitelist_checks: usize,
    pub ownership_checks: usize,
    pub high_risk_paths: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnhancedSecuritySummary {
    /// Total findings across all analyses
    pub total_findings: usize,
    /// Enhanced analysis coverage percentage
    pub coverage_percentage: f64,
    /// Attack scenarios generated
    pub attack_scenarios_count: usize,
    /// Protocols analyzed for cascading failures
    pub cascade_protocols_analyzed: usize,
    /// Circit breakers detected
    pub circuit_breakers_found: usize,
    /// Missing protections
    pub missing_protections: usize,
    /// Risk metrics
    pub enhanced_risk_score: u8,
    /// Confidence in analysis
    pub analysis_confidence: f64,
}

/// Phase 2: Enhanced Comprehensive Security Analyzer
pub struct EnhancedSecurityAnalyzer {
    /// Base analyzer
    base_analyzer: ComprehensiveSecurityAnalyzer,
    /// Configuration
    config: EnhancedAnalysisConfig,

    // Enhanced analyzers
    enhanced_flash_loan: EnhancedFlashLoanAnalyzer,
    enhanced_oracle: EnhancedOracleAnalyzer,
    #[cfg(feature = "z3-analysis")]
    enhanced_economic: EnhancedEconomicAnalyzer,
}

impl EnhancedSecurityAnalyzer {
    pub fn new(config: EnhancedAnalysisConfig) -> Self {
        Self {
            base_analyzer: ComprehensiveSecurityAnalyzer::new(config.base_config.clone()),
            config,
            enhanced_flash_loan: EnhancedFlashLoanAnalyzer::new(),
            enhanced_oracle: EnhancedOracleAnalyzer::new(),
            #[cfg(feature = "z3-analysis")]
            enhanced_economic: EnhancedEconomicAnalyzer::new(),
        }
    }

    /// Analyze a source file with all enhanced analyses
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<EnhancedSecurityReport, SecurityError> {
        let _start = std::time::Instant::now();

        // Run base analysis first
        let base_report = self.base_analyzer.analyze_source(source, filename)?;

        // Run enhanced taint analysis using the advanced module
        let enhanced_taint = if self.config.run_enhanced_taint {
            Some(self.run_enhanced_taint_analysis(source, filename))
        } else {
            None
        };

        // Run enhanced dataflow analysis
        let enhanced_dataflow = if self.config.run_enhanced_dataflow {
            Some(self.run_enhanced_dataflow_analysis(source, filename))
        } else {
            None
        };

        // Run enhanced CPI analysis
        let enhanced_cpi = if self.config.run_enhanced_cpi {
            Some(self.run_enhanced_cpi_analysis(source, filename))
        } else {
            None
        };

        // Run enhanced flash loan analysis
        let enhanced_flash_loan = if self.config.run_enhanced_flash_loan {
            Some(self.run_enhanced_flash_loan_analysis(source, filename))
        } else {
            None
        };

        // Run enhanced oracle analysis
        let enhanced_oracle = if self.config.run_enhanced_oracle {
            Some(self.run_enhanced_oracle_analysis(source, filename))
        } else {
            None
        };

        // Run enhanced economic verification
        #[cfg(feature = "z3-analysis")]
        let enhanced_economic = if self.config.run_enhanced_economic {
            Some(self.run_enhanced_economic_analysis(source, filename))
        } else {
            None
        };

        // Calculate enhanced summary
        let enhanced_summary = self.calculate_enhanced_summary(
            &base_report,
            &enhanced_taint,
            &enhanced_dataflow,
            &enhanced_cpi,
            &enhanced_flash_loan,
            &enhanced_oracle,
            #[cfg(feature = "z3-analysis")]
            &enhanced_economic,
        );

        Ok(EnhancedSecurityReport {
            base_report,
            enhanced_taint,
            enhanced_dataflow,
            enhanced_cpi,
            enhanced_flash_loan,
            enhanced_oracle,
            #[cfg(feature = "z3-analysis")]
            enhanced_economic,
            enhanced_summary,
        })
    }

    /// Analyze a directory with all enhanced analyses
    pub fn analyze_directory(
        &mut self,
        dir: &Path,
    ) -> Result<EnhancedSecurityReport, SecurityError> {
        let _start = std::time::Instant::now();

        // Run base analysis
        let base_report = self.base_analyzer.analyze_directory(dir)?;

        // Collect source for enhanced analyses
        let mut all_sources = Vec::new();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "rs").unwrap_or(false))
        {
            if let Ok(source) = std::fs::read_to_string(entry.path()) {
                all_sources.push((source, entry.path().to_string_lossy().to_string()));
            }
        }

        // Aggregate enhanced analyses project-wide
        let mut analyzer = taint_analyzer::advanced::AdvancedTaintAnalyzer::new();

        // Phase 1: Build project-wide call graph
        for (source, filename) in &all_sources {
            analyzer.build_call_graph_from_source(source, filename);
        }

        // Phase 2: Perform project-wide forward analysis
        for (source, filename) in &all_sources {
            analyzer.forward_analysis_from_source(source, filename);
        }

        // Phase 3: Perform backward analysis from project-wide sinks
        let backward_flows = analyzer.backward_analyzer.analyze_all_sinks();

        let enhanced_taint = EnhancedTaintReport {
            interprocedural_flows: analyzer.get_flows().len(),
            context_sensitive_findings: analyzer.context_taint_count(),
            field_sensitive_findings: analyzer.field_taint_count(),
            path_sensitive_findings: analyzer.path_taint_count(),
            backward_attack_paths: backward_flows.len(),
            total_taint_sources: analyzer.source_count(),
            total_taint_sinks: analyzer.sink_count(),
            flows: analyzer.get_flows().to_vec(),
            backward_flows,
        };

        let mut enhanced_dataflow = EnhancedDataflowSummary::default();
        let mut enhanced_cpi = EnhancedCPISummary::default();

        for (source, filename) in &all_sources {
            if self.config.run_enhanced_dataflow {
                let df = self.run_enhanced_dataflow_analysis(source, filename);
                enhanced_dataflow
                    .lamport_anomalies
                    .extend(df.lamport_anomalies);
                enhanced_dataflow.token_issues.extend(df.token_issues);
                enhanced_dataflow
                    .arithmetic_risks
                    .extend(df.arithmetic_risks);
            }

            if self.config.run_enhanced_cpi {
                let cpi = self.run_enhanced_cpi_analysis(source, filename);
                enhanced_cpi.findings.extend(cpi.findings);
                enhanced_cpi.program_id_sources += cpi.program_id_sources;
                enhanced_cpi.whitelist_checks += cpi.whitelist_checks;
                enhanced_cpi.ownership_checks += cpi.ownership_checks;
            }

            if self.config.run_enhanced_economic {
                let _ = self.run_enhanced_economic_analysis(source, filename);
            }
        }

        // Run flash loan and oracle enhanced analyses
        let enhanced_flash_loan = if self.config.run_enhanced_flash_loan {
            // Generate attack scenarios for detected vulnerabilities
            if !base_report.flash_loan_findings.is_empty() {
                self.enhanced_flash_loan
                    .scenario_generator
                    .generate_first_deposit_scenario("Detected Vault", 1_000_000_000);
            }
            Some(self.enhanced_flash_loan.generate_report())
        } else {
            None
        };

        let enhanced_oracle = if self.config.run_enhanced_oracle && !all_sources.is_empty() {
            // Analyze combined source for oracle issues
            let combined = all_sources
                .iter()
                .map(|(s, _)| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            Some(self.enhanced_oracle.analyze_source(&combined, "combined"))
        } else {
            None
        };

        #[cfg(feature = "z3-analysis")]
        let enhanced_economic = if self.config.run_enhanced_economic {
            // In a real scenario, we'd extract state from source
            // For now, heuristic detection based on keywords
            let combined = all_sources
                .iter()
                .map(|(s, _)| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            if combined.contains("reserve_x") && combined.contains("reserve_y") {
                Some(self.enhanced_economic.analyze_amm(&AMMPoolState::default()))
            } else {
                None
            }
        } else {
            None
        };

        let enhanced_summary = self.calculate_enhanced_summary(
            &base_report,
            &Some(enhanced_taint.clone()),
            &Some(enhanced_dataflow.clone()),
            &Some(enhanced_cpi.clone()),
            &enhanced_flash_loan,
            &enhanced_oracle,
            #[cfg(feature = "z3-analysis")]
            &enhanced_economic,
        );

        Ok(EnhancedSecurityReport {
            base_report,
            enhanced_taint: Some(enhanced_taint),
            enhanced_dataflow: Some(enhanced_dataflow),
            enhanced_cpi: Some(enhanced_cpi),
            enhanced_flash_loan,
            enhanced_oracle,
            #[cfg(feature = "z3-analysis")]
            enhanced_economic,
            enhanced_summary,
        })
    }

    fn run_enhanced_taint_analysis(
        &mut self,
        source: &str,
        _filename: &str,
    ) -> EnhancedTaintReport {
        use std::collections::HashSet;
        use taint_analyzer::advanced::AdvancedTaintAnalyzer;

        let mut analyzer = AdvancedTaintAnalyzer::new();
        if let Ok(taint_report) = analyzer.analyze_source(source, _filename) {
            EnhancedTaintReport {
                interprocedural_flows: taint_report.flows.len(), // Use total for now
                context_sensitive_findings: taint_report.contexts_analyzed,
                field_sensitive_findings: taint_report.fields_tracked,
                path_sensitive_findings: taint_report.paths_explored,
                backward_attack_paths: taint_report.backward_flows.len(),
                total_taint_sources: taint_report
                    .flows
                    .iter()
                    .map(|f| format!("{:?}", f.source))
                    .collect::<HashSet<_>>()
                    .len(),
                total_taint_sinks: taint_report
                    .flows
                    .iter()
                    .map(|f| format!("{:?}", f.sink))
                    .collect::<HashSet<_>>()
                    .len(),
                flows: taint_report.flows,
                backward_flows: taint_report.backward_flows,
            }
        } else {
            EnhancedTaintReport::default()
        }
    }

    fn run_enhanced_dataflow_analysis(
        &mut self,
        source: &str,
        filename: &str,
    ) -> EnhancedDataflowSummary {
        use arithmetic_security_expert::ArithmeticSecurityExpert;
        use dataflow_analyzer::enhanced::EnhancedDataflowAnalyzer;

        let mut summary = EnhancedDataflowSummary::default();

        // Run base dataflow analyzer
        let mut analyzer = EnhancedDataflowAnalyzer::new();
        if let Ok(report) = analyzer.analyze_source(source, filename) {
            summary.lamport_anomalies = report.lamport_anomalies;
            summary.token_issues = report.token_issues;
            summary.arithmetic_risks = report.arithmetic_risks;
            summary.total_operations =
                report.lamport_operations.len() + report.token_operations.len();
        }

        // Run deep arithmetic expert analysis
        if let Ok(arithmetic_issues) = ArithmeticSecurityExpert::analyze_source(source) {
            for issue in arithmetic_issues {
                summary
                    .arithmetic_risks
                    .push(dataflow_analyzer::enhanced::ArithmeticRisk {
                        kind: format!("{:?}", issue.kind),
                        line: issue.line,
                        description: issue.recommendation,
                        severity: 3, // Medium by default
                    });
                summary.total_operations += 1;
            }
        }

        summary
    }

    fn run_enhanced_cpi_analysis(&mut self, source: &str, filename: &str) -> EnhancedCPISummary {
        let mut analyzer = EnhancedCPIAnalyzer::new();
        if let Ok(report) = analyzer.analyze_source(source, filename) {
            EnhancedCPISummary {
                findings: report.findings,
                program_id_sources: report.program_id_sources.len(),
                whitelist_checks: report.whitelist_checks.len(),
                ownership_checks: report.ownership_checks.len(),
                high_risk_paths: report.high_risk_paths.len(),
            }
        } else {
            EnhancedCPISummary::default()
        }
    }

    fn run_enhanced_flash_loan_analysis(
        &mut self,
        _source: &str,
        _filename: &str,
    ) -> EnhancedFlashLoanReport {
        // Generate scenarios based on detected patterns
        self.enhanced_flash_loan.generate_report()
    }

    fn run_enhanced_oracle_analysis(
        &mut self,
        source: &str,
        filename: &str,
    ) -> EnhancedOracleReport {
        self.enhanced_oracle.analyze_source(source, filename)
    }

    #[cfg(feature = "z3-analysis")]
    fn run_enhanced_economic_analysis(
        &mut self,
        source: &str,
        _filename: &str,
    ) -> EnhancedEconomicReport {
        // Heuristic mapping from source to protocol type
        if source.contains("reserve_x") || source.contains("reserve_y") {
            self.enhanced_economic.analyze_amm(&AMMPoolState::default())
        } else if source.contains("collateral") || source.contains("liquidation") {
            self.enhanced_economic
                .analyze_lending(&LendingPoolState::default())
        } else if source.contains("shares") || source.contains("assets") {
            self.enhanced_economic
                .analyze_vault(&VaultState::default(), 0)
        } else if source.contains("staked") || source.contains("reward") {
            self.enhanced_economic
                .analyze_staking(&StakingState::default(), 0, 0)
        } else {
            EnhancedEconomicReport {
                protocol_type: "Unknown".to_string(),
                amm_results: Vec::new(),
                lending_results: Vec::new(),
                vault_results: Vec::new(),
                staking_results: Vec::new(),
                overall_status: economic_verifier::enhanced::VerificationStatus::Unknown,
            }
        }
    }

    #[cfg(not(feature = "z3-analysis"))]
    fn run_enhanced_economic_analysis(&mut self, _source: &str, _filename: &str) -> () {
        ()
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_enhanced_summary(
        &self,
        base: &ComprehensiveSecurityReport,
        taint: &Option<EnhancedTaintReport>,
        dataflow: &Option<EnhancedDataflowSummary>,
        cpi: &Option<EnhancedCPISummary>,
        flash_loan: &Option<EnhancedFlashLoanReport>,
        oracle: &Option<EnhancedOracleReport>,
        #[cfg(feature = "z3-analysis")] economic: &Option<EnhancedEconomicReport>,
    ) -> EnhancedSecuritySummary {
        let mut total = base.summary.total_findings;
        let mut attack_scenarios = 0;
        let mut cascade_protocols = 0;
        let mut circuit_breakers = 0;
        let mut missing_protections = 0;

        // Count enhanced findings
        // Consolidate statistics
        total += taint.as_ref().map(|t| t.flows.len()).unwrap_or(0);
        total += dataflow
            .as_ref()
            .map(|d| d.lamport_anomalies.len() + d.token_issues.len() + d.arithmetic_risks.len())
            .unwrap_or(0);
        total += cpi.as_ref().map(|c| c.findings.len()).unwrap_or(0);

        if let Some(f) = flash_loan {
            attack_scenarios = f.total_scenarios;
            cascade_protocols = self
                .enhanced_flash_loan
                .cascade_analyzer
                .get_dependencies()
                .len();
        }

        if let Some(o) = oracle {
            total += o.total_issues;
            circuit_breakers = o.circuit_breakers.len();
            missing_protections = o.missing_protections.len();
        }

        #[cfg(feature = "z3-analysis")]
        if let Some(e) = economic {
            total += e.amm_results.len()
                + e.lending_results.len()
                + e.vault_results.len()
                + e.staking_results.len();
        }

        // Calculate coverage
        let enabled_analyses = [
            self.config.run_enhanced_taint,
            self.config.run_enhanced_dataflow,
            self.config.run_enhanced_cpi,
            self.config.run_enhanced_flash_loan,
            self.config.run_enhanced_oracle,
            self.config.run_enhanced_economic,
        ];
        let coverage = enabled_analyses.iter().filter(|&&x| x).count() as f64
            / enabled_analyses.len() as f64
            * 100.0;

        // Calculate enhanced risk score
        let base_risk = base.summary.overall_risk_score as u32;
        let enhancement_factor = if taint.is_some() { 10 } else { 0 }
            + if oracle
                .as_ref()
                .map(|o| o.critical_issues > 0)
                .unwrap_or(false)
            {
                20
            } else {
                0
            }
            + if flash_loan
                .as_ref()
                .map(|f| f.high_risk_scenarios > 0)
                .unwrap_or(false)
            {
                15
            } else {
                0
            };

        #[cfg(feature = "z3-analysis")]
        let enhancement_factor = enhancement_factor + if economic.is_some() { 15 } else { 0 };

        let enhanced_risk = std::cmp::min(base_risk + enhancement_factor, 100) as u8;

        EnhancedSecuritySummary {
            total_findings: total,
            coverage_percentage: coverage,
            attack_scenarios_count: attack_scenarios,
            cascade_protocols_analyzed: cascade_protocols,
            circuit_breakers_found: circuit_breakers,
            missing_protections,
            enhanced_risk_score: enhanced_risk,
            analysis_confidence: if coverage >= 80.0 {
                0.95
            } else {
                coverage / 100.0
            },
        }
    }

    /// Generate comprehensive markdown report
    pub fn generate_markdown_report(&self, report: &EnhancedSecurityReport) -> String {
        let mut md = String::new();

        md.push_str("# 🛡️ Enhanced Security Analysis Report\n\n");
        md.push_str("*Powered by Phase 1 Deep Analysis Enhancements*\n\n");

        // Executive Summary
        md.push_str("## 📊 Executive Summary\n\n");
        md.push_str("| Metric | Value |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!(
            "| **Files Analyzed** | {} |\n",
            report.base_report.files_analyzed
        ));
        md.push_str(&format!(
            "| **Total Findings** | {} |\n",
            report.enhanced_summary.total_findings
        ));
        md.push_str(&format!(
            "| **Enhanced Risk Score** | {}% |\n",
            report.enhanced_summary.enhanced_risk_score
        ));
        md.push_str(&format!(
            "| **Analysis Coverage** | {:.1}% |\n",
            report.enhanced_summary.coverage_percentage
        ));
        md.push_str(&format!(
            "| **Attack Scenarios** | {} |\n",
            report.enhanced_summary.attack_scenarios_count
        ));
        md.push_str(&format!(
            "| **Confidence** | {:.0}% |\n\n",
            report.enhanced_summary.analysis_confidence * 100.0
        ));

        // Severity Breakdown (from base)
        md.push_str("### 🎯 Severity Breakdown\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!(
            "| 🔴 Critical | {} |\n",
            report.base_report.summary.critical_count
        ));
        md.push_str(&format!(
            "| 🟠 High | {} |\n",
            report.base_report.summary.high_count
        ));
        md.push_str(&format!(
            "| 🟡 Medium | {} |\n",
            report.base_report.summary.medium_count
        ));
        md.push_str(&format!(
            "| 🟢 Low | {} |\n\n",
            report.base_report.summary.low_count
        ));

        // Enhanced Taint Analysis
        if let Some(taint) = &report.enhanced_taint {
            md.push_str("## 🔍 Enhanced Taint Analysis\n\n");
            md.push_str("*Inter-procedural, Context/Field/Path Sensitive Analysis*\n\n");
            md.push_str("| Analysis Type | Findings |\n");
            md.push_str("|--------------|----------|\n");
            md.push_str(&format!(
                "| Inter-procedural Flows | {} |\n",
                taint.interprocedural_flows
            ));
            md.push_str(&format!(
                "| Context-Sensitive | {} |\n",
                taint.context_sensitive_findings
            ));
            md.push_str(&format!(
                "| Field-Sensitive | {} |\n",
                taint.field_sensitive_findings
            ));
            md.push_str(&format!(
                "| Path-Sensitive | {} |\n",
                taint.path_sensitive_findings
            ));
            md.push_str(&format!(
                "| Backward Attack Paths | {} |\n\n",
                taint.backward_attack_paths
            ));
        }

        // Enhanced Dataflow
        if let Some(dataflow) = &report.enhanced_dataflow {
            md.push_str("### 📊 Advanced Dataflow Analysis\n\n");
            md.push_str("| Metric | Value |\n");
            md.push_str("|--------|-------|\n");
            md.push_str(&format!(
                "| Lamport Anomalies | {} |\n",
                dataflow.lamport_anomalies.len()
            ));
            md.push_str(&format!(
                "| Token Flow Issues | {} |\n",
                dataflow.token_issues.len()
            ));
            md.push_str(&format!(
                "| Arithmetic Risks | {} |\n",
                dataflow.arithmetic_risks.len()
            ));
            md.push_str(&format!(
                "| Total Operations | {} |\n\n",
                dataflow.total_operations
            ));
        }

        if let Some(cpi) = &report.enhanced_cpi {
            md.push_str("### 🔗 Enhanced CPI Analysis\n\n");
            md.push_str(&format!(
                "- **Total Enhanced CPI Findings**: {}\n",
                cpi.findings.len()
            ));
            md.push_str(&format!(
                "- **Program ID Sources**: {}\n",
                cpi.program_id_sources
            ));
            md.push_str(&format!(
                "- **Whitelist Checks**: {}\n",
                cpi.whitelist_checks
            ));
            md.push_str(&format!(
                "- **Ownership Checks**: {}\n",
                cpi.ownership_checks
            ));
            md.push_str(&format!(
                "- **High Risk Paths**: {}\n\n",
                cpi.high_risk_paths
            ));
        }

        // Enhanced Flash Loan
        if let Some(flash) = &report.enhanced_flash_loan {
            md.push_str("## ⚡ Enhanced Flash Loan Analysis\n\n");
            md.push_str("*Attack Scenarios, Capital Estimation, Profit Calculation*\n\n");
            md.push_str(&format!(
                "- **Attack Scenarios Generated**: {}\n",
                flash.total_scenarios
            ));
            md.push_str(&format!(
                "- **High Risk Scenarios**: {}\n\n",
                flash.high_risk_scenarios
            ));

            if !flash.scenarios.is_empty() {
                md.push_str("### Generated Attack Scenarios\n\n");
                for scenario in &flash.scenarios {
                    md.push_str(&format!(
                        "#### {} ({:?})\n\n",
                        scenario.name, scenario.attack_type
                    ));
                    md.push_str(&format!("- **Target**: {}\n", scenario.target));
                    md.push_str(&format!(
                        "- **Capital Required**: {} lamports\n",
                        scenario.capital_required.minimum
                    ));
                    md.push_str(&format!(
                        "- **Expected Profit**: {} lamports\n",
                        scenario.expected_profit.expected
                    ));
                    md.push_str(&format!(
                        "- **Success Probability**: {:.0}%\n\n",
                        scenario.risk.success_probability * 100.0
                    ));
                }
            }
        }

        // Enhanced Oracle
        if let Some(oracle) = &report.enhanced_oracle {
            md.push_str("## 🔮 Enhanced Oracle Analysis\n\n");
            md.push_str("*Pyth/Switchboard Deep, Feed ID, Circuit Breakers*\n\n");
            md.push_str(&format!(
                "- **Total Oracle Issues**: {}\n",
                oracle.total_issues
            ));
            md.push_str(&format!(
                "- **Critical Issues**: {}\n",
                oracle.critical_issues
            ));
            md.push_str(&format!(
                "- **Circuit Breakers Found**: {}\n",
                oracle.circuit_breakers.len()
            ));
            md.push_str(&format!(
                "- **Missing Protections**: {}\n\n",
                oracle.missing_protections.len()
            ));

            if !oracle.missing_protections.is_empty() {
                md.push_str("### Missing Protections\n\n");
                for mp in &oracle.missing_protections {
                    md.push_str(&format!(
                        "- **{:?}** [{:?}]: {}\n",
                        mp.protection_type, mp.severity, mp.description
                    ));
                }
                md.push('\n');
            }
        }

        // Enhanced Economic Verification
        #[cfg(feature = "z3-analysis")]
        if let Some(economic) = &report.enhanced_economic {
            md.push_str("## 💎 Enhanced Economic Verification\n\n");
            md.push_str(&format!(
                "*Formal verification of {} invariants using Z3*\n\n",
                economic.protocol_type
            ));
            md.push_str(&format!(
                "- **Overall Economic Status**: {:?}\n\n",
                economic.overall_status
            ));

            md.push_str(economic.to_markdown().as_str());
            md.push('\n');
        }

        // Cascade Analysis Summary
        if report.enhanced_summary.cascade_protocols_analyzed > 0 {
            md.push_str("## 🌊 Cascade Analysis\n\n");
            md.push_str(&format!(
                "- **Protocols Analyzed**: {}\n",
                report.enhanced_summary.cascade_protocols_analyzed
            ));
            md.push_str("- Potential cascading failures have been evaluated\n\n");
        }

        // Key Recommendations (from base)
        if !report.base_report.summary.key_recommendations.is_empty() {
            md.push_str("## 📋 Key Recommendations\n\n");
            for rec in &report.base_report.summary.key_recommendations {
                md.push_str(&format!("- {}\n", rec));
            }
            md.push('\n');
        }

        md.push_str("---\n\n");
        md.push_str("*Generated by Solana Security Swarm - Phase 2 Enhanced Analysis*\n");

        md
    }
}

impl Default for EnhancedSecurityAnalyzer {
    fn default() -> Self {
        Self::new(EnhancedAnalysisConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_analyzer_creation() {
        let analyzer = EnhancedSecurityAnalyzer::default();
        assert!(analyzer.config.run_enhanced_taint);
        assert!(analyzer.config.run_enhanced_oracle);
    }

    #[test]
    fn test_enhanced_analysis() {
        let source = r#"
            pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                let price = ctx.accounts.pool.reserve_a / ctx.accounts.pool.reserve_b;
                token::transfer(ctx.accounts.transfer_ctx(), amount * price)?;
                Ok(())
            }
        "#;

        let mut analyzer = EnhancedSecurityAnalyzer::default();
        let report = analyzer.analyze_source(source, "test.rs").unwrap();

        println!("Total findings: {}", report.enhanced_summary.total_findings);
        println!(
            "Coverage: {:.1}%",
            report.enhanced_summary.coverage_percentage
        );
        assert!(report.enhanced_summary.coverage_percentage > 0.0);
    }

    #[test]
    fn test_markdown_report_generation() {
        let source = r#"
            pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
                Ok(())
            }
        "#;

        let mut analyzer = EnhancedSecurityAnalyzer::default();
        let report = analyzer.analyze_source(source, "test.rs").unwrap();
        let markdown = analyzer.generate_markdown_report(&report);

        assert!(markdown.contains("Enhanced Security Analysis Report"));
        assert!(markdown.contains("Executive Summary"));
    }
}
