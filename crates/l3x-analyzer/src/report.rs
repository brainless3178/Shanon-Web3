//! L3X analysis report data structures
//!
//! Defines the output format for AI-driven vulnerability detection.

use serde::{Deserialize, Serialize};

/// L3X analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3xAnalysisReport {
    pub program_path: String,
    pub timestamp: String,
    pub findings: Vec<L3xFinding>,
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub instructions_analyzed: usize,
    pub accounts_analyzed: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub execution_time_ms: u64,
    pub ml_models_used: Vec<String>,
    pub confidence_threshold: f32,
    pub engine_version: String,
}

/// L3X vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L3xFinding {
    pub id: String,
    pub category: L3xCategory,
    pub severity: L3xSeverity,
    pub confidence: f32, // 0.0-1.0 ML confidence score
    pub file_path: String,
    pub line_number: usize,
    pub instruction: String,
    pub account_name: Option<String>,
    pub description: String,
    pub ml_reasoning: String, // Why the ML model flagged this
    pub fix_recommendation: String,
    pub cwe: String,
    pub fingerprint: String,
    pub source_snippet: Option<String>,
    pub fix_diff: Option<String>,
    pub detection_method: DetectionMethod,
    pub related_patterns: Vec<String>, // Similar historical exploits
}

/// L3X vulnerability category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum L3xCategory {
    // Traditional categories
    MissingOwnerCheck,
    IntegerOverflow,
    AccountConfusion,
    MissingSignerCheck,
    ArbitraryCPI,
    InsecurePDADerivation,
    CloseAccountDrain,
    ReInitialization,
    DuplicateMutableAccounts,
    UncheckedRemainingAccounts,

    // AI-detected advanced patterns
    AnomalousControlFlow,
    SuspiciousDataFlow,
    UnusualAccountPattern,
    ComplexReentrancy,
    TimingVulnerability,
    StateInconsistency,
    AuthorizationBypass,
    OracleManipulation,
    FlashLoanExploit,
    CrossProgramVulnerability,
    ZeroDayPattern,
}

impl L3xCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MissingOwnerCheck => "Missing Owner Check",
            Self::IntegerOverflow => "Integer Overflow",
            Self::AccountConfusion => "Account Confusion",
            Self::MissingSignerCheck => "Missing Signer Check",
            Self::ArbitraryCPI => "Arbitrary CPI",
            Self::InsecurePDADerivation => "Insecure PDA Derivation",
            Self::CloseAccountDrain => "Close Account Drain",
            Self::ReInitialization => "Re-Initialization Attack",
            Self::DuplicateMutableAccounts => "Duplicate Mutable Accounts",
            Self::UncheckedRemainingAccounts => "Unchecked Remaining Accounts",
            Self::AnomalousControlFlow => "Anomalous Control Flow (AI)",
            Self::SuspiciousDataFlow => "Suspicious Data Flow (AI)",
            Self::UnusualAccountPattern => "Unusual Account Pattern (AI)",
            Self::ComplexReentrancy => "Complex Reentrancy (AI)",
            Self::TimingVulnerability => "Timing Vulnerability (AI)",
            Self::StateInconsistency => "State Inconsistency (AI)",
            Self::AuthorizationBypass => "Authorization Bypass (AI)",
            Self::OracleManipulation => "Oracle Manipulation (AI)",
            Self::FlashLoanExploit => "Flash Loan Exploit (AI)",
            Self::CrossProgramVulnerability => "Cross-Program Vulnerability (AI)",
            Self::ZeroDayPattern => "Zero-Day Pattern (AI)",
        }
    }
}

/// L3X severity levels (CVSS-aligned)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum L3xSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl L3xSeverity {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Detection method used by L3X
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    CodeEmbedding {
        model: String,
        similarity_score: f32,
    },
    ControlFlowGNN {
        graph_size: usize,
        anomaly_score: f32,
    },
    AnomalyDetection {
        deviation_score: f32,
    },
    PatternLearning {
        matched_exploit: String,
        similarity: f32,
    },
    Ensemble {
        component_scores: Vec<f32>,
        final_score: f32,
    },
}

impl DetectionMethod {
    pub fn description(&self) -> String {
        match self {
            Self::CodeEmbedding {
                model,
                similarity_score,
            } => {
                format!(
                    "Code embedding analysis using {} (similarity: {:.2})",
                    model, similarity_score
                )
            }
            Self::ControlFlowGNN {
                graph_size,
                anomaly_score,
            } => {
                format!(
                    "GNN control flow analysis ({} nodes, anomaly: {:.2})",
                    graph_size, anomaly_score
                )
            }
            Self::AnomalyDetection { deviation_score } => {
                format!("Anomaly detection (deviation: {:.2})", deviation_score)
            }
            Self::PatternLearning {
                matched_exploit,
                similarity,
            } => {
                format!(
                    "Pattern matching: {} (similarity: {:.2})",
                    matched_exploit, similarity
                )
            }
            Self::Ensemble { final_score, .. } => {
                format!("Ensemble scoring (confidence: {:.2})", final_score)
            }
        }
    }
}
