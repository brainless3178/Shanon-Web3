//! Firedancer monitoring report data structures

use serde::{Deserialize, Serialize};

/// Firedancer validator performance monitoring report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredancerMonitorReport {
    pub rpc_endpoint: String,
    pub timestamp: String,
    pub findings: Vec<FiredancerFinding>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub validator_health_score: u8, // 0-100, higher is better
    pub monitoring_duration_secs: u64,
    pub execution_time_ms: u64,
    pub engine_version: String,
}

/// Firedancer performance issue finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiredancerFinding {
    pub id: String,
    pub issue: FiredancerIssue,
    pub severity: FiredancerSeverity,
    pub slot: u64,
    pub timestamp: String,
    pub description: String,
    pub measured_value: f64, // e.g., lag in ms, skip count
    pub threshold_value: f64,
    pub risk_explanation: String,
    pub mitigation: String,
    pub validator_identity: Option<String>,
}

/// Firedancer-specific performance issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FiredancerIssue {
    VerificationLag,
    SkipVoteRisk,
    TransactionLatency,
    ValidatorStress,
    ConsensusDelay,
    NetworkCongestion,
}

impl FiredancerIssue {
    pub fn label(&self) -> &'static str {
        match self {
            Self::VerificationLag => "Verification Lag",
            Self::SkipVoteRisk => "Skip-Vote Risk",
            Self::TransactionLatency => "Transaction Latency",
            Self::ValidatorStress => "Validator Stress",
            Self::ConsensusDelay => "Consensus Delay",
            Self::NetworkCongestion => "Network Congestion",
        }
    }
}

/// Firedancer severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FiredancerSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl FiredancerSeverity {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}
