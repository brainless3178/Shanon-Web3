//! FuzzDelSol Report
//!
//! Structured report output from a FuzzDelSol binary fuzzing campaign.

use crate::bytecode_parser::EbpfProgramModel;
use crate::oracles::{OracleViolation, ViolationSeverity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete report from a FuzzDelSol campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzDelSolReport {
    /// Path to the binary that was fuzzed
    pub binary_path: PathBuf,
    /// ISO 8601 timestamp of analysis start
    pub timestamp: String,
    /// Binary hash (for caching/deduplication)
    pub binary_hash: String,
    /// The eBPF program model extracted from bytecode
    pub program_model: EbpfProgramModel,
    /// All oracle violations detected
    pub violations: Vec<FuzzDelSolFinding>,
    /// Count of critical-severity findings
    pub critical_count: usize,
    /// Count of high-severity findings
    pub high_count: usize,
    /// Count of medium-severity findings
    pub medium_count: usize,
    /// Count of low-severity findings
    pub low_count: usize,
    /// Total fuzz iterations executed
    pub total_iterations: u64,
    /// Code coverage percentage achieved
    pub coverage_pct: f64,
    /// Analysis duration in milliseconds
    pub execution_time_ms: u64,
    /// Fuzzing backend description
    pub fuzzing_backend: String,
}

/// A single finding from FuzzDelSol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzDelSolFinding {
    /// Unique identifier (e.g., "FUZZDELSOL-A1B2C3D4")
    pub id: String,
    /// Oracle that detected this violation
    pub oracle_name: String,
    /// Severity level
    pub severity: ViolationSeverity,
    /// Human-readable description
    pub description: String,
    /// Bytecode address where violation was detected
    pub address: u64,
    /// Function name where violation occurred
    pub function: String,
    /// Input that triggered the violation
    pub triggering_input: Option<String>,
    /// Recommended fix
    pub fix_recommendation: String,
    /// CWE identifier
    pub cwe: Option<String>,
    /// Deterministic fingerprint for deduplication
    pub fingerprint: String,
}

impl FuzzDelSolFinding {
    /// Create a finding from an oracle violation.
    pub fn from_violation(violation: OracleViolation) -> Self {
        let fingerprint = Self::compute_fingerprint(&violation);
        let id = format!("FUZZDELSOL-{}", &fingerprint[..8].to_uppercase());

        Self {
            id,
            oracle_name: violation.oracle_name,
            severity: violation.severity,
            description: violation.description,
            address: violation.address,
            function: violation.function,
            triggering_input: violation.triggering_input,
            fix_recommendation: violation.fix_recommendation,
            cwe: violation.cwe,
            fingerprint,
        }
    }

    fn compute_fingerprint(violation: &OracleViolation) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&violation.oracle_name);
        hasher.update(&violation.function);
        hasher.update(violation.address.to_le_bytes());
        hex::encode(hasher.finalize())[..16].to_string()
    }
}
