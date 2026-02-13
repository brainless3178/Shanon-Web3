//! WACANA report structures.
//!
//! Defines the output format for WACANA's concolic analysis findings.

use crate::vulnerability_detectors::VulnerabilityCategory;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete WACANA analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WacanaReport {
    /// Path to the analyzed program.
    pub program_path: PathBuf,
    /// ISO8601 timestamp.
    pub timestamp: String,
    /// Number of WASM modules analyzed.
    pub wasm_modules_analyzed: u32,
    /// Number of SBF binaries analyzed.
    pub sbf_binaries_analyzed: u32,
    /// Number of source files analyzed (source-assisted mode).
    pub source_files_analyzed: u32,
    /// Total concolic paths explored.
    pub total_paths_explored: usize,
    /// Total unique branches covered.
    pub total_branches_covered: usize,
    /// All findings.
    pub findings: Vec<WacanaFinding>,
    /// Count of critical findings.
    pub critical_count: usize,
    /// Count of high findings.
    pub high_count: usize,
    /// Count of medium findings.
    pub medium_count: usize,
    /// Count of low findings.
    pub low_count: usize,
    /// Total analysis duration in milliseconds.
    pub analysis_duration_ms: u64,
    /// Engine version string.
    pub concolic_engine_version: String,
    /// Solver backend.
    pub solver_backend: String,
}

impl WacanaReport {
    /// Get all findings at a given severity.
    pub fn findings_at_severity(&self, severity: WacanaSeverity) -> Vec<&WacanaFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    /// Get all findings in a given category.
    pub fn findings_in_category(&self, category: &VulnerabilityCategory) -> Vec<&WacanaFinding> {
        self.findings
            .iter()
            .filter(|f| &f.category == category)
            .collect()
    }

    /// Generate a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "WACANA Concolic Analysis Report\n\
             ================================\n\
             Program: {:?}\n\
             Engine: {}\n\
             Solver: {}\n\
             \n\
             Scope:\n\
             - WASM modules: {}\n\
             - SBF binaries: {}\n\
             - Source files: {}\n\
             \n\
             Coverage:\n\
             - Paths explored: {}\n\
             - Branches covered: {}\n\
             \n\
             Findings: {} total\n\
             - Critical: {}\n\
             - High: {}\n\
             - Medium: {}\n\
             - Low: {}\n\
             \n\
             Duration: {}ms\n\
             Timestamp: {}",
            self.program_path,
            self.concolic_engine_version,
            self.solver_backend,
            self.wasm_modules_analyzed,
            self.sbf_binaries_analyzed,
            self.source_files_analyzed,
            self.total_paths_explored,
            self.total_branches_covered,
            self.findings.len(),
            self.critical_count,
            self.high_count,
            self.medium_count,
            self.low_count,
            self.analysis_duration_ms,
            self.timestamp,
        )
    }

    /// Whether the analysis found any critical or high findings.
    pub fn has_critical_findings(&self) -> bool {
        self.critical_count > 0 || self.high_count > 0
    }
}

/// A single vulnerability finding from WACANA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WacanaFinding {
    /// Vulnerability category.
    pub category: VulnerabilityCategory,
    /// Severity level.
    pub severity: WacanaSeverity,
    /// Location in the program (function:offset or filename::function).
    pub location: String,
    /// Human-readable description.
    pub description: String,
    /// Concrete inputs that trigger this vulnerability (if available).
    pub triggering_input: Option<String>,
    /// Path constraints leading to this vulnerability.
    pub path_constraints: Vec<String>,
    /// Recommended fix.
    pub recommendation: String,
    /// Deterministic fingerprint for deduplication.
    pub fingerprint: String,
    /// CWE identifier.
    pub cwe: Option<String>,
    /// Concolic proof (concrete execution trace proving the vulnerability).
    pub concolic_proof: Option<String>,
}

/// Finding severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WacanaSeverity {
    Critical = 5,
    High = 4,
    Medium = 3,
    Low = 2,
    Info = 1,
}

impl WacanaSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            WacanaSeverity::Critical => "CRITICAL",
            WacanaSeverity::High => "HIGH",
            WacanaSeverity::Medium => "MEDIUM",
            WacanaSeverity::Low => "LOW",
            WacanaSeverity::Info => "INFO",
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl std::fmt::Display for WacanaSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
