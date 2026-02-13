//! Trident Fuzz Report
//!
//! Structured report output from a Trident fuzz campaign, designed
//! to integrate seamlessly with the orchestrator's `AuditReport`.

use crate::anchor_extractor::AnchorProgramModel;
use crate::crash_analyzer::CrashCategory;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete report from a Trident fuzz campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TridentFuzzReport {
    /// Path to the program that was fuzzed.
    pub program_path: PathBuf,
    /// ISO 8601 timestamp of analysis start.
    pub timestamp: String,
    /// The Anchor program model extracted from source.
    pub program_model: AnchorProgramModel,
    /// All findings (crashes + invariant violations).
    pub findings: Vec<TridentFinding>,
    /// Count of critical-severity findings.
    pub critical_count: usize,
    /// Count of high-severity findings.
    pub high_count: usize,
    /// Count of medium-severity findings.
    pub medium_count: usize,
    /// Count of low-severity findings.
    pub low_count: usize,
    /// Total fuzz iterations executed.
    pub total_iterations: u64,
    /// Total number of unique crashes detected.
    pub total_crashes: usize,
    /// Branch coverage percentage (if collected).
    pub branch_coverage_pct: f64,
    /// Path to generated harness files.
    pub harness_path: Option<PathBuf>,
    /// Trident version used (if CLI available).
    pub trident_version: Option<String>,
    /// Analysis duration in milliseconds.
    pub analysis_duration_ms: u64,
    /// Backend description.
    pub trident_backend: String,
}

/// A single finding from Trident fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TridentFinding {
    /// Unique identifier (e.g., "TRIDENT-A1B2C3D4").
    pub id: String,
    /// Vulnerability category.
    pub category: CrashCategory,
    /// Instruction where the issue was found.
    pub instruction: String,
    /// Human-readable description.
    pub description: String,
    /// Severity level.
    pub severity: TridentSeverity,
    /// Input that triggered the crash (hex-encoded or human-readable).
    pub triggering_input: Option<String>,
    /// State difference before/after the crash.
    pub state_diff: Option<String>,
    /// Stack trace at the crash point.
    pub stack_trace: Option<String>,
    /// Fuzz iteration number where the crash occurred.
    pub iteration: u64,
    /// Accounts involved in the crash.
    pub accounts_involved: Vec<String>,
    /// Property invariant that was violated (if any).
    pub property_violated: Option<String>,
    /// Recommended fix.
    pub fix_recommendation: String,
    /// Deterministic fingerprint for deduplication.
    pub fingerprint: String,
    /// CWE identifier.
    pub cwe: Option<String>,
}

/// Severity levels for Trident findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TridentSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl TridentSeverity {
    /// Numeric severity (5 = critical, 1 = info).
    pub fn as_u8(&self) -> u8 {
        match self {
            TridentSeverity::Critical => 5,
            TridentSeverity::High => 4,
            TridentSeverity::Medium => 3,
            TridentSeverity::Low => 2,
            TridentSeverity::Info => 1,
        }
    }

    /// Human-readable severity label.
    pub fn as_str(&self) -> &'static str {
        match self {
            TridentSeverity::Critical => "CRITICAL",
            TridentSeverity::High => "HIGH",
            TridentSeverity::Medium => "MEDIUM",
            TridentSeverity::Low => "LOW",
            TridentSeverity::Info => "INFO",
        }
    }
}
