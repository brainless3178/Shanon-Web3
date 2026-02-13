//! Anchor security analysis report data structures

use crate::metrics::AnchorMetrics;
use serde::{Deserialize, Serialize};

/// Anchor security analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorAnalysisReport {
    pub program_path: String,
    pub timestamp: String,
    pub is_anchor_program: bool,
    pub anchor_version: Option<String>,
    pub findings: Vec<AnchorFinding>,
    pub metrics: AnchorMetrics,
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub anchor_security_score: u8, // 0-100, higher is better
    pub execution_time_ms: u64,
    pub engine_version: String,
}

/// Anchor security violation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorFinding {
    pub id: String,
    pub violation: AnchorViolation,
    pub severity: AnchorSeverity,
    pub file_path: String,
    pub line_number: usize,
    pub struct_name: Option<String>,
    pub field_name: Option<String>,
    pub description: String,
    pub code_snippet: String,
    pub risk_explanation: String,
    pub fix_recommendation: String,
    pub anchor_pattern: String, // e.g., "#[account(signer)]"
    pub cwe: String,
    pub fingerprint: String,
}

/// Anchor security violation categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorViolation {
    MissingSignerCheck,
    MissingOwnerCheck,
    MissingPDAValidation,
    MissingCPIGuard,
    WeakConstraint,
    ReinitializationVulnerability,
    MissingCloseGuard,
    InvalidTokenHook,
    MissingHasOne,
    UnsafeConstraintExpression,
    MissingBumpValidation,
    MissingSpaceCalculation,
    MissingRentExemption,
    UncheckedAccountType,
}

impl AnchorViolation {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MissingSignerCheck => "Missing Signer Check",
            Self::MissingOwnerCheck => "Missing Owner Check",
            Self::MissingPDAValidation => "Missing PDA Validation",
            Self::MissingCPIGuard => "Missing CPI Guard",
            Self::WeakConstraint => "Weak Account Constraint",
            Self::ReinitializationVulnerability => "Reinitialization Vulnerability",
            Self::MissingCloseGuard => "Missing Close Guard",
            Self::InvalidTokenHook => "Invalid Token-2022 Transfer Hook",
            Self::MissingHasOne => "Missing has_one Constraint",
            Self::UnsafeConstraintExpression => "Unsafe Constraint Expression",
            Self::MissingBumpValidation => "Missing Bump Validation",
            Self::MissingSpaceCalculation => "Missing Space Calculation",
            Self::MissingRentExemption => "Missing Rent Exemption",
            Self::UncheckedAccountType => "Unchecked Account Type",
        }
    }

    pub fn cwe(&self) -> &'static str {
        match self {
            Self::MissingSignerCheck => "CWE-862", // Missing Authorization
            Self::MissingOwnerCheck => "CWE-284",  // Improper Access Control
            Self::MissingPDAValidation => "CWE-20", // Improper Input Validation
            Self::MissingCPIGuard => "CWE-862",    // Missing Authorization
            Self::WeakConstraint => "CWE-1188",    // Insecure Default Initialization
            Self::ReinitializationVulnerability => "CWE-665", // Improper Initialization
            Self::MissingCloseGuard => "CWE-404",  // Improper Resource Shutdown
            Self::InvalidTokenHook => "CWE-20",    // Improper Input Validation
            Self::MissingHasOne => "CWE-862",      // Missing Authorization
            Self::UnsafeConstraintExpression => "CWE-1188", // Insecure Default Initialization
            Self::MissingBumpValidation => "CWE-20", // Improper Input Validation
            Self::MissingSpaceCalculation => "CWE-770", // Allocation of Resources Without Limits
            Self::MissingRentExemption => "CWE-400", // Uncontrolled Resource Consumption
            Self::UncheckedAccountType => "CWE-843", // Access of Resource Using Incompatible Type
        }
    }

    pub fn anchor_pattern(&self) -> &'static str {
        match self {
            Self::MissingSignerCheck => "#[account(signer)]",
            Self::MissingOwnerCheck => "#[account(owner = program_id)]",
            Self::MissingPDAValidation => "#[account(seeds = [...], bump)]",
            Self::MissingCPIGuard => "#[account(signer)] on CPI authority",
            Self::WeakConstraint => "#[account(constraint = ...)]",
            Self::ReinitializationVulnerability => "#[account(init)] vs #[account(init_if_needed)]",
            Self::MissingCloseGuard => "#[account(close = authority)]",
            Self::InvalidTokenHook => "TransferHook interface implementation",
            Self::MissingHasOne => "#[account(has_one = authority)]",
            Self::UnsafeConstraintExpression => "#[account(constraint = safe_check(...))]",
            Self::MissingBumpValidation => "bump in seeds derivation",
            Self::MissingSpaceCalculation => "#[account(init, space = ...)]",
            Self::MissingRentExemption => "rent exempt check",
            Self::UncheckedAccountType => "Account<'info, T> type validation",
        }
    }
}

/// Anchor severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnchorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AnchorSeverity {
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
