//! Sec3 (Soteria) static analysis report data structures.
//!
//! Defines the structured output format consumed by the audit pipeline.
//! Each finding carries CWE mapping, severity, location, fix recommendation,
//! and a deterministic fingerprint for deduplication across runs.

use serde::{Deserialize, Serialize};

// ─── Severity ────────────────────────────────────────────────────────────────

/// Vulnerability severity aligned with CVSS v3.1 qualitative scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sec3Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Sec3Severity {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }
}

// ─── Vulnerability Category ─────────────────────────────────────────────────

/// Sec3/Soteria vulnerability categories covering the standard Solana pitfall taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sec3Category {
    /// Account passed without verifying owner matches expected program.
    MissingOwnerCheck,
    /// Arithmetic operation without checked_add/sub/mul/div.
    IntegerOverflow,
    /// Using raw `AccountInfo` instead of typed `Account<T>` / `Program<T>`.
    AccountConfusion,
    /// Mutable state change without signer verification.
    MissingSignerCheck,
    /// Same account supplied for two distinct mutable parameters.
    DuplicateMutableAccounts,
    /// Cross-program invocation without verifying the target program ID.
    ArbitraryCPI,
    /// Account not checked for rent exemption before use.
    MissingRentExemption,
    /// PDA seeds lack sufficient entropy or canonical bump validation.
    InsecurePDADerivation,
    /// Account closure does not zero data / drain lamports properly.
    CloseAccountDrain,
    /// Account deserialized without discriminator tag validation.
    MissingDiscriminator,
    /// `init_if_needed` allows re-initialization attacks.
    ReInitialization,
    /// Remaining accounts used without proper validation.
    UncheckedRemainingAccounts,
}

impl Sec3Category {
    /// Primary CWE identifier.
    pub fn cwe(&self) -> &'static str {
        match self {
            Self::MissingOwnerCheck => "CWE-284",
            Self::IntegerOverflow => "CWE-190",
            Self::AccountConfusion => "CWE-345",
            Self::MissingSignerCheck => "CWE-287",
            Self::DuplicateMutableAccounts => "CWE-362",
            Self::ArbitraryCPI => "CWE-94",
            Self::MissingRentExemption => "CWE-670",
            Self::InsecurePDADerivation => "CWE-330",
            Self::CloseAccountDrain => "CWE-672",
            Self::MissingDiscriminator => "CWE-345",
            Self::ReInitialization => "CWE-665",
            Self::UncheckedRemainingAccounts => "CWE-20",
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::MissingOwnerCheck => "Missing Owner Check",
            Self::IntegerOverflow => "Integer Overflow/Underflow",
            Self::AccountConfusion => "Account Type Confusion",
            Self::MissingSignerCheck => "Missing Signer Validation",
            Self::DuplicateMutableAccounts => "Duplicate Mutable Accounts",
            Self::ArbitraryCPI => "Arbitrary CPI Invocation",
            Self::MissingRentExemption => "Missing Rent Exemption Check",
            Self::InsecurePDADerivation => "Insecure PDA Derivation",
            Self::CloseAccountDrain => "Close Account Drain",
            Self::MissingDiscriminator => "Missing Discriminator Check",
            Self::ReInitialization => "Re-Initialization via init_if_needed",
            Self::UncheckedRemainingAccounts => "Unchecked Remaining Accounts",
        }
    }
}

// ─── Individual Finding ─────────────────────────────────────────────────────

/// A single vulnerability finding from Sec3 analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sec3Finding {
    /// Stable identifier, e.g. `SEC3-A1B2C3D4`.
    pub id: String,
    /// Vulnerability category.
    pub category: Sec3Category,
    /// Severity level.
    pub severity: Sec3Severity,
    /// Source file where the vulnerability was detected.
    pub file_path: String,
    /// Line number (1-based) in the source file.
    pub line_number: usize,
    /// Anchor instruction name containing the vulnerability.
    pub instruction: String,
    /// Account name involved (if applicable).
    pub account_name: Option<String>,
    /// Human-readable description.
    pub description: String,
    /// Recommended fix.
    pub fix_recommendation: String,
    /// CWE identifier.
    pub cwe: String,
    /// Deterministic fingerprint for deduplication (SHA-256 of category+file+line+instruction).
    pub fingerprint: String,
    /// Matched source snippet.
    pub source_snippet: Option<String>,
    /// Concrete fix diff (unified diff format).
    pub fix_diff: Option<String>,
}

// ─── Top-Level Report ────────────────────────────────────────────────────────

/// Top-level Sec3 (Soteria) analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sec3AnalysisReport {
    /// Root path of the analysed program.
    pub program_path: String,
    /// UTC timestamp.
    pub timestamp: String,
    /// All findings.
    pub findings: Vec<Sec3Finding>,
    /// Files scanned.
    pub files_scanned: usize,
    /// Total lines of code parsed.
    pub lines_scanned: usize,
    /// Number of Anchor instructions analysed.
    pub instructions_analysed: usize,
    /// Number of accounts analysed.
    pub accounts_analysed: usize,
    /// Count by severity.
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    /// Checklist completeness: (check_name, passed).
    pub checklist_results: Vec<(String, bool)>,
    /// Sec3 engine version label.
    pub engine_version: String,
}
