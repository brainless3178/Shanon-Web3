//! Crash Analyzer
//!
//! Takes raw crashes and invariant violations from a Trident fuzz campaign
//! and produces actionable `CrashReport`s with severity, category, and
//! fix recommendations.

use crate::anchor_extractor::AnchorProgramModel;
use crate::fuzz_executor::{FuzzCampaignResult, InvariantViolation, RawCrash};
use crate::report::{TridentFinding, TridentSeverity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Analyzes raw fuzzing crashes and invariant violations.
pub struct CrashAnalyzer {
    _private: (),
}

impl CrashAnalyzer {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Analyze all crashes and invariant violations from a campaign.
    pub fn analyze_all(
        &self,
        result: &FuzzCampaignResult,
        model: &AnchorProgramModel,
    ) -> Vec<CrashReport> {
        let mut reports = Vec::new();

        for crash in &result.crashes {
            reports.push(self.analyze_crash(crash, model));
        }

        for violation in &result.invariant_violations {
            reports.push(self.analyze_invariant_violation(violation, model));
        }

        // Deduplicate by fingerprint
        reports.sort_by_key(|a| a.fingerprint());
        reports.dedup_by(|a, b| a.fingerprint() == b.fingerprint());

        // Sort by severity (critical first)
        reports.sort_by(|a, b| a.severity.as_u8().cmp(&b.severity.as_u8()).reverse());

        reports
    }

    /// Analyze a single crash.
    fn analyze_crash(&self, crash: &RawCrash, _model: &AnchorProgramModel) -> CrashReport {
        let message_lower = crash.message.to_lowercase();

        let (category, severity, fix) = if message_lower.contains("signer")
            || message_lower.contains("unsigned")
        {
            (
                CrashCategory::MissingSigner,
                TridentSeverity::Critical,
                format!(
                    "Add signer constraint: `#[account(signer)]` or `Signer<'info>` type for \
                     authority account in '{}'",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("overflow") || message_lower.contains("underflow") {
            (
                CrashCategory::ArithmeticOverflow,
                TridentSeverity::High,
                format!(
                    "Replace unchecked arithmetic with `.checked_add()`, `.checked_sub()`, etc. in '{}'",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("cpi") || message_lower.contains("malicious program") {
            (
                CrashCategory::CPIReentrancy,
                TridentSeverity::Critical,
                format!(
                    "Validate CPI target program ID in '{}': \
                     `require_keys_eq!(ctx.accounts.program.key(), expected_program_id)`",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("reinit") || message_lower.contains("re-init") {
            (
                CrashCategory::ReInitialization,
                TridentSeverity::High,
                format!(
                    "Use `#[account(init, ...)]` constraint in '{}' to prevent re-initialization",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("substitution")
            || message_lower.contains("account confusion")
        {
            (
                CrashCategory::AccountConfusion,
                TridentSeverity::High,
                format!(
                    "Replace `AccountInfo` with typed `Account<'info, T>` in '{}'",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("pda") || message_lower.contains("seed") {
            (
                CrashCategory::PDASeedCollision,
                TridentSeverity::Medium,
                format!(
                    "Add more entropy to PDA seeds in '{}' (e.g., user pubkey, timestamp)",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("close") || message_lower.contains("drain") {
            (
                CrashCategory::CloseAccountDrain,
                TridentSeverity::High,
                format!(
                    "Use `#[account(close = destination)]` in '{}' for safe account closing",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("withdraw") || message_lower.contains("unauthorized") {
            (
                CrashCategory::UnauthorizedWithdrawal,
                TridentSeverity::Critical,
                format!(
                    "Enforce owner/authority check before fund transfer in '{}'",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("discriminator") || message_lower.contains("corruption") {
            (
                CrashCategory::StateCorruption,
                TridentSeverity::High,
                format!(
                    "Validate account discriminator before deserialization in '{}'",
                    crash.instruction,
                ),
            )
        } else if message_lower.contains("constraint") || message_lower.contains("bypass") {
            (
                CrashCategory::ConstraintBypass,
                TridentSeverity::High,
                format!(
                    "Review and strengthen Anchor constraints in '{}' — \
                     consider using `constraint = <expr>` for custom validation",
                    crash.instruction,
                ),
            )
        } else {
            (
                CrashCategory::StateCorruption,
                TridentSeverity::Medium,
                format!(
                    "Review instruction '{}' for unexpected state mutations",
                    crash.instruction,
                ),
            )
        };

        CrashReport {
            category,
            instruction: crash.instruction.clone(),
            description: crash.message.clone(),
            severity,
            triggering_input: crash.input_bytes.as_ref().map(hex::encode),
            state_diff: None,
            stack_trace: crash.stack_trace.clone(),
            iteration: 0,
            accounts_involved: vec![crash.instruction.clone()],
            property_violated: None,
            fix_recommendation: fix,
        }
    }

    /// Analyze an invariant violation.
    fn analyze_invariant_violation(
        &self,
        violation: &InvariantViolation,
        _model: &AnchorProgramModel,
    ) -> CrashReport {
        let property_lower = violation.property.to_lowercase();

        let (category, severity, fix) = if property_lower.contains("balance") {
            (
                CrashCategory::UnauthorizedWithdrawal,
                TridentSeverity::Critical,
                "Enforce balance conservation checks after token transfers".to_string(),
            )
        } else if property_lower.contains("access") || property_lower.contains("signer") {
            (
                CrashCategory::MissingSigner,
                TridentSeverity::Critical,
                "Add signer constraint to prevent unauthorized state mutations".to_string(),
            )
        } else if property_lower.contains("account_validation")
            || property_lower.contains("substitution")
        {
            (
                CrashCategory::AccountConfusion,
                TridentSeverity::High,
                "Replace unchecked AccountInfo with typed Account<> or add CHECK documentation"
                    .to_string(),
            )
        } else if property_lower.contains("discriminator") {
            (
                CrashCategory::StateCorruption,
                TridentSeverity::High,
                "Ensure account discriminators are validated before access".to_string(),
            )
        } else if property_lower.contains("pda") {
            (
                CrashCategory::PDASeedCollision,
                TridentSeverity::Medium,
                "Use canonical bumps and validate PDA derivation seeds".to_string(),
            )
        } else {
            (
                CrashCategory::ConstraintBypass,
                TridentSeverity::Medium,
                format!("Investigate property '{}' violation", violation.property),
            )
        };

        let description = if let Some(ref after) = violation.state_after {
            format!(
                "Property '{}' violated in '{}': {}",
                violation.property, violation.instruction, after,
            )
        } else {
            format!(
                "Property '{}' violated during instruction '{}'",
                violation.property, violation.instruction,
            )
        };

        CrashReport {
            category,
            instruction: violation.instruction.clone(),
            description,
            severity,
            triggering_input: None,
            state_diff: violation.state_after.clone(),
            stack_trace: None,
            iteration: 0,
            accounts_involved: vec![violation.instruction.clone()],
            property_violated: Some(violation.property.clone()),
            fix_recommendation: fix,
        }
    }
}

impl Default for CrashAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// Analyzed crash report with category, severity, and recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub category: CrashCategory,
    pub instruction: String,
    pub description: String,
    pub severity: TridentSeverity,
    pub triggering_input: Option<String>,
    pub state_diff: Option<String>,
    pub stack_trace: Option<String>,
    pub iteration: u64,
    pub accounts_involved: Vec<String>,
    pub property_violated: Option<String>,
    pub fix_recommendation: String,
}

impl CrashReport {
    /// Compute a deterministic fingerprint for deduplication.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", self.category));
        hasher.update(&self.instruction);
        if let Some(ref prop) = self.property_violated {
            hasher.update(prop);
        }
        hex::encode(hasher.finalize())[..16].to_string()
    }

    /// Convert to a `TridentFinding` for the report.
    pub fn to_finding(&self) -> TridentFinding {
        TridentFinding {
            id: format!(
                "TRIDENT-{}",
                self.fingerprint()
                    .to_uppercase()
                    .get(..8)
                    .unwrap_or("UNKNOWN")
            ),
            category: self.category.clone(),
            instruction: self.instruction.clone(),
            description: self.description.clone(),
            severity: self.severity.clone(),
            triggering_input: self.triggering_input.clone(),
            state_diff: self.state_diff.clone(),
            stack_trace: self.stack_trace.clone(),
            iteration: self.iteration,
            accounts_involved: self.accounts_involved.clone(),
            property_violated: self.property_violated.clone(),
            fix_recommendation: self.fix_recommendation.clone(),
            fingerprint: self.fingerprint(),
            cwe: self.category.cwe().map(String::from),
        }
    }
}

/// Categories of vulnerabilities found by Trident fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CrashCategory {
    /// Wrong account substitution bypasses checks.
    AccountConfusion,
    /// Unchecked math leads to token inflation.
    ArithmeticOverflow,
    /// Transaction accepted without required signer.
    MissingSigner,
    /// Account re-initialized to attacker-controlled state.
    ReInitialization,
    /// Derived addresses collide across users/pools.
    PDASeedCollision,
    /// Cross-program invocation re-enters mutably.
    CPIReentrancy,
    /// Funds drained without proper authorization.
    UnauthorizedWithdrawal,
    /// Discriminator / data layout corruption.
    StateCorruption,
    /// Anchor constraint circumvented via crafted input.
    ConstraintBypass,
    /// Lamport drain via account closing race.
    CloseAccountDrain,
}

impl CrashCategory {
    /// Get CWE identifier for this category.
    pub fn cwe(&self) -> Option<&'static str> {
        match self {
            CrashCategory::AccountConfusion => Some("CWE-345"),
            CrashCategory::ArithmeticOverflow => Some("CWE-190"),
            CrashCategory::MissingSigner => Some("CWE-284"),
            CrashCategory::ReInitialization => Some("CWE-665"),
            CrashCategory::PDASeedCollision => Some("CWE-330"),
            CrashCategory::CPIReentrancy => Some("CWE-841"),
            CrashCategory::UnauthorizedWithdrawal => Some("CWE-863"),
            CrashCategory::StateCorruption => Some("CWE-787"),
            CrashCategory::ConstraintBypass => Some("CWE-20"),
            CrashCategory::CloseAccountDrain => Some("CWE-362"),
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            CrashCategory::AccountConfusion => "Account Confusion",
            CrashCategory::ArithmeticOverflow => "Arithmetic Overflow",
            CrashCategory::MissingSigner => "Missing Signer",
            CrashCategory::ReInitialization => "Re-Initialization",
            CrashCategory::PDASeedCollision => "PDA Seed Collision",
            CrashCategory::CPIReentrancy => "CPI Reentrancy",
            CrashCategory::UnauthorizedWithdrawal => "Unauthorized Withdrawal",
            CrashCategory::StateCorruption => "State Corruption",
            CrashCategory::ConstraintBypass => "Constraint Bypass",
            CrashCategory::CloseAccountDrain => "Close Account Drain",
        }
    }
}
