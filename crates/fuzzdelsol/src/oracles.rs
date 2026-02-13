//! Security Oracles
//!
//! Oracles detect security violations during fuzzing:
//! - Missing signer checks before state mutations
//! - Unauthorized state changes
//! - Missing owner checks
//! - Arbitrary account substitution

use crate::bytecode_parser::EbpfProgramModel;
use crate::fuzz_engine::ExecutionResult;
use serde::{Deserialize, Serialize};

/// Oracle trait for detecting security violations.
pub trait Oracle: Send + Sync {
    fn check(&self, result: &ExecutionResult, model: &EbpfProgramModel) -> Option<OracleViolation>;
    fn name(&self) -> &'static str;
}

/// A security violation detected by an oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleViolation {
    pub oracle_name: String,
    pub severity: ViolationSeverity,
    pub description: String,
    pub address: u64,
    pub function: String,
    pub triggering_input: Option<String>,
    pub fix_recommendation: String,
    pub cwe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ViolationSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl ViolationSeverity {
    pub fn as_u8(&self) -> u8 {
        match self {
            ViolationSeverity::Critical => 5,
            ViolationSeverity::High => 4,
            ViolationSeverity::Medium => 3,
            ViolationSeverity::Low => 2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ViolationSeverity::Critical => "CRITICAL",
            ViolationSeverity::High => "HIGH",
            ViolationSeverity::Medium => "MEDIUM",
            ViolationSeverity::Low => "LOW",
        }
    }
}

// ─── Oracle Implementations ──────────────────────────────────────────────────

/// Detects missing signer checks before state mutations.
pub struct MissingSignerCheckOracle {
    _model: EbpfProgramModel,
}

impl MissingSignerCheckOracle {
    pub fn new(model: &EbpfProgramModel) -> Self {
        Self {
            _model: model.clone(),
        }
    }
}

impl Oracle for MissingSignerCheckOracle {
    fn check(
        &self,
        result: &ExecutionResult,
        _model: &EbpfProgramModel,
    ) -> Option<OracleViolation> {
        // Check if any state change occurred without a signer check
        for change in &result.state_changes {
            if !change.had_signer_check {
                // Check if any account in the input was a signer
                let has_signer = result.input.accounts.iter().any(|a| a.is_signer);

                if !has_signer {
                    return Some(OracleViolation {
                        oracle_name: "MissingSignerCheck".to_string(),
                        severity: ViolationSeverity::Critical,
                        description: format!(
                            "State mutation in function '{}' at 0x{:x} succeeded WITHOUT any signer. \
                             Fuzzer bypassed authorization by providing unsigned accounts.",
                            change.function, change.address
                        ),
                        address: change.address,
                        function: change.function.clone(),
                        triggering_input: Some(format!("{} accounts, {} bytes instruction data", 
                            result.input.accounts.len(), result.input.instruction_data.len())),
                        fix_recommendation: "Add signer check before state mutation: \
                            `require!(ctx.accounts.authority.is_signer, ErrorCode::MissingSigner)`".to_string(),
                        cwe: Some("CWE-862".to_string()),
                    });
                }
            }
        }
        None
    }

    fn name(&self) -> &'static str {
        "MissingSignerCheck"
    }
}

/// Detects unauthorized state changes.
pub struct UnauthorizedStateChangeOracle {
    _model: EbpfProgramModel,
}

impl UnauthorizedStateChangeOracle {
    pub fn new(model: &EbpfProgramModel) -> Self {
        Self {
            _model: model.clone(),
        }
    }
}

impl Oracle for UnauthorizedStateChangeOracle {
    fn check(&self, result: &ExecutionResult, model: &EbpfProgramModel) -> Option<OracleViolation> {
        // Check if state was mutated by a function that doesn't have proper checks
        for change in &result.state_changes {
            // Find the function in the model
            if let Some(func) = model.functions.iter().find(|f| f.name == change.function) {
                if func.modifies_account_data && !func.has_signer_check {
                    return Some(OracleViolation {
                        oracle_name: "UnauthorizedStateChange".to_string(),
                        severity: ViolationSeverity::Critical,
                        description: format!(
                            "Function '{}' at 0x{:x} modifies account data but has NO signer check in bytecode. \
                             Fuzzer confirmed unauthorized state mutation is possible.",
                            func.name, func.address
                        ),
                        address: func.address,
                        function: func.name.clone(),
                        triggering_input: Some(format!("{} accounts", result.input.accounts.len())),
                        fix_recommendation: "Add authorization check at bytecode level. \
                            Ensure compiled code includes signer/owner validation before writes.".to_string(),
                        cwe: Some("CWE-284".to_string()),
                    });
                }
            }
        }
        None
    }

    fn name(&self) -> &'static str {
        "UnauthorizedStateChange"
    }
}

/// Detects missing owner checks.
pub struct MissingOwnerCheckOracle {
    _model: EbpfProgramModel,
}

impl MissingOwnerCheckOracle {
    pub fn new(model: &EbpfProgramModel) -> Self {
        Self {
            _model: model.clone(),
        }
    }
}

impl Oracle for MissingOwnerCheckOracle {
    fn check(
        &self,
        result: &ExecutionResult,
        _model: &EbpfProgramModel,
    ) -> Option<OracleViolation> {
        // Check if accounts with different owners were accepted
        let owners: Vec<_> = result.input.accounts.iter().map(|a| a.owner).collect();
        let unique_owners: std::collections::HashSet<_> = owners.iter().collect();

        if unique_owners.len() > 1 && !result.state_changes.is_empty() {
            // State was mutated with accounts from different programs
            return Some(OracleViolation {
                oracle_name: "MissingOwnerCheck".to_string(),
                severity: ViolationSeverity::High,
                description: format!(
                    "Fuzzer provided accounts owned by {} different programs, and state mutation succeeded. \
                     Missing owner validation allows cross-program account confusion.",
                    unique_owners.len()
                ),
                address: result.state_changes[0].address,
                function: result.state_changes[0].function.clone(),
                triggering_input: Some(format!("{} different owners", unique_owners.len())),
                fix_recommendation: "Validate account owner before access: \
                    `require_keys_eq!(account.owner, expected_program_id)`".to_string(),
                cwe: Some("CWE-345".to_string()),
            });
        }
        None
    }

    fn name(&self) -> &'static str {
        "MissingOwnerCheck"
    }
}

/// Detects arbitrary account substitution vulnerabilities.
pub struct ArbitraryAccountSubstitutionOracle {
    _model: EbpfProgramModel,
}

impl ArbitraryAccountSubstitutionOracle {
    pub fn new(model: &EbpfProgramModel) -> Self {
        Self {
            _model: model.clone(),
        }
    }
}

impl Oracle for ArbitraryAccountSubstitutionOracle {
    fn check(
        &self,
        result: &ExecutionResult,
        _model: &EbpfProgramModel,
    ) -> Option<OracleViolation> {
        // Check if execution succeeded with completely random account keys
        if !result.state_changes.is_empty() {
            // All accounts are random (Pubkey::new_unique()), yet state mutation succeeded
            // This suggests the program doesn't validate account relationships
            return Some(OracleViolation {
                oracle_name: "ArbitraryAccountSubstitution".to_string(),
                severity: ViolationSeverity::High,
                description: format!(
                    "Fuzzer provided completely random account keys, and state mutation in '{}' succeeded. \
                     Program accepts arbitrary accounts without validating relationships or expected keys.",
                    result.state_changes[0].function
                ),
                address: result.state_changes[0].address,
                function: result.state_changes[0].function.clone(),
                triggering_input: Some(format!("{} random accounts", result.input.accounts.len())),
                fix_recommendation: "Validate account keys against expected values: \
                    `require_keys_eq!(account.key(), expected_key)` or use PDA derivation checks.".to_string(),
                cwe: Some("CWE-345".to_string()),
            });
        }
        None
    }

    fn name(&self) -> &'static str {
        "ArbitraryAccountSubstitution"
    }
}
