//! Anchor security metrics tracking

use serde::{Deserialize, Serialize};

/// Aggregated metrics for Anchor security patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorMetrics {
    /// Missing signer checks
    pub missing_signer_checks: usize,
    /// Missing owner checks
    pub missing_owner_checks: usize,
    /// Missing PDA validation
    pub missing_pda_validation: usize,
    /// Missing CPI guards
    pub missing_cpi_guards: usize,
    /// Weak constraints
    pub weak_constraints: usize,
    /// Reinitialization vulnerabilities
    pub reinit_vulnerabilities: usize,
    /// Missing close guards
    pub missing_close_guards: usize,
    /// Token-2022 hook implementations
    pub token_hook_implementations: usize,
    /// Custom constraint count
    pub custom_constraint_count: usize,
    /// Total account structs
    pub total_account_structs: usize,
    /// Total instruction handlers
    pub total_instruction_handlers: usize,
}

impl AnchorMetrics {
    pub fn new() -> Self {
        Self {
            missing_signer_checks: 0,
            missing_owner_checks: 0,
            missing_pda_validation: 0,
            missing_cpi_guards: 0,
            weak_constraints: 0,
            reinit_vulnerabilities: 0,
            missing_close_guards: 0,
            token_hook_implementations: 0,
            custom_constraint_count: 0,
            total_account_structs: 0,
            total_instruction_handlers: 0,
        }
    }

    /// Total violations found
    pub fn total_violations(&self) -> usize {
        self.missing_signer_checks
            + self.missing_owner_checks
            + self.missing_pda_validation
            + self.missing_cpi_guards
            + self.weak_constraints
            + self.reinit_vulnerabilities
            + self.missing_close_guards
    }

    /// Summary string for logging
    pub fn summary(&self) -> String {
        format!(
            "signer={}, owner={}, pda={}, cpi={}, weak={}, reinit={}, close={}",
            self.missing_signer_checks,
            self.missing_owner_checks,
            self.missing_pda_validation,
            self.missing_cpi_guards,
            self.weak_constraints,
            self.reinit_vulnerabilities,
            self.missing_close_guards
        )
    }
}

impl Default for AnchorMetrics {
    fn default() -> Self {
        Self::new()
    }
}
