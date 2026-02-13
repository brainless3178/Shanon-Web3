//! Invariant Miner - Automatic Program Invariant Discovery
//!
//! Analyzes Solana programs to discover implicit invariants that
//! should hold across all program states.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A discovered program invariant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub id: String,
    pub category: InvariantCategory,
    pub expression: String,
    pub description: String,
    pub confidence: f32,
    pub source_locations: Vec<String>,
    pub violation_impact: String,
}

/// Categories of invariants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InvariantCategory {
    /// Balance conservation invariants
    BalanceConservation,
    /// State transition invariants
    StateTransition,
    /// Access control invariants
    AccessControl,
    /// Arithmetic bounds invariants
    ArithmeticBounds,
    /// Account relationship invariants
    AccountRelationship,
    /// Temporal invariants (ordering)
    Temporal,
}

/// Mined invariant with supporting evidence
#[derive(Debug, Clone)]
pub struct MinedInvariant {
    pub invariant: Invariant,
    pub evidence: Vec<Evidence>,
    pub counterexample: Option<String>,
}

/// Evidence supporting an invariant
#[derive(Debug, Clone)]
pub struct Evidence {
    pub location: String,
    pub code_snippet: String,
    pub evidence_type: EvidenceType,
}

#[derive(Debug, Clone)]
pub enum EvidenceType {
    ExplicitCheck,
    ImpliedByType,
    ObservedPattern,
    AnchorConstraint,
}

/// Configuration for the invariant miner
#[derive(Debug, Clone)]
pub struct MinerConfig {
    pub min_confidence: f32,
    pub max_invariants: usize,
    pub include_speculative: bool,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.7,
            max_invariants: 50,
            include_speculative: false,
        }
    }
}

/// Main invariant miner
pub struct InvariantMiner {
    config: MinerConfig,
    discovered_invariants: Vec<MinedInvariant>,
    balance_vars: HashSet<String>,
    authority_vars: HashSet<String>,
    state_vars: HashSet<String>,
}

impl InvariantMiner {
    /// Create a new invariant miner with default config
    pub fn new() -> Self {
        Self::with_config(MinerConfig::default())
    }

    /// Create with specific configuration
    pub fn with_config(config: MinerConfig) -> Self {
        Self {
            config,
            discovered_invariants: Vec::new(),
            balance_vars: HashSet::new(),
            authority_vars: HashSet::new(),
            state_vars: HashSet::new(),
        }
    }

    /// Mine invariants from source code
    pub fn mine_from_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<Invariant>, MinerError> {
        let file = syn::parse_file(source).map_err(|e| MinerError::ParseError(e.to_string()))?;

        // Phase 1: Collect variable classifications
        self.classify_variables(&file);

        // Phase 2: Mine balance conservation invariants
        self.mine_balance_invariants(&file, filename);

        // Phase 3: Mine access control invariants
        self.mine_access_control_invariants(&file, filename);

        // Phase 4: Mine arithmetic bound invariants
        self.mine_arithmetic_invariants(&file, filename);

        // Phase 5: Mine state transition invariants
        self.mine_state_invariants(&file, filename);

        // Filter by confidence and return
        let results: Vec<Invariant> = self
            .discovered_invariants
            .iter()
            .filter(|mi| mi.invariant.confidence >= self.config.min_confidence)
            .take(self.config.max_invariants)
            .map(|mi| mi.invariant.clone())
            .collect();

        Ok(results)
    }

    /// Classify variables by their likely purpose
    fn classify_variables(&mut self, file: &syn::File) {
        let code = quote::quote!(#file).to_string().to_lowercase();

        // Balance-related variables
        for pattern in &[
            "balance", "amount", "lamports", "quantity", "supply", "reserve",
        ] {
            if code.contains(pattern) {
                self.balance_vars.insert(pattern.to_string());
            }
        }

        // Authority-related variables
        for pattern in &[
            "authority",
            "owner",
            "admin",
            "signer",
            "payer",
            "controller",
        ] {
            if code.contains(pattern) {
                self.authority_vars.insert(pattern.to_string());
            }
        }

        // State-related variables
        for pattern in &[
            "state",
            "status",
            "initialized",
            "is_active",
            "paused",
            "frozen",
        ] {
            if code.contains(pattern) {
                self.state_vars.insert(pattern.to_string());
            }
        }
    }

    /// Mine balance conservation invariants
    fn mine_balance_invariants(&mut self, file: &syn::File, filename: &str) {
        let code = quote::quote!(#file).to_string();

        // Pattern: transfer between accounts should conserve total
        if code.contains("transfer") && (code.contains("from") || code.contains("to")) {
            self.discovered_invariants.push(MinedInvariant {
                invariant: Invariant {
                    id: format!("BC-{}", self.discovered_invariants.len() + 1),
                    category: InvariantCategory::BalanceConservation,
                    expression: "from.balance + to.balance == TOTAL_BEFORE".to_string(),
                    description: "Token transfers must conserve total supply across accounts"
                        .to_string(),
                    confidence: 0.9,
                    source_locations: vec![filename.to_string()],
                    violation_impact:
                        "Tokens can be created or destroyed, leading to inflation or theft"
                            .to_string(),
                },
                evidence: vec![Evidence {
                    location: filename.to_string(),
                    code_snippet: "transfer detected".to_string(),
                    evidence_type: EvidenceType::ObservedPattern,
                }],
                counterexample: None,
            });
        }

        // Pattern: withdraw should not exceed balance
        if code.contains("withdraw") || code.contains("redeem") {
            self.discovered_invariants.push(MinedInvariant {
                invariant: Invariant {
                    id: format!("BC-{}", self.discovered_invariants.len() + 1),
                    category: InvariantCategory::BalanceConservation,
                    expression: "withdraw_amount <= account.balance".to_string(),
                    description: "Withdrawals cannot exceed available balance".to_string(),
                    confidence: 0.95,
                    source_locations: vec![filename.to_string()],
                    violation_impact: "Underflow attack allowing withdrawal of more than deposited"
                        .to_string(),
                },
                evidence: vec![],
                counterexample: None,
            });
        }

        // Pattern: deposit should increase balance
        if code.contains("deposit") || code.contains("stake") {
            self.discovered_invariants.push(MinedInvariant {
                invariant: Invariant {
                    id: format!("BC-{}", self.discovered_invariants.len() + 1),
                    category: InvariantCategory::BalanceConservation,
                    expression: "balance_after >= balance_before".to_string(),
                    description: "Deposits must increase or maintain balance".to_string(),
                    confidence: 0.85,
                    source_locations: vec![filename.to_string()],
                    violation_impact: "Deposits may be lost or misdirected".to_string(),
                },
                evidence: vec![],
                counterexample: None,
            });
        }
    }

    /// Mine access control invariants
    fn mine_access_control_invariants(&mut self, file: &syn::File, filename: &str) {
        let code = quote::quote!(#file).to_string();

        // Pattern: authority check before state modification
        if code.contains("authority") || code.contains("owner") {
            if code.contains("Signer<") {
                self.discovered_invariants.push(MinedInvariant {
                    invariant: Invariant {
                        id: format!("AC-{}", self.discovered_invariants.len() + 1),
                        category: InvariantCategory::AccessControl,
                        expression: "msg.sender == account.authority".to_string(),
                        description: "Only the designated authority can modify protected state"
                            .to_string(),
                        confidence: 0.95,
                        source_locations: vec![filename.to_string()],
                        violation_impact: "Unauthorized users can take control of accounts"
                            .to_string(),
                    },
                    evidence: vec![Evidence {
                        location: filename.to_string(),
                        code_snippet: "Signer<'info> constraint found".to_string(),
                        evidence_type: EvidenceType::AnchorConstraint,
                    }],
                    counterexample: None,
                });
            } else {
                // Missing signer - potential vulnerability
                self.discovered_invariants.push(MinedInvariant {
                    invariant: Invariant {
                        id: format!("AC-{}", self.discovered_invariants.len() + 1),
                        category: InvariantCategory::AccessControl,
                        expression: "authority MUST BE Signer".to_string(),
                        description: "Authority accounts must be validated as signers".to_string(),
                        confidence: 0.6, // Lower confidence - speculative
                        source_locations: vec![filename.to_string()],
                        violation_impact: "Anyone can impersonate the authority".to_string(),
                    },
                    evidence: vec![],
                    counterexample: Some("Authority used without Signer constraint".to_string()),
                });
            }
        }
    }

    /// Mine arithmetic bound invariants
    fn mine_arithmetic_invariants(&mut self, file: &syn::File, filename: &str) {
        let code = quote::quote!(#file).to_string();

        // Check for checked arithmetic
        let uses_checked = code.contains("checked_add")
            || code.contains("checked_sub")
            || code.contains("checked_mul")
            || code.contains("checked_div");

        let uses_saturating = code.contains("saturating_add") || code.contains("saturating_sub");

        if code.contains("u64") || code.contains("u128") {
            if uses_checked || uses_saturating {
                self.discovered_invariants.push(MinedInvariant {
                    invariant: Invariant {
                        id: format!("AR-{}", self.discovered_invariants.len() + 1),
                        category: InvariantCategory::ArithmeticBounds,
                        expression: "result in [0, u64::MAX]".to_string(),
                        description: "Arithmetic operations stay within type bounds".to_string(),
                        confidence: 0.9,
                        source_locations: vec![filename.to_string()],
                        violation_impact: "None - checked arithmetic prevents overflow".to_string(),
                    },
                    evidence: vec![Evidence {
                        location: filename.to_string(),
                        code_snippet: "checked/saturating arithmetic".to_string(),
                        evidence_type: EvidenceType::ExplicitCheck,
                    }],
                    counterexample: None,
                });
            } else if code.contains('+') || code.contains('-') || code.contains('*') {
                // Unchecked arithmetic - potential vulnerability
                self.discovered_invariants.push(MinedInvariant {
                    invariant: Invariant {
                        id: format!("AR-{}", self.discovered_invariants.len() + 1),
                        category: InvariantCategory::ArithmeticBounds,
                        expression: "result SHOULD BE in [0, u64::MAX]".to_string(),
                        description: "Arithmetic operations may overflow/underflow".to_string(),
                        confidence: 0.5, // Lower - speculative
                        source_locations: vec![filename.to_string()],
                        violation_impact: "Overflow can manipulate balances or bypass checks"
                            .to_string(),
                    },
                    evidence: vec![],
                    counterexample: Some("Unchecked arithmetic detected".to_string()),
                });
            }
        }
    }

    /// Mine state transition invariants
    fn mine_state_invariants(&mut self, file: &syn::File, filename: &str) {
        let code = quote::quote!(#file).to_string();

        // Pattern: initialized flag
        if code.contains("initialized") || code.contains("is_initialized") {
            self.discovered_invariants.push(MinedInvariant {
                invariant: Invariant {
                    id: format!("ST-{}", self.discovered_invariants.len() + 1),
                    category: InvariantCategory::StateTransition,
                    expression: "initialized: false -> true (one-way)".to_string(),
                    description: "Account initialization is irreversible".to_string(),
                    confidence: 0.85,
                    source_locations: vec![filename.to_string()],
                    violation_impact: "Reinitialization can reset account data or steal funds"
                        .to_string(),
                },
                evidence: vec![],
                counterexample: None,
            });
        }

        // Pattern: paused state
        if code.contains("paused") || code.contains("frozen") {
            self.discovered_invariants.push(MinedInvariant {
                invariant: Invariant {
                    id: format!("ST-{}", self.discovered_invariants.len() + 1),
                    category: InvariantCategory::StateTransition,
                    expression: "if paused then no_operations()".to_string(),
                    description: "Paused state must block all sensitive operations".to_string(),
                    confidence: 0.8,
                    source_locations: vec![filename.to_string()],
                    violation_impact: "Operations may proceed when protocol is halted".to_string(),
                },
                evidence: vec![],
                counterexample: None,
            });
        }
    }

    /// Get all discovered invariants
    pub fn get_invariants(&self) -> Vec<&Invariant> {
        self.discovered_invariants
            .iter()
            .map(|mi| &mi.invariant)
            .collect()
    }

    /// Get invariants with potential violations (counterexamples)
    pub fn get_potential_violations(&self) -> Vec<&MinedInvariant> {
        self.discovered_invariants
            .iter()
            .filter(|mi| mi.counterexample.is_some())
            .collect()
    }

    /// Export invariants in a format suitable for formal verification
    pub fn export_for_verification(&self) -> HashMap<String, String> {
        self.discovered_invariants
            .iter()
            .map(|mi| (mi.invariant.id.clone(), mi.invariant.expression.clone()))
            .collect()
    }
}

impl Default for InvariantMiner {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors during invariant mining
#[derive(Debug, thiserror::Error)]
pub enum MinerError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miner_creation() {
        let miner = InvariantMiner::new();
        assert!(miner.discovered_invariants.is_empty());
    }

    #[test]
    fn test_mine_balance_invariants() {
        let mut miner = InvariantMiner::new();
        let source = r#"
            pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
                let from = &mut ctx.accounts.from;
                let to = &mut ctx.accounts.to;
                from.balance -= amount;
                to.balance += amount;
                Ok(())
            }
        "#;

        let invariants = miner.mine_from_source(source, "test.rs").unwrap();
        assert!(!invariants.is_empty());
    }

    #[test]
    fn test_invariant_categories() {
        assert_ne!(
            InvariantCategory::BalanceConservation,
            InvariantCategory::AccessControl
        );
    }
}
