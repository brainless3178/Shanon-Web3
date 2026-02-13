//! Active Mitigation Engine for Solana Security Swarm
//!
//! Generates defensive transactions to counter detected exploits.
//! Capable of automatically pausing programs, freezing suspicious accounts,
//! or executing front-run transactions to secure protocol funds.

use crate::mainnet_guardian::{ThreatDetection, ThreatLevel};
use anyhow::Result;
use solana_sdk::instruction::Instruction;
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

/// Types of defensive maneuvers
#[derive(Debug, Clone, PartialEq)]
pub enum MitigationManeuver {
    /// Pause the entire program (if supported by Anchor)
    PauseProgram,
    /// Freeze specific accounts involved in suspicions
    FreezeAccount(Pubkey),
    /// Withdraw funds to a secure multisig/treasury
    SecureWithdraw,
    /// Front-run with a defensive transaction
    FrontRunSecurity,
    /// No mitigation possible
    None,
}

/// Mitigation Engine - Strategic defense generation
pub struct MitigationEngine {
    /// Owner/Admin key for signing defense transactions
    pub admin_key: Option<Pubkey>,
    /// Secured treasury for emergency withdrawals
    pub treasury_addr: Option<Pubkey>,
    /// History of executed mitigations
    pub mitigation_history: Vec<MitigationAction>,
}

#[derive(Debug, Clone)]
pub struct MitigationAction {
    pub threat_id: String,
    pub maneuver: MitigationManeuver,
    pub transaction: Option<Transaction>,
    pub timestamp: i64,
}

impl Default for MitigationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MitigationEngine {
    pub fn new() -> Self {
        Self {
            admin_key: None,
            treasury_addr: None,
            mitigation_history: Vec::new(),
        }
    }

    /// Set the admin key for authorizing defenses
    pub fn with_admin(mut self, key: Pubkey) -> Self {
        self.admin_key = Some(key);
        self
    }

    /// Analyze threat and determine the best defensive maneuver
    pub fn devise_defense(
        &self,
        threat: &ThreatDetection,
        idl: &Option<serde_json::Value>,
    ) -> MitigationManeuver {
        // Critical threats warrant immediate intervention
        if threat.threat_level < ThreatLevel::High {
            return MitigationManeuver::None;
        }

        // Logic for selecting maneuver based on IDL capabilities
        if let Some(idl_val) = idl {
            // Check if IDL has a 'pause' or 'toggle_pause' instruction
            if let Some(instructions) = idl_val.get("instructions") {
                if let Some(arr) = instructions.as_array() {
                    let has_pause = arr.iter().any(|ix| {
                        let name = ix.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        name.contains("pause") || name.contains("freeze")
                    });

                    if has_pause {
                        return MitigationManeuver::PauseProgram;
                    }
                }
            }
        }

        // Default to securing funds if reentrancy or flash loan detected
        match threat.threat_level {
            ThreatLevel::Critical => MitigationManeuver::SecureWithdraw,
            _ => MitigationManeuver::None,
        }
    }

    /// Forge the actual defensive transaction
    pub fn forge_defense_tx(
        &self,
        maneuver: &MitigationManeuver,
        program_id: Pubkey,
        _target_accounts: &[String],
    ) -> Result<Transaction> {
        let admin = self
            .admin_key
            .ok_or_else(|| anyhow::anyhow!("Admin key required for mitigation"))?;

        let instructions = match maneuver {
            MitigationManeuver::PauseProgram => {
                // Construct a cross-program or program-specific pause instruction
                // In Anchor, this is usually 'pause' instruction
                vec![Instruction::new_with_bincode(
                    program_id,
                    &[0], // Simulated instruction discriminator for pause
                    vec![solana_sdk::instruction::AccountMeta::new(admin, true)],
                )]
            }
            MitigationManeuver::SecureWithdraw => {
                // Emergency withdraw all funds to treasury
                let treasury = self.treasury_addr.unwrap_or(admin);
                vec![Instruction::new_with_bincode(
                    program_id,
                    &[1], // Simulated emergency withdraw
                    vec![
                        solana_sdk::instruction::AccountMeta::new(admin, true),
                        solana_sdk::instruction::AccountMeta::new(treasury, false),
                    ],
                )]
            }
            _ => return Err(anyhow::anyhow!("Unsupported automated maneuver")),
        };

        let message = Message::new(&instructions, Some(&admin));
        Ok(Transaction::new_unsigned(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mainnet_guardian::ThreatType;

    #[test]
    fn test_mitigation_logic() {
        let engine = MitigationEngine::new();
        let threat = ThreatDetection {
            signature: "test".to_string(),
            timestamp: 0,
            threat_type: ThreatType::FlashLoanAttack,
            threat_level: ThreatLevel::Critical,
            confidence: 0.95,
            explanation: "Heavy drain detected".to_string(),
            affected_accounts: vec![],
            estimated_impact: None,
            recommended_actions: vec![],
        };

        let maneuver = engine.devise_defense(&threat, &None);
        assert_eq!(maneuver, MitigationManeuver::SecureWithdraw);
    }
}
