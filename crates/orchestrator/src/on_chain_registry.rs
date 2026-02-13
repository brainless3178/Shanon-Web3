//! On-Chain Registry for Audit Results
//!
//! Registers vulnerability findings and exploit proofs on Solana devnet
//! for permanent, verifiable record-keeping. Supports querying audit history
//! and exploit reports by program ID via getProgramAccounts with memcmp filters.

use serde::{Deserialize, Serialize};
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
    rpc_filter::{Memcmp, RpcFilterType},
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;
use tracing::info;

/// Registry configuration
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub rpc_url: String,
    pub registry_program_id: String,
    pub commitment: CommitmentConfig,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.devnet.solana.com".to_string(),
            registry_program_id: "4cb3bZbBbXUxX6Ky4FFsEZEUBPe4TaRhvBEyuV9En6Zq".to_string(),
            commitment: CommitmentConfig::confirmed(),
        }
    }
}

/// A registered exploit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitEntry {
    pub id: String,
    pub program_id: String,
    pub vulnerability_type: String,
    pub severity: u8,
    pub finder: String,
    pub timestamp: i64,
    pub proof_hash: String,
    pub tx_signature: Option<String>,
}

/// A registered audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub program_id: String,
    pub auditor: String,
    pub findings_count: u32,
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub report_hash: String,
    pub timestamp: i64,
    pub tx_signature: Option<String>,
}

/// Main on-chain registry client
pub struct OnChainRegistry {
    client: RpcClient,
    config: RegistryConfig,
    payer: Option<Keypair>,
}

impl OnChainRegistry {
    /// Create a new registry client
    pub fn new(config: RegistryConfig) -> Self {
        let client = RpcClient::new_with_commitment(config.rpc_url.clone(), config.commitment);

        Self {
            client,
            config,
            payer: None,
        }
    }

    /// Create with default devnet configuration
    pub fn devnet() -> Self {
        Self::new(RegistryConfig::default())
    }

    /// Set the payer keypair for transactions
    pub fn with_payer(mut self, payer: Keypair) -> Self {
        self.payer = Some(payer);
        self
    }

    /// Register an exploit finding on-chain
    pub async fn register_exploit(
        &self,
        program_id: &str,
        vulnerability_type: &str,
        severity: u8,
        proof_data: &[u8],
    ) -> Result<String, RegistryError> {
        let payer = self.payer.as_ref().ok_or(RegistryError::NoPayer)?;

        // Create a hash of the proof data
        let proof_hash = self.hash_data(proof_data);

        // Build instruction data
        let mut instruction_data = vec![0x01]; // RegisterExploit discriminator
        instruction_data.extend_from_slice(&severity.to_le_bytes());
        instruction_data.extend_from_slice(proof_hash.as_bytes());
        instruction_data.extend_from_slice(vulnerability_type.as_bytes());

        // Create the registry PDA for this finding
        let registry_program = Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let target_program = Pubkey::from_str(program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        let (pda, _bump) = Pubkey::find_program_address(
            &[b"exploit", target_program.as_ref(), proof_hash.as_bytes()],
            &registry_program,
        );

        let accounts = vec![
            AccountMeta::new(payer.pubkey(), true), // Payer/finder
            AccountMeta::new(pda, false),           // Exploit record PDA
            AccountMeta::new_readonly(target_program, false), // Target program
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id: registry_program,
            accounts,
            data: instruction_data,
        };

        let recent_blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        let message = Message::new(&[instruction], Some(&payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[payer], recent_blockhash);

        // SEND AND CONFIRM: Real ledger interaction
        match self.client.send_and_confirm_transaction(&transaction) {
            Ok(sig) => Ok(sig.to_string()),
            Err(e) => Err(RegistryError::RpcError(format!(
                "Live ledger registration failed: {}",
                e
            ))),
        }
    }

    /// Register a complete audit on-chain
    #[allow(clippy::too_many_arguments)]
    pub async fn register_audit(
        &self,
        program_id: &str,
        findings_count: u32,
        critical_count: u32,
        high_count: u32,
        medium_count: u32,
        low_count: u32,
        report_data: &[u8],
    ) -> Result<AuditEntry, RegistryError> {
        let payer = self.payer.as_ref().ok_or(RegistryError::NoPayer)?;

        let report_hash = self.hash_data(report_data);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Build instruction data
        let mut instruction_data = vec![0x02]; // RegisterAudit discriminator
        instruction_data.extend_from_slice(&findings_count.to_le_bytes());
        instruction_data.extend_from_slice(&critical_count.to_le_bytes());
        instruction_data.extend_from_slice(&high_count.to_le_bytes());
        instruction_data.extend_from_slice(&medium_count.to_le_bytes());
        instruction_data.extend_from_slice(&low_count.to_le_bytes());
        instruction_data.extend_from_slice(report_hash.as_bytes());

        let registry_program = Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let target_program = Pubkey::from_str(program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        let (pda, _bump) = Pubkey::find_program_address(
            &[b"audit", target_program.as_ref(), &timestamp.to_le_bytes()],
            &registry_program,
        );

        let accounts = vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(target_program, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id: registry_program,
            accounts,
            data: instruction_data,
        };

        // Create and simulate transaction
        let recent_blockhash = self
            .client
            .get_latest_blockhash()
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        let message = Message::new(&[instruction], Some(&payer.pubkey()));
        let mut transaction = Transaction::new_unsigned(message);
        transaction.sign(&[payer], recent_blockhash);

        let tx_signature = match self.client.send_and_confirm_transaction(&transaction) {
            Ok(sig) => Some(sig.to_string()),
            Err(_) => None,
        };

        Ok(AuditEntry {
            id: format!("audit_{}_{}", program_id, timestamp),
            program_id: program_id.to_string(),
            auditor: payer.pubkey().to_string(),
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            report_hash,
            timestamp,
            tx_signature,
        })
    }

    /// Query audit history for a program via getProgramAccounts.
    /// Filters AuditSummary accounts where the stored program_id matches.
    pub async fn get_audit_history(
        &self,
        program_id: &str,
    ) -> Result<Vec<AuditEntry>, RegistryError> {
        let registry_program = Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let target = Pubkey::from_str(program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        // AuditSummary discriminator: SHA-256("account:AuditSummary")[..8]
        let discriminator = anchor_discriminator("AuditSummary");

        // Filter: discriminator at offset 0 AND program_id at offset 8
        let filters = vec![
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(0, &discriminator)),
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(8, target.as_ref())),
        ];

        let config = RpcProgramAccountsConfig {
            filters: Some(filters),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(self.config.commitment),
                ..Default::default()
            },
            with_context: Some(false),
        };

        let accounts = self
            .client
            .get_program_accounts_with_config(&registry_program, config)
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        info!(
            "Found {} AuditSummary accounts for {}",
            accounts.len(),
            program_id
        );

        let mut entries = Vec::new();
        for (pubkey, account) in accounts {
            if let Some(entry) = parse_audit_summary(&account.data, program_id, &pubkey.to_string()) {
                entries.push(entry);
            }
        }

        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(entries)
    }

    /// Query exploit reports for a program via getProgramAccounts.
    /// Filters ExploitProfile accounts where the stored program_id matches.
    pub async fn get_exploit_reports(
        &self,
        program_id: &str,
    ) -> Result<Vec<ExploitEntry>, RegistryError> {
        let registry_program = Pubkey::from_str(&self.config.registry_program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;
        let target = Pubkey::from_str(program_id)
            .map_err(|e| RegistryError::InvalidPubkey(e.to_string()))?;

        // ExploitProfile discriminator: SHA-256("account:ExploitProfile")[..8]
        let discriminator = anchor_discriminator("ExploitProfile");

        let filters = vec![
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(0, &discriminator)),
            RpcFilterType::Memcmp(Memcmp::new_base58_encoded(8, target.as_ref())),
        ];

        let config = RpcProgramAccountsConfig {
            filters: Some(filters),
            account_config: RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(self.config.commitment),
                ..Default::default()
            },
            with_context: Some(false),
        };

        let accounts = self
            .client
            .get_program_accounts_with_config(&registry_program, config)
            .map_err(|e| RegistryError::RpcError(e.to_string()))?;

        info!(
            "Found {} ExploitProfile accounts for {}",
            accounts.len(),
            program_id
        );

        let mut entries = Vec::new();
        for (pubkey, account) in accounts {
            if let Some(entry) = parse_exploit_profile(&account.data, program_id, &pubkey.to_string()) {
                entries.push(entry);
            }
        }

        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(entries)
    }

    /// Check if a program has any on-chain audit records.
    pub async fn has_audit_records(&self, program_id: &str) -> Result<bool, RegistryError> {
        let exploits = self.get_exploit_reports(program_id).await?;
        let audits = self.get_audit_history(program_id).await?;
        Ok(!exploits.is_empty() || !audits.is_empty())
    }

    /// Get the latest security score for a program (from the most recent audit).
    /// Returns None if the program has never been audited.
    pub async fn get_security_score(&self, program_id: &str) -> Result<Option<u8>, RegistryError> {
        let audits = self.get_audit_history(program_id).await?;
        Ok(audits.first().map(|a| {
            // Derive score from severity counts if not stored directly
            let score = 100u32
                .saturating_sub(a.critical_count * 25)
                .saturating_sub(a.high_count * 15)
                .saturating_sub(a.medium_count * 5)
                .saturating_sub(a.low_count * 1);
            score.min(100) as u8
        }))
    }

    pub async fn verify_exploit_registration(
        &self,
        tx_signature: &str,
    ) -> Result<bool, RegistryError> {
        // Validation of transaction signature on-chain
        let sig = solana_sdk::signature::Signature::from_str(tx_signature)
            .map_err(|e| RegistryError::InvalidSignature(e.to_string()))?;

        match self.client.get_signature_status(&sig) {
            Ok(Some(status)) => Ok(status.is_ok()),
            Ok(None) => Ok(false),
            Err(e) => Err(RegistryError::RpcError(e.to_string())),
        }
    }

    /// Helper to hash data
    fn hash_data(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

/// Compute the 8-byte Anchor account discriminator for a given type name.
/// Anchor uses SHA-256("account:<TypeName>")[..8].
fn anchor_discriminator(type_name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("account:{}", type_name).as_bytes());
    let hash = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

/// Parse an ExploitProfile from raw Anchor account data.
/// Layout: [8 disc][32 program_id][32 reporter][8 timestamp][1 severity][4+N vuln_type][32 proof_hash][4+N metadata_url][1 bump]
fn parse_exploit_profile(data: &[u8], program_id: &str, pda: &str) -> Option<ExploitEntry> {
    if data.len() < 8 + 32 + 32 + 8 + 1 {
        return None;
    }
    let mut offset = 8; // skip discriminator

    // program_id (32 bytes) — skip, we already filtered
    offset += 32;

    // reporter (32 bytes)
    let reporter = Pubkey::try_from(&data[offset..offset + 32]).ok()?;
    offset += 32;

    // timestamp (i64 LE)
    let timestamp = i64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    // severity (u8)
    let severity = data[offset];
    offset += 1;

    // vulnerability_type (borsh String: 4-byte len + utf8)
    let vuln_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;
    let vulnerability_type = if offset + vuln_len <= data.len() {
        String::from_utf8_lossy(&data[offset..offset + vuln_len]).to_string()
    } else {
        return None;
    };
    offset += vuln_len;

    // proof_hash (32 bytes)
    let proof_hash_bytes = if offset + 32 <= data.len() {
        &data[offset..offset + 32]
    } else {
        return None;
    };
    let proof_hash = bytes_to_hex(proof_hash_bytes);

    Some(ExploitEntry {
        id: format!("exploit_{}", &pda[..8.min(pda.len())]),
        program_id: program_id.to_string(),
        vulnerability_type,
        severity,
        finder: reporter.to_string(),
        timestamp,
        proof_hash,
        tx_signature: None,
    })
}

/// Parse an AuditSummary from raw Anchor account data.
/// Layout: [8 disc][32 program_id][32 auditor][8 timestamp][4 findings][4 crit][4 high][4 med][4 low][1 score][32 report_hash][4+N report_url][1 bump]
fn parse_audit_summary(data: &[u8], program_id: &str, pda: &str) -> Option<AuditEntry> {
    if data.len() < 8 + 32 + 32 + 8 + 20 + 1 + 32 {
        return None;
    }
    let mut offset = 8; // skip discriminator

    // program_id (32) — skip
    offset += 32;

    // auditor (32)
    let auditor = Pubkey::try_from(&data[offset..offset + 32]).ok()?;
    offset += 32;

    // timestamp (i64)
    let timestamp = i64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    // findings_count, critical_count, high_count, medium_count, low_count (each u32)
    let findings_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;
    let critical_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;
    let high_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;
    let medium_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;
    let low_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    // security_score (u8)
    let _security_score = data[offset];
    offset += 1;

    // report_hash (32 bytes)
    let report_hash = if offset + 32 <= data.len() {
        bytes_to_hex(&data[offset..offset + 32])
    } else {
        String::new()
    };

    Some(AuditEntry {
        id: format!("audit_{}", &pda[..8.min(pda.len())]),
        program_id: program_id.to_string(),
        auditor: auditor.to_string(),
        findings_count,
        critical_count,
        high_count,
        medium_count,
        low_count,
        report_hash,
        timestamp,
        tx_signature: None,
    })
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Registry errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("No payer keypair set")]
    NoPayer,
    #[error("Invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Not found: {0}")]
    NotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = OnChainRegistry::devnet();
        assert!(registry.payer.is_none());
    }

    #[test]
    fn test_config_defaults() {
        let config = RegistryConfig::default();
        assert!(config.rpc_url.contains("devnet"));
        assert_eq!(
            config.registry_program_id,
            "4cb3bZbBbXUxX6Ky4FFsEZEUBPe4TaRhvBEyuV9En6Zq"
        );
    }

    #[test]
    fn test_anchor_discriminator() {
        let disc = anchor_discriminator("ExploitProfile");
        assert_eq!(disc.len(), 8);
        // Discriminator should be deterministic
        assert_eq!(disc, anchor_discriminator("ExploitProfile"));
        // Different type names should produce different discriminators
        assert_ne!(disc, anchor_discriminator("AuditSummary"));
    }

    #[test]
    fn test_parse_exploit_profile_too_short() {
        // Data shorter than minimum should return None
        assert!(parse_exploit_profile(&[0u8; 40], "test", "pda").is_none());
    }

    #[test]
    fn test_parse_audit_summary_too_short() {
        assert!(parse_audit_summary(&[0u8; 40], "test", "pda").is_none());
    }
}
