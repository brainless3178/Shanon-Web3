//! Transaction Forge - Exploit Transaction Generation
//!
//! Converts symbolic exploit proofs into real, executable Solana transactions.

use serde::{Deserialize, Serialize};
use solana_sdk::{instruction::AccountMeta, transaction::Transaction};

pub mod builder;
pub mod error;
pub mod executor;
pub mod proof_generator;

pub use builder::TransactionBuilder;
pub use error::ForgeError;
pub use executor::ExploitExecutor;
pub use proof_generator::ExploitProofConverter;

/// A generated exploit transaction
#[derive(Debug, Clone)]
pub struct ExploitTransaction {
    pub transaction: Transaction,
    pub description: String,
    pub target_instruction: String,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Types of vulnerabilities for transaction forging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityType {
    MissingOwnerCheck,
    IntegerOverflow,
    ArbitraryCPI,
    Reentrancy,
    OracleManipulation,
    AccountConfusion,
    UninitializedData,
    MissingSignerCheck,
}

/// Configuration for transaction generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    pub rpc_url: String,
    pub commitment: String,
    pub payer_keypair_path: String,
    pub compute_budget: u32,
    pub simulate_only: bool,
    pub max_retries: usize,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.devnet.solana.com".to_string(),
            commitment: "confirmed".to_string(),
            payer_keypair_path: "~/.config/solana/id.json".to_string(),
            compute_budget: 200_000,
            simulate_only: true,
            max_retries: 3,
        }
    }
}
