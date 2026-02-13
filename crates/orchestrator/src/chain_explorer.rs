use anyhow::Result;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkStats {
    pub tps: f64,
    pub slot: u64,
    pub block_height: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountOverview {
    pub pubkey: String,
    pub lamports: u64,
    pub sol_balance: f64,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
    pub data_len: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransactionDetail {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub status: String,
    pub fee: u64,
    pub logs: Vec<String>,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
}

pub struct ChainExplorer {
    client: RpcClient,
}

impl ChainExplorer {
    pub fn new(rpc_url: String) -> Self {
        Self {
            client: RpcClient::new(rpc_url),
        }
    }

    /// Fetch real-time network performance samples to calculate TPS
    pub fn fetch_network_stats(&self) -> Result<NetworkStats> {
        let samples = self.client.get_recent_performance_samples(Some(1))?;
        let tps = if let Some(sample) = samples.first() {
            if sample.sample_period_secs > 0 {
                sample.num_transactions as f64 / sample.sample_period_secs as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        let slot = self.client.get_slot()?;
        let block_height = self.client.get_block_height()?;

        Ok(NetworkStats {
            tps,
            slot,
            block_height,
        })
    }

    /// Detailed lookup of an account
    pub fn inspect_account(&self, pubkey_str: &str) -> Result<AccountOverview> {
        let pubkey = Pubkey::from_str(pubkey_str)?;
        let account = self.client.get_account(&pubkey)?;

        Ok(AccountOverview {
            pubkey: pubkey_str.to_string(),
            lamports: account.lamports,
            sol_balance: account.lamports as f64 / 1_000_000_000.0,
            owner: account.owner.to_string(),
            executable: account.executable,
            rent_epoch: account.rent_epoch,
            data_len: account.data.len(),
        })
    }

    /// Detailed lookup of a transaction by signature
    pub fn inspect_transaction(&self, sig_str: &str) -> Result<TransactionDetail> {
        let signature = Signature::from_str(sig_str)?;
        let tx = self
            .client
            .get_transaction(&signature, UiTransactionEncoding::JsonParsed)?;

        let meta = tx.transaction.meta.as_ref();
        let status = if let Some(m) = meta {
            if m.err.is_none() {
                "Success".to_string()
            } else {
                format!("Error: {:?}", m.err)
            }
        } else {
            "Unknown".to_string()
        };

        let logs: Vec<String> = meta
            .and_then(|m| m.log_messages.clone().into())
            .unwrap_or_default();
        let fee = meta.map(|m| m.fee).unwrap_or(0);
        let pre_balances: Vec<u64> = meta
            .and_then(|m| m.pre_balances.clone().into())
            .unwrap_or_default();
        let post_balances: Vec<u64> = meta
            .and_then(|m| m.post_balances.clone().into())
            .unwrap_or_default();

        Ok(TransactionDetail {
            signature: sig_str.to_string(),
            slot: tx.slot,
            block_time: tx.block_time,
            status,
            fee,
            logs,
            pre_balances,
            post_balances,
        })
    }
}
