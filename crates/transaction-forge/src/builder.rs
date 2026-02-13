//! Exploit Transaction Builder
//!
//! Build instruction and transactions from exploit parameters.

use crate::{ExploitTransaction, ForgeError};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

pub struct TransactionBuilder {
    program_id: Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
}

impl TransactionBuilder {
    pub fn new(program_id: Pubkey) -> Self {
        Self {
            program_id,
            accounts: Vec::new(),
            data: Vec::new(),
        }
    }

    pub fn add_account(&mut self, pubkey: Pubkey, is_signer: bool, is_writable: bool) -> &mut Self {
        self.accounts.push(AccountMeta {
            pubkey,
            is_signer,
            is_writable,
        });
        self
    }

    pub fn set_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.data = data;
        self
    }

    pub fn build_instruction(&self) -> Instruction {
        Instruction {
            program_id: self.program_id,
            accounts: self.accounts.clone(),
            data: self.data.clone(),
        }
    }

    pub fn build_exploit_transaction(
        &self,
        payer: &Keypair,
        recent_blockhash: solana_sdk::hash::Hash,
    ) -> Result<ExploitTransaction, ForgeError> {
        let ix = self.build_instruction();
        let transaction = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[payer],
            recent_blockhash,
        );

        Ok(ExploitTransaction {
            transaction,
            description: "Generated exploit transaction".to_string(),
            target_instruction: "unknown".to_string(),
            accounts: self.accounts.clone(),
            data: self.data.clone(),
        })
    }
}
