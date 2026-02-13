use crate::builder::TransactionBuilder;
use crate::error::ForgeError;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

pub struct ExploitProofConverter;

impl ExploitProofConverter {
    pub fn new() -> Self {
        Self
    }

    /// Converts symbolic exploit parameters into a transaction builder
    pub fn convert_to_builder(
        &self,
        program_id: &str,
        instruction_data: &[u8],
        accounts: Vec<(String, bool, bool)>, // (pubkey_str, is_signer, is_writable)
    ) -> Result<TransactionBuilder, ForgeError> {
        let program_pubkey = Pubkey::from_str(program_id)
            .map_err(|e| ForgeError::ConversionFailed(e.to_string()))?;

        let mut builder = TransactionBuilder::new(program_pubkey);

        for (pk_str, is_signer, is_writable) in accounts {
            let pk = Pubkey::from_str(&pk_str)
                .map_err(|e| ForgeError::ConversionFailed(e.to_string()))?;
            builder.add_account(pk, is_signer, is_writable);
        }

        builder.set_data(instruction_data.to_vec());

        Ok(builder)
    }
}

impl Default for ExploitProofConverter {
    fn default() -> Self {
        Self::new()
    }
}
