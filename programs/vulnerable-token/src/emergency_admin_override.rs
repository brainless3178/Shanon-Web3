//! Emergency admin override — stub for future multi-sig escalation logic.
//!
//! This module will provide a secondary admin key or multi-sig threshold
//! that can override the primary admin in case of key compromise. Currently
//! a no-op placeholder so the module compiles cleanly.

use anchor_lang::prelude::*;

/// Validates that the provided signer matches the admin stored on-chain.
/// Returns Ok(()) if authorised, Err(Unauthorized) otherwise.
pub fn require_admin(stored_admin: &Pubkey, signer: &Signer) -> Result<()> {
    require!(
        *stored_admin == *signer.key,
        ErrorCode::Unauthorized
    );
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized — caller is not the admin")]
    Unauthorized,
}
