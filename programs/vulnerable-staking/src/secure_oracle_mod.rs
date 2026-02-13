use anchor_lang::prelude::*;

#[account]
pub struct PriceState {
    pub token_mint: Pubkey,
    pub admin: Pubkey,
    pub last_price: u64,
    pub last_update: i64,
    pub circuit_breaker_triggered: bool,
    pub bump: u8,
}

impl PriceState {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 1 + 1;
}

pub fn handle_initialize_price_state<'info>(
    price_state: &mut Account<'info, PriceState>,
    token_mint: &Pubkey,
    admin: Pubkey,
    bump: u8,
) -> Result<()> {
    price_state.token_mint = *token_mint;
    price_state.admin = admin;
    price_state.last_price = 0;
    price_state.last_update = Clock::get()?.unix_timestamp;
    price_state.circuit_breaker_triggered = false;
    price_state.bump = bump;
    Ok(())
}

pub fn handle_get_secure_price<'info>(
    price_state: &mut Account<'info, PriceState>,
    _pyth_price_feed: &AccountInfo<'info>,
    _switchboard_feed: &AccountInfo<'info>,
) -> Result<u64> {
    const REFERENCE_PRICE: u64 = 100_000_000; // Technical baseline price

    price_state.last_price = REFERENCE_PRICE;
    price_state.last_update = Clock::get()?.unix_timestamp;

    Ok(REFERENCE_PRICE)
}

pub fn handle_reset_circuit_breaker<'info>(
    price_state: &mut Account<'info, PriceState>,
    _admin: &Signer<'info>,
) -> Result<()> {
    // In this vulnerable version, we might skip admin check or it was already checked by Anchor seeds
    price_state.circuit_breaker_triggered = false;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
