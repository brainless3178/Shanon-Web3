//! Hardened MEV-resistant swap module with proper AMM math.
//!
//! Security measures applied:
//!   - Constant-product AMM (x * y = k) instead of 1:1 swap
//!   - Deadline enforcement prevents stale-transaction attacks
//!   - Slippage protection via min_out
//!   - Per-slot swap limit as crude sandwich-attack mitigation
//!   - Output tokens actually transferred to user

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

#[account]
pub struct ProtectedPool {
    pub mint_in: Pubkey,
    pub mint_out: Pubkey,
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub last_slot: u64,
    pub swaps_this_slot: u8,
    pub bump: u8,
}

impl ProtectedPool {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 8 + 1 + 1;
}

/// Max swaps per slot — crude rate limit to increase sandwich cost
const MAX_SWAPS_PER_SLOT: u8 = 3;

/// Swap fee in basis points (0.30%)
const FEE_BPS: u64 = 30;

// -- Events ----------------------------------------------------------

#[event]
pub struct SwapEvent {
    pub user: Pubkey,
    pub amount_in: u64,
    pub amount_out: u64,
    pub reserve_in_after: u64,
    pub reserve_out_after: u64,
}

// -- Handlers --------------------------------------------------------

pub fn handle_initialize_pool<'info>(
    pool: &mut Account<'info, ProtectedPool>,
    mint_in: &Account<'info, Mint>,
    mint_out: &Account<'info, Mint>,
    initial_reserve_in: u64,
    initial_reserve_out: u64,
    bump: u8,
) -> Result<()> {
    require!(
        initial_reserve_in > 0 && initial_reserve_out > 0,
        ErrorCode::ZeroReserve
    );
    pool.mint_in = mint_in.key();
    pool.mint_out = mint_out.key();
    pool.reserve_in = initial_reserve_in;
    pool.reserve_out = initial_reserve_out;
    pool.last_slot = Clock::get()?.slot;
    pool.swaps_this_slot = 0;
    pool.bump = bump;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_swap_with_protection<'info>(
    pool: &mut Account<'info, ProtectedPool>,
    user_source: &Account<'info, TokenAccount>,
    user_destination: &Account<'info, TokenAccount>,
    pool_source: &Account<'info, TokenAccount>,
    pool_token_out: &Account<'info, TokenAccount>,
    user: &Signer<'info>,
    token_program: &Program<'info, Token>,
    amount_in: u64,
    min_out: u64,
    deadline: i64,
) -> Result<u64> {
    // Deadline enforcement
    let now = Clock::get()?;
    require!(now.unix_timestamp <= deadline, ErrorCode::DeadlineExceeded);

    // Per-slot rate limit
    let current_slot = now.slot;
    if current_slot == pool.last_slot {
        require!(
            pool.swaps_this_slot < MAX_SWAPS_PER_SLOT,
            ErrorCode::SlotLimitExceeded
        );
        pool.swaps_this_slot += 1;
    } else {
        pool.swaps_this_slot = 1;
    }

    // Constant-product AMM: amount_out = (reserve_out * amount_in_after_fee) / (reserve_in + amount_in_after_fee)
    let amount_in_after_fee = amount_in
        .checked_mul(10_000 - FEE_BPS)
        .ok_or(ErrorCode::MathOverflow)?
        / 10_000;

    let numerator = pool
        .reserve_out
        .checked_mul(amount_in_after_fee)
        .ok_or(ErrorCode::MathOverflow)?;
    let denominator = pool
        .reserve_in
        .checked_add(amount_in_after_fee)
        .ok_or(ErrorCode::MathOverflow)?;

    let amount_out = numerator
        .checked_div(denominator)
        .ok_or(ErrorCode::MathOverflow)?;

    // Slippage protection
    require!(amount_out >= min_out, ErrorCode::SlippageExceeded);
    require!(amount_out > 0, ErrorCode::ZeroOutput);

    // Transfer tokens in from user
    let cpi_in = Transfer {
        from: user_source.to_account_info(),
        to: pool_source.to_account_info(),
        authority: user.to_account_info(),
    };
    token::transfer(
        CpiContext::new(token_program.to_account_info(), cpi_in),
        amount_in,
    )?;

    // Transfer tokens out to user via PDA signing
    let pool_seeds: &[&[u8]] = &[b"pool", &[pool.bump]];
    let signer_seeds = &[pool_seeds];

    let cpi_out = Transfer {
        from: pool_token_out.to_account_info(),
        to: user_destination.to_account_info(),
        authority: pool.to_account_info(),
    };
    token::transfer(
        CpiContext::new_with_signer(
            token_program.to_account_info(),
            cpi_out,
            signer_seeds,
        ),
        amount_out,
    )?;

    // Update reserves
    pool.reserve_in = pool
        .reserve_in
        .checked_add(amount_in)
        .ok_or(ErrorCode::MathOverflow)?;
    pool.reserve_out = pool
        .reserve_out
        .checked_sub(amount_out)
        .ok_or(ErrorCode::MathOverflow)?;
    pool.last_slot = current_slot;

    emit!(SwapEvent {
        user: *user.key,
        amount_in,
        amount_out,
        reserve_in_after: pool.reserve_in,
        reserve_out_after: pool.reserve_out,
    });

    Ok(amount_out)
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Deadline exceeded — transaction is stale")]
    DeadlineExceeded,
    #[msg("Slippage exceeded — output less than min_out")]
    SlippageExceeded,
    #[msg("Arithmetic overflow")]
    MathOverflow,
    #[msg("Zero output amount")]
    ZeroOutput,
    #[msg("Reserves must be non-zero")]
    ZeroReserve,
    #[msg("Max swaps per slot exceeded — try next slot")]
    SlotLimitExceeded,
}
