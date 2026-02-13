//! Hardened vault implementation demonstrating secure patterns.
//!
//! Security measures applied:
//!   - Minimum first deposit prevents share-inflation attacks (SOL-019 mitigation)
//!   - checked_mul/checked_div prevent arithmetic overflow
//!   - Withdraw executes CPI transfer via PDA signer seeds
//!   - Event emission for off-chain monitoring

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[account]
pub struct SecureVault {
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub total_shares: u64,
    pub total_assets: u64,
    pub bump: u8,
}

impl SecureVault {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 1;
}

#[account]
pub struct UserShares {
    pub owner: Pubkey,
    pub shares: u64,
    pub bump: u8,
}

impl UserShares {
    pub const LEN: usize = 8 + 32 + 8 + 1;
}

/// Minimum first deposit to prevent share-inflation attacks.
/// At 0.001 SOL the cost of inflating share price is prohibitively
/// expensive relative to potential profit.
pub const MIN_FIRST_DEPOSIT: u64 = 1_000_000;

// ── Events ──────────────────────────────────────────────────────────

#[event]
pub struct DepositEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub shares_minted: u64,
    pub vault_total_assets: u64,
    pub vault_total_shares: u64,
}

#[event]
pub struct WithdrawEvent {
    pub user: Pubkey,
    pub shares_burned: u64,
    pub amount_returned: u64,
    pub vault_total_assets: u64,
    pub vault_total_shares: u64,
}

// ── Handlers ────────────────────────────────────────────────────────

pub fn handle_initialize_vault<'info>(
    vault: &mut Account<'info, SecureVault>,
    admin: Pubkey,
    mint: Pubkey,
    bump: u8,
) -> Result<()> {
    vault.admin = admin;
    vault.mint = mint;
    vault.total_shares = 0;
    vault.total_assets = 0;
    vault.bump = bump;
    Ok(())
}

pub fn handle_initialize_user_shares<'info>(
    user_shares: &mut Account<'info, UserShares>,
    user: &Signer<'info>,
    bump: u8,
) -> Result<()> {
    user_shares.owner = *user.key;
    user_shares.shares = 0;
    user_shares.bump = bump;
    Ok(())
}

pub fn handle_deposit<'info>(
    vault: &mut Account<'info, SecureVault>,
    user_shares: &mut Account<'info, UserShares>,
    user_token: &Account<'info, TokenAccount>,
    vault_token: &Account<'info, TokenAccount>,
    user: &Signer<'info>,
    token_program: &Program<'info, Token>,
    amount: u64,
) -> Result<u64> {
    let shares = if vault.total_shares == 0 {
        // First deposit must meet minimum to prevent inflation attacks
        require!(amount >= MIN_FIRST_DEPOSIT, ErrorCode::FirstDepositTooSmall);
        amount
    } else {
        amount
            .checked_mul(vault.total_shares)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_div(vault.total_assets)
            .ok_or(ErrorCode::MathOverflow)?
    };

    require!(shares > 0, ErrorCode::ZeroShares);

    let cpi_accounts = Transfer {
        from: user_token.to_account_info(),
        to: vault_token.to_account_info(),
        authority: user.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi_ctx, amount)?;

    user_shares.shares = user_shares.shares
        .checked_add(shares)
        .ok_or(ErrorCode::MathOverflow)?;
    vault.total_shares = vault.total_shares
        .checked_add(shares)
        .ok_or(ErrorCode::MathOverflow)?;
    vault.total_assets = vault.total_assets
        .checked_add(amount)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(DepositEvent {
        user: *user.key,
        amount,
        shares_minted: shares,
        vault_total_assets: vault.total_assets,
        vault_total_shares: vault.total_shares,
    });

    Ok(shares)
}

pub fn handle_withdraw<'info>(
    vault: &mut Account<'info, SecureVault>,
    user_shares: &mut Account<'info, UserShares>,
    user_token: &Account<'info, TokenAccount>,
    vault_token: &Account<'info, TokenAccount>,
    user: &Signer<'info>,
    token_program: &Program<'info, Token>,
    shares: u64,
) -> Result<u64> {
    require!(
        user_shares.shares >= shares,
        ErrorCode::InsufficientShares
    );

    let amount = shares
        .checked_mul(vault.total_assets)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(vault.total_shares)
        .ok_or(ErrorCode::MathOverflow)?;

    require!(amount > 0, ErrorCode::ZeroWithdraw);

    // Transfer tokens from vault back to user via PDA signing
    let vault_seeds: &[&[u8]] = &[b"vault", &[vault.bump]];
    let signer_seeds = &[vault_seeds];

    let cpi_accounts = Transfer {
        from: vault_token.to_account_info(),
        to: user_token.to_account_info(),
        authority: vault.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );
    token::transfer(cpi_ctx, amount)?;

    user_shares.shares = user_shares.shares
        .checked_sub(shares)
        .ok_or(ErrorCode::MathOverflow)?;
    vault.total_shares = vault.total_shares
        .checked_sub(shares)
        .ok_or(ErrorCode::MathOverflow)?;
    vault.total_assets = vault.total_assets
        .checked_sub(amount)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(WithdrawEvent {
        user: *user.key,
        shares_burned: shares,
        amount_returned: amount,
        vault_total_assets: vault.total_assets,
        vault_total_shares: vault.total_shares,
    });

    Ok(amount)
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient shares")]
    InsufficientShares,
    #[msg("First deposit must be >= MIN_FIRST_DEPOSIT to prevent share inflation attack")]
    FirstDepositTooSmall,
    #[msg("Arithmetic overflow")]
    MathOverflow,
    #[msg("Zero shares minted — deposit too small relative to vault size")]
    ZeroShares,
    #[msg("Zero withdraw — shares too small relative to vault size")]
    ZeroWithdraw,
}
