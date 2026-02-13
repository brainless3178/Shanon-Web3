use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

// secure_vault.rs - Refactored as library module

/// Minimum dead shares to prevent share price manipulation
pub const INITIAL_DEAD_SHARES: u64 = 1_000_000;

/// Minimum deposit to prevent dust attacks
pub const MINIMUM_DEPOSIT: u64 = 1000;

/// Address where dead shares are "burned" (unrecoverable PDA)
pub const DEAD_SHARES_SEED: &[u8] = b"dead_shares";

// Instruction functions

// Instruction functions

/// Initialize a secure vault with first-deposit protection
pub fn handle_initialize_vault<'info>(
    vault: &mut Account<'info, SecureVault>,
    admin: Pubkey,
    mint: Pubkey,
    bump: u8,
) -> Result<()> {
    vault.admin = admin;
    vault.mint = mint;
    vault.total_shares = INITIAL_DEAD_SHARES;
    vault.total_assets = 0;
    vault.dead_shares = INITIAL_DEAD_SHARES;
    vault.is_initialized = true;
    vault.bump = bump;

    msg!(
        "Vault initialized for mint {} with admin {}",
        vault.mint,
        vault.admin
    );

    emit!(VaultInitializedEvent {
        dead_shares: INITIAL_DEAD_SHARES,
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

/// Deposit assets and receive shares
pub fn handle_deposit<'info>(
    vault: &mut Account<'info, SecureVault>,
    user_shares: &mut Account<'info, UserShares>,
    user_token: &Account<'info, TokenAccount>,
    vault_token: &Account<'info, TokenAccount>,
    user: &Signer<'info>,
    token_program: &Program<'info, Token>,
    amount: u64,
) -> Result<u64> {
    let clock = Clock::get()?;

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 1: Validate Initialization
    // ═══════════════════════════════════════════════════════════════════

    require!(vault.is_initialized, VaultError::VaultNotInitialized);

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 2: Minimum Deposit Check
    // ═══════════════════════════════════════════════════════════════════

    require!(amount >= MINIMUM_DEPOSIT, VaultError::DepositTooSmall);

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 3: Calculate Shares (Rounding DOWN - favors vault)
    // ═══════════════════════════════════════════════════════════════════

    let shares_to_mint = if vault.total_assets == 0 {
        amount
    } else {
        (amount as u128)
            .checked_mul(vault.total_shares as u128)
            .ok_or(VaultError::Overflow)?
            .checked_div(vault.total_assets as u128)
            .ok_or(VaultError::DivisionByZero)? as u64
    };

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE LAYER 4: Zero Share Prevention
    // ═══════════════════════════════════════════════════════════════════

    require!(shares_to_mint > 0, VaultError::InsufficientShares);

    // Calculate exchange rate for logging
    let exchange_rate = if vault.total_assets > 0 {
        (vault.total_assets as u128 * 1_000_000) / vault.total_shares as u128
    } else {
        1_000_000 // 1:1
    };

    // Update State BEFORE Transfer (Check-Effects-Interactions)
    vault.total_shares = vault
        .total_shares
        .checked_add(shares_to_mint)
        .ok_or(VaultError::Overflow)?;

    vault.total_assets = vault
        .total_assets
        .checked_add(amount)
        .ok_or(VaultError::Overflow)?;

    // Transfer Assets to Vault
    token::transfer(
        CpiContext::new(
            token_program.to_account_info(),
            Transfer {
                from: user_token.to_account_info(),
                to: vault_token.to_account_info(),
                authority: user.to_account_info(),
            },
        ),
        amount,
    )?;

    // Update user share balance
    user_shares.amount = user_shares
        .amount
        .checked_add(shares_to_mint)
        .ok_or(VaultError::Overflow)?;
    user_shares.last_deposit = clock.unix_timestamp;

    emit!(DepositEvent {
        user: user.key(),
        amount,
        shares_minted: shares_to_mint,
        exchange_rate: exchange_rate as u64,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Deposited {} tokens, minted {} shares (rate: {})",
        amount,
        shares_to_mint,
        exchange_rate
    );

    Ok(shares_to_mint)
}

/// Withdraw assets by burning shares
pub fn handle_withdraw<'info>(
    vault: &mut Account<'info, SecureVault>,
    user_shares: &mut Account<'info, UserShares>,
    user_token: &Account<'info, TokenAccount>,
    vault_token: &Account<'info, TokenAccount>,
    user: &Signer<'info>,
    token_program: &Program<'info, Token>,
    shares: u64,
) -> Result<u64> {
    let clock = Clock::get()?;

    // ═══════════════════════════════════════════════════════════════════
    // Validate Withdrawal
    // ═══════════════════════════════════════════════════════════════════

    require!(shares > 0, VaultError::InvalidAmount);
    require!(user_shares.amount >= shares, VaultError::InsufficientShares);

    // Prevent withdrawing dead shares
    let withdrawable_shares = vault
        .total_shares
        .checked_sub(vault.dead_shares)
        .ok_or(VaultError::Underflow)?;
    require!(
        shares <= withdrawable_shares,
        VaultError::CannotWithdrawDeadShares
    );

    // ═══════════════════════════════════════════════════════════════════
    // DEFENSE: Calculate Assets (Rounding UP - favors vault)
    // ═══════════════════════════════════════════════════════════════════

    // assets = (shares * total_assets + total_shares - 1) / total_shares
    let assets_to_withdraw = (shares as u128)
        .checked_mul(vault.total_assets as u128)
        .ok_or(VaultError::Overflow)?
        .checked_add(vault.total_shares as u128 - 1)
        .ok_or(VaultError::Overflow)?
        .checked_div(vault.total_shares as u128)
        .ok_or(VaultError::DivisionByZero)? as u64;

    // Ensure we don't withdraw more than available
    let actual_withdraw = assets_to_withdraw.min(vault.total_assets);

    // Update State BEFORE Transfer
    vault.total_shares = vault
        .total_shares
        .checked_sub(shares)
        .ok_or(VaultError::Underflow)?;

    vault.total_assets = vault
        .total_assets
        .checked_sub(actual_withdraw)
        .ok_or(VaultError::Underflow)?;

    user_shares.amount = user_shares
        .amount
        .checked_sub(shares)
        .ok_or(VaultError::Underflow)?;

    // Transfer Assets from Vault
    let seeds = &[b"vault".as_ref(), &[vault.bump]];
    let signer = &[&seeds[..]];

    token::transfer(
        CpiContext::new_with_signer(
            token_program.to_account_info(),
            Transfer {
                from: vault_token.to_account_info(),
                to: user_token.to_account_info(),
                authority: vault.to_account_info(),
            },
            signer,
        ),
        actual_withdraw,
    )?;

    emit!(WithdrawEvent {
        user: user.key(),
        shares_burned: shares,
        assets_withdrawn: actual_withdraw,
        timestamp: clock.unix_timestamp,
    });

    msg!(
        "Burned {} shares, withdrew {} assets",
        shares,
        actual_withdraw
    );

    Ok(actual_withdraw)
}

/// Initialize user share account
pub fn handle_initialize_user_shares<'info>(
    user_shares: &mut Account<'info, UserShares>,
    user: &Signer<'info>,
    bump: u8,
) -> Result<()> {
    user_shares.owner = user.key();
    user_shares.amount = 0;
    user_shares.last_deposit = 0;
    user_shares.bump = bump;

    msg!("User shares initialized for {}", user.key());

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Account Structures
// ═══════════════════════════════════════════════════════════════════════════

#[account]
pub struct SecureVault {
    /// Authority allowed to manage vault settings
    pub admin: Pubkey,
    /// The mint of the token held in the vault
    pub mint: Pubkey,
    /// Total assets held in vault
    pub total_assets: u64,
    /// Total shares outstanding (including dead shares)
    pub total_shares: u64,
    /// Dead shares that can never be redeemed
    pub dead_shares: u64,
    /// Whether vault has been initialized
    pub is_initialized: bool,
    /// PDA bump
    pub bump: u8,
}

impl SecureVault {
    pub const LEN: usize = 8 + // discriminator
        32 + // admin
        32 + // mint
        8 +  // total_assets
        8 +  // total_shares
        8 +  // dead_shares
        1 +  // is_initialized
        1; // bump
}

#[account]
pub struct UserShares {
    /// Owner of these shares
    pub owner: Pubkey,
    /// Number of shares held
    pub amount: u64,
    /// Timestamp of last deposit
    pub last_deposit: i64,
    /// PDA bump
    pub bump: u8,
}

impl UserShares {
    pub const LEN: usize = 8 + // discriminator
        32 + // owner
        8 +  // amount
        8 +  // last_deposit
        1; // bump
}

/// Vault statistics returned by get_vault_stats
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VaultStats {
    pub total_assets: u64,
    pub total_shares: u64,
    pub dead_shares: u64,
    pub active_shares: u64,
    pub share_price_e9: u64,
    pub is_initialized: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Events
// ═══════════════════════════════════════════════════════════════════════════

#[event]
pub struct VaultInitializedEvent {
    pub dead_shares: u64,
    pub timestamp: i64,
}

#[event]
pub struct DepositEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub shares_minted: u64,
    pub exchange_rate: u64,
    pub timestamp: i64,
}

#[event]
pub struct WithdrawEvent {
    pub user: Pubkey,
    pub shares_burned: u64,
    pub assets_withdrawn: u64,
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Error Codes
// ═══════════════════════════════════════════════════════════════════════════

#[error_code]
pub enum VaultError {
    #[msg("Vault has not been initialized")]
    VaultNotInitialized,

    #[msg("Deposit amount too small - minimum required")]
    DepositTooSmall,

    #[msg("Invalid amount - must be greater than zero")]
    InvalidAmount,

    #[msg("Insufficient shares to complete operation")]
    InsufficientShares,

    #[msg("Cannot withdraw dead shares")]
    CannotWithdrawDeadShares,

    #[msg("Unauthorized operation")]
    Unauthorized,

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Arithmetic underflow")]
    Underflow,

    #[msg("Division by zero")]
    DivisionByZero,
}
