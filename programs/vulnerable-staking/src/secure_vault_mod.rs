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
        amount
    } else {
        amount.checked_mul(vault.total_shares).unwrap() / vault.total_assets
    };

    let cpi_accounts = Transfer {
        from: user_token.to_account_info(),
        to: vault_token.to_account_info(),
        authority: user.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi_ctx, amount)?;

    user_shares.shares += shares;
    vault.total_shares += shares;
    vault.total_assets += amount;

    Ok(shares)
}

pub fn handle_withdraw<'info>(
    vault: &mut Account<'info, SecureVault>,
    user_shares: &mut Account<'info, UserShares>,
    _user_token: &Account<'info, TokenAccount>,
    _vault_token: &Account<'info, TokenAccount>,
    _user: &Signer<'info>,
    _token_program: &Program<'info, Token>,
    shares: u64,
) -> Result<u64> {
    if user_shares.shares < shares {
        return Err(error!(ErrorCode::InsufficientShares));
    }

    let amount = shares.checked_mul(vault.total_assets).unwrap() / vault.total_shares;

    user_shares.shares -= shares;
    vault.total_shares -= shares;
    vault.total_assets -= amount;

    Ok(amount)
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient shares")]
    InsufficientShares,
}
