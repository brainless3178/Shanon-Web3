use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

#[account]
pub struct ProtectedPool {
    pub mint_in: Pubkey,
    pub mint_out: Pubkey,
    pub reserve_in: u64,
    pub reserve_out: u64,
    pub last_slot: u64,
    pub bump: u8,
}

impl ProtectedPool {
    pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 8 + 1;
}

pub fn handle_initialize_pool<'info>(
    pool: &mut Account<'info, ProtectedPool>,
    mint_in: &Account<'info, Mint>,
    mint_out: &Account<'info, Mint>,
    initial_reserve_in: u64,
    initial_reserve_out: u64,
    bump: u8,
) -> Result<()> {
    pool.mint_in = mint_in.key();
    pool.mint_out = mint_out.key();
    pool.reserve_in = initial_reserve_in;
    pool.reserve_out = initial_reserve_out;
    pool.last_slot = Clock::get()?.slot;
    pool.bump = bump;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_swap_with_protection<'info>(
    pool: &mut Account<'info, ProtectedPool>,
    user_source: &Account<'info, TokenAccount>,
    _user_destination: &Account<'info, TokenAccount>,
    pool_source: &Account<'info, TokenAccount>,
    _pool_token_out: &Account<'info, TokenAccount>,
    user: &Signer<'info>,
    token_program: &Program<'info, Token>,
    amount_in: u64,
    min_out: u64,
    deadline: i64,
) -> Result<u64> {
    let current_slot = Clock::get()?.slot;
    if deadline < Clock::get()?.unix_timestamp {
        return Err(error!(ErrorCode::DeadlineExceeded));
    }

    let amount_out = amount_in; // 1:1 swap ignoring reserves - VULNERABLE

    if amount_out < min_out {
        return Err(error!(ErrorCode::SlippageExceeded));
    }

    let cpi_accounts = Transfer {
        from: user_source.to_account_info(),
        to: pool_source.to_account_info(),
        authority: user.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi_ctx, amount_in)?;

    pool.reserve_in += amount_in;
    pool.reserve_out -= amount_out;
    pool.last_slot = current_slot;

    Ok(amount_out)
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Deadline exceeded")]
    DeadlineExceeded,
    #[msg("Slippage exceeded")]
    SlippageExceeded,
}
