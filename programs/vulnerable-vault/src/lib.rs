#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint as LegacyMint, Token, TokenAccount as LegacyTokenAccount};
use anchor_spl::token_interface::{self, Mint, TokenAccount};

declare_id!("47poGSxjXsErkcCrZqEJtomHrdxHtfAbpfYmx3xRndVJ");

pub mod auto_response;
pub mod compute_guard;
pub mod emergency_systems_mod;
pub mod flash_loan_defense_mod;
pub mod mev_defense_mod;
pub mod pda_utils;
pub mod rent_guard;
pub mod secure_oracle_mod;
pub mod secure_time;
pub mod secure_vault_mod;
pub mod token_extensions_mod;

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn autonomous_pause(ctx: Context<AutoPause>) -> Result<()> {
        auto_response::handle_auto_pause(
            &mut ctx.accounts.config,
            &mut ctx.accounts.emergency_state,
            &ctx.accounts.exploit_profile,
        )
    }

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.authority.key();
        config.is_initialized = true;
        config.paused = false;
        config.version = 1;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn verify_transfer_amount(
        ctx: Context<VerifyTransfer>,
        amount: u64,
        decimals: u8,
    ) -> Result<u64> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        let cpi_accounts = token_interface::TransferChecked {
            from: ctx.accounts.source.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

        token_extensions_mod::handle_transfer_with_fee_check(
            cpi_ctx,
            amount,
            decimals,
            &mut ctx.accounts.destination,
        )
    }

    // [MEV] Transaction Sandwiching and Frontrunning Protections
    pub fn swap_with_protection(
        ctx: Context<SwapWithProtection>,
        amount_in: u64,
        min_out: u64,
        deadline: i64,
    ) -> Result<u64> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        mev_defense_mod::handle_swap_with_protection(
            &mut ctx.accounts.pool,
            &ctx.accounts.user_source,
            &ctx.accounts.user_destination,
            &ctx.accounts.pool_source,
            &ctx.accounts.pool_token_out,
            &ctx.accounts.user,
            &ctx.accounts.token_program,
            amount_in,
            min_out,
            deadline,
        )
    }

    // [ORACLE] Secure Pricing and Circuit Breaker Logic
    pub fn get_secure_price(ctx: Context<GetSecurePrice>) -> Result<u64> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        secure_oracle_mod::handle_get_secure_price(
            &mut ctx.accounts.price_state,
            &ctx.accounts.pyth_price_feed,
            &ctx.accounts.switchboard_feed,
        )
    }

    // [VAULT] Hardened Token Depository and Share Accounting
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<u64> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        secure_vault_mod::handle_deposit(
            &mut ctx.accounts.vault,
            &mut ctx.accounts.user_shares,
            &ctx.accounts.user_token,
            &ctx.accounts.vault_token,
            &ctx.accounts.user,
            &ctx.accounts.token_program,
            amount,
        )
    }

    // [GOV] Governance Protection Against Flash Loan Attacks
    pub fn create_voting_escrow(
        ctx: Context<CreateVotingEscrow>,
        amount: u64,
        lock_duration: i64,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        flash_loan_defense_mod::handle_create_voting_escrow(
            &mut ctx.accounts.escrow,
            &ctx.accounts.user,
            &ctx.accounts.user_token,
            &ctx.accounts.escrow_token,
            &ctx.accounts.token_program,
            amount,
            lock_duration,
            ctx.bumps.escrow,
        )
    }

    // [EMERGENCY] Protocol Pause and Administrative Controls
    pub fn initialize_emergency_state(ctx: Context<InitializeEmergencyState>) -> Result<()> {
        emergency_systems_mod::handle_initialize_emergency_state(
            &mut ctx.accounts.emergency_state,
            &ctx.accounts.admin,
            ctx.bumps.emergency_state,
        )
    }

    pub fn emergency_pause(
        ctx: Context<EmergencyPause>,
        reason: String,
        duration: i64,
    ) -> Result<()> {
        emergency_systems_mod::handle_emergency_pause(
            &mut ctx.accounts.emergency_state,
            &mut ctx.accounts.config,
            &ctx.accounts.caller,
            reason,
            duration,
        )
    }

    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        emergency_systems_mod::handle_unpause(
            &mut ctx.accounts.emergency_state,
            &mut ctx.accounts.config,
            &ctx.accounts.admin,
        )
    }

    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        secure_vault_mod::handle_initialize_vault(
            &mut ctx.accounts.vault,
            ctx.accounts.admin.key(),
            ctx.accounts.mint.key(),
            ctx.bumps.vault,
        )
    }

    pub fn withdraw(ctx: Context<Withdraw>, shares: u64) -> Result<u64> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        secure_vault_mod::handle_withdraw(
            &mut ctx.accounts.vault,
            &mut ctx.accounts.user_shares,
            &ctx.accounts.user_token,
            &ctx.accounts.vault_token,
            &ctx.accounts.user,
            &ctx.accounts.token_program,
            shares,
        )
    }

    pub fn initialize_user_shares(ctx: Context<InitializeUserShares>) -> Result<()> {
        secure_vault_mod::handle_initialize_user_shares(
            &mut ctx.accounts.user_shares,
            &ctx.accounts.user,
            ctx.bumps.user_shares,
        )
    }

    pub fn initialize_price_state(ctx: Context<InitializePriceState>) -> Result<()> {
        secure_oracle_mod::handle_initialize_price_state(
            &mut ctx.accounts.price_state,
            &ctx.accounts.token_mint.key(),
            ctx.accounts.admin.key(),
            ctx.bumps.price_state,
        )
    }

    pub fn reset_circuit_breaker(ctx: Context<ResetCircuitBreaker>) -> Result<()> {
        secure_oracle_mod::handle_reset_circuit_breaker(
            &mut ctx.accounts.price_state,
            &ctx.accounts.admin,
        )
    }

    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        initial_reserve_in: u64,
        initial_reserve_out: u64,
    ) -> Result<()> {
        mev_defense_mod::handle_initialize_pool(
            &mut ctx.accounts.pool,
            &ctx.accounts.mint_in,
            &ctx.accounts.mint_out,
            initial_reserve_in,
            initial_reserve_out,
            ctx.bumps.pool,
        )
    }

    pub fn vote_on_proposal(
        ctx: Context<VoteOnProposal>,
        proposal_id: u64,
        vote: bool,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        flash_loan_defense_mod::handle_vote_on_proposal(
            &mut ctx.accounts.escrow,
            &mut ctx.accounts.proposal,
            &ctx.accounts.user,
            proposal_id,
            vote,
        )
    }

    pub fn extend_lock(ctx: Context<ExtendLock>, additional_duration: i64) -> Result<()> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        flash_loan_defense_mod::handle_extend_lock(
            &mut ctx.accounts.escrow,
            &ctx.accounts.owner,
            additional_duration,
        )
    }

    pub fn withdraw_from_escrow(ctx: Context<WithdrawFromEscrow>) -> Result<()> {
        require!(!ctx.accounts.config.paused, ErrorCode::ProtocolPaused);
        flash_loan_defense_mod::handle_withdraw_from_escrow(
            &mut ctx.accounts.escrow,
            &ctx.accounts.user,
            &ctx.accounts.escrow_token,
            &ctx.accounts.user_token,
            &ctx.accounts.token_program,
        )
    }

    pub fn create_proposal(
        ctx: Context<CreateProposal>,
        proposal_id: u64,
        title: String,
        voting_duration: i64,
    ) -> Result<()> {
        flash_loan_defense_mod::handle_create_proposal(
            &mut ctx.accounts.proposal,
            &ctx.accounts.proposer,
            proposal_id,
            title,
            voting_duration,
            ctx.bumps.proposal,
        )
    }

    pub fn execute_proposal(ctx: Context<ExecuteProposal>, _proposal_id: u64) -> Result<()> {
        flash_loan_defense_mod::handle_execute_proposal(&mut ctx.accounts.proposal)
    }
}

// --- Account Structs for Program Logic ---

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub is_initialized: bool,
    pub paused: bool,
    pub version: u32,
    pub bump: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + 32 + 1 + 1 + 4 + 1, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyTransfer<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub source: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub destination: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, token_interface::TokenInterface>,
}

#[derive(Accounts)]
pub struct SwapWithProtection<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"pool"],
        bump = pool.bump
    )]
    pub pool: Account<'info, mev_defense_mod::ProtectedPool>,
    #[account(mut)]
    pub user_source: Account<'info, LegacyTokenAccount>,
    #[account(mut)]
    pub user_destination: Account<'info, LegacyTokenAccount>,
    #[account(mut)]
    pub pool_source: Account<'info, LegacyTokenAccount>,
    #[account(mut)]
    pub pool_token_out: Account<'info, LegacyTokenAccount>,
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct GetSecurePrice<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: Pyth price feed
    pub pyth_price_feed: AccountInfo<'info>,
    /// CHECK: Switchboard aggregator
    pub switchboard_feed: AccountInfo<'info>,
    #[account(
        mut,
        seeds = [b"price_state", token_mint.key().as_ref()],
        bump = price_state.bump,
    )]
    pub price_state: Account<'info, secure_oracle_mod::PriceState>,
    pub token_mint: Account<'info, LegacyMint>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, secure_vault_mod::SecureVault>,
    #[account(
        mut,
        seeds = [b"user_shares", user.key().as_ref()],
        bump = user_shares.bump,
        constraint = user_shares.owner == user.key()
    )]
    pub user_shares: Account<'info, secure_vault_mod::UserShares>,
    #[account(mut, constraint = user_token.mint == vault.mint)]
    pub user_token: Account<'info, LegacyTokenAccount>,
    #[account(mut, constraint = vault_token.mint == vault.mint)]
    pub vault_token: Account<'info, LegacyTokenAccount>,
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CreateVotingEscrow<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        init,
        payer = user,
        space = flash_loan_defense_mod::VotingEscrow::LEN,
        seeds = [b"voting_escrow", user.key().as_ref()],
        bump
    )]
    pub escrow: Account<'info, flash_loan_defense_mod::VotingEscrow>,
    #[account(mut, constraint = user_token.owner == user.key())]
    pub user_token: Account<'info, LegacyTokenAccount>,
    #[account(mut)]
    pub escrow_token: Account<'info, LegacyTokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeEmergencyState<'info> {
    #[account(
        init,
        payer = admin,
        space = emergency_systems_mod::EmergencyState::SPACE,
        seeds = [b"emergency_state"],
        bump
    )]
    pub emergency_state: Account<'info, emergency_systems_mod::EmergencyState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct EmergencyPause<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"emergency_state"],
        bump = emergency_state.bump
    )]
    pub emergency_state: Account<'info, emergency_systems_mod::EmergencyState>,
    pub caller: Signer<'info>,
    pub admin: SystemAccount<'info>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"emergency_state"],
        bump = emergency_state.bump
    )]
    pub emergency_state: Account<'info, emergency_systems_mod::EmergencyState>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AutoPause<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"emergency_state"],
        bump = emergency_state.bump
    )]
    pub emergency_state: Account<'info, emergency_systems_mod::EmergencyState>,
    pub exploit_profile: Account<'info, exploit_registry::state::ExploitProfile>,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = admin,
        space = secure_vault_mod::SecureVault::LEN,
        seeds = [b"vault"],
        bump
    )]
    pub vault: Account<'info, secure_vault_mod::SecureVault>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub mint: Account<'info, LegacyMint>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault.bump
    )]
    pub vault: Account<'info, secure_vault_mod::SecureVault>,
    #[account(
        mut,
        seeds = [b"user_shares", user.key().as_ref()],
        bump = user_shares.bump,
        constraint = user_shares.owner == user.key()
    )]
    pub user_shares: Account<'info, secure_vault_mod::UserShares>,
    #[account(mut, constraint = user_token.mint == vault.mint)]
    pub user_token: Account<'info, LegacyTokenAccount>,
    #[account(mut, constraint = vault_token.mint == vault.mint)]
    pub vault_token: Account<'info, LegacyTokenAccount>,
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct InitializeUserShares<'info> {
    #[account(
        init,
        payer = user,
        space = secure_vault_mod::UserShares::LEN,
        seeds = [b"user_shares", user.key().as_ref()],
        bump
    )]
    pub user_shares: Account<'info, secure_vault_mod::UserShares>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializePriceState<'info> {
    #[account(
        init,
        payer = admin,
        space = secure_oracle_mod::PriceState::LEN,
        seeds = [b"price_state", token_mint.key().as_ref()],
        bump
    )]
    pub price_state: Account<'info, secure_oracle_mod::PriceState>,
    pub token_mint: Account<'info, LegacyMint>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResetCircuitBreaker<'info> {
    #[account(
        mut,
        seeds = [b"price_state", token_mint.key().as_ref()],
        bump = price_state.bump
    )]
    pub price_state: Account<'info, secure_oracle_mod::PriceState>,
    pub token_mint: Account<'info, LegacyMint>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePool<'info> {
    #[account(
        init,
        payer = admin,
        space = mev_defense_mod::ProtectedPool::LEN,
        seeds = [b"pool"],
        bump
    )]
    pub pool: Account<'info, mev_defense_mod::ProtectedPool>,
    pub mint_in: Account<'info, LegacyMint>,
    pub mint_out: Account<'info, LegacyMint>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct VoteOnProposal<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"voting_escrow", user.key().as_ref()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, flash_loan_defense_mod::VotingEscrow>,
    #[account(
        mut,
        seeds = [b"proposal", proposal_id.to_le_bytes().as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, flash_loan_defense_mod::Proposal>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExtendLock<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"voting_escrow", owner.key().as_ref()],
        bump = escrow.bump,
    )]
    pub escrow: Account<'info, flash_loan_defense_mod::VotingEscrow>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawFromEscrow<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        seeds = [b"voting_escrow", user.key().as_ref()],
        bump = escrow.bump,
        constraint = escrow.owner == user.key(),
    )]
    pub escrow: Account<'info, flash_loan_defense_mod::VotingEscrow>,
    #[account(mut)]
    pub escrow_token: Account<'info, LegacyTokenAccount>,
    #[account(mut, constraint = user_token.owner == user.key())]
    pub user_token: Account<'info, LegacyTokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct CreateProposal<'info> {
    #[account(
        init,
        payer = proposer,
        space = flash_loan_defense_mod::Proposal::LEN,
        seeds = [b"proposal", proposal_id.to_le_bytes().as_ref()],
        bump
    )]
    pub proposal: Account<'info, flash_loan_defense_mod::Proposal>,
    #[account(mut)]
    pub proposer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proposal_id: u64)]
pub struct ExecuteProposal<'info> {
    #[account(
        mut,
        seeds = [b"proposal", proposal_id.to_le_bytes().as_ref()],
        bump = proposal.bump,
    )]
    pub proposal: Account<'info, flash_loan_defense_mod::Proposal>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Protocol is currently paused")]
    ProtocolPaused,
}
