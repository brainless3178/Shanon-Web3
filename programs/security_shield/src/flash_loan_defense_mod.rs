//! Hardened flash-loan defense / governance module.
//!
//! Security measures applied:
//!   - Voting escrow actually locks tokens via CPI transfer (SOL-025 mitigation)
//!   - Double-vote prevention via `has_voted` flag on escrow
//!   - checked_add for vote counting (overflow prevention)
//!   - Proper Proposal::LEN with MAX_TITLE_LEN and validation
//!   - Withdraw returns locked tokens via PDA signing

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

pub const MAX_TITLE_LEN: usize = 96;

#[account]
pub struct VotingEscrow {
    pub owner: Pubkey,
    pub amount: u64,
    pub lock_end: i64,
    pub has_voted: bool,
    pub bump: u8,
}

impl VotingEscrow {
    pub const LEN: usize = 8 + 32 + 8 + 8 + 1 + 1;
}

#[account]
pub struct Proposal {
    pub id: u64,
    pub title: String,
    pub votes_for: u64,
    pub votes_against: u64,
    pub end_time: i64,
    pub executed: bool,
    pub bump: u8,
}

impl Proposal {
    // 4-byte Borsh length prefix + MAX_TITLE_LEN for the String field
    pub const LEN: usize = 8 + 8 + (4 + MAX_TITLE_LEN) + 8 + 8 + 8 + 1 + 1;
}

// ── Events ──────────────────────────────────────────────────────────

#[event]
pub struct EscrowCreatedEvent {
    pub owner: Pubkey,
    pub amount: u64,
    pub lock_end: i64,
}

#[event]
pub struct VoteCastEvent {
    pub voter: Pubkey,
    pub proposal_id: u64,
    pub vote_for: bool,
    pub weight: u64,
}

#[event]
pub struct ProposalExecutedEvent {
    pub proposal_id: u64,
    pub votes_for: u64,
    pub votes_against: u64,
}

// ── Handlers ────────────────────────────────────────────────────────

/// Create a voting escrow — actually locks tokens via CPI transfer
/// to prevent flash-loan governance attacks.
pub fn handle_create_voting_escrow<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    user: &Signer<'info>,
    user_token: &Account<'info, TokenAccount>,
    escrow_token: &Account<'info, TokenAccount>,
    token_program: &Program<'info, Token>,
    amount: u64,
    lock_duration: i64,
    bump: u8,
) -> Result<()> {
    require!(amount > 0, ErrorCode::ZeroAmount);
    require!(lock_duration > 0, ErrorCode::InvalidLockDuration);

    // Actually lock tokens — flash-loan attacker can't vote without
    // having tokens locked for the full duration
    let cpi_accounts = Transfer {
        from: user_token.to_account_info(),
        to: escrow_token.to_account_info(),
        authority: user.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi_ctx, amount)?;

    escrow.owner = *user.key;
    escrow.amount = amount;
    escrow.lock_end = Clock::get()?.unix_timestamp + lock_duration;
    escrow.has_voted = false;
    escrow.bump = bump;

    emit!(EscrowCreatedEvent {
        owner: *user.key,
        amount,
        lock_end: escrow.lock_end,
    });

    Ok(())
}

/// Vote on a proposal — prevents double voting.
pub fn handle_vote_on_proposal<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    proposal: &mut Account<'info, Proposal>,
    user: &Signer<'info>,
    _proposal_id: u64,
    vote: bool,
) -> Result<()> {
    require!(escrow.owner == *user.key, ErrorCode::Unauthorized);
    require!(!escrow.has_voted, ErrorCode::AlreadyVoted);

    let now = Clock::get()?.unix_timestamp;
    require!(now < proposal.end_time, ErrorCode::VotingEnded);

    if vote {
        proposal.votes_for = proposal.votes_for
            .checked_add(escrow.amount)
            .ok_or(ErrorCode::MathOverflow)?;
    } else {
        proposal.votes_against = proposal.votes_against
            .checked_add(escrow.amount)
            .ok_or(ErrorCode::MathOverflow)?;
    }

    escrow.has_voted = true;

    emit!(VoteCastEvent {
        voter: *user.key,
        proposal_id: proposal.id,
        vote_for: vote,
        weight: escrow.amount,
    });

    Ok(())
}

pub fn handle_extend_lock<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    owner: &Signer<'info>,
    additional_duration: i64,
) -> Result<()> {
    require!(escrow.owner == *owner.key, ErrorCode::Unauthorized);
    require!(additional_duration > 0, ErrorCode::InvalidLockDuration);
    escrow.lock_end = escrow.lock_end
        .checked_add(additional_duration)
        .ok_or(ErrorCode::MathOverflow)?;
    Ok(())
}

/// Withdraw locked tokens after lock period expires via PDA signing.
pub fn handle_withdraw_from_escrow<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    user: &Signer<'info>,
    escrow_token: &Account<'info, TokenAccount>,
    user_token: &Account<'info, TokenAccount>,
    token_program: &Program<'info, Token>,
) -> Result<()> {
    require!(escrow.owner == *user.key, ErrorCode::Unauthorized);

    let now = Clock::get()?.unix_timestamp;
    require!(now >= escrow.lock_end, ErrorCode::LockNotExpired);

    let amount = escrow.amount;
    require!(amount > 0, ErrorCode::ZeroAmount);

    // Transfer locked tokens back to user via escrow PDA signing
    let escrow_seeds: &[&[u8]] = &[b"voting_escrow", user.key.as_ref(), &[escrow.bump]];
    let signer_seeds = &[escrow_seeds];

    let cpi_accounts = Transfer {
        from: escrow_token.to_account_info(),
        to: user_token.to_account_info(),
        authority: escrow.to_account_info(),
    };
    token::transfer(
        CpiContext::new_with_signer(
            token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        ),
        amount,
    )?;

    // Clear state
    escrow.amount = 0;
    escrow.has_voted = false;

    emit!(EscrowWithdrawnEvent {
        owner: *user.key,
        amount,
    });

    Ok(())
}

#[event]
pub struct EscrowWithdrawnEvent {
    pub owner: Pubkey,
    pub amount: u64,
}

pub fn handle_create_proposal<'info>(
    proposal: &mut Account<'info, Proposal>,
    _proposer: &Signer<'info>,
    proposal_id: u64,
    title: String,
    voting_duration: i64,
    bump: u8,
) -> Result<()> {
    require!(title.len() <= MAX_TITLE_LEN, ErrorCode::TitleTooLong);
    require!(voting_duration > 0, ErrorCode::InvalidLockDuration);

    proposal.id = proposal_id;
    proposal.title = title;
    proposal.votes_for = 0;
    proposal.votes_against = 0;
    proposal.end_time = Clock::get()?.unix_timestamp + voting_duration;
    proposal.executed = false;
    proposal.bump = bump;
    Ok(())
}

pub fn handle_execute_proposal<'info>(proposal: &mut Account<'info, Proposal>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    require!(now >= proposal.end_time, ErrorCode::VotingNotEnded);
    require!(!proposal.executed, ErrorCode::AlreadyExecuted);

    if proposal.votes_for > proposal.votes_against {
        proposal.executed = true;
        emit!(ProposalExecutedEvent {
            proposal_id: proposal.id,
            votes_for: proposal.votes_for,
            votes_against: proposal.votes_against,
        });
    }

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Lock not expired")]
    LockNotExpired,
    #[msg("Voting not ended")]
    VotingNotEnded,
    #[msg("Already executed")]
    AlreadyExecuted,
    #[msg("Already voted with this escrow")]
    AlreadyVoted,
    #[msg("Voting has ended")]
    VotingEnded,
    #[msg("Zero amount")]
    ZeroAmount,
    #[msg("Invalid lock duration")]
    InvalidLockDuration,
    #[msg("Arithmetic overflow")]
    MathOverflow,
    #[msg("Title exceeds MAX_TITLE_LEN")]
    TitleTooLong,
}
