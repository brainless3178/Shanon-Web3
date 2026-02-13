use anchor_lang::prelude::*;

#[account]
pub struct VotingEscrow {
    pub owner: Pubkey,
    pub amount: u64,
    pub lock_end: i64,
    pub bump: u8,
}

impl VotingEscrow {
    pub const LEN: usize = 8 + 32 + 8 + 8 + 1;
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
    pub const LEN: usize = 8 + 8 + (4 + 96) + 8 + 8 + 8 + 1 + 1;
}

pub fn handle_create_voting_escrow<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    user: &Signer<'info>,
    _system_program: &Program<'info, System>,
    amount: u64,
    lock_duration: i64,
    bump: u8,
) -> Result<()> {
    escrow.owner = *user.key;
    escrow.amount = amount;
    escrow.lock_end = Clock::get()?.unix_timestamp + lock_duration;
    escrow.bump = bump;
    Ok(())
}

pub fn handle_vote_on_proposal<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    proposal: &mut Account<'info, Proposal>,
    user: &Signer<'info>,
    _proposal_id: u64,
    vote: bool,
) -> Result<()> {
    if escrow.owner != *user.key {
        return Err(error!(ErrorCode::Unauthorized));
    }

    if vote {
        proposal.votes_for += escrow.amount;
    } else {
        proposal.votes_against += escrow.amount;
    }

    Ok(())
}

pub fn handle_extend_lock<'info>(
    escrow: &mut Account<'info, VotingEscrow>,
    owner: &Signer<'info>,
    additional_duration: i64,
) -> Result<()> {
    if escrow.owner != *owner.key {
        return Err(error!(ErrorCode::Unauthorized));
    }
    escrow.lock_end += additional_duration;
    Ok(())
}

pub fn handle_withdraw_from_escrow<'info>(
    escrow: &Account<'info, VotingEscrow>,
    _user: &AccountInfo<'info>,
) -> Result<()> {
    if Clock::get()?.unix_timestamp < escrow.lock_end {
        return Err(error!(ErrorCode::LockNotExpired));
    }
    Ok(())
}

pub fn handle_create_proposal<'info>(
    proposal: &mut Account<'info, Proposal>,
    _proposer: &Signer<'info>,
    proposal_id: u64,
    title: String,
    voting_duration: i64,
    bump: u8,
) -> Result<()> {
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
    if Clock::get()?.unix_timestamp < proposal.end_time {
        return Err(error!(ErrorCode::VotingNotEnded));
    }
    if proposal.executed {
        return Err(error!(ErrorCode::AlreadyExecuted));
    }

    if proposal.votes_for > proposal.votes_against {
        proposal.executed = true;
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
}
