use anchor_lang::prelude::*;

#[account]
pub struct VotingEscrow {
    pub bump: u8,
    pub owner: Pubkey,
    pub amount: u64,
    pub lock_end: i64,
    pub voting_power: u64,
}

impl VotingEscrow {
    pub const LEN: usize = 8 + 1 + 32 + 8 + 8 + 8;
}

#[account]
pub struct Proposal {
    pub bump: u8,
    pub id: u64,
    pub proposer: Pubkey,
    pub title: String,
    pub votes_for: u64,
    pub votes_against: u64,
    pub voting_end: i64,
    pub executed: bool,
}

impl Proposal {
    pub const LEN: usize = 8 + 1 + 8 + 32 + (4 + 60) + 8 + 8 + 8 + 1;
}

pub fn handle_create_voting_escrow(
    escrow: &mut Account<VotingEscrow>,
    user: &Signer,
    _system_program: &Program<System>,
    amount: u64,
    lock_duration: i64,
    bump: u8,
) -> Result<()> {
    escrow.bump = bump;
    escrow.owner = user.key();
    escrow.amount = amount;
    escrow.lock_end = Clock::get()?.unix_timestamp + lock_duration;
    escrow.voting_power = amount;
    Ok(())
}

pub fn handle_vote_on_proposal(
    _escrow: &mut Account<VotingEscrow>,
    _proposal: &mut Account<Proposal>,
    _user: &Signer,
    _proposal_id: u64,
    _vote: bool,
) -> Result<()> {
    // Stub implementation
    Ok(())
}

pub fn handle_extend_lock(
    escrow: &mut Account<VotingEscrow>,
    _owner: &Signer,
    additional_duration: i64,
) -> Result<()> {
    escrow.lock_end += additional_duration;
    Ok(())
}

pub fn handle_withdraw_from_escrow(
    _escrow: &Account<VotingEscrow>,
    _user: &AccountInfo,
) -> Result<()> {
    // Stub implementation
    Ok(())
}

pub fn handle_create_proposal(
    proposal: &mut Account<Proposal>,
    proposer: &Signer,
    proposal_id: u64,
    title: String,
    voting_duration: i64,
    bump: u8,
) -> Result<()> {
    proposal.bump = bump;
    proposal.id = proposal_id;
    proposal.proposer = proposer.key();
    proposal.title = title;
    proposal.votes_for = 0;
    proposal.votes_against = 0;
    proposal.voting_end = Clock::get()?.unix_timestamp + voting_duration;
    proposal.executed = false;
    Ok(())
}

pub fn handle_execute_proposal(proposal: &mut Account<Proposal>) -> Result<()> {
    proposal.executed = true;
    Ok(())
}
