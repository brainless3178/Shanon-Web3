use anchor_lang::prelude::*;

#[account]
pub struct EmergencyState {
    pub bump: u8,
    pub admin: Pubkey,
    pub is_paused: bool,
    pub pause_reason: String,
    pub pause_end: i64,
}

impl EmergencyState {
    pub const SPACE: usize = 8 + 1 + 32 + 1 + (4 + 60) + 8;
}

pub fn handle_initialize_emergency_state(
    state: &mut Account<EmergencyState>,
    admin: &Signer,
    bump: u8,
) -> Result<()> {
    state.bump = bump;
    state.admin = admin.key();
    state.is_paused = false;
    state.pause_reason = String::new();
    state.pause_end = 0;
    Ok(())
}

pub fn handle_emergency_pause(
    state: &mut Account<EmergencyState>,
    _caller: &Signer,
    reason: String,
    duration: i64,
) -> Result<()> {
    state.is_paused = true;
    state.pause_reason = reason;
    state.pause_end = Clock::get()?.unix_timestamp + duration;
    Ok(())
}

pub fn handle_unpause(state: &mut Account<EmergencyState>, _admin: &Signer) -> Result<()> {
    state.is_paused = false;
    state.pause_reason = String::new();
    state.pause_end = 0;
    Ok(())
}
