use anchor_lang::prelude::*;

#[account]
pub struct EmergencyState {
    pub admin: Pubkey,
    pub is_paused: bool,
    pub pause_reason: String,
    pub pause_until: i64,
    pub bump: u8,
}

impl EmergencyState {
    pub const SPACE: usize = 8 + 32 + 1 + (4 + 96) + 8 + 1;
}

pub fn handle_initialize_emergency_state<'info>(
    emergency_state: &mut Account<'info, EmergencyState>,
    admin: &Signer<'info>,
    bump: u8,
) -> Result<()> {
    emergency_state.admin = *admin.key;
    emergency_state.is_paused = false;
    emergency_state.pause_reason = String::new();
    emergency_state.pause_until = 0;
    emergency_state.bump = bump;
    Ok(())
}

pub fn handle_emergency_pause<'info>(
    emergency_state: &mut Account<'info, EmergencyState>,
    _caller: &Signer<'info>,
    reason: String,
    duration: i64,
) -> Result<()> {
    emergency_state.is_paused = true;
    emergency_state.pause_reason = reason;
    emergency_state.pause_until = Clock::get()?.unix_timestamp + duration;
    Ok(())
}

pub fn handle_unpause<'info>(
    emergency_state: &mut Account<'info, EmergencyState>,
    admin: &Signer<'info>,
) -> Result<()> {
    if emergency_state.admin != *admin.key {
        return Err(error!(ErrorCode::Unauthorized));
    }
    emergency_state.is_paused = false;
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
}
