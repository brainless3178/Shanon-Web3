//! Hardened emergency systems module.
//!
//! Security measures applied:
//!   - emergency_pause requires caller == admin (SOL-001 mitigation)
//!   - Event emission for pause/unpause operations
//!   - Pause duration capped to prevent permanent griefing

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

/// Maximum pause duration: 7 days
pub const MAX_PAUSE_DURATION: i64 = 7 * 24 * 60 * 60;

// ── Events ──────────────────────────────────────────────────────────

#[event]
pub struct EmergencyPauseEvent {
    pub admin: Pubkey,
    pub reason: String,
    pub pause_until: i64,
}

#[event]
pub struct UnpauseEvent {
    pub admin: Pubkey,
}

// ── Handlers ────────────────────────────────────────────────────────

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

/// Only the admin can pause the protocol.
pub fn handle_emergency_pause<'info>(
    emergency_state: &mut Account<'info, EmergencyState>,
    config: &mut Account<'info, crate::Config>,
    caller: &Signer<'info>,
    reason: String,
    duration: i64,
) -> Result<()> {
    // Access control: only admin can pause
    require!(
        config.admin == *caller.key,
        ErrorCode::Unauthorized
    );

    // Cap pause duration to prevent permanent griefing
    require!(
        duration > 0 && duration <= MAX_PAUSE_DURATION,
        ErrorCode::InvalidPauseDuration
    );

    let now = Clock::get()?.unix_timestamp;
    emergency_state.is_paused = true;
    emergency_state.pause_reason = reason.clone();
    emergency_state.pause_until = now + duration;
    
    // Sync to global config
    config.paused = true;

    emit!(EmergencyPauseEvent {
        admin: *caller.key,
        reason,
        pause_until: now + duration,
    });

    Ok(())
}

pub fn handle_unpause<'info>(
    emergency_state: &mut Account<'info, EmergencyState>,
    config: &mut Account<'info, crate::Config>,
    admin: &Signer<'info>,
) -> Result<()> {
    require!(
        config.admin == *admin.key,
        ErrorCode::Unauthorized
    );
    emergency_state.is_paused = false;
    config.paused = false;

    emit!(UnpauseEvent {
        admin: *admin.key,
    });

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized — only admin can perform this action")]
    Unauthorized,
    #[msg("Invalid pause duration — must be 1s to 7 days")]
    InvalidPauseDuration,
}
