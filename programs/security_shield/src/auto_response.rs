use anchor_lang::prelude::*;
use crate::emergency_systems_mod::EmergencyState;
use crate::Config;
use exploit_registry::state::ExploitProfile;

pub fn handle_auto_pause(
    config: &mut Account<Config>,
    emergency_state: &mut Account<EmergencyState>,
    exploit_profile: &Account<ExploitProfile>,
) -> Result<()> {
    // Verify this exploit report is for THIS program
    require!(
        exploit_profile.program_id == crate::ID,
        ErrorCode::InvalidExploitTarget
    );

    // Only auto-pause for high severity exploits (e.g. >= 8)
    require!(
        exploit_profile.severity >= 8,
        ErrorCode::SeverityTooLowForAutoPause
    );

    let now = Clock::get()?.unix_timestamp;
    
    // Set internal flags
    config.paused = true;
    emergency_state.is_paused = true;
    emergency_state.pause_reason = format!(
        "Autonomous Pause: verified exploit {} detected (severity {})",
        exploit_profile.key(),
        exploit_profile.severity
    );
    emergency_state.pause_until = now + (24 * 60 * 60); // Default 24h grace period

    msg!("Autonomous pause triggered by exploit report: {}", exploit_profile.key());

    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Exploit report does not target this program")]
    InvalidExploitTarget,
    #[msg("Exploit severity is too low for autonomous pause")]
    SeverityTooLowForAutoPause,
}
