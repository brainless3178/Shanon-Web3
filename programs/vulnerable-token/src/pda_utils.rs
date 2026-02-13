use anchor_lang::prelude::*;

pub fn verify_pda(seeds: &[&[u8]], expected: &Pubkey, program_id: &Pubkey) -> Result<()> {
    let (pda, _bump) = Pubkey::find_program_address(seeds, program_id);
    require!(pda == *expected, ErrorCode::InvalidPDA);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid PDA")]
    InvalidPDA,
}
