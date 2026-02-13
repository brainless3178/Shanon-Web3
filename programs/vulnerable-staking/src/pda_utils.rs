use anchor_lang::prelude::*;

pub fn find_pda_with_bump(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(seeds, program_id)
}

pub fn verify_pda(pda: &Pubkey, seeds: &[&[u8]], program_id: &Pubkey, bump: u8) -> bool {
    match Pubkey::create_program_address(&[seeds, &[&[bump]]].concat(), program_id) {
        Ok(derived_pda) => derived_pda == *pda,
        Err(_) => false,
    }
}
