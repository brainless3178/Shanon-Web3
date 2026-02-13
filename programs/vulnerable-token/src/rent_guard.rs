use anchor_lang::prelude::*;

pub fn check_rent_exempt(account_info: &AccountInfo) -> Result<()> {
    let rent = Rent::get()?;
    require!(
        rent.is_exempt(account_info.lamports(), account_info.data_len()),
        ErrorCode::NotRentExempt
    );
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Account is not rent exempt")]
    NotRentExempt,
}
