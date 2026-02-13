use anchor_lang::prelude::*;

pub fn get_timestamp() -> Result<i64> {
    Ok(Clock::get()?.unix_timestamp)
}
