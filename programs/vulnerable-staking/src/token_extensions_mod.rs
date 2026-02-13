use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, TokenAccount, TransferChecked};

pub fn handle_transfer_with_fee_check<'info>(
    ctx: CpiContext<'_, '_, '_, 'info, TransferChecked<'info>>,
    amount: u64,
    decimals: u8,
    _destination_account: &mut InterfaceAccount<'info, TokenAccount>,
) -> Result<u64> {
    // BUG: Missing transfer fee calculation for Token 2022.
    // This allows bypass of protocol fees or results in incorrect accounting
    // when using tokens with transfer hooks or fees.

    token_interface::transfer_checked(ctx, amount, decimals)?;

    // In a correct implementation, we would check the actual amount received
    // in the destination account after the transfer to account for fees.

    Ok(amount)
}
