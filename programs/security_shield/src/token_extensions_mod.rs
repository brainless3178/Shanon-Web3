use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, TokenAccount, TransferChecked};

/// Defense for Token-2022 Transfer Fee Blindness
///
/// This module provides a secure wrapper for token transfers that correctly
/// calculates the actual amount received after fees.
pub fn handle_transfer_with_fee_check<'info>(
    ctx: CpiContext<'_, '_, '_, 'info, TransferChecked<'info>>,
    amount: u64,
    decimals: u8,
    recipient_account: &mut InterfaceAccount<'info, TokenAccount>,
) -> Result<u64> {
    // 1. Record balance before transfer
    let balance_before = recipient_account.amount;

    // 2. Execute transfer
    token_interface::transfer_checked(ctx, amount, decimals)?;

    // 3. Reload account to get new balance
    // Note: In a real CPI, we'd need to reload the account info data
    // For this module, we assume the caller provides the account to reload
    recipient_account.reload()?;
    let balance_after = recipient_account.amount;

    // 4. Calculate net amount received
    let net_amount = balance_after
        .checked_sub(balance_before)
        .ok_or(error!(TokenExtensionError::BalanceMismatch))?;

    msg!(
        "Token-2022 Transfer: Requested={}, Received={}",
        amount,
        net_amount
    );

    // Safety check: net_amount should never exceed amount
    if net_amount > amount {
        return err!(TokenExtensionError::InvalidTransferResult);
    }

    Ok(net_amount)
}

#[error_code]
pub enum TokenExtensionError {
    #[msg("Account balance mismatch after transfer")]
    BalanceMismatch,
    #[msg("Received more tokens than sent (impossible)")]
    InvalidTransferResult,
}
