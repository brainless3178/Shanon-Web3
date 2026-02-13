//! Property invariants for ''
//! These checks run after every fuzz flow to verify program correctness.

use trident_fuzz::prelude::*;

/// Invariant: No tokens created from nothing.
/// After any instruction, total supply must not increase without a mint.
pub fn check_balance_conservation(
    pre_state: &AccountsSnapshot,
    post_state: &AccountsSnapshot,
) -> InvariantResult {
    let pre_total: u64 = pre_state.token_balances().values().sum();
    let post_total: u64 = post_state.token_balances().values().sum();
    if post_total > pre_total {
        InvariantResult::Violated(format!(
            "Balance conservation violated: {} -> {} (delta: +{})",
            pre_total, post_total, post_total - pre_total,
        ))
    } else {
        InvariantResult::Held
    }
}

/// Invariant: State mutations require authorized signer.
pub fn check_access_control(
    tx_result: &TransactionResult,
    expected_signer: &Pubkey,
) -> InvariantResult {
    if tx_result.succeeded() && !tx_result.signers().contains(expected_signer) {
        InvariantResult::Violated(format!(
            "State mutation succeeded without expected signer: {}",
            expected_signer,
        ))
    } else {
        InvariantResult::Held
    }
}

/// Invariant: Account discriminators must not change after initialization.
pub fn check_discriminator_integrity(
    pre_state: &AccountsSnapshot,
    post_state: &AccountsSnapshot,
) -> InvariantResult {
    for (key, pre_data) in pre_state.account_data() {
        if let Some(post_data) = post_state.account_data().get(key) {
            if pre_data.len() >= 8 && post_data.len() >= 8 {
                if pre_data[..8] != post_data[..8] {
                    return InvariantResult::Violated(format!(
                        "Discriminator changed for account {}", key,
                    ));
                }
            }
        }
    }
    InvariantResult::Held
}

