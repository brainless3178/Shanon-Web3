//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Double-Spend Attempt
/// Tries to execute the same transfer twice in rapid succession.
pub fn attack_double_spend(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut tx1 = VerifyTransferAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = VerifyTransferAmountTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleTransferWithFeeCheckTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleTransferWithFeeCheckTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

}

/// Attack Flow: Init → Close → Re-Init (Re-initialization Attack)
/// Initializes, closes, and re-initializes to steal lamports.
pub fn attack_reinit_drain(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut init = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateVotingEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeEmergencyStateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializeUserSharesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePriceStateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = InitializePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut init = CreateProposalTransaction::build(trident, accounts);
    trident.execute_transaction(&mut init, Some("init"));

    let mut close = WithdrawTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    let mut close = WithdrawFromEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut close, Some("close"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateVotingEscrowTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeEmergencyStateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeVaultTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializeUserSharesTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePriceStateTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = InitializePoolTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

    // Re-initialize after close — this should FAIL
    let mut reinit = CreateProposalTransaction::build(trident, accounts);
    trident.execute_transaction(&mut reinit, Some("reinit_attack"));

}

/// Attack Flow: Privilege Escalation
/// Attempts to call admin functions with non-admin accounts.
pub fn attack_privilege_escalation(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    // Call 'reset_circuit_breaker' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = ResetCircuitBreakerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_reset_circuit_breaker"));
    assert!(result.is_err(), "Admin function 'reset_circuit_breaker' accepted non-admin signer!");

}

