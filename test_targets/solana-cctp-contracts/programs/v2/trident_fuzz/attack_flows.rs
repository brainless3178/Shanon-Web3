//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Double-Spend Attempt
/// Tries to execute the same transfer twice in rapid succession.
pub fn attack_double_spend(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut tx1 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = HandleReceiveMessageTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = HandleReceiveMessageTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = TransferOwnershipTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

}

/// Attack Flow: Privilege Escalation
/// Attempts to call admin functions with non-admin accounts.
pub fn attack_privilege_escalation(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    // Call 'update_pauser' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePauserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pauser"));
    assert!(result.is_err(), "Admin function 'update_pauser' accepted non-admin signer!");

    // Call 'set_token_controller' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetTokenControllerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_token_controller"));
    assert!(result.is_err(), "Admin function 'set_token_controller' accepted non-admin signer!");

    // Call 'set_max_burn_amount_per_message' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMaxBurnAmountPerMessageTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_max_burn_amount_per_message"));
    assert!(result.is_err(), "Admin function 'set_max_burn_amount_per_message' accepted non-admin signer!");

    // Call 'update_denylister' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateDenylisterTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_denylister"));
    assert!(result.is_err(), "Admin function 'update_denylister' accepted non-admin signer!");

    // Call 'set_fee_recipient' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeeRecipientTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fee_recipient"));
    assert!(result.is_err(), "Admin function 'set_fee_recipient' accepted non-admin signer!");

    // Call 'set_min_fee_controller' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMinFeeControllerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_min_fee_controller"));
    assert!(result.is_err(), "Admin function 'set_min_fee_controller' accepted non-admin signer!");

    // Call 'set_min_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMinFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_min_fee"));
    assert!(result.is_err(), "Admin function 'set_min_fee' accepted non-admin signer!");

    // Call 'set_token_controller' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetTokenControllerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_token_controller"));
    assert!(result.is_err(), "Admin function 'set_token_controller' accepted non-admin signer!");

    // Call 'update_pauser' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePauserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pauser"));
    assert!(result.is_err(), "Admin function 'update_pauser' accepted non-admin signer!");

    // Call 'set_max_burn_amount_per_message' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMaxBurnAmountPerMessageTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_max_burn_amount_per_message"));
    assert!(result.is_err(), "Admin function 'set_max_burn_amount_per_message' accepted non-admin signer!");

    // Call 'set_fee_recipient' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetFeeRecipientTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_fee_recipient"));
    assert!(result.is_err(), "Admin function 'set_fee_recipient' accepted non-admin signer!");

    // Call 'update_denylister' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateDenylisterTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_denylister"));
    assert!(result.is_err(), "Admin function 'update_denylister' accepted non-admin signer!");

    // Call 'set_min_fee_controller' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMinFeeControllerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_min_fee_controller"));
    assert!(result.is_err(), "Admin function 'set_min_fee_controller' accepted non-admin signer!");

    // Call 'set_min_fee' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMinFeeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_min_fee"));
    assert!(result.is_err(), "Admin function 'set_min_fee' accepted non-admin signer!");

    // Call 'update_pauser' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePauserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pauser"));
    assert!(result.is_err(), "Admin function 'update_pauser' accepted non-admin signer!");

    // Call 'update_attester_manager' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAttesterManagerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_attester_manager"));
    assert!(result.is_err(), "Admin function 'update_attester_manager' accepted non-admin signer!");

    // Call 'set_max_message_body_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMaxMessageBodySizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_max_message_body_size"));
    assert!(result.is_err(), "Admin function 'set_max_message_body_size' accepted non-admin signer!");

    // Call 'set_signature_threshold' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetSignatureThresholdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_signature_threshold"));
    assert!(result.is_err(), "Admin function 'set_signature_threshold' accepted non-admin signer!");

    // Call 'update_pauser' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdatePauserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_pauser"));
    assert!(result.is_err(), "Admin function 'update_pauser' accepted non-admin signer!");

    // Call 'set_signature_threshold' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetSignatureThresholdTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_signature_threshold"));
    assert!(result.is_err(), "Admin function 'set_signature_threshold' accepted non-admin signer!");

    // Call 'update_attester_manager' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateAttesterManagerTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_attester_manager"));
    assert!(result.is_err(), "Admin function 'update_attester_manager' accepted non-admin signer!");

    // Call 'set_max_message_body_size' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetMaxMessageBodySizeTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_max_message_body_size"));
    assert!(result.is_err(), "Admin function 'set_max_message_body_size' accepted non-admin signer!");

}

