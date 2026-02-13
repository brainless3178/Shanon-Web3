//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Privilege Escalation
/// Attempts to call admin functions with non-admin accounts.
pub fn attack_privilege_escalation(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    // Call 'update_user' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user"));
    assert!(result.is_err(), "Admin function 'update_user' accepted non-admin signer!");

    // Call 'update_user' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user"));
    assert!(result.is_err(), "Admin function 'update_user' accepted non-admin signer!");

    // Call 'update_user' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = UpdateUserTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_update_user"));
    assert!(result.is_err(), "Admin function 'update_user' accepted non-admin signer!");

}

