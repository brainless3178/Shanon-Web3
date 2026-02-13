//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Privilege Escalation
/// Attempts to call admin functions with non-admin accounts.
pub fn attack_privilege_escalation(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    // Call 'set_value' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetValueTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_value"));
    assert!(result.is_err(), "Admin function 'set_value' accepted non-admin signer!");

    // Call 'set_value_secure' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetValueSecureTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_value_secure"));
    assert!(result.is_err(), "Admin function 'set_value_secure' accepted non-admin signer!");

    // Call 'set_value' with a random (non-admin) keypair
    let attacker = Keypair::new();
    let mut tx = SetValueTransaction::build_with_signer(trident, accounts, &attacker);
    let result = trident.execute_transaction(&mut tx, Some("priv_esc_set_value"));
    assert!(result.is_err(), "Admin function 'set_value' accepted non-admin signer!");

}

