//! Attack flow sequences for ''
//! Multi-instruction patterns that model real-world attack scenarios.

use trident_fuzz::prelude::*;

/// Attack Flow: Double-Spend Attempt
/// Tries to execute the same transfer twice in rapid succession.
pub fn attack_double_spend(trident: &mut TridentSVM, accounts: &mut FuzzAccounts) {
    let mut tx1 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = ForceDefundTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = ForceDefundTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

    let mut tx1 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx1, Some("double_spend_1"));
    let mut tx2 = CloseTransaction::build(trident, accounts);
    trident.execute_transaction(&mut tx2, Some("double_spend_2"));

}

