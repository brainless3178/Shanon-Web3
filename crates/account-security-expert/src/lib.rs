use serde::{Deserialize, Serialize};

pub struct AccountSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInsight {
    pub name: String,
    pub architecture_verdict: String,
    pub attack_vector: String,
    pub secure_pattern: String,
    pub design_checklist: Vec<String>,
}

impl AccountSecurityExpert {
    pub fn get_insight_for_id(id: &str) -> Option<AccountInsight> {
        match id {
            "3.1" | "SOL-001" => Some(AccountInsight {
                name: "Missing Signer Check".to_string(),
                architecture_verdict: "Vulnerable to unauthorized takeovers.".to_string(),
                attack_vector: "Attacker passes a target account without signing, bypassing authority checks.".to_string(),
                secure_pattern: "#[account(mut, constraint = my_account.owner == authority.key())]\npub my_account: Account<'info, MyData>,\npub authority: Signer<'info>,".to_string(),
                design_checklist: vec![
                    "Use Signer<'info> for all authority accounts".to_string(),
                    "Check seeds for PDA derived accounts".to_string(),
                ],
            }),
            "4.1" | "SOL-003" => Some(AccountInsight {
                name: "PDA Validation Failure".to_string(),
                architecture_verdict: "Protocol-wide security bypass.".to_string(),
                attack_vector: "Using unverified PDAs allows fake state injection.".to_string(),
                secure_pattern: "seeds = [b\"vault\", user.key().as_ref()], bump = vault.bump".to_string(),
                design_checklist: vec![
                    "Always store and verify the bump seed".to_string(),
                    "Use canonical PDA derivation".to_string(),
                ],
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_insight_missing_signer() {
        let insight = AccountSecurityExpert::get_insight_for_id("3.1");
        assert!(insight.is_some());
        let insight = insight.unwrap();
        assert_eq!(insight.name, "Missing Signer Check");
        assert!(!insight.architecture_verdict.is_empty());
        assert!(!insight.attack_vector.is_empty());
        assert!(insight.secure_pattern.contains("Signer"));
        assert!(!insight.design_checklist.is_empty());
    }

    #[test]
    fn test_get_insight_pda_validation() {
        let insight = AccountSecurityExpert::get_insight_for_id("4.1");
        assert!(insight.is_some());
        let insight = insight.unwrap();
        assert_eq!(insight.name, "PDA Validation Failure");
        assert!(insight.secure_pattern.contains("seeds"));
    }

    #[test]
    fn test_sol_id_aliases() {
        let a = AccountSecurityExpert::get_insight_for_id("SOL-001");
        let b = AccountSecurityExpert::get_insight_for_id("3.1");
        assert_eq!(a.unwrap().name, b.unwrap().name);

        let c = AccountSecurityExpert::get_insight_for_id("SOL-003");
        let d = AccountSecurityExpert::get_insight_for_id("4.1");
        assert_eq!(c.unwrap().name, d.unwrap().name);
    }

    #[test]
    fn test_get_insight_for_unknown_id() {
        assert!(AccountSecurityExpert::get_insight_for_id("99.99").is_none());
        assert!(AccountSecurityExpert::get_insight_for_id("").is_none());
    }

    #[test]
    fn test_insight_serialization() {
        let insight = AccountSecurityExpert::get_insight_for_id("3.1").unwrap();
        let json = serde_json::to_string(&insight).unwrap();
        let deserialized: AccountInsight = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, insight.name);
        assert_eq!(
            deserialized.design_checklist.len(),
            insight.design_checklist.len()
        );
    }
}
