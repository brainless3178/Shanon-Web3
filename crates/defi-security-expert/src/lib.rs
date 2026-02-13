use serde::{Deserialize, Serialize};

pub struct DeFiSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeFiInsight {
    pub name: String,
    pub defense_strategy: String,
    pub rust_implementation: String,
    pub security_checklist: Vec<String>,
}

impl DeFiSecurityExpert {
    pub fn get_defense_for_id(id: &str) -> Option<DeFiInsight> {
        match id {
            "7.1" | "SOL-020" => Some(DeFiInsight {
                name: "Oracle Price Manipulation".to_string(),
                defense_strategy: "Use multiple oracles (Pyth + Switchboard) and check for staleness and confidence levels.".to_string(),
                rust_implementation: "let price = pyth_feed.get_price_no_older_than(slot, 60)?;\nlet sb_price = switchboard_feed.get_result()?;\nrequire!(price.diff(sb_price) < MAX_DIFF, Error::OracleDivergence);".to_string(),
                security_checklist: vec![
                    "Verify oracle staleness (< 60s)".to_string(),
                    "Check oracle confidence interval".to_string(),
                    "Implement a circuit breaker for large price swings".to_string(),
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
    fn test_get_defense_for_known_id() {
        let insight = DeFiSecurityExpert::get_defense_for_id("7.1");
        assert!(insight.is_some());
        let insight = insight.unwrap();
        assert_eq!(insight.name, "Oracle Price Manipulation");
        assert!(!insight.defense_strategy.is_empty());
        assert!(!insight.rust_implementation.is_empty());
        assert!(!insight.security_checklist.is_empty());
    }

    #[test]
    fn test_get_defense_for_sol_id() {
        let insight = DeFiSecurityExpert::get_defense_for_id("SOL-020");
        assert!(insight.is_some());
        assert_eq!(insight.unwrap().name, "Oracle Price Manipulation");
    }

    #[test]
    fn test_get_defense_for_unknown_id() {
        assert!(DeFiSecurityExpert::get_defense_for_id("99.99").is_none());
        assert!(DeFiSecurityExpert::get_defense_for_id("").is_none());
        assert!(DeFiSecurityExpert::get_defense_for_id("unknown").is_none());
    }

    #[test]
    fn test_insight_serialization() {
        let insight = DeFiSecurityExpert::get_defense_for_id("7.1").unwrap();
        let json = serde_json::to_string(&insight).unwrap();
        assert!(json.contains("Oracle Price Manipulation"));
        let deserialized: DeFiInsight = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, insight.name);
    }
}
