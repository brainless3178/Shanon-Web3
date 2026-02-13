use serde::{Deserialize, Serialize};

pub struct TokenSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInsight {
    pub name: String,
    pub extension_risk_matrix: Vec<(String, String, String)>,
    pub rust_secure_pattern: String,
    pub security_checklist: Vec<String>,
}

impl TokenSecurityExpert {
    pub fn get_insight_for_id(id: &str) -> Option<TokenInsight> {
        match id {
            "6.1" | "SOL-010" => Some(TokenInsight {
                name: "Token Program Confusion".to_string(),
                extension_risk_matrix: vec![
                    (
                        "Transfer Fee".to_string(),
                        "High".to_string(),
                        "Bypasses protocol fee logic".to_string(),
                    ),
                    (
                        "Closing Account".to_string(),
                        "Medium".to_string(),
                        "Potential lamport drainage".to_string(),
                    ),
                ],
                rust_secure_pattern: "pub token_program: Interface<'info, TokenInterface>,"
                    .to_string(),
                security_checklist: vec![
                    "Use TokenInterface instead of raw Program<Token>".to_string(),
                    "Verify mint address and decimals".to_string(),
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
    fn test_get_insight_for_known_id() {
        let insight = TokenSecurityExpert::get_insight_for_id("6.1");
        assert!(insight.is_some());
        let insight = insight.unwrap();
        assert_eq!(insight.name, "Token Program Confusion");
        assert!(!insight.extension_risk_matrix.is_empty());
        assert!(!insight.rust_secure_pattern.is_empty());
        assert!(!insight.security_checklist.is_empty());
    }

    #[test]
    fn test_get_insight_for_sol_id() {
        let insight = TokenSecurityExpert::get_insight_for_id("SOL-010");
        assert!(insight.is_some());
        assert_eq!(insight.unwrap().name, "Token Program Confusion");
    }

    #[test]
    fn test_get_insight_for_unknown_id() {
        assert!(TokenSecurityExpert::get_insight_for_id("99.99").is_none());
        assert!(TokenSecurityExpert::get_insight_for_id("").is_none());
    }

    #[test]
    fn test_risk_matrix_content() {
        let insight = TokenSecurityExpert::get_insight_for_id("6.1").unwrap();
        let (ext, risk, _desc) = &insight.extension_risk_matrix[0];
        assert_eq!(ext, "Transfer Fee");
        assert_eq!(risk, "High");
    }

    #[test]
    fn test_insight_serialization() {
        let insight = TokenSecurityExpert::get_insight_for_id("6.1").unwrap();
        let json = serde_json::to_string(&insight).unwrap();
        assert!(json.contains("Token Program Confusion"));
        let deserialized: TokenInsight = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, insight.name);
    }
}
