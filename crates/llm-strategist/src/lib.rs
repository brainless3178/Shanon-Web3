use program_analyzer::VulnerabilityFinding;
use serde::{Deserialize, Serialize};

pub struct LlmStrategist {
    api_key: String,
    model: String,
    client: reqwest::Client,
}

impl LlmStrategist {
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            api_key,
            model,
            client: reqwest::Client::new(),
        }
    }


    pub fn api_key(&self) -> &str {
        &self.api_key
    }


    pub fn model(&self) -> &str {
        &self.model
    }

    /// Ask the LLM to generate a concrete exploit given a vulnerability + code
    pub async fn generate_exploit_strategy(
        &self,
        vulnerability: &VulnerabilityFinding,
        instruction_code: &str,
    ) -> Result<ExploitStrategy, StrategistError> {
        let prompt = self.build_exploit_prompt(vulnerability, instruction_code);

        let response = self.call_llm(&prompt).await?;

        self.parse_strategy_response(&response)
    }

    fn build_exploit_prompt(&self, vulnerability: &VulnerabilityFinding, code: &str) -> String {
        format!(
            r#"
You are a security researcher analyzing a Solana smart contract vulnerability.

VULNERABILITY DETECTED:
Type: {}
Severity: {}/5
Location: {}
Description: {}

INSTRUCTION SOURCE CODE:
```rust
{}
```

Your task: Generate a CONCRETE exploit strategy.

Provide:
1. attack_vector: Exactly what input/action triggers the vulnerability
2. payload: Concrete values to send (use actual numbers like 18446744073709551615 for u64::MAX)
3. expected_outcome: What happens when exploit succeeds (error code or state change)
4. explanation: 2-sentence technical explanation

Format as JSON:
{{
    "attack_vector": "...",
    "payload": {{
        "amount": 18446744073709551615,
        "recipient": "PUBKEY_STRING"
    }},
    "expected_outcome": "Program error 0x1770 (Arithmetic overflow)",
    "explanation": "..."
}}
NOTE: ensure payload keys match instruction argument names exactly.
"#,
            vulnerability.vuln_type,
            vulnerability.severity,
            vulnerability.location,
            vulnerability.description,
            code
        )
    }

    async fn call_llm(&self, prompt: &str) -> Result<String, StrategistError> {
        // detect provider from key prefix
        let is_nvidia = self.api_key.starts_with("nvapi-");
        let is_openai = !is_nvidia
            && (self.api_key.starts_with("sk-proj-")
                || (self.api_key.starts_with("sk-") && !self.api_key.starts_with("sk-or-")));

        // model-specific config
        let (max_tokens, reasoning_budget, chat_template_kwargs) = if is_nvidia {
            // Moonshot AI Kimi K2.5 via NVIDIA API
            if self.model.contains("kimi") || self.model.contains("moonshot") {
                (
                    Some(16384), // Kimi K2.5 supports up to 16K tokens
                    None,
                    Some(serde_json::json!({"thinking": true})),
                )
            }
            else if self.model.contains("nemotron") {
                (
                    Some(16384),
                    Some(16384),
                    Some(serde_json::json!({"enable_thinking": true})),
                )
            }
            else {
                (Some(4096), None, None)
            }
        } else {
            (Some(4096), None, None)
        };

        let request = OpenRouterRequest {
            model: self.model.clone(),
            messages: vec![OpenRouterMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: if is_openai { None } else { Some(1.0) },
            max_tokens,
            reasoning_budget,
            chat_template_kwargs,
        };

        let api_url = if is_nvidia {
            "https://integrate.api.nvidia.com/v1/chat/completions"
        } else if is_openai {
            "https://api.openai.com/v1/chat/completions"
        } else {
            "https://openrouter.ai/api/v1/chat/completions"
        };

        let mut req_builder = self
            .client
            .post(api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json");

        if !is_openai && !is_nvidia {
            req_builder = req_builder
                .header("HTTP-Referer", "https://solana-security-swarm.ai")
                .header("X-Title", "Solana Security Swarm");
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| StrategistError::Http(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(StrategistError::Api(format!(
                "LLM API error ({}): {}",
                status, error_text
            )));
        }

        let or_response: OpenRouterResponse = response
            .json()
            .await
            .map_err(|e| StrategistError::Http(e.to_string()))?;

        if or_response.choices.is_empty() {
            return Err(StrategistError::Api("Empty response from LLM".to_string()));
        }

        Ok(or_response.choices[0].message.content.clone())
    }

    fn parse_strategy_response(&self, response: &str) -> Result<ExploitStrategy, StrategistError> {
        // strip markdown fencing if present
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(response)
        } else {
            response
        };

        let strategy: ExploitStrategy = serde_json::from_str(json_str.trim())?;

        Ok(strategy)
    }

    pub async fn infer_system_invariants(
        &self,
        program_code: &str,
    ) -> Result<Vec<LogicInvariant>, StrategistError> {
        let prompt = format!(
            r#"
You are a formal methods engineer specialized in Solana security.
Analyze the following Anchor program code and identify CRITICAL logical invariants that must hold for the system to remain secure and solvent.

CODE:
```rust
{}
```

Identify invariants concerning:
1. Total Supply vs. Reserved Liquidity
2. User Balance consistency
3. Authorization mapping (e.g. only owner can withdraw)
4. State transition rules

Provide findings as a JSON array of objects:
{{
    "name": "short_name",
    "description": "what this invariant ensures",
    "formal_property": "Z3-like logical expression (e.g. user_balance <= total_vault_balance)",
    "failure_impact": "what happens if violated"
}}

Output ONLY the JSON array.
"#,
            program_code
        );

        let response = self.call_llm(&prompt).await?;

        let invariants: Vec<LogicInvariant> = if response.contains("[") {
            let json_str = response
                .split("[")
                .nth(1)
                .and_then(|s| s.rsplit("]").nth(0))
                .map(|s| format!("[{}]", s))
                .unwrap_or(response.clone());
            serde_json::from_str(&json_str)?
        } else {
            Vec::new()
        };

        Ok(invariants)
    }

    /// Enhance a finding with AI-generated insights
    pub async fn enhance_finding(
        &self,
        description: &str,
        attack_scenario: &str,
    ) -> Result<EnhancedFinding, StrategistError> {
        self.enhance_finding_with_context(description, attack_scenario, None, None)
            .await
    }

    /// Enhance with code context and related functions
    pub async fn enhance_finding_with_context(
        &self,
        description: &str,
        attack_scenario: &str,
        code_snippet: Option<&str>,
        related_functions: Option<&str>,
    ) -> Result<EnhancedFinding, StrategistError> {
        let prompt = format!(
            r#"You are a Solana protocol engineer reviewing a security finding from an automated scanner. Your audience is Rust developers shipping Anchor programs. Be precise — reference actual types, constraints, and runtime behavior.

## SOLANA CONTEXT (use to ground your analysis)
- The Sealevel runtime passes `AccountInfo` refs to each instruction. The runtime checks `is_signer` and `is_writable` flags but does NOT validate account data, ownership, or relationships — that's the program's job.
- Anchor's `Account<'info, T>` wrapper validates: (1) owner == program ID, (2) first 8 bytes match discriminator for T, (3) deserializes data as T. Using raw `AccountInfo` skips ALL of this.
- `Signer<'info>` enforces `is_signer == true`. `#[account(has_one = authority)]` checks `account.authority == authority.key()`. `#[account(seeds = [...], bump)]` validates PDA derivation.
- CPIs via `invoke_signed()` forward PDA signer seeds. If you don't validate the CPI target program with `Program<'info, T>`, an attacker can substitute a malicious program.
- Solana arithmetic wraps in release mode (BPF). `u64` overflows silently. Use `checked_add()`, `checked_sub()`, `checked_mul()`, or set `overflow-checks = true` in `[profile.release]`.
- Token program CPIs (transfer, mint_to, burn) require the token account's `authority` to sign. If this isn't validated, anyone can drain the account.
- Account closing: Anchor's `#[account(close = recipient)]` handles it correctly. Manual closing needs: zero data, transfer all lamports, set closed discriminator.
- Real Solana exploits to reference: Wormhole ($320M, unvalidated guardian signer), Cashio ($52M, unchecked mint in CPI), Mango Markets ($114M, oracle manipulation), Crema Finance ($8.8M, CPI to wrong program), Slope ($8M, key logging).

## FINDING TO ANALYZE
**Description:** {description}
**Attack Scenario from Scanner:** {attack_scenario}

{code_section}{related_section}

## PROVIDE YOUR ANALYSIS AS JSON
Every field must be specific to Solana's runtime model and Anchor's type system. No generic web3 advice:

{{
    "explanation": "Root cause analysis referencing specific Solana runtime guarantees that are missing. Name the exact Anchor type or constraint that should be used. Explain what the BPF runtime does and doesn't validate. 3-5 sentences, written for a Rust dev who knows Anchor but not security.",
    "vulnerability_type": "The precise Solana vulnerability category. Use standard names: Missing Signer Check, Integer Overflow, Type Cosplay, Arbitrary CPI, PDA Seed Collision, Oracle Manipulation, Unchecked Account Owner, Reinitialization, Account Resurrection, Insufficient Constraints, etc.",
    "attack_vector": "Step-by-step exploit execution: (1) what accounts to create/pass, (2) what instruction data to send, (3) what happens inside the program at each step, (4) where funds flow. Show concrete Solana operations — PDA derivation, CPI calls, token transfers — not abstract descriptions.",
    "economic_impact": "CRITICAL | HIGH | MEDIUM | LOW — with justification based on what funds this program likely handles and comparable real Solana exploit losses.",
    "exploit_difficulty": "trivial | easy | medium | hard — based on: does the attacker need capital (flash loan)? does it require timing? can a single transaction drain everything?",
    "poc_code": "15-30 lines of compilable Rust or TypeScript exploit code using @coral-xyz/anchor or solana_sdk. Show AccountMeta setup with correct is_signer/is_writable flags. Show the malicious instruction. This should be paste-and-run level quality.",
    "fix_code": "15-30 lines of the corrected Anchor struct or instruction handler. Use proper constraints: #[account(mut, has_one = authority @ ErrorCode::Unauthorized)], Signer<'info>, seeds + bump, Program<'info, Token>. Comment each security-critical line.",
    "fix_explanation": "Explain what each added constraint does in Anchor terms. Example: '#[account(has_one = authority)] makes Anchor check that vault.authority == authority.key() before deserialization succeeds, so passing someone else's vault reverts with ConstraintHasOne error.'",
    "related_exploits": ["Real Solana mainnet exploits with this pattern. Include project name, loss amount, and date. Empty array if none known."],
    "detection_evasion": "How an attacker might hide exploitation: batched transactions, use of intermediate accounts, CPI chains to obfuscate, timing relative to oracle updates, etc.",
    "monitoring_recommendation": "What on-chain signals to monitor: unexpected CPI targets, authority changes, large single-tx balance changes, PDA collisions, account closures followed by re-creation in same slot."
}}

Output ONLY the raw JSON. No markdown fencing. No preamble."#,
            description = description,
            attack_scenario = attack_scenario,
            code_section = code_snippet
                .map(|c| format!("\n**Vulnerable Code:**\n```rust\n{}\n```\n", c))
                .unwrap_or_default(),
            related_section = related_functions
                .map(|f| format!("\n**Related Functions:**\n{}\n", f))
                .unwrap_or_default(),
        );

        let response = self.call_llm(&prompt).await?;

        // parse the response
        let enhanced = self.parse_enhanced_finding(&response, description, attack_scenario)?;

        Ok(enhanced)
    }

    /// Best-effort parse of LLM JSON with fallback to raw text
    fn parse_enhanced_finding(
        &self,
        response: &str,
        original_description: &str,
        original_attack: &str,
    ) -> Result<EnhancedFinding, StrategistError> {
        // extract JSON block from response
        let json_str = if response.contains("{") {
            let start = response.find('{').unwrap_or(0);
            let end = response.rfind('}').map(|i| i + 1).unwrap_or(response.len());
            &response[start..end]
        } else {
            response
        };

        // try structured parse
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
            Ok(EnhancedFinding {
                explanation: parsed
                    .get("explanation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("AI analysis not available")
                    .to_string(),
                vulnerability_type: parsed
                    .get("vulnerability_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                description: original_description.to_string(),
                attack_scenario: parsed
                    .get("attack_vector")
                    .and_then(|v| v.as_str())
                    .unwrap_or(original_attack)
                    .to_string(),
                fix_suggestion: parsed
                    .get("fix_explanation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Review and fix the identified issue.")
                    .to_string(),
                economic_impact: parsed
                    .get("economic_impact")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                exploit_difficulty: parsed
                    .get("exploit_difficulty")
                    .and_then(|v| v.as_str())
                    .unwrap_or("medium")
                    .to_string(),
                poc_code: parsed
                    .get("poc_code")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                fix_code: parsed
                    .get("fix_code")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                related_exploits: parsed
                    .get("related_exploits")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default(),
                monitoring_recommendation: parsed
                    .get("monitoring_recommendation")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })
        } else {
            // fallback: raw text as explanation
            Ok(EnhancedFinding {
                explanation: if response.len() > 50 {
                    response.to_string()
                } else {
                    format!("AI analysis of: {}", original_description)
                },
                vulnerability_type: "Unknown".to_string(),
                description: original_description.to_string(),
                attack_scenario: original_attack.to_string(),
                fix_suggestion: "Review and fix the identified issue.".to_string(),
                economic_impact: "UNKNOWN".to_string(),
                exploit_difficulty: "medium".to_string(),
                poc_code: None,
                fix_code: None,
                related_exploits: vec![],
                monitoring_recommendation: None,
            })
        }
    }
}

/// LLM-enriched vulnerability report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedFinding {
    /// Detailed technical explanation of the vulnerability
    pub explanation: String,
    /// Category of vulnerability (e.g., "Missing Signer Check")
    pub vulnerability_type: String,
    /// Original description
    pub description: String,
    /// Step-by-step attack scenario
    pub attack_scenario: String,
    /// How to fix the vulnerability
    pub fix_suggestion: String,
    /// Economic impact assessment (LOW/MEDIUM/HIGH/CRITICAL)
    pub economic_impact: String,
    /// How difficult to exploit (trivial/easy/medium/hard)
    pub exploit_difficulty: String,
    /// Proof-of-concept code
    pub poc_code: Option<String>,
    /// Secure code fix
    pub fix_code: Option<String>,
    /// Similar real-world exploits
    pub related_exploits: Vec<String>,
    /// What to monitor for exploitation attempts
    pub monitoring_recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicInvariant {
    pub name: String,
    pub description: String,
    pub formal_property: String,
    pub failure_impact: String,
}

#[derive(Debug, Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<OpenRouterMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct OpenRouterMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenRouterResponse {
    choices: Vec<OpenRouterChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterChoice {
    message: OpenRouterChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct OpenRouterChoiceMessage {
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExploitStrategy {
    pub attack_vector: String,
    pub payload: serde_json::Value,
    pub expected_outcome: String,
    pub explanation: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StrategistError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("API error: {0}")]
    Api(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_strategist() -> LlmStrategist {
        LlmStrategist::new("test-key".to_string(), "test-model".to_string())
    }

    #[test]
    fn test_strategist_creation() {
        let s = make_strategist();
        assert_eq!(s.api_key(), "test-key");
        assert_eq!(s.model(), "test-model");
    }

    #[test]
    fn test_parse_strategy_response_valid_json() {
        let s = make_strategist();
        let response = r#"{
            "attack_vector": "Send u64::MAX as amount",
            "payload": {"amount": 18446744073709551615},
            "expected_outcome": "Overflow error",
            "explanation": "Causes arithmetic overflow."
        }"#;
        let result = s.parse_strategy_response(response);
        assert!(result.is_ok());
        let strategy = result.unwrap();
        assert_eq!(strategy.attack_vector, "Send u64::MAX as amount");
        assert_eq!(strategy.expected_outcome, "Overflow error");
    }

    #[test]
    fn test_parse_strategy_response_markdown_wrapped() {
        let s = make_strategist();
        let response = "Here is the strategy:\n```json\n{\"attack_vector\": \"test\", \"payload\": {}, \"expected_outcome\": \"err\", \"explanation\": \"x\"}\n```";
        let result = s.parse_strategy_response(response);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().attack_vector, "test");
    }

    #[test]
    fn test_parse_strategy_response_invalid() {
        let s = make_strategist();
        let result = s.parse_strategy_response("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_exploit_strategy_default() {
        let strategy = ExploitStrategy::default();
        assert!(strategy.attack_vector.is_empty());
        assert!(strategy.explanation.is_empty());
    }

    #[test]
    fn test_exploit_strategy_serialization() {
        let strategy = ExploitStrategy {
            attack_vector: "overflow".to_string(),
            payload: serde_json::json!({"amount": 100}),
            expected_outcome: "error".to_string(),
            explanation: "test".to_string(),
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let deserialized: ExploitStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.attack_vector, "overflow");
    }

    #[test]
    fn test_logic_invariant_serialization() {
        let invariant = LogicInvariant {
            name: "balance_conservation".to_string(),
            description: "Total supply must equal sum of balances".to_string(),
            formal_property: "total_supply == sum(balances)".to_string(),
            failure_impact: "Token inflation".to_string(),
        };
        let json = serde_json::to_string(&invariant).unwrap();
        let deserialized: LogicInvariant = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "balance_conservation");
    }

    #[test]
    fn test_enhanced_finding_serialization() {
        let finding = EnhancedFinding {
            explanation: "test explanation".to_string(),
            vulnerability_type: "Missing Signer".to_string(),
            description: "desc".to_string(),
            attack_scenario: "scenario".to_string(),
            fix_suggestion: "fix".to_string(),
            economic_impact: "HIGH".to_string(),
            exploit_difficulty: "easy".to_string(),
            poc_code: Some("let x = 1;".to_string()),
            fix_code: None,
            related_exploits: vec!["Wormhole".to_string()],
            monitoring_recommendation: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("Missing Signer"));
        assert!(json.contains("Wormhole"));
    }

    #[test]
    fn test_build_exploit_prompt() {
        let s = make_strategist();
        let vuln = program_analyzer::VulnerabilityFinding {
            id: "2.1".to_string(),
            category: "Arithmetic".to_string(),
            vuln_type: "Integer Overflow".to_string(),
            severity: 4,
            severity_label: "High".to_string(),
            cwe: Some("CWE-190".to_string()),
            location: "line 42".to_string(),
            function_name: "deposit".to_string(),
            line_number: 42,
            vulnerable_code: "amount + fee".to_string(),
            description: "Unchecked arithmetic".to_string(),
            attack_scenario: "Send max u64 value".to_string(),
            real_world_incident: None,
            secure_fix: "Use checked_add".to_string(),
            prevention: "Always use checked math".to_string(),
        };
        let prompt = s.build_exploit_prompt(&vuln, "pub fn deposit() {}");
        assert!(prompt.contains("Integer Overflow"));
        assert!(prompt.contains("pub fn deposit"));
        assert!(prompt.contains("attack_vector"));
    }
}
