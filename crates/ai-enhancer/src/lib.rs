use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Chat completion request (OpenRouter / OpenAI / NVIDIA compatible)
#[derive(Debug, Serialize)]
struct OpenRouterRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_budget: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chat_template_kwargs: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Chat completion response
#[derive(Debug, Deserialize)]
struct OpenRouterResponse {
    choices: Option<Vec<Choice>>,
    error: Option<OpenRouterError>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OpenRouterError {
    message: String,
    code: Option<i32>,
}

/// AI-generated vulnerability analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedExplanation {
    pub technical_explanation: String,
    pub attack_scenario: String,
    pub proof_of_concept: String,
    pub recommended_fix: String,
    pub economic_impact: String,
    pub severity_justification: String,
}

/// Vuln metadata passed to the AI for analysis
#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityInput {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: u8,
    pub code_snippet: String,
    pub file_path: String,
    pub line_number: usize,
}

/// Tuning knobs for AI requests
#[derive(Debug, Clone)]
pub struct AIEnhancerConfig {
    pub model: String,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub concurrency_limit: usize,
    pub temperature: f32,
    pub max_tokens: u32,
}

impl Default for AIEnhancerConfig {
    fn default() -> Self {
        Self {
            model: "anthropic/claude-3.5-sonnet".to_string(),
            max_retries: 3,
            retry_delay_ms: 1000,
            concurrency_limit: 1, // low for rate-limited models
            temperature: 0.3,

            max_tokens: 4096,
        }
    }
}

/// Calls LLM APIs to generate detailed vuln analysis
pub struct AIEnhancer {
    api_key: String,
    config: AIEnhancerConfig,
    client: reqwest::Client,
}

impl AIEnhancer {
    pub fn new(api_key: String, model: String) -> Self {
        let config = AIEnhancerConfig {
            model,
            ..Default::default()
        };
        Self::with_config(api_key, config)
    }

    pub fn with_config(api_key: String, config: AIEnhancerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            config,
            client,
        }
    }

    /// Build the prompt. References Solana runtime internals and real
    /// exploit patterns so the LLM gives actionable analysis, not boilerplate.
    fn generate_prompt(&self, vuln: &VulnerabilityInput) -> String {
        format!(
            r#"You are a senior Solana security engineer who writes production Anchor programs daily. Your job is to explain this vulnerability to a Rust developer who understands Anchor but may not have deep security expertise. Speak their language — reference concrete types, macros, and runtime behavior.

## SOLANA RUNTIME CONTEXT (use this to inform your analysis)
- Solana's Sealevel runtime processes transactions in parallel across accounts. Each instruction receives `AccountInfo` references with `is_signer`, `is_writable`, `owner`, `key`, and `data` fields. The runtime does NOT enforce type safety on account data — programs must validate everything.
- Anchor's `#[derive(Accounts)]` macro generates account validation via 8-byte discriminators and constraint checks. `Account<'info, T>` auto-deserializes and validates owner + discriminator. Raw `AccountInfo<'info>` does neither.
- `#[account(mut)]` marks writable. `#[account(signer)]` or `Signer<'info>` enforces signer. `#[account(has_one = authority)]` cross-references stored pubkeys. Missing any of these is exploitable.
- CPIs via `invoke()` / `invoke_signed()` pass the caller's privileges. If the target program isn't validated, an attacker substitutes a malicious program that mirrors the expected interface but steals funds.
- PDAs derived via `Pubkey::find_program_address(&[seeds], program_id)` return a canonical (address, bump). If you don't store/validate the bump, an attacker can derive a non-canonical PDA at a different address.
- Solana's BPF runtime uses u64 natively. All arithmetic on `u64`/`u128`/`i64` wraps silently in release builds unless you use `checked_*`, `saturating_*`, or enable `overflow-checks = true` in Cargo.toml.
- Account closing requires: (1) transfer ALL lamports to recipient, (2) zero the data buffer, (3) set discriminator to `CLOSED_ACCOUNT_DISCRIMINATOR`. Missing step 2 or 3 allows same-transaction resurrection.

## VULNERABILITY BEING ANALYZED
- **ID**: {id}
- **Pattern**: {title}
- **Scanner Description**: {description}
- **Severity**: {severity}/5 (5=Critical, 4=High, 3=Medium, 2=Low, 1=Info)
- **Source File**: `{file_path}` line {line_number}

## VULNERABLE CODE
```rust
{code}
```

## WHAT I NEED FROM YOU
Respond with a single JSON object (no markdown fencing, no extra text). Every field must be filled in with Solana-specific detail — not generic security advice:

{{
  "technical_explanation": "Explain the root cause in terms of what Solana runtime guarantees are MISSING. Reference specific Anchor types (Account<T>, Signer, UncheckedAccount), specific constraint attrs (#[account(has_one, seeds, constraint)]), and what the BPF runtime does vs what it doesn't do. Name the exact struct fields or function params that are unprotected. 2-3 paragraphs, written for a competent Rust dev.",

  "attack_scenario": "A concrete step-by-step attack a red-teamer would execute. Include: (1) which accounts to create/pass and how to construct them, (2) the exact instruction data to send, (3) what happens inside the program on each step, (4) where the funds flow. Reference actual Solana concepts: transaction instruction layout, compute budget, PDA derivation, CPI forwarding. NOT generic 'attacker calls function'.",

  "proof_of_concept": "A working Solana exploit snippet. For Anchor programs use `anchor_client` or `anchor_lang::InstructionData`. For native programs use `solana_sdk::instruction::Instruction`. Show account metas with `is_signer` / `is_writable` set correctly. Include the malicious account setup. 15-30 lines of real, compilable Rust or TypeScript (using @coral-xyz/anchor).",

  "recommended_fix": "The corrected Rust code using Anchor best practices. Show the FULL fixed struct or function. Use proper Anchor constraints: #[account(mut, has_one = authority)], Signer<'info>, seeds + bump, constraint = ..., etc. If arithmetic, show checked_* or require!() guards. If CPI, show Program<'info, T> validation. Explain each added line in a // comment.",

  "economic_impact": "Calculate impact based on what this program likely handles. Reference real exploits with similar patterns: Wormhole ($320M, missing signer on guardian set), Cashio ($52M, missing mint validation), Mango Markets ($114M, oracle manipulation), Crema Finance ($8.8M, unchecked CPI). Format: 'Estimated $X-$Y at risk. Comparable to [incident] because [reason].'",

  "severity_justification": "Justify using three axes: (1) Exploitability — can this be hit with a single transaction or requires setup? (2) Impact — total fund loss vs partial vs DoS? (3) Likelihood — is this pattern commonly exploited on Solana? Reference CWE ID and CVSS v3.1 base score estimate."
}}

CRITICAL: Output ONLY the raw JSON object. No ```json fencing. No preamble. No explanation outside the JSON."#,
            id = vuln.id,
            title = vuln.title,
            description = vuln.description,
            severity = vuln.severity,
            file_path = vuln.file_path,
            line_number = vuln.line_number,
            code = vuln.code_snippet
        )
    }

    /// Retry wrapper with rate-limit backoff
    async fn call_api_with_retry(&self, prompt: &str) -> Result<String, String> {
        let mut last_error = String::new();
        let max_attempts = 5;

        for attempt in 1..=max_attempts {
            match self.call_api(prompt).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = e.clone();
                    if attempt < max_attempts {
                        // rate limit? back off harder
                        let is_rate_limit = e.contains("429")
                            || e.contains("rate_limit_exceeded")
                            || e.contains("quota");

                        let delay = if is_rate_limit {
                            warn!("Rate limit reached. Waiting 35 seconds before retry...");
                            35000 // clear 3 RPM sliding window
                        } else {
                            self.config.retry_delay_ms * (attempt as u64)
                        };

                        warn!(
                            "API call failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt, max_attempts, e, delay
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                }
            }
        }

        Err(format!(
            "API call failed after {} attempts: {}",
            max_attempts, last_error
        ))
    }

    /// Single API call; auto-detects provider from key prefix
    async fn call_api(&self, prompt: &str) -> Result<String, String> {

        let is_nvidia = self.api_key.starts_with("nvapi-");
        let is_openai = !is_nvidia
            && (self.api_key.starts_with("sk-proj-")
                || (self.api_key.starts_with("sk-") && !self.api_key.starts_with("sk-or-")));

        // nemotron needs special config
        let (max_tokens, reasoning_budget, chat_template_kwargs) =
            if is_nvidia && self.config.model.contains("nemotron") {
                (
                    Some(16384),
                    Some(16384),
                    Some(serde_json::json!({"enable_thinking": true})),
                )
            } else {
                (Some(self.config.max_tokens), None, None)
            };

        // openai uses max_completion_tokens; openrouter/nvidia use max_tokens
        let request = OpenRouterRequest {
            model: self.config.model.clone(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            temperature: if is_openai {
                None
            } else {
                Some(self.config.temperature)
            },
            max_tokens: if is_openai { None } else { max_tokens },
            max_completion_tokens: if is_openai {
                Some(self.config.max_tokens)
            } else {
                None
            },
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

        // openrouter headers
        if !is_openai && !is_nvidia {
            req_builder = req_builder
                .header("HTTP-Referer", "https://solana-security-swarm.local")
                .header("X-Title", "Solana Security Swarm Auditor");
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if !status.is_success() {
            return Err(format!("API returned {}: {}", status, body));
        }

        let parsed: OpenRouterResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse response: {} - Body: {}", e, body))?;

        if let Some(error) = parsed.error {
            return Err(format!("API error: {}", error.message));
        }

        parsed
            .choices
            .and_then(|c| c.into_iter().next())
            .map(|c| c.message.content)
            .ok_or_else(|| "Empty response from API".to_string())
    }

    /// Extract the JSON from whatever wrapping the LLM used
    fn parse_response(&self, response: &str) -> Result<EnhancedExplanation, String> {
        // try raw parse
        if let Ok(parsed) = serde_json::from_str::<EnhancedExplanation>(response.trim()) {
            return Ok(parsed);
        }

        // strip markdown code fences
        let json_str = if response.contains("```json") {
            response
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(response)
        } else if response.contains("```") {
            response.split("```").nth(1).unwrap_or(response)
        } else {
            response
        };

        serde_json::from_str::<EnhancedExplanation>(json_str.trim()).map_err(|e| {
            format!(
                "JSON parse error: {} - Response: {}",
                e,
                &response[..response.len().min(500)]
            )
        })
    }

    /// Enhance one vulnerability with LLM analysis
    pub async fn enhance_vulnerability(
        &self,
        vuln: &VulnerabilityInput,
    ) -> Result<EnhancedExplanation, String> {
        info!("Enhancing vulnerability: {} - {}", vuln.id, vuln.title);

        let prompt = self.generate_prompt(vuln);
        let response = self.call_api_with_retry(&prompt).await?;
        let enhanced = self.parse_response(&response)?;

        info!("Successfully enhanced vulnerability: {}", vuln.id);
        Ok(enhanced)
    }

    /// Enhance a batch with controlled concurrency
    pub async fn enhance_vulnerabilities_batch(
        &self,
        vulns: Vec<VulnerabilityInput>,
    ) -> Vec<(String, Result<EnhancedExplanation, String>)> {
        info!(
            "Starting batch enhancement of {} vulnerabilities",
            vulns.len()
        );

        let results: Vec<_> = stream::iter(vulns)
            .map(|vuln| async move {
                let id = vuln.id.clone();
                let result = self.enhance_vulnerability(&vuln).await;
                (id, result)
            })
            .buffer_unordered(self.config.concurrency_limit)
            .collect()
            .await;

        let success_count = results.iter().filter(|(_, r)| r.is_ok()).count();
        info!(
            "Batch enhancement complete: {}/{} successful",
            success_count,
            results.len()
        );

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parsing_clean() {
        let json = r#"{
            "technical_explanation": "The code lacks signer verification.",
            "attack_scenario": "Attacker calls instruction directly.",
            "proof_of_concept": "// exploit code here",
            "recommended_fix": "Add Signer constraint.",
            "economic_impact": "$100k - $1M",
            "severity_justification": "Critical due to direct fund access."
        }"#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(json);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().technical_explanation,
            "The code lacks signer verification."
        );
    }

    #[test]
    fn test_json_parsing_with_markdown() {
        let response = r#"Here's my analysis:

```json
{
    "technical_explanation": "Missing signer check.",
    "attack_scenario": "Direct call.",
    "proof_of_concept": "code",
    "recommended_fix": "Add check.",
    "economic_impact": "$50k",
    "severity_justification": "High risk."
}
```

Hope this helps!"#;

        let enhancer = AIEnhancer::new("test".to_string(), "test".to_string());
        let result = enhancer.parse_response(response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prompt_generation() {
        let vuln = VulnerabilityInput {
            id: "1.1".to_string(),
            title: "Missing Signer Check".to_string(),
            description: "Authority not verified".to_string(),
            severity: 5,
            code_snippet: "pub authority: AccountInfo<'info>".to_string(),
            file_path: "src/lib.rs".to_string(),
            line_number: 42,
        };

        let enhancer = AIEnhancer::new(
            "test".to_string(),
            "anthropic/claude-3.5-sonnet".to_string(),
        );
        let prompt = enhancer.generate_prompt(&vuln);

        assert!(prompt.contains("Missing Signer Check"));
        assert!(prompt.contains("src/lib.rs:42"));
        assert!(prompt.contains("JSON object"));
    }
}
