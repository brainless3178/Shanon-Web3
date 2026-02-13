//! Certora Prover Output Parser
//!
//! Parses the output of `certoraSolanaProver` and the Certora dashboard
//! results into structured `RuleVerificationResult` objects.
//!
//! The Certora Prover output contains:
//! - Rule status: PASSED / FAILED / TIMEOUT
//! - Counterexamples for failed rules
//! - Call trace analysis
//! - Sanity check results (vacuity, reachability)

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Parses Certora Prover output into structured results.
#[allow(dead_code)]
pub struct CertoraResultParser {
    rule_result_re: Regex,
    counterexample_re: Regex,
    job_url_re: Regex,
    summary_re: Regex,
}

impl CertoraResultParser {
    pub fn new() -> Self {
        Self {
            // Match lines like: "rule_name: PASSED" or "rule_name: FAILED (counterexample found)"
            rule_result_re: Regex::new(
                r"(?m)(?:Rule\s+)?([\w_]+)\s*:\s*(PASSED|FAILED|TIMEOUT|VIOLATED|VERIFIED|SANITY_FAILED)"
            ).unwrap(),
            // Match counterexample blocks
            counterexample_re: Regex::new(
                r"(?ms)Counterexample for ([\w_]+):?\s*\n(.*?)(?:\n\n|\z)"
            ).unwrap(),
            // Match job URL
            job_url_re: Regex::new(
                r"https://prover\.certora\.com/output/[\w/\-]+"
            ).unwrap(),
            // Match summary lines
            summary_re: Regex::new(
                r"(?m)(\d+)\s+rules?\s+(passed|verified|failed|violated|timed?\s*out)"
            ).unwrap(),
        }
    }

    /// Parse raw Certora Prover output into structured results.
    pub fn parse_output(&self, raw_output: &str) -> Vec<RuleVerificationResult> {
        let mut results = Vec::new();

        // Try JSON parse first (Certora outputs JSON when using --json flag)
        if let Some(json_results) = self.try_parse_json(raw_output) {
            return json_results;
        }

        // Parse text output
        for caps in self.rule_result_re.captures_iter(raw_output) {
            let rule_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let status_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            let status = match status_str {
                "PASSED" | "VERIFIED" => RuleStatus::Passed,
                "FAILED" | "VIOLATED" => RuleStatus::Failed,
                "TIMEOUT" => RuleStatus::Timeout,
                "SANITY_FAILED" => RuleStatus::SanityFailed,
                _ => RuleStatus::Unknown,
            };

            // Look for counterexample
            let counterexample = self.extract_counterexample(raw_output, &rule_name);

            // Determine category from rule name
            let category = Self::categorize_rule(&rule_name);
            let severity = Self::severity_from_rule(&rule_name);

            results.push(RuleVerificationResult {
                rule_name: rule_name.clone(),
                status,
                description: format!("Certora formal verification of rule '{}'", rule_name),
                counterexample,
                source_location: None,
                severity,
                category,
            });
        }

        // If no structured results found, try to parse line-by-line
        if results.is_empty() {
            results = self.parse_line_by_line(raw_output);
        }

        if results.is_empty() {
            debug!(
                "No verification results parsed from Certora output ({} bytes)",
                raw_output.len()
            );
        }

        results
    }

    /// Try to parse JSON-formatted Certora output.
    fn try_parse_json(&self, raw_output: &str) -> Option<Vec<RuleVerificationResult>> {
        // Look for JSON arrays or objects in the output
        let json_start = raw_output.find('[')?;
        let json_end = raw_output.rfind(']')? + 1;

        if json_start >= json_end {
            return None;
        }

        let json_str = &raw_output[json_start..json_end];

        // Try to parse as an array of rule results
        if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
            let mut results = Vec::new();

            for item in &json_array {
                let rule_name = item
                    .get("rule")
                    .or_else(|| item.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if rule_name.is_empty() {
                    continue;
                }

                let status_str = item
                    .get("status")
                    .or_else(|| item.get("result"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");

                let status = match status_str.to_uppercase().as_str() {
                    "PASSED" | "VERIFIED" | "TRUE" => RuleStatus::Passed,
                    "FAILED" | "VIOLATED" | "FALSE" => RuleStatus::Failed,
                    "TIMEOUT" => RuleStatus::Timeout,
                    "SANITY_FAILED" | "SANITY" => RuleStatus::SanityFailed,
                    _ => RuleStatus::Unknown,
                };

                let counterexample = item
                    .get("counterexample")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let category = item
                    .get("category")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| Self::categorize_rule(&rule_name));

                let severity = item
                    .get("severity")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u8)
                    .unwrap_or_else(|| Self::severity_from_rule(&rule_name));

                let description = item
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                results.push(RuleVerificationResult {
                    rule_name,
                    status,
                    description,
                    counterexample,
                    source_location: item
                        .get("source_location")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    severity,
                    category,
                });
            }

            if !results.is_empty() {
                return Some(results);
            }
        }

        None
    }

    /// Parse output line by line for less structured formats.
    fn parse_line_by_line(&self, raw_output: &str) -> Vec<RuleVerificationResult> {
        let mut results = Vec::new();
        let bracket_re = Regex::new(r"\[(\w+)\]\s+([\w_]+)").ok();
        let checking_re = Regex::new(r"(?:Checking|Verifying)\s+([\w_]+)\s*\.{2,}\s*(\w+)").ok();

        for line in raw_output.lines() {
            let trimmed = line.trim();

            // Skip empty lines and non-result lines
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            // Look for patterns like "[PASS] rule_name" or "[FAIL] rule_name"
            if let Some(caps) = bracket_re
                .as_ref()
                .and_then(|re| re.captures(trimmed))
            {
                let status_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let rule_name = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();

                let status = match status_str.to_uppercase().as_str() {
                    "PASS" | "PASSED" | "OK" | "VERIFIED" => RuleStatus::Passed,
                    "FAIL" | "FAILED" | "VIOLATED" => RuleStatus::Failed,
                    "TIMEOUT" | "TIME" => RuleStatus::Timeout,
                    "SANITY" => RuleStatus::SanityFailed,
                    _ => continue,
                };

                results.push(RuleVerificationResult {
                    rule_name: rule_name.clone(),
                    status,
                    description: format!("Rule '{}'", rule_name),
                    counterexample: None,
                    source_location: None,
                    severity: Self::severity_from_rule(&rule_name),
                    category: Self::categorize_rule(&rule_name),
                });
            }

            // Look for "Checking rule_name ... PASSED/FAILED"
            if let Some(caps) = checking_re
                .as_ref()
                .and_then(|re| re.captures(trimmed))
            {
                let rule_name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                let status_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                let status = match status_str.to_uppercase().as_str() {
                    "PASSED" | "VERIFIED" | "OK" => RuleStatus::Passed,
                    "FAILED" | "VIOLATED" => RuleStatus::Failed,
                    "TIMEOUT" => RuleStatus::Timeout,
                    _ => continue,
                };

                results.push(RuleVerificationResult {
                    rule_name: rule_name.clone(),
                    status,
                    description: format!("Rule '{}'", rule_name),
                    counterexample: None,
                    source_location: None,
                    severity: Self::severity_from_rule(&rule_name),
                    category: Self::categorize_rule(&rule_name),
                });
            }
        }

        results
    }

    /// Extract counterexample for a specific rule from the output.
    fn extract_counterexample(&self, raw_output: &str, rule_name: &str) -> Option<String> {
        for caps in self.counterexample_re.captures_iter(raw_output) {
            let matched_rule = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if matched_rule == rule_name {
                return caps.get(2).map(|m| m.as_str().trim().to_string());
            }
        }
        None
    }

    /// Categorize a rule based on its name.
    fn categorize_rule(rule_name: &str) -> String {
        if rule_name.contains("solvency") || rule_name.contains("balance") {
            "Solvency / Balance Conservation".into()
        } else if rule_name.contains("reentrancy") || rule_name.contains("cpi") {
            "Reentrancy / CPI Safety".into()
        } else if rule_name.contains("authority")
            || rule_name.contains("signer")
            || rule_name.contains("access")
        {
            "Access Control".into()
        } else if rule_name.contains("init") {
            "Initialization Safety".into()
        } else if rule_name.contains("overflow") || rule_name.contains("arithmetic") {
            "Arithmetic Safety".into()
        } else if rule_name.contains("stack") {
            "Stack Safety".into()
        } else if rule_name.contains("discriminator") {
            "Account Validation".into()
        } else if rule_name.contains("compute") || rule_name.contains("budget") {
            "Resource Limits".into()
        } else if rule_name.contains("owner") {
            "Account Ownership".into()
        } else if rule_name.contains("rent") {
            "Rent Safety".into()
        } else if rule_name.contains("pda") {
            "PDA Validation".into()
        } else if rule_name.contains("wx")
            || rule_name.contains("writable")
            || rule_name.contains("memory")
        {
            "Memory Safety".into()
        } else if rule_name.contains("entry") {
            "Binary Integrity".into()
        } else if rule_name.starts_with("sbf_pattern") {
            "SBF Bytecode Pattern".into()
        } else {
            "General Verification".into()
        }
    }

    /// Determine severity from rule name.
    fn severity_from_rule(rule_name: &str) -> u8 {
        if rule_name.contains("solvency")
            || rule_name.contains("reentrancy")
            || rule_name.contains("authority")
            || rule_name.contains("signer")
            || rule_name.contains("discriminator")
            || rule_name.contains("wx")
            || rule_name.contains("cpi")
            || rule_name.contains("entry_point")
        {
            5 // Critical
        } else if rule_name.contains("overflow")
            || rule_name.contains("init")
            || rule_name.contains("owner")
            || rule_name.contains("pda")
        {
            4 // High
        } else {
            3 // Medium (including rent, compute, stack, and default)
        }
    }
}

impl Default for CertoraResultParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// Result of verifying a single CVLR rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleVerificationResult {
    /// The rule name (e.g. `rule_withdraw_solvency`)
    pub rule_name: String,
    /// Verification status
    pub status: RuleStatus,
    /// Description of what this rule checks
    pub description: String,
    /// Counterexample if the rule failed
    pub counterexample: Option<String>,
    /// Source location if available
    pub source_location: Option<String>,
    /// Severity (1-5)
    pub severity: u8,
    /// Category of the check
    pub category: String,
}

/// Status of a single rule verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleStatus {
    /// The assertion holds for all possible states
    Passed,
    /// A counterexample was found that violates the assertion
    Failed,
    /// The SMT solver timed out — property is unknown
    Timeout,
    /// Rule sanity check failed (vacuity, unreachability)
    SanityFailed,
    /// Unknown/unparseable status
    Unknown,
}
