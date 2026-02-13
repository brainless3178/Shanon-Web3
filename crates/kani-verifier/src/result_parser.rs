//! Kani Result Parser
//!
//! Parses the output of `cargo kani` / CBMC and converts it into structured
//! `PropertyCheckResult` values that can be consumed by the audit report.
//!
//! Kani output format includes lines like:
//! ```text
//! RESULTS:
//! proof_name::proof_fn_name
//!  - Status: SUCCESS
//!  - Description: "..."
//!
//! ** 1 of 1 successfully verified
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Parses raw Kani/CBMC output into structured results.
#[allow(dead_code)]
pub struct KaniResultParser {
    property_regex: Regex,
    status_regex: Regex,
    counterexample_regex: Regex,
    summary_regex: Regex,
    trace_regex: Regex,
}

impl KaniResultParser {
    pub fn new() -> Self {
        Self {
            property_regex: Regex::new(r"(?m)^Check\s+(\d+):\s*(.+?)$").unwrap(),
            status_regex: Regex::new(
                r"(?m)^\s*-\s*Status:\s*(SUCCESS|FAILURE|UNDETERMINED|UNREACHABLE)",
            )
            .unwrap(),
            counterexample_regex: Regex::new(r"(?m)COUNTEREXAMPLE:(?:.|\n)*?END COUNTEREXAMPLE")
                .unwrap(),
            summary_regex: Regex::new(
                r"(?m)\*\*\s*(\d+)\s*of\s*(\d+)\s*(successfully verified|failed)",
            )
            .unwrap(),
            trace_regex: Regex::new(r"(?m)Trace for (.+?):\n").unwrap(),
        }
    }

    /// Parse the full output from `cargo kani` into structured results.
    pub fn parse_output(&self, output: &str) -> Vec<PropertyCheckResult> {
        let mut results = Vec::new();

        // Strategy 1: Parse Kani's standard result format
        results.extend(self.parse_kani_format(output));

        // Strategy 2: Parse CBMC's property-check format
        if results.is_empty() {
            results.extend(self.parse_cbmc_format(output));
        }

        // Strategy 3: Parse verification summary
        if results.is_empty() {
            results.extend(self.parse_summary_format(output));
        }

        results
    }

    /// Parse Kani's standard output format.
    fn parse_kani_format(&self, output: &str) -> Vec<PropertyCheckResult> {
        let mut results = Vec::new();

        // Split by "=== Harness:" markers
        let harness_sections: Vec<&str> = output.split("=== Harness:").collect();

        for section in harness_sections.iter().skip(1) {
            let harness_name = section
                .lines()
                .next()
                .map(|l| l.trim().trim_end_matches("===").trim())
                .unwrap_or("unknown");

            // Look for VERIFICATION:- SUCCESSFUL or VERIFICATION:- FAILED
            let status = if section.contains("VERIFICATION:- SUCCESSFUL")
                || section.contains("VERIFICATION SUCCESSFUL")
                || section.contains("successfully verified")
            {
                CheckStatus::Success
            } else if section.contains("VERIFICATION:- FAILED")
                || section.contains("VERIFICATION FAILED")
                || section.contains("failed")
            {
                CheckStatus::Failure
            } else {
                CheckStatus::Undetermined
            };

            // Extract property descriptions
            let mut description = String::new();
            for line in section.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("- Description:") {
                    description = trimmed
                        .trim_start_matches("- Description:")
                        .trim()
                        .to_string();
                } else if trimmed.contains("assertion")
                    && description.is_empty() {
                        description = trimmed.to_string();
                    }
            }

            if description.is_empty() {
                description = format!("Property check for harness '{}'", harness_name);
            }

            // Extract counterexample if verification failed
            let counterexample = if status == CheckStatus::Failure {
                self.extract_counterexample(section)
            } else {
                None
            };

            // Extract trace
            let trace = self.extract_trace(section);

            results.push(PropertyCheckResult {
                property_name: harness_name.to_string(),
                status,
                description,
                source_location: String::new(),
                counterexample,
                trace,
                category: "KaniVerification".to_string(),
            });
        }

        results
    }

    /// Parse CBMC-style property check output.
    fn parse_cbmc_format(&self, output: &str) -> Vec<PropertyCheckResult> {
        let mut results = Vec::new();
        let mut _current_check: Option<(String, String)> = None;

        for line in output.lines() {
            let trimmed = line.trim();

            // "Check N: property_name"
            if let Some(caps) = self.property_regex.captures(trimmed) {
                let check_num = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let property = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                _current_check = Some((check_num.to_string(), property.to_string()));
            }

            // "[property_name] status
            if trimmed.contains("[") && trimmed.contains("]") {
                let status = if trimmed.contains("SUCCESS") || trimmed.contains("OK") {
                    CheckStatus::Success
                } else if trimmed.contains("FAILURE") || trimmed.contains("FAILED") {
                    CheckStatus::Failure
                } else {
                    CheckStatus::Undetermined
                };

                // Extract property name from brackets
                if let Some(start) = trimmed.find('[') {
                    if let Some(end) = trimmed.find(']') {
                        let property_name = &trimmed[start + 1..end];
                        results.push(PropertyCheckResult {
                            property_name: property_name.to_string(),
                            status,
                            description: trimmed.to_string(),
                            source_location: String::new(),
                            counterexample: None,
                            trace: None,
                            category: "CBMCPropertyCheck".to_string(),
                        });
                    }
                }
            }
        }

        results
    }

    /// Parse summary-level output.
    fn parse_summary_format(&self, output: &str) -> Vec<PropertyCheckResult> {
        let mut results = Vec::new();

        for caps in self.summary_regex.captures_iter(output) {
            let count = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<usize>().ok())
                .unwrap_or(0);
            let total = caps
                .get(2)
                .and_then(|m| m.as_str().parse::<usize>().ok())
                .unwrap_or(0);
            let result_type = caps.get(3).map(|m| m.as_str()).unwrap_or("");

            let status = if result_type.contains("success") {
                CheckStatus::Success
            } else {
                CheckStatus::Failure
            };

            results.push(PropertyCheckResult {
                property_name: format!("verification_summary_{}", count),
                status,
                description: format!("{} of {} properties {}", count, total, result_type),
                source_location: String::new(),
                counterexample: None,
                trace: None,
                category: "VerificationSummary".to_string(),
            });
        }

        results
    }

    /// Extract counterexample values from Kani output.
    fn extract_counterexample(&self, section: &str) -> Option<String> {
        let mut counterexample_lines = Vec::new();

        let mut in_counterexample = false;
        for line in section.lines() {
            let trimmed = line.trim();

            if trimmed.contains("COUNTEREXAMPLE") || trimmed.contains("Concrete") {
                in_counterexample = true;
                continue;
            }

            if in_counterexample {
                if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("**") {
                    break;
                }
                counterexample_lines.push(trimmed.to_string());
            }

            // Also capture individual variable assignments
            if trimmed.contains(" = ")
                && (trimmed.contains("u64")
                    || trimmed.contains("u128")
                    || trimmed.contains("bool")
                    || trimmed.contains("[u8"))
            {
                counterexample_lines.push(trimmed.to_string());
            }
        }

        if counterexample_lines.is_empty() {
            None
        } else {
            Some(counterexample_lines.join("\n"))
        }
    }

    /// Extract execution trace from Kani output.
    fn extract_trace(&self, section: &str) -> Option<String> {
        let mut trace_lines = Vec::new();
        let mut in_trace = false;

        for line in section.lines() {
            let trimmed = line.trim();

            if trimmed.contains("Trace for") || trimmed.contains("TRACE:") {
                in_trace = true;
                continue;
            }

            if in_trace {
                if trimmed.is_empty() && trace_lines.len() > 2 {
                    break;
                }
                if !trimmed.is_empty() {
                    trace_lines.push(trimmed.to_string());
                }
            }
        }

        if trace_lines.is_empty() {
            None
        } else {
            Some(trace_lines.join("\n"))
        }
    }
}

impl Default for KaniResultParser {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Result Types ────────────────────────────────────────────────────────────

/// Result of checking a single property/invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyCheckResult {
    /// Name of the property (harness function name)
    pub property_name: String,
    /// Verification status
    pub status: CheckStatus,
    /// Human-readable description
    pub description: String,
    /// Source location where the property is defined
    pub source_location: String,
    /// Counterexample if verification failed (concrete input values)
    pub counterexample: Option<String>,
    /// Execution trace if available
    pub trace: Option<String>,
    /// Category of the check
    pub category: String,
}

/// Status of a property check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Property verified to hold in all reachable states within the bound
    Success,
    /// Property violated — counterexample found
    Failure,
    /// Could not determine within the given bounds/timeout
    Undetermined,
}
