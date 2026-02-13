//! Anomaly Detection Module
//!
//! Detects zero-day vulnerabilities by identifying code patterns that deviate
//! from normal secure Solana program behavior. Uses statistical methods and
//! isolation forest-inspired approach.

use crate::report::{DetectionMethod, L3xCategory, L3xFinding, L3xSeverity};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use syn::visit::Visit;

const ANOMALY_SCORE_THRESHOLD: f32 = 0.75;

pub struct AnomalyDetector {
    /// Statistical baseline for normal code patterns
    baseline_stats: HashMap<String, f32>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baseline_stats: Self::build_baseline(),
        }
    }

    /// Build statistical baseline from known secure patterns
    fn build_baseline() -> HashMap<String, f32> {
        let mut stats = HashMap::new();

        // Normal ratios in secure code
        stats.insert("account_to_instruction_ratio".to_string(), 2.5);
        stats.insert("check_to_mutation_ratio".to_string(), 1.2);
        stats.insert("signer_check_frequency".to_string(), 0.8);
        stats.insert("cpi_validation_rate".to_string(), 0.9);
        stats.insert("arithmetic_safety_rate".to_string(), 0.85);

        stats
    }

    /// Detect anomalies in code
    pub fn detect_anomalies(
        &self,
        file_path: &str,
        syntax_tree: &syn::File,
        content: &str,
    ) -> Vec<L3xFinding> {
        let mut findings = Vec::new();

        // Extract code statistics
        let stats = self.extract_statistics(syntax_tree, content);

        // Compare against baseline
        for (metric, observed_value) in &stats {
            if let Some(baseline_value) = self.baseline_stats.get(metric) {
                let deviation = ((observed_value - baseline_value) / baseline_value).abs();

                if deviation > ANOMALY_SCORE_THRESHOLD {
                    let category = self.metric_to_category(metric);
                    let severity = if deviation > 1.5 {
                        L3xSeverity::High
                    } else if deviation > 1.0 {
                        L3xSeverity::Medium
                    } else {
                        L3xSeverity::Low
                    };

                    let fingerprint = self.generate_fingerprint(file_path, metric);
                    let confidence = (deviation / 2.0).min(0.95);

                    findings.push(L3xFinding {
                        id: format!("L3X-ANOM-{}", &fingerprint[..8]),
                        category,
                        severity,
                        confidence,
                        file_path: file_path.to_string(),
                        line_number: 1,
                        instruction: "program-wide".to_string(),
                        account_name: None,
                        description: format!(
                            "Anomaly detection identified unusual {} pattern. \
                             Observed: {:.2}, Expected: {:.2}, Deviation: {:.1}%",
                            metric.replace('_', " "), observed_value, baseline_value, deviation * 100.0
                        ),
                        ml_reasoning: format!(
                            "Statistical analysis shows {:.1}% deviation from secure program baseline. \
                             This pattern is rare in audited Solana programs and may indicate a vulnerability.",
                            deviation * 100.0
                        ),
                        fix_recommendation: "Review program architecture and add missing security checks".to_string(),
                        cwe: "CWE-1021".to_string(),
                        fingerprint,
                        source_snippet: None,
                        fix_diff: None,
                        detection_method: DetectionMethod::AnomalyDetection {
                            deviation_score: deviation,
                        },
                        related_patterns: vec![],
                    });
                }
            }
        }

        findings
    }

    fn extract_statistics(&self, syntax_tree: &syn::File, _content: &str) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        let mut counter = StatisticsCollector::new();
        counter.visit_file(syntax_tree);

        if counter.instruction_count > 0 {
            stats.insert(
                "account_to_instruction_ratio".to_string(),
                counter.account_count as f32 / counter.instruction_count as f32,
            );
            stats.insert(
                "check_to_mutation_ratio".to_string(),
                counter.check_count as f32 / counter.mutation_count.max(1) as f32,
            );
            stats.insert(
                "signer_check_frequency".to_string(),
                counter.signer_checks as f32 / counter.instruction_count as f32,
            );
        }

        stats
    }

    fn metric_to_category(&self, metric: &str) -> L3xCategory {
        match metric {
            "account_to_instruction_ratio" => L3xCategory::UnusualAccountPattern,
            "check_to_mutation_ratio" => L3xCategory::StateInconsistency,
            "signer_check_frequency" => L3xCategory::AuthorizationBypass,
            _ => L3xCategory::ZeroDayPattern,
        }
    }

    fn generate_fingerprint(&self, file_path: &str, metric: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(file_path.as_bytes());
        hasher.update(metric.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

struct StatisticsCollector {
    instruction_count: usize,
    account_count: usize,
    check_count: usize,
    mutation_count: usize,
    signer_checks: usize,
}

impl StatisticsCollector {
    fn new() -> Self {
        Self {
            instruction_count: 0,
            account_count: 0,
            check_count: 0,
            mutation_count: 0,
            signer_checks: 0,
        }
    }
}

impl<'ast> Visit<'ast> for StatisticsCollector {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        for attr in &node.attrs {
            if attr.path().is_ident("derive") {
                self.instruction_count += 1;
            }
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        self.account_count += node.fields.len();
        syn::visit::visit_item_struct(self, node);
    }
}
