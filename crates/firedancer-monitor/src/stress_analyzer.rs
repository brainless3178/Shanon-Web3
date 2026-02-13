//! Validator Stress Analyzer
//!
//! Analyzes validator performance under stress.
//! Critical for Firedancer's high-throughput design.

use crate::report::{FiredancerFinding, FiredancerIssue, FiredancerSeverity};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;

pub struct StressAnalyzer;

impl StressAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn analyze_stress(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<Vec<FiredancerFinding>, anyhow::Error> {
        let mut findings = Vec::new();

        let slot = rpc_client.get_slot()?;
        let stress_level = self.measure_stress(rpc_client)?;

        if stress_level > 70.0 {
            // >70% stress
            let severity = if stress_level > 90.0 {
                FiredancerSeverity::Critical
            } else if stress_level > 80.0 {
                FiredancerSeverity::High
            } else {
                FiredancerSeverity::Medium
            };

            findings.push(FiredancerFinding {
                id: format!("FD-STRESS-{}", self.fingerprint(slot)),
                issue: FiredancerIssue::ValidatorStress,
                severity,
                slot,
                timestamp: chrono::Utc::now().to_rfc3339(),
                description: format!("Validator under stress: {:.1}% load", stress_level),
                measured_value: stress_level,
                threshold_value: 70.0,
                risk_explanation: "High validator stress can cause performance degradation, \
                    increased latency, and potential consensus issues."
                    .to_string(),
                mitigation: "Scale validator resources, optimize configuration, \
                    ensure Firedancer is properly tuned for high throughput."
                    .to_string(),
                validator_identity: None,
            });
        }

        Ok(findings)
    }

    fn measure_stress(&self, rpc_client: &RpcClient) -> Result<f64, anyhow::Error> {
        let recent_perf = rpc_client.get_recent_performance_samples(Some(5))?;

        if recent_perf.is_empty() {
            return Ok(0.0);
        }

        // Calculate stress from transaction density
        let avg_tx_per_slot: f64 = recent_perf
            .iter()
            .map(|s| s.num_transactions as f64 / s.num_slots as f64)
            .sum::<f64>()
            / recent_perf.len() as f64;

        let max_capacity = 5000.0; // Firedancer target capacity
        let stress_level = (avg_tx_per_slot / max_capacity * 100.0).min(100.0);

        Ok(stress_level)
    }

    fn fingerprint(&self, slot: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"stress");
        h.update(slot.to_string().as_bytes());
        hex::encode(&h.finalize()[..8])
    }
}

impl Default for StressAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
