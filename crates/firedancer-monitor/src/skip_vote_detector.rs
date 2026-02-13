//! Skip-Vote Detector
//!
//! Detects validators skipping votes due to consensus delays.
//! Critical for Firedancer performance under stress.

use crate::report::{FiredancerFinding, FiredancerIssue, FiredancerSeverity};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;

pub struct SkipVoteDetector {
    skip_threshold: usize,
}

impl SkipVoteDetector {
    pub fn new(skip_threshold: usize) -> Self {
        Self { skip_threshold }
    }

    pub async fn detect_skip_votes(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<Vec<FiredancerFinding>, anyhow::Error> {
        let mut findings = Vec::new();

        let slot = rpc_client.get_slot()?;

        // Detect skip rate from recent performance
        let skip_rate = self.measure_skip_rate(rpc_client)?;

        if skip_rate > self.skip_threshold as f64 {
            let severity = if skip_rate > (self.skip_threshold * 3) as f64 {
                FiredancerSeverity::Critical
            } else if skip_rate > (self.skip_threshold * 2) as f64 {
                FiredancerSeverity::High
            } else {
                FiredancerSeverity::Medium
            };

            findings.push(FiredancerFinding {
                id: format!("FD-SKIP-{}", self.fingerprint(slot)),
                issue: FiredancerIssue::SkipVoteRisk,
                severity,
                slot,
                timestamp: chrono::Utc::now().to_rfc3339(),
                description: format!(
                    "Skip-vote risk detected: {:.1}% skip rate (threshold: {}%)",
                    skip_rate, self.skip_threshold
                ),
                measured_value: skip_rate,
                threshold_value: self.skip_threshold as f64,
                risk_explanation: "High skip-vote rate indicates consensus delays. Validators \
                    skipping votes can cause network instability and reduced finality."
                    .to_string(),
                mitigation: "Investigate validator performance, check for network issues, \
                    ensure Firedancer is properly configured for high throughput."
                    .to_string(),
                validator_identity: None,
            });
        }

        Ok(findings)
    }

    fn measure_skip_rate(&self, rpc_client: &RpcClient) -> Result<f64, anyhow::Error> {
        let recent_perf = rpc_client.get_recent_performance_samples(Some(10))?;

        if recent_perf.is_empty() {
            return Ok(0.0);
        }

        let total_slots: u64 = recent_perf.iter().map(|s| s.num_slots).sum();
        let total_transactions: u64 = recent_perf.iter().map(|s| s.num_transactions).sum();

        // Estimate skip rate from transaction density
        let avg_tx_per_slot = total_transactions as f64 / total_slots as f64;
        let expected_tx_per_slot = 3000.0; // Firedancer target

        let skip_rate =
            ((expected_tx_per_slot - avg_tx_per_slot) / expected_tx_per_slot * 100.0).max(0.0);
        Ok(skip_rate.min(100.0))
    }

    fn fingerprint(&self, slot: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"skip_vote");
        h.update(slot.to_string().as_bytes());
        hex::encode(&h.finalize()[..8])
    }
}
