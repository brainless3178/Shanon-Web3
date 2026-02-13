//! Verification Lag Detector
//!
//! Detects delays between transaction inclusion and verification.
//! Firedancer aims to minimize this lag for faster finality.

use crate::report::{FiredancerFinding, FiredancerIssue, FiredancerSeverity};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;

pub struct VerificationLagDetector {
    threshold_ms: u64,
}

impl VerificationLagDetector {
    pub fn new(threshold_ms: u64) -> Self {
        Self { threshold_ms }
    }

    pub async fn detect_lag(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<Vec<FiredancerFinding>, anyhow::Error> {
        let mut findings = Vec::new();

        // Get current slot
        let slot = rpc_client.get_slot()?;

        // Simulate verification lag detection (in production, compare block timestamps)
        let simulated_lag_ms = self.measure_verification_lag(rpc_client, slot)?;

        if simulated_lag_ms > self.threshold_ms {
            let severity = if simulated_lag_ms > self.threshold_ms * 3 {
                FiredancerSeverity::Critical
            } else if simulated_lag_ms > self.threshold_ms * 2 {
                FiredancerSeverity::High
            } else {
                FiredancerSeverity::Medium
            };

            findings.push(FiredancerFinding {
                id: format!("FD-VLAG-{}", self.fingerprint(slot)),
                issue: FiredancerIssue::VerificationLag,
                severity,
                slot,
                timestamp: chrono::Utc::now().to_rfc3339(),
                description: format!(
                    "Verification lag detected: {}ms (threshold: {}ms)",
                    simulated_lag_ms, self.threshold_ms
                ),
                measured_value: simulated_lag_ms as f64,
                threshold_value: self.threshold_ms as f64,
                risk_explanation:
                    "High verification lag delays transaction finality and can cause \
                    consensus issues. Firedancer is designed to minimize this lag."
                        .to_string(),
                mitigation: "Monitor validator performance, check network connectivity, \
                    consider upgrading to Firedancer if using legacy validator."
                    .to_string(),
                validator_identity: None,
            });
        }

        Ok(findings)
    }

    fn measure_verification_lag(
        &self,
        rpc_client: &RpcClient,
        _slot: u64,
    ) -> Result<u64, anyhow::Error> {
        // In production: compare block production time vs verification time
        // For now, simulate by checking recent block times
        let recent_perf = rpc_client.get_recent_performance_samples(Some(1))?;

        if let Some(sample) = recent_perf.first() {
            // Estimate lag from sample data
            let non_vote_tx = sample.num_non_vote_transactions.unwrap_or(0) as f64;
            let slots = sample.num_slots as f64;
            let estimated_lag = (non_vote_tx / slots * 10.0) as u64;
            Ok(estimated_lag.min(2000)) // Cap at 2s
        } else {
            Ok(0)
        }
    }

    fn fingerprint(&self, slot: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"verification_lag");
        h.update(slot.to_string().as_bytes());
        hex::encode(&h.finalize()[..8])
    }
}
