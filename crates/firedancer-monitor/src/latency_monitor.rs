//! Transaction Latency Monitor
//!
//! Monitors transaction inclusion latency.
//! Firedancer targets sub-second latency.

use crate::report::{FiredancerFinding, FiredancerIssue, FiredancerSeverity};
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;

pub struct LatencyMonitor {
    threshold_ms: u64,
}

impl LatencyMonitor {
    pub fn new(threshold_ms: u64) -> Self {
        Self { threshold_ms }
    }

    pub async fn monitor_latency(
        &self,
        rpc_client: &RpcClient,
    ) -> Result<Vec<FiredancerFinding>, anyhow::Error> {
        let mut findings = Vec::new();

        let slot = rpc_client.get_slot()?;
        let latency_ms = self.measure_latency(rpc_client)?;

        if latency_ms > self.threshold_ms {
            let severity = if latency_ms > self.threshold_ms * 3 {
                FiredancerSeverity::Critical
            } else if latency_ms > self.threshold_ms * 2 {
                FiredancerSeverity::High
            } else {
                FiredancerSeverity::Medium
            };

            findings.push(FiredancerFinding {
                id: format!("FD-LAT-{}", self.fingerprint(slot)),
                issue: FiredancerIssue::TransactionLatency,
                severity,
                slot,
                timestamp: chrono::Utc::now().to_rfc3339(),
                description: format!(
                    "High transaction latency: {}ms (threshold: {}ms)",
                    latency_ms, self.threshold_ms
                ),
                measured_value: latency_ms as f64,
                threshold_value: self.threshold_ms as f64,
                risk_explanation:
                    "High latency degrades user experience and can cause transaction \
                    failures. Firedancer is designed for sub-second latency."
                        .to_string(),
                mitigation: "Optimize validator configuration, check network bandwidth, \
                    ensure Firedancer is running latest version."
                    .to_string(),
                validator_identity: None,
            });
        }

        Ok(findings)
    }

    fn measure_latency(&self, rpc_client: &RpcClient) -> Result<u64, anyhow::Error> {
        let start = std::time::Instant::now();
        let _ = rpc_client.get_slot()?;
        let rpc_latency = start.elapsed().as_millis() as u64;

        // RPC latency is a proxy for network/validator latency
        Ok(rpc_latency)
    }

    fn fingerprint(&self, slot: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"latency");
        h.update(slot.to_string().as_bytes());
        hex::encode(&h.finalize()[..8])
    }
}
