//! # Firedancer-Aware Validator Performance Monitor
//!
//! Monitors Solana validators for Firedancer-specific performance issues:
//! - **Verification Lag**: Delay between transaction inclusion and verification
//! - **Skip-Vote Risk**: Validators skipping votes due to consensus delays
//! - **Transaction Inclusion Latency**: Time from submission to inclusion
//! - **Validator Stress Metrics**: Performance under high load
//!
//! Firedancer is the new high-performance Solana validator designed to reduce
//! latency and improve throughput. This monitor detects issues specific to
//! Firedancer's architecture.

pub mod latency_monitor;
pub mod report;
pub mod skip_vote_detector;
pub mod stress_analyzer;
pub mod verification_lag;

use latency_monitor::LatencyMonitor;
use report::{FiredancerFinding, FiredancerMonitorReport, FiredancerSeverity};
use skip_vote_detector::SkipVoteDetector;
use stress_analyzer::StressAnalyzer;
use verification_lag::VerificationLagDetector;

use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use std::time::Duration;
use tracing::info;

/// Firedancer monitor configuration
#[derive(Debug, Clone)]
pub struct FiredancerConfig {
    /// RPC endpoint URL
    pub rpc_url: String,
    /// Monitor verification lag
    pub check_verification_lag: bool,
    /// Monitor skip-vote risk
    pub check_skip_votes: bool,
    /// Monitor transaction latency
    pub check_latency: bool,
    /// Monitor validator stress
    pub check_stress: bool,
    /// Verification lag threshold (ms)
    pub verification_lag_threshold_ms: u64,
    /// Skip-vote threshold (consecutive skips)
    pub skip_vote_threshold: usize,
    /// Latency threshold (ms)
    pub latency_threshold_ms: u64,
    /// Monitoring duration (seconds)
    pub monitoring_duration_secs: u64,
}

impl Default for FiredancerConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            check_verification_lag: true,
            check_skip_votes: true,
            check_latency: true,
            check_stress: true,
            verification_lag_threshold_ms: 500, // 500ms is concerning for Firedancer
            skip_vote_threshold: 3,             // 3 consecutive skips
            latency_threshold_ms: 1000,         // 1s latency
            monitoring_duration_secs: 60,       // 1 minute monitoring
        }
    }
}

/// Firedancer validator performance monitor
pub struct FiredancerMonitor {
    config: FiredancerConfig,
    rpc_client: RpcClient,
    verification_lag_detector: VerificationLagDetector,
    skip_vote_detector: SkipVoteDetector,
    latency_monitor: LatencyMonitor,
    stress_analyzer: StressAnalyzer,
}

impl FiredancerMonitor {
    /// Create a new Firedancer monitor with default configuration
    pub fn new(rpc_url: String) -> Self {
        let config = FiredancerConfig {
            rpc_url: rpc_url.clone(),
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new Firedancer monitor with custom configuration
    pub fn with_config(config: FiredancerConfig) -> Self {
        info!("Initializing Firedancer validator performance monitor...");
        info!("RPC endpoint: {}", config.rpc_url);

        let rpc_client = RpcClient::new_with_timeout_and_commitment(
            config.rpc_url.clone(),
            Duration::from_secs(30),
            CommitmentConfig::confirmed(),
        );

        Self {
            verification_lag_detector: VerificationLagDetector::new(
                config.verification_lag_threshold_ms,
            ),
            skip_vote_detector: SkipVoteDetector::new(config.skip_vote_threshold),
            latency_monitor: LatencyMonitor::new(config.latency_threshold_ms),
            stress_analyzer: StressAnalyzer::new(),
            rpc_client,
            config,
        }
    }

    /// Monitor validator performance in real-time
    pub async fn monitor_validator(&mut self) -> Result<FiredancerMonitorReport, String> {
        info!(
            "Starting Firedancer validator performance monitoring for {} seconds...",
            self.config.monitoring_duration_secs
        );

        let start_time = std::time::Instant::now();
        let mut findings = Vec::new();

        // Phase 1: Check verification lag
        if self.config.check_verification_lag {
            info!("Phase 1: Detecting verification lag...");
            let lag_findings = self
                .verification_lag_detector
                .detect_lag(&self.rpc_client)
                .await
                .map_err(|e| format!("Verification lag detection failed: {}", e))?;
            findings.extend(lag_findings);
        }

        // Phase 2: Check skip-vote risk
        if self.config.check_skip_votes {
            info!("Phase 2: Detecting skip-vote risk...");
            let skip_findings = self
                .skip_vote_detector
                .detect_skip_votes(&self.rpc_client)
                .await
                .map_err(|e| format!("Skip-vote detection failed: {}", e))?;
            findings.extend(skip_findings);
        }

        // Phase 3: Monitor transaction latency
        if self.config.check_latency {
            info!("Phase 3: Monitoring transaction latency...");
            let latency_findings = self
                .latency_monitor
                .monitor_latency(&self.rpc_client)
                .await
                .map_err(|e| format!("Latency monitoring failed: {}", e))?;
            findings.extend(latency_findings);
        }

        // Phase 4: Analyze validator stress
        if self.config.check_stress {
            info!("Phase 4: Analyzing validator stress...");
            let stress_findings = self
                .stress_analyzer
                .analyze_stress(&self.rpc_client)
                .await
                .map_err(|e| format!("Stress analysis failed: {}", e))?;
            findings.extend(stress_findings);
        }

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Count severity levels
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, FiredancerSeverity::Critical))
            .count();
        let high_count = findings
            .iter()
            .filter(|f| matches!(f.severity, FiredancerSeverity::High))
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| matches!(f.severity, FiredancerSeverity::Medium))
            .count();
        let low_count = findings
            .iter()
            .filter(|f| matches!(f.severity, FiredancerSeverity::Low))
            .count();

        // Calculate health score (0-100, higher is better)
        let health_score = self.calculate_health_score(&findings);

        info!(
            "Firedancer monitoring complete: {} issues found ({} critical, {} high). Health score: {}/100 in {}ms",
            findings.len(), critical_count, high_count, health_score, execution_time_ms
        );

        Ok(FiredancerMonitorReport {
            rpc_endpoint: self.config.rpc_url.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            validator_health_score: health_score,
            monitoring_duration_secs: self.config.monitoring_duration_secs,
            execution_time_ms,
            engine_version: "firedancer-monitor-1.0.0".to_string(),
        })
    }

    /// Calculate validator health score based on findings
    fn calculate_health_score(&self, findings: &[FiredancerFinding]) -> u8 {
        let mut score: f64 = 100.0;

        for finding in findings {
            match finding.severity {
                FiredancerSeverity::Critical => score -= 15.0,
                FiredancerSeverity::High => score -= 10.0,
                FiredancerSeverity::Medium => score -= 5.0,
                FiredancerSeverity::Low => score -= 2.0,
            }
        }

        score.clamp(0.0, 100.0) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firedancer_monitor_creation() {
        let monitor = FiredancerMonitor::new("https://api.mainnet-beta.solana.com".to_string());
        assert_eq!(
            monitor.config.rpc_url,
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn test_custom_config() {
        let config = FiredancerConfig {
            verification_lag_threshold_ms: 1000,
            ..Default::default()
        };
        let monitor = FiredancerMonitor::with_config(config);
        assert_eq!(monitor.config.verification_lag_threshold_ms, 1000);
    }
}
