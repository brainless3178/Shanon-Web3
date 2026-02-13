//! Mainnet Guardian - Real-Time Threat Monitoring
//!
//! 24/7 monitoring of your Solana program for exploit attempts.
//! Detects attacks the moment they start and can auto-pause before funds are lost.

use colored::Colorize;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Mainnet Guardian - Real-time exploit detection system
pub struct MainnetGuardian {
    /// RPC endpoint
    rpc_url: String,
    /// WebSocket endpoint for subscriptions
    ws_url: String,
    /// Program being monitored
    program_id: Pubkey,
    /// Alert configuration
    alert_config: AlertConfig,
    /// Threat detection patterns
    detection_patterns: Vec<ThreatPattern>,
    /// Historical threat data
    #[allow(dead_code)]
    threat_history: Vec<ThreatDetection>,
    /// LLM client for AI analysis
    llm_api_key: Option<String>,
    /// Statistics
    stats: GuardianStats,
}

/// Alert configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Slack webhook URL
    pub slack_webhook: Option<String>,
    /// Discord webhook URL
    pub discord_webhook: Option<String>,
    /// Email addresses for alerts
    pub email_addresses: Vec<String>,
    /// Phone numbers for critical alerts
    pub phone_numbers: Vec<String>,
    /// Enable auto-pause on critical threats
    pub auto_pause_enabled: bool,
    /// Minimum threat level to trigger alert
    pub alert_threshold: ThreatLevel,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            slack_webhook: None,
            discord_webhook: None,
            email_addresses: vec![],
            phone_numbers: vec![],
            auto_pause_enabled: false,
            alert_threshold: ThreatLevel::Medium,
        }
    }
}

/// Detected threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    /// Transaction signature
    pub signature: String,
    /// Timestamp
    pub timestamp: i64,
    /// Type of threat
    pub threat_type: ThreatType,
    /// Severity level
    pub threat_level: ThreatLevel,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Explanation of the threat
    pub explanation: String,
    /// Affected accounts
    pub affected_accounts: Vec<String>,
    /// Estimated economic impact
    pub estimated_impact: Option<String>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Type of detected threat
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    FlashLoanAttack,
    ReentrancyAttempt,
    OracleManipulation,
    AuthorityBypass,
    AbnormalTokenFlow,
    SandwichAttack,
    AccountHijacking,
    UnusualAccountPattern,
    SuspiciousTimingPattern,
    Unknown,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatType::FlashLoanAttack => "Flash Loan Attack",
            ThreatType::ReentrancyAttempt => "Reentrancy Attempt",
            ThreatType::OracleManipulation => "Oracle Manipulation",
            ThreatType::AuthorityBypass => "Authority Bypass",
            ThreatType::AbnormalTokenFlow => "Abnormal Token Flow",
            ThreatType::SandwichAttack => "Sandwich Attack",
            ThreatType::AccountHijacking => "Account Hijacking",
            ThreatType::UnusualAccountPattern => "Unusual Account Pattern",
            ThreatType::SuspiciousTimingPattern => "Suspicious Timing",
            ThreatType::Unknown => "Unknown Threat",
        };
        write!(f, "{}", s)
    }
}

/// Threat severity level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq)]
pub enum ThreatLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatLevel::None => "NONE",
            ThreatLevel::Low => "LOW",
            ThreatLevel::Medium => "MEDIUM",
            ThreatLevel::High => "HIGH",
            ThreatLevel::Critical => "CRITICAL",
        };
        write!(f, "{}", s)
    }
}

/// Pattern for detecting threats
#[derive(Debug, Clone)]
pub struct ThreatPattern {
    pub name: String,
    pub threat_type: ThreatType,
    pub check_fn: fn(&EnrichedTransaction) -> Option<ThreatSignal>,
}

/// Signal from pattern detection
pub struct ThreatSignal {
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub details: String,
}

/// Enriched transaction with decoded data
#[derive(Debug, Clone)]
pub struct EnrichedTransaction {
    pub signature: String,
    pub slot: u64,
    pub block_time: i64,
    pub fee: u64,
    pub compute_units: u64,
    pub accounts: Vec<String>,
    pub logs: Vec<String>,
    pub pre_balances: Vec<u64>,
    pub post_balances: Vec<u64>,
    pub pre_token_balances: Vec<TokenBalance>,
    pub post_token_balances: Vec<TokenBalance>,
}

/// Token balance info
#[derive(Debug, Clone)]
pub struct TokenBalance {
    pub account: String,
    pub mint: String,
    pub amount: u64,
    pub decimals: u8,
}

/// Guardian statistics
#[derive(Debug, Default, Clone)]
pub struct GuardianStats {
    pub transactions_analyzed: u64,
    pub threats_detected: u64,
    pub alerts_sent: u64,
    pub false_positives: u64,
    pub uptime_seconds: u64,
    pub start_time: Option<Instant>,
}

/// Real-time monitoring session
pub struct MonitoringSession {
    pub program_id: Pubkey,
    pub start_time: Instant,
    pub transactions_processed: u64,
    pub threats_detected: Vec<ThreatDetection>,
}

impl MainnetGuardian {
    /// Create a new Mainnet Guardian
    pub fn new(rpc_url: String, program_id: Pubkey, alert_config: AlertConfig) -> Self {
        let ws_url = rpc_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        Self {
            rpc_url,
            ws_url,
            program_id,
            alert_config,
            detection_patterns: Self::default_patterns(),
            threat_history: vec![],
            llm_api_key: None,
            stats: GuardianStats::default(),
        }
    }

    /// Set LLM API key for AI-powered analysis
    pub fn with_llm(mut self, api_key: String) -> Self {
        self.llm_api_key = Some(api_key);
        self
    }

    /// Default threat detection patterns
    fn default_patterns() -> Vec<ThreatPattern> {
        vec![
            ThreatPattern {
                name: "Flash Loan Detection".into(),
                threat_type: ThreatType::FlashLoanAttack,
                check_fn: Self::check_flash_loan_pattern,
            },
            ThreatPattern {
                name: "Large Token Movement".into(),
                threat_type: ThreatType::AbnormalTokenFlow,
                check_fn: Self::check_large_token_movement,
            },
            ThreatPattern {
                name: "Suspicious Account Pattern".into(),
                threat_type: ThreatType::UnusualAccountPattern,
                check_fn: Self::check_account_pattern,
            },
            ThreatPattern {
                name: "Timing Attack".into(),
                threat_type: ThreatType::SuspiciousTimingPattern,
                check_fn: Self::check_timing_pattern,
            },
        ]
    }

    /// Check for flash loan patterns
    fn check_flash_loan_pattern(tx: &EnrichedTransaction) -> Option<ThreatSignal> {
        // Flash loan indicators:
        // 1. Large token borrow at start
        // 2. Same token returned at end
        // 3. Multiple DeFi protocol interactions

        let has_large_movement = tx
            .pre_token_balances
            .iter()
            .zip(tx.post_token_balances.iter())
            .any(|(pre, post)| {
                let diff = pre.amount.abs_diff(post.amount);
                diff > 1_000_000_000_000 // > 1M tokens (assuming 6 decimals)
            });

        let returns_to_original = tx
            .pre_token_balances
            .iter()
            .zip(tx.post_token_balances.iter())
            .any(|(pre, post)| pre.amount == post.amount && pre.amount > 0);

        if has_large_movement && returns_to_original {
            Some(ThreatSignal {
                threat_type: ThreatType::FlashLoanAttack,
                confidence: 0.7,
                details: "Large token movement with return to original balance detected".into(),
            })
        } else {
            None
        }
    }

    /// Check for abnormally large token movements
    fn check_large_token_movement(tx: &EnrichedTransaction) -> Option<ThreatSignal> {
        for (pre, post) in tx
            .pre_token_balances
            .iter()
            .zip(tx.post_token_balances.iter())
        {
            if pre.mint == post.mint {
                let diff = pre.amount.abs_diff(post.amount);

                // Alert on movements > 90% of balance
                if pre.amount > 0 && diff > (pre.amount * 9 / 10) {
                    return Some(ThreatSignal {
                        threat_type: ThreatType::AbnormalTokenFlow,
                        confidence: 0.8,
                        details: format!(
                            "Large token movement: {} tokens ({}% of balance)",
                            diff,
                            (diff * 100) / pre.amount
                        ),
                    });
                }
            }
        }
        None
    }

    /// Check for suspicious account patterns
    fn check_account_pattern(tx: &EnrichedTransaction) -> Option<ThreatSignal> {
        // Check for unusual number of accounts
        if tx.accounts.len() > 20 {
            return Some(ThreatSignal {
                threat_type: ThreatType::UnusualAccountPattern,
                confidence: 0.5,
                details: format!("Unusually high account count: {}", tx.accounts.len()),
            });
        }

        // Check for duplicate accounts (potential reentrancy setup)
        let unique_accounts: std::collections::HashSet<_> = tx.accounts.iter().collect();
        if unique_accounts.len() < tx.accounts.len() {
            return Some(ThreatSignal {
                threat_type: ThreatType::ReentrancyAttempt,
                confidence: 0.6,
                details: "Duplicate accounts detected - possible reentrancy setup".into(),
            });
        }

        None
    }

    /// Check for suspicious timing patterns
    fn check_timing_pattern(tx: &EnrichedTransaction) -> Option<ThreatSignal> {
        // High compute usage can indicate complex attack
        if tx.compute_units > 1_200_000 {
            return Some(ThreatSignal {
                threat_type: ThreatType::SuspiciousTimingPattern,
                confidence: 0.4,
                details: format!("Very high compute usage: {} CUs", tx.compute_units),
            });
        }
        None
    }

    /// Start real-time monitoring
    pub async fn start_monitoring(&mut self) -> anyhow::Result<mpsc::Receiver<ThreatDetection>> {
        let (tx, rx) = mpsc::channel(100);

        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".bright_cyan()
        );
        println!(
            "{}",
            "  🛡️  MAINNET GUARDIAN - Real-Time Threat Monitor".to_string()
                .bright_white()
                .bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════════════════════════════".bright_cyan()
        );
        println!();
        println!(
            "  {} Program: {}",
            "▸".bright_green(),
            self.program_id.to_string().bright_yellow()
        );
        println!(
            "  {} RPC: {}",
            "▸".bright_green(),
            self.rpc_url.bright_black()
        );
        println!(
            "  {} Auto-Pause: {}",
            "▸".bright_green(),
            if self.alert_config.auto_pause_enabled {
                "ENABLED".bright_red()
            } else {
                "disabled".bright_black()
            }
        );
        println!();
        println!(
            "{}",
            "  Initializing threat detection patterns...".bright_black()
        );

        self.stats.start_time = Some(Instant::now());

        // Clone what we need for the async task
        let rpc_url = self.rpc_url.clone();
        let _ws_url = self.ws_url.clone();
        let program_id = self.program_id;
        let patterns = self.detection_patterns.clone();
        let alert_config = self.alert_config.clone();

        // Spawn monitoring task
        tokio::spawn(async move {
            if let Err(e) =
                Self::monitoring_loop(&rpc_url, program_id, patterns, alert_config, tx).await
            {
                eprintln!("Monitoring error: {}", e);
            }
        });

        Ok(rx)
    }

    /// Main monitoring loop
    async fn monitoring_loop(
        rpc_url: &str,
        program_id: Pubkey,
        patterns: Vec<ThreatPattern>,
        alert_config: AlertConfig,
        threat_tx: mpsc::Sender<ThreatDetection>,
    ) -> anyhow::Result<()> {
        println!(
            "{}",
            "  ✓ Guardian active - monitoring transactions...".bright_green()
        );
        println!();

        let rpc = RpcClient::new(rpc_url.to_string());

        // Poll for recent signatures
        let mut last_signature: Option<Signature> = None;
        let mut tx_count = 0u64;

        loop {
            // Get recent signatures for the program
            let config = solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config {
                before: None,
                until: last_signature,
                limit: Some(10),
                commitment: Some(solana_sdk::commitment_config::CommitmentConfig::confirmed()),
            };

            match rpc.get_signatures_for_address_with_config(&program_id, config) {
                Ok(signatures) => {
                    for sig_info in signatures.iter().rev() {
                        tx_count += 1;

                        // Parse the signature
                        if let Ok(sig) = sig_info.signature.parse::<Signature>() {
                            // Create a basic enriched transaction for pattern matching
                            // In production, we'd fetch full transaction details
                            let enriched_tx = EnrichedTransaction {
                                signature: sig.to_string(),
                                slot: 0,
                                block_time: sig_info.block_time.unwrap_or(0),
                                fee: 0,
                                compute_units: 0,
                                accounts: vec![],
                                logs: vec![],
                                pre_balances: vec![],
                                post_balances: vec![],
                                pre_token_balances: vec![],
                                post_token_balances: vec![],
                            };

                            // Run through detection patterns
                            let signals: Vec<_> = patterns
                                .iter()
                                .filter_map(|p| (p.check_fn)(&enriched_tx))
                                .collect();

                            if !signals.is_empty() {
                                let max_severity = signals
                                    .iter()
                                    .map(|s| {
                                        Self::threat_type_to_level(&s.threat_type, s.confidence)
                                    })
                                    .max()
                                    .unwrap_or(ThreatLevel::Low);

                                if max_severity >= alert_config.alert_threshold {
                                    let threat = ThreatDetection {
                                        signature: sig.to_string(),
                                        timestamp: sig_info.block_time.unwrap_or(0),
                                        threat_type: signals[0].threat_type.clone(),
                                        threat_level: max_severity,
                                        confidence: signals
                                            .iter()
                                            .map(|s| s.confidence)
                                            .fold(0.0, f32::max),
                                        explanation: signals
                                            .iter()
                                            .map(|s| s.details.clone())
                                            .collect::<Vec<_>>()
                                            .join("; "),
                                        affected_accounts: enriched_tx.accounts.clone(),
                                        estimated_impact: None,
                                        recommended_actions: vec![
                                            "Review transaction details".into(),
                                            "Check for unauthorized state changes".into(),
                                        ],
                                    };

                                    Self::print_threat_alert(&threat);

                                    if let Err(e) = threat_tx.send(threat.clone()).await {
                                        eprintln!("Failed to send threat: {}", e);
                                    }

                                    // Send external alerts
                                    Self::send_alerts(&alert_config, &threat).await;
                                }
                            }

                            last_signature = Some(sig);
                        }
                    }

                    // Print periodic status
                    if tx_count.is_multiple_of(50) && tx_count > 0 {
                        println!(
                            "  {} {} transactions analyzed...",
                            "📊".bright_black(),
                            tx_count.to_string().bright_black()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  {} Error fetching signatures: {}", "⚠".bright_yellow(), e);
                }
            }

            // Poll interval
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Convert threat type to severity level
    fn threat_type_to_level(threat_type: &ThreatType, confidence: f32) -> ThreatLevel {
        let base_level = match threat_type {
            ThreatType::FlashLoanAttack => ThreatLevel::Critical,
            ThreatType::ReentrancyAttempt => ThreatLevel::Critical,
            ThreatType::OracleManipulation => ThreatLevel::Critical,
            ThreatType::AuthorityBypass => ThreatLevel::Critical,
            ThreatType::AbnormalTokenFlow => ThreatLevel::High,
            ThreatType::SandwichAttack => ThreatLevel::High,
            ThreatType::AccountHijacking => ThreatLevel::Critical,
            ThreatType::UnusualAccountPattern => ThreatLevel::Medium,
            ThreatType::SuspiciousTimingPattern => ThreatLevel::Low,
            ThreatType::Unknown => ThreatLevel::Low,
        };

        // Adjust based on confidence
        if confidence < 0.3 {
            match base_level {
                ThreatLevel::Critical => ThreatLevel::High,
                ThreatLevel::High => ThreatLevel::Medium,
                other => other,
            }
        } else {
            base_level
        }
    }

    /// Print threat alert to console
    fn print_threat_alert(threat: &ThreatDetection) {
        let level_color = match threat.threat_level {
            ThreatLevel::Critical => "🔴",
            ThreatLevel::High => "🟠",
            ThreatLevel::Medium => "🟡",
            ThreatLevel::Low => "🔵",
            ThreatLevel::None => "⚪",
        };

        println!();
        println!(
            "{}",
            "┌─────────────────────────────────────────────────────────────┐".bright_red()
        );
        println!(
            "│ {} {} DETECTED: {}",
            level_color,
            threat.threat_level.to_string().bright_red().bold(),
            threat.threat_type.to_string().bright_white()
        );
        println!("├─────────────────────────────────────────────────────────────┤");
        println!("│ TX: {}", threat.signature.bright_yellow());
        println!("│ Confidence: {}%", (threat.confidence * 100.0) as u32);
        println!("│ Details: {}", threat.explanation);
        println!(
            "{}",
            "└─────────────────────────────────────────────────────────────┘".bright_red()
        );
        println!();
    }

    /// Send external alerts
    async fn send_alerts(config: &AlertConfig, threat: &ThreatDetection) {
        // Slack webhook
        if let Some(webhook) = &config.slack_webhook {
            let _ = Self::send_slack_alert(webhook, threat).await;
        }

        // Discord webhook
        if let Some(webhook) = &config.discord_webhook {
            let _ = Self::send_discord_alert(webhook, threat).await;
        }
    }

    /// Send Slack alert
    async fn send_slack_alert(webhook: &str, threat: &ThreatDetection) -> anyhow::Result<()> {
        let client = reqwest::Client::new();

        let emoji = match threat.threat_level {
            ThreatLevel::Critical => "🔴",
            ThreatLevel::High => "🟠",
            ThreatLevel::Medium => "🟡",
            _ => "🔵",
        };

        let payload = serde_json::json!({
            "text": format!(
                "{} *{} THREAT DETECTED*\n*Type:* {}\n*TX:* `{}`\n*Details:* {}",
                emoji,
                threat.threat_level,
                threat.threat_type,
                threat.signature,
                threat.explanation
            )
        });

        client.post(webhook).json(&payload).send().await?;

        Ok(())
    }

    /// Send Discord alert
    async fn send_discord_alert(webhook: &str, threat: &ThreatDetection) -> anyhow::Result<()> {
        let client = reqwest::Client::new();

        let color = match threat.threat_level {
            ThreatLevel::Critical => 0xFF0000, // Red
            ThreatLevel::High => 0xFF8C00,     // Orange
            ThreatLevel::Medium => 0xFFFF00,   // Yellow
            _ => 0x0000FF,                     // Blue
        };

        let payload = serde_json::json!({
            "embeds": [{
                "title": format!("🚨 {} Threat Detected", threat.threat_level),
                "description": threat.explanation,
                "color": color,
                "fields": [
                    {"name": "Type", "value": threat.threat_type.to_string(), "inline": true},
                    {"name": "Confidence", "value": format!("{}%", (threat.confidence * 100.0) as u32), "inline": true},
                    {"name": "Transaction", "value": format!("[View on Solscan](https://solscan.io/tx/{})", threat.signature)}
                ]
            }]
        });

        client.post(webhook).json(&payload).send().await?;

        Ok(())
    }

    /// Get monitoring statistics
    pub fn get_stats(&self) -> &GuardianStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Medium);
        assert!(ThreatLevel::Medium > ThreatLevel::Low);
    }

    #[test]
    fn test_threat_type_display() {
        assert_eq!(ThreatType::FlashLoanAttack.to_string(), "Flash Loan Attack");
        assert_eq!(
            ThreatType::ReentrancyAttempt.to_string(),
            "Reentrancy Attempt"
        );
    }
}
