//! Trident Fuzz Executor
//!
//! Manages the execution of Trident fuzz campaigns, either via:
//! 1. `trident fuzz run` CLI (when `trident-cli` is installed)
//! 2. Built-in offline SVM simulation (static analysis fallback)

use crate::anchor_extractor::AnchorProgramModel;
use crate::TridentError;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

// ─── Configuration ───────────────────────────────────────────────────────────

/// Configuration for Trident fuzz execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TridentConfig {
    /// Maximum number of fuzz iterations per campaign.
    pub max_iterations: u64,
    /// Maximum time for the fuzz campaign, in seconds.
    pub timeout_seconds: u64,
    /// Number of concurrent fuzz workers.
    pub workers: usize,
    /// Random seed (0 = random).
    pub seed: u64,
    /// Whether to use honggfuzz or libfuzzer backend.
    pub fuzzer_backend: FuzzerBackend,
    /// Whether to collect code coverage.
    pub collect_coverage: bool,
    /// Maximum RAM per worker (MB).
    pub max_memory_mb: u64,
    /// Whether to run stateful (flow-based) fuzzing.
    pub stateful_fuzzing: bool,
    /// Whether to check property invariants after each flow.
    pub check_invariants: bool,
    /// Extra CLI arguments for `trident fuzz run`.
    pub extra_args: Vec<String>,
}

impl Default for TridentConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10_000,
            timeout_seconds: 120,
            workers: 4,
            seed: 0,
            fuzzer_backend: FuzzerBackend::Honggfuzz,
            collect_coverage: true,
            max_memory_mb: 2048,
            stateful_fuzzing: true,
            check_invariants: true,
            extra_args: Vec::new(),
        }
    }
}

/// Fuzzer backend selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzerBackend {
    Honggfuzz,
    Libfuzzer,
}

// ─── Executor ────────────────────────────────────────────────────────────────

/// Executes Trident fuzz campaigns against Solana programs.
#[allow(dead_code)]
pub struct TridentExecutor {
    config: TridentConfig,
    trident_available: Option<bool>,
    trident_version: Option<String>,
}

impl TridentExecutor {
    pub fn new(config: TridentConfig) -> Self {
        Self {
            config,
            trident_available: None,
            trident_version: None,
        }
    }

    /// Check whether `trident` CLI is available on the system.
    pub fn is_trident_available(&self) -> bool {
        *self.trident_available.get_or_init(|| {
            match Command::new("trident").arg("--version").output() {
                Ok(output) => {
                    if output.status.success() {
                        info!("Trident CLI detected");
                        true
                    } else {
                        warn!("Trident CLI found but returned error");
                        false
                    }
                }
                Err(_) => {
                    warn!("Trident CLI not found — install via: cargo install trident-cli");
                    false
                }
            }
        })
    }

    /// Detect installed Trident version.
    pub fn detect_trident_version(&self) -> Option<String> {
        Command::new("trident")
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout)
                        .ok()
                        .map(|v| v.trim().to_string())
                } else {
                    None
                }
            })
    }

    /// Run a complete fuzz campaign.
    ///
    /// First checks if `trident` CLI is available. If so, runs the campaign
    /// via the CLI. Otherwise, falls back to an offline static analysis
    /// that returns synthetic results based on the Anchor model.
    pub fn run_fuzz_campaign(
        &self,
        harness_dir: &Path,
        program_path: &Path,
        model: &AnchorProgramModel,
    ) -> Result<FuzzCampaignResult, TridentError> {
        if self.is_trident_available() {
            self.run_via_cli(harness_dir, program_path)
        } else {
            // Offline mode: simulate fuzz campaign results
            Ok(self.simulate_fuzz_campaign(model))
        }
    }

    /// Run fuzz campaign via `trident fuzz run`.
    fn run_via_cli(
        &self,
        harness_dir: &Path,
        program_path: &Path,
    ) -> Result<FuzzCampaignResult, TridentError> {
        info!(
            "Trident: Running fuzz campaign via CLI at {:?}",
            harness_dir
        );

        let mut cmd = Command::new("trident");
        cmd.arg("fuzz")
            .arg("run")
            .arg("fuzz_test")
            .arg("--iterations")
            .arg(self.config.max_iterations.to_string())
            .arg("--timeout")
            .arg(self.config.timeout_seconds.to_string())
            .current_dir(program_path);

        for arg in &self.config.extra_args {
            cmd.arg(arg);
        }

        let output = cmd
            .output()
            .map_err(|e| TridentError::ExecutionError(format!("Failed to run trident: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            self.parse_trident_output(&stdout, &stderr)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(TridentError::ExecutionError(format!(
                "trident fuzz run failed: {}",
                stderr.chars().take(500).collect::<String>(),
            )))
        }
    }

    /// Parse Trident CLI output into structured results.
    fn parse_trident_output(
        &self,
        stdout: &str,
        stderr: &str,
    ) -> Result<FuzzCampaignResult, TridentError> {
        let mut result = FuzzCampaignResult::default();

        // Parse iteration count
        let iter_re = regex::Regex::new(r"iterations:\s*(\d+)")
            .map_err(|e| TridentError::ParseError(e.to_string()))?;
        if let Some(cap) = iter_re.captures(stdout) {
            result.total_iterations = cap[1].parse().unwrap_or(0);
        }

        // Parse crash count
        let crash_re = regex::Regex::new(r"crashes?:\s*(\d+)")
            .map_err(|e| TridentError::ParseError(e.to_string()))?;
        if let Some(cap) = crash_re.captures(stdout) {
            let crash_count: usize = cap[1].parse().unwrap_or(0);
            for i in 0..crash_count {
                result.crashes.push(RawCrash {
                    id: format!("crash_{}", i),
                    instruction: "unknown".into(),
                    message: format!("Crash #{} detected by Trident", i),
                    stack_trace: None,
                    input_bytes: None,
                });
            }
        }

        // Parse coverage
        let cov_re = regex::Regex::new(r"coverage:\s*([\d.]+)%")
            .map_err(|e| TridentError::ParseError(e.to_string()))?;
        if let Some(cap) = cov_re.captures(stdout) {
            result.branch_coverage_pct = cap[1].parse().unwrap_or(0.0);
        }

        // Parse invariant violations from stderr or stdout
        let inv_re = regex::Regex::new(r"INVARIANT VIOLATION:\s*(.+)")
            .map_err(|e| TridentError::ParseError(e.to_string()))?;
        for cap in inv_re.captures_iter(&format!("{}\n{}", stdout, stderr)) {
            result.invariant_violations.push(InvariantViolation {
                property: cap[1].trim().to_string(),
                instruction: "unknown".into(),
                state_before: None,
                state_after: None,
            });
        }

        Ok(result)
    }

    /// Simulate a fuzz campaign using static analysis of the program model.
    fn simulate_fuzz_campaign(&self, model: &AnchorProgramModel) -> FuzzCampaignResult {
        let mut result = FuzzCampaignResult {
            total_iterations: 0, // offline mode — no actual iterations
            ..Default::default()
        };

        // Report potential crashes from model analysis
        for ix in &model.instructions {
            // Missing signer → would crash with `ConstraintSigner` in real fuzzing
            let has_authority = ix.accounts.iter().any(|a| {
                a.name.contains("authority") || a.name.contains("admin") || a.name.contains("owner")
            });
            let has_signer = ix.accounts.iter().any(|a| a.is_signer);

            if has_authority && !has_signer {
                result.crashes.push(RawCrash {
                    id: format!("offline_signer_{}", ix.name),
                    instruction: ix.name.clone(),
                    message: format!(
                        "Stateful fuzzing would accept unsigned transaction for '{}' — \
                         missing signer constraint",
                        ix.name,
                    ),
                    stack_trace: None,
                    input_bytes: None,
                });
            }

            // Unchecked arithmetic → would panic on overflow
            if ix.has_arithmetic && !ix.uses_checked_math {
                result.crashes.push(RawCrash {
                    id: format!("offline_overflow_{}", ix.name),
                    instruction: ix.name.clone(),
                    message: format!(
                        "Trident boundary value generation (u64::MAX, 0) would trigger arithmetic \
                         overflow in '{}'",
                        ix.name,
                    ),
                    stack_trace: None,
                    input_bytes: None,
                });
            }

            // Unchecked CPI → would accept malicious program
            if ix.has_cpi && !ix.validates_cpi_program_id {
                result.crashes.push(RawCrash {
                    id: format!("offline_cpi_{}", ix.name),
                    instruction: ix.name.clone(),
                    message: format!(
                        "Trident cross-program fuzzing would inject malicious program ID in '{}'",
                        ix.name,
                    ),
                    stack_trace: None,
                    input_bytes: None,
                });
            }
        }

        // Report invariant violations for unchecked accounts
        for account in &model.accounts {
            if account.account_type == "AccountInfo" && account.constraints.is_empty() {
                let is_system = account.name.contains("system_program")
                    || account.name.contains("rent")
                    || account.name.contains("clock");
                if !is_system {
                    result.invariant_violations.push(InvariantViolation {
                        property: format!("account_validation_{}", account.name),
                        instruction: account.context_struct.clone(),
                        state_before: None,
                        state_after: Some(format!(
                            "Unchecked AccountInfo '{}' accepts any account — \
                             Trident substitution attack would succeed",
                            account.name,
                        )),
                    });
                }
            }
        }

        result
    }
}

// We need a polyfill for Option's get_or_init (not available in std)
trait GetOrInit {
    fn get_or_init<F: FnOnce() -> bool>(&self, f: F) -> &bool;
}

impl GetOrInit for Option<bool> {
    fn get_or_init<F: FnOnce() -> bool>(&self, f: F) -> &bool {
        // For Option<bool>, just check lazily
        // In practice, we just compute it each time
        static TRUE: bool = true;
        static FALSE: bool = false;
        if self.unwrap_or_else(f) {
            &TRUE
        } else {
            &FALSE
        }
    }
}

// ─── Result Types ────────────────────────────────────────────────────────────

/// Raw results from a fuzz campaign.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuzzCampaignResult {
    pub total_iterations: u64,
    pub crashes: Vec<RawCrash>,
    pub invariant_violations: Vec<InvariantViolation>,
    pub branch_coverage_pct: f64,
    pub execution_time_ms: u64,
}

/// A raw crash from the fuzzer (before analysis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCrash {
    pub id: String,
    pub instruction: String,
    pub message: String,
    pub stack_trace: Option<String>,
    pub input_bytes: Option<Vec<u8>>,
}

/// An invariant violation detected during fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantViolation {
    pub property: String,
    pub instruction: String,
    pub state_before: Option<String>,
    pub state_after: Option<String>,
}
