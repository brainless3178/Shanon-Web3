//! Certora Prover Runner
//!
//! Invokes the Certora Solana Prover (`certoraSolanaProver`) or
//! `cargo certora-sbf` as a subprocess to perform formal verification
//! of SBF bytecode.
//!
//! There are two modes of operation:
//! 1. **From sources**: `certoraSolanaProver <conf_file>` which calls
//!    `cargo certora-sbf --json` internally
//! 2. **Pre-built**: `certoraSolanaProver <conf_file>` with `.so` path in config
//!
//! The runner captures stdout/stderr and returns raw output for parsing.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Configuration for the Certora Prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertoraConfig {
    /// Whether to use pre-built .so files (true) or build from sources (false)
    pub use_prebuilt: bool,
    /// Timeout for the verification job in seconds
    pub global_timeout: u32,
    /// SMT solver timeout per rule
    pub smt_timeout: u32,
    /// Whether to use optimistic loop unwinding
    pub optimistic_loop: bool,
    /// Maximum loop iterations for bounded verification
    pub loop_iter: u32,
    /// Whether to run rule sanity checks
    pub rule_sanity: bool,
    /// Whether to check each assertion independently
    pub multi_assert_check: bool,
    /// Custom message for the verification job
    pub msg: Option<String>,
    /// Cargo features to enable during build
    pub cargo_features: Vec<String>,
    /// Path to inlining configuration file
    pub solana_inlining: Option<PathBuf>,
    /// Path to summaries configuration file
    pub solana_summaries: Option<PathBuf>,
    /// CERTORA_KEY environment variable (API key for cloud prover)
    pub api_key: Option<String>,
    /// Whether to wait for results from the cloud prover
    pub wait_for_results: bool,
}

impl Default for CertoraConfig {
    fn default() -> Self {
        Self {
            use_prebuilt: true,  // Default to pre-built for audit workflow
            global_timeout: 600, // 10 minutes
            smt_timeout: 300,
            optimistic_loop: false,
            loop_iter: 3,
            rule_sanity: true,
            multi_assert_check: true,
            msg: Some("Automated SBF verification by solana-security-swarm".into()),
            cargo_features: Vec::new(),
            solana_inlining: None,
            solana_summaries: None,
            api_key: std::env::var("CERTORA_KEY").ok(),
            wait_for_results: true,
        }
    }
}

/// Runs the Certora Solana Prover subprocess.
pub struct CertoraRunner {
    config: CertoraConfig,
    certora_path: Option<PathBuf>,
    cargo_certora_available: bool,
}

impl CertoraRunner {
    pub fn new(config: CertoraConfig) -> Self {
        let certora_path = Self::find_certora_binary();
        let cargo_certora_available = Self::check_cargo_certora();

        if certora_path.is_some() {
            info!("Found certoraSolanaProver at: {:?}", certora_path);
        } else if cargo_certora_available {
            info!("cargo certora-sbf is available");
        } else {
            warn!(
                "Neither certoraSolanaProver nor cargo certora-sbf found — \
                   offline analysis mode will be used"
            );
        }

        Self {
            config,
            certora_path,
            cargo_certora_available,
        }
    }

    /// Check if the Certora Prover is installed.
    pub fn is_certora_available(&self) -> bool {
        self.certora_path.is_some() || self.cargo_certora_available
    }

    /// Detect the installed Certora version.
    pub fn detect_certora_version(&self) -> Option<String> {
        // Try certoraSolanaProver --version
        if let Some(ref path) = self.certora_path {
            if let Ok(output) = Command::new(path).arg("--version").output() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                let trimmed = version_str.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        // Try cargo certora-sbf --version
        if self.cargo_certora_available {
            if let Ok(output) = Command::new("cargo")
                .args(["certora-sbf", "--version"])
                .output()
            {
                let version_str = String::from_utf8_lossy(&output.stdout);
                let trimmed = version_str.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        None
    }

    /// Run verification using a `.conf` configuration file.
    pub fn run_verification(&self, conf_path: &Path) -> Result<String, crate::CertoraError> {
        if !self.is_certora_available() {
            return Err(crate::CertoraError::ExecutionError(
                "Certora Prover not installed. Install via: \
                 pip install certora-cli && cargo +1.81 install cargo-certora-sbf"
                    .to_string(),
            ));
        }

        // Check for API key
        let has_api_key = self.config.api_key.is_some() || std::env::var("CERTORA_KEY").is_ok();

        if !has_api_key {
            return Err(crate::CertoraError::ExecutionError(
                "CERTORA_KEY environment variable not set. \
                 Get an API key from https://prover.certora.com"
                    .to_string(),
            ));
        }

        let mut cmd = if let Some(ref path) = self.certora_path {
            let mut c = Command::new(path);
            c.arg(conf_path);
            c
        } else {
            let mut c = Command::new("certoraSolanaProver");
            c.arg(conf_path);
            c
        };

        // Add global options
        if let Some(ref msg) = self.config.msg {
            cmd.args(["--msg", msg]);
        }

        if self.config.rule_sanity {
            cmd.arg("--rule_sanity");
        }

        if self.config.multi_assert_check {
            cmd.arg("--multi_assert_check");
        }

        if self.config.wait_for_results {
            cmd.arg("--wait_for_results");
        }

        cmd.args(["--global_timeout", &self.config.global_timeout.to_string()]);
        cmd.args(["--smt_timeout", &self.config.smt_timeout.to_string()]);

        // Set CERTORA_KEY if configured
        if let Some(ref key) = self.config.api_key {
            cmd.env("CERTORA_KEY", key);
        }

        info!("Running Certora Prover: {:?}", cmd);

        let output = cmd.output().map_err(|e| {
            crate::CertoraError::ExecutionError(format!("Failed to invoke Certora Prover: {}", e))
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !stderr.is_empty() {
            debug!("Certora stderr: {}", stderr);
        }

        if !output.status.success() {
            let exit_code = output.status.code().unwrap_or(-1);
            error!("Certora Prover exited with code {}", exit_code);

            // Non-zero exit might still contain useful verification output
            if stdout.contains("PASSED") || stdout.contains("FAILED") || stdout.contains("TIMEOUT")
            {
                warn!("Certora exited non-zero but produced results — parsing output anyway");
                return Ok(format!("{}\n{}", stdout, stderr));
            }

            return Err(crate::CertoraError::ExecutionError(format!(
                "Certora Prover failed (exit {}): {}",
                exit_code,
                if stderr.is_empty() { &stdout } else { &stderr }
            )));
        }

        Ok(format!("{}\n{}", stdout, stderr))
    }

    /// Build a project using cargo certora-sbf.
    pub fn build_with_certora(&self, program_path: &Path) -> Result<PathBuf, crate::CertoraError> {
        if !self.cargo_certora_available {
            return Err(crate::CertoraError::BuildError(
                "cargo certora-sbf not available. Install: cargo +1.81 install cargo-certora-sbf"
                    .into(),
            ));
        }

        let mut cmd = Command::new("cargo");
        cmd.args(["certora-sbf", "--json"])
            .current_dir(program_path);

        if !self.config.cargo_features.is_empty() {
            cmd.arg("--features");
            cmd.arg(self.config.cargo_features.join(","));
        }

        info!("Building with cargo certora-sbf: {:?}", cmd);

        let output = cmd.output().map_err(|e| {
            crate::CertoraError::BuildError(format!("cargo certora-sbf failed: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::CertoraError::BuildError(format!(
                "cargo certora-sbf build failed: {}",
                stderr
            )));
        }

        // Parse JSON output to find the built .so path
        let _stdout = String::from_utf8_lossy(&output.stdout);

        // Look for the .so file in output or in target directory
        let target_dir = program_path.join("target").join("deploy");
        for entry in walkdir::WalkDir::new(&target_dir)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("so") {
                return Ok(entry.path().to_path_buf());
            }
        }

        Err(crate::CertoraError::BuildError(
            "No .so file found after cargo certora-sbf build".to_string(),
        ))
    }

    // ─── Private helpers ─────────────────────────────────────────────────

    fn find_certora_binary() -> Option<PathBuf> {
        // Check common locations
        let candidates = ["certoraSolanaProver"];

        for name in &candidates {
            if let Ok(output) = Command::new("which").arg(name).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Some(PathBuf::from(path));
                    }
                }
            }
        }

        // Check pip-installed location
        if let Ok(home) = std::env::var("HOME") {
            let pip_path = PathBuf::from(&home)
                .join(".local")
                .join("bin")
                .join("certoraSolanaProver");
            if pip_path.exists() {
                return Some(pip_path);
            }
        }

        None
    }

    fn check_cargo_certora() -> bool {
        Command::new("cargo")
            .args(["certora-sbf", "--help"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
