//! Kani Runner
//!
//! Responsible for invoking `cargo kani` (or `kani` directly) as a subprocess,
//! passing the correct flags for Solana program verification, capturing stdout/stderr,
//! and detecting availability of the Kani toolchain.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

/// Configuration for the Kani verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KaniConfig {
    /// Maximum loop unwind depth for CBMC bounded model checking
    pub unwind_depth: u32,
    /// Timeout in seconds for the verification run
    pub timeout_secs: u64,
    /// Whether to use concrete playback for counterexamples
    pub concrete_playback: bool,
    /// Whether to produce a CBMC trace for failed properties
    pub enable_traces: bool,
    /// Extra arguments to pass to `cargo kani`
    pub extra_args: Vec<String>,
    /// Number of parallel solver jobs
    pub solver_jobs: u32,
    /// SAT solver backend (minisat, cadical, glucose)
    pub solver: String,
    /// Whether to enable stubbing for external calls
    pub enable_stubbing: bool,
    /// Memory limit in MB for the CBMC process
    pub memory_limit_mb: u32,
}

impl Default for KaniConfig {
    fn default() -> Self {
        Self {
            unwind_depth: 16,
            timeout_secs: 300,
            concrete_playback: true,
            enable_traces: true,
            extra_args: Vec::new(),
            solver_jobs: 1,
            solver: "cadical".to_string(),
            enable_stubbing: true,
            memory_limit_mb: 4096,
        }
    }
}

impl KaniConfig {
    /// Create config optimized for Solana program verification.
    pub fn for_solana() -> Self {
        Self {
            unwind_depth: 20,
            timeout_secs: 600,
            concrete_playback: true,
            enable_traces: true,
            extra_args: vec!["--output-format=regular".to_string()],
            solver_jobs: 2,
            solver: "cadical".to_string(),
            enable_stubbing: true,
            memory_limit_mb: 8192,
        }
    }
}

/// Runner that invokes the Kani toolchain.
pub struct KaniRunner {
    config: KaniConfig,
    kani_available: Option<bool>,
    kani_version_cache: Option<String>,
}

impl KaniRunner {
    pub fn new(config: KaniConfig) -> Self {
        Self {
            config,
            kani_available: None,
            kani_version_cache: None,
        }
    }

    /// Check if `cargo kani` is available on the system.
    pub fn is_kani_available(&self) -> bool {
        if let Some(avail) = self.kani_available {
            return avail;
        }

        let result = Command::new("cargo").args(["kani", "--version"]).output();

        match result {
            Ok(output) => output.status.success(),
            Err(_) => {
                // Try direct kani binary
                Command::new("kani")
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            }
        }
    }

    /// Detect the installed Kani version.
    pub fn detect_kani_version(&self) -> Option<String> {
        if let Some(ref cached) = self.kani_version_cache {
            return Some(cached.clone());
        }

        let result = Command::new("cargo")
            .args(["kani", "--version"])
            .output()
            .ok()?;

        if result.status.success() {
            let version = String::from_utf8_lossy(&result.stdout).trim().to_string();
            Some(version)
        } else {
            None
        }
    }

    /// Run Kani verification on the generated harness files.
    ///
    /// Returns the raw stdout output for parsing.
    pub fn run_verification(
        &self,
        harness_dir: &Path,
        program_dir: &Path,
    ) -> Result<String, crate::KaniError> {
        if !self.is_kani_available() {
            return Err(crate::KaniError::ExecutionError(
                "cargo kani is not installed. Install via: cargo install --locked kani-verifier && cargo kani setup".to_string()
            ));
        }

        info!("Running cargo kani on {:?}", harness_dir);

        // Collect all harness files
        let harness_files: Vec<_> = std::fs::read_dir(harness_dir)
            .map_err(|e| crate::KaniError::IoError(e.to_string()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "rs")
                    .unwrap_or(false)
            })
            .collect();

        if harness_files.is_empty() {
            return Err(crate::KaniError::HarnessError(
                "No harness files found in harness directory".to_string(),
            ));
        }

        let mut combined_output = String::new();

        for harness_entry in &harness_files {
            let harness_path = harness_entry.path();
            let harness_name = harness_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");

            info!("Verifying harness: {}", harness_name);

            let mut cmd = Command::new("cargo");
            cmd.arg("kani")
                .arg("--harness-dir")
                .arg(harness_dir)
                .arg("--unwind")
                .arg(self.config.unwind_depth.to_string());

            if self.config.enable_traces {
                cmd.arg("--visualize");
            }

            if self.config.concrete_playback {
                cmd.arg("--concrete-playback=print");
            }

            cmd.arg("--solver").arg(&self.config.solver);

            if self.config.memory_limit_mb > 0 {
                cmd.env(
                    "CBMC_MEMORY_LIMIT",
                    format!("{}m", self.config.memory_limit_mb),
                );
            }

            for extra in &self.config.extra_args {
                cmd.arg(extra);
            }

            cmd.current_dir(program_dir);

            let output = cmd.output().map_err(|e| {
                crate::KaniError::ExecutionError(format!("Failed to execute cargo kani: {}", e))
            })?;

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            combined_output.push_str(&format!(
                "\n=== Harness: {} ===\n{}\n",
                harness_name, stdout
            ));

            if !stderr.is_empty() {
                debug!("Kani stderr for {}: {}", harness_name, stderr);
            }

            if !output.status.success() {
                warn!(
                    "Kani verification failed for harness '{}' (exit code: {:?})",
                    harness_name,
                    output.status.code()
                );
                combined_output.push_str(&format!(
                    "VERIFICATION FAILED for {}\n{}\n",
                    harness_name, stderr
                ));
            }
        }

        Ok(combined_output)
    }

    /// Run a single harness file through Kani.
    pub fn run_single_harness(
        &self,
        harness_file: &Path,
        program_dir: &Path,
    ) -> Result<String, crate::KaniError> {
        if !self.is_kani_available() {
            return Err(crate::KaniError::ExecutionError(
                "cargo kani not available".to_string(),
            ));
        }

        let mut cmd = Command::new("cargo");
        cmd.arg("kani")
            .arg(harness_file)
            .arg("--unwind")
            .arg(self.config.unwind_depth.to_string())
            .arg("--solver")
            .arg(&self.config.solver)
            .current_dir(program_dir);

        let output = cmd
            .output()
            .map_err(|e| crate::KaniError::ExecutionError(e.to_string()))?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Check if CBMC is available (Kani's backend).
    pub fn is_cbmc_available(&self) -> bool {
        Command::new("cbmc")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get CBMC version.
    pub fn cbmc_version(&self) -> Option<String> {
        Command::new("cbmc")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
}
