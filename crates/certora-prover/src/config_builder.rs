//! Certora Configuration Builder
//!
//! Generates `.conf` (JSON5) configuration files that control the
//! Certora Solana Prover's behavior.
//!
//! Two modes are supported:
//! 1. **From Sources**: References `Cargo.toml` and uses `cargo certora-sbf`
//! 2. **Pre-built**: References `.so` files directly with `"process": "sbf"`
//!
//! See: <https://docs.certora.com/en/latest/docs/solana/options.html>

use crate::certora_runner::CertoraConfig;
use crate::spec_generator::CvlrRule;
use serde_json;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Builds `.conf` configuration files for the Certora Prover.
pub struct CertoraConfBuilder;

impl CertoraConfBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build a `.conf` file and write it to disk.
    pub fn build(
        &self,
        program_path: &Path,
        sbf_path: &Path,
        rules: &[CvlrRule],
        config: &CertoraConfig,
    ) -> Result<PathBuf, crate::CertoraError> {
        let conf = if config.use_prebuilt {
            self.build_prebuilt_conf(sbf_path, rules, config)?
        } else {
            self.build_sources_conf(program_path, rules, config)?
        };

        // Write to a temp directory alongside the program
        let conf_dir = program_path.join(".certora");
        std::fs::create_dir_all(&conf_dir).map_err(|e| {
            crate::CertoraError::ConfigError(format!("Cannot create .certora directory: {}", e))
        })?;

        let conf_path = conf_dir.join("verification.conf");
        std::fs::write(&conf_path, &conf).map_err(|e| {
            crate::CertoraError::ConfigError(format!("Cannot write .conf file: {}", e))
        })?;

        // Also write the CVLR spec rules to a file
        self.write_spec_file(rules, &conf_dir)?;

        // Write inlining and summaries placeholder files
        self.write_inlining_file(&conf_dir)?;
        self.write_summaries_file(&conf_dir)?;

        info!("Certora configuration written to: {:?}", conf_path);
        Ok(conf_path)
    }

    /// Build configuration for pre-built .so verification.
    fn build_prebuilt_conf(
        &self,
        sbf_path: &Path,
        rules: &[CvlrRule],
        config: &CertoraConfig,
    ) -> Result<String, crate::CertoraError> {
        let rule_names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();

        let mut conf_obj = serde_json::Map::new();

        // Required: files array with the .so path
        conf_obj.insert(
            "files".into(),
            serde_json::json!([sbf_path.to_string_lossy()]),
        );

        // Process type: sbf for Solana
        conf_obj.insert("process".into(), serde_json::json!("sbf"));

        // Rule names to verify
        if !rule_names.is_empty() {
            conf_obj.insert("rule".into(), serde_json::json!(rule_names));
        }

        // Loop settings
        conf_obj.insert(
            "optimistic_loop".into(),
            serde_json::json!(config.optimistic_loop),
        );
        conf_obj.insert("loop_iter".into(), serde_json::json!(config.loop_iter));

        // Message
        if let Some(ref msg) = config.msg {
            conf_obj.insert("msg".into(), serde_json::json!(msg));
        }

        // Sanity checks
        if config.rule_sanity {
            conf_obj.insert("rule_sanity".into(), serde_json::json!("basic"));
        }

        // Multi-assertion checking
        if config.multi_assert_check {
            conf_obj.insert("multi_assert_check".into(), serde_json::json!(true));
        }

        // Inlining and summaries
        if let Some(ref inlining) = config.solana_inlining {
            conf_obj.insert(
                "solana_inlining".into(),
                serde_json::json!([inlining.to_string_lossy()]),
            );
        } else {
            conf_obj.insert(
                "solana_inlining".into(),
                serde_json::json!([".certora/cvlr_inlining.txt"]),
            );
        }

        if let Some(ref summaries) = config.solana_summaries {
            conf_obj.insert(
                "solana_summaries".into(),
                serde_json::json!([summaries.to_string_lossy()]),
            );
        } else {
            conf_obj.insert(
                "solana_summaries".into(),
                serde_json::json!([".certora/cvlr_summaries.txt"]),
            );
        }

        // Timeout
        conf_obj.insert(
            "global_timeout".into(),
            serde_json::json!(config.global_timeout),
        );
        conf_obj.insert("smt_timeout".into(), serde_json::json!(config.smt_timeout));

        // Wait for results
        if config.wait_for_results {
            conf_obj.insert("wait_for_results".into(), serde_json::json!(true));
        }

        let json =
            serde_json::to_string_pretty(&serde_json::Value::Object(conf_obj)).map_err(|e| {
                crate::CertoraError::ConfigError(format!("JSON serialization error: {}", e))
            })?;

        Ok(json)
    }

    /// Build configuration for source-based verification.
    fn build_sources_conf(
        &self,
        _program_path: &Path,
        rules: &[CvlrRule],
        config: &CertoraConfig,
    ) -> Result<String, crate::CertoraError> {
        let rule_names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();

        let mut conf_obj = serde_json::Map::new();

        // From sources: no "files" key — cargo certora-sbf builds the project
        if !rule_names.is_empty() {
            conf_obj.insert("rule".into(), serde_json::json!(rule_names));
        }

        conf_obj.insert(
            "optimistic_loop".into(),
            serde_json::json!(config.optimistic_loop),
        );
        conf_obj.insert("loop_iter".into(), serde_json::json!(config.loop_iter));

        if let Some(ref msg) = config.msg {
            conf_obj.insert("msg".into(), serde_json::json!(msg));
        }

        if config.rule_sanity {
            conf_obj.insert("rule_sanity".into(), serde_json::json!("basic"));
        }

        if config.multi_assert_check {
            conf_obj.insert("multi_assert_check".into(), serde_json::json!(true));
        }

        conf_obj.insert(
            "global_timeout".into(),
            serde_json::json!(config.global_timeout),
        );
        conf_obj.insert("smt_timeout".into(), serde_json::json!(config.smt_timeout));

        if !config.cargo_features.is_empty() {
            conf_obj.insert(
                "cargo_features".into(),
                serde_json::json!(config.cargo_features),
            );
        }

        if config.wait_for_results {
            conf_obj.insert("wait_for_results".into(), serde_json::json!(true));
        }

        let json =
            serde_json::to_string_pretty(&serde_json::Value::Object(conf_obj)).map_err(|e| {
                crate::CertoraError::ConfigError(format!("JSON serialization error: {}", e))
            })?;

        Ok(json)
    }

    /// Write CVLR specification rules to a Rust file.
    fn write_spec_file(
        &self,
        rules: &[CvlrRule],
        conf_dir: &Path,
    ) -> Result<(), crate::CertoraError> {
        let spec_path = conf_dir.join("cvlr_spec.rs");

        let mut content = String::new();
        content.push_str("//! Auto-generated CVLR specification rules for Certora Solana Prover\n");
        content.push_str("//! Generated by solana-security-swarm certora-prover integration\n\n");
        content.push_str("use certora_cvlr::*;\n\n");

        for rule in rules {
            content.push_str(&format!("// Category: {}\n", rule.category));
            content.push_str(&format!("// Severity: {}\n", rule.severity));
            content.push_str(&format!("// Description: {}\n", rule.description));
            content.push_str(&rule.body);
            content.push_str("\n\n");
        }

        std::fs::write(&spec_path, &content).map_err(|e| {
            crate::CertoraError::ConfigError(format!("Cannot write spec file: {}", e))
        })?;

        debug!("CVLR spec written to: {:?}", spec_path);
        Ok(())
    }

    /// Write inlining configuration file.
    ///
    /// Inlining files tell the Certora Prover how to inline Solana runtime
    /// functions for accurate analysis.
    fn write_inlining_file(&self, conf_dir: &Path) -> Result<(), crate::CertoraError> {
        let inlining_path = conf_dir.join("cvlr_inlining.txt");

        let inlining_content = r#"# Certora Solana Prover inlining configuration
# Auto-generated by solana-security-swarm
# See: https://github.com/Certora/SolanaExamples/blob/main/certora/summaries/cvlr_inlining_core.txt

# Inline Solana runtime system calls
sol_invoke_signed_rust
sol_log_
sol_log_64_
sol_log_compute_units_

# Inline SPL Token program operations
spl_token::instruction::transfer
spl_token::instruction::mint_to
spl_token::instruction::burn
spl_token::instruction::approve
spl_token::instruction::revoke

# Inline Anchor framework operations
anchor_lang::prelude::Program::invoke
anchor_lang::context::Context::remaining_accounts
anchor_lang::accounts::account::Account::try_from

# Inline borsh serialization
borsh::BorshSerialize::serialize
borsh::BorshDeserialize::deserialize

# Inline core Pubkey operations
solana_program::pubkey::Pubkey::find_program_address
solana_program::pubkey::Pubkey::create_program_address
"#;

        std::fs::write(&inlining_path, inlining_content).map_err(|e| {
            crate::CertoraError::ConfigError(format!("Cannot write inlining file: {}", e))
        })?;

        Ok(())
    }

    /// Write summaries configuration file.
    ///
    /// Summaries tell the Certora Prover how to model external functions
    /// that aren't being verified.
    fn write_summaries_file(&self, conf_dir: &Path) -> Result<(), crate::CertoraError> {
        let summaries_path = conf_dir.join("cvlr_summaries.txt");

        let summaries_content = r#"# Certora Solana Prover summaries configuration
# Auto-generated by solana-security-swarm
# See: https://github.com/Certora/SolanaExamples/blob/main/certora/summaries/cvlr_summaries_core.txt

# Solana system program summaries
sol_memcpy_ -> NONDET
sol_memset_ -> NONDET
sol_memmove_ -> NONDET
sol_memcmp_ -> NONDET

# SHA256 and Keccak are expensive to model precisely
sol_sha256 -> NONDET
sol_keccak256 -> NONDET

# Clock sysvar access
sol_get_clock_sysvar -> NONDET

# Rent sysvar access
sol_get_rent_sysvar -> NONDET

# Epoch schedule
sol_get_epoch_schedule_sysvar -> NONDET

# Logging (side-effect free for verification)
sol_log_ -> HAVOC_ECF
sol_log_64_ -> HAVOC_ECF
sol_log_pubkey -> HAVOC_ECF
sol_log_data -> HAVOC_ECF

# Allocator
sol_alloc_free_ -> NONDET

# Remaining compute units
sol_remaining_compute_units -> NONDET
"#;

        std::fs::write(&summaries_path, summaries_content).map_err(|e| {
            crate::CertoraError::ConfigError(format!("Cannot write summaries file: {}", e))
        })?;

        Ok(())
    }
}

impl Default for CertoraConfBuilder {
    fn default() -> Self {
        Self::new()
    }
}
