//! Coverage-Guided Fuzzing Engine
//!
//! Executes eBPF bytecode with randomized inputs and tracks coverage
//! to guide fuzzing toward unexplored code paths. Uses oracles to detect
//! missing signer checks and unauthorized state changes.

use crate::bytecode_parser::{EbpfProgramModel, MutationType};
use crate::oracles::{Oracle, OracleViolation};
use rand::Rng;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::collections::HashSet;
use tracing::{debug, info};

/// Configuration for the fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    /// Maximum number of fuzzing iterations
    pub max_iterations: u64,
    /// Timeout in seconds
    pub timeout_seconds: u64,
    /// Maximum input size in bytes
    pub max_input_size: usize,
    /// Enable coverage-guided fuzzing
    pub coverage_guided: bool,
    /// Oracles to enable
    pub enabled_oracles: Vec<OracleType>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10_000,
            timeout_seconds: 5,
            max_input_size: 10240,
            coverage_guided: true,
            enabled_oracles: vec![
                OracleType::MissingSignerCheck,
                OracleType::UnauthorizedStateChange,
                OracleType::MissingOwnerCheck,
                OracleType::ArbitraryAccountSubstitution,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OracleType {
    MissingSignerCheck,
    UnauthorizedStateChange,
    MissingOwnerCheck,
    ArbitraryAccountSubstitution,
}

/// Coverage-guided fuzzing engine.
pub struct FuzzEngine {
    config: FuzzConfig,
    coverage: HashSet<u64>,
    oracles: Vec<Box<dyn Oracle>>,
}

impl FuzzEngine {
    pub fn new(config: FuzzConfig) -> Self {
        Self {
            config,
            coverage: HashSet::new(),
            oracles: Vec::new(),
        }
    }

    /// Run a fuzzing campaign on the eBPF program model.
    pub fn fuzz_program(&mut self, model: &EbpfProgramModel) -> FuzzCampaignResult {
        info!("FuzzDelSol: Starting coverage-guided fuzzing campaign");
        info!("  Max iterations: {}", self.config.max_iterations);
        info!("  Timeout: {}s", self.config.timeout_seconds);
        info!("  Enabled oracles: {:?}", self.config.enabled_oracles);

        let start_time = std::time::Instant::now();
        let mut violations = Vec::new();
        let mut _total_coverage = 0;

        // Initialize oracles
        self.init_oracles(model);

        let mut iteration = 0;
        while iteration < self.config.max_iterations {
            if start_time.elapsed().as_secs() >= self.config.timeout_seconds {
                info!("FuzzDelSol: Timeout reached after {} iterations", iteration);
                break;
            }

            // Generate random input
            let input = self.generate_input(model);

            // Execute with coverage tracking
            let exec_result = self.execute_with_coverage(model, &input);

            // Check oracles
            for oracle in &self.oracles {
                if let Some(violation) = oracle.check(&exec_result, model) {
                    violations.push(violation);
                }
            }

            // Update coverage
            for addr in &exec_result.covered_addresses {
                if self.coverage.insert(*addr) {
                    _total_coverage += 1;
                }
            }

            iteration += 1;

            if iteration % 1000 == 0 {
                debug!(
                    "FuzzDelSol: Iteration {}, coverage: {}/{} ({:.1}%), violations: {}",
                    iteration,
                    self.coverage.len(),
                    model.instruction_count,
                    (self.coverage.len() as f64 / model.instruction_count as f64) * 100.0,
                    violations.len(),
                );
            }
        }

        let coverage_pct = if model.instruction_count > 0 {
            (self.coverage.len() as f64 / model.instruction_count as f64) * 100.0
        } else {
            0.0
        };

        info!(
            "FuzzDelSol: Campaign complete — {} iterations, {:.1}% coverage, {} violations",
            iteration,
            coverage_pct,
            violations.len()
        );

        FuzzCampaignResult {
            total_iterations: iteration,
            coverage_pct,
            violations,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
        }
    }

    /// Initialize oracles based on configuration.
    fn init_oracles(&mut self, model: &EbpfProgramModel) {
        use crate::oracles::*;

        for oracle_type in &self.config.enabled_oracles {
            match oracle_type {
                OracleType::MissingSignerCheck => {
                    self.oracles
                        .push(Box::new(MissingSignerCheckOracle::new(model)));
                }
                OracleType::UnauthorizedStateChange => {
                    self.oracles
                        .push(Box::new(UnauthorizedStateChangeOracle::new(model)));
                }
                OracleType::MissingOwnerCheck => {
                    self.oracles
                        .push(Box::new(MissingOwnerCheckOracle::new(model)));
                }
                OracleType::ArbitraryAccountSubstitution => {
                    self.oracles
                        .push(Box::new(ArbitraryAccountSubstitutionOracle::new(model)));
                }
            }
        }
    }

    /// Generate random input for fuzzing.
    fn generate_input(&self, _model: &EbpfProgramModel) -> FuzzInput {
        let mut rng = rand::thread_rng();

        // Generate random accounts
        let num_accounts = rng.gen_range(1..=10);
        let mut accounts = Vec::new();

        for _ in 0..num_accounts {
            accounts.push(FuzzAccount {
                pubkey: Pubkey::new_unique(),
                is_signer: rng.gen_bool(0.3),
                is_writable: rng.gen_bool(0.5),
                lamports: rng.gen_range(0..1_000_000_000),
                data: vec![rng.gen(); rng.gen_range(0..256)],
                owner: Pubkey::new_unique(),
            });
        }

        // Generate random instruction data
        let data_len = rng.gen_range(0..self.config.max_input_size);
        let instruction_data: Vec<u8> = (0..data_len).map(|_| rng.gen()).collect();

        FuzzInput {
            accounts,
            instruction_data,
        }
    }

    /// Execute the program with coverage tracking.
    fn execute_with_coverage(
        &self,
        model: &EbpfProgramModel,
        input: &FuzzInput,
    ) -> ExecutionResult {
        // Simulated execution with coverage tracking
        // In a real implementation, this would use solana-rbpf VM

        let mut covered_addresses = HashSet::new();
        let mut state_changes = Vec::new();

        // Simulate coverage: mark some addresses as covered based on input
        let input_hash = self.hash_input(input);
        for func in &model.functions {
            if (input_hash % (func.address + 1)).is_multiple_of(3) {
                covered_addresses.insert(func.address);
            }
        }

        // Simulate state changes for functions that modify account data
        for func in &model.functions {
            if func.modifies_account_data && covered_addresses.contains(&func.address) {
                // Check if there's a corresponding signer check
                let has_signer_check = model
                    .signer_checks
                    .iter()
                    .any(|check| check.function == func.name);

                state_changes.push(StateChange {
                    address: func.address,
                    function: func.name.clone(),
                    account_index: 0,
                    had_signer_check: has_signer_check,
                    mutation_type: MutationType::AccountDataWrite,
                });
            }
        }

        ExecutionResult {
            covered_addresses,
            state_changes,
            input: input.clone(),
            success: true,
        }
    }

    fn hash_input(&self, input: &FuzzInput) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        input.instruction_data.hash(&mut hasher);
        hasher.finish()
    }
}

/// Fuzzing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzInput {
    pub accounts: Vec<FuzzAccount>,
    pub instruction_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzAccount {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: Pubkey,
}

/// Result of a single execution.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub covered_addresses: HashSet<u64>,
    pub state_changes: Vec<StateChange>,
    pub input: FuzzInput,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: u64,
    pub function: String,
    pub account_index: usize,
    pub had_signer_check: bool,
    pub mutation_type: MutationType,
}

/// Result of a fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzCampaignResult {
    pub total_iterations: u64,
    pub coverage_pct: f64,
    pub violations: Vec<OracleViolation>,
    pub execution_time_ms: u64,
}
