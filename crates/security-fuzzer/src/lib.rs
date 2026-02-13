//! Coverage-Guided Security Fuzzing for Solana Programs
//!
//! Implements a coverage-guided fuzzer that generates test inputs
//! to maximize code coverage and find edge cases and crashes.

use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};

/// A single fuzz input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzInput {
    /// Raw instruction data
    pub data: Vec<u8>,
    /// Named fields (parsed)
    pub fields: HashMap<String, FuzzValue>,
    /// Accounts configuration
    pub accounts: Vec<FuzzAccount>,
    /// Input generation
    pub generation: usize,
    /// Coverage hash of this input
    pub coverage_hash: String,
}

/// A value in a fuzz input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I64(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    Pubkey([u8; 32]),
    String(String),
}

impl FuzzValue {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            FuzzValue::U8(v) => vec![*v],
            FuzzValue::U16(v) => v.to_le_bytes().to_vec(),
            FuzzValue::U32(v) => v.to_le_bytes().to_vec(),
            FuzzValue::U64(v) => v.to_le_bytes().to_vec(),
            FuzzValue::U128(v) => v.to_le_bytes().to_vec(),
            FuzzValue::I64(v) => v.to_le_bytes().to_vec(),
            FuzzValue::Bool(v) => vec![if *v { 1 } else { 0 }],
            FuzzValue::Bytes(v) => v.clone(),
            FuzzValue::Pubkey(v) => v.to_vec(),
            FuzzValue::String(v) => v.as_bytes().to_vec(),
        }
    }

    pub fn mutate(&self, rng: &mut StdRng) -> Self {
        match self {
            FuzzValue::U8(v) => FuzzValue::U8(Self::mutate_u8(*v, rng)),
            FuzzValue::U16(v) => FuzzValue::U16(Self::mutate_u16(*v, rng)),
            FuzzValue::U32(v) => FuzzValue::U32(Self::mutate_u32(*v, rng)),
            FuzzValue::U64(v) => FuzzValue::U64(Self::mutate_u64(*v, rng)),
            FuzzValue::U128(v) => FuzzValue::U128(Self::mutate_u128(*v, rng)),
            FuzzValue::I64(v) => FuzzValue::I64(Self::mutate_i64(*v, rng)),
            FuzzValue::Bool(_) => FuzzValue::Bool(rng.gen()),
            FuzzValue::Bytes(v) => FuzzValue::Bytes(Self::mutate_bytes(v, rng)),
            FuzzValue::Pubkey(v) => FuzzValue::Pubkey(Self::mutate_pubkey(v, rng)),
            FuzzValue::String(v) => FuzzValue::String(Self::mutate_string(v, rng)),
        }
    }

    fn mutate_u8(v: u8, rng: &mut StdRng) -> u8 {
        match rng.gen_range(0..5) {
            0 => v.wrapping_add(1),
            1 => v.wrapping_sub(1),
            2 => rng.gen(),
            3 => [0, 1, u8::MAX, u8::MAX - 1][rng.gen_range(0..4)],
            _ => v ^ (1 << rng.gen_range(0..8)),
        }
    }

    fn mutate_u16(v: u16, rng: &mut StdRng) -> u16 {
        match rng.gen_range(0..5) {
            0 => v.wrapping_add(1),
            1 => v.wrapping_sub(1),
            2 => rng.gen(),
            3 => [0, 1, u16::MAX, u16::MAX - 1][rng.gen_range(0..4)],
            _ => v ^ (1 << rng.gen_range(0..16)),
        }
    }

    fn mutate_u32(v: u32, rng: &mut StdRng) -> u32 {
        match rng.gen_range(0..5) {
            0 => v.wrapping_add(1),
            1 => v.wrapping_sub(1),
            2 => rng.gen(),
            3 => [0, 1, u32::MAX, u32::MAX - 1][rng.gen_range(0..4)],
            _ => v ^ (1 << rng.gen_range(0..32)),
        }
    }

    fn mutate_u64(v: u64, rng: &mut StdRng) -> u64 {
        match rng.gen_range(0..6) {
            0 => v.wrapping_add(1),
            1 => v.wrapping_sub(1),
            2 => rng.gen(),
            3 => [0, 1, u64::MAX, u64::MAX - 1][rng.gen_range(0..4)],
            4 => v ^ (1 << rng.gen_range(0..64)),
            _ => [1000, 1_000_000, 1_000_000_000][rng.gen_range(0..3)],
        }
    }

    fn mutate_u128(v: u128, rng: &mut StdRng) -> u128 {
        match rng.gen_range(0..5) {
            0 => v.wrapping_add(1),
            1 => v.wrapping_sub(1),
            2 => rng.gen(),
            3 => [0, 1, u128::MAX, u128::MAX - 1][rng.gen_range(0..4)],
            _ => v ^ (1 << rng.gen_range(0..128)),
        }
    }

    fn mutate_i64(v: i64, rng: &mut StdRng) -> i64 {
        match rng.gen_range(0..6) {
            0 => v.wrapping_add(1),
            1 => v.wrapping_sub(1),
            2 => rng.gen(),
            3 => [0, 1, -1, i64::MAX, i64::MIN][rng.gen_range(0..5)],
            4 => v ^ (1 << rng.gen_range(0..64)),
            _ => -v,
        }
    }

    fn mutate_bytes(v: &[u8], rng: &mut StdRng) -> Vec<u8> {
        let mut result = v.to_vec();
        if result.is_empty() {
            result.push(rng.gen());
            return result;
        }

        match rng.gen_range(0..5) {
            0 => {
                // Flip random byte
                let idx = rng.gen_range(0..result.len());
                result[idx] = result[idx].wrapping_add(1);
            }
            1 => {
                // Insert byte
                let idx = rng.gen_range(0..=result.len());
                result.insert(idx, rng.gen());
            }
            2 => {
                // Remove byte
                if result.len() > 1 {
                    let idx = rng.gen_range(0..result.len());
                    result.remove(idx);
                }
            }
            3 => {
                // Duplicate chunk
                if result.len() >= 2 {
                    let start = rng.gen_range(0..result.len() - 1);
                    let end = rng.gen_range(start + 1..result.len());
                    let chunk: Vec<u8> = result[start..end].to_vec();
                    result.extend(chunk);
                }
            }
            _ => {
                // Replace with interesting value
                result = vec![0xFF; rng.gen_range(1..10)];
            }
        }

        result
    }

    fn mutate_pubkey(v: &[u8; 32], rng: &mut StdRng) -> [u8; 32] {
        let mut result = *v;
        match rng.gen_range(0..4) {
            0 => {
                // Flip random byte
                let idx = rng.gen_range(0..32);
                result[idx] ^= 1 << rng.gen_range(0..8);
            }
            1 => {
                // All zeros
                result = [0u8; 32];
            }
            2 => {
                // All ones
                result = [0xFF; 32];
            }
            _ => {
                // Random key
                rng.fill(&mut result);
            }
        }
        result
    }

    fn mutate_string(v: &str, rng: &mut StdRng) -> String {
        let mut chars: Vec<char> = v.chars().collect();

        match rng.gen_range(0..5) {
            0 if !chars.is_empty() => {
                // Flip random char
                let idx = rng.gen_range(0..chars.len());
                chars[idx] = rng.gen();
            }
            1 => {
                // Insert char
                let idx = rng.gen_range(0..=chars.len());
                chars.insert(idx, rng.gen());
            }
            2 if chars.len() > 1 => {
                // Remove char
                let idx = rng.gen_range(0..chars.len());
                chars.remove(idx);
            }
            3 => {
                // Empty string
                chars.clear();
            }
            _ => {
                // Long string
                chars.extend(std::iter::repeat_n('A', 100));
            }
        }

        chars.into_iter().collect()
    }
}

/// Account configuration for fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzAccount {
    pub name: String,
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: [u8; 32],
}

/// Result of executing a fuzz input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub input: FuzzInput,
    pub success: bool,
    pub error: Option<String>,
    pub error_code: Option<u32>,
    pub coverage_bitmap: Vec<u8>,
    pub interesting: bool,
    pub is_crash: bool,
    pub execution_time_us: u64,
}

/// Coverage tracking
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct CoverageTracker {
    /// Bitmap of covered edges
    bitmap: Vec<u8>,
    /// Unique coverage hashes seen
    seen_coverage: HashSet<String>,
    /// Total edges discovered
    total_edges: usize,
    /// Coverage by input
    coverage_by_input: HashMap<String, usize>,
}

impl CoverageTracker {
    pub fn new(size: usize) -> Self {
        Self {
            bitmap: vec![0; size],
            seen_coverage: HashSet::new(),
            total_edges: 0,
            coverage_by_input: HashMap::new(),
        }
    }

    /// Update coverage with new bitmap
    pub fn update(&mut self, new_bitmap: &[u8]) -> bool {
        let mut new_coverage = false;

        for (i, &byte) in new_bitmap.iter().enumerate() {
            if i < self.bitmap.len() && byte != 0 {
                if self.bitmap[i] == 0 {
                    new_coverage = true;
                    self.total_edges += 1;
                }
                self.bitmap[i] |= byte;
            }
        }

        new_coverage
    }

    /// Get coverage hash for a bitmap
    pub fn hash_coverage(bitmap: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bitmap);
        format!("{:x}", hasher.finalize())
    }

    /// Check if coverage is new
    pub fn is_new_coverage(&mut self, bitmap: &[u8]) -> bool {
        let hash = Self::hash_coverage(bitmap);
        if self.seen_coverage.contains(&hash) {
            false
        } else {
            self.seen_coverage.insert(hash);
            true
        }
    }

    /// Get coverage percentage
    pub fn coverage_percentage(&self) -> f64 {
        let covered = self.bitmap.iter().filter(|&&b| b != 0).count();
        covered as f64 / self.bitmap.len() as f64 * 100.0
    }

    /// Get number of unique paths
    pub fn unique_paths(&self) -> usize {
        self.seen_coverage.len()
    }
}

/// Fuzzer configuration
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    /// Maximum iterations
    pub max_iterations: usize,
    /// Seed for RNG
    pub seed: u64,
    /// Coverage bitmap size
    pub coverage_size: usize,
    /// Maximum input size
    pub max_input_size: usize,
    /// Mutation probability
    pub mutation_probability: f64,
    /// Number of mutations per input
    pub mutations_per_input: usize,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10000,
            seed: 42,
            coverage_size: 65536,
            max_input_size: 1024,
            mutation_probability: 0.1,
            mutations_per_input: 5,
        }
    }
}

/// Fuzzing statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuzzStats {
    pub total_executions: usize,
    pub crashes_found: usize,
    pub unique_crashes: usize,
    pub coverage_paths: usize,
    pub coverage_percentage: f64,
    pub inputs_in_corpus: usize,
    pub execution_time_total_us: u64,
    pub findings: Vec<FuzzFinding>,
}

/// A finding from fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzFinding {
    pub finding_type: FindingType,
    pub input: FuzzInput,
    pub description: String,
    pub severity: FuzzSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingType {
    Crash,
    Panic,
    ArithmeticOverflow,
    OutOfBounds,
    InfiniteLoop,
    MemoryExhaustion,
    UnexpectedError(u32),
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Main fuzzer
pub struct SecurityFuzzer {
    config: FuzzerConfig,
    rng: StdRng,
    corpus: VecDeque<FuzzInput>,
    coverage: CoverageTracker,
    stats: FuzzStats,
    crash_hashes: HashSet<String>,
}

impl SecurityFuzzer {
    pub fn new(config: FuzzerConfig) -> Self {
        let rng = StdRng::seed_from_u64(config.seed);
        let coverage = CoverageTracker::new(config.coverage_size);

        Self {
            config,
            rng,
            corpus: VecDeque::new(),
            coverage,
            stats: FuzzStats::default(),
            crash_hashes: HashSet::new(),
        }
    }

    /// Add initial seed inputs to corpus
    pub fn add_seed(&mut self, input: FuzzInput) {
        self.corpus.push_back(input);
        self.stats.inputs_in_corpus = self.corpus.len();
    }

    /// Generate a random initial input
    pub fn generate_random_input(&mut self, schema: &FuzzInputSchema) -> FuzzInput {
        let mut fields = HashMap::new();

        for field in &schema.fields {
            let value = match field.field_type {
                FieldType::U8 => FuzzValue::U8(self.rng.gen()),
                FieldType::U16 => FuzzValue::U16(self.rng.gen()),
                FieldType::U32 => FuzzValue::U32(self.rng.gen()),
                FieldType::U64 => FuzzValue::U64(self.rng.gen()),
                FieldType::U128 => FuzzValue::U128(self.rng.gen()),
                FieldType::I64 => FuzzValue::I64(self.rng.gen()),
                FieldType::Bool => FuzzValue::Bool(self.rng.gen()),
                FieldType::Bytes(max_len) => {
                    let len = self.rng.gen_range(0..max_len);
                    let bytes: Vec<u8> = (0..len).map(|_| self.rng.gen()).collect();
                    FuzzValue::Bytes(bytes)
                }
                FieldType::Pubkey => {
                    let mut key = [0u8; 32];
                    self.rng.fill(&mut key);
                    FuzzValue::Pubkey(key)
                }
                FieldType::String(max_len) => {
                    let len = self.rng.gen_range(0..max_len);
                    let s: String = (0..len).map(|_| self.rng.gen_range('a'..='z')).collect();
                    FuzzValue::String(s)
                }
            };
            fields.insert(field.name.clone(), value);
        }

        // Convert fields to data
        let mut data = Vec::new();
        for field in &schema.fields {
            if let Some(value) = fields.get(&field.name) {
                data.extend(value.to_bytes());
            }
        }

        FuzzInput {
            data,
            fields,
            accounts: Vec::new(),
            generation: 0,
            coverage_hash: String::new(),
        }
    }

    /// Mutate an existing input
    pub fn mutate_input(&mut self, input: &FuzzInput) -> FuzzInput {
        let mut new_input = input.clone();
        new_input.generation = input.generation + 1;

        // Mutate random fields
        let field_names: Vec<String> = new_input.fields.keys().cloned().collect();
        for _ in 0..self.config.mutations_per_input {
            if self.rng.gen::<f64>() < self.config.mutation_probability && !field_names.is_empty() {
                let field_name = &field_names[self.rng.gen_range(0..field_names.len())];
                if let Some(value) = new_input.fields.get(field_name) {
                    let mutated = value.mutate(&mut self.rng);
                    new_input.fields.insert(field_name.clone(), mutated);
                }
            }
        }

        // Rebuild data from fields
        new_input.data = new_input
            .fields
            .values()
            .flat_map(|v| v.to_bytes())
            .collect();

        new_input
    }

    /// Process execution result
    pub fn process_result(&mut self, result: FuzzResult) {
        self.stats.total_executions += 1;
        self.stats.execution_time_total_us += result.execution_time_us;

        // Update coverage
        let is_new = self.coverage.update(&result.coverage_bitmap);
        let is_new_coverage = self.coverage.is_new_coverage(&result.coverage_bitmap);

        self.stats.coverage_percentage = self.coverage.coverage_percentage();
        self.stats.coverage_paths = self.coverage.unique_paths();

        // If new coverage, add to corpus
        if is_new || is_new_coverage {
            let mut input = result.input.clone();
            input.coverage_hash = CoverageTracker::hash_coverage(&result.coverage_bitmap);
            self.corpus.push_back(input);
            self.stats.inputs_in_corpus = self.corpus.len();
        }

        // Check for crashes
        if result.is_crash {
            let crash_hash = self.hash_crash(&result);
            if !self.crash_hashes.contains(&crash_hash) {
                self.crash_hashes.insert(crash_hash);
                self.stats.crashes_found += 1;
                self.stats.unique_crashes += 1;

                // Create finding
                let finding = FuzzFinding {
                    finding_type: self.classify_crash(&result),
                    input: result.input.clone(),
                    description: result.error.clone().unwrap_or_default(),
                    severity: FuzzSeverity::Critical,
                };
                self.stats.findings.push(finding);
            }
        }
    }

    /// Select an input from corpus for mutation
    pub fn select_input(&mut self) -> Option<FuzzInput> {
        if self.corpus.is_empty() {
            return None;
        }

        // Prefer newer inputs with higher coverage
        let idx = self.rng.gen_range(0..self.corpus.len());
        self.corpus.get(idx).cloned()
    }

    /// Run fuzzing loop
    pub fn fuzz<F>(&mut self, execute_fn: F) -> FuzzStats
    where
        F: Fn(&FuzzInput) -> FuzzResult,
    {
        for _ in 0..self.config.max_iterations {
            // Select or generate input
            let input = if let Some(parent) = self.select_input() {
                self.mutate_input(&parent)
            } else {
                continue;
            };

            // Execute and process
            let result = execute_fn(&input);
            self.process_result(result);
        }

        self.stats.clone()
    }

    /// Hash crash for deduplication
    fn hash_crash(&self, result: &FuzzResult) -> String {
        let mut hasher = Sha256::new();
        if let Some(ref error) = result.error {
            hasher.update(error.as_bytes());
        }
        if let Some(code) = result.error_code {
            hasher.update(code.to_le_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Classify crash type
    fn classify_crash(&self, result: &FuzzResult) -> FindingType {
        let error = result.error.as_deref().unwrap_or("");

        if error.contains("overflow") || error.contains("underflow") {
            FindingType::ArithmeticOverflow
        } else if error.contains("out of bounds") || error.contains("index out of range") {
            FindingType::OutOfBounds
        } else if error.contains("panic") {
            FindingType::Panic
        } else if error.contains("memory") {
            FindingType::MemoryExhaustion
        } else if let Some(code) = result.error_code {
            FindingType::UnexpectedError(code)
        } else {
            FindingType::Crash
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &FuzzStats {
        &self.stats
    }

    /// Get corpus
    pub fn get_corpus(&self) -> &VecDeque<FuzzInput> {
        &self.corpus
    }
}

/// Schema for generating fuzz inputs
#[derive(Debug, Clone)]
pub struct FuzzInputSchema {
    pub fields: Vec<FieldSchema>,
}

#[derive(Debug, Clone)]
pub struct FieldSchema {
    pub name: String,
    pub field_type: FieldType,
}

#[derive(Debug, Clone)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    U128,
    I64,
    Bool,
    Bytes(usize),
    Pubkey,
    String(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum FuzzError {
    #[error("Fuzzing error: {0}")]
    FuzzingError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_creation() {
        let config = FuzzerConfig::default();
        let fuzzer = SecurityFuzzer::new(config);
        assert!(fuzzer.corpus.is_empty());
    }

    #[test]
    fn test_mutation() {
        let config = FuzzerConfig::default();
        let mut fuzzer = SecurityFuzzer::new(config);

        let mut fields = HashMap::new();
        fields.insert("amount".to_string(), FuzzValue::U64(1000));

        let input = FuzzInput {
            data: vec![0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            fields,
            accounts: Vec::new(),
            generation: 0,
            coverage_hash: String::new(),
        };

        let mutated = fuzzer.mutate_input(&input);
        assert_eq!(mutated.generation, 1);
    }

    #[test]
    fn test_coverage_tracker() {
        let mut tracker = CoverageTracker::new(1024);

        let bitmap1 = vec![0, 1, 0, 1, 0, 0, 0, 0];
        let bitmap2 = vec![1, 0, 1, 0, 0, 0, 0, 0];

        assert!(tracker.update(&bitmap1));
        assert!(tracker.update(&bitmap2));
        assert!(tracker.coverage_percentage() > 0.0);
    }
}
