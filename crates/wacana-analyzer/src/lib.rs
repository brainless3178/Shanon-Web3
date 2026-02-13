//! # WACANA — Concolic Analysis for WASM/SBF Smart Contracts
//!
//! A specialized concolic analyzer designed to detect on-chain data
//! vulnerabilities in WASM and SBF smart contracts on Solana.
//!
//! ## Why WACANA?
//!
//! Many Solana smart contracts are compiled via WASM for compatibility
//! (e.g. Neon EVM, WASM-on-Solana runtimes). WACANA provides deep
//! concolic analysis that combines **concrete execution traces** with
//! **symbolic constraint solving** to detect data vulnerabilities that
//! are invisible to purely static tools.
//!
//! ## Concolic Execution Model
//!
//! 1. **Parse**: Decode WASM bytecode or SBF ELF binary into an
//!    intermediate instruction representation.
//! 2. **Concrete Seed**: Execute the program with concrete inputs to
//!    establish a baseline execution trace.
//! 3. **Symbolic Shadow**: Maintain symbolic variables in parallel with
//!    concrete values; collect path constraints at each branch.
//! 4. **Negate & Solve**: Systematically negate path constraints and use
//!    Z3 SMT solver to find new inputs exploring uncovered branches.
//! 5. **Vulnerability Detection**: At each explored path, apply
//!    WASM/SBF-specific vulnerability detectors (memory safety, type
//!    confusion, indirect call validation, linear memory overflow,
//!    uninitialized data, cross-contract re-entrancy patterns).
//! 6. **Report**: Aggregate findings with concrete triggering inputs.
//!
//! ## Integration Flow
//!
//! Designed to run **post-fuzzing** or **post-symbolic-execution** to
//! catch runtime anomalies that static analysis and fuzzing alone miss.
//! Integrates into the orchestrator audit pipeline alongside Kani and Certora.

pub mod concolic_engine;
pub mod constraint_collector;
pub mod report;
pub mod sbf_decoder;
pub mod vulnerability_detectors;
pub mod wasm_parser;

use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

pub use concolic_engine::{ConcolicConfig, ConcolicEngine, ConcolicState, ExecutionTrace};
pub use constraint_collector::{ConstraintCollector, PathConstraint, SymbolicVar};
pub use report::{WacanaFinding, WacanaReport, WacanaSeverity};
pub use sbf_decoder::{SbfDecodeResult, SbfInstruction, SbfModule};
pub use vulnerability_detectors::{
    VulnerabilityCategory, VulnerabilityDetector, WasmVulnerability, WasmVulnerabilitySeverity,
};
pub use wasm_parser::{WasmFunction, WasmInstruction, WasmMemoryConfig, WasmModule};

// ─── Main Analyzer ───────────────────────────────────────────────────────────

/// WACANA: top-level concolic analyzer for WASM/SBF programs.
///
/// Orchestrates WASM parsing → concolic execution → vulnerability detection
/// → report generation.
pub struct WacanaAnalyzer {
    config: WacanaConfig,
    engine: ConcolicEngine,
    detectors: Vec<Box<dyn VulnerabilityDetector>>,
}

/// Configuration for the WACANA analyzer.
#[derive(Debug, Clone)]
pub struct WacanaConfig {
    /// Maximum number of concolic paths to explore per function.
    pub max_paths_per_function: usize,
    /// Maximum depth of concolic exploration (branch count).
    pub max_depth: usize,
    /// Z3 solver timeout per query, in milliseconds.
    pub solver_timeout_ms: u64,
    /// Whether to analyze WASM bytecode (in addition to SBF).
    pub analyze_wasm: bool,
    /// Whether to analyze SBF bytecode.
    pub analyze_sbf: bool,
    /// Whether to run memory safety detectors.
    pub detect_memory_safety: bool,
    /// Whether to run type confusion detectors.
    pub detect_type_confusion: bool,
    /// Whether to run indirect call validation.
    pub detect_indirect_call_issues: bool,
    /// Whether to run linear memory overflow detection.
    pub detect_linear_memory_overflow: bool,
    /// Whether to run uninitialized data detectors.
    pub detect_uninitialized_data: bool,
    /// Whether to run cross-contract reentrancy pattern detection.
    pub detect_reentrancy_patterns: bool,
    /// Whether to run integer overflow/underflow patterns.
    pub detect_integer_issues: bool,
    /// Whether to include source-level hints (requires source code).
    pub source_assisted: bool,
    /// Random seed for concrete input generation.
    pub seed: u64,
}

impl Default for WacanaConfig {
    fn default() -> Self {
        Self {
            max_paths_per_function: 256,
            max_depth: 64,
            solver_timeout_ms: 5000,
            analyze_wasm: true,
            analyze_sbf: true,
            detect_memory_safety: true,
            detect_type_confusion: true,
            detect_indirect_call_issues: true,
            detect_linear_memory_overflow: true,
            detect_uninitialized_data: true,
            detect_reentrancy_patterns: true,
            detect_integer_issues: true,
            source_assisted: true,
            seed: 0xDEAD_BEEF,
        }
    }
}

impl WacanaAnalyzer {
    /// Create a new WACANA analyzer with the given configuration.
    pub fn new(config: WacanaConfig) -> Self {
        let concolic_config = ConcolicConfig {
            max_paths: config.max_paths_per_function,
            max_depth: config.max_depth,
            solver_timeout_ms: config.solver_timeout_ms,
            seed: config.seed,
        };

        let mut detectors: Vec<Box<dyn VulnerabilityDetector>> = Vec::new();

        if config.detect_memory_safety {
            detectors.push(Box::new(
                vulnerability_detectors::MemorySafetyDetector::new(),
            ));
        }
        if config.detect_type_confusion {
            detectors.push(Box::new(
                vulnerability_detectors::TypeConfusionDetector::new(),
            ));
        }
        if config.detect_indirect_call_issues {
            detectors.push(Box::new(
                vulnerability_detectors::IndirectCallDetector::new(),
            ));
        }
        if config.detect_linear_memory_overflow {
            detectors.push(Box::new(
                vulnerability_detectors::LinearMemoryOverflowDetector::new(),
            ));
        }
        if config.detect_uninitialized_data {
            detectors.push(Box::new(
                vulnerability_detectors::UninitializedDataDetector::new(),
            ));
        }
        if config.detect_reentrancy_patterns {
            detectors.push(Box::new(
                vulnerability_detectors::ReentrancyPatternDetector::new(),
            ));
        }
        if config.detect_integer_issues {
            detectors.push(Box::new(
                vulnerability_detectors::IntegerIssueDetector::new(),
            ));
        }

        Self {
            engine: ConcolicEngine::new(concolic_config),
            config,
            detectors,
        }
    }

    /// Analyze a Solana program directory for WASM/SBF data vulnerabilities.
    ///
    /// Scans for `.wasm` and `.so` binaries, then runs concolic analysis on each.
    /// Also performs source-assisted analysis on `.rs` files if enabled.
    pub fn analyze_program(&mut self, program_path: &Path) -> Result<WacanaReport, WacanaError> {
        info!("WACANA: Starting concolic analysis for {:?}", program_path);
        let start = std::time::Instant::now();

        let mut all_findings: Vec<WacanaFinding> = Vec::new();
        let mut wasm_modules_analyzed = 0u32;
        let mut sbf_binaries_analyzed = 0u32;
        let mut total_paths_explored = 0usize;
        let mut total_branches_covered = 0usize;
        let mut source_files_analyzed = 0u32;

        // Phase 1: Discover WASM files
        if self.config.analyze_wasm {
            let wasm_files = self.discover_wasm_files(program_path);
            for wasm_path in &wasm_files {
                info!("WACANA: Analyzing WASM module: {:?}", wasm_path);
                match self.analyze_wasm_binary(wasm_path) {
                    Ok(result) => {
                        wasm_modules_analyzed += 1;
                        total_paths_explored += result.paths_explored;
                        total_branches_covered += result.branches_covered;
                        all_findings.extend(result.findings);
                    }
                    Err(e) => {
                        warn!("WACANA: Failed to analyze WASM {:?}: {}", wasm_path, e);
                    }
                }
            }
        }

        // Phase 2: Discover SBF binaries
        if self.config.analyze_sbf {
            let sbf_files = self.discover_sbf_files(program_path);
            for sbf_path in &sbf_files {
                info!("WACANA: Analyzing SBF binary: {:?}", sbf_path);
                match self.analyze_sbf_binary(sbf_path) {
                    Ok(result) => {
                        sbf_binaries_analyzed += 1;
                        total_paths_explored += result.paths_explored;
                        total_branches_covered += result.branches_covered;
                        all_findings.extend(result.findings);
                    }
                    Err(e) => {
                        warn!("WACANA: Failed to analyze SBF {:?}: {}", sbf_path, e);
                    }
                }
            }
        }

        // Phase 3: Source-assisted concolic analysis
        if self.config.source_assisted {
            let rs_files = self.discover_source_files(program_path);
            for rs_path in &rs_files {
                match self.analyze_source_assisted(rs_path) {
                    Ok(findings) => {
                        source_files_analyzed += 1;
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        debug!(
                            "WACANA: Source-assisted analysis skipped for {:?}: {}",
                            rs_path, e
                        );
                    }
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Deduplicate findings by fingerprint
        all_findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        all_findings.dedup_by(|a, b| a.fingerprint == b.fingerprint);

        // Build report
        let critical = all_findings
            .iter()
            .filter(|f| f.severity == WacanaSeverity::Critical)
            .count();
        let high = all_findings
            .iter()
            .filter(|f| f.severity == WacanaSeverity::High)
            .count();
        let medium = all_findings
            .iter()
            .filter(|f| f.severity == WacanaSeverity::Medium)
            .count();
        let low = all_findings
            .iter()
            .filter(|f| f.severity == WacanaSeverity::Low)
            .count();

        let report = WacanaReport {
            program_path: program_path.to_path_buf(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            wasm_modules_analyzed,
            sbf_binaries_analyzed,
            source_files_analyzed,
            total_paths_explored,
            total_branches_covered,
            findings: all_findings,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            analysis_duration_ms: elapsed_ms,
            concolic_engine_version: "WACANA 0.1.0".to_string(),
            solver_backend: "Z3 SMT".to_string(),
        };

        info!(
            "WACANA: Analysis complete in {}ms — {} findings ({} critical, {} high, {} medium, {} low)",
            elapsed_ms,
            report.findings.len(),
            critical, high, medium, low,
        );

        Ok(report)
    }

    /// Analyze a raw WASM binary file.
    fn analyze_wasm_binary(&mut self, wasm_path: &Path) -> Result<AnalysisResult, WacanaError> {
        let wasm_bytes = std::fs::read(wasm_path)
            .map_err(|e| WacanaError::IoError(format!("Cannot read {:?}: {}", wasm_path, e)))?;

        // Parse the WASM module
        let wasm_module = wasm_parser::parse_wasm_module(&wasm_bytes)?;
        info!(
            "WACANA: Parsed WASM module — {} functions, {} memory pages, {} globals",
            wasm_module.functions.len(),
            wasm_module.memory.initial_pages,
            wasm_module.globals.len(),
        );

        let mut findings = Vec::new();
        let mut paths_explored = 0usize;
        let mut branches_covered = 0usize;

        // Run concolic engine on each function
        for func in &wasm_module.functions {
            if func.instructions.is_empty() {
                continue;
            }

            let trace = self.engine.explore_wasm_function(func, &wasm_module)?;
            paths_explored += trace.paths_explored;
            branches_covered += trace.branches_covered;

            // Run vulnerability detectors on each explored state
            for state in &trace.explored_states {
                for detector in &self.detectors {
                    let mut detected = detector.check_wasm_state(state, func, &wasm_module);
                    for finding in &mut detected {
                        finding.fingerprint = Self::compute_fingerprint(
                            &finding.category,
                            &finding.location,
                            &finding.description,
                        );
                    }
                    findings.extend(detected);
                }
            }
        }

        Ok(AnalysisResult {
            findings,
            paths_explored,
            branches_covered,
        })
    }

    /// Analyze an SBF (Solana Binary Format) ELF binary.
    fn analyze_sbf_binary(&mut self, sbf_path: &Path) -> Result<AnalysisResult, WacanaError> {
        let binary_bytes = std::fs::read(sbf_path)
            .map_err(|e| WacanaError::IoError(format!("Cannot read {:?}: {}", sbf_path, e)))?;

        let sbf_module = sbf_decoder::decode_sbf_binary(&binary_bytes)?;
        info!(
            "WACANA: Decoded SBF binary — {} entry points, {} sections, {} bytes code",
            sbf_module.entry_points.len(),
            sbf_module.sections.len(),
            sbf_module.code_size,
        );

        let mut findings = Vec::new();
        let mut paths_explored = 0usize;
        let mut branches_covered = 0usize;

        // Run concolic engine on SBF entry points
        for entry in &sbf_module.entry_points {
            let trace = self.engine.explore_sbf_entry(entry, &sbf_module)?;
            paths_explored += trace.paths_explored;
            branches_covered += trace.branches_covered;

            for state in &trace.explored_states {
                for detector in &self.detectors {
                    let mut detected = detector.check_sbf_state(state, entry, &sbf_module);
                    for finding in &mut detected {
                        finding.fingerprint = Self::compute_fingerprint(
                            &finding.category,
                            &finding.location,
                            &finding.description,
                        );
                    }
                    findings.extend(detected);
                }
            }
        }

        Ok(AnalysisResult {
            findings,
            paths_explored,
            branches_covered,
        })
    }

    /// Source-assisted analysis: parse Rust source and extract WASM/SBF-relevant
    /// vulnerability patterns that guide the concolic engine.
    fn analyze_source_assisted(
        &mut self,
        source_path: &Path,
    ) -> Result<Vec<WacanaFinding>, WacanaError> {
        let source = std::fs::read_to_string(source_path)
            .map_err(|e| WacanaError::IoError(format!("Cannot read {:?}: {}", source_path, e)))?;

        let filename = source_path.to_string_lossy().to_string();
        let mut findings = Vec::new();

        // Parse the Rust AST
        let file = syn::parse_file(&source).map_err(|e| {
            WacanaError::ParseError(format!("Syn parse error in {}: {}", filename, e))
        })?;

        // Scan for WASM-relevant patterns in source
        let patterns = vulnerability_detectors::scan_source_for_wasm_patterns(&file, &filename);
        for pattern in patterns {
            let mut finding = WacanaFinding {
                category: pattern.category,
                severity: pattern.severity,
                location: pattern.location,
                description: pattern.description,
                triggering_input: pattern.triggering_input,
                path_constraints: pattern.path_constraints,
                recommendation: pattern.recommendation,
                fingerprint: String::new(),
                cwe: pattern.cwe,
                concolic_proof: pattern.concolic_proof,
            };
            finding.fingerprint = Self::compute_fingerprint(
                &finding.category,
                &finding.location,
                &finding.description,
            );
            findings.push(finding);
        }

        Ok(findings)
    }

    // ── File Discovery ──────────────────────────────────────────────────────

    fn discover_wasm_files(&self, dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "wasm")
                    .unwrap_or(false)
            })
        {
            files.push(entry.path().to_path_buf());
        }
        files
    }

    fn discover_sbf_files(&self, dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        // Look in target/deploy/ and target/sbf-solana-solana/release/
        let deploy_dir = dir.join("target").join("deploy");
        let sbf_dir = dir.join("target").join("sbf-solana-solana").join("release");

        for search_dir in [deploy_dir, sbf_dir, dir.to_path_buf()] {
            if !search_dir.exists() {
                continue;
            }
            for entry in walkdir::WalkDir::new(&search_dir)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|ext| ext == "so").unwrap_or(false))
            {
                files.push(entry.path().to_path_buf());
            }
        }

        files.dedup();
        files
    }

    fn discover_source_files(&self, dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "rs").unwrap_or(false))
            .filter(|e| !e.path().to_string_lossy().contains("target/"))
        {
            files.push(entry.path().to_path_buf());
        }
        files
    }

    /// Compute a deterministic fingerprint for deduplication.
    fn compute_fingerprint(
        category: &VulnerabilityCategory,
        location: &str,
        description: &str,
    ) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}:{}:{}", category, location, description).as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..16])
    }
}

impl Default for WacanaAnalyzer {
    fn default() -> Self {
        Self::new(WacanaConfig::default())
    }
}

/// Internal result from a single binary analysis pass.
struct AnalysisResult {
    findings: Vec<WacanaFinding>,
    paths_explored: usize,
    branches_covered: usize,
}

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum WacanaError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("WASM parse error: {0}")]
    WasmParseError(String),
    #[error("SBF decode error: {0}")]
    SbfDecodeError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Concolic engine error: {0}")]
    EngineError(String),
    #[error("Solver error: {0}")]
    SolverError(String),
    #[error("Detector error: {0}")]
    DetectorError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WacanaConfig::default();
        assert_eq!(config.max_paths_per_function, 256);
        assert_eq!(config.max_depth, 64);
        assert_eq!(config.solver_timeout_ms, 5000);
        assert!(config.analyze_wasm);
        assert!(config.analyze_sbf);
        assert!(config.detect_memory_safety);
        assert!(config.detect_type_confusion);
        assert!(config.detect_indirect_call_issues);
        assert!(config.detect_linear_memory_overflow);
        assert!(config.detect_uninitialized_data);
        assert!(config.detect_reentrancy_patterns);
        assert!(config.detect_integer_issues);
        assert!(config.source_assisted);
        assert_eq!(config.seed, 0xDEAD_BEEF);
    }

    #[test]
    fn test_analyzer_creation_all_detectors() {
        let analyzer = WacanaAnalyzer::new(WacanaConfig::default());
        assert_eq!(analyzer.detectors.len(), 7);
    }

    #[test]
    fn test_analyzer_creation_no_detectors() {
        let config = WacanaConfig {
            detect_memory_safety: false,
            detect_type_confusion: false,
            detect_indirect_call_issues: false,
            detect_linear_memory_overflow: false,
            detect_uninitialized_data: false,
            detect_reentrancy_patterns: false,
            detect_integer_issues: false,
            ..WacanaConfig::default()
        };
        let analyzer = WacanaAnalyzer::new(config);
        assert_eq!(analyzer.detectors.len(), 0);
    }

    #[test]
    fn test_analyzer_default() {
        let analyzer = WacanaAnalyzer::default();
        assert_eq!(analyzer.detectors.len(), 7);
    }

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let fp1 = WacanaAnalyzer::compute_fingerprint(
            &VulnerabilityCategory::MemorySafety,
            "test.rs:42",
            "buffer overflow",
        );
        let fp2 = WacanaAnalyzer::compute_fingerprint(
            &VulnerabilityCategory::MemorySafety,
            "test.rs:42",
            "buffer overflow",
        );
        assert_eq!(fp1, fp2);
        assert!(!fp1.is_empty());
    }

    #[test]
    fn test_compute_fingerprint_different_inputs() {
        let fp1 = WacanaAnalyzer::compute_fingerprint(
            &VulnerabilityCategory::MemorySafety,
            "test.rs:42",
            "buffer overflow",
        );
        let fp2 = WacanaAnalyzer::compute_fingerprint(
            &VulnerabilityCategory::TypeConfusion,
            "test.rs:42",
            "buffer overflow",
        );
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_discover_wasm_files_empty_dir() {
        let analyzer = WacanaAnalyzer::default();
        let files = analyzer.discover_wasm_files(Path::new("/nonexistent"));
        assert!(files.is_empty());
    }

    #[test]
    fn test_discover_sbf_files_empty_dir() {
        let analyzer = WacanaAnalyzer::default();
        let files = analyzer.discover_sbf_files(Path::new("/nonexistent"));
        assert!(files.is_empty());
    }

    #[test]
    fn test_analyze_nonexistent_path() {
        let mut analyzer = WacanaAnalyzer::default();
        let result = analyzer.analyze_program(Path::new("/nonexistent/program"));
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.wasm_modules_analyzed, 0);
        assert_eq!(report.sbf_binaries_analyzed, 0);
        assert!(report.findings.is_empty());
        assert!(report.concolic_engine_version.contains("WACANA"));
    }

    #[test]
    fn test_error_display() {
        let err = WacanaError::IoError("file not found".to_string());
        assert!(err.to_string().contains("file not found"));
        let err = WacanaError::WasmParseError("bad wasm".to_string());
        assert!(err.to_string().contains("bad wasm"));
        let err = WacanaError::SolverError("timeout".to_string());
        assert!(err.to_string().contains("timeout"));
    }
}
