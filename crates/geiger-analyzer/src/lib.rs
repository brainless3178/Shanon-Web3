//! # Cargo-Geiger Analyzer for Solana Programs
//!
//! Detects and analyzes unsafe Rust code blocks in Solana smart contracts.
//! Unsafe code is common in high-performance Solana programs but introduces
//! significant security risks including:
//!
//! - Memory safety violations
//! - Data race conditions
//! - Undefined behavior
//! - Type safety bypasses
//! - Pointer arithmetic errors
//!
//! This analyzer provides:
//! 1. **Unsafe Block Detection** — Identifies all unsafe {} blocks
//! 2. **Unsafe Function Analysis** — Tracks unsafe fn declarations
//! 3. **Unsafe Trait Implementation** — Detects unsafe impl blocks
//! 4. **FFI Analysis** — Foreign function interface safety
//! 5. **Raw Pointer Usage** — Tracks *const and *mut usage
//! 6. **Inline Assembly** — Detects asm! macros
//! 7. **Transmute Analysis** — Identifies mem::transmute calls
//! 8. **Union Usage** — Detects unsafe union types

pub mod ffi_analyzer;
pub mod metrics;
pub mod pointer_analyzer;
pub mod report;
pub mod transmute_detector;
pub mod unsafe_detector;

use ffi_analyzer::FFIAnalyzer;
use metrics::UnsafeMetrics;
use pointer_analyzer::PointerAnalyzer;
use report::{GeigerAnalysisReport, GeigerSeverity};
use transmute_detector::TransmuteDetector;
use unsafe_detector::UnsafeDetector;

use std::fs;
use std::path::Path;
use tracing::{info, warn};
use walkdir::WalkDir;

/// Cargo-geiger analyzer configuration
#[derive(Debug, Clone)]
pub struct GeigerConfig {
    /// Scan for unsafe blocks
    pub detect_unsafe_blocks: bool,
    /// Scan for unsafe functions
    pub detect_unsafe_functions: bool,
    /// Scan for FFI calls
    pub detect_ffi: bool,
    /// Scan for raw pointers
    pub detect_raw_pointers: bool,
    /// Scan for transmute calls
    pub detect_transmute: bool,
    /// Scan for inline assembly
    pub detect_asm: bool,
    /// Maximum file size to analyze
    pub max_file_size: usize,
}

impl Default for GeigerConfig {
    fn default() -> Self {
        Self {
            detect_unsafe_blocks: true,
            detect_unsafe_functions: true,
            detect_ffi: true,
            detect_raw_pointers: true,
            detect_transmute: true,
            detect_asm: true,
            max_file_size: 1_000_000, // 1MB
        }
    }
}

/// Cargo-geiger analyzer for unsafe Rust code detection
pub struct GeigerAnalyzer {
    config: GeigerConfig,
    unsafe_detector: UnsafeDetector,
    ffi_analyzer: FFIAnalyzer,
    pointer_analyzer: PointerAnalyzer,
    transmute_detector: TransmuteDetector,
}

impl GeigerAnalyzer {
    /// Create a new geiger analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(GeigerConfig::default())
    }

    /// Create a new geiger analyzer with custom configuration
    pub fn with_config(config: GeigerConfig) -> Self {
        info!("Initializing cargo-geiger analyzer for unsafe code detection...");

        Self {
            unsafe_detector: UnsafeDetector::new(),
            ffi_analyzer: FFIAnalyzer::new(),
            pointer_analyzer: PointerAnalyzer::new(),
            transmute_detector: TransmuteDetector::new(),
            config,
        }
    }

    /// Analyze a Solana program for unsafe code
    pub fn analyze_program(&mut self, program_path: &Path) -> Result<GeigerAnalysisReport, String> {
        info!("Cargo-geiger analyzing program at: {:?}", program_path);

        let start_time = std::time::Instant::now();
        let mut findings = Vec::new();
        let mut metrics = UnsafeMetrics::new();

        // Collect Rust source files
        let source_files = self.collect_source_files(program_path)?;
        info!(
            "Geiger scanning {} source files for unsafe code",
            source_files.len()
        );

        if source_files.is_empty() {
            return Err("No Rust source files found".to_string());
        }

        let mut total_lines = 0;

        // Analyze each file
        for (file_path, content) in &source_files {
            total_lines += content.lines().count();

            // Parse AST
            let syntax_tree = match syn::parse_file(content) {
                Ok(tree) => tree,
                Err(e) => {
                    warn!("Failed to parse {}: {}", file_path, e);
                    continue;
                }
            };

            // Phase 1: Detect unsafe blocks
            if self.config.detect_unsafe_blocks {
                let unsafe_findings = self.unsafe_detector.detect_unsafe_blocks(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(unsafe_findings);
            }

            // Phase 2: Analyze FFI calls
            if self.config.detect_ffi {
                let ffi_findings =
                    self.ffi_analyzer
                        .analyze_ffi(file_path, &syntax_tree, content, &mut metrics);
                findings.extend(ffi_findings);
            }

            // Phase 3: Detect raw pointers
            if self.config.detect_raw_pointers {
                let pointer_findings = self.pointer_analyzer.analyze_pointers(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(pointer_findings);
            }

            // Phase 4: Detect transmute calls
            if self.config.detect_transmute {
                let transmute_findings = self.transmute_detector.detect_transmute(
                    file_path,
                    &syntax_tree,
                    content,
                    &mut metrics,
                );
                findings.extend(transmute_findings);
            }
        }

        // Calculate safety score (0-100, higher is safer)
        let safety_score = self.calculate_safety_score(&metrics, total_lines);

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Count severity levels
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, GeigerSeverity::Critical))
            .count();
        let high_count = findings
            .iter()
            .filter(|f| matches!(f.severity, GeigerSeverity::High))
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| matches!(f.severity, GeigerSeverity::Medium))
            .count();
        let low_count = findings
            .iter()
            .filter(|f| matches!(f.severity, GeigerSeverity::Low))
            .count();

        info!(
            "Geiger analysis complete: {} unsafe patterns found ({} critical, {} high) in {}ms. Safety score: {}/100",
            findings.len(), critical_count, high_count, execution_time_ms, safety_score
        );

        Ok(GeigerAnalysisReport {
            program_path: program_path.to_string_lossy().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings,
            metrics,
            files_scanned: source_files.len(),
            lines_scanned: total_lines,
            critical_count,
            high_count,
            medium_count,
            low_count,
            safety_score,
            execution_time_ms,
            engine_version: "cargo-geiger-analyzer-1.0.0".to_string(),
        })
    }

    /// Collect Rust source files from program directory
    fn collect_source_files(&self, program_path: &Path) -> Result<Vec<(String, String)>, String> {
        let mut files = Vec::new();

        let search_paths = vec![
            program_path.join("src"),
            program_path.join("programs"),
            program_path.to_path_buf(),
        ];

        for search_path in search_paths {
            if !search_path.exists() {
                continue;
            }

            for entry in WalkDir::new(&search_path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                if let Some(ext) = path.extension() {
                    if ext != "rs" {
                        continue;
                    }
                }

                let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
                if metadata.len() > self.config.max_file_size as u64 {
                    warn!("Skipping large file: {:?} ({} bytes)", path, metadata.len());
                    continue;
                }

                let content = fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read {:?}: {}", path, e))?;

                files.push((path.to_string_lossy().to_string(), content));
            }
        }

        Ok(files)
    }

    /// Calculate safety score based on unsafe code metrics
    fn calculate_safety_score(&self, metrics: &UnsafeMetrics, total_lines: usize) -> u8 {
        if total_lines == 0 {
            return 100;
        }

        // Base score starts at 100
        let mut score = 100.0;

        // Deduct points for unsafe patterns
        score -= (metrics.unsafe_blocks as f64 / total_lines as f64) * 1000.0;
        score -= (metrics.unsafe_functions as f64 / total_lines as f64) * 800.0;
        score -= (metrics.ffi_calls as f64 / total_lines as f64) * 600.0;
        score -= (metrics.raw_pointers as f64 / total_lines as f64) * 500.0;
        score -= (metrics.transmute_calls as f64 / total_lines as f64) * 700.0;
        score -= (metrics.asm_blocks as f64 / total_lines as f64) * 900.0;
        score -= (metrics.unsafe_traits as f64 / total_lines as f64) * 400.0;

        // Clamp to 0-100
        score.clamp(0.0, 100.0) as u8
    }
}

impl Default for GeigerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geiger_analyzer_creation() {
        let analyzer = GeigerAnalyzer::new();
        assert!(analyzer.config.detect_unsafe_blocks);
    }

    #[test]
    fn test_custom_config() {
        let config = GeigerConfig {
            detect_unsafe_blocks: false,
            ..Default::default()
        };
        let analyzer = GeigerAnalyzer::with_config(config);
        assert!(!analyzer.config.detect_unsafe_blocks);
    }

    #[test]
    fn test_safety_score_calculation() {
        let analyzer = GeigerAnalyzer::new();
        let metrics = UnsafeMetrics {
            unsafe_blocks: 0,
            unsafe_functions: 0,
            ffi_calls: 0,
            raw_pointers: 0,
            transmute_calls: 0,
            asm_blocks: 0,
            unsafe_traits: 0,
            union_types: 0,
        };
        let score = analyzer.calculate_safety_score(&metrics, 1000);
        assert_eq!(score, 100);
    }
}
