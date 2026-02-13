//! # Shared Analysis Traits
//!
//! Common interfaces for all analyzers to reduce code duplication
//! and ensure consistent behavior across the analysis pipeline.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result type for all analysis operations
pub type AnalysisResult<T> = Result<T, AnalysisError>;

/// Unified error type for all analysis modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisError {
    /// Error category
    pub kind: ErrorKind,
    /// Human-readable message
    pub message: String,
    /// Source location if applicable
    pub location: Option<SourceLocation>,
    /// Suggestion for fixing
    pub suggestion: Option<String>,
}

/// Categories of analysis errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorKind {
    /// Failed to parse source code
    ParseError,
    /// Invalid program structure
    InvalidStructure,
    /// IO error (file not found, etc.)
    IoError,
    /// Configuration error
    ConfigError,
    /// Analysis timeout
    Timeout,
    /// Resource limit exceeded
    ResourceExhausted,
    /// Internal error (bug in analyzer)
    InternalError,
}

/// Source code location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.kind, self.message)?;
        if let Some(loc) = &self.location {
            write!(f, " at {}:{}:{}", loc.file, loc.line, loc.column)?;
        }
        if let Some(suggestion) = &self.suggestion {
            write!(f, "\n  Suggestion: {}", suggestion)?;
        }
        Ok(())
    }
}

impl std::error::Error for AnalysisError {}

/// Core trait that all analyzers must implement
pub trait Analyzer: Send + Sync {
    /// Name of this analyzer for logging/reporting
    fn name(&self) -> &str;

    /// Version of this analyzer
    fn version(&self) -> &str;

    /// Analyze source code and return findings
    fn analyze(&self, source: &str) -> AnalysisResult<Vec<Finding>>;

    /// Analyze a file
    fn analyze_file(&self, path: &Path) -> AnalysisResult<Vec<Finding>> {
        let source = std::fs::read_to_string(path).map_err(|e| AnalysisError {
            kind: ErrorKind::IoError,
            message: format!("Failed to read file: {}", e),
            location: None,
            suggestion: Some("Check file path and permissions".to_string()),
        })?;
        self.analyze(&source)
    }

    /// Check if this analyzer is applicable to the given source
    fn is_applicable(&self, source: &str) -> bool;

    /// Get analyzer capabilities
    fn capabilities(&self) -> AnalyzerCapabilities;
}

/// Describes what an analyzer can do (for honest documentation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerCapabilities {
    /// Does it parse into an AST?
    pub uses_ast_parsing: bool,
    /// Does it use symbolic execution?
    pub uses_symbolic_execution: bool,
    /// Does it use SMT solving?
    pub uses_smt_solver: bool,
    /// Does it track data flow?
    pub uses_dataflow_analysis: bool,
    /// Does it track taint?
    pub uses_taint_tracking: bool,
    /// Does it use pattern matching?
    pub uses_pattern_matching: bool,
    /// Does it use machine learning?
    pub uses_ml: bool,
    /// Description of technique
    pub technique_description: String,
}

/// A security finding from any analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding type
    pub id: String,
    /// Severity level (1-5)
    pub severity: Severity,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Location in source
    pub location: SourceLocation,
    /// The vulnerable code snippet
    pub code_snippet: String,
    /// Recommended fix
    pub recommendation: String,
    /// Confidence level (0.0-1.0)
    pub confidence: f64,
    /// Which analyzer found this
    pub found_by: String,
    /// CWE ID if applicable
    pub cwe_id: Option<String>,
    /// References/links
    pub references: Vec<String>,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Severity::Info,
            2 => Severity::Low,
            3 => Severity::Medium,
            4 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "blue",
            Severity::Low => "green",
            Severity::Medium => "yellow",
            Severity::High => "orange",
            Severity::Critical => "red",
        }
    }
}

/// Pipeline for running multiple analyzers
pub struct AnalysisPipeline {
    analyzers: Vec<Box<dyn Analyzer>>,
    config: PipelineConfig,
}

/// Pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Timeout per analyzer in seconds
    pub timeout_seconds: u64,
    /// Maximum total findings
    pub max_findings: usize,
    /// Minimum severity to report
    pub min_severity: Severity,
    /// Run analyzers in parallel
    pub parallel: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 60,
            max_findings: 1000,
            min_severity: Severity::Low,
            parallel: true,
        }
    }
}

impl AnalysisPipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            analyzers: Vec::new(),
            config,
        }
    }

    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
    }

    pub fn run(&self, source: &str) -> AnalysisResult<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for analyzer in &self.analyzers {
            if !analyzer.is_applicable(source) {
                continue;
            }

            match analyzer.analyze(source) {
                Ok(findings) => {
                    for finding in findings {
                        if finding.severity >= self.config.min_severity {
                            all_findings.push(finding);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Analyzer {} failed: {}", analyzer.name(), e);
                }
            }

            if all_findings.len() >= self.config.max_findings {
                break;
            }
        }

        // Sort by severity (highest first)
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        Ok(all_findings)
    }

    /// Get capabilities of all registered analyzers
    pub fn capabilities(&self) -> Vec<(&str, AnalyzerCapabilities)> {
        self.analyzers
            .iter()
            .map(|a| (a.name(), a.capabilities()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_error_display() {
        let err = AnalysisError {
            kind: ErrorKind::ParseError,
            message: "Unexpected token".to_string(),
            location: Some(SourceLocation {
                file: "test.rs".to_string(),
                line: 10,
                column: 5,
            }),
            suggestion: Some("Check syntax".to_string()),
        };

        let display = format!("{}", err);
        assert!(display.contains("ParseError"));
        assert!(display.contains("test.rs:10:5"));
        assert!(display.contains("Check syntax"));
    }

    #[test]
    fn test_pipeline_config_default() {
        let config = PipelineConfig::default();
        assert_eq!(config.timeout_seconds, 60);
        assert_eq!(config.max_findings, 1000);
    }
}
