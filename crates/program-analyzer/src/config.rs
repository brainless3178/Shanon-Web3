//! Configuration module for the security analyzer
//!
//! Provides user-configurable options for analysis thresholds,
//! enabled checks, and output formats.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Main configuration for the security analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Minimum severity level to report (1-5)
    #[serde(default = "default_min_severity")]
    pub min_severity: u8,

    /// Vulnerability categories to check (empty = all)
    #[serde(default)]
    pub enabled_categories: HashSet<String>,

    /// Vulnerability categories to skip
    #[serde(default)]
    pub disabled_categories: HashSet<String>,

    /// Enable LLM-assisted analysis
    #[serde(default = "default_true")]
    pub enable_llm: bool,

    /// Enable parallel analysis for performance
    #[serde(default = "default_true")]
    pub parallel_analysis: bool,

    /// Maximum findings per file (0 = unlimited)
    #[serde(default)]
    pub max_findings_per_file: usize,

    /// Output format: "json", "markdown", "sarif"
    #[serde(default = "default_output_format")]
    pub output_format: String,

    /// Custom patterns file path
    #[serde(default)]
    pub custom_patterns_file: Option<String>,

    /// Thresholds for specific checks
    #[serde(default)]
    pub thresholds: AnalysisThresholds,
}

/// Configurable thresholds for analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisThresholds {
    /// Maximum code complexity before flagging
    #[serde(default = "default_complexity")]
    pub max_complexity: u32,

    /// Maximum function length (lines) before flagging
    #[serde(default = "default_function_length")]
    pub max_function_length: u32,

    /// Minimum confidence score to report (0.0-1.0)
    #[serde(default = "default_confidence")]
    pub min_confidence: f64,

    /// Oracle staleness threshold (seconds)
    #[serde(default = "default_staleness")]
    pub oracle_staleness_seconds: u64,

    /// Slippage tolerance for DEX operations (basis points)
    #[serde(default = "default_slippage")]
    pub max_slippage_bps: u32,
}

fn default_min_severity() -> u8 {
    1
}
fn default_true() -> bool {
    true
}
fn default_output_format() -> String {
    "markdown".to_string()
}
fn default_complexity() -> u32 {
    20
}
fn default_function_length() -> u32 {
    100
}
fn default_confidence() -> f64 {
    0.5
}
fn default_staleness() -> u64 {
    300
} // 5 minutes
fn default_slippage() -> u32 {
    100
} // 1%

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            min_severity: default_min_severity(),
            enabled_categories: HashSet::new(),
            disabled_categories: HashSet::new(),
            enable_llm: default_true(),
            parallel_analysis: default_true(),
            max_findings_per_file: 0,
            output_format: default_output_format(),
            custom_patterns_file: None,
            thresholds: AnalysisThresholds::default(),
        }
    }
}

impl AnalyzerConfig {
    /// Load configuration from a TOML file
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Save configuration to a TOML file
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::Serialize(e.to_string()))?;
        fs::write(path, content).map_err(|e| ConfigError::Io(e.to_string()))
    }

    /// Check if a category is enabled
    pub fn is_category_enabled(&self, category: &str) -> bool {
        // If disabled list contains it, skip
        if self.disabled_categories.contains(category) {
            return false;
        }
        // If enabled list is empty, all are enabled
        // Otherwise, must be in enabled list
        self.enabled_categories.is_empty() || self.enabled_categories.contains(category)
    }

    /// Check if a finding meets minimum severity
    pub fn meets_severity(&self, severity: u8) -> bool {
        severity >= self.min_severity
    }

    /// Create a config builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Builder pattern for configuration
#[derive(Default)]
pub struct ConfigBuilder {
    config: AnalyzerConfig,
}

impl ConfigBuilder {
    pub fn min_severity(mut self, level: u8) -> Self {
        self.config.min_severity = level.clamp(1, 5);
        self
    }

    pub fn enable_category(mut self, category: impl Into<String>) -> Self {
        self.config.enabled_categories.insert(category.into());
        self
    }

    pub fn disable_category(mut self, category: impl Into<String>) -> Self {
        self.config.disabled_categories.insert(category.into());
        self
    }

    pub fn no_llm(mut self) -> Self {
        self.config.enable_llm = false;
        self
    }

    pub fn sequential(mut self) -> Self {
        self.config.parallel_analysis = false;
        self
    }

    pub fn output_format(mut self, format: impl Into<String>) -> Self {
        self.config.output_format = format.into();
        self
    }

    pub fn build(self) -> AnalyzerConfig {
        self.config
    }
}

/// Configuration errors
#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    Serialize(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
            ConfigError::Serialize(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AnalyzerConfig::default();
        assert_eq!(config.min_severity, 1);
        assert!(config.enable_llm);
        assert!(config.parallel_analysis);
    }

    #[test]
    fn test_category_filtering() {
        let config = AnalyzerConfig::builder()
            .enable_category("authentication")
            .enable_category("arithmetic")
            .build();

        assert!(config.is_category_enabled("authentication"));
        assert!(config.is_category_enabled("arithmetic"));
        assert!(!config.is_category_enabled("oracle"));
    }

    #[test]
    fn test_severity_filtering() {
        let config = AnalyzerConfig::builder().min_severity(3).build();

        assert!(!config.meets_severity(1));
        assert!(!config.meets_severity(2));
        assert!(config.meets_severity(3));
        assert!(config.meets_severity(5));
    }

    #[test]
    fn test_builder_no_llm() {
        let config = AnalyzerConfig::builder().no_llm().build();

        assert!(!config.enable_llm);
    }
}
