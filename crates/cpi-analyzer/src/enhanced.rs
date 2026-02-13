use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedCPIFinding {
    pub vulnerability_type: EnhancedCPIVulnerability,
    pub severity: CPISeverity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnhancedCPIVulnerability {
    ArbitraryCPI,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CPISeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnhancedCPIReport {
    pub findings: Vec<EnhancedCPIFinding>,
    pub program_id_sources: Vec<String>,
    pub whitelist_checks: Vec<String>,
    pub ownership_checks: Vec<String>,
    pub high_risk_paths: Vec<String>,
}

pub struct EnhancedCPIAnalyzer;

impl Default for EnhancedCPIAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EnhancedCPIAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_source(
        &mut self,
        _source: &str,
        _filename: &str,
    ) -> Result<EnhancedCPIReport, String> {
        Ok(EnhancedCPIReport::default())
    }
}
