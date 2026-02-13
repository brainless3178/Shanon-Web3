pub mod enhanced;

pub use enhanced::{CPISeverity, EnhancedCPIAnalyzer, EnhancedCPIFinding, EnhancedCPIReport};

pub struct CPIAnalyzer;

impl Default for CPIAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CPIAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_source(
        &self,
        _source: &str,
        _filename: &str,
    ) -> Result<Vec<CPIFinding>, String> {
        Ok(Vec::new())
    }
}

pub type CPIFinding = EnhancedCPIFinding;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpi_analyzer_creation() {
        let analyzer = CPIAnalyzer::new();
        let result = analyzer.analyze_source("", "test.rs");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_cpi_analyzer_with_code() {
        let analyzer = CPIAnalyzer::new();
        let code = r#"
            pub fn transfer(ctx: Context<Transfer>) -> Result<()> {
                invoke_signed(&ix, &accs, &[&seeds])?;
                Ok(())
            }
        "#;
        let result = analyzer.analyze_source(code, "program.rs");
        assert!(result.is_ok());
    }

    #[test]
    fn test_enhanced_cpi_analyzer_creation() {
        let mut analyzer = EnhancedCPIAnalyzer::new();
        let report = analyzer.analyze_source("", "test.rs");
        assert!(report.is_ok());
        let report = report.unwrap();
        assert!(report.findings.is_empty());
        assert!(report.program_id_sources.is_empty());
        assert!(report.high_risk_paths.is_empty());
    }

    #[test]
    fn test_enhanced_cpi_report_default() {
        let report = EnhancedCPIReport::default();
        assert!(report.findings.is_empty());
        assert!(report.whitelist_checks.is_empty());
        assert!(report.ownership_checks.is_empty());
    }

    #[test]
    fn test_cpi_severity_equality() {
        assert_eq!(CPISeverity::Critical, CPISeverity::Critical);
        assert_ne!(CPISeverity::Critical, CPISeverity::Low);
    }
}
