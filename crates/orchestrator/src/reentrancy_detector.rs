//! Reentrancy Detector for Solana Programs
//!
//! Analyzes CPI patterns to detect potential reentrancy vulnerabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use syn::ItemFn;

/// A detected reentrancy finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReentrancyFinding {
    pub vulnerability_type: ReentrancyVulnerability,
    pub severity: ReentrancySeverity,
    pub description: String,
    pub recommendation: String,
    pub call_stack: Vec<String>,
    pub location: String,
    pub function_name: String,
    pub cpi_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReentrancyVulnerability {
    CrossProgramReentrancy,
    SameProgramReentrancy,
    CallbackReentrancy,
    FlashLoanReentrancy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReentrancySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Pattern representing a CPI call
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CpiCall {
    target_program: String,
    instruction: String,
    location: String,
    state_before: Vec<String>,
    state_after: Vec<String>,
}

/// Analysis context for tracking state
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AnalysisContext {
    current_function: String,
    state_reads: Vec<String>,
    state_writes: Vec<String>,
    cpi_calls: Vec<CpiCall>,
    writes_after_cpi: Vec<String>,
}

/// Main reentrancy detector
pub struct ReentrancyDetector {
    findings: Vec<ReentrancyFinding>,
    known_safe_programs: HashSet<String>,
}

impl ReentrancyDetector {
    pub fn new() -> Self {
        let mut safe_programs = HashSet::new();
        // Known safe Solana system programs
        safe_programs.insert("11111111111111111111111111111111".to_string()); // System Program
        safe_programs.insert("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()); // Token Program
        safe_programs.insert("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string()); // Token-2022
        safe_programs.insert("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".to_string()); // ATA

        Self {
            findings: Vec::new(),
            known_safe_programs: safe_programs,
        }
    }

    /// Analyze source code for reentrancy vulnerabilities
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<ReentrancyFinding>, String> {
        let file = syn::parse_file(source).map_err(|e| format!("Parse error: {}", e))?;

        let code = quote::quote!(#file).to_string();

        // Pattern 1: State modification after CPI
        self.check_state_after_cpi(&code, filename);

        // Pattern 2: invoke/invoke_signed without reentrancy guard
        self.check_unguarded_cpi(&code, filename);

        // Pattern 3: Callback patterns
        self.check_callback_reentrancy(&code, filename);

        // Pattern 4: Flash loan patterns
        self.check_flash_loan_reentrancy(&code, filename);

        Ok(self.findings.clone())
    }

    /// Check for state modifications after CPI calls
    fn check_state_after_cpi(&mut self, code: &str, filename: &str) {
        let lines: Vec<&str> = code.lines().collect();
        let mut in_cpi_region = false;
        let mut cpi_line = 0;
        let mut function_name = "unknown".to_string();

        for (i, line) in lines.iter().enumerate() {
            // Track function names
            if line.contains("pub fn ") || line.contains("fn ") {
                if let Some(start) = line.find("fn ") {
                    let rest = &line[start + 3..];
                    if let Some(end) = rest.find('(') {
                        function_name = rest[..end].trim().to_string();
                    }
                }
            }

            // Detect CPI calls
            if line.contains("invoke(")
                || line.contains("invoke_signed(")
                || line.contains("invoke_signed_unchecked(")
                || line.contains("CpiContext")
            {
                in_cpi_region = true;
                cpi_line = i;
            }

            // After CPI, check for state modifications
            if in_cpi_region && i > cpi_line {
                let is_state_write = line.contains(".balance")
                    || line.contains(".lamports")
                    || line.contains(".data")
                    || line.contains("borrow_mut")
                    || line.contains("set_")
                    || (line.contains("=") && !line.contains("==") && !line.contains("let"));

                if is_state_write {
                    self.findings.push(ReentrancyFinding {
                        vulnerability_type: ReentrancyVulnerability::CrossProgramReentrancy,
                        severity: ReentrancySeverity::Critical,
                        description: "State modification detected after CPI call. External program could re-enter before state is finalized.".to_string(),
                        recommendation: "Implement Checks-Effects-Interactions pattern: update all state BEFORE making CPI calls.".to_string(),
                        call_stack: vec![
                            format!("CPI at line {}", cpi_line),
                            format!("State write at line {}", i),
                        ],
                        location: filename.to_string(),
                        function_name: function_name.clone(),
                        cpi_target: None,
                    });
                    in_cpi_region = false;
                }

                // Reset after function boundary
                if line.contains("Ok(())") || line.contains("return") {
                    in_cpi_region = false;
                }
            }
        }
    }

    /// Check for CPI without reentrancy guards
    fn check_unguarded_cpi(&mut self, code: &str, filename: &str) {
        // Check if there's CPI but no reentrancy guard
        let has_cpi = code.contains("invoke(") || code.contains("invoke_signed(");
        let has_guard = code.contains("ReentrancyGuard")
            || code.contains("reentrancy")
            || code.contains("entered")
            || code.contains("locked");

        if has_cpi && !has_guard {
            // Check if CPI target is a known safe program
            let is_safe_cpi = self.known_safe_programs.iter().any(|p| code.contains(p))
                || code.contains("system_program")
                || code.contains("token_program");

            if !is_safe_cpi {
                self.findings.push(ReentrancyFinding {
                    vulnerability_type: ReentrancyVulnerability::CrossProgramReentrancy,
                    severity: ReentrancySeverity::High,
                    description: "CPI to external program without reentrancy guard detected."
                        .to_string(),
                    recommendation:
                        "Add a reentrancy guard or ensure CPI target is a trusted program."
                            .to_string(),
                    call_stack: vec!["invoke/invoke_signed detected".to_string()],
                    location: filename.to_string(),
                    function_name: "unknown".to_string(),
                    cpi_target: None,
                });
            }
        }
    }

    /// Check for callback-based reentrancy
    fn check_callback_reentrancy(&mut self, code: &str, filename: &str) {
        // Pattern: program calls external, external calls back
        let has_callback_pattern =
            (code.contains("callback") || code.contains("on_complete")) && code.contains("invoke");

        if has_callback_pattern {
            self.findings.push(ReentrancyFinding {
                vulnerability_type: ReentrancyVulnerability::CallbackReentrancy,
                severity: ReentrancySeverity::High,
                description:
                    "Callback pattern detected with CPI. Callbacks can be exploited for reentrancy."
                        .to_string(),
                recommendation:
                    "Ensure callback handlers validate caller and maintain consistent state."
                        .to_string(),
                call_stack: vec!["callback + invoke pattern".to_string()],
                location: filename.to_string(),
                function_name: "unknown".to_string(),
                cpi_target: None,
            });
        }
    }

    /// Check for flash loan reentrancy patterns
    fn check_flash_loan_reentrancy(&mut self, code: &str, filename: &str) {
        let is_flash_loan = code.contains("flash_loan")
            || code.contains("FlashLoan")
            || (code.contains("borrow") && code.contains("repay"));

        if is_flash_loan {
            // Check if there's proper validation between borrow and repay
            let has_validation = code.contains("require!")
                || code.contains("assert!")
                || code.contains("constraint");

            if !has_validation {
                self.findings.push(ReentrancyFinding {
                    vulnerability_type: ReentrancyVulnerability::FlashLoanReentrancy,
                    severity: ReentrancySeverity::Critical,
                    description: "Flash loan pattern without proper validation. Attacker can manipulate state during loan.".to_string(),
                    recommendation: "Add invariant checks before and after flash loan execution.".to_string(),
                    call_stack: vec!["flash loan pattern detected".to_string()],
                    location: filename.to_string(),
                    function_name: "unknown".to_string(),
                    cpi_target: None,
                });
            } else {
                self.findings.push(ReentrancyFinding {
                    vulnerability_type: ReentrancyVulnerability::FlashLoanReentrancy,
                    severity: ReentrancySeverity::Medium,
                    description: "Flash loan pattern detected. Ensure all invariants are checked."
                        .to_string(),
                    recommendation:
                        "Verify that loan repayment and fee collection cannot be bypassed."
                            .to_string(),
                    call_stack: vec!["flash loan with validation".to_string()],
                    location: filename.to_string(),
                    function_name: "unknown".to_string(),
                    cpi_target: None,
                });
            }
        }
    }

    /// Check a specific function for reentrancy
    pub fn check_function(&mut self, func: &ItemFn, filename: &str) -> Vec<ReentrancyFinding> {
        let code = quote::quote!(#func).to_string();
        let function_name = func.sig.ident.to_string();

        let mut findings = Vec::new();

        // Check for state-after-CPI pattern
        if (code.contains("invoke") || code.contains("CpiContext")) && code.contains("borrow_mut") {
            findings.push(ReentrancyFinding {
                vulnerability_type: ReentrancyVulnerability::CrossProgramReentrancy,
                severity: ReentrancySeverity::High,
                description: format!(
                    "Function {} contains CPI with mutable borrow",
                    function_name
                ),
                recommendation: "Review order of operations for reentrancy safety".to_string(),
                call_stack: vec![function_name.clone()],
                location: filename.to_string(),
                function_name,
                cpi_target: None,
            });
        }

        findings
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[ReentrancyFinding] {
        &self.findings
    }

    /// Clear findings for fresh analysis
    pub fn clear(&mut self) {
        self.findings.clear();
    }
}

impl Default for ReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = ReentrancyDetector::new();
        assert!(detector.findings.is_empty());
    }

    #[test]
    fn test_state_after_cpi_detection() {
        let mut detector = ReentrancyDetector::new();
        // Test the check_state_after_cpi function directly with code with newlines
        let code = r#"pub fn vulnerable(ctx: Context<Transfer>) -> Result<()> {
invoke(&instruction, &[])?;
ctx.accounts.user.balance = 0;
Ok(())
}"#;

        detector.check_state_after_cpi(code, "test.rs");

        // Should detect state write (.balance) after CPI (invoke)
        assert!(
            !detector.findings.is_empty(),
            "Should detect state write after CPI"
        );
    }

    #[test]
    fn test_flash_loan_detection() {
        let mut detector = ReentrancyDetector::new();
        // Test flash loan detection directly
        let code = "pub fn flash_loan ( ctx : Context < FlashLoan > , amount : u64 ) -> Result < ( ) > { let borrowed = borrow ( amount ) ; repay ( borrowed ) ; Ok ( ( ) ) }";

        detector.check_flash_loan_reentrancy(code, "test.rs");

        // Should detect borrow+repay pattern
        assert!(
            !detector.findings.is_empty(),
            "Should detect flash loan pattern"
        );
    }
}
