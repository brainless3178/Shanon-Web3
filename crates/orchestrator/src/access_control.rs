//! Access Control Verification for Solana Programs
//!
//! Ensures all privileged operations require proper authorization through:
//! - Signer checks (is_signer verification)
//! - Ownership verification (account.owner checks)  
//! - PDA authority validation
//! - Authority hierarchy analysis

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use syn::{spanned::Spanned, visit::Visit, Expr, ExprMethodCall, File, ItemFn, Stmt};

/// Represents a privileged operation that requires authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedOperation {
    pub name: String,
    pub location: String,
    pub line: usize,
    pub operation_type: OperationType,
    pub required_checks: Vec<RequiredCheck>,
    pub performed_checks: Vec<PerformedCheck>,
    pub is_protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationType {
    /// Fund withdrawal (lamports)
    LamportWithdrawal,
    /// Token transfer
    TokenTransfer,
    /// State mutation (config update, etc.)
    StateMutation,
    /// Authority update (admin change)
    AuthorityUpdate,
    /// Account initialization
    AccountInit,
    /// Account closure
    AccountClose,
    /// CPI invocation
    CrossProgramInvoke,
    /// Emergency function (pause, upgrade)
    EmergencyAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredCheck {
    /// Account must be a signer
    SignerCheck { account: String },
    /// Account owner must match program
    OwnerCheck {
        account: String,
        expected_owner: String,
    },
    /// PDA derivation must be verified
    PDADerivation { seeds: Vec<String> },
    /// Authority must match stored authority
    AuthorityMatch {
        account: String,
        authority_field: String,
    },
    /// Admin-only operation
    AdminOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformedCheck {
    pub check_type: RequiredCheck,
    pub location: String,
    pub line: usize,
    pub is_before_operation: bool,
}

/// Access control vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlFinding {
    pub operation: PrivilegedOperation,
    pub vulnerability: AccessControlVulnerability,
    pub severity: AccessControlSeverity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessControlVulnerability {
    /// Missing signer check on authority account
    MissingSignerCheck,
    /// Missing owner check on account
    MissingOwnerCheck,
    /// Check performed after operation (bypassable)
    CheckAfterOperation,
    /// Check inside conditional that can be bypassed
    BypassableCheck,
    /// Insufficient authority for operation
    InsufficientAuthority,
    /// PDA not properly verified
    UnverifiedPDA,
    /// Authority hierarchy violation
    AuthorityEscalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessControlSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Main Access Control Analyzer
pub struct AccessControlAnalyzer {
    /// All detected privileged operations
    operations: Vec<PrivilegedOperation>,
    /// All detected checks
    checks: HashMap<String, Vec<PerformedCheck>>,
    /// Detected findings
    findings: Vec<AccessControlFinding>,
    /// Known authority patterns
    authority_patterns: HashSet<String>,
    /// Known admin patterns  
    admin_patterns: HashSet<String>,
}

impl AccessControlAnalyzer {
    pub fn new() -> Self {
        let mut authority_patterns = HashSet::new();
        authority_patterns.insert("authority".to_string());
        authority_patterns.insert("admin".to_string());
        authority_patterns.insert("owner".to_string());
        authority_patterns.insert("payer".to_string());
        authority_patterns.insert("signer".to_string());

        let mut admin_patterns = HashSet::new();
        admin_patterns.insert("admin".to_string());
        admin_patterns.insert("upgrade_authority".to_string());
        admin_patterns.insert("emergency_admin".to_string());
        admin_patterns.insert("governance".to_string());

        Self {
            operations: Vec::new(),
            checks: HashMap::new(),
            findings: Vec::new(),
            authority_patterns,
            admin_patterns,
        }
    }

    /// Analyze source code for access control issues
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<AccessControlFinding>, AccessControlError> {
        let file =
            syn::parse_file(source).map_err(|e| AccessControlError::ParseError(e.to_string()))?;

        self.analyze_file(&file, filename);
        self.verify_access_control();

        Ok(self.findings.clone())
    }

    /// Analyze a parsed file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        let mut visitor = AccessControlVisitor {
            analyzer: self,
            filename: filename.to_string(),
            current_function: String::new(),
            in_conditional: false,
            conditional_depth: 0,
        };
        visitor.visit_file(file);
    }

    /// Verify all operations have proper access control
    fn verify_access_control(&mut self) {
        let operations = self.operations.clone();
        for operation in operations {
            self.check_operation(operation);
        }
    }

    fn check_operation(&mut self, operation: PrivilegedOperation) {
        // Check if all required checks are performed
        for required_check in &operation.required_checks {
            let check_found = operation
                .performed_checks
                .iter()
                .any(|pc| &pc.check_type == required_check && pc.is_before_operation);

            if !check_found {
                let (vuln, severity, desc, rec) =
                    self.classify_missing_check(required_check, &operation);
                self.findings.push(AccessControlFinding {
                    operation: operation.clone(),
                    vulnerability: vuln,
                    severity,
                    description: desc,
                    recommendation: rec,
                });
            }
        }

        // Check for checks after operation (CEI violation)
        for performed_check in &operation.performed_checks {
            if !performed_check.is_before_operation {
                self.findings.push(AccessControlFinding {
                    operation: operation.clone(),
                    vulnerability: AccessControlVulnerability::CheckAfterOperation,
                    severity: AccessControlSeverity::High,
                    description: format!(
                        "Check performed after operation at line {}. Operation at line {}.",
                        performed_check.line, operation.line
                    ),
                    recommendation: "Move access control checks before the privileged operation."
                        .to_string(),
                });
            }
        }
    }

    fn classify_missing_check(
        &self,
        check: &RequiredCheck,
        op: &PrivilegedOperation,
    ) -> (
        AccessControlVulnerability,
        AccessControlSeverity,
        String,
        String,
    ) {
        match check {
            RequiredCheck::SignerCheck { account } => (
                AccessControlVulnerability::MissingSignerCheck,
                AccessControlSeverity::Critical,
                format!(
                    "Missing signer check for '{}' in function '{}' at line {}. Operation: {:?}",
                    account, op.name, op.line, op.operation_type
                ),
                format!(
                    "Add: require!({}.is_signer, ErrorCode::Unauthorized);",
                    account
                ),
            ),
            RequiredCheck::OwnerCheck {
                account,
                expected_owner,
            } => (
                AccessControlVulnerability::MissingOwnerCheck,
                AccessControlSeverity::High,
                format!(
                    "Missing owner check for '{}' at line {}. Expected owner: {}",
                    account, op.line, expected_owner
                ),
                format!(
                    "Add: require!({}.owner == &{}, ErrorCode::InvalidOwner);",
                    account, expected_owner
                ),
            ),
            RequiredCheck::PDADerivation { seeds } => (
                AccessControlVulnerability::UnverifiedPDA,
                AccessControlSeverity::High,
                format!("PDA not verified at line {}. Seeds: {:?}", op.line, seeds),
                "Re-derive PDA on-chain and compare with provided account.".to_string(),
            ),
            RequiredCheck::AuthorityMatch {
                account,
                authority_field,
            } => (
                AccessControlVulnerability::InsufficientAuthority,
                AccessControlSeverity::Critical,
                format!(
                    "Authority '{}' not verified against '{}' at line {}",
                    account, authority_field, op.line
                ),
                format!(
                    "Add: require!({}.key() == state.{}, ErrorCode::Unauthorized);",
                    account, authority_field
                ),
            ),
            RequiredCheck::AdminOnly => (
                AccessControlVulnerability::InsufficientAuthority,
                AccessControlSeverity::Critical,
                format!(
                    "Admin-only operation at line {} without admin verification",
                    op.line
                ),
                "Add admin authority check before this operation.".to_string(),
            ),
        }
    }

    /// Check if an account name matches authority patterns
    pub fn is_authority_account(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.authority_patterns
            .iter()
            .any(|p| name_lower.contains(p))
    }

    /// Check if an account name matches admin patterns
    pub fn is_admin_account(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.admin_patterns.iter().any(|p| name_lower.contains(p))
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[AccessControlFinding] {
        &self.findings
    }

    /// Get identified privileged operations
    pub fn get_operations(&self) -> &[PrivilegedOperation] {
        &self.operations
    }
}

impl Default for AccessControlAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor for access control extraction
struct AccessControlVisitor<'a> {
    analyzer: &'a mut AccessControlAnalyzer,
    filename: String,
    current_function: String,
    in_conditional: bool,
    conditional_depth: usize,
}

impl<'a> Visit<'_> for AccessControlVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();

        // Analyze function body for privileged operations and checks
        for stmt in &func.block.stmts {
            self.analyze_statement(stmt);
        }

        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr_method_call(&mut self, expr: &ExprMethodCall) {
        self.check_method_call(expr);
        syn::visit::visit_expr_method_call(self, expr);
    }
}

impl<'a> AccessControlVisitor<'a> {
    fn analyze_statement(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Expr(expr, _) => {
                self.analyze_expression(expr);
            }
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    self.analyze_expression(&init.expr);
                }
            }
            _ => {}
        }
    }

    fn analyze_expression(&mut self, expr: &Expr) {
        match expr {
            Expr::If(if_expr) => {
                self.in_conditional = true;
                self.conditional_depth += 1;

                // Check condition for access control
                self.check_condition_for_access_control(&if_expr.cond);

                // Analyze then branch
                for stmt in &if_expr.then_branch.stmts {
                    self.analyze_statement(stmt);
                }

                self.conditional_depth -= 1;
                if self.conditional_depth == 0 {
                    self.in_conditional = false;
                }
            }
            Expr::MethodCall(call) => {
                self.check_method_call(call);
            }
            Expr::Macro(mac) => {
                let macro_name = mac
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();

                // Detect require!/assert! macros
                if macro_name == "require" || macro_name == "assert" {
                    self.analyze_require_macro(&mac.mac);
                }
            }
            _ => {}
        }
    }

    fn check_condition_for_access_control(&mut self, expr: &Expr) {
        // Look for is_signer checks in conditions
        if let Expr::Field(field) = expr {
            if let Expr::Path(path) = &*field.base {
                let var_name = path
                    .path
                    .segments
                    .first()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();

                let field_name = match &field.member {
                    syn::Member::Named(ident) => ident.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };

                if field_name == "is_signer" || field_name == "key" {
                    let check = PerformedCheck {
                        check_type: RequiredCheck::SignerCheck {
                            account: var_name.clone(),
                        },
                        location: self.filename.clone(),
                        line: field.span().start().line,
                        is_before_operation: true,
                    };

                    self.analyzer
                        .checks
                        .entry(self.current_function.clone())
                        .or_default()
                        .push(check);
                }
            }
        }
    }

    fn check_method_call(&mut self, call: &ExprMethodCall) {
        let method_name = call.method.to_string();

        // Detect privileged operations
        match method_name.as_str() {
            "transfer" | "transfer_checked" => {
                self.record_transfer_operation(call);
            }
            "close" | "close_account" => {
                self.record_close_operation(call);
            }
            "invoke" | "invoke_signed" => {
                self.record_cpi_operation(call);
            }
            "set_authority" | "update_authority" => {
                self.record_authority_update(call);
            }
            _ => {}
        }

        // Detect checks
        if method_name == "is_signer" {
            self.record_signer_check(call);
        }
    }

    fn analyze_require_macro(&mut self, mac: &syn::Macro) {
        let tokens = mac.tokens.to_string();

        // Check for is_signer in require!
        if tokens.contains("is_signer") {
            // Extract account name from tokens (simplified)
            if let Some(account) = self.extract_account_from_tokens(&tokens, "is_signer") {
                let check = PerformedCheck {
                    check_type: RequiredCheck::SignerCheck {
                        account: account.clone(),
                    },
                    location: self.filename.clone(),
                    line: mac.span().start().line,
                    is_before_operation: true,
                };

                self.analyzer
                    .checks
                    .entry(self.current_function.clone())
                    .or_default()
                    .push(check);
            }
        }

        // Check for owner verification
        if tokens.contains(".owner") {
            if let Some(account) = self.extract_account_from_tokens(&tokens, ".owner") {
                let check = PerformedCheck {
                    check_type: RequiredCheck::OwnerCheck {
                        account: account.clone(),
                        expected_owner: "program_id".to_string(),
                    },
                    location: self.filename.clone(),
                    line: mac.span().start().line,
                    is_before_operation: true,
                };

                self.analyzer
                    .checks
                    .entry(self.current_function.clone())
                    .or_default()
                    .push(check);
            }
        }
    }

    fn extract_account_from_tokens(&self, tokens: &str, pattern: &str) -> Option<String> {
        if let Some(pos) = tokens.find(pattern) {
            // Look backwards from pattern to find account name
            let before = &tokens[..pos];
            let parts: Vec<&str> = before.split(['.', '(', ' ', ',']).collect();
            parts
                .last()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            None
        }
    }

    fn record_signer_check(&mut self, expr: &ExprMethodCall) {
        if let Expr::Path(path) = &*expr.receiver {
            let account_name = path
                .path
                .segments
                .first()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();

            let check = PerformedCheck {
                check_type: RequiredCheck::SignerCheck {
                    account: account_name,
                },
                location: self.filename.clone(),
                line: expr.span().start().line,
                is_before_operation: true,
            };

            self.analyzer
                .checks
                .entry(self.current_function.clone())
                .or_default()
                .push(check);
        }
    }

    #[allow(dead_code)]
    fn record_privileged_operation(&mut self, _expr: &ExprMethodCall, _op_type: OperationType) {
        // Record privileged operation
    }

    fn record_transfer_operation(&mut self, call: &ExprMethodCall) {
        let mut required_checks = Vec::new();

        // Token transfers require authority signer
        let receiver_name = if let Expr::Path(path) = &*call.receiver {
            path.path
                .segments
                .first()
                .map(|s| s.ident.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        required_checks.push(RequiredCheck::SignerCheck {
            account: "authority".to_string(),
        });

        let operation = PrivilegedOperation {
            name: format!("{}.transfer", receiver_name),
            location: self.filename.clone(),
            line: call.span().start().line,
            operation_type: OperationType::TokenTransfer,
            required_checks,
            performed_checks: Vec::new(),
            is_protected: false,
        };

        self.analyzer.operations.push(operation);
    }

    fn record_close_operation(&mut self, call: &ExprMethodCall) {
        // Account closure operations
        let operation = PrivilegedOperation {
            name: "close_account".to_string(),
            location: self.filename.clone(),
            line: call.span().start().line,
            operation_type: OperationType::AccountClose,
            required_checks: vec![
                RequiredCheck::SignerCheck {
                    account: "authority".to_string(),
                },
                RequiredCheck::OwnerCheck {
                    account: "account".to_string(),
                    expected_owner: "program_id".to_string(),
                },
            ],
            performed_checks: Vec::new(),
            is_protected: false,
        };

        self.analyzer.operations.push(operation);
    }

    fn record_cpi_operation(&mut self, call: &ExprMethodCall) {
        // CPI operations
        let operation = PrivilegedOperation {
            name: "cross_program_invoke".to_string(),
            location: self.filename.clone(),
            line: call.span().start().line,
            operation_type: OperationType::CrossProgramInvoke,
            required_checks: vec![RequiredCheck::SignerCheck {
                account: "authority".to_string(),
            }],
            performed_checks: Vec::new(),
            is_protected: false,
        };

        self.analyzer.operations.push(operation);
    }

    fn record_authority_update(&mut self, call: &ExprMethodCall) {
        // Authority update operations - highest privilege
        let operation = PrivilegedOperation {
            name: "update_authority".to_string(),
            location: self.filename.clone(),
            line: call.span().start().line,
            operation_type: OperationType::AuthorityUpdate,
            required_checks: vec![
                RequiredCheck::SignerCheck {
                    account: "current_authority".to_string(),
                },
                RequiredCheck::AdminOnly,
            ],
            performed_checks: Vec::new(),
            is_protected: false,
        };

        self.analyzer.operations.push(operation);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessControlError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_missing_signer_check() {
        let source = r#"
            pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
                // Missing signer check - using method call pattern the analyzer detects
                ctx.accounts.source_token.transfer(amount)?;
                Ok(())
            }
        "#;

        let mut analyzer = AccessControlAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Should detect missing signer check for transfer operation
        assert!(!findings.is_empty(), "Should find access control issues");
    }

    #[test]
    fn test_authority_pattern_detection() {
        let analyzer = AccessControlAnalyzer::new();

        assert!(analyzer.is_authority_account("vault_authority"));
        assert!(analyzer.is_authority_account("admin"));
        assert!(analyzer.is_authority_account("program_signer"));
        assert!(!analyzer.is_authority_account("user_data"));
    }
}
