//! Privilege Escalation Detection for Solana Programs
//!
//! Identifies patterns that could lead to unauthorized privilege gain:
//! - Authority update paths
//! - Admin function exposure
//! - Upgrade authority vulnerabilities
//! - Emergency function abuse

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use syn::{spanned::Spanned, visit::Visit, Expr, ExprMethodCall, File, ItemFn};

/// Represents a privileged function in the program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedFunction {
    pub name: String,
    pub location: String,
    pub line: usize,
    pub privilege_level: PrivilegeLevel,
    pub protected_by: Vec<ProtectionMechanism>,
    pub can_modify: Vec<ModificationTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    /// System-level (upgrade, emergency)
    System,
    /// Admin-level (configuration)
    Admin,
    /// Operator-level (daily operations)
    Operator,
    /// User-level (normal user actions)
    User,
    /// Unknown/unclassified
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionMechanism {
    /// Single signer check
    SingleSigner { account: String },
    /// Multi-sig requirement
    MultiSig { threshold: u8, total: u8 },
    /// Timelock delay
    Timelock { delay_seconds: u64 },
    /// Governance vote
    Governance,
    /// PDA authority
    PDAAuthority { seeds: Vec<String> },
    /// No protection detected
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModificationTarget {
    /// Can update protocol authority
    Authority,
    /// Can update fee configuration
    Fees,
    /// Can pause/unpause protocol
    PauseState,
    /// Can upgrade program
    ProgramUpgrade,
    /// Can modify token minting
    MintAuthority,
    /// Can freeze accounts
    FreezeAuthority,
    /// Can modify pool parameters
    PoolParameters,
    /// Can modify global configuration
    GlobalConfig,
}

/// Privilege escalation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegeEscalationFinding {
    pub function: PrivilegedFunction,
    pub vulnerability: PrivilegeVulnerability,
    pub severity: PrivilegeEscalationSeverity,
    pub attack_path: Vec<AttackStep>,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeVulnerability {
    /// Single point of failure in authority
    SinglePointOfFailure,
    /// Authority update without timelock
    InstantAuthorityUpdate,
    /// Emergency function without safeguards
    UnsafeEmergencyFunction,
    /// Upgrade authority not protected
    UnprotectedUpgrade,
    /// Authority can be set to zero address
    ZeroAuthorityPossible,
    /// No rotation/revocation mechanism
    IrrevocableAuthority,
    /// Privilege can be transferred without limits
    UnconstrainedTransfer,
    /// Admin function callable by non-admin
    AdminFunctionExposed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeEscalationSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub step_number: usize,
    pub action: String,
    pub precondition: Option<String>,
    pub outcome: String,
}

/// Main Privilege Escalation Analyzer
pub struct PrivilegeAnalyzer {
    /// All detected privileged functions
    functions: Vec<PrivilegedFunction>,
    /// All detected findings
    findings: Vec<PrivilegeEscalationFinding>,
    /// Authority modification paths
    authority_paths: Vec<AuthorityPath>,
    /// Known admin patterns
    admin_patterns: HashSet<String>,
}

#[derive(Debug, Clone)]
struct AuthorityPath {
    from_function: String,
    target: ModificationTarget,
    protections: Vec<ProtectionMechanism>,
}

impl PrivilegeAnalyzer {
    pub fn new() -> Self {
        let mut admin_patterns = HashSet::new();
        admin_patterns.insert("admin".to_string());
        admin_patterns.insert("owner".to_string());
        admin_patterns.insert("upgrade".to_string());
        admin_patterns.insert("emergency".to_string());
        admin_patterns.insert("pause".to_string());
        admin_patterns.insert("set_authority".to_string());
        admin_patterns.insert("set_admin".to_string());
        admin_patterns.insert("update_config".to_string());
        admin_patterns.insert("initialize".to_string());

        Self {
            functions: Vec::new(),
            findings: Vec::new(),
            authority_paths: Vec::new(),
            admin_patterns,
        }
    }

    /// Analyze source code for privilege escalation issues
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<PrivilegeEscalationFinding>, PrivilegeError> {
        let file =
            syn::parse_file(source).map_err(|e| PrivilegeError::ParseError(e.to_string()))?;

        self.analyze_file(&file, filename);
        self.detect_escalation_paths();

        Ok(self.findings.clone())
    }

    /// Analyze a parsed file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        let mut visitor = PrivilegeVisitor {
            analyzer: self,
            filename: filename.to_string(),
            current_function: String::new(),
            current_protections: Vec::new(),
            current_modifications: Vec::new(),
        };
        visitor.visit_file(file);
    }

    /// Detect privilege escalation vulnerabilities
    fn detect_escalation_paths(&mut self) {
        for func in &self.functions.clone() {
            self.check_authority_protections(func);
            self.check_emergency_safeguards(func);
            self.check_upgrade_protection(func);
            self.check_zero_authority(func);
        }

        // Analyze authority chains
        self.analyze_authority_chains();
    }

    fn check_authority_protections(&mut self, func: &PrivilegedFunction) {
        // Check if authority updates have proper protections
        if func.can_modify.contains(&ModificationTarget::Authority) {
            let has_timelock = func
                .protected_by
                .iter()
                .any(|p| matches!(p, ProtectionMechanism::Timelock { .. }));

            let has_multisig = func
                .protected_by
                .iter()
                .any(|p| matches!(p, ProtectionMechanism::MultiSig { .. }));

            if !has_timelock && !has_multisig {
                let attack_path = vec![
                    AttackStep {
                        step_number: 1,
                        action: "Compromise current authority private key".to_string(),
                        precondition: Some("Phishing, malware, or insider".to_string()),
                        outcome: "Attacker has signing capability".to_string(),
                    },
                    AttackStep {
                        step_number: 2,
                        action: format!("Call {} to transfer authority", func.name),
                        precondition: None,
                        outcome: "Authority transferred to attacker".to_string(),
                    },
                    AttackStep {
                        step_number: 3,
                        action: "Drain protocol using new authority".to_string(),
                        precondition: None,
                        outcome: "Total fund loss".to_string(),
                    },
                ];

                self.findings.push(PrivilegeEscalationFinding {
                    function: func.clone(),
                    vulnerability: PrivilegeVulnerability::InstantAuthorityUpdate,
                    severity: PrivilegeEscalationSeverity::High,
                    attack_path,
                    description: format!(
                        "Function '{}' can update authority without timelock or multi-sig. \
                        Compromised key leads to immediate protocol takeover.",
                        func.name
                    ),
                    recommendation: "Implement 48-hour timelock for authority changes. \
                        Add multi-sig requirement (3/5 recommended). \
                        Emit event for monitoring."
                        .to_string(),
                });
            }

            // Check for single point of failure
            let only_single_signer = func.protected_by.len() == 1
                && matches!(
                    func.protected_by.first(),
                    Some(ProtectionMechanism::SingleSigner { .. })
                );

            if only_single_signer {
                self.findings.push(PrivilegeEscalationFinding {
                    function: func.clone(),
                    vulnerability: PrivilegeVulnerability::SinglePointOfFailure,
                    severity: PrivilegeEscalationSeverity::Medium,
                    attack_path: Vec::new(),
                    description: format!(
                        "Function '{}' protected by single signer only. \
                        Single key compromise = total protocol loss.",
                        func.name
                    ),
                    recommendation: "Add multi-sig for critical functions. \
                        Consider hardware wallet + timelock combination."
                        .to_string(),
                });
            }
        }
    }

    fn check_emergency_safeguards(&mut self, func: &PrivilegedFunction) {
        // Check if emergency functions have proper safeguards
        if func.can_modify.contains(&ModificationTarget::PauseState) {
            let has_safeguard = func.protected_by.iter().any(|p| {
                matches!(
                    p,
                    ProtectionMechanism::MultiSig { .. }
                        | ProtectionMechanism::Governance
                        | ProtectionMechanism::Timelock { .. }
                )
            });

            // Pause should be easy to execute (emergency), unpause needs more checks
            let is_unpause = func.name.to_lowercase().contains("unpause")
                || func.name.to_lowercase().contains("resume");

            if is_unpause && !has_safeguard {
                self.findings.push(PrivilegeEscalationFinding {
                    function: func.clone(),
                    vulnerability: PrivilegeVulnerability::UnsafeEmergencyFunction,
                    severity: PrivilegeEscalationSeverity::Medium,
                    attack_path: Vec::new(),
                    description: format!(
                        "Emergency unpause function '{}' lacks additional safeguards. \
                        Attacker who compromises pause could also immediately unpause.",
                        func.name
                    ),
                    recommendation: "Separate pause and unpause authorities. \
                        Add cooldown period or governance vote for unpause."
                        .to_string(),
                });
            }
        }
    }

    fn check_upgrade_protection(&mut self, func: &PrivilegedFunction) {
        if func
            .can_modify
            .contains(&ModificationTarget::ProgramUpgrade)
        {
            let has_strong_protection = func.protected_by.iter().any(|p| {
                matches!(p,
                    ProtectionMechanism::MultiSig { threshold, total }
                        if *threshold >= 3 && *total >= 5
                ) || matches!(p, ProtectionMechanism::Governance)
                    || matches!(p,
                        ProtectionMechanism::Timelock { delay_seconds }
                            if *delay_seconds >= 172800 // 48 hours
                    )
            });

            if !has_strong_protection {
                self.findings.push(PrivilegeEscalationFinding {
                    function: func.clone(),
                    vulnerability: PrivilegeVulnerability::UnprotectedUpgrade,
                    severity: PrivilegeEscalationSeverity::Critical,
                    attack_path: vec![
                        AttackStep {
                            step_number: 1,
                            action: "Compromise upgrade authority".to_string(),
                            precondition: None,
                            outcome: "Access to upgrade capability".to_string(),
                        },
                        AttackStep {
                            step_number: 2,
                            action: "Deploy malicious program upgrade".to_string(),
                            precondition: None,
                            outcome: "Backdoored program deployed".to_string(),
                        },
                        AttackStep {
                            step_number: 3,
                            action: "Execute arbitrary actions with new code".to_string(),
                            precondition: None,
                            outcome: "Complete protocol takeover".to_string(),
                        },
                    ],
                    description: format!(
                        "Program upgrade function '{}' lacks strong protection. \
                        Malicious upgrade = complete protocol takeover.",
                        func.name
                    ),
                    recommendation: "Require 3/5 multi-sig + 48hr timelock for upgrades. \
                        Consider making program immutable if possible. \
                        Implement upgrade monitoring."
                        .to_string(),
                });
            }
        }
    }

    fn check_zero_authority(&mut self, func: &PrivilegedFunction) {
        // Check if authority can be set to zero/null
        if func.can_modify.contains(&ModificationTarget::Authority) {
            // This would need more sophisticated analysis of the function body
            // For now, flag if there's no explicit zero-address check
            self.findings.push(PrivilegeEscalationFinding {
                function: func.clone(),
                vulnerability: PrivilegeVulnerability::ZeroAuthorityPossible,
                severity: PrivilegeEscalationSeverity::Medium,
                attack_path: Vec::new(),
                description: format!(
                    "Function '{}' may allow setting authority to zero address. \
                    Verify explicit check exists.",
                    func.name
                ),
                recommendation: "Add explicit check:\n\
                    require!(new_authority != Pubkey::default(), ErrorCode::ZeroAuthority);"
                    .to_string(),
            });
        }
    }

    fn analyze_authority_chains(&mut self) {
        // Analyze if there are circular or problematic authority dependencies
        for path in &self.authority_paths {
            // Check for unprotected authority modification
            if path.protections.is_empty() || path.protections.contains(&ProtectionMechanism::None)
            {
                self.findings.push(PrivilegeEscalationFinding {
                    function: PrivilegedFunction {
                        name: path.from_function.clone(),
                        location: String::new(),
                        line: 0,
                        privilege_level: PrivilegeLevel::Admin,
                        protected_by: path.protections.clone(),
                        can_modify: vec![path.target.clone()],
                    },
                    vulnerability: PrivilegeVulnerability::UnconstrainedTransfer,
                    severity: PrivilegeEscalationSeverity::High,
                    attack_path: Vec::new(),
                    description: format!(
                        "Authority path from '{}' to {:?} lacks constraints.",
                        path.from_function, path.target
                    ),
                    recommendation:
                        "Add rate limits, timelocks, or multi-sig to authority transfers."
                            .to_string(),
                });
            }
        }
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[PrivilegeEscalationFinding] {
        &self.findings
    }

    /// Get all detected privileged functions
    pub fn get_privileged_functions(&self) -> &[PrivilegedFunction] {
        &self.functions
    }

    /// Check if function name indicates admin function
    pub fn is_admin_function(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.admin_patterns.iter().any(|p| name_lower.contains(p))
    }
}

impl Default for PrivilegeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor for privilege extraction
struct PrivilegeVisitor<'a> {
    analyzer: &'a mut PrivilegeAnalyzer,
    filename: String,
    current_function: String,
    current_protections: Vec<ProtectionMechanism>,
    current_modifications: Vec<ModificationTarget>,
}

impl<'a> Visit<'_> for PrivilegeVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        let func_name = func.sig.ident.to_string();
        self.current_function = func_name.clone();
        self.current_protections.clear();
        self.current_modifications.clear();

        // Determine privilege level from function name
        let privilege_level = if self.analyzer.is_admin_function(&func_name) {
            PrivilegeLevel::Admin
        } else if func_name.contains("upgrade") || func_name.contains("emergency") {
            PrivilegeLevel::System
        } else {
            PrivilegeLevel::User
        };

        // Visit function body
        syn::visit::visit_item_fn(self, func);

        // Record function if it's privileged
        if privilege_level != PrivilegeLevel::User || !self.current_modifications.is_empty() {
            let protected_by = if self.current_protections.is_empty() {
                vec![ProtectionMechanism::None]
            } else {
                self.current_protections.clone()
            };

            self.analyzer.functions.push(PrivilegedFunction {
                name: func_name.clone(),
                location: self.filename.clone(),
                line: func.span().start().line,
                privilege_level,
                protected_by,
                can_modify: self.current_modifications.clone(),
            });
        }
    }

    fn visit_expr_method_call(&mut self, expr: &ExprMethodCall) {
        let method_name = expr.method.to_string();

        // Detect protection mechanisms
        if method_name == "is_signer" {
            let receiver = quote::quote!(#expr.receiver).to_string();
            self.current_protections
                .push(ProtectionMechanism::SingleSigner { account: receiver });
        }

        // Detect modification targets
        if method_name.contains("set_authority") || method_name.contains("update_authority") {
            self.current_modifications
                .push(ModificationTarget::Authority);
        }

        if method_name.contains("pause") {
            self.current_modifications
                .push(ModificationTarget::PauseState);
        }

        if method_name.contains("set_fee") || method_name.contains("update_fee") {
            self.current_modifications.push(ModificationTarget::Fees);
        }

        syn::visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        // Detect require!/assert! with signer checks
        if let Expr::Macro(mac) = expr {
            let macro_name = mac
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();

            if macro_name == "require" {
                let tokens = mac.mac.tokens.to_string();
                if tokens.contains("is_signer") {
                    // Extract account from tokens
                    self.current_protections
                        .push(ProtectionMechanism::SingleSigner {
                            account: "authority".to_string(),
                        });
                }
            }
        }

        syn::visit::visit_expr(self, expr);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_function_detection() {
        let analyzer = PrivilegeAnalyzer::new();

        assert!(analyzer.is_admin_function("set_admin"));
        assert!(analyzer.is_admin_function("set_authority")); // Matches "set_authority" pattern
        assert!(analyzer.is_admin_function("emergency_pause"));
        assert!(!analyzer.is_admin_function("deposit"));
    }

    #[test]
    fn test_detect_unprotected_authority() {
        let source = r#"
            pub fn set_authority(ctx: Context<SetAuth>, new_auth: Pubkey) -> Result<()> {
                // Missing signer check - this function name triggers admin detection
                // and the method call triggers authority modification detection
                ctx.accounts.config.set_authority(new_auth);
                Ok(())
            }
        "#;

        let mut analyzer = PrivilegeAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Function named 'set_authority' is detected as admin function
        // and will trigger findings due to lack of proper protection
        assert!(
            !findings.is_empty(),
            "Should find privilege escalation issues"
        );
    }
}
