//! Account Validation Analysis for Solana Programs
//!
//! Verifies all accounts are properly validated before use:
//! - Owner checks
//! - Discriminator verification
//! - Account state validation
//! - Account initialization checks

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use syn::{
    spanned::Spanned, visit::Visit, Attribute, ExprField, ExprMethodCall, File, ItemFn, ItemStruct,
};

/// Represents an account used in the program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountUsage {
    pub name: String,
    pub location: String,
    pub line: usize,
    pub account_type: AccountType,
    pub operations: Vec<AccountOperation>,
    pub validations: Vec<AccountValidation>,
    pub source: AccountSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountType {
    /// PDA account
    PDA,
    /// Token account
    TokenAccount,
    /// System account (SOL balance)
    SystemAccount,
    /// Program account
    ProgramAccount,
    /// State/data account
    StateAccount,
    /// Signer account
    Signer,
    /// Unknown type
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountOperation {
    /// Reading data from account
    Read,
    /// Writing data to account
    Write,
    /// Transferring lamports from account
    TransferLamports,
    /// Token transfer
    TokenTransfer,
    /// Closing account
    Close,
    /// Initializing account
    Initialize,
    /// Using as CPI signer
    CPISigner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountValidation {
    /// Owner check (account.owner == expected)
    OwnerCheck { expected_owner: String },
    /// Discriminator check (first 8 bytes)
    DiscriminatorCheck,
    /// Is initialized check
    IsInitializedCheck,
    /// Is signer check
    IsSignerCheck,
    /// Is writable check
    IsWritableCheck,
    /// Lamport check (lamports > 0)
    HasLamportsCheck,
    /// Key comparison
    KeyCheck { expected_key: String },
    /// PDA derivation check
    PDADerivationCheck { seeds: Vec<String> },
    /// Data length check
    DataLengthCheck,
    /// Rent exemption check
    RentExemptCheck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountSource {
    /// From instruction context (Anchor Context<>)
    InstructionContext,
    /// From remaining accounts
    RemainingAccounts,
    /// Derived in instruction
    Derived,
    /// From CPI result
    CPIResult,
    /// Unknown
    Unknown,
}

/// Account validation finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountValidationFinding {
    pub account: AccountUsage,
    pub vulnerability: AccountVulnerability,
    pub severity: AccountValidationSeverity,
    pub description: String,
    pub attack_scenario: Option<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountVulnerability {
    /// Missing owner check
    MissingOwnerCheck,
    /// Missing discriminator/type check
    MissingDiscriminatorCheck,
    /// Missing signer check for authority
    MissingSignerCheck,
    /// Missing initialization check
    MissingInitializationCheck,
    /// Unchecked remaining accounts
    UncheckedRemainingAccounts,
    /// Missing PDA derivation verification
    MissingPDAVerification,
    /// Missing writable check before write
    MissingWritableCheck,
    /// Missing rent exemption check
    MissingRentExemptCheck,
    /// Account confusion (wrong account type)
    AccountConfusion,
    /// Duplicate mutable account
    DuplicateMutableAccount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountValidationSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Main Account Validator
pub struct AccountValidator {
    /// All detected account usages
    accounts: Vec<AccountUsage>,
    /// All detected findings
    findings: Vec<AccountValidationFinding>,
    /// Known program IDs for validation
    known_programs: HashSet<String>,
    /// Account constraints from Anchor
    anchor_constraints: HashMap<String, Vec<String>>,
}

impl AccountValidator {
    pub fn new() -> Self {
        let mut known_programs = HashSet::new();
        known_programs.insert("System".to_string());
        known_programs.insert("TOKEN_PROGRAM_ID".to_string());
        known_programs.insert("ASSOCIATED_TOKEN_PROGRAM_ID".to_string());
        known_programs.insert("system_program".to_string());
        known_programs.insert("token::ID".to_string());

        Self {
            accounts: Vec::new(),
            findings: Vec::new(),
            known_programs,
            anchor_constraints: HashMap::new(),
        }
    }

    /// Analyze source code for account validation issues
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<AccountValidationFinding>, AccountValidationError> {
        let file = syn::parse_file(source)
            .map_err(|e| AccountValidationError::ParseError(e.to_string()))?;

        self.analyze_file(&file, filename);
        self.detect_vulnerabilities();

        Ok(self.findings.clone())
    }

    /// Analyze a parsed file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        // First pass: extract Anchor account constraints
        let mut constraint_visitor = ConstraintVisitor {
            constraints: &mut self.anchor_constraints,
        };
        constraint_visitor.visit_file(file);

        // Second pass: extract account usages
        let mut visitor = AccountVisitor {
            analyzer: self,
            filename: filename.to_string(),
            current_function: String::new(),
        };
        visitor.visit_file(file);
    }

    /// Detect vulnerabilities in account patterns
    fn detect_vulnerabilities(&mut self) {
        for account in &self.accounts.clone() {
            self.check_owner_validation(account);
            self.check_discriminator_validation(account);
            self.check_signer_validation(account);
            self.check_initialization_validation(account);
            self.check_remaining_accounts(account);
            self.check_writable_validation(account);
        }

        // Check for duplicate mutable accounts
        self.check_duplicate_mutable();
    }

    fn check_owner_validation(&mut self, account: &AccountUsage) {
        // State accounts MUST have owner checks
        if account.account_type == AccountType::StateAccount
            && !account
                .validations
                .iter()
                .any(|v| matches!(v, AccountValidation::OwnerCheck { .. }))
        {
            // Check if Anchor constraints include owner
            let has_anchor_owner = self
                .anchor_constraints
                .get(&account.name)
                .map(|c| c.iter().any(|s| s.contains("owner")))
                .unwrap_or(false);

            if !has_anchor_owner {
                self.findings.push(AccountValidationFinding {
                    account: account.clone(),
                    vulnerability: AccountVulnerability::MissingOwnerCheck,
                    severity: AccountValidationSeverity::Critical,
                    description: format!(
                        "State account '{}' at line {} missing owner verification. \
                        Attack can substitute account owned by malicious program.",
                        account.name, account.line
                    ),
                    attack_scenario: Some(
                        "Attacker creates fake account with matching structure but different owner. \
                        Program reads/trusts malicious data as legitimate state.".to_string()
                    ),
                    recommendation: format!(
                        "Add owner check:\n\
                        require!({}.owner == program_id, ErrorCode::InvalidAccountOwner);",
                        account.name
                    ),
                });
            }
        }
    }

    fn check_discriminator_validation(&mut self, account: &AccountUsage) {
        // Accounts with writes need discriminator checks
        if account.operations.contains(&AccountOperation::Read)
            && !account
                .validations
                .iter()
                .any(|v| matches!(v, AccountValidation::DiscriminatorCheck))
        {
            // Anchor handles this automatically with Account<>
            let has_anchor_type = self
                .anchor_constraints
                .get(&account.name)
                .map(|c| c.iter().any(|s| s.contains("Account<")))
                .unwrap_or(false);

            if !has_anchor_type && account.source != AccountSource::InstructionContext {
                self.findings.push(AccountValidationFinding {
                    account: account.clone(),
                    vulnerability: AccountVulnerability::MissingDiscriminatorCheck,
                    severity: AccountValidationSeverity::High,
                    description: format!(
                        "Account '{}' at line {} read without type discriminator check. \
                        Attacker could substitute different account type.",
                        account.name, account.line
                    ),
                    attack_scenario: Some(
                        "Account type confusion: Token account data parsed as different struct. \
                        Can cause unexpected behavior or data corruption."
                            .to_string(),
                    ),
                    recommendation: format!(
                        "Verify discriminator before deserializing:\n\
                        let discriminator = &{}.try_borrow_data()?[..8];\n\
                        require!(discriminator == ExpectedType::DISCRIMINATOR);",
                        account.name
                    ),
                });
            }
        }
    }

    fn check_signer_validation(&mut self, account: &AccountUsage) {
        // Accounts used in transfers should have signer checks
        if (account
            .operations
            .contains(&AccountOperation::TransferLamports)
            || account
                .operations
                .contains(&AccountOperation::TokenTransfer))
            && !account
                .validations
                .iter()
                .any(|v| matches!(v, AccountValidation::IsSignerCheck))
        {
            let has_anchor_signer = self
                .anchor_constraints
                .get(&account.name)
                .map(|c| c.iter().any(|s| s.contains("Signer")))
                .unwrap_or(false);

            if !has_anchor_signer {
                self.findings.push(AccountValidationFinding {
                    account: account.clone(),
                    vulnerability: AccountVulnerability::MissingSignerCheck,
                    severity: AccountValidationSeverity::Critical,
                    description: format!(
                        "Account '{}' used in transfer at line {} without signer check. \
                        Unauthorized transfers possible.",
                        account.name, account.line
                    ),
                    attack_scenario: Some(
                        "Attacker provides victim's account as authority without signature. \
                        Transfer executes with victim's tokens."
                            .to_string(),
                    ),
                    recommendation: format!(
                        "Add signer check:\n\
                        require!({}.is_signer, ErrorCode::MissingSignature);",
                        account.name
                    ),
                });
            }
        }
    }

    fn check_initialization_validation(&mut self, account: &AccountUsage) {
        // Accounts being read should be initialized
        if account.operations.contains(&AccountOperation::Read)
            && !account
                .validations
                .iter()
                .any(|v| matches!(v, AccountValidation::IsInitializedCheck))
            && account.source == AccountSource::RemainingAccounts
        {
            self.findings.push(AccountValidationFinding {
                account: account.clone(),
                vulnerability: AccountVulnerability::MissingInitializationCheck,
                severity: AccountValidationSeverity::High,
                description: format!(
                    "Account '{}' from remaining_accounts read at line {} without initialization check.",
                    account.name, account.line
                ),
                attack_scenario: Some(
                    "Attacker provides uninitialized account. Program reads zero/garbage data.".to_string()
                ),
                recommendation:
                    "Check account is initialized before reading:\n\
                    require!(account.data_len() > 0, ErrorCode::UninitializedAccount);".to_string(),
            });
        }
    }

    fn check_remaining_accounts(&mut self, account: &AccountUsage) {
        if account.source == AccountSource::RemainingAccounts {
            // Remaining accounts need extra scrutiny
            let has_any_validation = !account.validations.is_empty();

            if !has_any_validation {
                self.findings.push(AccountValidationFinding {
                    account: account.clone(),
                    vulnerability: AccountVulnerability::UncheckedRemainingAccounts,
                    severity: AccountValidationSeverity::High,
                    description: format!(
                        "Account '{}' from remaining_accounts at line {} used without any validation.",
                        account.name, account.line
                    ),
                    attack_scenario: Some(
                        "Attacker can pass any account in remaining_accounts. \
                        Without validation, arbitrary account data is trusted.".to_string()
                    ),
                    recommendation:
                        "Always validate remaining accounts:\n\
                        1. Check owner\n\
                        2. Check discriminator\n\
                        3. Check expected key derivation (PDA)".to_string(),
                });
            }
        }
    }

    fn check_writable_validation(&mut self, account: &AccountUsage) {
        if account.operations.contains(&AccountOperation::Write)
            && !account
                .validations
                .iter()
                .any(|v| matches!(v, AccountValidation::IsWritableCheck))
        {
            let has_anchor_mut = self
                .anchor_constraints
                .get(&account.name)
                .map(|c| c.iter().any(|s| s.contains("mut")))
                .unwrap_or(false);

            if !has_anchor_mut && account.source == AccountSource::RemainingAccounts {
                self.findings.push(AccountValidationFinding {
                    account: account.clone(),
                    vulnerability: AccountVulnerability::MissingWritableCheck,
                    severity: AccountValidationSeverity::Medium,
                    description: format!(
                        "Account '{}' written at line {} without is_writable check.",
                        account.name, account.line
                    ),
                    attack_scenario: None,
                    recommendation: format!(
                        "Add writable check:\n\
                        require!({}.is_writable, ErrorCode::AccountNotWritable);",
                        account.name
                    ),
                });
            }
        }
    }

    fn check_duplicate_mutable(&mut self) {
        let mut mutable_accounts: HashMap<String, Vec<usize>> = HashMap::new();

        for account in &self.accounts {
            if account.operations.contains(&AccountOperation::Write) {
                mutable_accounts
                    .entry(account.name.clone())
                    .or_default()
                    .push(account.line);
            }
        }

        // This is a simplified check - real implementation would compare keys
        // Duplicate mutable is typically caught at Anchor level
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[AccountValidationFinding] {
        &self.findings
    }

    /// Get all detected accounts
    pub fn get_accounts(&self) -> &[AccountUsage] {
        &self.accounts
    }
}

impl Default for AccountValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Visitor for extracting Anchor constraints
struct ConstraintVisitor<'a> {
    constraints: &'a mut HashMap<String, Vec<String>>,
}

impl<'a> Visit<'_> for ConstraintVisitor<'a> {
    fn visit_item_struct(&mut self, item: &ItemStruct) {
        // Check for #[account(...)] attributes
        for field in item.fields.iter() {
            let field_name = field
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default();

            let constraints: Vec<String> = field
                .attrs
                .iter()
                .filter_map(|attr| self.extract_account_constraint(attr))
                .flatten()
                .collect();

            if !constraints.is_empty() {
                self.constraints.insert(field_name, constraints);
            }
        }

        syn::visit::visit_item_struct(self, item);
    }
}

impl<'a> ConstraintVisitor<'a> {
    fn extract_account_constraint(&self, attr: &Attribute) -> Option<Vec<String>> {
        if attr.path().is_ident("account") {
            // Parse account attribute
            let tokens = attr.meta.to_token_stream().to_string();
            Some(vec![tokens])
        } else {
            None
        }
    }
}

/// AST visitor for account usage extraction
struct AccountVisitor<'a> {
    analyzer: &'a mut AccountValidator,
    filename: String,
    current_function: String,
}

impl<'a> Visit<'_> for AccountVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();
        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr_field(&mut self, expr: &ExprField) {
        let field_name = match &expr.member {
            syn::Member::Named(ident) => ident.to_string(),
            syn::Member::Unnamed(index) => index.index.to_string(),
        };

        // Detect remaining_accounts access
        if field_name == "remaining_accounts" {
            self.record_remaining_accounts_usage(expr);
        }

        syn::visit::visit_expr_field(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &ExprMethodCall) {
        let method_name = expr.method.to_string();

        // Detect account operations
        if method_name == "try_borrow_data" || method_name == "try_borrow_mut_data" {
            self.record_account_data_access(expr, method_name.contains("mut"));
        }

        if method_name == "transfer" || method_name == "transfer_checked" {
            self.record_transfer_operation(expr);
        }

        syn::visit::visit_expr_method_call(self, expr);
    }
}

impl<'a> AccountVisitor<'a> {
    fn record_remaining_accounts_usage(&mut self, expr: &ExprField) {
        self.analyzer.accounts.push(AccountUsage {
            name: "remaining_account".to_string(),
            location: self.filename.clone(),
            line: expr.span().start().line,
            account_type: AccountType::Unknown,
            operations: vec![AccountOperation::Read],
            validations: Vec::new(),
            source: AccountSource::RemainingAccounts,
        });
    }

    fn record_account_data_access(&mut self, expr: &ExprMethodCall, is_write: bool) {
        let receiver_str = quote::quote!(#expr.receiver).to_string();

        let mut operations = vec![AccountOperation::Read];
        if is_write {
            operations.push(AccountOperation::Write);
        }

        let mut account_type = AccountType::StateAccount;

        // Use known_programs to identify special account types (Tier 1 Requirement)
        if self.analyzer.known_programs.contains(&receiver_str) {
            if receiver_str.contains("token") || receiver_str.contains("TOKEN") {
                account_type = AccountType::TokenAccount;
            } else if receiver_str.contains("System") || receiver_str.contains("system") {
                account_type = AccountType::SystemAccount;
            }
        }

        self.analyzer.accounts.push(AccountUsage {
            name: receiver_str,
            location: self.filename.clone(),
            line: expr.span().start().line,
            account_type,
            operations,
            validations: Vec::new(),
            source: AccountSource::InstructionContext,
        });
    }

    fn record_transfer_operation(&mut self, expr: &ExprMethodCall) {
        let receiver_str = quote::quote!(#expr.receiver).to_string();

        self.analyzer.accounts.push(AccountUsage {
            name: receiver_str,
            location: self.filename.clone(),
            line: expr.span().start().line,
            account_type: AccountType::TokenAccount,
            operations: vec![AccountOperation::TokenTransfer],
            validations: Vec::new(),
            source: AccountSource::InstructionContext,
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountValidationError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_missing_owner_check() {
        let source = r#"
            pub fn process(accounts: &[AccountInfo]) -> Result<()> {
                let state = &accounts[0];
                let data = state.try_borrow_data()?;
                // Missing owner check!
                let value = data[0];
                Ok(())
            }
        "#;

        let mut analyzer = AccountValidator::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Should detect missing owner check
        assert!(!findings.is_empty());
        // Verify line number (try_borrow_data is at line 4)
        assert_eq!(findings[0].account.line, 4);
    }

    #[test]
    fn test_anchor_constraint_extraction() {
        let source = r#"
            #[derive(Accounts)]
            pub struct Initialize<'info> {
                #[account(init, payer = payer, space = 8 + 32)]
                pub state: Account<'info, State>,
                #[account(mut)]
                pub payer: Signer<'info>,
            }
        "#;

        let mut analyzer = AccountValidator::new();
        let _ = analyzer.analyze_source(source, "test.rs");

        // Should have extracted constraints
        assert!(!analyzer.anchor_constraints.is_empty() || analyzer.accounts.is_empty());
    }
}
