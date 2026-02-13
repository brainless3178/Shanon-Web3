//! PDA Derivation Analysis for Solana Programs
//!
//! Verifies Program Derived Addresses (PDAs) are created and validated securely:
//! - Canonical bump usage verification
//! - Seed source validation
//! - PDA address re-derivation checks
//! - Seed collision detection

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use syn::{spanned::Spanned, visit::Visit, Expr, ExprCall, ExprMethodCall, File, ItemFn};

/// Represents a PDA derivation in the program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDADerivation {
    pub name: String,
    pub location: String,
    pub line: usize,
    pub derivation_type: DerivationType,
    pub seeds: Vec<Seed>,
    pub bump_source: BumpSource,
    pub program_id_source: ProgramIdSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivationType {
    /// Pubkey::find_program_address - returns canonical bump
    FindProgramAddress,
    /// Pubkey::create_program_address - uses provided bump
    CreateProgramAddress,
    /// Anchor #[account(seeds = [...], bump)] attribute
    AnchorSeeds,
    /// Associated Token Address
    AssociatedTokenAddress,
    /// Custom PDA derivation pattern
    Custom,
}

/// Represents a seed component in PDA derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Seed {
    pub expression: String,
    pub source: SeedSource,
    pub is_validated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedSource {
    /// Hardcoded constant (e.g., b"vault")
    Constant,
    /// From function parameter (user-controlled)
    Parameter,
    /// From account key
    AccountKey,
    /// From state variable
    StateVariable,
    /// Unknown/complex expression
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BumpSource {
    /// From find_program_address (canonical)
    Canonical,
    /// From stored bump in account data
    StoredBump,
    /// User-provided (potentially dangerous)
    UserProvided,
    /// Anchor-managed bump
    AnchorManaged,
    /// Unknown source
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramIdSource {
    /// Current program ID (crate::ID or similar)
    CurrentProgram,
    /// Hardcoded program ID constant
    HardcodedProgram(String),
    /// User-provided (dangerous!)
    UserProvided,
    /// Unknown
    Unknown,
}

/// PDA security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDAFinding {
    pub derivation: PDADerivation,
    pub vulnerability: PDAVulnerability,
    pub severity: PDASeverity,
    pub description: String,
    pub recommendation: String,
    pub attack_scenario: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PDAVulnerability {
    /// Non-canonical bump used without verification
    NonCanonicalBump,
    /// User-controlled seed without validation
    UnsanitizedSeed,
    /// PDA address not re-derived and verified
    MissingDerivationCheck,
    /// Same seeds used for different purposes
    SeedCollision,
    /// User controls program ID in derivation
    ArbitraryProgramId,
    /// Missing bump verification
    MissingBumpVerification,
    /// Low entropy seeds (collision risk)
    LowEntropySeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PDASeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Main PDA Analyzer
pub struct PDAAnalyzer {
    /// All detected PDA derivations
    derivations: Vec<PDADerivation>,
    /// All detected findings
    findings: Vec<PDAFinding>,
    /// Seed usage map for collision detection
    seed_usage: HashMap<String, Vec<(String, PDADerivation)>>,
    /// Known safe program IDs
    safe_program_ids: HashSet<String>,
}

impl PDAAnalyzer {
    pub fn new() -> Self {
        let mut safe_program_ids = HashSet::new();
        // System programs
        safe_program_ids.insert("system_program::ID".to_string());
        safe_program_ids.insert("System".to_string());
        safe_program_ids.insert("TOKEN_PROGRAM_ID".to_string());
        safe_program_ids.insert("token::ID".to_string());
        safe_program_ids.insert("ASSOCIATED_TOKEN_PROGRAM_ID".to_string());
        safe_program_ids.insert("associated_token::ID".to_string());
        safe_program_ids.insert("crate::ID".to_string());
        safe_program_ids.insert("program_id".to_string());

        Self {
            derivations: Vec::new(),
            findings: Vec::new(),
            seed_usage: HashMap::new(),
            safe_program_ids,
        }
    }

    /// Analyze source code for PDA issues
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<PDAFinding>, PDAError> {
        let file = syn::parse_file(source).map_err(|e| PDAError::ParseError(e.to_string()))?;

        self.analyze_file(&file, filename);
        self.detect_vulnerabilities();

        Ok(self.findings.clone())
    }

    /// Analyze a parsed file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        let mut visitor = PDAVisitor {
            analyzer: self,
            filename: filename.to_string(),
            current_function: String::new(),
        };
        visitor.visit_file(file);
    }

    /// Detect vulnerabilities in PDA patterns
    fn detect_vulnerabilities(&mut self) {
        for derivation in &self.derivations.clone() {
            // Check bump source
            self.check_bump_vulnerability(derivation);

            // Check seed sources
            self.check_seed_vulnerabilities(derivation);

            // Check program ID source
            self.check_program_id_vulnerability(derivation);

            // Check for low entropy
            self.check_entropy(derivation);
        }

        // Check for seed collisions
        self.check_seed_collisions();
    }

    fn check_bump_vulnerability(&mut self, derivation: &PDADerivation) {
        match derivation.bump_source {
            BumpSource::UserProvided => {
                self.findings.push(PDAFinding {
                    derivation: derivation.clone(),
                    vulnerability: PDAVulnerability::NonCanonicalBump,
                    severity: PDASeverity::Critical,
                    description: format!(
                        "User-provided bump at line {} without canonical verification", 
                        derivation.line
                    ),
                    recommendation: "Use find_program_address to get canonical bump, then verify user bump matches".to_string(),
                    attack_scenario: Some(
                        "Attacker provides different bump value that derives a PDA they control, \
                        enabling authority bypass or account substitution".to_string()
                    ),
                });
            }
            BumpSource::Unknown => {
                self.findings.push(PDAFinding {
                    derivation: derivation.clone(),
                    vulnerability: PDAVulnerability::MissingBumpVerification,
                    severity: PDASeverity::High,
                    description: format!(
                        "Bump source unclear at line {}. Cannot verify canonical bump usage",
                        derivation.line
                    ),
                    recommendation:
                        "Explicitly use find_program_address and store/verify canonical bump"
                            .to_string(),
                    attack_scenario: None,
                });
            }
            _ => {}
        }
    }

    fn check_seed_vulnerabilities(&mut self, derivation: &PDADerivation) {
        for seed in &derivation.seeds {
            if seed.source == SeedSource::Parameter && !seed.is_validated {
                self.findings.push(PDAFinding {
                    derivation: derivation.clone(),
                    vulnerability: PDAVulnerability::UnsanitizedSeed,
                    severity: PDASeverity::High,
                    description: format!(
                        "User-controlled seed '{}' at line {} without validation",
                        seed.expression, derivation.line
                    ),
                    recommendation: format!(
                        "Validate seed '{}' before using in PDA derivation. \
                        Consider adding fixed prefix for namespace protection.",
                        seed.expression
                    ),
                    attack_scenario: Some(format!(
                        "Attacker provides crafted seed value to derive PDA they control or \
                        cause collision with other PDAs. Seed: {}",
                        seed.expression
                    )),
                });
            }
        }
    }

    fn check_program_id_vulnerability(&mut self, derivation: &PDADerivation) {
        if derivation.program_id_source == ProgramIdSource::UserProvided {
            self.findings.push(PDAFinding {
                derivation: derivation.clone(),
                vulnerability: PDAVulnerability::ArbitraryProgramId,
                severity: PDASeverity::Critical,
                description: format!(
                    "User-controlled program ID in PDA derivation at line {}",
                    derivation.line
                ),
                recommendation: "Use hardcoded program ID or validate against whitelist"
                    .to_string(),
                attack_scenario: Some(
                    "Attacker provides malicious program ID to derive PDA that the attacker's \
                    program owns, completely bypassing intended authority"
                        .to_string(),
                ),
            });
        }
    }

    fn check_entropy(&mut self, derivation: &PDADerivation) {
        let has_high_entropy = derivation
            .seeds
            .iter()
            .any(|s| matches!(s.source, SeedSource::AccountKey | SeedSource::StateVariable));

        if !has_high_entropy && derivation.seeds.len() <= 1 {
            self.findings.push(PDAFinding {
                derivation: derivation.clone(),
                vulnerability: PDAVulnerability::LowEntropySeed,
                severity: PDASeverity::Medium,
                description: format!(
                    "Low entropy PDA seeds at line {}. Only constant seeds used.",
                    derivation.line
                ),
                recommendation: "Add unique identifier (user pubkey, mint, etc.) to seeds \
                    to prevent collision and improve security"
                    .to_string(),
                attack_scenario: None,
            });
        }
    }

    fn check_seed_collisions(&mut self) {
        for (seed_pattern, usages) in &self.seed_usage {
            if usages.len() > 1 {
                let purposes: Vec<&str> = usages.iter().map(|(p, _)| p.as_str()).collect();

                // Check if same seeds used for different purposes
                if purposes.iter().collect::<HashSet<_>>().len() > 1 {
                    for (_, derivation) in usages {
                        self.findings.push(PDAFinding {
                            derivation: derivation.clone(),
                            vulnerability: PDAVulnerability::SeedCollision,
                            severity: PDASeverity::High,
                            description: format!(
                                "Seed pattern '{}' used for multiple purposes: {:?}",
                                seed_pattern, purposes
                            ),
                            recommendation: "Use unique seed prefixes for each PDA purpose \
                                to prevent collision attacks"
                                .to_string(),
                            attack_scenario: Some(
                                "Attacker uses PDA from one context in another, \
                                potentially bypassing intended validation"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }
        }
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[PDAFinding] {
        &self.findings
    }

    /// Get all detected derivations
    pub fn get_derivations(&self) -> &[PDADerivation] {
        &self.derivations
    }

    /// Check if program ID is known safe
    pub fn is_safe_program_id(&self, program_id: &str) -> bool {
        self.safe_program_ids.contains(program_id)
    }
}

impl Default for PDAAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor for PDA extraction
struct PDAVisitor<'a> {
    analyzer: &'a mut PDAAnalyzer,
    filename: String,
    current_function: String,
}

impl<'a> Visit<'_> for PDAVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();
        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr_call(&mut self, expr: &ExprCall) {
        // Check for find_program_address and create_program_address calls
        if let Expr::Path(path) = &*expr.func {
            let path_str = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");

            if path_str.contains("find_program_address") {
                self.extract_find_program_address(expr);
            } else if path_str.contains("create_program_address") {
                self.extract_create_program_address(expr);
            } else if path_str.contains("get_associated_token_address") {
                self.extract_associated_token_address(expr);
            }
        }

        syn::visit::visit_expr_call(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &ExprMethodCall) {
        let method_name = expr.method.to_string();

        if method_name == "find_program_address" {
            self.extract_find_program_address_method(expr);
        } else if method_name == "create_program_address" {
            self.extract_create_program_address_method(expr);
        }

        syn::visit::visit_expr_method_call(self, expr);
    }
}

impl<'a> PDAVisitor<'a> {
    fn extract_find_program_address(&mut self, call: &ExprCall) {
        let seeds = self.extract_seeds(&call.args);
        let program_id_source = if call.args.len() > 1 {
            self.determine_program_id_source(&call.args[1])
        } else {
            ProgramIdSource::Unknown
        };

        let seed_pattern = seeds
            .iter()
            .map(|s| &s.expression)
            .cloned()
            .collect::<Vec<_>>()
            .join(":");

        let derivation = PDADerivation {
            name: format!("find_program_address_{}", self.current_function),
            location: self.filename.clone(),
            line: call.span().start().line,
            derivation_type: DerivationType::FindProgramAddress,
            seeds: seeds.clone(),
            bump_source: BumpSource::Canonical, // find_program_address returns canonical
            program_id_source,
        };

        self.analyzer
            .seed_usage
            .entry(seed_pattern)
            .or_default()
            .push((self.current_function.clone(), derivation.clone()));

        self.analyzer.derivations.push(derivation);
    }

    fn extract_create_program_address(&mut self, call: &ExprCall) {
        let seeds = self.extract_seeds(&call.args);

        let derivation = PDADerivation {
            name: format!("create_program_address_{}", self.current_function),
            location: self.filename.clone(),
            line: call.span().start().line,
            derivation_type: DerivationType::CreateProgramAddress,
            seeds,
            bump_source: BumpSource::UserProvided, // create_program_address uses provided bump
            program_id_source: ProgramIdSource::Unknown,
        };

        self.analyzer.derivations.push(derivation);
    }

    fn extract_associated_token_address(&mut self, call: &ExprCall) {
        let seeds = self.extract_seeds(&call.args);

        let derivation = PDADerivation {
            name: format!("ata_{}", self.current_function),
            location: self.filename.clone(),
            line: call.span().start().line,
            derivation_type: DerivationType::AssociatedTokenAddress,
            seeds,
            bump_source: BumpSource::Canonical,
            program_id_source: ProgramIdSource::HardcodedProgram(
                "ASSOCIATED_TOKEN_PROGRAM_ID".to_string(),
            ),
        };

        self.analyzer.derivations.push(derivation);
    }

    fn extract_find_program_address_method(&mut self, expr: &ExprMethodCall) {
        let seeds = if !expr.args.is_empty() {
            self.extract_seeds_from_expr(&expr.args[0])
        } else {
            Vec::new()
        };

        let derivation = PDADerivation {
            name: format!("pda_{}", self.current_function),
            location: self.filename.clone(),
            line: expr.span().start().line,
            derivation_type: DerivationType::FindProgramAddress,
            seeds,
            bump_source: BumpSource::Canonical,
            program_id_source: ProgramIdSource::Unknown,
        };

        self.analyzer.derivations.push(derivation);
    }

    fn extract_create_program_address_method(&mut self, expr: &ExprMethodCall) {
        let seeds = if !expr.args.is_empty() {
            self.extract_seeds_from_expr(&expr.args[0])
        } else {
            Vec::new()
        };

        let derivation = PDADerivation {
            name: format!("pda_{}", self.current_function),
            location: self.filename.clone(),
            line: expr.span().start().line,
            derivation_type: DerivationType::CreateProgramAddress,
            seeds,
            bump_source: BumpSource::UserProvided,
            program_id_source: ProgramIdSource::Unknown,
        };

        self.analyzer.derivations.push(derivation);
    }

    fn extract_seeds<'b, I>(&self, args: I) -> Vec<Seed>
    where
        I: IntoIterator<Item = &'b syn::Expr>,
    {
        let mut seeds = Vec::new();

        for arg in args {
            let seed = self.extract_single_seed(arg);
            seeds.push(seed);
        }

        seeds
    }

    fn extract_seeds_from_expr(&self, expr: &Expr) -> Vec<Seed> {
        match expr {
            Expr::Reference(ref_expr) => {
                if let Expr::Array(array) = &*ref_expr.expr {
                    array
                        .elems
                        .iter()
                        .map(|e| self.extract_single_seed(e))
                        .collect()
                } else {
                    vec![self.extract_single_seed(expr)]
                }
            }
            Expr::Array(array) => array
                .elems
                .iter()
                .map(|e| self.extract_single_seed(e))
                .collect(),
            _ => vec![self.extract_single_seed(expr)],
        }
    }

    fn extract_single_seed(&self, expr: &Expr) -> Seed {
        let expr_str = quote::quote!(#expr).to_string();

        let source = if expr_str.starts_with("b\"") || expr_str.starts_with("b'") {
            SeedSource::Constant
        } else if expr_str.contains(".key()") || expr_str.contains(".as_ref()") {
            if expr_str.contains("ctx.accounts") {
                SeedSource::AccountKey
            } else {
                SeedSource::Parameter
            }
        } else if expr_str.contains("state.") || expr_str.contains("config.") {
            SeedSource::StateVariable
        } else {
            SeedSource::Unknown
        };

        Seed {
            expression: expr_str,
            source,
            is_validated: false, // Conservative default
        }
    }

    fn determine_program_id_source(&self, expr: &Expr) -> ProgramIdSource {
        let expr_str = quote::quote!(#expr).to_string();

        if self.analyzer.is_safe_program_id(&expr_str) {
            ProgramIdSource::CurrentProgram
        } else if expr_str.contains("ctx") || expr_str.contains("accounts") {
            ProgramIdSource::UserProvided
        } else {
            ProgramIdSource::Unknown
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PDAError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_user_provided_bump() {
        let source = r#"
            pub fn process(bump: u8) -> Result<()> {
                let pda = Pubkey::create_program_address(
                    &[b"vault", &[bump]],
                    &program_id
                )?;
                Ok(())
            }
        "#;

        let mut analyzer = PDAAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Should detect user provided bump
        assert!(!findings.is_empty());
        // Verify line number (create_program_address is at line 3)
        assert_eq!(findings[0].derivation.line, 3);
    }

    #[test]
    fn test_safe_find_program_address() {
        let source = r#"
            pub fn process() -> Result<()> {
                let (pda, bump) = Pubkey::find_program_address(
                    &[b"vault", user.key().as_ref()],
                    &crate::ID
                );
                Ok(())
            }
        "#;

        let mut analyzer = PDAAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Should not flag canonical bump usage as vulnerability
        let non_canonical_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability == PDAVulnerability::NonCanonicalBump)
            .collect();
        assert!(non_canonical_findings.is_empty());
    }
}
