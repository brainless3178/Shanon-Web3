//! # Solana Program Analyzer
//!
//! Static analysis for Solana/Anchor programs using `syn` for real AST parsing.
//! Ships with 52 vulnerability patterns covering auth, arithmetic, account validation,
//! PDA safety, CPI, reentrancy, oracle manipulation, and DeFi attack vectors.
//!
//! ```rust,ignore
//! let analyzer = ProgramAnalyzer::new(Path::new("./my-program"))?;
//! for finding in analyzer.scan_for_vulnerabilities() {
//!     println!("[{}] {}: {}", finding.severity_label, finding.vuln_type, finding.description);
//! }
//! ```

use colored::Colorize;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use syn::{Expr, File, Item, ItemFn, ItemStruct, Stmt};

/// Normalize `quote!()` token spacing back to source-level patterns.
/// `quote!` inserts spaces around `<`, `>`, `#[`, `(`, `)` etc., which
/// breaks all string-matching vulnerability detectors.
fn normalize_quote_output(code: &str) -> String {
    code
        .replace("# [", "#[")
        .replace("Signer < ", "Signer<")
        .replace("Account < ", "Account<")
        .replace("Program < ", "Program<")
        .replace("AccountInfo < ", "AccountInfo<")
        .replace("UncheckedAccount < ", "UncheckedAccount<")
        .replace("AccountLoader < ", "AccountLoader<")
        .replace("InterfaceAccount < ", "InterfaceAccount<")
        .replace("Interface < ", "Interface<")
        .replace("SystemAccount < ", "SystemAccount<")
        .replace("Context < ", "Context<")
        .replace("Box < ", "Box<")
        .replace("Option < ", "Option<")
        .replace("Vec < ", "Vec<")
        .replace("Result < ", "Result<")
        .replace("CpiContext < ", "CpiContext<")
        .replace("'info >", "'info>")
        .replace("'info , ", "'info, ")
        .replace("(signer )", "(signer)")
        .replace("(mut )", "(mut)")
        .replace("(mut , ", "(mut, ")
        .replace("(init , ", "(init, ")
}

pub mod anchor_extractor;
pub mod ast_parser;
pub mod config;
pub mod idl_loader;
pub mod metrics;
pub mod report_generator;
pub mod security;
pub mod traits;
pub mod vulnerability_db;

pub use config::{AnalyzerConfig, ConfigBuilder};
pub use metrics::{MetricsRegistry, METRICS};
pub use security::{validation, RateLimiter, Secret};
pub use traits::{AnalysisPipeline, Analyzer, AnalyzerCapabilities, Finding, Severity};
pub use vulnerability_db::VulnerabilityPattern;

/// Parses .rs files with `syn` and runs 52 vulnerability patterns against the AST.
pub struct ProgramAnalyzer {
    source_files: Vec<(String, File)>,
    vulnerability_db: vulnerability_db::VulnerabilityDatabase,
}

impl ProgramAnalyzer {
    pub fn new(program_dir: &Path) -> Result<Self, AnalyzerError> {
        let mut source_files = Vec::new();

        // walk directory, parse .rs files
        for entry in walkdir::WalkDir::new(program_dir) {
            let entry = entry.map_err(AnalyzerError::WalkDir)?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = fs::read_to_string(entry.path())?;
                match syn::parse_file(&content) {
                    Ok(file) => {
                        let filename = entry
                            .path()
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown.rs")
                            .to_string();
                        source_files.push((filename, file));
                    }
                    Err(e) => {
                        eprintln!(
                            "  {} Skipping {}: Parse error: {}",
                            "⚠️".yellow(),
                            entry.path().display(),
                            e
                        );
                    }
                }
            }
        }

        Ok(Self {
            source_files,
            vulnerability_db: vulnerability_db::VulnerabilityDatabase::load(),
        })
    }

    /// Analyze a source string directly (for testing or inline analysis).
    pub fn from_source(source: &str) -> Result<Self, AnalyzerError> {
        let file = syn::parse_file(source)?;
        Ok(Self {
            source_files: vec![("source.rs".to_string(), file)],
            vulnerability_db: vulnerability_db::VulnerabilityDatabase::load(),
        })
    }

    /// Find all structs with #[account]
    pub fn extract_account_schemas(&self) -> Vec<AccountSchema> {
        let mut schemas = Vec::new();

        for (_, file) in &self.source_files {
            for item in &file.items {
                if let Item::Struct(item_struct) = item {
                    if self.has_account_attribute(&item_struct.attrs) {
                        let schema = self.parse_account_struct(item_struct);
                        schemas.push(schema);
                    }
                }
            }
        }

        schemas
    }

    /// Get the body of a specific instruction fn
    pub fn extract_instruction_logic(&self, instruction_name: &str) -> Option<InstructionLogic> {
        for (_, file) in &self.source_files {
            for item in &file.items {
                if let Item::Fn(func) = item {
                    if func.sig.ident == instruction_name {
                        return Some(self.parse_function_logic(func));
                    }
                }
            }
        }
        None
    }

    /// Run all 52 vuln patterns against parsed AST
    pub fn scan_for_vulnerabilities(&self) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        for (filename, file) in &self.source_files {
            self.scan_items(&file.items, filename, &mut findings);
        }

        findings
    }

    /// Same as scan_for_vulnerabilities — kept for API compat.
    /// Closures in VulnerabilityDatabase aren't Send+Sync, so true
    /// parallelism requires separate ProgramAnalyzer instances per thread.
    pub fn scan_for_vulnerabilities_parallel(&self) -> Vec<VulnerabilityFinding> {

        self.scan_for_vulnerabilities()
    }


    #[allow(dead_code, clippy::only_used_in_recursion)]
    fn collect_code_items(
        &self,
        items: &[Item],
        filename: &str,
        results: &mut Vec<(String, String, String)>,
    ) {
        for item in items {
            match item {
                Item::Fn(func) => {
                    let code = normalize_quote_output(&quote::quote!(#func).to_string());
                    results.push((code, filename.to_string(), func.sig.ident.to_string()));
                }
                Item::Mod(item_mod) => {
                    if let Some((_, items)) = &item_mod.content {
                        self.collect_code_items(items, filename, results);
                    }
                }
                Item::Struct(item_struct) => {
                    let code = normalize_quote_output(&quote::quote!(#item_struct).to_string());
                    results.push((code, filename.to_string(), item_struct.ident.to_string()));
                }
                _ => {}
            }
        }
    }


    #[allow(dead_code)]
    fn scan_items_collect(&self, items: &[Item], filename: &str) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();
        self.scan_items(items, filename, &mut findings);
        findings
    }

    fn scan_items(&self, items: &[Item], filename: &str, findings: &mut Vec<VulnerabilityFinding>) {
        // Phase 1: Build a map of struct_name -> normalized code for
        // all #[derive(Accounts)] structs. This lets us cross-reference
        // handler functions with their associated account constraints.
        let mut accounts_structs: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        self.collect_accounts_structs(items, &mut accounts_structs);

        // Phase 2: Scan items with struct context available
        self.scan_items_with_context(items, filename, findings, &accounts_structs);
    }

    /// Recursively collect all #[derive(Accounts)] struct names and their code
    fn collect_accounts_structs(
        &self,
        items: &[Item],
        map: &mut std::collections::HashMap<String, String>,
    ) {
        for item in items {
            match item {
                Item::Struct(item_struct) => {
                    let has_accounts_derive = item_struct.attrs.iter().any(|attr| {
                        let s = quote::quote!(#attr).to_string();
                        s.contains("Accounts")
                    });
                    if has_accounts_derive {
                        let code = normalize_quote_output(&quote::quote!(#item_struct).to_string());
                        map.insert(item_struct.ident.to_string(), code);
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, inner)) = &item_mod.content {
                        self.collect_accounts_structs(inner, map);
                    }
                }
                _ => {}
            }
        }
    }

    /// Extract the Accounts struct name from a function signature like:
    /// `fn handler(ctx: Context<MyAccounts>, amount: u64)` or
    /// `fn handler(ctx: Context<'info, MyAccounts>, amount: u64)`
    fn extract_context_struct_name(code: &str) -> Option<String> {
        if let Some(start) = code.find("Context<") {
            let after = &code[start + 8..];
            if let Some(end) = after.find('>') {
                let inner = after[..end].trim();
                // Take the last comma-separated segment (handles lifetimes)
                let name = inner
                    .rsplit(',')
                    .next()
                    .unwrap_or(inner)
                    .trim()
                    .to_string();
                if !name.is_empty()
                    && name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Some(name);
                }
            }
        }
        None
    }

    fn scan_items_with_context(
        &self,
        items: &[Item],
        filename: &str,
        findings: &mut Vec<VulnerabilityFinding>,
        accounts_structs: &std::collections::HashMap<String, String>,
    ) {
        for item in items {
            match item {
                Item::Fn(func) => {
                    let func_code = normalize_quote_output(&quote::quote!(#func).to_string());
                    let line_number = func.sig.ident.span().start().line;

                    // Cross-reference: if this function uses Context<StructName>,
                    // prepend the struct code so checkers see its constraints
                    let code = if let Some(struct_name) = Self::extract_context_struct_name(&func_code) {
                        if let Some(struct_code) = accounts_structs.get(&struct_name) {
                            format!("/* ACCOUNTS_STRUCT: {} */
{}
/* HANDLER: */
{}", struct_name, struct_code, func_code)
                        } else {
                            func_code
                        }
                    } else {
                        func_code
                    };

                    for pattern in self.vulnerability_db.patterns() {
                        if let Some(mut finding) = (pattern.checker)(&code) {
                            finding.location = filename.to_string();
                            finding.function_name = func.sig.ident.to_string();
                            finding.line_number = line_number;
                            finding.vulnerable_code = code.clone();
                            findings.push(finding);
                        }
                    }
                }
                Item::Mod(item_mod) => {
                    if let Some((_, inner_items)) = &item_mod.content {
                        self.scan_items_with_context(inner_items, filename, findings, accounts_structs);
                    }
                }
                Item::Struct(item_struct) => {
                    let code = normalize_quote_output(&quote::quote!(#item_struct).to_string());
                    let line_number = item_struct.ident.span().start().line;
                    for pattern in self.vulnerability_db.patterns() {
                        if let Some(mut finding) = (pattern.checker)(&code) {
                            if pattern.id.starts_with("4.")
                                || pattern.id.starts_with("3.")
                                || pattern.id.starts_with("1.")
                            {
                                finding.location = filename.to_string();
                                finding.function_name = item_struct.ident.to_string();
                                finding.line_number = line_number;
                                finding.vulnerable_code = code.clone();
                                findings.push(finding);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn has_account_attribute(&self, attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("account"))
    }

    fn parse_account_struct(&self, item_struct: &ItemStruct) -> AccountSchema {
        let mut fields = std::collections::HashMap::new();

        if let syn::Fields::Named(named_fields) = &item_struct.fields {
            for field in &named_fields.named {
                let field_name = field.ident.as_ref().unwrap().to_string();
                let field_type = field.ty.to_token_stream().to_string();
                fields.insert(field_name, field_type);
            }
        }

        AccountSchema {
            name: item_struct.ident.to_string(),
            fields,
        }
    }

    fn parse_function_logic(&self, func: &ItemFn) -> InstructionLogic {
        InstructionLogic {
            name: func.sig.ident.to_string(),
            source_code: func.to_token_stream().to_string(),
            statements: self.extract_statements(&func.block.stmts),
        }
    }

    fn extract_statements(&self, stmts: &[Stmt]) -> Vec<Statement> {
        let mut statements = Vec::new();

        for stmt in stmts {
            match stmt {
                Stmt::Expr(expr, _) => {
                    if let Some(statement) = self.parse_expression(expr) {
                        statements.push(statement);
                    }
                }
                Stmt::Local(_local) => {
                    statements.push(Statement::Assignment);
                }
                _ => {}
            }
        }

        statements
    }

    fn parse_expression(&self, expr: &Expr) -> Option<Statement> {
        match expr {
            Expr::Binary(binary) => {

                Some(Statement::Arithmetic {
                    op: format!("{:?}", binary.op),
                    checked: self.is_checked_operation(&binary.to_token_stream().to_string()),
                })
            }
            Expr::MethodCall(method_call) => {
                if method_call.method == "checked_add"
                    || method_call.method == "checked_sub"
                    || method_call.method == "checked_mul"
                    || method_call.method == "checked_div"
                {
                    Some(Statement::CheckedArithmetic)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn is_checked_operation(&self, code: &str) -> bool {
        code.contains("checked_add")
            || code.contains("checked_sub")
            || code.contains("checked_mul")
            || code.contains("checked_div")
    }
}

#[derive(Debug, Clone)]
pub struct AccountSchema {
    pub name: String,
    pub fields: std::collections::HashMap<String, String>,
}

#[derive(Debug)]
pub struct InstructionLogic {
    pub name: String,
    pub source_code: String,
    pub statements: Vec<Statement>,
}

#[derive(Debug)]
pub enum Statement {
    Arithmetic { op: String, checked: bool },
    CheckedArithmetic,
    Assignment,
    CPI,
    Require,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub category: String,
    pub vuln_type: String,
    pub severity: u8,
    pub severity_label: String,
    pub id: String,
    pub cwe: Option<String>,
    pub location: String,
    pub function_name: String,
    pub line_number: usize,
    pub vulnerable_code: String,
    pub description: String,
    pub attack_scenario: String,
    pub real_world_incident: Option<Incident>,
    pub secure_fix: String,
    pub prevention: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub project: String,
    pub loss: String,
    pub date: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] syn::Error),
    #[error("Walkdir error: {0}")]
    WalkDir(walkdir::Error),
}
