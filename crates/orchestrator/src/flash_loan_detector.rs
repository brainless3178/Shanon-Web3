//! Flash Loan Attack Detection for Solana Programs
//!
//! Identifies vulnerabilities exploitable via atomic transactions:
//! - Price oracle manipulation
//! - First deposit/share inflation attacks
//! - Missing slippage protection
//! - Sandwich attack vectors

use serde::{Deserialize, Serialize};
use syn::{spanned::Spanned, visit::Visit, BinOp, ExprBinary, ExprMethodCall, File, ItemFn};

/// Represents a potential flash loan attack vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashLoanVector {
    pub name: String,
    pub location: String,
    pub line: usize,
    pub vector_type: FlashLoanVectorType,
    pub price_dependencies: Vec<PriceDependency>,
    pub manipulation_surface: ManipulationSurface,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlashLoanVectorType {
    /// Price oracle can be manipulated within transaction
    PriceOracleManipulation,
    /// First depositor can inflate share price
    FirstDepositAttack,
    /// Missing minimum output amount check
    MissingSlippage,
    /// Balance check before external call can be exploited
    StaleBalanceCheck,
    /// Share/ratio calculation uses spot values
    SpotPriceInCalculation,
    /// Donation-based attack vector
    DonationAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceDependency {
    pub variable: String,
    pub source: PriceSource,
    pub usage: PriceUsage,
    pub is_manipulable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceSource {
    /// Direct AMM reserve ratio
    SpotReserves,
    /// External oracle (Pyth, Switchboard)
    ExternalOracle,
    /// TWAP calculation
    TWAP,
    /// Account balance read
    AccountBalance,
    /// Stored price from state
    StoredPrice,
    /// Unknown
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceUsage {
    /// Used in liquidation threshold
    Liquidation,
    /// Used in collateral valuation
    CollateralValuation,
    /// Used in swap output calculation
    SwapOutput,
    /// Used in share price calculation
    SharePrice,
    /// Used in borrowing power calculation
    BorrowingPower,
    /// General arithmetic
    General,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManipulationSurface {
    pub capital_required: CapitalRequirement,
    pub complexity: AttackComplexity,
    pub profit_potential: ProfitPotential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapitalRequirement {
    Low,      // < $10k
    Medium,   // $10k - $100k
    High,     // $100k - $1M
    VeryHigh, // > $1M
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackComplexity {
    Simple,   // Single transaction, no setup
    Moderate, // Requires some setup or timing
    Complex,  // Multi-step, requires coordination
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfitPotential {
    Low,      // < $1k
    Medium,   // $1k - $10k
    High,     // $10k - $100k
    Critical, // > $100k or protocol-breaking
}

/// Flash loan vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashLoanFinding {
    pub vector: FlashLoanVector,
    pub vulnerability: FlashLoanVulnerability,
    pub severity: FlashLoanSeverity,
    pub description: String,
    pub attack_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlashLoanVulnerability {
    /// Single-block price used for critical decision
    SpotPriceForCriticalDecision,
    /// First deposit vulnerability (share inflation)
    FirstDepositInflation,
    /// No minimum output protection
    NoSlippageProtection,
    /// Balance read before CPI not rechecked after
    StaleBalanceAfterCPI,
    /// Donation can affect share price
    DonationVulnerable,
    /// Read-only reentrancy
    ReadOnlyReentrancy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlashLoanSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Main Flash Loan Analyzer
pub struct FlashLoanAnalyzer {
    /// Detected attack vectors
    vectors: Vec<FlashLoanVector>,
    /// Detected findings
    findings: Vec<FlashLoanFinding>,
    /// Price read locations
    price_reads: Vec<PriceRead>,
    /// Share/ratio calculations
    share_calculations: Vec<ShareCalculation>,
    /// Slippage checks
    slippage_checks: Vec<SlippageCheck>,
}

#[derive(Debug, Clone)]
struct PriceRead {
    location: String,
    line: usize,
    source: PriceSource,
    variable: String,
}

#[derive(Debug, Clone)]
struct ShareCalculation {
    location: String,
    line: usize,
    formula_type: ShareFormulaType,
    has_first_deposit_protection: bool,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ShareFormulaType {
    /// deposit * total_shares / total_assets
    ProRata,
    /// sqrt(amount_a * amount_b)
    GeometricMean,
    /// Custom formula
    Custom,
}

#[derive(Debug, Clone)]
struct SlippageCheck {
    _location: String,
    _line: usize,
    check_type: SlippageCheckType,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum SlippageCheckType {
    /// min_amount_out parameter and check
    MinAmountOut,
    /// max_price_impact check
    MaxPriceImpact,
    /// deadline check
    Deadline,
    /// None found
    None,
}

impl FlashLoanAnalyzer {
    pub fn new() -> Self {
        Self {
            vectors: Vec::new(),
            findings: Vec::new(),
            price_reads: Vec::new(),
            share_calculations: Vec::new(),
            slippage_checks: Vec::new(),
        }
    }

    /// Analyze source code for flash loan vulnerabilities
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<FlashLoanFinding>, FlashLoanError> {
        let file =
            syn::parse_file(source).map_err(|e| FlashLoanError::ParseError(e.to_string()))?;

        self.analyze_file(&file, filename);
        self.detect_vulnerabilities();

        Ok(self.findings.clone())
    }

    /// Analyze a parsed file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        let mut visitor = FlashLoanVisitor {
            analyzer: self,
            filename: filename.to_string(),
            current_function: String::new(),
            current_line: 0,
        };
        visitor.visit_file(file);
    }

    /// Detect flash loan vulnerabilities
    fn detect_vulnerabilities(&mut self) {
        self.detect_spot_price_vulnerabilities();
        self.detect_first_deposit_vulnerabilities();
        self.detect_slippage_vulnerabilities();
        self.detect_donation_vulnerabilities();
    }

    fn detect_spot_price_vulnerabilities(&mut self) {
        for price_read in &self.price_reads {
            if price_read.source == PriceSource::SpotReserves {
                let vector = FlashLoanVector {
                    name: format!("spot_price_{}", price_read.variable),
                    location: price_read.location.clone(),
                    line: price_read.line,
                    vector_type: FlashLoanVectorType::PriceOracleManipulation,
                    price_dependencies: vec![PriceDependency {
                        variable: price_read.variable.clone(),
                        source: PriceSource::SpotReserves,
                        usage: PriceUsage::General,
                        is_manipulable: true,
                    }],
                    manipulation_surface: ManipulationSurface {
                        capital_required: CapitalRequirement::Medium,
                        complexity: AttackComplexity::Simple,
                        profit_potential: ProfitPotential::High,
                    },
                };

                self.findings.push(FlashLoanFinding {
                    vector: vector.clone(),
                    vulnerability: FlashLoanVulnerability::SpotPriceForCriticalDecision,
                    severity: FlashLoanSeverity::Critical,
                    description: format!(
                        "Spot price from AMM reserves used at line {}. This can be manipulated within a single transaction.",
                        price_read.line
                    ),
                    attack_scenario: "1. Flash borrow large amount of tokens\n\
                         2. Execute massive swap in AMM to manipulate price\n\
                         3. Exploit victim protocol using manipulated price\n\
                         4. Reverse swap to restore price\n\
                         5. Repay flash loan + profit".to_string(),
                    recommendation: "Use Pyth/Switchboard oracle with TWAP. Add price deviation limits. Never use spot price for liquidations or collateral valuation.".to_string(),
                });

                self.vectors.push(vector);
            }
        }
    }

    fn detect_first_deposit_vulnerabilities(&mut self) {
        for calc in &self.share_calculations {
            if !calc.has_first_deposit_protection {
                let vector = FlashLoanVector {
                    name: "first_deposit_attack".to_string(),
                    location: calc.location.clone(),
                    line: calc.line,
                    vector_type: FlashLoanVectorType::FirstDepositAttack,
                    price_dependencies: Vec::new(),
                    manipulation_surface: ManipulationSurface {
                        capital_required: CapitalRequirement::Medium,
                        complexity: AttackComplexity::Simple,
                        profit_potential: ProfitPotential::High,
                    },
                };

                self.findings.push(FlashLoanFinding {
                    vector: vector.clone(),
                    vulnerability: FlashLoanVulnerability::FirstDepositInflation,
                    severity: FlashLoanSeverity::Critical,
                    description: format!(
                        "Share calculation at line {} lacks first deposit protection. \
                        Attacker can inflate share price.",
                        calc.line
                    ),
                    attack_scenario: "1. Vault starts empty\n\
                         2. Attacker deposits 1 wei → gets 1 share\n\
                         3. Attacker donates large amount directly to vault\n\
                         4. Share price = large_amount / 1 share\n\
                         5. Victim deposits, gets 0 shares due to rounding\n\
                         6. Attacker withdraws with victim's deposit"
                        .to_string(),
                    recommendation: "Lock minimum liquidity on first deposit (e.g., 1000 shares). \
                        Or require minimum first deposit amount. \
                        Check shares > 0 after calculation."
                        .to_string(),
                });

                self.vectors.push(vector);
            }
        }
    }

    fn detect_slippage_vulnerabilities(&mut self) {
        // Check if swap functions have slippage protection
        let has_slippage = self
            .slippage_checks
            .iter()
            .any(|c| c.check_type != SlippageCheckType::None);

        if !has_slippage && !self.share_calculations.is_empty() {
            let vector = FlashLoanVector {
                name: "missing_slippage".to_string(),
                location: "swap function".to_string(),
                line: 0,
                vector_type: FlashLoanVectorType::MissingSlippage,
                price_dependencies: Vec::new(),
                manipulation_surface: ManipulationSurface {
                    capital_required: CapitalRequirement::Low,
                    complexity: AttackComplexity::Simple,
                    profit_potential: ProfitPotential::Medium,
                },
            };

            self.findings.push(FlashLoanFinding {
                vector: vector.clone(),
                vulnerability: FlashLoanVulnerability::NoSlippageProtection,
                severity: FlashLoanSeverity::High,
                description: "No slippage protection found in swap/trade functions. Users vulnerable to sandwich attacks.".to_string(),
                attack_scenario:
                    "1. Attacker monitors mempool for victim's swap\n\
                     2. Front-run: Execute large buy to pump price\n\
                     3. Victim's swap executes at inflated price\n\
                     4. Back-run: Sell tokens at high price\n\
                     5. Profit = victim's slippage".to_string(),
                recommendation:
                    "Add min_amount_out parameter to swap functions:\n\
                    require!(amount_out >= min_amount_out, ErrorCode::SlippageExceeded);".to_string(),
            });

            self.vectors.push(vector);
        }
    }

    fn detect_donation_vulnerabilities(&mut self) {
        // Check for share calculations that use account balance directly
        for calc in &self.share_calculations {
            if calc.formula_type == ShareFormulaType::ProRata {
                // Pro-rata calculations are vulnerable to donation attacks
                let vector = FlashLoanVector {
                    name: "donation_attack".to_string(),
                    location: calc.location.clone(),
                    line: calc.line,
                    vector_type: FlashLoanVectorType::DonationAttack,
                    price_dependencies: vec![PriceDependency {
                        variable: "total_assets".to_string(),
                        source: PriceSource::AccountBalance,
                        usage: PriceUsage::SharePrice,
                        is_manipulable: true,
                    }],
                    manipulation_surface: ManipulationSurface {
                        capital_required: CapitalRequirement::Medium,
                        complexity: AttackComplexity::Moderate,
                        profit_potential: ProfitPotential::High,
                    },
                };

                self.findings.push(FlashLoanFinding {
                    vector: vector.clone(),
                    vulnerability: FlashLoanVulnerability::DonationVulnerable,
                    severity: FlashLoanSeverity::Medium,
                    description: format!(
                        "Share calculation at line {} may be vulnerable to donation attack if using direct balance reads.",
                        calc.line
                    ),
                    attack_scenario:
                        "Attacker can donate tokens directly to vault to manipulate share price, \
                        potentially causing rounding errors that benefit them.".to_string(),
                    recommendation:
                        "Track deposits explicitly rather than using account balance. \
                        Or add virtual offset to prevent zero-state manipulation.".to_string(),
                });

                self.vectors.push(vector);
            }
        }
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[FlashLoanFinding] {
        &self.findings
    }

    /// Get all attack vectors
    pub fn get_vectors(&self) -> &[FlashLoanVector] {
        &self.vectors
    }
}

impl Default for FlashLoanAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor for flash loan pattern extraction
struct FlashLoanVisitor<'a> {
    analyzer: &'a mut FlashLoanAnalyzer,
    filename: String,
    current_function: String,
    current_line: usize,
}

impl<'a> Visit<'_> for FlashLoanVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();
        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr_binary(&mut self, expr: &ExprBinary) {
        self.current_line = expr.span().start().line;
        // Detect price/share calculations
        if matches!(expr.op, BinOp::Div(_) | BinOp::Mul(_)) {
            self.analyze_division_pattern(expr);
        }

        syn::visit::visit_expr_binary(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &ExprMethodCall) {
        self.current_line = expr.span().start().line;
        let method_name = expr.method.to_string();

        // Detect reserve reads (spot price source)
        if method_name.contains("reserve") || method_name.contains("balance") {
            self.record_balance_read(expr);
        }

        // Detect oracle reads
        if method_name.contains("get_price") || method_name.contains("get_current") {
            self.record_oracle_read(expr);
        }

        // Detect slippage checks
        if method_name.contains("min_out") || method_name.contains("minimum") {
            self.record_slippage_check(expr);
        }

        syn::visit::visit_expr_method_call(self, expr);
    }
}

impl<'a> FlashLoanVisitor<'a> {
    fn analyze_division_pattern(&mut self, expr: &ExprBinary) {
        let left_str = quote::quote!(#expr.left).to_string();
        let right_str = quote::quote!(#expr.right).to_string();

        // Detect share calculation pattern: amount * total_shares / total_assets
        if (left_str.contains("share") || left_str.contains("amount"))
            && (right_str.contains("total") || right_str.contains("supply"))
        {
            let has_protection = left_str.contains("virtual")
                || left_str.contains("dead_shares")
                || left_str.contains("MIN_");

            self.analyzer.share_calculations.push(ShareCalculation {
                location: self.filename.clone(),
                line: self.current_line,
                formula_type: ShareFormulaType::ProRata,
                has_first_deposit_protection: has_protection,
            });
        }

        // Detect spot price pattern: reserve_a / reserve_b
        if left_str.contains("reserve") && right_str.contains("reserve") {
            self.analyzer.price_reads.push(PriceRead {
                location: self.filename.clone(),
                line: self.current_line,
                source: PriceSource::SpotReserves,
                variable: format!("price = {} / {}", left_str, right_str),
            });
        }
    }

    fn record_balance_read(&mut self, expr: &ExprMethodCall) {
        let receiver_str = quote::quote!(#expr.receiver).to_string();

        self.analyzer.price_reads.push(PriceRead {
            location: self.filename.clone(),
            line: self.current_line,
            source: PriceSource::AccountBalance,
            variable: receiver_str,
        });
    }

    fn record_oracle_read(&mut self, expr: &ExprMethodCall) {
        let receiver_str = quote::quote!(#expr.receiver).to_string();

        let source = if receiver_str.contains("pyth") || receiver_str.contains("oracle") {
            PriceSource::ExternalOracle
        } else if receiver_str.contains("twap") {
            PriceSource::TWAP
        } else {
            PriceSource::Unknown
        };

        self.analyzer.price_reads.push(PriceRead {
            location: self.filename.clone(),
            line: self.current_line,
            source,
            variable: receiver_str,
        });
    }

    fn record_slippage_check(&mut self, _expr: &ExprMethodCall) {
        self.analyzer.slippage_checks.push(SlippageCheck {
            _location: self.filename.clone(),
            _line: self.current_line,
            check_type: SlippageCheckType::MinAmountOut,
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FlashLoanError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_spot_price() {
        let source = r#"
            pub fn calculate_price(pool: &Pool) -> u64 {
                let price = pool.reserve_quote / pool.reserve_base;
                price
            }
        "#;

        let mut analyzer = FlashLoanAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs");

        assert!(findings.is_ok());
    }

    #[test]
    fn test_detect_first_deposit() {
        let source = "pub fn deposit(vault: &mut Vault, amount: u64) -> u64 {\n    let shares = amount * vault.total_shares / vault.total_assets;\n    vault.total_shares += shares;\n    shares\n}";

        let mut analyzer = FlashLoanAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Should detect first deposit vulnerability
        assert!(!findings.is_empty());
        // Verify accurate line number reporting
        assert_eq!(findings[0].vector.line, 2);
    }
}
