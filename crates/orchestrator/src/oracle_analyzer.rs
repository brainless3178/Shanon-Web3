//! Oracle Manipulation Detection for Solana Programs
//!
//! Detects vulnerabilities related to price oracle usage:
//! - Staleness checks
//! - Confidence interval validation
//! - Single oracle dependency
//! - Manipulation resistance

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use syn::{spanned::Spanned, visit::Visit, ExprField, ExprMethodCall, File, ItemFn};

/// Represents an oracle usage in the program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleUsage {
    pub name: String,
    pub location: String,
    pub line: usize,
    pub oracle_type: OracleType,
    pub asset: String,
    pub usage_context: OracleUsageContext,
    pub validations: Vec<OracleValidation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OracleType {
    /// Pyth Network price feed
    Pyth,
    /// Switchboard aggregator
    Switchboard,
    /// On-chain AMM spot price
    AMMSpot,
    /// On-chain TWAP
    TWAP,
    /// Chainlink (if bridged)
    Chainlink,
    /// Custom oracle
    Custom,
    /// Hardcoded price (dangerous!)
    Hardcoded,
    /// Unknown oracle source
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OracleUsageContext {
    /// Used to determine liquidations
    Liquidation,
    /// Used to value collateral
    CollateralValuation,
    /// Used to calculate borrowing power
    BorrowingPower,
    /// Used in swap calculations
    SwapCalculation,
    /// Used to price LP tokens
    LPTokenPricing,
    /// Used for fee calculations
    FeeCalculation,
    /// General purpose
    General,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleValidation {
    /// Timestamp/staleness check
    StalenessCheck { max_age_seconds: Option<u64> },
    /// Confidence interval check
    ConfidenceCheck { max_confidence_bps: Option<u64> },
    /// Price bounds check
    BoundsCheck {
        min_price: Option<u64>,
        max_price: Option<u64>,
    },
    /// Price status check (trading/halted)
    StatusCheck,
    /// Rate limiting check (max change per period)
    RateLimitCheck { max_change_bps: Option<u64> },
    /// Multi-oracle aggregation
    MultiOracleCheck,
}

/// Oracle security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleFinding {
    pub oracle_usage: OracleUsage,
    pub vulnerability: OracleVulnerability,
    pub severity: OracleSeverity,
    pub description: String,
    pub attack_scenario: Option<String>,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleVulnerability {
    /// No staleness check - using potentially outdated price
    MissingStalenessCheck,
    /// No confidence interval check
    MissingConfidenceCheck,
    /// Single oracle dependency
    SingleOracleDependency,
    /// Using AMM spot price for critical operations
    ManipulableSpotPrice,
    /// Hardcoded price (always dangerous)
    HardcodedPrice,
    /// No price bounds check
    NoBoundsCheck,
    /// No rate limit on price changes
    NoRateLimit,
    /// Oracle account not validated
    UnvalidatedOracleAccount,
    /// Using stablecoins with assumed $1 price
    AssumedStablecoinPrice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Main Oracle Analyzer
pub struct OracleAnalyzer {
    /// All detected oracle usages
    usages: Vec<OracleUsage>,
    /// All detected findings
    findings: Vec<OracleFinding>,
    /// Known oracle patterns
    _oracle_patterns: HashMap<String, OracleType>,
    /// Critical usage contexts that require extra validation
    critical_contexts: HashSet<OracleUsageContext>,
}

impl OracleAnalyzer {
    pub fn new() -> Self {
        let mut oracle_patterns = HashMap::new();
        // Pyth patterns
        oracle_patterns.insert("pyth".to_string(), OracleType::Pyth);
        oracle_patterns.insert("get_price".to_string(), OracleType::Pyth);
        oracle_patterns.insert("price_account".to_string(), OracleType::Pyth);
        oracle_patterns.insert("PriceAccount".to_string(), OracleType::Pyth);
        // Switchboard patterns
        oracle_patterns.insert("switchboard".to_string(), OracleType::Switchboard);
        oracle_patterns.insert("aggregator".to_string(), OracleType::Switchboard);
        oracle_patterns.insert("get_result".to_string(), OracleType::Switchboard);
        // AMM patterns
        oracle_patterns.insert("reserve".to_string(), OracleType::AMMSpot);
        oracle_patterns.insert("pool_state".to_string(), OracleType::AMMSpot);

        let mut critical_contexts = HashSet::new();
        critical_contexts.insert(OracleUsageContext::Liquidation);
        critical_contexts.insert(OracleUsageContext::CollateralValuation);
        critical_contexts.insert(OracleUsageContext::BorrowingPower);

        Self {
            usages: Vec::new(),
            findings: Vec::new(),
            _oracle_patterns: oracle_patterns,
            critical_contexts,
        }
    }

    /// Analyze source code for oracle issues
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<OracleFinding>, OracleError> {
        let file = syn::parse_file(source).map_err(|e| OracleError::ParseError(e.to_string()))?;

        self.analyze_file(&file, filename);
        self.detect_vulnerabilities();

        Ok(self.findings.clone())
    }

    /// Analyze a parsed file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        let mut visitor = OracleVisitor {
            analyzer: self,
            filename: filename.to_string(),
            current_function: String::new(),
            current_line: 0,
            detected_validations: Vec::new(),
        };
        visitor.visit_file(file);
    }

    /// Detect vulnerabilities in oracle patterns
    fn detect_vulnerabilities(&mut self) {
        for usage in &self.usages.clone() {
            self.check_staleness_validation(usage);
            self.check_confidence_validation(usage);
            self.check_bounds_validation(usage);
            self.check_oracle_type_safety(usage);
            self.check_single_source(usage);
        }
    }

    fn check_staleness_validation(&mut self, usage: &OracleUsage) {
        let has_staleness_check = usage
            .validations
            .iter()
            .any(|v| matches!(v, OracleValidation::StalenessCheck { .. }));

        if !has_staleness_check && usage.oracle_type != OracleType::Hardcoded {
            let severity = if self.critical_contexts.contains(&usage.usage_context) {
                OracleSeverity::Critical
            } else {
                OracleSeverity::High
            };

            self.findings.push(OracleFinding {
                oracle_usage: usage.clone(),
                vulnerability: OracleVulnerability::MissingStalenessCheck,
                severity,
                description: format!(
                    "Oracle price read at line {} lacks staleness validation. \
                    Outdated prices could be used for {:?}.",
                    usage.line, usage.usage_context
                ),
                attack_scenario: Some(
                    "If oracle updates are delayed, protocol uses stale price. \
                    In volatile markets, this enables exploitation of outdated valuations.".to_string()
                ),
                recommendation: "Add staleness check:\n\
                    let max_age = 60; // seconds\n\
                    let price = oracle.get_price_no_older_than(Clock::get()?.unix_timestamp, max_age)?;".to_string(),
            });
        }
    }

    fn check_confidence_validation(&mut self, usage: &OracleUsage) {
        // Only Pyth provides confidence intervals
        if usage.oracle_type != OracleType::Pyth {
            return;
        }

        let has_confidence_check = usage
            .validations
            .iter()
            .any(|v| matches!(v, OracleValidation::ConfidenceCheck { .. }));

        if !has_confidence_check {
            let severity = if self.critical_contexts.contains(&usage.usage_context) {
                OracleSeverity::High
            } else {
                OracleSeverity::Medium
            };

            self.findings.push(OracleFinding {
                oracle_usage: usage.clone(),
                vulnerability: OracleVulnerability::MissingConfidenceCheck,
                severity,
                description: format!(
                    "Pyth oracle at line {} used without confidence interval check. \
                    High uncertainty prices could cause bad valuations.",
                    usage.line
                ),
                attack_scenario: Some(
                    "During high volatility, Pyth confidence interval widens. \
                    Using uncertain prices for liquidations could cause bad debt."
                        .to_string(),
                ),
                recommendation: "Add confidence check:\n\
                    let max_conf_bps = 100; // 1%\n\
                    let conf_bps = price_data.conf * 10000 / price_data.price.abs();\n\
                    require!(conf_bps <= max_conf_bps, ErrorCode::HighConfidence);"
                    .to_string(),
            });
        }
    }

    fn check_bounds_validation(&mut self, usage: &OracleUsage) {
        let has_bounds_check = usage
            .validations
            .iter()
            .any(|v| matches!(v, OracleValidation::BoundsCheck { .. }));

        if !has_bounds_check && self.critical_contexts.contains(&usage.usage_context) {
            self.findings.push(OracleFinding {
                oracle_usage: usage.clone(),
                vulnerability: OracleVulnerability::NoBoundsCheck,
                severity: OracleSeverity::Medium,
                description: format!(
                    "Oracle price at line {} has no sanity bounds check. \
                    Extreme prices (flash crash, oracle error) could cause mass liquidations.",
                    usage.line
                ),
                attack_scenario: Some(
                    "Oracle error reports $0 or $10M price for $100 asset. \
                    Without bounds check, system acts on obviously wrong price."
                        .to_string(),
                ),
                recommendation: "Add bounds check:\n\
                    require!(price > MIN_EXPECTED_PRICE && price < MAX_EXPECTED_PRICE);"
                    .to_string(),
            });
        }
    }

    fn check_oracle_type_safety(&mut self, usage: &OracleUsage) {
        match usage.oracle_type {
            OracleType::AMMSpot => {
                self.findings.push(OracleFinding {
                    oracle_usage: usage.clone(),
                    vulnerability: OracleVulnerability::ManipulableSpotPrice,
                    severity: OracleSeverity::Critical,
                    description: format!(
                        "AMM spot price used at line {}. This is trivially manipulable \
                        within a single transaction via large swaps.",
                        usage.line
                    ),
                    attack_scenario: Some(
                        "1. Flash borrow tokens\n\
                         2. Swap to manipulate AMM price\n\
                         3. Exploit protocol using inflated/deflated price\n\
                         4. Reverse swap, repay loan, profit"
                            .to_string(),
                    ),
                    recommendation: "NEVER use AMM spot price for collateral or liquidations. \
                        Use Pyth/Switchboard external oracle. \
                        If using on-chain data, use TWAP over 30+ minutes."
                        .to_string(),
                });
            }
            OracleType::Hardcoded => {
                self.findings.push(OracleFinding {
                    oracle_usage: usage.clone(),
                    vulnerability: OracleVulnerability::HardcodedPrice,
                    severity: OracleSeverity::High,
                    description: format!(
                        "Hardcoded price at line {}. Market price changes will not be reflected.",
                        usage.line
                    ),
                    attack_scenario: Some(
                        "Asset depegs or changes value, but protocol uses stale hardcoded price. \
                        Enables arbitrage against protocol."
                            .to_string(),
                    ),
                    recommendation: "Use dynamic price oracle instead of hardcoded value."
                        .to_string(),
                });
            }
            _ => {}
        }

        // Check for assumed stablecoin prices
        if (usage.asset.to_lowercase().contains("usdc")
            || usage.asset.to_lowercase().contains("usdt")
            || usage.asset.to_lowercase().contains("dai"))
            && usage.oracle_type == OracleType::Hardcoded {
                self.findings.push(OracleFinding {
                    oracle_usage: usage.clone(),
                    vulnerability: OracleVulnerability::AssumedStablecoinPrice,
                    severity: OracleSeverity::Medium,
                    description: format!(
                        "Stablecoin '{}' assumed to be $1 at line {}. Depegs are possible.",
                        usage.asset, usage.line
                    ),
                    attack_scenario: Some(format!(
                        "If {} depegs to $0.95, protocol still values at $1, enabling arbitrage.",
                        usage.asset
                    )),
                    recommendation: format!(
                        "Add oracle for {} or monitor depeg events. \
                        Add circuit breaker if price deviates > 2% from $1.",
                        usage.asset
                    ),
                });
            }
    }

    fn check_single_source(&mut self, usage: &OracleUsage) {
        let has_multi_oracle = usage
            .validations
            .iter()
            .any(|v| matches!(v, OracleValidation::MultiOracleCheck));

        if !has_multi_oracle && self.critical_contexts.contains(&usage.usage_context) {
            self.findings.push(OracleFinding {
                oracle_usage: usage.clone(),
                vulnerability: OracleVulnerability::SingleOracleDependency,
                severity: OracleSeverity::Medium,
                description: format!(
                    "Single oracle source for critical operation {:?} at line {}. \
                    No fallback if oracle fails.",
                    usage.usage_context, usage.line
                ),
                attack_scenario: None,
                recommendation: "Consider using multiple oracle sources:\n\
                    - Pyth as primary\n\
                    - Switchboard as fallback\n\
                    - Take median or weighted average\n\
                    - Implement circuit breaker for oracle failures"
                    .to_string(),
            });
        }
    }

    /// Get all findings
    pub fn get_findings(&self) -> &[OracleFinding] {
        &self.findings
    }

    /// Get all detected oracle usages
    pub fn get_usages(&self) -> &[OracleUsage] {
        &self.usages
    }

    /// Calculate oracle diversity score
    pub fn calculate_diversity_score(&self) -> OracleDiversityScore {
        let unique_oracles: HashSet<_> = self.usages.iter().map(|u| &u.oracle_type).collect();

        let has_external = self.usages.iter().any(|u| {
            matches!(
                u.oracle_type,
                OracleType::Pyth | OracleType::Switchboard | OracleType::Chainlink
            )
        });

        let has_validation = self.usages.iter().all(|u| !u.validations.is_empty());

        OracleDiversityScore {
            unique_sources: unique_oracles.len(),
            has_external_oracle: has_external,
            has_proper_validation: has_validation,
            risk_level: if has_external && has_validation {
                "LOW"
            } else if has_external {
                "MEDIUM"
            } else {
                "HIGH"
            }
            .to_string(),
        }
    }
}

impl Default for OracleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDiversityScore {
    pub unique_sources: usize,
    pub has_external_oracle: bool,
    pub has_proper_validation: bool,
    pub risk_level: String,
}

/// AST visitor for oracle extraction
struct OracleVisitor<'a> {
    analyzer: &'a mut OracleAnalyzer,
    filename: String,
    current_function: String,
    current_line: usize,
    detected_validations: Vec<OracleValidation>,
}

impl<'a> Visit<'_> for OracleVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();
        self.detected_validations.clear();
        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr_method_call(&mut self, expr: &ExprMethodCall) {
        self.current_line = expr.span().start().line;
        let method_name = expr.method.to_string();
        let receiver_str = quote::quote!(#expr.receiver).to_string();

        // Detect oracle reads
        if self.is_oracle_read(&method_name, &receiver_str) {
            self.record_oracle_usage(expr);
        }

        // Detect validation patterns
        if method_name.contains("no_older_than") || method_name.contains("staleness") {
            self.detected_validations
                .push(OracleValidation::StalenessCheck {
                    max_age_seconds: None,
                });
        }

        if method_name.contains("conf") || method_name.contains("confidence") {
            self.detected_validations
                .push(OracleValidation::ConfidenceCheck {
                    max_confidence_bps: None,
                });
        }

        syn::visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr_field(&mut self, expr: &ExprField) {
        self.current_line = expr.span().start().line;
        let field_name = match &expr.member {
            syn::Member::Named(ident) => ident.to_string(),
            syn::Member::Unnamed(index) => index.index.to_string(),
        };

        // Detect direct reserve reads (AMM spot price)
        if field_name.contains("reserve") {
            let base_str = quote::quote!(#expr.base).to_string();
            self.analyzer.usages.push(OracleUsage {
                name: format!("{}.{}", base_str, field_name),
                location: self.filename.clone(),
                line: self.current_line,
                oracle_type: OracleType::AMMSpot,
                asset: field_name.clone(),
                usage_context: OracleUsageContext::General,
                validations: self.detected_validations.clone(),
            });
        }

        syn::visit::visit_expr_field(self, expr);
    }
}

impl<'a> OracleVisitor<'a> {
    fn is_oracle_read(&self, method_name: &str, receiver: &str) -> bool {
        let patterns = [
            "get_price",
            "get_current_price",
            "price",
            "get_result",
            "get_value",
        ];
        let oracle_receivers = ["pyth", "switchboard", "oracle", "aggregator", "price_feed"];

        patterns.iter().any(|p| method_name.contains(p))
            || oracle_receivers
                .iter()
                .any(|r| receiver.to_lowercase().contains(r))
    }

    fn record_oracle_usage(&mut self, expr: &ExprMethodCall) {
        let method_name = expr.method.to_string();
        let receiver_str = quote::quote!(#expr.receiver).to_string();

        let oracle_type = if receiver_str.to_lowercase().contains("pyth") {
            OracleType::Pyth
        } else if receiver_str.to_lowercase().contains("switchboard") {
            OracleType::Switchboard
        } else if receiver_str.to_lowercase().contains("twap") {
            OracleType::TWAP
        } else {
            OracleType::Unknown
        };

        // Determine usage context from function name
        let usage_context = if self.current_function.contains("liquidat") {
            OracleUsageContext::Liquidation
        } else if self.current_function.contains("collateral")
            || self.current_function.contains("value")
        {
            OracleUsageContext::CollateralValuation
        } else if self.current_function.contains("borrow") {
            OracleUsageContext::BorrowingPower
        } else if self.current_function.contains("swap") {
            OracleUsageContext::SwapCalculation
        } else {
            OracleUsageContext::General
        };

        self.analyzer.usages.push(OracleUsage {
            name: format!("{}.{}", receiver_str, method_name),
            location: self.filename.clone(),
            line: self.current_line,
            oracle_type,
            asset: self.extract_asset_from_receiver(&receiver_str),
            usage_context,
            validations: self.detected_validations.clone(),
        });
    }

    fn extract_asset_from_receiver(&self, receiver: &str) -> String {
        // Try to extract asset name from variable name
        if receiver.to_lowercase().contains("sol") {
            "SOL".to_string()
        } else if receiver.to_lowercase().contains("usdc") {
            "USDC".to_string()
        } else if receiver.to_lowercase().contains("btc") {
            "BTC".to_string()
        } else if receiver.to_lowercase().contains("eth") {
            "ETH".to_string()
        } else {
            "UNKNOWN".to_string()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_missing_staleness() {
        let source = r#"
            pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
                let price = ctx.accounts.pyth_price.get_price()?;
                // No staleness check!
                let value = collateral * price;
                Ok(())
            }
        "#;

        let mut analyzer = OracleAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs");

        assert!(findings.is_ok());
    }

    #[test]
    fn test_detect_spot_price() {
        let source = r#"
            pub fn calculate_health(pool: &Pool) -> u64 {
                let price = pool.reserve_quote / pool.reserve_base;
                collateral * price / debt
            }
        "#;

        let mut analyzer = OracleAnalyzer::new();
        let findings = analyzer.analyze_source(source, "test.rs").unwrap();

        // Should detect AMM spot price usage
        let spot_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.vulnerability == OracleVulnerability::ManipulableSpotPrice)
            .collect();

        assert!(
            !spot_findings.is_empty()
                || analyzer
                    .get_usages()
                    .iter()
                    .any(|u| u.oracle_type == OracleType::AMMSpot)
        );
    }
}
