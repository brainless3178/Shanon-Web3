use anyhow::Result;
use serde::{Deserialize, Serialize};
use syn::spanned::Spanned;
use syn::{
    visit::{self, Visit},
    BinOp, Expr,
};

pub struct ArithmeticSecurityExpert;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticInsight {
    pub name: String,
    pub risk_assessment: String,
    pub attack_vectors: Vec<String>,
    pub secure_pattern: String,
    pub precision_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArithmeticIssueKind {
    DivisionBeforeMultiplication,
    UncheckedArithmetic,
    PotentialPrecisionLoss,
    IntegerCastingRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArithmeticIssue {
    pub kind: ArithmeticIssueKind,
    pub line: usize,
    pub snippet: String,
    pub recommendation: String,
}

impl ArithmeticSecurityExpert {
    pub fn get_insight_for_id(id: &str) -> Option<ArithmeticInsight> {
        match id {
            "2.1" | "SOL-002" => Some(ArithmeticInsight {
                name: "Integer Overflow/Underflow".to_string(),
                risk_assessment: "Critical. Allows manipulation of balances and shares."
                    .to_string(),
                attack_vectors: vec![
                    "Large deposit amount causing overflow in total assets".to_string(),
                    "Small deposit/withdraw causing precision loss in share calculation"
                        .to_string(),
                ],
                secure_pattern:
                    "amount.checked_mul(total_shares).ok_or(Error::Overflow)? / total_assets"
                        .to_string(),
                precision_rules: vec![
                    "Always multiply before dividing".to_string(),
                    "Use checked arithmetic for all user-controlled inputs".to_string(),
                ],
            }),
            _ => None,
        }
    }

    /// Analyze a source file for arithmetic vulnerabilities
    pub fn analyze_source(source: &str) -> Result<Vec<ArithmeticIssue>> {
        let file = syn::parse_file(source)?;
        let mut visitor = ArithmeticVisitor { issues: Vec::new() };
        visitor.visit_file(&file);
        Ok(visitor.issues)
    }
}

struct ArithmeticVisitor {
    issues: Vec<ArithmeticIssue>,
}

impl ArithmeticVisitor {
    fn is_div_op(expr: &Expr) -> bool {
        match expr {
            Expr::Binary(eb) => matches!(eb.op, BinOp::Div(_)),
            Expr::Paren(ep) => Self::is_div_op(&ep.expr),
            _ => false,
        }
    }
}

impl<'ast> Visit<'ast> for ArithmeticVisitor {
    fn visit_expr_binary(&mut self, i: &'ast syn::ExprBinary) {
        let line = i.op.span().start().line;

        match i.op {
            // Check for division before multiplication: (a / b) * c
            BinOp::Mul(_) => {
                if Self::is_div_op(&i.left) {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::DivisionBeforeMultiplication,
                        line,
                        snippet: "Division before multiplication detected".to_string(),
                        recommendation: "Perform all multiplications before divisions to maintain maximum precision.".to_string(),
                    });
                }
            }
            // Check for direct arithmetic operators (unchecked)
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Div(_) | BinOp::Rem(_) => {
                if let BinOp::Div(_) = i.op {
                    self.issues.push(ArithmeticIssue {
                        kind: ArithmeticIssueKind::PotentialPrecisionLoss,
                        line,
                        snippet: "Direct division operator used".to_string(),
                        recommendation: "Ensure division doesn't result in zero prematurely or check for remainders.".to_string(),
                    });
                }
            }
            _ => {}
        }

        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_cast(&mut self, i: &'ast syn::ExprCast) {
        let line = i.as_token.span().start().line;
        // Basic check for potentially lossy casts
        let type_name = quote::quote!(#i.ty).to_string();
        if type_name.contains("u64") || type_name.contains("u32") || type_name.contains("u8") {
            self.issues.push(ArithmeticIssue {
                kind: ArithmeticIssueKind::IntegerCastingRisk,
                line,
                snippet: format!("Cast to {}", type_name),
                recommendation: "Use .try_into().map_err(...) instead of 'as' for potentially lossy type conversions.".to_string(),
            });
        }
        visit::visit_expr_cast(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_div_before_mul_detection() {
        let source = r#"
            pub fn calculate_yield(amount: u64, rate: u64, precision: u64) -> u64 {
                let result = (amount / precision) * rate; // Vulnerable: div before mul
                result
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| matches!(i.kind, ArithmeticIssueKind::DivisionBeforeMultiplication)));
    }

    #[test]
    fn test_lossy_cast_detection() {
        let source = r#"
            pub fn process(val: u128) -> u64 {
                let x = val as u64; // Vulnerable: potential truncation
                x
            }
        "#;
        let issues = ArithmeticSecurityExpert::analyze_source(source).unwrap();
        assert!(issues
            .iter()
            .any(|i| matches!(i.kind, ArithmeticIssueKind::IntegerCastingRisk)));
    }
}
