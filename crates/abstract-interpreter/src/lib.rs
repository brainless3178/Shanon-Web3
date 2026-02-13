//! Abstract Interpretation Engine for Solana Programs
//!
//! Performs sound numerical analysis using interval domains to
//! compute guaranteed bounds on program values. Essential for
//! proving absence of overflow/underflow.
//!
//! This engine uses abstract interpretation over the AST to track
//! variables as intervals [min, max], allowing the auditor to prove
//! that certain arithmetic operations can never fail.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Add, Div, Mul, Sub};
use syn::{visit::Visit, BinOp, Expr, ItemFn, Lit};

pub mod domains;
pub mod transfer;

/// Represents a numeric interval [min, max]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub min: i128,
    pub max: i128,
}

impl Interval {
    pub fn new(min: i128, max: i128) -> Self {
        assert!(min <= max, "Invalid interval: min > max");
        Self { min, max }
    }

    /// Create interval for a single value
    pub fn singleton(value: i128) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    /// Create the bottom element (empty interval)
    pub fn bottom() -> Self {
        Self { min: 1, max: 0 } // Invalid interval represents bottom
    }

    /// Create interval for u64 range
    pub fn u64_range() -> Self {
        Self {
            min: 0,
            max: u64::MAX as i128,
        }
    }

    /// Create interval for u128 range (capped for practicality)
    pub fn u128_range() -> Self {
        Self {
            min: 0,
            max: i128::MAX,
        }
    }

    /// Check if this is the bottom element
    pub fn is_bottom(&self) -> bool {
        self.min > self.max
    }

    /// Check if the interval contains a value
    pub fn contains(&self, value: i128) -> bool {
        !self.is_bottom() && value >= self.min && value <= self.max
    }

    /// Check if the interval might overflow u64
    pub fn might_overflow_u64(&self) -> bool {
        self.max > u64::MAX as i128 || self.min < 0
    }

    /// Check if the interval might underflow (go negative)
    pub fn might_underflow(&self) -> bool {
        self.min < 0
    }

    /// Join (least upper bound) of two intervals
    pub fn join(&self, other: &Interval) -> Interval {
        if self.is_bottom() {
            return *other;
        }
        if other.is_bottom() {
            return *self;
        }
        Interval {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }

    /// Meet (greatest lower bound) of two intervals
    pub fn meet(&self, other: &Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() {
            return Interval::bottom();
        }
        let min = self.min.max(other.min);
        let max = self.max.min(other.max);
        if min > max {
            Interval::bottom()
        } else {
            Interval { min, max }
        }
    }

    /// Widen operator for ensuring termination
    pub fn widen(&self, other: &Interval) -> Interval {
        if self.is_bottom() {
            return *other;
        }
        if other.is_bottom() {
            return *self;
        }

        let min = if other.min < self.min {
            i128::MIN / 2 // Widen to negative infinity (bounded)
        } else {
            self.min
        };

        let max = if other.max > self.max {
            i128::MAX / 2 // Widen to positive infinity (bounded)
        } else {
            self.max
        };

        Interval { min, max }
    }

    /// Narrow operator for improving precision
    pub fn narrow(&self, other: &Interval) -> Interval {
        if self.is_bottom() {
            return Interval::bottom();
        }
        if other.is_bottom() {
            return *self;
        }

        let min = if self.min == i128::MIN / 2 {
            other.min
        } else {
            self.min
        };

        let max = if self.max == i128::MAX / 2 {
            other.max
        } else {
            self.max
        };

        Interval { min, max }
    }
}

// Interval arithmetic operations
impl Add for Interval {
    type Output = Interval;

    fn add(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() {
            return Interval::bottom();
        }
        Interval {
            min: self.min.saturating_add(other.min),
            max: self.max.saturating_add(other.max),
        }
    }
}

impl Sub for Interval {
    type Output = Interval;

    fn sub(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() {
            return Interval::bottom();
        }
        Interval {
            min: self.min.saturating_sub(other.max),
            max: self.max.saturating_sub(other.min),
        }
    }
}

impl Mul for Interval {
    type Output = Interval;

    fn mul(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() {
            return Interval::bottom();
        }

        // Consider all four corner cases
        let products = [
            self.min.saturating_mul(other.min),
            self.min.saturating_mul(other.max),
            self.max.saturating_mul(other.min),
            self.max.saturating_mul(other.max),
        ];

        Interval {
            min: *products
                .iter()
                .min()
                .expect("Fixed size array is never empty"),
            max: *products
                .iter()
                .max()
                .expect("Fixed size array is never empty"),
        }
    }
}

impl Div for Interval {
    type Output = Interval;

    fn div(self, other: Interval) -> Interval {
        if self.is_bottom() || other.is_bottom() {
            return Interval::bottom();
        }

        // Handle division by zero
        if other.contains(0) {
            // Conservative: could be anything
            return Interval::u128_range();
        }

        let quotients = [
            self.min.saturating_div(other.min),
            self.min.saturating_div(other.max),
            self.max.saturating_div(other.min),
            self.max.saturating_div(other.max),
        ];

        Interval {
            min: *quotients
                .iter()
                .min()
                .expect("Fixed size array is never empty"),
            max: *quotients
                .iter()
                .max()
                .expect("Fixed size array is never empty"),
        }
    }
}

/// Abstract state mapping variables to intervals
#[derive(Debug, Clone, Default)]
pub struct AbstractState {
    pub intervals: HashMap<String, Interval>,
}

impl AbstractState {
    pub fn new() -> Self {
        Self {
            intervals: HashMap::new(),
        }
    }

    /// Get interval for a variable (returns u64_range if unknown)
    pub fn get(&self, var: &str) -> Interval {
        self.intervals
            .get(var)
            .copied()
            .unwrap_or(Interval::u64_range())
    }

    /// Set interval for a variable
    pub fn set(&mut self, var: String, interval: Interval) {
        self.intervals.insert(var, interval);
    }

    /// Join two abstract states
    pub fn join(&self, other: &AbstractState) -> AbstractState {
        let mut result = AbstractState::new();

        // Join all variables from both states
        for (var, interval) in &self.intervals {
            let other_interval = other.get(var);
            result.set(var.clone(), interval.join(&other_interval));
        }

        for (var, interval) in &other.intervals {
            if !result.intervals.contains_key(var) {
                result.set(var.clone(), self.get(var).join(interval));
            }
        }

        result
    }

    /// Widen two abstract states
    pub fn widen(&self, other: &AbstractState) -> AbstractState {
        let mut result = AbstractState::new();

        for (var, interval) in &self.intervals {
            let other_interval = other.get(var);
            result.set(var.clone(), interval.widen(&other_interval));
        }

        for (var, interval) in &other.intervals {
            if !result.intervals.contains_key(var) {
                result.set(var.clone(), *interval);
            }
        }

        result
    }
}

/// Result of overflow analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverflowAnalysis {
    pub location: String,
    pub operation: String,
    pub left_interval: (i128, i128),
    pub right_interval: (i128, i128),
    pub result_interval: (i128, i128),
    pub can_overflow: bool,
    pub can_underflow: bool,
    pub severity: OverflowSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverflowSeverity {
    Safe,       // Cannot overflow
    Possible,   // Might overflow with extreme inputs
    Likely,     // Will overflow with common inputs
    Guaranteed, // Always overflows
}

/// Main abstract interpreter
pub struct AbstractInterpreter {
    state: AbstractState,
    findings: Vec<OverflowAnalysis>,
    current_function: String,
    filename: String,
}

impl AbstractInterpreter {
    pub fn new() -> Self {
        Self {
            state: AbstractState::new(),
            findings: Vec::new(),
            current_function: String::new(),
            filename: String::new(),
        }
    }

    /// Analyze a Rust source file
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<Vec<OverflowAnalysis>, AbstractError> {
        self.filename = filename.to_string();

        let file = syn::parse_file(source).map_err(|e| AbstractError::ParseError(e.to_string()))?;

        self.visit_file(&file);

        Ok(self.findings.clone())
    }

    /// Evaluate an expression to an interval
    pub fn eval_expr(&mut self, expr: &Expr) -> Interval {
        match expr {
            // Literal values
            Expr::Lit(lit_expr) => match &lit_expr.lit {
                Lit::Int(lit_int) => {
                    if let Ok(value) = lit_int.base10_parse::<i128>() {
                        Interval::singleton(value)
                    } else {
                        Interval::u128_range()
                    }
                }
                _ => Interval::u128_range(),
            },

            // Variable reference
            Expr::Path(path) => {
                if let Some(ident) = path.path.get_ident() {
                    self.state.get(&ident.to_string())
                } else {
                    Interval::u64_range()
                }
            }

            // Binary operations
            Expr::Binary(binary) => {
                let left = self.eval_expr(&binary.left);
                let right = self.eval_expr(&binary.right);

                let result = match binary.op {
                    BinOp::Add(_) => left + right,
                    BinOp::Sub(_) => left - right,
                    BinOp::Mul(_) => left * right,
                    BinOp::Div(_) => left / right,
                    BinOp::Rem(_) => {
                        if right.min > 0 {
                            Interval::new(0, right.max - 1)
                        } else {
                            Interval::u64_range()
                        }
                    }
                    BinOp::BitAnd(_) => {
                        // x & y is in [0, min(max(x), max(y))]
                        Interval::new(0, left.max.min(right.max))
                    }
                    BinOp::BitOr(_) => {
                        // Approximation
                        Interval::new(left.min.max(right.min), left.max.max(right.max))
                    }
                    BinOp::Shl(_) => {
                        // Shift left
                        if right.max < 64 && right.min >= 0 {
                            Interval::new(
                                left.min.saturating_mul(1 << right.min),
                                left.max.saturating_mul(1 << right.max),
                            )
                        } else {
                            Interval::u128_range()
                        }
                    }
                    BinOp::Shr(_) => {
                        // Shift right
                        if right.max < 64 && right.min >= 0 {
                            Interval::new(left.min >> right.max, left.max >> right.min)
                        } else {
                            Interval::new(0, left.max)
                        }
                    }
                    _ => Interval::u64_range(),
                };

                // Check for overflow
                self.check_overflow(&binary.op, &left, &right, &result);

                result
            }

            // Method calls
            Expr::MethodCall(method_call) => {
                let receiver = self.eval_expr(&method_call.receiver);
                let method = method_call.method.to_string();

                match method.as_str() {
                    // Checked arithmetic returns Some/None
                    "checked_add" | "checked_sub" | "checked_mul" | "checked_div" => {
                        // Result is bounded by the operation
                        if !method_call.args.is_empty() {
                            let arg = self.eval_expr(&method_call.args[0]);
                            match method.as_str() {
                                "checked_add" => receiver + arg,
                                "checked_sub" => receiver - arg,
                                "checked_mul" => receiver * arg,
                                "checked_div" => receiver / arg,
                                _ => Interval::u64_range(),
                            }
                        } else {
                            Interval::u64_range()
                        }
                    }

                    // Saturating arithmetic
                    "saturating_add" => {
                        if !method_call.args.is_empty() {
                            let arg = self.eval_expr(&method_call.args[0]);
                            Interval::new(
                                (receiver.min + arg.min).min(u64::MAX as i128),
                                (receiver.max + arg.max).min(u64::MAX as i128),
                            )
                        } else {
                            Interval::u64_range()
                        }
                    }
                    "saturating_sub" => {
                        if !method_call.args.is_empty() {
                            let arg = self.eval_expr(&method_call.args[0]);
                            Interval::new(
                                (receiver.min - arg.max).max(0),
                                (receiver.max - arg.min).max(0),
                            )
                        } else {
                            Interval::u64_range()
                        }
                    }

                    // Min/max
                    "min" => {
                        if !method_call.args.is_empty() {
                            let arg = self.eval_expr(&method_call.args[0]);
                            Interval::new(receiver.min.min(arg.min), receiver.max.min(arg.max))
                        } else {
                            receiver
                        }
                    }
                    "max" => {
                        if !method_call.args.is_empty() {
                            let arg = self.eval_expr(&method_call.args[0]);
                            Interval::new(receiver.min.max(arg.min), receiver.max.max(arg.max))
                        } else {
                            receiver
                        }
                    }

                    _ => Interval::u64_range(),
                }
            }

            // Cast expressions
            Expr::Cast(cast) => {
                let inner = self.eval_expr(&cast.expr);
                let ty_str = quote::quote!(#cast.ty).to_string();

                // Apply type bounds
                if ty_str.contains("u8") {
                    Interval::new(inner.min.max(0), inner.max.min(255))
                } else if ty_str.contains("u16") {
                    Interval::new(inner.min.max(0), inner.max.min(65535))
                } else if ty_str.contains("u32") {
                    Interval::new(inner.min.max(0), inner.max.min(u32::MAX as i128))
                } else if ty_str.contains("u64") {
                    Interval::new(inner.min.max(0), inner.max.min(u64::MAX as i128))
                } else {
                    inner
                }
            }

            // Parenthesized expression
            Expr::Paren(paren) => self.eval_expr(&paren.expr),

            // Reference
            Expr::Reference(reference) => self.eval_expr(&reference.expr),

            // Unary operations
            Expr::Unary(unary) => {
                let inner = self.eval_expr(&unary.expr);
                match unary.op {
                    syn::UnOp::Neg(_) => Interval::new(-inner.max, -inner.min),
                    syn::UnOp::Not(_) => {
                        // Bitwise not
                        if inner.max <= u64::MAX as i128 && inner.min >= 0 {
                            Interval::new(!(inner.max as u64) as i128, !(inner.min as u64) as i128)
                        } else {
                            Interval::u64_range()
                        }
                    }
                    _ => inner,
                }
            }

            _ => Interval::u64_range(),
        }
    }

    /// Check for potential overflow in an arithmetic operation
    fn check_overflow(&mut self, op: &BinOp, left: &Interval, right: &Interval, result: &Interval) {
        let location = format!("{}::{}", self.filename, self.current_function);
        let op_str = match op {
            BinOp::Add(_) => "Add",
            BinOp::Sub(_) => "Sub",
            BinOp::Mul(_) => "Mul",
            BinOp::Div(_) => "Div",
            _ => return,
        };

        let can_overflow = result.might_overflow_u64();
        let can_underflow = result.might_underflow();

        if can_overflow || can_underflow {
            let severity = if result.min > u64::MAX as i128 || result.max < 0 {
                OverflowSeverity::Guaranteed
            } else if can_overflow && can_underflow {
                OverflowSeverity::Likely
            } else {
                OverflowSeverity::Possible
            };

            self.findings.push(OverflowAnalysis {
                location,
                operation: op_str.to_string(),
                left_interval: (left.min, left.max),
                right_interval: (right.min, right.max),
                result_interval: (result.min, result.max),
                can_overflow,
                can_underflow,
                severity,
            });
        }
    }

    /// Get analysis findings
    pub fn get_findings(&self) -> &[OverflowAnalysis] {
        &self.findings
    }

    /// Analyze a specific expression with given variable bounds
    pub fn analyze_with_bounds(
        &mut self,
        expr: &str,
        bounds: HashMap<String, (i128, i128)>,
    ) -> Result<Interval, AbstractError> {
        // Set up state with provided bounds
        for (var, (min, max)) in bounds {
            self.state.set(var, Interval::new(min, max));
        }

        // Parse and evaluate expression
        let expr: Expr =
            syn::parse_str(expr).map_err(|e| AbstractError::ParseError(e.to_string()))?;

        Ok(self.eval_expr(&expr))
    }
}

impl Default for AbstractInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl<'ast> Visit<'ast> for AbstractInterpreter {
    fn visit_item_fn(&mut self, func: &'ast ItemFn) {
        self.current_function = func.sig.ident.to_string();

        // Initialize parameter bounds
        for param in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    let param_name = pat_ident.ident.to_string();
                    let ty_str = quote::quote!(#pat_type.ty).to_string();

                    // Set type-based bounds
                    let interval = if ty_str.contains("u8") {
                        Interval::new(0, 255)
                    } else if ty_str.contains("u16") {
                        Interval::new(0, 65535)
                    } else if ty_str.contains("u32") {
                        Interval::new(0, u32::MAX as i128)
                    } else if ty_str.contains("u64") {
                        Interval::u64_range()
                    } else if ty_str.contains("i64") {
                        Interval::new(i64::MIN as i128, i64::MAX as i128)
                    } else {
                        Interval::u64_range()
                    };

                    self.state.set(param_name, interval);
                }
            }
        }

        syn::visit::visit_item_fn(self, func);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        // Handle variable definitions
        if let syn::Pat::Ident(pat_ident) = &local.pat {
            let var_name = pat_ident.ident.to_string();

            if let Some(init) = &local.init {
                let interval = self.eval_expr(&init.expr);
                self.state.set(var_name, interval);
            }
        }

        syn::visit::visit_local(self, local);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        // Evaluate all expressions to find overflows
        self.eval_expr(expr);
        syn::visit::visit_expr(self, expr);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AbstractError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_arithmetic() {
        let a = Interval::new(10, 20);
        let b = Interval::new(5, 15);

        let sum = a + b;
        assert_eq!(sum.min, 15);
        assert_eq!(sum.max, 35);

        let diff = a - b;
        assert_eq!(diff.min, -5);
        assert_eq!(diff.max, 15);
    }

    #[test]
    fn test_overflow_detection() {
        let a = Interval::new(u64::MAX as i128 - 10, u64::MAX as i128);
        let b = Interval::new(100, 200);

        let sum = a + b;
        assert!(sum.might_overflow_u64());
    }

    #[test]
    fn test_interval_join() {
        let a = Interval::new(10, 20);
        let b = Interval::new(15, 30);

        let joined = a.join(&b);
        assert_eq!(joined.min, 10);
        assert_eq!(joined.max, 30);
    }
}
