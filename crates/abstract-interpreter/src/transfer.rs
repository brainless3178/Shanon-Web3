use crate::Interval;
use std::collections::HashMap;
use syn::{BinOp, Expr};

pub struct TransferFunctions;

impl TransferFunctions {
    pub fn eval_expr(_expr: &Expr, _state: &HashMap<String, Interval>) -> Interval {
        Interval::u64_range()
    }

    pub fn eval_binop(_op: &BinOp, _left: Interval, _right: Interval) -> Interval {
        Interval::u64_range()
    }
}

pub struct AbstractInterpreter;

impl Default for AbstractInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractInterpreter {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze_source(&self, _source: &str) -> HashMap<String, Interval> {
        HashMap::new()
    }
}
