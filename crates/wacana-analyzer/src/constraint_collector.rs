//! Path constraint collector for concolic execution.
//!
//! Maintains symbolic variables alongside concrete values and collects
//! path constraints at branch points for later Z3 solving.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use z3::ast::{Ast, Bool, Int};
use z3::{Config, Context, SatResult, Solver};

/// A symbolic variable tracked during concolic execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicVar {
    /// Variable name (e.g. "param_0", "local_3", "mem_0x100").
    pub name: String,
    /// Concrete value observed during execution.
    pub concrete_value: i64,
    /// Bit width (32 or 64).
    pub bit_width: u32,
    /// Whether this is user-controlled input.
    pub is_input: bool,
    /// Origin (parameter, local, memory load, global).
    pub origin: VarOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VarOrigin {
    Parameter(u32),
    Local(u32),
    MemoryLoad { address: u64 },
    Global(u32),
    Computed,
}

/// A path constraint collected at a branch point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConstraint {
    /// The constraint expression (serialized for reporting).
    pub expression: String,
    /// Whether this branch was taken in the concrete run.
    pub taken: bool,
    /// Location in the program (function:offset).
    pub location: String,
    /// Variables involved in this constraint.
    pub variables: Vec<String>,
    /// Constraint kind.
    pub kind: ConstraintKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintKind {
    Comparison {
        op: CmpOp,
        left: String,
        right: String,
    },
    EqualZero {
        operand: String,
    },
    NotEqualZero {
        operand: String,
    },
    BoundsCheck {
        address: String,
        size: String,
        bound: String,
    },
    DivisionCheck {
        divisor: String,
    },
    Custom(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LtU,
    LeU,
    GtU,
    GeU,
}

/// Constraint collector — the symbolic shadow alongside concrete execution.
pub struct ConstraintCollector {
    /// Mapping from variable name to symbolic variable.
    variables: HashMap<String, SymbolicVar>,
    /// Collected path constraints.
    constraints: Vec<PathConstraint>,
    /// Maximum constraints to collect per path.
    max_constraints: usize,
}

impl ConstraintCollector {
    pub fn new(max_constraints: usize) -> Self {
        Self {
            variables: HashMap::new(),
            constraints: Vec::new(),
            max_constraints,
        }
    }

    /// Register a new symbolic variable.
    pub fn register_variable(
        &mut self,
        name: String,
        concrete_value: i64,
        bit_width: u32,
        is_input: bool,
        origin: VarOrigin,
    ) {
        self.variables.insert(
            name.clone(),
            SymbolicVar {
                name,
                concrete_value,
                bit_width,
                is_input,
                origin,
            },
        );
    }

    /// Record a comparison path constraint at a branch point.
    pub fn add_comparison_constraint(
        &mut self,
        op: CmpOp,
        left_name: &str,
        right_name: &str,
        taken: bool,
        location: String,
    ) {
        if self.constraints.len() >= self.max_constraints {
            return;
        }

        let expression = format!("{} {:?} {}", left_name, op, right_name);
        self.constraints.push(PathConstraint {
            expression,
            taken,
            location,
            variables: vec![left_name.to_string(), right_name.to_string()],
            kind: ConstraintKind::Comparison {
                op,
                left: left_name.to_string(),
                right: right_name.to_string(),
            },
        });
    }

    /// Record an equal-zero branch constraint.
    pub fn add_eqz_constraint(&mut self, operand_name: &str, taken: bool, location: String) {
        if self.constraints.len() >= self.max_constraints {
            return;
        }

        let expression = format!("{} == 0", operand_name);
        self.constraints.push(PathConstraint {
            expression,
            taken,
            location,
            variables: vec![operand_name.to_string()],
            kind: ConstraintKind::EqualZero {
                operand: operand_name.to_string(),
            },
        });
    }

    /// Record a bounds check constraint (for memory safety).
    pub fn add_bounds_constraint(
        &mut self,
        address_name: &str,
        size: &str,
        bound: &str,
        taken: bool,
        location: String,
    ) {
        if self.constraints.len() >= self.max_constraints {
            return;
        }

        let expression = format!("{} + {} <= {}", address_name, size, bound);
        self.constraints.push(PathConstraint {
            expression,
            taken,
            location,
            variables: vec![address_name.to_string()],
            kind: ConstraintKind::BoundsCheck {
                address: address_name.to_string(),
                size: size.to_string(),
                bound: bound.to_string(),
            },
        });
    }

    /// Record a division-by-zero guard constraint.
    pub fn add_div_check_constraint(&mut self, divisor_name: &str, taken: bool, location: String) {
        if self.constraints.len() >= self.max_constraints {
            return;
        }

        let expression = format!("{} != 0", divisor_name);
        self.constraints.push(PathConstraint {
            expression,
            taken,
            location,
            variables: vec![divisor_name.to_string()],
            kind: ConstraintKind::DivisionCheck {
                divisor: divisor_name.to_string(),
            },
        });
    }

    /// Get all collected constraints.
    pub fn get_constraints(&self) -> &[PathConstraint] {
        &self.constraints
    }

    /// Get a variable by name.
    pub fn get_variable(&self, name: &str) -> Option<&SymbolicVar> {
        self.variables.get(name)
    }

    /// Get all registered variables.
    pub fn get_variables(&self) -> &HashMap<String, SymbolicVar> {
        &self.variables
    }

    /// Clear all constraints (for new path exploration).
    pub fn clear_constraints(&mut self) {
        self.constraints.clear();
    }

    /// Clone the current state.
    pub fn fork(&self) -> Self {
        Self {
            variables: self.variables.clone(),
            constraints: self.constraints.clone(),
            max_constraints: self.max_constraints,
        }
    }

    /// Negate the last constraint and solve for new inputs using Z3.
    ///
    /// Returns `Some(new_concrete_values)` if satisfiable, `None` otherwise.
    pub fn solve_negated_last(&self, timeout_ms: u64) -> Option<HashMap<String, i64>> {
        if self.constraints.is_empty() {
            return None;
        }

        let mut cfg = Config::new();
        cfg.set_timeout_msec(timeout_ms);
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        // Add all constraints except the last as-is, negate the last
        for (i, constraint) in self.constraints.iter().enumerate() {
            let is_last = i == self.constraints.len() - 1;
            let taken = if is_last {
                !constraint.taken
            } else {
                constraint.taken
            };

            if let Some(z3_constraint) = self.constraint_to_z3(&ctx, constraint, taken) {
                solver.assert(&z3_constraint);
            }
        }

        // Check satisfiability
        if solver.check() == SatResult::Sat {
            if let Some(model) = solver.get_model() {
                let mut values = HashMap::new();
                for (name, var) in &self.variables {
                    if !var.is_input {
                        continue;
                    }
                    let z3_var = Int::new_const(&ctx, name.as_str());
                    if let Some(val) = model.eval(&z3_var, true) {
                        if let Some(i) = val.as_i64() {
                            values.insert(name.clone(), i);
                        }
                    }
                }
                if !values.is_empty() {
                    return Some(values);
                }
            }
        }

        None
    }

    /// Solve all constraints at a specific negation point (for systematic path exploration).
    pub fn solve_negated_at(&self, index: usize, timeout_ms: u64) -> Option<HashMap<String, i64>> {
        if index >= self.constraints.len() {
            return None;
        }

        let mut cfg = Config::new();
        cfg.set_timeout_msec(timeout_ms);
        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);

        // Add constraints: keep [0..index) as-is, negate [index], ignore [index+1..)
        for (i, constraint) in self.constraints.iter().enumerate() {
            if i > index {
                break;
            }
            let taken = if i == index {
                !constraint.taken
            } else {
                constraint.taken
            };
            if let Some(z3_constraint) = self.constraint_to_z3(&ctx, constraint, taken) {
                solver.assert(&z3_constraint);
            }
        }

        if solver.check() == SatResult::Sat {
            if let Some(model) = solver.get_model() {
                let mut values = HashMap::new();
                for (name, var) in &self.variables {
                    if !var.is_input {
                        continue;
                    }
                    let z3_var = Int::new_const(&ctx, name.as_str());
                    if let Some(val) = model.eval(&z3_var, true) {
                        if let Some(i) = val.as_i64() {
                            values.insert(name.clone(), i);
                        }
                    }
                }
                if !values.is_empty() {
                    return Some(values);
                }
            }
        }

        None
    }

    /// Translate a PathConstraint into a Z3 Bool.
    fn constraint_to_z3<'ctx>(
        &self,
        ctx: &'ctx Context,
        constraint: &PathConstraint,
        taken: bool,
    ) -> Option<Bool<'ctx>> {
        let z3_expr = match &constraint.kind {
            ConstraintKind::Comparison { op, left, right } => {
                let l = Int::new_const(ctx, left.as_str());
                let r = if let Ok(val) = right.parse::<i64>() {
                    Int::from_i64(ctx, val)
                } else {
                    Int::new_const(ctx, right.as_str())
                };

                Some(match op {
                    CmpOp::Eq => l._eq(&r),
                    CmpOp::Ne => l._eq(&r).not(),
                    CmpOp::Lt | CmpOp::LtU => l.lt(&r),
                    CmpOp::Le | CmpOp::LeU => l.le(&r),
                    CmpOp::Gt | CmpOp::GtU => l.gt(&r),
                    CmpOp::Ge | CmpOp::GeU => l.ge(&r),
                })
            }
            ConstraintKind::EqualZero { operand } => {
                let var = Int::new_const(ctx, operand.as_str());
                let zero = Int::from_i64(ctx, 0);
                Some(var._eq(&zero))
            }
            ConstraintKind::NotEqualZero { operand } => {
                let var = Int::new_const(ctx, operand.as_str());
                let zero = Int::from_i64(ctx, 0);
                Some(var._eq(&zero).not())
            }
            ConstraintKind::BoundsCheck {
                address,
                size,
                bound,
            } => {
                let addr = Int::new_const(ctx, address.as_str());
                let sz = if let Ok(val) = size.parse::<i64>() {
                    Int::from_i64(ctx, val)
                } else {
                    Int::new_const(ctx, size.as_str())
                };
                let bnd = if let Ok(val) = bound.parse::<i64>() {
                    Int::from_i64(ctx, val)
                } else {
                    Int::new_const(ctx, bound.as_str())
                };
                // addr + size <= bound
                let sum = Int::add(ctx, &[&addr, &sz]);
                Some(sum.le(&bnd))
            }
            ConstraintKind::DivisionCheck { divisor } => {
                let var = Int::new_const(ctx, divisor.as_str());
                let zero = Int::from_i64(ctx, 0);
                Some(var._eq(&zero).not())
            }
            ConstraintKind::Custom(_) => None,
        };

        z3_expr.map(|expr| if taken { expr } else { expr.not() })
    }
}
