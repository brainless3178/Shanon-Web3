//! Symbolic Execution Engine with Z3 Backend
//!
//! Provides formal verification capabilities by translating Solana
//! program logic and constraints into Z3 SMT formulae.
//!
//! Features:
//! - Arithmetic overflow/underflow proving
//! - Authority bypass detection via constraint contradiction
//! - Invariant violation counterexample generation
//! - Symbolic state modeling for Solana accounts

use std::collections::HashMap;
use z3::ast::{Ast, Bool, BV};
use z3::{Context, SatResult, Solver};

pub mod constraint_builder;
pub mod exploit_proof;
pub mod solver;
pub mod state_model;

pub use constraint_builder::ConstraintBuilder;
pub use exploit_proof::{
    AccountValidationType, ArithmeticOpType, ExploitProof, ExploitReport, ImpactEstimate,
    VulnerabilityType,
};
pub use solver::SymbolicSolver;
pub use state_model::{
    StateEffect, StateTransition, SymbolicAccount, SymbolicInstructionContext, SymbolicState,
};

/// Main symbolic execution engine
pub struct SymbolicEngine<'ctx> {
    context: &'ctx Context,
    solver: Solver<'ctx>,
    state: SymbolicState<'ctx>,
    invariants: Vec<Bool<'ctx>>,
}

impl<'ctx> SymbolicEngine<'ctx> {
    pub fn new(context: &'ctx Context) -> Self {
        let solver = Solver::new(context);

        Self {
            context,
            solver,
            state: SymbolicState::new(context),
            invariants: Vec::new(),
        }
    }

    /// Initialize symbolic state from account schema
    pub fn init_state_from_schema(&mut self, schema: &AccountSchema) {
        for (field_name, field_type) in &schema.fields {
            let symbolic_var = self.create_symbolic_var(field_name, field_type);
            self.state.add_variable(field_name.clone(), symbolic_var);
        }
    }

    /// Create symbolic variable based on Solana type
    fn create_symbolic_var(&self, name: &str, type_name: &str) -> SymbolicValue<'ctx> {
        match type_name {
            "u64" => SymbolicValue::BitVec(BV::new_const(self.context, name, 64)),
            "u128" => SymbolicValue::BitVec(BV::new_const(self.context, name, 128)),
            "u32" => SymbolicValue::BitVec(BV::new_const(self.context, name, 32)),
            "i64" => SymbolicValue::BitVec(BV::new_const(self.context, name, 64)),
            "bool" => SymbolicValue::Bool(Bool::new_const(self.context, name)),
            "Pubkey" => SymbolicValue::BitVec(BV::new_const(self.context, name, 256)),
            _ => SymbolicValue::BitVec(BV::new_const(self.context, name, 64)),
        }
    }

    /// Add invariant that must hold in all states
    pub fn add_invariant(&mut self, invariant: Bool<'ctx>) {
        self.invariants.push(invariant);
    }

    /// Check if arithmetic overflow is possible
    pub fn check_arithmetic_overflow(
        &mut self,
        operation: ArithmeticOp,
        left: &BV<'ctx>,
        right: &BV<'ctx>,
    ) -> Option<ExploitProof> {
        self.solver.reset();

        let width = left.get_size();
        let max_val: u64 = if width >= 128 {
            u64::MAX
        } else {
            (1u64 << width.min(63)) - 1
        };
        let max_value = BV::from_u64(self.context, max_val, width);

        // Create overflow condition based on operation
        let overflow_condition = match operation {
            ArithmeticOp::Add => {
                // Overflow if: left + right > MAX
                let sum = left.bvadd(right);
                sum.bvugt(&max_value)
            }
            ArithmeticOp::Sub => {
                // Underflow if: left < right
                left.bvult(right)
            }
            ArithmeticOp::Mul => {
                // Overflow if: left * right > MAX
                let product = left.bvmul(right);
                product.bvugt(&max_value)
            }
            ArithmeticOp::Div => {
                // Division by zero if: right == 0
                right._eq(&BV::from_u64(self.context, 0, width))
            }
        };

        self.solver.assert(&overflow_condition);

        if self.solver.check() == SatResult::Sat {
            let _model = self
                .solver
                .get_model()
                .expect("SAT result must have a model");

            // Extract concrete values that trigger overflow
            let left_v = _model.eval(left, true);
            let left_value = left_v.as_ref().and_then(|v| v.as_u64());
            let right_v = _model.eval(right, true);
            let right_value = right_v.as_ref().and_then(|v| v.as_u64());

            Some(
                ExploitProof::new(VulnerabilityType::ArithmeticOverflow(operation.into()))
                    .with_counterexample("left", left_value.unwrap_or(0))
                    .with_counterexample("right", right_value.unwrap_or(0))
                    .with_explanation(&format!("Arithmetic {:?} overflow detected", operation))
                    .with_mitigation("Use checked math operations or Anchor's checked arithmetic"),
            )
        } else {
            None
        }
    }

    /// Check if authority bypass is possible
    pub fn check_authority_bypass(
        &mut self,
        required_signer: &BV<'ctx>,
        actual_signer: &BV<'ctx>,
        constraints: &[Bool<'ctx>],
    ) -> Option<ExploitProof> {
        self.solver.reset();

        // Add all existing constraints
        for constraint in constraints {
            self.solver.assert(constraint);
        }

        // Check if signer can be different from required authority
        let bypass_condition = required_signer._eq(actual_signer).not();
        self.solver.assert(&bypass_condition);

        if self.solver.check() == SatResult::Sat {
            let _model = self
                .solver
                .get_model()
                .expect("SAT result must have a model");

            Some(ExploitProof::new(VulnerabilityType::AuthorityBypass)
                .with_explanation("Potential authority bypass detected: required signer can be different from actual signer")
                .with_mitigation("Ensure all sensitive operations strictly validate the signer's identity against the expected authority")
                .with_severity(9))
        } else {
            None
        }
    }

    /// Check if any invariant can be violated
    pub fn check_invariant_violations(&mut self) -> Vec<ExploitProof> {
        let mut exploits = Vec::new();

        for (idx, invariant) in self.invariants.iter().enumerate() {
            self.solver.reset();

            // Try to violate the invariant
            self.solver.assert(&invariant.not());

            if self.solver.check() == SatResult::Sat {
                let _model = self
                    .solver
                    .get_model()
                    .expect("SAT result must have a model");

                exploits.push(ExploitProof::new(VulnerabilityType::InvariantViolation(idx))
                    .with_explanation(&format!("Invariant #{} can be violated under specific state conditions", idx))
                    .with_mitigation("Review program logic to ensure the invariant is preserved across all state transitions")
                    .with_severity(7));
            }
        }

        exploits
    }

    /// Check if a custom logic invariant can be violated
    /// This supports strings like "balance_a <= total_balance"
    pub fn check_logic_invariant(&mut self, property: &str) -> Option<ExploitProof> {
        self.solver.reset();

        // Simple parser for property strings
        let (left_var, op, right_var) = if property.contains("<=") {
            let parts: Vec<&str> = property.split("<=").collect();
            (parts[0].trim(), "<=", parts[1].trim())
        } else if property.contains("==") {
            let parts: Vec<&str> = property.split("==").collect();
            (parts[0].trim(), "==", parts[1].trim())
        } else {
            return None;
        };

        let left_bv = match self.state.get_variable(left_var) {
            Some(SymbolicValue::BitVec(bv)) => bv,
            _ => return None,
        };

        let right_bv = match self.state.get_variable(right_var) {
            Some(SymbolicValue::BitVec(bv)) => bv,
            _ => return None,
        };

        // We want to prove the property is VIOLABLE, so we assert the NEGATION
        let violation_condition = match op {
            "<=" => left_bv.bvugt(right_bv),
            "==" => left_bv._eq(right_bv).not(),
            _ => return None,
        };

        self.solver.assert(&violation_condition);

        if self.solver.check() == SatResult::Sat {
            let _model = self
                .solver
                .get_model()
                .expect("SAT result must have a model");

            Some(
                ExploitProof::new(VulnerabilityType::InvariantViolation(100))
                    .with_counterexample(
                        left_var,
                        _model
                            .eval(left_bv, true)
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    )
                    .with_counterexample(
                        right_var,
                        _model
                            .eval(right_bv, true)
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    )
                    .with_explanation(&format!("Logic invariant violation: {}", property))
                    .with_mitigation(
                        "Add explicit checks to enforce this logic invariant in the program code",
                    )
                    .with_severity(6),
            )
        } else {
            None
        }
    }

    /// High-level exploit proving entry point
    pub fn prove_exploitability(
        &mut self,
        instruction_name: &str,
        vulcan_id: &str,
        program_id: &str,
    ) -> Option<ExploitProof> {
        let solver = SymbolicSolver::new(self.context);

        if vulcan_id.contains("SOL-019") {
            solver.prove_oracle_manipulation(instruction_name, program_id)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug)]
pub enum SymbolicValue<'ctx> {
    BitVec(BV<'ctx>),
    Bool(Bool<'ctx>),
}

pub struct AccountSchema {
    pub name: String,
    pub fields: HashMap<String, String>,
}

// Map ArithmeticOp to ArithmeticOpType for ExploitProof
impl From<ArithmeticOp> for exploit_proof::ArithmeticOpType {
    fn from(op: ArithmeticOp) -> Self {
        match op {
            ArithmeticOp::Add => exploit_proof::ArithmeticOpType::Add,
            ArithmeticOp::Sub => exploit_proof::ArithmeticOpType::Sub,
            ArithmeticOp::Mul => exploit_proof::ArithmeticOpType::Mul,
            ArithmeticOp::Div => exploit_proof::ArithmeticOpType::Div,
        }
    }
}
