//! Constraint Builder for Symbolic Execution
//!
//! Builds Z3 constraints from Solana program patterns and security checks.

use std::collections::HashMap;
use z3::ast::{Ast, Bool, BV};
use z3::Context;

pub struct ConstraintBuilder<'ctx> {
    context: &'ctx Context,
    /// Named constraints for debugging
    named_constraints: HashMap<String, Bool<'ctx>>,
}

impl<'ctx> ConstraintBuilder<'ctx> {
    pub fn new(context: &'ctx Context) -> Self {
        Self {
            context,
            named_constraints: HashMap::new(),
        }
    }

    /// Build overflow constraint for addition
    /// Returns true if overflow would occur
    pub fn build_add_overflow_constraint(&self, left: &BV<'ctx>, right: &BV<'ctx>) -> Bool<'ctx> {
        // Unsigned overflow: result wrapped around (sum < left)
        let sum = left.bvadd(right);
        sum.bvult(left)
    }

    /// Build underflow constraint for subtraction
    /// Returns true if underflow would occur
    pub fn build_sub_underflow_constraint(&self, left: &BV<'ctx>, right: &BV<'ctx>) -> Bool<'ctx> {
        // Unsigned underflow: left < right
        left.bvult(right)
    }

    /// Build overflow constraint for multiplication
    pub fn build_mul_overflow_constraint(&self, left: &BV<'ctx>, right: &BV<'ctx>) -> Bool<'ctx> {
        left.bvmul_no_overflow(right, false).not()
    }

    /// Build division by zero constraint
    pub fn build_div_by_zero_constraint(&self, divisor: &BV<'ctx>) -> Bool<'ctx> {
        let zero = BV::from_u64(self.context, 0, divisor.get_size());
        divisor._eq(&zero)
    }

    /// Build authority check constraint
    /// Returns true if authority can be bypassed (signer != expected_authority)
    pub fn build_authority_bypass_constraint(
        &self,
        expected_authority: &BV<'ctx>,
        actual_signer: &BV<'ctx>,
    ) -> Bool<'ctx> {
        expected_authority._eq(actual_signer).not()
    }

    /// Build PDA derivation mismatch constraint
    pub fn build_pda_mismatch_constraint(
        &self,
        expected_pda: &BV<'ctx>,
        provided_pda: &BV<'ctx>,
    ) -> Bool<'ctx> {
        expected_pda._eq(provided_pda).not()
    }

    /// Build account owner check constraint
    /// Returns true if owner is not the expected program
    pub fn build_owner_check_constraint(
        &self,
        account_owner: &BV<'ctx>,
        expected_program: &BV<'ctx>,
    ) -> Bool<'ctx> {
        account_owner._eq(expected_program).not()
    }

    /// Build balance conservation constraint
    /// total_in <= total_out (no value lost)
    pub fn build_balance_conservation(
        &self,
        inputs: &[&BV<'ctx>],
        outputs: &[&BV<'ctx>],
    ) -> Bool<'ctx> {
        let width = inputs.first().map(|bv| bv.get_size()).unwrap_or(64);

        // Sum all inputs
        let mut total_in = BV::from_u64(self.context, 0, width);
        for input in inputs {
            total_in = total_in.bvadd(input);
        }

        // Sum all outputs
        let mut total_out = BV::from_u64(self.context, 0, width);
        for output in outputs {
            total_out = total_out.bvadd(output);
        }

        // Conservation: total_out <= total_in (no value extracted from nowhere)
        total_out.bvule(&total_in)
    }

    /// Build reentrancy guard constraint
    /// Ensures state is locked before external calls
    pub fn build_reentrancy_guard(&self, is_locked: &Bool<'ctx>) -> Bool<'ctx> {
        // Safe if locked before call
        is_locked.clone()
    }

    /// Build mint authority check
    pub fn build_mint_authority_constraint(
        &self,
        mint_authority: &BV<'ctx>,
        expected_authority: &BV<'ctx>,
    ) -> Bool<'ctx> {
        mint_authority._eq(expected_authority)
    }

    /// Build freeze authority check
    pub fn build_freeze_authority_constraint(
        &self,
        freeze_authority: &BV<'ctx>,
        expected_authority: &BV<'ctx>,
    ) -> Bool<'ctx> {
        freeze_authority._eq(expected_authority)
    }

    /// Build slippage protection constraint
    /// Returns true if slippage is within acceptable range
    pub fn build_slippage_constraint(
        &self,
        expected_amount: &BV<'ctx>,
        actual_amount: &BV<'ctx>,
        max_slippage_bps: u64, // basis points (100 = 1%)
    ) -> Bool<'ctx> {
        let width = expected_amount.get_size();
        let basis_points = BV::from_u64(self.context, 10000, width);
        let max_slippage = BV::from_u64(self.context, max_slippage_bps, width);

        // min_acceptable = expected * (10000 - max_slippage) / 10000
        let tolerance = expected_amount.bvmul(&max_slippage).bvudiv(&basis_points);
        let min_acceptable = expected_amount.bvsub(&tolerance);

        // actual >= min_acceptable
        actual_amount.bvuge(&min_acceptable)
    }

    /// Build liquidity ratio constraint for AMM safety
    pub fn build_liquidity_ratio_constraint(
        &self,
        reserve_a: &BV<'ctx>,
        reserve_b: &BV<'ctx>,
        min_ratio: u64,
        max_ratio: u64,
    ) -> Bool<'ctx> {
        let width = reserve_a.get_size();
        let scaling = BV::from_u64(self.context, 1000000, width); // 6 decimal precision

        // ratio = reserve_a * 1000000 / reserve_b
        let scaled_a = reserve_a.bvmul(&scaling);
        let ratio = scaled_a.bvudiv(reserve_b);

        let min_bv = BV::from_u64(self.context, min_ratio, width);
        let max_bv = BV::from_u64(self.context, max_ratio, width);

        // min_ratio <= ratio <= max_ratio
        let ge_min = ratio.bvuge(&min_bv);
        let le_max = ratio.bvule(&max_bv);
        Bool::and(self.context, &[&ge_min, &le_max])
    }

    /// Build timestamp bounds constraint
    pub fn build_timestamp_bounds_constraint(
        &self,
        current_time: &BV<'ctx>,
        deadline: &BV<'ctx>,
    ) -> Bool<'ctx> {
        // Transaction is valid if current_time <= deadline
        current_time.bvule(deadline)
    }

    /// Build nonce uniqueness constraint (for replay protection)
    pub fn build_nonce_constraint(
        &self,
        nonce: &BV<'ctx>,
        used_nonces: &[&BV<'ctx>],
    ) -> Bool<'ctx> {
        // Nonce must not equal any previously used nonce
        let mut unique = Bool::from_bool(self.context, true);
        for used in used_nonces {
            let not_equal = nonce._eq(used).not();
            unique = Bool::and(self.context, &[&unique, &not_equal]);
        }
        unique
    }

    /// Store a named constraint for debugging
    pub fn save_constraint(&mut self, name: &str, constraint: Bool<'ctx>) {
        self.named_constraints.insert(name.to_string(), constraint);
    }

    /// Get a previously saved constraint
    pub fn get_constraint(&self, name: &str) -> Option<&Bool<'ctx>> {
        self.named_constraints.get(name)
    }

    /// Combine multiple constraints with AND
    pub fn and_all(&self, constraints: &[&Bool<'ctx>]) -> Bool<'ctx> {
        Bool::and(self.context, constraints)
    }

    /// Combine multiple constraints with OR
    pub fn or_all(&self, constraints: &[&Bool<'ctx>]) -> Bool<'ctx> {
        Bool::or(self.context, constraints)
    }

    /// Create implication: if condition then consequence
    pub fn implies(&self, condition: &Bool<'ctx>, consequence: &Bool<'ctx>) -> Bool<'ctx> {
        condition.implies(consequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overflow_constraint() {
        let cfg = z3::Config::new();
        let ctx = Context::new(&cfg);
        let builder = ConstraintBuilder::new(&ctx);

        let a = BV::from_u64(&ctx, u64::MAX - 10, 64);
        let b = BV::from_u64(&ctx, 20, 64);

        let overflow = builder.build_add_overflow_constraint(&a, &b);
        // The constraint should be satisfiable (overflow is possible)

        let solver = z3::Solver::new(&ctx);
        solver.assert(&overflow);
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_underflow_constraint() {
        let cfg = z3::Config::new();
        let ctx = Context::new(&cfg);
        let builder = ConstraintBuilder::new(&ctx);

        let a = BV::from_u64(&ctx, 5, 64);
        let b = BV::from_u64(&ctx, 10, 64);

        let underflow = builder.build_sub_underflow_constraint(&a, &b);

        let solver = z3::Solver::new(&ctx);
        solver.assert(&underflow);
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }

    #[test]
    fn test_balance_conservation() {
        let cfg = z3::Config::new();
        let ctx = Context::new(&cfg);
        let builder = ConstraintBuilder::new(&ctx);

        let input1 = BV::from_u64(&ctx, 100, 64);
        let input2 = BV::from_u64(&ctx, 50, 64);
        let output1 = BV::from_u64(&ctx, 75, 64);
        let output2 = BV::from_u64(&ctx, 75, 64);

        let conservation =
            builder.build_balance_conservation(&[&input1, &input2], &[&output1, &output2]);

        let solver = z3::Solver::new(&ctx);
        solver.assert(&conservation);
        // 100 + 50 = 150, 75 + 75 = 150, so conservation holds
        assert_eq!(solver.check(), z3::SatResult::Sat);
    }
}
