//! Concolic execution engine for WASM and SBF programs.
//!
//! Combines concrete execution with symbolic constraint collection to
//! systematically explore program paths and detect on-chain data
//! vulnerabilities.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::constraint_collector::{CmpOp, ConstraintCollector, PathConstraint, VarOrigin};
use crate::sbf_decoder::{SbfEntryPoint, SbfModule};
use crate::wasm_parser::{WasmFunction, WasmInstruction, WasmModule, WasmValType};
use crate::WacanaError;

/// Concolic execution configuration.
#[derive(Debug, Clone)]
pub struct ConcolicConfig {
    /// Maximum paths to explore per function.
    pub max_paths: usize,
    /// Maximum branch depth.
    pub max_depth: usize,
    /// Z3 solver timeout per query (ms).
    pub solver_timeout_ms: u64,
    /// Random seed for initial concrete inputs.
    pub seed: u64,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            max_paths: 256,
            max_depth: 64,
            solver_timeout_ms: 5000,
            seed: 0xDEAD_BEEF,
        }
    }
}

/// The concolic execution engine.
pub struct ConcolicEngine {
    config: ConcolicConfig,
    /// Explored path signatures (for deduplication).
    explored_paths: HashSet<String>,
}

/// Result of exploring a function or entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Number of paths explored.
    pub paths_explored: usize,
    /// Number of unique branches covered.
    pub branches_covered: usize,
    /// All explored states.
    pub explored_states: Vec<ConcolicState>,
}

/// Snapshot of a concolic state at a program point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicState {
    /// Concrete values for variables.
    pub concrete_values: HashMap<String, i64>,
    /// Operand stack (concrete).
    pub stack: Vec<StackValue>,
    /// Linear memory contents (sparse: address → byte).
    pub memory: HashMap<u64, u8>,
    /// Global variable values.
    pub globals: HashMap<u32, i64>,
    /// Local variable values.
    pub locals: HashMap<u32, i64>,
    /// Program counter (instruction index in function).
    pub pc: usize,
    /// Branch depth reached.
    pub depth: usize,
    /// Path constraints collected.
    pub path_constraints: Vec<PathConstraint>,
    /// Whether this state reached a vulnerability-relevant point.
    pub reached_critical_point: bool,
    /// Collected memory access log.
    pub memory_accesses: Vec<MemoryAccess>,
    /// Indirect call targets observed.
    pub indirect_calls: Vec<IndirectCallInfo>,
    /// Division operations observed.
    pub divisions: Vec<DivisionInfo>,
}

/// A concrete stack value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StackValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl StackValue {
    pub fn as_i64(&self) -> i64 {
        match self {
            StackValue::I32(v) => *v as i64,
            StackValue::I64(v) => *v,
            StackValue::F32(v) => *v as i64,
            StackValue::F64(v) => *v as i64,
        }
    }

    pub fn as_i32(&self) -> i32 {
        match self {
            StackValue::I32(v) => *v,
            StackValue::I64(v) => *v as i32,
            StackValue::F32(v) => *v as i32,
            StackValue::F64(v) => *v as i32,
        }
    }
}

/// Memory access record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub address: u64,
    pub size: u32,
    pub is_write: bool,
    pub value: i64,
    pub instruction_offset: usize,
}

/// Indirect call information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCallInfo {
    pub table_index: u32,
    pub function_index: i64,
    pub instruction_offset: usize,
}

/// Division operation information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivisionInfo {
    pub dividend: i64,
    pub divisor: i64,
    pub is_signed: bool,
    pub bit_width: u32,
    pub instruction_offset: usize,
}

impl ConcolicEngine {
    pub fn new(config: ConcolicConfig) -> Self {
        Self {
            config,
            explored_paths: HashSet::new(),
        }
    }

    /// Explore a WASM function concologically.
    ///
    /// Seeds the function with concrete inputs, executes, collects constraints,
    /// then uses Z3 to negate constraints and find new inputs for unexplored paths.
    pub fn explore_wasm_function(
        &mut self,
        func: &WasmFunction,
        module: &WasmModule,
    ) -> Result<ExecutionTrace, WacanaError> {
        if func.is_import || func.instructions.is_empty() {
            return Ok(ExecutionTrace {
                paths_explored: 0,
                branches_covered: 0,
                explored_states: Vec::new(),
            });
        }

        let mut all_states = Vec::new();
        let mut branches_covered = HashSet::new();
        let mut worklist: VecDeque<HashMap<String, i64>> = VecDeque::new();

        // Generate initial concrete inputs for parameters
        let initial_inputs = self.generate_initial_inputs(func);
        worklist.push_back(initial_inputs);

        let mut paths_explored = 0usize;

        while let Some(inputs) = worklist.pop_front() {
            if paths_explored >= self.config.max_paths {
                break;
            }

            // Create a constraint collector for this path
            let mut collector = ConstraintCollector::new(self.config.max_depth * 2);

            // Register input variables
            for (i, param_type) in func.params.iter().enumerate() {
                let name = format!("param_{}", i);
                let concrete = inputs.get(&name).copied().unwrap_or(0);
                let bit_width = match param_type {
                    WasmValType::I32 | WasmValType::F32 => 32,
                    _ => 64,
                };
                collector.register_variable(
                    name,
                    concrete,
                    bit_width,
                    true,
                    VarOrigin::Parameter(i as u32),
                );
            }

            // Execute the function concretely with symbolic shadow
            let state = self.execute_wasm_concretely(func, module, &inputs, &mut collector)?;

            // Record the path signature
            let path_sig = self.compute_path_signature(&state.path_constraints);
            if self.explored_paths.contains(&path_sig) {
                continue;
            }
            self.explored_paths.insert(path_sig);

            // Track branch coverage
            for (i, constraint) in state.path_constraints.iter().enumerate() {
                let branch_key = format!("{}:{}", constraint.location, i);
                branches_covered.insert(branch_key);
            }

            paths_explored += 1;
            all_states.push(state);

            // Use constraint solver to find new inputs for unexplored paths
            let num_constraints = collector.get_constraints().len();
            for idx in 0..num_constraints {
                if worklist.len() + paths_explored >= self.config.max_paths {
                    break;
                }
                if let Some(new_inputs) =
                    collector.solve_negated_at(idx, self.config.solver_timeout_ms)
                {
                    // Check if these inputs would lead to a new path
                    let mut merged = inputs.clone();
                    for (k, v) in new_inputs {
                        merged.insert(k, v);
                    }
                    worklist.push_back(merged);
                }
            }
        }

        Ok(ExecutionTrace {
            paths_explored,
            branches_covered: branches_covered.len(),
            explored_states: all_states,
        })
    }

    /// Explore an SBF entry point concologically.
    pub fn explore_sbf_entry(
        &mut self,
        entry: &SbfEntryPoint,
        module: &SbfModule,
    ) -> Result<ExecutionTrace, WacanaError> {
        if entry.instructions.is_empty() {
            return Ok(ExecutionTrace {
                paths_explored: 0,
                branches_covered: 0,
                explored_states: Vec::new(),
            });
        }

        let mut all_states = Vec::new();
        let mut branches_covered = HashSet::new();
        let mut worklist: VecDeque<HashMap<String, i64>> = VecDeque::new();

        // SBF uses r1..r5 for parameters
        let mut initial_inputs = HashMap::new();
        for reg in 1..=5 {
            initial_inputs.insert(format!("r{}", reg), self.seed_value(reg as u64));
        }
        worklist.push_back(initial_inputs);

        let mut paths_explored = 0usize;

        while let Some(inputs) = worklist.pop_front() {
            if paths_explored >= self.config.max_paths {
                break;
            }

            let mut collector = ConstraintCollector::new(self.config.max_depth * 2);

            // Register SBF registers as symbolic
            for reg in 1..=5u32 {
                let name = format!("r{}", reg);
                let concrete = inputs.get(&name).copied().unwrap_or(0);
                collector.register_variable(name, concrete, 64, true, VarOrigin::Parameter(reg));
            }

            let state = self.execute_sbf_concretely(entry, module, &inputs, &mut collector)?;

            let path_sig = self.compute_path_signature(&state.path_constraints);
            if self.explored_paths.contains(&path_sig) {
                continue;
            }
            self.explored_paths.insert(path_sig);

            for (i, constraint) in state.path_constraints.iter().enumerate() {
                let branch_key = format!("{}:{}", constraint.location, i);
                branches_covered.insert(branch_key);
            }

            paths_explored += 1;
            all_states.push(state);

            let num_constraints = collector.get_constraints().len();
            for idx in 0..num_constraints {
                if worklist.len() + paths_explored >= self.config.max_paths {
                    break;
                }
                if let Some(new_inputs) =
                    collector.solve_negated_at(idx, self.config.solver_timeout_ms)
                {
                    let mut merged = inputs.clone();
                    for (k, v) in new_inputs {
                        merged.insert(k, v);
                    }
                    worklist.push_back(merged);
                }
            }
        }

        Ok(ExecutionTrace {
            paths_explored,
            branches_covered: branches_covered.len(),
            explored_states: all_states,
        })
    }

    /// Concretely execute a WASM function while collecting symbolic constraints.
    fn execute_wasm_concretely(
        &self,
        func: &WasmFunction,
        module: &WasmModule,
        inputs: &HashMap<String, i64>,
        collector: &mut ConstraintCollector,
    ) -> Result<ConcolicState, WacanaError> {
        let mut state = ConcolicState {
            concrete_values: inputs.clone(),
            stack: Vec::new(),
            memory: HashMap::new(),
            globals: HashMap::new(),
            locals: HashMap::new(),
            pc: 0,
            depth: 0,
            path_constraints: Vec::new(),
            reached_critical_point: false,
            memory_accesses: Vec::new(),
            indirect_calls: Vec::new(),
            divisions: Vec::new(),
        };

        // Initialize locals from params
        for (i, _) in func.params.iter().enumerate() {
            let val = inputs.get(&format!("param_{}", i)).copied().unwrap_or(0);
            state.locals.insert(i as u32, val);
        }

        // Initialize remaining locals to zero
        for i in func.params.len()..((func.params.len() as u32 + func.local_count) as usize) {
            state.locals.insert(i as u32, 0);
        }

        // Initialize memory
        let memory_bytes = (module.memory.initial_pages as u64) * 65536;

        // Execute instructions
        let max_steps = self.config.max_depth * 100;
        let mut step_count = 0;
        let mut block_depth: i32 = 0;

        while state.pc < func.instructions.len() && step_count < max_steps {
            let instr = &func.instructions[state.pc];
            step_count += 1;

            match instr {
                WasmInstruction::I32Const { value } => {
                    state.stack.push(StackValue::I32(*value));
                }
                WasmInstruction::I64Const { value } => {
                    state.stack.push(StackValue::I64(*value));
                }
                WasmInstruction::LocalGet { idx } => {
                    let val = state.locals.get(idx).copied().unwrap_or(0);
                    state.stack.push(StackValue::I64(val));
                }
                WasmInstruction::LocalSet { idx } => {
                    if let Some(val) = state.stack.pop() {
                        state.locals.insert(*idx, val.as_i64());
                    }
                }
                WasmInstruction::LocalTee { idx } => {
                    if let Some(val) = state.stack.last() {
                        state.locals.insert(*idx, val.as_i64());
                    }
                }
                WasmInstruction::GlobalGet { idx } => {
                    let val = state.globals.get(idx).copied().unwrap_or(0);
                    state.stack.push(StackValue::I64(val));
                }
                WasmInstruction::GlobalSet { idx } => {
                    if let Some(val) = state.stack.pop() {
                        state.globals.insert(*idx, val.as_i64());
                    }
                }

                // Arithmetic
                WasmInstruction::I32Add | WasmInstruction::I64Add => {
                    self.execute_binop(&mut state, |a, b| a.wrapping_add(b));
                }
                WasmInstruction::I32Sub | WasmInstruction::I64Sub => {
                    self.execute_binop(&mut state, |a, b| a.wrapping_sub(b));
                }
                WasmInstruction::I32Mul | WasmInstruction::I64Mul => {
                    self.execute_binop(&mut state, |a, b| a.wrapping_mul(b));
                }
                WasmInstruction::I32DivS | WasmInstruction::I64DivS => {
                    let divisor = state.stack.last().map(|v| v.as_i64()).unwrap_or(1);
                    let is_64 = matches!(instr, WasmInstruction::I64DivS);
                    state.divisions.push(DivisionInfo {
                        dividend: if state.stack.len() >= 2 {
                            state.stack[state.stack.len() - 2].as_i64()
                        } else {
                            0
                        },
                        divisor,
                        is_signed: true,
                        bit_width: if is_64 { 64 } else { 32 },
                        instruction_offset: state.pc,
                    });

                    // Collect constraint: divisor != 0
                    collector.add_div_check_constraint(
                        &format!("div_{}_{}", func.index, state.pc),
                        divisor != 0,
                        format!("func_{}:{}", func.index, state.pc),
                    );

                    if divisor != 0 {
                        self.execute_binop(&mut state, |a, b| if b != 0 { a / b } else { 0 });
                    } else {
                        state.reached_critical_point = true;
                        break;
                    }
                }
                WasmInstruction::I32DivU | WasmInstruction::I64DivU => {
                    let divisor = state.stack.last().map(|v| v.as_i64()).unwrap_or(1);
                    state.divisions.push(DivisionInfo {
                        dividend: if state.stack.len() >= 2 {
                            state.stack[state.stack.len() - 2].as_i64()
                        } else {
                            0
                        },
                        divisor,
                        is_signed: false,
                        bit_width: if matches!(instr, WasmInstruction::I64DivU) {
                            64
                        } else {
                            32
                        },
                        instruction_offset: state.pc,
                    });
                    if divisor != 0 {
                        self.execute_binop(&mut state, |a, b| {
                            if b != 0 {
                                (a as u64 / b as u64) as i64
                            } else {
                                0
                            }
                        });
                    } else {
                        state.reached_critical_point = true;
                        break;
                    }
                }
                WasmInstruction::I32RemS
                | WasmInstruction::I64RemS
                | WasmInstruction::I32RemU
                | WasmInstruction::I64RemU => {
                    let divisor = state.stack.last().map(|v| v.as_i64()).unwrap_or(1);
                    if divisor != 0 {
                        self.execute_binop(&mut state, |a, b| if b != 0 { a % b } else { 0 });
                    } else {
                        state.reached_critical_point = true;
                        break;
                    }
                }

                // Bitwise
                WasmInstruction::I32And | WasmInstruction::I64And => {
                    self.execute_binop(&mut state, |a, b| a & b);
                }
                WasmInstruction::I32Or | WasmInstruction::I64Or => {
                    self.execute_binop(&mut state, |a, b| a | b);
                }
                WasmInstruction::I32Xor | WasmInstruction::I64Xor => {
                    self.execute_binop(&mut state, |a, b| a ^ b);
                }
                WasmInstruction::I32Shl | WasmInstruction::I64Shl => {
                    self.execute_binop(&mut state, |a, b| a.wrapping_shl(b as u32));
                }
                WasmInstruction::I32ShrS | WasmInstruction::I64ShrS => {
                    self.execute_binop(&mut state, |a, b| a.wrapping_shr(b as u32));
                }
                WasmInstruction::I32ShrU | WasmInstruction::I64ShrU => {
                    self.execute_binop(&mut state, |a, b| {
                        ((a as u64).wrapping_shr(b as u32)) as i64
                    });
                }

                // Comparisons
                WasmInstruction::I32Eqz | WasmInstruction::I64Eqz => {
                    if let Some(val) = state.stack.pop() {
                        let v = val.as_i64();
                        let result = if v == 0 { 1i32 } else { 0i32 };

                        collector.add_eqz_constraint(
                            &format!("eqz_{}_{}", func.index, state.pc),
                            v == 0,
                            format!("func_{}:{}", func.index, state.pc),
                        );

                        state.stack.push(StackValue::I32(result));
                        state.depth += 1;
                    }
                }
                WasmInstruction::I32Eq | WasmInstruction::I64Eq => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::Eq,
                        |a, b| if a == b { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32Ne | WasmInstruction::I64Ne => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::Ne,
                        |a, b| if a != b { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32LtS | WasmInstruction::I64LtS => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::Lt,
                        |a, b| if a < b { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32LtU | WasmInstruction::I64LtU => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::LtU,
                        |a, b| if (a as u64) < (b as u64) { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32GtS | WasmInstruction::I64GtS => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::Gt,
                        |a, b| if a > b { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32GtU | WasmInstruction::I64GtU => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::GtU,
                        |a, b| if (a as u64) > (b as u64) { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32LeS | WasmInstruction::I64LeS => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::Le,
                        |a, b| if a <= b { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32LeU | WasmInstruction::I64LeU => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::LeU,
                        |a, b| if (a as u64) <= (b as u64) { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32GeS | WasmInstruction::I64GeS => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::Ge,
                        |a, b| if a >= b { 1 } else { 0 },
                    );
                }
                WasmInstruction::I32GeU | WasmInstruction::I64GeU => {
                    self.execute_cmp_with_constraint(
                        &mut state,
                        collector,
                        func.index,
                        CmpOp::GeU,
                        |a, b| if (a as u64) >= (b as u64) { 1 } else { 0 },
                    );
                }

                // Memory loads
                WasmInstruction::I32Load { offset, .. }
                | WasmInstruction::I64Load { offset, .. } => {
                    let addr = state.stack.pop().map(|v| v.as_i64() as u64).unwrap_or(0) + offset;
                    let is_64 = matches!(instr, WasmInstruction::I64Load { .. });
                    let size = if is_64 { 8u32 } else { 4u32 };

                    // Record memory access
                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size,
                        is_write: false,
                        value: 0,
                        instruction_offset: state.pc,
                    });

                    // Bounds check constraint
                    collector.add_bounds_constraint(
                        &format!("mem_addr_{}_{}", func.index, state.pc),
                        &size.to_string(),
                        &memory_bytes.to_string(),
                        addr + size as u64 <= memory_bytes,
                        format!("func_{}:{}", func.index, state.pc),
                    );

                    if addr + size as u64 > memory_bytes {
                        state.reached_critical_point = true;
                    }

                    // Read from sparse memory
                    let mut val: i64 = 0;
                    for i in 0..size {
                        if let Some(&byte) = state.memory.get(&(addr + i as u64)) {
                            val |= (byte as i64) << (i * 8);
                        }
                    }
                    if is_64 {
                        state.stack.push(StackValue::I64(val));
                    } else {
                        state.stack.push(StackValue::I32(val as i32));
                    }
                }

                // Memory stores
                WasmInstruction::I32Store { offset, .. }
                | WasmInstruction::I64Store { offset, .. } => {
                    let val = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    let addr = state.stack.pop().map(|v| v.as_i64() as u64).unwrap_or(0) + offset;
                    let is_64 = matches!(instr, WasmInstruction::I64Store { .. });
                    let size = if is_64 { 8u32 } else { 4u32 };

                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size,
                        is_write: true,
                        value: val,
                        instruction_offset: state.pc,
                    });

                    collector.add_bounds_constraint(
                        &format!("mem_addr_{}_{}", func.index, state.pc),
                        &size.to_string(),
                        &memory_bytes.to_string(),
                        addr + size as u64 <= memory_bytes,
                        format!("func_{}:{}", func.index, state.pc),
                    );

                    if addr + size as u64 > memory_bytes {
                        state.reached_critical_point = true;
                    }

                    for i in 0..size {
                        state
                            .memory
                            .insert(addr + i as u64, ((val >> (i * 8)) & 0xff) as u8);
                    }
                }

                // Byte/half-word loads
                WasmInstruction::I32Load8S { offset, .. }
                | WasmInstruction::I32Load8U { offset, .. }
                | WasmInstruction::I32Load16S { offset, .. }
                | WasmInstruction::I32Load16U { offset, .. }
                | WasmInstruction::I64Load8S { offset, .. }
                | WasmInstruction::I64Load8U { offset, .. }
                | WasmInstruction::I64Load16S { offset, .. }
                | WasmInstruction::I64Load16U { offset, .. }
                | WasmInstruction::I64Load32S { offset, .. }
                | WasmInstruction::I64Load32U { offset, .. } => {
                    let addr = state.stack.pop().map(|v| v.as_i64() as u64).unwrap_or(0) + offset;
                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size: 1,
                        is_write: false,
                        value: 0,
                        instruction_offset: state.pc,
                    });
                    let val = state.memory.get(&addr).copied().unwrap_or(0);
                    state.stack.push(StackValue::I32(val as i32));
                }

                // Byte/half-word stores
                WasmInstruction::I32Store8 { offset, .. }
                | WasmInstruction::I32Store16 { offset, .. }
                | WasmInstruction::I64Store8 { offset, .. }
                | WasmInstruction::I64Store16 { offset, .. }
                | WasmInstruction::I64Store32 { offset, .. } => {
                    let val = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    let addr = state.stack.pop().map(|v| v.as_i64() as u64).unwrap_or(0) + offset;
                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size: 1,
                        is_write: true,
                        value: val,
                        instruction_offset: state.pc,
                    });
                    state.memory.insert(addr, (val & 0xff) as u8);
                }

                // Indirect calls
                WasmInstruction::CallIndirect {
                    type_idx: _type_idx,
                    table_idx,
                } => {
                    let func_idx = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    state.indirect_calls.push(IndirectCallInfo {
                        table_index: *table_idx,
                        function_index: func_idx,
                        instruction_offset: state.pc,
                    });
                }

                // Direct calls (skip into — treated as opaque)
                WasmInstruction::Call { func_idx: _ } => {
                    // Do not recurse into called functions; treat as opaque.
                    // Push a symbolic return value.
                    state.stack.push(StackValue::I64(0));
                }

                // Control flow
                WasmInstruction::Block { .. } => {
                    block_depth += 1;
                }
                WasmInstruction::Loop { .. } => {
                    block_depth += 1;
                }
                WasmInstruction::If { .. } => {
                    let cond = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    let taken = cond != 0;

                    collector.add_eqz_constraint(
                        &format!("if_cond_{}_{}", func.index, state.pc),
                        !taken,
                        format!("func_{}:{}", func.index, state.pc),
                    );

                    state.depth += 1;
                    block_depth += 1;

                    if state.depth > self.config.max_depth {
                        break;
                    }
                }
                WasmInstruction::End => {
                    block_depth = (block_depth - 1).max(0);
                    if block_depth < 0 {
                        break;
                    }
                }
                WasmInstruction::Else => {
                    // Skip else handling in concolic mode
                }
                WasmInstruction::Br { .. } | WasmInstruction::BrIf { .. } => {
                    // Branch instruction handling
                    if matches!(instr, WasmInstruction::BrIf { .. }) {
                        let cond = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                        let taken = cond != 0;
                        collector.add_eqz_constraint(
                            &format!("br_cond_{}_{}", func.index, state.pc),
                            !taken,
                            format!("func_{}:{}", func.index, state.pc),
                        );
                        state.depth += 1;
                    }
                }
                WasmInstruction::Return => {
                    break;
                }
                WasmInstruction::Unreachable => {
                    state.reached_critical_point = true;
                    break;
                }

                WasmInstruction::Drop => {
                    state.stack.pop();
                }
                WasmInstruction::Select => {
                    let cond = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    let val2 = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    let val1 = state.stack.pop().map(|v| v.as_i64()).unwrap_or(0);
                    let result = if cond != 0 { val1 } else { val2 };
                    state.stack.push(StackValue::I64(result));
                }

                WasmInstruction::MemorySize => {
                    state
                        .stack
                        .push(StackValue::I32(module.memory.initial_pages as i32));
                }
                WasmInstruction::MemoryGrow => {
                    // Simulate memory grow failure
                    state.stack.pop();
                    state.stack.push(StackValue::I32(-1));
                }

                // Conversions
                WasmInstruction::I32WrapI64 => {
                    if let Some(val) = state.stack.pop() {
                        state.stack.push(StackValue::I32(val.as_i64() as i32));
                    }
                }
                WasmInstruction::I64ExtendI32S | WasmInstruction::I64ExtendI32U => {
                    if let Some(val) = state.stack.pop() {
                        if matches!(instr, WasmInstruction::I64ExtendI32S) {
                            state.stack.push(StackValue::I64(val.as_i32() as i64));
                        } else {
                            state
                                .stack
                                .push(StackValue::I64((val.as_i32() as u32) as i64));
                        }
                    }
                }

                // Unary ops
                WasmInstruction::I32Clz | WasmInstruction::I64Clz => {
                    if let Some(val) = state.stack.pop() {
                        let v = val.as_i64();
                        state.stack.push(StackValue::I64(v.leading_zeros() as i64));
                    }
                }
                WasmInstruction::I32Ctz | WasmInstruction::I64Ctz => {
                    if let Some(val) = state.stack.pop() {
                        let v = val.as_i64();
                        state.stack.push(StackValue::I64(v.trailing_zeros() as i64));
                    }
                }
                WasmInstruction::I32Popcnt | WasmInstruction::I64Popcnt => {
                    if let Some(val) = state.stack.pop() {
                        let v = val.as_i64();
                        state.stack.push(StackValue::I64(v.count_ones() as i64));
                    }
                }

                _ => {
                    // Other instructions: skip for concolic purposes
                }
            }

            state.pc += 1;
        }

        state.path_constraints = collector.get_constraints().to_vec();
        Ok(state)
    }

    /// Concretely execute SBF instructions with constraint collection.
    #[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
    fn execute_sbf_concretely(
        &self,
        entry: &SbfEntryPoint,
        _module: &SbfModule,
        inputs: &HashMap<String, i64>,
        collector: &mut ConstraintCollector,
    ) -> Result<ConcolicState, WacanaError> {
        let mut state = ConcolicState {
            concrete_values: inputs.clone(),
            stack: Vec::new(),
            memory: HashMap::new(),
            globals: HashMap::new(),
            locals: HashMap::new(),
            pc: 0,
            depth: 0,
            path_constraints: Vec::new(),
            reached_critical_point: false,
            memory_accesses: Vec::new(),
            indirect_calls: Vec::new(),
            divisions: Vec::new(),
        };

        // Initialize registers (r0-r10)
        let mut regs: [i64; 11] = [0; 11];
        for i in 1..=5 {
            regs[i] = inputs.get(&format!("r{}", i)).copied().unwrap_or(0);
        }
        regs[10] = 0x200000000; // r10 = stack pointer (4GB mark)

        let max_steps = self.config.max_depth * 50;
        let mut step_count = 0;

        for (pc, instr) in entry.instructions.iter().enumerate() {
            if step_count >= max_steps {
                break;
            }
            step_count += 1;
            state.pc = pc;

            let class = instr.opcode & 0x07;
            let src_type = instr.opcode & 0x08;
            let op = instr.opcode & 0xf0;

            match class {
                // ALU64
                0x07 => {
                    let dst = instr.dst_reg as usize;
                    let src_val = if src_type == 0x08 {
                        regs[instr.src_reg as usize]
                    } else {
                        instr.imm as i64
                    };

                    match op {
                        0x00 => regs[dst] = regs[dst].wrapping_add(src_val),
                        0x10 => regs[dst] = regs[dst].wrapping_sub(src_val),
                        0x20 => regs[dst] = regs[dst].wrapping_mul(src_val),
                        0x30 => {
                            state.divisions.push(DivisionInfo {
                                dividend: regs[dst],
                                divisor: src_val,
                                is_signed: true,
                                bit_width: 64,
                                instruction_offset: pc,
                            });
                            if src_val != 0 {
                                regs[dst] /= src_val;
                            } else {
                                state.reached_critical_point = true;
                            }
                        }
                        0xb0 => regs[dst] = src_val,
                        0x40 => regs[dst] |= src_val,
                        0x50 => regs[dst] &= src_val,
                        0x60 => regs[dst] = regs[dst].wrapping_shl(src_val as u32),
                        0x70 => regs[dst] = ((regs[dst] as u64) >> (src_val as u32)) as i64,
                        0x90 => {
                            if src_val != 0 {
                                regs[dst] %= src_val;
                            }
                        }
                        0xa0 => regs[dst] ^= src_val,
                        _ => {}
                    }
                }

                // ALU32
                0x04 => {
                    let dst = instr.dst_reg as usize;
                    let src_val = if src_type == 0x08 {
                        regs[instr.src_reg as usize] as i32
                    } else {
                        instr.imm
                    };

                    let dst_val = regs[dst] as i32;
                    let result: i32 = match op {
                        0x00 => dst_val.wrapping_add(src_val),
                        0x10 => dst_val.wrapping_sub(src_val),
                        0x20 => dst_val.wrapping_mul(src_val),
                        0x30 => {
                            if src_val != 0 {
                                dst_val / src_val
                            } else {
                                0
                            }
                        }
                        0xb0 => src_val,
                        _ => dst_val,
                    };
                    regs[dst] = result as i64;
                }

                // JMP
                0x05 => {
                    let dst = instr.dst_reg as usize;
                    let src_val = if src_type == 0x08 {
                        regs[instr.src_reg as usize]
                    } else {
                        instr.imm as i64
                    };

                    match op {
                        0x90 => break, // exit
                        0x80 => {
                            // call — opaque
                            regs[0] = 0;
                        }
                        _ => {
                            // Conditional branches
                            let taken = match op {
                                0x10 => regs[dst] == src_val,
                                0x20 => (regs[dst] as u64) > (src_val as u64),
                                0x30 => (regs[dst] as u64) >= (src_val as u64),
                                0x40 => regs[dst] & src_val != 0,
                                0x50 => regs[dst] != src_val,
                                0x60 => regs[dst] > src_val,
                                0x70 => regs[dst] >= src_val,
                                0xa0 => (regs[dst] as u64) < (src_val as u64),
                                0xb0 => (regs[dst] as u64) <= (src_val as u64),
                                _ => false,
                            };

                            let cmp_op = match op {
                                0x10 => CmpOp::Eq,
                                0x20 => CmpOp::GtU,
                                0x30 => CmpOp::GeU,
                                0x50 => CmpOp::Ne,
                                0x60 => CmpOp::Gt,
                                0x70 => CmpOp::Ge,
                                0xa0 => CmpOp::LtU,
                                0xb0 => CmpOp::LeU,
                                _ => CmpOp::Eq,
                            };

                            collector.add_comparison_constraint(
                                cmp_op,
                                &format!("r{}", dst),
                                &format!("{}", src_val),
                                taken,
                                format!("{}:+{}", entry.name, pc),
                            );

                            state.depth += 1;
                        }
                    }
                }

                // Memory load
                0x01 => {
                    let base = regs[instr.src_reg as usize] as u64;
                    let addr = base.wrapping_add(instr.off as u64);
                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size: 8,
                        is_write: false,
                        value: 0,
                        instruction_offset: pc,
                    });
                    let val = state.memory.get(&addr).copied().unwrap_or(0) as i64;
                    regs[instr.dst_reg as usize] = val;
                }

                // Memory store (immediate)
                0x02 => {
                    let base = regs[instr.dst_reg as usize] as u64;
                    let addr = base.wrapping_add(instr.off as u64);
                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size: 8,
                        is_write: true,
                        value: instr.imm as i64,
                        instruction_offset: pc,
                    });
                    state.memory.insert(addr, instr.imm as u8);
                }

                // Memory store (register)
                0x03 => {
                    let base = regs[instr.dst_reg as usize] as u64;
                    let addr = base.wrapping_add(instr.off as u64);
                    let val = regs[instr.src_reg as usize];
                    state.memory_accesses.push(MemoryAccess {
                        address: addr,
                        size: 8,
                        is_write: true,
                        value: val,
                        instruction_offset: pc,
                    });
                    state.memory.insert(addr, val as u8);
                }

                _ => {}
            }
        }

        // Store register state
        for i in 0..=10 {
            state.concrete_values.insert(format!("r{}", i), regs[i]);
        }

        state.path_constraints = collector.get_constraints().to_vec();
        Ok(state)
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn execute_binop(&self, state: &mut ConcolicState, op: impl Fn(i64, i64) -> i64) {
        if state.stack.len() >= 2 {
            let b = state.stack.pop().unwrap().as_i64();
            let a = state.stack.pop().unwrap().as_i64();
            state.stack.push(StackValue::I64(op(a, b)));
        }
    }

    fn execute_cmp_with_constraint(
        &self,
        state: &mut ConcolicState,
        collector: &mut ConstraintCollector,
        func_index: u32,
        cmp_op: CmpOp,
        op: impl Fn(i64, i64) -> i64,
    ) {
        if state.stack.len() >= 2 {
            let b = state.stack.pop().unwrap().as_i64();
            let a = state.stack.pop().unwrap().as_i64();
            let result = op(a, b);

            collector.add_comparison_constraint(
                cmp_op,
                &format!("cmp_l_{}_{}", func_index, state.pc),
                &format!("cmp_r_{}_{}", func_index, state.pc),
                result != 0,
                format!("func_{}:{}", func_index, state.pc),
            );

            state.stack.push(StackValue::I32(result as i32));
            state.depth += 1;
        }
    }

    fn generate_initial_inputs(&self, func: &WasmFunction) -> HashMap<String, i64> {
        let mut inputs = HashMap::new();
        for (i, _) in func.params.iter().enumerate() {
            inputs.insert(format!("param_{}", i), self.seed_value(i as u64));
        }
        inputs
    }

    fn seed_value(&self, index: u64) -> i64 {
        // Deterministic seeded value generation
        let mut val = self.config.seed.wrapping_mul(6364136223846793005);
        val = val.wrapping_add(index.wrapping_mul(1442695040888963407));
        val = val ^ (val >> 33);
        val as i64
    }

    fn compute_path_signature(&self, constraints: &[PathConstraint]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for c in constraints {
            hasher.update(format!("{}:{}:{}", c.location, c.expression, c.taken).as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}
