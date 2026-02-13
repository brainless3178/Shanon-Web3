//! Concolic Execution Engine for Solana Programs
//!
//! Combines concrete execution with symbolic constraint collection
//! to systematically explore program paths and find vulnerabilities.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use z3::ast::{Ast, Bool, Int};
use z3::{Config, Context, SatResult, Solver};

/// A path condition from program execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    /// Constraint expression (in string form for serialization)
    pub constraint: String,
    /// Location where condition was generated
    pub location: String,
    /// Whether this is a branch taken or not taken
    pub branch_taken: bool,
}

/// Input that triggers a specific path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestInput {
    /// Variable name -> value mapping
    pub values: HashMap<String, u64>,
    /// Path conditions that led to this input
    pub path_conditions: Vec<PathCondition>,
    /// Whether this input triggers an error
    pub triggers_error: bool,
    /// Error type if any
    pub error_type: Option<String>,
}

/// Execution state during concolic execution
#[derive(Debug, Clone)]
pub struct ExecutionState {
    /// Concrete values of variables
    pub concrete_values: HashMap<String, u64>,
    /// Symbolic constraints collected
    pub symbolic_constraints: Vec<String>,
    /// Path conditions
    pub path_conditions: Vec<PathCondition>,
    /// Current program counter / location
    pub location: String,
    /// Execution depth
    pub depth: usize,
}

impl ExecutionState {
    pub fn new() -> Self {
        Self {
            concrete_values: HashMap::new(),
            symbolic_constraints: Vec::new(),
            path_conditions: Vec::new(),
            location: String::new(),
            depth: 0,
        }
    }

    pub fn fork(&self) -> Self {
        Self {
            concrete_values: self.concrete_values.clone(),
            symbolic_constraints: self.symbolic_constraints.clone(),
            path_conditions: self.path_conditions.clone(),
            location: self.location.clone(),
            depth: self.depth + 1,
        }
    }
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of concolic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicResult {
    /// All generated test inputs
    pub test_inputs: Vec<TestInput>,
    /// Paths explored
    pub paths_explored: usize,
    /// Maximum depth reached
    pub max_depth: usize,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<ConcolicFinding>,
    /// Coverage information
    pub coverage: CoverageInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct CoverageInfo {
    /// Locations visited
    pub locations_visited: HashSet<String>,
    /// Branches taken
    pub branches_taken: HashSet<String>,
    /// Branches not taken
    pub branches_not_taken: HashSet<String>,
}


/// Vulnerability found during concolic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcolicFinding {
    pub vulnerability_type: String,
    pub location: String,
    pub triggering_input: TestInput,
    pub description: String,
    pub severity: FindingSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Configuration for concolic execution
#[derive(Debug, Clone)]
pub struct ConcolicConfig {
    /// Maximum depth to explore
    pub max_depth: usize,
    /// Maximum number of paths to explore
    pub max_paths: usize,
    /// Timeout per path in milliseconds
    pub timeout_ms: u64,
    /// Random seed for concrete values
    pub seed: u64,
}

impl Default for ConcolicConfig {
    fn default() -> Self {
        Self {
            max_depth: 50,
            max_paths: 1000,
            timeout_ms: 1000,
            seed: 42,
        }
    }
}

/// Main concolic executor
pub struct ConcolicExecutor {
    config: ConcolicConfig,
    /// Worklist of states to explore
    worklist: VecDeque<ExecutionState>,
    /// Explored paths
    explored_paths: HashSet<Vec<bool>>,
    /// Generated test inputs
    test_inputs: Vec<TestInput>,
    /// Findings
    findings: Vec<ConcolicFinding>,
    /// Coverage
    coverage: CoverageInfo,
}

impl ConcolicExecutor {
    pub fn new(config: ConcolicConfig) -> Self {
        Self {
            config,
            worklist: VecDeque::new(),
            explored_paths: HashSet::new(),
            test_inputs: Vec::new(),
            findings: Vec::new(),
            coverage: CoverageInfo::default(),
        }
    }

    /// Execute concolic analysis starting with initial concrete inputs
    pub fn execute(&mut self, initial_inputs: HashMap<String, u64>) -> ConcolicResult {
        // Initialize with starting state
        let mut initial_state = ExecutionState::new();
        initial_state.concrete_values = initial_inputs;
        self.worklist.push_back(initial_state);

        let mut paths_explored = 0;
        let mut max_depth = 0;

        while let Some(state) = self.worklist.pop_front() {
            if paths_explored >= self.config.max_paths {
                break;
            }

            if state.depth > self.config.max_depth {
                continue;
            }

            max_depth = max_depth.max(state.depth);
            paths_explored += 1;

            // Execute path with this state
            self.execute_path(state);
        }

        ConcolicResult {
            test_inputs: self.test_inputs.clone(),
            paths_explored,
            max_depth,
            vulnerabilities: self.findings.clone(),
            coverage: self.coverage.clone(),
        }
    }

    /// Execute a single path
    fn execute_path(&mut self, state: ExecutionState) {
        // Record coverage
        if !state.location.is_empty() {
            self.coverage
                .locations_visited
                .insert(state.location.clone());
        }

        // Generate test input for this path
        let test_input = TestInput {
            values: state.concrete_values.clone(),
            path_conditions: state.path_conditions.clone(),
            triggers_error: false,
            error_type: None,
        };
        self.test_inputs.push(test_input);

        // Try to negate last path condition to explore alternatives
        if let Some(_last_condition) = state.path_conditions.last() {
            let mut negated_conditions = state.path_conditions.clone();
            if let Some(last) = negated_conditions.last_mut() {
                last.branch_taken = !last.branch_taken;
            }

            // Try to solve for new inputs
            if let Some(new_inputs) = self.solve_constraints(&negated_conditions) {
                // Create new state with negated condition
                let mut new_state = state.fork();
                new_state.concrete_values = new_inputs;
                new_state.path_conditions = negated_conditions;

                // Check if this path was already explored
                let path_signature: Vec<bool> = new_state
                    .path_conditions
                    .iter()
                    .map(|p| p.branch_taken)
                    .collect();

                if !self.explored_paths.contains(&path_signature) {
                    self.explored_paths.insert(path_signature);
                    self.worklist.push_back(new_state);
                }
            }
        }
    }

    /// Solve constraints to find inputs for alternative paths
    fn solve_constraints(&self, conditions: &[PathCondition]) -> Option<HashMap<String, u64>> {
        let config = Config::new();
        let context = Context::new(&config);
        let solver = Solver::new(&context);

        // Collect variable names from conditions
        let mut var_names: HashSet<String> = HashSet::new();

        // Add each path condition as constraint
        for condition in conditions {
            // Extract variable name from constraint (first word)
            if let Some(var_name) = condition.constraint.split_whitespace().next() {
                var_names.insert(var_name.to_string());
            }

            if let Some(constraint) =
                self.parse_constraint(&context, &condition.constraint, condition.branch_taken)
            {
                solver.assert(&constraint);
            }
        }

        // Check satisfiability
        if solver.check() == SatResult::Sat {
            // Extract model
            if let Some(model) = solver.get_model() {
                let mut inputs = HashMap::new();

                // Evaluate each variable we know about
                for var_name in var_names {
                    let var = Int::new_const(&context, var_name.as_str());
                    if let Some(val) = model.eval(&var, true) {
                        if let Some(i) = val.as_i64() {
                            inputs.insert(var_name, i as u64);
                        }
                    }
                }

                return Some(inputs);
            }
        }

        None
    }

    /// Parse a constraint string into Z3 constraint
    fn parse_constraint<'ctx>(
        &self,
        ctx: &'ctx Context,
        constraint: &str,
        branch_taken: bool,
    ) -> Option<Bool<'ctx>> {
        // Parse simple constraints like "x > 10", "y <= 100", etc.
        let parts: Vec<&str> = constraint.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let var_name = parts[0];
        let op = parts[1];
        let value_str = parts[2];

        let value: i64 = value_str.parse().ok()?;
        let var = Int::new_const(ctx, var_name);
        let val = Int::from_i64(ctx, value);

        let base_constraint = match op {
            ">" => var.gt(&val),
            ">=" => var.ge(&val),
            "<" => var.lt(&val),
            "<=" => var.le(&val),
            "==" | "=" => var._eq(&val),
            "!=" => var._eq(&val).not(),
            _ => return None,
        };

        Some(if branch_taken {
            base_constraint
        } else {
            base_constraint.not()
        })
    }

    /// Add a discovered branch condition
    pub fn add_branch_condition(
        &mut self,
        state: &mut ExecutionState,
        constraint: String,
        taken: bool,
        location: String,
    ) {
        let condition = PathCondition {
            constraint,
            location: location.clone(),
            branch_taken: taken,
        };

        state.path_conditions.push(condition);

        if taken {
            self.coverage.branches_taken.insert(location);
        } else {
            self.coverage.branches_not_taken.insert(location);
        }
    }

    /// Record a finding during execution
    pub fn record_finding(
        &mut self,
        vulnerability_type: String,
        location: String,
        inputs: HashMap<String, u64>,
        conditions: Vec<PathCondition>,
        severity: FindingSeverity,
    ) {
        self.findings.push(ConcolicFinding {
            vulnerability_type: vulnerability_type.clone(),
            location: location.clone(),
            triggering_input: TestInput {
                values: inputs,
                path_conditions: conditions,
                triggers_error: true,
                error_type: Some(vulnerability_type),
            },
            description: format!("Vulnerability at {}", location),
            severity,
        });
    }

    /// Generate random initial inputs
    pub fn generate_random_inputs(&self, variable_names: &[&str]) -> HashMap<String, u64> {
        let mut rng = rand::thread_rng();
        let mut inputs = HashMap::new();

        for name in variable_names {
            inputs.insert(name.to_string(), rng.gen_range(0..u64::MAX));
        }

        inputs
    }

    /// Generate boundary inputs (0, 1, MAX-1, MAX, etc.)
    pub fn generate_boundary_inputs(&self, variable_names: &[&str]) -> Vec<HashMap<String, u64>> {
        let boundaries = [0u64, 1, u64::MAX - 1, u64::MAX, 1000, 1_000_000];
        let mut all_inputs = Vec::new();

        // Generate combinations
        for &value in &boundaries {
            let mut inputs = HashMap::new();
            for name in variable_names {
                inputs.insert(name.to_string(), value);
            }
            all_inputs.push(inputs);
        }

        all_inputs
    }
}

/// Interface for program under test
pub trait ConcolicTestable {
    /// Execute with concrete inputs, returning path conditions
    fn execute_concrete(&self, inputs: &HashMap<String, u64>) -> ExecutionState;

    /// Get list of input variable names
    fn input_variables(&self) -> Vec<String>;

    /// Check if execution result indicates vulnerability
    fn check_vulnerability(&self, state: &ExecutionState) -> Option<(String, FindingSeverity)>;
}

#[derive(Debug, thiserror::Error)]
pub enum ConcolicError {
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Solver error: {0}")]
    SolverError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let config = ConcolicConfig::default();
        let executor = ConcolicExecutor::new(config);
        assert!(executor.test_inputs.is_empty());
    }

    #[test]
    fn test_boundary_generation() {
        let config = ConcolicConfig::default();
        let executor = ConcolicExecutor::new(config);

        let inputs = executor.generate_boundary_inputs(&["amount", "balance"]);
        assert!(!inputs.is_empty());
    }

    #[test]
    fn test_path_condition() {
        let condition = PathCondition {
            constraint: "amount > 0".to_string(),
            location: "test.rs:10".to_string(),
            branch_taken: true,
        };
        assert!(condition.branch_taken);
    }
}
