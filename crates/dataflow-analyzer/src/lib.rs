//! Dataflow Analysis Engine for Solana Programs
//!
//! Tracks how values propagate through a program using reaching definitions
//! and use-def chains. Essential for understanding data dependencies.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use syn::{visit::Visit, Expr, File, ItemFn, Local, Pat};

// CFG and dataflow modules
pub mod cfg;
pub mod enhanced;
pub mod live_vars;
pub mod reaching_defs;

// Re-export reaching definitions and live variables
pub use cfg::{
    build_cfg_from_source, BranchInfo, CFGBuilder, CFGEdge as CfgEdge, CFGEdgeKind as CfgEdgeKind,
    CFGError, CFGNode as CfgNode, CFGNodeKind as CfgNodeKind, ControlFlowGraph,
};
pub use live_vars::{DeadDef, LiveVariableAnalysis, LiveVarsResult, UseKind, VariableUse};
pub use reaching_defs::{
    CFGNode as ReachCFGNode, DefKind, Definition as ReachDef, EdgeKind as ReachEdgeKind,
    ReachingDefsAnalyzer, ReachingDefsResult,
};

// Re-export enhanced analysis types
pub use enhanced::{
    AnomalyType, ArithmeticRisk, ArithmeticRiskType, BalanceAnomaly, BalanceState,
    EnhancedDataflowAnalyzer, EnhancedDataflowReport, LamportOpType, LamportOperation,
    LamportTracker, TokenFlowIssue, TokenFlowTracker, TokenOpType, TokenOperation, ValueRange,
    ValueRangeAnalyzer,
};

/// A variable definition in the program
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Definition {
    /// Variable name
    pub var_name: String,
    /// Location where defined (file:line)
    pub location: String,
    /// Expression that defines the value
    pub defining_expr: String,
    /// Function containing the definition
    pub function: String,
    /// Type of definition
    pub kind: DefinitionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DefinitionKind {
    /// Local variable binding (let x = ...)
    LocalBinding,
    /// Function parameter
    Parameter,
    /// Assignment (x = ...)
    Assignment,
    /// Mutable borrow modification
    MutableBorrow,
    /// Struct field assignment
    FieldAssignment,
    /// Array/slice element assignment
    IndexAssignment,
}

/// A use of a variable in the program
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Use {
    /// Variable name
    pub var_name: String,
    /// Location where used
    pub location: String,
    /// Context of the use
    pub use_context: UseContext,
    /// Function containing the use
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UseContext {
    /// Used in an expression
    Expression,
    /// Used in a condition
    Condition,
    /// Used as function argument
    Argument,
    /// Used in return statement
    Return,
    /// Used in arithmetic operation
    Arithmetic,
    /// Used in comparison
    Comparison,
    /// Used in transfer/sink
    Transfer,
}

/// Control Flow Graph node
#[derive(Debug, Clone)]
pub struct CFGNode {
    pub id: usize,
    pub kind: CFGNodeKind,
    pub location: String,
    pub definitions: HashSet<String>,
    pub uses: HashSet<String>,
}

#[derive(Debug, Clone)]
pub enum CFGNodeKind {
    Entry,
    Exit,
    Statement(String),
    Branch(String),
    Join,
    Call(String),
}

/// Use-Definition chain entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseDefChain {
    pub use_site: Use,
    pub reaching_definitions: Vec<Definition>,
}

/// Definition-Use chain entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefUseChain {
    pub definition: Definition,
    pub uses: Vec<Use>,
}

/// Main dataflow analyzer
pub struct DataflowAnalyzer {
    /// Control flow graph
    cfg: DiGraph<CFGNode, CFGEdge>,
    /// All definitions in the program
    definitions: Vec<Definition>,
    /// All uses in the program
    uses: Vec<Use>,
    /// Use-def chains
    use_def_chains: HashMap<String, Vec<UseDefChain>>,
    /// Def-use chains
    def_use_chains: HashMap<String, Vec<DefUseChain>>,
    /// Reaching definitions at each CFG node
    reaching_at: HashMap<NodeIndex, HashSet<Definition>>,
    /// Live variables at each CFG node
    live_at: HashMap<NodeIndex, HashSet<String>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CFGEdge {
    kind: EdgeKind,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum EdgeKind {
    Sequential,
    TrueBranch,
    FalseBranch,
    LoopBack,
    Exception,
}

impl DataflowAnalyzer {
    pub fn new() -> Self {
        Self {
            cfg: DiGraph::new(),
            definitions: Vec::new(),
            uses: Vec::new(),
            use_def_chains: HashMap::new(),
            def_use_chains: HashMap::new(),
            reaching_at: HashMap::new(),
            live_at: HashMap::new(),
        }
    }

    /// Analyze a parsed Rust file
    pub fn analyze_file(&mut self, file: &File, filename: &str) {
        let mut visitor = DataflowVisitor {
            analyzer: self,
            current_function: String::new(),
            filename: filename.to_string(),
            current_node: None,
            node_counter: 0,
        };
        visitor.visit_file(file);

        // Compute reaching definitions
        self.compute_reaching_definitions();

        // Build use-def chains
        self.build_use_def_chains();

        // Compute live variables
        self.compute_live_variables();

        // Build def-use chains
        self.build_def_use_chains();
    }

    /// Analyze source code string
    pub fn analyze_source(&mut self, source: &str, filename: &str) -> Result<(), DataflowError> {
        let file = syn::parse_file(source).map_err(|e| DataflowError::ParseError(e.to_string()))?;
        self.analyze_file(&file, filename);
        Ok(())
    }

    /// Compute reaching definitions using worklist algorithm
    fn compute_reaching_definitions(&mut self) {
        // Initialize: each node starts with empty reaching set
        for node in self.cfg.node_indices() {
            self.reaching_at.insert(node, HashSet::new());
        }

        // Find entry node
        let entry = self
            .cfg
            .node_indices()
            .find(|&n| matches!(self.cfg[n].kind, CFGNodeKind::Entry));

        let Some(entry_node) = entry else { return };

        // Worklist algorithm
        let mut worklist: VecDeque<NodeIndex> = VecDeque::new();
        worklist.push_back(entry_node);

        while let Some(node) = worklist.pop_front() {
            // Compute IN[node] = union of OUT[pred] for all predecessors
            let mut in_set: HashSet<Definition> = HashSet::new();
            for pred in self.cfg.neighbors_directed(node, Direction::Incoming) {
                if let Some(pred_out) = self.reaching_at.get(&pred) {
                    in_set.extend(pred_out.iter().cloned());
                }
            }

            // Compute OUT[node] = GEN[node] union (IN[node] - KILL[node])
            let gen = self.get_gen_set(node);
            let kill = self.get_kill_set(node, &in_set);

            let mut out_set = in_set.clone();
            for def in &kill {
                out_set.remove(def);
            }
            out_set.extend(gen);

            // If OUT changed, add successors to worklist
            let old_out = self.reaching_at.get(&node).cloned().unwrap_or_default();
            if out_set != old_out {
                self.reaching_at.insert(node, out_set);
                for succ in self.cfg.neighbors_directed(node, Direction::Outgoing) {
                    worklist.push_back(succ);
                }
            }
        }
    }

    /// Get definitions generated at a node
    fn get_gen_set(&self, node: NodeIndex) -> HashSet<Definition> {
        let mut gen = HashSet::new();
        let cfg_node = &self.cfg[node];

        for var in &cfg_node.definitions {
            // Find the definition for this variable at this location
            for def in &self.definitions {
                if def.var_name == *var && def.location == cfg_node.location {
                    gen.insert(def.clone());
                }
            }
        }

        gen
    }

    /// Get definitions killed at a node
    fn get_kill_set(&self, node: NodeIndex, in_set: &HashSet<Definition>) -> HashSet<Definition> {
        let mut kill = HashSet::new();
        let cfg_node = &self.cfg[node];

        // A definition is killed if this node redefines the same variable
        for var in &cfg_node.definitions {
            for def in in_set {
                if def.var_name == *var {
                    kill.insert(def.clone());
                }
            }
        }

        kill
    }

    /// Build use-definition chains
    fn build_use_def_chains(&mut self) {
        for use_site in &self.uses {
            // Find the CFG node for this use
            let node = self.cfg.node_indices().find(|&n| {
                self.cfg[n].location == use_site.location
                    && self.cfg[n].uses.contains(&use_site.var_name)
            });

            let Some(node) = node else { continue };

            // Get reaching definitions at this node
            let reaching = self.reaching_at.get(&node).cloned().unwrap_or_default();

            // Filter to definitions of the used variable
            let reaching_defs: Vec<Definition> = reaching
                .into_iter()
                .filter(|d| d.var_name == use_site.var_name)
                .collect();

            let chain = UseDefChain {
                use_site: use_site.clone(),
                reaching_definitions: reaching_defs,
            };

            self.use_def_chains
                .entry(use_site.var_name.clone())
                .or_default()
                .push(chain);
        }
    }

    /// Compute live variables using backward analysis
    fn compute_live_variables(&mut self) {
        // Initialize: each node starts with empty live set
        for node in self.cfg.node_indices() {
            self.live_at.insert(node, HashSet::new());
        }

        // Find exit node
        let exit = self
            .cfg
            .node_indices()
            .find(|&n| matches!(self.cfg[n].kind, CFGNodeKind::Exit));

        let Some(exit_node) = exit else { return };

        // Worklist algorithm (backward)
        let mut worklist: VecDeque<NodeIndex> = VecDeque::new();
        worklist.push_back(exit_node);

        while let Some(node) = worklist.pop_front() {
            // Compute OUT[node] = union of IN[succ] for all successors
            let mut out_set: HashSet<String> = HashSet::new();
            for succ in self.cfg.neighbors_directed(node, Direction::Outgoing) {
                if let Some(succ_in) = self.live_at.get(&succ) {
                    out_set.extend(succ_in.iter().cloned());
                }
            }

            // Compute IN[node] = USE[node] union (OUT[node] - DEF[node])
            let uses = &self.cfg[node].uses;
            let defs = &self.cfg[node].definitions;

            let mut in_set = out_set.clone();
            for def in defs {
                in_set.remove(def);
            }
            in_set.extend(uses.iter().cloned());

            // If IN changed, add predecessors to worklist
            let old_in = self.live_at.get(&node).cloned().unwrap_or_default();
            if in_set != old_in {
                self.live_at.insert(node, in_set);
                for pred in self.cfg.neighbors_directed(node, Direction::Incoming) {
                    worklist.push_back(pred);
                }
            }
        }
    }

    /// Build definition-use chains
    fn build_def_use_chains(&mut self) {
        for def in &self.definitions {
            // Find all uses that this definition reaches
            let uses_of_def: Vec<Use> = self
                .uses
                .iter()
                .filter(|u| u.var_name == def.var_name)
                .filter(|u| {
                    // Check if this definition reaches this use
                    if let Some(chains) = self.use_def_chains.get(&u.var_name) {
                        chains.iter().any(|chain| {
                            chain.use_site == **u && chain.reaching_definitions.contains(def)
                        })
                    } else {
                        false
                    }
                })
                .cloned()
                .collect();

            let chain = DefUseChain {
                definition: def.clone(),
                uses: uses_of_def,
            };

            self.def_use_chains
                .entry(def.var_name.clone())
                .or_default()
                .push(chain);
        }
    }

    // Public query methods

    /// Get all definitions of a variable
    pub fn get_definitions(&self, var_name: &str) -> Vec<&Definition> {
        self.definitions
            .iter()
            .filter(|d| d.var_name == var_name)
            .collect()
    }

    /// Get all uses of a variable
    pub fn get_uses(&self, var_name: &str) -> Vec<&Use> {
        self.uses
            .iter()
            .filter(|u| u.var_name == var_name)
            .collect()
    }

    /// Get use-def chain for a variable
    pub fn get_use_def_chain(&self, var_name: &str) -> Option<&Vec<UseDefChain>> {
        self.use_def_chains.get(var_name)
    }

    /// Get def-use chain for a variable
    pub fn get_def_use_chain(&self, var_name: &str) -> Option<&Vec<DefUseChain>> {
        self.def_use_chains.get(var_name)
    }

    /// Check if a definition reaches a use
    pub fn definition_reaches_use(&self, def: &Definition, use_site: &Use) -> bool {
        if let Some(chains) = self.use_def_chains.get(&use_site.var_name) {
            chains.iter().any(|chain| {
                chain.use_site == *use_site && chain.reaching_definitions.contains(def)
            })
        } else {
            false
        }
    }

    /// Get all variables live at a location
    pub fn get_live_variables(&self, location: &str) -> HashSet<String> {
        for node in self.cfg.node_indices() {
            if self.cfg[node].location == location {
                return self.live_at.get(&node).cloned().unwrap_or_default();
            }
        }
        HashSet::new()
    }

    /// Find potential uninitialized uses
    pub fn find_uninitialized_uses(&self) -> Vec<&Use> {
        self.uses
            .iter()
            .filter(|u| {
                if let Some(chains) = self.use_def_chains.get(&u.var_name) {
                    chains
                        .iter()
                        .filter(|c| c.use_site == **u)
                        .all(|c| c.reaching_definitions.is_empty())
                } else {
                    true
                }
            })
            .collect()
    }

    /// Find dead definitions (defined but never used)
    pub fn find_dead_definitions(&self) -> Vec<&Definition> {
        self.definitions
            .iter()
            .filter(|d| {
                if let Some(chains) = self.def_use_chains.get(&d.var_name) {
                    chains
                        .iter()
                        .filter(|c| c.definition == **d)
                        .all(|c| c.uses.is_empty())
                } else {
                    true
                }
            })
            .collect()
    }

    /// Track where a value propagates to
    pub fn track_value_flow(&self, def: &Definition) -> Vec<Use> {
        if let Some(chains) = self.def_use_chains.get(&def.var_name) {
            chains
                .iter()
                .filter(|c| c.definition == *def)
                .flat_map(|c| c.uses.iter().cloned())
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl Default for DataflowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor for extracting dataflow information
struct DataflowVisitor<'a> {
    analyzer: &'a mut DataflowAnalyzer,
    current_function: String,
    filename: String,
    current_node: Option<NodeIndex>,
    node_counter: usize,
}

impl<'a> Visit<'_> for DataflowVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();

        // Create entry node
        let entry = self.analyzer.cfg.add_node(CFGNode {
            id: self.node_counter,
            kind: CFGNodeKind::Entry,
            location: format!("{}::{}::entry", self.filename, self.current_function),
            definitions: HashSet::new(),
            uses: HashSet::new(),
        });
        self.node_counter += 1;

        // Add parameter definitions
        for param in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    let param_name = pat_ident.ident.to_string();
                    let def = Definition {
                        var_name: param_name.clone(),
                        location: format!("{}::{}::param", self.filename, self.current_function),
                        defining_expr: format!("parameter {}", param_name),
                        function: self.current_function.clone(),
                        kind: DefinitionKind::Parameter,
                    };
                    self.analyzer.definitions.push(def);

                    // Add to entry node
                    self.analyzer.cfg[entry].definitions.insert(param_name);
                }
            }
        }

        self.current_node = Some(entry);

        // Visit function body
        syn::visit::visit_item_fn(self, func);

        // Create exit node
        let exit = self.analyzer.cfg.add_node(CFGNode {
            id: self.node_counter,
            kind: CFGNodeKind::Exit,
            location: format!("{}::{}::exit", self.filename, self.current_function),
            definitions: HashSet::new(),
            uses: HashSet::new(),
        });
        self.node_counter += 1;

        if let Some(current) = self.current_node {
            self.analyzer.cfg.add_edge(
                current,
                exit,
                CFGEdge {
                    kind: EdgeKind::Sequential,
                },
            );
        }
    }

    fn visit_local(&mut self, local: &Local) {
        let location = format!(
            "{}::{}::{}",
            self.filename, self.current_function, self.node_counter
        );

        // Extract defined variable
        if let Pat::Ident(pat_ident) = &local.pat {
            let var_name = pat_ident.ident.to_string();

            let defining_expr = if let Some(init) = &local.init {
                let expr = &init.expr;
                expr.to_token_stream().to_string()
            } else {
                "uninitialized".to_string()
            };

            let def = Definition {
                var_name: var_name.clone(),
                location: location.clone(),
                defining_expr,
                function: self.current_function.clone(),
                kind: DefinitionKind::LocalBinding,
            };
            self.analyzer.definitions.push(def);

            // Create CFG node
            let node = self.analyzer.cfg.add_node(CFGNode {
                id: self.node_counter,
                kind: CFGNodeKind::Statement(format!("let {}", var_name)),
                location: location.clone(),
                definitions: [var_name].into_iter().collect(),
                uses: HashSet::new(),
            });
            self.node_counter += 1;

            if let Some(current) = self.current_node {
                self.analyzer.cfg.add_edge(
                    current,
                    node,
                    CFGEdge {
                        kind: EdgeKind::Sequential,
                    },
                );
            }
            self.current_node = Some(node);

            // Extract uses from initializer
            if let Some(init) = &local.init {
                self.extract_uses_from_expr(&init.expr, &location);
            }
        }

        syn::visit::visit_local(self, local);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        let location = format!(
            "{}::{}::{}",
            self.filename, self.current_function, self.node_counter
        );

        match expr {
            // Assignment
            Expr::Assign(assign) => {
                let left = &assign.left;
                let right = &assign.right;
                let left_str = left.to_token_stream().to_string();

                // If it's a simple variable
                if !left_str.contains('.') && !left_str.contains('[') {
                    let var_name = left_str.trim().to_string();
                    let def = Definition {
                        var_name: var_name.clone(),
                        location: location.clone(),
                        defining_expr: right.to_token_stream().to_string(),
                        function: self.current_function.clone(),
                        kind: DefinitionKind::Assignment,
                    };
                    self.analyzer.definitions.push(def);
                }

                self.extract_uses_from_expr(&assign.right, &location);
            }

            // Method call (potential use)
            Expr::MethodCall(method_call) => {
                self.extract_uses_from_expr(&method_call.receiver, &location);
                for arg in &method_call.args {
                    self.extract_uses_from_expr(arg, &location);
                }
            }

            // Function call
            Expr::Call(call) => {
                for arg in &call.args {
                    self.extract_uses_from_expr(arg, &location);
                }
            }

            // Binary operations
            Expr::Binary(binary) => {
                self.extract_uses_from_expr(&binary.left, &location);
                self.extract_uses_from_expr(&binary.right, &location);
            }

            _ => {}
        }

        syn::visit::visit_expr(self, expr);
    }
}

impl<'a> DataflowVisitor<'a> {
    fn extract_uses_from_expr(&mut self, expr: &Expr, location: &str) {
        match expr {
            Expr::Path(path) => {
                if let Some(ident) = path.path.get_ident() {
                    let var_name = ident.to_string();
                    // Skip keywords and types
                    if !Self::is_keyword(&var_name) {
                        let use_site = Use {
                            var_name: var_name.clone(),
                            location: location.to_string(),
                            use_context: UseContext::Expression,
                            function: self.current_function.clone(),
                        };
                        self.analyzer.uses.push(use_site);

                        // Add to current CFG node
                        if let Some(current) = self.current_node {
                            self.analyzer.cfg[current].uses.insert(var_name);
                        }
                    }
                }
            }
            Expr::Binary(binary) => {
                self.extract_uses_from_expr(&binary.left, location);
                self.extract_uses_from_expr(&binary.right, location);
            }
            Expr::MethodCall(method_call) => {
                self.extract_uses_from_expr(&method_call.receiver, location);
                for arg in &method_call.args {
                    self.extract_uses_from_expr(arg, location);
                }
            }
            Expr::Call(call) => {
                for arg in &call.args {
                    self.extract_uses_from_expr(arg, location);
                }
            }
            Expr::Field(field) => {
                self.extract_uses_from_expr(&field.base, location);
            }
            Expr::Index(index) => {
                self.extract_uses_from_expr(&index.expr, location);
                self.extract_uses_from_expr(&index.index, location);
            }
            Expr::Reference(reference) => {
                self.extract_uses_from_expr(&reference.expr, location);
            }
            Expr::Unary(unary) => {
                self.extract_uses_from_expr(&unary.expr, location);
            }
            Expr::Paren(paren) => {
                self.extract_uses_from_expr(&paren.expr, location);
            }
            _ => {}
        }
    }

    fn is_keyword(name: &str) -> bool {
        matches!(
            name,
            "self"
                | "Self"
                | "true"
                | "false"
                | "None"
                | "Some"
                | "Ok"
                | "Err"
                | "Result"
                | "Option"
                | "Vec"
                | "String"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "bool"
                | "char"
                | "str"
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DataflowError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = DataflowAnalyzer::new();
        assert!(analyzer.definitions.is_empty());
        assert!(analyzer.uses.is_empty());
    }

    #[test]
    fn test_definition_kinds() {
        let def = Definition {
            var_name: "amount".to_string(),
            location: "test.rs:10".to_string(),
            defining_expr: "100".to_string(),
            function: "transfer".to_string(),
            kind: DefinitionKind::LocalBinding,
        };
        assert_eq!(def.var_name, "amount");
    }
}
