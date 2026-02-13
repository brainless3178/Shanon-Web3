//! Taint Analysis Engine for Solana Programs
//!
//! Tracks how untrusted data (sources) flows to sensitive operations (sinks).
//! Uses AST-based analysis to identify potential security vulnerabilities.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use syn::{visit::Visit, Expr, File, ItemFn, Pat, Stmt};

use crate::sinks::TaintSink;
use crate::sources::TaintSource;

#[derive(Debug, Clone, Default)]
pub struct PropagationRules;

impl PropagationRules {
    pub fn new() -> Self {
        Self
    }
}

/// A taint label tracking the origin of tainted data
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintLabel {
    pub source: TaintSource,
    pub propagation_path: Vec<String>,
    pub confidence: TaintConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintConfidence {
    Definite, // Definitely tainted
    Probable, // Likely tainted (through complex expressions)
    Possible, // Possibly tainted (conditional flow)
}

/// A detected taint flow from source to sink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<String>,
    pub severity: TaintSeverity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintSeverity {
    Critical, // Direct flow to sensitive sink
    High,     // Flow through minimal sanitization
    Medium,   // Flow with some validation
    Low,      // Flow with partial mitigation
}

/// Variable state in the taint analysis
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VariableState {
    name: String,
    labels: HashSet<TaintLabel>,
    defined_at: String,
}

/// The main taint analyzer
#[allow(dead_code)]
pub struct TaintAnalyzer {
    /// Graph representing data flow
    flow_graph: DiGraph<FlowNode, FlowEdge>,
    /// Map from variable names to their taint state
    taint_state: HashMap<String, HashSet<TaintLabel>>,
    /// Detected taint flows
    detected_flows: Vec<TaintFlow>,
    /// Known sanitizers that can remove taint
    sanitizers: HashSet<String>,
    /// Rules for propagation
    propagation_rules: PropagationRules,
    /// Cache for node indices
    node_cache: HashMap<(String, String), NodeIndex>,
}

#[derive(Debug, Clone)]
struct FlowNode {
    kind: FlowNodeKind,
    location: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum FlowNodeKind {
    Source(TaintSource),
    Sink(TaintSink),
    Variable(String),
    Operation(String),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FlowEdge {
    label: String,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        let mut sanitizers = HashSet::new();
        // Known sanitization functions
        sanitizers.insert("require!".to_string());
        sanitizers.insert("require_keys_eq!".to_string());
        sanitizers.insert("require_eq!".to_string());
        sanitizers.insert("constraint".to_string());
        sanitizers.insert("has_one".to_string());
        sanitizers.insert("checked_add".to_string());
        sanitizers.insert("checked_sub".to_string());
        sanitizers.insert("checked_mul".to_string());
        sanitizers.insert("checked_div".to_string());

        Self {
            flow_graph: DiGraph::new(),
            taint_state: HashMap::new(),
            detected_flows: Vec::new(),
            sanitizers,
            propagation_rules: PropagationRules::new(),
            node_cache: HashMap::new(),
        }
    }

    /// Analyze a Solana program directory for taint flows
    pub fn analyze_program(&mut self, program_dir: &Path) -> Result<Vec<TaintFlow>, TaintError> {
        // Walk directory and parse all .rs files
        for entry in walkdir::WalkDir::new(program_dir) {
            let entry = entry.map_err(|e| TaintError::IoError(e.to_string()))?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = std::fs::read_to_string(entry.path())
                    .map_err(|e| TaintError::IoError(e.to_string()))?;
                let file =
                    syn::parse_file(&content).map_err(|e| TaintError::ParseError(e.to_string()))?;

                self.analyze_file(&file, entry.path().to_string_lossy().to_string());
            }
        }

        // Compute taint propagation
        self.propagate_taint();

        // Detect flows from sources to sinks
        self.detect_flows();

        Ok(self.detected_flows.clone())
    }

    /// Analyze a single source file
    pub fn analyze_file(&mut self, file: &File, filename: String) {
        let mut visitor = TaintVisitor {
            analyzer: self,
            current_function: String::new(),
            filename,
            scope_stack: vec![HashSet::new()],
        };
        visitor.visit_file(file);
    }

    /// Mark a variable as tainted from a source
    pub fn mark_tainted(&mut self, var_name: &str, source: TaintSource, location: &str) {
        let label = TaintLabel {
            source: source.clone(),
            propagation_path: vec![location.to_string()],
            confidence: TaintConfidence::Definite,
        };

        self.taint_state
            .entry(var_name.to_string())
            .or_default()
            .insert(label);

        // Add to flow graph or get existing
        let source_node = self.flow_graph.add_node(FlowNode {
            kind: FlowNodeKind::Source(source),
            location: location.to_string(),
        });

        let var_node = self.get_or_create_node(var_name, location);

        self.flow_graph.add_edge(
            source_node,
            var_node,
            FlowEdge {
                label: "initial_taint".to_string(),
            },
        );
    }

    fn get_or_create_node(&mut self, name: &str, location: &str) -> NodeIndex {
        if let Some(&idx) = self
            .node_cache
            .get(&(name.to_string(), location.to_string()))
        {
            return idx;
        }

        let idx = self.flow_graph.add_node(FlowNode {
            kind: FlowNodeKind::Variable(name.to_string()),
            location: location.to_string(),
        });

        self.node_cache
            .insert((name.to_string(), location.to_string()), idx);
        idx
    }

    /// Add a dependency edge between two variables
    pub fn add_dependency(&mut self, from: &str, to: &str, location: &str) {
        let from_node = self.get_or_create_node(from, location);
        let to_node = self.get_or_create_node(to, location);

        self.flow_graph.add_edge(
            from_node,
            to_node,
            FlowEdge {
                label: "data_flow".to_string(),
            },
        );
    }

    /// Propagate taint through assignments and operations
    fn propagate_taint(&mut self) {
        // Use a worklist algorithm for fixed-point computation
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 100;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            // Clone the current state for iteration
            let current_state = self.taint_state.clone();

            // For each tainted variable, propagate to dependent variables
            for (var_name, labels) in &current_state {
                // Find all variables that depend on this one
                for node_idx in self.flow_graph.node_indices() {
                    if let FlowNodeKind::Variable(name) = &self.flow_graph[node_idx].kind {
                        if name == var_name {
                            // Propagate to successors
                            for neighbor in self
                                .flow_graph
                                .neighbors_directed(node_idx, Direction::Outgoing)
                            {
                                if let FlowNodeKind::Variable(successor_name) =
                                    &self.flow_graph[neighbor].kind
                                {
                                    let entry = self
                                        .taint_state
                                        .entry(successor_name.clone())
                                        .or_default();

                                    for label in labels {
                                        let mut propagated = label.clone();
                                        propagated.propagation_path.push(successor_name.clone());
                                        if entry.insert(propagated) {
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::debug!("Taint propagation completed in {} iterations", iterations);
    }

    /// Detect flows from tainted sources to sensitive sinks
    fn detect_flows(&mut self) {
        // Find all sink nodes and check if they're reachable from tainted sources
        for node_idx in self.flow_graph.node_indices() {
            if let FlowNodeKind::Sink(sink) = &self.flow_graph[node_idx].kind {
                // Check all predecessors for taint
                let mut visited = HashSet::new();
                let mut queue = VecDeque::new();
                queue.push_back(node_idx);

                while let Some(current) = queue.pop_front() {
                    if visited.contains(&current) {
                        continue;
                    }
                    visited.insert(current);

                    match &self.flow_graph[current].kind {
                        FlowNodeKind::Source(source) => {
                            // Found a path from source to sink
                            let flow = TaintFlow {
                                source: source.clone(),
                                sink: sink.clone(),
                                path: self.reconstruct_path(current, node_idx),
                                severity: self.compute_severity(source, sink),
                                description: self.generate_description(source, sink),
                                recommendation: self.generate_recommendation(source, sink),
                            };
                            self.detected_flows.push(flow);
                        }
                        FlowNodeKind::Variable(name) => {
                            // Check if this variable is tainted
                            if let Some(labels) = self.taint_state.get(name) {
                                for label in labels {
                                    let flow = TaintFlow {
                                        source: label.source.clone(),
                                        sink: sink.clone(),
                                        path: label.propagation_path.clone(),
                                        severity: self.compute_severity(&label.source, sink),
                                        description: self.generate_description(&label.source, sink),
                                        recommendation: self
                                            .generate_recommendation(&label.source, sink),
                                    };
                                    self.detected_flows.push(flow);
                                }
                            }
                        }
                        _ => {}
                    }

                    // Add predecessors to queue
                    for pred in self
                        .flow_graph
                        .neighbors_directed(current, Direction::Incoming)
                    {
                        queue.push_back(pred);
                    }
                }
            }
        }
    }

    fn reconstruct_path(&self, from: NodeIndex, to: NodeIndex) -> Vec<String> {
        vec![
            self.flow_graph[from].location.clone(),
            self.flow_graph[to].location.clone(),
        ]
    }

    fn compute_severity(&self, source: &TaintSource, sink: &TaintSink) -> TaintSeverity {
        match (source, sink) {
            // Critical: User input directly to transfers
            (TaintSource::InstructionData { .. }, TaintSink::LamportsTransfer { .. }) => {
                TaintSeverity::Critical
            }
            (TaintSource::InstructionData { .. }, TaintSink::TokenTransfer { .. }) => {
                TaintSeverity::Critical
            }
            (TaintSource::UncheckedAccount { .. }, TaintSink::CPIInvoke { .. }) => {
                TaintSeverity::Critical
            }

            // High: User input to state or authority
            (TaintSource::InstructionData { .. }, TaintSink::StateWrite { .. }) => {
                TaintSeverity::High
            }
            (TaintSource::InstructionData { .. }, TaintSink::AuthorityCheck { .. }) => {
                TaintSeverity::High
            }
            (TaintSource::UserProvidedSeeds { .. }, TaintSink::PDADerivation { .. }) => {
                TaintSeverity::High
            }

            // Medium: Oracle data to sensitive operations
            (TaintSource::OracleData { .. }, TaintSink::StateWrite { .. }) => TaintSeverity::Medium,
            (TaintSource::DeserializedData { .. }, TaintSink::UncheckedArithmetic { .. }) => {
                TaintSeverity::Medium
            }

            // Validation bypasses are high priority
            (_, TaintSink::ValidationBypass { .. }) => TaintSeverity::High,

            // Default
            _ => TaintSeverity::Low,
        }
    }

    fn generate_description(&self, source: &TaintSource, sink: &TaintSink) -> String {
        match (source, sink) {
            (
                TaintSource::InstructionData { param_name },
                TaintSink::LamportsTransfer { location },
            ) => {
                format!(
                    "User-controlled parameter '{}' flows directly to lamports transfer at {}. \
                    An attacker could manipulate the transfer amount.",
                    param_name, location
                )
            }
            (
                TaintSource::UncheckedAccount { account_name },
                TaintSink::CPIInvoke {
                    target_program,
                    location,
                },
            ) => {
                format!(
                    "Unchecked account '{}' is used in CPI to {} at {}. \
                    An attacker could substitute a malicious account.",
                    account_name, target_program, location
                )
            }
            (
                TaintSource::UserProvidedSeeds { seed_expr },
                TaintSink::PDADerivation { location },
            ) => {
                format!(
                    "User-provided seed '{}' used in PDA derivation at {}. \
                    This could allow PDA collision attacks.",
                    seed_expr, location
                )
            }
            (
                TaintSource::InstructionData { param_name },
                TaintSink::ValidationBypass { location },
            ) => {
                format!(
                    "User-controlled parameter '{}' used in validation at {}. \
                    This could allow bypassing security checks.",
                    param_name, location
                )
            }
            _ => format!(
                "Tainted data from {:?} reaches sensitive sink {:?}",
                source, sink
            ),
        }
    }

    fn generate_recommendation(&self, _source: &TaintSource, sink: &TaintSink) -> String {
        match sink {
            TaintSink::LamportsTransfer { .. } => {
                "Validate the transfer amount against expected bounds. Use require! to check \
                that the amount doesn't exceed the user's balance or program limits."
                    .to_string()
            }
            TaintSink::TokenTransfer { .. } => {
                "Verify token account ownership and balances before transfer. Use Anchor's \
                Account<'info, TokenAccount> for automatic validation."
                    .to_string()
            }
            TaintSink::CPIInvoke { .. } => {
                "Whitelist allowed program IDs for CPI calls. Use Program<'info, T> instead \
                of raw AccountInfo for the target program."
                    .to_string()
            }
            TaintSink::StateWrite { .. } => {
                "Validate user input before writing to state. Add bounds checks and \
                authorization verification."
                    .to_string()
            }
            TaintSink::PDADerivation { .. } => {
                "Include the signer's pubkey in PDA seeds to ensure user-specific PDAs. \
                Store and verify canonical bumps."
                    .to_string()
            }
            TaintSink::AuthorityCheck { .. } => {
                "Use Signer<'info> for authority accounts. Add require_keys_eq! for \
                explicit authority validation."
                    .to_string()
            }
            TaintSink::UncheckedArithmetic { .. } => {
                "Use checked arithmetic (checked_add, checked_sub, etc.) or require! \
                to validate input ranges before operations."
                    .to_string()
            }
            TaintSink::ValidationBypass { .. } => {
                "Ensure all security-critical validations use trusted data or \
                thoroughly sanitized user input."
                    .to_string()
            }
        }
    }

    /// Get all detected taint flows
    pub fn get_flows(&self) -> &[TaintFlow] {
        &self.detected_flows
    }

    /// Check if a variable is tainted
    pub fn is_tainted(&self, var_name: &str) -> bool {
        self.taint_state.contains_key(var_name)
    }

    /// Get taint labels for a variable
    pub fn get_taint_labels(&self, var_name: &str) -> Option<&HashSet<TaintLabel>> {
        self.taint_state.get(var_name)
    }
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// AST visitor for extracting taint sources and sinks
struct TaintVisitor<'a> {
    analyzer: &'a mut TaintAnalyzer,
    current_function: String,
    filename: String,
    scope_stack: Vec<HashSet<String>>,
}

impl<'a> Visit<'_> for TaintVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();

        // Check function parameters for taint sources
        for param in &func.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = param {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    let param_name = pat_ident.ident.to_string();
                    let ty = &pat_type.ty;
                    let type_str = quote::quote!(#ty).to_string();

                    if !type_str.contains("Context")
                        && !type_str.contains("Signer")
                        && !type_str.contains("Program")
                    {
                        self.analyzer.mark_tainted(
                            &param_name,
                            TaintSource::InstructionData {
                                param_name: param_name.clone(),
                            },
                            &format!("{}::{}", self.filename, self.current_function),
                        );
                        if let Some(scope) = self.scope_stack.last_mut() {
                            scope.insert(param_name);
                        }
                    }
                }
            }
        }

        // Continue visiting the function body
        syn::visit::visit_item_fn(self, func);
    }

    fn visit_stmt(&mut self, stmt: &Stmt) {
        let location = format!("{}::{}", self.filename, self.current_function);

        if let Stmt::Local(local) = stmt {
            if let Some(init) = &local.init {
                let expr = &init.expr;
                let pat = &local.pat;

                let target_vars = self.extract_vars_from_pat(pat);
                let source_vars = self.extract_variables(expr);

                for target in target_vars {
                    for source in &source_vars {
                        self.analyzer.add_dependency(source, &target, &location);
                    }
                }
            }
        }

        syn::visit::visit_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        let location = format!("{}::{}", self.filename, self.current_function);

        match expr {
            // Detect sensitive sinks
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();

                // Token transfers
                if method_name == "transfer" || method_name == "transfer_checked" {
                    let sink_node = self.analyzer.flow_graph.add_node(FlowNode {
                        kind: FlowNodeKind::Sink(TaintSink::TokenTransfer {
                            location: location.clone(),
                        }),
                        location: location.clone(),
                    });

                    // Check if any argument is tainted
                    for arg in &method_call.args {
                        self.check_expr_taint(arg, sink_node);
                    }
                }

                // Lamports manipulation
                if method_name == "borrow_mut" {
                    let receiver_str = quote::quote!(#method_call.receiver).to_string();
                    if receiver_str.contains("lamports") {
                        let sink_node = self.analyzer.flow_graph.add_node(FlowNode {
                            kind: FlowNodeKind::Sink(TaintSink::LamportsTransfer {
                                location: location.clone(),
                            }),
                            location: location.clone(),
                        });
                        self.check_expr_taint(&method_call.receiver, sink_node);
                    }
                }

                // CPI invocations
                if method_name == "invoke" || method_name == "invoke_signed" {
                    let sink_node = self.analyzer.flow_graph.add_node(FlowNode {
                        kind: FlowNodeKind::Sink(TaintSink::CPIInvoke {
                            target_program: "unknown".to_string(),
                            location: location.clone(),
                        }),
                        location: location.clone(),
                    });

                    for arg in &method_call.args {
                        self.check_expr_taint(arg, sink_node);
                    }
                }
            }

            // Detect PDA derivations
            Expr::Call(call) => {
                let func_str = quote::quote!(#call.func).to_string();
                if func_str.contains("find_program_address") {
                    let sink_node = self.analyzer.flow_graph.add_node(FlowNode {
                        kind: FlowNodeKind::Sink(TaintSink::PDADerivation {
                            location: location.clone(),
                        }),
                        location: location.clone(),
                    });

                    for arg in &call.args {
                        self.check_expr_taint(arg, sink_node);
                    }
                }
            }

            // Detect state writes and propagation in assignments
            Expr::Assign(assign) => {
                let left = &assign.left;
                let right = &assign.right;
                let left_str = if let Expr::Path(path) = &**left {
                    path.path
                        .segments
                        .last()
                        .map(|s| s.ident.to_string())
                        .unwrap_or_else(|| "unknown_path".to_string())
                } else {
                    "unknown_assign".to_string()
                };
                let location = format!("{}::{}", self.filename, self.current_function);

                // If writing to a field, it's a StateWrite sink
                if left_str.contains(".") {
                    let sink_node = self.analyzer.flow_graph.add_node(FlowNode {
                        kind: FlowNodeKind::Sink(TaintSink::StateWrite {
                            field: left_str.clone(),
                            location: location.clone(),
                        }),
                        location: location.clone(),
                    });
                    self.check_expr_taint(right, sink_node);
                } else {
                    // It's a variable assignment, track dependency
                    for var in self.extract_variables(right) {
                        self.analyzer.add_dependency(&var, &left_str, &location);
                    }
                }
            }

            // Detect unchecked arithmetic
            Expr::Binary(binary) => {
                let is_arithmetic = match binary.op {
                    syn::BinOp::Add(_) => Some("Add"),
                    syn::BinOp::Sub(_) => Some("Sub"),
                    syn::BinOp::Mul(_) => Some("Mul"),
                    syn::BinOp::Div(_) => Some("Div"),
                    _ => None,
                };

                if let Some(op_str) = is_arithmetic {
                    // Check if this is unchecked (not wrapped in checked_*)
                    let parent_str = expr.to_token_stream().to_string();
                    if !parent_str.contains("checked_") && !parent_str.contains("saturating_") {
                        let sink_node = self.analyzer.flow_graph.add_node(FlowNode {
                            kind: FlowNodeKind::Sink(TaintSink::UncheckedArithmetic {
                                operation: op_str.to_string(),
                                location: location.clone(),
                            }),
                            location: location.clone(),
                        });
                        self.check_expr_taint(&binary.left, sink_node);
                        self.check_expr_taint(&binary.right, sink_node);
                    }
                }
            }

            _ => {}
        }

        syn::visit::visit_expr(self, expr);
    }
}

impl<'a> TaintVisitor<'a> {
    fn extract_variables(&self, expr: &Expr) -> Vec<String> {
        let mut vars = Vec::new();
        let expr_str = expr.to_token_stream().to_string();

        // Very simple variable extraction for now
        // A better way would be using another visitor
        for token in expr_str.split(|c: char| !c.is_alphanumeric() && c != '_') {
            if let Some(first_char) = token.chars().next() {
                if first_char.is_alphabetic() {
                    // Skip common keywords and types
                    if !matches!(
                        token,
                        "u8" | "u16"
                            | "u32"
                            | "u64"
                            | "u128"
                            | "let"
                            | "mut"
                            | "self"
                            | "ctx"
                            | "accounts"
                    ) {
                        vars.push(token.to_string());
                    }
                }
            }
        }
        vars
    }

    #[allow(clippy::only_used_in_recursion)]
    fn extract_vars_from_pat(&self, pat: &Pat) -> Vec<String> {
        let mut vars = Vec::new();
        match pat {
            Pat::Ident(pat_ident) => {
                vars.push(pat_ident.ident.to_string());
            }
            Pat::Tuple(pat_tuple) => {
                for p in &pat_tuple.elems {
                    vars.extend(self.extract_vars_from_pat(p));
                }
            }
            Pat::TupleStruct(pat_struct) => {
                for p in &pat_struct.elems {
                    vars.extend(self.extract_vars_from_pat(p));
                }
            }
            Pat::Slice(pat_slice) => {
                for p in &pat_slice.elems {
                    vars.extend(self.extract_vars_from_pat(p));
                }
            }
            Pat::Type(pat_type) => {
                vars.extend(self.extract_vars_from_pat(&pat_type.pat));
            }
            _ => {}
        }
        vars
    }

    fn check_expr_taint(&mut self, expr: &Expr, sink_node: NodeIndex) {
        // Extract variable names from expression
        let expr_str = expr.to_token_stream().to_string();

        // Check if any tainted variable appears in this expression
        for var_name in self.analyzer.taint_state.keys() {
            if expr_str.contains(var_name) {
                // Create edge from variable to sink
                let var_node = self.analyzer.flow_graph.add_node(FlowNode {
                    kind: FlowNodeKind::Variable(var_name.clone()),
                    location: format!("{}::{}", self.filename, self.current_function),
                });
                self.analyzer.flow_graph.add_edge(
                    var_node,
                    sink_node,
                    FlowEdge {
                        label: "flows_to".to_string(),
                    },
                );
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TaintError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_source_creation() {
        let source = TaintSource::InstructionData {
            param_name: "amount".to_string(),
        };
        assert!(matches!(source, TaintSource::InstructionData { .. }));
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = TaintAnalyzer::new();
        assert!(analyzer.detected_flows.is_empty());
    }
}
