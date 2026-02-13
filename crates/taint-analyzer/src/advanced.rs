//! Advanced taint analysis: inter-procedural, context-sensitive, field-sensitive,
//! path-sensitive, and backward (sink→source) tracing.

use petgraph::algo::has_path_connecting;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use syn::{visit::Visit, Expr, ItemFn, Pat};

use crate::{TaintConfidence, TaintFlow, TaintLabel, TaintSeverity, TaintSink, TaintSource};

// ----------
// INTER-PROCEDURAL ANALYSIS
// ----------

/// Represents a function summary for inter-procedural analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    /// Function name
    pub name: String,
    /// Module/file location
    pub location: String,
    /// Parameters that are taint sources
    pub tainted_params: Vec<usize>,
    /// Parameters that flow to sinks
    pub params_to_sinks: HashMap<usize, Vec<TaintSink>>,
    /// Return value taint: which params taint the return
    pub return_taint: Vec<usize>,
    /// Internal sinks reached
    pub internal_sinks: Vec<TaintSink>,
    /// Functions called (for call graph)
    pub callees: Vec<String>,
}

/// Call graph for inter-procedural analysis
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// Graph of function calls
    graph: DiGraph<String, CallEdge>,
    /// Map from function names to node indices
    node_map: HashMap<String, NodeIndex>,
    /// Function summaries
    summaries: HashMap<String, FunctionSummary>,
}

#[derive(Debug, Clone)]
pub struct CallEdge {
    /// Call site location
    pub call_site: String,
    /// Arguments passed (indices map to callee params)
    pub arg_mapping: Vec<Option<String>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function to the call graph
    pub fn add_function(&mut self, name: &str) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(name) {
            idx
        } else {
            let idx = self.graph.add_node(name.to_string());
            self.node_map.insert(name.to_string(), idx);
            idx
        }
    }

    /// Add a call edge between functions
    pub fn add_call(
        &mut self,
        caller: &str,
        callee: &str,
        call_site: String,
        args: Vec<Option<String>>,
    ) {
        let caller_idx = self.add_function(caller);
        let callee_idx = self.add_function(callee);
        self.graph.add_edge(
            caller_idx,
            callee_idx,
            CallEdge {
                call_site,
                arg_mapping: args,
            },
        );
    }

    /// Check if there's a path from one function to another
    pub fn has_path(&self, from: &str, to: &str) -> bool {
        if let (Some(&from_idx), Some(&to_idx)) = (self.node_map.get(from), self.node_map.get(to)) {
            has_path_connecting(&self.graph, from_idx, to_idx, None)
        } else {
            false
        }
    }

    /// Get all functions reachable from a given function
    pub fn reachable_from(&self, func: &str) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(&start) = self.node_map.get(func) {
            let mut visited = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(start);

            while let Some(current) = queue.pop_front() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current);
                result.push(self.graph[current].clone());

                for neighbor in self.graph.neighbors_directed(current, Direction::Outgoing) {
                    queue.push_back(neighbor);
                }
            }
        }
        result
    }

    /// Store a function summary
    pub fn set_summary(&mut self, name: &str, summary: FunctionSummary) {
        self.summaries.insert(name.to_string(), summary);
    }

    /// Get a function summary
    pub fn get_summary(&self, name: &str) -> Option<&FunctionSummary> {
        self.summaries.get(name)
    }
}

// ----------
// CONTEXT SENSITIVITY
// ----------

/// Call-site context for context-sensitive analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallContext {
    /// Stack of call sites (most recent last)
    pub call_stack: Vec<CallSite>,
    /// Maximum context depth (k-CFA)
    pub max_depth: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallSite {
    /// Caller function name
    pub caller: String,
    /// Line/location of the call
    pub location: String,
    /// Arguments at this call site
    pub arguments: Vec<String>,
}

impl CallContext {
    pub fn new(max_depth: usize) -> Self {
        Self {
            call_stack: Vec::new(),
            max_depth,
        }
    }

    /// Push a new call site onto the context
    pub fn push(&self, site: CallSite) -> Self {
        let mut new_stack = self.call_stack.clone();
        new_stack.push(site);

        // Trim to max depth (k-limiting)
        while new_stack.len() > self.max_depth {
            new_stack.remove(0);
        }

        Self {
            call_stack: new_stack,
            max_depth: self.max_depth,
        }
    }

    /// Pop the most recent call site
    pub fn pop(&self) -> Self {
        let mut new_stack = self.call_stack.clone();
        new_stack.pop();
        Self {
            call_stack: new_stack,
            max_depth: self.max_depth,
        }
    }

    /// Get a string representation for use as a key
    pub fn to_key(&self) -> String {
        self.call_stack
            .iter()
            .map(|s| format!("{}@{}", s.caller, s.location))
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

/// Context-sensitive taint state
#[derive(Debug, Clone, Default)]
pub struct ContextSensitiveTaint {
    /// Map from (context, variable) to taint labels
    taint_map: HashMap<(String, String), HashSet<TaintLabel>>,
}

impl ContextSensitiveTaint {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a variable as tainted in a specific context
    pub fn mark_tainted(&mut self, context: &CallContext, var: &str, label: TaintLabel) {
        let key = (context.to_key(), var.to_string());
        self.taint_map
            .entry(key)
            .or_default()
            .insert(label);
    }

    /// Check if a variable is tainted in a context
    pub fn is_tainted(&self, context: &CallContext, var: &str) -> bool {
        let key = (context.to_key(), var.to_string());
        self.taint_map.contains_key(&key)
    }

    /// Get taint labels for a variable in a context
    pub fn get_taint(&self, context: &CallContext, var: &str) -> Option<&HashSet<TaintLabel>> {
        let key = (context.to_key(), var.to_string());
        self.taint_map.get(&key)
    }

    /// Merge taint from another context (for joins at control flow merge points)
    pub fn merge(&mut self, other: &ContextSensitiveTaint) {
        for (key, labels) in &other.taint_map {
            self.taint_map
                .entry(key.clone())
                .or_default()
                .extend(labels.clone());
        }
    }
}

// ----------
// FIELD SENSITIVITY
// ----------

/// Field-sensitive taint tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldSensitiveTaint {
    /// Map from (base_var, field_path) to taint labels
    /// field_path is like ["foo", "bar", "baz"] for foo.bar.baz
    field_taint: HashMap<(String, Vec<String>), HashSet<TaintLabel>>,
    /// Whole-object taint (when any field access taints the whole object)
    whole_object_taint: HashMap<String, HashSet<TaintLabel>>,
}

impl FieldSensitiveTaint {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a specific field as tainted
    pub fn mark_field_tainted(&mut self, base: &str, fields: Vec<String>, label: TaintLabel) {
        let key = (base.to_string(), fields);
        self.field_taint
            .entry(key)
            .or_default()
            .insert(label);
    }

    /// Mark the whole object as tainted
    pub fn mark_whole_tainted(&mut self, base: &str, label: TaintLabel) {
        self.whole_object_taint
            .entry(base.to_string())
            .or_default()
            .insert(label);
    }

    /// Check if a specific field is tainted
    pub fn is_field_tainted(&self, base: &str, fields: &[String]) -> bool {
        // Check exact field match
        let key = (base.to_string(), fields.to_vec());
        if self.field_taint.contains_key(&key) {
            return true;
        }

        // Check if whole object is tainted
        if self.whole_object_taint.contains_key(base) {
            return true;
        }

        // Check if any parent field is tainted (field.x is tainted if field is)
        for i in 0..fields.len() {
            let parent_key = (base.to_string(), fields[0..i].to_vec());
            if self.field_taint.contains_key(&parent_key) {
                return true;
            }
        }

        false
    }

    /// Get taint labels for a field
    pub fn get_field_taint(&self, base: &str, fields: &[String]) -> HashSet<TaintLabel> {
        let mut result = HashSet::new();

        // Add exact field taint
        let key = (base.to_string(), fields.to_vec());
        if let Some(labels) = self.field_taint.get(&key) {
            result.extend(labels.clone());
        }

        // Add whole object taint
        if let Some(labels) = self.whole_object_taint.get(base) {
            result.extend(labels.clone());
        }

        // Add parent field taint
        for i in 0..fields.len() {
            let parent_key = (base.to_string(), fields[0..i].to_vec());
            if let Some(labels) = self.field_taint.get(&parent_key) {
                result.extend(labels.clone());
            }
        }

        result
    }

    /// Parse a field access expression into (base, fields)
    pub fn parse_field_access(expr_str: &str) -> Option<(String, Vec<String>)> {
        let parts: Vec<&str> = expr_str.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let base = parts[0].trim().to_string();
        let fields: Vec<String> = parts[1..].iter().map(|s| s.trim().to_string()).collect();
        Some((base, fields))
    }
}

// ----------
// PATH SENSITIVITY
// ----------

/// Path condition for path-sensitive analysis
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PathCondition {
    /// Condition expression as string
    pub condition: String,
    /// Whether this branch was taken (true) or not taken (false)
    pub branch_taken: bool,
    /// Location of the branch
    pub location: String,
}

/// Path-sensitive taint state
#[derive(Debug, Clone, Default)]
pub struct PathSensitiveTaint {
    /// Map from path (sequence of conditions) to taint state
    path_states: HashMap<Vec<PathCondition>, HashMap<String, HashSet<TaintLabel>>>,
    /// Current path being analyzed
    current_path: Vec<PathCondition>,
}

impl PathSensitiveTaint {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a branch condition onto the current path
    pub fn push_condition(&mut self, condition: PathCondition) {
        self.current_path.push(condition);
    }

    /// Pop the last branch condition
    pub fn pop_condition(&mut self) -> Option<PathCondition> {
        self.current_path.pop()
    }

    /// Get current path
    pub fn current_path(&self) -> &[PathCondition] {
        &self.current_path
    }

    /// Mark a variable as tainted on current path
    pub fn mark_tainted(&mut self, var: &str, label: TaintLabel) {
        let state = self
            .path_states
            .entry(self.current_path.clone())
            .or_default();
        state
            .entry(var.to_string())
            .or_default()
            .insert(label);
    }

    /// Check if a variable is tainted on current path
    pub fn is_tainted(&self, var: &str) -> bool {
        // Check current path
        if let Some(state) = self.path_states.get(&self.current_path) {
            if state.contains_key(var) {
                return true;
            }
        }

        // Check parent paths (a variable tainted on a parent path is tainted on child paths)
        for i in 0..self.current_path.len() {
            let parent_path = self.current_path[0..i].to_vec();
            if let Some(state) = self.path_states.get(&parent_path) {
                if state.contains_key(var) {
                    return true;
                }
            }
        }

        false
    }

    /// Get all paths where a variable is tainted
    pub fn get_tainted_paths(&self, var: &str) -> Vec<Vec<PathCondition>> {
        self.path_states
            .iter()
            .filter(|(_, state)| state.contains_key(var))
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Merge paths at a join point
    pub fn merge_paths(&mut self, paths: Vec<Vec<PathCondition>>) {
        // At a join point, a variable is tainted if it's tainted on ANY incoming path
        let mut merged_state: HashMap<String, HashSet<TaintLabel>> = HashMap::new();

        for path in paths {
            if let Some(state) = self.path_states.get(&path) {
                for (var, labels) in state {
                    merged_state
                        .entry(var.clone())
                        .or_default()
                        .extend(labels.clone());
                }
            }
        }

        // Store merged state at current path
        self.path_states
            .insert(self.current_path.clone(), merged_state);
    }
}

// ----------
// BACKWARD ANALYSIS
// ----------

/// Backward analysis to trace from sinks to sources
#[derive(Debug, Clone)]
pub struct BackwardAnalyzer {
    /// Flow graph for backward traversal
    flow_graph: DiGraph<BackwardNode, BackwardEdge>,
    /// Map from names to node indices
    node_map: HashMap<String, NodeIndex>,
    /// Detected backward flows
    backward_flows: Vec<BackwardFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackwardNode {
    pub kind: BackwardNodeKind,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackwardNodeKind {
    Source(TaintSource),
    Sink(TaintSink),
    Variable(String),
    Operation(String),
    FunctionCall(String),
    FieldAccess { base: String, field: String },
}

#[derive(Debug, Clone)]
pub struct BackwardEdge {
    pub edge_type: BackwardEdgeType,
}

#[derive(Debug, Clone)]
pub enum BackwardEdgeType {
    DataDependency,
    ControlDependency,
    CallDependency,
    FieldDependency,
}

/// A backward flow from sink to source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackwardFlow {
    /// The sink where the analysis started
    pub sink: TaintSink,
    /// The source(s) that can reach this sink
    pub sources: Vec<TaintSource>,
    /// Complete path from source to sink
    pub path: Vec<String>,
    /// Path through variable names
    pub variable_path: Vec<String>,
    /// Severity based on source-sink combination
    pub severity: TaintSeverity,
    /// Human-readable attack description
    pub attack_narrative: String,
}

impl BackwardAnalyzer {
    pub fn new() -> Self {
        Self {
            flow_graph: DiGraph::new(),
            node_map: HashMap::new(),
            backward_flows: Vec::new(),
        }
    }

    /// Add a node to the backward flow graph
    pub fn add_node(&mut self, name: &str, kind: BackwardNodeKind, location: &str) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(name) {
            idx
        } else {
            let idx = self.flow_graph.add_node(BackwardNode {
                kind,
                location: location.to_string(),
            });
            self.node_map.insert(name.to_string(), idx);
            idx
        }
    }

    /// Add a dependency edge (from dependent to dependency)
    pub fn add_dependency(&mut self, from: NodeIndex, to: NodeIndex, edge_type: BackwardEdgeType) {
        self.flow_graph
            .add_edge(from, to, BackwardEdge { edge_type });
    }

    /// Perform backward analysis from a specific sink
    pub fn analyze_sink(&mut self, sink_name: &str) -> Vec<BackwardFlow> {
        let mut flows = Vec::new();

        if let Some(&sink_idx) = self.node_map.get(sink_name) {
            // BFS backward from sink
            let mut visited = HashSet::new();
            let mut queue = VecDeque::new();
            let mut paths: HashMap<NodeIndex, Vec<String>> = HashMap::new();

            queue.push_back(sink_idx);
            paths.insert(sink_idx, vec![sink_name.to_string()]);

            while let Some(current) = queue.pop_front() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current);

                let current_path = paths.get(&current).cloned().unwrap_or_default();

                // Check if we reached a source
                if let BackwardNodeKind::Source(source) = &self.flow_graph[current].kind {
                    if let BackwardNodeKind::Sink(sink) = &self.flow_graph[sink_idx].kind {
                        flows.push(BackwardFlow {
                            sink: sink.clone(),
                            sources: vec![source.clone()],
                            path: current_path.clone(),
                            variable_path: self.extract_variable_path(&current_path),
                            severity: self.compute_severity(source, sink),
                            attack_narrative: self.generate_narrative(source, sink, &current_path),
                        });
                    }
                }

                // Continue backward traversal
                for predecessor in self
                    .flow_graph
                    .neighbors_directed(current, Direction::Incoming)
                {
                    if !visited.contains(&predecessor) {
                        let mut new_path = current_path.clone();
                        new_path.push(self.node_name(predecessor));
                        paths.insert(predecessor, new_path);
                        queue.push_back(predecessor);
                    }
                }
            }
        }

        self.backward_flows.extend(flows.clone());
        flows
    }

    /// Analyze all sinks
    pub fn analyze_all_sinks(&mut self) -> Vec<BackwardFlow> {
        let sink_names: Vec<String> = self
            .node_map
            .iter()
            .filter(|(_, &idx)| matches!(self.flow_graph[idx].kind, BackwardNodeKind::Sink(_)))
            .map(|(name, _)| name.clone())
            .collect();

        let mut all_flows = Vec::new();
        for sink_name in sink_names {
            all_flows.extend(self.analyze_sink(&sink_name));
        }
        all_flows
    }

    fn node_name(&self, idx: NodeIndex) -> String {
        self.node_map
            .iter()
            .find(|(_, &v)| v == idx)
            .map(|(k, _)| k.clone())
            .unwrap_or_else(|| format!("node_{}", idx.index()))
    }

    fn extract_variable_path(&self, path: &[String]) -> Vec<String> {
        path.iter()
            .filter(|s| !s.contains("::") && !s.starts_with("invoke"))
            .cloned()
            .collect()
    }

    fn compute_severity(&self, source: &TaintSource, sink: &TaintSink) -> TaintSeverity {
        match (source, sink) {
            (TaintSource::InstructionData { .. }, TaintSink::LamportsTransfer { .. }) => {
                TaintSeverity::Critical
            }
            (TaintSource::InstructionData { .. }, TaintSink::TokenTransfer { .. }) => {
                TaintSeverity::Critical
            }
            (TaintSource::UncheckedAccount { .. }, TaintSink::CPIInvoke { .. }) => {
                TaintSeverity::Critical
            }
            (TaintSource::InstructionData { .. }, TaintSink::StateWrite { .. }) => {
                TaintSeverity::High
            }
            (TaintSource::UserProvidedSeeds { .. }, TaintSink::PDADerivation { .. }) => {
                TaintSeverity::High
            }
            (TaintSource::OracleData { .. }, TaintSink::StateWrite { .. }) => TaintSeverity::Medium,
            _ => TaintSeverity::Low,
        }
    }

    fn generate_narrative(
        &self,
        source: &TaintSource,
        sink: &TaintSink,
        path: &[String],
    ) -> String {
        let path_str = path.join(" → ");

        match (source, sink) {
            (
                TaintSource::InstructionData { param_name },
                TaintSink::LamportsTransfer { location },
            ) => {
                format!(
                    "CRITICAL: User-controlled parameter '{}' flows directly to SOL transfer at {}.\n\
                     Attack path: {}\n\
                     Impact: Attacker can drain funds by manipulating the transfer amount.",
                    param_name, location, path_str
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
                    "CRITICAL: Unchecked account '{}' passed to CPI call to {} at {}.\n\
                     Attack path: {}\n\
                     Impact: Attacker can substitute malicious account and hijack CPI.",
                    account_name, target_program, location, path_str
                )
            }
            (
                TaintSource::UserProvidedSeeds { seed_expr },
                TaintSink::PDADerivation { location },
            ) => {
                format!(
                    "HIGH: User-provided seed '{}' used in PDA derivation at {}.\n\
                     Attack path: {}\n\
                     Impact: Attacker may derive unintended PDA or cause collision.",
                    seed_expr, location, path_str
                )
            }
            _ => format!(
                "Tainted data flows from {:?} to {:?}.\nPath: {}",
                source, sink, path_str
            ),
        }
    }

    /// Get all detected backward flows
    pub fn get_flows(&self) -> &[BackwardFlow] {
        &self.backward_flows
    }
}

impl Default for BackwardAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ----------
// ADVANCED TAINT ANALYZER (Combines All Features)
// ----------

/// Advanced taint analyzer implementing all enhanced features
#[allow(dead_code)]
pub struct AdvancedTaintAnalyzer {
    /// Inter-procedural call graph
    pub call_graph: CallGraph,
    /// Context-sensitive taint
    pub context_taint: ContextSensitiveTaint,
    /// Field-sensitive taint
    pub field_taint: FieldSensitiveTaint,
    /// Path-sensitive taint
    pub path_taint: PathSensitiveTaint,
    /// Backward analyzer
    pub backward_analyzer: BackwardAnalyzer,
    /// Current analysis context
    current_context: CallContext,
    /// Detected flows
    detected_flows: Vec<TaintFlow>,
    /// K-limit for context sensitivity (default 2)
    k_limit: usize,
}

impl AdvancedTaintAnalyzer {
    pub fn new() -> Self {
        Self::with_k_limit(2)
    }

    pub fn with_k_limit(k: usize) -> Self {
        Self {
            call_graph: CallGraph::new(),
            context_taint: ContextSensitiveTaint::new(),
            field_taint: FieldSensitiveTaint::new(),
            path_taint: PathSensitiveTaint::new(),
            backward_analyzer: BackwardAnalyzer::new(),
            current_context: CallContext::new(k),
            detected_flows: Vec::new(),
            k_limit: k,
        }
    }

    /// Analyze a source file with all advanced features
    pub fn analyze_source(
        &mut self,
        source: &str,
        filename: &str,
    ) -> Result<AdvancedTaintReport, String> {
        let _file = syn::parse_file(source).map_err(|e| format!("Parse error: {}", e))?;

        // Phase 1: Build call graph and function summaries
        self.build_call_graph_from_source(source, filename);

        // Phase 2: Forward taint propagation with context/field/path sensitivity
        self.forward_analysis_from_source(source, filename);

        // Phase 3: Backward analysis from sinks
        let backward_flows = self.backward_analyzer.analyze_all_sinks();

        Ok(AdvancedTaintReport {
            flows: self.detected_flows.clone(),
            backward_flows,
            call_graph_size: self.call_graph.node_map.len(),
            contexts_analyzed: self.context_taint.taint_map.len(),
            fields_tracked: self.field_taint.field_taint.len(),
            paths_explored: self.path_taint.path_states.len(),
        })
    }

    /// Build call graph from source string
    pub fn build_call_graph_from_source(&mut self, source: &str, filename: &str) {
        if let Ok(file) = syn::parse_file(source) {
            let mut visitor = CallGraphVisitor {
                analyzer: self,
                filename: filename.to_string(),
                current_function: String::new(),
            };
            visitor.visit_file(&file);
        }
    }

    /// Perform forward analysis from source string
    pub fn forward_analysis_from_source(&mut self, source: &str, filename: &str) {
        if let Ok(file) = syn::parse_file(source) {
            let mut visitor = AdvancedTaintVisitor {
                analyzer: self,
                filename: filename.to_string(),
                current_function: String::new(),
            };
            visitor.visit_file(&file);
        }
    }

    pub fn context_taint_count(&self) -> usize {
        self.context_taint.taint_map.len()
    }

    pub fn field_taint_count(&self) -> usize {
        self.field_taint.field_taint.len()
    }

    pub fn path_taint_count(&self) -> usize {
        self.path_taint.path_states.len()
    }

    pub fn source_count(&self) -> usize {
        self.backward_analyzer
            .node_map
            .values()
            .filter(|&&idx| {
                matches!(
                    self.backward_analyzer.flow_graph[idx].kind,
                    BackwardNodeKind::Source(_)
                )
            })
            .count()
    }

    pub fn sink_count(&self) -> usize {
        self.backward_analyzer
            .node_map
            .values()
            .filter(|&&idx| {
                matches!(
                    self.backward_analyzer.flow_graph[idx].kind,
                    BackwardNodeKind::Sink(_)
                )
            })
            .count()
    }

    /// Mark a variable as tainted with full tracking
    pub fn mark_tainted_full(
        &mut self,
        var: &str,
        source: TaintSource,
        location: &str,
        fields: Option<Vec<String>>,
    ) {
        let label = TaintLabel {
            source: source.clone(),
            propagation_path: vec![location.to_string()],
            confidence: TaintConfidence::Definite,
        };

        // Context-sensitive
        self.context_taint
            .mark_tainted(&self.current_context, var, label.clone());

        // Field-sensitive
        if let Some(field_path) = fields {
            self.field_taint
                .mark_field_tainted(var, field_path, label.clone());
        } else {
            self.field_taint.mark_whole_tainted(var, label.clone());
        }

        // Path-sensitive
        self.path_taint.mark_tainted(var, label.clone());

        // Add to backward analyzer
        let source_name = format!("source_{}_{}", var, location);
        self.backward_analyzer
            .add_node(&source_name, BackwardNodeKind::Source(source), location);
    }

    /// Check if a variable is tainted (any sensitivity)
    pub fn is_tainted(&self, var: &str, fields: Option<&[String]>) -> bool {
        // Context-sensitive check
        if self.context_taint.is_tainted(&self.current_context, var) {
            return true;
        }

        // Field-sensitive check
        if let Some(field_path) = fields {
            if self.field_taint.is_field_tainted(var, field_path) {
                return true;
            }
        }

        // Path-sensitive check
        if self.path_taint.is_tainted(var) {
            return true;
        }

        false
    }

    /// Enter a function call (update context)
    pub fn enter_call(&mut self, caller: &str, _callee: &str, location: &str, args: Vec<String>) {
        let site = CallSite {
            caller: caller.to_string(),
            location: location.to_string(),
            arguments: args,
        };
        self.current_context = self.current_context.push(site);
    }

    /// Exit a function call (update context)
    pub fn exit_call(&mut self) {
        self.current_context = self.current_context.pop();
    }

    /// Enter a branch (update path)
    pub fn enter_branch(&mut self, condition: &str, taken: bool, location: &str) {
        self.path_taint.push_condition(PathCondition {
            condition: condition.to_string(),
            branch_taken: taken,
            location: location.to_string(),
        });
    }

    /// Exit a branch
    pub fn exit_branch(&mut self) {
        self.path_taint.pop_condition();
    }

    /// Get detected flows
    pub fn get_flows(&self) -> &[TaintFlow] {
        &self.detected_flows
    }
}

impl Default for AdvancedTaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Report from advanced taint analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTaintReport {
    pub flows: Vec<TaintFlow>,
    pub backward_flows: Vec<BackwardFlow>,
    pub call_graph_size: usize,
    pub contexts_analyzed: usize,
    pub fields_tracked: usize,
    pub paths_explored: usize,
}

// ----------
// AST VISITORS
// ----------

struct CallGraphVisitor<'a> {
    analyzer: &'a mut AdvancedTaintAnalyzer,
    filename: String,
    current_function: String,
}

impl<'a> Visit<'_> for CallGraphVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        let func_name = func.sig.ident.to_string();
        self.current_function = func_name.clone();
        self.analyzer.call_graph.add_function(&func_name);

        // Create function summary
        let summary = FunctionSummary {
            name: func_name.clone(),
            location: format!("{}::{}", self.filename, func_name),
            tainted_params: Vec::new(),
            params_to_sinks: HashMap::new(),
            return_taint: Vec::new(),
            internal_sinks: Vec::new(),
            callees: Vec::new(),
        };
        self.analyzer.call_graph.set_summary(&func_name, summary);

        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call(call) => {
                let callee = call.func.to_token_stream().to_string();
                let args: Vec<Option<String>> = call
                    .args
                    .iter()
                    .map(|a| Some(a.to_token_stream().to_string()))
                    .collect();

                self.analyzer.call_graph.add_call(
                    &self.current_function,
                    &callee,
                    format!("{}::{}", self.filename, self.current_function),
                    args,
                );

                // Update function summary
                if let Some(summary) = self
                    .analyzer
                    .call_graph
                    .summaries
                    .get_mut(&self.current_function)
                {
                    summary.callees.push(callee);
                }
            }
            Expr::MethodCall(method_call) => {
                let callee = method_call.method.to_string();
                let args: Vec<Option<String>> = method_call
                    .args
                    .iter()
                    .map(|a| Some(a.to_token_stream().to_string()))
                    .collect();

                self.analyzer.call_graph.add_call(
                    &self.current_function,
                    &callee,
                    format!("{}::{}", self.filename, self.current_function),
                    args,
                );
            }
            _ => {}
        }
        syn::visit::visit_expr(self, expr);
    }
}

struct AdvancedTaintVisitor<'a> {
    analyzer: &'a mut AdvancedTaintAnalyzer,
    filename: String,
    current_function: String,
}

impl<'a> Visit<'_> for AdvancedTaintVisitor<'a> {
    fn visit_item_fn(&mut self, func: &ItemFn) {
        self.current_function = func.sig.ident.to_string();
        let location = format!("{}::{}", self.filename, self.current_function);

        // Mark parameters as tainted sources
        for param in func.sig.inputs.iter() {
            if let syn::FnArg::Typed(pat_type) = param {
                if let Pat::Ident(pat_ident) = &*pat_type.pat {
                    let param_name = pat_ident.ident.to_string();
                    let ty = &pat_type.ty;
                    let type_str = quote::quote!(#ty).to_string();

                    // Non-context parameters are taint sources
                    if !type_str.contains("Context") && !type_str.contains("Signer") {
                        self.analyzer.mark_tainted_full(
                            &param_name,
                            TaintSource::InstructionData {
                                param_name: param_name.clone(),
                            },
                            &location,
                            None,
                        );
                    }
                }
            }
        }

        syn::visit::visit_item_fn(self, func);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        let location = format!("{}::{}", self.filename, self.current_function);

        match expr {
            // Handle if expressions (path sensitivity)
            Expr::If(if_expr) => {
                let condition = if_expr.cond.to_token_stream().to_string();

                // Analyze true branch
                self.analyzer.enter_branch(&condition, true, &location);
                self.visit_block(&if_expr.then_branch);
                self.analyzer.exit_branch();

                // Analyze false branch if exists
                if let Some((_, else_branch)) = &if_expr.else_branch {
                    self.analyzer.enter_branch(&condition, false, &location);
                    self.visit_expr(else_branch);
                    self.analyzer.exit_branch();
                }

                return; // Don't visit children again
            }

            // Handle field access (field sensitivity)
            Expr::Field(field_expr) => {
                let base = field_expr.base.to_token_stream().to_string();
                let field = field_expr.member.to_token_stream().to_string();

                // Check if base is tainted
                if self.analyzer.is_tainted(&base, None) {
                    // The field access is also tainted
                    let expr_str = format!("{}.{}", base, field);
                    self.analyzer.mark_tainted_full(
                        &expr_str,
                        TaintSource::AccountFieldData {
                            account: base.clone(),
                            field: field.clone(),
                        },
                        &location,
                        Some(vec![field]),
                    );
                }
            }

            // Handle method calls (inter-procedural)
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                let _receiver = method_call.receiver.to_token_stream().to_string();

                // Check for sinks
                if method_name == "transfer" || method_name == "transfer_checked" {
                    // Check if any argument is tainted
                    for arg in &method_call.args {
                        let arg_str = arg.to_token_stream().to_string();
                        if self.analyzer.is_tainted(&arg_str, None) {
                            let sink = TaintSink::TokenTransfer {
                                location: location.clone(),
                            };
                            self.analyzer.backward_analyzer.add_node(
                                &format!("sink_transfer_{}", location),
                                BackwardNodeKind::Sink(sink),
                                &location,
                            );
                        }
                    }
                }

                // Enter call context
                self.analyzer.enter_call(
                    &self.current_function,
                    &method_name,
                    &location,
                    method_call
                        .args
                        .iter()
                        .map(|a| a.to_token_stream().to_string())
                        .collect(),
                );

                syn::visit::visit_expr(self, expr);

                self.analyzer.exit_call();
                return;
            }

            _ => {}
        }

        syn::visit::visit_expr(self, expr);
    }
}

// ----------
// TESTS
// ----------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_graph_creation() {
        let mut graph = CallGraph::new();
        graph.add_function("main");
        graph.add_function("helper");
        graph.add_call(
            "main",
            "helper",
            "main.rs:10".to_string(),
            vec![Some("x".to_string())],
        );

        assert!(graph.has_path("main", "helper"));
        assert!(!graph.has_path("helper", "main"));
    }

    #[test]
    fn test_context_sensitivity() {
        let mut taint = ContextSensitiveTaint::new();
        let ctx1 = CallContext::new(2);
        let ctx2 = ctx1.push(CallSite {
            caller: "main".to_string(),
            location: "line10".to_string(),
            arguments: vec!["x".to_string()],
        });

        let label = TaintLabel {
            source: TaintSource::InstructionData {
                param_name: "amount".to_string(),
            },
            propagation_path: vec!["main".to_string()],
            confidence: TaintConfidence::Definite,
        };

        taint.mark_tainted(&ctx1, "x", label.clone());

        assert!(taint.is_tainted(&ctx1, "x"));
        assert!(!taint.is_tainted(&ctx2, "x")); // Different context
    }

    #[test]
    fn test_field_sensitivity() {
        let mut taint = FieldSensitiveTaint::new();
        let label = TaintLabel {
            source: TaintSource::InstructionData {
                param_name: "data".to_string(),
            },
            propagation_path: vec![],
            confidence: TaintConfidence::Definite,
        };

        taint.mark_field_tainted(
            "account",
            vec!["data".to_string(), "amount".to_string()],
            label,
        );

        assert!(taint.is_field_tainted("account", &["data".to_string(), "amount".to_string()]));
        assert!(!taint.is_field_tainted("account", &["other".to_string()]));

        // Child field of tainted field should be tainted
        assert!(taint.is_field_tainted(
            "account",
            &[
                "data".to_string(),
                "amount".to_string(),
                "value".to_string()
            ]
        ));
    }

    #[test]
    fn test_path_sensitivity() {
        let mut taint = PathSensitiveTaint::new();
        let label = TaintLabel {
            source: TaintSource::InstructionData {
                param_name: "x".to_string(),
            },
            propagation_path: vec![],
            confidence: TaintConfidence::Definite,
        };

        // Mark on empty path
        taint.mark_tainted("x", label.clone());
        assert!(taint.is_tainted("x"));

        // Enter a branch
        taint.push_condition(PathCondition {
            condition: "a > 0".to_string(),
            branch_taken: true,
            location: "line5".to_string(),
        });

        // x should still be tainted (inherited from parent path)
        assert!(taint.is_tainted("x"));

        // Mark y only on this path
        taint.mark_tainted("y", label);
        assert!(taint.is_tainted("y"));

        // Exit branch
        taint.pop_condition();

        // y should not be tainted on the parent path after pop
        // (our implementation doesn't automatically propagate back)
    }

    #[test]
    fn test_backward_analyzer() {
        let mut analyzer = BackwardAnalyzer::new();

        let source_idx = analyzer.add_node(
            "user_input",
            BackwardNodeKind::Source(TaintSource::InstructionData {
                param_name: "amount".to_string(),
            }),
            "line1",
        );

        let var_idx = analyzer.add_node(
            "temp",
            BackwardNodeKind::Variable("temp".to_string()),
            "line5",
        );

        let sink_idx = analyzer.add_node(
            "transfer",
            BackwardNodeKind::Sink(TaintSink::LamportsTransfer {
                location: "line10".to_string(),
            }),
            "line10",
        );

        // Edges point from data source TO data consumer (data flow direction)
        // So for backward analysis, we traverse INCOMING edges
        // source -> var -> sink (data flows forward)
        // Backward: sink <- var <- source
        analyzer.add_dependency(source_idx, var_idx, BackwardEdgeType::DataDependency);
        analyzer.add_dependency(var_idx, sink_idx, BackwardEdgeType::DataDependency);

        let flows = analyzer.analyze_sink("transfer");
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0].severity, TaintSeverity::Critical));
    }

    #[test]
    fn test_advanced_analyzer_creation() {
        let analyzer = AdvancedTaintAnalyzer::new();
        assert_eq!(analyzer.k_limit, 2);
    }
}
