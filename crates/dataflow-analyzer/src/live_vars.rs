//! Live Variable Analysis
//!
//! Computes which variables are live (may be used before redefinition) at each program point.
//! A backward dataflow analysis essential for optimization and dead code detection.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// A variable use at a specific location
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VariableUse {
    pub var_name: String,
    pub location: String,
    pub function: String,
    pub use_kind: UseKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UseKind {
    /// Read in expression
    Read,
    /// Used in condition
    Condition,
    /// Passed as argument
    Argument,
    /// Used in return
    Return,
    /// Used in arithmetic
    Arithmetic,
    /// Used in comparison
    Comparison,
}

/// Control Flow Graph node for live variable analysis
#[derive(Debug, Clone)]
pub struct LVNode {
    pub id: usize,
    pub location: String,
    /// Variables used at this node (before any definition)
    pub uses: HashSet<String>,
    /// Variables defined at this node
    pub defs: HashSet<String>,
}

/// Control Flow Graph edge
#[derive(Debug, Clone)]
pub struct LVEdge {
    pub kind: EdgeKind,
}

#[derive(Debug, Clone)]
pub enum EdgeKind {
    Sequential,
    TrueBranch,
    FalseBranch,
    LoopBack,
}

/// Results of live variable analysis
#[derive(Debug, Clone)]
pub struct LiveVarsResult {
    /// Variables live IN (at entry) of each node
    pub live_in: HashMap<NodeIndex, HashSet<String>>,
    /// Variables live OUT (at exit) of each node
    pub live_out: HashMap<NodeIndex, HashSet<String>>,
    /// Dead definitions (defined but never used)
    pub dead_definitions: Vec<DeadDef>,
}

/// A definition that is never used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDef {
    pub var_name: String,
    pub location: String,
    pub reason: String,
}

/// Live Variable Analyzer
/// Uses backward iterative dataflow analysis
pub struct LiveVariableAnalysis {
    /// Control flow graph
    cfg: DiGraph<LVNode, LVEdge>,
    /// All uses collected
    all_uses: Vec<VariableUse>,
    /// All definitions (var_name, location)
    all_defs: Vec<(String, String)>,
}

impl LiveVariableAnalysis {
    pub fn new() -> Self {
        Self {
            cfg: DiGraph::new(),
            all_uses: Vec::new(),
            all_defs: Vec::new(),
        }
    }

    /// Add a node to the CFG
    pub fn add_node(&mut self, location: String) -> NodeIndex {
        let node = LVNode {
            id: self.cfg.node_count(),
            location,
            uses: HashSet::new(),
            defs: HashSet::new(),
        };
        self.cfg.add_node(node)
    }

    /// Add an edge between nodes
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind) {
        self.cfg.add_edge(from, to, LVEdge { kind });
    }

    /// Record a variable use at a node
    pub fn add_use(
        &mut self,
        node: NodeIndex,
        var_name: String,
        location: String,
        function: String,
        use_kind: UseKind,
    ) {
        self.cfg[node].uses.insert(var_name.clone());
        self.all_uses.push(VariableUse {
            var_name,
            location,
            function,
            use_kind,
        });
    }

    /// Record a variable definition at a node
    pub fn add_def(&mut self, node: NodeIndex, var_name: String, location: String) {
        self.cfg[node].defs.insert(var_name.clone());
        self.all_defs.push((var_name, location));
    }

    /// Compute live variables using backward worklist algorithm
    pub fn compute(&self) -> LiveVarsResult {
        let mut live_in: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
        let mut live_out: HashMap<NodeIndex, HashSet<String>> = HashMap::new();

        // Initialize all sets to empty
        for node in self.cfg.node_indices() {
            live_in.insert(node, HashSet::new());
            live_out.insert(node, HashSet::new());
        }

        // Find exit nodes (nodes with no successors)
        let _exit_nodes: Vec<NodeIndex> = self
            .cfg
            .node_indices()
            .filter(|&n| self.cfg.neighbors_directed(n, Direction::Outgoing).count() == 0)
            .collect();

        // Initialize worklist with all nodes (start from exit for backward analysis)
        let mut worklist: VecDeque<NodeIndex> = self.cfg.node_indices().collect();
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while !worklist.is_empty() && iterations < MAX_ITERATIONS {
            iterations += 1;

            if let Some(node) = worklist.pop_front() {
                // OUT[n] = ∪ IN[s] for all successors s (backward)
                let mut out_set: HashSet<String> = HashSet::new();
                for succ in self.cfg.neighbors_directed(node, Direction::Outgoing) {
                    if let Some(succ_in) = live_in.get(&succ) {
                        out_set.extend(succ_in.iter().cloned());
                    }
                }

                // IN[n] = USE[n] ∪ (OUT[n] - DEF[n])
                let cfg_node = &self.cfg[node];
                let mut in_set = out_set.clone();

                // Remove defined variables
                for def in &cfg_node.defs {
                    in_set.remove(def);
                }

                // Add used variables
                in_set.extend(cfg_node.uses.iter().cloned());

                // Check if IN changed
                let old_in = live_in.get(&node).cloned().unwrap_or_default();
                if in_set != old_in {
                    live_in.insert(node, in_set);
                    live_out.insert(node, out_set);

                    // Add predecessors to worklist (backward analysis)
                    for pred in self.cfg.neighbors_directed(node, Direction::Incoming) {
                        if !worklist.contains(&pred) {
                            worklist.push_back(pred);
                        }
                    }
                }
            }
        }

        // Find dead definitions
        let dead_definitions = self.find_dead_definitions(&live_in, &live_out);

        #[cfg(debug_assertions)]
        eprintln!(
            "[DEBUG] Live variable analysis computed in {} iterations",
            iterations
        );

        LiveVarsResult {
            live_in,
            live_out,
            dead_definitions,
        }
    }

    /// Find definitions that are never used (dead code)
    fn find_dead_definitions(
        &self,
        _live_in: &HashMap<NodeIndex, HashSet<String>>,
        live_out: &HashMap<NodeIndex, HashSet<String>>,
    ) -> Vec<DeadDef> {
        let mut dead_defs = Vec::new();

        for node in self.cfg.node_indices() {
            let cfg_node = &self.cfg[node];
            let out = live_out.get(&node).cloned().unwrap_or_default();

            // A definition is dead if the variable is not live after the definition point
            for def_var in &cfg_node.defs {
                if !out.contains(def_var) {
                    dead_defs.push(DeadDef {
                        var_name: def_var.clone(),
                        location: cfg_node.location.clone(),
                        reason: format!(
                            "Variable '{}' is defined but never used after this point",
                            def_var
                        ),
                    });
                }
            }
        }

        dead_defs
    }

    /// Get variables live at a specific location
    pub fn get_live_at(&self, result: &LiveVarsResult, location: &str) -> HashSet<String> {
        for node in self.cfg.node_indices() {
            if self.cfg[node].location == location {
                return result.live_in.get(&node).cloned().unwrap_or_default();
            }
        }
        HashSet::new()
    }

    /// Check if a variable is live at a specific location
    pub fn is_live(&self, result: &LiveVarsResult, var_name: &str, location: &str) -> bool {
        self.get_live_at(result, location).contains(var_name)
    }

    /// Get all uses of a variable
    pub fn get_uses(&self, var_name: &str) -> Vec<&VariableUse> {
        self.all_uses
            .iter()
            .filter(|u| u.var_name == var_name)
            .collect()
    }

    /// Compute liveness intervals for register allocation hints
    pub fn compute_liveness_intervals(
        &self,
        result: &LiveVarsResult,
    ) -> HashMap<String, (usize, usize)> {
        let mut intervals: HashMap<String, (usize, usize)> = HashMap::new();

        for node in self.cfg.node_indices() {
            let node_id = self.cfg[node].id;

            if let Some(live) = result.live_in.get(&node) {
                for var in live {
                    intervals
                        .entry(var.clone())
                        .and_modify(|(start, end)| {
                            *start = (*start).min(node_id);
                            *end = (*end).max(node_id);
                        })
                        .or_insert((node_id, node_id));
                }
            }
        }

        intervals
    }
}

impl Default for LiveVariableAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = LiveVariableAnalysis::new();
        assert!(analyzer.all_uses.is_empty());
        assert!(analyzer.all_defs.is_empty());
    }

    #[test]
    fn test_basic_liveness() {
        let mut analyzer = LiveVariableAnalysis::new();

        let n1 = analyzer.add_node("test:1".to_string());
        let n2 = analyzer.add_node("test:2".to_string());
        let n3 = analyzer.add_node("test:3".to_string());

        analyzer.add_edge(n1, n2, EdgeKind::Sequential);
        analyzer.add_edge(n2, n3, EdgeKind::Sequential);

        // x = 10 at n1
        analyzer.add_def(n1, "x".to_string(), "test:1".to_string());

        // y = x + 1 at n2 (uses x, defines y)
        analyzer.add_use(
            n2,
            "x".to_string(),
            "test:2".to_string(),
            "main".to_string(),
            UseKind::Arithmetic,
        );
        analyzer.add_def(n2, "y".to_string(), "test:2".to_string());

        // return y at n3
        analyzer.add_use(
            n3,
            "y".to_string(),
            "test:3".to_string(),
            "main".to_string(),
            UseKind::Return,
        );

        let result = analyzer.compute();

        // At n1, x should NOT be live IN (it's defined here)
        // At n2, x should be live IN (used here), y should be live OUT
        // At n3, y should be live IN

        assert!(result.live_in.get(&n2).unwrap().contains("x"));
        assert!(!result.live_in.get(&n2).unwrap().contains("y")); // y defined here, not live in
        assert!(result.live_in.get(&n3).unwrap().contains("y"));
    }

    #[test]
    fn test_dead_definition_detection() {
        let mut analyzer = LiveVariableAnalysis::new();

        let n1 = analyzer.add_node("test:1".to_string());
        let n2 = analyzer.add_node("test:2".to_string());

        analyzer.add_edge(n1, n2, EdgeKind::Sequential);

        // x = 10 at n1, but never used
        analyzer.add_def(n1, "x".to_string(), "test:1".to_string());

        // y = 20 at n2, also never used
        analyzer.add_def(n2, "y".to_string(), "test:2".to_string());

        let result = analyzer.compute();

        // Both should be dead definitions
        assert_eq!(result.dead_definitions.len(), 2);
    }
}
