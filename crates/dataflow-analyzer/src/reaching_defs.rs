//! Reaching Definitions Analysis
//!
//! Computes which definitions of a variable may reach a given program point.
//! Essential for understanding data dependencies and detecting uninitialized uses.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// A definition of a variable at a specific location
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Definition {
    /// Variable name
    pub var_name: String,
    /// Unique definition ID
    pub def_id: usize,
    /// Location where defined
    pub location: String,
    /// Expression that defines the value
    pub defining_expr: String,
    /// Function containing the definition
    pub function: String,
    /// Definition kind
    pub kind: DefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DefKind {
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
}

/// Control Flow Graph node for reaching definitions
#[derive(Debug, Clone)]
pub struct CFGNode {
    pub id: usize,
    pub location: String,
    /// Definitions generated at this node
    pub gen: HashSet<usize>,
    /// Variables whose definitions are killed at this node
    pub kill_vars: HashSet<String>,
}

/// Control Flow Graph edge
#[derive(Debug, Clone)]
pub struct CFGEdge {
    pub kind: EdgeKind,
}

#[derive(Debug, Clone)]
pub enum EdgeKind {
    Sequential,
    TrueBranch,
    FalseBranch,
    LoopBack,
}

/// Results of reaching definitions analysis
#[derive(Debug, Clone)]
pub struct ReachingDefsResult {
    /// Definitions reaching IN to each node
    pub reaching_in: HashMap<NodeIndex, HashSet<usize>>,
    /// Definitions reaching OUT of each node
    pub reaching_out: HashMap<NodeIndex, HashSet<usize>>,
    /// All definitions in the program
    pub all_definitions: Vec<Definition>,
    /// Definition ID by location
    pub def_by_location: HashMap<String, HashSet<usize>>,
}

/// Reaching Definitions Analyzer
/// Uses iterative dataflow analysis to compute reaching definitions
pub struct ReachingDefsAnalyzer {
    /// Control flow graph
    cfg: DiGraph<CFGNode, CFGEdge>,
    /// All definitions
    definitions: Vec<Definition>,
    /// Definition counter
    def_counter: usize,
    /// Map from variable name to its definition IDs
    var_to_defs: HashMap<String, HashSet<usize>>,
}

impl ReachingDefsAnalyzer {
    pub fn new() -> Self {
        Self {
            cfg: DiGraph::new(),
            definitions: Vec::new(),
            def_counter: 0,
            var_to_defs: HashMap::new(),
        }
    }

    /// Add a node to the CFG
    pub fn add_node(&mut self, location: String) -> NodeIndex {
        let node = CFGNode {
            id: self.cfg.node_count(),
            location,
            gen: HashSet::new(),
            kill_vars: HashSet::new(),
        };
        self.cfg.add_node(node)
    }

    /// Add an edge between nodes
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, kind: EdgeKind) {
        self.cfg.add_edge(from, to, CFGEdge { kind });
    }

    /// Record a new definition
    pub fn add_definition(
        &mut self,
        node: NodeIndex,
        var_name: String,
        defining_expr: String,
        location: String,
        function: String,
        kind: DefKind,
    ) -> usize {
        let def_id = self.def_counter;
        self.def_counter += 1;

        let def = Definition {
            var_name: var_name.clone(),
            def_id,
            location,
            defining_expr,
            function,
            kind,
        };
        self.definitions.push(def);

        // Update GEN set for this node
        self.cfg[node].gen.insert(def_id);

        // Update KILL vars (this node kills previous defs of same var)
        self.cfg[node].kill_vars.insert(var_name.clone());

        // Track variable -> definitions mapping
        self.var_to_defs
            .entry(var_name)
            .or_default()
            .insert(def_id);

        def_id
    }

    /// Compute reaching definitions using a worklist algorithm
    pub fn compute(&self) -> ReachingDefsResult {
        let mut reaching_in: HashMap<NodeIndex, HashSet<usize>> = HashMap::new();
        let mut reaching_out: HashMap<NodeIndex, HashSet<usize>> = HashMap::new();

        // Initialize all sets to empty
        for node in self.cfg.node_indices() {
            reaching_in.insert(node, HashSet::new());
            reaching_out.insert(node, HashSet::new());
        }

        // Find entry nodes (nodes with no predecessors)
        let _entry_nodes: Vec<NodeIndex> = self
            .cfg
            .node_indices()
            .filter(|&n| self.cfg.neighbors_directed(n, Direction::Incoming).count() == 0)
            .collect();

        // Worklist algorithm
        let mut worklist: VecDeque<NodeIndex> = self.cfg.node_indices().collect();
        let _changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 1000;

        while !worklist.is_empty() && iterations < MAX_ITERATIONS {
            iterations += 1;

            if let Some(node) = worklist.pop_front() {
                // IN[n] = ∪ OUT[p] for all predecessors p
                let mut in_set: HashSet<usize> = HashSet::new();
                for pred in self.cfg.neighbors_directed(node, Direction::Incoming) {
                    if let Some(pred_out) = reaching_out.get(&pred) {
                        in_set.extend(pred_out.iter().cloned());
                    }
                }

                // OUT[n] = GEN[n] ∪ (IN[n] - KILL[n])
                let gen = &self.cfg[node].gen;
                let kill_vars = &self.cfg[node].kill_vars;

                // Compute KILL set: all definitions of variables that this node redefines
                let kill: HashSet<usize> = in_set
                    .iter()
                    .filter(|&&def_id| {
                        if let Some(def) = self.definitions.get(def_id) {
                            kill_vars.contains(&def.var_name)
                        } else {
                            false
                        }
                    })
                    .cloned()
                    .collect();

                let mut out_set = in_set.clone();
                for def_id in &kill {
                    out_set.remove(def_id);
                }
                out_set.extend(gen.iter().cloned());

                // Check if OUT changed
                let old_out = reaching_out.get(&node).cloned().unwrap_or_default();
                if out_set != old_out {
                    reaching_out.insert(node, out_set);
                    reaching_in.insert(node, in_set);

                    // Add successors to worklist
                    for succ in self.cfg.neighbors_directed(node, Direction::Outgoing) {
                        if !worklist.contains(&succ) {
                            worklist.push_back(succ);
                        }
                    }
                }
            }
        }

        // Build location -> defs mapping
        let mut def_by_location: HashMap<String, HashSet<usize>> = HashMap::new();
        for def in &self.definitions {
            def_by_location
                .entry(def.location.clone())
                .or_default()
                .insert(def.def_id);
        }

        #[cfg(debug_assertions)]
        eprintln!(
            "[DEBUG] Reaching definitions computed in {} iterations",
            iterations
        );

        ReachingDefsResult {
            reaching_in,
            reaching_out,
            all_definitions: self.definitions.clone(),
            def_by_location,
        }
    }

    /// Get definitions reaching a specific location
    pub fn get_reaching_at(&self, result: &ReachingDefsResult, location: &str) -> Vec<&Definition> {
        for node in self.cfg.node_indices() {
            if self.cfg[node].location == location {
                if let Some(reaching) = result.reaching_in.get(&node) {
                    return reaching
                        .iter()
                        .filter_map(|&def_id| self.definitions.get(def_id))
                        .collect();
                }
            }
        }
        Vec::new()
    }

    /// Find uses of uninitialized variables
    pub fn find_uninitialized_uses(
        &self,
        result: &ReachingDefsResult,
        var_name: &str,
    ) -> Vec<String> {
        let mut uninitialized_locations = Vec::new();

        for node in self.cfg.node_indices() {
            // Check if this node uses the variable
            // (You'd need to track uses separately for full implementation)
            let reaching = result.reaching_in.get(&node).cloned().unwrap_or_default();

            // If no definition of this variable reaches here, it might be uninitialized
            let has_def = reaching.iter().any(|&def_id| {
                self.definitions
                    .get(def_id)
                    .map(|d| d.var_name == var_name)
                    .unwrap_or(false)
            });

            if !has_def && !self.cfg[node].location.is_empty() {
                // This is a simplified check - in practice you'd also verify the variable is used here
                uninitialized_locations.push(self.cfg[node].location.clone());
            }
        }

        uninitialized_locations
    }

    /// Get all definitions of a variable
    pub fn get_definitions_for(&self, var_name: &str) -> Vec<&Definition> {
        self.definitions
            .iter()
            .filter(|d| d.var_name == var_name)
            .collect()
    }
}

impl Default for ReachingDefsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = ReachingDefsAnalyzer::new();
        assert!(analyzer.definitions.is_empty());
    }

    #[test]
    fn test_add_definition() {
        let mut analyzer = ReachingDefsAnalyzer::new();
        let node = analyzer.add_node("test:1".to_string());

        let def_id = analyzer.add_definition(
            node,
            "x".to_string(),
            "10".to_string(),
            "test:1".to_string(),
            "main".to_string(),
            DefKind::LocalBinding,
        );

        assert_eq!(def_id, 0);
        assert_eq!(analyzer.definitions.len(), 1);
    }

    #[test]
    fn test_reaching_computation() {
        let mut analyzer = ReachingDefsAnalyzer::new();

        let n1 = analyzer.add_node("test:1".to_string());
        let n2 = analyzer.add_node("test:2".to_string());
        let n3 = analyzer.add_node("test:3".to_string());

        analyzer.add_edge(n1, n2, EdgeKind::Sequential);
        analyzer.add_edge(n2, n3, EdgeKind::Sequential);

        analyzer.add_definition(
            n1,
            "x".to_string(),
            "10".to_string(),
            "test:1".to_string(),
            "main".to_string(),
            DefKind::LocalBinding,
        );

        analyzer.add_definition(
            n2,
            "x".to_string(),
            "20".to_string(),
            "test:2".to_string(),
            "main".to_string(),
            DefKind::Assignment,
        );

        let result = analyzer.compute();

        // At n3, only the definition from n2 should reach (n1's was killed)
        let reaching_n3 = result.reaching_in.get(&n3).unwrap();
        assert_eq!(reaching_n3.len(), 1);
        assert!(reaching_n3.contains(&1)); // def_id 1 (from n2)
    }
}
