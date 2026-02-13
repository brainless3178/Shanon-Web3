//! Control Flow Graph Construction
//!
//! Builds a control flow graph from Rust source code for dataflow analysis.

use petgraph::graph::{DiGraph, NodeIndex};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use syn::{Block, Expr, ItemFn, Stmt};

/// Control Flow Graph node types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CFGNodeKind {
    /// Function entry point
    Entry,
    /// Function exit point
    Exit,
    /// Regular statement
    Statement(String),
    /// Conditional branch
    Branch(BranchInfo),
    /// Join point (after if/match)
    Join,
    /// Loop header
    LoopHeader,
    /// Loop exit
    LoopExit,
    /// Function call
    Call(String),
    /// Return statement
    Return(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchInfo {
    pub condition: String,
    pub location: String,
}

/// CFG node
#[derive(Debug, Clone)]
pub struct CFGNode {
    pub id: usize,
    pub kind: CFGNodeKind,
    pub location: String,
    /// Source code snippet
    pub code: String,
}

/// CFG edge types
#[derive(Debug, Clone)]
pub enum CFGEdgeKind {
    /// Sequential execution
    Sequential,
    /// True branch of a conditional
    TrueBranch,
    /// False branch of a conditional
    FalseBranch,
    /// Loop back edge
    LoopBack,
    /// Exception/error path
    Exception,
}

#[derive(Debug, Clone)]
pub struct CFGEdge {
    pub kind: CFGEdgeKind,
}

/// Control Flow Graph
pub struct ControlFlowGraph {
    pub graph: DiGraph<CFGNode, CFGEdge>,
    pub entry: Option<NodeIndex>,
    pub exit: Option<NodeIndex>,
    pub function_name: String,
}

impl ControlFlowGraph {
    pub fn new(function_name: String) -> Self {
        Self {
            graph: DiGraph::new(),
            entry: None,
            exit: None,
            function_name,
        }
    }

    /// Add a node to the CFG
    pub fn add_node(&mut self, kind: CFGNodeKind, location: String, code: String) -> NodeIndex {
        let id = self.graph.node_count();
        let node = CFGNode {
            id,
            kind,
            location,
            code,
        };
        self.graph.add_node(node)
    }

    /// Add an edge between nodes
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, kind: CFGEdgeKind) {
        self.graph.add_edge(from, to, CFGEdge { kind });
    }

    /// Get all predecessors of a node
    pub fn predecessors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(node, petgraph::Direction::Incoming)
            .collect()
    }

    /// Get all successors of a node
    pub fn successors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(node, petgraph::Direction::Outgoing)
            .collect()
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get edge count
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get a node by index
    pub fn get_node(&self, idx: NodeIndex) -> Option<&CFGNode> {
        self.graph.node_weight(idx)
    }
}

/// CFG Builder - constructs CFG from AST
pub struct CFGBuilder {
    cfg: ControlFlowGraph,
    current_node: Option<NodeIndex>,
    filename: String,
    node_counter: usize,
    /// Loop context for break/continue handling
    loop_stack: Vec<(NodeIndex, NodeIndex)>, // (header, exit)
}

impl CFGBuilder {
    pub fn new(function_name: String, filename: String) -> Self {
        Self {
            cfg: ControlFlowGraph::new(function_name),
            current_node: None,
            filename,
            node_counter: 0,
            loop_stack: Vec::new(),
        }
    }

    /// Build CFG from a function
    pub fn build_from_function(mut self, func: &ItemFn) -> ControlFlowGraph {
        // Create entry node
        let entry = self.cfg.add_node(
            CFGNodeKind::Entry,
            format!("{}::entry", self.cfg.function_name),
            String::new(),
        );
        self.cfg.entry = Some(entry);
        self.current_node = Some(entry);

        // Process function body
        self.process_block(&func.block);

        // Create exit node
        let exit = self.cfg.add_node(
            CFGNodeKind::Exit,
            format!("{}::exit", self.cfg.function_name),
            String::new(),
        );
        self.cfg.exit = Some(exit);

        // Connect last node to exit
        if let Some(current) = self.current_node {
            self.cfg.add_edge(current, exit, CFGEdgeKind::Sequential);
        }

        self.cfg
    }

    /// Process a block of statements
    fn process_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.process_statement(stmt);
        }
    }

    /// Process a single statement
    fn process_statement(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Local(local) => {
                let code = local.to_token_stream().to_string();
                let location = self.make_location();
                let node = self
                    .cfg
                    .add_node(CFGNodeKind::Statement(code.clone()), location, code);
                self.connect_current(node);
            }

            Stmt::Expr(expr, _) => {
                self.process_expression(expr);
            }

            _ => {}
        }
    }

    /// Process an expression
    fn process_expression(&mut self, expr: &Expr) {
        match expr {
            // If expression
            Expr::If(if_expr) => {
                let cond_str = if_expr.cond.to_token_stream().to_string();
                let location = self.make_location();

                // Create branch node
                let branch = self.cfg.add_node(
                    CFGNodeKind::Branch(BranchInfo {
                        condition: cond_str.clone(),
                        location: location.clone(),
                    }),
                    location,
                    format!("if {}", cond_str),
                );
                self.connect_current(branch);

                // Create join node
                let join_location = self.make_location();
                let join = self
                    .cfg
                    .add_node(CFGNodeKind::Join, join_location, String::new());

                // Process then branch
                self.current_node = Some(branch);
                self.process_block(&if_expr.then_branch);
                if let Some(then_end) = self.current_node {
                    self.cfg.add_edge(then_end, join, CFGEdgeKind::TrueBranch);
                }

                // Process else branch
                if let Some((_, else_block)) = &if_expr.else_branch {
                    self.current_node = Some(branch);
                    if let Expr::Block(block) = &**else_block {
                        self.process_block(&block.block);
                    }
                    if let Some(else_end) = self.current_node {
                        self.cfg.add_edge(else_end, join, CFGEdgeKind::FalseBranch);
                    }
                } else {
                    // No else - false branch goes directly to join
                    self.cfg.add_edge(branch, join, CFGEdgeKind::FalseBranch);
                }

                self.current_node = Some(join);
            }

            // Loop expression
            Expr::Loop(loop_expr) => {
                let location = self.make_location();

                // Create loop header
                let header = self.cfg.add_node(
                    CFGNodeKind::LoopHeader,
                    location.clone(),
                    "loop".to_string(),
                );
                self.connect_current(header);

                // Create loop exit
                let exit_location = self.make_location();
                let exit = self
                    .cfg
                    .add_node(CFGNodeKind::LoopExit, exit_location, String::new());

                // Push loop context
                self.loop_stack.push((header, exit));

                // Process loop body
                self.current_node = Some(header);
                self.process_block(&loop_expr.body);

                // Loop back edge
                if let Some(body_end) = self.current_node {
                    self.cfg.add_edge(body_end, header, CFGEdgeKind::LoopBack);
                }

                self.loop_stack.pop();
                self.current_node = Some(exit);
            }

            // While loop
            Expr::While(while_expr) => {
                let cond_str = while_expr.cond.to_token_stream().to_string();
                let location = self.make_location();

                // Create loop header with condition
                let header = self.cfg.add_node(
                    CFGNodeKind::Branch(BranchInfo {
                        condition: cond_str.clone(),
                        location: location.clone(),
                    }),
                    location,
                    format!("while {}", cond_str),
                );
                self.connect_current(header);

                // Create loop exit
                let while_exit_location = self.make_location();
                let exit =
                    self.cfg
                        .add_node(CFGNodeKind::LoopExit, while_exit_location, String::new());

                // False branch exits the loop
                self.cfg.add_edge(header, exit, CFGEdgeKind::FalseBranch);

                // Push loop context
                self.loop_stack.push((header, exit));

                // Process loop body (true branch)
                self.current_node = Some(header);
                self.process_block(&while_expr.body);

                // Loop back edge
                if let Some(body_end) = self.current_node {
                    self.cfg.add_edge(body_end, header, CFGEdgeKind::LoopBack);
                }

                self.loop_stack.pop();
                self.current_node = Some(exit);
            }

            // Return expression
            Expr::Return(ret) => {
                let code = ret.to_token_stream().to_string();
                let location = self.make_location();
                let node = self
                    .cfg
                    .add_node(CFGNodeKind::Return(code.clone()), location, code);
                self.connect_current(node);
                // Return breaks normal flow - don't connect to next
                self.current_node = None;
            }

            // Method call
            Expr::MethodCall(call) => {
                let code = call.to_token_stream().to_string();
                let location = self.make_location();
                let node =
                    self.cfg
                        .add_node(CFGNodeKind::Call(call.method.to_string()), location, code);
                self.connect_current(node);
            }

            // Function call
            Expr::Call(call) => {
                let code = call.to_token_stream().to_string();
                let location = self.make_location();
                let node = self
                    .cfg
                    .add_node(CFGNodeKind::Call(code.clone()), location, code);
                self.connect_current(node);
            }

            // Block expression
            Expr::Block(block) => {
                self.process_block(&block.block);
            }

            // Other expressions - create regular statement node
            _ => {
                let code = expr.to_token_stream().to_string();
                if !code.is_empty() {
                    let location = self.make_location();
                    let node =
                        self.cfg
                            .add_node(CFGNodeKind::Statement(code.clone()), location, code);
                    self.connect_current(node);
                }
            }
        }
    }

    /// Connect current node to target node
    fn connect_current(&mut self, target: NodeIndex) {
        if let Some(current) = self.current_node {
            self.cfg.add_edge(current, target, CFGEdgeKind::Sequential);
        }
        self.current_node = Some(target);
    }

    /// Create a location string
    fn make_location(&mut self) -> String {
        self.node_counter += 1;
        format!("{}::{}", self.filename, self.node_counter)
    }
}

/// Build CFG from source code
pub fn build_cfg_from_source(
    source: &str,
    filename: &str,
) -> Result<Vec<ControlFlowGraph>, CFGError> {
    let file = syn::parse_file(source).map_err(|e| CFGError::ParseError(e.to_string()))?;

    let mut cfgs = Vec::new();

    for item in &file.items {
        if let syn::Item::Fn(func) = item {
            let builder = CFGBuilder::new(func.sig.ident.to_string(), filename.to_string());
            let cfg = builder.build_from_function(func);
            cfgs.push(cfg);
        }
    }

    Ok(cfgs)
}

#[derive(Debug, thiserror::Error)]
pub enum CFGError {
    #[error("Parse error: {0}")]
    ParseError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_function_cfg() {
        let source = r#"
            fn test() {
                let x = 10;
                let y = 20;
            }
        "#;

        let cfgs = build_cfg_from_source(source, "test.rs").unwrap();
        assert_eq!(cfgs.len(), 1);

        let cfg = &cfgs[0];
        assert!(cfg.entry.is_some());
        assert!(cfg.exit.is_some());
        // Entry + 2 statements + Exit = 4 nodes
        assert!(cfg.node_count() >= 4);
    }

    #[test]
    fn test_if_statement_cfg() {
        let source = r#"
            fn test(x: bool) {
                if x {
                    let a = 1;
                } else {
                    let b = 2;
                }
            }
        "#;

        let cfgs = build_cfg_from_source(source, "test.rs").unwrap();
        let cfg = &cfgs[0];

        // Should have branch and join nodes
        assert!(cfg.node_count() >= 6);
    }

    #[test]
    fn test_while_loop_cfg() {
        let source = r#"
            fn test() {
                let mut i = 0;
                while i < 10 {
                    i = i + 1;
                }
            }
        "#;

        let cfgs = build_cfg_from_source(source, "test.rs").unwrap();
        let cfg = &cfgs[0];

        // Should have loop header and exit
        assert!(cfg.node_count() >= 5);
    }
}
