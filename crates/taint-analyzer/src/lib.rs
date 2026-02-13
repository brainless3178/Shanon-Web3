//! Taint Analysis Engine for Solana Programs
//!
//! Tracks how untrusted data (sources) flows to sensitive operations (sinks).
//! Uses AST-based analysis to identify potential security vulnerabilities.

pub mod advanced;
pub mod propagation;
pub mod sinks;
pub mod sources;

pub use advanced::BackwardFlow;
pub use propagation::{TaintAnalyzer, TaintConfidence, TaintFlow, TaintLabel, TaintSeverity};
pub use sinks::TaintSink;
pub use sources::TaintSource;
