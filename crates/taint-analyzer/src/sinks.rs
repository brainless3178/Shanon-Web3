use serde::{Deserialize, Serialize};

/// Represents a taint sink - where tainted data can cause harm
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSink {
    /// Direct lamports transfer
    LamportsTransfer { location: String },
    /// SPL Token transfer
    TokenTransfer { location: String },
    /// Cross-program invocation
    CPIInvoke {
        target_program: String,
        location: String,
    },
    /// State modification
    StateWrite { field: String, location: String },
    /// PDA derivation with user seeds
    PDADerivation { location: String },
    /// Authority check comparison
    AuthorityCheck { location: String },
    /// Arithmetic operation without bounds check
    UncheckedArithmetic { operation: String, location: String },
    /// Dangerous data usage in validation
    ValidationBypass { location: String },
}
