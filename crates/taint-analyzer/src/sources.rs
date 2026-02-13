use serde::{Deserialize, Serialize};

/// Represents a taint source - where untrusted data enters the program
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintSource {
    /// Instruction data from transaction
    InstructionData { param_name: String },
    /// Unchecked account passed by user
    UncheckedAccount { account_name: String },
    /// Remaining accounts array
    RemainingAccounts,
    /// External oracle data
    OracleData { feed_name: String },
    /// Deserialized account data without validation
    DeserializedData { account_name: String },
    /// User-provided PDA seeds
    UserProvidedSeeds { seed_expr: String },
    /// Account data field access
    AccountFieldData { account: String, field: String },
}
