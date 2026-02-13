//! Forge Error Definitions

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ForgeError {
    #[error("Transaction building failed: {0}")]
    BuildFailed(String),

    #[error("Exploit execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Proof conversion failed: {0}")]
    ConversionFailed(String),

    #[error("IO error: {0}")]
    IoError(String),
}
