use alloy_primitives::Bytes;

use crate::storage::SubCallError;

/// Precompile error types.
///
/// Marked `#[non_exhaustive]` so adding future variants is forward-compatible
/// for downstream crates that match on this enum.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PrecompileError {
    /// Out of gas.
    #[error("out of gas")]
    OutOfGas,

    /// Storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// The node-local off-chain body backend could not serve this execution read.
    #[error("body read unavailable: {0}")]
    BodyReadUnavailable(String),

    /// The local consensus request expired while waiting for an off-chain read.
    #[error("body read request deadline exceeded")]
    BodyReadRequestDeadline,

    /// A body or body index violated its deterministic repository invariants.
    #[error("body read corruption: {0}")]
    BodyReadCorruption(String),

    /// Exact finalized compressed-entity tree materialization is unavailable
    /// to this node. This is local readiness, not evidence of block invalidity.
    #[error("compressed-entity tree unavailable: {0}")]
    TreeUnavailable(String),

    /// One transaction can never fit inside the configured CE work budget.
    #[error("transaction exceeds the compressed-entity work limit")]
    TransactionCeWorkLimitExceeded,

    /// This payload has exhausted its deterministic CE work budget.
    #[error("block compressed-entity work capacity exhausted")]
    BlockCeWorkCapacityExhausted,

    /// Write attempted during static call.
    #[error("write protection: cannot modify state during static call")]
    WriteProtection,

    /// User-triggerable error - transaction reverts but does not halt the EVM.
    #[error("revert: {0}")]
    Revert(String),

    /// Sub-call revert that carries the raw returndata bytes from the child
    /// frame. Used by sub-call API to surface Solidity revert payloads to the
    /// caller.
    #[error("revert with bytes: {0}")]
    RevertBytes(Bytes),

    /// Sub-call halt forwarded from `run_sub_call_impl`.
    #[error("sub-call error: {0}")]
    SubCall(SubCallError),

    /// Operation is not supported by this provider (e.g., `set_code` on
    /// `DirectStorageProvider`).
    #[error("unsupported operation")]
    Unsupported,

    /// Fatal / unrecoverable error.
    #[error("fatal: {0}")]
    Fatal(String),
}

/// Result type alias for precompile operations.
pub type Result<T> = std::result::Result<T, PrecompileError>;

impl From<SubCallError> for PrecompileError {
    fn from(value: SubCallError) -> Self {
        PrecompileError::SubCall(value)
    }
}
