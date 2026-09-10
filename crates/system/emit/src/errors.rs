//! Emit domain errors.
//!
//! User-facing failures are `Error(string)`-style reverts with frozen texts
//! (the `Emit …` list in the precompile plan). Infrastructure and
//! invariant failures — a credited balance smaller than the burn, CRS
//! initialization — map to [`PrecompileError::Fatal`] and are never
//! converted into "invalid proof". Verification-phase backend errors are
//! raised on caller-supplied proof bytes, cannot be distinguished from
//! rejected input at the backend seam, and therefore revert (see
//! `runtime::mint`); promoting them to fatal would let any caller trigger a
//! consensus-visible fatal error with a malformed proof tail.

use alloy_primitives::U256;
use outbe_primitives::error::PrecompileError;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum EmitError {
    #[error("Emit is not initialized")]
    NotInitialized,
    #[error("Emit burn value must be non-zero")]
    BurnValueZero,
    #[error("Emit {0} is not a canonical BN254 field")]
    NonCanonicalField(&'static str),
    #[error("Emit {0} must be non-zero")]
    MustBeNonZero(&'static str),
    #[error("Emit mint proof is malformed: {0}")]
    MalformedProof(String),
    #[error("Emit mint proof statement does not match calldata")]
    StatementMismatch,
    #[error("Emit chain ID does not match runtime")]
    ChainIdMismatch,
    #[error("Emit note owner must be non-zero")]
    OwnerZero,
    #[error("Emit payout recipient must be non-zero")]
    RecipientZero,
    #[error("Emit mint units must be non-zero")]
    MintUnitsZero,
    #[error("Emit caller is not note owner")]
    NotNoteOwner,
    #[error("Emit root is not recent")]
    RootNotRecent,
    #[error("Emit nullifier has already been spent")]
    NullifierSpent,
    #[error("Emit proof is invalid")]
    ProofInvalid,
    #[error("Emit commitment tree is full")]
    TreeFull,
    #[error("Emit commitment already exists")]
    CommitmentExists,
    #[error("Emit payout balance overflow")]
    PayoutOverflow,
    /// Fatal: revm credits `msg.value` before dispatch, so the Emit balance
    /// can never be smaller than the burn unless accounting is corrupted.
    #[error("Emit balance is smaller than the credited burn ({balance} < {credited})")]
    UnderfundedBurn { balance: U256, credited: U256 },
    /// Fatal: Barretenberg CRS initialization failure, never a user proof
    /// verdict. Backend errors raised while verifying caller-supplied bytes
    /// revert as malformed proofs instead (see `runtime::mint`).
    #[error("ZK verifier unavailable: {0}")]
    VerifierUnavailable(String),
}

impl From<EmitError> for PrecompileError {
    fn from(error: EmitError) -> Self {
        match error {
            EmitError::UnderfundedBurn { .. } | EmitError::VerifierUnavailable(_) => {
                PrecompileError::Fatal(error.to_string())
            }
            _ => PrecompileError::Revert(error.to_string()),
        }
    }
}
