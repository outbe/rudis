use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum GovernanceError {
    #[error("not authorized")]
    NotAuthorized,

    #[error("not the proposal author")]
    NotAuthor,

    #[error("proposal not found")]
    ProposalNotFound,

    #[error("invalid status transition")]
    InvalidStatusTransition,

    #[error("invalid status value")]
    InvalidStatus,

    #[error("text is not editable in the current status")]
    TextNotEditableInStatus,

    #[error("text must not be empty")]
    EmptyText,

    #[error("text exceeds the maximum size")]
    TextTooLarge,

    #[error("invalid diff base (expected 0 = canon or 1 = meta-canon)")]
    InvalidDiffBase,

    #[error("invalid vote payload")]
    InvalidPayload,
}

impl From<GovernanceError> for PrecompileError {
    fn from(value: GovernanceError) -> Self {
        PrecompileError::Revert(value.to_string())
    }
}
