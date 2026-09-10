use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GemError {
    #[error("gem is non-transferable")]
    NonTransferable,

    #[error("gem not found")]
    GemNotFound,

    #[error("invalid state transition")]
    InvalidState,

    #[error("floor price not met")]
    FloorPriceNotMet,

    #[error("oracle nominal unavailable")]
    OracleUnavailable,

    #[error("index out of bounds")]
    IndexOutOfBounds,

    #[error("invalid owner")]
    InvalidOwner,

    #[error("gem already exists")]
    AlreadyExists,
}

impl From<GemError> for PrecompileError {
    fn from(value: GemError) -> Self {
        PrecompileError::Revert(value.to_string())
    }
}
