use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RadicleRegistryError {
    #[error("Radicle repository id must be non-zero")]
    ZeroRepositoryId,
    #[error("Radicle repository is already registered")]
    AlreadyRegistered,
    #[error("Radicle repository registry capacity {maximum} reached")]
    CapacityReached { maximum: u32 },
    #[error("Radicle repository index {index} is outside count {count}")]
    IndexOutOfBounds { index: u32, count: u32 },
}

impl From<RadicleRegistryError> for PrecompileError {
    fn from(error: RadicleRegistryError) -> Self {
        Self::Revert(error.to_string())
    }
}
