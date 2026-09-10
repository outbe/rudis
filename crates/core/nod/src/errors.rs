use outbe_primitives::error::PrecompileError;
use thiserror::Error;

use crate::NodRepositoryError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NodError {
    #[error("invalid nodId length")]
    InvalidNodIdLength,

    #[error("invalid nodId hex")]
    InvalidNodIdHex,

    #[error("nod not found")]
    NodNotFound,

    #[error("bucket not found")]
    BucketNotFound,

    #[error("index out of bounds")]
    IndexOutOfBounds,

    #[error("nod query exceeds the runtime result limit")]
    QueryLimitExceeded,

    #[error("reference currency must be a nonzero ISO 4217 numeric code")]
    ZeroReferenceCurrency,
}

impl From<NodError> for PrecompileError {
    fn from(value: NodError) -> Self {
        PrecompileError::Revert(value.to_string())
    }
}

impl From<NodRepositoryError> for PrecompileError {
    fn from(value: NodRepositoryError) -> Self {
        use outbe_offchain_storage::StorageErrorKind;

        match value {
            NodRepositoryError::Storage(error)
                if error.kind() == StorageErrorKind::RequestDeadline =>
            {
                PrecompileError::BodyReadRequestDeadline
            }
            NodRepositoryError::Storage(error) if error.kind() == StorageErrorKind::Unavailable => {
                PrecompileError::BodyReadUnavailable(error.to_string())
            }
            other => PrecompileError::BodyReadCorruption(other.to_string()),
        }
    }
}
