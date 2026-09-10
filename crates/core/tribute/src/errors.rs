use outbe_primitives::error::PrecompileError;
use thiserror::Error;

use crate::TributeRepositoryError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TributeError {
    #[error("tribute not found")]
    TributeNotFound,

    #[error("tribute already exists")]
    TributeAlreadyExists,

    #[error("invalid owner")]
    InvalidOwner,

    #[error("settlement amount must be positive")]
    SettlementAmountMustBePositive,

    #[error("worldwide day is sealed")]
    WorldwideDaySealed,

    #[error("tribute pre-admission inputs are sealed")]
    PreAdmissionSealed,

    #[error("sealed Tribute collection root must be non-zero")]
    InvalidSealedCollectionRoot,

    #[error("Tribute OCOMP profile is not initialized")]
    OcompProfileNotReady,

    #[error("owner balance overflow")]
    OwnerBalanceOverflow,

    #[error("tribute query exceeds the runtime result limit")]
    QueryLimitExceeded,
}

impl From<TributeError> for PrecompileError {
    fn from(value: TributeError) -> Self {
        PrecompileError::Revert(value.to_string())
    }
}

impl From<TributeRepositoryError> for PrecompileError {
    fn from(value: TributeRepositoryError) -> Self {
        use outbe_offchain_storage::StorageErrorKind;

        let message = value.to_string();
        match &value {
            TributeRepositoryError::Storage(error)
                if error.kind() == StorageErrorKind::RequestDeadline =>
            {
                PrecompileError::BodyReadRequestDeadline
            }
            TributeRepositoryError::Storage(error)
                if error.kind() == StorageErrorKind::Unavailable =>
            {
                PrecompileError::BodyReadUnavailable(message)
            }
            TributeRepositoryError::Storage(_)
            | TributeRepositoryError::CanonicalBody(_)
            | TributeRepositoryError::InvalidPageLimit { .. }
            | TributeRepositoryError::MalformedPrimaryKey
            | TributeRepositoryError::MalformedIndexKey { .. }
            | TributeRepositoryError::NonEmptyIndexValue { .. }
            | TributeRepositoryError::IndexMetadata { .. }
            | TributeRepositoryError::DanglingIndex { .. }
            | TributeRepositoryError::PrimaryKeyBodyMismatch { .. }
            | TributeRepositoryError::IndexedOwnerMismatch { .. }
            | TributeRepositoryError::IndexedDayMismatch { .. }
            | TributeRepositoryError::InvalidDayCursor { .. }
            | TributeRepositoryError::NonAscendingIdPage { .. }
            | TributeRepositoryError::InvalidPageContinuation { .. }
            | TributeRepositoryError::UntrackedProjectionIdentity { .. }
            | TributeRepositoryError::MissingCurrentBodyForRetention { .. }
            | TributeRepositoryError::RetainedDayMismatch { .. }
            | TributeRepositoryError::RetainedIdentity(_)
            | TributeRepositoryError::RetainedCommitment(_)
            | TributeRepositoryError::ConflictingRetainedBody { .. }
            | TributeRepositoryError::RetainedCommitmentMismatch { .. }
            | TributeRepositoryError::RetainedMetadata { .. }
            | TributeRepositoryError::DanglingRetainedIndex { .. }
            | TributeRepositoryError::MissingRetainedIndex { .. }
            | TributeRepositoryError::NonAscendingRetainedPage { .. }
            | TributeRepositoryError::InvalidRetainedCursor { .. }
            | TributeRepositoryError::InvalidRetainedContinuation { .. }
            | TributeRepositoryError::RetainedNamespaceMismatch { .. } => {
                PrecompileError::BodyReadCorruption(message)
            }
        }
    }
}

pub type TributeResult<T> = std::result::Result<T, TributeError>;
