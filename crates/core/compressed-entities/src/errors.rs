use thiserror::Error;

/// Failure returned by the finalized-parent body/index adapter.
#[derive(Debug, Error)]
pub enum ParentBodySourceError {
    /// The node-local consensus request expired while waiting for the body.
    /// This is request cancellation, not backend unavailability.
    #[error("parent body source request deadline exceeded: {0}")]
    RequestDeadline(String),
    /// The local backend could not serve the request. This is not canonical
    /// absence and must enter the ADR-005 recovery path.
    #[error("parent body source unavailable: {0}")]
    Unavailable(String),
    /// The local projection violated a canonical body/index invariant.
    #[error("parent body source corruption: {0}")]
    Corruption(String),
}

impl From<ParentBodySourceError> for outbe_primitives::error::PrecompileError {
    fn from(value: ParentBodySourceError) -> Self {
        match value {
            ParentBodySourceError::RequestDeadline(_) => Self::BodyReadRequestDeadline,
            ParentBodySourceError::Unavailable(message) => Self::BodyReadUnavailable(message),
            ParentBodySourceError::Corruption(message) => Self::BodyReadCorruption(message),
        }
    }
}
