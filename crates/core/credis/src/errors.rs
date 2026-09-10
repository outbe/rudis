//! Module-local error types for the Credis position contract.
//!
//! Errors that are not credis-specific (out-of-gas, generic revert) come from
//! `outbe_primitives::error::PrecompileError`.

use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CredisError {
    #[error("position not found")]
    PositionNotFound,
    #[error("position already exists")]
    PositionAlreadyExists,
    #[error("position is closed")]
    PositionClosed,
    #[error("amount must be positive")]
    InvalidAmount,
    #[error("invalid position state value: {0}")]
    InvalidStateValue(u8),
    #[error("payment is below the interest accrued since the last settlement")]
    PaymentBelowAccruedInterest,
    #[error("position is not called")]
    NotCalled,
    #[error("call window has not lapsed")]
    CallWindowOpen,
    #[error("position has no outstanding principal")]
    NothingOutstanding,
    #[error("credis arithmetic overflow")]
    ArithmeticOverflow,
    #[error("index out of bounds")]
    IndexOutOfBounds,
}

impl From<CredisError> for PrecompileError {
    fn from(err: CredisError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
