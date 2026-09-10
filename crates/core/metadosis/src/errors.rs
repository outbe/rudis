use alloy_primitives::{Bytes, B256, U256};
use outbe_ocomp_protocol::abi::{
    OCOMP_ACTIVATION_REJECTED_SELECTOR, OCOMP_RESULT_VOTE_REJECTED_SELECTOR,
};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MetadosisError {
    #[error("worldwide day type is UNKNOWN")]
    UnknownWorldwideDayType,

    #[error("VWAP must be non-zero")]
    VwapMustBeNonZero,

    #[error(
        "invalid OCOMP budget split: lysis budget {lysis_budget} exceeds day limit {day_limit}"
    )]
    InvalidOcompBudgetSplit { day_limit: U256, lysis_budget: U256 },

    #[error("existing OCOMP request budget receipt does not match the immutable day split")]
    OcompBudgetReceiptMismatch,

    #[error("Desis returned a different OCOMP request brief hash")]
    OcompDesisBriefHashMismatch,

    #[error("OCOMP pre-admission state is not initialized for WWD {wwd}")]
    OcompPreAdmissionNotInitialized { wwd: WorldwideDay },

    #[error("OCOMP pre-admission envelope is already sealed for WWD {wwd}")]
    OcompPreAdmissionAlreadySealed { wwd: WorldwideDay },

    #[error("OCOMP pre-admission envelope WWD {actual} does not match state WWD {expected}")]
    OcompPreAdmissionWwdMismatch { expected: WorldwideDay, actual: u32 },

    #[error("invalid OCOMP pre-admission envelope: {reason}")]
    InvalidOcompPreAdmissionEnvelope { reason: String },

    #[error("OCOMP pre-admission envelope produced the reserved zero hash")]
    InvalidOcompPreAdmissionEnvelopeHash,

    #[error("OCOMP state version overflow for WWD {wwd}")]
    OcompStateVersionOverflow { wwd: WorldwideDay },

    #[error(
        "existing OCOMP pre-admission state for WWD {wwd} is corrupt: initialized={initialized}, version={state_version}, hash={envelope_hash}"
    )]
    CorruptOcompPreAdmissionState {
        wwd: WorldwideDay,
        initialized: bool,
        state_version: u64,
        envelope_hash: B256,
    },

    #[error("cannot mark WWD {wwd} as COMPLETED from status {current} (requires READY)")]
    InvalidTransitionToCompleted { wwd: WorldwideDay, current: u8 },

    #[error("cannot mark WWD {wwd} as FAILED: day is already COMPLETED")]
    InvalidTransitionToFailed { wwd: WorldwideDay },
}

impl From<MetadosisError> for PrecompileError {
    fn from(value: MetadosisError) -> Self {
        let message = value.to_string();
        match value {
            MetadosisError::UnknownWorldwideDayType
            | MetadosisError::VwapMustBeNonZero
            | MetadosisError::InvalidOcompBudgetSplit { .. }
            | MetadosisError::OcompDesisBriefHashMismatch => business_failure(message),
            MetadosisError::OcompBudgetReceiptMismatch
            | MetadosisError::OcompPreAdmissionNotInitialized { .. }
            | MetadosisError::OcompPreAdmissionAlreadySealed { .. }
            | MetadosisError::OcompPreAdmissionWwdMismatch { .. }
            | MetadosisError::InvalidOcompPreAdmissionEnvelope { .. }
            | MetadosisError::InvalidOcompPreAdmissionEnvelopeHash
            | MetadosisError::OcompStateVersionOverflow { .. }
            | MetadosisError::CorruptOcompPreAdmissionState { .. }
            | MetadosisError::InvalidTransitionToCompleted { .. }
            | MetadosisError::InvalidTransitionToFailed { .. } => storage_corruption(message),
        }
    }
}

pub type MetadosisResult<T> = std::result::Result<T, MetadosisError>;

/// Sole constructor for fatal Metadosis failures. Callers must use it only
/// when authenticated persisted state cannot satisfy its storage invariants.
pub(crate) fn storage_corruption(message: String) -> PrecompileError {
    PrecompileError::Fatal(message)
}

pub(crate) fn storage_corruption_message(message: impl Into<String>) -> PrecompileError {
    storage_corruption(message.into())
}

pub(crate) fn caller_rejection(message: impl Into<String>) -> PrecompileError {
    PrecompileError::Revert(message.into())
}

pub(crate) fn business_failure(message: impl Into<String>) -> PrecompileError {
    PrecompileError::Revert(format!("Metadosis business failure: {}", message.into()))
}

pub(crate) fn is_business_failure(error: &PrecompileError) -> bool {
    matches!(error, PrecompileError::Revert(message) if message.starts_with("Metadosis business failure: "))
}

pub(crate) fn activation_rejection(code: u16) -> PrecompileError {
    encoded_rejection(OCOMP_ACTIVATION_REJECTED_SELECTOR, code)
}

pub(crate) fn result_vote_rejection(code: u16) -> PrecompileError {
    encoded_rejection(OCOMP_RESULT_VOTE_REJECTED_SELECTOR, code)
}

fn encoded_rejection(selector: [u8; 4], code: u16) -> PrecompileError {
    let mut encoded = Vec::with_capacity(36);
    encoded.extend_from_slice(&selector);
    encoded.extend_from_slice(&U256::from(code).to_be_bytes::<32>());
    PrecompileError::RevertBytes(Bytes::from(encoded))
}

pub(crate) mod activation_rejection_code {
    pub const LIMIT_EXCEEDED: u16 = 2;
    pub const FORK_OR_BUNDLE_MISMATCH: u16 = 3;
    pub const JOB_BINDING_INVALID: u16 = 9;
    pub const COMMITTEE_SNAPSHOT_INVALID: u16 = 10;
    pub const RESULT_DIGEST_MISMATCH: u16 = 12;
    pub const RESULT_STRUCTURE_INVALID: u16 = 13;
    pub const ACTIVATION_PRECONDITIONS_CHANGED: u16 = 14;
}

pub(crate) mod vote_rejection_code {
    pub const MALFORMED_ENCODING: u16 = 1;
    pub const LIMIT_EXCEEDED: u16 = 2;
    pub const CALL_MODE: u16 = 3;
    pub const PROTOCOL_VOTE: u16 = 4;
    pub const LIFECYCLE_INACTIVE: u16 = 5;
    pub const DEADLINE_PASSED: u16 = 6;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_invariant_errors_are_fatal() {
        let wwd = WorldwideDay::new(2026_0731);
        let errors = [
            MetadosisError::OcompBudgetReceiptMismatch,
            MetadosisError::OcompStateVersionOverflow { wwd },
            MetadosisError::CorruptOcompPreAdmissionState {
                wwd,
                initialized: true,
                state_version: 0,
                envelope_hash: B256::ZERO,
            },
        ];

        for error in errors {
            let error: PrecompileError = error.into();
            assert!(matches!(error, PrecompileError::Fatal(_)));
        }
    }

    #[test]
    fn deterministic_calculation_errors_are_business_failures() {
        let error: PrecompileError = MetadosisError::VwapMustBeNonZero.into();

        assert!(matches!(error, PrecompileError::Revert(_)));
    }
}
