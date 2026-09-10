//! Canonical replay-visible carrier for validator-authenticated OCOMP actions.
//!
//! The signed EIP-1559 envelope is propagated and replayed like any other
//! transaction, but its `gas_limit` is a protocol marker rather than the budget
//! for the OCOMP precompile work. Pool and execution must classify this exact
//! shape before ordinary Ethereum intrinsic-gas handling.

use alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE;
use alloy_primitives::{Address, U256};

use crate::{
    abi::{
        decode_materialize_certified_nods_calldata, MATERIALIZE_CERTIFIED_NODS_SELECTOR,
        METADOSIS_ADDRESS, NOD_FACTORY_ADDRESS, SUBMIT_LYSIS_RESULT_SELECTOR,
    },
    vote::{decode_submit_lysis_result_prefix, ResultVotePrefixV1},
    ProtocolError, SchemaLimits,
};

/// Exact visible gas marker signed into every OCOMP system carrier.
pub const OCOMP_SYSTEM_CARRIER_GAS_LIMIT: u64 = 30_000;

/// Per-carrier internal execution ceiling, separate from Ethereum user gas.
pub const OCOMP_SYSTEM_CARRIER_INTERNAL_GAS_LIMIT: u64 =
    crate::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1.max_activation_internal_work;

/// Public-pool compatibility floor for the signed EIP-1559 fee cap.
///
/// The carrier never debits this fee after system authorization succeeds.
pub const MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS: u128 = MIN_PROTOCOL_BASE_FEE as u128;

/// Maximum exact ABI envelope for `submitLysisResult(bytes)` under the pinned
/// OCOMP schema profile.
pub const MAX_OCOMP_SYSTEM_CARRIER_CALLDATA_BYTES: usize = 68
    + ((crate::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1.max_result_vote_bytes as usize + 31)
        & !31);

/// Execution-layer-independent view of one signed transaction envelope.
#[derive(Debug, Clone, Copy)]
pub struct OcompSystemCarrierView<'a> {
    pub is_eip1559: bool,
    pub to: Option<Address>,
    pub value: U256,
    pub input: &'a [u8],
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: Option<u128>,
}

/// Canonical routing data retained after stateless carrier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcompSystemCarrierCandidate {
    ResultVote {
        prefix: ResultVotePrefixV1,
    },
    NodMaterialization {
        queue_sequence: u64,
        first_nod_ordinal: u32,
    },
}

/// Strict rejection for a transaction that targets an OCOMP system selector
/// but does not satisfy the canonical carrier envelope.
#[derive(Debug, thiserror::Error)]
pub enum OcompSystemCarrierError {
    #[error("OCOMP system carrier must be one EIP-1559 transaction")]
    NotEip1559,
    #[error("OCOMP system carrier must not transfer native value")]
    NonZeroValue,
    #[error("OCOMP system carrier priority fee must be exactly zero")]
    NonZeroPriorityFee,
    #[error("OCOMP system carrier max fee {actual} is below protocol minimum {minimum}")]
    FeeCapTooLow { actual: u128, minimum: u128 },
    #[error("OCOMP system carrier gas limit must be exactly {expected}, got {actual}")]
    WrongGasLimit { actual: u64, expected: u64 },
    #[error("OCOMP system carrier calldata size {actual} exceeds limit {limit}")]
    CalldataTooLarge { actual: usize, limit: usize },
    #[error("malformed canonical OCOMP result vote carrier: {0}")]
    MalformedVote(#[source] ProtocolError),
    #[error("malformed canonical OCOMP NOD materialization carrier: {0}")]
    MalformedMaterialization(#[source] ProtocolError),
}

/// Classifies the exact OCOMP system carrier without reading chain state.
///
/// `Ok(None)` is reserved for transactions that do not target
/// an OCOMP system action. Once a target and selector match, every envelope or
/// payload defect is a fail-closed error rather than a fallback to ordinary
/// transaction execution.
pub fn classify_ocomp_system_carrier(
    tx: OcompSystemCarrierView<'_>,
    limits: &SchemaLimits,
) -> Result<Option<OcompSystemCarrierCandidate>, OcompSystemCarrierError> {
    let is_vote = tx.to == Some(METADOSIS_ADDRESS)
        && tx.input.get(..4) == Some(SUBMIT_LYSIS_RESULT_SELECTOR.as_slice());
    let is_materialization = tx.to == Some(NOD_FACTORY_ADDRESS)
        && tx.input.get(..4) == Some(MATERIALIZE_CERTIFIED_NODS_SELECTOR.as_slice());
    if !is_vote && !is_materialization {
        return Ok(None);
    }
    if !tx.is_eip1559 {
        return Err(OcompSystemCarrierError::NotEip1559);
    }
    if !tx.value.is_zero() {
        return Err(OcompSystemCarrierError::NonZeroValue);
    }
    if tx.max_priority_fee_per_gas != Some(0) {
        return Err(OcompSystemCarrierError::NonZeroPriorityFee);
    }
    if tx.max_fee_per_gas < MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS {
        return Err(OcompSystemCarrierError::FeeCapTooLow {
            actual: tx.max_fee_per_gas,
            minimum: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
        });
    }
    if tx.gas_limit != OCOMP_SYSTEM_CARRIER_GAS_LIMIT {
        return Err(OcompSystemCarrierError::WrongGasLimit {
            actual: tx.gas_limit,
            expected: OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
        });
    }
    let calldata_limit = if is_vote {
        MAX_OCOMP_SYSTEM_CARRIER_CALLDATA_BYTES
    } else {
        68 + ((limits.codec.max_body_bytes + crate::codec::OCB1_HEADER_LEN + 31) & !31)
    };
    if tx.input.len() > calldata_limit {
        return Err(OcompSystemCarrierError::CalldataTooLarge {
            actual: tx.input.len(),
            limit: calldata_limit,
        });
    }
    if is_vote {
        let prefix = decode_submit_lysis_result_prefix(tx.input, limits)
            .map_err(OcompSystemCarrierError::MalformedVote)?;
        Ok(Some(OcompSystemCarrierCandidate::ResultVote { prefix }))
    } else {
        let batch = decode_materialize_certified_nods_calldata(tx.input, limits)
            .map_err(OcompSystemCarrierError::MalformedMaterialization)?;
        Ok(Some(OcompSystemCarrierCandidate::NodMaterialization {
            queue_sequence: batch.queue_sequence,
            first_nod_ordinal: batch.first_nod_ordinal,
        }))
    }
}
