use alloy_primitives::{address, b256, Address, B256, U256};

use crate::nod_materialization::NodMaterializationBatchV1;
use crate::{vote::ResultVoteV1, ProtocolError, SchemaLimits};

pub const METADOSIS_ADDRESS: Address = address!("000000000000000000000000000000000000100e");
pub const NOD_FACTORY_ADDRESS: Address = address!("0000000000000000000000000000000000001007");

pub const SUBMIT_LYSIS_RESULT_SELECTOR: [u8; 4] = [0x80, 0x58, 0x4e, 0x19];
pub const MATERIALIZE_CERTIFIED_NODS_SELECTOR: [u8; 4] = [0xa8, 0xfd, 0x21, 0x1d];
pub const GET_OFFCHAIN_JOB_SELECTOR: [u8; 4] = [0x4c, 0x13, 0x2d, 0x3d];
pub const GET_OFFCHAIN_VOTE_ACCOUNTABILITY_SELECTOR: [u8; 4] = [0xff, 0x98, 0xdf, 0x7a];
pub const GET_ACTIVE_LYSIS_GENERATION_SELECTOR: [u8; 4] = [0x50, 0xf8, 0xb3, 0xe4];
pub const GET_LYSIS_TERMINAL_RECEIPT_SELECTOR: [u8; 4] = [0x20, 0xf4, 0x6b, 0xe7];
pub const OCOMP_ACTIVATION_REJECTED_SELECTOR: [u8; 4] = [0x8e, 0x34, 0x68, 0x03];
pub const OCOMP_RESULT_VOTE_REJECTED_SELECTOR: [u8; 4] = [0xdd, 0x8b, 0xa0, 0x84];

pub const OCOMP_REQUESTED_TOPIC0: B256 =
    b256!("69a11b11a3b39ad0968d02a67ee3b9e2d790cb9aafbc4de957beed93c39b7dad");
pub const OCOMP_EXPIRED_TOPIC0: B256 =
    b256!("b64fbb190e984aacb53ee095943ebdf40566c8da9a5811e168f546cb796d6c26");
pub const LYSIS_ACTIVATED_TOPIC0: B256 =
    b256!("f9f846ebfcc5895f442c47e436aeb0a86c170ad48a7863eb9f9dddb0a4492f68");

pub const OCOMP_LIFECYCLE_BEGIN_SELECTOR: [u8; 4] = *b"OSE2";
pub const OCOMP_TERMINAL_REQUEST_SELECTOR: [u8; 4] = *b"OSR2";

pub const OCOMP_ACTIVATION_REJECTION_CODES: core::ops::RangeInclusive<u8> = 1..=17;

/// Encodes the one canonical public ingress for a validator result vote.
pub fn encode_submit_lysis_result_calldata(
    vote: &ResultVoteV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    let payload = vote.encode_canonical(limits)?;
    let vote_cap = usize::try_from(
        crate::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1.max_result_vote_bytes,
    )
    .map_err(|_| ProtocolError::InvalidInvariant("result vote byte cap"))?;
    if payload.len() > vote_cap {
        return Err(ProtocolError::CapacityExceeded {
            what: "result vote bytes",
            limit: vote_cap,
            actual: payload.len(),
        });
    }
    let padded_len = payload
        .len()
        .checked_add(31)
        .map(|value| value & !31)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "result vote ABI padding",
        })?;
    let total_len = 68_usize
        .checked_add(padded_len)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "result vote ABI calldata",
        })?;
    let mut calldata = vec![0_u8; total_len];
    calldata[..4].copy_from_slice(&SUBMIT_LYSIS_RESULT_SELECTOR);
    calldata[4..36].copy_from_slice(&U256::from(32).to_be_bytes::<32>());
    calldata[36..68].copy_from_slice(&U256::from(payload.len()).to_be_bytes::<32>());
    calldata[68..68 + payload.len()].copy_from_slice(&payload);
    Ok(calldata)
}

pub fn encode_materialize_certified_nods_calldata(
    batch: &NodMaterializationBatchV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    encode_dynamic_bytes_call(
        MATERIALIZE_CERTIFIED_NODS_SELECTOR,
        &batch.encode_canonical(limits)?,
    )
}

pub fn decode_materialize_certified_nods_calldata(
    calldata: &[u8],
    limits: &SchemaLimits,
) -> Result<NodMaterializationBatchV1, ProtocolError> {
    let payload = decode_dynamic_bytes_call(
        calldata,
        MATERIALIZE_CERTIFIED_NODS_SELECTOR,
        limits.codec.max_body_bytes + crate::codec::OCB1_HEADER_LEN,
    )?;
    NodMaterializationBatchV1::decode_canonical(payload, limits)
}

fn encode_dynamic_bytes_call(selector: [u8; 4], payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let padded_len = payload
        .len()
        .checked_add(31)
        .map(|value| value & !31)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "dynamic ABI padding",
        })?;
    let total_len = 68_usize
        .checked_add(padded_len)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "dynamic ABI calldata",
        })?;
    let mut calldata = vec![0_u8; total_len];
    calldata[..4].copy_from_slice(&selector);
    calldata[4..36].copy_from_slice(&U256::from(32).to_be_bytes::<32>());
    calldata[36..68].copy_from_slice(&U256::from(payload.len()).to_be_bytes::<32>());
    calldata[68..68 + payload.len()].copy_from_slice(payload);
    Ok(calldata)
}

fn decode_dynamic_bytes_call(
    calldata: &[u8],
    selector: [u8; 4],
    payload_cap: usize,
) -> Result<&[u8], ProtocolError> {
    const ABI_HEAD_LEN: usize = 68;
    if calldata.len() < ABI_HEAD_LEN {
        return Err(ProtocolError::UnexpectedEof {
            offset: 0,
            needed: ABI_HEAD_LEN,
            remaining: calldata.len(),
        });
    }
    if calldata[..4] != selector {
        return Err(ProtocolError::InvalidInvariant("dynamic ABI selector"));
    }
    let mut expected_offset = [0_u8; 32];
    expected_offset[31] = 32;
    if calldata[4..36] != expected_offset {
        return Err(ProtocolError::InvalidInvariant("dynamic ABI offset"));
    }
    let length_word = U256::from_be_slice(&calldata[36..68]);
    let payload_len = usize::try_from(length_word).map_err(|_| ProtocolError::IntegerOverflow {
        what: "dynamic ABI payload length",
    })?;
    if payload_len > payload_cap {
        return Err(ProtocolError::CapacityExceeded {
            what: "dynamic ABI payload bytes",
            limit: payload_cap,
            actual: payload_len,
        });
    }
    let padded_len = payload_len.checked_add(31).map(|value| value & !31).ok_or(
        ProtocolError::IntegerOverflow {
            what: "dynamic ABI padding",
        },
    )?;
    let expected_len =
        ABI_HEAD_LEN
            .checked_add(padded_len)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "dynamic ABI calldata length",
            })?;
    if calldata.len() != expected_len {
        return Err(ProtocolError::InvalidInvariant("dynamic ABI length"));
    }
    let payload_end =
        ABI_HEAD_LEN
            .checked_add(payload_len)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "dynamic ABI payload end",
            })?;
    if !calldata[payload_end..].iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidInvariant("dynamic ABI padding"));
    }
    Ok(&calldata[ABI_HEAD_LEN..payload_end])
}
