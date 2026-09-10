use std::collections::BTreeSet;

use alloy_primitives::{Address, B256, U256};

use crate::{
    codec::{require_canonical_reencoding, CanonicalReader, CanonicalWriter},
    common::ProofBytes,
    error::ProtocolError,
    schema::{require, wire_struct, NestedCodec, SchemaLimits},
};

/// Per-request allocation/proof bound. It is not a total job or Tribute cap.
pub const MAX_FIDELITY_OWNERS_PER_OPENING: usize = 256;

wire_struct! {
    pub struct OpeningSubjectsV1 {
        pub owners: Vec<Address>,
        pub reference_isos: Vec<u16>,
    }
    validate = validate_opening_subjects;
}

wire_struct! {
    pub struct RawStorageSlotV1 {
        pub slot: B256,
        pub value: U256,
    }
}

wire_struct! {
    pub struct RawContractOpeningProofV1 {
        pub contract_address: Address,
        pub state_root: B256,
        pub ordered_slots: Vec<RawStorageSlotV1>,
        pub account_proof: ProofBytes,
        pub storage_proof: ProofBytes,
    }
    validate = validate_raw_contract_opening;
}

wire_struct! {
    pub struct LysisOpeningsProofV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub finalized_block_hash: B256,
        pub finalized_state_root: B256,
        pub wwd: u32,
        pub subjects: OpeningSubjectsV1,
        pub fidelity: RawContractOpeningProofV1,
        pub oracle: RawContractOpeningProofV1,
    }
    validate = validate_lysis_openings;
}

impl LysisOpeningsProofV1 {
    /// Validates the complete typed opening, including the generated aggregate
    /// byte ceiling that is stricter than the per-proof field cap.
    pub fn validate_profile(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)
    }
}

impl RawContractOpeningProofV1 {
    pub fn encode_canonical_record(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)?;
        let mut writer = CanonicalWriter::new(limits.codec);
        self.encode_nested(&mut writer, limits)?;
        Ok(writer.into_bytes())
    }

    pub fn decode_canonical_record(
        encoded: &[u8],
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        let mut reader = CanonicalReader::new(encoded, limits.codec)?;
        let opening = Self::decode_nested(&mut reader, limits)?;
        reader.finish()?;
        <Self as NestedCodec>::validate(&opening, limits)?;
        require_canonical_reencoding(encoded, &opening.encode_canonical_record(limits)?)?;
        Ok(opening)
    }
}

/// Partitions one complete canonical owner set into bounded node opening
/// requests. Every request carries the same complete Oracle ISO subject set;
/// callers publish one byte-identical Oracle opening after verification.
pub fn partition_lysis_opening_subjects(
    owners: &[Address],
    reference_isos: &[u16],
    limits: &SchemaLimits,
) -> Result<Vec<OpeningSubjectsV1>, ProtocolError> {
    require(!owners.is_empty(), "opening owner set must not be empty")?;
    require(
        owners.windows(2).all(|pair| pair[0] < pair[1]),
        "opening owners strictly ordered and unique",
    )?;
    require(
        !reference_isos.is_empty(),
        "opening reference ISO set must not be empty",
    )?;
    require(
        reference_isos.len() <= limits.max_collection_items,
        "opening reference ISO cap",
    )?;
    require(
        reference_isos.windows(2).all(|pair| pair[0] < pair[1]),
        "opening reference ISOs strictly ordered and unique",
    )?;
    require(
        reference_isos.contains(&840),
        "opening reference ISOs include mandatory 840",
    )?;

    let batch_count = owners.len().div_ceil(MAX_FIDELITY_OWNERS_PER_OPENING);
    let allocation_bytes = batch_count
        .checked_mul(core::mem::size_of::<OpeningSubjectsV1>())
        .ok_or(ProtocolError::IntegerOverflow {
            what: "opening request batch allocation bytes",
        })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(batch_count)
        .map_err(|_| ProtocolError::AllocationFailed {
            what: "opening request batches",
            bytes: allocation_bytes,
        })?;
    for batch in owners.chunks(MAX_FIDELITY_OWNERS_PER_OPENING) {
        let request = OpeningSubjectsV1 {
            owners: batch.to_vec(),
            reference_isos: reference_isos.to_vec(),
        };
        request.validate(limits)?;
        requests.push(request);
    }
    Ok(requests)
}

fn validate_opening_subjects(
    subjects: &OpeningSubjectsV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !subjects.owners.is_empty(),
        "opening owner set must not be empty",
    )?;
    require(
        subjects.owners.len() <= limits.max_collection_items,
        "opening owner cap",
    )?;
    require(
        subjects.owners.windows(2).all(|pair| pair[0] < pair[1]),
        "opening owners strictly ordered and unique",
    )?;
    require(
        !subjects.reference_isos.is_empty(),
        "opening reference ISO set must not be empty",
    )?;
    require(
        subjects.reference_isos.len() <= limits.max_collection_items,
        "opening reference ISO cap",
    )?;
    require(
        subjects
            .reference_isos
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "opening reference ISOs strictly ordered and unique",
    )?;
    require(
        subjects.reference_isos.contains(&840),
        "opening reference ISOs include mandatory 840",
    )
}

fn validate_raw_contract_opening(
    opening: &RawContractOpeningProofV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !opening.ordered_slots.is_empty(),
        "raw opening slot set must not be empty",
    )?;
    require(
        opening.ordered_slots.len() <= limits.max_collection_items,
        "raw opening slot cap",
    )?;
    require(
        opening.account_proof.0.len() <= limits.max_proof_bytes,
        "raw opening account proof cap",
    )?;
    require(
        opening.storage_proof.0.len() <= limits.max_proof_bytes,
        "raw opening storage proof cap",
    )?;
    let mut unique = BTreeSet::new();
    require(
        opening
            .ordered_slots
            .iter()
            .all(|slot| unique.insert(slot.slot)),
        "raw opening slots unique",
    )
}

fn validate_lysis_openings(
    openings: &LysisOpeningsProofV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    openings.subjects.validate(limits)?;
    openings.fidelity.validate(limits)?;
    openings.oracle.validate(limits)?;
    require(
        openings.fidelity.state_root == openings.finalized_state_root
            && openings.oracle.state_root == openings.finalized_state_root,
        "raw openings bind finalized state root",
    )?;
    let encoded_len = lysis_openings_encoded_len(openings)?;
    if encoded_len > limits.max_opening_bytes {
        return Err(ProtocolError::CapacityExceeded {
            what: "Lysis opening bytes",
            limit: limits.max_opening_bytes,
            actual: encoded_len,
        });
    }
    Ok(())
}

fn lysis_openings_encoded_len(openings: &LysisOpeningsProofV1) -> Result<usize, ProtocolError> {
    checked_sum([
        4 * 32,
        4,
        opening_subjects_encoded_len(&openings.subjects)?,
        raw_contract_opening_encoded_len(&openings.fidelity)?,
        raw_contract_opening_encoded_len(&openings.oracle)?,
    ])
}

fn opening_subjects_encoded_len(subjects: &OpeningSubjectsV1) -> Result<usize, ProtocolError> {
    checked_sum([
        4,
        checked_product(subjects.owners.len(), 20)?,
        4,
        checked_product(subjects.reference_isos.len(), 2)?,
    ])
}

fn raw_contract_opening_encoded_len(
    opening: &RawContractOpeningProofV1,
) -> Result<usize, ProtocolError> {
    checked_sum([
        20,
        32,
        4,
        checked_product(opening.ordered_slots.len(), 64)?,
        4,
        opening.account_proof.0.len(),
        4,
        opening.storage_proof.0.len(),
    ])
}

fn checked_product(count: usize, width: usize) -> Result<usize, ProtocolError> {
    count
        .checked_mul(width)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "Lysis opening byte length",
        })
}

fn checked_sum<const N: usize>(parts: [usize; N]) -> Result<usize, ProtocolError> {
    parts.into_iter().try_fold(0_usize, |total, part| {
        total
            .checked_add(part)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "Lysis opening byte length",
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::CodecLimits;

    #[test]
    fn total_opening_bytes_are_capped_even_when_each_proof_field_is_individually_valid() {
        let limits = SchemaLimits {
            codec: CodecLimits::new(1_048_576, 4_096, 2_097_152),
            max_bounded_bytes: 1_048_576,
            max_proof_bytes: 262_144,
            max_opening_bytes: 262_144,
            max_collection_items: 4_096,
            max_action_items: 4_096,
            max_chunk_items: 768,
            max_unit_inputs: 43,
            max_result_chunk_bytes: 524_288,
            max_control_body_bytes: 65_536,
        };
        let raw = |address| RawContractOpeningProofV1 {
            contract_address: address,
            state_root: B256::repeat_byte(0x41),
            ordered_slots: vec![RawStorageSlotV1 {
                slot: B256::repeat_byte(0x42),
                value: U256::from(7),
            }],
            account_proof: ProofBytes(vec![0x43; 200_000]),
            storage_proof: ProofBytes(vec![0x44; 200_000]),
        };
        let openings = LysisOpeningsProofV1 {
            protocol_bundle_hash: B256::repeat_byte(0x45),
            job_id: B256::repeat_byte(0x46),
            finalized_block_hash: B256::repeat_byte(0x47),
            finalized_state_root: B256::repeat_byte(0x41),
            wwd: 20_260_724,
            subjects: OpeningSubjectsV1 {
                owners: vec![Address::repeat_byte(0x48)],
                reference_isos: vec![840],
            },
            fidelity: raw(Address::repeat_byte(0x49)),
            oracle: raw(Address::repeat_byte(0x4a)),
        };

        assert!(validate_lysis_openings(&openings, &limits).is_err());
    }
}
