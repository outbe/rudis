use std::collections::BTreeSet;

use alloy_primitives::{B256, U256};

use crate::{
    codec::{require_canonical_reencoding, CanonicalReader, CanonicalWriter},
    common::BoundedBytes,
    error::ProtocolError,
    hash::hash_framed,
    list::{ordered_list_root, OrderedListLimits},
    opening::{LysisOpeningsProofV1, RawContractOpeningProofV1},
    profile::ProtocolBundleV1,
    registry::{HashDomain, ListKind},
    schema::{impl_top_level_codec, require, wire_enum_u8, wire_struct, NestedCodec, SchemaLimits},
};

const MAX_ORACLE_SETTLEMENT_ISOS: usize = 256;

wire_enum_u8! {
    pub enum InputChunkKind {
        Tribute = 1,
        Fidelity = 2,
        Oracle = 3,
    }
}

wire_enum_u8! {
    pub enum OpeningSourceKind {
        Fidelity = 1,
        Oracle = 2,
    }
}

wire_enum_u8! {
    pub enum Compression {
        None = 0,
    }
}

wire_struct! {
    pub struct CheckpointIdentityV1 {
        pub finalized_block_number: u64,
        pub finalized_block_hash: B256,
        pub finalized_state_root: B256,
        pub finalized_ce_root: B256,
        pub ce_schema_version: u16,
    }
}

wire_struct! {
    pub struct InputChunkRefV1 {
        pub kind: InputChunkKind,
        pub ordinal: u32,
        pub record_count: u32,
        pub first_key: BoundedBytes,
        pub last_key_inclusive: BoundedBytes,
        pub encoded_bytes: u64,
        pub semantic_digest: B256,
        pub transport_digest: B256,
    }
    validate = validate_input_chunk_ref;
}

wire_struct! {
    pub struct AuthenticatedOpeningV1 {
        pub source_kind: OpeningSourceKind,
        pub canonical_subject_key: BoundedBytes,
        pub canonical_value: BoundedBytes,
        pub opening_codec_id: B256,
        pub canonical_opening: BoundedBytes,
    }
    validate = validate_authenticated_opening;
}

wire_struct! {
    pub struct AuthenticatedInputChunkV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub kind: InputChunkKind,
        pub ordinal: u32,
        pub canonical_records_or_openings: Vec<BoundedBytes>,
    }
    validate = validate_input_chunk;
}
impl_top_level_codec!(AuthenticatedInputChunkV1, AuthenticatedInputChunkV1);

wire_struct! {
    pub struct InputManifestV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub checkpoint: CheckpointIdentityV1,
        pub wwd: u32,
        pub sealed_tribute_collection_key: B256,
        pub sealed_tribute_collection_root: B256,
        pub tribute_count: u32,
        pub tribute_nominal_total: U256,
        pub input_chunk_count: u32,
        pub input_chunk_list_root: B256,
        pub fidelity_opening_root: B256,
        pub oracle_opening_root: B256,
        pub exact_encoded_bytes: u64,
        pub exact_record_count: u32,
        pub body_codec_id: B256,
        pub opening_codec_registry_hash: B256,
        pub compression: Compression,
    }
    validate = validate_input_manifest;
}
impl_top_level_codec!(InputManifestV1, InputManifestV1);

impl AuthenticatedInputChunkV1 {
    pub fn semantic_digest(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        require(
            self.canonical_records_or_openings.len() <= limits.max_chunk_items,
            "input chunk item cap",
        )?;
        hash_framed(HashDomain::InputChunk, &self.encode_canonical(limits)?)
    }
}

impl InputChunkRefV1 {
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
        let reference = Self::decode_nested(&mut reader, limits)?;
        reader.finish()?;
        <Self as NestedCodec>::validate(&reference, limits)?;
        require_canonical_reencoding(encoded, &reference.encode_canonical_record(limits)?)?;
        Ok(reference)
    }
}

impl AuthenticatedOpeningV1 {
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

    pub fn validate_against_bundle(
        &self,
        bundle: &ProtocolBundleV1,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)?;
        bundle.validate_lysis_v1_input_codecs()?;
        let expected = match self.source_kind {
            OpeningSourceKind::Fidelity => bundle.fidelity_opening_codec_id,
            OpeningSourceKind::Oracle => bundle.oracle_opening_codec_id,
        };
        require(
            self.opening_codec_id == expected,
            "authenticated opening source codec binding",
        )
    }

    pub fn decode_and_validate_raw_opening(
        &self,
        checkpoint_state_root: B256,
        limits: &SchemaLimits,
    ) -> Result<RawContractOpeningProofV1, ProtocolError> {
        let opening =
            RawContractOpeningProofV1::decode_canonical_record(&self.canonical_opening.0, limits)?;
        require(
            opening.state_root == checkpoint_state_root,
            "authenticated opening checkpoint state root",
        )?;
        require(
            self.canonical_value.0 == canonical_slot_values(&opening, limits)?,
            "authenticated opening canonical slot values",
        )?;
        Ok(opening)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedOpeningsV1 {
    pub fidelity: AuthenticatedOpeningV1,
    pub oracle: AuthenticatedOpeningV1,
}

/// Converts the already authenticated node handoff into the exact source
/// records committed by the input manifest. MPT verification remains the
/// caller's responsibility and must happen before this pure materialization.
pub fn materialize_authenticated_openings(
    openings: &LysisOpeningsProofV1,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<MaterializedOpeningsV1, ProtocolError> {
    openings.validate_profile(limits)?;
    bundle.validate_lysis_v1_input_codecs()?;
    require(
        openings.protocol_bundle_hash == bundle.protocol_bundle_hash(limits)?,
        "Lysis openings protocol bundle binding",
    )?;

    let fidelity = AuthenticatedOpeningV1 {
        source_kind: OpeningSourceKind::Fidelity,
        canonical_subject_key: BoundedBytes(canonical_fidelity_subject(&openings.subjects.owners)?),
        canonical_value: BoundedBytes(canonical_slot_values(&openings.fidelity, limits)?),
        opening_codec_id: bundle.fidelity_opening_codec_id,
        canonical_opening: BoundedBytes(canonical_raw_opening(&openings.fidelity, limits)?),
    };
    fidelity.validate_against_bundle(bundle, limits)?;

    let oracle = AuthenticatedOpeningV1 {
        source_kind: OpeningSourceKind::Oracle,
        canonical_subject_key: BoundedBytes(canonical_oracle_subject(
            openings.wwd,
            &openings.subjects.reference_isos,
        )?),
        canonical_value: BoundedBytes(canonical_slot_values(&openings.oracle, limits)?),
        opening_codec_id: bundle.oracle_opening_codec_id,
        canonical_opening: BoundedBytes(canonical_raw_opening(&openings.oracle, limits)?),
    };
    oracle.validate_against_bundle(bundle, limits)?;
    Ok(MaterializedOpeningsV1 { fidelity, oracle })
}

pub fn authenticated_opening_root(
    source_kind: OpeningSourceKind,
    openings: &[AuthenticatedOpeningV1],
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
    list_limits: OrderedListLimits,
) -> Result<B256, ProtocolError> {
    require(!openings.is_empty(), "authenticated opening list empty")?;
    let mut seen_subjects = BTreeSet::new();
    let allocation_bytes = openings
        .len()
        .checked_mul(core::mem::size_of::<Vec<u8>>())
        .ok_or(ProtocolError::IntegerOverflow {
            what: "authenticated opening list allocation bytes",
        })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(openings.len())
        .map_err(|_| ProtocolError::AllocationFailed {
            what: "authenticated opening list encoding",
            bytes: allocation_bytes,
        })?;
    for opening in openings {
        require(
            opening.source_kind == source_kind,
            "authenticated opening list source kind",
        )?;
        opening.validate_against_bundle(bundle, limits)?;
        require(
            seen_subjects.insert(opening.canonical_subject_key.0.as_slice()),
            "authenticated opening subject unique",
        )?;
        encoded.push(opening.encode_canonical_record(limits)?);
    }
    let kind = match source_kind {
        OpeningSourceKind::Fidelity => ListKind::FidelityOpenings,
        OpeningSourceKind::Oracle => ListKind::OracleOpenings,
    };
    ordered_list_root(kind, &encoded, list_limits)
}

fn canonical_fidelity_subject(
    owners: &[alloy_primitives::Address],
) -> Result<Vec<u8>, ProtocolError> {
    require(
        !owners.is_empty() && owners.len() <= crate::opening::MAX_FIDELITY_OWNERS_PER_OPENING,
        "Fidelity opening owner batch bound",
    )?;
    require(
        owners.windows(2).all(|pair| pair[0] < pair[1]),
        "Fidelity opening owners canonical",
    )?;
    let count = u32::try_from(owners.len()).map_err(|_| ProtocolError::IntegerOverflow {
        what: "Fidelity opening owner count",
    })?;
    let capacity = 4_usize
        .checked_add(
            owners
                .len()
                .checked_mul(20)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Fidelity opening subject bytes",
                })?,
        )
        .ok_or(ProtocolError::IntegerOverflow {
            what: "Fidelity opening subject bytes",
        })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ProtocolError::AllocationFailed {
            what: "Fidelity opening subject",
            bytes: capacity,
        })?;
    encoded.extend_from_slice(&count.to_be_bytes());
    for owner in owners {
        encoded.extend_from_slice(owner.as_slice());
    }
    Ok(encoded)
}

fn canonical_oracle_subject(wwd: u32, isos: &[u16]) -> Result<Vec<u8>, ProtocolError> {
    require(
        !isos.is_empty() && isos.len() <= MAX_ORACLE_SETTLEMENT_ISOS,
        "Oracle opening ISO bound",
    )?;
    require(
        isos.windows(2).all(|pair| pair[0] < pair[1]) && isos.contains(&840),
        "Oracle opening ISOs canonical",
    )?;
    let count = u16::try_from(isos.len()).map_err(|_| ProtocolError::IntegerOverflow {
        what: "Oracle opening ISO count",
    })?;
    let capacity = 6_usize
        .checked_add(
            isos.len()
                .checked_mul(2)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Oracle opening subject bytes",
                })?,
        )
        .ok_or(ProtocolError::IntegerOverflow {
            what: "Oracle opening subject bytes",
        })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ProtocolError::AllocationFailed {
            what: "Oracle opening subject",
            bytes: capacity,
        })?;
    encoded.extend_from_slice(&wwd.to_be_bytes());
    encoded.extend_from_slice(&count.to_be_bytes());
    for iso in isos {
        encoded.extend_from_slice(&iso.to_be_bytes());
    }
    Ok(encoded)
}

fn canonical_slot_values(
    opening: &RawContractOpeningProofV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    require(
        !opening.ordered_slots.is_empty()
            && opening.ordered_slots.len() <= limits.max_collection_items,
        "authenticated opening slot count",
    )?;
    let count =
        u32::try_from(opening.ordered_slots.len()).map_err(|_| ProtocolError::IntegerOverflow {
            what: "authenticated opening slot count",
        })?;
    let capacity = 4_usize
        .checked_add(opening.ordered_slots.len().checked_mul(64).ok_or(
            ProtocolError::IntegerOverflow {
                what: "authenticated opening slot values bytes",
            },
        )?)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "authenticated opening slot values bytes",
        })?;
    require(
        capacity <= limits.max_bounded_bytes,
        "authenticated opening slot values byte cap",
    )?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| ProtocolError::AllocationFailed {
            what: "authenticated opening slot values",
            bytes: capacity,
        })?;
    encoded.extend_from_slice(&count.to_be_bytes());
    for slot in &opening.ordered_slots {
        encoded.extend_from_slice(slot.slot.as_slice());
        encoded.extend_from_slice(&slot.value.to_be_bytes::<32>());
    }
    Ok(encoded)
}

fn canonical_raw_opening(
    opening: &RawContractOpeningProofV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>, ProtocolError> {
    opening.encode_canonical_record(limits)
}

impl InputManifestV1 {
    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.tribute_count > 0
                && self.input_chunk_count > 0
                && self.exact_record_count >= self.tribute_count
                && self.exact_encoded_bytes > 0
                && !self.input_chunk_list_root.is_zero(),
            "input manifest committed population",
        )?;
        let _ = limits;
        Ok(())
    }

    pub fn manifest_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(HashDomain::InputManifest, &self.encode_canonical(limits)?)
    }

    pub fn validate_against_bundle(
        &self,
        bundle: &ProtocolBundleV1,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        self.validate_semantics(limits)?;
        bundle.validate_lysis_v1_input_codecs()?;
        require(
            self.protocol_bundle_hash == bundle.protocol_bundle_hash(limits)?,
            "input manifest protocol bundle binding",
        )?;
        require(
            self.body_codec_id == bundle.tribute_body_codec_id,
            "input manifest Tribute body codec binding",
        )?;
        require(
            self.opening_codec_registry_hash == bundle.opening_codec_registry_hash()?,
            "input manifest opening codec registry binding",
        )
    }
}

fn validate_authenticated_opening(
    opening: &AuthenticatedOpeningV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !opening.canonical_subject_key.0.is_empty()
            && !opening.canonical_value.0.is_empty()
            && !opening.opening_codec_id.is_zero()
            && !opening.canonical_opening.0.is_empty(),
        "authenticated opening committed bytes",
    )
}

fn validate_input_chunk_ref(
    reference: &InputChunkRefV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        reference.record_count > 0
            && !reference.first_key.0.is_empty()
            && !reference.last_key_inclusive.0.is_empty()
            && reference.first_key.0 <= reference.last_key_inclusive.0
            && reference.encoded_bytes > 0
            && !reference.semantic_digest.is_zero()
            && !reference.transport_digest.is_zero(),
        "input chunk reference committed range",
    )
}

fn validate_input_chunk(
    chunk: &AuthenticatedInputChunkV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        chunk.canonical_records_or_openings.len() <= limits.max_chunk_items,
        "input chunk item cap",
    )
}

fn validate_input_manifest(
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    manifest.validate_semantics(limits)
}
