use std::collections::BTreeSet;

use alloy_primitives::{Address, B256, U256};

use crate::{
    codec::{require_canonical_reencoding, CanonicalReader, CanonicalWriter},
    control::CasObjectRefV1,
    error::ProtocolError,
    hash::hash_framed,
    intent::{DayType, JobIntentV1},
    list::verify_ordered_list_membership,
    registry::{HashDomain, ListKind, ObjectKind},
    schema::{impl_top_level_codec, require, wire_enum_u8, wire_struct, NestedCodec, SchemaLimits},
};

wire_enum_u8! {
    pub enum CompletionStatus {
        Completed = 1,
    }
}

wire_enum_u8! {
    pub enum CarryOverReason {
        UnusedLysis = 1,
    }
}

wire_struct! {
    pub struct NodActionV1 {
        pub raw_ordinal: u32,
        pub tribute_id: B256,
        pub nod_id: B256,
        pub owner: Address,
        pub wwd: u32,
        pub league_id: u16,
        pub floor_price_minor: U256,
        pub gratis_load_minor: U256,
        pub entry_price_minor: U256,
        pub cost_amount_minor: U256,
        pub issuance_currency: u16,
        pub reference_currency: u16,
        pub issued_at: u64,
        pub bucket_key: B256,
    }
}

/// Finalized on-chain authority against which one Nod membership proof is
/// checked.
///
/// This value is deliberately not a self-authenticating wire object. A caller
/// must derive it from finalized `ActiveGenerationV1` and the matching Nod
/// owner generation projection; the proof cannot supply its own trusted root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveNodSetV1 {
    pub job_id: B256,
    pub program_semantics_hash: B256,
    pub worldwide_day: u32,
    pub generation: u64,
    pub nod_root: B256,
    pub nod_count: u32,
}

wire_struct! {
    /// One canonical Nod body and its bottom-up path in the certified
    /// `ListKind::NodActions` population.
    pub struct NodMembershipProofV1 {
        pub job_id: B256,
        pub program_semantics_hash: B256,
        pub worldwide_day: u32,
        pub generation: u64,
        pub nod_ordinal: u32,
        pub action: NodActionV1,
        pub membership_siblings: Vec<B256>,
    }
    validate = validate_nod_membership_proof;
}

wire_struct! {
    pub struct ContributorActionV1 {
        pub owner: Address,
        pub source_tribute_id: B256,
        pub nominal_amount_minor: U256,
    }
}

wire_struct! {
    pub struct CarryOverCreditActionV1 {
        pub source_wwd: u32,
        pub reason: CarryOverReason,
        pub amount: U256,
    }
}

wire_struct! {
    pub struct MetadosisCompletionSummaryV1 {
        pub wwd: u32,
        pub pending_nonce: u64,
        pub day_type: DayType,
        pub tribute_nominal_total: U256,
        pub day_limit: U256,
        pub gratis_demand: U256,
        pub gratis_supply: U256,
        pub lysis_budget: U256,
        pub auction_base: U256,
        pub nod_gratis_consumed: U256,
        pub unused_lysis: U256,
        pub carry_over_credit: U256,
        pub status: CompletionStatus,
        pub logical_evaluation_height: u64,
        pub logical_evaluation_time: u64,
    }
}

wire_struct! {
    /// One bounded, independently retrievable chunk of the complete Lysis
    /// effect set. The full result commits an ordered list root of these chunks;
    /// it never embeds all actions in one consensus object.
    pub struct ResultChunkV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub chunk_ordinal: u32,
        pub first_nod_ordinal: u32,
        pub ordered_nod_actions: Vec<NodActionV1>,
        pub ordered_eligible_contributors: Vec<ContributorActionV1>,
    }
    validate = validate_result_chunk;
}
impl_top_level_codec!(ResultChunkV1, ResultChunkV1);

wire_struct! {
    /// Canonical semantic-to-transport binding for one result chunk.
    ///
    /// The reference deliberately carries no path or validator-local namespace.
    pub struct OutputManifestEntryV1 {
        pub chunk_ordinal: u32,
        pub result_chunk_hash: B256,
        pub result_chunk_ref: CasObjectRefV1,
    }
    validate = validate_output_manifest_entry;
}

wire_struct! {
    pub struct ExactCountsV1 {
        pub tribute_count: u32,
        pub nod_count: u32,
        pub bucket_count: u32,
        pub contributor_count: u32,
        pub semantic_event_count: u32,
    }
}

wire_struct! {
    pub struct ConservationTotalsV1 {
        pub tribute_nominal_total: U256,
        pub eligible_nominal_total: U256,
        pub day_limit: U256,
        pub gratis_demand: U256,
        pub gratis_supply: U256,
        pub lysis_budget: U256,
        pub auction_base: U256,
        pub nod_gratis_consumed: U256,
        pub unused_lysis: U256,
        pub carry_over_credit: U256,
        pub nod_cost_total: U256,
    }
}

wire_struct! {
    pub struct ResultRootsV1 {
        pub nod_root: B256,
        pub bucket_root: B256,
        pub contributor_root: B256,
        pub output_manifest_root: B256,
    }
}

wire_struct! {
    pub struct LysisArithmeticSummaryV1 {
        pub input_manifest_hash: B256,
        pub plan_hash: B256,
        pub unit_artifact_root: B256,
        pub fidelity_fraction_root: B256,
        pub gratis_prefix_root: B256,
        pub roots: ResultRootsV1,
        pub counts: ExactCountsV1,
        pub conservation: ConservationTotalsV1,
        pub first_error_ordinal: Option<u32>,
    }
}
impl_top_level_codec!(LysisArithmeticSummaryV1, LysisArithmeticSummaryV1);

wire_struct! {
    pub struct LysisResultV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub input_manifest_hash: B256,
        pub plan_hash: B256,
        pub unit_artifact_root: B256,
        pub fidelity_fraction_root: B256,
        pub gratis_prefix_root: B256,
        pub result_chunk_count: u32,
        pub result_chunk_list_root: B256,
        pub carry_over_credit: CarryOverCreditActionV1,
        pub metadosis_completion_summary: MetadosisCompletionSummaryV1,
        pub tribute_count: u32,
        pub tribute_nominal_total: U256,
        pub unused_lysis: U256,
        pub roots: ResultRootsV1,
        pub counts: ExactCountsV1,
        pub conservation: ConservationTotalsV1,
        pub arithmetic_commitment: B256,
        pub event_summary_hash: B256,
    }
    validate = validate_lysis_result;
}
impl_top_level_codec!(LysisResultV1, LysisResultV1);

wire_struct! {
    pub struct ActivationPayloadV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub result_chunk_count: u32,
        pub result_chunk_list_root: B256,
        pub roots: ResultRootsV1,
        pub counts: ExactCountsV1,
        pub conservation: ConservationTotalsV1,
        pub arithmetic_commitment: B256,
        pub event_summary_hash: B256,
    }
    validate = validate_activation_payload;
}
impl_top_level_codec!(ActivationPayloadV1, ActivationPayloadV1);

pub fn lysis_v1_empty_semantic_event_root() -> Result<B256, ProtocolError> {
    hash_framed(
        HashDomain::ListEmpty,
        &ListKind::SemanticEventRecords.id().to_be_bytes(),
    )
}

fn validate_lysis_v1_event_commitment(
    counts: &ExactCountsV1,
    event_summary_hash: B256,
) -> Result<(), ProtocolError> {
    require(
        counts.semantic_event_count == 0
            && event_summary_hash == lysis_v1_empty_semantic_event_root()?,
        "LYSIS_V1 empty semantic event commitment",
    )
}

impl ResultChunkV1 {
    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.ordered_nod_actions.len() <= limits.max_action_items
                && self.ordered_eligible_contributors.len() <= limits.max_action_items,
            "action stream item cap",
        )?;
        let mut tribute_ids = BTreeSet::new();
        let mut nod_ids = BTreeSet::new();
        let mut owners = BTreeSet::new();
        for (index, action) in self.ordered_nod_actions.iter().enumerate() {
            let expected_ordinal = self
                .first_nod_ordinal
                .checked_add(
                    u32::try_from(index).map_err(|_| ProtocolError::IntegerOverflow {
                        what: "result chunk local Nod ordinal",
                    })?,
                )
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "result chunk Nod ordinal",
                })?;
            require(
                action.raw_ordinal == expected_ordinal,
                "result chunk Nod ordinals gap-free",
            )?;
            require(tribute_ids.insert(action.tribute_id), "unique tribute id")?;
            require(nod_ids.insert(action.nod_id), "unique nod id")?;
            require(owners.insert(action.owner), "unique nod owner")?;
            if let Some(previous) = index
                .checked_sub(1)
                .and_then(|previous| self.ordered_nod_actions.get(previous))
            {
                require(
                    (previous.raw_ordinal, previous.tribute_id)
                        < (action.raw_ordinal, action.tribute_id),
                    "nod actions strictly ordered",
                )?;
            }
        }
        for pair in self.ordered_eligible_contributors.windows(2) {
            require(
                (pair[0].owner, pair[0].source_tribute_id)
                    < (pair[1].owner, pair[1].source_tribute_id),
                "contributors strictly ordered",
            )?;
        }
        Ok(())
    }

    pub fn result_chunk_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(HashDomain::ResultChunk, &self.encode_canonical(limits)?)
    }
}

impl OutputManifestEntryV1 {
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
        let entry = Self::decode_nested(&mut reader, limits)?;
        reader.finish()?;
        <Self as NestedCodec>::validate(&entry, limits)?;
        require_canonical_reencoding(encoded, &entry.encode_canonical_record(limits)?)?;
        Ok(entry)
    }
}

impl NodActionV1 {
    pub fn encode_canonical_record(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)?;
        let mut writer = CanonicalWriter::new(limits.codec);
        self.encode_nested(&mut writer, limits)?;
        Ok(writer.into_bytes())
    }
}

impl ActiveNodSetV1 {
    fn validate(&self) -> Result<(), ProtocolError> {
        require(
            !self.job_id.is_zero()
                && !self.program_semantics_hash.is_zero()
                && self.worldwide_day != 0
                && self.generation != 0
                && !self.nod_root.is_zero()
                && self.nod_count != 0,
            "active Nod set authority",
        )
    }
}

impl NodMembershipProofV1 {
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
        let proof = Self::decode_nested(&mut reader, limits)?;
        reader.finish()?;
        <Self as NestedCodec>::validate(&proof, limits)?;
        require_canonical_reencoding(encoded, &proof.encode_canonical_record(limits)?)?;
        Ok(proof)
    }

    /// Verifies the complete public read against authority obtained separately
    /// from finalized chain state.
    pub fn verify_against<'action>(
        &'action self,
        authority: &ActiveNodSetV1,
        limits: &SchemaLimits,
    ) -> Result<&'action NodActionV1, ProtocolError> {
        authority.validate()?;
        <Self as NestedCodec>::validate(self, limits)?;
        require(
            self.job_id == authority.job_id
                && self.program_semantics_hash == authority.program_semantics_hash
                && self.worldwide_day == authority.worldwide_day
                && self.generation == authority.generation,
            "Nod proof active generation binding",
        )?;
        require(
            self.nod_ordinal == self.action.raw_ordinal
                && self.action.wwd == authority.worldwide_day,
            "Nod proof action binding",
        )?;
        let canonical_action = self.action.encode_canonical_record(limits)?;
        verify_ordered_list_membership(
            ListKind::NodActions,
            authority.nod_count,
            self.nod_ordinal,
            &canonical_action,
            &self.membership_siblings,
            authority.nod_root,
        )?;
        Ok(&self.action)
    }
}

impl ContributorActionV1 {
    pub fn encode_canonical_record(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)?;
        let mut writer = CanonicalWriter::new(limits.codec);
        self.encode_nested(&mut writer, limits)?;
        Ok(writer.into_bytes())
    }
}

fn validate_nod_membership_proof(
    proof: &NodMembershipProofV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    let proof_bytes = proof
        .membership_siblings
        .len()
        .checked_mul(core::mem::size_of::<B256>())
        .ok_or(ProtocolError::IntegerOverflow {
            what: "Nod membership proof bytes",
        })?;
    require(
        !proof.job_id.is_zero()
            && !proof.program_semantics_hash.is_zero()
            && proof.worldwide_day != 0
            && proof.generation != 0
            && proof.membership_siblings.len() <= u32::BITS as usize
            && proof_bytes <= limits.max_proof_bytes,
        "Nod membership proof shape",
    )
}

impl LysisResultV1 {
    #[must_use]
    pub fn arithmetic_summary(&self) -> LysisArithmeticSummaryV1 {
        LysisArithmeticSummaryV1 {
            input_manifest_hash: self.input_manifest_hash,
            plan_hash: self.plan_hash,
            unit_artifact_root: self.unit_artifact_root,
            fidelity_fraction_root: self.fidelity_fraction_root,
            gratis_prefix_root: self.gratis_prefix_root,
            roots: self.roots.clone(),
            counts: self.counts.clone(),
            conservation: self.conservation.clone(),
            first_error_ordinal: None,
        }
    }

    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.result_chunk_count > 0 && !self.result_chunk_list_root.is_zero(),
            "result committed chunk population",
        )?;
        require(
            self.tribute_count > 0
                && self.tribute_count == self.counts.tribute_count
                && self.tribute_count == self.counts.nod_count
                && self.counts.contributor_count <= self.tribute_count
                && self.counts.bucket_count <= self.tribute_count,
            "result exact counts",
        )?;
        validate_lysis_v1_event_commitment(&self.counts, self.event_summary_hash)?;
        require(
            self.tribute_nominal_total == self.conservation.tribute_nominal_total
                && self.unused_lysis == self.conservation.unused_lysis,
            "result scalar conservation binding",
        )?;
        let split_sum = self
            .conservation
            .lysis_budget
            .checked_add(self.conservation.auction_base)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "day budget conservation",
            })?;
        // Bounded, not exact: the unissued headroom returns to the warehouse (see the split receipt).
        require(
            split_sum <= self.conservation.day_limit,
            "day budget conservation",
        )?;
        let lysis_sum = self
            .conservation
            .nod_gratis_consumed
            .checked_add(self.conservation.unused_lysis)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "Lysis budget conservation",
            })?;
        require(
            lysis_sum == self.conservation.lysis_budget,
            "Lysis budget conservation",
        )?;
        require(
            self.conservation.carry_over_credit == self.unused_lysis
                && self.carry_over_credit.reason == CarryOverReason::UnusedLysis
                && self.carry_over_credit.amount == self.unused_lysis
                && self.carry_over_credit.source_wwd == self.metadosis_completion_summary.wwd,
            "carry-over conservation",
        )?;
        let completion = &self.metadosis_completion_summary;
        require(
            completion.tribute_nominal_total == self.tribute_nominal_total
                && completion.day_limit == self.conservation.day_limit
                && completion.gratis_demand == self.conservation.gratis_demand
                && completion.gratis_supply == self.conservation.gratis_supply
                && completion.lysis_budget == self.conservation.lysis_budget
                && completion.auction_base == self.conservation.auction_base
                && completion.nod_gratis_consumed == self.conservation.nod_gratis_consumed
                && completion.unused_lysis == self.conservation.unused_lysis
                && completion.carry_over_credit == self.conservation.carry_over_credit,
            "Metadosis completion conservation binding",
        )?;
        let arithmetic = self.arithmetic_summary();
        let commitment = hash_framed(
            HashDomain::LysisArithmetic,
            &arithmetic.encode_canonical(limits)?,
        )?;
        require(
            commitment == self.arithmetic_commitment,
            "arithmetic commitment",
        )
    }

    /// Canonical semantic identity of the complete constant-size Lysis result.
    ///
    /// The digest deliberately covers fields that were not present in the
    /// superseded activation payload (manifest/plan/unit roots, carry-over
    /// action, completion summary and explicit Tribute totals).
    pub fn result_digest(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(HashDomain::Result, &self.encode_canonical(limits)?)
    }

    /// Canonical evidence object retained by the applied generation.
    ///
    /// Unlike the result digest's signing domain, this domain identifies the
    /// complete result as terminal evidence. Quorum metadata is retained
    /// separately in `OcompCompletedBindingV1`.
    pub fn result_evidence_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(HashDomain::ResultEvidence, &self.encode_canonical(limits)?)
    }

    pub fn activation_payload(
        &self,
        limits: &SchemaLimits,
    ) -> Result<ActivationPayloadV1, ProtocolError> {
        self.validate_semantics(limits)?;
        Ok(ActivationPayloadV1 {
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.job_id,
            attempt: self.attempt,
            result_chunk_count: self.result_chunk_count,
            result_chunk_list_root: self.result_chunk_list_root,
            roots: self.roots.clone(),
            counts: self.counts.clone(),
            conservation: self.conservation.clone(),
            arithmetic_commitment: self.arithmetic_commitment,
            event_summary_hash: self.event_summary_hash,
        })
    }

    pub fn validate_finalized_intent(&self, intent: &JobIntentV1) -> Result<(), ProtocolError> {
        let completion = &self.metadosis_completion_summary;
        let frozen = &intent.frozen_metadosis_values;
        require(
            self.protocol_bundle_hash == intent.protocol_bundle_hash
                && self.attempt == intent.attempt
                && self.tribute_count == intent.authenticated_day_count
                && self.tribute_nominal_total == intent.authenticated_day_nominal
                && completion.wwd == intent.wwd
                && completion.pending_nonce == intent.pending_nonce
                && completion.day_type == frozen.day_type
                && completion.day_limit == frozen.day_limit
                && completion.gratis_demand == frozen.gratis_demand
                && completion.gratis_supply == frozen.gratis_supply
                && completion.lysis_budget == frozen.lysis_budget
                && completion.auction_base == frozen.auction_base
                && completion.status == CompletionStatus::Completed
                && completion.logical_evaluation_height == intent.logical_evaluation_height
                && completion.logical_evaluation_time == intent.logical_evaluation_time,
            "result finalized intent binding",
        )
    }
}

fn validate_result_chunk(
    chunk: &ResultChunkV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    chunk.validate_semantics(limits)
}

fn validate_output_manifest_entry(
    value: &OutputManifestEntryV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !value.result_chunk_hash.is_zero(),
        "output manifest semantic chunk hash",
    )?;
    require(
        !value.result_chunk_ref.transport_digest.is_zero(),
        "output manifest transport digest",
    )?;
    require(
        value.result_chunk_ref.encoded_bytes > 0
            && value.result_chunk_ref.encoded_bytes <= limits.max_result_chunk_bytes,
        "output manifest exact chunk byte cap",
    )?;
    require(
        value.result_chunk_ref.expected_ocb1_kind == Some(ObjectKind::ResultChunkV1.tag()),
        "output manifest ResultChunkV1 kind",
    )
}

fn validate_lysis_result(
    result: &LysisResultV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    result.validate_semantics(limits)
}

fn validate_activation_payload(
    payload: &ActivationPayloadV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        payload.result_chunk_count > 0 && !payload.result_chunk_list_root.is_zero(),
        "activation committed result chunks",
    )?;
    validate_lysis_v1_event_commitment(&payload.counts, payload.event_summary_hash)
}
