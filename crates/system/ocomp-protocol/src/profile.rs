use alloy_primitives::B256;

use crate::{
    codec::CodecLimits,
    error::ProtocolError,
    generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1,
    hash::hash_framed,
    registry::HashDomain,
    schema::{impl_top_level_codec, wire_enum_u8, wire_struct, SchemaLimits},
};

/// Generated measurement ceilings shared by every OCOMP PoC process.
///
/// These compile ceilings do not arm a network or provide a bundle hash.
#[must_use]
pub fn poc_schema_limits() -> SchemaLimits {
    let candidate = OCOMP_POC_CANDIDATE_LIMITS_V1;
    let max_body_bytes = usize::try_from(candidate.max_activation_ocb1_bytes)
        .expect("generated body cap fits usize");
    let max_collection_items = usize::try_from(candidate.max_protocol_collection_items)
        .expect("generated item cap fits usize");
    SchemaLimits {
        codec: CodecLimits::new(
            max_body_bytes,
            max_collection_items,
            usize::try_from(candidate.max_transaction_rlp_bytes)
                .expect("generated allocation cap fits usize"),
        ),
        max_bounded_bytes: max_body_bytes,
        max_proof_bytes: usize::try_from(candidate.max_finalized_intent_proof_bytes)
            .expect("generated proof cap fits usize"),
        max_opening_bytes: usize::try_from(candidate.max_opening_bytes)
            .expect("generated opening cap fits usize"),
        max_collection_items,
        max_action_items: usize::try_from(
            candidate
                .max_nod_actions_per_result_chunk
                .min(candidate.max_contributor_actions_per_result_chunk),
        )
        .expect("generated per-result-chunk action cap fits usize"),
        max_chunk_items: usize::try_from(candidate.max_records_per_input_chunk)
            .expect("generated per-chunk record cap fits usize"),
        max_unit_inputs: usize::try_from(candidate.max_inputs_per_work_unit)
            .expect("generated per-unit input cap fits usize"),
        max_result_chunk_bytes: candidate.max_result_chunk_bytes,
        // Local control transports typed off-chain proofs and openings as well
        // as compact activation data. Method codecs enforce their narrower
        // limits; the frame ceiling must not reject a body accepted by the
        // shared canonical codec.
        max_control_body_bytes: max_body_bytes,
    }
}

wire_enum_u8! {
    /// Closed program registry for the PoC.
    pub enum ProgramId {
        LysisV1 = 1,
    }
}

wire_struct! {
    pub struct CorrectnessProfileV1 {
        pub profile_id: B256,
        pub program: ProgramId,
        pub arithmetic_profile_id: B256,
        pub object_codec_registry_hash: B256,
        pub list_root_scheme_id: B256,
        pub result_signature_profile_id: B256,
        pub finality_verifier_profile_id: B256,
    }
}
impl_top_level_codec!(CorrectnessProfileV1, CorrectnessProfileV1);

wire_struct! {
    pub struct CapacityProfileV1 {
        pub profile_id: B256,
        pub max_tributes_per_work_shard: u32,
        pub max_workers_per_domain: u8,
        pub max_intents_per_block: u8,
        pub max_activations_per_block: u8,
        pub max_ready_inspections_per_block: u8,
        pub max_expirations_per_block: u8,
        pub ready_backoff_blocks: u64,
        pub max_reference_currencies: u16,
        pub max_oracle_wwd_pair_entries: u32,
        pub max_active_scurve_entries: u32,
        pub result_deadline_blocks: u64,
        pub source_retention_after_terminal_blocks: u64,
        pub generated_limits_manifest_hash: B256,
    }
}
impl_top_level_codec!(CapacityProfileV1, CapacityProfileV1);

wire_struct! {
    pub struct ProtocolBundleV1 {
        pub protocol_version: u16,
        pub fork_id: B256,
        pub intent_codec_id: B256,
        pub finalized_intent_proof_codec_id: B256,
        pub tribute_body_codec_id: B256,
        pub fidelity_opening_codec_id: B256,
        pub oracle_opening_codec_id: B256,
        pub result_codec_id: B256,
        pub action_codec_id: B256,
        pub activation_codec_id: B256,
        pub evidence_codec_id: B256,
        pub request_semantics_version: u16,
        pub lysis_program_semantics_hash: B256,
        pub planner_spec_version: u16,
        pub reducer_spec_version: u16,
        pub activation_apply_semantics_hash: B256,
        pub effect_contract_registry_hash: B256,
        pub object_codec_registry_hash: B256,
        pub correctness_profile_id: B256,
        pub capacity_profile_id: B256,
        pub result_signature_profile_id: B256,
        pub finality_verifier_and_vote_domain_id: B256,
        pub consensus_committee_history_schema_version: u16,
        pub ocomp_committee_schema_version: u16,
        pub proof_system_and_verifier_key_id: Option<B256>,
        pub da_codec_and_binding_verifier_id: Option<B256>,
        pub anti_equivocation_journal_schema_hash: B256,
        pub mode_pause_revocation_semantics_hash: B256,
        pub upgrade_fsm_semantics_hash: B256,
        pub release_requirement_catalog_sequence: u64,
        pub release_requirement_catalog_hash: B256,
        pub release_requirement_catalog_parent_hash: B256,
        pub release_gate_authority_envelope_hash: B256,
        pub release_approval_policy_hash: B256,
        pub release_validator_command_artifact_hash: B256,
        pub consensus_state_schema_version: u16,
        pub migration_manifest_hash: B256,
        pub required_upgrade_handler_set_hash: B256,
    }
}
impl_top_level_codec!(ProtocolBundleV1, ProtocolBundleV1);

impl ProtocolBundleV1 {
    pub fn protocol_bundle_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        hash_framed(HashDomain::ProtocolBundle, &self.encode_canonical(limits)?)
    }

    pub fn opening_codec_registry_hash(&self) -> Result<B256, ProtocolError> {
        let mut payload = Vec::with_capacity(68);
        payload.extend_from_slice(&2_u16.to_be_bytes());
        payload.push(1);
        payload.extend_from_slice(self.fidelity_opening_codec_id.as_slice());
        payload.push(2);
        payload.extend_from_slice(self.oracle_opening_codec_id.as_slice());
        hash_framed(HashDomain::OpeningCodecRegistry, &payload)
    }

    pub fn validate_lysis_v1_input_codecs(&self) -> Result<(), ProtocolError> {
        crate::schema::require(
            self.tribute_body_codec_id == crate::registry::TRIBUTE_BODY_CODEC_ID
                && self.fidelity_opening_codec_id == crate::registry::FIDELITY_OPENING_CODEC_ID
                && self.oracle_opening_codec_id == crate::registry::ORACLE_OPENING_CODEC_ID,
            "unsupported Lysis V1 input codec bundle",
        )
    }
}
