use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::{FinalizedJobSpecV1, FinalizedJobSummaryV1},
    intent::{
        ActivationPreconditionsV1, AuctionEntryPriceSource, ContributorTargetPreconditionV1,
        DayType, FrozenMetadosisValuesV1, JobIntentV1, MetadosisAttemptPreconditionV1,
        MetadosisExpectedStatus, NodTargetPreconditionV1, ReferenceEntryPriceV1,
        TributeInputBindingV1,
    },
    profile::poc_schema_limits,
    profile::ProtocolBundleV1,
    registry::{FIDELITY_OPENING_CODEC_ID, ORACLE_OPENING_CODEC_ID, TRIBUTE_BODY_CODEC_ID},
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(if byte == 0 { 0xff } else { byte })
}

pub fn protocol_bundle() -> ProtocolBundleV1 {
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(1),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: ORACLE_OPENING_CODEC_ID,
        result_codec_id: hash(4),
        action_codec_id: hash(5),
        activation_codec_id: hash(6),
        evidence_codec_id: hash(7),
        request_semantics_version: 1,
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: hash(9),
        effect_contract_registry_hash: hash(10),
        object_codec_registry_hash: hash(11),
        correctness_profile_id: hash(12),
        capacity_profile_id: hash(13),
        result_signature_profile_id: hash(14),
        finality_verifier_and_vote_domain_id: hash(15),
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: hash(16),
        mode_pause_revocation_semantics_hash: hash(17),
        upgrade_fsm_semantics_hash: hash(18),
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: hash(19),
        release_requirement_catalog_parent_hash: hash(20),
        release_gate_authority_envelope_hash: hash(21),
        release_approval_policy_hash: hash(22),
        release_validator_command_artifact_hash: hash(23),
        consensus_state_schema_version: 1,
        migration_manifest_hash: hash(24),
        required_upgrade_handler_set_hash: hash(25),
    }
}

#[allow(dead_code)]
pub fn finalized_job_spec(
    seed: u8,
    cursor: u64,
    chain_id: u64,
    genesis_hash: B256,
) -> FinalizedJobSpecV1 {
    let limits = poc_schema_limits();
    let day = 20_260_901_u32;
    let bundle = protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let collection_key = hash(seed.wrapping_add(2));
    let collection_root = hash(seed.wrapping_add(3));
    let nominal = U256::from(1);
    let intent = JobIntentV1 {
        chain_id,
        genesis_hash,
        fork_id: bundle.fork_id,
        wwd: day,
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash,
        ce_sealed_root: hash(seed.wrapping_add(5)),
        sealed_tribute_collection_key: collection_key,
        sealed_tribute_collection_root: collection_root,
        authenticated_day_count: 1,
        authenticated_day_nominal: nominal,
        pre_admission_envelope_hash: hash(seed.wrapping_add(6)),
        source_availability_policy_id: hash(seed.wrapping_add(7)),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: DayType::Green,
            day_limit: nominal,
            previous_vwap: nominal,
            current_vwap: nominal,
            gratis_demand: U256::ZERO,
            gratis_supply: U256::ZERO,
            lysis_budget: nominal,
            auction_base: U256::ZERO,
            auction_entry_prices: vec![ReferenceEntryPriceV1 {
                reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
                entry_price_minor: nominal,
                source: AuctionEntryPriceSource::LastClosedDayVwap,
                source_day: day - 1,
            }],
            request_budget_split_receipt_hash: hash(seed.wrapping_add(8)),
        },
        logical_evaluation_height: cursor,
        logical_evaluation_time: cursor,
        activation_preconditions: ActivationPreconditionsV1 {
            tribute: TributeInputBindingV1 {
                wwd: day,
                source_generation: 1,
                collection_key,
                sealed_collection_root: collection_root,
                exact_count: 1,
                exact_nominal_total: nominal,
            },
            nod: NodTargetPreconditionV1 {
                wwd: day,
                target_generation: 1,
                namespace_root_before: hash(seed.wrapping_add(9)),
                max_nod_count: 1,
            },
            contributors: ContributorTargetPreconditionV1 {
                worldwide_day: day,
                expected_series_version: 1,
                max_contributor_count: 1,
                max_eligible_nominal_total: nominal,
            },
            metadosis: MetadosisAttemptPreconditionV1 {
                wwd: day,
                pending_nonce: 0,
                expected_status: MetadosisExpectedStatus::OffchainPending,
                state_version: 1,
            },
        },
        result_validator_set_epoch: 1,
        result_committee_set_hash: hash(seed.wrapping_add(10)),
        result_ocomp_binding_hash: hash(seed.wrapping_add(11)),
        result_member_count: 4,
        result_quorum_threshold: 3,
        custody_committee_epoch_hash: None,
    };
    let finalized_block_hash = hash(seed.wrapping_add(12));
    let finalized_state_root = hash(seed.wrapping_add(13));
    FinalizedJobSpecV1 {
        summary: FinalizedJobSummaryV1 {
            cursor,
            job_id: intent
                .job_id(finalized_block_hash, finalized_state_root, &limits)
                .unwrap(),
            intent_id: intent.intent_id(&limits).unwrap(),
            finalized_block_hash,
            finalized_state_root,
            protocol_bundle_hash,
            open_height: cursor + 1,
            deadline_height: cursor + 1_801,
        },
        canonical_job_intent: BoundedBytes(intent.encode_canonical(&limits).unwrap()),
    }
}
