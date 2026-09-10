use std::{fs, os::unix::fs::MetadataExt as _};

use alloy_primitives::{keccak256, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashVerifier as _, Signature, VerifyingKey};
use outbe_ocomp::{
    control::EndpointIdentity,
    result_attestation::{LocalResultAttestationErrorV1, LocalResultVoteAttesterV1},
    result_signer::OcompSigner,
    sign_once::{SignOnceError, SignOnceStore},
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::{FinalizedJobSpecV1, FinalizedJobSummaryV1},
    hash::hash_framed,
    intent::{
        ActivationPreconditionsV1, AuctionEntryPriceSource, ContributorTargetPreconditionV1,
        DayType, FrozenMetadosisValuesV1, JobIntentV1, MetadosisAttemptPreconditionV1,
        MetadosisExpectedStatus, NodTargetPreconditionV1, ReferenceEntryPriceV1,
        TributeInputBindingV1,
    },
    profile::poc_schema_limits,
    registry::HashDomain,
    result::{
        lysis_v1_empty_semantic_event_root, CarryOverCreditActionV1, CarryOverReason,
        CompletionStatus, ConservationTotalsV1, ExactCountsV1, LysisArithmeticSummaryV1,
        LysisResultV1, MetadosisCompletionSummaryV1, ResultRootsV1,
    },
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn fixture() -> (EndpointIdentity, B256, FinalizedJobSpecV1, LysisResultV1) {
    let limits = poc_schema_limits();
    let fork_id = hash(1);
    let identity = EndpointIdentity {
        chain_id: 42,
        genesis_hash: hash(40),
        boot_nonce: hash(99),
        protocol_bundle_hash: hash(41),
    };
    let intent = JobIntentV1 {
        chain_id: identity.chain_id,
        genesis_hash: identity.genesis_hash,
        fork_id,
        wwd: 7,
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash: identity.protocol_bundle_hash,
        ce_sealed_root: hash(42),
        sealed_tribute_collection_key: hash(30),
        sealed_tribute_collection_root: hash(31),
        authenticated_day_count: 1,
        authenticated_day_nominal: U256::ZERO,
        pre_admission_envelope_hash: hash(43),
        source_availability_policy_id: hash(44),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: DayType::Green,
            day_limit: U256::ZERO,
            previous_vwap: U256::ZERO,
            current_vwap: U256::ZERO,
            gratis_demand: U256::ZERO,
            gratis_supply: U256::ZERO,
            lysis_budget: U256::ZERO,
            auction_base: U256::ZERO,
            auction_entry_prices: vec![ReferenceEntryPriceV1 {
                reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
                entry_price_minor: U256::ZERO,
                source: AuctionEntryPriceSource::LastClosedDayVwap,
                source_day: 6,
            }],
            request_budget_split_receipt_hash: hash(45),
        },
        logical_evaluation_height: 100,
        logical_evaluation_time: 1_000,
        activation_preconditions: ActivationPreconditionsV1 {
            tribute: TributeInputBindingV1 {
                wwd: 7,
                source_generation: 3,
                collection_key: hash(30),
                sealed_collection_root: hash(31),
                exact_count: 1,
                exact_nominal_total: U256::ZERO,
            },
            nod: NodTargetPreconditionV1 {
                wwd: 7,
                target_generation: 5,
                namespace_root_before: hash(32),
                max_nod_count: 1,
            },
            contributors: ContributorTargetPreconditionV1 {
                worldwide_day: 7,
                expected_series_version: 8,
                max_contributor_count: 1,
                max_eligible_nominal_total: U256::ZERO,
            },
            metadosis: MetadosisAttemptPreconditionV1 {
                wwd: 7,
                pending_nonce: 0,
                expected_status: MetadosisExpectedStatus::OffchainPending,
                state_version: 12,
            },
        },
        result_validator_set_epoch: 1,
        result_committee_set_hash: hash(70),
        result_ocomp_binding_hash: hash(71),
        result_member_count: 4,
        result_quorum_threshold: 3,
        custody_committee_epoch_hash: None,
    };
    let block_hash = hash(90);
    let state_root = hash(91);
    let job_id = intent.job_id(block_hash, state_root, &limits).unwrap();
    let roots = ResultRootsV1 {
        nod_root: hash(50),
        bucket_root: hash(51),
        contributor_root: hash(52),
        output_manifest_root: hash(53),
    };
    let counts = ExactCountsV1 {
        tribute_count: 1,
        nod_count: 1,
        bucket_count: 0,
        contributor_count: 0,
        semantic_event_count: 0,
    };
    let conservation = ConservationTotalsV1 {
        tribute_nominal_total: U256::ZERO,
        eligible_nominal_total: U256::ZERO,
        day_limit: U256::ZERO,
        gratis_demand: U256::ZERO,
        gratis_supply: U256::ZERO,
        lysis_budget: U256::ZERO,
        auction_base: U256::ZERO,
        nod_gratis_consumed: U256::ZERO,
        unused_lysis: U256::ZERO,
        carry_over_credit: U256::ZERO,
        nod_cost_total: U256::ZERO,
    };
    let summary = LysisArithmeticSummaryV1 {
        input_manifest_hash: hash(54),
        plan_hash: hash(55),
        unit_artifact_root: hash(56),
        fidelity_fraction_root: hash(57),
        gratis_prefix_root: hash(58),
        roots: roots.clone(),
        counts: counts.clone(),
        conservation: conservation.clone(),
        first_error_ordinal: None,
    };
    let result = LysisResultV1 {
        protocol_bundle_hash: intent.protocol_bundle_hash,
        job_id,
        attempt: intent.attempt,
        input_manifest_hash: summary.input_manifest_hash,
        plan_hash: summary.plan_hash,
        unit_artifact_root: summary.unit_artifact_root,
        fidelity_fraction_root: summary.fidelity_fraction_root,
        gratis_prefix_root: summary.gratis_prefix_root,
        result_chunk_count: 1,
        result_chunk_list_root: hash(61),
        carry_over_credit: CarryOverCreditActionV1 {
            source_wwd: 7,
            reason: CarryOverReason::UnusedLysis,
            amount: U256::ZERO,
        },
        metadosis_completion_summary: MetadosisCompletionSummaryV1 {
            wwd: 7,
            pending_nonce: 0,
            day_type: DayType::Green,
            tribute_nominal_total: U256::ZERO,
            day_limit: U256::ZERO,
            gratis_demand: U256::ZERO,
            gratis_supply: U256::ZERO,
            lysis_budget: U256::ZERO,
            auction_base: U256::ZERO,
            nod_gratis_consumed: U256::ZERO,
            unused_lysis: U256::ZERO,
            carry_over_credit: U256::ZERO,
            status: CompletionStatus::Completed,
            logical_evaluation_height: 100,
            logical_evaluation_time: 1_000,
        },
        tribute_count: 1,
        tribute_nominal_total: U256::ZERO,
        unused_lysis: U256::ZERO,
        roots,
        counts,
        conservation,
        arithmetic_commitment: hash_framed(
            HashDomain::LysisArithmetic,
            &summary.encode_canonical(&limits).unwrap(),
        )
        .unwrap(),
        event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
    };
    let spec = FinalizedJobSpecV1 {
        summary: FinalizedJobSummaryV1 {
            cursor: 99,
            job_id,
            intent_id: intent.intent_id(&limits).unwrap(),
            finalized_block_hash: block_hash,
            finalized_state_root: state_root,
            protocol_bundle_hash: intent.protocol_bundle_hash,
            open_height: 1,
            deadline_height: 1_000,
        },
        canonical_job_intent: BoundedBytes(intent.encode_canonical(&limits).unwrap()),
    };
    (identity, fork_id, spec, result)
}

#[test]
fn supervisor_signs_exact_result_vote_once_and_rejects_a_conflict() {
    let limits = poc_schema_limits();
    let (identity, fork_id, spec, result) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let owner_uid = fs::metadata(directory.path()).unwrap().uid();
    let signer = OcompSigner::from_secret([1; 32]).unwrap();
    let public_key = signer.public_key_sec1();
    let store = SignOnceStore::open(directory.path().join("sign-once"), owner_uid, limits).unwrap();
    let attester =
        LocalResultVoteAttesterV1::new(identity, fork_id, signer, store, limits).unwrap();
    let canonical = result.encode_canonical(&limits).unwrap();

    assert!(matches!(
        attester.attest(&canonical, &spec, 1_000),
        Err(LocalResultAttestationErrorV1::Binding(
            "canonical voting window"
        ))
    ));
    let first = attester.attest(&canonical, &spec, 100).unwrap();
    assert_eq!(first.ocomp_key_hash, keccak256(public_key));
    let replay = attester.attest(&canonical, &spec, 100).unwrap();
    assert_eq!(first, replay);
    let intent = JobIntentV1::decode_canonical(&spec.canonical_job_intent.0, &limits).unwrap();
    let digest = first.signing_digest(&intent, &limits).unwrap();
    let key = VerifyingKey::from_sec1_bytes(&public_key).unwrap();
    let signature = Signature::from_slice(&first.signature_rs).unwrap();
    key.verify_prehash(digest.as_slice(), &signature).unwrap();

    let mut conflicting = result;
    conflicting.result_chunk_list_root = hash(62);
    let error = attester
        .attest(&conflicting.encode_canonical(&limits).unwrap(), &spec, 100)
        .unwrap_err();
    assert!(matches!(
        error,
        LocalResultAttestationErrorV1::SignOnce(SignOnceError::Equivocation { .. })
    ));
}
