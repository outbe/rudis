use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    hash::hash_framed,
    intent::DayType,
    profile::poc_schema_limits,
    registry::HashDomain,
    result::{
        lysis_v1_empty_semantic_event_root, CarryOverCreditActionV1, CarryOverReason,
        CompletionStatus, ConservationTotalsV1, ExactCountsV1, LysisArithmeticSummaryV1,
        LysisResultV1, MetadosisCompletionSummaryV1, ResultRootsV1,
    },
};

use crate::ocomp::local_result::{LocalLysisResultError, LocalLysisResultStore};

fn canonical_result() -> (B256, LysisResultV1, Vec<u8>) {
    let limits = poc_schema_limits();
    let roots = ResultRootsV1 {
        nod_root: B256::repeat_byte(0x31),
        bucket_root: B256::repeat_byte(0x32),
        contributor_root: B256::repeat_byte(0x33),
        output_manifest_root: B256::repeat_byte(0x34),
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
        input_manifest_hash: B256::repeat_byte(0x35),
        plan_hash: B256::repeat_byte(0x36),
        unit_artifact_root: B256::repeat_byte(0x37),
        fidelity_fraction_root: B256::repeat_byte(0x38),
        gratis_prefix_root: B256::repeat_byte(0x39),
        roots: roots.clone(),
        counts: counts.clone(),
        conservation: conservation.clone(),
        first_error_ordinal: None,
    };
    let job_id = B256::repeat_byte(0x21);
    let result = LysisResultV1 {
        protocol_bundle_hash: B256::repeat_byte(0x20),
        job_id,
        attempt: 0,
        input_manifest_hash: summary.input_manifest_hash,
        plan_hash: summary.plan_hash,
        unit_artifact_root: summary.unit_artifact_root,
        fidelity_fraction_root: summary.fidelity_fraction_root,
        gratis_prefix_root: summary.gratis_prefix_root,
        result_chunk_count: 1,
        result_chunk_list_root: B256::repeat_byte(0x3a),
        carry_over_credit: CarryOverCreditActionV1 {
            source_wwd: 1,
            reason: CarryOverReason::UnusedLysis,
            amount: U256::ZERO,
        },
        metadosis_completion_summary: MetadosisCompletionSummaryV1 {
            wwd: 1,
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
            logical_evaluation_height: 1,
            logical_evaluation_time: 1,
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
    let encoded = result
        .encode_canonical(&limits)
        .expect("fixture result encodes canonically");
    (job_id, result, encoded)
}

#[test]
fn local_result_store_survives_restart_and_accepts_exact_replay() {
    let root = tempfile::tempdir().unwrap();
    let store_root = root.path().join("local-results");
    let limits = poc_schema_limits();
    let (job_id, result, encoded) = canonical_result();

    let store = LocalLysisResultStore::open(&store_root, limits).unwrap();
    assert_eq!(store.load(job_id).unwrap(), None);
    let committed = store.commit(job_id, &encoded).unwrap();
    assert_eq!(committed.job_id, job_id);
    assert_eq!(
        committed.result_digest,
        result.result_digest(&limits).unwrap()
    );
    assert_eq!(store.commit(job_id, &encoded).unwrap(), committed);
    drop(store);

    let reopened = LocalLysisResultStore::open(&store_root, limits).unwrap();
    let loaded = reopened
        .load(job_id)
        .unwrap()
        .expect("committed local result survives restart");
    assert_eq!(loaded.committed, committed);
    assert_eq!(loaded.canonical_result, encoded);
    reopened.verify_exact(job_id, &result).unwrap();
}

#[test]
fn local_result_store_fails_closed_for_missing_mismatch_and_conflict() {
    let root = tempfile::tempdir().unwrap();
    let store_root = root.path().join("local-results");
    let limits = poc_schema_limits();
    let (job_id, result, encoded) = canonical_result();
    let store = LocalLysisResultStore::open(&store_root, limits).unwrap();

    assert!(matches!(
        store.verify_exact(job_id, &result),
        Err(LocalLysisResultError::Missing { .. })
    ));
    store.commit(job_id, &encoded).unwrap();

    let mut different = result.clone();
    different.result_chunk_list_root = B256::repeat_byte(0xE1);
    let different_bytes = different.encode_canonical(&limits).unwrap();
    assert!(matches!(
        store.commit(job_id, &different_bytes),
        Err(LocalLysisResultError::Conflict { .. })
    ));
    assert!(matches!(
        store.verify_exact(job_id, &different),
        Err(LocalLysisResultError::Mismatch { .. })
    ));
}
