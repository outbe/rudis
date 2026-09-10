// OCOMP-TEST-ID: OCM-SEM-002

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, WwdEntityId};
use outbe_lysis::program_v1::artifacts::{
    decode_amount_run, decode_enumerated_run, decode_fidelity_map_output,
    decode_finalized_output_run, decode_fixed_reduce_output, decode_gratis_prefix_down_output,
    decode_gratis_segment_summary, decode_raw_coverage_carrier, encode_amount_run,
    encode_enumerated_run, encode_fidelity_map_output, encode_finalized_output_run,
    encode_fixed_reduce_output, encode_gratis_prefix_down_output, encode_gratis_segment_summary,
    encode_raw_coverage_carrier, enumerate_tributes, gratis_summary_coverage, FixedReduceOutputV1,
    GratisPrefixDownOutputV1, RawCoverageCarrierV1,
};
use outbe_lysis::program_v1::phases::{
    amount_map, fidelity_map, fidelity_reduce, fidelity_reduce_pair, finalize_fi_fraction_table,
    finalize_gratis_leaf, gratis_prefix_down, gratis_summary, gratis_summary_reduce_pair,
    output_finalize, shuffle_buckets, shuffle_owners, AmountRecordV1, AmountRunV1,
    FidelityAggregateV1, FidelityLeaguePartialV1, FidelityReduceValueV1, GratisIncomingV1,
    GratisLeafPrefixV1, GratisSegmentSummaryV1, GratisSummaryValueV1,
};
use outbe_lysis::program_v1::planner::{
    primary_work_unit_count, LysisPlanTopologyV1, LysisPlannerBindingsV1, LysisPlannerV1,
    PaddedBinaryTreeV1, PlannedProducerV1, PlannedUnitPositionV1, PlannerErrorV1, ReducerInputV1,
    PRIMARY_WORK_SHARD_SIZE,
};
use outbe_lysis::program_v1::reducers::{
    merge_bucket_runs_streaming, merge_owner_runs_streaming, CanonicalRunSpanV1,
    StreamingMergeErrorV1,
};
use outbe_lysis::program_v1::result::{
    decode_root_reduce_output, decode_root_reduce_summary, encode_root_reduce_output,
    encode_root_reduce_summary, LysisListSubtreeCarrierV1, RootReduceOutputV1, RootReduceSummaryV1,
};
use outbe_lysis::program_v1::{
    execute, LeagueFractionV1, ObservationValueV1, ObservedTributeV1, ProgramErrorV1,
    ProgramInputV1, TributeInputV1,
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::CasObjectRefV1,
    input::{InputChunkKind, InputChunkRefV1},
    local_control::poc_schema_limits,
    ordered_list_root,
    result::OutputManifestEntryV1,
    unit::{InputPurpose, InputSourceKind, UnitInterval, UnitPhase},
    ListKind, ObjectKind, OrderedListLimits,
};
use outbe_primitives::time::WorldwideDay;
use std::collections::BTreeMap;

const SIX_DECIMAL_SCALE: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

fn tribute(seed: u32, day: WorldwideDay, nominal: u64, excluded: bool) -> TributeInputV1 {
    let mut owner_bytes = [0_u8; 20];
    owner_bytes[16..].copy_from_slice(&seed.to_be_bytes());
    let owner = Address::from(owner_bytes);
    TributeInputV1 {
        tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
        owner,
        worldwide_day: day,
        issuance_currency: 840,
        nominal_amount_minor: U256::from(nominal),
        reference_currency: 978,
        tribute_price_minor: U256::from(2),
        exclude_from_intex_issuance: excluded,
    }
}

fn observed(
    seed: u32,
    day: WorldwideDay,
    nominal: u64,
    league: u16,
    excluded: bool,
) -> ObservedTributeV1 {
    ObservedTributeV1 {
        tribute: tribute(seed, day, nominal, excluded),
        first_league: ObservationValueV1::Value(league),
        second_league: ObservationValueV1::Value(league),
        conditional_entry_price_minor: ObservationValueV1::Value(U256::from(3)),
        nod_target_available: true,
    }
}

fn tribute_chunk_ref(ordinal: u32, ids: &[B256], encoded_bytes: u64) -> InputChunkRefV1 {
    InputChunkRefV1 {
        kind: InputChunkKind::Tribute,
        ordinal,
        record_count: u32::try_from(ids.len()).unwrap(),
        first_key: BoundedBytes(ids.first().unwrap().0.to_vec()),
        last_key_inclusive: BoundedBytes(ids.last().unwrap().0.to_vec()),
        encoded_bytes,
        semantic_digest: B256::repeat_byte(u8::try_from(ordinal + 10).unwrap()),
        transport_digest: B256::repeat_byte(u8::try_from(ordinal + 20).unwrap()),
    }
}

fn planner_bindings(tribute_count: u32) -> LysisPlannerBindingsV1 {
    LysisPlannerBindingsV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 3,
        input_manifest_hash: B256::repeat_byte(4),
        input_manifest_encoded_bytes: 512,
        fidelity_opening_root: B256::repeat_byte(6),
        oracle_opening_root: B256::repeat_byte(7),
        wwd: 20_260_724,
        lysis_budget: U256::from(99_000_000_u64),
        logical_evaluation_time: 1_784_765_900,
        tribute_count,
        lysis_program_semantics_hash: B256::repeat_byte(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    }
}

// OCM-SEM-002: planner, unit coverage and fixed reducer topology.
#[test]
fn primary_work_is_unbounded_in_total_and_partitioned_in_exact_256_record_shards() {
    assert_eq!(PRIMARY_WORK_SHARD_SIZE, 256);
    for (tribute_count, expected_units) in [
        (1, 1),
        (255, 1),
        (256, 1),
        (257, 2),
        (10_000, 40),
        (1_000_000_000, 3_906_250),
    ] {
        assert_eq!(
            primary_work_unit_count(tribute_count).unwrap(),
            expected_units,
            "unexpected primary unit count for {tribute_count} Tribute"
        );
    }
    assert_eq!(
        primary_work_unit_count(0),
        Err(PlannerErrorV1::EmptyTributePopulation)
    );
}

#[test]
fn enumerate_artifact_is_bounded_canonical_and_commits_raw_coverage() {
    let limits = poc_schema_limits();
    let day = WorldwideDay::new(20_260_724);
    let mut tributes = vec![tribute(1, day, 10, false), tribute(2, day, 20, true)];
    tributes.sort_by_key(|tribute| tribute.tribute_id);
    let run = enumerate_tributes(256, day, &tributes).unwrap();

    assert_eq!((run.start_ordinal, run.end_ordinal), (256, 258));
    assert_eq!(run.ordered_records[0].raw_ordinal, 256);
    assert_eq!(run.ordered_records[1].raw_ordinal, 257);
    assert_ne!(run.coverage_root().unwrap(), B256::ZERO);

    let encoded = encode_enumerated_run(&run, &limits).unwrap();
    assert_eq!(decode_enumerated_run(&encoded, &limits).unwrap(), run);

    let mut changed = encoded.clone();
    changed[24] ^= 1;
    assert!(decode_enumerated_run(&changed, &limits).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_enumerated_run(&trailing, &limits).is_err());
}

#[test]
fn enumerate_rejects_empty_oversized_and_noncanonical_shards() {
    let day = WorldwideDay::new(20_260_724);
    assert!(enumerate_tributes(0, day, &[]).is_err());

    let mut oversized = (0..257)
        .map(|index| tribute(index + 1, day, 1, false))
        .collect::<Vec<_>>();
    oversized.sort_by_key(|tribute| tribute.tribute_id);
    assert!(enumerate_tributes(0, day, &oversized).is_err());

    let duplicate = tribute(1, day, 1, false);
    assert!(enumerate_tributes(0, day, &[duplicate.clone(), duplicate]).is_err());
}

#[test]
fn fidelity_map_artifact_is_bounded_canonical_and_preserves_raw_coverage() {
    let limits = poc_schema_limits();
    let day = WorldwideDay::new(20_260_724);
    let mut observed = vec![
        observed(1, day, 10, 2, false),
        observed(2, day, 20, 3, true),
    ];
    observed.sort_by_key(|item| item.tribute.tribute_id);
    let output = fidelity_map(256, &observed).unwrap();

    let encoded = encode_fidelity_map_output(&output, &limits).unwrap();
    assert_eq!(
        decode_fidelity_map_output(&encoded, &limits).unwrap(),
        output
    );
    assert_eq!(output.coverage_root().unwrap(), {
        let enumerated = enumerate_tributes(
            256,
            day,
            &observed
                .iter()
                .map(|item| item.tribute.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        enumerated.coverage_root().unwrap()
    });

    let mut changed = encoded.clone();
    changed[24] ^= 1;
    assert!(decode_fidelity_map_output(&changed, &limits).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_fidelity_map_output(&trailing, &limits).is_err());
}

#[test]
fn constant_size_coverage_carriers_merge_to_the_canonical_full_raw_root() {
    let limits = poc_schema_limits();
    for total_count in [1_u32, 255, 256, 257, 513] {
        let records = (0..total_count)
            .map(|raw_ordinal| (raw_ordinal, WwdEntityId::from(entity_id(raw_ordinal))))
            .collect::<Vec<_>>();
        let primary_count = total_count.div_ceil(PRIMARY_WORK_SHARD_SIZE);
        let mut carriers = (0..primary_count)
            .map(|ordinal| {
                let start = ordinal * PRIMARY_WORK_SHARD_SIZE;
                let end = (start + PRIMARY_WORK_SHARD_SIZE).min(total_count);
                RawCoverageCarrierV1::from_records(
                    total_count,
                    &records[start as usize..end as usize],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        if primary_count > 1 {
            let padded_count = primary_count.next_power_of_two();
            carriers.extend((primary_count..padded_count).map(|ordinal| {
                RawCoverageCarrierV1::canonical_empty(total_count, ordinal).unwrap()
            }));
            while carriers.len() > 1 {
                carriers = carriers
                    .chunks_exact(2)
                    .map(|pair| RawCoverageCarrierV1::merge(&pair[0], &pair[1]).unwrap())
                    .collect();
            }
        }
        let carrier = carriers.first().unwrap();
        let expected_records = records
            .iter()
            .map(|(ordinal, id)| {
                let mut encoded = [0_u8; 36];
                encoded[..4].copy_from_slice(&ordinal.to_be_bytes());
                encoded[4..].copy_from_slice(id.as_slice());
                encoded
            })
            .collect::<Vec<_>>();
        let expected_root = outbe_ocomp_protocol::ordered_list_root(
            outbe_ocomp_protocol::ListKind::RawTributeCoverage,
            &expected_records,
            outbe_ocomp_protocol::OrderedListLimits::new(
                expected_records.len(),
                40,
                expected_records.len().next_power_of_two() * 32,
            ),
        )
        .unwrap();
        assert_eq!(carrier.final_root(total_count).unwrap(), expected_root);

        let encoded = encode_raw_coverage_carrier(carrier, &limits).unwrap();
        assert_eq!(
            decode_raw_coverage_carrier(&encoded, &limits).unwrap(),
            *carrier
        );
        assert!(encoded.len() < 128);
    }
}

#[test]
fn coverage_carriers_reject_non_canonical_ranges_and_merge_order() {
    let total_count = 257_u32;
    let records = (0..total_count)
        .map(|raw_ordinal| (raw_ordinal, WwdEntityId::from(entity_id(raw_ordinal))))
        .collect::<Vec<_>>();
    let left = RawCoverageCarrierV1::from_records(total_count, &records[..256]).unwrap();
    let right = RawCoverageCarrierV1::from_records(total_count, &records[256..]).unwrap();

    assert!(RawCoverageCarrierV1::merge(&right, &left).is_err());

    let mut non_contiguous = records[..256].to_vec();
    non_contiguous[127].0 += 1;
    assert!(RawCoverageCarrierV1::from_records(total_count, &non_contiguous).is_err());

    let limits = poc_schema_limits();
    let mut trailing = encode_raw_coverage_carrier(&left, &limits).unwrap();
    trailing.push(0);
    assert!(decode_raw_coverage_carrier(&trailing, &limits).is_err());
}

#[test]
fn fixed_reduce_output_is_canonical_and_binds_aggregate_carrier_and_fractions() {
    let limits = poc_schema_limits();
    let records = (0..257_u32)
        .map(|raw_ordinal| (raw_ordinal, WwdEntityId::from(entity_id(raw_ordinal))))
        .collect::<Vec<_>>();
    let left = RawCoverageCarrierV1::from_records(257, &records[..256]).unwrap();
    let right = RawCoverageCarrierV1::from_records(257, &records[256..]).unwrap();
    let coverage = RawCoverageCarrierV1::merge(&left, &right).unwrap();
    let output = FixedReduceOutputV1 {
        aggregate: Some(FidelityAggregateV1 {
            start_ordinal: 0,
            end_ordinal: 257,
            tribute_count: 257,
            checked_total_nominal: U256::from(257),
            ordered_league_partials: vec![FidelityLeaguePartialV1 {
                league_id: 7,
                count: 257,
                nominal_amount_minor: U256::from(257),
            }],
        }),
        coverage,
        ordered_fractions: vec![LeagueFractionV1 {
            league: 7,
            fraction: U256::from(9),
        }],
    };

    let encoded = encode_fixed_reduce_output(&output, &limits).unwrap();
    assert_eq!(
        decode_fixed_reduce_output(&encoded, &limits).unwrap(),
        output
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_fixed_reduce_output(&trailing, &limits).is_err());

    let mut mismatched = output;
    mismatched.coverage.end_ordinal = 256;
    assert!(encode_fixed_reduce_output(&mismatched, &limits).is_err());
}

#[test]
fn root_reduce_summary_is_bounded_canonical_and_rejects_cross_list_substitution() {
    let limits = poc_schema_limits();
    let carrier = |list_kind, real_count, subtree_height, marker| LysisListSubtreeCarrierV1 {
        list_kind,
        start_ordinal: 0,
        real_count,
        subtree_height,
        subtree_index: 0,
        tree_root: B256::repeat_byte(marker),
    };
    let summary = RootReduceSummaryV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 3,
        plan_hash: B256::repeat_byte(4),
        covered_primary_start: 0,
        covered_primary_count: 2,
        nod_actions: carrier(outbe_ocomp_protocol::ListKind::NodActions, 257, 9, 11),
        bucket_records: carrier(outbe_ocomp_protocol::ListKind::BucketRecords, 257, 9, 12),
        contributor_actions: carrier(outbe_ocomp_protocol::ListKind::ContributorActions, 1, 9, 13),
        output_manifest_entries: carrier(
            outbe_ocomp_protocol::ListKind::CompleteOutputManifest,
            2,
            1,
            14,
        ),
        result_chunk_hashes: carrier(outbe_ocomp_protocol::ListKind::ResultChunkHashes, 2, 1, 15),
        tribute_count: 257,
        nod_count: 257,
        bucket_count: 257,
        contributor_count: 1,
        tribute_nominal_total: U256::from(10_000),
        eligible_nominal_total: U256::from(100),
        nod_gratis_consumed: U256::from(90),
        nod_cost_total: U256::from(9_000),
        first_error_ordinal: None,
    };

    let encoded = encode_root_reduce_summary(&summary, &limits).unwrap();
    assert!(encoded.len() < 512);
    assert_eq!(
        decode_root_reduce_summary(&encoded, &limits).unwrap(),
        summary
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_root_reduce_summary(&trailing, &limits).is_err());

    let mut substituted = summary.clone();
    substituted.nod_actions.list_kind = outbe_ocomp_protocol::ListKind::BucketRecords;
    assert!(encode_root_reduce_summary(&substituted, &limits).is_err());

    let mut wrong_span = summary.clone();
    wrong_span.contributor_actions.subtree_height = 8;
    assert!(encode_root_reduce_summary(&wrong_span, &limits).is_err());

    let mut manifest_per_nod = summary.clone();
    manifest_per_nod.output_manifest_entries.real_count = manifest_per_nod.nod_count;
    manifest_per_nod.output_manifest_entries.subtree_height = 9;
    assert!(encode_root_reduce_summary(&manifest_per_nod, &limits).is_err());

    let mut inconsistent = summary;
    inconsistent.contributor_count = 2;
    assert!(encode_root_reduce_summary(&inconsistent, &limits).is_err());
}

#[test]
fn root_reduce_output_is_a_closed_leaf_or_node_payload() {
    let limits = poc_schema_limits();
    let entry = OutputManifestEntryV1 {
        chunk_ordinal: 0,
        result_chunk_hash: B256::repeat_byte(0x41),
        result_chunk_ref: CasObjectRefV1 {
            transport_digest: B256::repeat_byte(0x42),
            encoded_bytes: 128,
            expected_ocb1_kind: Some(ObjectKind::ResultChunkV1.tag()),
        },
    };
    let carrier = |kind, item: &[u8]| {
        LysisListSubtreeCarrierV1::from_primary_page(kind, 0, &[item], 512).unwrap()
    };
    let summary = RootReduceSummaryV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 3,
        plan_hash: B256::repeat_byte(4),
        covered_primary_start: 0,
        covered_primary_count: 1,
        nod_actions: carrier(ListKind::NodActions, &[1]),
        bucket_records: carrier(ListKind::BucketRecords, &[2]),
        contributor_actions: carrier(ListKind::ContributorActions, &[3]),
        output_manifest_entries: carrier(
            ListKind::CompleteOutputManifest,
            &entry.encode_canonical_record(&limits).unwrap(),
        ),
        result_chunk_hashes: carrier(
            ListKind::ResultChunkHashes,
            entry.result_chunk_hash.as_slice(),
        ),
        tribute_count: 1,
        nod_count: 1,
        bucket_count: 1,
        contributor_count: 1,
        tribute_nominal_total: U256::from(100),
        eligible_nominal_total: U256::from(100),
        nod_gratis_consumed: U256::from(10),
        nod_cost_total: U256::from(90),
        first_error_ordinal: None,
    };

    let mut node_summary = summary.clone();
    for carrier in [
        &mut node_summary.nod_actions,
        &mut node_summary.bucket_records,
        &mut node_summary.contributor_actions,
    ] {
        carrier.subtree_height = 9;
    }
    node_summary.output_manifest_entries.subtree_height = 1;
    node_summary.result_chunk_hashes.subtree_height = 1;

    for output in [
        RootReduceOutputV1::Leaf {
            summary: summary.clone(),
            output_manifest_entry: entry.clone(),
        },
        RootReduceOutputV1::Node {
            summary: node_summary,
        },
    ] {
        let encoded = encode_root_reduce_output(&output, &limits).unwrap();
        assert_eq!(
            decode_root_reduce_output(&encoded, &limits).unwrap(),
            output
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_root_reduce_output(&trailing, &limits).is_err());
    }

    let mut substituted_entry = entry;
    substituted_entry.result_chunk_hash = B256::repeat_byte(0xff);
    assert!(encode_root_reduce_output(
        &RootReduceOutputV1::Leaf {
            summary: summary.clone(),
            output_manifest_entry: substituted_entry,
        },
        &limits,
    )
    .is_err());
    assert!(encode_root_reduce_output(&RootReduceOutputV1::Node { summary }, &limits,).is_err());
}

#[test]
fn fixed_capacity_result_carriers_merge_by_position_without_becoming_dense_roots() {
    let first_items = (0_u16..256)
        .map(|value| value.to_be_bytes().to_vec())
        .collect::<Vec<_>>();
    let second_items = vec![b"last".to_vec()];
    let first = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::ContributorActions,
        0,
        &first_items,
        16,
    )
    .unwrap();
    let second = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::ContributorActions,
        1,
        &second_items,
        16,
    )
    .unwrap();
    let merged = first.merge_adjacent(second).unwrap();

    assert_eq!(first.subtree_height, 8);
    assert_eq!(second.start_ordinal, PRIMARY_WORK_SHARD_SIZE);
    assert_eq!(merged.real_count, 257);
    assert_eq!(merged.subtree_height, 9);
    assert_eq!(merged.subtree_index, 0);

    let mut dense_items = first_items;
    dense_items.extend(second_items);
    let dense_root = ordered_list_root(
        ListKind::ContributorActions,
        &dense_items,
        OrderedListLimits::new(512, 16, 512 * 32),
    )
    .unwrap();
    let merged_dense_root = outbe_ocomp_protocol::list::root_hash(
        ListKind::ContributorActions,
        257,
        merged.subtree_height,
        merged.tree_root,
    )
    .unwrap();
    assert_eq!(merged_dense_root, dense_root);

    let sparse_items = vec![b"only".to_vec()];
    let sparse = LysisListSubtreeCarrierV1::from_primary_page(
        ListKind::ContributorActions,
        0,
        &sparse_items,
        16,
    )
    .unwrap();
    let empty =
        LysisListSubtreeCarrierV1::canonical_empty_primary_page(ListKind::ContributorActions, 1)
            .unwrap();
    assert!(!empty.tree_root.is_zero());
    assert_eq!(
        empty,
        LysisListSubtreeCarrierV1::canonical_empty_primary_page(ListKind::ContributorActions, 1,)
            .unwrap()
    );

    let sparse_coverage = sparse.merge_adjacent(empty).unwrap();
    let sparse_wrapped = outbe_ocomp_protocol::list::root_hash(
        ListKind::ContributorActions,
        1,
        sparse_coverage.subtree_height,
        sparse_coverage.tree_root,
    )
    .unwrap();
    let canonical_sparse = ordered_list_root(
        ListKind::ContributorActions,
        &sparse_items,
        OrderedListLimits::new(1, 16, 32),
    )
    .unwrap();
    assert_ne!(sparse_wrapped, canonical_sparse);

    let non_adjacent =
        LysisListSubtreeCarrierV1::canonical_empty_primary_page(ListKind::ContributorActions, 2)
            .unwrap();
    assert!(sparse.merge_adjacent(non_adjacent).is_err());
    let wrong_kind =
        LysisListSubtreeCarrierV1::canonical_empty_primary_page(ListKind::NodActions, 1).unwrap();
    assert!(sparse.merge_adjacent(wrong_kind).is_err());
}

#[test]
fn root_reduce_summaries_merge_only_adjacent_complete_prefixes() {
    let summary = |primary_ordinal: u32,
                   tribute_count: u32,
                   contributor_count: u32,
                   marker: u8,
                   first_error_ordinal: Option<u32>| {
        let actions = vec![vec![marker]; usize::try_from(tribute_count).unwrap()];
        let contributors = vec![vec![marker]; usize::try_from(contributor_count).unwrap()];
        let manifest_entry = vec![vec![marker]];
        let result_hash = vec![vec![marker; 32]];
        RootReduceSummaryV1 {
            protocol_bundle_hash: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 3,
            plan_hash: B256::repeat_byte(4),
            covered_primary_start: primary_ordinal,
            covered_primary_count: 1,
            nod_actions: LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::NodActions,
                primary_ordinal,
                &actions,
                16,
            )
            .unwrap(),
            bucket_records: LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::BucketRecords,
                primary_ordinal,
                &actions,
                16,
            )
            .unwrap(),
            contributor_actions: LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::ContributorActions,
                primary_ordinal,
                &contributors,
                16,
            )
            .unwrap(),
            output_manifest_entries: LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::CompleteOutputManifest,
                primary_ordinal,
                &manifest_entry,
                16,
            )
            .unwrap(),
            result_chunk_hashes: LysisListSubtreeCarrierV1::from_primary_page(
                ListKind::ResultChunkHashes,
                primary_ordinal,
                &result_hash,
                32,
            )
            .unwrap(),
            tribute_count,
            nod_count: tribute_count,
            bucket_count: tribute_count,
            contributor_count,
            tribute_nominal_total: U256::from(tribute_count) * U256::from(10),
            eligible_nominal_total: U256::from(tribute_count) * U256::from(8),
            nod_gratis_consumed: U256::from(tribute_count) * U256::from(3),
            nod_cost_total: U256::from(tribute_count) * U256::from(7),
            first_error_ordinal,
        }
    };

    let left = summary(0, 256, 1, 11, Some(1));
    let right = summary(1, 1, 1, 12, Some(256));
    let merged = left.clone().merge_adjacent(right.clone()).unwrap();
    assert_eq!(merged.covered_primary_start, 0);
    assert_eq!(merged.covered_primary_count, 2);
    assert_eq!(merged.tribute_count, 257);
    assert_eq!(merged.contributor_count, 2);
    assert_eq!(merged.tribute_nominal_total, U256::from(2_570));
    assert_eq!(merged.first_error_ordinal, Some(1));
    assert_eq!(merged.nod_actions.subtree_height, 9);
    assert_eq!(merged.output_manifest_entries.subtree_height, 1);
    assert_eq!(merged.result_chunk_hashes.subtree_height, 1);

    assert!(right.clone().merge_adjacent(left.clone()).is_err());
    let mut mismatched = right.clone();
    mismatched.plan_hash = B256::repeat_byte(99);
    assert!(left.clone().merge_adjacent(mismatched).is_err());
    let mut overflowing = left.clone();
    overflowing.tribute_nominal_total = U256::MAX;
    assert!(overflowing.merge_adjacent(right.clone()).is_err());

    // Contributor pages are globally owner-sorted, while Tribute totals are
    // partitioned by the primary Tribute shard. A valid contributor page can
    // therefore carry more nominal value than the unrelated Tribute page at
    // the same ordinal. Conservation only becomes meaningful at the complete
    // root, after all pages have been reduced.
    let mut owner_paged_left = left.clone();
    owner_paged_left.tribute_nominal_total = U256::from(1_000);
    owner_paged_left.eligible_nominal_total = U256::from(2_000);
    let mut owner_paged_right = right.clone();
    owner_paged_right.tribute_nominal_total = U256::from(1_570);
    owner_paged_right.eligible_nominal_total = U256::ZERO;
    encode_root_reduce_summary(&owner_paged_left, &poc_schema_limits())
        .expect("globally owner-paged leaf is a valid reducer summary");
    let globally_conserved = owner_paged_left
        .merge_adjacent(owner_paged_right)
        .expect("adjacent owner pages reduce independently of primary Tribute totals");
    assert_eq!(globally_conserved.eligible_nominal_total, U256::from(2_000));
    assert_eq!(globally_conserved.tribute_nominal_total, U256::from(2_570));

    let empty_summary = |primary_ordinal| RootReduceSummaryV1 {
        protocol_bundle_hash: left.protocol_bundle_hash,
        job_id: left.job_id,
        attempt: left.attempt,
        plan_hash: left.plan_hash,
        covered_primary_start: primary_ordinal,
        covered_primary_count: 0,
        nod_actions: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::NodActions,
            primary_ordinal,
        )
        .unwrap(),
        bucket_records: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::BucketRecords,
            primary_ordinal,
        )
        .unwrap(),
        contributor_actions: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::ContributorActions,
            primary_ordinal,
        )
        .unwrap(),
        output_manifest_entries: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::CompleteOutputManifest,
            primary_ordinal,
        )
        .unwrap(),
        result_chunk_hashes: LysisListSubtreeCarrierV1::canonical_empty_primary_page(
            ListKind::ResultChunkHashes,
            primary_ordinal,
        )
        .unwrap(),
        tribute_count: 0,
        nod_count: 0,
        bucket_count: 0,
        contributor_count: 0,
        tribute_nominal_total: U256::ZERO,
        eligible_nominal_total: U256::ZERO,
        nod_gratis_consumed: U256::ZERO,
        nod_cost_total: U256::ZERO,
        first_error_ordinal: None,
    };
    let padded = left.clone().merge_adjacent(empty_summary(1)).unwrap();
    assert_eq!(padded.covered_primary_count, 1);
    assert_eq!(padded.result_chunk_hashes.subtree_height, 1);
    assert!(empty_summary(0).merge_adjacent(right).is_err());
}

#[test]
fn shard_cap_plus_one_places_the_last_tribute_in_the_second_adjacent_range() {
    let tree = PaddedBinaryTreeV1::for_tribute_count(257).unwrap();
    assert_eq!(tree.primary_leaf_count(), 2);

    let first = tree.primary_shard(0).unwrap();
    let second = tree.primary_shard(1).unwrap();
    assert_eq!((first.start_ordinal, first.end_ordinal), (0, 256));
    assert_eq!((second.start_ordinal, second.end_ordinal), (256, 257));
    assert_eq!(first.end_ordinal, second.start_ordinal);
    assert_eq!(second.record_count(), 1);
    assert_eq!(
        tree.primary_shard(2),
        Err(PlannerErrorV1::PrimaryShardOutOfRange {
            ordinal: 2,
            primary_leaf_count: 2,
        })
    );
}

#[test]
fn padded_binary_reducer_is_derived_by_position_without_completion_order() {
    let tree = PaddedBinaryTreeV1::for_primary_leaf_count(3).unwrap();
    assert_eq!(tree.padded_leaf_count(), 4);
    assert_eq!(tree.height(), 2);
    assert_eq!(tree.reducer_node_count(), 3);

    let left = tree.reducer_node(1, 0).unwrap();
    assert_eq!(
        left.inputs,
        [ReducerInputV1::Primary(0), ReducerInputV1::Primary(1)]
    );

    let padded = tree.reducer_node(1, 1).unwrap();
    assert_eq!(
        padded.inputs,
        [
            ReducerInputV1::Primary(2),
            ReducerInputV1::CanonicalEmpty { padded_ordinal: 3 },
        ]
    );

    let root = tree.reducer_node(2, 0).unwrap();
    assert_eq!(
        root.inputs,
        [
            ReducerInputV1::Reducer { level: 1, index: 0 },
            ReducerInputV1::Reducer { level: 1, index: 1 },
        ]
    );

    let single = PaddedBinaryTreeV1::for_primary_leaf_count(1).unwrap();
    assert_eq!(single.padded_leaf_count(), 2);
    assert_eq!(single.height(), 1);
    assert_eq!(
        single.reducer_node(1, 0).unwrap().inputs,
        [
            ReducerInputV1::Primary(0),
            ReducerInputV1::CanonicalEmpty { padded_ordinal: 1 },
        ]
    );
}

#[test]
fn primary_catalog_and_units_are_deterministic_and_lazily_derived() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(257)).unwrap();
    let ids = (0..257).map(entity_id).collect::<Vec<_>>();
    let chunks = [
        tribute_chunk_ref(0, &ids[..256], 65_536),
        tribute_chunk_ref(1, &ids[256..], 512),
    ];

    let mut lookups = Vec::new();
    let first = planner
        .primary_unit_at(
            0,
            |ordinal| {
                lookups.push(ordinal);
                chunks.get(ordinal as usize).cloned()
            },
            &limits,
        )
        .unwrap();
    assert_eq!(lookups, [0, 1]);
    assert_eq!(first.phase, UnitPhase::Enumerate);
    assert_eq!(
        first
            .canonical_ordered_inputs
            .iter()
            .map(|input| (input.purpose, input.source_kind))
            .collect::<Vec<_>>(),
        [
            (
                InputPurpose::InputManifest,
                InputSourceKind::AuthenticatedRoot
            ),
            (
                InputPurpose::TributeStream,
                InputSourceKind::AuthenticatedRoot
            ),
        ]
    );
    assert_eq!(
        first.interval,
        UnitInterval::EntityIdRange(outbe_ocomp_protocol::unit::EntityIdHalfOpenRange {
            start: ids[0],
            end: Some(ids[256]),
        })
    );
    assert_eq!(
        first.canonical_ordered_inputs[1].source_id,
        chunks[0].semantic_digest
    );
    assert_eq!(
        first.canonical_ordered_inputs[1].max_encoded_bytes,
        chunks[0].encoded_bytes
    );

    lookups.clear();
    let second = planner
        .primary_unit_at(
            1,
            |ordinal| {
                lookups.push(ordinal);
                chunks.get(ordinal as usize).cloned()
            },
            &limits,
        )
        .unwrap();
    assert_eq!(lookups, [1]);
    assert_eq!(
        second.interval,
        UnitInterval::EntityIdRange(outbe_ocomp_protocol::unit::EntityIdHalfOpenRange {
            start: ids[256],
            end: None,
        })
    );
    assert_eq!(
        second.canonical_ordered_inputs[1].source_id,
        chunks[1].semantic_digest
    );

    let plan = planner
        .commit_primary_catalog(chunks.iter().cloned(), &limits)
        .unwrap();
    let replay = planner
        .commit_primary_catalog(chunks.iter().cloned(), &limits)
        .unwrap();
    assert_eq!(plan, replay);
    assert_eq!(plan.primary_work_unit_count, 2);
    assert_eq!(plan.tribute_count, 257);
    assert_eq!(plan.wwd, 20_260_724);
    assert_eq!(plan.lysis_budget, U256::from(99_000_000_u64));
    assert_eq!(plan.logical_evaluation_time, 1_784_765_900);
    assert_eq!(
        plan.plan_hash(&limits).unwrap(),
        replay.plan_hash(&limits).unwrap()
    );

    let mut wrong_chunk = chunks[0].clone();
    wrong_chunk.first_key.0[0] ^= 1;
    assert!(planner
        .primary_unit_at(
            0,
            |ordinal| {
                if ordinal == 0 {
                    Some(wrong_chunk.clone())
                } else {
                    chunks.get(ordinal as usize).cloned()
                }
            },
            &limits,
        )
        .is_err());
    assert!(planner
        .commit_primary_catalog(std::iter::once(chunks[0].clone()), &limits)
        .is_err());
    assert!(planner
        .commit_primary_catalog(
            chunks
                .iter()
                .cloned()
                .chain(std::iter::once(chunks[1].clone())),
            &limits,
        )
        .is_err());

    let mut changed_budget = plan.clone();
    changed_budget.lysis_budget += U256::from(1);
    assert_ne!(
        changed_budget.plan_hash(&limits).unwrap(),
        plan.plan_hash(&limits).unwrap()
    );
}

#[test]
fn fidelity_map_unit_is_derived_only_from_plan_and_exact_enumerate_unit() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(257)).unwrap();
    let enumerate_unit_id = B256::repeat_byte(0x31);

    let first = planner
        .fidelity_map_unit_at(0, enumerate_unit_id, &limits)
        .unwrap();
    assert_eq!(first.phase, UnitPhase::FidelityMap);
    assert_eq!(
        first.interval,
        UnitInterval::FidelityIndexRange(outbe_ocomp_protocol::unit::FidelityIndexHalfOpenRange {
            start: 0,
            end: 256,
        })
    );
    assert_eq!(
        first
            .canonical_ordered_inputs
            .iter()
            .map(|input| (input.purpose, input.source_kind, input.source_id))
            .collect::<Vec<_>>(),
        [
            (
                InputPurpose::InputManifest,
                InputSourceKind::AuthenticatedRoot,
                planner_bindings(257).input_manifest_hash,
            ),
            (
                InputPurpose::EnumeratedTributes,
                InputSourceKind::UnitOutput,
                enumerate_unit_id,
            ),
            (
                InputPurpose::FidelityOpenings,
                InputSourceKind::AuthenticatedRoot,
                planner_bindings(257).fidelity_opening_root,
            ),
        ]
    );

    let second = planner
        .fidelity_map_unit_at(1, B256::repeat_byte(0x32), &limits)
        .unwrap();
    assert_eq!(
        second.interval,
        UnitInterval::FidelityIndexRange(outbe_ocomp_protocol::unit::FidelityIndexHalfOpenRange {
            start: 256,
            end: 257,
        })
    );
    assert_ne!(
        first.unit_id(&limits).unwrap(),
        planner
            .fidelity_map_unit_at(0, B256::repeat_byte(0x33), &limits)
            .unwrap()
            .unit_id(&limits)
            .unwrap()
    );
    assert!(planner
        .fidelity_map_unit_at(0, B256::ZERO, &limits)
        .is_err());
}

#[test]
fn fixed_reduce_units_bind_exact_left_right_producers_and_canonical_padding() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(513)).unwrap();
    let left = B256::repeat_byte(0x41);
    let right = B256::repeat_byte(0x42);

    let first = planner
        .fixed_reduce_unit_at(0, [Some(left), Some(right)], &limits)
        .unwrap();
    assert_eq!(first.phase, UnitPhase::FixedReduce);
    assert_eq!(
        first.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 1,
            index: 0
        })
    );
    assert_eq!(
        first
            .canonical_ordered_inputs
            .iter()
            .skip(1)
            .map(|input| (input.source_kind, input.source_id))
            .collect::<Vec<_>>(),
        [
            (InputSourceKind::UnitOutput, left),
            (InputSourceKind::UnitOutput, right),
        ]
    );

    let padded = planner
        .fixed_reduce_unit_at(1, [Some(left), None], &limits)
        .unwrap();
    assert_eq!(
        padded.canonical_ordered_inputs[2].source_kind,
        InputSourceKind::CanonicalEmpty
    );
    assert!(planner
        .fixed_reduce_unit_at(0, [Some(left), None], &limits)
        .is_err());
    assert!(planner
        .fixed_reduce_unit_at(1, [Some(left), Some(right)], &limits)
        .is_err());
}

#[test]
fn amount_map_unit_binds_exact_enumerate_fidelity_root_and_oracle_inputs() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(257)).unwrap();
    let ids = (0..257).map(entity_id).collect::<Vec<_>>();
    let chunks = [
        tribute_chunk_ref(0, &ids[..256], 10_000),
        tribute_chunk_ref(1, &ids[256..], 100),
    ];
    let enumerate = planner
        .primary_unit_at(1, |ordinal| chunks.get(ordinal as usize).cloned(), &limits)
        .unwrap();
    let enumerate_id = enumerate.unit_id(&limits).unwrap();
    let fidelity_id = B256::repeat_byte(0x51);
    let root_id = B256::repeat_byte(0x52);
    let amount = planner
        .amount_map_unit_at(1, &enumerate, fidelity_id, root_id, &limits)
        .unwrap();

    assert_eq!(amount.phase, UnitPhase::AmountMap);
    assert_eq!(amount.interval, enumerate.interval);
    assert_eq!(
        amount
            .canonical_ordered_inputs
            .iter()
            .map(|input| (input.purpose, input.source_kind, input.source_id))
            .collect::<Vec<_>>(),
        [
            (
                InputPurpose::InputManifest,
                InputSourceKind::AuthenticatedRoot,
                planner_bindings(257).input_manifest_hash,
            ),
            (
                InputPurpose::EnumeratedTributes,
                InputSourceKind::UnitOutput,
                enumerate_id,
            ),
            (
                InputPurpose::FidelityPartials,
                InputSourceKind::UnitOutput,
                fidelity_id,
            ),
            (
                InputPurpose::FiFractionTable,
                InputSourceKind::UnitOutput,
                root_id,
            ),
            (
                InputPurpose::OracleOpenings,
                InputSourceKind::AuthenticatedRoot,
                planner_bindings(257).oracle_opening_root,
            ),
        ]
    );
}

#[test]
fn gratis_prefix_units_bind_exact_amount_children_and_padding() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(513)).unwrap();
    let left = B256::repeat_byte(0x61);
    let right = B256::repeat_byte(0x62);

    let leaf = planner
        .gratis_prefix_unit_at(0, &[Some(left)], &limits)
        .unwrap();
    assert_eq!(leaf.phase, UnitPhase::GratisPrefix);
    assert_eq!(
        leaf.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 0,
            index: 0
        })
    );
    assert_eq!(
        leaf.canonical_ordered_inputs[1].purpose,
        InputPurpose::AmountRecords
    );
    assert_eq!(leaf.canonical_ordered_inputs[1].source_id, left);

    let internal = planner
        .gratis_prefix_unit_at(3, &[Some(left), Some(right)], &limits)
        .unwrap();
    assert_eq!(
        internal.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 1,
            index: 0
        })
    );
    assert!(internal
        .canonical_ordered_inputs
        .iter()
        .skip(1)
        .all(|input| input.purpose == InputPurpose::GratisPrefixTable));

    let padded = planner
        .gratis_prefix_unit_at(4, &[Some(left), None], &limits)
        .unwrap();
    assert_eq!(
        padded.canonical_ordered_inputs[2].source_kind,
        InputSourceKind::CanonicalEmpty
    );
    assert!(planner
        .gratis_prefix_unit_at(0, &[Some(left), Some(right)], &limits)
        .is_err());
    assert!(planner
        .gratis_prefix_unit_at(4, &[Some(left), Some(right)], &limits)
        .is_err());
}

#[test]
fn gratis_prefix_down_units_bind_parent_and_immediate_summaries() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(513)).unwrap();
    let parent = B256::repeat_byte(0x71);
    let left = B256::repeat_byte(0x72);
    let right = B256::repeat_byte(0x73);

    let root = planner
        .gratis_prefix_down_unit_at(0, &[Some(left), Some(right)], &limits)
        .unwrap();
    assert_eq!(root.phase, UnitPhase::GratisPrefixDown);
    assert_eq!(
        root.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 2,
            index: 0
        })
    );

    let internal = planner
        .gratis_prefix_down_unit_at(2, &[Some(parent), Some(left), None], &limits)
        .unwrap();
    assert_eq!(
        internal.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 1,
            index: 1
        })
    );
    assert_eq!(internal.canonical_ordered_inputs[1].source_id, parent);
    assert_eq!(
        internal.canonical_ordered_inputs[3].source_kind,
        InputSourceKind::CanonicalEmpty
    );

    let leaf = planner
        .gratis_prefix_down_unit_at(5, &[Some(parent), Some(left)], &limits)
        .unwrap();
    assert_eq!(
        leaf.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 0,
            index: 2
        })
    );
    assert!(leaf
        .canonical_ordered_inputs
        .iter()
        .skip(1)
        .all(|input| input.purpose == InputPurpose::GratisPrefixTable));
    assert!(planner
        .gratis_prefix_down_unit_at(0, &[Some(parent), Some(left), Some(right)], &limits)
        .is_err());
}

#[test]
fn output_finalize_unit_binds_exact_amount_and_leaf_prefix() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(257)).unwrap();
    let ids = (0..257).map(entity_id).collect::<Vec<_>>();
    let chunks = [
        tribute_chunk_ref(0, &ids[..256], 10_000),
        tribute_chunk_ref(1, &ids[256..], 100),
    ];
    let enumerate = planner
        .primary_unit_at(1, |ordinal| chunks.get(ordinal as usize).cloned(), &limits)
        .unwrap();
    let amount = planner
        .amount_map_unit_at(
            1,
            &enumerate,
            B256::repeat_byte(0x91),
            B256::repeat_byte(0x92),
            &limits,
        )
        .unwrap();
    let prefix_id = B256::repeat_byte(0x93);
    let finalize = planner
        .output_finalize_unit_at(1, &amount, prefix_id, &limits)
        .unwrap();

    assert_eq!(finalize.phase, UnitPhase::OutputFinalize);
    assert_eq!(finalize.interval, amount.interval);
    assert_eq!(
        finalize
            .canonical_ordered_inputs
            .iter()
            .skip(1)
            .map(|input| (input.purpose, input.source_kind, input.source_id))
            .collect::<Vec<_>>(),
        [
            (
                InputPurpose::AmountRecords,
                InputSourceKind::UnitOutput,
                amount.unit_id(&limits).unwrap(),
            ),
            (
                InputPurpose::GratisPrefixTable,
                InputSourceKind::UnitOutput,
                prefix_id,
            ),
        ]
    );
    assert!(planner
        .output_finalize_unit_at(1, &amount, B256::ZERO, &limits)
        .is_err());
    let mut wrong_phase = amount;
    wrong_phase.phase = UnitPhase::Enumerate;
    assert!(planner
        .output_finalize_unit_at(1, &wrong_phase, prefix_id, &limits)
        .is_err());
}

#[test]
fn shuffle_units_bind_only_the_exact_materialized_producer_runs() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(513)).unwrap();
    let leaf_source = B256::repeat_byte(0x71);
    let leaf = planner
        .shuffle_unit_at(UnitPhase::OwnerShuffle, 2, &[leaf_source], &limits)
        .unwrap();
    assert_eq!(
        leaf.interval,
        UnitInterval::CanonicalRunSpan(outbe_ocomp_protocol::unit::CanonicalRunSpan {
            start_run: 2,
            end_run: 3,
        })
    );
    assert_eq!(
        leaf.canonical_ordered_inputs[1].purpose,
        InputPurpose::FinalizedOutputRecords
    );
    assert_eq!(leaf.canonical_ordered_inputs[1].source_id, leaf_source);

    let left = B256::repeat_byte(0x72);
    let right = B256::repeat_byte(0x73);
    let root = planner
        .shuffle_unit_at(UnitPhase::OwnerShuffle, 4, &[left, right], &limits)
        .unwrap();
    assert_eq!(
        root.interval,
        UnitInterval::CanonicalRunSpan(outbe_ocomp_protocol::unit::CanonicalRunSpan {
            start_run: 0,
            end_run: 3,
        })
    );
    assert_eq!(
        root.canonical_ordered_inputs[1..]
            .iter()
            .map(|input| (input.purpose, input.source_kind, input.source_id))
            .collect::<Vec<_>>(),
        [
            (
                InputPurpose::OwnerOrderedRecords,
                InputSourceKind::UnitOutput,
                left,
            ),
            (
                InputPurpose::OwnerOrderedRecords,
                InputSourceKind::UnitOutput,
                right,
            ),
        ]
    );
    assert!(planner
        .shuffle_unit_at(UnitPhase::OwnerShuffle, 4, &[left], &limits)
        .is_err());
    assert!(planner
        .shuffle_unit_at(UnitPhase::BucketShuffle, 4, &[left, B256::ZERO], &limits,)
        .is_err());
    assert!(planner
        .shuffle_unit_at(UnitPhase::RootReduce, 4, &[left, right], &limits)
        .is_err());
}

#[test]
fn root_reduce_units_bind_exact_leaf_shuffle_roots_and_padded_summaries() {
    let limits = poc_schema_limits();
    let planner = LysisPlannerV1::new(planner_bindings(513)).unwrap();
    let finalized = B256::repeat_byte(0x81);
    let owner_root = B256::repeat_byte(0x82);
    let bucket_root = B256::repeat_byte(0x83);

    let leaf = planner
        .root_reduce_unit_at(
            2,
            &[Some(finalized), Some(owner_root), Some(bucket_root)],
            &limits,
        )
        .unwrap();
    assert_eq!(leaf.phase, UnitPhase::RootReduce);
    assert_eq!(
        leaf.interval,
        UnitInterval::BinaryReducerNode(outbe_ocomp_protocol::unit::BinaryReducerNode {
            level: 0,
            index: 2
        })
    );
    assert_eq!(
        leaf.canonical_ordered_inputs[1..]
            .iter()
            .map(|input| (input.purpose, input.source_kind, input.source_id))
            .collect::<Vec<_>>(),
        [
            (
                InputPurpose::FinalizedOutputRecords,
                InputSourceKind::UnitOutput,
                finalized,
            ),
            (
                InputPurpose::OwnerOrderedRecords,
                InputSourceKind::UnitOutput,
                owner_root,
            ),
            (
                InputPurpose::BucketOrderedRecords,
                InputSourceKind::UnitOutput,
                bucket_root,
            ),
        ]
    );

    let left = B256::repeat_byte(0x84);
    let right = B256::repeat_byte(0x85);
    let internal = planner
        .root_reduce_unit_at(3, &[Some(left), Some(right)], &limits)
        .unwrap();
    assert!(internal
        .canonical_ordered_inputs
        .iter()
        .skip(1)
        .all(|input| input.purpose == InputPurpose::RootSummary));

    let padded = planner
        .root_reduce_unit_at(4, &[Some(left), None], &limits)
        .unwrap();
    assert_eq!(
        padded.canonical_ordered_inputs[2].source_kind,
        InputSourceKind::CanonicalEmpty
    );
    assert!(planner
        .root_reduce_unit_at(2, &[Some(finalized), Some(owner_root)], &limits)
        .is_err());
    assert!(planner
        .root_reduce_unit_at(3, &[Some(left), Some(B256::ZERO)], &limits)
        .is_err());
}

#[test]
fn one_shard_root_reduce_finishes_at_the_leaf_without_a_padded_node() {
    let topology = LysisPlanTopologyV1::new(1).unwrap();
    let final_position = PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::RootReduce,
        level: 0,
        index: 0,
    };

    assert_eq!(topology.phase_unit_count(UnitPhase::RootReduce), 1);
    assert_eq!(
        topology
            .phase_position_at(UnitPhase::RootReduce, 0)
            .unwrap(),
        final_position
    );
    assert_eq!(
        topology
            .plan_position_at(topology.plan_ordinal_of(final_position).unwrap())
            .unwrap(),
        final_position
    );
    assert!(topology
        .phase_position_at(UnitPhase::RootReduce, 1)
        .is_err());
}

#[test]
fn gratis_scan_artifacts_are_typed_canonical_and_reject_trailing_bytes() {
    let limits = poc_schema_limits();
    let summary = GratisSegmentSummaryV1 {
        start_ordinal: 256,
        end_ordinal: 513,
        checked_segment_gratis_total: U256::from(77),
    };
    let encoded_summary = encode_gratis_segment_summary(&summary, &limits).unwrap();
    assert_eq!(
        decode_gratis_segment_summary(&encoded_summary, &limits).unwrap(),
        summary
    );

    let branch = GratisPrefixDownOutputV1::Branch([
        Some(GratisIncomingV1 {
            start_ordinal: 0,
            end_ordinal: 256,
            incoming_remaining: Some(U256::from(1_000)),
        }),
        Some(GratisIncomingV1 {
            start_ordinal: 256,
            end_ordinal: 513,
            incoming_remaining: Some(U256::from(700)),
        }),
    ]);
    let encoded_branch = encode_gratis_prefix_down_output(&branch, &limits).unwrap();
    assert_eq!(
        decode_gratis_prefix_down_output(&encoded_branch, &limits).unwrap(),
        branch
    );

    let leaf = GratisPrefixDownOutputV1::Leaf(GratisLeafPrefixV1 {
        segment_ordinal: 2,
        incoming_remaining: U256::from(700),
        outgoing_remaining: U256::from(623),
        first_error_ordinal: None,
    });
    let mut encoded_leaf = encode_gratis_prefix_down_output(&leaf, &limits).unwrap();
    assert_eq!(
        decode_gratis_prefix_down_output(&encoded_leaf, &limits).unwrap(),
        leaf
    );
    encoded_leaf.push(0);
    assert!(decode_gratis_prefix_down_output(&encoded_leaf, &limits).is_err());

    let interval = B256::repeat_byte(0x81);
    let left = (B256::repeat_byte(0x82), 256);
    let right = (B256::repeat_byte(0x83), 257);
    let complete = gratis_summary_coverage(interval, [Some(left), Some(right)]).unwrap();
    assert_eq!(complete.count, 513);
    assert_ne!(complete.root, B256::ZERO);
    assert_ne!(
        complete,
        gratis_summary_coverage(interval, [Some(left), None]).unwrap()
    );
    assert!(gratis_summary_coverage(interval, [None, Some(right)]).is_err());
}

#[test]
fn complete_lysis_dag_has_frozen_phase_counts_and_both_prefix_directions() {
    for primary_count in 1..=8 {
        let topology = LysisPlanTopologyV1::new(primary_count).unwrap();
        let padded = primary_count.next_power_of_two().max(2);
        let internal = padded - 1;
        let active_internal = (1..=topology.tree().height())
            .map(|level| primary_count.div_ceil(1_u32 << level))
            .sum::<u32>();

        assert_eq!(
            topology.phase_unit_count(UnitPhase::Enumerate),
            primary_count
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::FidelityMap),
            primary_count
        );
        assert_eq!(topology.phase_unit_count(UnitPhase::FixedReduce), internal);
        assert_eq!(
            topology.phase_unit_count(UnitPhase::AmountMap),
            primary_count
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::GratisPrefix),
            primary_count + active_internal
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::GratisPrefixDown),
            primary_count + active_internal
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::OutputFinalize),
            primary_count
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::OwnerShuffle),
            primary_count * 2 - 1
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::BucketShuffle),
            primary_count * 2 - 1
        );
        assert_eq!(
            topology.phase_unit_count(UnitPhase::RootReduce),
            if primary_count == 1 {
                1
            } else {
                primary_count + internal
            }
        );

        let prefix = topology
            .phase_position_at(UnitPhase::GratisPrefix, primary_count)
            .unwrap();
        assert_eq!(
            prefix,
            PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefix,
                level: 1,
                index: 0,
            }
        );
        let prefix_down = topology
            .phase_position_at(UnitPhase::GratisPrefixDown, 0)
            .unwrap();
        assert_eq!(
            prefix_down,
            PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefixDown,
                level: topology.tree().height(),
                index: 0,
            }
        );
        assert_eq!(
            topology
                .phase_position_at(
                    UnitPhase::GratisPrefixDown,
                    topology.phase_unit_count(UnitPhase::GratisPrefixDown) - 1,
                )
                .unwrap(),
            PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefixDown,
                level: 0,
                index: primary_count - 1,
            }
        );
    }
}

#[test]
fn complete_plan_cursor_uses_protocol_order_not_runtime_completion_order() {
    let topology = LysisPlanTopologyV1::new(2).unwrap();
    let positions = (0..topology.total_unit_count())
        .map(|ordinal| topology.plan_position_at(ordinal).unwrap())
        .collect::<Vec<_>>();
    let phases = positions
        .iter()
        .map(PlannedUnitPositionV1::phase)
        .collect::<Vec<_>>();
    let mut runs = Vec::new();
    for phase in phases {
        if runs.last() != Some(&phase) {
            runs.push(phase);
        }
    }
    assert_eq!(
        runs,
        [
            UnitPhase::Enumerate,
            UnitPhase::FidelityMap,
            UnitPhase::FixedReduce,
            UnitPhase::AmountMap,
            UnitPhase::GratisPrefix,
            UnitPhase::GratisPrefixDown,
            UnitPhase::OutputFinalize,
            UnitPhase::OwnerShuffle,
            UnitPhase::BucketShuffle,
            UnitPhase::RootReduce,
        ]
    );
}

#[test]
fn exact_plan_positions_round_trip_to_their_global_ordinals() {
    for primary_count in 1..=8 {
        let topology = LysisPlanTopologyV1::new(primary_count).unwrap();
        for ordinal in 0..topology.total_unit_count() {
            let position = topology.plan_position_at(ordinal).unwrap();
            assert_eq!(topology.plan_ordinal_of(position).unwrap(), ordinal);
        }
    }

    let primary_count = primary_work_unit_count(1_000_000_000).unwrap();
    let topology = LysisPlanTopologyV1::new(primary_count).unwrap();
    let last = topology.total_unit_count() - 1;
    for ordinal in [0, primary_count - 1, primary_count, last / 2, last] {
        let position = topology.plan_position_at(ordinal).unwrap();
        assert_eq!(topology.plan_ordinal_of(position).unwrap(), ordinal);
    }
}

#[test]
fn three_shuffle_runs_have_only_real_binary_merges() {
    let topology = LysisPlanTopologyV1::new(3).unwrap();
    for phase in [UnitPhase::OwnerShuffle, UnitPhase::BucketShuffle] {
        assert_eq!(topology.phase_unit_count(phase), 5);

        let root = topology.phase_position_at(phase, 4).unwrap();
        assert_eq!(
            root,
            PlannedUnitPositionV1::RunSpan {
                phase,
                level: 2,
                index: 0,
                start_run: 0,
                end_run: 3,
            }
        );
        assert_eq!(
            topology.required_producers(root).unwrap(),
            [
                PlannedProducerV1::Unit(PlannedUnitPositionV1::RunSpan {
                    phase,
                    level: 1,
                    index: 0,
                    start_run: 0,
                    end_run: 2,
                }),
                PlannedProducerV1::Unit(PlannedUnitPositionV1::RunSpan {
                    phase,
                    level: 0,
                    index: 2,
                    start_run: 2,
                    end_run: 3,
                }),
            ]
        );
    }
}

#[test]
fn shuffle_topology_is_exact_for_small_boundaries_and_a_billion_tributes() {
    for primary_count in [1, 2, 3, 5, 256, 257] {
        let topology = LysisPlanTopologyV1::new(primary_count).unwrap();
        for phase in [UnitPhase::OwnerShuffle, UnitPhase::BucketShuffle] {
            let unit_count = primary_count * 2 - 1;
            assert_eq!(topology.phase_unit_count(phase), unit_count);

            let positions = (0..unit_count)
                .map(|ordinal| topology.phase_position_at(phase, ordinal).unwrap())
                .collect::<Vec<_>>();
            let root = *positions.last().unwrap();
            assert!(matches!(
                root,
                PlannedUnitPositionV1::RunSpan {
                    start_run: 0,
                    end_run,
                    ..
                } if end_run == primary_count
            ));

            for (consumer_ordinal, consumer) in positions
                .iter()
                .copied()
                .enumerate()
                .skip(primary_count as usize)
            {
                let producers = topology.required_producers(consumer).unwrap();
                assert_eq!(producers.len(), 2);
                for producer in producers {
                    let PlannedProducerV1::Unit(producer) = producer else {
                        panic!("shuffle topology must not contain CanonicalEmpty");
                    };
                    let producer_ordinal = positions
                        .iter()
                        .position(|candidate| *candidate == producer)
                        .expect("shuffle producer belongs to the same phase");
                    assert!(producer_ordinal < consumer_ordinal);
                }
            }
        }
    }

    let billion_primary = primary_work_unit_count(1_000_000_000).unwrap();
    assert_eq!(billion_primary, 3_906_250);
    let topology = LysisPlanTopologyV1::new(billion_primary).unwrap();
    let unit_count = topology.phase_unit_count(UnitPhase::OwnerShuffle);
    assert_eq!(unit_count, 7_812_499);
    assert!(matches!(
        topology
            .phase_position_at(UnitPhase::OwnerShuffle, unit_count - 1)
            .unwrap(),
        PlannedUnitPositionV1::RunSpan {
            start_run: 0,
            end_run: 3_906_250,
            ..
        }
    ));
}

#[test]
fn owner_merge_preserves_source_span_when_every_contributor_is_excluded() {
    let mut sink_calls = 0_u32;
    let summary = merge_owner_runs_streaming(
        CanonicalRunSpanV1 {
            start_run: 0,
            end_run: 1,
        },
        Vec::new(),
        CanonicalRunSpanV1 {
            start_run: 1,
            end_run: 2,
        },
        Vec::new(),
        256,
        |_, _| {
            sink_calls += 1;
            Ok::<_, ()>(())
        },
    )
    .unwrap();

    assert_eq!(
        summary.span,
        CanonicalRunSpanV1 {
            start_run: 0,
            end_run: 2,
        }
    );
    assert_eq!(summary.record_count, 0);
    assert_eq!(summary.chunk_count, 0);
    assert_eq!(summary.checked_eligible_nominal_total, U256::ZERO);
    assert_eq!(sink_calls, 0);
}

#[test]
fn prefix_down_reads_parent_prefix_and_immediate_child_summaries() {
    let topology = LysisPlanTopologyV1::new(3).unwrap();
    let root = PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::GratisPrefixDown,
        level: 2,
        index: 0,
    };
    assert_eq!(
        topology.required_producers(root).unwrap(),
        [
            PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefix,
                level: 1,
                index: 0,
            }),
            PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefix,
                level: 1,
                index: 1,
            }),
        ]
    );

    let internal = PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::GratisPrefixDown,
        level: 1,
        index: 1,
    };
    assert_eq!(
        topology.required_producers(internal).unwrap(),
        [
            PlannedProducerV1::Unit(root),
            PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefix,
                level: 0,
                index: 2,
            }),
            PlannedProducerV1::CanonicalEmpty {
                purpose: InputPurpose::GratisPrefixTable,
                padded_ordinal: 3,
            },
        ]
    );

    let leaf = PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::GratisPrefixDown,
        level: 0,
        index: 2,
    };
    assert_eq!(
        topology.required_producers(leaf).unwrap(),
        [
            PlannedProducerV1::Unit(internal),
            PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::GratisPrefix,
                level: 0,
                index: 2,
            }),
        ]
    );
}

#[test]
fn every_derived_producer_is_an_earlier_exact_plan_member() {
    for primary_count in 1..=8 {
        let topology = LysisPlanTopologyV1::new(primary_count).unwrap();
        let positions = (0..topology.total_unit_count())
            .map(|ordinal| topology.plan_position_at(ordinal).unwrap())
            .collect::<Vec<_>>();

        for (consumer_ordinal, consumer) in positions.iter().copied().enumerate() {
            let producers = topology.required_producers(consumer).unwrap();
            assert!(producers.len() <= 3);
            for producer in producers {
                let PlannedProducerV1::Unit(producer) = producer else {
                    continue;
                };
                let producer_ordinal = positions
                    .iter()
                    .position(|candidate| *candidate == producer)
                    .expect("producer is an exact member of the same plan");
                assert!(
                    producer_ordinal < consumer_ordinal,
                    "{producer:?} must precede {consumer:?}"
                );
                assert_ne!(producer, consumer, "a UnitId cannot depend on itself");
            }
        }
    }
}

#[test]
fn producer_membership_rejects_missing_duplicate_and_replaced_inputs() {
    let topology = LysisPlanTopologyV1::new(3).unwrap();
    let consumer = PlannedUnitPositionV1::TreeNode {
        phase: UnitPhase::FixedReduce,
        level: 1,
        index: 0,
    };
    let expected = topology.required_producers(consumer).unwrap();
    assert_eq!(expected.len(), 2);
    assert!(topology
        .validate_exact_producers(consumer, &expected)
        .is_ok());
    assert!(topology
        .validate_exact_producers(consumer, &expected[..1])
        .is_err());
    assert!(topology
        .validate_exact_producers(consumer, &[expected[0], expected[0]])
        .is_err());
    assert!(topology
        .validate_exact_producers(
            consumer,
            &[
                expected[0],
                PlannedProducerV1::Unit(PlannedUnitPositionV1::Primary {
                    phase: UnitPhase::Enumerate,
                    ordinal: 2,
                }),
            ],
        )
        .is_err());
}

#[test]
fn amount_map_requires_the_matching_fidelity_leaf_not_only_the_global_fraction_table() {
    let topology = LysisPlanTopologyV1::new(3).unwrap();
    let consumer = PlannedUnitPositionV1::Primary {
        phase: UnitPhase::AmountMap,
        ordinal: 1,
    };
    let expected = topology.required_producers(consumer).unwrap();
    assert_eq!(
        expected,
        [
            PlannedProducerV1::Unit(PlannedUnitPositionV1::Primary {
                phase: UnitPhase::Enumerate,
                ordinal: 1,
            }),
            PlannedProducerV1::Unit(PlannedUnitPositionV1::Primary {
                phase: UnitPhase::FidelityMap,
                ordinal: 1,
            }),
            PlannedProducerV1::Unit(PlannedUnitPositionV1::TreeNode {
                phase: UnitPhase::FixedReduce,
                level: topology.tree().height(),
                index: 0,
            }),
        ]
    );
    assert!(topology
        .validate_exact_producers(consumer, &[expected[0], expected[2]])
        .is_err());
}

#[test]
fn fidelity_map_and_fixed_reduce_match_the_native_lysis_fraction_table() {
    let day = WorldwideDay::new(20_260_724);
    let mut tributes = (0..257_u32)
        .map(|ordinal| {
            let mut owner_bytes = [0_u8; 20];
            owner_bytes[16..].copy_from_slice(&(ordinal + 1).to_be_bytes());
            let owner = Address::from(owner_bytes);
            ObservedTributeV1 {
                tribute: TributeInputV1 {
                    tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
                    owner,
                    worldwide_day: day,
                    issuance_currency: 978,
                    nominal_amount_minor: U256::from(1_000_000_u64) * SIX_DECIMAL_SCALE,
                    reference_currency: 840,
                    tribute_price_minor: U256::ZERO,
                    exclude_from_intex_issuance: ordinal.is_multiple_of(11),
                },
                first_league: ObservationValueV1::Value(7),
                second_league: ObservationValueV1::Value(7),
                conditional_entry_price_minor: ObservationValueV1::Unavailable,
                nod_target_available: true,
            }
        })
        .collect::<Vec<_>>();
    tributes.sort_by_key(|observed| observed.tribute.tribute_id);
    let total_nominal = tributes
        .iter()
        .map(|observed| observed.tribute.nominal_amount_minor)
        .sum::<U256>();
    let gratis_allocation = total_nominal * U256::from(32_u8) / U256::from(100_u8);
    let expected = execute(ProgramInputV1 {
        worldwide_day: day,
        logical_evaluation_time: 1_784_765_900,
        gratis_allocation,
        mandatory_entry_price_840: ObservationValueV1::Value(SIX_DECIMAL_SCALE),
        tributes: tributes.clone(),
    })
    .unwrap();

    let first = fidelity_map(0, &tributes[..256]).unwrap();
    let second = fidelity_map(256, &tributes[256..]).unwrap();
    assert_eq!(first.observations.len(), 256);
    assert_eq!(second.observations.len(), 1);
    let aggregate = fidelity_reduce(&first.aggregate, &second.aggregate).unwrap();
    let actual = finalize_fi_fraction_table(&aggregate, gratis_allocation).unwrap();

    assert_eq!(aggregate.tribute_count, 257);
    assert_eq!(aggregate.checked_total_nominal, expected.total_nominal);
    assert_eq!(actual, expected.league_fractions);
}

#[test]
fn fidelity_phase_rejects_missing_mismatched_and_non_adjacent_evidence() {
    let day = WorldwideDay::new(20_260_724);
    let owner = Address::repeat_byte(9);
    let mut observed = ObservedTributeV1 {
        tribute: TributeInputV1 {
            tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
            owner,
            worldwide_day: day,
            issuance_currency: 978,
            nominal_amount_minor: SIX_DECIMAL_SCALE,
            reference_currency: 840,
            tribute_price_minor: U256::ZERO,
            exclude_from_intex_issuance: false,
        },
        first_league: ObservationValueV1::Unavailable,
        second_league: ObservationValueV1::Value(7),
        conditional_entry_price_minor: ObservationValueV1::Unavailable,
        nod_target_available: true,
    };
    assert!(fidelity_map(0, &[observed.clone()]).is_err());

    observed.first_league = ObservationValueV1::Value(6);
    assert!(fidelity_map(0, &[observed.clone()]).is_err());

    observed.first_league = ObservationValueV1::Value(7);
    let left = fidelity_map(0, &[observed.clone()]).unwrap();
    let right = fidelity_map(2, &[observed]).unwrap();
    assert!(fidelity_reduce(&left.aggregate, &right.aggregate).is_err());
}

#[test]
fn amount_and_output_finalize_phases_match_sequential_lysis_for_shard_cap_plus_one() {
    let day = WorldwideDay::new(20_260_724);
    let mut tributes = (0..257_u32)
        .map(|ordinal| {
            let mut owner_bytes = [0_u8; 20];
            owner_bytes[16..].copy_from_slice(&(ordinal + 1).to_be_bytes());
            let owner = Address::from(owner_bytes);
            ObservedTributeV1 {
                tribute: TributeInputV1 {
                    tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
                    owner,
                    worldwide_day: day,
                    issuance_currency: 978,
                    nominal_amount_minor: U256::from(1_000_000_u64) * SIX_DECIMAL_SCALE,
                    reference_currency: 840,
                    tribute_price_minor: U256::from(2_u8) * SIX_DECIMAL_SCALE,
                    exclude_from_intex_issuance: ordinal.is_multiple_of(11),
                },
                first_league: ObservationValueV1::Value(7),
                second_league: ObservationValueV1::Value(7),
                conditional_entry_price_minor: ObservationValueV1::Unavailable,
                nod_target_available: true,
            }
        })
        .collect::<Vec<_>>();
    tributes.sort_by_key(|observed| observed.tribute.tribute_id);
    let total_nominal = tributes
        .iter()
        .map(|observed| observed.tribute.nominal_amount_minor)
        .sum::<U256>();
    let lysis_budget = total_nominal * U256::from(32_u8) / U256::from(100_u8);
    let logical_time = 1_784_765_900;
    let entry_price = SIX_DECIMAL_SCALE;
    let sequential = execute(ProgramInputV1 {
        worldwide_day: day,
        logical_evaluation_time: logical_time,
        gratis_allocation: lysis_budget,
        mandatory_entry_price_840: ObservationValueV1::Value(entry_price),
        tributes: tributes.clone(),
    })
    .unwrap();

    let fidelity_left = fidelity_map(0, &tributes[..256]).unwrap();
    let fidelity_right = fidelity_map(256, &tributes[256..]).unwrap();
    let fidelity_root =
        fidelity_reduce(&fidelity_left.aggregate, &fidelity_right.aggregate).unwrap();
    let fractions = finalize_fi_fraction_table(&fidelity_root, lysis_budget).unwrap();
    let amount_left = amount_map(
        0,
        &tributes[..256],
        &fidelity_left.observations,
        &fractions,
        entry_price,
    )
    .unwrap();
    let amount_right = amount_map(
        256,
        &tributes[256..],
        &fidelity_right.observations,
        &fractions,
        entry_price,
    )
    .unwrap();
    let limits = poc_schema_limits();
    let encoded_amount = encode_amount_run(&amount_right, &limits).unwrap();
    assert_eq!(
        decode_amount_run(&encoded_amount, &limits).unwrap(),
        amount_right
    );
    let mut trailing_amount = encoded_amount;
    trailing_amount.push(0);
    assert!(decode_amount_run(&trailing_amount, &limits).is_err());

    let left_summary = gratis_summary(
        0,
        &amount_left
            .ordered_records
            .iter()
            .map(|record| record.gratis_load_minor)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let right_summary = gratis_summary(
        256,
        &amount_right
            .ordered_records
            .iter()
            .map(|record| record.gratis_load_minor)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let prefixes = gratis_prefix_down(
        Some(lysis_budget),
        GratisSummaryValueV1::Summary(left_summary),
        GratisSummaryValueV1::Summary(right_summary),
    )
    .unwrap();
    let left_prefix = finalize_gratis_leaf(
        prefixes[0].as_ref().unwrap().incoming_remaining,
        0,
        &amount_left
            .ordered_records
            .iter()
            .map(|record| record.gratis_load_minor)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let right_prefix = finalize_gratis_leaf(
        prefixes[1].as_ref().unwrap().incoming_remaining,
        256,
        &amount_right
            .ordered_records
            .iter()
            .map(|record| record.gratis_load_minor)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let finalized_left = output_finalize(&amount_left, &left_prefix, logical_time).unwrap();
    let finalized_right = output_finalize(&amount_right, &right_prefix, logical_time).unwrap();
    assert_eq!(
        finalized_left.checked_tribute_nominal_total,
        amount_left
            .ordered_records
            .iter()
            .map(|record| record.nominal_amount_minor)
            .sum::<U256>()
    );
    assert_eq!(
        finalized_right.checked_tribute_nominal_total,
        amount_right
            .ordered_records
            .iter()
            .map(|record| record.nominal_amount_minor)
            .sum::<U256>()
    );
    assert_eq!(
        finalized_left
            .checked_tribute_nominal_total
            .checked_add(finalized_right.checked_tribute_nominal_total)
            .unwrap(),
        total_nominal
    );
    let encoded_finalized = encode_finalized_output_run(&finalized_right, &limits).unwrap();
    assert_eq!(
        decode_finalized_output_run(&encoded_finalized, &limits).unwrap(),
        finalized_right
    );
    let mut trailing_finalized = encoded_finalized;
    trailing_finalized.push(0);
    assert!(decode_finalized_output_run(&trailing_finalized, &limits).is_err());
    let records = finalized_left
        .ordered_records
        .iter()
        .chain(&finalized_right.ordered_records)
        .cloned()
        .collect::<Vec<_>>();

    assert_eq!(
        records
            .iter()
            .map(|record| record.nod_action.clone())
            .collect::<Vec<_>>(),
        sequential.nod_actions
    );
    let mut contributors = records
        .iter()
        .filter_map(|record| record.contributor_action.clone())
        .collect::<Vec<_>>();
    contributors.sort_by_key(|action| action.owner);
    assert_eq!(
        contributors
            .iter()
            .map(|action| (action.owner, action.nominal_amount_minor))
            .collect::<Vec<_>>(),
        sequential
            .contributors
            .iter()
            .map(|action| (action.owner, action.nominal_amount_minor))
            .collect::<Vec<_>>()
    );
    assert_eq!(right_prefix.outgoing_remaining, sequential.remaining_gratis);

    let owner_left = shuffle_owners(&finalized_left).unwrap();
    let owner_right = shuffle_owners(&finalized_right).unwrap();
    let mut owner_records = owner_left
        .ordered_contributors
        .iter()
        .chain(&owner_right.ordered_contributors)
        .collect::<Vec<_>>();
    owner_records.sort_by_key(|action| (action.owner, action.source_tribute_id));
    assert_eq!(
        owner_records
            .iter()
            .map(|action| (action.owner, action.nominal_amount_minor))
            .collect::<Vec<_>>(),
        sequential
            .contributors
            .iter()
            .map(|action| (action.owner, action.nominal_amount_minor))
            .collect::<Vec<_>>()
    );

    let bucket_left = shuffle_buckets(&finalized_left).unwrap();
    let bucket_right = shuffle_buckets(&finalized_right).unwrap();
    assert!(owner_left.ordered_contributors.len() <= 256);
    assert!(bucket_left.ordered_records.len() <= 256);
    let mut bucket_ordinals = bucket_left
        .ordered_records
        .iter()
        .chain(&bucket_right.ordered_records)
        .map(|record| record.raw_ordinal)
        .collect::<Vec<_>>();
    bucket_ordinals.sort_unstable();
    assert_eq!(bucket_ordinals, (0..257_u32).collect::<Vec<_>>());

    let mut owner_chunk_sizes = Vec::new();
    let mut previous_merged_owner = None;
    let owner_summary = merge_owner_runs_streaming(
        CanonicalRunSpanV1 {
            start_run: 0,
            end_run: 1,
        },
        owner_left.ordered_contributors.clone(),
        CanonicalRunSpanV1 {
            start_run: 1,
            end_run: 2,
        },
        owner_right.ordered_contributors.clone(),
        64,
        |_, chunk| {
            owner_chunk_sizes.push(chunk.len());
            for action in chunk {
                assert!(previous_merged_owner.is_none_or(|owner| owner < action.owner));
                previous_merged_owner = Some(action.owner);
            }
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(
        owner_summary.record_count as usize,
        sequential.contributors.len()
    );
    assert!(owner_chunk_sizes.iter().all(|count| *count <= 64));
    assert_eq!(owner_summary.chunk_count as usize, owner_chunk_sizes.len());

    let mut bucket_chunk_sizes = Vec::new();
    let mut previous_bucket_key = None;
    let bucket_summary = merge_bucket_runs_streaming(
        CanonicalRunSpanV1 {
            start_run: 0,
            end_run: 1,
        },
        bucket_left.ordered_records.clone(),
        CanonicalRunSpanV1 {
            start_run: 1,
            end_run: 2,
        },
        bucket_right.ordered_records.clone(),
        64,
        |_, chunk| {
            bucket_chunk_sizes.push(chunk.len());
            for record in chunk {
                let key = (record.bucket_key, record.raw_ordinal);
                assert!(previous_bucket_key.is_none_or(|previous| previous < key));
                previous_bucket_key = Some(key);
            }
            Ok::<_, ()>(())
        },
    )
    .unwrap();
    assert_eq!(bucket_summary.record_count, 257);
    assert!(bucket_chunk_sizes.iter().all(|count| *count <= 64));
    assert!(merge_bucket_runs_streaming(
        CanonicalRunSpanV1 {
            start_run: 1,
            end_run: 2,
        },
        bucket_right.ordered_records,
        CanonicalRunSpanV1 {
            start_run: 0,
            end_run: 1,
        },
        bucket_left.ordered_records,
        64,
        |_, _| Ok::<_, ()>(()),
    )
    .is_err());
    assert!(matches!(
        merge_owner_runs_streaming(
            CanonicalRunSpanV1 {
                start_run: 0,
                end_run: 1,
            },
            owner_left.ordered_contributors,
            CanonicalRunSpanV1 {
                start_run: 1,
                end_run: 2,
            },
            owner_right.ordered_contributors,
            64,
            |_, _| Err::<(), _>("persist failed"),
        ),
        Err(StreamingMergeErrorV1::Sink("persist failed"))
    ));

    let mut wrong_coverage = finalized_left.clone();
    wrong_coverage.ordered_records[0].raw_ordinal = 1;
    assert!(shuffle_owners(&wrong_coverage).is_err());
    assert!(shuffle_buckets(&wrong_coverage).is_err());

    let mut duplicate_owner = finalized_left.clone();
    let eligible_indices = duplicate_owner
        .ordered_records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| record.contributor_action.as_ref().map(|_| index))
        .take(2)
        .collect::<Vec<_>>();
    let first_owner = duplicate_owner.ordered_records[eligible_indices[0]]
        .contributor_action
        .as_ref()
        .unwrap()
        .owner;
    duplicate_owner.ordered_records[eligible_indices[1]]
        .contributor_action
        .as_mut()
        .unwrap()
        .owner = first_owner;
    assert!(shuffle_owners(&duplicate_owner).is_err());

    let mut wrong_fidelity_leaf = fidelity_left.observations;
    wrong_fidelity_leaf[0].tribute_id = tributes[256].tribute.tribute_id;
    assert!(amount_map(
        0,
        &tributes[..256],
        &wrong_fidelity_leaf,
        &fractions,
        entry_price,
    )
    .is_err());

    let mut wrong_prefix = left_prefix.clone();
    wrong_prefix.outgoing_remaining += U256::from(1);
    assert!(output_finalize(&amount_left, &wrong_prefix, logical_time).is_err());

    let mut wrong_amount_summary = amount_left;
    wrong_amount_summary.checked_segment_gratis_total += U256::from(1);
    assert!(output_finalize(&wrong_amount_summary, &left_prefix, logical_time).is_err());
}

#[test]
fn output_finalize_commits_all_excluded_nominal_once_per_shard_and_checks_overflow() {
    let day = WorldwideDay::new(20_260_724);
    let make_record = |seed: u8| {
        let owner = Address::repeat_byte(seed);
        AmountRecordV1 {
            raw_ordinal: 0,
            tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
            owner,
            worldwide_day: day,
            league_id: 7,
            nominal_amount_minor: U256::ZERO,
            gratis_fraction_fp: SIX_DECIMAL_SCALE,
            gratis_load_minor: U256::from(1),
            entry_price_minor: SIX_DECIMAL_SCALE,
            floor_price_minor: SIX_DECIMAL_SCALE,
            cost_amount_minor: U256::from(1),
            issuance_currency: 840,
            reference_currency: 978,
            exclude_from_intex_issuance: true,
        }
    };
    let run = |nominals: [U256; 2]| {
        let mut ordered_records = vec![make_record(1), make_record(2)];
        ordered_records.sort_by_key(|record| record.tribute_id);
        for (ordinal, record) in ordered_records.iter_mut().enumerate() {
            record.raw_ordinal = u32::try_from(ordinal).unwrap();
            record.nominal_amount_minor = nominals[ordinal];
        }
        AmountRunV1 {
            start_ordinal: 0,
            end_ordinal: 2,
            ordered_records,
            checked_segment_gratis_total: U256::from(2),
        }
    };
    let prefix = GratisLeafPrefixV1 {
        segment_ordinal: 0,
        incoming_remaining: U256::from(10),
        outgoing_remaining: U256::from(8),
        first_error_ordinal: None,
    };

    let finalized = output_finalize(
        &run([U256::from(7), U256::from(11)]),
        &prefix,
        1_784_765_900,
    )
    .unwrap();
    assert_eq!(finalized.checked_tribute_nominal_total, U256::from(18));
    assert!(finalized
        .ordered_records
        .iter()
        .all(|record| record.contributor_action.is_none()));
    let limits = poc_schema_limits();
    let encoded = encode_finalized_output_run(&finalized, &limits).unwrap();
    assert_eq!(
        decode_finalized_output_run(&encoded, &limits).unwrap(),
        finalized
    );

    assert!(matches!(
        output_finalize(&run([U256::MAX, U256::from(1)]), &prefix, 1_784_765_900,),
        Err(ProgramErrorV1::TotalNominalOverflow { ordinal: 1 })
    ));
}

#[test]
fn fidelity_reducer_handles_every_padded_empty_shape_for_one_to_eight_shards() {
    let day = WorldwideDay::new(20_260_724);
    for primary_count in 1..=8_u32 {
        let tree = PaddedBinaryTreeV1::for_primary_leaf_count(primary_count).unwrap();
        let leaves = (0..primary_count)
            .map(|ordinal| {
                let mut owner_bytes = [0_u8; 20];
                owner_bytes[16..].copy_from_slice(&(ordinal + 1).to_be_bytes());
                let owner = Address::from(owner_bytes);
                let observed = ObservedTributeV1 {
                    tribute: TributeInputV1 {
                        tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
                        owner,
                        worldwide_day: day,
                        issuance_currency: 978,
                        nominal_amount_minor: SIX_DECIMAL_SCALE,
                        reference_currency: 840,
                        tribute_price_minor: U256::ZERO,
                        exclude_from_intex_issuance: false,
                    },
                    first_league: ObservationValueV1::Value((ordinal % 3 + 1) as u16),
                    second_league: ObservationValueV1::Value((ordinal % 3 + 1) as u16),
                    conditional_entry_price_minor: ObservationValueV1::Unavailable,
                    nod_target_available: true,
                };
                fidelity_map(ordinal, &[observed]).unwrap().aggregate
            })
            .collect::<Vec<_>>();
        let mut nodes = BTreeMap::<(u16, u32), FidelityReduceValueV1>::new();

        for level in 1..=tree.height() {
            let width = tree.padded_leaf_count() >> level;
            for index in 0..width {
                let node = tree.reducer_node(level, index).unwrap();
                let resolve = |input| match input {
                    ReducerInputV1::Primary(ordinal) => {
                        FidelityReduceValueV1::Aggregate(leaves[ordinal as usize].clone())
                    }
                    ReducerInputV1::CanonicalEmpty { .. } => FidelityReduceValueV1::Empty,
                    ReducerInputV1::Reducer { level, index } => {
                        nodes.get(&(level, index)).unwrap().clone()
                    }
                };
                let output =
                    fidelity_reduce_pair(resolve(node.inputs[0]), resolve(node.inputs[1])).unwrap();
                nodes.insert((level, index), output);
            }
        }

        let FidelityReduceValueV1::Aggregate(root) = nodes.get(&(tree.height(), 0)).unwrap() else {
            panic!("a non-empty plan must have a non-empty Fidelity root");
        };
        assert_eq!(root.tribute_count, primary_count);
        assert_eq!(root.start_ordinal, 0);
        assert_eq!(root.end_ordinal, primary_count);
    }
}

#[test]
fn two_direction_gratis_prefix_preserves_exact_sequential_budget_semantics() {
    let first_loads = vec![U256::from(1_u8); 256];
    let second_loads = vec![U256::from(1_u8)];
    let first = gratis_summary(0, &first_loads).unwrap();
    let second = gratis_summary(256, &second_loads).unwrap();
    let root = gratis_summary_reduce_pair(
        GratisSummaryValueV1::Summary(first.clone()),
        GratisSummaryValueV1::Summary(second.clone()),
    )
    .unwrap();
    let GratisSummaryValueV1::Summary(root) = root else {
        panic!("non-empty Gratis tree has a summary");
    };
    assert_eq!(root.checked_segment_gratis_total, U256::from(257_u16));

    let exact = gratis_prefix_down(
        Some(U256::from(257_u16)),
        GratisSummaryValueV1::Summary(first.clone()),
        GratisSummaryValueV1::Summary(second.clone()),
    )
    .unwrap();
    assert_eq!(
        exact[0].as_ref().unwrap().incoming_remaining,
        Some(U256::from(257_u16))
    );
    assert_eq!(
        exact[1].as_ref().unwrap().incoming_remaining,
        Some(U256::from(1_u8))
    );
    let first_leaf = finalize_gratis_leaf(
        exact[0].as_ref().unwrap().incoming_remaining,
        0,
        &first_loads,
    )
    .unwrap();
    let second_leaf = finalize_gratis_leaf(
        exact[1].as_ref().unwrap().incoming_remaining,
        256,
        &second_loads,
    )
    .unwrap();
    assert_eq!(first_leaf.outgoing_remaining, U256::from(1_u8));
    assert_eq!(second_leaf.outgoing_remaining, U256::ZERO);
    assert_eq!(second_leaf.first_error_ordinal, None);

    let exhausted = gratis_prefix_down(
        Some(U256::from(256_u16)),
        GratisSummaryValueV1::Summary(first),
        GratisSummaryValueV1::Summary(second),
    )
    .unwrap();
    let error = finalize_gratis_leaf(
        exhausted[1].as_ref().unwrap().incoming_remaining,
        256,
        &second_loads,
    )
    .unwrap_err();
    assert_eq!(
        error,
        outbe_lysis::program_v1::ProgramErrorV1::GratisLoadExceedsRemaining { ordinal: 256 }
    );
}

#[test]
fn gratis_prefix_treats_padding_as_identity_not_as_work() {
    let summary = gratis_summary(0, &[U256::from(9_u8)]).unwrap();
    let reduced = gratis_summary_reduce_pair(
        GratisSummaryValueV1::Summary(summary.clone()),
        GratisSummaryValueV1::Empty,
    )
    .unwrap();
    assert_eq!(reduced, GratisSummaryValueV1::Summary(summary.clone()));

    let children = gratis_prefix_down(
        Some(U256::from(10_u8)),
        GratisSummaryValueV1::Summary(summary),
        GratisSummaryValueV1::Empty,
    )
    .unwrap();
    assert_eq!(children.len(), 2);
    assert!(children[0].is_some());
    assert!(children[1].is_none());
}

fn entity_id(ordinal: u32) -> B256 {
    let mut bytes = [0_u8; 32];
    bytes[28..].copy_from_slice(&ordinal.to_be_bytes());
    B256::from(bytes)
}
