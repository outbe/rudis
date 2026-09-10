use std::collections::BTreeMap;

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_ocomp_protocol::{
    codec::CodecLimits,
    control::CasObjectRefV1,
    registry::ObjectKind,
    result::ContributorActionV1,
    shuffle::{
        build_bucket_shuffle_run, build_owner_shuffle_run, merge_verified_shuffle_runs,
        verified_shuffle_run_page, verified_shuffle_run_records, ShuffleBucketRecordV1,
        ShufflePageSpanV1, ShuffleRunArtifactV1, ShuffleRunBuildContextV1, ShuffleRunChildV1,
        ShuffleRunKindV1, ShuffleRunPayloadV1, ShuffleSourceCoverageV1, VerifiedShuffleRecordV1,
        MAX_SHUFFLE_LEAF_RECORDS,
    },
    unit::CanonicalRunSpan,
    ProtocolError, SchemaLimits,
};

const LIMITS: SchemaLimits = SchemaLimits {
    codec: CodecLimits::new(1_048_576, 4_096, 2_097_152),
    max_bounded_bytes: 262_144,
    max_proof_bytes: 262_144,
    max_opening_bytes: 262_144,
    max_collection_items: 4_096,
    max_action_items: 4_096,
    max_chunk_items: 4_096,
    max_unit_inputs: 64,
    max_result_chunk_bytes: 524_288,
    max_control_body_bytes: 262_144,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn entity(index: u32) -> B256 {
    let mut bytes = [0_u8; 32];
    bytes[28..].copy_from_slice(&index.to_be_bytes());
    B256::from(bytes)
}

fn owner(index: u32) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[16..].copy_from_slice(&index.to_be_bytes());
    Address::from(bytes)
}

fn contributor(index: u32) -> ContributorActionV1 {
    ContributorActionV1 {
        owner: owner(index + 1),
        source_tribute_id: entity(index),
        nominal_amount_minor: U256::from(index + 1),
    }
}

fn owner_leaf(record_count: usize) -> ShuffleRunArtifactV1 {
    let artifact = ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        kind: ShuffleRunKindV1::Owner,
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: 1,
        },
        page_span: ShufflePageSpanV1 {
            start_page: 0,
            end_page: 1,
        },
        first_record_ordinal: 0,
        record_count: u32::try_from(record_count).unwrap(),
        source_coverage_root: hash(4),
        source_coverage_count: 300,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::OwnerLeaf(
            (0..u32::try_from(record_count).unwrap())
                .map(contributor)
                .collect(),
        ),
    };
    if record_count <= MAX_SHUFFLE_LEAF_RECORDS {
        artifact
            .with_recomputed_ordered_record_root(&LIMITS)
            .unwrap()
    } else {
        artifact
    }
}

#[test]
fn source_coverage_composes_exact_adjacent_raw_runs_without_padding_units() {
    let run_0 = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 0,
            end_run: 1,
        },
        hash(41),
        256,
        &LIMITS,
    )
    .unwrap();
    let run_1 = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 1,
            end_run: 2,
        },
        hash(42),
        256,
        &LIMITS,
    )
    .unwrap();
    let run_2 = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 2,
            end_run: 3,
        },
        hash(43),
        1,
        &LIMITS,
    )
    .unwrap();

    let first_pair = ShuffleSourceCoverageV1::merge(&run_0, &run_1, &LIMITS).unwrap();
    let complete = ShuffleSourceCoverageV1::merge(&first_pair, &run_2, &LIMITS).unwrap();
    assert_eq!(
        complete.run_span,
        CanonicalRunSpan {
            start_run: 0,
            end_run: 3
        }
    );
    assert_eq!(complete.count, 513);
    assert!(!complete.root.is_zero());

    let changed_last_raw_root = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 2,
            end_run: 3,
        },
        hash(44),
        1,
        &LIMITS,
    )
    .unwrap();
    assert_ne!(
        complete.root,
        ShuffleSourceCoverageV1::merge(&first_pair, &changed_last_raw_root, &LIMITS)
            .unwrap()
            .root
    );
}

#[test]
fn source_coverage_rejects_gap_overlap_and_reordered_producers() {
    let left = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 0,
            end_run: 1,
        },
        hash(41),
        256,
        &LIMITS,
    )
    .unwrap();
    let adjacent = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 1,
            end_run: 2,
        },
        hash(42),
        1,
        &LIMITS,
    )
    .unwrap();
    let gap = ShuffleSourceCoverageV1::leaf(
        CanonicalRunSpan {
            start_run: 2,
            end_run: 3,
        },
        hash(43),
        1,
        &LIMITS,
    )
    .unwrap();

    assert!(ShuffleSourceCoverageV1::merge(&left, &adjacent, &LIMITS).is_ok());
    assert!(ShuffleSourceCoverageV1::merge(&left, &gap, &LIMITS).is_err());
    assert!(ShuffleSourceCoverageV1::merge(&adjacent, &left, &LIMITS).is_err());
}

fn child(
    digest: u8,
    start_page: u32,
    end_page: u32,
    first_record_ordinal: u32,
    record_count: u32,
) -> ShuffleRunChildV1 {
    ShuffleRunChildV1 {
        artifact_ref: CasObjectRefV1 {
            transport_digest: hash(digest),
            encoded_bytes: 128,
            expected_ocb1_kind: Some(ObjectKind::ShuffleRunArtifactV1.tag()),
        },
        page_span: ShufflePageSpanV1 {
            start_page,
            end_page,
        },
        first_record_ordinal,
        record_count,
        ordered_record_root: hash(digest + 20),
    }
}

fn owner_page(
    page: u32,
    first_record_ordinal: u32,
    records: Vec<ContributorActionV1>,
) -> ShuffleRunArtifactV1 {
    ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        kind: ShuffleRunKindV1::Owner,
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: 2,
        },
        page_span: ShufflePageSpanV1 {
            start_page: page,
            end_page: page + 1,
        },
        first_record_ordinal,
        record_count: u32::try_from(records.len()).unwrap(),
        source_coverage_root: hash(4),
        source_coverage_count: 512,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::OwnerLeaf(records),
    }
    .with_recomputed_ordered_record_root(&LIMITS)
    .unwrap()
}

fn store_child(
    artifact: &ShuffleRunArtifactV1,
    objects: &mut BTreeMap<B256, Vec<u8>>,
) -> ShuffleRunChildV1 {
    let bytes = artifact.encode_canonical(&LIMITS).unwrap();
    let digest = keccak256(&bytes);
    let encoded_bytes = u64::try_from(bytes.len()).unwrap();
    objects.insert(digest, bytes);
    ShuffleRunChildV1 {
        artifact_ref: CasObjectRefV1 {
            transport_digest: digest,
            encoded_bytes,
            expected_ocb1_kind: Some(ObjectKind::ShuffleRunArtifactV1.tag()),
        },
        page_span: artifact.page_span.clone(),
        first_record_ordinal: artifact.first_record_ordinal,
        record_count: artifact.record_count,
        ordered_record_root: artifact.ordered_record_root,
    }
}

fn build_context(source_coverage_count: u32) -> ShuffleRunBuildContextV1 {
    ShuffleRunBuildContextV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: source_coverage_count.div_ceil(MAX_SHUFFLE_LEAF_RECORDS as u32),
        },
        source_coverage_root: hash(4),
        source_coverage_count,
    }
}

fn memory_stage(
    objects: &mut BTreeMap<B256, Vec<u8>>,
    bytes: &[u8],
) -> Result<CasObjectRefV1, ProtocolError> {
    let digest = keccak256(bytes);
    objects.insert(digest, bytes.to_vec());
    Ok(CasObjectRefV1 {
        transport_digest: digest,
        encoded_bytes: u64::try_from(bytes.len()).unwrap(),
        expected_ocb1_kind: Some(ObjectKind::ShuffleRunArtifactV1.tag()),
    })
}

fn owner_root(
    left: &ShuffleRunArtifactV1,
    right: &ShuffleRunArtifactV1,
    objects: &mut BTreeMap<B256, Vec<u8>>,
) -> ShuffleRunArtifactV1 {
    let left = store_child(left, objects);
    let right = store_child(right, objects);
    ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        kind: ShuffleRunKindV1::Owner,
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: 2,
        },
        page_span: ShufflePageSpanV1 {
            start_page: 0,
            end_page: 2,
        },
        first_record_ordinal: 0,
        record_count: left.record_count + right.record_count,
        source_coverage_root: hash(4),
        source_coverage_count: 512,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::Node { left, right },
    }
    .with_recomputed_ordered_record_root(&LIMITS)
    .unwrap()
}

#[test]
fn traversal_opens_typed_children_and_yields_one_globally_ordered_stream() {
    let left_records = (0..MAX_SHUFFLE_LEAF_RECORDS as u32)
        .map(contributor)
        .collect::<Vec<_>>();
    let right_records = vec![contributor(MAX_SHUFFLE_LEAF_RECORDS as u32)];
    let left = owner_page(0, 0, left_records);
    let right = owner_page(1, MAX_SHUFFLE_LEAF_RECORDS as u32, right_records);
    let mut objects = BTreeMap::new();
    let root = owner_root(&left, &right, &mut objects);

    let records = verified_shuffle_run_records(root, &LIMITS, |reference| {
        objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(records.len(), MAX_SHUFFLE_LEAF_RECORDS + 1);
    assert!(matches!(
        records.last(),
        Some(VerifiedShuffleRecordV1::Owner(record))
            if record.owner == owner(MAX_SHUFFLE_LEAF_RECORDS as u32 + 1)
    ));
}

#[test]
fn streaming_builder_materializes_three_canonical_pages_with_logarithmic_frontier() {
    let mut objects = BTreeMap::new();
    let root = build_owner_shuffle_run(
        build_context(513),
        (0..513_u32).map(|index| Ok(contributor(index))),
        &LIMITS,
        |bytes| memory_stage(&mut objects, bytes),
    )
    .unwrap();
    assert_eq!(root.page_span.end_page, 3);
    assert_eq!(root.record_count, 513);
    assert_eq!(objects.len(), 5);

    let records = verified_shuffle_run_records(root, &LIMITS, |reference| {
        objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(records.len(), 513);
}

#[test]
fn indexed_page_lookup_opens_only_the_authenticated_path_and_returns_exact_slices() {
    let mut objects = BTreeMap::new();
    let root = build_owner_shuffle_run(
        build_context(513),
        (0..513_u32).map(|index| Ok(contributor(index))),
        &LIMITS,
        |bytes| memory_stage(&mut objects, bytes),
    )
    .unwrap();

    let mut opened = 0_usize;
    let middle = verified_shuffle_run_page(root.clone(), 1, &LIMITS, |reference| {
        opened += 1;
        objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap();
    assert_eq!(middle.len(), MAX_SHUFFLE_LEAF_RECORDS);
    assert!(matches!(
        middle.first(),
        Some(VerifiedShuffleRecordV1::Owner(record))
            if record.owner == owner(MAX_SHUFFLE_LEAF_RECORDS as u32 + 1)
    ));
    assert_eq!(opened, 2);

    let tail = verified_shuffle_run_page(root.clone(), 2, &LIMITS, |reference| {
        objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap();
    assert_eq!(tail.len(), 1);

    assert!(verified_shuffle_run_page(root.clone(), 1, &LIMITS, |_| Err(
        ProtocolError::InvalidInvariant("selected descendant missing")
    ))
    .is_err());
    assert!(
        verified_shuffle_run_page(root.clone(), 1, &LIMITS, |reference| {
            let mut bytes = objects
                .get(&reference.transport_digest)
                .cloned()
                .ok_or(ProtocolError::InvalidInvariant("test object missing"))?;
            let last = bytes
                .last_mut()
                .ok_or(ProtocolError::InvalidInvariant("empty test object"))?;
            *last ^= 0x01;
            Ok(bytes)
        })
        .is_err()
    );

    let mut opened_beyond_end = 0_usize;
    let empty = verified_shuffle_run_page(root, 3, &LIMITS, |_| {
        opened_beyond_end += 1;
        Err(ProtocolError::InvalidInvariant("unexpected lookup"))
    })
    .unwrap();
    assert!(empty.is_empty());
    assert_eq!(opened_beyond_end, 0);
}

#[test]
fn streaming_builder_uses_the_unique_canonical_split_for_every_page_count() {
    for page_count in [1_u32, 2, 3, 5, 6, 7, 8, 9, 13, 17] {
        let record_count = page_count * MAX_SHUFFLE_LEAF_RECORDS as u32;
        let mut objects = BTreeMap::new();
        let root = build_owner_shuffle_run(
            build_context(record_count),
            (0..record_count).map(|index| Ok(contributor(index))),
            &LIMITS,
            |bytes| memory_stage(&mut objects, bytes),
        )
        .unwrap();
        assert_eq!(root.page_span.end_page, page_count);
        assert_eq!(root.record_count, record_count);
        assert_eq!(objects.len(), (page_count * 2 - 1) as usize);

        let traversed = verified_shuffle_run_records(root, &LIMITS, |reference| {
            objects
                .get(&reference.transport_digest)
                .cloned()
                .ok_or(ProtocolError::InvalidInvariant("test object missing"))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        assert_eq!(traversed.len(), record_count as usize);
    }
}

#[test]
fn streaming_merge_interleaves_two_verified_runs_and_rejects_duplicate_keys() {
    let left = [0_u32, 2].map(|index| Ok(VerifiedShuffleRecordV1::Owner(contributor(index))));
    let right = [1_u32, 3].map(|index| Ok(VerifiedShuffleRecordV1::Owner(contributor(index))));
    let merged = merge_verified_shuffle_runs(ShuffleRunKindV1::Owner, left, right)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let owners = merged
        .into_iter()
        .map(|record| match record {
            VerifiedShuffleRecordV1::Owner(record) => record.owner,
            VerifiedShuffleRecordV1::Bucket(_) => unreachable!(),
        })
        .collect::<Vec<_>>();
    assert_eq!(owners, (1..=4).map(owner).collect::<Vec<_>>());

    let mut second_tribute_same_owner = contributor(1);
    second_tribute_same_owner.owner = owner(1);
    let duplicate = merge_verified_shuffle_runs(
        ShuffleRunKindV1::Owner,
        [Ok(VerifiedShuffleRecordV1::Owner(contributor(0)))],
        [Ok(VerifiedShuffleRecordV1::Owner(
            second_tribute_same_owner,
        ))],
    )
    .collect::<Result<Vec<_>, _>>();
    assert_eq!(
        duplicate,
        Err(ProtocolError::InvalidInvariant(
            "strict merged shuffle order"
        ))
    );

    let mut second_tribute_same_owner = contributor(1);
    second_tribute_same_owner.owner = owner(1);
    let mut objects = BTreeMap::new();
    assert_eq!(
        build_owner_shuffle_run(
            build_context(2),
            [Ok(contributor(0)), Ok(second_tribute_same_owner),],
            &LIMITS,
            |bytes| memory_stage(&mut objects, bytes),
        ),
        Err(ProtocolError::InvalidInvariant(
            "global owner shuffle order"
        ))
    );
    assert!(objects.is_empty());
}

#[test]
fn builder_emits_one_empty_owner_leaf_but_rejects_an_empty_bucket_stream() {
    let mut owner_objects = BTreeMap::new();
    let owner_root =
        build_owner_shuffle_run(build_context(1), std::iter::empty(), &LIMITS, |bytes| {
            memory_stage(&mut owner_objects, bytes)
        })
        .unwrap();
    assert!(matches!(
        owner_root.payload,
        ShuffleRunPayloadV1::OwnerLeaf(ref records) if records.is_empty()
    ));
    assert_eq!(owner_objects.len(), 1);

    let mut bucket_objects = BTreeMap::new();
    assert_eq!(
        build_bucket_shuffle_run(build_context(1), std::iter::empty(), &LIMITS, |bytes| {
            memory_stage(&mut bucket_objects, bytes)
        },),
        Err(ProtocolError::InvalidInvariant(
            "non-empty bucket shuffle run"
        ))
    );
    assert!(bucket_objects.is_empty());
}

#[test]
fn builder_rejects_a_sink_that_lies_about_the_staged_content_descriptor() {
    let result =
        build_owner_shuffle_run(build_context(1), [Ok(contributor(0))], &LIMITS, |bytes| {
            Ok(CasObjectRefV1 {
                transport_digest: hash(99),
                encoded_bytes: u64::try_from(bytes.len()).unwrap(),
                expected_ocb1_kind: Some(ObjectKind::ShuffleRunArtifactV1.tag()),
            })
        });
    assert_eq!(
        result,
        Err(ProtocolError::InvalidInvariant(
            "staged shuffle object descriptor"
        ))
    );
}

#[test]
fn traversal_rejects_underfilled_non_final_pages_and_cross_page_reordering() {
    let mut underfilled_objects = BTreeMap::new();
    let underfilled = owner_root(
        &owner_page(0, 0, vec![contributor(0)]),
        &owner_page(1, 1, vec![contributor(1)]),
        &mut underfilled_objects,
    );
    let underfilled_result = verified_shuffle_run_records(underfilled, &LIMITS, |reference| {
        underfilled_objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>();
    assert_eq!(
        underfilled_result,
        Err(ProtocolError::InvalidInvariant(
            "full non-final shuffle leaf"
        ))
    );

    let left_records = (0..MAX_SHUFFLE_LEAF_RECORDS as u32)
        .map(|index| contributor(index + 1))
        .collect::<Vec<_>>();
    let mut reordered_objects = BTreeMap::new();
    let reordered = owner_root(
        &owner_page(0, 0, left_records),
        &owner_page(1, MAX_SHUFFLE_LEAF_RECORDS as u32, vec![contributor(0)]),
        &mut reordered_objects,
    );
    let reordered_result = verified_shuffle_run_records(reordered, &LIMITS, |reference| {
        reordered_objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>();
    assert_eq!(
        reordered_result,
        Err(ProtocolError::InvalidInvariant(
            "global owner shuffle order"
        ))
    );
}

#[test]
fn traversal_rejects_a_digest_valid_descendant_from_another_unit() {
    let left_records = (0..MAX_SHUFFLE_LEAF_RECORDS as u32)
        .map(contributor)
        .collect::<Vec<_>>();
    let mut wrong_unit = owner_page(0, 0, left_records);
    wrong_unit.unit_id = hash(9);
    let right = owner_page(
        1,
        MAX_SHUFFLE_LEAF_RECORDS as u32,
        vec![contributor(MAX_SHUFFLE_LEAF_RECORDS as u32)],
    );
    let mut objects = BTreeMap::new();
    let root = owner_root(&wrong_unit, &right, &mut objects);
    let result = verified_shuffle_run_records(root, &LIMITS, |reference| {
        objects
            .get(&reference.transport_digest)
            .cloned()
            .ok_or(ProtocolError::InvalidInvariant("test object missing"))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>();
    assert_eq!(
        result,
        Err(ProtocolError::InvalidInvariant(
            "shuffle descendant context"
        ))
    );
}

#[test]
fn owner_leaf_round_trips_at_the_exact_256_record_boundary() {
    let artifact = owner_leaf(MAX_SHUFFLE_LEAF_RECORDS);
    let encoded = artifact.encode_canonical(&LIMITS).unwrap();
    assert_eq!(
        ShuffleRunArtifactV1::decode_canonical(&encoded, &LIMITS).unwrap(),
        artifact
    );
}

#[test]
fn a_257th_record_requires_another_leaf_instead_of_growing_one_object() {
    let artifact = owner_leaf(MAX_SHUFFLE_LEAF_RECORDS + 1);
    assert_eq!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("shuffle leaf record cap"))
    );
}

#[test]
fn leaf_kind_order_and_count_are_validated_from_values() {
    let mut artifact = owner_leaf(2);
    artifact.kind = ShuffleRunKindV1::Bucket;
    assert!(matches!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "shuffle payload kind binding"
        ))
    ));

    let mut artifact = owner_leaf(2);
    if let ShuffleRunPayloadV1::OwnerLeaf(records) = &mut artifact.payload {
        records.swap(0, 1);
    }
    assert!(matches!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "owner shuffle records strictly ordered"
        ))
    ));

    let mut artifact = owner_leaf(2);
    artifact.record_count = 1;
    assert!(matches!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("shuffle leaf record count"))
    ));
}

#[test]
fn bucket_leaf_rejects_duplicate_or_reordered_raw_records() {
    let mut artifact = owner_leaf(0);
    artifact.kind = ShuffleRunKindV1::Bucket;
    artifact.record_count = 2;
    artifact.payload = ShuffleRunPayloadV1::BucketLeaf(vec![
        ShuffleBucketRecordV1 {
            bucket_key: hash(9),
            raw_ordinal: 2,
            tribute_id: entity(2),
            nod_id: entity(102),
        },
        ShuffleBucketRecordV1 {
            bucket_key: hash(9),
            raw_ordinal: 1,
            tribute_id: entity(1),
            nod_id: entity(101),
        },
    ]);
    assert!(matches!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "bucket shuffle records strictly ordered"
        ))
    ));
}

#[test]
fn node_requires_the_canonical_adjacent_page_and_record_split() {
    let valid = ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        kind: ShuffleRunKindV1::Owner,
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: 4,
        },
        page_span: ShufflePageSpanV1 {
            start_page: 0,
            end_page: 3,
        },
        first_record_ordinal: 0,
        record_count: 600,
        source_coverage_root: hash(4),
        source_coverage_count: 1_024,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::Node {
            left: child(10, 0, 2, 0, 512),
            right: child(11, 2, 3, 512, 88),
        },
    }
    .with_recomputed_ordered_record_root(&LIMITS)
    .unwrap();
    let encoded = valid.encode_canonical(&LIMITS).unwrap();
    assert_eq!(
        ShuffleRunArtifactV1::decode_canonical(&encoded, &LIMITS).unwrap(),
        valid
    );

    let mut wrong_split = valid.clone();
    if let ShuffleRunPayloadV1::Node { left, right } = &mut wrong_split.payload {
        left.page_span.end_page = 1;
        right.page_span.start_page = 1;
    }
    assert!(matches!(
        wrong_split.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "shuffle node canonical page split"
        ))
    ));

    let mut gap = valid;
    if let ShuffleRunPayloadV1::Node { right, .. } = &mut gap.payload {
        right.first_record_ordinal += 1;
    }
    assert!(matches!(
        gap.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "shuffle node record adjacency"
        ))
    ));
}

#[test]
fn node_references_must_be_distinct_typed_nonempty_cas_objects() {
    let mut artifact = owner_leaf(0);
    artifact.page_span.end_page = 2;
    artifact.record_count = 2;
    artifact.payload = ShuffleRunPayloadV1::Node {
        left: child(10, 0, 1, 0, 1),
        right: child(10, 1, 2, 1, 1),
    };
    assert!(matches!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "shuffle node distinct child objects"
        ))
    ));
}

#[test]
fn empty_owner_stream_is_one_leaf_and_never_an_empty_node_tree() {
    let artifact = ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        kind: ShuffleRunKindV1::Owner,
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: 2,
        },
        page_span: ShufflePageSpanV1 {
            start_page: 0,
            end_page: 2,
        },
        first_record_ordinal: 0,
        record_count: 0,
        source_coverage_root: hash(4),
        source_coverage_count: 512,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::Node {
            left: child(10, 0, 1, 0, 0),
            right: child(11, 1, 2, 0, 0),
        },
    }
    .with_recomputed_ordered_record_root(&LIMITS)
    .unwrap();
    assert_eq!(
        artifact.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant("non-empty shuffle node"))
    );

    let empty = owner_leaf(0);
    let records = verified_shuffle_run_records(empty, &LIMITS, |_| {
        Err(ProtocolError::InvalidInvariant(
            "empty leaf has no descendants",
        ))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert!(records.is_empty());
}

#[test]
fn ordered_record_root_is_computed_from_leaf_records_and_child_summaries() {
    let mut leaf = owner_leaf(2);
    leaf.ordered_record_root = hash(99);
    assert_eq!(
        leaf.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "shuffle ordered record root"
        ))
    );

    let mut node = ShuffleRunArtifactV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 1,
        unit_id: hash(3),
        kind: ShuffleRunKindV1::Owner,
        run_span: CanonicalRunSpan {
            start_run: 0,
            end_run: 2,
        },
        page_span: ShufflePageSpanV1 {
            start_page: 0,
            end_page: 2,
        },
        first_record_ordinal: 0,
        record_count: 2,
        source_coverage_root: hash(4),
        source_coverage_count: 512,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::Node {
            left: child(10, 0, 1, 0, 1),
            right: child(11, 1, 2, 1, 1),
        },
    }
    .with_recomputed_ordered_record_root(&LIMITS)
    .unwrap();
    if let ShuffleRunPayloadV1::Node { right, .. } = &mut node.payload {
        right.ordered_record_root = hash(98);
    }
    assert_eq!(
        node.encode_canonical(&LIMITS),
        Err(ProtocolError::InvalidInvariant(
            "shuffle ordered record root"
        ))
    );
}

#[test]
fn decoder_rejects_trailing_bytes_instead_of_accepting_an_ambiguous_artifact() {
    let mut encoded = owner_leaf(1).encode_canonical(&LIMITS).unwrap();
    encoded.push(0);
    assert!(matches!(
        ShuffleRunArtifactV1::decode_canonical(&encoded, &LIMITS),
        Err(ProtocolError::BodyLengthMismatch { .. })
            | Err(ProtocolError::TrailingBytes { .. })
            | Err(ProtocolError::NonCanonicalEncoding)
    ));
}
