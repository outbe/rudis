use alloy_primitives::Address;
use outbe_compressed_entities::{
    derive_poseidon_entity_id, tribute_partition_root_from_leaves, BoundedTributePartitionVerifier,
    Commitment, TributePartitionExpectationV1, TributePartitionReconstructionError,
    TributePartitionWorkConfig,
};
use outbe_primitives::time::WorldwideDay;
use std::cell::Cell;
use std::io::Write;

fn commitment(value: u64) -> Commitment {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Commitment::try_from(bytes).unwrap()
}

fn leaves(
    day: WorldwideDay,
    count: u64,
) -> Vec<(outbe_compressed_entities::WwdEntityId, Commitment)> {
    (1..=count)
        .map(|value| {
            let mut owner = [0_u8; 20];
            owner[12..].copy_from_slice(&value.to_be_bytes());
            let owner = Address::from(owner);
            (
                derive_poseidon_entity_id(owner, day).unwrap(),
                commitment(value + 100),
            )
        })
        .collect()
}

fn expected_root(
    day: WorldwideDay,
    leaves: &[(outbe_compressed_entities::WwdEntityId, Commitment)],
) -> alloy_primitives::B256 {
    tribute_partition_root_from_leaves(day, leaves.iter().copied()).unwrap()
}

fn verifier(
    scratch: &std::path::Path,
    day: WorldwideDay,
    leaves: &[(outbe_compressed_entities::WwdEntityId, Commitment)],
    records_per_run: usize,
    merge_fan_in: usize,
) -> BoundedTributePartitionVerifier {
    BoundedTributePartitionVerifier::create(
        scratch,
        TributePartitionExpectationV1 {
            day,
            exact_leaf_count: u32::try_from(leaves.len()).unwrap(),
            expected_collection_root: expected_root(day, leaves),
            commitment_scheme: outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME,
        },
        TributePartitionWorkConfig {
            records_per_run,
            merge_fan_in,
        },
    )
    .unwrap()
}

#[test]
fn tiny_runs_and_fan_in_reconstruct_the_existing_root_in_any_input_order() {
    let day = WorldwideDay::new(20_260_901);
    let leaves = leaves(day, 17);
    let expected_root = expected_root(day, &leaves);

    for (case, input) in [
        ("forward", leaves.clone()),
        ("reverse", leaves.iter().copied().rev().collect()),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = BoundedTributePartitionVerifier::create(
            directory.path().join(case),
            TributePartitionExpectationV1 {
                day,
                exact_leaf_count: 17,
                expected_collection_root: expected_root,
                commitment_scheme: outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME,
            },
            TributePartitionWorkConfig {
                records_per_run: 2,
                merge_fan_in: 2,
            },
        )
        .unwrap();
        for (entity_id, commitment) in input {
            verifier.push(entity_id, commitment).unwrap();
        }
        let verified = verifier.finish().unwrap();
        assert_eq!(verified.collection_root, expected_root);
        assert_eq!(verified.exact_leaf_count, 17);
    }
}

#[test]
fn multipass_reconstruction_reports_progress_without_changing_its_result() {
    let day = WorldwideDay::new(20_260_901);
    let leaves = leaves(day, 17);
    let directory = tempfile::tempdir().unwrap();
    let mut verifier = verifier(&directory.path().join("observed"), day, &leaves, 2, 2);
    for (entity_id, commitment) in &leaves {
        verifier.push(*entity_id, *commitment).unwrap();
    }
    let progress = Cell::new(0_u64);

    let verified = verifier
        .finish_observing(|| progress.set(progress.get() + 1))
        .unwrap();

    assert_eq!(verified.collection_root, expected_root(day, &leaves));
    assert!(progress.get() > u64::try_from(leaves.len()).unwrap());
}

#[test]
fn boundary_populations_match_the_existing_eager_reconstruction() {
    let day = WorldwideDay::new(20_260_901);
    for count in [0_u64, 1, 15, 16, 17, 255, 256, 257, 4_097] {
        let leaves = leaves(day, count);
        let mut shuffled = leaves.clone();
        let len = shuffled.len();
        if len > 1 {
            for index in 0..len {
                let target = (index.wrapping_mul(2_654_435_761).wrapping_add(17)) % len;
                shuffled.swap(index, target);
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let mut verifier = verifier(
            &directory.path().join(format!("count-{count}")),
            day,
            &leaves,
            31,
            3,
        );
        for (entity_id, commitment) in shuffled {
            verifier.push(entity_id, commitment).unwrap();
        }
        assert_eq!(
            verifier.finish().unwrap().collection_root,
            expected_root(day, &leaves),
            "count={count}"
        );
    }
}

#[test]
fn duplicate_across_runs_and_invalid_expectations_fail_closed() {
    let day = WorldwideDay::new(20_260_901);
    let leaves = leaves(day, 2);
    let directory = tempfile::tempdir().unwrap();
    let mut duplicate = verifier(&directory.path().join("duplicate"), day, &leaves, 1, 2);
    duplicate.push(leaves[0].0, leaves[0].1).unwrap();
    duplicate.push(leaves[0].0, leaves[0].1).unwrap();
    assert!(matches!(
        duplicate.finish(),
        Err(TributePartitionReconstructionError::Collection(_))
    ));

    assert!(matches!(
        BoundedTributePartitionVerifier::create(
            directory.path().join("work"),
            TributePartitionExpectationV1 {
                day,
                exact_leaf_count: 0,
                expected_collection_root: expected_root(day, &[]),
                commitment_scheme: outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME,
            },
            TributePartitionWorkConfig {
                records_per_run: 0,
                merge_fan_in: 1,
            },
        ),
        Err(TributePartitionReconstructionError::InvalidWorkConfig)
    ));
    assert!(matches!(
        BoundedTributePartitionVerifier::create(
            directory.path().join("scheme"),
            TributePartitionExpectationV1 {
                day,
                exact_leaf_count: 0,
                expected_collection_root: expected_root(day, &[]),
                commitment_scheme: 99,
            },
            TributePartitionWorkConfig::default(),
        ),
        Err(TributePartitionReconstructionError::UnsupportedCommitmentScheme(99))
    ));
}

#[test]
fn count_root_day_and_scratch_corruption_fail_closed() {
    let day = WorldwideDay::new(20_260_901);
    let leaves = leaves(day, 2);
    let directory = tempfile::tempdir().unwrap();

    let mut short = verifier(&directory.path().join("short"), day, &leaves, 2, 2);
    short.push(leaves[0].0, leaves[0].1).unwrap();
    assert!(matches!(
        short.finish(),
        Err(TributePartitionReconstructionError::CountMismatch {
            expected: 2,
            actual: 1
        })
    ));

    let mut long = BoundedTributePartitionVerifier::create(
        directory.path().join("long"),
        TributePartitionExpectationV1 {
            day,
            exact_leaf_count: 1,
            expected_collection_root: expected_root(day, &leaves[..1]),
            commitment_scheme: outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME,
        },
        TributePartitionWorkConfig::default(),
    )
    .unwrap();
    long.push(leaves[0].0, leaves[0].1).unwrap();
    assert!(matches!(
        long.push(leaves[1].0, leaves[1].1),
        Err(TributePartitionReconstructionError::CountMismatch {
            expected: 1,
            actual: 2
        })
    ));

    let wrong_day = WorldwideDay::new(day.value() + 1);
    let mut day_bound = verifier(&directory.path().join("day"), day, &leaves, 2, 2);
    assert!(matches!(
        day_bound.push(
            derive_poseidon_entity_id(Address::repeat_byte(9), wrong_day).unwrap(),
            commitment(9)
        ),
        Err(TributePartitionReconstructionError::Collection(_))
    ));

    let mut wrong_root = BoundedTributePartitionVerifier::create(
        directory.path().join("root"),
        TributePartitionExpectationV1 {
            day,
            exact_leaf_count: 1,
            expected_collection_root: alloy_primitives::B256::repeat_byte(0x55),
            commitment_scheme: outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME,
        },
        TributePartitionWorkConfig::default(),
    )
    .unwrap();
    wrong_root.push(leaves[0].0, leaves[0].1).unwrap();
    assert!(matches!(
        wrong_root.finish(),
        Err(TributePartitionReconstructionError::RootMismatch { .. })
    ));

    let corrupt_root = directory.path().join("corrupt");
    let mut corrupt = verifier(&corrupt_root, day, &leaves[..1], 1, 2);
    corrupt.push(leaves[0].0, leaves[0].1).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(corrupt_root.join("run-0000000000-00000000000000000000.bin"))
        .unwrap()
        .write_all(&[0])
        .unwrap();
    assert!(matches!(
        corrupt.finish(),
        Err(TributePartitionReconstructionError::CorruptRun(_))
    ));
}
