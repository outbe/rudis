use std::fs;
use std::os::unix::fs::symlink;
use std::sync::{Arc, Barrier};
use std::thread;

use alloy_primitives::B256;
use outbe_ocomp::control::poc_schema_limits;
use outbe_ocomp::inbox::{WorkerInbox, WorkerInboxError, WorkerInboxLimits};
use outbe_ocomp_protocol::{
    result::ResultChunkV1,
    shuffle::{ShufflePageSpanV1, ShuffleRunArtifactV1, ShuffleRunKindV1, ShuffleRunPayloadV1},
    unit::CanonicalRunSpan,
    ObjectKind,
};
use tempfile::tempdir;

fn shuffle_leaf_bytes() -> Vec<u8> {
    ShuffleRunArtifactV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        unit_id: B256::repeat_byte(3),
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
        record_count: 0,
        source_coverage_root: B256::repeat_byte(4),
        source_coverage_count: 256,
        ordered_record_root: B256::ZERO,
        payload: ShuffleRunPayloadV1::OwnerLeaf(Vec::new()),
    }
    .with_recomputed_ordered_record_root(&poc_schema_limits())
    .expect("bind shuffle leaf root")
    .encode_canonical(&poc_schema_limits())
    .expect("canonical shuffle leaf")
}

fn result_chunk_bytes() -> Vec<u8> {
    ResultChunkV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        chunk_ordinal: 0,
        first_nod_ordinal: 0,
        ordered_nod_actions: Vec::new(),
        ordered_eligible_contributors: Vec::new(),
    }
    .encode_canonical(&poc_schema_limits())
    .expect("canonical result chunk")
}

#[test]
fn worker_inbox_derives_one_atomic_artifact_path_from_unit_id() {
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: 64,
            max_total_bytes: 128,
        },
    )
    .expect("open worker inbox");
    let unit_id = B256::repeat_byte(0x41);

    let staged = inbox
        .stage(unit_id, b"canonical result chunk")
        .expect("stage worker artifact");

    assert_eq!(staged.unit_id(), unit_id);
    assert_eq!(
        inbox
            .read_verified(&staged)
            .expect("verify staged artifact")
            .bytes(),
        b"canonical result chunk"
    );
    assert_eq!(inbox.artifact_count().expect("artifact count"), 1);
    assert_eq!(inbox.staging_count().expect("staging count"), 0);
}

#[test]
fn worker_inbox_rejects_cap_plus_one_without_partial_artifact() {
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: 4,
            max_total_bytes: 6,
        },
    )
    .expect("open worker inbox");

    assert!(matches!(
        inbox
            .stage(B256::repeat_byte(0x42), b"12345")
            .expect_err("cap plus one must reject"),
        WorkerInboxError::ArtifactLimitExceeded {
            limit: 4,
            actual: 5
        }
    ));
    assert_eq!(inbox.artifact_count().expect("artifact count"), 0);
    assert_eq!(inbox.staging_count().expect("staging count"), 0);

    inbox
        .stage(B256::repeat_byte(0x45), b"abc")
        .expect("first bounded artifact");
    assert!(matches!(
        inbox
            .stage(B256::repeat_byte(0x46), b"defg")
            .expect_err("total cap must reject"),
        WorkerInboxError::TotalLimitExceeded {
            limit: 6,
            attempted: 7
        }
    ));
    assert_eq!(inbox.artifact_count().expect("artifact count"), 1);
    assert_eq!(inbox.staging_count().expect("staging count"), 0);
}

#[test]
fn worker_inbox_never_overwrites_existing_or_symlinked_unit_artifact() {
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: 64,
            max_total_bytes: 128,
        },
    )
    .expect("open worker inbox");
    let unit_id = B256::repeat_byte(0x43);
    let first = inbox.stage(unit_id, b"first").expect("first artifact");

    assert!(matches!(
        inbox
            .stage(unit_id, b"second")
            .expect_err("same UnitId cannot be overwritten"),
        WorkerInboxError::AlreadyStaged { .. }
    ));
    assert_eq!(
        inbox
            .read_verified(&first)
            .expect("original remains")
            .bytes(),
        b"first"
    );

    let other_unit = B256::repeat_byte(0x44);
    let target = directory.path().join("attacker-controlled");
    fs::write(&target, b"hostile").expect("symlink target");
    let artifact_path = directory
        .path()
        .join("artifacts")
        .join(format!("{}.ocb1", hex::encode(other_unit.as_slice())));
    symlink(&target, &artifact_path).expect("simulate symlink substitution");
    assert!(matches!(
        inbox
            .stage(other_unit, b"legitimate")
            .expect_err("symlink must not be replaced"),
        WorkerInboxError::UnsafeArtifact { .. } | WorkerInboxError::AlreadyStaged { .. }
    ));
    assert_eq!(
        fs::read(&target).expect("attacker target remains"),
        b"hostile"
    );
}

#[test]
fn supervisor_adoption_accepts_exact_reexecution_and_rejects_conflicting_artifact() {
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: 64,
            max_total_bytes: 128,
        },
    )
    .expect("open worker inbox");
    let unit_id = B256::repeat_byte(0x47);

    let first = inbox
        .adopt(unit_id, b"canonical artifact")
        .expect("first execution");
    let replay = inbox
        .adopt(unit_id, b"canonical artifact")
        .expect("byte-identical retry is a cache hit");
    assert_eq!(first, replay);
    assert_eq!(inbox.artifact_count().expect("artifact count"), 1);

    assert!(matches!(
        inbox
            .adopt(unit_id, b"different valid-looking artifact")
            .expect_err("same UnitId with different bytes must conflict"),
        WorkerInboxError::ArtifactConflict {
            unit_id: conflicting
        } if conflicting == unit_id
    ));
    assert_eq!(
        inbox
            .read_verified(&first)
            .expect("original remains")
            .bytes(),
        b"canonical artifact"
    );
}

#[test]
fn concurrent_identical_reexecutions_adopt_one_immutable_artifact() {
    let directory = tempdir().expect("worker inbox directory");
    let inbox = Arc::new(
        WorkerInbox::open(
            directory.path(),
            WorkerInboxLimits {
                max_artifact_bytes: 64,
                max_total_bytes: 64,
            },
        )
        .expect("open worker inbox"),
    );
    let barrier = Arc::new(Barrier::new(4));
    let unit_id = B256::repeat_byte(0x48);
    let handles = (0..4)
        .map(|_| {
            let inbox = Arc::clone(&inbox);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                inbox.adopt(unit_id, b"same deterministic bytes")
            })
        })
        .collect::<Vec<_>>();
    let adopted = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker thread").expect("adopt"))
        .collect::<Vec<_>>();

    assert!(adopted.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(inbox.artifact_count().expect("artifact count"), 1);
}

#[test]
fn concurrent_workers_cannot_race_past_the_total_inbox_quota() {
    let directory = tempdir().expect("worker inbox directory");
    let inbox = Arc::new(
        WorkerInbox::open(
            directory.path(),
            WorkerInboxLimits {
                max_artifact_bytes: 4,
                max_total_bytes: 8,
            },
        )
        .expect("open worker inbox"),
    );
    let barrier = Arc::new(Barrier::new(4));
    let handles = (1_u8..=4)
        .map(|byte| {
            let inbox = Arc::clone(&inbox);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                inbox.stage(B256::repeat_byte(byte), &[byte; 4])
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("worker thread"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 2);
    assert!(results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .all(|error| matches!(
            error,
            WorkerInboxError::TotalLimitExceeded {
                limit: 8,
                attempted: 12
            }
        )));
    assert_eq!(inbox.artifact_count().expect("artifact count"), 2);
    assert_eq!(inbox.staging_count().expect("staging count"), 0);
}

#[test]
fn shuffle_descendants_are_typed_content_addressed_and_idempotent() {
    let bytes = shuffle_leaf_bytes();
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: 1_024,
            max_total_bytes: 2_048,
        },
    )
    .expect("open worker inbox");
    let limits = poc_schema_limits();

    let first = inbox
        .stage_shuffle_object(&bytes, &limits)
        .expect("stage shuffle child");
    let replay = inbox
        .stage_shuffle_object(&bytes, &limits)
        .expect("same content is an idempotent cache hit");
    assert_eq!(first, replay);
    assert_eq!(
        first.expected_ocb1_kind,
        Some(ObjectKind::ShuffleRunArtifactV1.tag())
    );
    assert_eq!(
        inbox
            .read_shuffle_object(&first, &limits)
            .expect("verify shuffle child")
            .bytes(),
        bytes
    );
    assert_eq!(inbox.object_count().expect("object count"), 1);
    assert_eq!(inbox.artifact_count().expect("artifact count"), 0);

    assert!(matches!(
        inbox
            .stage_shuffle_object(b"not an OCB1 object", &limits)
            .expect_err("untyped bytes must never enter shuffle object storage"),
        WorkerInboxError::InvalidShuffleObject(_)
    ));
    assert_eq!(inbox.object_count().expect("object count"), 1);
}

#[test]
fn result_chunks_are_typed_content_addressed_and_idempotent() {
    let bytes = result_chunk_bytes();
    let exact_bytes = u64::try_from(bytes.len()).expect("fixture length");
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: exact_bytes,
            max_total_bytes: exact_bytes,
        },
    )
    .expect("open worker inbox");
    let limits = poc_schema_limits();

    let first = inbox
        .stage_result_chunk(&bytes, &limits)
        .expect("stage result chunk");
    let replay = inbox
        .stage_result_chunk(&bytes, &limits)
        .expect("same result chunk is an idempotent cache hit");
    assert_eq!(first, replay);
    assert_eq!(
        first.expected_ocb1_kind,
        Some(ObjectKind::ResultChunkV1.tag())
    );
    assert_eq!(
        inbox
            .read_result_chunk(&first, &limits)
            .expect("verify result chunk")
            .bytes(),
        bytes
    );
    assert_eq!(inbox.object_count().expect("object count"), 1);

    assert!(matches!(
        inbox
            .stage_result_chunk(&shuffle_leaf_bytes(), &limits)
            .expect_err("a different OCB1 kind must not enter result-chunk storage"),
        WorkerInboxError::InvalidResultChunk(_)
    ));
    assert_eq!(inbox.object_count().expect("object count"), 1);
}

#[test]
fn unit_artifacts_and_shuffle_objects_share_one_total_quota() {
    let bytes = shuffle_leaf_bytes();
    let exact_bytes = u64::try_from(bytes.len()).expect("fixture length");
    let directory = tempdir().expect("worker inbox directory");
    let inbox = WorkerInbox::open(
        directory.path(),
        WorkerInboxLimits {
            max_artifact_bytes: exact_bytes,
            max_total_bytes: exact_bytes,
        },
    )
    .expect("open worker inbox");
    inbox
        .stage_shuffle_object(&bytes, &poc_schema_limits())
        .expect("bounded shuffle object");

    assert!(matches!(
        inbox
            .stage(B256::repeat_byte(0x55), b"x")
            .expect_err("unit artifact cannot race past shared quota"),
        WorkerInboxError::TotalLimitExceeded {
            limit,
            attempted
        } if limit == exact_bytes && attempted == exact_bytes + 1
    ));
    assert_eq!(inbox.object_count().expect("object count"), 1);
    assert_eq!(inbox.artifact_count().expect("artifact count"), 0);
    assert_eq!(inbox.staging_count().expect("staging count"), 0);
}
