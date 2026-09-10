use std::fs;
use std::os::unix::fs::PermissionsExt;

use alloy_primitives::{B256, U256};
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    export_receipt::{
        list_prepared_export_jobs, ExportReceiptCandidate, ExportReceiptError,
        ExportReceiptPreparation, ExportReceiptReader, ExportReceiptRecordOutcome,
        ExportReceiptStore,
    },
};
use outbe_ocomp_protocol::{
    input::{CheckpointIdentityV1, Compression, InputManifestV1},
    CasObjectRefV1, ObjectKind, SchemaLimits, SnapshotExportCommittedV1, SnapshotHandoffV1,
};

mod support;

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

struct ReceiptFixture {
    _directory: tempfile::TempDir,
    limits: SchemaLimits,
    cas_root: std::path::PathBuf,
    cas: FilesystemCas,
    reader: FilesystemCasReader,
    job_id: B256,
    manifest_ref: CasObjectRefV1,
    manifest_hash: B256,
    handoff: SnapshotHandoffV1,
    committed: SnapshotExportCommittedV1,
    receipt_root: std::path::PathBuf,
}

impl ReceiptFixture {
    fn candidate(&self) -> ExportReceiptCandidate<'_> {
        ExportReceiptCandidate {
            handoff: &self.handoff,
            manifest_ref: &self.manifest_ref,
            manifest_hash: self.manifest_hash,
            committed: &self.committed,
        }
    }
}

fn fixture() -> ReceiptFixture {
    let directory = tempfile::tempdir().unwrap();
    let limits = poc_schema_limits();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 8_388_608,
    };
    let cas_root = directory.path().join("cas");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::SnapshotExporter, cas_limits).unwrap();
    let reader = FilesystemCasReader::open(&cas_root, cas_limits).unwrap();
    let job_id = hash(1);
    let bundle = support::protocol_bundle();
    let manifest = InputManifestV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 91,
            finalized_block_hash: hash(3),
            finalized_state_root: hash(4),
            finalized_ce_root: hash(5),
            ce_schema_version: 1,
        },
        wwd: 20_260_725,
        sealed_tribute_collection_key: hash(6),
        sealed_tribute_collection_root: hash(7),
        tribute_count: 2,
        tribute_nominal_total: U256::from(46),
        input_chunk_count: 1,
        input_chunk_list_root: hash(8),
        fidelity_opening_root: hash(9),
        oracle_opening_root: hash(10),
        exact_encoded_bytes: 128,
        exact_record_count: 2,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle.opening_codec_registry_hash().unwrap(),
        compression: Compression::None,
    };
    let manifest_hash = manifest.manifest_hash(&limits).unwrap();
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let handoff = SnapshotHandoffV1 {
        job_id,
        input_lease_id: hash(12),
        pin_generation: 11,
        lease_generation: 17,
        checkpoint: manifest.checkpoint,
        canonical_lease_offer: outbe_ocomp_protocol::common::BoundedBytes(vec![1, 2, 3]),
    };
    let committed = SnapshotExportCommittedV1 {
        job_id,
        pin_generation: 12,
        record_hash: hash(11),
    };
    let receipt_root = directory.path().join("receipts");
    ReceiptFixture {
        _directory: directory,
        limits,
        cas_root,
        cas,
        reader,
        job_id,
        manifest_ref,
        manifest_hash,
        handoff,
        committed,
        receipt_root,
    }
}

#[test]
fn exporter_receipt_survives_restart_and_replays_exact_node_commit() {
    let fixture = fixture();
    let first = {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        let (outcome, receipt) = store
            .record(&fixture.cas, &fixture.reader, fixture.candidate())
            .unwrap();
        assert_eq!(outcome, ExportReceiptRecordOutcome::NewlyRecorded);
        receipt
    };

    let restarted = ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
        .unwrap()
        .load_exact(&fixture.reader)
        .unwrap();
    assert_eq!(restarted.receipt_ref(), first.receipt_ref());
    assert_eq!(restarted.job_id(), fixture.job_id);
    assert_eq!(restarted.manifest_ref(), fixture.manifest_ref);
    assert_eq!(
        restarted.commit_replay_request(),
        outbe_ocomp_protocol::CommitSnapshotExportV1 {
            job_id: fixture.job_id,
            pin_generation: fixture.handoff.pin_generation,
            lease_generation: fixture.handoff.lease_generation,
            manifest_hash: fixture.manifest_hash,
        }
    );
    restarted
        .require_exact_node_replay(&fixture.committed)
        .unwrap();
}

#[test]
fn conflicting_export_receipt_permanently_abstains_the_job() {
    let fixture = fixture();
    let conflicting = SnapshotExportCommittedV1 {
        record_hash: hash(12),
        ..fixture.committed.clone()
    };

    {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        store
            .record(&fixture.cas, &fixture.reader, fixture.candidate())
            .unwrap();
        assert!(matches!(
            store.record(
                &fixture.cas,
                &fixture.reader,
                ExportReceiptCandidate {
                    committed: &conflicting,
                    ..fixture.candidate()
                },
            ),
            Err(ExportReceiptError::ConflictingReceipt)
        ));
    }

    let abstained =
        ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits).unwrap();
    assert!(matches!(
        abstained.load_exact(&fixture.reader),
        Err(ExportReceiptError::Abstained)
    ));
}

#[test]
fn corrupted_content_addressed_receipt_cannot_be_reloaded() {
    let fixture = fixture();
    let receipt_ref = {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        store
            .record(&fixture.cas, &fixture.reader, fixture.candidate())
            .unwrap()
            .1
            .receipt_ref()
    };
    let digest = hex::encode(receipt_ref.transport_digest.as_slice());
    let receipt_path = fixture
        .cas_root
        .join("objects")
        .join(&digest[..2])
        .join(&digest[2..]);
    let mut corrupted = fs::read(&receipt_path).unwrap();
    corrupted[0] ^= 0xFF;
    fs::write(&receipt_path, corrupted).unwrap();

    let restarted =
        ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits).unwrap();
    assert!(matches!(
        restarted.load_exact(&fixture.reader),
        Err(ExportReceiptError::Cas(
            outbe_ocomp::cas::CasError::DigestMismatch { .. }
        ))
    ));
}

#[test]
fn prepared_export_closes_the_crash_window_before_node_commit() {
    let fixture = fixture();
    {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        let (outcome, prepared) = store
            .prepare(
                &fixture.cas,
                &fixture.reader,
                ExportReceiptPreparation {
                    handoff: &fixture.handoff,
                    manifest_ref: &fixture.manifest_ref,
                    manifest_hash: fixture.manifest_hash,
                },
            )
            .unwrap();
        assert_eq!(outcome, ExportReceiptRecordOutcome::NewlyRecorded);
        assert_eq!(
            prepared.commit_request(),
            outbe_ocomp_protocol::CommitSnapshotExportV1 {
                job_id: fixture.job_id,
                pin_generation: fixture.handoff.pin_generation,
                lease_generation: fixture.handoff.lease_generation,
                manifest_hash: fixture.manifest_hash,
            }
        );
    }

    let completed = {
        let mut restarted =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        let prepared = restarted.load_prepared_exact(&fixture.reader).unwrap();
        restarted
            .record_committed(&fixture.cas, &fixture.reader, &prepared, &fixture.committed)
            .unwrap()
            .1
    };
    completed
        .require_exact_node_replay(&fixture.committed)
        .unwrap();
}

#[test]
fn prepared_jobs_are_discoverable_for_cold_node_commit_replay() {
    let fixture = fixture();
    {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        store
            .prepare(
                &fixture.cas,
                &fixture.reader,
                ExportReceiptPreparation {
                    handoff: &fixture.handoff,
                    manifest_ref: &fixture.manifest_ref,
                    manifest_hash: fixture.manifest_hash,
                },
            )
            .unwrap();
    }

    assert_eq!(
        list_prepared_export_jobs(&fixture.receipt_root, 1).unwrap(),
        vec![fixture.job_id]
    );
}

#[test]
fn completed_receipts_do_not_remain_in_the_exporter_recovery_queue() {
    let fixture = fixture();
    {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        store
            .record(&fixture.cas, &fixture.reader, fixture.candidate())
            .unwrap();
    }

    assert!(
        list_prepared_export_jobs(&fixture.receipt_root, 1)
            .unwrap()
            .is_empty(),
        "a durable final receipt no longer requires exporter recovery"
    );
}

#[test]
fn exporter_artifacts_are_group_readable_without_group_write_authority() {
    let fixture = fixture();
    let receipt = {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        store
            .record(&fixture.cas, &fixture.reader, fixture.candidate())
            .unwrap()
            .1
    };
    let job_root = fixture
        .receipt_root
        .join(hex::encode(fixture.job_id.as_slice()));
    assert_eq!(
        fs::metadata(&fixture.receipt_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );
    assert_eq!(
        fs::metadata(&job_root).unwrap().permissions().mode() & 0o777,
        0o750
    );
    for entry in fs::read_dir(&job_root).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o640,
            "exporter journal files are immutable to sibling roles"
        );
    }

    let digest = hex::encode(receipt.receipt_ref().transport_digest.as_slice());
    let receipt_object = fixture
        .cas_root
        .join("objects")
        .join(&digest[..2])
        .join(&digest[2..]);
    assert_eq!(
        fs::metadata(receipt_object).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn supervisor_reads_completed_receipt_without_mutating_exporter_journal() {
    let fixture = fixture();
    {
        let mut store =
            ExportReceiptStore::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
                .unwrap();
        store
            .record(&fixture.cas, &fixture.reader, fixture.candidate())
            .unwrap();
    }
    let job_root = fixture
        .receipt_root
        .join(hex::encode(fixture.job_id.as_slice()));
    let mut entries_before = fs::read_dir(&job_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries_before.sort_unstable();
    for entry in fs::read_dir(&job_root).unwrap() {
        fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o400)).unwrap();
    }
    fs::set_permissions(&job_root, fs::Permissions::from_mode(0o500)).unwrap();

    let receipt = ExportReceiptReader::open(&fixture.receipt_root, fixture.job_id, fixture.limits)
        .unwrap()
        .load_exact(&fixture.reader)
        .unwrap();
    assert_eq!(receipt.job_id(), fixture.job_id);
    let mut entries_after = fs::read_dir(&job_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries_after.sort_unstable();
    assert_eq!(entries_after, entries_before);
}
