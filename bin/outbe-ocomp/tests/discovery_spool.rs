#![allow(clippy::expect_used)]

#[allow(dead_code)]
mod support;

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt as _},
};

use alloy_primitives::B256;
use outbe_compressed_entities::LOCAL_STORAGE_SCHEMA_VERSION;
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits as exporter_schema_limits,
    discovery_control::{DiscoveryAckRefV1, DiscoveryOfferRefV1},
    discovery_spool::{
        AckPutOutcomeV1, CheckpointAdvanceOutcomeV1, ContiguousCheckpointStoreV1,
        DiscoverySpoolError, DiscoverySpoolV1, PutOutcomeV1,
    },
    export_receipt::{ExportReceiptCandidate, ExportReceiptStore, VerifiedExportReceipt},
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::{FinalizedJobSpecV1, SnapshotExportCommittedV1},
    input::{CheckpointIdentityV1, Compression, InputManifestV1},
    intent::JobIntentV1,
    profile::poc_schema_limits,
    ObjectKind, SnapshotHandoffV1,
};
use outbe_primitives::projection::ProjectionCheckpoint;
use tempfile::TempDir;

const CHAIN_ID: u64 = 42;

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn spec(seed: u8, cursor: u64) -> FinalizedJobSpecV1 {
    support::finalized_job_spec(seed, cursor, CHAIN_ID, hash(0x11))
}

fn committed(job: &FinalizedJobSpecV1, generation: u64, byte: u8) -> SnapshotExportCommittedV1 {
    SnapshotExportCommittedV1 {
        job_id: job.summary.job_id,
        pin_generation: generation.checked_add(1).expect("next pin generation"),
        record_hash: hash(byte),
    }
}

fn verified_receipt(
    job: &FinalizedJobSpecV1,
    source_generation: u64,
    byte: u8,
) -> VerifiedExportReceipt {
    verified_receipt_with(job, source_generation, byte, |_| {})
}

fn verified_receipt_with(
    job: &FinalizedJobSpecV1,
    source_generation: u64,
    byte: u8,
    mutate_manifest: impl FnOnce(&mut InputManifestV1),
) -> VerifiedExportReceipt {
    let directory = TempDir::new().expect("receipt tempdir");
    let limits = exporter_schema_limits();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 8_388_608,
    };
    let cas_root = directory.path().join("cas");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::SnapshotExporter, cas_limits)
        .expect("receipt CAS");
    let reader = FilesystemCasReader::open(&cas_root, cas_limits).expect("receipt CAS reader");
    let bundle = support::protocol_bundle();
    let intent = JobIntentV1::decode_canonical(&job.canonical_job_intent.0, &limits)
        .expect("finalized JobIntent");
    let checkpoint = CheckpointIdentityV1 {
        finalized_block_number: job.summary.cursor,
        finalized_block_hash: job.summary.finalized_block_hash,
        finalized_state_root: job.summary.finalized_state_root,
        finalized_ce_root: intent.ce_sealed_root,
        ce_schema_version: u16::try_from(LOCAL_STORAGE_SCHEMA_VERSION).expect("CE schema version"),
    };
    let mut manifest = InputManifestV1 {
        protocol_bundle_hash: intent.protocol_bundle_hash,
        job_id: job.summary.job_id,
        attempt: intent.attempt,
        checkpoint: checkpoint.clone(),
        wwd: intent.wwd,
        sealed_tribute_collection_key: intent.sealed_tribute_collection_key,
        sealed_tribute_collection_root: intent.sealed_tribute_collection_root,
        tribute_count: intent.authenticated_day_count,
        tribute_nominal_total: intent.authenticated_day_nominal,
        input_chunk_count: 1,
        input_chunk_list_root: hash(0xC4),
        fidelity_opening_root: hash(0xC5),
        oracle_opening_root: hash(0xC6),
        exact_encoded_bytes: 1,
        exact_record_count: 1,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle
            .opening_codec_registry_hash()
            .expect("opening registry hash"),
        compression: Compression::None,
    };
    mutate_manifest(&mut manifest);
    let manifest_hash = manifest.manifest_hash(&limits).expect("manifest hash");
    let mut manifest_ref = cas
        .publish_bytes(
            &manifest
                .encode_canonical(&limits)
                .expect("manifest encoding"),
        )
        .expect("publish manifest");
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let handoff = SnapshotHandoffV1 {
        job_id: job.summary.job_id,
        input_lease_id: hash(0xC7),
        pin_generation: source_generation,
        lease_generation: 1,
        checkpoint: manifest.checkpoint.clone(),
        canonical_lease_offer: BoundedBytes(vec![1]),
    };
    let committed = SnapshotExportCommittedV1 {
        job_id: job.summary.job_id,
        pin_generation: source_generation
            .checked_add(1)
            .expect("verified receipt generation"),
        record_hash: hash(byte),
    };
    let mut store = ExportReceiptStore::open(
        directory.path().join("receipts"),
        job.summary.job_id,
        limits,
    )
    .expect("receipt store");
    store
        .record(
            &cas,
            &reader,
            ExportReceiptCandidate {
                handoff: &handoff,
                manifest_ref: &manifest_ref,
                manifest_hash,
                committed: &committed,
            },
        )
        .expect("verified export receipt")
        .1
}

fn spool(temp: &TempDir) -> DiscoverySpoolV1 {
    DiscoverySpoolV1::open(
        temp.path().join("discovery"),
        CHAIN_ID,
        hash(0x11),
        poc_schema_limits(),
    )
    .expect("open discovery spool")
}

#[test]
fn refs_are_fixed_canonical_and_carry_no_payload() {
    let limits = poc_schema_limits();
    let job = spec(0xA7, 1);
    let offer =
        DiscoveryOfferRefV1::from_spec(CHAIN_ID, hash(0x11), 7, &job, &limits).expect("offer ref");
    let encoded_offer = offer.encode_fixed();
    assert_eq!(encoded_offer.len(), DiscoveryOfferRefV1::FIXED_BYTES);
    assert_eq!(
        DiscoveryOfferRefV1::decode_fixed(&encoded_offer).expect("decode offer"),
        offer
    );
    assert!(!encoded_offer.windows(24).any(|window| window == [0xA7; 24]));
    let mut trailing = encoded_offer.clone();
    trailing.push(0);
    assert!(DiscoveryOfferRefV1::decode_fixed(&trailing).is_err());

    let receipt = committed(&job, 7, 0x91);
    let ack =
        DiscoveryAckRefV1::from_committed(&offer, &receipt, hash(0xE1), &limits).expect("ack ref");
    let encoded_ack = ack.encode_fixed();
    assert_eq!(encoded_ack.len(), DiscoveryAckRefV1::FIXED_BYTES);
    assert_eq!(
        DiscoveryAckRefV1::decode_fixed(&encoded_ack).expect("decode ack"),
        ack
    );
    assert!(!encoded_ack.windows(24).any(|window| window == [0xA7; 24]));
    assert_eq!(ack.export_receipt_digest, hash(0xE1));
    assert!(DiscoveryAckRefV1::from_committed(&offer, &receipt, B256::ZERO, &limits).is_err());
}

#[test]
fn observation_locator_excludes_substitutable_authority_fields() {
    let limits = poc_schema_limits();
    let original = spec(0x11, 1);
    let mut substituted = original.clone();
    substituted.summary.finalized_block_hash = hash(0x92);
    substituted.summary.finalized_state_root = hash(0x93);
    substituted.summary.open_height += 1;
    substituted.summary.deadline_height += 1;
    let intent = JobIntentV1::decode_canonical(&substituted.canonical_job_intent.0, &limits)
        .expect("canonical intent");
    substituted.summary.job_id = intent
        .job_id(
            substituted.summary.finalized_block_hash,
            substituted.summary.finalized_state_root,
            &limits,
        )
        .expect("substituted JobId");
    let original_ref = DiscoveryOfferRefV1::from_spec(CHAIN_ID, hash(0x11), 7, &original, &limits)
        .expect("original ref");
    let substituted_ref =
        DiscoveryOfferRefV1::from_spec(CHAIN_ID, hash(0x11), 7, &substituted, &limits)
            .expect("substituted ref");
    assert_eq!(original_ref.observation_id, substituted_ref.observation_id);
    assert_ne!(
        original_ref.discovery_record_digest,
        substituted_ref.discovery_record_digest
    );
}

#[test]
fn offer_restart_duplicate_and_scalar_pending_are_exact() {
    let temp = TempDir::new().expect("tempdir");
    let job = spec(0x71, 1);
    let first = spool(&temp);
    let (offer, outcome) = first.put_offer(3, &job).expect("first offer");
    assert_eq!(outcome, PutOutcomeV1::Inserted);
    assert_eq!(first.pending_count().expect("count"), 1);
    assert_eq!(
        first
            .pending(&offer.observation_id)
            .expect("inspect")
            .expect("pending")
            .spec,
        job
    );
    drop(first);

    let reopened = spool(&temp);
    let (duplicate, outcome) = reopened.put_offer(3, &job).expect("duplicate");
    assert_eq!(duplicate, offer);
    assert_eq!(outcome, PutOutcomeV1::ExactDuplicate);
    assert_eq!(reopened.pending_count().expect("count"), 1);
}

#[test]
fn pending_cursor_streams_without_collecting_the_spool() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    for cursor in 1..=257 {
        spool
            .put_offer(cursor, &spec(cursor as u8, cursor))
            .expect("offer");
    }
    let cursor = spool.pending_cursor().expect("pending cursor");
    let mut seen = 0_u64;
    for record in cursor {
        let record = record.expect("pending record");
        assert_eq!(record.reference.version, 1);
        seen += 1;
    }
    assert_eq!(seen, 257);
}

#[test]
fn pending_cursor_releases_the_spool_lock_between_records() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let job = spec(0x61, 1);
    let (offer, _) = spool.put_offer(6, &job).expect("offer");
    let mut cursor = spool.pending_cursor().expect("pending cursor");
    let pending = cursor.next().expect("one pending record").expect("record");
    assert_eq!(pending.reference, offer);

    let receipt = verified_receipt(&job, 6, 0x62);
    spool
        .put_ack(&offer, &receipt, &support::protocol_bundle())
        .expect("ACK can be fsynced while the startup cursor remains alive");
    assert_eq!(spool.pending_count().expect("pending count"), 0);
}

#[test]
fn acknowledged_history_is_absent_from_the_durable_pending_index() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    for (seed, cursor) in [(0x41, 1), (0x42, 2), (0x43, 3)] {
        let job = spec(seed, cursor);
        let (offer, _) = spool.put_offer(cursor, &job).expect("offer");
        let receipt = verified_receipt(&job, cursor, seed.wrapping_add(0x20));
        spool
            .put_ack(&offer, &receipt, &support::protocol_bundle())
            .expect("ack");
    }
    assert_eq!(
        fs::read_dir(temp.path().join("discovery/offers"))
            .expect("offer history")
            .count(),
        3,
        "ACK history remains available for exact authority verification"
    );
    assert_eq!(
        fs::read_dir(temp.path().join("discovery/pending"))
            .expect("pending index")
            .count(),
        0,
        "completed history must not be revisited by each exporter cycle"
    );

    spool.put_offer(4, &spec(0x44, 4)).expect("pending offer");
    assert_eq!(spool.pending_count().expect("pending count"), 1);
}

#[test]
fn retirement_waits_for_the_durable_closure_checkpoint_then_removes_history() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let job = spec(0x45, 7);
    let (offer, _) = spool.put_offer(7, &job).expect("offer");
    let receipt = verified_receipt(&job, 7, 0x85);
    spool
        .put_ack(&offer, &receipt, &support::protocol_bundle())
        .expect("ack");

    assert_eq!(
        spool
            .prepare_retirement(&offer, 10)
            .expect("prepare retirement"),
        PutOutcomeV1::Inserted
    );
    assert_eq!(
        spool
            .prepare_retirement(&offer, 12)
            .expect("duplicate retirement"),
        PutOutcomeV1::ExactDuplicate
    );
    let waiting = spool
        .complete_retirements_through(9)
        .expect("checkpoint before authority");
    assert_eq!(waiting.waiting_for_checkpoint, 1);
    assert!(spool
        .ack(&offer.observation_id)
        .expect("ack remains before closure")
        .is_some());

    let completed = spool
        .complete_retirements_through(10)
        .expect("authorized retirement");
    assert_eq!(completed.completed, 1);
    for directory in ["offers", "acks", "pending", "retirements"] {
        assert_eq!(
            fs::read_dir(temp.path().join("discovery").join(directory))
                .expect("retirement directory")
                .count(),
            0,
            "{directory} retains closed discovery history"
        );
    }
    assert!(spool
        .ack(&offer.observation_id)
        .expect("retired ACK lookup")
        .is_none());
}

#[test]
fn prepared_retirement_survives_restart_and_fences_late_ack() {
    let temp = TempDir::new().expect("tempdir");
    let job = spec(0x46, 8);
    let first = spool(&temp);
    let (offer, _) = first.put_offer(8, &job).expect("offer");
    first
        .prepare_retirement(&offer, 20)
        .expect("prepare before checkpoint");
    drop(first);

    let reopened = spool(&temp);
    let waiting = reopened
        .complete_retirements_through(19)
        .expect("restart before checkpoint");
    assert_eq!(waiting.waiting_for_checkpoint, 1);
    assert!(reopened
        .pending(&offer.observation_id)
        .expect("retired offer lookup")
        .is_none());

    let receipt = verified_receipt(&job, 8, 0x86);
    assert_eq!(
        reopened
            .put_ack(&offer, &receipt, &support::protocol_bundle())
            .expect("late ACK is handled without reopening the offer"),
        AckPutOutcomeV1::Retired
    );
    assert!(reopened
        .ack(&offer.observation_id)
        .expect("retired ACK lookup")
        .is_none());
    let completed = reopened
        .complete_retirements_through(20)
        .expect("restart completion");
    assert_eq!(completed.completed, 1);
    assert_eq!(completed.waiting_for_checkpoint, 0);
    assert_eq!(
        reopened
            .put_ack(&offer, &receipt, &support::protocol_bundle())
            .expect("late ACK after physical retirement"),
        AckPutOutcomeV1::Retired
    );
}

#[test]
fn retirement_recovers_after_each_unlink_crash_cut() {
    for cut in ["after_ack", "after_offer"] {
        let temp = TempDir::new().expect("tempdir");
        let first = spool(&temp);
        let job = spec(0x47, 9);
        let (offer, _) = first.put_offer(9, &job).expect("offer");
        let receipt = verified_receipt(&job, 9, 0x87);
        first
            .put_ack(&offer, &receipt, &support::protocol_bundle())
            .expect("ack");
        first
            .prepare_retirement(&offer, 30)
            .expect("prepare retirement");
        let encoded = hex::encode(offer.observation_id.as_slice());
        fs::remove_file(
            temp.path()
                .join("discovery/acks")
                .join(format!("{encoded}.ack")),
        )
        .expect("simulate crash after ACK unlink");
        if cut == "after_offer" {
            fs::remove_file(
                temp.path()
                    .join("discovery/offers")
                    .join(format!("{encoded}.offer")),
            )
            .expect("simulate crash after offer unlink");
        }
        drop(first);

        let reopened = spool(&temp);
        let completed = reopened
            .complete_retirements_through(30)
            .expect("complete partial retirement");
        assert_eq!(completed.completed, 1, "crash cut {cut}");
        assert_eq!(
            fs::read_dir(temp.path().join("discovery/retirements"))
                .expect("retirement directory")
                .count(),
            0,
            "crash cut {cut} retained its intent"
        );
    }
}

#[test]
fn closed_unacknowledged_offer_and_pending_marker_are_retired_together() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let job = spec(0x48, 10);
    let (offer, _) = spool.put_offer(10, &job).expect("offer");
    spool
        .prepare_retirement(&offer, 40)
        .expect("prepare retirement");
    let completed = spool
        .complete_retirements_through(40)
        .expect("retire unacknowledged offer");
    assert_eq!(completed.completed, 1);
    assert_eq!(spool.pending_count().expect("pending count"), 0);
    assert!(!spool.offer_path(&offer.observation_id).exists());
}

#[test]
fn unacknowledged_retirement_recovers_after_pending_unlink() {
    let temp = TempDir::new().expect("tempdir");
    let first = spool(&temp);
    let job = spec(0x49, 11);
    let (offer, _) = first.put_offer(11, &job).expect("offer");
    first
        .prepare_retirement(&offer, 41)
        .expect("prepare retirement");
    let encoded = hex::encode(offer.observation_id.as_slice());
    fs::remove_file(
        temp.path()
            .join("discovery/pending")
            .join(format!("{encoded}.pending")),
    )
    .expect("simulate crash after pending unlink");
    drop(first);

    let reopened = spool(&temp);
    let completed = reopened
        .complete_retirements_through(41)
        .expect("complete partial unacknowledged retirement");
    assert_eq!(completed.completed, 1);
    assert!(!reopened.offer_path(&offer.observation_id).exists());
    assert_eq!(
        fs::read_dir(temp.path().join("discovery/retirements"))
            .expect("retirement directory")
            .count(),
        0
    );
}

#[test]
fn substituted_spec_generation_and_identity_latch_quarantine() {
    for conflict in ["spec", "generation", "identity"] {
        let temp = TempDir::new().expect("tempdir");
        let spool = spool(&temp);
        let original = spec(0x51, 1);
        let (reference, _) = spool.put_offer(4, &original).expect("offer");
        let result = match conflict {
            "spec" => {
                let substituted = spec(0x52, 1);
                spool.put_offer_exact(&reference, &substituted)
            }
            "generation" => spool.put_offer(5, &original).map(|(_, outcome)| outcome),
            "identity" => {
                let mut foreign = reference.clone();
                foreign.chain_id += 1;
                spool.put_offer_exact(&foreign, &original)
            }
            _ => unreachable!(),
        };
        assert!(matches!(
            result,
            Err(DiscoverySpoolError::ConflictLatched { .. })
        ));
        assert!(spool
            .is_quarantined(&reference.observation_id)
            .expect("quarantine state"));
        assert!(matches!(
            spool.pending(&reference.observation_id),
            Err(DiscoverySpoolError::Quarantined { .. })
        ));
    }
}

#[test]
fn ack_before_restart_and_ack_after_restart_are_durable() {
    let temp = TempDir::new().expect("tempdir");
    let first_job = spec(0x31, 1);
    let first = spool(&temp);
    let (first_offer, _) = first.put_offer(8, &first_job).expect("offer");
    let first_receipt = verified_receipt(&first_job, 8, 0x81);
    let AckPutOutcomeV1::Committed {
        reference: first_ack,
        outcome,
    } = first
        .put_ack(&first_offer, &first_receipt, &support::protocol_bundle())
        .expect("ack before restart")
    else {
        panic!("live offer was unexpectedly retired");
    };
    assert_eq!(outcome, PutOutcomeV1::Inserted);
    assert_eq!(
        first_ack.export_receipt_digest,
        first_receipt.receipt_ref().transport_digest
    );
    drop(first);

    let reopened = spool(&temp);
    let stored = reopened
        .ack(&first_offer.observation_id)
        .expect("read ack")
        .expect("stored ack");
    assert_eq!(stored.reference, first_ack);
    assert_eq!(stored.lease_generation, first_receipt.lease_generation());
    assert_eq!(stored.manifest_hash, first_receipt.manifest_hash());
    assert_eq!(reopened.pending_count().expect("pending count"), 0);

    let second_job = spec(0x32, 2);
    let (second_offer, _) = reopened.put_offer(9, &second_job).expect("second offer");
    drop(reopened);
    let reopened_again = spool(&temp);
    let second_receipt = verified_receipt(&second_job, 9, 0x82);
    reopened_again
        .put_ack(&second_offer, &second_receipt, &support::protocol_bundle())
        .expect("ack after restart");
    assert_eq!(reopened_again.pending_count().expect("pending count"), 0);
}

#[test]
fn duplicate_ack_is_idempotent_and_conflicting_ack_latches() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let job = spec(0x44, 1);
    let (offer, _) = spool.put_offer(11, &job).expect("offer");
    let receipt = verified_receipt(&job, 11, 0xA1);
    assert_eq!(
        spool
            .put_ack(&offer, &receipt, &support::protocol_bundle())
            .expect("ack"),
        AckPutOutcomeV1::Committed {
            reference: DiscoveryAckRefV1::from_committed(
                &offer,
                &receipt.committed(),
                receipt.receipt_ref().transport_digest,
                &poc_schema_limits(),
            )
            .expect("ACK reference"),
            outcome: PutOutcomeV1::Inserted,
        }
    );
    assert_eq!(
        spool
            .put_ack(&offer, &receipt, &support::protocol_bundle())
            .expect("duplicate ack"),
        AckPutOutcomeV1::Committed {
            reference: DiscoveryAckRefV1::from_committed(
                &offer,
                &receipt.committed(),
                receipt.receipt_ref().transport_digest,
                &poc_schema_limits(),
            )
            .expect("ACK reference"),
            outcome: PutOutcomeV1::ExactDuplicate,
        }
    );
    let conflict = verified_receipt(&job, 11, 0xA2);
    assert!(matches!(
        spool.put_ack(&offer, &conflict, &support::protocol_bundle()),
        Err(DiscoverySpoolError::ConflictLatched { .. })
    ));
    assert!(spool
        .is_quarantined(&offer.observation_id)
        .expect("quarantine state"));
}

#[test]
fn ack_rejects_a_self_consistent_receipt_for_substituted_finalized_authority() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let job = spec(0x46, 1);
    let (offer, _) = spool.put_offer(12, &job).expect("offer");
    let substituted = verified_receipt_with(&job, 12, 0xA3, |manifest| {
        manifest.checkpoint.finalized_state_root = hash(0xE9);
    });

    assert!(matches!(
        spool.put_ack(&offer, &substituted, &support::protocol_bundle()),
        Err(DiscoverySpoolError::ConflictLatched { .. })
    ));
    assert!(spool
        .is_quarantined(&offer.observation_id)
        .expect("quarantine state"));
}

#[test]
fn malformed_or_foreign_ack_never_suppresses_a_pending_offer() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let first_job = spec(0x61, 1);
    let second_job = spec(0x62, 2);
    let (first_offer, _) = spool.put_offer(4, &first_job).expect("first offer");
    let (second_offer, _) = spool.put_offer(5, &second_job).expect("second offer");
    let first_receipt = verified_receipt(&first_job, 4, 0x81);
    spool
        .put_ack(&first_offer, &first_receipt, &support::protocol_bundle())
        .expect("first ack");

    let acks = temp.path().join("discovery").join("acks");
    let first_ack = acks.join(format!(
        "{}.ack",
        hex::encode(first_offer.observation_id.as_slice())
    ));
    let second_ack = acks.join(format!(
        "{}.ack",
        hex::encode(second_offer.observation_id.as_slice())
    ));
    fs::copy(first_ack, &second_ack).expect("copy foreign ack");
    fs::set_permissions(&second_ack, fs::Permissions::from_mode(0o600)).expect("private mode");

    assert!(matches!(
        spool.pending(&second_offer.observation_id),
        Err(DiscoverySpoolError::CorruptRecord { .. })
    ));
    assert!(matches!(
        spool.ack(&second_offer.observation_id),
        Err(DiscoverySpoolError::CorruptRecord { .. })
    ));
}

#[test]
fn ack_requires_exact_next_pin_generation_and_generation_overflow_latches() {
    let wrong_temp = TempDir::new().expect("tempdir");
    let wrong_spool = spool(&wrong_temp);
    let job = spec(0x45, 1);
    let (offer, _) = wrong_spool.put_offer(11, &job).expect("offer");
    let wrong_generation = verified_receipt(&job, 10, 0xB1);
    assert!(matches!(
        wrong_spool.put_ack(&offer, &wrong_generation, &support::protocol_bundle()),
        Err(DiscoverySpoolError::ConflictLatched { .. })
    ));

    let overflow_temp = TempDir::new().expect("tempdir");
    let overflow_spool = spool(&overflow_temp);
    let (overflow_offer, _) = overflow_spool
        .put_offer(u64::MAX, &job)
        .expect("maximum offer generation remains representable");
    let impossible_next = verified_receipt(&job, 1, 0xB2);
    assert!(matches!(
        overflow_spool.put_ack(
            &overflow_offer,
            &impossible_next,
            &support::protocol_bundle()
        ),
        Err(DiscoverySpoolError::ConflictLatched { .. })
    ));
    assert!(overflow_spool
        .is_quarantined(&overflow_offer.observation_id)
        .expect("overflow quarantine"));
}

#[test]
fn malformed_corrupt_symlink_and_permissive_modes_are_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let spool = spool(&temp);
    let job = spec(0x21, 1);
    let (offer, _) = spool.put_offer(3, &job).expect("offer");
    let offer_path = spool.offer_path(&offer.observation_id);
    fs::write(&offer_path, b"malformed").expect("corrupt offer");
    assert!(matches!(
        spool.pending(&offer.observation_id),
        Err(DiscoverySpoolError::MalformedRecord { .. })
            | Err(DiscoverySpoolError::CorruptRecord { .. })
    ));

    let symlink_temp = TempDir::new().expect("tempdir");
    let root = symlink_temp.path().join("link-root");
    symlink(symlink_temp.path().join("missing"), &root).expect("symlink root");
    assert!(matches!(
        DiscoverySpoolV1::open(root, CHAIN_ID, hash(0x11), poc_schema_limits()),
        Err(DiscoverySpoolError::UnsafePath(_))
    ));

    let mode_temp = TempDir::new().expect("tempdir");
    let mode_root = mode_temp.path().join("mode-root");
    fs::create_dir(&mode_root).expect("mode root");
    fs::set_permissions(&mode_root, fs::Permissions::from_mode(0o755)).expect("mode");
    assert!(matches!(
        DiscoverySpoolV1::open(mode_root, CHAIN_ID, hash(0x11), poc_schema_limits()),
        Err(DiscoverySpoolError::PermissiveMode { .. })
    ));
}

#[test]
fn regular_crash_temps_are_removed_but_symlink_temps_are_rejected() {
    let temp = TempDir::new().expect("tempdir");
    let first = spool(&temp);
    let crash_temp = first.offers_root().join("crashed.offer.tmp");
    fs::write(&crash_temp, b"partial").expect("crash temp");
    fs::set_permissions(&crash_temp, fs::Permissions::from_mode(0o600)).expect("temp mode");
    drop(first);
    let reopened = spool(&temp);
    assert!(!crash_temp.exists());
    drop(reopened);

    let symlink_temp = temp.path().join("discovery/offers/hostile.offer.tmp");
    symlink("/dev/null", &symlink_temp).expect("temp symlink");
    assert!(matches!(
        DiscoverySpoolV1::open(
            temp.path().join("discovery"),
            CHAIN_ID,
            hash(0x11),
            poc_schema_limits()
        ),
        Err(DiscoverySpoolError::UnsafePath(_))
    ));
}

fn checkpoint(number: u64, byte: u8) -> ProjectionCheckpoint {
    ProjectionCheckpoint {
        block_number: number,
        block_hash: hash(byte),
    }
}

#[test]
fn checkpoint_store_initializes_restarts_and_advances_contiguously() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("checkpoint");
    let baseline = checkpoint(100, 0x10);
    let next = checkpoint(101, 0x11);
    let store = ContiguousCheckpointStoreV1::open(&root, baseline).expect("checkpoint store");
    assert_eq!(store.current().expect("current"), baseline);
    assert_eq!(
        store.compare_and_advance(baseline, next).expect("advance"),
        CheckpointAdvanceOutcomeV1::Advanced
    );
    assert_eq!(
        store.compare_and_advance(baseline, next).expect("replay"),
        CheckpointAdvanceOutcomeV1::ExactReplay
    );
    drop(store);
    let reopened = ContiguousCheckpointStoreV1::open(&root, baseline).expect("restart");
    assert_eq!(reopened.current().expect("current"), next);
}

#[test]
fn checkpoint_store_persists_a_sparse_advance_without_per_block_ram_state() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("sparse-checkpoint");
    let baseline = checkpoint(100, 0x10);
    let sparse = checkpoint(10_000, 0x20);
    let store = ContiguousCheckpointStoreV1::open(&root, baseline).expect("checkpoint store");
    assert_eq!(
        store
            .compare_and_advance_to(baseline, sparse)
            .expect("sparse advance"),
        CheckpointAdvanceOutcomeV1::Advanced
    );
    assert_eq!(
        store
            .compare_and_advance_to(baseline, sparse)
            .expect("exact sparse replay"),
        CheckpointAdvanceOutcomeV1::ExactReplay
    );
    drop(store);

    let reopened = ContiguousCheckpointStoreV1::open(&root, baseline).expect("restart");
    assert_eq!(reopened.current().expect("current"), sparse);
    reopened
        .compare_and_advance(sparse, checkpoint(10_001, 0x21))
        .expect("contiguous progress resumes after sparse checkpoint");
}

#[test]
fn checkpoint_store_rejects_wrong_baseline_stale_conflict_and_non_contiguous() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("checkpoint");
    let baseline = checkpoint(10, 0x10);
    let store = ContiguousCheckpointStoreV1::open(&root, baseline).expect("store");
    assert!(store
        .compare_and_advance(baseline, checkpoint(12, 0x12))
        .is_err());
    let next = checkpoint(11, 0x11);
    store.compare_and_advance(baseline, next).expect("advance");
    assert!(store
        .compare_and_advance(baseline, checkpoint(11, 0x22))
        .is_err());
    assert!(store
        .compare_and_advance(next, checkpoint(11, 0x11))
        .is_err());
    assert!(store
        .compare_and_advance(checkpoint(11, 0x99), checkpoint(12, 0x12))
        .is_err());
    drop(store);
    assert!(ContiguousCheckpointStoreV1::open(&root, checkpoint(10, 0x77)).is_err());
}
