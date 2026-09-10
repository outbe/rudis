mod admission_support;

use alloy_primitives::{Address, B256, U256};
use outbe_ocomp::{
    admission_catalog::{AdmissionOutcome, AdmissionPositionV1, VerifiedAdmissionCatalog},
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    inbox::{WorkerInbox, WorkerInboxLimits},
    lysis_shuffle_adoption::{admit_reported_lysis_shuffle_unit, adopt_lysis_shuffle_descendants},
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    result::ContributorActionV1,
    shuffle::{build_owner_shuffle_run, verified_shuffle_run_records, ShuffleRunBuildContextV1},
    unit::{
        CanonicalInputRefV1, CanonicalRunSpan, InputPurpose, InputSourceKind, UnitArtifactV1,
        UnitInterval, UnitPhase, UnitSpecV1, WorkOutputHeaderV1,
    },
    ObjectKind, ProtocolError, UnitFinishedStatus, UnitFinishedV1,
};
use tempfile::tempdir;

const CAS_LIMITS: CasLimits = CasLimits {
    max_object_bytes: 1_048_576,
    max_total_bytes: 16_777_216,
};
const INBOX_LIMITS: WorkerInboxLimits = WorkerInboxLimits {
    max_artifact_bytes: 1_048_576,
    max_total_bytes: 16_777_216,
};

fn contributor(index: u32) -> ContributorActionV1 {
    let mut owner = [0_u8; 20];
    owner[16..].copy_from_slice(&(index + 1).to_be_bytes());
    let mut tribute = [0_u8; 32];
    tribute[28..].copy_from_slice(&index.to_be_bytes());
    ContributorActionV1 {
        owner: Address::from(owner),
        source_tribute_id: B256::from(tribute),
        nominal_amount_minor: U256::from(index + 1),
    }
}

fn owner_shuffle_spec() -> UnitSpecV1 {
    UnitSpecV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        phase: UnitPhase::OwnerShuffle,
        interval: UnitInterval::CanonicalRunSpan(CanonicalRunSpan {
            start_run: 0,
            end_run: 2,
        }),
        canonical_ordered_inputs: vec![
            CanonicalInputRefV1 {
                purpose: InputPurpose::InputManifest,
                source_kind: InputSourceKind::AuthenticatedRoot,
                source_id: B256::repeat_byte(5),
                record_count_limit: 1,
                max_encoded_bytes: 1024,
                max_decoded_bytes: 1024,
            },
            CanonicalInputRefV1 {
                purpose: InputPurpose::FinalizedOutputRecords,
                source_kind: InputSourceKind::UnitOutput,
                source_id: B256::repeat_byte(6),
                record_count_limit: 257,
                max_encoded_bytes: 1_048_576,
                max_decoded_bytes: 1_048_576,
            },
        ],
        lysis_program_semantics_hash: B256::repeat_byte(7),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    }
}

#[test]
fn supervisor_adopts_the_complete_verified_descendant_closure_into_cas() {
    let directory = tempdir().unwrap();
    let limits = poc_schema_limits();
    let inbox = WorkerInbox::open(directory.path().join("inbox"), INBOX_LIMITS).unwrap();
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::Supervisor,
        CAS_LIMITS,
    )
    .unwrap();
    let root = build_owner_shuffle_run(
        ShuffleRunBuildContextV1 {
            protocol_bundle_hash: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 0,
            unit_id: B256::repeat_byte(3),
            run_span: CanonicalRunSpan {
                start_run: 0,
                end_run: 3,
            },
            source_coverage_root: B256::repeat_byte(4),
            source_coverage_count: 513,
        },
        (0..513_u32).map(|index| Ok(contributor(index))),
        &limits,
        |bytes| {
            inbox
                .stage_shuffle_object(bytes, &limits)
                .map_err(|_| ProtocolError::InvalidInvariant("test inbox stage"))
        },
    )
    .unwrap();
    assert_eq!(inbox.object_count().unwrap(), 5);
    assert_eq!(cas.object_count().unwrap(), 0);

    let adopted = adopt_lysis_shuffle_descendants(root.clone(), &inbox, &cas, &limits).unwrap();
    assert_eq!(adopted.descendant_object_count, 4);
    assert_eq!(adopted.verified_record_count, 513);
    assert_eq!(cas.object_count().unwrap(), 4);

    let reader = FilesystemCasReader::open(directory.path().join("cas"), CAS_LIMITS).unwrap();
    let records = verified_shuffle_run_records(root, &limits, |reference| {
        reader
            .read_verified(reference)
            .map(|object| object.bytes().to_vec())
            .map_err(|_| ProtocolError::InvalidInvariant("test CAS read"))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(records.len(), 513);
}

#[test]
fn adoption_fails_closed_when_a_referenced_worker_object_is_missing() {
    let directory = tempdir().unwrap();
    let limits = poc_schema_limits();
    let source_inbox =
        WorkerInbox::open(directory.path().join("source-inbox"), INBOX_LIMITS).unwrap();
    let empty_inbox =
        WorkerInbox::open(directory.path().join("empty-inbox"), INBOX_LIMITS).unwrap();
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::Supervisor,
        CAS_LIMITS,
    )
    .unwrap();
    let spec = owner_shuffle_spec();
    let authority = admission_support::publish_admission_authority(&cas, &spec, 1, 1, &limits);
    let authority_object_count = cas.object_count().unwrap();
    let mut catalog = VerifiedAdmissionCatalog::open(
        directory.path().join("catalog"),
        &cas,
        &authority.plan_ref,
        &authority.manifest_ref,
        limits,
    )
    .unwrap();
    let unit_id = spec.unit_id(&limits).unwrap();
    let root = build_owner_shuffle_run(
        ShuffleRunBuildContextV1 {
            protocol_bundle_hash: spec.protocol_bundle_hash,
            job_id: spec.job_id,
            attempt: spec.attempt,
            unit_id,
            run_span: CanonicalRunSpan {
                start_run: 0,
                end_run: 2,
            },
            source_coverage_root: B256::repeat_byte(4),
            source_coverage_count: 257,
        },
        (0..257_u32).map(|index| Ok(contributor(index))),
        &limits,
        |bytes| {
            source_inbox
                .stage_shuffle_object(bytes, &limits)
                .map_err(|_| ProtocolError::InvalidInvariant("test inbox stage"))
        },
    )
    .unwrap();
    let artifact = UnitArtifactV1::from_canonical_output(
        &spec,
        WorkOutputHeaderV1 {
            source_coverage_root: root.source_coverage_root,
            output_coverage_root: root.ordered_record_root,
            source_coverage_count: root.source_coverage_count,
            output_coverage_count: root.record_count,
        },
        BoundedBytes(root.encode_canonical(&limits).unwrap()),
        &limits,
    )
    .unwrap();
    let staged = empty_inbox
        .adopt(unit_id, &artifact.encode_canonical(&limits).unwrap())
        .unwrap();
    let reference = staged.reference();
    let finished = UnitFinishedV1 {
        unit_id,
        status: UnitFinishedStatus::Success,
        exact_staged_bytes: reference.encoded_bytes,
        transport_digest: reference.transport_digest,
    };

    assert!(admit_reported_lysis_shuffle_unit(
        AdmissionPositionV1 { plan_ordinal: 9 },
        &spec,
        &finished,
        &empty_inbox,
        &cas,
        &mut catalog,
        &limits,
    )
    .is_err());
    assert_eq!(cas.object_count().unwrap(), authority_object_count);
}

#[test]
fn reported_shuffle_unit_becomes_authoritative_only_after_full_closure_adoption() {
    let directory = tempdir().unwrap();
    let limits = poc_schema_limits();
    let inbox = WorkerInbox::open(directory.path().join("inbox"), INBOX_LIMITS).unwrap();
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::Supervisor,
        CAS_LIMITS,
    )
    .unwrap();
    let spec = owner_shuffle_spec();
    let authority = admission_support::publish_admission_authority(&cas, &spec, 1, 1, &limits);
    let mut catalog = VerifiedAdmissionCatalog::open(
        directory.path().join("catalog"),
        &cas,
        &authority.plan_ref,
        &authority.manifest_ref,
        limits,
    )
    .unwrap();
    let unit_id = spec.unit_id(&limits).unwrap();
    let root = build_owner_shuffle_run(
        ShuffleRunBuildContextV1 {
            protocol_bundle_hash: spec.protocol_bundle_hash,
            job_id: spec.job_id,
            attempt: spec.attempt,
            unit_id,
            run_span: CanonicalRunSpan {
                start_run: 0,
                end_run: 2,
            },
            source_coverage_root: B256::repeat_byte(4),
            source_coverage_count: 257,
        },
        (0..257_u32).map(|index| Ok(contributor(index))),
        &limits,
        |bytes| {
            inbox
                .stage_shuffle_object(bytes, &limits)
                .map_err(|_| ProtocolError::InvalidInvariant("test inbox stage"))
        },
    )
    .unwrap();
    let artifact = UnitArtifactV1::from_canonical_output(
        &spec,
        WorkOutputHeaderV1 {
            source_coverage_root: root.source_coverage_root,
            output_coverage_root: root.ordered_record_root,
            source_coverage_count: root.source_coverage_count,
            output_coverage_count: root.record_count,
        },
        BoundedBytes(root.encode_canonical(&limits).unwrap()),
        &limits,
    )
    .unwrap();
    let bytes = artifact.encode_canonical(&limits).unwrap();
    let staged = inbox.adopt(unit_id, &bytes).unwrap();
    let reference = staged.reference();
    let finished = UnitFinishedV1 {
        unit_id,
        status: UnitFinishedStatus::Success,
        exact_staged_bytes: reference.encoded_bytes,
        transport_digest: reference.transport_digest,
    };

    let admitted = admit_reported_lysis_shuffle_unit(
        AdmissionPositionV1 { plan_ordinal: 9 },
        &spec,
        &finished,
        &inbox,
        &cas,
        &mut catalog,
        &limits,
    )
    .unwrap();
    assert_eq!(admitted.closure.verified_record_count, 257);
    assert_eq!(admitted.admission, AdmissionOutcome::NewlyAdmitted);
    assert_eq!(catalog.read(9).unwrap().plan_hash, authority.plan_hash);
    assert_eq!(
        admitted.artifact_ref.expected_ocb1_kind,
        Some(ObjectKind::UnitArtifactV1.tag())
    );
    assert_eq!(
        cas.read_verified(&admitted.artifact_ref).unwrap().bytes(),
        bytes
    );
}
