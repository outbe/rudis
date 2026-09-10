mod admission_support;

use alloy_primitives::B256;
use outbe_lysis::program_v1::planner::LysisPlanTopologyV1;
use outbe_ocomp::{
    admission_catalog::{AdmissionPositionV1, VerifiedAdmissionCatalog},
    bucket_shuffle_cursor::authoritative_bucket_shuffle_records,
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    inbox::{WorkerInbox, WorkerInboxLimits},
    lysis_shuffle_adoption::admit_reported_lysis_shuffle_unit,
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    shuffle::{
        build_bucket_shuffle_run, ShuffleBucketRecordV1, ShuffleRunBuildContextV1,
        ShuffleRunPayloadV1, VerifiedShuffleRecordV1,
    },
    unit::{
        CanonicalRunSpan, UnitArtifactV1, UnitInterval, UnitPhase, UnitSpecV1, WorkOutputHeaderV1,
    },
    CasObjectRefV1, ObjectKind, SchemaLimits, UnitFinishedStatus, UnitFinishedV1,
};

const CAS_LIMITS: CasLimits = CasLimits {
    max_object_bytes: 1_048_576,
    max_total_bytes: 16_777_216,
};
const INBOX_LIMITS: WorkerInboxLimits = WorkerInboxLimits {
    max_artifact_bytes: 1_048_576,
    max_total_bytes: 16_777_216,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn bucket_record(index: u32) -> ShuffleBucketRecordV1 {
    let mut bucket_key = [0_u8; 32];
    bucket_key[28..].copy_from_slice(&index.to_be_bytes());
    let mut tribute_id = [0_u8; 32];
    tribute_id[28..].copy_from_slice(&index.to_be_bytes());
    let mut nod_id = [0_u8; 32];
    nod_id[28..].copy_from_slice(&(index + 1).to_be_bytes());
    ShuffleBucketRecordV1 {
        bucket_key: B256::from(bucket_key),
        raw_ordinal: index,
        tribute_id: B256::from(tribute_id),
        nod_id: B256::from(nod_id),
    }
}

fn final_bucket_shuffle_plan_ordinal(topology: LysisPlanTopologyV1) -> u32 {
    let offset = [
        UnitPhase::Enumerate,
        UnitPhase::FidelityMap,
        UnitPhase::FixedReduce,
        UnitPhase::AmountMap,
        UnitPhase::GratisPrefix,
        UnitPhase::GratisPrefixDown,
        UnitPhase::OutputFinalize,
        UnitPhase::OwnerShuffle,
    ]
    .into_iter()
    .map(|phase| topology.phase_unit_count(phase))
    .sum::<u32>();
    offset + topology.phase_unit_count(UnitPhase::BucketShuffle) - 1
}

struct AdmittedBucketFixture {
    _directory: tempfile::TempDir,
    cas_root: std::path::PathBuf,
    catalog_root: std::path::PathBuf,
    limits: SchemaLimits,
    plan_ordinal: u32,
    plan_hash: B256,
    descendant_ref: CasObjectRefV1,
}

fn admitted_bucket_fixture() -> AdmittedBucketFixture {
    let limits = poc_schema_limits();
    let directory = tempfile::tempdir().unwrap();
    let inbox = WorkerInbox::open(directory.path().join("inbox"), INBOX_LIMITS).unwrap();
    let cas_root = directory.path().join("cas");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::Supervisor, CAS_LIMITS).unwrap();
    let spec = UnitSpecV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 0,
        phase: UnitPhase::BucketShuffle,
        interval: UnitInterval::CanonicalRunSpan(CanonicalRunSpan {
            start_run: 0,
            end_run: 2,
        }),
        canonical_ordered_inputs: Vec::new(),
        lysis_program_semantics_hash: hash(3),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    let unit_id = spec.unit_id(&limits).unwrap();
    let root = build_bucket_shuffle_run(
        ShuffleRunBuildContextV1 {
            protocol_bundle_hash: spec.protocol_bundle_hash,
            job_id: spec.job_id,
            attempt: spec.attempt,
            unit_id,
            run_span: CanonicalRunSpan {
                start_run: 0,
                end_run: 2,
            },
            source_coverage_root: hash(4),
            source_coverage_count: 257,
        },
        (0..257_u32).map(|index| Ok(bucket_record(index))),
        &limits,
        |bytes| {
            inbox
                .stage_shuffle_object(bytes, &limits)
                .map_err(|_| outbe_ocomp_protocol::ProtocolError::InvalidInvariant("test stage"))
        },
    )
    .unwrap();
    let descendant_ref = match &root.payload {
        ShuffleRunPayloadV1::Node { left, .. } => left.artifact_ref.clone(),
        ShuffleRunPayloadV1::OwnerLeaf(_) | ShuffleRunPayloadV1::BucketLeaf(_) => {
            panic!("257 records must produce a descendant page")
        }
    };
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
    let artifact_bytes = artifact.encode_canonical(&limits).unwrap();
    let staged = inbox.adopt(unit_id, &artifact_bytes).unwrap();
    let finished = UnitFinishedV1 {
        unit_id,
        status: UnitFinishedStatus::Success,
        exact_staged_bytes: staged.reference().encoded_bytes,
        transport_digest: staged.reference().transport_digest,
    };
    let authority = admission_support::publish_admission_authority(&cas, &spec, 257, 2, &limits);
    let catalog_root = directory.path().join("admissions");
    let mut catalog = VerifiedAdmissionCatalog::open(
        &catalog_root,
        &cas,
        &authority.plan_ref,
        &authority.manifest_ref,
        limits,
    )
    .unwrap();
    let topology = LysisPlanTopologyV1::new(2).unwrap();
    let plan_ordinal = final_bucket_shuffle_plan_ordinal(topology);
    let admitted = admit_reported_lysis_shuffle_unit(
        AdmissionPositionV1 { plan_ordinal },
        &spec,
        &finished,
        &inbox,
        &cas,
        &mut catalog,
        &limits,
    )
    .unwrap();
    assert_eq!(
        admitted.artifact_ref.expected_ocb1_kind,
        Some(ObjectKind::UnitArtifactV1.tag())
    );
    drop(catalog);
    drop(cas);

    AdmittedBucketFixture {
        _directory: directory,
        cas_root,
        catalog_root,
        limits,
        plan_ordinal,
        plan_hash: authority.plan_hash,
        descendant_ref,
    }
}

#[test]
fn cold_restart_streams_the_final_bucket_shuffle_from_authoritative_cas() {
    let fixture = admitted_bucket_fixture();
    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let catalog =
        VerifiedAdmissionCatalog::reopen(&fixture.catalog_root, &reader, fixture.limits).unwrap();
    assert_eq!(
        catalog.read(fixture.plan_ordinal).unwrap().plan_hash,
        fixture.plan_hash
    );
    let records = authoritative_bucket_shuffle_records(&catalog, &reader, &fixture.limits)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records.len(), 257);
    assert!(matches!(
        &records[0],
        VerifiedShuffleRecordV1::Bucket(record) if record.raw_ordinal == 0
    ));
    assert!(matches!(
        &records[256],
        VerifiedShuffleRecordV1::Bucket(record) if record.raw_ordinal == 256
    ));
}

#[test]
fn a_missing_authoritative_bucket_page_fails_during_bounded_iteration() {
    let fixture = admitted_bucket_fixture();
    let digest = hex::encode(fixture.descendant_ref.transport_digest.as_slice());
    let missing = fixture
        .cas_root
        .join("objects")
        .join(&digest[..2])
        .join(&digest[2..]);
    std::fs::remove_file(missing).unwrap();

    let reader = FilesystemCasReader::open(&fixture.cas_root, CAS_LIMITS).unwrap();
    let catalog =
        VerifiedAdmissionCatalog::reopen(&fixture.catalog_root, &reader, fixture.limits).unwrap();
    let records = authoritative_bucket_shuffle_records(&catalog, &reader, &fixture.limits)
        .unwrap()
        .collect::<Result<Vec<_>, _>>();
    assert!(records.is_err());
}
