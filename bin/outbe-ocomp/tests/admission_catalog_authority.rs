use alloy_primitives::{B256, U256};
use outbe_ocomp::{
    admission_catalog::{AdmissionCatalogError, VerifiedAdmissionCatalog},
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
};
use outbe_ocomp_protocol::{
    input::{CheckpointIdentityV1, Compression, InputManifestV1},
    registry::ObjectKind,
    unit::PlanCommitmentV1,
    CasObjectRefV1, SchemaLimits,
};

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

struct Fixture {
    directory: tempfile::TempDir,
    cas_root: std::path::PathBuf,
    cas: FilesystemCas,
    cas_limits: CasLimits,
    limits: SchemaLimits,
    manifest_ref: CasObjectRefV1,
    plan: PlanCommitmentV1,
    plan_ref: CasObjectRefV1,
}

fn fixture() -> Fixture {
    let limits = poc_schema_limits();
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 8_388_608,
    };
    let cas_root = directory.path().join("cas");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::Supervisor, cas_limits).unwrap();
    let manifest = InputManifestV1 {
        protocol_bundle_hash: hash(1),
        job_id: hash(2),
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 4,
            finalized_block_hash: hash(5),
            finalized_state_root: hash(6),
            finalized_ce_root: hash(7),
            ce_schema_version: 1,
        },
        wwd: 20_260_725,
        sealed_tribute_collection_key: hash(8),
        sealed_tribute_collection_root: hash(9),
        tribute_count: 1,
        tribute_nominal_total: U256::from(100),
        input_chunk_count: 1,
        input_chunk_list_root: hash(10),
        fidelity_opening_root: hash(11),
        oracle_opening_root: hash(12),
        exact_encoded_bytes: 100,
        exact_record_count: 1,
        body_codec_id: hash(13),
        opening_codec_registry_hash: hash(14),
        compression: Compression::None,
    };
    let manifest_hash = manifest.manifest_hash(&limits).unwrap();
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let plan = PlanCommitmentV1 {
        protocol_bundle_hash: manifest.protocol_bundle_hash,
        job_id: manifest.job_id,
        attempt: manifest.attempt,
        input_manifest_hash: manifest_hash,
        wwd: manifest.wwd,
        lysis_budget: U256::from(90),
        logical_evaluation_time: 1_784_765_900,
        tribute_count: manifest.tribute_count,
        max_tributes_per_work_shard: 256,
        primary_work_unit_count: 1,
        primary_work_unit_root: hash(15),
        planner_spec_version: 1,
        reducer_spec_version: 1,
    };
    let plan_ref = cas
        .publish_bytes(&plan.encode_canonical_record(&limits).unwrap())
        .unwrap();
    Fixture {
        directory,
        cas_root,
        cas,
        cas_limits,
        limits,
        manifest_ref,
        plan,
        plan_ref,
    }
}

#[test]
fn cold_restart_uses_the_manifest_and_plan_pinned_in_the_catalog_header() {
    let fixture = fixture();
    let catalog_root = fixture.directory.path().join("admissions");
    VerifiedAdmissionCatalog::open(
        &catalog_root,
        &fixture.cas,
        &fixture.plan_ref,
        &fixture.manifest_ref,
        fixture.limits,
    )
    .unwrap();
    drop(fixture.cas);

    let reader = FilesystemCasReader::open(&fixture.cas_root, fixture.cas_limits).unwrap();
    let catalog = VerifiedAdmissionCatalog::reopen(&catalog_root, &reader, fixture.limits).unwrap();
    assert!(matches!(
        catalog.exact_plan_cursor(),
        Err(AdmissionCatalogError::MissingAdmission { plan_ordinal: 0 })
    ));
}

#[test]
fn an_existing_catalog_rejects_a_different_plan_authority() {
    let fixture = fixture();
    let catalog_root = fixture.directory.path().join("admissions");
    VerifiedAdmissionCatalog::open(
        &catalog_root,
        &fixture.cas,
        &fixture.plan_ref,
        &fixture.manifest_ref,
        fixture.limits,
    )
    .unwrap();
    let mut different_plan = fixture.plan;
    different_plan.logical_evaluation_time += 1;
    let different_plan_ref = fixture
        .cas
        .publish_bytes(
            &different_plan
                .encode_canonical_record(&fixture.limits)
                .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        VerifiedAdmissionCatalog::open(
            &catalog_root,
            &fixture.cas,
            &different_plan_ref,
            &fixture.manifest_ref,
            fixture.limits,
        ),
        Err(AdmissionCatalogError::AuthorityMismatch)
    ));
}

#[test]
fn admission_state_without_its_header_is_never_rebound_to_a_new_authority() {
    let fixture = fixture();
    let catalog_root = fixture.directory.path().join("admissions");
    VerifiedAdmissionCatalog::open(
        &catalog_root,
        &fixture.cas,
        &fixture.plan_ref,
        &fixture.manifest_ref,
        fixture.limits,
    )
    .unwrap();
    std::fs::remove_file(catalog_root.join("catalog.header")).unwrap();
    std::fs::write(
        catalog_root.join("0000000000.admission"),
        b"orphaned admission",
    )
    .unwrap();

    assert!(matches!(
        VerifiedAdmissionCatalog::open(
            &catalog_root,
            &fixture.cas,
            &fixture.plan_ref,
            &fixture.manifest_ref,
            fixture.limits,
        ),
        Err(AdmissionCatalogError::MissingHeader)
    ));
}
