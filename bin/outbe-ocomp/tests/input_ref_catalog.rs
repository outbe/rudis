mod support;

use std::cell::Cell;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, encode_tribute_v1, TributeBodyV1};
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    input_artifacts::derive_input_chunk_ref,
    input_ref_catalog::{
        InputRefAdmissionOutcome, InputRefCatalogError, InputRefCatalogPublisher,
        InputRefCatalogSubjectV1, VerifiedInputChunkRefCatalog,
    },
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    input::{
        AuthenticatedInputChunkV1, CheckpointIdentityV1, Compression, InputChunkKind,
        InputChunkRefV1, InputManifestV1,
    },
    profile::ProtocolBundleV1,
    registry::ObjectKind,
    CasObjectRefV1, ListKind, OrderedListLimits,
};
use outbe_primitives::time::WorldwideDay;

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn input_ref(kind: InputChunkKind, ordinal: u32, records: u32, byte: u8) -> InputChunkRefV1 {
    InputChunkRefV1 {
        kind,
        ordinal,
        record_count: records,
        first_key: BoundedBytes(vec![byte]),
        last_key_inclusive: BoundedBytes(vec![byte.saturating_add(1)]),
        encoded_bytes: u64::from(records) * 100,
        semantic_digest: hash(byte),
        transport_digest: hash(byte.saturating_add(1)),
    }
}

struct Fixture {
    cas: FilesystemCas,
    catalog_root: PathBuf,
    limits: outbe_ocomp_protocol::SchemaLimits,
    list_limits: OrderedListLimits,
    references: [InputChunkRefV1; 2],
    manifest_ref: CasObjectRefV1,
    _directory: tempfile::TempDir,
}

struct OneChunkStageFixture {
    cas: FilesystemCas,
    reader: FilesystemCasReader,
    catalog_root: PathBuf,
    limits: outbe_ocomp_protocol::SchemaLimits,
    list_limits: OrderedListLimits,
    bundle: ProtocolBundleV1,
    subject: InputRefCatalogSubjectV1,
    reference: InputChunkRefV1,
    day: WorldwideDay,
    nominal: U256,
    _directory: tempfile::TempDir,
}

impl OneChunkStageFixture {
    fn manifest(
        &self,
        summary: outbe_ocomp::input_ref_catalog::InputRefCatalogSummaryV1,
        checkpoint_byte: u8,
    ) -> InputManifestV1 {
        InputManifestV1 {
            protocol_bundle_hash: self.subject.protocol_bundle_hash,
            job_id: self.subject.job_id,
            attempt: self.subject.attempt,
            checkpoint: CheckpointIdentityV1 {
                finalized_block_number: u64::from(checkpoint_byte),
                finalized_block_hash: hash(checkpoint_byte),
                finalized_state_root: hash(checkpoint_byte.saturating_add(1)),
                finalized_ce_root: hash(checkpoint_byte.saturating_add(2)),
                ce_schema_version: 1,
            },
            wwd: self.day.value(),
            sealed_tribute_collection_key: hash(93),
            sealed_tribute_collection_root: hash(94),
            tribute_count: summary.tribute_count,
            tribute_nominal_total: self.nominal,
            input_chunk_count: summary.input_chunk_count,
            input_chunk_list_root: summary.input_chunk_list_root,
            fidelity_opening_root: hash(95),
            oracle_opening_root: hash(96),
            exact_encoded_bytes: summary.exact_encoded_bytes,
            exact_record_count: summary.exact_record_count,
            body_codec_id: self.bundle.tribute_body_codec_id,
            opening_codec_registry_hash: self.bundle.opening_codec_registry_hash().unwrap(),
            compression: Compression::None,
        }
    }

    fn publish_manifest(&self, manifest: &InputManifestV1) -> CasObjectRefV1 {
        let mut reference = self
            .cas
            .publish_bytes(&manifest.encode_canonical(&self.limits).unwrap())
            .unwrap();
        reference.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
        reference
    }
}

fn one_chunk_stage_fixture() -> OneChunkStageFixture {
    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(1, 4096, 4096);
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = hash(90);
    let day = WorldwideDay::new(20_260_725);
    let owner = Address::repeat_byte(91);
    let nominal = U256::from(11);
    let tribute = TributeBodyV1 {
        tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
        owner,
        worldwide_day: day,
        issuance_amount_minor: U256::from(10),
        issuance_currency: 840,
        nominal_amount_minor: nominal,
        reference_currency: 978,
        tribute_price_minor: U256::from(12),
        exclude_from_intex_issuance: false,
    };
    let chunk = AuthenticatedInputChunkV1 {
        protocol_bundle_hash,
        job_id,
        kind: InputChunkKind::Tribute,
        ordinal: 0,
        canonical_records_or_openings: vec![BoundedBytes(encode_tribute_v1(&tribute).unwrap())],
    };
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 8_388_608,
    };
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::SnapshotExporter,
        cas_limits,
    )
    .unwrap();
    let reader = FilesystemCasReader::open(directory.path().join("cas"), cas_limits).unwrap();
    let mut object_ref = cas
        .publish_bytes(&chunk.encode_canonical(&limits).unwrap())
        .unwrap();
    object_ref.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
    let reference =
        derive_input_chunk_ref(&cas.read_verified(&object_ref).unwrap(), &bundle, &limits)
            .unwrap()
            .reference;
    OneChunkStageFixture {
        cas,
        reader,
        catalog_root: directory.path().join("staged-input-refs"),
        limits,
        list_limits,
        bundle,
        subject: InputRefCatalogSubjectV1 {
            protocol_bundle_hash,
            job_id,
            attempt: 0,
        },
        reference,
        day,
        nominal,
        _directory: directory,
    }
}

fn fixture() -> Fixture {
    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(16, 1024, 4096);
    let references = [
        input_ref(InputChunkKind::Tribute, 0, 2, 10),
        input_ref(InputChunkKind::Fidelity, 1, 1, 20),
    ];
    let encoded = references
        .iter()
        .map(|reference| reference.encode_canonical_record(&limits).unwrap())
        .collect::<Vec<_>>();
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
        tribute_count: 2,
        tribute_nominal_total: U256::from(100),
        input_chunk_count: 2,
        input_chunk_list_root: outbe_ocomp_protocol::ordered_list_root(
            ListKind::InputChunkReferences,
            &encoded,
            list_limits,
        )
        .unwrap(),
        fidelity_opening_root: hash(11),
        oracle_opening_root: hash(12),
        exact_encoded_bytes: references
            .iter()
            .map(|reference| reference.encoded_bytes)
            .sum(),
        exact_record_count: references
            .iter()
            .map(|reference| reference.record_count)
            .sum(),
        body_codec_id: hash(13),
        opening_codec_registry_hash: hash(14),
        compression: Compression::None,
    };
    let directory = tempfile::tempdir().unwrap();
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::SnapshotExporter,
        CasLimits {
            max_object_bytes: 1_048_576,
            max_total_bytes: 8_388_608,
        },
    )
    .unwrap();
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    Fixture {
        cas,
        catalog_root: directory.path().join("input-refs"),
        limits,
        list_limits,
        references,
        manifest_ref,
        _directory: directory,
    }
}

#[test]
fn exact_input_refs_survive_cold_restart_under_the_manifest_authority() {
    let fixture = fixture();

    {
        let mut catalog = VerifiedInputChunkRefCatalog::open(
            &fixture.catalog_root,
            &fixture.cas,
            &fixture.manifest_ref,
            fixture.limits,
            fixture.list_limits,
        )
        .unwrap();
        for reference in &fixture.references {
            assert_eq!(
                catalog.admit(reference).unwrap(),
                InputRefAdmissionOutcome::NewlyAdmitted
            );
        }
    }

    let catalog = VerifiedInputChunkRefCatalog::open(
        &fixture.catalog_root,
        &fixture.cas,
        &fixture.manifest_ref,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    let progress = Cell::new(0_u64);
    assert_eq!(
        catalog
            .exact_cursor_observing(|| progress.set(progress.get() + 1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        fixture.references
    );
    assert!(progress.get() > 0);
}

#[test]
fn partial_input_ref_catalog_never_opens_an_exact_cursor() {
    let fixture = fixture();
    let mut catalog = VerifiedInputChunkRefCatalog::open(
        &fixture.catalog_root,
        &fixture.cas,
        &fixture.manifest_ref,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    catalog.admit(&fixture.references[0]).unwrap();

    assert!(matches!(
        catalog.exact_cursor(),
        Err(InputRefCatalogError::MissingReference { ordinal: 1 })
    ));
}

#[test]
fn input_ref_state_without_its_header_is_never_rebound_to_a_manifest() {
    let fixture = fixture();
    {
        let mut catalog = VerifiedInputChunkRefCatalog::open(
            &fixture.catalog_root,
            &fixture.cas,
            &fixture.manifest_ref,
            fixture.limits,
            fixture.list_limits,
        )
        .unwrap();
        catalog.admit(&fixture.references[0]).unwrap();
    }
    std::fs::remove_file(fixture.catalog_root.join("catalog.header")).unwrap();

    assert!(matches!(
        VerifiedInputChunkRefCatalog::open(
            &fixture.catalog_root,
            &fixture.cas,
            &fixture.manifest_ref,
            fixture.limits,
            fixture.list_limits,
        ),
        Err(InputRefCatalogError::MissingHeader)
    ));
}

#[test]
fn cold_restart_reopens_each_input_chunk_from_authoritative_cas_and_rederives_its_ref() {
    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(16, 4096, 4096);
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = hash(30);
    let day = WorldwideDay::new(20_260_725);
    let owner = Address::repeat_byte(31);
    let tribute = TributeBodyV1 {
        tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
        owner,
        worldwide_day: day,
        issuance_amount_minor: U256::from(10),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(11),
        reference_currency: 978,
        tribute_price_minor: U256::from(12),
        exclude_from_intex_issuance: false,
    };
    let chunk = AuthenticatedInputChunkV1 {
        protocol_bundle_hash,
        job_id,
        kind: InputChunkKind::Tribute,
        ordinal: 0,
        canonical_records_or_openings: vec![BoundedBytes(encode_tribute_v1(&tribute).unwrap())],
    };
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 8_388_608,
    };
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::SnapshotExporter,
        cas_limits,
    )
    .unwrap();
    let mut chunk_ref = cas
        .publish_bytes(&chunk.encode_canonical(&limits).unwrap())
        .unwrap();
    chunk_ref.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
    let derived_ref =
        derive_input_chunk_ref(&cas.read_verified(&chunk_ref).unwrap(), &bundle, &limits)
            .unwrap()
            .reference;
    let encoded_ref = derived_ref.encode_canonical_record(&limits).unwrap();
    let manifest = InputManifestV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 40,
            finalized_block_hash: hash(41),
            finalized_state_root: hash(42),
            finalized_ce_root: hash(43),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: hash(44),
        sealed_tribute_collection_root: hash(45),
        tribute_count: 1,
        tribute_nominal_total: tribute.nominal_amount_minor,
        input_chunk_count: 1,
        input_chunk_list_root: outbe_ocomp_protocol::ordered_list_root(
            ListKind::InputChunkReferences,
            &[encoded_ref],
            list_limits,
        )
        .unwrap(),
        fidelity_opening_root: hash(46),
        oracle_opening_root: hash(47),
        exact_encoded_bytes: derived_ref.encoded_bytes,
        exact_record_count: 1,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle.opening_codec_registry_hash().unwrap(),
        compression: Compression::None,
    };
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let catalog_path = directory.path().join("input-refs");
    {
        let mut catalog = VerifiedInputChunkRefCatalog::open(
            &catalog_path,
            &cas,
            &manifest_ref,
            limits,
            list_limits,
        )
        .unwrap();
        catalog.admit(&derived_ref).unwrap();
    }
    drop(cas);
    for entry in fs::read_dir(&catalog_path).unwrap() {
        fs::set_permissions(entry.unwrap().path(), fs::Permissions::from_mode(0o400)).unwrap();
    }
    fs::set_permissions(&catalog_path, fs::Permissions::from_mode(0o500)).unwrap();

    let reader = FilesystemCasReader::open(directory.path().join("cas"), cas_limits).unwrap();
    let mut catalog =
        VerifiedInputChunkRefCatalog::reopen(&catalog_path, &reader, limits, list_limits).unwrap();
    let reopened = catalog
        .exact_verified_cursor(&reader, &bundle)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(reopened.len(), 1);
    assert_eq!(reopened[0].reference, derived_ref);
    assert_eq!(reopened[0].chunk, chunk);
    assert!(matches!(
        catalog.admit(&derived_ref),
        Err(InputRefCatalogError::ReadOnly)
    ));
    drop(catalog);
    fs::set_permissions(&catalog_path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn staged_reference_survives_restart_and_seals_only_after_the_manifest_exists() {
    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(16, 4096, 4096);
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = hash(60);
    let day = WorldwideDay::new(20_260_725);
    let owner = Address::repeat_byte(61);
    let tribute = TributeBodyV1 {
        tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
        owner,
        worldwide_day: day,
        issuance_amount_minor: U256::from(10),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(11),
        reference_currency: 978,
        tribute_price_minor: U256::from(12),
        exclude_from_intex_issuance: false,
    };
    let chunk = AuthenticatedInputChunkV1 {
        protocol_bundle_hash,
        job_id,
        kind: InputChunkKind::Tribute,
        ordinal: 0,
        canonical_records_or_openings: vec![BoundedBytes(encode_tribute_v1(&tribute).unwrap())],
    };
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 8_388_608,
    };
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::SnapshotExporter,
        cas_limits,
    )
    .unwrap();
    let reader = FilesystemCasReader::open(directory.path().join("cas"), cas_limits).unwrap();
    let mut chunk_ref = cas
        .publish_bytes(&chunk.encode_canonical(&limits).unwrap())
        .unwrap();
    chunk_ref.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
    let reference =
        derive_input_chunk_ref(&cas.read_verified(&chunk_ref).unwrap(), &bundle, &limits)
            .unwrap()
            .reference;
    let catalog_root = directory.path().join("staged-input-refs");
    let subject = InputRefCatalogSubjectV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
    };
    {
        let mut publisher =
            InputRefCatalogPublisher::open_or_resume(&catalog_root, subject, limits, list_limits)
                .unwrap();
        assert_eq!(
            publisher.append(&reference).unwrap(),
            InputRefAdmissionOutcome::NewlyAdmitted
        );
    }
    let mut publisher =
        InputRefCatalogPublisher::open_or_resume(&catalog_root, subject, limits, list_limits)
            .unwrap();
    assert_eq!(
        publisher.append(&reference).unwrap(),
        InputRefAdmissionOutcome::ExactReplay
    );
    let prepared = publisher.prepare(&reader, &bundle).unwrap();
    let summary = prepared.summary();
    assert_eq!(summary.input_chunk_count, 1);
    assert_eq!(summary.tribute_count, 1);
    let manifest = InputManifestV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 62,
            finalized_block_hash: hash(63),
            finalized_state_root: hash(64),
            finalized_ce_root: hash(65),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: hash(66),
        sealed_tribute_collection_root: hash(67),
        tribute_count: summary.tribute_count,
        tribute_nominal_total: tribute.nominal_amount_minor,
        input_chunk_count: summary.input_chunk_count,
        input_chunk_list_root: summary.input_chunk_list_root,
        fidelity_opening_root: hash(68),
        oracle_opening_root: hash(69),
        exact_encoded_bytes: summary.exact_encoded_bytes,
        exact_record_count: summary.exact_record_count,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle.opening_codec_registry_hash().unwrap(),
        compression: Compression::None,
    };
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let sealed = prepared.seal(&cas, &manifest_ref, &bundle).unwrap();
    assert_eq!(
        sealed
            .exact_cursor()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![reference]
    );
}

#[test]
fn staged_append_rejects_gaps_kind_regressions_and_latches_conflicts() {
    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(1, 1024, 1024);
    let subject = InputRefCatalogSubjectV1 {
        protocol_bundle_hash: hash(70),
        job_id: hash(71),
        attempt: 0,
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("input-refs");
    let mut publisher =
        InputRefCatalogPublisher::open_or_resume(&root, subject, limits, list_limits).unwrap();
    assert!(matches!(
        publisher.append(&input_ref(InputChunkKind::Tribute, 1, 1, 72)),
        Err(InputRefCatalogError::OrdinalGap {
            expected: 0,
            actual: 1
        })
    ));
    let fidelity = input_ref(InputChunkKind::Fidelity, 0, 1, 73);
    publisher.append(&fidelity).unwrap();
    assert!(matches!(
        publisher.append(&input_ref(InputChunkKind::Tribute, 1, 1, 74)),
        Err(InputRefCatalogError::KindOrder { ordinal: 1 })
    ));
    assert_eq!(
        publisher
            .append(&input_ref(InputChunkKind::Oracle, 1, 1, 75))
            .unwrap(),
        InputRefAdmissionOutcome::NewlyAdmitted
    );
    let mut conflict = fidelity.clone();
    conflict.semantic_digest = hash(76);
    assert!(matches!(
        publisher.append(&conflict),
        Err(InputRefCatalogError::ConflictingReference { ordinal: 0 })
    ));
    drop(publisher);

    let mut reopened =
        InputRefCatalogPublisher::open_or_resume(&root, subject, limits, list_limits).unwrap();
    assert!(matches!(
        reopened.append(&fidelity),
        Err(InputRefCatalogError::Abstained)
    ));
}

#[test]
fn staged_reopen_discards_regular_orphan_temps_but_rejects_symlinks() {
    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(1, 1024, 1024);
    let subject = InputRefCatalogSubjectV1 {
        protocol_bundle_hash: hash(80),
        job_id: hash(81),
        attempt: 0,
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("input-refs");
    drop(InputRefCatalogPublisher::open_or_resume(&root, subject, limits, list_limits).unwrap());
    fs::write(root.join("interrupted.input-ref.tmp"), b"partial").unwrap();
    drop(InputRefCatalogPublisher::open_or_resume(&root, subject, limits, list_limits).unwrap());
    assert!(!root.join("interrupted.input-ref.tmp").exists());

    symlink(root.join("catalog.staging"), root.join("hostile.tmp")).unwrap();
    assert!(matches!(
        InputRefCatalogPublisher::open_or_resume(&root, subject, limits, list_limits),
        Err(InputRefCatalogError::AmbiguousTemporary(_))
    ));
}

#[test]
fn staged_prepare_rejects_missing_and_conflicting_cas_preimages() {
    let fixture = one_chunk_stage_fixture();
    let missing_root = fixture.catalog_root.with_file_name("missing-input-refs");
    let mut missing = InputRefCatalogPublisher::open_or_resume(
        &missing_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    let mut missing_reference = fixture.reference.clone();
    missing_reference.transport_digest = hash(100);
    missing.append(&missing_reference).unwrap();
    assert!(matches!(
        missing.prepare(&fixture.reader, &fixture.bundle),
        Err(InputRefCatalogError::Cas(_))
    ));

    let conflicting_root = fixture
        .catalog_root
        .with_file_name("conflicting-input-refs");
    let mut conflicting = InputRefCatalogPublisher::open_or_resume(
        &conflicting_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    let mut conflicting_reference = fixture.reference.clone();
    conflicting_reference.semantic_digest = hash(101);
    conflicting.append(&conflicting_reference).unwrap();
    assert!(matches!(
        conflicting.prepare(&fixture.reader, &fixture.bundle),
        Err(InputRefCatalogError::Protocol(_))
    ));
}

#[test]
fn manifest_mismatch_does_not_seal_and_exact_seal_replays_but_rebinding_fails() {
    let fixture = one_chunk_stage_fixture();
    let mut publisher = InputRefCatalogPublisher::open_or_resume(
        &fixture.catalog_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    publisher.append(&fixture.reference).unwrap();
    let prepared = publisher.prepare(&fixture.reader, &fixture.bundle).unwrap();
    let summary = prepared.summary();
    let mut wrong = fixture.manifest(summary, 102);
    wrong.input_chunk_list_root = hash(103);
    let wrong_ref = fixture.publish_manifest(&wrong);
    assert!(matches!(
        prepared.seal(&fixture.cas, &wrong_ref, &fixture.bundle),
        Err(InputRefCatalogError::AuthorityMismatch)
    ));

    let mut resumed = InputRefCatalogPublisher::open_or_resume(
        &fixture.catalog_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    assert_eq!(
        resumed.append(&fixture.reference).unwrap(),
        InputRefAdmissionOutcome::ExactReplay
    );
    let prepared = resumed.prepare(&fixture.reader, &fixture.bundle).unwrap();
    let manifest = fixture.manifest(prepared.summary(), 104);
    let manifest_ref = fixture.publish_manifest(&manifest);
    drop(
        prepared
            .seal(&fixture.cas, &manifest_ref, &fixture.bundle)
            .unwrap(),
    );

    let mut replay = InputRefCatalogPublisher::open_or_resume(
        &fixture.catalog_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    assert_eq!(
        replay.append(&fixture.reference).unwrap(),
        InputRefAdmissionOutcome::ExactReplay
    );
    drop(
        replay
            .prepare(&fixture.reader, &fixture.bundle)
            .unwrap()
            .seal(&fixture.cas, &manifest_ref, &fixture.bundle)
            .unwrap(),
    );

    let rebound_manifest = fixture.manifest(summary, 105);
    let rebound_ref = fixture.publish_manifest(&rebound_manifest);
    let mut rebound = InputRefCatalogPublisher::open_or_resume(
        &fixture.catalog_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    rebound.append(&fixture.reference).unwrap();
    assert!(matches!(
        rebound
            .prepare(&fixture.reader, &fixture.bundle)
            .unwrap()
            .seal(&fixture.cas, &rebound_ref, &fixture.bundle),
        Err(InputRefCatalogError::AuthorityMismatch)
    ));

    let wrong_subject = InputRefCatalogSubjectV1 {
        job_id: hash(106),
        ..fixture.subject
    };
    assert!(matches!(
        InputRefCatalogPublisher::open_or_resume(
            &fixture.catalog_root,
            wrong_subject,
            fixture.limits,
            fixture.list_limits,
        ),
        Err(InputRefCatalogError::AuthorityMismatch)
    ));
}

#[test]
fn deleting_prepared_authority_fails_closed_without_format_repair() {
    let fixture = one_chunk_stage_fixture();
    let mut publisher = InputRefCatalogPublisher::open_or_resume(
        &fixture.catalog_root,
        fixture.subject,
        fixture.limits,
        fixture.list_limits,
    )
    .unwrap();
    publisher.append(&fixture.reference).unwrap();
    let prepared = publisher.prepare(&fixture.reader, &fixture.bundle).unwrap();
    let original = fixture.manifest(prepared.summary(), 120);
    let original_ref = fixture.publish_manifest(&original);
    drop(
        prepared
            .seal(&fixture.cas, &original_ref, &fixture.bundle)
            .unwrap(),
    );
    fs::remove_file(fixture.catalog_root.join("catalog.prepared")).unwrap();
    assert!(matches!(
        InputRefCatalogPublisher::open_or_resume(
            &fixture.catalog_root,
            fixture.subject,
            fixture.limits,
            fixture.list_limits,
        ),
        Err(InputRefCatalogError::AuthorityMismatch)
    ));
}

#[test]
fn a_header_first_catalog_is_rejected_by_the_greenfield_staging_protocol() {
    let fixture = one_chunk_stage_fixture();
    let manifest = fixture.manifest(
        outbe_ocomp::input_ref_catalog::InputRefCatalogSummaryV1 {
            input_chunk_count: 1,
            input_chunk_list_root: outbe_ocomp_protocol::ordered_list_root(
                ListKind::InputChunkReferences,
                &[fixture
                    .reference
                    .encode_canonical_record(&fixture.limits)
                    .unwrap()],
                fixture.list_limits,
            )
            .unwrap(),
            exact_encoded_bytes: fixture.reference.encoded_bytes,
            exact_record_count: fixture.reference.record_count,
            tribute_count: fixture.reference.record_count,
        },
        125,
    );
    let manifest_ref = fixture.publish_manifest(&manifest);
    drop(
        VerifiedInputChunkRefCatalog::open(
            &fixture.catalog_root,
            &fixture.cas,
            &manifest_ref,
            fixture.limits,
            fixture.list_limits,
        )
        .unwrap(),
    );

    assert!(matches!(
        InputRefCatalogPublisher::open_or_resume(
            &fixture.catalog_root,
            fixture.subject,
            fixture.limits,
            fixture.list_limits,
        ),
        Err(InputRefCatalogError::AuthorityMismatch)
    ));
}

#[test]
fn staged_catalog_rejects_a_symlinked_ancestor() {
    let fixture = one_chunk_stage_fixture();
    let redirected = fixture.catalog_root.with_file_name("redirected");
    fs::create_dir(&redirected).unwrap();
    let symlinked_parent = fixture.catalog_root.with_file_name("symlinked-parent");
    symlink(&redirected, &symlinked_parent).unwrap();
    let root = symlinked_parent.join("catalog");

    assert!(matches!(
        InputRefCatalogPublisher::open_or_resume(
            &root,
            fixture.subject,
            fixture.limits,
            fixture.list_limits,
        ),
        Err(InputRefCatalogError::UnsafePath(_))
    ));
    assert!(!redirected.join("catalog").exists());
}

#[test]
fn staged_prepare_streams_past_the_old_4096_reference_limit() {
    const CHUNK_COUNT: u32 = 4_097;

    let limits = poc_schema_limits();
    let list_limits = OrderedListLimits::new(1, 4096, 4096);
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = hash(110);
    let day = WorldwideDay::new(20_260_725);
    let owner = Address::repeat_byte(111);
    let tribute = TributeBodyV1 {
        tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
        owner,
        worldwide_day: day,
        issuance_amount_minor: U256::from(1),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(1),
        reference_currency: 978,
        tribute_price_minor: U256::from(1),
        exclude_from_intex_issuance: false,
    };
    let canonical_tribute = encode_tribute_v1(&tribute).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 128 * 1_048_576,
    };
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::SnapshotExporter,
        cas_limits,
    )
    .unwrap();
    let reader = FilesystemCasReader::open(directory.path().join("cas"), cas_limits).unwrap();
    let catalog_root = directory.path().join("input-refs");
    let subject = InputRefCatalogSubjectV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
    };
    let mut publisher =
        InputRefCatalogPublisher::open_or_resume(&catalog_root, subject, limits, list_limits)
            .unwrap();
    for ordinal in 0..CHUNK_COUNT {
        let chunk = AuthenticatedInputChunkV1 {
            protocol_bundle_hash,
            job_id,
            kind: InputChunkKind::Tribute,
            ordinal,
            canonical_records_or_openings: vec![BoundedBytes(canonical_tribute.clone())],
        };
        let mut object_ref = cas
            .publish_bytes(&chunk.encode_canonical(&limits).unwrap())
            .unwrap();
        object_ref.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
        let reference =
            derive_input_chunk_ref(&cas.read_verified(&object_ref).unwrap(), &bundle, &limits)
                .unwrap()
                .reference;
        publisher.append(&reference).unwrap();
    }
    let prepared = publisher.prepare(&reader, &bundle).unwrap();
    let summary = prepared.summary();
    assert_eq!(summary.input_chunk_count, CHUNK_COUNT);
    assert_eq!(summary.tribute_count, CHUNK_COUNT);
    let manifest = InputManifestV1 {
        protocol_bundle_hash,
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 112,
            finalized_block_hash: hash(113),
            finalized_state_root: hash(114),
            finalized_ce_root: hash(115),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: hash(116),
        sealed_tribute_collection_root: hash(117),
        tribute_count: summary.tribute_count,
        tribute_nominal_total: U256::from(CHUNK_COUNT),
        input_chunk_count: summary.input_chunk_count,
        input_chunk_list_root: summary.input_chunk_list_root,
        fidelity_opening_root: hash(118),
        oracle_opening_root: hash(119),
        exact_encoded_bytes: summary.exact_encoded_bytes,
        exact_record_count: summary.exact_record_count,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle.opening_codec_registry_hash().unwrap(),
        compression: Compression::None,
    };
    let mut manifest_ref = cas
        .publish_bytes(&manifest.encode_canonical(&limits).unwrap())
        .unwrap();
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let sealed = prepared.seal(&cas, &manifest_ref, &bundle).unwrap();
    assert_eq!(
        sealed.exact_cursor().unwrap().len(),
        usize::try_from(CHUNK_COUNT).unwrap()
    );
}
