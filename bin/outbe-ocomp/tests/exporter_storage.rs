//! Real RocksDB secondary integration for the production current/retained input stream.
mod support;

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::WwdEntityId;
use outbe_ocomp::exporter::{
    AuthenticatedTributeRecord, FinalizedTributeSource, TributeStreamSummary,
};
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas},
    control::poc_schema_limits,
    input_artifacts::{
        poc_input_list_limits, publish_streaming_input_artifact_set, InputArtifactIdentity,
    },
};
use outbe_ocomp_protocol::{
    common::ProofBytes,
    input::{materialize_authenticated_openings, CheckpointIdentityV1},
    opening::{
        partition_lysis_opening_subjects, LysisOpeningsProofV1, RawContractOpeningProofV1,
        RawStorageSlotV1,
    },
};
use outbe_offchain_storage::{
    AtomicWriteBatch, MemoryStorage, StorageConfig, StorageProvider, StorageReaderHandle,
    StorageWriterHandle,
};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{
    RetainedTributePin, RetainedTributeReader, TributeData, TributeRepositoryReader,
    TributeRepositoryWriter,
};

fn pin() -> RetainedTributePin {
    RetainedTributePin {
        input_lease_id: B256::repeat_byte(71),
        worldwide_day: WorldwideDay::new(20260901),
    }
}

fn populate(reader: StorageReaderHandle, writer: StorageWriterHandle) {
    let current = TributeRepositoryReader::new(reader.clone());
    let repository = TributeRepositoryWriter::new(reader.clone(), writer.clone());
    let retained = RetainedTributeReader::new(reader);
    for index in 1..=11_u8 {
        let body = TributeData {
            tribute_id: WwdEntityId::from_day_and_digest(pin().worldwide_day, [index; 32]),
            owner: Address::repeat_byte(index),
            worldwide_day: pin().worldwide_day,
            issuance_amount_minor: U256::from(1000),
            issuance_currency: 840,
            nominal_amount_minor: U256::from(700),
            reference_currency: 840,
            tribute_price_minor: U256::from(2),
            exclude_from_intex_issuance: false,
        };
        repository.put(&body).unwrap();
        if index <= 4 {
            let mut batch = AtomicWriteBatch::new();
            batch.extend(
                retained
                    .plan_retain_current(pin(), body.tribute_id)
                    .unwrap()
                    .operations()
                    .iter()
                    .cloned(),
            );
            if index <= 3 {
                batch.extend(
                    current
                        .projection_session(&[body.tribute_id])
                        .unwrap()
                        .delete(body.tribute_id)
                        .unwrap()
                        .operations()
                        .iter()
                        .cloned(),
                );
            }
            writer.apply_atomic(&batch).unwrap();
        }
    }
}

fn collect(reader: StorageReaderHandle) -> (Vec<AuthenticatedTributeRecord>, TributeStreamSummary) {
    // Odd total page budget and overlapping current/retained entries exercise both pagers.
    let source = FinalizedTributeSource::new(reader, 3).unwrap();
    let mut stream = source
        .reconstruction_stream(pin(), 11, U256::from(7700))
        .unwrap();
    let mut records = Vec::new();
    while let Some(record) = stream.next_record().unwrap() {
        records.push(record);
    }
    assert!(stream.retention_stats().peak_combined_page_records <= 3);
    (records, stream.finish().unwrap())
}

fn rocks_input() -> (Vec<AuthenticatedTributeRecord>, TributeStreamSummary) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("offchain-storage.toml");
    std::fs::write(
        &path,
        "version=1\nbackend='rocksdb'\n[rocksdb]\npath='primary'\nsecondary_path='secondary'\n",
    )
    .unwrap();
    let provider = StorageProvider::new(StorageConfig::load(&path).unwrap()).unwrap();
    {
        let storage = provider.open_writer().unwrap();
        populate(storage.reader.clone(), storage.writer.clone());
    }
    // Node reopens its writer; the exporter independently loads the same TOML.
    let _primary = provider.open_writer().unwrap();
    let exporter = StorageProvider::new(StorageConfig::load(&path).unwrap()).unwrap();
    collect(
        exporter
            .read_source("exporter-v1")
            .unwrap()
            .open_session()
            .unwrap(),
    )
}

// This checks actual CAS bytes, including manifest roots and chunk ordering. Chain
// opening proofs are fixed fixtures: proof validation and result execution belong
// to the separate full-network E2E, not this storage/publisher integration test.
fn artifact_bytes(records: &[AuthenticatedTributeRecord]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let identity = InputArtifactIdentity {
        job_id: B256::repeat_byte(31),
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 100,
            finalized_block_hash: B256::repeat_byte(32),
            finalized_state_root: B256::repeat_byte(33),
            finalized_ce_root: B256::repeat_byte(34),
            ce_schema_version: 1,
        },
        wwd: pin().worldwide_day.value(),
        sealed_tribute_collection_key: B256::repeat_byte(35),
        sealed_tribute_collection_root: B256::repeat_byte(36),
    };
    let owners = records
        .iter()
        .map(|record| record.body.owner)
        .collect::<Vec<_>>();
    let raw = |address, slot| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: identity.checkpoint.finalized_state_root,
        ordered_slots: vec![RawStorageSlotV1 {
            slot: B256::repeat_byte(slot),
            value: U256::from(1),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let mut fidelity = Vec::new();
    let mut oracle = None;
    for subjects in partition_lysis_opening_subjects(&owners, &[840], &limits).unwrap() {
        let openings = materialize_authenticated_openings(
            &LysisOpeningsProofV1 {
                protocol_bundle_hash,
                job_id: identity.job_id,
                finalized_block_hash: identity.checkpoint.finalized_block_hash,
                finalized_state_root: identity.checkpoint.finalized_state_root,
                wwd: identity.wwd,
                subjects,
                fidelity: raw(Address::repeat_byte(37), 38),
                oracle: raw(Address::repeat_byte(39), 40),
            },
            &bundle,
            &limits,
        )
        .unwrap();
        fidelity.push(openings.fidelity);
        oracle = Some(openings.oracle);
    }
    let root = tempfile::tempdir().unwrap();
    let canonical_root = root.path().canonicalize().unwrap();
    let cas = FilesystemCas::open(
        canonical_root.join("cas"),
        CasWriterRole::SnapshotExporter,
        CasLimits {
            max_object_bytes: 1_048_576,
            max_total_bytes: 8 * 1_048_576,
        },
    )
    .unwrap();
    let mut bodies = records.iter().map(|record| record.canonical_body.clone());
    let published = publish_streaming_input_artifact_set(
        &cas,
        canonical_root.join("refs"),
        &bundle,
        identity,
        u32::try_from(records.len()).unwrap(),
        || Ok(bodies.next()),
        fidelity,
        oracle.unwrap(),
        &limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let manifest = cas
        .read_verified(&published.manifest_ref)
        .unwrap()
        .bytes()
        .to_vec();
    let chunks = published
        .ordered_chunk_refs
        .iter()
        .map(|reference| cas.read_verified(reference).unwrap().bytes().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), 3, "Tribute, Fidelity and Oracle chunks");
    (manifest, chunks)
}

#[test]
fn rocksdb_secondary_produces_identical_canonical_inputs_and_artifacts_to_memory() {
    let memory = Arc::new(MemoryStorage::new());
    populate(memory.clone(), memory.clone());
    let expected = collect(memory);
    let rocks = rocks_input();
    assert_eq!(artifact_bytes(&rocks.0), artifact_bytes(&expected.0));
    assert_eq!(rocks, expected);
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI pointing to an isolated test replica"]
fn mongodb_toml_provider_produces_identical_canonical_inputs_and_artifacts_to_rocksdb() {
    use outbe_offchain_storage::{MongoStorageConfig, StorageBackend};
    let uri = std::env::var("OUTBE_TEST_MONGODB_URI").expect("isolated test replica URI");
    let config = StorageConfig {
        start_block: 1,
        backend: StorageBackend::MongoDb(MongoStorageConfig {
            uri,
            database: format!("outbe_exporter_parity_{}", std::process::id()),
        }),
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("offchain-storage.toml");
    std::fs::write(&path, config.to_toml().unwrap()).unwrap();
    let provider = StorageProvider::new(StorageConfig::load(&path).unwrap()).unwrap();
    let storage = provider.open_writer().unwrap();
    populate(storage.reader.clone(), storage.writer.clone());
    let exporter = StorageProvider::new(StorageConfig::load(&path).unwrap()).unwrap();
    let memory = Arc::new(MemoryStorage::new());
    populate(memory.clone(), memory.clone());
    let mongo = collect(
        exporter
            .read_source("exporter-v1")
            .unwrap()
            .open_session()
            .unwrap(),
    );
    let rocks = rocks_input();
    assert_eq!(artifact_bytes(&mongo.0), artifact_bytes(&rocks.0));
    assert_eq!(mongo, rocks);
    assert_eq!(mongo, collect(memory));
}
