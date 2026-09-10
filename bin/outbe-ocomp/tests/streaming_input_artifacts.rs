mod support;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    derive_poseidon_entity_id, encode_tribute_v1, TributeBodyV1, WwdEntityId,
};
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    input_artifacts::{
        poc_input_list_limits, publish_streaming_input_artifact_set,
        streaming_input_chunk_reference_root, validate_verified_input_manifest_semantics,
        DurableInputArtifactPublisher, InputArtifactIdentity,
    },
    input_ref_catalog::VerifiedInputChunkRefCatalog,
};
use outbe_ocomp_protocol::{
    common::{BoundedBytes, ProofBytes},
    input::{
        materialize_authenticated_openings, AuthenticatedInputChunkV1, CheckpointIdentityV1,
        InputChunkKind, InputChunkRefV1, InputManifestV1,
    },
    opening::{
        partition_lysis_opening_subjects, LysisOpeningsProofV1, RawContractOpeningProofV1,
        RawStorageSlotV1,
    },
};
use outbe_primitives::time::WorldwideDay;

#[test]
fn input_reference_commitment_streams_past_the_old_4096_list_limit() {
    let limits = poc_schema_limits();
    for count in [4_096, 4_097] {
        let root = streaming_input_chunk_reference_root(
            count,
            (0..count).map(|ordinal| {
                Ok(InputChunkRefV1 {
                    kind: InputChunkKind::Tribute,
                    ordinal,
                    record_count: 1,
                    first_key: BoundedBytes(ordinal.to_be_bytes().to_vec()),
                    last_key_inclusive: BoundedBytes(ordinal.to_be_bytes().to_vec()),
                    encoded_bytes: 1,
                    semantic_digest: B256::from(U256::from(ordinal + 1)),
                    transport_digest: B256::from(U256::from(ordinal + 10_000)),
                })
            }),
            &limits,
        )
        .unwrap();

        assert!(!root.is_zero());
    }
}

#[test]
fn production_publisher_streams_one_million_records_with_a_256_record_peak() {
    const COUNT: u32 = 1_000_000;
    const RECORDS_PER_CHUNK: u32 = 256;

    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = B256::repeat_byte(0x21);
    let finalized_block_hash = B256::repeat_byte(0x22);
    let finalized_state_root = B256::repeat_byte(0x23);
    let day = WorldwideDay::new(20_260_901);
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 512 * 1_048_576,
    };
    let cas_root = directory.path().join("cas");
    let catalog_root = directory.path().join("input-refs");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::SnapshotExporter, cas_limits).unwrap();
    let reader = FilesystemCasReader::open(&cas_root, cas_limits).unwrap();
    let identity = InputArtifactIdentity {
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 100,
            finalized_block_hash,
            finalized_state_root,
            finalized_ce_root: B256::repeat_byte(0x24),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: B256::repeat_byte(0x25),
        sealed_tribute_collection_root: B256::repeat_byte(0x26),
    };
    let subjects =
        partition_lysis_opening_subjects(&[Address::with_last_byte(1)], &[840, 978], &limits)
            .unwrap()
            .pop()
            .unwrap();
    let raw = |address, slot| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: finalized_state_root,
        ordered_slots: vec![RawStorageSlotV1 {
            slot: B256::repeat_byte(slot),
            value: U256::from(1),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let openings = materialize_authenticated_openings(
        &LysisOpeningsProofV1 {
            protocol_bundle_hash,
            job_id,
            finalized_block_hash,
            finalized_state_root,
            wwd: day.value(),
            subjects,
            fidelity: raw(Address::repeat_byte(0x27), 0x28),
            oracle: raw(Address::repeat_byte(0x29), 0x2a),
        },
        &bundle,
        &limits,
    )
    .unwrap();

    let mut publisher = DurableInputArtifactPublisher::open(
        &cas,
        &reader,
        &catalog_root,
        &bundle,
        identity,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    for index in 0..COUNT {
        let mut digest = [0_u8; 32];
        digest[28..].copy_from_slice(&(index + 1).to_be_bytes());
        publisher
            .publish_tribute(
                encode_tribute_v1(&TributeBodyV1 {
                    tribute_id: WwdEntityId::from_day_and_digest(day, digest),
                    owner: Address::from_word(B256::from(U256::from(index + 1))),
                    worldwide_day: day,
                    issuance_amount_minor: U256::from(1),
                    issuance_currency: 840,
                    nominal_amount_minor: U256::from(1),
                    reference_currency: 978,
                    tribute_price_minor: U256::from(1),
                    exclude_from_intex_issuance: false,
                })
                .unwrap(),
            )
            .unwrap();
    }
    let retention = publisher.retention_stats().unwrap();
    assert_eq!(retention.peak_tribute_records, RECORDS_PER_CHUNK as usize);
    assert_eq!(
        retention.configured_tribute_record_bound,
        RECORDS_PER_CHUNK as usize
    );
    assert!(retention.current_tribute_records < RECORDS_PER_CHUNK as usize);
    publisher.finish_tributes().unwrap();
    publisher
        .publish_fidelity_opening(openings.fidelity.clone())
        .unwrap();
    publisher
        .publish_oracle_opening(openings.oracle.clone())
        .unwrap();
    let mut fidelity = Some(openings.fidelity);
    publisher
        .finish(COUNT, U256::from(COUNT), 1, || Ok(fidelity.take()))
        .unwrap();

    let catalog = VerifiedInputChunkRefCatalog::reopen(
        &catalog_root,
        &reader,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let mut chunk_count = 0_u32;
    let mut tribute_count = 0_u32;
    for item in catalog.exact_verified_cursor(&reader, &bundle).unwrap() {
        let chunk = item.unwrap().chunk;
        chunk_count += 1;
        if chunk.kind == InputChunkKind::Tribute {
            tribute_count += u32::try_from(chunk.canonical_records_or_openings.len()).unwrap();
            assert!(chunk.canonical_records_or_openings.len() <= RECORDS_PER_CHUNK as usize);
        }
    }
    assert_eq!(tribute_count, COUNT);
    assert_eq!(chunk_count, COUNT.div_ceil(RECORDS_PER_CHUNK) + 2);
}

#[test]
fn durable_publisher_matches_existing_chunk_root_catalog_and_manifest_bytes() {
    const COUNT: u32 = 513;
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = B256::repeat_byte(0x31);
    let finalized_block_hash = B256::repeat_byte(0x32);
    let finalized_state_root = B256::repeat_byte(0x33);
    let day = WorldwideDay::new(20_260_901);
    let identity = InputArtifactIdentity {
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 100,
            finalized_block_hash,
            finalized_state_root,
            finalized_ce_root: B256::repeat_byte(0x34),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: B256::repeat_byte(0x35),
        sealed_tribute_collection_root: B256::repeat_byte(0x36),
    };
    let canonical = (0..COUNT)
        .map(|index| {
            let mut digest = [0_u8; 32];
            digest[28..].copy_from_slice(&(index + 1).to_be_bytes());
            encode_tribute_v1(&TributeBodyV1 {
                tribute_id: WwdEntityId::from_day_and_digest(day, digest),
                owner: Address::from_word(B256::from(U256::from(index + 1))),
                worldwide_day: day,
                issuance_amount_minor: U256::from(1),
                issuance_currency: 840,
                nominal_amount_minor: U256::from(1),
                reference_currency: 978,
                tribute_price_minor: U256::from(1),
                exclude_from_intex_issuance: false,
            })
            .unwrap()
        })
        .collect::<Vec<_>>();
    let owners = (0..COUNT)
        .map(|index| Address::from_word(B256::from(U256::from(index + 1))))
        .collect::<Vec<_>>();
    let raw = |address, slot| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: finalized_state_root,
        ordered_slots: vec![RawStorageSlotV1 {
            slot: B256::repeat_byte(slot),
            value: U256::from(1),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let mut fidelity_openings = Vec::new();
    let mut oracle_opening = None;
    for subjects in partition_lysis_opening_subjects(&owners, &[840, 978], &limits).unwrap() {
        let materialized = materialize_authenticated_openings(
            &LysisOpeningsProofV1 {
                protocol_bundle_hash,
                job_id,
                finalized_block_hash,
                finalized_state_root,
                wwd: day.value(),
                subjects,
                fidelity: raw(Address::repeat_byte(0x37), 0x38),
                oracle: raw(Address::repeat_byte(0x39), 0x3a),
            },
            &bundle,
            &limits,
        )
        .unwrap();
        fidelity_openings.push(materialized.fidelity);
        match &oracle_opening {
            None => oracle_opening = Some(materialized.oracle),
            Some(existing) => assert_eq!(existing, &materialized.oracle),
        }
    }
    let oracle_opening = oracle_opening.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 16 * 1_048_576,
    };

    let baseline_cas_root = directory.path().join("baseline-cas");
    let baseline_catalog_root = directory.path().join("baseline-refs");
    let baseline_cas = FilesystemCas::open(
        &baseline_cas_root,
        CasWriterRole::SnapshotExporter,
        cas_limits,
    )
    .unwrap();
    let mut baseline_bodies = canonical.clone().into_iter();
    let baseline = publish_streaming_input_artifact_set(
        &baseline_cas,
        &baseline_catalog_root,
        &bundle,
        identity.clone(),
        COUNT,
        || Ok(baseline_bodies.next()),
        fidelity_openings.clone(),
        oracle_opening.clone(),
        &limits,
        poc_input_list_limits(),
    )
    .unwrap();

    let durable_cas_root = directory.path().join("durable-cas");
    let durable_catalog_root = directory.path().join("durable-refs");
    let durable_cas = FilesystemCas::open(
        &durable_cas_root,
        CasWriterRole::SnapshotExporter,
        cas_limits,
    )
    .unwrap();
    let durable_reader = FilesystemCasReader::open(&durable_cas_root, cas_limits).unwrap();
    let mut durable = DurableInputArtifactPublisher::open(
        &durable_cas,
        &durable_reader,
        &durable_catalog_root,
        &bundle,
        identity,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    for body in canonical {
        durable.publish_tribute(body).unwrap();
    }
    durable.finish_tributes().unwrap();
    for opening in fidelity_openings.iter().cloned() {
        durable.publish_fidelity_opening(opening).unwrap();
    }
    durable.publish_oracle_opening(oracle_opening).unwrap();
    let expected_fidelity_count = u32::try_from(fidelity_openings.len()).unwrap();
    let mut fidelity = fidelity_openings.into_iter();
    let durable = durable
        .finish(COUNT, U256::from(COUNT), expected_fidelity_count, || {
            Ok(fidelity.next())
        })
        .unwrap();

    assert_eq!(durable.manifest_hash, baseline.manifest_hash);
    assert_eq!(durable.manifest_ref, baseline.manifest_ref);
    assert_eq!(durable.tribute_count, baseline.tribute_count);
    assert_eq!(
        durable.tribute_nominal_total,
        baseline.tribute_nominal_total
    );
    assert_eq!(
        durable_cas
            .read_verified(&durable.manifest_ref)
            .unwrap()
            .bytes(),
        baseline_cas
            .read_verified(&baseline.manifest_ref)
            .unwrap()
            .bytes(),
    );

    let baseline_reader = FilesystemCasReader::open(&baseline_cas_root, cas_limits).unwrap();
    let baseline_catalog = VerifiedInputChunkRefCatalog::reopen(
        &baseline_catalog_root,
        &baseline_reader,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let durable_catalog = VerifiedInputChunkRefCatalog::reopen(
        &durable_catalog_root,
        &durable_reader,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let baseline_chunks = baseline_catalog
        .exact_verified_cursor(&baseline_reader, &bundle)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let durable_chunks = durable_catalog
        .exact_verified_cursor(&durable_reader, &bundle)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(durable_chunks, baseline_chunks);

    let manifest = InputManifestV1::decode_canonical(
        durable_cas
            .read_verified(&durable.manifest_ref)
            .unwrap()
            .bytes(),
        &limits,
    )
    .unwrap();
    validate_verified_input_manifest_semantics(
        &durable_catalog,
        &durable_reader,
        &bundle,
        &manifest,
        &limits,
    )
    .unwrap();
    for substituted in [
        {
            let mut substituted = manifest.clone();
            substituted.fidelity_opening_root = B256::repeat_byte(0x3b);
            substituted
        },
        {
            let mut substituted = manifest.clone();
            substituted.oracle_opening_root = B256::repeat_byte(0x3c);
            substituted
        },
    ] {
        assert!(validate_verified_input_manifest_semantics(
            &durable_catalog,
            &durable_reader,
            &bundle,
            &substituted,
            &limits,
        )
        .is_err());
    }
}

#[test]
fn durable_publisher_replays_10000_tributes_without_population_sized_results() {
    const COUNT: u32 = 10_000;
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = B256::repeat_byte(0x41);
    let finalized_block_hash = B256::repeat_byte(0x42);
    let finalized_state_root = B256::repeat_byte(0x43);
    let day = WorldwideDay::new(20_260_901);
    let directory = tempfile::tempdir().unwrap();
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 64 * 1_048_576,
    };
    let cas_root = directory.path().join("cas");
    let catalog_root = directory.path().join("input-refs");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::SnapshotExporter, cas_limits).unwrap();
    let reader = FilesystemCasReader::open(&cas_root, cas_limits).unwrap();
    let identity = InputArtifactIdentity {
        job_id,
        attempt: 0,
        checkpoint: CheckpointIdentityV1 {
            finalized_block_number: 100,
            finalized_block_hash,
            finalized_state_root,
            finalized_ce_root: B256::repeat_byte(0x44),
            ce_schema_version: 1,
        },
        wwd: day.value(),
        sealed_tribute_collection_key: B256::repeat_byte(0x45),
        sealed_tribute_collection_root: B256::repeat_byte(0x46),
    };
    let subjects =
        partition_lysis_opening_subjects(&[Address::with_last_byte(1)], &[840, 978], &limits)
            .unwrap()
            .pop()
            .unwrap();
    let raw = |address, slot| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: finalized_state_root,
        ordered_slots: vec![RawStorageSlotV1 {
            slot: B256::repeat_byte(slot),
            value: U256::from(1),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let openings = materialize_authenticated_openings(
        &LysisOpeningsProofV1 {
            protocol_bundle_hash,
            job_id,
            finalized_block_hash,
            finalized_state_root,
            wwd: day.value(),
            subjects,
            fidelity: raw(Address::repeat_byte(0x47), 0x48),
            oracle: raw(Address::repeat_byte(0x49), 0x4a),
        },
        &bundle,
        &limits,
    )
    .unwrap();

    let publish = || {
        let mut publisher = DurableInputArtifactPublisher::open(
            &cas,
            &reader,
            &catalog_root,
            &bundle,
            identity.clone(),
            limits,
            poc_input_list_limits(),
        )
        .unwrap();
        for index in 0..COUNT {
            let owner = Address::from_word(B256::from(U256::from(index + 1)));
            let mut digest = [0_u8; 32];
            digest[28..].copy_from_slice(&(index + 1).to_be_bytes());
            publisher
                .publish_tribute(
                    encode_tribute_v1(&TributeBodyV1 {
                        tribute_id: WwdEntityId::from_day_and_digest(day, digest),
                        owner,
                        worldwide_day: day,
                        issuance_amount_minor: U256::from(1),
                        issuance_currency: 840,
                        nominal_amount_minor: U256::from(1),
                        reference_currency: 978,
                        tribute_price_minor: U256::from(1),
                        exclude_from_intex_issuance: false,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        let retention = publisher.retention_stats().unwrap();
        assert_eq!(retention.peak_tribute_records, 256);
        assert_eq!(retention.configured_tribute_record_bound, 256);
        assert!(retention.current_tribute_records < 256);
        publisher.finish_tributes().unwrap();
        publisher
            .publish_fidelity_opening(openings.fidelity.clone())
            .unwrap();
        publisher
            .publish_oracle_opening(openings.oracle.clone())
            .unwrap();
        let mut fidelity = Some(openings.fidelity.clone());
        publisher
            .finish(COUNT, U256::from(COUNT), 1, || Ok(fidelity.take()))
            .unwrap()
    };

    let first = publish();
    let replay = publish();
    assert_eq!(first, replay);
    let catalog = VerifiedInputChunkRefCatalog::reopen(
        &catalog_root,
        &reader,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let chunks = catalog
        .exact_verified_cursor(&reader, &bundle)
        .unwrap()
        .map(|item| item.unwrap().chunk)
        .collect::<Vec<_>>();
    let tribute_chunks = chunks
        .iter()
        .filter(|chunk| chunk.kind == InputChunkKind::Tribute)
        .collect::<Vec<_>>();
    assert_eq!(tribute_chunks.len(), 40);
    assert!(tribute_chunks[..39]
        .iter()
        .all(|chunk| chunk.canonical_records_or_openings.len() == 256));
    assert_eq!(tribute_chunks[39].canonical_records_or_openings.len(), 16);
}

#[test]
fn population_above_the_old_4096_ceiling_streams_into_existing_256_record_chunks() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let job_id = B256::repeat_byte(0x71);
    let finalized_block_hash = B256::repeat_byte(0x72);
    let finalized_state_root = B256::repeat_byte(0x73);
    let day = WorldwideDay::new(20_260_901);

    let mut tributes = (0..4_097_u32)
        .map(|index| {
            let mut owner_bytes = [0_u8; 20];
            owner_bytes[16..].copy_from_slice(&(index + 1).to_be_bytes());
            let owner = Address::from(owner_bytes);
            TributeBodyV1 {
                tribute_id: derive_poseidon_entity_id(owner, day).unwrap(),
                owner,
                worldwide_day: day,
                issuance_amount_minor: U256::from(1),
                issuance_currency: 840,
                nominal_amount_minor: U256::from(1),
                reference_currency: 978,
                tribute_price_minor: U256::from(1),
                exclude_from_intex_issuance: false,
            }
        })
        .collect::<Vec<_>>();
    tributes.sort_by_key(|tribute| tribute.tribute_id);
    let owners = tributes
        .iter()
        .map(|tribute| tribute.owner)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let raw_opening = |address, slot_byte| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: finalized_state_root,
        ordered_slots: vec![RawStorageSlotV1 {
            slot: B256::repeat_byte(slot_byte),
            value: U256::from(1),
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let mut fidelity_openings = Vec::new();
    let mut oracle_opening = None;
    for subjects in partition_lysis_opening_subjects(&owners, &[840, 978], &limits).unwrap() {
        let materialized = materialize_authenticated_openings(
            &LysisOpeningsProofV1 {
                protocol_bundle_hash,
                job_id,
                finalized_block_hash,
                finalized_state_root,
                wwd: day.value(),
                subjects,
                fidelity: raw_opening(Address::repeat_byte(0x74), 0x75),
                oracle: raw_opening(Address::repeat_byte(0x76), 0x77),
            },
            &bundle,
            &limits,
        )
        .unwrap();
        fidelity_openings.push(materialized.fidelity);
        match &oracle_opening {
            None => oracle_opening = Some(materialized.oracle),
            Some(existing) => assert_eq!(existing, &materialized.oracle),
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let cas = FilesystemCas::open(
        directory.path().join("cas"),
        CasWriterRole::SnapshotExporter,
        CasLimits {
            max_object_bytes: 1_048_576,
            max_total_bytes: 64 * 1_048_576,
        },
    )
    .unwrap();
    let mut canonical = tributes
        .iter()
        .map(|tribute| encode_tribute_v1(tribute).unwrap());
    let published = publish_streaming_input_artifact_set(
        &cas,
        directory.path().join("input-refs"),
        &bundle,
        InputArtifactIdentity {
            job_id,
            attempt: 0,
            checkpoint: CheckpointIdentityV1 {
                finalized_block_number: 100,
                finalized_block_hash,
                finalized_state_root,
                finalized_ce_root: B256::repeat_byte(0x78),
                ce_schema_version: 1,
            },
            wwd: day.value(),
            sealed_tribute_collection_key: B256::repeat_byte(0x79),
            sealed_tribute_collection_root: B256::repeat_byte(0x7a),
        },
        4_097,
        || Ok(canonical.next()),
        fidelity_openings,
        oracle_opening.unwrap(),
        &limits,
        poc_input_list_limits(),
    )
    .unwrap();

    assert_eq!(published.tribute_count, 4_097);
    let tribute_chunks = published
        .ordered_chunk_refs
        .iter()
        .map(|reference| {
            AuthenticatedInputChunkV1::decode_canonical(
                cas.read_verified(reference).unwrap().bytes(),
                &limits,
            )
            .unwrap()
        })
        .filter(|chunk| chunk.kind == InputChunkKind::Tribute)
        .collect::<Vec<_>>();
    assert_eq!(tribute_chunks.len(), 17);
    assert!(tribute_chunks[..16]
        .iter()
        .all(|chunk| chunk.canonical_records_or_openings.len() == 256));
    assert_eq!(tribute_chunks[16].canonical_records_or_openings.len(), 1);
}
