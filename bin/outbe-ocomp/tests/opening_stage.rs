mod support;

use std::fs;

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_compressed_entities::{
    body_commitment, derive_poseidon_entity_id, encode_tribute_v1,
    tribute_partition_root_from_leaves, TributeBodyV1, TributePartitionWorkConfig,
    ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_ocomp::{
    cas::{CasLimits, CasWriterRole, FilesystemCas, FilesystemCasReader},
    control::poc_schema_limits,
    input_artifacts::{
        poc_input_list_limits, DurableInputArtifactPublisher, InputArtifactIdentity,
    },
    input_inventory::{
        TributeInventoryBuilder, TributeInventoryRecordV1, TributeInventorySubjectV1,
        TributeInventoryWorkConfig,
    },
    input_ref_catalog::VerifiedInputChunkRefCatalog,
    opening_stage::{
        DurableOpeningStage, OpeningResolutionV1, OpeningStageError, OpeningStageSubjectV1,
    },
};
use outbe_ocomp_protocol::{
    common::{BoundedBytes, ProofBytes},
    input::{
        materialize_authenticated_openings, AuthenticatedOpeningV1, CheckpointIdentityV1,
        InputChunkKind,
    },
    opening::{LysisOpeningsProofV1, RawContractOpeningProofV1, RawStorageSlotV1},
};
use outbe_primitives::time::WorldwideDay;

fn checkpoint() -> CheckpointIdentityV1 {
    CheckpointIdentityV1 {
        finalized_block_number: 100,
        finalized_block_hash: B256::repeat_byte(4),
        finalized_state_root: B256::repeat_byte(5),
        finalized_ce_root: B256::repeat_byte(10),
        ce_schema_version: 1,
    }
}

fn count_marker(magic: &[u8; 8], value: u32) -> Vec<u8> {
    let body = value.to_be_bytes();
    let mut encoded = Vec::with_capacity(44);
    encoded.extend_from_slice(magic);
    encoded.extend_from_slice(keccak256(body).as_slice());
    encoded.extend_from_slice(&body);
    encoded
}

fn inventory(
    directory: &tempfile::TempDir,
) -> (
    outbe_ocomp::input_inventory::SealedTributeInventory,
    WorldwideDay,
) {
    let day = WorldwideDay::new(20_260_901);
    let mut records = (0..257_u32)
        .map(|index| {
            let mut owner = [0_u8; 20];
            owner[16..].copy_from_slice(&(index + 1).to_be_bytes());
            let owner = Address::from(owner);
            let tribute_id = derive_poseidon_entity_id(owner, day).unwrap();
            let body = TributeBodyV1 {
                tribute_id,
                owner,
                worldwide_day: day,
                issuance_amount_minor: U256::from(1),
                issuance_currency: 840,
                nominal_amount_minor: U256::from(1),
                reference_currency: 978,
                tribute_price_minor: U256::from(1),
                exclude_from_intex_issuance: false,
            };
            let canonical_body = encode_tribute_v1(&body).unwrap();
            let commitment = body_commitment(
                ACTIVE_COMMITMENT_SCHEME,
                BODY_SCHEMA_V1,
                tribute_id,
                &canonical_body,
            )
            .unwrap();
            TributeInventoryRecordV1 {
                tribute_id,
                commitment,
                owner,
                reference_iso: 978,
                nominal_amount_minor: U256::from(1),
                canonical_body,
            }
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| record.tribute_id);
    let root = tribute_partition_root_from_leaves(
        day,
        records
            .iter()
            .map(|record| (record.tribute_id, record.commitment)),
    )
    .unwrap();
    let mut builder = TributeInventoryBuilder::create(
        directory.path().join("inventory"),
        TributeInventorySubjectV1 {
            protocol_bundle_hash: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 0,
            checkpoint: checkpoint(),
            worldwide_day: day,
            sealed_tribute_collection_root: root,
            expected_tribute_count: 257,
            expected_nominal_total: U256::from(257),
        },
        TributeInventoryWorkConfig {
            owners_per_run: 17,
            merge_fan_in: 3,
            root_verifier: TributePartitionWorkConfig {
                records_per_run: 19,
                merge_fan_in: 2,
            },
        },
    )
    .unwrap();
    for record in records {
        builder.push(record).unwrap();
    }
    (builder.finish().unwrap(), day)
}

fn opening_resolution(
    subjects: &outbe_ocomp_protocol::opening::OpeningSubjectsV1,
    day: WorldwideDay,
) -> OpeningResolutionV1 {
    opening_resolution_with_oracle_value(subjects, day, U256::from(1))
}

fn opening_resolution_with_oracle_value(
    subjects: &outbe_ocomp_protocol::opening::OpeningSubjectsV1,
    day: WorldwideDay,
    oracle_value: U256,
) -> OpeningResolutionV1 {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let raw = |address: Address, byte: u8, value: U256| RawContractOpeningProofV1 {
        contract_address: address,
        state_root: B256::repeat_byte(5),
        ordered_slots: vec![RawStorageSlotV1 {
            slot: B256::repeat_byte(byte),
            value,
        }],
        account_proof: ProofBytes(vec![0xa1]),
        storage_proof: ProofBytes(vec![0xb1]),
    };
    let materialized = materialize_authenticated_openings(
        &LysisOpeningsProofV1 {
            protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
            job_id: B256::repeat_byte(2),
            finalized_block_hash: B256::repeat_byte(4),
            finalized_state_root: B256::repeat_byte(5),
            wwd: day.value(),
            subjects: subjects.clone(),
            fidelity: raw(Address::repeat_byte(6), 7, U256::from(1)),
            oracle: raw(Address::repeat_byte(8), 9, oracle_value),
        },
        &bundle,
        &limits,
    )
    .unwrap();
    OpeningResolutionV1::Complete(Box::new(
        outbe_ocomp_protocol::input::MaterializedOpeningsV1 {
            fidelity: materialized.fidelity,
            oracle: materialized.oracle,
        },
    ))
}

#[test]
fn split_tree_and_completed_openings_replay_identically_after_restart() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let directory = tempfile::tempdir().unwrap();
    let (inventory, day) = inventory(&directory);
    let subject = OpeningStageSubjectV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day.value(),
        inventory_authority_digest: inventory.authority_digest(),
    };
    let root = directory.path().join("opening-stage");
    let mut stage = DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    let mut published = Vec::new();
    let report = stage
        .run(
            &inventory,
            |subjects| {
                if subjects.owners.len() > 64 {
                    Ok(OpeningResolutionV1::Split)
                } else {
                    Ok(opening_resolution(subjects, day))
                }
            },
            |_, _, _| Ok(()),
            |opening| {
                published.push(opening.canonical_subject_key.0.clone());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.fidelity_opening_count, 5);
    assert_eq!(published.len(), 5);
    let first_publication = published.clone();
    let mut cursor = stage.fidelity_cursor(report.fidelity_opening_count);
    for expected in &first_publication {
        assert_eq!(
            cursor
                .next_opening()
                .unwrap()
                .unwrap()
                .canonical_subject_key
                .0,
            *expected
        );
    }
    assert!(cursor.next_opening().unwrap().is_none());
    drop(stage);

    let mut rejected = DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    let mut rejected_resolver_calls = 0;
    let mut rejected_publication_calls = 0;
    let replay_error = rejected.run(
        &inventory,
        |subjects| {
            rejected_resolver_calls += 1;
            Ok(opening_resolution(subjects, day))
        },
        |_, _, _| Err(OpeningStageError::Verification("injected".into())),
        |_| {
            rejected_publication_calls += 1;
            Ok(())
        },
    );
    assert!(matches!(
        replay_error,
        Err(OpeningStageError::Verification(_))
    ));
    assert_eq!(rejected_resolver_calls, 0);
    assert_eq!(rejected_publication_calls, 0);
    drop(rejected);

    let mut restarted =
        DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    let mut resolver_calls = 0;
    let mut verifier_calls = 0;
    let mut replayed = Vec::new();
    let replay = restarted
        .run(
            &inventory,
            |subjects| {
                resolver_calls += 1;
                Ok(opening_resolution(subjects, day))
            },
            |_, _, _| {
                verifier_calls += 1;
                Ok(())
            },
            |opening| {
                replayed.push(opening.canonical_subject_key.0.clone());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(resolver_calls, 0);
    assert_eq!(verifier_calls, 5);
    assert_eq!(replay.fidelity_opening_count, 5);
    assert_eq!(replayed, first_publication);
}

#[test]
fn opening_stage_rejects_a_substituted_finalized_checkpoint() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let directory = tempfile::tempdir().unwrap();
    let (inventory, day) = inventory(&directory);
    let subject = OpeningStageSubjectV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day.value(),
        inventory_authority_digest: inventory.authority_digest(),
    };
    let root = directory.path().join("opening-stage");
    drop(DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap());

    let mut substituted = subject;
    substituted.checkpoint.finalized_state_root = B256::repeat_byte(11);
    assert!(DurableOpeningStage::open_or_resume(&root, substituted, limits).is_err());
}

#[test]
fn contradictory_done_and_split_markers_fail_before_replay_side_effects() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let directory = tempfile::tempdir().unwrap();
    let (inventory, day) = inventory(&directory);
    let subject = OpeningStageSubjectV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day.value(),
        inventory_authority_digest: inventory.authority_digest(),
    };
    let root = directory.path().join("opening-stage");
    let mut stage = DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    stage
        .run(
            &inventory,
            |subjects| {
                if subjects.owners.len() > 64 {
                    Ok(OpeningResolutionV1::Split)
                } else {
                    Ok(opening_resolution(subjects, day))
                }
            },
            |_, _, _| Ok(()),
            |_| Ok(()),
        )
        .unwrap();
    drop(stage);
    fs::write(
        root.join("tasks/00000000000000000000-0000000256.done"),
        count_marker(b"OUTBODN1", 0),
    )
    .unwrap();

    let mut restarted = DurableOpeningStage::open_or_resume(&root, subject, limits).unwrap();
    let mut resolver_calls = 0;
    let mut verifier_calls = 0;
    let mut publication_calls = 0;
    assert!(matches!(
        restarted.run(
            &inventory,
            |_| {
                resolver_calls += 1;
                Ok(OpeningResolutionV1::Split)
            },
            |_, _, _| {
                verifier_calls += 1;
                Ok(())
            },
            |_| {
                publication_calls += 1;
                Ok(())
            },
        ),
        Err(OpeningStageError::Authority(_))
    ));
    assert_eq!(resolver_calls, 0);
    assert_eq!(verifier_calls, 0);
    assert_eq!(publication_calls, 0);
}

#[test]
fn durable_publication_failure_replays_the_persisted_opening_without_rpc() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let directory = tempfile::tempdir().unwrap();
    let (inventory, day) = inventory(&directory);
    let subject = OpeningStageSubjectV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day.value(),
        inventory_authority_digest: inventory.authority_digest(),
    };
    let cas_limits = CasLimits {
        max_object_bytes: 1_048_576,
        max_total_bytes: 16 * 1_048_576,
    };
    let cas_root = directory.path().join("cas");
    let catalog_root = directory.path().join("input-refs");
    let cas = FilesystemCas::open(&cas_root, CasWriterRole::SnapshotExporter, cas_limits).unwrap();
    let reader = FilesystemCasReader::open(&cas_root, cas_limits).unwrap();
    let identity = InputArtifactIdentity {
        job_id: subject.job_id,
        attempt: subject.attempt,
        checkpoint: subject.checkpoint.clone(),
        wwd: subject.worldwide_day,
        sealed_tribute_collection_key: B256::repeat_byte(12),
        sealed_tribute_collection_root: B256::repeat_byte(13),
    };
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
    let mut bodies = inventory.tribute_bodies().unwrap();
    while let Some(body) = bodies.next_body(limits.max_bounded_bytes).unwrap() {
        publisher.publish_tribute(body).unwrap();
    }
    publisher.finish_tributes().unwrap();
    let root = directory.path().join("opening-stage");
    let mut stage = DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    let failed = stage.run(
        &inventory,
        |subjects| Ok(opening_resolution(subjects, day)),
        |_, _, _| Ok(()),
        |opening| {
            publisher.publish_fidelity_opening(opening).unwrap();
            Err(OpeningStageError::Publication("after durable ref".into()))
        },
    );
    assert!(matches!(failed, Err(OpeningStageError::Publication(_))));
    drop(stage);
    drop(publisher);

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
    let mut bodies = inventory.tribute_bodies().unwrap();
    while let Some(body) = bodies.next_body(limits.max_bounded_bytes).unwrap() {
        publisher.publish_tribute(body).unwrap();
    }
    publisher.finish_tributes().unwrap();
    let mut restarted =
        DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    let mut resolver_calls = 0;
    let report = restarted
        .run(
            &inventory,
            |subjects| {
                resolver_calls += 1;
                Ok(opening_resolution(subjects, day))
            },
            |_, _, _| Ok(()),
            |opening| {
                publisher
                    .publish_fidelity_opening(opening)
                    .map_err(Into::into)
            },
        )
        .unwrap();
    assert_eq!(resolver_calls, 1);
    publisher.publish_oracle_opening(report.oracle).unwrap();
    let mut fidelity = restarted.fidelity_cursor(report.fidelity_opening_count);
    publisher
        .finish(257, U256::from(257), report.fidelity_opening_count, || {
            fidelity.next_opening().map_err(|error| {
                outbe_ocomp::input_artifacts::InputArtifactError::OpeningSource(error.to_string())
            })
        })
        .unwrap();
    drop(restarted);
    let catalog = VerifiedInputChunkRefCatalog::reopen(
        &catalog_root,
        &reader,
        limits,
        poc_input_list_limits(),
    )
    .unwrap();
    let fidelity_count = catalog
        .exact_verified_cursor(&reader, &bundle)
        .unwrap()
        .map(|verified| verified.unwrap())
        .filter(|verified| verified.reference.kind == InputChunkKind::Fidelity)
        .count();
    assert_eq!(fidelity_count, 2);
}

#[test]
fn durable_oracle_subject_substitution_fails_before_replay_side_effects() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let directory = tempfile::tempdir().unwrap();
    let (inventory, day) = inventory(&directory);
    let subject = OpeningStageSubjectV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day.value(),
        inventory_authority_digest: inventory.authority_digest(),
    };
    let root = directory.path().join("opening-stage");
    let mut stage = DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    assert!(stage
        .run(
            &inventory,
            |subjects| Ok(opening_resolution(subjects, day)),
            |_, _, _| Ok(()),
            |_| Err(OpeningStageError::Publication("injected".into())),
        )
        .is_err());
    drop(stage);

    let path = root.join("oracle.opening");
    let encoded = fs::read(&path).unwrap();
    let mut oracle =
        AuthenticatedOpeningV1::decode_canonical_record(&encoded[40..], &limits).unwrap();
    oracle.canonical_subject_key = BoundedBytes(vec![0x55]);
    let canonical = oracle.encode_canonical_record(&limits).unwrap();
    let mut substituted = Vec::with_capacity(40 + canonical.len());
    substituted.extend_from_slice(b"OUTBOOR1");
    substituted.extend_from_slice(keccak256(&canonical).as_slice());
    substituted.extend_from_slice(&canonical);
    fs::write(path, substituted).unwrap();

    let mut restarted = DurableOpeningStage::open_or_resume(&root, subject, limits).unwrap();
    let mut resolver_calls = 0;
    let mut verifier_calls = 0;
    let mut publication_calls = 0;
    assert!(restarted
        .run(
            &inventory,
            |subjects| {
                resolver_calls += 1;
                Ok(opening_resolution(subjects, day))
            },
            |_, _, _| {
                verifier_calls += 1;
                Ok(())
            },
            |_| {
                publication_calls += 1;
                Ok(())
            },
        )
        .is_err());
    assert_eq!(resolver_calls, 0);
    assert_eq!(verifier_calls, 0);
    assert_eq!(publication_calls, 0);
}

#[test]
fn oracle_conflict_after_partial_publication_fails_closed() {
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let directory = tempfile::tempdir().unwrap();
    let (inventory, day) = inventory(&directory);
    let subject = OpeningStageSubjectV1 {
        protocol_bundle_hash: bundle.protocol_bundle_hash(&limits).unwrap(),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day.value(),
        inventory_authority_digest: inventory.authority_digest(),
    };
    let root = directory.path().join("opening-stage");
    let mut stage = DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    assert!(stage
        .run(
            &inventory,
            |subjects| Ok(opening_resolution(subjects, day)),
            |_, _, _| Ok(()),
            |_| Err(OpeningStageError::Publication("injected".into())),
        )
        .is_err());
    drop(stage);

    let mut restarted =
        DurableOpeningStage::open_or_resume(&root, subject.clone(), limits).unwrap();
    let conflict = restarted.run(
        &inventory,
        |subjects| {
            Ok(opening_resolution_with_oracle_value(
                subjects,
                day,
                U256::from(2),
            ))
        },
        |_, _, _| Ok(()),
        |_| Ok(()),
    );
    assert!(matches!(conflict, Err(OpeningStageError::Abstained)));
    drop(restarted);

    let mut latched = DurableOpeningStage::open_or_resume(&root, subject, limits).unwrap();
    let mut resolver_calls = 0;
    let mut verifier_calls = 0;
    let mut publication_calls = 0;
    let abstained = latched.run(
        &inventory,
        |subjects| {
            resolver_calls += 1;
            Ok(opening_resolution(subjects, day))
        },
        |_, _, _| {
            verifier_calls += 1;
            Ok(())
        },
        |_| {
            publication_calls += 1;
            Ok(())
        },
    );
    assert!(matches!(abstained, Err(OpeningStageError::Abstained)));
    assert_eq!(resolver_calls, 0);
    assert_eq!(verifier_calls, 0);
    assert_eq!(publication_calls, 0);
}
