use std::fs;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    body_commitment, derive_poseidon_entity_id, encode_tribute_v1,
    tribute_partition_root_from_leaves, TributeBodyV1, TributePartitionWorkConfig,
    ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_ocomp::input_inventory::{
    SealedTributeInventory, TributeInventoryBuilder, TributeInventoryRecordV1,
    TributeInventorySubjectV1, TributeInventoryWorkConfig,
};
use outbe_ocomp_protocol::input::CheckpointIdentityV1;
use outbe_primitives::time::WorldwideDay;

fn checkpoint() -> CheckpointIdentityV1 {
    CheckpointIdentityV1 {
        finalized_block_number: 100,
        finalized_block_hash: B256::repeat_byte(3),
        finalized_state_root: B256::repeat_byte(4),
        finalized_ce_root: B256::repeat_byte(5),
        ce_schema_version: 1,
    }
}

fn fixture_records(count: u32) -> (WorldwideDay, Vec<TributeInventoryRecordV1>, B256) {
    let day = WorldwideDay::new(20_260_901);
    let mut records = (0..count)
        .map(|index| {
            let owner_index = index + 1;
            let mut owner = [0_u8; 20];
            owner[16..].copy_from_slice(&owner_index.to_be_bytes());
            let owner = Address::from(owner);
            let tribute_id = derive_poseidon_entity_id(owner, day).unwrap();
            let body = TributeBodyV1 {
                tribute_id,
                owner,
                worldwide_day: day,
                issuance_amount_minor: U256::from(index + 1),
                issuance_currency: 840,
                nominal_amount_minor: U256::from(1),
                reference_currency: if index % 2 == 0 { 978 } else { 840 },
                tribute_price_minor: U256::from(index + 2),
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
                reference_iso: body.reference_currency,
                nominal_amount_minor: body.nominal_amount_minor,
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
    (day, records, root)
}

fn subject(day: WorldwideDay, count: u32, root: B256) -> TributeInventorySubjectV1 {
    TributeInventorySubjectV1 {
        protocol_bundle_hash: B256::repeat_byte(1),
        job_id: B256::repeat_byte(2),
        attempt: 0,
        checkpoint: checkpoint(),
        worldwide_day: day,
        sealed_tribute_collection_root: root,
        expected_tribute_count: count,
        expected_nominal_total: U256::from(count),
    }
}

fn tiny_work() -> TributeInventoryWorkConfig {
    TributeInventoryWorkConfig {
        owners_per_run: 17,
        merge_fan_in: 3,
        root_verifier: TributePartitionWorkConfig {
            records_per_run: 19,
            merge_fan_in: 2,
        },
    }
}

#[test]
fn inventory_streams_4097_bodies_and_disk_sorts_unique_owners() {
    const COUNT: u32 = 4_097;
    let (day, records, root) = fixture_records(COUNT);
    let directory = tempfile::tempdir().unwrap();
    let inventory_root = directory.path().join("inventory");
    let authority = subject(day, COUNT, root);
    let mut builder =
        TributeInventoryBuilder::create(&inventory_root, authority.clone(), tiny_work()).unwrap();
    for record in records.iter().cloned() {
        builder.push(record).unwrap();
    }
    let retention = builder.retention_stats();
    assert_eq!(retention.peak_owner_records, 17);
    assert_eq!(retention.configured_owner_record_bound, 17);
    assert_eq!(retention.root_verifier.peak_buffered_records, 19);
    assert_eq!(retention.root_verifier.configured_record_bound, 19);
    let inventory = builder.finish().unwrap();

    assert_eq!(inventory.unique_owner_count(), 4_097);
    assert_eq!(inventory.reference_isos(), vec![840, 978]);
    let mut owners = inventory.owner_batches().unwrap();
    let mut observed_owners = Vec::new();
    while let Some(batch) = owners.next_batch(256).unwrap() {
        assert!(batch.len() <= 256);
        observed_owners.extend(batch);
    }
    assert_eq!(observed_owners.len(), 4_097);
    assert!(observed_owners.windows(2).all(|pair| pair[0] < pair[1]));

    let mut bodies = inventory.tribute_bodies().unwrap();
    for expected in &records {
        assert_eq!(
            bodies.next_body(1_048_576).unwrap().as_deref(),
            Some(expected.canonical_body.as_slice())
        );
    }
    assert!(bodies.next_body(1_048_576).unwrap().is_none());
    drop(inventory);

    let reopened = SealedTributeInventory::open(&inventory_root, authority).unwrap();
    assert_eq!(reopened.unique_owner_count(), 4_097);
}

#[test]
fn incomplete_inventory_is_rebuilt_without_accepting_partial_authority() {
    let (day, records, root) = fixture_records(257);
    let directory = tempfile::tempdir().unwrap();
    let inventory_root = directory.path().join("inventory");
    let authority = subject(day, 257, root);
    let mut interrupted =
        TributeInventoryBuilder::create(&inventory_root, authority.clone(), tiny_work()).unwrap();
    for record in records.iter().take(100).cloned() {
        interrupted.push(record).unwrap();
    }
    drop(interrupted);

    let mut rebuilt =
        TributeInventoryBuilder::create(&inventory_root, authority, tiny_work()).unwrap();
    for record in records {
        rebuilt.push(record).unwrap();
    }
    assert_eq!(rebuilt.finish().unwrap().unique_owner_count(), 257);
}

#[test]
fn inventory_rejects_body_field_substitution_and_source_reordering() {
    let (day, records, root) = fixture_records(2);
    let directory = tempfile::tempdir().unwrap();
    let authority = subject(day, 2, root);
    let mut substituted = TributeInventoryBuilder::create(
        directory.path().join("substituted"),
        authority.clone(),
        tiny_work(),
    )
    .unwrap();
    let mut wrong = records[0].clone();
    wrong.owner = Address::repeat_byte(9);
    assert!(substituted.push(wrong).is_err());

    let mut mismatched_commitment = TributeInventoryBuilder::create(
        directory.path().join("mismatched-commitment"),
        authority.clone(),
        tiny_work(),
    )
    .unwrap();
    let mut wrong_body = records[0].clone();
    let mut decoded =
        outbe_compressed_entities::decode_tribute_v1(&wrong_body.canonical_body).unwrap();
    decoded.tribute_price_minor += U256::from(1);
    wrong_body.canonical_body = encode_tribute_v1(&decoded).unwrap();
    assert!(mismatched_commitment.push(wrong_body).is_err());

    let mut reordered = TributeInventoryBuilder::create(
        directory.path().join("reordered"),
        authority.clone(),
        tiny_work(),
    )
    .unwrap();
    reordered.push(records[1].clone()).unwrap();
    assert!(reordered.push(records[0].clone()).is_err());
}

#[test]
fn sealed_inventory_rejects_a_substituted_finalized_checkpoint() {
    let (day, records, root) = fixture_records(17);
    let directory = tempfile::tempdir().unwrap();
    let inventory_root = directory.path().join("inventory");
    let authority = subject(day, 17, root);
    let mut builder =
        TributeInventoryBuilder::create(&inventory_root, authority.clone(), tiny_work()).unwrap();
    for record in records {
        builder.push(record).unwrap();
    }
    drop(builder.finish().unwrap());

    let mut substituted = authority.clone();
    substituted.checkpoint.finalized_block_number += 1;
    assert!(SealedTributeInventory::open(&inventory_root, substituted).is_err());
}

#[test]
fn sealed_inventory_detects_body_spool_corruption() {
    let (day, records, root) = fixture_records(17);
    let directory = tempfile::tempdir().unwrap();
    let inventory_root = directory.path().join("inventory");
    let authority = subject(day, 17, root);
    let mut builder =
        TributeInventoryBuilder::create(&inventory_root, authority.clone(), tiny_work()).unwrap();
    for record in records {
        builder.push(record).unwrap();
    }
    drop(builder.finish().unwrap());
    let spool = inventory_root.join("tributes.spool");
    let mut bytes = fs::read(&spool).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(spool, bytes).unwrap();
    assert!(SealedTributeInventory::open(&inventory_root, authority).is_err());
}
