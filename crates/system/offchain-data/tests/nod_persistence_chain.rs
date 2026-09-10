//! Exercise production NOD mutations, emitted receipts, CE sealing and RocksDB projection.
//! Only the EVM storage host and finalized receipt/header envelopes are test fixtures.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    begin_block, derive_poseidon_entity_id, encode_nod_item_v1, end_block, CeMdbx, CeWorkConfig,
    EntityRef, EnvironmentIdentity, ExactParentIdentity, ExecutionScope, FinalizedMarker,
    MdbxAuthenticatedTree, WwdEntityId, ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
};
use outbe_nod::{api, canonical_item, NodContract, NodItemState};
use outbe_offchain_data::{
    FinalizedBlock, FinalizedLog, FinalizedReceipt, OffchainDataProjection, ProjectionConfig,
    RuntimeBodyReaders,
};
use outbe_offchain_storage::RocksDbStorage;
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
    time::WorldwideDay,
};

fn assert_authenticated_nods(
    evm: &mut HashMapStorageProvider,
    ce: &Arc<CeMdbx>,
    identity: ExactParentIdentity,
    readers: &RuntimeBodyReaders,
    items: &[NodItemState],
) {
    let scope = ExecutionScope::with_parent_tree(
        Arc::new(MdbxAuthenticatedTree::open(ce.clone(), identity).unwrap()),
        CeWorkConfig::new(0, 0, u64::MAX),
    );
    // A fresh scope cannot read a mutation left in the preceding block's overlay.
    StorageHandle::enter(evm, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        for item in items {
            let loaded = api::load_item(&storage, &scope, readers, item.nod_id)
                .expect("authenticate projected NOD against its persisted CE leaf")
                .expect("NOD exists");
            assert_eq!(canonical_item(loaded.body()), canonical_item(item));
            let verified = outbe_compressed_entities::read(
                storage.clone(),
                &scope,
                readers,
                EntityRef::NodItem(item.nod_id),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                verified.stored_body().payload(),
                encode_nod_item_v1(&canonical_item(item)).unwrap(),
                "production write and projected read must preserve exact canonical bytes"
            );
        }
        let first = &items[0];
        let bucket_id = WwdEntityId::from_day_and_digest(first.worldwide_day, first.bucket_key);
        let bucket = api::load_bucket(&storage, &scope, readers, bucket_id)
            .expect("authenticate the updated bucket against its persisted CE leaf")
            .unwrap();
        assert_eq!(bucket.body().total_nods, items.len() as u64);
        assert_eq!(bucket.body().entry_price_minor, U256::from(5));
        assert_eq!(bucket.body().floor_price_minor, first.floor_price_minor);
        assert_eq!(bucket.body().reference_currency, first.reference_currency);
    });
}

#[test]
fn production_nod_receipts_and_ce_seal_agree_with_rocksdb_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let ce_path = directory.path().join("ce");
    let rocks_path = directory.path().join("projection");
    let genesis = B256::repeat_byte(0x42);
    let empty_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
    let environment = EnvironmentIdentity {
        local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
        chain_id: 91,
        genesis_hash: genesis,
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        topology: outbe_compressed_entities::CeTopologyV1.encode(),
        tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".into(),
        vendor_revision: "nod-persistence-chain-test".into(),
    };
    let genesis_marker = FinalizedMarker {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        height: 0,
        block_hash: genesis,
        parent_block_hash: B256::ZERO,
        parent_root: B256::ZERO,
        new_root: empty_root,
    };
    let ce = Arc::new(CeMdbx::open(&ce_path, environment.clone(), genesis_marker).unwrap());
    let rocks = Arc::new(RocksDbStorage::open(&rocks_path).unwrap());
    let config = ProjectionConfig {
        chain_id: 91,
        genesis_hash: genesis,
        start_block: 1,
    };
    let mut projector = OffchainDataProjection::open(config, rocks.clone(), rocks.clone()).unwrap();
    let readers = RuntimeBodyReaders::new(rocks.clone());
    let mut evm = HashMapStorageProvider::new_with_chain_identity(91, genesis);
    // Seed only the empty genesis CE state; all later roots/leaves come from end_block.
    StorageHandle::enter(&mut evm, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_bytes(empty_root.0),
            )
            .unwrap();
    });
    let day = WorldwideDay::new(20260906);
    let mut items = Vec::new();
    let mut identity = ExactParentIdentity {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        block_number: 0,
        block_hash: genesis,
        root: empty_root,
    };

    for height in 1..=2_u64 {
        let owner = Address::repeat_byte(height as u8);
        let item = NodItemState {
            nod_id: derive_poseidon_entity_id(owner, day).unwrap(),
            owner,
            gratis_load_minor: U256::from(123_456),
            worldwide_day: day,
            league_id: 7,
            floor_price_minor: U256::from(8),
            bucket_key: NodContract::bucket_key(day, U256::from(8), 978),
            issuance_currency: 840,
            reference_currency: 978,
            issued_at: 1_788_652_800 + height,
        };
        evm.set_block_number(height);
        let first_event = evm.get_ordered_events().len();
        let scope = ExecutionScope::with_parent_tree(
            Arc::new(MdbxAuthenticatedTree::open(ce.clone(), identity).unwrap()),
            CeWorkConfig::new(0, 0, u64::MAX),
        );
        let seal = StorageHandle::enter(&mut evm, |storage| {
            begin_block(storage.clone(), &scope).unwrap();
            api::add_nod(&storage, &scope, &readers, &item, U256::from(5)).unwrap();
            end_block(storage, &scope).unwrap()
        });
        let hash = B256::repeat_byte(height as u8);
        let batch = seal.staged_tree_batch.freeze(hash);
        ce.apply_finalized(&batch).unwrap();
        let logs = evm.get_ordered_events()[first_event..]
            .iter()
            .enumerate()
            .map(|(index, log)| FinalizedLog {
                log_index: index as u64,
                emitter: log.address,
                data: log.data.clone(),
            })
            .collect::<Vec<_>>();
        assert!(
            !logs.is_empty(),
            "production mutation must emit projection events"
        );
        projector
            .project_block(&FinalizedBlock {
                number: height,
                hash,
                receipts: vec![FinalizedReceipt {
                    tx_hash: B256::repeat_byte(0x70 + height as u8),
                    transaction_index: 0,
                    success: true,
                    logs,
                }],
            })
            .unwrap();
        identity = ExactParentIdentity {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            block_number: height,
            block_hash: hash,
            root: seal.new_root,
        };
        items.push(item);
        assert_authenticated_nods(&mut evm, &ce, identity, &readers, &items);
    }

    drop(readers);
    drop(projector);
    drop(rocks);
    drop(ce);
    let reopened_ce = Arc::new(CeMdbx::open(&ce_path, environment, genesis_marker).unwrap());
    let reopened_rocks = Arc::new(RocksDbStorage::open(&rocks_path).unwrap());
    let reopened_projector =
        OffchainDataProjection::open(config, reopened_rocks.clone(), reopened_rocks.clone())
            .unwrap();
    assert_eq!(
        reopened_projector.state().checkpoint.unwrap().block_number,
        2
    );
    let (failure_sender, failures) = tokio::sync::watch::channel(None);
    let reopened_readers =
        RuntimeBodyReaders::new_supervised(reopened_rocks.clone(), failure_sender);
    assert_authenticated_nods(&mut evm, &reopened_ce, identity, &reopened_readers, &items);

    // Negative control: valid bytes with one changed field must remain fatal,
    // and diagnostics must expose the mismatch rather than turn it into a retry.
    let mut changed = items.remove(0);
    changed.gratis_load_minor += U256::from(1);
    outbe_nod::NodRepositoryWriter::new(reopened_rocks.clone(), reopened_rocks)
        .put_nod(&changed)
        .unwrap();
    let scope = ExecutionScope::with_parent_tree(
        Arc::new(MdbxAuthenticatedTree::open(reopened_ce, identity).unwrap()),
        CeWorkConfig::new(0, 0, u64::MAX),
    );
    let error = StorageHandle::enter(&mut evm, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        outbe_compressed_entities::read(
            storage,
            &scope,
            &reopened_readers,
            EntityRef::NodItem(changed.nod_id),
        )
        .unwrap_err()
    });
    let outbe_primitives::error::PrecompileError::BodyReadCorruption(message) = &error else {
        panic!("body mismatch must remain corruption, got {error:?}");
    };
    for field in [
        "expected=0x",
        "actual=0x",
        "payload_hex=",
        "stored_body_hex=",
        "decoded=",
        "evm_block=",
        "evm_ce_root=",
        "binding=",
    ] {
        assert!(message.contains(field), "missing {field}: {message}");
    }
    reopened_readers.report_precompile_error(&error);
    let failure = failures.borrow().clone().unwrap();
    let outbe_offchain_data::RuntimeBodyFailure::Fatal(failure) = failure else {
        panic!("body mismatch must be reported as fatal");
    };
    assert_eq!(format!("{:?}", failure.class), "CorruptBody");
    for field in [
        "last_body_read=",
        "namespace=nods",
        "projection_after_detection=",
        "block_number: 2",
    ] {
        assert!(
            failure.message.contains(field),
            "missing {field}: {}",
            failure.message
        );
    }
}
