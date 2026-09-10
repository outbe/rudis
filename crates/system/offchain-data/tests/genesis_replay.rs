use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_primitives::{Address, LogData, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    begin_block, body_commitment, encode_nod_bucket_v1, encode_nod_item_v1, encode_tribute_v1,
    end_block, read, update, BodyInput, CandidateCacheLimits, CeMdbx, CeWorkConfig,
    CompressedTreeService, EntityRef, EnvironmentIdentity, ExactParentIdentity, ExecutionScope,
    FinalizedMarker, ParentBodySource, SealOutput, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
    LOCAL_STORAGE_SCHEMA_VERSION,
};
use outbe_nod::{
    canonical_bucket, canonical_item, precompile::INod, NodBucketState, NodContract, NodItemState,
    NodRepositoryReader,
};
use outbe_offchain_data::{
    FinalizedBlock, FinalizedLog, FinalizedReceipt, OffchainDataProjection, ProjectionConfig,
    RuntimeBodyReaders,
};
use outbe_offchain_storage::MemoryStorage;
use outbe_primitives::addresses::{NOD_ADDRESS, TRIBUTE_ADDRESS};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{
    canonical_body, precompile::ITribute, TributeContract, TributeData, TributeRepositoryReader,
};

#[derive(Default)]
struct ObserverCommitments {
    tributes: BTreeMap<WwdEntityId, B256>,
    nod_items: BTreeMap<WwdEntityId, B256>,
    nod_buckets: BTreeMap<WwdEntityId, B256>,
}

impl ObserverCommitments {
    fn replay_block(&mut self, block: &FinalizedBlock) {
        for receipt in &block.receipts {
            assert!(receipt.success);
            for log in &receipt.logs {
                self.replay_log(log.emitter, &log.data);
            }
        }
    }

    fn replay_log(&mut self, emitter: Address, data: &LogData) {
        let Some(signature) = data.topics().first().copied() else {
            return;
        };
        if emitter == TRIBUTE_ADDRESS && signature == ITribute::TributeBodyStored::SIGNATURE_HASH {
            let event = ITribute::TributeBodyStored::decode_log_data(data).unwrap();
            replay_stored(
                &mut self.tributes,
                WwdEntityId::from(event.tributeId),
                event.commitmentSchemeVersion,
                event.schemaVersion,
                event.previousCommitment,
                event.newCommitment,
                &event.canonicalPayload,
            );
        } else if emitter == TRIBUTE_ADDRESS
            && signature == ITribute::TributeBodyDeleted::SIGNATURE_HASH
        {
            let event = ITribute::TributeBodyDeleted::decode_log_data(data).unwrap();
            replay_deleted(
                &mut self.tributes,
                WwdEntityId::from(event.tributeId),
                event.previousCommitment,
            );
        } else if emitter == NOD_ADDRESS && signature == INod::NodBodyStored::SIGNATURE_HASH {
            let event = INod::NodBodyStored::decode_log_data(data).unwrap();
            replay_stored(
                &mut self.nod_items,
                WwdEntityId::from(event.nodId),
                event.commitmentSchemeVersion,
                event.schemaVersion,
                event.previousCommitment,
                event.newCommitment,
                &event.canonicalPayload,
            );
        } else if emitter == NOD_ADDRESS && signature == INod::NodBodyDeleted::SIGNATURE_HASH {
            let event = INod::NodBodyDeleted::decode_log_data(data).unwrap();
            replay_deleted(
                &mut self.nod_items,
                WwdEntityId::from(event.nodId),
                event.previousCommitment,
            );
        } else if emitter == NOD_ADDRESS && signature == INod::NodBucketBodyStored::SIGNATURE_HASH {
            let event = INod::NodBucketBodyStored::decode_log_data(data).unwrap();
            replay_stored(
                &mut self.nod_buckets,
                WwdEntityId::from(event.bucketId),
                event.commitmentSchemeVersion,
                event.schemaVersion,
                event.previousCommitment,
                event.newCommitment,
                &event.canonicalPayload,
            );
        } else if emitter == NOD_ADDRESS && signature == INod::NodBucketBodyDeleted::SIGNATURE_HASH
        {
            let event = INod::NodBucketBodyDeleted::decode_log_data(data).unwrap();
            replay_deleted(
                &mut self.nod_buckets,
                WwdEntityId::from(event.bucketId),
                event.previousCommitment,
            );
        }
    }
}

fn replay_stored(
    commitments: &mut BTreeMap<WwdEntityId, B256>,
    identity: WwdEntityId,
    scheme: u32,
    schema: u32,
    previous: B256,
    new: B256,
    payload: &[u8],
) {
    assert_eq!(
        commitments.get(&identity).copied().unwrap_or(B256::ZERO),
        previous
    );
    let recomputed = body_commitment(scheme, schema, identity, payload).unwrap();
    assert_eq!(new, B256::from(*recomputed.as_bytes()));
    assert!(!new.is_zero());
    commitments.insert(identity, new);
}

fn replay_deleted(
    commitments: &mut BTreeMap<WwdEntityId, B256>,
    identity: WwdEntityId,
    previous: B256,
) {
    assert!(!previous.is_zero());
    assert_eq!(commitments.remove(&identity), Some(previous));
}

fn finalized_block(execution: &mut HashMapStorageProvider, number: u64) -> FinalizedBlock {
    let logs = execution
        .get_ordered_events()
        .iter()
        .enumerate()
        .map(|(index, event)| FinalizedLog {
            log_index: u64::try_from(index).unwrap(),
            emitter: event.address,
            data: event.data.clone(),
        })
        .collect();
    execution.clear_events(TRIBUTE_ADDRESS);
    execution.clear_events(NOD_ADDRESS);
    FinalizedBlock {
        number,
        hash: B256::from(U256::from(number)),
        receipts: vec![FinalizedReceipt {
            tx_hash: B256::from(U256::from(number + 100)),
            transaction_index: 0,
            success: true,
            logs,
        }],
    }
}

fn update_tribute(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    body: &TributeData,
) {
    let current = read(
        storage.clone(),
        scope,
        parent,
        EntityRef::Tribute(body.tribute_id),
    )
    .unwrap()
    .unwrap();
    let canonical = canonical_body(body);
    update(
        storage.clone(),
        scope,
        current,
        BodyInput::Tribute(&canonical),
    )
    .unwrap();
}

fn update_nod_item(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    body: &NodItemState,
) {
    let current = read(
        storage.clone(),
        scope,
        parent,
        EntityRef::NodItem(body.nod_id),
    )
    .unwrap()
    .unwrap();
    let canonical = canonical_item(body);
    update(
        storage.clone(),
        scope,
        current,
        BodyInput::NodItem(&canonical),
    )
    .unwrap();
}

fn as_b256(commitment: Option<outbe_compressed_entities::Commitment>) -> Option<B256> {
    commitment.map(|value| B256::from(*value.as_bytes()))
}

fn assert_execution_tree(
    tree: &CompressedTreeService,
    identity: ExactParentIdentity,
    observer: &ObserverCommitments,
    tribute_id: WwdEntityId,
    nod_id: WwdEntityId,
    bucket_id: WwdEntityId,
) {
    let parent = tree.open_parent(identity).unwrap();
    for (entity, expected) in [
        (
            EntityRef::Tribute(tribute_id),
            observer.tributes.get(&tribute_id).copied(),
        ),
        (
            EntityRef::NodItem(nod_id),
            observer.nod_items.get(&nod_id).copied(),
        ),
        (
            EntityRef::NodBucket(bucket_id),
            observer.nod_buckets.get(&bucket_id).copied(),
        ),
    ] {
        assert_eq!(
            as_b256(parent.read_leaf_verified(entity, identity.root).unwrap()),
            expected
        );
    }
}

fn tree_service(directory: &std::path::Path, genesis_hash: B256) -> CompressedTreeService {
    let db = CeMdbx::open(
        directory,
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: 91,
            genesis_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: outbe_compressed_entities::CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        },
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
        },
    )
    .unwrap();
    CompressedTreeService::new(
        db,
        CandidateCacheLimits {
            max_candidates: 4,
            max_encoded_bytes: 1_000_000,
        },
    )
    .unwrap()
}

fn finalize_tree_block(
    tree: &CompressedTreeService,
    block: &FinalizedBlock,
    seal: SealOutput,
) -> ExactParentIdentity {
    tree.publish_candidate(block.hash, seal.staged_tree_batch)
        .unwrap();
    tree.apply_finalized(block.number, block.hash, seal.new_root)
        .unwrap();
    ExactParentIdentity {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        block_number: block.number,
        block_hash: block.hash,
        root: seal.new_root,
    }
}

fn execution_scope(tree: &CompressedTreeService, parent: ExactParentIdentity) -> ExecutionScope {
    ExecutionScope::with_parent_tree(
        tree.open_parent(parent).unwrap(),
        CeWorkConfig::new(0, 0, u64::MAX),
    )
}

#[test]
fn replay_from_genesis_converges_for_mint_update_and_delete_in_all_namespaces() {
    let projected = Arc::new(MemoryStorage::new());
    let tribute_reader = TributeRepositoryReader::new(projected.clone());
    let nod_reader = NodRepositoryReader::new(projected.clone());
    let parent = RuntimeBodyReaders::new(projected.clone());
    let mut projection = OffchainDataProjection::open(
        ProjectionConfig {
            chain_id: 91,
            genesis_hash: B256::repeat_byte(0x91),
            start_block: 1,
        },
        projected.clone(),
        projected.clone(),
    )
    .unwrap();

    let owner = Address::repeat_byte(0x41);
    let day = WorldwideDay::new(20_260_716);
    let tribute_id = outbe_compressed_entities::derive_poseidon_entity_id(owner, day).unwrap();
    let mut tribute = TributeData {
        tribute_id,
        owner,
        worldwide_day: day,
        issuance_amount_minor: U256::from(10),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(11),
        reference_currency: 978,
        tribute_price_minor: U256::from(12),
        exclude_from_intex_issuance: false,
    };
    let nod_owner = Address::repeat_byte(0x42);
    let nod_id = outbe_compressed_entities::derive_poseidon_entity_id(nod_owner, day).unwrap();
    let bucket_key = NodContract::bucket_key(day, U256::from(14), 978);
    let mut nod = NodItemState {
        nod_id,
        owner: nod_owner,
        gratis_load_minor: U256::from(13),
        worldwide_day: day,
        league_id: 7,
        floor_price_minor: U256::from(14),
        bucket_key,
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 1_752_534_000,
    };
    let bucket_id = WwdEntityId::from_day_and_digest(day, bucket_key.0);
    let mut execution = HashMapStorageProvider::new(1);
    let empty_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
    StorageHandle::enter(&mut execution, |storage| {
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(2_u64),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1_u64),
                U256::from_be_bytes(empty_root.0),
            )
            .unwrap();
    });
    let mut observer = ObserverCommitments::default();
    let tree_directory = tempfile::tempdir().unwrap();
    let genesis_hash = B256::repeat_byte(0x91);
    let tree = tree_service(tree_directory.path(), genesis_hash);
    let mut tree_parent = ExactParentIdentity {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        block_number: 0,
        block_hash: genesis_hash,
        root: empty_root,
    };

    // Block 1: normal domain mint paths emit all three Stored namespaces.
    execution.set_block_number(1);
    let scope = execution_scope(&tree, tree_parent);
    let seal1 = StorageHandle::enter(&mut execution, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let mut contract = TributeContract::new(storage.clone());
        contract.unseal_day(day).unwrap();
        contract.issue(&scope, &parent, &tribute).unwrap();
        outbe_nod::api::add_nod(&storage, &scope, &parent, &nod, U256::from(16)).unwrap();
        end_block(storage, &scope).unwrap()
    });
    let block1 = finalized_block(&mut execution, 1);
    tree_parent = finalize_tree_block(&tree, &block1, seal1);
    observer.replay_block(&block1);
    projection.project_block(&block1).unwrap();
    assert_execution_tree(&tree, tree_parent, &observer, tribute_id, nod_id, bucket_id);

    // Block 2: update each namespace through the generic capability boundary.
    tribute.tribute_price_minor += U256::from(1);
    nod.gratis_load_minor += U256::from(1);
    execution.set_block_number(2);
    let scope = execution_scope(&tree, tree_parent);
    let seal2 = StorageHandle::enter(&mut execution, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        update_tribute(&storage, &scope, &parent, &tribute);
        update_nod_item(&storage, &scope, &parent, &nod);
        NodContract::new(storage.clone())
            .qualify_bucket(&scope, &parent, bucket_key)
            .unwrap();
        end_block(storage, &scope).unwrap()
    });
    let block2 = finalized_block(&mut execution, 2);
    tree_parent = finalize_tree_block(&tree, &block2, seal2);
    observer.replay_block(&block2);
    projection.project_block(&block2).unwrap();
    assert_execution_tree(&tree, tree_parent, &observer, tribute_id, nod_id, bucket_id);

    let projected_tribute = tribute_reader.get(tribute_id).unwrap().unwrap();
    let projected_nod = nod_reader.get(nod_id).unwrap().unwrap();
    let projected_bucket = nod_reader.get_bucket(bucket_id).unwrap().unwrap();
    let expected_bucket = NodBucketState {
        bucket_key,
        worldwide_day: day,
        floor_price_minor: nod.floor_price_minor,
        is_qualified: true,
        total_nods: 1,
        entry_price_minor: U256::from(16),
        reference_currency: nod.reference_currency,
    };
    assert_eq!(
        encode_tribute_v1(&canonical_body(&projected_tribute)).unwrap(),
        encode_tribute_v1(&canonical_body(&tribute)).unwrap()
    );
    assert_eq!(
        encode_nod_item_v1(&canonical_item(&projected_nod)).unwrap(),
        encode_nod_item_v1(&canonical_item(&nod)).unwrap()
    );
    assert_eq!(
        encode_nod_bucket_v1(&canonical_bucket(&projected_bucket)).unwrap(),
        encode_nod_bucket_v1(&canonical_bucket(&expected_bucket)).unwrap()
    );

    // Block 3: normal domain delete paths clear all three tree leaves and emit all
    // three Deleted namespaces from the updated projected bodies.
    execution.set_block_number(3);
    let scope = execution_scope(&tree, tree_parent);
    let seal3 = StorageHandle::enter(&mut execution, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        TributeContract::new(storage.clone())
            .burn(&scope, &parent, tribute_id)
            .unwrap();
        let item = outbe_nod::api::load_item(&storage, &scope, &parent, nod_id)
            .unwrap()
            .unwrap();
        let bucket = outbe_nod::api::load_bucket(&storage, &scope, &parent, bucket_id)
            .unwrap()
            .unwrap();
        outbe_nod::api::remove_nod(&storage, &scope, item, bucket).unwrap();
        end_block(storage, &scope).unwrap()
    });
    let block3 = finalized_block(&mut execution, 3);
    tree_parent = finalize_tree_block(&tree, &block3, seal3);
    observer.replay_block(&block3);
    projection.project_block(&block3).unwrap();
    assert_execution_tree(&tree, tree_parent, &observer, tribute_id, nod_id, bucket_id);

    assert!(observer.tributes.is_empty());
    assert!(observer.nod_items.is_empty());
    assert!(observer.nod_buckets.is_empty());
    assert!(tribute_reader.get(tribute_id).unwrap().is_none());
    assert!(nod_reader.get(nod_id).unwrap().is_none());
    assert!(nod_reader.get_bucket(bucket_id).unwrap().is_none());
    assert_eq!(projection.state().checkpoint.unwrap().block_number, 3);
}
