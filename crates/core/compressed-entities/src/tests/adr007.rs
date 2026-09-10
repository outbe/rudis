use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::{COMPRESSED_ENTITIES_ADDRESS, NOD_ADDRESS, TRIBUTE_ADDRESS},
    error::{PrecompileError, Result},
    storage::{hashmap::HashMapStorageProvider, types::StorageKey, StorageHandle},
};

use crate::{
    begin_block, body_commitment, delete, encode_nod_bucket_v1, encode_nod_item_v1,
    encode_tribute_v1, end_block, list, mint, read, update, AuthenticatedParentTree, BodyInput,
    CeWorkConfig, EntityRef, ExecutionScope, FinalLeafMutation, IdPage, IdPageRequest,
    NodBucketBodyV1, NodItemBodyV1, ParentBodySource, ParentBodySourceError, PartitionRef,
    ProvisionalTreeBatch, QueryRef, StoredBody, TributeBodyV1, VerifiedBody, WwdEntityId,
    ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, MAX_ID_PAGE_LIMIT,
};
use crate::{
    runtime::{
        NodBodyStored, TributeBodyDeleted, TributeBodyStored, INDEX_RECORD_SCAN_GAS, PARENT_ID_GAS,
        READ_FIXED_GAS, READ_GAS_PER_CANONICAL_BYTE,
    },
    schema::{
        body_locator, Collection, CompressedEntitiesSchema, DeltaStatus, IndexKind, IndexRecord,
        PendingWord,
    },
    state::{
        State, BODY_TOUCHED_LENGTH_CLEANUP_GAS, FIRST_BODY_TOUCH_CLEANUP_GAS,
        FIRST_INDEX_TOUCH_CLEANUP_GAS, INDEX_TOUCHED_LENGTH_CLEANUP_GAS, MAX_STORED_BODY_BYTES_V1,
    },
};

const FIRST_TRIBUTE_CLEANUP_GAS: u64 = FIRST_BODY_TOUCH_CLEANUP_GAS
    + BODY_TOUCHED_LENGTH_CLEANUP_GAS
    + 2 * FIRST_INDEX_TOUCH_CLEANUP_GAS
    + INDEX_TOUCHED_LENGTH_CLEANUP_GAS;

#[derive(Debug, Default)]
struct TestAuthenticatedTree(Mutex<HashMap<EntityRef, crate::Commitment>>);

impl TestAuthenticatedTree {
    fn insert(&self, entity: EntityRef, commitment: crate::Commitment) {
        self.0.lock().unwrap().insert(entity, commitment);
    }
}

impl AuthenticatedParentTree for TestAuthenticatedTree {
    fn parent_block_hash(&self) -> B256 {
        B256::ZERO
    }

    fn parent_root(&self) -> B256 {
        crate::sealed_root(B256::ZERO).unwrap()
    }

    fn read_leaf_verified(
        &self,
        entity: EntityRef,
        expected_parent_root: B256,
    ) -> Result<Option<crate::Commitment>> {
        assert_eq!(
            expected_parent_root,
            crate::sealed_root(B256::ZERO).unwrap()
        );
        Ok(self.0.lock().unwrap().get(&entity).copied())
    }

    fn partition_present_verified(
        &self,
        _partition: PartitionRef,
        _expected_parent_root: B256,
    ) -> Result<bool> {
        Ok(false)
    }

    fn prepare_seal(
        &self,
        block_number: u64,
        _mutations: &[FinalLeafMutation],
        _retirements: &[PartitionRef],
    ) -> Result<ProvisionalTreeBatch> {
        ProvisionalTreeBatch::new_fixture_single_collection(
            block_number,
            B256::ZERO,
            B256::ZERO,
            B256::ZERO,
            Default::default(),
            Default::default(),
        )
        .map_err(|error| PrecompileError::Fatal(error.to_string()))
    }
}

fn scope_with_tree(tree: Arc<TestAuthenticatedTree>) -> ExecutionScope {
    ExecutionScope::with_parent_tree(tree, CeWorkConfig::new(0, 0, u64::MAX))
}

fn overlay_leaf(
    storage: StorageHandle<'_>,
    collection: Collection,
    id: WwdEntityId,
) -> Option<crate::Commitment> {
    match State::new(storage).pending(collection, id).unwrap().1 {
        PendingWord::Set(commitment) => Some(commitment),
        PendingWord::Untouched | PendingWord::Deleted => None,
    }
}

#[derive(Default)]
struct MemoryParent {
    bodies: HashMap<EntityRef, StoredBody>,
    tribute_by_owner: HashMap<Address, Vec<WwdEntityId>>,
    tribute_by_day: HashMap<WorldwideDay, Vec<WwdEntityId>>,
    nod_by_owner: HashMap<Address, Vec<WwdEntityId>>,
    nod_all: Vec<WwdEntityId>,
    get_calls: Cell<u32>,
    list_calls: Cell<u32>,
    reverse_pages: bool,
}

impl MemoryParent {
    fn insert_tribute(&mut self, body: &TributeBodyV1) -> StoredBody {
        let stored = stored_tribute(body);
        self.bodies
            .insert(EntityRef::Tribute(body.tribute_id), stored.clone());
        self.tribute_by_owner
            .entry(body.owner)
            .or_default()
            .push(body.tribute_id);
        self.tribute_by_day
            .entry(body.worldwide_day)
            .or_default()
            .push(body.tribute_id);
        self.sort_indexes();
        stored
    }

    fn insert_nod_item(&mut self, body: &NodItemBodyV1) -> StoredBody {
        let stored = stored_nod_item(body);
        self.bodies
            .insert(EntityRef::NodItem(body.nod_id), stored.clone());
        self.nod_by_owner
            .entry(body.owner)
            .or_default()
            .push(body.nod_id);
        self.nod_all.push(body.nod_id);
        self.sort_indexes();
        stored
    }

    fn sort_indexes(&mut self) {
        for ids in self.tribute_by_owner.values_mut() {
            ids.sort_unstable();
        }
        for ids in self.tribute_by_day.values_mut() {
            ids.sort_unstable();
        }
        for ids in self.nod_by_owner.values_mut() {
            ids.sort_unstable();
        }
        self.nod_all.sort_unstable();
    }

    fn ids(&self, query: QueryRef) -> Vec<WwdEntityId> {
        match query {
            QueryRef::TributeByOwner(owner) => self
                .tribute_by_owner
                .get(&owner)
                .cloned()
                .unwrap_or_default(),
            QueryRef::TributeByDay(day) => {
                self.tribute_by_day.get(&day).cloned().unwrap_or_default()
            }
            QueryRef::NodByOwner(owner) => {
                self.nod_by_owner.get(&owner).cloned().unwrap_or_default()
            }
            QueryRef::NodAll => self.nod_all.clone(),
        }
    }
}

impl ParentBodySource for MemoryParent {
    fn get(
        &self,
        entity: EntityRef,
    ) -> core::result::Result<Option<StoredBody>, ParentBodySourceError> {
        self.get_calls.set(self.get_calls.get() + 1);
        Ok(self.bodies.get(&entity).cloned())
    }

    fn list(
        &self,
        query: QueryRef,
        request: IdPageRequest,
    ) -> core::result::Result<IdPage, ParentBodySourceError> {
        self.list_calls.set(self.list_calls.get() + 1);
        let mut ids = self.ids(query);
        if self.reverse_pages {
            ids.reverse();
        }
        let start = request
            .after
            .map_or(0, |after| ids.partition_point(|id| *id <= after));
        let end = (start + request.limit as usize).min(ids.len());
        let page_ids = ids[start..end].to_vec();
        let next_after = (end < ids.len()).then(|| *page_ids.last().expect("non-empty page"));
        Ok(IdPage {
            ids: page_ids,
            next_after,
        })
    }
}

#[derive(Default)]
struct ScriptedParent {
    bodies: HashMap<EntityRef, StoredBody>,
    pages: RefCell<VecDeque<IdPage>>,
}

impl ParentBodySource for ScriptedParent {
    fn get(
        &self,
        entity: EntityRef,
    ) -> core::result::Result<Option<StoredBody>, ParentBodySourceError> {
        Ok(self.bodies.get(&entity).cloned())
    }

    fn list(
        &self,
        _query: QueryRef,
        _request: IdPageRequest,
    ) -> core::result::Result<IdPage, ParentBodySourceError> {
        Ok(self.pages.borrow_mut().pop_front().unwrap_or(IdPage {
            ids: Vec::new(),
            next_after: None,
        }))
    }
}

fn entity(day: u32, suffix: u8) -> WwdEntityId {
    WwdEntityId::from_day_and_digest(WorldwideDay::new(day), [suffix; 32])
}

fn tribute(id: WwdEntityId, owner: Address, price: u64) -> TributeBodyV1 {
    TributeBodyV1 {
        tribute_id: id,
        owner,
        worldwide_day: id.worldwide_day(),
        issuance_amount_minor: U256::from(10),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(20),
        reference_currency: 978,
        tribute_price_minor: U256::from(price),
        exclude_from_intex_issuance: false,
    }
}

fn nod_item(id: WwdEntityId, owner: Address) -> NodItemBodyV1 {
    NodItemBodyV1 {
        nod_id: id,
        owner,
        gratis_load_minor: U256::from(1),
        worldwide_day: id.worldwide_day(),
        league_id: 3,
        floor_price_minor: U256::from(4),
        bucket_key: B256::repeat_byte(5),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 7,
    }
}

fn stored_tribute(body: &TributeBodyV1) -> StoredBody {
    StoredBody::new_v1(encode_tribute_v1(body).unwrap()).unwrap()
}

fn stored_nod_item(body: &NodItemBodyV1) -> StoredBody {
    StoredBody::new_v1(encode_nod_item_v1(body).unwrap()).unwrap()
}

fn tribute_commitment(body: &TributeBodyV1) -> crate::Commitment {
    let payload = encode_tribute_v1(body).unwrap();
    body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        body.tribute_id,
        &payload,
    )
    .unwrap()
}

fn nod_item_commitment(body: &NodItemBodyV1) -> crate::Commitment {
    let payload = encode_nod_item_v1(body).unwrap();
    body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        body.nod_id,
        &payload,
    )
    .unwrap()
}

fn seed_parent_tribute(
    parent: &mut MemoryParent,
    tree: &TestAuthenticatedTree,
    body: &TributeBodyV1,
) {
    parent.insert_tribute(body);
    tree.insert(
        EntityRef::Tribute(body.tribute_id),
        tribute_commitment(body),
    );
}

fn seed_parent_nod_item(
    parent: &mut MemoryParent,
    tree: &TestAuthenticatedTree,
    body: &NodItemBodyV1,
) {
    parent.insert_nod_item(body);
    tree.insert(EntityRef::NodItem(body.nod_id), nod_item_commitment(body));
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FixtureBody {
    Tribute(TributeBodyV1),
    NodItem(NodItemBodyV1),
    NodBucket(NodBucketBodyV1),
}

impl FixtureBody {
    fn input(&self) -> BodyInput<'_> {
        match self {
            Self::Tribute(body) => BodyInput::Tribute(body),
            Self::NodItem(body) => BodyInput::NodItem(body),
            Self::NodBucket(body) => BodyInput::NodBucket(body),
        }
    }

    fn entity_ref(&self) -> EntityRef {
        match self {
            Self::Tribute(body) => EntityRef::Tribute(body.tribute_id),
            Self::NodItem(body) => EntityRef::NodItem(body.nod_id),
            Self::NodBucket(body) => EntityRef::NodBucket(body.entity_id()),
        }
    }

    fn assert_verified(&self, verified: &VerifiedBody) {
        match self {
            Self::Tribute(expected) => {
                assert_eq!(verified.payload().as_tribute(), Some(expected));
            }
            Self::NodItem(expected) => {
                assert_eq!(verified.payload().as_nod_item(), Some(expected));
            }
            Self::NodBucket(expected) => {
                assert_eq!(verified.payload().as_nod_bucket(), Some(expected));
            }
        }
    }

    fn expected_index_touches(&self) -> u32 {
        match self {
            Self::Tribute(_) | Self::NodItem(_) => 2,
            Self::NodBucket(_) => 0,
        }
    }

    fn emitter(&self) -> Address {
        match self {
            Self::Tribute(_) => TRIBUTE_ADDRESS,
            Self::NodItem(_) | Self::NodBucket(_) => NOD_ADDRESS,
        }
    }
}

#[derive(Clone, Copy)]
enum BodyVersion {
    Original,
    Updated,
}

#[derive(Clone, Copy)]
enum MatrixMutation {
    Mint(BodyVersion),
    Update(BodyVersion),
    Delete,
}

fn exercise_transition_sequence(
    original: &FixtureBody,
    updated: &FixtureBody,
    sequence: &[(MatrixMutation, bool)],
) {
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    let mut expected: Option<BodyVersion> = None;
    let mut last_capability: Option<VerifiedBody> = None;
    let mut successful_operations = 0;

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        for (operation, should_succeed) in sequence {
            let selected = |version: BodyVersion| match version {
                BodyVersion::Original => original,
                BodyVersion::Updated => updated,
            };
            let result = match operation {
                MatrixMutation::Mint(version) => {
                    mint(storage.clone(), &scope, selected(*version).input())
                }
                MatrixMutation::Update(version) => {
                    let current = read(storage.clone(), &scope, &parent, original.entity_ref())
                        .unwrap()
                        .or_else(|| last_capability.clone())
                        .expect("update scenario retains a prior value capability");
                    last_capability = Some(current.clone());
                    update(storage.clone(), &scope, current, selected(*version).input())
                }
                MatrixMutation::Delete => {
                    let current = read(storage.clone(), &scope, &parent, original.entity_ref())
                        .unwrap()
                        .or_else(|| last_capability.clone())
                        .expect("delete scenario retains a prior value capability");
                    last_capability = Some(current.clone());
                    delete(storage.clone(), &scope, current)
                }
            };

            if *should_succeed {
                result.unwrap();
                successful_operations += 1;
                expected = match operation {
                    MatrixMutation::Mint(version) | MatrixMutation::Update(version) => {
                        Some(*version)
                    }
                    MatrixMutation::Delete => None,
                };
            } else {
                assert!(matches!(result, Err(PrecompileError::Revert(_))));
            }

            let current = read(storage.clone(), &scope, &parent, original.entity_ref()).unwrap();
            match (expected, current) {
                (None, None) => {}
                (Some(version), Some(verified)) => selected(version).assert_verified(&verified),
                _ => panic!("transition produced the wrong observable existence state"),
            }
        }

        let schema = CompressedEntitiesSchema::new(storage.clone());
        assert_eq!(schema.touched.len().unwrap(), 1);
        assert_eq!(
            schema.touched_index_deltas.len().unwrap(),
            original.expected_index_touches()
        );
        end_block(storage, &scope).unwrap();
    });

    assert_eq!(provider.get_ordered_events().len(), successful_operations);
    assert!(provider
        .get_ordered_events()
        .iter()
        .all(|event| event.address == original.emitter()));
}

/// The bucket key an identity is consistent with.
///
/// `NodBucketBodyV1::entity_id` derives the identity as `wwd ++ key[4..]`, so
/// the key's leading four bytes are not recoverable from it. Fixtures that
/// start from an identity rebuild the one key that re-derives to it.
fn bucket_key_for(id: WwdEntityId) -> B256 {
    let mut key = [0_u8; 32];
    key[4..].copy_from_slice(&id.body());
    B256::from(key)
}

#[test]
fn same_block_transition_matrix_is_overlay_first_and_single_touch() {
    let owner = address!("1000000000000000000000000000000000000001");
    let id = entity(7, 1);
    let first = tribute(id, owner, 100);
    let second = tribute(id, owner, 200);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();
        assert_eq!(parent.get_calls.get(), 0);
        let minted = read(storage.clone(), &scope, &parent, EntityRef::Tribute(id))
            .unwrap()
            .unwrap();
        assert_eq!(minted.payload().as_tribute().unwrap(), &first);
        assert!(matches!(
            mint(storage.clone(), &scope, BodyInput::Tribute(&first)),
            Err(PrecompileError::Revert(_))
        ));

        update(storage.clone(), &scope, minted, BodyInput::Tribute(&second)).unwrap();
        let updated = read(storage.clone(), &scope, &parent, EntityRef::Tribute(id))
            .unwrap()
            .unwrap();
        assert_eq!(updated.payload().as_tribute().unwrap(), &second);
        delete(storage.clone(), &scope, updated).unwrap();
        assert!(
            read(storage.clone(), &scope, &parent, EntityRef::Tribute(id))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            delete(
                storage.clone(),
                &scope,
                // A capability can only be acquired while present, so use a
                // mint/read cycle to test the absent rejection below.
                {
                    mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();
                    let cap = read(storage.clone(), &scope, &parent, EntityRef::Tribute(id))
                        .unwrap()
                        .unwrap();
                    delete(storage.clone(), &scope, cap.clone()).unwrap();
                    cap
                }
            ),
            Err(PrecompileError::Revert(_))
        ));
        mint(storage.clone(), &scope, BodyInput::Tribute(&second)).unwrap();

        let schema = CompressedEntitiesSchema::new(storage);
        assert_eq!(schema.touched.len().unwrap(), 1);
        // Two memberships, each touched once despite the repeated sequence.
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 2);
        assert_eq!(parent.get_calls.get(), 0);
    });
}

#[test]
fn completed_seal_projection_is_unavailable_before_end_and_exact_after_end() {
    let day = WorldwideDay::new(2026_0707);
    let body = tribute(
        entity(day.value(), 0x71),
        address!("7100000000000000000000000000000000000071"),
        100,
    );
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&body)).unwrap();

        assert!(scope.completed_sealed_root().is_err());
        assert!(scope
            .completed_partition_root(PartitionRef::TributeWwd(day))
            .is_err());

        let preview = crate::preview_end_block(storage.clone(), &scope).unwrap();
        assert_eq!(scope.provisional_sealed_root().unwrap(), preview.new_root);
        let provisional_collection = scope
            .provisional_partition_root(PartitionRef::TributeWwd(day))
            .unwrap();
        assert_eq!(
            provisional_collection.partition(),
            PartitionRef::TributeWwd(day)
        );
        assert!(!provisional_collection.root().is_zero());

        let seal = end_block(storage, &scope).unwrap();
        assert_eq!(seal, preview);
        assert_eq!(scope.completed_sealed_root().unwrap(), seal.new_root);
        let collection = scope
            .completed_partition_root(PartitionRef::TributeWwd(day))
            .unwrap();
        assert_eq!(collection.partition(), PartitionRef::TributeWwd(day));
        assert!(!collection.root().is_zero());
        assert_eq!(
            collection,
            scope
                .sealed_collection_root(&seal, PartitionRef::TributeWwd(day))
                .unwrap()
        );
        assert_eq!(collection, provisional_collection);
        let payload = crate::encode_tribute_v1(&body).unwrap();
        let commitment = crate::body_commitment(
            crate::ACTIVE_COMMITMENT_SCHEME,
            crate::BODY_SCHEMA_V1,
            body.tribute_id,
            &payload,
        )
        .unwrap();
        assert_eq!(
            crate::tribute_partition_root_from_leaves(day, [(body.tribute_id, commitment)],)
                .unwrap(),
            collection.root(),
        );
    });
}

#[test]
fn same_leaf_aba_capability_remains_value_valid() {
    let owner = address!("2000000000000000000000000000000000000002");
    let body = tribute(entity(8, 2), owner, 100);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&body)).unwrap();
        let old = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(body.tribute_id),
        )
        .unwrap()
        .unwrap();
        update(
            storage.clone(),
            &scope,
            old.clone(),
            BodyInput::Tribute(&body),
        )
        .unwrap();
        // The current authenticated value is identical, so the earlier value
        // capability deliberately remains valid.
        delete(storage, &scope, old).unwrap();
    });
}

#[test]
fn nod_item_and_bucket_follow_the_same_closed_transition_lifecycle() {
    let owner = address!("2100000000000000000000000000000000000002");
    let mut item = nod_item(entity(8, 21), owner);
    let mut bucket = NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(22),
        worldwide_day: WorldwideDay::new(8),
        floor_price_minor: U256::from(10),
        is_qualified: false,
        total_nods: 1,
        entry_price_minor: U256::from(11),
        reference_currency: 840,
    };
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::NodItem(&item)).unwrap();
        mint(storage.clone(), &scope, BodyInput::NodBucket(&bucket)).unwrap();
        let old_item = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::NodItem(item.nod_id),
        )
        .unwrap()
        .unwrap();
        let old_bucket = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::NodBucket(bucket.entity_id()),
        )
        .unwrap()
        .unwrap();
        item.gratis_load_minor = U256::from(99);
        bucket.is_qualified = true;
        update(storage.clone(), &scope, old_item, BodyInput::NodItem(&item)).unwrap();
        update(
            storage.clone(),
            &scope,
            old_bucket,
            BodyInput::NodBucket(&bucket),
        )
        .unwrap();
        let item_cap = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::NodItem(item.nod_id),
        )
        .unwrap()
        .unwrap();
        let bucket_cap = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::NodBucket(bucket.entity_id()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(item_cap.payload().as_nod_item().unwrap(), &item);
        assert_eq!(bucket_cap.payload().as_nod_bucket().unwrap(), &bucket);
        delete(storage.clone(), &scope, item_cap).unwrap();
        delete(storage.clone(), &scope, bucket_cap).unwrap();
        assert!(read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::NodItem(item.nod_id)
        )
        .unwrap()
        .is_none());
        assert!(read(
            storage,
            &scope,
            &parent,
            EntityRef::NodBucket(bucket.entity_id())
        )
        .unwrap()
        .is_none());
    });
    assert!(provider
        .get_ordered_events()
        .iter()
        .all(|log| log.address == NOD_ADDRESS));
    assert_eq!(provider.get_ordered_events().len(), 6);
}

#[test]
fn every_typed_collection_obeys_the_complete_same_block_transition_matrix() {
    let owner = address!("2150000000000000000000000000000000000002");
    let tribute_original = tribute(entity(8, 0x31), owner, 100);
    let tribute_updated = tribute(tribute_original.tribute_id, owner, 200);

    let nod_original = nod_item(entity(8, 0x32), owner);
    let mut nod_updated = nod_original.clone();
    nod_updated.gratis_load_minor = U256::from(99);

    let bucket_original = NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(0x33),
        worldwide_day: WorldwideDay::new(8),
        floor_price_minor: U256::from(10),
        is_qualified: false,
        total_nods: 1,
        entry_price_minor: U256::from(11),
        reference_currency: 840,
    };
    let mut bucket_updated = bucket_original.clone();
    bucket_updated.is_qualified = true;

    let fixtures = [
        (
            FixtureBody::Tribute(tribute_original),
            FixtureBody::Tribute(tribute_updated),
        ),
        (
            FixtureBody::NodItem(nod_original),
            FixtureBody::NodItem(nod_updated),
        ),
        (
            FixtureBody::NodBucket(bucket_original),
            FixtureBody::NodBucket(bucket_updated),
        ),
    ];

    for (original, updated) in &fixtures {
        exercise_transition_sequence(
            original,
            updated,
            &[
                (MatrixMutation::Mint(BodyVersion::Original), true),
                (MatrixMutation::Mint(BodyVersion::Original), false),
            ],
        );
        exercise_transition_sequence(
            original,
            updated,
            &[
                (MatrixMutation::Mint(BodyVersion::Original), true),
                (MatrixMutation::Update(BodyVersion::Updated), true),
                (MatrixMutation::Update(BodyVersion::Original), true),
                (MatrixMutation::Delete, true),
            ],
        );
        exercise_transition_sequence(
            original,
            updated,
            &[
                (MatrixMutation::Mint(BodyVersion::Original), true),
                (MatrixMutation::Delete, true),
                (MatrixMutation::Update(BodyVersion::Updated), false),
                (MatrixMutation::Delete, false),
                (MatrixMutation::Mint(BodyVersion::Updated), true),
            ],
        );
        exercise_transition_sequence(
            original,
            updated,
            &[
                (MatrixMutation::Mint(BodyVersion::Original), true),
                (MatrixMutation::Update(BodyVersion::Original), true),
            ],
        );
    }
}

#[test]
fn stale_or_wrong_identity_capability_reverts_without_mutation() {
    let owner = address!("2200000000000000000000000000000000000002");
    let first = tribute(entity(8, 23), owner, 100);
    let second = tribute(first.tribute_id, owner, 200);
    let other = tribute(entity(8, 24), owner, 300);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();
        let stale = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(first.tribute_id),
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            update(
                storage.clone(),
                &scope,
                stale.clone(),
                BodyInput::Tribute(&other)
            ),
            Err(PrecompileError::Revert(_))
        ));
        update(
            storage.clone(),
            &scope,
            stale.clone(),
            BodyInput::Tribute(&second),
        )
        .unwrap();
        assert!(matches!(
            delete(storage.clone(), &scope, stale),
            Err(PrecompileError::Revert(_))
        ));
        let current = read(
            storage,
            &scope,
            &parent,
            EntityRef::Tribute(first.tribute_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(current.payload().as_tribute().unwrap(), &second);
    });
}

#[test]
fn untouched_reads_use_parent_once_and_classify_missing_committed_body() {
    let owner = address!("2300000000000000000000000000000000000002");
    let present = tribute(entity(8, 25), owner, 100);
    let missing = tribute(entity(8, 26), owner, 200);
    let stale_tribute = tribute(entity(8, 27), owner, 300);
    let stale_nod = nod_item(entity(8, 28), owner);
    let stale_bucket_id = entity(8, 29);
    let stale_bucket = NodBucketBodyV1 {
        bucket_key: bucket_key_for(stale_bucket_id),
        worldwide_day: stale_bucket_id.worldwide_day(),
        floor_price_minor: U256::from(4),
        is_qualified: false,
        total_nods: 1,
        entry_price_minor: U256::from(5),
        reference_currency: 840,
    };
    let missing_bucket_id = entity(8, 30);
    let missing_bucket = NodBucketBodyV1 {
        bucket_key: bucket_key_for(missing_bucket_id),
        worldwide_day: missing_bucket_id.worldwide_day(),
        floor_price_minor: U256::from(6),
        is_qualified: true,
        total_nods: 2,
        entry_price_minor: U256::from(7),
        reference_currency: 840,
    };
    let mut parent = MemoryParent::default();
    let tree = Arc::new(TestAuthenticatedTree::default());
    let scope = scope_with_tree(tree.clone());
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        seed_parent_tribute(&mut parent, tree.as_ref(), &present);
        tree.insert(
            EntityRef::Tribute(missing.tribute_id),
            tribute_commitment(&missing),
        );
        parent.insert_tribute(&stale_tribute);
        parent.insert_nod_item(&stale_nod);
        parent.bodies.insert(
            EntityRef::NodBucket(stale_bucket_id),
            StoredBody::new_v1(encode_nod_bucket_v1(&stale_bucket).unwrap()).unwrap(),
        );
        tree.insert(
            EntityRef::NodBucket(missing_bucket_id),
            body_commitment(
                ACTIVE_COMMITMENT_SCHEME,
                BODY_SCHEMA_V1,
                missing_bucket_id,
                &encode_nod_bucket_v1(&missing_bucket).unwrap(),
            )
            .unwrap(),
        );
        begin_block(storage.clone(), &scope).unwrap();
        let loaded = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(present.tribute_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(loaded.payload().as_tribute().unwrap(), &present);
        assert_eq!(parent.get_calls.get(), 1);
        for absent in [
            EntityRef::Tribute(stale_tribute.tribute_id),
            EntityRef::NodItem(stale_nod.nod_id),
            EntityRef::NodBucket(stale_bucket_id),
        ] {
            assert!(read(storage.clone(), &scope, &parent, absent)
                .unwrap()
                .is_none());
        }
        assert_eq!(
            parent.get_calls.get(),
            1,
            "authenticated absence must bypass even stale Mongo rows in every collection"
        );
        assert!(matches!(
            read(
                storage.clone(),
                &scope,
                &parent,
                EntityRef::Tribute(missing.tribute_id)
            ),
            Err(PrecompileError::BodyReadCorruption(_))
        ));
        assert_eq!(parent.get_calls.get(), 2);
        assert!(matches!(
            read(
                storage,
                &scope,
                &parent,
                EntityRef::NodBucket(missing_bucket_id)
            ),
            Err(PrecompileError::BodyReadCorruption(_))
        ));
        assert_eq!(parent.get_calls.get(), 3);
    });
}

#[test]
fn canonical_events_use_domain_emitters_and_survive_as_ordered_operations() {
    let owner = address!("3000000000000000000000000000000000000003");
    let id = entity(9, 3);
    let first = tribute(id, owner, 100);
    let second = tribute(id, owner, 200);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();
        let cap = read(storage.clone(), &scope, &parent, EntityRef::Tribute(id))
            .unwrap()
            .unwrap();
        update(storage.clone(), &scope, cap, BodyInput::Tribute(&second)).unwrap();
        let cap = read(storage.clone(), &scope, &parent, EntityRef::Tribute(id))
            .unwrap()
            .unwrap();
        delete(storage, &scope, cap).unwrap();
    });

    let logs = provider.get_ordered_events();
    assert_eq!(logs.len(), 3);
    assert!(logs.iter().all(|log| log.address == TRIBUTE_ADDRESS));
    let mint_event = TributeBodyStored::decode_log_data(&logs[0].data).unwrap();
    let update_event = TributeBodyStored::decode_log_data(&logs[1].data).unwrap();
    let delete_event = TributeBodyDeleted::decode_log_data(&logs[2].data).unwrap();
    assert_eq!(mint_event.tributeId, id.to_u256());
    assert_eq!(mint_event.previousCommitment, B256::ZERO);
    assert_eq!(
        mint_event.canonicalPayload,
        encode_tribute_v1(&first).unwrap()
    );
    assert_eq!(update_event.previousCommitment, mint_event.newCommitment);
    assert_ne!(update_event.newCommitment, mint_event.newCommitment);
    assert_eq!(delete_event.previousCommitment, update_event.newCommitment);

    let nod = nod_item(entity(10, 4), owner);
    let nod_scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        // Finish the previous scope first; cleanup emits no event.
        end_block(storage.clone(), &scope).unwrap();
        begin_block(storage.clone(), &nod_scope).unwrap();
        mint(storage, &nod_scope, BodyInput::NodItem(&nod)).unwrap();
    });
    let last = provider.get_ordered_events().last().unwrap();
    assert_eq!(last.address, NOD_ADDRESS);
    assert_eq!(last.data.topics()[0], NodBodyStored::SIGNATURE_HASH);
}

#[test]
fn outer_checkpoint_reverts_commitment_overlay_indexes_and_event_together() {
    let owner = address!("4000000000000000000000000000000000000004");
    let body = tribute(entity(11, 5), owner, 100);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let transaction_gas = scope.explicit_gas_checkpoint();
        let failed: Result<()> = storage.with_checkpoint(|| {
            mint(storage.clone(), &scope, BodyInput::Tribute(&body))?;
            Err(PrecompileError::Revert("outer transaction reverted".into()))
        });
        assert!(matches!(failed, Err(PrecompileError::Revert(_))));
        assert!(overlay_leaf(storage.clone(), Collection::Tribute, body.tribute_id).is_none());
        assert!(read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(body.tribute_id)
        )
        .unwrap()
        .is_none());
        let schema = CompressedEntitiesSchema::new(storage);
        assert_eq!(schema.touched.len().unwrap(), 0);
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 0);
        assert_eq!(
            scope.explicit_gas_since(transaction_gas).unwrap(),
            FIRST_TRIBUTE_CLEANUP_GAS,
            "journal rollback must not refund explicit work gas"
        );
    });
    assert!(provider.get_ordered_events().is_empty());
}

#[test]
fn merged_list_applies_removals_additions_pagination_and_overlay_bodies() {
    let owner1 = address!("5000000000000000000000000000000000000005");
    let owner2 = address!("6000000000000000000000000000000000000006");
    let a = tribute(entity(12, 1), owner1, 10);
    let b = tribute(entity(12, 2), owner1, 20);
    let c = tribute(entity(12, 3), owner1, 30);
    let d = tribute(entity(12, 4), owner1, 40);
    let b_moved = tribute(b.tribute_id, owner2, 21);
    let mut parent = MemoryParent::default();
    let tree = Arc::new(TestAuthenticatedTree::default());
    let scope = scope_with_tree(tree.clone());
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        for body in [&a, &b, &c] {
            seed_parent_tribute(&mut parent, tree.as_ref(), body);
        }
        begin_block(storage.clone(), &scope).unwrap();
        let a_cap = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(a.tribute_id),
        )
        .unwrap()
        .unwrap();
        delete(storage.clone(), &scope, a_cap).unwrap();
        let b_cap = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(b.tribute_id),
        )
        .unwrap()
        .unwrap();
        update(storage.clone(), &scope, b_cap, BodyInput::Tribute(&b_moved)).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&d)).unwrap();

        let first = list(
            storage.clone(),
            &scope,
            &parent,
            QueryRef::TributeByOwner(owner1),
            IdPageRequest {
                after: None,
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(
            first
                .bodies()
                .iter()
                .map(|body| body.entity_id())
                .collect::<Vec<_>>(),
            vec![c.tribute_id]
        );
        assert_eq!(first.next_after(), Some(c.tribute_id));
        let second = list(
            storage.clone(),
            &scope,
            &parent,
            QueryRef::TributeByOwner(owner1),
            IdPageRequest {
                after: first.next_after(),
                limit: 1,
            },
        )
        .unwrap();
        assert_eq!(second.bodies()[0].entity_id(), d.tribute_id);
        assert_eq!(second.next_after(), None);
        assert_eq!(second.bodies()[0].payload().as_tribute().unwrap(), &d);

        let moved = list(
            storage,
            &scope,
            &parent,
            QueryRef::TributeByOwner(owner2),
            IdPageRequest {
                after: None,
                limit: 10,
            },
        )
        .unwrap();
        assert_eq!(moved.bodies()[0].payload().as_tribute().unwrap(), &b_moved);
    });
    assert!(parent.list_calls.get() >= 3);
}

#[test]
fn malformed_parent_order_is_rejected_as_corruption() {
    let owner = address!("7000000000000000000000000000000000000007");
    let a = tribute(entity(13, 1), owner, 10);
    let b = tribute(entity(13, 2), owner, 20);
    let mut parent = MemoryParent {
        reverse_pages: true,
        ..MemoryParent::default()
    };
    let tree = Arc::new(TestAuthenticatedTree::default());
    let scope = scope_with_tree(tree.clone());
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        seed_parent_tribute(&mut parent, tree.as_ref(), &a);
        seed_parent_tribute(&mut parent, tree.as_ref(), &b);
        begin_block(storage.clone(), &scope).unwrap();
        let result = list(
            storage,
            &scope,
            &parent,
            QueryRef::TributeByOwner(owner),
            IdPageRequest {
                after: None,
                limit: 2,
            },
        );
        assert!(matches!(
            result,
            Err(PrecompileError::BodyReadCorruption(_))
        ));
    });
}

#[test]
fn page_limit_outside_fork_bound_is_a_deterministic_revert() {
    let parent = MemoryParent::default();
    let tree = Arc::new(TestAuthenticatedTree::default());
    let scope = scope_with_tree(tree.clone());
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        for limit in [0, MAX_ID_PAGE_LIMIT + 1] {
            assert!(matches!(
                list(
                    storage.clone(),
                    &scope,
                    &parent,
                    QueryRef::NodAll,
                    IdPageRequest { after: None, limit }
                ),
                Err(PrecompileError::Revert(_))
            ));
        }
    });
    assert_eq!(parent.list_calls.get(), 0);
}

#[test]
fn cleanup_zeroes_overlay_and_phase_rejects_post_end_access() {
    let owner = address!("8000000000000000000000000000000000000008");
    let body = tribute(entity(14, 8), owner, 100);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    let mut locator = B256::ZERO;

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&body)).unwrap();
        let capability = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(body.tribute_id),
        )
        .unwrap()
        .unwrap();
        locator = body_locator(Collection::Tribute, body.tribute_id).unwrap();
        let seal = end_block(storage.clone(), &scope).unwrap();

        assert_eq!(State::new(storage.clone()).root().unwrap(), seal.new_root);
        assert_ne!(seal.new_root, seal.parent_root);
        let schema = CompressedEntitiesSchema::new(storage.clone());
        assert_eq!(schema.touched.len().unwrap(), 0);
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 0);
        assert!(schema.pending_word.read(&locator).unwrap().is_zero());
        assert!(schema.pending_body.get_bytes(&locator).is_empty().unwrap());
        assert_eq!(
            schema.body_identity_collection.read(&locator).unwrap(),
            0,
            "cleanup must clear the identity presence marker"
        );
        assert!(matches!(
            read(
                storage.clone(),
                &scope,
                &parent,
                EntityRef::Tribute(body.tribute_id)
            ),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            list(
                storage.clone(),
                &scope,
                &parent,
                QueryRef::TributeByOwner(owner),
                IdPageRequest {
                    after: None,
                    limit: 1,
                },
            ),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            mint(storage.clone(), &scope, BodyInput::Tribute(&body)),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            update(
                storage.clone(),
                &scope,
                capability.clone(),
                BodyInput::Tribute(&body),
            ),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            delete(storage, &scope, capability),
            Err(PrecompileError::Fatal(_))
        ));
    });

    let pending_slot = locator.mapping_slot(U256::from(4));
    assert_eq!(
        provider
            .storage
            .get(&(COMPRESSED_ENTITIES_ADDRESS, pending_slot))
            .copied()
            .unwrap_or_default(),
        U256::ZERO
    );
}

#[test]
fn begin_block_rejects_a_dirty_prior_overlay_without_repairing_it() {
    let owner = address!("8100000000000000000000000000000000000008");
    let body = tribute(entity(14, 81), owner, 100);
    let first_scope = ExecutionScope::new();
    let second_scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &first_scope).unwrap();
        mint(storage.clone(), &first_scope, BodyInput::Tribute(&body)).unwrap();
        assert!(matches!(
            begin_block(storage.clone(), &second_scope),
            Err(PrecompileError::Fatal(_))
        ));
        let schema = CompressedEntitiesSchema::new(storage);
        assert_eq!(schema.touched.len().unwrap(), 1);
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 2);
    });
}

#[test]
fn gas_reserve_is_first_touch_only_and_oog_rolls_back_before_overlay_write() {
    let owner = address!("8200000000000000000000000000000000000008");
    let body = tribute(entity(14, 82), owner, 100);
    let parent = MemoryParent::default();

    let mut provider = HashMapStorageProvider::new(1);
    provider.set_gas_limit(FIRST_TRIBUTE_CLEANUP_GAS + 100_000);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let first_touch = scope.explicit_gas_checkpoint();
        mint(storage.clone(), &scope, BodyInput::Tribute(&body)).unwrap();
        assert_eq!(storage.gas_used().unwrap(), FIRST_TRIBUTE_CLEANUP_GAS);
        assert_eq!(
            scope.explicit_gas_since(first_touch).unwrap(),
            FIRST_TRIBUTE_CLEANUP_GAS
        );
        let cap = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(body.tribute_id),
        )
        .unwrap()
        .unwrap();
        let before_repeat = storage.gas_used().unwrap();
        let repeat_touch = scope.explicit_gas_checkpoint();
        update(storage.clone(), &scope, cap, BodyInput::Tribute(&body)).unwrap();
        assert_eq!(
            storage.gas_used().unwrap(),
            before_repeat,
            "repeat body/index touches must not reserve cleanup twice"
        );
        assert_eq!(scope.explicit_gas_since(repeat_touch).unwrap(), 0);
    });

    let mut body_oog = HashMapStorageProvider::new(1);
    body_oog.set_gas_limit(FIRST_BODY_TOUCH_CLEANUP_GAS - 1);
    let body_scope = ExecutionScope::new();
    StorageHandle::enter(&mut body_oog, |storage| {
        begin_block(storage.clone(), &body_scope).unwrap();
        let failed_charge = body_scope.explicit_gas_checkpoint();
        assert!(matches!(
            mint(storage.clone(), &body_scope, BodyInput::Tribute(&body)),
            Err(PrecompileError::OutOfGas)
        ));
        assert!(overlay_leaf(storage.clone(), Collection::Tribute, body.tribute_id).is_none());
        let schema = CompressedEntitiesSchema::new(storage);
        assert_eq!(schema.touched.len().unwrap(), 0);
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 0);
        assert_eq!(body_scope.explicit_gas_since(failed_charge).unwrap(), 0);
    });
    assert!(body_oog.get_ordered_events().is_empty());

    // The second index reserve fails after temporary body/first-index writes;
    // the mutation's local checkpoint must still restore every component.
    let mut index_oog = HashMapStorageProvider::new(1);
    index_oog.set_gas_limit(
        FIRST_BODY_TOUCH_CLEANUP_GAS
            + BODY_TOUCHED_LENGTH_CLEANUP_GAS
            + 2 * FIRST_INDEX_TOUCH_CLEANUP_GAS
            + INDEX_TOUCHED_LENGTH_CLEANUP_GAS
            - 1,
    );
    let index_scope = ExecutionScope::new();
    StorageHandle::enter(&mut index_oog, |storage| {
        begin_block(storage.clone(), &index_scope).unwrap();
        let failed_charge = index_scope.explicit_gas_checkpoint();
        assert!(matches!(
            mint(storage.clone(), &index_scope, BodyInput::Tribute(&body)),
            Err(PrecompileError::OutOfGas)
        ));
        assert!(overlay_leaf(storage.clone(), Collection::Tribute, body.tribute_id).is_none());
        let schema = CompressedEntitiesSchema::new(storage);
        assert_eq!(schema.touched.len().unwrap(), 0);
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 0);
        assert_eq!(
            index_scope.explicit_gas_since(failed_charge).unwrap(),
            FIRST_BODY_TOUCH_CLEANUP_GAS
                + BODY_TOUCHED_LENGTH_CLEANUP_GAS
                + FIRST_INDEX_TOUCH_CLEANUP_GAS
                + INDEX_TOUCHED_LENGTH_CLEANUP_GAS,
            "successful explicit deductions remain charged when later work OOGs"
        );
    });
    assert!(index_oog.get_ordered_events().is_empty());
}

#[test]
fn static_context_rejects_mutation_before_overlay_or_event_state() {
    let owner = address!("8210000000000000000000000000000000000008");
    let body = tribute(entity(14, 85), owner, 100);
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage, &scope).unwrap();
    });
    provider.set_static(true);
    StorageHandle::enter(&mut provider, |storage| {
        assert!(matches!(
            mint(storage, &scope, BodyInput::Tribute(&body)),
            Err(PrecompileError::WriteProtection)
        ));
    });
    provider.set_static(false);
    StorageHandle::enter(&mut provider, |storage| {
        let schema = CompressedEntitiesSchema::new(storage.clone());
        assert_eq!(schema.touched.len().unwrap(), 0);
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 0);
        end_block(storage, &scope).unwrap();
    });
    assert!(provider.get_ordered_events().is_empty());
}

#[test]
fn explicit_gas_window_stops_a_system_transaction_before_it_exceeds_its_envelope() {
    let owner = address!("8300000000000000000000000000000000000008");
    let first = tribute(entity(14, 83), owner, 100);
    let second = tribute(entity(14, 84), owner, 101);
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_gas_limit(FIRST_TRIBUTE_CLEANUP_GAS * 2);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let window = scope
            .begin_explicit_gas_window(FIRST_TRIBUTE_CLEANUP_GAS)
            .expect("system transaction opens its CE gas window");

        mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();
        assert!(matches!(
            mint(storage.clone(), &scope, BodyInput::Tribute(&second)),
            Err(PrecompileError::OutOfGas)
        ));
        assert_eq!(window.gas_used().unwrap(), FIRST_TRIBUTE_CLEANUP_GAS);
        assert!(overlay_leaf(storage.clone(), Collection::Tribute, first.tribute_id).is_some());
        assert!(overlay_leaf(storage, Collection::Tribute, second.tribute_id).is_none());
    });
}

#[test]
fn ce_work_meter_reserves_unique_keys_and_restores_only_excluded_transactions() {
    let owner = address!("8400000000000000000000000000000000000008");
    let first = tribute(entity(14, 85), owner, 100);
    let second = tribute(entity(14, 86), owner, 101);
    let third = tribute(entity(14, 87), owner, 102);
    let tree = Arc::new(TestAuthenticatedTree::default());
    let scope = ExecutionScope::with_parent_tree(tree, CeWorkConfig::new(3, 4, 11));
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        assert_eq!(scope.ce_work_used().unwrap(), 3);
        mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();
        assert_eq!(scope.ce_work_used().unwrap(), 7);

        let excluded = scope.ce_work_checkpoint().unwrap();
        let excluded_result: Result<()> = storage.clone().with_checkpoint(|| {
            mint(storage.clone(), &scope, BodyInput::Tribute(&second))?;
            Err(PrecompileError::Revert(
                "payload builder excluded transaction".into(),
            ))
        });
        assert!(matches!(excluded_result, Err(PrecompileError::Revert(_))));
        assert_eq!(scope.ce_work_used().unwrap(), 11);
        scope.restore_ce_work_checkpoint(excluded).unwrap();
        assert_eq!(scope.ce_work_used().unwrap(), 7);
        assert!(overlay_leaf(storage.clone(), Collection::Tribute, second.tribute_id).is_none());

        mint(storage.clone(), &scope, BodyInput::Tribute(&third)).unwrap();
        assert_eq!(scope.ce_work_used().unwrap(), 11);
        assert!(matches!(
            mint(storage, &scope, BodyInput::Tribute(&second)),
            Err(PrecompileError::BlockCeWorkCapacityExhausted)
        ));
    });

    let too_small = ExecutionScope::with_parent_tree(
        Arc::new(TestAuthenticatedTree::default()),
        CeWorkConfig::new(3, 4, 6),
    );
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &too_small).unwrap();
        assert!(matches!(
            mint(storage, &too_small, BodyInput::Tribute(&first)),
            Err(PrecompileError::TransactionCeWorkLimitExceeded)
        ));
    });

    let multi_key = ExecutionScope::with_parent_tree(
        Arc::new(TestAuthenticatedTree::default()),
        CeWorkConfig::new(3, 4, 11),
    );
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &multi_key).unwrap();
        multi_key.begin_ce_work_transaction().unwrap();
        mint(storage.clone(), &multi_key, BodyInput::Tribute(&first)).unwrap();
        mint(storage.clone(), &multi_key, BodyInput::Tribute(&second)).unwrap();
        assert!(matches!(
            mint(storage.clone(), &multi_key, BodyInput::Tribute(&third)),
            Err(PrecompileError::TransactionCeWorkLimitExceeded)
        ));
        assert!(matches!(
            multi_key.take_ce_work_failure(),
            Some(PrecompileError::TransactionCeWorkLimitExceeded)
        ));
        multi_key.end_ce_work_transaction().unwrap();
    });

    let overlapping_transaction = ExecutionScope::with_parent_tree(
        Arc::new(TestAuthenticatedTree::default()),
        CeWorkConfig::new(3, 4, 11),
    );
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &overlapping_transaction).unwrap();
        overlapping_transaction.begin_ce_work_transaction().unwrap();
        mint(
            storage.clone(),
            &overlapping_transaction,
            BodyInput::Tribute(&first),
        )
        .unwrap();
        let first_capability = read(
            storage.clone(),
            &overlapping_transaction,
            &MemoryParent::default(),
            EntityRef::Tribute(first.tribute_id),
        )
        .unwrap()
        .unwrap();
        overlapping_transaction.end_ce_work_transaction().unwrap();

        overlapping_transaction.begin_ce_work_transaction().unwrap();
        delete(storage.clone(), &overlapping_transaction, first_capability).unwrap();
        mint(
            storage.clone(),
            &overlapping_transaction,
            BodyInput::Tribute(&second),
        )
        .unwrap();
        assert!(matches!(
            mint(
                storage,
                &overlapping_transaction,
                BodyInput::Tribute(&third)
            ),
            Err(PrecompileError::TransactionCeWorkLimitExceeded)
        ));
        assert!(matches!(
            overlapping_transaction.take_ce_work_failure(),
            Some(PrecompileError::TransactionCeWorkLimitExceeded)
        ));
        overlapping_transaction.end_ce_work_transaction().unwrap();
    });

    let remaining_capacity = ExecutionScope::with_parent_tree(
        Arc::new(TestAuthenticatedTree::default()),
        CeWorkConfig::new(3, 4, 11),
    );
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &remaining_capacity).unwrap();
        remaining_capacity.begin_ce_work_transaction().unwrap();
        mint(
            storage.clone(),
            &remaining_capacity,
            BodyInput::Tribute(&first),
        )
        .unwrap();
        remaining_capacity.end_ce_work_transaction().unwrap();

        remaining_capacity.begin_ce_work_transaction().unwrap();
        mint(
            storage.clone(),
            &remaining_capacity,
            BodyInput::Tribute(&second),
        )
        .unwrap();
        assert!(matches!(
            mint(storage, &remaining_capacity, BodyInput::Tribute(&third)),
            Err(PrecompileError::BlockCeWorkCapacityExhausted)
        ));
        assert!(matches!(
            remaining_capacity.take_ce_work_failure(),
            Some(PrecompileError::BlockCeWorkCapacityExhausted)
        ));
        remaining_capacity.end_ce_work_transaction().unwrap();
    });
}

#[derive(Clone, Copy)]
enum FaultMutation {
    Mint,
    Update,
    Delete,
}

#[derive(Clone, Copy)]
enum FaultPosition {
    Before,
    After,
}

fn prepare_fault_mutation(
    provider: &mut HashMapStorageProvider,
    scope: &ExecutionScope,
    original: &FixtureBody,
    mutation: FaultMutation,
) -> Option<VerifiedBody> {
    StorageHandle::enter(provider, |storage| {
        begin_block(storage.clone(), scope).unwrap();
        if matches!(mutation, FaultMutation::Mint) {
            return None;
        }
        mint(storage.clone(), scope, original.input()).unwrap();
        read(
            storage,
            scope,
            &MemoryParent::default(),
            original.entity_ref(),
        )
        .unwrap()
    })
}

fn apply_fault_mutation(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    original: &FixtureBody,
    updated: &FixtureBody,
    mutation: FaultMutation,
    capability: Option<VerifiedBody>,
) -> Result<()> {
    match mutation {
        FaultMutation::Mint => mint(storage, scope, original.input()),
        FaultMutation::Update => update(
            storage,
            scope,
            capability.expect("update fixture has a value capability"),
            updated.input(),
        ),
        FaultMutation::Delete => delete(
            storage,
            scope,
            capability.expect("delete fixture has a value capability"),
        ),
    }
}

fn arm_fault(provider: &mut HashMapStorageProvider, position: FaultPosition, operation: usize) {
    match position {
        FaultPosition::Before => provider.fail_mutation_at(operation),
        FaultPosition::After => provider.fail_after_mutation_at(operation),
    }
}

fn exercise_every_fault_boundary(
    original: &FixtureBody,
    updated: &FixtureBody,
    mutation: FaultMutation,
) {
    let mut baseline = HashMapStorageProvider::new(1);
    let baseline_scope = ExecutionScope::new();
    let capability = prepare_fault_mutation(&mut baseline, &baseline_scope, original, mutation);
    baseline.clear_mutation_failure();
    StorageHandle::enter(&mut baseline, |storage| {
        apply_fault_mutation(
            storage,
            &baseline_scope,
            original,
            updated,
            mutation,
            capability,
        )
        .unwrap();
    });
    let mutation_operations = baseline.clear_mutation_failure();
    assert!(mutation_operations > 0);

    for position in [FaultPosition::Before, FaultPosition::After] {
        for failure_at in 0..mutation_operations {
            let mut provider = HashMapStorageProvider::new(1);
            let scope = ExecutionScope::new();
            let capability = prepare_fault_mutation(&mut provider, &scope, original, mutation);
            let storage_before = provider.storage.clone();
            let events_before = provider.get_ordered_events().to_vec();
            provider.clear_mutation_failure();
            arm_fault(&mut provider, position, failure_at);

            let error = StorageHandle::enter(&mut provider, |storage| {
                apply_fault_mutation(storage, &scope, original, updated, mutation, capability)
                    .unwrap_err()
            });
            assert!(matches!(error, PrecompileError::Storage(_)));
            provider.clear_mutation_failure();
            assert_eq!(&provider.storage, &storage_before);
            assert_eq!(provider.get_ordered_events(), events_before);

            StorageHandle::enter(&mut provider, |storage| {
                let current = read(
                    storage.clone(),
                    &scope,
                    &MemoryParent::default(),
                    original.entity_ref(),
                )
                .unwrap();
                let schema = CompressedEntitiesSchema::new(storage.clone());
                if matches!(mutation, FaultMutation::Mint) {
                    assert!(current.is_none());
                    assert_eq!(schema.touched.len().unwrap(), 0);
                    assert_eq!(schema.touched_index_deltas.len().unwrap(), 0);
                } else {
                    original.assert_verified(&current.unwrap());
                    assert_eq!(schema.touched.len().unwrap(), 1);
                    assert_eq!(
                        schema.touched_index_deltas.len().unwrap(),
                        original.expected_index_touches()
                    );
                }
                end_block(storage, &scope).unwrap();
            });
        }
    }
}

#[test]
fn every_mutation_write_and_event_boundary_rolls_back_for_all_typed_collections() {
    let owner = address!("8a0000000000000000000000000000000000008a");
    let moved_owner = address!("8b0000000000000000000000000000000000008b");

    let tribute_original = tribute(entity(14, 0x8a), owner, 100);
    let mut tribute_updated = tribute(tribute_original.tribute_id, moved_owner, 200);
    tribute_updated.worldwide_day = tribute_original.worldwide_day;

    let nod_original = nod_item(entity(14, 0x8b), owner);
    let mut nod_updated = nod_original.clone();
    nod_updated.owner = moved_owner;
    nod_updated.gratis_load_minor = U256::from(99);

    let bucket_original = NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(0x8c),
        worldwide_day: WorldwideDay::new(14),
        floor_price_minor: U256::from(10),
        is_qualified: false,
        total_nods: 1,
        entry_price_minor: U256::from(11),
        reference_currency: 840,
    };
    let mut bucket_updated = bucket_original.clone();
    bucket_updated.is_qualified = true;

    for (original, updated) in [
        (
            FixtureBody::Tribute(tribute_original),
            FixtureBody::Tribute(tribute_updated),
        ),
        (
            FixtureBody::NodItem(nod_original),
            FixtureBody::NodItem(nod_updated),
        ),
        (
            FixtureBody::NodBucket(bucket_original),
            FixtureBody::NodBucket(bucket_updated),
        ),
    ] {
        for mutation in [
            FaultMutation::Mint,
            FaultMutation::Update,
            FaultMutation::Delete,
        ] {
            exercise_every_fault_boundary(&original, &updated, mutation);
        }
    }
}

fn populate_cleanup_fixture(
    provider: &mut HashMapStorageProvider,
    scope: &ExecutionScope,
    fixtures: &[FixtureBody],
) {
    StorageHandle::enter(provider, |storage| {
        begin_block(storage.clone(), scope).unwrap();
        for fixture in fixtures {
            mint(storage.clone(), scope, fixture.input()).unwrap();
        }
    });
}

#[test]
fn every_cleanup_write_boundary_rolls_back_the_complete_end_block_cleanup() {
    let owner = address!("8d0000000000000000000000000000000000008d");
    let fixtures = [
        FixtureBody::Tribute(tribute(entity(14, 0x8d), owner, 100)),
        FixtureBody::NodItem(nod_item(entity(14, 0x8e), owner)),
        FixtureBody::NodBucket(NodBucketBodyV1 {
            bucket_key: B256::repeat_byte(0x8f),
            worldwide_day: WorldwideDay::new(14),
            floor_price_minor: U256::from(10),
            is_qualified: false,
            total_nods: 1,
            entry_price_minor: U256::from(11),
            reference_currency: 840,
        }),
    ];

    let mut baseline = HashMapStorageProvider::new(1);
    let baseline_scope = ExecutionScope::new();
    populate_cleanup_fixture(&mut baseline, &baseline_scope, &fixtures);
    let baseline_preview = StorageHandle::enter(&mut baseline, |storage| {
        crate::preview_end_block(storage, &baseline_scope).unwrap()
    });
    baseline.clear_mutation_failure();
    let baseline_seal = StorageHandle::enter(&mut baseline, |storage| {
        end_block(storage, &baseline_scope).unwrap()
    });
    assert_eq!(baseline_seal, baseline_preview);
    let cleanup_operations = baseline.clear_mutation_failure();
    assert!(cleanup_operations > 0);

    for position in [FaultPosition::Before, FaultPosition::After] {
        for failure_at in 0..cleanup_operations {
            let mut provider = HashMapStorageProvider::new(1);
            let scope = ExecutionScope::new();
            populate_cleanup_fixture(&mut provider, &scope, &fixtures);
            let preview = StorageHandle::enter(&mut provider, |storage| {
                crate::preview_end_block(storage, &scope).unwrap()
            });
            let storage_before = provider.storage.clone();
            let events_before = provider.get_ordered_events().to_vec();
            provider.clear_mutation_failure();
            arm_fault(&mut provider, position, failure_at);

            let error = StorageHandle::enter(&mut provider, |storage| {
                end_block(storage, &scope).unwrap_err()
            });
            assert!(matches!(error, PrecompileError::Storage(_)));
            provider.clear_mutation_failure();
            assert_eq!(&provider.storage, &storage_before);
            assert_eq!(provider.get_ordered_events(), events_before);

            StorageHandle::enter(&mut provider, |storage| {
                let schema = CompressedEntitiesSchema::new(storage);
                assert_eq!(schema.touched.len().unwrap(), 3);
                assert_eq!(schema.touched_index_deltas.len().unwrap(), 4);
            });
            let retry =
                StorageHandle::enter(&mut provider, |storage| end_block(storage, &scope).unwrap());
            assert_eq!(retry, preview);
        }
    }
}

#[test]
fn storage_layout_uses_exact_slots_zero_through_thirteen() {
    let owner = address!("9000000000000000000000000000000000000009");
    let body = tribute(entity(15, 9), owner, 100);
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    let mut locator = B256::ZERO;

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage, &scope, BodyInput::Tribute(&body)).unwrap();
        locator = body_locator(Collection::Tribute, body.tribute_id).unwrap();
    });

    let pending_slot = locator.mapping_slot(U256::from(4));
    let identity_slot = locator.mapping_slot(U256::from(10));
    let identity_collection_slot = locator.mapping_slot(U256::from(13));
    assert_eq!(
        provider.storage[&(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO)],
        U256::from(4)
    );
    assert_eq!(
        provider
            .storage
            .get(&(COMPRESSED_ENTITIES_ADDRESS, U256::from(1)))
            .copied()
            .unwrap_or_default(),
        U256::from_be_slice(crate::sealed_root(B256::ZERO).unwrap().as_slice())
    );
    for reserved in [U256::from(2), U256::from(3)] {
        assert_eq!(
            provider
                .storage
                .get(&(COMPRESSED_ENTITIES_ADDRESS, reserved))
                .copied()
                .unwrap_or_default(),
            U256::ZERO
        );
    }
    assert_eq!(
        provider.storage[&(COMPRESSED_ENTITIES_ADDRESS, pending_slot)],
        tribute_commitment(&body).to_u256()
    );
    assert_eq!(
        provider.storage[&(COMPRESSED_ENTITIES_ADDRESS, U256::from(6))],
        U256::from(1)
    );
    // One word each: the identity at slot 10 and its collection marker at 13.
    assert_eq!(
        provider.storage[&(COMPRESSED_ENTITIES_ADDRESS, identity_slot)],
        body.tribute_id.to_u256()
    );
    assert_eq!(
        provider.storage[&(COMPRESSED_ENTITIES_ADDRESS, identity_collection_slot)],
        U256::from(Collection::Tribute.id())
    );
    // No base slot exists beyond 13.
    assert!(!provider
        .storage
        .contains_key(&(COMPRESSED_ENTITIES_ADDRESS, U256::from(14))));
}

#[test]
fn first_touch_lists_preserve_the_exact_deterministic_operation_order() {
    let owner = address!("7f00000000000000000000000000000000000007");
    let first = tribute(entity(24, 1), owner, 10);
    let second = tribute(entity(24, 2), owner, 20);
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&second)).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&first)).unwrap();

        let schema = CompressedEntitiesSchema::new(storage.clone());
        assert_eq!(schema.touched.len().unwrap(), 2);
        assert_eq!(
            schema.touched.get(0).unwrap(),
            Some(body_locator(Collection::Tribute, second.tribute_id).unwrap())
        );
        assert_eq!(
            schema.touched.get(1).unwrap(),
            Some(body_locator(Collection::Tribute, first.tribute_id).unwrap())
        );

        let expected_indexes = [
            IndexRecord::owner(IndexKind::TributeByOwner, owner, second.tribute_id).key(),
            IndexRecord::day(second.worldwide_day, second.tribute_id).key(),
            IndexRecord::owner(IndexKind::TributeByOwner, owner, first.tribute_id).key(),
            IndexRecord::day(first.worldwide_day, first.tribute_id).key(),
        ];
        assert_eq!(schema.touched_index_deltas.len().unwrap(), 4);
        for (index, expected) in expected_indexes.into_iter().enumerate() {
            assert_eq!(
                schema
                    .touched_index_deltas
                    .get(u32::try_from(index).unwrap())
                    .unwrap(),
                Some(expected)
            );
        }

        end_block(storage, &scope).unwrap();
    });
}

#[test]
fn body_codecs_cover_all_three_closed_variants() {
    let owner = address!("a00000000000000000000000000000000000000a");
    let item = nod_item(entity(16, 10), owner);
    let bucket = NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(11),
        worldwide_day: WorldwideDay::new(16),
        floor_price_minor: U256::from(12),
        is_qualified: true,
        total_nods: 13,
        entry_price_minor: U256::from(14),
        reference_currency: 840,
    };
    assert!(!encode_nod_item_v1(&item).unwrap().is_empty());
    assert!(!encode_nod_bucket_v1(&bucket).unwrap().is_empty());
    // Pin the central event signatures independently from their Rust types.
    assert_eq!(
        TributeBodyStored::SIGNATURE_HASH,
        keccak256("TributeBodyStored(uint256,uint32,uint32,bytes32,bytes32,bytes)")
    );
    assert_eq!(
        NodBodyStored::SIGNATURE_HASH,
        keccak256("NodBodyStored(uint256,uint32,uint32,bytes32,bytes32,bytes)")
    );
}

#[test]
fn exact_overlay_locator_and_record_vectors_are_protocol_pinned() {
    let id = WwdEntityId::from_day_and_digest(WorldwideDay::new(42), [0x11; 32]);
    let cases = [
        (
            Collection::Tribute,
            b256!("efe7430ecc84638c827107a7b8c81e65149beafaaa94bf3ccdd5a7ce047a7e27"),
        ),
        (
            Collection::NodItem,
            b256!("d6a30f530d7d202867408fcdb9dd825155f914cd830a3b5db6f599e710ef27ba"),
        ),
        (
            Collection::NodBucket,
            b256!("c4f00d37b7f206de8ac85d35728a73ecba6856f54bd9ead4fd2a42e80562f32f"),
        ),
    ];

    for (collection, expected_locator) in cases {
        assert_eq!(body_locator(collection, id).unwrap(), expected_locator);
    }
}

#[test]
fn exact_index_record_key_and_status_vectors_are_protocol_pinned() {
    let id = WwdEntityId::from_day_and_digest(WorldwideDay::new(42), [0x11; 32]);
    let owner = Address::repeat_byte(0x22);
    let cases = [
        (
            IndexRecord::owner(IndexKind::TributeByOwner, owner, id),
            concat!(
                "010114",
                "2222222222222222222222222222222222222222",
                "0000002a",
                "11111111111111111111111111111111111111111111111111111111"
            ),
            b256!("c3acc7bd8c73c96af18b80b2415d643c6d68e64573cc620ed0e086b13b79e165"),
        ),
        (
            IndexRecord::day(WorldwideDay::new(42), id),
            concat!(
                "0102040000002a0000002a",
                "11111111111111111111111111111111111111111111111111111111"
            ),
            b256!("b31e3d821bf8623570743703cba38e51b5f66dbed443719bc06b95f7405148bb"),
        ),
        (
            IndexRecord::owner(IndexKind::NodByOwner, owner, id),
            concat!(
                "010314",
                "2222222222222222222222222222222222222222",
                "0000002a",
                "11111111111111111111111111111111111111111111111111111111"
            ),
            b256!("d74fd5e8d1103a315a0503320b48ae5d88cd7a48ce67781bd9c8b6bbd2868ae6"),
        ),
        (
            IndexRecord::nod_all(id),
            concat!(
                "0104000000002a",
                "11111111111111111111111111111111111111111111111111111111"
            ),
            b256!("638c71f7b03c234465ab777494472e896c80f87cf31e7afb7a8b2b441ccd661f"),
        ),
    ];

    for (record, expected_hex, expected_key) in cases {
        let expected = hex::decode(expected_hex).unwrap();
        assert_eq!(record.encode(), expected);
        assert_eq!(IndexRecord::decode(&expected).unwrap(), record);
        assert_eq!(record.key(), expected_key);
    }

    let commitment = tribute_commitment(&tribute(id, owner, 1));
    assert_eq!(PendingWord::Untouched.encode(), U256::ZERO);
    assert_eq!(PendingWord::Set(commitment).encode(), commitment.to_u256());
    assert_eq!(PendingWord::Deleted.encode(), U256::MAX);
    for (word, expected) in [
        (U256::ZERO, PendingWord::Untouched),
        (commitment.to_u256(), PendingWord::Set(commitment)),
        (U256::MAX, PendingWord::Deleted),
    ] {
        assert_eq!(PendingWord::decode(word).unwrap(), expected);
    }
    for (status, word) in [
        (DeltaStatus::NeverTouched, 0_u64),
        (DeltaStatus::Added, 1),
        (DeltaStatus::Removed, 2),
        (DeltaStatus::NoChangeTouched, 3),
    ] {
        assert_eq!(status.encode(), U256::from(word));
        assert_eq!(DeltaStatus::decode(U256::from(word)).unwrap(), status);
    }
}

#[test]
fn overlay_wire_decoders_reject_every_noncanonical_boundary_class() {
    let id = WwdEntityId::from_day_and_digest(WorldwideDay::new(42), [0x11; 32]);
    let owner = Address::repeat_byte(0x22);
    let modulus = U256::from_be_bytes::<32>(
        hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    for invalid in [modulus, modulus + U256::from(1), U256::MAX - U256::from(1)] {
        assert!(matches!(
            PendingWord::decode(invalid),
            Err(PrecompileError::Fatal(_))
        ));
    }
    for invalid in [U256::from(4), U256::from(u64::MAX), U256::MAX] {
        assert!(matches!(
            DeltaStatus::decode(invalid),
            Err(PrecompileError::Fatal(_))
        ));
    }

    for invalid in [0_u8, 4, u8::MAX] {
        assert!(
            matches!(Collection::from_id(invalid), Err(PrecompileError::Fatal(_))),
            "collection id {invalid} must not decode"
        );
    }

    let valid_index = IndexRecord::owner(IndexKind::TributeByOwner, owner, id).encode();
    for invalid in [
        valid_index[..38].to_vec(),
        {
            let mut value = valid_index.clone();
            value[0] = 2;
            value
        },
        {
            let mut value = valid_index.clone();
            value[1] = 9;
            value
        },
        {
            let mut value = valid_index.clone();
            value[2] = 19;
            value
        },
        {
            let mut value = valid_index.clone();
            value.push(0);
            value
        },
    ] {
        assert!(matches!(
            IndexRecord::decode(&invalid),
            Err(PrecompileError::Fatal(_))
        ));
    }
}

#[test]
fn maximum_v1_body_footprint_and_storage_tail_cleanup_are_exact() {
    let day = WorldwideDay::new(u32::MAX);
    let id = WwdEntityId::from_day_and_digest(day, [0xff; 32]);
    let maximum = NodItemBodyV1 {
        nod_id: id,
        owner: Address::repeat_byte(0xff),
        gratis_load_minor: U256::MAX,
        worldwide_day: day,
        league_id: u16::MAX,
        floor_price_minor: U256::MAX,
        bucket_key: B256::repeat_byte(0xff),
        issuance_currency: u16::MAX,
        reference_currency: u16::MAX,
        issued_at: u64::MAX,
    };
    let maximum_stored = StoredBody::new_v1(encode_nod_item_v1(&maximum).unwrap())
        .unwrap()
        .encode();
    assert_eq!(maximum_stored.len(), MAX_STORED_BODY_BYTES_V1);

    // The reserve only covers the tail it prepays for, so the Nod item has to
    // stay the largest of the three v1 bodies.
    let widest_tribute = TributeBodyV1 {
        tribute_id: id,
        owner: Address::repeat_byte(0xff),
        worldwide_day: day,
        issuance_amount_minor: U256::MAX,
        issuance_currency: u16::MAX,
        nominal_amount_minor: U256::MAX,
        reference_currency: u16::MAX,
        tribute_price_minor: U256::MAX,
        exclude_from_intex_issuance: true,
    };
    assert!(stored_tribute(&widest_tribute).encode().len() <= MAX_STORED_BODY_BYTES_V1);
    assert!(
        StoredBody::new_v1(encode_nod_bucket_v1(&widest_bucket(day)).unwrap())
            .unwrap()
            .encode()
            .len()
            <= MAX_STORED_BODY_BYTES_V1
    );

    let scope = ExecutionScope::new();
    let parent = MemoryParent::default();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::NodItem(&maximum)).unwrap();
        let locator = body_locator(Collection::NodItem, id).unwrap();
        let base = locator.mapping_slot(U256::from(5));
        let data_start = U256::from_be_bytes(keccak256(base.to_be_bytes::<32>()).0);
        let maximum_slots = maximum_stored.len().div_ceil(32);
        assert_eq!(
            CompressedEntitiesSchema::new(storage.clone())
                .pending_body
                .get_bytes(&locator)
                .read()
                .unwrap(),
            maximum_stored
        );
        assert!(!storage
            .sload(
                COMPRESSED_ENTITIES_ADDRESS,
                data_start + U256::from(maximum_slots - 1),
            )
            .unwrap()
            .is_zero());

        let cap = read(storage.clone(), &scope, &parent, EntityRef::NodItem(id))
            .unwrap()
            .unwrap();
        delete(storage.clone(), &scope, cap).unwrap();
        for slot in 0..maximum_slots {
            assert!(storage
                .sload(COMPRESSED_ENTITIES_ADDRESS, data_start + U256::from(slot))
                .unwrap()
                .is_zero());
        }

        mint(storage.clone(), &scope, BodyInput::NodItem(&maximum)).unwrap();
        end_block(storage.clone(), &scope).unwrap();
        assert!(storage
            .sload(COMPRESSED_ENTITIES_ADDRESS, base)
            .unwrap()
            .is_zero());
        for slot in 0..maximum_slots {
            assert!(storage
                .sload(COMPRESSED_ENTITIES_ADDRESS, data_start + U256::from(slot))
                .unwrap()
                .is_zero());
        }
    });
}

fn widest_bucket(day: WorldwideDay) -> NodBucketBodyV1 {
    NodBucketBodyV1 {
        bucket_key: B256::repeat_byte(0xff),
        worldwide_day: day,
        floor_price_minor: U256::MAX,
        is_qualified: true,
        total_nods: u64::MAX,
        entry_price_minor: U256::MAX,
        reference_currency: u16::MAX,
    }
}

/// A shrinking body must zero the slots it frees. The bucket carries this: it
/// is the one v1 body whose widest and narrowest forms differ by a whole slot,
/// so a stale tail would survive here and nowhere else.
#[test]
fn shrinking_a_body_zeroes_the_storage_tail_it_frees() {
    let day = WorldwideDay::new(u32::MAX);
    let widest = widest_bucket(day);
    let narrowest = NodBucketBodyV1 {
        bucket_key: widest.bucket_key,
        worldwide_day: day,
        floor_price_minor: U256::ZERO,
        is_qualified: false,
        total_nods: 1,
        entry_price_minor: U256::ZERO,
        reference_currency: 0,
    };
    let stored = |body: &NodBucketBodyV1| {
        StoredBody::new_v1(encode_nod_bucket_v1(body).unwrap())
            .unwrap()
            .encode()
            .len()
            .div_ceil(32)
    };
    let widest_slots = stored(&widest);
    let narrowest_slots = stored(&narrowest);
    assert!(narrowest_slots < widest_slots);

    let id = widest.entity_id();
    let scope = ExecutionScope::new();
    let parent = MemoryParent::default();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::NodBucket(&widest)).unwrap();
        let locator = body_locator(Collection::NodBucket, id).unwrap();
        let base = locator.mapping_slot(U256::from(5));
        let data_start = U256::from_be_bytes(keccak256(base.to_be_bytes::<32>()).0);
        let cap = read(storage.clone(), &scope, &parent, EntityRef::NodBucket(id))
            .unwrap()
            .unwrap();
        update(
            storage.clone(),
            &scope,
            cap,
            BodyInput::NodBucket(&narrowest),
        )
        .unwrap();
        for slot in narrowest_slots..widest_slots {
            assert!(storage
                .sload(COMPRESSED_ENTITIES_ADDRESS, data_start + U256::from(slot))
                .unwrap()
                .is_zero());
        }
    });
}

#[test]
fn golden_read_list_and_first_touch_gas_coefficients_are_exact() {
    assert_eq!(READ_FIXED_GAS, 200);
    assert_eq!(READ_GAS_PER_CANONICAL_BYTE, 8);
    assert_eq!(INDEX_RECORD_SCAN_GAS, 300);
    assert_eq!(PARENT_ID_GAS, 120);
    assert_eq!(FIRST_BODY_TOUCH_CLEANUP_GAS, 55_000);
    assert_eq!(BODY_TOUCHED_LENGTH_CLEANUP_GAS, 5_000);
    assert_eq!(FIRST_INDEX_TOUCH_CLEANUP_GAS, 25_000);
    assert_eq!(INDEX_TOUCHED_LENGTH_CLEANUP_GAS, 5_000);

    let owner = address!("b00000000000000000000000000000000000000b");
    let overlay = tribute(entity(20, 4), owner, 100);
    let overlay_bytes = stored_tribute(&overlay).encode().len() as u64;
    let parent_a = tribute(entity(20, 2), owner, 200);
    let parent_b = tribute(entity(20, 3), owner, 300);
    let parent_bytes = [stored_tribute(&parent_a), stored_tribute(&parent_b)]
        .map(|body| body.encode().len() as u64);
    let mut parent = MemoryParent::default();
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_gas_limit(u64::MAX);
    let tree = Arc::new(TestAuthenticatedTree::default());
    let scope = scope_with_tree(tree.clone());

    StorageHandle::enter(&mut provider, |storage| {
        seed_parent_tribute(&mut parent, tree.as_ref(), &parent_a);
        seed_parent_tribute(&mut parent, tree.as_ref(), &parent_b);
        begin_block(storage.clone(), &scope).unwrap();
        let first_touch = scope.explicit_gas_checkpoint();
        mint(storage.clone(), &scope, BodyInput::Tribute(&overlay)).unwrap();
        assert_eq!(
            scope.explicit_gas_since(first_touch).unwrap(),
            FIRST_BODY_TOUCH_CLEANUP_GAS
                + BODY_TOUCHED_LENGTH_CLEANUP_GAS
                + 2 * FIRST_INDEX_TOUCH_CLEANUP_GAS
                + INDEX_TOUCHED_LENGTH_CLEANUP_GAS,
            "60k body + 5k first body-list length + 2*25k indexes + 5k first index-list length"
        );

        let overlay_read = scope.explicit_gas_checkpoint();
        read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(overlay.tribute_id),
        )
        .unwrap();
        let read_charge = READ_FIXED_GAS + READ_GAS_PER_CANONICAL_BYTE * overlay_bytes;
        assert_eq!(scope.explicit_gas_since(overlay_read).unwrap(), read_charge);

        let repeat = scope.explicit_gas_checkpoint();
        let cap = read(
            storage.clone(),
            &scope,
            &parent,
            EntityRef::Tribute(overlay.tribute_id),
        )
        .unwrap()
        .unwrap();
        update(storage.clone(), &scope, cap, BodyInput::Tribute(&overlay)).unwrap();
        assert_eq!(scope.explicit_gas_since(repeat).unwrap(), read_charge);

        let delta_scan = scope.explicit_gas_checkpoint();
        list(
            storage.clone(),
            &scope,
            &parent,
            QueryRef::TributeByOwner(owner),
            IdPageRequest {
                after: Some(parent_b.tribute_id),
                limit: 10,
            },
        )
        .unwrap();
        assert_eq!(
            scope.explicit_gas_since(delta_scan).unwrap(),
            2 * INDEX_RECORD_SCAN_GAS + read_charge
        );

        let parent_page = scope.explicit_gas_checkpoint();
        list(
            storage,
            &scope,
            &parent,
            QueryRef::TributeByOwner(owner),
            IdPageRequest {
                after: None,
                limit: 2,
            },
        )
        .unwrap();
        assert_eq!(
            scope.explicit_gas_since(parent_page).unwrap(),
            2 * INDEX_RECORD_SCAN_GAS
                + 2 * PARENT_ID_GAS
                + parent_bytes
                    .into_iter()
                    .map(|bytes| READ_FIXED_GAS + READ_GAS_PER_CANONICAL_BYTE * bytes)
                    .sum::<u64>()
        );
    });

    let mut body_length_oog = HashMapStorageProvider::new(1);
    body_length_oog
        .set_gas_limit(FIRST_BODY_TOUCH_CLEANUP_GAS + BODY_TOUCHED_LENGTH_CLEANUP_GAS - 1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut body_length_oog, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let checkpoint = scope.explicit_gas_checkpoint();
        assert!(matches!(
            mint(storage.clone(), &scope, BodyInput::Tribute(&overlay)),
            Err(PrecompileError::OutOfGas)
        ));
        assert_eq!(scope.explicit_gas_since(checkpoint).unwrap(), 0);
        assert!(overlay_leaf(storage.clone(), Collection::Tribute, overlay.tribute_id).is_none());
        assert!(CompressedEntitiesSchema::new(storage)
            .touched
            .is_empty()
            .unwrap());
    });

    let mut index_length_oog = HashMapStorageProvider::new(1);
    index_length_oog.set_gas_limit(
        FIRST_BODY_TOUCH_CLEANUP_GAS
            + BODY_TOUCHED_LENGTH_CLEANUP_GAS
            + FIRST_INDEX_TOUCH_CLEANUP_GAS
            + INDEX_TOUCHED_LENGTH_CLEANUP_GAS
            - 1,
    );
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut index_length_oog, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let checkpoint = scope.explicit_gas_checkpoint();
        assert!(matches!(
            mint(storage.clone(), &scope, BodyInput::Tribute(&overlay)),
            Err(PrecompileError::OutOfGas)
        ));
        assert_eq!(
            scope.explicit_gas_since(checkpoint).unwrap(),
            FIRST_BODY_TOUCH_CLEANUP_GAS + BODY_TOUCHED_LENGTH_CLEANUP_GAS
        );
        let schema = CompressedEntitiesSchema::new(storage.clone());
        assert!(schema.touched.is_empty().unwrap());
        assert!(schema.touched_index_deltas.is_empty().unwrap());
        assert!(overlay_leaf(storage, Collection::Tribute, overlay.tribute_id).is_none());
    });
}

#[test]
fn all_four_query_kinds_resolve_same_block_membership_and_overlay_bodies() {
    let owner = address!("c00000000000000000000000000000000000000c");
    let tribute = tribute(entity(21, 1), owner, 100);
    let nod = nod_item(entity(21, 2), owner);
    let parent = MemoryParent::default();
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&tribute)).unwrap();
        mint(storage.clone(), &scope, BodyInput::NodItem(&nod)).unwrap();
        for (query, expected) in [
            (QueryRef::TributeByOwner(owner), tribute.tribute_id),
            (
                QueryRef::TributeByDay(tribute.worldwide_day),
                tribute.tribute_id,
            ),
            (QueryRef::NodByOwner(owner), nod.nod_id),
            (QueryRef::NodAll, nod.nod_id),
        ] {
            let page = list(
                storage.clone(),
                &scope,
                &parent,
                query,
                IdPageRequest {
                    after: None,
                    limit: 10,
                },
            )
            .unwrap();
            assert_eq!(
                page.bodies()
                    .iter()
                    .map(|body| body.entity_id())
                    .collect::<Vec<_>>(),
                vec![expected]
            );
            assert_eq!(page.next_after(), None);
        }
    });
}

#[test]
fn all_four_query_kinds_merge_non_empty_parent_pages_with_exact_pagination() {
    let owner = address!("c10000000000000000000000000000000000000c");

    let tribute_parent = [
        tribute(entity(24, 1), owner, 101),
        tribute(entity(24, 3), owner, 103),
        tribute(entity(24, 5), owner, 105),
    ];
    let tribute_added = tribute(entity(24, 2), owner, 102);
    let mut tribute_source = MemoryParent::default();
    let tribute_tree = Arc::new(TestAuthenticatedTree::default());
    let tribute_scope = scope_with_tree(tribute_tree.clone());
    let mut tribute_provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut tribute_provider, |storage| {
        for body in &tribute_parent {
            seed_parent_tribute(&mut tribute_source, tribute_tree.as_ref(), body);
        }
        begin_block(storage.clone(), &tribute_scope).unwrap();
        let removed = read(
            storage.clone(),
            &tribute_scope,
            &tribute_source,
            EntityRef::Tribute(tribute_parent[1].tribute_id),
        )
        .unwrap()
        .unwrap();
        delete(storage.clone(), &tribute_scope, removed).unwrap();
        mint(
            storage.clone(),
            &tribute_scope,
            BodyInput::Tribute(&tribute_added),
        )
        .unwrap();

        for query in [
            QueryRef::TributeByOwner(owner),
            QueryRef::TributeByDay(WorldwideDay::new(24)),
        ] {
            let first = list(
                storage.clone(),
                &tribute_scope,
                &tribute_source,
                query,
                IdPageRequest {
                    after: None,
                    limit: 2,
                },
            )
            .unwrap();
            assert_eq!(
                first
                    .bodies()
                    .iter()
                    .map(VerifiedBody::entity_id)
                    .collect::<Vec<_>>(),
                vec![tribute_parent[0].tribute_id, tribute_added.tribute_id]
            );
            assert_eq!(first.next_after(), Some(tribute_added.tribute_id));
            assert_eq!(
                first.bodies()[1].payload().as_tribute(),
                Some(&tribute_added)
            );

            let second = list(
                storage.clone(),
                &tribute_scope,
                &tribute_source,
                query,
                IdPageRequest {
                    after: first.next_after(),
                    limit: 2,
                },
            )
            .unwrap();
            assert_eq!(
                second
                    .bodies()
                    .iter()
                    .map(VerifiedBody::entity_id)
                    .collect::<Vec<_>>(),
                vec![tribute_parent[2].tribute_id]
            );
            assert_eq!(second.next_after(), None);
        }
    });
    assert!(tribute_source.list_calls.get() >= 6);

    let nod_parent = [
        nod_item(entity(25, 1), owner),
        nod_item(entity(25, 3), owner),
        nod_item(entity(25, 5), owner),
    ];
    let nod_added = nod_item(entity(25, 2), owner);
    let mut nod_source = MemoryParent::default();
    let nod_tree = Arc::new(TestAuthenticatedTree::default());
    let nod_scope = scope_with_tree(nod_tree.clone());
    let mut nod_provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut nod_provider, |storage| {
        for body in &nod_parent {
            seed_parent_nod_item(&mut nod_source, nod_tree.as_ref(), body);
        }
        begin_block(storage.clone(), &nod_scope).unwrap();
        let removed = read(
            storage.clone(),
            &nod_scope,
            &nod_source,
            EntityRef::NodItem(nod_parent[1].nod_id),
        )
        .unwrap()
        .unwrap();
        delete(storage.clone(), &nod_scope, removed).unwrap();
        mint(storage.clone(), &nod_scope, BodyInput::NodItem(&nod_added)).unwrap();

        for query in [QueryRef::NodByOwner(owner), QueryRef::NodAll] {
            let first = list(
                storage.clone(),
                &nod_scope,
                &nod_source,
                query,
                IdPageRequest {
                    after: None,
                    limit: 2,
                },
            )
            .unwrap();
            assert_eq!(
                first
                    .bodies()
                    .iter()
                    .map(VerifiedBody::entity_id)
                    .collect::<Vec<_>>(),
                vec![nod_parent[0].nod_id, nod_added.nod_id]
            );
            assert_eq!(first.next_after(), Some(nod_added.nod_id));
            assert_eq!(first.bodies()[1].payload().as_nod_item(), Some(&nod_added));

            let second = list(
                storage.clone(),
                &nod_scope,
                &nod_source,
                query,
                IdPageRequest {
                    after: first.next_after(),
                    limit: 2,
                },
            )
            .unwrap();
            assert_eq!(
                second
                    .bodies()
                    .iter()
                    .map(VerifiedBody::entity_id)
                    .collect::<Vec<_>>(),
                vec![nod_parent[2].nod_id]
            );
            assert_eq!(second.next_after(), None);
        }
    });
    assert!(nod_source.list_calls.get() >= 6);
}

#[test]
fn pagination_and_parent_corruption_boundaries_fail_closed() {
    let owner = address!("d00000000000000000000000000000000000000d");
    let id = entity(22, 1);
    let wrong_day = entity(23, 1);

    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let parent = MemoryParent::default();
        assert!(matches!(
            list(
                storage,
                &scope,
                &parent,
                QueryRef::TributeByDay(WorldwideDay::new(22)),
                IdPageRequest {
                    after: Some(wrong_day),
                    limit: 1,
                },
            ),
            Err(PrecompileError::Revert(_))
        ));
    });

    for (page, query) in [
        (
            IdPage {
                ids: vec![id, entity(22, 2)],
                next_after: None,
            },
            QueryRef::TributeByOwner(owner),
        ),
        (
            IdPage {
                ids: vec![id],
                next_after: Some(entity(22, 2)),
            },
            QueryRef::TributeByOwner(owner),
        ),
        (
            IdPage {
                ids: Vec::new(),
                next_after: Some(id),
            },
            QueryRef::TributeByOwner(owner),
        ),
        (
            IdPage {
                ids: vec![wrong_day],
                next_after: None,
            },
            QueryRef::TributeByDay(WorldwideDay::new(22)),
        ),
    ] {
        let scripted = ScriptedParent {
            pages: RefCell::new(VecDeque::from([page])),
            ..ScriptedParent::default()
        };
        let scope = ExecutionScope::new();
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            begin_block(storage.clone(), &scope).unwrap();
            assert!(matches!(
                list(
                    storage,
                    &scope,
                    &scripted,
                    query,
                    IdPageRequest {
                        after: None,
                        limit: 1,
                    },
                ),
                Err(PrecompileError::BodyReadCorruption(_))
            ));
        });
    }

    let body = tribute(id, owner, 100);
    let scripted = ScriptedParent {
        pages: RefCell::new(VecDeque::from([IdPage {
            ids: vec![id],
            next_after: None,
        }])),
        ..ScriptedParent::default()
    };
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        mint(storage.clone(), &scope, BodyInput::Tribute(&body)).unwrap();
        assert!(matches!(
            list(
                storage,
                &scope,
                &scripted,
                QueryRef::TributeByOwner(owner),
                IdPageRequest {
                    after: None,
                    limit: 1,
                },
            ),
            Err(PrecompileError::BodyReadCorruption(_))
        ));
    });

    let scripted = ScriptedParent {
        bodies: HashMap::from([(EntityRef::Tribute(id), stored_tribute(&body))]),
        pages: RefCell::new(VecDeque::from([IdPage {
            ids: Vec::new(),
            next_after: None,
        }])),
    };
    let tree = Arc::new(TestAuthenticatedTree::default());
    tree.insert(EntityRef::Tribute(id), tribute_commitment(&body));
    let scope = scope_with_tree(tree);
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        let cap = read(storage.clone(), &scope, &scripted, EntityRef::Tribute(id))
            .unwrap()
            .unwrap();
        delete(storage.clone(), &scope, cap).unwrap();
        assert!(matches!(
            list(
                storage,
                &scope,
                &scripted,
                QueryRef::TributeByOwner(owner),
                IdPageRequest {
                    after: None,
                    limit: 1,
                },
            ),
            Err(PrecompileError::BodyReadCorruption(_))
        ));
    });

    let wrong_owner_body = tribute(
        id,
        address!("9900000000000000000000000000000000000009"),
        100,
    );
    let scripted = ScriptedParent {
        bodies: HashMap::from([(EntityRef::Tribute(id), stored_tribute(&wrong_owner_body))]),
        pages: RefCell::new(VecDeque::from([IdPage {
            ids: vec![id],
            next_after: None,
        }])),
    };
    let tree = Arc::new(TestAuthenticatedTree::default());
    tree.insert(
        EntityRef::Tribute(id),
        tribute_commitment(&wrong_owner_body),
    );
    let scope = scope_with_tree(tree);
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        begin_block(storage.clone(), &scope).unwrap();
        assert!(matches!(
            list(
                storage,
                &scope,
                &scripted,
                QueryRef::TributeByOwner(owner),
                IdPageRequest {
                    after: None,
                    limit: 1,
                },
            ),
            Err(PrecompileError::BodyReadCorruption(_))
        ));
    });
}
