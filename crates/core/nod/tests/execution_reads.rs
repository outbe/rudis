use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    begin_block, EntityRef, ExecutionScope, IdPage, IdPageRequest, ParentBodySource,
    ParentBodySourceError, QueryRef, StoredBody, WwdEntityId,
};
use outbe_nod::{
    api, constants::MAX_BUCKET_QUALIFICATIONS_PER_BLOCK, hooks, precompile::INod, NodContract,
    NodItemState, NodRepositoryReader,
};
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::{COMPRESSED_ENTITIES_ADDRESS, NOD_ADDRESS},
    block::{BlockContext, BlockRuntimeContext},
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

fn item(owner: Address, day: WorldwideDay) -> NodItemState {
    let nod_id = NodContract::generate_nod_id(owner, day).unwrap();
    NodItemState {
        nod_id,
        owner,
        gratis_load_minor: U256::from(11),
        worldwide_day: day,
        league_id: 4,
        floor_price_minor: U256::from(13),
        bucket_key: NodContract::bucket_key(day, U256::from(13), 978),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 1_752_534_000,
    }
}

fn active_world() -> (HashMapStorageProvider, ExecutionScope, NodRepositoryReader) {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage;
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(
                    outbe_compressed_entities::sealed_root(B256::ZERO)
                        .unwrap()
                        .as_slice(),
                ),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    (provider, scope, NodRepositoryReader::new(reader))
}

#[test]
fn same_block_issue_is_visible_to_point_and_list_reads() {
    let (mut provider, scope, parent) = active_world();
    let body = item(Address::repeat_byte(0x21), WorldwideDay::new(20_260_716));

    StorageHandle::enter(&mut provider, |storage| {
        api::add_nod(&storage, &scope, &parent, &body, U256::from(5)).unwrap();
        assert_eq!(
            api::get_item(&storage, &scope, &parent, body.nod_id)
                .unwrap()
                .unwrap()
                .owner,
            body.owner
        );
        assert_eq!(
            api::list_by_owner(&storage, &scope, &parent, body.owner)
                .unwrap()
                .into_iter()
                .map(|item| item.nod_id)
                .collect::<Vec<_>>(),
            [body.nod_id]
        );
        assert_eq!(api::list_all(&storage, &scope, &parent).unwrap().len(), 1);
    });

    let signatures: Vec<_> = provider
        .get_events(NOD_ADDRESS)
        .iter()
        .map(|event| event.topics()[0])
        .collect();
    assert_eq!(
        signatures,
        [
            INod::NodBodyStored::SIGNATURE_HASH,
            INod::NodBucketBodyStored::SIGNATURE_HASH,
        ]
    );
}

#[test]
fn qualification_updates_the_overlay_and_keeps_the_product_event() {
    let (mut provider, scope, parent) = active_world();
    let body = item(Address::repeat_byte(0x31), WorldwideDay::new(20_260_716));
    StorageHandle::enter(&mut provider, |storage| {
        api::add_nod(&storage, &scope, &parent, &body, U256::from(5)).unwrap();
        let context = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(1, 1_752_534_000, 1),
            storage.clone(),
        );
        let inspected = hooks::qualify_buckets_with_rate(
            &context,
            &scope,
            &parent,
            body.reference_currency,
            body.floor_price_minor + U256::from(1),
            MAX_BUCKET_QUALIFICATIONS_PER_BLOCK,
        )
        .unwrap();
        assert_eq!(inspected, 1);
        let bucket_id = WwdEntityId::from_day_and_digest(body.worldwide_day, body.bucket_key.0);
        assert!(
            api::get_bucket(&storage, &scope, &parent, bucket_id)
                .unwrap()
                .unwrap()
                .is_qualified
        );

        // A different reference currency walks its own trie and sees nothing,
        // even though the floor value is identical.
        assert_eq!(
            hooks::qualify_buckets_with_rate(
                &context,
                &scope,
                &parent,
                840,
                body.floor_price_minor + U256::from(1),
                MAX_BUCKET_QUALIFICATIONS_PER_BLOCK,
            )
            .unwrap(),
            0
        );
    });
    assert!(provider
        .get_events(NOD_ADDRESS)
        .iter()
        .any(|event| event.topics()[0] == INod::NodBucketQualified::SIGNATURE_HASH));
}

#[test]
fn qualification_takes_only_own_currency_buckets_strictly_below_the_rate() {
    let (mut provider, scope, parent) = active_world();
    let day = WorldwideDay::new(20_260_716);
    // (owner byte, reference currency, floor price).
    let specs = [
        (0x51u8, 840u16, 1000u64),
        (0x52, 978, 1200),
        (0x53, 840, 1250),
        (0x54, 840, 1300),
        (0x55, 978, 1300),
        // Shares the rate's bin, so it exercises the tail-bin exact compare.
        (0x56, 840, 1299),
    ];
    // Only the 840 buckets strictly below 1299 qualify: 1299/1300 are at or
    // above the rate and the 978 buckets belong to another currency's trie.
    let expected = [true, false, true, false, false, false];

    StorageHandle::enter(&mut provider, |storage| {
        let bucket_ids: Vec<WwdEntityId> = specs
            .iter()
            .map(|&(owner_byte, currency, floor)| {
                let floor = U256::from(floor);
                let mut body = item(Address::repeat_byte(owner_byte), day);
                body.floor_price_minor = floor;
                body.reference_currency = currency;
                body.bucket_key = NodContract::bucket_key(day, floor, currency);
                api::add_nod(&storage, &scope, &parent, &body, U256::from(5)).unwrap();
                WwdEntityId::from_day_and_digest(day, body.bucket_key.0)
            })
            .collect();

        let context = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(1, 1_752_534_000, 1),
            storage.clone(),
        );
        hooks::qualify_buckets_with_rate(
            &context,
            &scope,
            &parent,
            840,
            U256::from(1299),
            MAX_BUCKET_QUALIFICATIONS_PER_BLOCK,
        )
        .unwrap();

        let qualified: Vec<bool> = bucket_ids
            .iter()
            .map(|&bucket_id| {
                api::get_bucket(&storage, &scope, &parent, bucket_id)
                    .unwrap()
                    .unwrap()
                    .is_qualified
            })
            .collect();
        assert_eq!(qualified, expected);
    });
}

struct CountingParent {
    inner: NodRepositoryReader,
    gets: AtomicUsize,
}

impl ParentBodySource for CountingParent {
    fn get(&self, entity: EntityRef) -> Result<Option<StoredBody>, ParentBodySourceError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        ParentBodySource::get(&self.inner, entity)
    }

    fn list(
        &self,
        query: QueryRef,
        request: IdPageRequest,
    ) -> Result<IdPage, ParentBodySourceError> {
        ParentBodySource::list(&self.inner, query, request)
    }
}

#[test]
fn removal_consumes_loaded_capabilities_without_a_second_parent_read() {
    let (mut provider, scope, reader) = active_world();
    let parent = CountingParent {
        inner: reader,
        gets: AtomicUsize::new(0),
    };
    let body = item(Address::repeat_byte(0x41), WorldwideDay::new(20_260_716));
    StorageHandle::enter(&mut provider, |storage| {
        api::add_nod(&storage, &scope, &parent, &body, U256::from(5)).unwrap();
        let loaded_item = api::load_item(&storage, &scope, &parent, body.nod_id)
            .unwrap()
            .unwrap();
        let bucket_id = WwdEntityId::from_day_and_digest(body.worldwide_day, body.bucket_key.0);
        let loaded_bucket = api::load_bucket(&storage, &scope, &parent, bucket_id)
            .unwrap()
            .unwrap();
        let reads_before_remove = parent.gets.load(Ordering::SeqCst);
        api::remove_nod(&storage, &scope, loaded_item, loaded_bucket).unwrap();
        assert_eq!(parent.gets.load(Ordering::SeqCst), reads_before_remove);
        assert!(api::get_item(&storage, &scope, &parent, body.nod_id)
            .unwrap()
            .is_none());
    });
}
