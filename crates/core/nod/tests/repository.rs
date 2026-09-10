use std::{
    io,
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_primitives::{Address, B256, U256};
use mongodb::sync::Client;
use outbe_compressed_entities::{
    decode_stored_nod_bucket_v1, decode_stored_nod_item_v1, encode_nod_bucket_v1,
    encode_nod_item_v1, IdPageRequest, StoredBody, WwdEntityId,
};
use outbe_nod::{
    canonical_bucket, canonical_item, from_canonical_bucket, from_canonical_item, NodBucketState,
    NodItemState, NodPageRequest, NodRepositoryError, NodRepositoryReader, NodRepositoryWriter,
};
use outbe_offchain_storage::{
    AtomicWriteBatch, Key, MemoryStorage, MongoStorage, MongoStorageConfig, Namespace,
    StorageError, StorageReader, StorageReaderHandle, StorageWriter, StorageWriterHandle, Value,
    MAX_SCAN_ENTRIES,
};
use outbe_primitives::time::WorldwideDay;

fn entity(seed: U256, worldwide_day: WorldwideDay) -> WwdEntityId {
    WwdEntityId::from_day_and_digest(worldwide_day, seed.to_be_bytes::<32>())
}

fn nod_id(seed: u64) -> WwdEntityId {
    entity(U256::from(seed), WorldwideDay::new(u32::MAX))
}

fn bucket_id(key: B256, worldwide_day: WorldwideDay) -> WwdEntityId {
    WwdEntityId::from_day_and_digest(worldwide_day, key.0)
}

fn nod(nod_id: WwdEntityId, owner: Address) -> NodItemState {
    NodItemState {
        nod_id,
        owner,
        gratis_load_minor: U256::MAX,
        worldwide_day: nod_id.worldwide_day(),
        league_id: u16::MAX,
        floor_price_minor: U256::ZERO,
        bucket_key: B256::repeat_byte(0x33),
        issuance_currency: 0,
        reference_currency: u16::MAX,
        issued_at: u64::MAX,
    }
}

/// `NodBucketBodyV1::entity_id` derives the identity as `wwd ++ key[4..]`, so
/// the key's leading four bytes are not recoverable from it. Rebuild the one
/// key that re-derives to this identity.
fn bucket_key_for(id: WwdEntityId) -> B256 {
    let mut key = [0_u8; 32];
    key[4..].copy_from_slice(&id.body());
    B256::from(key)
}

fn bucket(bucket_id: WwdEntityId) -> NodBucketState {
    NodBucketState {
        bucket_key: bucket_key_for(bucket_id),
        worldwide_day: bucket_id.worldwide_day(),
        floor_price_minor: U256::MAX,
        is_qualified: false,
        total_nods: u64::MAX,
        entry_price_minor: U256::ZERO,
        reference_currency: 978,
    }
}

fn namespace(name: &str) -> Namespace {
    Namespace::new(name).unwrap()
}

fn key(bytes: impl Into<Vec<u8>>) -> Key {
    Key::new(bytes).unwrap()
}

fn id_key(id: WwdEntityId) -> Key {
    key(id.as_slice().to_vec())
}

fn owner_key(owner: Address, id: WwdEntityId) -> Key {
    key([owner.as_slice(), id.as_slice()].concat())
}

fn stored_nod(body: &NodItemState) -> Vec<u8> {
    StoredBody::new_v1(encode_nod_item_v1(&canonical_item(body)).unwrap())
        .unwrap()
        .encode()
}

fn stored_bucket(body: &NodBucketState) -> Vec<u8> {
    StoredBody::new_v1(encode_nod_bucket_v1(&canonical_bucket(body)).unwrap())
        .unwrap()
        .encode()
}

#[test]
fn projection_stores_derive_item_and_bucket_identity_from_canonical_bytes() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage.clone();
    let item = nod(nod_id(41), Address::repeat_byte(0x41));
    let item_value = Value::new(stored_nod(&item)).unwrap();

    let repository = NodRepositoryReader::new(reader);
    let mut session = repository.projection_session(&[item.nod_id], &[]).unwrap();
    let item_batch = session
        .store_item(item.nod_id, item_value.clone(), None)
        .unwrap();
    writer.apply_atomic(&item_batch).unwrap();
    assert_eq!(
        repository
            .list_by_owner(
                item.owner,
                NodPageRequest {
                    after: None,
                    limit: 1,
                },
            )
            .unwrap()
            .records[0]
            .nod_id,
        item.nod_id
    );

    let wrong_item_id = nod_id(42);
    let mut wrong_item_session = repository
        .projection_session(&[wrong_item_id], &[])
        .unwrap();
    assert!(matches!(
        wrong_item_session.store_item(wrong_item_id, item_value, None),
        Err(NodRepositoryError::PrimaryKeyBodyMismatch {
            expected,
            actual,
        }) if expected == wrong_item_id && actual == item.nod_id
    ));
    let mut malformed_item_session = repository.projection_session(&[item.nod_id], &[]).unwrap();
    assert!(matches!(
        malformed_item_session.store_item(item.nod_id, Value::new(vec![0xff]).unwrap(), None,),
        Err(NodRepositoryError::CanonicalBody(_))
    ));

    let body = bucket(bucket_id(
        B256::repeat_byte(0x51),
        WorldwideDay::new(20260716),
    ));
    let canonical_id = bucket_id(body.bucket_key, body.worldwide_day);
    let wrong_bucket_id = bucket_id(B256::repeat_byte(0x52), body.worldwide_day);
    let mut wrong_bucket_session = repository
        .projection_session(&[], &[wrong_bucket_id])
        .unwrap();
    assert!(matches!(
        wrong_bucket_session.store_bucket(
            wrong_bucket_id,
            Value::new(stored_bucket(&body)).unwrap(),
            None,
        ),
        Err(NodRepositoryError::BucketIdBodyMismatch {
            expected,
            actual,
        }) if expected == wrong_bucket_id && actual == canonical_id
    ));
    let mut malformed_bucket_session = repository.projection_session(&[], &[canonical_id]).unwrap();
    assert!(matches!(
        malformed_bucket_session.store_bucket(canonical_id, Value::new(vec![0xff]).unwrap(), None,),
        Err(NodRepositoryError::CanonicalBody(_))
    ));
}

#[test]
fn projection_session_owns_item_prior_state_and_rejects_untracked_identity() {
    let storage = Arc::new(MemoryStorage::new());
    let reader_handle: StorageReaderHandle = storage.clone();
    let writer_handle: StorageWriterHandle = storage;
    let repository_reader = NodRepositoryReader::new(reader_handle.clone());
    let repository_writer = NodRepositoryWriter::new(reader_handle, writer_handle.clone());
    let old = nod(nod_id(43), Address::repeat_byte(0x43));
    repository_writer.put_nod(&old).unwrap();

    let replacement = nod(old.nod_id, Address::repeat_byte(0x44));
    let mut session = repository_reader
        .projection_session(&[old.nod_id], &[])
        .unwrap();
    let batch = session
        .store_item(
            old.nod_id,
            Value::new(stored_nod(&replacement)).unwrap(),
            None,
        )
        .unwrap();
    writer_handle.apply_atomic(&batch).unwrap();

    assert!(repository_reader
        .list_by_owner(
            old.owner,
            NodPageRequest {
                after: None,
                limit: 1,
            },
        )
        .unwrap()
        .records
        .is_empty());
    assert_eq!(
        repository_reader
            .list_by_owner(
                replacement.owner,
                NodPageRequest {
                    after: None,
                    limit: 1,
                },
            )
            .unwrap()
            .records[0]
            .nod_id,
        old.nod_id
    );

    let mut delete_session = repository_reader
        .projection_session(&[old.nod_id], &[])
        .unwrap();
    let batch = delete_session.delete_item(old.nod_id).unwrap();
    writer_handle.apply_atomic(&batch).unwrap();
    assert!(repository_reader
        .list_by_owner(
            replacement.owner,
            NodPageRequest {
                after: None,
                limit: 1,
            },
        )
        .unwrap()
        .records
        .is_empty());

    let mut untracked = repository_reader.projection_session(&[], &[]).unwrap();
    assert!(matches!(
        untracked.delete_item(old.nod_id),
        Err(NodRepositoryError::UntrackedProjectionIdentity {
            entity: "Nod item",
            identity,
        }) if identity == old.nod_id
    ));
    let untracked_bucket_id = bucket_id(B256::repeat_byte(0x45), WorldwideDay::new(20260716));
    assert!(matches!(
        untracked.delete_bucket(untracked_bucket_id),
        Err(NodRepositoryError::UntrackedProjectionIdentity {
            entity: "Nod bucket",
            identity,
        }) if identity == untracked_bucket_id
    ));
}

/// The bucket's `reference_currency` is likewise append-only and omitted on
/// zero, so every bucket body written before the field existed keeps its exact
/// prior bytes — which is what keeps the pinned `ces1-noble-poseidon` bucket
/// payload and its leaf commitment unchanged.
#[test]
fn the_bucket_reference_currency_only_appends_to_the_canonical_payload() {
    let mut body = bucket(bucket_id(
        B256::repeat_byte(0x21),
        WorldwideDay::new(20_260_715),
    ));
    body.reference_currency = 0;
    let unpriced = encode_nod_bucket_v1(&canonical_bucket(&body)).unwrap();
    body.reference_currency = 840;
    let priced = encode_nod_bucket_v1(&canonical_bucket(&body)).unwrap();

    // Tag = (7 << 3) | 0 = 0x38; 840 as a varint = 0xC8 0x06.
    assert_eq!(priced, [unpriced.as_slice(), &[0x38, 0xC8, 0x06]].concat());
}

#[test]
fn canonical_stored_bodies_roundtrip_all_nod_field_boundaries() {
    for body in [
        NodItemState {
            nod_id: entity(U256::ZERO, WorldwideDay::new(0)),
            owner: Address::ZERO,
            gratis_load_minor: U256::ZERO,
            worldwide_day: WorldwideDay::new(0),
            league_id: 0,
            floor_price_minor: U256::ZERO,
            bucket_key: B256::ZERO,
            issuance_currency: 0,
            reference_currency: 0,
            issued_at: 0,
        },
        NodItemState {
            nod_id: entity(U256::MAX, WorldwideDay::new(u32::MAX)),
            owner: Address::repeat_byte(u8::MAX),
            gratis_load_minor: U256::MAX,
            worldwide_day: WorldwideDay::new(u32::MAX),
            league_id: u16::MAX,
            floor_price_minor: U256::MAX,
            bucket_key: B256::repeat_byte(u8::MAX),
            issuance_currency: u16::MAX,
            reference_currency: u16::MAX,
            issued_at: u64::MAX,
        },
    ] {
        let stored = stored_nod(&body);
        let decoded = from_canonical_item(decode_stored_nod_item_v1(&stored).unwrap());
        assert_eq!(decoded.nod_id, body.nod_id);
        assert_eq!(decoded.owner, body.owner);
        assert_eq!(decoded.gratis_load_minor, body.gratis_load_minor);
        assert_eq!(decoded.worldwide_day, body.worldwide_day);
        assert_eq!(decoded.league_id, body.league_id);
        assert_eq!(decoded.floor_price_minor, body.floor_price_minor);
        assert_eq!(decoded.bucket_key, body.bucket_key);
        assert_eq!(decoded.issuance_currency, body.issuance_currency);
        assert_eq!(decoded.reference_currency, body.reference_currency);
        assert_eq!(decoded.issued_at, body.issued_at);
    }

    for body in [
        NodBucketState {
            bucket_key: B256::ZERO,
            worldwide_day: WorldwideDay::new(0),
            floor_price_minor: U256::ZERO,
            is_qualified: false,
            total_nods: 0,
            entry_price_minor: U256::ZERO,
            reference_currency: 0,
        },
        NodBucketState {
            floor_price_minor: U256::MAX,
            is_qualified: true,
            total_nods: u64::MAX,
            entry_price_minor: U256::MAX,
            reference_currency: u16::MAX,
            ..bucket(bucket_id(
                B256::repeat_byte(u8::MAX),
                WorldwideDay::new(u32::MAX),
            ))
        },
    ] {
        let stored = stored_bucket(&body);
        let decoded = from_canonical_bucket(decode_stored_nod_bucket_v1(&stored).unwrap());
        assert_eq!(decoded.bucket_key, body.bucket_key);
        assert_eq!(decoded.worldwide_day, body.worldwide_day);
        assert_eq!(decoded.floor_price_minor, body.floor_price_minor);
        assert_eq!(decoded.is_qualified, body.is_qualified);
        assert_eq!(decoded.total_nods, body.total_nods);
        assert_eq!(decoded.entry_price_minor, body.entry_price_minor);
        assert_eq!(decoded.reference_currency, body.reference_currency);
    }
}

fn run_contract(reader: StorageReaderHandle, writer: StorageWriterHandle) {
    let repository_reader = NodRepositoryReader::new(reader.clone());
    let repository_writer = NodRepositoryWriter::new(reader.clone(), writer.clone());
    let owner_a = Address::repeat_byte(0x22);
    let owner_b = Address::repeat_byte(0x44);

    for id in [nod_id(3), nod_id(1), nod_id(2)] {
        repository_writer.put_nod(&nod(id, owner_a)).unwrap();
    }
    repository_writer.put_nod(&nod(nod_id(4), owner_b)).unwrap();
    // A bucket identity keeps only `key[4..]`, so a key with a non-zero first
    // four bytes cannot round-trip through it. Pick one that can, so the
    // assertion below still checks a real round trip.
    let bucket_key = {
        let mut key = [0x55_u8; 32];
        key[..4].fill(0);
        B256::from(key)
    };
    let selected_bucket_id = bucket_id(bucket_key, WorldwideDay::new(0));
    repository_writer
        .put_bucket(&bucket(selected_bucket_id))
        .unwrap();

    let stored = repository_reader.get(nod_id(1)).unwrap().unwrap();
    assert_eq!(stored.nod_id, nod_id(1));
    assert_eq!(stored.gratis_load_minor, U256::MAX);
    assert_eq!(stored.issued_at, u64::MAX);
    assert_eq!(
        repository_reader
            .get_bucket(selected_bucket_id)
            .unwrap()
            .unwrap()
            .bucket_key,
        bucket_key
    );

    let primary = reader
        .get(namespace("nods"), &id_key(nod_id(1)))
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_stored_nod_item_v1(primary.as_bytes())
            .unwrap()
            .nod_id,
        nod_id(1)
    );
    assert!(reader
        .get(namespace("nods_by_owner"), &owner_key(owner_a, nod_id(1)),)
        .unwrap()
        .unwrap()
        .as_bytes()
        .is_empty());
    assert_eq!(
        reader
            .get(namespace("nod_buckets"), &id_key(selected_bucket_id))
            .unwrap()
            .unwrap()
            .as_bytes(),
        stored_bucket(&bucket(selected_bucket_id))
    );

    let first = repository_reader
        .list_all(NodPageRequest {
            after: None,
            limit: 2,
        })
        .unwrap();
    assert_eq!(
        first
            .records
            .iter()
            .map(|body| body.nod_id)
            .collect::<Vec<_>>(),
        [nod_id(1), nod_id(2)]
    );
    assert_eq!(first.next_after, Some(nod_id(2)));
    let second = repository_reader
        .list_all(NodPageRequest {
            after: first.next_after,
            limit: 3,
        })
        .unwrap();
    assert_eq!(
        second
            .records
            .iter()
            .map(|body| body.nod_id)
            .collect::<Vec<_>>(),
        [nod_id(3), nod_id(4)]
    );
    assert_eq!(second.next_after, None);
    assert_eq!(
        repository_reader
            .list_by_owner(
                owner_b,
                NodPageRequest {
                    after: None,
                    limit: 10
                }
            )
            .unwrap()
            .records[0]
            .nod_id,
        nod_id(4)
    );

    repository_writer.put_nod(&nod(nod_id(1), owner_b)).unwrap();
    assert!(reader
        .get(namespace("nods_by_owner"), &owner_key(owner_a, nod_id(1)),)
        .unwrap()
        .is_none());
    assert_eq!(
        repository_reader.get(nod_id(1)).unwrap().unwrap().owner,
        owner_b
    );

    repository_writer.delete_nod(nod_id(2)).unwrap();
    repository_writer.delete_nod(nod_id(2)).unwrap();
    let remaining = repository_reader
        .list_all(NodPageRequest {
            after: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(
        remaining
            .records
            .iter()
            .map(|body| body.nod_id)
            .collect::<Vec<_>>(),
        [nod_id(1), nod_id(3), nod_id(4)]
    );
    repository_writer.delete_bucket(selected_bucket_id).unwrap();
    repository_writer.delete_bucket(selected_bucket_id).unwrap();
    assert!(repository_reader
        .get_bucket(selected_bucket_id)
        .unwrap()
        .is_none());
}

#[test]
fn memory_contract() {
    let storage = Arc::new(MemoryStorage::new());
    run_contract(storage.clone(), storage);
}

#[test]
fn parent_seam_returns_exact_stored_bodies_and_strict_id_pages() {
    let storage = Arc::new(MemoryStorage::new());
    let reader_handle: StorageReaderHandle = storage.clone();
    let writer_handle: StorageWriterHandle = storage;
    let reader = NodRepositoryReader::new(reader_handle.clone());
    let writer = NodRepositoryWriter::new(reader_handle, writer_handle);
    let owner = Address::repeat_byte(0x29);
    let ids = [nod_id(1), nod_id(2), nod_id(3)];
    for id in [ids[2], ids[0], ids[1]] {
        writer.put_nod(&nod(id, owner)).unwrap();
    }
    let selected_bucket = bucket_id(B256::repeat_byte(0x59), WorldwideDay::new(0));
    writer.put_bucket(&bucket(selected_bucket)).unwrap();

    assert_eq!(
        reader.get_stored_item(ids[0]).unwrap().unwrap().encode(),
        stored_nod(&nod(ids[0], owner))
    );
    assert_eq!(
        reader
            .get_stored_bucket(selected_bucket)
            .unwrap()
            .unwrap()
            .encode(),
        stored_bucket(&bucket(selected_bucket))
    );
    assert!(reader.get_stored_item(nod_id(99)).unwrap().is_none());

    for page in [
        reader
            .list_ids_all(IdPageRequest {
                after: None,
                limit: 2,
            })
            .unwrap(),
        reader
            .list_ids_by_owner(
                owner,
                IdPageRequest {
                    after: None,
                    limit: 2,
                },
            )
            .unwrap(),
    ] {
        assert_eq!(page.ids, ids[..2]);
        assert_eq!(page.next_after, Some(ids[1]));
    }
    let tail = reader
        .list_ids_all(IdPageRequest {
            after: Some(ids[1]),
            limit: 2,
        })
        .unwrap();
    assert_eq!(tail.ids, ids[2..]);
    assert_eq!(tail.next_after, None);

    assert!(matches!(
        reader.list_ids_all(IdPageRequest {
            after: None,
            limit: 0,
        }),
        Err(NodRepositoryError::InvalidPageLimit { .. })
    ));
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn mongo_contract() {
    run_isolated_mongo("nod_repository", run_contract);
}

#[test]
fn rejects_corrupt_items_buckets_indexes_and_limits() {
    let storage = Arc::new(MemoryStorage::new());
    run_corruption_contract(storage.clone(), storage);
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn mongo_rejects_corrupt_items_buckets_indexes_and_limits() {
    run_isolated_mongo("nod_corruption", run_corruption_contract);
}

fn run_corruption_contract(reader_storage: StorageReaderHandle, storage: StorageWriterHandle) {
    let reader = NodRepositoryReader::new(reader_storage);
    let owner = Address::repeat_byte(0x61);
    let id = nod_id(9);

    storage
        .put(namespace("nods"), &id_key(id), &Value::new([0xff]).unwrap())
        .unwrap();
    assert!(matches!(
        reader.get(id),
        Err(NodRepositoryError::CanonicalBody(_))
    ));
    let wrong = nod(nod_id(10), owner);
    storage
        .put(
            namespace("nods"),
            &id_key(id),
            &Value::new(stored_nod(&wrong)).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get(id),
        Err(NodRepositoryError::PrimaryKeyBodyMismatch { .. })
    ));

    let mut trailing = stored_nod(&nod(id, owner));
    trailing.push(0);
    storage
        .put(
            namespace("nods"),
            &id_key(id),
            &Value::new(trailing).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get(id),
        Err(NodRepositoryError::CanonicalBody(_))
    ));

    storage.delete(namespace("nods"), &id_key(id)).unwrap();
    storage
        .put(
            namespace("nods_by_owner"),
            &owner_key(owner, id),
            &Value::new([1]).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            NodPageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(NodRepositoryError::NonEmptyIndexValue)
    ));
    storage
        .put(
            namespace("nods_by_owner"),
            &owner_key(owner, id),
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            NodPageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(NodRepositoryError::DanglingIndex { .. })
    ));
    storage
        .delete(namespace("nods_by_owner"), &owner_key(owner, id))
        .unwrap();
    let malformed_owner_key = key([owner.as_slice(), &[1, 2]].concat());
    storage
        .put(
            namespace("nods_by_owner"),
            &malformed_owner_key,
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            NodPageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(NodRepositoryError::MalformedIndexKey)
    ));

    let malformed_primary = key([0xaa]);
    storage
        .put(
            namespace("nods"),
            &malformed_primary,
            &Value::new([0]).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_all(NodPageRequest {
            after: None,
            limit: 10
        }),
        Err(NodRepositoryError::MalformedPrimaryKey)
    ));

    let selected_bucket = bucket_id(B256::repeat_byte(0x71), WorldwideDay::new(0));
    let wrong_bucket = bucket(bucket_id(B256::repeat_byte(0x72), WorldwideDay::new(0)));
    storage
        .put(
            namespace("nod_buckets"),
            &id_key(selected_bucket),
            &Value::new(stored_bucket(&wrong_bucket)).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get_bucket(selected_bucket),
        Err(NodRepositoryError::BucketIdBodyMismatch { .. })
    ));
    storage
        .put(
            namespace("nod_buckets"),
            &id_key(selected_bucket),
            &Value::new([0xff]).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get_bucket(selected_bucket),
        Err(NodRepositoryError::CanonicalBody(_))
    ));
    let mut trailing_bucket = stored_bucket(&bucket(selected_bucket));
    trailing_bucket.push(0);
    storage
        .put(
            namespace("nod_buckets"),
            &id_key(selected_bucket),
            &Value::new(trailing_bucket).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get_bucket(selected_bucket),
        Err(NodRepositoryError::CanonicalBody(_))
    ));
    assert!(matches!(
        reader.list_all(NodPageRequest {
            after: None,
            limit: 0
        }),
        Err(NodRepositoryError::InvalidPageLimit { .. })
    ));
    assert!(matches!(
        reader.list_all(NodPageRequest {
            after: None,
            limit: MAX_SCAN_ENTRIES + 1,
        }),
        Err(NodRepositoryError::InvalidPageLimit { .. })
    ));

    storage
        .delete(namespace("nods"), &malformed_primary)
        .unwrap();
    storage
        .delete(namespace("nods_by_owner"), &malformed_owner_key)
        .unwrap();
    let mismatched = nod(id, Address::repeat_byte(0x62));
    storage
        .put(
            namespace("nods"),
            &id_key(id),
            &Value::new(stored_nod(&mismatched)).unwrap(),
        )
        .unwrap();
    storage
        .put(
            namespace("nods_by_owner"),
            &owner_key(owner, id),
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            NodPageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(NodRepositoryError::IndexedOwnerMismatch { .. })
    ));
}

#[derive(Debug)]
struct FailAfterWriter {
    inner: Arc<MemoryStorage>,
    fail_after: usize,
    calls: AtomicUsize,
}

impl FailAfterWriter {
    fn finish_step(&self) -> Result<(), StorageError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_after {
            return Err(StorageError::Backend {
                source: Box::new(io::Error::other("injected failure after write step")),
            });
        }
        Ok(())
    }
}

impl StorageWriter for FailAfterWriter {
    fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
        for _ in batch.operations() {
            self.finish_step()?;
        }
        self.inner.apply_atomic(batch)
    }
}

#[test]
fn failures_before_each_nod_batch_step_leave_repository_unchanged() {
    let owner = Address::repeat_byte(0x91);
    let new_owner = Address::repeat_byte(0x92);
    let id = nod_id(88);

    for fail_after in 1..=2 {
        let storage = Arc::new(MemoryStorage::new());
        let failing = Arc::new(FailAfterWriter {
            inner: storage.clone(),
            fail_after,
            calls: AtomicUsize::new(0),
        });
        let repository = NodRepositoryWriter::new(storage.clone(), failing);
        assert!(matches!(
            repository.put_nod(&nod(id, owner)),
            Err(NodRepositoryError::Storage(_))
        ));
        assert!(storage
            .get(namespace("nods"), &id_key(id))
            .unwrap()
            .is_none());
        assert!(storage
            .get(namespace("nods_by_owner"), &owner_key(owner, id))
            .unwrap()
            .is_none());
    }

    for fail_after in 1..=3 {
        let storage = Arc::new(MemoryStorage::new());
        let seed = NodRepositoryWriter::new(storage.clone(), storage.clone());
        seed.put_nod(&nod(id, owner)).unwrap();
        let failing = Arc::new(FailAfterWriter {
            inner: storage.clone(),
            fail_after,
            calls: AtomicUsize::new(0),
        });
        let repository = NodRepositoryWriter::new(storage.clone(), failing);
        assert!(matches!(
            repository.put_nod(&nod(id, new_owner)),
            Err(NodRepositoryError::Storage(_))
        ));
        assert_eq!(
            NodRepositoryReader::new(storage.clone())
                .get(id)
                .unwrap()
                .unwrap()
                .owner,
            owner
        );
        assert!(storage
            .get(namespace("nods_by_owner"), &owner_key(new_owner, id))
            .unwrap()
            .is_none());
        assert!(storage
            .get(namespace("nods_by_owner"), &owner_key(owner, id))
            .unwrap()
            .is_some());
    }

    for fail_after in 1..=2 {
        let storage = Arc::new(MemoryStorage::new());
        let seed = NodRepositoryWriter::new(storage.clone(), storage.clone());
        seed.put_nod(&nod(id, owner)).unwrap();
        let failing = Arc::new(FailAfterWriter {
            inner: storage.clone(),
            fail_after,
            calls: AtomicUsize::new(0),
        });
        let repository = NodRepositoryWriter::new(storage.clone(), failing);
        assert!(matches!(
            repository.delete_nod(id),
            Err(NodRepositoryError::Storage(_))
        ));
        assert!(storage
            .get(namespace("nods_by_owner"), &owner_key(owner, id))
            .unwrap()
            .is_some());
        assert!(storage
            .get(namespace("nods"), &id_key(id))
            .unwrap()
            .is_some());
    }

    let selected_bucket_id = bucket_id(B256::repeat_byte(0xa1), WorldwideDay::new(0));
    let storage = Arc::new(MemoryStorage::new());
    let failing = Arc::new(FailAfterWriter {
        inner: storage.clone(),
        fail_after: 1,
        calls: AtomicUsize::new(0),
    });
    let repository = NodRepositoryWriter::new(storage.clone(), failing);
    assert!(matches!(
        repository.put_bucket(&bucket(selected_bucket_id)),
        Err(NodRepositoryError::Storage(_))
    ));
    assert!(storage
        .get(namespace("nod_buckets"), &id_key(selected_bucket_id),)
        .unwrap()
        .is_none());

    let seed = NodRepositoryWriter::new(storage.clone(), storage.clone());
    seed.put_bucket(&bucket(selected_bucket_id)).unwrap();
    let failing = Arc::new(FailAfterWriter {
        inner: storage.clone(),
        fail_after: 1,
        calls: AtomicUsize::new(0),
    });
    let repository = NodRepositoryWriter::new(storage.clone(), failing);
    assert!(matches!(
        repository.delete_bucket(selected_bucket_id),
        Err(NodRepositoryError::Storage(_))
    ));
    assert!(storage
        .get(namespace("nod_buckets"), &id_key(selected_bucket_id),)
        .unwrap()
        .is_some());
}

fn run_isolated_mongo(test_name: &str, test: fn(StorageReaderHandle, StorageWriterHandle)) {
    let uri = std::env::var("OUTBE_TEST_MONGODB_URI")
        .expect("set OUTBE_TEST_MONGODB_URI before running ignored MongoDB tests");
    let database = format!("outbe_{}_{}_{}", test_name, std::process::id(), 1);
    let client = Client::with_uri_str(&uri).unwrap();
    client.database(&database).drop().run().unwrap();
    let storage = Arc::new(
        MongoStorage::connect(MongoStorageConfig {
            uri,
            database: database.clone(),
        })
        .unwrap(),
    );
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        test(storage.clone(), storage);
    }));
    client.database(&database).drop().run().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
