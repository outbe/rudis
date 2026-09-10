use std::{
    io,
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_primitives::{Address, U256};
use mongodb::sync::Client;
use outbe_compressed_entities::{
    decode_tribute_v1, encode_tribute_v1, IdPageRequest, StoredBody, WwdEntityId,
};
use outbe_offchain_storage::{
    AtomicWriteBatch, Key, MemoryStorage, MongoStorage, MongoStorageConfig, Namespace,
    StorageError, StorageReader, StorageReaderHandle, StorageWriter, StorageWriterHandle, Value,
    MAX_SCAN_ENTRIES,
};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{
    TributeData, TributePageRequest, TributeRepositoryError, TributeRepositoryReader,
    TributeRepositoryWriter,
};

fn tribute(tribute_id: U256, owner: Address, day: u32) -> TributeData {
    let worldwide_day = WorldwideDay::new(day);
    TributeData {
        tribute_id: WwdEntityId::from_day_and_digest(worldwide_day, tribute_id.to_be_bytes::<32>()),
        owner,
        worldwide_day,
        issuance_amount_minor: U256::MAX,
        issuance_currency: u16::MAX,
        nominal_amount_minor: U256::ZERO,
        reference_currency: 0,
        tribute_price_minor: U256::MAX,
        exclude_from_intex_issuance: true,
    }
}

fn namespace(name: &str) -> Namespace {
    Namespace::new(name).unwrap()
}

fn key(bytes: impl Into<Vec<u8>>) -> Key {
    Key::new(bytes).unwrap()
}

fn entity_id(id: U256, day: u32) -> WwdEntityId {
    WwdEntityId::from_day_and_digest(WorldwideDay::new(day), id.to_be_bytes::<32>())
}

fn id_key(id: WwdEntityId) -> Key {
    key(id.as_slice().to_vec())
}

fn owner_key(owner: Address, id: WwdEntityId) -> Key {
    key([owner.as_slice(), id.as_slice()].concat())
}

fn day_key(day: u32, id: WwdEntityId) -> Key {
    key([day.to_be_bytes().as_slice(), id.as_slice()].concat())
}

#[test]
fn canonical_payload_roundtrips_all_tribute_field_boundaries() {
    for body in [
        TributeData {
            tribute_id: entity_id(U256::ZERO, 0),
            owner: Address::ZERO,
            worldwide_day: WorldwideDay::new(0),
            issuance_amount_minor: U256::ZERO,
            issuance_currency: 0,
            nominal_amount_minor: U256::ZERO,
            reference_currency: 0,
            tribute_price_minor: U256::ZERO,
            exclude_from_intex_issuance: false,
        },
        TributeData {
            tribute_id: entity_id(U256::MAX, u32::MAX),
            owner: Address::repeat_byte(u8::MAX),
            worldwide_day: WorldwideDay::new(u32::MAX),
            issuance_amount_minor: U256::MAX,
            issuance_currency: u16::MAX,
            nominal_amount_minor: U256::MAX,
            reference_currency: u16::MAX,
            tribute_price_minor: U256::MAX,
            exclude_from_intex_issuance: true,
        },
    ] {
        let payload = encode_tribute_v1(&outbe_tribute::canonical_body(&body)).unwrap();
        let decoded = outbe_tribute::from_canonical_body(decode_tribute_v1(&payload).unwrap());
        assert_eq!(decoded.tribute_id, body.tribute_id);
        assert_eq!(decoded.owner, body.owner);
        assert_eq!(decoded.worldwide_day, body.worldwide_day);
        assert_eq!(decoded.issuance_amount_minor, body.issuance_amount_minor);
        assert_eq!(decoded.issuance_currency, body.issuance_currency);
        assert_eq!(decoded.nominal_amount_minor, body.nominal_amount_minor);
        assert_eq!(decoded.reference_currency, body.reference_currency);
        assert_eq!(decoded.tribute_price_minor, body.tribute_price_minor);
        assert_eq!(
            decoded.exclude_from_intex_issuance,
            body.exclude_from_intex_issuance
        );
    }
}

#[test]
fn projection_store_derives_identity_and_indexes_from_the_canonical_stored_body() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage.clone();
    let body = tribute(U256::from(41), Address::repeat_byte(0x41), 20260716);
    let stored_body = Value::new(
        StoredBody::new_v1(encode_tribute_v1(&outbe_tribute::canonical_body(&body)).unwrap())
            .unwrap()
            .encode(),
    )
    .unwrap();

    let repository = TributeRepositoryReader::new(reader);
    let mut session = repository.projection_session(&[body.tribute_id]).unwrap();
    let batch = session
        .store(body.tribute_id, stored_body.clone(), None)
        .unwrap();
    writer.apply_atomic(&batch).unwrap();

    assert_eq!(
        repository
            .list_by_owner(
                body.owner,
                TributePageRequest {
                    after: None,
                    limit: 1,
                },
            )
            .unwrap()
            .records[0]
            .tribute_id,
        body.tribute_id
    );

    let wrong_id = entity_id(U256::from(42), body.worldwide_day.value());
    let mut wrong_identity_session = repository.projection_session(&[wrong_id]).unwrap();
    assert!(matches!(
        wrong_identity_session.store(wrong_id, stored_body, None),
        Err(TributeRepositoryError::PrimaryKeyBodyMismatch {
            expected,
            actual,
        }) if expected == wrong_id && actual == body.tribute_id
    ));

    let mut malformed_session = repository.projection_session(&[body.tribute_id]).unwrap();
    assert!(matches!(
        malformed_session.store(body.tribute_id, Value::new(vec![0xff]).unwrap(), None,),
        Err(TributeRepositoryError::CanonicalBody(_))
    ));
}

#[test]
fn projection_session_owns_prior_state_and_rejects_untracked_identity() {
    let storage = Arc::new(MemoryStorage::new());
    let reader_handle: StorageReaderHandle = storage.clone();
    let writer_handle: StorageWriterHandle = storage;
    let repository_reader = TributeRepositoryReader::new(reader_handle.clone());
    let repository_writer = TributeRepositoryWriter::new(reader_handle, writer_handle.clone());
    let old = tribute(U256::from(43), Address::repeat_byte(0x43), 20260716);
    repository_writer.put(&old).unwrap();

    let replacement = tribute(
        U256::from(43),
        Address::repeat_byte(0x44),
        old.worldwide_day.value(),
    );
    let replacement_body = Value::new(
        StoredBody::new_v1(
            encode_tribute_v1(&outbe_tribute::canonical_body(&replacement)).unwrap(),
        )
        .unwrap()
        .encode(),
    )
    .unwrap();
    let mut session = repository_reader
        .projection_session(&[old.tribute_id])
        .unwrap();
    let batch = session
        .store(old.tribute_id, replacement_body, None)
        .unwrap();
    writer_handle.apply_atomic(&batch).unwrap();

    assert!(repository_reader
        .list_by_owner(
            old.owner,
            TributePageRequest {
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
                TributePageRequest {
                    after: None,
                    limit: 1,
                },
            )
            .unwrap()
            .records[0]
            .tribute_id,
        old.tribute_id
    );

    let mut delete_session = repository_reader
        .projection_session(&[old.tribute_id])
        .unwrap();
    let batch = delete_session.delete(old.tribute_id).unwrap();
    writer_handle.apply_atomic(&batch).unwrap();
    assert!(repository_reader
        .list_by_owner(
            replacement.owner,
            TributePageRequest {
                after: None,
                limit: 1,
            },
        )
        .unwrap()
        .records
        .is_empty());
    assert!(repository_reader
        .list_by_day(
            replacement.worldwide_day,
            TributePageRequest {
                after: None,
                limit: 1,
            },
        )
        .unwrap()
        .records
        .is_empty());

    let mut untracked = repository_reader.projection_session(&[]).unwrap();
    assert!(matches!(
        untracked.delete(old.tribute_id),
        Err(TributeRepositoryError::UntrackedProjectionIdentity { tribute_id })
            if tribute_id == old.tribute_id
    ));
}

fn run_contract(reader: StorageReaderHandle, writer: StorageWriterHandle) {
    let repository_reader = TributeRepositoryReader::new(reader.clone());
    let repository_writer = TributeRepositoryWriter::new(reader.clone(), writer.clone());
    let owner_a = Address::repeat_byte(0x11);
    let owner_b = Address::repeat_byte(0x22);

    for id in [U256::from(3), U256::from(1), U256::from(2)] {
        repository_writer.put(&tribute(id, owner_a, 7)).unwrap();
    }
    repository_writer
        .put(&tribute(U256::from(4), owner_b, 8))
        .unwrap();

    let first_id = entity_id(U256::from(1), 7);
    let stored = repository_reader.get(first_id).unwrap().unwrap();
    assert_eq!(stored.tribute_id, first_id);
    assert_eq!(stored.issuance_amount_minor, U256::MAX);
    assert_eq!(stored.nominal_amount_minor, U256::ZERO);
    assert!(stored.exclude_from_intex_issuance);

    let primary = reader
        .get(namespace("tributes"), &id_key(first_id))
        .unwrap()
        .unwrap();
    assert_eq!(
        outbe_tribute::from_canonical_body(
            outbe_compressed_entities::decode_stored_tribute_v1(primary.as_bytes()).unwrap()
        )
        .tribute_id,
        first_id
    );
    assert!(reader
        .get(
            namespace("tributes_by_owner"),
            &owner_key(owner_a, first_id),
        )
        .unwrap()
        .unwrap()
        .as_bytes()
        .is_empty());
    assert!(reader
        .get(namespace("tributes_by_day"), &day_key(7, first_id),)
        .unwrap()
        .unwrap()
        .as_bytes()
        .is_empty());

    let first = repository_reader
        .list_by_owner(
            owner_a,
            TributePageRequest {
                after: None,
                limit: 2,
            },
        )
        .unwrap();
    assert_eq!(
        first
            .records
            .iter()
            .map(|body| body.tribute_id)
            .collect::<Vec<_>>(),
        [entity_id(U256::from(1), 7), entity_id(U256::from(2), 7)]
    );
    assert_eq!(first.next_after, Some(entity_id(U256::from(2), 7)));
    let second = repository_reader
        .list_by_owner(
            owner_a,
            TributePageRequest {
                after: first.next_after,
                limit: 2,
            },
        )
        .unwrap();
    assert_eq!(
        second
            .records
            .iter()
            .map(|body| body.tribute_id)
            .collect::<Vec<_>>(),
        [entity_id(U256::from(3), 7)]
    );
    assert_eq!(second.next_after, None);
    assert_eq!(
        repository_reader
            .list_by_day(
                WorldwideDay::new(8),
                TributePageRequest {
                    after: None,
                    limit: 10,
                },
            )
            .unwrap()
            .records[0]
            .tribute_id,
        entity_id(U256::from(4), 8)
    );

    let replacement = tribute(U256::from(1), owner_b, 7);
    repository_writer.put(&replacement).unwrap();
    assert!(reader
        .get(
            namespace("tributes_by_owner"),
            &owner_key(owner_a, first_id),
        )
        .unwrap()
        .is_none());
    assert!(reader
        .get(namespace("tributes_by_day"), &day_key(7, first_id),)
        .unwrap()
        .is_some());
    assert_eq!(
        repository_reader.get(first_id).unwrap().unwrap().owner,
        owner_b
    );

    repository_writer.delete(first_id).unwrap();
    repository_writer.delete(first_id).unwrap();
    assert!(repository_reader.get(first_id).unwrap().is_none());
    assert!(reader
        .get(
            namespace("tributes_by_owner"),
            &owner_key(owner_b, first_id),
        )
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
    let reader = TributeRepositoryReader::new(reader_handle.clone());
    let writer = TributeRepositoryWriter::new(reader_handle, writer_handle);
    let owner = Address::repeat_byte(0x19);
    let day = WorldwideDay::new(7);
    let ids = [
        entity_id(U256::from(1), day.value()),
        entity_id(U256::from(2), day.value()),
        entity_id(U256::from(3), day.value()),
    ];
    for seed in [3_u64, 1, 2] {
        writer
            .put(&tribute(U256::from(seed), owner, day.value()))
            .unwrap();
    }

    let expected = StoredBody::new_v1(
        encode_tribute_v1(&outbe_tribute::canonical_body(&tribute(
            U256::from(1),
            owner,
            day.value(),
        )))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        reader.get_stored_body(ids[0]).unwrap().unwrap().encode(),
        expected.encode()
    );
    assert!(reader
        .get_stored_body(entity_id(U256::from(99), day.value()))
        .unwrap()
        .is_none());

    for page in [
        reader
            .list_ids_by_owner(
                owner,
                IdPageRequest {
                    after: None,
                    limit: 2,
                },
            )
            .unwrap(),
        reader
            .list_ids_by_day(
                day,
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
        .list_ids_by_owner(
            owner,
            IdPageRequest {
                after: Some(ids[1]),
                limit: 2,
            },
        )
        .unwrap();
    assert_eq!(tail.ids, ids[2..]);
    assert_eq!(tail.next_after, None);

    assert!(matches!(
        reader.list_ids_by_day(
            day,
            IdPageRequest {
                after: Some(entity_id(U256::from(1), day.value() + 1)),
                limit: 1,
            },
        ),
        Err(TributeRepositoryError::InvalidDayCursor { .. })
    ));
    assert!(matches!(
        reader.list_ids_by_owner(
            owner,
            IdPageRequest {
                after: None,
                limit: 0,
            },
        ),
        Err(TributeRepositoryError::InvalidPageLimit { .. })
    ));
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn mongo_contract() {
    run_isolated_mongo("tribute_repository", run_contract);
}

#[test]
fn rejects_corrupt_bodies_indexes_and_limits() {
    let storage = Arc::new(MemoryStorage::new());
    run_corruption_contract(storage.clone(), storage);
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn mongo_rejects_corrupt_bodies_indexes_and_limits() {
    run_isolated_mongo("tribute_corruption", run_corruption_contract);
}

fn run_corruption_contract(reader_storage: StorageReaderHandle, storage: StorageWriterHandle) {
    let reader = TributeRepositoryReader::new(reader_storage);
    let owner = Address::repeat_byte(0x31);
    let id = entity_id(U256::from(9), 4);

    storage
        .put(
            namespace("tributes"),
            &id_key(id),
            &Value::new([0xff]).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get(id),
        Err(TributeRepositoryError::CanonicalBody(_))
    ));

    let wrong = tribute(U256::from(10), owner, 4);
    let wrong_bytes =
        StoredBody::new_v1(encode_tribute_v1(&outbe_tribute::canonical_body(&wrong)).unwrap())
            .unwrap()
            .encode();
    storage
        .put(
            namespace("tributes"),
            &id_key(id),
            &Value::new(wrong_bytes).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get(id),
        Err(TributeRepositoryError::PrimaryKeyBodyMismatch { .. })
    ));

    let matching = TributeData {
        tribute_id: id,
        ..tribute(U256::from(9), owner, 4)
    };
    let mut trailing =
        StoredBody::new_v1(encode_tribute_v1(&outbe_tribute::canonical_body(&matching)).unwrap())
            .unwrap()
            .encode();
    trailing.push(0);
    storage
        .put(
            namespace("tributes"),
            &id_key(id),
            &Value::new(trailing).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.get(id),
        Err(TributeRepositoryError::CanonicalBody(_))
    ));

    storage.delete(namespace("tributes"), &id_key(id)).unwrap();
    storage
        .put(
            namespace("tributes_by_owner"),
            &owner_key(owner, id),
            &Value::new([1]).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            TributePageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(TributeRepositoryError::NonEmptyIndexValue { .. })
    ));
    storage
        .put(
            namespace("tributes_by_owner"),
            &owner_key(owner, id),
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            TributePageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(TributeRepositoryError::DanglingIndex { .. })
    ));
    storage
        .delete(namespace("tributes_by_owner"), &owner_key(owner, id))
        .unwrap();
    let malformed_owner_key = key([owner.as_slice(), &[1, 2, 3]].concat());
    storage
        .put(
            namespace("tributes_by_owner"),
            &malformed_owner_key,
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            TributePageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(TributeRepositoryError::MalformedIndexKey { .. })
    ));
    assert!(matches!(
        reader.list_by_owner(
            owner,
            TributePageRequest {
                after: None,
                limit: 0
            }
        ),
        Err(TributeRepositoryError::InvalidPageLimit { .. })
    ));
    assert!(matches!(
        reader.list_by_owner(
            owner,
            TributePageRequest {
                after: None,
                limit: MAX_SCAN_ENTRIES + 1,
            },
        ),
        Err(TributeRepositoryError::InvalidPageLimit { .. })
    ));

    storage
        .delete(namespace("tributes_by_owner"), &malformed_owner_key)
        .unwrap();
    let actual_owner = Address::repeat_byte(0x32);
    let mismatched = TributeData {
        tribute_id: id,
        owner: actual_owner,
        worldwide_day: WorldwideDay::new(4),
        ..tribute(U256::from(9), actual_owner, 4)
    };
    let mismatched_bytes =
        StoredBody::new_v1(encode_tribute_v1(&outbe_tribute::canonical_body(&mismatched)).unwrap())
            .unwrap()
            .encode();
    storage
        .put(
            namespace("tributes"),
            &id_key(id),
            &Value::new(mismatched_bytes).unwrap(),
        )
        .unwrap();
    storage
        .put(
            namespace("tributes_by_owner"),
            &owner_key(owner, id),
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_owner(
            owner,
            TributePageRequest {
                after: None,
                limit: 1
            }
        ),
        Err(TributeRepositoryError::IndexedOwnerMismatch { .. })
    ));
    storage
        .put(
            namespace("tributes_by_day"),
            &day_key(5, id),
            &Value::new(Vec::new()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        reader.list_by_day(
            WorldwideDay::new(5),
            TributePageRequest {
                after: None,
                limit: 1
            },
        ),
        Err(TributeRepositoryError::IndexedDayMismatch { .. })
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
fn failures_before_each_tribute_batch_step_leave_repository_unchanged() {
    let owner = Address::repeat_byte(0x81);
    let new_owner = Address::repeat_byte(0x82);
    let seed = U256::from(77);
    let id = entity_id(seed, 7);

    for fail_after in 1..=3 {
        let storage = Arc::new(MemoryStorage::new());
        let failing = Arc::new(FailAfterWriter {
            inner: storage.clone(),
            fail_after,
            calls: AtomicUsize::new(0),
        });
        let repository = TributeRepositoryWriter::new(storage.clone(), failing);
        assert!(matches!(
            repository.put(&tribute(seed, owner, 7)),
            Err(TributeRepositoryError::Storage(_))
        ));
        assert!(storage
            .get(namespace("tributes"), &id_key(id))
            .unwrap()
            .is_none());
        assert!(storage
            .get(namespace("tributes_by_owner"), &owner_key(owner, id))
            .unwrap()
            .is_none());
        assert!(storage
            .get(namespace("tributes_by_day"), &day_key(7, id))
            .unwrap()
            .is_none());
    }

    for fail_after in 1..=4 {
        let storage = Arc::new(MemoryStorage::new());
        let seed = TributeRepositoryWriter::new(storage.clone(), storage.clone());
        seed.put(&tribute(U256::from(77), owner, 7)).unwrap();
        let failing = Arc::new(FailAfterWriter {
            inner: storage.clone(),
            fail_after,
            calls: AtomicUsize::new(0),
        });
        let repository = TributeRepositoryWriter::new(storage.clone(), failing);
        assert!(matches!(
            repository.put(&tribute(U256::from(77), new_owner, 7)),
            Err(TributeRepositoryError::Storage(_))
        ));
        assert_eq!(
            TributeRepositoryReader::new(storage.clone())
                .get(id)
                .unwrap()
                .unwrap()
                .owner,
            owner
        );
        assert!(storage
            .get(namespace("tributes_by_owner"), &owner_key(new_owner, id))
            .unwrap()
            .is_none());
        assert!(storage
            .get(namespace("tributes_by_owner"), &owner_key(owner, id))
            .unwrap()
            .is_some());
        assert!(storage
            .get(namespace("tributes_by_day"), &day_key(7, id))
            .unwrap()
            .is_some());
    }

    for fail_after in 1..=3 {
        let storage = Arc::new(MemoryStorage::new());
        let seed = TributeRepositoryWriter::new(storage.clone(), storage.clone());
        seed.put(&tribute(U256::from(77), owner, 7)).unwrap();
        let failing = Arc::new(FailAfterWriter {
            inner: storage.clone(),
            fail_after,
            calls: AtomicUsize::new(0),
        });
        let repository = TributeRepositoryWriter::new(storage.clone(), failing);
        assert!(matches!(
            repository.delete(id),
            Err(TributeRepositoryError::Storage(_))
        ));
        assert!(storage
            .get(namespace("tributes_by_owner"), &owner_key(owner, id))
            .unwrap()
            .is_some());
        assert!(storage
            .get(namespace("tributes_by_day"), &day_key(7, id))
            .unwrap()
            .is_some());
        assert!(storage
            .get(namespace("tributes"), &id_key(id))
            .unwrap()
            .is_some());
    }
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
