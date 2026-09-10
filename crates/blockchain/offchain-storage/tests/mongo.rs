mod conformance;

use std::{panic::AssertUnwindSafe, sync::Arc};

use mongodb::{
    bson::{doc, spec::BinarySubtype, Binary, Bson, Document},
    sync::Client,
};
use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, MongoStorage, MongoStorageConfig, Namespace,
    StorageErrorKind, StorageReader, StorageReaderHandle, StorageWriter, StorageWriterHandle,
    Value, MAX_VALUE_BYTES,
};

macro_rules! mongo_conformance_test {
    ($name:ident) => {
        #[test]
        #[ignore = "requires OUTBE_TEST_MONGODB_URI"]
        fn $name() {
            run_isolated(stringify!($name), conformance::$name);
        }
    };
}

mongo_conformance_test!(put_get_replace_and_repeat);
mongo_conformance_test!(delete_is_idempotent_and_namespaces_are_isolated);
mongo_conformance_test!(scans_are_raw_byte_ordered_and_prefix_bounded);
mongo_conformance_test!(cursors_are_exclusive_and_traverse_multiple_pages);
mongo_conformance_test!(pages_are_bounded_by_total_value_bytes);
mongo_conformance_test!(cloned_handles_share_state_without_torn_values);
mongo_conformance_test!(maximum_key_value_and_entry_count_boundaries);
mongo_conformance_test!(atomic_batches_preserve_order_metadata_and_idempotency);

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn malformed_mongo_documents_are_corruption() {
    let uri = mongo_uri();
    let database = isolated_database_name("malformed_mongo_documents_are_corruption");
    let client = Client::with_uri_str(&uri).unwrap();
    let storage = MongoStorage::connect(MongoStorageConfig {
        uri,
        database: database.clone(),
    })
    .unwrap();
    let namespace = Namespace::new("corrupt_records").unwrap();
    let collection = client
        .database(&database)
        .collection::<Document>(namespace.as_str());

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        collection
            .insert_one(doc! { "_id": "aa", "value": "not binary" })
            .run()
            .unwrap();
        let error = storage
            .get(namespace.clone(), &Key::new([0xaa]).unwrap())
            .expect_err("wrong value type must be corruption");
        assert_eq!(error.kind(), StorageErrorKind::Corruption);
        collection.delete_many(doc! {}).run().unwrap();

        for malformed_projection in [
            Bson::String("not a document".to_owned()),
            Bson::Document(doc! {}),
            Bson::Document(doc! { "block_number": 7 }),
            Bson::Document(doc! { "UPPERCASE": "7" }),
        ] {
            collection
                .insert_one(doc! {
                    "_id": "aa",
                    "value": Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: vec![1],
                    }),
                    "_projection": malformed_projection,
                })
                .run()
                .unwrap();
            let error = storage
                .get_record(namespace.clone(), &Key::new([0xaa]).unwrap())
                .expect_err("malformed _projection must be corruption");
            assert_eq!(error.kind(), StorageErrorKind::Corruption);
            collection.delete_many(doc! {}).run().unwrap();
        }

        collection
            .insert_one(doc! {
                "_id": 7,
                "value": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: vec![1],
                }),
            })
            .run()
            .unwrap();
        let request = outbe_offchain_storage::ScanRequest::new(b"a", None, 1).unwrap();
        let error = storage
            .scan_prefix(namespace.clone(), request)
            .expect_err("non-string _id must not disappear from a prefix scan");
        assert_eq!(error.kind(), StorageErrorKind::Corruption);
        collection.delete_many(doc! {}).run().unwrap();

        collection
            .insert_one(doc! {
                "_id": "aa",
                "value": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: vec![1],
                }),
                "unexpected": true,
            })
            .run()
            .unwrap();
        let error = storage
            .get(namespace.clone(), &Key::new([0xaa]).unwrap())
            .expect_err("unexpected fields must be corruption");
        assert_eq!(error.kind(), StorageErrorKind::Corruption);
        collection.delete_many(doc! {}).run().unwrap();

        collection
            .insert_one(doc! {
                "_id": "aa",
                "value": Bson::Binary(Binary {
                    subtype: BinarySubtype::Uuid,
                    bytes: vec![1; 16],
                }),
            })
            .run()
            .unwrap();
        let error = storage
            .get(namespace.clone(), &Key::new([0xaa]).unwrap())
            .expect_err("unexpected binary subtype must be corruption");
        assert_eq!(error.kind(), StorageErrorKind::Corruption);
        collection.delete_many(doc! {}).run().unwrap();

        collection
            .insert_one(doc! {
                "_id": "zz",
                "value": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: vec![1],
                }),
            })
            .run()
            .unwrap();
        let request = outbe_offchain_storage::ScanRequest::new(&[], None, 1).unwrap();
        let error = storage
            .scan_prefix(namespace.clone(), request)
            .expect_err("invalid key encoding must be corruption");
        assert_eq!(error.kind(), StorageErrorKind::Corruption);
        collection.delete_many(doc! {}).run().unwrap();

        collection
            .insert_one(doc! {
                "_id": "aa",
                "value": Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: vec![2; MAX_VALUE_BYTES + 1],
                }),
            })
            .run()
            .unwrap();
        let error = storage
            .get(namespace, &Key::new([0xaa]).unwrap())
            .expect_err("oversized stored value must be corruption");
        assert_eq!(error.kind(), StorageErrorKind::Corruption);
    }));

    client.database(&database).drop().run().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn atomic_batch_rolls_back_when_a_late_operation_fails() {
    let uri = mongo_uri();
    let database = isolated_database_name("atomic_batch_rolls_back");
    let client = Client::with_uri_str(&uri).unwrap();
    client.database(&database).drop().run().unwrap();
    let accepted = Namespace::new("accepted_records").unwrap();
    let rejected = Namespace::new("rejected_records").unwrap();
    client
        .database(&database)
        .create_collection(rejected.as_str())
        .validator(doc! { "$expr": false })
        .run()
        .unwrap();
    let storage = MongoStorage::connect(MongoStorageConfig {
        uri,
        database: database.clone(),
    })
    .unwrap();
    storage.verify_transaction_support().unwrap();

    let first_key = Key::new(b"first".to_vec()).unwrap();
    let second_key = Key::new(b"second".to_vec()).unwrap();
    let batch = AtomicWriteBatch::from_operations(vec![
        AtomicWriteOperation::put(
            accepted.clone(),
            first_key.clone(),
            Value::new(b"first".to_vec()).unwrap(),
        ),
        AtomicWriteOperation::put(
            rejected.clone(),
            second_key.clone(),
            Value::new(b"second".to_vec()).unwrap(),
        ),
    ]);
    let error = storage
        .apply_atomic(&batch)
        .expect_err("the late rejected write must abort the transaction");
    assert_eq!(error.kind(), StorageErrorKind::Backend);
    assert_eq!(storage.get(accepted, &first_key).unwrap(), None);
    assert_eq!(storage.get(rejected, &second_key).unwrap(), None);

    client.database(&database).drop().run().unwrap();
}

#[test]
#[ignore = "requires OUTBE_TEST_MONGODB_URI"]
fn other_mongo_failures_are_backend_errors() {
    let uri = mongo_uri();
    let database = isolated_database_name("other_mongo_failures_are_backend_errors");
    let client = Client::with_uri_str(&uri).unwrap();
    client.database(&database).drop().run().unwrap();
    let namespace = Namespace::new("rejected_records").unwrap();
    client
        .database(&database)
        .create_collection(namespace.as_str())
        .validator(doc! { "$expr": false })
        .run()
        .unwrap();
    let storage = MongoStorage::connect(MongoStorageConfig {
        uri,
        database: database.clone(),
    })
    .unwrap();

    let error = storage
        .put(
            namespace,
            &Key::new(b"key".to_vec()).unwrap(),
            &Value::new(b"value".to_vec()).unwrap(),
        )
        .expect_err("collection validator must reject the write");
    assert_eq!(error.kind(), StorageErrorKind::Backend);
    client.database(&database).drop().run().unwrap();
}

fn run_isolated(test_name: &str, test: fn(StorageReaderHandle, StorageWriterHandle)) {
    let uri = mongo_uri();
    let database = isolated_database_name(test_name);
    let cleanup_client = Client::with_uri_str(&uri).unwrap();
    cleanup_client.database(&database).drop().run().unwrap();
    let storage = Arc::new(
        MongoStorage::connect(MongoStorageConfig {
            uri,
            database: database.clone(),
        })
        .unwrap(),
    );
    storage.verify_transaction_support().unwrap();
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| test(reader, writer)));
    cleanup_client.database(&database).drop().run().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn mongo_uri() -> String {
    std::env::var("OUTBE_TEST_MONGODB_URI")
        .expect("set OUTBE_TEST_MONGODB_URI before running ignored MongoDB tests")
}

fn isolated_database_name(test_name: &str) -> String {
    let compact_name: String = test_name.chars().take(30).collect();
    format!("outbe_storage_{}_{}", std::process::id(), compact_name)
}
