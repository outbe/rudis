mod conformance;

use std::sync::Arc;

use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, RocksDbReader, RocksDbStorage,
    StorageReader, StorageReaderHandle, StorageWriter, StorageWriterHandle, Value,
    MAX_ATOMIC_BATCH_OPERATIONS,
};

macro_rules! conformance_test {
    ($name:ident) => {
        #[test]
        fn $name() {
            let root = tempfile::tempdir().unwrap();
            let storage = Arc::new(RocksDbStorage::open(root.path().join("primary")).unwrap());
            let reader: StorageReaderHandle = storage.clone();
            let writer: StorageWriterHandle = storage;
            conformance::$name(reader, writer);
        }
    };
}
conformance_test!(atomic_batches_preserve_order_metadata_and_idempotency);
conformance_test!(put_get_replace_and_repeat);
conformance_test!(delete_is_idempotent_and_namespaces_are_isolated);
conformance_test!(scans_are_raw_byte_ordered_and_prefix_bounded);
conformance_test!(cursors_are_exclusive_and_traverse_multiple_pages);
conformance_test!(pages_are_bounded_by_total_value_bytes);
conformance_test!(cloned_handles_share_state_without_torn_values);
conformance_test!(maximum_key_value_and_entry_count_boundaries);

#[test]
fn invalid_batch_cannot_publish_its_valid_prefix() {
    let root = tempfile::tempdir().unwrap();
    let storage = RocksDbStorage::open(root.path().join("primary")).unwrap();
    let ns = Namespace::new("records").unwrap();
    let key = Key::new(b"key".to_vec()).unwrap();
    let value = Value::new(b"value".to_vec()).unwrap();
    let batch = AtomicWriteBatch::from_operations(vec![
        AtomicWriteOperation::put(
            ns.clone(),
            key.clone(),
            value
        );
        MAX_ATOMIC_BATCH_OPERATIONS + 1
    ]);
    assert!(storage.apply_atomic(&batch).is_err());
    assert!(storage.get(ns, &key).unwrap().is_none());
}

#[test]
fn secondary_sessions_are_frozen_isolated_and_reopenable() {
    let root = tempfile::tempdir().unwrap();
    let primary = root.path().join("primary");
    let first_dir = root.path().join("lane_a");
    let second_dir = root.path().join("lane_b");
    assert!(RocksDbReader::open(&primary, &first_dir).is_err());
    assert!(
        !primary.exists(),
        "reader must not create a missing primary"
    );
    let writer = RocksDbStorage::open(&primary).unwrap();
    let ns = Namespace::new("records").unwrap();
    let key = Key::new(b"key".to_vec()).unwrap();
    let old = Value::new(b"old".to_vec()).unwrap();
    let new = Value::new(b"new".to_vec()).unwrap();
    writer.put(ns.clone(), &key, &old).unwrap();
    let first = RocksDbReader::open(&primary, &first_dir).unwrap();
    assert!(RocksDbReader::open(&primary, &first_dir).is_err());
    writer.put(ns.clone(), &key, &new).unwrap();
    let second = RocksDbReader::open(&primary, &second_dir).unwrap();
    assert_eq!(first.get(ns.clone(), &key).unwrap(), Some(old));
    assert_eq!(second.get(ns.clone(), &key).unwrap(), Some(new.clone()));
    drop(first);
    let refreshed = RocksDbReader::open(&primary, &first_dir).unwrap();
    assert_eq!(refreshed.get(ns, &key).unwrap(), Some(new));
}

#[test]
fn primary_exclusion_and_durable_reopen() {
    let root = tempfile::tempdir().unwrap();
    let primary = root.path().join("primary");
    let storage = RocksDbStorage::open(&primary).unwrap();
    let ns = Namespace::new("records").unwrap();
    let key = Key::new(b"key".to_vec()).unwrap();
    let value = Value::new(b"durable".to_vec()).unwrap();
    storage.put(ns.clone(), &key, &value).unwrap();
    storage.verify_transaction_capability().unwrap();
    assert!(RocksDbStorage::open(&primary).is_err());
    drop(storage);
    let reopened = RocksDbStorage::open(&primary).unwrap();
    assert_eq!(reopened.get(ns, &key).unwrap(), Some(value));
}

#[cfg(unix)]
#[test]
fn symlinked_secondary_overlap_is_rejected_before_creating_any_primary_subdirectory() {
    let root = tempfile::tempdir().unwrap();
    let primary = root.path().join("primary");
    let _writer = RocksDbStorage::open(&primary).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&primary, &alias).unwrap();
    let error = RocksDbReader::open(&primary, &alias.join("reader")).unwrap_err();
    assert_eq!(
        error.kind(),
        outbe_offchain_storage::StorageErrorKind::InvalidArgument
    );
    assert!(!primary.join("reader").exists());
}
