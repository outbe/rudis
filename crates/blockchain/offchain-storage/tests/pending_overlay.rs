use std::sync::Arc;

use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, MemoryStorage, Namespace, PendingOverlayStorage,
    ScanRequest, StorageReader, StorageReaderHandle, StorageWriter, Value,
};

#[test]
fn pending_batch_overrides_base_puts_and_deletes_without_copying_untouched_records() {
    let base = Arc::new(MemoryStorage::new());
    let namespace = Namespace::new("records").unwrap();
    let replaced = Key::new(b"replaced".to_vec()).unwrap();
    let deleted = Key::new(b"deleted".to_vec()).unwrap();
    let untouched = Key::new(b"untouched".to_vec()).unwrap();
    base.put(
        namespace.clone(),
        &replaced,
        &Value::new(b"base-replaced".to_vec()).unwrap(),
    )
    .unwrap();
    base.put(
        namespace.clone(),
        &deleted,
        &Value::new(b"base-deleted".to_vec()).unwrap(),
    )
    .unwrap();
    base.put(
        namespace.clone(),
        &untouched,
        &Value::new(b"base-untouched".to_vec()).unwrap(),
    )
    .unwrap();

    let base_reader: StorageReaderHandle = base.clone();
    let overlay = PendingOverlayStorage::new(base_reader);
    overlay
        .apply_atomic(&AtomicWriteBatch::from_operations(vec![
            AtomicWriteOperation::put(
                namespace.clone(),
                replaced.clone(),
                Value::new(b"pending-replaced".to_vec()).unwrap(),
            ),
            AtomicWriteOperation::delete(namespace.clone(), deleted.clone()),
        ]))
        .unwrap();

    assert_eq!(
        overlay
            .get(namespace.clone(), &replaced)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"pending-replaced"
    );
    assert_eq!(overlay.get(namespace.clone(), &deleted).unwrap(), None);
    assert_eq!(
        overlay
            .get(namespace.clone(), &untouched)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"base-untouched"
    );

    assert_eq!(
        base.get(namespace.clone(), &replaced)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"base-replaced"
    );
    assert!(base.get(namespace, &deleted).unwrap().is_some());
}

#[test]
fn pending_index_mutations_merge_with_base_order_and_pagination() {
    let base = Arc::new(MemoryStorage::new());
    let namespace = Namespace::new("owner_index").unwrap();
    for raw_key in [10_u8, 20, 30, 40] {
        let key = Key::new(vec![raw_key]).unwrap();
        base.put(namespace.clone(), &key, &Value::new(vec![raw_key]).unwrap())
            .unwrap();
    }

    let base_reader: StorageReaderHandle = base;
    let overlay = PendingOverlayStorage::new(base_reader);
    overlay
        .apply_atomic(&AtomicWriteBatch::from_operations(vec![
            AtomicWriteOperation::delete(namespace.clone(), Key::new(vec![20]).unwrap()),
            AtomicWriteOperation::put(
                namespace.clone(),
                Key::new(vec![15]).unwrap(),
                Value::new(vec![15]).unwrap(),
            ),
            AtomicWriteOperation::put(
                namespace.clone(),
                Key::new(vec![30]).unwrap(),
                Value::new(vec![99]).unwrap(),
            ),
        ]))
        .unwrap();

    let first = overlay
        .scan_prefix(namespace.clone(), ScanRequest::new(&[], None, 2).unwrap())
        .unwrap();
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| entry.key.as_bytes()[0])
            .collect::<Vec<_>>(),
        vec![10, 15]
    );
    let cursor = first.next_after.expect("two merged records remain");

    let second = overlay
        .scan_prefix(namespace, ScanRequest::new(&[], Some(&cursor), 2).unwrap())
        .unwrap();
    assert_eq!(
        second
            .entries
            .iter()
            .map(|entry| (entry.key.as_bytes()[0], entry.value.as_bytes()[0]))
            .collect::<Vec<_>>(),
        vec![(30, 99), (40, 40)]
    );
    assert_eq!(second.next_after, None);
}

#[test]
fn durable_ack_only_retires_overlay_mutations_through_its_generation() {
    let base = Arc::new(MemoryStorage::new());
    let namespace = Namespace::new("records").unwrap();
    let key = Key::new(b"same-key".to_vec()).unwrap();
    let base_reader: StorageReaderHandle = base.clone();
    let overlay = PendingOverlayStorage::new(base_reader);
    let first_batch = AtomicWriteBatch::from_operations(vec![AtomicWriteOperation::put(
        namespace.clone(),
        key.clone(),
        Value::new(b"first".to_vec()).unwrap(),
    )]);
    let second_batch = AtomicWriteBatch::from_operations(vec![AtomicWriteOperation::put(
        namespace.clone(),
        key.clone(),
        Value::new(b"second".to_vec()).unwrap(),
    )]);

    overlay.apply_atomic(&first_batch).unwrap();
    let first_generation = overlay.current_generation();
    overlay.apply_atomic(&second_batch).unwrap();
    let second_generation = overlay.current_generation();

    base.apply_atomic(&first_batch).unwrap();
    overlay.acknowledge(first_generation);
    assert_eq!(
        overlay
            .get(namespace.clone(), &key)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"second",
        "ACK of N must not remove the newer N+1 value"
    );

    base.apply_atomic(&second_batch).unwrap();
    overlay.acknowledge(second_generation);
    base.put(
        namespace.clone(),
        &key,
        &Value::new(b"base-after-ack".to_vec()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        overlay.get(namespace, &key).unwrap().unwrap().as_bytes(),
        b"base-after-ack",
        "after the latest ACK the overlay must fall back to the durable base"
    );
}
