use std::collections::BTreeMap;

use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, ScanRequest, StorageMetadata,
    StorageReaderHandle, StorageWriterHandle, StoredValue, Value, MAX_KEY_BYTES, MAX_SCAN_ENTRIES,
    MAX_SCAN_PAGE_VALUE_BYTES, MAX_VALUE_BYTES,
};

pub fn atomic_batches_preserve_order_metadata_and_idempotency(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let primary = Namespace::new("atomic_primary").unwrap();
    let index = Namespace::new("atomic_index").unwrap();
    let first_key = Key::new(b"first".to_vec()).unwrap();
    let second_key = Key::new(b"second".to_vec()).unwrap();
    let index_key = Key::new(b"index".to_vec()).unwrap();
    let metadata = StorageMetadata::new(BTreeMap::from([
        ("block_number".to_owned(), "7".to_owned()),
        ("block_hash".to_owned(), "0x01".to_owned()),
    ]))
    .unwrap();

    let mut batch = AtomicWriteBatch::new();
    batch.push(AtomicWriteOperation::put_record(
        primary.clone(),
        first_key.clone(),
        StoredValue::with_metadata(Value::new(b"old".to_vec()).unwrap(), metadata.clone()),
    ));
    batch.push(AtomicWriteOperation::put(
        primary.clone(),
        first_key.clone(),
        Value::new(b"replacement".to_vec()).unwrap(),
    ));
    batch.push(AtomicWriteOperation::put_record(
        primary.clone(),
        second_key.clone(),
        StoredValue::with_metadata(Value::new(b"second".to_vec()).unwrap(), metadata.clone()),
    ));
    batch.push(AtomicWriteOperation::put(
        index.clone(),
        index_key.clone(),
        Value::new(Vec::new()).unwrap(),
    ));

    writer.apply_atomic(&batch).unwrap();
    writer.apply_atomic(&batch).unwrap();

    let first = reader
        .get_record(primary.clone(), &first_key)
        .unwrap()
        .unwrap();
    assert_eq!(first.value.as_bytes(), b"replacement");
    assert_eq!(first.metadata, None, "plain replacement removes metadata");
    let second = reader
        .get_record(primary.clone(), &second_key)
        .unwrap()
        .unwrap();
    assert_eq!(second.metadata, Some(metadata.clone()));
    assert_eq!(
        reader.get(primary.clone(), &second_key).unwrap().unwrap(),
        second.value,
        "value-only reads intentionally discard metadata"
    );
    assert_eq!(
        reader
            .get_records(primary.clone(), &[second_key.clone(), first_key.clone()])
            .unwrap(),
        vec![Some(second.clone()), Some(first)]
    );
    assert_eq!(
        reader
            .get_records(primary.clone(), &[second_key.clone(), second_key.clone()])
            .unwrap(),
        vec![Some(second.clone()), Some(second)]
    );
    let page = reader
        .scan_prefix(
            primary,
            ScanRequest::new(&[], None, MAX_SCAN_ENTRIES).unwrap(),
        )
        .unwrap();
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].metadata, None);
    assert_eq!(page.entries[1].metadata, Some(metadata));
    assert_eq!(
        reader
            .get_record(index, &index_key)
            .unwrap()
            .unwrap()
            .metadata,
        None
    );
}

pub fn put_get_replace_and_repeat(reader: StorageReaderHandle, writer: StorageWriterHandle) {
    let namespace = Namespace::new("records").expect("valid namespace");
    let key = Key::new(b"key".to_vec()).expect("valid key");
    let first = Value::new(b"first".to_vec()).expect("valid value");
    let replacement = Value::new(b"replacement".to_vec()).expect("valid value");

    assert_eq!(reader.get(namespace.clone(), &key).unwrap(), None);

    writer.put(namespace.clone(), &key, &first).unwrap();
    assert_eq!(reader.get(namespace.clone(), &key).unwrap(), Some(first));

    writer.put(namespace.clone(), &key, &replacement).unwrap();
    writer.put(namespace.clone(), &key, &replacement).unwrap();
    assert_eq!(reader.get(namespace, &key).unwrap(), Some(replacement));
}

pub fn delete_is_idempotent_and_namespaces_are_isolated(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let first_namespace = Namespace::new("first_records").expect("valid namespace");
    let second_namespace = Namespace::new("second_records").expect("valid namespace");
    let key = Key::new(b"same-key".to_vec()).expect("valid key");
    let first_value = Value::new(b"first".to_vec()).expect("valid value");
    let second_value = Value::new(b"second".to_vec()).expect("valid value");

    writer
        .put(first_namespace.clone(), &key, &first_value)
        .unwrap();
    writer
        .put(second_namespace.clone(), &key, &second_value)
        .unwrap();
    writer.delete(first_namespace.clone(), &key).unwrap();
    writer.delete(first_namespace.clone(), &key).unwrap();

    assert_eq!(reader.get(first_namespace, &key).unwrap(), None);
    assert_eq!(
        reader.get(second_namespace, &key).unwrap(),
        Some(second_value)
    );
}

pub fn scans_are_raw_byte_ordered_and_prefix_bounded(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let namespace = Namespace::new("scan_records").expect("valid namespace");
    let raw_keys = [
        vec![0x00],
        vec![0x00, 0xff],
        vec![0x01],
        vec![0x01, 0x00],
        vec![0xff],
        vec![0xff, 0x00],
    ];
    for raw_key in &raw_keys {
        let key = Key::new(raw_key.clone()).unwrap();
        let value = Value::new(raw_key.clone()).unwrap();
        writer.put(namespace.clone(), &key, &value).unwrap();
    }

    let empty = ScanRequest::new(&[], None, 10).unwrap();
    let empty_page = reader.scan_prefix(namespace.clone(), empty).unwrap();
    assert_eq!(
        empty_page
            .entries
            .iter()
            .map(|entry| entry.key.as_bytes())
            .collect::<Vec<_>>(),
        raw_keys.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert_eq!(empty_page.next_after, None);

    let ordinary = ScanRequest::new(&[0x01], None, 10).unwrap();
    let ordinary_page = reader.scan_prefix(namespace.clone(), ordinary).unwrap();
    assert_eq!(
        ordinary_page
            .entries
            .iter()
            .map(|entry| entry.key.as_bytes())
            .collect::<Vec<_>>(),
        vec![&[0x01][..], &[0x01, 0x00][..]]
    );

    let all_ff = ScanRequest::new(&[0xff], None, 10).unwrap();
    let all_ff_page = reader.scan_prefix(namespace, all_ff).unwrap();
    assert_eq!(
        all_ff_page
            .entries
            .iter()
            .map(|entry| entry.key.as_bytes())
            .collect::<Vec<_>>(),
        vec![&[0xff][..], &[0xff, 0x00][..]]
    );
}

pub fn cursors_are_exclusive_and_traverse_multiple_pages(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let namespace = Namespace::new("paged_records").expect("valid namespace");
    for raw_key in [b"p0".as_slice(), b"p1", b"p2", b"q0"] {
        let key = Key::new(raw_key.to_vec()).unwrap();
        writer
            .put(namespace.clone(), &key, &Value::new(vec![1]).unwrap())
            .unwrap();
    }

    let first = reader
        .scan_prefix(namespace.clone(), ScanRequest::new(b"p", None, 2).unwrap())
        .unwrap();
    assert_eq!(
        first
            .entries
            .iter()
            .map(|entry| entry.key.as_bytes())
            .collect::<Vec<_>>(),
        vec![b"p0".as_slice(), b"p1"]
    );
    let cursor = first.next_after.expect("there is another matching key");

    let second = reader
        .scan_prefix(namespace, ScanRequest::new(b"p", Some(&cursor), 2).unwrap())
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].key.as_bytes(), b"p2");
    assert_eq!(second.next_after, None);
}

pub fn pages_are_bounded_by_total_value_bytes(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let namespace = Namespace::new("byte_bounded_records").expect("valid namespace");
    let first_key = Key::new(b"a".to_vec()).unwrap();
    let second_key = Key::new(b"b".to_vec()).unwrap();
    let first_value = Value::new(vec![7; MAX_SCAN_PAGE_VALUE_BYTES]).unwrap();
    let second_value = Value::new(vec![8]).unwrap();
    writer
        .put(namespace.clone(), &first_key, &first_value)
        .unwrap();
    writer
        .put(namespace.clone(), &second_key, &second_value)
        .unwrap();

    let first = reader
        .scan_prefix(namespace.clone(), ScanRequest::new(&[], None, 2).unwrap())
        .unwrap();
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].key, first_key);
    let cursor = first.next_after.expect("byte bound leaves another entry");

    let second = reader
        .scan_prefix(namespace, ScanRequest::new(&[], Some(&cursor), 2).unwrap())
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].key, second_key);
    assert_eq!(second.next_after, None);
}

pub fn cloned_handles_share_state_without_torn_values(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let namespace = Namespace::new("concurrent_records").expect("valid namespace");
    let key = Key::new(b"key".to_vec()).unwrap();
    let first = Value::new(vec![0x55; 64 * 1024]).unwrap();
    let second = Value::new(vec![0xaa; 64 * 1024]).unwrap();
    writer.put(namespace.clone(), &key, &first).unwrap();

    let writer_clone = writer.clone();
    let writer_namespace = namespace.clone();
    let writer_key = key.clone();
    let first_clone = first.clone();
    let second_clone = second.clone();
    let writer_thread = std::thread::spawn(move || {
        for iteration in 0..32 {
            let value = if iteration % 2 == 0 {
                &second_clone
            } else {
                &first_clone
            };
            writer_clone
                .put(writer_namespace.clone(), &writer_key, value)
                .unwrap();
        }
    });

    let reader_clone = reader.clone();
    for _ in 0..64 {
        let observed = reader_clone
            .get(namespace.clone(), &key)
            .unwrap()
            .expect("value remains present");
        assert!(observed == first || observed == second);
    }
    writer_thread.join().unwrap();

    assert!(reader.get(namespace, &key).unwrap().is_some());
}

pub fn maximum_key_value_and_entry_count_boundaries(
    reader: StorageReaderHandle,
    writer: StorageWriterHandle,
) {
    let boundary_namespace = Namespace::new("boundary_records").unwrap();
    let max_key = Key::new(vec![0x10; MAX_KEY_BYTES]).unwrap();
    let max_value = Value::new(vec![0x20; MAX_VALUE_BYTES]).unwrap();
    writer
        .put(boundary_namespace.clone(), &max_key, &max_value)
        .unwrap();
    assert_eq!(
        reader.get(boundary_namespace, &max_key).unwrap(),
        Some(max_value)
    );

    let page_namespace = Namespace::new("entry_boundary_records").unwrap();
    let value = Value::new(Vec::new()).unwrap();
    for index in 0..=MAX_SCAN_ENTRIES {
        let key = Key::new(u16::try_from(index).unwrap().to_be_bytes()).unwrap();
        writer.put(page_namespace.clone(), &key, &value).unwrap();
    }

    let first = reader
        .scan_prefix(
            page_namespace.clone(),
            ScanRequest::new(&[], None, MAX_SCAN_ENTRIES).unwrap(),
        )
        .unwrap();
    assert_eq!(first.entries.len(), MAX_SCAN_ENTRIES);
    let cursor = first.next_after.expect("one entry remains");
    let second = reader
        .scan_prefix(
            page_namespace,
            ScanRequest::new(&[], Some(&cursor), MAX_SCAN_ENTRIES).unwrap(),
        )
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.next_after, None);
}
