mod conformance;

use std::sync::Arc;

use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle, StorageWriterHandle};

#[test]
fn atomic_batches_preserve_order_metadata_and_idempotency() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::atomic_batches_preserve_order_metadata_and_idempotency(reader, writer);
}

#[test]
fn put_get_replace_and_repeat() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::put_get_replace_and_repeat(reader, writer);
}

#[test]
fn delete_is_idempotent_and_namespaces_are_isolated() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::delete_is_idempotent_and_namespaces_are_isolated(reader, writer);
}

#[test]
fn scans_are_raw_byte_ordered_and_prefix_bounded() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::scans_are_raw_byte_ordered_and_prefix_bounded(reader, writer);
}

#[test]
fn cursors_are_exclusive_and_traverse_multiple_pages() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::cursors_are_exclusive_and_traverse_multiple_pages(reader, writer);
}

#[test]
fn pages_are_bounded_by_total_value_bytes() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::pages_are_bounded_by_total_value_bytes(reader, writer);
}

#[test]
fn cloned_handles_share_state_without_torn_values() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::cloned_handles_share_state_without_torn_values(reader, writer);
}

#[test]
fn maximum_key_value_and_entry_count_boundaries() {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;

    conformance::maximum_key_value_and_entry_count_boundaries(reader, writer);
}
