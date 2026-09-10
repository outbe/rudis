use std::collections::BTreeMap;

use parking_lot::RwLock;

use crate::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, ScanEntry, ScanPage, ScanRequest,
    StorageError, StorageReader, StorageWriter, StoredValue, MAX_SCAN_PAGE_VALUE_BYTES,
};

/// Instance-owned in-memory storage adapter.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    records: RwLock<BTreeMap<Namespace, BTreeMap<Key, StoredValue>>>,
}

impl MemoryStorage {
    /// Creates an empty, isolated adapter instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageReader for MemoryStorage {
    fn get_record(
        &self,
        namespace: Namespace,
        key: &Key,
    ) -> Result<Option<StoredValue>, StorageError> {
        Ok(self
            .records
            .read()
            .get(&namespace)
            .and_then(|records| records.get(key))
            .cloned())
    }

    fn get_records(
        &self,
        namespace: Namespace,
        keys: &[Key],
    ) -> Result<Vec<Option<StoredValue>>, StorageError> {
        let records = self.records.read();
        let namespace_records = records.get(&namespace);
        Ok(keys
            .iter()
            .map(|key| {
                namespace_records
                    .and_then(|records| records.get(key))
                    .cloned()
            })
            .collect())
    }

    fn scan_prefix(
        &self,
        namespace: Namespace,
        request: ScanRequest<'_>,
    ) -> Result<ScanPage, StorageError> {
        request.validate()?;
        let records = self.records.read();
        let Some(records) = records.get(&namespace) else {
            return Ok(ScanPage::default());
        };

        let mut entries = Vec::new();
        let mut value_bytes = 0_usize;
        let mut has_more = false;
        for (key, record) in records {
            if !key.as_bytes().starts_with(request.prefix()) {
                continue;
            }
            if request.after().is_some_and(|after| key <= after) {
                continue;
            }
            if entries.len() == request.limit()
                || value_bytes
                    + record.value.as_bytes().len()
                    + record
                        .metadata
                        .as_ref()
                        .map_or(0, |metadata| metadata.encoded_len())
                    > MAX_SCAN_PAGE_VALUE_BYTES
            {
                has_more = true;
                break;
            }
            value_bytes += record.value.as_bytes().len()
                + record
                    .metadata
                    .as_ref()
                    .map_or(0, |metadata| metadata.encoded_len());
            entries.push(ScanEntry {
                key: key.clone(),
                value: record.value.clone(),
                metadata: record.metadata.clone(),
            });
        }

        let next_after = if has_more {
            Some(
                entries
                    .last()
                    .ok_or_else(|| {
                        StorageError::Corruption(
                            "stored record exceeds the scan page byte bound".to_owned(),
                        )
                    })?
                    .key
                    .clone(),
            )
        } else {
            None
        };
        Ok(ScanPage {
            entries,
            next_after,
        })
    }
}

impl StorageWriter for MemoryStorage {
    fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
        batch.validate()?;
        let mut records = self.records.write();
        for operation in batch.operations() {
            match operation {
                AtomicWriteOperation::Put {
                    namespace,
                    key,
                    record,
                } => {
                    records
                        .entry(namespace.clone())
                        .or_default()
                        .insert(key.clone(), record.clone());
                }
                AtomicWriteOperation::Delete { namespace, key } => {
                    if let Some(namespace_records) = records.get_mut(namespace) {
                        namespace_records.remove(key);
                    }
                }
            }
        }
        Ok(())
    }
}
