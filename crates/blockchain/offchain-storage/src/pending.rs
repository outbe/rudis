use std::collections::{BTreeMap, VecDeque};

use parking_lot::RwLock;

use crate::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, ScanEntry, ScanPage, ScanRequest,
    StorageError, StorageReader, StorageReaderHandle, StorageWriter, StoredValue, MAX_SCAN_ENTRIES,
    MAX_SCAN_PAGE_VALUE_BYTES,
};

#[derive(Clone, Debug)]
enum PendingRecord {
    Put(StoredValue),
    Delete,
}

#[derive(Clone, Debug)]
struct VersionedPendingRecord {
    generation: u64,
    record: PendingRecord,
}

#[derive(Default)]
struct PendingState {
    generation: u64,
    records: BTreeMap<Namespace, BTreeMap<Key, VersionedPendingRecord>>,
}

/// Process-local finalized mutations layered over the durable MongoDB projection.
pub struct PendingOverlayStorage {
    base: StorageReaderHandle,
    state: RwLock<PendingState>,
}

impl PendingOverlayStorage {
    #[must_use]
    pub fn new(base: StorageReaderHandle) -> Self {
        Self {
            base,
            state: RwLock::new(PendingState::default()),
        }
    }

    /// Returns the generation assigned to the latest applied pending batch.
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.state.read().generation
    }

    /// Retires mutations that are now covered by a durable MongoDB acknowledgement.
    pub fn acknowledge(&self, generation: u64) {
        let mut state = self.state.write();
        state.records.retain(|_, records| {
            records.retain(|_, record| record.generation > generation);
            !records.is_empty()
        });
    }
}

impl StorageReader for PendingOverlayStorage {
    fn get_record(
        &self,
        namespace: Namespace,
        key: &Key,
    ) -> Result<Option<StoredValue>, StorageError> {
        match self
            .state
            .read()
            .records
            .get(&namespace)
            .and_then(|records| records.get(key))
            .cloned()
        {
            Some(VersionedPendingRecord {
                record: PendingRecord::Put(record),
                ..
            }) => Ok(Some(record)),
            Some(VersionedPendingRecord {
                record: PendingRecord::Delete,
                ..
            }) => Ok(None),
            None => self.base.get_record(namespace, key),
        }
    }

    fn get_records(
        &self,
        namespace: Namespace,
        keys: &[Key],
    ) -> Result<Vec<Option<StoredValue>>, StorageError> {
        keys.iter()
            .map(|key| self.get_record(namespace.clone(), key))
            .collect()
    }

    fn scan_prefix(
        &self,
        namespace: Namespace,
        request: ScanRequest<'_>,
    ) -> Result<ScanPage, StorageError> {
        request.validate()?;
        let prefix = request.prefix().to_vec();
        let requested_after = request.after().cloned();
        let limit = request.limit();
        let pending = self
            .state
            .read()
            .records
            .get(&namespace)
            .map(|records| {
                records
                    .iter()
                    .filter(|(key, _)| {
                        key.as_bytes().starts_with(&prefix)
                            && requested_after.as_ref().is_none_or(|after| *key > after)
                    })
                    .map(|(key, record)| (key.clone(), record.record.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let mut pending_index = 0;
        let mut base_after = requested_after;
        let mut base_entries = VecDeque::new();
        let mut base_exhausted = false;
        let mut entries = Vec::new();
        let mut value_bytes = 0_usize;
        let mut has_more = false;

        loop {
            if base_entries.is_empty() && !base_exhausted {
                let page = self.base.scan_prefix(
                    namespace.clone(),
                    ScanRequest::new(&prefix, base_after.as_ref(), MAX_SCAN_ENTRIES)?,
                )?;
                if page.entries.is_empty() {
                    if page.next_after.is_some() {
                        return Err(StorageError::Corruption(
                            "base scan returned an empty page with a continuation".to_owned(),
                        ));
                    }
                    base_exhausted = true;
                } else {
                    base_exhausted = page.next_after.is_none();
                    if let Some(next_after) = page.next_after {
                        base_after = Some(next_after);
                    }
                    base_entries.extend(page.entries);
                }
            }

            let base_key = base_entries.front().map(|entry| &entry.key);
            let pending_key = pending.get(pending_index).map(|(key, _)| key);
            let candidate = match (base_key, pending_key) {
                (None, None) => break,
                (Some(_), None) => base_entries.pop_front(),
                (None, Some(_)) => {
                    let (key, record) = &pending[pending_index];
                    pending_index += 1;
                    pending_scan_entry(key, record)
                }
                (Some(base_key), Some(pending_key)) => match base_key.cmp(pending_key) {
                    std::cmp::Ordering::Less => base_entries.pop_front(),
                    std::cmp::Ordering::Equal => {
                        base_entries.pop_front();
                        let (key, record) = &pending[pending_index];
                        pending_index += 1;
                        pending_scan_entry(key, record)
                    }
                    std::cmp::Ordering::Greater => {
                        let (key, record) = &pending[pending_index];
                        pending_index += 1;
                        pending_scan_entry(key, record)
                    }
                },
            };
            let Some(candidate) = candidate else {
                continue;
            };
            let candidate_bytes = candidate.value.as_bytes().len()
                + candidate
                    .metadata
                    .as_ref()
                    .map_or(0, |metadata| metadata.encoded_len());
            if entries.len() == limit
                || value_bytes.saturating_add(candidate_bytes) > MAX_SCAN_PAGE_VALUE_BYTES
            {
                has_more = true;
                break;
            }
            value_bytes += candidate_bytes;
            entries.push(candidate);
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

fn pending_scan_entry(key: &Key, record: &PendingRecord) -> Option<ScanEntry> {
    match record {
        PendingRecord::Put(record) => Some(ScanEntry {
            key: key.clone(),
            value: record.value.clone(),
            metadata: record.metadata.clone(),
        }),
        PendingRecord::Delete => None,
    }
}

impl StorageWriter for PendingOverlayStorage {
    fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
        batch.validate()?;
        if batch.is_empty() {
            return Ok(());
        }
        let mut state = self.state.write();
        let generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| StorageError::Corruption("pending generation overflow".to_owned()))?;
        state.generation = generation;
        for operation in batch.operations() {
            match operation {
                AtomicWriteOperation::Put {
                    namespace,
                    key,
                    record,
                } => {
                    state.records.entry(namespace.clone()).or_default().insert(
                        key.clone(),
                        VersionedPendingRecord {
                            generation,
                            record: PendingRecord::Put(record.clone()),
                        },
                    );
                }
                AtomicWriteOperation::Delete { namespace, key } => {
                    state.records.entry(namespace.clone()).or_default().insert(
                        key.clone(),
                        VersionedPendingRecord {
                            generation,
                            record: PendingRecord::Delete,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}
