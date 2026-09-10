//! Durable primary and immutable-per-session secondary RocksDB capabilities.

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

use rocksdb::{Direction, ErrorKind, IteratorMode, Options, WriteBatch, WriteOptions, DB};

use crate::{
    rocks_codec::{decode_record, encode_key, encode_record, namespace_prefix},
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, ScanEntry, ScanPage, ScanRequest,
    StorageError, StorageReader, StorageWriter, StoredValue, MAX_SCAN_PAGE_VALUE_BYTES,
};

// The zero prefix cannot collide with encoded namespace keys (which start at 1).
const FORMAT_KEY: &[u8] = b"\0outbe-offchain-format";
const FORMAT_VALUE: &[u8] = b"outbe-offchain-rocksdb-v1";
const PROBE_KEY: &[u8] = b"\0outbe-write-probe";

/// Sole process-owned durable projection writer. Its DB lifetime owns the primary lock.
pub struct RocksDbStorage {
    db: DB,
}

/// One secondary view. It deliberately exposes no catch-up or write capability.
pub struct RocksDbReader {
    db: DB,
    // Drop the database before unlocking the secondary working directory.
    _ownership: File,
}

impl std::fmt::Debug for RocksDbStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbStorage").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RocksDbReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbReader").finish_non_exhaustive()
    }
}

impl RocksDbStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let mut options = options();
        options.create_if_missing(true);
        let db = DB::open(&options, path).map_err(map_error)?;
        match db.get(FORMAT_KEY).map_err(map_error)? {
            Some(value) if value == FORMAT_VALUE => {}
            Some(_) => {
                return Err(StorageError::Corruption(
                    "unsupported RocksDB storage format".into(),
                ))
            }
            None => {
                if let Some(entry) = db.iterator(IteratorMode::Start).next() {
                    entry.map_err(map_error)?;
                    return Err(StorageError::Corruption(
                        "nonempty RocksDB lacks storage format marker".into(),
                    ));
                }
                db.put_opt(FORMAT_KEY, FORMAT_VALUE, &durable_options())
                    .map_err(map_error)?;
            }
        }
        Ok(Self { db })
    }
}

impl RocksDbReader {
    /// Open and catch up before publishing the view; subsequent reads never refresh it.
    pub fn open(primary: &Path, secondary: &Path) -> Result<Self, StorageError> {
        // In particular, a reader never initializes an empty primary database.
        std::fs::metadata(primary.join("CURRENT")).map_err(StorageError::unavailable)?;
        // Canonical paths also catch aliases through symlinked parent directories.
        let primary = std::fs::canonicalize(primary).map_err(StorageError::unavailable)?;
        let proposed_secondary = resolve_existing_ancestor(secondary)?;
        if primary.starts_with(&proposed_secondary) || proposed_secondary.starts_with(&primary) {
            return Err(StorageError::invalid_argument(
                "RocksDB primary and secondary directories overlap",
            ));
        }
        std::fs::create_dir_all(secondary).map_err(StorageError::unavailable)?;
        let secondary = std::fs::canonicalize(secondary).map_err(StorageError::unavailable)?;
        if primary.starts_with(&secondary) || secondary.starts_with(&primary) {
            return Err(StorageError::invalid_argument(
                "RocksDB primary and secondary directories overlap",
            ));
        }
        let ownership = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(secondary.join("outbe-secondary.lock"))
            .map_err(StorageError::unavailable)?;
        ownership.try_lock().map_err(|error| {
            StorageError::invalid_argument(format!(
                "RocksDB secondary directory is already owned or cannot be locked: {error}"
            ))
        })?;
        let db = DB::open_as_secondary(&options(), &primary, &secondary).map_err(map_error)?;
        db.try_catch_up_with_primary().map_err(map_error)?;
        if db.get(FORMAT_KEY).map_err(map_error)?.as_deref() != Some(FORMAT_VALUE) {
            return Err(StorageError::Corruption(
                "missing or unsupported RocksDB storage format".into(),
            ));
        }
        Ok(Self {
            db,
            _ownership: ownership,
        })
    }
}

// Resolve symlinked parents before creating a missing secondary directory. A rejected
// reader configuration must not first create a directory inside the primary.
fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf, StorageError> {
    let absolute = std::path::absolute(path).map_err(StorageError::unavailable)?;
    let mut ancestor = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(ancestor) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = ancestor.file_name() else {
                    return Err(StorageError::unavailable(error));
                };
                missing.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| StorageError::unavailable(error))?;
            }
            Err(error) => return Err(StorageError::unavailable(error)),
        }
    }
}

fn options() -> Options {
    let mut options = Options::default();
    options.set_compression_type(rocksdb::DBCompressionType::Lz4);
    // Secondary needs to retain SST descriptors across primary unlink/compaction.
    options.set_max_open_files(-1);
    options
}

fn durable_options() -> WriteOptions {
    let mut options = WriteOptions::default();
    options.set_sync(true);
    options.disable_wal(false);
    options
}

fn get_record(
    db: &DB,
    namespace: Namespace,
    key: &Key,
) -> Result<Option<StoredValue>, StorageError> {
    db.get(encode_key(&namespace, key))
        .map_err(map_error)?
        .map(|bytes| decode_record(&bytes))
        .transpose()
}

fn get_records(
    db: &DB,
    namespace: Namespace,
    keys: &[Key],
) -> Result<Vec<Option<StoredValue>>, StorageError> {
    db.multi_get(keys.iter().map(|key| encode_key(&namespace, key)))
        .into_iter()
        .map(|result| {
            result
                .map_err(map_error)?
                .map(|bytes| decode_record(&bytes))
                .transpose()
        })
        .collect()
}

fn scan_prefix(
    db: &DB,
    namespace: Namespace,
    request: ScanRequest<'_>,
) -> Result<ScanPage, StorageError> {
    request.validate()?;
    let namespace = namespace_prefix(&namespace);
    let mut prefix = namespace.clone();
    prefix.extend_from_slice(request.prefix());
    let mut start = namespace.clone();
    start.extend_from_slice(request.after().map_or(request.prefix(), Key::as_bytes));
    let mut entries = Vec::<ScanEntry>::new();
    let mut value_bytes = 0;
    for item in db.iterator(IteratorMode::From(&start, Direction::Forward)) {
        let (encoded_key, encoded_value) = item.map_err(map_error)?;
        if !encoded_key.starts_with(&prefix) {
            break;
        }
        let key = Key::new(encoded_key[namespace.len()..].to_vec())
            .map_err(|_| StorageError::Corruption("invalid RocksDB storage key".into()))?;
        if request.after().is_some_and(|after| &key <= after) {
            continue;
        }
        let record = decode_record(&encoded_value)?;
        let bytes =
            record.value.as_bytes().len() + record.metadata.as_ref().map_or(0, |m| m.encoded_len());
        if entries.len() == request.limit() || value_bytes + bytes > MAX_SCAN_PAGE_VALUE_BYTES {
            let next_after = entries
                .last()
                .ok_or_else(|| StorageError::Corruption("record exceeds scan page bound".into()))?
                .key
                .clone();
            return Ok(ScanPage {
                entries,
                next_after: Some(next_after),
            });
        }
        value_bytes += bytes;
        entries.push(ScanEntry {
            key,
            value: record.value,
            metadata: record.metadata,
        });
    }
    Ok(ScanPage {
        entries,
        next_after: None,
    })
}

macro_rules! impl_reader {
    ($adapter:ty) => {
        impl StorageReader for $adapter {
            fn get_record(
                &self,
                namespace: Namespace,
                key: &Key,
            ) -> Result<Option<StoredValue>, StorageError> {
                get_record(&self.db, namespace, key)
            }
            fn get_records(
                &self,
                namespace: Namespace,
                keys: &[Key],
            ) -> Result<Vec<Option<StoredValue>>, StorageError> {
                get_records(&self.db, namespace, keys)
            }
            fn scan_prefix(
                &self,
                namespace: Namespace,
                request: ScanRequest<'_>,
            ) -> Result<ScanPage, StorageError> {
                scan_prefix(&self.db, namespace, request)
            }
        }
    };
}
impl_reader!(RocksDbStorage);
impl_reader!(RocksDbReader);

impl StorageWriter for RocksDbStorage {
    fn verify_transaction_capability(&self) -> Result<(), StorageError> {
        // Exercise the durable write path without touching managed projection state.
        let mut batch = WriteBatch::default();
        batch.put(PROBE_KEY, b"probe");
        batch.delete(PROBE_KEY);
        self.db
            .write_opt(batch, &durable_options())
            .map_err(map_error)
    }

    fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
        batch.validate()?;
        if batch.is_empty() {
            return Ok(());
        }
        let mut write = WriteBatch::default();
        for operation in batch.operations() {
            match operation {
                AtomicWriteOperation::Put {
                    namespace,
                    key,
                    record,
                } => write.put(encode_key(namespace, key), encode_record(record)?),
                AtomicWriteOperation::Delete { namespace, key } => {
                    write.delete(encode_key(namespace, key))
                }
            }
        }
        self.db
            .write_opt(write, &durable_options())
            .map_err(map_error)
    }
}

fn map_error(error: rocksdb::Error) -> StorageError {
    match error.kind() {
        ErrorKind::Corruption => StorageError::Corruption(error.to_string()),
        ErrorKind::InvalidArgument | ErrorKind::NotSupported => {
            StorageError::invalid_argument(error.to_string())
        }
        ErrorKind::IOError
        | ErrorKind::Busy
        | ErrorKind::TimedOut
        | ErrorKind::TryAgain
        | ErrorKind::ShutdownInProgress
        | ErrorKind::Incomplete
        | ErrorKind::Aborted => StorageError::unavailable(error),
        _ => StorageError::backend(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;

    #[test]
    fn secondary_survives_primary_flush_compaction_and_deletion() {
        let root = tempfile::tempdir().unwrap();
        let primary = root.path().join("primary");
        let writer = RocksDbStorage::open(&primary).unwrap();
        let ns = Namespace::new("records").unwrap();
        let key = Key::new(b"retained".to_vec()).unwrap();
        let value = Value::new(vec![7; 1024]).unwrap();
        writer.put(ns.clone(), &key, &value).unwrap();
        writer.db.flush().unwrap();
        let reader = RocksDbReader::open(&primary, &root.path().join("secondary")).unwrap();
        writer.delete(ns.clone(), &key).unwrap();
        writer.db.flush().unwrap();
        writer.db.compact_range::<&[u8], &[u8]>(None, None);
        assert_eq!(reader.get(ns.clone(), &key).unwrap(), Some(value));
        drop(reader);
        let reader = RocksDbReader::open(&primary, &root.path().join("secondary")).unwrap();
        assert_eq!(reader.get(ns, &key).unwrap(), None);
    }

    #[test]
    fn malformed_records_and_foreign_databases_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let primary = root.path().join("primary");
        let writer = RocksDbStorage::open(&primary).unwrap();
        let ns = Namespace::new("records").unwrap();
        let key = Key::new(b"key".to_vec()).unwrap();
        writer.db.put(encode_key(&ns, &key), b"malformed").unwrap();
        assert_eq!(
            writer.get(ns.clone(), &key).unwrap_err().kind(),
            crate::StorageErrorKind::Corruption
        );
        assert_eq!(
            writer
                .scan_prefix(ns, ScanRequest::new(&[], None, 1).unwrap())
                .unwrap_err()
                .kind(),
            crate::StorageErrorKind::Corruption
        );
        writer.db.delete(FORMAT_KEY).unwrap();
        drop(writer);
        assert_eq!(
            RocksDbStorage::open(primary).unwrap_err().kind(),
            crate::StorageErrorKind::Corruption
        );
    }
}
