//! Backend lifecycle is kept outside the node and the domain repositories.

use std::sync::Arc;

use crate::{
    MongoStorage, MongoWriterLease, RocksDbReader, RocksDbStorage, StorageBackend, StorageConfig,
    StorageError, StorageReaderHandle, StorageWriterHandle,
};

/// Keeps the writer's backend-specific ownership alive through node shutdown.
pub struct StorageOwnershipGuard {
    _inner: Ownership,
}

enum Ownership {
    Mongo { _lease: MongoWriterLease },
    Rocks { _storage: Arc<RocksDbStorage> },
}

/// One writer and its read capability, referring to the same physical database.
pub struct OpenedStorage {
    pub reader: StorageReaderHandle,
    pub writer: StorageWriterHandle,
    pub ownership: StorageOwnershipGuard,
}

/// Opens capabilities for the configured storage implementation.
#[derive(Clone, Debug)]
pub struct StorageProvider {
    config: StorageConfig,
}

impl StorageProvider {
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn open_writer(&self) -> Result<OpenedStorage, StorageError> {
        match &self.config.backend {
            StorageBackend::MongoDb(config) => {
                let storage = Arc::new(MongoStorage::connect(config.clone())?);
                storage.verify_transaction_support()?;
                let lease = storage.acquire_writer_lease()?;
                Ok(OpenedStorage {
                    reader: storage.clone(),
                    writer: storage,
                    ownership: StorageOwnershipGuard {
                        _inner: Ownership::Mongo { _lease: lease },
                    },
                })
            }
            StorageBackend::RocksDb(config) => {
                let storage = Arc::new(RocksDbStorage::open(&config.path)?);
                Ok(OpenedStorage {
                    reader: storage.clone(),
                    writer: storage.clone(),
                    ownership: StorageOwnershipGuard {
                        _inner: Ownership::Rocks { _storage: storage },
                    },
                })
            }
        }
    }

    /// Each concurrently active consumer must have its own stable, directory-safe identity.
    pub fn read_source(&self, reader_id: &str) -> Result<StorageReadSource, StorageError> {
        if reader_id.is_empty()
            || reader_id.len() > 128
            || !reader_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(StorageError::invalid_argument(
                "invalid storage reader identity",
            ));
        }
        Ok(StorageReadSource {
            config: self.config.clone(),
            reader_id: reader_id.to_owned(),
        })
    }
}

/// Factory for independent export attempts. A session cannot refresh itself.
#[derive(Clone, Debug)]
pub struct StorageReadSource {
    config: StorageConfig,
    reader_id: String,
}

impl StorageReadSource {
    /// Mongo preserves its primary/majority read contract; Rocks pins the caught-up view.
    /// Domain completeness/commitment checks remain required for either backend.
    pub fn open_session(&self) -> Result<StorageReaderHandle, StorageError> {
        match &self.config.backend {
            StorageBackend::MongoDb(config) => Ok(Arc::new(MongoStorage::connect(config.clone())?)),
            StorageBackend::RocksDb(config) => Ok(Arc::new(RocksDbReader::open(
                &config.path,
                &config.secondary_path.join(&self.reader_id),
            )?)),
        }
    }
}
