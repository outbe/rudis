//! One configuration document shared by a node and its snapshot exporter.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{MongoStorageConfig, StorageError};

/// Filesystem locations for one primary and its independent read sessions.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RocksDbConfig {
    pub path: PathBuf,
    pub secondary_path: PathBuf,
}

/// Backend selection. Runtime consumers receive capabilities, not this enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageBackend {
    RocksDb(RocksDbConfig),
    MongoDb(MongoStorageConfig),
}

/// Validated storage settings with paths resolved relative to the configuration file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageConfig {
    pub start_block: u64,
    pub backend: StorageBackend,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    backend: BackendName,
    #[serde(default = "first_block")]
    start_block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rocksdb: Option<RocksDbConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mongodb: Option<MongoDocument>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum BackendName {
    Rocksdb,
    Mongodb,
}

// This representation deliberately has no Debug implementation: TOML parse errors
// and diagnostics must not echo a credential-bearing source line.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MongoDocument {
    uri: String,
    database: String,
}

const fn first_block() -> u64 {
    1
}

impl StorageConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path).map_err(|error| {
            StorageError::invalid_argument(format!(
                "cannot read storage configuration {}: {error}",
                path.display()
            ))
        })?;
        Self::from_toml(&source, path)
    }

    /// Parse using the file's location, never the working directory of its consumer.
    pub fn from_toml(source: &str, path: &Path) -> Result<Self, StorageError> {
        let document: Document = toml::from_str(source).map_err(|error: toml::de::Error| {
            StorageError::invalid_argument(format!(
                "invalid storage TOML at byte range {:?}",
                error.span()
            ))
        })?;
        if document.version != 1 {
            return Err(StorageError::invalid_argument(
                "unsupported storage configuration version",
            ));
        }
        let config_path = absolute_path(path)?;
        let base = config_path.parent().ok_or_else(|| {
            StorageError::invalid_argument("storage configuration must have a parent directory")
        })?;
        let backend = match (document.backend, document.rocksdb, document.mongodb) {
            (BackendName::Rocksdb, Some(mut config), None) => {
                if config.path.as_os_str().is_empty()
                    || config.secondary_path.as_os_str().is_empty()
                {
                    return Err(StorageError::invalid_argument(
                        "RocksDB paths must not be empty",
                    ));
                }
                config.path = normalize_path(&base.join(config.path));
                config.secondary_path = normalize_path(&base.join(config.secondary_path));
                StorageBackend::RocksDb(config)
            }
            (BackendName::Mongodb, None, Some(config)) => {
                StorageBackend::MongoDb(MongoStorageConfig {
                    uri: config.uri,
                    database: config.database,
                })
            }
            _ => {
                return Err(StorageError::invalid_argument(
                    "storage configuration requires exactly the selected backend section",
                ))
            }
        };
        let config = Self {
            start_block: document.start_block,
            backend,
        };
        config.validate()?;
        Ok(config)
    }

    /// Serialize for launch generators and isolated test fixtures. The result contains credentials.
    pub fn to_toml(&self) -> Result<String, StorageError> {
        self.validate()?;
        let (backend, rocksdb, mongodb) = match &self.backend {
            StorageBackend::RocksDb(config) => (BackendName::Rocksdb, Some(config.clone()), None),
            StorageBackend::MongoDb(config) => (
                BackendName::Mongodb,
                None,
                Some(MongoDocument {
                    uri: config.uri.clone(),
                    database: config.database.clone(),
                }),
            ),
        };
        toml::to_string_pretty(&Document {
            version: 1,
            backend,
            start_block: self.start_block,
            rocksdb,
            mongodb,
        })
        .map_err(|_| StorageError::invalid_argument("cannot encode storage configuration"))
    }

    #[must_use]
    pub const fn backend_name(&self) -> &'static str {
        match self.backend {
            StorageBackend::RocksDb(_) => "rocksdb",
            StorageBackend::MongoDb(_) => "mongodb",
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        match &self.backend {
            StorageBackend::MongoDb(config) => {
                if config.uri.trim().is_empty() || config.database.trim().is_empty() {
                    return Err(StorageError::invalid_argument(
                        "MongoDB URI and database must not be empty",
                    ));
                }
            }
            StorageBackend::RocksDb(config) => {
                if !config.path.is_absolute() || !config.secondary_path.is_absolute() {
                    return Err(StorageError::invalid_argument(
                        "resolved RocksDB paths must be absolute",
                    ));
                }
                let primary = normalize_path(&config.path);
                let secondary = normalize_path(&config.secondary_path);
                if primary.starts_with(&secondary) || secondary.starts_with(&primary) {
                    return Err(StorageError::invalid_argument(
                        "RocksDB primary and secondary directories must not overlap",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, StorageError> {
    if path.is_absolute() {
        Ok(normalize_path(path))
    } else {
        Ok(normalize_path(
            &std::env::current_dir()
                .map_err(StorageError::backend)?
                .join(path),
        ))
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            part => result.push(part.as_os_str()),
        }
    }
    result
}
