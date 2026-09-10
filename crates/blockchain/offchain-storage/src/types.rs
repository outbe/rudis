use std::{collections::BTreeMap, error::Error as StdError, fmt};

use thiserror::Error;

/// Provisional maximum UTF-8 byte length of a namespace.
pub const MAX_NAMESPACE_BYTES: usize = 63;
/// Provisional maximum byte length of a key.
pub const MAX_KEY_BYTES: usize = 1_024;
/// Provisional maximum byte length of a value.
pub const MAX_VALUE_BYTES: usize = 8 * 1024 * 1024;
/// Provisional maximum requested entries in one scan page.
pub const MAX_SCAN_ENTRIES: usize = 1_024;
/// Provisional maximum sum of value bytes in one scan page.
pub const MAX_SCAN_PAGE_VALUE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum number of metadata entries attached to one stored value.
pub const MAX_METADATA_ENTRIES: usize = 32;
/// Maximum byte length of one metadata key.
pub const MAX_METADATA_KEY_BYTES: usize = 63;
/// Maximum byte length of one metadata value.
pub const MAX_METADATA_VALUE_BYTES: usize = 1_024;
/// Maximum number of ordered operations in one atomic batch.
pub const MAX_ATOMIC_BATCH_OPERATIONS: usize = 16_384;
/// Maximum combined value and metadata bytes in one atomic batch.
pub const MAX_ATOMIC_BATCH_BYTES: usize = 64 * 1024 * 1024;

/// A validated collection/keyspace identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Namespace(Box<str>);

impl Namespace {
    /// Validates a code-defined namespace.
    pub fn new(value: impl Into<Box<str>>) -> Result<Self, StorageError> {
        let value = value.into();
        validate_namespace(&value)?;
        Ok(Self(value))
    }

    /// Returns the exact backend namespace name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for Namespace {
    type Error = StorageError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A validated, non-empty opaque storage key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Key(Vec<u8>);

impl Key {
    /// Validates an opaque key.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StorageError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(StorageError::invalid_argument("key must not be empty"));
        }
        if bytes.len() > MAX_KEY_BYTES {
            return Err(StorageError::invalid_argument(format!(
                "key exceeds {MAX_KEY_BYTES} bytes"
            )));
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = StorageError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const N: usize> TryFrom<[u8; N]> for Key {
    type Error = StorageError;

    fn try_from(value: [u8; N]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A validated opaque storage value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Value(Vec<u8>);

impl Value {
    /// Validates an opaque value. Empty values are valid.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StorageError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_VALUE_BYTES {
            return Err(StorageError::invalid_argument(format!(
                "value exceeds {MAX_VALUE_BYTES} bytes"
            )));
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque value bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for Value {
    type Error = StorageError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const N: usize> TryFrom<[u8; N]> for Value {
    type Error = StorageError;

    fn try_from(value: [u8; N]) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Validated backend-neutral metadata attached to one primary value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageMetadata(BTreeMap<String, String>);

impl StorageMetadata {
    /// Validates metadata keys and values.
    pub fn new(entries: BTreeMap<String, String>) -> Result<Self, StorageError> {
        if entries.is_empty() {
            return Err(StorageError::invalid_argument(
                "metadata must contain at least one entry",
            ));
        }
        if entries.len() > MAX_METADATA_ENTRIES {
            return Err(StorageError::invalid_argument(format!(
                "metadata exceeds {MAX_METADATA_ENTRIES} entries"
            )));
        }
        for (key, value) in &entries {
            validate_metadata_key(key)?;
            validate_metadata_value(value)?;
        }
        Ok(Self(entries))
    }

    /// Returns one metadata value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Iterates over metadata in canonical key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    /// Returns the number of metadata entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the metadata is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum()
    }
}

/// One stored value together with optional backend-neutral metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredValue {
    /// Opaque stored bytes.
    pub value: Value,
    /// Optional provenance or other validated metadata.
    pub metadata: Option<StorageMetadata>,
}

impl StoredValue {
    /// Creates a value with no metadata.
    #[must_use]
    pub const fn plain(value: Value) -> Self {
        Self {
            value,
            metadata: None,
        }
    }

    /// Creates a value with metadata.
    #[must_use]
    pub const fn with_metadata(value: Value, metadata: StorageMetadata) -> Self {
        Self {
            value,
            metadata: Some(metadata),
        }
    }
}

/// One ordered mutation inside an atomic write batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicWriteOperation {
    /// Insert or completely replace one record.
    Put {
        /// Target namespace.
        namespace: Namespace,
        /// Target key.
        key: Key,
        /// Complete replacement record.
        record: StoredValue,
    },
    /// Delete one record. Deleting an absent key succeeds.
    Delete {
        /// Target namespace.
        namespace: Namespace,
        /// Target key.
        key: Key,
    },
}

impl AtomicWriteOperation {
    /// Builds a metadata-free replacement.
    #[must_use]
    pub const fn put(namespace: Namespace, key: Key, value: Value) -> Self {
        Self::Put {
            namespace,
            key,
            record: StoredValue::plain(value),
        }
    }

    /// Builds a replacement carrying metadata.
    #[must_use]
    pub const fn put_record(namespace: Namespace, key: Key, record: StoredValue) -> Self {
        Self::Put {
            namespace,
            key,
            record,
        }
    }

    /// Builds an idempotent deletion.
    #[must_use]
    pub const fn delete(namespace: Namespace, key: Key) -> Self {
        Self::Delete { namespace, key }
    }
}

/// Ordered, all-or-nothing backend-neutral mutations.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AtomicWriteBatch {
    operations: Vec<AtomicWriteOperation>,
}

impl AtomicWriteBatch {
    /// Creates an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Creates a batch from already validated mutations.
    #[must_use]
    pub const fn from_operations(operations: Vec<AtomicWriteOperation>) -> Self {
        Self { operations }
    }

    /// Appends one mutation, preserving caller order.
    pub fn push(&mut self, operation: AtomicWriteOperation) {
        self.operations.push(operation);
    }

    /// Appends another ordered mutation sequence.
    pub fn extend(&mut self, operations: impl IntoIterator<Item = AtomicWriteOperation>) {
        self.operations.extend(operations);
    }

    /// Returns mutations in their application order.
    #[must_use]
    pub fn operations(&self) -> &[AtomicWriteOperation] {
        &self.operations
    }

    /// Returns whether the batch has no mutations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Validates operation-count and aggregate encoded-size bounds before writing.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.operations.len() > MAX_ATOMIC_BATCH_OPERATIONS {
            return Err(StorageError::invalid_argument(format!(
                "atomic batch exceeds {MAX_ATOMIC_BATCH_OPERATIONS} operations"
            )));
        }
        let mut bytes = 0usize;
        for operation in &self.operations {
            if let AtomicWriteOperation::Put { record, .. } = operation {
                let record_bytes = record.value.as_bytes().len()
                    + record
                        .metadata
                        .as_ref()
                        .map_or(0, StorageMetadata::encoded_len);
                if record_bytes > MAX_SCAN_PAGE_VALUE_BYTES {
                    return Err(StorageError::invalid_argument(format!(
                        "stored record exceeds {MAX_SCAN_PAGE_VALUE_BYTES} value and metadata bytes"
                    )));
                }
                bytes = bytes
                    .checked_add(record.value.as_bytes().len())
                    .and_then(|total| {
                        record.metadata.as_ref().map_or(Some(total), |metadata| {
                            total.checked_add(metadata.encoded_len())
                        })
                    })
                    .ok_or_else(|| StorageError::invalid_argument("atomic batch size overflow"))?;
                if bytes > MAX_ATOMIC_BATCH_BYTES {
                    return Err(StorageError::invalid_argument(format!(
                        "atomic batch exceeds {MAX_ATOMIC_BATCH_BYTES} value and metadata bytes"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// One ordered prefix-scan request.
#[derive(Clone, Copy, Debug)]
pub struct ScanRequest<'a> {
    prefix: &'a [u8],
    after: Option<&'a Key>,
    limit: usize,
}

impl<'a> ScanRequest<'a> {
    /// Validates a bounded scan request.
    pub fn new(
        prefix: &'a [u8],
        after: Option<&'a Key>,
        limit: usize,
    ) -> Result<Self, StorageError> {
        let request = Self {
            prefix,
            after,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(self) -> Result<(), StorageError> {
        if self.prefix.len() > MAX_KEY_BYTES {
            return Err(StorageError::invalid_argument(format!(
                "scan prefix exceeds {MAX_KEY_BYTES} bytes"
            )));
        }
        if self.limit == 0 || self.limit > MAX_SCAN_ENTRIES {
            return Err(StorageError::invalid_argument(format!(
                "scan limit must be between 1 and {MAX_SCAN_ENTRIES}"
            )));
        }
        if let Some(after) = self.after {
            if !after.as_bytes().starts_with(self.prefix) {
                return Err(StorageError::invalid_argument(
                    "scan cursor does not match the requested prefix",
                ));
            }
        }
        Ok(())
    }

    pub fn prefix(self) -> &'a [u8] {
        self.prefix
    }

    pub fn after(self) -> Option<&'a Key> {
        self.after
    }

    pub const fn limit(self) -> usize {
        self.limit
    }
}

/// One key/value record returned by a scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanEntry {
    /// The record key.
    pub key: Key,
    /// The record value.
    pub value: Value,
    /// Optional metadata stored with the value.
    pub metadata: Option<StorageMetadata>,
}

/// A complete bounded scan page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanPage {
    /// Ordered records in this page.
    pub entries: Vec<ScanEntry>,
    /// Exclusive cursor to pass to the next request, if more records exist.
    pub next_after: Option<Key>,
}

/// Stable backend-neutral error classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageErrorKind {
    /// A namespace, key, prefix, cursor, or limit is invalid.
    InvalidArgument,
    /// The backend cannot currently serve the operation.
    Unavailable,
    /// Stored data violates an adapter representation or invariant.
    Corruption,
    /// Another backend failure.
    Backend,
    /// The caller's local execution budget expired before the read completed.
    RequestDeadline,
    /// The caller no longer owns the storage writer lease.
    WriterLeaseLost,
}

/// Backend-neutral storage failure.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A namespace, key, prefix, cursor, or limit is invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The backend cannot currently serve the operation.
    #[error("storage backend unavailable")]
    Unavailable {
        /// Backend diagnostic retained without exposing backend result types.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Stored data violates an adapter representation or invariant.
    #[error("storage corruption: {0}")]
    Corruption(String),
    /// Another backend failure.
    #[error("storage backend failure")]
    Backend {
        /// Backend diagnostic retained without exposing backend result types.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// The caller's local execution budget expired. This is not a backend outage.
    #[error("execution read request deadline exceeded")]
    RequestDeadline,
    /// Another writer acquired the sole-writer lease.
    #[error("storage writer lease lost")]
    WriterLeaseLost,
}

impl StorageError {
    /// Returns the stable class of this error.
    #[must_use]
    pub const fn kind(&self) -> StorageErrorKind {
        match self {
            Self::InvalidArgument(_) => StorageErrorKind::InvalidArgument,
            Self::Unavailable { .. } => StorageErrorKind::Unavailable,
            Self::Corruption(_) => StorageErrorKind::Corruption,
            Self::Backend { .. } => StorageErrorKind::Backend,
            Self::RequestDeadline => StorageErrorKind::RequestDeadline,
            Self::WriterLeaseLost => StorageErrorKind::WriterLeaseLost,
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub(crate) fn unavailable(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Unavailable {
            source: Box::new(source),
        }
    }

    pub(crate) fn backend(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Backend {
            source: Box::new(source),
        }
    }
}

fn validate_namespace(value: &str) -> Result<(), StorageError> {
    if value.is_empty() {
        return Err(StorageError::invalid_argument(
            "namespace must not be empty",
        ));
    }
    if value.len() > MAX_NAMESPACE_BYTES {
        return Err(StorageError::invalid_argument(format!(
            "namespace exceeds {MAX_NAMESPACE_BYTES} bytes"
        )));
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(StorageError::invalid_argument(
            "namespace must not be empty",
        ));
    };
    if !first.is_ascii_lowercase() {
        return Err(StorageError::invalid_argument(
            "namespace must start with an ASCII lowercase letter",
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
        return Err(StorageError::invalid_argument(
            "namespace may contain only ASCII lowercase letters, digits, and underscores",
        ));
    }
    if value.starts_with("system.") {
        return Err(StorageError::invalid_argument("reserved MongoDB namespace"));
    }
    Ok(())
}

fn validate_metadata_key(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > MAX_METADATA_KEY_BYTES {
        return Err(StorageError::invalid_argument(format!(
            "metadata key length must be between 1 and {MAX_METADATA_KEY_BYTES} bytes"
        )));
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(StorageError::invalid_argument(
            "metadata key must not be empty",
        ));
    };
    if !first.is_ascii_lowercase()
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(StorageError::invalid_argument(
            "metadata keys must be lowercase ASCII identifiers",
        ));
    }
    Ok(())
}

fn validate_metadata_value(value: &str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > MAX_METADATA_VALUE_BYTES {
        return Err(StorageError::invalid_argument(format!(
            "metadata value length must be between 1 and {MAX_METADATA_VALUE_BYTES} bytes"
        )));
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(StorageError::invalid_argument(
            "metadata values must contain printable non-whitespace ASCII",
        ));
    }
    Ok(())
}
