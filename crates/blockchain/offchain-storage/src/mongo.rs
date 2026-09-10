use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

use mongodb::{
    bson::{doc, oid::ObjectId, spec::BinarySubtype, Binary, Bson, DateTime, Document},
    error::{Error as MongoError, ErrorKind as MongoErrorKind, WriteFailure},
    options::{
        Acknowledgment, ClientOptions, Collation, DatabaseOptions, ReadConcern, ReadPreference,
        SelectionCriteria, WriteConcern,
    },
    sync::{Client, Collection, Database},
};

use crate::{
    AtomicWriteBatch, AtomicWriteOperation, Key, Namespace, ScanEntry, ScanPage, ScanRequest,
    StorageError, StorageErrorKind, StorageMetadata, StorageReader, StorageWriter, StoredValue,
    Value, MAX_SCAN_PAGE_VALUE_BYTES,
};

const EXECUTION_READ_TIMEOUT: Duration = Duration::from_secs(1);
const WRITER_LEASE_DURATION: Duration = Duration::from_secs(5);
const WRITER_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(2);
const WRITER_LEASE_COLLECTION: &str = "projection_writer_lease";
const WRITER_LEASE_ID: &str = "active_projection_writer";

const WRITE_CONCERN_FAILED_CODE: i32 = 64;
const READ_CONCERN_MAJORITY_NOT_AVAILABLE_CODE: i32 = 134;
const MAX_TIME_MS_EXPIRED_CODE: i32 = 50;
const RETRYABLE_READ_CODES: &[i32] = &[
    6,
    7,
    89,
    91,
    189,
    262,
    9001,
    10_107,
    11_600,
    11_602,
    13_435,
    13_436,
    READ_CONCERN_MAJORITY_NOT_AVAILABLE_CODE,
];

/// Connection settings for the persistent adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct MongoStorageConfig {
    /// MongoDB connection string.
    ///
    /// Read/write consistency options may be omitted or set to the required
    /// primary/majority contract. Conflicting URI options are rejected.
    pub uri: String,
    /// Database containing the namespace collections.
    pub database: String,
}

impl fmt::Debug for MongoStorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MongoStorageConfig")
            .field("uri", &"<redacted>")
            .field("database", &self.database)
            .finish()
    }
}

/// Persistent MongoDB storage adapter.
pub struct MongoStorage {
    client: Client,
    database: Database,
    writer_lease: parking_lot::Mutex<Option<WriterLeaseBinding>>,
}

#[derive(Clone)]
struct WriterLeaseBinding {
    owner: String,
    lost: Arc<AtomicBool>,
}

/// Process-lifetime ownership of the sole projection writer for one database.
pub struct MongoWriterLease {
    storage: Arc<MongoStorage>,
    owner: String,
    lost: Arc<AtomicBool>,
    stop: Option<mpsc::Sender<()>>,
    renewer: Option<JoinHandle<()>>,
}

impl fmt::Debug for MongoStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MongoStorage")
            .field("database", &self.database.name())
            .finish_non_exhaustive()
    }
}

impl MongoStorage {
    /// Connects to the configured database.
    pub fn connect(config: MongoStorageConfig) -> Result<Self, StorageError> {
        let mut options = ClientOptions::parse(&config.uri)
            .run()
            .map_err(map_configuration_error)?;
        cap_execution_timeouts(&mut options);
        let client = Client::with_options(options).map_err(map_configuration_error)?;
        if !matches!(
            client.selection_criteria(),
            None | Some(SelectionCriteria::ReadPreference(ReadPreference::Primary))
        ) {
            return Err(StorageError::invalid_argument(
                "MongoDB execution storage requires primary read preference",
            ));
        }
        if client
            .read_concern()
            .is_some_and(|concern| concern != &ReadConcern::majority())
        {
            return Err(StorageError::invalid_argument(
                "MongoDB execution storage requires majority read concern",
            ));
        }
        if client
            .write_concern()
            .is_some_and(|concern| !matches!(concern.w.as_ref(), Some(Acknowledgment::Majority)))
        {
            return Err(StorageError::invalid_argument(
                "MongoDB execution storage requires majority write concern",
            ));
        }
        let database = client.database_with_options(&config.database, execution_database_options());
        Ok(Self {
            client,
            database,
            writer_lease: parking_lot::Mutex::new(None),
        })
    }

    fn collection(&self, namespace: &Namespace) -> Collection<Document> {
        self.database.collection(namespace.as_str())
    }

    /// Verifies that the server exposes sessions and a transaction-capable topology.
    pub fn verify_transaction_support(&self) -> Result<(), StorageError> {
        self.client
            .start_session()
            .run()
            .map_err(map_operation_error)?;
        let hello = self
            .client
            .database("admin")
            .run_command(doc! { "hello": 1 })
            .run()
            .map_err(map_operation_error)?;
        if !transaction_topology_supported(&hello) {
            return Err(StorageError::invalid_argument(
                "MongoDB projector requires a replica set or sharded transaction-capable topology",
            ));
        }
        Ok(())
    }

    /// Proves recovery with a server-acknowledged operation inside a transaction.
    ///
    /// The projection state collection is guaranteed to exist after projector
    /// startup. The impossible filter keeps this probe side-effect free while
    /// still forcing the driver to start and commit a real transaction.
    pub fn verify_acknowledged_transaction(&self) -> Result<(), StorageError> {
        let mut session = self
            .client
            .start_session()
            .run()
            .map_err(map_operation_error)?;
        session
            .start_transaction()
            .selection_criteria(primary_selection())
            .read_concern(ReadConcern::majority())
            .write_concern(majority_write_concern())
            .max_commit_time(EXECUTION_READ_TIMEOUT)
            .and_run(|session| {
                self.database
                    .collection::<Document>("projection_state")
                    .update_one(
                        doc! { "_id": { "$exists": false } },
                        doc! { "$set": { "_outbe_transaction_probe": true } },
                    )
                    .upsert(false)
                    .session(&mut *session)
                    .run()?;
                Ok(())
            })
            .map_err(map_operation_error)
    }

    /// Atomically acquires the database's single active projection-writer lease.
    pub fn acquire_writer_lease(self: &Arc<Self>) -> Result<MongoWriterLease, StorageError> {
        let mut binding = self.writer_lease.lock();
        if binding.is_some() {
            return Err(StorageError::invalid_argument(
                "this MongoDB adapter already owns a projection writer lease",
            ));
        }

        let owner = ObjectId::new().to_hex();
        acquire_writer_lease(&self.database, &owner)?;
        let lost = Arc::new(AtomicBool::new(false));
        *binding = Some(WriterLeaseBinding {
            owner: owner.clone(),
            lost: lost.clone(),
        });
        drop(binding);

        let (stop_tx, stop_rx) = mpsc::channel();
        let database = self.database.clone();
        let renew_owner = owner.clone();
        let renew_lost = lost.clone();
        let renewer = match std::thread::Builder::new()
            .name("offchain-writer-lease".to_owned())
            .spawn(move || loop {
                match stop_rx.recv_timeout(WRITER_LEASE_RENEW_INTERVAL) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                match renew_writer_lease(&database, &renew_owner) {
                    Ok(true) => {}
                    Ok(false) => {
                        renew_lost.store(true, Ordering::Release);
                        break;
                    }
                    Err(error) if error.kind() == StorageErrorKind::Unavailable => {}
                    Err(_) => {
                        renew_lost.store(true, Ordering::Release);
                        break;
                    }
                }
            }) {
            Ok(renewer) => renewer,
            Err(error) => {
                self.writer_lease.lock().take();
                release_writer_lease_detached(self.database.clone(), owner);
                return Err(StorageError::unavailable(error));
            }
        };

        Ok(MongoWriterLease {
            storage: self.clone(),
            owner,
            lost,
            stop: Some(stop_tx),
            renewer: Some(renewer),
        })
    }
}

impl Drop for MongoWriterLease {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        // Detach both Mongo operations: a stalled network syscall in the
        // driver must not delay whole-node shutdown. Owner-qualified cleanup
        // is safe to race with an already in-flight, non-upserting renewal.
        drop(self.renewer.take());
        let mut binding = self.storage.writer_lease.lock();
        if binding
            .as_ref()
            .is_some_and(|lease| lease.owner == self.owner)
        {
            binding.take();
        }
        drop(binding);
        release_writer_lease_detached(self.storage.database.clone(), self.owner.clone());
    }
}

impl MongoWriterLease {
    /// Returns false after another writer has replaced this expired lease.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.lost.load(Ordering::Acquire)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("MongoDB projection writer lease was lost")]
struct WriterLeaseLost;

#[derive(Debug, thiserror::Error)]
#[error("MongoDB projection database already has an active writer")]
struct WriterLeaseBusy;

fn writer_lease_duration_millis() -> i64 {
    i64::try_from(WRITER_LEASE_DURATION.as_millis()).unwrap_or(i64::MAX)
}

fn writer_lease_update(owner: &str) -> Vec<Document> {
    vec![doc! {
        "$set": {
            "owner": owner,
            "lease_until": {
                "$dateAdd": {
                    "startDate": "$$NOW",
                    "unit": "millisecond",
                    "amount": writer_lease_duration_millis(),
                }
            }
        }
    }]
}

fn writer_lease_collection(database: &Database) -> Collection<Document> {
    database.collection(WRITER_LEASE_COLLECTION)
}

fn acquire_writer_lease(database: &Database, owner: &str) -> Result<(), StorageError> {
    let collection = writer_lease_collection(database);
    match collection
        .insert_one(doc! {
            "_id": WRITER_LEASE_ID,
            "owner": "",
            "lease_until": DateTime::from_millis(0),
        })
        .run()
    {
        Ok(_) => {}
        Err(error) if is_duplicate_key_error(&error) => {}
        Err(error) => return Err(map_operation_error(error)),
    }
    let result = collection
        .update_one(
            doc! {
                "_id": WRITER_LEASE_ID,
                "$or": [
                    { "owner": owner },
                    { "$expr": { "$lte": ["$lease_until", "$$NOW"] } },
                ],
            },
            writer_lease_update(owner),
        )
        .run();
    match result {
        Ok(result) if result.matched_count == 1 || result.upserted_id.is_some() => Ok(()),
        Ok(_) => Err(StorageError::unavailable(WriterLeaseBusy)),
        Err(error) if is_duplicate_key_error(&error) => {
            Err(StorageError::unavailable(WriterLeaseBusy))
        }
        Err(error) => Err(map_operation_error(error)),
    }
}

fn renew_writer_lease(database: &Database, owner: &str) -> Result<bool, StorageError> {
    writer_lease_collection(database)
        .update_one(
            doc! { "_id": WRITER_LEASE_ID, "owner": owner },
            writer_lease_update(owner),
        )
        .run()
        .map(|result| result.matched_count == 1)
        .map_err(map_operation_error)
}

fn release_writer_lease(database: &Database, owner: &str) {
    let _ = writer_lease_collection(database)
        .delete_one(doc! { "_id": WRITER_LEASE_ID, "owner": owner })
        .run();
}

fn release_writer_lease_detached(database: Database, owner: String) {
    let _ = std::thread::Builder::new()
        .name("offchain-writer-release".to_owned())
        .spawn(move || release_writer_lease(&database, &owner));
}

fn is_duplicate_key_error(error: &MongoError) -> bool {
    match error.kind.as_ref() {
        MongoErrorKind::Command(command) => command.code == 11_000,
        MongoErrorKind::Write(WriteFailure::WriteError(write)) => write.code == 11_000,
        _ => false,
    }
}

fn cap_execution_timeouts(options: &mut ClientOptions) {
    options.server_selection_timeout = Some(
        options
            .server_selection_timeout
            .unwrap_or(EXECUTION_READ_TIMEOUT)
            .min(EXECUTION_READ_TIMEOUT),
    );
    options.connect_timeout = Some(
        options
            .connect_timeout
            .unwrap_or(EXECUTION_READ_TIMEOUT)
            .min(EXECUTION_READ_TIMEOUT),
    );
}

fn transaction_topology_supported(hello: &Document) -> bool {
    let has_sessions = hello.contains_key("logicalSessionTimeoutMinutes");
    let replica_set = hello.get_str("setName").is_ok();
    let sharded = hello
        .get_str("msg")
        .is_ok_and(|message| message == "isdbgrid");
    has_sessions && (replica_set || sharded)
}

impl StorageReader for MongoStorage {
    fn get_record(
        &self,
        namespace: Namespace,
        key: &Key,
    ) -> Result<Option<StoredValue>, StorageError> {
        let encoded_key = hex::encode(key.as_bytes());
        self.collection(&namespace)
            .find_one(doc! { "_id": &encoded_key })
            .collation(simple_binary_collation())
            .max_time(EXECUTION_READ_TIMEOUT)
            .run()
            .map_err(map_operation_error)?
            .map(|document| {
                decode_document(document, Some(key)).map(|entry| StoredValue {
                    value: entry.value,
                    metadata: entry.metadata,
                })
            })
            .transpose()
    }

    fn get_records(
        &self,
        namespace: Namespace,
        keys: &[Key],
    ) -> Result<Vec<Option<StoredValue>>, StorageError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let encoded_keys: Vec<_> = keys
            .iter()
            .map(|key| Bson::String(hex::encode(key.as_bytes())))
            .collect();
        let cursor = self
            .collection(&namespace)
            .find(doc! { "_id": { "$in": encoded_keys } })
            .collation(simple_binary_collation())
            .max_time(EXECUTION_READ_TIMEOUT)
            .run()
            .map_err(map_operation_error)?;
        let mut records = std::collections::HashMap::new();
        for result in cursor {
            let entry = decode_document(result.map_err(map_operation_error)?, None)?;
            let record = StoredValue {
                value: entry.value,
                metadata: entry.metadata,
            };
            if records.insert(entry.key, record).is_some() {
                return Err(StorageError::Corruption(
                    "MongoDB returned a duplicate storage key".to_owned(),
                ));
            }
        }
        Ok(keys.iter().map(|key| records.get(key).cloned()).collect())
    }

    fn scan_prefix(
        &self,
        namespace: Namespace,
        request: ScanRequest<'_>,
    ) -> Result<ScanPage, StorageError> {
        request.validate()?;
        let filter = prefix_filter(request);
        let internal_limit = i64::try_from(request.limit() + 1)
            .map_err(|_| StorageError::invalid_argument("scan limit does not fit i64"))?;
        let cursor = self
            .collection(&namespace)
            .find(filter)
            .sort(doc! { "_id": 1 })
            .collation(simple_binary_collation())
            .limit(internal_limit)
            .max_time(EXECUTION_READ_TIMEOUT)
            .run()
            .map_err(map_operation_error)?;

        let mut entries = Vec::new();
        let mut value_bytes = 0_usize;
        let mut has_more = false;
        for result in cursor {
            let entry = decode_document(result.map_err(map_operation_error)?, None)?;
            if !entry.key.as_bytes().starts_with(request.prefix()) {
                return Err(StorageError::Corruption(
                    "MongoDB prefix query returned an out-of-range key".to_owned(),
                ));
            }
            if entries.len() == request.limit()
                || value_bytes
                    + entry.value.as_bytes().len()
                    + entry
                        .metadata
                        .as_ref()
                        .map_or(0, |metadata| metadata.encoded_len())
                    > MAX_SCAN_PAGE_VALUE_BYTES
            {
                has_more = true;
                break;
            }
            value_bytes += entry.value.as_bytes().len()
                + entry
                    .metadata
                    .as_ref()
                    .map_or(0, |metadata| metadata.encoded_len());
            entries.push(entry);
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

impl StorageWriter for MongoStorage {
    fn verify_transaction_capability(&self) -> Result<(), StorageError> {
        MongoStorage::verify_acknowledged_transaction(self)
    }

    fn apply_atomic(&self, batch: &AtomicWriteBatch) -> Result<(), StorageError> {
        batch.validate()?;
        if batch.is_empty() {
            return Ok(());
        }
        let writer_lease = self.writer_lease.lock().clone();
        if writer_lease
            .as_ref()
            .is_some_and(|lease| lease.lost.load(Ordering::Acquire))
        {
            return Err(StorageError::WriterLeaseLost);
        }
        let operations = batch
            .operations()
            .iter()
            .map(PreparedMongoOperation::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let mut session = self
            .client
            .start_session()
            .run()
            .map_err(map_operation_error)?;
        session
            .start_transaction()
            .selection_criteria(primary_selection())
            .read_concern(ReadConcern::majority())
            .write_concern(majority_write_concern())
            .max_commit_time(EXECUTION_READ_TIMEOUT)
            .and_run(|session| {
                if let Some(lease) = &writer_lease {
                    let result = writer_lease_collection(&self.database)
                        .update_one(
                            doc! { "_id": WRITER_LEASE_ID, "owner": &lease.owner },
                            writer_lease_update(&lease.owner),
                        )
                        .session(&mut *session)
                        .run()?;
                    if result.matched_count != 1 {
                        lease.lost.store(true, Ordering::Release);
                        return Err(MongoError::custom(WriterLeaseLost));
                    }
                }
                for operation in &operations {
                    match operation {
                        PreparedMongoOperation::Put {
                            namespace,
                            encoded_key,
                            document,
                        } => {
                            self.collection(namespace)
                                .replace_one(doc! { "_id": encoded_key }, document.clone())
                                .upsert(true)
                                .collation(simple_binary_collation())
                                .session(&mut *session)
                                .run()?;
                        }
                        PreparedMongoOperation::Delete {
                            namespace,
                            encoded_key,
                        } => {
                            self.collection(namespace)
                                .delete_one(doc! { "_id": encoded_key })
                                .collation(simple_binary_collation())
                                .session(&mut *session)
                                .run()?;
                        }
                    }
                }
                Ok(())
            })
            .map_err(map_operation_error)
    }
}

fn execution_database_options() -> DatabaseOptions {
    DatabaseOptions::builder()
        .selection_criteria(primary_selection())
        .read_concern(ReadConcern::majority())
        .write_concern(majority_write_concern())
        .build()
}

fn primary_selection() -> SelectionCriteria {
    SelectionCriteria::ReadPreference(ReadPreference::Primary)
}

fn majority_write_concern() -> WriteConcern {
    WriteConcern::builder()
        .w(Acknowledgment::Majority)
        .w_timeout(EXECUTION_READ_TIMEOUT)
        .build()
}

enum PreparedMongoOperation {
    Put {
        namespace: Namespace,
        encoded_key: String,
        document: Document,
    },
    Delete {
        namespace: Namespace,
        encoded_key: String,
    },
}

impl TryFrom<&AtomicWriteOperation> for PreparedMongoOperation {
    type Error = StorageError;

    fn try_from(operation: &AtomicWriteOperation) -> Result<Self, Self::Error> {
        Ok(match operation {
            AtomicWriteOperation::Put {
                namespace,
                key,
                record,
            } => {
                let encoded_key = hex::encode(key.as_bytes());
                Self::Put {
                    namespace: namespace.clone(),
                    document: encode_document(&encoded_key, record),
                    encoded_key,
                }
            }
            AtomicWriteOperation::Delete { namespace, key } => Self::Delete {
                namespace: namespace.clone(),
                encoded_key: hex::encode(key.as_bytes()),
            },
        })
    }
}

fn encode_document(encoded_key: &str, record: &StoredValue) -> Document {
    let mut document = doc! {
        "_id": encoded_key,
        "value": Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes: record.value.as_bytes().to_vec(),
        }),
    };
    if let Some(metadata) = &record.metadata {
        let projection: Document = metadata
            .iter()
            .map(|(key, value)| (key.to_owned(), Bson::String(value.to_owned())))
            .collect();
        document.insert("_projection", projection);
    }
    document
}

fn simple_binary_collation() -> Collation {
    Collation::builder().locale("simple").build()
}

fn prefix_filter(request: ScanRequest<'_>) -> Document {
    let mut bounds = Document::new();
    if let Some(after) = request.after() {
        bounds.insert("$gt", hex::encode(after.as_bytes()));
    } else if !request.prefix().is_empty() {
        bounds.insert("$gte", hex::encode(request.prefix()));
    }
    if let Some(upper_bound) = raw_prefix_upper_bound(request.prefix()) {
        bounds.insert("$lt", hex::encode(upper_bound));
    }

    let range = if bounds.is_empty() {
        Document::new()
    } else {
        doc! { "_id": bounds }
    };

    if range.is_empty() {
        range
    } else {
        // MongoDB range comparisons are type-bracketed. Explicitly include
        // non-string identifiers so a damaged document remains visible to the
        // adapter and is classified as corruption instead of disappearing
        // from a prefix scan.
        doc! {
            "$or": [
                range,
                { "_id": { "$not": { "$type": "string" } } },
            ]
        }
    }
}

fn raw_prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper_bound = prefix.to_vec();
    let index = upper_bound.iter().rposition(|byte| *byte != u8::MAX)?;
    upper_bound[index] += 1;
    upper_bound.truncate(index + 1);
    Some(upper_bound)
}

fn decode_document(
    mut document: Document,
    expected_key: Option<&Key>,
) -> Result<ScanEntry, StorageError> {
    if !(2..=3).contains(&document.len()) {
        return Err(StorageError::Corruption(
            "MongoDB storage document must contain _id, value, and optional _projection".to_owned(),
        ));
    }
    let metadata = document
        .remove("_projection")
        .map(decode_metadata)
        .transpose()?;
    let encoded_key = document
        .remove("_id")
        .and_then(|id| match id {
            Bson::String(id) => Some(id),
            _ => None,
        })
        .ok_or_else(|| {
            StorageError::Corruption("MongoDB storage document has a non-string _id".to_owned())
        })?;
    let raw_key = hex::decode(&encoded_key).map_err(|_| {
        StorageError::Corruption("MongoDB storage document has invalid key encoding".to_owned())
    })?;
    if hex::encode(&raw_key) != encoded_key {
        return Err(StorageError::Corruption(
            "MongoDB storage document key is not canonical lowercase hex".to_owned(),
        ));
    }
    let key = Key::new(raw_key).map_err(|_| {
        StorageError::Corruption("MongoDB storage document contains an invalid key".to_owned())
    })?;
    if expected_key.is_some_and(|expected| expected != &key) {
        return Err(StorageError::Corruption(
            "MongoDB storage document key does not match its lookup key".to_owned(),
        ));
    }

    let binary = document
        .remove("value")
        .and_then(|value| match value {
            Bson::Binary(binary) => Some(binary),
            _ => None,
        })
        .ok_or_else(|| {
            StorageError::Corruption("MongoDB storage document has a non-binary value".to_owned())
        })?;
    if binary.subtype != BinarySubtype::Generic {
        return Err(StorageError::Corruption(
            "MongoDB storage document uses an unexpected binary subtype".to_owned(),
        ));
    }
    let value = Value::new(binary.bytes).map_err(|_| {
        StorageError::Corruption("MongoDB storage document contains an oversized value".to_owned())
    })?;
    if !document.is_empty() {
        return Err(StorageError::Corruption(
            "MongoDB storage document contains unexpected fields".to_owned(),
        ));
    }
    Ok(ScanEntry {
        key,
        value,
        metadata,
    })
}

fn decode_metadata(value: Bson) -> Result<StorageMetadata, StorageError> {
    let Bson::Document(document) = value else {
        return Err(StorageError::Corruption(
            "MongoDB _projection field is not a document".to_owned(),
        ));
    };
    let mut entries = std::collections::BTreeMap::new();
    for (key, value) in document {
        let Bson::String(value) = value else {
            return Err(StorageError::Corruption(
                "MongoDB _projection values must be strings".to_owned(),
            ));
        };
        entries.insert(key, value);
    }
    StorageMetadata::new(entries).map_err(|error| {
        StorageError::Corruption(format!("invalid MongoDB _projection metadata: {error}"))
    })
}

fn map_configuration_error(error: MongoError) -> StorageError {
    match error.kind.as_ref() {
        MongoErrorKind::InvalidArgument { .. } => StorageError::InvalidArgument(error.to_string()),
        _ => map_operation_error(error),
    }
}

fn map_operation_error(error: MongoError) -> StorageError {
    if error.get_custom::<WriterLeaseLost>().is_some() {
        return StorageError::WriterLeaseLost;
    }
    match error.kind.as_ref() {
        MongoErrorKind::DnsResolve { .. }
        | MongoErrorKind::Io(_)
        | MongoErrorKind::ConnectionPoolCleared { .. }
        | MongoErrorKind::ServerSelection { .. }
        | MongoErrorKind::Write(WriteFailure::WriteConcernError(_)) => {
            StorageError::unavailable(error)
        }
        MongoErrorKind::Command(command)
            if matches!(
                command.code,
                WRITE_CONCERN_FAILED_CODE | MAX_TIME_MS_EXPIRED_CODE
            ) || RETRYABLE_READ_CODES.contains(&command.code) =>
        {
            StorageError::unavailable(error)
        }
        _ => StorageError::backend(error),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mongodb::{
        bson::{doc, from_document},
        error::{CommandError, Error as MongoError, ErrorKind, WriteConcernError, WriteFailure},
        options::ClientOptions,
    };

    use super::{
        cap_execution_timeouts, map_operation_error, transaction_topology_supported,
        MongoStorageConfig, EXECUTION_READ_TIMEOUT,
    };
    use crate::StorageErrorKind;

    #[test]
    fn topology_capability_rejects_standalone_and_accepts_supported_deployments() {
        assert!(!transaction_topology_supported(&doc! {
            "isWritablePrimary": true,
            "logicalSessionTimeoutMinutes": 30,
        }));
        assert!(transaction_topology_supported(&doc! {
            "setName": "rs0",
            "logicalSessionTimeoutMinutes": 30,
        }));
        assert!(transaction_topology_supported(&doc! {
            "msg": "isdbgrid",
            "logicalSessionTimeoutMinutes": 30,
        }));
        assert!(!transaction_topology_supported(&doc! {
            "setName": "rs0",
        }));
    }

    #[test]
    fn configuration_debug_redacts_mongodb_credentials() {
        let config = MongoStorageConfig {
            uri: "mongodb://user:secret@localhost:27017".to_owned(),
            database: "projection".to_owned(),
        };

        let debug = format!("{config:?}");
        assert!(!debug.contains("user:secret"));
        assert!(debug.contains("uri: \"<redacted>\""));
        assert!(debug.contains("database: \"projection\""));
    }

    #[test]
    fn unsatisfied_majority_concerns_are_unavailable() {
        let read_concern_error: CommandError = from_document(doc! {
            "code": 134,
            "codeName": "ReadConcernMajorityNotAvailableYet",
            "errmsg": "majority read concern is temporarily unavailable",
        })
        .unwrap();
        let read_concern_error: MongoError = ErrorKind::Command(read_concern_error).into();
        assert_eq!(
            map_operation_error(read_concern_error).kind(),
            StorageErrorKind::Unavailable
        );

        let write_concern_error: WriteConcernError = from_document(doc! {
            "code": 64,
            "codeName": "WriteConcernFailed",
            "errmsg": "majority acknowledgement timed out",
        })
        .unwrap();
        let write_concern_error: MongoError =
            ErrorKind::Write(WriteFailure::WriteConcernError(write_concern_error)).into();
        assert_eq!(
            map_operation_error(write_concern_error).kind(),
            StorageErrorKind::Unavailable
        );
    }

    #[test]
    fn transient_command_failures_are_unavailable() {
        for (code, code_name) in [
            (50, "MaxTimeMSExpired"),
            (91, "ShutdownInProgress"),
            (10_107, "NotWritablePrimary"),
            (11_602, "InterruptedDueToReplStateChange"),
        ] {
            let command: CommandError = from_document(doc! {
                "code": code,
                "codeName": code_name,
                "errmsg": "temporary topology or operation failure",
            })
            .unwrap();
            let error: MongoError = ErrorKind::Command(command).into();
            assert_eq!(
                map_operation_error(error).kind(),
                StorageErrorKind::Unavailable,
                "MongoDB command code {code} must enter recovery",
            );
        }
    }

    #[test]
    fn deterministic_command_failure_remains_backend_failure() {
        let command: CommandError = from_document(doc! {
            "code": 13,
            "codeName": "Unauthorized",
            "errmsg": "not authorized",
        })
        .unwrap();
        let error: MongoError = ErrorKind::Command(command).into();
        assert_eq!(map_operation_error(error).kind(), StorageErrorKind::Backend,);
    }

    #[test]
    fn execution_connection_attempts_cannot_exceed_the_one_second_read_budget() {
        let mut options = ClientOptions::default();
        options.server_selection_timeout = Some(Duration::from_secs(30));
        options.connect_timeout = Some(Duration::from_secs(15));

        cap_execution_timeouts(&mut options);

        assert_eq!(
            options.server_selection_timeout,
            Some(EXECUTION_READ_TIMEOUT)
        );
        assert_eq!(options.connect_timeout, Some(EXECUTION_READ_TIMEOUT));
    }
}
