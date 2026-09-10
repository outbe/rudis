//! Typed off-chain persistence boundary for Nod item and bucket bodies.

use alloy_primitives::Address;
use outbe_compressed_entities::{
    decode_stored_nod_bucket_v1, decode_stored_nod_item_v1, encode_nod_bucket_v1,
    encode_nod_item_v1, CanonicalBodyError, EntityRef, IdPage, IdPageRequest, NodBucketBodyV1,
    NodItemBodyV1, ParentBodySource, ParentBodySourceError, QueryRef, StoredBody, WwdEntityId,
};
use outbe_offchain_storage::{
    Key, Namespace, ScanEntry, ScanRequest, StorageError, StorageMetadata, StorageReaderHandle,
    StorageWriterHandle, Value, MAX_SCAN_ENTRIES,
};
use thiserror::Error;

use crate::{NodBucketState, NodItemState};

pub(crate) const NODS_NAMESPACE: &str = "nods";
pub(crate) const NOD_BUCKETS_NAMESPACE: &str = "nod_buckets";
pub(crate) const NODS_BY_OWNER_NAMESPACE: &str = "nods_by_owner";
const PRIMARY_KEY_LEN: usize = WwdEntityId::len_bytes();
const OWNER_INDEX_KEY_LEN: usize = 20 + PRIMARY_KEY_LEN;

/// Domain-level request for one ascending page of Nods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodPageRequest {
    /// Exclusive Nod ID cursor.
    pub after: Option<WwdEntityId>,
    /// Requested number of records, in `1..=MAX_SCAN_ENTRIES`.
    pub limit: usize,
}

/// One ascending, all-or-error page of Nod item bodies.
pub struct NodPage {
    /// Decoded Nod item bodies.
    pub records: Vec<NodItemState>,
    /// Exclusive cursor for the next page, when more records exist.
    pub next_after: Option<WwdEntityId>,
}

/// One decoded Nod item and optional primary storage metadata.
pub type NodItemRecordWithMetadata = (NodItemState, Option<StorageMetadata>);
/// One decoded Nod bucket and optional primary storage metadata.
pub type NodBucketRecordWithMetadata = (NodBucketState, Option<StorageMetadata>);

/// Failure at the typed Nod persistence boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NodRepositoryError {
    /// Backend-neutral storage failure.
    #[error("off-chain storage failure: {0}")]
    Storage(#[from] StorageError),
    /// StoredBody or typed payload violates the canonical profile.
    #[error("invalid canonical Nod body: {0}")]
    CanonicalBody(#[from] CanonicalBodyError),
    /// Page bounds are outside the shared storage contract.
    #[error("page limit {limit} is outside 1..={MAX_SCAN_ENTRIES}")]
    InvalidPageLimit { limit: usize },
    /// A primary item key is not one big-endian U256.
    #[error("malformed Nod primary key")]
    MalformedPrimaryKey,
    /// An owner-index key violates its fixed binary layout.
    #[error("malformed Nod owner index key")]
    MalformedIndexKey,
    /// Owner-index values must be exactly empty.
    #[error("Nod owner index value is not empty")]
    NonEmptyIndexValue,
    /// Owner-index documents must not carry primary provenance.
    #[error("Nod owner index unexpectedly carries metadata")]
    IndexMetadata,
    /// An owner index selects a missing primary body.
    #[error("Nod owner index points to missing body {nod_id}")]
    DanglingIndex { nod_id: WwdEntityId },
    /// The selecting primary key and embedded body ID disagree.
    #[error("Nod primary key/body mismatch: expected {expected}, found {actual}")]
    PrimaryKeyBodyMismatch {
        expected: WwdEntityId,
        actual: WwdEntityId,
    },
    /// An owner index selected a body owned by someone else.
    #[error("Nod owner index/body mismatch for {nod_id}")]
    IndexedOwnerMismatch { nod_id: WwdEntityId },
    /// An ID-only repository page is not strictly ascending after its cursor.
    #[error("Nod {index} ID page is not strictly ascending")]
    NonAscendingIdPage { index: &'static str },
    /// The storage adapter returned a continuation that is not the last page key.
    #[error("Nod {index} ID page has an invalid continuation")]
    InvalidPageContinuation { index: &'static str },
    /// The selecting bucket key and embedded body key disagree.
    #[error("Nod bucket ID/body mismatch: expected {expected}, found {actual}")]
    BucketIdBodyMismatch {
        expected: WwdEntityId,
        actual: WwdEntityId,
    },
    /// A projection session may mutate only identities loaded into its repository snapshot.
    #[error("{entity} projection identity {identity} was not loaded")]
    UntrackedProjectionIdentity {
        entity: &'static str,
        identity: WwdEntityId,
    },
}

/// Cloneable read authority for Nod item and bucket bodies.
#[derive(Clone)]
pub struct NodRepositoryReader {
    storage: StorageReaderHandle,
}

impl NodRepositoryReader {
    /// Creates a typed Nod reader over a backend-neutral storage handle.
    #[must_use]
    pub fn new(storage: StorageReaderHandle) -> Self {
        Self { storage }
    }

    /// Loads one Nod item and verifies its embedded identity.
    pub fn get(&self, nod_id: WwdEntityId) -> Result<Option<NodItemState>, NodRepositoryError> {
        Ok(self
            .get_with_metadata(nod_id)?
            .map(|(body, _metadata)| body))
    }

    /// Loads the exact canonical item StoredBody used by the execution parent seam.
    pub fn get_stored_item(
        &self,
        nod_id: WwdEntityId,
    ) -> Result<Option<StoredBody>, NodRepositoryError> {
        let key = item_key(nod_id)?;
        let Some(record) = self.storage.get_record(namespace(NODS_NAMESPACE)?, &key)? else {
            return Ok(None);
        };
        decode_stored_item(nod_id, record.value.as_bytes()).map(Some)
    }

    /// Loads one Nod item together with optional primary provenance.
    pub fn get_with_metadata(
        &self,
        nod_id: WwdEntityId,
    ) -> Result<Option<(NodItemState, Option<StorageMetadata>)>, NodRepositoryError> {
        let key = item_key(nod_id)?;
        let Some(record) = self.storage.get_record(namespace(NODS_NAMESPACE)?, &key)? else {
            return Ok(None);
        };
        decode_item(nod_id, record.value.as_bytes()).map(|body| Some((body, record.metadata)))
    }

    /// Batch-loads Nod items and metadata in the same order as the supplied identities.
    pub fn get_many_with_metadata(
        &self,
        nod_ids: &[WwdEntityId],
    ) -> Result<Vec<Option<NodItemRecordWithMetadata>>, NodRepositoryError> {
        let keys = nod_ids
            .iter()
            .copied()
            .map(item_key)
            .collect::<Result<Vec<_>, _>>()?;
        self.storage
            .get_records(namespace(NODS_NAMESPACE)?, &keys)?
            .into_iter()
            .zip(nod_ids.iter().copied())
            .map(|(record, nod_id)| {
                record
                    .map(|record| {
                        decode_item(nod_id, record.value.as_bytes())
                            .map(|body| (body, record.metadata))
                    })
                    .transpose()
            })
            .collect()
    }

    /// Loads one Nod bucket and verifies its embedded key.
    pub fn get_bucket(
        &self,
        bucket_id: WwdEntityId,
    ) -> Result<Option<NodBucketState>, NodRepositoryError> {
        Ok(self
            .get_bucket_with_metadata(bucket_id)?
            .map(|(body, _metadata)| body))
    }

    /// Loads the exact canonical bucket StoredBody used by the execution parent seam.
    pub fn get_stored_bucket(
        &self,
        bucket_id: WwdEntityId,
    ) -> Result<Option<StoredBody>, NodRepositoryError> {
        let key = bucket_storage_key(bucket_id)?;
        let Some(record) = self
            .storage
            .get_record(namespace(NOD_BUCKETS_NAMESPACE)?, &key)?
        else {
            return Ok(None);
        };
        decode_stored_bucket(bucket_id, record.value.as_bytes()).map(Some)
    }

    /// Loads one Nod bucket together with optional primary provenance.
    pub fn get_bucket_with_metadata(
        &self,
        bucket_id: WwdEntityId,
    ) -> Result<Option<(NodBucketState, Option<StorageMetadata>)>, NodRepositoryError> {
        let key = bucket_storage_key(bucket_id)?;
        let Some(record) = self
            .storage
            .get_record(namespace(NOD_BUCKETS_NAMESPACE)?, &key)?
        else {
            return Ok(None);
        };
        decode_bucket(bucket_id, record.value.as_bytes()).map(|body| Some((body, record.metadata)))
    }

    /// Batch-loads Nod buckets and metadata in the supplied key order.
    pub fn get_buckets_with_metadata(
        &self,
        bucket_ids: &[WwdEntityId],
    ) -> Result<Vec<Option<NodBucketRecordWithMetadata>>, NodRepositoryError> {
        let keys = bucket_ids
            .iter()
            .copied()
            .map(bucket_storage_key)
            .collect::<Result<Vec<_>, _>>()?;
        self.storage
            .get_records(namespace(NOD_BUCKETS_NAMESPACE)?, &keys)?
            .into_iter()
            .zip(bucket_ids.iter().copied())
            .map(|(record, bucket_id)| {
                record
                    .map(|record| {
                        decode_bucket(bucket_id, record.value.as_bytes())
                            .map(|body| (body, record.metadata))
                    })
                    .transpose()
            })
            .collect()
    }

    /// Loads an opaque repository-owned snapshot for item/bucket planning and in-block overlay.
    pub fn projection_session(
        &self,
        nod_ids: &[WwdEntityId],
        bucket_ids: &[WwdEntityId],
    ) -> Result<crate::projection::NodProjectionSession, NodRepositoryError> {
        let items = self.get_many_with_metadata(nod_ids)?;
        let buckets = self.get_buckets_with_metadata(bucket_ids)?;
        Ok(crate::projection::NodProjectionSession::from_records(
            nod_ids, items, bucket_ids, buckets,
        ))
    }

    /// Lists all Nod items by ascending numeric Nod ID.
    pub fn list_all(&self, request: NodPageRequest) -> Result<NodPage, NodRepositoryError> {
        validate_page_limit(request.limit)?;
        let after = request.after.map(item_key).transpose()?;
        let scan = ScanRequest::new(&[], after.as_ref(), request.limit)?;
        let page = self.storage.scan_prefix(namespace(NODS_NAMESPACE)?, scan)?;
        let has_more = page.next_after.is_some();
        let mut records = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let nod_id = parse_primary_key(entry.key.as_bytes())?;
            records.push(decode_item(nod_id, entry.value.as_bytes())?);
        }
        Ok(NodPage {
            next_after: next_cursor(has_more, &records),
            records,
        })
    }

    /// Lists only canonical Nod item identities for overlay merging.
    pub fn list_ids_all(&self, request: IdPageRequest) -> Result<IdPage, NodRepositoryError> {
        let limit = validate_id_page_request(request)?;
        let after = request.after.map(item_key).transpose()?;
        let scan = ScanRequest::new(&[], after.as_ref(), limit)?;
        let page = self.storage.scan_prefix(namespace(NODS_NAMESPACE)?, scan)?;
        id_page_from_entries(page, request.after, "all", |entry| {
            parse_primary_key(entry.key.as_bytes())
        })
    }

    /// Lists one owner's Nod items in ascending numeric ID order.
    pub fn list_by_owner(
        &self,
        owner: Address,
        request: NodPageRequest,
    ) -> Result<NodPage, NodRepositoryError> {
        validate_page_limit(request.limit)?;
        let prefix = owner.as_slice();
        let after = request
            .after
            .map(|id| owner_index_key(owner, id))
            .transpose()?;
        let scan = ScanRequest::new(prefix, after.as_ref(), request.limit)?;
        let page = self
            .storage
            .scan_prefix(namespace(NODS_BY_OWNER_NAMESPACE)?, scan)?;
        let has_more = page.next_after.is_some();
        let mut records = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let nod_id = parse_owner_index(&entry, owner)?;
            let body = self
                .get(nod_id)?
                .ok_or(NodRepositoryError::DanglingIndex { nod_id })?;
            if body.owner != owner {
                return Err(NodRepositoryError::IndexedOwnerMismatch { nod_id });
            }
            records.push(body);
        }
        Ok(NodPage {
            next_after: next_cursor(has_more, &records),
            records,
        })
    }

    /// Lists only one owner's canonical Nod item identities for overlay merging.
    pub fn list_ids_by_owner(
        &self,
        owner: Address,
        request: IdPageRequest,
    ) -> Result<IdPage, NodRepositoryError> {
        let limit = validate_id_page_request(request)?;
        let after = request
            .after
            .map(|id| owner_index_key(owner, id))
            .transpose()?;
        let scan = ScanRequest::new(owner.as_slice(), after.as_ref(), limit)?;
        let page = self
            .storage
            .scan_prefix(namespace(NODS_BY_OWNER_NAMESPACE)?, scan)?;
        id_page_from_entries(page, request.after, "owner", |entry| {
            parse_owner_index(entry, owner)
        })
    }
}

impl ParentBodySource for NodRepositoryReader {
    fn get(&self, entity: EntityRef) -> Result<Option<StoredBody>, ParentBodySourceError> {
        match entity {
            EntityRef::NodItem(nod_id) => self.get_stored_item(nod_id),
            EntityRef::NodBucket(bucket_id) => self.get_stored_bucket(bucket_id),
            EntityRef::Tribute(_) => {
                return Err(ParentBodySourceError::Corruption(
                    "Nod repository cannot serve a Tribute entity".into(),
                ));
            }
        }
        .map_err(map_parent_source_error)
    }

    fn list(
        &self,
        query: QueryRef,
        request: IdPageRequest,
    ) -> Result<IdPage, ParentBodySourceError> {
        match query {
            QueryRef::NodByOwner(owner) => self.list_ids_by_owner(owner, request),
            QueryRef::NodAll => self.list_ids_all(request),
            QueryRef::TributeByOwner(_) | QueryRef::TributeByDay(_) => {
                return Err(ParentBodySourceError::Corruption(
                    "Nod repository cannot serve a Tribute query".into(),
                ));
            }
        }
        .map_err(map_parent_source_error)
    }
}

/// Cloneable write authority for Nod item/bucket bodies and the owner index.
///
/// Callers must serialize mutations of the same Nod or bucket identity. Each resulting body/index
/// batch is atomic, but the old-body read used to plan replacement or deletion precedes that batch.
pub struct NodRepositoryWriter {
    reader: NodRepositoryReader,
    writer: StorageWriterHandle,
}

impl NodRepositoryWriter {
    /// Creates a writer. Both handles must address the same adapter instance.
    ///
    /// The read handle is required for replacement and deletion.
    #[must_use]
    pub fn new(reader: StorageReaderHandle, writer: StorageWriterHandle) -> Self {
        Self {
            reader: NodRepositoryReader::new(reader),
            writer,
        }
    }

    /// Inserts or replaces one Nod item and its owner index.
    pub fn put_nod(&self, nod: &NodItemState) -> Result<(), NodRepositoryError> {
        let mut session = self.reader.projection_session(&[nod.nod_id], &[])?;
        let batch = session.store_item(nod.nod_id, encode_item(nod)?, None)?;
        self.writer.apply_atomic(&batch)?;
        Ok(())
    }

    /// Deletes a Nod item and its owner index. Missing bodies are a success.
    pub fn delete_nod(&self, nod_id: WwdEntityId) -> Result<(), NodRepositoryError> {
        let mut session = self.reader.projection_session(&[nod_id], &[])?;
        let batch = session.delete_item(nod_id)?;
        self.writer.apply_atomic(&batch)?;
        Ok(())
    }

    /// Inserts or replaces one independently stored Nod bucket.
    pub fn put_bucket(&self, bucket: &NodBucketState) -> Result<(), NodRepositoryError> {
        let bucket_id = canonical_bucket_id(bucket);
        let mut session = self.reader.projection_session(&[], &[bucket_id])?;
        let batch = session.store_bucket(bucket_id, encode_bucket(bucket)?, None)?;
        self.writer.apply_atomic(&batch)?;
        Ok(())
    }

    /// Deletes one Nod bucket. Missing buckets are a success.
    pub fn delete_bucket(&self, bucket_id: WwdEntityId) -> Result<(), NodRepositoryError> {
        let mut session = self.reader.projection_session(&[], &[bucket_id])?;
        let batch = session.delete_bucket(bucket_id)?;
        self.writer.apply_atomic(&batch)?;
        Ok(())
    }
}

pub(crate) fn namespace(name: &'static str) -> Result<Namespace, NodRepositoryError> {
    Ok(Namespace::new(name)?)
}

pub(crate) fn encode_item(nod: &NodItemState) -> Result<Value, NodRepositoryError> {
    let payload = encode_nod_item_v1(&canonical_item(nod))?;
    Ok(Value::new(StoredBody::new_v1(payload)?.encode())?)
}

pub(crate) fn decode_item(
    nod_id: WwdEntityId,
    bytes: &[u8],
) -> Result<NodItemState, NodRepositoryError> {
    let body = from_canonical_item(decode_stored_nod_item_v1(bytes)?);
    if body.nod_id != nod_id {
        return Err(NodRepositoryError::PrimaryKeyBodyMismatch {
            expected: nod_id,
            actual: body.nod_id,
        });
    }
    Ok(body)
}

fn decode_stored_item(nod_id: WwdEntityId, bytes: &[u8]) -> Result<StoredBody, NodRepositoryError> {
    let stored = StoredBody::decode(bytes)?;
    let body = decode_stored_nod_item_v1(bytes)?;
    if body.nod_id != nod_id {
        return Err(NodRepositoryError::PrimaryKeyBodyMismatch {
            expected: nod_id,
            actual: body.nod_id,
        });
    }
    Ok(stored)
}

pub(crate) fn encode_bucket(bucket: &NodBucketState) -> Result<Value, NodRepositoryError> {
    let payload = encode_nod_bucket_v1(&canonical_bucket(bucket))?;
    Ok(Value::new(StoredBody::new_v1(payload)?.encode())?)
}

pub(crate) fn decode_bucket(
    bucket_id: WwdEntityId,
    bytes: &[u8],
) -> Result<NodBucketState, NodRepositoryError> {
    let body = from_canonical_bucket(decode_stored_nod_bucket_v1(bytes)?);
    let actual = canonical_bucket_id(&body);
    if actual != bucket_id {
        return Err(NodRepositoryError::BucketIdBodyMismatch {
            expected: bucket_id,
            actual,
        });
    }
    Ok(body)
}

fn decode_stored_bucket(
    bucket_id: WwdEntityId,
    bytes: &[u8],
) -> Result<StoredBody, NodRepositoryError> {
    let stored = StoredBody::decode(bytes)?;
    let body = decode_stored_nod_bucket_v1(bytes)?;
    let actual = body.entity_id();
    if actual != bucket_id {
        return Err(NodRepositoryError::BucketIdBodyMismatch {
            expected: bucket_id,
            actual,
        });
    }
    Ok(stored)
}

pub(crate) fn item_key(nod_id: WwdEntityId) -> Result<Key, NodRepositoryError> {
    Ok(Key::new(nod_id.as_slice().to_vec())?)
}

pub(crate) fn bucket_storage_key(bucket_id: WwdEntityId) -> Result<Key, NodRepositoryError> {
    Ok(Key::new(bucket_id.as_slice().to_vec())?)
}

pub(crate) fn owner_index_key(
    owner: Address,
    nod_id: WwdEntityId,
) -> Result<Key, NodRepositoryError> {
    let mut bytes = Vec::with_capacity(OWNER_INDEX_KEY_LEN);
    bytes.extend_from_slice(owner.as_slice());
    bytes.extend_from_slice(nod_id.as_slice());
    Ok(Key::new(bytes)?)
}

fn parse_primary_key(bytes: &[u8]) -> Result<WwdEntityId, NodRepositoryError> {
    WwdEntityId::try_from(bytes).map_err(|_| NodRepositoryError::MalformedPrimaryKey)
}

fn parse_owner_index(entry: &ScanEntry, owner: Address) -> Result<WwdEntityId, NodRepositoryError> {
    if !entry.value.as_bytes().is_empty() {
        return Err(NodRepositoryError::NonEmptyIndexValue);
    }
    if entry.metadata.is_some() {
        return Err(NodRepositoryError::IndexMetadata);
    }
    let bytes = entry.key.as_bytes();
    if bytes.len() != OWNER_INDEX_KEY_LEN || &bytes[..20] != owner.as_slice() {
        return Err(NodRepositoryError::MalformedIndexKey);
    }
    parse_primary_key(&bytes[20..]).map_err(|_| NodRepositoryError::MalformedIndexKey)
}

fn validate_page_limit(limit: usize) -> Result<(), NodRepositoryError> {
    if !(1..=MAX_SCAN_ENTRIES).contains(&limit) {
        return Err(NodRepositoryError::InvalidPageLimit { limit });
    }
    Ok(())
}

fn map_parent_source_error(error: NodRepositoryError) -> ParentBodySourceError {
    use outbe_offchain_storage::StorageErrorKind;

    let message = error.to_string();
    match &error {
        NodRepositoryError::Storage(storage)
            if storage.kind() == StorageErrorKind::RequestDeadline =>
        {
            ParentBodySourceError::RequestDeadline(message)
        }
        NodRepositoryError::Storage(storage) if storage.kind() == StorageErrorKind::Unavailable => {
            ParentBodySourceError::Unavailable(message)
        }
        _ => ParentBodySourceError::Corruption(message),
    }
}

fn validate_id_page_request(request: IdPageRequest) -> Result<usize, NodRepositoryError> {
    let limit = usize::try_from(request.limit)
        .map_err(|_| NodRepositoryError::InvalidPageLimit { limit: usize::MAX })?;
    validate_page_limit(limit)?;
    Ok(limit)
}

fn id_page_from_entries(
    page: outbe_offchain_storage::ScanPage,
    after: Option<WwdEntityId>,
    index: &'static str,
    mut parse: impl FnMut(&ScanEntry) -> Result<WwdEntityId, NodRepositoryError>,
) -> Result<IdPage, NodRepositoryError> {
    if let Some(continuation) = &page.next_after {
        if page.entries.last().map(|entry| &entry.key) != Some(continuation) {
            return Err(NodRepositoryError::InvalidPageContinuation { index });
        }
    }
    let mut ids = Vec::with_capacity(page.entries.len());
    let mut previous = after;
    for entry in &page.entries {
        let id = parse(entry)?;
        if previous.is_some_and(|previous| id <= previous) {
            return Err(NodRepositoryError::NonAscendingIdPage { index });
        }
        ids.push(id);
        previous = Some(id);
    }
    let next_after = if page.next_after.is_some() {
        Some(
            ids.last()
                .copied()
                .ok_or(NodRepositoryError::InvalidPageContinuation { index })?,
        )
    } else {
        None
    };
    Ok(IdPage { ids, next_after })
}

fn next_cursor(has_more: bool, records: &[NodItemState]) -> Option<WwdEntityId> {
    has_more
        .then(|| records.last().map(|record| record.nod_id))
        .flatten()
}

/// Converts one runtime Nod item into its normative v1 payload model.
pub fn canonical_item(body: &NodItemState) -> NodItemBodyV1 {
    NodItemBodyV1 {
        nod_id: body.nod_id,
        owner: body.owner,
        gratis_load_minor: body.gratis_load_minor,
        worldwide_day: body.worldwide_day,
        league_id: body.league_id,
        floor_price_minor: body.floor_price_minor,
        bucket_key: body.bucket_key,
        issuance_currency: body.issuance_currency,
        reference_currency: body.reference_currency,
        issued_at: body.issued_at,
    }
}

/// Converts one runtime Nod bucket into its normative v1 payload model.
pub fn canonical_bucket(body: &NodBucketState) -> NodBucketBodyV1 {
    NodBucketBodyV1 {
        bucket_key: body.bucket_key,
        worldwide_day: body.worldwide_day,
        floor_price_minor: body.floor_price_minor,
        is_qualified: body.is_qualified,
        total_nods: body.total_nods,
        entry_price_minor: body.entry_price_minor,
        reference_currency: body.reference_currency,
    }
}

/// Reconstructs the canonical bucket identity from the body.
pub fn canonical_bucket_id(body: &NodBucketState) -> WwdEntityId {
    canonical_bucket(body).entity_id()
}

/// Converts a validated normative v1 payload into the runtime item type.
pub fn from_canonical_item(body: NodItemBodyV1) -> NodItemState {
    NodItemState {
        nod_id: body.nod_id,
        owner: body.owner,
        gratis_load_minor: body.gratis_load_minor,
        worldwide_day: body.worldwide_day,
        league_id: body.league_id,
        floor_price_minor: body.floor_price_minor,
        bucket_key: body.bucket_key,
        issuance_currency: body.issuance_currency,
        reference_currency: body.reference_currency,
        issued_at: body.issued_at,
    }
}

/// Converts a validated normative v1 payload into the runtime bucket type.
pub fn from_canonical_bucket(body: NodBucketBodyV1) -> NodBucketState {
    NodBucketState {
        bucket_key: body.bucket_key,
        worldwide_day: body.worldwide_day,
        floor_price_minor: body.floor_price_minor,
        is_qualified: body.is_qualified,
        total_nods: body.total_nods,
        entry_price_minor: body.entry_price_minor,
        reference_currency: body.reference_currency,
    }
}
