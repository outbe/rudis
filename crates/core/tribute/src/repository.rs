//! Typed off-chain persistence boundary for Tribute bodies and indexes.

use alloy_primitives::{Address, B256};
use outbe_compressed_entities::{
    decode_stored_tribute_v1, encode_tribute_v1, CanonicalBodyError, EntityRef, IdPage,
    IdPageRequest, ParentBodySource, ParentBodySourceError, QueryRef, StoredBody, TributeBodyV1,
    WwdEntityId,
};
use outbe_offchain_storage::{
    Key, Namespace, ScanEntry, ScanRequest, StorageError, StorageMetadata, StorageReaderHandle,
    StorageWriterHandle, Value, MAX_SCAN_ENTRIES,
};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::TributeData;

pub(crate) const TRIBUTES_NAMESPACE: &str = "tributes";
pub(crate) const TRIBUTES_BY_OWNER_NAMESPACE: &str = "tributes_by_owner";
pub(crate) const TRIBUTES_BY_DAY_NAMESPACE: &str = "tributes_by_day";
const PRIMARY_KEY_LEN: usize = WwdEntityId::len_bytes();
const OWNER_INDEX_KEY_LEN: usize = 20 + PRIMARY_KEY_LEN;
const DAY_INDEX_KEY_LEN: usize = 4 + PRIMARY_KEY_LEN;

/// Domain-level request for one ascending page of Tributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributePageRequest {
    /// Exclusive Tribute ID cursor.
    pub after: Option<WwdEntityId>,
    /// Requested number of records, in `1..=MAX_SCAN_ENTRIES`.
    pub limit: usize,
}

/// One ascending, all-or-error page of Tribute bodies.
pub struct TributePage {
    /// Decoded Tribute bodies.
    pub records: Vec<TributeData>,
    /// Exclusive cursor for the next page, when more records exist.
    pub next_after: Option<WwdEntityId>,
}

/// One decoded Tribute body and optional primary storage metadata.
pub type TributeRecordWithMetadata = (TributeData, Option<StorageMetadata>);

/// Failure at the typed Tribute persistence boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TributeRepositoryError {
    /// Backend-neutral storage failure.
    #[error("off-chain storage failure: {0}")]
    Storage(#[from] StorageError),
    /// A Tribute body could not be encoded.
    #[error("failed to encode Tribute body")]
    CanonicalBody(#[from] CanonicalBodyError),
    /// Page bounds are outside the shared storage contract.
    #[error("page limit {limit} is outside 1..={MAX_SCAN_ENTRIES}")]
    InvalidPageLimit { limit: usize },
    /// A primary key returned by a scan is not one big-endian U256.
    #[error("malformed Tribute primary key")]
    MalformedPrimaryKey,
    /// A secondary-index key violates its fixed binary layout.
    #[error("malformed Tribute {index} index key")]
    MalformedIndexKey { index: &'static str },
    /// Secondary-index values must be exactly empty.
    #[error("Tribute {index} index value is not empty")]
    NonEmptyIndexValue { index: &'static str },
    /// Secondary-index documents must not carry primary provenance.
    #[error("Tribute {index} index unexpectedly carries metadata")]
    IndexMetadata { index: &'static str },
    /// An index selects a missing primary body.
    #[error("Tribute {index} index points to missing body {tribute_id}")]
    DanglingIndex {
        index: &'static str,
        tribute_id: WwdEntityId,
    },
    /// The selecting primary key and embedded body ID disagree.
    #[error("Tribute primary key/body mismatch: expected {expected}, found {actual}")]
    PrimaryKeyBodyMismatch {
        expected: WwdEntityId,
        actual: WwdEntityId,
    },
    /// An owner index selected a body owned by someone else.
    #[error("Tribute owner index/body mismatch for {tribute_id}")]
    IndexedOwnerMismatch { tribute_id: WwdEntityId },
    /// A day index selected a body assigned to another day.
    #[error("Tribute day index/body mismatch for {tribute_id}")]
    IndexedDayMismatch { tribute_id: WwdEntityId },
    /// A day-index cursor belongs to another immutable WWD partition.
    #[error("Tribute day cursor {cursor} does not belong to {worldwide_day}")]
    InvalidDayCursor {
        cursor: WwdEntityId,
        worldwide_day: WorldwideDay,
    },
    /// An ID-only repository page is not strictly ascending after its cursor.
    #[error("Tribute {index} ID page is not strictly ascending")]
    NonAscendingIdPage { index: &'static str },
    /// The storage adapter returned a continuation that is not the last page key.
    #[error("Tribute {index} ID page has an invalid continuation")]
    InvalidPageContinuation { index: &'static str },
    /// A projection session may mutate only identities loaded into its repository snapshot.
    #[error("Tribute projection identity {tribute_id} was not loaded")]
    UntrackedProjectionIdentity { tribute_id: WwdEntityId },
    /// A retained copy can only be made while the current canonical body exists.
    #[error("current Tribute body {tribute_id} is missing during OCOMP retention")]
    MissingCurrentBodyForRetention { tribute_id: WwdEntityId },
    /// The node-selected retained day and body identity disagree.
    #[error("OCOMP retained job {job_id} day {worldwide_day} does not match Tribute {tribute_id}")]
    RetainedDayMismatch {
        job_id: B256,
        tribute_id: WwdEntityId,
        worldwide_day: WorldwideDay,
    },
    /// Retained keys must carry one exact 32-byte entity identity.
    #[error("invalid retained Tribute entity identity")]
    RetainedIdentity(#[from] core::array::TryFromSliceError),
    /// CES1 commitment construction failed for a retained body.
    #[error("failed to derive retained Tribute commitment: {0}")]
    RetainedCommitment(String),
    /// One job/entity identity resolved to different retained bytes or commitments.
    #[error("OCOMP retained job {job_id} has conflicting bytes for Tribute {tribute_id}")]
    ConflictingRetainedBody {
        job_id: B256,
        tribute_id: WwdEntityId,
    },
    /// A retained body did not reproduce its key commitment.
    #[error("OCOMP retained job {job_id} commitment mismatch for Tribute {tribute_id}")]
    RetainedCommitmentMismatch {
        job_id: B256,
        tribute_id: WwdEntityId,
    },
    /// Retained bodies never carry mutable projection provenance.
    #[error("OCOMP retained job {job_id} body {tribute_id} unexpectedly carries metadata")]
    RetainedMetadata {
        job_id: B256,
        tribute_id: WwdEntityId,
    },
    /// The retained day index exists without its exact body.
    #[error("OCOMP retained job {job_id} has a dangling index for Tribute {tribute_id}")]
    DanglingRetainedIndex {
        job_id: B256,
        tribute_id: WwdEntityId,
    },
    /// The retained body exists without its exact day-index entry.
    #[error("OCOMP retained job {job_id} has no index for Tribute {tribute_id}")]
    MissingRetainedIndex {
        job_id: B256,
        tribute_id: WwdEntityId,
    },
    /// Retained paging must remain strictly ordered and contain one commitment per identity.
    #[error("OCOMP retained job {job_id} day {worldwide_day} page is not strictly ascending")]
    NonAscendingRetainedPage {
        job_id: B256,
        worldwide_day: WorldwideDay,
    },
    /// The retained cursor must belong to the selected job/day.
    #[error("OCOMP retained cursor does not belong to job {job_id} day {worldwide_day}")]
    InvalidRetainedCursor {
        job_id: B256,
        worldwide_day: WorldwideDay,
    },
    /// The backend returned a malformed retained page continuation.
    #[error("OCOMP retained job {job_id} day {worldwide_day} continuation is invalid")]
    InvalidRetainedContinuation {
        job_id: B256,
        worldwide_day: WorldwideDay,
    },
    /// Exact job GC requires body and index key sets to agree.
    #[error("OCOMP retained job {job_id} body/index namespaces disagree")]
    RetainedNamespaceMismatch { job_id: B256 },
}

/// Cloneable read authority for Tribute bodies and typed indexes.
#[derive(Clone)]
pub struct TributeRepositoryReader {
    storage: StorageReaderHandle,
}

impl TributeRepositoryReader {
    /// Creates a typed Tribute reader over a backend-neutral storage handle.
    #[must_use]
    pub fn new(storage: StorageReaderHandle) -> Self {
        Self { storage }
    }

    /// Loads one Tribute body and verifies its embedded identity.
    pub fn get(
        &self,
        tribute_id: WwdEntityId,
    ) -> Result<Option<TributeData>, TributeRepositoryError> {
        Ok(self
            .get_with_metadata(tribute_id)?
            .map(|(body, _metadata)| body))
    }

    /// Loads the exact canonical StoredBody used by the execution parent seam.
    pub fn get_stored_body(
        &self,
        tribute_id: WwdEntityId,
    ) -> Result<Option<StoredBody>, TributeRepositoryError> {
        let key = primary_key(tribute_id)?;
        let Some(record) = self
            .storage
            .get_record(namespace(TRIBUTES_NAMESPACE)?, &key)?
        else {
            return Ok(None);
        };
        decode_stored_body(tribute_id, record.value.as_bytes()).map(Some)
    }

    /// Loads one Tribute body together with optional primary provenance.
    pub fn get_with_metadata(
        &self,
        tribute_id: WwdEntityId,
    ) -> Result<Option<(TributeData, Option<StorageMetadata>)>, TributeRepositoryError> {
        let key = primary_key(tribute_id)?;
        let Some(record) = self
            .storage
            .get_record(namespace(TRIBUTES_NAMESPACE)?, &key)?
        else {
            return Ok(None);
        };
        decode_body(tribute_id, record.value.as_bytes()).map(|body| Some((body, record.metadata)))
    }

    /// Batch-loads bodies and metadata in the same order as the supplied identities.
    pub fn get_many_with_metadata(
        &self,
        tribute_ids: &[WwdEntityId],
    ) -> Result<Vec<Option<TributeRecordWithMetadata>>, TributeRepositoryError> {
        let keys = tribute_ids
            .iter()
            .copied()
            .map(primary_key)
            .collect::<Result<Vec<_>, _>>()?;
        self.storage
            .get_records(namespace(TRIBUTES_NAMESPACE)?, &keys)?
            .into_iter()
            .zip(tribute_ids.iter().copied())
            .map(|(record, tribute_id)| {
                record
                    .map(|record| {
                        decode_body(tribute_id, record.value.as_bytes())
                            .map(|body| (body, record.metadata))
                    })
                    .transpose()
            })
            .collect()
    }

    /// Loads an opaque repository-owned snapshot for projection planning and in-block overlay.
    pub fn projection_session(
        &self,
        tribute_ids: &[WwdEntityId],
    ) -> Result<crate::projection::TributeProjectionSession, TributeRepositoryError> {
        let keys = tribute_ids
            .iter()
            .copied()
            .map(primary_key)
            .collect::<Result<Vec<_>, _>>()?;
        let records = self
            .storage
            .get_records(namespace(TRIBUTES_NAMESPACE)?, &keys)?;
        crate::projection::TributeProjectionSession::from_records(tribute_ids, records)
    }

    /// Lists one owner's Tributes in ascending ID order.
    pub fn list_by_owner(
        &self,
        owner: Address,
        request: TributePageRequest,
    ) -> Result<TributePage, TributeRepositoryError> {
        validate_page_limit(request.limit)?;
        let prefix = owner.as_slice();
        let after = request
            .after
            .map(|id| owner_index_key(owner, id))
            .transpose()?;
        let scan = ScanRequest::new(prefix, after.as_ref(), request.limit)?;
        let page = self
            .storage
            .scan_prefix(namespace(TRIBUTES_BY_OWNER_NAMESPACE)?, scan)?;
        let has_more = page.next_after.is_some();
        let mut records = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let tribute_id = parse_owner_index(&entry, owner)?;
            let body = self
                .get(tribute_id)?
                .ok_or(TributeRepositoryError::DanglingIndex {
                    index: "owner",
                    tribute_id,
                })?;
            if body.owner != owner {
                return Err(TributeRepositoryError::IndexedOwnerMismatch { tribute_id });
            }
            records.push(body);
        }
        Ok(TributePage {
            next_after: next_cursor(has_more, &records),
            records,
        })
    }

    /// Lists only one owner's canonical Tribute identities for overlay merging.
    pub fn list_ids_by_owner(
        &self,
        owner: Address,
        request: IdPageRequest,
    ) -> Result<IdPage, TributeRepositoryError> {
        let limit = validate_id_page_request(request)?;
        let after = request
            .after
            .map(|id| owner_index_key(owner, id))
            .transpose()?;
        let scan = ScanRequest::new(owner.as_slice(), after.as_ref(), limit)?;
        let page = self
            .storage
            .scan_prefix(namespace(TRIBUTES_BY_OWNER_NAMESPACE)?, scan)?;
        id_page_from_entries(page, request.after, "owner", |entry| {
            parse_owner_index(entry, owner)
        })
    }

    /// Lists one worldwide day's Tributes in ascending ID order.
    pub fn list_by_day(
        &self,
        worldwide_day: WorldwideDay,
        request: TributePageRequest,
    ) -> Result<TributePage, TributeRepositoryError> {
        validate_page_limit(request.limit)?;
        let prefix = worldwide_day.value().to_be_bytes();
        let after = request
            .after
            .map(|id| day_index_key(worldwide_day, id))
            .transpose()?;
        let scan = ScanRequest::new(&prefix, after.as_ref(), request.limit)?;
        let page = self
            .storage
            .scan_prefix(namespace(TRIBUTES_BY_DAY_NAMESPACE)?, scan)?;
        let has_more = page.next_after.is_some();
        let mut records = Vec::with_capacity(page.entries.len());
        for entry in page.entries {
            let tribute_id = parse_day_index(&entry, worldwide_day)?;
            let body = self
                .get(tribute_id)?
                .ok_or(TributeRepositoryError::DanglingIndex {
                    index: "day",
                    tribute_id,
                })?;
            if body.worldwide_day != worldwide_day {
                return Err(TributeRepositoryError::IndexedDayMismatch { tribute_id });
            }
            records.push(body);
        }
        Ok(TributePage {
            next_after: next_cursor(has_more, &records),
            records,
        })
    }

    /// Lists only one day's canonical Tribute identities for overlay merging.
    pub fn list_ids_by_day(
        &self,
        worldwide_day: WorldwideDay,
        request: IdPageRequest,
    ) -> Result<IdPage, TributeRepositoryError> {
        let limit = validate_id_page_request(request)?;
        if let Some(cursor) = request.after {
            if cursor.worldwide_day() != worldwide_day {
                return Err(TributeRepositoryError::InvalidDayCursor {
                    cursor,
                    worldwide_day,
                });
            }
        }
        let prefix = worldwide_day.value().to_be_bytes();
        let after = request
            .after
            .map(|id| day_index_key(worldwide_day, id))
            .transpose()?;
        let scan = ScanRequest::new(&prefix, after.as_ref(), limit)?;
        let page = self
            .storage
            .scan_prefix(namespace(TRIBUTES_BY_DAY_NAMESPACE)?, scan)?;
        id_page_from_entries(page, request.after, "day", |entry| {
            parse_day_index(entry, worldwide_day)
        })
    }
}

impl ParentBodySource for TributeRepositoryReader {
    fn get(&self, entity: EntityRef) -> Result<Option<StoredBody>, ParentBodySourceError> {
        let EntityRef::Tribute(tribute_id) = entity else {
            return Err(ParentBodySourceError::Corruption(
                "Tribute repository cannot serve a non-Tribute entity".into(),
            ));
        };
        self.get_stored_body(tribute_id)
            .map_err(map_parent_source_error)
    }

    fn list(
        &self,
        query: QueryRef,
        request: IdPageRequest,
    ) -> Result<IdPage, ParentBodySourceError> {
        match query {
            QueryRef::TributeByOwner(owner) => self.list_ids_by_owner(owner, request),
            QueryRef::TributeByDay(worldwide_day) => self.list_ids_by_day(worldwide_day, request),
            QueryRef::NodByOwner(_) | QueryRef::NodAll => {
                return Err(ParentBodySourceError::Corruption(
                    "Tribute repository cannot serve a Nod query".into(),
                ));
            }
        }
        .map_err(map_parent_source_error)
    }
}

/// Cloneable write authority for Tribute bodies and derived indexes.
///
/// Callers must serialize mutations of the same Tribute identity. Each resulting body/index batch
/// is atomic, but the old-body read used to plan replacement or deletion precedes that batch.
pub struct TributeRepositoryWriter {
    reader: TributeRepositoryReader,
    writer: StorageWriterHandle,
}

impl TributeRepositoryWriter {
    /// Creates a writer. Both handles must address the same adapter instance.
    ///
    /// The read handle is required for replacement and deletion.
    #[must_use]
    pub fn new(reader: StorageReaderHandle, writer: StorageWriterHandle) -> Self {
        Self {
            reader: TributeRepositoryReader::new(reader),
            writer,
        }
    }

    /// Inserts or replaces one body and its owner/day indexes.
    pub fn put(&self, tribute: &TributeData) -> Result<(), TributeRepositoryError> {
        let mut session = self.reader.projection_session(&[tribute.tribute_id])?;
        let batch = session.store(tribute.tribute_id, encode_body(tribute)?, None)?;
        self.writer.apply_atomic(&batch)?;
        Ok(())
    }

    /// Deletes a body and its derived indexes. Missing bodies are a success.
    pub fn delete(&self, tribute_id: WwdEntityId) -> Result<(), TributeRepositoryError> {
        let mut session = self.reader.projection_session(&[tribute_id])?;
        let batch = session.delete(tribute_id)?;
        self.writer.apply_atomic(&batch)?;
        Ok(())
    }
}

pub(crate) fn namespace(name: &'static str) -> Result<Namespace, TributeRepositoryError> {
    Ok(Namespace::new(name)?)
}

pub(crate) fn encode_body(tribute: &TributeData) -> Result<Value, TributeRepositoryError> {
    let payload = encode_tribute_v1(&canonical_body(tribute))?;
    Ok(Value::new(StoredBody::new_v1(payload)?.encode())?)
}

pub(crate) fn decode_body(
    tribute_id: WwdEntityId,
    bytes: &[u8],
) -> Result<TributeData, TributeRepositoryError> {
    let body = from_canonical_body(decode_stored_tribute_v1(bytes)?);
    if body.tribute_id != tribute_id {
        return Err(TributeRepositoryError::PrimaryKeyBodyMismatch {
            expected: tribute_id,
            actual: body.tribute_id,
        });
    }
    Ok(body)
}

fn decode_stored_body(
    tribute_id: WwdEntityId,
    bytes: &[u8],
) -> Result<StoredBody, TributeRepositoryError> {
    let stored = StoredBody::decode(bytes)?;
    let body = decode_stored_tribute_v1(bytes)?;
    if body.tribute_id != tribute_id {
        return Err(TributeRepositoryError::PrimaryKeyBodyMismatch {
            expected: tribute_id,
            actual: body.tribute_id,
        });
    }
    Ok(stored)
}

pub(crate) fn primary_key(tribute_id: WwdEntityId) -> Result<Key, TributeRepositoryError> {
    Ok(Key::new(tribute_id.to_vec())?)
}

pub(crate) fn owner_index_key(
    owner: Address,
    tribute_id: WwdEntityId,
) -> Result<Key, TributeRepositoryError> {
    let mut bytes = Vec::with_capacity(OWNER_INDEX_KEY_LEN);
    bytes.extend_from_slice(owner.as_slice());
    bytes.extend_from_slice(tribute_id.as_slice());
    Ok(Key::new(bytes)?)
}

pub(crate) fn day_index_key(
    worldwide_day: WorldwideDay,
    tribute_id: WwdEntityId,
) -> Result<Key, TributeRepositoryError> {
    let mut bytes = Vec::with_capacity(DAY_INDEX_KEY_LEN);
    bytes.extend_from_slice(&worldwide_day.value().to_be_bytes());
    bytes.extend_from_slice(tribute_id.as_slice());
    Ok(Key::new(bytes)?)
}

fn parse_owner_index(
    entry: &ScanEntry,
    owner: Address,
) -> Result<WwdEntityId, TributeRepositoryError> {
    validate_empty_index(entry, "owner")?;
    let bytes = entry.key.as_bytes();
    if bytes.len() != OWNER_INDEX_KEY_LEN || &bytes[..20] != owner.as_slice() {
        return Err(TributeRepositoryError::MalformedIndexKey { index: "owner" });
    }
    parse_id_suffix(&bytes[20..], "owner")
}

fn parse_day_index(
    entry: &ScanEntry,
    day: WorldwideDay,
) -> Result<WwdEntityId, TributeRepositoryError> {
    validate_empty_index(entry, "day")?;
    let bytes = entry.key.as_bytes();
    if bytes.len() != DAY_INDEX_KEY_LEN || bytes[..4] != day.value().to_be_bytes() {
        return Err(TributeRepositoryError::MalformedIndexKey { index: "day" });
    }
    parse_id_suffix(&bytes[4..], "day")
}

fn validate_empty_index(
    entry: &ScanEntry,
    index: &'static str,
) -> Result<(), TributeRepositoryError> {
    if !entry.value.as_bytes().is_empty() {
        return Err(TributeRepositoryError::NonEmptyIndexValue { index });
    }
    if entry.metadata.is_some() {
        return Err(TributeRepositoryError::IndexMetadata { index });
    }
    Ok(())
}

fn parse_id_suffix(
    bytes: &[u8],
    index: &'static str,
) -> Result<WwdEntityId, TributeRepositoryError> {
    WwdEntityId::try_from(bytes).map_err(|_| TributeRepositoryError::MalformedIndexKey { index })
}

fn validate_page_limit(limit: usize) -> Result<(), TributeRepositoryError> {
    if !(1..=MAX_SCAN_ENTRIES).contains(&limit) {
        return Err(TributeRepositoryError::InvalidPageLimit { limit });
    }
    Ok(())
}

fn map_parent_source_error(error: TributeRepositoryError) -> ParentBodySourceError {
    use outbe_offchain_storage::StorageErrorKind;

    let message = error.to_string();
    match &error {
        TributeRepositoryError::Storage(storage)
            if storage.kind() == StorageErrorKind::RequestDeadline =>
        {
            ParentBodySourceError::RequestDeadline(message)
        }
        TributeRepositoryError::Storage(storage)
            if storage.kind() == StorageErrorKind::Unavailable =>
        {
            ParentBodySourceError::Unavailable(message)
        }
        _ => ParentBodySourceError::Corruption(message),
    }
}

fn validate_id_page_request(request: IdPageRequest) -> Result<usize, TributeRepositoryError> {
    let limit = usize::try_from(request.limit)
        .map_err(|_| TributeRepositoryError::InvalidPageLimit { limit: usize::MAX })?;
    validate_page_limit(limit)?;
    Ok(limit)
}

fn id_page_from_entries(
    page: outbe_offchain_storage::ScanPage,
    after: Option<WwdEntityId>,
    index: &'static str,
    mut parse: impl FnMut(&ScanEntry) -> Result<WwdEntityId, TributeRepositoryError>,
) -> Result<IdPage, TributeRepositoryError> {
    if let Some(continuation) = &page.next_after {
        if page.entries.last().map(|entry| &entry.key) != Some(continuation) {
            return Err(TributeRepositoryError::InvalidPageContinuation { index });
        }
    }
    let mut ids = Vec::with_capacity(page.entries.len());
    let mut previous = after;
    for entry in &page.entries {
        let id = parse(entry)?;
        if previous.is_some_and(|previous| id <= previous) {
            return Err(TributeRepositoryError::NonAscendingIdPage { index });
        }
        ids.push(id);
        previous = Some(id);
    }
    let next_after = if page.next_after.is_some() {
        Some(
            ids.last()
                .copied()
                .ok_or(TributeRepositoryError::InvalidPageContinuation { index })?,
        )
    } else {
        None
    };
    Ok(IdPage { ids, next_after })
}

fn next_cursor(has_more: bool, records: &[TributeData]) -> Option<WwdEntityId> {
    has_more
        .then(|| records.last().map(|record| record.tribute_id))
        .flatten()
}

/// Converts the runtime body into its normative v1 payload model.
pub fn canonical_body(body: &TributeData) -> TributeBodyV1 {
    TributeBodyV1 {
        tribute_id: body.tribute_id,
        owner: body.owner,
        worldwide_day: body.worldwide_day,
        issuance_amount_minor: body.issuance_amount_minor,
        issuance_currency: body.issuance_currency,
        nominal_amount_minor: body.nominal_amount_minor,
        reference_currency: body.reference_currency,
        tribute_price_minor: body.tribute_price_minor,
        exclude_from_intex_issuance: body.exclude_from_intex_issuance,
    }
}

/// Converts a validated normative v1 payload into the runtime body type.
pub fn from_canonical_body(body: TributeBodyV1) -> TributeData {
    TributeData {
        tribute_id: body.tribute_id,
        owner: body.owner,
        worldwide_day: body.worldwide_day,
        issuance_amount_minor: body.issuance_amount_minor,
        issuance_currency: body.issuance_currency,
        nominal_amount_minor: body.nominal_amount_minor,
        reference_currency: body.reference_currency,
        tribute_price_minor: body.tribute_price_minor,
        exclude_from_intex_issuance: body.exclude_from_intex_issuance,
    }
}
