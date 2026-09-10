//! Authenticated-input-lease retention for finalized OCOMP Tribute inputs.
//!
//! The current repository remains the execution projection. This module owns
//! the one additional PoC namespace that preserves exact canonical body bytes
//! across a partition retirement. Every retained key binds the node-derived
//! `InputLeaseId`, WWD, complete `WwdEntityId`, and CES1 body commitment.

use std::collections::BTreeSet;

use alloy_primitives::B256;
use outbe_compressed_entities::{
    body_commitment, decode_stored_tribute_v1, StoredBody, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
};
use outbe_ocomp_protocol::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1;
use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, Key, ScanEntry, ScanRequest, StorageReaderHandle,
    StorageWriterHandle, StoredValue, Value, MAX_SCAN_ENTRIES,
};
use outbe_primitives::time::WorldwideDay;

use crate::{
    repository::{namespace, primary_key, TRIBUTES_NAMESPACE},
    TributeRepositoryError,
};

/// Exact retained Tribute bodies, keyed by job/day/entity/commitment.
pub const OCOMP_RETAINED_TRIBUTES_NAMESPACE: &str = "ocomp_retained_tributes";
/// Empty-value discovery index with the same canonical key as the retained body.
pub const OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE: &str = "ocomp_retained_tributes_by_day";

const JOB_PREFIX_LEN: usize = 32;
const DAY_PREFIX_LEN: usize = JOB_PREFIX_LEN + 4;
const ID_PREFIX_LEN: usize = DAY_PREFIX_LEN + WwdEntityId::len_bytes();
const RETAINED_KEY_LEN: usize = ID_PREFIX_LEN + 32;
const RETAINED_RELEASE_PAGE_LIMIT: usize =
    OCOMP_POC_CANDIDATE_LIMITS_V1.max_tributes_per_work_shard as usize;

/// Node-derived selector for one OCOMP source partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedTributePin {
    pub input_lease_id: B256,
    pub worldwide_day: WorldwideDay,
}

/// One authenticated retained-index entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetainedTributeRef {
    pub tribute_id: WwdEntityId,
    pub body_commitment: B256,
}

/// Exclusive cursor for the retained day index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedTributeCursor {
    pub tribute_id: WwdEntityId,
    pub body_commitment: B256,
}

/// Bounded retained-index page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedTributePage {
    pub records: Vec<RetainedTributeRef>,
    pub next_after: Option<RetainedTributeCursor>,
}

/// Read and mutation-planning authority for the job-retained namespace.
#[derive(Clone)]
pub struct RetainedTributeReader {
    storage: StorageReaderHandle,
}

impl RetainedTributeReader {
    #[must_use]
    pub fn new(storage: StorageReaderHandle) -> Self {
        Self { storage }
    }

    /// Plans the immutable retained copy for one current canonical body.
    ///
    /// The returned operations are deliberately not applied here: the
    /// finalized projection combines them with the current-body/index deletes
    /// and its checkpoint in one backend transaction.
    pub fn plan_retain_current(
        &self,
        pin: RetainedTributePin,
        tribute_id: WwdEntityId,
    ) -> Result<AtomicWriteBatch, TributeRepositoryError> {
        let current_key = primary_key(tribute_id)?;
        let current = self
            .storage
            .get_record(namespace(TRIBUTES_NAMESPACE)?, &current_key)?
            .ok_or(TributeRepositoryError::MissingCurrentBodyForRetention { tribute_id })?;
        self.plan_retain_stored(pin, tribute_id, current.value)
    }

    pub(crate) fn plan_retain_stored(
        &self,
        pin: RetainedTributePin,
        tribute_id: WwdEntityId,
        stored_body: Value,
    ) -> Result<AtomicWriteBatch, TributeRepositoryError> {
        ensure_pin_day(pin, tribute_id)?;
        let commitment = commitment_for_stored_bytes(tribute_id, stored_body.as_bytes())?;
        let retained_key = retained_key(pin, tribute_id, commitment)?;
        let identity_prefix = retained_identity_prefix(pin, tribute_id);

        let existing = self.storage.scan_prefix(
            namespace(OCOMP_RETAINED_TRIBUTES_NAMESPACE)?,
            ScanRequest::new(&identity_prefix, None, 2)?,
        )?;
        if existing.next_after.is_some() || existing.entries.len() > 1 {
            return Err(TributeRepositoryError::ConflictingRetainedBody {
                job_id: pin.input_lease_id,
                tribute_id,
            });
        }

        if let Some(entry) = existing.entries.first() {
            let parsed = parse_retained_entry(entry, pin, false)?;
            if parsed.tribute_id != tribute_id
                || parsed.body_commitment != commitment
                || entry.key != retained_key
                || entry.value.as_bytes() != stored_body.as_bytes()
            {
                return Err(TributeRepositoryError::ConflictingRetainedBody {
                    job_id: pin.input_lease_id,
                    tribute_id,
                });
            }
            validate_retained_index_record(&self.storage, &retained_key, pin)?;
            return Ok(AtomicWriteBatch::new());
        }

        if self
            .storage
            .get_record(
                namespace(OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE)?,
                &retained_key,
            )?
            .is_some()
        {
            return Err(TributeRepositoryError::DanglingRetainedIndex {
                job_id: pin.input_lease_id,
                tribute_id,
            });
        }

        let mut batch = AtomicWriteBatch::new();
        batch.push(AtomicWriteOperation::put_record(
            namespace(OCOMP_RETAINED_TRIBUTES_NAMESPACE)?,
            retained_key.clone(),
            StoredValue::plain(stored_body),
        ));
        batch.push(AtomicWriteOperation::put(
            namespace(OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE)?,
            retained_key,
            Value::new(Vec::new())?,
        ));
        batch.validate()?;
        Ok(batch)
    }

    /// Resolves exact bytes from the current or job-retained location.
    ///
    /// A present value is returned only after its embedded Tribute identity and
    /// CES1 commitment match the caller's already-authenticated CE leaf.
    pub fn get_current_or_retained(
        &self,
        pin: RetainedTributePin,
        tribute_id: WwdEntityId,
        expected_commitment: B256,
    ) -> Result<Option<StoredBody>, TributeRepositoryError> {
        ensure_pin_day(pin, tribute_id)?;
        let mut selected: Option<Vec<u8>> = None;
        let mut current_mismatch = false;

        if let Some(current) = self
            .storage
            .get_record(namespace(TRIBUTES_NAMESPACE)?, &primary_key(tribute_id)?)?
        {
            let commitment = commitment_for_stored_bytes(tribute_id, current.value.as_bytes())?;
            if commitment == expected_commitment {
                selected = Some(current.value.as_bytes().to_vec());
            } else {
                current_mismatch = true;
            }
        }

        let retained_key = retained_key(pin, tribute_id, expected_commitment)?;
        if let Some(retained) = self
            .storage
            .get_record(namespace(OCOMP_RETAINED_TRIBUTES_NAMESPACE)?, &retained_key)?
        {
            if retained.metadata.is_some() {
                return Err(TributeRepositoryError::RetainedMetadata {
                    job_id: pin.input_lease_id,
                    tribute_id,
                });
            }
            let commitment = commitment_for_stored_bytes(tribute_id, retained.value.as_bytes())?;
            if commitment != expected_commitment {
                return Err(TributeRepositoryError::RetainedCommitmentMismatch {
                    job_id: pin.input_lease_id,
                    tribute_id,
                });
            }
            validate_retained_index_record(&self.storage, &retained_key, pin)?;
            if selected
                .as_ref()
                .is_some_and(|current| current.as_slice() != retained.value.as_bytes())
            {
                return Err(TributeRepositoryError::ConflictingRetainedBody {
                    job_id: pin.input_lease_id,
                    tribute_id,
                });
            }
            selected = Some(retained.value.as_bytes().to_vec());
        } else {
            let conflicting = self.storage.scan_prefix(
                namespace(OCOMP_RETAINED_TRIBUTES_NAMESPACE)?,
                ScanRequest::new(&retained_identity_prefix(pin, tribute_id), None, 1)?,
            )?;
            if !conflicting.entries.is_empty() {
                return Err(TributeRepositoryError::ConflictingRetainedBody {
                    job_id: pin.input_lease_id,
                    tribute_id,
                });
            }
        }

        match selected {
            Some(bytes) => StoredBody::decode(&bytes).map(Some).map_err(Into::into),
            None if current_mismatch => Err(TributeRepositoryError::RetainedCommitmentMismatch {
                job_id: pin.input_lease_id,
                tribute_id,
            }),
            None => Ok(None),
        }
    }

    /// Lists one exact job/day retained index in canonical key order.
    pub fn list_by_day(
        &self,
        pin: RetainedTributePin,
        after: Option<RetainedTributeCursor>,
        limit: usize,
    ) -> Result<RetainedTributePage, TributeRepositoryError> {
        if !(1..=MAX_SCAN_ENTRIES).contains(&limit) {
            return Err(TributeRepositoryError::InvalidPageLimit { limit });
        }
        if after.is_some_and(|cursor| cursor.tribute_id.worldwide_day() != pin.worldwide_day) {
            return Err(TributeRepositoryError::InvalidRetainedCursor {
                job_id: pin.input_lease_id,
                worldwide_day: pin.worldwide_day,
            });
        }
        let prefix = retained_day_prefix(pin);
        let after_key = after
            .map(|cursor| retained_key(pin, cursor.tribute_id, cursor.body_commitment))
            .transpose()?;
        let page = self.storage.scan_prefix(
            namespace(OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE)?,
            ScanRequest::new(&prefix, after_key.as_ref(), limit)?,
        )?;
        if let Some(continuation) = &page.next_after {
            if page.entries.last().map(|entry| &entry.key) != Some(continuation) {
                return Err(TributeRepositoryError::InvalidRetainedContinuation {
                    job_id: pin.input_lease_id,
                    worldwide_day: pin.worldwide_day,
                });
            }
        }

        let mut records = Vec::with_capacity(page.entries.len());
        let mut previous = after.map(|cursor| RetainedTributeRef {
            tribute_id: cursor.tribute_id,
            body_commitment: cursor.body_commitment,
        });
        for entry in &page.entries {
            let record = parse_retained_entry(entry, pin, true)?;
            if previous.is_some_and(|previous| record <= previous)
                || previous.is_some_and(|previous| record.tribute_id == previous.tribute_id)
            {
                return Err(TributeRepositoryError::NonAscendingRetainedPage {
                    job_id: pin.input_lease_id,
                    worldwide_day: pin.worldwide_day,
                });
            }
            previous = Some(record);
            records.push(record);
        }
        let next_after = page.next_after.map(|_| {
            let last = records
                .last()
                .copied()
                .expect("storage continuation requires a non-empty page");
            RetainedTributeCursor {
                tribute_id: last.tribute_id,
                body_commitment: last.body_commitment,
            }
        });
        Ok(RetainedTributePage {
            records,
            next_after,
        })
    }

    fn plan_release_input_lease_page(
        &self,
        input_lease_id: B256,
    ) -> Result<(AtomicWriteBatch, bool), TributeRepositoryError> {
        let (body_keys, body_has_more) = collect_job_key_page(
            &self.storage,
            OCOMP_RETAINED_TRIBUTES_NAMESPACE,
            input_lease_id,
            false,
        )?;
        let (index_keys, index_has_more) = collect_job_key_page(
            &self.storage,
            OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE,
            input_lease_id,
            true,
        )?;
        if body_keys != index_keys || body_has_more != index_has_more {
            return Err(TributeRepositoryError::RetainedNamespaceMismatch {
                job_id: input_lease_id,
            });
        }

        let mut batch = AtomicWriteBatch::new();
        for key in body_keys {
            batch.push(AtomicWriteOperation::delete(
                namespace(OCOMP_RETAINED_TRIBUTES_NAMESPACE)?,
                key.clone(),
            ));
            batch.push(AtomicWriteOperation::delete(
                namespace(OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE)?,
                key,
            ));
        }
        batch.validate()?;
        Ok((batch, !body_has_more))
    }
}

/// Node-owned release capability. Compute processes receive only the reader.
pub struct RetainedTributeWriter {
    reader: RetainedTributeReader,
    writer: StorageWriterHandle,
}

impl RetainedTributeWriter {
    #[must_use]
    pub fn new(reader: StorageReaderHandle, writer: StorageWriterHandle) -> Self {
        Self {
            reader: RetainedTributeReader::new(reader),
            writer,
        }
    }

    /// Idempotently deletes one bounded page of one exact input lease's bodies
    /// and index. Returns `true` only after the final page has been deleted.
    pub fn release_input_lease_page(
        &self,
        input_lease_id: B256,
    ) -> Result<bool, TributeRepositoryError> {
        let (batch, complete) = self.reader.plan_release_input_lease_page(input_lease_id)?;
        self.writer.apply_atomic(&batch)?;
        Ok(complete)
    }
}

fn ensure_pin_day(
    pin: RetainedTributePin,
    tribute_id: WwdEntityId,
) -> Result<(), TributeRepositoryError> {
    if tribute_id.worldwide_day() != pin.worldwide_day {
        return Err(TributeRepositoryError::RetainedDayMismatch {
            job_id: pin.input_lease_id,
            tribute_id,
            worldwide_day: pin.worldwide_day,
        });
    }
    Ok(())
}

fn commitment_for_stored_bytes(
    tribute_id: WwdEntityId,
    bytes: &[u8],
) -> Result<B256, TributeRepositoryError> {
    let stored = StoredBody::decode(bytes)?;
    let body = decode_stored_tribute_v1(bytes)?;
    if body.tribute_id != tribute_id {
        return Err(TributeRepositoryError::PrimaryKeyBodyMismatch {
            expected: tribute_id,
            actual: body.tribute_id,
        });
    }
    let commitment = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        stored.schema_version(),
        tribute_id,
        stored.payload(),
    )
    .map_err(|error| TributeRepositoryError::RetainedCommitment(error.to_string()))?;
    Ok(B256::from(*commitment.as_bytes()))
}

fn retained_day_prefix(pin: RetainedTributePin) -> [u8; DAY_PREFIX_LEN] {
    let mut bytes = [0_u8; DAY_PREFIX_LEN];
    bytes[..JOB_PREFIX_LEN].copy_from_slice(pin.input_lease_id.as_slice());
    bytes[JOB_PREFIX_LEN..].copy_from_slice(&pin.worldwide_day.value().to_be_bytes());
    bytes
}

fn retained_identity_prefix(
    pin: RetainedTributePin,
    tribute_id: WwdEntityId,
) -> [u8; ID_PREFIX_LEN] {
    let mut bytes = [0_u8; ID_PREFIX_LEN];
    bytes[..DAY_PREFIX_LEN].copy_from_slice(&retained_day_prefix(pin));
    bytes[DAY_PREFIX_LEN..].copy_from_slice(tribute_id.as_slice());
    bytes
}

fn retained_key(
    pin: RetainedTributePin,
    tribute_id: WwdEntityId,
    commitment: B256,
) -> Result<Key, TributeRepositoryError> {
    ensure_pin_day(pin, tribute_id)?;
    let mut bytes = Vec::with_capacity(RETAINED_KEY_LEN);
    bytes.extend_from_slice(&retained_identity_prefix(pin, tribute_id));
    bytes.extend_from_slice(commitment.as_slice());
    Ok(Key::new(bytes)?)
}

fn parse_retained_entry(
    entry: &ScanEntry,
    pin: RetainedTributePin,
    index: bool,
) -> Result<RetainedTributeRef, TributeRepositoryError> {
    if index && !entry.value.as_bytes().is_empty() {
        return Err(TributeRepositoryError::NonEmptyIndexValue {
            index: "OCOMP retained day",
        });
    }
    let bytes = entry.key.as_bytes();
    if bytes.len() != RETAINED_KEY_LEN
        || bytes[..JOB_PREFIX_LEN] != *pin.input_lease_id.as_slice()
        || bytes[JOB_PREFIX_LEN..DAY_PREFIX_LEN] != pin.worldwide_day.value().to_be_bytes()
    {
        return Err(TributeRepositoryError::MalformedIndexKey {
            index: "OCOMP retained",
        });
    }
    let tribute_id = WwdEntityId::try_from(&bytes[DAY_PREFIX_LEN..ID_PREFIX_LEN])?;
    ensure_pin_day(pin, tribute_id)?;
    if !index && entry.metadata.is_some() {
        return Err(TributeRepositoryError::RetainedMetadata {
            job_id: pin.input_lease_id,
            tribute_id,
        });
    }
    let body_commitment = B256::from_slice(&bytes[ID_PREFIX_LEN..RETAINED_KEY_LEN]);
    if !index && commitment_for_stored_bytes(tribute_id, entry.value.as_bytes())? != body_commitment
    {
        return Err(TributeRepositoryError::RetainedCommitmentMismatch {
            job_id: pin.input_lease_id,
            tribute_id,
        });
    }
    Ok(RetainedTributeRef {
        tribute_id,
        body_commitment,
    })
}

fn validate_retained_index_record(
    storage: &StorageReaderHandle,
    key: &Key,
    pin: RetainedTributePin,
) -> Result<(), TributeRepositoryError> {
    let entry = storage
        .get_record(namespace(OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE)?, key)?
        .ok_or_else(|| {
            let tribute_id = WwdEntityId::try_from(&key.as_bytes()[DAY_PREFIX_LEN..ID_PREFIX_LEN])
                .expect("validated retained key");
            TributeRepositoryError::MissingRetainedIndex {
                job_id: pin.input_lease_id,
                tribute_id,
            }
        })?;
    let scan_entry = ScanEntry {
        key: key.clone(),
        value: entry.value,
        metadata: entry.metadata,
    };
    parse_retained_entry(&scan_entry, pin, true)?;
    Ok(())
}

fn collect_job_key_page(
    storage: &StorageReaderHandle,
    namespace_name: &'static str,
    job_id: B256,
    index: bool,
) -> Result<(BTreeSet<Key>, bool), TributeRepositoryError> {
    let page = storage.scan_prefix(
        namespace(namespace_name)?,
        ScanRequest::new(job_id.as_slice(), None, RETAINED_RELEASE_PAGE_LIMIT)?,
    )?;
    if let Some(continuation) = &page.next_after {
        if page.entries.last().map(|entry| &entry.key) != Some(continuation) {
            return Err(TributeRepositoryError::InvalidRetainedContinuation {
                job_id,
                worldwide_day: WorldwideDay::new(0),
            });
        }
    }

    let mut output = BTreeSet::new();
    for entry in &page.entries {
        if entry.key.as_bytes().len() != RETAINED_KEY_LEN {
            return Err(TributeRepositoryError::MalformedIndexKey {
                index: "OCOMP retained",
            });
        }
        let day = WorldwideDay::new(u32::from_be_bytes(
            entry.key.as_bytes()[JOB_PREFIX_LEN..DAY_PREFIX_LEN]
                .try_into()
                .expect("fixed retained day"),
        ));
        let pin = RetainedTributePin {
            input_lease_id: job_id,
            worldwide_day: day,
        };
        parse_retained_entry(entry, pin, index)?;
        if !output.insert(entry.key.clone()) {
            return Err(TributeRepositoryError::NonAscendingRetainedPage {
                job_id,
                worldwide_day: day,
            });
        }
    }
    Ok((output, page.next_after.is_some()))
}
