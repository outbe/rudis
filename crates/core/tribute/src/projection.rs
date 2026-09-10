//! Pure off-chain mutation planning for Tribute projection.

use std::collections::BTreeMap;

use outbe_compressed_entities::WwdEntityId;
use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, StorageMetadata, StoredValue, Value,
};

use crate::{
    repository::{
        day_index_key, decode_body, namespace, owner_index_key, primary_key,
        TRIBUTES_BY_DAY_NAMESPACE, TRIBUTES_BY_OWNER_NAMESPACE, TRIBUTES_NAMESPACE,
    },
    retention::{
        RetainedTributePin, RetainedTributeReader, OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE,
        OCOMP_RETAINED_TRIBUTES_NAMESPACE,
    },
    TributeData, TributeRepositoryError,
};

/// Code-defined namespaces owned by the Tribute repository.
pub const TRIBUTE_PROJECTION_NAMESPACES: [&str; 5] = [
    TRIBUTES_NAMESPACE,
    TRIBUTES_BY_OWNER_NAMESPACE,
    TRIBUTES_BY_DAY_NAMESPACE,
    OCOMP_RETAINED_TRIBUTES_NAMESPACE,
    OCOMP_RETAINED_TRIBUTES_BY_DAY_NAMESPACE,
];

/// Repository-owned prior state plus an in-block overlay for Tribute projection.
///
/// Callers can mutate only identities loaded through
/// [`crate::TributeRepositoryReader::projection_session`]. They cannot supply or omit an
/// arbitrary semantic prior body.
pub struct TributeProjectionSession {
    records: BTreeMap<WwdEntityId, Option<ProjectionTributeRecord>>,
}

struct ProjectionTributeRecord {
    body: TributeData,
    metadata: Option<StorageMetadata>,
    stored_body: Value,
}

impl TributeProjectionSession {
    pub(crate) fn from_records(
        tribute_ids: &[WwdEntityId],
        records: Vec<Option<StoredValue>>,
    ) -> Result<Self, TributeRepositoryError> {
        let records = tribute_ids
            .iter()
            .copied()
            .zip(records)
            .map(|(tribute_id, record)| {
                let record = record
                    .map(|record| {
                        let body = decode_body(tribute_id, record.value.as_bytes())?;
                        Ok::<ProjectionTributeRecord, TributeRepositoryError>(
                            ProjectionTributeRecord {
                                body,
                                metadata: record.metadata,
                                stored_body: record.value,
                            },
                        )
                    })
                    .transpose()?;
                Ok((tribute_id, record))
            })
            .collect::<Result<_, TributeRepositoryError>>()?;
        Ok(Self { records })
    }

    /// Returns the current semantic body from the repository snapshot or in-block overlay.
    pub fn current(
        &self,
        tribute_id: WwdEntityId,
    ) -> Result<Option<&TributeData>, TributeRepositoryError> {
        Ok(self
            .current_with_metadata(tribute_id)?
            .map(|(body, _)| body))
    }

    /// Returns the current body and provenance without exposing a constructible prior snapshot.
    pub fn current_with_metadata(
        &self,
        tribute_id: WwdEntityId,
    ) -> Result<Option<(&TributeData, Option<&StorageMetadata>)>, TributeRepositoryError> {
        match self
            .records
            .get(&tribute_id)
            .ok_or(TributeRepositoryError::UntrackedProjectionIdentity { tribute_id })?
        {
            Some(record) => Ok(Some((&record.body, record.metadata.as_ref()))),
            None => Ok(None),
        }
    }

    /// Plans one canonical store and advances the overlay only after full validation.
    pub fn store(
        &mut self,
        tribute_id: WwdEntityId,
        stored_body: Value,
        metadata: Option<StorageMetadata>,
    ) -> Result<AtomicWriteBatch, TributeRepositoryError> {
        let body = decode_body(tribute_id, stored_body.as_bytes())?;
        let overlay_body = stored_body.clone();
        let old = self.current(tribute_id)?;
        let batch = plan_tribute_mutation(
            old,
            TributeMutation::Store {
                tribute_id,
                stored_body,
                metadata: metadata.clone(),
            },
        )?;
        self.records.insert(
            tribute_id,
            Some(ProjectionTributeRecord {
                body,
                metadata,
                stored_body: overlay_body,
            }),
        );
        Ok(batch)
    }

    /// Plans one delete from the owned prior snapshot and advances the overlay to absence.
    pub fn delete(
        &mut self,
        tribute_id: WwdEntityId,
    ) -> Result<AtomicWriteBatch, TributeRepositoryError> {
        let old = self.current(tribute_id)?;
        let batch = plan_tribute_mutation(old, TributeMutation::Delete { tribute_id })?;
        self.records.insert(tribute_id, None);
        Ok(batch)
    }

    /// Plans an immutable job-retained copy followed by the canonical delete.
    ///
    /// The caller must apply the returned operations in the same transaction
    /// as the finalized projection checkpoint.
    pub fn retain_then_delete(
        &mut self,
        retained: &RetainedTributeReader,
        pin: RetainedTributePin,
        tribute_id: WwdEntityId,
    ) -> Result<AtomicWriteBatch, TributeRepositoryError> {
        let stored_body = self
            .records
            .get(&tribute_id)
            .ok_or(TributeRepositoryError::UntrackedProjectionIdentity { tribute_id })?
            .as_ref()
            .map(|record| record.stored_body.clone())
            .ok_or(TributeRepositoryError::MissingCurrentBodyForRetention { tribute_id })?;
        let retained_batch = retained.plan_retain_stored(pin, tribute_id, stored_body)?;
        let delete_batch = self.delete(tribute_id)?;
        let mut batch = AtomicWriteBatch::new();
        batch.extend(retained_batch.operations().iter().cloned());
        batch.extend(delete_batch.operations().iter().cloned());
        batch.validate()?;
        Ok(batch)
    }
}

/// One complete Tribute projection mutation.
enum TributeMutation {
    /// Store a complete body and its optional primary metadata.
    Store {
        /// Indexed event identity.
        tribute_id: WwdEntityId,
        /// Exact canonical StoredBody bytes. The planner decodes this value and
        /// derives every semantic index from it.
        stored_body: Value,
        /// Metadata attached only to the primary body.
        metadata: Option<StorageMetadata>,
    },
    /// Delete one body identity and all indexes derivable from the old body.
    Delete {
        /// Indexed event identity.
        tribute_id: WwdEntityId,
    },
}

/// Plans all primary and index mutations without reading or writing storage.
fn plan_tribute_mutation(
    old: Option<&TributeData>,
    mutation: TributeMutation,
) -> Result<AtomicWriteBatch, TributeRepositoryError> {
    let tribute_id = match &mutation {
        TributeMutation::Store { tribute_id, .. } | TributeMutation::Delete { tribute_id } => {
            *tribute_id
        }
    };
    if let Some(old) = old {
        validate_identity(tribute_id, old)?;
    }

    let mut batch = AtomicWriteBatch::new();
    match mutation {
        TributeMutation::Store {
            tribute_id,
            stored_body,
            metadata,
        } => {
            let body = decode_body(tribute_id, stored_body.as_bytes())?;
            let primary_record = match metadata {
                Some(metadata) => StoredValue::with_metadata(stored_body, metadata),
                None => StoredValue::plain(stored_body),
            };
            batch.push(AtomicWriteOperation::put_record(
                namespace(TRIBUTES_NAMESPACE)?,
                primary_key(tribute_id)?,
                primary_record,
            ));
            let empty = Value::new(Vec::new())?;
            batch.push(AtomicWriteOperation::put(
                namespace(TRIBUTES_BY_OWNER_NAMESPACE)?,
                owner_index_key(body.owner, tribute_id)?,
                empty.clone(),
            ));
            batch.push(AtomicWriteOperation::put(
                namespace(TRIBUTES_BY_DAY_NAMESPACE)?,
                day_index_key(body.worldwide_day, tribute_id)?,
                empty,
            ));
            if let Some(old) = old {
                if old.owner != body.owner {
                    batch.push(AtomicWriteOperation::delete(
                        namespace(TRIBUTES_BY_OWNER_NAMESPACE)?,
                        owner_index_key(old.owner, tribute_id)?,
                    ));
                }
                if old.worldwide_day != body.worldwide_day {
                    batch.push(AtomicWriteOperation::delete(
                        namespace(TRIBUTES_BY_DAY_NAMESPACE)?,
                        day_index_key(old.worldwide_day, tribute_id)?,
                    ));
                }
            }
        }
        TributeMutation::Delete { tribute_id } => {
            if let Some(old) = old {
                batch.push(AtomicWriteOperation::delete(
                    namespace(TRIBUTES_BY_OWNER_NAMESPACE)?,
                    owner_index_key(old.owner, tribute_id)?,
                ));
                batch.push(AtomicWriteOperation::delete(
                    namespace(TRIBUTES_BY_DAY_NAMESPACE)?,
                    day_index_key(old.worldwide_day, tribute_id)?,
                ));
            }
            batch.push(AtomicWriteOperation::delete(
                namespace(TRIBUTES_NAMESPACE)?,
                primary_key(tribute_id)?,
            ));
        }
    }
    Ok(batch)
}

fn validate_identity(
    expected: WwdEntityId,
    body: &TributeData,
) -> Result<(), TributeRepositoryError> {
    if body.tribute_id != expected {
        return Err(TributeRepositoryError::PrimaryKeyBodyMismatch {
            expected,
            actual: body.tribute_id,
        });
    }
    Ok(())
}
