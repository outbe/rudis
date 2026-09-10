//! Pure off-chain mutation planning for Nod item and bucket projection.

use std::collections::BTreeMap;

use outbe_compressed_entities::WwdEntityId;
use outbe_offchain_storage::{
    AtomicWriteBatch, AtomicWriteOperation, StorageMetadata, StoredValue, Value,
};

use crate::{
    repository::{
        bucket_storage_key, decode_bucket, decode_item, item_key, namespace, owner_index_key,
        NODS_BY_OWNER_NAMESPACE, NODS_NAMESPACE, NOD_BUCKETS_NAMESPACE,
    },
    repository::{NodBucketRecordWithMetadata, NodItemRecordWithMetadata},
    NodBucketState, NodItemState, NodRepositoryError,
};

/// Code-defined namespaces owned by the Nod repository.
pub const NOD_PROJECTION_NAMESPACES: [&str; 3] = [
    NODS_NAMESPACE,
    NOD_BUCKETS_NAMESPACE,
    NODS_BY_OWNER_NAMESPACE,
];

/// Repository-owned prior state plus an in-block overlay for Nod projection.
///
/// Callers can mutate only identities loaded through
/// [`crate::NodRepositoryReader::projection_session`]. They cannot supply or omit arbitrary
/// semantic prior item or bucket bodies.
pub struct NodProjectionSession {
    items: BTreeMap<WwdEntityId, Option<NodItemRecordWithMetadata>>,
    buckets: BTreeMap<WwdEntityId, Option<NodBucketRecordWithMetadata>>,
}

impl NodProjectionSession {
    pub(crate) fn from_records(
        nod_ids: &[WwdEntityId],
        items: Vec<Option<NodItemRecordWithMetadata>>,
        bucket_ids: &[WwdEntityId],
        buckets: Vec<Option<NodBucketRecordWithMetadata>>,
    ) -> Self {
        Self {
            items: nod_ids.iter().copied().zip(items).collect(),
            buckets: bucket_ids.iter().copied().zip(buckets).collect(),
        }
    }

    /// Returns the current item body from the repository snapshot or in-block overlay.
    pub fn current_item(
        &self,
        nod_id: WwdEntityId,
    ) -> Result<Option<&NodItemState>, NodRepositoryError> {
        Ok(self
            .current_item_with_metadata(nod_id)?
            .map(|(body, _)| body))
    }

    /// Returns the current item and provenance without exposing a constructible prior snapshot.
    pub fn current_item_with_metadata(
        &self,
        nod_id: WwdEntityId,
    ) -> Result<Option<(&NodItemState, Option<&StorageMetadata>)>, NodRepositoryError> {
        match self
            .items
            .get(&nod_id)
            .ok_or(NodRepositoryError::UntrackedProjectionIdentity {
                entity: "Nod item",
                identity: nod_id,
            })? {
            Some((body, metadata)) => Ok(Some((body, metadata.as_ref()))),
            None => Ok(None),
        }
    }

    /// Returns the current bucket body from the repository snapshot or in-block overlay.
    pub fn current_bucket(
        &self,
        bucket_id: WwdEntityId,
    ) -> Result<Option<&NodBucketState>, NodRepositoryError> {
        Ok(self
            .current_bucket_with_metadata(bucket_id)?
            .map(|(body, _)| body))
    }

    /// Returns the current bucket and provenance without exposing a constructible prior snapshot.
    pub fn current_bucket_with_metadata(
        &self,
        bucket_id: WwdEntityId,
    ) -> Result<Option<(&NodBucketState, Option<&StorageMetadata>)>, NodRepositoryError> {
        match self.buckets.get(&bucket_id).ok_or(
            NodRepositoryError::UntrackedProjectionIdentity {
                entity: "Nod bucket",
                identity: bucket_id,
            },
        )? {
            Some((body, metadata)) => Ok(Some((body, metadata.as_ref()))),
            None => Ok(None),
        }
    }

    /// Plans one canonical item store and advances the overlay after full validation.
    pub fn store_item(
        &mut self,
        nod_id: WwdEntityId,
        stored_body: Value,
        metadata: Option<StorageMetadata>,
    ) -> Result<AtomicWriteBatch, NodRepositoryError> {
        let body = decode_item(nod_id, stored_body.as_bytes())?;
        let old = self.current_item(nod_id)?;
        let batch = plan_nod_item_mutation(
            old,
            NodItemMutation::Store {
                nod_id,
                stored_body,
                metadata: metadata.clone(),
            },
        )?;
        self.items.insert(nod_id, Some((body, metadata)));
        Ok(batch)
    }

    /// Plans one item delete from the owned prior snapshot and advances overlay to absence.
    pub fn delete_item(
        &mut self,
        nod_id: WwdEntityId,
    ) -> Result<AtomicWriteBatch, NodRepositoryError> {
        let old = self.current_item(nod_id)?;
        let batch = plan_nod_item_mutation(old, NodItemMutation::Delete { nod_id })?;
        self.items.insert(nod_id, None);
        Ok(batch)
    }

    /// Plans one canonical bucket store and advances the overlay after full validation.
    pub fn store_bucket(
        &mut self,
        bucket_id: WwdEntityId,
        stored_body: Value,
        metadata: Option<StorageMetadata>,
    ) -> Result<AtomicWriteBatch, NodRepositoryError> {
        let body = decode_bucket(bucket_id, stored_body.as_bytes())?;
        let old = self.current_bucket(bucket_id)?;
        let batch = plan_nod_bucket_mutation(
            old,
            NodBucketMutation::Store {
                bucket_id,
                stored_body,
                metadata: metadata.clone(),
            },
        )?;
        self.buckets.insert(bucket_id, Some((body, metadata)));
        Ok(batch)
    }

    /// Plans one bucket delete from the owned prior snapshot and advances overlay to absence.
    pub fn delete_bucket(
        &mut self,
        bucket_id: WwdEntityId,
    ) -> Result<AtomicWriteBatch, NodRepositoryError> {
        let old = self.current_bucket(bucket_id)?;
        let batch = plan_nod_bucket_mutation(old, NodBucketMutation::Delete { bucket_id })?;
        self.buckets.insert(bucket_id, None);
        Ok(batch)
    }
}

/// One complete Nod item projection mutation.
enum NodItemMutation {
    /// Store a complete item and its optional primary metadata.
    Store {
        /// Indexed event identity.
        nod_id: WwdEntityId,
        /// Exact canonical StoredBody bytes. The planner decodes this value and
        /// derives every semantic index from it.
        stored_body: Value,
        /// Metadata attached only to the primary body.
        metadata: Option<StorageMetadata>,
    },
    /// Delete one item identity and its index derivable from the old body.
    Delete {
        /// Indexed event identity.
        nod_id: WwdEntityId,
    },
}

/// One complete Nod bucket projection mutation.
enum NodBucketMutation {
    /// Store a complete bucket and its optional primary metadata.
    Store {
        /// Indexed event identity.
        bucket_id: WwdEntityId,
        /// Exact canonical StoredBody bytes. The planner decodes this value and
        /// validates its canonical bucket identity.
        stored_body: Value,
        /// Metadata attached only to the primary body.
        metadata: Option<StorageMetadata>,
    },
    /// Delete one bucket identity.
    Delete {
        /// Indexed event identity.
        bucket_id: WwdEntityId,
    },
}

/// Plans all Nod item primary/index mutations without storage access.
fn plan_nod_item_mutation(
    old: Option<&NodItemState>,
    mutation: NodItemMutation,
) -> Result<AtomicWriteBatch, NodRepositoryError> {
    let nod_id = match &mutation {
        NodItemMutation::Store { nod_id, .. } | NodItemMutation::Delete { nod_id } => *nod_id,
    };
    if let Some(old) = old {
        validate_item_identity(nod_id, old)?;
    }

    let mut batch = AtomicWriteBatch::new();
    match mutation {
        NodItemMutation::Store {
            nod_id,
            stored_body,
            metadata,
        } => {
            let body = decode_item(nod_id, stored_body.as_bytes())?;
            let primary_record = match metadata {
                Some(metadata) => StoredValue::with_metadata(stored_body, metadata),
                None => StoredValue::plain(stored_body),
            };
            batch.push(AtomicWriteOperation::put_record(
                namespace(NODS_NAMESPACE)?,
                item_key(nod_id)?,
                primary_record,
            ));
            batch.push(AtomicWriteOperation::put(
                namespace(NODS_BY_OWNER_NAMESPACE)?,
                owner_index_key(body.owner, nod_id)?,
                Value::new(Vec::new())?,
            ));
            if let Some(old) = old {
                if old.owner != body.owner {
                    batch.push(AtomicWriteOperation::delete(
                        namespace(NODS_BY_OWNER_NAMESPACE)?,
                        owner_index_key(old.owner, nod_id)?,
                    ));
                }
            }
        }
        NodItemMutation::Delete { nod_id } => {
            if let Some(old) = old {
                batch.push(AtomicWriteOperation::delete(
                    namespace(NODS_BY_OWNER_NAMESPACE)?,
                    owner_index_key(old.owner, nod_id)?,
                ));
            }
            batch.push(AtomicWriteOperation::delete(
                namespace(NODS_NAMESPACE)?,
                item_key(nod_id)?,
            ));
        }
    }
    Ok(batch)
}

/// Plans one Nod bucket primary mutation without storage access.
fn plan_nod_bucket_mutation(
    old: Option<&NodBucketState>,
    mutation: NodBucketMutation,
) -> Result<AtomicWriteBatch, NodRepositoryError> {
    let bucket_id = match &mutation {
        NodBucketMutation::Store { bucket_id, .. } | NodBucketMutation::Delete { bucket_id } => {
            *bucket_id
        }
    };
    if let Some(old) = old {
        validate_bucket_identity(bucket_id, old)?;
    }

    let mut batch = AtomicWriteBatch::new();
    match mutation {
        NodBucketMutation::Store {
            bucket_id,
            stored_body,
            metadata,
        } => {
            decode_bucket(bucket_id, stored_body.as_bytes())?;
            let primary_record = match metadata {
                Some(metadata) => StoredValue::with_metadata(stored_body, metadata),
                None => StoredValue::plain(stored_body),
            };
            batch.push(AtomicWriteOperation::put_record(
                namespace(NOD_BUCKETS_NAMESPACE)?,
                bucket_storage_key(bucket_id)?,
                primary_record,
            ));
        }
        NodBucketMutation::Delete { bucket_id } => {
            batch.push(AtomicWriteOperation::delete(
                namespace(NOD_BUCKETS_NAMESPACE)?,
                bucket_storage_key(bucket_id)?,
            ));
        }
    }
    Ok(batch)
}

fn validate_item_identity(
    expected: WwdEntityId,
    body: &NodItemState,
) -> Result<(), NodRepositoryError> {
    if body.nod_id != expected {
        return Err(NodRepositoryError::PrimaryKeyBodyMismatch {
            expected,
            actual: body.nod_id,
        });
    }
    Ok(())
}

fn validate_bucket_identity(
    expected: WwdEntityId,
    body: &NodBucketState,
) -> Result<(), NodRepositoryError> {
    let actual = crate::repository::canonical_bucket_id(body);
    if actual != expected {
        return Err(NodRepositoryError::BucketIdBodyMismatch { expected, actual });
    }
    Ok(())
}
