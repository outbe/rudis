use std::collections::BTreeSet;

use alloy_primitives::{B256, U256};
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::StorageHandle,
};

use crate::{
    api::{EntityRef, ExecutionScope},
    collection_key, partition_collection_key,
    schema::{
        body_locator, Collection, CompressedEntitiesSchema, DeltaStatus, IndexRecord, PendingWord,
        STORAGE_SCHEMA_VERSION,
    },
    CeDomain, Commitment, PartitionRef, RetirementOutcome, WwdEntityId,
};

// Cleanup is prepaid on the first touch. The provider separately meters the
// transaction's immediate SLOAD/SSTORE work. These reserves cover the later
// no-refund end-block zeroing only.
const SSTORE_RESET_GAS: u64 = 5_000;
pub(crate) const MAX_STORED_BODY_BYTES_V1: usize = 192;
/// The identity is two plain words now (slot 10 and slot 13), not a
/// dynamic byte record, so cleanup zeroes exactly two slots.
const BODY_IDENTITY_SLOTS: u64 = 2;
const MAX_INDEX_RECORD_BYTES: usize = 55;

const fn dynamic_storage_slots(bytes: usize) -> u64 {
    1 + bytes.div_ceil(32) as u64
}

pub(crate) const FIRST_BODY_TOUCH_CLEANUP_GAS: u64 = SSTORE_RESET_GAS
    * (1 + dynamic_storage_slots(MAX_STORED_BODY_BYTES_V1) + BODY_IDENTITY_SLOTS + 1);
pub(crate) const FIRST_INDEX_TOUCH_CLEANUP_GAS: u64 =
    SSTORE_RESET_GAS * (1 + dynamic_storage_slots(MAX_INDEX_RECORD_BYTES) + 1);
pub(crate) const BODY_TOUCHED_LENGTH_CLEANUP_GAS: u64 = SSTORE_RESET_GAS;
pub(crate) const INDEX_TOUCHED_LENGTH_CLEANUP_GAS: u64 = SSTORE_RESET_GAS;
pub(crate) const FIRST_RETIREMENT_TOUCH_CLEANUP_GAS: u64 = SSTORE_RESET_GAS * 2;
pub(crate) const RETIREMENT_TOUCHED_LENGTH_CLEANUP_GAS: u64 = SSTORE_RESET_GAS;

pub(crate) struct State<'storage> {
    storage: StorageHandle<'storage>,
}

impl<'storage> State<'storage> {
    pub(crate) fn new(storage: StorageHandle<'storage>) -> Self {
        Self { storage }
    }

    fn schema(&self) -> CompressedEntitiesSchema<'storage> {
        CompressedEntitiesSchema::new(self.storage.clone())
    }

    pub(crate) fn ensure_schema(&self) -> Result<()> {
        let schema = self.schema();
        let actual = schema.storage_schema_version.read()?;
        match actual {
            0 => {
                if !schema.last_smt_root.read()?.is_zero()
                    || !schema.reserved_2.read()?.is_zero()
                    || !schema.reserved_3.read()?.is_zero()
                {
                    return Err(fatal(
                        "compressed-entity schema initialization found non-empty root/reserved slots",
                    ));
                }
                #[cfg(test)]
                {
                    let root =
                        crate::sealed_root(B256::ZERO).map_err(|error| fatal(error.to_string()))?;
                    schema
                        .last_smt_root
                        .write(U256::from_be_slice(root.as_slice()))?;
                    schema.storage_schema_version.write(STORAGE_SCHEMA_VERSION)
                }
                #[cfg(not(test))]
                {
                    Err(fatal(
                        "compressed-entity genesis allocation is missing; lazy initialization is forbidden",
                    ))
                }
            }
            STORAGE_SCHEMA_VERSION => Ok(()),
            2 => {
                if !schema.touched.is_empty()?
                    || !schema.touched_index_deltas.is_empty()?
                    || !schema.retirement_touched.is_empty()?
                {
                    return Err(fatal(
                        "compressed-entity schema migration requires an empty overlay",
                    ));
                }
                schema.storage_schema_version.write(STORAGE_SCHEMA_VERSION)
            }
            _ => Err(fatal(format!(
                "unsupported compressed-entity storage schema {actual}"
            ))),
        }
    }

    fn validate_schema_for_read(&self) -> Result<()> {
        let actual = self.schema().storage_schema_version.read()?;
        match actual {
            STORAGE_SCHEMA_VERSION => Ok(()),
            #[cfg(test)]
            0 => Ok(()),
            #[cfg(not(test))]
            0 => Err(fatal(
                "compressed-entity genesis allocation is missing; reads cannot bootstrap it",
            )),
            _ => Err(fatal(format!(
                "unsupported compressed-entity storage schema {actual}"
            ))),
        }
    }

    pub(crate) fn root(&self) -> Result<B256> {
        self.validate_schema_for_read()?;
        let schema = self.schema();
        if !schema.reserved_2.read()?.is_zero() || !schema.reserved_3.read()?.is_zero() {
            return Err(fatal(
                "compressed-entity reserved schema slots are non-zero",
            ));
        }
        Ok(B256::from(schema.last_smt_root.read()?.to_be_bytes::<32>()))
    }

    pub(crate) fn write_root(&self, root: B256) -> Result<()> {
        self.ensure_schema()?;
        let schema = self.schema();
        if !schema.reserved_2.read()?.is_zero() || !schema.reserved_3.read()?.is_zero() {
            return Err(fatal(
                "compressed-entity reserved schema slots are non-zero",
            ));
        }
        schema.last_smt_root.write(U256::from_be_bytes(root.0))
    }

    pub(crate) fn pending(
        &self,
        collection: Collection,
        entity_id: WwdEntityId,
    ) -> Result<(B256, PendingWord, Vec<u8>)> {
        self.validate_schema_for_read()?;
        let locator = body_locator(collection, entity_id)?;
        let schema = self.schema();
        let pending = PendingWord::decode(schema.pending_word.read(&locator)?)?;
        let body = schema.pending_body.get_bytes(&locator).read()?;
        let identity_record = self.read_body_identity(locator)?;

        match pending {
            PendingWord::Untouched => {
                if !body.is_empty() || identity_record.is_some() {
                    return Err(fatal(
                        "untouched compressed-entity locator has residual dynamic state",
                    ));
                }
            }
            PendingWord::Set(_) => {
                self.validate_body_record(locator, collection, entity_id, identity_record)?;
                if body.is_empty() {
                    return Err(fatal("compressed-entity Set entry has no pending body"));
                }
            }
            PendingWord::Deleted => {
                self.validate_body_record(locator, collection, entity_id, identity_record)?;
                if !body.is_empty() {
                    return Err(fatal(
                        "compressed-entity Deleted entry retains pending body",
                    ));
                }
            }
        }
        Ok((locator, pending, body))
    }

    fn validate_body_record(
        &self,
        locator: B256,
        collection: Collection,
        entity_id: WwdEntityId,
        stored: Option<(Collection, WwdEntityId)>,
    ) -> Result<()> {
        let Some((stored_collection, stored_id)) = stored else {
            return Err(fatal(
                "compressed-entity body identity record/hash mismatch",
            ));
        };
        if stored_collection != collection
            || stored_id != entity_id
            || body_locator(stored_collection, stored_id)? != locator
        {
            return Err(fatal(
                "compressed-entity body identity record/hash mismatch",
            ));
        }
        Ok(())
    }

    /// The identity at `locator`, or `None` when the locator is untouched.
    /// Absence is carried by the collection byte, not by a zero identity:
    /// `Collection::from_id` rejects 0, and a zero identity is a representable
    /// value rather than a sentinel.
    fn read_body_identity(&self, locator: B256) -> Result<Option<(Collection, WwdEntityId)>> {
        let schema = self.schema();
        let collection_id = schema.body_identity_collection.read(&locator)?;
        if collection_id == 0 {
            return Ok(None);
        }
        let collection = Collection::from_id(collection_id)?;
        Ok(Some((collection, schema.body_identity.read(&locator)?)))
    }

    /// Writes both words. A half-written pair decodes as a different identity
    /// rather than a missing one, so callers holding a checkpoint must keep
    /// this inside it.
    fn write_body_identity(
        &self,
        locator: B256,
        collection: Collection,
        entity_id: WwdEntityId,
    ) -> Result<()> {
        let schema = self.schema();
        schema.body_identity.write(&locator, entity_id)?;
        schema
            .body_identity_collection
            .write(&locator, collection.id())
    }

    fn clear_body_identity(&self, locator: B256) -> Result<()> {
        let schema = self.schema();
        schema.body_identity.write(&locator, WwdEntityId::ZERO)?;
        schema.body_identity_collection.write(&locator, 0)
    }

    fn has_body_identity(&self, locator: B256) -> Result<bool> {
        Ok(self.schema().body_identity_collection.read(&locator)? != 0)
    }

    pub(crate) fn prepare_body_touch(
        &self,
        scope: &ExecutionScope,
        collection: Collection,
        entity_id: WwdEntityId,
    ) -> Result<B256> {
        let (locator, pending, _) = self.pending(collection, entity_id)?;
        let entity = match collection {
            Collection::Tribute => EntityRef::Tribute(entity_id),
            Collection::NodItem => EntityRef::NodItem(entity_id),
            Collection::NodBucket => EntityRef::NodBucket(entity_id),
        };
        let domain = match collection {
            Collection::Tribute => CeDomain::Tribute,
            Collection::NodItem => CeDomain::NodItem,
            Collection::NodBucket => CeDomain::NodBucket,
        };
        let collection_key =
            collection_key(domain, entity_id).map_err(|error| fatal(error.to_string()))?;
        if !self
            .schema()
            .pending_retirement
            .read(&B256::from(*collection_key.as_bytes()))?
            .is_zero()
        {
            return Err(fatal(
                "compressed-entity mutation conflicts with pending collection retirement",
            ));
        }
        // The transaction footprint includes keys already touched by an
        // earlier transaction in this block, even though they need no second
        // block-level sealing reservation.
        scope.reserve_unique_key_work(entity)?;
        if pending == PendingWord::Untouched {
            // Reserve deterministic deferred sealing/persistence work before
            // the first overlay write or event for this key.
            // Reserve cleanup before any corresponding state or event write.
            let schema = self.schema();
            let cleanup_gas = FIRST_BODY_TOUCH_CLEANUP_GAS
                + if schema.touched.is_empty()? {
                    BODY_TOUCHED_LENGTH_CLEANUP_GAS
                } else {
                    0
                };
            scope.deduct_explicit_gas(&self.storage, cleanup_gas)?;
            self.write_body_identity(locator, collection, entity_id)?;
            schema.touched.push(locator)?;
        }
        Ok(locator)
    }

    pub(crate) fn request_retirement(
        &self,
        scope: &ExecutionScope,
        partition: PartitionRef,
    ) -> Result<RetirementOutcome> {
        self.ensure_schema()?;
        let (_, key) =
            partition_collection_key(partition).map_err(|error| fatal(error.to_string()))?;
        let storage_key = B256::from(*key.as_bytes());
        if !self
            .schema()
            .pending_retirement
            .read(&storage_key)?
            .is_zero()
        {
            return Err(fatal("duplicate compressed-entity retirement request"));
        }
        for (collection, entity_id, _) in self.final_body_mutations()? {
            let domain = match collection {
                Collection::Tribute => CeDomain::Tribute,
                Collection::NodItem => CeDomain::NodItem,
                Collection::NodBucket => CeDomain::NodBucket,
            };
            if collection_key(domain, entity_id).map_err(|error| fatal(error.to_string()))? == key {
                return Err(fatal(
                    "collection retirement conflicts with an earlier entity mutation",
                ));
            }
        }
        if !scope.partition_present_verified(partition)? {
            return Ok(RetirementOutcome::NotPresent);
        }
        let schema = self.schema();
        let cleanup_gas = FIRST_RETIREMENT_TOUCH_CLEANUP_GAS
            + if schema.retirement_touched.is_empty()? {
                RETIREMENT_TOUCHED_LENGTH_CLEANUP_GAS
            } else {
                0
            };
        scope.deduct_explicit_gas(&self.storage, cleanup_gas)?;
        schema
            .pending_retirement
            .write(&storage_key, U256::from(1))?;
        let PartitionRef::TributeWwd(day) = partition;
        schema.retirement_touched.push(day.value())?;
        Ok(RetirementOutcome::Requested)
    }

    pub(crate) fn retirements(&self) -> Result<Vec<PartitionRef>> {
        self.validate_schema_for_read()?;
        let schema = self.schema();
        let days = schema.retirement_touched.read_all()?;
        let mut unique = BTreeSet::new();
        let mut retirements = Vec::with_capacity(days.len());
        for day in days {
            let partition =
                PartitionRef::TributeWwd(outbe_primitives::time::WorldwideDay::new(day));
            let (_, key) =
                partition_collection_key(partition).map_err(|error| fatal(error.to_string()))?;
            let storage_key = B256::from(*key.as_bytes());
            if !unique.insert(storage_key)
                || self.schema().pending_retirement.read(&storage_key)? != U256::from(1)
            {
                return Err(fatal("malformed compressed-entity retirement journal"));
            }
            retirements.push(partition);
        }
        Ok(retirements)
    }

    pub(crate) fn set_pending_prepared(
        &self,
        locator: B256,
        commitment: Commitment,
        stored_body: &[u8],
    ) -> Result<()> {
        self.ensure_schema()?;
        let schema = self.schema();
        if !self.has_body_identity(locator)? {
            return Err(fatal("pending Set was not prepared by first-touch logic"));
        }
        schema.pending_body.get_bytes(&locator).write(stored_body)?;
        schema
            .pending_word
            .write(&locator, PendingWord::Set(commitment).encode())
    }

    pub(crate) fn set_deleted_prepared(&self, locator: B256) -> Result<()> {
        self.ensure_schema()?;
        let schema = self.schema();
        if !self.has_body_identity(locator)? {
            return Err(fatal(
                "pending Deleted was not prepared by first-touch logic",
            ));
        }
        schema.pending_body.get_bytes(&locator).clear()?;
        schema
            .pending_word
            .write(&locator, PendingWord::Deleted.encode())
    }

    pub(crate) fn apply_index_add(
        &self,
        scope: &ExecutionScope,
        record: &IndexRecord,
    ) -> Result<()> {
        let current = self.validate_or_prepare_delta(scope, record)?;
        let next = match current {
            DeltaStatus::NeverTouched | DeltaStatus::NoChangeTouched => DeltaStatus::Added,
            DeltaStatus::Removed => DeltaStatus::NoChangeTouched,
            DeltaStatus::Added => {
                return Err(fatal(
                    "index add requested for an already-current membership",
                ));
            }
        };
        self.schema()
            .index_delta_word
            .write(&record.key(), next.encode())
    }

    pub(crate) fn apply_index_remove(
        &self,
        scope: &ExecutionScope,
        record: &IndexRecord,
    ) -> Result<()> {
        let current = self.validate_or_prepare_delta(scope, record)?;
        let next = match current {
            DeltaStatus::NeverTouched | DeltaStatus::NoChangeTouched => DeltaStatus::Removed,
            DeltaStatus::Added => DeltaStatus::NoChangeTouched,
            DeltaStatus::Removed => {
                return Err(fatal("index remove requested for a non-current membership"));
            }
        };
        self.schema()
            .index_delta_word
            .write(&record.key(), next.encode())
    }

    fn validate_or_prepare_delta(
        &self,
        scope: &ExecutionScope,
        record: &IndexRecord,
    ) -> Result<DeltaStatus> {
        self.ensure_schema()?;
        let key = record.key();
        let schema = self.schema();
        let current = DeltaStatus::decode(schema.index_delta_word.read(&key)?)?;
        let stored = schema.index_delta_record.get_bytes(&key).read()?;
        if current == DeltaStatus::NeverTouched {
            if !stored.is_empty() {
                return Err(fatal("untouched index delta has residual record"));
            }
            let cleanup_gas = FIRST_INDEX_TOUCH_CLEANUP_GAS
                + if schema.touched_index_deltas.is_empty()? {
                    INDEX_TOUCHED_LENGTH_CLEANUP_GAS
                } else {
                    0
                };
            scope.deduct_explicit_gas(&self.storage, cleanup_gas)?;
            schema
                .index_delta_record
                .get_bytes(&key)
                .write(&record.encode())?;
            schema.touched_index_deltas.push(key)?;
        } else if stored != record.encode() || IndexRecord::decode(&stored)?.key() != key {
            return Err(fatal("compressed-entity index record/hash mismatch"));
        }
        Ok(current)
    }

    pub(crate) fn index_deltas(&self) -> Result<Vec<(IndexRecord, DeltaStatus)>> {
        self.validate_schema_for_read()?;
        let schema = self.schema();
        let keys = schema.touched_index_deltas.read_all()?;
        let mut unique = BTreeSet::new();
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if !unique.insert(key) {
                return Err(fatal("duplicate compressed-entity touched index key"));
            }
            let status = DeltaStatus::decode(schema.index_delta_word.read(&key)?)?;
            if status == DeltaStatus::NeverTouched {
                return Err(fatal("touched index key has zero status"));
            }
            let bytes = schema.index_delta_record.get_bytes(&key).read()?;
            let record = IndexRecord::decode(&bytes)?;
            if record.key() != key {
                return Err(fatal("compressed-entity touched index hash mismatch"));
            }
            records.push((record, status));
        }
        Ok(records)
    }

    pub(crate) fn assert_clean_begin(&self) -> Result<()> {
        self.ensure_schema()?;
        let schema = self.schema();
        if !schema.reserved_2.read()?.is_zero() || !schema.reserved_3.read()?.is_zero() {
            return Err(fatal(
                "compressed-entity reserved schema slots are non-zero",
            ));
        }
        if !schema.touched.is_empty()?
            || !schema.touched_index_deltas.is_empty()?
            || !schema.retirement_touched.is_empty()?
        {
            return Err(fatal(
                "compressed-entity block overlay is dirty at begin_block",
            ));
        }
        Ok(())
    }

    pub(crate) fn final_body_mutations(
        &self,
    ) -> Result<Vec<(Collection, WwdEntityId, Option<Commitment>)>> {
        self.validate_schema_for_read()?;
        let schema = self.schema();
        let locators = schema.touched.read_all()?;
        let mut unique_locators = BTreeSet::new();
        let mut unique_identities = BTreeSet::new();
        let mut mutations = Vec::with_capacity(locators.len());
        for locator in locators {
            if !unique_locators.insert(locator) {
                return Err(fatal("duplicate compressed-entity touched body locator"));
            }
            let (collection, entity_id) = self
                .read_body_identity(locator)?
                .ok_or_else(|| fatal("touched compressed-entity body has no identity"))?;
            if body_locator(collection, entity_id)? != locator {
                return Err(fatal("compressed-entity touched body locator mismatch"));
            }
            if !unique_identities.insert((collection.id(), entity_id)) {
                return Err(fatal("duplicate compressed-entity touched identity"));
            }
            let final_leaf = match PendingWord::decode(schema.pending_word.read(&locator)?)? {
                PendingWord::Set(commitment) => Some(commitment),
                PendingWord::Deleted => None,
                PendingWord::Untouched => {
                    return Err(fatal("touched compressed-entity body is Untouched"));
                }
            };
            mutations.push((collection, entity_id, final_leaf));
        }
        Ok(mutations)
    }

    pub(crate) fn cleanup(&self) -> Result<()> {
        self.validate_schema_for_read()?;
        let schema = self.schema();
        let body_keys = schema.touched.read_all()?;
        let mut unique_bodies = BTreeSet::new();
        for locator in &body_keys {
            if !unique_bodies.insert(*locator) {
                return Err(fatal("duplicate compressed-entity touched body locator"));
            }
            let (collection, entity_id) = self
                .read_body_identity(*locator)?
                .ok_or_else(|| fatal("compressed-entity cleanup body has no identity"))?;
            if body_locator(collection, entity_id)? != *locator {
                return Err(fatal("compressed-entity cleanup body locator mismatch"));
            }
            let pending = PendingWord::decode(schema.pending_word.read(locator)?)?;
            let body = schema.pending_body.get_bytes(locator).read()?;
            match pending {
                PendingWord::Set(_) if body.is_empty() => {
                    return Err(fatal("compressed-entity cleanup Set entry has no body"));
                }
                PendingWord::Deleted if !body.is_empty() => {
                    return Err(fatal(
                        "compressed-entity cleanup Deleted entry retains body",
                    ));
                }
                PendingWord::Untouched => {
                    return Err(fatal("compressed-entity cleanup reached untouched body"));
                }
                _ => {}
            }
            schema.pending_body.get_bytes(locator).clear()?;
            self.clear_body_identity(*locator)?;
            schema.pending_word.write(locator, U256::ZERO)?;
        }

        let index_keys = schema.touched_index_deltas.read_all()?;
        let mut unique_indexes = BTreeSet::new();
        for key in &index_keys {
            if !unique_indexes.insert(*key) {
                return Err(fatal("duplicate compressed-entity touched index key"));
            }
            let status = DeltaStatus::decode(schema.index_delta_word.read(key)?)?;
            if status == DeltaStatus::NeverTouched {
                return Err(fatal("compressed-entity cleanup reached untouched index"));
            }
            let record = schema.index_delta_record.get_bytes(key).read()?;
            if IndexRecord::decode(&record)?.key() != *key {
                return Err(fatal("compressed-entity cleanup index hash mismatch"));
            }
            schema.index_delta_record.get_bytes(key).clear()?;
            schema.index_delta_word.write(key, U256::ZERO)?;
        }

        let retirement_days = schema.retirement_touched.read_all()?;
        let mut unique_retirements = BTreeSet::new();
        for day in &retirement_days {
            let partition =
                PartitionRef::TributeWwd(outbe_primitives::time::WorldwideDay::new(*day));
            let (_, key) =
                partition_collection_key(partition).map_err(|error| fatal(error.to_string()))?;
            let storage_key = B256::from(*key.as_bytes());
            if !unique_retirements.insert(storage_key)
                || schema.pending_retirement.read(&storage_key)? != U256::from(1)
            {
                return Err(fatal("malformed retirement journal during cleanup"));
            }
            schema.pending_retirement.write(&storage_key, U256::ZERO)?;
        }

        if !body_keys.is_empty() {
            schema.touched.clear()?;
        }
        if !index_keys.is_empty() {
            schema.touched_index_deltas.clear()?;
        }
        if !retirement_days.is_empty() {
            schema.retirement_touched.clear()?;
        }

        if !schema.touched.is_empty()?
            || !schema.touched_index_deltas.is_empty()?
            || !schema.retirement_touched.is_empty()?
        {
            return Err(fatal(
                "compressed-entity cleanup left non-empty touched lists",
            ));
        }
        for locator in body_keys {
            if !schema.pending_word.read(&locator)?.is_zero()
                || !schema.pending_body.get_bytes(&locator).is_empty()?
                || self.has_body_identity(locator)?
            {
                return Err(fatal(
                    "compressed-entity body cleanup post-condition failed",
                ));
            }
        }
        for key in index_keys {
            if !schema.index_delta_word.read(&key)?.is_zero()
                || !schema.index_delta_record.get_bytes(&key).is_empty()?
            {
                return Err(fatal(
                    "compressed-entity index cleanup post-condition failed",
                ));
            }
        }
        for storage_key in unique_retirements {
            if !schema.pending_retirement.read(&storage_key)?.is_zero() {
                return Err(fatal(
                    "compressed-entity retirement cleanup post-condition failed",
                ));
            }
        }
        Ok(())
    }
}

fn fatal(message: impl Into<String>) -> PrecompileError {
    PrecompileError::Fatal(message.into())
}
