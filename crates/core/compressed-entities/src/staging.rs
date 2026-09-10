//! Immutable speculative tree batches and exact-parent staging views.
//!
//! The types in this module deliberately model CKB store records instead of a
//! generic tree backend. Candidate writes are ordered, immutable once frozen,
//! and never reach the finalized MDBX environment through this API.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use outbe_sparse_merkle_tree_v061::{
    error::Error as VendorError,
    merge::MergeValue as VendorMergeValue,
    traits::{StoreReadOps, StoreWriteOps},
    BranchKey as VendorBranchKey, BranchNode as VendorBranchNode, H256,
};
use thiserror::Error;

use crate::persistence::{
    BranchKey, BranchNode, ExactParentIdentity, FieldValue, FinalizedMarker, LeafValue, MergeValue,
    PersistenceError, TreeKey, TreeNamespace,
};
use crate::{
    collection::{collection_root, sealed_root},
    sharding::{aggregate_b256_shard_roots, shard_index},
    smt::TreeKey as SmtTreeKey,
    CeDomain, CollectionKey,
};

pub type ShardIndex = u32;

/// A staged store mutation. Deletes are represented only in candidate memory;
/// finalized MDBX applies them by removing the corresponding record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeChange<T> {
    Set(T),
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalShardBatch {
    pub(crate) parent_shard_root: B256,
    pub(crate) new_shard_root: B256,
    pub(crate) branch_changes: BTreeMap<BranchKey, TreeChange<BranchNode>>,
    pub(crate) leaf_changes: BTreeMap<TreeKey, TreeChange<LeafValue>>,
}

impl ProvisionalShardBatch {
    pub(crate) fn new(
        parent_shard_root: B256,
        new_shard_root: B256,
        branch_changes: BTreeMap<BranchKey, TreeChange<BranchNode>>,
        leaf_changes: BTreeMap<TreeKey, TreeChange<LeafValue>>,
    ) -> Result<Self, StagingError> {
        crate::persistence::validate_root(parent_shard_root)?;
        crate::persistence::validate_root(new_shard_root)?;
        if parent_shard_root == new_shard_root {
            return Err(StagingError::InvalidShardEnvelope(
                "changed shard roots must differ",
            ));
        }
        if branch_changes.is_empty() && leaf_changes.is_empty() {
            return Err(StagingError::InvalidShardEnvelope(
                "changed shard must contain effective records",
            ));
        }
        Ok(Self {
            parent_shard_root,
            new_shard_root,
            branch_changes,
            leaf_changes,
        })
    }

    #[must_use]
    pub fn branch_change_count(&self) -> usize {
        self.branch_changes.len()
    }

    #[must_use]
    pub fn leaf_change_count(&self) -> usize {
        self.leaf_changes.len()
    }
}

/// ADR-009's canonical shard-set payload reused inside one ADR-010 collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalShardSetBatch {
    pub(crate) shard_count: u32,
    pub(crate) parent_shard_top_root: B256,
    pub(crate) new_shard_top_root: B256,
    pub(crate) parent_shard_roots: Vec<B256>,
    pub(crate) new_shard_roots: Vec<B256>,
    pub(crate) changed_shards: BTreeMap<ShardIndex, ProvisionalShardBatch>,
    pub(crate) encoded_size: usize,
}

impl ProvisionalShardSetBatch {
    pub(crate) fn new(
        shard_count: u32,
        parent_shard_top_root: B256,
        new_shard_top_root: B256,
        parent_shard_roots: Vec<B256>,
        new_shard_roots: Vec<B256>,
        changed_shards: BTreeMap<ShardIndex, ProvisionalShardBatch>,
    ) -> Result<Self, StagingError> {
        validate_shard_envelope(
            shard_count,
            parent_shard_top_root,
            new_shard_top_root,
            &parent_shard_roots,
            &new_shard_roots,
            &changed_shards,
        )?;
        let encoded_size = encoded_shard_set_size(
            shard_count,
            &parent_shard_roots,
            &new_shard_roots,
            &changed_shards,
        )?;
        Ok(Self {
            shard_count,
            parent_shard_top_root,
            new_shard_top_root,
            parent_shard_roots,
            new_shard_roots,
            changed_shards,
            encoded_size,
        })
    }

    #[must_use]
    pub const fn shard_count(&self) -> u32 {
        self.shard_count
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionBatch {
    pub(crate) domain_id: u16,
    pub(crate) parent_collection_root: Option<B256>,
    pub(crate) new_collection_root: B256,
    pub(crate) shard_set: ProvisionalShardSetBatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementBatch {
    pub(crate) domain_id: u16,
    pub(crate) parent_collection_root: B256,
    pub(crate) parent_shard_roots: Vec<B256>,
}

impl RetirementBatch {
    pub(crate) fn new(
        domain: CeDomain,
        key: CollectionKey,
        parent_collection_root: B256,
        parent_shard_roots: Vec<B256>,
    ) -> Result<Self, StagingError> {
        if domain != CeDomain::Tribute || parent_shard_roots.len() != domain.shard_count() as usize
        {
            return Err(StagingError::InvalidCatalogEnvelope(
                "only a complete Tribute collection may retire",
            ));
        }
        let top = aggregate_b256_shard_roots(&parent_shard_roots)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid retirement shard roots"))?;
        if collection_root(domain, key, top)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid retirement collection"))?
            != parent_collection_root
        {
            return Err(StagingError::InvalidCatalogEnvelope(
                "retirement parent collection root mismatch",
            ));
        }
        Ok(Self {
            domain_id: domain.id(),
            parent_collection_root,
            parent_shard_roots,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectionOperation {
    Mutate(CollectionBatch),
    Retire(RetirementBatch),
}

impl CollectionOperation {
    pub(crate) fn mutation(&self) -> Option<&CollectionBatch> {
        match self {
            Self::Mutate(batch) => Some(batch),
            Self::Retire(_) => None,
        }
    }
}

impl CollectionBatch {
    pub(crate) fn new(
        domain: CeDomain,
        key: CollectionKey,
        parent_collection_root: Option<B256>,
        new_collection_root: B256,
        shard_set: ProvisionalShardSetBatch,
    ) -> Result<Self, StagingError> {
        if shard_set.shard_count != domain.shard_count() {
            return Err(StagingError::InvalidCatalogEnvelope(
                "collection shard count does not match domain topology",
            ));
        }
        if let Some(parent) = parent_collection_root {
            let expected = collection_root(domain, key, shard_set.parent_shard_top_root)
                .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid parent collection"))?;
            if parent != expected {
                return Err(StagingError::InvalidCatalogEnvelope(
                    "parent collection root mismatch",
                ));
            }
        } else if shard_set
            .parent_shard_roots
            .iter()
            .any(|root| *root != B256::ZERO)
        {
            return Err(StagingError::InvalidCatalogEnvelope(
                "absent collection must start from all-zero shard roots",
            ));
        }
        let expected = collection_root(domain, key, shard_set.new_shard_top_root)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid new collection"))?;
        if expected != new_collection_root || shard_set.changed_shards.is_empty() {
            return Err(StagingError::InvalidCatalogEnvelope(
                "changed collection root or shard payload mismatch",
            ));
        }
        Ok(Self {
            domain_id: domain.id(),
            parent_collection_root,
            new_collection_root,
            shard_set,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalCatalogBatch {
    pub(crate) parent_catalog_root: B256,
    pub(crate) new_catalog_root: B256,
    pub(crate) branch_changes: BTreeMap<BranchKey, TreeChange<BranchNode>>,
    pub(crate) leaf_changes: BTreeMap<TreeKey, TreeChange<LeafValue>>,
}

macro_rules! tree_batch_accessors {
    () => {
        #[must_use]
        pub const fn block_number(&self) -> u64 {
            self.block_number
        }
        #[must_use]
        pub const fn parent_block_hash(&self) -> B256 {
            self.parent_block_hash
        }
        #[must_use]
        pub const fn parent_root(&self) -> B256 {
            self.parent_r_sealed
        }
        #[must_use]
        pub const fn new_root(&self) -> B256 {
            self.new_r_sealed
        }
        #[must_use]
        pub fn changed_shard_count(&self) -> usize {
            self.changed_collections
                .values()
                .filter_map(CollectionOperation::mutation)
                .map(|batch| batch.shard_set.changed_shards.len())
                .sum()
        }
        #[must_use]
        pub fn branch_change_count(&self) -> usize {
            self.changed_collections
                .values()
                .filter_map(CollectionOperation::mutation)
                .flat_map(|batch| batch.shard_set.changed_shards.values())
                .map(ProvisionalShardBatch::branch_change_count)
                .sum::<usize>()
                + self
                    .catalog_batch
                    .as_ref()
                    .map_or(0, |batch| batch.branch_changes.len())
        }
        #[must_use]
        pub fn leaf_change_count(&self) -> usize {
            self.changed_collections
                .values()
                .filter_map(CollectionOperation::mutation)
                .flat_map(|batch| batch.shard_set.changed_shards.values())
                .map(ProvisionalShardBatch::leaf_change_count)
                .sum::<usize>()
                + self
                    .catalog_batch
                    .as_ref()
                    .map_or(0, |batch| batch.leaf_changes.len())
        }
        #[must_use]
        pub const fn encoded_size(&self) -> usize {
            self.encoded_size
        }
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalTreeBatch {
    pub(crate) block_number: u64,
    pub(crate) parent_block_hash: B256,
    pub(crate) parent_r_sealed: B256,
    pub(crate) new_r_sealed: B256,
    pub(crate) parent_catalog_root: B256,
    pub(crate) new_catalog_root: B256,
    pub(crate) changed_collections: BTreeMap<CollectionKey, CollectionOperation>,
    pub(crate) catalog_batch: Option<ProvisionalCatalogBatch>,
    pub(crate) encoded_size: usize,
}

impl ProvisionalTreeBatch {
    /// Builds the ordinary no-effective-change candidate for an exact parent.
    pub fn new_identity(
        block_number: u64,
        parent_block_hash: B256,
        parent_catalog_root: B256,
    ) -> Result<Self, StagingError> {
        let parent_r_sealed = sealed_root(parent_catalog_root)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid identity parent"))?;
        Self::new(
            block_number,
            parent_block_hash,
            parent_r_sealed,
            parent_r_sealed,
            parent_catalog_root,
            parent_catalog_root,
            BTreeMap::new(),
            None,
        )
    }

    /// Synthetic single-collection fixture retained only for historical tests
    /// and benchmarks. It is deliberately not part of the public API.
    pub(crate) fn new_fixture_single_collection(
        block_number: u64,
        parent_block_hash: B256,
        _parent_root: B256,
        new_root: B256,
        branch_changes: BTreeMap<BranchKey, TreeChange<BranchNode>>,
        leaf_changes: BTreeMap<TreeKey, TreeChange<LeafValue>>,
    ) -> Result<Self, StagingError> {
        let parent_catalog_root = B256::ZERO;
        let parent_r_sealed = sealed_root(parent_catalog_root)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid benchmark parent"))?;
        if branch_changes.is_empty() && leaf_changes.is_empty() {
            return Self::new_identity(block_number, parent_block_hash, parent_catalog_root);
        }

        let domain = CeDomain::Tribute;
        let collection_key = CollectionKey::try_from(B256::from([0_u8; 32]))
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid benchmark collection"))?;
        let mut parent_shard_roots = vec![B256::ZERO; domain.shard_count() as usize];
        let mut new_shard_roots = parent_shard_roots.clone();
        new_shard_roots[0] = new_root;
        let parent_shard_top_root = aggregate_b256_shard_roots(&parent_shard_roots)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid benchmark shard roots"))?;
        let new_shard_top_root = aggregate_b256_shard_roots(&new_shard_roots)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid benchmark shard roots"))?;
        let shard = ProvisionalShardBatch::new(B256::ZERO, new_root, branch_changes, leaf_changes)?;
        let shard_set = ProvisionalShardSetBatch::new(
            domain.shard_count(),
            parent_shard_top_root,
            new_shard_top_root,
            std::mem::take(&mut parent_shard_roots),
            new_shard_roots,
            BTreeMap::from([(0, shard)]),
        )?;
        let new_collection_root = collection_root(domain, collection_key, new_shard_top_root)
            .map_err(|_| {
                StagingError::InvalidCatalogEnvelope("invalid benchmark collection root")
            })?;
        let collection = CollectionOperation::Mutate(CollectionBatch::new(
            domain,
            collection_key,
            None,
            new_collection_root,
            shard_set,
        )?);
        let catalog_key = TreeKey::try_from(B256::from(*collection_key.as_bytes()))?;
        let catalog_value = LeafValue::try_from(new_collection_root)?;
        let new_catalog_root = new_root;
        let catalog_batch = ProvisionalCatalogBatch {
            parent_catalog_root,
            new_catalog_root,
            branch_changes: BTreeMap::new(),
            leaf_changes: BTreeMap::from([(catalog_key, TreeChange::Set(catalog_value))]),
        };
        let new_r_sealed = sealed_root(new_catalog_root)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid benchmark root"))?;
        Self::new(
            block_number,
            parent_block_hash,
            parent_r_sealed,
            new_r_sealed,
            parent_catalog_root,
            new_catalog_root,
            BTreeMap::from([(collection_key, collection)]),
            Some(catalog_batch),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        block_number: u64,
        parent_block_hash: B256,
        parent_r_sealed: B256,
        new_r_sealed: B256,
        parent_catalog_root: B256,
        new_catalog_root: B256,
        changed_collections: BTreeMap<CollectionKey, CollectionOperation>,
        catalog_batch: Option<ProvisionalCatalogBatch>,
    ) -> Result<Self, StagingError> {
        validate_catalog_envelope(
            parent_r_sealed,
            new_r_sealed,
            parent_catalog_root,
            new_catalog_root,
            &changed_collections,
            catalog_batch.as_ref(),
        )?;
        let mut batch = Self {
            block_number,
            parent_block_hash,
            parent_r_sealed,
            new_r_sealed,
            parent_catalog_root,
            new_catalog_root,
            changed_collections,
            catalog_batch,
            encoded_size: 0,
        };
        batch.encoded_size = canonical_tree_bytes(&batch, B256::ZERO)?.len();
        Ok(batch)
    }

    #[must_use]
    pub fn freeze(self, block_hash: B256) -> StagedTreeBatch {
        StagedTreeBatch {
            block_number: self.block_number,
            block_hash,
            parent_block_hash: self.parent_block_hash,
            parent_r_sealed: self.parent_r_sealed,
            new_r_sealed: self.new_r_sealed,
            parent_catalog_root: self.parent_catalog_root,
            new_catalog_root: self.new_catalog_root,
            changed_collections: self.changed_collections,
            catalog_batch: self.catalog_batch,
            encoded_size: self.encoded_size,
        }
    }

    tree_batch_accessors!();
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedTreeBatch {
    pub(crate) block_number: u64,
    pub(crate) block_hash: B256,
    pub(crate) parent_block_hash: B256,
    pub(crate) parent_r_sealed: B256,
    pub(crate) new_r_sealed: B256,
    pub(crate) parent_catalog_root: B256,
    pub(crate) new_catalog_root: B256,
    pub(crate) changed_collections: BTreeMap<CollectionKey, CollectionOperation>,
    pub(crate) catalog_batch: Option<ProvisionalCatalogBatch>,
    pub(crate) encoded_size: usize,
}

impl StagedTreeBatch {
    #[must_use]
    pub const fn marker(&self, commitment_scheme_version: u32) -> FinalizedMarker {
        FinalizedMarker {
            commitment_scheme_version,
            height: self.block_number,
            block_hash: self.block_hash,
            parent_block_hash: self.parent_block_hash,
            parent_root: self.parent_r_sealed,
            new_root: self.new_r_sealed,
        }
    }

    pub fn validate_encoded_size(&self) -> Result<(), StagingError> {
        validate_catalog_envelope(
            self.parent_r_sealed,
            self.new_r_sealed,
            self.parent_catalog_root,
            self.new_catalog_root,
            &self.changed_collections,
            self.catalog_batch.as_ref(),
        )?;
        let actual = canonical_staged_tree_bytes(self)?.len();
        if actual != self.encoded_size {
            return Err(StagingError::EncodedSizeMismatch {
                declared: self.encoded_size,
                actual,
            });
        }
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, StagingError> {
        canonical_staged_tree_bytes(self)
    }

    tree_batch_accessors!();

    #[must_use]
    pub const fn block_hash(&self) -> B256 {
        self.block_hash
    }
}

fn validate_shard_envelope(
    shard_count: u32,
    parent_root: B256,
    new_root: B256,
    parent_shard_roots: &[B256],
    new_shard_roots: &[B256],
    changed_shards: &BTreeMap<ShardIndex, ProvisionalShardBatch>,
) -> Result<(), StagingError> {
    let expected_len = usize::try_from(shard_count)
        .map_err(|_| StagingError::InvalidShardEnvelope("shard count is not representable"))?;
    if shard_count == 0 || shard_count > 32 || !shard_count.is_power_of_two() {
        return Err(StagingError::InvalidShardEnvelope("invalid shard count"));
    }
    if parent_shard_roots.len() != expected_len || new_shard_roots.len() != expected_len {
        return Err(StagingError::InvalidShardEnvelope(
            "root vector length mismatch",
        ));
    }
    let parent = aggregate_b256_roots(parent_shard_roots)?;
    let new = aggregate_b256_roots(new_shard_roots)?;
    if parent != parent_root || new != new_root {
        return Err(StagingError::InvalidShardEnvelope(
            "aggregate root mismatch",
        ));
    }
    for index in 0..shard_count {
        let position = usize::try_from(index)
            .map_err(|_| StagingError::InvalidShardEnvelope("shard index overflow"))?;
        let changed = parent_shard_roots[position] != new_shard_roots[position];
        match (changed, changed_shards.get(&index)) {
            (true, Some(batch)) => {
                if batch.parent_shard_root != parent_shard_roots[position]
                    || batch.new_shard_root != new_shard_roots[position]
                {
                    return Err(StagingError::InvalidShardEnvelope(
                        "changed shard root mismatch",
                    ));
                }
                for key in batch.leaf_changes.keys() {
                    let smt_key = SmtTreeKey::from_be_bytes(key.encode())
                        .map_err(|_| StagingError::InvalidShardEnvelope("invalid leaf key"))?;
                    if shard_index(smt_key, shard_count).map_err(|_| {
                        StagingError::InvalidShardEnvelope("invalid shard derivation")
                    })? != index
                    {
                        return Err(StagingError::InvalidShardEnvelope("misderived leaf shard"));
                    }
                }
            }
            (false, None) => {}
            (true, None) => {
                return Err(StagingError::InvalidShardEnvelope("missing changed shard"));
            }
            (false, Some(_)) => {
                return Err(StagingError::InvalidShardEnvelope(
                    "unchanged shard included",
                ));
            }
        }
    }
    if changed_shards.keys().any(|index| *index >= shard_count) {
        return Err(StagingError::InvalidShardEnvelope(
            "shard index out of range",
        ));
    }
    Ok(())
}

fn aggregate_b256_roots(roots: &[B256]) -> Result<B256, StagingError> {
    aggregate_b256_shard_roots(roots)
        .map_err(|_| StagingError::InvalidShardEnvelope("invalid shard root aggregate"))
}

fn validate_catalog_envelope(
    parent_r_sealed: B256,
    new_r_sealed: B256,
    parent_catalog_root: B256,
    new_catalog_root: B256,
    changed_collections: &BTreeMap<CollectionKey, CollectionOperation>,
    catalog_batch: Option<&ProvisionalCatalogBatch>,
) -> Result<(), StagingError> {
    if sealed_root(parent_catalog_root)
        .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid parent sealed-root wrapper"))?
        != parent_r_sealed
        || sealed_root(new_catalog_root)
            .map_err(|_| StagingError::InvalidCatalogEnvelope("invalid new sealed-root wrapper"))?
            != new_r_sealed
    {
        return Err(StagingError::InvalidCatalogEnvelope(
            "sealed-root wrapper mismatch",
        ));
    }
    match (changed_collections.is_empty(), catalog_batch) {
        (true, None) if parent_catalog_root == new_catalog_root => return Ok(()),
        (true, _) => {
            return Err(StagingError::InvalidCatalogEnvelope(
                "identity candidate contains catalog changes",
            ));
        }
        (false, None) => {
            return Err(StagingError::InvalidCatalogEnvelope(
                "changed collections require one aggregate catalog batch",
            ));
        }
        (false, Some(batch)) => {
            if batch.parent_catalog_root != parent_catalog_root
                || batch.new_catalog_root != new_catalog_root
                || parent_catalog_root == new_catalog_root
            {
                return Err(StagingError::InvalidCatalogEnvelope(
                    "catalog batch root mismatch",
                ));
            }
            if batch.leaf_changes.len() != changed_collections.len() {
                return Err(StagingError::InvalidCatalogEnvelope(
                    "catalog leaf changes do not cover changed collections",
                ));
            }
            for (key, operation) in changed_collections {
                let tree_key = TreeKey::try_from(B256::from(*key.as_bytes()))?;
                match operation {
                    CollectionOperation::Mutate(collection) => {
                        let domain = CeDomain::try_from(collection.domain_id).map_err(|_| {
                            StagingError::InvalidCatalogEnvelope("unknown collection domain")
                        })?;
                        if collection.shard_set.shard_count != domain.shard_count() {
                            return Err(StagingError::InvalidCatalogEnvelope(
                                "collection shard count does not match domain topology",
                            ));
                        }
                        validate_shard_envelope(
                            collection.shard_set.shard_count,
                            collection.shard_set.parent_shard_top_root,
                            collection.shard_set.new_shard_top_root,
                            &collection.shard_set.parent_shard_roots,
                            &collection.shard_set.new_shard_roots,
                            &collection.shard_set.changed_shards,
                        )?;
                        let expected_parent = collection
                            .parent_collection_root
                            .map(|_| {
                                collection_root(
                                    domain,
                                    *key,
                                    collection.shard_set.parent_shard_top_root,
                                )
                            })
                            .transpose()
                            .map_err(|_| {
                                StagingError::InvalidCatalogEnvelope("invalid parent collection")
                            })?;
                        if expected_parent != collection.parent_collection_root
                            || (collection.parent_collection_root.is_none()
                                && collection
                                    .shard_set
                                    .parent_shard_roots
                                    .iter()
                                    .any(|root| *root != B256::ZERO))
                            || collection_root(
                                domain,
                                *key,
                                collection.shard_set.new_shard_top_root,
                            )
                            .map_err(|_| {
                                StagingError::InvalidCatalogEnvelope("invalid new collection")
                            })? != collection.new_collection_root
                        {
                            return Err(StagingError::InvalidCatalogEnvelope(
                                "collection root mismatch",
                            ));
                        }
                        let expected = LeafValue::try_from(collection.new_collection_root)?;
                        if batch.leaf_changes.get(&tree_key) != Some(&TreeChange::Set(expected)) {
                            return Err(StagingError::InvalidCatalogEnvelope(
                                "catalog leaf is not the changed collection root",
                            ));
                        }
                    }
                    CollectionOperation::Retire(retirement) => {
                        let domain = CeDomain::try_from(retirement.domain_id).map_err(|_| {
                            StagingError::InvalidCatalogEnvelope("unknown retirement domain")
                        })?;
                        RetirementBatch::new(
                            domain,
                            *key,
                            retirement.parent_collection_root,
                            retirement.parent_shard_roots.clone(),
                        )?;
                        if batch.leaf_changes.get(&tree_key) != Some(&TreeChange::Delete) {
                            return Err(StagingError::InvalidCatalogEnvelope(
                                "retired catalog leaf is not deleted",
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn be4_len(len: usize) -> Result<[u8; 4], StagingError> {
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| StagingError::EncodedSizeOverflow)
}

fn append_change_maps(
    bytes: &mut Vec<u8>,
    branch_changes: &BTreeMap<BranchKey, TreeChange<BranchNode>>,
    leaf_changes: &BTreeMap<TreeKey, TreeChange<LeafValue>>,
) -> Result<(), StagingError> {
    bytes.extend_from_slice(&be4_len(branch_changes.len())?);
    for (key, change) in branch_changes {
        bytes.extend_from_slice(&key.encode());
        match change {
            TreeChange::Set(node) => {
                bytes.push(1);
                let encoded = node.encode();
                bytes.extend_from_slice(&be4_len(encoded.len())?);
                bytes.extend_from_slice(&encoded);
            }
            TreeChange::Delete => bytes.push(0),
        }
    }
    bytes.extend_from_slice(&be4_len(leaf_changes.len())?);
    for (key, change) in leaf_changes {
        bytes.extend_from_slice(&key.encode());
        match change {
            TreeChange::Set(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.encode());
            }
            TreeChange::Delete => bytes.push(0),
        }
    }
    Ok(())
}

fn append_shard_set(
    bytes: &mut Vec<u8>,
    shard_set: &ProvisionalShardSetBatch,
) -> Result<(), StagingError> {
    bytes.extend_from_slice(&shard_set.shard_count.to_be_bytes());
    bytes.extend_from_slice(shard_set.parent_shard_top_root.as_slice());
    bytes.extend_from_slice(shard_set.new_shard_top_root.as_slice());
    for root in &shard_set.parent_shard_roots {
        bytes.extend_from_slice(root.as_slice());
    }
    for root in &shard_set.new_shard_roots {
        bytes.extend_from_slice(root.as_slice());
    }
    bytes.extend_from_slice(&be4_len(shard_set.changed_shards.len())?);
    for (index, shard) in &shard_set.changed_shards {
        bytes.extend_from_slice(&index.to_be_bytes());
        bytes.extend_from_slice(shard.parent_shard_root.as_slice());
        bytes.extend_from_slice(shard.new_shard_root.as_slice());
        append_change_maps(bytes, &shard.branch_changes, &shard.leaf_changes)?;
    }
    bytes.extend_from_slice(
        &u64::try_from(shard_set.encoded_size)
            .map_err(|_| StagingError::EncodedSizeOverflow)?
            .to_be_bytes(),
    );
    Ok(())
}

fn canonical_tree_bytes(
    batch: &ProvisionalTreeBatch,
    block_hash: B256,
) -> Result<Vec<u8>, StagingError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&batch.block_number.to_be_bytes());
    bytes.extend_from_slice(block_hash.as_slice());
    bytes.extend_from_slice(batch.parent_block_hash.as_slice());
    bytes.extend_from_slice(batch.parent_r_sealed.as_slice());
    bytes.extend_from_slice(batch.new_r_sealed.as_slice());
    bytes.extend_from_slice(batch.parent_catalog_root.as_slice());
    bytes.extend_from_slice(batch.new_catalog_root.as_slice());
    bytes.extend_from_slice(&be4_len(batch.changed_collections.len())?);
    for (key, operation) in &batch.changed_collections {
        bytes.extend_from_slice(key.as_bytes());
        match operation {
            CollectionOperation::Mutate(collection) => {
                bytes.push(0);
                bytes.extend_from_slice(&collection.domain_id.to_be_bytes());
                match collection.parent_collection_root {
                    Some(root) => {
                        bytes.push(1);
                        bytes.extend_from_slice(root.as_slice());
                    }
                    None => bytes.push(0),
                }
                bytes.extend_from_slice(collection.new_collection_root.as_slice());
                append_shard_set(&mut bytes, &collection.shard_set)?;
            }
            CollectionOperation::Retire(retirement) => {
                bytes.push(1);
                bytes.extend_from_slice(&retirement.domain_id.to_be_bytes());
                bytes.extend_from_slice(retirement.parent_collection_root.as_slice());
                bytes.extend_from_slice(&be4_len(retirement.parent_shard_roots.len())?);
                for root in &retirement.parent_shard_roots {
                    bytes.extend_from_slice(root.as_slice());
                }
            }
        }
    }
    match &batch.catalog_batch {
        Some(catalog) => {
            bytes.push(1);
            bytes.extend_from_slice(catalog.parent_catalog_root.as_slice());
            bytes.extend_from_slice(catalog.new_catalog_root.as_slice());
            append_change_maps(&mut bytes, &catalog.branch_changes, &catalog.leaf_changes)?;
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(
        &u64::try_from(batch.encoded_size)
            .map_err(|_| StagingError::EncodedSizeOverflow)?
            .to_be_bytes(),
    );
    Ok(bytes)
}

fn canonical_staged_tree_bytes(batch: &StagedTreeBatch) -> Result<Vec<u8>, StagingError> {
    canonical_tree_bytes(
        &ProvisionalTreeBatch {
            block_number: batch.block_number,
            parent_block_hash: batch.parent_block_hash,
            parent_r_sealed: batch.parent_r_sealed,
            new_r_sealed: batch.new_r_sealed,
            parent_catalog_root: batch.parent_catalog_root,
            new_catalog_root: batch.new_catalog_root,
            changed_collections: batch.changed_collections.clone(),
            catalog_batch: batch.catalog_batch.clone(),
            encoded_size: batch.encoded_size,
        },
        batch.block_hash,
    )
}

fn encoded_shard_set_size(
    shard_count: u32,
    parent_roots: &[B256],
    new_roots: &[B256],
    changed_shards: &BTreeMap<ShardIndex, ProvisionalShardBatch>,
) -> Result<usize, StagingError> {
    if usize::try_from(shard_count).ok() != Some(parent_roots.len()) {
        return Err(StagingError::InvalidShardEnvelope(
            "root vector length mismatch",
        ));
    }
    let mut bytes = Vec::new();
    append_shard_set(
        &mut bytes,
        &ProvisionalShardSetBatch {
            shard_count,
            parent_shard_top_root: aggregate_b256_roots(parent_roots)?,
            new_shard_top_root: aggregate_b256_roots(new_roots)?,
            parent_shard_roots: parent_roots.to_vec(),
            new_shard_roots: new_roots.to_vec(),
            changed_shards: changed_shards.clone(),
            encoded_size: 0,
        },
    )?;
    let size = bytes.len();
    u64::try_from(size).map_err(|_| StagingError::EncodedSizeOverflow)?;
    Ok(size)
}

/// A consistent finalized read transaction used by one exact-parent view.
/// Implementations must return all reads from the same immutable snapshot.
pub trait FinalizedTreeSnapshot: Send {
    fn marker(&self) -> Result<FinalizedMarker, PersistenceError>;
    fn tree_root(&self, namespace: TreeNamespace) -> Result<Option<B256>, PersistenceError>;
    fn collection_has_records(&self, collection: CollectionKey) -> Result<bool, PersistenceError>;
    fn collection_root_count(&self, collection: CollectionKey) -> Result<usize, PersistenceError>;
    fn collection_leaf_count(&self, collection: CollectionKey) -> Result<usize, PersistenceError>;
    fn read_branch(
        &self,
        namespace: TreeNamespace,
        key: BranchKey,
    ) -> Result<Option<BranchNode>, PersistenceError>;
    fn read_leaf(
        &self,
        namespace: TreeNamespace,
        key: TreeKey,
    ) -> Result<Option<LeafValue>, PersistenceError>;
}

/// One exact finalized-parent view. Construction checks all identity fields,
/// including equality between the EVM-authoritative root and the MDBX marker.
#[derive(Clone)]
pub struct AuthenticatedCatalogView {
    snapshot: Arc<Mutex<Box<dyn FinalizedTreeSnapshot>>>,
    identity: ExactParentIdentity,
    catalog_root: B256,
}

impl std::fmt::Debug for AuthenticatedCatalogView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedCatalogView")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedCatalogView {
    pub fn open(
        snapshot: Box<dyn FinalizedTreeSnapshot>,
        required: ExactParentIdentity,
    ) -> Result<Self, StagingError> {
        let marker = snapshot.marker()?;
        marker.verify_exact_parent(required)?;
        let catalog_root = snapshot.tree_root(TreeNamespace::Catalog)?.ok_or(
            StagingError::InvalidCatalogEnvelope("catalog root is missing"),
        )?;
        if sealed_root(catalog_root).map_err(|_| {
            StagingError::InvalidCatalogEnvelope("invalid exact-parent catalog root")
        })? != required.root
        {
            return Err(StagingError::InvalidCatalogEnvelope(
                "exact-parent catalog root does not match authoritative sealed root",
            ));
        }
        Ok(Self {
            snapshot: Arc::new(Mutex::new(snapshot)),
            identity: required,
            catalog_root,
        })
    }

    #[must_use]
    pub const fn catalog_root(&self) -> B256 {
        self.catalog_root
    }

    #[must_use]
    pub const fn identity(&self) -> ExactParentIdentity {
        self.identity
    }

    pub fn tree_root(&self, namespace: TreeNamespace) -> Result<Option<B256>, StagingError> {
        self.snapshot
            .lock()
            .map_err(|_| StagingError::SnapshotLockPoisoned)?
            .tree_root(namespace)
            .map_err(Into::into)
    }

    pub fn collection_has_records(&self, collection: CollectionKey) -> Result<bool, StagingError> {
        self.snapshot
            .lock()
            .map_err(|_| StagingError::SnapshotLockPoisoned)?
            .collection_has_records(collection)
            .map_err(Into::into)
    }

    pub fn collection_root_count(&self, collection: CollectionKey) -> Result<usize, StagingError> {
        self.snapshot
            .lock()
            .map_err(|_| StagingError::SnapshotLockPoisoned)?
            .collection_root_count(collection)
            .map_err(Into::into)
    }

    /// Full-folds the persisted non-zero leaves for one collection inside this
    /// exact immutable snapshot. The count is authoritative CE materialization,
    /// never a Mongo/body-store count.
    pub fn collection_leaf_count(&self, collection: CollectionKey) -> Result<usize, StagingError> {
        self.snapshot
            .lock()
            .map_err(|_| StagingError::SnapshotLockPoisoned)?
            .collection_leaf_count(collection)
            .map_err(Into::into)
    }

    pub fn read_branch(
        &self,
        namespace: TreeNamespace,
        key: BranchKey,
    ) -> Result<Option<BranchNode>, StagingError> {
        self.snapshot
            .lock()
            .map_err(|_| StagingError::SnapshotLockPoisoned)?
            .read_branch(namespace, key)
            .map_err(Into::into)
    }

    pub fn read_leaf(
        &self,
        namespace: TreeNamespace,
        key: TreeKey,
    ) -> Result<Option<LeafValue>, StagingError> {
        self.snapshot
            .lock()
            .map_err(|_| StagingError::SnapshotLockPoisoned)?
            .read_leaf(namespace, key)
            .map_err(Into::into)
    }
}

/// CKB-compatible speculative store semantics: candidate writes shadow the
/// immutable exact-parent snapshot and remain confined to ordered maps.
#[derive(Debug)]
pub struct StagingCkbStore {
    base: AuthenticatedCatalogView,
    namespace: TreeNamespace,
    parent_root: B256,
    branch_changes: BTreeMap<BranchKey, TreeChange<BranchNode>>,
    leaf_changes: BTreeMap<TreeKey, TreeChange<LeafValue>>,
}

impl StoreReadOps<H256> for StagingCkbStore {
    fn get_branch(
        &self,
        branch_key: &VendorBranchKey,
    ) -> Result<Option<VendorBranchNode>, VendorError> {
        let key = from_vendor_branch_key(branch_key).map_err(vendor_store_error)?;
        Ok(self
            .read_branch(key)
            .map_err(vendor_store_error)?
            .map(to_vendor_branch_node))
    }

    fn get_leaf(&self, leaf_key: &H256) -> Result<Option<H256>, VendorError> {
        let key = from_vendor_tree_key(*leaf_key).map_err(vendor_store_error)?;
        self.read_leaf(key)
            .map_err(vendor_store_error)
            .map(|value| value.map(|leaf| H256::from(leaf.encode())))
    }
}

impl StoreWriteOps<H256> for StagingCkbStore {
    fn insert_branch(
        &mut self,
        branch_key: VendorBranchKey,
        branch: VendorBranchNode,
    ) -> Result<(), VendorError> {
        let key = from_vendor_branch_key(&branch_key).map_err(vendor_store_error)?;
        let node = from_vendor_branch_node(&branch).map_err(vendor_store_error)?;
        self.write_branch(key, node);
        Ok(())
    }

    fn insert_leaf(&mut self, leaf_key: H256, leaf: H256) -> Result<(), VendorError> {
        let key = from_vendor_tree_key(leaf_key).map_err(vendor_store_error)?;
        let value =
            LeafValue::try_from(B256::from(<[u8; 32]>::from(leaf))).map_err(vendor_store_error)?;
        self.write_leaf(key, value);
        Ok(())
    }

    fn remove_branch(&mut self, branch_key: &VendorBranchKey) -> Result<(), VendorError> {
        let key = from_vendor_branch_key(branch_key).map_err(vendor_store_error)?;
        self.delete_branch(key);
        Ok(())
    }

    fn remove_leaf(&mut self, leaf_key: &H256) -> Result<(), VendorError> {
        let key = from_vendor_tree_key(*leaf_key).map_err(vendor_store_error)?;
        self.delete_leaf(key);
        Ok(())
    }
}

fn from_vendor_tree_key(key: H256) -> Result<TreeKey, PersistenceError> {
    TreeKey::try_from(B256::from(<[u8; 32]>::from(key)))
}

fn from_vendor_branch_key(key: &VendorBranchKey) -> Result<BranchKey, PersistenceError> {
    BranchKey::new(key.height, B256::from(<[u8; 32]>::from(key.node_key)))
}

fn to_vendor_branch_node(node: BranchNode) -> VendorBranchNode {
    VendorBranchNode {
        left: to_vendor_merge_value(node.left),
        right: to_vendor_merge_value(node.right),
    }
}

fn from_vendor_branch_node(node: &VendorBranchNode) -> Result<BranchNode, PersistenceError> {
    Ok(BranchNode {
        left: from_vendor_merge_value(&node.left)?,
        right: from_vendor_merge_value(&node.right)?,
    })
}

fn to_vendor_merge_value(value: MergeValue) -> VendorMergeValue {
    match value {
        MergeValue::Value(value) => VendorMergeValue::Value(H256::from(value.encode())),
        MergeValue::MergeWithZero {
            base_node,
            zero_bits,
            zero_count,
        } => VendorMergeValue::MergeWithZero {
            base_node: H256::from(base_node.encode()),
            zero_bits: H256::from(zero_bits.encode()),
            zero_count,
        },
    }
}

fn from_vendor_merge_value(value: &VendorMergeValue) -> Result<MergeValue, PersistenceError> {
    match value {
        VendorMergeValue::Value(value) => {
            Ok(MergeValue::Value(FieldValue::try_from(B256::from(<[u8;
                32]>::from(
                *value,
            )))?))
        }
        VendorMergeValue::MergeWithZero {
            base_node,
            zero_bits,
            zero_count,
        } => Ok(MergeValue::MergeWithZero {
            base_node: FieldValue::try_from(B256::from(<[u8; 32]>::from(*base_node)))?,
            zero_bits: FieldValue::try_from(B256::from(<[u8; 32]>::from(*zero_bits)))?,
            zero_count: *zero_count,
        }),
    }
}

fn vendor_store_error(error: impl std::fmt::Display) -> VendorError {
    VendorError::Store(error.to_string())
}

impl StagingCkbStore {
    pub fn new(
        base: AuthenticatedCatalogView,
        namespace: TreeNamespace,
        parent_root: B256,
    ) -> Self {
        Self {
            base,
            namespace,
            parent_root,
            branch_changes: BTreeMap::new(),
            leaf_changes: BTreeMap::new(),
        }
    }

    pub fn read_branch(&self, key: BranchKey) -> Result<Option<BranchNode>, StagingError> {
        match self.branch_changes.get(&key) {
            Some(TreeChange::Set(node)) => Ok(Some(*node)),
            Some(TreeChange::Delete) => Ok(None),
            None => self.base.read_branch(self.namespace, key),
        }
    }

    pub fn write_branch(&mut self, key: BranchKey, node: BranchNode) {
        self.branch_changes.insert(key, TreeChange::Set(node));
    }

    pub fn delete_branch(&mut self, key: BranchKey) {
        self.branch_changes.insert(key, TreeChange::Delete);
    }

    pub fn read_leaf(&self, key: TreeKey) -> Result<Option<LeafValue>, StagingError> {
        match self.leaf_changes.get(&key) {
            Some(TreeChange::Set(value)) => Ok(Some(*value)),
            Some(TreeChange::Delete) => Ok(None),
            None => self.base.read_leaf(self.namespace, key),
        }
    }

    pub fn write_leaf(&mut self, key: TreeKey, value: LeafValue) {
        self.leaf_changes.insert(key, TreeChange::Set(value));
    }

    pub fn delete_leaf(&mut self, key: TreeKey) {
        self.leaf_changes.insert(key, TreeChange::Delete);
    }

    pub fn freeze_shard(
        self,
        new_root: B256,
    ) -> Result<Option<ProvisionalShardBatch>, StagingError> {
        let parent_root = self.parent_root;
        if new_root == parent_root {
            if !self.branch_changes.is_empty() || !self.leaf_changes.is_empty() {
                return Err(StagingError::InvalidShardEnvelope(
                    "net-no-op shard contains records",
                ));
            }
            return Ok(None);
        }
        ProvisionalShardBatch::new(
            parent_root,
            new_root,
            self.branch_changes,
            self.leaf_changes,
        )
        .map(Some)
    }
}

/// Benchmark-fixed local candidate cache bounds. No entry is implicitly
/// evicted, so a required pending-finalized candidate cannot disappear under
/// pressure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateCacheLimits {
    pub max_candidates: usize,
    pub max_encoded_bytes: usize,
}

#[derive(Debug)]
pub struct CandidateCache {
    limits: CandidateCacheLimits,
    encoded_bytes: usize,
    candidates: BTreeMap<B256, Arc<StagedTreeBatch>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationOutcome {
    Published,
    AlreadyPublished,
}

impl CandidateCache {
    #[must_use]
    pub fn new(limits: CandidateCacheLimits) -> Self {
        Self {
            limits,
            encoded_bytes: 0,
            candidates: BTreeMap::new(),
        }
    }

    pub fn publish(&mut self, batch: StagedTreeBatch) -> Result<PublicationOutcome, StagingError> {
        batch.validate_encoded_size()?;
        if let Some(existing) = self.candidates.get(&batch.block_hash) {
            if existing.as_ref() == &batch {
                return Ok(PublicationOutcome::AlreadyPublished);
            }
            return Err(StagingError::ConflictingPublication {
                block_hash: batch.block_hash,
            });
        }

        let candidate_count = self
            .candidates
            .len()
            .checked_add(1)
            .ok_or(StagingError::CacheCapacity)?;
        let encoded_bytes = self
            .encoded_bytes
            .checked_add(batch.encoded_size)
            .ok_or(StagingError::CacheCapacity)?;
        if candidate_count > self.limits.max_candidates
            || encoded_bytes > self.limits.max_encoded_bytes
        {
            return Err(StagingError::CacheCapacity);
        }

        self.encoded_bytes = encoded_bytes;
        self.candidates.insert(batch.block_hash, Arc::new(batch));
        Ok(PublicationOutcome::Published)
    }

    #[must_use]
    pub fn get(&self, block_hash: B256) -> Option<Arc<StagedTreeBatch>> {
        self.candidates.get(&block_hash).cloned()
    }

    /// Removes one rejected speculative payload without disturbing competing
    /// candidates. Open readers retain their immutable `Arc`.
    pub fn remove(&mut self, block_hash: B256) -> Option<Arc<StagedTreeBatch>> {
        let removed = self.candidates.remove(&block_hash);
        if let Some(batch) = &removed {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(batch.encoded_size);
        }
        removed
    }

    /// Removes the winning entry and every losing candidate at or below the
    /// committed height. Open readers keep their own `Arc` immutable batch.
    pub fn remove_finalized(&mut self, height: u64) {
        let removed: Vec<_> = self
            .candidates
            .iter()
            .filter_map(|(hash, batch)| (batch.block_number <= height).then_some(*hash))
            .collect();
        for hash in removed {
            self.remove(hash);
        }
    }

    /// Restart deliberately discards all speculative candidates.
    pub fn discard_all_on_restart(&mut self) {
        self.candidates.clear();
        self.encoded_bytes = 0;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

#[derive(Debug, Error)]
pub enum StagingError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("staged record size overflow")]
    EncodedSizeOverflow,
    #[error("staged encoded size mismatch: declared {declared}, actual {actual}")]
    EncodedSizeMismatch { declared: usize, actual: usize },
    #[error("invalid staged shard-set envelope: {0}")]
    InvalidShardEnvelope(&'static str),
    #[error("invalid staged Root Catalog envelope: {0}")]
    InvalidCatalogEnvelope(&'static str),
    #[error("exact-parent snapshot lock poisoned")]
    SnapshotLockPoisoned,
    #[error("candidate does not fit the configured speculative tree cache")]
    CacheCapacity,
    #[error("conflicting staged tree batch for block {block_hash}")]
    ConflictingPublication { block_hash: B256 },
    #[error(
        "candidate block {block_number} parent {parent_block_hash} does not match exact view {view:?}"
    )]
    CandidateParentMismatch {
        block_number: u64,
        parent_block_hash: B256,
        view: ExactParentIdentity,
    },
    #[error("candidate block number zero has no finalized execution parent")]
    CandidateBlockNumberZero,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::{FieldValue, MergeValue};

    #[derive(Debug)]
    struct MemorySnapshot {
        marker: FinalizedMarker,
        branches: BTreeMap<BranchKey, BranchNode>,
        leaves: BTreeMap<TreeKey, LeafValue>,
    }

    impl FinalizedTreeSnapshot for MemorySnapshot {
        fn marker(&self) -> Result<FinalizedMarker, PersistenceError> {
            Ok(self.marker)
        }

        fn tree_root(&self, namespace: TreeNamespace) -> Result<Option<B256>, PersistenceError> {
            Ok((namespace == TreeNamespace::Catalog).then_some(b256(17)))
        }

        fn collection_has_records(
            &self,
            _collection: CollectionKey,
        ) -> Result<bool, PersistenceError> {
            Ok(false)
        }

        fn collection_root_count(
            &self,
            _collection: CollectionKey,
        ) -> Result<usize, PersistenceError> {
            Ok(0)
        }

        fn collection_leaf_count(
            &self,
            _collection: CollectionKey,
        ) -> Result<usize, PersistenceError> {
            Ok(0)
        }

        fn read_branch(
            &self,
            namespace: TreeNamespace,
            key: BranchKey,
        ) -> Result<Option<BranchNode>, PersistenceError> {
            assert_eq!(namespace, TreeNamespace::Catalog);
            Ok(self.branches.get(&key).copied())
        }

        fn read_leaf(
            &self,
            namespace: TreeNamespace,
            key: TreeKey,
        ) -> Result<Option<LeafValue>, PersistenceError> {
            assert_eq!(namespace, TreeNamespace::Catalog);
            Ok(self.leaves.get(&key).copied())
        }
    }

    fn b256(last: u8) -> B256 {
        let mut bytes = [0_u8; 32];
        bytes[31] = last;
        B256::from(bytes)
    }

    fn marker() -> FinalizedMarker {
        FinalizedMarker {
            commitment_scheme_version: 1,
            height: 7,
            block_hash: b256(7),
            parent_block_hash: b256(6),
            parent_root: b256(16),
            new_root: sealed_root(b256(17)).unwrap(),
        }
    }

    fn exact() -> ExactParentIdentity {
        ExactParentIdentity {
            commitment_scheme_version: 1,
            block_number: 7,
            block_hash: b256(7),
            root: sealed_root(b256(17)).unwrap(),
        }
    }

    fn leaf(last: u8) -> LeafValue {
        LeafValue::try_from(b256(last)).unwrap()
    }

    fn key(last: u8) -> TreeKey {
        TreeKey::try_from(b256(last)).unwrap()
    }

    fn key_in_shard(shard: ShardIndex, ordinal: usize) -> TreeKey {
        (0..=u8::MAX)
            .map(key)
            .filter(|candidate| {
                let smt_key = SmtTreeKey::from_be_bytes(candidate.encode()).unwrap();
                shard_index(smt_key, CeDomain::Tribute.shard_count()).unwrap() == shard
            })
            .nth(ordinal)
            .unwrap()
    }

    fn node(last: u8) -> BranchNode {
        BranchNode {
            left: MergeValue::Value(FieldValue::try_from(b256(last)).unwrap()),
            right: MergeValue::Value(FieldValue::try_from(b256(last + 1)).unwrap()),
        }
    }

    fn view(snapshot: MemorySnapshot) -> AuthenticatedCatalogView {
        AuthenticatedCatalogView::open(Box::new(snapshot), exact()).unwrap()
    }

    #[test]
    fn exact_view_rejects_every_marker_identity_mismatch() {
        type MarkerMutation = Box<dyn Fn(&mut FinalizedMarker)>;

        let expected = exact();
        let mut mutations: Vec<MarkerMutation> = vec![
            Box::new(|value| value.commitment_scheme_version += 1),
            Box::new(|value| value.height += 1),
            Box::new(|value| value.block_hash = b256(99)),
            Box::new(|value| value.new_root = b256(99)),
        ];
        for mutate in &mut mutations {
            let mut wrong = marker();
            mutate(&mut wrong);
            let snapshot = MemorySnapshot {
                marker: wrong,
                branches: BTreeMap::new(),
                leaves: BTreeMap::new(),
            };
            assert!(AuthenticatedCatalogView::open(Box::new(snapshot), expected).is_err());
        }
    }

    #[test]
    fn candidate_writes_shadow_base_without_mutating_snapshot() {
        let branch_key = BranchKey::new(9, b256(5)).unwrap();
        let leaf_key = key(6);
        let base_node = node(10);
        let base_leaf = leaf(12);
        let snapshot = MemorySnapshot {
            marker: marker(),
            branches: BTreeMap::from([(branch_key, base_node)]),
            leaves: BTreeMap::from([(leaf_key, base_leaf)]),
        };
        let mut store = StagingCkbStore::new(view(snapshot), TreeNamespace::Catalog, b256(17));

        assert_eq!(store.read_branch(branch_key).unwrap(), Some(base_node));
        assert_eq!(store.read_leaf(leaf_key).unwrap(), Some(base_leaf));
        store.write_branch(branch_key, node(20));
        store.delete_leaf(leaf_key);
        assert_eq!(store.read_branch(branch_key).unwrap(), Some(node(20)));
        assert_eq!(store.read_leaf(leaf_key).unwrap(), None);

        let batch = store.freeze_shard(b256(18)).unwrap().unwrap();
        assert_eq!(batch.branch_changes.len(), 1);
        assert_eq!(batch.leaf_changes.len(), 1);
    }

    #[test]
    fn ckb_store_traits_round_trip_typed_records_and_reject_invalid_leaf() {
        let snapshot = MemorySnapshot {
            marker: marker(),
            branches: BTreeMap::new(),
            leaves: BTreeMap::new(),
        };
        let mut store = StagingCkbStore::new(view(snapshot), TreeNamespace::Catalog, b256(17));
        let vendor_key = VendorBranchKey::new(12, H256::from(key(4).encode()));
        let vendor_node = VendorBranchNode {
            left: VendorMergeValue::Value(H256::from(leaf(5).encode())),
            right: VendorMergeValue::MergeWithZero {
                base_node: H256::from(leaf(6).encode()),
                zero_bits: H256::from(key(7).encode()),
                zero_count: 0,
            },
        };
        StoreWriteOps::insert_branch(&mut store, vendor_key.clone(), vendor_node.clone()).unwrap();
        assert_eq!(
            StoreReadOps::<H256>::get_branch(&store, &vendor_key).unwrap(),
            Some(vendor_node)
        );

        let leaf_key = H256::from(key(8).encode());
        let leaf_value = H256::from(leaf(9).encode());
        StoreWriteOps::insert_leaf(&mut store, leaf_key, leaf_value).unwrap();
        assert_eq!(
            StoreReadOps::<H256>::get_leaf(&store, &leaf_key).unwrap(),
            Some(leaf_value)
        );
        assert!(StoreWriteOps::insert_leaf(&mut store, leaf_key, H256::zero()).is_err());
        assert!(
            StoreWriteOps::insert_leaf(&mut store, H256::from([u8::MAX; 32]), leaf_value,).is_err()
        );
    }

    #[test]
    fn catalog_envelope_binds_collection_shards_derivations_and_canonical_size() {
        let domain = CeDomain::Tribute;
        let collection_key = CollectionKey::try_from(B256::ZERO).unwrap();
        let parent_roots = vec![B256::ZERO; 16];
        let parent_root = aggregate_b256_roots(&parent_roots).unwrap();
        let mut new_roots = parent_roots.clone();
        new_roots[1] = b256(9);
        let new_root = aggregate_b256_roots(&new_roots).unwrap();
        let changed = ProvisionalShardBatch::new(
            B256::ZERO,
            b256(9),
            BTreeMap::new(),
            BTreeMap::from([(key_in_shard(1, 0), TreeChange::Set(leaf(2)))]),
        )
        .unwrap();
        let shard_set = ProvisionalShardSetBatch::new(
            16,
            parent_root,
            new_root,
            parent_roots.clone(),
            new_roots.clone(),
            BTreeMap::from([(1, changed.clone())]),
        )
        .unwrap();
        assert_eq!(shard_set.shard_count(), 16);
        let new_collection_root = collection_root(domain, collection_key, new_root).unwrap();
        let collection =
            CollectionBatch::new(domain, collection_key, None, new_collection_root, shard_set)
                .unwrap();
        let parent_catalog_root = B256::ZERO;
        let new_catalog_root = b256(20);
        let catalog_key = TreeKey::try_from(B256::from(*collection_key.as_bytes())).unwrap();
        let catalog_batch = ProvisionalCatalogBatch {
            parent_catalog_root,
            new_catalog_root,
            branch_changes: BTreeMap::new(),
            leaf_changes: BTreeMap::from([(
                catalog_key,
                TreeChange::Set(LeafValue::try_from(new_collection_root).unwrap()),
            )]),
        };
        let provisional = ProvisionalTreeBatch::new(
            8,
            b256(7),
            sealed_root(parent_catalog_root).unwrap(),
            sealed_root(new_catalog_root).unwrap(),
            parent_catalog_root,
            new_catalog_root,
            BTreeMap::from([(collection_key, CollectionOperation::Mutate(collection))]),
            Some(catalog_batch),
        )
        .unwrap();
        assert_eq!(provisional.changed_shard_count(), 1);

        let staged = provisional.freeze(b256(8));
        assert_eq!(
            staged.parent_root(),
            sealed_root(parent_catalog_root).unwrap()
        );
        assert_eq!(staged.new_root(), sealed_root(new_catalog_root).unwrap());
        staged.validate_encoded_size().unwrap();
        let canonical = staged.canonical_bytes().unwrap();
        assert_eq!(canonical.len(), staged.encoded_size());
        assert_eq!(
            &canonical[canonical.len() - 8..],
            &u64::try_from(staged.encoded_size()).unwrap().to_be_bytes()
        );
        assert_eq!(
            crate::bench_support::candidate_checksum(&staged),
            alloy_primitives::keccak256(canonical)
        );

        assert!(ProvisionalShardSetBatch::new(
            16,
            parent_root,
            new_root,
            vec![B256::ZERO; 15],
            new_roots.clone(),
            BTreeMap::from([(1, changed.clone())]),
        )
        .is_err());
        assert!(ProvisionalShardSetBatch::new(
            16,
            parent_root,
            new_root,
            parent_roots.clone(),
            new_roots.clone(),
            BTreeMap::from([(2, changed.clone())]),
        )
        .is_err());
        let misderived = ProvisionalShardBatch::new(
            B256::ZERO,
            b256(9),
            BTreeMap::new(),
            BTreeMap::from([(key(2), TreeChange::Set(leaf(2)))]),
        )
        .unwrap();
        assert!(ProvisionalShardSetBatch::new(
            16,
            parent_root,
            new_root,
            parent_roots,
            new_roots,
            BTreeMap::from([(1, misderived)]),
        )
        .is_err());
    }

    #[test]
    fn adr011_retirement_operation_has_pinned_discriminant_size_and_checksum() {
        let domain = CeDomain::Tribute;
        let collection_key = CollectionKey::try_from(B256::ZERO).unwrap();
        let parent_shard_roots = vec![B256::ZERO; 16];
        let parent_top = aggregate_b256_roots(&parent_shard_roots).unwrap();
        let parent_collection_root = collection_root(domain, collection_key, parent_top).unwrap();
        let retirement = RetirementBatch::new(
            domain,
            collection_key,
            parent_collection_root,
            parent_shard_roots,
        )
        .unwrap();
        let parent_catalog_root = b256(30);
        let new_catalog_root = b256(31);
        let catalog_key = TreeKey::try_from(B256::from(*collection_key.as_bytes())).unwrap();
        let provisional = ProvisionalTreeBatch::new(
            8,
            b256(7),
            sealed_root(parent_catalog_root).unwrap(),
            sealed_root(new_catalog_root).unwrap(),
            parent_catalog_root,
            new_catalog_root,
            BTreeMap::from([(collection_key, CollectionOperation::Retire(retirement))]),
            Some(ProvisionalCatalogBatch {
                parent_catalog_root,
                new_catalog_root,
                branch_changes: BTreeMap::new(),
                leaf_changes: BTreeMap::from([(catalog_key, TreeChange::Delete)]),
            }),
        )
        .unwrap();
        let staged = provisional.freeze(b256(8));
        let canonical = staged.canonical_bytes().unwrap();

        assert_eq!(canonical.len(), 901);
        assert_eq!(canonical[236], 1, "Retire discriminant must remain one");
        assert_eq!(
            alloy_primitives::keccak256(&canonical),
            alloy_primitives::b256!(
                "a8f190e2fd539aa5dad1fe39a615792a0bcde0e658faf5d2849d2df8fb3d52e7"
            )
        );
    }

    #[test]
    fn publication_is_structurally_idempotent_and_never_evicts() {
        let provisional = ProvisionalTreeBatch::new_fixture_single_collection(
            8,
            b256(7),
            b256(17),
            b256(18),
            BTreeMap::new(),
            BTreeMap::from([(key_in_shard(0, 0), TreeChange::Set(leaf(2)))]),
        )
        .unwrap();
        let batch = provisional.freeze(b256(8));
        let mut cache = CandidateCache::new(CandidateCacheLimits {
            max_candidates: 1,
            max_encoded_bytes: batch.encoded_size,
        });
        assert_eq!(
            cache.publish(batch.clone()).unwrap(),
            PublicationOutcome::Published
        );
        assert_eq!(
            cache.publish(batch.clone()).unwrap(),
            PublicationOutcome::AlreadyPublished
        );

        let competing = ProvisionalTreeBatch::new_fixture_single_collection(
            8,
            b256(7),
            b256(17),
            b256(19),
            BTreeMap::new(),
            BTreeMap::from([(key_in_shard(0, 1), TreeChange::Set(leaf(3)))]),
        )
        .unwrap()
        .freeze(b256(9));
        assert!(matches!(
            cache.publish(competing),
            Err(StagingError::CacheCapacity)
        ));
        assert_eq!(cache.get(b256(8)).unwrap().as_ref(), &batch);
    }

    #[test]
    fn same_hash_with_different_typed_batch_is_corruption() {
        let first = ProvisionalTreeBatch::new_fixture_single_collection(
            8,
            b256(7),
            b256(17),
            b256(18),
            BTreeMap::new(),
            BTreeMap::from([(key_in_shard(0, 0), TreeChange::Set(leaf(2)))]),
        )
        .unwrap()
        .freeze(b256(8));
        let conflicting = ProvisionalTreeBatch::new_fixture_single_collection(
            8,
            b256(7),
            b256(17),
            b256(19),
            BTreeMap::new(),
            BTreeMap::from([(key_in_shard(0, 0), TreeChange::Set(leaf(3)))]),
        )
        .unwrap()
        .freeze(b256(8));
        let mut cache = CandidateCache::new(CandidateCacheLimits {
            max_candidates: 2,
            max_encoded_bytes: 2_000,
        });
        cache.publish(first).unwrap();
        assert!(matches!(
            cache.publish(conflicting),
            Err(StagingError::ConflictingPublication { .. })
        ));
    }

    #[test]
    fn finalization_and_restart_remove_only_by_explicit_policy() {
        let mut cache = CandidateCache::new(CandidateCacheLimits {
            max_candidates: 4,
            max_encoded_bytes: 20_000,
        });
        for (height, hash) in [(8, 8), (8, 9), (9, 10)] {
            cache
                .publish(
                    ProvisionalTreeBatch::new_fixture_single_collection(
                        height,
                        b256(7),
                        b256(17),
                        b256(18),
                        BTreeMap::new(),
                        BTreeMap::from([(
                            key_in_shard(0, usize::from(hash - 8)),
                            TreeChange::Set(leaf(hash + 1)),
                        )]),
                    )
                    .unwrap()
                    .freeze(b256(hash)),
                )
                .unwrap();
        }
        cache.remove_finalized(8);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(b256(10)).is_some());
        cache.discard_all_on_restart();
        assert!(cache.is_empty());
        assert_eq!(cache.encoded_bytes(), 0);
    }
}
