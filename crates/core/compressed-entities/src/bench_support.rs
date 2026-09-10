//! Narrow, non-consensus harness used only by reproducible ADR benchmarks.

use std::collections::BTreeMap;

use alloy_primitives::{keccak256, B256};

use crate::{
    api::EntityRef,
    persistence::{
        BranchKey, BranchNode, FieldValue, LeafValue, MergeValue, TreeKey as PersistedTreeKey,
    },
    schema::Collection,
    sharding::{aggregate_b256_shard_roots, shard_index},
    smt::{PoseidonSmt, TreeKey, TreeLeaf, TreeProof, TreeRoot},
    ProvisionalTreeBatch, StagedTreeBatch, TreeChange,
};

/// Returns the protocol-derived shard for a real typed entity. This keeps the
/// ADR-009 benchmark dataset on the production key-derivation path.
pub fn derived_shard(entity: EntityRef, shard_count: u32) -> Result<u32, String> {
    let (collection, identity) = match entity {
        EntityRef::Tribute(identity) => (Collection::Tribute, identity),
        EntityRef::NodItem(identity) => (Collection::NodItem, identity),
        EntityRef::NodBucket(identity) => (Collection::NodBucket, identity),
    };
    let key =
        crate::smt::derive_tree_key(collection, identity).map_err(|error| error.to_string())?;
    shard_index(key, shard_count).map_err(|error| error.to_string())
}

/// Stable checksum of the canonical candidate accounting bytes used by reports.
/// This is an artifact checksum, not a consensus hash.
#[must_use]
pub fn candidate_checksum(batch: &StagedTreeBatch) -> B256 {
    keccak256(
        batch
            .canonical_bytes()
            .expect("validated candidate has canonical accounting bytes"),
    )
}

/// Returns the first changed collection's shard roots for the historical
/// ADR-009 aggregation benchmark.
pub fn candidate_shard_roots(batch: &ProvisionalTreeBatch) -> Vec<B256> {
    batch
        .changed_collections
        .values()
        .find_map(crate::CollectionOperation::mutation)
        .map_or_else(Vec::new, |collection| {
            collection.shard_set.new_shard_roots.clone()
        })
}

/// Recomputes the production shard-top aggregation for phase benchmarks.
pub fn aggregate_shard_roots(roots: &[B256]) -> Result<B256, String> {
    aggregate_b256_shard_roots(roots).map_err(|error| error.to_string())
}

pub struct Adr008SmtHarness {
    tree: PoseidonSmt,
}

pub struct Adr008Proof(TreeProof);

impl Adr008SmtHarness {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            tree: PoseidonSmt::empty(),
        }
    }

    pub fn root(&self) -> Result<[u8; 32], String> {
        self.tree
            .root()
            .map(TreeRoot::as_bytes)
            .map_err(|error| error.to_string())
    }

    pub fn update_all(&mut self, updates: &[([u8; 32], [u8; 32])]) -> Result<[u8; 32], String> {
        let updates = updates
            .iter()
            .map(|(key, leaf)| -> Result<_, String> {
                Ok((
                    TreeKey::from_be_bytes(*key).map_err(|error| error.to_string())?,
                    TreeLeaf::from_be_bytes(*leaf).map_err(|error| error.to_string())?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.tree
            .update_all(updates)
            .map(TreeRoot::as_bytes)
            .map_err(|error| error.to_string())
    }

    pub fn proof(&self, keys: &[[u8; 32]]) -> Result<Adr008Proof, String> {
        let keys = keys
            .iter()
            .copied()
            .map(|key| TreeKey::from_be_bytes(key).map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        self.tree
            .prove(keys)
            .map(Adr008Proof)
            .map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        root: [u8; 32],
        proof: &Adr008Proof,
        leaves: &[([u8; 32], [u8; 32])],
    ) -> Result<(), String> {
        let root = TreeRoot::from_be_bytes(root).map_err(|error| error.to_string())?;
        let leaves = leaves
            .iter()
            .map(|(key, leaf)| -> Result<_, String> {
                Ok((
                    TreeKey::from_be_bytes(*key).map_err(|error| error.to_string())?,
                    TreeLeaf::from_be_bytes(*leaf).map_err(|error| error.to_string())?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.tree
            .verify(root, &proof.0, leaves)
            .map_err(|error| error.to_string())
    }
}

/// Builds a codec-valid staged batch for measuring the finalized MDBX apply
/// path. It intentionally does not assert any protocol capacity or timing.
pub fn staged_batch(
    block_number: u64,
    block_hash: B256,
    parent_block_hash: B256,
    parent_root: B256,
    new_root: B256,
    record_count: usize,
) -> Result<StagedTreeBatch, String> {
    let mut branches = BTreeMap::new();
    let mut leaves = BTreeMap::new();
    let mut key_candidate = 1_u64;
    for index in 0..record_count {
        let ordinal = u64::try_from(index)
            .map_err(|_| "benchmark record count is not representable as u64".to_owned())?
            .saturating_add(1);
        let key_word = loop {
            let word = field_b256(key_candidate);
            key_candidate = key_candidate
                .checked_add(1)
                .ok_or_else(|| "benchmark key search overflowed".to_owned())?;
            let smt_key = TreeKey::from_be_bytes(word.0).map_err(|error| error.to_string())?;
            if shard_index(smt_key, crate::K_PROVISIONAL).map_err(|error| error.to_string())? == 0 {
                break word;
            }
        };
        let value_word = field_b256(block_number.wrapping_add(ordinal).max(1));
        let field = FieldValue::try_from(value_word).map_err(|error| error.to_string())?;
        let branch_key =
            BranchKey::new(index as u8, key_word).map_err(|error| error.to_string())?;
        branches.insert(
            branch_key,
            TreeChange::Set(BranchNode {
                left: MergeValue::Value(field),
                right: MergeValue::Value(
                    FieldValue::try_from(B256::ZERO).map_err(|error| error.to_string())?,
                ),
            }),
        );
        leaves.insert(
            PersistedTreeKey::try_from(key_word).map_err(|error| error.to_string())?,
            TreeChange::Set(LeafValue::try_from(value_word).map_err(|error| error.to_string())?),
        );
    }
    ProvisionalTreeBatch::new_fixture_single_collection(
        block_number,
        parent_block_hash,
        parent_root,
        new_root,
        branches,
        leaves,
    )
    .map(|batch| batch.freeze(block_hash))
    .map_err(|error| error.to_string())
}

#[must_use]
pub fn field_word(value: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

#[must_use]
pub fn field_b256(value: u64) -> B256 {
    B256::from(field_word(value))
}
