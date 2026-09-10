use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_sparse_merkle_tree_v061::{
    error::Error as VendorError,
    merge::{merge, MergeValue},
    traits::{StoreReadOps, StoreWriteOps},
    BranchKey, BranchNode, CompiledMerkleProof, SparseMerkleTree, H256,
};
use thiserror::Error;

use super::codec::{hash_error, is_canonical, PoseidonCkbHasher};
use crate::{schema::Collection, WwdEntityId};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TreeKey([u8; 32]);

impl Ord for TreeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for TreeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TreeKey {
    pub(crate) fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, TreeError> {
        validate_field_bytes(bytes, "tree key")?;
        Ok(Self(bytes))
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn ckb(self) -> H256 {
        H256::from(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TreeLeaf([u8; 32]);

impl TreeLeaf {
    pub(crate) const ZERO: Self = Self([0_u8; 32]);

    pub(crate) fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, TreeError> {
        validate_field_bytes(bytes, "tree leaf")?;
        Ok(Self(bytes))
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn ckb(self) -> H256 {
        H256::from(self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TreeRoot([u8; 32]);

impl TreeRoot {
    pub(crate) const EMPTY: Self = Self([0_u8; 32]);

    pub(crate) fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, TreeError> {
        validate_field_bytes(bytes, "tree root")?;
        Ok(Self(bytes))
    }

    pub(crate) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn ckb(self) -> H256 {
        H256::from(self.0)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TreeProof(CompiledMerkleProof);

impl TreeProof {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(CompiledMerkleProof(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0 .0
    }

    pub(crate) fn compute_root(&self, key: TreeKey, leaf: TreeLeaf) -> Result<TreeRoot, TreeError> {
        self.0
            .compute_root::<PoseidonCkbHasher>(vec![(key.ckb(), leaf.ckb())])
            .map_err(vendor_error)
            .and_then(checked_root)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum TreeError {
    #[error("shard count must be a power of two in 1..=32, got {actual}")]
    InvalidShardCount { actual: u32 },
    #[error("{kind} is not a canonical BN254 field encoding")]
    NonCanonicalField { kind: &'static str },
    #[error("{kind} equals the reserved CKB hasher poison value")]
    HashPoison { kind: &'static str },
    #[error("Poseidon CKB tree hashing failed")]
    TreeHashError,
    #[error("duplicate tree key in one update batch")]
    DuplicateKey,
    #[error("tree keys must be supplied in strict ascending order")]
    NonAscendingKey,
    #[error("present tree leaf must be non-zero")]
    ZeroLeaf,
    #[error("sorted SMT reducer invariant failed: {0}")]
    ReducerInvariant(&'static str),
    #[error("invalid CKB membership or non-membership proof")]
    InvalidProof,
    #[error("vendored CKB SMT failure: {0}")]
    Vendor(String),
    #[error("Poseidon-BN254 tree-key derivation failed: {0}")]
    Poseidon(String),
}

#[derive(Clone, Default)]
pub(crate) struct MemoryStore {
    branches: BTreeMap<BranchKey, BranchNode>,
    leaves: BTreeMap<H256, H256>,
}

impl StoreReadOps<H256> for MemoryStore {
    fn get_branch(&self, key: &BranchKey) -> Result<Option<BranchNode>, VendorError> {
        Ok(self.branches.get(key).cloned())
    }

    fn get_leaf(&self, key: &H256) -> Result<Option<H256>, VendorError> {
        Ok(self.leaves.get(key).copied())
    }
}

impl StoreWriteOps<H256> for MemoryStore {
    fn insert_branch(&mut self, key: BranchKey, branch: BranchNode) -> Result<(), VendorError> {
        validate_merge_value(&branch.left).map_err(vendor_store_error)?;
        validate_merge_value(&branch.right).map_err(vendor_store_error)?;
        self.branches.insert(key, branch);
        Ok(())
    }

    fn insert_leaf(&mut self, key: H256, leaf: H256) -> Result<(), VendorError> {
        validate_ckb(key, "tree key").map_err(vendor_store_error)?;
        validate_ckb(leaf, "stored leaf").map_err(vendor_store_error)?;
        if leaf.is_zero() {
            return Err(VendorError::Store("zero leaf must be deleted".into()));
        }
        self.leaves.insert(key, leaf);
        Ok(())
    }

    fn remove_branch(&mut self, key: &BranchKey) -> Result<(), VendorError> {
        self.branches.remove(key);
        Ok(())
    }

    fn remove_leaf(&mut self, key: &H256) -> Result<(), VendorError> {
        self.leaves.remove(key);
        Ok(())
    }
}

/// Private, single-engine facade. Persistence adapters use the same CKB Store seams.
pub(crate) struct PoseidonSmt<S = MemoryStore> {
    inner: SparseMerkleTree<PoseidonCkbHasher, H256, S>,
}

/// Reduces strictly ordered non-zero leaves to the canonical CKB SMT root
/// while retaining at most one pending subtree per tree level.
pub(crate) struct SortedPoseidonRootReducer {
    frontier: Vec<Option<PendingSortedNode>>,
    current: Option<PendingSortedNode>,
}

struct PendingSortedNode {
    key: TreeKey,
    value: MergeValue,
}

impl SortedPoseidonRootReducer {
    pub(crate) fn new() -> Self {
        Self {
            frontier: std::iter::repeat_with(|| None).take(256).collect(),
            current: None,
        }
    }

    pub(crate) fn push(&mut self, key: TreeKey, leaf: TreeLeaf) -> Result<(), TreeError> {
        if leaf == TreeLeaf::ZERO {
            return Err(TreeError::ZeroLeaf);
        }
        if let Some(current) = self.current.as_ref() {
            match key.cmp(&current.key) {
                Ordering::Less => return Err(TreeError::NonAscendingKey),
                Ordering::Equal => return Err(TreeError::DuplicateKey),
                Ordering::Greater => {}
            }
            let fork_height = current.key.ckb().fork_height(&key.ckb());
            self.lift_current(fork_height)?;
            let completed = self
                .current
                .take()
                .ok_or(TreeError::ReducerInvariant("current subtree disappeared"))?;
            if completed.key.ckb().is_right(fork_height) {
                return Err(TreeError::ReducerInvariant(
                    "ordered subtree is not the left fork child",
                ));
            }
            let slot = self
                .frontier
                .get_mut(usize::from(fork_height))
                .ok_or(TreeError::ReducerInvariant("fork height outside frontier"))?;
            if slot.is_some() {
                return Err(TreeError::ReducerInvariant(
                    "fork frontier already contains a subtree",
                ));
            }
            *slot = Some(completed);
        }
        self.current = Some(PendingSortedNode {
            key,
            value: MergeValue::from_h256(leaf.ckb()),
        });
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<TreeRoot, TreeError> {
        if self.current.is_none() {
            if self.frontier.iter().any(Option::is_some) {
                return Err(TreeError::ReducerInvariant(
                    "empty reducer retains a pending subtree",
                ));
            }
            return Ok(TreeRoot::EMPTY);
        }
        self.lift_current(u8::MAX)?;
        self.merge_current_level(u8::MAX)?;
        if self.frontier.iter().any(Option::is_some) {
            return Err(TreeError::ReducerInvariant(
                "finished reducer retains a pending subtree",
            ));
        }
        let root = self
            .current
            .take()
            .ok_or(TreeError::ReducerInvariant("root subtree disappeared"))?
            .value
            .hash::<PoseidonCkbHasher>();
        checked_root(root)
    }

    fn lift_current(&mut self, target_height: u8) -> Result<(), TreeError> {
        for height in 0..target_height {
            self.merge_current_level(height)?;
        }
        Ok(())
    }

    fn merge_current_level(&mut self, height: u8) -> Result<(), TreeError> {
        let mut current = self
            .current
            .take()
            .ok_or(TreeError::ReducerInvariant("current subtree is missing"))?;
        let ckb_key = current.key.ckb();
        let parent_key = ckb_key.parent_path(height);
        let left = self.frontier[usize::from(height)].take();
        current.value = if let Some(left) = left {
            let left_key = left.key.ckb();
            if left_key.is_right(height)
                || !ckb_key.is_right(height)
                || left_key.parent_path(height) != parent_key
            {
                return Err(TreeError::ReducerInvariant(
                    "pending subtrees are not ordered siblings",
                ));
            }
            merge::<PoseidonCkbHasher>(height, &parent_key, &left.value, &current.value)
        } else if ckb_key.is_right(height) {
            merge::<PoseidonCkbHasher>(height, &parent_key, &MergeValue::zero(), &current.value)
        } else {
            merge::<PoseidonCkbHasher>(height, &parent_key, &current.value, &MergeValue::zero())
        };
        self.current = Some(current);
        Ok(())
    }
}

impl Default for PoseidonSmt<MemoryStore> {
    fn default() -> Self {
        Self::empty()
    }
}

impl PoseidonSmt<MemoryStore> {
    pub(crate) fn empty() -> Self {
        Self {
            inner: SparseMerkleTree::new(H256::zero(), MemoryStore::default()),
        }
    }
}

impl<S> PoseidonSmt<S> {
    pub(crate) fn open_with_store(root: TreeRoot, store: S) -> Self {
        Self {
            inner: SparseMerkleTree::new(root.ckb(), store),
        }
    }

    pub(crate) fn root(&self) -> Result<TreeRoot, TreeError> {
        checked_root(*self.inner.root())
    }

    pub(crate) fn into_store(self) -> S {
        self.inner.take_store()
    }

    pub(crate) fn verify(
        &self,
        root: TreeRoot,
        proof: &TreeProof,
        leaves: Vec<(TreeKey, TreeLeaf)>,
    ) -> Result<(), TreeError> {
        let keys: Vec<_> = leaves.iter().map(|(key, _)| *key).collect();
        ensure_unique_keys(&keys)?;
        let calculated = proof
            .0
            .compute_root::<PoseidonCkbHasher>(
                leaves
                    .into_iter()
                    .map(|(key, leaf)| (key.ckb(), leaf.ckb()))
                    .collect(),
            )
            .map_err(vendor_error)?;
        let calculated = checked_root(calculated)?;
        if calculated != root {
            return Err(TreeError::InvalidProof);
        }
        Ok(())
    }
}

impl<S: StoreReadOps<H256>> PoseidonSmt<S> {
    pub(crate) fn get(&self, key: TreeKey) -> Result<TreeLeaf, TreeError> {
        let leaf = self.inner.get(&key.ckb()).map_err(vendor_error)?;
        TreeLeaf::from_be_bytes(leaf.into())
    }

    pub(crate) fn prove(&self, keys: Vec<TreeKey>) -> Result<TreeProof, TreeError> {
        ensure_unique_keys(&keys)?;
        let ckb_keys: Vec<_> = keys.into_iter().map(TreeKey::ckb).collect();
        let proof = self
            .inner
            .merkle_proof(ckb_keys.clone())
            .and_then(|proof| proof.compile(ckb_keys))
            .map_err(vendor_error)?;
        Ok(TreeProof(proof))
    }
}

impl<S: StoreReadOps<H256> + StoreWriteOps<H256>> PoseidonSmt<S> {
    pub(crate) fn update(&mut self, key: TreeKey, leaf: TreeLeaf) -> Result<TreeRoot, TreeError> {
        self.update_all(vec![(key, leaf)])
    }

    pub(crate) fn update_all(
        &mut self,
        updates: Vec<(TreeKey, TreeLeaf)>,
    ) -> Result<TreeRoot, TreeError> {
        let mut unique = BTreeSet::new();
        if updates.iter().any(|(key, _)| !unique.insert(*key)) {
            return Err(TreeError::DuplicateKey);
        }
        if updates.is_empty() {
            return self.root();
        }
        self.inner
            .update_all(
                updates
                    .into_iter()
                    .map(|(key, leaf)| (key.ckb(), leaf.ckb()))
                    .collect(),
            )
            .map_err(vendor_error)?;
        checked_root(*self.inner.root())
    }
}

pub(crate) fn derive_tree_key(
    collection: Collection,
    identity: WwdEntityId,
) -> Result<TreeKey, TreeError> {
    crate::collection::tree_key_bytes(collection.into(), identity)
        .map_err(|error| TreeError::Poseidon(error.to_string()))
        .and_then(TreeKey::from_be_bytes)
}

fn ensure_unique_keys(keys: &[TreeKey]) -> Result<(), TreeError> {
    let mut unique = BTreeSet::new();
    if keys.iter().any(|key| !unique.insert(*key)) {
        return Err(TreeError::DuplicateKey);
    }
    if keys.is_empty() {
        return Err(TreeError::Vendor("proof keys must not be empty".into()));
    }
    Ok(())
}

fn validate_merge_value(value: &MergeValue) -> Result<(), TreeError> {
    match value {
        MergeValue::Value(value) => validate_ckb(*value, "branch value"),
        MergeValue::MergeWithZero {
            base_node,
            zero_bits,
            ..
        } => {
            validate_ckb(*base_node, "compact-zero base node")?;
            validate_ckb(*zero_bits, "compact-zero bits")
        }
    }
}

fn validate_ckb(value: H256, kind: &'static str) -> Result<(), TreeError> {
    if value == hash_error() {
        return Err(TreeError::HashPoison { kind });
    }
    if !is_canonical(value) {
        return Err(TreeError::NonCanonicalField { kind });
    }
    Ok(())
}

fn validate_field_bytes(bytes: [u8; 32], kind: &'static str) -> Result<(), TreeError> {
    validate_ckb(H256::from(bytes), kind)
}

fn checked_root(root: H256) -> Result<TreeRoot, TreeError> {
    if root == hash_error() {
        return Err(TreeError::TreeHashError);
    }
    let bytes: [u8; 32] = root.into();
    TreeRoot::from_be_bytes(bytes)
}

fn vendor_error(error: VendorError) -> TreeError {
    let message = error.to_string();
    if message.contains("poison") || message.contains("canonical") {
        TreeError::TreeHashError
    } else {
        TreeError::Vendor(message)
    }
}

fn vendor_store_error(error: TreeError) -> VendorError {
    VendorError::Store(error.to_string())
}

fn field_to_be32(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut output = [0_u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    output
}
