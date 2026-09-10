//! CE-owned finalized sparse-tree persistence.
//!
//! This module owns deterministic local codecs, the separate MDBX environment,
//! atomic contiguous finalized application, and restart/ACK classification. It
//! is authenticated materialization only: the exact EVM root remains the sole
//! consensus authority.

use std::{
    cmp::Ordering as CmpOrdering,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use reth_db::{
    cursor::DbCursorRO,
    database::Database,
    mdbx::{create_db, tx::Tx, DatabaseArguments, RO},
    open_db_read_only,
    table::Table,
    transaction::{DbTx, DbTxMut},
    ClientVersion, DatabaseEnv,
};
use thiserror::Error;

use crate::{
    sharding::aggregate_b256_shard_roots,
    staging::{
        FinalizedTreeSnapshot, ProvisionalShardBatch, ShardIndex, StagedTreeBatch, StagingError,
        TreeChange,
    },
    CollectionKey, K_PROVISIONAL,
};

pub const LOCAL_STORAGE_SCHEMA_VERSION: u32 = 3;
pub const FINALIZED_MARKER_ENCODED_LEN: usize = 4 + 8 + 32 * 4;
pub const CE_SMT_RELATIVE_PATH: &str = "compressed_entities/smt";

const IDENTITY_KEY: &[u8] = b"environment_identity";
const LAST_APPLIED_KEY: &[u8] = b"last_applied";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TreeNamespace {
    Catalog,
    CollectionShard(CollectionKey, ShardIndex),
}

#[cfg(test)]
mod adr010_tests {
    use std::sync::Arc;

    use alloy_primitives::B256;

    use super::*;
    use crate::{
        api::{AuthenticatedParentTree, EntityRef, FinalLeafMutation},
        collection_key, sealed_root, CeDomain, CeTopologyV1, Commitment, MdbxAuthenticatedTree,
        WwdEntityId, ACTIVE_COMMITMENT_SCHEME, K_PROVISIONAL,
    };

    const VENDOR: &str = "ad555350c866b2265d87d2d7fbd146fbc918bfe5";

    fn identity(genesis_hash: B256) -> EnvironmentIdentity {
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: 10,
            genesis_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: VENDOR.to_owned(),
        }
    }

    fn genesis(genesis_hash: B256) -> FinalizedMarker {
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        }
    }

    fn tribute_id(day: u32, suffix: u8) -> WwdEntityId {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&day.to_be_bytes());
        bytes[31] = suffix;
        WwdEntityId::try_from(bytes.as_slice()).unwrap()
    }

    #[test]
    fn v3_retirement_reclaims_all_prefixes_alongside_other_wwd_and_both_nod_mutations() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x10);
        let db = Arc::new(
            CeMdbx::open(
                directory.path(),
                identity(genesis_hash),
                genesis(genesis_hash),
            )
            .unwrap(),
        );
        let snapshot = db.open_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_root(TreeNamespace::Catalog).unwrap(),
            Some(B256::ZERO)
        );

        let id = tribute_id(20_260_717, 1);
        let collection = collection_key(CeDomain::Tribute, id).unwrap();
        assert!(!snapshot.collection_has_records(collection).unwrap());
        for shard in 0..K_PROVISIONAL {
            assert_eq!(
                snapshot
                    .tree_root(TreeNamespace::CollectionShard(collection, shard))
                    .unwrap(),
                None
            );
        }
        drop(snapshot);

        let parent = MdbxAuthenticatedTree::open(
            Arc::clone(&db),
            ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: sealed_root(B256::ZERO).unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            parent
                .read_leaf_verified(
                    EntityRef::Tribute(tribute_id(20_260_717, 9)),
                    sealed_root(B256::ZERO).unwrap()
                )
                .unwrap(),
            None
        );
        assert!(!db
            .open_snapshot()
            .unwrap()
            .collection_has_records(collection)
            .unwrap());
        let commitment = Commitment::try_from(B256::with_last_byte(1).0).unwrap();
        let provisional = parent
            .prepare_seal(
                1,
                &[FinalLeafMutation {
                    entity: EntityRef::Tribute(id),
                    final_leaf: Some(commitment),
                }],
                &[],
            )
            .unwrap();
        let staged = provisional.freeze(B256::repeat_byte(0x11));
        assert_eq!(
            db.apply_finalized(&staged).unwrap(),
            ApplyOutcome::Applied(staged.marker(1))
        );

        let snapshot = db.open_snapshot().unwrap();
        assert_ne!(
            snapshot.tree_root(TreeNamespace::Catalog).unwrap(),
            Some(B256::ZERO)
        );
        assert!(snapshot.collection_has_records(collection).unwrap());
        for shard in 0..K_PROVISIONAL {
            assert!(snapshot
                .tree_root(TreeNamespace::CollectionShard(collection, shard))
                .unwrap()
                .is_some());
        }
        assert_eq!(
            snapshot
                .tree_root(TreeNamespace::CollectionShard(collection, K_PROVISIONAL))
                .unwrap(),
            None
        );
        let block_one_root = staged.new_root();
        let block_one_hash = staged.block_hash();
        drop(snapshot);

        let parent = MdbxAuthenticatedTree::open(
            Arc::clone(&db),
            ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 1,
                block_hash: block_one_hash,
                root: block_one_root,
            },
        )
        .unwrap();
        let emptied = parent
            .prepare_seal(
                2,
                &[FinalLeafMutation {
                    entity: EntityRef::Tribute(id),
                    final_leaf: None,
                }],
                &[],
            )
            .unwrap()
            .freeze(B256::repeat_byte(0x12));
        db.apply_finalized(&emptied).unwrap();
        let snapshot = db.open_snapshot().unwrap();
        assert!(snapshot.collection_has_records(collection).unwrap());
        for shard in 0..K_PROVISIONAL {
            assert_eq!(
                snapshot
                    .tree_root(TreeNamespace::CollectionShard(collection, shard))
                    .unwrap(),
                Some(B256::ZERO)
            );
        }
        let emptied_root = emptied.new_root();
        let emptied_hash = emptied.block_hash();
        drop(snapshot);

        let parent = MdbxAuthenticatedTree::open(
            Arc::clone(&db),
            ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 2,
                block_hash: emptied_hash,
                root: emptied_root,
            },
        )
        .unwrap();
        let nod_id = tribute_id(20_260_718, 2);
        let other_tribute_id = tribute_id(20_260_719, 3);
        let nod_collection = collection_key(CeDomain::NodItem, nod_id).unwrap();
        let bucket_collection = collection_key(CeDomain::NodBucket, nod_id).unwrap();
        let other_tribute_collection = collection_key(CeDomain::Tribute, other_tribute_id).unwrap();
        let staged_delete = parent
            .prepare_seal(
                3,
                &[
                    FinalLeafMutation {
                        entity: EntityRef::NodItem(nod_id),
                        final_leaf: Some(Commitment::try_from(B256::with_last_byte(2).0).unwrap()),
                    },
                    FinalLeafMutation {
                        entity: EntityRef::NodBucket(nod_id),
                        final_leaf: Some(Commitment::try_from(B256::with_last_byte(3).0).unwrap()),
                    },
                    FinalLeafMutation {
                        entity: EntityRef::Tribute(other_tribute_id),
                        final_leaf: Some(Commitment::try_from(B256::with_last_byte(4).0).unwrap()),
                    },
                ],
                &[crate::PartitionRef::TributeWwd(
                    outbe_primitives::time::WorldwideDay::new(20_260_717),
                )],
            )
            .unwrap()
            .freeze(B256::repeat_byte(0x13));
        db.apply_finalized(&staged_delete).unwrap();
        let snapshot = db.open_snapshot().unwrap();
        let catalog_key = TreeKey::try_from(B256::from(*collection.as_bytes())).unwrap();
        assert!(snapshot
            .read_leaf(TreeNamespace::Catalog, catalog_key)
            .unwrap()
            .is_none());
        assert!(!snapshot.collection_has_records(collection).unwrap());
        assert!(snapshot.collection_has_records(nod_collection).unwrap());
        assert!(snapshot.collection_has_records(bucket_collection).unwrap());
        assert!(snapshot
            .collection_has_records(other_tribute_collection)
            .unwrap());
        for shard in 0..K_PROVISIONAL {
            assert_eq!(
                snapshot
                    .tree_root(TreeNamespace::CollectionShard(collection, shard))
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn topology_identity_is_canonical_and_mismatch_never_falls_back() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x20);
        let expected = identity(genesis_hash);
        drop(CeMdbx::open(directory.path(), expected.clone(), genesis(genesis_hash)).unwrap());

        let mut mismatched = expected;
        mismatched.topology.push(0);
        assert!(matches!(
            CeMdbx::open(directory.path(), mismatched, genesis(genesis_hash)),
            Err(PersistenceError::InvalidTopologyIdentity)
        ));
    }

    #[test]
    fn one_block_atomically_creates_three_independent_domain_collections() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x30);
        let db = Arc::new(
            CeMdbx::open(
                directory.path(),
                identity(genesis_hash),
                genesis(genesis_hash),
            )
            .unwrap(),
        );
        let parent = MdbxAuthenticatedTree::open(
            Arc::clone(&db),
            ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: sealed_root(B256::ZERO).unwrap(),
            },
        )
        .unwrap();
        let id = tribute_id(20_260_718, 7);
        let mutations = [
            EntityRef::Tribute(id),
            EntityRef::NodItem(id),
            EntityRef::NodBucket(id),
        ]
        .map(|entity| FinalLeafMutation {
            entity,
            final_leaf: Some(
                Commitment::try_from(B256::with_last_byte(entity_kind(entity)).0).unwrap(),
            ),
        });
        let staged = parent
            .prepare_seal(1, &mutations, &[])
            .unwrap()
            .freeze(B256::repeat_byte(0x31));
        assert_eq!(staged.changed_collections.len(), 3);
        assert_eq!(staged.catalog_batch.as_ref().unwrap().leaf_changes.len(), 3);
        db.apply_finalized(&staged).unwrap();

        let snapshot = db.open_snapshot().unwrap();
        for domain in [CeDomain::Tribute, CeDomain::NodItem, CeDomain::NodBucket] {
            let key = collection_key(domain, id).unwrap();
            assert!(snapshot.collection_has_records(key).unwrap());
            assert!(snapshot
                .read_leaf(
                    TreeNamespace::Catalog,
                    TreeKey::try_from(B256::from(*key.as_bytes())).unwrap(),
                )
                .unwrap()
                .is_some());
        }
        assert_eq!(
            snapshot.marker().unwrap(),
            staged.marker(ACTIVE_COMMITMENT_SCHEME)
        );
    }

    fn entity_kind(entity: EntityRef) -> u8 {
        match entity {
            EntityRef::Tribute(_) => 1,
            EntityRef::NodItem(_) => 2,
            EntityRef::NodBucket(_) => 3,
        }
    }

    #[test]
    fn v3_namespace_codec_is_typed_strict_and_order_preserving() {
        let key = collection_key(CeDomain::Tribute, tribute_id(20_260_719, 1)).unwrap();
        let catalog = TreeNamespace::Catalog.encode();
        let shard = TreeNamespace::CollectionShard(key, 15).encode();
        assert_eq!(catalog, vec![0]);
        assert_eq!(shard.len(), 37);
        assert_eq!(
            TreeNamespace::decode(&catalog).unwrap(),
            TreeNamespace::Catalog
        );
        assert_eq!(
            TreeNamespace::decode(&shard).unwrap(),
            TreeNamespace::CollectionShard(key, 15)
        );
        for malformed in [
            vec![2],
            vec![0, 0],
            TreeNamespace::CollectionShard(key, K_PROVISIONAL).encode(),
        ] {
            assert!(TreeNamespace::decode(&malformed).is_err());
        }
    }

    #[test]
    fn present_collection_rejects_missing_and_extra_root_records() {
        for extra in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let genesis_hash = B256::repeat_byte(if extra { 0x41 } else { 0x40 });
            let db = Arc::new(
                CeMdbx::open(
                    directory.path(),
                    identity(genesis_hash),
                    genesis(genesis_hash),
                )
                .unwrap(),
            );
            let id = tribute_id(20_260_720, 1);
            let collection = collection_key(CeDomain::Tribute, id).unwrap();
            let parent = MdbxAuthenticatedTree::open(
                Arc::clone(&db),
                ExactParentIdentity {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    block_number: 0,
                    block_hash: genesis_hash,
                    root: sealed_root(B256::ZERO).unwrap(),
                },
            )
            .unwrap();
            let staged = parent
                .prepare_seal(
                    1,
                    &[FinalLeafMutation {
                        entity: EntityRef::Tribute(id),
                        final_leaf: Some(Commitment::try_from(B256::with_last_byte(1).0).unwrap()),
                    }],
                    &[],
                )
                .unwrap()
                .freeze(B256::repeat_byte(0x42));
            db.apply_finalized(&staged).unwrap();

            let tx = db.db.tx_mut().unwrap();
            let namespace =
                TreeNamespace::CollectionShard(collection, if extra { K_PROVISIONAL } else { 0 });
            if extra {
                tx.put::<tables::CeTreeRoots>(namespace.encode(), B256::ZERO.as_slice().to_vec())
                    .unwrap();
            } else {
                tx.delete::<tables::CeTreeRoots>(namespace.encode(), None)
                    .unwrap();
            }
            tx.commit().unwrap();

            let reopened = MdbxAuthenticatedTree::open(
                Arc::clone(&db),
                ExactParentIdentity {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    block_number: 1,
                    block_hash: staged.block_hash(),
                    root: staged.new_root(),
                },
            )
            .unwrap();
            assert!(reopened
                .read_leaf_verified(EntityRef::Tribute(id), staged.new_root())
                .is_err());
        }
    }

    #[test]
    fn catalog_non_membership_rejects_orphan_collection_prefix_records() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x50);
        let db = Arc::new(
            CeMdbx::open(
                directory.path(),
                identity(genesis_hash),
                genesis(genesis_hash),
            )
            .unwrap(),
        );
        let id = tribute_id(20_260_721, 1);
        let collection = collection_key(CeDomain::Tribute, id).unwrap();
        let key = TreeKey::try_from(B256::with_last_byte(1)).unwrap();
        let tx = db.db.tx_mut().unwrap();
        tx.put::<tables::CeLeaves>(
            prefixed_key(TreeNamespace::CollectionShard(collection, 0), &key.encode()),
            LeafValue::try_from(B256::with_last_byte(1))
                .unwrap()
                .encode()
                .to_vec(),
        )
        .unwrap();
        tx.commit().unwrap();

        let parent = MdbxAuthenticatedTree::open(
            Arc::clone(&db),
            ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: sealed_root(B256::ZERO).unwrap(),
            },
        )
        .unwrap();
        assert!(parent
            .read_leaf_verified(EntityRef::Tribute(id), sealed_root(B256::ZERO).unwrap())
            .is_err());
    }

    #[test]
    fn identity_candidate_advances_only_marker_and_keeps_empty_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x60);
        let db = Arc::new(
            CeMdbx::open(
                directory.path(),
                identity(genesis_hash),
                genesis(genesis_hash),
            )
            .unwrap(),
        );
        let parent = MdbxAuthenticatedTree::open(
            Arc::clone(&db),
            ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: sealed_root(B256::ZERO).unwrap(),
            },
        )
        .unwrap();
        let staged = parent
            .prepare_seal(1, &[], &[])
            .unwrap()
            .freeze(B256::repeat_byte(0x61));
        assert!(staged.changed_collections.is_empty());
        assert!(staged.catalog_batch.is_none());
        assert_eq!(staged.parent_root(), staged.new_root());
        db.apply_finalized(&staged).unwrap();
        let snapshot = db.open_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_root(TreeNamespace::Catalog).unwrap(),
            Some(B256::ZERO)
        );
        assert_eq!(
            snapshot.marker().unwrap(),
            staged.marker(ACTIVE_COMMITMENT_SCHEME)
        );
    }
}

impl TreeNamespace {
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Catalog => vec![0],
            Self::CollectionShard(collection, shard) => {
                let mut bytes = Vec::with_capacity(37);
                bytes.push(1);
                bytes.extend_from_slice(collection.as_bytes());
                bytes.extend_from_slice(&shard.to_be_bytes());
                bytes
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        match bytes {
            [0] => Ok(Self::Catalog),
            [1, collection @ .., a, b, c, d] if collection.len() == 32 => {
                let collection = CollectionKey::try_from(B256::from_slice(collection))
                    .map_err(|_| PersistenceError::NonCanonicalTreeNamespace)?;
                let shard = u32::from_be_bytes([*a, *b, *c, *d]);
                if shard >= K_PROVISIONAL {
                    return Err(PersistenceError::InvalidNamespaceShard { shard });
                }
                Ok(Self::CollectionShard(collection, shard))
            }
            _ => Err(PersistenceError::NonCanonicalTreeNamespace),
        }
    }
}

/// Canonical BN254 field bytes. Zero is allowed for structural emptiness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldValue(B256);

impl FieldValue {
    #[must_use]
    pub const fn into_inner(self) -> B256 {
        self.0
    }

    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == B256::ZERO
    }

    #[must_use]
    pub const fn encode(self) -> [u8; 32] {
        self.0 .0
    }
}

impl TryFrom<B256> for FieldValue {
    type Error = PersistenceError;

    fn try_from(value: B256) -> Result<Self, Self::Error> {
        validate_field(value)?;
        Ok(Self(value))
    }
}

/// Exact CKB 256-level path key. Key zero is a valid position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TreeKey(FieldValue);

impl Ord for TreeKey {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.encode().iter().rev().cmp(other.encode().iter().rev())
    }
}

impl PartialOrd for TreeKey {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl TreeKey {
    #[must_use]
    pub const fn into_inner(self) -> B256 {
        self.0.into_inner()
    }

    #[must_use]
    pub const fn encode(self) -> [u8; 32] {
        self.0.encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        Ok(Self(FieldValue::try_from(decode_b256(bytes, "tree key")?)?))
    }
}

impl TryFrom<B256> for TreeKey {
    type Error = PersistenceError;

    fn try_from(value: B256) -> Result<Self, Self::Error> {
        Ok(Self(FieldValue::try_from(value)?))
    }
}

/// A persisted non-zero body leaf. Delete is represented by record absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafValue(FieldValue);

impl LeafValue {
    #[must_use]
    pub const fn into_inner(self) -> B256 {
        self.0.into_inner()
    }

    #[must_use]
    pub const fn encode(self) -> [u8; 32] {
        self.0.encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        Self::try_from(decode_b256(bytes, "leaf value")?)
    }
}

impl TryFrom<B256> for LeafValue {
    type Error = PersistenceError;

    fn try_from(value: B256) -> Result<Self, Self::Error> {
        let field = FieldValue::try_from(value)?;
        if field.is_zero() {
            return Err(PersistenceError::ZeroPersistedLeaf);
        }
        Ok(Self(field))
    }
}

/// A canonical CKB node path stored together with its height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BranchKey {
    pub height: u8,
    pub node_key: FieldValue,
}

impl Ord for BranchKey {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        self.height.cmp(&other.height).then_with(|| {
            self.node_key
                .encode()
                .iter()
                .rev()
                .cmp(other.node_key.encode().iter().rev())
        })
    }
}

impl PartialOrd for BranchKey {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl BranchKey {
    pub fn new(height: u8, node_key: B256) -> Result<Self, PersistenceError> {
        Ok(Self {
            height,
            node_key: FieldValue::try_from(node_key)?,
        })
    }

    #[must_use]
    pub fn encode(self) -> [u8; 33] {
        let mut bytes = [0_u8; 33];
        bytes[0] = self.height;
        bytes[1..].copy_from_slice(&self.node_key.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        if bytes.len() != 33 {
            return Err(PersistenceError::MalformedCodec {
                record: "branch key",
                expected: "33 bytes",
                actual: bytes.len(),
            });
        }
        Self::new(bytes[0], decode_b256(&bytes[1..], "branch node key")?)
    }
}

/// The only MergeValue variants retained by the vendored production subset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeValue {
    Value(FieldValue),
    MergeWithZero {
        base_node: FieldValue,
        zero_bits: FieldValue,
        zero_count: u8,
    },
}

impl MergeValue {
    #[must_use]
    pub fn encoded_len(self) -> usize {
        match self {
            Self::Value(_) => 33,
            Self::MergeWithZero { .. } => 66,
        }
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        match self {
            Self::Value(value) => {
                bytes.push(0);
                bytes.extend_from_slice(&value.encode());
            }
            Self::MergeWithZero {
                base_node,
                zero_bits,
                zero_count,
            } => {
                bytes.push(1);
                bytes.extend_from_slice(&base_node.encode());
                bytes.extend_from_slice(&zero_bits.encode());
                bytes.push(zero_count);
            }
        }
        bytes
    }

    fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), PersistenceError> {
        let Some(tag) = bytes.first().copied() else {
            return Err(PersistenceError::MalformedCodec {
                record: "merge value",
                expected: "tag and payload",
                actual: 0,
            });
        };
        match tag {
            0 if bytes.len() >= 33 => {
                let value = FieldValue::try_from(decode_b256(&bytes[1..33], "merge value")?)?;
                Ok((Self::Value(value), 33))
            }
            1 if bytes.len() >= 66 => {
                let base_node =
                    FieldValue::try_from(decode_b256(&bytes[1..33], "merge base node")?)?;
                let zero_bits =
                    FieldValue::try_from(decode_b256(&bytes[33..65], "merge zero bits")?)?;
                Ok((
                    Self::MergeWithZero {
                        base_node,
                        zero_bits,
                        zero_count: bytes[65],
                    },
                    66,
                ))
            }
            0 => Err(PersistenceError::MalformedCodec {
                record: "merge value",
                expected: "33 bytes",
                actual: bytes.len(),
            }),
            1 => Err(PersistenceError::MalformedCodec {
                record: "merge-with-zero value",
                expected: "66 bytes",
                actual: bytes.len(),
            }),
            actual => Err(PersistenceError::UnknownMergeValueTag(actual)),
        }
    }
}

/// CKB branch record value: two self-delimiting MergeValues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchNode {
    pub left: MergeValue,
    pub right: MergeValue,
}

impl BranchNode {
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = self.left.encode();
        bytes.extend_from_slice(&self.right.encode());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        let (left, consumed) = MergeValue::decode_prefix(bytes)?;
        let (right, right_consumed) = MergeValue::decode_prefix(&bytes[consumed..])?;
        let total = consumed
            .checked_add(right_consumed)
            .ok_or(PersistenceError::LengthOverflow)?;
        if total != bytes.len() {
            return Err(PersistenceError::TrailingBytes {
                record: "branch value",
                trailing: bytes.len() - total,
            });
        }
        Ok(Self { left, right })
    }
}

/// Persistent environment identity. A mismatch requires an explicit rebuild or
/// migration; it is never silently reinterpreted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentIdentity {
    pub local_storage_schema_version: u32,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub commitment_scheme_version: u32,
    pub topology: Vec<u8>,
    pub tree_format: String,
    pub vendor_revision: String,
}

impl EnvironmentIdentity {
    pub fn encode(&self) -> Result<Vec<u8>, PersistenceError> {
        let tree = self.tree_format.as_bytes();
        let vendor = self.vendor_revision.as_bytes();
        let tree_len = u16::try_from(tree.len()).map_err(|_| PersistenceError::LengthOverflow)?;
        let vendor_len =
            u16::try_from(vendor.len()).map_err(|_| PersistenceError::LengthOverflow)?;
        let topology_len =
            u16::try_from(self.topology.len()).map_err(|_| PersistenceError::LengthOverflow)?;
        crate::CeTopologyV1::decode(&self.topology)
            .map_err(|_| PersistenceError::InvalidTopologyIdentity)?;
        let mut bytes = Vec::with_capacity(58 + self.topology.len() + tree.len() + vendor.len());
        bytes.extend_from_slice(&self.local_storage_schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.chain_id.to_be_bytes());
        bytes.extend_from_slice(self.genesis_hash.as_slice());
        bytes.extend_from_slice(&self.commitment_scheme_version.to_be_bytes());
        bytes.extend_from_slice(&topology_len.to_be_bytes());
        bytes.extend_from_slice(&self.topology);
        bytes.extend_from_slice(&tree_len.to_be_bytes());
        bytes.extend_from_slice(tree);
        bytes.extend_from_slice(&vendor_len.to_be_bytes());
        bytes.extend_from_slice(vendor);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        let mut decoder = Decoder::new(bytes, "environment identity");
        let local_storage_schema_version = decoder.u32()?;
        let chain_id = decoder.u64()?;
        let genesis_hash = decoder.b256()?;
        let commitment_scheme_version = decoder.u32()?;
        let topology_len = decoder.u16()?;
        let topology = decoder.take(usize::from(topology_len))?.to_vec();
        crate::CeTopologyV1::decode(&topology)
            .map_err(|_| PersistenceError::InvalidTopologyIdentity)?;
        let tree_format = decoder.string_u16()?;
        let vendor_revision = decoder.string_u16()?;
        decoder.finish()?;
        Ok(Self {
            local_storage_schema_version,
            chain_id,
            genesis_hash,
            commitment_scheme_version,
            topology,
            tree_format,
            vendor_revision,
        })
    }
}

/// Atomic finalized progress marker, encoded exactly as specified by ADR-008.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedMarker {
    pub commitment_scheme_version: u32,
    pub height: u64,
    pub block_hash: B256,
    pub parent_block_hash: B256,
    pub parent_root: B256,
    pub new_root: B256,
}

impl FinalizedMarker {
    #[must_use]
    pub fn encode(self) -> [u8; FINALIZED_MARKER_ENCODED_LEN] {
        let mut bytes = [0_u8; FINALIZED_MARKER_ENCODED_LEN];
        bytes[0..4].copy_from_slice(&self.commitment_scheme_version.to_be_bytes());
        bytes[4..12].copy_from_slice(&self.height.to_be_bytes());
        bytes[12..44].copy_from_slice(self.block_hash.as_slice());
        bytes[44..76].copy_from_slice(self.parent_block_hash.as_slice());
        bytes[76..108].copy_from_slice(self.parent_root.as_slice());
        bytes[108..140].copy_from_slice(self.new_root.as_slice());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        if bytes.len() != FINALIZED_MARKER_ENCODED_LEN {
            return Err(PersistenceError::MalformedCodec {
                record: "last_applied",
                expected: "140 bytes",
                actual: bytes.len(),
            });
        }
        let mut decoder = Decoder::new(bytes, "last_applied");
        let marker = Self {
            commitment_scheme_version: decoder.u32()?,
            height: decoder.u64()?,
            block_hash: decoder.b256()?,
            parent_block_hash: decoder.b256()?,
            parent_root: decoder.b256()?,
            new_root: decoder.b256()?,
        };
        decoder.finish()?;
        validate_root(marker.parent_root)?;
        validate_root(marker.new_root)?;
        Ok(marker)
    }

    pub fn verify_exact_parent(
        self,
        required: ExactParentIdentity,
    ) -> Result<(), PersistenceError> {
        if self.commitment_scheme_version != required.commitment_scheme_version
            || self.height != required.block_number
            || self.block_hash != required.block_hash
            || self.new_root != required.root
        {
            return Err(PersistenceError::ExactParentMismatch {
                required,
                actual: self,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactParentIdentity {
    pub commitment_scheme_version: u32,
    pub block_number: u64,
    pub block_hash: B256,
    /// The root read from the exact parent's authoritative EVM slot.
    pub root: B256,
}

/// The durable finalized EVM/finality checkpoint used during restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableFinalizedCheckpoint {
    pub commitment_scheme_version: u32,
    pub height: u64,
    pub block_hash: B256,
    pub root: B256,
    pub parent_block_hash: B256,
    pub parent_root: B256,
    pub consensus_finalized_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartClassification {
    Equal,
    Behind { first_missing: u64, target: u64 },
    Ahead,
    Conflict,
}

pub fn classify_restart(
    marker: FinalizedMarker,
    durable: DurableFinalizedCheckpoint,
) -> RestartClassification {
    if marker.commitment_scheme_version != durable.commitment_scheme_version {
        return RestartClassification::Conflict;
    }
    if marker.height > durable.height || marker.height > durable.consensus_finalized_height {
        return RestartClassification::Ahead;
    }
    if marker.height < durable.height {
        return RestartClassification::Behind {
            first_missing: marker.height.saturating_add(1),
            target: durable.height.min(durable.consensus_finalized_height),
        };
    }
    if marker.block_hash == durable.block_hash
        && marker.new_root == durable.root
        && marker.parent_block_hash == durable.parent_block_hash
        && marker.parent_root == durable.parent_root
    {
        RestartClassification::Equal
    } else {
        RestartClassification::Conflict
    }
}

/// Local pruning fence. It is seeded only from a root-verified marker and moves
/// only after a known-successful CE transaction.
#[derive(Debug)]
pub struct CeRetentionCursor(AtomicU64);

impl CeRetentionCursor {
    #[must_use]
    pub const fn from_verified_marker(marker: FinalizedMarker) -> Self {
        Self(AtomicU64::new(marker.height))
    }

    #[must_use]
    pub fn height(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    pub fn advance_after_known_commit(
        &self,
        previous: FinalizedMarker,
        committed: FinalizedMarker,
    ) -> Result<(), PersistenceError> {
        if committed.height != previous.height.saturating_add(1) || self.height() != previous.height
        {
            return Err(PersistenceError::RetentionAdvanceOutOfOrder {
                cursor: self.height(),
                previous: previous.height,
                committed: committed.height,
            });
        }
        self.0.store(committed.height, Ordering::Release);
        Ok(())
    }

    /// Advances by one after a known-successful CE apply, or confirms an
    /// already-observed commit. This covers retry after an MDBX commit whose
    /// first return path was ambiguous without weakening contiguous progress.
    pub fn advance_or_confirm_after_known_commit(
        &self,
        committed: FinalizedMarker,
    ) -> Result<(), PersistenceError> {
        let current = self.height();
        if current == committed.height {
            return Ok(());
        }
        if committed.height != current.saturating_add(1) {
            return Err(PersistenceError::RetentionAdvanceOutOfOrder {
                cursor: current,
                previous: current,
                committed: committed.height,
            });
        }
        self.0
            .compare_exchange(
                current,
                committed.height,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|actual| PersistenceError::RetentionAdvanceOutOfOrder {
                cursor: actual,
                previous: current,
                committed: committed.height,
            })?;
        Ok(())
    }
}

/// Crash-injection stages for the finalized persistence/ACK boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FinalizationStage {
    Delivered,
    MarshalDurable,
    RethFinalized,
    RethPersisted,
    ProviderVerified,
    CeCommitUnknown,
    CeCommitted,
    RetentionAdvanced,
    CacheRemoved,
    MarshalAcknowledged,
}

impl FinalizationStage {
    #[must_use]
    pub fn marshal_ack_allowed(self) -> bool {
        matches!(self, Self::CacheRemoved | Self::MarshalAcknowledged)
    }

    #[must_use]
    pub fn restart_requires_marker_classification(self) -> bool {
        matches!(self, Self::CeCommitUnknown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied(FinalizedMarker),
    AlreadyApplied(FinalizedMarker),
}

mod tables {
    use reth_db::{
        table::{Table, TableInfo},
        TableSet,
    };

    #[derive(Debug)]
    pub struct CeMetadata;
    impl Table for CeMetadata {
        const NAME: &'static str = "OutbeCompressedEntitiesMetadataV3";
        const DUPSORT: bool = false;
        type Key = Vec<u8>;
        type Value = Vec<u8>;
    }
    impl TableInfo for CeMetadata {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }
        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    #[derive(Debug)]
    pub struct CeBranches;
    impl Table for CeBranches {
        const NAME: &'static str = "OutbeCompressedEntitiesBranchesV3";
        const DUPSORT: bool = false;
        type Key = Vec<u8>;
        type Value = Vec<u8>;
    }
    impl TableInfo for CeBranches {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }
        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    #[derive(Debug)]
    pub struct CeLeaves;
    impl Table for CeLeaves {
        const NAME: &'static str = "OutbeCompressedEntitiesLeavesV3";
        const DUPSORT: bool = false;
        type Key = Vec<u8>;
        type Value = Vec<u8>;
    }
    impl TableInfo for CeLeaves {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }
        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    #[derive(Debug)]
    pub struct CeTreeRoots;
    impl Table for CeTreeRoots {
        const NAME: &'static str = "OutbeCompressedEntitiesTreeRootsV3";
        const DUPSORT: bool = false;
        type Key = Vec<u8>;
        type Value = Vec<u8>;
    }
    impl TableInfo for CeTreeRoots {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }
        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    #[derive(Debug)]
    pub struct CeTables;
    impl TableSet for CeTables {
        fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
            Box::new(
                [
                    Box::new(CeMetadata) as Box<dyn TableInfo>,
                    Box::new(CeBranches) as Box<dyn TableInfo>,
                    Box::new(CeLeaves) as Box<dyn TableInfo>,
                    Box::new(CeTreeRoots) as Box<dyn TableInfo>,
                ]
                .into_iter(),
            )
        }
    }
}

/// Separate CE-owned MDBX environment. It does not share Reth's primary DB.
#[derive(Debug)]
pub struct CeMdbx {
    path: PathBuf,
    identity: EnvironmentIdentity,
    db: DatabaseEnv,
}

/// Exporter-side view of the fixed CE environment.
///
/// This type is deliberately distinct from [`CeMdbx`]: it opens MDBX in
/// `Mode::ReadOnly`, exposes no mutation method and can only create an exact
/// authenticated finalized snapshot.
#[derive(Debug)]
pub struct CeMdbxReadOnly {
    path: PathBuf,
    identity: EnvironmentIdentity,
    db: DatabaseEnv,
}

impl CeMdbxReadOnly {
    /// Opens the service-manager-configured CE environment without creating a
    /// directory, table or record.
    pub fn open(
        datadir: &Path,
        expected_identity: EnvironmentIdentity,
    ) -> Result<Self, PersistenceError> {
        validate_expected_environment_identity(&expected_identity)?;
        let path = datadir.join(CE_SMT_RELATIVE_PATH);
        let args = DatabaseArguments::new(ClientVersion::default());
        let db = open_db_read_only(&path, args).map_err(|error| PersistenceError::Database {
            path: path.clone(),
            message: format!("{error:#}"),
        })?;
        let store = Self {
            path,
            identity: expected_identity,
            db,
        };
        store.verify_existing()?;
        Ok(store)
    }

    #[must_use]
    pub const fn identity(&self) -> &EnvironmentIdentity {
        &self.identity
    }

    pub fn marker(&self) -> Result<FinalizedMarker, PersistenceError> {
        let tx = self.tx()?;
        let marker = read_marker(&tx, &self.path)?;
        tx.commit().map_err(|error| self.db_error(error))?;
        Ok(marker)
    }

    /// Opens one immutable transaction and rejects any marker/root mismatch
    /// before returning the view.
    pub fn open_exact(
        &self,
        required: ExactParentIdentity,
    ) -> Result<crate::staging::AuthenticatedCatalogView, PersistenceError> {
        let snapshot = self.open_snapshot()?;
        crate::staging::AuthenticatedCatalogView::open(snapshot, required)
            .map_err(|error| PersistenceError::Staging(error.to_string()))
    }

    fn open_snapshot(&self) -> Result<Box<dyn FinalizedTreeSnapshot>, PersistenceError> {
        let tx = self.tx()?;
        let marker = read_marker(&tx, &self.path)?;
        let catalog_root = read_required_tree_root(&tx, &self.path, TreeNamespace::Catalog)?;
        let wrapped = crate::sealed_root(catalog_root)
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        if wrapped != marker.new_root {
            return Err(PersistenceError::CatalogWrapperMismatch {
                expected: marker.new_root,
                actual: wrapped,
            });
        }
        Ok(Box::new(MdbxSnapshot {
            path: self.path.clone(),
            tx,
            marker,
        }))
    }

    fn verify_existing(&self) -> Result<(), PersistenceError> {
        let tx = self.tx()?;
        let stored_identity = tx
            .get::<tables::CeMetadata>(IDENTITY_KEY.to_vec())
            .map_err(|error| self.db_error(error))?;
        let stored_marker = tx
            .get::<tables::CeMetadata>(LAST_APPLIED_KEY.to_vec())
            .map_err(|error| self.db_error(error))?;
        let (Some(identity), Some(marker)) = (stored_identity, stored_marker) else {
            return Err(PersistenceError::PartialEnvironmentInitialization);
        };
        let actual_identity = EnvironmentIdentity::decode(&identity)?;
        if actual_identity != self.identity {
            return Err(PersistenceError::EnvironmentIdentityMismatch {
                expected: self.identity.clone(),
                actual: actual_identity,
            });
        }
        let marker = FinalizedMarker::decode(&marker)?;
        if marker.commitment_scheme_version != self.identity.commitment_scheme_version {
            return Err(PersistenceError::EnvironmentMarkerSchemeMismatch);
        }
        let catalog_root = read_required_tree_root(&tx, &self.path, TreeNamespace::Catalog)?;
        let wrapped = crate::sealed_root(catalog_root)
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        if wrapped != marker.new_root {
            return Err(PersistenceError::CatalogWrapperMismatch {
                expected: marker.new_root,
                actual: wrapped,
            });
        }
        tx.commit().map_err(|error| self.db_error(error))
    }

    fn tx(&self) -> Result<Tx<RO>, PersistenceError> {
        self.db.tx().map_err(|error| self.db_error(error))
    }

    fn db_error(&self, error: impl std::fmt::Display) -> PersistenceError {
        PersistenceError::Database {
            path: self.path.clone(),
            message: error.to_string(),
        }
    }
}

impl CeMdbx {
    /// Opens `<datadir>/compressed_entities/smt/`, initializes an empty
    /// environment atomically, or verifies every existing identity field.
    pub fn open(
        datadir: &Path,
        expected_identity: EnvironmentIdentity,
        genesis_marker: FinalizedMarker,
    ) -> Result<Self, PersistenceError> {
        validate_expected_environment_identity(&expected_identity)?;
        if genesis_marker.height != 0 || genesis_marker.block_hash != expected_identity.genesis_hash
        {
            return Err(PersistenceError::InvalidGenesisMarker {
                expected_genesis_hash: expected_identity.genesis_hash,
                actual: genesis_marker,
            });
        }
        if genesis_marker.commitment_scheme_version != expected_identity.commitment_scheme_version {
            return Err(PersistenceError::EnvironmentMarkerSchemeMismatch);
        }
        validate_root(genesis_marker.parent_root)?;
        validate_root(genesis_marker.new_root)?;
        let expected_genesis_root = crate::sealed_root(B256::ZERO)
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        if genesis_marker.new_root != expected_genesis_root {
            return Err(PersistenceError::InvalidGenesisShardRoot {
                expected: expected_genesis_root,
                actual: genesis_marker.new_root,
            });
        }

        let path = datadir.join(CE_SMT_RELATIVE_PATH);
        std::fs::create_dir_all(&path).map_err(|error| PersistenceError::Io {
            path: path.clone(),
            message: error.to_string(),
        })?;
        let args = DatabaseArguments::new(ClientVersion::default());
        let client_version = args.client_version().clone();
        let mut db = create_db(&path, args).map_err(|error| PersistenceError::Database {
            path: path.clone(),
            message: error.to_string(),
        })?;
        db.create_and_track_tables_for::<tables::CeTables>()
            .map_err(|error| PersistenceError::Database {
                path: path.clone(),
                message: error.to_string(),
            })?;
        db.record_client_version(client_version)
            .map_err(|error| PersistenceError::Database {
                path: path.clone(),
                message: error.to_string(),
            })?;

        let store = Self {
            path,
            identity: expected_identity.clone(),
            db,
        };
        store.initialize_or_verify(&expected_identity, genesis_marker)?;
        Ok(store)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn identity(&self) -> &EnvironmentIdentity {
        &self.identity
    }

    pub fn marker(&self) -> Result<FinalizedMarker, PersistenceError> {
        let tx = self.tx()?;
        let marker = read_marker(&tx, &self.path)?;
        tx.commit().map_err(|error| self.db_error(error))?;
        Ok(marker)
    }

    /// Seeds an exact finalized parent for cross-crate executor tests without
    /// replaying every empty intermediate block. This is unavailable in
    /// production builds and preserves the persisted catalog/root invariant.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn test_seed_finalized_marker(
        &self,
        marker: FinalizedMarker,
    ) -> Result<(), PersistenceError> {
        if marker.commitment_scheme_version != self.identity.commitment_scheme_version {
            return Err(PersistenceError::EnvironmentMarkerSchemeMismatch);
        }
        validate_root(marker.parent_root)?;
        validate_root(marker.new_root)?;
        let tx = self.db.tx_mut().map_err(|error| self.db_error(error))?;
        let catalog_root = read_required_tree_root(&tx, &self.path, TreeNamespace::Catalog)?;
        let wrapped = crate::sealed_root(catalog_root)
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        if wrapped != marker.new_root {
            return Err(PersistenceError::CatalogWrapperMismatch {
                expected: marker.new_root,
                actual: wrapped,
            });
        }
        tx.put::<tables::CeMetadata>(LAST_APPLIED_KEY.to_vec(), marker.encode().to_vec())
            .map_err(|error| self.db_error(error))?;
        tx.commit()
            .map_err(|error| PersistenceError::CommitOutcomeUnknown {
                path: self.path.clone(),
                marker,
                message: error.to_string(),
            })
    }

    pub fn open_snapshot(&self) -> Result<Box<dyn FinalizedTreeSnapshot>, PersistenceError> {
        let tx = self.tx()?;
        let marker = read_marker(&tx, &self.path)?;
        let catalog_root = read_required_tree_root(&tx, &self.path, TreeNamespace::Catalog)?;
        let wrapped = crate::sealed_root(catalog_root)
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        if wrapped != marker.new_root {
            return Err(PersistenceError::CatalogWrapperMismatch {
                expected: marker.new_root,
                actual: wrapped,
            });
        }
        Ok(Box::new(MdbxSnapshot {
            path: self.path.clone(),
            tx,
            marker,
        }))
    }

    /// Atomically applies one contiguous finalized batch and writes the marker
    /// last. A commit error is explicitly reported as an unknown outcome.
    pub fn apply_finalized(
        &self,
        batch: &StagedTreeBatch,
    ) -> Result<ApplyOutcome, PersistenceError> {
        batch
            .validate_encoded_size()
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        validate_root(batch.parent_root())?;
        validate_root(batch.new_root())?;
        let next = batch.marker(self.identity.commitment_scheme_version);
        let tx = self.db.tx_mut().map_err(|error| self.db_error(error))?;
        let current = read_marker(&tx, &self.path)?;

        if next == current {
            tx.commit().map_err(|error| self.db_error(error))?;
            return Ok(ApplyOutcome::AlreadyApplied(current));
        }
        if next.height <= current.height {
            return Err(PersistenceError::ConflictingFinalizedMarker { current, next });
        }
        if next.height != current.height.saturating_add(1)
            || next.parent_block_hash != current.block_hash
            || next.parent_root != current.new_root
            || next.commitment_scheme_version != current.commitment_scheme_version
        {
            return Err(PersistenceError::NonContiguousFinalizedApply { current, next });
        }

        let parent_catalog = read_required_tree_root(&tx, &self.path, TreeNamespace::Catalog)?;
        if parent_catalog != batch.parent_catalog_root
            || crate::sealed_root(parent_catalog)
                .map_err(|error| PersistenceError::Staging(error.to_string()))?
                != current.new_root
        {
            return Err(PersistenceError::ParentCatalogRootMismatch);
        }

        for (collection_key, operation) in &batch.changed_collections {
            let catalog_key = TreeKey::try_from(B256::from(*collection_key.as_bytes()))?;
            let catalog_leaf =
                read_tree_leaf(&tx, &self.path, TreeNamespace::Catalog, catalog_key)?
                    .map(LeafValue::into_inner);
            match operation {
                crate::CollectionOperation::Mutate(collection) => {
                    let domain = crate::CeDomain::try_from(collection.domain_id)
                        .map_err(|_| PersistenceError::InvalidTopologyIdentity)?;
                    let shard_count = domain.shard_count();
                    if catalog_leaf != collection.parent_collection_root {
                        return Err(PersistenceError::ParentCatalogRootMismatch);
                    }
                    let persisted =
                        read_collection_roots(&tx, &self.path, *collection_key, shard_count)?;
                    match (&persisted, collection.parent_collection_root) {
                        (None, None) => {
                            if collection_has_records(&tx, &self.path, *collection_key)? {
                                return Err(PersistenceError::OrphanCollectionRecords {
                                    collection: *collection_key,
                                });
                            }
                        }
                        (Some(roots), Some(_))
                            if roots == &collection.shard_set.parent_shard_roots => {}
                        _ => return Err(PersistenceError::ParentShardRootsMismatch),
                    }

                    for shard_index in 0..shard_count {
                        let namespace =
                            TreeNamespace::CollectionShard(*collection_key, shard_index);
                        let position = usize::try_from(shard_index).map_err(|_| {
                            PersistenceError::InvalidShardCount {
                                actual: shard_index,
                            }
                        })?;
                        if let Some(shard) = collection.shard_set.changed_shards.get(&shard_index) {
                            apply_tree_changes(&tx, self, namespace, shard)?;
                        }
                        tx.put::<tables::CeTreeRoots>(
                            namespace.encode(),
                            collection.shard_set.new_shard_roots[position]
                                .as_slice()
                                .to_vec(),
                        )
                        .map_err(|error| self.db_error(error))?;
                    }
                    let top = aggregate_b256_shard_roots(&collection.shard_set.new_shard_roots)
                        .map_err(|error| PersistenceError::Staging(error.to_string()))?;
                    let recomputed = crate::collection_root(domain, *collection_key, top)
                        .map_err(|error| PersistenceError::Staging(error.to_string()))?;
                    if recomputed != collection.new_collection_root {
                        return Err(PersistenceError::NewCollectionRootMismatch);
                    }
                }
                crate::CollectionOperation::Retire(retirement) => {
                    let domain = crate::CeDomain::try_from(retirement.domain_id)
                        .map_err(|_| PersistenceError::InvalidTopologyIdentity)?;
                    if domain != crate::CeDomain::Tribute
                        || catalog_leaf != Some(retirement.parent_collection_root)
                    {
                        return Err(PersistenceError::ParentCatalogRootMismatch);
                    }
                    let persisted = read_collection_roots(
                        &tx,
                        &self.path,
                        *collection_key,
                        domain.shard_count(),
                    )?;
                    if persisted.as_ref() != Some(&retirement.parent_shard_roots) {
                        return Err(PersistenceError::ParentShardRootsMismatch);
                    }
                    let top = aggregate_b256_shard_roots(&retirement.parent_shard_roots)
                        .map_err(|error| PersistenceError::Staging(error.to_string()))?;
                    if crate::collection_root(domain, *collection_key, top)
                        .map_err(|error| PersistenceError::Staging(error.to_string()))?
                        != retirement.parent_collection_root
                    {
                        return Err(PersistenceError::ParentCatalogRootMismatch);
                    }
                    delete_collection_records(&tx, self, *collection_key)?;
                }
            }
        }

        if let Some(catalog) = &batch.catalog_batch {
            apply_raw_tree_changes(
                &tx,
                self,
                TreeNamespace::Catalog,
                &catalog.branch_changes,
                &catalog.leaf_changes,
            )?;
            tx.put::<tables::CeTreeRoots>(
                TreeNamespace::Catalog.encode(),
                batch.new_catalog_root.as_slice().to_vec(),
            )
            .map_err(|error| self.db_error(error))?;
        }
        let wrapped = crate::sealed_root(batch.new_catalog_root)
            .map_err(|error| PersistenceError::Staging(error.to_string()))?;
        if wrapped != batch.new_root() {
            return Err(PersistenceError::CatalogWrapperMismatch {
                expected: batch.new_root(),
                actual: wrapped,
            });
        }
        // Progress is deliberately the final write in this transaction.
        tx.put::<tables::CeMetadata>(LAST_APPLIED_KEY.to_vec(), next.encode().to_vec())
            .map_err(|error| self.db_error(error))?;
        tx.commit()
            .map_err(|error| PersistenceError::CommitOutcomeUnknown {
                path: self.path.clone(),
                marker: next,
                message: error.to_string(),
            })?;
        Ok(ApplyOutcome::Applied(next))
    }

    fn initialize_or_verify(
        &self,
        expected_identity: &EnvironmentIdentity,
        genesis_marker: FinalizedMarker,
    ) -> Result<(), PersistenceError> {
        let tx = self.db.tx().map_err(|error| self.db_error(error))?;
        let stored_identity = tx
            .get::<tables::CeMetadata>(IDENTITY_KEY.to_vec())
            .map_err(|error| self.db_error(error))?;
        let stored_marker = tx
            .get::<tables::CeMetadata>(LAST_APPLIED_KEY.to_vec())
            .map_err(|error| self.db_error(error))?;
        let branch_records = tx
            .entries::<tables::CeBranches>()
            .map_err(|error| self.db_error(error))?;
        let leaf_records = tx
            .entries::<tables::CeLeaves>()
            .map_err(|error| self.db_error(error))?;
        let shard_root_records = tx
            .entries::<tables::CeTreeRoots>()
            .map_err(|error| self.db_error(error))?;
        tx.commit().map_err(|error| self.db_error(error))?;

        match (stored_identity, stored_marker) {
            (None, None) => {
                if branch_records != 0 || leaf_records != 0 || shard_root_records != 0 {
                    return Err(PersistenceError::OrphanTreeRecords {
                        branches: branch_records,
                        leaves: leaf_records,
                        shard_roots: shard_root_records,
                    });
                }
                let identity = expected_identity.encode()?;
                let tx = self.db.tx_mut().map_err(|error| self.db_error(error))?;
                tx.put::<tables::CeMetadata>(IDENTITY_KEY.to_vec(), identity)
                    .map_err(|error| self.db_error(error))?;
                tx.put::<tables::CeTreeRoots>(
                    TreeNamespace::Catalog.encode(),
                    B256::ZERO.as_slice().to_vec(),
                )
                .map_err(|error| self.db_error(error))?;
                tx.put::<tables::CeMetadata>(
                    LAST_APPLIED_KEY.to_vec(),
                    genesis_marker.encode().to_vec(),
                )
                .map_err(|error| self.db_error(error))?;
                tx.commit()
                    .map_err(|error| PersistenceError::CommitOutcomeUnknown {
                        path: self.path.clone(),
                        marker: genesis_marker,
                        message: error.to_string(),
                    })?;
            }
            (Some(identity), Some(marker)) => {
                let actual_identity = EnvironmentIdentity::decode(&identity)?;
                if &actual_identity != expected_identity {
                    return Err(PersistenceError::EnvironmentIdentityMismatch {
                        expected: expected_identity.clone(),
                        actual: actual_identity,
                    });
                }
                let marker = FinalizedMarker::decode(&marker)?;
                if marker.commitment_scheme_version != expected_identity.commitment_scheme_version {
                    return Err(PersistenceError::EnvironmentMarkerSchemeMismatch);
                }
                let tx = self.tx()?;
                let catalog_root =
                    read_required_tree_root(&tx, &self.path, TreeNamespace::Catalog)?;
                let wrapped = crate::sealed_root(catalog_root)
                    .map_err(|error| PersistenceError::Staging(error.to_string()))?;
                if wrapped != marker.new_root {
                    return Err(PersistenceError::CatalogWrapperMismatch {
                        expected: marker.new_root,
                        actual: wrapped,
                    });
                }
                tx.commit().map_err(|error| self.db_error(error))?;
            }
            _ => return Err(PersistenceError::PartialEnvironmentInitialization),
        }
        Ok(())
    }

    fn tx(&self) -> Result<Tx<RO>, PersistenceError> {
        self.db.tx().map_err(|error| self.db_error(error))
    }

    fn db_error(&self, error: impl std::fmt::Display) -> PersistenceError {
        PersistenceError::Database {
            path: self.path.clone(),
            message: error.to_string(),
        }
    }
}

fn validate_expected_environment_identity(
    expected_identity: &EnvironmentIdentity,
) -> Result<(), PersistenceError> {
    if expected_identity.local_storage_schema_version != LOCAL_STORAGE_SCHEMA_VERSION {
        return Err(PersistenceError::UnsupportedLocalSchema {
            actual: expected_identity.local_storage_schema_version,
        });
    }
    if expected_identity.tree_format.is_empty() || expected_identity.vendor_revision.is_empty() {
        return Err(PersistenceError::EmptyEnvironmentIdentityField);
    }
    crate::CeTopologyV1::decode(&expected_identity.topology)
        .map_err(|_| PersistenceError::InvalidTopologyIdentity)?;
    Ok(())
}

fn apply_tree_changes<T: DbTxMut>(
    tx: &T,
    db: &CeMdbx,
    namespace: TreeNamespace,
    batch: &ProvisionalShardBatch,
) -> Result<(), PersistenceError> {
    apply_raw_tree_changes(
        tx,
        db,
        namespace,
        &batch.branch_changes,
        &batch.leaf_changes,
    )
}

fn apply_raw_tree_changes<T: DbTxMut>(
    tx: &T,
    db: &CeMdbx,
    namespace: TreeNamespace,
    branches: &std::collections::BTreeMap<BranchKey, TreeChange<BranchNode>>,
    leaves: &std::collections::BTreeMap<TreeKey, TreeChange<LeafValue>>,
) -> Result<(), PersistenceError> {
    for (key, change) in branches {
        let key = prefixed_key(namespace, &key.encode());
        match change {
            TreeChange::Set(node) => tx
                .put::<tables::CeBranches>(key, node.encode())
                .map_err(|error| db.db_error(error))?,
            TreeChange::Delete => {
                tx.delete::<tables::CeBranches>(key, None)
                    .map_err(|error| db.db_error(error))?;
            }
        }
    }
    for (key, change) in leaves {
        let key = prefixed_key(namespace, &key.encode());
        match change {
            TreeChange::Set(value) => tx
                .put::<tables::CeLeaves>(key, value.encode().to_vec())
                .map_err(|error| db.db_error(error))?,
            TreeChange::Delete => {
                tx.delete::<tables::CeLeaves>(key, None)
                    .map_err(|error| db.db_error(error))?;
            }
        }
    }
    Ok(())
}

struct MdbxSnapshot {
    path: PathBuf,
    tx: Tx<RO>,
    marker: FinalizedMarker,
}

impl FinalizedTreeSnapshot for MdbxSnapshot {
    fn marker(&self) -> Result<FinalizedMarker, PersistenceError> {
        Ok(self.marker)
    }

    fn tree_root(&self, namespace: TreeNamespace) -> Result<Option<B256>, PersistenceError> {
        read_tree_root(&self.tx, &self.path, namespace)
    }

    fn collection_has_records(&self, collection: CollectionKey) -> Result<bool, PersistenceError> {
        collection_has_records(&self.tx, &self.path, collection)
    }

    fn collection_root_count(&self, collection: CollectionKey) -> Result<usize, PersistenceError> {
        count_collection_root_records(&self.tx, &self.path, collection)
    }

    fn collection_leaf_count(&self, collection: CollectionKey) -> Result<usize, PersistenceError> {
        count_collection_leaf_records(&self.tx, &self.path, collection)
    }

    fn read_branch(
        &self,
        namespace: TreeNamespace,
        key: BranchKey,
    ) -> Result<Option<BranchNode>, PersistenceError> {
        self.tx
            .get::<tables::CeBranches>(prefixed_key(namespace, &key.encode()))
            .map_err(|error| PersistenceError::Database {
                path: self.path.clone(),
                message: error.to_string(),
            })?
            .map(|bytes| BranchNode::decode(&bytes))
            .transpose()
    }

    fn read_leaf(
        &self,
        namespace: TreeNamespace,
        key: TreeKey,
    ) -> Result<Option<LeafValue>, PersistenceError> {
        self.tx
            .get::<tables::CeLeaves>(prefixed_key(namespace, &key.encode()))
            .map_err(|error| PersistenceError::Database {
                path: self.path.clone(),
                message: error.to_string(),
            })?
            .map(|bytes| LeafValue::decode(&bytes))
            .transpose()
    }
}

fn prefixed_key(namespace: TreeNamespace, key: &[u8]) -> Vec<u8> {
    let namespace = namespace.encode();
    let mut output = Vec::with_capacity(namespace.len() + key.len());
    output.extend_from_slice(&namespace);
    output.extend_from_slice(key);
    output
}

fn read_tree_leaf<T: DbTx>(
    tx: &T,
    path: &Path,
    namespace: TreeNamespace,
    key: TreeKey,
) -> Result<Option<LeafValue>, PersistenceError> {
    tx.get::<tables::CeLeaves>(prefixed_key(namespace, &key.encode()))
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .map(|bytes| LeafValue::decode(&bytes))
        .transpose()
}

fn read_tree_root<T: DbTx>(
    tx: &T,
    path: &Path,
    namespace: TreeNamespace,
) -> Result<Option<B256>, PersistenceError> {
    tx.get::<tables::CeTreeRoots>(namespace.encode())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .map(|bytes| {
            let root = decode_b256(&bytes, "tree root")?;
            validate_root(root)?;
            Ok(root)
        })
        .transpose()
}

fn read_required_tree_root<T: DbTx>(
    tx: &T,
    path: &Path,
    namespace: TreeNamespace,
) -> Result<B256, PersistenceError> {
    read_tree_root(tx, path, namespace)?.ok_or(PersistenceError::MissingTreeRoot { namespace })
}

fn read_collection_roots<T: DbTx>(
    tx: &T,
    path: &Path,
    collection: CollectionKey,
    shard_count: u32,
) -> Result<Option<Vec<B256>>, PersistenceError> {
    let actual = count_collection_root_records(tx, path, collection)?;
    if actual != 0 && actual != shard_count as usize {
        return Err(PersistenceError::CollectionRootCountMismatch {
            collection,
            expected: shard_count as usize,
            actual,
        });
    }
    let mut roots = Vec::with_capacity(shard_count as usize);
    let mut present = 0_usize;
    for shard in 0..shard_count {
        if let Some(root) =
            read_tree_root(tx, path, TreeNamespace::CollectionShard(collection, shard))?
        {
            present += 1;
            roots.push(root);
        } else {
            roots.push(B256::ZERO);
        }
    }
    if present == 0 && actual == 0 {
        Ok(None)
    } else if present == shard_count as usize && actual == shard_count as usize {
        Ok(Some(roots))
    } else {
        Err(PersistenceError::CollectionRootCountMismatch {
            collection,
            expected: shard_count as usize,
            actual: present,
        })
    }
}

fn count_collection_root_records<T: DbTx>(
    tx: &T,
    path: &Path,
    collection: CollectionKey,
) -> Result<usize, PersistenceError> {
    let prefix = collection_prefix(collection);
    let mut cursor =
        tx.cursor_read::<tables::CeTreeRoots>()
            .map_err(|error| PersistenceError::Database {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
    let mut entry = cursor
        .seek(prefix.clone())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    let mut count = 0_usize;
    while let Some((key, _)) = entry {
        if !key.starts_with(&prefix) {
            break;
        }
        let namespace = TreeNamespace::decode(&key)?;
        if !matches!(namespace, TreeNamespace::CollectionShard(actual, _) if actual == collection) {
            return Err(PersistenceError::NonCanonicalTreeNamespace);
        }
        count = count.saturating_add(1);
        entry = cursor.next().map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    }
    Ok(count)
}

fn count_collection_leaf_records<T: DbTx>(
    tx: &T,
    path: &Path,
    collection: CollectionKey,
) -> Result<usize, PersistenceError> {
    const NAMESPACE_BYTES: usize = 1 + 32 + 4;
    const LEAF_KEY_BYTES: usize = NAMESPACE_BYTES + 32;

    let prefix = collection_prefix(collection);
    let mut cursor =
        tx.cursor_read::<tables::CeLeaves>()
            .map_err(|error| PersistenceError::Database {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
    let mut entry = cursor
        .seek(prefix.clone())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    let mut count = 0_usize;
    while let Some((key, value)) = entry {
        if !key.starts_with(&prefix) {
            break;
        }
        if key.len() != LEAF_KEY_BYTES {
            return Err(PersistenceError::MalformedCollectionLeafKey);
        }
        let namespace = TreeNamespace::decode(&key[..NAMESPACE_BYTES])?;
        if !matches!(
            namespace,
            TreeNamespace::CollectionShard(actual, _) if actual == collection
        ) {
            return Err(PersistenceError::NonCanonicalTreeNamespace);
        }
        TreeKey::decode(&key[NAMESPACE_BYTES..])?;
        LeafValue::decode(&value)?;
        count = count
            .checked_add(1)
            .ok_or(PersistenceError::CollectionLeafCountOverflow)?;
        entry = cursor.next().map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    }
    Ok(count)
}

fn collection_prefix(collection: CollectionKey) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(33);
    prefix.push(1);
    prefix.extend_from_slice(collection.as_bytes());
    prefix
}

fn collection_has_records<T: DbTx>(
    tx: &T,
    path: &Path,
    collection: CollectionKey,
) -> Result<bool, PersistenceError> {
    let prefix = collection_prefix(collection);
    let mut roots =
        tx.cursor_read::<tables::CeTreeRoots>()
            .map_err(|error| PersistenceError::Database {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
    if roots
        .seek(prefix.clone())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .is_some_and(|(key, _)| key.starts_with(&prefix))
    {
        return Ok(true);
    }
    let mut branches =
        tx.cursor_read::<tables::CeBranches>()
            .map_err(|error| PersistenceError::Database {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
    if branches
        .seek(prefix.clone())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .is_some_and(|(key, _)| key.starts_with(&prefix))
    {
        return Ok(true);
    }
    let mut leaves =
        tx.cursor_read::<tables::CeLeaves>()
            .map_err(|error| PersistenceError::Database {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
    Ok(leaves
        .seek(prefix.clone())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .is_some_and(|(key, _)| key.starts_with(&prefix)))
}

fn delete_collection_records(
    tx: &(impl DbTxMut + DbTx),
    store: &CeMdbx,
    collection: CollectionKey,
) -> Result<(), PersistenceError> {
    let prefix = collection_prefix(collection);

    let root_keys = {
        let mut cursor = tx
            .cursor_read::<tables::CeTreeRoots>()
            .map_err(|error| store.db_error(error))?;
        collect_prefixed_keys::<tables::CeTreeRoots, _>(&mut cursor, &prefix, store)?
    };
    let branch_keys = {
        let mut cursor = tx
            .cursor_read::<tables::CeBranches>()
            .map_err(|error| store.db_error(error))?;
        collect_prefixed_keys::<tables::CeBranches, _>(&mut cursor, &prefix, store)?
    };
    let leaf_keys = {
        let mut cursor = tx
            .cursor_read::<tables::CeLeaves>()
            .map_err(|error| store.db_error(error))?;
        collect_prefixed_keys::<tables::CeLeaves, _>(&mut cursor, &prefix, store)?
    };

    for key in root_keys {
        tx.delete::<tables::CeTreeRoots>(key, None)
            .map_err(|error| store.db_error(error))?;
    }
    for key in branch_keys {
        tx.delete::<tables::CeBranches>(key, None)
            .map_err(|error| store.db_error(error))?;
    }
    for key in leaf_keys {
        tx.delete::<tables::CeLeaves>(key, None)
            .map_err(|error| store.db_error(error))?;
    }
    Ok(())
}

fn collect_prefixed_keys<T, C>(
    cursor: &mut C,
    prefix: &[u8],
    store: &CeMdbx,
) -> Result<Vec<Vec<u8>>, PersistenceError>
where
    T: Table<Key = Vec<u8>, Value = Vec<u8>>,
    C: DbCursorRO<T>,
{
    let mut keys = Vec::new();
    let mut row = cursor
        .seek(prefix.to_vec())
        .map_err(|error| store.db_error(error))?;
    while let Some((key, _)) = row {
        if !key.starts_with(prefix) {
            break;
        }
        keys.push(key);
        row = cursor.next().map_err(|error| store.db_error(error))?;
    }
    Ok(keys)
}

fn read_marker<T: DbTx>(tx: &T, path: &Path) -> Result<FinalizedMarker, PersistenceError> {
    let bytes = tx
        .get::<tables::CeMetadata>(LAST_APPLIED_KEY.to_vec())
        .map_err(|error| PersistenceError::Database {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?
        .ok_or(PersistenceError::MissingFinalizedMarker)?;
    FinalizedMarker::decode(&bytes)
}

pub(crate) fn validate_root(root: B256) -> Result<(), PersistenceError> {
    validate_field(root)
}

fn validate_field(value: B256) -> Result<(), PersistenceError> {
    if value == B256::repeat_byte(0xff) {
        return Err(PersistenceError::HashPoison);
    }
    let field = Fr::from_be_bytes_mod_order(value.as_slice());
    let bytes = field.into_bigint().to_bytes_be();
    let mut canonical = [0_u8; 32];
    canonical[32 - bytes.len()..].copy_from_slice(&bytes);
    if canonical != value.0 {
        return Err(PersistenceError::NonCanonicalField);
    }
    Ok(())
}

fn decode_b256(bytes: &[u8], record: &'static str) -> Result<B256, PersistenceError> {
    if bytes.len() != 32 {
        return Err(PersistenceError::MalformedCodec {
            record,
            expected: "32 bytes",
            actual: bytes.len(),
        });
    }
    Ok(B256::from_slice(bytes))
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    record: &'static str,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8], record: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            record,
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PersistenceError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PersistenceError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PersistenceError::MalformedCodec {
                record: self.record,
                expected: "complete deterministic record",
                actual: self.bytes.len(),
            })?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, PersistenceError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    fn u16(&mut self) -> Result<u16, PersistenceError> {
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, PersistenceError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn b256(&mut self) -> Result<B256, PersistenceError> {
        Ok(B256::from_slice(self.take(32)?))
    }

    fn string_u16(&mut self) -> Result<String, PersistenceError> {
        let mut length = [0_u8; 2];
        length.copy_from_slice(self.take(2)?);
        let bytes = self.take(usize::from(u16::from_be_bytes(length)))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| PersistenceError::InvalidUtf8 {
            record: self.record,
        })
    }

    fn finish(self) -> Result<(), PersistenceError> {
        if self.offset != self.bytes.len() {
            return Err(PersistenceError::TrailingBytes {
                record: self.record,
                trailing: self.bytes.len() - self.offset,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("I/O error at {path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("MDBX error at {path}: {message}")]
    Database { path: PathBuf, message: String },
    #[error("MDBX commit outcome is unknown at {path} for marker {marker:?}: {message}")]
    CommitOutcomeUnknown {
        path: PathBuf,
        marker: FinalizedMarker,
        message: String,
    },
    #[error("unsupported CE local storage schema {actual}")]
    UnsupportedLocalSchema { actual: u32 },
    #[error("invalid CE shard count {actual}")]
    InvalidShardCount { actual: u32 },
    #[error("invalid canonical CE topology in environment identity")]
    InvalidTopologyIdentity,
    #[error("non-canonical CE tree namespace")]
    NonCanonicalTreeNamespace,
    #[error("CE tree namespace shard {shard} is outside the fork-fixed domain topology")]
    InvalidNamespaceShard { shard: u32 },
    #[error("CE batch shard count mismatch: expected {expected}, got {actual}")]
    ShardCountMismatch { expected: u32, actual: u32 },
    #[error("environment identity does not match: expected {expected:?}, actual {actual:?}")]
    EnvironmentIdentityMismatch {
        expected: EnvironmentIdentity,
        actual: EnvironmentIdentity,
    },
    #[error("environment identity and finalized marker are only partially initialized")]
    PartialEnvironmentInitialization,
    #[error(
        "CE MDBX contains tree records without identity/marker: {branches} branches, {leaves} leaves, {shard_roots} shard roots"
    )]
    OrphanTreeRecords {
        branches: usize,
        leaves: usize,
        shard_roots: usize,
    },
    #[error("environment and finalized marker commitment schemes differ")]
    EnvironmentMarkerSchemeMismatch,
    #[error("tree format and vendor revision must be non-empty")]
    EmptyEnvironmentIdentityField,
    #[error("invalid height-0 CE marker for genesis {expected_genesis_hash}: actual {actual:?}")]
    InvalidGenesisMarker {
        expected_genesis_hash: B256,
        actual: FinalizedMarker,
    },
    #[error("invalid height-0 shard top root: expected {expected}, got {actual}")]
    InvalidGenesisShardRoot { expected: B256, actual: B256 },
    #[error("finalized marker is missing")]
    MissingFinalizedMarker,
    #[error("missing persisted shard root {index}")]
    MissingShardRoot { index: u32 },
    #[error("missing persisted tree root for namespace {namespace:?}")]
    MissingTreeRoot { namespace: TreeNamespace },
    #[error("catalog sealed-root wrapper mismatch: expected {expected}, got {actual}")]
    CatalogWrapperMismatch { expected: B256, actual: B256 },
    #[error("persisted parent catalog root differs from candidate")]
    ParentCatalogRootMismatch,
    #[error("orphan records exist behind absent catalog collection {collection:?}")]
    OrphanCollectionRecords { collection: CollectionKey },
    #[error("collection {collection:?} root count mismatch: expected {expected}, got {actual}")]
    CollectionRootCountMismatch {
        collection: CollectionKey,
        expected: usize,
        actual: usize,
    },
    #[error("persisted collection leaf key is malformed")]
    MalformedCollectionLeafKey,
    #[error("persisted collection leaf count overflows usize")]
    CollectionLeafCountOverflow,
    #[error("recomputed collection root differs from candidate")]
    NewCollectionRootMismatch,
    #[error("persisted shard root count mismatch: expected {expected}, got {actual}")]
    ShardRootCountMismatch { expected: usize, actual: usize },
    #[error("persisted parent shard roots differ from candidate vector")]
    ParentShardRootsMismatch,
    #[error("persisted resulting shard roots differ from candidate vector")]
    NewShardRootsMismatch,
    #[error("shard-root aggregate mismatch: expected {expected}, got {actual}")]
    ShardRootAggregateMismatch { expected: B256, actual: B256 },
    #[error("malformed {record}: expected {expected}, got {actual} bytes")]
    MalformedCodec {
        record: &'static str,
        expected: &'static str,
        actual: usize,
    },
    #[error("unknown MergeValue tag {0}")]
    UnknownMergeValueTag(u8),
    #[error("trailing bytes in {record}: {trailing}")]
    TrailingBytes {
        record: &'static str,
        trailing: usize,
    },
    #[error("invalid UTF-8 in {record}")]
    InvalidUtf8 { record: &'static str },
    #[error("deterministic record length overflow")]
    LengthOverflow,
    #[error("non-canonical BN254 field element")]
    NonCanonicalField,
    #[error("CKB/Poseidon HASH_ERROR poison value")]
    HashPoison,
    #[error("zero cannot be persisted as a leaf value")]
    ZeroPersistedLeaf,
    #[error("exact parent mismatch: required {required:?}, marker {actual:?}")]
    ExactParentMismatch {
        required: ExactParentIdentity,
        actual: FinalizedMarker,
    },
    #[error("conflicting finalized marker: current {current:?}, next {next:?}")]
    ConflictingFinalizedMarker {
        current: FinalizedMarker,
        next: FinalizedMarker,
    },
    #[error("non-contiguous finalized apply: current {current:?}, next {next:?}")]
    NonContiguousFinalizedApply {
        current: FinalizedMarker,
        next: FinalizedMarker,
    },
    #[error(
        "retention cursor advance out of order: cursor {cursor}, previous {previous}, committed {committed}"
    )]
    RetentionAdvanceOutOfOrder {
        cursor: u64,
        previous: u64,
        committed: u64,
    },
    #[error("staged batch rejected: {0}")]
    Staging(String),
}

impl From<StagingError> for PersistenceError {
    fn from(error: StagingError) -> Self {
        Self::Staging(error.to_string())
    }
}

// ADR-009's flat-namespace fixtures are replaced by ADR-010 catalog fixtures below.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::{
        collection_root, sealed_root,
        staging::{
            CollectionBatch, CollectionOperation, ProvisionalCatalogBatch, ProvisionalShardBatch,
            ProvisionalShardSetBatch, ProvisionalTreeBatch,
        },
        CeDomain, CeTopologyV1, K_PROVISIONAL,
    };

    fn b256(last: u8) -> B256 {
        let mut bytes = [0_u8; 32];
        bytes[31] = last;
        B256::from(bytes)
    }

    fn marker(height: u64) -> FinalizedMarker {
        FinalizedMarker {
            commitment_scheme_version: 1,
            height,
            block_hash: b256(u8::try_from(height).unwrap()),
            parent_block_hash: b256(u8::try_from(height.saturating_sub(1)).unwrap()),
            parent_root: b256(u8::try_from(height.saturating_add(10)).unwrap()),
            new_root: b256(u8::try_from(height.saturating_add(11)).unwrap()),
        }
    }

    fn identity() -> EnvironmentIdentity {
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: 99,
            genesis_hash: b256(42),
            commitment_scheme_version: 1,
            topology: CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        }
    }

    fn sharded_identity(_shard_count: u32) -> EnvironmentIdentity {
        identity()
    }

    fn sharded_genesis(shard_count: u32) -> FinalizedMarker {
        let identity = sharded_identity(shard_count);
        FinalizedMarker {
            commitment_scheme_version: identity.commitment_scheme_version,
            height: 0,
            block_hash: identity.genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        }
    }

    fn legacy_collection_namespace(shard: u32) -> TreeNamespace {
        TreeNamespace::CollectionShard(CollectionKey::try_from(B256::ZERO).unwrap(), shard)
    }

    fn key_in_shard(shard: u32, ordinal: usize) -> TreeKey {
        (0..=u8::MAX)
            .map(|value| TreeKey::try_from(b256(value)).unwrap())
            .filter(|candidate| {
                let smt_key = crate::smt::TreeKey::from_be_bytes(candidate.encode()).unwrap();
                crate::sharding::shard_index(smt_key, K_PROVISIONAL).unwrap() == shard
            })
            .nth(ordinal)
            .unwrap()
    }

    #[test]
    fn typed_codecs_round_trip_and_reject_trailing_unknown_and_zero_leaf() {
        let field = FieldValue::try_from(b256(1)).unwrap();
        let node = BranchNode {
            left: MergeValue::Value(field),
            right: MergeValue::MergeWithZero {
                base_node: FieldValue::try_from(b256(2)).unwrap(),
                zero_bits: FieldValue::try_from(b256(3)).unwrap(),
                zero_count: 0,
            },
        };
        let encoded = node.encode();
        assert_eq!(BranchNode::decode(&encoded).unwrap(), node);
        let mut trailing = encoded;
        trailing.push(7);
        assert!(matches!(
            BranchNode::decode(&trailing),
            Err(PersistenceError::TrailingBytes { .. })
        ));
        assert!(matches!(
            BranchNode::decode(&[2; 66]),
            Err(PersistenceError::UnknownMergeValueTag(2))
        ));
        assert!(matches!(
            LeafValue::try_from(B256::ZERO),
            Err(PersistenceError::ZeroPersistedLeaf)
        ));
    }

    #[test]
    fn v3_tree_namespaces_are_typed_canonical_and_domain_bounded() {
        let entity = crate::WwdEntityId::from([7_u8; 32]);
        let collection = crate::collection_key(crate::CeDomain::NodItem, entity).unwrap();
        let namespaces = [
            TreeNamespace::Catalog,
            TreeNamespace::CollectionShard(collection, 0),
            TreeNamespace::CollectionShard(collection, K_PROVISIONAL - 1),
        ];
        for namespace in namespaces {
            let encoded = namespace.encode();
            assert_eq!(TreeNamespace::decode(&encoded).unwrap(), namespace);
        }
        assert!(TreeNamespace::decode(&[]).is_err());
        assert!(TreeNamespace::decode(&[2]).is_err());
        assert!(TreeNamespace::decode(&[0, 0]).is_err());
        assert!(TreeNamespace::decode(
            &TreeNamespace::CollectionShard(collection, K_PROVISIONAL).encode()
        )
        .is_err());
    }

    #[test]
    fn staged_tree_and_branch_keys_follow_ckb_reversed_byte_order() {
        let mut natural_high = [0_u8; 32];
        natural_high[0] = 2;
        let mut ckb_high = [0_u8; 32];
        ckb_high[31] = 1;
        let natural_high = B256::from(natural_high);
        let ckb_high = B256::from(ckb_high);

        assert!(TreeKey::try_from(natural_high).unwrap() < TreeKey::try_from(ckb_high).unwrap());
        assert!(BranchKey::new(7, natural_high).unwrap() < BranchKey::new(7, ckb_high).unwrap());
        assert!(BranchKey::new(6, ckb_high).unwrap() < BranchKey::new(7, natural_high).unwrap());
    }

    #[test]
    fn marker_and_environment_identity_have_deterministic_exact_codecs() {
        let value = marker(7);
        let encoded = value.encode();
        assert_eq!(encoded.len(), 140);
        assert_eq!(FinalizedMarker::decode(&encoded).unwrap(), value);
        assert!(FinalizedMarker::decode(&encoded[..139]).is_err());

        let environment = identity();
        let encoded = environment.encode().unwrap();
        assert_eq!(EnvironmentIdentity::decode(&encoded).unwrap(), environment);
        let mut trailing = encoded;
        trailing.push(1);
        assert!(matches!(
            EnvironmentIdentity::decode(&trailing),
            Err(PersistenceError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn restart_rows_distinguish_equal_behind_ahead_and_conflict() {
        let current = marker(7);
        let equal = DurableFinalizedCheckpoint {
            commitment_scheme_version: 1,
            height: 7,
            block_hash: current.block_hash,
            root: current.new_root,
            parent_block_hash: current.parent_block_hash,
            parent_root: current.parent_root,
            consensus_finalized_height: 7,
        };
        assert_eq!(
            classify_restart(current, equal),
            RestartClassification::Equal
        );

        let behind = DurableFinalizedCheckpoint {
            height: 9,
            consensus_finalized_height: 9,
            ..equal
        };
        assert_eq!(
            classify_restart(current, behind),
            RestartClassification::Behind {
                first_missing: 8,
                target: 9
            }
        );

        let ahead_marker = marker(10);
        assert_eq!(
            classify_restart(ahead_marker, behind),
            RestartClassification::Ahead
        );
        assert_eq!(
            classify_restart(
                current,
                DurableFinalizedCheckpoint {
                    block_hash: b256(99),
                    ..equal
                }
            ),
            RestartClassification::Conflict
        );
        assert_eq!(
            classify_restart(
                current,
                DurableFinalizedCheckpoint {
                    parent_root: b256(98),
                    ..equal
                }
            ),
            RestartClassification::Conflict
        );
    }

    #[test]
    fn ack_and_retention_require_known_successful_commit() {
        for stage in [
            FinalizationStage::Delivered,
            FinalizationStage::MarshalDurable,
            FinalizationStage::RethFinalized,
            FinalizationStage::RethPersisted,
            FinalizationStage::ProviderVerified,
            FinalizationStage::CeCommitUnknown,
            FinalizationStage::CeCommitted,
            FinalizationStage::RetentionAdvanced,
        ] {
            assert!(!stage.marshal_ack_allowed());
        }
        assert!(FinalizationStage::CacheRemoved.marshal_ack_allowed());
        assert!(FinalizationStage::CeCommitUnknown.restart_requires_marker_classification());

        let previous = marker(7);
        let committed = marker(8);
        let cursor = CeRetentionCursor::from_verified_marker(previous);
        cursor
            .advance_after_known_commit(previous, committed)
            .unwrap();
        assert_eq!(cursor.height(), 8);
        assert!(cursor
            .advance_after_known_commit(previous, committed)
            .is_err());
    }

    #[test]
    fn no_change_batch_still_carries_a_complete_next_marker() {
        let batch = crate::staging::ProvisionalTreeBatch::new_fixture_single_collection(
            8,
            b256(7),
            b256(18),
            b256(18),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .freeze(b256(8));
        let next = batch.marker(1);
        assert_eq!(next.height, 8);
        assert_eq!(next.parent_root, next.new_root);
        assert_eq!(next.block_hash, b256(8));
    }

    #[test]
    fn mdbx_applies_contiguous_batches_atomically_and_reopens_exact_marker() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = FinalizedMarker {
            commitment_scheme_version: 1,
            height: 0,
            block_hash: identity().genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        };
        let store = CeMdbx::open(directory.path(), identity(), genesis).unwrap();
        let tree_key = key_in_shard(0, 0);
        let leaf = LeafValue::try_from(b256(4)).unwrap();
        let branch_key = BranchKey::new(1, b256(5)).unwrap();
        let branch = BranchNode {
            left: MergeValue::Value(FieldValue::try_from(b256(6)).unwrap()),
            right: MergeValue::Value(FieldValue::try_from(b256(7)).unwrap()),
        };
        let batch = crate::staging::ProvisionalTreeBatch::new_fixture_single_collection(
            1,
            genesis.block_hash,
            genesis.new_root,
            b256(8),
            BTreeMap::from([(branch_key, TreeChange::Set(branch))]),
            BTreeMap::from([(tree_key, TreeChange::Set(leaf))]),
        )
        .unwrap()
        .freeze(b256(41));

        let applied = store.apply_finalized(&batch).unwrap();
        assert_eq!(applied, ApplyOutcome::Applied(batch.marker(1)));
        assert_eq!(
            store.apply_finalized(&batch).unwrap(),
            ApplyOutcome::AlreadyApplied(batch.marker(1))
        );
        let snapshot = store.open_snapshot().unwrap();
        assert_eq!(snapshot.marker().unwrap(), batch.marker(1));
        assert_eq!(
            snapshot
                .read_leaf(legacy_collection_namespace(0), tree_key)
                .unwrap(),
            Some(leaf)
        );
        assert_eq!(
            snapshot
                .read_branch(legacy_collection_namespace(0), branch_key)
                .unwrap(),
            Some(branch)
        );

        drop(snapshot);
        drop(store);
        let reopened = CeMdbx::open(directory.path(), identity(), genesis).unwrap();
        assert_eq!(reopened.marker().unwrap(), batch.marker(1));
    }

    #[test]
    fn mdbx_rejects_gap_conflict_and_bad_batch_before_persistent_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = FinalizedMarker {
            commitment_scheme_version: 1,
            height: 0,
            block_hash: identity().genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        };
        let store = CeMdbx::open(directory.path(), identity(), genesis).unwrap();
        let gap = crate::staging::ProvisionalTreeBatch::new_fixture_single_collection(
            2,
            genesis.block_hash,
            genesis.new_root,
            b256(51),
            BTreeMap::new(),
            BTreeMap::from([(
                key_in_shard(0, 0),
                TreeChange::Set(LeafValue::try_from(b256(2)).unwrap()),
            )]),
        )
        .unwrap()
        .freeze(b256(52));
        assert!(matches!(
            store.apply_finalized(&gap),
            Err(PersistenceError::NonContiguousFinalizedApply { .. })
        ));

        let mut malformed = crate::staging::ProvisionalTreeBatch::new_fixture_single_collection(
            1,
            genesis.block_hash,
            genesis.new_root,
            b256(51),
            BTreeMap::new(),
            BTreeMap::from([(
                key_in_shard(0, 0),
                TreeChange::Set(LeafValue::try_from(b256(2)).unwrap()),
            )]),
        )
        .unwrap()
        .freeze(b256(51));
        malformed.encoded_size = 1;
        assert!(matches!(
            store.apply_finalized(&malformed),
            Err(PersistenceError::Staging(_))
        ));
        assert_eq!(store.marker().unwrap(), genesis);
    }

    #[test]
    fn open_snapshot_remains_on_one_mdbx_read_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = FinalizedMarker {
            commitment_scheme_version: 1,
            height: 0,
            block_hash: identity().genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        };
        let store = CeMdbx::open(directory.path(), identity(), genesis).unwrap();
        let old_snapshot = store.open_snapshot().unwrap();
        let tree_key = key_in_shard(0, 1);
        let leaf = LeafValue::try_from(b256(11)).unwrap();
        let batch = crate::staging::ProvisionalTreeBatch::new_fixture_single_collection(
            1,
            genesis.block_hash,
            genesis.new_root,
            b256(12),
            BTreeMap::new(),
            BTreeMap::from([(tree_key, TreeChange::Set(leaf))]),
        )
        .unwrap()
        .freeze(b256(61));
        store.apply_finalized(&batch).unwrap();

        assert_eq!(old_snapshot.marker().unwrap(), genesis);
        assert_eq!(
            old_snapshot
                .read_leaf(legacy_collection_namespace(0), tree_key)
                .unwrap(),
            None
        );
        let new_snapshot = store.open_snapshot().unwrap();
        assert_eq!(new_snapshot.marker().unwrap(), batch.marker(1));
        assert_eq!(
            new_snapshot
                .read_leaf(legacy_collection_namespace(0), tree_key)
                .unwrap(),
            Some(leaf)
        );
    }

    #[test]
    fn reopen_rejects_environment_identity_drift() {
        let directory = tempfile::tempdir().unwrap();
        let genesis = FinalizedMarker {
            commitment_scheme_version: 1,
            height: 0,
            block_hash: identity().genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: sealed_root(B256::ZERO).unwrap(),
        };
        let store = CeMdbx::open(directory.path(), identity(), genesis).unwrap();
        drop(store);
        let mut wrong = identity();
        wrong.chain_id += 1;
        assert!(matches!(
            CeMdbx::open(directory.path(), wrong, genesis),
            Err(PersistenceError::EnvironmentIdentityMismatch { .. })
        ));
    }

    #[test]
    fn v3_initializes_only_catalog_and_rejects_topology_drift() {
        let directory = tempfile::tempdir().unwrap();
        let identity = sharded_identity(K_PROVISIONAL);
        let genesis = sharded_genesis(K_PROVISIONAL);
        assert_ne!(genesis.new_root, B256::ZERO);

        let store = CeMdbx::open(directory.path(), identity.clone(), genesis).unwrap();
        let snapshot = store.open_snapshot().unwrap();
        assert_eq!(
            snapshot.tree_root(TreeNamespace::Catalog).unwrap(),
            Some(B256::ZERO)
        );
        assert_eq!(snapshot.marker().unwrap(), genesis);
        drop(snapshot);
        drop(store);

        let mut wrong = identity;
        wrong.topology.push(0);
        assert!(matches!(
            CeMdbx::open(directory.path(), wrong, genesis),
            Err(PersistenceError::InvalidTopologyIdentity)
        ));
    }

    #[test]
    fn v3_collection_leaf_namespaces_are_isolated_by_typed_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let identity = sharded_identity(K_PROVISIONAL);
        let genesis = sharded_genesis(K_PROVISIONAL);
        let store = CeMdbx::open(directory.path(), identity, genesis).unwrap();
        let key = TreeKey::try_from(b256(3)).unwrap();
        let first = LeafValue::try_from(b256(4)).unwrap();
        let second = LeafValue::try_from(b256(5)).unwrap();
        let tx = store.db.tx_mut().unwrap();
        tx.put::<tables::CeLeaves>(
            prefixed_key(legacy_collection_namespace(1), &key.encode()),
            first.encode().to_vec(),
        )
        .unwrap();
        tx.put::<tables::CeLeaves>(
            prefixed_key(legacy_collection_namespace(2), &key.encode()),
            second.encode().to_vec(),
        )
        .unwrap();
        tx.commit().unwrap();

        let snapshot = store.open_snapshot().unwrap();
        assert_eq!(
            snapshot.read_leaf(TreeNamespace::Catalog, key).unwrap(),
            None
        );
        assert_eq!(
            snapshot
                .read_leaf(legacy_collection_namespace(1), key)
                .unwrap(),
            Some(first)
        );
        assert_eq!(
            snapshot
                .read_leaf(legacy_collection_namespace(2), key)
                .unwrap(),
            Some(second)
        );
    }

    #[test]
    fn v3_applies_two_changed_shards_and_catalog_leaf_under_one_marker() {
        let directory = tempfile::tempdir().unwrap();
        let identity = sharded_identity(K_PROVISIONAL);
        let genesis = sharded_genesis(K_PROVISIONAL);
        let store = CeMdbx::open(directory.path(), identity, genesis).unwrap();
        let key_one = TreeKey::try_from(b256(1)).unwrap();
        let key_two = TreeKey::try_from(b256(2)).unwrap();
        let leaf_one = LeafValue::try_from(b256(31)).unwrap();
        let leaf_two = LeafValue::try_from(b256(32)).unwrap();
        let mut new_roots = vec![B256::ZERO; K_PROVISIONAL as usize];
        new_roots[1] = b256(21);
        new_roots[2] = b256(22);
        let parent_roots = vec![B256::ZERO; K_PROVISIONAL as usize];
        let parent_top = aggregate_b256_shard_roots(&parent_roots).unwrap();
        let new_top = aggregate_b256_shard_roots(&new_roots).unwrap();
        let collection_key = CollectionKey::try_from(B256::ZERO).unwrap();
        let shard_set = ProvisionalShardSetBatch::new(
            K_PROVISIONAL,
            parent_top,
            new_top,
            parent_roots,
            new_roots,
            BTreeMap::from([
                (
                    1,
                    ProvisionalShardBatch::new(
                        B256::ZERO,
                        b256(21),
                        BTreeMap::new(),
                        BTreeMap::from([(key_one, TreeChange::Set(leaf_one))]),
                    )
                    .unwrap(),
                ),
                (
                    2,
                    ProvisionalShardBatch::new(
                        B256::ZERO,
                        b256(22),
                        BTreeMap::new(),
                        BTreeMap::from([(key_two, TreeChange::Set(leaf_two))]),
                    )
                    .unwrap(),
                ),
            ]),
        )
        .unwrap();
        let new_collection_root =
            collection_root(CeDomain::Tribute, collection_key, new_top).unwrap();
        let collection = CollectionBatch::new(
            CeDomain::Tribute,
            collection_key,
            None,
            new_collection_root,
            shard_set,
        )
        .unwrap();
        let parent_catalog_root = B256::ZERO;
        let new_catalog_root = b256(50);
        let catalog_key = TreeKey::try_from(B256::from(*collection_key.as_bytes())).unwrap();
        let batch = ProvisionalTreeBatch::new(
            1,
            genesis.block_hash,
            sealed_root(parent_catalog_root).unwrap(),
            sealed_root(new_catalog_root).unwrap(),
            parent_catalog_root,
            new_catalog_root,
            BTreeMap::from([(collection_key, CollectionOperation::Mutate(collection))]),
            Some(ProvisionalCatalogBatch {
                parent_catalog_root,
                new_catalog_root,
                branch_changes: BTreeMap::new(),
                leaf_changes: BTreeMap::from([(
                    catalog_key,
                    TreeChange::Set(LeafValue::try_from(new_collection_root).unwrap()),
                )]),
            }),
        )
        .unwrap()
        .freeze(b256(50));

        assert_eq!(batch.changed_shard_count(), 2);
        assert_eq!(batch.leaf_change_count(), 3);
        assert_eq!(
            store.apply_finalized(&batch).unwrap(),
            ApplyOutcome::Applied(batch.marker(1))
        );
        let snapshot = store.open_snapshot().unwrap();
        assert_eq!(snapshot.marker().unwrap(), batch.marker(1));
        assert_eq!(
            snapshot
                .read_leaf(TreeNamespace::CollectionShard(collection_key, 1), key_one)
                .unwrap(),
            Some(leaf_one)
        );
        assert_eq!(
            snapshot
                .read_leaf(TreeNamespace::CollectionShard(collection_key, 2), key_two)
                .unwrap(),
            Some(leaf_two)
        );
        assert_eq!(
            snapshot
                .read_leaf(TreeNamespace::CollectionShard(collection_key, 2), key_one)
                .unwrap(),
            None
        );
    }

    #[test]
    fn exporter_environment_is_really_read_only_at_the_mdbx_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let expected_identity = identity();
        let genesis = FinalizedMarker {
            commitment_scheme_version: expected_identity.commitment_scheme_version,
            height: 0,
            block_hash: expected_identity.genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: crate::sealed_root(B256::ZERO).unwrap(),
        };
        let writer = CeMdbx::open(directory.path(), expected_identity.clone(), genesis).unwrap();
        let expected = writer.marker().unwrap();
        drop(writer);
        let reader = CeMdbxReadOnly::open(directory.path(), expected_identity).unwrap();

        assert_eq!(reader.marker().unwrap(), expected);
        assert!(reader.db.tx_mut().is_err());
        assert!(reader
            .open_exact(ExactParentIdentity {
                commitment_scheme_version: expected.commitment_scheme_version,
                block_number: expected.height,
                block_hash: B256::repeat_byte(0xFF),
                root: expected.new_root,
            })
            .is_err());
    }
}
