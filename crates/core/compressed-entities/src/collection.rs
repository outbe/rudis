use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use thiserror::Error;

use crate::{
    commitment::{field_to_be32, poseidon},
    pbytes, PartitionRef, WwdEntityId, TAG_COLLECTION_KEY, TAG_COLLECTION_ROOT, TAG_KEY,
    TAG_SEALED_ROOT,
};

pub const K_PROVISIONAL: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum CeDomain {
    Tribute = 1,
    NodItem = 2,
    NodBucket = 3,
}

impl CeDomain {
    #[must_use]
    pub const fn id(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn shard_count(self) -> u32 {
        K_PROVISIONAL
    }

    const fn policy(self) -> PartitionPolicy {
        match self {
            Self::Tribute => PartitionPolicy::WwdBe4,
            Self::NodItem | Self::NodBucket => PartitionPolicy::Singleton,
        }
    }
}

impl TryFrom<u16> for CeDomain {
    type Error = CollectionError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tribute),
            2 => Ok(Self::NodItem),
            3 => Ok(Self::NodBucket),
            _ => Err(CollectionError::UnknownDomain(value)),
        }
    }
}

impl From<crate::schema::Collection> for CeDomain {
    fn from(value: crate::schema::Collection) -> Self {
        match value {
            crate::schema::Collection::Tribute => Self::Tribute,
            crate::schema::Collection::NodItem => Self::NodItem,
            crate::schema::Collection::NodBucket => Self::NodBucket,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PartitionPolicy {
    Singleton = 0,
    WwdBe4 = 1,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CollectionKey([u8; 32]);

impl CollectionKey {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Ord for CollectionKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for CollectionKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TryFrom<B256> for CollectionKey {
    type Error = CollectionError;

    fn try_from(value: B256) -> Result<Self, Self::Error> {
        let field = Fr::from_be_bytes_mod_order(value.as_slice());
        if field_to_be32(field) != value.0 {
            return Err(CollectionError::NonCanonicalCollectionKey);
        }
        Ok(Self(value.0))
    }
}

#[derive(Debug, Error)]
pub enum CollectionError {
    #[error("CES1 collection hashing failed: {0}")]
    Hash(String),
    #[error("present collection root computed to zero")]
    ZeroCollectionRoot,
    #[error("sealed root computed to zero")]
    ZeroSealedRoot,
    #[error("invalid CE topology descriptor")]
    InvalidTopology,
    #[error("collection key is not a canonical BN254 scalar")]
    NonCanonicalCollectionKey,
    #[error("unknown compressed-entity domain {0}")]
    UnknownDomain(u16),
    #[error("invalid canonical Tribute WWD partition {0}")]
    InvalidTributeWwd(u32),
    #[error("Tribute leaf belongs to WWD {actual}, expected {expected}")]
    TributeDayMismatch { expected: u32, actual: u32 },
    #[error("duplicate Tribute tree key in partition reconstruction")]
    DuplicateTributeKey,
    #[error("Tribute partition tree reconstruction failed: {0}")]
    Tree(String),
}

pub fn collection_key(
    domain: CeDomain,
    entity_id: WwdEntityId,
) -> Result<CollectionKey, CollectionError> {
    let mut input = Vec::with_capacity(11);
    input.extend_from_slice(&domain.id().to_be_bytes());
    match domain.policy() {
        PartitionPolicy::WwdBe4 => {
            input.push(1);
            input.extend_from_slice(&4_u32.to_be_bytes());
            input.extend_from_slice(&entity_id.as_slice()[..4]);
        }
        PartitionPolicy::Singleton => {
            input.push(0);
            input.extend_from_slice(&0_u32.to_be_bytes());
        }
    }
    pbytes(TAG_COLLECTION_KEY, &input)
        .map(CollectionKey)
        .map_err(|error| CollectionError::Hash(error.to_string()))
}

pub fn partition_collection_key(
    partition: PartitionRef,
) -> Result<(CeDomain, CollectionKey), CollectionError> {
    match partition {
        PartitionRef::TributeWwd(day) => {
            if !day.is_valid() {
                return Err(CollectionError::InvalidTributeWwd(day.value()));
            }
            let id = WwdEntityId::from_day_and_digest(day, B256::ZERO);
            collection_key(CeDomain::Tribute, id).map(|key| (CeDomain::Tribute, key))
        }
    }
}

pub(crate) fn tree_key_bytes(
    domain: CeDomain,
    entity_id: WwdEntityId,
) -> Result<[u8; 32], CollectionError> {
    let collection = collection_key(domain, entity_id)?;
    let identity = crate::identity_field(entity_id)
        .map_err(|error| CollectionError::Hash(error.to_string()))?;
    poseidon(
        TAG_KEY,
        &[
            Fr::from(crate::ACTIVE_COMMITMENT_SCHEME),
            Fr::from_be_bytes_mod_order(collection.as_bytes()),
            Fr::from_be_bytes_mod_order(&identity),
        ],
    )
    .map(field_to_be32)
    .map_err(|error| CollectionError::Hash(error.to_string()))
}

pub fn collection_root(
    domain: CeDomain,
    key: CollectionKey,
    shard_top_root: B256,
) -> Result<B256, CollectionError> {
    let root = poseidon(
        TAG_COLLECTION_ROOT,
        &[
            Fr::from(crate::ACTIVE_COMMITMENT_SCHEME),
            Fr::from_be_bytes_mod_order(key.as_bytes()),
            Fr::from(domain.shard_count()),
            Fr::from_be_bytes_mod_order(shard_top_root.as_slice()),
        ],
    )
    .map(field_to_be32)
    .map(B256::from)
    .map_err(|error| CollectionError::Hash(error.to_string()))?;
    if root == B256::ZERO {
        return Err(CollectionError::ZeroCollectionRoot);
    }
    Ok(root)
}

/// Reconstructs one independently sealed WWD Tribute collection root from its
/// exact `(entity id, body commitment)` leaves.
///
/// This is the public-RPC verification seam used by OCOMP: receipt payloads
/// supply bodies, but they are accepted only when their recomputed leaves close
/// to the collection root committed by the finalized `JobIntent`.
pub fn tribute_partition_root_from_leaves(
    day: outbe_primitives::time::WorldwideDay,
    leaves: impl IntoIterator<Item = (WwdEntityId, crate::Commitment)>,
) -> Result<B256, CollectionError> {
    use crate::{
        schema::Collection,
        sharding::{aggregate_b256_shard_roots, shard_index},
        smt::{derive_tree_key, PoseidonSmt, TreeLeaf},
    };
    use std::collections::{BTreeMap, BTreeSet};

    if !day.is_valid() {
        return Err(CollectionError::InvalidTributeWwd(day.value()));
    }
    let mut by_shard = BTreeMap::<u32, Vec<_>>::new();
    let mut seen = BTreeSet::new();
    for (entity_id, commitment) in leaves {
        if entity_id.worldwide_day() != day {
            return Err(CollectionError::TributeDayMismatch {
                expected: day.value(),
                actual: entity_id.worldwide_day().value(),
            });
        }
        let key = derive_tree_key(Collection::Tribute, entity_id)
            .map_err(|error| CollectionError::Tree(error.to_string()))?;
        if !seen.insert(key) {
            return Err(CollectionError::DuplicateTributeKey);
        }
        let shard = shard_index(key, CeDomain::Tribute.shard_count())
            .map_err(|error| CollectionError::Tree(error.to_string()))?;
        let leaf = TreeLeaf::from_be_bytes(*commitment.as_bytes())
            .map_err(|error| CollectionError::Tree(error.to_string()))?;
        by_shard.entry(shard).or_default().push((key, leaf));
    }

    let mut roots = vec![B256::ZERO; CeDomain::Tribute.shard_count() as usize];
    for (shard, updates) in by_shard {
        let mut tree = PoseidonSmt::empty();
        roots[shard as usize] = B256::from(
            tree.update_all(updates)
                .map_err(|error| CollectionError::Tree(error.to_string()))?
                .as_bytes(),
        );
    }
    let top = aggregate_b256_shard_roots(&roots)
        .map_err(|error| CollectionError::Tree(error.to_string()))?;
    let (_, key) = partition_collection_key(PartitionRef::TributeWwd(day))?;
    collection_root(CeDomain::Tribute, key, top)
}

pub fn sealed_root(catalog_root: B256) -> Result<B256, CollectionError> {
    let root = poseidon(
        TAG_SEALED_ROOT,
        &[
            Fr::from(crate::ACTIVE_COMMITMENT_SCHEME),
            Fr::from_be_bytes_mod_order(catalog_root.as_slice()),
        ],
    )
    .map(field_to_be32)
    .map(B256::from)
    .map_err(|error| CollectionError::Hash(error.to_string()))?;
    if root == B256::ZERO {
        return Err(CollectionError::ZeroSealedRoot);
    }
    Ok(root)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CeTopologyV1;

impl CeTopologyV1 {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + 3 * 11);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        for domain in [CeDomain::Tribute, CeDomain::NodItem, CeDomain::NodBucket] {
            bytes.extend_from_slice(&domain.id().to_be_bytes());
            bytes.push(domain.policy() as u8);
            bytes.extend_from_slice(
                &(if domain.policy() == PartitionPolicy::WwdBe4 {
                    4_u32
                } else {
                    0
                })
                .to_be_bytes(),
            );
            bytes.extend_from_slice(&domain.shard_count().to_be_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CollectionError> {
        let topology = Self;
        if bytes != topology.encode() {
            return Err(CollectionError::InvalidTopology);
        }
        Ok(topology)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> WwdEntityId {
        WwdEntityId::try_from(
            hex::decode("000000010405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .as_slice(),
        )
        .unwrap()
    }

    #[test]
    fn domains_and_topology_are_fork_fixed() {
        assert_eq!(CeDomain::Tribute.id(), 1);
        assert_eq!(CeDomain::NodItem.id(), 2);
        assert_eq!(CeDomain::NodBucket.id(), 3);
        assert_eq!(CeDomain::Tribute.shard_count(), 16);
        let encoded = CeTopologyV1.encode();
        assert_eq!(CeTopologyV1::decode(&encoded).unwrap(), CeTopologyV1);
        for malformed in [
            &encoded[..encoded.len() - 1],
            &[encoded.as_slice(), &[0]].concat(),
        ] {
            assert!(CeTopologyV1::decode(malformed).is_err());
        }
    }

    #[test]
    fn collection_keys_bind_domain_and_canonical_partition() {
        let id = identity();
        let keys = [
            collection_key(CeDomain::Tribute, id).unwrap(),
            collection_key(CeDomain::NodItem, id).unwrap(),
            collection_key(CeDomain::NodBucket, id).unwrap(),
        ];
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);

        let mut next_day: [u8; 32] = id.into();
        next_day[..4].copy_from_slice(&2_u32.to_be_bytes());
        let next_day = WwdEntityId::from(next_day);
        assert_ne!(
            collection_key(CeDomain::Tribute, id).unwrap(),
            collection_key(CeDomain::Tribute, next_day).unwrap()
        );
        assert_eq!(
            collection_key(CeDomain::NodItem, id).unwrap(),
            collection_key(CeDomain::NodItem, next_day).unwrap()
        );
    }

    #[test]
    fn empty_system_and_empty_present_collection_are_non_zero() {
        let key = collection_key(CeDomain::Tribute, identity()).unwrap();
        let top = crate::empty_shard_top_root(K_PROVISIONAL).unwrap();
        assert_ne!(
            collection_root(CeDomain::Tribute, key, top).unwrap(),
            B256::ZERO
        );
        assert_ne!(sealed_root(B256::ZERO).unwrap(), B256::ZERO);
    }

    #[test]
    fn adr010_golden_vectors_pin_topology_collection_tree_and_root_formulas() {
        let id = identity();
        let tribute = collection_key(CeDomain::Tribute, id).unwrap();
        let nod_item = collection_key(CeDomain::NodItem, id).unwrap();
        let nod_bucket = collection_key(CeDomain::NodBucket, id).unwrap();
        let top = crate::empty_shard_top_root(K_PROVISIONAL).unwrap();
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/adr010-catalog.json")).unwrap();
        assert_eq!(
            vectors["tribute_collection_preimage"].as_str().unwrap(),
            "0001010000000400000001"
        );
        assert_eq!(
            vectors["nod_item_collection_preimage"].as_str().unwrap(),
            "00020000000000"
        );
        assert_eq!(
            vectors["nod_bucket_collection_preimage"].as_str().unwrap(),
            "00030000000000"
        );
        assert_eq!(
            hex::encode(CeTopologyV1.encode()),
            vectors["topology_be"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(tribute.as_bytes()),
            vectors["tribute_collection_key"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(nod_item.as_bytes()),
            vectors["nod_item_collection_key"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(nod_bucket.as_bytes()),
            vectors["nod_bucket_collection_key"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(tree_key_bytes(CeDomain::Tribute, id).unwrap()),
            vectors["tribute_tree_key"].as_str().unwrap()
        );
        assert_eq!(
            format!("{top:#x}"),
            vectors["empty_shard_top"].as_str().unwrap()
        );
        assert_eq!(
            format!(
                "{:#x}",
                collection_root(CeDomain::Tribute, tribute, top).unwrap()
            ),
            vectors["empty_tribute_collection_root"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:#x}", sealed_root(B256::ZERO).unwrap()),
            vectors["empty_sealed_root"].as_str().unwrap()
        );
    }
}
