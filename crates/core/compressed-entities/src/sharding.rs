use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon, PoseidonHasher};
use outbe_sparse_merkle_tree_v061::H256;
use thiserror::Error;

use crate::{
    smt::{TreeError, TreeKey, TreeRoot},
    TAG_TOP_NODE,
};

pub const K_CANDIDATES: [u32; 6] = [1, 2, 4, 8, 16, 32];

#[derive(Debug, Error)]
pub enum ShardingError {
    #[error("shard count must be a power of two in 1..=32, got {actual}")]
    InvalidShardCount { actual: u32 },
    #[error("Poseidon shard-top aggregation failed")]
    TreeHash,
}

pub fn empty_shard_top_root(shard_count: u32) -> Result<alloy_primitives::B256, ShardingError> {
    validate_shard_count(shard_count).map_err(|_| ShardingError::InvalidShardCount {
        actual: shard_count,
    })?;
    aggregate_shard_roots(&vec![
        TreeRoot::EMPTY;
        usize::try_from(shard_count).map_err(|_| {
            ShardingError::InvalidShardCount {
                actual: shard_count,
            }
        })?
    ])
    .map(|root| alloy_primitives::B256::from(root.as_bytes()))
    .map_err(|_| ShardingError::TreeHash)
}

pub(crate) fn aggregate_b256_shard_roots(roots: &[B256]) -> Result<B256, TreeError> {
    roots
        .iter()
        .map(|root| TreeRoot::from_be_bytes(root.0))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|roots| aggregate_shard_roots(&roots))
        .map(|root| B256::from(root.as_bytes()))
}

pub(crate) fn shard_index(key: TreeKey, shard_count: u32) -> Result<u32, TreeError> {
    validate_shard_count(shard_count)?;
    let ckb_key = H256::from(key.as_bytes());
    let bit_count = shard_count.trailing_zeros();
    let mut index = 0_u32;
    for numeric_bit in 0..bit_count {
        let byte_from_right = numeric_bit / 8;
        let bit_in_byte = numeric_bit % 8;
        let ckb_bit_index = 8 * (31 - byte_from_right) + bit_in_byte;
        let ckb_bit_index =
            u8::try_from(ckb_bit_index).map_err(|_| TreeError::InvalidShardCount {
                actual: shard_count,
            })?;
        if ckb_key.get_bit(ckb_bit_index) {
            index |= 1 << numeric_bit;
        }
    }
    Ok(index)
}

pub(crate) fn aggregate_shard_roots(roots: &[TreeRoot]) -> Result<TreeRoot, TreeError> {
    let shard_count = u32::try_from(roots.len())
        .map_err(|_| TreeError::InvalidShardCount { actual: u32::MAX })?;
    validate_shard_count(shard_count)?;
    if shard_count == 1 {
        return Ok(roots[0]);
    }

    let mut level_roots = roots.to_vec();
    let mut level = 0_u32;
    while level_roots.len() > 1 {
        let mut parents = Vec::with_capacity(level_roots.len() / 2);
        for pair in level_roots.chunks_exact(2) {
            let inputs = [
                Fr::from(level),
                Fr::from_be_bytes_mod_order(&pair[0].as_bytes()),
                Fr::from_be_bytes_mod_order(&pair[1].as_bytes()),
            ];
            let mut hasher =
                Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(TAG_TOP_NODE))
                    .map_err(|_| TreeError::TreeHashError)?;
            let output = hasher.hash(&inputs).map_err(|_| TreeError::TreeHashError)?;
            let bytes = field_to_be32(output);
            if bytes == [0_u8; 32] {
                return Err(TreeError::TreeHashError);
            }
            parents.push(TreeRoot::from_be_bytes(bytes)?);
        }
        level_roots = parents;
        level = level.saturating_add(1);
    }
    Ok(level_roots[0])
}

fn validate_shard_count(shard_count: u32) -> Result<(), TreeError> {
    if shard_count == 0 || shard_count > 32 || !shard_count.is_power_of_two() {
        return Err(TreeError::InvalidShardCount {
            actual: shard_count,
        });
    }
    Ok(())
}

fn field_to_be32(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut output = [0_u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    output
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use serde::Deserialize;

    use super::*;
    use crate::{schema::Collection, smt::derive_tree_key, WwdEntityId, K_PROVISIONAL};

    fn key(bytes: [u8; 32]) -> TreeKey {
        TreeKey::from_be_bytes(bytes).unwrap()
    }

    #[test]
    fn shard_selection_uses_numeric_low_bits_through_ckb_indexing() {
        assert_eq!(K_CANDIDATES, [1, 2, 4, 8, 16, 32]);
        let vectors = [
            ([0_u8; 32], 1, 0),
            ([0_u8; 32], K_PROVISIONAL, 0),
            (
                {
                    let mut value = [0_u8; 32];
                    value[31] = 0x01;
                    value
                },
                K_PROVISIONAL,
                1,
            ),
            (
                {
                    let mut value = [0_u8; 32];
                    value[31] = 0x0f;
                    value
                },
                K_PROVISIONAL,
                15,
            ),
            (
                {
                    let mut value = [0_u8; 32];
                    value[31] = 0x10;
                    value
                },
                K_PROVISIONAL,
                0,
            ),
            (
                {
                    let mut value = [0_u8; 32];
                    value[31] = 0xff;
                    value
                },
                K_PROVISIONAL,
                15,
            ),
            (
                {
                    let mut value = [0_u8; 32];
                    value[0] = 0x0f;
                    value
                },
                K_PROVISIONAL,
                0,
            ),
        ];

        for (tree_key, shard_count, expected) in vectors {
            assert_eq!(shard_index(key(tree_key), shard_count).unwrap(), expected);
        }
        for invalid in [0, 3, 64] {
            assert!(shard_index(key([0_u8; 32]), invalid).is_err());
        }
    }

    #[test]
    fn real_collection_keys_have_cross_architecture_pinned_shards() {
        let identity = WwdEntityId::try_from(
            hex::decode("000000010405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let actual = [
            derive_tree_key(Collection::Tribute, identity).unwrap(),
            derive_tree_key(Collection::NodItem, identity).unwrap(),
            derive_tree_key(Collection::NodBucket, identity).unwrap(),
        ]
        .map(|tree_key| shard_index(tree_key, K_PROVISIONAL).unwrap());

        assert_eq!(actual, [5, 4, 2]);
    }

    #[derive(Deserialize)]
    struct ShardingVectors {
        k_test: u32,
        identity_hex: String,
        synthetic: Vec<SyntheticVector>,
        real: Vec<RealVector>,
    }

    #[derive(Deserialize)]
    struct SyntheticVector {
        tree_key_hex: String,
        shard_count: u32,
        shard_index: u32,
    }

    #[derive(Deserialize)]
    struct RealVector {
        collection: String,
        tree_key_hex: String,
        shard_index: u32,
    }

    #[test]
    fn checked_in_vectors_reproduce_full_keys_and_shards() {
        let vectors: ShardingVectors =
            serde_json::from_str(include_str!("../vectors/adr009-sharding.json")).unwrap();
        assert_eq!(vectors.k_test, K_PROVISIONAL);
        for vector in vectors.synthetic {
            let bytes: [u8; 32] = hex::decode(vector.tree_key_hex)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                shard_index(key(bytes), vector.shard_count).unwrap(),
                vector.shard_index
            );
        }

        let identity_bytes = hex::decode(vectors.identity_hex).unwrap();
        let identity = WwdEntityId::try_from(identity_bytes.as_slice()).unwrap();
        for vector in vectors.real {
            let collection = match vector.collection.as_str() {
                "Tribute" => Collection::Tribute,
                "NodItem" => Collection::NodItem,
                "NodBucket" => Collection::NodBucket,
                other => panic!("unknown vector collection {other}"),
            };
            let derived = derive_tree_key(collection, identity).unwrap();
            assert_eq!(hex::encode(derived.as_bytes()), vector.tree_key_hex);
            assert_eq!(
                shard_index(derived, K_PROVISIONAL).unwrap(),
                vector.shard_index
            );
        }
    }

    #[test]
    fn complete_ordered_top_tree_hashes_zero_children_and_special_cases_k_one() {
        assert_eq!(
            aggregate_shard_roots(&[TreeRoot::EMPTY]).unwrap(),
            TreeRoot::EMPTY
        );

        let empty = vec![TreeRoot::EMPTY; usize::try_from(K_PROVISIONAL).unwrap()];
        let empty_top = aggregate_shard_roots(&empty).unwrap();
        assert_ne!(empty_top, TreeRoot::EMPTY);

        let mut changed = empty.clone();
        changed[0] = TreeRoot::from_be_bytes(B256::with_last_byte(1).0).unwrap();
        let first = aggregate_shard_roots(&changed).unwrap();
        changed.swap(0, 1);
        let second = aggregate_shard_roots(&changed).unwrap();
        assert_ne!(first, second);

        assert!(aggregate_shard_roots(&[]).is_err());
        assert!(aggregate_shard_roots(&[TreeRoot::EMPTY; 3]).is_err());
    }
}
