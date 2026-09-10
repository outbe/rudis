use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ckb_smt_pristine as pristine;
use outbe_poseidon::{Poseidon, PoseidonHasher};
use outbe_sparse_merkle_tree_v061::{
    merge::{hash_base_node, merge, merge_with_zero, MergeValue},
    traits::Hasher,
    H256,
};

use super::*;
use crate::{schema::Collection, WwdEntityId, TAG_SMT_BASE, TAG_SMT_NORMAL, TAG_SMT_ZERO};

fn field_word(value: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn key(value: u64) -> TreeKey {
    TreeKey::from_be_bytes(field_word(value)).unwrap()
}

fn leaf(value: u64) -> TreeLeaf {
    TreeLeaf::from_be_bytes(field_word(value)).unwrap()
}

fn reference_field(word: H256) -> Fr {
    let bytes: [u8; 32] = word.into();
    let value = Fr::from_be_bytes_mod_order(&bytes);
    assert_eq!(
        reference_field_word(value),
        bytes,
        "test input is not canonical"
    );
    value
}

fn reference_field_word(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut output = [0_u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    output
}

/// Deliberately bypasses `PoseidonCkbHasher` and its transcript classifier.
/// Each CKB operation below supplies its CES1 domain and field inputs directly,
/// making this a small independent reference for the adapter boundary.
fn reference_poseidon(tag: u64, inputs: &[Fr]) -> H256 {
    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(tag)).unwrap();
    H256::from(reference_field_word(hasher.hash(inputs).unwrap()))
}

/// Small test-only SMT model built directly from the normative CKB path and
/// MergeValue rules. It deliberately does not call the vendored merge, tree,
/// proof, or store implementations.
#[derive(Clone, Debug)]
enum ReferenceMerge {
    Value([u8; 32]),
    MergeWithZero {
        base_node: [u8; 32],
        zero_bits: [u8; 32],
        zero_count: u8,
    },
}

impl ReferenceMerge {
    const fn zero() -> Self {
        Self::Value([0; 32])
    }

    fn is_zero(&self) -> bool {
        matches!(self, Self::Value(value) if *value == [0; 32])
    }

    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Value(value) => *value,
            Self::MergeWithZero {
                base_node,
                zero_bits,
                zero_count,
            } => reference_poseidon(
                TAG_SMT_ZERO,
                &[
                    reference_field(H256::from(*base_node)),
                    reference_field(H256::from(*zero_bits)),
                    Fr::from(*zero_count),
                ],
            )
            .into(),
        }
    }
}

fn reference_bit(key: &[u8; 32], height: u8) -> bool {
    let byte = usize::from(height / 8);
    let bit = height % 8;
    key[byte] & (1 << bit) != 0
}

fn reference_set_bit(key: &mut [u8; 32], height: u8) {
    let byte = usize::from(height / 8);
    let bit = height % 8;
    key[byte] |= 1 << bit;
}

fn reference_parent_path(mut key: [u8; 32], height: u8) -> [u8; 32] {
    for bit in 0..=height {
        let byte = usize::from(bit / 8);
        key[byte] &= !(1 << (bit % 8));
    }
    key
}

fn reference_base_node(height: u8, key: [u8; 32], value: [u8; 32]) -> [u8; 32] {
    reference_poseidon(
        TAG_SMT_BASE,
        &[
            Fr::from(height),
            reference_field(H256::from(key)),
            reference_field(H256::from(value)),
        ],
    )
    .into()
}

fn reference_merge_with_zero(
    height: u8,
    node_key: [u8; 32],
    value: ReferenceMerge,
    set_bit: bool,
) -> ReferenceMerge {
    match value {
        ReferenceMerge::Value(value) => {
            let mut zero_bits = [0; 32];
            if set_bit {
                reference_set_bit(&mut zero_bits, height);
            }
            ReferenceMerge::MergeWithZero {
                base_node: reference_base_node(height, node_key, value),
                zero_bits,
                zero_count: 1,
            }
        }
        ReferenceMerge::MergeWithZero {
            base_node,
            mut zero_bits,
            zero_count,
        } => {
            if set_bit {
                reference_set_bit(&mut zero_bits, height);
            }
            ReferenceMerge::MergeWithZero {
                base_node,
                zero_bits,
                zero_count: zero_count.wrapping_add(1),
            }
        }
    }
}

fn reference_merge(
    height: u8,
    node_key: [u8; 32],
    left: ReferenceMerge,
    right: ReferenceMerge,
) -> ReferenceMerge {
    match (left.is_zero(), right.is_zero()) {
        (true, true) => ReferenceMerge::zero(),
        (true, false) => reference_merge_with_zero(height, node_key, right, true),
        (false, true) => reference_merge_with_zero(height, node_key, left, false),
        (false, false) => ReferenceMerge::Value(
            reference_poseidon(
                TAG_SMT_NORMAL,
                &[
                    Fr::from(height),
                    reference_field(H256::from(node_key)),
                    reference_field(H256::from(left.hash())),
                    reference_field(H256::from(right.hash())),
                ],
            )
            .into(),
        ),
    }
}

fn reference_root(leaves: &BTreeMap<[u8; 32], [u8; 32]>) -> [u8; 32] {
    let mut level = leaves
        .iter()
        .map(|(key, value)| (*key, ReferenceMerge::Value(*value)))
        .collect::<BTreeMap<_, _>>();
    if level.is_empty() {
        return [0; 32];
    }

    for height in 0..=u8::MAX {
        let mut parents =
            BTreeMap::<[u8; 32], (Option<ReferenceMerge>, Option<ReferenceMerge>)>::new();
        for (key, node) in level {
            let parent_key = reference_parent_path(key, height);
            let children = parents.entry(parent_key).or_default();
            if reference_bit(&key, height) {
                assert!(children.1.replace(node).is_none());
            } else {
                assert!(children.0.replace(node).is_none());
            }
        }
        level = parents
            .into_iter()
            .map(|(parent_key, (left, right))| {
                (
                    parent_key,
                    reference_merge(
                        height,
                        parent_key,
                        left.unwrap_or_else(ReferenceMerge::zero),
                        right.unwrap_or_else(ReferenceMerge::zero),
                    ),
                )
            })
            .collect();
    }

    assert_eq!(level.len(), 1);
    level.into_values().next().unwrap().hash()
}

#[test]
fn ckb_h256_uses_exact_bytes_little_bit_paths_and_reversed_byte_order() {
    let mut bytes = [0_u8; 32];
    bytes[0] = 0b0000_0011;
    bytes[1] = 0b1000_0000;
    bytes[31] = 1;
    let value = H256::from(bytes);

    assert!(value.get_bit(0));
    assert!(value.get_bit(1));
    assert!(!value.get_bit(2));
    assert!(value.get_bit(15));
    assert!(value.get_bit(248));

    let parent = value.parent_path(1);
    let parent_bytes: [u8; 32] = parent.into();
    assert_eq!(parent_bytes[0], 0);
    assert_eq!(&parent_bytes[1..], &bytes[1..]);

    let mut low_first = [0_u8; 32];
    low_first[0] = 2;
    let mut high_last = [0_u8; 32];
    high_last[31] = 1;
    assert!(H256::from(low_first) < H256::from(high_last));
    assert!(
        TreeKey::from_be_bytes(low_first).unwrap() < TreeKey::from_be_bytes(high_last).unwrap()
    );
}

#[test]
fn tree_key_binds_collection_and_preserves_be32_without_reversal() {
    let identity = WwdEntityId::try_from(
        hex::decode("000000010405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let tribute = derive_tree_key(Collection::Tribute, identity).unwrap();
    let nod = derive_tree_key(Collection::NodItem, identity).unwrap();
    let bucket = derive_tree_key(Collection::NodBucket, identity).unwrap();

    assert_ne!(tribute, nod);
    assert_ne!(tribute, bucket);
    assert_ne!(nod, bucket);
    assert_eq!(
        H256::from(tribute.as_bytes()).as_slice(),
        &tribute.as_bytes()
    );
    assert_eq!(tribute.as_bytes()[0] & 0b1100_0000, 0);
}

#[test]
fn poseidon_transcripts_cover_base_normal_and_compact_zero_forms() {
    let key = H256::from(field_word(5));
    let left = H256::from(field_word(7));
    let right = H256::from(field_word(11));

    let base = hash_base_node::<PoseidonCkbHasher>(3, &key, &left);
    let normal = merge::<PoseidonCkbHasher>(
        4,
        &key,
        &MergeValue::from_h256(left),
        &MergeValue::from_h256(right),
    );
    let compact = merge_with_zero::<PoseidonCkbHasher>(4, &key, &MergeValue::from_h256(left), true);

    assert_ne!(base, hash_error());
    assert!(matches!(normal, MergeValue::Value(value) if value != hash_error()));
    assert!(matches!(
        compact,
        MergeValue::MergeWithZero { zero_count: 1, .. }
    ));
}

#[test]
fn ckb_poseidon_operations_match_direct_reference_and_fixed_numeric_vectors() {
    let node_key = H256::from(field_word(5));
    let left = H256::from(field_word(7));
    let right = H256::from(field_word(11));

    let base = hash_base_node::<PoseidonCkbHasher>(3, &node_key, &left);
    let base_reference = reference_poseidon(
        TAG_SMT_BASE,
        &[
            Fr::from(3_u64),
            reference_field(node_key),
            reference_field(left),
        ],
    );
    assert_eq!(base, base_reference);
    assert_eq!(
        hex::encode(<[u8; 32]>::from(base)),
        "040823651d7e1b1e06319b642420f12663c76eb676b3e537dc12b69004c15274"
    );

    let normal = merge::<PoseidonCkbHasher>(
        4,
        &node_key,
        &MergeValue::from_h256(left),
        &MergeValue::from_h256(right),
    );
    let MergeValue::Value(normal_hash) = normal else {
        panic!("two non-zero leaves must use a normal merge")
    };
    let normal_reference = reference_poseidon(
        TAG_SMT_NORMAL,
        &[
            Fr::from(4_u64),
            reference_field(node_key),
            reference_field(left),
            reference_field(right),
        ],
    );
    assert_eq!(normal_hash, normal_reference);
    assert_eq!(
        hex::encode(<[u8; 32]>::from(normal_hash)),
        "11b351f30ad8ef1236b9ebbd92ec10b02ccbc0f803851979f0e8272035cbb6c9"
    );

    let compact =
        merge_with_zero::<PoseidonCkbHasher>(4, &node_key, &MergeValue::from_h256(left), true);
    let MergeValue::MergeWithZero {
        base_node,
        zero_bits,
        zero_count,
    } = compact
    else {
        panic!("one non-zero leaf must use a compact zero merge")
    };
    assert_eq!(zero_count, 1);
    let compact_reference = reference_poseidon(
        TAG_SMT_ZERO,
        &[
            reference_field(base_node),
            reference_field(zero_bits),
            Fr::from(1_u64),
        ],
    );
    let compact_hash = MergeValue::MergeWithZero {
        base_node,
        zero_bits,
        zero_count,
    }
    .hash::<PoseidonCkbHasher>();
    assert_eq!(compact_hash, compact_reference);
    assert_eq!(
        hex::encode(<[u8; 32]>::from(compact_hash)),
        "24f4b67dad9a4d9534472e1a13b1c7bca78515bf7bab4a8eca6fd7ba8a41d9e4"
    );

    let wrapped = merge_with_zero::<PoseidonCkbHasher>(
        u8::MAX,
        &H256::zero(),
        &MergeValue::MergeWithZero {
            base_node: H256::from(field_word(1)),
            zero_bits: H256::zero(),
            zero_count: u8::MAX,
        },
        false,
    );
    let MergeValue::MergeWithZero {
        base_node,
        zero_bits,
        zero_count,
    } = wrapped
    else {
        panic!("compact merge must stay compact when its counter wraps")
    };
    assert_eq!(zero_count, 0, "255 + 1 uses CKB's encoded 256 value");
    let wrapped_reference = reference_poseidon(
        TAG_SMT_ZERO,
        &[
            reference_field(base_node),
            reference_field(zero_bits),
            Fr::from(0_u64),
        ],
    );
    let wrapped_hash = MergeValue::MergeWithZero {
        base_node,
        zero_bits,
        zero_count,
    }
    .hash::<PoseidonCkbHasher>();
    assert_eq!(wrapped_hash, wrapped_reference);
    assert_eq!(
        hex::encode(<[u8; 32]>::from(wrapped_hash)),
        "070191cbbfd2b6f37f860a5ce6122fa730582505908181ead344e8c030c08e18"
    );
}

#[test]
fn compact_zero_count_wraps_from_255_to_zero_exactly() {
    let value = MergeValue::MergeWithZero {
        base_node: H256::from(field_word(1)),
        zero_bits: H256::zero(),
        zero_count: u8::MAX,
    };
    let merged = merge_with_zero::<PoseidonCkbHasher>(u8::MAX, &H256::zero(), &value, false);
    assert!(matches!(
        merged,
        MergeValue::MergeWithZero { zero_count: 0, .. }
    ));
}

#[test]
fn empty_singleton_update_delete_and_reinsert_have_canonical_roots() {
    let mut tree = PoseidonSmt::empty();
    assert_eq!(tree.root().unwrap(), TreeRoot::EMPTY);

    let first = tree.update(key(1), leaf(101)).unwrap();
    assert_ne!(first, TreeRoot::EMPTY);
    assert_eq!(tree.get(key(1)).unwrap(), leaf(101));

    let updated = tree.update(key(1), leaf(202)).unwrap();
    assert_ne!(updated, first);
    assert_eq!(
        tree.update(key(1), TreeLeaf::ZERO).unwrap(),
        TreeRoot::EMPTY
    );
    assert_eq!(tree.get(key(1)).unwrap(), TreeLeaf::ZERO);
    assert_eq!(tree.update(key(1), leaf(101)).unwrap(), first);
}

#[test]
fn batch_root_is_order_independent_and_duplicate_input_is_rejected() {
    let changes = vec![(key(9), leaf(90)), (key(2), leaf(20)), (key(7), leaf(70))];
    let mut forward = PoseidonSmt::empty();
    let forward_root = forward.update_all(changes.clone()).unwrap();
    let mut reverse = PoseidonSmt::empty();
    let reverse_root = reverse
        .update_all(changes.into_iter().rev().collect())
        .unwrap();
    assert_eq!(forward_root, reverse_root);

    assert_eq!(
        forward.update_all(vec![(key(1), leaf(1)), (key(1), leaf(2))]),
        Err(TreeError::DuplicateKey)
    );
    assert_eq!(forward.root().unwrap(), forward_root);
}

#[test]
fn sorted_reducer_matches_the_canonical_batch_tree() {
    let mut leaves = vec![
        (key(1), leaf(101)),
        (key(2), leaf(102)),
        (key(3), leaf(103)),
        (key(9), leaf(109)),
        (key(257), leaf(357)),
    ];
    leaves.sort_by_key(|(key, _)| *key);

    let mut canonical = PoseidonSmt::empty();
    let expected = canonical.update_all(leaves.clone()).unwrap();
    let mut reduced = SortedPoseidonRootReducer::new();
    for (key, leaf) in leaves {
        reduced.push(key, leaf).unwrap();
    }

    assert_eq!(reduced.finish().unwrap(), expected);
}

#[test]
fn sorted_reducer_matches_canonical_roots_across_random_sets() {
    assert_eq!(
        SortedPoseidonRootReducer::new().finish().unwrap(),
        TreeRoot::EMPTY
    );
    let mut random = 0x517c_c1b7_2722_0a95_u64;
    for count in [1_usize, 2, 3, 15, 16, 17, 63, 257] {
        let mut unique = BTreeMap::new();
        while unique.len() < count {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let key = (random % 1_000_003) + 1;
            unique.insert(key, key.wrapping_mul(17).wrapping_add(1));
        }
        let mut leaves = unique
            .into_iter()
            .map(|(key_number, leaf_number)| (key(key_number), leaf(leaf_number)))
            .collect::<Vec<_>>();
        leaves.sort_by_key(|(key, _)| *key);
        let mut canonical = PoseidonSmt::empty();
        let expected = canonical.update_all(leaves.clone()).unwrap();
        let mut reduced = SortedPoseidonRootReducer::new();
        for (key, leaf) in leaves {
            reduced.push(key, leaf).unwrap();
        }
        assert_eq!(reduced.finish().unwrap(), expected, "count={count}");
    }
}

#[test]
fn sorted_reducer_rejects_duplicate_regressing_and_zero_leaves() {
    let mut duplicate = SortedPoseidonRootReducer::new();
    duplicate.push(key(1), leaf(1)).unwrap();
    assert_eq!(
        duplicate.push(key(1), leaf(2)),
        Err(TreeError::DuplicateKey)
    );

    let mut regressing = SortedPoseidonRootReducer::new();
    regressing.push(key(2), leaf(2)).unwrap();
    assert_eq!(
        regressing.push(key(1), leaf(1)),
        Err(TreeError::NonAscendingKey)
    );

    assert_eq!(
        SortedPoseidonRootReducer::new().push(key(1), TreeLeaf::ZERO),
        Err(TreeError::ZeroLeaf)
    );
}

#[test]
fn membership_non_membership_and_tampered_proofs_are_checked_behaviorally() {
    let mut tree = PoseidonSmt::empty();
    tree.update_all(vec![
        (key(1), leaf(10)),
        (key(2), leaf(20)),
        (key(3), leaf(30)),
    ])
    .unwrap();
    let root = tree.root().unwrap();
    let proof = tree.prove(vec![key(1), key(8)]).unwrap();
    tree.verify(
        root,
        &proof,
        vec![(key(1), leaf(10)), (key(8), TreeLeaf::ZERO)],
    )
    .unwrap();

    assert_eq!(
        tree.verify(
            root,
            &proof,
            vec![(key(1), leaf(11)), (key(8), TreeLeaf::ZERO)]
        ),
        Err(TreeError::InvalidProof)
    );

    let mut bytes = proof.as_bytes().to_vec();
    let index = bytes.len() / 2;
    bytes[index] ^= 0x80;
    assert!(tree
        .verify(
            root,
            &TreeProof::from_bytes(bytes),
            vec![(key(1), leaf(10)), (key(8), TreeLeaf::ZERO)]
        )
        .is_err());
}

#[derive(Default)]
struct PristineHasher(PoseidonCkbHasher);

impl pristine::traits::Hasher for PristineHasher {
    fn write_h256(&mut self, h: &pristine::H256) {
        let bytes: [u8; 32] = (*h).into();
        self.0.write_h256(&H256::from(bytes));
    }

    fn write_byte(&mut self, b: u8) {
        self.0.write_byte(b);
    }

    fn finish(self) -> pristine::H256 {
        let bytes: [u8; 32] = self.0.finish().into();
        pristine::H256::from(bytes)
    }
}

#[derive(Clone, Default)]
struct PristineStore {
    branches: BTreeMap<pristine::BranchKey, pristine::BranchNode>,
    leaves: BTreeMap<pristine::H256, pristine::H256>,
}

impl pristine::traits::StoreReadOps<pristine::H256> for PristineStore {
    fn get_branch(
        &self,
        key: &pristine::BranchKey,
    ) -> Result<Option<pristine::BranchNode>, pristine::error::Error> {
        Ok(self.branches.get(key).cloned())
    }

    fn get_leaf(
        &self,
        key: &pristine::H256,
    ) -> Result<Option<pristine::H256>, pristine::error::Error> {
        Ok(self.leaves.get(key).copied())
    }
}

impl pristine::traits::StoreWriteOps<pristine::H256> for PristineStore {
    fn insert_branch(
        &mut self,
        key: pristine::BranchKey,
        branch: pristine::BranchNode,
    ) -> Result<(), pristine::error::Error> {
        self.branches.insert(key, branch);
        Ok(())
    }

    fn insert_leaf(
        &mut self,
        key: pristine::H256,
        leaf: pristine::H256,
    ) -> Result<(), pristine::error::Error> {
        self.leaves.insert(key, leaf);
        Ok(())
    }

    fn remove_branch(&mut self, key: &pristine::BranchKey) -> Result<(), pristine::error::Error> {
        self.branches.remove(key);
        Ok(())
    }

    fn remove_leaf(&mut self, key: &pristine::H256) -> Result<(), pristine::error::Error> {
        self.leaves.remove(key);
        Ok(())
    }
}

#[test]
fn sanitized_vendor_matches_pristine_update_delete_and_proof_mechanics() {
    type PristineTree = pristine::SparseMerkleTree<PristineHasher, pristine::H256, PristineStore>;
    let mut pristine = PristineTree::new(pristine::H256::zero(), PristineStore::default());
    let mut sanitized = PoseidonSmt::empty();

    let operations = [
        (1, 10),
        (200, 20),
        (3, 30),
        (1, 11),
        (200, 0),
        (255, 40),
        (3, 0),
        (200, 22),
    ];
    for (key_value, leaf_value) in operations {
        let key_bytes = field_word(key_value);
        let leaf_bytes = field_word(leaf_value);
        let pristine_root = pristine
            .update(
                pristine::H256::from(key_bytes),
                pristine::H256::from(leaf_bytes),
            )
            .unwrap();
        let sanitized_root = sanitized
            .update(
                TreeKey::from_be_bytes(key_bytes).unwrap(),
                TreeLeaf::from_be_bytes(leaf_bytes).unwrap(),
            )
            .unwrap();
        assert_eq!(sanitized_root.as_bytes(), <[u8; 32]>::from(*pristine_root));
    }

    let proof_keys = [field_word(1), field_word(200), field_word(9)];
    let pristine_proof = pristine
        .merkle_proof(
            proof_keys
                .iter()
                .copied()
                .map(pristine::H256::from)
                .collect(),
        )
        .unwrap()
        .compile(
            proof_keys
                .iter()
                .copied()
                .map(pristine::H256::from)
                .collect(),
        )
        .unwrap();
    let sanitized_proof = sanitized
        .prove(
            proof_keys
                .iter()
                .copied()
                .map(|bytes| TreeKey::from_be_bytes(bytes).unwrap())
                .collect(),
        )
        .unwrap();
    assert_eq!(sanitized_proof.as_bytes(), pristine_proof.0);
}

#[test]
fn production_roots_match_independent_model_across_random_mutation_sequences() {
    let mut production = PoseidonSmt::empty();
    let mut reference = BTreeMap::new();
    let mut random = 0x9e37_79b9_7f4a_7c15_u64;

    for step in 0..128_u64 {
        // Fixed LCG keeps the sequence reproducible without sharing any tree
        // implementation or adding a random-number dependency.
        random = random
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let key_number = (random % 31) + 1;
        let key_bytes = field_word(key_number);
        let delete = random.rotate_left(17).is_multiple_of(5);
        let leaf_bytes = if delete {
            [0; 32]
        } else {
            field_word((step + 1) * 1_000 + (random.rotate_right(11) % 997) + 1)
        };

        if delete {
            reference.remove(&key_bytes);
        } else {
            reference.insert(key_bytes, leaf_bytes);
        }
        let production_root = production
            .update(
                TreeKey::from_be_bytes(key_bytes).unwrap(),
                TreeLeaf::from_be_bytes(leaf_bytes).unwrap(),
            )
            .unwrap();

        assert_eq!(
            production_root.as_bytes(),
            reference_root(&reference),
            "independent SMT root mismatch after mutation {step}"
        );
    }
}
