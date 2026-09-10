//! Private CKB SMT engine and CES1 Poseidon codec.

#[allow(dead_code)]
mod codec;
#[allow(dead_code)]
mod facade;

#[allow(unused_imports)]
pub(crate) use codec::{hash_error, PoseidonCkbHasher};
#[allow(unused_imports)]
pub(crate) use facade::{
    derive_tree_key, PoseidonSmt, SortedPoseidonRootReducer, TreeError, TreeKey, TreeLeaf,
    TreeProof, TreeRoot,
};

#[cfg(test)]
mod tests;
