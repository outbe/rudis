//! Test-only pristine CKB sparse-merkle-tree v0.6.1 source snapshot.

#![allow(clippy::legacy_numeric_constants, clippy::unnecessary_cast)]

pub mod error;
pub mod h256;
pub mod merge;
pub mod merkle_proof;
pub mod traits;
mod tree;

pub use h256::H256;
pub use merkle_proof::{CompiledMerkleProof, MerkleProof};
pub use tree::{BranchKey, BranchNode, SparseMerkleTree};

pub const EXPECTED_PATH_SIZE: usize = 16;
pub(crate) const MAX_STACK_SIZE: usize = 257;

pub(crate) use std::{collections, string, vec};
