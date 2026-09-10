//! `L2Registry` - storage-backed registry of L2 networks (`0x...EE0E`).
//!
//! Records registered L2 networks keyed by `chain_id`: the L1 operator address
//! that submits on behalf of the network, its BLS MinSig committee group key
//! (compressed G2, 96 bytes), and a
//! per-network `zk_enabled` flag. Registration and ZK policy changes are
//! applied only by the module's validator [`vote_target::L2RegistryVoteTarget`].
//! The public precompile exposes registry views plus owner-authorized removal.
//!
//! The cross-module surface ([`api`]) verifies the BLS signature carried in
//! `TributeFactory.offerTribute` over `zkMerkleRoot` against the caller's
//! registered network key when that network has ZK verification enabled.

pub mod api;
pub mod errors;
pub mod precompile;
pub mod schema;
pub mod vote_target;

mod runtime;

pub use schema::{L2NetworkRecord, L2RegistryContract, BLS_PUBLIC_KEY_LEN};
pub use vote_target::{L2RegistryVotePayloadV1, L2RegistryVoteTarget};

#[cfg(test)]
mod tests;
