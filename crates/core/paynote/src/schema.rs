//! Frozen V1 storage schema at `PAYNOTE_ADDRESS`.
//!
//! Tornado-style incremental Merkle tree state: no leaves, right nodes, paths,
//! or empty hashes are ever stored. The empty ladder is chain-specific and
//! rederived in memory per request (see [`crate::hash::empty_subtrees`]).
//!
//! There is deliberately no schema-version field: a pristine tree is exactly
//! `leaf_count == 0`, so a version gate would add checks without adding state.
//! A future schema change lands as a new slot or an explicit migration, not an
//! in-place version bump.

use alloy_primitives::B256;
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::PAYNOTE_ADDRESS;

/// Commitment-tree depth, fixed by the `outbe.paynote@1.1.0` circuit's
/// generated `auth_path: [Field; 32]`.
pub const PAYNOTE_TREE_DEPTH: usize = 32;

/// Tree capacity: `2^32` leaves.
///
/// Held as `u64` on purpose. The circuit's `leaf_index` is a `u32`, so the last
/// valid index is `2^32 - 1` and the capacity itself does **not** fit in `u32`
/// — a `u32` counter would wrap on the final append instead of reporting a full
/// tree. [`PayNoteContract::leaf_count`] is therefore `u64` and every append
/// guards against this bound before incrementing.
pub const PAYNOTE_TREE_CAPACITY: u64 = 1 << PAYNOTE_TREE_DEPTH;

/// Number of accepted roots retained for spend proofs (the root window).
///
/// A proof is built against whatever root was current when its witness was
/// assembled; deposits landing before it is consumed would otherwise
/// invalidate it. Accepting the last 32 roots absorbs that race.
pub const PAYNOTE_ROOT_WINDOW: u32 = 32;

/// EVM storage layout for the chain's PayNote pool (V1).
#[storage_schema]
#[contract(addr = PAYNOTE_ADDRESS)]
pub struct PayNoteContract {
    // slot 0: latest commitment root
    #[attribute(order = 0)]
    pub current_root: outbe_primitives::storage::dsl::Value<B256>,

    // slot 1: next append index (0 = pristine)
    #[attribute(order = 1)]
    pub leaf_count: outbe_primitives::storage::dsl::Value<u64>,

    // slot 2: one completed left subtree per level
    #[attribute(order = 2)]
    pub filled_subtrees: outbe_primitives::storage::dsl::Map<u8, B256>,

    // slots 3-4: last PAYNOTE_ROOT_WINDOW root-producing appends, seeded with
    // the empty root
    #[attribute(order = 3)]
    pub recent_roots: outbe_primitives::storage::dsl::CircularBuffer<B256>,

    // slot 5: permanent duplicate prevention, keyed on the leaf (never the
    // serial — two notes may legitimately share a serial)
    #[attribute(order = 4)]
    pub commitments: outbe_primitives::storage::dsl::Map<B256, bool>,

    // slot 6: permanent replay prevention
    #[attribute(order = 5)]
    pub spent_nullifiers: outbe_primitives::storage::dsl::Map<B256, bool>,
}
