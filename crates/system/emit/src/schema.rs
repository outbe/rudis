//! Frozen V1 storage schema at `EMIT_ADDRESS`.
//!
//! Tornado-style incremental merkle tree state: no leaves, right nodes,
//! paths, or empty hashes are ever stored. Slot assignment is by declaration
//! order; the circular buffer occupies two slots (3–4).
//!
//! There is deliberately no schema-version field (decision 2026-08-25): a
//! pristine tree is exactly `leaf_count == 0`, so a version gate adds checks
//! without adding state. A future schema change lands as a new slot or an
//! explicit update-handler migration, not an in-place version bump.
use alloy_primitives::B256;
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::EMIT_ADDRESS;

/// Commitment-tree depth (fixed by the `outbe.emit.mint@1.5.0` circuit:
/// the protocol-canonical depth in `outbe_circuit_core::merkle_tree`).
pub const EMIT_TREE_DEPTH: usize = 32;

/// Tree capacity: `2^32` leaves geometrically; the u32 `leaf_count` cannot
/// count them all, so the tree is declared full one leaf early and the last
/// append is refused before the index counter would overflow.
pub const EMIT_TREE_CAPACITY: u64 = (1u64 << EMIT_TREE_DEPTH) - 1;

/// Number of accepted roots retained for mint proofs (the root window).
pub const EMIT_ROOT_WINDOW: u32 = 32;

/// EVM storage layout for the chain's Emit tree (V1).
#[storage_schema]
#[contract(addr = EMIT_ADDRESS)]
pub struct EmitContract {
    // slot 0: latest commitment root
    pub current_root: Value<B256>,
    // slot 1: next append index (0 = pristine)
    pub leaf_count: Value<u32>,
    // slot 2: one completed left subtree per level
    pub filled_subtrees: Map<u8, B256>,
    // slots 3–4: last 32 root-producing appends, seeded with the empty root
    pub recent_roots: CircularBuffer<B256>,
    // slot 5: permanent duplicate prevention
    pub commitments: Map<B256, bool>,
    // slot 6: permanent replay prevention
    pub spent_nullifiers: Map<B256, bool>,
}
