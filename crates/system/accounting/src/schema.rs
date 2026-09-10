//! V2 Phase 1 accounting-progress storage schema.
//!
//! ## Storage layout (`ACCOUNTING_PROGRESS_ADDRESS`)
//!
//! ```text
//! slot  0: last_accounted_block_number - u64
//! slot  1..=15: reserved (genesis zero; do not reuse)
//! ```
//!
//! Slot 0 is the highest exact-parent block number whose V2 Phase 1 system
//! tx has successfully committed. Cycle and Rewards
//! read this slot via [`crate::runtime::read_last_accounted_block_number`]
//! to gate per-day and per-finalized-block accounting.
//!
//! Slots 1..=15 are deliberately reserved (no field declared) so future
//! hard forks can add bounded extra progress / counter fields without
//! disturbing slot 0. Any chain bootstrapped under V2 must observe zero in
//! all of slots 1..=15 (INV2; tested in `tests/tests.rs`).

use outbe_macros::contract;
use outbe_primitives::addresses::ACCOUNTING_PROGRESS_ADDRESS;
use outbe_primitives::storage::types::Slot;

/// V2 Phase 1 accounting-progress storage facade.
///
/// Backed by EVM storage at [`ACCOUNTING_PROGRESS_ADDRESS`]. The only
/// declared field occupies slot 0; slots 1..=15 are reserved (zero in
/// genesis V2, never reused).
#[contract(addr = ACCOUNTING_PROGRESS_ADDRESS)]
pub struct Accounting {
    /// Highest exact-parent block number whose V2 Phase 1 system tx has
    /// successfully committed. `0` means no Phase 1 has committed yet on
    /// this chain (fresh genesis).
    pub last_accounted_block_number: Slot<u64>,
}
