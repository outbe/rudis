//! On-chain storage layout for the zero-fee paymaster precompile.
//!
//! Tracks per-signer daily quota usage for EIP-7702 sponsored
//! transactions. A single `Map<Address, u64>` packs `(date_key, count)`:
//!
//! ```text
//! packed: [ date_key u32 (high 32 bits) | count u32 (low 32 bits) ]
//! ```
//!
//! Slot 0 carries the schema version (currently `1`), written at
//! genesis by `scripts/seed_genesis.py::seed_zerofee`. The macro-
//! allocated `counter` Map uses slot 0 as its keccak base, but Map
//! entries are stored at `keccak256(addr || base_slot)`, which never
//! collides with slot 0 itself. A future layout migration would bump
//! the version marker and key its transformation off it; today the
//! only consumer is the README rule "All precompiles ... slot 0 =
//! version" plus future migration logic.

use alloy_primitives::Address;
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::ZEROFEE_ADDRESS;

/// EVM storage layout for the zero-fee paymaster contract.
///
/// `counter` is the single per-signer record. The packed encoding keeps
/// reads and writes to one storage slot per signer regardless of how
/// many txs they have ever sponsored. Lazy day reset: when
/// `unpack(stored).date_key != current_day`, the effective count is 0.
#[storage_schema]
#[contract(addr = ZEROFEE_ADDRESS)]
pub struct ZeroFeeContract {
    // slot N (macro-allocated): per-signer packed `(date_key u32, count u32)`.
    #[attribute(order = 0)]
    pub counter: outbe_primitives::storage::dsl::Map<Address, u64>,
}

/// Packs `(date_key, count)` into a single `u64` for storage.
#[inline]
pub const fn pack_counter(date_key: u32, count: u32) -> u64 {
    ((date_key as u64) << 32) | (count as u64)
}

/// Unpacks `(date_key, count)` from the stored `u64`.
#[inline]
pub const fn unpack_counter(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, (packed & 0xFFFF_FFFF) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        for (d, c) in [(0, 0), (1, 1), (20251231, 7), (u32::MAX, u32::MAX)] {
            let packed = pack_counter(d, c);
            assert_eq!(unpack_counter(packed), (d, c));
        }
    }

    #[test]
    fn zero_packed_means_zero_day_zero_count() {
        assert_eq!(unpack_counter(0), (0, 0));
    }
}
