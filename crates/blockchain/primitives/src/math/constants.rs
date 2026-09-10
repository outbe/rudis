//! PancakeSwap Liquidity Book constants (port).
//!
//! Verified against `pancakeswap/infinity-core@main` (2026-05-12):
//! - `src/pool-bin/libraries/Constants.sol`
//! - `src/pool-bin/libraries/PriceHelper.sol`

use alloy_primitives::U256;

/// Fractional-bit count for the 128.128 fixed-point format used by the LB
/// price ladder. Mirrors `Constants.SCALE_OFFSET`.
pub const SCALE_OFFSET: u32 = 128;

/// `1.0` in 128.128 fixed point (== `1 << 128`). Mirrors `Constants.SCALE`.
/// Stored as four little-endian u64 limbs: bit 128 lives in limb 2.
pub const SCALE_1_128_128: U256 = U256::from_limbs([0, 0, 1, 0]);

/// Decimal precision for "real-world" prices fed into the ladder (1e18).
/// Mirrors `Constants.PRECISION`.
pub const PRECISION: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

/// Maximum value of a basis-point quantity (10_000 bp = 100%).
/// Mirrors `Constants.BASIS_POINT_MAX`.
pub const BASIS_POINT_MAX: u16 = 10_000;

/// Bin id corresponding to price = 1.0. Centers the 24-bit id space.
/// Mirrors `PriceHelper.REAL_ID_SHIFT = 1 << 23`. Signed so the
/// `id - REAL_ID_SHIFT` exponent can go negative.
pub const REAL_ID_SHIFT: i32 = 1 << 23;

/// Largest representable bin id (uint24 max). LB's `safe24` reverts past
/// this; the Outbe `price_helper::get_id_from_price` saturates instead.
pub const MAX_BIN_ID: u32 = (1 << 24) - 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_pancakeswap() {
        assert_eq!(SCALE_1_128_128, U256::ONE << 128);
        assert_eq!(PRECISION, U256::from(1_000_000_000_000_000_000u64));
        assert_eq!(REAL_ID_SHIFT, 1 << 23);
        assert_eq!(BASIS_POINT_MAX, 10_000);
        assert_eq!(SCALE_OFFSET, 128);
    }
}
