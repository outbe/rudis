//! PancakeSwap Liquidity Book `BitMath` port.
//!
//! Verified against `pancakeswap/infinity-core@main` (2026-05-12):
//! - `src/pool-bin/libraries/math/BitMath.sol`
//!
//! Solidity assembly becomes deterministic U256 ops. Targets are pure Rust,
//! no `unsafe`, deterministic across all platforms.

use alloy_primitives::U256;

/// Mirrors `BitMath.mostSignificantBit(uint256)` (BitMath.sol L36-69).
/// Returns the index (0..=255) of the highest set bit. Returns 0 if `x == 0`.
pub fn most_significant_bit(mut x: U256) -> u8 {
    let mut msb: u8 = 0;
    let mask128 = U256::from_limbs([u64::MAX, u64::MAX, 0, 0]); // 0xff..ff (low 128 bits)
    if x > mask128 {
        x >>= 128;
        msb = 128;
    }
    if x > U256::from(u64::MAX) {
        x >>= 64;
        msb += 64;
    }
    if x > U256::from(0xFFFF_FFFFu64) {
        x >>= 32;
        msb += 32;
    }
    if x > U256::from(0xFFFFu64) {
        x >>= 16;
        msb += 16;
    }
    if x > U256::from(0xFFu64) {
        x >>= 8;
        msb += 8;
    }
    if x > U256::from(0xFu64) {
        x >>= 4;
        msb += 4;
    }
    if x > U256::from(0x3u64) {
        x >>= 2;
        msb += 2;
    }
    if x > U256::from(0x1u64) {
        msb += 1;
    }
    msb
}

/// Mirrors `BitMath.leastSignificantBit(uint256)` (BitMath.sol L74-117).
/// Returns the index (0..=255) of the lowest set bit. Returns 255 for zero
/// (matches LB sentinel-ish behavior; no caller should pass zero in
/// performance-critical paths).
///
/// Implementation: walks alloy's little-endian limb array (limb[0] = bits
/// 0..63) and uses `u64::trailing_zeros`, which is deterministic across
/// every Rust target (defined for 0 -> 64, never CPU-intrinsic-dependent).
pub fn least_significant_bit(word: U256) -> u32 {
    let limbs = word.as_limbs();
    // SAFETY: i in {0,1,2,3}, so (i as u32) * 64 in {0,64,128,192}; no narrowing.
    for (i, &limb) in limbs.iter().enumerate() {
        if limb != 0 {
            return limb.trailing_zeros() + (i as u32) * 64;
        }
    }
    255 // unreachable per precondition; matches LB's "leastSignificantBit(0) == 255".
}

/// Returns `word` with all bits below `from_bit` cleared.
/// `from_bit == 0` -> returns `word` unchanged.
pub fn mask_from(word: U256, from_bit: u8) -> U256 {
    if from_bit == 0 {
        word
    } else {
        word & (U256::MAX << (from_bit as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::constants::SCALE_1_128_128;

    #[test]
    fn most_significant_bit_known_values() {
        assert_eq!(most_significant_bit(U256::from(1u64)), 0);
        assert_eq!(most_significant_bit(U256::from(2u64)), 1);
        assert_eq!(most_significant_bit(U256::from(0xFFu64)), 7);
        assert_eq!(most_significant_bit(U256::from(0x100u64)), 8);
        assert_eq!(most_significant_bit(SCALE_1_128_128), 128);
        assert_eq!(most_significant_bit(U256::MAX), 255);
    }

    #[test]
    fn least_significant_bit_known_values() {
        assert_eq!(least_significant_bit(U256::ONE), 0);
        assert_eq!(least_significant_bit(U256::from(0b1000u64)), 3);
        assert_eq!(least_significant_bit(U256::ONE << 64), 64);
        assert_eq!(least_significant_bit(U256::ONE << 128), 128);
        assert_eq!(least_significant_bit(U256::ONE << 200), 200);
        assert_eq!(least_significant_bit(U256::ONE << 255), 255);
        assert_eq!(least_significant_bit(U256::MAX), 0);
    }

    #[test]
    fn mask_from_known_values() {
        assert_eq!(mask_from(U256::MAX, 0), U256::MAX);
        // mask_from(MAX, 1) clears bit 0.
        assert_eq!(mask_from(U256::MAX, 1), U256::MAX - U256::ONE);
        // mask_from(0xFF, 4) keeps bits 4..=7 -> 0xF0.
        assert_eq!(mask_from(U256::from(0xFFu64), 4), U256::from(0xF0u64));
    }
}
