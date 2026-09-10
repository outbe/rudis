//! PancakeSwap Liquidity Book `PriceHelper` port.
//!
//! Verified against `pancakeswap/infinity-core@main` (2026-05-12):
//! - `src/pool-bin/libraries/PriceHelper.sol`
//!
//! Function names mirror the Solidity verbatim. Note that
//! `get_id_from_price` **saturates** instead of reverting on out-of-range
//! cast - see inline comment for the rationale.

use alloy_primitives::{I256, U256};

use crate::error::{PrecompileError, Result};
use crate::math::constants::{
    BASIS_POINT_MAX, MAX_BIN_ID, PRECISION, REAL_ID_SHIFT, SCALE_1_128_128, SCALE_OFFSET,
};
use crate::math::uint128x128_math::{log2, pow};
use crate::math::uint256x256_math::{mul_shift_round_down, shift_div_round_down};

/// Mirrors `PriceHelper.getBase(uint16)` (PriceHelper.sol L46-50).
/// Returns `1 + binStep / BASIS_POINT_MAX` in 128.128 fixed-point.
pub fn get_base(bin_step: u16) -> U256 {
    let bin_step_u256 = U256::from(bin_step);
    SCALE_1_128_128 + (bin_step_u256 << SCALE_OFFSET as usize) / U256::from(BASIS_POINT_MAX)
}

/// Mirrors `PriceHelper.getExponent(uint24)` (PriceHelper.sol L54-58).
/// `exponent = id - REAL_ID_SHIFT`. Caller passes `id` as `u32`; we treat
/// it as `i32` (top byte must be 0 since `id` is at most `(1 << 24) - 1`).
pub fn get_exponent(id: u32) -> i32 {
    (id as i32) - REAL_ID_SHIFT
}

/// Mirrors `PriceHelper.getPriceFromId(uint24, uint16)`
/// (PriceHelper.sol L21-26). Returns the 128.128 fixed-point price for
/// the given bin id. May error at extreme bin ids where LB's pow exponent
/// exceeds `2^20`; for typical bin ladders these ids correspond to
/// astronomical or sub-atomic prices that the caller treats as diagnostic.
pub fn get_price_from_id(id: u32, bin_step: u16) -> Result<U256> {
    let base = get_base(bin_step);
    let exponent = get_exponent(id);
    pow(base, exponent)
}

/// Mirrors `PriceHelper.getIdFromPrice(uint256, uint16)`
/// (PriceHelper.sol L29-37) - but **saturates** instead of reverting on
/// out-of-range cast (LB uses `safe24`). Saturation rationale: reverting
/// would brick downstream callers that need a deterministic id for any
/// finite 128.128 price.
pub fn get_id_from_price(price_128x128: U256, bin_step: u16) -> Result<u32> {
    let base = get_base(bin_step);
    let log2_price = log2(price_128x128)?;
    let log2_base = log2(base)?;
    if log2_base.is_zero() {
        return Err(PrecompileError::Revert("lb_math: log2(base) == 0".into()));
    }
    // Solidity int256 / int256 truncates toward zero (matches I256 / impl).
    let real_id = log2_price / log2_base;

    let shift = I256::try_from(REAL_ID_SHIFT)
        .map_err(|_| PrecompileError::Revert("lb_math: REAL_ID_SHIFT widen".into()))?;
    let id_signed = real_id.saturating_add(shift);

    // Saturate to [0, MAX_BIN_ID].
    if id_signed.is_negative() {
        return Ok(0);
    }
    let id_unsigned = U256::try_from(id_signed)
        .map_err(|_| PrecompileError::Revert("lb_math: id widen".into()))?;
    let max = U256::from(MAX_BIN_ID);
    let bounded = if id_unsigned > max { max } else { id_unsigned };
    Ok(bounded.to::<u32>())
}

/// Mirrors `PriceHelper.convertDecimalPriceTo128x128(uint256)`
/// (PriceHelper.sol L62-64): `(price << 128) / 1e18`.
pub fn convert_decimal_price_to_128x128(price_18dec: U256) -> Result<U256> {
    shift_div_round_down(price_18dec, SCALE_OFFSET as u8, PRECISION)
}

/// Mirrors `PriceHelper.convert128x128PriceToDecimal(uint256)`
/// (PriceHelper.sol L68-70): `(price128x128 * 1e18) >> 128`.
pub fn convert_128x128_price_to_decimal(price_128x128: U256) -> Result<U256> {
    mul_shift_round_down(price_128x128, PRECISION, SCALE_OFFSET as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIN_STEP_BP: u16 = 25;

    #[test]
    fn get_base_25bp() {
        // base = (1 << 128) + ((25 << 128) / 10_000)
        let expected = (U256::ONE << 128) + (U256::from(25u64) << 128) / U256::from(10_000u64);
        assert_eq!(get_base(BIN_STEP_BP), expected);
    }

    #[test]
    fn get_exponent_centered_at_real_id_shift() {
        assert_eq!(get_exponent(REAL_ID_SHIFT as u32), 0);
        assert_eq!(get_exponent(0), -REAL_ID_SHIFT);
        assert_eq!(get_exponent(REAL_ID_SHIFT as u32 + 100), 100);
    }

    #[test]
    fn convert_decimal_round_trip() {
        // 1.0 in 18-decimal == 1.0 in 128.128 == SCALE.
        assert_eq!(
            convert_decimal_price_to_128x128(PRECISION).unwrap(),
            SCALE_1_128_128
        );
        assert_eq!(
            convert_128x128_price_to_decimal(SCALE_1_128_128).unwrap(),
            PRECISION
        );
    }

    #[test]
    fn get_id_from_price_one_is_real_id_shift() {
        // Price = 1.0 -> bin_id = REAL_ID_SHIFT.
        let id = get_id_from_price(SCALE_1_128_128, BIN_STEP_BP).unwrap();
        assert_eq!(id, REAL_ID_SHIFT as u32);
    }

    #[test]
    fn get_id_from_price_does_not_underflow() {
        // U256::ONE in 128.128 represents 2^-128 - log2 special-cased to -128
        // (raw, NOT 128.128-encoded - see Uint128x128Math.sol L37). After
        // dividing by `log2(base)` ~= 1.225e36, the quotient rounds to 0, so
        // `id == REAL_ID_SHIFT` rather than 0. With BIN_STEP_BP = 25 the
        // saturate-to-0 branch is unreachable for any non-zero U256.
        let id = get_id_from_price(U256::ONE, BIN_STEP_BP).unwrap();
        assert_eq!(id, REAL_ID_SHIFT as u32);
    }

    #[test]
    fn get_id_from_price_does_not_overflow() {
        // The full 128.128 dynamic range (up to U256::MAX) gives log2 in
        // [-128, +128]; divided by log2(base) ~= 1.225e36 (in 128.128) the
        // quotient stays in roughly +/-35_000 around REAL_ID_SHIFT. So
        // U256::MAX maps to ~REAL_ID_SHIFT + 35_533, well below MAX_BIN_ID.
        // Saturation branches exist defensively for future BIN_STEP_BP
        // values where the bin range could overflow.
        let id = get_id_from_price(U256::MAX, BIN_STEP_BP).unwrap();
        // Stays within the realistic narrow band; confirm < MAX_BIN_ID.
        assert!(
            id > REAL_ID_SHIFT as u32 && id < MAX_BIN_ID,
            "id = {id}; expected REAL_ID_SHIFT < id < MAX_BIN_ID"
        );
    }

    #[test]
    fn price_to_bin_monotonic_small_sample() {
        // For a hand-picked ascending price ladder, bin ids must be
        // non-decreasing.
        let prices = [
            U256::from(1u64),
            U256::from(1_000u64),
            U256::from(1_000_000u64),
            PRECISION / U256::from(1000u64),
            PRECISION,
            PRECISION * U256::from(1000u64),
        ];
        let mut last_bin = 0u32;
        for p in prices {
            let p128 = convert_decimal_price_to_128x128(p).unwrap();
            let id = get_id_from_price(p128, BIN_STEP_BP).unwrap();
            assert!(id >= last_bin, "monotonicity broken: {last_bin} -> {id}");
            last_bin = id;
        }
    }
}
