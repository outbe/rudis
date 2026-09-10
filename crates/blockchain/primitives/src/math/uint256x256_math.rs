//! PancakeSwap Liquidity Book `Uint256x256Math` port.
//!
//! Verified against `pancakeswap/infinity-core@main` (2026-05-12):
//! - `src/pool-bin/libraries/math/Uint256x256Math.sol`
//!
//! Function names mirror the Solidity verbatim so the port is auditable
//! line-for-line. Solidity `revert` becomes Outbe `Err(PrecompileError)`;
//! Solidity assembly becomes deterministic U256 ops with explicit widening
//! through limb-based 512-bit multiplication. No floats, no randomness,
//! no time - safe on consensus paths.

use alloy_primitives::U256;

use crate::error::{PrecompileError, Result};

// --- 512-bit multiplication / division ---------------------------------------

/// 512-bit multiplication via schoolbook on u64 limbs.
///
/// Mirrors `Uint256x256Math._getMulProds` (Uint256x256Math.sol L120-129).
/// Returns `(prod0, prod1)` such that `x * y == prod1 * 2^256 + prod0`.
/// Pure Rust - no inline assembly, no `unsafe`. Deterministic across all
/// targets because every intermediate fits in `u128` (u64*u64 <= 2^128 - 2^65 + 1
/// + 2*u64 carry chain).
fn get_mul_prods(x: U256, y: U256) -> (U256, U256) {
    let xs = x.as_limbs(); // little-endian: limb[0] = bits 0..63
    let ys = y.as_limbs();
    let mut product: [u64; 8] = [0u64; 8];

    // Standard schoolbook: O(16) inner mults; 64-bit outputs accumulate via u128.
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cur = product[i + j] as u128;
            let p = (xs[i] as u128) * (ys[j] as u128) + cur + carry;
            product[i + j] = p as u64;
            carry = p >> 64;
        }
        product[i + 4] = carry as u64;
    }

    let prod0 = U256::from_limbs([product[0], product[1], product[2], product[3]]);
    let prod1 = U256::from_limbs([product[4], product[5], product[6], product[7]]);
    (prod0, prod1)
}

/// `(x * y) mod denom` for a 256-bit denominator and 256-bit operands.
/// Returns the remainder via long division of the 512-bit product.
fn mul_mod_512(x: U256, y: U256, denom: U256) -> U256 {
    debug_assert!(!denom.is_zero(), "mul_mod_512: zero denominator");
    let (prod0, prod1) = get_mul_prods(x, y);
    // Bit-by-bit long division of [prod1, prod0] by denom; we only need the
    // remainder. 512 iterations; each is U256 ops only.
    let mut rem = U256::ZERO;
    // High half first, then low half.
    for word in [prod1, prod0] {
        for bit in (0..256u32).rev() {
            // Shift remainder left by 1.
            rem <<= 1;
            // Or in the next bit of the dividend.
            if !(word & (U256::ONE << bit as usize)).is_zero() {
                rem |= U256::ONE;
            }
            if rem >= denom {
                rem = rem.wrapping_sub(denom);
            }
        }
    }
    rem
}

/// Remco Bloemen's mulDiv with rounding down. Mirrors
/// `Uint256x256Math._getEndOfDivRoundDown` (Uint256x256Math.sol L138-194).
/// Computes `floor((x * y) / denom)` with full 512-bit precision; reverts
/// when the quotient would not fit in `U256`.
fn get_end_of_div_round_down(
    x: U256,
    y: U256,
    denom: U256,
    prod0_in: U256,
    prod1: U256,
) -> Result<U256> {
    if prod1.is_zero() {
        if denom.is_zero() {
            return Err(PrecompileError::Revert("lb_math: mul_div by zero".into()));
        }
        return Ok(prod0_in / denom);
    }
    if prod1 >= denom {
        return Err(PrecompileError::Revert("lb_math: mul_div overflow".into()));
    }

    // Make division exact by subtracting remainder from [prod1, prod0].
    let remainder = mul_mod_512(x, y, denom);
    let prod1_adj = if remainder > prod0_in {
        prod1.wrapping_sub(U256::ONE)
    } else {
        prod1
    };
    let prod0_adj = prod0_in.wrapping_sub(remainder);

    // Factor powers of two out of denominator.
    // lpotdod = denom & -denom - largest power-of-two divisor of denom.
    let lpotdod = denom & denom.wrapping_neg();
    let denom_odd = denom / lpotdod;
    let prod0_shifted = prod0_adj / lpotdod;

    // lpotdod_inv = 2^256 / lpotdod (or 1 if lpotdod == 0).
    // In Solidity assembly: `add(div(sub(0, lpotdod), lpotdod), 1)`.
    let lpotdod_inv = if lpotdod.is_zero() {
        U256::ONE
    } else {
        // (0 - lpotdod) / lpotdod + 1, all wrapping.
        // Equivalent: 2^256 / lpotdod when lpotdod is a power of 2.
        (U256::ZERO.wrapping_sub(lpotdod) / lpotdod).wrapping_add(U256::ONE)
    };

    // Shift in bits from prod1 into prod0_shifted.
    let combined = prod0_shifted | prod1_adj.wrapping_mul(lpotdod_inv);

    // Newton-Raphson modular inverse of denom_odd (mod 2^256).
    // Seed exact for 4 bits; doubles each iteration (Hensel lifting).
    let two = U256::from(2u64);
    let mut inverse = (U256::from(3u64).wrapping_mul(denom_odd)) ^ two;
    for _ in 0..6 {
        let term = two.wrapping_sub(denom_odd.wrapping_mul(inverse));
        inverse = inverse.wrapping_mul(term);
    }

    Ok(combined.wrapping_mul(inverse))
}

// --- Public API --------------------------------------------------------------

/// Mirrors `Uint256x256Math.mulShiftRoundDown(x, y, offset)`
/// (Uint256x256Math.sol L60-72): `floor((x * y) >> offset)`.
pub fn mul_shift_round_down(x: U256, y: U256, offset: u8) -> Result<U256> {
    let (prod0, prod1) = get_mul_prods(x, y);
    let off = offset as usize;
    let mut result = U256::ZERO;
    if !prod0.is_zero() {
        result = prod0 >> off;
    }
    if !prod1.is_zero() {
        // Result must fit in 256 bits.
        if prod1 >= (U256::ONE << off) {
            return Err(PrecompileError::Revert(
                "lb_math: mul_shift overflow".into(),
            ));
        }
        // (256 - offset) is in (0, 256] - guard offset == 0.
        if off > 0 {
            result = result.wrapping_add(prod1 << (256 - off));
        }
    }
    Ok(result)
}

/// Mirrors `Uint256x256Math.shiftDivRoundDown(x, offset, denominator)`
/// (Uint256x256Math.sol L98-107): `floor((x << offset) / denominator)`.
pub fn shift_div_round_down(x: U256, offset: u8, denom: U256) -> Result<U256> {
    let off = offset as usize;
    let prod0 = x << off;
    let prod1 = if off == 0 {
        U256::ZERO
    } else {
        x >> (256 - off)
    };
    // y = 1 << offset (used by mul_mod_512 inside _getEndOfDivRoundDown).
    let y = if off >= 256 {
        U256::ZERO // unreachable; offset is always < 256 by precondition.
    } else {
        U256::ONE << off
    };
    get_end_of_div_round_down(x, y, denom, prod0, prod1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_shift_round_down_matches_simple_cases() {
        // (5 * 8) >> 2 = 40 >> 2 = 10.
        let r = mul_shift_round_down(U256::from(5u64), U256::from(8u64), 2).unwrap();
        assert_eq!(r, U256::from(10u64));
    }

    #[test]
    fn shift_div_round_down_matches_simple_cases() {
        // (3 << 4) / 6 = 48 / 6 = 8.
        let r = shift_div_round_down(U256::from(3u64), 4, U256::from(6u64)).unwrap();
        assert_eq!(r, U256::from(8u64));
    }

    #[test]
    fn get_mul_prods_max_squared() {
        // U256::MAX * U256::MAX = (2^256 - 1)^2 = 2^512 - 2^257 + 1.
        // High = 2^256 - 2, low = 1.
        let (lo, hi) = get_mul_prods(U256::MAX, U256::MAX);
        assert_eq!(lo, U256::ONE);
        assert_eq!(hi, U256::MAX - U256::ONE);
    }

    #[test]
    fn get_mul_prods_small_cases() {
        let (lo, hi) = get_mul_prods(U256::from(7u64), U256::from(13u64));
        assert_eq!(lo, U256::from(91u64));
        assert_eq!(hi, U256::ZERO);
    }
}
