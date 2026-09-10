//! PancakeSwap Liquidity Book `Uint128x128Math` port.
//!
//! Verified against `pancakeswap/infinity-core@main` (2026-05-12):
//! - `src/pool-bin/libraries/math/Uint128x128Math.sol`
//!
//! Function names mirror the Solidity verbatim so the port is auditable
//! line-for-line. Solidity `revert` becomes Outbe `Err(PrecompileError)`.

use alloy_primitives::{I256, U256};

use crate::error::{PrecompileError, Result};
use crate::math::bit_math::most_significant_bit;
use crate::math::constants::SCALE_1_128_128;

const LOG_SCALE_OFFSET: u32 = 127;
/// `1 << 127` - the 1.0 of the inner 129.127 fixed-point space used by `log2`.
/// Bit 127 lives at limb 1 (bits 64..127), position 63.
const LOG_SCALE: U256 = U256::from_limbs([0, 1u64 << 63, 0, 0]);
/// `LOG_SCALE * LOG_SCALE = 1 << 254`. Bit 254 lives at limb 3, position 62.
const LOG_SCALE_SQUARED: U256 = U256::from_limbs([0, 0, 0, 1u64 << 62]);

/// Mirrors `Uint128x128Math.log2(uint256)` (Uint128x128Math.sol L29-86).
/// Calculates `log2(x)` for `x` in 128.128 fixed-point. Returns the result
/// as a signed 128.128 fixed-point. Reverts if `x == 0` (LB
/// `Uint128x128Math__LogUnderflow`).
pub fn log2(x: U256) -> Result<I256> {
    // Special cases match LB.
    if x == U256::ONE {
        return I256::try_from(-128i32)
            .map_err(|_| PrecompileError::Revert("lb_math: log2 i256 conversion".into()));
    }
    if x.is_zero() {
        return Err(PrecompileError::Revert(
            "lb_math: log2 underflow (x == 0)".into(),
        ));
    }

    // Convert x from 128.128 to 129.127 by halving (one bit of headroom).
    let mut x_inner = x >> 1;

    // Sign: log2(1/x) = -log2(x). If x < 1.0 (i.e., x_inner < LOG_SCALE),
    // invert and negate.
    let sign: I256;
    if x_inner >= LOG_SCALE {
        sign = I256::ONE;
    } else {
        sign = I256::MINUS_ONE;
        // Inline fixed-point inversion: (LOG_SCALE^2) / x_inner.
        x_inner = LOG_SCALE_SQUARED / x_inner;
    }

    // Integer part: n = MSB(x >> LOG_SCALE_OFFSET).
    let n = most_significant_bit(x_inner >> LOG_SCALE_OFFSET as usize);
    // result = n << LOG_SCALE_OFFSET (signed 129.127).
    let mut result = I256::try_from(U256::from(n))
        .map_err(|_| PrecompileError::Revert("lb_math: log2 n widen".into()))?
        << LOG_SCALE_OFFSET as usize;

    // y = x * 2^(-n).
    let mut y: U256 = x_inner >> n as usize;

    if y != LOG_SCALE {
        // Iterative refinement: 127 rounds of bit-by-bit fractional logarithm.
        let mut delta: I256 = I256::ONE << (LOG_SCALE_OFFSET - 1) as usize;
        while delta > I256::ZERO {
            // y = (y * y) >> LOG_SCALE_OFFSET. y stays under 2^128 by construction
            // (we squared a 128-bit number, shift back down).
            y = y.wrapping_mul(y) >> LOG_SCALE_OFFSET as usize;
            // If y^2 >= 2 (== 1 << (LOG_SCALE_OFFSET + 1)), record the bit.
            let two_threshold = U256::ONE << (LOG_SCALE_OFFSET + 1) as usize;
            if y >= two_threshold {
                result = result.saturating_add(delta);
                y >>= 1;
            }
            delta >>= 1;
        }
    }

    // Convert from signed 129.127 back to signed 128.128: multiply by sign,
    // then shift left by 1.
    Ok((result * sign) << 1u32)
}

/// Mirrors `Uint128x128Math.pow(uint256, int256)` (Uint128x128Math.sol L91-159).
/// Computes `x^y` in 128.128 fixed-point. `y` is a signed plain integer
/// (no decimals); LB constrains `|y| < 2^20`. Returns
/// `Err(PrecompileError::Revert)` for `result == 0` (matches LB underflow)
/// or for `|y| >= 2^20` (LB skips the assembly block, leaving `result == 0`,
/// then reverts with `PowUnderflow`).
pub fn pow(x: U256, y: i32) -> Result<U256> {
    if y == 0 {
        return Ok(SCALE_1_128_128);
    }
    let mut invert = false;
    let abs_y: u32 = if y < 0 {
        invert = true;
        // y is i32; -y can overflow only when y == i32::MIN. For our use
        // case |y| < 2^23, so this is safe.
        y.unsigned_abs()
    } else {
        y as u32
    };

    if abs_y >= 0x100000 {
        // LB writes `revert PowUnderflow(x, y)` after the if-block when result == 0.
        // Our caller treats this as either saturation (caller decides) or hard error.
        return Err(PrecompileError::Revert(format!(
            "lb_math: pow exponent out of LB range (|y| = {abs_y})"
        )));
    }

    // Square-and-multiply over the 20 bits of |y|.
    let mut squared = x;
    // If x > 2^128 - 1 (i.e., x >= 2^128, x represents >= 1.0), invert squared
    // to (2^256 - 1) / x and flip invert. This keeps `squared` < 2^128 so
    // `mul(squared, squared)` doesn't overflow.
    let above_one = U256::from_limbs([u64::MAX, u64::MAX, 0, 0]);
    if squared > above_one {
        squared = U256::MAX / squared;
        invert = !invert;
    }

    let mut result = SCALE_1_128_128;
    for bit in 0..20u32 {
        if (abs_y >> bit) & 1 == 1 {
            // result = (result * squared) >> 128. Multiplication in U256
            // wraps mod 2^256; we then take the upper 128 bits via >> 128.
            result = result.wrapping_mul(squared) >> 128;
        }
        // squared = (squared * squared) >> 128 - for next bit.
        squared = squared.wrapping_mul(squared) >> 128;
    }

    if result.is_zero() {
        return Err(PrecompileError::Revert(format!(
            "lb_math: pow underflow (x = {x}, y = {y})"
        )));
    }

    if invert {
        // (2^256 - 1) / result ~= 2^256 / result (off by < 1 ULP).
        Ok(U256::MAX / result)
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::price_helper::get_base;

    const BIN_STEP_BP: u16 = 25;

    #[test]
    fn pow_zero_exponent_returns_scale() {
        assert_eq!(pow(SCALE_1_128_128, 0).unwrap(), SCALE_1_128_128);
        assert_eq!(pow(get_base(BIN_STEP_BP), 0).unwrap(), SCALE_1_128_128);
    }

    #[test]
    fn pow_one_returns_x() {
        // pow(SCALE, 1) should be SCALE within 1 ULP. LB's pow inverts the
        // squared base when x >= 2^128 (SCALE itself triggers this), so the
        // round-trip incurs a single-bit error: we get SCALE + 1, not SCALE.
        let r = pow(SCALE_1_128_128, 1).unwrap();
        let diff = if r > SCALE_1_128_128 {
            r - SCALE_1_128_128
        } else {
            SCALE_1_128_128 - r
        };
        assert!(diff <= U256::from(1u64), "pow(SCALE, 1) diff = {diff}");
    }

    #[test]
    fn pow_base_one_returns_base_within_ulp() {
        // pow(BASE, 1) should equal BASE up to 1 ULP.
        let base = get_base(BIN_STEP_BP);
        let result = pow(base, 1).unwrap();
        let diff = if result > base {
            result - base
        } else {
            base - result
        };
        // Tolerance: a few ULPs of 128.128 (i.e., a few bits at position 0).
        assert!(diff <= U256::from(0x10u64), "pow(base,1) diff = {diff}");
    }

    #[test]
    fn pow_exponent_too_large_errors() {
        assert!(pow(SCALE_1_128_128, 1_048_576).is_err());
        assert!(pow(SCALE_1_128_128, -1_048_576).is_err());
    }

    #[test]
    fn log2_one_is_zero() {
        // log2(1.0_128x128) should be 0.
        let r = log2(SCALE_1_128_128).unwrap();
        // Within a small tolerance of 0.
        let abs = if r >= I256::ZERO { r } else { -r };
        assert!(abs <= I256::try_from(U256::ONE << 64).unwrap());
    }

    #[test]
    fn log2_two_is_one_in_128x128() {
        // log2(2.0_128x128) should be 1.0_128x128 = SCALE.
        let r = log2(SCALE_1_128_128 << 1).unwrap();
        let one_128x128 = I256::try_from(SCALE_1_128_128).unwrap();
        let diff = if r > one_128x128 {
            r - one_128x128
        } else {
            one_128x128 - r
        };
        // Within a few bits of SCALE.
        assert!(diff <= I256::try_from(U256::ONE << 64).unwrap());
    }

    #[test]
    fn log2_zero_errors() {
        assert!(log2(U256::ZERO).is_err());
    }
}
