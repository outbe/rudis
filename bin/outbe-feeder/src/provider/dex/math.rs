use alloy_primitives::{aliases::U1024, U256, U512};
use eyre::{ensure, eyre, Result};

use crate::fixed::FixedValue;

/// Convert an oriented raw-token ratio into human quote/base FP18. At most 77
/// decimals per token keeps intermediate products below 1024 bits, even when
/// squaring a uint160 sqrt price. Round only after orientation and scaling.
pub(super) fn rate(
    numerator: U512,
    denominator: U512,
    base_decimals: u8,
    quote_decimals: u8,
) -> Result<FixedValue> {
    ensure!(
        !numerator.is_zero() && !denominator.is_zero(),
        "uninitialized or zero pool price"
    );
    ensure!(
        base_decimals <= 77 && quote_decimals <= 77,
        "unsupported token decimals (>77)"
    );
    let n = U1024::from(numerator)
        .checked_mul(ten_pow(u32::from(base_decimals) + 18))
        .ok_or_else(|| eyre!("DEX rate numerator overflow"))?;
    let d = U1024::from(denominator)
        .checked_mul(ten_pow(u32::from(quote_decimals)))
        .ok_or_else(|| eyre!("DEX rate denominator overflow"))?;
    let result = n / d;
    ensure!(
        result > U1024::ZERO && result <= U1024::from(U256::MAX),
        "DEX rate outside FP18 range"
    );
    // Explicit range check above proves the narrowing preserves the value.
    Ok(FixedValue::from_raw(result.wrapping_to::<U256>()))
}

pub(super) fn base_volume(raw: U256, decimals: u8) -> Result<FixedValue> {
    ensure!(decimals <= 77, "unsupported token decimals (>77)");
    let result = U1024::from(raw) * ten_pow(18) / ten_pow(u32::from(decimals));
    ensure!(
        result <= U1024::from(U256::MAX),
        "DEX volume outside FP18 range"
    );
    Ok(FixedValue::from_raw(result.wrapping_to::<U256>()))
}

fn ten_pow(exponent: u32) -> U1024 {
    // Callers bound exponent to 95; 10^95 fits well within U1024.
    U1024::from(10u64).pow(U1024::from(exponent))
}

/// Infinity PriceHelper's Q128.128 bin price, including its reciprocal and
/// rounding convention. Normalize below 1 before exponentiation so each
/// multiplication fits in 256 bits. Accepted exponents match upstream pow().
pub(super) fn bin_price(active_id: u32, bin_step: u16) -> Result<U256> {
    ensure!(bin_step > 0, "zero bin step");
    let exponent = i64::from(active_id) - (1i64 << 23);
    let mut power = exponent.unsigned_abs();
    ensure!(power < 0x10_0000, "Infinity bin exponent out of range");
    let scale = U256::ONE << 128;
    if power == 0 {
        return Ok(scale);
    }
    let base = scale + (U256::from(bin_step) << 128) / U256::from(10_000u64);
    let mut factor = U256::MAX / base;
    let mut result = scale;
    while power > 0 {
        if power & 1 != 0 {
            result = (result * factor) >> 128;
        }
        power >>= 1;
        if power > 0 {
            factor = (factor * factor) >> 128;
        }
    }
    ensure!(!result.is_zero(), "Infinity bin price underflow");
    Ok(if exponent > 0 {
        U256::MAX / result
    } else {
        result
    })
}
