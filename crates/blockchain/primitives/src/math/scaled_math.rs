//! Checked integer scaling shared by monetary protocol modules.
//!
//! These helpers deliberately reject a `U256` product overflow. Callers keep
//! their existing `U256` domain and choose floor or ceil explicitly at the
//! economic ownership boundary.

use alloy_primitives::U256;

use crate::error::{PrecompileError, Result};

fn checked_product(numerator: U256, multiplier: U256) -> Result<U256> {
    numerator
        .checked_mul(multiplier)
        .ok_or_else(|| PrecompileError::Revert("scaled_math: multiplication overflow".into()))
}

fn require_denominator(denominator: U256) -> Result<()> {
    if denominator.is_zero() {
        return Err(PrecompileError::Revert(
            "scaled_math: division by zero".into(),
        ));
    }
    Ok(())
}

/// Returns `floor(numerator * multiplier / denominator)`.
pub fn checked_mul_div_floor(numerator: U256, multiplier: U256, denominator: U256) -> Result<U256> {
    require_denominator(denominator)?;
    Ok(checked_product(numerator, multiplier)? / denominator)
}

/// Returns `ceil(numerator * multiplier / denominator)`.
pub fn checked_mul_div_ceil(numerator: U256, multiplier: U256, denominator: U256) -> Result<U256> {
    require_denominator(denominator)?;
    let product = checked_product(numerator, multiplier)?;
    let quotient = product / denominator;
    if product % denominator == U256::ZERO {
        return Ok(quotient);
    }
    quotient
        .checked_add(U256::ONE)
        .ok_or_else(|| PrecompileError::Revert("scaled_math: ceiling overflow".into()))
}
