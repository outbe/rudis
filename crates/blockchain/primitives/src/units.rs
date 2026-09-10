//! Fixed-point scaling helpers.
//!
//! The default economic type is `U256`

use alloy_primitives::U256;

/// Native token symbol.
pub const NATIVE_TOKEN_SYMBOL: &str = "rudis";

/// Base denomination.
pub const BASE_DENOM: &str = "unit";

/// Independent 18-decimal fixed-point scale.
///
/// This is not a token denomination. Dimensionless protocols that explicitly
/// own an FP18 contract may keep using it after the native-token cutover.
pub const SCALE_1E18: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);
pub const SCALE_1E18_U128: u128 = 1_000_000_000_000_000_000;

/// Shared six-decimal integer scale in the representation required by a caller.
///
/// The constant owns only the numeric scale. The surrounding field or variable
/// name must identify whether the value is a token amount, price, rate, or ratio.
pub const SCALE_1E6_U64: u64 = 1_000_000;
pub const SCALE_1E6_U128: u128 = 1_000_000;
pub const SCALE_1E6_U256: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

/// Decimal places used by protocol amounts such as PROMIS, GRATIS, emission,
/// Gem loads, and stablecoin-backed COEN/ISO prices.
pub const PROTOCOL_AMOUNT_DECIMALS: u8 = 6;

/// Native atomic units represented by one minimal six-decimal protocol unit.
pub const NATIVE_UNITS_PER_PROTOCOL_UNIT: U256 = U256::from_limbs([1_000_000_000_000, 0, 0, 0]);

/// One whole native COEN, expressed in the EVM account-balance representation.
pub const ONE_COEN: U256 = SCALE_1E18;

/// The smallest representable on-chain amount (1 unit).
pub const ONE_UNIT: U256 = U256::ONE;

/// Number of decimal places.
pub const NATIVE_TOKEN_DECIMALS: u8 = 18;

/// Converts a six-decimal protocol amount into native COEN atomic units.
///
/// Returns `None` rather than wrapping when the native representation would
/// exceed `U256`.
pub fn checked_protocol_to_native(amount: U256) -> Option<U256> {
    amount.checked_mul(NATIVE_UNITS_PER_PROTOCOL_UNIT)
}

/// Converts a whole-COEN count into native COEN atomic units.
///
/// The explicit name prevents this helper from being mistaken for a PROMIS,
/// GRATIS, price, rate, or emission conversion.
pub fn checked_whole_coen_to_native(whole_coen: U256) -> Option<U256> {
    whole_coen.checked_mul(ONE_COEN)
}

/// Reduces a native COEN amount to the protocol's six-decimal precision.
/// Any sub-protocol-unit native remainder is deliberately discarded.
pub fn native_to_protocol_floor(amount: U256) -> U256 {
    amount / NATIVE_UNITS_PER_PROTOCOL_UNIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_coen_uses_eighteen_decimal_units_while_protocol_stays_six_decimal() {
        let one_coen = U256::from(1_000_000_000_000_000_000u128);

        assert_eq!(ONE_UNIT, U256::ONE);
        assert_eq!(ONE_COEN, one_coen);
        assert_eq!(SCALE_1E6_U64, 1_000_000);
        assert_eq!(SCALE_1E6_U128, 1_000_000);
        assert_eq!(SCALE_1E6_U256, U256::from(1_000_000u64));
        assert_eq!(NATIVE_TOKEN_DECIMALS, 18);
        assert_eq!(NATIVE_TOKEN_SYMBOL, "rudis");
        assert_eq!(BASE_DENOM, "unit");
    }

    #[test]
    fn protocol_amount_converts_to_native_coen_without_changing_protocol_precision() {
        assert_eq!(
            checked_protocol_to_native(U256::ONE),
            Some(U256::from(1_000_000_000_000u64))
        );
        assert_eq!(checked_protocol_to_native(SCALE_1E6_U256), Some(ONE_COEN));
    }

    #[test]
    fn native_remainder_is_dropped_only_when_returning_to_protocol_precision() {
        assert_eq!(
            native_to_protocol_floor(NATIVE_UNITS_PER_PROTOCOL_UNIT - U256::ONE),
            U256::ZERO
        );
        assert_eq!(
            native_to_protocol_floor(NATIVE_UNITS_PER_PROTOCOL_UNIT + U256::from(7u64)),
            U256::ONE
        );
    }

    #[test]
    fn whole_coen_conversion_is_explicitly_native() {
        assert_eq!(
            checked_whole_coen_to_native(U256::from(2u64)),
            Some(ONE_COEN * U256::from(2u64))
        );
    }

    #[test]
    fn protocol_to_native_conversion_rejects_overflow() {
        assert_eq!(checked_protocol_to_native(U256::MAX), None);
    }
}
