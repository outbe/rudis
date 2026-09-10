use alloy_primitives::{U256, U512};
use serde::{de::Error as _, Deserialize, Deserializer};

#[cfg(test)]
use outbe_primitives::units::SCALE_1E18;

/// Non-negative decimal value represented deterministically at FP18.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FixedValue(U256);

impl FixedValue {
    pub const ZERO: Self = Self(U256::ZERO);

    pub const fn from_raw(raw: U256) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> U256 {
        self.0
    }

    pub fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    pub fn checked_mul_ratio(self, numerator: u64, denominator: u64) -> Option<Self> {
        let result = U512::from(self.0)
            .checked_mul(U512::from(numerator))?
            .checked_div(U512::from(denominator))?;
        if result > U512::from(U256::MAX) {
            return None;
        }
        Some(Self(result.wrapping_to::<U256>()))
    }

    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        if input.is_empty() || input.starts_with('-') {
            return None;
        }
        let input = input.strip_prefix('+').unwrap_or(input);
        let mut exponent_parts = input.split(['e', 'E']);
        let mantissa = exponent_parts.next()?;
        let exponent = exponent_parts
            .next()
            .map_or(Some(0i32), |value| value.parse::<i32>().ok())?;
        if exponent_parts.next().is_some() {
            return None;
        }

        let mut decimal_parts = mantissa.split('.');
        let whole = decimal_parts.next()?;
        let fraction = decimal_parts.next().unwrap_or("");
        if decimal_parts.next().is_some()
            || (whole.is_empty() && fraction.is_empty())
            || !whole
                .bytes()
                .chain(fraction.bytes())
                .all(|byte| byte.is_ascii_digit())
        {
            return None;
        }

        let fraction_len = i64::try_from(fraction.len()).ok()?;
        let shift = 18i64
            .checked_add(i64::from(exponent))
            .and_then(|value| value.checked_sub(fraction_len))?;
        let digit_count = whole.len().checked_add(fraction.len())?;
        let kept_digits = if shift < 0 {
            let discarded = usize::try_from(-shift).unwrap_or(usize::MAX);
            digit_count.saturating_sub(discarded)
        } else {
            digit_count
        };

        let mut coefficient = U256::ZERO;
        for byte in whole.bytes().chain(fraction.bytes()).take(kept_digits) {
            coefficient = coefficient.checked_mul(U256::from(10u64))?;
            coefficient = coefficient.checked_add(U256::from(byte - b'0'))?;
        }
        if coefficient.is_zero() {
            return Some(Self::ZERO);
        }

        let raw = if shift >= 0 {
            let shift = u32::try_from(shift).ok()?;
            if shift > 77 {
                return None;
            }
            coefficient.checked_mul(pow10(shift)?)?
        } else {
            coefficient
        };
        Some(Self(raw))
    }
}

fn pow10(exponent: u32) -> Option<U256> {
    let mut value = U256::ONE;
    for _ in 0..exponent {
        value = value.checked_mul(U256::from(10u64))?;
    }
    Some(value)
}

impl<'de> Deserialize<'de> for FixedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| D::Error::custom("expected a non-negative decimal string"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum JsonDecimal {
    String(String),
    Number(serde_json::Number),
}

impl JsonDecimal {
    pub fn fixed(&self) -> Option<FixedValue> {
        match self {
            Self::String(value) => FixedValue::parse(value),
            Self::Number(value) => FixedValue::parse(&value.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_parser_is_exact_and_supports_scientific_notation() {
        assert_eq!(FixedValue::parse("1").unwrap().raw(), SCALE_1E18);
        assert_eq!(
            FixedValue::parse("0.000000000000000001").unwrap().raw(),
            U256::ONE
        );
        assert_eq!(
            FixedValue::parse("2.5e3").unwrap().raw(),
            U256::from(2_500u64) * SCALE_1E18
        );
        assert_eq!(
            FixedValue::parse("25e-1").unwrap().raw(),
            U256::from(25u64) * SCALE_1E18 / U256::from(10u64)
        );
    }

    #[test]
    fn decimal_parser_floors_beyond_fp18_without_binary_rounding() {
        assert_eq!(
            FixedValue::parse("1.0000000000000000009").unwrap().raw(),
            SCALE_1E18
        );
        assert_eq!(FixedValue::parse("4e-19").unwrap().raw(), U256::ZERO);
    }

    #[test]
    fn decimal_parser_discards_a_long_fraction_before_u256_conversion() {
        let one_with_irrelevant_tail = format!("1.{}9", "0".repeat(200));
        assert_eq!(
            FixedValue::parse(&one_with_irrelevant_tail).unwrap().raw(),
            SCALE_1E18
        );
        let one_minor_unit_with_irrelevant_tail =
            format!("0.000000000000000001{}9", "9".repeat(200));
        assert_eq!(
            FixedValue::parse(&one_minor_unit_with_irrelevant_tail)
                .unwrap()
                .raw(),
            U256::ONE
        );
    }

    #[test]
    fn config_deserialization_requires_a_decimal_string() {
        assert!(serde_json::from_str::<FixedValue>("\"2.0\"").is_ok());
        assert!(serde_json::from_str::<FixedValue>("2.0").is_err());
    }

    #[test]
    fn arbitrary_precision_json_number_keeps_its_decimal_lexeme() {
        let value: JsonDecimal =
            serde_json::from_str("1.000000000000000001").expect("JSON number parses");
        assert_eq!(value.fixed().unwrap().raw(), SCALE_1E18 + U256::ONE);
    }

    #[test]
    fn decimal_parser_rejects_negative_malformed_and_overflowing_values() {
        for invalid in ["-1", "", ".", "1.2.3", "1e", "1e78"] {
            assert!(FixedValue::parse(invalid).is_none(), "accepted {invalid:?}");
        }
    }
}
