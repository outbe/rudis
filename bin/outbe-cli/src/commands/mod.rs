pub mod chain;
pub mod epoch;
pub mod monitor;
pub mod oracle;
pub mod rad;
pub mod radicle;
pub mod rewards;
pub mod slash;
pub mod stablecoin;
pub mod staking;
pub mod tee;
pub mod tribute;
pub mod validator;
pub mod vote;
pub mod zerofee;

use crate::tx::TxSigner;
use eyre::Result;

pub fn require_signer(private_key: Option<&str>) -> Result<TxSigner> {
    let key =
        private_key.ok_or_else(|| eyre::eyre!("--private-key required for this operation"))?;
    TxSigner::new(key)
}

fn format_decimals(value: alloy_primitives::U256, decimals: u8) -> String {
    use alloy_primitives::U256;

    if value.is_zero() {
        return "0".to_string();
    }

    let divisor = U256::from(10u64).pow(U256::from(decimals));
    let whole = value / divisor;
    let frac = value % divisor;

    if frac.is_zero() {
        format!("{whole}")
    } else {
        let frac_str = format!("{frac:0>width$}", width = usize::from(decimals));
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed}")
    }
}

/// Format a raw native COEN amount in 18-decimal base units.
pub fn format_coen_amount(value: alloy_primitives::U256) -> String {
    format_decimals(value, 18)
}

/// Format a six-decimal protocol amount, such as a COEN/ISO oracle rate.
pub fn format_protocol_amount(value: alloy_primitives::U256) -> String {
    format_decimals(value, 6)
}

/// Format an independently owned FP18 value.
pub fn format_generic_fp18(value: alloy_primitives::U256) -> String {
    format_decimals(value, 18)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    #[test]
    fn test_format_unit_zero() {
        assert_eq!(format_coen_amount(U256::ZERO), "0");
    }

    #[test]
    fn test_format_unit_one_coen() {
        assert_eq!(
            format_coen_amount(U256::from(1_000_000_000_000_000_000u128)),
            "1"
        );
    }

    #[test]
    fn test_format_unit_large_whole() {
        let val = U256::from(1_000_000_000_000_000_000_000u128);
        assert_eq!(format_coen_amount(val), "1000");
    }

    #[test]
    fn test_format_unit_fractional() {
        let val = U256::from(1_500_000_000_000_000_000u128);
        assert_eq!(format_coen_amount(val), "1.5");
    }

    #[test]
    fn test_format_unit_pure_fraction() {
        let val = U256::from(500_000_000_000_000_000u128);
        assert_eq!(format_coen_amount(val), "0.5");
    }

    #[test]
    fn test_format_unit_one_native_unit() {
        assert_eq!(format_coen_amount(U256::from(1u64)), "0.000000000000000001");
    }

    #[test]
    fn test_format_unit_trailing_zeros_trimmed() {
        let val = U256::from(1_200_000_000_000_000_000u128);
        assert_eq!(format_coen_amount(val), "1.2");
    }

    #[test]
    fn test_format_unit_all_decimal_places() {
        let val = U256::from(999_999_999_999_999_999u128);
        assert_eq!(format_coen_amount(val), "0.999999999999999999");
    }

    #[test]
    fn test_format_protocol_amount_remains_six_decimals() {
        assert_eq!(format_protocol_amount(U256::from(1_500_000u64)), "1.5");
    }

    #[test]
    fn test_format_unit_max_u256_does_not_panic() {
        let result = format_coen_amount(U256::MAX);
        assert!(!result.is_empty());
        assert!(result.contains('.'));
    }
}
