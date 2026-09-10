//! Every asset an oracle pair can name, encoded as a single [`Address`].
//!
//! Native COEN, an ISO 4217 currency and an ERC20 token all collapse onto one
//! 20-byte address, so a pair of assets is just an [`AddressPair`] and needs no
//! symbol strings and no hashing.

use alloy_primitives::{Address, U256};

/// Native COEN as an asset address - the base of every settlement pair.
pub const COEN_ASSET: Address = Address::ZERO;

/// Represents an asset type supported by the Oracle.
/// Such assets can be used for keying pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetType {
    /// Native token i.e. COEN
    Native,
    /// Arbitrary ERC20 token address
    ERC20(Address),
    /// ISO 4217 currency code
    IsoCurrency(u16),
}

impl From<AssetType> for Address {
    /// A currency code is packed as BCD behind the [`ISO_MARKER`] nibbles, so
    /// ISO 840 becomes `0x0000...0cc840`. `ERC20` addresses inside that reserved
    /// range decode back as `IsoCurrency`.
    fn from(value: AssetType) -> Self {
        match value {
            AssetType::Native => COEN_ASSET,
            AssetType::ERC20(address) => address,
            AssetType::IsoCurrency(code) => {
                let marked = ISO_MARKER | u32::from(bcd_encode(code));
                Address::left_padding_from(&marked.to_be_bytes())
            }
        }
    }
}

impl From<Address> for AssetType {
    fn from(value: Address) -> Self {
        let raw = U256::from_be_slice(value.as_slice());
        if raw.is_zero() {
            AssetType::Native
        } else if let Some(code) = iso_code(raw) {
            AssetType::IsoCurrency(code)
        } else {
            AssetType::ERC20(value)
        }
    }
}

/// ISO 4217 numeric code `iso_code` as an asset address, e.g. 840 for USD.
pub fn currency_address(iso_code: u16) -> Address {
    AssetType::IsoCurrency(iso_code).into()
}

/// Marker nibbles every ISO currency address carries, keeping the reserved
/// range clear of low-numbered token addresses.
const ISO_MARKER: u32 = 0xcc000;

/// Highest address in the reserved ISO range: the marker plus BCD 999.
const ISO_MARKER_MAX: u32 = 0xcc999;

/// The ISO code an address encodes, or `None` when it falls outside
/// `ISO_MARKER..=ISO_MARKER_MAX` or carries a non-decimal nibble.
///
/// The range is matched against the whole 20-byte value, so every byte above
/// the marker has to be zero: a token address that merely ends in `cc840` is
/// not an ISO code. Anything wider than `u32` saturates past the range.
fn iso_code(raw: U256) -> Option<u16> {
    let marked = raw.saturating_to::<u32>();
    if !(ISO_MARKER..=ISO_MARKER_MAX).contains(&marked) {
        return None;
    }
    bcd_decode(u16::try_from(marked - ISO_MARKER).ok()?)
}

/// One decimal digit per nibble: `840 -> 0x0840`. Only the four lowest decimal
/// digits fit, which is exact for every code in `0..=999`.
fn bcd_encode(code: u16) -> u16 {
    let mut rest = code % 10_000;
    let mut packed = 0u16;
    for shift in [0u32, 4, 8, 12] {
        packed |= (rest % 10) << shift;
        rest /= 10;
    }
    packed
}

/// Inverse of [`bcd_encode`] over the three low nibbles, or `None` when one of
/// them is not a decimal digit.
fn bcd_decode(packed: u16) -> Option<u16> {
    let mut code = 0u16;
    for shift in [8u32, 4, 0] {
        let digit = (packed >> shift) & 0xf;
        if digit > 9 {
            return None;
        }
        code = code * 10 + digit;
    }
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::AssetType;
    use alloy_primitives::{address, Address};

    /// Highest ISO 4217 numeric currency code.
    const MAX_ISO_CODE: u16 = 999;

    #[test]
    fn native_round_trips_through_the_zero_address() {
        assert_eq!(Address::from(AssetType::Native), Address::ZERO);
        assert_eq!(AssetType::from(Address::ZERO), AssetType::Native);
    }

    #[test]
    fn iso_currency_encodes_each_decimal_digit_as_a_nibble_behind_the_marker() {
        assert_eq!(
            Address::from(AssetType::IsoCurrency(840)),
            address!("0x00000000000000000000000000000000000cc840"),
        );
        assert_eq!(
            Address::from(AssetType::IsoCurrency(8)),
            address!("0x00000000000000000000000000000000000cc008"),
        );
        assert_eq!(
            Address::from(AssetType::IsoCurrency(MAX_ISO_CODE)),
            address!("0x00000000000000000000000000000000000cc999"),
        );
    }

    #[test]
    fn an_unmarked_currency_code_decodes_as_erc20() {
        let token = address!("0x0000000000000000000000000000000000000840");
        assert_eq!(AssetType::from(token), AssetType::ERC20(token));
    }

    #[test]
    fn iso_currency_round_trips_every_code_in_range() {
        for code in 1..=MAX_ISO_CODE {
            let asset = AssetType::IsoCurrency(code);
            assert_eq!(
                AssetType::from(Address::from(asset)),
                asset,
                "iso code {code}"
            );
        }
    }

    #[test]
    fn erc20_round_trips_through_its_own_address() {
        let token = address!("0x000000000000000000000000000000000000099a");
        assert_eq!(Address::from(AssetType::ERC20(token)), token);
        assert_eq!(AssetType::from(token), AssetType::ERC20(token));
    }

    #[test]
    fn an_address_above_the_iso_range_decodes_as_erc20() {
        let token = address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        assert_eq!(AssetType::from(token), AssetType::ERC20(token));
    }

    #[test]
    fn every_variant_converts_through_into() {
        let token = address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let converted: [Address; 3] = [
            AssetType::Native.into(),
            AssetType::IsoCurrency(840).into(),
            AssetType::ERC20(token).into(),
        ];

        assert_eq!(
            converted,
            [
                Address::ZERO,
                address!("0x00000000000000000000000000000000000cc840"),
                token,
            ],
        );
    }

    #[test]
    fn an_address_outside_the_marked_iso_range_decodes_as_erc20() {
        for token in [
            // Marked, but a nibble is not a decimal digit.
            address!("0x00000000000000000000000000000000000cc8a0"),
            address!("0x00000000000000000000000000000000000cc84f"),
            // Just past either end of the reserved range.
            address!("0x00000000000000000000000000000000000cb999"),
            address!("0x00000000000000000000000000000000000cd000"),
            // Marker present but shifted out of place.
            address!("0x0000000000000000000000000000000000cc8400"),
            // Correctly placed marker, but a non-zero byte above it.
            address!("0x00000000000000000000000000000000100cc840"),
            address!("0xa0b86991c6218b36c1d19d4a2e9eb0ce360cc840"),
        ] {
            assert_eq!(AssetType::from(token), AssetType::ERC20(token), "{token}");
        }
    }
}
