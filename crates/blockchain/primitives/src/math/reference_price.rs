//! Outbe-owned COEN/ISO price adapter for the existing Liquidity Book bins.
//!
//! Stablecoin-backed COEN/ISO prices are six-decimal integers. The underlying PancakeSwap port
//! remains unchanged and continues to consume and return 128.128 prices.

use alloy_primitives::U256;

use crate::address_pair::AddressPair;
use crate::asset_type::AssetType;
use crate::error::Result;
use crate::math::price_helper;
use crate::math::uint256x256_math::{mul_shift_round_down, shift_div_round_down};
use crate::units::SCALE_1E6_U256;

const PRICE_BINARY_OFFSET: u8 = 128;

/// Whether a market is native COEN against an ISO reference currency.
pub fn is_coen_iso_market(pair: AddressPair) -> bool {
    matches!(
        (pair.asset1(), pair.asset2()),
        (AssetType::Native, AssetType::IsoCurrency(_))
            | (AssetType::IsoCurrency(_), AssetType::Native)
    )
}

/// Decimals each side of a market is quoted in; both sides match today.
pub fn pair_scales(pair: AddressPair) -> (u8, u8) {
    if is_coen_iso_market(pair) {
        (6, 6)
    } else {
        (18, 18)
    }
}

/// Converts a six-decimal COEN/ISO price to the existing 128.128 price domain.
pub fn coen_iso_price_to_128x128(price: U256) -> Result<U256> {
    shift_div_round_down(price, PRICE_BINARY_OFFSET, SCALE_1E6_U256)
}

/// Converts an existing 128.128 price to a six-decimal COEN/ISO price.
pub fn price_128x128_to_coen_iso(price: U256) -> Result<U256> {
    mul_shift_round_down(price, SCALE_1E6_U256, PRICE_BINARY_OFFSET)
}

/// Maps a six-decimal COEN/ISO price to a Liquidity Book bin id.
pub fn coen_iso_price_to_bin_id(price: U256, bin_step: u16) -> Result<u32> {
    price_helper::get_id_from_price(coen_iso_price_to_128x128(price)?, bin_step)
}

/// Maps a Liquidity Book bin id back to a six-decimal COEN/ISO price.
pub fn bin_id_to_coen_iso_price(bin_id: u32, bin_step: u16) -> Result<U256> {
    let price = price_helper::get_price_from_id(bin_id, bin_step)?;
    price_128x128_to_coen_iso(price)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, U256};

    use super::{coen_iso_price_to_bin_id, is_coen_iso_market};
    use crate::address_pair::AddressPair;
    use crate::asset_type::AssetType;
    use crate::math::constants::REAL_ID_SHIFT;

    const TOKEN: alloy_primitives::Address = address!("0x1111111111111111111111111111111111111111");

    #[test]
    fn classifier_selects_every_coen_iso_orientation_and_no_generic_market() {
        for iso in [840, 978] {
            let forward = AddressPair::from_assets(AssetType::Native, AssetType::IsoCurrency(iso));
            let reverse = AddressPair::from_assets(AssetType::IsoCurrency(iso), AssetType::Native);
            assert!(is_coen_iso_market(forward));
            assert!(is_coen_iso_market(reverse));
        }

        assert!(!is_coen_iso_market(AddressPair::from_assets(
            AssetType::Native,
            AssetType::ERC20(TOKEN),
        )));
        assert!(!is_coen_iso_market(AddressPair::from_assets(
            AssetType::ERC20(TOKEN),
            AssetType::IsoCurrency(840),
        )));
    }

    #[test]
    fn one_coen_in_any_iso_stable_unit_maps_to_the_center_bin() {
        assert_eq!(
            coen_iso_price_to_bin_id(U256::from(1_000_000u64), 1).unwrap(),
            REAL_ID_SHIFT as u32
        );
    }
}
