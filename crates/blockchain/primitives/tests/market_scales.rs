use alloy_primitives::Address;
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::asset_type::{currency_address, AssetType};
use outbe_primitives::math::reference_price::pair_scales;

const COEN: Address = Address::ZERO;

fn erc20(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

#[test]
fn coen_against_an_iso_currency_is_quoted_in_six_decimals() {
    let pair = AddressPair::from_addresses(COEN, currency_address(840));
    assert_eq!(pair_scales(pair), (6, 6));
}

#[test]
fn the_iso_side_may_come_first() {
    let pair = AddressPair::from_addresses(currency_address(978), COEN);
    assert_eq!(pair_scales(pair), (6, 6));
}

#[test]
fn every_other_market_keeps_eighteen_decimals() {
    let token_pair = AddressPair::from_addresses(erc20(1), erc20(2));
    let coen_token = AddressPair::from_addresses(COEN, erc20(3));
    assert_eq!(pair_scales(token_pair), (18, 18));
    assert_eq!(pair_scales(coen_token), (18, 18));
}

#[test]
fn an_iso_address_decodes_back_to_its_code() {
    assert_eq!(
        AssetType::from(currency_address(949)),
        AssetType::IsoCurrency(949)
    );
}
