use alloy_primitives::{keccak256, wrap_fixed_bytes, Address, U256};
// `wrap_fixed_bytes!` expands to `derive_more` derives that emit unqualified
// paths, so the crate has to be nameable here.
use crate::asset_type::AssetType;
use crate::storage::types::StorageKey;
use alloy_primitives::private::derive_more;

wrap_fixed_bytes!(
    /// Two Ethereum addresses concatenated, 40 bytes in length.
    ///
    /// Declared with the [`wrap_fixed_bytes!`] macro like [`Address`] itself,
    /// so it inherits hex parsing, formatting, and `FixedBytes` conversions.
    pub struct AddressPair<40>;
);

impl AddressPair {
    pub fn from_addresses(asset1: Address, asset2: Address) -> Self {
        let mut bytes = [0u8; 40];
        bytes[0..20].copy_from_slice(asset1.as_slice());
        bytes[20..40].copy_from_slice(asset2.as_slice());
        Self::from(bytes)
    }

    /// Creates a new `AddressPair` from asset types.
    pub fn from_assets(asset1: AssetType, asset2: AssetType) -> Self {
        Self::from_addresses(asset1.into(), asset2.into())
    }

    /// The `COEN/<iso>` pair, e.g. `new_coen_to(840)` for COEN/USD.
    ///
    /// COEN base, ISO quote - the orientation these pairs are registered in.
    /// COEN is also the zero address, so this is the canonical key form too.
    pub fn new_coen_to(iso_code: u16) -> Self {
        AddressPair::from_assets(AssetType::Native, AssetType::IsoCurrency(iso_code))
    }

    pub fn address1(&self) -> Address {
        Address::from_slice(&self[0..20])
    }

    pub fn address2(&self) -> Address {
        Address::from_slice(&self[20..40])
    }
    pub fn asset1(&self) -> AssetType {
        AssetType::from(self.address1())
    }

    pub fn asset2(&self) -> AssetType {
        AssetType::from(self.address2())
    }

    /// The 40 bytes this pair keys on: both addresses ascending, so the two
    /// directions of one market collapse onto a single slot. Idempotent.
    pub fn to_canonical(&self) -> Self {
        let (base, quote) = (self.address1(), self.address2());
        if base <= quote {
            *self
        } else {
            Self::from_addresses(quote, base)
        }
    }

    pub fn is_canonical(&self) -> bool {
        self.address1() <= self.address2()
    }

    /// Whether both quotes name the same market.
    pub fn same_market(&self, other: &Self) -> bool {
        self.to_canonical() == other.to_canonical()
    }
}

/// Usable as a `Mapping` key, and as a value only through the two-word
/// `Mapping<K, AddressPair>` accessors: [`Storable`] round-trips through a
/// single 32-byte word and 40 bytes do not fit one.
///
/// [`Storable`]: crate::storage::types::Storable
impl StorageKey for AddressPair {
    /// Sorted, so `quoted(a, b)` and `quoted(b, a)` address the same slot.
    fn key_bytes(&self) -> Vec<u8> {
        self.to_canonical().to_vec()
    }

    /// Solidity left-pads a mapping key only when it is narrower than a word;
    /// a wider key is concatenated with the base slot as-is. The provided
    /// implementation computes `32 - key.len()`, which a 40-byte key underflows,
    /// so the concatenation is spelled out here against a fixed-size buffer.
    fn mapping_slot(&self, base_slot: U256) -> U256 {
        let mut buf = [0u8; 72];
        buf[..40].copy_from_slice(self.to_canonical().as_slice());
        buf[40..].copy_from_slice(&base_slot.to_be_bytes::<32>());
        U256::from_be_bytes(keccak256(buf).0)
    }
}

#[cfg(test)]
mod tests {
    use super::AddressPair;
    use crate::asset_type::AssetType;
    use crate::storage::types::StorageKey;
    use alloy_primitives::{address, b256, keccak256, Address, U256};

    const FIRST: Address = address!("0x1111111111111111111111111111111111111111");
    const SECOND: Address = address!("0x2222222222222222222222222222222222222222");
    const THIRD: Address = address!("0x3333333333333333333333333333333333333333");

    #[test]
    fn quoted_packs_base_first_and_quote_second() {
        let pair = AddressPair::from_addresses(SECOND, FIRST);

        assert_eq!(AddressPair::len_bytes(), 40);
        assert_eq!(&pair[0..20], SECOND.as_slice());
        assert_eq!(&pair[20..40], FIRST.as_slice());
    }

    #[test]
    fn the_accessors_return_the_quoted_orientation() {
        let pair = AddressPair::from_addresses(SECOND, FIRST);

        assert_eq!(pair.address1(), SECOND);
        assert_eq!(pair.address2(), FIRST);
    }

    #[test]
    fn the_accessors_round_trip_back_into_the_same_pair() {
        let pair = AddressPair::from_addresses(SECOND, FIRST);

        assert_eq!(
            AddressPair::from_addresses(pair.address1(), pair.address2()),
            pair
        );
    }

    #[test]
    fn quoted_keeps_the_two_directions_of_one_market_distinct() {
        assert_ne!(
            AddressPair::from_addresses(FIRST, SECOND),
            AddressPair::from_addresses(SECOND, FIRST),
        );
    }

    #[test]
    fn sorted_collapses_the_two_directions_of_one_market() {
        let forward = AddressPair::from_addresses(FIRST, SECOND);
        let reverse = AddressPair::from_addresses(SECOND, FIRST);

        assert_eq!(forward.to_canonical(), reverse.to_canonical());
        assert!(forward.same_market(&reverse));
        // Idempotent: sorting an already-sorted pair is a no-op.
        assert_eq!(
            forward.to_canonical().to_canonical(),
            forward.to_canonical()
        );
        assert_eq!(forward.to_canonical(), forward);
    }

    #[test]
    fn same_market_separates_markets_sharing_an_asset() {
        assert!(!AddressPair::from_addresses(FIRST, SECOND)
            .same_market(&AddressPair::from_addresses(FIRST, THIRD)));
    }

    #[test]
    fn quoted_separates_pairs_sharing_an_address() {
        assert_ne!(
            AddressPair::from_addresses(FIRST, SECOND),
            AddressPair::from_addresses(FIRST, THIRD),
        );
    }

    #[test]
    fn quoted_packs_an_address_paired_with_itself() {
        let pair = AddressPair::from_addresses(FIRST, FIRST);

        assert_eq!(&pair[0..20], FIRST.as_slice());
        assert_eq!(&pair[20..40], FIRST.as_slice());
    }

    #[test]
    fn a_pair_round_trips_through_hex() {
        let pair = AddressPair::from_addresses(FIRST, SECOND);

        assert_eq!(pair.to_string().parse::<AddressPair>(), Ok(pair));
    }

    #[test]
    fn the_zero_pair_holds_forty_zero_bytes() {
        assert_eq!(
            AddressPair::from_addresses(Address::ZERO, Address::ZERO),
            AddressPair::ZERO,
        );
    }

    #[test]
    fn the_mapping_slot_concatenates_the_forty_byte_key_with_the_base_slot() {
        let pair = AddressPair::from_addresses(FIRST, SECOND);
        let base_slot = U256::from(10u64);

        let mut expected = Vec::with_capacity(72);
        expected.extend_from_slice(pair.as_slice());
        expected.extend_from_slice(&base_slot.to_be_bytes::<32>());

        assert_eq!(
            pair.mapping_slot(base_slot),
            U256::from_be_bytes(keccak256(&expected).0),
        );
    }

    /// The one property that lets a single `Mapping<AddressPair, _>` serve both
    /// quote directions: the key derivation sorts even though the value does not.
    #[test]
    fn the_mapping_slot_ignores_the_quote_direction() {
        let base_slot = U256::from(10u64);

        assert_eq!(
            AddressPair::from_addresses(FIRST, SECOND).mapping_slot(base_slot),
            AddressPair::from_addresses(SECOND, FIRST).mapping_slot(base_slot),
        );
    }

    #[test]
    fn the_mapping_slot_separates_distinct_pairs_and_distinct_base_slots() {
        let pair = AddressPair::from_addresses(FIRST, SECOND);
        let other = AddressPair::from_addresses(FIRST, THIRD);

        assert_ne!(
            pair.mapping_slot(U256::from(10u64)),
            other.mapping_slot(U256::from(10u64))
        );
        assert_ne!(
            pair.mapping_slot(U256::from(10u64)),
            pair.mapping_slot(U256::from(11u64))
        );
    }

    #[test]
    fn the_mapping_slot_handles_the_zero_pair_and_the_zero_base_slot() {
        // The 40-byte key underflows the default 32-byte left-pad, so the
        // override is the only thing keeping this from panicking.
        let _ = AddressPair::ZERO.mapping_slot(U256::ZERO);
    }

    /// Pins the exact slot `scripts/seed_genesis.py` has to reproduce for the
    /// canonical COEN/840 pair at the pair-registry base slot. Its `mapping_key`
    /// helper already agrees: `rjust(32)` never truncates, so a 40-byte key
    /// falls through unpadded. A change here is genesis-breaking, not a refactor.
    #[test]
    fn the_coen_iso_840_pair_derives_a_stable_registry_slot() {
        let coen_usd = AddressPair::from_addresses(
            Address::ZERO,
            address!("0x00000000000000000000000000000000000cc840"),
        );

        assert_eq!(
            coen_usd.mapping_slot(U256::from(10u64)),
            U256::from_be_bytes(
                b256!("0xfa9240513fa8af0cd3aa94db0c237a129a63076f21ab227c30018c124938bc88").0
            ),
        );
    }

    #[test]
    fn new_coen_to_keys_on_the_zero_address_and_the_currency_code() {
        let pair = AddressPair::new_coen_to(840);

        assert_eq!(&pair[0..20], Address::ZERO.as_slice());
        assert_eq!(
            &pair[20..40],
            address!("0x00000000000000000000000000000000000cc840").as_slice(),
        );
    }

    /// The quoted value keeps the order; only the storage key drops it.
    #[test]
    fn quoted_assets_keeps_the_order_the_assets_are_quoted_in() {
        let forward = AddressPair::from_assets(AssetType::Native, AssetType::IsoCurrency(840));
        let reverse = AddressPair::from_assets(AssetType::IsoCurrency(840), AssetType::Native);

        assert_ne!(forward, reverse);
        assert!(forward.same_market(&reverse));
    }

    #[test]
    fn new_coen_to_separates_pairs_sharing_an_asset() {
        assert_ne!(AddressPair::new_coen_to(840), AddressPair::new_coen_to(978));
    }
}
