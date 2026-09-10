use alloy_primitives::{wrap_fixed_bytes, B256, U256};
// `wrap_fixed_bytes!` expands to `derive_more` derives that emit unqualified
// paths, so the crate has to be nameable here.
use crate::storage::types::{Storable, StorableType, StorageKey};
use crate::time::WorldwideDay;
use alloy_primitives::private::derive_more;

/// Byte width of the WorldwideDay prefix.
const WWD_PREFIX_LEN: usize = 4;

wrap_fixed_bytes!(
    /// An entity identity: a big-endian WorldwideDay over a digest tail, 32 bytes.
    ///
    /// Declared with the [`wrap_fixed_bytes!`] macro, so it
    /// inherits hex parsing, formatting, serde, and `FixedBytes` conversions.
    ///
    /// The day occupies the top four bytes, which is what makes the `uint256`
    /// the ABI carries meaningful day, and ordering by the word orders by day and then by body.
    pub struct WwdEntityId<32>;
);

impl WwdEntityId {
    /// Builds an identity from a day and a digest, keeping the digest's last
    /// 28 bytes. The four discarded bytes are the price of the day prefix; a
    /// caller that needs the whole digest must keep it separately.
    pub fn from_day_and_digest(worldwide_day: WorldwideDay, digest: impl Into<B256>) -> Self {
        let digest = digest.into();
        let mut bytes = [0u8; 32];
        bytes[..WWD_PREFIX_LEN].copy_from_slice(&worldwide_day.value().to_be_bytes());
        bytes[WWD_PREFIX_LEN..].copy_from_slice(&digest[WWD_PREFIX_LEN..]);
        Self::from(bytes)
    }

    /// The immutable partition/day prefix.
    pub fn worldwide_day(&self) -> WorldwideDay {
        // Indexed rather than sliced so the fixed width needs no fallible
        // conversion on a consensus path.
        WorldwideDay::new(u32::from_be_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3],
        ]))
    }

    /// The digest tail. Named `body` rather than `digest` because it is not the
    /// whole digest and must not be treated as one.
    pub fn body(&self) -> [u8; 32 - WWD_PREFIX_LEN] {
        let mut out = [0u8; 32 - WWD_PREFIX_LEN];
        out.copy_from_slice(&self.0[WWD_PREFIX_LEN..]);
        out
    }
}

impl WwdEntityId {
    /// The `uint256` every precompile ABI carries this identity as. Big-endian,
    /// so the day stays in the high bytes and survives the round trip.
    ///
    /// Spelled as an inherent method because `U256::from` is an inherent method
    /// on `Uint` bounded by `UintTryFrom`; it shadows the `From` impl below, so
    /// `U256::from(id)` does not compile. `id.into()` does.
    pub fn to_u256(self) -> U256 {
        U256::from_be_bytes(self.0 .0)
    }
}

impl From<WwdEntityId> for U256 {
    fn from(value: WwdEntityId) -> Self {
        value.to_u256()
    }
}

impl From<U256> for WwdEntityId {
    fn from(value: U256) -> Self {
        Self::from(value.to_be_bytes::<32>())
    }
}

impl StorableType for WwdEntityId {
    const SLOTS: usize = 1;
}

impl Storable for WwdEntityId {
    fn from_word(word: U256) -> Self {
        Self::from(word)
    }

    fn to_word(&self) -> U256 {
        self.to_u256()
    }
}

/// A 32-byte key needs no `mapping_slot` override: the provided implementation
/// left-pads by `32 - key.len()`, which is exactly zero here.
impl StorageKey for WwdEntityId {
    fn key_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::WwdEntityId;
    use crate::storage::types::{Storable, StorableType, StorageKey};
    use crate::time::WorldwideDay;
    use alloy_primitives::{keccak256, B256, U256};

    const DAY: u32 = 20_260_824;

    fn digest() -> B256 {
        B256::from([0xa5; 32])
    }

    #[test]
    fn the_id_packs_the_day_over_the_digest_tail_and_round_trips_through_a_word() {
        let day = WorldwideDay::new(DAY);
        let id = WwdEntityId::from_day_and_digest(day, digest());

        assert_eq!(WwdEntityId::len_bytes(), 32);
        assert_eq!(&id[..4], &DAY.to_be_bytes());
        assert_eq!(&id[4..], &digest()[4..]);
        assert_eq!(id.worldwide_day(), day);
        assert_eq!(id.body(), digest()[4..]);

        // The uint256 view Solidity sees: the day is recoverable from the high
        // bytes, which is the whole reason the prefix leads.
        let word = id.to_u256();
        assert_eq!((word >> 224usize).to::<u32>(), DAY);
        assert_eq!(WwdEntityId::from(word), id);

        // Single-slot storage round trip.
        assert_eq!(<WwdEntityId as StorableType>::SLOTS, 1);
        assert_eq!(WwdEntityId::from_word(id.to_word()), id);
    }

    #[test]
    fn the_day_prefix_orders_ids_by_day_before_body() {
        let early =
            WwdEntityId::from_day_and_digest(WorldwideDay::new(20_260_823), B256::from([0xff; 32]));
        let late = WwdEntityId::from_day_and_digest(WorldwideDay::new(DAY), B256::from([0x00; 32]));

        assert!(early < late, "a later day must sort after an earlier one");
        assert!(early.to_u256() < late.to_u256(), "and so must the word");
    }

    #[test]
    fn distinct_days_and_distinct_digests_stay_distinct() {
        let day = WorldwideDay::new(DAY);
        let other_day = WorldwideDay::new(20_260_825);
        let other_digest = B256::from([0x5a; 32]);

        assert_ne!(
            WwdEntityId::from_day_and_digest(day, digest()),
            WwdEntityId::from_day_and_digest(other_day, digest())
        );
        assert_ne!(
            WwdEntityId::from_day_and_digest(day, digest()),
            WwdEntityId::from_day_and_digest(day, other_digest)
        );
    }

    /// The four bytes `new` drops are the digest's leading ones, so two digests
    /// differing only there collide. Pinned so the truncation stays deliberate.
    #[test]
    fn the_id_ignores_the_leading_four_digest_bytes() {
        let day = WorldwideDay::new(DAY);
        let mut shifted = [0xa5; 32];
        shifted[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(
            WwdEntityId::from_day_and_digest(day, digest()),
            WwdEntityId::from_day_and_digest(day, B256::from(shifted)),
        );
    }

    #[test]
    fn an_id_round_trips_through_hex() {
        let id = WwdEntityId::from_day_and_digest(WorldwideDay::new(DAY), digest());

        assert_eq!(id.to_string().parse::<WwdEntityId>(), Ok(id));
    }

    #[test]
    fn the_mapping_slot_needs_no_override_for_a_full_width_key() {
        let id = WwdEntityId::from_day_and_digest(WorldwideDay::new(DAY), digest());
        let base_slot = U256::from(10u64);

        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(id.as_slice());
        expected[32..].copy_from_slice(&base_slot.to_be_bytes::<32>());

        assert_eq!(
            id.mapping_slot(base_slot),
            U256::from_be_bytes(keccak256(expected).0),
        );
    }

    /// A 36-byte key underflowed the provided `32 - key.len()` left-pad. At 32
    /// the subtraction is zero, so the zero id and zero base slot are safe.
    #[test]
    fn the_mapping_slot_handles_the_zero_id_and_the_zero_base_slot() {
        let _ = WwdEntityId::ZERO.mapping_slot(U256::ZERO);
    }
}
