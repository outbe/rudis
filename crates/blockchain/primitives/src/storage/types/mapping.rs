use alloy_primitives::{Address, U256};

use crate::address_pair::AddressPair;
use crate::error::Result;
use crate::storage::types::{Slot, Storable, StorageBytes, StorageKey, StorageSet};
use crate::storage::StorageHandle;

/// A Solidity-compatible mapping: `mapping(K => V)`.
///
/// Slot computation: `keccak256(left_pad(key, 32) ++ base_slot)`
///
/// Supports nested mappings: `Mapping<K1, Mapping<K2, V>>`.
pub struct Mapping<'storage, K, V> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _key: std::marker::PhantomData<K>,
    _value: std::marker::PhantomData<V>,
}

impl<'storage, K, V> Mapping<'storage, K, V> {
    /// Creates a new mapping at the given base slot for the given contract address.
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _key: std::marker::PhantomData,
            _value: std::marker::PhantomData,
        }
    }

    /// Returns the base slot.
    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }
}

// Mapping<K, V> where V is a simple Storable type -> returns Slot<V>
impl<'storage, K: StorageKey, V: Storable> Mapping<'storage, K, V> {
    /// Returns a `Slot<V>` for the given key.
    pub fn get(&self, key: &K) -> Slot<'storage, V> {
        let slot = key.mapping_slot(self.base_slot);
        Slot::new(slot, self.address, self.storage.clone())
    }

    /// Reads the value for the given key.
    pub fn read(&self, key: &K) -> Result<V> {
        self.get(key).read()
    }

    /// Writes a value for the given key.
    pub fn write(&self, key: &K, value: V) -> Result<()> {
        self.get(key).write(value)
    }
}

// Mapping<K, Mapping<K2, V>> -> nested mapping support
impl<'storage, K: StorageKey, K2, V> Mapping<'storage, K, Mapping<'storage, K2, V>> {
    /// Returns the inner `Mapping<K2, V>` for the given outer key.
    pub fn get_nested(&self, key: &K) -> Mapping<'storage, K2, V> {
        let inner_base = key.mapping_slot(self.base_slot);
        Mapping::new(inner_base, self.address, self.storage.clone())
    }
}

// Mapping<K, StorageBytes> -> dynamic bytes/string support
impl<'storage, K: StorageKey> Mapping<'storage, K, StorageBytes<'storage>> {
    /// Returns a `StorageBytes` value for the given key.
    pub fn get_bytes(&self, key: &K) -> StorageBytes<'storage> {
        let slot = key.mapping_slot(self.base_slot);
        StorageBytes::new(slot, self.address, self.storage.clone())
    }

    /// Reads a UTF-8 string value for the given key.
    pub fn read_string(&self, key: &K) -> Result<String> {
        self.get_bytes(key).read_string()
    }

    /// Writes a UTF-8 string value for the given key.
    pub fn write_string(&self, key: &K, value: &str) -> Result<()> {
        self.get_bytes(key).write_string(value)
    }
}

// Mapping<K, AddressPair> -> a two-word value, laid out exactly like a Solidity
// `mapping(K => struct { address base; address quote; })`: base at the key's
// mapping slot, quote at the next one. `AddressPair` is 40 bytes so it cannot be
// `Storable`, which is what keeps it off the single-word `read`/`write` above.
impl<'storage, K: StorageKey> Mapping<'storage, K, AddressPair> {
    /// Reads the pair for the given key, in the orientation it was written.
    pub fn read_pair(&self, key: &K) -> Result<AddressPair> {
        let slot = key.mapping_slot(self.base_slot);
        let base = self.word(slot)?;
        let quote = self.word(slot + U256::ONE)?;
        Ok(AddressPair::from_addresses(
            Address::from_word(base.into()),
            Address::from_word(quote.into()),
        ))
    }

    /// Writes both words. Callers holding a checkpoint must keep this inside it:
    /// half a pair decodes as a different pair, not as a missing one.
    pub fn write_pair(&self, key: &K, pair: AddressPair) -> Result<()> {
        let slot = key.mapping_slot(self.base_slot);
        self.set_word(slot, pair.address1().to_word())?;
        self.set_word(slot + U256::ONE, pair.address2().to_word())
    }

    fn word(&self, slot: U256) -> Result<U256> {
        Slot::<U256>::new(slot, self.address, self.storage.clone()).read()
    }

    fn set_word(&self, slot: U256, value: U256) -> Result<()> {
        Slot::<U256>::new(slot, self.address, self.storage.clone()).write(value)
    }
}

// Mapping<K, StorageSet<T>> -> an enumerable set per key (OZ `mapping(key =>
// EnumerableSet)` pattern). The inner set is rooted at the key's mapping slot.
impl<'storage, K: StorageKey, T: Storable + StorageKey>
    Mapping<'storage, K, StorageSet<'storage, T>>
{
    /// Returns the `StorageSet` bucket for the given key.
    pub fn get_set(&self, key: &K) -> StorageSet<'storage, T> {
        let slot = key.mapping_slot(self.base_slot);
        StorageSet::new(slot, self.address, self.storage.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use crate::storage::StorageHandle;
    use alloy_primitives::{address, keccak256};

    #[test]
    fn test_mapping_slot_computation() {
        // Verify our slot computation matches Solidity's keccak256(abi.encode(key, slot))
        let addr = address!("0x1111111111111111111111111111111111111111");
        let base_slot = U256::from(2);

        let slot = addr.mapping_slot(base_slot);

        // Manual: keccak256([12 zero bytes][20 addr bytes][32 base_slot bytes])
        let mut buf = [0u8; 64];
        buf[12..32].copy_from_slice(addr.as_slice());
        buf[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
        let expected = U256::from_be_bytes(keccak256(buf).0);

        assert_eq!(slot, expected);
    }

    #[test]
    fn test_mapping_read_write() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let user = address!("0x2222222222222222222222222222222222222222");

        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let mapping: Mapping<Address, U256> = Mapping::new(U256::from(1), contract, storage);

        // Initially zero
        let val = mapping.read(&user).unwrap();
        assert_eq!(val, U256::ZERO);

        // Write and read back
        mapping.write(&user, U256::from(100)).unwrap();
        let val = mapping.read(&user).unwrap();
        assert_eq!(val, U256::from(100));
    }

    #[test]
    fn test_nested_mapping() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let user = address!("0x3333333333333333333333333333333333333333");
        let key = U256::from(42);

        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let mapping: Mapping<Address, Mapping<U256, bool>> =
            Mapping::new(U256::from(5), contract, storage);
        let inner = mapping.get_nested(&user);

        let val = inner.read(&key).unwrap();
        assert!(!val);

        inner.write(&key, true).unwrap();
        let val = inner.read(&key).unwrap();
        assert!(val);
    }

    #[test]
    fn test_mapping_address_pair_round_trip() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let base = address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let quote = address!("0x00000000000000000000000000000000000cc840");

        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let mapping: Mapping<u32, AddressPair> = Mapping::new(U256::from(43), contract, storage);

        // Unwritten reads back as the zero pair, not as an error - the zero
        // address is a legitimate asset, so absence is decided elsewhere.
        assert_eq!(mapping.read_pair(&1).unwrap(), AddressPair::ZERO);

        let pair = AddressPair::from_addresses(base, quote);
        mapping.write_pair(&1, pair).unwrap();

        // The quoted orientation survives the round trip; it is not sorted.
        assert_eq!(mapping.read_pair(&1).unwrap(), pair);
        assert_eq!(mapping.read_pair(&1).unwrap().address1(), base);
        assert_eq!(mapping.read_pair(&1).unwrap().address2(), quote);
        assert_eq!(mapping.read_pair(&2).unwrap(), AddressPair::ZERO);
    }

    /// Pins the two-word layout `scripts/seed_genesis.py` and the OCOMP opening
    /// plan both reproduce by hand: base at the key's mapping slot, quote at +1.
    #[test]
    fn test_mapping_address_pair_occupies_two_consecutive_slots() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let base = address!("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let quote = address!("0x00000000000000000000000000000000000cc840");
        let base_slot = U256::from(43);

        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let mapping: Mapping<u32, AddressPair> = Mapping::new(base_slot, contract, storage.clone());
        mapping
            .write_pair(&7, AddressPair::from_addresses(base, quote))
            .unwrap();

        let mut buf = [0u8; 64];
        buf[28..32].copy_from_slice(&7u32.to_be_bytes());
        buf[32..64].copy_from_slice(&base_slot.to_be_bytes::<32>());
        let slot = U256::from_be_bytes(keccak256(buf).0);

        assert_eq!(
            storage.sload(contract, slot).unwrap(),
            U256::from_be_bytes(base.into_word().0),
        );
        assert_eq!(
            storage.sload(contract, slot + U256::from(1)).unwrap(),
            U256::from_be_bytes(quote.into_word().0),
        );
    }

    #[test]
    fn test_mapping_storage_bytes_read_write() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let mapping: Mapping<u32, StorageBytes> = Mapping::new(U256::from(7), contract, storage);

        mapping.write_string(&1, "COEN").unwrap();
        mapping.write_string(&2, "0xUSD").unwrap();

        assert_eq!(mapping.read_string(&1).unwrap(), "COEN");
        assert_eq!(mapping.read_string(&2).unwrap(), "0xUSD");
        assert_eq!(mapping.read_string(&3).unwrap(), "");
    }
}
