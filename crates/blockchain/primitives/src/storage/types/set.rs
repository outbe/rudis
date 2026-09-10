use alloy_primitives::{keccak256, Address, U256};

use crate::error::Result;
use crate::storage::StorageHandle;

use super::{Storable, StorageKey};

/// EVM-compatible enumerable set (OpenZeppelin pattern).
///
/// Storage layout:
/// - Base slot: values array length
/// - Base slot + 1: positions mapping base (1-indexed, 0 = not in set)
/// - Data: keccak256(base_slot) + index
///
/// O(1) contains/insert/remove, O(N) enumeration.
pub struct StorageSet<'storage, T> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _marker: std::marker::PhantomData<T>,
}

impl<'storage, T: Storable + StorageKey> StorageSet<'storage, T> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn len(&self) -> Result<u32> {
        Ok(self
            .storage
            .sload(self.address, self.base_slot)?
            .to::<u32>())
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|l| l == 0)
    }

    pub fn contains(&self, value: &T) -> Result<bool> {
        Ok(self.read_position(value)? != 0)
    }

    pub fn at(&self, index: u32) -> Result<Option<T>> {
        if index >= self.len()? {
            return Ok(None);
        }
        let word = self.storage.sload(self.address, self.value_slot(index))?;
        Ok(Some(T::from_word(word)))
    }

    pub fn insert(&self, value: T) -> Result<bool> {
        if self.read_position(&value)? != 0 {
            return Ok(false);
        }
        let length = self.len()?;
        self.storage
            .sstore(self.address, self.value_slot(length), value.to_word())?;
        let pos_slot = value.mapping_slot(self.positions_base());
        self.storage
            .sstore(self.address, pos_slot, U256::from(length + 1))?;
        self.storage
            .sstore(self.address, self.base_slot, U256::from(length + 1))
            .map(|_| true)
    }

    pub fn remove(&self, value: &T) -> Result<bool> {
        let pos = self.read_position(value)?;
        if pos == 0 {
            return Ok(false);
        }
        let length = self.len()?;
        let idx = pos - 1;
        let last = length - 1;

        if idx != last {
            let last_word = self.storage.sload(self.address, self.value_slot(last))?;
            let last_val = T::from_word(last_word);
            self.storage
                .sstore(self.address, self.value_slot(idx), last_word)?;
            let pos_slot = last_val.mapping_slot(self.positions_base());
            self.storage
                .sstore(self.address, pos_slot, U256::from(pos))?;
        }

        self.storage
            .sstore(self.address, self.value_slot(last), U256::ZERO)?;
        let pos_slot = value.mapping_slot(self.positions_base());
        self.storage.sstore(self.address, pos_slot, U256::ZERO)?;
        self.storage
            .sstore(self.address, self.base_slot, U256::from(last))
            .map(|_| true)
    }

    pub fn read_all(&self) -> Result<Vec<T>> {
        let length = self.len()?;
        let mut result = Vec::with_capacity(length as usize);
        for i in 0..length {
            let word = self.storage.sload(self.address, self.value_slot(i))?;
            result.push(T::from_word(word));
        }
        Ok(result)
    }

    fn value_slot(&self, index: u32) -> U256 {
        U256::from_be_bytes(keccak256(self.base_slot.to_be_bytes::<32>()).0) + U256::from(index)
    }

    fn positions_base(&self) -> U256 {
        self.base_slot + U256::from(1u64)
    }

    fn read_position(&self, value: &T) -> Result<u32> {
        let pos_slot = value.mapping_slot(self.positions_base());
        Ok(self.storage.sload(self.address, pos_slot)?.to::<u32>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;
    use crate::storage::StorageHandle;
    use alloy_primitives::address;

    fn with_storage<F: FnOnce(StorageHandle)>(f: F) {
        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        f(storage);
    }

    const ADDR: Address = address!("0x0000000000000000000000000000000000001003");

    #[test]
    fn test_empty() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            assert_eq!(s.len().unwrap(), 0);
            assert!(s.is_empty().unwrap());
        });
    }

    #[test]
    fn test_insert_contains() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            assert!(s.insert(10).unwrap());
            assert!(!s.insert(10).unwrap()); // duplicate
            assert!(s.insert(20).unwrap());
            assert_eq!(s.len().unwrap(), 2);
            assert!(s.contains(&10).unwrap());
            assert!(s.contains(&20).unwrap());
            assert!(!s.contains(&30).unwrap());
        });
    }

    #[test]
    fn test_remove_last() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            s.insert(10).unwrap();
            s.insert(20).unwrap();
            assert!(s.remove(&20).unwrap());
            assert_eq!(s.len().unwrap(), 1);
            assert!(!s.contains(&20).unwrap());
            assert!(s.contains(&10).unwrap());
        });
    }

    #[test]
    fn test_remove_middle_swap() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            s.insert(10).unwrap();
            s.insert(20).unwrap();
            s.insert(30).unwrap();
            assert!(s.remove(&20).unwrap());
            // After swap: [10, 30]
            assert_eq!(s.at(0).unwrap(), Some(10));
            assert_eq!(s.at(1).unwrap(), Some(30));
            assert!(!s.contains(&20).unwrap());
        });
    }

    #[test]
    fn test_remove_nonexistent() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            s.insert(10).unwrap();
            assert!(!s.remove(&99).unwrap());
        });
    }

    #[test]
    fn test_reinsert() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            s.insert(10).unwrap();
            s.remove(&10).unwrap();
            assert!(s.insert(10).unwrap());
            assert!(s.contains(&10).unwrap());
        });
    }

    #[test]
    fn test_read_all() {
        with_storage(|storage| {
            let s: StorageSet<u64> = StorageSet::new(U256::ZERO, ADDR, storage);
            s.insert(1).unwrap();
            s.insert(2).unwrap();
            s.insert(3).unwrap();
            assert_eq!(s.read_all().unwrap(), vec![1, 2, 3]);
        });
    }

    #[test]
    fn test_address_set() {
        with_storage(|storage| {
            let s: StorageSet<Address> = StorageSet::new(U256::from(10u64), ADDR, storage);
            let a1 = Address::new([0xAA; 20]);
            let a2 = Address::new([0xBB; 20]);
            s.insert(a1).unwrap();
            s.insert(a2).unwrap();
            assert!(s.contains(&a1).unwrap());
            s.remove(&a1).unwrap();
            assert!(!s.contains(&a1).unwrap());
            assert_eq!(s.len().unwrap(), 1);
        });
    }
}
