use alloy_primitives::{Address, U256};

use crate::error::Result;
use crate::storage::StorageHandle;

use super::Storable;

/// Fixed-size array stored in consecutive EVM storage slots.
///
/// Storage layout: elements at `base_slot + index * T::SLOTS`.
/// No length stored - size is known at compile time.
pub struct StorageArray<'storage, T, const N: usize> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _marker: std::marker::PhantomData<T>,
}

impl<'storage, T: Storable, const N: usize> StorageArray<'storage, T, N> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _marker: std::marker::PhantomData,
        }
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    pub fn get(&self, index: usize) -> Result<Option<T>> {
        if index >= N {
            return Ok(None);
        }
        let word = self.storage.sload(self.address, self.element_slot(index))?;
        Ok(Some(T::from_word(word)))
    }

    pub fn set(&self, index: usize, value: T) -> Result<()> {
        if index >= N {
            return Err(crate::error::PrecompileError::Fatal(
                "array index out of bounds".into(),
            ));
        }
        self.storage
            .sstore(self.address, self.element_slot(index), value.to_word())
    }

    pub fn read_all(&self) -> Result<Vec<T>> {
        let mut result = Vec::with_capacity(N);
        for i in 0..N {
            let word = self.storage.sload(self.address, self.element_slot(i))?;
            result.push(T::from_word(word));
        }
        Ok(result)
    }

    pub fn write_all(&self, values: &[T]) -> Result<()>
    where
        T: Copy,
    {
        assert_eq!(values.len(), N);
        for (i, v) in values.iter().enumerate() {
            self.storage
                .sstore(self.address, self.element_slot(i), v.to_word())?;
        }
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        for i in 0..N {
            self.storage
                .sstore(self.address, self.element_slot(i), U256::ZERO)?;
        }
        Ok(())
    }

    fn element_slot(&self, index: usize) -> U256 {
        self.base_slot + U256::from(index * T::SLOTS)
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
    fn test_get_set() {
        with_storage(|storage| {
            let a: StorageArray<u64, 3> = StorageArray::new(U256::ZERO, ADDR, storage);
            a.set(0, 100).unwrap();
            a.set(1, 200).unwrap();
            a.set(2, 300).unwrap();
            assert_eq!(a.get(0).unwrap(), Some(100));
            assert_eq!(a.get(1).unwrap(), Some(200));
            assert_eq!(a.get(2).unwrap(), Some(300));
            assert_eq!(a.get(3).unwrap(), None);
            assert!(a.set(3, 0).is_err());
        });
    }

    #[test]
    fn test_read_write_all() {
        with_storage(|storage| {
            let a: StorageArray<u64, 3> = StorageArray::new(U256::ZERO, ADDR, storage);
            a.write_all(&[11, 22, 33]).unwrap();
            assert_eq!(a.read_all().unwrap(), vec![11, 22, 33]);
        });
    }

    #[test]
    fn test_clear() {
        with_storage(|storage| {
            let a: StorageArray<u64, 3> = StorageArray::new(U256::ZERO, ADDR, storage);
            a.write_all(&[1, 2, 3]).unwrap();
            a.clear().unwrap();
            assert_eq!(a.read_all().unwrap(), vec![0, 0, 0]);
        });
    }
}
