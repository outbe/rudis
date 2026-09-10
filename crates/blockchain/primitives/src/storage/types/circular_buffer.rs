use alloy_primitives::{keccak256, Address, U256};

use crate::error::PrecompileError;
use crate::error::Result;
use crate::storage::StorageHandle;

use super::Storable;

/// EVM-compatible fixed-capacity ring buffer (port of OpenZeppelin `CircularBuffer`).
///
/// Retains the last `capacity` pushed elements; pushing into a full buffer
/// overwrites (and returns) the oldest one. `push` is O(1).
///
/// Storage layout:
/// - Base slot:      `total` - monotonic count of all pushes ever (`U256`)
/// - Base slot + 1:  `capacity` (`u32`)
/// - Data:           `keccak256(base_slot) + index * T::SLOTS`, `index` in `0..capacity`
///
/// [`setup`](Self::setup) must be called once before [`push`](Self::push).
pub struct StorageCircularBuffer<'storage, T> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _marker: std::marker::PhantomData<T>,
}

impl<'storage, T: Storable> StorageCircularBuffer<'storage, T> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _marker: std::marker::PhantomData,
        }
    }

    /// The schema slot this buffer is anchored at (`total`; `capacity` is `base_slot + 1`).
    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    /// Sets the capacity and resets the buffer to empty.
    pub fn setup(&self, capacity: u32) -> Result<()> {
        self.storage
            .sstore(self.address, self.base_slot, U256::ZERO)?;
        self.storage
            .sstore(self.address, self.capacity_slot(), U256::from(capacity))
    }

    pub fn capacity(&self) -> Result<u32> {
        Ok(self
            .storage
            .sload(self.address, self.capacity_slot())?
            .to::<u32>())
    }

    /// Number of elements currently stored (`min(total, capacity)`).
    pub fn count(&self) -> Result<u32> {
        let cap = self.capacity()?;
        let total = self.read_total()?;
        Ok(if total >= U256::from(cap) {
            cap
        } else {
            total.to::<u32>()
        })
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.count().map(|c| c == 0)
    }

    /// Pushes `value`; returns the evicted oldest element if the buffer was full.
    pub fn push(&self, value: T) -> Result<Option<T>> {
        let cap = self.capacity()?;
        if cap == 0 {
            return Err(PrecompileError::Revert(
                "circular buffer not initialized".into(),
            ));
        }
        let total = self.read_total()?;
        // total % cap < cap (<= u32::MAX), so the conversion is lossless.
        let idx = (total % U256::from(cap)).to::<u32>();
        let evicted = if total >= U256::from(cap) {
            Some(T::from_word(
                self.storage.sload(self.address, self.data_slot(idx))?,
            ))
        } else {
            None
        };
        self.storage
            .sstore(self.address, self.data_slot(idx), value.to_word())?;
        self.storage
            .sstore(self.address, self.base_slot, total + U256::from(1u64))?;
        Ok(evicted)
    }

    pub fn at(&self, index: u32) -> Result<Option<T>> {
        if index >= self.count()? {
            return Ok(None);
        }
        Ok(Some(T::from_word(
            self.storage.sload(self.address, self.data_slot(index))?,
        )))
    }

    /// All stored elements (physical slot order; membership-grade, not chronological).
    pub fn read_all(&self) -> Result<Vec<T>> {
        let count = self.count()?;
        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count {
            result.push(T::from_word(
                self.storage.sload(self.address, self.data_slot(i))?,
            ));
        }
        Ok(result)
    }

    /// Zeroes stored data and resets the push counter (capacity is preserved).
    pub fn clear(&self) -> Result<()> {
        let count = self.count()?;
        for i in 0..count {
            self.storage
                .sstore(self.address, self.data_slot(i), U256::ZERO)?;
        }
        self.storage
            .sstore(self.address, self.base_slot, U256::ZERO)
    }

    fn read_total(&self) -> Result<U256> {
        self.storage.sload(self.address, self.base_slot)
    }

    fn capacity_slot(&self) -> U256 {
        self.base_slot + U256::from(1u64)
    }

    fn data_slot(&self, index: u32) -> U256 {
        let start = U256::from_be_bytes(keccak256(self.base_slot.to_be_bytes::<32>()).0);
        start + U256::from(index as u64 * T::SLOTS as u64)
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
    fn test_push_before_setup_errors() {
        with_storage(|storage| {
            let b: StorageCircularBuffer<u64> =
                StorageCircularBuffer::new(U256::ZERO, ADDR, storage);
            assert!(b.push(1).is_err());
        });
    }

    #[test]
    fn test_fill_without_eviction() {
        with_storage(|storage| {
            let b: StorageCircularBuffer<u64> =
                StorageCircularBuffer::new(U256::ZERO, ADDR, storage);
            b.setup(3).unwrap();
            assert_eq!(b.push(10).unwrap(), None);
            assert_eq!(b.push(20).unwrap(), None);
            assert_eq!(b.push(30).unwrap(), None);
            assert_eq!(b.count().unwrap(), 3);
            assert_eq!(b.capacity().unwrap(), 3);
            let mut all = b.read_all().unwrap();
            all.sort();
            assert_eq!(all, vec![10, 20, 30]);
        });
    }

    #[test]
    fn test_eviction_oldest_first() {
        with_storage(|storage| {
            let b: StorageCircularBuffer<u64> =
                StorageCircularBuffer::new(U256::ZERO, ADDR, storage);
            b.setup(3).unwrap();
            b.push(10).unwrap();
            b.push(20).unwrap();
            b.push(30).unwrap();
            assert_eq!(b.push(40).unwrap(), Some(10));
            assert_eq!(b.push(50).unwrap(), Some(20));
            assert_eq!(b.count().unwrap(), 3);
            let mut all = b.read_all().unwrap();
            all.sort();
            assert_eq!(all, vec![30, 40, 50]);
        });
    }

    #[test]
    fn test_clear() {
        with_storage(|storage| {
            let b: StorageCircularBuffer<u64> =
                StorageCircularBuffer::new(U256::ZERO, ADDR, storage);
            b.setup(2).unwrap();
            b.push(1).unwrap();
            b.push(2).unwrap();
            b.clear().unwrap();
            assert!(b.is_empty().unwrap());
            assert_eq!(b.capacity().unwrap(), 2);
            assert_eq!(b.push(9).unwrap(), None);
        });
    }
}
