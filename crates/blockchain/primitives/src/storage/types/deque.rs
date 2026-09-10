use alloy_primitives::{keccak256, Address, U256};

use crate::error::Result;
use crate::storage::StorageHandle;

use super::Storable;

/// EVM-compatible double-ended queue (port of OpenZeppelin `DoubleEndedQueue`).
///
/// Supports amortized O(1) `push`/`pop` at both ends and O(1) indexed access,
/// with O(N) enumeration. Indices are `u128` and wrap on overflow (matching the
/// OZ reference); the queue is empty iff `begin == end`.
///
/// Storage layout:
/// - Base slot:      `begin` index (`u128`)
/// - Base slot + 1:  `end` index (`u128`)
/// - Data:           `keccak256(base_slot) + index * T::SLOTS`
pub struct StorageDeque<'storage, T> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _marker: std::marker::PhantomData<T>,
}

impl<'storage, T: Storable> StorageDeque<'storage, T> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _marker: std::marker::PhantomData,
        }
    }

    /// The schema slot this queue is anchored at (`begin`; `end` is `base_slot + 1`).
    pub fn base_slot(&self) -> U256 {
        self.base_slot
    }

    /// Number of elements currently queued. Bounded by usage well below
    /// `u64::MAX`; saturates rather than panicking in the impossible overflow.
    pub fn len(&self) -> Result<u64> {
        let span = self.read_end()?.wrapping_sub(self.read_begin()?);
        Ok(u64::try_from(span).unwrap_or(u64::MAX))
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.read_begin()? == self.read_end()?)
    }

    /// Appends `value` at the back (highest index).
    pub fn push_back(&self, value: T) -> Result<()> {
        let end = self.read_end()?;
        self.storage
            .sstore(self.address, self.data_slot(end), value.to_word())?;
        self.write_end(end.wrapping_add(1))
    }

    /// Prepends `value` at the front (lowest index).
    pub fn push_front(&self, value: T) -> Result<()> {
        let begin = self.read_begin()?.wrapping_sub(1);
        self.storage
            .sstore(self.address, self.data_slot(begin), value.to_word())?;
        self.write_begin(begin)
    }

    /// Removes and returns the front element, or `None` if empty.
    pub fn pop_front(&self) -> Result<Option<T>> {
        let begin = self.read_begin()?;
        if begin == self.read_end()? {
            return Ok(None);
        }
        let slot = self.data_slot(begin);
        let value = T::from_word(self.storage.sload(self.address, slot)?);
        self.storage.sstore(self.address, slot, U256::ZERO)?; // reclaim
        self.write_begin(begin.wrapping_add(1))?;
        Ok(Some(value))
    }

    /// Removes and returns the back element, or `None` if empty.
    pub fn pop_back(&self) -> Result<Option<T>> {
        let end = self.read_end()?;
        if self.read_begin()? == end {
            return Ok(None);
        }
        let new_end = end.wrapping_sub(1);
        let slot = self.data_slot(new_end);
        let value = T::from_word(self.storage.sload(self.address, slot)?);
        self.storage.sstore(self.address, slot, U256::ZERO)?; // reclaim
        self.write_end(new_end)?;
        Ok(Some(value))
    }

    pub fn front(&self) -> Result<Option<T>> {
        let begin = self.read_begin()?;
        if begin == self.read_end()? {
            return Ok(None);
        }
        Ok(Some(T::from_word(
            self.storage.sload(self.address, self.data_slot(begin))?,
        )))
    }

    pub fn back(&self) -> Result<Option<T>> {
        let end = self.read_end()?;
        if self.read_begin()? == end {
            return Ok(None);
        }
        Ok(Some(T::from_word(self.storage.sload(
            self.address,
            self.data_slot(end.wrapping_sub(1)),
        )?)))
    }

    /// Element at logical position `index` (0 = front), or `None` if out of range.
    pub fn at(&self, index: u64) -> Result<Option<T>> {
        let begin = self.read_begin()?;
        let span = self.read_end()?.wrapping_sub(begin);
        if u128::from(index) >= span {
            return Ok(None);
        }
        let slot = self.data_slot(begin.wrapping_add(u128::from(index)));
        Ok(Some(T::from_word(self.storage.sload(self.address, slot)?)))
    }

    /// All elements in front-to-back order.
    pub fn read_all(&self) -> Result<Vec<T>> {
        let begin = self.read_begin()?;
        let span = self.read_end()?.wrapping_sub(begin);
        let mut result = Vec::with_capacity(usize::try_from(span).unwrap_or(0));
        let mut i: u128 = 0;
        while i < span {
            let slot = self.data_slot(begin.wrapping_add(i));
            result.push(T::from_word(self.storage.sload(self.address, slot)?));
            i += 1;
        }
        Ok(result)
    }

    /// Empties the queue, zeroing the vacated data slots.
    pub fn clear(&self) -> Result<()> {
        let begin = self.read_begin()?;
        let end = self.read_end()?;
        let mut idx = begin;
        while idx != end {
            self.storage
                .sstore(self.address, self.data_slot(idx), U256::ZERO)?;
            idx = idx.wrapping_add(1);
        }
        self.write_begin(0)?;
        self.write_end(0)
    }

    fn read_begin(&self) -> Result<u128> {
        Ok(self
            .storage
            .sload(self.address, self.base_slot)?
            .to::<u128>())
    }

    fn read_end(&self) -> Result<u128> {
        Ok(self
            .storage
            .sload(self.address, self.end_slot())?
            .to::<u128>())
    }

    fn write_begin(&self, begin: u128) -> Result<()> {
        self.storage
            .sstore(self.address, self.base_slot, U256::from(begin))
    }

    fn write_end(&self, end: u128) -> Result<()> {
        self.storage
            .sstore(self.address, self.end_slot(), U256::from(end))
    }

    fn end_slot(&self) -> U256 {
        self.base_slot + U256::from(1u64)
    }

    fn data_slot(&self, index: u128) -> U256 {
        let start = U256::from_be_bytes(keccak256(self.base_slot.to_be_bytes::<32>()).0);
        start + U256::from(index) * U256::from(T::SLOTS as u64)
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
            let q: StorageDeque<u64> = StorageDeque::new(U256::ZERO, ADDR, storage);
            assert_eq!(q.len().unwrap(), 0);
            assert!(q.is_empty().unwrap());
            assert_eq!(q.pop_front().unwrap(), None);
            assert_eq!(q.pop_back().unwrap(), None);
            assert_eq!(q.front().unwrap(), None);
            assert_eq!(q.back().unwrap(), None);
        });
    }

    #[test]
    fn test_push_back_pop_front_fifo() {
        with_storage(|storage| {
            let q: StorageDeque<u64> = StorageDeque::new(U256::ZERO, ADDR, storage);
            q.push_back(10).unwrap();
            q.push_back(20).unwrap();
            q.push_back(30).unwrap();
            assert_eq!(q.len().unwrap(), 3);
            assert_eq!(q.read_all().unwrap(), vec![10, 20, 30]);
            assert_eq!(q.front().unwrap(), Some(10));
            assert_eq!(q.back().unwrap(), Some(30));
            assert_eq!(q.pop_front().unwrap(), Some(10));
            assert_eq!(q.pop_front().unwrap(), Some(20));
            assert_eq!(q.len().unwrap(), 1);
            assert_eq!(q.read_all().unwrap(), vec![30]);
        });
    }

    #[test]
    fn test_push_front_and_pop_back() {
        with_storage(|storage| {
            let q: StorageDeque<u64> = StorageDeque::new(U256::from(7u64), ADDR, storage);
            q.push_back(20).unwrap();
            q.push_front(10).unwrap();
            q.push_front(5).unwrap();
            assert_eq!(q.read_all().unwrap(), vec![5, 10, 20]);
            assert_eq!(q.at(1).unwrap(), Some(10));
            assert_eq!(q.pop_back().unwrap(), Some(20));
            assert_eq!(q.pop_back().unwrap(), Some(10));
            assert_eq!(q.front().unwrap(), Some(5));
        });
    }

    #[test]
    fn test_clear_then_reuse() {
        with_storage(|storage| {
            let q: StorageDeque<u64> = StorageDeque::new(U256::ZERO, ADDR, storage);
            q.push_back(1).unwrap();
            q.push_back(2).unwrap();
            q.clear().unwrap();
            assert!(q.is_empty().unwrap());
            q.push_back(9).unwrap();
            assert_eq!(q.read_all().unwrap(), vec![9]);
        });
    }

    #[test]
    fn test_at_out_of_range() {
        with_storage(|storage| {
            let q: StorageDeque<u64> = StorageDeque::new(U256::ZERO, ADDR, storage);
            q.push_back(1).unwrap();
            assert_eq!(q.at(0).unwrap(), Some(1));
            assert_eq!(q.at(1).unwrap(), None);
        });
    }
}
