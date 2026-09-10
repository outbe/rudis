use alloy_primitives::{keccak256, Address, U256};
use std::cmp::Ordering;
use std::marker::PhantomData;

use crate::error::Result;
use crate::storage::StorageHandle;

use super::Storable;

/// EVM-backed binary min-heap.
///
/// Mirrors the OpenZeppelin `Heap.sol` pattern: a single-array heap indexed by
/// `parent = (i-1)/2`, `children = 2i+1, 2i+2`, with `peek: O(1)`, `push:
/// O(log N)`, `pop_min: O(log N)`.
///
/// Storage layout:
/// - Base slot: stores length as `U256` (same convention as `StorageVec`).
/// - Data slots: `keccak256(base_slot) + index * T::SLOTS`.
///
/// Ordering is injected at each mutation via a fallible closure - our
/// use-case compares by priorities looked up from a neighbouring `Map`,
/// which requires `sload` and can fail. The caller MUST use a consistent
/// comparator across the heap's lifetime; mixing yields undefined behavior
/// (same caveat as OZ `Heap.sol`).
pub struct BinaryHeap<'storage, T> {
    base_slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _marker: PhantomData<T>,
}

impl<'storage, T: Storable + Copy + PartialEq> BinaryHeap<'storage, T> {
    pub fn new(base_slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            base_slot,
            address,
            storage,
            _marker: PhantomData,
        }
    }

    pub fn len(&self) -> Result<u32> {
        let word = self.storage.sload(self.address, self.base_slot)?;
        Ok(word.to::<u32>())
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|l| l == 0)
    }

    pub fn peek(&self) -> Result<Option<T>> {
        let len = self.len()?;
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(self.read(0)?))
    }

    /// Inserts `value` and sifts up using `cmp`. Comparator returns `Less`
    /// when the first argument should bubble above the second (min-heap).
    pub fn push<F>(&mut self, value: T, mut cmp: F) -> Result<()>
    where
        F: FnMut(&T, &T) -> Result<Ordering>,
    {
        let len = self.len()?;
        self.write(len, value)?;
        self.set_len(len + 1)?;
        self.sift_up(len, &mut cmp)?;
        Ok(())
    }

    /// Removes the root (min element). Swap last-into-root + sift-down.
    pub fn pop_min<F>(&mut self, mut cmp: F) -> Result<Option<T>>
    where
        F: FnMut(&T, &T) -> Result<Ordering>,
    {
        let len = self.len()?;
        if len == 0 {
            return Ok(None);
        }
        let root = self.read(0)?;
        let last_idx = len - 1;
        if last_idx > 0 {
            let tail = self.read(last_idx)?;
            self.write(0, tail)?;
        }
        self.clear_slot(last_idx)?;
        self.set_len(last_idx)?;
        if last_idx > 0 {
            self.sift_down(0, &mut cmp)?;
        }
        Ok(Some(root))
    }

    /// Removes the first entry equal to `target` (by `PartialEq`). Returns
    /// `true` if found. O(N) find + O(log N) sift.
    pub fn remove<F>(&mut self, target: &T, mut cmp: F) -> Result<bool>
    where
        F: FnMut(&T, &T) -> Result<Ordering>,
    {
        let len = self.len()?;
        let mut found: Option<u32> = None;
        for i in 0..len {
            if &self.read(i)? == target {
                found = Some(i);
                break;
            }
        }
        let Some(idx) = found else {
            return Ok(false);
        };
        let last_idx = len - 1;
        if idx != last_idx {
            let tail = self.read(last_idx)?;
            self.write(idx, tail)?;
        }
        self.clear_slot(last_idx)?;
        self.set_len(last_idx)?;
        if idx != last_idx && last_idx > 0 {
            // Restore invariant: entry at `idx` may be too small or too large
            // relative to its neighbours - try both directions.
            let parent = if idx == 0 { None } else { Some((idx - 1) / 2) };
            let should_sift_up = match parent {
                Some(p) => cmp(&self.read(idx)?, &self.read(p)?)? == Ordering::Less,
                None => false,
            };
            if should_sift_up {
                self.sift_up(idx, &mut cmp)?;
            } else {
                self.sift_down(idx, &mut cmp)?;
            }
        }
        Ok(true)
    }

    pub fn clear(&mut self) -> Result<()> {
        let len = self.len()?;
        for i in 0..len {
            self.clear_slot(i)?;
        }
        self.set_len(0)
    }

    /// Raw snapshot in heap-array order (NOT sorted). For admin / debug.
    pub fn read_all(&self) -> Result<Vec<T>> {
        let len = self.len()?;
        let mut out = Vec::with_capacity(len as usize);
        for i in 0..len {
            out.push(self.read(i)?);
        }
        Ok(out)
    }

    // --- internal helpers ---

    fn data_slot(&self, index: u32) -> U256 {
        let start = U256::from_be_bytes(keccak256(self.base_slot.to_be_bytes::<32>()).0);
        start + U256::from(index as u64 * T::SLOTS as u64)
    }

    fn read(&self, index: u32) -> Result<T> {
        let word = self.storage.sload(self.address, self.data_slot(index))?;
        Ok(T::from_word(word))
    }

    fn write(&self, index: u32, value: T) -> Result<()> {
        self.storage
            .sstore(self.address, self.data_slot(index), value.to_word())
    }

    fn clear_slot(&self, index: u32) -> Result<()> {
        self.storage
            .sstore(self.address, self.data_slot(index), U256::ZERO)
    }

    fn set_len(&self, len: u32) -> Result<()> {
        self.storage
            .sstore(self.address, self.base_slot, U256::from(len))
    }

    fn sift_up<F>(&self, mut i: u32, cmp: &mut F) -> Result<()>
    where
        F: FnMut(&T, &T) -> Result<Ordering>,
    {
        while i > 0 {
            let parent = (i - 1) / 2;
            let child_val = self.read(i)?;
            let parent_val = self.read(parent)?;
            if cmp(&child_val, &parent_val)? == Ordering::Less {
                self.write(i, parent_val)?;
                self.write(parent, child_val)?;
                i = parent;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn sift_down<F>(&self, mut i: u32, cmp: &mut F) -> Result<()>
    where
        F: FnMut(&T, &T) -> Result<Ordering>,
    {
        let len = self.len()?;
        loop {
            let left = 2 * i + 1;
            let right = 2 * i + 2;
            if left >= len {
                break;
            }
            let mut smallest = left;
            if right < len {
                let l = self.read(left)?;
                let r = self.read(right)?;
                if cmp(&r, &l)? == Ordering::Less {
                    smallest = right;
                }
            }
            let current = self.read(i)?;
            let child = self.read(smallest)?;
            if cmp(&child, &current)? == Ordering::Less {
                self.write(i, child)?;
                self.write(smallest, current)?;
                i = smallest;
            } else {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PrecompileError;
    use crate::storage::hashmap::HashMapStorageProvider;
    use alloy_primitives::address;

    fn with_storage<F: FnOnce(StorageHandle)>(f: F) {
        let mut provider = HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        f(storage);
    }

    const ADDR: Address = address!("0x0000000000000000000000000000000000001004");

    fn u64_cmp(a: &u64, b: &u64) -> Result<Ordering> {
        Ok(a.cmp(b))
    }

    fn u64_cmp_rev(a: &u64, b: &u64) -> Result<Ordering> {
        Ok(b.cmp(a))
    }

    #[test]
    fn test_empty_heap_peek_pop_return_none() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            assert_eq!(h.len().unwrap(), 0);
            assert!(h.is_empty().unwrap());
            assert_eq!(h.peek().unwrap(), None);
            assert_eq!(h.pop_min(u64_cmp).unwrap(), None);
        });
    }

    #[test]
    fn test_push_peek_is_min() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            for v in [3u64, 1, 4, 1, 5, 9, 2, 6] {
                h.push(v, u64_cmp).unwrap();
            }
            assert_eq!(h.len().unwrap(), 8);
            assert_eq!(h.peek().unwrap(), Some(1));
        });
    }

    #[test]
    fn test_pop_min_sequence_matches_sorted() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            for v in [3u64, 1, 4, 1, 5, 9, 2, 6] {
                h.push(v, u64_cmp).unwrap();
            }
            let mut popped = Vec::new();
            while let Some(v) = h.pop_min(u64_cmp).unwrap() {
                popped.push(v);
            }
            assert_eq!(popped, vec![1, 1, 2, 3, 4, 5, 6, 9]);
            assert!(h.is_empty().unwrap());
        });
    }

    #[test]
    fn test_custom_comparator_max_heap() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            for v in [3u64, 1, 4, 1, 5, 9, 2, 6] {
                h.push(v, u64_cmp_rev).unwrap();
            }
            // pop_min under reverse cmp = pop max under natural order
            let mut popped = Vec::new();
            while let Some(v) = h.pop_min(u64_cmp_rev).unwrap() {
                popped.push(v);
            }
            assert_eq!(popped, vec![9, 6, 5, 4, 3, 2, 1, 1]);
        });
    }

    #[test]
    fn test_remove_by_equality_restores_invariant() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            for v in [3u64, 1, 4, 1, 5, 9, 2, 6] {
                h.push(v, u64_cmp).unwrap();
            }
            assert!(h.remove(&4, u64_cmp).unwrap());
            assert_eq!(h.len().unwrap(), 7);

            let mut popped = Vec::new();
            while let Some(v) = h.pop_min(u64_cmp).unwrap() {
                popped.push(v);
            }
            assert_eq!(popped, vec![1, 1, 2, 3, 5, 6, 9]);
        });
    }

    #[test]
    fn test_remove_missing_returns_false() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            h.push(10, u64_cmp).unwrap();
            assert!(!h.remove(&99, u64_cmp).unwrap());
            assert_eq!(h.len().unwrap(), 1);
        });
    }

    #[test]
    fn test_clear_resets_length() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            for v in [3u64, 1, 4] {
                h.push(v, u64_cmp).unwrap();
            }
            h.clear().unwrap();
            assert!(h.is_empty().unwrap());
            h.push(7, u64_cmp).unwrap();
            assert_eq!(h.peek().unwrap(), Some(7));
        });
    }

    #[test]
    fn test_fallible_comparator_propagates_error() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            h.push(1, u64_cmp).unwrap();
            let err = h.push(2, |_a, _b| Err(PrecompileError::Revert("boom".into())));
            assert!(err.is_err());
        });
    }

    #[test]
    fn test_read_all_returns_heap_array_order() {
        with_storage(|storage| {
            let mut h: BinaryHeap<u64> = BinaryHeap::new(U256::ZERO, ADDR, storage);
            for v in [3u64, 1, 2] {
                h.push(v, u64_cmp).unwrap();
            }
            // min-heap invariant: root is smallest, other positions are
            // implementation-specific but bounded above by children.
            let snapshot = h.read_all().unwrap();
            assert_eq!(snapshot.len(), 3);
            assert_eq!(snapshot[0], 1);
            assert!(snapshot[1..].iter().all(|v| *v >= 1));
        });
    }
}
