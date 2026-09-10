use alloy_primitives::{Address, U256};
use std::marker::PhantomData;

use crate::error::Result;
use crate::storage::types::Storable;
use crate::storage::StorageHandle;

/// Type-safe accessor for a single EVM storage slot.
///
/// `Slot<T>` knows the contract address, the slot index, and the Rust type `T`
/// stored there.
pub struct Slot<'storage, T> {
    slot: U256,
    address: Address,
    storage: StorageHandle<'storage>,
    _ty: PhantomData<T>,
}

impl<'storage, T> Slot<'storage, T> {
    /// Creates a new slot accessor.
    pub fn new(slot: U256, address: Address, storage: StorageHandle<'storage>) -> Self {
        Self {
            slot,
            address,
            storage,
            _ty: PhantomData,
        }
    }

    /// Returns the raw slot index.
    pub fn slot(&self) -> U256 {
        self.slot
    }

    /// Returns the contract address.
    pub fn address(&self) -> Address {
        self.address
    }
}

impl<T: Storable> Slot<'_, T> {
    /// Reads the value from storage.
    pub fn read(&self) -> Result<T> {
        let word = self.storage.sload(self.address, self.slot)?;
        Ok(T::from_word(word))
    }

    /// Writes a value to storage.
    pub fn write(&self, value: T) -> Result<()> {
        self.storage
            .sstore(self.address, self.slot, value.to_word())
    }

    /// Deletes (zeroes) the storage slot.
    pub fn delete(&self) -> Result<()> {
        self.storage.sstore(self.address, self.slot, U256::ZERO)
    }
}
