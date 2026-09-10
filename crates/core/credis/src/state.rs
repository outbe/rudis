//! Storage CRUD and per-address index helpers for the Credis contract.
//!
//! All functions take a short-lived `&mut CredisContract` (or `&CredisContract`
//! for reads) constructed via `CredisContract::new(storage)`. They only touch
//! local storage; orchestration logic lives in `runtime.rs`.

use alloy_primitives::{Address, U256};

use outbe_primitives::error::Result;

use crate::errors::CredisError;
use crate::schema::{CredisContract, Position};

impl CredisContract<'_> {
    // ---------------------------------------------------------------------
    // Position CRUD
    // ---------------------------------------------------------------------

    pub(crate) fn position_exists(&self, position_id: U256) -> Result<bool> {
        self.positions.exists(position_id)
    }

    pub(crate) fn load_position(&self, position_id: U256) -> Result<Position> {
        self.positions
            .get(position_id)?
            .ok_or_else(|| CredisError::PositionNotFound.into())
    }

    pub(crate) fn create_position_record(&mut self, position: &Position) -> Result<()> {
        self.positions.create(position)
    }

    pub(crate) fn update_position_record(&mut self, position: &Position) -> Result<()> {
        self.positions.update(position)
    }

    // ---------------------------------------------------------------------
    // Per-address dense index (mirrors outbe-nod owner_nod_* shape)
    // ---------------------------------------------------------------------

    pub(crate) fn append_to_address_index(
        &mut self,
        account: Address,
        position_id: U256,
    ) -> Result<()> {
        let count = self.address_position_counts.read(&account)?;
        let key = CredisContract::address_index_key(account, count);
        self.address_position_ids.write(&key, position_id)?;
        self.address_position_counts.write(&account, count + 1)?;
        Ok(())
    }

    pub(crate) fn read_address_position_count(&self, account: Address) -> Result<u32> {
        self.address_position_counts.read(&account)
    }

    pub(crate) fn read_address_position_id(&self, account: Address, index: u32) -> Result<U256> {
        let key = CredisContract::address_index_key(account, index);
        self.address_position_ids.read(&key)
    }

    // ---------------------------------------------------------------------
    // Global dense index backing `totalSupply` / `positionByIndex`
    // ---------------------------------------------------------------------

    pub(crate) fn append_to_global_index(&mut self, position_id: U256) -> Result<()> {
        let total = self.total_positions.read()?;
        self.position_id_at_index.write(&total, position_id)?;
        self.total_positions.write(total + 1)?;
        Ok(())
    }

    pub(crate) fn read_total_positions(&self) -> Result<u64> {
        self.total_positions.read()
    }

    pub(crate) fn read_position_id_at(&self, index: u64) -> Result<U256> {
        self.position_id_at_index.read(&index)
    }

    // ---------------------------------------------------------------------
    // Active-position index (non-terminal positions only)
    // ---------------------------------------------------------------------

    /// Appends a position to the dense active index.
    pub(crate) fn insert_active(&mut self, position_id: U256) -> Result<()> {
        let index = self.active_positions.len()?;
        self.active_positions.push(position_id)?;
        self.active_position_index.write(&position_id, index)?;
        Ok(())
    }

    /// Swap-removes a position from the dense active index. Caller guarantees
    /// the position is currently listed, i.e. its state was non-terminal.
    pub(crate) fn remove_active(&mut self, position_id: U256) -> Result<()> {
        let index = self.active_position_index.read(&position_id)?;
        let last = self
            .active_positions
            .len()?
            .checked_sub(1)
            .ok_or(CredisError::PositionNotFound)?;
        if index != last {
            let moved = self
                .active_positions
                .get(last)?
                .ok_or(CredisError::PositionNotFound)?;
            self.active_positions.set(index, moved)?;
            self.active_position_index.write(&moved, index)?;
        }
        self.active_positions.pop()?;
        self.active_position_index.clear(&position_id)?;
        Ok(())
    }

    pub(crate) fn read_active_len(&self) -> Result<u32> {
        self.active_positions.len()
    }

    pub(crate) fn read_active_at(&self, index: u32) -> Result<Option<U256>> {
        self.active_positions.get(index)
    }

    // ---------------------------------------------------------------------
    // Called-position counter
    // ---------------------------------------------------------------------

    pub(crate) fn bump_called_count(&mut self, account: Address) -> Result<()> {
        let count = self.called_position_counts.read(&account)?;
        self.called_position_counts
            .write(&account, count.saturating_add(1))
    }

    pub(crate) fn drop_called_count(&mut self, account: Address) -> Result<()> {
        let count = self.called_position_counts.read(&account)?;
        self.called_position_counts
            .write(&account, count.saturating_sub(1))
    }
}
