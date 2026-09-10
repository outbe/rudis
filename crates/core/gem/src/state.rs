use alloy_primitives::{keccak256, Address, B256, U256};
use base64::Engine;
use outbe_primitives::error::Result;
use outbe_primitives::math::{
    constants::MAX_BIN_ID,
    reference_price,
    tree_math::{self, BinTreeStorage},
};

use crate::{
    constants::{BIN_STEP_BP, TOKEN_DESCRIPTION, TOKEN_NAME, TOKEN_SYMBOL},
    errors::GemError,
    schema::{GemContract, GemData, GemState},
};

impl GemContract<'_> {
    pub fn name() -> &'static str {
        TOKEN_NAME
    }

    pub fn symbol() -> &'static str {
        TOKEN_SYMBOL
    }

    pub fn parse_gem_id(gem_id: &str) -> Result<U256> {
        let trimmed = gem_id.strip_prefix("0x").unwrap_or(gem_id);
        if trimmed.len() != 64 {
            return Err(GemError::GemNotFound.into());
        }
        let mut buf = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut buf).map_err(|_| GemError::GemNotFound)?;
        Ok(U256::from_be_bytes(buf))
    }

    pub fn total_supply(&self) -> Result<u64> {
        self.total_supply.read()
    }

    pub fn balance_of(&self, owner: Address) -> Result<u32> {
        self.owner_gem_counts.read(&owner)
    }

    pub fn owner_of(&self, gem_id: U256) -> Result<Address> {
        let item = self.gem_items.get(gem_id)?.ok_or(GemError::GemNotFound)?;
        Ok(item.owner)
    }

    pub fn get_gem(&self, gem_id: U256) -> Result<Option<GemData>> {
        self.gem_items.get(gem_id)
    }

    pub fn token_of_owner_by_index(&self, owner: Address, index: u32) -> Result<U256> {
        let count = self.owner_gem_counts.read(&owner)?;
        if index >= count {
            return Err(GemError::IndexOutOfBounds.into());
        }
        self.owner_gem_ids
            .read(&Self::owner_index_key(owner, index))
    }

    pub fn token_uri(&self, gem_id: U256) -> Result<String> {
        let item = self.gem_items.get(gem_id)?.ok_or(GemError::GemNotFound)?;
        // TODO: replace hand-rolled JSON with type-safe serialization (serde struct).
        let json = format!(
            "{{\"name\":\"Gem #{}\",\"description\":\"{}\",\"attributes\":[{{\"trait_type\":\"gem_id\",\"value\":\"{}\"}},{{\"trait_type\":\"gem_type\",\"value\":{}}},{{\"trait_type\":\"state\",\"value\":{}}},{{\"trait_type\":\"promis_load_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"entry_price_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"floor_price_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"issuance_currency\",\"value\":{}}},{{\"trait_type\":\"reference_currency\",\"value\":{}}}]}}",
            gem_id,
            TOKEN_DESCRIPTION,
            gem_id,
            item.gem_type,
            item.state,
            item.promis_load_minor,
            item.entry_price_minor,
            item.floor_price_minor,
            item.issuance_currency,
            item.reference_currency,
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        Ok(format!("data:application/json;base64,{}", encoded))
    }

    pub(crate) fn owner_index_key(owner: Address, index: u32) -> B256 {
        let mut buf = [0u8; 24];
        buf[0..20].copy_from_slice(owner.as_slice());
        buf[20..24].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    pub(crate) fn add_gem(&mut self, item: &GemData) -> Result<()> {
        if self.gem_items.exists(item.gem_id)? {
            return Err(GemError::AlreadyExists.into());
        }
        self.gem_items.create(item)?;

        let owner_count = self.owner_gem_counts.read(&item.owner)?;
        self.owner_gem_ids
            .write(&Self::owner_index_key(item.owner, owner_count), item.gem_id)?;
        self.owner_gem_counts.write(&item.owner, owner_count + 1)?;

        let idx = self.all_gem_ids.len()?;
        self.all_gem_ids.push(item.gem_id)?;
        self.gem_index.write(&item.gem_id, idx)?;

        let supply = self.total_supply.read()?;
        self.total_supply.write(supply + 1)?;

        // Park unqualified gems in the bin index so the qualifier hook can
        // skip non-candidates without scanning the full population.
        if item.state == GemState::Issued as u8 {
            self.insert_unqualified(item.gem_id, item.floor_price_minor, item.reference_currency)?;
        } else if item.state == GemState::Qualified as u8 {
            // Genesis gems are born Qualified - index them by call price.
            self.insert_qualified(item.gem_id, item.call_price_minor, item.reference_currency)?;
        }

        if item.call_window > self.max_call_window.read(&item.reference_currency)? {
            self.max_call_window
                .write(&item.reference_currency, item.call_window)?;
        }

        Ok(())
    }

    pub(crate) fn burn(&mut self, item: &GemData) -> Result<()> {
        self.gem_items.delete(item.gem_id)?;

        // Settled gems (promis mining) are in neither structure.
        if item.state == GemState::Qualified as u8 {
            self.remove_qualified(item.gem_id, item.call_price_minor, item.reference_currency)?;
        } else if item.state == GemState::Called as u8 {
            self.remove_called(item.gem_id)?;
        }

        let idx = self.gem_index.read(&item.gem_id)?;
        let last = self
            .all_gem_ids
            .len()?
            .checked_sub(1)
            .ok_or(GemError::GemNotFound)?;
        if idx != last {
            let last_id = self.all_gem_ids.get(last)?.ok_or(GemError::GemNotFound)?;
            self.all_gem_ids.set(idx, last_id)?;
            self.gem_index.write(&last_id, idx)?;
        }
        self.all_gem_ids.pop()?;
        self.gem_index.clear(&item.gem_id)?;

        self.compact_owner_index(item.owner, item.gem_id)?;

        let supply = self.total_supply.read()?;
        if supply > 0 {
            self.total_supply.write(supply - 1)?;
        }
        Ok(())
    }

    pub(crate) fn set_state(&mut self, gem_id: U256, new_state: GemState) -> Result<()> {
        let mut item = self.gem_items.get(gem_id)?.ok_or(GemError::GemNotFound)?;
        // Issued is the only state parked in the bin index; any transition
        // out of Issued must clean it up. Idempotent if the gem isn't there.
        if item.state == GemState::Issued as u8 && new_state != GemState::Issued {
            self.remove_unqualified(gem_id, item.floor_price_minor, item.reference_currency)?;
        }

        match new_state {
            GemState::Qualified => {
                self.insert_qualified(gem_id, item.call_price_minor, item.reference_currency)?;
                item.qualified_at = self.storage.timestamp()?.to::<u64>();
            }
            GemState::Settled => {
                // Qualified leaves the bin index; Called leaves it below.
                if item.state == GemState::Qualified as u8 {
                    self.remove_qualified(gem_id, item.call_price_minor, item.reference_currency)?;
                }
                item.settled_at = self.storage.timestamp()?.to::<u64>();
            }
            _ => {}
        }

        if item.state == GemState::Called as u8 && new_state != GemState::Called {
            self.remove_called(gem_id)?;
        }

        item.state = new_state as u8;
        self.gem_items.update(&item)?;
        Ok(())
    }

    pub(crate) fn insert_qualified(
        &mut self,
        gem_id: U256,
        call_price_minor: U256,
        reference_currency: u16,
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(call_price_minor)?;
        let scoped = Self::scoped(reference_currency, bin_id);
        let count = self.qualified_bin_count.read(&scoped)?;
        self.qualified_bin_gems.write(
            &Self::bin_index_key(reference_currency, bin_id, count),
            gem_id,
        )?;
        self.qualified_bin_count.write(&scoped, count + 1)?;
        tree_math::add(&QualifiedBins(self, reference_currency), bin_id)?;
        Ok(())
    }

    pub(crate) fn remove_qualified(
        &mut self,
        gem_id: U256,
        call_price_minor: U256,
        reference_currency: u16,
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(call_price_minor)?;
        let scoped = Self::scoped(reference_currency, bin_id);
        let count = self.qualified_bin_count.read(&scoped)?;
        if count == 0 {
            return Ok(());
        }
        let mut found: Option<u32> = None;
        for i in 0..count {
            if self
                .qualified_bin_gems
                .read(&Self::bin_index_key(reference_currency, bin_id, i))?
                == gem_id
            {
                found = Some(i);
                break;
            }
        }
        let Some(idx) = found else {
            return Ok(());
        };
        let last = count - 1;
        let last_key = Self::bin_index_key(reference_currency, bin_id, last);
        if idx != last {
            let last_id = self.qualified_bin_gems.read(&last_key)?;
            self.qualified_bin_gems.write(
                &Self::bin_index_key(reference_currency, bin_id, idx),
                last_id,
            )?;
        }
        self.qualified_bin_gems.clear(&last_key)?;
        self.qualified_bin_count.write(&scoped, last)?;
        if last == 0 {
            tree_math::remove(&QualifiedBins(self, reference_currency), bin_id)?;
        }
        Ok(())
    }

    /// Gems in one bin, snapshotted: qualifying or calling one shifts the bin.
    pub(crate) fn qualified_bin_gems_at(
        &self,
        reference_currency: u16,
        bin_id: u32,
    ) -> Result<Vec<U256>> {
        let count = self
            .qualified_bin_count
            .read(&Self::scoped(reference_currency, bin_id))?;
        let mut gems = Vec::with_capacity(count as usize);
        for i in 0..count {
            let id = self.qualified_bin_gems.read(&Self::bin_index_key(
                reference_currency,
                bin_id,
                i,
            ))?;
            if !id.is_zero() {
                gems.push(id);
            }
        }
        Ok(gems)
    }

    /// `Qualified -> Called`. Records the call timestamp used to enforce the
    /// notice-period settlement deadline. Qualified gems are not parked in the
    /// unqualified bin index, so there is nothing to clean up here.
    pub(crate) fn mark_called(&mut self, gem_id: U256, called_at: u64) -> Result<()> {
        let mut item = self.gem_items.get(gem_id)?.ok_or(GemError::GemNotFound)?;
        if item.state != GemState::Qualified as u8 {
            return Err(GemError::InvalidState.into());
        }
        item.state = GemState::Called as u8;
        item.called_at = called_at;
        self.gem_items.update(&item)?;

        self.remove_qualified(gem_id, item.call_price_minor, item.reference_currency)?;
        self.push_called(gem_id, called_at + u64::from(item.call_notice_period))
    }

    pub(crate) fn push_called(&mut self, gem_id: U256, deadline: u64) -> Result<()> {
        let day = Self::deadline_bucket(deadline);
        let slot = self.expiry_bucket_len.read(&day)?;
        self.expiry_bucket_at
            .write(&Self::bucket_slot_key(day, slot), gem_id)?;
        self.expiry_bucket_len.write(&day, slot.saturating_add(1))?;
        self.called_bucket_slot
            .write(&gem_id, Self::packed_slot(day, slot))?;
        self.called_deadline.write(&gem_id, deadline)?;

        let live = self.expiry_bucket_live.read(&day)?;
        self.expiry_bucket_live
            .write(&day, live.saturating_add(1))?;
        if live == 0 {
            tree_math::add(&ExpiryDayTree(&*self), day)?;
        }
        Ok(())
    }

    pub(crate) fn remove_called(&mut self, gem_id: U256) -> Result<()> {
        let packed = self.called_bucket_slot.read(&gem_id)?;
        self.called_bucket_slot.clear(&gem_id)?;
        self.called_deadline.clear(&gem_id)?;
        if packed == 0 {
            return Ok(());
        }
        let (day, slot) = Self::unpack_slot(packed);
        self.release_expiry_slot(day, slot, gem_id)
    }

    /// Free one bucket slot, retiring the bucket once nothing waits in it.
    pub(crate) fn release_expiry_slot(&mut self, day: u32, slot: u32, gem_id: U256) -> Result<()> {
        let slot_key = Self::bucket_slot_key(day, slot);
        if self.expiry_bucket_at.read(&slot_key)? != gem_id {
            return Ok(());
        }
        self.expiry_bucket_at.clear(&slot_key)?;

        let live = self.expiry_bucket_live.read(&day)?.saturating_sub(1);
        self.expiry_bucket_live.write(&day, live)?;
        if live == 0 {
            self.expiry_bucket_len.clear(&day)?;
            self.expiry_bucket_live.clear(&day)?;
            tree_math::remove(&ExpiryDayTree(&*self), day)?;
            // The cursor names a slot in a length that no longer exists; a refill of
            // this day would otherwise resume past its new end.
            if self.expiry_sweep_day.read()? == day {
                self.expiry_sweep_day.write(0)?;
                self.expiry_cursor.write(0)?;
            }
        }
        Ok(())
    }

    /// Hour since the epoch a deadline falls in: plain UTC, not a WorldwideDay.
    pub(crate) const fn deadline_bucket(deadline: u64) -> u32 {
        (deadline / 3_600) as u32
    }

    pub(crate) const fn bucket_end(day: u32) -> u64 {
        (day as u64 + 1) * 3_600
    }

    const fn packed_slot(day: u32, slot: u32) -> u64 {
        ((day as u64) << 32) | slot as u64
    }

    const fn unpack_slot(packed: u64) -> (u32, u32) {
        ((packed >> 32) as u32, (packed & 0xffff_ffff) as u32)
    }

    pub(crate) fn bucket_slot_key(day: u32, slot: u32) -> B256 {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&day.to_be_bytes());
        buf[4..8].copy_from_slice(&slot.to_be_bytes());
        keccak256(buf)
    }

    pub(crate) fn expiry_slot(&self, day: u32, slot: u32) -> Result<Option<U256>> {
        let id = self
            .expiry_bucket_at
            .read(&Self::bucket_slot_key(day, slot))?;
        Ok((!id.is_zero()).then_some(id))
    }

    /// Drop whatever is left of a bucket the sweep has finished.
    pub(crate) fn force_retire_bucket(&mut self, day: u32) -> Result<u32> {
        let len = self.expiry_bucket_len.read(&day)?;
        let mut dropped = 0u32;
        for slot in 0..len {
            let gem_id = self
                .expiry_bucket_at
                .read(&Self::bucket_slot_key(day, slot))?;
            if gem_id.is_zero() {
                continue;
            }
            self.remove_called(gem_id)?;
            dropped += 1;
        }
        self.expiry_bucket_len.clear(&day)?;
        self.expiry_bucket_live.clear(&day)?;
        tree_math::remove(&ExpiryDayTree(&*self), day)?;
        if self.expiry_sweep_day.read()? == day {
            self.expiry_sweep_day.write(0)?;
            self.expiry_cursor.write(0)?;
        }
        Ok(dropped)
    }

    pub(crate) fn first_expiry_day(&self) -> Result<Option<u32>> {
        tree_math::find_first_left_inclusive(&ExpiryDayTree(self), 0)
    }

    fn compact_owner_index(&mut self, owner: Address, gem_id: U256) -> Result<()> {
        let count = self.owner_gem_counts.read(&owner)?;
        let last = count.checked_sub(1).ok_or(GemError::GemNotFound)?;
        let mut found: Option<u32> = None;
        for i in 0..count {
            let key = Self::owner_index_key(owner, i);
            if self.owner_gem_ids.read(&key)? == gem_id {
                found = Some(i);
                break;
            }
        }
        let idx = found.ok_or(GemError::GemNotFound)?;
        let last_key = Self::owner_index_key(owner, last);
        if idx != last {
            let last_id = self.owner_gem_ids.read(&last_key)?;
            self.owner_gem_ids
                .write(&Self::owner_index_key(owner, idx), last_id)?;
        }
        self.owner_gem_ids.clear(&last_key)?;
        self.owner_gem_counts.write(&owner, last)?;
        Ok(())
    }

    // --- Unqualified-gem bin index (PancakeSwap LB-style) ----------------

    pub fn price_to_bin(price: U256) -> Result<u32> {
        if price.is_zero() {
            return Ok(0);
        }
        reference_price::coen_iso_price_to_bin_id(price, BIN_STEP_BP)
    }

    /// Namespaces a bin-column key by the gem's reference currency.
    ///
    /// Mapping keys are left-padded to 32 bytes before hashing, so a wider
    /// integer type alone namespaces nothing - the ISO has to occupy real high
    /// bits. Bin ids are 24-bit and the trie's mid/leaf keys are 16-bit, so the
    /// low 32 bits always hold `key` unambiguously.
    pub(crate) const fn scoped(reference_currency: u16, key: u32) -> u64 {
        ((reference_currency as u64) << 32) | key as u64
    }

    pub(crate) fn bin_index_key(reference_currency: u16, bin_id: u32, index: u32) -> B256 {
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&reference_currency.to_be_bytes());
        buf[2..6].copy_from_slice(&bin_id.to_be_bytes());
        buf[6..10].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    pub(crate) fn insert_unqualified(
        &mut self,
        gem_id: U256,
        floor_price_minor: U256,
        reference_currency: u16,
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(floor_price_minor)?;
        debug_assert!(bin_id <= MAX_BIN_ID);
        let scoped = Self::scoped(reference_currency, bin_id);
        let count = self.unqualified_bin_count.read(&scoped)?;
        self.unqualified_bin_gems.write(
            &Self::bin_index_key(reference_currency, bin_id, count),
            gem_id,
        )?;
        self.unqualified_bin_count.write(&scoped, count + 1)?;
        tree_math::add(&CurrencyBins(self, reference_currency), bin_id)?;
        Ok(())
    }

    /// Remove `gem_id` from the bin at its `floor_price_minor`. Performs swap-and-pop
    /// to keep the bin's index dense; clears the bin's trie bit when emptied.
    pub(crate) fn remove_unqualified(
        &mut self,
        gem_id: U256,
        floor_price_minor: U256,
        reference_currency: u16,
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(floor_price_minor)?;
        let scoped = Self::scoped(reference_currency, bin_id);
        let count = self.unqualified_bin_count.read(&scoped)?;
        if count == 0 {
            return Ok(());
        }
        let mut found: Option<u32> = None;
        for i in 0..count {
            let key = Self::bin_index_key(reference_currency, bin_id, i);
            if self.unqualified_bin_gems.read(&key)? == gem_id {
                found = Some(i);
                break;
            }
        }
        let Some(idx) = found else {
            return Ok(());
        };
        let last = count - 1;
        let last_key = Self::bin_index_key(reference_currency, bin_id, last);
        if idx != last {
            let last_id = self.unqualified_bin_gems.read(&last_key)?;
            self.unqualified_bin_gems.write(
                &Self::bin_index_key(reference_currency, bin_id, idx),
                last_id,
            )?;
        }
        self.unqualified_bin_gems.clear(&last_key)?;
        self.unqualified_bin_count.write(&scoped, last)?;
        if last == 0 {
            tree_math::remove(&CurrencyBins(self, reference_currency), bin_id)?;
        }
        Ok(())
    }
}

// Adapter between one currency's slice of the contract's three bin-tree columns
// and the `tree_math::BinTreeStorage` trait. Mirrors `nod::state::CurrencyBins`.
//
// The trait functions take `&self` - storage writes go through the DSL's
// interior-mutable `StorageHandle`, so no `&mut` is needed at any call site.
// Construct the view inline at each `tree_math` call rather than binding it, so
// it never conflicts with a `&mut GemContract` borrow.
pub(crate) struct CurrencyBins<'a, 'storage>(pub(crate) &'a GemContract<'storage>, pub(crate) u16);

/// The qualified (call-price) trie of one reference currency.
/// Buckets holding a called gem whose notice period has not closed yet.
pub(crate) struct ExpiryDayTree<'a, 'storage>(pub(crate) &'a GemContract<'storage>);

impl BinTreeStorage for ExpiryDayTree<'_, '_> {
    fn read_root(&self) -> Result<U256> {
        self.0.expiry_tree_root.read()
    }
    fn write_root(&self, value: U256) -> Result<()> {
        self.0.expiry_tree_root.write(value)
    }
    fn read_mid(&self, key: u32) -> Result<U256> {
        self.0.expiry_tree_mid.read(&key)
    }
    fn write_mid(&self, key: u32, value: U256) -> Result<()> {
        self.0.expiry_tree_mid.write(&key, value)
    }
    fn read_leaf(&self, key: u32) -> Result<U256> {
        self.0.expiry_tree_leaf.read(&key)
    }
    fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
        self.0.expiry_tree_leaf.write(&key, value)
    }
}

pub(crate) struct QualifiedBins<'a, 'storage>(pub(crate) &'a GemContract<'storage>, pub(crate) u16);

impl BinTreeStorage for QualifiedBins<'_, '_> {
    fn read_root(&self) -> Result<U256> {
        self.0.qualified_bin_tree_root.read(&self.1)
    }
    fn write_root(&self, value: U256) -> Result<()> {
        self.0.qualified_bin_tree_root.write(&self.1, value)
    }
    fn read_mid(&self, key: u32) -> Result<U256> {
        self.0
            .qualified_bin_tree_mid
            .read(&GemContract::scoped(self.1, key))
    }
    fn write_mid(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .qualified_bin_tree_mid
            .write(&GemContract::scoped(self.1, key), value)
    }
    fn read_leaf(&self, key: u32) -> Result<U256> {
        self.0
            .qualified_bin_tree_leaf
            .read(&GemContract::scoped(self.1, key))
    }
    fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .qualified_bin_tree_leaf
            .write(&GemContract::scoped(self.1, key), value)
    }
}

impl BinTreeStorage for CurrencyBins<'_, '_> {
    fn read_root(&self) -> Result<U256> {
        self.0.bin_tree_root.read(&self.1)
    }
    fn write_root(&self, value: U256) -> Result<()> {
        self.0.bin_tree_root.write(&self.1, value)
    }
    fn read_mid(&self, key: u32) -> Result<U256> {
        self.0.bin_tree_mid.read(&GemContract::scoped(self.1, key))
    }
    fn write_mid(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .bin_tree_mid
            .write(&GemContract::scoped(self.1, key), value)
    }
    fn read_leaf(&self, key: u32) -> Result<U256> {
        self.0.bin_tree_leaf.read(&GemContract::scoped(self.1, key))
    }
    fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .bin_tree_leaf
            .write(&GemContract::scoped(self.1, key), value)
    }
}
