//! Local storage helpers for the IntexFactory module (settlement bookkeeping
//! + the unqualified-series bin index). Orchestration lives in `runtime.rs`.

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_intex::SeriesId;
use outbe_primitives::error::Result;
use outbe_primitives::math::{
    reference_price,
    tree_math::{self, BinTreeStorage},
};
use outbe_primitives::storage::dsl::Map;
use outbe_primitives::storage::types::Storable;
use outbe_primitives::time::{WorldwideDay, SECONDS_PER_DAY};

use crate::constants::BIN_STEP_BP;
use crate::errors::IntexFactoryError;
use crate::schema::IntexFactoryContract;

impl IntexFactoryContract<'_> {
    // --- authorizedSettler ---

    pub(crate) fn read_authorized_settler(
        &self,
        holder: Address,
        series_id: SeriesId,
    ) -> Result<Address> {
        let key = Self::authorized_settler_key(holder, series_id);
        self.authorized_settler.read(&key)
    }

    pub(crate) fn write_authorized_settler(
        &mut self,
        holder: Address,
        series_id: SeriesId,
        settler: Address,
    ) -> Result<()> {
        let key = Self::authorized_settler_key(holder, series_id);
        self.authorized_settler.write(&key, settler)
    }

    // --- mineSeq ---

    pub(crate) fn read_mine_seq(&self, series_id: SeriesId, holder: Address) -> Result<u32> {
        let key = Self::mine_seq_key(series_id, holder);
        self.mine_seq.read(&key)
    }

    pub(crate) fn write_mine_seq(
        &mut self,
        series_id: SeriesId,
        holder: Address,
        value: u32,
    ) -> Result<()> {
        let key = Self::mine_seq_key(series_id, holder);
        self.mine_seq.write(&key, value)
    }

    // --- unqualified-series bin index (by floor_price_minor) ---

    /// Map a six-decimal COEN/ISO price to its LB-style bin id (bounded by the codec).
    pub fn price_to_bin(price: U256) -> Result<u32> {
        if price.is_zero() {
            return Ok(0);
        }
        reference_price::coen_iso_price_to_bin_id(price, BIN_STEP_BP)
    }

    pub(crate) fn bin_index_key(reference_currency: u16, bin_id: u32, index: u32) -> B256 {
        let mut buf = [0u8; 10];
        buf[0..2].copy_from_slice(&reference_currency.to_be_bytes());
        buf[2..6].copy_from_slice(&bin_id.to_be_bytes());
        buf[6..10].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    /// Composite key for a group's member list; the layout `bin_index_key` uses,
    /// over a separate column keyed by worldwide day instead of bin id.
    pub(crate) fn group_member_key(
        reference_currency: u16,
        worldwide_day: WorldwideDay,
        index: u32,
    ) -> B256 {
        Self::bin_index_key(reference_currency, worldwide_day.value(), index)
    }

    pub(crate) fn insert_unqualified(
        &mut self,
        series_id: SeriesId,
        reference_currency: u16,
        floor_price: U256,
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(floor_price)?;
        self.unqualified_index(reference_currency).insert(
            &UnqualifiedBinTree(&*self, reference_currency),
            series_id,
            bin_id,
        )
    }

    pub(crate) fn remove_unqualified_group(
        &mut self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<()> {
        self.unqualified_index(reference_currency).remove_group(
            &UnqualifiedBinTree(&*self, reference_currency),
            worldwide_day,
        )
    }

    pub(crate) fn unqualified_groups_in_bin(
        &self,
        reference_currency: u16,
        bin_id: u32,
    ) -> Result<Vec<WorldwideDay>> {
        self.unqualified_index(reference_currency)
            .groups_in_bin(bin_id)
    }

    pub(crate) fn unqualified_group_members(
        &self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<Vec<SeriesId>> {
        self.unqualified_index(reference_currency)
            .members(worldwide_day)
    }

    pub(crate) fn unqualified_group(
        &self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<Group> {
        Ok(Group {
            iso_code: reference_currency,
            worldwide_day,
            members: self.unqualified_group_members(reference_currency, worldwide_day)?,
        })
    }

    /// Widen the currency's stored terms to cover a newly issued series.
    pub(crate) fn widen_call_terms(
        &mut self,
        reference_currency: u16,
        call_window: u32,
        call_threshold: u32,
    ) -> Result<()> {
        let secs_per_day = SECONDS_PER_DAY as u32;
        if call_window > self.max_call_window.read(&reference_currency)? {
            self.max_call_window
                .write(&reference_currency, call_window)?;
        }
        // A threshold under a day can never be met, and would latch the range shut.
        if call_threshold < secs_per_day {
            return Ok(());
        }
        let min = self.min_call_threshold.read(&reference_currency)?;
        if min == 0 || call_threshold < min {
            self.min_call_threshold
                .write(&reference_currency, call_threshold)?;
        }
        Ok(())
    }

    /// Window and threshold, in days, the call scan must search to cover every live
    /// series: the widest of the stored pair and the live profile.
    pub(crate) fn scan_call_terms(
        &self,
        reference_currency: u16,
        live_window: u32,
        live_threshold: u32,
    ) -> Result<(u32, u32)> {
        let secs_per_day = SECONDS_PER_DAY as u32;
        let stored_window = self.max_call_window.read(&reference_currency)?;
        let days = stored_window.max(live_window) / secs_per_day;

        let stored_threshold = self.min_call_threshold.read(&reference_currency)?;
        let threshold = if stored_threshold == 0 {
            live_threshold
        } else {
            stored_threshold.min(live_threshold)
        };
        Ok((days, threshold / secs_per_day))
    }

    // --- qualified-series bin index (by call_price_minor) ---

    pub(crate) fn insert_qualified_group(
        &mut self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
        trigger_price: U256,
        members: &[SeriesId],
    ) -> Result<()> {
        let bin_id = Self::price_to_bin(trigger_price)?;
        self.qualified_index(reference_currency).insert_group(
            &QualifiedBinTree(&*self, reference_currency),
            worldwide_day,
            bin_id,
            members,
        )
    }

    pub(crate) fn remove_qualified_group(
        &mut self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<()> {
        self.qualified_index(reference_currency)
            .remove_group(&QualifiedBinTree(&*self, reference_currency), worldwide_day)
    }

    pub(crate) fn qualified_groups_in_bin(
        &self,
        reference_currency: u16,
        bin_id: u32,
    ) -> Result<Vec<WorldwideDay>> {
        self.qualified_index(reference_currency)
            .groups_in_bin(bin_id)
    }

    pub(crate) fn qualified_group_members(
        &self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<Vec<SeriesId>> {
        self.qualified_index(reference_currency)
            .members(worldwide_day)
    }

    pub(crate) fn qualified_group(
        &self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<Group> {
        Ok(Group {
            iso_code: reference_currency,
            worldwide_day,
            members: self.qualified_group_members(reference_currency, worldwide_day)?,
        })
    }

    // --- called groups awaiting their deadline ---

    /// Park a called group with the members and deadline the expiry sweep needs:
    /// the bin index has just dropped it and nothing else maps (iso, day) -> series.
    pub(crate) fn push_called_group(
        &mut self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
        deadline: u64,
        members: &[SeriesId],
    ) -> Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        let key = Self::scoped(reference_currency, worldwide_day.value());
        // A second push would orphan the first slot and credit the members twice.
        if self.called_group_count.read(&key)? != 0 {
            return Err(IntexFactoryError::GroupAlreadyIndexed {
                iso: reference_currency,
                worldwide_day,
            }
            .into());
        }
        for (index, series_id) in members.iter().enumerate() {
            self.called_group_members.write(
                &Self::group_member_key(reference_currency, worldwide_day, index as u32),
                series_id.to_word(),
            )?;
        }
        self.called_group_count.write(&key, members.len() as u32)?;
        self.called_group_deadline.write(&key, deadline)?;

        let day = Self::deadline_bucket(deadline);
        let slot = self.expiry_bucket_len.read(&day)?;
        self.expiry_bucket_at
            .write(&Self::bucket_slot_key(day, slot), key)?;
        self.expiry_bucket_len.write(&day, slot.saturating_add(1))?;
        self.called_group_slot
            .write(&key, Self::packed_slot(day, slot))?;

        let live = self.expiry_bucket_live.read(&day)?;
        self.expiry_bucket_live
            .write(&day, live.saturating_add(1))?;
        if live == 0 {
            tree_math::add(&ExpiryDayTree(&*self), day)?;
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

    pub(crate) fn expiry_slot(&self, day: u32, slot: u32) -> Result<Option<(u16, WorldwideDay)>> {
        // `scoped` keeps a non-zero ISO code in the high half, so zero cannot collide.
        let key = self
            .expiry_bucket_at
            .read(&Self::bucket_slot_key(day, slot))?;
        Ok((key != 0).then(|| Self::unscoped(key)))
    }

    pub(crate) fn first_expiry_day(&self) -> Result<Option<u32>> {
        tree_math::find_first_left_inclusive(&ExpiryDayTree(self), 0)
    }

    pub(crate) fn called_group(
        &self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<Group> {
        let key = Self::scoped(reference_currency, worldwide_day.value());
        let count = self.called_group_count.read(&key)?;
        let mut members = Vec::with_capacity(count as usize);
        for index in 0..count {
            members.push(SeriesId::from_word(self.called_group_members.read(
                &Self::group_member_key(reference_currency, worldwide_day, index),
            )?));
        }
        Ok(Group {
            iso_code: reference_currency,
            worldwide_day,
            members,
        })
    }

    /// Drop an expired group and free the bucket slot it says it waits in.
    pub(crate) fn remove_called_group(
        &mut self,
        reference_currency: u16,
        worldwide_day: WorldwideDay,
    ) -> Result<()> {
        let key = Self::scoped(reference_currency, worldwide_day.value());
        let count = self.called_group_count.read(&key)?;
        for index in 0..count {
            self.called_group_members.clear(&Self::group_member_key(
                reference_currency,
                worldwide_day,
                index,
            ))?;
        }
        self.called_group_count.clear(&key)?;
        self.called_group_deadline.clear(&key)?;

        let packed = self.called_group_slot.read(&key)?;
        self.called_group_slot.clear(&key)?;
        if packed == 0 {
            return Ok(());
        }
        let (day, slot) = Self::unpack_slot(packed);
        self.release_expiry_slot(day, slot, key)
    }

    /// Drop whatever is left of a bucket the sweep has finished.
    pub(crate) fn force_retire_bucket(&mut self, day: u32) -> Result<u32> {
        let len = self.expiry_bucket_len.read(&day)?;
        let mut dropped = 0u32;
        for slot in 0..len {
            let slot_key = Self::bucket_slot_key(day, slot);
            let key = self.expiry_bucket_at.read(&slot_key)?;
            if key == 0 {
                continue;
            }
            let (iso_code, worldwide_day) = Self::unscoped(key);
            self.remove_called_group(iso_code, worldwide_day)?;
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

    /// Free one bucket slot, retiring the bucket once nothing waits in it.
    pub(crate) fn release_expiry_slot(&mut self, day: u32, slot: u32, key: u64) -> Result<()> {
        let slot_key = Self::bucket_slot_key(day, slot);
        if self.expiry_bucket_at.read(&slot_key)? != key {
            return Ok(());
        }
        self.expiry_bucket_at.clear(&slot_key)?;

        let live = self.expiry_bucket_live.read(&day)?.saturating_sub(1);
        self.expiry_bucket_live.write(&day, live)?;
        if live == 0 {
            self.expiry_bucket_len.clear(&day)?;
            self.expiry_bucket_live.clear(&day)?;
            tree_math::remove(&ExpiryDayTree(&*self), day)?;
            if self.expiry_sweep_day.read()? == day {
                self.expiry_sweep_day.write(0)?;
                self.expiry_cursor.write(0)?;
            }
        }
        Ok(())
    }
}

impl<'storage> IntexFactoryContract<'storage> {
    fn unqualified_index(&self, reference_currency: u16) -> GroupIndex<'storage> {
        GroupIndex {
            bin_count: self.unqualified_bin_count.clone(),
            bin_groups: self.unqualified_bin_groups.clone(),
            group_count: self.unqualified_group_count.clone(),
            group_members: self.unqualified_group_members.clone(),
            group_bin: self.unqualified_group_bin.clone(),
            iso: reference_currency,
        }
    }

    fn qualified_index(&self, reference_currency: u16) -> GroupIndex<'storage> {
        GroupIndex {
            bin_count: self.qualified_bin_count.clone(),
            bin_groups: self.qualified_bin_groups.clone(),
            group_count: self.qualified_group_count.clone(),
            group_members: self.qualified_group_members.clone(),
            group_bin: self.qualified_group_bin.clone(),
            iso: reference_currency,
        }
    }
}

/// One day's series in one reference currency: the unit a lifecycle decision is
/// taken over, since all of them share the inputs it reads.
pub(crate) struct Group {
    pub(crate) iso_code: u16,
    pub(crate) worldwide_day: WorldwideDay,
    pub(crate) members: Vec<SeriesId>,
}

/// One currency's two-level index: price bins hold worldwide-day groups, and
/// each group holds the series that share its decision inputs.
struct GroupIndex<'storage> {
    bin_count: Map<'storage, u64, u32>,
    bin_groups: Map<'storage, B256, u32>,
    group_count: Map<'storage, u64, u32>,
    group_members: Map<'storage, B256, U256>,
    group_bin: Map<'storage, u64, u32>,
    iso: u16,
}

impl GroupIndex<'_> {
    fn group_key(&self, worldwide_day: WorldwideDay) -> u64 {
        IntexFactoryContract::scoped(self.iso, worldwide_day.value())
    }

    fn member_key(&self, worldwide_day: WorldwideDay, index: u32) -> B256 {
        IntexFactoryContract::group_member_key(self.iso, worldwide_day, index)
    }

    fn bin_key(&self, bin_id: u32, index: u32) -> B256 {
        IntexFactoryContract::bin_index_key(self.iso, bin_id, index)
    }

    fn groups_in_bin(&self, bin_id: u32) -> Result<Vec<WorldwideDay>> {
        let count = self
            .bin_count
            .read(&IntexFactoryContract::scoped(self.iso, bin_id))?;
        let mut groups = Vec::with_capacity(count as usize);
        for index in 0..count {
            groups.push(WorldwideDay::new(
                self.bin_groups.read(&self.bin_key(bin_id, index))?,
            ));
        }
        Ok(groups)
    }

    fn members(&self, worldwide_day: WorldwideDay) -> Result<Vec<SeriesId>> {
        let count = self.group_count.read(&self.group_key(worldwide_day))?;
        let mut members = Vec::with_capacity(count as usize);
        for index in 0..count {
            members.push(SeriesId::from_word(
                self.group_members
                    .read(&self.member_key(worldwide_day, index))?,
            ));
        }
        Ok(members)
    }

    /// Append `series_id` to its day's group, creating it in `bin_id` when first.
    /// A member priced into another bin would split the group's decision: refused.
    fn insert(&self, tree: &impl BinTreeStorage, series_id: SeriesId, bin_id: u32) -> Result<()> {
        let worldwide_day = series_id.worldwide_day();
        let group_key = self.group_key(worldwide_day);
        let count = self.group_count.read(&group_key)?;
        if count == 0 {
            self.attach(tree, worldwide_day, bin_id)?;
        } else {
            let expected = self.group_bin.read(&group_key)?;
            if expected != bin_id {
                return Err(IntexFactoryError::GroupBinMismatch {
                    iso: self.iso,
                    worldwide_day,
                    expected,
                    got: bin_id,
                }
                .into());
            }
        }
        self.group_members
            .write(&self.member_key(worldwide_day, count), series_id.to_word())?;
        self.group_count.write(&group_key, count + 1)?;
        Ok(())
    }

    /// Index a whole group at once: its members and its place in `bin_id`.
    fn insert_group(
        &self,
        tree: &impl BinTreeStorage,
        worldwide_day: WorldwideDay,
        bin_id: u32,
        members: &[SeriesId],
    ) -> Result<()> {
        if members.is_empty() {
            return Ok(());
        }
        let group_key = self.group_key(worldwide_day);
        if self.group_count.read(&group_key)? != 0 {
            return Err(IntexFactoryError::GroupAlreadyIndexed {
                iso: self.iso,
                worldwide_day,
            }
            .into());
        }
        self.attach(tree, worldwide_day, bin_id)?;
        for (index, series_id) in members.iter().enumerate() {
            self.group_members.write(
                &self.member_key(worldwide_day, index as u32),
                series_id.to_word(),
            )?;
        }
        self.group_count.write(&group_key, members.len() as u32)?;
        Ok(())
    }

    /// Drop a whole group: its members and its place in the bin.
    fn remove_group(&self, tree: &impl BinTreeStorage, worldwide_day: WorldwideDay) -> Result<()> {
        let group_key = self.group_key(worldwide_day);
        let count = self.group_count.read(&group_key)?;
        if count == 0 {
            return Ok(());
        }
        for index in 0..count {
            self.group_members
                .clear(&self.member_key(worldwide_day, index))?;
        }
        self.group_count.write(&group_key, 0)?;
        let bin_id = self.group_bin.read(&group_key)?;
        self.detach(tree, worldwide_day, bin_id)
    }

    /// Register the group in `bin_id` and set the bin's trie bit.
    fn attach(
        &self,
        tree: &impl BinTreeStorage,
        worldwide_day: WorldwideDay,
        bin_id: u32,
    ) -> Result<()> {
        let scoped = IntexFactoryContract::scoped(self.iso, bin_id);
        let count = self.bin_count.read(&scoped)?;
        self.bin_groups
            .write(&self.bin_key(bin_id, count), worldwide_day.value())?;
        self.bin_count.write(&scoped, count + 1)?;
        self.group_bin
            .write(&self.group_key(worldwide_day), bin_id)?;
        tree_math::add(tree, bin_id)?;
        Ok(())
    }

    /// Drop the group's bin entry (swap-and-pop); clear the trie bit when the bin
    /// empties.
    fn detach(
        &self,
        tree: &impl BinTreeStorage,
        worldwide_day: WorldwideDay,
        bin_id: u32,
    ) -> Result<()> {
        let scoped = IntexFactoryContract::scoped(self.iso, bin_id);
        let count = self.bin_count.read(&scoped)?;
        if count == 0 {
            return Ok(());
        }
        let mut found: Option<u32> = None;
        for index in 0..count {
            if self.bin_groups.read(&self.bin_key(bin_id, index))? == worldwide_day.value() {
                found = Some(index);
                break;
            }
        }
        let Some(idx) = found else {
            return Ok(());
        };
        let last = count - 1;
        if idx != last {
            let last_day = self.bin_groups.read(&self.bin_key(bin_id, last))?;
            self.bin_groups
                .write(&self.bin_key(bin_id, idx), last_day)?;
        }
        self.bin_groups.clear(&self.bin_key(bin_id, last))?;
        self.bin_count.write(&scoped, last)?;
        self.group_bin.clear(&self.group_key(worldwide_day))?;
        if last == 0 {
            tree_math::remove(tree, bin_id)?;
        }
        Ok(())
    }
}

// Adapters between one currency's slice of a bin-tree's columns and `BinTreeStorage`.
// Construct inline at each `tree_math` call, so it never conflicts with a `&mut` borrow.

/// The unqualified (floor-price) trie of one reference currency.
pub(crate) struct UnqualifiedBinTree<'a, 'b>(
    pub(crate) &'a IntexFactoryContract<'b>,
    pub(crate) u16,
);

impl BinTreeStorage for UnqualifiedBinTree<'_, '_> {
    fn read_root(&self) -> Result<U256> {
        self.0.bin_tree_root.read(&self.1)
    }
    fn write_root(&self, value: U256) -> Result<()> {
        self.0.bin_tree_root.write(&self.1, value)
    }
    fn read_mid(&self, key: u32) -> Result<U256> {
        self.0
            .bin_tree_mid
            .read(&IntexFactoryContract::scoped(self.1, key))
    }
    fn write_mid(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .bin_tree_mid
            .write(&IntexFactoryContract::scoped(self.1, key), value)
    }
    fn read_leaf(&self, key: u32) -> Result<U256> {
        self.0
            .bin_tree_leaf
            .read(&IntexFactoryContract::scoped(self.1, key))
    }
    fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .bin_tree_leaf
            .write(&IntexFactoryContract::scoped(self.1, key), value)
    }
}

/// The qualified (call-trigger) trie of one reference currency.
/// Buckets holding a called group whose settlement window has not closed yet.
pub(crate) struct ExpiryDayTree<'a, 'b>(pub(crate) &'a IntexFactoryContract<'b>);

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

pub(crate) struct QualifiedBinTree<'a, 'b>(pub(crate) &'a IntexFactoryContract<'b>, pub(crate) u16);

impl BinTreeStorage for QualifiedBinTree<'_, '_> {
    fn read_root(&self) -> Result<U256> {
        self.0.qualified_bin_tree_root.read(&self.1)
    }
    fn write_root(&self, value: U256) -> Result<()> {
        self.0.qualified_bin_tree_root.write(&self.1, value)
    }
    fn read_mid(&self, key: u32) -> Result<U256> {
        self.0
            .qualified_bin_tree_mid
            .read(&IntexFactoryContract::scoped(self.1, key))
    }
    fn write_mid(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .qualified_bin_tree_mid
            .write(&IntexFactoryContract::scoped(self.1, key), value)
    }
    fn read_leaf(&self, key: u32) -> Result<U256> {
        self.0
            .qualified_bin_tree_leaf
            .read(&IntexFactoryContract::scoped(self.1, key))
    }
    fn write_leaf(&self, key: u32, value: U256) -> Result<()> {
        self.0
            .qualified_bin_tree_leaf
            .write(&IntexFactoryContract::scoped(self.1, key), value)
    }
}
