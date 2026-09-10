use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_intex::{SeriesId, SERIES_ID_LEN};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::GEM_FACTORY_ADDRESS;
use outbe_primitives::error::Result;

use crate::constants::MAX_POSITION_EXPIRIES_PER_RUN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GemTypes {
    Genesis = 0,
    Validator = 1,
    Sra = 2,
    Wallet = 3,
    Cca = 4,
    Merchant = 5,
}

/// A merchant's parked-Intex position: the pool of Promis capacity from which
/// Merchant gems are issued. Modeled as a single-owner, non-transferable NFT
/// (owner = `merchant`), keyed by `position_id`. `merchant == 0` means "no
/// position".
#[storage_record(exists_field = merchant)]
pub struct GemPosition {
    #[key]
    pub position_id: U256,

    #[attribute(order = 0)]
    pub merchant: Address,

    #[attribute(order = 1)]
    pub source_intex_id: SeriesId,

    /// Remaining Promis capacity; drains by `promis_load` on each issue.
    #[attribute(order = 2)]
    pub remaining_capacity: U256,

    /// Snapshot of the parked Intex entry/floor, used as issuance lower bounds.
    #[attribute(order = 3)]
    pub source_entry_price: U256,

    #[attribute(order = 4)]
    pub source_floor_price: U256,

    #[attribute(order = 5)]
    pub issuance_currency: u16,

    #[attribute(order = 6)]
    pub reference_currency: u16,

    #[attribute(order = 7)]
    pub parked_at: u64,

    /// Deadline snapshotted from the profile at parking, so a later profile
    /// change cannot retroactively expire positions already in the queue.
    #[attribute(order = 8)]
    pub expires_at: u64,
}

#[storage_schema]
#[contract(addr = GEM_FACTORY_ADDRESS)]
pub struct GemFactoryContract {
    #[attribute(order = 0)]
    pub total_gems_issued: outbe_primitives::storage::dsl::Value<U256>,

    #[attribute(order = 1)]
    pub total_intex_parked: outbe_primitives::storage::dsl::Value<U256>,

    #[attribute(order = 2)]
    pub positions: outbe_primitives::storage::dsl::Map<U256, GemPosition>,

    // --- Position-NFT owner index (per-merchant enumeration) ---
    #[attribute(order = 3)]
    pub position_owner_counts: outbe_primitives::storage::dsl::Map<Address, u32>,

    #[attribute(order = 4)]
    pub position_owner_ids: outbe_primitives::storage::dsl::Map<B256, U256>,

    // --- Live positions, in parking order: nothing else enumerates them, the
    // owner index answers "whose", not "which are alive".
    #[attribute(order = 5)]
    pub live_head: outbe_primitives::storage::dsl::Value<u32>,
    #[attribute(order = 6)]
    pub live_tail: outbe_primitives::storage::dsl::Value<u32>,
    /// Queue index -> position id; zero marks a slot already taken.
    #[attribute(order = 7)]
    pub live_queue_at: outbe_primitives::storage::dsl::Map<u32, U256>,
    #[attribute(order = 8)]
    pub live_queue_index: outbe_primitives::storage::dsl::Map<U256, u32>,
}

impl GemFactoryContract<'_> {
    pub(crate) fn push_live_position(&mut self, position_id: U256) -> Result<()> {
        let tail = self.live_tail.read()?;
        self.live_queue_at.write(&tail, position_id)?;
        self.live_queue_index.write(&position_id, tail)?;
        self.live_tail.write(tail.saturating_add(1))
    }

    pub(crate) fn remove_live_position(&mut self, position_id: U256) -> Result<()> {
        let index = self.live_queue_index.read(&position_id)?;
        // A position that never queued reads index 0; only clear a slot it owns.
        if self.live_queue_at.read(&index)? == position_id {
            self.live_queue_at.clear(&index)?;
        }
        self.live_queue_index.clear(&position_id)
    }

    pub(crate) fn live_queue_slot(&self, index: u32) -> Result<Option<U256>> {
        let position_id = self.live_queue_at.read(&index)?;
        Ok((!position_id.is_zero()).then_some(position_id))
    }

    pub(crate) fn compact_live_queue(&mut self) -> Result<()> {
        let tail = self.live_tail.read()?;
        let mut head = self.live_head.read()?;
        let limit = tail.min(head.saturating_add(MAX_POSITION_EXPIRIES_PER_RUN));
        while head < limit && self.live_queue_at.read(&head)?.is_zero() {
            head = head.saturating_add(1);
        }
        if head >= tail {
            self.live_head.write(0)?;
            return self.live_tail.write(0);
        }
        self.live_head.write(head)
    }

    /// `position_id = keccak256("gemposition" || source_intex_id_be || block_number_be)`.
    /// A source Intex is parked once, so `source_intex_id` alone disambiguates.
    pub fn generate_position_id(source_intex_id: SeriesId, block_number: u64) -> U256 {
        let mut buf = [0u8; 11 + SERIES_ID_LEN + 8];
        buf[0..11].copy_from_slice(b"gemposition");
        buf[11..11 + SERIES_ID_LEN].copy_from_slice(source_intex_id.as_bytes());
        buf[11 + SERIES_ID_LEN..].copy_from_slice(&block_number.to_be_bytes());
        U256::from_be_bytes(keccak256(buf).0)
    }
}
