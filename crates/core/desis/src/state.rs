//! Local storage helpers for the Desis module.

use alloy_primitives::U256;
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::schema::{
    AuctionConfig, AuctionStage, BidData, DesisContract, IntexCallTrigger, ReferenceCurrencyPrice,
};

impl DesisContract<'_> {
    // --- AuctionStage ---

    pub(crate) fn read_stage(&self, worldwide_day: WorldwideDay) -> Result<AuctionStage> {
        let raw = self.auction_stage.read(&worldwide_day)?;
        AuctionStage::from_u8(raw).map_err(Into::into)
    }

    pub(crate) fn write_stage(
        &self,
        worldwide_day: WorldwideDay,
        stage: AuctionStage,
    ) -> Result<()> {
        self.auction_stage.write(&worldwide_day, stage as u8)
    }

    // --- AuctionConfig ---

    pub(crate) fn read_auction_config(&self, worldwide_day: WorldwideDay) -> Result<AuctionConfig> {
        let promis_load_minor = self.config_promis_load_minor.read(&worldwide_day)?;
        Ok(AuctionConfig {
            promis_load_minor: u128::try_from(promis_load_minor)
                .map_err(|_| crate::DesisError::InvalidWorldwideDay(worldwide_day))?,
            call_trigger: IntexCallTrigger {
                call_window: self.config_call_window.read(&worldwide_day)?,
                call_threshold: self.config_call_threshold.read(&worldwide_day)?,
                call_notice_period: self.config_call_notice_period.read(&worldwide_day)?,
            },
            min_intex_bid_rate: self.config_min_bid_rate.read(&worldwide_day)?,
            min_intex_bid_quantity: self.config_min_bid_quantity.read(&worldwide_day)? as u16,
            commit_bond_minor: u128::try_from(self.config_commit_bond_minor.read(&worldwide_day)?)
                .map_err(|_| crate::DesisError::InvalidWorldwideDay(worldwide_day))?,
            reference_prices: self.read_reference_prices(worldwide_day)?,
        })
    }

    pub(crate) fn read_reference_prices(
        &self,
        worldwide_day: WorldwideDay,
    ) -> Result<Vec<ReferenceCurrencyPrice>> {
        let count = self.reference_price_count.read(&worldwide_day)?;
        let mut rows = Vec::with_capacity(count as usize);
        for index in 0..count {
            let key = Self::reference_price_key(worldwide_day, index);
            rows.push(ReferenceCurrencyPrice {
                iso_code: self.reference_price_iso.read(&key)? as u16,
                entry_price_minor: self.reference_price_entry.read(&key)?,
            });
        }
        Ok(rows)
    }

    pub(crate) fn write_auction_config(
        &self,
        worldwide_day: WorldwideDay,
        cfg: &AuctionConfig,
    ) -> Result<()> {
        self.config_promis_load_minor
            .write(&worldwide_day, U256::from(cfg.promis_load_minor))?;
        self.config_call_window
            .write(&worldwide_day, cfg.call_trigger.call_window)?;
        self.config_call_threshold
            .write(&worldwide_day, cfg.call_trigger.call_threshold)?;
        self.config_call_notice_period
            .write(&worldwide_day, cfg.call_trigger.call_notice_period)?;
        self.config_min_bid_rate
            .write(&worldwide_day, cfg.min_intex_bid_rate)?;
        self.config_min_bid_quantity
            .write(&worldwide_day, u32::from(cfg.min_intex_bid_quantity))?;
        self.config_commit_bond_minor
            .write(&worldwide_day, U256::from(cfg.commit_bond_minor))?;
        self.reference_price_count
            .write(&worldwide_day, cfg.reference_prices.len() as u32)?;
        for (index, row) in cfg.reference_prices.iter().enumerate() {
            let key = Self::reference_price_key(worldwide_day, index as u32);
            self.reference_price_iso
                .write(&key, u32::from(row.iso_code))?;
            self.reference_price_entry
                .write(&key, row.entry_price_minor)?;
        }
        Ok(())
    }

    // --- bid storage (per chain) ---

    pub(crate) fn append_bid(
        &self,
        worldwide_day: WorldwideDay,
        chain_id: u32,
        bid: &BidData,
    ) -> Result<u32> {
        let chain_key = Self::chain_key(worldwide_day, chain_id);
        let index = self.chain_bid_count.read(&chain_key)?;
        self.write_bid_at(worldwide_day, chain_id, index, bid)?;
        self.chain_bid_count.write(&chain_key, index + 1)?;
        let day_count = self.day_bid_count.read(&worldwide_day)?;
        self.day_bid_count.write(&worldwide_day, day_count + 1)?;
        Ok(index)
    }

    pub(crate) fn read_bid_at(
        &self,
        worldwide_day: WorldwideDay,
        chain_id: u32,
        index: u32,
    ) -> Result<BidData> {
        let key = Self::bid_key(worldwide_day, chain_id, index);
        let packed = self.bid_packed.read(&key)?;
        let limbs = packed.as_limbs();
        Ok(BidData {
            bidder_address: self.bid_bidder.read(&key)?,
            intex_bid_rate: limbs[0] as u32,
            timestamp: limbs[1] as u32,
            intex_quantity: (limbs[1] >> 32) as u16,
            issuance_currency: (limbs[1] >> 48) as u16,
            reference_currency: limbs[2] as u16,
        })
    }

    fn write_bid_at(
        &self,
        worldwide_day: WorldwideDay,
        chain_id: u32,
        index: u32,
        bid: &BidData,
    ) -> Result<()> {
        let key = Self::bid_key(worldwide_day, chain_id, index);
        self.bid_bidder.write(&key, bid.bidder_address)?;
        // The currency pair rides the free limbs of the same word: no new map and no
        // attribute-order change.
        let packed = U256::from_limbs([
            u64::from(bid.intex_bid_rate),
            (u64::from(bid.issuance_currency) << 48)
                | (u64::from(bid.intex_quantity) << 32)
                | u64::from(bid.timestamp),
            u64::from(bid.reference_currency),
            0,
        ]);
        self.bid_packed.write(&key, packed)
    }

    /// Load the chains' bids into memory, tagged with their source chain.
    pub(crate) fn read_chains_bids(
        &self,
        worldwide_day: WorldwideDay,
        chain_ids: &[u32],
    ) -> Result<Vec<(u32, BidData)>> {
        let mut bids = Vec::new();
        for &chain_id in chain_ids {
            let count = self
                .chain_bid_count
                .read(&Self::chain_key(worldwide_day, chain_id))?;
            for i in 0..count {
                bids.push((chain_id, self.read_bid_at(worldwide_day, chain_id, i)?));
            }
        }
        Ok(bids)
    }

    /// Drop the chain's bids for a generation supersede or post-clear cleanup.
    pub(crate) fn reset_chain_intake(
        &self,
        worldwide_day: WorldwideDay,
        chain_id: u32,
    ) -> Result<()> {
        let key = Self::chain_key(worldwide_day, chain_id);
        let chain_count = self.chain_bid_count.read(&key)?;
        let day_count = self.day_bid_count.read(&worldwide_day)?;
        self.day_bid_count
            .write(&worldwide_day, day_count.saturating_sub(chain_count))?;
        self.chain_bid_count.write(&key, 0)?;
        self.chain_total_batches.write(&key, 0)?;
        self.chain_arrived_mask.write(&key, U256::ZERO)?;
        self.chain_done.write(&key, 0u8)?;
        self.chain_done_batches.write(&key, 0)?;
        self.chain_done_bids.write(&key, 0)
    }

    // --- clearing fan-in gate (dense active set) ---

    /// Append a day to the gate-active set (idempotent).
    pub(crate) fn push_gate_active(&mut self, worldwide_day: WorldwideDay) -> Result<()> {
        if self.gate_active_slot.read(&worldwide_day)? != 0 {
            return Ok(());
        }
        let count = self.gate_active_count.read()?;
        self.gate_active_at.write(&count, worldwide_day.value())?;
        // store index + 1 so that 0 unambiguously means "absent".
        self.gate_active_slot.write(&worldwide_day, count + 1)?;
        self.gate_active_count.write(count + 1)?;
        Ok(())
    }

    /// Remove a day from the gate-active set via swap-remove (idempotent).
    pub(crate) fn remove_gate_active(&mut self, worldwide_day: WorldwideDay) -> Result<()> {
        let slot1 = self.gate_active_slot.read(&worldwide_day)?;
        if slot1 == 0 {
            return Ok(());
        }
        let idx = slot1 - 1;
        let last = self.gate_active_count.read()? - 1;
        if idx != last {
            let last_day: WorldwideDay = self.gate_active_at.read(&last)?.into();
            self.gate_active_at.write(&idx, last_day.value())?;
            self.gate_active_slot.write(&last_day, idx + 1)?;
        }
        self.gate_active_at.clear(&last)?;
        self.gate_active_slot.clear(&worldwide_day)?;
        self.gate_active_count.write(last)?;
        Ok(())
    }

    /// Append a day to the schedule-active set (idempotent).
    pub(crate) fn push_sched_active(&mut self, worldwide_day: WorldwideDay) -> Result<()> {
        if self.sched_active_slot.read(&worldwide_day)? != 0 {
            return Ok(());
        }
        let count = self.sched_active_count.read()?;
        self.sched_active_at.write(&count, worldwide_day.value())?;
        // store index + 1 so that 0 unambiguously means "absent".
        self.sched_active_slot.write(&worldwide_day, count + 1)?;
        self.sched_active_count.write(count + 1)?;
        Ok(())
    }

    /// Remove a day from the schedule-active set via swap-remove (idempotent).
    pub(crate) fn remove_sched_active(&mut self, worldwide_day: WorldwideDay) -> Result<()> {
        let slot1 = self.sched_active_slot.read(&worldwide_day)?;
        if slot1 == 0 {
            return Ok(());
        }
        let idx = slot1 - 1;
        let last = self.sched_active_count.read()? - 1;
        if idx != last {
            let last_day: WorldwideDay = self.sched_active_at.read(&last)?.into();
            self.sched_active_at.write(&idx, last_day.value())?;
            self.sched_active_slot.write(&last_day, idx + 1)?;
        }
        self.sched_active_at.clear(&last)?;
        self.sched_active_slot.clear(&worldwide_day)?;
        self.sched_active_count.write(last)?;
        Ok(())
    }

    // --- last cleared series ---

    pub(crate) fn read_last_cleared_worldwide_day(&self) -> Result<WorldwideDay> {
        self.last_cleared_worldwide_day.read()
    }

    pub(crate) fn write_last_cleared_worldwide_day(
        &self,
        worldwide_day: WorldwideDay,
    ) -> Result<()> {
        self.last_cleared_worldwide_day.write(worldwide_day)
    }

    pub(crate) fn read_last_clearing_issued_count(&self) -> Result<u32> {
        self.last_clearing_issued_count.read()
    }

    pub(crate) fn write_last_clearing_issued_count(&self, count: u32) -> Result<()> {
        self.last_clearing_issued_count.write(count)
    }
}
