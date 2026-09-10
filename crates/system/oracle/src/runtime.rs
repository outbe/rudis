//! Oracle business logic: vote submission, VWAP/TWAP computation, WorldwideDay
//! and UTC-day finalization, and the OCOMP projection profile.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::addresses::ORACLE_ADDRESS;
use outbe_primitives::error::Result;
use outbe_primitives::math::reference_price::is_coen_iso_market;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::time::{date_key_to_utc_timestamp, SECONDS_PER_DAY};
use std::collections::BTreeSet;

use crate::constants::{zero_volume_weight, DAY_TYPE_PAIR};
use crate::errors::{OracleError, OracleOcompError};
use crate::precompile::IOracle;
use crate::schema::OracleContract;

/// `(pairs, values, lookbacks)` - one row per active vote-target pair, each
/// carrying the orientation it was registered in.
type PairSeries = (Vec<AddressPair>, Vec<U256>, Vec<u64>);

#[derive(Clone, Copy, Default)]
struct VwapAccumulator {
    price_volume: U256,
    volume: U256,
}

impl VwapAccumulator {
    fn add(
        &mut self,
        pair: AddressPair,
        price_volume: U256,
        volume: U256,
        price_volume_error: &'static str,
        volume_error: &'static str,
    ) -> Result<()> {
        if is_coen_iso_market(pair) {
            self.price_volume = self
                .price_volume
                .checked_add(price_volume)
                .ok_or(OracleError::VwapOverflow(price_volume_error))?;
            self.volume = self
                .volume
                .checked_add(volume)
                .ok_or(OracleError::VwapOverflow(volume_error))?;
        } else {
            self.price_volume = self.price_volume.saturating_add(price_volume);
            self.volume = self.volume.saturating_add(volume);
        }
        Ok(())
    }

    fn finish(self) -> Option<U256> {
        (!self.volume.is_zero()).then(|| self.price_volume / self.volume)
    }
}

impl OracleContract<'_> {
    /// Initializes the fixed OCOMP Oracle projection for a fresh devnet.
    pub fn initialize_fresh_ocomp_profile(&mut self) -> Result<()> {
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            if self.pair_index_of(DAY_TYPE_PAIR)? == 0 {
                return Err(OracleOcompError::DayTypePairNotRegistered.into());
            }

            if self.ocomp_profile_ready.read()? {
                if self.ocomp_state_version.read()? == 0 {
                    return Err(OracleOcompError::ProfileReadyWithZeroVersion.into());
                }
                return Ok(());
            }
            if self.ocomp_state_version.read()? != 0 {
                return Err(OracleOcompError::PartialPreForkState.into());
            }

            self.ocomp_state_version.write(1)?;
            self.ocomp_profile_ready.write(true)
        })
    }

    /// Reserves the next OCOMP-visible Oracle version before its owner writes.
    ///
    /// Returning `None` keeps every historical pre-fork mutation byte-for-byte
    /// inert. Overflow is rejected before any related owner state changes.
    pub(crate) fn next_ocomp_state_version(&self) -> Result<Option<u64>> {
        if !self.ocomp_profile_ready.read()? {
            return Ok(None);
        }
        let current = self.ocomp_state_version.read()?;
        if current == 0 {
            return Err(OracleOcompError::StateVersionZero.into());
        }
        current
            .checked_add(1)
            .map(Some)
            .ok_or_else(|| OracleOcompError::StateVersionOverflow.into())
    }

    pub(crate) fn commit_ocomp_state_version(&self, next: Option<u64>) -> Result<()> {
        if let Some(version) = next {
            self.ocomp_state_version.write(version)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Vote Submission
    // -----------------------------------------------------------------------

    /// Submits an aggregate oracle vote on behalf of a validator.
    ///
    /// The caller must be the validator itself or a delegated feeder.
    /// Each tuple contains (base, quote, rate, volume) for one pair, quoted in
    /// the direction the pair was registered in.
    pub fn submit_vote(
        &mut self,
        caller: Address,
        tuples: &[(Address, Address, U256, U256)],
    ) -> Result<Address> {
        let validator = self.resolve_validator_for_feeder(caller)?;

        // Validate tuple count: cannot exceed active pair count
        let pair_count = self.pair_count.read()?;
        if tuples.len() as u32 > pair_count {
            return Err(OracleError::VoteTupleCountExceedsPairCount.into());
        }

        // Resolve every quoted pair up front. `require_pair` rejects an
        // unregistered pair and one quoted against the registered direction -
        // the rate is a bare scalar, so a flipped quote would otherwise feed an
        // uninverted price into the tally median with nothing downstream able to
        // notice.
        let mut resolved = Vec::with_capacity(tuples.len());
        for (base, quote, _, _) in tuples {
            resolved.push(self.require_pair_from(*base, *quote)?);
        }

        // Check for duplicate pairs in the submission. Kept separate from the
        // vote-target loop below so the revert precedence for a submission that
        // is both duplicated and untargeted stays unchanged.
        let mut seen = BTreeSet::new();
        for pair in &resolved {
            if !seen.insert(*pair) {
                return Err(OracleError::DuplicatePairInVote.into());
            }
        }

        // Verify all pairs are vote targets
        for pair in &resolved {
            let is_target = self.vote_target.read(pair)?;
            if !is_target {
                return Err(OracleError::PairNotVoteTarget.into());
            }
        }

        // Check if already voted this period
        let already_voted = self.vote_exists.read(&validator)?;
        if already_voted {
            return Err(OracleError::AlreadyVotedThisPeriod.into());
        }

        // Mark as voted FIRST to prevent concurrent overwrite (ORC-AUD-037).
        // EVM executes transactions sequentially within a block, so a second
        // submitVote TX in the same block sees this flag immediately.
        self.vote_exists.write(&validator, true)?;

        // Store vote tuples
        let tuple_count = tuples.len() as u32;
        self.vote_tuple_count.write(&validator, tuple_count)?;

        let pair_map = self.vote_pair.get_nested(&validator);
        let rate_map = self.vote_rate.get_nested(&validator);
        let volume_map = self.vote_volume.get_nested(&validator);

        // Store the pairs `require_pair` already resolved rather than re-packing
        // the raw tuples, so what lands in storage is exactly what was validated.
        for (i, (pair, (_, _, rate, volume))) in resolved.iter().zip(tuples).enumerate() {
            let idx = i as u32;
            pair_map.write_pair(&idx, *pair)?;
            rate_map.write(&idx, *rate)?;
            volume_map.write(&idx, *volume)?;
        }

        // Add to voter list for tally iteration
        self.voter_list.push(validator)?;

        Ok(validator)
    }

    fn add_daily_aggregates(
        &self,
        pair: AddressPair,
        start_time: u64,
        end_time: u64,
        total: &mut VwapAccumulator,
    ) -> Result<()> {
        let day_pv = self.daily_pv_sum.get_nested(&pair);
        let day_vol = self.daily_vol_sum.get_nested(&pair);
        let mut day = start_time;
        while day < end_time {
            let pv = day_pv.read(&day)?;
            let volume = day_vol.read(&day)?;
            if !volume.is_zero() {
                total.add(
                    pair,
                    pv,
                    volume,
                    "daily sum accumulation",
                    "daily volume sum",
                )?;
            }
            day = day
                .checked_add(SECONDS_PER_DAY)
                .ok_or(OracleError::InvalidVwapRange)?;
        }
        Ok(())
    }

    fn add_raw_snapshots(
        &self,
        pair: AddressPair,
        start_time: u64,
        end_time: u64,
        total: &mut VwapAccumulator,
    ) -> Result<()> {
        if start_time >= end_time {
            return Ok(());
        }
        let write_idx = self.snapshot_write_idx.read()?;
        let oldest_idx = self.snapshot_oldest_idx.read()?;
        if write_idx <= oldest_idx {
            if oldest_idx > 0 {
                return Err(OracleError::NoVwapData.into());
            }
            return Ok(());
        }
        if oldest_idx > 0 && start_time < self.snapshot_timestamp.read(&oldest_idx)? {
            return Err(OracleError::NoVwapData.into());
        }

        let range_start = self.binary_search_snapshot_idx(start_time, oldest_idx, write_idx)?;
        let range_end = self.binary_search_snapshot_idx(end_time, oldest_idx, write_idx)?;
        for idx in range_start..range_end {
            let pair_count = self.snapshot_pair_count.read(&idx)?;
            let pair_map = self.snapshot_pair.get_nested(&idx);
            let rate_map = self.snapshot_rate.get_nested(&idx);
            let volume_map = self.snapshot_volume.get_nested(&idx);
            for entry in 0..pair_count {
                if !pair_map.read_pair(&entry)?.same_market(&pair) {
                    continue;
                }
                let rate = rate_map.read(&entry)?;
                let stored_volume = volume_map.read(&entry)?;
                let volume = if stored_volume.is_zero() {
                    zero_volume_weight(pair)
                } else {
                    stored_volume
                };
                let price_volume = rate
                    .checked_mul(volume)
                    .ok_or(OracleError::VwapOverflow("rate * volume"))?;
                total.add(pair, price_volume, volume, "sum accumulation", "volume sum")?;
                break;
            }
        }
        Ok(())
    }

    /// Calculates VWAP for a specific pair over a time range.
    ///
    /// VWAP = sum(price_i * volume_i) / sum(volume_i)
    /// Values remain in the pair's registered scale.
    pub fn calculate_vwap(
        &self,
        pair: AddressPair,
        start_time: u64,
        end_time: u64,
    ) -> Result<U256> {
        self.try_calculate_vwap(pair, start_time, end_time)?
            .ok_or_else(|| OracleError::NoVwapData.into())
    }

    /// [`Self::calculate_vwap`] with "the window held no samples" as `Ok(None)`.
    ///
    /// Callers that skip empty pairs rather than reverting route through this,
    /// so no code path has to recognise the empty case by its revert message.
    pub(crate) fn try_calculate_vwap(
        &self,
        pair: AddressPair,
        start_time: u64,
        end_time: u64,
    ) -> Result<Option<U256>> {
        if start_time >= end_time {
            return Err(OracleError::InvalidVwapRange.into());
        }
        let first_full_day = if start_time.is_multiple_of(SECONDS_PER_DAY) {
            start_time
        } else {
            start_time
                .checked_add(SECONDS_PER_DAY - start_time % SECONDS_PER_DAY)
                .ok_or(OracleError::InvalidVwapRange)?
        };
        let complete_days_end = end_time - end_time % SECONDS_PER_DAY;
        let mut total = VwapAccumulator::default();
        if first_full_day < complete_days_end {
            self.add_raw_snapshots(pair, start_time, first_full_day, &mut total)?;
            self.add_daily_aggregates(pair, first_full_day, complete_days_end, &mut total)?;
            self.add_raw_snapshots(pair, complete_days_end, end_time, &mut total)?;
        } else {
            self.add_raw_snapshots(pair, start_time, end_time, &mut total)?;
        }
        Ok(total.finish())
    }

    fn try_worldwide_day_vwap(&self, pair: AddressPair, start_time: u64) -> Result<Option<U256>> {
        let suffix_day = start_time - start_time % SECONDS_PER_DAY;
        let full_day = suffix_day
            .checked_add(SECONDS_PER_DAY)
            .ok_or(OracleError::InvalidVwapRange)?;
        let prefix_day = full_day
            .checked_add(SECONDS_PER_DAY)
            .ok_or(OracleError::InvalidVwapRange)?;
        let components = [
            (
                self.wwd_suffix_pv_sum.get_nested(&pair).read(&suffix_day)?,
                self.wwd_suffix_vol_sum
                    .get_nested(&pair)
                    .read(&suffix_day)?,
            ),
            (
                self.daily_pv_sum.get_nested(&pair).read(&full_day)?,
                self.daily_vol_sum.get_nested(&pair).read(&full_day)?,
            ),
            (
                self.wwd_prefix_pv_sum.get_nested(&pair).read(&prefix_day)?,
                self.wwd_prefix_vol_sum
                    .get_nested(&pair)
                    .read(&prefix_day)?,
            ),
        ];
        let mut total = VwapAccumulator::default();
        for (price_volume, volume) in components {
            if !volume.is_zero() {
                total.add(
                    pair,
                    price_volume,
                    volume,
                    "WWD sum accumulation",
                    "WWD volume sum",
                )?;
            }
        }
        Ok(total.finish())
    }

    /// Calculates TWAP (time-weighted average price) for a pair.
    ///
    /// TWAP = sum(price_i * duration_i) / sum(duration_i)
    /// where duration_i is the time between consecutive snapshots.
    pub fn calculate_twap(
        &self,
        pair: AddressPair,
        now: u64,
        lookback_seconds: u64,
    ) -> Result<U256> {
        self.try_calculate_twap(pair, now, lookback_seconds)?
            .ok_or_else(|| OracleError::NoTwapData.into())
    }

    /// [`Self::calculate_twap`] with "the window held no samples" as `Ok(None)`.
    fn try_calculate_twap(
        &self,
        pair: AddressPair,
        now: u64,
        lookback_seconds: u64,
    ) -> Result<Option<U256>> {
        let max_lookback = self.config_lookback_duration.read()?;
        if lookback_seconds == 0 || lookback_seconds > max_lookback {
            return Err(OracleError::InvalidLookbackSeconds.into());
        }
        let start_time = now.saturating_sub(lookback_seconds);

        let write_idx = self.snapshot_write_idx.read()?;
        let oldest_idx = self.snapshot_oldest_idx.read()?;

        // Collect (timestamp, rate) pairs in chronological order
        let mut data: Vec<(u64, U256)> = Vec::new();

        for idx in oldest_idx..write_idx {
            let ts = self.snapshot_timestamp.read(&idx)?;
            if ts < start_time {
                continue;
            }
            if ts > now {
                break;
            }

            let pc = self.snapshot_pair_count.read(&idx)?;
            let pair_map = self.snapshot_pair.get_nested(&idx);
            let rate_map = self.snapshot_rate.get_nested(&idx);

            for p in 0..pc {
                if pair_map.read_pair(&p)?.same_market(&pair) {
                    data.push((ts, rate_map.read(&p)?));
                    break;
                }
            }
        }

        if data.is_empty() {
            return Ok(None);
        }

        if data.len() == 1 {
            return Ok(Some(data[0].1));
        }

        // TWAP: weight each price by time until next price change
        let mut price_time_sum = U256::ZERO;
        let mut time_sum = U256::ZERO;

        for i in 0..data.len() - 1 {
            let duration = U256::from(data[i + 1].0 - data[i].0);
            let pv = data[i]
                .1
                .checked_mul(duration)
                .ok_or(OracleError::TwapOverflow)?;
            price_time_sum = price_time_sum
                .checked_add(pv)
                .ok_or(OracleError::TwapOverflow)?;
            time_sum = time_sum
                .checked_add(duration)
                .ok_or(OracleError::TwapOverflow)?;
        }

        // Include last price until `now`
        let last = data.last().ok_or(OracleError::MissingTwapData)?;
        let last_duration = U256::from(now.saturating_sub(last.0));
        if !last_duration.is_zero() {
            let pv = last
                .1
                .checked_mul(last_duration)
                .ok_or(OracleError::TwapOverflow)?;
            price_time_sum = price_time_sum
                .checked_add(pv)
                .ok_or(OracleError::TwapOverflow)?;
            time_sum = time_sum
                .checked_add(last_duration)
                .ok_or(OracleError::TwapOverflow)?;
        }

        if time_sum.is_zero() {
            return Ok(Some(data[0].1));
        }

        Ok(Some(price_time_sum / time_sum))
    }

    /// Calculates TWAPs for all active vote-target pairs.
    pub fn calculate_twaps(&self, now: u64, lookback_seconds: u64) -> Result<PairSeries> {
        self.try_calculate_twaps(now, lookback_seconds)?
            .ok_or_else(|| OracleError::NoTwapData.into())
    }

    /// [`Self::calculate_twaps`] with "no pair had data" as `Ok(None)`.
    fn try_calculate_twaps(&self, now: u64, lookback_seconds: u64) -> Result<Option<PairSeries>> {
        let count = self.pair_count.read()?;
        let mut pairs = Vec::new();
        let mut twaps = Vec::new();
        let mut lookbacks = Vec::new();

        for pid in 1..=count {
            let entry = self.pair_at(pid)?;
            if !self.vote_target.read(&entry)? {
                continue;
            }

            if let Some(twap) = self.try_calculate_twap(entry, now, lookback_seconds)? {
                pairs.push(entry);
                twaps.push(twap);
                lookbacks.push(lookback_seconds);
            }
        }

        if pairs.is_empty() {
            return Ok(None);
        }

        Ok(Some((pairs, twaps, lookbacks)))
    }

    /// Calculates VWAPs for all active vote-target pairs over an explicit range.
    pub fn calculate_vwaps(&self, start_time: u64, end_time: u64) -> Result<PairSeries> {
        self.try_calculate_vwaps(start_time, end_time)?
            .ok_or_else(|| OracleError::NoVwapData.into())
    }

    /// [`Self::calculate_vwaps`] with "no pair had data" as `Ok(None)`.
    ///
    /// An invalid range is still an error: an empty result means the oracle had
    /// nothing to say about a well-formed window, not that the window was junk.
    fn try_calculate_vwaps(&self, start_time: u64, end_time: u64) -> Result<Option<PairSeries>> {
        if start_time >= end_time {
            return Err(OracleError::InvalidVwapRange.into());
        }

        let count = self.pair_count.read()?;
        let lookback = end_time - start_time;
        let mut pairs = Vec::new();
        let mut vwaps = Vec::new();
        let mut lookbacks = Vec::new();

        for pid in 1..=count {
            let entry = self.pair_at(pid)?;
            if !self.vote_target.read(&entry)? {
                continue;
            }

            if let Some(vwap) = self.try_calculate_vwap(entry, start_time, end_time)? {
                pairs.push(entry);
                vwaps.push(vwap);
                lookbacks.push(lookback);
            }
        }

        if pairs.is_empty() {
            return Ok(None);
        }

        Ok(Some((pairs, vwaps, lookbacks)))
    }

    /// Calculates VWAPs for the given WorldwideDay window and stores them in
    /// oracle state. Returns `false` when the window held no oracle data, in
    /// which case nothing is written - a deterministic no-op, not an error.
    pub fn store_worldwide_day_vwap_snapshot(
        &mut self,
        worldwide_day: WorldwideDay,
        start_time: u64,
        end_time: u64,
    ) -> Result<bool> {
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.store_worldwide_day_vwap_snapshot_inner(worldwide_day, start_time, end_time)
        })
    }

    fn store_worldwide_day_vwap_snapshot_inner(
        &mut self,
        worldwide_day: WorldwideDay,
        start_time: u64,
        end_time: u64,
    ) -> Result<bool> {
        // The forming window is a protocol parameter, not an oracle constant:
        // a chain that shortens it (localnet, E2E) still hands Metadosis'
        // real window here, and a second hardcoded copy would reject it.
        let expected_start = worldwide_day.start_timestamp();
        let expected_end = expected_start
            .checked_add(outbe_chain_constants::get_metadosis_forming_period_seconds())
            .ok_or(OracleError::InvalidVwapRange)?;
        if !worldwide_day.is_valid() || start_time != expected_start || end_time != expected_end {
            return Err(OracleError::InvalidVwapRange.into());
        }

        let pair_count = self.pair_count.read()?;
        let mut pairs = Vec::new();
        let mut vwaps = Vec::new();
        for pair_index in 1..=pair_count {
            let pair = self.pair_at(pair_index)?;
            if !self.vote_target.read(&pair)? {
                continue;
            }
            if let Some(vwap) = self.try_worldwide_day_vwap(pair, start_time)? {
                pairs.push(pair);
                vwaps.push(vwap);
            }
        }
        if pairs.is_empty() {
            return Ok(false);
        }
        let next_ocomp_version = self.next_ocomp_state_version()?;

        self.worldwide_day_vwap_exists.write(&worldwide_day, true)?;
        self.worldwide_day_vwap_start
            .write(&worldwide_day, start_time)?;
        self.worldwide_day_vwap_end
            .write(&worldwide_day, end_time)?;

        // Keyed by the registry index, so the pair itself is already recorded in
        // `pair_by_index`. Values not written stay zero, which reads back as "no
        // VWAP for this pair on this day". A WorldwideDay is written once, at the
        // Metadosis ResolveForming edge, so a second write with fewer pairs
        // cannot leave a stale entry behind.
        let value_map = self.worldwide_day_vwap_value.get_nested(&worldwide_day);
        for (pair, vwap) in pairs.iter().zip(vwaps.iter()) {
            value_map.write(&self.pair_index_of(*pair)?, *vwap)?;
        }

        self.commit_ocomp_state_version(next_ocomp_version)?;
        Ok(true)
    }

    /// Computes and persists the VWAP of every active vote-target pair for the
    /// fully-closed UTC calendar day `utc_day` (yyyymmdd UTC - *not* a
    /// WorldwideDay, which is UTC+14). The window is the canonical
    /// `[date_key_to_utc_timestamp(utc_day), +SECONDS_PER_DAY)`.
    ///
    /// Pairs without data for the day are skipped (mirrors `calculate_vwaps`);
    /// if no pair has data, nothing is written, so the day stays empty and is
    /// told apart from an unfinalized one by the `utc_day_vwap_last_finalized`
    /// watermark. Emits one `VwapCalculated` event per written pair in
    /// registration order. The method overwrites unconditionally - the
    /// caller gates re-finalization via that same watermark.
    pub fn finalize_utc_day_vwap(&mut self, utc_day: u32) -> Result<()> {
        if self.ocomp_profile_ready.read()? {
            let storage = self.storage.clone();
            storage.with_checkpoint(|| self.finalize_utc_day_vwap_inner(utc_day))
        } else {
            self.finalize_utc_day_vwap_inner(utc_day)
        }
    }

    fn finalize_utc_day_vwap_inner(&mut self, utc_day: u32) -> Result<()> {
        let day_start = date_key_to_utc_timestamp(utc_day);
        let day_end = day_start.saturating_add(SECONDS_PER_DAY);

        // No vote-target pair had data for the day - leave it unwritten so the
        // day reads as finalized-empty against the watermark.
        let Some((pairs, vwaps, _)) = self.try_calculate_vwaps(day_start, day_end)? else {
            return Ok(());
        };
        let next_ocomp_version = self.next_ocomp_state_version()?;
        let profile_ready = self.ocomp_profile_ready.read()?;

        // Keyed by the registry index; unwritten entries stay zero and read back
        // as "no VWAP for this pair on this day". Re-finalizing a closed day
        // recomputes over the same immutable window, so no stale entry survives.
        let value_map = self.utc_day_vwap_value.get_nested(&utc_day);
        for (pair, vwap) in pairs.iter().copied().zip(vwaps.iter().copied()) {
            value_map.write(&self.pair_index_of(pair)?, vwap)?;
            if profile_ready && pair.same_market(&DAY_TYPE_PAIR) {
                self.ocomp_day_type_vwap_by_utc_day.write(&utc_day, vwap)?;
            }
            let event = IOracle::VwapCalculated {
                utcDay: utc_day,
                base: pair.address1(),
                quote: pair.address2(),
                vwap,
            };
            let event_result = self
                .storage
                .emit_event(ORACLE_ADDRESS, event.encode_log_data());
            if next_ocomp_version.is_some() {
                event_result?;
            }
        }

        self.commit_ocomp_state_version(next_ocomp_version)
    }

    /// Returns `(nominal, vwap, max_scurve, source)` for a pair.
    ///
    /// Nominal price follows the Cosmos port rule: `max(VWAP, S-curve)`.
    /// If no VWAP samples exist for the day, VWAP contributes zero.
    pub fn get_nominal_price_components(
        &self,
        pair: AddressPair,
        timestamp: u64,
    ) -> Result<(U256, U256, U256, String)> {
        let day_start = crate::scurve::truncate_to_day(timestamp);
        let day_end = day_start.saturating_add(crate::scurve::DAY_SECONDS);
        let vwap = self
            .try_calculate_vwap(pair, day_start, day_end)?
            .unwrap_or(U256::ZERO);
        let max_scurve = crate::scurve::get_max_active_scurve_value(self, pair, timestamp)?;

        let (nominal, source) = if vwap.is_zero() && max_scurve.is_zero() {
            (U256::ZERO, "none".to_string())
        } else if vwap > max_scurve {
            (vwap, "vwap".to_string())
        } else {
            (max_scurve, "scurve".to_string())
        };

        Ok((nominal, vwap, max_scurve, source))
    }

    /// Calculates VWAP for a pair using a lookback in seconds from `now`.
    pub fn calculate_vwap_lookback(
        &self,
        pair: AddressPair,
        now: u64,
        lookback_seconds: u64,
    ) -> Result<U256> {
        let max_lookback = self.config_lookback_duration.read()?;
        let effective_lookback = lookback_seconds.min(max_lookback);
        let start_time = now.saturating_sub(effective_lookback);
        self.calculate_vwap(pair, start_time, now)
    }
}
