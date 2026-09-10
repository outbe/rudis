//! Property-based tests for the EIP-7702 sponsorship policy.
//!
//! Targets behaviours that are easy to spec but hard to spot-test
//! exhaustively - UTC day boundary arithmetic, lazy reset around
//! midnight, and the determinism contract that a fixed `(signer,
//! timestamp)` tuple always produces the same
//! authorization outcome regardless of pre-existing storage history
//! from a different day.

use alloy_primitives::{address, Address};
use outbe_primitives::{
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
    time::{previous_date_key, timestamp_to_date_key, SECONDS_PER_DAY},
};
use outbe_zerofee::{
    authorize_sponsorship, pack_counter, record_sponsorship_use, ZeroFeeContract,
    ZeroFeePolicyError, FREE_TX_DAILY_LIMIT,
};
use proptest::prelude::*;

const SIGNER: Address = address!("0x1111111111111111111111111111111111111111");

fn with_storage<R>(f: impl FnOnce(StorageHandle<'_>) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, f)
}

proptest! {
    /// `current_day` is purely a function of the block timestamp; the
    /// stored state and the signer's account view never influence it.
    /// This is the deterministic contract executor and txpool both
    /// rely on to keep their views in sync.
    #[test]
    fn current_day_is_deterministic_in_timestamp(
        ts in 0u64..=4_102_444_800u64,
    ) {
        with_storage(|storage| {
            let auth = authorize_sponsorship(storage, SIGNER, ts).unwrap();
            prop_assert_eq!(auth.current_day, timestamp_to_date_key(ts));
            Ok(())
        })?;
    }

    /// Within a single UTC day, the effective count is whatever was
    /// written; across day boundaries, it lazily resets. The property
    /// hold across the full range of stored counts (0..=255) and
    /// stored days (genesis..=2099).
    #[test]
    fn effective_count_lazy_reset_property(
        stored_day in 19_700_101u32..=20_991_231u32,
        stored_count in 0u32..=255u32,
        block_ts in 0u64..=4_102_444_800u64,
    ) {
        with_storage(|storage| {
            let zerofee = ZeroFeeContract::new(storage.clone());
            zerofee
                .counter
                .write(&SIGNER, pack_counter(stored_day, stored_count))
                .unwrap();

            let current_day = timestamp_to_date_key(block_ts);
            let effective = ZeroFeeContract::new(storage)
                .effective_count(SIGNER, current_day)
                .unwrap();

            let expected = if stored_day == current_day { stored_count } else { 0 };
            prop_assert_eq!(effective, expected);
            Ok(())
        })?;
    }

    /// `record_sponsorship_use` increments the counter by exactly 1
    /// per call within a single day, regardless of where the timestamp
    /// falls inside that day's window.
    #[test]
    fn record_use_monotonic_within_day(
        day_offset_secs in 0u64..SECONDS_PER_DAY,
        // Start from year 2000 to avoid the genesis-day skew.
        base_day_index in 11_000u64..=20_000u64,
    ) {
        let ts = base_day_index * SECONDS_PER_DAY + day_offset_secs;
        let day = timestamp_to_date_key(ts);
        with_storage(|storage| {
            for expected in 1..=FREE_TX_DAILY_LIMIT {
                let auth = authorize_sponsorship(storage.clone(), SIGNER, ts)
                .unwrap();
                prop_assert_eq!(auth.next_count, expected);
                prop_assert_eq!(auth.current_day, day);
                let written = record_sponsorship_use(storage.clone(), SIGNER, auth.current_day)
                    .unwrap();
                prop_assert_eq!(written, expected);
            }

            // The next attempt must surface `FreeTxDailyExhausted`.
            let err = authorize_sponsorship(storage, SIGNER, ts).unwrap_err();
            let is_exhausted = matches!(
                err,
                ZeroFeePolicyError::FreeTxDailyExhausted {
                    used: FREE_TX_DAILY_LIMIT,
                    limit: FREE_TX_DAILY_LIMIT,
                },
            );
            prop_assert!(is_exhausted, "ninth attempt must be FreeTxDailyExhausted");
            Ok(())
        })?;
    }

    /// Stepping across midnight resets the quota lazily on the first
    /// authorize of the new day, no matter how many slots had been
    /// burned on the previous day.
    #[test]
    fn midnight_lazy_reset_property(
        burned_yesterday in 0u32..=FREE_TX_DAILY_LIMIT,
        // Pick a today_ts safely inside year 2026 so previous_date_key
        // works against a real calendar.
        today_offset_secs in 0u64..SECONDS_PER_DAY,
    ) {
        let today_ts = 1_775_001_600u64 + today_offset_secs;
        let today = timestamp_to_date_key(today_ts);
        let yesterday = previous_date_key(today);

        with_storage(|storage| {
            // Seed yesterday at `burned_yesterday`.
            ZeroFeeContract::new(storage.clone())
                .counter
                .write(&SIGNER, pack_counter(yesterday, burned_yesterday))
                .unwrap();

            // Today's first authorize must produce next_count == 1
            // regardless of how saturated yesterday was.
            let auth = authorize_sponsorship(storage, SIGNER, today_ts)
            .unwrap();
            prop_assert_eq!(auth.current_day, today);
            prop_assert_eq!(auth.next_count, 1);
            Ok(())
        })?;
    }
}
