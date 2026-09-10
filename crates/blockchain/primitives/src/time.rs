//! UTC date and time helpers.
//!
//! All functions are pure integer arithmetic - no `chrono`, no float, no
//! locale, no DST. The yyyymmdd "date key" is a `u32` like `20251205`. UTC
//! is the only calendar; `worldwide_day_from_timestamp` shifts by +14h
//! (UTC+14) for Metadosis-internal "Worldwide Day" semantics.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
// This module is itself named `time`, so the extern crate needs an absolute path.
use ::time::{Date, Month};

use crate::storage::types::{Storable, StorableType, StorageKey};

/// Seconds in one calendar day. Public so consumers can do day-aligned
/// timestamp arithmetic without redefining the constant.
pub const SECONDS_PER_DAY: u64 = 86_400;

/// UTC+14 offset used by `worldwide_day_from_timestamp`. Public so
/// callers that need to align Metadosis WWD with arbitrary timestamps can
/// use the same constant.
pub const UTC_PLUS_14_OFFSET: u64 = 50_400;

/// Errors returned by the time helpers. Currently only one variant; the
/// enum is `non_exhaustive` so additional variants can be introduced
/// without breaking callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeError {
    /// `utc_day` is strictly before `genesis_utc_day`. Caller is expected
    /// to translate this into a fatal protocol error - a finalized block
    /// predating genesis must not be processed.
    PreGenesis { utc_day: u32, genesis_utc_day: u32 },
}

impl core::fmt::Display for TimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TimeError::PreGenesis {
                utc_day,
                genesis_utc_day,
            } => write!(
                f,
                "utc_day {utc_day} predates genesis_utc_day {genesis_utc_day}"
            ),
        }
    }
}

/// Converts a unix timestamp to a yyyymmdd date key in UTC.
pub fn timestamp_to_date_key(timestamp: u64) -> u32 {
    // `timestamp / SECONDS_PER_DAY` is at most `u64::MAX / 86_400` ~= 2.1e14, far
    // below `i64::MAX`, so this never saturates; `try_from` (not `as`) keeps the
    // conversion non-narrowing and deterministic on the consensus date path.
    let days = i64::try_from(timestamp / SECONDS_PER_DAY).unwrap_or(i64::MAX);
    civil_date_from_days(days)
}

/// Returns the worldwide day key for a unix timestamp (UTC+14).
pub fn worldwide_day_from_timestamp(timestamp: u64) -> u32 {
    timestamp_to_date_key(timestamp + UTC_PLUS_14_OFFSET)
}

/// Returns the unix timestamp for midnight UTC of a yyyymmdd date key.
pub fn date_key_to_utc_timestamp(date_key: u32) -> u64 {
    let year = (date_key / 10_000) as i64;
    let month = ((date_key / 100) % 100) as i64;
    let day = (date_key % 100) as i64;
    let days = days_from_civil(year, month, day);
    (days as u64) * SECONDS_PER_DAY
}

/// Returns the previous calendar day key for a yyyymmdd date key.
pub fn previous_date_key(date_key: u32) -> u32 {
    let ts = date_key_to_utc_timestamp(date_key).saturating_sub(SECONDS_PER_DAY);
    timestamp_to_date_key(ts)
}

/// Returns the next calendar day key for a yyyymmdd date key.
///
/// Walks forward 24h via integer timestamp arithmetic; this is the only
/// correct way to advance across month/year boundaries - direct `u32`
/// arithmetic on `yyyymmdd` is wrong (e.g., `20251231 + 1 != 20260101`).
pub fn next_date_key(date_key: u32) -> u32 {
    let ts = date_key_to_utc_timestamp(date_key).saturating_add(SECONDS_PER_DAY);
    timestamp_to_date_key(ts)
}

/// Computes the integer number of UTC days between two date keys.
///
/// Returns `Ok(0)` when `utc_day == genesis_utc_day`,
/// `Ok(n)` when `utc_day > genesis_utc_day`, and
/// `Err(TimeError::PreGenesis)` when `utc_day < genesis_utc_day`.
///
/// Computed via `(date_key_to_timestamp(utc_day) -
/// date_key_to_timestamp(genesis_utc_day)) / SECONDS_PER_DAY`. Direct
/// `u32` subtraction of `yyyymmdd` keys is wrong across month/year
/// boundaries and must not be used.
pub fn day_number_between(genesis_utc_day: u32, utc_day: u32) -> Result<u32, TimeError> {
    let g_ts = date_key_to_utc_timestamp(genesis_utc_day);
    let u_ts = date_key_to_utc_timestamp(utc_day);
    let delta = u_ts.checked_sub(g_ts).ok_or(TimeError::PreGenesis {
        utc_day,
        genesis_utc_day,
    })?;
    // Day count since genesis. `u32` covers ~11.7M years of days; saturating
    // `try_from` (not `as`) keeps it non-narrowing and deterministic - an
    // unreachable overflow clamps rather than silently wrapping.
    Ok(u32::try_from(delta / SECONDS_PER_DAY).unwrap_or(u32::MAX))
}

fn civil_date_from_days(days_since_epoch: i64) -> u32 {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32) * 10000 + m * 100 + d
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Typed worldwide day identifier in YYYYMMDD format.
#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct WorldwideDay(u32);

impl WorldwideDay {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    /// Returns true if this value encodes a valid YYYYMMDD calendar date.
    pub fn is_valid(self) -> bool {
        let (year, month, day) = self.parse_wwd_to_nums();
        let Ok(month) = Month::try_from(month) else {
            return false;
        };
        Date::from_calendar_date(year, month, day).is_ok()
    }

    fn parse_wwd_to_nums(self) -> (i32, u8, u8) {
        let raw = self.0;
        let year = (raw / 10_000) as i32;
        let month = ((raw / 100) % 100) as u8;
        let day = (raw % 100) as u8;
        (year, month, day)
    }

    /// Returns the worldwide day key for a unix timestamp (UTC+14).
    pub fn from_timestamp(timestamp: u64) -> Self {
        Self(timestamp_to_date_key(timestamp + UTC_PLUS_14_OFFSET))
    }

    /// Returns the forming-start timestamp for this worldwide day.
    pub fn start_timestamp(self) -> u64 {
        date_key_to_utc_timestamp(self.0).saturating_sub(UTC_PLUS_14_OFFSET)
    }

    /// Returns the previous calendar day.
    pub fn previous_date_key(self) -> Self {
        Self(previous_date_key(self.0))
    }

    /// Returns the WWD in UNIX timestamp seconds.
    pub fn to_timestamp_utc(self) -> u64 {
        date_key_to_utc_timestamp(self.0)
    }
}

impl fmt::Display for WorldwideDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for WorldwideDay {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl From<WorldwideDay> for u32 {
    fn from(value: WorldwideDay) -> Self {
        value.value()
    }
}

impl From<WorldwideDay> for u64 {
    fn from(val: WorldwideDay) -> Self {
        u64::from(val.0)
    }
}

impl FromStr for WorldwideDay {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s
            .parse::<u32>()
            .map_err(|_| "worldwide_day must be a valid u32 value".to_string())?;
        let value = Self::new(raw);
        if !value.is_valid() {
            return Err("worldwide_day must be a valid YYYYMMDD date".to_string());
        }
        Ok(value)
    }
}

/// Storage implementation for WorldwideDay as a single 32-bit word.
impl StorableType for WorldwideDay {
    const SLOTS: usize = 1;
}

impl Storable for WorldwideDay {
    fn from_word(word: U256) -> Self {
        Self(word.to::<u32>())
    }

    fn to_word(&self) -> U256 {
        U256::from(self.0)
    }
}

impl StorageKey for WorldwideDay {
    fn key_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_to_date_key_uses_utc() {
        assert_eq!(timestamp_to_date_key(0), 19700101);
        assert_eq!(timestamp_to_date_key(1_704_067_200), 20240101);
        assert_eq!(timestamp_to_date_key(1_734_706_800), 20241220);
    }

    #[test]
    fn worldwide_day_uses_utc_plus_14_boundary() {
        assert_eq!(worldwide_day_from_timestamp(1_734_706_800), 20241221);
    }

    #[test]
    fn date_key_to_timestamp_roundtrip_at_midnight() {
        // Midnight UTC of 2024-01-01 = 1_704_067_200.
        assert_eq!(date_key_to_utc_timestamp(20240101), 1_704_067_200);
        assert_eq!(date_key_to_utc_timestamp(19700101), 0);
    }

    #[test]
    fn date_key_roundtrip_through_timestamp() {
        for k in [19700101u32, 20240101, 20240229, 20241231, 20251205] {
            let ts = date_key_to_utc_timestamp(k);
            assert_eq!(timestamp_to_date_key(ts), k, "roundtrip failed for {k}");
        }
    }

    #[test]
    fn previous_date_key_crosses_month_and_year() {
        assert_eq!(previous_date_key(20240101), 20231231);
        assert_eq!(previous_date_key(20240301), 20240229); // leap year
        assert_eq!(previous_date_key(20230301), 20230228);
    }

    #[test]
    fn next_date_key_crosses_month_and_year() {
        assert_eq!(next_date_key(20231231), 20240101);
        assert_eq!(next_date_key(20240229), 20240301); // leap year
        assert_eq!(next_date_key(20230228), 20230301);
        assert_eq!(next_date_key(20240630), 20240701);
    }

    #[test]
    fn day_number_between_same_day_is_zero() {
        assert_eq!(day_number_between(20240101, 20240101), Ok(0));
    }

    #[test]
    fn day_number_between_walks_forward_across_year() {
        // 2024 is leap -> 366 days.
        assert_eq!(day_number_between(20240101, 20250101), Ok(366));
        // 2023 is non-leap -> 365 days.
        assert_eq!(day_number_between(20230101, 20240101), Ok(365));
    }

    #[test]
    fn day_number_between_walks_forward_within_year() {
        assert_eq!(day_number_between(20240101, 20240131), Ok(30));
        assert_eq!(day_number_between(20240101, 20240301), Ok(60)); // 31 + 29 (leap)
    }

    #[test]
    fn day_number_between_pre_genesis_is_error() {
        assert_eq!(
            day_number_between(20240101, 20231231),
            Err(TimeError::PreGenesis {
                utc_day: 20231231,
                genesis_utc_day: 20240101,
            })
        );
    }

    // --- WorldwideDay ---

    use crate::storage::{
        hashmap::HashMapStorageProvider,
        types::{Mapping, Slot, Storable, StorableType, StorageKey},
        StorageHandle,
    };
    use alloy_primitives::{address, U256};

    #[test]
    fn worldwide_day_to_utc_timestamp_roundtrip_known_midnight() {
        let wwd = WorldwideDay::new(20241220);
        // Midnight UTC of 2024-12-20
        assert_eq!(date_key_to_utc_timestamp(wwd.value()), 1_734_652_800);
    }

    #[test]
    fn is_valid_accepts_basic_valid_dates() {
        assert!(WorldwideDay::new(20240101).is_valid());
        assert!(WorldwideDay::new(20000229).is_valid());
    }

    #[test]
    fn is_valid_rejects_basic_invalid_dates() {
        assert!(!WorldwideDay::new(0).is_valid());
        assert!(!WorldwideDay::new(20240001).is_valid());
        assert!(!WorldwideDay::new(20241301).is_valid());
        assert!(!WorldwideDay::new(20240100).is_valid());
        assert!(!WorldwideDay::new(20240431).is_valid());
        assert!(!WorldwideDay::new(20230229).is_valid());
        assert!(!WorldwideDay::new(19000229).is_valid());
    }

    #[test]
    fn serde_is_transparent_u32() {
        let wwd = WorldwideDay::new(20241220);
        let encoded = serde_json::to_string(&wwd).expect("serialize worldwideday");
        assert_eq!(encoded, "20241220");

        let decoded: WorldwideDay =
            serde_json::from_str(&encoded).expect("deserialize worldwideday");
        assert_eq!(decoded, wwd);
    }

    #[test]
    fn storage_word_roundtrip() {
        let wwd = WorldwideDay::new(20251231);
        let word = wwd.to_word();
        let decoded = WorldwideDay::from_word(word);
        assert_eq!(decoded, wwd);
    }

    #[test]
    fn storage_key_is_big_endian_u32() {
        let wwd = WorldwideDay::new(0x0102_0304);
        assert_eq!(wwd.key_bytes(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    /// Storage-compatible with the raw `u32` day key it replaced: schemas that
    /// retyped a `Map<u32, _>` / `Map<_, u32>` day slot must address and store the
    /// exact same bytes, or live state silently moves.
    #[test]
    fn storage_encoding_is_identical_to_the_raw_u32_day() {
        for raw in [0u32, 1, 20_260_101, u32::MAX] {
            let wwd = WorldwideDay::new(raw);
            assert_eq!(wwd.key_bytes(), raw.key_bytes(), "mapping key moved");
            assert_eq!(wwd.to_word(), raw.to_word(), "stored word moved");
            assert_eq!(
                <WorldwideDay as StorableType>::SLOTS,
                <u32 as StorableType>::SLOTS,
                "slot count moved"
            );
        }
    }

    #[test]
    fn storage_slot_roundtrip_is_raw_u32_word() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let slot_index = U256::from(7u64);
        let value = WorldwideDay::new(20241220);

        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let slot: Slot<WorldwideDay> = Slot::new(slot_index, contract, storage.clone());
            slot.write(value).expect("write worldwideday slot");

            let decoded = slot.read().expect("read worldwideday slot");
            assert_eq!(decoded, value);

            let raw = storage
                .sload(contract, slot_index)
                .expect("read raw storage word");
            assert_eq!(raw, U256::from(value.value()));
        });
    }

    #[test]
    fn storage_mapping_roundtrip_as_key_and_value() {
        let contract = address!("0x0000000000000000000000000000000000001003");
        let key = WorldwideDay::new(20250101);
        let value = WorldwideDay::new(20251231);

        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let mapping: Mapping<WorldwideDay, WorldwideDay> =
                Mapping::new(U256::from(9u64), contract, storage);

            mapping
                .write(&key, value)
                .expect("write worldwideday mapping");
            let decoded = mapping.read(&key).expect("read worldwideday mapping");
            assert_eq!(decoded, value);
        });
    }

    #[test]
    fn display_and_parse_roundtrip() {
        let wwd = WorldwideDay::new(20241220);
        let encoded = wwd.to_string();
        assert_eq!(encoded, "20241220");

        let decoded: WorldwideDay = encoded.parse().expect("parse worldwideday");
        assert_eq!(decoded, wwd);
    }

    #[test]
    fn parse_rejects_invalid_date() {
        let err = "20240230".parse::<WorldwideDay>().unwrap_err();
        assert!(err.contains("valid YYYYMMDD"));
    }
}
