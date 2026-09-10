//! S-curve pricing algorithm.
//!
//! The curve shape comes from Cosmos SDK `x/oracle/algorithm/scurve.go`; the
//! stored coefficients are quantized to the COEN/840 six-decimal contract.
//! Every 128-day segment applies the same coefficient table. The next segment
//! starts from `floor(previous_anchor * 0.92)`, forming one continuous chain.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::ORACLE_ADDRESS;
use outbe_primitives::error::Result;
use outbe_primitives::units::SCALE_1E6_U256;

use crate::errors::OracleError;

use outbe_primitives::address_pair::AddressPair;

use crate::precompile::IOracle;
use crate::schema::OracleContract;

/// `(bases, quotes, peak_days, peak_prices)` - every active S-curve entry.
type ScurveTable = (Vec<Address>, Vec<Address>, Vec<u64>, Vec<U256>);

/// The pair an S-curve entry belongs to.
fn entry_pair(oracle: &OracleContract, idx: u32) -> Result<AddressPair> {
    oracle.scurve_pair.read_pair(&idx)
}

/// S-curve period in days.
pub const PERIOD: usize = 128;

/// Seconds in one day.
pub const DAY_SECONDS: u64 = 86400;

/// Truncates a timestamp to the start of the UTC day (00:00 UTC).
pub fn truncate_to_day(timestamp: u64) -> u64 {
    (timestamp / DAY_SECONDS) * DAY_SECONDS
}

/// Precomputed COEN/840 S-curve coefficients at six-decimal scale (128 entries).
///
/// Formula: `coef_i = 1 - alpha * (sigmoid(x_i) - sigmoid_min) / (sigmoid_0 - sigmoid_min)`
/// Parameters: alpha=0.08, beta=0.08, center=64
///
/// Source: `x/oracle/algorithm/scurve.go:precomputedCoefficients`
///
/// Each value is `floor(original_decimal18 / 10^12)`.
pub static COEFFICIENTS: [U256; PERIOD] = [
    U256::from_limbs([1_000_000, 0, 0, 0]), // [0] 1.000000000000000000
    U256::from_limbs([999_960, 0, 0, 0]),   // [1]
    U256::from_limbs([999_917, 0, 0, 0]),   // [2]
    U256::from_limbs([999_870, 0, 0, 0]),   // [3]
    U256::from_limbs([999_820, 0, 0, 0]),   // [4]
    U256::from_limbs([999_765, 0, 0, 0]),   // [5]
    U256::from_limbs([999_706, 0, 0, 0]),   // [6]
    U256::from_limbs([999_642, 0, 0, 0]),   // [7]
    U256::from_limbs([999_573, 0, 0, 0]),   // [8]
    U256::from_limbs([999_498, 0, 0, 0]),   // [9]
    U256::from_limbs([999_418, 0, 0, 0]),   // [10]
    U256::from_limbs([999_330, 0, 0, 0]),   // [11]
    U256::from_limbs([999_236, 0, 0, 0]),   // [12]
    U256::from_limbs([999_134, 0, 0, 0]),   // [13]
    U256::from_limbs([999_024, 0, 0, 0]),   // [14]
    U256::from_limbs([998_905, 0, 0, 0]),   // [15]
    U256::from_limbs([998_776, 0, 0, 0]),   // [16]
    U256::from_limbs([998_638, 0, 0, 0]),   // [17]
    U256::from_limbs([998_488, 0, 0, 0]),   // [18]
    U256::from_limbs([998_326, 0, 0, 0]),   // [19]
    U256::from_limbs([998_152, 0, 0, 0]),   // [20]
    U256::from_limbs([997_964, 0, 0, 0]),   // [21]
    U256::from_limbs([997_762, 0, 0, 0]),   // [22]
    U256::from_limbs([997_543, 0, 0, 0]),   // [23]
    U256::from_limbs([997_308, 0, 0, 0]),   // [24]
    U256::from_limbs([997_055, 0, 0, 0]),   // [25]
    U256::from_limbs([996_783, 0, 0, 0]),   // [26]
    U256::from_limbs([996_490, 0, 0, 0]),   // [27]
    U256::from_limbs([996_175, 0, 0, 0]),   // [28]
    U256::from_limbs([995_837, 0, 0, 0]),   // [29]
    U256::from_limbs([995_474, 0, 0, 0]),   // [30]
    U256::from_limbs([995_085, 0, 0, 0]),   // [31]
    U256::from_limbs([994_668, 0, 0, 0]),   // [32]
    U256::from_limbs([994_221, 0, 0, 0]),   // [33]
    U256::from_limbs([993_744, 0, 0, 0]),   // [34]
    U256::from_limbs([993_233, 0, 0, 0]),   // [35]
    U256::from_limbs([992_687, 0, 0, 0]),   // [36]
    U256::from_limbs([992_105, 0, 0, 0]),   // [37]
    U256::from_limbs([991_485, 0, 0, 0]),   // [38]
    U256::from_limbs([990_825, 0, 0, 0]),   // [39]
    U256::from_limbs([990_124, 0, 0, 0]),   // [40]
    U256::from_limbs([989_379, 0, 0, 0]),   // [41]
    U256::from_limbs([988_590, 0, 0, 0]),   // [42]
    U256::from_limbs([987_756, 0, 0, 0]),   // [43]
    U256::from_limbs([986_874, 0, 0, 0]),   // [44]
    U256::from_limbs([985_944, 0, 0, 0]),   // [45]
    U256::from_limbs([984_965, 0, 0, 0]),   // [46]
    U256::from_limbs([983_937, 0, 0, 0]),   // [47]
    U256::from_limbs([982_859, 0, 0, 0]),   // [48]
    U256::from_limbs([981_731, 0, 0, 0]),   // [49]
    U256::from_limbs([980_553, 0, 0, 0]),   // [50]
    U256::from_limbs([979_327, 0, 0, 0]),   // [51]
    U256::from_limbs([978_053, 0, 0, 0]),   // [52]
    U256::from_limbs([976_733, 0, 0, 0]),   // [53]
    U256::from_limbs([975_368, 0, 0, 0]),   // [54]
    U256::from_limbs([973_961, 0, 0, 0]),   // [55]
    U256::from_limbs([972_515, 0, 0, 0]),   // [56]
    U256::from_limbs([971_033, 0, 0, 0]),   // [57]
    U256::from_limbs([969_517, 0, 0, 0]),   // [58]
    U256::from_limbs([967_974, 0, 0, 0]),   // [59]
    U256::from_limbs([966_405, 0, 0, 0]),   // [60]
    U256::from_limbs([964_817, 0, 0, 0]),   // [61]
    U256::from_limbs([963_213, 0, 0, 0]),   // [62]
    U256::from_limbs([961_599, 0, 0, 0]),   // [63]
    U256::from_limbs([959_980, 0, 0, 0]),   // [64] center
    U256::from_limbs([958_360, 0, 0, 0]),   // [65]
    U256::from_limbs([956_746, 0, 0, 0]),   // [66]
    U256::from_limbs([955_143, 0, 0, 0]),   // [67]
    U256::from_limbs([953_554, 0, 0, 0]),   // [68]
    U256::from_limbs([951_986, 0, 0, 0]),   // [69]
    U256::from_limbs([950_442, 0, 0, 0]),   // [70]
    U256::from_limbs([948_927, 0, 0, 0]),   // [71]
    U256::from_limbs([947_444, 0, 0, 0]),   // [72]
    U256::from_limbs([945_998, 0, 0, 0]),   // [73]
    U256::from_limbs([944_591, 0, 0, 0]),   // [74]
    U256::from_limbs([943_227, 0, 0, 0]),   // [75]
    U256::from_limbs([941_906, 0, 0, 0]),   // [76]
    U256::from_limbs([940_632, 0, 0, 0]),   // [77]
    U256::from_limbs([939_406, 0, 0, 0]),   // [78]
    U256::from_limbs([938_228, 0, 0, 0]),   // [79]
    U256::from_limbs([937_101, 0, 0, 0]),   // [80]
    U256::from_limbs([936_022, 0, 0, 0]),   // [81]
    U256::from_limbs([934_994, 0, 0, 0]),   // [82]
    U256::from_limbs([934_015, 0, 0, 0]),   // [83]
    U256::from_limbs([933_085, 0, 0, 0]),   // [84]
    U256::from_limbs([932_204, 0, 0, 0]),   // [85]
    U256::from_limbs([931_369, 0, 0, 0]),   // [86]
    U256::from_limbs([930_580, 0, 0, 0]),   // [87]
    U256::from_limbs([929_836, 0, 0, 0]),   // [88]
    U256::from_limbs([929_134, 0, 0, 0]),   // [89]
    U256::from_limbs([928_474, 0, 0, 0]),   // [90]
    U256::from_limbs([927_854, 0, 0, 0]),   // [91]
    U256::from_limbs([927_272, 0, 0, 0]),   // [92]
    U256::from_limbs([926_727, 0, 0, 0]),   // [93]
    U256::from_limbs([926_216, 0, 0, 0]),   // [94]
    U256::from_limbs([925_738, 0, 0, 0]),   // [95]
    U256::from_limbs([925_291, 0, 0, 0]),   // [96]
    U256::from_limbs([924_874, 0, 0, 0]),   // [97]
    U256::from_limbs([924_485, 0, 0, 0]),   // [98]
    U256::from_limbs([924_122, 0, 0, 0]),   // [99]
    U256::from_limbs([923_784, 0, 0, 0]),   // [100]
    U256::from_limbs([923_469, 0, 0, 0]),   // [101]
    U256::from_limbs([923_176, 0, 0, 0]),   // [102]
    U256::from_limbs([922_904, 0, 0, 0]),   // [103]
    U256::from_limbs([922_651, 0, 0, 0]),   // [104]
    U256::from_limbs([922_416, 0, 0, 0]),   // [105]
    U256::from_limbs([922_198, 0, 0, 0]),   // [106]
    U256::from_limbs([921_995, 0, 0, 0]),   // [107]
    U256::from_limbs([921_807, 0, 0, 0]),   // [108]
    U256::from_limbs([921_633, 0, 0, 0]),   // [109]
    U256::from_limbs([921_471, 0, 0, 0]),   // [110]
    U256::from_limbs([921_322, 0, 0, 0]),   // [111]
    U256::from_limbs([921_183, 0, 0, 0]),   // [112]
    U256::from_limbs([921_054, 0, 0, 0]),   // [113]
    U256::from_limbs([920_935, 0, 0, 0]),   // [114]
    U256::from_limbs([920_825, 0, 0, 0]),   // [115]
    U256::from_limbs([920_723, 0, 0, 0]),   // [116]
    U256::from_limbs([920_629, 0, 0, 0]),   // [117]
    U256::from_limbs([920_542, 0, 0, 0]),   // [118]
    U256::from_limbs([920_461, 0, 0, 0]),   // [119]
    U256::from_limbs([920_386, 0, 0, 0]),   // [120]
    U256::from_limbs([920_317, 0, 0, 0]),   // [121]
    U256::from_limbs([920_253, 0, 0, 0]),   // [122]
    U256::from_limbs([920_194, 0, 0, 0]),   // [123]
    U256::from_limbs([920_140, 0, 0, 0]),   // [124]
    U256::from_limbs([920_089, 0, 0, 0]),   // [125]
    U256::from_limbs([920_043, 0, 0, 0]),   // [126]
    U256::from_limbs([920_000, 0, 0, 0]),   // [127]
];

/// Multiplies a value by a scale-6 factor without overflowing `U256`.
fn mul_scale_1e6(value: U256, factor: U256) -> U256 {
    let whole = value / SCALE_1E6_U256;
    let remainder = value % SCALE_1E6_U256;
    whole * factor + remainder * factor / SCALE_1E6_U256
}

/// Computes the continuous S-curve value for a peak and absolute day index.
///
/// Each 128-day period starts from the previous period's anchor multiplied by
/// exactly `0.92` with floor rounding. The coefficient table is then applied
/// at the offset inside that period. This preserves the day-127/day-128
/// boundary and continues the same chain indefinitely.
pub fn compute_scurve_value(peak_price: U256, day_index: usize) -> U256 {
    let periods = day_index / PERIOD;
    let offset = day_index % PERIOD;
    let successor_factor = COEFFICIENTS[PERIOD - 1];
    let mut anchor = peak_price;
    for _ in 0..periods {
        anchor = mul_scale_1e6(anchor, successor_factor);
        if anchor.is_zero() {
            break;
        }
    }
    mul_scale_1e6(anchor, COEFFICIENTS[offset])
}

/// Returns the S-curve value for a pair at a given timestamp.
///
/// The public name is retained for ABI compatibility. Fresh state stores at
/// most one continuous entry per pair.
pub fn get_max_active_scurve_value(
    oracle: &OracleContract,
    pair: AddressPair,
    timestamp: u64,
) -> Result<U256> {
    let count = oracle.scurve_count.read()?;
    let oldest = oracle.scurve_oldest_idx.read()?;
    let target_day = truncate_to_day(timestamp);

    let mut max_value = U256::ZERO;

    for idx in oldest..count {
        if entry_pair(oracle, idx)? != pair {
            continue;
        }

        let peak_day = oracle.scurve_peak_day.read(&idx)?;
        let peak_price = oracle.scurve_peak_price.read(&idx)?;

        if target_day < peak_day {
            continue;
        }

        let days_since = ((target_day - peak_day) / DAY_SECONDS) as usize;
        let value = compute_scurve_value(peak_price, days_since);
        if value > max_value {
            max_value = value;
        }
    }

    Ok(max_value)
}

/// Returns the continuous S-curve entry for a specific pair.
///
/// Returns `(peak_days, peak_prices, current_values)` as parallel arrays.
pub fn get_scurve_entries(
    oracle: &OracleContract,
    pair: AddressPair,
    current_timestamp: u64,
) -> Result<(Vec<u64>, Vec<U256>, Vec<U256>)> {
    let count = oracle.scurve_count.read()?;
    let oldest = oracle.scurve_oldest_idx.read()?;
    let target_day = truncate_to_day(current_timestamp);

    let mut peak_days = Vec::new();
    let mut peak_prices = Vec::new();
    let mut current_values = Vec::new();

    for idx in oldest..count {
        if entry_pair(oracle, idx)? != pair {
            continue;
        }

        let peak_day = oracle.scurve_peak_day.read(&idx)?;
        let peak_price = oracle.scurve_peak_price.read(&idx)?;

        let days_since = if target_day >= peak_day {
            ((target_day - peak_day) / DAY_SECONDS) as usize
        } else {
            continue;
        };

        peak_days.push(peak_day);
        peak_prices.push(peak_price);
        current_values.push(compute_scurve_value(peak_price, days_since));
    }

    Ok((peak_days, peak_prices, current_values))
}

/// Returns all S-curve data across all pairs.
///
/// Returns `(bases, quotes, peak_days, peak_prices)` as parallel arrays.
pub fn get_all_scurve_data(oracle: &OracleContract) -> Result<ScurveTable> {
    let count = oracle.scurve_count.read()?;
    let oldest = oracle.scurve_oldest_idx.read()?;

    let mut bases = Vec::new();
    let mut quotes = Vec::new();
    let mut peak_days = Vec::new();
    let mut peak_prices = Vec::new();

    for idx in oldest..count {
        let pair = entry_pair(oracle, idx)?;
        let peak_day = oracle.scurve_peak_day.read(&idx)?;
        let peak_price = oracle.scurve_peak_price.read(&idx)?;

        bases.push(pair.address1());
        quotes.push(pair.address2());
        peak_days.push(peak_day);
        peak_prices.push(peak_price);
    }

    Ok((bases, quotes, peak_days, peak_prices))
}

/// Returns all S-curve data for a specific pair.
///
/// Returns `(peak_days, peak_prices)` as parallel arrays. The full continuous
/// value chain is deterministic from the peak price, so callers can use
/// `getScurveValues` for timestamp-specific values.
pub fn get_all_scurve_data_for_pair(
    oracle: &OracleContract,
    pair: AddressPair,
) -> Result<(Vec<u64>, Vec<U256>)> {
    let count = oracle.scurve_count.read()?;
    let oldest = oracle.scurve_oldest_idx.read()?;

    let mut peak_days = Vec::new();
    let mut peak_prices = Vec::new();

    for idx in oldest..count {
        if !entry_pair(oracle, idx)?.same_market(&pair) {
            continue;
        }
        peak_days.push(oracle.scurve_peak_day.read(&idx)?);
        peak_prices.push(oracle.scurve_peak_price.read(&idx)?);
    }

    Ok((peak_days, peak_prices))
}

/// Stores or replaces the single S-curve chain for a pair.
pub fn store_scurve_entry(
    oracle: &mut OracleContract,
    pair: AddressPair,
    peak_day: u64,
    peak_price: U256,
) -> Result<()> {
    if oracle.ocomp_profile_ready.read()? {
        let storage = oracle.storage.clone();
        storage
            .with_checkpoint(|| store_scurve_entry_inner(oracle, pair, peak_day, peak_price))
            .map(|_| ())
    } else {
        store_scurve_entry_inner(oracle, pair, peak_day, peak_price).map(|_| ())
    }
}

fn store_scurve_entry_inner(
    oracle: &mut OracleContract,
    pair: AddressPair,
    peak_day: u64,
    peak_price: U256,
) -> Result<bool> {
    let count = oracle.scurve_count.read()?;
    let next_idx = count
        .checked_add(1)
        .ok_or(OracleError::ScurveWriteIndexOverflow)?;
    let oldest = oracle.scurve_oldest_idx.read()?;
    for idx in oldest..count {
        if entry_pair(oracle, idx)? != pair {
            continue;
        }

        let current_peak_day = oracle.scurve_peak_day.read(&idx)?;
        if peak_day < current_peak_day {
            return Ok(false);
        }
        let days_since = ((peak_day - current_peak_day) / DAY_SECONDS) as usize;
        let current_value = compute_scurve_value(oracle.scurve_peak_price.read(&idx)?, days_since);
        if peak_price <= current_value {
            return Ok(false);
        }

        let next_ocomp_version = oracle.next_ocomp_state_version()?;
        oracle.scurve_peak_day.write(&idx, peak_day)?;
        oracle.scurve_peak_price.write(&idx, peak_price)?;
        oracle.commit_ocomp_state_version(next_ocomp_version)?;
        return Ok(true);
    }

    let idx = count;
    let next_ocomp_version = oracle.next_ocomp_state_version()?;
    oracle.scurve_pair.write_pair(&idx, pair)?;
    oracle.scurve_peak_day.write(&idx, peak_day)?;
    oracle.scurve_peak_price.write(&idx, peak_price)?;
    oracle.scurve_count.write(next_idx)?;
    oracle.commit_ocomp_state_version(next_ocomp_version)?;
    Ok(true)
}

/// Retained public seam. Continuous chains never expire or advance `oldest`.
pub fn evict_expired_scurves(_oracle: &mut OracleContract, _current_timestamp: u64) -> Result<()> {
    Ok(())
}

/// Detects peaks from the last 3 *closed* daily close prices for a pair
/// and stores new S-curve entries.
///
/// A peak occurs when: close[D-3] < close[D-2] > close[D-1], i.e. D-2 is the
/// peak. The current (just-started) day is never used as a close, so the peak
/// of a day X is confirmed at the start of X+2.
///
/// Called from the daily hook on the first block of each UTC day.
pub fn process_daily_scurve(
    oracle: &mut OracleContract,
    pair: AddressPair,
    timestamp: u64,
) -> Result<()> {
    if oracle.ocomp_profile_ready.read()? {
        let storage = oracle.storage.clone();
        storage.with_checkpoint(|| process_daily_scurve_inner(oracle, pair, timestamp))
    } else {
        process_daily_scurve_inner(oracle, pair, timestamp)
    }
}

fn process_daily_scurve_inner(
    oracle: &mut OracleContract,
    pair: AddressPair,
    timestamp: u64,
) -> Result<()> {
    let current_day = truncate_to_day(timestamp);

    // The daily hook fires on the first block of `current_day`, so
    // `current_day` itself has no close yet. Detect peaks only over fully
    // CLOSED UTC days. At this point the most recent closed day is D-1, so
    // the latest peak we can confirm is D-2 - confirming a peak requires the
    // close of the day that follows it.
    //
    //   day_minus_3 (close before peak) < day_minus_2 (peak) > day_minus_1 (close after peak)
    let day_minus_1 = current_day.saturating_sub(DAY_SECONDS);
    let day_minus_2 = current_day.saturating_sub(2 * DAY_SECONDS);
    let day_minus_3 = current_day.saturating_sub(3 * DAY_SECONDS);

    // Last snapshot rate within each fully-closed UTC day.
    let close_d1 = get_daily_close(oracle, pair, day_minus_1)?;
    let close_d2 = get_daily_close(oracle, pair, day_minus_2)?;
    let close_d3 = get_daily_close(oracle, pair, day_minus_3)?;

    // Need all three closed-day prices to detect a peak.
    if close_d1.is_zero() || close_d2.is_zero() || close_d3.is_zero() {
        return Ok(());
    }

    // Peak detection: D-3 < D-2 > D-1 (i.e., D-2 is the peak).
    if close_d3 < close_d2
        && close_d2 > close_d1
        && store_scurve_entry_inner(oracle, pair, day_minus_2, close_d2)?
    {
        let event = IOracle::ScurvePeakDetected {
            base: pair.address1(),
            quote: pair.address2(),
            peakPrice: close_d2,
            peakDay: day_minus_2,
        };
        let event_result = oracle
            .storage
            .emit_event(ORACLE_ADDRESS, event.encode_log_data());
        if oracle.ocomp_profile_ready.read()? {
            event_result?;
        }
    }

    Ok(())
}

/// Gets the closest exchange rate snapshot for a pair on a given day.
///
/// Scans snapshots backwards from the day end to find the last rate for that day.
fn get_daily_close(oracle: &OracleContract, pair: AddressPair, day_start: u64) -> Result<U256> {
    let day_end = day_start + DAY_SECONDS;
    let write_idx = oracle.snapshot_write_idx.read()?;
    let oldest_idx = oracle.snapshot_oldest_idx.read()?;

    let mut idx = write_idx;
    while idx > oldest_idx {
        idx -= 1;
        let ts = oracle.snapshot_timestamp.read(&idx)?;
        if ts < day_start {
            break;
        }
        if ts >= day_end {
            continue;
        }

        // Found a snapshot in this day - look for our pair
        let pc = oracle.snapshot_pair_count.read(&idx)?;
        let pair_map = oracle.snapshot_pair.get_nested(&idx);
        let rate_map = oracle.snapshot_rate.get_nested(&idx);

        for p in 0..pc {
            if pair_map.read_pair(&p)?.same_market(&pair) {
                return rate_map.read(&p);
            }
        }
    }

    Ok(U256::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COEN840_SCALE: u64 = 1_000_000;

    fn price6(whole: u64) -> U256 {
        U256::from(whole) * U256::from(COEN840_SCALE)
    }

    #[test]
    fn test_coefficients_boundary_values() {
        // COEN/840 coefficients use the same six-decimal denominator as prices.
        assert_eq!(COEFFICIENTS[0], U256::from(1_000_000u64));
        // Last coefficient is exactly 0.92.
        assert_eq!(COEFFICIENTS[127], U256::from(920_000u64));
        // Center (64) should be ~0.95998
        assert_eq!(COEFFICIENTS[64], U256::from(959_980u64));
    }

    #[test]
    fn coen840_coefficients_and_products_match_reference_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/coen840-scurve-v1.json")).unwrap();
        assert_eq!(vector["pair"], "COEN/840");
        assert_eq!(vector["coefficientScale"], COEN840_SCALE.to_string());
        assert_eq!(vector["rounding"], "floor");

        let coefficients = vector["coefficients"].as_array().unwrap();
        assert_eq!(coefficients.len(), PERIOD);
        for (index, expected) in coefficients.iter().enumerate() {
            let expected = expected.as_str().unwrap().parse::<u64>().unwrap();
            assert_eq!(
                COEFFICIENTS[index],
                U256::from(expected),
                "coefficient[{index}]"
            );
        }

        for pin in vector["productPins"].as_array().unwrap() {
            let index = pin["index"].as_u64().unwrap() as usize;
            let peak = pin["peakPrice"].as_str().unwrap().parse::<u64>().unwrap();
            let expected = pin["expected"].as_str().unwrap().parse::<u64>().unwrap();
            assert_eq!(
                compute_scurve_value(U256::from(peak), index),
                U256::from(expected),
                "product pin {index}"
            );
        }
    }

    #[test]
    fn test_coefficients_monotonically_decreasing() {
        for i in 1..PERIOD {
            assert!(
                COEFFICIENTS[i] <= COEFFICIENTS[i - 1],
                "coefficient[{}] > coefficient[{}]: {} > {}",
                i,
                i - 1,
                COEFFICIENTS[i],
                COEFFICIENTS[i - 1]
            );
        }
    }

    fn scale_floor(value: U256, factor: U256) -> U256 {
        let whole = value / SCALE_1E6_U256;
        let remainder = value % SCALE_1E6_U256;
        whole * factor + remainder * factor / SCALE_1E6_U256
    }

    fn period_anchor(mut peak: U256, periods: usize) -> U256 {
        for _ in 0..periods {
            peak = scale_floor(peak, COEFFICIENTS[PERIOD - 1]);
        }
        peak
    }

    fn expected_curve_value(peak: U256, day: usize) -> U256 {
        let anchor = period_anchor(peak, day / PERIOD);
        scale_floor(anchor, COEFFICIENTS[day % PERIOD])
    }

    #[test]
    fn curve_chains_across_periods() {
        let peak_price = price6(100);
        for day in [0, 127, 128, 255, 256, 383, 384, 1_000] {
            assert_eq!(
                compute_scurve_value(peak_price, day),
                expected_curve_value(peak_price, day),
                "day {day}"
            );
        }
        assert_eq!(
            compute_scurve_value(peak_price, 127),
            compute_scurve_value(peak_price, 128)
        );
        assert_eq!(
            compute_scurve_value(peak_price, 255),
            compute_scurve_value(peak_price, 256)
        );
        assert!(!compute_scurve_value(peak_price, 1_000).is_zero());
    }

    #[test]
    fn curve_math_does_not_overflow_to_zero() {
        let peak = U256::MAX;
        for day in [0, 1, 127, 128, 256, 1_000] {
            let value = compute_scurve_value(peak, day);
            assert_eq!(value, expected_curve_value(peak, day), "day {day}");
            assert!(!value.is_zero(), "day {day}");
            assert!(value <= peak, "day {day}");
        }
    }

    #[test]
    fn curve_preserves_fractional_precision() {
        // Test with a non-round peak price
        let peak = U256::from(18_343_660_000u64); // 18343.66 on the COEN/840 scale
        let val_day1 = compute_scurve_value(peak, 1);
        // Expected: 18343.66 * 0.999960180425626732 = ~18342.93 (approx)
        // The exact value depends on integer truncation
        assert!(val_day1 < peak);
        assert!(val_day1 > price6(18_342));
    }

    #[test]
    fn test_truncate_to_day() {
        // 2025-01-01 12:34:56 UTC
        let ts = 1735735696u64;
        let day = truncate_to_day(ts);
        assert_eq!(day % DAY_SECONDS, 0);
        assert!(day <= ts);
        assert!(ts - day < DAY_SECONDS);
    }

    #[test]
    fn stored_chain_remains_queryable_after_day_128() {
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);

            // Store an S-curve entry. Use day-aligned timestamps.
            let pair = register_test_pair(&mut oracle);
            let peak_day = truncate_to_day(1_000_000);
            let peak_price = price6(500);

            store_scurve_entry(&mut oracle, pair, peak_day, peak_price).unwrap();
            assert_eq!(oracle.scurve_count.read().unwrap(), 1);

            // Query value at peak day (day_index=0) -> should equal peak_price
            let val = get_max_active_scurve_value(&oracle, pair, peak_day).unwrap();
            assert_eq!(val, peak_price);

            // Query value at peak_day + 127 days -> should be ~92% of peak
            let far_future = peak_day + 127 * DAY_SECONDS;
            let val_127 = get_max_active_scurve_value(&oracle, pair, far_future).unwrap();
            assert_eq!(val_127, price6(460)); // 500 * 0.92 = 460

            let continued = peak_day + 128 * DAY_SECONDS;
            let value = get_max_active_scurve_value(&oracle, pair, continued).unwrap();
            assert_eq!(value, price6(460));

            let (days, prices, values) = get_scurve_entries(&oracle, pair, continued).unwrap();
            assert_eq!(days, vec![peak_day]);
            assert_eq!(prices, vec![peak_price]);
            assert_eq!(values, vec![price6(460)]);

            evict_expired_scurves(&mut oracle, continued).unwrap();
            assert_eq!(oracle.scurve_oldest_idx.read().unwrap(), 0);
            assert_eq!(
                get_max_active_scurve_value(&oracle, pair, continued).unwrap(),
                price6(460)
            );
        });
    }

    #[test]
    fn one_pair_owns_one_replaceable_chain() {
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);
            let pair = register_test_pair(&mut oracle);

            // A lower candidate is compared with the existing chain value at
            // the candidate day and is ignored.
            let peak1_day = truncate_to_day(1_000_000);
            let peak1_price = price6(100);
            store_scurve_entry(&mut oracle, pair, peak1_day, peak1_price).unwrap();

            let peak2_day = peak1_day + 10 * DAY_SECONDS;
            store_scurve_entry(&mut oracle, pair, peak2_day, price6(90)).unwrap();
            assert_eq!(oracle.scurve_count.read().unwrap(), 1);
            assert_eq!(oracle.scurve_peak_day.read(&0).unwrap(), peak1_day);

            // At day 128 the old chain is 92, so a new peak of 93 replaces
            // it even though it is lower than the original 100 peak.
            let replacement_day = peak1_day + 128 * DAY_SECONDS;
            let replacement_price = price6(93);
            store_scurve_entry(&mut oracle, pair, replacement_day, replacement_price).unwrap();
            assert_eq!(oracle.scurve_count.read().unwrap(), 1);
            assert_eq!(oracle.scurve_peak_day.read(&0).unwrap(), replacement_day);
            assert_eq!(
                oracle.scurve_peak_price.read(&0).unwrap(),
                replacement_price
            );
            assert_eq!(
                get_max_active_scurve_value(&oracle, pair, replacement_day).unwrap(),
                replacement_price
            );

            // Replays and lower peaks remain storage no-ops.
            store_scurve_entry(&mut oracle, pair, replacement_day, replacement_price).unwrap();
            store_scurve_entry(&mut oracle, pair, replacement_day + DAY_SECONDS, price6(80))
                .unwrap();
            assert_eq!(oracle.scurve_count.read().unwrap(), 1);
            assert_eq!(oracle.scurve_peak_day.read(&0).unwrap(), replacement_day);
        });
    }

    #[test]
    fn chains_are_isolated_by_pair() {
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);
            let usd = register_test_pair_with_iso(&mut oracle, 840);
            let eur = register_test_pair_with_iso(&mut oracle, 978);
            let peak_day = truncate_to_day(1_000_000);

            store_scurve_entry(&mut oracle, usd, peak_day, price6(100)).unwrap();
            store_scurve_entry(&mut oracle, eur, peak_day, price6(200)).unwrap();
            store_scurve_entry(&mut oracle, usd, peak_day + DAY_SECONDS, price6(150)).unwrap();

            assert_eq!(oracle.scurve_count.read().unwrap(), 2);
            assert_eq!(
                get_max_active_scurve_value(&oracle, usd, peak_day + DAY_SECONDS).unwrap(),
                price6(150)
            );
            assert_eq!(
                get_max_active_scurve_value(&oracle, eur, peak_day + DAY_SECONDS).unwrap(),
                compute_scurve_value(price6(200), 1)
            );
        });
    }

    // ===================================================================
    // Daily peak-detection window (regression tests).
    //
    // The daily hook fires on the FIRST block of the current UTC day, when
    // that day has no close yet. Detection therefore runs over fully-CLOSED
    // days only: D-3 < D-2 > D-1 confirms a peak on D-2. The previous
    // implementation used the just-started current day as a close, so
    // `close_d0` was zero at fire time and no runtime peak was ever stored.
    // ===================================================================

    /// Writes a single end-of-day snapshot so `get_daily_close` treats `rate`
    /// as that UTC day's close.
    /// Registers the canonical COEN/USD pair so snapshot writes can resolve an
    /// ordinal for it. Returns ordinal 1 as the first registration.
    fn register_test_pair_with_iso(oracle: &mut OracleContract, iso_code: u16) -> AddressPair {
        let quote: Address = crate::types::AssetType::IsoCurrency(iso_code).into();
        let pair = AddressPair::from_addresses(Address::ZERO, quote);
        oracle.register_pair(pair).unwrap();
        pair
    }

    fn register_test_pair(oracle: &mut OracleContract) -> AddressPair {
        register_test_pair_with_iso(oracle, 840)
    }

    fn write_daily_close(
        oracle: &mut OracleContract,
        pair: AddressPair,
        day_start: u64,
        rate: U256,
    ) {
        oracle
            .write_snapshot(day_start + 80_000, &[(pair, rate, price6(1))])
            .unwrap();
    }

    #[test]
    fn test_peak_detected_over_closed_days_without_current_day_data() {
        // Core regression: a peak on D-2 is detected at the start of D0 using
        // only closed days, regardless of whether the current day has data.
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);
            let pair = register_test_pair(&mut oracle);

            let d0 = truncate_to_day(1_700_000_000); // current day - empty at fire time
            let d1 = d0 - DAY_SECONDS;
            let d2 = d0 - 2 * DAY_SECONDS; // peak
            let d3 = d0 - 3 * DAY_SECONDS;

            write_daily_close(&mut oracle, pair, d3, price6(100));
            write_daily_close(&mut oracle, pair, d2, price6(120));
            write_daily_close(&mut oracle, pair, d1, price6(110));
            // intentionally NO D0 data - the fix must not depend on it

            process_daily_scurve(&mut oracle, pair, d0).unwrap();

            assert_eq!(oracle.scurve_count.read().unwrap(), 1);
            assert_eq!(oracle.scurve_peak_day.read(&0).unwrap(), d2);
            assert_eq!(oracle.scurve_peak_price.read(&0).unwrap(), price6(120));
        });
    }

    #[test]
    fn test_current_day_data_is_irrelevant() {
        // Whatever the current (incomplete) day shows must not change the
        // outcome - detection is over closed days only.
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);
            let pair = register_test_pair(&mut oracle);

            let d0 = truncate_to_day(1_700_000_000);
            let d1 = d0 - DAY_SECONDS;
            let d2 = d0 - 2 * DAY_SECONDS;
            let d3 = d0 - 3 * DAY_SECONDS;

            write_daily_close(&mut oracle, pair, d3, price6(100));
            write_daily_close(&mut oracle, pair, d2, price6(120));
            write_daily_close(&mut oracle, pair, d1, price6(110));
            // A spurious current-day tick that the old code would have consumed.
            write_daily_close(&mut oracle, pair, d0, price6(999));

            process_daily_scurve(&mut oracle, pair, d0).unwrap();

            assert_eq!(oracle.scurve_count.read().unwrap(), 1);
            assert_eq!(oracle.scurve_peak_day.read(&0).unwrap(), d2);
            assert_eq!(oracle.scurve_peak_price.read(&0).unwrap(), price6(120));
        });
    }

    #[test]
    fn test_no_peak_on_monotonic_closed_days() {
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);
            let pair = register_test_pair(&mut oracle);

            let d0 = truncate_to_day(1_700_000_000);
            let d1 = d0 - DAY_SECONDS;
            let d2 = d0 - 2 * DAY_SECONDS;
            let d3 = d0 - 3 * DAY_SECONDS;

            // Monotonic rising: no local max at D-2.
            write_daily_close(&mut oracle, pair, d3, price6(100));
            write_daily_close(&mut oracle, pair, d2, price6(110));
            write_daily_close(&mut oracle, pair, d1, price6(120));

            process_daily_scurve(&mut oracle, pair, d0).unwrap();

            assert_eq!(oracle.scurve_count.read().unwrap(), 0);
        });
    }

    #[test]
    fn test_no_detection_with_insufficient_history() {
        // Only two closed days available (D-3 missing) -> no peak, no panic.
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let mut oracle = OracleContract::new(storage);
            let pair = register_test_pair(&mut oracle);

            let d0 = truncate_to_day(1_700_000_000);
            let d1 = d0 - DAY_SECONDS;
            let d2 = d0 - 2 * DAY_SECONDS;

            write_daily_close(&mut oracle, pair, d2, price6(100));
            write_daily_close(&mut oracle, pair, d1, price6(120));
            // D-3 missing

            process_daily_scurve(&mut oracle, pair, d0).unwrap();

            assert_eq!(oracle.scurve_count.read().unwrap(), 0);
        });
    }
}
