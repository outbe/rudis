//! Closed-form two-phase day emission cap.
//!
//! The curve rises from 2^28 COEN to `P` through day 1024, then falls to
//! 2^26 COEN on day 3072. From that day onward it returns the permanent
//! `FLOOR_DAY_EMISSION`.
//!
//! Consensus execution uses deterministic U256 fixed-point arithmetic. The
//! committed reference vectors are generated independently with Python
//! `Decimal` arithmetic.

use alloy_primitives::{uint, U256};
use std::sync::LazyLock;

/// Initial day emission: 2^28 COEN expressed in six-decimal `unit`.
pub const INITIAL_DAY_EMISSION: U256 = uint!(268_435_456_000_000_U256);

/// Floor day emission: 2^26 COEN expressed in six-decimal `unit`.
pub const FLOOR_DAY_EMISSION: U256 = uint!(67_108_864_000_000_U256);

/// The founder curve reaches 2^26 COEN on this day and stays there forever.
pub const FLOOR_DAY_THRESHOLD: u32 = 3_072;

const UNITS_PER_COEN: U256 = uint!(1_000_000_U256);

// Every reachable exponential has |x| <= 4. With terms 0..=64, the real
// Taylor remainder is below 9.1e-51; the 1e30 fixed-point scale still leaves
// more than fourteen decimal guard digits beyond the protocol's 1e-6 unit.
// The largest amount-domain multiplication is below 6e74, over 190 times
// below U256::MAX. Any formula/scale change must re-establish both bounds and
// regenerate the exhaustive reference vector.
const MATH_SCALE: U256 = uint!(1_000_000_000_000_000_000_000_000_000_000_U256);
const EXP_TAYLOR_TERMS: u32 = 64;
const K1: u32 = 128;
const K2: u32 = K1 * 3;
const PHASE_ONE_MIDPOINT_DAY: u32 = 512;
const PHASE_SPLIT_DAY: u32 = 1_024;
const PHASE_TWO_MIDPOINT_DAY: u32 = 2_048;

// Founder formula (kept symbolically, rather than replacing it with
// precomputed constants):
//
// P  = 26 * 2**26 / 3
// K1 = 128
// K2 = K1 * 3
// A  = (P - 2**28) / math.tanh(512/(2*K1))
// o1 = (2**28 + P)/2 - A/2
// D  = (P - 2**26) / math.tanh(1024/(2*K2))
// o2 = (P + 2**26)/2 + D/2
static TWO_26: LazyLock<U256> =
    LazyLock::new(|| U256::from(1u64 << 26) * UNITS_PER_COEN * MATH_SCALE);
static TWO_28: LazyLock<U256> =
    LazyLock::new(|| U256::from(1u64 << 28) * UNITS_PER_COEN * MATH_SCALE);
static P: LazyLock<U256> = LazyLock::new(|| U256::from(26) * *TWO_26 / U256::from(3));
static A: LazyLock<U256> = LazyLock::new(|| {
    fixed_div(
        *P - *TWO_28,
        tanh_positive_ratio(PHASE_ONE_MIDPOINT_DAY, 2 * K1),
    )
});
static O1: LazyLock<U256> = LazyLock::new(|| (*TWO_28 + *P) / U256::from(2) - *A / U256::from(2));
static D: LazyLock<U256> =
    LazyLock::new(|| fixed_div(*P - *TWO_26, tanh_positive_ratio(PHASE_SPLIT_DAY, 2 * K2)));
static O2: LazyLock<U256> = LazyLock::new(|| (*P + *TWO_26) / U256::from(2) + *D / U256::from(2));

fn exp_positive_ratio(numerator: u32, denominator: u32) -> U256 {
    let x = U256::from(numerator) * MATH_SCALE / U256::from(denominator);
    let mut sum = MATH_SCALE;
    let mut term = MATH_SCALE;

    for index in 1..=EXP_TAYLOR_TERMS {
        term = term * x / (MATH_SCALE * U256::from(index));
        if term.is_zero() {
            break;
        }
        sum += term;
    }

    sum
}

fn exp_signed_ratio(numerator: i64, denominator: u32) -> U256 {
    if numerator >= 0 {
        exp_positive_ratio(numerator as u32, denominator)
    } else {
        MATH_SCALE * MATH_SCALE / exp_positive_ratio(numerator.unsigned_abs() as u32, denominator)
    }
}

fn tanh_positive_ratio(numerator: u32, denominator: u32) -> U256 {
    let exp_twice_x = exp_positive_ratio(numerator * 2, denominator);
    (exp_twice_x - MATH_SCALE) * MATH_SCALE / (exp_twice_x + MATH_SCALE)
}

fn fixed_div(value: U256, divisor: U256) -> U256 {
    value * MATH_SCALE / divisor
}

/// Returns the day emission cap for `day_number` days since the chain's
/// genesis UTC day. Closed-form, no storage I/O, pure function. The result is
/// rounded down to the protocol's six-decimal unit and floor-clamped forever
/// once `day_number >= FLOOR_DAY_THRESHOLD`.
pub fn day_emission_limit(day_number: u32) -> U256 {
    if day_number >= FLOOR_DAY_THRESHOLD {
        return FLOOR_DAY_EMISSION;
    }
    if day_number == 0 {
        return INITIAL_DAY_EMISSION;
    }

    // The first access initializes the private values once in dependency order:
    // P -> A -> O1 -> D -> O2. Later calls only read the stored values.
    let a = *A;
    let o1 = *O1;
    let d = *D;
    let o2 = *O2;

    let emission = if day_number <= PHASE_SPLIT_DAY {
        let exponent = exp_signed_ratio(
            i64::from(PHASE_ONE_MIDPOINT_DAY) - i64::from(day_number),
            K1,
        );
        o1 + a * MATH_SCALE / (MATH_SCALE + exponent)
    } else {
        let exponent = exp_signed_ratio(
            i64::from(PHASE_TWO_MIDPOINT_DAY) - i64::from(day_number),
            K2,
        );
        o2 - d * MATH_SCALE / (MATH_SCALE + exponent)
    };
    let reward = emission / MATH_SCALE;
    if reward < FLOOR_DAY_EMISSION {
        FLOOR_DAY_EMISSION
    } else {
        reward
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE_VECTORS: &str = include_str!("../testdata/vectors.json");
    const PIN_DAY_0: U256 = uint!(268_435_456_000_000_U256);
    const PIN_DAY_1: U256 = uint!(268_480_452_713_195_U256);
    const PIN_DAY_365: U256 = uint!(340_810_652_554_498_U256);
    const PIN_DAY_512: U256 = uint!(425_022_805_333_333_U256);
    const PIN_DAY_730: U256 = uint!(537_405_916_355_515_U256);
    const PIN_DAY_1024: U256 = uint!(581_610_154_666_666_U256);
    const PIN_DAY_1025: U256 = uint!(581_516_499_768_072_U256);
    const PIN_DAY_1460: U256 = uint!(514_882_469_694_896_U256);
    const PIN_DAY_2048: U256 = uint!(324_359_509_333_333_U256);
    const PIN_DAY_2190: U256 = uint!(270_306_028_209_700_U256);
    const PIN_DAY_2919: U256 = uint!(84_150_920_679_186_U256);
    const PIN_DAY_2920: U256 = uint!(84_020_175_581_053_U256);
    const PIN_DAY_3071: U256 = uint!(67_202_518_898_594_U256);
    const PIN_DAY_3072: U256 = uint!(67_108_864_000_000_U256);

    fn reference_days() -> Vec<(u32, U256)> {
        let value: serde_json::Value =
            serde_json::from_str(REFERENCE_VECTORS).expect("independent emission vectors parse");
        value["days"]
            .as_array()
            .expect("days is an array")
            .iter()
            .map(|row| {
                let day =
                    u32::try_from(row["day"].as_u64().expect("day is u64")).expect("day fits u32");
                let emission = U256::from_str_radix(
                    row["emission_units"]
                        .as_str()
                        .expect("emission_units is a decimal string"),
                    10,
                )
                .expect("emission_units fits U256");
                (day, emission)
            })
            .collect()
    }

    #[test]
    fn founder_curve_checkpoints_match_independent_reference() {
        for (day, expected) in [
            (0, PIN_DAY_0),
            (1, PIN_DAY_1),
            (365, PIN_DAY_365),
            (512, PIN_DAY_512),
            (730, PIN_DAY_730),
            (1024, PIN_DAY_1024),
            (1025, PIN_DAY_1025),
            (1460, PIN_DAY_1460),
            (2048, PIN_DAY_2048),
            (2190, PIN_DAY_2190),
            (2919, PIN_DAY_2919),
            (2920, PIN_DAY_2920),
            (3071, PIN_DAY_3071),
            (3072, PIN_DAY_3072),
        ] {
            assert_eq!(day_emission_limit(day), expected, "day {day}");
        }
    }

    #[test]
    fn floor_clamp_at_and_beyond_threshold() {
        assert_eq!(FLOOR_DAY_THRESHOLD, 3_072);
        assert_eq!(day_emission_limit(FLOOR_DAY_THRESHOLD), PIN_DAY_3072);
        assert_eq!(day_emission_limit(FLOOR_DAY_THRESHOLD + 1), PIN_DAY_3072);
        assert_eq!(day_emission_limit(u32::MAX), PIN_DAY_3072);
    }

    #[test]
    fn independent_reference_is_contiguous_two_phase_and_floor_clamped() {
        let days = reference_days();
        assert_eq!(days.len(), FLOOR_DAY_THRESHOLD as usize + 1);
        for (index, (day, value)) in days.iter().copied().enumerate() {
            assert_eq!(day as usize, index, "reference day sequence");
            if let Some((_, previous)) = index.checked_sub(1).map(|i| days[i]) {
                if day <= 1_024 {
                    assert!(
                        value >= previous,
                        "reference decreases before P at day {day}"
                    );
                } else {
                    assert!(
                        value <= previous,
                        "reference increases after P at day {day}"
                    );
                }
            }
        }
        assert_eq!(
            days.last().copied(),
            Some((FLOOR_DAY_THRESHOLD, PIN_DAY_3072))
        );
    }

    #[test]
    fn production_matches_independent_reference_for_full_range() {
        for (day, expected) in reference_days() {
            assert_eq!(day_emission_limit(day), expected, "day {day}");
        }
    }

    #[test]
    fn production_rises_to_p_then_falls_to_the_floor() {
        let mut previous = day_emission_limit(0);
        for day in 1..=FLOOR_DAY_THRESHOLD {
            let current = day_emission_limit(day);
            if day <= 1_024 {
                assert!(
                    current >= previous,
                    "production decreases before P at day {day}"
                );
            } else {
                assert!(
                    current <= previous,
                    "production increases after P at day {day}"
                );
            }
            previous = current;
        }
    }
}
