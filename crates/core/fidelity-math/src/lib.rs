//! Fixed-point time-decay math for the Retention Component of Fidelity Index.
//!
//! Pure integer arithmetic (`SCALE = 10^18`), no `f32/f64`, deterministic across
//! nodes. Implements the spec curve `T_dec(T) = L * (1 - (1/2)^(T/H))` with
//! half-life `H = 365 days` and saturation limit `L = H/ln2 ~= 526.58 days`.
//!
//! `(1/2)^x` is evaluated by binary decomposition of the fractional part of `x`:
//! `(1/2)^x = (1/2)^k * prod_i ((1/2)^(2^-i))^{b_i}` where `k` is the integer part
//! and `b_i` the i-th fractional bit. The per-bit factors `(1/2)^(2^-i)` are the
//! precomputed [`HALF_POW_TABLE`] constants; the integer part is a right shift.
//! Validated against the PDF reference `decay.py` (errors ~1e-15 vs float64).

use alloy_primitives::U256;
use outbe_primitives::units::SCALE_1E18;

/// Fixed-point denominator (10^18).
pub(crate) const SCALE: U256 = SCALE_1E18;

/// Decimal precision of the fixed-point RCFI: `SCALE = 10^DECIMALS`, so a
/// `getRcfi` value of `10^18` represents one decayed day. Exposed externally via
/// `IFidelity.decimals()`.
pub const DECIMALS: u8 = 18;

/// Half-life in seconds (365 days). The decay ratio `T/H` is computed in
/// seconds so sub-day precision is preserved.
pub(crate) const H_SEC: u64 = 365 * 86_400;

/// Saturation limit `L = H / ln2` in fixed-point decayed-days
/// (~= 526.583690 days). `526583689924471619584 = round(365/ln2 * 10^18)`.
pub(crate) const L_FP: U256 = U256::from_limbs([10074855860604174336, 28, 0, 0]);
/// Inclusive bounds of the Fidelity league scale. A valid league is always in
/// `[MIN_LEAGUE, MAX_LEAGUE]`; the derivation from RCFI lives in
/// [`league_from_rcfi`]. Public so consumers (and fixtures) reference the
/// canonical range instead of hard-coding it.
pub const MIN_LEAGUE: u16 = 1;
pub const MAX_LEAGUE: u16 = 4096;

/// Public (not `pub(crate)`): the TEE enclave engine accumulates RCFI over
/// decrypted cohorts with the exact same arithmetic, so this is the single
/// source of truth shared by the on-chain and in-enclave evaluation paths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RcfiAccumulator {
    numerator: U256,
    denominator: U256,
}

impl RcfiAccumulator {
    pub fn add_active(&mut self, size: U256, acquired_at: u64, timestamp: u64) -> Option<()> {
        let contribution = size.checked_mul(t_dec(timestamp.saturating_sub(acquired_at)))?;
        self.numerator = self.numerator.checked_add(contribution)?;
        self.denominator = self.denominator.checked_add(contribution)?;
        Some(())
    }

    pub fn add_sold(
        &mut self,
        size: U256,
        acquired_at: u64,
        sold_at: u64,
        timestamp: u64,
    ) -> Option<()> {
        let held = t_dec(timestamp.saturating_sub(acquired_at))
            .saturating_sub(t_dec(timestamp.saturating_sub(sold_at)));
        self.denominator = self.denominator.checked_add(size.checked_mul(held)?)?;
        Some(())
    }

    pub fn finish(self, qualified_start: u64, timestamp: u64) -> Option<(U256, U256, U256)> {
        if qualified_start == 0 {
            return Some((U256::ZERO, U256::ZERO, U256::ZERO));
        }
        let d_dec_age = t_dec(timestamp.saturating_sub(qualified_start));
        let efficiency = if self.denominator.is_zero() {
            U256::ZERO
        } else {
            self.numerator.checked_mul(SCALE)? / self.denominator
        };
        let rcfi = d_dec_age.checked_mul(efficiency)? / SCALE;
        Some((rcfi, efficiency, d_dec_age))
    }
}

pub fn league_from_rcfi(rcfi: U256, maximum_rcfi: U256) -> Option<u16> {
    if maximum_rcfi.is_zero() {
        return Some(MIN_LEAGUE);
    }
    let slot = rcfi.checked_mul(U256::from(MAX_LEAGUE))? / maximum_rcfi;
    Some(MIN_LEAGUE + slot.min(U256::from(MAX_LEAGUE - 1)).to::<u16>())
}

/// `HALF_POW_TABLE[i] = round((1/2)^(2^-(i+1)) * 10^18)` for `i = 0..=62`,
/// i.e. the factor applied when the `2^-(i+1)` fractional bit of `x` is set.
/// Computed offline with 60-digit precision (see `reference/decay.py`).
pub(crate) const HALF_POW_TABLE: [U256; 63] = [
    U256::from_limbs([707106781186547524, 0, 0, 0]),
    U256::from_limbs([840896415253714543, 0, 0, 0]),
    U256::from_limbs([917004043204671232, 0, 0, 0]),
    U256::from_limbs([957603280698573647, 0, 0, 0]),
    U256::from_limbs([978572062087700135, 0, 0, 0]),
    U256::from_limbs([989228013193975484, 0, 0, 0]),
    U256::from_limbs([994599423483633176, 0, 0, 0]),
    U256::from_limbs([997296056085470126, 0, 0, 0]),
    U256::from_limbs([998647112890970174, 0, 0, 0]),
    U256::from_limbs([999323327502650752, 0, 0, 0]),
    U256::from_limbs([999661606496243684, 0, 0, 0]),
    U256::from_limbs([999830788931929063, 0, 0, 0]),
    U256::from_limbs([999915390886613498, 0, 0, 0]),
    U256::from_limbs([999957694548431133, 0, 0, 0]),
    U256::from_limbs([999978847050491930, 0, 0, 0]),
    U256::from_limbs([999989423469314464, 0, 0, 0]),
    U256::from_limbs([999994711720674283, 0, 0, 0]),
    U256::from_limbs([999997355856841395, 0, 0, 0]),
    U256::from_limbs([999998677927546760, 0, 0, 0]),
    U256::from_limbs([999999338963554895, 0, 0, 0]),
    U256::from_limbs([999999669481722826, 0, 0, 0]),
    U256::from_limbs([999999834740847758, 0, 0, 0]),
    U256::from_limbs([999999917370420465, 0, 0, 0]),
    U256::from_limbs([999999958685209379, 0, 0, 0]),
    U256::from_limbs([999999979342604476, 0, 0, 0]),
    U256::from_limbs([999999989671302185, 0, 0, 0]),
    U256::from_limbs([999999994835651079, 0, 0, 0]),
    U256::from_limbs([999999997417825536, 0, 0, 0]),
    U256::from_limbs([999999998708912767, 0, 0, 0]),
    U256::from_limbs([999999999354456383, 0, 0, 0]),
    U256::from_limbs([999999999677228192, 0, 0, 0]),
    U256::from_limbs([999999999838614096, 0, 0, 0]),
    U256::from_limbs([999999999919307048, 0, 0, 0]),
    U256::from_limbs([999999999959653524, 0, 0, 0]),
    U256::from_limbs([999999999979826762, 0, 0, 0]),
    U256::from_limbs([999999999989913381, 0, 0, 0]),
    U256::from_limbs([999999999994956690, 0, 0, 0]),
    U256::from_limbs([999999999997478345, 0, 0, 0]),
    U256::from_limbs([999999999998739173, 0, 0, 0]),
    U256::from_limbs([999999999999369586, 0, 0, 0]),
    U256::from_limbs([999999999999684793, 0, 0, 0]),
    U256::from_limbs([999999999999842397, 0, 0, 0]),
    U256::from_limbs([999999999999921198, 0, 0, 0]),
    U256::from_limbs([999999999999960599, 0, 0, 0]),
    U256::from_limbs([999999999999980300, 0, 0, 0]),
    U256::from_limbs([999999999999990150, 0, 0, 0]),
    U256::from_limbs([999999999999995075, 0, 0, 0]),
    U256::from_limbs([999999999999997537, 0, 0, 0]),
    U256::from_limbs([999999999999998769, 0, 0, 0]),
    U256::from_limbs([999999999999999384, 0, 0, 0]),
    U256::from_limbs([999999999999999692, 0, 0, 0]),
    U256::from_limbs([999999999999999846, 0, 0, 0]),
    U256::from_limbs([999999999999999923, 0, 0, 0]),
    U256::from_limbs([999999999999999962, 0, 0, 0]),
    U256::from_limbs([999999999999999981, 0, 0, 0]),
    U256::from_limbs([999999999999999990, 0, 0, 0]),
    U256::from_limbs([999999999999999995, 0, 0, 0]),
    U256::from_limbs([999999999999999998, 0, 0, 0]),
    U256::from_limbs([999999999999999999, 0, 0, 0]),
    U256::from_limbs([999999999999999999, 0, 0, 0]),
    U256::from_limbs([1000000000000000000, 0, 0, 0]),
    U256::from_limbs([1000000000000000000, 0, 0, 0]),
    U256::from_limbs([1000000000000000000, 0, 0, 0]),
];

/// Computes `(1/2)^x * SCALE` for `x = x_fp / SCALE` (`x >= 0`).
///
/// Splits `x` into integer part `k` (a right shift) and fractional part, then
/// folds in one [`HALF_POW_TABLE`] factor per set fractional bit, MSB-first.
pub(crate) fn pow_one_half_fp(x_fp: U256) -> U256 {
    let k = x_fp / SCALE;
    // Past 256 halvings the result underflows fixed-point to zero.
    if k >= U256::from(256u64) {
        return U256::ZERO;
    }
    let two = U256::from(2u64);
    let mut frac = x_fp % SCALE;
    let mut result = SCALE;
    // Iterate factors for fractional bits 2^-1, 2^-2, ... extracting each bit by
    // doubling `frac` and testing the carry past SCALE.
    for &factor in HALF_POW_TABLE.iter() {
        frac *= two;
        if frac >= SCALE {
            frac -= SCALE;
            result = result * factor / SCALE;
        }
    }
    result >> k.to::<u64>() as usize
}

/// Decayed time `T_dec(age) = L * (1 - (1/2)^(age/H))` in fixed-point
/// decayed-days. `age_sec` is the elapsed time since the event in seconds;
/// callers must clamp clock skew (`now < event_time`) to `0` before calling.
pub fn t_dec(age_sec: u64) -> U256 {
    if age_sec == 0 {
        return U256::ZERO;
    }
    let x_fp = U256::from(age_sec) * SCALE / U256::from(H_SEC);
    let half = pow_one_half_fp(x_fp);
    // half <= SCALE always, so the subtraction never underflows.
    L_FP * (SCALE - half) / SCALE
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn days(fp: U256) -> f64 {
        // fixed-point decayed-days -> f64 for tolerance checks only.
        let scaled: u128 = (fp * U256::from(1_000_000u64) / SCALE).to::<u128>();
        scaled as f64 / 1_000_000.0
    }

    #[test]
    fn pow_one_half_edge_values() {
        assert_eq!(pow_one_half_fp(U256::ZERO), SCALE); // (1/2)^0 = 1
        assert_eq!(pow_one_half_fp(SCALE), SCALE / U256::from(2u64)); // (1/2)^1 = 0.5
                                                                      // (1/2)^k == SCALE >> k
        assert_eq!(
            pow_one_half_fp(U256::from(4u64) * SCALE),
            SCALE >> 4usize // 0.0625
        );
        assert_eq!(pow_one_half_fp(U256::from(256u64) * SCALE), U256::ZERO);
        assert_eq!(pow_one_half_fp(U256::from(1000u64) * SCALE), U256::ZERO);
    }

    #[test]
    fn t_dec_spec_checkpoints() {
        // From the PDF / decay.py reference benchmark.
        assert_eq!(t_dec(0), U256::ZERO);
        assert!((days(t_dec(365 * DAY)) - 263.2918).abs() < 0.001); // 0.5 L
        assert!((days(t_dec(730 * DAY)) - 394.9378).abs() < 0.001); // 0.75 L
        assert!((days(t_dec(1460 * DAY)) - 493.6722).abs() < 0.001); // 4 years, 0.9375 L
    }

    #[test]
    fn t_dec_saturates_at_l() {
        // Ancient ages saturate at L (526.58 days) and never exceed it.
        let ancient = t_dec(100 * 365 * DAY);
        assert!(ancient <= L_FP);
        assert!((days(ancient) - 526.5837).abs() < 0.001);
    }

    #[test]
    fn t_dec_is_monotonic_non_decreasing() {
        let mut prev = U256::ZERO;
        for d in [0u64, 1, 10, 100, 365, 730, 1460, 3650, 36500] {
            let cur = t_dec(d * DAY);
            assert!(cur >= prev, "t_dec decreased at {d} days");
            prev = cur;
        }
    }
}
