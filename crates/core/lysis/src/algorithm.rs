use alloy_primitives::ruint::UintTryTo;
use alloy_primitives::{Uint, I256, U256};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::units::{SCALE_1E6_U128, SCALE_1E6_U256};

pub(crate) const SCALE_U128: u128 = SCALE_1E6_U128;
pub(crate) const SCALE: U256 = SCALE_1E6_U256;

/// Wide integer used solely to hold the worst-case `fp_root` intermediate.
type U1024 = Uint<1024, 16>;

pub(crate) const fn u256_from_u128(v: u128) -> U256 {
    U256::from_limbs([v as u64, (v >> 64) as u64, 0, 0])
}

/// Policy parameters (fixed-point, denominator = 1000).
/// a=0.2 -> 200/1000, b=0.1 -> 100/1000, c=0.2 -> 200/1000
const POLICY_A_NUM: u32 = 1;
const POLICY_A_DEN: u32 = 5; // a = 1/5 -> x^(1/5)
const POLICY_B_NUM: u32 = 1;
const POLICY_B_DEN: u32 = 10; // b = 1/10 -> x^(1/10)
const POLICY_C: U256 = u256_from_u128(SCALE_U128 * 2 / 10); // 0.2 * SCALE

// ---------------------------------------------------------------------------
// Fixed-point nth root
// ---------------------------------------------------------------------------

/// Fixed-point fractional power: (x_fp)^(p/q) where x_fp = x * SCALE.
/// Returns y = x^(p/q) * SCALE.
///
/// For p=1, q=5 (x^0.2): y^5 = x * SCALE^5, so y = (x * SCALE^5)^(1/5).
/// We use y = (x_fp * SCALE^(q-1))^(1/q) for p=1.
fn fp_root(x_fp: U256, _p: u32, q: u32) -> Result<U256> {
    if x_fp.is_zero() {
        return Ok(U256::ZERO);
    }
    if x_fp == SCALE {
        return Ok(SCALE); // 1.0^anything = 1.0
    }

    let scale_w = U1024::from(SCALE);
    let one = U1024::from(1u64);
    let two = U1024::from(2u64);

    // For p=1: y^q = x_fp * SCALE^(q-1). Built in U1024 so the scale-stacking
    // cannot wrap; `checked_mul` turns the by-width-impossible overflow into a
    // structured revert instead of masking it mod 2^256.
    let mut target = U1024::from(x_fp);
    for _ in 0..(q - 1) {
        target = target.checked_mul(scale_w).ok_or_else(|| {
            PrecompileError::Revert("lysis: fp_root intermediate overflow".to_string())
        })?;
    }
    // Search bound: a partial power above 2*target means `mid` is too big.
    // In-use targets sit far inside U1024; saturate the search bound defensively.
    let target2 = target.saturating_mul(two);

    // Binary search for y such that y^q <= target (all in U1024).
    let mut lo = one;
    let mut hi = U1024::from(x_fp).max(scale_w); // upper bound
    while lo < hi {
        let mid = lo + (hi - lo + one) / two;
        let mut mid_pow = mid;
        let mut overflow = false;
        for _ in 1..q {
            let (new_val, of) = mid_pow.overflowing_mul(mid);
            if of || new_val > target2 {
                overflow = true;
                break;
            }
            mid_pow = new_val;
        }
        if overflow || mid_pow > target {
            hi = mid - one;
        } else {
            lo = mid;
        }
    }

    // The root is small (`~= 10^6`); narrow it back with a checked conversion
    // rather than a silent truncation.
    let y: U256 = lo
        .uint_try_to()
        .map_err(|_| PrecompileError::Revert("lysis: fp_root result exceeds U256".to_string()))?;
    Ok(y)
}

// ---------------------------------------------------------------------------
// Fixed-point policy tau computation
// ---------------------------------------------------------------------------

/// Compute tau weights (Eq. 3.54) in fixed-point.
/// tau[i] = (i-0.5)^a / min(pi^b, pi_prev^b) for i in 1..N-1
/// tau[0] = c * sum_middle, tau[N] = (1-c) * sum_middle
fn policy_tau_fp(p: &[u64], nt: usize) -> Result<Vec<U256>> {
    let ng = p.len();
    let mut tau = vec![U256::ZERO; ng + 1];

    for i in 1..ng {
        let pi = p[i];
        let pi_prev = p[i - 1];

        if pi != 0 && pi_prev != 0 {
            // (i - 0.5) in fixed-point: (2*i - 1) * SCALE / 2
            let i_minus_half_fp = U256::from(2 * i as u64 - 1) * SCALE / U256::from(2u64);

            // (i-0.5)^(1/5) in fixed-point
            let numerator = fp_root(i_minus_half_fp, POLICY_A_NUM, POLICY_A_DEN)?;

            // pi^(1/10) and pi_prev^(1/10) in fixed-point
            let pi_fp = U256::from(pi) * SCALE;
            let pi_prev_fp = U256::from(pi_prev) * SCALE;
            let pi_root = fp_root(pi_fp, POLICY_B_NUM, POLICY_B_DEN)?;
            let pi_prev_root = fp_root(pi_prev_fp, POLICY_B_NUM, POLICY_B_DEN)?;

            let min_val = pi_root.min(pi_prev_root);

            if !min_val.is_zero() {
                // tau[i] = numerator / min_val (both in SCALE)
                tau[i] = numerator * SCALE / min_val;
            } else {
                // Fallback: ng^a * nt^b
                tau[i] = fallback_tau(ng, nt)?;
            }
        } else {
            // Fallback
            tau[i] = fallback_tau(ng, nt)?;
        }
    }

    let sum_middle: U256 = tau[1..ng].iter().copied().sum();
    tau[0] = POLICY_C * sum_middle / SCALE;
    tau[ng] = (SCALE - POLICY_C) * sum_middle / SCALE;

    Ok(tau)
}

/// Fallback tau weight `ng^(1/5) * nt^(1/10)` used when a group has zero
/// population or a zero root divisor. Extracted so the two call sites share one
/// implementation (both roots are computed via the overflow-safe [`fp_root`]).
fn fallback_tau(ng: usize, nt: usize) -> Result<U256> {
    let ng_fp = U256::from(ng as u64) * SCALE;
    let nt_fp = U256::from(nt as u64) * SCALE;
    let ng_root = fp_root(ng_fp, POLICY_A_NUM, POLICY_A_DEN)?;
    let nt_root = fp_root(nt_fp, POLICY_B_NUM, POLICY_B_DEN)?;
    Ok(ng_root * nt_root / SCALE)
}

// ---------------------------------------------------------------------------
// Simplified moments (kappa = 0)
// ---------------------------------------------------------------------------

struct MomentsFp {
    m: Vec<U256>,     // mass weights (sum = SCALE)
    y_cum: Vec<U256>, // cumulative Y (0 to SCALE)
    ey: U256,         // E[Y] in SCALE
    var_y: U256,      // Var[Y] in SCALE (may be 0)
}

fn compute_moments_fp(y_fp: &[U256], tau: &[U256]) -> MomentsFp {
    let t_total: U256 = tau.iter().copied().sum();

    // m[i] = tau[i] * SCALE / t_total (normalized mass)
    let m: Vec<U256> = if !t_total.is_zero() {
        tau.iter().map(|&t| t * SCALE / t_total).collect()
    } else {
        vec![U256::ZERO; tau.len()]
    };

    // Y cumulative sum of y_fp (y_fp sums to SCALE)
    let mut y_cum = vec![U256::ZERO; y_fp.len() + 1];
    let mut cum = U256::ZERO;
    for (i, &val) in y_fp.iter().enumerate() {
        cum += val;
        y_cum[i + 1] = cum;
    }
    // Ensure last = SCALE
    *y_cum.last_mut().unwrap() = SCALE;

    // E[Y] and E[Y^2]. Intermediates fit in U256: m, y_cum <= SCALE ~= 2^60, so
    // `m * y * y` <= 2^180 - well under U256::MAX.
    let mut ey = U256::ZERO;
    let mut ey2 = U256::ZERO;
    for i in 0..m.len() {
        let mi = m[i];
        let yi = y_cum[i];
        ey += mi * yi / SCALE;
        ey2 += mi * yi * yi / (SCALE * SCALE);
    }

    // var_y = E[Y^2] - E[Y]^2 / SCALE
    let ey_sq = ey * ey / SCALE;
    let var_y = ey2.saturating_sub(ey_sq);

    MomentsFp {
        m,
        y_cum,
        ey,
        var_y,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Computes lysis fractions for each FI group using fixed-point integer math.
///
/// # Parameters
/// - `y_fp`: interest share per FI group in fixed-point (sum = SCALE, sorted ascending FI).
///   Caller is responsible for normalization - integer-division truncation must
///   be absorbed before this call.
/// - `p`: population counts per FI group
/// - `nt`: total tribute count
/// - `f_fp`: target fraction in fixed-point (SCALE-based)
/// - `fmax_fp`: maximum fraction in fixed-point (SCALE-based)
///
/// # Returns
/// Fraction per FI group in fixed-point (SCALE-based).
///
/// # Post-condition
/// `sum(f1[i] * y_fp[i]) / SCALE <= f_fp` - weighted expenditure never exceeds
/// the target allocation. Fractions are scaled down monotonically if the raw
/// algorithm output would overshoot; relative ratios between groups are preserved.
///
/// # Errors
/// Returns `PrecompileError::Revert` if a signed-int conversion fails at a
/// boundary (impossible under current bounds; see overflow analysis in tests).
pub fn calc_fraction_distribution_fp(
    y_fp: &[U256],
    p: &[u64],
    nt: usize,
    f_fp: U256,
    fmax_fp: U256,
) -> Result<Vec<U256>> {
    if p.is_empty() {
        return Ok(vec![U256::ZERO]);
    }
    if p.len() == 1 {
        return Ok(vec![f_fp]);
    }

    let tau = policy_tau_fp(p, nt)?;
    let moments = compute_moments_fp(y_fp, &tau);

    // With kappa=0: alpha=0, so:
    // beta = (f/fmax - E[Y]) / Var[Y]
    // f1[i] = fmax * sum_{j>=i} m[j] * (1 + beta * (Y[j] - E[Y]))

    // signed I256 arithmetic throughout - no intermediate scale-down.
    // All unsigned inputs are <= SCALE (10^6), far under I256::MAX (~5.8*10^76),
    // so try_from conversions cannot fail in practice; we still return a
    // structured Fatal instead of panicking per CLAUDE.md rules.
    let f_over_fmax = (f_fp * SCALE).checked_div(fmax_fp).unwrap_or(U256::ZERO);
    let scale_i = u256_to_i256(SCALE)?;
    let ey_i = u256_to_i256(moments.ey)?;
    let beta_num_i = u256_to_i256(f_over_fmax)? - ey_i;
    let beta_den_i = u256_to_i256(moments.var_y)?;
    let fmax_i = u256_to_i256(fmax_fp)?;

    let n = y_fp.len();
    let mut f1 = vec![U256::ZERO; n];

    for i in 1..=n {
        let mut sum_i = I256::ZERO;
        for j in i..moments.m.len() {
            let y_cum_i = u256_to_i256(moments.y_cum[j])?;
            let y_diff = y_cum_i - ey_i;
            let beta_term = if beta_den_i > I256::ZERO {
                beta_num_i * y_diff / beta_den_i
            } else {
                I256::ZERO
            };
            // factor = SCALE + beta_term (in SCALE units) - exact, no scale-down.
            let factor = scale_i + beta_term;
            let mj_i = u256_to_i256(moments.m[j])?;
            sum_i += mj_i * factor / scale_i;
        }

        // f1[i] = fmax * sum / SCALE - exact; clamp negative to 0.
        let result = fmax_i * sum_i / scale_i;
        f1[i - 1] = if result <= I256::ZERO {
            U256::ZERO
        } else {
            i256_to_u256_clamped(result)
        };
    }

    // normalize f1 so weighted expenditure does not exceed f_fp.
    // Raw algorithm output can have `sum(f1[i] * y_fp[i]) / SCALE > f_fp` because
    // the per-group distribution doesn't enforce a budget-preserving invariant
    // on its own. Scale down proportionally (monotone, preserves ratios, never
    // rounds up) so downstream `gratis_load = fraction * nominal / SCALE` in
    // `lysis::runtime` cannot overspend the allocation and silently skip the
    // tail of the tribute list.
    let weighted_total: U256 = f1
        .iter()
        .zip(y_fp.iter())
        .map(|(f, y)| *f * *y / SCALE)
        .sum();
    if weighted_total > f_fp {
        for f in f1.iter_mut() {
            *f = *f * f_fp / weighted_total;
        }
    }

    Ok(f1)
}

fn u256_to_i256(value: U256) -> Result<I256> {
    I256::try_from(value).map_err(|_| {
        PrecompileError::Revert(format!("lysis: U256 -> I256 conversion overflow ({value})"))
    })
}

/// Narrow a positive `I256` back to `U256`. Negative inputs clamp to zero;
/// positive `I256` always fits in `U256` (positive range is `[0, 2^255)`,
/// strictly contained in `U256`).
fn i256_to_u256_clamped(value: I256) -> U256 {
    U256::try_from(value).unwrap_or(U256::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The symbolic share as a day-average fraction, and the per-league ceiling twice that.
    /// Production derives both from the day; these only feed the tests below.
    const F_FP_DEFAULT: U256 = u256_from_u128(SCALE_U128 * 32 / 100);
    const F_MAX_FP: U256 = u256_from_u128(SCALE_U128 * 64 / 100);

    /// Compute floor(base^exp) for u128, saturating on overflow.
    fn pow_u128(base: u128, exp: u32) -> Option<u128> {
        let mut result: u128 = 1;
        for _ in 0..exp {
            result = result.checked_mul(base)?;
        }
        Some(result)
    }

    /// Integer nth root: floor(x^(1/n)) via binary search.
    fn int_nth_root(x: u128, n: u32) -> u128 {
        if x <= 1 || n == 1 {
            return x;
        }
        let bit_bound = 128 / n;
        let mut hi: u128 = if bit_bound >= 64 {
            x
        } else {
            (1u128 << (bit_bound + 1)).min(x)
        };
        let mut lo: u128 = 1;
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            match pow_u128(mid, n) {
                Some(v) if v <= x => lo = mid,
                _ => hi = mid - 1,
            }
        }
        lo
    }

    #[test]
    fn test_int_nth_root() {
        assert_eq!(int_nth_root(32, 5), 2); // 2^5 = 32
        assert_eq!(int_nth_root(100, 2), 10); // 10^2 = 100
        assert_eq!(int_nth_root(1000, 3), 10); // 10^3 = 1000
        assert_eq!(int_nth_root(1, 5), 1);
        assert_eq!(int_nth_root(0, 5), 0);
    }

    #[test]
    fn test_fp_root_identity() {
        // 1.0^(1/5) = 1.0
        assert_eq!(fp_root(SCALE, 1, 5).unwrap(), SCALE);
    }

    /// Reference `round(base^(1/q) * SCALE)` computed in `f64` (test-only per
    /// CLAUDE.md section 5.6). Used only to know the *magnitude* of the expected root;
    /// the exactness is pinned by [`test_fp_root_floor_identity`] in integers.
    fn ref_root_scaled(base: u128, q: u32) -> u128 {
        let root = (base as f64).powf(1.0 / q as f64);
        (root * SCALE_U128 as f64).round() as u128
    }

    /// Known-answer test: `fp_root` must land within a tiny tolerance of the
    /// real fractional power at the in-use `q in {5, 10}`. A scale-stacking wrap
    /// (the OIP-00043 bug) makes `target` - and thus the root - garbage, off by
    /// many orders of magnitude, so it fails this check while still satisfying
    /// the loose `frac > 0` / `frac <= 2*fmax` bounds the distribution tests use.
    #[test]
    fn test_fp_root_known_answers() {
        // pi^(1/10) at q = 10 - the call site that overflows U256 hardest.
        for &pi in &[2u128, 16, 1000, 1_000_000] {
            let got: u128 = fp_root(U256::from(pi) * SCALE, POLICY_B_NUM, POLICY_B_DEN)
                .unwrap()
                .try_into()
                .unwrap();
            let want = ref_root_scaled(pi, 10);
            let diff = got.abs_diff(want);
            // fp_root returns the integer floor of the true root; allow a few
            // ULP for f64 rounding in the reference. A wrap is off by >> this.
            assert!(
                diff <= 4_096,
                "fp_root({pi}*SCALE, 1, 10) = {got}, expected ~{want} (diff {diff})"
            );
        }

        // (i-0.5)^(1/5) at q = 5 for representative x_fp = x * SCALE.
        for &(num, den) in &[(1u128, 2u128), (3, 2), (5, 2), (99, 2)] {
            let x_fp = U256::from(num) * SCALE / U256::from(den);
            let got: u128 = fp_root(x_fp, POLICY_A_NUM, POLICY_A_DEN)
                .unwrap()
                .try_into()
                .unwrap();
            // reference: (num/den)^(1/5) * SCALE
            let root = ((num as f64) / (den as f64)).powf(1.0 / 5.0);
            let want = (root * SCALE_U128 as f64).round() as u128;
            let diff = got.abs_diff(want);
            assert!(
                diff <= 4_096,
                "fp_root({num}/{den}*SCALE, 1, 5) = {got}, expected ~{want} (diff {diff})"
            );
        }
    }

    /// Exact integer defining-identity: `fp_root` returns `floor(target^(1/q))`
    /// where `target = x_fp * SCALE^(q-1)`. Verified as `y^q <= target < (y+1)^q`,
    /// with `target` and the powers computed in the wide reference type so a
    /// U256 wrap cannot slip through. No `f64`; fully deterministic.
    #[test]
    fn test_fp_root_floor_identity() {
        let scale_w = U1024::from(SCALE);
        for &q in &[POLICY_A_DEN, POLICY_B_DEN] {
            for &pi in &[2u128, 7, 16, 255, 1000, 1_000_000] {
                let x_fp = U256::from(pi) * SCALE;
                let y = fp_root(x_fp, 1, q).unwrap();

                // target = x_fp * SCALE^(q-1), exact in U1024.
                let mut target = U1024::from(x_fp);
                for _ in 0..(q - 1) {
                    target = target.checked_mul(scale_w).unwrap();
                }

                let yw = U1024::from(y);
                let y_pow = pow_u1024(yw, q);
                let y1_pow = pow_u1024(yw + U1024::from(1u64), q);
                assert!(
                    y_pow <= target && target < y1_pow,
                    "fp_root({pi}*SCALE,1,{q})={y}: floor identity broken"
                );
            }
        }
    }

    /// The largest in-use `x_fp` (a fidelity-group population up to the
    /// OIP-00043 `pi <= 10^9` bound, at the hardest `q = 10`) must return `Ok`
    /// with a correctly-bounded root - not a revert and not a wrap.
    #[test]
    fn test_fp_root_no_overflow_at_q10() {
        let pi: u128 = 1_000_000_000; // 10^9
        let root = fp_root(U256::from(pi) * SCALE, POLICY_B_NUM, POLICY_B_DEN)
            .expect("fp_root must not overflow for in-use populations");
        // 10^9^(1/10) = 10^0.9 ~= 7.94, so root ~= 7.94 * SCALE.
        let want = ref_root_scaled(pi, 10);
        let got: u128 = root.try_into().unwrap();
        assert!(
            got.abs_diff(want) <= 4_096,
            "fp_root(10^9*SCALE,1,10) = {got}, expected ~{want}"
        );
    }

    /// `y^exp` in U1024, saturating at `U1024::MAX` (only hit for out-of-range
    /// inputs this test never supplies).
    fn pow_u1024(base: U1024, exp: u32) -> U1024 {
        let mut acc = U1024::from(1u64);
        for _ in 0..exp {
            acc = acc.saturating_mul(base);
        }
        acc
    }

    #[test]
    fn test_single_group_returns_f() {
        let y_fp = vec![SCALE]; // 100%
        let p = vec![10];
        let f_fp = F_FP_DEFAULT;
        let fmax_fp = F_MAX_FP;

        let result = calc_fraction_distribution_fp(&y_fp, &p, 10, f_fp, fmax_fp).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], f_fp);
    }

    #[test]
    fn test_two_groups_sum_reasonable() {
        let half = SCALE / U256::from(2u64);
        let y_fp = vec![half, half]; // 50/50
        let p = vec![5, 5];
        let f_fp = F_FP_DEFAULT;
        let fmax_fp = F_MAX_FP;

        let result = calc_fraction_distribution_fp(&y_fp, &p, 10, f_fp, fmax_fp).unwrap();
        assert_eq!(result.len(), 2);
        // Both fractions should be positive and <= fmax
        for &frac in &result {
            assert!(!frac.is_zero(), "fraction should be positive");
            assert!(
                frac <= fmax_fp * U256::from(2u64),
                "fraction should be bounded"
            );
        }
    }
}
