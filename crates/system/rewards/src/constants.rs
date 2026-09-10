//! Protocol constants for the inclusion-window reward mechanism.
//!
//! Block `N`'s fees are escrowed and, at `N+K`, split across the full voter set
//! with a **distance-decayed, fixed-denominator** payout (residue burned). All
//! weights are scaled-`U256` integers - **no `f32`/`f64`** (CLAUDE.md numeric
//! rule).
//!
//! `K` itself lives in [`outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K`]
//! because the executor also needs it for settle timing.

use alloy_primitives::{uint, U256};
use outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K;

/// ISO 4217 code both currency axes of a validator top-up gem carry.
///
/// Validator rewards are denominated in USD by protocol policy
pub const REWARD_GEM_CURRENCY: u16 = 840;

/// Number of inclusion-distance slots, `k in {0..=K}` => `K + 1` weights.
pub const LATE_FINALIZE_SLOTS: usize = LATE_FINALIZE_WINDOW_K as usize + 1;

/// Decay weight `w(k)` by inclusion distance `k = inclusion_block - N`.
///
/// Flat full weight through the geo-latency band, hard cliff at `k = K`:
/// `[100, 100, 100, 0]` for `K = 3`. `w(0) = w_max`. A voter first seen at
/// `k = K` (the settle slot) earns nothing; a slow-but-honest validator that
/// lands at `k = 1` earns full weight, so a proposer pushing a victim `k0->k1`
/// (or `k1->k2`) inflicts ~0 - and under the fixed denominator earns nothing by
/// excluding it anyway.
///
/// The literal length is checked against `K + 1` at compile time.
pub const LATE_FINALIZE_DECAY: [U256; LATE_FINALIZE_SLOTS] = [
    uint!(100_U256),
    uint!(100_U256),
    uint!(100_U256),
    uint!(0_U256),
];

/// `w_max = max_k w(k) = w(0)`. The fixed per-block denominator is
/// `D = committee_size * w_max` - constant per block, independent of who voted,
/// so excluding a peer enriches nobody.
pub const LATE_FINALIZE_W_MAX: U256 = LATE_FINALIZE_DECAY[0];

/// Decay weight for inclusion distance `k`.
///
/// Returns `0` for `k > K` (out of window). Such a credit must already have been
/// rejected FATAL upstream by the verifier; this is a defensive clamp, never a
/// silent acceptance path.
pub fn decay_weight(k: u64) -> U256 {
    LATE_FINALIZE_DECAY
        .get(k as usize)
        .copied()
        .unwrap_or(U256::ZERO)
}

/// Fixed per-block denominator `D = committee_size * w_max`.
///
/// `committee_size` is the epoch `CommitteeSnapshot` participant count for the
/// settled block - fixed per block, so the divisor never depends on attendance.
pub fn fixed_denominator(committee_size: u64) -> U256 {
    U256::from(committee_size).saturating_mul(LATE_FINALIZE_W_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_curve_values() {
        assert_eq!(LATE_FINALIZE_SLOTS, 4, "K=3 => 4 inclusion slots");
        assert_eq!(
            LATE_FINALIZE_DECAY,
            [
                uint!(100_U256),
                uint!(100_U256),
                uint!(100_U256),
                uint!(0_U256)
            ]
        );
        assert_eq!(LATE_FINALIZE_W_MAX, uint!(100_U256));
    }

    #[test]
    fn decay_weight_per_slot_and_out_of_window() {
        assert_eq!(decay_weight(0), uint!(100_U256));
        assert_eq!(decay_weight(1), uint!(100_U256));
        assert_eq!(decay_weight(2), uint!(100_U256));
        assert_eq!(decay_weight(3), U256::ZERO); // k = K is the cliff
        assert_eq!(decay_weight(4), U256::ZERO); // out of window
        assert_eq!(decay_weight(u64::MAX), U256::ZERO);
    }

    /// full attendance at `k <= 2` pays exactly the pool and never
    /// more (`N*w_max / D = 1`); the fixed denominator means an absent voter's
    /// share burns rather than redistributing.
    #[test]
    fn w_max_solvency_full_attendance() {
        let committee_size: u64 = 16;
        let pool = U256::from(committee_size) * uint!(1_000_000_U256); // one COEN per member; divisible by N
        let denom = fixed_denominator(committee_size);
        assert_eq!(denom, U256::from(committee_size) * uint!(100_U256));

        // All committee members present at k = 0 (full weight).
        let mut distributed = U256::ZERO;
        for _ in 0..committee_size {
            distributed += pool * decay_weight(0) / denom;
        }
        assert_eq!(
            distributed, pool,
            "full k0 attendance pays exactly the pool"
        );

        // Excluding one voter must not raise anyone else's share (fixed denom):
        // the remaining payouts are unchanged and the missing share becomes residue.
        let mut distributed_minus_one = U256::ZERO;
        for _ in 0..(committee_size - 1) {
            distributed_minus_one += pool * decay_weight(0) / denom;
        }
        let residue = pool - distributed_minus_one;
        assert_eq!(
            distributed_minus_one,
            pool - pool / U256::from(committee_size),
            "remaining shares unchanged when one voter is excluded"
        );
        assert_eq!(
            residue,
            pool / U256::from(committee_size),
            "excluded voter's share becomes burnable residue, not redistribution"
        );
    }
}
