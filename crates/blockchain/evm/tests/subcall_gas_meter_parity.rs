//! differential proptests verifying that
//! [`outbe_evm::gas::SubcallGasMeter`] is byte-for-byte equal to upstream
//! [`revm::interpreter::Gas`] across `record_regular_cost`, `erase_cost`,
//! `record_refund`, `set_state_gas_spent`, and `set_reservoir`.
//!
//! Each proptest:
//! 1. Constructs a `revm::Gas` and a `SubcallGasMeter` with the same limit.
//! 2. Applies a randomized sequence of operations to both.
//! 3. Asserts byte-equal post-state on `(limit, remaining, refunded,
//!    state_gas_spent, reservoir)` after each step.
//!
//! Total fixtures: 5 x 100 = 500 cases minimum.

use outbe_evm::gas::SubcallGasMeter;
use proptest::prelude::*;
use revm::interpreter::Gas;

fn snapshot(gas: &Gas) -> (u64, u64, i64, u64, u64) {
    (
        gas.limit(),
        gas.remaining(),
        gas.refunded(),
        gas.state_gas_spent(),
        gas.reservoir(),
    )
}

fn snapshot_outbe(meter: &SubcallGasMeter) -> (u64, u64, i64, u64, u64) {
    (
        meter.limit(),
        meter.remaining(),
        meter.refunded(),
        meter.state_gas_spent(),
        meter.reservoir(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Mirrors `revm::Gas::record_regular_cost`.
    #[test]
    fn record_regular_cost_byte_equal(
        limit in 0u64..=u64::MAX,
        costs in proptest::collection::vec(0u64..=u64::MAX / 4, 1..16),
    ) {
        let mut upstream = Gas::new(limit);
        let mut outbe = SubcallGasMeter::new(limit);
        prop_assert_eq!(snapshot(&upstream), snapshot_outbe(&outbe), "initial state");

        for cost in costs {
            let up_ok = upstream.record_regular_cost(cost);
            let ob_ok = outbe.record_regular_cost(cost);
            prop_assert_eq!(up_ok, ob_ok, "record_regular_cost bool differs at cost={}", cost);
            prop_assert_eq!(
                snapshot(&upstream),
                snapshot_outbe(&outbe),
                "post-record_regular_cost state diverged at cost={}",
                cost
            );
        }
    }

    /// Mirrors `revm::Gas::erase_cost`. Inputs bounded below `u64::MAX / 32`
    /// per step to avoid `remaining + returned` overflow in upstream's
    /// unchecked add (which is the documented production-realistic range -
    /// gas budgets are sub-tx and never approach `u64::MAX`).
    #[test]
    fn erase_cost_byte_equal(
        limit in 0u64..=u64::MAX / 4,
        prep_cost in 0u64..=u64::MAX / 8,
        returns in proptest::collection::vec(0u64..=u64::MAX / 32, 1..16),
    ) {
        let mut upstream = Gas::new(limit);
        let mut outbe = SubcallGasMeter::new(limit);

        // Spend some gas so `erase_cost` has room to refund.
        let _ = upstream.record_regular_cost(prep_cost);
        let _ = outbe.record_regular_cost(prep_cost);
        prop_assert_eq!(snapshot(&upstream), snapshot_outbe(&outbe), "after prep-spend");

        for ret in returns {
            upstream.erase_cost(ret);
            outbe.erase_cost(ret);
            prop_assert_eq!(
                snapshot(&upstream),
                snapshot_outbe(&outbe),
                "post-erase_cost state diverged at ret={}",
                ret
            );
        }
    }

    /// Mirrors `revm::Gas::record_refund`. Inputs bounded to +/-1B per step
    /// to avoid `refunded += refund` i64-overflow in upstream. Realistic
    /// per-call refund values (EIP-3529 cap) are bounded by tx gas limit,
    /// always within `i64` headroom.
    #[test]
    fn record_refund_byte_equal(
        limit in 0u64..=u64::MAX,
        refunds in proptest::collection::vec(-1_000_000_000i64..=1_000_000_000, 1..16),
    ) {
        let mut upstream = Gas::new(limit);
        let mut outbe = SubcallGasMeter::new(limit);

        for r in refunds {
            upstream.record_refund(r);
            outbe.record_refund(r);
            prop_assert_eq!(
                snapshot(&upstream),
                snapshot_outbe(&outbe),
                "post-record_refund state diverged at refund={}",
                r
            );
        }
    }

    /// Mirrors `revm::Gas::set_state_gas_spent`.
    #[test]
    fn set_state_gas_spent_byte_equal(
        limit in 0u64..=u64::MAX,
        vals in proptest::collection::vec(0u64..=u64::MAX, 1..16),
    ) {
        let mut upstream = Gas::new(limit);
        let mut outbe = SubcallGasMeter::new(limit);

        for v in vals {
            upstream.set_state_gas_spent(v);
            outbe.set_state_gas_spent(v);
            prop_assert_eq!(
                snapshot(&upstream),
                snapshot_outbe(&outbe),
                "post-set_state_gas_spent diverged at val={}",
                v
            );
        }
    }

    /// Mirrors `revm::Gas::set_reservoir`.
    #[test]
    fn set_reservoir_byte_equal(
        limit in 0u64..=u64::MAX,
        vals in proptest::collection::vec(0u64..=u64::MAX, 1..16),
    ) {
        let mut upstream = Gas::new(limit);
        let mut outbe = SubcallGasMeter::new(limit);

        for v in vals {
            upstream.set_reservoir(v);
            outbe.set_reservoir(v);
            prop_assert_eq!(
                snapshot(&upstream),
                snapshot_outbe(&outbe),
                "post-set_reservoir diverged at val={}",
                v
            );
        }
    }
}

#[cfg(test)]
mod smoke {
    use super::*;

    /// Sanity: fresh meter at `new(0)` returns zero on every accessor.
    #[test]
    fn fresh_zero_limit_is_zero_everywhere() {
        let m = SubcallGasMeter::new(0);
        let g = Gas::new(0);
        assert_eq!(snapshot_outbe(&m), snapshot(&g));
        assert_eq!(m.limit(), 0);
        assert_eq!(m.remaining(), 0);
        assert_eq!(m.refunded(), 0);
        assert_eq!(m.state_gas_spent(), 0);
        assert_eq!(m.reservoir(), 0);
    }

    /// Sanity: `record_regular_cost` returns the same bool as upstream
    /// when gas is exhausted.
    #[test]
    fn out_of_gas_returns_false() {
        let mut m = SubcallGasMeter::new(100);
        let mut g = Gas::new(100);
        assert_eq!(m.record_regular_cost(50), g.record_regular_cost(50));
        // Exhaust the budget.
        let too_much_outbe = m.record_regular_cost(60);
        let too_much_revm = g.record_regular_cost(60);
        assert_eq!(too_much_outbe, too_much_revm);
        assert!(!too_much_outbe, "over-budget cost must return false");
    }
}
