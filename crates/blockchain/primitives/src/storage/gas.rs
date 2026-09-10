//! Gas model for Outbe stateful precompiles.
//!
//! Outbe runs a permissioned validator set and does not use a fee market.
//! Pricing for SLOAD/SSTORE is sourced directly from revm upstream
//! ([`revm::context_interface::cfg::gas::WARM_STORAGE_READ_COST`] and
//! [`revm::context_interface::cfg::gas::SSTORE_RESET`]) - see their use in
//! [`super::evm::EvmStorageProvider`]. Outbe does not distinguish warm/cold
//! accesses and does not implement SSTORE refunds, so every read is billed
//! at the warm price and every write at the reset price.
//!
//! The Outbe-specific constants live here: [`PRECOMPILE_BASE_GAS`] for flat
//! dispatch entry and [`ZK_VERIFY_GAS`] for one proof verification.

use crate::error::{PrecompileError, Result};

/// Flat entry cost charged once per precompile dispatch.
///
/// No direct EIP-2929 counterpart: a precompile entry is a cross-boundary
/// action, not an SLOAD. Chosen in the same order of magnitude as the
/// cheapest metered op so dispatch is cheap but not free, which is adequate
/// DoS protection in Outbe's permissioned model.
pub const PRECOMPILE_BASE_GAS: u64 = 200;

/// Flat gas cost for one UltraHonkKeccak verification.
pub const ZK_VERIFY_GAS: u64 = 3_000_000;

/// Deterministic gas meter used by [`EvmStorageProvider`](super::evm::EvmStorageProvider).
///
/// The tracker remembers the original limit so [`Self::used`] is correct
/// regardless of the starting value. A failed [`Self::deduct`] must not
/// advance the meter - the invariant is exercised by unit tests below.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GasTracker {
    limit: u64,
    remaining: u64,
    refunded: i64,
}

impl GasTracker {
    pub const fn new(limit: u64) -> Self {
        Self {
            limit,
            remaining: limit,
            refunded: 0,
        }
    }

    pub fn deduct(&mut self, gas: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(gas)
            .ok_or(PrecompileError::OutOfGas)?;
        Ok(())
    }

    pub fn refund(&mut self, gas: i64) {
        self.refunded = self.refunded.saturating_add(gas);
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub fn used(&self) -> u64 {
        self.limit.saturating_sub(self.remaining)
    }

    pub fn refunded(&self) -> i64 {
        self.refunded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::context_interface::cfg::gas::{SSTORE_RESET, WARM_STORAGE_READ_COST};

    #[test]
    fn new_starts_with_zero_used() {
        let g = GasTracker::new(10_000);
        assert_eq!(g.used(), 0);
        assert_eq!(g.remaining(), 10_000);
        assert_eq!(g.refunded(), 0);
    }

    #[test]
    fn max_limit_reports_zero_used() {
        // Regression: `used` must stay zero on a fresh
        // tracker even when constructed at `u64::MAX` (the non-metered
        // code path). The previous implementation derived `used` from
        // `u64::MAX - remaining` directly and only happened to be correct
        // for that one limit.
        let g = GasTracker::new(u64::MAX);
        assert_eq!(g.used(), 0);
    }

    #[test]
    fn used_tracks_sum_of_per_op_constants() {
        let mut g = GasTracker::new(10_000);
        g.deduct(WARM_STORAGE_READ_COST).unwrap();
        g.deduct(SSTORE_RESET).unwrap();
        assert_eq!(g.used(), WARM_STORAGE_READ_COST + SSTORE_RESET);
        assert_eq!(
            g.remaining(),
            10_000 - WARM_STORAGE_READ_COST - SSTORE_RESET
        );
    }

    #[test]
    fn used_is_correct_for_metered_construction() {
        // Regression: under `new_with_gas(N)` the legacy
        // implementation returned `u64::MAX - remaining`, which was wrong
        // for any `N < u64::MAX`. Verify both constructors via the same
        // accounting invariant.
        let mut g = GasTracker::new(5_400);
        g.deduct(PRECOMPILE_BASE_GAS).unwrap();
        g.deduct(SSTORE_RESET).unwrap();
        assert_eq!(g.used(), PRECOMPILE_BASE_GAS + SSTORE_RESET);
        assert_eq!(g.remaining(), 5_400 - PRECOMPILE_BASE_GAS - SSTORE_RESET);
    }

    #[test]
    fn deduct_past_limit_returns_out_of_gas_without_advancing() {
        let mut g = GasTracker::new(50);
        let err = g.deduct(WARM_STORAGE_READ_COST).unwrap_err();
        assert!(matches!(err, PrecompileError::OutOfGas));
        // A failed deduction must not mutate remaining/used.
        assert_eq!(g.remaining(), 50);
        assert_eq!(g.used(), 0);
    }

    #[test]
    fn refund_saturates_on_overflow() {
        let mut g = GasTracker::new(10_000);
        g.refund(1_000);
        g.refund(-200);
        assert_eq!(g.refunded(), 800);

        g.refund(i64::MAX);
        assert_eq!(g.refunded(), i64::MAX);
    }

    #[test]
    fn outbe_protocol_gas_values_are_stable() {
        // Protocol-visible values. If revm ever changes these upstream,
        // Outbe must decide explicitly whether to follow or pin a local
        // value. A silent upstream shift is a protocol change.
        assert_eq!(WARM_STORAGE_READ_COST, 100);
        assert_eq!(SSTORE_RESET, 5_000);
        assert_eq!(PRECOMPILE_BASE_GAS, 200);
    }
}
