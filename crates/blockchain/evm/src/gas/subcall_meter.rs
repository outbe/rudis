//! `SubcallGasMeter` - a thin wrapper over [`revm::interpreter::Gas`] used by
//! the outbe sub-call driver.
//!
//! Each method delegates 1:1 to the inner [`revm::interpreter::Gas`] instance
//! so byte-for-byte parity vs upstream is guaranteed by construction. The
//! mirror is verified by 5 differential proptests in
//! `crates/blockchain/evm/tests/subcall_gas_meter_parity.rs`.

use revm::interpreter::Gas;

/// Sub-call gas meter mirroring [`revm::interpreter::Gas`] byte-for-byte.
///
/// Owned per sub-call frame by the driver. All
/// accounting semantics (regular gas, reservoir, refunds, state gas spent)
/// match upstream `revm::interpreter::Gas` so the settlement triple in
/// produces identical results across proposer and validator
/// re-execution paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubcallGasMeter {
    inner: Gas,
}

impl SubcallGasMeter {
    /// Creates a new meter with the given regular-gas limit.
    ///
    /// Reservoir is zero - Outbe does not use EIP-8037 at this stage, so the
    /// meter behaves as a single-pool tracker. The field is preserved to
    /// keep the byte-for-byte mirror with upstream `Gas`.
    ///
    /// Mirrors revm Gas::new.
    #[inline]
    pub const fn new(limit: u64) -> Self {
        Self {
            inner: Gas::new(limit),
        }
    }

    /// Returns the gas limit.
    ///
    /// Mirrors revm Gas::limit.
    #[inline]
    pub const fn limit(&self) -> u64 {
        self.inner.limit()
    }

    /// Returns the gas remaining (regular budget, exclusive of reservoir).
    ///
    /// Mirrors revm Gas::remaining.
    #[inline]
    pub const fn remaining(&self) -> u64 {
        self.inner.remaining()
    }

    /// Returns the total amount of gas refunded.
    ///
    /// Mirrors revm Gas::refunded.
    #[inline]
    pub const fn refunded(&self) -> i64 {
        self.inner.refunded()
    }

    /// Returns total state gas spent so far (EIP-8037).
    ///
    /// Mirrors revm Gas::state_gas_spent.
    #[inline]
    pub const fn state_gas_spent(&self) -> u64 {
        self.inner.state_gas_spent()
    }

    /// Returns the state gas reservoir (EIP-8037).
    ///
    /// Mirrors revm Gas::reservoir.
    #[inline]
    pub const fn reservoir(&self) -> u64 {
        self.inner.reservoir()
    }

    /// Deducts `cost` from `remaining` only (used for child frame gas
    /// forwarding). Does not touch reservoir or regular gas budget.
    ///
    /// Returns `false` if total remaining gas is insufficient.
    ///
    /// Mirrors revm Gas::record_regular_cost.
    #[inline]
    #[must_use = "On insufficient gas the caller must halt with an out-of-gas error"]
    pub fn record_regular_cost(&mut self, cost: u64) -> bool {
        self.inner.record_regular_cost(cost)
    }

    /// Erases `returned` gas from the spent counter - i.e. returns unused
    /// gas from a child frame back into the meter's `remaining` budget.
    ///
    /// Mirrors revm Gas::erase_cost.
    #[inline]
    pub fn erase_cost(&mut self, returned: u64) {
        self.inner.erase_cost(returned)
    }

    /// Records a refund. `refund` may be negative; the cumulative refund
    /// counter is expected to be non-negative at the end of execution.
    ///
    /// Mirrors revm Gas::record_refund.
    #[inline]
    pub fn record_refund(&mut self, refund: i64) {
        self.inner.record_refund(refund)
    }

    /// Sets the total state gas spent (used when propagating from a child
    /// frame's settlement).
    ///
    /// Mirrors revm Gas::set_state_gas_spent.
    #[inline]
    pub fn set_state_gas_spent(&mut self, val: u64) {
        self.inner.set_state_gas_spent(val)
    }

    /// Sets the state gas reservoir (used when propagating from a child
    /// frame's settlement).
    ///
    /// Mirrors revm Gas::set_reservoir.
    #[inline]
    pub fn set_reservoir(&mut self, val: u64) {
        self.inner.set_reservoir(val)
    }

    /// Returns the underlying revm [`Gas`] instance.
    ///
    /// Provided so the sub-call driver in can pass the
    /// inner gas tracker to upstream helpers
    /// (`handle_reservoir_remaining_gas`, `load_acc_and_calc_gas`).
    /// **Not** marked `Mirrors revm Gas::*` - this is an outbe-only escape
    /// hatch, not a method on `Gas`.
    #[inline]
    pub const fn inner(&self) -> &Gas {
        &self.inner
    }

    /// Returns the underlying revm [`Gas`] instance mutably. See [`Self::inner`].
    #[inline]
    pub const fn inner_mut(&mut self) -> &mut Gas {
        &mut self.inner
    }
}
