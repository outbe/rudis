//! Module-local protocol constants for credis positions.
//!
//! Values trace to the Credis product paper section 10. Those still marked TBD there
//! carry a placeholder here plus a `ponytail:` note naming what has to be
//! decided before launch.

/// Denominator for [`CALL_RATE_PCT`].
pub const PRICE_RATE_DEN: u16 = 100;

/// Call price: `entry + 64%`. A sustained breach of it arms the call.
pub const CALL_RATE_PCT: u16 = 64;

/// Evaluation window for the call, in closed UTC days: the daily scan looks
/// back this far over the official daily reference series. Distinct from
/// [`CALL_WINDOW_SECS`], which is the settlement window the call itself opens.
pub const CALL_LOOKBACK_DAYS: u32 = 28;

/// Breach threshold: a position is called once the official daily reference
/// price sat strictly above its call price on this many days of the
/// [`CALL_LOOKBACK_DAYS`] window. Days at or below the call price and days with
/// no published price both simply fail to count, so the window absorbs up to
/// `CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS` of them. Mirrors gem's
/// `CALL_WINDOW` / `CALL_THRESHOLD` pair.
pub const CALL_BREACH_DAYS: u32 = 21;

/// Settlement window opened by the call.
pub const CALL_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

/// Day count convention for interest accrual: simple, ACT/365.
pub const DAYS_PER_YEAR: u64 = 365;

/// Basis-point multiplier applied to the currency's official policy rate when
/// pinning a position's `policy_rate` at opening. 10_000 bp = x1.
// ponytail: section 10 lists the policy-rate factor as TBD and proposes a default of 1.
// A governance-settable parameter is the upgrade path if it needs retuning
// without a redeploy.
pub const POLICY_RATE_FACTOR_BP: u32 = 10_000;

/// Denominator for [`POLICY_RATE_FACTOR_BP`].
pub const BP_DEN: u32 = 10_000;
