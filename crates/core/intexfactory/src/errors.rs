//! Module-local error types. Other errors come from
//! `outbe_primitives::error::PrecompileError`.

use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IntexFactoryError {
    #[error("zero address")]
    ZeroAddress,
    #[error("amount must be positive")]
    ZeroAmount,
    #[error("series not found")]
    SeriesNotFound,
    #[error("series not settleable in state {0}")]
    NotSettleable(u8),
    #[error("settlement deadline expired")]
    DeadlineExpired,
    #[error("zero balance")]
    ZeroBalance,
    #[error("amount exceeds balance")]
    AmountExceedsBalance,
    #[error("caller not authorized to settle for holder")]
    NotAuthorized,
    #[error("insufficient settled balance")]
    InsufficientSettled,
    #[error("insufficient proof of work")]
    InsufficientProofOfWork,
    #[error("payment token has unsupported decimals {0}")]
    UnsupportedPaymentDecimals(u8),
    #[error("payment token {0} has no registered vault")]
    PaymentTokenNotRegistered(alloy_primitives::Address),
    #[error("payment token currency {0} does not match the series")]
    SettlementCurrencyMismatch(u16),
    #[error("no rudis rate published for currency {0}")]
    FxRateUnavailable(u16),
    #[error("rudis rate for currency {0} is too old to convert with")]
    FxRateStale(u16),
    #[error("caller is not the origin router")]
    NotOriginRouter,
    #[error("no contributors recorded for series {0}")]
    NoContributors(u32),
    #[error("no in-flight distribution for series {0}")]
    NoDistribution(u32),
    #[error("distribution payout math overflow for series {0}")]
    DistributionOverflow(u32),
    #[error("no open certified payout round for day {0}")]
    NoCertifiedRound(u32),
    #[error("contributor batch has an invalid shape")]
    BadContributorBatch,
    #[error("contributor payout would exceed the round amount for day {0}")]
    PayoutExceedsRound(u32),
    #[error(
        "currency {iso} day {worldwide_day} is indexed in bin {expected}, series priced into {got}"
    )]
    GroupBinMismatch {
        iso: u16,
        worldwide_day: outbe_primitives::time::WorldwideDay,
        expected: u32,
        got: u32,
    },
    #[error("currency {iso} day {worldwide_day} is already indexed")]
    GroupAlreadyIndexed {
        iso: u16,
        worldwide_day: outbe_primitives::time::WorldwideDay,
    },

    #[error("PayNote proof names spender {actual}, expected {expected}")]
    PayNoteSpenderMismatch {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },

    #[error("PayNote spends {covered}, settlement costs {required}")]
    PayNoteUndercoversCost {
        covered: alloy_primitives::U256,
        required: alloy_primitives::U256,
    },
}

impl From<IntexFactoryError> for PrecompileError {
    fn from(err: IntexFactoryError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
