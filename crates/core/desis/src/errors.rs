use alloy_primitives::Address;
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DesisError {
    #[error("invalid worldwide day: {0}")]
    InvalidWorldwideDay(WorldwideDay),

    #[error("invalid stage transition")]
    InvalidStageTransition,

    #[error("pending clearing data missing for series {0}")]
    PendingClearingDataMissing(WorldwideDay),

    #[error("unauthorized origin: {0}")]
    UnauthorizedOrigin(Address),

    #[error("winning bid references an unpriced currency: {0}")]
    UnpricedReferenceCurrency(u16),

    #[error("chain relayed {0} bidders, more than the refund fan-out can carry")]
    RefundFanOutTooLarge(usize),

    #[error("relayed bid names a currency no series id can spell: issuance {0}, reference {1}")]
    UnspellableBidCurrency(u16, u16),

    #[error("relayed bid batch carries {0} bids, over the {1} the codec may send")]
    BidBatchTooLarge(usize, usize),
}

impl From<DesisError> for outbe_primitives::error::PrecompileError {
    fn from(e: DesisError) -> Self {
        outbe_primitives::error::PrecompileError::Revert(e.to_string())
    }
}
