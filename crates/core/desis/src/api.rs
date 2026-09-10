//! Cross-module API for Desis (Rust-to-Rust, not precompile selectors).
//!
//! Metadosis hands the day over as a one-shot auction brief; the Desis
//! begin-block schedule drives every stage from there. Capacity rejection is a
//! typed business result. Every technical or invariant failure remains an
//! `Err`, with all partial writes reverted. The auction key is the worldwide
//! day - one auction per day; series ids are allocated at issuance.

use alloy_primitives::U256;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;

use crate::precompile::IDesis;
use crate::runtime;
use crate::schema::{DesisContract, ReferenceCurrencyPrice};

/// Stable consensus reason for the only business-level auction-brief rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuctionBriefRejectionReason {
    SupplyExceedsAuctionDomain = 1,
}

impl AuctionBriefRejectionReason {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// What an oversized supply means for the caller: the settlement paths carry it
/// to the unallocated pool, the OCOMP request path cannot because its receipt
/// commits a brief hash that a rejection would have nothing to fill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BriefOverflowPolicy {
    CarryOver,
    Reject,
}

/// Semantic result of one auction-brief formation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuctionBriefReceipt {
    Accepted,
    RejectedToCarryOver {
        reason: AuctionBriefRejectionReason,
        supply: U256,
        max_accepted: U256,
    },
}

/// Record the day's auction brief (supply in raw PROMIS, entry price, day
/// type). Only a supply outside Desis' `u128` auction domain is a committed
/// rejection. Invalid state, timestamp overflow, storage/index/event faults and
/// corruption propagate as `Err`.
pub fn dispatch_auction_brief(
    storage: StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    supply_promis: U256,
    reference_prices: Vec<ReferenceCurrencyPrice>,
    is_green: bool,
    now: u64,
    overflow: BriefOverflowPolicy,
) -> Result<AuctionBriefReceipt> {
    storage.clone().with_checkpoint(|| {
        let anchor = runtime::preflight_brief(&storage, worldwide_day, now)?;
        let Ok(supply_u128) = u128::try_from(supply_promis) else {
            let max_accepted = U256::from(u128::MAX);
            let reason = AuctionBriefRejectionReason::SupplyExceedsAuctionDomain;
            if matches!(overflow, BriefOverflowPolicy::Reject) {
                return Err(outbe_primitives::error::PrecompileError::Revert(
                    "auction brief supply exceeds Desis u128 domain".into(),
                ));
            }
            let mut contract = storage.contract::<DesisContract>();
            contract.emit(IDesis::AuctionBriefRejectedToCarryOver {
                worldwideDay: worldwide_day.into(),
                supply: supply_promis,
                maxAccepted: max_accepted,
                reasonCode: reason.code(),
            })?;
            return Ok(AuctionBriefReceipt::RejectedToCarryOver {
                reason,
                supply: supply_promis,
                max_accepted,
            });
        };
        runtime::record_preflighted_brief(
            storage.clone(),
            worldwide_day,
            supply_u128,
            reference_prices,
            is_green,
            anchor,
        )?;
        Ok(AuctionBriefReceipt::Accepted)
    })
}
