//! Strict OCOMP request-phase ownership boundary for Desis.
//!
//! The legacy cross-module API is deliberately best-effort because it is used
//! from a block hook. OCOMP request application instead needs an atomic,
//! fail-closed owner write whose exact input can be committed by the request
//! receipt.

use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::intent::ReferenceEntryPriceV1;
use outbe_ocomp_protocol::receipts::desis_request_brief_hash;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;

use crate::schema::ReferenceCurrencyPrice;

/// Apply the day's immutable `auction_base` and return the canonical hash
/// committed by `RequestBudgetSplitReceiptV1`. A red day briefs no supply, but
/// is briefed all the same so its targets learn the auction is cancelled.
pub fn apply_request_auction_base(
    storage: StorageHandle<'_>,
    protocol_bundle_hash: B256,
    worldwide_day: WorldwideDay,
    auction_base: U256,
    auction_entry_prices: &[ReferenceEntryPriceV1],
    logical_anchor: u64,
    green: bool,
) -> Result<B256> {
    let briefed_supply = if green { auction_base } else { U256::ZERO };
    let brief_hash = desis_request_brief_hash(
        protocol_bundle_hash,
        worldwide_day.value(),
        briefed_supply,
        auction_entry_prices,
        logical_anchor,
    )
    .map_err(|error| PrecompileError::Revert(format!("invalid OCOMP Desis brief hash: {error}")))?;
    // Same door as the settlement paths; only the overflow policy differs,
    // because this receipt commits a hash a rejection could not fill.
    crate::api::dispatch_auction_brief(
        storage,
        worldwide_day,
        briefed_supply,
        auction_entry_prices
            .iter()
            .map(|row| ReferenceCurrencyPrice {
                iso_code: row.reference_currency,
                entry_price_minor: row.entry_price_minor,
            })
            .collect(),
        green,
        logical_anchor,
        crate::api::BriefOverflowPolicy::Reject,
    )?;
    Ok(brief_hash)
}
