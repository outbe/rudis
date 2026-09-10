use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{
    intent::{DayType, ReferenceEntryPriceV1},
    receipts::{desis_request_brief_hash, BudgetSplitDestination, RequestBudgetSplitReceiptV1},
};
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::StorageHandle,
};
use outbe_promislimit::PromisLimitContract;

use crate::errors::MetadosisError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestBudgetEffect {
    pub protocol_bundle_hash: B256,
    pub wwd: u32,
    pub pending_nonce: u64,
    pub day_type: DayType,
    pub day_limit: U256,
    pub lysis_budget: U256,
    pub nominal_total: U256,
    pub auction_entry_prices: Vec<ReferenceEntryPriceV1>,
    pub logical_anchor: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestBudgetSplit {
    /// The day's own emission plus what it drew from the accumulator.
    pub day_limit: U256,
    pub lysis_budget: U256,
    pub auction_base: U256,
    /// What Lysis left of the day's own emission, credited before the auction draws.
    pub carry_over_credit: U256,
}

impl RequestBudgetSplit {
    /// Lysis is bounded by the day's own emission and what it leaves is credited to the
    /// accumulator. The auction then draws from that accumulator: no more than the nominal beyond
    /// the symbolic share, and no more than the accumulator holds.
    pub(crate) fn derive(
        base_limit: U256,
        lysis_budget: U256,
        nominal_total: U256,
        carry_over_before: U256,
        green: bool,
    ) -> Result<Self> {
        let invalid = || MetadosisError::InvalidOcompBudgetSplit {
            day_limit: base_limit,
            lysis_budget,
        };
        let carry_over_credit = base_limit.checked_sub(lysis_budget).ok_or_else(invalid)?;
        let available = carry_over_before
            .checked_add(carry_over_credit)
            .ok_or_else(invalid)?;
        let auction_base = if green {
            nominal_total
                .checked_sub(lysis_budget)
                .ok_or_else(invalid)?
                .min(available)
        } else {
            U256::ZERO
        };
        Self::assemble(base_limit, lysis_budget, auction_base, carry_over_credit)
    }

    fn assemble(
        base_limit: U256,
        lysis_budget: U256,
        auction_base: U256,
        carry_over_credit: U256,
    ) -> Result<Self> {
        let invalid = || MetadosisError::InvalidOcompBudgetSplit {
            day_limit: base_limit,
            lysis_budget,
        };
        if lysis_budget.checked_add(carry_over_credit) != Some(base_limit) {
            return Err(invalid().into());
        }
        let day_limit = base_limit.checked_add(auction_base).ok_or_else(invalid)?;
        Ok(Self {
            day_limit,
            lysis_budget,
            auction_base,
            carry_over_credit,
        })
    }
}

/// Apply the request effect for a split that the authoritative Metadosis job
/// state has proven fresh.
///
/// The single-attempt FSM invokes this exactly once for a WorldwideDay. An
/// existing receipt is an invariant violation rather than a replay path.
pub(crate) fn apply_fresh_request_budget_effect(
    storage: StorageHandle<'_>,
    request: RequestBudgetEffect,
) -> Result<RequestBudgetSplitReceiptV1> {
    let green = request.day_type == DayType::Green;
    let carry_over_before = PromisLimitContract::new(storage.clone()).get_total_unallocated()?;
    let split = RequestBudgetSplit::derive(
        request.day_limit,
        request.lysis_budget,
        request.nominal_total,
        carry_over_before,
        green,
    )?;
    let receipt = expected_receipt(&request, split, request.pending_nonce)?;
    receipt
        .validate_semantics()
        .map_err(protocol_error_to_revert)?;
    // The request only credits what Lysis left of the day's own emission. The draw and the brief
    // wait for the Lysis deadline: a day whose Lysis never completes must not open an auction.
    if !split.carry_over_credit.is_zero() {
        let delta = PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(split.carry_over_credit)?;
        if delta.credited != split.carry_over_credit {
            return Err(MetadosisError::OcompBudgetReceiptMismatch.into());
        }
    }
    Ok(receipt)
}

/// Draw the day's auction base from the accumulator and brief Desis with it.
///
/// Called once Lysis has closed, so the accumulator already holds what Lysis returned and a day
/// whose Lysis never completed never opens an auction.
///
/// The amount was frozen on the request receipt, because the brief hash covers it. An activation
/// delayed past a later day's own draw can therefore find the accumulator short; the draw then
/// fails the activation rather than briefing less than the receipt promises, and the day's whole
/// emission returns to the accumulator.
pub(crate) fn apply_auction_brief(
    storage: StorageHandle<'_>,
    receipt: &RequestBudgetSplitReceiptV1,
) -> Result<()> {
    let green = receipt.day_type == DayType::Green;
    // One checkpoint: the draw and the brief may not survive each other's failure.
    storage.with_checkpoint(|| {
        if !receipt.auction_base.is_zero() {
            let drawn = PromisLimitContract::new(storage.clone())
                .checked_take_carry_over_up_to(receipt.auction_base)?;
            if drawn.taken != receipt.auction_base {
                return Err(MetadosisError::OcompBudgetReceiptMismatch.into());
            }
        }
        let actual = outbe_desis::ocomp_budget::apply_request_auction_base(
            storage.clone(),
            receipt.protocol_bundle_hash,
            receipt.wwd.into(),
            receipt.auction_base,
            &receipt.auction_entry_prices,
            receipt.logical_anchor,
            green,
        )?;
        if receipt.desis_brief_hash != Some(actual) {
            return Err(MetadosisError::OcompDesisBriefHashMismatch.into());
        }
        Ok(())
    })
}

fn expected_receipt(
    request: &RequestBudgetEffect,
    split: RequestBudgetSplit,
    effect_nonce: u64,
) -> Result<RequestBudgetSplitReceiptV1> {
    let (destination, briefed_supply) = match request.day_type {
        DayType::Green => (BudgetSplitDestination::DesisAuction, split.auction_base),
        DayType::Red => (BudgetSplitDestination::CarryOver, U256::ZERO),
    };
    let carry_over_credit = split.carry_over_credit;
    let desis_brief_hash = Some(
        desis_request_brief_hash(
            request.protocol_bundle_hash,
            request.wwd,
            briefed_supply,
            &request.auction_entry_prices,
            request.logical_anchor,
        )
        .map_err(protocol_error_to_revert)?,
    );
    let receipt = RequestBudgetSplitReceiptV1 {
        protocol_bundle_hash: request.protocol_bundle_hash,
        wwd: request.wwd,
        pending_nonce: effect_nonce,
        day_type: request.day_type,
        day_limit: split.day_limit,
        lysis_budget: split.lysis_budget,
        auction_base: split.auction_base,
        destination,
        desis_brief_hash,
        carry_over_credit,
        auction_entry_prices: request.auction_entry_prices.clone(),
        logical_anchor: request.logical_anchor,
    };
    receipt
        .validate_semantics()
        .map_err(protocol_error_to_revert)?;
    Ok(receipt)
}

fn protocol_error_to_revert(error: outbe_ocomp_protocol::ProtocolError) -> PrecompileError {
    crate::errors::caller_rejection(format!("invalid OCOMP request budget receipt: {error}"))
}
