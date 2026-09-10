//! IntexFactory runtime use-cases: issuance, settlement, Promis mining.

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};

use outbe_intex::{SeriesId, SERIES_ID_LEN};
use outbe_primitives::addresses::{INTEX_FACTORY_ADDRESS, VAULT_ROUTER_ADDRESS};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::units::PROTOCOL_AMOUNT_DECIMALS;

use outbe_intex::payout::ContributorLeafData;
use outbe_intex::IntexState;
use outbe_vaultrouter::api::IVaultRouter;

use crate::config;
use crate::constants::{
    DIST_CHUNK_LIMIT, INTEX_NFT1155_ADDRESS, MAX_RECIPIENTS_PER_ISSUANCE, MAX_SERIES_PER_MESSAGE,
    ORIGIN_ROUTER_ADDRESS, POW_DIFFICULTY, PRICE_RATE_DEN, PROCEEDS_FANIN_TIMEOUT_SECS,
};
use crate::errors::IntexFactoryError;
use crate::schema::{IntexFactoryContract, IssuanceParams};
use crate::sol_ext::{IIntexNFT1155, IOriginRouter, IReferenceCurrency, IERC1155, IERC20};
use IOriginRouter::IssuanceInstructionsParams;

/// Emit an IntexFactory event from `INTEX_FACTORY_ADDRESS`.
pub(crate) fn emit_event<E: SolEvent>(storage: &StorageHandle<'_>, event: E) -> Result<()> {
    storage.emit_event(INTEX_FACTORY_ADDRESS, event.encode_log_data())
}

/// Capture series identity in Intex, enroll it in the floor-bin index, and send
/// ISSUANCE_INSTRUCTIONS to every target chain of the day's snapshot. The
/// canonical IntexNFT1155 createSeries now arrives per chain via the ISSUANCE
/// broadcast (including a loopback leg on the origin), so there is no in-process
/// NFT call here.
pub fn issue(storage: &StorageHandle<'_>, params: IssuanceParams) -> Result<Vec<IssuanceLeg>> {
    if params.issued_intex_count == 0 {
        // Whether the day distributes is the caller's decision: one empty group
        // must not touch the state its siblings armed.
        return Ok(Vec::new());
    }

    // u32 timestamp; bounded until 2106.
    let issued_at = u32::try_from(storage.timestamp()?.to::<u64>())
        .map_err(|_| PrecompileError::Revert("block timestamp exceeds u32".into()))?;

    let mut factory = IntexFactoryContract::new(storage.clone());
    let cfg = config::read_from(&factory, storage.chain_id()?)?;

    let floor_price_minor = marked_up(params.entry_price_minor, cfg.floor_rate)?;
    let call_price_minor = marked_up(params.entry_price_minor, cfg.call_rate)?;

    let entry_price_minor_u64 = to_wire_price(params.entry_price_minor)?;
    let floor_price_minor_u64 = to_wire_price(floor_price_minor)?;
    let call_price_minor_u64 = to_wire_price(call_price_minor)?;

    let record = outbe_intex::CreateSeriesParams {
        series_id: params.series_id,
        worldwide_day: params.worldwide_day,
        issued_intex_count: params.issued_intex_count,
        promis_load_minor: params.promis_load_minor,
        entry_price_minor: params.entry_price_minor,
        floor_price_minor,
        call_price_minor,
        call_trigger: outbe_intex::IntexCallTrigger {
            call_window: cfg.call_window,
            call_threshold: cfg.call_threshold,
            call_notice_period: cfg.call_notice_period,
        },
        issued_at,
        issuance_currency: params.issuance_currency,
        reference_currency: params.reference_currency,
    };
    outbe_intex::api::create_series(storage, record)?;
    factory.widen_call_terms(
        params.reference_currency,
        cfg.call_window,
        cfg.call_threshold,
    )?;

    // Not sent here: only the caller sees the whole day, and a chain's share of it
    // travels in as few messages as the caps allow.
    let legs: Vec<IssuanceLeg> = issuance_legs(&params)
        .into_iter()
        .map(|(chain_id, recipients, quantities)| IssuanceLeg {
            chain_id,
            payload: IOriginRouter::IssuanceInstructionsParams {
                seriesId: params.series_id.into(),
                worldwideDay: params.worldwide_day.into(),
                issuedIntexCount: params.issued_intex_count,
                promisLoadMinor: params.promis_load_minor,
                entryPriceMinor: entry_price_minor_u64,
                floorPriceMinor: floor_price_minor_u64,
                callNoticePeriod: cfg.call_notice_period,
                issuanceCurrency: params.issuance_currency,
                referenceCurrency: params.reference_currency,
                callWindow: cfg.call_window,
                callThreshold: cfg.call_threshold,
                callPriceMinor: call_price_minor_u64,
                recipients,
                quantities,
            },
        })
        .collect();

    // Enroll into the unqualified floor-bin index for begin_block qualify.
    factory.insert_unqualified(
        params.series_id,
        params.reference_currency,
        floor_price_minor,
    )?;

    // Arm the creator-reward proceeds fan-in: the winning chains are expected to
    // route proceeds; creators are paid once all arrive or the deadline passes.
    let deadline = storage
        .timestamp()?
        .to::<u64>()
        .saturating_add(PROCEEDS_FANIN_TIMEOUT_SECS);
    outbe_intex::api::arm_proceeds(
        storage,
        params.worldwide_day,
        &params.recipient_chains,
        deadline,
    )?;

    emit_event(
        storage,
        crate::precompile::IIntexFactory::SeriesIssued {
            seriesId: params.series_id.into(),
            issuedIntexCount: params.issued_intex_count,
            entryPrice: params.entry_price_minor,
        },
    )?;

    Ok(legs)
}

/// What one series adds to one chain: the series to create and that chain's winners
/// (empty on a chain with none, which still needs the series for bridging).
#[derive(Clone)]
pub struct IssuanceLeg {
    pub chain_id: u32,
    pub payload: IOriginRouter::IssuanceInstructionsParams,
}

/// Pack a day's legs into per-chain messages, up to `MAX_SERIES_PER_MESSAGE` series and
/// `MAX_RECIPIENTS_PER_ISSUANCE` recipients each. A series with more winners spans several,
/// which the receiver's create-if-absent makes safe.
pub fn pack_issuance_messages(
    legs: Vec<IssuanceLeg>,
) -> Vec<(u32, Vec<IssuanceInstructionsParams>)> {
    let mut per_chain: Vec<(u32, Vec<IssuanceInstructionsParams>)> = Vec::new();
    for leg in legs {
        for slice in split_recipients(leg.payload) {
            // Legs arrive series by series, so this chain's open message is not the last one
            // built; matching on the tail alone would batch nothing.
            let open = per_chain
                .iter_mut()
                .rev()
                .find(|(chain, _)| *chain == leg.chain_id);
            match open {
                Some((_, message))
                    if message.len() < MAX_SERIES_PER_MESSAGE
                        && recipient_count(message) + slice.recipients.len()
                            <= MAX_RECIPIENTS_PER_ISSUANCE =>
                {
                    message.push(slice);
                }
                _ => per_chain.push((leg.chain_id, vec![slice])),
            }
        }
    }
    per_chain
}

/// Send a day's packed issuance messages, each stamped with its position in the chain's run.
/// Relay-float-funded: value 0, the router quotes and pays the bridge fee from its own float.
pub fn send_issuance(storage: &StorageHandle<'_>, legs: Vec<IssuanceLeg>) -> Result<()> {
    for ((chain_id, worldwide_day), messages) in
        chunk_issuance_messages(pack_issuance_messages(legs))
    {
        let total_chunks = u16::try_from(messages.len())
            .map_err(|_| PrecompileError::Revert("issuance chunk count exceeds u16".into()))?;
        for (chunk_index, series) in messages.into_iter().enumerate() {
            storage.call(
                ORIGIN_ROUTER_ADDRESS,
                U256::ZERO,
                IOriginRouter::sendIssuanceInstructionsCall {
                    dstChainId: chain_id,
                    worldwideDay: worldwide_day,
                    chunkIndex: chunk_index as u16,
                    totalChunks: total_chunks,
                    series,
                }
                .abi_encode()
                .into(),
            )?;
        }
    }
    Ok(())
}

/// One (chain, worldwide day) run of issuance messages, in send order: what the chunk header numbers.
pub(crate) type IssuanceRun = ((u32, u32), Vec<Vec<IssuanceInstructionsParams>>);

/// Group packed messages into the runs the chunk header numbers: one per (chain, day), the pair the
/// receiver counts chunks against. Callers pass one day's legs (clearing does), which is also what
/// keeps `pack_issuance_messages` from batching two days into one message.
pub(crate) fn chunk_issuance_messages(
    packed: Vec<(u32, Vec<IssuanceInstructionsParams>)>,
) -> Vec<IssuanceRun> {
    let mut runs: Vec<IssuanceRun> = Vec::new();
    for (chain_id, message) in packed {
        let key = (chain_id, message[0].worldwideDay);
        match runs.iter_mut().find(|(run_key, _)| *run_key == key) {
            Some((_, messages)) => messages.push(message),
            None => runs.push((key, vec![message])),
        }
    }
    runs
}

fn recipient_count(message: &[IssuanceInstructionsParams]) -> usize {
    message.iter().map(|item| item.recipients.len()).sum()
}

/// One series' instructions cut into pieces a message can carry; only the winners differ.
fn split_recipients(payload: IssuanceInstructionsParams) -> Vec<IssuanceInstructionsParams> {
    if payload.recipients.len() <= MAX_RECIPIENTS_PER_ISSUANCE {
        return vec![payload];
    }
    (0..payload.recipients.len())
        .step_by(MAX_RECIPIENTS_PER_ISSUANCE)
        .map(|start| {
            let end = (start + MAX_RECIPIENTS_PER_ISSUANCE).min(payload.recipients.len());
            IssuanceInstructionsParams {
                recipients: payload.recipients[start..end].to_vec(),
                quantities: payload.quantities[start..end].to_vec(),
                ..payload.clone()
            }
        })
        .collect()
}

/// One `(chain, recipients, quantities)` issuance leg per snapshot chain: winners land on their
/// own chain and every other chain gets an empty leg, so the series is created there too (needed
/// for user NFT bridging).
pub(crate) fn issuance_legs(params: &IssuanceParams) -> Vec<(u32, Vec<Address>, Vec<U256>)> {
    params
        .snapshot_chains
        .iter()
        .map(|&chain_id| {
            let mut recipients = Vec::new();
            let mut quantities = Vec::new();
            for (i, &c) in params.recipient_chains.iter().enumerate() {
                if c == chain_id {
                    recipients.push(params.recipients[i]);
                    quantities.push(params.quantities[i]);
                }
            }
            (chain_id, recipients, quantities)
        })
        .collect()
}

/// Narrows a six-decimal COEN/ISO price to the wire's existing `u64` shape.
pub fn to_wire_price(price_minor: U256) -> Result<u64> {
    u64::try_from(price_minor)
        .map_err(|_| PrecompileError::Revert("price exceeds the wire type".into()))
}

/// Applies a markup rate in percentage points: `entry * (100 + rate) / 100`.
pub fn marked_up(entry_price: U256, rate: u16) -> Result<U256> {
    entry_price
        .checked_mul(U256::from(PRICE_RATE_DEN + rate))
        .map(|v| v / U256::from(PRICE_RATE_DEN))
        .ok_or_else(|| PrecompileError::Revert("marked-up price overflow".into()))
}

/// Decimals a price x PROMIS load product carries: both protocol factors stay
/// on the six-decimal scale independently of native COEN denomination.
const PRODUCT_DECIMALS: u32 = 2 * PROTOCOL_AMOUNT_DECIMALS as u32;

/// Converts a price (scale 1e6) x PROMIS load (scale 1e6) product into payment-token
/// minor units, rounded up in favor of the reserve receiving the settlement.
pub(crate) fn product_to_payment_units(product: U256, payment_decimals: u8) -> Result<U256> {
    const MAX_PAYMENT_DECIMALS: u8 = 18;

    if payment_decimals > MAX_PAYMENT_DECIMALS {
        return Err(IntexFactoryError::UnsupportedPaymentDecimals(payment_decimals).into());
    }

    let payment_decimals = u32::from(payment_decimals);
    if payment_decimals < PRODUCT_DECIMALS {
        Ok(
            product
                .div_ceil(U256::from(10u64).pow(U256::from(PRODUCT_DECIMALS - payment_decimals))),
        )
    } else if payment_decimals > PRODUCT_DECIMALS {
        product
            .checked_mul(U256::from(10u64).pow(U256::from(payment_decimals - PRODUCT_DECIMALS)))
            .ok_or_else(|| PrecompileError::Revert("settlement conversion overflow".into()))
    } else {
        Ok(product)
    }
}

/// Set the dual-wallet authorized settler for `holder`'s position in `series_id`.
/// `holder` is the caller (the precompile passes its caller).
pub fn set_authorized_settler(
    storage: &StorageHandle<'_>,
    holder: Address,
    series_id: SeriesId,
    settler: Address,
) -> Result<()> {
    if holder.is_zero() || settler.is_zero() {
        return Err(IntexFactoryError::ZeroAddress.into());
    }
    let mut factory = IntexFactoryContract::new(storage.clone());
    factory.write_authorized_settler(holder, series_id, settler)
}

/// Credit auction proceeds (native COEN, arriving as `amount` = msg.value) from
/// one target chain into the day's pot. Gated to the OriginRouter. Creators are
/// paid once every winning chain has routed its proceeds (or the fan-in deadline
/// passes); the payout itself runs in the begin-block drain. Because proceeds
/// arrive once per winning chain (loopback same-block, remote minutes later),
/// the credit only accumulates - it never reverts on a repeat or ownerless day,
/// which would strand that chain's delivery.
pub fn distribute(
    storage: &StorageHandle<'_>,
    caller: Address,
    worldwide_day: WorldwideDay,
    src_chain_id: u32,
    amount: U256,
) -> Result<()> {
    #[cfg(not(feature = "e2e-test"))]
    let from_router = caller == ORIGIN_ROUTER_ADDRESS;
    #[cfg(feature = "e2e-test")]
    let from_router =
        caller == ORIGIN_ROUTER_ADDRESS || caller == crate::constants::PROCEEDS_TEST_SENDER;
    if !from_router {
        return Err(IntexFactoryError::NotOriginRouter.into());
    }
    if amount.is_zero() {
        return Err(IntexFactoryError::ZeroAmount.into());
    }
    outbe_intex::api::credit_proceeds(storage, worldwide_day, src_chain_id, amount)?;
    emit_event(
        storage,
        crate::precompile::IIntexFactory::ProceedsCredited {
            worldwideDay: worldwide_day.value(),
            srcChainId: src_chain_id,
            amount,
        },
    )?;
    let now = storage.timestamp()?.to::<u64>();
    try_settle_proceeds(storage, worldwide_day, now)
}

/// Start a distribution round for a series if its proceeds fan-in is satisfied
/// (all winning chains in) or its deadline has passed. Idempotent: it no-ops
/// while a round is still draining, so repeated arrivals and the begin-block
/// sweep can both call it safely.
pub(crate) fn try_settle_proceeds(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    now: u64,
) -> Result<()> {
    // Never overlap a round that is still paying out.
    if outbe_intex::api::get_progress(storage, worldwide_day)?.is_some() {
        return Ok(());
    }
    // Batches drain a certified round, not this sweep, and a day gets exactly
    // one - anything arriving after it opened missed the window.
    if outbe_intex::api::certified_payout_round(storage, worldwide_day.value())?.is_some() {
        let late = outbe_intex::api::take_proceeds_pot(storage, worldwide_day)?;
        if !late.is_zero() {
            burn_late_proceeds(storage, worldwide_day.value(), late)?;
        }
        return Ok(());
    }
    let deadline = outbe_intex::api::proceeds_deadline(storage, worldwide_day)?;
    if deadline == 0 {
        // Never armed - or already finalized. A certified day past finalization
        // (an ownerless one never opens a round) treats any re-delivery as late.
        if outbe_intex::api::certified_contributor_generation(storage, worldwide_day)?.is_some() {
            let late = outbe_intex::api::take_proceeds_pot(storage, worldwide_day)?;
            if !late.is_zero() {
                burn_late_proceeds(storage, worldwide_day.value(), late)?;
            }
        }
        return Ok(());
    }
    let complete = outbe_intex::api::proceeds_ready(storage, worldwide_day)?;
    if !complete && now < deadline {
        return Ok(()); // keep waiting for the remaining chains
    }

    let certified = outbe_intex::api::certified_contributor_generation(storage, worldwide_day)?;
    let legacy_total = outbe_intex::api::contributor_total(storage, worldwide_day)?;
    // Proceeds can complete before quorum installs the root, so hold the pot
    // until the window closes rather than burn a day about to become payable.
    if certified.is_none() && legacy_total.is_zero() && now < deadline {
        return Ok(());
    }

    let pot = outbe_intex::api::take_proceeds_pot(storage, worldwide_day)?;
    if pot.is_zero() {
        // Nothing to pay, and nothing left to wait for: an incomplete fan-in only
        // reaches here past its deadline. Finalize either way, so a day no chain
        // ever paid into leaves the awaiting set instead of being re-swept forever.
        // A later arrival is still caught, and burned, by the branches above.
        outbe_intex::api::finalize_proceeds(storage, worldwide_day)?;
        return Ok(());
    }

    if let Some(generation) = certified {
        if generation.contributor_count == 0 {
            burn_ownerless_proceeds(storage, worldwide_day, pot)?;
        } else {
            outbe_intex::api::open_certified_payout_round(storage, worldwide_day.value(), pot)?;
            emit_event(
                storage,
                crate::precompile::IIntexFactory::ContributorPayoutOpened {
                    worldwideDay: worldwide_day.value(),
                    amount: pot,
                    contributorCount: generation.contributor_count,
                },
            )?;
        }
        // Unconditional: batches drain the round, so staying in the awaiting set
        // would re-enter this sweep every block.
        outbe_intex::api::finalize_proceeds(storage, worldwide_day)?;
        return Ok(());
    }

    let total = legacy_total;
    if total.is_zero() {
        // Ownerless proceeds: burn instead of stranding them.
        burn_ownerless_proceeds(storage, worldwide_day, pot)?;
        if complete {
            outbe_intex::api::finalize_proceeds(storage, worldwide_day)?;
        }
        return Ok(());
    }

    // Finalize on completion only when every winning chain is in; otherwise the
    // deadline forced a partial payout and the map is retained for a top-up.
    outbe_intex::api::set_proceeds_finalize_on_done(storage, worldwide_day, complete)?;
    outbe_intex::api::start_distribution(storage, worldwide_day, pot, total)
}

/// Pay one chunk-aligned range of certified contributors.
///
/// Permissionless: a batch is accepted only if its records rebuild the day's
/// certified contributor root. Shares divide the amount frozen at round open,
/// never the live balance.
pub(crate) fn pay_contributor_batch(
    storage: &StorageHandle<'_>,
    worldwide_day: u32,
    start_index: u32,
    leaves: &[crate::precompile::IIntexFactory::ContributorLeaf],
    proof: &[B256],
) -> Result<()> {
    let round = outbe_intex::api::certified_payout_round(storage, worldwide_day)?
        .ok_or(IntexFactoryError::NoCertifiedRound(worldwide_day))?;
    let leaf_count =
        u32::try_from(leaves.len()).map_err(|_| IntexFactoryError::BadContributorBatch)?;

    // Cheapest gate first: a batch another sender already paid costs one
    // storage read instead of a full proof verification.
    outbe_intex::api::require_certified_leaves_unpaid(
        storage,
        worldwide_day,
        start_index,
        leaf_count,
    )?;

    let decoded: Vec<ContributorLeafData> = leaves.iter().map(decode_contributor_leaf).collect();
    let generation = outbe_intex::api::verify_certified_contributor_batch(
        storage,
        worldwide_day,
        start_index,
        &decoded,
        proof,
    )?;
    storage.with_checkpoint(|| {
        let mut shares = Vec::with_capacity(decoded.len());
        let mut paid = U256::ZERO;
        for leaf in &decoded {
            // Floor for every leaf: batches arrive in any order, so none can be
            // the one that absorbs the remainder.
            let share = round
                .amount
                .checked_mul(leaf.nominal)
                .ok_or(IntexFactoryError::DistributionOverflow(worldwide_day))?
                / generation.eligible_nominal_total;
            paid = paid
                .checked_add(share)
                .ok_or(IntexFactoryError::DistributionOverflow(worldwide_day))?;
            shares.push(share);
        }
        // One balance serves every day; bounding before any transfer keeps a
        // bad denominator from spending another day's proceeds and from
        // draining into an insufficient-balance Fatal mid-batch.
        let total_paid = round
            .paid_so_far
            .checked_add(paid)
            .ok_or(IntexFactoryError::DistributionOverflow(worldwide_day))?;
        if total_paid > round.amount {
            return Err(IntexFactoryError::PayoutExceedsRound(worldwide_day).into());
        }
        for (leaf, share) in decoded.iter().zip(&shares) {
            storage.transfer_balance(INTEX_FACTORY_ADDRESS, leaf.owner, *share)?;
        }
        outbe_intex::api::mark_certified_leaves_paid(
            storage,
            worldwide_day,
            start_index,
            leaf_count,
            paid,
        )?;
        emit_event(
            storage,
            crate::precompile::IIntexFactory::ContributorBatchPaid {
                worldwideDay: worldwide_day,
                startIndex: start_index,
                leafCount: leaf_count,
                paidAmount: paid,
            },
        )?;
        close_round_if_complete(storage, worldwide_day, generation.contributor_count)
    })
}

/// Burns what floor division left behind, once every leaf of the round is paid.
///
/// Completion is what gates this: until the last leaf is paid the balance still
/// holds outstanding shares, which are owed rather than left over.
fn close_round_if_complete(
    storage: &StorageHandle<'_>,
    worldwide_day: u32,
    contributor_count: u32,
) -> Result<()> {
    let round = outbe_intex::api::certified_payout_round(storage, worldwide_day)?
        .ok_or(IntexFactoryError::NoCertifiedRound(worldwide_day))?;
    if round.paid_leaf_count != contributor_count {
        return Ok(());
    }
    // The per-batch cap keeps the sum within `amount`; a shortfall here means
    // the round accounting is corrupt.
    let remainder = round.amount.checked_sub(round.paid_so_far).ok_or_else(|| {
        PrecompileError::Fatal("certified payout exceeded the round amount".into())
    })?;
    if !remainder.is_zero() {
        storage.decrease_balance(INTEX_FACTORY_ADDRESS, remainder)?;
    }
    emit_event(
        storage,
        crate::precompile::IIntexFactory::ContributorRoundClosed {
            worldwideDay: worldwide_day,
            paidAmount: round.paid_so_far,
            burnedAmount: remainder,
        },
    )
}

/// Destroy proceeds that arrived after the day's payout round had already opened.
fn burn_late_proceeds(storage: &StorageHandle<'_>, worldwide_day: u32, amount: U256) -> Result<()> {
    storage.decrease_balance(INTEX_FACTORY_ADDRESS, amount)?;
    emit_event(
        storage,
        crate::precompile::IIntexFactory::LateProceedsBurned {
            worldwideDay: worldwide_day,
            amount,
        },
    )
}

/// Progress of one day's payout round; all-zero when no round is open.
pub(crate) fn contributor_payout_round(
    storage: &StorageHandle<'_>,
    worldwide_day: u32,
) -> Result<crate::precompile::IIntexFactory::ContributorRound> {
    let Some(round) = outbe_intex::api::certified_payout_round(storage, worldwide_day)? else {
        return Ok(crate::precompile::IIntexFactory::ContributorRound {
            amount: U256::ZERO,
            contributorCount: 0,
            paidSoFar: U256::ZERO,
            paidLeafCount: 0,
        });
    };
    let contributor_count = outbe_intex::api::certified_contributor_generation(
        storage,
        outbe_primitives::time::WorldwideDay::new(worldwide_day),
    )?
    .map_or(0, |generation| generation.contributor_count);
    Ok(crate::precompile::IIntexFactory::ContributorRound {
        amount: round.amount,
        contributorCount: contributor_count,
        paidSoFar: round.paid_so_far,
        paidLeafCount: round.paid_leaf_count,
    })
}

/// The ABI leaf and the canonical leaf carry the same three words, so this is a
/// plain field copy.
fn decode_contributor_leaf(
    leaf: &crate::precompile::IIntexFactory::ContributorLeaf,
) -> ContributorLeafData {
    ContributorLeafData {
        owner: leaf.owner,
        source_tribute_id: leaf.sourceTributeId,
        nominal: leaf.nominal,
    }
}

/// Begin-block sweep: settle every series whose proceeds fan-in deadline has
/// passed. The set holds one entry per day and releases it once its deadline is
/// out, so a whole pass is a handful of reads. Each series runs in its own
/// checkpoint so one failure is retried next block instead of halting the block.
pub(crate) fn sweep_proceeds_deadlines(storage: &StorageHandle<'_>, now: u64) -> Result<()> {
    let count = outbe_intex::api::awaiting_proceeds_count(storage)?;
    // Read the set before settling: settling swap-removes from it.
    let mut worldwide_days = Vec::with_capacity(count as usize);
    for i in 0..count {
        worldwide_days.push(outbe_intex::api::awaiting_proceeds_at(storage, i)?);
    }
    for worldwide_day in worldwide_days {
        let res = storage.with_checkpoint(|| try_settle_proceeds(storage, worldwide_day, now));
        if let Err(e) = res {
            tracing::warn!(target: "outbe::intexfactory", worldwide_day = worldwide_day.value(), error = ?e, "proceeds sweep: skipping series");
        }
    }
    Ok(())
}

/// Burn the ownerless proceeds of a series with no recorded contributors:
/// destroy the native COEN held by the factory, reducing total supply.
fn burn_ownerless_proceeds(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    amount: U256,
) -> Result<()> {
    storage.decrease_balance(INTEX_FACTORY_ADDRESS, amount)?;
    emit_event(
        storage,
        crate::precompile::IIntexFactory::ProceedsBurned {
            worldwideDay: worldwide_day.value(),
            amount,
        },
    )
}

/// Pay up to `limit` contributors of an in-flight distribution, advancing the
/// cursor. The last contributor absorbs the integer-division remainder so the
/// full `amount` is paid out exactly. On reaching the last contributor the
/// distribution is finalized (progress + contributor map cleared). Driven by
/// the begin-block drain.
pub(crate) fn pay_chunk(
    storage: &StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    limit: u32,
) -> Result<()> {
    let mut progress = outbe_intex::api::get_progress(storage, worldwide_day)?
        .ok_or(IntexFactoryError::NoDistribution(worldwide_day.value()))?;
    let count = outbe_intex::api::contributor_count(storage, worldwide_day)?;
    let end = progress.cursor.saturating_add(limit).min(count);

    // A zero denominator would panic on divide; begin-block panics halt the chain (not checkpoint-isolated),
    // so fail as an isolated Err instead.
    if progress.total_nominal.is_zero() {
        return Err(IntexFactoryError::NoContributors(worldwide_day.value()).into());
    }

    let mut paid = progress.paid_so_far;
    for i in progress.cursor..end {
        let (owner, nominal) = outbe_intex::api::contributor_at(storage, worldwide_day, i)?;
        // The final contributor absorbs the rounding remainder so the sum of
        // payouts equals `amount` exactly. checked_mul: isolated Err over a silent wrap.
        let share =
            if i == count - 1 {
                progress.amount - paid
            } else {
                progress.amount.checked_mul(nominal).ok_or(
                    IntexFactoryError::DistributionOverflow(worldwide_day.value()),
                )? / progress.total_nominal
            };
        storage.transfer_balance(INTEX_FACTORY_ADDRESS, owner, share)?;
        paid += share;
    }

    if end == count {
        // End this round (progress + active-set entry). Whether the contributor
        // map is also cleared depends on the fan-in: finalize when every winning
        // chain is in, otherwise retain the map for a late top-up.
        outbe_intex::api::finish_distribution_round(storage, worldwide_day)?;
        emit_event(
            storage,
            crate::precompile::IIntexFactory::ProceedsDistributed {
                worldwideDay: worldwide_day.value(),
                amount: progress.amount,
                contributors: count,
            },
        )?;
        if outbe_intex::api::proceeds_finalize_on_done(storage, worldwide_day)? {
            // A straggler (or a chain sending its proceeds in parts) can top the
            // pot up while this final round drains. finalize clears the map, so
            // pay any such top-up over it first and finalize only once the pot is
            // empty - otherwise the top-up is later burned as ownerless.
            let pot = outbe_intex::api::take_proceeds_pot(storage, worldwide_day)?;
            if pot.is_zero() {
                outbe_intex::api::finalize_proceeds(storage, worldwide_day)?;
            } else {
                let total = outbe_intex::api::contributor_total(storage, worldwide_day)?;
                outbe_intex::api::start_distribution(storage, worldwide_day, pot, total)?;
            }
        }
    } else {
        progress.cursor = end;
        progress.paid_so_far = paid;
        outbe_intex::api::save_progress(storage, &progress)?;
    }
    Ok(())
}

/// Begin-block drain: advance every in-flight distribution by one chunk
/// (`DIST_CHUNK_LIMIT` payouts). Completed distributions remove themselves from
/// the active set inside `pay_chunk`, so the snapshot avoids iterating a set
/// that mutates underneath us.
pub(crate) fn drain_distributions(storage: &StorageHandle<'_>) -> Result<()> {
    let count = outbe_intex::api::active_dist_count(storage)?;
    // One open round per day, and each pays at most a chunk per block, so the
    // set is a handful. Read it before paying: finishing a round removes from it.
    let mut worldwide_days = Vec::with_capacity(count as usize);
    for i in 0..count {
        worldwide_days.push(outbe_intex::api::active_dist_at(storage, i)?);
    }
    for worldwide_day in worldwide_days {
        // Per-series isolation: Err reverts the series' checkpoint, retried next block.
        let res = storage.with_checkpoint(|| pay_chunk(storage, worldwide_day, DIST_CHUNK_LIMIT));
        if let Err(e) = res {
            tracing::warn!(target: "outbe::intexfactory", worldwide_day = worldwide_day.value(), error = ?e, "distribution drain: skipping series");
        }
    }
    Ok(())
}

/// Settle: `settler` is the caller. The cost is discharged by spending a PayNote,
/// so no tokens move here; the NFT move goes via storage.call.
pub fn settle(
    storage: &StorageHandle<'_>,
    series_id: SeriesId,
    intex_holder: Address,
    settler: Address,
    amount: U256,
    paynote_proof: &[u8],
) -> Result<()> {
    if intex_holder.is_zero() || settler.is_zero() {
        return Err(IntexFactoryError::ZeroAddress.into());
    }
    if amount.is_zero() {
        return Err(IntexFactoryError::ZeroAmount.into());
    }

    let series = outbe_intex::api::read_series(storage, series_id)?;
    let state = series.lifecycle_state()?;
    // Settle is allowed in Qualified (voluntary) and Called (forced).
    if state != IntexState::Qualified && state != IntexState::Called {
        return Err(IntexFactoryError::NotSettleable(series.state).into());
    }
    // The deadline only constrains forced settlement (Called).
    if state == IntexState::Called {
        let now = storage.timestamp()?.to::<u64>();
        let deadline = u64::from(series.called_at) + u64::from(series.call_notice_period);
        if now > deadline {
            return Err(IntexFactoryError::DeadlineExpired.into());
        }
    }

    // Issued balance (NFT). Issued token id = uint256(seriesId).
    let issued_token_id = U256::from_be_slice(series_id.as_bytes());
    let balance = nft_balance_of(storage, intex_holder, issued_token_id)?;
    if balance.is_zero() {
        return Err(IntexFactoryError::ZeroBalance.into());
    }
    if amount > balance {
        return Err(IntexFactoryError::AmountExceedsBalance.into());
    }

    // Dual-wallet authorization: only the holder or its authorized settler.
    let factory = IntexFactoryContract::new(storage.clone());
    if intex_holder != settler
        && factory.read_authorized_settler(intex_holder, series_id)? != settler
    {
        return Err(IntexFactoryError::NotAuthorized.into());
    }

    // Last, so a doomed settle never pays for proof verification.
    discharge_cost(storage, &series, amount, settler, paynote_proof)?;

    // Burn Issued from holder, issue Settled to the settler.
    storage.call(
        INTEX_NFT1155_ADDRESS,
        U256::ZERO,
        IIntexNFT1155::settleCall {
            seriesId: series_id.into(),
            from: intex_holder,
            to: settler,
            amount,
        }
        .abi_encode()
        .into(),
    )?;

    let settled_units = u32::try_from(amount)
        .map_err(|_| PrecompileError::Revert("settled amount exceeds u32".into()))?;
    outbe_intex::api::record_settled_units(storage, series_id, settled_units)?;

    emit_event(
        storage,
        crate::precompile::IIntexFactory::Settled {
            seriesId: series_id.into(),
            intexHolder: intex_holder,
            settler,
            amount,
        },
    )
}

/// Discharges the settlement cost by spending one PayNote.
fn discharge_cost(
    storage: &StorageHandle<'_>,
    series: &outbe_intex::SeriesRecord,
    amount: U256,
    settler: Address,
    paynote_proof: &[u8],
) -> Result<()> {
    let claim = outbe_paynote::api::consume(storage, paynote_proof)?;

    // Notes are bearer: anyone can relay a proof, so bind its spender to the settler.
    if claim.spender != settler {
        return Err(IntexFactoryError::PayNoteSpenderMismatch {
            expected: settler,
            actual: claim.spender,
        }
        .into());
    }

    let currency = accept_payment_token(storage, claim.asset, series)?;
    let cost = cost_in_token(storage, series, claim.asset, currency)?
        .checked_mul(amount)
        .ok_or_else(|| PrecompileError::Revert("settlement cost overflow".into()))?;
    if claim.spend_amount < cost {
        return Err(IntexFactoryError::PayNoteUndercoversCost {
            covered: claim.spend_amount,
            required: cost,
        }
        .into());
    }
    Ok(())
}

// --- storage.call helpers (localnet-exercised) ---

fn nft_balance_of(storage: &StorageHandle<'_>, account: Address, id: U256) -> Result<U256> {
    let ret = storage.staticcall(
        INTEX_NFT1155_ADDRESS,
        IERC1155::balanceOfCall { account, id }.abi_encode().into(),
    )?;
    IERC1155::balanceOfCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("NFT balanceOf undecodable".into()))
}

/// What settling one Intex of `series_id` with `payment_token` costs, and which of
/// the series' two currencies that token settles on. Rejects a token the series
/// does not accept.
pub fn quote_settlement(
    storage: &StorageHandle<'_>,
    series_id: SeriesId,
    payment_token: Address,
) -> Result<(u16, U256)> {
    let series = outbe_intex::api::read_series(storage, series_id)?;
    let currency = accept_payment_token(storage, payment_token, &series)?;
    let settlement_currency = match currency {
        PaymentCurrency::Reference => series.reference_currency,
        PaymentCurrency::Issuance => series.issuance_currency,
    };
    Ok((
        settlement_currency,
        cost_in_token(storage, &series, payment_token, currency)?,
    ))
}

/// Which of the series' two currencies a payment token is denominated in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PaymentCurrency {
    Reference,
    Issuance,
}

/// Per-Intex cost in `token`'s minor units. The Cost Amount is denominated in the
/// reference currency; an issuance-currency token is charged at the live COEN cross
/// rate. Multiplying scaling is exact and precedes the conversion; dividing scaling
/// follows it, and nested ceilings collapse to one net rounding, always upwards.
fn cost_in_token(
    storage: &StorageHandle<'_>,
    series: &outbe_intex::SeriesRecord,
    token: Address,
    currency: PaymentCurrency,
) -> Result<U256> {
    let payment_decimals = erc20_decimals(storage, token)?;
    let product = series
        .entry_price_minor
        .checked_mul(series.promis_load_minor)
        .ok_or_else(|| PrecompileError::Revert("cost amount overflow".into()))?;
    let target_iso = match currency {
        PaymentCurrency::Reference => series.reference_currency,
        PaymentCurrency::Issuance => series.issuance_currency,
    };
    let convert = |amount| {
        outbe_oracle::api::fresh_currency_cross_rate(
            storage.clone(),
            series.reference_currency,
            target_iso,
            amount,
        )
    };
    if u32::from(payment_decimals) >= PRODUCT_DECIMALS {
        convert(product_to_payment_units(product, payment_decimals)?)
    } else {
        product_to_payment_units(convert(product)?, payment_decimals)
    }
}

/// Rejects `token` unless the router holds a vault for it and the token reports
/// one of the series' two currencies; returns which one. Registration is checked
/// first: an unregistered token need not implement `isoCode()` at all.
fn accept_payment_token(
    storage: &StorageHandle<'_>,
    token: Address,
    series: &outbe_intex::SeriesRecord,
) -> Result<PaymentCurrency> {
    let ret = storage.staticcall(
        VAULT_ROUTER_ADDRESS,
        IVaultRouter::assetVaultsCountCall { asset: token }
            .abi_encode()
            .into(),
    )?;
    let vaults = IVaultRouter::assetVaultsCountCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("assetVaultsCount undecodable".into()))?;
    if vaults.is_zero() {
        return Err(IntexFactoryError::PaymentTokenNotRegistered(token).into());
    }

    let iso = asset_iso_code(storage, token)?;
    if iso == series.reference_currency {
        return Ok(PaymentCurrency::Reference);
    }
    if iso == series.issuance_currency {
        return Ok(PaymentCurrency::Issuance);
    }
    Err(IntexFactoryError::SettlementCurrencyMismatch(iso).into())
}

fn asset_iso_code(storage: &StorageHandle<'_>, token: Address) -> Result<u16> {
    let ret = storage.staticcall(
        token,
        IReferenceCurrency::isoCodeCall {}.abi_encode().into(),
    )?;
    IReferenceCurrency::isoCodeCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("isoCode undecodable".into()))
}

fn erc20_decimals(storage: &StorageHandle<'_>, token: Address) -> Result<u8> {
    let ret = storage.staticcall(token, IERC20::decimalsCall {}.abi_encode().into())?;
    IERC20::decimalsCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("ERC20 decimals undecodable".into()))
}

/// minePromis: PoW-gated burn of Settled then mint of Promis. `holder` is the
/// caller.
pub fn mine_promis(
    storage: &StorageHandle<'_>,
    series_id: SeriesId,
    holder: Address,
    amount: U256,
    nonce: u64,
    auth: outbe_promisfactory::api::ModifyAuth,
) -> Result<U256> {
    if holder.is_zero() {
        return Err(IntexFactoryError::ZeroAddress.into());
    }
    if amount.is_zero() {
        return Err(IntexFactoryError::ZeroAmount.into());
    }

    let series = outbe_intex::api::read_series(storage, series_id)?;
    let settled = nft_balance_of(storage, holder, settled_token_id(series_id))?;
    if settled < amount {
        return Err(IntexFactoryError::InsufficientSettled.into());
    }

    let promis_amount = series
        .promis_load_minor
        .checked_mul(amount)
        .ok_or_else(|| PrecompileError::Revert("promis amount overflow".into()))?;

    // PoW over the per-(series, holder) sequence; bump it on success.
    let mut factory = IntexFactoryContract::new(storage.clone());
    let seq = factory.read_mine_seq(series_id, holder)?;
    validate_pow(holder, promis_amount, series_id, seq, nonce)?;
    factory.write_mine_seq(series_id, holder, seq + 1)?;

    // Burn Settled from holder on the NFT.
    storage.call(
        INTEX_NFT1155_ADDRESS,
        U256::ZERO,
        IIntexNFT1155::burnSettledCall {
            holder,
            seriesId: series_id.into(),
            amount,
        }
        .abi_encode()
        .into(),
    )?;

    // Promis is confidential: the mint runs inside the enclave, authorized by the
    // holder's Promis modify key (the `mac`/`opNonce` must bind `promis_amount`).
    outbe_promisfactory::api::mint(storage.clone(), holder, promis_amount, auth)?;

    emit_event(
        storage,
        crate::precompile::IIntexFactory::PromisMined {
            seriesId: series_id.into(),
            holder,
            amount,
            promisAmount: promis_amount,
        },
    )?;
    Ok(promis_amount)
}

/// Settled token id = `uint256(keccak256("SETTLED" ++ seriesId))`.
pub(crate) fn settled_token_id(series_id: SeriesId) -> U256 {
    let mut buf = Vec::with_capacity(7 + SERIES_ID_LEN);
    buf.extend_from_slice(b"SETTLED");
    buf.extend_from_slice(series_id.as_bytes());
    U256::from_be_bytes(keccak256(&buf).0)
}

/// PoW hash: `SHA256(holder ++ promisAmount_be32 ++ seriesId ++ seq_be4 ++ nonce_be8)`.
pub(crate) fn compute_pow_hash(
    holder: Address,
    promis_amount: U256,
    series_id: SeriesId,
    seq: u32,
    nonce: u64,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(20 + 32 + SERIES_ID_LEN + 4 + 8);
    data.extend_from_slice(holder.as_slice());
    data.extend_from_slice(&promis_amount.to_be_bytes::<32>());
    data.extend_from_slice(series_id.as_bytes());
    data.extend_from_slice(&seq.to_be_bytes());
    data.extend_from_slice(&nonce.to_be_bytes());

    let digest = ring::digest::digest(&ring::digest::SHA256, &data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The PoW hash must have `POW_DIFFICULTY` leading zero bytes.
pub(crate) fn validate_pow(
    holder: Address,
    promis_amount: U256,
    series_id: SeriesId,
    seq: u32,
    nonce: u64,
) -> Result<()> {
    let hash = compute_pow_hash(holder, promis_amount, series_id, seq, nonce);
    for b in &hash[..POW_DIFFICULTY] {
        if *b != 0 {
            return Err(IntexFactoryError::InsufficientProofOfWork.into());
        }
    }
    Ok(())
}
