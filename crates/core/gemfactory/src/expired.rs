//! Daily sweep returning the capacity an expired merchant position never issued.

use alloy_primitives::U256;
use outbe_primitives::{block::BlockRuntimeContext, error::Result};

use crate::constants::MAX_POSITION_EXPIRIES_PER_RUN;
use crate::runtime::emit_event;
use crate::schema::{GemFactoryContract, GemPosition};

pub fn run_daily(ctx: &BlockRuntimeContext) -> Result<()> {
    sweep_expired_positions(ctx)?;
    Ok(())
}

/// Positions queue in parking order, so a head still inside its year ends the pass.
pub(crate) fn sweep_expired_positions(ctx: &BlockRuntimeContext) -> Result<u32> {
    let storage = &ctx.storage;
    let mut factory = GemFactoryContract::new(storage.clone());
    let head = factory.live_head.read()?;
    let tail = factory.live_tail.read()?;
    if head >= tail {
        return Ok(0);
    }

    let now = ctx.block.timestamp;
    let mut budget = MAX_POSITION_EXPIRIES_PER_RUN;
    let mut expired: u32 = 0;
    // Slots, not just actions: a position the sweep cannot retire pins the head, and
    // the run of emptied slots behind it would otherwise grow without bound.
    for index in head..tail.min(head.saturating_add(MAX_POSITION_EXPIRIES_PER_RUN)) {
        if budget == 0 {
            break;
        }
        let Some(position_id) = factory.live_queue_slot(index)? else {
            continue;
        };
        let Some(record) = factory.positions.get(position_id)? else {
            factory.remove_live_position(position_id)?;
            continue;
        };
        // `>=`, copied from the guard in `issue_merchant_gem`: the merchant can no
        // longer issue from the position at exactly this instant.
        if now < record.expires_at {
            break;
        }
        budget -= 1;

        match storage.with_checkpoint(|| expire_position(ctx, &record)) {
            Ok(()) => expired = expired.saturating_add(1),
            Err(error) => {
                tracing::warn!(
                    target: "outbe::gemfactory",
                    %position_id,
                    error = ?error,
                    "position sweep: skipping position"
                );
            }
        }
    }

    factory.compact_live_queue()?;
    Ok(expired)
}

/// The record is kept: a merchant should still see the position they held.
fn expire_position(ctx: &BlockRuntimeContext, record: &GemPosition) -> Result<()> {
    let storage = &ctx.storage;
    let mut factory = GemFactoryContract::new(storage.clone());
    let position_id = record.position_id;

    let returned = record.remaining_capacity;
    factory.positions.update(&GemPosition {
        remaining_capacity: U256::ZERO,
        ..*record
    })?;
    factory.remove_live_position(position_id)?;

    if !returned.is_zero() {
        outbe_promislimit::PromisLimitContract::new(storage.clone())
            .add_to_total_unallocated(returned)?;
    }
    emit_event(
        storage,
        crate::precompile::IGemFactory::GemPositionExpired {
            positionId: position_id,
            merchant: record.merchant,
            sourceIntexId: record.source_intex_id.into(),
            returnedCapacity: returned,
        },
    )
}
