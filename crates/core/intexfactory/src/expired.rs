//! Begin-block expiry sweep: closes a called group's settlement window and returns
//! the Promis load of everything left unrealized to the unallocated limit.

use alloy_primitives::U256;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::{PrecompileError, Result},
    storage::StorageHandle,
};

use crate::constants::MAX_SERIES_ACTIONS_PER_BLOCK;
use crate::runtime::emit_event;
use crate::schema::IntexFactoryContract;

/// Retire every group whose settlement window has closed, earliest bucket first.
pub(crate) fn sweep_expiry_deadlines(ctx: &BlockRuntimeContext) -> Result<()> {
    let storage = &ctx.storage;
    let now = ctx.block.timestamp;
    let mut budget = MAX_SERIES_ACTIONS_PER_BLOCK;

    while budget > 0 {
        let mut factory = IntexFactoryContract::new(storage.clone());
        let Some(day) = factory.first_expiry_day()? else {
            break;
        };
        // A deadline lies inside its own bucket, so an open one holds nobody due.
        if now < IntexFactoryContract::bucket_end(day) {
            break;
        }
        let len = factory.expiry_bucket_len.read(&day)?;
        let resume = match factory.expiry_sweep_day.read()? == day {
            true => factory.expiry_cursor.read()?.min(len),
            false => 0,
        };

        let mut slot = resume;
        while slot < len {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let Some((iso_code, worldwide_day)) = factory.expiry_slot(day, slot)? else {
                slot += 1;
                continue;
            };
            let key = IntexFactoryContract::scoped(iso_code, worldwide_day.value());
            // Strictly after, like `settle`: a hook runs before the block's transactions.
            if now <= factory.called_group_deadline.read(&key)? {
                slot += 1;
                continue;
            }

            match storage.with_checkpoint(|| expire_group(storage, iso_code, worldwide_day)) {
                // The slot itself was already charged above.
                Ok(members) => budget = budget.saturating_sub(members.saturating_sub(1)),
                Err(error) => {
                    tracing::warn!(
                        target: "outbe::intexfactory",
                        iso_code,
                        worldwide_day = worldwide_day.value(),
                        error = ?error,
                        "expiry sweep: retiring group without credit"
                    );
                    // Dropped whole: leftover records would refuse the pair a later call.
                    let dropped = storage.with_checkpoint(|| {
                        let mut factory = IntexFactoryContract::new(storage.clone());
                        let members =
                            factory
                                .called_group_count
                                .read(&IntexFactoryContract::scoped(
                                    iso_code,
                                    worldwide_day.value(),
                                ))?;
                        factory.remove_called_group(iso_code, worldwide_day)?;
                        Ok(members)
                    });
                    budget = budget.saturating_sub(dropped.unwrap_or(1).saturating_sub(1));
                }
            }
            slot += 1;
        }

        if slot < len {
            factory.expiry_sweep_day.write(day)?;
            factory.expiry_cursor.write(slot)?;
            break;
        }
        factory.expiry_sweep_day.write(0)?;
        factory.expiry_cursor.write(0)?;
        // Anything left broke the invariant above; retiring it keeps the tree moving.
        if factory.expiry_bucket_live.read(&day)? != 0 {
            let dropped = factory.force_retire_bucket(day)?;
            tracing::warn!(
                target: "outbe::intexfactory",
                day,
                dropped,
                "expiry sweep: bucket outlived its day, retiring it"
            );
        }
    }
    Ok(())
}

/// Expire one group in a single credit. Returns the members expired.
fn expire_group(
    storage: &StorageHandle<'_>,
    iso_code: u16,
    worldwide_day: WorldwideDay,
) -> Result<u32> {
    let mut factory = IntexFactoryContract::new(storage.clone());
    let group = factory.called_group(iso_code, worldwide_day)?;

    let mut credit = U256::ZERO;
    for &series_id in &group.members {
        // Per member: a shared checkpoint would roll the whole group's credit back.
        let returned = storage.with_checkpoint(|| {
            let forfeited = outbe_intex::api::expire_series(storage, series_id)?;
            let returned = forfeited
                .promis_load_minor
                .checked_mul(U256::from(forfeited.units))
                .ok_or_else(|| PrecompileError::Revert("forfeited promis load overflow".into()))?;
            emit_event(
                storage,
                crate::precompile::IIntexFactory::SeriesExpired {
                    seriesId: series_id.into(),
                    forfeitedUnits: forfeited.units,
                    returnedPromis: returned,
                },
            )?;
            Ok(returned)
        });
        let returned = match returned {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(target: "outbe::intexfactory", series = %series_id, error = ?error, "expiry sweep: skipping series");
                continue;
            }
        };
        credit = credit
            .checked_add(returned)
            .ok_or_else(|| PrecompileError::Revert("forfeited promis credit overflow".into()))?;
    }

    if !credit.is_zero() {
        outbe_promislimit::PromisLimitContract::new(storage.clone())
            .add_to_total_unallocated(credit)?;
    }
    factory.remove_called_group(iso_code, worldwide_day)?;
    Ok(group.members.len() as u32)
}
