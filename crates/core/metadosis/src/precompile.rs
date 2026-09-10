use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};
use outbe_primitives::dispatch::{dispatch_call, metadata, view};
use outbe_primitives::error::Result;

use crate::{
    aggregate::{WwdDayType, WwdStatus},
    schema::{terminal_outcome, terminal_retirement, MetadosisContract, WorldwideDayEntryExt},
};

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IMetadosis.sol"
);

/// Dispatches an ABI-encoded call to the Metadosis precompile (view-only).
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(data, IMetadosis::IMetadosisCalls::abi_decode, |call| {
        let metadosis = MetadosisContract::new(storage);
        use IMetadosis::IMetadosisCalls::*;
        match call {
            getWorldwideDay(c) => view(c, |c| {
                let Some(day) = metadosis.worldwide_days.get(c.wwd.into())? else {
                    return Err(outbe_primitives::storage::dsl::missing_record_err(
                        "WorldwideDay",
                    ));
                };
                // Persisted bytes are validated as closed tags before they are
                // returned through the raw ABI representation.
                WwdStatus::try_from(day.status)?;
                WwdDayType::try_from(day.day_type)?;
                Ok((
                    day.status,
                    day.day_type,
                    day.forming_start,
                    day.forming_end,
                    day.lookback_end,
                    day.offering_end,
                    day.scheduled_process_time,
                    day.previous_vwap,
                    day.current_vwap,
                )
                    .into())
            }),
            getActiveWorldwideDays(_) => metadata::<IMetadosis::getActiveWorldwideDaysCall>(|| {
                let wwds = metadosis.active_wwd.read_all()?;
                Ok(wwds.into_iter().map(u32::from).collect())
            }),
            getWorldwideDaysByStatus(c) => view(c, |c| {
                let wanted = WwdStatus::try_from(c.status)
                    .map_err(|_| crate::errors::caller_rejection("unknown WorldwideDay status"))?;
                let wwds = metadosis.get_active_wwd_by_status(wanted)?;
                Ok(wwds.into_iter().map(u32::from).collect())
            }),
            getBootstrapEndTime(_) => metadata::<IMetadosis::getBootstrapEndTimeCall>(|| {
                metadosis.get_bootstrap_end_time()
            }),
            getWorldwideDayTerminalReceipt(c) => view(c, |c| {
                let wwd = c.wwd.into();
                let Some(stored) = metadosis.worldwide_day_terminal_receipts.get(wwd)? else {
                    return Ok((
                        terminal_outcome::NONE,
                        U256::ZERO,
                        U256::ZERO,
                        U256::ZERO,
                        terminal_retirement::NONE,
                        0_u64,
                    )
                        .into());
                };
                match stored.outcome {
                    terminal_outcome::MISSED_OFFERING => {
                        metadosis.read_missed_offering_receipt(wwd)?;
                    }
                    terminal_outcome::CAPACITY_FORFEITURE => {
                        metadosis.read_capacity_forfeiture_receipt(wwd)?;
                    }
                    terminal_outcome::METADOSIS_FAILURE => {
                        let expected_value_routed = metadosis
                            .request_budget_receipt(
                                wwd,
                                &crate::ocomp::schema::poc_schema_limits(),
                            )?
                            .map_or(
                                metadosis
                                    .worldwide_days
                                    .entry(wwd)
                                    .metadosis_limit_amount()
                                    .read()?,
                                |receipt| receipt.lysis_budget,
                            );
                        metadosis.read_metadosis_failure_receipt(wwd, expected_value_routed)?;
                    }
                    _ => {
                        return Err(crate::errors::storage_corruption(
                            "Metadosis WWD has an unknown terminal receipt outcome".into(),
                        ));
                    }
                }
                Ok((
                    stored.outcome,
                    stored.value_routed,
                    stored.carry_over_before,
                    stored.carry_over_after,
                    stored.retirement,
                    stored.block_number,
                )
                    .into())
            }),
            getCapacityForfeitureReceipt(c) => view(c, |c| {
                let Some(receipt) = metadosis.read_capacity_forfeiture_receipt(c.wwd.into())?
                else {
                    return Ok((
                        terminal_outcome::NONE,
                        0_u32,
                        0_u32,
                        U256::ZERO,
                        U256::ZERO,
                        U256::ZERO,
                        alloy_primitives::B256::ZERO,
                        0_u32,
                        U256::ZERO,
                        0_u64,
                        0_u64,
                        terminal_retirement::NONE,
                        0_u64,
                    )
                        .into());
                };
                let retirement = match receipt.retirement {
                    outbe_compressed_entities::RetirementOutcome::NotPresent => {
                        terminal_retirement::NOT_PRESENT
                    }
                    outbe_compressed_entities::RetirementOutcome::Requested => {
                        terminal_retirement::REQUESTED
                    }
                };
                Ok((
                    terminal_outcome::CAPACITY_FORFEITURE,
                    receipt.max_retained_wwds,
                    receipt.retained_count_before,
                    receipt.value_routed,
                    receipt.carry_over_before,
                    receipt.carry_over_after,
                    receipt.sealed_collection_root,
                    receipt.forfeited_count,
                    receipt.forfeited_nominal,
                    receipt.source_generation,
                    receipt.retired_generation,
                    retirement,
                    receipt.block_number,
                )
                    .into())
            }),
            getOffchainJob(c) => view(c, |c| {
                crate::ocomp::views::get_offchain_job(metadosis.storage.clone(), c.intentId)
                    .map(Bytes::from)
            }),
            getOffchainVoteAccountability(c) => view(c, |c| {
                crate::ocomp::views::get_offchain_vote_accountability(
                    metadosis.storage.clone(),
                    c.jobId,
                )
                .map(Bytes::from)
            }),
            getActiveLysisGeneration(c) => view(c, |c| {
                crate::ocomp::views::get_active_lysis_generation(
                    metadosis.storage.clone(),
                    c.wwd.into(),
                )
                .map(Bytes::from)
            }),
            getLysisTerminalReceipt(c) => view(c, |c| {
                crate::ocomp::views::get_lysis_terminal_receipt(
                    metadosis.storage.clone(),
                    c.intentId,
                )
                .map(Bytes::from)
            }),
            // Reachable from arbitrary calldata whenever the OCOMP lifecycle is
            // inactive: the EVM dispatcher routes this selector to
            // `commands::submit_verified_result_vote` only while
            // `ocomp_lifecycle_active` is true, so with the lifecycle active this
            // arm is structurally unreachable. Caller-supplied ingress must
            // revert, never `Fatal` - a `Fatal` here aborts the whole payload
            // build for a transaction any external account can submit.
            submitLysisResult(_) => Err(crate::errors::result_vote_rejection(
                crate::errors::vote_rejection_code::LIFECYCLE_INACTIVE,
            )),
        }
    })
}
