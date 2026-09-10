use alloy_primitives::{keccak256, B256, U256};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    error::Result,
    storage::{MetadosisCycleLifecycle, MetadosisMutationPurpose, StorageHandle},
};
use outbe_tribute::TributeContract;

#[cfg(any(test, feature = "test-utils"))]
use crate::aggregate::WwdProjection;
use crate::{
    aggregate::{ValidatedWwdAggregate, WwdDayType, WwdMembership, WwdStatus},
    precompile::IMetadosis,
    reducer::{
        reduce_outer_wwd, OuterWwdEvent, OuterWwdTransition, OuterWwdTransitionKind, WwdAdvanceEdge,
    },
    schema::{MetadosisContract, WorldwideDayEntryExt},
    state::{DayLimitFormationReceipt, OcompDayLimitFormation},
};

/// Non-forgeable, non-cloneable proof owned by exactly one outer-WWD commit.
/// The constructor is private to this module and the value never crosses into
/// reducer, runtime, OCOMP, commands, or the semantic test facade.
pub(crate) struct CommitPermit<'transition> {
    _transition: &'transition mut (),
}

/// The sole mint for an outer-WWD commit permit. The higher-ranked closure
/// prevents the permit from escaping the one transition that owns it.
fn with_commit_permit<R>(
    effect: impl for<'transition> FnOnce(&CommitPermit<'transition>) -> Result<R>,
) -> Result<R> {
    let mut transition_scope = ();
    let permit = CommitPermit {
        _transition: &mut transition_scope,
    };
    effect(&permit)
}

pub(crate) fn plan_outer_transition(
    storage: StorageHandle<'_>,
    worldwide_day: WorldwideDay,
    event: OuterWwdEvent,
) -> Result<OuterWwdTransition> {
    let aggregate = ValidatedWwdAggregate::load_and_validate(storage)?;
    let current = aggregate.record(worldwide_day).ok_or_else(|| {
        crate::errors::storage_corruption(format!(
            "Metadosis outer transition has no persisted WWD {worldwide_day}"
        ))
    })?;
    reduce_outer_wwd(Some(current), event)
}

#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn plan_outer_transition_for_test_fixture(
    metadosis: &MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    event: OuterWwdEvent,
) -> Result<OuterWwdTransition> {
    let record = metadosis
        .worldwide_days
        .get(worldwide_day)?
        .ok_or_else(|| {
            crate::errors::storage_corruption(format!(
                "Metadosis test fixture has no WWD {worldwide_day}"
            ))
        })?;
    let projection = WwdProjection::from_record(
        worldwide_day,
        WwdStatus::try_from(record.status)?,
        WwdDayType::try_from(record.day_type)?,
        WwdMembership::Active,
        &record,
    );
    reduce_outer_wwd(Some(&projection), event)
}

/// The single production mutation seam. The provider grants an exact
/// purpose-bound lease, its checkpoint covers state and EVM events, and the
/// complete indexed WWD/OCOMP aggregate is validated both before effects and
/// before commit.
pub(crate) fn commit_transition<P, R>(
    storage: StorageHandle<'_>,
    binding: B256,
    effect: impl FnOnce(StorageHandle<'_>) -> Result<R>,
) -> Result<R>
where
    P: MetadosisMutationPurpose,
{
    let command_storage = storage.clone();
    storage.with_metadosis_mutation::<P, R>(binding, || {
        ValidatedWwdAggregate::load_and_validate(command_storage.clone())?;
        let result = effect(command_storage.clone())?;
        ValidatedWwdAggregate::load_and_validate(command_storage)?;
        Ok(result)
    })
}

/// Broad fail-closed terminalization owned by the commit module. This is not a
/// raw status setter: the exhaustive reducer decides whether the persisted WWD
/// may enter (or replay) the emergency terminal state, and the normal command
/// checkpoint owns record, membership, and ordered-event atomicity.
#[cfg_attr(not(any(test, feature = "test-utils")), allow(dead_code))]
pub(crate) fn commit_emergency_fail(
    storage: StorageHandle<'_>,
    worldwide_day: WorldwideDay,
) -> Result<()> {
    let chain_id = storage.chain_id()?;
    let block_number = storage.block_number()?;
    let binding = keccak256(
        [
            b"OUTBE_METADOSIS_EMERGENCY_FAIL_V1".as_slice(),
            &chain_id.to_be_bytes(),
            &block_number.to_be_bytes(),
            &worldwide_day.value().to_be_bytes(),
        ]
        .concat(),
    );
    commit_transition::<MetadosisCycleLifecycle, _>(storage.clone(), binding, |storage| {
        let transition =
            plan_outer_transition(storage.clone(), worldwide_day, OuterWwdEvent::EmergencyFail)?;
        commit_outer_transition(
            &mut MetadosisContract::new(storage),
            worldwide_day,
            &transition,
            block_number,
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NewWwdSchedule {
    pub(crate) forming_start: u64,
    pub(crate) forming_period_seconds: u64,
    pub(crate) lookback_delay_seconds: u64,
    pub(crate) offering_period_seconds: u64,
    pub(crate) waiting_period_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WwdRateResolution {
    pub(crate) previous_vwap: U256,
    pub(crate) current_vwap: U256,
    pub(crate) day_type: WwdDayType,
}

/// Commits the reducer-authorized creation of one new WWD record, membership,
/// Tribute seal, and canonical creation event.
pub(crate) fn commit_new_wwd(
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    schedule: NewWwdSchedule,
    transition: &OuterWwdTransition,
) -> Result<()> {
    commit_outer_transition_owned(
        metadosis,
        worldwide_day,
        transition,
        OuterCommitMode::Create(schedule),
    )
}

fn commit_new_wwd_inner(
    permit: &CommitPermit<'_>,
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    schedule: NewWwdSchedule,
    transition: &OuterWwdTransition,
) -> Result<()> {
    if transition.source().is_some()
        || transition.target() != WwdStatus::Forming
        || transition.membership_after() != WwdMembership::Active
        || transition.kind() != &OuterWwdTransitionKind::Created
    {
        return Err(crate::errors::storage_corruption(
            "Metadosis WWD creation requires the exact reducer Created transition".into(),
        ));
    }
    if metadosis.worldwide_days.get(worldwide_day)?.is_some() {
        return Err(crate::errors::storage_corruption(format!(
            "Metadosis WWD {worldwide_day} already exists at creation commit"
        )));
    }

    metadosis.commit_create_worldwide_day(permit, worldwide_day, schedule)?;
    metadosis.commit_add_active_wwd(permit, worldwide_day)?;
    TributeContract::new(metadosis.storage.clone()).seal_day(worldwide_day)?;

    let record = metadosis
        .worldwide_days
        .get(worldwide_day)?
        .ok_or_else(|| {
            crate::errors::storage_corruption("created WWD record disappeared".into())
        })?;
    metadosis.emit(IMetadosis::WorldwideDayStarted {
        worldwideDay: worldwide_day.into(),
        formingStart: record.forming_start,
        formingEnd: record.forming_end,
        offeringStart: record.lookback_end,
        offeringEnd: record.offering_end,
        scheduledTime: record.scheduled_process_time,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OuterCommitMode {
    Create(NewWwdSchedule),
    Existing {
        block_number: u64,
        rate_resolution: Option<WwdRateResolution>,
    },
}

/// The only production owner of outer WWD status, active/closed membership,
/// cleanup, and canonical status-change events.
pub(crate) fn commit_outer_transition(
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    transition: &OuterWwdTransition,
    block_number: u64,
) -> Result<()> {
    commit_outer_transition_owned(
        metadosis,
        worldwide_day,
        transition,
        OuterCommitMode::Existing {
            block_number,
            rate_resolution: None,
        },
    )
}

pub(crate) fn commit_outer_transition_with_rate(
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    transition: &OuterWwdTransition,
    block_number: u64,
    rate_resolution: Option<WwdRateResolution>,
) -> Result<()> {
    commit_outer_transition_owned(
        metadosis,
        worldwide_day,
        transition,
        OuterCommitMode::Existing {
            block_number,
            rate_resolution,
        },
    )
}

/// Commits one immutable Cycle day-limit formation while proving that the
/// target WWD is a reducer-valid persisted outer aggregate. The permit is born
/// and consumed inside this single no-op outer transition; callers can supply
/// values, but cannot mutate WWD state directly.
pub(crate) fn commit_day_limit_formation(
    metadosis: &mut MetadosisContract<'_>,
    formation: OcompDayLimitFormation,
) -> Result<DayLimitFormationReceipt> {
    let aggregate = ValidatedWwdAggregate::load_and_validate(metadosis.storage.clone())?;
    let current = aggregate.record(formation.worldwide_day).ok_or_else(|| {
        crate::errors::storage_corruption(format!(
            "day-limit formation has no persisted WWD {}",
            formation.worldwide_day
        ))
    })?;
    let transition = reduce_outer_wwd(Some(current), OuterWwdEvent::CreateDay)?;
    if transition.kind() != &OuterWwdTransitionKind::Noop
        || transition.source() != Some(current.status)
        || transition.target() != current.status
        || transition.membership_after() != current.membership
    {
        return Err(crate::errors::storage_corruption(
            "day-limit formation requires an exact reducer no-op outer transition".into(),
        ));
    }

    with_commit_permit(|permit| {
        metadosis.commit_write_day_limit_formation(permit, formation)?;
        metadosis.emit(IMetadosis::MetadosisAccumulation {
            date: formation.worldwide_day.value(),
            dayMetadosisLimitAmount: formation.day_limit,
            totalAccumulated: formation.day_limit,
            blockNumber: formation.block_number,
        })?;
        metadosis.emit(IMetadosis::OcompDayLimitFormed {
            worldwideDay: formation.worldwide_day.value(),
            baseLimit: formation.base_limit,
            carryOverBefore: formation.carry_over_before,
            carryOverTaken: formation.carry_over_taken,
            carryOverAfter: formation.carry_over_after,
            formedDayLimit: formation.day_limit,
            blockNumber: formation.block_number,
        })?;
        // Selector-last: neither an interrupted write nor an event failure may
        // make a partial formation observable as committed.
        metadosis.commit_seal_day_limit_formation(permit, formation.worldwide_day)?;

        metadosis
            .day_limit_formation_receipt(formation.worldwide_day)?
            .ok_or_else(|| {
                crate::errors::storage_corruption(
                    "formed OCOMP day-limit receipt disappeared after commit".into(),
                )
            })
    })
}

fn commit_outer_transition_owned(
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    transition: &OuterWwdTransition,
    mode: OuterCommitMode,
) -> Result<()> {
    with_commit_permit(|permit| {
        commit_outer_transition_inner(permit, metadosis, worldwide_day, transition, mode)
    })
}

fn commit_outer_transition_inner(
    permit: &CommitPermit<'_>,
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    transition: &OuterWwdTransition,
    mode: OuterCommitMode,
) -> Result<()> {
    let block_number = match mode {
        OuterCommitMode::Create(schedule) => {
            return commit_new_wwd_inner(permit, metadosis, worldwide_day, schedule, transition);
        }
        OuterCommitMode::Existing {
            block_number,
            rate_resolution,
        } => {
            let requires_resolution = matches!(
                transition.kind(),
                OuterWwdTransitionKind::Advance(edges)
                    if edges.contains(&WwdAdvanceEdge::ResolveForming)
            );
            if requires_resolution != rate_resolution.is_some() {
                return Err(crate::errors::storage_corruption(
                    "ResolveForming commit requires exactly one typed rate resolution".into(),
                ));
            }
            if let Some(resolution) = rate_resolution {
                metadosis.commit_set_wwd_rate_resolution(
                    permit,
                    worldwide_day,
                    resolution.previous_vwap,
                    resolution.current_vwap,
                    resolution.day_type,
                )?;
            }
            block_number
        }
    };
    let source = transition.source().ok_or_else(|| {
        crate::errors::storage_corruption(
            "persisted WWD transition is missing a source status".into(),
        )
    })?;
    let persisted = metadosis.get_wwd_status(worldwide_day)?;
    if persisted != source {
        return Err(crate::errors::storage_corruption(format!(
            "Metadosis WWD {worldwide_day} reducer expected {source:?}, found {persisted:?}"
        )));
    }
    let expected_membership = if transition.target().is_terminal() {
        WwdMembership::Closed
    } else {
        WwdMembership::Active
    };
    if transition.membership_after() != expected_membership {
        return Err(crate::errors::storage_corruption(
            "outer transition target/membership decision is inconsistent".into(),
        ));
    }

    match transition.kind() {
        OuterWwdTransitionKind::Noop => {
            if transition.target() != source {
                return Err(crate::errors::storage_corruption(
                    "outer Noop transition changes status".into(),
                ));
            }
        }
        OuterWwdTransitionKind::Created => {
            return Err(crate::errors::storage_corruption(
                "Created transition must use commit_new_wwd".into(),
            ));
        }
        OuterWwdTransitionKind::Advance(edges) => {
            let final_status = commit_advance_edges(
                permit,
                metadosis,
                worldwide_day,
                source,
                edges,
                block_number,
            )?;
            if final_status != transition.target() {
                return Err(crate::errors::storage_corruption(
                    "outer advance edges do not reach the reducer target".into(),
                ));
            }
        }
        OuterWwdTransitionKind::MissedOffering => {
            commit_status(
                permit,
                metadosis,
                worldwide_day,
                source,
                WwdStatus::Failed,
                block_number,
                true,
            )?;
            metadosis.commit_retire_terminal_wwd(permit, worldwide_day)?;
        }
        OuterWwdTransitionKind::EmergencyFail => {
            commit_status(
                permit,
                metadosis,
                worldwide_day,
                source,
                WwdStatus::Failed,
                block_number,
                true,
            )?;
            metadosis.commit_retire_terminal_wwd(permit, worldwide_day)?;
        }
        OuterWwdTransitionKind::CapacityForfeiture { preceding_edges } => {
            let status = commit_advance_edges(
                permit,
                metadosis,
                worldwide_day,
                source,
                preceding_edges,
                block_number,
            )?;
            if status != WwdStatus::Waiting {
                return Err(crate::errors::storage_corruption(
                    "CapacityForfeiture commit must terminate from WAITING".into(),
                ));
            }
            commit_status(
                permit,
                metadosis,
                worldwide_day,
                status,
                WwdStatus::Failed,
                block_number,
                true,
            )?;
            metadosis.commit_retire_terminal_wwd(permit, worldwide_day)?;
        }
        OuterWwdTransitionKind::ProcessReady(_)
        | OuterWwdTransitionKind::OcompRequestCommitted
        | OuterWwdTransitionKind::OcompExpired
        | OuterWwdTransitionKind::OcompCompleted => {
            if transition.target() != source {
                commit_status(
                    permit,
                    metadosis,
                    worldwide_day,
                    source,
                    transition.target(),
                    block_number,
                    false,
                )?;
            }
            if transition.target().is_terminal() {
                metadosis.commit_retire_terminal_wwd(permit, worldwide_day)?;
            }
        }
    }
    Ok(())
}

fn commit_advance_edges(
    permit: &CommitPermit<'_>,
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    source: WwdStatus,
    edges: &[WwdAdvanceEdge],
    block_number: u64,
) -> Result<WwdStatus> {
    let mut status = source;
    for edge in edges {
        if edge.source() != status {
            return Err(crate::errors::storage_corruption(format!(
                "Metadosis WWD {worldwide_day} has a non-contiguous reducer edge {edge:?}"
            )));
        }
        commit_status(
            permit,
            metadosis,
            worldwide_day,
            status,
            edge.target(),
            block_number,
            true,
        )?;
        status = edge.target();
    }
    Ok(status)
}

fn commit_status(
    _permit: &CommitPermit<'_>,
    metadosis: &mut MetadosisContract<'_>,
    worldwide_day: WorldwideDay,
    source: WwdStatus,
    target: WwdStatus,
    block_number: u64,
    emit_status_change: bool,
) -> Result<()> {
    let persisted = metadosis.get_wwd_status(worldwide_day)?;
    if persisted != source {
        return Err(crate::errors::storage_corruption(format!(
            "Metadosis WWD {worldwide_day} commit expected {source:?}, found {persisted:?}"
        )));
    }
    metadosis
        .worldwide_days
        .entry(worldwide_day)
        .status()
        .write(target.as_u8())?;
    if emit_status_change {
        metadosis.emit(IMetadosis::WorldwideDayStatusChange {
            worldwideDay: worldwide_day.into(),
            oldStatus: source.as_u8(),
            newStatus: target.as_u8(),
            blockNumber: block_number,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use alloy_primitives::{B256, U256};
    use outbe_ocomp_protocol::profile::CapacityProfileV1;
    use outbe_primitives::storage::{
        hashmap::HashMapStorageProvider, MetadosisCertifiedFinality, MetadosisCycleLifecycle,
        MetadosisMutationPurposeTag,
    };
    use outbe_primitives::time::WorldwideDay;

    use super::*;
    use crate::{
        aggregate::{ValidatedWwdAggregate, WwdDayType, WwdStatus},
        constants::MAX_RECORDS_KEPT,
        fixture_kernel::ActivationFixture,
        ocomp::schema::{poc_schema_limits, OcompRequestProfile, ResponseDeadlineKey},
        schema::{
            day_type, status, MetadosisContract, WorldwideDay as WorldwideDayRecord,
            WorldwideDayEntryExt,
        },
    };

    fn wwd() -> WorldwideDay {
        WorldwideDay::new(20260730)
    }

    fn record(status: u8, day_type: u8) -> WorldwideDayRecord {
        WorldwideDayRecord {
            wwd: wwd(),
            status,
            day_type,
            forming_start: 1,
            forming_end: 2,
            lookback_end: 3,
            offering_end: 4,
            scheduled_process_time: 5,
            metadosis_limit_amount: U256::ZERO,
            previous_vwap: U256::ZERO,
            current_vwap: U256::ZERO,
        }
    }

    fn seed_active(provider: &mut HashMapStorageProvider, record: &WorldwideDayRecord) {
        provider
            .enter(|storage| {
                let contract = MetadosisContract::new(storage);
                contract.worldwide_days.create(record)?;
                contract.active_wwd.insert(record.wwd)?;
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    fn seed_full_terminal_retention(provider: &mut HashMapStorageProvider) -> WorldwideDay {
        let oldest = WorldwideDay::new(2025_0001);
        provider
            .enter(|storage| {
                let contract = MetadosisContract::new(storage);
                for offset in 0..MAX_RECORDS_KEPT {
                    let mut terminal = record(status::FAILED, day_type::GREEN);
                    terminal.wwd = WorldwideDay::new(
                        oldest
                            .value()
                            .checked_add(u32::try_from(offset).expect("retention offset fits u32"))
                            .expect("retention WWD fits u32"),
                    );
                    contract.worldwide_days.create(&terminal)?;
                    contract.closed_wwd.push_back(terminal.wwd)?;
                }
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
        oldest
    }

    fn request_profile() -> OcompRequestProfile {
        OcompRequestProfile {
            chain_id: 1,
            genesis_hash: B256::repeat_byte(0x11),
            fork_id: B256::repeat_byte(0x21),
            protocol_bundle_hash: B256::repeat_byte(0x41),
            correctness_profile_id: B256::repeat_byte(0x24),
            capacity_profile: CapacityProfileV1 {
                profile_id: B256::repeat_byte(0x25),
                max_tributes_per_work_shard: 256,
                max_workers_per_domain: 4,
                max_intents_per_block: 1,
                max_activations_per_block: 1,
                max_ready_inspections_per_block: 1,
                max_expirations_per_block: 1,
                ready_backoff_blocks: 1,
                max_reference_currencies: 256,
                max_oracle_wwd_pair_entries: 256,
                max_active_scurve_entries: 256,
                result_deadline_blocks:
                    outbe_chain_constants::DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
                source_retention_after_terminal_blocks: 64,
                generated_limits_manifest_hash: B256::repeat_byte(0x23),
            },
            source_availability_policy_id: B256::repeat_byte(0x35),
        }
    }

    fn assert_ocomp_state_without_profile_is_rejected(
        inject: impl FnOnce(&mut MetadosisContract<'_>) -> outbe_primitives::error::Result<()>,
    ) {
        let mut provider = HashMapStorageProvider::new(1);
        seed_active(&mut provider, &record(status::READY, day_type::GREEN));
        provider
            .enter(|storage| {
                let mut contract = MetadosisContract::new(storage.clone());
                inject(&mut contract)?;
                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error
                    .to_string()
                    .contains("OCOMP state exists without an active profile"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn reserved_persisted_status_is_rejected_for_green_and_red_before_effects() {
        for day_type in [day_type::GREEN, day_type::RED] {
            let mut provider = HashMapStorageProvider::new(1);
            seed_active(
                &mut provider,
                &record(status::RESERVED_IN_PROGRESS, day_type),
            );
            provider
                .enter(|storage| {
                    assert!(matches!(
                        ValidatedWwdAggregate::load_and_validate(storage),
                        Err(outbe_primitives::error::PrecompileError::Fatal(_))
                    ));
                    Ok::<_, outbe_primitives::error::PrecompileError>(())
                })
                .unwrap();
        }
    }

    #[test]
    fn typed_tags_reject_unrecognized_values() {
        assert!(WwdStatus::try_from(255).is_err());
        assert!(WwdDayType::try_from(255).is_err());
    }

    #[test]
    fn aggregate_rejects_active_closed_overlap() {
        let mut provider = HashMapStorageProvider::new(1);
        let terminal = record(status::COMPLETED, day_type::GREEN);
        provider
            .enter(|storage| {
                let contract = MetadosisContract::new(storage.clone());
                contract.worldwide_days.create(&terminal)?;
                contract.active_wwd.insert(terminal.wwd)?;
                contract.closed_wwd.push_back(terminal.wwd)?;
                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error.to_string().contains("both active and closed"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn aggregate_rejects_missing_record_status_membership_and_phase_drift() {
        let mut missing = HashMapStorageProvider::new(1);
        missing
            .enter(|storage| {
                let contract = MetadosisContract::new(storage.clone());
                contract.active_wwd.insert(wwd())?;
                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error.to_string().contains("missing WWD"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();

        let mut membership = HashMapStorageProvider::new(1);
        seed_active(&mut membership, &record(status::COMPLETED, day_type::GREEN));
        membership.enter(|storage| {
            let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
            assert!(error.to_string().contains("status/membership mismatch"));
        });

        let mut boundaries = HashMapStorageProvider::new(1);
        let mut invalid = record(status::FORMING, day_type::UNKNOWN);
        invalid.forming_end = 0;
        seed_active(&mut boundaries, &invalid);
        boundaries.enter(|storage| {
            let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
            assert!(error.to_string().contains("non-monotonic"));
        });
    }

    #[test]
    fn aggregate_rejects_ocomp_indexes_without_profile() {
        assert_ocomp_state_without_profile_is_rejected(|contract| {
            contract.ocomp_fsm_states.get_bytes(&wwd()).write(&[1])
        });
        assert_ocomp_state_without_profile_is_rejected(|contract| {
            contract.enqueue_ocomp_ready(wwd(), 10)?;
            contract.ocomp_fsm_states.get_bytes(&wwd()).clear()
        });
        assert_ocomp_state_without_profile_is_rejected(|contract| {
            contract.ocomp_scheduler.write(&[1])
        });
        assert_ocomp_state_without_profile_is_rejected(|contract| {
            contract.write_response_deadline_index(&[ResponseDeadlineKey {
                deadline_height: 10,
                job_id: B256::repeat_byte(0x61),
                intent_id: B256::repeat_byte(0x62),
            }])
        });
    }

    #[test]
    fn aggregate_requires_exact_response_deadline_equivalence() {
        let mut missing = ActivationFixture::new_voting(100, 1_700_000_000, true);
        missing
            .provider
            .enter(|storage| {
                ValidatedWwdAggregate::load_and_validate(storage.clone())?;
                let contract = MetadosisContract::new(storage.clone());
                contract.ocomp_response_deadline_index.clear()?;

                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error.to_string().contains("no exact response deadline key"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();

        let mut stale = ActivationFixture::new_voting(100, 1_700_000_000, true);
        stale
            .provider
            .enter(|storage| {
                ValidatedWwdAggregate::load_and_validate(storage.clone())?;
                let contract = MetadosisContract::new(storage.clone());
                let mut index = contract.read_response_deadline_index()?;
                assert_eq!(index.len(), 1);
                index[0].deadline_height = index[0]
                    .deadline_height
                    .checked_add(1)
                    .expect("fixture deadline has headroom");
                contract.write_response_deadline_index(&index)?;

                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error
                    .to_string()
                    .contains("response index/job deadline mismatch"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn aggregate_rejects_ready_index_without_fsm() {
        let mut provider = HashMapStorageProvider::new(1);
        seed_active(&mut provider, &record(status::READY, day_type::GREEN));
        provider
            .enter(|storage| {
                let mut contract = MetadosisContract::new(storage.clone());
                let profile = request_profile();
                let schema_limits = poc_schema_limits();
                contract.initialize_ocomp_request_profile(&profile, &schema_limits)?;
                contract.enqueue_ocomp_ready(wwd(), 10)?;
                contract.ocomp_fsm_states.get_bytes(&wwd()).clear()?;

                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error
                    .to_string()
                    .contains("READY index points to a missing FSM"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn aggregate_rejects_closed_wwd_with_live_fsm() {
        let mut provider = HashMapStorageProvider::new(1);
        seed_active(&mut provider, &record(status::READY, day_type::GREEN));
        provider
            .enter(|storage| {
                let mut contract = MetadosisContract::new(storage.clone());
                contract.enqueue_ocomp_ready(wwd(), 10)?;
                contract
                    .worldwide_days
                    .entry(wwd())
                    .status()
                    .write(status::COMPLETED)?;
                contract.active_wwd.remove(&wwd())?;
                contract.closed_wwd.push_back(wwd())?;

                let error = ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
                assert!(error.to_string().contains("retains a live OCOMP FSM"));
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn invalid_pre_state_rejects_before_effect() {
        let mut provider = HashMapStorageProvider::new(1);
        seed_active(&mut provider, &record(255, day_type::UNKNOWN));
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        let effect_called = Cell::new(false);

        let error = provider
            .enter(|storage| {
                commit_transition::<MetadosisCycleLifecycle, _>(
                    storage,
                    B256::repeat_byte(0x51),
                    |_| {
                        effect_called.set(true);
                        Ok(())
                    },
                )
            })
            .unwrap_err();

        assert!(error.to_string().contains("unknown status tag"));
        assert!(!effect_called.get());
    }

    #[test]
    fn invalid_post_state_reverts_effect() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);

        let error = provider
            .enter(|storage| {
                commit_transition::<MetadosisCycleLifecycle, _>(
                    storage,
                    B256::repeat_byte(0x52),
                    |storage| {
                        let contract = MetadosisContract::new(storage);
                        let invalid = record(255, day_type::UNKNOWN);
                        contract.worldwide_days.create(&invalid)?;
                        contract.active_wwd.insert(invalid.wwd)?;
                        Ok(())
                    },
                )
            })
            .unwrap_err();
        assert!(error.to_string().contains("unknown status tag"));

        provider
            .enter(|storage| {
                let contract = MetadosisContract::new(storage);
                assert!(contract.worldwide_days.get(wwd())?.is_none());
                assert!(contract.active_wwd.read_all()?.is_empty());
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn wrong_purpose_rejects_before_aggregate_or_effect() {
        let mut provider = HashMapStorageProvider::new(1);
        seed_active(&mut provider, &record(255, day_type::UNKNOWN));
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CertifiedFinality);
        let effect_called = Cell::new(false);

        let error = provider
            .enter(|storage| {
                commit_transition::<MetadosisCycleLifecycle, _>(
                    storage,
                    B256::repeat_byte(0x53),
                    |_| {
                        effect_called.set(true);
                        Ok(())
                    },
                )
            })
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("no matching Metadosis mutation lease"));
        assert!(!effect_called.get());
    }

    #[test]
    fn nested_mutation_rejects_before_nested_aggregate_or_effect() {
        let mut provider = HashMapStorageProvider::new(1);
        seed_active(&mut provider, &record(255, day_type::UNKNOWN));
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CertifiedFinality);
        let nested_effect_called = Cell::new(false);

        provider
            .enter(|storage| {
                let nested_storage = storage.clone();
                storage.with_metadosis_mutation::<MetadosisCertifiedFinality, _>(
                    B256::repeat_byte(0x54),
                    || {
                        let error = commit_transition::<MetadosisCertifiedFinality, _>(
                            nested_storage,
                            B256::repeat_byte(0x55),
                            |_| {
                                nested_effect_called.set(true);
                                Ok(())
                            },
                        )
                        .unwrap_err();
                        assert!(error
                            .to_string()
                            .contains("no matching Metadosis mutation lease"));
                        Ok(())
                    },
                )
            })
            .unwrap();

        assert!(!nested_effect_called.get());
    }

    #[test]
    fn commit_owned_emergency_fail_is_atomic_and_idempotent() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.set_block_number(17);
        seed_active(&mut provider, &record(status::FORMING, day_type::UNKNOWN));
        provider.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 2);

        provider
            .enter(|storage| commit_emergency_fail(storage, wwd()))
            .unwrap();
        let events_after_first = provider.events.clone();
        let ordered_after_first = provider.get_ordered_events().to_vec();
        provider
            .enter(|storage| commit_emergency_fail(storage, wwd()))
            .unwrap();
        assert_eq!(provider.events, events_after_first);
        assert_eq!(
            provider.get_ordered_events(),
            ordered_after_first.as_slice()
        );
        assert_eq!(ordered_after_first.len(), 1);

        provider
            .enter(|storage| {
                let contract = MetadosisContract::new(storage);
                assert_eq!(contract.get_wwd_status(wwd())?, WwdStatus::Failed);
                assert!(contract.active_wwd.read_all()?.is_empty());
                assert_eq!(contract.closed_wwd.read_all()?, vec![wwd()]);
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();
    }

    #[test]
    fn emergency_fail_rolls_back_every_mutation_and_retries_once() {
        let mut probe = HashMapStorageProvider::new(1);
        probe.set_block_number(17);
        seed_active(&mut probe, &record(status::FORMING, day_type::UNKNOWN));
        probe.fail_after_mutation_at(usize::MAX);
        probe.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        probe
            .enter(|storage| commit_emergency_fail(storage, wwd()))
            .unwrap();
        let mutation_count = probe.clear_mutation_failure();
        assert!(mutation_count >= 4);
        let clean_storage = probe.storage.clone();
        let clean_events = probe.events.clone();
        let clean_ordered = probe.get_ordered_events().to_vec();

        for operation in 0..mutation_count {
            let mut provider = HashMapStorageProvider::new(1);
            provider.set_block_number(17);
            seed_active(&mut provider, &record(status::FORMING, day_type::UNKNOWN));
            let storage_before = provider.storage.clone();
            let events_before = provider.events.clone();
            let ordered_before = provider.get_ordered_events().to_vec();
            provider.fail_after_mutation_at(operation);
            provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);

            assert!(provider
                .enter(|storage| commit_emergency_fail(storage, wwd()))
                .is_err());
            assert_eq!(provider.clear_mutation_failure(), operation + 1);
            assert_eq!(provider.storage, storage_before, "storage at {operation}");
            assert_eq!(provider.events, events_before, "events at {operation}");
            assert_eq!(
                provider.get_ordered_events(),
                ordered_before.as_slice(),
                "ordered events at {operation}"
            );

            provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
            provider
                .enter(|storage| commit_emergency_fail(storage, wwd()))
                .unwrap();
            assert_eq!(
                provider.storage, clean_storage,
                "retry storage at {operation}"
            );
            assert_eq!(provider.events, clean_events, "retry events at {operation}");
            assert_eq!(
                provider.get_ordered_events(),
                clean_ordered.as_slice(),
                "retry ordered events at {operation}"
            );
            provider
                .enter(|storage| {
                    let contract = MetadosisContract::new(storage);
                    assert_eq!(contract.get_wwd_status(wwd())?, WwdStatus::Failed);
                    assert!(contract.active_wwd.read_all()?.is_empty());
                    assert_eq!(contract.closed_wwd.read_all()?, vec![wwd()]);
                    Ok::<_, outbe_primitives::error::PrecompileError>(())
                })
                .unwrap();
        }
    }

    #[test]
    fn emergency_fail_retention_eviction_rolls_back_every_mutation_and_retries_exactly() {
        let prepare = |provider: &mut HashMapStorageProvider| {
            provider.set_block_number(17);
            let oldest = seed_full_terminal_retention(provider);
            seed_active(provider, &record(status::FORMING, day_type::UNKNOWN));
            oldest
        };

        let mut control = HashMapStorageProvider::new(1);
        let oldest = prepare(&mut control);
        control.fail_after_mutation_at(usize::MAX);
        control.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        control
            .enter(|storage| commit_emergency_fail(storage, wwd()))
            .unwrap();
        let mutation_count = control.clear_mutation_failure();
        assert!(
            mutation_count >= 6,
            "retention eviction must add terminal state and delete the oldest record"
        );
        let clean_storage = control.storage.clone();
        let clean_events = control.events.clone();
        let clean_ordered = control.get_ordered_events().to_vec();
        control
            .enter(|storage| {
                assert!(!MetadosisContract::new(storage)
                    .worldwide_days
                    .exists(oldest)?);
                Ok::<_, outbe_primitives::error::PrecompileError>(())
            })
            .unwrap();

        for operation in 0..mutation_count {
            let mut provider = HashMapStorageProvider::new(1);
            let oldest = prepare(&mut provider);
            let storage_before = provider.storage.clone();
            let events_before = provider.events.clone();
            let ordered_before = provider.get_ordered_events().to_vec();
            provider.fail_after_mutation_at(operation);
            provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);

            assert!(provider
                .enter(|storage| commit_emergency_fail(storage, wwd()))
                .is_err());
            assert_eq!(provider.clear_mutation_failure(), operation + 1);
            assert_eq!(provider.storage, storage_before, "storage at {operation}");
            assert_eq!(provider.events, events_before, "events at {operation}");
            assert_eq!(provider.get_ordered_events(), ordered_before.as_slice());

            provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
            provider
                .enter(|storage| commit_emergency_fail(storage, wwd()))
                .unwrap();
            assert_eq!(
                provider.storage, clean_storage,
                "retry storage at {operation}"
            );
            assert_eq!(provider.events, clean_events, "retry events at {operation}");
            assert_eq!(provider.get_ordered_events(), clean_ordered.as_slice());
            provider
                .enter(|storage| {
                    assert!(!MetadosisContract::new(storage)
                        .worldwide_days
                        .exists(oldest)?);
                    Ok::<_, outbe_primitives::error::PrecompileError>(())
                })
                .unwrap();
        }
    }
}
