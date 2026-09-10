use super::*;
use crate::{WwdDayType, WwdStatus};

use alloy_sol_types::{SolCall, SolEvent};
use outbe_compressed_entities::{
    AuthenticatedParentTree, CeWorkConfig, Commitment, FinalLeafMutation, PartitionRef,
    ProvisionalTreeBatch, RetirementOutcome,
};
use outbe_primitives::error::{PrecompileError, Result};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug)]
struct FixedPartitionTree {
    parent_root: B256,
    partition_root: B256,
    leaf_reads: AtomicUsize,
}

impl AuthenticatedParentTree for FixedPartitionTree {
    fn parent_block_hash(&self) -> B256 {
        B256::ZERO
    }

    fn parent_root(&self) -> B256 {
        self.parent_root
    }

    fn read_leaf_verified(
        &self,
        _entity: EntityRef,
        expected_parent_root: B256,
    ) -> Result<Option<Commitment>> {
        if expected_parent_root != self.parent_root {
            return Err(PrecompileError::Fatal(
                "fixed partition parent-root mismatch".into(),
            ));
        }
        self.leaf_reads.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn partition_present_verified(
        &self,
        partition: PartitionRef,
        expected_parent_root: B256,
    ) -> Result<bool> {
        Ok(self
            .partition_root_verified(partition, expected_parent_root)?
            .is_some())
    }

    fn partition_root_verified(
        &self,
        partition: PartitionRef,
        expected_parent_root: B256,
    ) -> Result<Option<B256>> {
        if expected_parent_root != self.parent_root
            || !matches!(partition, PartitionRef::TributeWwd(_))
        {
            return Err(PrecompileError::Fatal(
                "fixed partition authentication mismatch".into(),
            ));
        }
        Ok(Some(self.partition_root))
    }

    fn prepare_seal(
        &self,
        _block_number: u64,
        _mutations: &[FinalLeafMutation],
        _retirements: &[PartitionRef],
    ) -> Result<ProvisionalTreeBatch> {
        Err(PrecompileError::Fatal(
            "capacity test does not close its synthetic parent tree".into(),
        ))
    }
}

fn seed_day(
    storage: &StorageHandle<'_>,
    wwd: outbe_primitives::time::WorldwideDay,
    state: u8,
    day_limit: U256,
) -> u64 {
    let mut metadosis = MetadosisContract::new(storage.clone());
    metadosis
        .create_worldwide_day(
            wwd,
            wwd.start_timestamp(),
            LOOKBACK_DELAY_HOURS,
            OFFERING_PERIOD_HOURS,
        )
        .unwrap();
    metadosis.add_active_wwd(wwd).unwrap();
    metadosis
        .fixture_set_wwd_status(wwd, WwdStatus::try_from(state).unwrap())
        .unwrap();
    metadosis.set_wwd_day_type(wwd, WwdDayType::Green).unwrap();
    metadosis.set_metadosis_limit(wwd, day_limit).unwrap();
    if state == status::WAITING || state == status::OFFERING {
        metadosis.fixture_seed_day_limit_formation(wwd).unwrap();
    }
    metadosis
        .worldwide_days
        .entry(wwd)
        .scheduled_process_time()
        .read()
        .unwrap()
}

fn seed_empty_waiting_candidate(
    storage: &StorageHandle<'_>,
    tribute: &mut TributeContract<'_>,
    wwd: outbe_primitives::time::WorldwideDay,
    scheduled_process_time: u64,
) {
    seed_day(storage, wwd, status::WAITING, U256::from(10));
    MetadosisContract::new(storage.clone())
        .fixture_set_scheduled_process_time(wwd, scheduled_process_time)
        .unwrap();
    tribute
        .day_totals
        .create(&outbe_tribute::DayTotals {
            worldwide_day: wwd,
            initialized: true,
            tribute_count: 0,
            tribute_nominal_amount: U256::ZERO,
            is_sealed: true,
        })
        .unwrap();
}

fn wwd_words(
    metadosis: &MetadosisContract<'_>,
    wwd: outbe_primitives::time::WorldwideDay,
) -> Vec<U256> {
    let record = metadosis.worldwide_days.get(wwd).unwrap().unwrap();
    vec![
        U256::from(record.status),
        U256::from(record.day_type),
        U256::from(record.forming_start),
        U256::from(record.forming_end),
        U256::from(record.lookback_end),
        U256::from(record.offering_end),
        U256::from(record.scheduled_process_time),
        record.metadosis_limit_amount,
        record.previous_vwap,
        record.current_vwap,
    ]
}

fn seed_capacity_fixture(
    provider: &mut HashMapStorageProvider,
    retained_count: usize,
    tribute_count: u32,
    tribute_nominal: U256,
    initial_carry: U256,
) -> (outbe_primitives::time::WorldwideDay, u64) {
    seed_capacity_fixture_with_victim_state(
        provider,
        retained_count,
        tribute_count,
        tribute_nominal,
        initial_carry,
        status::WAITING,
    )
}

fn seed_capacity_fixture_with_victim_state(
    provider: &mut HashMapStorageProvider,
    retained_count: usize,
    tribute_count: u32,
    tribute_nominal: U256,
    initial_carry: U256,
    victim_state: u8,
) -> (outbe_primitives::time::WorldwideDay, u64) {
    StorageHandle::enter(provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let mut tribute = TributeContract::new(storage.clone());
        tribute.initialize_fresh_ocomp_profile().unwrap();
        for offset in 0..retained_count {
            seed_day(
                &storage,
                outbe_primitives::time::WorldwideDay::new(2026_0101 + offset as u32),
                status::READY,
                U256::from(1),
            );
        }
        let victim = outbe_primitives::time::WorldwideDay::new(2099_1231);
        let scheduled = seed_day(&storage, victim, victim_state, U256::from(100));
        tribute
            .day_totals
            .create(&outbe_tribute::DayTotals {
                worldwide_day: victim,
                initialized: true,
                tribute_count,
                tribute_nominal_amount: tribute_nominal,
                is_sealed: victim_state != status::OFFERING,
            })
            .unwrap();
        tribute
            .total_supply
            .write(u64::from(tribute_count))
            .unwrap();
        PromisLimitContract::new(storage)
            .checked_add_carry_over(initial_carry)
            .unwrap();
        (victim, scheduled)
    })
}

fn begin_empty_scope(provider: &mut HashMapStorageProvider) -> ExecutionScope {
    let scope = ExecutionScope::new();
    let parent_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
    StorageHandle::enter(provider, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    scope
}

fn begin_fixed_partition_scope(
    provider: &mut HashMapStorageProvider,
) -> (ExecutionScope, Arc<FixedPartitionTree>) {
    let parent_root = outbe_compressed_entities::sealed_root(B256::repeat_byte(0x71)).unwrap();
    let tree = Arc::new(FixedPartitionTree {
        parent_root,
        partition_root: B256::repeat_byte(0x72),
        leaf_reads: AtomicUsize::new(0),
    });
    let scope = ExecutionScope::with_parent_tree(tree.clone(), CeWorkConfig::new(0, 0, u64::MAX));
    StorageHandle::enter(provider, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    (scope, tree)
}

fn run_advance(
    provider: &mut HashMapStorageProvider,
    scope: &ExecutionScope,
    block_number: u64,
    timestamp: u64,
) -> Result<()> {
    provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    StorageHandle::enter(provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
            storage,
        );
        crate::commands::advance_active_worldwide_days(&ctx, scope)
    })
}

#[test]
fn derived_caps_are_bound_to_production_phase_and_tick_cadence() {
    assert_eq!(MAX_PIPELINE_WWDS, 27);
    assert_eq!(MAX_RETAINED_WWDS, MAX_RECORDS_KEPT);
    assert_eq!(MAX_ACTIVE_WWDS, MAX_PIPELINE_WWDS + MAX_RECORDS_KEPT);
    assert_eq!(MAX_ADMISSION_WAIT_TICKS, 27);
    assert_eq!(MAX_ADMISSION_WAIT_HOURS, 27);
    const {
        assert!(WWD_ADVANCE_TICK_CADENCE_HOURS < WWD_CREATION_CADENCE_HOURS);
    }
}

#[test]
fn validated_snapshot_rejects_a_pending_fsm_missing_from_the_live_scheduler() {
    let mut fixture = crate::fixture_kernel::ActivationFixture::new_voting(30, 3_000, false);
    StorageHandle::enter(&mut fixture.provider, |storage| {
        crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage.clone()).unwrap();
        MetadosisContract::new(storage.clone())
            .ocomp_scheduler
            .clear()
            .unwrap();
        let error =
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage).unwrap_err();
        assert!(matches!(error, PrecompileError::Fatal(_)));
        assert!(error
            .to_string()
            .contains("pending FSM membership does not exactly match"));
    });
}

#[test]
fn validated_snapshot_orders_ready_days_by_scheduled_time_then_wwd() {
    let expected = [
        outbe_primitives::time::WorldwideDay::new(2026_0201),
        outbe_primitives::time::WorldwideDay::new(2026_0202),
    ];
    for insertion in [[expected[0], expected[1]], [expected[1], expected[0]]] {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut provider, |storage| {
            arm_genesis_ocomp(&storage, CHAIN_ID);
            for wwd in insertion {
                seed_day(&storage, wwd, status::READY, U256::from(1));
            }
            let aggregate =
                crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage.clone())
                    .unwrap();
            assert_eq!(
                aggregate
                    .ready_records()
                    .map(|record| record.worldwide_day)
                    .collect::<Vec<_>>(),
                expected
            );

            let mut metadosis = MetadosisContract::new(storage.clone());
            metadosis.remove_active_wwd(expected[1]).unwrap();
            metadosis.add_active_wwd(expected[1]).unwrap();
            let requeued =
                crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage).unwrap();
            assert_eq!(
                requeued
                    .ready_records()
                    .map(|record| record.worldwide_day)
                    .collect::<Vec<_>>(),
                expected
            );
        });
    }
}

#[test]
fn active_protocol_order_matches_btreeset_across_insert_remove_and_requeue_histories() {
    use std::collections::BTreeSet;

    let wwds = [
        outbe_primitives::time::WorldwideDay::new(2026_0301),
        outbe_primitives::time::WorldwideDay::new(2026_0302),
        outbe_primitives::time::WorldwideDay::new(2026_0303),
        outbe_primitives::time::WorldwideDay::new(2026_0304),
    ];
    let scheduled = [
        2_000_000_300_u64,
        2_000_000_100,
        2_000_000_200,
        2_000_000_200,
    ];
    for insertion in [[0_usize, 1, 2, 3], [3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]] {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut provider, |storage| {
            arm_genesis_ocomp(&storage, CHAIN_ID);
            let mut model = BTreeSet::new();
            for index in insertion {
                seed_day(&storage, wwds[index], status::WAITING, U256::from(1));
                MetadosisContract::new(storage.clone())
                    .fixture_set_scheduled_process_time(wwds[index], scheduled[index])
                    .unwrap();
                model.insert((scheduled[index], wwds[index]));
            }

            let actual =
                crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage.clone())
                    .unwrap()
                    .active_records()
                    .map(|record| (record.scheduled_process_time, record.worldwide_day))
                    .collect::<Vec<_>>();
            assert_eq!(actual, model.iter().copied().collect::<Vec<_>>());

            let mut metadosis = MetadosisContract::new(storage.clone());
            metadosis.remove_active_wwd(wwds[2]).unwrap();
            metadosis.add_active_wwd(wwds[2]).unwrap();
            let requeued = crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage)
                .unwrap()
                .active_records()
                .map(|record| (record.scheduled_process_time, record.worldwide_day))
                .collect::<Vec<_>>();
            assert_eq!(requeued, model.iter().copied().collect::<Vec<_>>());
        });
    }
}

#[test]
fn retained_cap_minus_one_admits_cap_forfeits_and_cap_plus_one_is_corruption() {
    let mut below = HashMapStorageProvider::new(CHAIN_ID);
    let (victim, scheduled) =
        seed_capacity_fixture(&mut below, MAX_RETAINED_WWDS - 1, 0, U256::ZERO, U256::ZERO);
    let scope = begin_empty_scope(&mut below);
    run_advance(&mut below, &scope, 2, scheduled).unwrap();
    StorageHandle::enter(&mut below, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_status(victim).unwrap(), status::READY);
        assert!(metadosis
            .read_capacity_forfeiture_receipt(victim)
            .unwrap()
            .is_none());
    });

    let mut at = HashMapStorageProvider::new(CHAIN_ID);
    let (victim, scheduled) =
        seed_capacity_fixture(&mut at, MAX_RETAINED_WWDS, 0, U256::ZERO, U256::from(7));
    let scope = begin_empty_scope(&mut at);
    run_advance(&mut at, &scope, 2, scheduled).unwrap();
    StorageHandle::enter(&mut at, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_status(victim).unwrap(), status::FAILED);
        assert_eq!(
            metadosis
                .read_capacity_forfeiture_receipt(victim)
                .unwrap()
                .unwrap()
                .retained_count_before,
            MAX_RETAINED_WWDS as u32
        );
    });

    let mut above = HashMapStorageProvider::new(CHAIN_ID);
    let (victim, scheduled) = seed_capacity_fixture(
        &mut above,
        MAX_RETAINED_WWDS + 1,
        0,
        U256::ZERO,
        U256::from(7),
    );
    let scope = begin_empty_scope(&mut above);
    let before_storage = above.storage.clone();
    let before_events = above.events.clone();
    let error = run_advance(&mut above, &scope, 2, scheduled).unwrap_err();
    assert!(matches!(error, PrecompileError::Fatal(_)));
    assert_eq!(above.storage, before_storage);
    assert_eq!(above.events, before_events);
    StorageHandle::enter(&mut above, |storage| {
        assert_eq!(
            MetadosisContract::new(storage)
                .get_wwd_status(victim)
                .unwrap(),
            status::WAITING
        );
    });
}

#[test]
fn multiple_due_candidates_advance_exactly_one_per_tick_in_protocol_order() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let candidates = [
        outbe_primitives::time::WorldwideDay::new(2026_0401),
        outbe_primitives::time::WorldwideDay::new(2026_0402),
        outbe_primitives::time::WorldwideDay::new(2026_0403),
    ];
    let timestamp = StorageHandle::enter(&mut provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let mut tribute = TributeContract::new(storage.clone());
        tribute.initialize_fresh_ocomp_profile().unwrap();
        let mut latest = 0;
        for candidate in candidates {
            latest = latest.max(seed_day(
                &storage,
                candidate,
                status::WAITING,
                U256::from(10),
            ));
            tribute
                .day_totals
                .create(&outbe_tribute::DayTotals {
                    worldwide_day: candidate,
                    initialized: true,
                    tribute_count: 0,
                    tribute_nominal_amount: U256::ZERO,
                    is_sealed: true,
                })
                .unwrap();
        }
        latest
    });
    let scope = begin_empty_scope(&mut provider);

    run_advance(&mut provider, &scope, 10, timestamp).unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert_eq!(
            candidates.map(|wwd| metadosis.get_wwd_status(wwd).unwrap()),
            [status::READY, status::WAITING, status::WAITING]
        );
    });

    run_advance(&mut provider, &scope, 11, timestamp + 1).unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert_eq!(
            candidates.map(|wwd| metadosis.get_wwd_status(wwd).unwrap()),
            [status::READY, status::READY, status::WAITING]
        );
    });

    run_advance(&mut provider, &scope, 12, timestamp + 2).unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert_eq!(
            candidates.map(|wwd| metadosis.get_wwd_status(wwd).unwrap()),
            [status::READY, status::READY, status::READY]
        );
        assert!(metadosis
            .read_capacity_forfeiture_receipt(candidates[2])
            .unwrap()
            .is_none());
    });
}

#[test]
fn continuous_creation_cadence_keeps_due_candidates_within_the_derived_wait_bound() {
    use std::collections::BTreeMap;

    const EXTRA_ARRIVALS: usize = 8;
    const BASE_DAY_TIMESTAMP: u64 = 1_900_000_000;
    const DUE_AT: u64 = 2_000_000_000;

    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let mut candidates = Vec::with_capacity(MAX_PIPELINE_WWDS + EXTRA_ARRIVALS);
    StorageHandle::enter(&mut provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let mut tribute = TributeContract::new(storage.clone());
        tribute.initialize_fresh_ocomp_profile().unwrap();
        for sequence in 0..MAX_PIPELINE_WWDS {
            let wwd = outbe_primitives::time::WorldwideDay::from_timestamp(
                BASE_DAY_TIMESTAMP
                    + u64::try_from(sequence).unwrap()
                        * WWD_CREATION_CADENCE_HOURS
                        * SECONDS_PER_HOUR,
            );
            seed_empty_waiting_candidate(&storage, &mut tribute, wwd, DUE_AT);
            candidates.push((wwd, 0_usize));
        }
    });
    let scope = begin_empty_scope(&mut provider);
    let total_candidates = MAX_PIPELINE_WWDS + EXTRA_ARRIVALS;
    let mut terminal_or_admitted_at = BTreeMap::new();
    let mut next_sequence = MAX_PIPELINE_WWDS;

    for tick in 1..=total_candidates {
        run_advance(
            &mut provider,
            &scope,
            u64::try_from(100 + tick).unwrap(),
            DUE_AT + u64::try_from(tick).unwrap(),
        )
        .unwrap();

        StorageHandle::enter(&mut provider, |storage| {
            let metadosis = MetadosisContract::new(storage);
            let newly_processed = candidates
                .iter()
                .filter(|(wwd, _)| !terminal_or_admitted_at.contains_key(wwd))
                .filter(|(wwd, _)| metadosis.get_wwd_status(*wwd).unwrap() != status::WAITING)
                .map(|(wwd, _)| *wwd)
                .collect::<Vec<_>>();
            assert_eq!(
                newly_processed.len(),
                1,
                "exactly one due admission candidate must leave WAITING at tick {tick}"
            );
            terminal_or_admitted_at.insert(newly_processed[0], tick);
        });

        if tick % 2 == 0 && next_sequence < total_candidates {
            let wwd = outbe_primitives::time::WorldwideDay::from_timestamp(
                BASE_DAY_TIMESTAMP
                    + u64::try_from(next_sequence).unwrap()
                        * WWD_CREATION_CADENCE_HOURS
                        * SECONDS_PER_HOUR,
            );
            StorageHandle::enter(&mut provider, |storage| {
                let mut tribute = TributeContract::new(storage.clone());
                seed_empty_waiting_candidate(
                    &storage,
                    &mut tribute,
                    wwd,
                    DUE_AT + u64::try_from(tick).unwrap(),
                );
            });
            candidates.push((wwd, tick));
            next_sequence += 1;
        }
    }

    assert_eq!(terminal_or_admitted_at.len(), total_candidates);
    for (wwd, inserted_at) in candidates {
        let processed_at = terminal_or_admitted_at[&wwd];
        assert!(
            processed_at - inserted_at <= MAX_ADMISSION_WAIT_TICKS,
            "{wwd} waited {} ticks, exceeding the derived bound {MAX_ADMISSION_WAIT_TICKS}",
            processed_at - inserted_at
        );
    }
    StorageHandle::enter(&mut provider, |storage| {
        let aggregate =
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage).unwrap();
        assert_eq!(aggregate.retained_count(), total_candidates);
    });
}

#[test]
fn start_metadosis_settles_one_ready_day_per_tick_oldest_first() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let older = outbe_primitives::time::WorldwideDay::new(2026_0501);
    let newer = outbe_primitives::time::WorldwideDay::new(2026_0502);
    let timestamp = StorageHandle::enter(&mut provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let newer_time = seed_day(&storage, newer, status::READY, U256::ZERO);
        let older_time = seed_day(&storage, older, status::READY, U256::ZERO);
        newer_time.max(older_time)
    });
    let scope = begin_empty_scope(&mut provider);
    let parent = TestParent::empty();

    for (block_number, expected) in [
        (50_u64, [status::FAILED, status::READY]),
        (51_u64, [status::FAILED, status::FAILED]),
    ] {
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        StorageHandle::enter(&mut provider, |storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
                storage,
            );
            crate::commands::start_metadosis(&ctx, &scope, &parent).unwrap();
        });
        StorageHandle::enter(&mut provider, |storage| {
            let metadosis = MetadosisContract::new(storage);
            assert_eq!(
                [
                    metadosis.get_wwd_status(older).unwrap(),
                    metadosis.get_wwd_status(newer).unwrap(),
                ],
                expected
            );
        });
    }
}

#[test]
fn capacity_forfeiture_preserves_retained_work_and_replays_without_effects() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let initial_carry = U256::from(7);
    let (victim, scheduled) = seed_capacity_fixture(
        &mut provider,
        MAX_RETAINED_WWDS,
        0,
        U256::ZERO,
        initial_carry,
    );
    let retained_before = StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        (
            wwd_words(&metadosis, 2026_0101u32.into()),
            wwd_words(&metadosis, 2026_0102u32.into()),
            metadosis.ocomp_scheduler.read().unwrap(),
            metadosis.ocomp_ready_index.read().unwrap(),
        )
    });
    let scope = begin_empty_scope(&mut provider);
    run_advance(&mut provider, &scope, 20, scheduled).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(victim).unwrap(), status::FAILED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&victim));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&victim));
        assert_eq!(
            (
                wwd_words(&metadosis, 2026_0101u32.into()),
                wwd_words(&metadosis, 2026_0102u32.into()),
                metadosis.ocomp_scheduler.read().unwrap(),
                metadosis.ocomp_ready_index.read().unwrap(),
            ),
            retained_before
        );
        assert!(metadosis
            .ocomp_fsm_states
            .get_bytes(&victim)
            .is_empty()
            .unwrap());
        assert!(metadosis
            .active_lysis_generation(victim, &crate::ocomp::schema::poc_schema_limits())
            .unwrap()
            .is_none());
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&victim).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );
        assert_eq!(
            desis.pending_supply_promis.read(&victim).unwrap(),
            U256::ZERO
        );

        let receipt = metadosis
            .read_capacity_forfeiture_receipt(victim)
            .unwrap()
            .unwrap();
        assert!(metadosis
            .read_missed_offering_receipt(victim)
            .unwrap()
            .is_none());
        assert_eq!(receipt.max_retained_wwds, MAX_RETAINED_WWDS as u32);
        assert_eq!(receipt.retained_count_before, MAX_RETAINED_WWDS as u32);
        assert_eq!(receipt.value_routed, U256::from(100));
        assert_eq!(receipt.carry_over_before, initial_carry);
        assert_eq!(receipt.carry_over_after, initial_carry + U256::from(100));
        assert_eq!(receipt.forfeited_count, 0);
        assert_eq!(receipt.forfeited_nominal, U256::ZERO);
        assert_eq!(receipt.source_generation, 0);
        assert_eq!(receipt.retired_generation, 1);
        assert_eq!(receipt.retirement, RetirementOutcome::NotPresent);

        let call = IMetadosis::getCapacityForfeitureReceiptCall {
            wwd: victim.value(),
        };
        let output = metadosis_dispatch(
            storage.clone(),
            &call.abi_encode(),
            Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let decoded =
            IMetadosis::getCapacityForfeitureReceiptCall::abi_decode_returns(&output).unwrap();
        assert_eq!(
            decoded.outcome,
            crate::schema::terminal_outcome::CAPACITY_FORFEITURE
        );
        assert_eq!(decoded.valueRouted, U256::from(100));
        assert_eq!(
            decoded.retirementOutcome,
            crate::schema::terminal_retirement::NOT_PRESENT
        );

        let generic = IMetadosis::getWorldwideDayTerminalReceiptCall {
            wwd: victim.value(),
        };
        let output =
            metadosis_dispatch(storage, &generic.abi_encode(), Address::ZERO, U256::ZERO).unwrap();
        let decoded =
            IMetadosis::getWorldwideDayTerminalReceiptCall::abi_decode_returns(&output).unwrap();
        assert_eq!(
            decoded.outcome,
            crate::schema::terminal_outcome::CAPACITY_FORFEITURE
        );
        assert_eq!(decoded.valueRouted, U256::from(100));
    });

    assert_eq!(
        provider
            .get_ordered_events()
            .iter()
            .filter_map(|event| {
                IMetadosis::WorldwideDayCapacityForfeited::decode_log(event).ok()
            })
            .count(),
        1
    );
    let storage_before_replay = provider.storage.clone();
    let events_before_replay = provider.events.clone();
    run_advance(&mut provider, &scope, 21, scheduled + 1).unwrap();
    assert_eq!(provider.storage, storage_before_replay);
    assert_eq!(provider.events, events_before_replay);
}

#[test]
fn additional_ready_day_preserves_real_pending_ocomp_job_and_indexes_byte_for_byte() {
    let mut fixture = crate::fixture_kernel::ActivationFixture::new_voting(50, 5_000, true);
    let pending = crate::fixture_kernel::TEST_WWD;
    let ready = outbe_primitives::time::WorldwideDay::new(2026_0724);
    let victim = outbe_primitives::time::WorldwideDay::new(2026_0725);
    let intent_id = fixture.intent_id;
    let limits = fixture.limits;
    let scheduled = StorageHandle::enter(&mut fixture.provider, |storage| {
        seed_day(&storage, ready, status::READY, U256::from(1));
        let scheduled = seed_day(&storage, victim, status::WAITING, U256::from(100));
        TributeContract::new(storage)
            .day_totals
            .create(&outbe_tribute::DayTotals {
                worldwide_day: victim,
                initialized: true,
                tribute_count: 0,
                tribute_nominal_amount: U256::ZERO,
                is_sealed: true,
            })
            .unwrap();
        scheduled
    });
    let retained_before = StorageHandle::enter(&mut fixture.provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        let job_storage_key = outbe_ocomp_protocol::intent::intent_storage_key(intent_id).unwrap();
        let snapshot = (
            wwd_words(&metadosis, pending),
            metadosis.ocomp_scheduler.read().unwrap(),
            metadosis.read_ready_index().unwrap(),
            metadosis.read_response_deadline_index().unwrap(),
            metadosis
                .ocomp_fsm_states
                .get_bytes(&pending)
                .read()
                .unwrap(),
            metadosis
                .ocomp_job_records
                .get_bytes(&job_storage_key)
                .read()
                .unwrap(),
        );
        assert!(
            !snapshot.1.is_empty(),
            "real pending scheduler must be seeded"
        );
        assert!(
            !snapshot.3.is_empty(),
            "real voting deadline index must be seeded"
        );
        assert!(!snapshot.4.is_empty(), "real pending FSM must be seeded");
        assert!(!snapshot.5.is_empty(), "real pending job must be seeded");
        snapshot
    });

    let scope = begin_empty_scope(&mut fixture.provider);
    run_advance(&mut fixture.provider, &scope, 51, scheduled).unwrap();

    StorageHandle::enter(&mut fixture.provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        let job_storage_key = outbe_ocomp_protocol::intent::intent_storage_key(intent_id).unwrap();
        assert_eq!(
            (
                wwd_words(&metadosis, pending),
                metadosis.ocomp_scheduler.read().unwrap(),
                metadosis.read_ready_index().unwrap(),
                metadosis.read_response_deadline_index().unwrap(),
                metadosis
                    .ocomp_fsm_states
                    .get_bytes(&pending)
                    .read()
                    .unwrap(),
                metadosis
                    .ocomp_job_records
                    .get_bytes(&job_storage_key)
                    .read()
                    .unwrap(),
            ),
            retained_before
        );
        assert_eq!(
            metadosis.get_wwd_status(pending).unwrap(),
            status::OFFCHAIN_PENDING
        );
        assert_eq!(metadosis.get_wwd_status(ready).unwrap(), status::READY);
        assert_eq!(metadosis.get_wwd_status(victim).unwrap(), status::READY);
        assert!(metadosis.active_wwd.read_all().unwrap().contains(&victim));
        assert!(metadosis
            .read_capacity_forfeiture_receipt(victim)
            .unwrap()
            .is_none());
        assert!(metadosis
            .ocomp_fsm_states
            .get_bytes(&victim)
            .is_empty()
            .unwrap());
        assert!(metadosis
            .active_lysis_generation(victim, &limits)
            .unwrap()
            .is_none());
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&victim).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );
        assert_eq!(
            desis.pending_supply_promis.read(&victim).unwrap(),
            U256::ZERO
        );
    });
}

#[test]
fn malformed_capacity_detail_is_fatal() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (victim, scheduled) = seed_capacity_fixture(
        &mut provider,
        MAX_RETAINED_WWDS,
        0,
        U256::ZERO,
        U256::from(7),
    );
    let scope = begin_empty_scope(&mut provider);
    run_advance(&mut provider, &scope, 20, scheduled).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        let mut detail = metadosis
            .capacity_forfeiture_receipts
            .get(victim)
            .unwrap()
            .unwrap();
        detail.block_number += 1;
        metadosis
            .capacity_forfeiture_receipts
            .update(&detail)
            .unwrap();

        assert!(matches!(
            metadosis.read_capacity_forfeiture_receipt(victim),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn capacity_generic_without_detail_is_fatal_in_reader_and_aggregate() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (victim, scheduled) = seed_capacity_fixture(
        &mut provider,
        MAX_RETAINED_WWDS,
        0,
        U256::ZERO,
        U256::from(7),
    );
    let scope = begin_empty_scope(&mut provider);
    run_advance(&mut provider, &scope, 20, scheduled).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .capacity_forfeiture_receipts
            .delete(victim)
            .unwrap();

        assert!(matches!(
            metadosis.read_capacity_forfeiture_receipt(victim),
            Err(PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn populated_and_max_shape_forfeiture_is_constant_size_and_emits_one_canonical_retirement() {
    for (count, nominal) in [(1, U256::from(55)), (u32::MAX, U256::MAX)] {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        let (victim, scheduled) = seed_capacity_fixture(
            &mut provider,
            MAX_RETAINED_WWDS,
            count,
            nominal,
            U256::from(7),
        );
        let (scope, tree) = begin_fixed_partition_scope(&mut provider);
        run_advance(&mut provider, &scope, 30, scheduled).unwrap();

        StorageHandle::enter(&mut provider, |storage| {
            let metadosis = MetadosisContract::new(storage.clone());
            let receipt = metadosis
                .read_capacity_forfeiture_receipt(victim)
                .unwrap()
                .unwrap();
            assert_eq!(receipt.sealed_collection_root, tree.partition_root);
            assert_eq!(receipt.forfeited_count, count);
            assert_eq!(receipt.forfeited_nominal, nominal);
            assert_eq!(receipt.retirement, RetirementOutcome::Requested);
            let tribute = TributeContract::new(storage);
            assert_eq!(tribute.total_supply.read().unwrap(), 0);
            let totals = tribute.get_day_totals(victim).unwrap();
            assert_eq!(totals.tribute_count, 0);
            assert_eq!(totals.tribute_nominal_amount, U256::ZERO);
            let admission = tribute.pre_admission_projection(victim).unwrap();
            assert_eq!(admission.sealed_collection_root, tree.partition_root);
            assert_eq!(admission.source_generation, 1);
        });
        assert_eq!(tree.leaf_reads.load(Ordering::SeqCst), 0);
        let tribute_events = provider
            .get_ordered_events()
            .iter()
            .filter(|event| event.address == outbe_primitives::addresses::TRIBUTE_ADDRESS)
            .collect::<Vec<_>>();
        assert_eq!(tribute_events.len(), 1);
        assert!(
            outbe_tribute::precompile::ITribute::TributePartitionRetired::decode_log(
                tribute_events[0]
            )
            .is_ok()
        );
    }
}

#[test]
#[ignore = "exhaustive fault-injection gate; run explicitly with --ignored"]
fn every_capacity_forfeiture_mutation_failure_restores_state_events_and_ce_work_then_retries() {
    let mut probe = HashMapStorageProvider::new(CHAIN_ID);
    let (probe_victim, scheduled) = seed_capacity_fixture_with_victim_state(
        &mut probe,
        MAX_RETAINED_WWDS,
        1,
        U256::from(55),
        U256::from(7),
        status::OFFERING,
    );
    let (probe_scope, _) = begin_fixed_partition_scope(&mut probe);
    probe.fail_after_mutation_at(usize::MAX);
    run_advance(&mut probe, &probe_scope, 40, scheduled).unwrap();
    let mutation_count = probe.clear_mutation_failure();
    assert!(mutation_count >= 12);
    StorageHandle::enter(&mut probe, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(
            metadosis.get_wwd_status(probe_victim).unwrap(),
            status::FAILED
        );
        let receipt = metadosis
            .read_capacity_forfeiture_receipt(probe_victim)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.value_routed, U256::from(100));
        assert_eq!(receipt.carry_over_before, U256::from(7));
        assert_eq!(receipt.carry_over_after, U256::from(107));
        assert_eq!(receipt.forfeited_count, 1);
        assert_eq!(receipt.forfeited_nominal, U256::from(55));
        assert!(TributeContract::new(storage.clone())
            .is_day_sealed(probe_victim)
            .unwrap());
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(107)
        );
        assert!(metadosis
            .ocomp_fsm_states
            .get_bytes(&probe_victim)
            .is_empty()
            .unwrap());
        assert!(metadosis
            .active_lysis_generation(probe_victim, &crate::ocomp::schema::poc_schema_limits())
            .unwrap()
            .is_none());
    });
    let status_events = probe
        .get_ordered_events()
        .iter()
        .filter_map(|event| IMetadosis::WorldwideDayStatusChange::decode_log(event).ok())
        .filter(|event| event.data.worldwideDay == probe_victim.value())
        .map(|event| {
            (
                event.data.oldStatus,
                event.data.newStatus,
                event.data.blockNumber,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        status_events,
        vec![
            (status::OFFERING, status::WAITING, 40),
            (status::WAITING, status::FAILED, 40),
        ],
        "the exact-cap composite must seal before the canonical terminal edge"
    );
    let clean_storage = probe.storage.clone();
    let clean_events = probe.events.clone();
    let clean_ordered_events = probe.get_ordered_events().to_vec();
    let clean_ce_work = probe_scope.ce_work_checkpoint().unwrap();

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        let (victim, scheduled) = seed_capacity_fixture_with_victim_state(
            &mut provider,
            MAX_RETAINED_WWDS,
            1,
            U256::from(55),
            U256::from(7),
            status::OFFERING,
        );
        let (scope, _) = begin_fixed_partition_scope(&mut provider);
        let storage_before = provider.storage.clone();
        let events_before = provider.events.clone();
        let ordered_events_before = provider.get_ordered_events().to_vec();
        let ce_before = scope.ce_work_checkpoint().unwrap();
        provider.fail_after_mutation_at(operation);

        let result = run_advance(&mut provider, &scope, 40, scheduled);
        assert!(
            result.is_err(),
            "mutation {operation} unexpectedly succeeded"
        );
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(provider.storage, storage_before, "storage at {operation}");
        assert_eq!(provider.events, events_before, "events at {operation}");
        assert_eq!(
            provider.get_ordered_events(),
            ordered_events_before.as_slice(),
            "ordered events at {operation}"
        );
        assert_eq!(
            scope.ce_work_checkpoint().unwrap(),
            ce_before,
            "CE work at {operation}"
        );

        run_advance(&mut provider, &scope, 40, scheduled).unwrap();
        StorageHandle::enter(&mut provider, |storage| {
            let metadosis = MetadosisContract::new(storage.clone());
            assert_eq!(metadosis.get_wwd_status(victim).unwrap(), status::FAILED);
            let receipt = metadosis
                .read_capacity_forfeiture_receipt(victim)
                .unwrap()
                .unwrap();
            assert_eq!(receipt.value_routed, U256::from(100));
            assert_eq!(receipt.carry_over_after, U256::from(107));
            assert!(TributeContract::new(storage).is_day_sealed(victim).unwrap());
        });
        let status_events = provider
            .get_ordered_events()
            .iter()
            .filter_map(|event| IMetadosis::WorldwideDayStatusChange::decode_log(event).ok())
            .filter(|event| event.data.worldwideDay == victim.value())
            .map(|event| (event.data.oldStatus, event.data.newStatus))
            .collect::<Vec<_>>();
        assert_eq!(
            status_events,
            vec![
                (status::OFFERING, status::WAITING),
                (status::WAITING, status::FAILED),
            ]
        );
        assert_eq!(
            provider.storage, clean_storage,
            "capacity retry storage diverged at {operation}"
        );
        assert_eq!(
            provider.events, clean_events,
            "capacity retry events diverged at {operation}"
        );
        assert_eq!(
            provider.get_ordered_events(),
            clean_ordered_events.as_slice(),
            "capacity retry ordered events diverged at {operation}"
        );
        assert_eq!(
            scope.ce_work_checkpoint().unwrap(),
            clean_ce_work,
            "capacity retry CE work diverged at {operation}"
        );
    }
}

#[test]
fn active_cap_rejects_create_before_an_orphan_record_or_event() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let start = 1_700_000_000_u64;
        for offset in 0..MAX_ACTIVE_WWDS {
            let wwd = outbe_primitives::time::WorldwideDay::from_timestamp(
                start + offset as u64 * WWD_CREATION_CADENCE_HOURS * SECONDS_PER_HOUR,
            );
            let mut metadosis = MetadosisContract::new(storage.clone());
            metadosis
                .create_worldwide_day(
                    wwd,
                    wwd.start_timestamp(),
                    LOOKBACK_DELAY_HOURS,
                    OFFERING_PERIOD_HOURS,
                )
                .unwrap();
            metadosis.add_active_wwd(wwd).unwrap();
        }
    });
    let rejected = outbe_primitives::time::WorldwideDay::from_timestamp(
        1_700_000_000 + MAX_ACTIVE_WWDS as u64 * WWD_CREATION_CADENCE_HOURS * SECONDS_PER_HOUR,
    );
    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    provider.set_block_number(2);
    let error = StorageHandle::enter(&mut provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(2, rejected.start_timestamp(), CHAIN_ID),
            storage.clone(),
        );
        crate::commands::apply_cycle_day_limit(&ctx, U256::from(1))
    })
    .unwrap_err();
    assert!(matches!(error, PrecompileError::Fatal(_)));
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert!(!metadosis.worldwide_days.exists(rejected).unwrap());
    });
}
