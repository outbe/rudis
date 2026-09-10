use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use alloy_primitives::{Address, U256};
use outbe_metadosis::{
    api::{
        capacity_forfeiture_receipt, day_limit_formation_receipt, missed_offering_receipt,
        worldwide_day, worldwide_days,
    },
    constants::MAX_RETAINED_WWDS,
    WwdMembership, WwdStatus,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::{CYCLE_ADDRESS, METADOSIS_ADDRESS},
    block::{BlockRuntimeContext, BlockRuntimeContext as RuntimeContext},
    storage::{hashmap::HashMapStorageProvider, MetadosisMutationPurposeTag, StorageHandle},
};
use proptest::{
    collection::vec,
    prop_assert, prop_assert_eq, prop_oneof,
    strategy::{Just, Strategy},
    test_runner::{
        Config, FileFailurePersistence, RngAlgorithm, TestCaseResult, TestRng, TestRunner,
    },
};

use super::{
    account_parent, anchor_genesis, block_ctx, cycle_storage, run_cycle_lifecycle,
    run_cycle_lifecycle_at_activation, Cycle, TriggerId, ACTIVE_TRIGGERS, GENESIS_TS,
    SECONDS_PER_DAY,
};

const GENERATED_OUTER_WWD_SEED: [u8; 32] = *b"metadosis-outer-wwd-model-seed!!";
const GENESIS_WWD: WorldwideDay = WorldwideDay::new(20_240_101);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelPhase {
    Forming,
    LookbackDelay,
    Offering,
    Waiting,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OuterWwdModel {
    phase: ModelPhase,
    membership: WwdMembership,
    has_terminal_receipt: bool,
    has_capacity_forfeiture: bool,
}

impl OuterWwdModel {
    const fn genesis() -> Self {
        Self {
            phase: ModelPhase::Forming,
            membership: WwdMembership::Active,
            has_terminal_receipt: false,
            has_capacity_forfeiture: false,
        }
    }

    fn observe(
        self,
        storage: &mut HashMapStorageProvider,
        wwd: WorldwideDay,
        replay_receipt: &Option<outbe_metadosis::api::DayLimitFormationReceipt>,
    ) -> TestCaseResult {
        let (actual, terminal_receipt, forfeiture, replay) =
            StorageHandle::enter(storage, |handle| {
                let actual = worldwide_day(handle.clone(), wwd).expect("typed WWD query");
                let missed = missed_offering_receipt(handle.clone(), wwd).unwrap();
                let forfeiture = capacity_forfeiture_receipt(handle.clone(), wwd).unwrap();
                (
                    actual,
                    missed.is_some() || forfeiture.is_some(),
                    forfeiture,
                    day_limit_formation_receipt(handle, wwd).unwrap(),
                )
            });
        let actual = actual.expect("model WWD exists");
        let expected_status = match self.phase {
            ModelPhase::Forming => WwdStatus::Forming,
            ModelPhase::LookbackDelay => WwdStatus::LookbackDelay,
            ModelPhase::Offering => WwdStatus::Offering,
            ModelPhase::Waiting => WwdStatus::Waiting,
            ModelPhase::Completed => WwdStatus::Completed,
        };
        prop_assert_eq!(actual.status, expected_status);
        prop_assert_eq!(actual.membership, self.membership);
        prop_assert_eq!(terminal_receipt, self.has_terminal_receipt);
        prop_assert_eq!(forfeiture.is_some(), self.has_capacity_forfeiture);
        prop_assert_eq!(&replay, replay_receipt);
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Coverage {
    terminal: usize,
    illegal: usize,
    duplicate: usize,
    rollback: usize,
    cap_minus_one: usize,
    cap: usize,
    cap_plus_one: usize,
    forfeiture: usize,
    multi_record: usize,
}

impl Coverage {
    fn merge(&mut self, other: &Self) {
        self.terminal += other.terminal;
        self.illegal += other.illegal;
        self.duplicate += other.duplicate;
        self.rollback += other.rollback;
        self.cap_minus_one += other.cap_minus_one;
        self.cap += other.cap;
        self.cap_plus_one += other.cap_plus_one;
        self.forfeiture += other.forfeiture;
        self.multi_record += other.multi_record;
    }

    fn assert_complete(&self, cases: usize) {
        for (label, count) in [
            ("terminal", self.terminal),
            ("illegal", self.illegal),
            ("duplicate", self.duplicate),
            ("rollback", self.rollback),
            ("cap-1", self.cap_minus_one),
            ("cap", self.cap),
            ("cap+1", self.cap_plus_one),
            ("forfeiture", self.forfeiture),
            ("multi-record", self.multi_record),
        ] {
            assert!(count > 0, "generated distribution missing {label}");
        }
        println!(
            "METADOSIS_CASE_DISTRIBUTION_V1 {{\"suite\":\"outer-wwd\",\"seed_family\":\"metadosis-outer-wwd-model\",\"cases\":{cases},\"terminal\":{},\"illegal\":{},\"duplicate\":{},\"rollback\":{},\"cap-1\":{},\"cap\":{},\"cap+1\":{},\"forfeiture\":{},\"multi-record\":{}}}",
            self.terminal,
            self.illegal,
            self.duplicate,
            self.rollback,
            self.cap_minus_one,
            self.cap,
            self.cap_plus_one,
            self.forfeiture,
            self.multi_record,
        );
    }
}

fn run_block(
    storage: &mut HashMapStorageProvider,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 128);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(block_number, timestamp), handle);
        if block_number == 1 {
            anchor_genesis(&ctx);
        }
        account_parent(&ctx, block_number);
        run_cycle_lifecycle(&ctx)
    })
}

fn hourly_fire_at(timestamp: u64) -> u64 {
    timestamp.div_ceil(3_600) * 3_600
}

fn advance_only(
    storage: &mut HashMapStorageProvider,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    StorageHandle::enter(storage, |handle| {
        let ctx = RuntimeContext::new(block_ctx(block_number, timestamp), handle);
        super::with_execution_scope(&ctx, |scope, _| {
            outbe_metadosis::commands::advance_active_worldwide_days(&ctx, scope)
        })
    })
}

fn cycle_metadosis_snapshot(storage: &HashMapStorageProvider) -> BTreeMap<(Address, U256), U256> {
    storage
        .storage
        .iter()
        .filter(|((address, _), _)| matches!(*address, METADOSIS_ADDRESS | CYCLE_ADDRESS))
        .map(|(key, value)| (*key, *value))
        .collect()
}

#[derive(Clone, Debug)]
enum OuterProbe {
    Duplicate,
    Backward(u8),
    BeforeOffering(u8),
    AdvanceOffering,
    FaultAtOffering,
}

#[derive(Clone, Debug)]
struct OuterHistory {
    genesis_jitter: u8,
    probes: Vec<OuterProbe>,
}

fn outer_history_strategy() -> impl Strategy<Value = OuterHistory> {
    let probe = prop_oneof![
        Just(OuterProbe::Duplicate),
        (1_u8..=30).prop_map(OuterProbe::Backward),
        (1_u8..=30).prop_map(OuterProbe::BeforeOffering),
        Just(OuterProbe::AdvanceOffering),
        Just(OuterProbe::FaultAtOffering),
    ];
    (0_u8..59, vec(probe, 1..=16)).prop_map(|(genesis_jitter, probes)| OuterHistory {
        genesis_jitter,
        probes,
    })
}

fn outer_history(history: OuterHistory, coverage: &mut Coverage) -> TestCaseResult {
    let mut storage = cycle_storage();
    let genesis_time = GENESIS_TS + 1 + u64::from(history.genesis_jitter);
    run_block(&mut storage, 1, genesis_time).expect("genesis Cycle command");
    let no_replay = None;
    OuterWwdModel::genesis().observe(&mut storage, GENESIS_WWD, &no_replay)?;

    let forming_edge = StorageHandle::enter(&mut storage, |handle| {
        worldwide_day(handle, GENESIS_WWD)
            .unwrap()
            .unwrap()
            .forming_end
    });
    let forming_fire = hourly_fire_at(forming_edge);
    let midnight = GENESIS_TS + SECONDS_PER_DAY;
    run_block(&mut storage, 2, midnight + 1).expect("midnight Cycle command");
    let replay_receipt = StorageHandle::enter(&mut storage, |handle| {
        day_limit_formation_receipt(handle, GENESIS_WWD).unwrap()
    });
    OuterWwdModel::genesis().observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    run_block(&mut storage, 3, forming_fire - 1).expect("T-1 Cycle command");
    OuterWwdModel::genesis().observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    run_block(&mut storage, 4, forming_fire).expect("T Cycle command");
    let lookback = OuterWwdModel {
        phase: ModelPhase::LookbackDelay,
        membership: WwdMembership::Active,
        has_terminal_receipt: false,
        has_capacity_forfeiture: false,
    };
    lookback.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    let duplicate_before = cycle_metadosis_snapshot(&storage);
    run_block(&mut storage, 5, forming_fire).expect("duplicate Cycle command");
    prop_assert_eq!(cycle_metadosis_snapshot(&storage), duplicate_before);
    lookback.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    let backward_before = cycle_metadosis_snapshot(&storage);
    run_block(&mut storage, 6, forming_fire - 1).expect("backward timestamp is effect-free");
    prop_assert_eq!(cycle_metadosis_snapshot(&storage), backward_before);
    lookback.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    run_block(&mut storage, 7, forming_fire + 1).expect("T+1 Cycle command");
    lookback.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    let offering_edge = StorageHandle::enter(&mut storage, |handle| {
        worldwide_day(handle, GENESIS_WWD)
            .unwrap()
            .unwrap()
            .lookback_end
    });
    let offering_fire = hourly_fire_at(offering_edge);
    let offering = OuterWwdModel {
        phase: ModelPhase::Offering,
        membership: WwdMembership::Active,
        has_terminal_receipt: false,
        has_capacity_forfeiture: false,
    };
    let mut model = lookback;
    let mut next_block = 8_u64;
    for probe in history.probes {
        let before_wwd = StorageHandle::enter(&mut storage, |handle| {
            worldwide_day(handle, GENESIS_WWD)
                .unwrap()
                .expect("generated-history WWD exists")
        });
        let (timestamp, expected_error, advances) = match probe {
            OuterProbe::Duplicate => {
                coverage.duplicate += 1;
                (
                    if model.phase == ModelPhase::Offering {
                        offering_fire
                    } else {
                        forming_fire + 1
                    },
                    false,
                    false,
                )
            }
            OuterProbe::Backward(delta) => {
                coverage.illegal += 1;
                (forming_fire.saturating_sub(u64::from(delta)), false, false)
            }
            OuterProbe::BeforeOffering(delta) => {
                coverage.illegal += 1;
                (offering_fire.saturating_sub(u64::from(delta)), false, false)
            }
            OuterProbe::AdvanceOffering => (
                offering_fire,
                false,
                model.phase == ModelPhase::LookbackDelay,
            ),
            OuterProbe::FaultAtOffering if model.phase == ModelPhase::LookbackDelay => {
                storage.fail_mutation_at_address(METADOSIS_ADDRESS);
                (offering_fire, true, false)
            }
            OuterProbe::FaultAtOffering => (offering_fire, false, false),
        };
        let result = run_block(&mut storage, next_block, timestamp);
        next_block += 1;
        if expected_error {
            prop_assert!(result.is_err());
            storage.clear_mutation_failure();
            coverage.rollback += 1;
        } else {
            result.expect("generated Cycle command");
        }
        if advances {
            model = offering;
        } else {
            let after_wwd = StorageHandle::enter(&mut storage, |handle| {
                worldwide_day(handle, GENESIS_WWD)
                    .unwrap()
                    .expect("generated-history WWD exists")
            });
            prop_assert_eq!(after_wwd, before_wwd);
        }
        model.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;
    }
    if model.phase == ModelPhase::LookbackDelay {
        run_block(&mut storage, next_block, offering_fire).expect("offering T Cycle command");
        next_block += 1;
        model = offering;
        model.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;
    }

    let offering_end = StorageHandle::enter(&mut storage, |handle| {
        worldwide_day(handle, GENESIS_WWD)
            .unwrap()
            .unwrap()
            .offering_end
    });
    let fire_at = hourly_fire_at(offering_end);

    let rollback_storage = cycle_metadosis_snapshot(&storage);
    let rollback_events = storage.get_ordered_events().to_vec();
    storage.fail_mutation_at_address(METADOSIS_ADDRESS);
    let failed = run_block(&mut storage, next_block, fire_at);
    prop_assert!(failed.is_err());
    storage.clear_mutation_failure();
    prop_assert_eq!(cycle_metadosis_snapshot(&storage), rollback_storage);
    prop_assert_eq!(storage.get_ordered_events(), rollback_events.as_slice());
    offering.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;

    run_block(&mut storage, next_block, fire_at).expect("exact retry after Cycle rollback");
    next_block += 1;
    let waiting = OuterWwdModel {
        phase: ModelPhase::Waiting,
        membership: WwdMembership::Active,
        has_terminal_receipt: false,
        has_capacity_forfeiture: false,
    };
    waiting.observe(&mut storage, GENESIS_WWD, &replay_receipt)?;
    let scheduled_process_time = StorageHandle::enter(&mut storage, |handle| {
        worldwide_day(handle, GENESIS_WWD)
            .unwrap()
            .unwrap()
            .scheduled_process_time
    });
    let process_fire_at = hourly_fire_at(scheduled_process_time.max(fire_at + 1));
    run_block(&mut storage, next_block, process_fire_at).expect("empty-day terminal Cycle command");
    OuterWwdModel {
        phase: ModelPhase::Completed,
        membership: WwdMembership::Closed,
        has_terminal_receipt: false,
        has_capacity_forfeiture: false,
    }
    .observe(&mut storage, GENESIS_WWD, &replay_receipt)?;
    let active_count = StorageHandle::enter(&mut storage, |handle| {
        worldwide_days(handle)
            .unwrap()
            .into_iter()
            .filter(|projection| projection.membership == WwdMembership::Active)
            .count()
    });
    prop_assert!(active_count > 1);
    coverage.terminal += 1;
    coverage.multi_record += 1;
    Ok(())
}

fn capacity_history(retained_before: usize, coverage: &mut Coverage) -> TestCaseResult {
    prop_assert!(retained_before == MAX_RETAINED_WWDS - 1 || retained_before == MAX_RETAINED_WWDS);
    let mut storage = cycle_storage();
    let victim = WorldwideDay::new(20_260_910);
    let day_limit = U256::from(100);
    StorageHandle::enter(&mut storage, |handle| {
        outbe_tribute::TributeContract::new(handle)
            .initialize_fresh_ocomp_profile()
            .unwrap();
    });

    let retained = super::retained_days_before(victim, retained_before);
    StorageHandle::enter(&mut storage, |handle| {
        outbe_metadosis::test_support::seed_ready_worldwide_days_for_capacity(handle, &retained)
            .unwrap();
    });

    let mut next_block = 2_u64;
    storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    let victim_projection = StorageHandle::enter(&mut storage, |handle| {
        let ctx = RuntimeContext::new(
            block_ctx(next_block, victim.start_timestamp() + 2 * 3_600),
            handle.clone(),
        );
        outbe_metadosis::commands::apply_cycle_day_limit(&ctx, day_limit).unwrap();
        worldwide_day(handle, victim).unwrap().unwrap()
    });
    next_block += 1;
    for boundary in [
        victim_projection.forming_end,
        victim_projection.lookback_end,
        victim_projection.offering_end,
    ] {
        advance_only(&mut storage, next_block, boundary).unwrap();
        next_block += 1;
    }
    let scheduled_process_time = victim_projection.scheduled_process_time;
    let fire_at = hourly_fire_at(scheduled_process_time);
    let previous_hour = fire_at - 3_600;
    StorageHandle::enter(&mut storage, |handle| {
        let cycle: Cycle<'_> = handle.contract::<Cycle<'_>>();
        for spec in ACTIVE_TRIGGERS {
            cycle
                .last_executed_at
                .write(
                    &spec.id,
                    if spec.id == TriggerId::ProtocolCycle.as_u32() {
                        previous_hour
                    } else {
                        fire_at
                    },
                )
                .unwrap();
        }
        cycle
            .active_utc_day
            .write(outbe_primitives::time::timestamp_to_date_key(fire_at))
            .unwrap();
    });

    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 4);
    StorageHandle::enter(&mut storage, |handle| {
        let ctx = RuntimeContext::new(block_ctx(30, fire_at), handle);
        account_parent(&ctx, 30);
        run_cycle_lifecycle_at_activation(&ctx, 0).unwrap();
    });

    let (projection, forfeiture) = StorageHandle::enter(&mut storage, |handle| {
        let projection = worldwide_day(handle.clone(), victim).unwrap().unwrap();
        let forfeiture = capacity_forfeiture_receipt(handle, victim).unwrap();
        (projection, forfeiture)
    });
    coverage.cap_minus_one += usize::from(retained_before == MAX_RETAINED_WWDS - 1);
    coverage.cap += usize::from(retained_before == MAX_RETAINED_WWDS);
    if retained_before < MAX_RETAINED_WWDS {
        prop_assert_eq!(projection.status, WwdStatus::Ready);
        prop_assert_eq!(projection.membership, WwdMembership::Active);
        prop_assert!(forfeiture.is_none());
    } else {
        prop_assert_eq!(projection.status, WwdStatus::Failed);
        prop_assert_eq!(projection.membership, WwdMembership::Closed);
        let receipt = forfeiture.expect("cap+1 attempt has a forfeiture receipt");
        prop_assert_eq!(receipt.retained_count_before as usize, MAX_RETAINED_WWDS);
        prop_assert_eq!(receipt.value_routed, day_limit);
        coverage.cap_plus_one += 1;
        coverage.forfeiture += 1;
    }
    Ok(())
}

#[test]
fn generated_outer_wwd_histories_match_cycle_begin_block_model() {
    let config = Config {
        cases: 64,
        failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
            "proptest-regressions",
        ))),
        source_file: Some(file!()),
        test_name: Some(concat!(
            module_path!(),
            "::generated_outer_wwd_histories_match_cycle_begin_block_model"
        )),
        ..Config::default()
    };
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &GENERATED_OUTER_WWD_SEED);
    let mut runner = TestRunner::new_with_rng(config, rng);
    let strategy = outer_history_strategy();
    let distribution = Arc::new(Mutex::new(Coverage::default()));
    let observed = distribution.clone();
    runner
        .run(&strategy, move |history| {
            let mut coverage = Coverage::default();
            outer_history(history, &mut coverage)?;
            observed.lock().unwrap().merge(&coverage);
            Ok(())
        })
        .unwrap();
    let mut capacity_coverage = Coverage::default();
    capacity_history(MAX_RETAINED_WWDS - 1, &mut capacity_coverage).unwrap();
    capacity_history(MAX_RETAINED_WWDS, &mut capacity_coverage).unwrap();
    distribution.lock().unwrap().merge(&capacity_coverage);
    distribution.lock().unwrap().assert_complete(64);
}
