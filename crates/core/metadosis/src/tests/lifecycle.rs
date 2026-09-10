use super::*;
use crate::{WwdDayType, WwdStatus};
use alloy_sol_types::SolEvent;
use outbe_nod::NodContract;
use outbe_oracle::schema::OracleContract;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct FailOncePartitionLookup {
    parent_root: B256,
    calls: AtomicUsize,
}

impl outbe_compressed_entities::AuthenticatedParentTree for FailOncePartitionLookup {
    fn parent_block_hash(&self) -> B256 {
        B256::ZERO
    }

    fn parent_root(&self) -> B256 {
        self.parent_root
    }

    fn read_leaf_verified(
        &self,
        _entity: outbe_compressed_entities::EntityRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<Option<outbe_compressed_entities::Commitment>> {
        if expected_parent_root != self.parent_root {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "injected parent root mismatch".into(),
            ));
        }
        Ok(None)
    }

    fn partition_present_verified(
        &self,
        _partition: outbe_compressed_entities::PartitionRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<bool> {
        if expected_parent_root != self.parent_root {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "injected parent root mismatch".into(),
            ));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(outbe_primitives::error::PrecompileError::TreeUnavailable(
                "injected partition lookup failure after Promis credit".into(),
            ));
        }
        Ok(false)
    }

    fn partition_root_verified(
        &self,
        _partition: outbe_compressed_entities::PartitionRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<Option<B256>> {
        if expected_parent_root != self.parent_root {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "injected parent root mismatch".into(),
            ));
        }
        Ok(None)
    }

    fn prepare_seal(
        &self,
        block_number: u64,
        mutations: &[outbe_compressed_entities::FinalLeafMutation],
        retirements: &[outbe_compressed_entities::PartitionRef],
    ) -> outbe_primitives::error::Result<outbe_compressed_entities::ProvisionalTreeBatch> {
        if !mutations.is_empty() || !retirements.is_empty() {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "empty injected parent received unexpected CE changes".into(),
            ));
        }
        outbe_compressed_entities::ProvisionalTreeBatch::new_identity(
            block_number,
            B256::ZERO,
            B256::ZERO,
        )
        .map_err(|error| {
            outbe_primitives::error::PrecompileError::Fatal(format!(
                "build injected identity batch: {error}"
            ))
        })
    }
}

#[derive(Debug)]
struct FailSecondPartitionLookup {
    parent_root: B256,
    partition_root: B256,
    calls: AtomicUsize,
}

impl outbe_compressed_entities::AuthenticatedParentTree for FailSecondPartitionLookup {
    fn parent_block_hash(&self) -> B256 {
        B256::ZERO
    }

    fn parent_root(&self) -> B256 {
        self.parent_root
    }

    fn read_leaf_verified(
        &self,
        _entity: outbe_compressed_entities::EntityRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<Option<outbe_compressed_entities::Commitment>> {
        if expected_parent_root != self.parent_root {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "injected parent root mismatch".into(),
            ));
        }
        Ok(None)
    }

    fn partition_present_verified(
        &self,
        partition: outbe_compressed_entities::PartitionRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<bool> {
        Ok(self
            .partition_root_verified(partition, expected_parent_root)?
            .is_some())
    }

    fn partition_root_verified(
        &self,
        partition: outbe_compressed_entities::PartitionRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<Option<B256>> {
        if expected_parent_root != self.parent_root
            || !matches!(
                partition,
                outbe_compressed_entities::PartitionRef::TributeWwd(_)
            )
        {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "injected partition authentication mismatch".into(),
            ));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(outbe_primitives::error::PrecompileError::TreeUnavailable(
                "injected second partition lookup failure".into(),
            ));
        }
        Ok(Some(self.partition_root))
    }

    fn prepare_seal(
        &self,
        _block_number: u64,
        _mutations: &[outbe_compressed_entities::FinalLeafMutation],
        _retirements: &[outbe_compressed_entities::PartitionRef],
    ) -> outbe_primitives::error::Result<outbe_compressed_entities::ProvisionalTreeBatch> {
        Err(outbe_primitives::error::PrecompileError::Fatal(
            "multi-WWD rollback test does not seal its synthetic parent tree".into(),
        ))
    }
}

fn create_waiting_day(
    storage: &StorageHandle,
    wwd: outbe_primitives::time::WorldwideDay,
    dtype: u8,
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
        .set_wwd_day_type(wwd, WwdDayType::try_from(dtype).unwrap())
        .unwrap();
    metadosis
        .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
        .unwrap();
    metadosis.set_metadosis_limit(wwd, day_limit).unwrap();
    metadosis
        .worldwide_days
        .entry(wwd)
        .scheduled_process_time()
        .read()
        .unwrap()
}

fn issue_one_tribute_and_run_metadosis(
    storage: &StorageHandle,
    wwd: outbe_primitives::time::WorldwideDay,
    nominal: U256,
    block_number: u64,
    timestamp: u64,
) {
    let owner = address!("7400000000000000000000000000000000000074");
    let ctx = BlockRuntimeContext::new(
        BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
        storage.clone(),
    );
    with_active_scope(storage.clone(), |scope, parent| {
        issue_one_tribute_in_scope(storage, scope, parent, owner, wwd, nominal);
        crate::commands::start_metadosis(&ctx, scope, parent).unwrap();
    });
}

fn issue_one_tribute_in_scope(
    storage: &StorageHandle,
    scope: &ExecutionScope,
    parent: &TestParent,
    owner: Address,
    wwd: outbe_primitives::time::WorldwideDay,
    nominal: U256,
) {
    let mut tribute = TributeContract::new(storage.clone());
    tribute.initialize_fresh_ocomp_profile().unwrap();
    tribute.unseal_day(wwd).unwrap();
    tribute
        .issue(
            scope,
            parent,
            &TributeData {
                tribute_id: NodContract::generate_nod_id(owner, wwd).unwrap(),
                owner,
                worldwide_day: wwd,
                issuance_amount_minor: nominal,
                issuance_currency: 840,
                nominal_amount_minor: nominal,
                reference_currency: 840,
                exclude_from_intex_issuance: false,
                tribute_price_minor: U256::from(2),
            },
        )
        .unwrap();
    tribute.seal_day(wwd).unwrap();
}

fn assert_no_ocomp_job(storage: &StorageHandle, wwd: outbe_primitives::time::WorldwideDay) {
    let metadosis = MetadosisContract::new(storage.clone());
    let limits = crate::ocomp::schema::poc_schema_limits();
    assert!(metadosis.ocomp_scheduler.is_empty().unwrap());
    assert!(metadosis.ocomp_ready_index.is_empty().unwrap());
    assert!(metadosis
        .ocomp_fsm_states
        .get_bytes(&wwd)
        .is_empty()
        .unwrap());
    assert_eq!(metadosis.terminal_intent_count(wwd).unwrap(), 0);
    assert!(metadosis
        .request_budget_receipt(wwd, &limits)
        .unwrap()
        .is_none());
    assert!(metadosis
        .read_pre_admission_envelope(wwd, &limits)
        .unwrap()
        .is_none());
}

fn seed_missed_offering_day(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
    base_limit: U256,
    formation_carry_over: U256,
    later_carry_over: U256,
) -> u64 {
    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    StorageHandle::enter(provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(formation_carry_over)
            .unwrap();
        let formation_ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(
                1,
                wwd.start_timestamp() + 2 * SECONDS_PER_HOUR,
                CHAIN_ID,
            ),
            storage.clone(),
        );
        crate::emission_sink::apply(&formation_ctx, base_limit).unwrap();
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(later_carry_over)
            .unwrap();
        MetadosisContract::new(storage)
            .worldwide_days
            .entry(wwd)
            .offering_end()
            .read()
            .unwrap()
    })
}

fn begin_persistent_active_scope(
    provider: &mut HashMapStorageProvider,
) -> (ExecutionScope, TestParent) {
    let scope = ExecutionScope::new();
    let parent = TestParent::empty();
    StorageHandle::enter(provider, |storage| {
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(4),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(
                    outbe_compressed_entities::sealed_root(B256::ZERO)
                        .unwrap()
                        .as_slice(),
                ),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    (scope, parent)
}

fn end_persistent_active_scope(provider: &mut HashMapStorageProvider, scope: &ExecutionScope) {
    StorageHandle::enter(provider, |storage| end_block(storage, scope).unwrap());
}

fn run_missed_offering_command(
    provider: &mut HashMapStorageProvider,
    scope: &ExecutionScope,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    run_advance_command(provider, scope, block_number, timestamp)
}

fn run_advance_command(
    provider: &mut HashMapStorageProvider,
    scope: &ExecutionScope,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    provider.set_block_number(block_number);
    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    StorageHandle::enter(provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
            storage,
        );
        crate::commands::advance_active_worldwide_days(&ctx, scope)
    })
}

fn run_start_command(
    provider: &mut HashMapStorageProvider,
    scope: &ExecutionScope,
    parent: &TestParent,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    provider.set_block_number(block_number);
    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    StorageHandle::enter(provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
            storage,
        );
        crate::commands::start_metadosis(&ctx, scope, parent)
    })
}

fn run_init_genesis_command(
    provider: &mut HashMapStorageProvider,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    provider.set_block_number(block_number);
    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    StorageHandle::enter(provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
            storage,
        );
        crate::commands::init_genesis_day(&ctx)
    })
}

fn seed_genesis_profile(provider: &mut HashMapStorageProvider) {
    StorageHandle::enter(provider, |storage| arm_genesis_ocomp(&storage, CHAIN_ID));
}

fn assert_genesis_created_once(
    provider: &mut HashMapStorageProvider,
    timestamp: u64,
) -> outbe_primitives::time::WorldwideDay {
    let expected = outbe_primitives::time::WorldwideDay::from_timestamp(timestamp);
    StorageHandle::enter(provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.active_wwd.read_all().unwrap(), vec![expected]);
        assert_eq!(metadosis.get_wwd_status(expected).unwrap(), status::FORMING);
        assert!(TributeContract::new(storage)
            .is_day_sealed(expected)
            .unwrap());
    });
    let started = provider
        .get_ordered_events()
        .iter()
        .filter_map(|event| IMetadosis::WorldwideDayStarted::decode_log(event).ok())
        .filter(|event| event.data.worldwideDay == expected.value())
        .count();
    assert_eq!(started, 1);
    expected
}

#[test]
fn genesis_creation_command_rolls_back_every_mutation_and_retries_exactly_once() {
    let timestamp = outbe_primitives::time::WorldwideDay::new(2026_0810).to_timestamp_utc()
        + 2 * SECONDS_PER_HOUR;

    let mut probe = HashMapStorageProvider::new(CHAIN_ID);
    seed_genesis_profile(&mut probe);
    probe.fail_after_mutation_at(usize::MAX);
    run_init_genesis_command(&mut probe, 1, timestamp).unwrap();
    let mutation_count = probe.clear_mutation_failure();
    assert!(
        mutation_count >= 4,
        "creation must persist the WWD, membership, Tribute seal and event"
    );
    let expected = assert_genesis_created_once(&mut probe, timestamp);
    assert_eq!(
        provider_status_events(&probe, expected),
        Vec::<(u8, u8, u64)>::new()
    );

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        seed_genesis_profile(&mut provider);
        let storage_before = provider.storage.clone();
        let events_before = provider.events.clone();
        let ordered_before = provider.get_ordered_events().to_vec();
        provider.fail_after_mutation_at(operation);

        assert!(
            run_init_genesis_command(&mut provider, 1, timestamp).is_err(),
            "mutation {operation} unexpectedly succeeded"
        );
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(provider.storage, storage_before, "storage at {operation}");
        assert_eq!(provider.events, events_before, "events at {operation}");
        assert_eq!(
            provider.get_ordered_events(),
            ordered_before.as_slice(),
            "ordered events at {operation}"
        );

        run_init_genesis_command(&mut provider, 1, timestamp).unwrap();
        assert_eq!(
            assert_genesis_created_once(&mut provider, timestamp),
            expected
        );
    }
}

fn provider_status_events(
    provider: &HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
) -> Vec<(u8, u8, u64)> {
    provider
        .get_ordered_events()
        .iter()
        .filter_map(|event| IMetadosis::WorldwideDayStatusChange::decode_log(event).ok())
        .filter(|event| event.data.worldwideDay == wwd.value())
        .map(|event| {
            (
                event.data.oldStatus,
                event.data.newStatus,
                event.data.blockNumber,
            )
        })
        .collect()
}

fn seed_forming_day_for_advance(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
) -> u64 {
    StorageHandle::enter(provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
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
        TributeContract::new(storage).seal_day(wwd).unwrap();
        metadosis
            .worldwide_days
            .entry(wwd)
            .lookback_end()
            .read()
            .unwrap()
    })
}

fn seed_unformed_missed_offering_day(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
    carry_over: U256,
) -> u64 {
    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    StorageHandle::enter(provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(carry_over)
            .unwrap();
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
        TributeContract::new(storage.clone()).seal_day(wwd).unwrap();
        metadosis
            .worldwide_days
            .entry(wwd)
            .offering_end()
            .read()
            .unwrap()
    })
}

fn assert_opened_offering_once(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
    block_number: u64,
) {
    StorageHandle::enter(provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::OFFERING);
        assert_eq!(metadosis.active_wwd.read_all().unwrap(), vec![wwd]);
        assert!(!TributeContract::new(storage).is_day_sealed(wwd).unwrap());
    });
    assert_eq!(
        provider_status_events(provider, wwd),
        vec![
            (status::FORMING, status::LOOKBACK_DELAY, block_number),
            (status::LOOKBACK_DELAY, status::OFFERING, block_number),
        ]
    );
}

fn seed_positive_ocomp_admission_fixture(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
) -> (ExecutionScope, TestParent, u64) {
    let day_limit = U256::from(5_000u64) * U256::from(10u64).pow(U256::from(18u64));
    let nominal = U256::from(1_000u64) * U256::from(10u64).pow(U256::from(18u64));
    let scheduled = StorageHandle::enter(provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        create_waiting_day(&storage, wwd, day_type::GREEN, day_limit)
    });
    let (scope, parent) = begin_persistent_active_scope(provider);
    StorageHandle::enter(provider, |storage| {
        issue_one_tribute_in_scope(
            &storage,
            &scope,
            &parent,
            address!("7400000000000000000000000000000000000074"),
            wwd,
            nominal,
        );
    });
    (scope, parent, scheduled)
}

#[test]
fn positive_ocomp_admission_rolls_back_every_mutation_and_retries_exactly() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0819);
    let block_number = 2;

    let mut control = HashMapStorageProvider::new(CHAIN_ID);
    let (control_scope, control_parent, scheduled) =
        seed_positive_ocomp_admission_fixture(&mut control, wwd);
    control.fail_after_mutation_at(usize::MAX);
    run_start_command(
        &mut control,
        &control_scope,
        &control_parent,
        block_number,
        scheduled,
    )
    .unwrap();
    let mutation_count = control.clear_mutation_failure();
    assert!(
        mutation_count >= 6,
        "positive OCOMP admission must persist pre-admission, scheduler, outer state and events"
    );
    let clean_storage = control.storage.clone();
    let clean_events = control.events.clone();
    let clean_ordered_events = control.get_ordered_events().to_vec();
    let clean_ce_work = control_scope.ce_work_checkpoint().unwrap();
    end_persistent_active_scope(&mut control, &control_scope);

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        let (scope, parent, scheduled) = seed_positive_ocomp_admission_fixture(&mut provider, wwd);
        let storage_before = provider.storage.clone();
        let events_before = provider.events.clone();
        let ordered_events_before = provider.get_ordered_events().to_vec();
        let ce_before = scope.ce_work_checkpoint().unwrap();
        provider.fail_after_mutation_at(operation);

        assert!(matches!(
            run_start_command(&mut provider, &scope, &parent, block_number, scheduled,),
            Err(outbe_primitives::error::PrecompileError::Storage(_))
        ));
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(provider.storage, storage_before, "storage at {operation}");
        assert_eq!(provider.events, events_before, "events at {operation}");
        assert_eq!(
            provider.get_ordered_events(),
            ordered_events_before.as_slice(),
            "ordered events at {operation}"
        );
        assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);

        run_start_command(&mut provider, &scope, &parent, block_number, scheduled).unwrap();
        assert_eq!(
            provider.storage, clean_storage,
            "storage retry at {operation}"
        );
        assert_eq!(provider.events, clean_events, "events retry at {operation}");
        assert_eq!(
            provider.get_ordered_events(),
            clean_ordered_events.as_slice(),
            "ordered events retry at {operation}"
        );
        assert_eq!(scope.ce_work_checkpoint().unwrap(), clean_ce_work);
        end_persistent_active_scope(&mut provider, &scope);
    }
}

#[test]
fn normal_advance_command_rolls_back_every_mutation_and_retries_with_ordered_edges() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0811);
    let block_number = 2;

    let mut probe = HashMapStorageProvider::new(CHAIN_ID);
    let offering_entry = seed_forming_day_for_advance(&mut probe, wwd);
    let probe_scope = ExecutionScope::new();
    let ce_before_probe = probe_scope.ce_work_checkpoint().unwrap();
    probe.fail_after_mutation_at(usize::MAX);
    run_advance_command(&mut probe, &probe_scope, block_number, offering_entry).unwrap();
    let mutation_count = probe.clear_mutation_failure();
    assert!(
        mutation_count >= 5,
        "normal advance must persist both edges, their events and offering effects"
    );
    assert_eq!(probe_scope.ce_work_checkpoint().unwrap(), ce_before_probe);
    assert_opened_offering_once(&mut probe, wwd, block_number);

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        let offering_entry = seed_forming_day_for_advance(&mut provider, wwd);
        let scope = ExecutionScope::new();
        let storage_before = provider.storage.clone();
        let events_before = provider.events.clone();
        let ordered_before = provider.get_ordered_events().to_vec();
        let ce_before = scope.ce_work_checkpoint().unwrap();
        provider.fail_after_mutation_at(operation);

        assert!(
            run_advance_command(&mut provider, &scope, block_number, offering_entry).is_err(),
            "mutation {operation} unexpectedly succeeded"
        );
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(provider.storage, storage_before, "storage at {operation}");
        assert_eq!(provider.events, events_before, "events at {operation}");
        assert_eq!(
            provider.get_ordered_events(),
            ordered_before.as_slice(),
            "ordered events at {operation}"
        );
        assert_eq!(
            scope.ce_work_checkpoint().unwrap(),
            ce_before,
            "CE work at {operation}"
        );

        run_advance_command(&mut provider, &scope, block_number, offering_entry).unwrap();
        assert_opened_offering_once(&mut provider, wwd, block_number);
    }
}

fn seed_local_terminal_fixture(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
    day_type: u8,
    day_limit: U256,
    tribute_count: u32,
    tribute_nominal: U256,
) -> u64 {
    StorageHandle::enter(provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let scheduled = create_waiting_day(&storage, wwd, day_type, day_limit);
        super::arm_reference_price(&storage, scheduled);
        let mut tribute = TributeContract::new(storage);
        tribute.initialize_fresh_ocomp_profile().unwrap();
        tribute
            .total_supply
            .write(u64::from(tribute_count))
            .unwrap();
        tribute
            .day_totals
            .create(&outbe_tribute::DayTotals {
                worldwide_day: wwd,
                initialized: true,
                tribute_count,
                tribute_nominal_amount: tribute_nominal,
                is_sealed: true,
            })
            .unwrap();
        let admission = tribute.pre_admission_projection(wwd).unwrap();
        assert!(admission.profile_ready);
        assert!(
            !admission.is_sealed,
            "local terminal classification precedes OCOMP pre-admission sealing"
        );
        assert_eq!(admission.tribute_count, tribute_count);
        assert_eq!(admission.tribute_nominal_amount, tribute_nominal);
        scheduled
    })
}

fn assert_local_terminal_completed(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
    expected_promis: U256,
) {
    assert_local_terminal_outcome(provider, wwd, status::COMPLETED, expected_promis);
}

fn assert_local_terminal_outcome(
    provider: &mut HashMapStorageProvider,
    wwd: outbe_primitives::time::WorldwideDay,
    expected_status: u8,
    expected_promis: U256,
) {
    StorageHandle::enter(provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), expected_status);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            expected_promis
        );
    });
}

fn exercise_local_terminal_fault_matrix(
    wwd: outbe_primitives::time::WorldwideDay,
    day_type: u8,
    day_limit: U256,
    tribute_count: u32,
    tribute_nominal: U256,
    expected_status: u8,
    expected_promis: U256,
) {
    let block_number = 2;

    let mut probe = HashMapStorageProvider::new(CHAIN_ID);
    let scheduled = seed_local_terminal_fixture(
        &mut probe,
        wwd,
        day_type,
        day_limit,
        tribute_count,
        tribute_nominal,
    );
    let (probe_scope, probe_parent) = begin_persistent_active_scope(&mut probe);
    let ce_before_probe = probe_scope.ce_work_checkpoint().unwrap();
    probe.fail_after_mutation_at(usize::MAX);
    run_start_command(
        &mut probe,
        &probe_scope,
        &probe_parent,
        block_number,
        scheduled,
    )
    .unwrap();
    let mutation_count = probe.clear_mutation_failure();
    assert!(
        mutation_count >= 7,
        "local terminal command must include transition, domain effects, retirement and events"
    );
    assert_eq!(probe_scope.ce_work_checkpoint().unwrap(), ce_before_probe);
    assert_local_terminal_outcome(&mut probe, wwd, expected_status, expected_promis);
    let clean_storage = probe.storage.clone();
    let clean_events = probe.events.clone();
    let clean_ordered_events = probe.get_ordered_events().to_vec();
    let clean_ce_work = probe_scope.ce_work_checkpoint().unwrap();
    end_persistent_active_scope(&mut probe, &probe_scope);

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        let scheduled = seed_local_terminal_fixture(
            &mut provider,
            wwd,
            day_type,
            day_limit,
            tribute_count,
            tribute_nominal,
        );
        let (scope, parent) = begin_persistent_active_scope(&mut provider);
        let storage_before = provider.storage.clone();
        let events_before = provider.events.clone();
        let ordered_before = provider.get_ordered_events().to_vec();
        let ce_before = scope.ce_work_checkpoint().unwrap();
        provider.fail_after_mutation_at(operation);

        assert!(
            run_start_command(&mut provider, &scope, &parent, block_number, scheduled).is_err(),
            "mutation {operation} unexpectedly succeeded"
        );
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(provider.storage, storage_before, "storage at {operation}");
        assert_eq!(provider.events, events_before, "events at {operation}");
        assert_eq!(
            provider.get_ordered_events(),
            ordered_before.as_slice(),
            "ordered events at {operation}"
        );
        assert_eq!(
            scope.ce_work_checkpoint().unwrap(),
            ce_before,
            "CE work at {operation}"
        );

        run_start_command(&mut provider, &scope, &parent, block_number, scheduled).unwrap();
        assert_local_terminal_outcome(&mut provider, wwd, expected_status, expected_promis);
        assert_eq!(
            provider.storage, clean_storage,
            "local terminal retry storage diverged at {operation}"
        );
        assert_eq!(
            provider.events, clean_events,
            "local terminal retry events diverged at {operation}"
        );
        assert_eq!(
            provider.get_ordered_events(),
            clean_ordered_events.as_slice(),
            "local terminal retry ordered events diverged at {operation}"
        );
        assert_eq!(
            scope.ce_work_checkpoint().unwrap(),
            clean_ce_work,
            "local terminal retry CE work diverged at {operation}"
        );
        end_persistent_active_scope(&mut provider, &scope);
    }
}

#[test]
fn empty_tribute_day_command_rolls_back_every_mutation_and_ce_work_then_retries() {
    exercise_local_terminal_fault_matrix(
        outbe_primitives::time::WorldwideDay::new(2026_0812),
        day_type::RED,
        U256::from(777),
        0,
        U256::ZERO,
        status::COMPLETED,
        U256::from(777),
    );
}

#[test]
fn zero_gratis_command_rolls_back_every_mutation_and_ce_work_then_retries() {
    exercise_local_terminal_fault_matrix(
        outbe_primitives::time::WorldwideDay::new(2026_0813),
        day_type::RED,
        U256::from(2),
        1,
        U256::from(1_000),
        status::COMPLETED,
        U256::from(2),
    );
}

#[test]
fn zero_day_limit_rolls_back_every_mutation_and_retries_exactly() {
    exercise_local_terminal_fault_matrix(
        outbe_primitives::time::WorldwideDay::new(2026_0820),
        day_type::GREEN,
        U256::ZERO,
        1,
        U256::from(1_000),
        status::FAILED,
        U256::ZERO,
    );
}

#[test]
fn unknown_day_type_rolls_back_every_mutation_and_retries_exactly() {
    exercise_local_terminal_fault_matrix(
        outbe_primitives::time::WorldwideDay::new(2026_0821),
        day_type::UNKNOWN,
        U256::from(777),
        1,
        U256::from(1_000),
        status::FAILED,
        U256::from(777),
    );
}

#[test]
fn green_empty_tribute_day_rolls_back_every_mutation_and_retries_exactly() {
    exercise_local_terminal_fault_matrix(
        outbe_primitives::time::WorldwideDay::new(2026_0822),
        day_type::GREEN,
        U256::from(777),
        0,
        U256::ZERO,
        status::COMPLETED,
        U256::from(777),
    );
}

#[test]
fn green_zero_gratis_rolls_back_every_mutation_and_retries_exactly() {
    exercise_local_terminal_fault_matrix(
        outbe_primitives::time::WorldwideDay::new(2026_0823),
        day_type::GREEN,
        U256::from(2),
        1,
        U256::ONE,
        status::COMPLETED,
        U256::ONE,
    );
}

#[test]
fn zero_gratis_completes_with_a_present_parent_partition_without_retiring_input() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0818);
    let day_limit = U256::from(2);
    let nominal = U256::from(1_000);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let scheduled =
        seed_local_terminal_fixture(&mut provider, wwd, day_type::RED, day_limit, 1, nominal);
    let parent_root = outbe_compressed_entities::sealed_root(B256::repeat_byte(0x86)).unwrap();
    let tree = Arc::new(FailSecondPartitionLookup {
        parent_root,
        partition_root: B256::repeat_byte(0x87),
        calls: AtomicUsize::new(0),
    });
    let scope = ExecutionScope::with_parent_tree(
        tree.clone(),
        outbe_compressed_entities::CeWorkConfig::new(0, 0, u64::MAX),
    );
    let parent = TestParent::empty();
    StorageHandle::enter(&mut provider, |storage| {
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(4),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    let ce_before = scope.ce_work_checkpoint().unwrap();

    run_start_command(&mut provider, &scope, &parent, 2, scheduled).unwrap();

    assert_eq!(
        tree.calls.load(Ordering::SeqCst),
        0,
        "populated zero-gratis input remains available and is not retired"
    );
    assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);
    assert_local_terminal_completed(&mut provider, wwd, day_limit);
    StorageHandle::enter(&mut provider, |storage| {
        let tribute = TributeContract::new(storage.clone());
        assert_eq!(tribute.total_supply().unwrap(), 1);
        let totals = tribute.get_day_totals(wwd).unwrap();
        assert_eq!(totals.tribute_count, 1);
        assert_eq!(totals.tribute_nominal_amount, nominal);
        assert_no_ocomp_job(&storage, wwd);
    });
}

#[test]
fn empty_tribute_day_restores_outer_ce_checkpoint_after_late_parent_failure_then_retries() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0814);
    let day_limit = U256::from(777);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let scheduled =
        seed_local_terminal_fixture(&mut provider, wwd, day_type::RED, day_limit, 0, U256::ZERO);
    let parent_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
    let tree = Arc::new(FailOncePartitionLookup {
        parent_root,
        calls: AtomicUsize::new(0),
    });
    let scope = ExecutionScope::with_parent_tree(
        tree.clone(),
        outbe_compressed_entities::CeWorkConfig::new(0, 0, u64::MAX),
    );
    let parent = TestParent::empty();
    StorageHandle::enter(&mut provider, |storage| {
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(4),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    let ordered_before = provider.get_ordered_events().to_vec();
    let ce_before = scope.ce_work_checkpoint().unwrap();

    let error = run_start_command(&mut provider, &scope, &parent, 2, scheduled).unwrap_err();
    assert!(matches!(
        error,
        outbe_primitives::error::PrecompileError::TreeUnavailable(_)
    ));
    assert_eq!(tree.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    assert_eq!(provider.get_ordered_events(), ordered_before.as_slice());
    assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);

    run_start_command(&mut provider, &scope, &parent, 2, scheduled).unwrap();
    assert_eq!(tree.calls.load(Ordering::SeqCst), 2);
    assert_local_terminal_completed(&mut provider, wwd, day_limit);
    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn test_emission_sink_writes_metadosis_limit_for_worldwide_day() {
    with_storage(|storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let timestamp = outbe_primitives::time::WorldwideDay::new(20241221).start_timestamp()
            + 2 * SECONDS_PER_HOUR;
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(1, timestamp, CHAIN_ID),
            storage.clone(),
        );

        // The terminal sink now writes the limit onto the WorldwideDay record
        // (UTC+14 keyed) for the block timestamp, not a separate UTC-date-key map.
        let wwd = outbe_primitives::time::WorldwideDay::from_timestamp(timestamp);

        let day_limit = U256::from(500_000_000u64);
        crate::emission_sink::apply(&ctx, day_limit).unwrap();

        let metadosis = MetadosisContract::new(storage);
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .metadosis_limit_amount()
                .read()
                .unwrap(),
            day_limit
        );
        // A neighboring day is untouched.
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd.previous_date_key())
                .metadosis_limit_amount()
                .read()
                .unwrap(),
            U256::ZERO
        );
    });
}

#[test]
fn ocomp_day_limit_formation_leaves_the_accumulator_untouched() {
    fn apply_limit(
        provider: &mut HashMapStorageProvider,
        block_number: u64,
        wwd: outbe_primitives::time::WorldwideDay,
        amount: U256,
    ) -> outbe_primitives::error::Result<U256> {
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
        );
        provider.set_block_number(block_number);
        StorageHandle::enter(provider, |storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(
                    block_number,
                    wwd.start_timestamp() + 2 * SECONDS_PER_HOUR,
                    CHAIN_ID,
                ),
                storage,
            );
            crate::commands::apply_cycle_day_limit(&ctx, amount)
        })
    }

    let first = outbe_primitives::time::WorldwideDay::new(20260725);
    let second = outbe_primitives::time::WorldwideDay::new(20260726);
    let third = outbe_primitives::time::WorldwideDay::new(20260727);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        PromisLimitContract::new(storage)
            .checked_add_carry_over(U256::from(30))
            .unwrap();
    });
    apply_limit(&mut provider, 10, first, U256::from(100)).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let promis = PromisLimitContract::new(storage.clone());
        let metadosis = MetadosisContract::new(storage.clone());
        let first_day = metadosis.worldwide_days.entry(first);
        let first_formation = metadosis.ocomp_day_limit_formation(first).unwrap().unwrap();
        assert_eq!(first_formation.worldwide_day, first);
        assert_eq!(first_formation.base_limit, U256::from(100));
        assert_eq!(first_formation.carry_over_before, U256::from(30));
        assert_eq!(first_formation.carry_over_taken, U256::ZERO);
        assert_eq!(first_formation.carry_over_after, U256::from(30));
        assert_eq!(first_formation.day_limit, U256::from(100));
        assert_eq!(first_formation.block_number, 10);
        assert_eq!(
            crate::api::day_limit_formation_receipt(storage.clone(), first).unwrap(),
            Some(crate::DayLimitFormationReceipt::Formed(first_formation))
        );
        assert_eq!(
            first_day.metadosis_limit_amount().read().unwrap(),
            U256::from(100)
        );
        assert_eq!(promis.get_total_unallocated().unwrap(), U256::from(30));

        PromisLimitContract::new(storage)
            .checked_add_carry_over(U256::from(7))
            .unwrap();
    });
    apply_limit(&mut provider, 10, first, U256::from(100)).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let promis = PromisLimitContract::new(storage.clone());
        let first_day = MetadosisContract::new(storage.clone())
            .worldwide_days
            .entry(first);
        assert_eq!(
            first_day.metadosis_limit_amount().read().unwrap(),
            U256::from(100)
        );
        assert_eq!(promis.get_total_unallocated().unwrap(), U256::from(37));
        assert!(MetadosisContract::new(storage.clone())
            .set_metadosis_limit(first, U256::from(999))
            .is_err());
        assert_eq!(
            first_day.metadosis_limit_amount().read().unwrap(),
            U256::from(100)
        );
        assert_eq!(promis.get_total_unallocated().unwrap(), U256::from(37));
    });
    assert!(apply_limit(&mut provider, 10, first, U256::from(101)).is_err());

    apply_limit(&mut provider, 20, second, U256::from(200)).unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let promis = PromisLimitContract::new(storage.clone());
        let metadosis = MetadosisContract::new(storage);
        let second_day = metadosis.worldwide_days.entry(second);
        let second_formation = metadosis
            .ocomp_day_limit_formation(second)
            .unwrap()
            .unwrap();
        assert_eq!(second_formation.carry_over_taken, U256::ZERO);
        assert_eq!(second_formation.carry_over_before, U256::from(37));
        assert_eq!(second_formation.carry_over_after, U256::from(37));
        assert_eq!(second_formation.block_number, 20);
        assert_eq!(
            second_day.metadosis_limit_amount().read().unwrap(),
            U256::from(200)
        );
        assert_eq!(promis.get_total_unallocated().unwrap(), U256::from(37));
    });

    apply_limit(&mut provider, 30, third, U256::from(50)).unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        let third_formation = metadosis.ocomp_day_limit_formation(third).unwrap().unwrap();
        assert_eq!(third_formation.base_limit, U256::from(50));
        assert_eq!(third_formation.carry_over_taken, U256::ZERO);
        assert_eq!(third_formation.day_limit, U256::from(50));

        MetadosisContract::new(storage.clone())
            .delete_worldwide_day(third)
            .unwrap();
        assert!(MetadosisContract::new(storage)
            .ocomp_day_limit_formation(third)
            .unwrap()
            .is_none());
    })
}

#[test]
fn ocomp_day_limit_rejection_and_every_mutation_failure_are_atomic() {
    fn seed(provider: &mut HashMapStorageProvider, carry_over: U256) {
        StorageHandle::enter(provider, |storage| {
            arm_genesis_ocomp(&storage, CHAIN_ID);
            PromisLimitContract::new(storage)
                .checked_add_carry_over(carry_over)
                .unwrap();
        });
    }

    fn apply_limit(
        provider: &mut HashMapStorageProvider,
        base_limit: U256,
    ) -> outbe_primitives::error::Result<U256> {
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
        );
        let wwd = outbe_primitives::time::WorldwideDay::new(20260727);
        StorageHandle::enter(provider, |storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(
                    30,
                    wwd.start_timestamp() + 2 * SECONDS_PER_HOUR,
                    CHAIN_ID,
                ),
                storage,
            );
            crate::commands::apply_cycle_day_limit(&ctx, base_limit)
        })
    }

    // A formed day limit cannot be replaced, and the refusal leaves no trace.
    let mut rejected = HashMapStorageProvider::new(CHAIN_ID);
    outbe_fidelity::enclave_client::test_enclave::install();
    seed(&mut rejected, U256::from(1));
    apply_limit(&mut rejected, U256::from(100)).unwrap();
    let before_storage = rejected.storage.clone();
    let before_events = rejected.events.clone();
    let before_ordered = rejected.get_ordered_events().to_vec();
    assert!(apply_limit(&mut rejected, U256::from(101)).is_err());
    assert_eq!(rejected.storage, before_storage);
    assert_eq!(rejected.events, before_events);
    assert_eq!(rejected.get_ordered_events(), before_ordered.as_slice());
    StorageHandle::enter(&mut rejected, |storage| {
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            U256::from(1)
        );
        let formation = MetadosisContract::new(storage)
            .ocomp_day_limit_formation(outbe_primitives::time::WorldwideDay::new(20260727))
            .unwrap()
            .unwrap();
        assert_eq!(formation.base_limit, U256::from(100));
        assert_eq!(formation.day_limit, U256::from(100));
    });

    let mut probe = HashMapStorageProvider::new(CHAIN_ID);
    outbe_fidelity::enclave_client::test_enclave::install();
    seed(&mut probe, U256::from(9));
    probe.fail_after_mutation_at(usize::MAX);
    apply_limit(&mut probe, U256::from(100)).unwrap();
    let mutation_count = probe.clear_mutation_failure();
    assert!(
        mutation_count >= 2,
        "formation must mutate Metadosis and events"
    );
    let event = IMetadosis::OcompDayLimitFormed::decode_log(
        probe.get_ordered_events().last().expect("formation event"),
    )
    .unwrap();
    assert_eq!(event.data.worldwideDay, 20260727);
    assert_eq!(event.data.baseLimit, U256::from(100));
    assert_eq!(event.data.carryOverBefore, U256::from(9));
    assert_eq!(event.data.carryOverTaken, U256::ZERO);
    assert_eq!(event.data.carryOverAfter, U256::from(9));
    assert_eq!(event.data.formedDayLimit, U256::from(100));
    let replay_event_count = probe.get_ordered_events().len();
    apply_limit(&mut probe, U256::from(100)).unwrap();
    assert_eq!(probe.get_ordered_events().len(), replay_event_count);
    let clean_storage = probe.storage.clone();
    let clean_events = probe.events.clone();
    let clean_ordered = probe.get_ordered_events().to_vec();

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        outbe_fidelity::enclave_client::test_enclave::install();
        seed(&mut provider, U256::from(9));
        let before_storage = provider.storage.clone();
        let before_events = provider.events.clone();
        let before_ordered = provider.get_ordered_events().to_vec();
        provider.fail_after_mutation_at(operation);

        assert!(apply_limit(&mut provider, U256::from(100)).is_err());
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(provider.storage, before_storage);
        assert_eq!(provider.events, before_events);
        assert_eq!(provider.get_ordered_events(), before_ordered.as_slice());

        apply_limit(&mut provider, U256::from(100)).unwrap();
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
        StorageHandle::enter(&mut provider, |storage| {
            let formed = MetadosisContract::new(storage.clone())
                .ocomp_day_limit_formation(outbe_primitives::time::WorldwideDay::new(20260727))
                .unwrap()
                .unwrap();
            assert_eq!(formed.base_limit, U256::from(100));
            assert_eq!(formed.carry_over_taken, U256::ZERO);
            assert_eq!(formed.day_limit, U256::from(100));
            assert_eq!(
                PromisLimitContract::new(storage)
                    .get_total_unallocated()
                    .unwrap(),
                U256::from(9)
            );
        });
    }
}

#[test]
fn missed_offering_routes_the_formed_limit_once_and_exposes_a_durable_receipt() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0731);
    let base_limit = U256::from(100);
    let formation_carry = U256::from(9);
    let later_carry = U256::from(7);
    // Formation no longer folds the accumulator in, so the day is formed against its own base.
    let formed_limit = base_limit;
    let carried = formation_carry + later_carry;
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, base_limit, formation_carry, later_carry);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);

    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        let receipt = metadosis
            .read_missed_offering_receipt(wwd)
            .unwrap()
            .unwrap();
        assert!(metadosis
            .read_capacity_forfeiture_receipt(wwd)
            .unwrap()
            .is_none());
        assert_eq!(receipt.value_routed, formed_limit);
        assert_eq!(receipt.carry_over_before, carried);
        assert_eq!(receipt.carry_over_after, carried + formed_limit);
        assert_eq!(receipt.block_number, 2);
        assert_eq!(
            receipt.retirement,
            outbe_compressed_entities::RetirementOutcome::NotPresent
        );
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            carried + formed_limit
        );
        assert_no_ocomp_job(&storage, wwd);
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        assert_eq!(
            TributeContract::new(storage.clone())
                .get_day_totals(wwd)
                .unwrap()
                .tribute_count,
            0
        );
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&wwd).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );

        let call = IMetadosis::getWorldwideDayTerminalReceiptCall { wwd: wwd.value() };
        let output =
            metadosis_dispatch(storage, &call.abi_encode(), Address::ZERO, U256::ZERO).unwrap();
        let decoded =
            IMetadosis::getWorldwideDayTerminalReceiptCall::abi_decode_returns(&output).unwrap();
        assert_eq!(decoded.outcome, 1);
        assert_eq!(decoded.valueRouted, formed_limit);
        assert_eq!(decoded.carryOverBefore, carried);
        assert_eq!(decoded.carryOverAfter, carried + formed_limit);
        assert_eq!(
            decoded.retirementOutcome,
            crate::schema::terminal_retirement::NOT_PRESENT
        );
        assert_eq!(decoded.blockNumber, 2);
    });

    let missed_events_before = provider
        .get_ordered_events()
        .iter()
        .filter_map(|event| IMetadosis::WorldwideDayMissedOffering::decode_log(event).ok())
        .count();
    assert_eq!(missed_events_before, 1);
    let storage_before_replay = provider.storage.clone();
    let events_before_replay = provider.events.clone();
    run_missed_offering_command(&mut provider, &scope, 3, offering_end + 1).unwrap();
    assert_eq!(provider.storage, storage_before_replay);
    assert_eq!(provider.events, events_before_replay);

    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn malformed_missed_offering_receipt_is_fatal() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0801);
    with_contract(|metadosis| {
        metadosis
            .worldwide_day_terminal_receipts
            .create(&crate::schema::WorldwideDayTerminalReceiptState {
                wwd,
                outcome: crate::schema::terminal_outcome::MISSED_OFFERING,
                value_routed: U256::from(10),
                carry_over_before: U256::from(3),
                carry_over_after: U256::from(12),
                retirement: crate::schema::terminal_retirement::NOT_PRESENT,
                block_number: 1,
            })
            .unwrap();

        assert!(matches!(
            metadosis.read_missed_offering_receipt(wwd),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn missed_receipt_value_drift_is_fatal_in_reader_and_aggregate() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0802);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, U256::from(100), U256::ZERO, U256::ZERO);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);
    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        let mut receipt = metadosis
            .worldwide_day_terminal_receipts
            .get(wwd)
            .unwrap()
            .unwrap();
        receipt.value_routed += U256::from(1);
        receipt.carry_over_after += U256::from(1);
        metadosis
            .worldwide_day_terminal_receipts
            .update(&receipt)
            .unwrap();

        assert!(matches!(
            metadosis.read_missed_offering_receipt(wwd),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn missed_receipt_with_capacity_detail_is_fatal_in_reader_and_aggregate() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0803);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, U256::from(100), U256::ZERO, U256::ZERO);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);
    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        let receipt = metadosis
            .worldwide_day_terminal_receipts
            .get(wwd)
            .unwrap()
            .unwrap();
        metadosis
            .capacity_forfeiture_receipts
            .create(&crate::schema::CapacityForfeitureReceiptState {
                wwd,
                outcome: crate::schema::terminal_outcome::CAPACITY_FORFEITURE,
                max_retained_wwds: MAX_RETAINED_WWDS as u32,
                retained_count_before: MAX_RETAINED_WWDS as u32,
                value_routed: receipt.value_routed,
                carry_over_before: receipt.carry_over_before,
                carry_over_after: receipt.carry_over_after,
                sealed_collection_root: B256::ZERO,
                forfeited_count: 0,
                forfeited_nominal: U256::ZERO,
                source_generation: 0,
                retired_generation: 1,
                retirement: receipt.retirement,
                block_number: receipt.block_number,
            })
            .unwrap();

        assert!(matches!(
            metadosis.read_missed_offering_receipt(wwd),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn missed_receipt_status_drift_is_fatal_in_reader_and_aggregate() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0804);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, U256::from(100), U256::ZERO, U256::ZERO);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);
    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Completed)
            .unwrap();

        assert!(matches!(
            metadosis.read_missed_offering_receipt(wwd),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn missed_receipt_membership_drift_is_fatal_in_reader_and_aggregate() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0805);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, U256::from(100), U256::ZERO, U256::ZERO);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);
    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis.add_active_wwd(wwd).unwrap();

        assert!(matches!(
            metadosis.read_missed_offering_receipt(wwd),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn duplicate_closed_membership_is_fatal_in_reader_and_aggregate() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0806);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, U256::from(100), U256::ZERO, U256::ZERO);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);
    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        metadosis.closed_wwd.push_back(wwd).unwrap();

        assert!(matches!(
            metadosis.read_missed_offering_receipt(wwd),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
        assert!(matches!(
            crate::aggregate::ValidatedWwdAggregate::load_and_validate(storage),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn missed_offering_rejects_a_populated_partition_without_any_partial_effect() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0801);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end = seed_missed_offering_day(
        &mut provider,
        wwd,
        U256::from(100),
        U256::ZERO,
        U256::from(7),
    );
    let (scope, parent) = begin_persistent_active_scope(&mut provider);
    StorageHandle::enter(&mut provider, |storage| {
        issue_one_tribute_in_scope(
            &storage,
            &scope,
            &parent,
            address!("7600000000000000000000000000000000000076"),
            wwd,
            U256::from(10),
        );
    });

    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    let ce_before = scope.ce_work_checkpoint().unwrap();
    let error = run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap_err();
    assert!(matches!(
        error,
        outbe_primitives::error::PrecompileError::BodyReadCorruption(_)
    ));
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FORMING);
        assert!(metadosis
            .read_missed_offering_receipt(wwd)
            .unwrap()
            .is_none());
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(7)
        );
    });

    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn missed_offering_rolls_back_every_injected_storage_or_event_failure_then_retries() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0802);
    let mut probe = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut probe, wwd, U256::from(100), U256::ZERO, U256::from(7));
    let (probe_scope, _parent) = begin_persistent_active_scope(&mut probe);
    probe.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    probe.fail_after_mutation_at(usize::MAX);
    StorageHandle::enter(&mut probe, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(2, offering_end, CHAIN_ID),
            storage,
        );
        crate::commands::advance_active_worldwide_days(&ctx, &probe_scope).unwrap();
    });
    let mutation_count = probe.clear_mutation_failure();
    assert!(
        mutation_count >= 6,
        "MissedOffering must touch Promis, retirement, receipt, WWD indexes and events"
    );
    let clean_storage = probe.storage.clone();
    let clean_events = probe.events.clone();
    let clean_ordered_events = probe.get_ordered_events().to_vec();
    let clean_ce_work = probe_scope.ce_work_checkpoint().unwrap();
    end_persistent_active_scope(&mut probe, &probe_scope);

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        let offering_end = seed_missed_offering_day(
            &mut provider,
            wwd,
            U256::from(100),
            U256::ZERO,
            U256::from(7),
        );
        let (scope, _parent) = begin_persistent_active_scope(&mut provider);
        let storage_before = provider.storage.clone();
        let events_before = provider.events.clone();
        let ordered_events_before = provider.get_ordered_events().to_vec();
        let ce_before = scope.ce_work_checkpoint().unwrap();

        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
        );
        provider.fail_after_mutation_at(operation);
        let result = StorageHandle::enter(&mut provider, |storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(2, offering_end, CHAIN_ID),
                storage,
            );
            crate::commands::advance_active_worldwide_days(&ctx, &scope)
        });
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

        run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();
        StorageHandle::enter(&mut provider, |storage| {
            assert_eq!(
                MetadosisContract::new(storage).get_wwd_status(wwd).unwrap(),
                status::FAILED
            );
        });
        assert_eq!(
            provider.storage, clean_storage,
            "MissedOffering retry storage diverged at {operation}"
        );
        assert_eq!(
            provider.events, clean_events,
            "MissedOffering retry events diverged at {operation}"
        );
        assert_eq!(
            provider.get_ordered_events(),
            clean_ordered_events.as_slice(),
            "MissedOffering retry ordered events diverged at {operation}"
        );
        assert_eq!(
            scope.ce_work_checkpoint().unwrap(),
            clean_ce_work,
            "MissedOffering retry CE work diverged at {operation}"
        );
        end_persistent_active_scope(&mut provider, &scope);
    }
}

#[test]
fn missed_offering_rolls_back_a_ce_lookup_failure_after_promis_then_retries_once() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0808);
    let later_carry = U256::from(7);
    let formed_limit = U256::from(100);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end =
        seed_missed_offering_day(&mut provider, wwd, formed_limit, U256::ZERO, later_carry);
    let parent_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
    let tree = Arc::new(FailOncePartitionLookup {
        parent_root,
        calls: AtomicUsize::new(0),
    });
    let scope = ExecutionScope::with_parent_tree(
        tree.clone(),
        outbe_compressed_entities::CeWorkConfig::new(0, 0, u64::MAX),
    );
    StorageHandle::enter(&mut provider, |storage| {
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(4),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });

    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    let ce_before = scope.ce_work_checkpoint().unwrap();
    let error = run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap_err();
    assert!(matches!(
        error,
        outbe_primitives::error::PrecompileError::TreeUnavailable(_)
    ));
    assert_eq!(tree.calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FORMING);
        assert!(metadosis
            .read_missed_offering_receipt(wwd)
            .unwrap()
            .is_none());
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            later_carry
        );
    });

    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();
    assert_eq!(tree.calls.load(Ordering::SeqCst), 2);
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            later_carry + formed_limit
        );
        assert_eq!(
            metadosis
                .read_missed_offering_receipt(wwd)
                .unwrap()
                .unwrap()
                .retirement,
            outbe_compressed_entities::RetirementOutcome::NotPresent
        );
    });
    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn cycle_command_restores_all_prior_ce_work_when_a_later_wwd_fails() {
    let first = outbe_primitives::time::WorldwideDay::new(2026_0815);
    let second = outbe_primitives::time::WorldwideDay::new(2026_0816);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let first_offering_end = seed_missed_offering_day(
        &mut provider,
        first,
        U256::from(100),
        U256::ZERO,
        U256::ZERO,
    );
    let second_offering_end = seed_missed_offering_day(
        &mut provider,
        second,
        U256::from(200),
        U256::ZERO,
        U256::ZERO,
    );
    let timestamp = first_offering_end.max(second_offering_end);
    let parent_root = outbe_compressed_entities::sealed_root(B256::repeat_byte(0x81)).unwrap();
    let tree = Arc::new(FailSecondPartitionLookup {
        parent_root,
        partition_root: B256::repeat_byte(0x82),
        calls: AtomicUsize::new(0),
    });
    let scope = ExecutionScope::with_parent_tree(
        tree.clone(),
        outbe_compressed_entities::CeWorkConfig::new(0, 0, u64::MAX),
    );
    StorageHandle::enter(&mut provider, |storage| {
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::ZERO,
                U256::from(4),
            )
            .unwrap();
        storage
            .sstore(
                outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    let ordered_before = provider.get_ordered_events().to_vec();
    let ce_before = scope.ce_work_checkpoint().unwrap();

    let error = run_advance_command(&mut provider, &scope, 3, timestamp).unwrap_err();
    assert!(matches!(
        error,
        outbe_primitives::error::PrecompileError::TreeUnavailable(_)
    ));
    assert_eq!(
        tree.calls.load(Ordering::SeqCst),
        2,
        "the first WWD must request retirement before the second lookup fails"
    );
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    assert_eq!(provider.get_ordered_events(), ordered_before.as_slice());
    assert_eq!(
        scope.ce_work_checkpoint().unwrap(),
        ce_before,
        "the command checkpoint must remove the first WWD retirement too"
    );
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_status(first).unwrap(), status::FORMING);
        assert_eq!(metadosis.get_wwd_status(second).unwrap(), status::FORMING);
        assert!(metadosis
            .read_missed_offering_receipt(first)
            .unwrap()
            .is_none());
        assert!(metadosis
            .read_missed_offering_receipt(second)
            .unwrap()
            .is_none());
    });

    run_advance_command(&mut provider, &scope, 3, timestamp).unwrap();
    assert_eq!(tree.calls.load(Ordering::SeqCst), 4);
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(first).unwrap(), status::FAILED);
        assert_eq!(metadosis.get_wwd_status(second).unwrap(), status::FAILED);
        assert_eq!(
            metadosis
                .read_missed_offering_receipt(first)
                .unwrap()
                .unwrap()
                .retirement,
            outbe_compressed_entities::RetirementOutcome::Requested
        );
        assert_eq!(
            metadosis
                .read_missed_offering_receipt(second)
                .unwrap()
                .unwrap()
                .retirement,
            outbe_compressed_entities::RetirementOutcome::Requested
        );
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(300)
        );
    });
}

#[test]
fn absent_profile_rejects_the_offering_edge_before_any_effect() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0803);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_entry = StorageHandle::enter(&mut provider, |storage| {
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
        TributeContract::new(storage).seal_day(wwd).unwrap();
        metadosis
            .worldwide_days
            .entry(wwd)
            .lookback_end()
            .read()
            .unwrap()
    });
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);
    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    let ce_before = scope.ce_work_checkpoint().unwrap();

    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    let error = StorageHandle::enter(&mut provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(2, offering_entry, CHAIN_ID),
            storage,
        );
        crate::commands::advance_active_worldwide_days(&ctx, &scope)
    })
    .unwrap_err();
    assert!(matches!(
        error,
        outbe_primitives::error::PrecompileError::Fatal(_)
    ));
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);
    StorageHandle::enter(&mut provider, |storage| {
        assert_eq!(
            MetadosisContract::new(storage).get_wwd_status(wwd).unwrap(),
            status::FORMING
        );
    });
    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn absent_profile_rejects_populated_ready_before_failed_state_or_lysis_effects() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0804);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let scheduled = StorageHandle::enter(&mut provider, |storage| {
        let scheduled = create_waiting_day(&storage, wwd, day_type::GREEN, U256::from(1_000));
        MetadosisContract::new(storage)
            .fixture_set_wwd_status(wwd, WwdStatus::Ready)
            .unwrap();
        scheduled
    });
    let (scope, parent) = begin_persistent_active_scope(&mut provider);
    StorageHandle::enter(&mut provider, |storage| {
        issue_one_tribute_in_scope(
            &storage,
            &scope,
            &parent,
            address!("7700000000000000000000000000000000000077"),
            wwd,
            U256::from(10),
        );
    });
    let storage_before = provider.storage.clone();
    let events_before = provider.events.clone();
    let ce_before = scope.ce_work_checkpoint().unwrap();

    provider.enable_metadosis_mutation_frame(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
    );
    let error = StorageHandle::enter(&mut provider, |storage| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(2, scheduled, CHAIN_ID),
            storage,
        );
        crate::commands::start_metadosis(&ctx, &scope, &parent)
    })
    .unwrap_err();
    assert!(matches!(
        error,
        outbe_primitives::error::PrecompileError::Fatal(_)
    ));
    assert_eq!(provider.storage, storage_before);
    assert_eq!(provider.events, events_before);
    assert_eq!(scope.ce_work_checkpoint().unwrap(), ce_before);
    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::READY);
        assert_no_ocomp_job(&storage, wwd);
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        assert_eq!(TributeContract::new(storage).total_supply().unwrap(), 1);
    });
    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn test_cold_start_creates_only_current_utc_plus_14_day() {
    with_storage(|storage| {
        let timestamp = outbe_primitives::time::WorldwideDay::new(20260302).start_timestamp()
            + 2 * SECONDS_PER_HOUR;
        run_begin_block(storage.clone(), 1, timestamp);

        let metadosis = MetadosisContract::new(storage.clone());
        let active = metadosis.active_wwd.read_all().unwrap();
        assert_eq!(active, vec![20260302u32.into()]);
        assert_eq!(
            metadosis.get_bootstrap_end_time().unwrap(),
            timestamp + BOOTSTRAP_DURATION_HOURS * SECONDS_PER_HOUR
        );

        let tribute = TributeContract::new(storage);
        assert!(tribute.is_day_sealed(20260302u32.into()).unwrap());
    });
}

#[test]
fn genesis_day_uses_the_canonical_utc_plus_14_boundary() {
    let utc_midnight = crate::runtime::date_key_to_timestamp(20260302);

    for (timestamp, expected) in [
        (utc_midnight + 9 * SECONDS_PER_HOUR + 59 * 60, 20260302),
        (utc_midnight + 10 * SECONDS_PER_HOUR, 20260303),
    ] {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        seed_genesis_profile(&mut provider);
        run_init_genesis_command(&mut provider, 1, timestamp).unwrap();

        let created = assert_genesis_created_once(&mut provider, timestamp);
        assert_eq!(created, outbe_primitives::time::WorldwideDay::new(expected));
        let constants = outbe_chain_constants::GenesisProtocolParametersV1::default();
        StorageHandle::enter(&mut provider, |storage| {
            let metadosis = MetadosisContract::new(storage);
            let day = metadosis.worldwide_days.entry(created);
            let forming_start = created.start_timestamp();
            let forming_end = forming_start + constants.metadosis_forming_period_seconds;
            let lookback_end = forming_end + constants.metadosis_lookback_delay_seconds;
            let offering_end = lookback_end + constants.metadosis_offering_period_seconds;
            assert_eq!(day.forming_start().read().unwrap(), forming_start);
            assert_eq!(day.forming_end().read().unwrap(), forming_end);
            assert_eq!(day.lookback_end().read().unwrap(), lookback_end);
            assert_eq!(day.offering_end().read().unwrap(), offering_end);
            assert_eq!(
                day.scheduled_process_time().read().unwrap(),
                offering_end + constants.metadosis_waiting_period_seconds
            );
        });
    }
}

#[test]
fn test_cold_start_uses_genesis_default_schedule_independent_of_chain_id() {
    with_storage(|storage| {
        let timestamp = outbe_primitives::time::WorldwideDay::new(20260302).start_timestamp()
            + 2 * SECONDS_PER_HOUR;
        run_begin_block_with_chain_id(storage.clone(), 1, timestamp, CHAIN_ID);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(
            metadosis.get_bootstrap_end_time().unwrap(),
            timestamp + BOOTSTRAP_DURATION_HOURS * SECONDS_PER_HOUR
        );

        let active = metadosis.active_wwd.read_all().unwrap();
        assert_eq!(active, vec![20260302u32.into()]);

        let wwd = 20260302u32;
        let forming_start = outbe_primitives::time::WorldwideDay::new(wwd).start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let expected_lookback_end = forming_end + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;
        let expected_offering_end =
            expected_lookback_end + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR;

        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd.into())
                .lookback_end()
                .read()
                .unwrap(),
            expected_lookback_end
        );
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd.into())
                .offering_end()
                .read()
                .unwrap(),
            expected_offering_end
        );
    });
}

#[test]
fn test_offering_entry_captures_vwap_unblocks_and_exit_reblocks() {
    with_storage(|storage| {
        let wwd_raw = 20260302u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let previous_wwd = wwd.previous_date_key();
        let forming_start = wwd.start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let previous_forming_start = previous_wwd.start_timestamp();
        let previous_forming_end = previous_forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let offering_entry = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;
        let offering_end = offering_entry + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();

        let mut tribute = TributeContract::new(storage.clone());
        tribute.seal_day(wwd).unwrap();

        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let pair = outbe_oracle::api::DAY_TYPE_PAIR;
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .write_snapshot(
                previous_forming_start + SECONDS_PER_HOUR,
                &[(pair, U256::from(100u64), U256::from(1u64))],
            )
            .unwrap();
        oracle
            .write_snapshot(
                forming_start + 30 * SECONDS_PER_HOUR,
                &[(pair, U256::from(110u64), U256::from(1u64))],
            )
            .unwrap();
        oracle
            .store_worldwide_day_vwap_snapshot(
                previous_wwd,
                previous_forming_start,
                previous_forming_end,
            )
            .unwrap();

        run_begin_block(storage.clone(), 2, forming_end);

        let oracle = OracleContract::new(storage.clone());
        let (_, _, bases, quotes, vwaps, _) = oracle.get_worldwide_day_vwap_snapshot(wwd).unwrap();
        assert_eq!(bases, vec![outbe_oracle::api::COEN_ASSET]);
        assert_eq!(quotes, vec![outbe_oracle::api::currency_address(840)]);
        assert_eq!(vwaps, vec![U256::from(110u64)]);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(
            metadosis.get_wwd_status(wwd).unwrap(),
            status::LOOKBACK_DELAY
        );
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .previous_vwap()
                .read()
                .unwrap(),
            U256::from(100u64)
        );
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .current_vwap()
                .read()
                .unwrap(),
            U256::from(110u64)
        );
        assert_eq!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::GREEN);

        run_begin_block(storage.clone(), 3, offering_entry);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::OFFERING);
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .previous_vwap()
                .read()
                .unwrap(),
            U256::from(100u64)
        );
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .current_vwap()
                .read()
                .unwrap(),
            U256::from(110u64)
        );
        assert_eq!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::GREEN);

        let tribute = TributeContract::new(storage.clone());
        assert!(!tribute.is_day_sealed(wwd).unwrap());

        run_begin_block(storage.clone(), 4, offering_end);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::WAITING);
        let tribute = TributeContract::new(storage);
        assert!(tribute.is_day_sealed(wwd).unwrap());
    });
}

/// `advance_active_worldwide_days` (the 12:00 UTC `wwd_advance_noon` Cycle
/// trigger handler) must walk the status machine forward exactly like the
/// midnight path - including the FORMING->OFFERING side effects (tribute day
/// unseal) - but must NOT create a new worldwide day and must NOT settle a
/// READY one; day creation and settlement stay midnight-owned in
/// `start_metadosis`.
#[test]
fn advance_active_worldwide_days_advances_status_without_creating_or_settling() {
    with_storage(|storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let wwd = outbe_primitives::time::WorldwideDay::new(20260302u32);
        let forming_start = wwd.start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let offering_entry = forming_end + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;
        let offering_end = offering_entry + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let scheduled = offering_end + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        drop(metadosis);

        let mut tribute = TributeContract::new(storage.clone());
        tribute.seal_day(wwd).unwrap();
        drop(tribute);

        let advance = |block_number: u64, timestamp: u64| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(block_number, timestamp, CHAIN_ID),
                storage.clone(),
            );
            let scope = ExecutionScope::new();
            crate::commands::advance_active_worldwide_days(&ctx, &scope).unwrap();
        };

        // At the offering-entry edge the day opens and the tribute day
        // unseals - offers stop reverting `not in OFFERING status`.
        advance(2, offering_entry);
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::OFFERING);
        let tribute = TributeContract::new(storage.clone());
        assert!(!tribute.is_day_sealed(wwd).unwrap());

        // Advancing did not create any other worldwide day.
        let active = metadosis.active_wwd.read_all().unwrap();
        assert_eq!(active, vec![wwd], "advance must not create worldwide days");
        drop(metadosis);

        // Past scheduled-process time the walk parks the day at READY and
        // leaves it active: settlement belongs to `start_metadosis` only.
        advance(3, scheduled);
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::READY);
        assert_eq!(
            metadosis.active_wwd.read_all().unwrap(),
            vec![wwd],
            "advance must not settle or retire a READY day"
        );
    });
}

#[test]
fn test_missing_previous_vwap_results_in_red_day() {
    with_storage(|storage| {
        let wwd_raw = 20260303u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let forming_start = wwd.start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let offering_entry = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();

        let mut tribute = TributeContract::new(storage.clone());
        tribute.seal_day(wwd).unwrap();

        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let pair = outbe_oracle::api::DAY_TYPE_PAIR;
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .write_snapshot(
                forming_start + 30 * SECONDS_PER_HOUR,
                &[(pair, U256::from(110u64), U256::from(1u64))],
            )
            .unwrap();

        run_begin_block(storage.clone(), 2, forming_end);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(
            metadosis.get_wwd_status(wwd).unwrap(),
            status::LOOKBACK_DELAY
        );
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .previous_vwap()
                .read()
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(wwd)
                .current_vwap()
                .read()
                .unwrap(),
            U256::from(110u64)
        );
        assert_eq!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::RED);

        run_begin_block(storage.clone(), 3, offering_entry);

        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::RED);
    });
}

#[test]
fn test_equal_vwap_results_in_red_day() {
    with_storage(|storage| {
        let wwd_raw = 20260303u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let previous_wwd = wwd.previous_date_key();
        let forming_start = wwd.start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let previous_forming_start = previous_wwd.start_timestamp();
        let previous_forming_end = previous_forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let offering_entry = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();

        let mut tribute = TributeContract::new(storage.clone());
        tribute.seal_day(wwd).unwrap();

        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let pair = outbe_oracle::api::DAY_TYPE_PAIR;
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .write_snapshot(
                previous_forming_start + SECONDS_PER_HOUR,
                &[(pair, U256::from(100u64), U256::from(1u64))],
            )
            .unwrap();
        oracle
            .write_snapshot(
                forming_start + 30 * SECONDS_PER_HOUR,
                &[(pair, U256::from(100u64), U256::from(1u64))],
            )
            .unwrap();
        oracle
            .store_worldwide_day_vwap_snapshot(
                previous_wwd,
                previous_forming_start,
                previous_forming_end,
            )
            .unwrap();

        run_begin_block(storage.clone(), 2, forming_end);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(
            metadosis.get_wwd_status(wwd).unwrap(),
            status::LOOKBACK_DELAY
        );
        assert_eq!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::RED);

        run_begin_block(storage.clone(), 3, offering_entry);

        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::RED);
    });
}

#[test]
fn test_normal_lifecycle_never_leaves_ready_day_type_unknown() {
    with_storage(|storage| {
        let wwd_raw = 20260304u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let previous_wwd = wwd.previous_date_key();
        let forming_start = wwd.start_timestamp();
        let forming_end = forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let previous_forming_start = previous_wwd.start_timestamp();
        let previous_forming_end = previous_forming_start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let offering_entry = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR;
        let scheduled = offering_entry
            + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
            + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();

        let mut tribute = TributeContract::new(storage.clone());
        tribute.seal_day(wwd).unwrap();

        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let pair = outbe_oracle::api::DAY_TYPE_PAIR;
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .write_snapshot(
                previous_forming_start + SECONDS_PER_HOUR,
                &[(pair, U256::from(100u64), U256::from(1u64))],
            )
            .unwrap();
        oracle
            .write_snapshot(
                forming_start + SECONDS_PER_HOUR,
                &[(pair, U256::from(120u64), U256::from(1u64))],
            )
            .unwrap();
        oracle
            .store_worldwide_day_vwap_snapshot(
                previous_wwd,
                previous_forming_start,
                previous_forming_end,
            )
            .unwrap();

        run_begin_block(storage.clone(), 2, forming_end);
        run_begin_block(storage.clone(), 3, offering_entry);
        run_begin_block(storage.clone(), 4, scheduled);

        let metadosis = MetadosisContract::new(storage);
        assert_ne!(metadosis.get_wwd_day_type(wwd).unwrap(), day_type::UNKNOWN);
    });
}

#[test]
fn test_ready_processing_missing_limit_fails_like_source() {
    with_storage(|storage| {
        let wwd_raw = 20260310u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let forming_start = wwd.start_timestamp();
        let scheduled = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
            + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
            + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis.set_wwd_day_type(wwd, WwdDayType::Red).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
    });
}

#[test]
fn test_ready_processing_unknown_day_type_fails_and_returns_limit_to_promis() {
    with_storage(|storage| {
        let wwd_raw = 20260310u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let day_limit = U256::from(333u64);
        let forming_start = wwd.start_timestamp();
        let scheduled = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
            + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
            + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();
        metadosis.set_metadosis_limit(wwd, day_limit).unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);

        let promis = PromisLimitContract::new(storage);
        assert_eq!(promis.get_total_unallocated().unwrap(), day_limit);
    });
}

#[test]
fn test_ready_processing_zero_limit_fails() {
    with_storage(|storage| {
        let wwd_raw = 20260311u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let forming_start = wwd.start_timestamp();
        let scheduled = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
            + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
            + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis.set_wwd_day_type(wwd, WwdDayType::Red).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();
        metadosis.set_metadosis_limit(wwd, U256::ZERO).unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage);
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
    });
}

#[test]
fn test_ready_processing_no_tributes_returns_the_limit_to_promis() {
    with_storage(|storage| {
        let wwd_raw = 20260312u32;
        let wwd = outbe_primitives::time::WorldwideDay::new(wwd_raw);
        let day_limit = U256::from(777u64);
        let forming_start = wwd.start_timestamp();
        let scheduled = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
            + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
            + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis.set_wwd_day_type(wwd, WwdDayType::Red).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();
        metadosis.set_metadosis_limit(wwd, day_limit).unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::COMPLETED);

        // A red day is recorded as a supply-less brief; a day with no tributes issues nothing,
        // so its whole limit goes back to the warehouse.
        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::Briefed as u8
        );
        assert_eq!(desis.brief_green.read(&series).unwrap(), 0);
        assert_eq!(
            desis.pending_supply_promis.read(&series).unwrap(),
            U256::ZERO
        );

        let promis = PromisLimitContract::new(storage);
        assert_eq!(promis.get_total_unallocated().unwrap(), day_limit);
    });
}

#[test]
fn active_ocomp_profile_discovers_later_ready_day_after_first_was_indexed() {
    with_storage(|storage| {
        let first_wwd = outbe_primitives::time::WorldwideDay::new(2026_0316);
        let second_wwd = outbe_primitives::time::WorldwideDay::new(2026_0317);
        let nominal = U256::from(1_000);
        let first_scheduled =
            create_waiting_day(&storage, first_wwd, day_type::GREEN, U256::from(800));
        let second_scheduled =
            create_waiting_day(&storage, second_wwd, day_type::GREEN, U256::from(900));
        let timestamp = first_scheduled.max(second_scheduled) + SECONDS_PER_HOUR;
        arm_genesis_ocomp(&storage, CHAIN_ID);

        with_active_scope(storage.clone(), |scope, parent| {
            issue_one_tribute_in_scope(
                &storage,
                scope,
                parent,
                address!("7400000000000000000000000000000000000074"),
                first_wwd,
                nominal,
            );
            issue_one_tribute_in_scope(
                &storage,
                scope,
                parent,
                address!("7500000000000000000000000000000000000075"),
                second_wwd,
                nominal,
            );

            let first_ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(10, timestamp, CHAIN_ID),
                storage.clone(),
            );
            crate::commands::start_metadosis(&first_ctx, scope, parent).unwrap();

            let after_first = MetadosisContract::new(storage.clone());
            assert!(!after_first
                .ocomp_fsm_states
                .get_bytes(&first_wwd)
                .is_empty()
                .unwrap());
            assert!(after_first
                .ocomp_fsm_states
                .get_bytes(&second_wwd)
                .is_empty()
                .unwrap());

            let second_ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(11, timestamp + 1, CHAIN_ID),
                storage.clone(),
            );
            crate::commands::start_metadosis(&second_ctx, scope, parent).unwrap();
        });

        let metadosis = MetadosisContract::new(storage);
        let schema_limits = crate::ocomp::schema::poc_schema_limits();
        let first = metadosis
            .ocomp_fsm_state(first_wwd, &schema_limits)
            .unwrap()
            .projection();
        let second = metadosis
            .ocomp_fsm_state(second_wwd, &schema_limits)
            .unwrap()
            .projection();
        assert_eq!(first.phase, crate::ocomp::state::DayPhase::Ready);
        assert_eq!(first.next_check_height, Some(10));
        assert_eq!(second.phase, crate::ocomp::state::DayPhase::Ready);
        assert_eq!(second.next_check_height, Some(11));
        assert!(metadosis.ocomp_scheduler.is_empty().unwrap());
    });
}

// Stable historical ID retained after moving this invariant out of the
// four-node E2E lane.
// OCOMP-TEST-ID: OCM-E2E-002
#[test]
fn active_ocomp_profile_preserves_the_empty_day_compatibility_branch() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0313);
        let day_limit = U256::from(777);
        let scheduled = create_waiting_day(&storage, wwd, day_type::RED, day_limit);
        arm_genesis_ocomp(&storage, CHAIN_ID);

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::COMPLETED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        assert_no_ocomp_job(&storage, wwd);

        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::Briefed as u8
        );
        assert_eq!(desis.brief_green.read(&series).unwrap(), 0);
        assert_eq!(
            desis.pending_supply_promis.read(&series).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            day_limit
        );
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        assert_eq!(
            TributeContract::new(storage)
                .get_day_totals(wwd)
                .unwrap()
                .tribute_count,
            0
        );
    });
}

#[test]
fn green_empty_day_briefs_no_supply_however_large_the_limit() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    StorageHandle::enter(&mut provider, |storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0321);
        let scheduled = create_waiting_day(&storage, wwd, day_type::GREEN, U256::MAX);
        arm_genesis_ocomp(&storage, CHAIN_ID);

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), WwdStatus::Completed);
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            outbe_desis::AuctionStage::from_u8(desis.auction_stage.read(&wwd).unwrap()).unwrap(),
            outbe_desis::AuctionStage::Briefed
        );
        assert_eq!(desis.brief_green.read(&wwd).unwrap(), 0);
        assert_eq!(desis.pending_supply_promis.read(&wwd).unwrap(), U256::ZERO);
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::MAX
        );
    });
}

#[test]
fn technical_desis_refusal_rolls_back_the_metadosis_cycle_command() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0322);
        let day_limit = U256::from(777_u64);
        let scheduled = create_waiting_day(&storage, wwd, day_type::GREEN, day_limit);
        arm_genesis_ocomp(&storage, CHAIN_ID);
        assert_eq!(
            outbe_desis::api::dispatch_auction_brief(
                storage.clone(),
                wwd,
                U256::from(1_u8),
                vec![outbe_desis::ReferenceCurrencyPrice {
                    iso_code: 840,
                    entry_price_minor: U256::from(1_u8),
                }],
                true,
                scheduled,
                outbe_desis::api::BriefOverflowPolicy::CarryOver,
            )
            .unwrap(),
            outbe_desis::api::AuctionBriefReceipt::Accepted
        );

        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(2, scheduled + SECONDS_PER_HOUR, CHAIN_ID),
            storage.clone(),
        );
        with_active_scope(storage.clone(), |scope, parent| {
            assert!(crate::commands::start_metadosis(&ctx, scope, parent).is_err());
        });

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), WwdStatus::Waiting);
        assert!(metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(!metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            U256::ZERO
        );
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.pending_supply_promis.read(&wwd).unwrap(),
            U256::from(1_u8)
        );
        assert_eq!(desis.sched_active_count.read().unwrap(), 1);
    });
}

#[test]
fn active_ocomp_profile_preserves_the_populated_zero_limit_branch() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0314);
        let nominal = U256::from(1_000);
        let scheduled = create_waiting_day(&storage, wwd, day_type::GREEN, U256::ZERO);
        arm_genesis_ocomp(&storage, CHAIN_ID);

        issue_one_tribute_and_run_metadosis(
            &storage,
            wwd,
            nominal,
            2,
            scheduled + SECONDS_PER_HOUR,
        );

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        assert_no_ocomp_job(&storage, wwd);

        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );
        assert_eq!(desis.clearing_initiated.read(&series).unwrap(), 0);
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        let tribute = TributeContract::new(storage);
        assert_eq!(tribute.total_supply().unwrap(), 1);
        let totals = tribute.get_day_totals(wwd).unwrap();
        assert_eq!(totals.tribute_count, 1);
        assert_eq!(totals.tribute_nominal_amount, nominal);
    });
}

#[test]
fn active_ocomp_profile_preserves_the_populated_zero_lysis_budget_branch() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0318);
        let nominal = U256::from(1_000);
        // A red day divides supply by RED_DAY_REDUCTION_COEF. This non-zero
        // day limit therefore produces an exact zero Lysis allocation.
        let day_limit = U256::from(2);
        let scheduled = create_waiting_day(&storage, wwd, day_type::RED, day_limit);
        arm_genesis_ocomp(&storage, CHAIN_ID);

        let tribute = TributeContract::new(storage.clone());
        tribute.total_supply.write(1).unwrap();
        let mut totals = outbe_tribute::schema::DayTotals::with_key(wwd);
        totals.initialized = true;
        totals.is_sealed = true;
        totals.tribute_count = 1;
        totals.tribute_nominal_amount = nominal;
        tribute.day_totals.create(&totals).unwrap();
        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::COMPLETED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        assert_no_ocomp_job(&storage, wwd);

        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::Briefed as u8
        );
        assert_eq!(desis.brief_green.read(&series).unwrap(), 0);
        assert_eq!(
            desis.pending_supply_promis.read(&series).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            day_limit
        );
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        let tribute = TributeContract::new(storage);
        assert_eq!(tribute.total_supply().unwrap(), 1);
        let totals = tribute.get_day_totals(wwd).unwrap();
        assert_eq!(totals.tribute_count, 1);
        assert_eq!(totals.tribute_nominal_amount, nominal);
    });
}

#[test]
fn active_ocomp_profile_preserves_the_populated_unknown_day_branch() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0315);
        let nominal = U256::from(1_000);
        let day_limit = U256::from(333);
        let scheduled = create_waiting_day(&storage, wwd, day_type::UNKNOWN, day_limit);
        arm_genesis_ocomp(&storage, CHAIN_ID);

        issue_one_tribute_and_run_metadosis(
            &storage,
            wwd,
            nominal,
            2,
            scheduled + SECONDS_PER_HOUR,
        );

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        assert_no_ocomp_job(&storage, wwd);

        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );
        assert_eq!(desis.clearing_initiated.read(&series).unwrap(), 0);
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            day_limit
        );
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        let tribute = TributeContract::new(storage);
        assert_eq!(tribute.total_supply().unwrap(), 1);
        let totals = tribute.get_day_totals(wwd).unwrap();
        assert_eq!(totals.tribute_count, 1);
        assert_eq!(totals.tribute_nominal_amount, nominal);
    });
}

#[test]
fn populated_positive_gratis_day_enqueues_ocomp_without_synchronous_lysis() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0313);
        let day_limit = U256::from(5_000u64) * U256::from(10u64).pow(U256::from(18u64));
        let nominal = U256::from(1_000u64) * U256::from(10u64).pow(U256::from(18u64));
        let owner = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let scheduled = create_waiting_day(&storage, wwd, day_type::GREEN, day_limit);
        arm_genesis_ocomp(&storage, CHAIN_ID);

        with_active_scope(storage.clone(), |scope, parent| {
            issue_one_tribute_in_scope(&storage, scope, parent, owner, wwd, nominal);

            // This collides with the NOD the removed synchronous Lysis path
            // would have attempted to issue. OCOMP admission must not touch it.
            outbe_nodfactory::api::issue_nod(
                &storage,
                scope,
                parent,
                &outbe_nod::NodIssueParams {
                    owner,
                    gratis_load_minor: U256::from(1),
                    worldwide_day: wwd,
                    league_id: 1,
                    floor_price_minor: U256::from(1),
                    entry_price_minor: U256::from(1),
                    issuance_currency: 840,
                    reference_currency: 840,
                },
            )
            .unwrap();

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(
                    2,
                    scheduled + SECONDS_PER_HOUR,
                    outbe_primitives::chain::CHAIN_ID,
                ),
                storage.clone(),
            );
            crate::commands::start_metadosis(&ctx, scope, parent).unwrap();
        });

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::READY);
        assert!(metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(!metadosis.closed_wwd.read_all().unwrap().contains(&wwd));
        let limits = crate::ocomp::schema::poc_schema_limits();
        let _profile = metadosis
            .read_ocomp_request_profile(&limits)
            .unwrap()
            .unwrap();
        let fsm = metadosis
            .ocomp_fsm_state(wwd, &limits)
            .unwrap()
            .projection();
        assert_eq!(fsm.phase, crate::ocomp::state::DayPhase::Ready);
        assert_eq!(fsm.next_check_height, Some(2));
        assert!(
            metadosis
                .ocomp_pre_admission_projection(wwd)
                .unwrap()
                .initialized
        );
        let tribute = TributeContract::new(storage.clone());
        assert_eq!(tribute.total_supply().unwrap(), 1);
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 1);
        let promis = PromisLimitContract::new(storage);
        assert_eq!(promis.get_total_unallocated().unwrap(), U256::ZERO);
    });
}

#[test]
fn no_tributes_green_day_briefs_no_supply_and_returns_the_limit() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(20260401u32);
        let day_limit = U256::from(10u64).pow(U256::from(26u64));
        let forming_start = wwd.start_timestamp();

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis.set_wwd_day_type(wwd, WwdDayType::Green).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();
        metadosis.set_metadosis_limit(wwd, day_limit).unwrap();

        let scheduled = metadosis
            .worldwide_days
            .entry(wwd)
            .scheduled_process_time()
            .read()
            .unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::COMPLETED);

        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::Briefed as u8
        );
        assert_eq!(desis.brief_green.read(&series).unwrap(), 0);
        assert_eq!(
            desis.pending_supply_promis.read(&series).unwrap(),
            U256::ZERO
        );

        let promis = PromisLimitContract::new(storage);
        assert_eq!(
            promis.get_total_unallocated().unwrap(),
            day_limit,
            "a day that earned nothing auctions nothing and leaves its limit on the warehouse"
        );
    });
}

#[test]
fn zero_limit_green_day_dispatches_no_brief() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(20260501u32);
        let forming_start = wwd.start_timestamp();

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis.set_wwd_day_type(wwd, WwdDayType::Green).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();

        let scheduled = metadosis
            .worldwide_days
            .entry(wwd)
            .scheduled_process_time()
            .read()
            .unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);

        let series = wwd;
        let desis = storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&series).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );
        assert_eq!(desis.clearing_initiated.read(&series).unwrap(), 0);
    });
}

#[test]
fn test_events_emitted_for_accumulation_and_lifecycle() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enable_metadosis_mutation_frames(
        outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
        2,
    );
    outbe_fidelity::enclave_client::test_enclave::install();
    let contract_addr = outbe_primitives::addresses::METADOSIS_ADDRESS;

    StorageHandle::enter(&mut storage, |storage| {
        arm_genesis_ocomp(&storage, CHAIN_ID);
        let timestamp = outbe_primitives::time::WorldwideDay::new(20260302).start_timestamp()
            + 2 * SECONDS_PER_HOUR;
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(1, timestamp, outbe_primitives::chain::CHAIN_ID),
            storage.clone(),
        );
        crate::emission_sink::apply(&ctx, U256::from(10u64)).unwrap();
        with_active_scope(storage, |scope, parent| {
            crate::commands::start_metadosis(&ctx, scope, parent)
        })
        .unwrap();
    });

    let events = storage.get_events(contract_addr);
    assert!(
        events.len() >= 2,
        "expected accumulation + lifecycle events"
    );
}

#[test]
fn test_terminal_day_leaves_active_set() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(20260315u32);
        let forming_start = wwd.start_timestamp();
        let scheduled = forming_start
            + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR
            + LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
            + OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
            + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(
                wwd,
                forming_start,
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            )
            .unwrap();
        metadosis.add_active_wwd(wwd).unwrap();
        metadosis.set_wwd_day_type(wwd, WwdDayType::Red).unwrap();
        metadosis
            .fixture_set_wwd_status(wwd, WwdStatus::Waiting)
            .unwrap();
        metadosis
            .set_metadosis_limit(wwd, U256::from(777u64))
            .unwrap();

        run_begin_block(storage.clone(), 2, scheduled + SECONDS_PER_HOUR);

        let metadosis = MetadosisContract::new(storage);
        // The day completed and was retired out of the active set into the
        // bounded delete-queue, but stays readable while under the cap.
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::COMPLETED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        assert!(metadosis
            .get_active_wwd_by_status(WwdStatus::Completed)
            .unwrap()
            .contains(&wwd));
    });
}

#[test]
fn the_local_brief_prices_a_day_by_the_canonical_projection() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(2026_0805);
        let scheduled = create_waiting_day(&storage, wwd, day_type::GREEN, U256::from(1_000_u64));
        arm_genesis_ocomp(&storage, CHAIN_ID);

        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(2, scheduled + SECONDS_PER_HOUR, CHAIN_ID),
            storage.clone(),
        );
        let mut metadosis = MetadosisContract::new(storage.clone());

        // A cold oracle prices nothing, and the empty table is load-bearing: it
        // is how Desis is told the day is unpriced, so it cancels the auction and
        // refunds the supply instead of opening one at a zero entry price.
        assert!(
            crate::settlement::day_entry_prices(&mut metadosis, &ctx, wwd)
                .unwrap()
                .is_empty()
        );

        // The COEN/USD pair is not registered here, so the rule the settlement
        // path used to carry of its own - which resolved every row through
        // `require_coen_pair` - could never price this day at all.
        assert!(outbe_oracle::api::require_coen_pair(storage.clone(), 840).is_err());

        // The day carries a WorldwideDay VWAP of its own and it is still not an
        // entry price: an auction is priced from the last closed UTC day alone.
        metadosis.set_wwd_vwap(wwd, U256::from(110_u64)).unwrap();
        let table = crate::settlement::day_entry_prices(&mut metadosis, &ctx, wwd).unwrap();
        assert!(table.is_empty());

        let projection =
            outbe_oracle::api::ocomp_pre_admission_projection(storage.clone(), ctx.block.timestamp)
                .unwrap();

        // One rule prices every day: the settlement table is the projection's,
        // less rows the oracle could not put a price on.
        assert_eq!(
            table
                .iter()
                .map(|row| (row.iso_code, row.entry_price_minor))
                .collect::<Vec<_>>(),
            projection
                .auction_entry_prices
                .iter()
                .filter(|row| !row.entry_price_minor.is_zero())
                .map(|row| (row.reference_currency, row.entry_price_minor))
                .collect::<Vec<_>>()
        );
    });
}

#[test]
fn missed_offering_terminalizes_a_day_that_never_formed_its_limit() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0803);
    let carry_over = U256::from(11);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end = seed_unformed_missed_offering_day(&mut provider, wwd, carry_over);
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);

    run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap();

    StorageHandle::enter(&mut provider, |storage| {
        let metadosis = MetadosisContract::new(storage.clone());
        assert_eq!(metadosis.get_wwd_status(wwd).unwrap(), status::FAILED);
        assert!(!metadosis.active_wwd.read_all().unwrap().contains(&wwd));
        let receipt = metadosis
            .read_missed_offering_receipt(wwd)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.value_routed, U256::ZERO);
        assert_eq!(receipt.carry_over_before, carry_over);
        assert_eq!(receipt.carry_over_after, carry_over);
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            carry_over
        );
    });

    end_persistent_active_scope(&mut provider, &scope);
}

#[test]
fn missed_offering_rejects_a_day_limit_with_no_formation() {
    let wwd = outbe_primitives::time::WorldwideDay::new(2026_0804);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let offering_end = seed_unformed_missed_offering_day(&mut provider, wwd, U256::ZERO);
    StorageHandle::enter(&mut provider, |storage| {
        MetadosisContract::new(storage)
            .worldwide_days
            .entry(wwd)
            .metadosis_limit_amount()
            .write(U256::from(5))
            .unwrap();
    });
    let (scope, _parent) = begin_persistent_active_scope(&mut provider);

    let error = run_missed_offering_command(&mut provider, &scope, 2, offering_end).unwrap_err();
    assert!(
        format!("{error:?}").contains("has a day limit with no formation"),
        "unexpected error: {error:?}"
    );

    end_persistent_active_scope(&mut provider, &scope);
}
