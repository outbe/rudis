//! Cycle dispatcher tests.
//!
//! `next_fire_at` is asserted in `schedule_math_*`. Integration tests
//! exercise the dispatcher loop against the `HashMapStorageProvider`
//! so they cover the storage round-trip (`Cycle.last_executed_at`)
//! and the genesis-anchor interaction with Rewards.
//!
//! The dispatcher uses a lazy first-encounter anchor: on the very
//! first block it sees a trigger, it writes
//! `last_executed_at = block_ts` instead of firing. This anchors the
//! schedule at the chain's deployment instant so the first real fire
//! happens at the *next* slot strictly after that anchor. Without
//! this, every chain would fire its daily trigger on block 1 because
//! `block_ts >> 86_400` is always true on a real chain.

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    CompressedEntitiesLifecycle, CompressedEntitiesLifecycleContext, ExecutionScope,
};
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
use outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockLifecycle, BlockRuntimeContext};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::{MetadosisMutationPurposeTag, StorageHandle};
use outbe_tribute::TributeRepositoryReader;
use outbe_validatorset::contract::ValidatorSet;
use std::sync::Arc;

use crate::lifecycle::{CycleLifecycle, CycleLifecycleContext};
use crate::schema::Cycle;
use crate::triggers::{next_fire_at, TriggerId, ACTIVE_TRIGGERS};

mod model;

const CHAIN_ID: u64 = 1;
/// Genesis at midnight UTC of 2024-01-01.
const GENESIS_TS: u64 = 1_704_067_200;
const SECONDS_PER_DAY: u64 = 86_400;
const EMISSION_LIMIT_1_ID: u32 = TriggerId::ProtocolCycle.as_u32();

fn retained_days_before(
    victim: outbe_primitives::time::WorldwideDay,
    count: usize,
) -> Vec<outbe_primitives::time::WorldwideDay> {
    (0..count)
        .map(|offset| {
            let days_before = count - offset;
            let seconds_before = u64::try_from(days_before)
                .unwrap()
                .checked_mul(SECONDS_PER_DAY)
                .unwrap();
            outbe_primitives::time::WorldwideDay::from_timestamp(
                victim
                    .start_timestamp()
                    .checked_sub(seconds_before)
                    .unwrap(),
            )
        })
        .collect()
}

fn cycle_storage() -> HashMapStorageProvider {
    cycle_storage_for(CHAIN_ID)
}

fn cycle_storage_for(chain_id: u64) -> HashMapStorageProvider {
    let genesis_hash = B256::repeat_byte(0x11);
    let mut storage = HashMapStorageProvider::new_with_chain_identity(chain_id, genesis_hash);
    storage.set_block_number(1);
    storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::ForkProfile);
    let install = outbe_metadosis::test_support::ForkInstallScenario::measurement_at(
        1,
        chain_id,
        genesis_hash,
    )
    .unwrap()
    .into_install();
    StorageHandle::enter(&mut storage, |handle| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(1, GENESIS_TS, chain_id),
            handle,
        );
        ctx.storage
            .contract::<Cycle<'_>>()
            .active_utc_day
            .write(20_240_101)
            .unwrap();
        let owner = Address::repeat_byte(0xA0);
        let founder = Address::repeat_byte(0xB0);
        let consensus_key = [0x30; 48];
        let mut validators = ValidatorSet::new(ctx.storage.clone());
        validators.config_owner.write(owner).unwrap();
        validators.set_config_max_validators(1).unwrap();
        validators
            .register_validator(owner, founder, &consensus_key)
            .unwrap();
        validators.mark_pending(founder).unwrap();
        let registration = install.founder_registrations[0]
            .encode_canonical(&outbe_metadosis::config::poc_schema_limits())
            .unwrap();
        validators
            .confirm_validator_ready(founder, &registration)
            .unwrap();
        validators
            .activate_validator_via_boundary_for_test(founder)
            .unwrap();
        outbe_oracle::api::register_pair(ctx.storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        outbe_metadosis::commands::install_fork_profile(&ctx, &install).unwrap();
    });
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 4);
    storage
}

fn block_ctx(block_number: u64, timestamp: u64) -> BlockContext {
    BlockContext::new(block_number, timestamp, CHAIN_ID, Address::ZERO, Vec::new())
}

fn anchor_genesis(ctx: &BlockRuntimeContext) {
    outbe_rewards::runtime::ensure_genesis_anchor(ctx).unwrap();
}

fn seed_fresh_reward_oracle(ctx: &BlockRuntimeContext) {
    outbe_oracle::api::set_exchange_rate(
        ctx.storage.clone(),
        Address::ZERO,
        outbe_oracle::api::DAY_TYPE_PAIR,
        U256::from(2_000_000u64),
        ctx.block.block_number,
        ctx.block.timestamp,
    )
    .unwrap();
    let oracle = ctx
        .storage
        .contract::<outbe_oracle::schema::OracleContract<'_>>();
    oracle.reference_currencies.push(840).unwrap();
    // Close the reward day: no day carries a VWAP, so delivery takes the live quote.
    oracle
        .utc_day_vwap_last_finalized
        .write(29_991_231)
        .unwrap();
}

fn seed_daily_voters(ctx: &BlockRuntimeContext, day: u32, voters: &[(Address, u64)]) {
    let rewards = ctx.storage.contract::<outbe_rewards::schema::Rewards<'_>>();
    let voter_at = rewards.daily_voter_at.get_nested(&day);
    let participation = rewards.daily_participation.get_nested(&day);
    let mut total = 0u64;
    for (index, (voter, count)) in voters.iter().enumerate() {
        voter_at.write(&(index as u32), *voter).unwrap();
        participation.write(voter, *count).unwrap();
        total = total.checked_add(*count).unwrap();
    }
    rewards
        .daily_voter_count
        .write(&day, voters.len() as u32)
        .unwrap();
    rewards
        .daily_total_participation
        .write(&day, total)
        .unwrap();
}

/// seed V2 Phase 1 accounting progress so the dispatcher's
/// new gate (`last_accounted_block_number >= block_number - 1`) is
/// satisfied for tests that fire the trigger at `block_number >= 2`.
/// Mirrors what `apply_phase1_commit_in_preexec` records in production.
fn account_parent(ctx: &BlockRuntimeContext, block_number: u64) {
    if block_number >= 2 {
        outbe_accounting::record_phase1_progress(ctx, block_number - 1).unwrap();
    }
}

fn with_execution_scope(
    ctx: &BlockRuntimeContext,
    f: impl FnOnce(&ExecutionScope, &TributeRepositoryReader) -> outbe_primitives::error::Result<()>,
) -> outbe_primitives::error::Result<()> {
    ctx.storage
        .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))?;
    ctx.storage.sstore(
        COMPRESSED_ENTITIES_ADDRESS,
        U256::from(1),
        U256::from_be_slice(
            outbe_compressed_entities::sealed_root(B256::ZERO)
                .unwrap()
                .as_slice(),
        ),
    )?;
    let storage: StorageReaderHandle = Arc::new(MemoryStorage::new());
    let parent = TributeRepositoryReader::new(storage);
    let scope = ExecutionScope::new();
    let lifecycle = CompressedEntitiesLifecycleContext::new(ctx.clone(), &scope);
    <CompressedEntitiesLifecycle as BlockLifecycle>::begin_block(&lifecycle)?;
    let result = f(&scope, &parent);
    let cleanup =
        <CompressedEntitiesLifecycle as BlockLifecycle>::end_block(&lifecycle).map(|_| ());
    result.and(cleanup)
}

fn dispatch_triggers(ctx: &BlockRuntimeContext) -> outbe_primitives::error::Result<()> {
    with_execution_scope(ctx, |scope, parent| {
        crate::runtime::dispatch_triggers(ctx, scope, parent)
    })
}

fn run_cycle_lifecycle(ctx: &BlockRuntimeContext) -> outbe_primitives::error::Result<()> {
    run_cycle_lifecycle_at_activation(ctx, 1)
}

fn run_cycle_lifecycle_at_activation(
    ctx: &BlockRuntimeContext,
    metadosis_genesis_activation_height: u64,
) -> outbe_primitives::error::Result<()> {
    with_execution_scope(ctx, |scope, parent| {
        let lifecycle = CycleLifecycleContext::new(ctx.clone(), scope, parent)
            .with_metadosis_genesis_activation_height(metadosis_genesis_activation_height);
        <CycleLifecycle as BlockLifecycle>::begin_block(&lifecycle)
    })
}

fn run_emission_limit_daily(ctx: &BlockRuntimeContext) -> outbe_primitives::error::Result<()> {
    with_execution_scope(ctx, |scope, parent| {
        crate::handler::run_emission_limit_daily(ctx, scope, parent)
    })
}

fn advance_metadosis_only(
    storage: &mut HashMapStorageProvider,
    block_number: u64,
    timestamp: u64,
) -> outbe_primitives::error::Result<()> {
    storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    StorageHandle::enter(storage, |handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(block_number, timestamp), handle);
        with_execution_scope(&ctx, |scope, _| {
            outbe_metadosis::commands::advance_active_worldwide_days(&ctx, scope)
        })
    })
}

// ---------------------------------------------------------------------------
// next_fire_at - pure scheduling math
// ---------------------------------------------------------------------------

#[test]
fn schedule_math_pinned_values() {
    // Daily, offset = 0 => first slot is `period_seconds`.
    assert_eq!(next_fire_at(86_400, 0, 0), 86_400);
    // Hourly @ :30 (offset = 1800), first slot at 1800.
    assert_eq!(next_fire_at(3_600, 1_800, 0), 1_800);
    // Hourly @ :30, last fired at 1800 => next at 5400.
    assert_eq!(next_fire_at(3_600, 1_800, 1_800), 5_400);
    // 5-minute, offset = 0, last fired at 299 => next at 300.
    assert_eq!(next_fire_at(300, 0, 299), 300);
    // 5-minute, offset = 0, last fired at 300 => next at 600.
    assert_eq!(next_fire_at(300, 0, 300), 600);
    // last well past first slot.
    assert_eq!(next_fire_at(86_400, 0, 86_400 * 5), 86_400 * 6);
}

#[test]
fn schedule_math_aligned_property() {
    // (next - offset) % period == 0 for arbitrary inputs.
    for &period in &[60u64, 300, 3_600, 86_400] {
        for &offset in &[0u64, 1, 7, period - 1] {
            for &last in &[0u64, 1, 100, 86_400, 86_400 * 365] {
                let next = next_fire_at(period, offset, last);
                assert!(next > last, "p={period} o={offset} l={last} n={next}");
                assert!(next >= offset);
                assert_eq!((next - offset) % period, 0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher: lazy first-encounter anchor + slot-based fire
// ---------------------------------------------------------------------------

#[test]
fn first_encounter_anchors_without_firing() {
    // First time the dispatcher sees the trigger, it anchors
    // `last_executed_at = block_ts` and skips firing. No event, no
    // handler invocation, no settle.
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let block_ts = GENESIS_TS + 60;
        let ctx = BlockRuntimeContext::new(block_ctx(1, block_ts), handle);
        anchor_genesis(&ctx);

        dispatch_triggers(&ctx).unwrap();

        let cycle: Cycle<'_> = ctx.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            block_ts,
            "first encounter anchors at block timestamp"
        );
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&EMISSION_LIMIT_1_ID)
                .unwrap(),
            0,
            "no fire = no last_executed_block_number write"
        );
    });
}

#[test]
fn block_1_begin_block_creates_genesis_worldwide_day() {
    // Production regression: at block 1 the daily Cycle trigger only anchors
    // (it never invokes `start_metadosis`), so `CycleLifecycle::begin_block`
    // must itself create the genesis metadosis worldwide day. Before the fix
    // the active-WWD set was empty until the first block past the next UTC
    // midnight.
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let block_ts = GENESIS_TS + 60;
        let ctx = BlockRuntimeContext::new(block_ctx(1, block_ts), handle);
        anchor_genesis(&ctx);

        // Sanity: no worldwide day exists before begin_block.
        assert!(outbe_metadosis::api::has_active_ocomp_profile(ctx.storage.clone()).unwrap());
        assert!(
            outbe_metadosis::api::worldwide_days(ctx.storage.clone())
                .unwrap()
                .is_empty(),
            "no worldwide day should exist before block-1 begin_block"
        );

        run_cycle_lifecycle(&ctx).unwrap();

        assert!(
            !outbe_metadosis::api::worldwide_days(ctx.storage.clone())
                .unwrap()
                .is_empty(),
            "block-1 begin_block must create the genesis worldwide day"
        );

        // The daily trigger must only have anchored - no settlement fired.
        let cycle: Cycle<'_> = ctx.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            block_ts,
            "daily trigger still only anchors on block 1"
        );
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&EMISSION_LIMIT_1_ID)
                .unwrap(),
            0,
            "daily settlement must not fire on block 1"
        );
    });
}

#[test]
fn block_1_begin_block_rejects_missing_genesis_ocomp_profile_without_partial_state() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 4);
    storage.enter(|handle| {
        handle
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        handle
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(
                    outbe_compressed_entities::sealed_root(B256::ZERO)
                        .unwrap()
                        .as_slice(),
                ),
            )
            .unwrap();
        let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
        anchor_genesis(&ctx);
    });
    let storage_before = storage.storage.clone();
    let events_before = storage.events.clone();

    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
        assert!(run_cycle_lifecycle(&ctx).is_err());
    });

    assert_eq!(storage.storage, storage_before);
    assert_eq!(storage.events, events_before);
}

#[test]
fn frozen_final_profile_initializes_metadosis_at_its_existing_activation_height() {
    let mut storage = cycle_storage();

    storage.enter(|handle| {
        let block_1 = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&block_1);
        run_cycle_lifecycle_at_activation(&block_1, 32).unwrap();

        assert!(
            outbe_metadosis::api::worldwide_days(block_1.storage.clone())
                .unwrap()
                .is_empty(),
            "the frozen Final/32 evidence profile must not initialize Metadosis at block 1"
        );

        let activation =
            BlockRuntimeContext::new(block_ctx(32, GENESIS_TS + 31 * 60), handle.clone());
        run_cycle_lifecycle_at_activation(&activation, 32).unwrap();

        assert!(
            !outbe_metadosis::api::worldwide_days(activation.storage.clone())
                .unwrap()
                .is_empty(),
            "the existing Final/32 evidence profile must initialize Metadosis after its fork install"
        );
    });
}

#[test]
fn does_not_fire_before_next_slot_after_anchor() {
    // Anchor at 00:01 UTC; the first aligned hourly slot is 01:00 UTC.
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        // Block at 00:59:59 UTC - still before the next slot.
        let ctx_before =
            BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + 3_600 - 1), handle.clone());
        dispatch_triggers(&ctx_before).unwrap();

        let cycle: Cycle<'_> = ctx_before.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            anchor_ts,
            "trigger must not fire before the next slot"
        );
    });
}

#[test]
fn fires_at_first_block_past_next_slot() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        // Step 1: anchor.
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        // Step 2: first block past the next aligned hour.
        let fire_ts = GENESIS_TS + 3_600 + 5;
        let ctx_fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&ctx_fire, 2);
        dispatch_triggers(&ctx_fire).unwrap();

        let cycle: Cycle<'_> = ctx_fire.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            GENESIS_TS + 3_600,
            "last_executed_at must be the slot, not block.timestamp"
        );
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&EMISSION_LIMIT_1_ID)
                .unwrap(),
            2
        );
    });
}

#[test]
fn does_not_refire_within_same_slot() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        let fire_ts = GENESIS_TS + 3_600 + 60;
        let ctx_fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle.clone());
        account_parent(&ctx_fire, 2);
        dispatch_triggers(&ctx_fire).unwrap();
        let after_first_fire = ctx_fire
            .storage
            .contract::<Cycle<'_>>()
            .last_executed_at
            .read(&EMISSION_LIMIT_1_ID)
            .unwrap();

        // Second block within the same slot.
        let ctx_again = BlockRuntimeContext::new(block_ctx(3, fire_ts + 30), handle);
        account_parent(&ctx_again, 3);
        dispatch_triggers(&ctx_again).unwrap();
        let cycle: Cycle<'_> = ctx_again.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            after_first_fire,
            "trigger must not refire within the same slot"
        );
    });
}

#[test]
fn multi_slot_gap_fires_only_for_latest_slot_after_anchor() {
    // Anchor, then jump 3 slots ahead in one block.
    let mut storage = cycle_storage();
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 10);
    storage.enter(|handle| {
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        // Missed hourly scheduler slots collapse to one execution at the latest
        // due boundary. Calendar policy then forfeits this multi-day gap.
        let ctx_fire =
            BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + 4 * SECONDS_PER_DAY), handle);
        account_parent(&ctx_fire, 2);
        dispatch_triggers(&ctx_fire).unwrap();

        let cycle: Cycle<'_> = ctx_fire.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            GENESIS_TS + 4 * SECONDS_PER_DAY,
            "multi-slot gap fires once at the latest due hourly slot"
        );
    });
}

#[test]
fn protocol_cycle_forfeits_every_completed_day_after_a_multi_day_halt() {
    let mut storage = cycle_storage();
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 16);
    storage.enter(|handle| {
        let anchor_ts = GENESIS_TS + 60;
        let anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&anchor);
        run_cycle_lifecycle(&anchor).unwrap();

        let fire_ts = GENESIS_TS + 3 * SECONDS_PER_DAY + 3_600;
        let fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&fire, 2);
        dispatch_triggers(&fire).unwrap();

        let rewards = fire
            .storage
            .contract::<outbe_rewards::schema::Rewards<'_>>();
        for day in [20_240_101, 20_240_102, 20_240_103] {
            assert!(!rewards.daily_settled.read(&day).unwrap());
            assert!(!rewards.daily_topup_settled.read(&day).unwrap());
            assert!(
                outbe_metadosis::api::day_limit_formation_receipt(
                    fire.storage.clone(),
                    outbe_primitives::time::WorldwideDay::new(day),
                )
                .unwrap()
                .is_none(),
                "forfeited day {day} must not gain a formation receipt"
            );
        }

        for day in [20_240_102, 20_240_103] {
            let wwd = outbe_primitives::time::WorldwideDay::new(day);
            assert!(
                outbe_metadosis::api::worldwide_day(fire.storage.clone(), wwd)
                    .unwrap()
                    .is_none(),
                "missed day {day} must not gain the WWD identity required by downstream OCOMP or Promis work"
            );
            assert!(
                outbe_metadosis::api::missed_offering_receipt(fire.storage.clone(), wwd)
                    .unwrap()
                    .is_none(),
                "missed day {day} must not gain a Promis-bearing terminal receipt"
            );
            assert!(
                outbe_metadosis::api::capacity_forfeiture_receipt(fire.storage.clone(), wwd)
                    .unwrap()
                    .is_none(),
                "missed day {day} must not gain a capacity/Promis receipt"
            );
        }
        assert!(
            outbe_metadosis::api::worldwide_day(
                fire.storage.clone(),
                outbe_primitives::time::WorldwideDay::new(20_240_104),
            )
            .unwrap()
            .is_some(),
            "the one current WWD flow must still run after the gap"
        );
        assert_eq!(
            fire.storage
                .contract::<Cycle<'_>>()
                .active_utc_day
                .read()
                .unwrap(),
            20_240_104
        );
    });
}

#[test]
fn contiguous_day_settlement_failure_preserves_the_calendar_cursor() {
    let mut storage = cycle_storage();
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 16);
    storage.enter(|handle| {
        let anchor = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&anchor);
        run_cycle_lifecycle(&anchor).unwrap();

        // Create only the Metadosis half of day 1's idempotency pair. The
        // contiguous transition must fail before advancing the cursor.
        let inconsistent = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + 60), handle.clone());
        outbe_metadosis::commands::apply_cycle_day_limit(&inconsistent, U256::from(17_u8)).unwrap();
        assert!(outbe_metadosis::api::day_limit_formation_receipt(
            handle.clone(),
            outbe_primitives::time::WorldwideDay::new(20_240_101),
        )
        .unwrap()
        .is_some());

        let fire =
            BlockRuntimeContext::new(block_ctx(3, GENESIS_TS + SECONDS_PER_DAY + 3_600), handle);
        account_parent(&fire, 3);
        assert!(matches!(
            dispatch_triggers(&fire),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));

        let cycle: Cycle<'_> = fire.storage.contract::<Cycle<'_>>();
        assert_eq!(cycle.active_utc_day.read().unwrap(), 20_240_101);
        let rewards = fire
            .storage
            .contract::<outbe_rewards::schema::Rewards<'_>>();
        assert!(!rewards.daily_settled.read(&20_240_101).unwrap());
    });
}

#[test]
fn cycle_lifecycle_begin_block_runs_dispatcher() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let block_ts = GENESIS_TS + 60;
        let ctx = BlockRuntimeContext::new(block_ctx(1, block_ts), handle);
        anchor_genesis(&ctx);

        run_cycle_lifecycle(&ctx).unwrap();

        // Same as `first_encounter_anchors_without_firing`: begin_block
        // delegates to dispatch_triggers.
        let cycle: Cycle<'_> = ctx.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            block_ts
        );
    });
}

// ---------------------------------------------------------------------------
// auction_advance trigger
// ---------------------------------------------------------------------------

#[test]
fn auction_advance_runs_after_emission_limit_1() {
    use crate::triggers::ACTIVE_TRIGGERS;
    let position = |id: u32| {
        ACTIVE_TRIGGERS
            .iter()
            .position(|spec| spec.id == id)
            .expect("trigger registered")
    };
    assert!(
        position(TriggerId::AuctionAdvance.as_u32())
            > position(TriggerId::ProtocolCycle.as_u32()),
        "auction_advance must dispatch after emission_limit_1 so the same-slot brief starts the auction"
    );
}

#[test]
fn dispatcher_fires_auction_advance_at_its_slot() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        let fire_ts = GENESIS_TS + SECONDS_PER_DAY + 5;
        let ctx_fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&ctx_fire, 2);
        dispatch_triggers(&ctx_fire).unwrap();

        let auction_advance_id = TriggerId::AuctionAdvance.as_u32();
        let cycle: Cycle<'_> = ctx_fire.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&auction_advance_id).unwrap(),
            GENESIS_TS + SECONDS_PER_DAY,
            "coalesces the backlog to the latest slot at or before the block"
        );
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&auction_advance_id)
                .unwrap(),
            2
        );
    });
}

// ---------------------------------------------------------------------------
// End-to-end: handler effects on Rewards, AgentReward, Metadosis
// ---------------------------------------------------------------------------

#[test]
fn protocol_cycle_keeps_midnight_slot_pending_until_late_reward_window_closes() {
    let mut storage = cycle_storage();
    let hash = B256::repeat_byte(0x77);
    let early = Address::repeat_byte(0xB0);
    let late = Address::repeat_byte(0xB1);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&ctx);
        seed_fresh_reward_oracle(&ctx);
        dispatch_triggers(&ctx).unwrap();
        let ctx = BlockRuntimeContext::new(block_ctx(11, GENESIS_TS + SECONDS_PER_DAY), handle);
        let metadata = outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata {
            finalized_block_number: 10,
            finalized_block_hash: hash,
            finalized_epoch: 0,
            finalized_view: 10,
            parent_view: 9,
            ordered_committee: vec![early, late],
            signer_bitmap: vec![1],
            proof: Default::default(),
            committee_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key_hash: B256::ZERO,
            proof_kind:
                outbe_primitives::consensus_metadata::ParentParticipationProof::Finalization,
            missed_proposers: vec![],
        };
        outbe_rewards::finalized_metadata_hook::on_finalized_metadata(
            &ctx,
            &metadata,
            U256::ZERO,
            GENESIS_TS + SECONDS_PER_DAY - 1,
            &[early],
        )
        .unwrap();
    });
    for height in 11..=13 {
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(
                block_ctx(height, GENESIS_TS + SECONDS_PER_DAY + height - 11),
                handle,
            );
            account_parent(&ctx, height);
            dispatch_triggers(&ctx).unwrap();
            let cycle = ctx.storage.contract::<Cycle>();
            assert_eq!(cycle.active_utc_day.read().unwrap(), 20240101);
            assert_eq!(
                cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
                GENESIS_TS + 60
            );
            assert!(!outbe_rewards::api::is_day_settled(&ctx, 20240101).unwrap());
            if height == 13 {
                // Real phase order: Cycle first, then final-slot credit and GC.
                outbe_rewards::late_settlement::record_late_credit(&ctx, hash, late, 3).unwrap();
                outbe_rewards::late_settlement::settle_matured(&ctx, 13, 3).unwrap();
            }
        });
    }
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(14, GENESIS_TS + SECONDS_PER_DAY + 3), handle);
        account_parent(&ctx, 14);
        dispatch_triggers(&ctx).unwrap();
        assert!(outbe_rewards::api::is_day_settled(&ctx, 20240101).unwrap());
        let cycle = ctx.storage.contract::<Cycle>();
        assert_eq!(cycle.active_utc_day.read().unwrap(), 20240102);
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&EMISSION_LIMIT_1_ID)
                .unwrap(),
            14
        );
        let rewards = ctx.storage.contract::<outbe_rewards::schema::Rewards>();
        assert_eq!(
            rewards.reward_gem_recipient_count.read(&20240101).unwrap(),
            2
        );
        let loads = rewards.reward_promis_load_at.get_nested(&20240101);
        assert_eq!(loads.read(&0).unwrap(), loads.read(&1).unwrap());
        assert!(loads.read(&1).unwrap() > U256::ZERO);
        dispatch_triggers(&ctx).unwrap();
        assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
    });
}

#[test]
fn end_to_end_emission_dispatch_marks_day_settled_and_credits_metadosis() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        // Step 1: anchor at chain start.
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        // Step 2: block past first slot. prev_day = genesis_utc_day
        // (20240101); day_number_since_genesis = 0; cap = INITIAL_DAY_EMISSION.
        let fire_ts = GENESIS_TS + SECONDS_PER_DAY + 60;
        let ctx_fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&ctx_fire, 2);
        dispatch_triggers(&ctx_fire).unwrap();

        // Rewards.daily_settled[20240101] = true (sealed against late
        // finalized metadata for the previous UTC day).
        let rewards = ctx_fire
            .storage
            .contract::<outbe_rewards::schema::Rewards<'_>>();
        assert!(
            rewards.daily_settled.read(&20_240_101).unwrap(),
            "Cycle handler must seal prev_day"
        );

        // Cycle's last_executed_at advanced to the slot
        // (GENESIS_TS + 86_400), not the block timestamp.
        let cycle: Cycle<'_> = ctx_fire.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            GENESIS_TS + SECONDS_PER_DAY
        );

        // No tributes for any AgentReward pool, so all three
        // WAA/SRA/CCA amounts are accounted for.
        // burn parity: WAA + SRA pools are pre-funded then burned in
        // their no-tribute branch; CCA lands on its own
        // accumulator address. AGENT_REWARD balance is therefore
        // zero (no claimable was credited).
        let agent_reward_balance = ctx_fire
            .storage
            .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
            .unwrap();
        assert_eq!(agent_reward_balance, U256::ZERO);

        // The CCA accumulator received its 4 %. The exact amount comes
        // from `day_emission_limit(0) * 4 / 100` which is fully covered
        // by emissionlimit pinned tests; here we only assert it is
        // non-zero.
        let cca = ctx_fire
            .storage
            .balance(outbe_primitives::addresses::CCA_ADDRESS)
            .unwrap();
        assert!(!cca.is_zero(), "CCA accumulator received its 4 %");
    });
}

#[test]
fn next_day_cycle_settlement_pays_previous_utc_day_agent_activity() {
    const REWARD_UTC_DAY: u32 = 20_240_101;

    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor_ts = GENESIS_TS + 60;
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        let wallet = Address::repeat_byte(0x71);
        let sra = Address::repeat_byte(0x72);
        let reward_day = outbe_primitives::time::WorldwideDay::new(REWARD_UTC_DAY);
        let mut agent_reward = outbe_agentreward::AgentRewardContract::new(handle.clone());
        agent_reward
            .increment_waa_tribute(reward_day, wallet)
            .unwrap();
        agent_reward.increment_sra_tribute(reward_day, sra).unwrap();

        let fire_ts = GENESIS_TS + SECONDS_PER_DAY + 60;
        let ctx_fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&ctx_fire, 2);
        dispatch_triggers(&ctx_fire).unwrap();

        let agent_reward = outbe_agentreward::AgentRewardContract::new(ctx_fire.storage.clone());
        let wallet_claimable = agent_reward.get_claimable_reward(wallet).unwrap();
        let sra_claimable = agent_reward.get_claimable_reward(sra).unwrap();
        assert!(
            !wallet_claimable.is_zero(),
            "the next UTC day must pay the previous day's WAA activity"
        );
        assert!(
            !sra_claimable.is_zero(),
            "the next UTC day must pay the previous day's SRA activity"
        );
        assert!(
            agent_reward
                .get_all_waa_counts(reward_day)
                .unwrap()
                .is_empty(),
            "settled WAA counters must be cleared"
        );
        assert!(
            agent_reward
                .get_all_sra_counts(reward_day)
                .unwrap()
                .is_empty(),
            "settled SRA counters must be cleared"
        );
        assert_eq!(
            ctx_fire
                .storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            wallet_claimable + sra_claimable,
            "the AgentReward native balance must back every new claim"
        );
    });
}

#[test]
fn prepared_validator_topup_and_terminal_residue_conserve_the_allocation() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&anchor);
        let ctx = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);

        seed_fresh_reward_oracle(&ctx);

        let voters = [
            Address::repeat_byte(0x31),
            Address::repeat_byte(0x32),
            Address::repeat_byte(0x33),
        ];
        seed_daily_voters(&ctx, 20_240_101, &voters.map(|voter| (voter, 1)));

        run_emission_limit_daily(&ctx).unwrap();

        let allocations = outbe_emissionlimit::allocation::allocate_emission(
            outbe_emissionlimit::day_emission::day_emission_limit(0),
        )
        .unwrap();
        let amount_for = |id| {
            allocations
                .iter()
                .find(|allocation| allocation.id == id)
                .unwrap()
                .amount
        };
        let validator_amount =
            amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Validator);
        let metadosis_amount =
            amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Metadosis);
        let agent_terminal = amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Waa)
            .checked_add(amount_for(
                outbe_emissionlimit::allocation::EmissionSinkId::Sra,
            ))
            .unwrap();
        let rewards = ctx.storage.contract::<outbe_rewards::schema::Rewards<'_>>();
        let planned = rewards
            .reward_gem_planned_load_amount
            .read(&20_240_101)
            .unwrap();
        let gem = outbe_gem::GemContract::new(ctx.storage.clone());
        for voter in voters {
            assert_eq!(
                gem.balance_of(voter).unwrap(),
                0,
                "Cycle prepares the batch but does not mint Gems"
            );
        }
        let formation = outbe_metadosis::api::day_limit_formation_receipt(
            ctx.storage.clone(),
            outbe_primitives::time::WorldwideDay::new(20_240_101),
        )
        .unwrap()
        .unwrap();
        let outbe_metadosis::DayLimitFormationReceipt::Formed(formed) = formation;
        let validator_terminal = formed
            .base_limit
            .checked_sub(metadosis_amount)
            .and_then(|amount| amount.checked_sub(agent_terminal))
            .unwrap();

        assert_eq!(
            planned.checked_add(validator_terminal).unwrap(),
            validator_amount,
            "prepared Gem liability plus terminal residue must conserve the validator allocation"
        );
    });
}

#[test]
fn zero_total_validator_participation_routes_the_pool_without_halting() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&anchor);
        let ctx = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);

        let voters = [Address::repeat_byte(0x51), Address::repeat_byte(0x52)];
        seed_daily_voters(&ctx, 20_240_101, &voters.map(|voter| (voter, 0)));

        run_emission_limit_daily(&ctx).unwrap();

        let rewards = ctx.storage.contract::<outbe_rewards::schema::Rewards<'_>>();
        assert!(rewards.daily_topup_prepared.read(&20_240_101).unwrap());
        assert!(rewards.daily_topup_settled.read(&20_240_101).unwrap());
        assert!(rewards.daily_settled.read(&20_240_101).unwrap());
        assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
        assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 0);
        let gem = outbe_gem::GemContract::new(ctx.storage.clone());
        for voter in voters {
            assert_eq!(gem.balance_of(voter).unwrap(), 0, "no Gem may be minted");
        }

        let allocations = outbe_emissionlimit::allocation::allocate_emission(
            outbe_emissionlimit::day_emission::day_emission_limit(0),
        )
        .unwrap();
        let amount_for = |id| {
            allocations
                .iter()
                .find(|allocation| allocation.id == id)
                .unwrap()
                .amount
        };
        let expected_terminal =
            amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Metadosis)
                .checked_add(amount_for(
                    outbe_emissionlimit::allocation::EmissionSinkId::Validator,
                ))
                .and_then(|amount| {
                    amount.checked_add(amount_for(
                        outbe_emissionlimit::allocation::EmissionSinkId::Waa,
                    ))
                })
                .and_then(|amount| {
                    amount.checked_add(amount_for(
                        outbe_emissionlimit::allocation::EmissionSinkId::Sra,
                    ))
                })
                .unwrap();
        let receipt = outbe_metadosis::api::day_limit_formation_receipt(
            ctx.storage.clone(),
            outbe_primitives::time::WorldwideDay::new(20_240_101),
        )
        .unwrap()
        .unwrap();
        let outbe_metadosis::DayLimitFormationReceipt::Formed(formed) = receipt;
        assert_eq!(formed.base_limit, expected_terminal);
    });
}

#[test]
fn failed_terminal_dispatch_rolls_back_validator_topup_and_retry_settles_once() {
    let mut storage = cycle_storage();
    let anchor_ts = GENESIS_TS + 60;
    storage.enter(|handle| {
        let anchor = BlockRuntimeContext::new(block_ctx(1, anchor_ts), handle);
        anchor_genesis(&anchor);
        dispatch_triggers(&anchor).unwrap();
    });

    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 0);
    let fire_ts = GENESIS_TS + SECONDS_PER_DAY + 60;
    let voters = [
        Address::repeat_byte(0x61),
        Address::repeat_byte(0x62),
        Address::repeat_byte(0x63),
    ];
    storage.enter(|handle| {
        let fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&fire, 2);
        seed_fresh_reward_oracle(&fire);
        seed_daily_voters(&fire, 20_240_101, &voters.map(|voter| (voter, 1)));

        let error = dispatch_triggers(&fire).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no matching Metadosis mutation lease"),
            "the injected downstream failure must reach the terminal sink: {error}"
        );

        let rewards = fire
            .storage
            .contract::<outbe_rewards::schema::Rewards<'_>>();
        assert!(!rewards.daily_topup_prepared.read(&20_240_101).unwrap());
        assert!(!rewards.daily_topup_settled.read(&20_240_101).unwrap());
        assert!(!rewards.daily_settled.read(&20_240_101).unwrap());
        assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
        assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 0);
        assert!(outbe_metadosis::api::day_limit_formation_receipt(
            fire.storage.clone(),
            outbe_primitives::time::WorldwideDay::new(20_240_101),
        )
        .unwrap()
        .is_none());
        let gem = outbe_gem::GemContract::new(fire.storage.clone());
        for voter in voters {
            assert_eq!(gem.balance_of(voter).unwrap(), 0, "Gem mint must roll back");
        }
        assert_eq!(
            fire.storage
                .balance(outbe_primitives::addresses::CCA_ADDRESS)
                .unwrap(),
            U256::ZERO,
            "CCA credit before the terminal failure must roll back"
        );
        let cycle: Cycle<'_> = fire.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            anchor_ts,
            "the failed trigger must remain due for retry"
        );
        assert_eq!(cycle.active_utc_day.read().unwrap(), 20_240_101);
    });

    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 4);
    storage.enter(|handle| {
        let retry = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        dispatch_triggers(&retry).unwrap();

        let rewards = retry
            .storage
            .contract::<outbe_rewards::schema::Rewards<'_>>();
        assert!(rewards.daily_topup_prepared.read(&20_240_101).unwrap());
        assert!(!rewards.daily_topup_settled.read(&20_240_101).unwrap());
        assert!(rewards.daily_settled.read(&20_240_101).unwrap());
        assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
        assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
        let receipt = outbe_metadosis::api::day_limit_formation_receipt(
            retry.storage.clone(),
            outbe_primitives::time::WorldwideDay::new(20_240_101),
        )
        .unwrap()
        .unwrap();

        let allocations = outbe_emissionlimit::allocation::allocate_emission(
            outbe_emissionlimit::day_emission::day_emission_limit(0),
        )
        .unwrap();
        let amount_for = |id| {
            allocations
                .iter()
                .find(|allocation| allocation.id == id)
                .unwrap()
                .amount
        };
        let validator_amount =
            amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Validator);
        let expected_promis_load = validator_amount / U256::from(voters.len());
        let distributed = expected_promis_load * U256::from(voters.len());
        let validator_residue = validator_amount.checked_sub(distributed).unwrap();
        let expected_terminal =
            amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Metadosis)
                .checked_add(amount_for(
                    outbe_emissionlimit::allocation::EmissionSinkId::Waa,
                ))
                .and_then(|amount| {
                    amount.checked_add(amount_for(
                        outbe_emissionlimit::allocation::EmissionSinkId::Sra,
                    ))
                })
                .and_then(|amount| amount.checked_add(validator_residue))
                .unwrap();
        let outbe_metadosis::DayLimitFormationReceipt::Formed(formed) = receipt;
        assert_eq!(formed.base_limit, expected_terminal);
        assert_eq!(
            retry
                .storage
                .balance(outbe_primitives::addresses::CCA_ADDRESS)
                .unwrap(),
            outbe_primitives::units::checked_protocol_to_native(amount_for(
                outbe_emissionlimit::allocation::EmissionSinkId::Cca,
            ))
            .unwrap(),
            "retry must credit CCA exactly once"
        );
        let gem = outbe_gem::GemContract::new(retry.storage.clone());
        for voter in voters {
            assert_eq!(
                gem.balance_of(voter).unwrap(),
                0,
                "Cycle retry prepares exactly once; delivery owns Gem creation"
            );
        }
        assert_eq!(
            rewards
                .reward_gem_planned_load_amount
                .read(&20_240_101)
                .unwrap(),
            expected_promis_load * U256::from(voters.len())
        );
        let cycle: Cycle<'_> = retry.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle.last_executed_at.read(&EMISSION_LIMIT_1_ID).unwrap(),
            GENESIS_TS + SECONDS_PER_DAY
        );
    });
}

#[test]
fn open_day_preserves_an_already_delivered_validator_batch_without_reminting() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&anchor);
        let ctx = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);

        let voter = Address::repeat_byte(0x41);
        seed_fresh_reward_oracle(&ctx);
        seed_daily_voters(&ctx, 20_240_101, &[(voter, 1)]);

        let validator_amount = outbe_emissionlimit::allocation::allocate_emission(
            outbe_emissionlimit::day_emission::day_emission_limit(0),
        )
        .unwrap()
        .into_iter()
        .find(|allocation| {
            allocation.id == outbe_emissionlimit::allocation::EmissionSinkId::Validator
        })
        .unwrap()
        .amount;
        let outcome = outbe_rewards::api::prepare_daily_validator_gem_batch(
            &ctx,
            20_240_101,
            validator_amount,
            &[(voter, 1)],
        )
        .unwrap();
        assert!(matches!(
            outcome,
            outbe_rewards::api::RewardGemPreparationOutcome::Prepared(_)
        ));
        outbe_rewards::api::deliver_oldest_reward_gem_batch(&ctx).unwrap();

        let gem = outbe_gem::GemContract::new(ctx.storage.clone());
        assert_eq!(gem.balance_of(voter).unwrap(), 1);
        let gem_id = gem.token_of_owner_by_index(voter, 0).unwrap();
        let load_before = outbe_gem::api::get_gem(&ctx.storage, gem_id)
            .unwrap()
            .unwrap()
            .promis_load_minor;

        let rewards = ctx.storage.contract::<outbe_rewards::schema::Rewards<'_>>();
        run_emission_limit_daily(&ctx).unwrap();

        assert_eq!(gem.balance_of(voter).unwrap(), 1, "top-up must not remint");
        assert_eq!(
            outbe_gem::api::get_gem(&ctx.storage, gem_id)
                .unwrap()
                .unwrap()
                .promis_load_minor,
            load_before,
            "the prior Gem must remain unchanged"
        );
        assert!(rewards.daily_settled.read(&20_240_101).unwrap());
        let receipt = outbe_metadosis::api::day_limit_formation_receipt(
            ctx.storage.clone(),
            outbe_primitives::time::WorldwideDay::new(20_240_101),
        )
        .unwrap()
        .unwrap();
        let allocations = outbe_emissionlimit::allocation::allocate_emission(
            outbe_emissionlimit::day_emission::day_emission_limit(0),
        )
        .unwrap();
        let amount_for = |id| {
            allocations
                .iter()
                .find(|allocation| allocation.id == id)
                .unwrap()
                .amount
        };
        let expected_terminal =
            amount_for(outbe_emissionlimit::allocation::EmissionSinkId::Metadosis)
                .checked_add(amount_for(
                    outbe_emissionlimit::allocation::EmissionSinkId::Waa,
                ))
                .and_then(|amount| {
                    amount.checked_add(amount_for(
                        outbe_emissionlimit::allocation::EmissionSinkId::Sra,
                    ))
                })
                .unwrap();
        let outbe_metadosis::DayLimitFormationReceipt::Formed(formed) = receipt;
        assert_eq!(
            formed.base_limit, expected_terminal,
            "AlreadySettled must contribute no second validator top-up to the terminal sink"
        );
    });
}

/// a second `run_emission_limit_daily` invocation for an already-settled
/// `prev_day` is a no-op - the CCA agent pool (and terminal Metadosis)
/// are NOT minted twice. Guards the per-day idempotency added on top of the
/// C-01 timestamp drift band.
#[test]
fn emission_dispatch_is_idempotent_per_prev_day() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&ctx_anchor);
        dispatch_triggers(&ctx_anchor).unwrap();

        let ctx = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);
        account_parent(&ctx, 2);

        // First settlement of prev_day = 20240101: mints the pools + seals.
        run_emission_limit_daily(&ctx).unwrap();
        let rewards = ctx.storage.contract::<outbe_rewards::schema::Rewards<'_>>();
        assert!(
            rewards.daily_settled.read(&20_240_101).unwrap(),
            "first fire must seal prev_day"
        );
        let cca_after_first = ctx
            .storage
            .balance(outbe_primitives::addresses::CCA_ADDRESS)
            .unwrap();
        let metadosis_after_first = ctx
            .storage
            .balance(outbe_primitives::addresses::METADOSIS_ADDRESS)
            .unwrap();
        assert!(!cca_after_first.is_zero(), "first fire credited CCA");

        // Second invocation for the SAME prev_day: the idempotency guard sees
        // `daily_settled[20240101] == true` and returns early - no double-mint.
        run_emission_limit_daily(&ctx).unwrap();
        assert_eq!(
            ctx.storage
                .balance(outbe_primitives::addresses::CCA_ADDRESS)
                .unwrap(),
            cca_after_first,
            "CCA pool must not be minted twice for the same prev_day"
        );
        assert_eq!(
            ctx.storage
                .balance(outbe_primitives::addresses::METADOSIS_ADDRESS)
                .unwrap(),
            metadosis_after_first,
            "terminal Metadosis must not be re-dispatched for the same prev_day"
        );
    });
}

#[test]
fn repeated_settled_cycle_slot_replays_without_any_storage_or_event_write() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let anchor = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle.clone());
        anchor_genesis(&anchor);
        dispatch_triggers(&anchor).unwrap();

        let fire =
            BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);
        account_parent(&fire, 2);
        run_emission_limit_daily(&fire).unwrap();
        assert!(matches!(
            outbe_metadosis::api::day_limit_formation_receipt(
                fire.storage.clone(),
                outbe_primitives::time::WorldwideDay::new(20_240_101),
            )
            .unwrap(),
            Some(outbe_metadosis::DayLimitFormationReceipt::Formed(_))
        ));
    });
    let storage_after_first = storage.storage.clone();
    let events_after_first = storage.events.clone();

    storage.enter(|handle| {
        let replay =
            BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);
        run_emission_limit_daily(&replay).unwrap();
    });
    assert_eq!(storage.storage, storage_after_first);
    assert_eq!(storage.events, events_after_first);
}

#[test]
fn settled_cycle_marker_without_metadosis_semantic_receipt_is_fatal() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);
        outbe_rewards::api::mark_day_settled(&ctx, 20_240_101).unwrap();
        assert!(matches!(
            run_emission_limit_daily(&ctx),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn metadosis_semantic_receipt_without_settled_cycle_marker_is_fatal_before_effects() {
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
        outbe_metadosis::commands::apply_cycle_day_limit(&ctx, U256::from(17_u8)).unwrap();
    });
    let storage_before = storage.storage.clone();
    let events_before = storage.events.clone();

    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + SECONDS_PER_DAY + 60), handle);
        let parent_storage: StorageReaderHandle = Arc::new(MemoryStorage::new());
        let parent = TributeRepositoryReader::new(parent_storage);
        let scope = ExecutionScope::new();
        assert!(matches!(
            crate::handler::run_emission_limit_daily(&ctx, &scope, &parent),
            Err(outbe_primitives::error::PrecompileError::Fatal(_))
        ));
    });

    assert_eq!(storage.storage, storage_before);
    assert_eq!(storage.events, events_before);
}

#[test]
fn hourly_protocol_cycle_commits_the_same_typed_missed_offering_outcome() {
    let wwd = outbe_primitives::time::WorldwideDay::new(20_240_105);
    let day_limit = U256::from(109);
    let mut storage = cycle_storage();
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 4);
    let offering_end = storage.enter(|handle| {
        let formation_ctx = BlockRuntimeContext::new(
            block_ctx(10, wwd.start_timestamp() + 2 * 3_600),
            handle.clone(),
        );
        outbe_metadosis::commands::apply_cycle_day_limit(&formation_ctx, day_limit).unwrap();
        outbe_metadosis::api::worldwide_day(handle, wwd)
            .unwrap()
            .unwrap()
            .offering_end
    });
    let fire_at = offering_end.div_ceil(3_600) * 3_600;
    let previous_hour = fire_at - 3_600;

    storage.enter(|handle| {
        let cycle: Cycle<'_> = handle.contract::<Cycle<'_>>();
        for spec in ACTIVE_TRIGGERS {
            let last = if spec.id == TriggerId::ProtocolCycle.as_u32() {
                previous_hour
            } else {
                fire_at
            };
            cycle.last_executed_at.write(&spec.id, last).unwrap();
        }
        cycle
            .active_utc_day
            .write(outbe_primitives::time::timestamp_to_date_key(fire_at))
            .unwrap();
    });
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 4);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(20, fire_at), handle.clone());
        account_parent(&ctx, 20);
        dispatch_triggers(&ctx).unwrap();

        let projection = outbe_metadosis::api::worldwide_day(ctx.storage.clone(), wwd)
            .unwrap()
            .unwrap();
        assert_eq!(projection.status, outbe_metadosis::WwdStatus::Failed);
        assert_eq!(
            projection.membership,
            outbe_metadosis::WwdMembership::Closed
        );
        let receipt = outbe_metadosis::api::missed_offering_receipt(ctx.storage.clone(), wwd)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.value_routed, day_limit);
        assert_eq!(receipt.carry_over_before, U256::ZERO);
        assert_eq!(receipt.carry_over_after, day_limit);
        assert_eq!(
            receipt.retirement,
            outbe_compressed_entities::RetirementOutcome::NotPresent
        );
        assert_eq!(receipt.block_number, 20);

        let desis = ctx.storage.contract::<outbe_desis::schema::DesisContract>();
        assert_eq!(
            desis.auction_stage.read(&wwd).unwrap(),
            outbe_desis::schema::AuctionStage::None as u8
        );
        let cycle: Cycle<'_> = ctx.storage.contract::<Cycle<'_>>();
        assert_eq!(
            cycle
                .last_executed_at
                .read(&TriggerId::ProtocolCycle.as_u32())
                .unwrap(),
            fire_at
        );
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&TriggerId::ProtocolCycle.as_u32())
                .unwrap(),
            20
        );
    });
}

#[test]
fn hourly_protocol_cycle_applies_exact_capacity_forfeiture_to_the_new_due_candidate() {
    use outbe_metadosis::constants::MAX_RETAINED_WWDS;
    use outbe_primitives::time::WorldwideDay;

    let victim = WorldwideDay::new(20_260_910);
    let retained = retained_days_before(victim, MAX_RETAINED_WWDS);
    let day_limit = U256::from(100);
    let mut storage = cycle_storage();
    storage.enter(|handle| {
        outbe_tribute::TributeContract::new(handle)
            .initialize_fresh_ocomp_profile()
            .unwrap();
    });

    storage.enter(|handle| {
        outbe_metadosis::test_support::seed_ready_worldwide_days_for_capacity(handle, &retained)
            .unwrap();
    });

    let mut next_block = 2_u64;
    storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
    let victim_projection = storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(
            block_ctx(next_block, victim.start_timestamp() + 2 * 3_600),
            handle.clone(),
        );
        outbe_metadosis::commands::apply_cycle_day_limit(&ctx, day_limit).unwrap();
        outbe_metadosis::api::worldwide_day(handle, victim)
            .unwrap()
            .unwrap()
    });
    next_block += 1;
    for boundary in [
        victim_projection.forming_end,
        victim_projection.lookback_end,
        victim_projection.offering_end,
    ] {
        advance_metadosis_only(&mut storage, next_block, boundary).unwrap();
        next_block += 1;
    }

    let fire_at = victim_projection.scheduled_process_time.div_ceil(3_600) * 3_600;
    let previous_hour = fire_at - 3_600;
    storage.enter(|handle| {
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
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(next_block, fire_at), handle.clone());
        account_parent(&ctx, next_block);
        dispatch_triggers(&ctx).unwrap();

        let projection = outbe_metadosis::api::worldwide_day(handle.clone(), victim)
            .unwrap()
            .unwrap();
        assert_eq!(projection.status, outbe_metadosis::WwdStatus::Failed);
        assert_eq!(
            projection.membership,
            outbe_metadosis::WwdMembership::Closed
        );

        let receipt = outbe_metadosis::api::capacity_forfeiture_receipt(handle.clone(), victim)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.max_retained_wwds, MAX_RETAINED_WWDS as u32);
        assert_eq!(receipt.retained_count_before, MAX_RETAINED_WWDS as u32);
        assert_eq!(receipt.value_routed, day_limit);
        assert_eq!(receipt.carry_over_before, U256::ZERO);
        assert_eq!(receipt.carry_over_after, day_limit);
        assert_eq!(receipt.forfeited_count, 0);
        assert_eq!(receipt.forfeited_nominal, U256::ZERO);
        assert_eq!(
            receipt.retirement,
            outbe_compressed_entities::RetirementOutcome::NotPresent
        );

        let cycle: Cycle<'_> = handle.contract::<Cycle<'_>>();
        assert_eq!(
            cycle
                .last_executed_at
                .read(&TriggerId::ProtocolCycle.as_u32())
                .unwrap(),
            fire_at
        );
        assert_eq!(
            cycle
                .last_executed_block_number
                .read(&TriggerId::ProtocolCycle.as_u32())
                .unwrap(),
            next_block
        );
    });
}

#[test]
fn genesis_midday_first_cycle_at_next_midnight_settles_genesis_day() {
    // Genesis at 10:00 UTC on day D. First CycleTick fires at 00:00:01 UTC
    // on day D+1. prev_day = D = genesis_utc_day -> day_number = 0 -> Ok.
    // This is the production scenario that was broken when genesis_utc_day
    // was derived from block 0 timestamp at 10:00 instead of genesisTime.
    const DAY_D_MIDNIGHT: u64 = GENESIS_TS; // 2024-01-01 00:00:00
    const DAY_D_10AM: u64 = DAY_D_MIDNIGHT + 10 * 3600; // 10:00 UTC

    let mut storage = cycle_storage();
    storage.enter(|handle| {
        // Block 1 at 10:00 - genesis anchor records genesis_utc_day = day D.
        let ctx_anchor = BlockRuntimeContext::new(block_ctx(1, DAY_D_10AM), handle.clone());
        anchor_genesis(&ctx_anchor);
        run_cycle_lifecycle(&ctx_anchor).unwrap();
        let canonical_wwd = outbe_primitives::time::WorldwideDay::new(20_240_102);
        assert_eq!(
            outbe_metadosis::api::worldwide_days(ctx_anchor.storage.clone())
                .unwrap()
                .into_iter()
                .map(|day| day.worldwide_day)
                .collect::<Vec<_>>(),
            vec![canonical_wwd],
            "block 1 at the UTC+14 boundary must create only the canonical WWD"
        );

        // Block at 00:00:01 UTC day D+1 - CycleTick fires.
        // prev_day = D = genesis_utc_day -> day_number_since_genesis = 0.
        let fire_ts = DAY_D_MIDNIGHT + SECONDS_PER_DAY + 1;
        let ctx_fire = BlockRuntimeContext::new(block_ctx(2, fire_ts), handle);
        account_parent(&ctx_fire, 2);
        run_cycle_lifecycle(&ctx_fire).unwrap();

        assert_eq!(
            outbe_metadosis::api::worldwide_days(ctx_fire.storage.clone())
                .unwrap()
                .into_iter()
                .map(|day| day.worldwide_day)
                .collect::<Vec<_>>(),
            vec![
                outbe_primitives::time::WorldwideDay::new(20_240_101),
                canonical_wwd,
            ],
            "the first UTC midnight must retain the canonical genesis WWD and add only the explicitly settled previous UTC day"
        );

        let rewards = ctx_fire
            .storage
            .contract::<outbe_rewards::schema::Rewards<'_>>();
        let genesis_day = rewards.genesis_utc_day.read().unwrap();
        assert_eq!(genesis_day, 20_240_101, "genesis_utc_day = day D");
        assert!(
            rewards.daily_settled.read(&genesis_day).unwrap(),
            "CycleTick must settle genesis day (day_number=0)"
        );
    });
}
