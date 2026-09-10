//! - executor ordering contract.
//!
//! Pins the invariant that backs the slashindicator precompile's epoch-lag
//! admissibility: `ValidatorSet.epoch_number` names the committee that was
//! actually activated by a certified `BoundaryOutcome`, not the epoch whose
//! nominal height has merely been reached.
//!
//! The behaviour test here drives `run_outbe_pre_execution_hooks`
//! against a primed in-memory storage provider and asserts that reaching the
//! nominal boundary without carrying a certified `BoundaryOutcome` leaves the
//! activated epoch untouched. The receipt-visible BoundaryOutcome path owns
//! the later atomic epoch/member/snapshot switch before user transactions.

use alloy_primitives::{Address, U256};
use outbe_evm::executor::run_outbe_pre_execution_hooks;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::EpochSnapshot;

const CHAIN_ID: u64 = 1;
const EPOCH_LENGTH: u32 = 10;
const PROPOSER: Address = Address::ZERO;

/// Seeds the minimum on-chain state the pre-exec hook chain needs to reach a
/// nominal epoch boundary:
///   * `config_epoch_length_blocks = EPOCH_LENGTH`
///   * `epoch_start_block = 0`
///   * `epoch_number = 1` (the currently activated epoch)
fn seed_validator_set(storage: StorageHandle, initial_epoch: u64) {
    let mut vs = ValidatorSet::new(storage.clone());
    vs.test_set_epoch_snapshot(EpochSnapshot {
        number: U256::from(initial_epoch),
        start_timestamp: 0,
        start_block: 0,
        length_blocks: EPOCH_LENGTH,
    })
    .unwrap();
    // Seed COEN/840 pair + 1.0 rate so begin-block NOD/GEM/INTEX promotion
    // reads a registered pair instead of reverting "pair not registered".
    outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR).unwrap();
    outbe_oracle::api::set_exchange_rate(
        storage,
        Address::ZERO,
        outbe_oracle::api::DAY_TYPE_PAIR,
        U256::from(1_000_000u64),
        0,
        0,
    )
    .unwrap();
}

#[test]
fn nominal_epoch_boundary_without_certified_outcome_keeps_activated_epoch() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let boundary_block = EPOCH_LENGTH as u64;
    provider.set_block_number(boundary_block);

    provider.enter(|storage| {
        // (1) Seed the boundary-crossing epoch state.
        seed_validator_set(storage.clone(), 1);

        // Sanity: epoch_number BEFORE the pre-exec hook chain is the
        // pre-bump value.
        let vs_before = ValidatorSet::new(storage.clone());
        let epoch_before = vs_before.epoch_snapshot().unwrap();
        assert_eq!(
            epoch_before.number,
            U256::from(1u64),
            "pre-condition: epoch_number must be 1 before pre-exec",
        );
        assert_eq!(
            epoch_before.start_block, 0,
            "pre-condition: epoch_start_block must be 0 before pre-exec",
        );

        // (2) Drive the pre-execution hook chain. `genesis_validators
        // = None` because we are well past block 1; the genesis-state
        // validation branch is gated on `block_number <= 1`.
        let ctx = BlockRuntimeContext::new(
            BlockContext::new(
                boundary_block,
                /*timestamp=*/ 1_700_000_000,
                CHAIN_ID,
                PROPOSER,
                Vec::new(),
            ),
            storage.clone(),
        );
        run_outbe_pre_execution_hooks(&ctx, None).expect("pre-exec hook chain must succeed");

        // (3) The scheduled height is not activation authority. Until the
        // receipt-visible BoundaryOutcome executes, every consumer - including
        // OCOMP - must continue to observe the old epoch and its snapshot.
        let vs_after = ValidatorSet::new(storage);
        let epoch_after = vs_after.epoch_snapshot().unwrap();
        assert_eq!(
            epoch_after.number,
            U256::from(1u64),
            "nominal boundary without certified outcome must not advance epoch",
        );
        assert_eq!(
            epoch_after.start_block, 0,
            "nominal boundary without certified outcome must not move epoch anchor",
        );
    });
}

/// Companion negative test: an ordinary mid-epoch block also leaves the
/// activated epoch untouched.
#[test]
fn transition_epoch_does_not_fire_inside_an_epoch() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let mid_epoch_block = (EPOCH_LENGTH as u64) / 2;
    provider.set_block_number(mid_epoch_block);

    provider.enter(|storage| {
        seed_validator_set(storage.clone(), 1);

        let ctx = BlockRuntimeContext::new(
            BlockContext::new(
                mid_epoch_block,
                1_700_000_000,
                CHAIN_ID,
                PROPOSER,
                Vec::new(),
            ),
            storage.clone(),
        );
        run_outbe_pre_execution_hooks(&ctx, None).expect("pre-exec hook chain must succeed");

        let vs_after = ValidatorSet::new(storage);
        let epoch_after = vs_after.epoch_snapshot().unwrap();
        assert_eq!(
            epoch_after.number,
            U256::from(1u64),
            "mid-epoch block must NOT bump epoch_number",
        );
        assert_eq!(
            epoch_after.start_block, 0,
            "mid-epoch block must NOT advance epoch_start_block",
        );
    });
}
