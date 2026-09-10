//! A validator reward Gem is priced by the day it rewards, and no day can lose one.

use alloy_primitives::{Address, U256};
use outbe_primitives::{
    block::{BlockContext, BlockRuntimeContext},
    storage::hashmap::HashMapStorageProvider,
};
use outbe_rewards::api::{
    deliver_oldest_reward_gem_batch, prepare_daily_validator_gem_batch, RewardGemDeliveryOutcome,
};

const CHAIN_ID: u64 = 1;
const GENESIS_TS: u64 = 1_704_067_200;
const REWARD_DAY: u32 = 20_240_101;
const VOTER: Address = Address::repeat_byte(0x5a);
const LOAD: u64 = 90;

fn one_coen840() -> U256 {
    U256::from(1_000_000u64)
}

/// Registers COEN/840, publishes `live_quote` on it and closes days up to
/// `last_finalized_day`.
fn seed_oracle(ctx: &BlockRuntimeContext, live_quote: U256, last_finalized_day: u32) {
    outbe_oracle::api::register_pair(ctx.storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
        .unwrap();
    outbe_oracle::api::set_exchange_rate(
        ctx.storage.clone(),
        Address::ZERO,
        outbe_oracle::api::DAY_TYPE_PAIR,
        live_quote,
        ctx.block.block_number,
        ctx.block.timestamp,
    )
    .unwrap();
    let oracle = outbe_oracle::schema::OracleContract::new(ctx.storage.clone());
    oracle.reference_currencies.push(840u16).unwrap();
    oracle
        .utc_day_vwap_last_finalized
        .write(last_finalized_day)
        .unwrap();
}

/// Publishes `vwap` as `day`'s finalized COEN/840 VWAP.
fn seed_day_vwap(ctx: &BlockRuntimeContext, day: u32, vwap: U256) {
    let index = outbe_oracle::api::coen_pair_index_opt(ctx.storage.clone(), 840)
        .unwrap()
        .expect("COEN/840 registered");
    outbe_oracle::schema::OracleContract::new(ctx.storage.clone())
        .utc_day_vwap_value
        .get_nested(&day)
        .write(&index, vwap)
        .unwrap();
}

fn prepare(ctx: &BlockRuntimeContext) {
    prepare_daily_validator_gem_batch(ctx, REWARD_DAY, U256::from(LOAD), &[(VOTER, 1)]).unwrap();
}

/// The entry price the voter's delivered gem carries.
fn delivered_entry_price(ctx: &BlockRuntimeContext) -> U256 {
    let gem = outbe_gem::GemContract::new(ctx.storage.clone());
    let gem_id = gem.token_of_owner_by_index(VOTER, 0).unwrap();
    outbe_gem::api::get_gem(&ctx.storage, gem_id)
        .unwrap()
        .unwrap()
        .entry_price_minor
}

fn with_ctx<R>(f: impl FnOnce(&BlockRuntimeContext) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(
            BlockContext::new(1, GENESIS_TS + 60, CHAIN_ID, Address::ZERO, Vec::new()),
            handle,
        );
        outbe_rewards::runtime::ensure_genesis_anchor(&ctx).unwrap();
        f(&ctx)
    })
}

#[test]
fn a_batch_prices_off_the_day_it_rewards() {
    with_ctx(|ctx| {
        // The live quote and the day's VWAP differ, so only the reward day's own
        // price satisfies the assertion.
        seed_oracle(ctx, U256::from(9u64) * one_coen840(), REWARD_DAY);
        seed_day_vwap(ctx, REWARD_DAY, U256::from(2u64) * one_coen840());

        prepare(ctx);
        deliver_oldest_reward_gem_batch(ctx).unwrap();

        assert_eq!(delivered_entry_price(ctx), U256::from(2u64) * one_coen840());
    });
}

#[test]
fn a_day_closed_without_a_price_falls_back_to_the_live_quote() {
    with_ctx(|ctx| {
        // No day carries a VWAP, so the reward must not be lost to that.
        seed_oracle(ctx, U256::from(9u64) * one_coen840(), REWARD_DAY);

        prepare(ctx);
        deliver_oldest_reward_gem_batch(ctx).unwrap();

        assert_eq!(delivered_entry_price(ctx), U256::from(9u64) * one_coen840());
    });
}

#[test]
fn a_batch_waits_while_its_day_is_not_closed() {
    with_ctx(|ctx| {
        // An unclosed day is not an unpriced one: wait for it rather than reach
        // past it to the live quote.
        seed_oracle(ctx, U256::from(9u64) * one_coen840(), REWARD_DAY - 1);

        prepare(ctx);
        assert!(matches!(
            deliver_oldest_reward_gem_batch(ctx).unwrap(),
            RewardGemDeliveryOutcome::PendingRate {
                reward_utc_day: REWARD_DAY
            }
        ));
        assert_eq!(
            outbe_gem::GemContract::new(ctx.storage.clone())
                .balance_of(VOTER)
                .unwrap(),
            0
        );
    });
}
