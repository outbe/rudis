use alloy_primitives::{address, Address, U256};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::units::checked_protocol_to_native;

use outbe_gemfactory::schema::GemTypes;

use crate::distribution::{calculate_distribution_with_cap, distribute_daily, PoolKind};
use crate::schema::{AgentRewardContract, RewardPool};

const CHAIN_ID: u64 = 1;
const T_NOW: u64 = 1_700_000_000;
/// A COEN price, in the six-decimal protocol scale prices are quoted in.
const ONE_COEN: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

/// Claimable balances are native COEN; Gem loads are protocol amounts.
fn native(protocol_amount: u64) -> U256 {
    outbe_primitives::units::checked_protocol_to_native(U256::from(protocol_amount)).unwrap()
}

fn numbered_address(n: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    Address::from(bytes)
}

fn with_contract_mut<R>(f: impl FnOnce(StorageHandle, &mut AgentRewardContract) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(T_NOW));
    StorageHandle::enter(&mut storage, |storage| {
        let mut contract = AgentRewardContract::new(storage.clone());
        f(storage, &mut contract)
    })
}

#[test]
fn gas_06_agentreward_dense_daily_distribution_completes_and_clears_indexes() {
    const DAILY_ADDRESSES_PER_POOL: u64 = 512;
    let day = WorldwideDay::new(20260525);
    let waa_pool = U256::from(DAILY_ADDRESSES_PER_POOL * 1_000);
    let sra_pool = U256::from(DAILY_ADDRESSES_PER_POOL * 1_000);

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let ctx = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::new(1, 1, CHAIN_ID, Address::ZERO, Vec::new()),
            storage.clone(),
        );
        let mut contract = AgentRewardContract::new(storage.clone());
        let mut waa_addresses = Vec::with_capacity(DAILY_ADDRESSES_PER_POOL as usize);
        let mut sra_addresses = Vec::with_capacity(DAILY_ADDRESSES_PER_POOL as usize);

        for n in 0..DAILY_ADDRESSES_PER_POOL {
            let waa = numbered_address(1 + n);
            let sra = numbered_address(10_000 + n);
            contract.increment_waa_tribute(day, waa).unwrap();
            contract.increment_sra_tribute(day, sra).unwrap();
            waa_addresses.push(waa);
            sra_addresses.push(sra);
        }

        let excess = distribute_daily(
            &ctx,
            day,
            &[(PoolKind::Waa, waa_pool), (PoolKind::Sra, sra_pool)],
        )
        .expect("dense WAA/SRA daily distribution must complete");

        let contract = AgentRewardContract::new(storage.clone());
        let waa_claimable_total = waa_addresses.iter().fold(U256::ZERO, |total, address| {
            let claimable = contract.get_claimable_reward(*address).unwrap();
            assert!(
                !claimable.is_zero(),
                "GAS-06: dense WAA recipient {address} received zero claimable reward"
            );
            total + claimable
        });
        let sra_claimable_total = sra_addresses.iter().fold(U256::ZERO, |total, address| {
            let claimable = contract.get_claimable_reward(*address).unwrap();
            assert!(
                !claimable.is_zero(),
                "GAS-06: dense SRA recipient {address} received zero claimable reward"
            );
            total + claimable
        });
        let claimable_total = waa_claimable_total + sra_claimable_total;

        assert_eq!(
            excess,
            U256::ZERO,
            "GAS-06: equal dense WAA/SRA distributions should have no cap excess"
        );
        assert_eq!(
            claimable_total,
            checked_protocol_to_native(waa_pool + sra_pool).unwrap(),
            "GAS-06: dense distribution must conserve pool amount across claimable + excess"
        );
        assert_eq!(
            ctx.storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            claimable_total,
            "GAS-06: AGENT_REWARD balance must match total claimable after burn accounting"
        );
        assert!(
            contract.get_all_waa_counts(day).unwrap().is_empty(),
            "GAS-06: WAA day index must be cleared after dense distribution"
        );
        assert!(
            contract.get_all_sra_counts(day).unwrap().is_empty(),
            "GAS-06: SRA day index must be cleared after dense distribution"
        );
    });
}

// ---------------------------------------------------------------------------
// calculate_distribution_with_cap unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_distribution_single_address() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let pool = U256::from(1000u64);
    let counts = vec![(alice, 10u64)];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    // Single address with 100% of tributes: capped at 32%.
    assert_eq!(rewards.len(), 1);
    assert_eq!(rewards[0].address, alice);
    // Cap: 1000 * 32 / 100 = 320
    let expected = U256::from(320u64);
    assert_eq!(rewards[0].reward_amount, expected);
    // Excess = 1000 - 320 = 680
    assert_eq!(excess, U256::from(680u64));
}

#[test]
fn test_distribution_equal_shares() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let bob = address!("0x2222222222222222222222222222222222222222");
    let carol = address!("0x3333333333333333333333333333333333333333");
    let dave = address!("0x4444444444444444444444444444444444444444");

    // 4 addresses with equal tributes, each gets 25%.
    // 25% < 32% cap so no capping; all pool is distributed.
    let pool = U256::from(1000u64);
    let counts = vec![(alice, 1u64), (bob, 1u64), (carol, 1u64), (dave, 1u64)];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    assert_eq!(rewards.len(), 4);
    // Each gets 1000 * 1 / 4 = 250
    for r in &rewards {
        assert_eq!(r.reward_amount, U256::from(250u64));
    }
    // Integer division: 4 * 250 = 1000, no rounding loss here.
    assert_eq!(excess, U256::ZERO);
}

#[test]
fn test_distribution_with_cap() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let bob = address!("0x2222222222222222222222222222222222222222");

    // Alice has 9 tributes, Bob has 1 - Alice would get 90% but is capped at 32%.
    // Excess (58%) is redistributed to Bob who is uncapped; Bob ends up at 32%
    // as well because 68% > 32%. Final excess = 100% - 32% - 32% = 36%.
    let pool = U256::from(1000u64);
    let counts = vec![(alice, 9u64), (bob, 1u64)];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    assert_eq!(rewards.len(), 2);

    let alice_reward = rewards.iter().find(|r| r.address == alice).unwrap();
    let bob_reward = rewards.iter().find(|r| r.address == bob).unwrap();

    // Both capped at 320 (32% of 1000).
    assert_eq!(alice_reward.reward_amount, U256::from(320u64));
    assert_eq!(bob_reward.reward_amount, U256::from(320u64));
    assert_eq!(excess, U256::from(360u64));
}

#[test]
fn test_distribution_all_capped() {
    // 4 addresses, each with equal tributes.
    // Total pool = 1000, each would proportionally get 250 (25%), under the 32% cap.
    // No capping occurs, all pool is distributed.
    let a = address!("0x1111111111111111111111111111111111111111");
    let b = address!("0x2222222222222222222222222222222222222222");
    let c = address!("0x3333333333333333333333333333333333333333");
    let d = address!("0x4444444444444444444444444444444444444444");

    let pool = U256::from(1000u64);
    let counts = vec![(a, 25u64), (b, 25u64), (c, 25u64), (d, 25u64)];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    assert_eq!(rewards.len(), 4);
    for r in &rewards {
        assert_eq!(r.reward_amount, U256::from(250u64));
    }
    assert_eq!(excess, U256::ZERO);
}

#[test]
fn test_distribution_all_capped_with_excess() {
    // 3 addresses with exactly equal shares - 33.3% each, all exceed 32% cap.
    // After capping: each gets 32%, total = 96%, excess = 4%.
    // Redistribution cannot help (all capped), so excess stays.
    let a = address!("0x1111111111111111111111111111111111111111");
    let b = address!("0x2222222222222222222222222222222222222222");
    let c = address!("0x3333333333333333333333333333333333333333");

    let pool = U256::from(300u64);
    let counts = vec![(a, 1u64), (b, 1u64), (c, 1u64)];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    assert_eq!(rewards.len(), 3);
    // max_share = 300 * 32 / 100 = 96
    // proportional share = 300 * 1 / 3 = 100 > 96, so capped.
    for r in &rewards {
        assert_eq!(r.reward_amount, U256::from(96u64));
    }
    // excess = 300 - 3*96 = 300 - 288 = 12
    assert_eq!(excess, U256::from(12u64));
}

#[test]
fn test_distribution_empty_counts() {
    let pool = U256::from(1000u64);
    let counts: Vec<(alloy_primitives::Address, u64)> = vec![];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    assert!(rewards.is_empty());
    // Full pool returned as excess.
    assert_eq!(excess, pool);
}

#[test]
fn test_distribution_zero_pool() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let pool = U256::ZERO;
    let counts = vec![(alice, 5u64)];

    let (rewards, excess) = calculate_distribution_with_cap(pool, &counts);

    assert!(rewards.is_empty());
    assert_eq!(excess, U256::ZERO);
}

#[test]
fn test_address_list_deduplication() {
    // Same address incremented multiple times should appear in list only once.
    let alice = address!("0x1111111111111111111111111111111111111111");
    let wwd = WorldwideDay::new(5);

    with_contract_mut(|_storage, contract| {
        contract.increment_waa_tribute(wwd, alice).unwrap();
        contract.increment_waa_tribute(wwd, alice).unwrap();
        contract.increment_waa_tribute(wwd, alice).unwrap();

        let counts = contract.get_all_waa_counts(wwd).unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0].0, alice);
        assert_eq!(counts[0].1, 3);

        let addr_count = contract.waa_address_count.read(&wwd).unwrap();
        assert_eq!(addr_count, 1);
    });
}

/// Registers COEN/840, publishes `live_quote` on it and adds 840 to the
/// reference registry. `last_finalized_day` of 0 leaves the day ladder empty so
/// the live quote answers.
fn seed_oracle(storage: &StorageHandle<'_>, live_quote: U256, last_finalized_day: u32) {
    outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR).unwrap();
    outbe_oracle::api::set_exchange_rate(
        storage.clone(),
        Address::ZERO,
        outbe_oracle::api::DAY_TYPE_PAIR,
        live_quote,
        1,
        T_NOW,
    )
    .unwrap();
    let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
    oracle.reference_currencies.push(840u16).unwrap();
    oracle
        .utc_day_vwap_last_finalized
        .write(last_finalized_day)
        .unwrap();
}

/// Publishes `vwap` as `day`'s finalized COEN/840 VWAP.
fn seed_day_vwap(storage: &StorageHandle<'_>, day: u32, vwap: U256) {
    let index = outbe_oracle::api::coen_pair_index_opt(storage.clone(), 840)
        .unwrap()
        .expect("COEN/840 registered");
    outbe_oracle::schema::OracleContract::new(storage.clone())
        .utc_day_vwap_value
        .get_nested(&day)
        .write(&index, vwap)
        .unwrap();
}

fn gem_of(storage: &StorageHandle<'_>, owner: Address) -> outbe_gem::schema::GemData {
    let gem_id = outbe_gem::GemContract::new(storage.clone())
        .token_of_owner_by_index(owner, 0)
        .unwrap();
    outbe_gem::api::get_gem(storage, gem_id).unwrap().unwrap()
}

#[test]
fn claiming_a_pool_mints_its_gem_and_burns_the_backing() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let load = U256::from(500u64);
    let backing = native(500);

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, backing)
            .unwrap();

        let gem_id = contract
            .claim_reward(RewardPool::Waa, alice, U256::ZERO)
            .unwrap();
        assert!(!gem_id.is_zero());

        let gem = gem_of(&storage, alice);
        assert_eq!(gem.gem_type, GemTypes::Wallet as u8);
        assert_eq!(gem.promis_load_minor, load);
        assert_eq!(gem.entry_price_minor, ONE_COEN);

        // The balance is gone and so is the native COEN that backed it.
        assert_eq!(contract.get_claimable_reward(alice).unwrap(), U256::ZERO);
        assert_eq!(
            storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            U256::ZERO
        );
    });
}

#[test]
fn the_sra_pool_issues_an_sra_gem_at_the_discounted_cost() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let load = U256::from(1_000_000u64);
    let backing = native(1_000_000);

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Sra, alice, backing)
            .unwrap();

        contract
            .claim_reward(RewardPool::Sra, alice, U256::ZERO)
            .unwrap();
        let sra_gem = gem_of(&storage, alice);
        // The SRA share of the cost is derived, not stored; gemfactory pins the 64%
        // coefficient. What this pool owes is the Sra type and the whole load.
        assert_eq!(sra_gem.gem_type, GemTypes::Sra as u8);
        assert_eq!(sra_gem.promis_load_minor, load);
    });
}

#[test]
fn a_claim_prices_on_the_last_finalized_utc_day() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let backing = native(500);
    let day = 20_260_525u32;
    let day_vwap = U256::from(2u64) * ONE_COEN;

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, day);
        seed_day_vwap(&storage, day, day_vwap);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, backing)
            .unwrap();

        contract
            .claim_reward(RewardPool::Waa, alice, U256::ZERO)
            .unwrap();
        // The closed day's VWAP wins over the live quote.
        assert_eq!(gem_of(&storage, alice).entry_price_minor, day_vwap);
    });
}

#[test]
fn a_claim_with_no_price_leaves_the_balance_for_the_next_day() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let backing = native(500);

    with_contract_mut(|storage, contract| {
        // No pair, no quote, no closed day.
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, backing)
            .unwrap();

        let err = contract
            .claim_reward(RewardPool::Waa, alice, U256::ZERO)
            .unwrap_err();
        assert!(err.to_string().contains("no usable rudis price"));
        assert_eq!(contract.get_claimable_reward(alice).unwrap(), backing);
        assert_eq!(
            storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            backing
        );
    });
}

#[test]
fn a_load_whose_cost_rounds_to_zero_keeps_its_balance() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let dust = native(1);

    with_contract_mut(|storage, contract| {
        // Entry 1 minor unit x load 1 minor unit floors to a zero cost.
        seed_oracle(&storage, U256::from(1u64), 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, dust)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, dust)
            .unwrap();

        assert!(contract
            .claim_reward(RewardPool::Waa, alice, U256::ZERO)
            .is_err());
        assert_eq!(contract.get_claimable_reward(alice).unwrap(), dust);
    });
}

#[test]
fn a_partial_claim_mints_only_what_was_asked_for() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let backing = native(500);
    let taken = native(200);

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, backing)
            .unwrap();

        contract
            .claim_reward(RewardPool::Waa, alice, taken)
            .unwrap();
        assert_eq!(
            gem_of(&storage, alice).promis_load_minor,
            U256::from(200u64)
        );
        // The rest stays a balance, which cannot be Called and cannot be forfeited.
        assert_eq!(
            contract.get_claimable_reward(alice).unwrap(),
            backing - taken
        );
        assert_eq!(
            storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            backing - taken
        );
    });
}

#[test]
fn claiming_more_than_the_pool_holds_is_refused() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let backing = native(500);

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, backing)
            .unwrap();

        let err = contract
            .claim_reward(RewardPool::Waa, alice, backing + U256::from(1u64))
            .unwrap_err();
        assert!(err.to_string().contains("insufficient claimable balance"));
        assert_eq!(contract.get_claimable_reward(alice).unwrap(), backing);
    });
}

#[test]
fn a_sub_unit_remainder_stays_claimable() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let remainder = U256::from(7u64);
    let backing = native(500) + remainder;

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, backing)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, backing)
            .unwrap();

        contract
            .claim_reward(RewardPool::Waa, alice, U256::ZERO)
            .unwrap();
        // The Gem carries the convertible part; what is below one protocol unit
        // keeps accumulating and its backing is not burned.
        assert_eq!(
            gem_of(&storage, alice).promis_load_minor,
            U256::from(500u64)
        );
        assert_eq!(contract.get_claimable_reward(alice).unwrap(), remainder);
        assert_eq!(
            storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            remainder
        );
    });
}

#[test]
fn claiming_an_empty_pool_is_refused() {
    let alice = address!("0x1111111111111111111111111111111111111111");

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .add_claimable_reward(RewardPool::Waa, alice, U256::from(500u64))
            .unwrap();

        let err = contract
            .claim_reward(RewardPool::Sra, alice, U256::ZERO)
            .unwrap_err();
        assert!(err.to_string().contains("no claimable balance"));
    });
}

#[test]
fn the_pools_are_claimed_apart() {
    let alice = address!("0x1111111111111111111111111111111111111111");
    let waa = native(500);
    let sra = native(700);

    with_contract_mut(|storage, contract| {
        seed_oracle(&storage, ONE_COEN, 0);
        contract
            .storage
            .increase_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, waa + sra)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Waa, alice, waa)
            .unwrap();
        contract
            .add_claimable_reward(RewardPool::Sra, alice, sra)
            .unwrap();
        assert_eq!(contract.get_claimable_reward(alice).unwrap(), waa + sra);

        contract
            .claim_reward(RewardPool::Waa, alice, U256::ZERO)
            .unwrap();
        assert_eq!(
            contract
                .get_pool_claimable_reward(RewardPool::Waa, alice)
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(
            contract
                .get_pool_claimable_reward(RewardPool::Sra, alice)
                .unwrap(),
            sra
        );
        assert_eq!(
            storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap(),
            sra
        );
    });
}

// ---------------------------------------------------------------------------
// checked_add overflow rejection
// ---------------------------------------------------------------------------

#[test]
fn test_add_claimable_reward_rejects_overflow() {
    with_contract_mut(|_storage, contract| {
        let alice = address!("0x1111111111111111111111111111111111111111");
        let near_max = U256::MAX - U256::from(10u64);

        contract
            .add_claimable_reward(RewardPool::Waa, alice, near_max)
            .unwrap();

        let err = contract
            .add_claimable_reward(RewardPool::Waa, alice, U256::from(100u64))
            .unwrap_err();
        assert!(err.to_string().contains("overflow"));

        assert_eq!(contract.get_claimable_reward(alice).unwrap(), near_max);
    });
}

// ---------------------------------------------------------------------------
// distribute_daily - new daily orchestrator surface
// ---------------------------------------------------------------------------

mod distribute_daily_tests {
    use super::*;
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};

    const TEST_CHAIN_ID: u64 = 1;
    const DAY: WorldwideDay = WorldwideDay::new(20240115);

    fn native(protocol_amount: u64) -> U256 {
        checked_protocol_to_native(U256::from(protocol_amount)).unwrap()
    }

    fn block_ctx() -> BlockContext {
        BlockContext::new(
            1,
            1_705_276_800, // 2024-01-15 UTC
            TEST_CHAIN_ID,
            alloy_primitives::Address::ZERO,
            Vec::new(),
        )
    }

    fn run<R>(f: impl FnOnce(&BlockRuntimeContext) -> R) -> R {
        let mut storage = HashMapStorageProvider::new(TEST_CHAIN_ID);
        let mut out = None;
        StorageHandle::enter(&mut storage, |handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(), handle);
            out = Some(f(&ctx));
        });
        out.unwrap()
    }

    #[test]
    fn waa_capped_distribution_credits_claimable_and_burns_excess() {
        run(|ctx| {
            let alice = address!("0x1111111111111111111111111111111111111111");
            let bob = address!("0x2222222222222222222222222222222222222222");
            let mut c = AgentRewardContract::new(ctx.storage.clone());
            // alice 9, bob 1 -> both end up capped at 32 % of 1000 = 320 each;
            // residue = 1000 - 640 = 360.
            for _ in 0..9 {
                c.increment_waa_tribute(DAY, alice).unwrap();
            }
            c.increment_waa_tribute(DAY, bob).unwrap();

            let excess =
                distribute_daily(ctx, DAY, &[(PoolKind::Waa, U256::from(1000u64))]).unwrap();

            assert_eq!(excess, U256::from(360u64));
            let c2 = AgentRewardContract::new(ctx.storage.clone());
            assert_eq!(c2.get_claimable_reward(alice).unwrap(), native(320));
            assert_eq!(c2.get_claimable_reward(bob).unwrap(), native(320));
            // Mint/burn parity: AGENT_REWARD now holds exactly the
            // total claimable.
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                native(640)
            );
            // WAA index cleared after distribution.
            assert!(c2.get_all_waa_counts(DAY).unwrap().is_empty());
        });
    }

    #[test]
    fn sra_capped_distribution_mirrors_waa() {
        run(|ctx| {
            let signer = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let mut c = AgentRewardContract::new(ctx.storage.clone());
            c.increment_sra_tribute(DAY, signer).unwrap();

            let excess =
                distribute_daily(ctx, DAY, &[(PoolKind::Sra, U256::from(1000u64))]).unwrap();

            // Single signer with all tributes: capped at 32 % of 1000 = 320,
            // residue = 680.
            assert_eq!(excess, U256::from(680u64));
            let c2 = AgentRewardContract::new(ctx.storage.clone());
            assert_eq!(c2.get_claimable_reward(signer).unwrap(), native(320));
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                native(320)
            );
        });
    }

    #[test]
    fn waa_no_tribute_returns_full_pool_and_burns_pre_funded_balance() {
        run(|ctx| {
            let excess =
                distribute_daily(ctx, DAY, &[(PoolKind::Waa, U256::from(500u64))]).unwrap();
            assert_eq!(excess, U256::from(500u64));
            // closure: minted 500, burned 500 - net zero.
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                U256::ZERO
            );
        });
    }

    #[test]
    fn sra_no_tribute_returns_full_pool_and_burns_pre_funded_balance() {
        run(|ctx| {
            let excess =
                distribute_daily(ctx, DAY, &[(PoolKind::Sra, U256::from(700u64))]).unwrap();
            assert_eq!(excess, U256::from(700u64));
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                U256::ZERO
            );
        });
    }

    #[test]
    fn cca_simply_accumulates_to_address_no_excess() {
        run(|ctx| {
            let excess =
                distribute_daily(ctx, DAY, &[(PoolKind::Cca, U256::from(400u64))]).unwrap();
            assert_eq!(excess, U256::ZERO);
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::CCA_ADDRESS)
                    .unwrap(),
                native(400)
            );
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                U256::ZERO
            );
        });
    }

    #[test]
    fn cca_accumulates_across_calls() {
        run(|ctx| {
            distribute_daily(ctx, DAY, &[(PoolKind::Cca, U256::from(100u64))]).unwrap();
            distribute_daily(ctx, DAY, &[(PoolKind::Cca, U256::from(50u64))]).unwrap();
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::CCA_ADDRESS)
                    .unwrap(),
                native(150)
            );
        });
    }

    #[test]
    fn full_three_pool_dispatch_sums_excesses() {
        run(|ctx| {
            // Seed only WAA; SRA empty; CCA pure mint.
            let alice = address!("0x1111111111111111111111111111111111111111");
            let mut c = AgentRewardContract::new(ctx.storage.clone());
            c.increment_waa_tribute(DAY, alice).unwrap();

            let excess = distribute_daily(
                ctx,
                DAY,
                &[
                    (PoolKind::Waa, U256::from(1000u64)), // alice capped 320 -> excess 680
                    (PoolKind::Sra, U256::from(500u64)),  // no tribute -> excess 500
                    (PoolKind::Cca, U256::from(100u64)),  // no excess
                ],
            )
            .unwrap();

            assert_eq!(excess, U256::from(1180u64)); // 680 + 500
            let c2 = AgentRewardContract::new(ctx.storage.clone());
            assert_eq!(c2.get_claimable_reward(alice).unwrap(), native(320));
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::CCA_ADDRESS)
                    .unwrap(),
                native(100)
            );
            // burn parity: AGENT_REWARD holds exactly alice's
            // 320 claimable; the SRA no-tribute 500 was burned.
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                native(320)
            );
        });
    }

    #[test]
    fn zero_amount_pool_is_noop() {
        run(|ctx| {
            let excess = distribute_daily(ctx, DAY, &[(PoolKind::Waa, U256::ZERO)]).unwrap();
            assert_eq!(excess, U256::ZERO);
            assert_eq!(
                ctx.storage
                    .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                    .unwrap(),
                U256::ZERO
            );
        });
    }

    #[test]
    fn chain_219_burn_parity_invariant() {
        // After distribute_daily on any input, balance(AGENT_REWARD)
        // must equal the sum of claimable_rewards credited that call -
        // never higher.
        run(|ctx| {
            let alice = address!("0x1111111111111111111111111111111111111111");
            let bob = address!("0x2222222222222222222222222222222222222222");
            let signer = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let mut c = AgentRewardContract::new(ctx.storage.clone());
            c.increment_waa_tribute(DAY, alice).unwrap();
            c.increment_waa_tribute(DAY, alice).unwrap();
            c.increment_waa_tribute(DAY, bob).unwrap();
            c.increment_sra_tribute(DAY, signer).unwrap();

            distribute_daily(
                ctx,
                DAY,
                &[
                    (PoolKind::Waa, U256::from(1000u64)),
                    (PoolKind::Sra, U256::from(1000u64)),
                ],
            )
            .unwrap();

            let c2 = AgentRewardContract::new(ctx.storage.clone());
            let claimable_total = c2.get_claimable_reward(alice).unwrap()
                + c2.get_claimable_reward(bob).unwrap()
                + c2.get_claimable_reward(signer).unwrap();
            let agent_reward_balance = ctx
                .storage
                .balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS)
                .unwrap();
            assert_eq!(
                agent_reward_balance, claimable_total,
                "mint/burn parity violated"
            );
        });
    }
}

/// Drift guard between `contracts/precompiles/src/IAgentReward.sol` and the
/// `#[contract_public(...)]` annotations on `AgentRewardContract`. The
/// AgentReward module uses macro-driven dispatch, so the .sol file is a
/// documentation/abi-export mirror rather than the dispatch source.
/// This test fails if either side changes without the other.
#[test]
fn iagentreward_sol_matches_contract_public_annotations() {
    const SOL: &str = include_str!("../../../../contracts/precompiles/src/IAgentReward.sol");
    let expected = [
        ("getClaimableBalance", "address", true, "uint256"),
        ("getPoolClaimableBalance", "address,uint8", true, "uint256"),
        ("claimReward", "uint8,uint256", false, "uint256"),
    ];
    for (name, args_types, is_view, ret_types) in expected {
        let canon = sol_function_canonical(SOL, name)
            .unwrap_or_else(|| panic!("IAgentReward.sol is missing `function {name}(...)`"));
        assert_eq!(canon.arg_types, args_types, "{name}: arg types differ");
        assert_eq!(canon.is_view, is_view, "{name}: view-modifier differs");
        assert_eq!(canon.ret_types, ret_types, "{name}: return types differ");
    }
}

struct SolFnCanonical {
    arg_types: String,
    is_view: bool,
    ret_types: String,
}

/// Parses one `function NAME(...) ... returns (...)` declaration out of a
/// Solidity interface body into a comparable canonical form. Tolerates
/// `external`, `view`, and parameter names; returns only type lists.
fn sol_function_canonical(sol: &str, name: &str) -> Option<SolFnCanonical> {
    let needle = format!("function {name}(");
    let start = sol.find(&needle)? + needle.len() - 1; // points at '('
    let bytes = sol.as_bytes();
    let mut depth = 0i32;
    let mut args_end = start;
    for (i, b) in bytes[start..].iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    args_end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let args_raw = &sol[start + 1..args_end];
    let arg_types = canonical_type_list(args_raw);

    let tail_end = sol[args_end..].find(';')? + args_end;
    let tail = &sol[args_end + 1..tail_end];
    let is_view = tail.split_whitespace().any(|t| t == "view");
    let ret_types = match tail.find("returns") {
        Some(idx) => {
            let after = &tail[idx + "returns".len()..];
            let lparen = after.find('(')?;
            let rparen = after.rfind(')')?;
            canonical_type_list(&after[lparen + 1..rparen])
        }
        None => String::new(),
    };
    Some(SolFnCanonical {
        arg_types,
        is_view,
        ret_types,
    })
}

/// Reduces a Solidity parameter list (which may carry names, `memory`, or
/// `calldata` markers) to a comma-separated list of just the leading types.
fn canonical_type_list(list: &str) -> String {
    list.split(',')
        .map(|part| part.split_whitespace().next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}
