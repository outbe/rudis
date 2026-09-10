use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::checked_whole_coen_to_native;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::ValidatorLifecycle;

use crate::contract::Staking;
use crate::hooks;

const CHAIN_ID: u64 = 1;
const MIN_STAKE: u64 = 1_000;

/// Default large balance seeded to callers so transfer_balance succeeds.
const DEFAULT_BALANCE: u64 = 1_000_000;

fn with_staking<R>(f: impl FnOnce(StorageHandle, &mut Staking) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    // Height zero is the persisted "not set" sentinel for lifecycle heights;
    // ordinary staking transactions execute only after genesis.
    storage.set_block_number(1);
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        // Set a default min stake for tests
        s.config_min_stake
            .write(U256::from(MIN_STAKE))
            .expect("write min_stake");
        s.config_unbonding_period
            .write(3600)
            .expect("write unbonding_period");
        f(storage, &mut s)
    })
}

fn with_staking_timed<R>(timestamp: u64, f: impl FnOnce(StorageHandle, &mut Staking) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_block_number(1);
    storage.set_timestamp(U256::from(timestamp));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake
            .write(U256::from(MIN_STAKE))
            .expect("write min_stake");
        s.config_unbonding_period
            .write(3600)
            .expect("write unbonding_period");
        f(storage, &mut s)
    })
}

/// Seed a caller's native balance so transfer_balance in stake() succeeds.
fn seed_balance(storage: StorageHandle, addr: Address, amount: u64) {
    let ctx = storage.clone();
    ctx.set_balance(addr, U256::from(amount)).unwrap();
}

/// Registers a validator in ValidatorSet so cross-calls work correctly.
/// Uses the explicit test-only bootstrap seam; production registration requires PoP.
fn register_validator(storage: StorageHandle, validator: Address) {
    let owner = address!("0xffffffffffffffffffffffffffffffffffffffff");
    let mut val_set = ValidatorSet::new(storage.clone());
    val_set.config_owner.write(owner).expect("write owner");
    val_set.set_config_max_validators(100).expect("write max");
    let mut consensus_pubkey = [0u8; 48];
    consensus_pubkey[..20].copy_from_slice(validator.as_slice());
    val_set
        .test_register_validator_without_pop(validator, &consensus_pubkey)
        .expect("register_validator");
}

fn stake_registered(
    storage: StorageHandle,
    staking: &mut Staking<'_>,
    validator: Address,
    amount: U256,
) -> outbe_primitives::error::Result<()> {
    let val_set = ValidatorSet::new(storage.clone());
    if !val_set.is_validator(validator)? {
        register_validator(storage, validator);
    }
    staking.stake(validator, validator, amount)
}

/// Seeds STAKING_ADDRESS with balance (simulating EVM-level msg.value transfer).
/// stake() no longer transfers; in production EVM does it.
fn seed_staking_balance(storage: StorageHandle, amount: u64) {
    seed_staking_balance_u256(storage, U256::from(amount));
}

fn seed_staking_balance_u256(storage: StorageHandle, amount: U256) {
    let ctx = storage.clone();
    let current = ctx.balance(STAKING_ADDRESS).unwrap();
    ctx.set_balance(STAKING_ADDRESS, current + amount).unwrap();
}

// ---------------------------------------------------------------------------
// test_stake
// ---------------------------------------------------------------------------

#[test]
fn test_stake() {
    with_staking(|storage, s| {
        // Self-stake only (caller == validator)
        let validator = address!("0x1111111111111111111111111111111111111111");
        let amount = U256::from(500u64);

        // stake() doesn't transfer funds; in production EVM does it.
        // Seed STAKING_ADDRESS to simulate EVM msg.value transfer.
        seed_staking_balance(storage.clone(), 500);
        stake_registered(storage.clone(), s, validator, amount).unwrap();

        assert_eq!(s.get_stake(validator).unwrap(), amount);
        assert_eq!(s.get_total_staked().unwrap(), amount);
    });
}

#[test]
fn test_stake_with_eighteen_decimal_native_coen_fixture() {
    with_staking(|storage, s| {
        let validator = address!("0x1212121212121212121212121212121212121212");
        let amount = checked_whole_coen_to_native(U256::from(100_000u64)).unwrap();

        register_validator(storage.clone(), validator);
        s.config_min_stake.write(amount).unwrap();
        seed_staking_balance_u256(storage.clone(), amount);
        s.stake(validator, validator, amount).unwrap();

        assert_eq!(s.get_stake(validator).unwrap(), amount);
        assert_eq!(s.get_total_staked().unwrap(), amount);
        let validators = ValidatorSet::new(storage);
        assert!(matches!(
            validators.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));
    });
}

#[test]
fn test_stake_third_party_rejected() {
    with_staking(|_storage, s| {
        // Third-party staking is no longer supported
        let validator = address!("0x1111111111111111111111111111111111111111");
        let caller = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(s.stake(caller, validator, U256::from(500u64)).is_err());
    });
}

#[test]
fn test_stake_accumulates() {
    with_staking(|storage, s| {
        let validator = address!("0x1111111111111111111111111111111111111111");

        seed_staking_balance(storage.clone(), 1_000);
        stake_registered(storage.clone(), s, validator, U256::from(300u64)).unwrap();
        stake_registered(storage.clone(), s, validator, U256::from(700u64)).unwrap();

        assert_eq!(s.get_stake(validator).unwrap(), U256::from(1_000u64));
        assert_eq!(s.get_total_staked().unwrap(), U256::from(1_000u64));
    });
}

#[test]
fn test_stake_marks_registered_validator_pending() {
    with_staking(|storage, s| {
        let validator = address!("0x2222222222222222222222222222222222222222");
        register_validator(storage.clone(), validator);

        // Check initial status is REGISTERED
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForStake(_)
        ));

        // Stake enough to meet min_stake
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();

        // PoS: staking to min_stake marks the validator PENDING (admitted, syncing,
        // not yet voting). The DKG reshare promotes PENDING->ACTIVE once it gets a
        // share. The pending_set_change flag is raised so consensus schedules it.
        let val_set = ValidatorSet::new(storage.clone());
        let lifecycle = val_set.validator_lifecycle(validator).unwrap();
        assert!(matches!(
            &lifecycle,
            ValidatorLifecycle::WaitingForReadiness(_)
        ));
        assert!(val_set.has_pending_set_change().unwrap());
        assert!(!lifecycle.has_bls_share());
    });
}

#[test]
fn test_stake_zero_fails() {
    with_staking(|_storage, s| {
        let validator = address!("0x1111111111111111111111111111111111111111");
        assert!(s.stake(validator, validator, U256::ZERO).is_err());
    });
}

// ---------------------------------------------------------------------------
// test_unstake
// ---------------------------------------------------------------------------

#[test]
fn test_unstake() {
    with_staking_timed(1_000_000, |storage, s| {
        let validator = address!("0x3333333333333333333333333333333333333333");
        let amount = U256::from(2_000u64);

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), s, validator, amount).unwrap();
        s.unstake(validator, U256::from(500u64)).unwrap();

        // Stake reduced
        assert_eq!(s.get_stake(validator).unwrap(), U256::from(1_500u64));
        assert_eq!(s.get_total_staked().unwrap(), U256::from(1_500u64));

        // Queue entry created
        assert_eq!(s.unbonding_count.read().unwrap(), 1);
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), validator);
        assert_eq!(s.unbonding_amount.read(&0u32).unwrap(), U256::from(500u64));
        // complete_time = 1_000_000 + 3600
        assert_eq!(s.unbonding_complete_time.read(&0u32).unwrap(), 1_003_600u64);
    });
}

#[test]
fn test_unstake_below_min_sets_exiting_status() {
    with_staking_timed(0, |storage, s| {
        let validator = address!("0x4444444444444444444444444444444444444444");
        register_validator(storage.clone(), validator);

        // Stake above min_stake and activate
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();

        // Stake marks PENDING; simulate the reshare promotion to ACTIVE so the
        // unstake-below-min ACTIVE->EXITING path is what is exercised here.
        let mut val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));
        val_set
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        assert!(val_set
            .validator_lifecycle(validator)
            .unwrap()
            .is_active_status());

        // Unstake to drop below min_stake
        s.unstake(validator, U256::from(500u64)).unwrap();

        // Should now be EXITING (DKG reshare pending to exclude from consensus)
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::Exiting(_)
        ));
    });
}

#[test]
fn test_unstake_below_min_reverts_pending_to_registered() {
    with_staking_timed(0, |storage, s| {
        let validator = address!("0x4A44444444444444444444444444444444444444");
        register_validator(storage.clone(), validator);
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();
        // PENDING joiner (not yet activated) unstaking below min reverts to REGISTERED.
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));
        s.unstake(validator, U256::from(500u64)).unwrap();
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForStake(_)
        ));
    });
}
#[test]
fn test_unstake_from_jailed_goes_exiting() {
    // Leave-from-jail: unstaking the full stake from JAILED routes to EXITING, then
    // the normal EXITING -> UNBONDING -> INACTIVE drain runs.
    with_staking_timed(0, |storage, s| {
        let validator = address!("0x4B44444444444444444444444444444444444444");
        register_validator(storage.clone(), validator);
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();
        let mut val_set = ValidatorSet::new(storage.clone());
        val_set
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        val_set.jail_validator(validator).unwrap();
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));

        s.unstake(validator, U256::from(MIN_STAKE)).unwrap();
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::Exiting(_)
        ));
    });
}

#[test]
fn test_unjail_requires_min_stake_and_explicit_tx() {
    // unjailValidator needs stake >= min_stake AND is always explicit: a top-up
    // alone does NOT auto-unjail.
    with_staking_timed(0, |storage, s| {
        let validator = address!("0x4D44444444444444444444444444444444444444");
        register_validator(storage.clone(), validator);
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();
        let mut val_set = ValidatorSet::new(storage.clone());
        val_set
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        val_set.jail_validator(validator).unwrap();

        // Exclude the jailed validator at a validated boundary and slash its
        // remaining bonded stake so the explicit unjail stake check is exercised.
        val_set
            .test_activate_validated_boundary_set(&[], B256::ZERO, 1)
            .unwrap();
        s.slash_stake(validator, 100).unwrap();

        // No stake yet -> unjail rejected (needs >= min_stake).
        assert!(
            s.unjail_validator(validator).is_err(),
            "unjail must require stake >= min_stake"
        );

        // Top up to min_stake; this does NOT change the JAILED status by itself.
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();
        let val_set = ValidatorSet::new(storage.clone());
        assert!(
            matches!(
                val_set.validator_lifecycle(validator).unwrap(),
                ValidatorLifecycle::Jail(_)
            ),
            "a stake top-up alone must NOT unjail"
        );

        // Explicit unjail now succeeds -> PENDING.
        s.unjail_validator(validator).unwrap();
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));
    });
}

#[test]
fn test_unstake_insufficient_fails() {
    with_staking(|storage, s| {
        let validator = address!("0x5555555555555555555555555555555555555555");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 100);
        stake_registered(storage.clone(), s, validator, U256::from(100u64)).unwrap();
        assert!(s.unstake(validator, U256::from(200u64)).is_err());
    });
}

// ---------------------------------------------------------------------------
// test_slash_stake
// ---------------------------------------------------------------------------

#[test]
fn test_slash_stake() {
    with_staking(|storage, s| {
        let validator = address!("0x6666666666666666666666666666666666666666");
        let initial = U256::from(1_000u64);

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 1_000);
        stake_registered(storage.clone(), s, validator, initial).unwrap();
        let slashed = s.slash_stake(validator, 20).unwrap(); // 20%

        // 1000 * 20 / 100 = 200 slashed
        assert_eq!(slashed, U256::from(200u64));
        // 1000 - 200 = 800
        assert_eq!(s.get_stake(validator).unwrap(), U256::from(800u64));
        assert_eq!(s.get_total_staked().unwrap(), U256::from(800u64));
    });
}

#[test]
fn test_slash_stake_100_percent() {
    with_staking(|storage, s| {
        let validator = address!("0x7777777777777777777777777777777777777777");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 500);
        stake_registered(storage.clone(), s, validator, U256::from(500u64)).unwrap();
        let slashed = s.slash_stake(validator, 100).unwrap();

        assert_eq!(slashed, U256::from(500u64));
        assert_eq!(s.get_stake(validator).unwrap(), U256::ZERO);
        assert_eq!(s.get_total_staked().unwrap(), U256::ZERO);
    });
}

#[test]
fn test_slash_above_100_fails() {
    with_staking(|storage, s| {
        let validator = address!("0x8888888888888888888888888888888888888888");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 100);
        stake_registered(storage.clone(), s, validator, U256::from(100u64)).unwrap();
        assert!(s.slash_stake(validator, 101).is_err());
    });
}

#[test]
fn test_slash_below_min_stake_transitions_to_exiting() {
    with_staking(|storage, s| {
        let validator = address!("0x9999999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);

        // Stake exactly at min -> PENDING, then simulate a DKG reshare promotion to
        // ACTIVE via manual activation (the slash-below-min path under test demotes a
        // consensus-ACTIVE validator to EXITING).
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();
        let mut val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));
        val_set
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        assert!(val_set
            .validator_lifecycle(validator)
            .unwrap()
            .is_active_status());

        // Slash 50% - new stake = 500, below min_stake (1000)
        // Now auto-transitions ACTIVE -> EXITING when stake < min_stake
        s.slash_stake(validator, 50).unwrap();

        // Status transitions to EXITING (stake below min_stake)
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::Exiting(_)
        ));

        // Stake was reduced
        assert_eq!(s.get_stake(validator).unwrap(), U256::from(500u64));

        // Pending set change flagged
        assert!(val_set.has_pending_set_change().unwrap());
    });
}

#[test]
fn first_ocomp_miss_slashes_bonded_once_and_keeps_validator_active() {
    with_staking(|storage, staking| {
        let validator = address!("0x9B99999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), staking, validator, U256::from(MIN_STAKE)).unwrap();
        let mut validators = ValidatorSet::new(storage.clone());
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        assert!(!validators.has_pending_set_change().unwrap());

        let first = staking.record_ocomp_miss(validator).unwrap();
        assert!(first.first_in_window);
        assert_eq!(first.miss_count, 1);
        assert_eq!(first.recovery_deadline, 43_201);
        assert_eq!(first.slashed_bonded, U256::from(100));
        assert_eq!(staking.get_stake(validator).unwrap(), U256::from(900));
        assert_eq!(staking.get_total_staked().unwrap(), U256::from(900));
        assert_eq!(storage.balance(STAKING_ADDRESS).unwrap(), U256::from(900));
        let validators = ValidatorSet::new(storage.clone());
        assert!(matches!(
            validators.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::Active(_)
        ));
        assert!(!validators.has_pending_set_change().unwrap());

        let repeated = staking.record_ocomp_miss(validator).unwrap();
        assert!(!repeated.first_in_window);
        assert_eq!(repeated.miss_count, 2);
        assert_eq!(repeated.recovery_deadline, 43_201);
        assert_eq!(repeated.slashed_bonded, U256::ZERO);
        assert_eq!(staking.get_stake(validator).unwrap(), U256::from(900));
        assert_eq!(storage.balance(STAKING_ADDRESS).unwrap(), U256::from(900));
    });
}

#[test]
fn first_ocomp_miss_handles_the_full_u256_bonded_domain() {
    with_staking(|storage, staking| {
        let validator = address!("0x9199999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), staking, validator, U256::from(MIN_STAKE)).unwrap();
        let mut validators = ValidatorSet::new(storage.clone());
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();

        staking.stake_amount.write(&validator, U256::MAX).unwrap();
        staking.total_staked.write(U256::MAX).unwrap();
        storage.set_balance(STAKING_ADDRESS, U256::MAX).unwrap();
        validators
            .record_stake_increase(validator, U256::MAX, U256::from(MIN_STAKE))
            .unwrap();

        let expected_slash = U256::MAX / U256::from(10u64);
        let expected_remaining = U256::MAX - expected_slash;
        let penalty = staking.record_ocomp_miss(validator).unwrap();

        assert_eq!(penalty.slashed_bonded, expected_slash);
        assert_eq!(staking.get_stake(validator).unwrap(), expected_remaining);
        assert_eq!(staking.get_total_staked().unwrap(), expected_remaining);
        assert_eq!(
            storage.balance(STAKING_ADDRESS).unwrap(),
            expected_remaining
        );
        assert!(matches!(
            ValidatorSet::new(storage)
                .validator_lifecycle(validator)
                .unwrap(),
            ValidatorLifecycle::Active(_)
        ));
    });
}

#[test]
fn due_window_is_resolved_before_a_same_height_new_miss() {
    let validator = address!("0x9299999999999999999999999999999999999999");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        staking
            .config_min_stake
            .write(U256::from(MIN_STAKE))
            .unwrap();
        register_validator(storage.clone(), validator);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), &mut staking, validator, U256::from(2_000)).unwrap();
        ValidatorSet::new(storage)
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        let first = staking.record_ocomp_miss(validator).unwrap();
        assert_eq!(first.slashed_bonded, U256::from(200));
    });

    provider.set_block_number(43_201);
    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        let resolution = staking
            .resolve_due_ocomp_recovery_window(validator)
            .unwrap();
        assert!(matches!(
            resolution,
            crate::logic::OcompRecoveryResolution::Restored {
                recovery_deadline: 43_201
            }
        ));

        let next = staking.record_ocomp_miss(validator).unwrap();
        assert!(next.first_in_window);
        assert_eq!(next.miss_count, 2);
        assert_eq!(next.slashed_bonded, U256::from(180));
        assert_eq!(next.recovery_deadline, 86_401);
        assert_eq!(staking.get_stake(validator).unwrap(), U256::from(1_620));
    });
}

#[test]
fn ocomp_recovery_is_decided_at_deadline_from_authoritative_bonded_stake() {
    let restored = address!("0x9C99999999999999999999999999999999999999");
    let underfunded = address!("0x9D99999999999999999999999999999999999999");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(1);

    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        staking
            .config_min_stake
            .write(U256::from(MIN_STAKE))
            .unwrap();
        staking.config_unbonding_period.write(3_600).unwrap();
        for validator in [restored, underfunded] {
            register_validator(storage.clone(), validator);
            seed_staking_balance(storage.clone(), MIN_STAKE);
            stake_registered(
                storage.clone(),
                &mut staking,
                validator,
                U256::from(MIN_STAKE),
            )
            .unwrap();
            ValidatorSet::new(storage.clone())
                .activate_validator_via_boundary_for_test(validator)
                .unwrap();
            staking.record_ocomp_miss(validator).unwrap();
        }

        seed_staking_balance(storage.clone(), 100);
        staking.stake(restored, restored, U256::from(100)).unwrap();
    });

    provider.set_block_number(43_200);
    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        let before = staking.close_due_ocomp_recovery_windows().unwrap();
        assert_eq!(before.open_windows, 2);
        assert_eq!(before.restored, 0);
        assert_eq!(before.jailed, 0);
    });

    provider.set_block_number(43_201);
    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        let due = staking.close_due_ocomp_recovery_windows().unwrap();
        assert_eq!(due.open_windows, 2);
        assert_eq!(due.restored, 1);
        assert_eq!(due.jailed, 1);

        let validators = ValidatorSet::new(storage);
        assert!(matches!(
            validators.validator_lifecycle(restored).unwrap(),
            ValidatorLifecycle::Active(_)
        ));
        assert!(matches!(
            validators.validator_lifecycle(underfunded).unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));
        assert!(validators
            .ocomp_recovery_window(restored)
            .unwrap()
            .is_none());
        assert!(validators
            .ocomp_recovery_window(underfunded)
            .unwrap()
            .is_none());
    });

    let resolutions = provider
        .get_ordered_events()
        .iter()
        .filter_map(|log| {
            outbe_validatorset::precompile::IValidatorSet::OcompRecoveryResolved::decode_log(log)
                .ok()
        })
        .collect::<Vec<_>>();
    assert_eq!(resolutions.len(), 2);
    assert!(resolutions.iter().any(|event| {
        event.validator == restored
            && event.recoveryDeadline == 43_201
            && event.bondedStake == U256::from(MIN_STAKE)
            && event.outcome == 1
    }));
    assert!(resolutions.iter().any(|event| {
        event.validator == underfunded
            && event.recoveryDeadline == 43_201
            && event.bondedStake == U256::from(900)
            && event.outcome == 2
    }));
}

#[test]
fn ocomp_miss_slash_never_touches_unbonding_claims() {
    with_staking_timed(10_000, |storage, staking| {
        let validator = address!("0x9E99999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), staking, validator, U256::from(2_000)).unwrap();
        ValidatorSet::new(storage.clone())
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        staking.unstake(validator, U256::from(500)).unwrap();

        let head_before = staking.per_val_unbonding_head.read(&validator).unwrap();
        let amount_before = staking.unbonding_amount.read(&0).unwrap();
        let complete_before = staking.unbonding_complete_time.read(&0).unwrap();
        let next_before = staking.unbonding_next.read(&0).unwrap();

        let penalty = staking.record_ocomp_miss(validator).unwrap();
        assert_eq!(penalty.slashed_bonded, U256::from(150));
        assert_eq!(staking.get_stake(validator).unwrap(), U256::from(1_350));
        assert_eq!(staking.get_total_staked().unwrap(), U256::from(1_350));
        assert_eq!(
            staking.per_val_unbonding_head.read(&validator).unwrap(),
            head_before
        );
        assert_eq!(staking.unbonding_amount.read(&0).unwrap(), amount_before);
        assert_eq!(
            staking.unbonding_complete_time.read(&0).unwrap(),
            complete_before
        );
        assert_eq!(staking.unbonding_next.read(&0).unwrap(), next_before);
        assert_eq!(amount_before, U256::from(500));
    });
}

#[test]
fn open_ocomp_recovery_does_not_weaken_ordinary_slash_policy() {
    with_staking_timed(20_000, |storage, staking| {
        let validator = address!("0x9F99999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), staking, validator, U256::from(2_000)).unwrap();
        ValidatorSet::new(storage.clone())
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        staking.unstake(validator, U256::from(500)).unwrap();
        staking.record_ocomp_miss(validator).unwrap();
        let complete_before = staking.unbonding_complete_time.read(&0).unwrap();

        staking.slash_stake(validator, 60).unwrap();

        assert_eq!(staking.get_stake(validator).unwrap(), U256::from(540));
        assert_eq!(staking.unbonding_amount.read(&0).unwrap(), U256::from(200));
        assert!(staking.unbonding_complete_time.read(&0).unwrap() > complete_before);
        assert!(matches!(
            ValidatorSet::new(storage)
                .validator_lifecycle(validator)
                .unwrap(),
            ValidatorLifecycle::Exiting(_)
        ));
    });
}

#[test]
fn recovery_sweep_keeps_non_active_window_until_deadline() {
    with_staking(|storage, staking| {
        let validator = address!("0x9099999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);
        let mut validators = ValidatorSet::new(storage.clone());
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        staking.record_ocomp_miss(validator).unwrap();
        validators.jail_validator(validator).unwrap();

        let sweep = staking.close_due_ocomp_recovery_windows().unwrap();
        assert_eq!(sweep.open_windows, 1);
        assert_eq!(sweep.closed_non_active, 0);
        assert_eq!(sweep.jailed, 0);
        assert!(validators
            .ocomp_recovery_window(validator)
            .unwrap()
            .is_some());
        assert!(matches!(
            validators.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));
    });
}

#[test]
fn recovery_sweep_closes_non_active_window_at_deadline_without_reverting() {
    let validator = address!("0x9199999999999999999999999999999999999999");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        staking
            .config_min_stake
            .write(U256::from(MIN_STAKE))
            .unwrap();
        register_validator(storage.clone(), validator);
        let mut validators = ValidatorSet::new(storage.clone());
        validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
        staking.record_ocomp_miss(validator).unwrap();
        validators.jail_validator(validator).unwrap();
    });

    provider.set_block_number(43_201);
    StorageHandle::enter(&mut provider, |storage| {
        let mut staking = Staking::new(storage.clone());
        let sweep = staking.close_due_ocomp_recovery_windows().unwrap();
        assert_eq!(sweep.open_windows, 1);
        assert_eq!(sweep.closed_non_active, 1);
        assert_eq!(sweep.jailed, 0);
        let validators = ValidatorSet::new(storage);
        assert!(validators
            .ocomp_recovery_window(validator)
            .unwrap()
            .is_none());
        assert!(matches!(
            validators.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::JailRetained(_)
        ));
    });
}

#[test]
fn recovery_sweep_rejects_registry_state_beyond_the_existing_consensus_bound() {
    with_staking(|storage, staking| {
        let mut validators = ValidatorSet::new(storage);
        for index in 0..=outbe_validatorset::runtime::CONSENSUS_VALIDATOR_BOUND {
            let ordinal = u64::from(index) + 1;
            let mut address_bytes = [0u8; 20];
            address_bytes[12..].copy_from_slice(&ordinal.to_be_bytes());
            let mut consensus_pubkey = [0u8; 48];
            consensus_pubkey[..8].copy_from_slice(&ordinal.to_be_bytes());
            validators
                .test_register_validator_without_pop(
                    Address::from(address_bytes),
                    &consensus_pubkey,
                )
                .unwrap();
        }
        let error = staking.close_due_ocomp_recovery_windows().unwrap_err();
        assert!(error
            .to_string()
            .contains("validator registry exceeds consensus bound"));
    });
}

#[test]
fn test_slash_below_min_stake_reverts_pending_to_registered() {
    with_staking(|storage, s| {
        let validator = address!("0x9A99999999999999999999999999999999999999");
        register_validator(storage.clone(), validator);

        // Stake -> PENDING (staked joiner, not yet activated by a reshare).
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), MIN_STAKE);
        stake_registered(storage.clone(), s, validator, U256::from(MIN_STAKE)).unwrap();
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));

        // Slash below min before activation -> revert PENDING->REGISTERED so the next
        // reshare target does not select an under-staked joiner.
        s.slash_stake(validator, 50).unwrap();
        let val_set = ValidatorSet::new(storage.clone());
        assert!(matches!(
            val_set.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForStake(_)
        ));
        assert!(val_set.has_pending_set_change().unwrap());
    });
}

// ---------------------------------------------------------------------------
// test_claim_unbonded
// ---------------------------------------------------------------------------

#[test]
fn test_claim_unbonded() {
    let base_time: u64 = 10_000;
    let unbonding_period: u64 = 3_600;

    // Setup: stake and unstake before mature time
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        let validator = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), &mut s, validator, U256::from(2_000u64)).unwrap();
        s.unstake(validator, U256::from(500u64)).unwrap();

        // Entry not yet mature - claim should leave it intact
        s.claim_unbonded(validator).unwrap();
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), validator);
    });

    // Advance time past unbonding period and claim
    storage.set_timestamp(U256::from(base_time + unbonding_period + 1));

    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        let validator = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        s.claim_unbonded(validator).unwrap();

        // Entry should be zeroed out
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), Address::ZERO);
        assert_eq!(s.unbonding_amount.read(&0u32).unwrap(), U256::ZERO);

        // Validator received native tokens back.
        // stake() no longer deducts from caller; validator balance stays at DEFAULT_BALANCE
        // and claim_unbonded adds the 500 back.
        let ctx = storage.clone();
        let expected = DEFAULT_BALANCE + 500;
        assert_eq!(ctx.balance(validator).unwrap(), U256::from(expected));
    });
}

// ---------------------------------------------------------------------------
// test_process_unbonding
// ---------------------------------------------------------------------------

#[test]
fn test_process_unbonding_preserves_claimable() {
    with_staking_timed(0, |storage, s| {
        let v1 = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let v2 = address!("0xcccccccccccccccccccccccccccccccccccccccc");

        // Give both validators enough stake to unstake
        seed_balance(storage.clone(), v1, DEFAULT_BALANCE);
        seed_balance(storage.clone(), v2, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 4_000);
        stake_registered(storage.clone(), s, v1, U256::from(2_000u64)).unwrap();
        stake_registered(storage.clone(), s, v2, U256::from(2_000u64)).unwrap();

        // Both unstake - both entries land at timestamp 0 + 3600
        s.unstake(v1, U256::from(500u64)).unwrap();
        s.unstake(v2, U256::from(300u64)).unwrap();

        assert_eq!(s.unbonding_count.read().unwrap(), 2);

        // Process at any timestamp - entries are NOT zeroed (only compaction of
        // already-claimed entries happens). Mature entries remain for claim_unbonded.
        s.process_unbonding(100).unwrap();
        assert_eq!(s.unbonding_count.read().unwrap(), 2);

        s.process_unbonding(10_000).unwrap();
        // Entries still present - process_unbonding only compacts zeroed entries,
        // it does NOT zero mature entries. That is claim_unbonded's responsibility.
        assert_eq!(s.unbonding_count.read().unwrap(), 2);
    });
}

#[test]
fn test_process_unbonding_compacts_zeroed() {
    with_staking_timed(0, |storage, s| {
        let v1 = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        seed_balance(storage.clone(), v1, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), s, v1, U256::from(2_000u64)).unwrap();
        s.unstake(v1, U256::from(500u64)).unwrap();

        assert_eq!(s.unbonding_count.read().unwrap(), 1);

        // Manually zero the entry (simulating what claim_unbonded does)
        s.unbonding_validator.write(&0u32, Address::ZERO).unwrap();
        s.unbonding_amount.write(&0u32, U256::ZERO).unwrap();

        // Process should compact the zeroed entry
        s.process_unbonding(10_000).unwrap();
        assert_eq!(s.unbonding_count.read().unwrap(), 0);
    });
}

#[test]
fn test_process_unbonding_hook() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(100).unwrap();

        let validator = address!("0xdddddddddddddddddddddddddddddddddddddddd");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 2_000);
        stake_registered(storage.clone(), &mut s, validator, U256::from(2_000u64)).unwrap();
        // At timestamp 0, complete_time = 0 + 100 = 100
        s.unstake(validator, U256::from(200u64)).unwrap();

        assert_eq!(s.unbonding_count.read().unwrap(), 1);
    });

    // Call hook at timestamp 200 - process_unbonding only compacts zeroed entries,
    // so the mature entry remains (it must be claimed via claim_unbonded).
    StorageHandle::enter(&mut storage, |storage| {
        hooks::process_unbonding(storage.clone(), 200).unwrap();

        let s = Staking::new(storage.clone());
        // Entry still present - not claimed yet
        assert_eq!(s.unbonding_count.read().unwrap(), 1);
    });
}

// ---------------------------------------------------------------------------
// test_unbonding_full_flow: stake -> unstake -> advance time -> claim -> verify balance
// ---------------------------------------------------------------------------

#[test]
fn test_unbonding_full_flow() {
    let base_time: u64 = 10_000;
    let unbonding_period: u64 = 3_600;
    let stake_amount: u64 = 5_000;
    let unstake_amount: u64 = 2_000;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    let validator = address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

    // 1. Stake
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        // stake() no longer transfers; seed STAKING_ADDRESS to simulate EVM msg.value.
        seed_staking_balance(storage.clone(), stake_amount);
        stake_registered(storage.clone(), &mut s, validator, U256::from(stake_amount)).unwrap();

        // Verify STAKING_ADDRESS was seeded correctly
        let ctx = storage.clone();
        assert_eq!(
            ctx.balance(STAKING_ADDRESS).unwrap(),
            U256::from(stake_amount),
        );
    });

    // 2. Unstake
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        s.unstake(validator, U256::from(unstake_amount)).unwrap();
        assert_eq!(s.unbonding_count.read().unwrap(), 1);
    });

    // 3. process_unbonding - mature entry NOT zeroed
    storage.set_timestamp(U256::from(base_time + unbonding_period + 1));
    StorageHandle::enter(&mut storage, |storage| {
        hooks::process_unbonding(storage.clone(), base_time + unbonding_period + 1).unwrap();
        let s = Staking::new(storage.clone());
        assert_eq!(
            s.unbonding_count.read().unwrap(),
            1,
            "entry must survive process_unbonding"
        );
    });

    // 4. claim_unbonded - funds returned to validator
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        s.claim_unbonded(validator).unwrap();

        // Entry zeroed by claim
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), Address::ZERO,);

        // Validator received the unstaked tokens.
        // stake() no longer deducts from caller; validator balance stays at DEFAULT_BALANCE
        // and claim_unbonded adds the unstaked amount back.
        let ctx = storage.clone();
        let expected_balance = DEFAULT_BALANCE + unstake_amount;
        assert_eq!(
            ctx.balance(validator).unwrap(),
            U256::from(expected_balance)
        );

        // Staking contract balance decreased by the claimed amount
        assert_eq!(
            ctx.balance(STAKING_ADDRESS).unwrap(),
            U256::from(stake_amount - unstake_amount),
        );
    });

    // 5. process_unbonding now compacts the zeroed entry
    StorageHandle::enter(&mut storage, |storage| {
        hooks::process_unbonding(storage.clone(), base_time + unbonding_period + 100).unwrap();
        let s = Staking::new(storage.clone());
        assert_eq!(
            s.unbonding_count.read().unwrap(),
            0,
            "zeroed entry should be compacted"
        );
    });
}

// ---------------------------------------------------------------------------
// test_process_unbonding_capped - verify MAX_COMPACTION_PER_BLOCK limit
// ---------------------------------------------------------------------------
#[test]
fn test_process_unbonding_capped() {
    with_staking(|_storage, s| {
        // Create 100 zeroed unbonding entries (simulating previously-claimed entries)
        let total: u32 = 100;
        for i in 0..total {
            s.unbonding_validator.write(&i, Address::ZERO).unwrap();
            s.unbonding_amount.write(&i, U256::ZERO).unwrap();
            s.unbonding_complete_time.write(&i, 0).unwrap();
        }
        s.unbonding_count.write(total).unwrap();

        // First call: compacts at most MAX_COMPACTION_PER_BLOCK (64)
        s.process_unbonding(0).unwrap();
        let count_after_first = s.unbonding_count.read().unwrap();
        // All 100 entries are zeroed, but only 64 compactions allowed per call
        // Since all entries are zero from tail too, compaction just decrements
        assert!(
            count_after_first <= total - Staking::MAX_COMPACTION_PER_BLOCK,
            "should compact at most 64 entries, got count={}",
            count_after_first
        );

        // Second call gets the rest
        s.process_unbonding(0).unwrap();
        assert_eq!(
            s.unbonding_count.read().unwrap(),
            0,
            "all zeroed entries compacted"
        );
    });
}

// ---------------------------------------------------------------------------
// P2-2: Per-validator unbonding linked list tests
// ---------------------------------------------------------------------------

#[test]
fn test_claim_unbonded_linked_list_basic() {
    let base_time: u64 = 10_000;
    let unbonding_period: u64 = 100;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    let validator = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    // Unstake 3 times
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 3_000);
        stake_registered(storage.clone(), &mut s, validator, U256::from(3_000u64)).unwrap();
        s.unstake(validator, U256::from(100u64)).unwrap();
        s.unstake(validator, U256::from(200u64)).unwrap();
        s.unstake(validator, U256::from(300u64)).unwrap();

        assert_eq!(s.unbonding_count.read().unwrap(), 3);
        // Head should point to last unstake (prepend: 3->2->1)
        assert_eq!(s.per_val_unbonding_head.read(&validator).unwrap(), 3); // stored = idx+1 = 2+1
    });

    // Advance past unbonding period and claim all
    storage.set_timestamp(U256::from(base_time + unbonding_period + 1));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.claim_unbonded(validator).unwrap();

        // All entries zeroed
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), Address::ZERO);
        assert_eq!(s.unbonding_validator.read(&1u32).unwrap(), Address::ZERO);
        assert_eq!(s.unbonding_validator.read(&2u32).unwrap(), Address::ZERO);

        // Linked list head cleared
        assert_eq!(s.per_val_unbonding_head.read(&validator).unwrap(), 0);

        // Validator received 100 + 200 + 300 = 600.
        // stake() no longer deducts from caller; validator stays at DEFAULT_BALANCE
        // and claim_unbonded adds 600 back.
        let ctx = storage.clone();
        let expected = DEFAULT_BALANCE + 600;
        assert_eq!(ctx.balance(validator).unwrap(), U256::from(expected));
    });
}

#[test]
fn test_claim_unbonded_partial_maturity() {
    let base_time: u64 = 10_000;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    let validator = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(100).unwrap(); // short period

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 3_000);
        stake_registered(storage.clone(), &mut s, validator, U256::from(3_000u64)).unwrap();

        // Entry 0: complete at 10100
        s.unstake(validator, U256::from(100u64)).unwrap();
        s.unstake(validator, U256::from(200u64)).unwrap();
    });

    // Change unbonding period for next unstake - entry 2 will mature much later
    storage.set_timestamp(U256::from(base_time + 50));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(10_000).unwrap(); // long period

        // Entry 2: complete at 10050 + 10000 = 20050
        s.unstake(validator, U256::from(300u64)).unwrap();
    });

    // Advance to 10200 - entries 0,1 mature (10100), entry 2 not (20050)
    storage.set_timestamp(U256::from(10_200));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.claim_unbonded(validator).unwrap();

        // Entries 0,1 zeroed
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), Address::ZERO);
        assert_eq!(s.unbonding_validator.read(&1u32).unwrap(), Address::ZERO);

        // Entry 2 still present
        assert_eq!(s.unbonding_validator.read(&2u32).unwrap(), validator);

        // Linked list head points to entry 2 (stored = 3)
        assert_eq!(s.per_val_unbonding_head.read(&validator).unwrap(), 3);

        // Next of entry 2 = 0 (end of list)
        assert_eq!(s.unbonding_next.read(&2u32).unwrap(), 0);

        // Validator received 100 + 200 = 300.
        // stake() no longer deducts from caller; validator stays at DEFAULT_BALANCE
        // and claim_unbonded adds 300 back.
        let ctx = storage.clone();
        let expected = DEFAULT_BALANCE + 300;
        assert_eq!(ctx.balance(validator).unwrap(), U256::from(expected));
    });
}

#[test]
fn test_claim_unbonded_two_validators() {
    let base_time: u64 = 10_000;
    let unbonding_period: u64 = 100;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    let v1 = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let v2 = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        seed_balance(storage.clone(), v1, DEFAULT_BALANCE);
        seed_balance(storage.clone(), v2, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 6_000);
        stake_registered(storage.clone(), &mut s, v1, U256::from(3_000u64)).unwrap();
        stake_registered(storage.clone(), &mut s, v2, U256::from(3_000u64)).unwrap();

        // v1 unstakes twice, v2 unstakes once
        s.unstake(v1, U256::from(100u64)).unwrap(); // idx 0
        s.unstake(v2, U256::from(200u64)).unwrap(); // idx 1
        s.unstake(v1, U256::from(300u64)).unwrap(); // idx 2

        // v1 head: 3 (idx 2) -> 1 (idx 0) -> end
        assert_eq!(s.per_val_unbonding_head.read(&v1).unwrap(), 3);
        // v2 head: 2 (idx 1) -> end
        assert_eq!(s.per_val_unbonding_head.read(&v2).unwrap(), 2);
    });

    // Advance past unbonding period
    storage.set_timestamp(U256::from(base_time + unbonding_period + 1));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());

        // Only v1 claims
        s.claim_unbonded(v1).unwrap();

        // v1 entries (0, 2) zeroed
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), Address::ZERO);
        assert_eq!(s.unbonding_validator.read(&2u32).unwrap(), Address::ZERO);
        assert_eq!(s.per_val_unbonding_head.read(&v1).unwrap(), 0);

        // v2 entry (1) still present
        assert_eq!(s.unbonding_validator.read(&1u32).unwrap(), v2);
        assert_eq!(s.per_val_unbonding_head.read(&v2).unwrap(), 2); // stored = 1+1

        // v1 got 100 + 300 = 400.
        // stake() no longer deducts from caller; v1 stays at DEFAULT_BALANCE
        // and claim_unbonded adds 400 back.
        let ctx = storage.clone();
        assert_eq!(ctx.balance(v1).unwrap(), U256::from(DEFAULT_BALANCE + 400));
        // v2 balance unchanged (hasn't claimed); still at DEFAULT_BALANCE since stake() didn't deduct.
        assert_eq!(ctx.balance(v2).unwrap(), U256::from(DEFAULT_BALANCE));
    });
}

#[test]
fn test_process_unbonding_tail_trim() {
    with_staking(|_storage, s| {
        // Create entries: [v1, ZERO, ZERO] - tail trim should remove 2 zeroed tail entries
        let v1 = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        s.unbonding_validator.write(&0u32, v1).unwrap();
        s.unbonding_amount.write(&0u32, U256::from(100u64)).unwrap();
        s.unbonding_complete_time.write(&0u32, 9999u64).unwrap();

        s.unbonding_validator.write(&1u32, Address::ZERO).unwrap();
        s.unbonding_validator.write(&2u32, Address::ZERO).unwrap();
        s.unbonding_count.write(3).unwrap();

        s.process_unbonding(0).unwrap();

        // Only 1 entry remains (the non-zero one)
        assert_eq!(s.unbonding_count.read().unwrap(), 1);
        // Entry 0 still intact
        assert_eq!(s.unbonding_validator.read(&0u32).unwrap(), v1);
    });
}

#[test]
fn test_process_unbonding_no_trim_when_tail_nonzero() {
    with_staking(|_storage, s| {
        // Create entries: [ZERO, v1] - tail is non-zero, no trim
        let v1 = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        s.unbonding_validator.write(&0u32, Address::ZERO).unwrap();
        s.unbonding_validator.write(&1u32, v1).unwrap();
        s.unbonding_amount.write(&1u32, U256::from(100u64)).unwrap();
        s.unbonding_count.write(2).unwrap();

        s.process_unbonding(0).unwrap();

        // Count unchanged - tail is non-zero
        assert_eq!(s.unbonding_count.read().unwrap(), 2);
    });
}

#[test]
fn test_unstake_prepend_linked_list() {
    with_staking_timed(0, |storage, s| {
        let v = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        seed_balance(storage.clone(), v, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 5_000);
        stake_registered(storage.clone(), s, v, U256::from(5_000u64)).unwrap();

        s.unstake(v, U256::from(100u64)).unwrap(); // idx 0
        s.unstake(v, U256::from(200u64)).unwrap(); // idx 1
        s.unstake(v, U256::from(300u64)).unwrap(); // idx 2

        // Head = 3 (stored = idx 2 + 1)
        assert_eq!(s.per_val_unbonding_head.read(&v).unwrap(), 3);
        // idx 2 -> next = 2 (stored = idx 1 + 1)
        assert_eq!(s.unbonding_next.read(&2u32).unwrap(), 2);
        // idx 1 -> next = 1 (stored = idx 0 + 1)
        assert_eq!(s.unbonding_next.read(&1u32).unwrap(), 1);
        // idx 0 -> next = 0 (end of list)
        assert_eq!(s.unbonding_next.read(&0u32).unwrap(), 0);
    });
}

// ===========================================================================
// Slash unbonding entries regression tests
// ===========================================================================

/// unstake -> slash -> claim: unbonding amount must be reduced.
#[test]
fn test_slash_reduces_unbonding() {
    let base_time: u64 = 10_000;
    let unbonding_period: u64 = 100;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    let validator = address!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 10_000);
        stake_registered(storage.clone(), &mut s, validator, U256::from(10_000u64)).unwrap();

        // Unstake 8000 into unbonding
        s.unstake(validator, U256::from(8_000u64)).unwrap();

        // Slash 50% - must hit both active stake (2000) and unbonding (8000)
        let slashed = s.slash_stake(validator, 50).unwrap();

        // Active: 2000 * 50% = 1000 slashed
        // Unbonding: 8000 * 50% = 4000 slashed
        // Total slashed = 5000
        assert_eq!(slashed, U256::from(5_000u64));
        assert_eq!(s.get_stake(validator).unwrap(), U256::from(1_000u64));
        assert_eq!(
            s.unbonding_amount.read(&0u32).unwrap(),
            U256::from(4_000u64)
        );
    });

    // Normal maturity is not enough after slash; slashed entries use the
    // extended withdrawability delay.
    storage.set_timestamp(U256::from(base_time + unbonding_period + 1));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        s.claim_unbonded(validator).unwrap();

        let ctx = storage.clone();
        assert_eq!(ctx.balance(validator).unwrap(), U256::from(DEFAULT_BALANCE));
    });

    // Claim after slashed withdrawability delay - should receive reduced amount.
    storage.set_timestamp(U256::from(base_time + (unbonding_period * 2) + 1));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        s.claim_unbonded(validator).unwrap();

        let ctx = storage.clone();
        assert_eq!(
            ctx.balance(validator).unwrap(),
            U256::from(DEFAULT_BALANCE + 4_000)
        );
    });
}

/// 100% slash zeroes all unbonding entries.
#[test]
fn test_slash_100_zeroes_unbonding() {
    with_staking_timed(0, |storage, s| {
        let validator = address!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 5_000);
        stake_registered(storage.clone(), s, validator, U256::from(5_000u64)).unwrap();

        s.unstake(validator, U256::from(1_000u64)).unwrap();
        s.unstake(validator, U256::from(2_000u64)).unwrap();

        let slashed = s.slash_stake(validator, 100).unwrap();

        // Active: 2000 * 100% = 2000
        // Unbonding[0]: 1000 * 100% = 1000
        // Unbonding[1]: 2000 * 100% = 2000
        // Total = 5000
        assert_eq!(slashed, U256::from(5_000u64));
        assert_eq!(s.get_stake(validator).unwrap(), U256::ZERO);
        assert_eq!(s.unbonding_amount.read(&0u32).unwrap(), U256::ZERO);
        assert_eq!(s.unbonding_amount.read(&1u32).unwrap(), U256::ZERO);
    });
}

// ===========================================================================
// Balance invariant after slash
// ===========================================================================

/// After slash, STAKING_ADDRESS balance == remaining stake + remaining unbonding.
#[test]
fn test_slash_balance_invariant() {
    with_staking(|storage, s| {
        let validator = address!("0xcccccccccccccccccccccccccccccccccccccccc");
        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 10_000);
        stake_registered(storage.clone(), s, validator, U256::from(10_000u64)).unwrap();

        s.unstake(validator, U256::from(3_000u64)).unwrap();

        // Slash 20%
        s.slash_stake(validator, 20).unwrap();

        let remaining_stake = s.get_stake(validator).unwrap();
        let remaining_unbonding = s.unbonding_amount.read(&0u32).unwrap();
        let staking_balance = storage.balance(STAKING_ADDRESS).unwrap();

        // balance == stake + unbonding (no orphaned tokens)
        assert_eq!(
            staking_balance,
            remaining_stake + remaining_unbonding,
            "STAKING_ADDRESS balance must equal stake + unbonding after slash"
        );
    });
}

// ===========================================================================
// Self-stake only - unstake/claim rights remain with the staker
// ===========================================================================

/// Self-staker can unstake and claim their own funds.
#[test]
fn test_self_staker_can_unstake_and_claim() {
    let base_time: u64 = 10_000;
    let unbonding_period: u64 = 100;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(base_time));

    let validator = address!("0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD");

    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        seed_balance(storage.clone(), validator, DEFAULT_BALANCE);
        seed_staking_balance(storage.clone(), 5_000);
        stake_registered(storage.clone(), &mut s, validator, U256::from(5_000u64)).unwrap();
        s.unstake(validator, U256::from(2_000u64)).unwrap();

        assert_eq!(s.get_stake(validator).unwrap(), U256::from(3_000u64));
    });

    // Advance past unbonding and claim
    storage.set_timestamp(U256::from(base_time + unbonding_period + 1));
    StorageHandle::enter(&mut storage, |storage| {
        let mut s = Staking::new(storage.clone());
        s.config_min_stake.write(U256::from(MIN_STAKE)).unwrap();
        s.config_unbonding_period.write(unbonding_period).unwrap();

        s.claim_unbonded(validator).unwrap();

        let ctx = storage.clone();
        // Validator received 2000 back
        assert_eq!(
            ctx.balance(validator).unwrap(),
            U256::from(DEFAULT_BALANCE + 2_000)
        );
    });
}

/// `STAKING_ADDRESS` is allow-listed at the precompile boundary because
/// `stake` is payable, so value reaches every selector on the address. The
/// read-only selectors must reject it themselves or a value-carrying view call
/// would strand funds in the balance that backs `claimUnbonded`.
#[test]
fn read_only_selectors_reject_native_value() {
    use alloy_sol_types::SolCall;

    use crate::precompile::{dispatch, IStaking};

    let validator = address!("0x0000000000000000000000000000000000000001");
    let calls = [
        IStaking::getStakeCall { validator }.abi_encode(),
        IStaking::getTotalStakedCall {}.abi_encode(),
    ];

    with_staking(|storage, _| {
        for data in &calls {
            let rejected = dispatch(storage.clone(), data, validator, U256::from(1u64));
            assert!(
                matches!(
                    rejected,
                    Err(outbe_primitives::error::PrecompileError::Revert(ref message))
                        if message == "non-payable function called with value"
                ),
                "value-carrying read call must revert, got {rejected:?}"
            );
            dispatch(storage.clone(), data, validator, U256::ZERO)
                .expect("zero-value read call must still succeed");
        }
    });
}
