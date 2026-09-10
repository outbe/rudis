use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolError, SolEvent};
use outbe_primitives::addresses::{STABLECOIN_ADDRESS_PREFIX, STABLECOIN_FACTORY_ADDRESS};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::stablecoin::{predict_stablecoin, StablecoinCreatePayload};
use outbe_primitives::stablecoin_fork::STABLECOIN_V1_SCHEMA_VERSION;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::{PrecompileStorageProvider, StorageHandle};
use outbe_stablecoinpolicy::{
    PolicyType, StablecoinPolicyRegistryContract, ALLOW_ALL_POLICY_ID, DENY_ALL_POLICY_ID,
};

use crate::abi::IStablecoin;
use crate::api::{FactoryTokenInitialization, StablecoinFactoryApi};
use crate::precompile::dispatch;
use crate::schema::{
    role_key, StablecoinContract, ADMIN_ROLE, CAP_MANAGER_ROLE, COMPLIANCE_ROLE, ENFORCER_ROLE,
    GUARDIAN_ROLE, ISSUER_ROLE, OPERATIONAL_ROLES,
};

const CHAIN_ID: u64 = 7;
const ISSUER: Address = address!("1000000000000000000000000000000000000001");
const PERMIT_OWNER: Address = address!("17c5185167401ed00cf5f5b2fc97d9bbfdb7d025");
const PERMIT_SPENDER: Address = address!("2222222222222222222222222222222222222222");

fn assert_revert<E: SolError>(error: PrecompileError) {
    match error {
        PrecompileError::RevertBytes(bytes) => assert_eq!(&bytes[..4], E::SELECTOR),
        other => panic!("expected typed revert, got {other:?}"),
    }
}

fn initialization(ticker: &str) -> FactoryTokenInitialization {
    initialization_for(CHAIN_ID, ticker)
}

fn initialization_for(chain_id: u64, ticker: &str) -> FactoryTokenInitialization {
    let (token_id, token_address) = predict_stablecoin(
        chain_id,
        STABLECOIN_FACTORY_ADDRESS,
        ISSUER,
        ticker,
        STABLECOIN_ADDRESS_PREFIX,
    )
    .unwrap();
    FactoryTokenInitialization {
        token_address,
        token_id,
        creation_protocol_version: 0,
        payload: StablecoinCreatePayload {
            issuer: ISSUER,
            name: format!("{ticker} Stablecoin"),
            ticker: ticker.to_owned(),
            iso4217: 840,
            decimals: 6,
            supply_cap: U256::from(1_000_000_000u64),
            policy_id: ALLOW_ALL_POLICY_ID,
        },
    }
}

fn golden_permit_call() -> IStablecoin::permitCall {
    IStablecoin::permitCall {
        owner: PERMIT_OWNER,
        spender: PERMIT_SPENDER,
        value: U256::from(123),
        deadline: U256::from(1_000),
        v: 27,
        r: b256!("c950efadce76e65dd301a34af5cfc60a8bd2eb0a7c8e3ff961b2bade7c8e7dc7"),
        s: b256!("03b8238df3821137d7de64a1bedd28d4a846c19c0be68d1bf4ffbb57c2275380"),
    }
}

fn permit_baseline(
    init: &FactoryTokenInitialization,
    current_allowance: U256,
    frozen: U256,
    timestamp: U256,
) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_timestamp(timestamp);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        if !current_allowance.is_zero() {
            token
                .approve(PERMIT_OWNER, PERMIT_SPENDER, current_allowance)
                .unwrap();
        }
        if !frozen.is_zero() {
            token
                .set_frozen_tokens(ISSUER, PERMIT_OWNER, frozen)
                .unwrap();
        }
    });
    provider.clear_events(init.token_address);
    provider.clear_mutation_failure();
    provider
}

fn transfer_from_baseline(
    init: &FactoryTokenInitialization,
    owner: Address,
    spender: Address,
) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(owner, U256::from(100)).unwrap();
        token.approve(owner, spender, U256::from(60)).unwrap();
    });
    provider.clear_events(init.token_address);
    provider.clear_mutation_failure();
    provider
}

fn pending_admin_baseline(
    init: &FactoryTokenInitialization,
    candidate: Address,
) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(init)
            .unwrap();
        StablecoinContract::new(storage, init.token_address)
            .begin_admin_transfer(ISSUER, candidate)
            .unwrap();
    });
    provider.clear_events(init.token_address);
    provider.clear_mutation_failure();
    provider
}

fn forced_transfer_baseline(
    init: &FactoryTokenInitialization,
    from: Address,
) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(from, U256::from(100)).unwrap();
        token
            .set_frozen_tokens(ISSUER, from, U256::from(80))
            .unwrap();
    });
    provider.clear_events(init.token_address);
    provider.clear_mutation_failure();
    provider
}

#[test]
fn layout_is_pinned_to_the_documented_root_slots() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, initialization("USDX").token_address);
        assert_eq!(token.schema_version.slot(), U256::from(0));
        assert_eq!(token.creation_protocol_version.slot(), U256::from(1));
        assert_eq!(token.token_id.slot(), U256::from(2));
        assert_eq!(token.currency.slot(), U256::from(5));
        assert_eq!(token.decimals.slot(), U256::from(6));
        assert_eq!(token.issuer.slot(), U256::from(7));
        assert_eq!(token.supply_cap.slot(), U256::from(8));
        assert_eq!(token.total_supply.slot(), U256::from(9));
        assert_eq!(token.policy_id.slot(), U256::from(10));
        assert_eq!(token.paused.slot(), U256::from(11));
        assert_eq!(token.admin.slot(), U256::from(12));
        assert_eq!(token.pending_admin.slot(), U256::from(13));
        assert_eq!(token.balances.base_slot(), U256::from(14));
        assert_eq!(token.allowances.base_slot(), U256::from(15));
        assert_eq!(token.nonces.base_slot(), U256::from(16));
        assert_eq!(token.roles.base_slot(), U256::from(17));
        assert_eq!(token.frozen.base_slot(), U256::from(18));
    });
}

#[test]
fn role_ids_match_the_frozen_abi_vectors() {
    assert_eq!(ADMIN_ROLE, keccak256("ADMIN"));
    assert_eq!(ISSUER_ROLE, keccak256("ISSUER"));
    assert_eq!(CAP_MANAGER_ROLE, keccak256("CAP_MANAGER"));
    assert_eq!(GUARDIAN_ROLE, keccak256("GUARDIAN"));
    assert_eq!(COMPLIANCE_ROLE, keccak256("COMPLIANCE"));
    assert_eq!(ENFORCER_ROLE, keccak256("ENFORCER"));
}

#[test]
fn factory_initialization_sets_identity_roles_and_zero_supply() {
    let init = initialization("USDX");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let token = StablecoinContract::new(storage, init.token_address);

        assert_eq!(
            token.schema_version.read().unwrap(),
            u64::from(STABLECOIN_V1_SCHEMA_VERSION)
        );
        assert_eq!(
            token.creation_protocol_version.read().unwrap(),
            init.creation_protocol_version
        );
        assert_eq!(token.token_id.read().unwrap(), init.token_id);
        assert_eq!(token.name.read_string().unwrap(), "USDX Stablecoin");
        assert_eq!(token.symbol.read_string().unwrap(), "USDX");
        assert_eq!(token.currency.read().unwrap(), 840);
        assert_eq!(token.decimals.read().unwrap(), 6);
        assert_eq!(token.issuer.read().unwrap(), ISSUER);
        assert_eq!(token.supply_cap.read().unwrap(), init.payload.supply_cap);
        assert_eq!(token.total_supply.read().unwrap(), U256::ZERO);
        assert_eq!(token.policy_id.read().unwrap(), ALLOW_ALL_POLICY_ID);
        assert!(!token.paused.read().unwrap());
        assert_eq!(token.admin.read().unwrap(), ISSUER);
        assert_eq!(token.pending_admin.read().unwrap(), Address::ZERO);
        assert!(token.roles.read(&role_key(ADMIN_ROLE, ISSUER)).unwrap());
        for role in OPERATIONAL_ROLES {
            assert!(token.roles.read(&role_key(role, ISSUER)).unwrap());
        }
    });
}

#[test]
fn token_addresses_are_storage_isolated() {
    let first = initialization("USDX");
    let second = initialization("EURX");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let factory = StablecoinFactoryApi::new(storage.clone());
        factory.initialize(&first).unwrap();
        factory.initialize(&second).unwrap();

        let first_token = StablecoinContract::new(storage.clone(), first.token_address);
        let second_token = StablecoinContract::new(storage, second.token_address);
        assert_eq!(first_token.symbol.read_string().unwrap(), "USDX");
        assert_eq!(second_token.symbol.read_string().unwrap(), "EURX");
        assert_eq!(first_token.token_id.read().unwrap(), first.token_id);
        assert_eq!(second_token.token_id.read().unwrap(), second.token_id);
    });
}

#[test]
fn invalid_or_repeated_initialization_does_not_mutate_state() {
    let valid = initialization("USDX");
    let mut invalid = valid.clone();
    invalid.token_id = B256::repeat_byte(0x44);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);

    StorageHandle::enter(&mut provider, |storage| {
        let factory = StablecoinFactoryApi::new(storage.clone());
        assert!(matches!(
            factory.initialize(&invalid),
            Err(PrecompileError::Revert(_))
        ));
        let token = StablecoinContract::new(storage.clone(), valid.token_address);
        assert_eq!(token.schema_version.read().unwrap(), 0);
        assert!(token.name.is_empty().unwrap());

        factory.initialize(&valid).unwrap();
        assert!(matches!(
            factory.initialize(&valid),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(token.token_id.read().unwrap(), valid.token_id);
        assert_eq!(token.total_supply.read().unwrap(), U256::ZERO);
    });
}

#[test]
fn unknown_schema_fails_closed_with_exact_migration_error() {
    let init = initialization("USDX");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage.clone(), init.token_address);
        token.schema_version.write(9).unwrap();
        assert!(matches!(
            StablecoinFactoryApi::new(storage).initialize(&init),
            Err(PrecompileError::Fatal(_))
        ));
        let error = token.identity().unwrap_err();
        let expected = IStablecoin::MigrationRequired {
            storedSchemaVersion: 9,
            activeSchemaVersion: u64::from(STABLECOIN_V1_SCHEMA_VERSION),
        }
        .abi_encode();
        assert!(matches!(
            error,
            PrecompileError::RevertBytes(bytes) if bytes.as_ref() == expected
        ));
        assert_eq!(token.schema_version.read().unwrap(), 9);
        assert!(token.name.is_empty().unwrap());
    });
}

#[test]
fn non_pristine_root_is_rejected_without_overwrite() {
    let init = initialization("USDX");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider
        .sstore(init.token_address, U256::from(8), U256::from(777))
        .unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let factory = StablecoinFactoryApi::new(storage.clone());
        assert!(matches!(
            factory.initialize(&init),
            Err(PrecompileError::Fatal(_))
        ));
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(token.schema_version.read().unwrap(), 0);
        assert_eq!(token.supply_cap.read().unwrap(), U256::from(777));
    });
}

#[test]
fn every_injected_initialization_failure_rolls_back_all_token_state() {
    let init = initialization("USDX");
    let mut measured = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut measured, |storage| {
        StablecoinFactoryApi::new(storage)
            .initialize(&init)
            .unwrap();
    });
    let operation_count = measured.clear_mutation_failure();
    assert!(operation_count > 6);

    for failure_at in 0..operation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.fail_after_mutation_at(failure_at);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(StablecoinFactoryApi::new(storage)
                .initialize(&init)
                .is_err());
        });
        provider.clear_mutation_failure();

        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.schema_version.read().unwrap(), 0);
            assert!(token.name.is_empty().unwrap());
            assert!(token.symbol.is_empty().unwrap());
            assert_eq!(token.token_id.read().unwrap(), B256::ZERO);
            assert_eq!(token.admin.read().unwrap(), Address::ZERO);
            assert!(!token.roles.read(&role_key(ADMIN_ROLE, ISSUER)).unwrap());
            for role in OPERATIONAL_ROLES {
                assert!(!token.roles.read(&role_key(role, ISSUER)).unwrap());
            }
        });
    }
}

#[test]
fn erc20_core_handles_transfer_approval_and_infinite_allowance() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x21);
    let bob = Address::repeat_byte(0x22);
    let spender = Address::repeat_byte(0x23);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);

    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(alice, U256::from(100)).unwrap();
        token.transfer(alice, bob, U256::from(25)).unwrap();
        token.approve(alice, spender, U256::from(40)).unwrap();
        token
            .transfer_from(spender, alice, bob, U256::from(10))
            .unwrap();

        assert_eq!(token.total_supply().unwrap(), U256::from(100));
        assert_eq!(token.balance_of(alice).unwrap(), U256::from(65));
        assert_eq!(token.balance_of(bob).unwrap(), U256::from(35));
        assert_eq!(token.allowance_of(alice, spender).unwrap(), U256::from(30));

        token.approve(alice, spender, U256::MAX).unwrap();
        token
            .transfer_from(spender, alice, bob, U256::from(5))
            .unwrap();
        assert_eq!(token.allowance_of(alice, spender).unwrap(), U256::MAX);
        assert_eq!(token.balance_of(alice).unwrap(), U256::from(60));
        assert_eq!(token.balance_of(bob).unwrap(), U256::from(40));
    });
}

#[test]
fn self_transfer_preserves_max_balance_and_still_emits() {
    let mut init = initialization("USDX");
    init.payload.supply_cap = U256::MAX;
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(ISSUER, U256::MAX).unwrap();
        token.transfer(ISSUER, ISSUER, U256::MAX).unwrap();
        token.approve(ISSUER, ISSUER, U256::MAX).unwrap();
        token
            .transfer_from(ISSUER, ISSUER, ISSUER, U256::MAX)
            .unwrap();
        assert_eq!(token.balance_of(ISSUER).unwrap(), U256::MAX);
        assert_eq!(token.total_supply().unwrap(), U256::MAX);
        assert_eq!(token.allowance_of(ISSUER, ISSUER).unwrap(), U256::MAX);
    });
}

#[test]
fn pfs_010_07_cap_failures_restore_supply_balances_and_events() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x31);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
    });

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);

        assert!(matches!(
            token.mint_core(alice, U256::ZERO),
            Err(PrecompileError::RevertBytes(_))
        ));
        assert!(matches!(
            token.burn_core(alice, U256::ZERO),
            Err(PrecompileError::RevertBytes(_))
        ));
    });
    assert!(provider.get_events(init.token_address).is_empty());

    StorageHandle::enter(&mut provider, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .mint_core(alice, init.payload.supply_cap)
            .unwrap();
    });
    assert_eq!(provider.get_events(init.token_address).len(), 1);

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        assert!(matches!(
            token.mint_core(alice, U256::from(1)),
            Err(PrecompileError::RevertBytes(_))
        ));
        assert_eq!(token.total_supply().unwrap(), init.payload.supply_cap);
        assert_eq!(token.balance_of(alice).unwrap(), init.payload.supply_cap);
    });
    assert_eq!(provider.get_events(init.token_address).len(), 1);

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.burn_core(alice, U256::from(17)).unwrap();
        assert_eq!(
            token.total_supply().unwrap(),
            init.payload.supply_cap - U256::from(17)
        );
        assert_eq!(
            token.balance_of(alice).unwrap(),
            init.payload.supply_cap - U256::from(17)
        );
    });
    assert_eq!(provider.get_events(init.token_address).len(), 2);

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        assert!(matches!(
            token.burn_core(alice, init.payload.supply_cap),
            Err(PrecompileError::RevertBytes(_))
        ));
        assert_eq!(
            token.total_supply().unwrap(),
            init.payload.supply_cap - U256::from(17)
        );
        assert_eq!(
            token.balance_of(alice).unwrap(),
            init.payload.supply_cap - U256::from(17)
        );
    });
    assert_eq!(provider.get_events(init.token_address).len(), 2);
}

#[test]
fn erc20_core_uses_the_exact_public_error_selectors() {
    let mut init = initialization("USDX");
    init.payload.supply_cap = U256::from(10);
    let alice = Address::repeat_byte(0x35);
    let bob = Address::repeat_byte(0x36);
    let spender = Address::repeat_byte(0x37);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);

        assert_revert::<IStablecoin::InvalidAddress>(
            token
                .transfer(alice, Address::ZERO, U256::ZERO)
                .unwrap_err(),
        );
        assert_revert::<IStablecoin::InvalidAmount>(
            token.mint_core(alice, U256::ZERO).unwrap_err(),
        );
        assert_revert::<IStablecoin::InsufficientBalance>(
            token.transfer(alice, bob, U256::from(1)).unwrap_err(),
        );
        assert_revert::<IStablecoin::InsufficientAllowance>(
            token
                .transfer_from(spender, alice, bob, U256::from(1))
                .unwrap_err(),
        );
        token.mint_core(alice, U256::from(10)).unwrap();
        assert_revert::<IStablecoin::SupplyCapExceeded>(
            token.mint_core(alice, U256::from(1)).unwrap_err(),
        );
    });
}

#[test]
fn erc20_zero_value_transfer_is_valid_and_invalid_addresses_fail_before_writes() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x41);
    let bob = Address::repeat_byte(0x42);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.transfer(alice, bob, U256::ZERO).unwrap();
        assert_eq!(token.balance_of(alice).unwrap(), U256::ZERO);
        assert_eq!(token.balance_of(bob).unwrap(), U256::ZERO);

        for result in [
            token.transfer(alice, Address::ZERO, U256::ZERO),
            token.approve(alice, Address::ZERO, U256::from(1)),
            token.mint_core(Address::ZERO, U256::from(1)),
            token.burn_core(Address::ZERO, U256::from(1)),
        ] {
            assert!(matches!(result, Err(PrecompileError::RevertBytes(_))));
        }
        assert_eq!(token.total_supply().unwrap(), U256::ZERO);
    });
}

#[test]
fn erc20_events_use_the_exact_canonical_log_shapes() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x51);
    let bob = Address::repeat_byte(0x52);
    let spender = Address::repeat_byte(0x53);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(alice, U256::from(10)).unwrap();
        token.approve(alice, spender, U256::from(7)).unwrap();
        token.transfer(alice, bob, U256::from(3)).unwrap();
        token.burn_core(bob, U256::from(1)).unwrap();
    });

    let events = provider.get_events(init.token_address);
    assert_eq!(events.len(), 4);
    assert_eq!(
        events[0],
        IStablecoin::Transfer {
            from: Address::ZERO,
            to: alice,
            value: U256::from(10),
        }
        .encode_log_data()
    );
    assert_eq!(
        events[1],
        IStablecoin::Approval {
            owner: alice,
            spender,
            value: U256::from(7),
        }
        .encode_log_data()
    );
    assert_eq!(
        events[2],
        IStablecoin::Transfer {
            from: alice,
            to: bob,
            value: U256::from(3),
        }
        .encode_log_data()
    );
    assert_eq!(
        events[3],
        IStablecoin::Transfer {
            from: bob,
            to: Address::ZERO,
            value: U256::from(1),
        }
        .encode_log_data()
    );
}

#[test]
fn erc20_abi_core_roundtrips_and_rejects_value_before_schema_reads() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x61);
    let bob = Address::repeat_byte(0x62);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        StablecoinContract::new(storage, init.token_address)
            .mint_core(alice, U256::from(20))
            .unwrap();
    });

    let name = dispatch(
        StorageHandle::new(&mut provider),
        init.token_address,
        &IStablecoin::nameCall {}.abi_encode(),
        alice,
        U256::ZERO,
    )
    .unwrap();
    assert_eq!(
        IStablecoin::nameCall::abi_decode_returns(&name).unwrap(),
        "USDX Stablecoin"
    );
    let transferred = dispatch(
        StorageHandle::new(&mut provider),
        init.token_address,
        &IStablecoin::transferCall {
            to: bob,
            value: U256::from(4),
        }
        .abi_encode(),
        alice,
        U256::ZERO,
    )
    .unwrap();
    assert!(IStablecoin::transferCall::abi_decode_returns(&transferred).unwrap());

    let dirty = initialization("EURX").token_address;
    let error = dispatch(
        StorageHandle::new(&mut provider),
        dirty,
        &IStablecoin::totalSupplyCall {}.abi_encode(),
        alice,
        U256::from(1),
    )
    .unwrap_err();
    assert_revert::<IStablecoin::UnexpectedValue>(error);
    assert_eq!(
        provider.sload(dirty, U256::ZERO).unwrap(),
        U256::ZERO,
        "unexpected value must be rejected before token state access"
    );
}

#[test]
fn malformed_or_noncanonical_abi_never_mutates_token_state() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x63);
    let bob = Address::repeat_byte(0x64);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        StablecoinContract::new(storage, init.token_address)
            .mint_core(alice, U256::from(20))
            .unwrap();
    });
    provider.clear_events(init.token_address);

    let canonical = IStablecoin::transferCall {
        to: bob,
        value: U256::from(4),
    }
    .abi_encode();
    let mut trailing = canonical.clone();
    trailing.push(0);
    let malformed = [
        Vec::new(),
        vec![0xde, 0xad, 0xbe, 0xef],
        canonical[..canonical.len() - 1].to_vec(),
        trailing,
    ];

    for calldata in malformed {
        assert!(matches!(
            dispatch(
                StorageHandle::new(&mut provider),
                init.token_address,
                &calldata,
                alice,
                U256::ZERO,
            ),
            Err(PrecompileError::Revert(_))
        ));
    }

    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(token.balance_of(alice).unwrap(), U256::from(20));
        assert_eq!(token.balance_of(bob).unwrap(), U256::ZERO);
        assert_eq!(token.total_supply().unwrap(), U256::from(20));
    });
    assert!(provider.get_events(init.token_address).is_empty());
}

#[test]
fn deterministic_erc20_sequences_match_a_reference_model() {
    let init = initialization("USDX");
    let accounts = [
        Address::repeat_byte(0x71),
        Address::repeat_byte(0x72),
        Address::repeat_byte(0x73),
    ];
    let mut balances = [0u64; 3];
    let mut allowances = [[U256::ZERO; 3]; 3];
    let mut supply = 0u64;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);

    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);

        for step in 0..512 {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            seed ^= seed << 8;
            let operation = (seed % 5) as usize;
            let first = ((seed >> 8) % 3) as usize;
            let second = ((seed >> 16) % 3) as usize;
            let third = ((seed >> 24) % 3) as usize;
            let amount = (seed >> 32) % 31;

            match operation {
                0 => {
                    let expected = amount != 0
                        && supply
                            .checked_add(amount)
                            .is_some_and(|next| U256::from(next) <= init.payload.supply_cap);
                    let result = token.mint_core(accounts[first], U256::from(amount));
                    assert_eq!(result.is_ok(), expected, "mint step {step}");
                    if expected {
                        balances[first] += amount;
                        supply += amount;
                    }
                }
                1 => {
                    let expected = amount != 0 && balances[first] >= amount;
                    let result = token.burn_core(accounts[first], U256::from(amount));
                    assert_eq!(result.is_ok(), expected, "burn step {step}");
                    if expected {
                        balances[first] -= amount;
                        supply -= amount;
                    }
                }
                2 => {
                    let expected = balances[first] >= amount;
                    let result =
                        token.transfer(accounts[first], accounts[second], U256::from(amount));
                    assert_eq!(result.is_ok(), expected, "transfer step {step}");
                    if expected && first != second {
                        balances[first] -= amount;
                        balances[second] += amount;
                    }
                }
                3 => {
                    let value = if step % 37 == 0 {
                        U256::MAX
                    } else {
                        U256::from(amount)
                    };
                    token
                        .approve(accounts[first], accounts[second], value)
                        .unwrap();
                    allowances[first][second] = value;
                }
                4 => {
                    let allowance = allowances[first][second];
                    let expected = allowance >= U256::from(amount) && balances[first] >= amount;
                    let result = token.transfer_from(
                        accounts[second],
                        accounts[first],
                        accounts[third],
                        U256::from(amount),
                    );
                    assert_eq!(result.is_ok(), expected, "transferFrom step {step}");
                    if expected {
                        if allowance != U256::MAX {
                            allowances[first][second] -= U256::from(amount);
                        }
                        if first != third {
                            balances[first] -= amount;
                            balances[third] += amount;
                        }
                    }
                }
                _ => unreachable!(),
            }

            assert_eq!(token.total_supply().unwrap(), U256::from(supply));
            assert_eq!(balances.iter().sum::<u64>(), supply);
            for owner in 0..3 {
                assert_eq!(
                    token.balance_of(accounts[owner]).unwrap(),
                    U256::from(balances[owner]),
                    "balance mismatch at step {step}"
                );
                for spender in 0..3 {
                    assert_eq!(
                        token
                            .allowance_of(accounts[owner], accounts[spender])
                            .unwrap(),
                        allowances[owner][spender],
                        "allowance mismatch at step {step}"
                    );
                }
            }
        }
    });
}

#[test]
fn transfer_from_rolls_back_allowance_balances_and_log_at_every_failure_point() {
    let init = initialization("USDX");
    let owner = Address::repeat_byte(0x81);
    let spender = Address::repeat_byte(0x82);
    let recipient = Address::repeat_byte(0x83);

    let mut measured = transfer_from_baseline(&init, owner, spender);
    StorageHandle::enter(&mut measured, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .transfer_from(spender, owner, recipient, U256::from(25))
            .unwrap();
    });
    let operation_count = measured.clear_mutation_failure();
    assert!(operation_count >= 4);

    for failure_at in 0..operation_count {
        let mut provider = transfer_from_baseline(&init, owner, spender);
        provider.fail_after_mutation_at(failure_at);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(StablecoinContract::new(storage, init.token_address)
                .transfer_from(spender, owner, recipient, U256::from(25))
                .is_err());
        });
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.balance_of(owner).unwrap(), U256::from(100));
            assert_eq!(token.balance_of(recipient).unwrap(), U256::ZERO);
            assert_eq!(token.allowance_of(owner, spender).unwrap(), U256::from(60));
            assert_eq!(token.total_supply().unwrap(), U256::from(100));
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }
}

#[test]
fn operational_roles_are_admin_managed_and_repeats_are_eventless_noops() {
    let init = initialization("USDX");
    let account = Address::repeat_byte(0x91);
    let attacker = Address::repeat_byte(0x92);
    let unknown_role = B256::repeat_byte(0xcc);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);

        assert_revert::<IStablecoin::Unauthorized>(
            token
                .grant_role(attacker, ISSUER_ROLE, account)
                .unwrap_err(),
        );
        assert_revert::<IStablecoin::UnsupportedRole>(
            token.grant_role(ISSUER, ADMIN_ROLE, account).unwrap_err(),
        );
        assert_revert::<IStablecoin::UnsupportedRole>(
            token.grant_role(ISSUER, unknown_role, account).unwrap_err(),
        );
        assert!(!token.has_role(unknown_role, account).unwrap());

        token.grant_role(ISSUER, ISSUER_ROLE, account).unwrap();
        assert!(token.has_role(ISSUER_ROLE, account).unwrap());
    });
    let events_after_grant = provider.get_events(init.token_address).len();
    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.grant_role(ISSUER, ISSUER_ROLE, account).unwrap();
    });
    assert_eq!(
        provider.get_events(init.token_address).len(),
        events_after_grant
    );
    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.revoke_role(ISSUER, ISSUER_ROLE, account).unwrap();
        assert!(!token.has_role(ISSUER_ROLE, account).unwrap());
    });
    let events_after_revoke = provider.get_events(init.token_address).len();
    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.revoke_role(ISSUER, ISSUER_ROLE, account).unwrap();
    });
    assert_eq!(
        provider.get_events(init.token_address).len(),
        events_after_revoke
    );

    let events = provider.get_events(init.token_address);
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        IStablecoin::RoleGranted {
            role: ISSUER_ROLE,
            account,
            actor: ISSUER,
        }
        .encode_log_data()
    );
    assert_eq!(
        events[1],
        IStablecoin::RoleRevoked {
            role: ISSUER_ROLE,
            account,
            actor: ISSUER,
        }
        .encode_log_data()
    );
}

#[test]
fn token_admin_transfer_is_two_step_and_never_creates_two_admins() {
    let init = initialization("USDX");
    let candidate = Address::repeat_byte(0xa1);
    let other = Address::repeat_byte(0xa2);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);

        assert_revert::<IStablecoin::InvalidPendingAdmin>(
            token
                .begin_admin_transfer(ISSUER, Address::ZERO)
                .unwrap_err(),
        );
        assert_revert::<IStablecoin::Unauthorized>(
            token.begin_admin_transfer(other, candidate).unwrap_err(),
        );
        token.begin_admin_transfer(ISSUER, candidate).unwrap();
        assert_eq!(token.pending_admin.read().unwrap(), candidate);
        assert_revert::<IStablecoin::NotPendingAdmin>(
            token.accept_admin_transfer(other).unwrap_err(),
        );
        token.cancel_admin_transfer(ISSUER).unwrap();
        assert_eq!(token.pending_admin.read().unwrap(), Address::ZERO);

        token.begin_admin_transfer(ISSUER, candidate).unwrap();
        token.accept_admin_transfer(candidate).unwrap();
        assert_eq!(token.admin.read().unwrap(), candidate);
        assert_eq!(token.pending_admin.read().unwrap(), Address::ZERO);
        assert!(!token.has_role(ADMIN_ROLE, ISSUER).unwrap());
        assert!(token.has_role(ADMIN_ROLE, candidate).unwrap());
        assert_revert::<IStablecoin::Unauthorized>(
            token.grant_role(ISSUER, GUARDIAN_ROLE, other).unwrap_err(),
        );
        token.grant_role(candidate, GUARDIAN_ROLE, other).unwrap();
    });
}

#[test]
fn pause_blocks_ledger_paths_but_keeps_recovery_paths_available() {
    let init = initialization("USDX");
    let holder = Address::repeat_byte(0xb1);
    let spender = Address::repeat_byte(0xb2);
    let guardian = Address::repeat_byte(0xb3);
    let role_member = Address::repeat_byte(0xb4);
    let admin_candidate = Address::repeat_byte(0xb5);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint(ISSUER, holder, U256::from(100)).unwrap();
        token.approve(holder, spender, U256::from(70)).unwrap();
        token.grant_role(ISSUER, GUARDIAN_ROLE, guardian).unwrap();
        token.revoke_role(ISSUER, GUARDIAN_ROLE, ISSUER).unwrap();
        token.pause(guardian).unwrap();

        assert_revert::<IStablecoin::TokenPaused>(
            token.transfer(holder, spender, U256::ZERO).unwrap_err(),
        );
        assert_revert::<IStablecoin::TokenPaused>(
            token
                .transfer_from(spender, holder, spender, U256::from(1))
                .unwrap_err(),
        );
        assert_revert::<IStablecoin::TokenPaused>(
            token.mint(ISSUER, holder, U256::from(1)).unwrap_err(),
        );
        assert_revert::<IStablecoin::TokenPaused>(token.burn(ISSUER, U256::from(1)).unwrap_err());
        assert_revert::<IStablecoin::TokenPaused>(
            token.burn_from(spender, holder, U256::from(1)).unwrap_err(),
        );

        // Recovery/configuration remains live while paused.
        token.approve(holder, spender, U256::from(20)).unwrap();
        token
            .grant_role(ISSUER, COMPLIANCE_ROLE, role_member)
            .unwrap();
        token.set_supply_cap(ISSUER, U256::from(1_000)).unwrap();
        token.begin_admin_transfer(ISSUER, admin_candidate).unwrap();
        token.cancel_admin_transfer(ISSUER).unwrap();

        assert_eq!(token.allowance_of(holder, spender).unwrap(), U256::from(20));
        assert_eq!(token.balance_of(holder).unwrap(), U256::from(100));
        assert_eq!(token.total_supply().unwrap(), U256::from(100));
        assert_revert::<IStablecoin::Unauthorized>(token.unpause(guardian).unwrap_err());
        token.unpause(ISSUER).unwrap();
        assert_revert::<IStablecoin::TokenNotPaused>(token.unpause(ISSUER).unwrap_err());
        token.transfer(holder, spender, U256::from(1)).unwrap();
    });
}

#[test]
fn mint_burn_burn_from_and_cap_follow_the_fixed_roles() {
    let init = initialization("USDX");
    let holder = Address::repeat_byte(0xc1);
    let spender = Address::repeat_byte(0xc2);
    let attacker = Address::repeat_byte(0xc3);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);

        assert_revert::<IStablecoin::Unauthorized>(
            token.mint(attacker, holder, U256::from(1)).unwrap_err(),
        );
        token.mint(ISSUER, holder, U256::from(100)).unwrap();
        token.mint(ISSUER, ISSUER, U256::from(20)).unwrap();
        token.burn(ISSUER, U256::from(5)).unwrap();

        token.approve(holder, spender, U256::from(40)).unwrap();
        token.burn_from(spender, holder, U256::from(15)).unwrap();
        assert_eq!(token.allowance_of(holder, spender).unwrap(), U256::from(25));
        token.approve(holder, spender, U256::MAX).unwrap();
        token.burn_from(spender, holder, U256::from(10)).unwrap();
        assert_eq!(token.allowance_of(holder, spender).unwrap(), U256::MAX);
        assert_eq!(token.balance_of(holder).unwrap(), U256::from(75));
        assert_eq!(token.balance_of(ISSUER).unwrap(), U256::from(15));
        assert_eq!(token.total_supply().unwrap(), U256::from(90));

        assert_revert::<IStablecoin::Unauthorized>(
            token.set_supply_cap(attacker, U256::from(100)).unwrap_err(),
        );
        assert_revert::<IStablecoin::SupplyCapBelowSupply>(
            token.set_supply_cap(ISSUER, U256::from(89)).unwrap_err(),
        );
        token.set_supply_cap(ISSUER, U256::from(90)).unwrap();
        assert_eq!(token.supply_cap.read().unwrap(), U256::from(90));
    });
}

#[test]
fn pfs_010_07_role_failures_restore_state_and_events() {
    let init = initialization("USDX");
    let attacker = Address::repeat_byte(0xd1);
    let target = Address::repeat_byte(0xd2);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);

        for step in 0..256 {
            let error = match step % 8 {
                0 => token.grant_role(attacker, ISSUER_ROLE, target),
                1 => token.revoke_role(attacker, ISSUER_ROLE, ISSUER),
                2 => token.pause(attacker),
                3 => token.unpause(attacker),
                4 => token.set_supply_cap(attacker, U256::from(step)),
                5 => token.begin_admin_transfer(attacker, target),
                6 => token.mint(attacker, target, U256::from(1)),
                7 => token.burn(attacker, U256::from(1)),
                _ => unreachable!(),
            }
            .unwrap_err();
            assert_revert::<IStablecoin::Unauthorized>(error);
        }

        assert_eq!(token.admin.read().unwrap(), ISSUER);
        assert_eq!(token.pending_admin.read().unwrap(), Address::ZERO);
        assert!(!token.paused.read().unwrap());
        assert_eq!(token.supply_cap.read().unwrap(), init.payload.supply_cap);
        assert_eq!(token.total_supply().unwrap(), U256::ZERO);
        assert!(!token.has_role(ISSUER_ROLE, target).unwrap());
    });
    assert!(provider.get_events(init.token_address).is_empty());
}

#[test]
fn admin_acceptance_rolls_back_both_roles_and_slots_at_every_failure_point() {
    let init = initialization("USDX");
    let candidate = Address::repeat_byte(0xe1);
    let mut measured = pending_admin_baseline(&init, candidate);
    StorageHandle::enter(&mut measured, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .accept_admin_transfer(candidate)
            .unwrap();
    });
    let operation_count = measured.clear_mutation_failure();
    assert!(operation_count >= 5);

    for failure_at in 0..operation_count {
        let mut provider = pending_admin_baseline(&init, candidate);
        provider.fail_after_mutation_at(failure_at);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(StablecoinContract::new(storage, init.token_address)
                .accept_admin_transfer(candidate)
                .is_err());
        });
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.admin.read().unwrap(), ISSUER);
            assert_eq!(token.pending_admin.read().unwrap(), candidate);
            assert!(token.has_role(ADMIN_ROLE, ISSUER).unwrap());
            assert!(!token.has_role(ADMIN_ROLE, candidate).unwrap());
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }
}

#[test]
fn policy_lanes_drive_public_erc7943_results_without_registry_errors() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0xf1);
    let bob = Address::repeat_byte(0xf2);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut registry = StablecoinPolicyRegistryContract::new(storage.clone());
        let send_whitelist = registry
            .create_policy(ISSUER, PolicyType::Whitelist as u8, ISSUER)
            .unwrap();
        registry
            .add_members(send_whitelist, ISSUER, &[alice])
            .unwrap();
        let directional = registry
            .create_directional_policy(
                ISSUER,
                ISSUER,
                send_whitelist,
                ALLOW_ALL_POLICY_ID,
                DENY_ALL_POLICY_ID,
            )
            .unwrap();

        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(alice, U256::from(100)).unwrap();
        token.set_policy_id(ISSUER, directional).unwrap();

        assert!(token.can_send(alice).unwrap());
        assert!(!token.can_send(bob).unwrap());
        assert!(token.can_receive(bob).unwrap());
        assert!(token.can_transfer(alice, bob, U256::from(1_000)).unwrap());
        assert!(!token.can_transfer(bob, alice, U256::ZERO).unwrap());

        token.transfer(alice, bob, U256::from(10)).unwrap();
        assert_revert::<IStablecoin::ERC7943CannotSend>(
            token.transfer(bob, alice, U256::ZERO).unwrap_err(),
        );
        assert_revert::<IStablecoin::ERC7943CannotReceive>(
            token.mint(ISSUER, bob, U256::from(1)).unwrap_err(),
        );

        let unknown = U256::from(999_999u64);
        assert_revert::<IStablecoin::UnknownPolicy>(
            token.set_policy_id(ISSUER, unknown).unwrap_err(),
        );
        assert_eq!(token.policy_id.read().unwrap(), directional);
    });
}

#[test]
fn frozen_amount_covers_all_balance_relations_and_only_allows_allowance_reduction() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0xe1);
    let bob = Address::repeat_byte(0xe2);
    let spender = Address::repeat_byte(0xe3);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(alice, U256::from(100)).unwrap();
        token.approve(alice, spender, U256::from(50)).unwrap();
    });
    provider.clear_events(init.token_address);

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        token
            .set_frozen_tokens(ISSUER, alice, U256::from(60))
            .unwrap();
        token
            .set_frozen_tokens(ISSUER, alice, U256::from(60))
            .unwrap();
    });
    assert_eq!(
        provider.get_events(init.token_address),
        &vec![
            IStablecoin::Frozen {
                account: alice,
                amount: U256::from(60),
            }
            .encode_log_data(),
            IStablecoin::Frozen {
                account: alice,
                amount: U256::from(60),
            }
            .encode_log_data(),
        ]
    );

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        assert!(token.can_transfer(alice, bob, U256::from(40)).unwrap());
        assert!(!token.can_transfer(alice, bob, U256::from(41)).unwrap());
        assert_revert::<IStablecoin::FrozenAllowanceIncrease>(
            token.approve(alice, spender, U256::from(51)).unwrap_err(),
        );
        token.approve(alice, spender, U256::from(40)).unwrap();
        token.transfer(alice, bob, U256::from(40)).unwrap();

        assert_eq!(token.balance_of(alice).unwrap(), U256::from(60));
        assert!(token.can_transfer(alice, bob, U256::ZERO).unwrap());
        assert!(!token.can_transfer(alice, bob, U256::from(1)).unwrap());
        assert_revert::<IStablecoin::ERC7943InsufficientUnfrozenBalance>(
            token.transfer(alice, bob, U256::from(1)).unwrap_err(),
        );

        token
            .set_frozen_tokens(ISSUER, alice, U256::from(120))
            .unwrap();
        assert_eq!(token.frozen_tokens(alice).unwrap(), U256::from(120));
        assert!(!token.can_transfer(alice, bob, U256::from(1)).unwrap());
    });
}

#[test]
fn forced_transfer_bypasses_source_checks_consumes_only_frozen_units_and_orders_events() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0xd1);
    let bob = Address::repeat_byte(0xd2);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let directional = StablecoinPolicyRegistryContract::new(storage.clone())
            .create_directional_policy(
                ISSUER,
                ISSUER,
                DENY_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(alice, U256::from(100)).unwrap();
        token.set_policy_id(ISSUER, directional).unwrap();
        token
            .set_frozen_tokens(ISSUER, alice, U256::from(80))
            .unwrap();
    });
    provider.clear_events(init.token_address);

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        assert!(!token.can_send(alice).unwrap());
        token
            .forced_transfer(ISSUER, alice, bob, U256::from(30))
            .unwrap();
        assert_eq!(token.balance_of(alice).unwrap(), U256::from(70));
        assert_eq!(token.balance_of(bob).unwrap(), U256::from(30));
        assert_eq!(token.frozen_tokens(alice).unwrap(), U256::from(70));
        assert_eq!(token.total_supply().unwrap(), U256::from(100));
        assert_revert::<IStablecoin::ForcedSelfTransfer>(
            token
                .forced_transfer(ISSUER, alice, alice, U256::from(1))
                .unwrap_err(),
        );
    });
    assert_eq!(
        provider.get_events(init.token_address),
        &vec![
            IStablecoin::Frozen {
                account: alice,
                amount: U256::from(70),
            }
            .encode_log_data(),
            IStablecoin::Transfer {
                from: alice,
                to: bob,
                value: U256::from(30),
            }
            .encode_log_data(),
            IStablecoin::ForcedTransfer {
                from: alice,
                to: bob,
                amount: U256::from(30),
            }
            .encode_log_data(),
        ]
    );
}

#[test]
fn pfs_010_07_policy_failures_restore_balances_freeze_supply_and_events() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0xc1);
    let bob = Address::repeat_byte(0xc2);
    let mut denied = forced_transfer_baseline(&init, alice);
    StorageHandle::enter(&mut denied, |storage| {
        let directional = StablecoinPolicyRegistryContract::new(storage.clone())
            .create_directional_policy(
                ISSUER,
                ISSUER,
                ALLOW_ALL_POLICY_ID,
                DENY_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.set_policy_id(ISSUER, directional).unwrap();
    });
    denied.clear_events(init.token_address);
    StorageHandle::enter(&mut denied, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        assert_revert::<IStablecoin::ERC7943CannotReceive>(
            token
                .forced_transfer(ISSUER, alice, bob, U256::from(30))
                .unwrap_err(),
        );
        assert_eq!(token.balance_of(alice).unwrap(), U256::from(100));
        assert_eq!(token.balance_of(bob).unwrap(), U256::ZERO);
        assert_eq!(token.frozen_tokens(alice).unwrap(), U256::from(80));
    });
    assert!(denied.get_events(init.token_address).is_empty());

    let mut measured = forced_transfer_baseline(&init, alice);
    StorageHandle::enter(&mut measured, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .forced_transfer(ISSUER, alice, bob, U256::from(30))
            .unwrap();
    });
    let operation_count = measured.clear_mutation_failure();
    assert!(operation_count >= 6);

    for failure_at in 0..operation_count {
        let mut provider = forced_transfer_baseline(&init, alice);
        provider.fail_after_mutation_at(failure_at);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(StablecoinContract::new(storage, init.token_address)
                .forced_transfer(ISSUER, alice, bob, U256::from(30))
                .is_err());
        });
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.balance_of(alice).unwrap(), U256::from(100));
            assert_eq!(token.balance_of(bob).unwrap(), U256::ZERO);
            assert_eq!(token.frozen_tokens(alice).unwrap(), U256::from(80));
            assert_eq!(token.total_supply().unwrap(), U256::from(100));
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }
}

#[test]
fn issuer_burn_bypasses_send_policy_and_consumes_frozen_before_transfer_event() {
    let init = initialization("USDX");
    let holder = Address::repeat_byte(0xb1);
    let spender = Address::repeat_byte(0xb2);
    let attacker = Address::repeat_byte(0xb3);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let directional = StablecoinPolicyRegistryContract::new(storage.clone())
            .create_directional_policy(
                ISSUER,
                ISSUER,
                DENY_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(ISSUER, U256::from(100)).unwrap();
        token.mint_core(holder, U256::from(100)).unwrap();
        token.approve(holder, spender, U256::from(50)).unwrap();
        token.set_policy_id(ISSUER, directional).unwrap();
        token
            .set_frozen_tokens(ISSUER, ISSUER, U256::from(80))
            .unwrap();
        token
            .set_frozen_tokens(ISSUER, holder, U256::from(80))
            .unwrap();
    });
    provider.clear_events(init.token_address);

    StorageHandle::enter(&mut provider, |storage| {
        let mut token = StablecoinContract::new(storage, init.token_address);
        assert_revert::<IStablecoin::Unauthorized>(
            token.burn(attacker, U256::from(1)).unwrap_err(),
        );
        assert_revert::<IStablecoin::ERC7943CannotSend>(
            token
                .burn_from(spender, holder, U256::from(30))
                .unwrap_err(),
        );
        assert_eq!(token.allowance_of(holder, spender).unwrap(), U256::from(50));

        token.burn(ISSUER, U256::from(30)).unwrap();
        assert_eq!(token.balance_of(ISSUER).unwrap(), U256::from(70));
        assert_eq!(token.frozen_tokens(ISSUER).unwrap(), U256::from(70));
        assert_eq!(token.total_supply().unwrap(), U256::from(170));
    });
    assert_eq!(
        provider.get_events(init.token_address),
        &vec![
            IStablecoin::Frozen {
                account: ISSUER,
                amount: U256::from(70),
            }
            .encode_log_data(),
            IStablecoin::Transfer {
                from: ISSUER,
                to: Address::ZERO,
                value: U256::from(30),
            }
            .encode_log_data(),
        ]
    );
}

#[test]
fn erc7943_abi_reports_interface_and_roundtrips_views_and_mutations() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0xa1);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        StablecoinContract::new(storage, init.token_address)
            .mint_core(alice, U256::from(10))
            .unwrap();
    });

    for (interface_id, expected) in [
        ([0x01, 0xff, 0xc9, 0xa7], true),
        ([0x3e, 0xdb, 0xb4, 0xc4], true),
        ([0xde, 0xad, 0xbe, 0xef], false),
    ] {
        let output = dispatch(
            StorageHandle::new(&mut provider),
            init.token_address,
            &IStablecoin::supportsInterfaceCall {
                interfaceId: interface_id.into(),
            }
            .abi_encode(),
            alice,
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(
            IStablecoin::supportsInterfaceCall::abi_decode_returns(&output).unwrap(),
            expected
        );
    }

    let output = dispatch(
        StorageHandle::new(&mut provider),
        init.token_address,
        &IStablecoin::setFrozenTokensCall {
            account: alice,
            amount: U256::from(4),
        }
        .abi_encode(),
        ISSUER,
        U256::ZERO,
    )
    .unwrap();
    assert!(IStablecoin::setFrozenTokensCall::abi_decode_returns(&output).unwrap());

    let output = dispatch(
        StorageHandle::new(&mut provider),
        init.token_address,
        &IStablecoin::getFrozenTokensCall { account: alice }.abi_encode(),
        alice,
        U256::ZERO,
    )
    .unwrap();
    assert_eq!(
        IStablecoin::getFrozenTokensCall::abi_decode_returns(&output).unwrap(),
        U256::from(4)
    );
}

#[test]
fn permit_domain_and_cast_golden_signature_are_exact_and_work_at_deadline_while_paused() {
    let init = initialization("USDX");
    assert_eq!(
        init.token_address,
        address!("53c07065554d086969e4bc8944eb2331be50ff1a")
    );
    let mut provider = permit_baseline(&init, U256::from(200), U256::from(1), U256::from(1_000));
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .pause(ISSUER)
            .unwrap();
    });
    provider.clear_events(init.token_address);

    let domain_output = dispatch(
        StorageHandle::new(&mut provider),
        init.token_address,
        &IStablecoin::DOMAIN_SEPARATORCall {}.abi_encode(),
        Address::repeat_byte(0x99),
        U256::ZERO,
    )
    .unwrap();
    assert_eq!(
        IStablecoin::DOMAIN_SEPARATORCall::abi_decode_returns(&domain_output).unwrap(),
        b256!("bbf205147c84535a518d8c96008013f7bcb49f08a374448ecfeff86c3dcfde03")
    );

    let call = golden_permit_call();
    dispatch(
        StorageHandle::new(&mut provider),
        init.token_address,
        &call.abi_encode(),
        Address::repeat_byte(0x98),
        U256::ZERO,
    )
    .unwrap();
    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(
            token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
            U256::from(123)
        );
        assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::from(1));
        assert!(token.paused.read().unwrap());
    });
    assert_eq!(
        provider.get_events(init.token_address),
        &vec![IStablecoin::Approval {
            owner: PERMIT_OWNER,
            spender: PERMIT_SPENDER,
            value: U256::from(123),
        }
        .encode_log_data()]
    );

    assert_revert::<IStablecoin::InvalidPermitSignature>(
        dispatch(
            StorageHandle::new(&mut provider),
            init.token_address,
            &call.abi_encode(),
            Address::repeat_byte(0x97),
            U256::ZERO,
        )
        .unwrap_err(),
    );
    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::from(1));
        assert_eq!(
            token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
            U256::from(123)
        );
    });
}

#[test]
fn pfs_010_07_signature_failures_restore_nonce_allowance_and_events() {
    let init = initialization("USDX");
    let call = golden_permit_call();

    let mut expired = permit_baseline(&init, U256::ZERO, U256::ZERO, U256::from(1_001));
    assert_revert::<IStablecoin::PermitExpired>(
        dispatch(
            StorageHandle::new(&mut expired),
            init.token_address,
            &call.abi_encode(),
            Address::repeat_byte(0x91),
            U256::ZERO,
        )
        .unwrap_err(),
    );
    StorageHandle::enter(&mut expired, |storage| {
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
        assert_eq!(
            token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
            U256::ZERO
        );
    });
    assert!(expired.get_events(init.token_address).is_empty());

    let wrong_chain_init = initialization_for(CHAIN_ID + 1, "USDX");
    let mut wrong_chain = HashMapStorageProvider::new(CHAIN_ID + 1);
    StorageHandle::enter(&mut wrong_chain, |storage| {
        StablecoinFactoryApi::new(storage)
            .initialize(&wrong_chain_init)
            .unwrap();
    });
    assert_revert::<IStablecoin::InvalidPermitSignature>(
        dispatch(
            StorageHandle::new(&mut wrong_chain),
            wrong_chain_init.token_address,
            &call.abi_encode(),
            Address::repeat_byte(0x92),
            U256::ZERO,
        )
        .unwrap_err(),
    );
    StorageHandle::enter(&mut wrong_chain, |storage| {
        let token = StablecoinContract::new(storage, wrong_chain_init.token_address);
        assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
        assert_eq!(
            token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
            U256::ZERO
        );
    });
    assert!(wrong_chain
        .get_events(wrong_chain_init.token_address)
        .is_empty());

    let wrong_token_init = initialization("EURX");
    let mut wrong_token = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut wrong_token, |storage| {
        StablecoinFactoryApi::new(storage)
            .initialize(&wrong_token_init)
            .unwrap();
    });
    assert_revert::<IStablecoin::InvalidPermitSignature>(
        dispatch(
            StorageHandle::new(&mut wrong_token),
            wrong_token_init.token_address,
            &call.abi_encode(),
            Address::repeat_byte(0x93),
            U256::ZERO,
        )
        .unwrap_err(),
    );
    StorageHandle::enter(&mut wrong_token, |storage| {
        let token = StablecoinContract::new(storage, wrong_token_init.token_address);
        assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
        assert_eq!(
            token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
            U256::ZERO
        );
    });
    assert!(wrong_token
        .get_events(wrong_token_init.token_address)
        .is_empty());

    for changed_call in [
        IStablecoin::permitCall {
            value: U256::from(124),
            ..call
        },
        IStablecoin::permitCall {
            spender: Address::repeat_byte(0x94),
            ..call
        },
        IStablecoin::permitCall {
            deadline: U256::from(1_001),
            ..call
        },
    ] {
        let mut provider = permit_baseline(&init, U256::ZERO, U256::ZERO, U256::from(1_000));
        assert_revert::<IStablecoin::InvalidPermitSignature>(
            dispatch(
                StorageHandle::new(&mut provider),
                init.token_address,
                &changed_call.abi_encode(),
                Address::repeat_byte(0x95),
                U256::ZERO,
            )
            .unwrap_err(),
        );
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
            assert_eq!(
                token
                    .allowance_of(PERMIT_OWNER, changed_call.spender)
                    .unwrap(),
                U256::ZERO
            );
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }
}

#[test]
fn permit_rejects_noncanonical_vrs_and_high_s_malleability() {
    let init = initialization("USDX");
    let call = golden_permit_call();
    let high_s = b256!("fc47dc720c7deec828219b5e4122d72a12681b4aa362131fcad2a3350e0eedc1");
    for invalid_call in [
        IStablecoin::permitCall { v: 0, ..call },
        IStablecoin::permitCall {
            r: B256::ZERO,
            ..call
        },
        IStablecoin::permitCall {
            s: B256::ZERO,
            ..call
        },
        IStablecoin::permitCall {
            v: 28,
            s: high_s,
            ..call
        },
    ] {
        let mut provider = permit_baseline(&init, U256::ZERO, U256::ZERO, U256::from(1_000));
        assert_revert::<IStablecoin::InvalidPermitSignature>(
            dispatch(
                StorageHandle::new(&mut provider),
                init.token_address,
                &invalid_call.abi_encode(),
                Address::repeat_byte(0x96),
                U256::ZERO,
            )
            .unwrap_err(),
        );
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
            assert_eq!(
                token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
                U256::ZERO
            );
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }
}

#[test]
fn frozen_permit_increase_fails_after_valid_signature_without_consuming_nonce() {
    let init = initialization("USDX");
    let mut provider = permit_baseline(&init, U256::from(100), U256::from(1), U256::from(1_000));
    assert_revert::<IStablecoin::FrozenAllowanceIncrease>(
        dispatch(
            StorageHandle::new(&mut provider),
            init.token_address,
            &golden_permit_call().abi_encode(),
            Address::repeat_byte(0x88),
            U256::ZERO,
        )
        .unwrap_err(),
    );
    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
        assert_eq!(
            token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
            U256::from(100)
        );
    });
    assert!(provider.get_events(init.token_address).is_empty());
}

#[test]
fn permit_rolls_back_nonce_allowance_and_approval_log_after_every_failure() {
    let init = initialization("USDX");
    let mut measured = permit_baseline(&init, U256::from(200), U256::from(1), U256::from(1_000));
    dispatch(
        StorageHandle::new(&mut measured),
        init.token_address,
        &golden_permit_call().abi_encode(),
        Address::repeat_byte(0x81),
        U256::ZERO,
    )
    .unwrap();
    let operation_count = measured.clear_mutation_failure();
    assert_eq!(operation_count, 3);

    for failure_at in 0..operation_count {
        let mut provider =
            permit_baseline(&init, U256::from(200), U256::from(1), U256::from(1_000));
        provider.fail_after_mutation_at(failure_at);
        assert!(dispatch(
            StorageHandle::new(&mut provider),
            init.token_address,
            &golden_permit_call().abi_encode(),
            Address::repeat_byte(0x82),
            U256::ZERO,
        )
        .is_err());
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.nonces.read(&PERMIT_OWNER).unwrap(), U256::ZERO);
            assert_eq!(
                token.allowance_of(PERMIT_OWNER, PERMIT_SPENDER).unwrap(),
                U256::from(200)
            );
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }
}

#[test]
fn all_six_memo_selectors_reuse_base_operations_and_emit_memo_last() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x71);
    let bob = Address::repeat_byte(0x72);
    let spender = Address::repeat_byte(0x73);
    let zero_memo = B256::ZERO;
    let mixed_memo = b256!("00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100");
    let ones_memo = B256::repeat_byte(0xff);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        StablecoinFactoryApi::new(storage.clone())
            .initialize(&init)
            .unwrap();
        let mut token = StablecoinContract::new(storage, init.token_address);
        token.mint_core(alice, U256::from(100)).unwrap();
        token.mint_core(ISSUER, U256::from(50)).unwrap();
        token.approve(alice, spender, U256::from(50)).unwrap();
    });
    provider.clear_events(init.token_address);

    let calls = [
        IStablecoin::transferWithMemoCall {
            to: bob,
            amount: U256::from(10),
            memo: zero_memo,
        }
        .abi_encode(),
        IStablecoin::transferFromWithMemoCall {
            from: alice,
            to: bob,
            amount: U256::from(5),
            memo: mixed_memo,
        }
        .abi_encode(),
        IStablecoin::mintWithMemoCall {
            to: bob,
            amount: U256::from(7),
            memo: ones_memo,
        }
        .abi_encode(),
        IStablecoin::burnWithMemoCall {
            amount: U256::from(3),
            memo: zero_memo,
        }
        .abi_encode(),
        IStablecoin::burnFromWithMemoCall {
            from: alice,
            amount: U256::from(4),
            memo: mixed_memo,
        }
        .abi_encode(),
        IStablecoin::forcedTransferWithMemoCall {
            from: alice,
            to: bob,
            amount: U256::from(6),
            memo: ones_memo,
        }
        .abi_encode(),
    ];
    for (index, call) in calls.iter().enumerate() {
        let caller = match index {
            0 => alice,
            1 | 4 => spender,
            _ => ISSUER,
        };
        dispatch(
            StorageHandle::new(&mut provider),
            init.token_address,
            call,
            caller,
            U256::ZERO,
        )
        .unwrap();
    }

    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, init.token_address);
        assert_eq!(token.balance_of(alice).unwrap(), U256::from(75));
        assert_eq!(token.balance_of(bob).unwrap(), U256::from(28));
        assert_eq!(token.balance_of(ISSUER).unwrap(), U256::from(47));
        assert_eq!(token.total_supply().unwrap(), U256::from(150));
        assert_eq!(token.allowance_of(alice, spender).unwrap(), U256::from(41));
    });

    let events = provider.get_events(init.token_address);
    assert_eq!(events.len(), 13);
    let expected_memos = [
        (1, alice, bob, U256::from(10), zero_memo),
        (3, alice, bob, U256::from(5), mixed_memo),
        (5, Address::ZERO, bob, U256::from(7), ones_memo),
        (7, ISSUER, Address::ZERO, U256::from(3), zero_memo),
        (9, alice, Address::ZERO, U256::from(4), mixed_memo),
        (12, alice, bob, U256::from(6), ones_memo),
    ];
    for (index, from, to, amount, memo) in expected_memos {
        assert_eq!(
            events[index],
            IStablecoin::TransferWithMemo {
                from,
                to,
                amount,
                memo,
            }
            .encode_log_data()
        );
    }
    assert_eq!(
        events[10],
        IStablecoin::Transfer {
            from: alice,
            to: bob,
            value: U256::from(6),
        }
        .encode_log_data()
    );
    assert_eq!(
        events[11],
        IStablecoin::ForcedTransfer {
            from: alice,
            to: bob,
            amount: U256::from(6),
        }
        .encode_log_data()
    );
}

#[test]
fn arbitrary_memo_never_changes_state_and_failed_base_operation_emits_nothing() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x61);
    let bob = Address::repeat_byte(0x62);
    let memo = b256!("7c89ab01ff23dd45aa67ee890123456789abcdef0123456789abcdef01234567");
    let mut plain = HashMapStorageProvider::new(CHAIN_ID);
    let mut with_memo = HashMapStorageProvider::new(CHAIN_ID);
    for provider in [&mut plain, &mut with_memo] {
        StorageHandle::enter(provider, |storage| {
            StablecoinFactoryApi::new(storage.clone())
                .initialize(&init)
                .unwrap();
            StablecoinContract::new(storage, init.token_address)
                .mint_core(alice, U256::from(100))
                .unwrap();
        });
        provider.clear_events(init.token_address);
    }

    StorageHandle::enter(&mut plain, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .transfer(alice, bob, U256::from(37))
            .unwrap();
    });
    StorageHandle::enter(&mut with_memo, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .transfer_with_memo(alice, bob, U256::from(37), memo)
            .unwrap();
    });
    assert_eq!(plain.storage, with_memo.storage);
    assert_eq!(
        plain.get_events(init.token_address),
        &with_memo.get_events(init.token_address)[..1]
    );

    with_memo.clear_events(init.token_address);
    let before = with_memo.storage.clone();
    StorageHandle::enter(&mut with_memo, |storage| {
        assert_revert::<IStablecoin::InsufficientBalance>(
            StablecoinContract::new(storage, init.token_address)
                .transfer_with_memo(alice, bob, U256::from(1_000), memo)
                .unwrap_err(),
        );
    });
    assert_eq!(with_memo.storage, before);
    assert!(with_memo.get_events(init.token_address).is_empty());
}

#[test]
fn memo_event_failure_rolls_back_base_state_and_forced_memo_keeps_frozen_event_order() {
    let init = initialization("USDX");
    let alice = Address::repeat_byte(0x51);
    let bob = Address::repeat_byte(0x52);
    let memo = B256::repeat_byte(0xa5);

    let baseline = || {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut provider, |storage| {
            StablecoinFactoryApi::new(storage.clone())
                .initialize(&init)
                .unwrap();
            StablecoinContract::new(storage, init.token_address)
                .mint_core(alice, U256::from(100))
                .unwrap();
        });
        provider.clear_events(init.token_address);
        provider.clear_mutation_failure();
        provider
    };

    let mut measured = baseline();
    StorageHandle::enter(&mut measured, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .transfer_with_memo(alice, bob, U256::from(10), memo)
            .unwrap();
    });
    let operation_count = measured.clear_mutation_failure();
    assert_eq!(operation_count, 4);

    for failure_at in 0..operation_count {
        let mut provider = baseline();
        provider.fail_after_mutation_at(failure_at);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(StablecoinContract::new(storage, init.token_address)
                .transfer_with_memo(alice, bob, U256::from(10), memo)
                .is_err());
        });
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let token = StablecoinContract::new(storage, init.token_address);
            assert_eq!(token.balance_of(alice).unwrap(), U256::from(100));
            assert_eq!(token.balance_of(bob).unwrap(), U256::ZERO);
        });
        assert!(provider.get_events(init.token_address).is_empty());
    }

    let mut forced = forced_transfer_baseline(&init, alice);
    StorageHandle::enter(&mut forced, |storage| {
        StablecoinContract::new(storage, init.token_address)
            .forced_transfer_with_memo(ISSUER, alice, bob, U256::from(30), memo)
            .unwrap();
    });
    assert_eq!(
        forced.get_events(init.token_address),
        &vec![
            IStablecoin::Frozen {
                account: alice,
                amount: U256::from(70),
            }
            .encode_log_data(),
            IStablecoin::Transfer {
                from: alice,
                to: bob,
                value: U256::from(30),
            }
            .encode_log_data(),
            IStablecoin::ForcedTransfer {
                from: alice,
                to: bob,
                amount: U256::from(30),
            }
            .encode_log_data(),
            IStablecoin::TransferWithMemo {
                from: alice,
                to: bob,
                amount: U256::from(30),
                memo,
            }
            .encode_log_data(),
        ]
    );
}
