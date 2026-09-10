use alloy_primitives::{Address, FixedBytes, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use outbe_primitives::{
    error::PrecompileError,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

use crate::{
    precompile::{dispatch, IRadicleRegistry},
    repo_id_from_storage_key, repo_id_storage_key,
    schema::RadicleRegistry,
};

const CHAIN_ID: u64 = 1;

fn repo(byte: u8) -> FixedBytes<20> {
    FixedBytes::repeat_byte(byte)
}

fn with_registry<R>(maximum: u32, f: impl FnOnce(&mut RadicleRegistry<'_>) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = RadicleRegistry::new(storage);
        registry.config_max_repositories.write(maximum).unwrap();
        f(&mut registry)
    })
}

fn revert(error: PrecompileError) -> String {
    match error {
        PrecompileError::Revert(message) => message,
        other => panic!("expected revert, got {other:?}"),
    }
}

#[test]
fn canonical_repo_id_word_has_zero_twelve_byte_tail() {
    let id = repo(0x42);
    let key = repo_id_storage_key(id);
    assert_eq!(&key.as_slice()[..20], id.as_slice());
    assert_eq!(&key.as_slice()[20..], &[0_u8; 12]);
    assert_eq!(repo_id_from_storage_key(key).unwrap(), id);

    let mut malformed = [0_u8; 32];
    malformed[31] = 1;
    assert!(matches!(
        repo_id_from_storage_key(B256::from(malformed)),
        Err(PrecompileError::Fatal(_))
    ));
}

#[test]
fn registration_is_dense_unique_and_records_registrant_and_generation() {
    with_registry(2, |registry| {
        let alice = Address::repeat_byte(0xa1);
        let bob = Address::repeat_byte(0xb2);
        assert_eq!(
            registry.register_repository(repo(1), alice).unwrap().index,
            0
        );
        assert_eq!(registry.register_repository(repo(2), bob).unwrap().index, 1);
        assert_eq!(registry.repository_count.read().unwrap(), 2);
        assert_eq!(registry.registry_generation.read().unwrap(), 2);
        assert_eq!(registry.repository_at(0).unwrap(), repo(1));
        assert_eq!(registry.repository_at(1).unwrap(), repo(2));
        assert_eq!(registry.registrant_of(repo(1)).unwrap(), alice);
        assert_eq!(registry.registrant_of(repo(2)).unwrap(), bob);
        assert_eq!(
            registry
                .repository_index
                .read(&repo_id_storage_key(repo(2)))
                .unwrap(),
            2
        );
    });
}

#[test]
fn zero_duplicate_capacity_and_out_of_range_revert_without_advancing() {
    with_registry(1, |registry| {
        assert!(revert(
            registry
                .register_repository(FixedBytes::ZERO, Address::ZERO)
                .unwrap_err()
        )
        .contains("non-zero"));
        registry
            .register_repository(repo(1), Address::repeat_byte(1))
            .unwrap();
        assert!(revert(
            registry
                .register_repository(repo(1), Address::repeat_byte(2))
                .unwrap_err()
        )
        .contains("already"));
        assert!(revert(
            registry
                .register_repository(repo(2), Address::repeat_byte(2))
                .unwrap_err()
        )
        .contains("capacity"));
        assert!(revert(registry.repository_at(1).unwrap_err()).contains("outside"));
        assert_eq!(registry.repository_count.read().unwrap(), 1);
        assert_eq!(registry.registry_generation.read().unwrap(), 1);
    });
}

#[test]
fn unlimited_capacity() {
    with_registry(u32::MAX, |registry| {
        assert_eq!(registry.config_max_repositories.read().unwrap(), u32::MAX);
        registry
            .register_repository(repo(1), Address::repeat_byte(1))
            .unwrap();
        assert_eq!(registry.repository_count.read().unwrap(), 1);
    });
}

#[test]
fn storage_layout_slots_zero_through_five_are_stable() {
    with_registry(1, |registry| {
        assert_eq!(registry.repository_count.slot(), U256::from(0));
        assert_eq!(registry.repository_by_index.base_slot(), U256::from(1));
        assert_eq!(registry.repository_index.base_slot(), U256::from(2));
        assert_eq!(registry.repository_registrant.base_slot(), U256::from(3));
        assert_eq!(registry.registry_generation.slot(), U256::from(4));
        assert_eq!(registry.config_max_repositories.slot(), U256::from(5));
    });
}

#[test]
fn every_mutation_failure_rolls_back_the_whole_registration() {
    for operation in 0..=5 {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.enter(|storage| {
            RadicleRegistry::new(storage)
                .config_max_repositories
                .write(1)
                .unwrap();
        });
        provider.fail_after_mutation_at(operation);
        let result = provider.enter(|storage| {
            RadicleRegistry::new(storage).register_repository(repo(7), Address::repeat_byte(7))
        });
        assert!(result.is_err(), "operation {operation} must fail");
        provider.clear_mutation_failure();
        provider.enter(|storage| {
            let registry = RadicleRegistry::new(storage);
            assert_eq!(registry.repository_count.read().unwrap(), 0);
            assert_eq!(registry.registry_generation.read().unwrap(), 0);
            assert_eq!(
                registry
                    .repository_index
                    .read(&repo_id_storage_key(repo(7)))
                    .unwrap(),
                0
            );
        });
    }
}

#[test]
fn precompile_exposes_mutation_views_event_and_rejects_value() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.enter(|storage| {
        RadicleRegistry::new(storage)
            .config_max_repositories
            .write(3)
            .unwrap();
    });
    let caller = Address::repeat_byte(0x33);
    let data = IRadicleRegistry::registerRepositoryCall { repoId: repo(9) }.abi_encode();
    provider
        .enter(|storage| dispatch(storage, &data, caller, U256::ZERO))
        .unwrap();
    let events = provider.get_events(outbe_primitives::addresses::RADICLE_REGISTRY_ADDRESS);
    assert_eq!(events.len(), 1);
    let event = IRadicleRegistry::RepositoryRegistered::decode_log_data(&events[0]).unwrap();
    assert_eq!(event.repoId, repo(9));
    assert_eq!(event.registrant, caller);
    assert_eq!(event.index, 0);
    assert_eq!(event.generation, 1);

    let count = IRadicleRegistry::repositoryCountCall {}.abi_encode();
    let output = provider
        .enter(|storage| dispatch(storage, &count, Address::ZERO, U256::ZERO))
        .unwrap();
    assert_eq!(
        IRadicleRegistry::repositoryCountCall::abi_decode_returns(&output).unwrap(),
        1
    );

    let at = IRadicleRegistry::repositoryAtCall { index: 0 }.abi_encode();
    let output = provider
        .enter(|storage| dispatch(storage, &at, Address::ZERO, U256::ZERO))
        .unwrap();
    assert_eq!(
        IRadicleRegistry::repositoryAtCall::abi_decode_returns(&output).unwrap(),
        repo(9)
    );

    let registrant = IRadicleRegistry::repositoryRegistrantCall { repoId: repo(9) }.abi_encode();
    let output = provider
        .enter(|storage| dispatch(storage, &registrant, Address::ZERO, U256::ZERO))
        .unwrap();
    assert_eq!(
        IRadicleRegistry::repositoryRegistrantCall::abi_decode_returns(&output).unwrap(),
        caller
    );

    let generation = IRadicleRegistry::registryGenerationCall {}.abi_encode();
    let output = provider
        .enter(|storage| dispatch(storage, &generation, Address::ZERO, U256::ZERO))
        .unwrap();
    assert_eq!(
        IRadicleRegistry::registryGenerationCall::abi_decode_returns(&output).unwrap(),
        1
    );

    let maximum = IRadicleRegistry::maxRepositoriesCall {}.abi_encode();
    let output = provider
        .enter(|storage| dispatch(storage, &maximum, Address::ZERO, U256::ZERO))
        .unwrap();
    assert_eq!(
        IRadicleRegistry::maxRepositoriesCall::abi_decode_returns(&output).unwrap(),
        3
    );
    assert!(provider
        .enter(|storage| dispatch(storage, &count, Address::ZERO, U256::from(1)))
        .is_err());
}
