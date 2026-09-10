use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, SolError, SolEvent};
use outbe_primitives::addresses::STABLECOIN_POLICY_REGISTRY_ADDRESS;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::stablecoin_fork::{
    STABLECOIN_LIST_PAGE_CAP, STABLECOIN_POLICY_MEMBER_BATCH_CAP,
};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::types::StorageKey;
use outbe_primitives::storage::StorageHandle;

use crate::precompile::dispatch;
use crate::precompile::IStablecoinPolicyRegistry as I;
use crate::schema::{
    PolicyLane, PolicyType, StablecoinPolicyRegistryContract, ALLOW_ALL_POLICY_ID,
    DENY_ALL_POLICY_ID,
};

fn admin() -> Address {
    Address::repeat_byte(0x11)
}

fn other() -> Address {
    Address::repeat_byte(0x22)
}

fn member(index: u8) -> Address {
    Address::with_last_byte(index)
}

fn assert_revert<E: SolError>(error: PrecompileError) {
    match error {
        PrecompileError::RevertBytes(bytes) => assert_eq!(&bytes[..4], E::SELECTOR),
        other => panic!("expected revert, got {other:?}"),
    }
}

fn with_registry(test: impl FnOnce(StorageHandle<'_>, StablecoinPolicyRegistryContract<'_>)) {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        test(
            storage.clone(),
            StablecoinPolicyRegistryContract::new(storage),
        );
    });
}

fn invoke<C: SolCall>(
    provider: &mut HashMapStorageProvider,
    caller: Address,
    call: C,
) -> C::Return {
    let output = dispatch(
        StorageHandle::new(provider),
        &call.abi_encode(),
        caller,
        U256::ZERO,
    )
    .unwrap();
    C::abi_decode_returns(&output).unwrap()
}

#[test]
fn v1_layout_and_first_id_are_stable() {
    with_registry(|storage, mut registry| {
        assert_eq!(registry.next_policy_id.slot(), U256::ZERO);
        assert_eq!(registry.policies.base_slot(), U256::from(1u64));
        assert_eq!(registry.member_sets.base_slot(), U256::from(8u64));

        let policy_id = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        assert_eq!(policy_id, U256::from(2u64));
        assert_eq!(
            storage
                .sload(STABLECOIN_POLICY_REGISTRY_ADDRESS, U256::ZERO)
                .unwrap(),
            U256::from(3u64)
        );

        let exists_slot = policy_id.mapping_slot(U256::from(1u64));
        let type_slot = policy_id.mapping_slot(U256::from(2u64));
        let admin_slot = policy_id.mapping_slot(U256::from(3u64));
        assert_eq!(
            storage
                .sload(STABLECOIN_POLICY_REGISTRY_ADDRESS, exists_slot)
                .unwrap(),
            U256::from(1u64)
        );
        assert_eq!(
            storage
                .sload(STABLECOIN_POLICY_REGISTRY_ADDRESS, type_slot)
                .unwrap(),
            U256::from(PolicyType::Whitelist as u8)
        );
        assert_eq!(
            storage
                .sload(STABLECOIN_POLICY_REGISTRY_ADDRESS, admin_slot)
                .unwrap(),
            U256::from_be_slice(admin().as_slice())
        );
    });
}

#[test]
fn builtins_always_exist_and_unknown_views_are_explicit() {
    with_registry(|_, registry| {
        assert!(registry.policy_exists(DENY_ALL_POLICY_ID).unwrap());
        assert!(registry.policy_exists(ALLOW_ALL_POLICY_ID).unwrap());
        assert_eq!(
            registry.policy_type(DENY_ALL_POLICY_ID).unwrap(),
            PolicyType::DenyAll
        );
        assert_eq!(
            registry.policy_type(ALLOW_ALL_POLICY_ID).unwrap(),
            PolicyType::AllowAll
        );
        assert_eq!(
            registry.policy_admin(ALLOW_ALL_POLICY_ID).unwrap(),
            Address::ZERO
        );

        let unknown = U256::from(77u64);
        assert!(!registry.policy_exists(unknown).unwrap());
        assert!(!registry.is_member(unknown, member(1)).unwrap());
        assert!(!registry.can(unknown, member(1), PolicyLane::Send).unwrap());
        assert_revert::<I::UnknownPolicy>(registry.policy_type(unknown).unwrap_err());
    });
}

#[test]
fn checked_policy_id_exhaustion_writes_nothing() {
    with_registry(|_, mut registry| {
        registry.next_policy_id.write(U256::MAX).unwrap();
        let error = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap_err();
        assert_revert::<I::PolicyIdExhausted>(error);
        assert_eq!(registry.next_policy_id.read().unwrap(), U256::MAX);
        assert!(!registry.policies.exists(U256::MAX).unwrap());
    });
}

#[test]
fn simple_policy_truth_tables_are_exact() {
    with_registry(|_, mut registry| {
        let account = member(1);
        let whitelist = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let blacklist = registry
            .create_policy(other(), PolicyType::Blacklist as u8, admin())
            .unwrap();

        for lane in [PolicyLane::Send, PolicyLane::Receive, PolicyLane::Mint] {
            assert!(!registry.can(DENY_ALL_POLICY_ID, account, lane).unwrap());
            assert!(registry.can(ALLOW_ALL_POLICY_ID, account, lane).unwrap());
            assert!(!registry.can(whitelist, account, lane).unwrap());
            assert!(registry.can(blacklist, account, lane).unwrap());
        }

        registry
            .add_members(whitelist, admin(), &[account])
            .unwrap();
        registry
            .add_members(blacklist, admin(), &[account])
            .unwrap();
        for lane in [PolicyLane::Send, PolicyLane::Receive, PolicyLane::Mint] {
            assert!(registry.can(whitelist, account, lane).unwrap());
            assert!(!registry.can(blacklist, account, lane).unwrap());
        }
    });
}

#[test]
fn directional_policy_selects_one_non_recursive_child_per_lane() {
    with_registry(|_, mut registry| {
        let account = member(1);
        let whitelist = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        registry
            .add_members(whitelist, admin(), &[account])
            .unwrap();

        let directional = registry
            .create_directional_policy(
                other(),
                admin(),
                whitelist,
                DENY_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap();
        assert!(registry
            .can(directional, account, PolicyLane::Send)
            .unwrap());
        assert!(!registry
            .can(directional, account, PolicyLane::Receive)
            .unwrap());
        assert!(registry
            .can(directional, account, PolicyLane::Mint)
            .unwrap());
        assert!(!registry.is_member(directional, account).unwrap());

        let error = registry
            .create_directional_policy(
                other(),
                admin(),
                directional,
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap_err();
        assert_revert::<I::InvalidDirectionalChild>(error);
        let error = registry
            .create_directional_policy(
                other(),
                admin(),
                U256::from(999u64),
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap_err();
        assert_revert::<I::InvalidDirectionalChild>(error);
    });
}

#[test]
fn corrupted_directional_links_and_descriptors_fail_closed_without_recursion() {
    with_registry(|_, mut registry| {
        let account = member(1);
        let directional = registry
            .create_directional_policy(
                other(),
                admin(),
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap();

        let mut descriptor = registry.descriptor(directional).unwrap();
        descriptor.send_policy_id = directional;
        registry.policies.update(&descriptor).unwrap();
        assert!(!registry
            .can(directional, account, PolicyLane::Send)
            .unwrap());

        descriptor.policy_type = 99;
        registry.policies.update(&descriptor).unwrap();
        assert!(!registry
            .can(directional, account, PolicyLane::Send)
            .unwrap());
        assert!(!registry.is_member(directional, account).unwrap());
        assert!(matches!(
            registry.policy_type(directional),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn creation_accepts_only_simple_types_and_nonzero_admin() {
    with_registry(|_, mut registry| {
        for policy_type in [
            PolicyType::DenyAll as u8,
            PolicyType::AllowAll as u8,
            PolicyType::Directional as u8,
            99,
        ] {
            let error = registry
                .create_policy(other(), policy_type, admin())
                .unwrap_err();
            assert_revert::<I::InvalidPolicyType>(error);
        }
        let error = registry
            .create_policy(other(), PolicyType::Whitelist as u8, Address::ZERO)
            .unwrap_err();
        assert_revert::<I::InvalidPolicyAdmin>(error);
        assert_eq!(registry.next_policy_id.read().unwrap(), U256::ZERO);
    });
}

#[test]
fn member_batches_validate_fully_before_writes() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let first = member(1);
        registry.add_members(policy_id, admin(), &[first]).unwrap();

        let cases = [
            Vec::new(),
            vec![member(2), Address::ZERO],
            vec![member(2), member(2)],
        ];
        for accounts in cases {
            assert!(registry.add_members(policy_id, admin(), &accounts).is_err());
            assert_eq!(
                registry.policy_member_count(policy_id).unwrap(),
                U256::from(1u64)
            );
            assert!(!registry.is_member(policy_id, member(2)).unwrap());
        }

        let oversized = (0..=STABLECOIN_POLICY_MEMBER_BATCH_CAP)
            .map(|index| Address::with_last_byte((index + 2) as u8))
            .collect::<Vec<_>>();
        assert_revert::<I::MemberBatchTooLarge>(
            registry
                .add_members(policy_id, admin(), &oversized)
                .unwrap_err(),
        );
        assert_eq!(
            registry.policy_member_count(policy_id).unwrap(),
            U256::from(1u64)
        );

        let unchanged = registry
            .add_members(policy_id, admin(), &[member(3), first])
            .unwrap_err();
        assert_revert::<I::MembershipUnchanged>(unchanged);
        assert!(!registry.is_member(policy_id, member(3)).unwrap());
    });
}

#[test]
fn member_batch_cap_and_dense_swap_remove_preserve_invariants() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let accounts = (1..=STABLECOIN_POLICY_MEMBER_BATCH_CAP)
            .map(|index| Address::with_last_byte(index as u8))
            .collect::<Vec<_>>();
        registry.add_members(policy_id, admin(), &accounts).unwrap();
        assert_eq!(
            registry.policy_member_count(policy_id).unwrap(),
            U256::from(STABLECOIN_POLICY_MEMBER_BATCH_CAP)
        );

        registry
            .remove_members(policy_id, admin(), &[accounts[10], accounts[31]])
            .unwrap();
        assert_eq!(
            registry.policy_member_count(policy_id).unwrap(),
            U256::from(STABLECOIN_POLICY_MEMBER_BATCH_CAP - 2)
        );
        for account in &accounts {
            let expected = *account != accounts[10] && *account != accounts[31];
            assert_eq!(registry.is_member(policy_id, *account).unwrap(), expected);
        }
        let page = registry
            .list_policy_members(policy_id, U256::ZERO, U256::from(STABLECOIN_LIST_PAGE_CAP))
            .unwrap();
        assert_eq!(page.len(), STABLECOIN_POLICY_MEMBER_BATCH_CAP - 2);
        assert!(page
            .iter()
            .all(|account| registry.is_member(policy_id, *account).unwrap()));
    });
}

#[test]
fn membership_requires_current_admin_and_simple_policy() {
    with_registry(|_, mut registry| {
        let simple = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let directional = registry
            .create_directional_policy(
                other(),
                admin(),
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
                ALLOW_ALL_POLICY_ID,
            )
            .unwrap();
        assert_revert::<I::UnauthorizedPolicyAdmin>(
            registry
                .add_members(simple, other(), &[member(1)])
                .unwrap_err(),
        );
        assert_revert::<I::DirectionalMembershipUnsupported>(
            registry
                .add_members(directional, admin(), &[member(1)])
                .unwrap_err(),
        );
        assert_revert::<I::ImmutablePolicy>(
            registry
                .add_members(ALLOW_ALL_POLICY_ID, admin(), &[member(1)])
                .unwrap_err(),
        );
    });
}

#[test]
fn membership_unchanged_is_typed_for_add_and_remove() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Blacklist as u8, admin())
            .unwrap();
        let account = member(1);
        let error = registry
            .remove_members(policy_id, admin(), &[account])
            .unwrap_err();
        assert_revert::<I::MembershipUnchanged>(error);
        registry
            .add_members(policy_id, admin(), &[account])
            .unwrap();
        let error = registry
            .add_members(policy_id, admin(), &[account])
            .unwrap_err();
        assert_revert::<I::MembershipUnchanged>(error);
    });
}

#[test]
fn member_paging_has_only_count_offset_and_bounded_limit() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let accounts = (1..=5).map(member).collect::<Vec<_>>();
        registry.add_members(policy_id, admin(), &accounts).unwrap();

        assert_eq!(
            registry
                .list_policy_members(policy_id, U256::from(2u64), U256::from(2u64))
                .unwrap(),
            accounts[2..4]
        );
        assert_eq!(
            registry
                .list_policy_members(policy_id, U256::from(4u64), U256::from(100u64))
                .unwrap(),
            accounts[4..]
        );
        assert!(registry
            .list_policy_members(policy_id, U256::from(5u64), U256::from(1u64))
            .unwrap()
            .is_empty());
        assert!(registry
            .list_policy_members(policy_id, U256::MAX, U256::from(1u64))
            .unwrap()
            .is_empty());

        for invalid in [U256::ZERO, U256::from(101u64)] {
            assert_revert::<I::InvalidListLimit>(
                registry
                    .list_policy_members(policy_id, U256::ZERO, invalid)
                    .unwrap_err(),
            );
        }
        assert_revert::<I::PolicyMemberEnumerationUnsupported>(
            registry
                .list_policy_members(ALLOW_ALL_POLICY_ID, U256::ZERO, U256::from(1u64))
                .unwrap_err(),
        );
    });
}

#[test]
fn admin_transfer_is_two_step_and_stale_nominees_cannot_accept() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let first_candidate = other();
        let replacement = Address::repeat_byte(0x33);

        registry
            .begin_policy_admin_transfer(policy_id, admin(), first_candidate)
            .unwrap();
        registry
            .begin_policy_admin_transfer(policy_id, admin(), replacement)
            .unwrap();
        assert_eq!(
            registry.pending_policy_admin(policy_id).unwrap(),
            replacement
        );
        assert_revert::<I::NotPendingPolicyAdmin>(
            registry
                .accept_policy_admin_transfer(policy_id, first_candidate)
                .unwrap_err(),
        );

        registry
            .accept_policy_admin_transfer(policy_id, replacement)
            .unwrap();
        assert_eq!(registry.policy_admin(policy_id).unwrap(), replacement);
        assert_eq!(
            registry.pending_policy_admin(policy_id).unwrap(),
            Address::ZERO
        );
        assert!(registry
            .add_members(policy_id, admin(), &[member(1)])
            .is_err());
        registry
            .add_members(policy_id, replacement, &[member(1)])
            .unwrap();
    });
}

#[test]
fn admin_transfer_cancel_clears_candidate() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Blacklist as u8, admin())
            .unwrap();
        registry
            .begin_policy_admin_transfer(policy_id, admin(), other())
            .unwrap();
        registry
            .cancel_policy_admin_transfer(policy_id, admin())
            .unwrap();
        assert_eq!(
            registry.pending_policy_admin(policy_id).unwrap(),
            Address::ZERO
        );
        assert!(registry
            .accept_policy_admin_transfer(policy_id, other())
            .is_err());
        assert!(registry
            .cancel_policy_admin_transfer(policy_id, admin())
            .is_err());
    });
}

#[test]
fn mixed_member_history_keeps_mapping_count_and_dense_index_in_sync() {
    with_registry(|_, mut registry| {
        let policy_id = registry
            .create_policy(other(), PolicyType::Whitelist as u8, admin())
            .unwrap();
        let universe = (1..=32).map(member).collect::<Vec<_>>();
        let mut expected = std::collections::HashSet::new();
        let mut seed = 0x5eed_u64;

        for _ in 0..256 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let account = universe[(seed as usize) % universe.len()];
            if expected.insert(account) {
                registry
                    .add_members(policy_id, admin(), &[account])
                    .unwrap();
            } else {
                expected.remove(&account);
                registry
                    .remove_members(policy_id, admin(), &[account])
                    .unwrap();
            }

            assert_eq!(
                registry.policy_member_count(policy_id).unwrap(),
                U256::from(expected.len())
            );
            for candidate in &universe {
                assert_eq!(
                    registry.is_member(policy_id, *candidate).unwrap(),
                    expected.contains(candidate)
                );
            }

            let dense = registry
                .list_policy_members(policy_id, U256::ZERO, U256::from(STABLECOIN_LIST_PAGE_CAP))
                .unwrap()
                .into_iter()
                .collect::<std::collections::HashSet<_>>();
            assert_eq!(dense, expected);
        }
    });
}

#[test]
fn precompile_dispatch_covers_every_selector_and_emits_typed_events() {
    let mut provider = HashMapStorageProvider::new(1);
    let actor = other();
    let current_admin = admin();
    let candidate = Address::repeat_byte(0x33);
    let account = member(1);

    let whitelist = invoke(
        &mut provider,
        actor,
        I::createPolicyCall {
            policyType: PolicyType::Whitelist as u8,
            admin: current_admin,
        },
    );
    assert_eq!(whitelist, U256::from(2u64));
    let blacklist = invoke(
        &mut provider,
        actor,
        I::createPolicyCall {
            policyType: PolicyType::Blacklist as u8,
            admin: current_admin,
        },
    );
    assert_eq!(blacklist, U256::from(3u64));
    let directional = invoke(
        &mut provider,
        actor,
        I::createDirectionalPolicyCall {
            admin: current_admin,
            sendPolicyId: whitelist,
            receivePolicyId: DENY_ALL_POLICY_ID,
            mintPolicyId: ALLOW_ALL_POLICY_ID,
        },
    );
    assert_eq!(directional, U256::from(4u64));

    invoke(
        &mut provider,
        current_admin,
        I::addMembersCall {
            policyId: whitelist,
            accounts: vec![account],
        },
    );
    assert!(invoke(
        &mut provider,
        actor,
        I::policyExistsCall {
            policyId: whitelist
        }
    ));
    assert_eq!(
        invoke(
            &mut provider,
            actor,
            I::policyTypeCall {
                policyId: whitelist
            }
        ),
        PolicyType::Whitelist as u8
    );
    assert_eq!(
        invoke(
            &mut provider,
            actor,
            I::policyAdminCall {
                policyId: whitelist
            }
        ),
        current_admin
    );
    assert!(invoke(
        &mut provider,
        actor,
        I::isMemberCall {
            policyId: whitelist,
            account,
        }
    ));
    assert_eq!(
        invoke(
            &mut provider,
            actor,
            I::policyMemberCountCall {
                policyId: whitelist
            }
        ),
        U256::from(1u64)
    );
    assert_eq!(
        invoke(
            &mut provider,
            actor,
            I::listPolicyMembersCall {
                policyId: whitelist,
                offset: U256::ZERO,
                limit: U256::from(10u64),
            }
        ),
        vec![account]
    );
    assert!(invoke(
        &mut provider,
        actor,
        I::canSendCall {
            policyId: directional,
            account,
        }
    ));
    assert!(!invoke(
        &mut provider,
        actor,
        I::canReceiveCall {
            policyId: directional,
            account,
        }
    ));
    assert!(invoke(
        &mut provider,
        actor,
        I::canMintCall {
            policyId: directional,
            account,
        }
    ));

    invoke(
        &mut provider,
        current_admin,
        I::beginPolicyAdminTransferCall {
            policyId: whitelist,
            candidate,
        },
    );
    assert_eq!(
        invoke(
            &mut provider,
            actor,
            I::pendingPolicyAdminCall {
                policyId: whitelist
            }
        ),
        candidate
    );
    invoke(
        &mut provider,
        current_admin,
        I::cancelPolicyAdminTransferCall {
            policyId: whitelist,
        },
    );
    invoke(
        &mut provider,
        current_admin,
        I::beginPolicyAdminTransferCall {
            policyId: whitelist,
            candidate,
        },
    );
    invoke(
        &mut provider,
        candidate,
        I::acceptPolicyAdminTransferCall {
            policyId: whitelist,
        },
    );
    invoke(
        &mut provider,
        candidate,
        I::removeMembersCall {
            policyId: whitelist,
            accounts: vec![account],
        },
    );

    let signatures = provider
        .get_events(STABLECOIN_POLICY_REGISTRY_ADDRESS)
        .iter()
        .map(|event| event.topics()[0])
        .collect::<Vec<_>>();
    assert_eq!(
        signatures,
        vec![
            I::PolicyCreated::SIGNATURE_HASH,
            I::PolicyCreated::SIGNATURE_HASH,
            I::PolicyCreated::SIGNATURE_HASH,
            I::PolicyMemberAdded::SIGNATURE_HASH,
            I::PolicyAdminTransferStarted::SIGNATURE_HASH,
            I::PolicyAdminTransferCancelled::SIGNATURE_HASH,
            I::PolicyAdminTransferStarted::SIGNATURE_HASH,
            I::PolicyAdminTransferred::SIGNATURE_HASH,
            I::PolicyMemberRemoved::SIGNATURE_HASH,
        ]
    );
}

#[test]
fn precompile_rejects_value_and_malformed_or_trailing_calldata() {
    let mut provider = HashMapStorageProvider::new(1);
    let call = I::policyExistsCall {
        policyId: ALLOW_ALL_POLICY_ID,
    }
    .abi_encode();

    assert_revert::<I::UnexpectedValue>(
        dispatch(
            StorageHandle::new(&mut provider),
            &call,
            other(),
            U256::from(1u64),
        )
        .unwrap_err(),
    );
    assert!(provider
        .get_events(STABLECOIN_POLICY_REGISTRY_ADDRESS)
        .is_empty());

    assert!(dispatch(
        StorageHandle::new(&mut provider),
        &[0x01, 0x02, 0x03],
        other(),
        U256::ZERO,
    )
    .is_err());

    let mut trailing = call;
    trailing.push(0);
    assert!(dispatch(
        StorageHandle::new(&mut provider),
        &trailing,
        other(),
        U256::ZERO,
    )
    .is_err());
}

#[test]
fn arbitrary_calldata_never_panics_or_mutates_policy_state() {
    let mut provider = HashMapStorageProvider::new(1);
    let mut seed = 0x51ab_1ec7_u64;

    for length in 0..=256usize {
        let mut data = vec![0u8; length];
        for byte in &mut data {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *byte = (seed >> 32) as u8;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dispatch(
                StorageHandle::new(&mut provider),
                &data,
                other(),
                U256::ZERO,
            )
        }));
        assert!(result.is_ok());
    }

    StorageHandle::enter(&mut provider, |storage| {
        let registry = StablecoinPolicyRegistryContract::new(storage);
        assert_eq!(registry.next_policy_id.read().unwrap(), U256::ZERO);
    });
    assert!(provider
        .get_events(STABLECOIN_POLICY_REGISTRY_ADDRESS)
        .is_empty());
}

#[test]
fn static_context_allows_views_and_rejects_mutations() {
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_static(true);
    assert!(invoke(
        &mut provider,
        other(),
        I::policyExistsCall {
            policyId: ALLOW_ALL_POLICY_ID
        }
    ));

    let error = dispatch(
        StorageHandle::new(&mut provider),
        &I::createPolicyCall {
            policyType: PolicyType::Whitelist as u8,
            admin: admin(),
        }
        .abi_encode(),
        other(),
        U256::ZERO,
    )
    .unwrap_err();
    assert!(matches!(error, PrecompileError::WriteProtection));
}

#[test]
fn create_and_batch_roll_back_storage_and_logs_on_injected_failure() {
    let create = I::createPolicyCall {
        policyType: PolicyType::Whitelist as u8,
        admin: admin(),
    };

    let mut measured = HashMapStorageProvider::new(1);
    invoke(&mut measured, other(), create.clone());
    let operation_count = measured.clear_mutation_failure();
    assert!(operation_count > 1);

    for failure_at in 0..operation_count {
        let mut provider = HashMapStorageProvider::new(1);
        provider.fail_after_mutation_at(failure_at);
        assert!(dispatch(
            StorageHandle::new(&mut provider),
            &create.abi_encode(),
            other(),
            U256::ZERO,
        )
        .is_err());
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            let registry = StablecoinPolicyRegistryContract::new(storage);
            assert_eq!(registry.next_policy_id.read().unwrap(), U256::ZERO);
            assert!(!registry.policy_exists(U256::from(2u64)).unwrap());
        });
        assert!(provider
            .get_events(STABLECOIN_POLICY_REGISTRY_ADDRESS)
            .is_empty());
    }

    let mut provider = HashMapStorageProvider::new(1);
    let policy_id = invoke(&mut provider, other(), create);
    provider.clear_events(STABLECOIN_POLICY_REGISTRY_ADDRESS);
    provider.fail_after_mutation_at(2);
    assert!(dispatch(
        StorageHandle::new(&mut provider),
        &I::addMembersCall {
            policyId: policy_id,
            accounts: vec![member(1), member(2)],
        }
        .abi_encode(),
        admin(),
        U256::ZERO,
    )
    .is_err());
    provider.clear_mutation_failure();
    StorageHandle::enter(&mut provider, |storage| {
        let registry = StablecoinPolicyRegistryContract::new(storage);
        assert_eq!(registry.policy_member_count(policy_id).unwrap(), U256::ZERO);
    });
    assert!(provider
        .get_events(STABLECOIN_POLICY_REGISTRY_ADDRESS)
        .is_empty());
}
