use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolError, SolEvent};
use outbe_primitives::{
    addresses::{STABLECOIN_FACTORY_ADDRESS, STABLECOIN_MARKER_CODE},
    block::BlockContext,
    error::PrecompileError,
    stablecoin::{
        encode_canonical_stablecoin_create, StablecoinCreatePayload, MAX_NAME_LEN, MAX_TICKER_LEN,
    },
    stablecoin_fork::{STABLECOIN_LIST_PAGE_CAP, STABLECOIN_V1_SCHEMA_VERSION},
    storage::{direct::DirectStorageProvider, hashmap::HashMapStorageProvider, StorageHandle},
};
use outbe_stablecoin::StablecoinContract;
use revm::{
    database::{CacheDB, EmptyDB},
    state::{AccountInfo, Bytecode},
    Database,
};

use crate::{
    abi::IStablecoinFactory as I,
    api::{FactoryReservation, StablecoinFactoryApi},
    precompile::dispatch,
    schema::StablecoinFactoryContract,
};

fn with_factory(test: impl FnOnce(StorageHandle<'_>, StablecoinFactoryContract<'_>)) {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        test(storage.clone(), StablecoinFactoryContract::new(storage));
    });
}

fn reservation(
    factory: &StablecoinFactoryContract<'_>,
    proposal_id: u64,
    issuer: Address,
    ticker: &str,
) -> FactoryReservation {
    let (token_id, token) = factory.predict_token_address(issuer, ticker).unwrap();
    FactoryReservation {
        proposal_id: U256::from(proposal_id),
        token_id,
        ticker: ticker.to_owned(),
        token,
    }
}

fn assert_revert<E: SolError>(error: PrecompileError) {
    match error {
        PrecompileError::RevertBytes(bytes) => assert_eq!(&bytes[..4], E::SELECTOR),
        other => panic!("expected revert, got {other:?}"),
    }
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

fn create_payload(issuer: Address, policy_id: U256) -> StablecoinCreatePayload {
    StablecoinCreatePayload {
        issuer,
        name: "Example Dollar".into(),
        ticker: "EXUSD".into(),
        iso4217: 840,
        decimals: 6,
        supply_cap: U256::from(1_000_000_000_000u64),
        policy_id,
    }
}

#[test]
fn canonical_admission_returns_pinned_identity_and_ignores_native_balance() {
    let issuer = Address::repeat_byte(0x11);
    let expected_token_id =
        b256!("2cf34bcaf12fe89ab2f3f6f34667f667dc28c8716bdac45fd1696b34000f2863");
    let expected_token = address!("53c0f667dc28c8716bdac45fd1696b34000f2863");
    let native_balance = U256::from(123_456u64);
    let raw = encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64)))
        .expect("valid test payload");
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(expected_token, native_balance);

    StorageHandle::enter(&mut provider, |storage| {
        let validated = StablecoinFactoryApi::validate_create(storage, issuer, &raw).unwrap();
        assert_eq!(validated.payload, create_payload(issuer, U256::from(1u64)));
        assert_eq!(validated.token_id, expected_token_id);
        assert_eq!(validated.token, expected_token);
    });

    assert!(
        provider.storage.is_empty(),
        "validation must not write Factory or Policy state"
    );
    assert_eq!(provider.get_balance(expected_token), native_balance);
}

#[test]
fn malformed_or_noncanonical_payloads_revert_without_writes() {
    let issuer = Address::repeat_byte(0x11);
    let canonical =
        encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64))).unwrap();
    let mut trailing = canonical.clone();
    trailing.push(b'\n');
    let invalid_metadata = br#"{"version":1,"kind":"StablecoinCreate","issuer":"0x1111111111111111111111111111111111111111","name":"Example Dollar","ticker":"EXUSD","iso4217":840,"decimals":19,"supplyCap":"1000000000000","policyId":"1"}"#;
    let cases: [&[u8]; 4] = [b"{", b"\xff", &trailing, invalid_metadata];
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        for raw in cases {
            assert_revert::<I::NonCanonicalPayload>(
                StablecoinFactoryApi::validate_create(storage.clone(), issuer, raw)
                    .expect_err("invalid payload"),
            );
        }
    });

    assert!(provider.storage.is_empty());
}

#[test]
fn proposer_and_policy_validation_fail_before_any_write() {
    let issuer = Address::repeat_byte(0x11);
    let wrong_proposer = Address::repeat_byte(0x22);
    let valid =
        encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64))).unwrap();
    let missing_policy =
        encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(99u64))).unwrap();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        assert_revert::<I::InvalidIssuer>(
            StablecoinFactoryApi::validate_create(storage.clone(), wrong_proposer, &valid)
                .expect_err("proposer must be issuer"),
        );
        assert_revert::<I::UnknownPolicy>(
            StablecoinFactoryApi::validate_create(storage, issuer, &missing_policy)
                .expect_err("policy must exist"),
        );
    });

    assert!(provider.storage.is_empty());
}

#[test]
fn admission_checks_the_same_pending_and_permanent_indexes_as_reservation() {
    with_factory(|storage, mut factory| {
        let issuer = Address::repeat_byte(0x11);
        let raw =
            encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64))).unwrap();
        let validated =
            StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw).unwrap();
        let item = FactoryReservation {
            proposal_id: U256::from(1u64),
            token_id: validated.token_id,
            ticker: validated.payload.ticker,
            token: validated.token,
        };
        factory.reserve(&item).unwrap();
        assert_revert::<I::TokenIdReserved>(
            StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw)
                .expect_err("pending identity"),
        );

        factory.consume_and_register(item.proposal_id).unwrap();
        assert_revert::<I::TokenIdAlreadyRegistered>(
            StablecoinFactoryApi::validate_create(storage, issuer, &raw)
                .expect_err("permanent identity"),
        );
    });
}

#[test]
fn approved_execution_initializes_marker_registry_and_one_canonical_event() {
    let issuer = Address::repeat_byte(0x11);
    let proposal_id = U256::from(7u64);
    let raw = encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64)))
        .expect("valid payload");
    let token = address!("53c0f667dc28c8716bdac45fd1696b34000f2863");
    let native_balance = U256::from(777u64);
    let mut provider = HashMapStorageProvider::new(1);
    provider.set_balance(token, native_balance);

    let created = StorageHandle::enter(&mut provider, |storage| {
        let validated =
            StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw).unwrap();
        StablecoinFactoryApi::reserve(
            storage.clone(),
            &FactoryReservation {
                proposal_id,
                token_id: validated.token_id,
                ticker: validated.payload.ticker.clone(),
                token: validated.token,
            },
        )
        .unwrap();

        let created =
            StablecoinFactoryApi::execute_approved(storage.clone(), proposal_id, issuer, &raw, 0)
                .unwrap();
        assert_eq!(created, validated);

        let factory = StablecoinFactoryContract::new(storage.clone());
        assert_eq!(factory.token_count().unwrap(), U256::from(1u64));
        assert_eq!(
            factory.token_by_id(created.token_id).unwrap(),
            created.token
        );
        assert_eq!(
            factory.token_by_ticker(&created.payload.ticker).unwrap(),
            created.token
        );
        assert!(!factory.reservations.exists(proposal_id).unwrap());

        let ledger = StablecoinContract::new(storage.clone(), created.token);
        assert_eq!(ledger.total_supply().unwrap(), U256::ZERO);
        assert_eq!(
            outbe_stablecoin::api::identity(storage, created.token).unwrap(),
            outbe_stablecoin::TokenIdentity {
                token_id: created.token_id,
                name: created.payload.name.clone(),
                symbol: created.payload.ticker.clone(),
                currency: created.payload.iso4217,
                decimals: created.payload.decimals,
                issuer,
                creation_protocol_version: 0,
            }
        );
        created
    });

    let account = provider
        .get_account_info(created.token)
        .expect("created token account");
    assert_eq!(
        account
            .code
            .as_ref()
            .expect("marker code")
            .original_bytes()
            .as_ref(),
        STABLECOIN_MARKER_CODE
    );
    assert_eq!(provider.get_balance(created.token), native_balance);
    assert_eq!(
        provider.get_events(STABLECOIN_FACTORY_ADDRESS),
        &[I::StablecoinCreated {
            tokenId: created.token_id,
            token: created.token,
            issuer,
            proposalId: proposal_id,
            name: created.payload.name,
            ticker: created.payload.ticker,
            iso4217: created.payload.iso4217,
            decimals: created.payload.decimals,
            supplyCap: created.payload.supply_cap,
            policyId: created.payload.policy_id,
        }
        .encode_log_data()]
    );
}

#[test]
fn maximum_accepted_metadata_and_supply_cap_create_a_token() {
    let issuer = Address::repeat_byte(0x11);
    let proposal_id = U256::from(8u64);
    let payload = StablecoinCreatePayload {
        issuer,
        name: "N".repeat(MAX_NAME_LEN),
        ticker: "MAXBOUNDARY1".into(),
        iso4217: 840,
        decimals: 18,
        supply_cap: U256::MAX,
        policy_id: U256::from(1u64),
    };
    assert_eq!(payload.name.len(), MAX_NAME_LEN);
    assert_eq!(payload.ticker.len(), MAX_TICKER_LEN);
    let raw = encode_canonical_stablecoin_create(&payload).unwrap();
    let mut provider = HashMapStorageProvider::new(1);

    let created = StorageHandle::enter(&mut provider, |storage| {
        let validated =
            StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw).unwrap();
        StablecoinFactoryApi::reserve(
            storage.clone(),
            &FactoryReservation {
                proposal_id,
                token_id: validated.token_id,
                ticker: validated.payload.ticker.clone(),
                token: validated.token,
            },
        )
        .unwrap();
        StablecoinFactoryApi::execute_approved(storage, proposal_id, issuer, &raw, 0).unwrap()
    });

    assert_eq!(created.payload, payload);
    StorageHandle::enter(&mut provider, |storage| {
        let token = StablecoinContract::new(storage, created.token);
        assert_eq!(token.total_supply().unwrap(), U256::ZERO);
        assert_eq!(token.supply_cap.read().unwrap(), U256::MAX);
    });
}

#[test]
fn execution_revalidation_rejects_payload_or_account_mismatch_and_keeps_reservation() {
    let issuer = Address::repeat_byte(0x11);
    let proposal_id = U256::from(7u64);
    let raw =
        encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64))).unwrap();
    let mut changed_payload = create_payload(issuer, U256::from(1u64));
    changed_payload.ticker = "OTHER".into();
    let changed_raw = encode_canonical_stablecoin_create(&changed_payload).unwrap();

    with_factory(|storage, mut factory| {
        let item = reservation(&factory, 7, issuer, "EXUSD");
        factory.reserve(&item).unwrap();
        assert!(matches!(
            factory.execute_approved(proposal_id, issuer, &changed_raw, 0),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(
            factory.pending_token_id.read(&item.token_id).unwrap(),
            proposal_id
        );
        assert_eq!(factory.token_count().unwrap(), U256::ZERO);
        assert_eq!(storage.sload(item.token, U256::ZERO).unwrap(), U256::ZERO);
    });

    with_factory(|storage, mut factory| {
        let item = reservation(&factory, 7, issuer, "EXUSD");
        factory.reserve(&item).unwrap();
        storage
            .set_code(
                item.token,
                Bytecode::new_raw(alloy_primitives::Bytes::from_static(&[0x01])),
            )
            .unwrap();
        assert!(matches!(
            factory.execute_approved(proposal_id, issuer, &raw, 0),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(
            factory.pending_token_id.read(&item.token_id).unwrap(),
            proposal_id
        );
        assert_eq!(factory.token_count().unwrap(), U256::ZERO);
        assert_eq!(storage.sload(item.token, U256::ZERO).unwrap(), U256::ZERO);
    });
}

#[test]
fn pfs_010_08_every_initializer_failure_rolls_back_token_marker_registry_and_event() {
    let issuer = Address::repeat_byte(0x11);
    let proposal_id = U256::from(7u64);
    let raw =
        encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64))).unwrap();
    let protocol_version = 0;

    let mutation_count = {
        let mut provider = HashMapStorageProvider::new(1);
        let validated = StorageHandle::enter(&mut provider, |storage| {
            let validated =
                StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw).unwrap();
            StablecoinFactoryApi::reserve(
                storage,
                &FactoryReservation {
                    proposal_id,
                    token_id: validated.token_id,
                    ticker: validated.payload.ticker.clone(),
                    token: validated.token,
                },
            )
            .unwrap();
            validated
        });
        provider.clear_mutation_failure();
        StorageHandle::enter(&mut provider, |storage| {
            StablecoinFactoryApi::execute_approved(
                storage,
                proposal_id,
                issuer,
                &raw,
                protocol_version,
            )
            .unwrap();
        });
        let count = provider.clear_mutation_failure();
        assert_eq!(provider.get_events(STABLECOIN_FACTORY_ADDRESS).len(), 1);
        assert!(provider.get_account_info(validated.token).is_some());
        count
    };

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(1);
        let validated = StorageHandle::enter(&mut provider, |storage| {
            let validated =
                StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw).unwrap();
            StablecoinFactoryApi::reserve(
                storage,
                &FactoryReservation {
                    proposal_id,
                    token_id: validated.token_id,
                    ticker: validated.payload.ticker.clone(),
                    token: validated.token,
                },
            )
            .unwrap();
            validated
        });
        provider.clear_mutation_failure();
        provider.fail_after_mutation_at(operation);
        StorageHandle::enter(&mut provider, |storage| {
            assert!(matches!(
                StablecoinFactoryApi::execute_approved(
                    storage,
                    proposal_id,
                    issuer,
                    &raw,
                    protocol_version
                ),
                Err(PrecompileError::Storage(_))
            ));
        });
        provider.clear_mutation_failure();

        StorageHandle::enter(&mut provider, |storage| {
            let factory = StablecoinFactoryContract::new(storage.clone());
            assert_eq!(factory.token_count().unwrap(), U256::ZERO);
            assert_eq!(
                factory.pending_token_id.read(&validated.token_id).unwrap(),
                proposal_id
            );
            assert_eq!(
                storage.sload(validated.token, U256::ZERO).unwrap(),
                U256::ZERO
            );
        });
        if let Some(account) = provider.get_account_info(validated.token) {
            assert!(
                account
                    .code
                    .as_ref()
                    .is_none_or(|code| code.original_bytes().is_empty()),
                "operation {operation} left marker code"
            );
        }
        assert!(provider.get_events(STABLECOIN_FACTORY_ADDRESS).is_empty());
    }
}

#[test]
fn approved_execution_flushes_marker_storage_and_preserves_forced_balance() {
    let issuer = Address::repeat_byte(0x11);
    let proposal_id = U256::from(7u64);
    let raw =
        encode_canonical_stablecoin_create(&create_payload(issuer, U256::from(1u64))).unwrap();
    let token = address!("53c0f667dc28c8716bdac45fd1696b34000f2863");
    let native_balance = U256::from(777u64);
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        token,
        AccountInfo {
            balance: native_balance,
            ..Default::default()
        },
    );
    let context = BlockContext::new(7, 1_700_000_000, 1, issuer, vec![issuer]);
    let mut provider = DirectStorageProvider::new(&mut db, context);

    StorageHandle::enter(&mut provider, |storage| {
        let validated =
            StablecoinFactoryApi::validate_create(storage.clone(), issuer, &raw).unwrap();
        StablecoinFactoryApi::reserve(
            storage.clone(),
            &FactoryReservation {
                proposal_id,
                token_id: validated.token_id,
                ticker: validated.payload.ticker,
                token: validated.token,
            },
        )
        .unwrap();
        StablecoinFactoryApi::execute_approved(storage, proposal_id, issuer, &raw, 0).unwrap();
    });

    provider.flush().unwrap();
    let changes = provider.take_committed_changes();
    let token_change = changes.get(&token).expect("token state/code change");
    assert_eq!(token_change.info.balance, native_balance);
    assert_eq!(
        token_change
            .info
            .code
            .as_ref()
            .expect("marker")
            .original_bytes()
            .as_ref(),
        STABLECOIN_MARKER_CODE
    );
    assert!(!token_change.storage.is_empty());
    assert!(changes.contains_key(&STABLECOIN_FACTORY_ADDRESS));
    let events = provider.take_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].address, STABLECOIN_FACTORY_ADDRESS);
    drop(provider);

    let persisted = db.basic(token).unwrap().expect("persisted token account");
    assert_eq!(persisted.balance, native_balance);
    assert_eq!(
        db.code_by_hash(persisted.code_hash)
            .unwrap()
            .original_bytes()
            .as_ref(),
        STABLECOIN_MARKER_CODE
    );
}

#[test]
fn factory_precompile_exposes_only_the_frozen_view_surface() {
    let issuer = Address::repeat_byte(0x11);
    let mut provider = HashMapStorageProvider::new(1);
    let predicted = invoke(
        &mut provider,
        issuer,
        I::predictTokenAddressCall {
            issuer,
            ticker: "EXUSD".into(),
        },
    );
    assert_eq!(
        predicted.tokenId,
        b256!("2cf34bcaf12fe89ab2f3f6f34667f667dc28c8716bdac45fd1696b34000f2863")
    );
    assert_eq!(
        invoke(&mut provider, issuer, I::tokenCountCall {}),
        U256::ZERO
    );
    assert!(!invoke(
        &mut provider,
        issuer,
        I::isStablecoinCall {
            token: predicted.token
        }
    ));
    assert!(invoke(
        &mut provider,
        issuer,
        I::listTokensCall {
            offset: U256::ZERO,
            limit: U256::from(10u64),
        },
    )
    .is_empty());
}

#[test]
fn factory_precompile_rejects_value_malformed_and_trailing_calldata_without_writes() {
    let caller = Address::repeat_byte(0x11);
    let call = I::tokenCountCall {}.abi_encode();
    let mut provider = HashMapStorageProvider::new(1);

    assert_revert::<I::UnexpectedValue>(
        dispatch(
            StorageHandle::new(&mut provider),
            &call,
            caller,
            U256::from(1u64),
        )
        .unwrap_err(),
    );
    assert!(dispatch(
        StorageHandle::new(&mut provider),
        &[0x01, 0x02, 0x03],
        caller,
        U256::ZERO,
    )
    .is_err());
    let mut trailing = call;
    trailing.push(0);
    assert!(dispatch(
        StorageHandle::new(&mut provider),
        &trailing,
        caller,
        U256::ZERO,
    )
    .is_err());
    assert!(provider.storage.is_empty());
    assert!(provider.get_events(STABLECOIN_FACTORY_ADDRESS).is_empty());
}

#[test]
fn v1_raw_layout_and_pristine_schema_are_pinned() {
    with_factory(|storage, factory| {
        assert_eq!(factory.schema_version.slot(), U256::ZERO);
        assert_eq!(factory.token_by_id_index.base_slot(), U256::from(3u64));
        assert_eq!(factory.token_by_ticker_index.base_slot(), U256::from(4u64));
        assert_eq!(factory.token_id_of_index.base_slot(), U256::from(5u64));
        assert_eq!(factory.pending_token_id.base_slot(), U256::from(6u64));
        assert_eq!(factory.pending_ticker.base_slot(), U256::from(7u64));
        assert_eq!(factory.pending_address.base_slot(), U256::from(8u64));
        assert_eq!(factory.reservations.base_slot(), U256::from(9u64));
        assert_eq!(factory.token_count().unwrap(), U256::ZERO);

        let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
        let mut factory = factory;
        factory.reserve(&item).unwrap();
        assert_eq!(
            storage
                .sload(STABLECOIN_FACTORY_ADDRESS, U256::ZERO)
                .unwrap(),
            U256::from(STABLECOIN_V1_SCHEMA_VERSION)
        );
    });
}

#[test]
fn reservation_release_and_consume_keep_all_indexes_inverse() {
    with_factory(|_storage, mut factory| {
        let released = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
        factory.reserve(&released).unwrap();
        assert_eq!(
            factory.pending_token_id.read(&released.token_id).unwrap(),
            released.proposal_id
        );
        assert_eq!(
            factory
                .pending_ticker
                .read(&keccak256(released.ticker.as_bytes()))
                .unwrap(),
            released.proposal_id
        );
        assert_eq!(
            factory.pending_address.read(&released.token).unwrap(),
            released.proposal_id
        );

        let record = factory.release(released.proposal_id).unwrap();
        assert_eq!(record.token_id, released.token_id);
        assert!(factory
            .pending_token_id
            .read(&released.token_id)
            .unwrap()
            .is_zero());
        assert!(factory
            .pending_ticker
            .read(&record.ticker_hash)
            .unwrap()
            .is_zero());
        assert!(factory
            .pending_address
            .read(&released.token)
            .unwrap()
            .is_zero());
        assert!(!factory.reservations.exists(released.proposal_id).unwrap());

        let registered = reservation(&factory, 2, Address::repeat_byte(0x22), "EUR1");
        factory.reserve(&registered).unwrap();
        factory
            .consume_and_register(registered.proposal_id)
            .unwrap();

        assert_eq!(factory.token_count().unwrap(), U256::from(1u64));
        assert_eq!(
            factory.token_by_id(registered.token_id).unwrap(),
            registered.token
        );
        assert_eq!(
            factory.token_by_ticker(&registered.ticker).unwrap(),
            registered.token
        );
        assert_eq!(
            factory.token_id_of(registered.token).unwrap(),
            registered.token_id
        );
        assert!(factory.is_stablecoin(registered.token).unwrap());
        assert!(factory
            .pending_token_id
            .read(&registered.token_id)
            .unwrap()
            .is_zero());
        assert!(!factory.reservations.exists(registered.proposal_id).unwrap());
    });
}

#[test]
fn ticker_is_global_across_issuers_and_pending_address_reserves_full_id() {
    with_factory(|_storage, mut factory| {
        let first = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
        factory.reserve(&first).unwrap();

        let second = reservation(&factory, 2, Address::repeat_byte(0x22), "USD1");
        assert_ne!(first.token_id, second.token_id);
        assert_revert::<I::TickerReserved>(
            factory
                .reserve(&second)
                .expect_err("ticker is globally pending"),
        );

        let address_collision = FactoryReservation {
            proposal_id: U256::from(3u64),
            token_id: B256::repeat_byte(0x33),
            ticker: "EUR1".into(),
            token: first.token,
        };
        assert_revert::<I::TokenAddressCollision>(
            factory
                .reserve(&address_collision)
                .expect_err("predicted address is already reserved"),
        );

        factory.consume_and_register(first.proposal_id).unwrap();
        let third = reservation(&factory, 4, Address::repeat_byte(0x44), "USD1");
        assert_revert::<I::TickerAlreadyRegistered>(
            factory
                .reserve(&third)
                .expect_err("ticker remains globally permanent"),
        );

        let permanent_address_collision = FactoryReservation {
            proposal_id: U256::from(5u64),
            token_id: B256::repeat_byte(0x55),
            ticker: "GBP1".into(),
            token: first.token,
        };
        assert_revert::<I::TokenAddressCollision>(
            factory
                .reserve(&permanent_address_collision)
                .expect_err("registered address cannot be reserved under another full id"),
        );
    });
}

#[test]
fn list_accepts_any_limit_from_one_through_one_hundred_and_clamps_pages() {
    with_factory(|_storage, mut factory| {
        assert_revert::<I::InvalidListLimit>(
            factory
                .list_tokens(U256::ZERO, U256::ZERO)
                .expect_err("zero limit"),
        );
        assert_revert::<I::InvalidListLimit>(
            factory
                .list_tokens(U256::ZERO, U256::from(STABLECOIN_LIST_PAGE_CAP + 1))
                .expect_err("limit above cap"),
        );

        for index in 0..101u64 {
            let item = reservation(
                &factory,
                index + 1,
                Address::from_word(U256::from(index + 1).into()),
                &format!("T{index:03}"),
            );
            factory.reserve(&item).unwrap();
            factory.consume_and_register(item.proposal_id).unwrap();
        }

        assert_eq!(
            factory
                .list_tokens(U256::ZERO, U256::from(1u64))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            factory
                .list_tokens(U256::ZERO, U256::from(100u64))
                .unwrap()
                .len(),
            100
        );
        assert_eq!(
            factory
                .list_tokens(U256::from(100u64), U256::from(10u64))
                .unwrap()
                .len(),
            1
        );
        assert!(factory
            .list_tokens(U256::from(101u64), U256::from(10u64))
            .unwrap()
            .is_empty());
        assert!(factory
            .list_tokens(U256::MAX, U256::from(10u64))
            .unwrap()
            .is_empty());
    });
}

#[test]
fn outer_checkpoint_rolls_back_the_complete_reservation_triple() {
    with_factory(|storage, factory| {
        let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
        let result: outbe_primitives::error::Result<()> = storage.with_checkpoint(|| {
            let mut factory = StablecoinFactoryContract::new(storage.clone());
            factory.reserve(&item)?;
            Err(PrecompileError::Fatal("forced after reservation".into()))
        });
        assert!(matches!(result, Err(PrecompileError::Fatal(_))));

        let factory = StablecoinFactoryContract::new(storage);
        assert!(factory
            .pending_token_id
            .read(&item.token_id)
            .unwrap()
            .is_zero());
        assert!(factory
            .pending_ticker
            .read(&keccak256(item.ticker.as_bytes()))
            .unwrap()
            .is_zero());
        assert!(factory.pending_address.read(&item.token).unwrap().is_zero());
        assert!(!factory.reservations.exists(item.proposal_id).unwrap());
        assert_eq!(factory.schema_version.read().unwrap(), 0);
    });
}

#[test]
fn injected_failure_after_every_reservation_mutation_leaves_no_partial_index() {
    let mutation_count = {
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let mut factory = StablecoinFactoryContract::new(storage);
            let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
            factory.reserve(&item).unwrap();
        });
        provider.clear_mutation_failure()
    };
    assert!(
        mutation_count >= 4,
        "reservation must write the complete record"
    );

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(1);
        provider.fail_after_mutation_at(operation);
        StorageHandle::enter(&mut provider, |storage| {
            let factory = StablecoinFactoryContract::new(storage.clone());
            let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
            let result = storage
                .with_checkpoint(|| StablecoinFactoryContract::new(storage.clone()).reserve(&item));
            assert!(
                matches!(result, Err(PrecompileError::Storage(_))),
                "operation {operation}: {result:?}"
            );
        });
        provider.clear_mutation_failure();
        assert!(
            provider.storage.is_empty(),
            "operation {operation} left partial Factory state"
        );
    }
}

#[test]
fn injected_failure_after_every_release_or_consume_mutation_restores_pending_state() {
    let mutation_counts = {
        let mut release_provider = HashMapStorageProvider::new(1);
        let release_item = StorageHandle::enter(&mut release_provider, |storage| {
            let mut factory = StablecoinFactoryContract::new(storage);
            let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
            factory.reserve(&item).unwrap();
            item
        });
        release_provider.clear_mutation_failure();
        StorageHandle::enter(&mut release_provider, |storage| {
            StablecoinFactoryContract::new(storage)
                .release(release_item.proposal_id)
                .unwrap();
        });
        let release = release_provider.clear_mutation_failure();

        let mut consume_provider = HashMapStorageProvider::new(1);
        let consume_item = StorageHandle::enter(&mut consume_provider, |storage| {
            let mut factory = StablecoinFactoryContract::new(storage);
            let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
            factory.reserve(&item).unwrap();
            item
        });
        consume_provider.clear_mutation_failure();
        StorageHandle::enter(&mut consume_provider, |storage| {
            StablecoinFactoryContract::new(storage)
                .consume_and_register(consume_item.proposal_id)
                .unwrap();
        });
        let consume = consume_provider.clear_mutation_failure();
        (release, consume)
    };

    for (consume, mutation_count) in [(false, mutation_counts.0), (true, mutation_counts.1)] {
        for operation in 0..mutation_count {
            let mut provider = HashMapStorageProvider::new(1);
            let item = StorageHandle::enter(&mut provider, |storage| {
                let mut factory = StablecoinFactoryContract::new(storage);
                let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
                factory.reserve(&item).unwrap();
                item
            });
            provider.clear_mutation_failure();
            provider.fail_after_mutation_at(operation);

            StorageHandle::enter(&mut provider, |storage| {
                let result = storage.with_checkpoint(|| {
                    let mut factory = StablecoinFactoryContract::new(storage.clone());
                    if consume {
                        factory.consume_and_register(item.proposal_id)?;
                    } else {
                        factory.release(item.proposal_id)?;
                    }
                    Ok(())
                });
                assert!(
                    matches!(result, Err(PrecompileError::Storage(_))),
                    "consume={consume} operation={operation}: {result:?}"
                );
            });
            provider.clear_mutation_failure();

            StorageHandle::enter(&mut provider, |storage| {
                let factory = StablecoinFactoryContract::new(storage);
                assert_eq!(
                    factory.pending_token_id.read(&item.token_id).unwrap(),
                    item.proposal_id
                );
                assert_eq!(
                    factory
                        .pending_ticker
                        .read(&keccak256(item.ticker.as_bytes()))
                        .unwrap(),
                    item.proposal_id
                );
                assert_eq!(
                    factory.pending_address.read(&item.token).unwrap(),
                    item.proposal_id
                );
                assert!(factory.reservations.exists(item.proposal_id).unwrap());
                assert_eq!(factory.token_count().unwrap(), U256::ZERO);
                assert!(factory.token_by_id(item.token_id).unwrap().is_zero());
                assert!(factory.token_by_ticker(&item.ticker).unwrap().is_zero());
            });
        }
    }
}

#[test]
fn release_allows_corrected_resubmission_and_target_error_keeps_the_triple() {
    with_factory(|storage, mut factory| {
        let first = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
        factory.reserve(&first).unwrap();
        factory.release(first.proposal_id).unwrap();

        let corrected = FactoryReservation {
            proposal_id: U256::from(2u64),
            ..first
        };
        factory.reserve(&corrected).unwrap();

        let target_result: outbe_primitives::error::Result<()> =
            storage.with_checkpoint(|| Err(PrecompileError::Revert("typed target error".into())));
        assert!(matches!(target_result, Err(PrecompileError::Revert(_))));

        assert_eq!(
            factory.pending_token_id.read(&corrected.token_id).unwrap(),
            corrected.proposal_id
        );
        assert_eq!(
            factory
                .pending_ticker
                .read(&keccak256(corrected.ticker.as_bytes()))
                .unwrap(),
            corrected.proposal_id
        );
        assert_eq!(
            factory.pending_address.read(&corrected.token).unwrap(),
            corrected.proposal_id
        );
        assert!(factory.reservations.exists(corrected.proposal_id).unwrap());
    });
}

#[test]
fn corrupted_reservation_triple_is_fatal_and_not_partially_cleaned() {
    with_factory(|_storage, mut factory| {
        let item = reservation(&factory, 1, Address::repeat_byte(0x11), "USD1");
        factory.reserve(&item).unwrap();
        factory.pending_address.clear(&item.token).unwrap();

        assert!(matches!(
            factory.release(item.proposal_id),
            Err(PrecompileError::Fatal(_))
        ));
        assert_eq!(
            factory.pending_token_id.read(&item.token_id).unwrap(),
            item.proposal_id
        );
        assert!(factory.reservations.exists(item.proposal_id).unwrap());
    });
}

#[test]
fn mixed_reserve_release_consume_history_preserves_every_inverse() {
    with_factory(|_storage, mut factory| {
        let mut pending = Vec::new();
        let mut expected_permanent = Vec::new();
        let mut rng = 0x5eed_cafe_f00d_beefu64;

        for batch in 0..4u64 {
            for index in 0..32u64 {
                let ordinal = batch * 32 + index;
                let item = reservation(
                    &factory,
                    ordinal + 1,
                    Address::from_word(U256::from(ordinal + 1).into()),
                    &format!("R{ordinal:03}"),
                );
                factory.reserve(&item).unwrap();
                pending.push(item);
            }

            while let Some(item) = pending.pop() {
                rng = rng.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                if rng & 1 == 0 {
                    factory.release(item.proposal_id).unwrap();
                } else {
                    factory.consume_and_register(item.proposal_id).unwrap();
                    expected_permanent.push(item.clone());
                }

                assert!(factory
                    .pending_token_id
                    .read(&item.token_id)
                    .unwrap()
                    .is_zero());
                assert!(factory
                    .pending_ticker
                    .read(&keccak256(item.ticker.as_bytes()))
                    .unwrap()
                    .is_zero());
                assert!(factory.pending_address.read(&item.token).unwrap().is_zero());
                assert!(!factory.reservations.exists(item.proposal_id).unwrap());
            }
        }

        assert_eq!(
            factory.token_count().unwrap(),
            U256::from(expected_permanent.len())
        );
        for item in expected_permanent {
            assert_eq!(factory.token_by_id(item.token_id).unwrap(), item.token);
            assert_eq!(factory.token_by_ticker(&item.ticker).unwrap(), item.token);
            assert_eq!(factory.token_id_of(item.token).unwrap(), item.token_id);
        }
    });
}

#[test]
fn unknown_schema_and_unknown_reverse_lookup_fail_closed() {
    with_factory(|_storage, factory| {
        factory.schema_version.write(2).unwrap();
        assert!(matches!(
            factory.token_count(),
            Err(PrecompileError::Fatal(_))
        ));
    });

    with_factory(|_storage, factory| {
        assert_revert::<I::UnknownStablecoin>(
            factory
                .token_id_of(Address::repeat_byte(0x99))
                .expect_err("unknown reverse lookup"),
        );
        assert!(!factory.is_stablecoin(Address::repeat_byte(0x99)).unwrap());
    });
}
