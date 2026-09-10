use std::sync::Arc;

use alloy_evm::{Evm as _, EvmFactory as _};
use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
use outbe_evm::{sub_call, OutbeEvmFactory};
use outbe_primitives::{
    addresses::{STABLECOIN_ADDRESS_PREFIX, STABLECOIN_FACTORY_ADDRESS, STABLECOIN_MARKER_CODE},
    block::BlockContext,
    stablecoin::{predict_stablecoin, StablecoinCreatePayload},
    storage::{
        direct::DirectStorageProvider, StorageHandle, SubCallError, SubCallInput, SubCallStatus,
    },
};
use outbe_stablecoin::{
    api::{FactoryTokenInitialization, StablecoinFactoryApi as TokenFactoryApi},
    precompile::IStablecoin,
};
use outbe_stablecoinfactory::{FactoryReservation, StablecoinFactoryApi as RegistryApi};
use reth_ethereum::evm::primitives::EvmEnv;
use revm::{
    context::{
        result::{ExecutionResult, Output},
        BlockEnv, CfgEnv, TxEnv,
    },
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::{hardfork::SpecId, TxKind},
    state::{AccountInfo, Bytecode},
    Context,
};

const CHAIN_ID: u64 = 1;
const CALLER: Address = Address::new([0xc0; 20]);
const ISSUER: Address = Address::new([0x44; 20]);
const GAS_LIMIT: u64 = 1_000_000;

fn test_env() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(CHAIN_ID)
            .with_spec_and_mainnet_gas_params(SpecId::PRAGUE),
        block_env: BlockEnv {
            gas_limit: 30_000_000,
            ..Default::default()
        },
    }
}

fn funded_account() -> AccountInfo {
    AccountInfo {
        balance: U256::from(10u64).pow(U256::from(20u64)),
        ..Default::default()
    }
}

fn seed_registered_tokens(definitions: &[(&str, &str)]) -> (CacheDB<EmptyDB>, Vec<Address>) {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(CALLER, funded_account());

    let mut initializations = Vec::with_capacity(definitions.len());
    for (index, (name, ticker)) in definitions.iter().enumerate() {
        let payload = StablecoinCreatePayload {
            issuer: ISSUER,
            name: (*name).to_owned(),
            ticker: (*ticker).to_owned(),
            iso4217: 840,
            decimals: 6,
            supply_cap: U256::from(1_000_000u64),
            policy_id: U256::from(1u64),
        };
        let (token_id, token) = predict_stablecoin(
            CHAIN_ID,
            STABLECOIN_FACTORY_ADDRESS,
            ISSUER,
            ticker,
            STABLECOIN_ADDRESS_PREFIX,
        )
        .unwrap();
        let marker = Bytecode::new_raw(Bytes::from_static(&STABLECOIN_MARKER_CODE));
        db.insert_account_info(
            token,
            AccountInfo {
                code_hash: marker.hash_slow(),
                code: Some(marker),
                ..Default::default()
            },
        );
        initializations.push((
            FactoryReservation {
                proposal_id: U256::from(index + 1),
                token_id,
                ticker: (*ticker).to_owned(),
                token,
            },
            FactoryTokenInitialization {
                token_address: token,
                token_id,
                creation_protocol_version: 0,
                payload,
            },
        ));
    }

    {
        let mut provider =
            DirectStorageProvider::new(&mut db, BlockContext::empty_for_tests(1, 1, CHAIN_ID));
        StorageHandle::enter(&mut provider, |storage| {
            for (reservation, initialization) in &initializations {
                RegistryApi::reserve(storage.clone(), reservation).unwrap();
                TokenFactoryApi::new(storage.clone())
                    .initialize(initialization)
                    .unwrap();
                RegistryApi::consume(storage.clone(), reservation.proposal_id).unwrap();
            }
        });
        provider.flush().unwrap();
    }

    let tokens = initializations
        .iter()
        .map(|(_, initialization)| initialization.token_address)
        .collect();
    (db, tokens)
}

fn symbol_calldata() -> Bytes {
    IStablecoin::symbolCall {}.abi_encode().into()
}

fn class_address(last: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[..2].copy_from_slice(&STABLECOIN_ADDRESS_PREFIX);
    bytes[19] = last;
    Address::from(bytes)
}

#[test]
fn top_level_calls_route_by_actual_stablecoin_callee_and_keep_instances_isolated() {
    let (db, tokens) =
        seed_registered_tokens(&[("Example Dollar", "EXUSD"), ("Second Dollar", "SCD")]);
    let mut evm = OutbeEvmFactory::new().create_evm(db, test_env());

    for (token, expected) in tokens.into_iter().zip(["EXUSD", "SCD"]) {
        let tx = TxEnv::builder()
            .caller(CALLER)
            .nonce(0)
            .kind(TxKind::Call(token))
            .data(symbol_calldata())
            .gas_limit(GAS_LIMIT)
            .build()
            .unwrap();
        let result = evm.transact_raw(tx).unwrap();
        let ExecutionResult::Success {
            output: Output::Call(output),
            ..
        } = result.result
        else {
            panic!("stablecoin symbol call did not succeed");
        };
        assert_eq!(
            IStablecoin::symbolCall::abi_decode_returns(&output).unwrap(),
            expected
        );
    }
}

#[test]
fn nested_staticcall_uses_the_same_authenticated_dynamic_route() {
    let (db, tokens) = seed_registered_tokens(&[("Example Dollar", "EXUSD")]);
    let token = tokens[0];
    let mut ctx = Context::mainnet().with_db(db);

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        None,
        Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        SubCallInput {
            target: token,
            value: U256::ZERO,
            calldata: symbol_calldata(),
            gas_limit: GAS_LIMIT,
            is_static: true,
        },
    )
    .unwrap();

    assert!(matches!(result.status, SubCallStatus::Success));
    assert_eq!(
        IStablecoin::symbolCall::abi_decode_returns(&result.returndata).unwrap(),
        "EXUSD"
    );
}

#[test]
fn nested_static_mutation_halts_without_committing_an_event() {
    let (db, tokens) = seed_registered_tokens(&[("Example Dollar", "EXUSD")]);
    let token = tokens[0];
    let mut ctx = Context::mainnet().with_db(db);
    let spender = Address::repeat_byte(0x77);
    let calldata = IStablecoin::approveCall {
        spender,
        value: U256::from(1u64),
    }
    .abi_encode();

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        None,
        Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        SubCallInput {
            target: token,
            value: U256::ZERO,
            calldata: calldata.into(),
            gas_limit: GAS_LIMIT,
            is_static: true,
        },
    )
    .unwrap();

    assert!(matches!(result.status, SubCallStatus::Halt(_)));

    let allowance = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        None,
        Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        SubCallInput {
            target: token,
            value: U256::ZERO,
            calldata: IStablecoin::allowanceCall {
                owner: CALLER,
                spender,
            }
            .abi_encode()
            .into(),
            gas_limit: GAS_LIMIT,
            is_static: true,
        },
    )
    .unwrap();
    assert!(matches!(allowance.status, SubCallStatus::Success));
    assert_eq!(
        IStablecoin::allowanceCall::abi_decode_returns(&allowance.returndata).unwrap(),
        U256::ZERO
    );
}

#[test]
fn nested_call_with_insufficient_gas_halts_out_of_gas() {
    let (db, tokens) = seed_registered_tokens(&[("Example Dollar", "EXUSD")]);
    let token = tokens[0];
    let mut ctx = Context::mainnet().with_db(db);

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        None,
        Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        SubCallInput {
            target: token,
            value: U256::ZERO,
            calldata: symbol_calldata(),
            gas_limit: 1,
            is_static: true,
        },
    )
    .unwrap();

    assert!(matches!(
        result.status,
        SubCallStatus::Halt(SubCallError::OutOfGas)
    ));
}

#[test]
fn unregistered_class_member_reverts_without_executing_installed_bytecode() {
    let unknown = class_address(0xfe);
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(CALLER, funded_account());

    // This runtime would return success if the reserved address ever fell
    // through to ordinary EVM bytecode.
    let bytecode = Bytecode::new_raw(Bytes::from_static(&[0x00]));
    db.insert_account_info(
        unknown,
        AccountInfo {
            code_hash: bytecode.hash_slow(),
            code: Some(bytecode),
            ..Default::default()
        },
    );

    let tx = TxEnv::builder()
        .caller(CALLER)
        .nonce(0)
        .kind(TxKind::Call(unknown))
        .gas_limit(GAS_LIMIT)
        .build()
        .unwrap();
    let mut evm = OutbeEvmFactory::new().create_evm(db, test_env());
    let result = evm.transact_raw(tx).unwrap();

    assert!(matches!(result.result, ExecutionResult::Revert { .. }));
}
