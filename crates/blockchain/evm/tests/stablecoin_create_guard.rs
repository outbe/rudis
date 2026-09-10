use alloy_evm::{Evm as _, EvmFactory as _};
use alloy_primitives::{Address, Bytes, U256};
use outbe_evm::OutbeEvmFactory;
use outbe_primitives::addresses::is_stablecoin_address;
use reth_ethereum::evm::primitives::EvmEnv;
use revm::{
    context::{
        result::{ExecutionResult, HaltReason, Output},
        BlockEnv, CfgEnv, TxEnv,
    },
    database::{CacheDB, EmptyDB},
    inspector::NoOpInspector,
    primitives::{hardfork::SpecId, TxKind},
    state::{AccountInfo, Bytecode},
};

const GAS_LIMIT: u64 = 1_000_000;

fn test_env() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(1)
            .with_spec_and_mainnet_gas_params(SpecId::PRAGUE),
        block_env: BlockEnv {
            gas_limit: 30_000_000,
            ..Default::default()
        },
    }
}

fn address_from_counter(counter: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&counter.to_be_bytes());
    Address::from(bytes)
}

fn find_create_caller(nonce: u64, reserved: bool) -> Address {
    (1..2_000_000)
        .map(address_from_counter)
        .find(|caller| is_stablecoin_address(caller.create(nonce)) == reserved)
        .expect("search range contains both prefix classes")
}

fn funded_account(nonce: u64) -> AccountInfo {
    AccountInfo {
        balance: U256::from(10u64).pow(U256::from(20u64)),
        nonce,
        ..Default::default()
    }
}

fn create_tx(caller: Address, nonce: u64) -> TxEnv {
    TxEnv::builder()
        .caller(caller)
        .nonce(nonce)
        .kind(TxKind::Create)
        .data(Bytes::from_static(&[0x00]))
        .gas_limit(GAS_LIMIT)
        .build()
        .expect("valid create transaction")
}

#[test]
fn top_level_create_uses_canonical_collision_while_adjacent_create_succeeds() {
    let reserved_caller = find_create_caller(0, true);
    let reserved_target = reserved_caller.create(0);
    let adjacent_caller = find_create_caller(0, false);
    let adjacent_target = adjacent_caller.create(0);

    let mut reserved_db = CacheDB::new(EmptyDB::default());
    reserved_db.insert_account_info(reserved_caller, funded_account(0));
    let mut reserved_evm = OutbeEvmFactory::new().create_evm(reserved_db, test_env());
    let reserved = reserved_evm
        .transact_raw(create_tx(reserved_caller, 0))
        .expect("reserved create executes as an EVM halt");

    assert!(matches!(
        reserved.result,
        ExecutionResult::Halt {
            reason: HaltReason::CreateCollision,
            ..
        }
    ));
    assert_eq!(reserved.state[&reserved_caller].info.nonce, 1);
    let reserved_account = &reserved.state[&reserved_target].info;
    assert_eq!(reserved_account.nonce, 0);
    assert_eq!(reserved_account.balance, U256::ZERO);
    assert!(reserved_account.code.clone().unwrap_or_default().is_empty());

    let mut inspected_db = CacheDB::new(EmptyDB::default());
    inspected_db.insert_account_info(reserved_caller, funded_account(0));
    let mut inspected_evm = OutbeEvmFactory::new().create_evm_with_inspector(
        inspected_db,
        test_env(),
        NoOpInspector {},
    );
    let inspected = inspected_evm
        .transact_raw(create_tx(reserved_caller, 0))
        .expect("inspected reserved create executes as an EVM halt");
    assert!(matches!(
        inspected.result,
        ExecutionResult::Halt {
            reason: HaltReason::CreateCollision,
            ..
        }
    ));
    assert_eq!(
        inspected.result.tx_gas_used(),
        reserved.result.tx_gas_used()
    );

    let mut canonical_collision_db = CacheDB::new(EmptyDB::default());
    canonical_collision_db.insert_account_info(adjacent_caller, funded_account(0));
    canonical_collision_db.insert_account_info(
        adjacent_target,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    let mut canonical_collision_evm =
        OutbeEvmFactory::new().create_evm(canonical_collision_db, test_env());
    let canonical_collision = canonical_collision_evm
        .transact_raw(create_tx(adjacent_caller, 0))
        .expect("ordinary occupied target produces a collision halt");
    assert!(matches!(
        canonical_collision.result,
        ExecutionResult::Halt {
            reason: HaltReason::CreateCollision,
            ..
        }
    ));
    assert_eq!(
        canonical_collision.result.tx_gas_used(),
        reserved.result.tx_gas_used()
    );

    let mut adjacent_db = CacheDB::new(EmptyDB::default());
    adjacent_db.insert_account_info(adjacent_caller, funded_account(0));
    let mut adjacent_evm = OutbeEvmFactory::new().create_evm(adjacent_db, test_env());
    let adjacent = adjacent_evm
        .transact_raw(create_tx(adjacent_caller, 0))
        .expect("adjacent create executes");

    assert!(matches!(
        adjacent.result,
        ExecutionResult::Success {
            output: Output::Create(_, Some(address)),
            ..
        } if address == adjacent_target
    ));
    assert_eq!(adjacent.state[&adjacent_caller].info.nonce, 1);
    assert!(adjacent.state.contains_key(&adjacent_target));
}

fn create_and_store_runtime(create2_salt: Option<[u8; 32]>) -> Bytes {
    let mut code = Vec::new();
    if let Some(salt) = create2_salt {
        code.push(0x7f); // PUSH32 salt
        code.extend_from_slice(&salt);
    }
    code.extend_from_slice(&[
        0x60,
        0x01, // PUSH1 init-code length
        0x60,
        0x00, // PUSH1 init-code offset
        0x60,
        0x00, // PUSH1 value
        if create2_salt.is_some() { 0xf5 } else { 0xf0 },
        0x60,
        0x00, // PUSH1 storage slot
        0x55, // SSTORE returned address
        0x00, // STOP
    ]);
    Bytes::from(code)
}

fn execute_parent(parent: Address, nonce: u64, runtime: Bytes) -> (U256, u64) {
    let bytecode = Bytecode::new_raw(runtime);
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        parent,
        AccountInfo {
            nonce,
            code_hash: bytecode.hash_slow(),
            code: Some(bytecode),
            ..funded_account(nonce)
        },
    );
    let caller = Address::repeat_byte(0xee);
    db.insert_account_info(caller, funded_account(0));

    let tx = TxEnv::builder()
        .caller(caller)
        .nonce(0)
        .kind(TxKind::Call(parent))
        .gas_limit(GAS_LIMIT)
        .build()
        .expect("valid parent call");
    let mut evm = OutbeEvmFactory::new().create_evm(db, test_env());
    let result = evm.transact_raw(tx).expect("parent call executes");
    assert!(result.result.is_success());
    (
        result.state[&parent].storage[&U256::ZERO].present_value(),
        result.state[&parent].info.nonce,
    )
}

#[test]
fn nested_create_and_create2_return_zero_for_reserved_destinations() {
    let create_parent = find_create_caller(1, true);
    assert_eq!(
        execute_parent(create_parent, 1, create_and_store_runtime(None)),
        (U256::ZERO, 2)
    );

    let create2_parent = Address::repeat_byte(0x42);
    let init_code = [0x00];
    let (salt, destination) = (0u64..2_000_000)
        .find_map(|counter| {
            let mut salt = [0u8; 32];
            salt[24..].copy_from_slice(&counter.to_be_bytes());
            let destination = create2_parent.create2_from_code(salt, init_code);
            is_stablecoin_address(destination).then_some((salt, destination))
        })
        .expect("search range contains reserved CREATE2 destination");
    assert!(is_stablecoin_address(destination));
    assert_eq!(
        execute_parent(create2_parent, 1, create_and_store_runtime(Some(salt))),
        (U256::ZERO, 2)
    );
}

#[test]
fn native_value_transfer_to_reserved_address_remains_valid() {
    let sender = Address::repeat_byte(0x77);
    let reserved = find_create_caller(0, true).create(0);
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(sender, funded_account(0));

    let tx = TxEnv::builder()
        .caller(sender)
        .nonce(0)
        .kind(TxKind::Call(reserved))
        .value(U256::from(123u64))
        .gas_limit(100_000)
        .build()
        .expect("valid transfer");
    let mut evm = OutbeEvmFactory::new().create_evm(db, test_env());
    let result = evm.transact_raw(tx).expect("transfer executes");

    assert!(result.result.is_success());
    assert_eq!(result.state[&reserved].info.balance, U256::from(123u64));
}
