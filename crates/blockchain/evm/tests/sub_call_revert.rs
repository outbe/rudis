//! sub-call revert path.
//!
//! Deploys EVM bytecode that immediately REVERTs with payload, calls it
//! via `sub_call::run`, and asserts `SubCallStatus::Revert(payload)`.
//!
//! Revert bytecode:
//! ```text
//! 60 42      PUSH1 0x42       ; load value 0x42
//! 60 00      PUSH1 0x00       ; memory offset 0
//! 52         MSTORE           ; store 32-byte word
//! 60 20      PUSH1 0x20       ; size 32
//! 60 00      PUSH1 0x00       ; memory offset 0
//! fd         REVERT           ; revert with the 32-byte word
//! ```

use alloy_primitives::{Address, Bytes, U256};
use outbe_evm::sub_call;
use outbe_primitives::storage::{SubCallInput, SubCallStatus};
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context,
};

const TARGET: Address = Address::new([0xAB; 20]);
const CALLER: Address = Address::new([0xC0; 20]);

const REVERT_PAYLOAD_BYTECODE: &[u8] = &[
    0x60, 0x42, // PUSH1 0x42
    0x60, 0x00, // PUSH1 0x00
    0x52, // MSTORE
    0x60, 0x20, // PUSH1 0x20
    0x60, 0x00, // PUSH1 0x00
    0xFD, // REVERT
];

#[test]
fn sub_call_to_reverting_contract_returns_revert_payload() {
    let mut db = CacheDB::new(EmptyDB::default());
    let code = Bytecode::new_raw(Bytes::from_static(REVERT_PAYLOAD_BYTECODE));
    let info = AccountInfo {
        balance: U256::ZERO,
        nonce: 0,
        code_hash: code.hash_slow(),
        code: Some(code),
        ..Default::default()
    };
    db.insert_account_info(TARGET, info);
    let mut ctx = Context::mainnet().with_db(db);

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        /* outer_is_static = */ false,
        SpecId::PRAGUE,
        None,
        std::sync::Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        SubCallInput {
            target: TARGET,
            value: U256::ZERO,
            calldata: Bytes::new(),
            gas_limit: 1_000_000,
            is_static: true,
        },
    )
    .expect("sub_call should not fail fatally on a child REVERT");

    match result.status {
        SubCallStatus::Revert(payload) => {
            let mut expected = [0u8; 32];
            expected[31] = 0x42;
            assert_eq!(
                payload,
                Bytes::from(expected.to_vec()),
                "revert payload must be the 32-byte word the contract REVERTed with"
            );
        }
        other => panic!("expected SubCallStatus::Revert, got {other:?}"),
    }

    // gas_used must be > 0 (child consumed some gas before reverting).
    assert!(result.gas_used > 0, "gas_used must be > 0, got 0");
}
