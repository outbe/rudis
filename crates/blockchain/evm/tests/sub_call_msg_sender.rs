//! `msg.sender` propagation.
//!
//! Deploys EVM bytecode that returns `msg.sender` as a 32-byte word. The
//! sub-call driver must set `CallInputs::caller = self_address` so the
//! target sees the precompile (or its proxy) as `msg.sender`.
//!
//! Bytecode:
//! ```text
//! 33         CALLER          ; push msg.sender (20 bytes, zero-padded to 32)
//! 60 00      PUSH1 0x00      ; memory offset 0
//! 52         MSTORE          ; store the 32-byte word
//! 60 20      PUSH1 0x20      ; size 32
//! 60 00      PUSH1 0x00      ; memory offset 0
//! f3         RETURN          ; return
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

const RETURN_CALLER_BYTECODE: &[u8] = &[
    0x33, // CALLER
    0x60, 0x00, // PUSH1 0x00
    0x52, // MSTORE
    0x60, 0x20, // PUSH1 0x20
    0x60, 0x00, // PUSH1 0x00
    0xF3, // RETURN
];

#[test]
fn sub_call_propagates_caller_as_msg_sender() {
    let mut db = CacheDB::new(EmptyDB::default());
    let code = Bytecode::new_raw(Bytes::from_static(RETURN_CALLER_BYTECODE));
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
    .expect("sub_call should succeed");

    assert!(matches!(result.status, SubCallStatus::Success));

    // CALLER opcode pushes 20-byte address into a 32-byte word
    // (left-zero-padded for big-endian).
    let mut expected = [0u8; 32];
    expected[12..].copy_from_slice(CALLER.as_slice());
    assert_eq!(
        result.returndata,
        Bytes::from(expected.to_vec()),
        "msg.sender returned by CALLER opcode must equal SubCallInput.self_address"
    );
}
