//! happy-path sub-call integration test.
//!
//! Deploys minimal EVM bytecode at a target address inside an
//! `EthEvmContext<InMemoryDB>` and invokes `sub_call::run` directly with a
//! `SubCallInput`. Asserts that the driver:
//! 1. Builds a borrowed-ctx Evm (`Evm<&mut EthEvmContext<DB>, ...>`),
//! 2. Loads the target's bytecode through the journal,
//! 3. Runs the frame loop to completion via revm's canonical
//!    `frame_init` / `frame_run` / `frame_return_result` pattern,
//! 4. Returns `SubCallOutput { status: Success, returndata, ... }` with
//!    the bytes produced by the child contract's `RETURN` opcode.
//!
//! The "contract" is a 10-byte EVM bytecode sequence that pushes
//! `0x000...001` onto memory and returns its 32-byte word:
//!
//! ```text
//! 6001         PUSH1 0x01
//! 6000         PUSH1 0x00
//! 52           MSTORE
//! 6020         PUSH1 0x20
//! 6000         PUSH1 0x00
//! f3           RETURN
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

/// Minimal EVM bytecode: stores `0x000...001` at memory offset 0 and
/// returns the 32-byte word.
const RETURN_ONE_BYTECODE: &[u8] = &[
    0x60, 0x01, // PUSH1 0x01
    0x60, 0x00, // PUSH1 0x00
    0x52, // MSTORE
    0x60, 0x20, // PUSH1 0x20
    0x60, 0x00, // PUSH1 0x00
    0xF3, // RETURN
];

fn build_ctx_with_bytecode() -> alloy_evm::eth::EthEvmContext<CacheDB<EmptyDB>> {
    let mut db = CacheDB::new(EmptyDB::default());
    let code = Bytecode::new_raw(Bytes::from_static(RETURN_ONE_BYTECODE));
    let info = AccountInfo {
        balance: U256::ZERO,
        nonce: 0,
        code_hash: code.hash_slow(),
        code: Some(code),
        ..Default::default()
    };
    db.insert_account_info(TARGET, info);
    Context::mainnet().with_db(db)
}

#[test]
fn staticcall_returns_contract_returndata() {
    let mut ctx = build_ctx_with_bytecode();

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
    .expect("sub_call should not return a fatal error");

    assert!(
        matches!(result.status, SubCallStatus::Success),
        "expected Success, got {:?}",
        result.status,
    );

    // Bytecode returns 32 bytes with value 0x00..01 - verify byte-exact.
    let expected = {
        let mut buf = [0u8; 32];
        buf[31] = 1;
        Bytes::from(buf.to_vec())
    };
    assert_eq!(
        result.returndata, expected,
        "returndata must be the 32-byte word the contract RETURNs"
    );

    assert!(
        result.gas_used > 0 && result.gas_used < 1_000_000,
        "gas_used must be within the requested budget, got {}",
        result.gas_used
    );
}
