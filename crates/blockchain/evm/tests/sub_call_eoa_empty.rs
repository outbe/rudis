//! sub-call to an EOA (no bytecode) returns success with
//! empty returndata.
//!
//! revm's `make_call_frame` short-circuits when the target's bytecode is
//! empty: commits the journal checkpoint and returns `InstructionResult::Stop`
//! with empty output. The driver must translate this to
//! `SubCallStatus::Success` + `returndata = empty`.

use alloy_primitives::{Address, Bytes, U256};
use outbe_evm::sub_call;
use outbe_primitives::storage::{SubCallInput, SubCallStatus};
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    Context,
};

const EOA_TARGET: Address = Address::new([0xAB; 20]);
const CALLER: Address = Address::new([0xC0; 20]);

#[test]
fn sub_call_to_eoa_returns_success_empty() {
    let db = CacheDB::new(EmptyDB::default());
    // No insert_account_info(target, ...) - target is an EOA / empty account.
    let mut ctx = Context::mainnet().with_db(db);

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        /* outer_is_static = */ false,
        SpecId::PRAGUE,
        None,
        std::sync::Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        SubCallInput {
            target: EOA_TARGET,
            value: U256::ZERO,
            calldata: Bytes::new(),
            gas_limit: 100_000,
            is_static: true,
        },
    )
    .expect("sub_call to EOA must not fail fatally");

    assert!(
        matches!(result.status, SubCallStatus::Success),
        "expected Success for EOA target, got {:?}",
        result.status
    );
    assert_eq!(
        result.returndata,
        Bytes::new(),
        "EOA call must return empty bytes"
    );
}
