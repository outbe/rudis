//! verifies that each of the 8 mutating methods on
//! [`outbe_primitives::storage::StorageHandle`] returns
//! [`outbe_primitives::error::PrecompileError::WriteProtection`] when
//! the underlying provider reports `is_static() == true`.
//!
//! The gates are the runtime enforcement of STATICCALL semantics: a
//! precompile invoked under STATICCALL must not modify state. Before
//! the gates were absent and mutations silently succeeded
//! (consensus bug).

use alloy_primitives::{address, Address, LogData, U256};
use outbe_primitives::{
    error::PrecompileError,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};
use revm::state::Bytecode;

fn provider() -> HashMapStorageProvider {
    let mut p = HashMapStorageProvider::new(1);
    p.set_static(true);
    p
}

const TARGET: Address = address!("00000000000000000000000000000000000000aa");

fn assert_write_protection<T: core::fmt::Debug>(
    name: &'static str,
    result: Result<T, PrecompileError>,
) {
    match result {
        Err(PrecompileError::WriteProtection) => {}
        other => panic!(
            "{}: expected Err(PrecompileError::WriteProtection), got {:?}",
            name, other,
        ),
    }
}

#[test]
fn sstore_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection("sstore", storage.sstore(TARGET, U256::ZERO, U256::ONE));
    });
}

#[test]
fn tstore_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection("tstore", storage.tstore(TARGET, U256::ZERO, U256::ONE));
    });
}

#[test]
fn emit_event_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection("emit_event", storage.emit_event(TARGET, LogData::default()));
    });
}

#[test]
fn transfer_balance_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        let other = address!("00000000000000000000000000000000000000bb");
        assert_write_protection(
            "transfer_balance",
            storage.transfer_balance(TARGET, other, U256::from(1u64)),
        );
    });
}

#[test]
fn increase_balance_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection(
            "increase_balance",
            storage.increase_balance(TARGET, U256::from(1u64)),
        );
    });
}

#[test]
fn decrease_balance_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection(
            "decrease_balance",
            storage.decrease_balance(TARGET, U256::from(1u64)),
        );
    });
}

#[test]
fn set_balance_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection("set_balance", storage.set_balance(TARGET, U256::from(1u64)));
    });
}

#[test]
fn set_code_under_static_returns_write_protection() {
    let mut p = provider();
    StorageHandle::enter(&mut p, |storage| {
        assert_write_protection(
            "set_code",
            storage.set_code(TARGET, Bytecode::new_raw(vec![0x00u8].into())),
        );
    });
}
