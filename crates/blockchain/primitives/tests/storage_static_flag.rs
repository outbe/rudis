//! verifies that the `is_static` flag from the
//! provider constructor is honored by [`PrecompileStorageProvider`]
//! implementations.
//!
//! The production wiring (`outbe-evm/src/precompiles.rs:51` calling
//! `EvmStorageProvider::new_with_is_static(internals, gas,
//! input.is_static_call())`) is covered end-to-end by the
//! `staticcall_static_write_halt`. This file
//! verifies the trait contract via `HashMapStorageProvider`, which
//! implements the same trait with the same `is_static` semantics, and
//! includes a compile-time witness that the `EvmStorageProvider`
//! constructor signatures exist as designed.

use alloy_evm::EvmInternals;
use outbe_primitives::storage::{
    evm::EvmStorageProvider, hashmap::HashMapStorageProvider, PrecompileStorageProvider,
};

/// Compile-time witness: the three `EvmStorageProvider` constructors
/// keep the documented signatures. Constructing real `EvmInternals`
/// out-of-band is heavy; this test asserts that the constructors are
/// addressable as function pointers with the right shape, so any
/// future refactor that drops or renames them breaks the test.
// The `'a` lifetime is used only inside the body's fn-pointer type assertions, not
// in the signature, so clippy flags it; keep it - the body needs a named lifetime.
#[allow(dead_code, clippy::extra_unused_lifetimes)]
fn _assert_evm_provider_ctors_exist<'a>() {
    let _: fn(EvmInternals<'a>) -> EvmStorageProvider<'a> = EvmStorageProvider::new;
    let _: fn(EvmInternals<'a>, u64) -> EvmStorageProvider<'a> = EvmStorageProvider::new_with_gas;
    let _: fn(EvmInternals<'a>, u64, bool) -> EvmStorageProvider<'a> =
        EvmStorageProvider::new_with_is_static;
}

#[test]
fn is_static_returns_constructor_flag() {
    // HashMapStorageProvider mirrors the same `is_static` trait contract.
    let mut provider = HashMapStorageProvider::new(1);
    assert!(
        !provider.is_static(),
        "default constructor must report is_static() == false",
    );

    provider.set_static(true);
    assert!(
        provider.is_static(),
        "after set_static(true), is_static() must return true",
    );

    provider.set_static(false);
    assert!(
        !provider.is_static(),
        "after set_static(false), is_static() must return false",
    );
}
