use std::cell::Cell;

use alloy_primitives::B256;
use outbe_primitives::{
    error::PrecompileError,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

// OCOMP-TEST-ID: OCM-BND-001
#[test]
fn ordinary_storage_provider_cannot_mint_the_certified_activation_capability() {
    let mut provider = HashMapStorageProvider::new(1);
    let entered = Cell::new(false);

    let error = StorageHandle::enter(&mut provider, |storage| {
        storage
            .with_lysis_activation_frame(B256::repeat_byte(1), |_capability| {
                entered.set(true);
                Ok(())
            })
            .unwrap_err()
    });

    assert!(!entered.get());
    assert!(matches!(error, PrecompileError::Fatal(_)));
}

#[test]
fn entitled_frame_enforces_the_fixed_owner_cursor_and_terminal_completion() {
    let mut provider = HashMapStorageProvider::new(1);
    provider.enable_lysis_activation_frame();

    StorageHandle::enter(&mut provider, |storage| {
        storage
            .with_lysis_activation_frame(B256::repeat_byte(2), |capability| {
                assert!(capability.authorize_contributor_installation().is_err());
                capability.authorize_nod_installation()?;
                assert!(capability.authorize_nod_installation().is_err());
                capability.authorize_contributor_installation()?;
                capability.authorize_carry_over_credit()?;
                capability.authorize_tribute_retirement()?;
                capability.authorize_terminal_receipt()
            })
            .unwrap();
    });
}

#[test]
fn entitled_frame_rejects_success_without_all_owner_effects() {
    let mut provider = HashMapStorageProvider::new(1);
    provider.enable_lysis_activation_frame();

    let error = StorageHandle::enter(&mut provider, |storage| {
        storage
            .with_lysis_activation_frame(B256::repeat_byte(3), |capability| {
                capability.authorize_nod_installation()
            })
            .unwrap_err()
    });

    assert!(matches!(error, PrecompileError::Fatal(_)));
}
