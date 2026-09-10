use alloy_primitives::B256;
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};

#[test]
fn ordinary_storage_provider_cannot_mint_lysis_activation_authority() {
    let mut provider = HashMapStorageProvider::new(1);
    let handle = StorageHandle::new(&mut provider);
    let mut closure_called = false;
    let result = handle.with_lysis_activation_frame(B256::repeat_byte(7), |_| {
        closure_called = true;
        Ok(())
    });

    assert!(result.is_err());
    assert!(!closure_called);
}
