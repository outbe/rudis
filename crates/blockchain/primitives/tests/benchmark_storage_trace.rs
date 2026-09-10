#![cfg(feature = "bench-utils")]

use alloy_primitives::{Address, U256};
use outbe_primitives::storage::{
    hashmap::{HashMapStorageProvider, StorageTraceKind},
    PrecompileStorageProvider,
};

#[test]
fn benchmark_trace_reverts_with_the_storage_checkpoint() {
    let address = Address::repeat_byte(0x11);
    let first_slot = U256::from(7);
    let reverted_slot = U256::from(8);
    let mut provider = HashMapStorageProvider::new(1);
    provider.enable_storage_trace();

    provider.sstore(address, first_slot, U256::from(1)).unwrap();
    let checkpoint = provider.checkpoint();
    assert_eq!(provider.sload(address, first_slot).unwrap(), U256::from(1));
    provider
        .sstore(address, reverted_slot, U256::from(2))
        .unwrap();
    provider.checkpoint_revert(checkpoint);

    assert_eq!(
        provider.storage_trace(),
        [outbe_primitives::storage::hashmap::StorageTraceOperation {
            address,
            slot: first_slot,
            kind: StorageTraceKind::Write,
        }]
    );
    assert_eq!(provider.sload(address, reverted_slot).unwrap(), U256::ZERO);
}
