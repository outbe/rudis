use alloy_primitives::{Address, B256};
use outbe_primitives::{
    block::BlockContext,
    error::Result,
    storage::{
        hashmap::HashMapStorageProvider,
        readonly::{ReadOnlyStorageProvider, StorageReader},
        StorageHandle,
    },
};

struct EmptyReader;

impl StorageReader for EmptyReader {
    fn read_storage(&self, _address: Address, _key: B256) -> Result<alloy_primitives::U256> {
        Ok(alloy_primitives::U256::ZERO)
    }
}

#[test]
fn block_context_carries_explicit_genesis_hash_beside_chain_id() {
    let genesis_hash = B256::repeat_byte(0x42);
    let context = BlockContext::new_with_genesis_hash(
        7,
        1_700_000_000,
        70_860_602,
        genesis_hash,
        Address::repeat_byte(0x11),
        vec![Address::repeat_byte(0x22)],
    );

    assert_eq!(context.chain_id, 70_860_602);
    assert_eq!(context.genesis_hash, genesis_hash);
}

#[test]
fn storage_handle_exposes_the_provider_chain_identity() {
    let genesis_hash = B256::repeat_byte(0x43);
    let mut provider = HashMapStorageProvider::new_with_chain_identity(70_860_602, genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        assert_eq!(storage.chain_id().unwrap(), 70_860_602);
        assert_eq!(storage.genesis_hash().unwrap(), genesis_hash);
    });
}

#[test]
fn follower_read_only_context_can_be_bound_to_the_same_chain_identity() {
    let genesis_hash = B256::repeat_byte(0x44);
    let mut provider =
        ReadOnlyStorageProvider::new_with_chain_identity(EmptyReader, 70_860_602, genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        assert_eq!(storage.chain_id().unwrap(), 70_860_602);
        assert_eq!(storage.genesis_hash().unwrap(), genesis_hash);
    });
}
