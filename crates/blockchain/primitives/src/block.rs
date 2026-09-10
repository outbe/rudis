use alloy_primitives::{Address, B256};

use crate::{
    error::Result,
    storage::{StorageBacked, StorageHandle},
};

/// Runtime context shared by begin-block/end-block handlers.
///
/// The lifecycle executor builds this context from canonical block/header,
/// chain, and validator-set state before calling runtime modules.
#[derive(Clone, Debug, Default)]
pub struct BlockContext {
    pub block_number: u64,
    pub timestamp: u64,
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub proposer: Address,
    pub validators: Vec<Address>,
}

impl BlockContext {
    pub fn new(
        block_number: u64,
        timestamp: u64,
        chain_id: u64,
        proposer: Address,
        validators: Vec<Address>,
    ) -> Self {
        Self::new_with_genesis_hash(
            block_number,
            timestamp,
            chain_id,
            B256::ZERO,
            proposer,
            validators,
        )
    }

    /// Creates an execution context bound to the immutable chain identity.
    ///
    /// Production execution must source `genesis_hash` from the canonical
    /// `ChainSpec`; transaction calldata and mutable storage are not
    /// authorities for this value.
    pub fn new_with_genesis_hash(
        block_number: u64,
        timestamp: u64,
        chain_id: u64,
        genesis_hash: B256,
        proposer: Address,
        validators: Vec<Address>,
    ) -> Self {
        Self {
            block_number,
            timestamp,
            chain_id,
            genesis_hash,
            proposer,
            validators,
        }
    }

    pub fn empty_for_tests(block_number: u64, timestamp: u64, chain_id: u64) -> Self {
        Self::new(block_number, timestamp, chain_id, Address::ZERO, Vec::new())
    }
}

#[derive(Clone)]
pub struct BlockRuntimeContext<'storage> {
    pub block: BlockContext,
    pub storage: StorageHandle<'storage>,
}

impl<'storage> BlockRuntimeContext<'storage> {
    pub fn new(block: BlockContext, storage: StorageHandle<'storage>) -> Self {
        Self { block, storage }
    }

    pub fn contract<C: StorageBacked<'storage>>(&self) -> C {
        self.storage.contract::<C>()
    }

    pub fn contract_at<C: StorageBacked<'storage>>(&self, address: Address) -> C {
        self.storage.contract_at::<C>(address)
    }

    pub fn with_checkpoint<R>(&self, f: impl FnOnce() -> Result<R>) -> Result<R> {
        self.storage.with_checkpoint(f)
    }
}

/// Static lifecycle contract for deterministic block-boundary runtime modules.
///
/// Implementations should be zero-sized marker types. The executor keeps the
/// ordering explicit and calls implementations through this trait instead of
/// passing ad hoc `(timestamp, block_number, ...)` argument lists.
pub trait BlockLifecycle {
    /// Typed runtime authority required by this lifecycle. Ordinary modules
    /// use [`BlockRuntimeContext`]; modules that need additional explicit
    /// capabilities wrap it in a dedicated context instead of bypassing the
    /// lifecycle contract with an ad-hoc entrypoint.
    type Context<'a, 'storage>;

    /// Value produced after all lifecycle-owned end-block work succeeds.
    ///
    /// Lifecycles without an associated output use `()`.
    type EndBlockResult;

    fn begin_block(_ctx: &Self::Context<'_, '_>) -> Result<()> {
        Ok(())
    }

    fn end_block(ctx: &Self::Context<'_, '_>) -> Result<Self::EndBlockResult>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;

    struct OutputLifecycle;

    impl BlockLifecycle for OutputLifecycle {
        type Context<'a, 'storage> = BlockRuntimeContext<'storage>;
        type EndBlockResult = u64;

        fn end_block(ctx: &BlockRuntimeContext) -> Result<Self::EndBlockResult> {
            Ok(ctx.block.block_number)
        }
    }

    #[test]
    fn lifecycle_end_block_can_return_an_associated_output() {
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let ctx = BlockRuntimeContext::new(BlockContext::empty_for_tests(7, 11, 1), storage);

            assert_eq!(OutputLifecycle::end_block(&ctx).unwrap(), 7);
        });
    }
}
