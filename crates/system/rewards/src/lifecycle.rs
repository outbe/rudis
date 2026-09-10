//! Block lifecycle hook for the Rewards module.
//!
//! `RewardsLifecycle` is the zero-sized marker type that implements
//! [`BlockLifecycle`] and is registered in the executor's pre-execution
//! ordering. It runs at the start of every block and currently performs
//! only the genesis-anchor lazy initialization.
//!
//! Day-boundary settle has moved out of Rewards as part of the Cycle
//! refactor: the daily orchestration runs on
//! `CycleLifecycle::begin_block` and dispatches into EmissionLimit ->
//! AgentReward -> Rewards (via
//! [`crate::api::prepare_daily_validator_gem_batch`]) exactly once per UTC day.

use outbe_primitives::{block::BlockLifecycle, block::BlockRuntimeContext, error::Result};

use crate::runtime;

/// Zero-sized marker implementing the block-lifecycle contract for the
/// Rewards module. Registered in
/// `outbe_evm::executor::run_outbe_pre_execution_hooks` so the executor
/// can keep ordering explicit and hard-fork governed
pub struct RewardsLifecycle;

impl BlockLifecycle for RewardsLifecycle {
    type Context<'a, 'storage> = BlockRuntimeContext<'storage>;
    type EndBlockResult = ();

    fn begin_block(ctx: &BlockRuntimeContext) -> Result<()> {
        // Lock in `genesis_utc_day` from block 0's timestamp on the very
        // first invocation of this lifecycle on a fresh chain.
        // Subsequent calls are no-ops because the slot is already
        // non-zero. This is the single source of truth for the
        // closed-form daily-emission curve in `crate::emission`.
        let _genesis = runtime::ensure_genesis_anchor(ctx)?;
        Ok(())
    }

    fn end_block(_ctx: &BlockRuntimeContext) -> Result<Self::EndBlockResult> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use outbe_primitives::block::BlockContext;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;

    const CHAIN_ID: u64 = 1;
    const GENESIS_TS_2024_01_01: u64 = 1_704_067_200;

    fn block_ctx(block_number: u64, timestamp: u64) -> BlockContext {
        BlockContext::new(block_number, timestamp, CHAIN_ID, Address::ZERO, Vec::new())
    }

    #[test]
    fn begin_block_locks_in_genesis_utc_day_on_block_zero() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(0, GENESIS_TS_2024_01_01), handle);

            <RewardsLifecycle as BlockLifecycle>::begin_block(&ctx).unwrap();

            assert_eq!(runtime::genesis_utc_day(&ctx).unwrap(), 20240101);
        });
    }

    #[test]
    fn begin_block_is_idempotent_across_blocks() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx0 =
                BlockRuntimeContext::new(block_ctx(0, GENESIS_TS_2024_01_01), handle.clone());
            <RewardsLifecycle as BlockLifecycle>::begin_block(&ctx0).unwrap();

            // Block 1, slightly later - must not move the locked-in day.
            let ctx1 =
                BlockRuntimeContext::new(block_ctx(1, GENESIS_TS_2024_01_01 + 60), handle.clone());
            <RewardsLifecycle as BlockLifecycle>::begin_block(&ctx1).unwrap();
            assert_eq!(runtime::genesis_utc_day(&ctx1).unwrap(), 20240101);

            // Block 100, 30 days later - still 20240101.
            let ctx_later = BlockRuntimeContext::new(
                block_ctx(100, GENESIS_TS_2024_01_01 + 86_400 * 30),
                handle,
            );
            <RewardsLifecycle as BlockLifecycle>::begin_block(&ctx_later).unwrap();
            assert_eq!(runtime::genesis_utc_day(&ctx_later).unwrap(), 20240101);
        });
    }
}
