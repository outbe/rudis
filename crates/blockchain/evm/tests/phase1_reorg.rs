//! Phase 1 accounting-progress reorg regression.
//!
//! The Fresh Phase 1 guard requires `last_accounted_block_number == N - 1`
//! before a child block accounts parent `N`. A same-height reorg is therefore
//! valid only when execution starts from that branch's parent state, not from
//! an abandoned sibling's post-state.

use alloy_primitives::{address, Address, U256};
use outbe_primitives::{
    block::{BlockContext, BlockRuntimeContext},
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

const CHAIN_ID: u64 = 2026;
const VALIDATOR: Address = address!("0x1111111111111111111111111111111111111111");

fn provider(block_number: u64) -> HashMapStorageProvider {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.set_block_number(block_number);
    provider.set_timestamp(U256::from(1_700_000_000u64));
    provider.set_beneficiary(VALIDATOR);
    provider
}

fn runtime_ctx(storage: StorageHandle<'_>) -> BlockRuntimeContext<'_> {
    BlockRuntimeContext::new(
        BlockContext::new(
            storage.block_number().expect("block number"),
            storage.timestamp().expect("timestamp").to::<u64>(),
            storage.chain_id().expect("chain id"),
            VALIDATOR,
            vec![VALIDATOR],
        ),
        storage,
    )
}

fn read_progress(provider: &mut HashMapStorageProvider) -> u64 {
    provider.enter(|storage| {
        let ctx = runtime_ctx(storage);
        outbe_accounting::read_last_accounted_block_number(&ctx).expect("read progress")
    })
}

fn record_progress(provider: &mut HashMapStorageProvider, block_number: u64) {
    provider.enter(|storage| {
        let ctx = runtime_ctx(storage);
        outbe_accounting::record_phase1_progress(&ctx, block_number).expect("record progress");
    });
}

#[test]
fn phase1_reorg_requires_branch_parent_state_for_fresh_progress() {
    const CHILD_BLOCK: u64 = 27;
    const PARENT_BLOCK: u64 = CHILD_BLOCK - 1;
    const REQUIRED_PREVIOUS: u64 = PARENT_BLOCK - 1;

    let mut parent = provider(CHILD_BLOCK);
    record_progress(&mut parent, REQUIRED_PREVIOUS);
    let parent_state = parent.storage.clone();

    let mut branch_a = provider(CHILD_BLOCK);
    branch_a.storage = parent_state.clone();
    assert_eq!(read_progress(&mut branch_a), REQUIRED_PREVIOUS);
    record_progress(&mut branch_a, PARENT_BLOCK);
    assert_eq!(read_progress(&mut branch_a), PARENT_BLOCK);

    let mut branch_b_from_parent = provider(CHILD_BLOCK);
    branch_b_from_parent.storage = parent_state;
    assert_eq!(
        read_progress(&mut branch_b_from_parent),
        REQUIRED_PREVIOUS,
        "same-height reorg branch must begin from its own parent state"
    );
    record_progress(&mut branch_b_from_parent, PARENT_BLOCK);
    assert_eq!(read_progress(&mut branch_b_from_parent), PARENT_BLOCK);

    let mut branch_b_from_abandoned_post_state = provider(CHILD_BLOCK);
    branch_b_from_abandoned_post_state.storage = branch_a.storage.clone();
    assert_eq!(
        read_progress(&mut branch_b_from_abandoned_post_state),
        PARENT_BLOCK,
        "using abandoned sibling post-state would make the Fresh Phase 1 guard reject"
    );
}
