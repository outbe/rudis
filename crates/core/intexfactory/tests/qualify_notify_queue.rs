//! Queue mechanics of the lifecycle notices the `intex_notify` trigger sends.
//!
//! The notice itself is best-effort, so these pin what must hold regardless of
//! whether it reaches the router: the chunk bound, the resume point, and that a
//! drained entry is gone.

use alloy_primitives::U256;
use outbe_intex::SeriesId;
use outbe_intexfactory::constants::MAX_ROUTER_CALLS_PER_FIRING;
use outbe_intexfactory::qualified::{drain_notices, NOTICE_CALLED};
use outbe_intexfactory::IntexFactoryContract;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::types::Storable;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;

const CHAIN_ID: u64 = 1;
const NOW: u64 = 1_700_000_000;

fn series(index: u32) -> SeriesId {
    SeriesId::pack(WorldwideDay::new(20_260_101 + index), *b"USD", b'U')
        .expect("well-formed series id")
}

fn seed(handle: &StorageHandle<'_>, count: u32) {
    let factory = IntexFactoryContract::new(handle.clone());
    for index in 0..count {
        factory
            .notify_at
            .write(&index, series(index).to_word())
            .unwrap();
        factory.notify_kind.write(&index, NOTICE_CALLED).unwrap();
    }
    factory.notify_tail.write(count).unwrap();
}

fn drain(handle: &StorageHandle<'_>) {
    let ctx = BlockRuntimeContext::new(
        BlockContext::empty_for_tests(1, NOW, CHAIN_ID),
        handle.clone(),
    );
    drain_notices(&ctx).expect("a dropped notice never fails the drain");
}

fn queue_bounds(handle: &StorageHandle<'_>) -> (u32, u32) {
    let factory = IntexFactoryContract::new(handle.clone());
    (
        factory.notify_head.read().unwrap(),
        factory.notify_tail.read().unwrap(),
    )
}

#[test]
fn a_backlog_drains_one_firing_worth_at_a_time() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |handle| {
        let queued = MAX_ROUTER_CALLS_PER_FIRING + 5;
        seed(&handle, queued);

        drain(&handle);
        assert_eq!(
            queue_bounds(&handle),
            (MAX_ROUTER_CALLS_PER_FIRING, queued),
            "one firing spends its budget and leaves the rest queued"
        );

        drain(&handle);
        assert_eq!(
            queue_bounds(&handle),
            (0, 0),
            "emptying the queue rewinds it so the indices cannot run away"
        );
    });
}

#[test]
fn a_drained_entry_is_gone() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |handle| {
        seed(&handle, 3);
        drain(&handle);

        let factory = IntexFactoryContract::new(handle.clone());
        for index in 0..3 {
            assert_eq!(
                factory.notify_at.read(&index).unwrap(),
                U256::ZERO,
                "a sent notice must not be sent twice"
            );
        }
    });
}

#[test]
fn an_empty_queue_is_a_noop() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |handle| {
        drain(&handle);
        assert_eq!(queue_bounds(&handle), (0, 0));
    });
}

#[test]
fn an_exactly_full_firing_rewinds_the_queue() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |handle| {
        seed(&handle, MAX_ROUTER_CALLS_PER_FIRING);
        drain(&handle);
        assert_eq!(queue_bounds(&handle), (0, 0));
    });
}
