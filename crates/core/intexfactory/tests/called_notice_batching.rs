//! Coalescing of Called notices in the `intex_notify` drain.
//!
//! The harness cannot observe outbound calls, so the grouping rule is pinned as a predicate and the
//! rest covers the queue walk: what each firing consumes and where it resumes.

use alloy_primitives::U256;
use outbe_intex::SeriesId;
use outbe_intexfactory::constants::{MAX_ROUTER_CALLS_PER_FIRING, MAX_SERIES_PER_MARK};
use outbe_intexfactory::qualified::{
    drain_notices, joins_run, pack_called_notice, NOTICE_CALLED, NOTICE_QUALIFIED,
};
use outbe_intexfactory::IntexFactoryContract;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;

const CHAIN_ID: u64 = 1;
const NOW: u64 = 1_700_000_000;
const DAY: u32 = 20_260_101;
const CALLED_AT: u32 = NOW as u32 - 3_600;

fn series(index: u32) -> SeriesId {
    // Three digits of currency, so a long queue wraps; these tests measure the walk.
    let index = index % 1000;
    let iso = [
        b'0' + (index / 100) as u8,
        b'0' + ((index / 10) % 10) as u8,
        b'0' + (index % 10) as u8,
    ];
    SeriesId::pack(WorldwideDay::new(DAY), iso, b'U').expect("well-formed series id")
}

fn push(handle: &StorageHandle<'_>, kind: u8, entry: U256) {
    let factory = IntexFactoryContract::new(handle.clone());
    let tail = factory.notify_tail.read().unwrap();
    factory.notify_at.write(&tail, entry).unwrap();
    factory.notify_kind.write(&tail, kind).unwrap();
    factory.notify_tail.write(tail + 1).unwrap();
}

fn push_called(handle: &StorageHandle<'_>, index: u32, called_at: u32) {
    push(
        handle,
        NOTICE_CALLED,
        pack_called_notice(series(index), called_at),
    );
}

fn drain(handle: &StorageHandle<'_>) {
    let ctx = BlockRuntimeContext::new(
        BlockContext::empty_for_tests(1, NOW, CHAIN_ID),
        handle.clone(),
    );
    drain_notices(&ctx).expect("a dropped notice never fails the drain");
}

/// A provider whose OriginRouter accepts sends, so the drain exercises the path a live chain takes
/// rather than the drop-and-log one a missing stub produces.
fn provider() -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.stub_sub_call_at(
        outbe_intexfactory::constants::ORIGIN_ROUTER_ADDRESS,
        alloy_primitives::Bytes::from(vec![0u8; 32]),
    );
    storage
}

fn bounds(handle: &StorageHandle<'_>) -> (u32, u32) {
    let factory = IntexFactoryContract::new(handle.clone());
    (
        factory.notify_head.read().unwrap(),
        factory.notify_tail.read().unwrap(),
    )
}

#[test]
fn a_run_longer_than_the_wire_cap_still_empties() {
    let mut storage = provider();
    StorageHandle::enter(&mut storage, |handle| {
        for index in 0..20 {
            push_called(&handle, index, CALLED_AT);
        }
        drain(&handle);
        assert_eq!(
            bounds(&handle),
            (0, 0),
            "the whole run fits one firing and rewinds the queue"
        );
    });
}

#[test]
fn a_run_never_reaches_past_the_chunk_limit() {
    let mut storage = provider();
    StorageHandle::enter(&mut storage, |handle| {
        // One coalesced run: the wire cap turns every eight entries into one call.
        let run_cap = MAX_ROUTER_CALLS_PER_FIRING * MAX_SERIES_PER_MARK as u32;
        let queued = run_cap + 5;
        for index in 0..queued {
            push_called(&handle, index, CALLED_AT);
        }
        drain(&handle);
        assert_eq!(
            bounds(&handle),
            (run_cap, queued),
            "head lands on the first unconsumed entry, not past it"
        );

        drain(&handle);
        assert_eq!(bounds(&handle), (0, 0), "the remainder goes next firing");
    });
}

#[test]
fn a_run_takes_only_entries_sharing_the_day_and_the_call_time() {
    let day = WorldwideDay::new(DAY);
    assert!(
        joins_run(day, CALLED_AT, series(1), CALLED_AT),
        "same day and stamp ride together"
    );
    assert!(
        !joins_run(day, CALLED_AT, series(1), CALLED_AT + 1),
        "a later stamp starts its own message"
    );
    assert!(
        !joins_run(day, CALLED_AT, series(1), CALLED_AT - 1),
        "an earlier stamp does too"
    );

    let other_day =
        SeriesId::pack(WorldwideDay::new(DAY + 1), *b"840", b'U').expect("well-formed series id");
    assert!(
        !joins_run(day, CALLED_AT, other_day, CALLED_AT),
        "the wire carries one day per message"
    );
}

#[test]
fn a_qualified_entry_ends_the_run() {
    let mut storage = provider();
    StorageHandle::enter(&mut storage, |handle| {
        push_called(&handle, 0, CALLED_AT);
        push(&handle, NOTICE_QUALIFIED, U256::from(1u64));
        push_called(&handle, 1, CALLED_AT);

        drain(&handle);

        let factory = IntexFactoryContract::new(handle.clone());
        for index in 0..3u32 {
            assert_eq!(
                factory.notify_at.read(&index).unwrap(),
                U256::ZERO,
                "every entry consumed once"
            );
        }
        assert_eq!(bounds(&handle), (0, 0));
    });
}

#[test]
fn a_different_call_time_ends_the_run() {
    let mut storage = provider();
    StorageHandle::enter(&mut storage, |handle| {
        push_called(&handle, 0, CALLED_AT);
        push_called(&handle, 1, CALLED_AT + 1);

        drain(&handle);

        assert_eq!(
            bounds(&handle),
            (0, 0),
            "both groups leave, each with its own stamp"
        );
    });
}

#[test]
fn a_run_that_hits_the_chunk_limit_is_split_not_overrun() {
    let mut storage = provider();
    StorageHandle::enter(&mut storage, |handle| {
        let queued = MAX_ROUTER_CALLS_PER_FIRING + 5;
        for index in 0..queued {
            push_called(&handle, index, CALLED_AT + index);
        }

        drain(&handle);
        assert_eq!(
            bounds(&handle),
            (MAX_ROUTER_CALLS_PER_FIRING, queued),
            "the firing stops on its router-call budget"
        );

        let factory = IntexFactoryContract::new(handle.clone());
        for index in MAX_ROUTER_CALLS_PER_FIRING..queued {
            assert_ne!(
                factory.notify_at.read(&index).unwrap(),
                U256::ZERO,
                "entries past the limit are untouched, not cleared behind the drain's back"
            );
        }

        drain(&handle);
        assert_eq!(
            bounds(&handle),
            (0, 0),
            "the tail of the run leaves next firing"
        );
    });
}
