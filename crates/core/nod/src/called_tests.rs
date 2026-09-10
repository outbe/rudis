//! Daily call-scan tests: the 21-of-28 breach rule and the seven-day forfeit.
//!
//! Every test drives the real [`crate::called::scan_and_call`] through [`scan`]
//! against seeded oracle history, so the breach count is recomputed from the
//! finalized daily VWAP series exactly as it is in a block.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{begin_block, ExecutionScope, WwdEntityId};
use outbe_offchain_storage::MemoryStorage;
use outbe_oracle::{api::AddressPair, schema::OracleContract};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS,
    block::{BlockContext, BlockRuntimeContext},
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
    time::{previous_date_key, timestamp_to_date_key},
};

use crate::{
    api,
    constants::{CALL_BREACH_DAYS, CALL_LOOKBACK_DAYS, CALL_NOTICE_PERIOD, CALL_RATE_PCT},
    NodContract, NodItemState, NodRepositoryReader,
};

const CHAIN_ID: u64 = 1;
const BLOCK_NUMBER: u64 = 42;
const DAY: u64 = 86_400;
const ISO: u16 = 840;
const OTHER_ISO: u16 = 978;
/// Issuance instant, 2027-01-15 08:00 UTC.
const START: u64 = 1_800_000_000;

/// The worldwide day [`START`] falls in. The two must agree: the breach walk
/// stops at the first day preceding the bucket's worldwide day, so a fixture
/// whose day predates its timestamp would silently never exercise that guard.
const WWD: u32 = 20_270_115;

/// Entry price every bucket here is issued at: 2.0 at scale 1e6. The call price
/// is therefore `2.0 x 3.56 = 7.12`.
fn entry_price() -> U256 {
    U256::from(2_000_000u64)
}

/// Exactly the call price (7.12). The breach test is strict `>`, so a day at
/// this value must NOT count.
fn at_call() -> U256 {
    U256::from(7_120_000u64)
}

/// A day above the call price.
fn above_call() -> U256 {
    U256::from(7_200_000u64)
}

/// A day below the call price.
fn below_call() -> U256 {
    U256::from(4_000_000u64)
}

fn seed_compressed_entities_genesis(storage: &StorageHandle<'_>) {
    storage
        .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
        .unwrap();
    storage
        .sstore(
            COMPRESSED_ENTITIES_ADDRESS,
            U256::from(1),
            U256::from_be_slice(
                outbe_compressed_entities::sealed_root(B256::ZERO)
                    .unwrap()
                    .as_slice(),
            ),
        )
        .unwrap();
}

fn nod_item(owner: Address, iso: u16) -> NodItemState {
    nod_item_at(owner, iso, U256::from(13))
}

/// A Nod whose bucket is keyed by `floor_price_minor`, so distinct floors give
/// distinct buckets on the same worldwide day.
fn nod_item_at(owner: Address, iso: u16, floor_price_minor: U256) -> NodItemState {
    let worldwide_day = WorldwideDay::new(WWD);
    NodItemState {
        nod_id: NodContract::generate_nod_id(owner, worldwide_day).unwrap(),
        owner,
        gratis_load_minor: U256::from(11),
        worldwide_day,
        league_id: 4,
        floor_price_minor,
        bucket_key: NodContract::bucket_key(worldwide_day, floor_price_minor, iso),
        issuance_currency: iso,
        reference_currency: iso,
        issued_at: START,
    }
}

fn register(storage: &StorageHandle<'_>, iso: u16) {
    if outbe_oracle::api::coen_pair_index_opt(storage.clone(), iso)
        .unwrap()
        .is_none()
    {
        outbe_oracle::api::register_pair(storage.clone(), AddressPair::new_coen_to(iso)).unwrap();
    }
}

fn last_closed_day(timestamp: u64) -> u32 {
    previous_date_key(timestamp_to_date_key(timestamp))
}

fn bump_watermark(storage: &StorageHandle<'_>, utc_day: u32) {
    let oracle = OracleContract::new(storage.clone());
    if oracle.utc_day_vwap_last_finalized.read().unwrap() < utc_day {
        oracle.utc_day_vwap_last_finalized.write(utc_day).unwrap();
    }
}

/// Publishes a finalized daily reference price for one UTC day on `COEN/<iso>`.
fn set_vwap_for(storage: &StorageHandle<'_>, iso: u16, utc_day: u32, value: U256) {
    let index = outbe_oracle::api::coen_pair_index_opt(storage.clone(), iso)
        .unwrap()
        .expect("the pair must be registered before its series is seeded");
    let oracle = OracleContract::new(storage.clone());
    oracle
        .utc_day_vwap_value
        .get_nested(&utc_day)
        .write(&index, value)
        .unwrap();
    bump_watermark(storage, utc_day);
}

/// Sets `days` consecutive closed UTC days ending at `latest` to `value`.
fn fill_days_for(storage: &StorageHandle<'_>, iso: u16, latest: u32, days: u32, value: U256) {
    let mut day = latest;
    for _ in 0..days {
        set_vwap_for(storage, iso, day, value);
        day = previous_date_key(day);
    }
}

fn fill_days(storage: &StorageHandle<'_>, latest: u32, days: u32, value: U256) {
    fill_days_for(storage, ISO, latest, days, value);
}

/// Advances the watermark without publishing any price.
fn finalize_through(storage: &StorageHandle<'_>, timestamp: u64) {
    bump_watermark(storage, last_closed_day(timestamp));
}

/// Issues one Nod owned by `owner` and qualifies its bucket, which is what arms
/// the bucket for the call scan.
fn issue_qualified(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &NodRepositoryReader,
    owner: Address,
    iso: u16,
) -> NodItemState {
    let item = nod_item(owner, iso);
    api::add_nod(storage, scope, parent, &item, entry_price()).unwrap();
    NodContract::new(storage.clone())
        .qualify_bucket(scope, parent, item.bucket_key)
        .unwrap();
    item
}

fn scan(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &NodRepositoryReader,
    timestamp: u64,
) -> u32 {
    let ctx = BlockRuntimeContext::new(
        BlockContext::empty_for_tests(BLOCK_NUMBER, timestamp, CHAIN_ID),
        storage.clone(),
    );
    crate::called::scan_and_call(&ctx, scope, parent).unwrap()
}

/// Promis Reserve balance - what a forfeited `gratis_load_minor` returns to.
fn reserve(storage: &StorageHandle<'_>) -> U256 {
    outbe_promislimit::PromisLimitContract::new(storage.clone())
        .get_total_unallocated()
        .unwrap()
}

fn called_at(storage: &StorageHandle<'_>, bucket_key: B256) -> u64 {
    NodContract::new(storage.clone())
        .bucket_called_at
        .read(&bucket_key)
        .unwrap()
}

/// Runs `body` inside a storage scope with compressed entities open and the
/// default `COEN/840` pair registered.
fn harness(body: impl FnOnce(&StorageHandle<'_>, &ExecutionScope, &NodRepositoryReader)) {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        register(&storage, ISO);
        body(&storage, &scope, &parent);
    });
}

// --- Call arm --------------------------------------------------------------

#[test]
fn the_call_price_is_the_entry_price_times_the_call_rate() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let stored = NodContract::new(storage.clone())
            .callable_bucket_call_price
            .read(&item.bucket_key)
            .unwrap();
        assert_eq!(
            stored,
            entry_price() * U256::from(100 + CALL_RATE_PCT) / U256::from(100)
        );
        assert_eq!(stored, at_call(), "2.0 x 3.56 == 7.12");
    });
}

#[test]
fn a_full_window_above_the_call_price_calls_the_bucket() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let at = START + 30 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        assert_eq!(scan(storage, scope, parent, at), 1);
        assert_eq!(called_at(storage, item.bucket_key), at);

        // Idempotent: a called bucket is not called twice.
        assert_eq!(scan(storage, scope, parent, at + DAY), 0);
        assert_eq!(called_at(storage, item.bucket_key), at);
    });
}

#[test]
fn one_breach_day_short_of_the_threshold_does_not_call() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let at = START + 30 * DAY;
        let latest = last_closed_day(at);
        fill_days(storage, latest, CALL_LOOKBACK_DAYS, below_call());
        fill_days(storage, latest, CALL_BREACH_DAYS - 1, above_call());

        assert_eq!(scan(storage, scope, parent, at), 0);
        assert_eq!(called_at(storage, item.bucket_key), 0);
    });
}

#[test]
fn the_window_absorbs_below_call_days_up_to_the_slack() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let at = START + 30 * DAY;
        let latest = last_closed_day(at);
        fill_days(storage, latest, CALL_LOOKBACK_DAYS, above_call());

        // Scatter exactly the slack (28 - 21 = 7) below-call days through the
        // window; the count, not a streak, is what decides.
        let slack = CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS;
        let mut day = latest;
        let mut dropped = 0;
        let mut offset = 0;
        while dropped < slack {
            if offset % 3 == 0 {
                set_vwap_for(storage, ISO, day, below_call());
                dropped += 1;
            }
            day = previous_date_key(day);
            offset += 1;
        }

        assert_eq!(scan(storage, scope, parent, at), 1);
        assert_eq!(called_at(storage, item.bucket_key), at);
    });
}

#[test]
fn a_day_exactly_at_the_call_price_does_not_count_as_a_breach() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let at = START + 30 * DAY;
        fill_days(storage, last_closed_day(at), CALL_LOOKBACK_DAYS, at_call());

        assert_eq!(scan(storage, scope, parent, at), 0);
        assert_eq!(called_at(storage, item.bucket_key), 0);
    });
}

#[test]
fn missing_days_do_not_count_as_breaches() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let at = START + 30 * DAY;
        let latest = last_closed_day(at);
        // Only one day short of the threshold is published; the rest are absent.
        fill_days(storage, latest, CALL_BREACH_DAYS - 1, above_call());
        finalize_through(storage, at);

        assert_eq!(scan(storage, scope, parent, at), 0);
        assert_eq!(called_at(storage, item.bucket_key), 0);
    });
}

#[test]
fn a_breach_run_that_predates_the_bucket_does_not_call_it() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        // Scan two days into the bucket's worldwide day: only a couple of closed
        // days post-date it, so the pre-existence run beyond them is ignored even
        // though the whole series breaches.
        let at = START + 2 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        assert_eq!(scan(storage, scope, parent, at), 0);
        assert_eq!(called_at(storage, item.bucket_key), 0);
    });
}

#[test]
fn an_unfinalized_day_skips_the_run_without_touching_state() {
    harness(|storage, scope, parent| {
        let item = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let at = START + 30 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        // Ask a day later than anything the oracle has finalized.
        let ahead = at + 2 * DAY;
        assert_eq!(scan(storage, scope, parent, ahead), 0);
        assert_eq!(called_at(storage, item.bucket_key), 0);
    });
}

#[test]
fn each_bucket_reads_its_own_currency_series() {
    harness(|storage, scope, parent| {
        register(storage, OTHER_ISO);
        let usd = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let eur = issue_qualified(
            storage,
            scope,
            parent,
            Address::repeat_byte(0x22),
            OTHER_ISO,
        );

        let at = START + 30 * DAY;
        let latest = last_closed_day(at);
        // Only the EUR series breaches.
        fill_days_for(storage, ISO, latest, CALL_LOOKBACK_DAYS, below_call());
        fill_days_for(storage, OTHER_ISO, latest, CALL_LOOKBACK_DAYS, above_call());

        assert_eq!(scan(storage, scope, parent, at), 1);
        assert_eq!(called_at(storage, usd.bucket_key), 0);
        assert_eq!(called_at(storage, eur.bucket_key), at);
    });
}

// --- Forfeit arm -----------------------------------------------------------

/// Calls a bucket at `at`, returning the issued Nod.
fn call_bucket(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &NodRepositoryReader,
    owner: Address,
    at: u64,
) -> NodItemState {
    let item = issue_qualified(storage, scope, parent, owner, ISO);
    fill_days(
        storage,
        last_closed_day(at),
        CALL_LOOKBACK_DAYS,
        above_call(),
    );
    assert_eq!(scan(storage, scope, parent, at), 1);
    item
}

#[test]
fn the_notice_period_expires_strictly_after_the_deadline() {
    harness(|storage, scope, parent| {
        let at = START + 30 * DAY;
        let item = call_bucket(storage, scope, parent, Address::repeat_byte(0x11), at);
        let deadline = at + CALL_NOTICE_PERIOD;

        // Exactly at the deadline the Nod survives.
        finalize_through(storage, deadline);
        assert_eq!(scan(storage, scope, parent, deadline), 0);
        assert!(api::get_item(storage, scope, parent, item.nod_id)
            .unwrap()
            .is_some());

        // One second past it, the Nod is forfeit-burned.
        finalize_through(storage, deadline + 1);
        assert_eq!(scan(storage, scope, parent, deadline + 1), 1);
        assert!(api::get_item(storage, scope, parent, item.nod_id)
            .unwrap()
            .is_none());
    });
}

#[test]
fn forfeiting_the_last_member_drops_the_bucket_from_the_callable_index() {
    harness(|storage, scope, parent| {
        let at = START + 30 * DAY;
        let item = call_bucket(storage, scope, parent, Address::repeat_byte(0x11), at);
        assert_eq!(
            NodContract::new(storage.clone())
                .callable_buckets
                .len()
                .unwrap(),
            1
        );

        let past = at + CALL_NOTICE_PERIOD + 1;
        finalize_through(storage, past);
        assert_eq!(scan(storage, scope, parent, past), 1);

        let nod = NodContract::new(storage.clone());
        assert_eq!(nod.callable_buckets.len().unwrap(), 0);
        assert_eq!(nod.bucket_called_at.read(&item.bucket_key).unwrap(), 0);
        assert_eq!(nod.bucket_nod_count.read(&item.bucket_key).unwrap(), 0);
        assert_eq!(nod.total_supply().unwrap(), 0);
        // The bucket body is gone with its last member.
        let bucket_id = WwdEntityId::from_day_and_digest(item.worldwide_day, item.bucket_key.0);
        assert!(api::get_bucket(storage, scope, parent, bucket_id)
            .unwrap()
            .is_none());
    });
}

// --- Index parity ----------------------------------------------------------

#[test]
fn the_member_index_tracks_the_bucket_body_count() {
    harness(|storage, scope, parent| {
        // Two owners on the same worldwide day share one bucket: identical floor
        // price and currency.
        let a = issue_qualified(storage, scope, parent, Address::repeat_byte(0x11), ISO);
        let b_item = nod_item(Address::repeat_byte(0x22), ISO);
        api::add_nod(storage, scope, parent, &b_item, entry_price()).unwrap();
        assert_eq!(a.bucket_key, b_item.bucket_key, "same bucket");

        let nod = NodContract::new(storage.clone());
        assert_eq!(nod.bucket_nod_count.read(&a.bucket_key).unwrap(), 2);
        let bucket_id = WwdEntityId::from_day_and_digest(a.worldwide_day, a.bucket_key.0);
        assert_eq!(
            api::get_bucket(storage, scope, parent, bucket_id)
                .unwrap()
                .unwrap()
                .total_nods,
            2
        );

        // Removing one keeps both counts in step and clears only its own entry.
        let item = api::load_item(storage, scope, parent, a.nod_id)
            .unwrap()
            .unwrap();
        let bucket = api::load_bucket(storage, scope, parent, bucket_id)
            .unwrap()
            .unwrap();
        api::remove_nod(storage, scope, item, bucket).unwrap();

        let nod = NodContract::new(storage.clone());
        assert_eq!(nod.bucket_nod_count.read(&a.bucket_key).unwrap(), 1);
        assert_eq!(
            api::get_bucket(storage, scope, parent, bucket_id)
                .unwrap()
                .unwrap()
                .total_nods,
            1
        );
        assert_eq!(
            nod.bucket_nod_index.read(&a.nod_id).unwrap(),
            0,
            "the removed Nod's reverse index entry is cleared"
        );
        // The survivor is still reachable at slot 0.
        assert_eq!(
            nod.bucket_nods
                .read(&NodContract::bucket_nod_key(a.bucket_key, 0))
                .unwrap(),
            b_item.nod_id
        );
    });
}

#[test]
fn an_unqualified_bucket_is_never_visited_by_the_call_scan() {
    harness(|storage, scope, parent| {
        let item = nod_item(Address::repeat_byte(0x11), ISO);
        api::add_nod(storage, scope, parent, &item, entry_price()).unwrap();

        let at = START + 30 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );

        assert_eq!(scan(storage, scope, parent, at), 0);
        assert_eq!(called_at(storage, item.bucket_key), 0);
    });
}

#[test]
fn every_member_of_a_lapsed_bucket_burns_in_one_pass() {
    harness(|storage, scope, parent| {
        // Three owners on the same day, floor and currency share one bucket.
        let owners = [0x11u8, 0x22, 0x33].map(Address::repeat_byte);
        let items: Vec<NodItemState> = owners
            .iter()
            .map(|owner| {
                let item = nod_item(*owner, ISO);
                api::add_nod(storage, scope, parent, &item, entry_price()).unwrap();
                item
            })
            .collect();
        let bucket_key = items[0].bucket_key;
        NodContract::new(storage.clone())
            .qualify_bucket(scope, parent, bucket_key)
            .unwrap();

        let at = START + 30 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(scan(storage, scope, parent, at), 1);

        let past = at + CALL_NOTICE_PERIOD + 1;
        finalize_through(storage, past);
        assert_eq!(scan(storage, scope, parent, past), 3, "all three burn");

        for item in &items {
            assert!(
                api::get_item(storage, scope, parent, item.nod_id)
                    .unwrap()
                    .is_none(),
                "nod {} survived the forfeit",
                item.nod_id
            );
        }
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
    });
}

#[test]
fn a_lapsed_bucket_returns_every_forfeited_load_to_the_promis_reserve() {
    harness(|storage, scope, parent| {
        let owners = [0x11u8, 0x22, 0x33].map(Address::repeat_byte);
        let items: Vec<NodItemState> = owners
            .iter()
            .map(|owner| {
                let item = nod_item(*owner, ISO);
                api::add_nod(storage, scope, parent, &item, entry_price()).unwrap();
                item
            })
            .collect();
        let bucket_key = items[0].bucket_key;
        NodContract::new(storage.clone())
            .qualify_bucket(scope, parent, bucket_key)
            .unwrap();

        let at = START + 30 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(scan(storage, scope, parent, at), 1);

        // The call alone forfeits nothing, so nothing is returned yet.
        assert_eq!(reserve(storage), U256::ZERO);

        let past = at + CALL_NOTICE_PERIOD + 1;
        finalize_through(storage, past);
        assert_eq!(scan(storage, scope, parent, past), 3);

        let expected: U256 = items.iter().map(|item| item.gratis_load_minor).sum();
        assert_eq!(reserve(storage), expected);
    });
}

#[test]
fn forfeiting_a_bucket_mid_list_does_not_skip_its_neighbours() {
    harness(|storage, scope, parent| {
        // Three distinct buckets: distinct floor prices on one worldwide day.
        let specs = [
            (Address::repeat_byte(0x11), U256::from(11)),
            (Address::repeat_byte(0x22), U256::from(22)),
            (Address::repeat_byte(0x33), U256::from(33)),
        ];
        let items: Vec<NodItemState> = specs
            .iter()
            .map(|(owner, floor)| {
                let item = nod_item_at(*owner, ISO, *floor);
                api::add_nod(storage, scope, parent, &item, entry_price()).unwrap();
                NodContract::new(storage.clone())
                    .qualify_bucket(scope, parent, item.bucket_key)
                    .unwrap();
                item
            })
            .collect();

        // Call only the middle bucket, by breaching while the others are unarmed.
        // Arming order is issuance order, so index 1 is the middle of the list.
        let at = START + 30 * DAY;
        fill_days(
            storage,
            last_closed_day(at),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        assert_eq!(scan(storage, scope, parent, at), 3, "all three call");

        // Drop the outer two back to uncalled so only the middle one lapses; the
        // pass must still visit the neighbours the swap-pop moves around.
        let nod = NodContract::new(storage.clone());
        nod.bucket_called_at.write(&items[0].bucket_key, 0).unwrap();
        nod.bucket_called_at.write(&items[2].bucket_key, 0).unwrap();

        let past = at + CALL_NOTICE_PERIOD + 1;
        fill_days(
            storage,
            last_closed_day(past),
            CALL_LOOKBACK_DAYS,
            above_call(),
        );
        // One forfeit for the middle bucket plus two fresh calls for the others.
        assert_eq!(scan(storage, scope, parent, past), 3);

        assert!(api::get_item(storage, scope, parent, items[1].nod_id)
            .unwrap()
            .is_none());
        for index in [0usize, 2] {
            assert!(
                api::get_item(storage, scope, parent, items[index].nod_id)
                    .unwrap()
                    .is_some(),
                "neighbour bucket {index} was wrongly burned"
            );
            assert_eq!(
                called_at(storage, items[index].bucket_key),
                past,
                "neighbour bucket {index} was skipped by the pass"
            );
        }
        assert_eq!(
            NodContract::new(storage.clone())
                .callable_buckets
                .len()
                .unwrap(),
            2
        );
    });
}
