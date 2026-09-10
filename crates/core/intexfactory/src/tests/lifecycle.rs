use super::*;

#[test]
fn issue_enrolls_in_floor_bin() {
    with_factory(|s| {
        runtime::issue(&s, sample(7)).unwrap();
        let f = IntexFactoryContract::new(s.clone());
        let bin = IntexFactoryContract::price_to_bin(U256::from(EXPECTED_FLOOR)).unwrap();
        assert_eq!(
            f.unqualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            1
        );
    });
}

#[test]
fn insert_remove_unqualified_roundtrip() {
    with_factory(|s| {
        let mut f = IntexFactoryContract::new(s.clone());
        let floor = U256::from(2_000u64);
        let bin = IntexFactoryContract::price_to_bin(floor).unwrap();
        f.insert_unqualified(sid(11), REFERENCE_ISO, floor).unwrap();
        f.insert_unqualified(sid(22), REFERENCE_ISO, floor).unwrap();
        assert_eq!(
            f.unqualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            2
        );
        f.remove_unqualified_group(REFERENCE_ISO, WorldwideDay::new(11))
            .unwrap();
        assert_eq!(
            f.unqualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            1
        );
        f.remove_unqualified_group(REFERENCE_ISO, WorldwideDay::new(22))
            .unwrap();
        assert_eq!(
            f.unqualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            0
        );
    });
}

#[test]
fn try_qualify_gates_the_floor_and_latches() {
    with_factory(|s| {
        runtime::issue(&s, sample(7)).unwrap();
        let mut f = IntexFactoryContract::new(s.clone());
        let floor = U256::from(EXPECTED_FLOOR);

        // Rate == floor (strict >) -> false.
        assert_eq!(qualify_day(&s, &mut f, 7, floor), 0);
        // Rate > floor -> qualifies, latched, removed from bin.
        assert_eq!(qualify_day(&s, &mut f, 7, floor + U256::from(1)), 1);
        assert_eq!(
            outbe_intex::api::read_series(&s, sid(7))
                .unwrap()
                .lifecycle_state()
                .unwrap(),
            outbe_intex::IntexState::Qualified
        );
        let bin = IntexFactoryContract::price_to_bin(floor).unwrap();
        assert_eq!(
            f.unqualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            0
        );
        // Already Qualified -> false.
        assert_eq!(qualify_day(&s, &mut f, 7, floor + U256::from(1)), 0);
    });
}

pub(super) fn qualify_series<'a>(
    s: &StorageHandle<'a>,
    id: u32,
    params: IssuanceParams,
) -> IntexFactoryContract<'a> {
    runtime::issue(s, params).unwrap();
    let mut f = IntexFactoryContract::new(s.clone());
    let floor = U256::from(EXPECTED_FLOOR);
    assert!(qualify_day(s, &mut f, id, floor + U256::from(1)) == 1);
    f
}

/// Registry index the fixtures register the qualifier pair at; the rate
/// columns are keyed by it.
const PAIR_ID: u32 = 1;

/// List the qualifier currency in the oracle's reference registry, which the
/// scans walk to decide which currencies to price this block.
pub(super) fn list_reference(oracle: &OracleContract) {
    if oracle.reference_currencies.len().unwrap() == 0 {
        oracle.reference_currencies.push(REFERENCE_ISO).unwrap();
    }
}

pub(super) fn setup_pair(oracle: &OracleContract) -> AddressPair {
    let pair = outbe_oracle::api::AddressPair::new_coen_to(REFERENCE_ISO);
    let pair_id = PAIR_ID;
    oracle.pair_to_index.write(&pair, pair_id).unwrap();
    // Full registry entry so the production VWAP paths (calculate_vwaps
    // iterating registered vote-target pairs) see the pair too. `pair_at` reads
    // the reverse column.
    oracle.pair_count.write(pair_id).unwrap();
    oracle.pair_by_index.write_pair(&pair_id, pair).unwrap();
    oracle.vote_target.write(&pair, true).unwrap();
    list_reference(oracle);
    pair
}

fn set_vwap(oracle: &OracleContract, utc_day: u32, pair: AddressPair, value: U256) {
    // The value column is keyed by the pair's registry index.
    let pair_id = oracle.pair_index_of(pair).unwrap();
    oracle
        .utc_day_vwap_value
        .get_nested(&utc_day)
        .write(&pair_id, value)
        .unwrap();
    // Mirror the begin-block hook: the watermark covers every seeded day.
    if oracle.utc_day_vwap_last_finalized.read().unwrap() < utc_day {
        oracle.utc_day_vwap_last_finalized.write(utc_day).unwrap();
    }
}

/// Set `days` consecutive closed UTC days ending at `latest` to `value`.
pub(super) fn fill_days(
    oracle: &OracleContract,
    latest: u32,
    pair: AddressPair,
    days: u32,
    value: U256,
) {
    let mut d = latest;
    for _ in 0..days {
        set_vwap(oracle, d, pair, value);
        d = previous_date_key(d);
    }
}

#[test]
fn qualify_enrolls_in_call_trigger_bin() {
    with_factory(|s| {
        let f = qualify_series(&s, 7, sample(7));
        // Moved out of the floor index, into the call-trigger index.
        let floor_bin = IntexFactoryContract::price_to_bin(U256::from(EXPECTED_FLOOR)).unwrap();
        let trig_bin = IntexFactoryContract::price_to_bin(U256::from(EXPECTED_TRIGGER)).unwrap();
        assert_eq!(
            f.unqualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, floor_bin))
                .unwrap(),
            0
        );
        assert_eq!(
            f.qualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, trig_bin))
                .unwrap(),
            1
        );
    });
}

#[test]
fn insert_remove_qualified_roundtrip() {
    with_factory(|s| {
        let mut f = IntexFactoryContract::new(s.clone());
        let trigger = U256::from(EXPECTED_TRIGGER);
        let bin = IntexFactoryContract::price_to_bin(trigger).unwrap();
        f.insert_qualified_group(REFERENCE_ISO, WorldwideDay::new(11), trigger, &[sid(11)])
            .unwrap();
        f.insert_qualified_group(REFERENCE_ISO, WorldwideDay::new(22), trigger, &[sid(22)])
            .unwrap();
        assert_eq!(
            f.qualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            2
        );
        f.remove_qualified_group(REFERENCE_ISO, WorldwideDay::new(11))
            .unwrap();
        assert_eq!(
            f.qualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            1
        );
        f.remove_qualified_group(REFERENCE_ISO, WorldwideDay::new(22))
            .unwrap();
        assert_eq!(
            f.qualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            0
        );
    });
}

#[test]
fn try_call_marks_called_when_threshold_met() {
    with_factory(|s| {
        let mut f = qualify_series(&s, 7, sample(7));
        let oracle = OracleContract::new(s.clone());
        let pair = setup_pair(&oracle);
        // All 30 window days above the trigger (threshold is 21).
        let scan_ts = ISSUED_AT as u64 + 60 * DAY;
        let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
        let breach = U256::from(EXPECTED_TRIGGER) + U256::from(1);
        fill_days(&oracle, last_closed_day, pair, 30, breach);

        let group = f
            .qualified_group(REFERENCE_ISO, WorldwideDay::new(7))
            .unwrap();
        assert_eq!(
            call_group(&s, &mut f, &oracle, pair, &group, last_closed_day, scan_ts),
            1
        );
        assert_eq!(
            outbe_intex::api::read_series(&s, sid(7))
                .unwrap()
                .lifecycle_state()
                .unwrap(),
            outbe_intex::IntexState::Called
        );
        let bin = IntexFactoryContract::price_to_bin(U256::from(EXPECTED_TRIGGER)).unwrap();
        assert_eq!(
            f.qualified_bin_count
                .read(&IntexFactoryContract::scoped(REFERENCE_ISO, bin))
                .unwrap(),
            0
        );
    });
}

#[test]
fn try_call_skips_when_below_threshold() {
    with_factory(|s| {
        let mut f = qualify_series(&s, 7, sample(7));
        let oracle = OracleContract::new(s.clone());
        let pair = setup_pair(&oracle);
        let scan_ts = ISSUED_AT as u64 + 60 * DAY;
        let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
        let breach = U256::from(EXPECTED_TRIGGER) + U256::from(1);
        let calm = U256::from(EXPECTED_TRIGGER); // equal: strict `>` is not a breach
                                                 // 20 breach days + 10 calm days; threshold is 21.
        let mut d = last_closed_day;
        for _ in 0..20 {
            set_vwap(&oracle, d, pair, breach);
            d = previous_date_key(d);
        }
        for _ in 0..10 {
            set_vwap(&oracle, d, pair, calm);
            d = previous_date_key(d);
        }

        let group = f
            .qualified_group(REFERENCE_ISO, WorldwideDay::new(7))
            .unwrap();
        assert_eq!(
            call_group(&s, &mut f, &oracle, pair, &group, last_closed_day, scan_ts),
            0
        );
        assert_eq!(
            outbe_intex::api::read_series(&s, sid(7))
                .unwrap()
                .lifecycle_state()
                .unwrap(),
            outbe_intex::IntexState::Qualified
        );
    });
}

#[test]
fn try_call_excludes_pre_issuance_days() {
    with_factory(|s| {
        // window 30, threshold 27: only days from issuance onward may count.
        // Seed the series directly with threshold 27 (above the 21d qualification
        // period), since the protocol default (21) does not exceed it and a
        // qualified series would always have >= 21 completed post-issuance days.
        outbe_intex::api::create_series(
            &s,
            outbe_intex::CreateSeriesParams {
                series_id: sid(8),
                worldwide_day: 8.into(),
                issued_intex_count: 100,
                promis_load_minor: PROMIS_LOAD_MINOR,
                entry_price_minor: U256::from(ENTRY_PRICE),
                floor_price_minor: U256::from(EXPECTED_FLOOR),
                call_price_minor: U256::from(EXPECTED_TRIGGER),
                call_trigger: outbe_intex::IntexCallTrigger {
                    call_window: 30 * DAY as u32,
                    call_threshold: 27 * DAY as u32,
                    call_notice_period: CALL_NOTICE_PERIOD,
                },
                issued_at: ISSUED_AT,
                issuance_currency: 840,
                reference_currency: 840,
            },
        )
        .unwrap();
        outbe_intex::api::mark_qualified(&s, sid(8)).unwrap();
        let mut f = IntexFactoryContract::new(s.clone());
        let oracle = OracleContract::new(s.clone());
        let pair = setup_pair(&oracle);
        // Scan only ~23 days after issuance, but set all 30 window days as
        // breaches: the ~7 pre-issuance days must not count, so 23 < 27.
        let scan_ts = ISSUED_AT as u64 + 23 * DAY;
        let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
        let breach = U256::from(EXPECTED_TRIGGER) + U256::from(1);
        fill_days(&oracle, last_closed_day, pair, 30, breach);

        let group = Group {
            iso_code: REFERENCE_ISO,
            worldwide_day: WorldwideDay::new(8),
            members: vec![sid(8)],
        };
        assert_eq!(
            call_group(&s, &mut f, &oracle, pair, &group, last_closed_day, scan_ts),
            0
        );
        assert_eq!(
            outbe_intex::api::read_series(&s, sid(8))
                .unwrap()
                .lifecycle_state()
                .unwrap(),
            outbe_intex::IntexState::Qualified
        );
    });
}

mod call_sweep {
    //! A call sweep too large for one run carries on across blocks, pinned to the
    //! day it opened on.

    use alloy_primitives::U256;
    use outbe_intex::SeriesId;
    use outbe_oracle::api::AddressPair;
    use outbe_oracle::schema::OracleContract;
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::types::Storable;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::time::WorldwideDay;
    use outbe_primitives::time::{previous_date_key, timestamp_to_date_key};

    use crate::called;
    use crate::constants::{MAX_GROUP_DECISIONS_PER_BLOCK, MAX_SERIES_ACTIONS_PER_BLOCK};
    use crate::schema::IntexFactoryContract;

    const CHAIN_ID: u64 = 1;
    const REFERENCE_ISO: u16 = 840;
    const PAIR_ID: u32 = 1;
    const ISSUED_AT: u32 = 1_700_000_000;
    const DAY: u64 = 24 * 60 * 60;
    const TRIGGER: u64 = 1_000_000;
    const WINDOW_DAYS: u32 = 28;

    fn with_factory<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.set_timestamp(U256::from(ISSUED_AT as u64));
        storage.stub_sub_call_at(
            crate::constants::INTEX_NFT1155_ADDRESS,
            alloy_primitives::Bytes::from(vec![0u8; 32]),
        );
        storage.stub_sub_call_at(
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            alloy_primitives::Bytes::from(vec![0u8; 32]),
        );
        StorageHandle::enter(&mut storage, |handle| {
            crate::tests::select_prod_profile(&handle);
            f(handle)
        })
    }

    fn setup_pair(oracle: &OracleContract) -> AddressPair {
        let pair = AddressPair::new_coen_to(REFERENCE_ISO);
        oracle.pair_to_index.write(&pair, PAIR_ID).unwrap();
        oracle.pair_count.write(PAIR_ID).unwrap();
        oracle.pair_by_index.write_pair(&PAIR_ID, pair).unwrap();
        oracle.vote_target.write(&pair, true).unwrap();
        oracle.reference_currencies.push(REFERENCE_ISO).unwrap();
        pair
    }

    fn set_vwap(oracle: &OracleContract, utc_day: u32, pair: AddressPair, value: U256) {
        let pair_id = oracle.pair_index_of(pair).unwrap();
        oracle
            .utc_day_vwap_value
            .get_nested(&utc_day)
            .write(&pair_id, value)
            .unwrap();
        if oracle.utc_day_vwap_last_finalized.read().unwrap() < utc_day {
            oracle.utc_day_vwap_last_finalized.write(utc_day).unwrap();
        }
    }

    fn fill_window(oracle: &OracleContract, latest: u32, pair: AddressPair, value: U256) {
        let mut day = latest;
        for _ in 0..WINDOW_DAYS {
            set_vwap(oracle, day, pair, value);
            day = previous_date_key(day);
        }
    }

    fn seed_called_candidate(s: &StorageHandle<'_>, worldwide_day: u32) {
        seed_candidate_at(s, worldwide_day, ISSUED_AT, TRIGGER)
    }

    fn seed_young_candidate_at(
        s: &StorageHandle<'_>,
        worldwide_day: u32,
        issued_at: u32,
        trigger: u64,
    ) {
        seed_candidate_at(s, worldwide_day, issued_at, trigger)
    }

    /// A Qualified series of its own day, carrying `trigger` as its call price.
    fn seed_candidate_at(
        s: &StorageHandle<'_>,
        worldwide_day: u32,
        issued_at: u32,
        trigger_minor: u64,
    ) {
        let series_id =
            SeriesId::for_pair(WorldwideDay::new(worldwide_day), 840, REFERENCE_ISO).unwrap();
        let trigger = U256::from(trigger_minor);
        outbe_intex::api::create_series(
            s,
            outbe_intex::CreateSeriesParams {
                series_id,
                worldwide_day: WorldwideDay::new(worldwide_day),
                issued_intex_count: 100,
                promis_load_minor: 1_000_000_000_000_000_000,
                entry_price_minor: trigger,
                floor_price_minor: trigger,
                call_price_minor: trigger,
                call_trigger: outbe_intex::IntexCallTrigger {
                    call_window: WINDOW_DAYS * DAY as u32,
                    call_threshold: 21 * DAY as u32,
                    call_notice_period: 7 * DAY as u32,
                },
                issued_at,
                issuance_currency: 840,
                reference_currency: REFERENCE_ISO,
            },
        )
        .unwrap();
        outbe_intex::api::mark_qualified(s, series_id).unwrap();
        IntexFactoryContract::new(s.clone())
            .insert_qualified_group(
                REFERENCE_ISO,
                WorldwideDay::new(worldwide_day),
                trigger,
                &[series_id],
            )
            .unwrap();
    }

    fn called_count(s: &StorageHandle<'_>, days: std::ops::Range<u32>) -> u32 {
        days.filter(|d| {
            let series_id = SeriesId::for_pair(WorldwideDay::new(*d), 840, REFERENCE_ISO).unwrap();
            outbe_intex::api::read_series(s, series_id)
                .unwrap()
                .lifecycle_state()
                .unwrap()
                == outbe_intex::IntexState::Called
        })
        .count() as u32
    }

    #[test]
    fn a_called_group_is_parked_with_its_members_and_call_time() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER + 1));
            seed_called_candidate(&s, 20260101);

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(called::scan_and_call(&ctx).unwrap(), 1);

            let factory = IntexFactoryContract::new(s.clone());
            let day = WorldwideDay::new(20260101);
            let key = IntexFactoryContract::scoped(REFERENCE_ISO, day.value());

            // The price index has dropped the group, and the parked copy is the
            // only way back to the series it held.
            assert!(factory
                .qualified_group_members(REFERENCE_ISO, day)
                .unwrap()
                .is_empty());
            let bucket = IntexFactoryContract::deadline_bucket(scan_ts + 7 * DAY);
            assert_eq!(
                factory
                    .expiry_bucket_at
                    .read(&IntexFactoryContract::bucket_slot_key(bucket, 0))
                    .unwrap(),
                key
            );
            assert_eq!(factory.expiry_bucket_live.read(&bucket).unwrap(), 1);
            assert_eq!(factory.called_group_count.read(&key).unwrap(), 1);
            assert_eq!(
                factory.called_group_deadline.read(&key).unwrap(),
                scan_ts + 7 * DAY
            );
            assert_eq!(
                SeriesId::from_word(
                    factory
                        .called_group_members
                        .read(&IntexFactoryContract::group_member_key(
                            REFERENCE_ISO,
                            day,
                            0
                        ))
                        .unwrap()
                ),
                SeriesId::for_pair(day, 840, REFERENCE_ISO).unwrap()
            );
        });
    }

    /// Drive `worldwide_day` to Called at `scan_ts` and return the deadline its
    /// group now carries.
    fn call_and_deadline(s: &StorageHandle<'_>, worldwide_day: u32, scan_ts: u64) -> u64 {
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
            s.clone(),
        );
        called::scan_and_call(&ctx).unwrap();
        IntexFactoryContract::new(s.clone())
            .called_group_deadline
            .read(&IntexFactoryContract::scoped(REFERENCE_ISO, worldwide_day))
            .unwrap()
    }

    /// First instant a group with this deadline can be retired: the sweep works a
    /// deadline day only once that day has closed.
    fn due(deadline: u64) -> u64 {
        IntexFactoryContract::bucket_end(IntexFactoryContract::deadline_bucket(deadline))
    }

    fn sweep_at(s: &StorageHandle<'_>, now: u64) {
        let ctx =
            BlockRuntimeContext::new(BlockContext::empty_for_tests(2, now, CHAIN_ID), s.clone());
        crate::expired::sweep_expiry_deadlines(&ctx).unwrap();
    }

    fn unallocated(s: &StorageHandle<'_>) -> U256 {
        outbe_promislimit::PromisLimitContract::new(s.clone())
            .get_total_unallocated()
            .unwrap()
    }

    fn priced_window(s: &StorageHandle<'_>, scan_ts: u64) {
        let oracle = OracleContract::new(s.clone());
        let pair = setup_pair(&oracle);
        let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
        fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER + 1));
    }

    /// The one place an off-by-one costs capacity twice: settlement is legal at
    /// the deadline itself (`settle_rejects_expired_deadline` pins that side), and
    /// a block hook runs before the block's transactions, so the sweep must wait
    /// for the tick after it.
    #[test]
    fn the_sweep_waits_until_settlement_has_actually_closed() {
        with_factory(|s| {
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            priced_window(&s, scan_ts);
            seed_called_candidate(&s, 20260101);
            let deadline = call_and_deadline(&s, 20260101, scan_ts);

            sweep_at(&s, deadline);
            assert_eq!(unallocated(&s), U256::ZERO, "still settleable");
            assert_eq!(
                outbe_intex::api::read_series(
                    &s,
                    SeriesId::for_pair(WorldwideDay::new(20260101), 840, REFERENCE_ISO).unwrap()
                )
                .unwrap()
                .lifecycle_state()
                .unwrap(),
                outbe_intex::IntexState::Called
            );

            sweep_at(&s, due(deadline));
            assert_eq!(
                unallocated(&s),
                U256::from(100u64) * U256::from(1_000_000_000_000_000_000u128)
            );
        });
    }

    #[test]
    fn expiry_returns_only_the_load_nobody_realized() {
        with_factory(|s| {
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            priced_window(&s, scan_ts);
            seed_called_candidate(&s, 20260101);
            let series_id =
                SeriesId::for_pair(WorldwideDay::new(20260101), 840, REFERENCE_ISO).unwrap();
            outbe_intex::api::record_settled_units(&s, series_id, 30).unwrap();
            outbe_intex::api::record_parked_units(&s, series_id, 25).unwrap();

            let deadline = call_and_deadline(&s, 20260101, scan_ts);
            sweep_at(&s, due(deadline));

            assert_eq!(
                unallocated(&s),
                U256::from(45u64) * U256::from(1_000_000_000_000_000_000u128)
            );
        });
    }

    /// A day's group holds one series per issuance currency, and the credit is
    /// written once for the whole group - so the total has to be the sum over its
    /// members, with neither double-counted nor dropped.
    #[test]
    fn a_group_credits_every_member_exactly_once() {
        with_factory(|s| {
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            priced_window(&s, scan_ts);

            let day = WorldwideDay::new(20260101);
            let trigger = U256::from(TRIGGER);
            let mut members = Vec::new();
            for (issuance, count) in [(840u16, 100u32), (978u16, 40u32)] {
                let series_id = SeriesId::for_pair(day, issuance, REFERENCE_ISO).unwrap();
                let params = outbe_intex::CreateSeriesParams {
                    series_id,
                    worldwide_day: day,
                    issued_intex_count: count,
                    promis_load_minor: 1_000_000_000_000_000_000,
                    entry_price_minor: trigger,
                    floor_price_minor: trigger,
                    call_price_minor: trigger,
                    call_trigger: outbe_intex::IntexCallTrigger {
                        call_window: WINDOW_DAYS * DAY as u32,
                        call_threshold: 21 * DAY as u32,
                        call_notice_period: 7 * DAY as u32,
                    },
                    issued_at: ISSUED_AT,
                    issuance_currency: issuance,
                    reference_currency: REFERENCE_ISO,
                };
                outbe_intex::api::create_series(&s, params).unwrap();
                outbe_intex::api::mark_qualified(&s, series_id).unwrap();
                members.push(series_id);
            }
            IntexFactoryContract::new(s.clone())
                .insert_qualified_group(REFERENCE_ISO, day, trigger, &members)
                .unwrap();

            let deadline = call_and_deadline(&s, 20260101, scan_ts);
            sweep_at(&s, due(deadline));

            assert_eq!(
                unallocated(&s),
                U256::from(140u64) * U256::from(1_000_000_000_000_000_000u128)
            );
            for series_id in members {
                assert_eq!(
                    outbe_intex::api::read_series(&s, series_id)
                        .unwrap()
                        .lifecycle_state()
                        .unwrap(),
                    outbe_intex::IntexState::Expired
                );
            }
        });
    }

    #[test]
    fn a_second_pass_over_an_expired_group_credits_nothing() {
        with_factory(|s| {
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            priced_window(&s, scan_ts);
            seed_called_candidate(&s, 20260101);
            let deadline = call_and_deadline(&s, 20260101, scan_ts);

            sweep_at(&s, due(deadline));
            let after_first = unallocated(&s);
            sweep_at(&s, due(deadline) + 1);
            assert_eq!(unallocated(&s), after_first);

            // The bucket emptied, so its day left the tree rather than being handed
            // back every block.
            let factory = IntexFactoryContract::new(s.clone());
            assert_eq!(factory.first_expiry_day().unwrap(), None);
        });
    }

    #[test]
    fn a_backlog_larger_than_one_block_drains_over_the_next_ones() {
        with_factory(|s| {
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            priced_window(&s, scan_ts);
            // One series per group, so the action budget bounds the groups taken.
            let groups = MAX_SERIES_ACTIONS_PER_BLOCK + MAX_SERIES_ACTIONS_PER_BLOCK / 2;
            for day in 20260101..20260101 + groups {
                seed_called_candidate(&s, day);
            }
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            while called::run_call_slice(&ctx).unwrap() > 0 {}
            called::scan_and_call(&ctx).unwrap();
            while called::run_call_slice(&ctx).unwrap() > 0 {}

            let deadline = scan_ts + 7 * DAY;
            let per_group = U256::from(100u64) * U256::from(1_000_000_000_000_000_000u128);

            sweep_at(&s, due(deadline));
            assert_eq!(
                unallocated(&s),
                per_group * U256::from(MAX_SERIES_ACTIONS_PER_BLOCK)
            );

            sweep_at(&s, due(deadline) + 1);
            assert_eq!(unallocated(&s), per_group * U256::from(groups));
        });
    }

    #[test]
    fn a_sweep_wider_than_one_run_finishes_over_the_next_blocks() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            // Every window day above the trigger: all of them are due a call.
            fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER + 1));

            // One group per day, half again as many as one slice may move.
            let groups = MAX_SERIES_ACTIONS_PER_BLOCK + MAX_SERIES_ACTIONS_PER_BLOCK / 2;
            let days = 20260101..20260101 + groups;
            for day in days.clone() {
                seed_called_candidate(&s, day);
            }

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );

            // The daily trigger opens the sweep and takes what it can.
            let first = called::scan_and_call(&ctx).unwrap();
            assert_eq!(first, MAX_SERIES_ACTIONS_PER_BLOCK);
            assert_ne!(
                IntexFactoryContract::new(s.clone())
                    .call_sweep_day
                    .read()
                    .unwrap(),
                0,
                "the sweep stays open"
            );

            // The next block's slice finishes it and closes the sweep.
            let second = called::run_call_slice(&ctx).unwrap();
            assert_eq!(first + second, groups);
            assert_eq!(called_count(&s, days), groups);
            assert_eq!(
                IntexFactoryContract::new(s.clone())
                    .call_sweep_day
                    .read()
                    .unwrap(),
                0,
                "the sweep closed"
            );
        });
    }

    /// A window whose breaches sit at its old end: it holds exactly the threshold
    /// on `latest`, and one day later the oldest breach has aged out of it.
    fn fill_expiring_window(oracle: &OracleContract, latest: u32, pair: AddressPair) {
        let breach = U256::from(TRIGGER + 1);
        let quiet = U256::from(TRIGGER);
        let mut day = latest;
        for _ in 0..WINDOW_DAYS - 21 {
            set_vwap(oracle, day, pair, quiet);
            day = previous_date_key(day);
        }
        for _ in 0..21 {
            set_vwap(oracle, day, pair, breach);
            day = previous_date_key(day);
        }
    }

    #[test]
    fn a_sweep_that_runs_past_midnight_keeps_deciding_against_its_own_day() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let opened_on = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_expiring_window(&oracle, opened_on, pair);
            // The day the sweep spills into is quiet, so the window it would see has
            // one breach fewer than the threshold.
            set_vwap(
                &oracle,
                timestamp_to_date_key(scan_ts),
                pair,
                U256::from(TRIGGER),
            );

            let groups = MAX_SERIES_ACTIONS_PER_BLOCK + 1;
            let days = 20260101..20260101 + groups;
            for day in days.clone() {
                seed_called_candidate(&s, day);
            }

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(
                called::scan_and_call(&ctx).unwrap(),
                MAX_SERIES_ACTIONS_PER_BLOCK
            );

            // The next slice lands after midnight. Pinned to the day it opened on,
            // the sweep finishes on the terms it started with.
            let next_day = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(2, scan_ts + DAY, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(called::run_call_slice(&next_day).unwrap(), 1);
            assert_eq!(called_count(&s, days), groups);
        });
    }

    /// The control for the test above: opened a day later, the same window has
    /// aged one breach out and calls nothing.
    #[test]
    fn a_sweep_opened_a_day_later_sees_the_window_expire() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let opened_on = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_expiring_window(&oracle, opened_on, pair);
            set_vwap(
                &oracle,
                timestamp_to_date_key(scan_ts),
                pair,
                U256::from(TRIGGER),
            );
            seed_called_candidate(&s, 20260101);

            let next_day = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts + DAY, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(called::scan_and_call(&next_day).unwrap(), 0);
            assert_eq!(called_count(&s, 20260101..20260102), 0);
        });
    }

    #[test]
    fn a_slice_without_an_open_sweep_does_nothing() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER + 1));
            seed_called_candidate(&s, 20260101);

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            // No trigger has opened one, so the block hook leaves the group alone.
            assert_eq!(called::run_call_slice(&ctx).unwrap(), 0);
            assert_eq!(called_count(&s, 20260101..20260102), 0);
        });
    }

    #[test]
    fn a_sweep_that_fits_in_one_run_closes_at_once() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER + 1));
            for day in 20260101..20260105 {
                seed_called_candidate(&s, day);
            }

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(called::scan_and_call(&ctx).unwrap(), 4);
            assert_eq!(
                IntexFactoryContract::new(s.clone())
                    .call_sweep_day
                    .read()
                    .unwrap(),
                0
            );
        });
    }

    /// A young series: issued inside the window, so its truncated window cannot hold
    /// the threshold however loud the days were.
    fn seed_young_candidate(s: &StorageHandle<'_>, worldwide_day: u32, issued_at: u32) {
        let series_id =
            SeriesId::for_pair(WorldwideDay::new(worldwide_day), 840, REFERENCE_ISO).unwrap();
        let trigger = U256::from(TRIGGER);
        outbe_intex::api::create_series(
            s,
            outbe_intex::CreateSeriesParams {
                series_id,
                worldwide_day: WorldwideDay::new(worldwide_day),
                issued_intex_count: 100,
                promis_load_minor: 1_000_000_000_000_000_000,
                entry_price_minor: trigger,
                floor_price_minor: trigger,
                call_price_minor: trigger,
                call_trigger: outbe_intex::IntexCallTrigger {
                    call_window: WINDOW_DAYS * DAY as u32,
                    call_threshold: 21 * DAY as u32,
                    call_notice_period: 7 * DAY as u32,
                },
                issued_at,
                issuance_currency: 840,
                reference_currency: REFERENCE_ISO,
            },
        )
        .unwrap();
        outbe_intex::api::mark_qualified(s, series_id).unwrap();
        IntexFactoryContract::new(s.clone())
            .insert_qualified_group(
                REFERENCE_ISO,
                WorldwideDay::new(worldwide_day),
                trigger,
                &[series_id],
            )
            .unwrap();
    }

    /// Nothing shrinks a bin whose groups all decide against a move, so the sweep has
    /// to walk past it rather than restart on them forever.
    #[test]
    fn a_bin_of_undecided_groups_does_not_stall_the_sweep() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER + 1));

            // All issued five days ago: every one is visited, decided, and left alone.
            let young_at = (scan_ts - 5 * DAY) as u32;
            let groups = MAX_GROUP_DECISIONS_PER_BLOCK + 1;
            for day in 20260101..20260101 + groups {
                seed_young_candidate(&s, day, young_at);
            }

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(
                called::scan_and_call(&ctx).unwrap(),
                0,
                "none is due a call"
            );

            // The next slices must reach the end of the range and close the sweep.
            for _ in 0..4 {
                called::run_call_slice(&ctx).unwrap();
            }
            assert_eq!(
                IntexFactoryContract::new(s.clone())
                    .call_sweep_day
                    .read()
                    .unwrap(),
                0,
                "the sweep closed instead of restarting on the same groups"
            );
        });
    }

    /// A price the bin ladder cannot hold skips its currency instead of halting the
    /// block - the scan runs in `begin_block`, where an error is not survivable.
    #[test]
    fn a_window_price_out_of_range_skips_the_currency() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            // Priced days enough to reach the threshold, at a price no bin covers.
            fill_window(&oracle, last_closed_day, pair, U256::MAX);
            seed_called_candidate(&s, 20260101);

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(called::scan_and_call(&ctx).unwrap(), 0, "nothing is called");
            assert_eq!(called_count(&s, 20260101..20260102), 0);
            assert_eq!(
                IntexFactoryContract::new(s.clone())
                    .call_sweep_day
                    .read()
                    .unwrap(),
                0,
                "the sweep closed rather than retrying a currency it cannot price"
            );
        });
    }

    /// A group the previous sweep left behind its cursor has to be walked again when
    /// the next day opens, or a day's worth of calls is skipped in silence.
    #[test]
    fn a_new_sweep_walks_the_bins_the_last_one_stopped_above() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_window(&oracle, last_closed_day, pair, U256::from(TRIGGER * 4));

            // Below the budget-stop: issued inside the window, so it decides against a
            // call today however loud the days were.
            let young = 20260001;
            seed_young_candidate_at(&s, young, (scan_ts - 5 * DAY) as u32, TRIGGER);
            // Above it: enough mature groups at a higher trigger to spend every action.
            for day in 20260101..20260101 + MAX_SERIES_ACTIONS_PER_BLOCK + 1 {
                seed_candidate_at(&s, day, ISSUED_AT, TRIGGER * 2);
            }

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            assert_eq!(
                called::scan_and_call(&ctx).unwrap(),
                MAX_SERIES_ACTIONS_PER_BLOCK,
                "the slice stops on its action budget"
            );
            assert_ne!(
                IntexFactoryContract::new(s.clone())
                    .call_scan_cursor
                    .read(&REFERENCE_ISO)
                    .unwrap(),
                0,
                "the cursor stands above the young group's bin"
            );

            // Twenty days on, the young group's own window reaches the threshold. The
            // day's trigger has to find it, which it only does from a reset cursor.
            let later_ts = scan_ts + 20 * DAY;
            let later_day = previous_date_key(timestamp_to_date_key(later_ts));
            fill_window(&oracle, later_day, pair, U256::from(TRIGGER * 4));
            let later = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(2, later_ts, CHAIN_ID),
                s.clone(),
            );
            called::scan_and_call(&later).unwrap();
            for _ in 0..4 {
                called::run_call_slice(&later).unwrap();
            }

            assert_eq!(
                called_count(&s, young..young + 1),
                1,
                "the group below the old cursor was called"
            );
        });
    }

    const SECOND_ISO: u16 = 978;
    const SECOND_PAIR_ID: u32 = 2;

    fn setup_second_pair(oracle: &OracleContract) -> AddressPair {
        let pair = AddressPair::new_coen_to(SECOND_ISO);
        oracle.pair_to_index.write(&pair, SECOND_PAIR_ID).unwrap();
        oracle.pair_count.write(SECOND_PAIR_ID).unwrap();
        oracle
            .pair_by_index
            .write_pair(&SECOND_PAIR_ID, pair)
            .unwrap();
        oracle.vote_target.write(&pair, true).unwrap();
        oracle.reference_currencies.push(SECOND_ISO).unwrap();
        pair
    }

    /// Seeds one callable group of `iso`, priced so its trigger sits under the window.
    fn seed_candidate_for(s: &StorageHandle<'_>, iso: u16, worldwide_day: u32) {
        let series_id = SeriesId::for_pair(WorldwideDay::new(worldwide_day), 840, iso).unwrap();
        let trigger = U256::from(TRIGGER);
        outbe_intex::api::create_series(
            s,
            outbe_intex::CreateSeriesParams {
                series_id,
                worldwide_day: WorldwideDay::new(worldwide_day),
                issued_intex_count: 100,
                promis_load_minor: 1_000_000_000_000_000_000,
                entry_price_minor: trigger,
                floor_price_minor: trigger,
                call_price_minor: trigger,
                call_trigger: outbe_intex::IntexCallTrigger {
                    call_window: WINDOW_DAYS * DAY as u32,
                    call_threshold: 21 * DAY as u32,
                    call_notice_period: 7 * DAY as u32,
                },
                issued_at: ISSUED_AT,
                issuance_currency: 840,
                reference_currency: iso,
            },
        )
        .unwrap();
        outbe_intex::api::mark_qualified(s, series_id).unwrap();
        IntexFactoryContract::new(s.clone())
            .insert_qualified_group(iso, WorldwideDay::new(worldwide_day), trigger, &[series_id])
            .unwrap();
    }

    /// A budget that gives out inside the last currency of the rotation must resume
    /// there, not back at the first: the ones already closed would eat the next
    /// slice's allowance before it ever reached the one that was cut off.
    #[test]
    fn a_slice_resumes_at_the_currency_it_gave_out_on() {
        with_factory(|s| {
            let oracle = OracleContract::new(s.clone());
            let first = setup_pair(&oracle);
            let second = setup_second_pair(&oracle);
            let scan_ts = ISSUED_AT as u64 + 60 * DAY;
            let last_closed_day = previous_date_key(timestamp_to_date_key(scan_ts));
            fill_window(&oracle, last_closed_day, first, U256::from(TRIGGER + 1));
            fill_window(&oracle, last_closed_day, second, U256::from(TRIGGER + 1));

            // The first currency is small; the second holds more than one slice can move.
            seed_candidate_for(&s, REFERENCE_ISO, 20260101);
            for day in 20260201..20260201 + MAX_SERIES_ACTIONS_PER_BLOCK + 1 {
                seed_candidate_for(&s, SECOND_ISO, day);
            }

            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, scan_ts, CHAIN_ID),
                s.clone(),
            );
            called::scan_and_call(&ctx).unwrap();

            // The rotation is [840, 978]; it gave out on the last one, so that is where
            // the cursor stands.
            assert_eq!(
                IntexFactoryContract::new(s.clone())
                    .call_currency_cursor
                    .read()
                    .unwrap(),
                u32::from(SECOND_ISO),
                "the cursor points at the currency that did not finish"
            );
        });
    }
}

mod called_pstar {
    //! `trigger < p_star` and "breached on at least `threshold` days" are the same
    //! statement; these check that they stay the same statement.

    use alloy_primitives::U256;
    use outbe_intex::SeriesId;
    use outbe_oracle::api::AddressPair;
    use outbe_oracle::schema::OracleContract;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::time::previous_date_key;
    use outbe_primitives::time::WorldwideDay;

    use crate::called::{self, DayVwaps};
    use crate::schema::IntexFactoryContract;
    use crate::state::Group;

    const CHAIN_ID: u64 = 1;
    const REFERENCE_ISO: u16 = 840;
    const PAIR_ID: u32 = 1;
    const LAST_DAY: u32 = 20260212;
    const WINDOW: u32 = 28;
    const THRESHOLD: u32 = 21;
    const ISSUED_AT: u32 = 1_700_000_000;
    const DAY_SECS: u64 = 24 * 60 * 60;

    fn with_oracle<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.set_timestamp(U256::from(ISSUED_AT as u64));
        storage.stub_sub_call_at(
            crate::constants::INTEX_NFT1155_ADDRESS,
            alloy_primitives::Bytes::from(vec![0u8; 32]),
        );
        storage.stub_sub_call_at(
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            alloy_primitives::Bytes::from(vec![0u8; 32]),
        );
        StorageHandle::enter(&mut storage, |handle| {
            crate::tests::select_prod_profile(&handle);
            f(handle)
        })
    }

    fn setup_pair(oracle: &OracleContract) -> AddressPair {
        let pair = AddressPair::new_coen_to(REFERENCE_ISO);
        oracle.pair_to_index.write(&pair, PAIR_ID).unwrap();
        oracle.pair_count.write(PAIR_ID).unwrap();
        oracle.pair_by_index.write_pair(&PAIR_ID, pair).unwrap();
        oracle.vote_target.write(&pair, true).unwrap();
        oracle.reference_currencies.push(REFERENCE_ISO).unwrap();
        pair
    }

    fn set_vwap(oracle: &OracleContract, utc_day: u32, pair: AddressPair, value: U256) {
        let pair_id = oracle.pair_index_of(pair).unwrap();
        oracle
            .utc_day_vwap_value
            .get_nested(&utc_day)
            .write(&pair_id, value)
            .unwrap();
        if oracle.utc_day_vwap_last_finalized.read().unwrap() < utc_day {
            oracle.utc_day_vwap_last_finalized.write(utc_day).unwrap();
        }
    }

    /// Write one window's days, latest first. `None` leaves the day unpriced.
    fn seed_window(oracle: &OracleContract, pair: AddressPair, days: &[Option<u64>]) {
        let mut day = LAST_DAY;
        for value in days {
            if let Some(v) = value {
                set_vwap(oracle, day, pair, U256::from(*v));
            }
            day = previous_date_key(day);
        }
    }

    /// The decision as specified: count the days whose VWAP exceeded the trigger.
    fn breaches_at_least(days: &[Option<u64>], trigger: u64, threshold: u32) -> bool {
        days.iter()
            .flatten()
            .filter(|value| **value > trigger)
            .count() as u32
            >= threshold
    }

    /// The decision as the scan takes it: one comparison against the window price.
    fn called_by_p_star(oracle: &OracleContract, pair: AddressPair, trigger: u64) -> bool {
        let mut vwaps = DayVwaps::new(oracle.pair_index_of(pair).unwrap());
        match called::call_window(oracle, &mut vwaps, LAST_DAY, WINDOW, THRESHOLD).unwrap() {
            Some(window) => U256::from(trigger) < window.p_star,
            // Too few priced days for any trigger to reach the threshold.
            None => false,
        }
    }

    /// Window shapes worth disagreeing on: unpriced days, zeros, ties, all-quiet,
    /// all-breach, and a run of breaches that has since ended.
    fn windows() -> Vec<Vec<Option<u64>>> {
        let quiet = |n: usize| vec![Some(100u64); n];
        let loud = |n: usize| vec![Some(300u64); n];
        let mut cases = vec![
            quiet(28),
            loud(28),
            [loud(21), quiet(7)].concat(),
            [loud(20), quiet(8)].concat(),
            [quiet(7), loud(21)].concat(),
            [quiet(3), loud(25)].concat(),
            [loud(14), vec![None; 7], loud(7)].concat(),
            [loud(21), vec![Some(0); 7]].concat(),
            [vec![Some(0); 21], loud(7)].concat(),
            vec![None; 28],
            [loud(20), vec![None; 8]].concat(),
            [loud(21), vec![None; 7]].concat(),
        ];
        // A window where every day differs: P* must pick the 21st largest exactly.
        cases.push((0..28).map(|i| Some(100 + i as u64 * 10)).collect());
        cases
    }

    #[test]
    fn the_window_price_decides_exactly_what_the_walk_decides() {
        for (case, days) in windows().into_iter().enumerate() {
            with_oracle(|s| {
                let oracle = OracleContract::new(s.clone());
                let pair = setup_pair(&oracle);
                seed_window(&oracle, pair, &days);

                for trigger in [0u64, 99, 100, 101, 150, 199, 200, 299, 300, 301, 400] {
                    assert_eq!(
                        called_by_p_star(&oracle, pair, trigger),
                        breaches_at_least(&days, trigger, THRESHOLD),
                        "case {case}, trigger {trigger}, days {days:?}"
                    );
                }
            });
        }
    }

    #[test]
    fn a_window_with_too_few_priced_days_calls_nothing() {
        with_oracle(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            // 20 priced days against a threshold of 21: no trigger can reach it.
            seed_window(
                &oracle,
                pair,
                &[vec![Some(300u64); 20], vec![None; 8]].concat(),
            );

            let mut vwaps = DayVwaps::new(oracle.pair_index_of(pair).unwrap());
            assert!(
                called::call_window(&oracle, &mut vwaps, LAST_DAY, WINDOW, THRESHOLD)
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn a_trigger_equal_to_the_window_price_is_not_breached() {
        with_oracle(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            seed_window(&oracle, pair, &vec![Some(300u64); 28]);

            // Strictly below calls; equal does not.
            assert!(called_by_p_star(&oracle, pair, 299));
            assert!(!called_by_p_star(&oracle, pair, 300));
        });
    }

    /// Candidates used to come from the bins under yesterday's price, so a series that
    /// had breached enough went unseen once the price dipped. P* is blind to the dip.
    #[test]
    fn a_group_still_calls_after_the_price_falls_back_under_its_trigger() {
        with_oracle(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            // 24 breach days, then three quiet ones - including the last closed day.
            seed_window(
                &oracle,
                pair,
                &[vec![Some(100u64); 3], vec![Some(300u64); 25]].concat(),
            );

            assert!(called_by_p_star(&oracle, pair, 200));
        });
    }

    #[test]
    fn a_group_issued_inside_the_window_counts_only_its_own_days() {
        with_oracle(|s| {
            let oracle = OracleContract::new(s.clone());
            let pair = setup_pair(&oracle);
            seed_window(&oracle, pair, &vec![Some(300u64); 28]);

            // Issued 10 days before the window's last day: only those days count, so
            // it cannot reach a threshold of 21 however loud they were.
            let issued_at = day_start(LAST_DAY) - 10 * DAY_SECS;
            let series = seed_qualified(&s, issued_at as u32, U256::from(200u64));

            let mut f = IntexFactoryContract::new(s.clone());
            let mut vwaps = DayVwaps::new(oracle.pair_index_of(pair).unwrap());
            let window = called::call_window(&oracle, &mut vwaps, LAST_DAY, WINDOW, THRESHOLD)
                .unwrap()
                .unwrap();
            let group = Group {
                iso_code: REFERENCE_ISO,
                worldwide_day: series.worldwide_day(),
                members: vec![series],
            };
            assert_eq!(
                called::try_call_group(
                    &s,
                    &mut f,
                    &oracle,
                    &mut vwaps,
                    &group,
                    &window,
                    day_start(LAST_DAY) + DAY_SECS
                )
                .unwrap(),
                0
            );
        });
    }

    fn day_start(date_key: u32) -> u64 {
        outbe_primitives::time::date_key_to_utc_timestamp(date_key)
    }

    /// A Qualified series with the protocol call parameters and the given trigger.
    fn seed_qualified(s: &StorageHandle<'_>, issued_at: u32, trigger: U256) -> SeriesId {
        let series_id =
            SeriesId::for_pair(WorldwideDay::new(LAST_DAY), 840, REFERENCE_ISO).unwrap();
        outbe_intex::api::create_series(
            s,
            outbe_intex::CreateSeriesParams {
                series_id,
                worldwide_day: WorldwideDay::new(LAST_DAY),
                issued_intex_count: 100,
                promis_load_minor: 1_000_000_000_000_000_000,
                entry_price_minor: trigger,
                floor_price_minor: trigger,
                call_price_minor: trigger,
                call_trigger: outbe_intex::IntexCallTrigger {
                    call_window: WINDOW * DAY_SECS as u32,
                    call_threshold: THRESHOLD * DAY_SECS as u32,
                    call_notice_period: 7 * DAY_SECS as u32,
                },
                issued_at,
                issuance_currency: 840,
                reference_currency: REFERENCE_ISO,
            },
        )
        .unwrap();
        outbe_intex::api::mark_qualified(s, series_id).unwrap();
        series_id
    }
}
