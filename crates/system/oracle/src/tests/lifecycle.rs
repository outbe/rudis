//! Lifecycle tests: tally, begin-block hooks, slash window, OCOMP atomicity.

use alloy_primitives::{Address, U256};
use outbe_primitives::block::{BlockContext, BlockLifecycle, BlockRuntimeContext};
use outbe_primitives::storage::StorageHandle;
use outbe_validatorset::ValidatorLifecycle;

use crate::schema::{OracleContract, SCALE_1E18};

use super::common::*;

#[test]
fn ocomp_pre_admission_selects_stored_price_and_reads_bounded_counts() {
    let timestamp = 1_753_315_200_u64;
    with_storage_at(timestamp, |storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();
        let wwd = outbe_primitives::time::WorldwideDay::from_timestamp(timestamp);
        let last_closed = outbe_primitives::time::previous_date_key(
            outbe_primitives::time::timestamp_to_date_key(timestamp),
        );
        let last_closed_start = outbe_primitives::time::date_key_to_utc_timestamp(last_closed);
        let last_closed_price = coen_iso(125);

        let uninitialized =
            crate::api::ocomp_pre_admission_projection(storage.clone(), timestamp).unwrap();
        assert!(!uninitialized.profile_ready);
        assert_eq!(uninitialized.oracle_state_version, 0);

        crate::api::initialize_fresh_ocomp_profile(storage.clone()).unwrap();
        let forming_start = wwd.start_timestamp();
        oracle
            .write_snapshot(
                forming_start + 100,
                &[(pair_key(COEN, usd()), last_closed_price, coen_iso(1))],
            )
            .unwrap();
        oracle
            .store_worldwide_day_vwap_snapshot(wwd, forming_start, forming_start + 50 * 60 * 60)
            .unwrap();
        oracle.finalize_utc_day_vwap(last_closed).unwrap();
        crate::scurve::store_scurve_entry(
            &mut oracle,
            pair_key(COEN, usd()),
            last_closed_start,
            coen_iso(200),
        )
        .unwrap();

        let registered_pairs = oracle.pair_count.read().unwrap();
        let closed =
            crate::api::ocomp_pre_admission_projection(storage.clone(), timestamp).unwrap();
        assert!(closed.profile_ready);
        // Only a currency whose own pair closed on the last UTC day is present.
        assert_eq!(closed.auction_entry_prices.len(), 1);
        let day_type_row = &closed.auction_entry_prices[0];
        assert_eq!(
            day_type_row.reference_currency,
            crate::constants::DAY_TYPE_ISO
        );
        assert_eq!(day_type_row.entry_price_minor, last_closed_price);
        assert_eq!(
            day_type_row.source,
            crate::api::OcompAuctionEntryPriceSource::LastClosedDayVwap
        );
        assert_eq!(day_type_row.source_day, last_closed);
        assert_eq!(closed.oracle_state_version, 5);
        // The opening bound is now the registry size, not a per-day entry count.
        assert_eq!(closed.wwd_pair_entries, registered_pairs);
        assert_eq!(closed.active_scurve_entries, 1);

        // The next day's last closed UTC day carries no price, so the day-type row is
        // omitted rather than substituted: an unpriced day announces itself as empty.
        let next_timestamp = timestamp + outbe_primitives::time::SECONDS_PER_DAY;
        let unpriced = crate::api::ocomp_pre_admission_projection(storage, next_timestamp).unwrap();
        assert!(unpriced.profile_ready);
        assert!(unpriced.auction_entry_prices.is_empty());
        assert_eq!(unpriced.oracle_state_version, 5);
        // Registry-derived, so it does not drop to zero on a day with no snapshot.
        assert_eq!(unpriced.wwd_pair_entries, registered_pairs);
        assert_eq!(unpriced.active_scurve_entries, 1);
    });
}

#[test]
fn ocomp_oracle_profile_initialization_is_exact_and_idempotent() {
    with_storage(|storage| {
        assert!(crate::api::initialize_fresh_ocomp_profile(storage.clone()).is_err());

        let mut oracle = OracleContract::new(storage.clone());
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();
        crate::api::initialize_fresh_ocomp_profile(storage.clone()).unwrap();
        crate::api::initialize_fresh_ocomp_profile(storage).unwrap();

        assert!(oracle.ocomp_profile_ready.read().unwrap());
        assert_eq!(oracle.ocomp_state_version.read().unwrap(), 1);
    });
}

#[test]
fn ocomp_state_version_overflow_rejects_before_oracle_mutation() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();
        crate::api::initialize_fresh_ocomp_profile(storage).unwrap();
        oracle.ocomp_state_version.write(u64::MAX).unwrap();

        assert!(oracle
            .write_snapshot(1_000, &[(pair_key(COEN, usd()), coen_iso(10), coen_iso(1))],)
            .is_err());
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        assert_eq!(oracle.snapshot_pair_count.read(&0).unwrap(), 0);
        assert_eq!(oracle.ocomp_state_version.read().unwrap(), u64::MAX);
    });
}
#[test]
fn ocomp_oracle_owner_mutations_roll_back_every_partial_write_boundary() {
    for (label, fixture, mutation) in [
        (
            "write_snapshot",
            seed_ocomp_oracle as OracleFixture,
            write_snapshot_mutation as OracleMutation,
        ),
        (
            "store_worldwide_day_vwap_snapshot",
            seed_ocomp_oracle_with_snapshot,
            store_wwd_snapshot_mutation,
        ),
        (
            "finalize_utc_day_vwap",
            seed_ocomp_oracle_with_snapshot,
            finalize_utc_day_mutation,
        ),
        (
            "store_scurve_entry",
            seed_ocomp_oracle,
            store_scurve_mutation,
        ),
        (
            "process_daily_scurve",
            seed_ocomp_oracle_with_peak_history,
            process_scurve_mutation,
        ),
    ] {
        assert_oracle_mutation_is_atomic(label, fixture, mutation);
    }
}
#[test]
fn prefork_oracle_event_failures_preserve_historical_best_effort_mutations() {
    let mut finalized = run_prefork_with_last_mutation_failure(
        seed_prefork_oracle_with_snapshot,
        finalize_utc_day_mutation,
    );
    StorageHandle::enter(&mut finalized, |storage| {
        let oracle = OracleContract::new(storage);
        assert_eq!(
            oracle
                .get_utc_day_vwap_for_pair(
                    outbe_primitives::time::timestamp_to_date_key(ATOMIC_DAY_START),
                    oracle.pair_index_of(pair_key(COEN, usd())).unwrap(),
                )
                .unwrap(),
            Some(coen_iso(125))
        );
        assert!(!oracle.ocomp_profile_ready.read().unwrap());
    });

    let mut processed = run_prefork_with_last_mutation_failure(
        seed_prefork_oracle_with_peak_history,
        process_scurve_mutation,
    );
    StorageHandle::enter(&mut processed, |storage| {
        let oracle = OracleContract::new(storage);
        assert_eq!(oracle.scurve_count.read().unwrap(), 1);
        assert_eq!(
            oracle.scurve_peak_day.read(&0).unwrap(),
            SCURVE_CURRENT_DAY - 2 * crate::scurve::DAY_SECONDS
        );
        assert!(!oracle.ocomp_profile_ready.read().unwrap());
    });
}

#[test]
fn scurve_count_overflow_rejects_before_any_owner_write() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();
        crate::api::initialize_fresh_ocomp_profile(storage).unwrap();
        oracle.scurve_count.write(u32::MAX).unwrap();
        let version_before = oracle.ocomp_state_version.read().unwrap();

        assert!(crate::scurve::store_scurve_entry(
            &mut oracle,
            pair_key(COEN, usd()),
            ATOMIC_DAY_START,
            coen_iso(125),
        )
        .is_err());
        assert_eq!(oracle.scurve_count.read().unwrap(), u32::MAX);
        assert_eq!(
            oracle.scurve_pair.read_pair(&u32::MAX).unwrap(),
            AddressPair::ZERO
        );
        assert_eq!(oracle.ocomp_state_version.read().unwrap(), version_before);
    });
}
#[test]
fn run_tally_accepts_a_single_validator_as_the_validator_median() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let validator = Address::new([0x11; 20]);
        register_validator(storage.clone(), validator, native_coen(100));
        let rate = fixed18(50);
        let volume = fixed18(1000);

        oracle
            .submit_vote(validator, &[(COEN, USDT, rate, volume)])
            .unwrap();

        // Run tally
        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        // Exchange rate should be updated to the voted rate
        let (stored_rate, block, ts) = oracle.get_exchange_rate_data(COEN, USDT).unwrap();
        assert_eq!(stored_rate, rate);
        assert_eq!(block, 2);
        assert_eq!(ts, 24);

        // Validator should get success (voted within band for all pairs)
        assert_eq!(oracle.penalty_success_count.read(&validator).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&validator).unwrap(), 0);
        assert_eq!(oracle.penalty_abstain_count.read(&validator).unwrap(), 0);

        // Votes should be cleared
        assert_eq!(oracle.voter_list.len().unwrap(), 0);

        // Snapshot should exist
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 1);
    });
}

#[test]
fn run_tally_rewards_every_voter_inside_the_reward_band() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let v1 = Address::new([0x11; 20]);
        let v2 = Address::new([0x22; 20]);
        let v3 = Address::new([0x33; 20]);

        register_validator(storage.clone(), v1, native_coen(100));
        register_validator(storage.clone(), v2, native_coen(200));
        register_validator(storage.clone(), v3, native_coen(100));

        // All vote very close: 1000, 1001, 1002 (spread < 0.2% of median)
        // With 2% reward band, all should be within band.
        let base = fixed18(1000);
        oracle
            .submit_vote(v1, &[(COEN, USDT, base, SCALE_1E18)])
            .unwrap();
        oracle
            .submit_vote(v2, &[(COEN, USDT, base + SCALE_1E18, SCALE_1E18)])
            .unwrap();
        oracle
            .submit_vote(v3, &[(COEN, USDT, base + fixed18(2), SCALE_1E18)])
            .unwrap();

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        // One validator contributes one observation, so the central rate is 1001.
        let rate = oracle.get_exchange_rate(COEN, USDT).unwrap();
        assert_eq!(rate, fixed18(1001));

        // Reward spread = max(std_dev, 1001 * 0.02 / 2) = max(~0.816, ~10.01) = ~10.01
        // All votes within [990.99, 1011.01] -> all win
        assert_eq!(oracle.penalty_success_count.read(&v1).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v2).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v3).unwrap(), 1);
    });
}

#[test]
fn run_tally_gives_every_validator_one_median_observation_regardless_of_stake() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();

        let v1 = Address::new([0x11; 20]);
        let v2 = Address::new([0x22; 20]);
        let v3 = Address::new([0x33; 20]);
        register_validator(storage.clone(), v1, native_coen(1_000_000));
        register_validator(storage.clone(), v2, native_coen(1));
        register_validator(storage, v3, native_coen(1));

        for (voter, rate) in [(v1, 100), (v2, 200), (v3, 300)] {
            oracle
                .submit_vote(voter, &[(COEN, usd(), coen_iso(rate), COEN_ISO_SCALE)])
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle.get_exchange_rate(COEN, usd()).unwrap(),
            coen_iso(200)
        );
    });
}

#[test]
fn run_tally_penalizes_a_voter_outside_the_reward_band() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let v1 = Address::new([0x11; 20]);
        let v2 = Address::new([0x22; 20]);
        let v3 = Address::new([0x33; 20]);

        register_validator(storage.clone(), v1, native_coen(100));
        register_validator(storage.clone(), v2, native_coen(200));
        register_validator(storage.clone(), v3, native_coen(100));

        // v1 and v2 vote 50, v3 votes 500 (extreme outlier)
        oracle
            .submit_vote(v1, &[(COEN, USDT, fixed18(50), SCALE_1E18)])
            .unwrap();
        oracle
            .submit_vote(v2, &[(COEN, USDT, fixed18(50), SCALE_1E18)])
            .unwrap();
        oracle
            .submit_vote(v3, &[(COEN, USDT, fixed18(500), SCALE_1E18)])
            .unwrap();

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        // The validator median is 50.
        let rate = oracle.get_exchange_rate(COEN, USDT).unwrap();
        assert_eq!(rate, fixed18(50));

        // v1 and v2 should be winners, v3 (outlier at 500) should miss
        assert_eq!(oracle.penalty_success_count.read(&v1).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v2).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&v3).unwrap(), 1);
    });
}

#[test]
fn run_tally_counts_a_zero_rate_submission_as_a_miss_without_poisoning_price() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let valid = Address::new([0x11; 20]);
        let valid2 = Address::new([0x22; 20]);
        let invalid = Address::new([0x33; 20]);
        register_validator(storage.clone(), valid, native_coen(100));
        register_validator(storage.clone(), valid2, native_coen(100));
        register_validator(storage.clone(), invalid, native_coen(100));
        oracle
            .submit_vote(valid, &[(COEN, USDT, fixed18(50), SCALE_1E18)])
            .unwrap();
        oracle
            .submit_vote(valid2, &[(COEN, USDT, fixed18(50), SCALE_1E18)])
            .unwrap();
        oracle
            .submit_vote(invalid, &[(COEN, USDT, U256::ZERO, SCALE_1E18)])
            .unwrap();

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(oracle.get_exchange_rate(COEN, USDT).unwrap(), fixed18(50));
        assert_eq!(oracle.penalty_success_count.read(&valid).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&valid2).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&invalid).unwrap(), 1);
        assert_eq!(oracle.penalty_abstain_count.read(&invalid).unwrap(), 0);
    });
}

#[test]
fn run_tally_breaks_equal_reference_observation_ties_by_registry_order() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let lower = AddressPair::from_addresses(COEN, USDT).to_canonical();
        let higher = AddressPair::from_addresses(USDT, ETH).to_canonical();
        oracle.register_pair(lower).unwrap();
        oracle.register_pair(higher).unwrap();

        let voter1 = Address::new([0x11; 20]);
        let voter2 = Address::new([0x22; 20]);
        register_validator(storage.clone(), voter1, native_coen(100));
        register_validator(storage.clone(), voter2, native_coen(100));
        oracle
            .submit_vote(
                voter1,
                &[
                    (lower.address1(), lower.address2(), fixed18(50), SCALE_1E18),
                    (
                        higher.address1(),
                        higher.address2(),
                        fixed18(2_000),
                        SCALE_1E18,
                    ),
                ],
            )
            .unwrap();
        oracle
            .submit_vote(
                voter2,
                &[
                    (lower.address1(), lower.address2(), fixed18(50), SCALE_1E18),
                    (
                        higher.address1(),
                        higher.address2(),
                        fixed18(2_000),
                        SCALE_1E18,
                    ),
                ],
            )
            .unwrap();

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle
                .get_exchange_rate(lower.address1(), lower.address2())
                .unwrap(),
            fixed18(50)
        );
        assert_eq!(
            oracle
                .get_exchange_rate(higher.address1(), higher.address2())
                .unwrap(),
            fixed18(2_000)
        );
        let (_, _, bases, quotes, _, _) = oracle.get_all_price_snapshot_history(1).unwrap();
        assert_eq!((bases[0], quotes[0]), (lower.address1(), lower.address2()));
    });
}

#[test]
fn later_pair_with_more_observations_becomes_the_reference_pair() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let first = AddressPair::from_addresses(Address::new([0x71; 20]), Address::new([0x72; 20]));
        let later = AddressPair::from_addresses(Address::new([0x81; 20]), Address::new([0x82; 20]));
        oracle.register_pair(first).unwrap();
        oracle.register_pair(later).unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }

        for (index, voter) in voters.into_iter().enumerate() {
            let mut votes = vec![(later.address1(), later.address2(), fixed18(1), SCALE_1E18)];
            if index < 3 {
                let rate = [fixed18(2), fixed18(3), fixed18(7)][index];
                votes.push((first.address1(), first.address2(), rate, SCALE_1E18));
            }
            oracle.submit_vote(voter, &votes).unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle
                .get_exchange_rate(later.address1(), later.address2())
                .unwrap(),
            fixed18(1)
        );
        assert_eq!(
            oracle
                .get_exchange_rate(first.address1(), first.address2())
                .unwrap(),
            fixed18(3) + U256::from(3u64)
        );
        let (_, _, bases, quotes, _, _) = oracle.get_all_price_snapshot_history(1).unwrap();
        assert_eq!((bases[0], quotes[0]), (later.address1(), later.address2()));
    });
}

#[test]
fn pair_below_quorum_is_not_selected_as_reference() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let first = AddressPair::from_addresses(Address::new([0x71; 20]), Address::new([0x72; 20]));
        let later = AddressPair::from_addresses(Address::new([0x81; 20]), Address::new([0x82; 20]));
        oracle.register_pair(first).unwrap();
        oracle.register_pair(later).unwrap();
        oracle
            .set_exchange_rate(Address::ZERO, first, fixed18(40), 1, 12)
            .unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }

        oracle
            .submit_vote(
                voters[0],
                &[(first.address1(), first.address2(), fixed18(50), SCALE_1E18)],
            )
            .unwrap();
        oracle
            .submit_vote(
                voters[1],
                &[
                    (first.address1(), first.address2(), fixed18(50), SCALE_1E18),
                    (later.address1(), later.address2(), fixed18(2), SCALE_1E18),
                ],
            )
            .unwrap();
        for voter in &voters[2..] {
            oracle
                .submit_vote(
                    *voter,
                    &[(later.address1(), later.address2(), fixed18(2), SCALE_1E18)],
                )
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle
                .get_exchange_rate_data(first.address1(), first.address2())
                .unwrap(),
            (fixed18(40), 1, 12)
        );
        assert_eq!(
            oracle
                .get_exchange_rate(later.address1(), later.address2())
                .unwrap(),
            fixed18(2)
        );
        let (_, _, bases, quotes, _, _) = oracle.get_all_price_snapshot_history(1).unwrap();
        assert_eq!((bases[0], quotes[0]), (later.address1(), later.address2()));
    });
}

#[test]
fn two_votes_cannot_replace_the_third_vote_required_for_four_validator_quorum() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::from_addresses(COEN, USDT);
        oracle.register_pair(pair).unwrap();
        oracle
            .set_exchange_rate(Address::ZERO, pair, fixed18(40), 1, 12)
            .unwrap();

        let v1 = Address::new([0x11; 20]);
        let v2 = Address::new([0x22; 20]);
        let v3 = Address::new([0x33; 20]);
        let v4 = Address::new([0x44; 20]);
        register_validator(storage.clone(), v1, native_coen(100));
        register_validator(storage.clone(), v2, native_coen(100));
        register_validator(storage.clone(), v3, native_coen(1));
        register_validator(storage.clone(), v4, native_coen(1));

        for voter in [v1, v2] {
            oracle
                .submit_vote(voter, &[(COEN, USDT, fixed18(50), SCALE_1E18)])
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle.get_exchange_rate_data(COEN, USDT).unwrap(),
            (fixed18(40), 1, 12)
        );
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        assert_eq!(oracle.penalty_success_count.read(&v1).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v2).unwrap(), 1);
        assert_eq!(oracle.penalty_abstain_count.read(&v3).unwrap(), 1);
        assert_eq!(oracle.penalty_abstain_count.read(&v4).unwrap(), 1);
    });
}

#[test]
fn a_validator_deactivated_after_submission_does_not_count_toward_tally_quorum() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        oracle
            .set_exchange_rate(Address::ZERO, pair, coen_iso(40), 1, 12)
            .unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }

        for voter in &voters[..2] {
            oracle
                .submit_vote(*voter, &[(COEN, usd(), coen_iso(50), COEN_ISO_SCALE)])
                .unwrap();
        }
        outbe_validatorset::contract::ValidatorSet::new(storage)
            .deactivate_validator(Address::ZERO, voters[1])
            .unwrap();

        // Three validators remain active, so two observations are required.
        // The exiting validator's stored row must not supply the missing vote.
        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle.get_exchange_rate_data(COEN, usd()).unwrap(),
            (coen_iso(40), 1, 12)
        );
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        assert_eq!(oracle.penalty_success_count.read(&voters[0]).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&voters[1]).unwrap(), 0);
        assert_eq!(oracle.penalty_abstain_count.read(&voters[2]).unwrap(), 1);
        assert_eq!(oracle.penalty_abstain_count.read(&voters[3]).unwrap(), 1);
    });
}

#[test]
fn partial_pair_votes_use_independent_quorum_and_no_cross_intersection_quorum() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let reference = AddressPair::from_addresses(COEN, USDT);
        let target = AddressPair::from_addresses(USDT, ETH).to_canonical();
        oracle.register_pair(reference).unwrap();
        oracle.register_pair(target).unwrap();

        let v1 = Address::new([0x11; 20]);
        let v2 = Address::new([0x22; 20]);
        let v3 = Address::new([0x33; 20]);
        let v4 = Address::new([0x44; 20]);
        for voter in [v1, v2, v3, v4] {
            register_validator(storage.clone(), voter, native_coen(100));
        }

        oracle
            .submit_vote(v1, &[(COEN, USDT, fixed18(50), fixed18(10))])
            .unwrap();
        oracle
            .submit_vote(
                v2,
                &[
                    (COEN, USDT, fixed18(50), fixed18(10)),
                    (
                        target.address1(),
                        target.address2(),
                        fixed18(2_000),
                        fixed18(20),
                    ),
                ],
            )
            .unwrap();
        oracle
            .submit_vote(
                v3,
                &[
                    (COEN, USDT, fixed18(50), fixed18(10)),
                    (
                        target.address1(),
                        target.address2(),
                        fixed18(2_000),
                        fixed18(30),
                    ),
                ],
            )
            .unwrap();
        oracle
            .submit_vote(
                v4,
                &[(
                    target.address1(),
                    target.address2(),
                    fixed18(2_000),
                    fixed18(40),
                )],
            )
            .unwrap();

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(oracle.get_exchange_rate(COEN, USDT).unwrap(), fixed18(50));
        assert_eq!(
            oracle
                .get_exchange_rate(target.address1(), target.address2())
                .unwrap(),
            fixed18(2_000)
        );
        let (_, _, bases, quotes, _, volumes) = oracle.get_all_price_snapshot_history(1).unwrap();
        let target_row = bases
            .iter()
            .zip(&quotes)
            .position(|(base, quote)| (*base, *quote) == (target.address1(), target.address2()))
            .unwrap();
        assert_eq!(volumes[target_row], fixed18(90));

        assert_eq!(oracle.penalty_miss_count.read(&v1).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v2).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v3).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&v4).unwrap(), 1);
    });
}

#[test]
fn begin_block_skips_only_the_overflowing_cross_row() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let lower = AddressPair::from_addresses(COEN, USDT).to_canonical();
        let higher = AddressPair::from_addresses(USDT, ETH).to_canonical();
        // Registry-order tie-break makes the first pair the reference. Its
        // extreme row overflows only that validator's cross conversion.
        oracle.register_pair(higher).unwrap();
        oracle.register_pair(lower).unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }
        oracle
            .submit_vote(
                voters[0],
                &[
                    (higher.address1(), higher.address2(), U256::MAX, SCALE_1E18),
                    (lower.address1(), lower.address2(), U256::ONE, SCALE_1E18),
                ],
            )
            .unwrap();
        for voter in &voters[1..] {
            oracle
                .submit_vote(
                    *voter,
                    &[
                        (
                            higher.address1(),
                            higher.address2(),
                            fixed18(100),
                            SCALE_1E18,
                        ),
                        (lower.address1(), lower.address2(), fixed18(50), SCALE_1E18),
                    ],
                )
                .unwrap();
        }

        let runtime_ctx =
            BlockRuntimeContext::new(BlockContext::empty_for_tests(2, 24, 1), storage.clone());
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&runtime_ctx).unwrap();

        assert_eq!(
            oracle
                .get_exchange_rate(higher.address1(), higher.address2())
                .unwrap(),
            fixed18(100)
        );
        assert_eq!(
            oracle
                .get_exchange_rate(lower.address1(), lower.address2())
                .unwrap(),
            fixed18(50)
        );
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&voters[0]).unwrap(), 1);
        for voter in &voters[1..] {
            assert_eq!(oracle.penalty_success_count.read(voter).unwrap(), 1);
        }
        assert!(voters
            .iter()
            .all(|voter| !oracle.vote_exists.read(voter).unwrap()));
    });
}

#[test]
fn run_tally_skips_only_a_target_with_unrepresentable_final_cross_rate() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let reference =
            AddressPair::from_addresses(Address::new([0x71; 20]), Address::new([0x72; 20]));
        let target =
            AddressPair::from_addresses(Address::new([0x81; 20]), Address::new([0x82; 20]));
        oracle.register_pair(reference).unwrap();
        oracle.register_pair(target).unwrap();
        oracle
            .set_exchange_rate(Address::ZERO, target, fixed18(7), 1, 12)
            .unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }

        for (index, voter) in voters.into_iter().enumerate() {
            let reference_rate = if index < 2 { U256::ONE } else { U256::MAX };
            let mut votes = vec![(
                reference.address1(),
                reference.address2(),
                reference_rate,
                U256::ZERO,
            )];
            if index < 3 {
                votes.push((target.address1(), target.address2(), SCALE_1E18, U256::ZERO));
            }
            oracle.submit_vote(voter, &votes).unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_ne!(
            oracle
                .get_exchange_rate(reference.address1(), reference.address2())
                .unwrap(),
            U256::ZERO
        );
        assert_eq!(
            oracle
                .get_exchange_rate_data(target.address1(), target.address2())
                .unwrap(),
            (fixed18(7), 1, 12)
        );
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        assert!(voters
            .iter()
            .all(|voter| !oracle.vote_exists.read(voter).unwrap()));
    });
}

#[test]
fn unrepresentable_volume_removes_the_whole_tuple_before_quorum_and_tally() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }
        oracle
            .submit_vote(voters[0], &[(COEN, usd(), coen_iso(2), U256::MAX)])
            .unwrap();
        for voter in &voters[1..] {
            oracle
                .submit_vote(*voter, &[(COEN, usd(), coen_iso(2), coen_iso(1))])
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(oracle.get_exchange_rate(COEN, usd()).unwrap(), coen_iso(2));
        let (_, _, _, _, _, volumes) = oracle.get_all_price_snapshot_history(1).unwrap();
        assert_eq!(volumes, vec![coen_iso(3)]);
        assert_eq!(oracle.penalty_miss_count.read(&voters[0]).unwrap(), 1);
        for voter in &voters[1..] {
            assert_eq!(oracle.penalty_success_count.read(voter).unwrap(), 1);
        }
    });
}

#[test]
fn unrepresentable_volume_can_drop_a_pair_below_quorum() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        oracle
            .set_exchange_rate(Address::ZERO, pair, coen_iso(7), 1, 12)
            .unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }
        oracle
            .submit_vote(voters[0], &[(COEN, usd(), coen_iso(2), U256::MAX)])
            .unwrap();
        for voter in &voters[1..3] {
            oracle
                .submit_vote(*voter, &[(COEN, usd(), coen_iso(2), coen_iso(1))])
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle.get_exchange_rate_data(COEN, usd()).unwrap(),
            (coen_iso(7), 1, 12)
        );
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        assert_eq!(oracle.penalty_miss_count.read(&voters[0]).unwrap(), 1);
        for voter in &voters[1..3] {
            assert_eq!(oracle.penalty_success_count.read(voter).unwrap(), 1);
        }
        assert_eq!(oracle.penalty_abstain_count.read(&voters[3]).unwrap(), 1);
    });
}

#[test]
fn exhausted_existing_aggregate_omits_snapshot_without_penalizing_valid_votes() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        let timestamp = 1_780_012_800u64 + 60 * 60;
        let day = timestamp - timestamp % 86_400;
        oracle
            .wwd_prefix_pv_sum
            .get_nested(&pair)
            .write(&day, U256::MAX)
            .unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }
        for voter in &voters[..3] {
            oracle
                .submit_vote(*voter, &[(COEN, usd(), coen_iso(2), coen_iso(1))])
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, timestamp).unwrap();

        assert_eq!(oracle.get_exchange_rate(COEN, usd()).unwrap(), coen_iso(2));
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        for voter in &voters[..3] {
            assert_eq!(oracle.penalty_success_count.read(voter).unwrap(), 1);
        }
        assert_eq!(oracle.penalty_abstain_count.read(&voters[3]).unwrap(), 1);
        assert!(voters
            .iter()
            .all(|voter| !oracle.vote_exists.read(voter).unwrap()));
    });
}

#[test]
fn limited_existing_headroom_omits_snapshot_without_penalizing_any_validator() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        let timestamp = 1_780_012_800u64 + 60 * 60;
        let day = timestamp - timestamp % 86_400;
        let rate = coen_iso(2);
        let unit_volume = coen_iso(1);
        oracle
            .wwd_prefix_pv_sum
            .get_nested(&pair)
            .write(&day, U256::MAX - rate * (unit_volume * U256::from(3u64)))
            .unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
            oracle
                .submit_vote(voter, &[(COEN, usd(), rate, unit_volume)])
                .unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, timestamp).unwrap();

        assert_eq!(oracle.get_exchange_rate(COEN, usd()).unwrap(), rate);
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        for voter in &voters {
            assert_eq!(oracle.penalty_success_count.read(voter).unwrap(), 1);
        }
    });
}

#[test]
fn cross_target_volume_is_validated_against_the_derived_rate_not_raw_median() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let reference =
            AddressPair::from_addresses(Address::new([0x71; 20]), Address::new([0x72; 20]));
        let target =
            AddressPair::from_addresses(Address::new([0x81; 20]), Address::new([0x82; 20]));
        oracle.register_pair(reference).unwrap();
        oracle.register_pair(target).unwrap();

        let voters = [
            Address::new([0x11; 20]),
            Address::new([0x22; 20]),
            Address::new([0x33; 20]),
            Address::new([0x44; 20]),
        ];
        for voter in voters {
            register_validator(storage.clone(), voter, native_coen(100));
        }

        let high_rate = fixed18(100);
        let large_but_derived_rate_safe_volume = U256::MAX / high_rate + U256::ONE;
        let reference_rates = [fixed18(1), high_rate, fixed18(1), fixed18(1)];
        let target_rates = [fixed18(1), high_rate, high_rate];
        let target_volumes = [U256::ZERO, large_but_derived_rate_safe_volume, U256::ZERO];

        for (index, voter) in voters.into_iter().enumerate() {
            let mut votes = vec![(
                reference.address1(),
                reference.address2(),
                reference_rates[index],
                U256::ZERO,
            )];
            if index < 3 {
                votes.push((
                    target.address1(),
                    target.address2(),
                    target_rates[index],
                    target_volumes[index],
                ));
            }
            oracle.submit_vote(voter, &votes).unwrap();
        }

        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(
            oracle
                .get_exchange_rate(target.address1(), target.address2())
                .unwrap(),
            fixed18(1)
        );
        let (_, _, bases, quotes, _, volumes) = oracle.get_all_price_snapshot_history(1).unwrap();
        let target_row = bases
            .iter()
            .zip(&quotes)
            .position(|(base, quote)| (*base, *quote) == (target.address1(), target.address2()))
            .unwrap();
        assert_eq!(volumes[target_row], large_but_derived_rate_safe_volume);
        assert_eq!(oracle.penalty_success_count.read(&voters[0]).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&voters[1]).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&voters[2]).unwrap(), 1);
        assert_eq!(oracle.penalty_miss_count.read(&voters[3]).unwrap(), 1);
    });
}

#[test]
fn run_tally_counts_an_abstain_for_every_silent_validator() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let v1 = Address::new([0x11; 20]);
        register_validator(storage.clone(), v1, native_coen(100));

        // No votes submitted -> all abstain
        crate::tally::run_tally(&mut oracle, 2, 24).unwrap();

        assert_eq!(oracle.penalty_abstain_count.read(&v1).unwrap(), 1);
        assert_eq!(oracle.penalty_success_count.read(&v1).unwrap(), 0);
    });
}

#[test]
fn begin_block_tallies_only_on_a_vote_period_boundary() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let v1 = Address::new([0x11; 20]);
        register_validator(storage.clone(), v1, native_coen(100));
        oracle
            .submit_vote(v1, &[(COEN, USDT, fixed18(42), SCALE_1E18)])
            .unwrap();

        // Block 1: not a vote period boundary (period=2), no tally
        let runtime_ctx =
            BlockRuntimeContext::new(BlockContext::empty_for_tests(1, 12, 1), storage.clone());
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&runtime_ctx).unwrap();
        assert!(oracle.vote_exists.read(&v1).unwrap()); // vote still exists

        // Block 2: vote period boundary, tally runs
        let runtime_ctx =
            BlockRuntimeContext::new(BlockContext::empty_for_tests(2, 24, 1), storage.clone());
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&runtime_ctx).unwrap();
        assert!(!oracle.vote_exists.read(&v1).unwrap()); // votes cleared

        let rate = oracle.get_exchange_rate(COEN, USDT).unwrap();
        assert_eq!(rate, fixed18(42));
    });
}

#[test]
fn slash_window_resets_penalty_counters_at_the_window_end() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);

        let v1 = Address::new([0x11; 20]);
        register_validator(storage.clone(), v1, native_coen(100));

        // Simulate many misses (below 5% success rate)
        for _ in 0..20 {
            oracle.increment_miss(&v1).unwrap();
        }
        oracle.increment_success(&v1).unwrap(); // 1 success out of 21 = 4.76% < 5%

        // Run slash and reset
        crate::tally::slash_and_reset_counters(&mut oracle, 10000).unwrap();

        // Counters should be reset
        assert_eq!(oracle.penalty_success_count.read(&v1).unwrap(), 0);
        assert_eq!(oracle.penalty_miss_count.read(&v1).unwrap(), 0);

        // Validator should be force-exited (check via ValidatorSet)
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        assert!(matches!(
            vs.validator_lifecycle(v1).unwrap(),
            ValidatorLifecycle::JailRetained(_) | ValidatorLifecycle::Jail(_)
        ));
    });
}

#[test]
fn slash_window_rejects_unbounded_validator_work() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);

        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.config_is_initialized.write(true).unwrap();
        vs.config_owner.write(Address::ZERO).unwrap();
        vs.config_epoch_length_blocks.write(3600).unwrap();
        vs.config_max_validators
            .write((crate::tally::MAX_ORACLE_SLASH_WINDOW_VALIDATORS + 1) as u32)
            .unwrap();

        for i in 1..=(crate::tally::MAX_ORACLE_SLASH_WINDOW_VALIDATORS + 1) {
            let mut bytes = [0u8; 20];
            bytes[16..].copy_from_slice(&(i as u32).to_be_bytes());
            register_validator(storage.clone(), Address::new(bytes), U256::from(1u64));
        }

        let err = crate::tally::slash_and_reset_counters(&mut oracle, 10_000).unwrap_err();
        assert!(
            err.to_string().contains("exceeds cap"),
            "unexpected error: {err}"
        );
    });
}

#[test]
fn slash_window_rolls_back_slash_state_when_force_exit_fails() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .config_slash_fraction
            .write(SCALE_1E18 / U256::from(10u64))
            .unwrap();

        let validator = Address::new([0x33; 20]);
        let stake = native_coen(100);
        register_waiting_for_readiness(storage.clone(), validator, stake);
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.test_set_pending_set_change(false).unwrap();

        let staking = outbe_staking::contract::Staking::new(storage.clone());
        staking.stake_amount.write(&validator, stake).unwrap();
        staking.total_staked.write(stake).unwrap();
        oracle
            .storage
            .set_balance(outbe_primitives::addresses::STAKING_ADDRESS, stake)
            .unwrap();

        oracle.increment_miss(&validator).unwrap();

        let err = crate::tally::slash_and_reset_counters(&mut oracle, 10_000).unwrap_err();
        assert!(err.to_string().contains("cannot jail validator"));

        let staking = outbe_staking::contract::Staking::new(storage.clone());
        assert_eq!(staking.stake_amount.read(&validator).unwrap(), stake);
        assert_eq!(staking.total_staked.read().unwrap(), stake);
        assert_eq!(
            oracle
                .storage
                .balance(outbe_primitives::addresses::STAKING_ADDRESS)
                .unwrap(),
            stake
        );

        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        assert_eq!(vs.validator_state(validator).unwrap().bonded_stake(), stake);
        assert!(matches!(
            vs.validator_lifecycle(validator).unwrap(),
            ValidatorLifecycle::WaitingForReadiness(_)
        ));

        assert_eq!(oracle.penalty_miss_count.read(&validator).unwrap(), 1);
    });
}

#[test]
fn slash_window_rolls_back_the_forced_exit_when_slashing_fails() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .config_slash_fraction
            .write(SCALE_1E18 / U256::from(10u64))
            .unwrap();

        let validator = Address::new([0x44; 20]);
        let stake = native_coen(100);
        register_validator(storage.clone(), validator, stake);
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        vs.test_set_pending_set_change(false).unwrap();

        let staking = outbe_staking::contract::Staking::new(storage.clone());
        staking.stake_amount.write(&validator, stake).unwrap();
        staking.total_staked.write(stake).unwrap();
        oracle
            .storage
            .set_balance(outbe_primitives::addresses::STAKING_ADDRESS, U256::ZERO)
            .unwrap();

        oracle.increment_miss(&validator).unwrap();

        let err = crate::tally::slash_and_reset_counters(&mut oracle, 10_000).unwrap_err();
        assert!(
            err.to_string().contains("insufficient") || err.to_string().contains("balance"),
            "unexpected error: {err}"
        );

        assert!(vs
            .validator_lifecycle(validator)
            .unwrap()
            .is_active_status());
        assert!(!vs.has_pending_set_change().unwrap());
        assert_eq!(oracle.penalty_miss_count.read(&validator).unwrap(), 1);
        assert_eq!(staking.stake_amount.read(&validator).unwrap(), stake);
        assert_eq!(staking.total_staked.read().unwrap(), stake);
    });
}

#[test]
fn slash_window_never_force_exits_a_protected_validator() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle.config_allow_protected.write(true).unwrap();

        let v1 = Address::new([0x11; 20]);
        register_validator(storage.clone(), v1, native_coen(100));

        // Mark as protected
        oracle.protected_validator.write(&v1, true).unwrap();

        // Simulate many misses
        for _ in 0..20 {
            oracle.increment_miss(&v1).unwrap();
        }

        crate::tally::slash_and_reset_counters(&mut oracle, 10000).unwrap();

        // Counters reset but validator NOT force-exited
        assert_eq!(oracle.penalty_miss_count.read(&v1).unwrap(), 0);
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        assert!(vs.validator_lifecycle(v1).unwrap().is_active_status());
    });
}
#[test]
fn begin_block_scurve_hook_records_the_daily_peak() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle.reference_currencies.push(840).unwrap();
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();

        let day_1 = crate::scurve::DAY_SECONDS;
        let day_2 = 2 * crate::scurve::DAY_SECONDS;
        let day_3 = 3 * crate::scurve::DAY_SECONDS;
        let day_4 = 4 * crate::scurve::DAY_SECONDS;
        // Three fully-closed days forming a peak at day_2: 100 < 150 > 120.
        oracle
            .write_snapshot(
                day_1 + 60,
                &[(pair_key(COEN, usd()), coen_iso(100), coen_iso(1))],
            )
            .unwrap();
        oracle
            .write_snapshot(
                day_2 + 60,
                &[(pair_key(COEN, usd()), coen_iso(150), coen_iso(1))],
            )
            .unwrap();
        oracle
            .write_snapshot(
                day_3 + 60,
                &[(pair_key(COEN, usd()), coen_iso(120), coen_iso(1))],
            )
            .unwrap();

        // Hook fires on the first block of day_4 - the current day has NO
        // close yet, mirroring the real start-of-day boundary block.
        let runtime_ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(4, day_4 + 120, 1),
            storage.clone(),
        );
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&runtime_ctx).unwrap();

        assert_eq!(oracle.scurve_count.read().unwrap(), 1);
        assert_eq!(
            oracle.scurve_pair.read_pair(&0u32).unwrap(),
            pair_key(COEN, usd())
        );
        assert_eq!(oracle.scurve_peak_day.read(&0).unwrap(), day_2);
        assert_eq!(oracle.scurve_peak_price.read(&0).unwrap(), coen_iso(150));
        assert_eq!(oracle.scurve_last_processed_day.read().unwrap(), day_4);

        let active_value =
            crate::scurve::get_max_active_scurve_value(&oracle, pair_key(COEN, usd()), day_4)
                .unwrap();
        assert!(!active_value.is_zero());
        assert!(active_value < coen_iso(150));

        // The begin-block owner must keep the same chain alive after the first
        // 128-day coefficient period; no expiry/eviction or successor row is
        // required for continuation.
        let day_130 = day_2 + 128 * crate::scurve::DAY_SECONDS;
        let runtime_ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(130, day_130 + 120, 1),
            storage,
        );
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&runtime_ctx).unwrap();
        assert_eq!(oracle.scurve_count.read().unwrap(), 1);
        assert_eq!(
            crate::scurve::get_max_active_scurve_value(&oracle, pair_key(COEN, usd()), day_130)
                .unwrap(),
            crate::scurve::compute_scurve_value(coen_iso(150), 128)
        );
    });
}

#[test]
fn begin_block_scurve_hook_processes_only_registered_reference_pairs() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle.reference_currencies.push(840).unwrap();
        oracle.reference_currencies.push(978).unwrap();
        oracle.reference_currencies.push(392).unwrap(); // no pair: no-op

        let usd_pair = AddressPair::new_coen_to(840);
        let eur_pair = AddressPair::new_coen_to(978);
        let cad_pair = AddressPair::new_coen_to(124); // active, priced, non-reference
        let generic_pair = AddressPair::from_addresses(COEN, USDT);
        oracle.register_pair(usd_pair).unwrap();
        oracle.register_pair(eur_pair).unwrap();
        oracle.register_pair(cad_pair).unwrap();
        oracle.register_pair(generic_pair).unwrap();

        let day_1 = crate::scurve::DAY_SECONDS;
        let day_2 = 2 * crate::scurve::DAY_SECONDS;
        let day_3 = 3 * crate::scurve::DAY_SECONDS;
        let day_4 = 4 * crate::scurve::DAY_SECONDS;
        for (timestamp, usd_price, eur_price, cad_price, generic_price) in [
            (
                day_1 + 60,
                coen_iso(100),
                coen_iso(90),
                coen_iso(80),
                fixed18(2),
            ),
            (
                day_2 + 60,
                coen_iso(150),
                coen_iso(140),
                coen_iso(130),
                fixed18(3),
            ),
            (
                day_3 + 60,
                coen_iso(120),
                coen_iso(110),
                coen_iso(100),
                fixed18(2),
            ),
        ] {
            oracle
                .write_snapshot(
                    timestamp,
                    &[
                        (usd_pair, usd_price, coen_iso(1)),
                        (eur_pair, eur_price, coen_iso(1)),
                        (cad_pair, cad_price, coen_iso(1)),
                        (generic_pair, generic_price, SCALE_1E18),
                    ],
                )
                .unwrap();
        }

        let runtime_ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(4, day_4 + 120, 1),
            storage.clone(),
        );
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&runtime_ctx).unwrap();

        assert_eq!(oracle.scurve_count.read().unwrap(), 2);
        assert_eq!(oracle.scurve_pair.read_pair(&0).unwrap(), usd_pair);
        assert_eq!(oracle.scurve_pair.read_pair(&1).unwrap(), eur_pair);
        assert_eq!(oracle.scurve_peak_price.read(&0).unwrap(), coen_iso(150));
        assert_eq!(oracle.scurve_peak_price.read(&1).unwrap(), coen_iso(140));
        assert_ne!(oracle.scurve_pair.read_pair(&0).unwrap(), cad_pair);
        assert_ne!(oracle.scurve_pair.read_pair(&1).unwrap(), cad_pair);
        assert_eq!(oracle.scurve_last_processed_day.read().unwrap(), day_4);
    });
}

#[test]
fn begin_block_finalizes_the_closed_utc_day() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle.config_is_initialized.write(true).unwrap();
        oracle.config_vote_period.write(2).unwrap();
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();
        let coen = pair_key(COEN, usd());

        let day_d = 20260624u32;
        let day_d1 = 20260625u32;
        let day_d2 = 20260626u32;
        let d_start = outbe_primitives::time::date_key_to_utc_timestamp(day_d);
        let d1_start = outbe_primitives::time::date_key_to_utc_timestamp(day_d1);
        let d2_start = outbe_primitives::time::date_key_to_utc_timestamp(day_d2);

        oracle
            .write_snapshot(
                d_start + 1_000,
                &[(pair_key(COEN, usd()), coen_iso(170), coen_iso(1))],
            )
            .unwrap();

        // First block of day D+1 -> day D is now fully closed and finalized.
        // Odd block number avoids the vote-period tally path (period == 2).
        let ctx = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(11, d1_start + 5, 1),
            storage.clone(),
        );
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&ctx).unwrap();

        assert_eq!(oracle.utc_day_vwap_last_finalized.read().unwrap(), day_d);
        assert_eq!(
            oracle
                .get_utc_day_vwap_for_pair(day_d, oracle.pair_index_of(coen).unwrap())
                .unwrap(),
            Some(coen_iso(170))
        );
        // The in-progress current day is not finalized.
        assert_eq!(
            oracle
                .get_utc_day_vwap_for_pair(day_d1, oracle.pair_index_of(coen).unwrap())
                .unwrap(),
            None
        );

        // Idempotent: a later block on the same UTC day neither advances the
        // watermark nor re-finalizes.
        let ctx2 = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(13, d1_start + 50, 1),
            storage.clone(),
        );
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&ctx2).unwrap();
        assert_eq!(oracle.utc_day_vwap_last_finalized.read().unwrap(), day_d);

        // Next rollover finalizes the next day contiguously (non-zero
        // watermark path).
        oracle
            .write_snapshot(
                d1_start + 2_000,
                &[(pair_key(COEN, usd()), coen_iso(190), coen_iso(1))],
            )
            .unwrap();
        let ctx3 = BlockRuntimeContext::new(
            BlockContext::empty_for_tests(15, d2_start + 5, 1),
            storage.clone(),
        );
        <crate::lifecycle::OracleLifecycle as BlockLifecycle>::begin_block(&ctx3).unwrap();
        assert_eq!(oracle.utc_day_vwap_last_finalized.read().unwrap(), day_d1);
        assert_eq!(
            oracle
                .get_utc_day_vwap_for_pair(day_d1, oracle.pair_index_of(coen).unwrap())
                .unwrap(),
            Some(coen_iso(190))
        );
    });
}
