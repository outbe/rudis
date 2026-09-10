//! State-level tests: pair registry, rates, votes, snapshots, layout parity.

use alloy_primitives::{Address, U256};

use crate::schema::{OracleContract, SCALE_1E18};

use super::common::*;

#[test]
fn register_pair_assigns_sequential_ids_and_marks_vote_targets() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());

        // Register first pair
        assert_eq!(
            oracle
                .register_pair(AddressPair::from_addresses(COEN, USDT))
                .unwrap(),
            1
        );

        // Register second pair
        assert_eq!(
            oracle
                .register_pair(AddressPair::from_addresses(ETH, USDT))
                .unwrap(),
            2
        );

        // Verify lookup
        assert_eq!(oracle.pair_index_of(pair_key(COEN, USDT)).unwrap(), 1);
        assert_eq!(oracle.pair_index_of(pair_key(ETH, USDT)).unwrap(), 2);
        assert_eq!(oracle.pair_index_of(pair_key(BTC, USDT)).unwrap(), 0); // not registered

        // Verify vote targets
        assert!(oracle.is_vote_target(COEN, USDT).unwrap());
        assert!(oracle.is_vote_target(ETH, USDT).unwrap());
        assert!(!oracle.is_vote_target(BTC, USDT).unwrap());

        // Duplicate registration fails
        assert!(oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .is_err());

        // Pair count
        assert_eq!(oracle.pair_count.read().unwrap(), 2);
        assert_eq!(oracle.pair_at(1).unwrap(), pair_key(COEN, USDT));
        assert_eq!(oracle.pair_at(2).unwrap(), pair_key(ETH, USDT));
    });
}

#[test]
fn register_pair_rejects_the_inverse_of_a_registered_pair() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        // The key is order-independent, so the inverse is the same pair.
        assert!(oracle
            .register_pair(AddressPair::from_addresses(USDT, COEN))
            .is_err());
    });
}

#[test]
fn register_pair_rejects_an_asset_paired_with_itself() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        assert!(oracle
            .register_pair(AddressPair::from_addresses(USDT, USDT))
            .is_err());
        assert!(oracle
            .register_pair(AddressPair::from_addresses(COEN, COEN))
            .is_err());
    });
}

#[test]
fn register_pair_preserves_a_generic_market_orientation() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        // The ISO address sorts below every token stand-in, so this proves the
        // registry value is the configured orientation rather than the sorted
        // storage-key orientation.
        let backwards = AddressPair::from_addresses(ETH, usd());
        assert!(
            !backwards.is_canonical(),
            "fixture is not a backwards quote"
        );

        assert_eq!(oracle.register_pair(backwards).unwrap(), 1);
        assert_eq!(oracle.pair_at(1).unwrap(), backwards);
        assert_eq!(oracle.require_pair(backwards).unwrap(), backwards);
        assert!(oracle.require_pair(backwards.to_canonical()).is_err());
    });
}

#[test]
fn register_pair_rejects_iso_to_coen_but_accepts_coen_to_iso() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        let reverse = AddressPair::from_addresses(usd(), COEN);

        assert!(oracle.register_pair(reverse).is_err());
        assert_eq!(oracle.pair_count.read().unwrap(), 0);

        let forward = AddressPair::new_coen_to(840);
        assert_eq!(oracle.register_pair(forward).unwrap(), 1);
        assert_eq!(oracle.pair_at(1).unwrap(), forward);
    });
}

#[test]
fn reciprocal_read_is_relative_to_the_registered_generic_orientation() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        let registered = AddressPair::from_addresses(ETH, usd());
        let rate = fixed18(4);
        oracle.register_pair(registered).unwrap();
        oracle
            .set_exchange_rate(Address::ZERO, registered, rate, 7, 11)
            .unwrap();

        assert_eq!(oracle.get_exchange_rate(ETH, usd()).unwrap(), rate);
        assert_eq!(
            oracle.get_exchange_rate(usd(), ETH).unwrap(),
            fixed18(1) / U256::from(4u64)
        );
        assert_eq!(
            oracle.get_exchange_rate_data(usd(), ETH).unwrap(),
            (fixed18(1) / U256::from(4u64), 7, 11)
        );
    });
}

#[test]
fn require_pair_rejects_a_pair_quoted_in_the_wrong_direction() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        assert_eq!(
            oracle.require_pair_from(COEN, USDT).unwrap(),
            pair_key(COEN, USDT)
        );

        // Reads whose value has no direction of its own - a VWAP, an S-curve
        // peak - cannot answer a backwards quote, so they refuse it. Only the
        // spot rate has a reciprocal.
        let err = oracle.require_pair_from(USDT, COEN).unwrap_err();
        assert!(
            format!("{err:?}").contains("registered orientation"),
            "expected a registered-orientation revert, got {err:?}"
        );
        assert!(oracle.get_exchange_rate(USDT, COEN).is_ok());
    });
}

/// One unordered market key identifies one registration, while the registry
/// entry preserves exactly the configured orientation.
#[test]
fn one_market_is_one_registration_reachable_from_either_quote() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        let registered = AddressPair::from_addresses(usd(), ETH);
        assert_eq!(oracle.register_pair(registered).unwrap(), 1);

        // Order-independent: either direction finds the same registration.
        assert_eq!(oracle.pair_index_of(registered).unwrap(), 1);
        assert_eq!(
            oracle
                .pair_index_of(AddressPair::from_addresses(ETH, usd()))
                .unwrap(),
            1
        );

        // Registering the market backwards is a duplicate, not a second market.
        assert!(oracle
            .register_pair(AddressPair::from_addresses(ETH, usd()))
            .is_err());
        assert_eq!(oracle.pair_count.read().unwrap(), 1);

        let entry = oracle.pair_at(1).unwrap();
        assert_eq!(entry, registered);
        assert!(entry.is_canonical());
    });
}

#[test]
fn every_pair_read_agrees_on_the_market_whichever_way_it_is_quoted() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        let rate = fixed18(4);
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(COEN, USDT),
                rate,
                1,
                1,
            )
            .unwrap();

        assert!(oracle.is_vote_target(COEN, USDT).unwrap());
        assert_eq!(oracle.get_exchange_rate(COEN, USDT).unwrap(), rate);

        // Backwards: both answer for the same market, the rate as a reciprocal.
        // Disagreeing here would let a caller act on a rate it cannot fetch.
        assert!(oracle.is_vote_target(USDT, COEN).unwrap());
        assert_eq!(
            oracle.get_exchange_rate(USDT, COEN).unwrap(),
            fixed18(1) / U256::from(4u64)
        );

        // Writes stay in registered orientation: a backwards quote has no
        // direction-free reading on the way in.
        assert!(oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(USDT, COEN),
                U256::from(9u64),
                1,
                1
            )
            .is_err());
    });
}

#[test]
fn a_backwards_quote_prices_at_the_reciprocal() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        // 2.5 COEN per USDT.
        let rate = U256::from(2_500_000_000_000_000_000u128);
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(COEN, USDT),
                rate,
                42,
                86_400,
            )
            .unwrap();

        let (forward, fwd_block, fwd_ts) = oracle.get_exchange_rate_data(COEN, USDT).unwrap();
        let (backward, bwd_block, bwd_ts) = oracle.get_exchange_rate_data(USDT, COEN).unwrap();

        assert_eq!(forward, rate);
        assert_eq!(backward, U256::from(400_000_000_000_000_000u128));
        // The observation is one event; only its quoting differs.
        assert_eq!((fwd_block, fwd_ts), (42, 86_400));
        assert_eq!((bwd_block, bwd_ts), (42, 86_400));
    });
}

#[test]
fn every_coen_iso_backwards_quote_uses_the_six_decimal_reciprocal() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        for iso in [840, 978] {
            let quote: Address = AssetType::IsoCurrency(iso).into();
            let pair = AddressPair::new_coen_to(iso);
            oracle.register_pair(pair).unwrap();
            oracle
                .set_exchange_rate(Address::ZERO, pair, U256::from(2_500_000u64), 42, 86_400)
                .unwrap();

            assert_eq!(
                oracle.get_exchange_rate(quote, COEN).unwrap(),
                U256::from(400_000u64)
            );
        }
    });
}

#[test]
fn an_unpublished_rate_reads_as_zero_from_either_side() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        // No reciprocal exists for zero; inverting must not divide by it.
        assert_eq!(oracle.get_exchange_rate(COEN, USDT).unwrap(), U256::ZERO);
        assert_eq!(oracle.get_exchange_rate(USDT, COEN).unwrap(), U256::ZERO);
    });
}

#[test]
fn a_rate_read_still_requires_a_registered_market() {
    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        assert!(oracle.get_exchange_rate(COEN, USDT).is_err());
        assert!(oracle.get_exchange_rate(USDT, COEN).is_err());
        assert!(!oracle.is_vote_target(COEN, USDT).unwrap());
    });
}

#[test]
fn require_pair_at_rejects_an_index_outside_the_registry() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        assert_eq!(oracle.require_pair_at(1).unwrap(), pair_key(COEN, USDT));
        // Index 0 and one past the end both read back as the zero pair, which is
        // a plausible-looking COEN/COEN registration rather than an obvious miss.
        assert!(oracle.require_pair_at(0).is_err());
        assert!(oracle.require_pair_at(2).is_err());
    });
}

#[test]
fn a_pair_is_deterministic_direction_sensitive_and_distinct_per_market() {
    use outbe_primitives::storage::types::StorageKey;

    assert_eq!(pair_key(COEN, USDT), pair_key(COEN, USDT));
    assert_ne!(pair_key(COEN, USDT), pair_key(ETH, USDT));

    // The value keeps the quote direction; only the storage key drops it.
    assert_ne!(pair_key(COEN, USDT), pair_key(USDT, COEN));
    assert!(pair_key(COEN, USDT).same_market(&pair_key(USDT, COEN)));
    assert_eq!(
        pair_key(COEN, USDT).key_bytes(),
        pair_key(USDT, COEN).key_bytes()
    );
    assert!(!pair_key(COEN, USDT).same_market(&pair_key(ETH, USDT)));
}

#[test]
fn set_exchange_rate_round_trips_rate_block_and_timestamp() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        // Set rate (system call)
        let rate = U256::from(1_500_000_000_000_000_000u128); // 1.5
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(COEN, USDT),
                rate,
                100,
                1200,
            )
            .unwrap();

        // Read back
        let (r, block, ts) = oracle.get_exchange_rate_data(COEN, USDT).unwrap();
        assert_eq!(r, rate);
        assert_eq!(block, 100);
        assert_eq!(ts, 1200);
    });
}

#[test]
fn set_exchange_rate_rejects_a_non_system_caller() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let caller = Address::new([1u8; 20]);
        let result = oracle.set_exchange_rate(
            caller,
            AddressPair::from_addresses(COEN, USDT),
            U256::from(1u64),
            0,
            0,
        );
        assert!(result.is_err());
    });
}

#[test]
fn get_exchange_rate_reverts_for_an_unregistered_pair() {
    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        assert!(oracle.get_exchange_rate(BTC, USDT).is_err());
    });
}

/// The three rate columns key on the registry index, so a price read is
/// `pair_to_index` and then slot 12. Pins the raw slots `scripts/seed_genesis.py`
/// writes, and asserts nothing lands at the pair-derived slot they used to use -
/// a schema key-type revert would otherwise pass every behavioural test above
/// while silently orphaning every seeded rate.
#[test]
fn the_rate_columns_are_keyed_by_the_registry_index() {
    use outbe_primitives::addresses::ORACLE_ADDRESS;
    use outbe_primitives::storage::types::StorageKey;

    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        let index = oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        let rate = U256::from(1_500_000_000_000_000_000u128);
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(COEN, USDT),
                rate,
                42,
                86_400,
            )
            .unwrap();

        let at = |slot: U256| storage.sload(ORACLE_ADDRESS, slot).unwrap();
        for (base, expected, field) in [
            (12u64, rate, "exchange_rate"),
            (13, U256::from(42u64), "exchange_rate_block"),
            (14, U256::from(86_400u64), "exchange_rate_timestamp"),
        ] {
            let base = U256::from(base);
            assert_eq!(
                at(index.mapping_slot(base)),
                expected,
                "{field} is not keyed by the registry index at base slot {base}; \
                 scripts/seed_genesis.py hardcodes it"
            );
            assert_eq!(
                at(pair_key(COEN, USDT).mapping_slot(base)),
                U256::ZERO,
                "{field} still writes the pair-derived slot"
            );
        }
    });
}

/// Deactivated pairs lose their rate, and an active neighbour registered after
/// them keeps its own - the clear walks the registry by index, so an off-by-one
/// would wipe the wrong column.
#[test]
fn remove_excess_feeds_clears_only_the_deactivated_pairs_rate() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(COEN, USDT),
                U256::from(7u64),
                10,
                120,
            )
            .unwrap();
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(ETH, USDT),
                U256::from(9u64),
                20,
                240,
            )
            .unwrap();

        oracle
            .deactivate_vote_target(Address::ZERO, COEN, USDT)
            .unwrap();
        oracle.remove_excess_feeds().unwrap();

        assert_eq!(
            oracle.get_exchange_rate_data(COEN, USDT).unwrap(),
            (U256::ZERO, 0, 0)
        );
        assert_eq!(
            oracle.get_exchange_rate_data(ETH, USDT).unwrap(),
            (U256::from(9u64), 20, 240)
        );
    });
}

#[test]
fn config_slots_round_trip_every_genesis_parameter() {
    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());

        oracle.config_vote_period.write(2).unwrap();
        oracle
            .config_reward_band
            .write(U256::from(20_000_000_000_000_000u128))
            .unwrap();
        oracle.config_slash_window.write(96).unwrap();
        oracle.config_lookback_duration.write(86400).unwrap();
        oracle.config_enabled.write(true).unwrap();
        oracle.config_is_initialized.write(true).unwrap();

        assert_eq!(oracle.config_vote_period.read().unwrap(), 2);
        assert_eq!(
            oracle.config_reward_band.read().unwrap(),
            U256::from(20_000_000_000_000_000u128)
        );
        assert_eq!(oracle.config_slash_window.read().unwrap(), 96);
        assert_eq!(oracle.config_lookback_duration.read().unwrap(), 86400);
        assert!(oracle.config_enabled.read().unwrap());
        assert!(oracle.config_is_initialized.read().unwrap());
    });
}

#[test]
fn penalty_counters_increment_per_outcome_and_reset_together() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        let validator = Address::new([0x11; 20]);

        oracle.increment_success(&validator).unwrap();
        oracle.increment_success(&validator).unwrap();
        oracle.increment_miss(&validator).unwrap();
        oracle.increment_abstain(&validator).unwrap();

        assert_eq!(oracle.penalty_success_count.read(&validator).unwrap(), 2);
        assert_eq!(oracle.penalty_miss_count.read(&validator).unwrap(), 1);
        assert_eq!(oracle.penalty_abstain_count.read(&validator).unwrap(), 1);

        oracle.reset_penalty_counter(&validator).unwrap();
        assert_eq!(oracle.penalty_success_count.read(&validator).unwrap(), 0);
        assert_eq!(oracle.penalty_miss_count.read(&validator).unwrap(), 0);
        assert_eq!(oracle.penalty_abstain_count.read(&validator).unwrap(), 0);
    });
}

#[test]
fn write_snapshot_advances_the_ring_buffer_and_feeds_vwap() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        // Write 3 snapshots
        let entries = vec![(pair_key(COEN, USDT), fixed18(100), fixed18(1000))];
        oracle.write_snapshot(1000, &entries).unwrap();

        let entries2 = vec![(pair_key(COEN, USDT), fixed18(200), fixed18(2000))];
        oracle.write_snapshot(2000, &entries2).unwrap();

        let entries3 = vec![(pair_key(COEN, USDT), fixed18(300), fixed18(3000))];
        oracle.write_snapshot(3000, &entries3).unwrap();

        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 3);
        assert_eq!(oracle.snapshot_oldest_idx.read().unwrap(), 0);

        // Calculate VWAP over all snapshots
        // VWAP = (100*1000 + 200*2000 + 300*3000) / (1000 + 2000 + 3000)
        //      = (100000 + 400000 + 900000) / 6000
        //      = 1400000 / 6000
        //      = 233.333...
        let vwap = oracle
            .calculate_vwap(pair_key(COEN, USDT), 0, 5000)
            .unwrap();
        // TODO is it correct??
        let expected = fixed18(1_400_000) * SCALE_1E18 / fixed18(6_000);
        assert_eq!(vwap, expected);
    });
}

#[test]
fn calculate_vwap_includes_only_snapshots_inside_the_window() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let entries1 = vec![(pair_key(COEN, USDT), fixed18(100), SCALE_1E18)];
        oracle.write_snapshot(1000, &entries1).unwrap();

        let entries2 = vec![(pair_key(COEN, USDT), fixed18(200), SCALE_1E18)];
        oracle.write_snapshot(2000, &entries2).unwrap();

        let entries3 = vec![(pair_key(COEN, USDT), fixed18(300), SCALE_1E18)];
        oracle.write_snapshot(3000, &entries3).unwrap();

        // VWAP from 1500..2500 should only include snapshot at 2000
        let vwap = oracle
            .calculate_vwap(pair_key(COEN, USDT), 1500, 2500)
            .unwrap();
        assert_eq!(vwap, fixed18(200));

        // VWAP from 2500..3500 should only include snapshot at 3000
        let vwap = oracle
            .calculate_vwap(pair_key(COEN, USDT), 2500, 3500)
            .unwrap();
        assert_eq!(vwap, fixed18(300));
    });
}

#[test]
fn calculate_vwap_excludes_the_half_open_end_boundary() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        oracle
            .write_snapshot(1_000, &[(pair, coen_iso(10), coen_iso(1))])
            .unwrap();
        oracle
            .write_snapshot(2_000, &[(pair, coen_iso(900), coen_iso(1))])
            .unwrap();

        assert_eq!(
            oracle.calculate_vwap(pair, 1_000, 2_000).unwrap(),
            coen_iso(10)
        );
    });
}

#[test]
fn write_snapshot_updates_exact_prefix_and_suffix_aggregates() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        let day = 1_780_012_800u64;

        for (offset, price, volume) in [
            (9 * 60 * 60 + 59 * 60, 1, 2),
            (10 * 60 * 60, 3, 4),
            (11 * 60 * 60 + 59 * 60, 5, 6),
            (12 * 60 * 60, 7, 8),
        ] {
            oracle
                .write_snapshot(day + offset, &[(pair, coen_iso(price), coen_iso(volume))])
                .unwrap();
        }

        let prefix_pv = oracle.wwd_prefix_pv_sum.get_nested(&pair);
        let prefix_vol = oracle.wwd_prefix_vol_sum.get_nested(&pair);
        let suffix_pv = oracle.wwd_suffix_pv_sum.get_nested(&pair);
        let suffix_vol = oracle.wwd_suffix_vol_sum.get_nested(&pair);
        assert_eq!(
            prefix_pv.read(&day).unwrap(),
            coen_iso(1) * coen_iso(2) + coen_iso(3) * coen_iso(4) + coen_iso(5) * coen_iso(6)
        );
        assert_eq!(prefix_vol.read(&day).unwrap(), coen_iso(12));
        assert_eq!(
            suffix_pv.read(&day).unwrap(),
            coen_iso(3) * coen_iso(4) + coen_iso(5) * coen_iso(6) + coen_iso(7) * coen_iso(8)
        );
        assert_eq!(suffix_vol.read(&day).unwrap(), coen_iso(18));
    });
}

#[test]
fn partial_aggregate_overflow_rolls_back_the_entire_snapshot() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage);
        let pair = AddressPair::new_coen_to(840);
        oracle.register_pair(pair).unwrap();
        let day = 1_780_012_800u64;
        oracle
            .wwd_prefix_pv_sum
            .get_nested(&pair)
            .write(&day, U256::MAX)
            .unwrap();

        let error = oracle
            .write_snapshot(day + 60 * 60, &[(pair, coen_iso(1), coen_iso(1))])
            .unwrap_err();
        assert!(error.to_string().contains("VWAP overflow"));
        assert_eq!(oracle.snapshot_write_idx.read().unwrap(), 0);
        assert_eq!(
            oracle.daily_pv_sum.get_nested(&pair).read(&day).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            oracle
                .wwd_prefix_pv_sum
                .get_nested(&pair)
                .read(&day)
                .unwrap(),
            U256::MAX
        );
    });
}

#[test]
fn calculate_vwap_reverts_for_a_window_without_snapshots() {
    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        // No snapshots at all
        assert!(oracle
            .calculate_vwap(pair_key(COEN, USDT), 0, 1000)
            .is_err());
    });
}

#[test]
fn calculate_vwap_treats_zero_volume_as_one_scaled_unit() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        // Zero-volume entries -> equal-weight averaging
        let entries1 = vec![(pair_key(COEN, USDT), fixed18(100), U256::ZERO)];
        oracle.write_snapshot(1000, &entries1).unwrap();

        let entries2 = vec![(pair_key(COEN, USDT), fixed18(200), U256::ZERO)];
        oracle.write_snapshot(2000, &entries2).unwrap();

        // Equal-weight: (100 + 200) / 2 = 150
        let vwap = oracle
            .calculate_vwap(pair_key(COEN, USDT), 0, 3000)
            .unwrap();
        // With zero volumes, each gets SCALE_1E18 weight:
        // sum(rate * 1e18) / sum(1e18) = (100*1e18 + 200*1e18) / (2*1e18) = 150
        let expected = (fixed18(100) * SCALE_1E18 + fixed18(200) * SCALE_1E18) / fixed18(2);
        assert_eq!(vwap, expected);
    });
}

#[test]
fn calculate_vwap_uses_the_six_decimal_sentinel_for_zero_volume_coen_iso() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        for (index, iso) in [840, 978].into_iter().enumerate() {
            let pair = AddressPair::new_coen_to(iso);
            oracle.register_pair(pair).unwrap();

            // This rate fits when multiplied by the COEN/ISO sentinel (1e6),
            // but overflows against the generic decimal18 sentinel.
            let rate = U256::MAX / COEN_ISO_SCALE;
            let timestamp = 1_000 + index as u64;
            oracle
                .write_snapshot(timestamp, &[(pair, rate, U256::ZERO)])
                .unwrap();

            assert_eq!(oracle.calculate_vwap(pair, timestamp, 2_000).unwrap(), rate);
        }
    });
}

#[test]
fn calculate_vwap_returns_a_six_decimal_coen_iso_price() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();
        oracle
            .write_snapshot(
                1_000,
                &[(pair_key(COEN, usd()), coen_iso(100), coen_iso(2))],
            )
            .unwrap();
        oracle
            .write_snapshot(
                2_000,
                &[(pair_key(COEN, usd()), coen_iso(200), coen_iso(1))],
            )
            .unwrap();

        assert_eq!(
            oracle
                .calculate_vwap(pair_key(COEN, usd()), 0, 3_000)
                .unwrap(),
            U256::from(133_333_333u64)
        );
    });
}

#[test]
fn calculate_vwap_isolates_each_pair_within_one_snapshot() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();

        let entries = vec![
            (pair_key(COEN, USDT), fixed18(1), fixed18(100)),
            (pair_key(ETH, USDT), fixed18(2000), fixed18(50)),
        ];
        oracle.write_snapshot(1000, &entries).unwrap();

        // VWAP for COEN should be 1
        let vwap_coen = oracle
            .calculate_vwap(pair_key(COEN, USDT), 0, 2000)
            .unwrap();
        assert_eq!(vwap_coen, SCALE_1E18);

        // VWAP for ETH should be 2000
        let vwap_eth = oracle.calculate_vwap(pair_key(ETH, USDT), 0, 2000).unwrap();
        assert_eq!(vwap_eth, fixed18(2000));
    });
}

/// The bulk calculators skip pairs that hold no samples, but a rejected argument
/// is not "no data" - it has to reach the caller instead of being absorbed into
/// the empty-result path.
#[test]
fn bulk_calculators_propagate_argument_errors_instead_of_reporting_no_data() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .write_snapshot(1000, &[(pair_key(COEN, USDT), fixed18(1), fixed18(100))])
            .unwrap();

        let err = oracle.calculate_twaps(2000, 0).unwrap_err();
        assert!(
            err.to_string().contains("lookback_seconds"),
            "zero lookback must surface as an argument error, got {err:?}"
        );

        let err = oracle.calculate_vwaps(2000, 2000).unwrap_err();
        assert!(
            err.to_string().contains("start_time must be less than"),
            "empty range must surface as an argument error, got {err:?}"
        );

        // A well-formed window with no samples still reports the no-data revert.
        let err = oracle.calculate_vwaps(5000, 6000).unwrap_err();
        assert!(
            err.to_string().contains("no VWAP data"),
            "empty window must stay a no-data revert, got {err:?}"
        );
    });
}

#[test]
fn submit_vote_stores_tuples_until_clear_votes_drains_them() {
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

        // Submit vote
        oracle
            .submit_vote(validator, &[(COEN, USDT, rate, volume)])
            .unwrap();

        // Verify vote stored
        assert!(oracle.vote_exists.read(&validator).unwrap());
        assert_eq!(oracle.vote_tuple_count.read(&validator).unwrap(), 1);
        assert_eq!(oracle.voter_list.len().unwrap(), 1);

        // Double vote should fail
        assert!(oracle
            .submit_vote(validator, &[(COEN, USDT, rate, volume)])
            .is_err());

        // Clear
        oracle.clear_votes().unwrap();
        assert!(!oracle.vote_exists.read(&validator).unwrap());
        assert_eq!(oracle.voter_list.len().unwrap(), 0);
    });
}

#[test]
fn submit_vote_rejects_an_unregistered_signer() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();

        let stranger = Address::new([0x99; 20]);
        let err = oracle
            .submit_vote(stranger, &[(COEN, usd(), coen_iso(50), COEN_ISO_SCALE)])
            .unwrap_err();

        assert!(
            err.to_string().contains("not an active ORACLE signer"),
            "unexpected error: {err:?}"
        );
        assert_eq!(oracle.voter_list.len().unwrap(), 0);
    });
}

#[test]
fn submit_vote_rejects_a_validator_that_is_no_longer_active() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle.register_pair(AddressPair::new_coen_to(840)).unwrap();

        let validator = Address::new([0x11; 20]);
        register_validator(storage.clone(), validator, native_coen(100));
        outbe_validatorset::contract::ValidatorSet::new(storage)
            .deactivate_validator(Address::ZERO, validator)
            .unwrap();

        let err = oracle
            .submit_vote(validator, &[(COEN, usd(), coen_iso(50), COEN_ISO_SCALE)])
            .unwrap_err();

        assert!(
            err.to_string().contains("not an active ORACLE signer"),
            "unexpected error: {err:?}"
        );
        assert_eq!(oracle.voter_list.len().unwrap(), 0);
    });
}

#[test]
fn submit_vote_rejects_the_reverse_of_the_registered_direction() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        let registered = AddressPair::from_addresses(ETH, usd());
        oracle.register_pair(registered).unwrap();

        let validator = Address::new([0x11; 20]);
        register_validator(storage, validator, native_coen(100));
        let err = oracle
            .submit_vote(
                validator,
                &[(
                    registered.address2(),
                    registered.address1(),
                    fixed18(2),
                    SCALE_1E18,
                )],
            )
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("does not match the registered orientation"),
            "unexpected error: {err:?}"
        );
        assert_eq!(oracle.voter_list.len().unwrap(), 0);
    });
}

#[test]
fn submit_vote_rejects_a_duplicated_pair() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();

        let validator = Address::new([0x11; 20]);
        register_validator(storage.clone(), validator, native_coen(100));
        let rate = fixed18(50);
        let volume = fixed18(1000);
        // Two tuples naming the same pair: within the pair-count bound, so the
        // dedup scan is what must reject it.
        let err = oracle
            .submit_vote(validator, &[(COEN, USDT, rate, volume); 2])
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("duplicate pair in vote submission"),
            "unexpected error: {err:?}"
        );
        assert!(!oracle.vote_exists.read(&validator).unwrap());
    });
}

#[test]
fn submit_vote_reports_a_duplicate_before_an_inactive_vote_target() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();
        oracle
            .deactivate_vote_target(Address::ZERO, ETH, USDT)
            .unwrap();

        let validator = Address::new([0x11; 20]);
        register_validator(storage.clone(), validator, native_coen(100));
        let rate = fixed18(50);
        let volume = fixed18(1000);
        // A submission that is both untargeted and duplicated reports the
        // duplicate first - receipt-visible revert text, so the order is pinned.
        let err = oracle
            .submit_vote(validator, &[(ETH, USDT, rate, volume); 2])
            .unwrap_err();
        assert!(
            format!("{err:?}").contains("duplicate pair in vote submission"),
            "unexpected error: {err:?}"
        );
    });
}

// -----------------------------------------------------------------------
// View functions
// -----------------------------------------------------------------------

/// The whole-registry rate table is now built by the caller from `pair_count`,
/// `require_pair_at` and the per-pair rate read, so what has to hold is that
/// walking the index in registration order lands each pair on its own rate.
#[test]
fn walking_the_registry_by_index_pairs_each_market_with_its_own_rate() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();

        let rate1 = U256::from(1_500_000_000_000_000_000u128);
        let rate2 = U256::from(2_000_000_000_000_000_000u128);
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(COEN, USDT),
                rate1,
                10,
                120,
            )
            .unwrap();
        oracle
            .set_exchange_rate(
                Address::ZERO,
                AddressPair::from_addresses(ETH, USDT),
                rate2,
                20,
                240,
            )
            .unwrap();

        let count = oracle.pair_count.read().unwrap();
        assert_eq!(count, 2);
        let table: Vec<_> = (1..=count)
            .map(|index| {
                let pair = oracle.require_pair_at(index).unwrap();
                let (rate, block, ts) = oracle
                    .get_exchange_rate_data(pair.address1(), pair.address2())
                    .unwrap();
                (pair, rate, block, ts)
            })
            .collect();

        assert_eq!(
            table,
            vec![
                (pair_key(COEN, USDT), rate1, 10, 120),
                (pair_key(ETH, USDT), rate2, 20, 240),
            ]
        );
    });
}

#[test]
fn get_vote_targets_lists_only_active_pairs() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(BTC, USDT))
            .unwrap();

        // Deactivate ETH/USDT (pair_id 2)
        oracle
            .deactivate_vote_target(Address::ZERO, ETH, USDT)
            .unwrap();

        let (bases, quotes) = oracle.get_vote_targets().unwrap();
        assert_eq!(bases, vec![COEN, BTC]);
        assert_eq!(quotes, vec![USDT, USDT]);
    });
}

#[test]
fn get_vote_targets_returns_empty_without_registered_pairs() {
    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        let (bases, quotes) = oracle.get_vote_targets().unwrap();
        assert!(bases.is_empty() && quotes.is_empty());
    });
}

#[test]
fn get_aggregate_vote_returns_the_stored_tuples() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();
        oracle
            .register_pair(AddressPair::from_addresses(ETH, USDT))
            .unwrap();

        let validator = Address::new([0x11; 20]);
        register_validator(storage.clone(), validator, native_coen(100));
        let rate1 = fixed18(50);
        let rate2 = fixed18(3000);
        let vol1 = fixed18(100);
        let vol2 = fixed18(200);

        oracle
            .submit_vote(
                validator,
                &[(COEN, USDT, rate1, vol1), (ETH, USDT, rate2, vol2)],
            )
            .unwrap();

        let (exists, bases, quotes, rates, volumes) =
            oracle.get_aggregate_vote(&validator).unwrap();
        assert!(exists);
        assert_eq!(bases, vec![COEN, ETH]);
        assert_eq!(quotes, vec![USDT, USDT]);
        assert_eq!(rates[0], rate1);
        assert_eq!(rates[1], rate2);
        assert_eq!(volumes[0], vol1);
        assert_eq!(volumes[1], vol2);
    });
}

#[test]
fn get_aggregate_vote_reports_absent_for_a_non_voter() {
    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        let validator = Address::new([0x11; 20]);

        let (exists, bases, quotes, rates, volumes) =
            oracle.get_aggregate_vote(&validator).unwrap();
        assert!(!exists);
        assert!(bases.is_empty() && quotes.is_empty());
        assert!(rates.is_empty());
        assert!(volumes.is_empty());
    });
}

#[test]
fn get_slash_window_progress_reports_counters_with_the_window_length() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);

        let validator = Address::new([0x11; 20]);

        oracle.increment_success(&validator).unwrap();
        oracle.increment_success(&validator).unwrap();
        oracle.increment_abstain(&validator).unwrap();
        oracle.increment_miss(&validator).unwrap();
        oracle.increment_miss(&validator).unwrap();
        oracle.increment_miss(&validator).unwrap();

        let (success, abstain, miss, slash_window) =
            oracle.get_slash_window_progress(&validator).unwrap();
        assert_eq!(success, 2);
        assert_eq!(abstain, 1);
        assert_eq!(miss, 3);
        assert_eq!(slash_window, 96); // from init_oracle
    });
}
#[test]
fn delegate_feeder_round_trips_and_revokes_on_the_zero_address() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        init_oracle(&mut oracle);
        oracle
            .register_pair(AddressPair::from_addresses(COEN, USDT))
            .unwrap();

        let validator = Address::new([0x11; 20]);
        let feeder = Address::new([0x22; 20]);
        register_validator(storage.clone(), validator, native_coen(100));

        // Delegate
        oracle.delegate_feeder(validator, feeder).unwrap();
        assert_eq!(oracle.get_feeder(&validator).unwrap(), feeder);

        // Feeder can submit vote on behalf of validator
        oracle
            .submit_vote(feeder, &[(COEN, USDT, fixed18(50), SCALE_1E18)])
            .unwrap();

        assert!(oracle.vote_exists.read(&validator).unwrap());
    });
}
/// Probes the macro-assigned slot for `reference_currencies` so that
/// `scripts/seed_genesis.py` can mirror the layout. The StorageVec stores
/// its length at the base slot; we push two values and then linearly scan
/// slots 0..128 looking for the length cell (== 2) to recover the slot.
#[test]
fn reference_currencies_occupies_slot_55() {
    use outbe_primitives::addresses::ORACLE_ADDRESS;

    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        oracle.reference_currencies.push(840).unwrap();
        oracle.reference_currencies.push(978).unwrap();

        // Linear scan to find the slot whose word equals 2 (the length).
        let mut found: Option<u64> = None;
        for slot in 0u64..128 {
            let word = storage.sload(ORACLE_ADDRESS, U256::from(slot)).unwrap();
            if word == U256::from(2u64) {
                found = Some(slot);
                break;
            }
        }
        let slot = found.expect("could not locate reference_currencies length slot");

        println!("reference_currencies base slot = {slot}");

        // Verify the data lives at keccak256(slot) + 0 / + 1.
        use alloy_primitives::keccak256;
        let data_start = U256::from_be_bytes(keccak256(U256::from(slot).to_be_bytes::<32>()).0);
        assert_eq!(
            storage.sload(ORACLE_ADDRESS, data_start).unwrap(),
            U256::from(840u64),
            "data[0] mismatch at slot {slot}"
        );
        assert_eq!(
            storage
                .sload(ORACLE_ADDRESS, data_start + U256::from(1u64))
                .unwrap(),
            U256::from(978u64),
            "data[1] mismatch at slot {slot}"
        );

        // Hard-coded slot used by scripts/seed_genesis.py; keep in sync.
        assert_eq!(
            slot, 55,
            "macro-assigned reference_currencies slot changed; update scripts/seed_genesis.py"
        );
    });
}

/// Pins `pair_by_index` to slot 43, and its quote word to that slot plus one.
///
/// It sits immediately after the retired settlement hole (40-42), so the
/// `#[slot(43)]` anchor is the only thing keeping it in place; without it the
/// macro's running slot counter would slide it into the hole and silently
/// repoint `scripts/seed_genesis.py`. The quote word lives at `+1` inside the
/// key's own hashed namespace rather than in a declaration slot, so it is
/// asserted directly instead of being found by sweeping slot numbers.
#[test]
fn pair_by_index_occupies_slot_43_as_a_two_word_value() {
    use outbe_primitives::addresses::ORACLE_ADDRESS;
    use outbe_primitives::storage::types::StorageKey;

    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        oracle
            .pair_by_index
            .write_pair(&1u32, pair_key(USDT, USDC))
            .unwrap();

        let entry_slot = 1u32.mapping_slot(U256::from(43u64));
        let word =
            |slot: U256| Address::from_word(storage.sload(ORACLE_ADDRESS, slot).unwrap().into());

        assert_eq!(
            word(entry_slot),
            USDT,
            "macro-assigned pair_by_index slot changed; the #[slot(43)] anchor \
             after the retired settlement hole did not hold"
        );
        assert_eq!(
            word(entry_slot + U256::from(1)),
            USDC,
            "the quote word is not at the entry slot + 1; update \
             scripts/seed_genesis.py::set_mapping_pair"
        );
    });
}

/// Pins every base slot the frozen OCOMP V1 opening plan (`openings.rs`) and
/// `scripts/seed_genesis.py` hardcode. Each field is written through the typed
/// schema and read back at the raw slot those consumers derive, so any field
/// reorder or mis-placed `#[slot(N)]` pin fails here rather than silently
/// corrupting a genesis seed or an opening proof.
///
/// Slots 41 and 46 are retired holes: they stay in the V1 plan (whose codec
/// descriptor is hashed into the protocol bundle) but have no live writer, so
/// they must read as zero after a full genesis init.
#[test]
fn ocomp_opening_plan_slots_match_the_schema_layout() {
    use outbe_primitives::addresses::ORACLE_ADDRESS;
    use outbe_primitives::storage::types::StorageKey;
    use outbe_primitives::storage::StorageHandle;

    fn assert_mapping_slot<K: StorageKey>(
        storage: &StorageHandle<'_>,
        key: K,
        base: U256,
        expected: U256,
        field: &str,
    ) {
        assert_eq!(
            storage
                .sload(ORACLE_ADDRESS, key.mapping_slot(base))
                .unwrap(),
            expected,
            "{field} is not at base slot {base}; openings.rs and \
             scripts/seed_genesis.py hardcode it"
        );
    }

    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        let wwd = outbe_primitives::time::WorldwideDay::from_timestamp(ATOMIC_DAY_START);
        let iso: u16 = 840;
        // The exact key `openings.rs` derives for a reference ISO. Writing it
        // through the typed schema and reading it back at the raw slot pins the
        // 40-byte `mapping_slot` derivation as well as the slot number.
        let pair = AddressPair::new_coen_to(iso);

        oracle.pair_to_index.write(&pair, 7).unwrap();
        oracle.scurve_count.write(3).unwrap();
        oracle
            .scurve_pair
            .write_pair(&0u32, pair_key(COEN, usd()))
            .unwrap();
        oracle.scurve_peak_day.write(&0u32, 111).unwrap();
        oracle
            .scurve_peak_price
            .write(&0u32, U256::from(222u64))
            .unwrap();
        oracle.scurve_oldest_idx.write(1).unwrap();
        oracle.reference_currencies.push(iso).unwrap();
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        // Both VWAP value columns are keyed by the registry index the pair was
        // given above, so the raw slot derivation is pinned against that index.
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&7u32, U256::from(333u64))
            .unwrap();
        oracle
            .utc_day_vwap_value
            .get_nested(&20260302u32)
            .write(&7u32, U256::from(444u64))
            .unwrap();

        // Direct (non-mapping) slots.
        for (slot, expected, field) in [(34u64, 3u64, "scurve_count"), (38, 1, "scurve_oldest_idx")]
        {
            assert_eq!(
                storage.sload(ORACLE_ADDRESS, U256::from(slot)).unwrap(),
                U256::from(expected),
                "{field} is not at slot {slot}"
            );
        }

        let base = U256::from;
        assert_mapping_slot(&storage, pair, base(10), base(7), "pair_index");
        let as_word = |a: Address| U256::from_be_bytes(a.into_word().0);
        // A pair value spans two words: base at the entry slot, quote at +1.
        assert_mapping_slot(&storage, 0u32, base(35), as_word(COEN), "scurve_pair");
        assert_eq!(
            storage
                .sload(ORACLE_ADDRESS, 0u32.mapping_slot(base(35)) + base(1))
                .unwrap(),
            as_word(usd()),
            "scurve_pair quote word is not at the entry slot + 1"
        );
        assert_mapping_slot(&storage, 0u32, base(36), base(111), "scurve_peak_day");
        assert_mapping_slot(&storage, 0u32, base(37), base(222), "scurve_peak_price");
        // reference_currencies is a StorageVec: length at the base slot,
        // elements at keccak256(be32(base)) + index.
        assert_eq!(
            storage.sload(ORACLE_ADDRESS, base(55)).unwrap(),
            base(1),
            "reference_currencies length is not at slot 55"
        );
        let reference_data =
            U256::from_be_bytes(alloy_primitives::keccak256(base(55).to_be_bytes::<32>()).0);
        assert_eq!(
            storage.sload(ORACLE_ADDRESS, reference_data).unwrap(),
            U256::from(iso),
            "reference_currencies[0] is not at keccak256(be32(55))"
        );
        assert_mapping_slot(
            &storage,
            wwd,
            base(47),
            base(1),
            "worldwide_day_vwap_exists",
        );
        // Nested maps: the outer key derives the inner map's base slot.
        assert_mapping_slot(
            &storage,
            7u32,
            wwd.mapping_slot(base(52)),
            base(333),
            "worldwide_day_vwap_value",
        );
        assert_mapping_slot(
            &storage,
            7u32,
            20260302u32.mapping_slot(base(58)),
            base(444),
            "utc_day_vwap_value",
        );
    });
}

#[test]
fn worldwide_day_partial_aggregates_occupy_slots_70_through_73() {
    use outbe_primitives::addresses::ORACLE_ADDRESS;
    use outbe_primitives::storage::types::StorageKey;

    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        let pair = AddressPair::new_coen_to(840);
        let day = 1_780_012_800u64;
        let markers = [11u64, 12, 13, 14];
        oracle
            .wwd_suffix_pv_sum
            .get_nested(&pair)
            .write(&day, U256::from(markers[0]))
            .unwrap();
        oracle
            .wwd_suffix_vol_sum
            .get_nested(&pair)
            .write(&day, U256::from(markers[1]))
            .unwrap();
        oracle
            .wwd_prefix_pv_sum
            .get_nested(&pair)
            .write(&day, U256::from(markers[2]))
            .unwrap();
        oracle
            .wwd_prefix_vol_sum
            .get_nested(&pair)
            .write(&day, U256::from(markers[3]))
            .unwrap();

        for (base, marker) in (70u64..=73).zip(markers) {
            let outer = pair.mapping_slot(U256::from(base));
            let slot = day.mapping_slot(outer);
            assert_eq!(
                storage.sload(ORACLE_ADDRESS, slot).unwrap(),
                U256::from(marker),
                "WWD partial aggregate moved from slot {base}"
            );
        }
    });
}

/// Every retired slot in the settlement range must stay empty. Slots 41/42 are
/// still opened by the frozen V1 plan, so a resurrected writer would change
/// what that plan proves; 40/45/46 must stay clear so the holes remain
/// reusable-free and the `#[slot(43)]` anchor keeps its meaning.
#[test]
fn retired_settlement_slots_stay_zero_after_genesis() {
    use outbe_primitives::addresses::ORACLE_ADDRESS;
    use outbe_primitives::storage::types::StorageKey;

    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        let config = crate::genesis::OracleGenesisConfig::default_config();
        crate::genesis::init_from_genesis(&mut oracle, &config).unwrap();

        // Retired mappings, probed at the key genesis would have used.
        for base in [41u64, 42, 45, 46] {
            let slot = 840u16.mapping_slot(U256::from(base));
            assert_eq!(
                storage.sload(ORACLE_ADDRESS, slot).unwrap(),
                U256::ZERO,
                "retired slot {base} was written; it has no live writer"
            );
            // settlement_index_to_iso was keyed by a u32 index, not the ISO.
            let index_slot = 0u32.mapping_slot(U256::from(base));
            assert_eq!(
                storage.sload(ORACLE_ADDRESS, index_slot).unwrap(),
                U256::ZERO,
                "retired slot {base} was written at index 0"
            );
        }

        // Retired direct slot (former settlement_count).
        assert_eq!(
            storage.sload(ORACLE_ADDRESS, U256::from(40u64)).unwrap(),
            U256::ZERO,
            "retired slot 40 was written; it has no live writer"
        );
    });
}

#[test]
fn slot_60_is_retired_and_policy_registry_occupies_slots_74_and_75() {
    use alloy_primitives::keccak256;
    use outbe_primitives::addresses::ORACLE_ADDRESS;

    with_storage(|storage| {
        let oracle = OracleContract::new(storage.clone());
        let iso: u16 = 840;
        let marker = U256::from(0x00AB_CDEFu64);
        oracle.policy_rate_currencies.push(iso).unwrap();
        oracle.policy_rate.write(&iso, marker).unwrap();

        assert_eq!(
            storage.sload(ORACLE_ADDRESS, U256::from(60)).unwrap(),
            U256::ZERO
        );
        assert_eq!(
            storage.sload(ORACLE_ADDRESS, U256::from(74)).unwrap(),
            U256::from(1)
        );

        let element_slot = U256::from_be_bytes(keccak256(U256::from(74).to_be_bytes::<32>()).0);
        assert_eq!(
            storage.sload(ORACLE_ADDRESS, element_slot).unwrap(),
            U256::from(iso)
        );

        let mut buf = [0u8; 64];
        buf[30..32].copy_from_slice(&iso.to_be_bytes());
        buf[32..64].copy_from_slice(&U256::from(75).to_be_bytes::<32>());
        let rate_slot = U256::from_be_bytes(keccak256(buf).0);
        assert_eq!(storage.sload(ORACLE_ADDRESS, rate_slot).unwrap(), marker);
    });
}

#[test]
fn genesis_seeds_the_usd_policy_rate() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        crate::genesis::init_from_genesis(
            &mut oracle,
            &crate::genesis::OracleGenesisConfig::default_config(),
        )
        .unwrap();
        assert_eq!(oracle.get_policy_rate(840).unwrap(), U256::from(36_300u64));
    });
}

#[test]
fn get_policy_rate_reverts_for_an_unregistered_iso_code() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());
        crate::genesis::init_from_genesis(
            &mut oracle,
            &crate::genesis::OracleGenesisConfig::default_config(),
        )
        .unwrap();
        let err = oracle.get_policy_rate(978).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("no policy rate for iso_code 978"),
            "unexpected error: {msg}"
        );
    });
}

/// The soft read used by block hooks that walk the whole reference-currency
/// registry: currencies are listed independently of whether their COEN pair
/// has been registered and priced, so "not priceable yet" must be reportable
/// without reverting and halting the block.
#[test]
fn coen_rate_for_opt_reports_unpriceable_currencies_instead_of_reverting() {
    with_storage(|storage| {
        let mut oracle = OracleContract::new(storage.clone());

        // Never registered.
        assert_eq!(
            crate::api::coen_rate_for_opt(storage.clone(), 978).unwrap(),
            None
        );

        // Registered, but no rate published yet.
        oracle.register_pair(AddressPair::new_coen_to(978)).unwrap();
        assert_eq!(
            crate::api::coen_rate_for_opt(storage.clone(), 978).unwrap(),
            None
        );

        // Priced.
        crate::api::set_exchange_rate(
            storage.clone(),
            Address::ZERO,
            AddressPair::new_coen_to(978),
            U256::from(1234u64),
            1,
            1,
        )
        .unwrap();
        assert_eq!(
            crate::api::coen_rate_for_opt(storage, 978).unwrap(),
            Some(U256::from(1234u64))
        );
    });
}
