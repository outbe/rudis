use alloy_primitives::{B256, U256};
use outbe_oracle::api::AddressPair;
use outbe_oracle::schema::OracleContract;
use outbe_oracle::{
    evaluate_oracle_opening_v1, oracle_count_slot_plan_v1, oracle_opening_slot_plan_v1,
    OracleOcompError, MAX_OCOMP_ACTIVE_SCURVE_ENTRIES, MAX_OCOMP_REFERENCE_CURRENCIES,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::ORACLE_ADDRESS,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

const COEN_ISO_SCALE: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

fn scaled(whole: u64, scale: U256) -> U256 {
    U256::from(whole) * scale
}

fn slot_word(storage: &StorageHandle<'_>, slot: B256) -> U256 {
    storage
        .sload(ORACLE_ADDRESS, U256::from_be_bytes(slot.0))
        .unwrap()
}

/// Seeds the Oracle state both plan rounds are derived against and returns the
/// two derived settlement pairs.
fn seed_oracle(storage: &StorageHandle<'_>, day: WorldwideDay) -> (AddressPair, AddressPair) {
    let oracle = OracleContract::new(storage.clone());
    // The settlement pair is derived from the ISO code, not stored.
    let usd_pair = AddressPair::new_coen_to(840);
    let eur_pair = AddressPair::new_coen_to(978);
    oracle.pair_to_index.write(&usd_pair, 1).unwrap();
    oracle.pair_to_index.write(&eur_pair, 2).unwrap();
    oracle.reference_currencies.push(840).unwrap();
    oracle.reference_currencies.push(978).unwrap();
    oracle.worldwide_day_vwap_exists.write(&day, true).unwrap();
    // Keyed by the registry index written above, not by a per-day ordinal.
    let wwd_values = oracle.worldwide_day_vwap_value.get_nested(&day);
    wwd_values.write(&1, scaled(100, COEN_ISO_SCALE)).unwrap();
    wwd_values.write(&2, scaled(200, COEN_ISO_SCALE)).unwrap();
    // S-Curve/day-type remains specific to COEN/840; other COEN/ISO markets
    // are six-decimal VWAP markets without an S-Curve entry.
    oracle.scurve_count.write(3).unwrap();
    oracle.scurve_oldest_idx.write(2).unwrap();
    let target_day = outbe_oracle::scurve::truncate_to_day(day.to_timestamp_utc());
    oracle.scurve_pair.write_pair(&2, usd_pair).unwrap();
    oracle.scurve_peak_day.write(&2, target_day).unwrap();
    oracle
        .scurve_peak_price
        .write(&2, scaled(300, COEN_ISO_SCALE))
        .unwrap();
    (usd_pair, eur_pair)
}

#[test]
fn oracle_opening_plan_reads_the_exact_raw_slots_used_by_runtime_semantics() {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let day = WorldwideDay::new(20260715);
        let (_usd_pair, _eur_pair) = seed_oracle(&storage, day);
        let oracle = OracleContract::new(storage.clone());
        let target_day = outbe_oracle::scurve::truncate_to_day(day.to_timestamp_utc());

        // Round one: four counters, then one pair-index word per subject ISO.
        let counts = oracle_count_slot_plan_v1(day, &[840, 978]).unwrap();
        assert_eq!(
            counts
                .slots
                .iter()
                .copied()
                .map(|slot| slot_word(&storage, slot))
                .collect::<Vec<_>>(),
            vec![
                U256::from(2), // reference_currencies length
                U256::from(1), // wwd_vwap_exists
                U256::from(3), // scurve_count
                U256::from(2), // scurve_oldest
                U256::from(1), // pair_index[COEN/840]
                U256::from(2), // pair_index[COEN/978]
            ]
        );

        let plan = oracle_opening_slot_plan_v1(day, &[840, 978], 2, &[1, 2], 3, 2).unwrap();
        let raw_slots = plan
            .slots
            .iter()
            .copied()
            .map(|slot| (slot, slot_word(&storage, slot)))
            .collect::<Vec<_>>();
        assert_eq!(
            raw_slots
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>(),
            vec![
                U256::from(2),   // reference_currencies length
                U256::from(840), // reference_currencies[0]
                U256::from(978), // reference_currencies[1]
                U256::from(1),   // pair_index[COEN/840]
                U256::from(2),   // pair_index[COEN/978]
                U256::from(1),   // wwd_vwap_exists
                // One value word per subject pair, at its registry index - the
                // pair itself no longer has to be opened alongside it.
                scaled(100, COEN_ISO_SCALE), // wwd_vwap_value[1]
                scaled(200, COEN_ISO_SCALE), // wwd_vwap_value[2]
                U256::from(3),               // scurve_count
                U256::from(2),               // scurve_oldest
                // One COEN/840 S-Curve entry: pair base, pair quote, peak day,
                // peak price. COEN is the zero address and 840 encodes as
                // 0xcc840 == 837_696.
                U256::ZERO,
                U256::from(0xcc840),
                U256::from(target_day),
                scaled(300, COEN_ISO_SCALE),
            ]
        );

        let evaluated = evaluate_oracle_opening_v1(day, &[840, 978], &raw_slots).unwrap();
        for iso in [840u16, 978] {
            let pair = AddressPair::new_coen_to(iso);
            let runtime_vwap = oracle
                .get_worldwide_day_vwap_for_pair(day, oracle.pair_index_of(pair).unwrap())
                .unwrap()
                .unwrap_or(U256::ZERO);
            assert_eq!(
                evaluated.entry_price(iso),
                Some(runtime_vwap),
                "authenticated OCOMP entry prices use WWD VWAP only"
            );
        }
        assert_eq!(
            evaluated.entry_price(840),
            Some(scaled(100, COEN_ISO_SCALE))
        );
        assert_eq!(
            evaluated.entry_price(978),
            Some(scaled(200, COEN_ISO_SCALE))
        );

        let mut reordered = raw_slots;
        reordered.swap(0, 1);
        assert!(evaluate_oracle_opening_v1(day, &[840, 978], &reordered).is_err());
    });
}

/// An ISO the chain does not list as a reference currency must not evaluate,
/// even when its derived pair happens to be registered.
#[test]
fn oracle_opening_rejects_an_iso_outside_the_on_chain_reference_list() {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let day = WorldwideDay::new(20260715);
        seed_oracle(&storage, day);
        // 826 (GBP) has a registered pair but is absent from slot 55.
        let oracle = OracleContract::new(storage.clone());
        oracle
            .pair_to_index
            .write(&AddressPair::new_coen_to(826), 3)
            .unwrap();

        let plan = oracle_opening_slot_plan_v1(day, &[826, 840, 978], 2, &[3, 1, 2], 3, 2).unwrap();
        let raw_slots = plan
            .slots
            .iter()
            .copied()
            .map(|slot| (slot, slot_word(&storage, slot)))
            .collect::<Vec<_>>();

        assert_eq!(
            evaluate_oracle_opening_v1(day, &[826, 840, 978], &raw_slots),
            Err(OracleOcompError::IsoNotAReferenceCurrency { iso: 826 })
        );
    });
}

#[test]
fn oracle_opening_plan_checks_every_cap_before_detail_allocation() {
    let day = WorldwideDay::new(20260715);
    let isos = [840u16];
    assert!(oracle_opening_slot_plan_v1(
        day,
        &isos,
        MAX_OCOMP_REFERENCE_CURRENCIES,
        &[1],
        MAX_OCOMP_ACTIVE_SCURVE_ENTRIES,
        0,
    )
    .is_ok());
    assert_eq!(
        oracle_opening_slot_plan_v1(day, &isos, MAX_OCOMP_REFERENCE_CURRENCIES + 1, &[1], 0, 0),
        Err(OracleOcompError::ReferenceCurrencyCountExceedsCap {
            actual: 257,
            cap: 256,
        })
    );
    assert_eq!(
        oracle_opening_slot_plan_v1(day, &isos, 1, &[1, 2], 0, 0),
        Err(OracleOcompError::PairIndexCountMismatch {
            actual: 2,
            expected: 1,
        })
    );
    assert_eq!(
        oracle_opening_slot_plan_v1(day, &isos, 1, &[1], MAX_OCOMP_ACTIVE_SCURVE_ENTRIES + 1, 0),
        Err(OracleOcompError::ActiveScurveCountExceedsCap {
            actual: 257,
            cap: 256,
        })
    );
    assert_eq!(
        oracle_opening_slot_plan_v1(day, &isos, 1, &[1], 2, 3),
        Err(OracleOcompError::ScurveOldestExceedsCount {
            oldest: 3,
            count: 2,
        })
    );
}

/// A pair registered *after* the day's VWAP was written still resolves: the
/// value column is keyed by the registry index, so a later registration simply
/// finds an unwritten (zero) slot rather than a mismatched entry.
#[test]
fn oracle_opening_prices_a_pair_registered_after_the_day_was_written() {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let day = WorldwideDay::new(20260715);
        seed_oracle(&storage, day);
        let oracle = OracleContract::new(storage.clone());
        // GBP joins the registry and the reference list after the fact; it has
        // no VWAP for the day and no S-curve entry.
        oracle
            .pair_to_index
            .write(&AddressPair::new_coen_to(826), 3)
            .unwrap();
        oracle.reference_currencies.push(826).unwrap();

        let plan = oracle_opening_slot_plan_v1(day, &[826, 840, 978], 3, &[3, 1, 2], 3, 2).unwrap();
        let raw_slots = plan
            .slots
            .iter()
            .copied()
            .map(|slot| (slot, slot_word(&storage, slot)))
            .collect::<Vec<_>>();

        let evaluated = evaluate_oracle_opening_v1(day, &[826, 840, 978], &raw_slots).unwrap();
        assert_eq!(evaluated.entry_price(826), Some(U256::ZERO));
        assert_eq!(
            evaluated.entry_price(840),
            Some(scaled(100, COEN_ISO_SCALE))
        );
        assert_eq!(
            evaluated.entry_price(978),
            Some(scaled(200, COEN_ISO_SCALE))
        );
    });
}
