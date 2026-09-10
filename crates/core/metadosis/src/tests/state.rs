use super::*;
use crate::{WwdDayType, WwdStatus};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::time::WorldwideDay as WwdKey;

fn as_big(value: U256) -> num_bigint::BigUint {
    num_bigint::BigUint::from_bytes_be(&value.to_be_bytes::<32>())
}

#[test]
fn closed_wwd_tags_cover_every_byte_and_reject_unknown_storage() {
    for byte in 0_u8..=u8::MAX {
        let decoded_status = WwdStatus::try_from(byte);
        let known_status = matches!(
            byte,
            status::FORMING
                | status::LOOKBACK_DELAY
                | status::OFFERING
                | status::WAITING
                | status::READY
                | status::COMPLETED
                | status::FAILED
                | status::OFFCHAIN_PENDING
        );
        assert_eq!(decoded_status.is_ok(), known_status, "status byte {byte}");
        if let Ok(status) = decoded_status {
            assert_eq!(status.as_u8(), byte);
        }

        let decoded_day_type = WwdDayType::try_from(byte);
        let known_day_type = matches!(byte, day_type::UNKNOWN | day_type::GREEN | day_type::RED);
        assert_eq!(
            decoded_day_type.is_ok(),
            known_day_type,
            "day-type byte {byte}"
        );
        if let Ok(day_type) = decoded_day_type {
            assert_eq!(day_type.as_u8(), byte);
        }
    }

    with_contract(|metadosis| {
        let status_wwd = WwdKey::new(20270101);
        metadosis
            .corrupt_wwd_status_tag(status_wwd, u8::MAX)
            .unwrap();
        assert!(matches!(
            metadosis.get_wwd_status(status_wwd),
            Err(PrecompileError::Fatal(_))
        ));

        let day_type_wwd = WwdKey::new(20270102);
        metadosis
            .corrupt_wwd_day_type_tag(day_type_wwd, u8::MAX)
            .unwrap();
        assert!(matches!(
            metadosis.get_wwd_day_type(day_type_wwd),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn fresh_devnet_sentinel_probe_is_test_only_and_checks_per_day_residue() {
    with_storage(|storage| {
        let sentinel = WwdKey::new(2099_1231);
        assert!(
            crate::test_support::fresh_devnet_sentinel_is_pristine(storage.clone(), sentinel,)
                .unwrap()
        );

        MetadosisContract::new(storage.clone())
            .ocomp_fsm_states
            .get_bytes(&sentinel)
            .write(&[1])
            .unwrap();

        assert!(
            !crate::test_support::fresh_devnet_sentinel_is_pristine(storage, sentinel,).unwrap()
        );
    });
}

#[test]
fn unknown_abi_status_reverts_and_corrupt_get_day_is_fatal() {
    with_storage(|storage| {
        let reserved_status = IMetadosis::getWorldwideDaysByStatusCall {
            status: status::RESERVED_IN_PROGRESS,
        };
        assert!(matches!(
            metadosis_dispatch(
                storage.clone(),
                &reserved_status.abi_encode(),
                Address::ZERO,
                U256::ZERO,
            ),
            Err(PrecompileError::Revert(_))
        ));

        let unknown_status = IMetadosis::getWorldwideDaysByStatusCall { status: u8::MAX };
        assert!(matches!(
            metadosis_dispatch(
                storage.clone(),
                &unknown_status.abi_encode(),
                Address::ZERO,
                U256::ZERO,
            ),
            Err(PrecompileError::Revert(_))
        ));

        let wwd = WwdKey::new(20270103);
        let mut metadosis = MetadosisContract::new(storage.clone());
        metadosis
            .create_worldwide_day(wwd, 1_000, LOOKBACK_DELAY_HOURS, OFFERING_PERIOD_HOURS)
            .unwrap();
        metadosis.corrupt_wwd_status_tag(wwd, u8::MAX).unwrap();
        let get_day = IMetadosis::getWorldwideDayCall { wwd: wwd.value() };
        assert!(matches!(
            metadosis_dispatch(storage, &get_day.abi_encode(), Address::ZERO, U256::ZERO,),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn full_domain_allocation_matches_independent_big_integer_model_and_conserves() {
    with_contract(|metadosis| {
        let wwd = WwdKey::new(20270104);
        metadosis.set_wwd_day_type(wwd, WwdDayType::Green).unwrap();

        for total in [
            U256::ZERO,
            U256::from(1_u8),
            U256::MAX.checked_sub(U256::from(1_u8)).unwrap(),
            U256::MAX,
        ] {
            let calculation = metadosis
                .calculate_metadosis(wwd, total, U256::MAX)
                .unwrap();
            let expected = (as_big(total) * 32_u8) / 100_u8;
            assert_eq!(as_big(calculation.gratis_demand), expected);
            assert_eq!(
                calculation
                    .gratis_allocation
                    .checked_add(calculation.auction_base),
                Some(total)
            );
            assert!(calculation.gratis_allocation <= calculation.gratis_supply);
        }
    });
}

#[test]
fn worldwide_day_window_accepts_exact_u64_boundary_and_rejects_the_next_value() {
    with_contract(|metadosis| {
        let duration = FORMING_PERIOD_HOURS
            .checked_add(LOOKBACK_DELAY_HOURS)
            .and_then(|hours| hours.checked_add(OFFERING_PERIOD_HOURS))
            .and_then(|hours| hours.checked_add(WAITING_PERIOD_HOURS))
            .and_then(|hours| hours.checked_mul(SECONDS_PER_HOUR))
            .unwrap();
        let exact = u64::MAX.checked_sub(duration).unwrap();
        let accepted = WwdKey::new(20270105);
        metadosis
            .create_worldwide_day(accepted, exact, LOOKBACK_DELAY_HOURS, OFFERING_PERIOD_HOURS)
            .unwrap();
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(accepted)
                .scheduled_process_time()
                .read()
                .unwrap(),
            u64::MAX
        );

        let rejected = WwdKey::new(20270106);
        assert!(matches!(
            metadosis.create_worldwide_day(
                rejected,
                exact.checked_add(1).unwrap(),
                LOOKBACK_DELAY_HOURS,
                OFFERING_PERIOD_HOURS,
            ),
            Err(PrecompileError::Revert(_))
        ));
        assert_eq!(
            metadosis
                .worldwide_days
                .entry(rejected)
                .forming_start()
                .read()
                .unwrap(),
            0
        );
    });
}

#[test]
fn test_create_worldwide_day() {
    with_contract(|m| {
        let wwd = WwdKey::new(20241220);
        let start = 1000u64;
        let lookback_h = LOOKBACK_DELAY_HOURS;
        let offering_h = OFFERING_PERIOD_HOURS;

        m.create_worldwide_day(wwd, start, lookback_h, offering_h)
            .unwrap();

        let forming_end = start + FORMING_PERIOD_HOURS * SECONDS_PER_HOUR;
        let lookback_end = forming_end + lookback_h * SECONDS_PER_HOUR;
        let offering_end = lookback_end + offering_h * SECONDS_PER_HOUR;
        let scheduled = offering_end + WAITING_PERIOD_HOURS * SECONDS_PER_HOUR;

        assert_eq!(
            m.worldwide_days.entry(wwd).forming_start().read().unwrap(),
            start
        );
        assert_eq!(
            m.worldwide_days.entry(wwd).forming_end().read().unwrap(),
            forming_end
        );
        assert_eq!(
            m.worldwide_days.entry(wwd).lookback_end().read().unwrap(),
            lookback_end
        );
        assert_eq!(
            m.worldwide_days.entry(wwd).offering_end().read().unwrap(),
            offering_end
        );
        assert_eq!(
            m.worldwide_days
                .entry(wwd)
                .scheduled_process_time()
                .read()
                .unwrap(),
            scheduled
        );

        assert_eq!(m.get_wwd_status(wwd).unwrap(), status::FORMING);
        assert_eq!(m.get_wwd_day_type(wwd).unwrap(), day_type::UNKNOWN);
    });
}

#[test]
fn test_timestamp_to_date_key() {
    assert_eq!(timestamp_to_date_key(1734652800u64), 20241220);
    assert_eq!(timestamp_to_date_key(1704067200u64), 20240101);
    assert_eq!(timestamp_to_date_key(0), 19700101);
}

#[test]
fn test_wwd_from_timestamp() {
    assert_eq!(WwdKey::from_timestamp(1734649200u64), WwdKey::new(20241220));
    assert_eq!(WwdKey::from_timestamp(1734688800u64), WwdKey::new(20241221));
}

#[test]
fn test_set_metadosis_limit_overwrites() {
    with_contract(|m| {
        let date = WwdKey::new(20241220);

        // The per-WWD limit is now a single field on the WorldwideDay record,
        // not a separate accumulating map: each write overwrites the prior value.
        m.set_metadosis_limit(date, U256::from(100u64)).unwrap();
        assert_eq!(
            m.worldwide_days
                .entry(date)
                .metadosis_limit_amount()
                .read()
                .unwrap(),
            U256::from(100u64)
        );

        m.set_metadosis_limit(date, U256::from(250u64)).unwrap();
        assert_eq!(
            m.worldwide_days
                .entry(date)
                .metadosis_limit_amount()
                .read()
                .unwrap(),
            U256::from(250u64)
        );
    });
}

#[test]
fn test_active_wwd_add_remove() {
    with_contract(|m| {
        m.add_active_wwd(WwdKey::new(20241218)).unwrap();
        m.add_active_wwd(WwdKey::new(20241219)).unwrap();
        m.add_active_wwd(WwdKey::new(20241220)).unwrap();

        let active = m.active_wwd.read_all().unwrap();
        assert_eq!(active.len(), 3);
        assert!(active.contains(&WwdKey::new(20241218)));
        assert!(active.contains(&WwdKey::new(20241219)));
        assert!(active.contains(&WwdKey::new(20241220)));

        m.remove_active_wwd(WwdKey::new(20241219)).unwrap();

        let active = m.active_wwd.read_all().unwrap();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&WwdKey::new(20241218)));
        assert!(active.contains(&WwdKey::new(20241220)));
        assert!(!active.contains(&WwdKey::new(20241219)));

        m.remove_active_wwd(WwdKey::new(20241218)).unwrap();
        m.remove_active_wwd(WwdKey::new(20241220)).unwrap();
        assert!(m.active_wwd.read_all().unwrap().is_empty());
    });
}

#[test]
fn test_calculate_metadosis_green_day() {
    with_contract(|m| {
        let wwd = WwdKey::new(20241220);
        m.fixture_set_wwd_status(wwd, WwdStatus::Ready).unwrap();
        m.set_wwd_day_type(wwd, WwdDayType::Green).unwrap();

        let tribute_total = U256::from(10_000u64);
        let day_limit = U256::from(5_000u64);

        let calc = m
            .calculate_metadosis(wwd, tribute_total, day_limit)
            .unwrap();

        // SYMBOLIC_RATE = 32, GREEN day:
        //   demand     = 10_000 * 32 / 100 = 3_200
        //   limit      = day_limit         = 5_000
        //   allocation = min(demand, limit) = 3_200
        //   auction    = min(total, limit) - allocation = 1_800
        assert_eq!(calc.gratis_allocation, U256::from(3_200u64));
        assert_eq!(calc.auction_base, U256::from(1_800u64));
    });
}

#[test]
fn test_calculate_metadosis_green_day_below_the_limit() {
    with_contract(|m| {
        let wwd = WwdKey::new(20241220);
        m.fixture_set_wwd_status(wwd, WwdStatus::Ready).unwrap();
        m.set_wwd_day_type(wwd, WwdDayType::Green).unwrap();

        let tribute_total = U256::from(1_000u64);
        let day_limit = U256::from(10_000u64);

        let calc = m
            .calculate_metadosis(wwd, tribute_total, day_limit)
            .unwrap();

        // The day earned less than the limit, so the limit does not bind:
        //   allocation = 1_000 * 32 / 100                  = 320
        //   auction    = min(1_000, 10_000) - 320          = 680
        //   unissued   = 10_000 - 320 - 680                = 9_000
        assert_eq!(calc.gratis_allocation, U256::from(320u64));
        assert_eq!(calc.auction_base, U256::from(680u64));
    });
}

#[test]
fn test_calculate_metadosis_red_day() {
    with_contract(|m| {
        let wwd = WwdKey::new(20241220);
        m.fixture_set_wwd_status(wwd, WwdStatus::Ready).unwrap();
        m.set_wwd_day_type(wwd, WwdDayType::Red).unwrap();

        let tribute_total = U256::from(10_000u64);
        let day_limit = U256::from(5_000u64);

        let calc = m
            .calculate_metadosis(wwd, tribute_total, day_limit)
            .unwrap();
        let (allocation, auction_base) = (calc.gratis_allocation, calc.auction_base);

        // SYMBOLIC_RATE = 32, RED_DAY_REDUCTION_COEF = 8, RED day:
        //   demand     = 10_000 * 32 / 100 / 8 = 400
        //   limit      = day_limit / 8         = 625
        //   allocation = min(demand, limit)     = 400
        //   auction    = min(total, day_limit) - allocation = 4_600
        assert_eq!(allocation, U256::from(400u64));
        assert_eq!(auction_base, U256::from(4_600u64));
    });
}

#[test]
fn test_calculate_metadosis_unknown_day_type_errors() {
    with_contract(|m| {
        let wwd = WwdKey::new(20241220);
        m.fixture_set_wwd_status(wwd, WwdStatus::Ready).unwrap();
        assert_eq!(
            m.worldwide_days.entry(wwd).day_type().read().unwrap(),
            day_type::UNKNOWN
        );

        let tribute_total = U256::from(10_000u64);
        let day_limit = U256::from(5_000u64);

        assert!(matches!(
            m.calculate_metadosis(wwd, tribute_total, day_limit),
            Err(outbe_primitives::error::PrecompileError::Revert(_))
        ));
    });
}

#[test]
fn test_default_timing_is_chain_identity_independent() {
    let defaults = outbe_chain_constants::GenesisProtocolParametersV1::default();
    assert_eq!(
        defaults.metadosis_lookback_delay_seconds,
        LOOKBACK_DELAY_HOURS * SECONDS_PER_HOUR
    );
    assert_eq!(
        defaults.metadosis_offering_period_seconds,
        OFFERING_PERIOD_HOURS * SECONDS_PER_HOUR
    );
}

#[test]
fn test_query_worldwide_days_by_status_via_precompile() {
    with_storage(|storage| {
        let mut metadosis = MetadosisContract::new(storage.clone());
        for (wwd, st) in [
            (WwdKey::new(20260320), status::OFFERING),
            (WwdKey::new(20260321), status::OFFERING),
            (WwdKey::new(20260322), status::FORMING),
        ] {
            metadosis
                .fixture_set_wwd_status(wwd, WwdStatus::try_from(st).unwrap())
                .unwrap();
            metadosis.add_active_wwd(wwd).unwrap();
        }

        let call_data = IMetadosis::getWorldwideDaysByStatusCall {
            status: status::OFFERING,
        }
        .abi_encode();
        let encoded = metadosis_dispatch(storage, &call_data, Address::ZERO, U256::ZERO).unwrap();
        let decoded =
            IMetadosis::getWorldwideDaysByStatusCall::abi_decode_returns(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert!(decoded.contains(&20260320));
        assert!(decoded.contains(&20260321));
    });
}

#[test]
fn test_storage_dsl_layout_slots() {
    with_contract(|m| {
        assert_eq!(m.bootstrap_end_time.slot(), U256::ZERO);
        assert_eq!(m.worldwide_days.base_slot(), U256::from(1u64));
        // WorldwideDay gained `metadosis_limit_amount`, so the record is now
        // 10 scalar slots (was 9); worldwide_days occupies slots 1..=10.
        assert_eq!(<WorldwideDay as StorageRecord>::SLOTS, 10);
        assert_eq!(m.active_wwd_count.slot(), U256::from(11u64));
        // `active_wwd` is a Set (2 slots: 12 = length, 13 = positions), so the
        // next schema field lands at 14 - this pins the Set's position too.
        // `closed_wwd` is a Deque (2 slots: 14 = begin, 15 = end).
        assert_eq!(m.closed_wwd.base_slot(), U256::from(14u64));
        assert_eq!(
            <crate::schema::WorldwideDayTerminalReceiptState as StorageRecord>::SLOTS,
            6
        );
        assert_eq!(
            m.worldwide_day_terminal_receipts.base_slot(),
            U256::from(36u64)
        );
        assert_eq!(
            <crate::schema::CapacityForfeitureReceiptState as StorageRecord>::SLOTS,
            13
        );
        assert_eq!(
            m.capacity_forfeiture_receipts.base_slot(),
            U256::from(42u64)
        );
        assert_eq!(
            <crate::schema::DayLimitFormationReceiptState as StorageRecord>::SLOTS,
            7
        );
        assert_eq!(
            m.day_limit_formation_receipts.base_slot(),
            U256::from(55u64)
        );
        // The terminal-intents field changed shape (StorageVec -> sparse
        // Mapping) but both are 1-slot fields: its base slot and every later
        // base slot must stay fixed, so the pinned layout hash is unchanged.
        assert_eq!(m.ocomp_terminal_intents.base_slot(), U256::from(24u64));
        // Order 17 remains the one-slot reserved committee bytes at slot 31;
        // the following mapping must therefore remain rooted at slot 32.
        assert_eq!(m.ocomp_vote_accountability.base_slot(), U256::from(32u64));
        assert!(m.ocomp_result_committee_snapshot.is_empty().unwrap());
        // Appended per-day terminal count lands after the last pre-existing
        // field (day-limit receipts occupy 55..=61).
        assert_eq!(m.ocomp_terminal_counts.base_slot(), U256::from(62u64));
        assert_eq!(
            alloy_primitives::keccak256(crate::proof_layout::METADOSIS_STORAGE_LAYOUT_V1_CANONICAL),
            crate::proof_layout::METADOSIS_STORAGE_LAYOUT_V1_HASH
        );
    });
}
