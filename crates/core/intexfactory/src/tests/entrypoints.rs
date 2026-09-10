use super::*;

#[test]
fn dispatch_set_authorized_settler_round_trip() {
    with_factory(|s| {
        let settler = address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let data = IIntexFactory::setAuthorizedSettlerCall {
            seriesId: sid(7).into(),
            settler,
        }
        .abi_encode();
        // Caller (holder) is taken from msg.sender, not the calldata.
        precompile::dispatch(s.clone(), &data, holder(), U256::ZERO).unwrap();
        let f = IntexFactoryContract::new(s.clone());
        assert_eq!(
            f.read_authorized_settler(holder(), sid(7)).unwrap(),
            settler
        );
    });
}

#[test]
fn dispatch_rejects_value() {
    with_factory(|s| {
        let settler = address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let data = IIntexFactory::setAuthorizedSettlerCall {
            seriesId: sid(7).into(),
            settler,
        }
        .abi_encode();
        assert!(precompile::dispatch(s.clone(), &data, holder(), U256::from(1)).is_err());
    });
}

#[test]
fn dispatch_mine_promis_routes_to_runtime() {
    with_factory(|s| {
        // Missing series -> the runtime error surfaces through dispatch.
        let data = IIntexFactory::minePromisCall {
            seriesId: sid(7).into(),
            amount: U256::from(1),
            nonce: 0,
            mac: alloy_primitives::FixedBytes([0u8; 32]),
            opNonce: 0,
        }
        .abi_encode();
        assert!(precompile::dispatch(s.clone(), &data, holder(), U256::ZERO).is_err());
    });
}

#[test]
fn config_unset_resolves_by_chain_id() {
    with_factory(|s| {
        let f = IntexFactoryContract::new(s.clone());
        // Undo the fixture's explicit choice: an unset selector resolves by
        // network, and CHAIN_ID is not mainnet.
        f.config_profile.write(crate::config::PROFILE_AUTO).unwrap();
        assert_eq!(
            crate::config::read(&s).unwrap(),
            crate::config::IntexParams::DEV
        );
        // An explicit selector still wins over the network default.
        f.config_profile.write(crate::config::PROFILE_PROD).unwrap();
        assert_eq!(
            crate::config::read(&s).unwrap(),
            crate::config::IntexParams::PROD
        );
        assert_eq!(
            crate::config::IntexParams::PROD.commit_bond_minor,
            100_000_000u128 * 1_000_000_000_000_000_000u128
        );
        assert_eq!(
            crate::config::IntexParams::DEV.commit_bond_minor,
            100u128 * 1_000_000_000_000_000_000u128
        );
    });
}

#[test]
fn config_dev_profile_drives_issuance_and_qualification() {
    with_factory(|s| {
        let mut f = IntexFactoryContract::new(s.clone());
        // Select the dev profile through the single selector byte.
        f.config_profile.write(crate::config::PROFILE_DEV).unwrap();
        assert_eq!(
            crate::config::read(&s).unwrap(),
            crate::config::IntexParams::DEV
        );

        runtime::issue(&s, sample(7)).unwrap();

        // Issuance captures the dev call-trigger and dev-derived prices.
        let dev = crate::config::IntexParams::DEV;
        let r = outbe_intex::api::read_series(&s, sid(7)).unwrap();
        assert_eq!(r.call_notice_period, dev.call_notice_period);
        assert_eq!(
            r.floor_price_minor,
            U256::from(ENTRY_PRICE * u64::from(100 + dev.floor_rate) / 100)
        );
        assert_eq!(
            r.call_price_minor,
            U256::from(ENTRY_PRICE * u64::from(100 + dev.call_rate) / 100)
        );
        assert_eq!(
            r.call_trigger(),
            outbe_intex::IntexCallTrigger {
                call_window: dev.call_window,
                call_threshold: dev.call_threshold,
                call_notice_period: dev.call_notice_period,
            }
        );

        // Promotion is the floor comparison alone: a rate one unit past the
        // dev-derived floor qualifies the day.
        let rate = r.floor_price_minor + U256::from(1);
        assert_eq!(qualify_day(&s, &mut f, 7, rate), 1);
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
fn config_unknown_selector_errors() {
    with_factory(|s| {
        let f = IntexFactoryContract::new(s.clone());
        f.config_profile.write(99u8).unwrap();
        assert!(crate::config::read(&s).is_err());
    });
}

/// The network default: only mainnet runs the real timings.
#[test]
fn config_auto_profile_follows_the_network() {
    use outbe_primitives::chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};

    assert_eq!(
        crate::config::IntexParams::for_chain_id(MAINNET_CHAIN_ID),
        crate::config::IntexParams::PROD
    );
    for chain_id in [TESTNET_CHAIN_ID, DEVNET_CHAIN_ID, 31_337] {
        assert_eq!(
            crate::config::IntexParams::for_chain_id(chain_id),
            crate::config::IntexParams::DEV
        );
    }
}

/// Pin the selector slot index: the seeder writes a raw slot, so the schema must
/// map `config_profile` to the same one.
#[test]
fn config_profile_slot_matches_seeder_layout() {
    with_factory(|s| {
        let f = IntexFactoryContract::new(s.clone());
        assert_eq!(f.config_profile.slot(), U256::from(10));
    });
}
