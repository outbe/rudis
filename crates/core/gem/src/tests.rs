use alloy_primitives::{address, Address, U256};
use alloy_sol_types::SolCall;
use outbe_oracle::schema::OracleContract;
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::math::constants::REAL_ID_SHIFT;
use outbe_primitives::math::tree_math;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::{previous_date_key, timestamp_to_date_key};

use crate::api;
use crate::config::GemParams;
use crate::precompile::{dispatch, IGem};
use crate::schema::{GemAddParams, GemContract, GemState};

const T_NOW: u64 = 1_700_000_000;
const ALICE: Address = address!("0x1111111111111111111111111111111111111111");
const BOB: Address = address!("0x2222222222222222222222222222222222222222");

fn with_storage<R>(f: impl FnOnce(&StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(1);
    storage.set_timestamp(U256::from(T_NOW));
    StorageHandle::enter(&mut storage, |handle| f(&handle))
}

fn sample_params(owner: Address) -> GemAddParams {
    GemAddParams {
        owner,
        gem_type: 2, // WALLET
        promis_load_minor: U256::from(1_000_000u64),
        entry_price_minor: U256::from(500_000u64),
        floor_price_minor: U256::from(540_000u64),
        call_price_minor: U256::from(1_140_000u64),
        call_rate: 228,
        issuance_currency: 840,
        reference_currency: 840,
        initial_state: GemState::Issued,
        issued_at: T_NOW,
    }
}

#[test]
fn coen_iso_one_maps_to_the_center_price_bin_at_six_decimals() {
    assert_eq!(
        GemContract::price_to_bin(U256::from(1_000_000u64)).unwrap(),
        REAL_ID_SHIFT as u32
    );
}

#[test]
fn initial_state_empty() {
    with_storage(|storage| {
        let gem = GemContract::new(storage.clone());
        assert_eq!(gem.total_supply().unwrap(), 0);
        assert_eq!(gem.balance_of(ALICE).unwrap(), 0);
    });
}

#[test]
fn add_gem_inserts_and_bumps_counters() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let gem = GemContract::new(storage.clone());
        assert_eq!(gem.total_supply().unwrap(), 1);
        assert_eq!(gem.balance_of(ALICE).unwrap(), 1);
        assert_eq!(gem.owner_of(gem_id).unwrap(), ALICE);
        assert_eq!(gem.token_of_owner_by_index(ALICE, 0).unwrap(), gem_id);
        let stored = api::get_gem(storage, gem_id).unwrap().unwrap();
        assert_eq!(stored.state, GemState::Issued as u8);
    });
}

#[test]
fn token_uri_exposes_rudis_metadata_without_an_external_image_host() {
    use base64::Engine as _;
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let uri = GemContract::new(storage.clone()).token_uri(gem_id).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(uri.strip_prefix("data:application/json;base64,").unwrap())
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["name"], format!("Gem #{gem_id}"));
        assert_eq!(json["description"], "Rudis Gem");
        assert!(json.get("image").is_none());
        assert!(!String::from_utf8(bytes).unwrap().contains("Outbe"));
    });
}

#[test]
fn add_gem_rejects_zero_owner() {
    with_storage(|storage| {
        let mut p = sample_params(ALICE);
        p.owner = Address::ZERO;
        assert!(api::add_gem(storage, p).is_err());
    });
}

#[test]
fn enumerable_returns_only_owned_gems() {
    with_storage(|storage| {
        let g1 = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let mut p2 = sample_params(ALICE);
        p2.promis_load_minor = U256::from(2u64);
        let g2 = api::add_gem(storage, p2).unwrap();
        let p3 = sample_params(BOB);
        let _g3 = api::add_gem(storage, p3).unwrap();

        let gem = GemContract::new(storage.clone());
        let alice_count = gem.balance_of(ALICE).unwrap();
        let alice_gems: Vec<U256> = (0..alice_count)
            .map(|i| gem.token_of_owner_by_index(ALICE, i).unwrap())
            .collect();
        assert_eq!(alice_gems.len(), 2);
        assert!(alice_gems.contains(&g1));
        assert!(alice_gems.contains(&g2));
        assert_eq!(gem.balance_of(ALICE).unwrap(), 2);
        assert_eq!(gem.balance_of(BOB).unwrap(), 1);
        assert_eq!(gem.total_supply().unwrap(), 3);
    });
}

#[test]
fn burn_requires_settled_state() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        assert!(api::burn(storage, gem_id).is_err());

        api::set_state(storage, gem_id, GemState::Qualified).unwrap();
        assert!(api::burn(storage, gem_id).is_err());

        api::set_state(storage, gem_id, GemState::Settled).unwrap();
        api::burn(storage, gem_id).unwrap();

        let gem = GemContract::new(storage.clone());
        assert_eq!(gem.total_supply().unwrap(), 0);
        assert_eq!(gem.balance_of(ALICE).unwrap(), 0);
        assert!(gem.get_gem(gem_id).unwrap().is_none());
    });
}

#[test]
fn burn_compacts_owner_index() {
    with_storage(|storage| {
        let g1 = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let mut p2 = sample_params(ALICE);
        p2.promis_load_minor = U256::from(2u64);
        let g2 = api::add_gem(storage, p2).unwrap();
        let mut p3 = sample_params(ALICE);
        p3.promis_load_minor = U256::from(3u64);
        let g3 = api::add_gem(storage, p3).unwrap();

        api::set_state(storage, g1, GemState::Settled).unwrap();
        api::burn(storage, g1).unwrap();

        let gem = GemContract::new(storage.clone());
        let count = gem.balance_of(ALICE).unwrap();
        let remaining: Vec<U256> = (0..count)
            .map(|i| gem.token_of_owner_by_index(ALICE, i).unwrap())
            .collect();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&g2));
        assert!(remaining.contains(&g3));
        assert_eq!(gem.balance_of(ALICE).unwrap(), 2);
    });
}

#[test]
fn qualify_respects_state_and_floor() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let mut gem = GemContract::new(storage.clone());
        let floor = U256::from(540_000u64);

        // Rate equals floor (strict `>`) - must NOT qualify.
        assert!(!gem.qualify(gem_id, T_NOW, 840, floor).unwrap());

        // Rate below floor.
        assert!(!gem
            .qualify(gem_id, T_NOW, 840, floor - U256::from(1u64))
            .unwrap());

        // Rate strictly above floor - qualifies.
        assert!(gem
            .qualify(gem_id, T_NOW, 840, floor + U256::from(1u64))
            .unwrap());
        let after = gem.get_gem(gem_id).unwrap().unwrap();
        assert_eq!(after.state, GemState::Qualified as u8);

        // Second qualify is a no-op (already qualified).
        assert!(!gem
            .qualify(gem_id, T_NOW, 840, floor + U256::from(1u64))
            .unwrap());
    });
}

#[test]
fn add_gem_parks_issued_in_bin_tree() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let gem = GemContract::new(storage.clone());
        let floor = U256::from(540_000u64);
        let bin = GemContract::price_to_bin(floor).unwrap();
        assert_eq!(
            gem.unqualified_bin_count
                .read(&GemContract::scoped(840, bin))
                .unwrap(),
            1
        );
        assert_eq!(
            gem.unqualified_bin_gems
                .read(&GemContract::bin_index_key(840, bin, 0))
                .unwrap(),
            gem_id
        );
        assert!(tree_math::contains(&crate::state::CurrencyBins(&gem, 840), bin).unwrap());
    });
}

#[test]
fn qualify_removes_from_bin_tree() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let mut gem = GemContract::new(storage.clone());
        let floor = U256::from(540_000u64);
        let bin = GemContract::price_to_bin(floor).unwrap();

        assert!(gem
            .qualify(gem_id, T_NOW, 840, floor + U256::from(1u64))
            .unwrap());
        assert_eq!(
            gem.unqualified_bin_count
                .read(&GemContract::scoped(840, bin))
                .unwrap(),
            0
        );
        assert!(!tree_math::contains(&crate::state::CurrencyBins(&gem, 840), bin).unwrap());
    });
}

#[test]
fn add_gem_qualified_initial_state_skips_bin_tree() {
    with_storage(|storage| {
        let mut p = sample_params(ALICE);
        p.gem_type = 0;
        p.initial_state = GemState::Qualified;
        let _gem_id = api::add_gem(storage, p.clone()).unwrap();
        let gem = GemContract::new(storage.clone());
        let bin = GemContract::price_to_bin(p.floor_price_minor).unwrap();
        assert_eq!(
            gem.unqualified_bin_count
                .read(&GemContract::scoped(840, bin))
                .unwrap(),
            0
        );
        assert!(!tree_math::contains(&crate::state::CurrencyBins(&gem, 840), bin).unwrap());
    });
}

#[test]
fn scan_skips_bins_above_rate() {
    with_storage(|storage| {
        let mut low = sample_params(ALICE);
        low.floor_price_minor = U256::from(100_000u64);
        let low_id = api::add_gem(storage, low.clone()).unwrap();

        let mut high = sample_params(BOB);
        high.floor_price_minor = U256::from(900_000u64);
        let _high_id = api::add_gem(storage, high.clone()).unwrap();

        let mut gem = GemContract::new(storage.clone());
        let rate = U256::from(500_000u64);

        // Direct qualify call on low gem: passes (floor 0.1 < rate 0.5).
        assert!(gem.qualify(low_id, T_NOW, 840, rate).unwrap());

        // High gem stays Issued (rate 0.5 < floor 0.9). It must still be
        // in its bin and the bin must still be set in the trie.
        let high_bin = GemContract::price_to_bin(high.floor_price_minor).unwrap();
        assert_eq!(
            gem.unqualified_bin_count
                .read(&GemContract::scoped(840, high_bin))
                .unwrap(),
            1
        );
        assert!(tree_math::contains(&crate::state::CurrencyBins(&gem, 840), high_bin).unwrap());
    });
}

const EUR: u16 = 978;

/// Registers `iso_code` as a reference currency, and its `COEN/<iso>` pair when
/// `rate` is given. Returns the pair index, or 0 when no pair was registered.
fn seed_currency(storage: &StorageHandle, iso_code: u16, rate: Option<U256>) -> u32 {
    let oracle = OracleContract::new(storage.clone());
    oracle.reference_currencies.push(iso_code).unwrap();
    let Some(rate) = rate else {
        return 0;
    };
    let index =
        outbe_oracle::api::register_pair(storage.clone(), AddressPair::new_coen_to(iso_code))
            .unwrap();
    oracle.exchange_rate.write(&index, rate).unwrap();
    oracle.exchange_rate_timestamp.write(&index, T_NOW).unwrap();
    index
}

fn block_ctx_at<'s>(
    storage: &StorageHandle<'s>,
    timestamp: u64,
) -> outbe_primitives::block::BlockRuntimeContext<'s> {
    outbe_primitives::block::BlockRuntimeContext::new(
        outbe_primitives::block::BlockContext::empty_for_tests(1, timestamp, 1),
        storage.clone(),
    )
}

fn block_ctx<'s>(storage: &StorageHandle<'s>) -> outbe_primitives::block::BlockRuntimeContext<'s> {
    let timestamp = storage.timestamp().unwrap().to::<u64>();
    outbe_primitives::block::BlockRuntimeContext::new(
        outbe_primitives::block::BlockContext::empty_for_tests(1, timestamp, 1),
        storage.clone(),
    )
}

fn eur_gem(storage: &StorageHandle) -> U256 {
    let mut p = sample_params(BOB);
    p.reference_currency = EUR;
    api::add_gem(storage, p).unwrap()
}

/// The bin ladder is shared across currencies, so both gems below sit in the
/// same bin: each must be promoted only by its own currency's rate.
#[test]
fn scan_qualifies_each_currency_against_its_own_rate() {
    with_storage(|storage| {
        let usd_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let eur_id = eur_gem(storage);
        let floor = sample_params(ALICE).floor_price_minor;
        assert_eq!(
            GemContract::price_to_bin(floor).unwrap(),
            GemContract::price_to_bin(sample_params(BOB).floor_price_minor).unwrap()
        );

        seed_currency(storage, 840, Some(floor + U256::from(1u64)));
        seed_currency(storage, EUR, Some(floor - U256::from(1u64)));

        crate::hooks::scan_and_qualify(&block_ctx(storage)).unwrap();
        assert_eq!(
            api::get_gem(storage, usd_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
        assert_eq!(
            api::get_gem(storage, eur_id).unwrap().unwrap().state,
            GemState::Issued as u8
        );
    });
}

/// The issuance currency is a settlement label and must never reach a lifecycle
/// decision: a gem whose two currencies differ is judged by its reference alone.
#[test]
fn a_gem_is_qualified_by_its_reference_currency_not_its_issuance_one() {
    with_storage(|storage| {
        let mut p = sample_params(ALICE);
        p.issuance_currency = EUR;
        let gem_id = api::add_gem(storage, p).unwrap();
        let floor = sample_params(ALICE).floor_price_minor;

        // The issuance currency is well above the floor, the reference one below.
        // Reading the wrong code would promote this gem.
        seed_currency(storage, 840, Some(floor - U256::from(1u64)));
        seed_currency(storage, EUR, Some(floor + U256::from(1u64)));

        crate::hooks::scan_and_qualify(&block_ctx(storage)).unwrap();
        assert_eq!(
            api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Issued as u8
        );
    });
}

/// One currency filling the whole per-block budget must not starve the ones
/// behind it: the sweep resumes where it stopped instead of restarting.
#[test]
fn a_spent_budget_defers_the_rest_of_the_currency_list_to_the_next_block() {
    with_storage(|storage| {
        let floor = sample_params(ALICE).floor_price_minor;
        // Fill USD's bin past the budget. Whole bins are processed atomically, so
        // this one sweep spends everything the block had.
        for i in 0..=crate::constants::MAX_GEM_QUALIFICATIONS_PER_BLOCK {
            let mut p = sample_params(ALICE);
            p.promis_load_minor = U256::from(1_000_000u64 + u64::from(i));
            api::add_gem(storage, p).unwrap();
        }
        let eur_id = eur_gem(storage);
        seed_currency(storage, 840, Some(floor + U256::from(1u64)));
        seed_currency(storage, EUR, Some(floor + U256::from(1u64)));

        crate::hooks::scan_and_qualify(&block_ctx(storage)).unwrap();
        assert_eq!(
            api::get_gem(storage, eur_id).unwrap().unwrap().state,
            GemState::Issued as u8,
            "USD spent the budget, so EUR was not reached this block"
        );

        crate::hooks::scan_and_qualify(&block_ctx(storage)).unwrap();
        assert_eq!(
            api::get_gem(storage, eur_id).unwrap().unwrap().state,
            GemState::Qualified as u8,
            "the next block resumes at EUR rather than restarting at USD"
        );
    });
}

/// A registry entry whose COEN pair is unregistered must skip that currency for
/// the block, not halt the scan for the currencies that are priced.
#[test]
fn scan_skips_a_currency_without_a_priced_pair() {
    with_storage(|storage| {
        let usd_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let eur_id = eur_gem(storage);
        let floor = sample_params(ALICE).floor_price_minor;

        seed_currency(storage, 840, Some(floor + U256::from(1u64)));
        seed_currency(storage, EUR, None);

        crate::hooks::scan_and_qualify(&block_ctx(storage)).unwrap();
        assert_eq!(
            api::get_gem(storage, usd_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
        assert_eq!(
            api::get_gem(storage, eur_id).unwrap().unwrap().state,
            GemState::Issued as u8
        );
    });
}

#[test]
fn scan_skips_a_currency_with_a_stale_rate() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();
        let floor = sample_params(ALICE).floor_price_minor;
        seed_currency(storage, 840, Some(floor + U256::from(1u64)));
        storage
            .set_block_timestamp(U256::from(
                T_NOW + outbe_oracle::constants::FX_RATE_MAX_AGE_SECONDS + 1,
            ))
            .unwrap();

        crate::hooks::scan_and_qualify(&block_ctx(storage)).unwrap();
        assert_eq!(
            api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Issued as u8
        );
    });
}

/// A sweep cut short by the budget must resume from its persisted bin cursor.
#[test]
fn qualify_resumes_from_the_bin_cursor_after_the_budget_runs_out() {
    with_storage(|storage| {
        let mut low = sample_params(ALICE);
        low.floor_price_minor = U256::from(100_000u64);
        let low_id = api::add_gem(storage, low).unwrap();
        let mut high = sample_params(BOB);
        high.floor_price_minor = U256::from(200_000u64);
        let high_id = api::add_gem(storage, high).unwrap();

        let rate = U256::from(500_000u64);
        let ctx = block_ctx(storage);

        // Budget of one: only the lower bin is drained this block.
        assert_eq!(
            crate::hooks::qualify_with_rate(&ctx, 840, rate, 1).unwrap(),
            1
        );
        assert_eq!(
            api::get_gem(storage, high_id).unwrap().unwrap().state,
            GemState::Issued as u8
        );
        assert!(
            GemContract::new(storage.clone())
                .qualify_scan_cursor
                .read(&840)
                .unwrap()
                > 0
        );

        // Next block picks up where it stopped, then resets for a fresh sweep.
        assert_eq!(
            crate::hooks::qualify_with_rate(&ctx, 840, rate, 256).unwrap(),
            1
        );
        for id in [low_id, high_id] {
            assert_eq!(
                api::get_gem(storage, id).unwrap().unwrap().state,
                GemState::Qualified as u8
            );
        }
        assert_eq!(
            GemContract::new(storage.clone())
                .qualify_scan_cursor
                .read(&840)
                .unwrap(),
            0
        );
    });
}

/// The qualified bins mix currencies, so the call scan must read each gem's
/// breaches off its own `COEN/<iso>` VWAP window.
#[test]
fn call_scan_reads_each_gem_own_pair_window() {
    with_storage(|storage| {
        let usd_id = qualified_gem(storage);
        let mut p = sample_params(BOB);
        p.reference_currency = EUR;
        p.issued_at = T_NOW - 100 * 86_400;
        let eur_id = api::add_gem(storage, p).unwrap();
        api::set_state(storage, eur_id, GemState::Qualified).unwrap();

        let rate = U256::from(600_000u64);
        seed_currency(storage, 840, Some(rate));
        let eur_pair = seed_currency(storage, EUR, Some(rate));

        // Only the EUR pair breaches: the USD pair has no published VWAPs.
        let breach = api::get_gem(storage, eur_id)
            .unwrap()
            .unwrap()
            .call_price_minor
            + U256::from(1u64);
        let oracle = OracleContract::new(storage.clone());
        let last_closed_day = previous_date_key(timestamp_to_date_key(T_NOW));
        let mut day = last_closed_day;
        for _ in 0..(crate::constants::CALL_THRESHOLD / 86_400) {
            oracle
                .utc_day_vwap_value
                .get_nested(&day)
                .write(&eur_pair, breach)
                .unwrap();
            day = previous_date_key(day);
        }
        oracle
            .utc_day_vwap_last_finalized
            .write(last_closed_day)
            .unwrap();

        assert_eq!(crate::hooks::scan_and_call(&block_ctx(storage)).unwrap(), 1);
        assert_eq!(
            api::get_gem(storage, eur_id).unwrap().unwrap().state,
            GemState::Called as u8
        );
        assert_eq!(
            api::get_gem(storage, usd_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
    });
}

#[test]
fn precompile_transfer_paths_revert() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();

        let calls: Vec<Vec<u8>> = vec![
            IGem::transferFromCall {
                from: ALICE,
                to: BOB,
                gemId: gem_id,
            }
            .abi_encode(),
            IGem::safeTransferFromCall {
                from: ALICE,
                to: BOB,
                gemId: gem_id,
            }
            .abi_encode(),
            IGem::approveCall {
                to: BOB,
                gemId: gem_id,
            }
            .abi_encode(),
            IGem::setApprovalForAllCall {
                operator: BOB,
                approved: true,
            }
            .abi_encode(),
        ];

        for data in calls {
            let err = dispatch(storage.clone(), &data, ALICE, U256::ZERO).unwrap_err();
            assert!(
                format!("{err:?}").contains("non-transferable"),
                "expected NonTransferable revert, got {err:?}",
            );
        }
    });
}

#[test]
fn precompile_balance_and_owner_views() {
    with_storage(|storage| {
        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();

        let data = IGem::balanceOfCall { owner: ALICE }.abi_encode();
        let bytes = dispatch(storage.clone(), &data, Address::ZERO, U256::ZERO).unwrap();
        let bal = IGem::balanceOfCall::abi_decode_returns(&bytes).unwrap();
        assert_eq!(bal, U256::from(1u64));

        let data = IGem::ownerOfCall { gemId: gem_id }.abi_encode();
        let bytes = dispatch(storage.clone(), &data, Address::ZERO, U256::ZERO).unwrap();
        let owner = IGem::ownerOfCall::abi_decode_returns(&bytes).unwrap();
        assert_eq!(owner, ALICE);

        let data = IGem::totalSupplyCall {}.abi_encode();
        let bytes = dispatch(storage.clone(), &data, Address::ZERO, U256::ZERO).unwrap();
        let total = IGem::totalSupplyCall::abi_decode_returns(&bytes).unwrap();
        assert_eq!(total, U256::from(1u64));
    });
}

/// Pins the flat `GemContract` storage layout that `scripts/seed_genesis.py`
/// (`seed_gems`) depends on to genesis-seed a Settled gem. If the schema field
/// order or `GemData` field count changes, these slots shift and the Python
/// seeder must be updated in lockstep - this test is the tripwire.
#[test]
fn gem_storage_layout_matches_genesis_seeder() {
    use outbe_primitives::storage::dsl::StorageRecord;
    with_storage(|storage| {
        let gem = GemContract::new(storage.clone());
        assert_eq!(gem.total_supply.slot(), U256::from(0u64));
        assert_eq!(gem.gem_items.base_slot(), U256::from(1u64));
        // GemData record spans 17 slots (owner@+0 .. settled_at@+16), so
        // the schema fields after gem_items start at 1 + 17 = 18.
        assert_eq!(<crate::schema::GemData as StorageRecord>::SLOTS, 17);
        assert_eq!(gem.owner_gem_counts.base_slot(), U256::from(18u64));
        assert_eq!(gem.owner_gem_ids.base_slot(), U256::from(19u64));
        // all_gem_ids (List) occupies slot 20.
        assert_eq!(gem.gem_index.base_slot(), U256::from(21u64));
        // The seeder writes the raw `state` byte, so its GEM_STATE_SETTLED must
        // track this discriminant.
        assert_eq!(GemState::Settled as u8, 3);
    });
}
/// Build a full-window (newest-first) list with `breach_days` entries above the
/// gem's call threshold, the rest at zero.
fn breach_window(now: u64, breach: U256, breach_days: usize) -> Vec<(u32, Option<U256>)> {
    let window_days = (crate::constants::CALL_WINDOW / 86_400) as usize;
    let mut window = Vec::with_capacity(window_days);
    let mut day = timestamp_to_date_key(now);
    for i in 0..window_days {
        let v = if i < breach_days { breach } else { U256::ZERO };
        window.push((day, Some(v)));
        day = previous_date_key(day);
    }
    window
}

fn qualified_gem(storage: &StorageHandle) -> U256 {
    // These cases reason in the PROD call terms; the test chain id resolves to DEV.
    GemContract::new(storage.clone())
        .config_profile
        .write(crate::config::PROFILE_PROD)
        .unwrap();
    let mut p = sample_params(ALICE);
    // Issue well before the window so no day is skipped as pre-issuance.
    p.issued_at = T_NOW - 100 * 86_400;
    let gem_id = api::add_gem(storage, p).unwrap();
    api::set_state(storage, gem_id, GemState::Qualified).unwrap();
    gem_id
}

#[test]
fn the_call_pass_resumes_from_its_bin_cursor() {
    with_storage(|storage| {
        let mut low = sample_params(ALICE);
        low.issued_at = T_NOW - 100 * 86_400;
        low.call_price_minor = U256::from(100_000u64);
        let low_id = api::add_gem(storage, low).unwrap();
        let mut high = sample_params(BOB);
        high.issued_at = T_NOW - 100 * 86_400;
        high.call_price_minor = U256::from(200_000u64);
        let high_id = api::add_gem(storage, high).unwrap();
        api::set_state(storage, low_id, GemState::Qualified).unwrap();
        api::set_state(storage, high_id, GemState::Qualified).unwrap();

        // Every day of the window sits above both call prices.
        let pair = seed_currency(storage, 840, Some(U256::from(600_000u64)));
        let oracle = OracleContract::new(storage.clone());
        let last_closed_day = previous_date_key(timestamp_to_date_key(T_NOW));
        let mut day = last_closed_day;
        for _ in 0..(crate::constants::CALL_WINDOW / 86_400) {
            oracle
                .utc_day_vwap_value
                .get_nested(&day)
                .write(&pair, U256::from(300_000u64))
                .unwrap();
            day = previous_date_key(day);
        }
        oracle
            .utc_day_vwap_last_finalized
            .write(last_closed_day)
            .unwrap();

        // A budget of one takes the lower bin and persists the cursor above it.
        let ctx = block_ctx(storage);
        let mut budget = 1u32;
        let window = vec![
            (last_closed_day, Some(U256::from(300_000u64)));
            (crate::constants::CALL_WINDOW / 86_400) as usize
        ];
        assert_eq!(
            crate::hooks::call_currency(
                &ctx,
                840,
                &window,
                outbe_primitives::math::constants::MAX_BIN_ID,
                &mut budget
            )
            .unwrap(),
            (1, false)
        );
        assert_eq!(
            api::get_gem(storage, high_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );

        let mut budget = 8u32;
        assert_eq!(
            crate::hooks::call_currency(
                &ctx,
                840,
                &window,
                outbe_primitives::math::constants::MAX_BIN_ID,
                &mut budget
            )
            .unwrap(),
            (1, true)
        );
        assert_eq!(
            api::get_gem(storage, high_id).unwrap().unwrap().state,
            GemState::Called as u8
        );
    });
}

/// The daily trigger opens a sweep and closes it once nothing is left to walk;
/// with none open, a block costs nothing and calls nobody.
#[test]
fn a_finished_sweep_closes_itself_and_idle_blocks_do_nothing() {
    with_storage(|storage| {
        let mut first = sample_params(ALICE);
        first.issued_at = T_NOW - 100 * 86_400;
        first.call_price_minor = U256::from(100_000u64);
        let first_id = api::add_gem(storage, first).unwrap();
        api::set_state(storage, first_id, GemState::Qualified).unwrap();

        let pair = seed_currency(storage, 840, Some(U256::from(600_000u64)));
        let oracle = OracleContract::new(storage.clone());
        let last_closed_day = previous_date_key(timestamp_to_date_key(T_NOW));
        let mut day = last_closed_day;
        for _ in 0..(crate::constants::CALL_WINDOW / 86_400) {
            oracle
                .utc_day_vwap_value
                .get_nested(&day)
                .write(&pair, U256::from(300_000u64))
                .unwrap();
            day = previous_date_key(day);
        }
        oracle
            .utc_day_vwap_last_finalized
            .write(last_closed_day)
            .unwrap();

        let ctx = block_ctx(storage);
        crate::hooks::run_call_daily(&ctx).unwrap();
        let gem = GemContract::new(storage.clone());
        assert_eq!(
            api::get_gem(storage, first_id).unwrap().unwrap().state,
            GemState::Called as u8
        );
        assert_eq!(gem.call_sweep_day.read().unwrap(), 0);

        // A gem that breaches just as hard is left alone: no sweep is open.
        let mut second = sample_params(BOB);
        second.issued_at = T_NOW - 100 * 86_400;
        second.call_price_minor = U256::from(100_000u64);
        let second_id = api::add_gem(storage, second).unwrap();
        api::set_state(storage, second_id, GemState::Qualified).unwrap();
        assert_eq!(crate::hooks::run_call_slice(&ctx).unwrap(), 0);
        assert_eq!(
            api::get_gem(storage, second_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
    });
}

/// A bin left half-visited would be stepped over by the cursor.
#[test]
fn a_bin_wider_than_the_budget_is_not_left_half_called() {
    with_storage(|storage| {
        let mut ids = Vec::new();
        for owner in [ALICE, BOB] {
            let mut params = sample_params(owner);
            params.issued_at = T_NOW - 100 * 86_400;
            params.call_price_minor = U256::from(100_000u64);
            let id = api::add_gem(storage, params).unwrap();
            api::set_state(storage, id, GemState::Qualified).unwrap();
            ids.push(id);
        }

        let pair = seed_currency(storage, 840, Some(U256::from(600_000u64)));
        let oracle = OracleContract::new(storage.clone());
        let last_closed_day = previous_date_key(timestamp_to_date_key(T_NOW));
        let mut day = last_closed_day;
        for _ in 0..(crate::constants::CALL_WINDOW / 86_400) {
            oracle
                .utc_day_vwap_value
                .get_nested(&day)
                .write(&pair, U256::from(300_000u64))
                .unwrap();
            day = previous_date_key(day);
        }
        oracle
            .utc_day_vwap_last_finalized
            .write(last_closed_day)
            .unwrap();

        let ctx = block_ctx(storage);
        let mut budget = 1u32;
        let window = vec![
            (last_closed_day, Some(U256::from(300_000u64)));
            (crate::constants::CALL_WINDOW / 86_400) as usize
        ];
        assert_eq!(
            crate::hooks::call_currency(
                &ctx,
                840,
                &window,
                outbe_primitives::math::constants::MAX_BIN_ID,
                &mut budget
            )
            .unwrap(),
            (2, false)
        );
        for id in ids {
            assert_eq!(
                api::get_gem(storage, id).unwrap().unwrap().state,
                GemState::Called as u8
            );
        }
    });
}

/// An entry the sweep cannot retire credits nothing - the burn and the credit
/// share a checkpoint - and leaves its bucket, so the gems behind it still drain.
#[test]
fn an_entry_the_sweep_cannot_retire_does_not_hold_up_its_bucket() {
    with_storage(|storage| {
        let live = qualified_gem(storage);
        let mut gem = GemContract::new(storage.clone());
        // A slot pointing at a gem that is not there: forfeit errors every run.
        let ghost = U256::from(0xdeadu64);
        let deadline = T_NOW + 7 * 86_400;
        gem.push_called(ghost, deadline).unwrap();
        gem.mark_called(live, T_NOW).unwrap();
        let day = GemContract::deadline_bucket(deadline);
        let load = api::get_gem(storage, live)
            .unwrap()
            .unwrap()
            .promis_load_minor;

        let ctx = block_ctx_at(storage, GemContract::bucket_end(day));
        <crate::hooks::GemLifecycle as outbe_primitives::block::BlockLifecycle>::begin_block(&ctx)
            .unwrap();

        assert_eq!(gem.expiry_slot(day, 0).unwrap(), None, "the ghost is out");
        assert_eq!(
            unallocated(storage),
            load,
            "and the gem behind it was still forfeited"
        );
    });
}

/// Same for a due entry whose gem is no longer Called: it burns nothing.
#[test]
fn a_due_entry_that_cannot_burn_credits_nothing() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let mut gem = GemContract::new(storage.clone());
        gem.push_called(gem_id, T_NOW).unwrap();

        let ctx = block_ctx_at(
            storage,
            GemContract::bucket_end(GemContract::deadline_bucket(T_NOW)),
        );
        <crate::hooks::GemLifecycle as outbe_primitives::block::BlockLifecycle>::begin_block(&ctx)
            .unwrap();

        assert_eq!(unallocated(storage), U256::ZERO);
    });
}

#[test]
fn forfeiting_a_gem_returns_its_load_to_the_pool() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let load = api::get_gem(storage, gem_id)
            .unwrap()
            .unwrap()
            .promis_load_minor;
        let mut gem = GemContract::new(storage.clone());
        gem.mark_called(gem_id, T_NOW).unwrap();

        assert!(!gem.forfeit(gem_id, T_NOW + 6 * 86_400).unwrap());
        assert_eq!(unallocated(storage), U256::ZERO);

        assert!(gem.forfeit(gem_id, T_NOW + 7 * 86_400 + 1).unwrap());
        assert_eq!(unallocated(storage), load);
    });
}

/// Its holder paid the strike, so the load is theirs.
#[test]
fn a_settled_gem_is_never_forfeited() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let mut gem = GemContract::new(storage.clone());
        gem.mark_called(gem_id, T_NOW).unwrap();
        gem.set_state(gem_id, GemState::Settled).unwrap();

        assert!(!gem.forfeit(gem_id, T_NOW + 7 * 86_400 + 1).unwrap());
        assert_eq!(unallocated(storage), U256::ZERO);
        assert_eq!(gem.called_bucket_slot.read(&gem_id).unwrap(), 0);
    });
}

fn unallocated(storage: &StorageHandle) -> U256 {
    outbe_promislimit::PromisLimitContract::new(storage.clone())
        .get_total_unallocated()
        .unwrap()
}

/// Expiry reads the queue, not the tree: the reason the two stages are separate.
#[test]
fn a_gem_above_the_window_is_not_visited_but_still_expires() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let call_price = api::get_gem(storage, gem_id)
            .unwrap()
            .unwrap()
            .call_price_minor;

        // Every published day sits below the gem's call price.
        let pair = seed_currency(storage, 840, Some(U256::from(600_000u64)));
        let oracle = OracleContract::new(storage.clone());
        let last_closed_day = previous_date_key(timestamp_to_date_key(T_NOW));
        let mut day = last_closed_day;
        for _ in 0..(crate::constants::CALL_WINDOW / 86_400) {
            oracle
                .utc_day_vwap_value
                .get_nested(&day)
                .write(&pair, call_price - U256::from(1u64))
                .unwrap();
            day = previous_date_key(day);
        }
        oracle
            .utc_day_vwap_last_finalized
            .write(last_closed_day)
            .unwrap();

        assert_eq!(crate::hooks::scan_and_call(&block_ctx(storage)).unwrap(), 0);
        assert_eq!(
            api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );

        let mut gem = GemContract::new(storage.clone());
        gem.mark_called(gem_id, T_NOW).unwrap();
        assert!(gem.forfeit(gem_id, T_NOW + 7 * 86_400 + 1).unwrap());
        assert!(api::get_gem(storage, gem_id).unwrap().is_none());
    });
}

#[test]
fn call_then_forfeit_lifecycle() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let threshold = api::get_gem(storage, gem_id)
            .unwrap()
            .unwrap()
            .call_price_minor;
        let breach_days = (crate::constants::CALL_THRESHOLD / 86_400) as usize;
        let window = breach_window(T_NOW, threshold + U256::from(1u64), breach_days);

        let mut gem = GemContract::new(storage.clone());
        assert!(gem.trigger_call(&window, gem_id, T_NOW).unwrap());
        let item = api::get_gem(storage, gem_id).unwrap().unwrap();
        assert_eq!(item.state, GemState::Called as u8);
        assert_eq!(item.called_at, T_NOW);

        // Within the 7-day notice period: no forfeit.
        assert!(!gem.forfeit(gem_id, T_NOW + 6 * 86_400).unwrap());
        // Past the deadline: forfeit-burned.
        assert!(gem.forfeit(gem_id, T_NOW + 7 * 86_400 + 1).unwrap());
        assert!(api::get_gem(storage, gem_id).unwrap().is_none());
    });
}

#[test]
fn call_skips_below_threshold() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let threshold = api::get_gem(storage, gem_id)
            .unwrap()
            .unwrap()
            .call_price_minor;
        // One below the threshold: not enough breach-days to force a call.
        let breach_days = (crate::constants::CALL_THRESHOLD / 86_400) as usize - 1;
        let window = breach_window(T_NOW, threshold + U256::from(1u64), breach_days);

        let mut gem = GemContract::new(storage.clone());
        assert!(!gem.trigger_call(&window, gem_id, T_NOW).unwrap());
        assert_eq!(
            api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
    });
}

#[test]
fn a_registry_edit_does_not_move_the_cursor_onto_another_currency() {
    let currencies = [840u16, 978u16];
    assert_eq!(
        crate::hooks::currency_position(&currencies, 978),
        1,
        "the cursor names a currency, not a slot"
    );
    assert_eq!(
        crate::hooks::currency_position(&currencies[1..], 978),
        0,
        "dropping the currency ahead of it does not shift the cursor onto a stranger"
    );
    assert_eq!(
        crate::hooks::currency_position(&currencies, 392),
        0,
        "a currency the registry no longer carries restarts at the head"
    );
}

#[test]
fn a_wider_window_than_the_live_profile_widens_the_span_the_scan_collects() {
    with_storage(|storage| {
        let gem = GemContract::new(storage.clone());
        let iso = sample_params(ALICE).reference_currency;
        let profile = |p: u8| {
            GemContract::new(storage.clone())
                .config_profile
                .write(p)
                .unwrap()
        };

        profile(crate::config::PROFILE_DEV);
        api::add_gem(storage, sample_params(ALICE)).unwrap();
        assert_eq!(
            gem.max_call_window.read(&iso).unwrap(),
            GemParams::DEV.call_window
        );

        profile(crate::config::PROFILE_PROD);
        api::add_gem(storage, sample_params(BOB)).unwrap();
        assert_eq!(
            gem.max_call_window.read(&iso).unwrap(),
            GemParams::PROD.call_window,
            "a wider profile widens the span"
        );

        profile(crate::config::PROFILE_DEV);
        let mut third = sample_params(ALICE);
        third.promis_load_minor = U256::from(2_000_000u64);
        api::add_gem(storage, third).unwrap();
        assert_eq!(
            gem.max_call_window.read(&iso).unwrap(),
            GemParams::PROD.call_window,
            "going back to the narrow one does not shrink it"
        );
    });
}

#[test]
fn config_unset_resolves_by_chain_id() {
    with_storage(|storage| {
        // No genesis profile selected -> resolved by network; the test chain is not mainnet.
        assert_eq!(crate::config::read(storage).unwrap(), GemParams::DEV);
        // An explicit selector still wins over the network default.
        GemContract::new(storage.clone())
            .config_profile
            .write(crate::config::PROFILE_PROD)
            .unwrap();
        assert_eq!(crate::config::read(storage).unwrap(), GemParams::PROD);
        assert_eq!(GemParams::PROD.call_window, 28 * 24 * 3600);
        assert_eq!(GemParams::PROD.position_validity, 365 * 24 * 3600);
    });
}

/// The network default: only mainnet runs the real timings.
#[test]
fn config_auto_profile_follows_the_network() {
    use outbe_primitives::chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};

    assert_eq!(GemParams::for_chain_id(MAINNET_CHAIN_ID), GemParams::PROD);
    for chain_id in [TESTNET_CHAIN_ID, DEVNET_CHAIN_ID, 31_337] {
        assert_eq!(GemParams::for_chain_id(chain_id), GemParams::DEV);
    }
}

#[test]
fn config_unknown_selector_errors() {
    with_storage(|storage| {
        GemContract::new(storage.clone())
            .config_profile
            .write(99u8)
            .unwrap();
        assert!(crate::config::read(storage).is_err());
    });
}

/// Pin the selector slot index: the seeder writes a raw slot, and `gem_items`
/// spans a 17-slot record, so the attribute order is not the slot.
#[test]
fn config_profile_slot_matches_seeder_layout() {
    with_storage(|storage| {
        assert_eq!(
            GemContract::new(storage.clone()).config_profile.slot(),
            U256::from(42)
        );
    });
}

#[test]
fn a_bucket_that_outlives_its_hour_is_retired_rather_than_left_in_front() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let mut gem = GemContract::new(storage.clone());
        gem.mark_called(gem_id, T_NOW).unwrap();
        let deadline = T_NOW + 7 * 86_400;
        let bucket = GemContract::deadline_bucket(deadline);

        gem.called_deadline
            .write(&gem_id, deadline + 400 * 86_400)
            .unwrap();

        let ctx = block_ctx_at(storage, GemContract::bucket_end(bucket));
        <crate::hooks::GemLifecycle as outbe_primitives::block::BlockLifecycle>::begin_block(&ctx)
            .unwrap();

        assert_eq!(
            gem.first_expiry_day().unwrap(),
            None,
            "the bucket leaves the tree instead of blocking every later one"
        );
        assert_eq!(
            gem.called_bucket_slot.read(&gem_id).unwrap(),
            0,
            "and the gem stops pointing at a slot it no longer owns"
        );
    });
}

#[test]
fn leaving_called_frees_the_expiry_slot() {
    with_storage(|storage| {
        let gem_id = qualified_gem(storage);
        let mut gem = GemContract::new(storage.clone());
        gem.mark_called(gem_id, T_NOW).unwrap();
        let bucket = GemContract::deadline_bucket(T_NOW + 7 * 86_400);
        assert_eq!(gem.expiry_bucket_live.read(&bucket).unwrap(), 1);

        gem.set_state(gem_id, GemState::Qualified).unwrap();
        assert_eq!(gem.expiry_bucket_live.read(&bucket).unwrap(), 0);
        assert_eq!(gem.first_expiry_day().unwrap(), None);
    });
}

#[test]
fn config_dev_profile_terms_a_new_gem() {
    with_storage(|storage| {
        GemContract::new(storage.clone())
            .config_profile
            .write(crate::config::PROFILE_DEV)
            .unwrap();

        let gem_id = api::add_gem(storage, sample_params(ALICE)).unwrap();

        // A gem snapshots its call terms at issuance, so the dev bundle has to
        // reach the record; the prod one must not.
        let item = api::get_gem(storage, gem_id).unwrap().unwrap();
        assert_eq!(item.call_window, GemParams::DEV.call_window);
        assert_eq!(item.call_threshold, GemParams::DEV.call_threshold);
        assert_eq!(item.call_notice_period, GemParams::DEV.call_notice_period);
        assert!(item.call_window < GemParams::PROD.call_window);
    });
}
