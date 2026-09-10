use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_gem::{api as gem_api, GemContract, GemState};
use outbe_intex::SeriesId;
use outbe_oracle::schema::OracleContract;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;
use outbe_promisfactory::api::ModifyAuth;
use outbe_tee::protocol::PromisOp;
use outbe_tee_enclave::promis::{decrypt_balance, derive_modify_key, derive_view_key, modify_mac};

use outbe_primitives::block::{BlockContext, BlockRuntimeContext};

const POSITION_VALIDITY_SECONDS: u64 = outbe_gem::GemParams::PROD.position_validity;
use crate::expired;
use crate::runtime;
use crate::schema::{GemFactoryContract, GemPosition, GemTypes};
use crate::sol_ext::{IReferenceCurrency, IERC20};
use alloy_sol_types::SolCall;
use outbe_vaultrouter::api::IVaultRouter;

const T_NOW: u64 = 1_700_000_000;
const ALICE: Address = address!("0x1111111111111111111111111111111111111111");
const BOB: Address = address!("0x2222222222222222222222222222222222222222");
/// Mock settlement stablecoin passed to `settle_gem` in tests; `isoCode()`
/// stubbed to 840 (USD), matching the default test currency.
const STABLE: Address = address!("0x00000000000000000000000000000000000000AA");
/// Mock stablecoin whose `isoCode()` is 978 (EUR): a currency mismatch for a
/// USD-denominated gem.
const STABLE_EUR: Address = address!("0x00000000000000000000000000000000000000BB");
/// Mock USD stablecoin carrying eighteen decimals instead of six.
const STABLE_18: Address = address!("0x00000000000000000000000000000000000000CC");

/// A no-op authorization for mine paths that reject before reaching the (enclave)
/// Promis mint (ownership/state/PoW failures).
fn no_auth() -> ModifyAuth {
    ModifyAuth {
        mac: [0u8; 32],
        op_nonce: 0,
    }
}

/// The Promis modify authorization for `account`'s first mint of `amount`. Requires
/// the in-process Promis enclave to be installed (chain id 1 matches the harness).
fn promis_auth(account: Address, amount: U256, nonce: u64) -> ModifyAuth {
    let sk = outbe_promis::enclave_client::test_enclave::state_key();
    let mk = derive_modify_key(&sk, account).unwrap();
    ModifyAuth {
        mac: modify_mac(
            &mk,
            account,
            PromisOp::Mint,
            amount,
            nonce,
            B256::from(U256::from(1u64)),
        ),
        op_nonce: nonce,
    }
}

/// Units the stubbed `parkIntex` reports as burned (its `uint256` return).
const PARK_UNITS: u64 = 100;

fn word(value: u64) -> alloy_primitives::Bytes {
    alloy_primitives::Bytes::from(U256::from(value).to_be_bytes::<32>().to_vec())
}

/// Stubs one settlement stablecoin's `isoCode()` and `decimals()`.
fn stub_stablecoin(
    storage: &mut HashMapStorageProvider,
    asset: Address,
    iso_code: u64,
    decimals: u64,
) {
    storage.stub_sub_call_at_selector(
        asset,
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(iso_code),
    );
    storage.stub_sub_call_at_selector(asset, IERC20::decimalsCall::SELECTOR, word(decimals));
    // The deposit path pulls and approves before handing over to the router.
    storage.stub_sub_call_at_selector(asset, IERC20::transferFromCall::SELECTOR, word(1));
    storage.stub_sub_call_at_selector(asset, IERC20::approveCall::SELECTOR, word(1));
    // A fixed stub cannot vary between the two reads, so the delta is zero here.
    storage.stub_sub_call_at_selector(asset, IERC20::balanceOfCall::SELECTOR, word(0));
}

fn test_storage(rate: Option<U256>) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new(1);
    storage.set_timestamp(U256::from(T_NOW));
    // Stub IntexNFT1155: `parkIntex` returns PARK_UNITS (32-byte uint256).
    storage.stub_sub_call_at(
        outbe_primitives::addresses::INTEX_NFT1155_ADDRESS,
        alloy_primitives::Bytes::from(U256::from(PARK_UNITS).to_be_bytes::<32>().to_vec()),
    );
    // Answered per selector, so the settlement path can tell USD from EUR.
    stub_stablecoin(&mut storage, STABLE, 840, 6);
    stub_stablecoin(&mut storage, STABLE_EUR, 978, 6);
    stub_stablecoin(&mut storage, STABLE_18, 840, 18);
    // Every asset the tests pass in has a registered vault.
    storage.stub_sub_call_at_selector(
        outbe_primitives::addresses::VAULT_ROUTER_ADDRESS,
        IVaultRouter::assetVaultsCountCall::SELECTOR,
        word(1),
    );
    // `deposit` reports minted shares.
    storage.stub_sub_call_at_selector(
        outbe_primitives::addresses::VAULT_ROUTER_ADDRESS,
        IVaultRouter::depositCall::SELECTOR,
        word(1),
    );
    StorageHandle::enter(&mut storage, |handle| {
        // These cases assert the PROD gem terms; an unset profile would resolve
        // by chain id, and the test chain is not mainnet.
        outbe_gem::schema::GemContract::new(handle.clone())
            .config_profile
            .write(outbe_gem::config::PROFILE_PROD)
            .unwrap();
        // Registry membership is independent of whether a price exists: 840 is a
        // reference currency in every fixture, priced or not.
        OracleContract::new(handle.clone())
            .reference_currencies
            .push(840u16)
            .unwrap();
        if let Some(rate) = rate {
            outbe_oracle::api::register_pair(handle.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .unwrap();
            outbe_oracle::api::set_exchange_rate(
                handle.clone(),
                Address::ZERO,
                outbe_oracle::api::DAY_TYPE_PAIR,
                rate,
                1,
                T_NOW,
            )
            .unwrap();
        }
    });
    storage
}

fn with_storage<R>(rate: Option<U256>, f: impl FnOnce(&StorageHandle) -> R) -> R {
    let mut storage = test_storage(rate);
    StorageHandle::enter(&mut storage, |handle| f(&handle))
}

/// Far above every cost these tests produce, so coverage is never what fails.
const NOTE_AMOUNT: u128 = 1_000_000_000_000_000_000_000_000_000_000;

/// Seeds the pool with one note over `asset` and proves a spend of it.
fn note_proof(
    provider: &mut HashMapStorageProvider,
    asset: Address,
    spender: Address,
    amount: u128,
) -> Vec<u8> {
    let amount = U256::from(amount);
    let fixture =
        outbe_paynote::test_support::note_and_spend_proof(1, asset, spender, amount, amount);
    outbe_paynote::test_support::seed_pool(provider, 1, &[fixture.commitment]);
    fixture.proof
}

/// [`with_storage`] plus a funded note.
fn with_storage_paying<R>(
    rate: Option<U256>,
    asset: Address,
    spender: Address,
    f: impl FnOnce(&StorageHandle, &[u8]) -> R,
) -> R {
    let mut storage = test_storage(rate);
    let proof = note_proof(&mut storage, asset, spender, NOTE_AMOUNT);
    StorageHandle::enter(&mut storage, |handle| f(&handle, &proof))
}

fn six_decimal_unit() -> U256 {
    U256::from(1_000_000u64)
}

fn err_msg<T>(r: outbe_primitives::error::Result<T>) -> String {
    format!("{:?}", r.err().unwrap())
}

/// Brute-force the lowest nonce that satisfies `validate_pow(gem_id, _)` for
/// the current `POW_DIFFICULTY`. With difficulty=1 the expected loop length
/// is ~256 iterations.
fn find_valid_nonce(gem_id: U256) -> u64 {
    for nonce in 0u64..u64::MAX {
        if runtime::validate_pow(gem_id, nonce).is_ok() {
            return nonce;
        }
    }
    panic!("no valid nonce found")
}

#[test]
fn issue_genesis_pays_like_agents_but_born_qualified() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let load = U256::from(10u64) * six_decimal_unit();
        let gem_id = issue_at_live_rate(storage, ALICE, GemTypes::Genesis, load, 840, 840).unwrap();

        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        // Genesis now pays like Wallet/Cca/Validator: cost = entry x load,
        // floor = rate x 1.08. It only keeps the born-Qualified fast path
        // (no maturity wait) - settle still moves cost into the Reserve.
        assert_eq!(
            runtime::gem_cost_minor(&item).unwrap(),
            U256::from(20u64) * six_decimal_unit()
        );
        assert_eq!(item.entry_price_minor, rate);
        assert_eq!(
            item.floor_price_minor,
            rate * U256::from(108u64) / U256::from(100u64)
        );
        assert_eq!(item.state, GemState::Qualified as u8);
        assert_eq!(item.gem_type, GemTypes::Genesis as u8);

        let factory = GemFactoryContract::new(storage.clone());
        assert_eq!(factory.total_gems_issued.read().unwrap(), U256::from(1u64));
    });
}

#[test]
fn issue_validator_post_genesis_behaves_like_wallet() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let load = U256::from(5u64) * six_decimal_unit();
        let gem_id =
            issue_at_live_rate(storage, ALICE, GemTypes::Validator, load, 840, 840).unwrap();

        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        // Same as WALLET: cost = entry x load, floor with 8% markup, Issued.
        assert_eq!(
            runtime::gem_cost_minor(&item).unwrap(),
            U256::from(10u64) * six_decimal_unit()
        );
        assert_eq!(
            item.floor_price_minor,
            rate * U256::from(108u64) / U256::from(100u64)
        );
        assert_eq!(item.state, GemState::Issued as u8);
        assert_eq!(item.gem_type, GemTypes::Validator as u8);
    });
}

#[test]
fn issue_wallet_cost_and_floor_markup_state_issued() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let load = U256::from(5u64) * six_decimal_unit();
        let gem_id = issue_at_live_rate(storage, ALICE, GemTypes::Wallet, load, 840, 840).unwrap();

        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        // entry = coen_rate = 2; cost = entry * load / six_decimal_unit() = 2 * 5 = 10
        assert_eq!(item.entry_price_minor, rate);
        assert_eq!(
            runtime::gem_cost_minor(&item).unwrap(),
            U256::from(10u64) * six_decimal_unit()
        );
        // floor = rate * 108 / 100 = 2 * 1.08 = 2.16
        assert_eq!(
            item.floor_price_minor,
            rate * U256::from(108u64) / U256::from(100u64)
        );
        assert_eq!(item.state, GemState::Issued as u8);
    });
}

#[test]
fn issue_rejects_positive_price_and_load_when_six_decimal_cost_rounds_to_zero() {
    with_storage(Some(U256::ONE), |storage| {
        let result = issue_at_live_rate(storage, ALICE, GemTypes::Wallet, U256::ONE, 840, 840);
        assert!(
            result.is_err(),
            "positive economics produced a zero-cost Gem"
        );
    });
}

#[test]
fn issue_sra_applies_64_percent_discount() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let load = U256::from(10u64) * six_decimal_unit();
        let gem_id = issue_at_live_rate(storage, ALICE, GemTypes::Sra, load, 840, 840).unwrap();

        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        // entry = rate = 2; cost = 2 * 10 * 64 / 100 = 12.8 (six-decimal)
        let expected = rate * load * U256::from(64u64) / U256::from(100u64) / six_decimal_unit();
        assert_eq!(runtime::gem_cost_minor(&item).unwrap(), expected);
    });
}

#[test]
fn issue_cca_no_discount() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let load = U256::from(7u64) * six_decimal_unit();
        let gem_id = issue_at_live_rate(storage, ALICE, GemTypes::Cca, load, 840, 840).unwrap();

        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        // entry = rate = 2; cost = 2 * 7 = 14
        assert_eq!(
            runtime::gem_cost_minor(&item).unwrap(),
            U256::from(14u64) * six_decimal_unit()
        );
    });
}

#[test]
fn issue_gem_rejects_merchant_type() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let res = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Merchant,
            U256::from(1u64) * six_decimal_unit(),
            840,
            840,
        );
        assert!(err_msg(res).contains("unsupported gem type"));
    });
}

#[test]
fn issue_zero_owner_rejected() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let res = issue_at_live_rate(
            storage,
            Address::ZERO,
            GemTypes::Wallet,
            U256::from(1u64) * six_decimal_unit(),
            840,
            840,
        );
        assert!(err_msg(res).contains("invalid owner"));
    });
}

#[test]
fn issue_no_oracle_setup_rejected() {
    // The reference currency is registered but its COEN pair is not, so the gem
    // has no price to anchor its entry, floor and call to and issuing reverts.
    with_storage(None, |storage| {
        let res = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(1u64) * six_decimal_unit(),
            840,
            840,
        );
        assert!(err_msg(res).contains("not registered"));
    });
}

#[test]
fn issue_rejects_a_stale_oracle_rate_before_writing_a_gem() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        outbe_oracle::api::set_exchange_rate(
            storage.clone(),
            Address::ZERO,
            outbe_oracle::api::DAY_TYPE_PAIR,
            rate,
            1,
            T_NOW - outbe_oracle::constants::FX_RATE_MAX_AGE_SECONDS - 1,
        )
        .unwrap();

        let error = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            six_decimal_unit(),
            840,
            840,
        )
        .unwrap_err();

        assert!(error.to_string().contains("stale"), "{error}");
        assert_eq!(
            GemFactoryContract::new(storage.clone())
                .total_gems_issued
                .read()
                .unwrap(),
            U256::ZERO
        );
    });
}

#[test]
fn settle_wallet_settles_with_a_registered_asset() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage_paying(Some(rate), STABLE, ALICE, |storage, proof| {
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        gem_api::set_state(storage, gem_id, GemState::Qualified).unwrap();

        // STABLE reports 840, which is the gem's reference currency, so it
        // settles on the reference rail. Real vault interaction is covered by
        // integration tests; here the router is stubbed.
        runtime::settle_gem(storage, ALICE, gem_id, proof).unwrap();
        assert_eq!(
            gem_api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Settled as u8
        );
    });
}

#[test]
fn settlement_event_reports_the_rail_the_asset_matched() {
    let rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(rate));
    let proof = note_proof(&mut provider, STABLE, ALICE, NOTE_AMOUNT);
    let gem_id = StorageHandle::enter(&mut provider, |storage| {
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            949,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
        gem_id
    });

    let event = provider
        .get_ordered_events()
        .iter()
        .filter_map(|log| crate::precompile::IGemFactory::GemSettled::decode_log(log).ok())
        .next()
        .expect("settlement emits GemSettled");
    assert_eq!(event.gemId, gem_id);
    assert_eq!(event.settlementCurrency, 840);
}

/// Issues at the fixture's live COEN/reference rate. The production caller
/// resolves the price for the gem's own day; these tests only need a price that
/// matches the rate the fixture published.
fn issue_at_live_rate(
    storage: &StorageHandle<'_>,
    owner: Address,
    gem_type: GemTypes,
    promis_load: U256,
    issuance_currency: u16,
    reference_currency: u16,
) -> outbe_primitives::error::Result<U256> {
    let price = outbe_oracle::api::fresh_coen_rate_for(storage.clone(), reference_currency)?;
    runtime::issue_gem(
        storage,
        owner,
        gem_type,
        promis_load,
        issuance_currency,
        reference_currency,
        price,
    )
}

/// The single `GemSettled` a settlement emitted.
fn settled_event(provider: &HashMapStorageProvider) -> crate::precompile::IGemFactory::GemSettled {
    provider
        .get_ordered_events()
        .iter()
        .filter_map(|log| crate::precompile::IGemFactory::GemSettled::decode_log(log).ok())
        .next()
        .expect("settlement emits GemSettled")
        .data
}

/// Registers and prices `COEN/<iso>` and adds `iso` to the reference registry.
fn register_currency(storage: &StorageHandle<'_>, iso: u16, rate: U256) {
    let pair = outbe_oracle::api::AddressPair::new_coen_to(iso);
    outbe_oracle::api::register_pair(storage.clone(), pair).unwrap();
    outbe_oracle::api::set_exchange_rate(storage.clone(), Address::ZERO, pair, rate, 1, T_NOW)
        .unwrap();
    OracleContract::new(storage.clone())
        .reference_currencies
        .push(iso)
        .unwrap();
}

#[test]
fn the_issuance_currency_settles_through_the_coen_pivot() {
    // COEN/USD 2.0, COEN/EUR 1.0: the same cost converts to half as many EUR units.
    let usd_rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(usd_rate));
    let proof = note_proof(&mut provider, STABLE_EUR, ALICE, NOTE_AMOUNT);
    let cost = StorageHandle::enter(&mut provider, |storage| {
        register_currency(&storage, 978, six_decimal_unit());
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            978,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        let cost =
            runtime::gem_cost_minor(&gem_api::get_gem(&storage, gem_id).unwrap().unwrap()).unwrap();
        // Paying with the EUR asset picks the issuance rail.
        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
        cost
    });

    let event = settled_event(&provider);
    assert_eq!(event.settlementCurrency, 978);
    assert_eq!(event.amountPaid, cost / U256::from(2u64));
}

#[test]
fn the_issuance_rail_rounds_up_exactly_once() {
    // COEN/USD 7.0 and a one-unit load put the cost at 7 minor units. Converting
    // it at COEN/EUR 1.000001 lands on 1.000001 units, so a single round-up gives
    // 2 and a second rounding anywhere in the chain could not.
    let usd_rate = U256::from(7u64) * six_decimal_unit();
    let mut provider = test_storage(Some(usd_rate));
    let proof = note_proof(&mut provider, STABLE_EUR, ALICE, NOTE_AMOUNT);
    StorageHandle::enter(&mut provider, |storage| {
        register_currency(&storage, 978, U256::from(1_000_001u64));
        let gem_id =
            issue_at_live_rate(&storage, ALICE, GemTypes::Wallet, U256::ONE, 978, 840).unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        assert_eq!(
            runtime::gem_cost_minor(&gem_api::get_gem(&storage, gem_id).unwrap().unwrap()).unwrap(),
            U256::from(7u64)
        );
        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
    });

    assert_eq!(settled_event(&provider).amountPaid, U256::from(2u64));
}

#[test]
fn settling_on_an_unregistered_issuance_leg_is_refused() {
    let usd_rate = U256::from(2u64) * six_decimal_unit();
    with_storage_paying(Some(usd_rate), STABLE_EUR, ALICE, |storage, proof| {
        // The EUR asset is a valid vault asset, but COEN/978 was never registered,
        // so the pivot has no leg to convert through.
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            six_decimal_unit(),
            978,
            840,
        )
        .unwrap();
        gem_api::set_state(storage, gem_id, GemState::Qualified).unwrap();
        let res = runtime::settle_gem(storage, ALICE, gem_id, proof);
        assert!(err_msg(res).contains("not registered"));
        assert_eq!(
            gem_api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
    });
}

#[test]
fn the_reference_currency_settles_without_reading_any_issuance_rate() {
    let usd_rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(usd_rate));
    let proof = note_proof(&mut provider, STABLE, ALICE, NOTE_AMOUNT);
    let cost = StorageHandle::enter(&mut provider, |storage| {
        // Issuance 978 is never registered, so it carries no rate at all.
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            978,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        let cost =
            runtime::gem_cost_minor(&gem_api::get_gem(&storage, gem_id).unwrap().unwrap()).unwrap();
        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
        cost
    });

    let event = settled_event(&provider);
    assert_eq!(event.settlementCurrency, 840);
    assert_eq!(event.amountPaid, cost);
}

#[test]
fn settle_rejects_an_asset_with_no_registered_vault() {
    let rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(rate));
    let proof = note_proof(&mut provider, STABLE, ALICE, NOTE_AMOUNT);
    // Override the blanket vault count: this asset has none.
    provider.stub_sub_call_at_selector(
        outbe_primitives::addresses::VAULT_ROUTER_ADDRESS,
        IVaultRouter::assetVaultsCountCall::SELECTOR,
        word(0),
    );
    StorageHandle::enter(&mut provider, |storage| {
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        let res = runtime::settle_gem(&storage, ALICE, gem_id, &proof);
        assert!(err_msg(res).contains("no registered vault"));
    });
}

#[test]
fn settlement_scales_the_cost_to_the_asset_decimals() {
    let usd_rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(usd_rate));
    let proof = note_proof(&mut provider, STABLE_18, ALICE, NOTE_AMOUNT);
    let cost = StorageHandle::enter(&mut provider, |storage| {
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        let cost =
            runtime::gem_cost_minor(&gem_api::get_gem(&storage, gem_id).unwrap().unwrap()).unwrap();
        // An eighteen-decimal asset was a hard revert before; now it scales.
        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
        cost
    });

    let event = settled_event(&provider);
    assert_eq!(event.amountPaid, cost * U256::from(1_000_000_000_000u64));
}

#[test]
fn an_unassigned_issuance_code_mints_and_settles_on_the_reference_rail() {
    // 899 is inside the three-digit range but is not an assigned ISO 4217 code.
    // Gem no longer refuses it: nothing prices against it, and no settlement
    // asset can ever report it, so it is inert - exactly as it is for a bid.
    let rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(rate));
    let proof = note_proof(&mut provider, STABLE, ALICE, NOTE_AMOUNT);
    let cost = StorageHandle::enter(&mut provider, |storage| {
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            899,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();
        let cost =
            runtime::gem_cost_minor(&gem_api::get_gem(&storage, gem_id).unwrap().unwrap()).unwrap();
        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
        cost
    });

    let event = settled_event(&provider);
    assert_eq!(event.settlementCurrency, 840);
    assert_eq!(event.amountPaid, cost);
}

#[test]
fn issue_rejects_an_issuance_code_outside_the_three_digit_range() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        for iso in [0u16, 1000u16] {
            let res = issue_at_live_rate(
                storage,
                ALICE,
                GemTypes::Wallet,
                six_decimal_unit(),
                iso,
                840,
            );
            assert!(err_msg(res).contains("is not an ISO 4217 currency code"));
        }
    });
}

#[test]
fn parking_rejects_a_series_whose_reference_currency_is_unregistered() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        outbe_intex::api::create_series(
            storage,
            outbe_intex::CreateSeriesParams {
                series_id: source_intex_id(),
                worldwide_day: WorldwideDay::new(0),
                issued_intex_count: PARK_UNITS as u32,
                promis_load_minor: six_decimal_u128(),
                entry_price_minor: six_decimal_unit(),
                floor_price_minor: six_decimal_unit(),
                call_price_minor: U256::ZERO,
                call_trigger: outbe_intex::IntexCallTrigger::default(),
                issued_at: T_NOW as u32,
                issuance_currency: 840,
                // 978 is never pushed into the reference registry here.
                reference_currency: 978,
            },
        )
        .unwrap();
        let res =
            runtime::issue_gem_position(storage, ALICE, source_intex_id(), U256::from(PARK_UNITS));
        assert!(err_msg(res).contains("reference currency"));
    });
}

#[test]
fn the_quote_agrees_with_what_settling_charges_on_both_rails() {
    let usd_rate = U256::from(2u64) * six_decimal_unit();
    let mut provider = test_storage(Some(usd_rate));
    let proof = note_proof(&mut provider, STABLE_EUR, ALICE, NOTE_AMOUNT);
    let quoted = StorageHandle::enter(&mut provider, |storage| {
        register_currency(&storage, 978, six_decimal_unit());
        let gem_id = issue_at_live_rate(
            &storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            978,
            840,
        )
        .unwrap();
        gem_api::set_state(&storage, gem_id, GemState::Qualified).unwrap();

        // Both rails quote, and neither quote moves anything.
        let (ref_iso, ref_amount) = runtime::quote_settlement(&storage, gem_id, STABLE).unwrap();
        let (iss_iso, iss_amount) =
            runtime::quote_settlement(&storage, gem_id, STABLE_EUR).unwrap();
        assert_eq!(ref_iso, 840);
        assert_eq!(iss_iso, 978);
        assert_eq!(iss_amount, ref_amount / U256::from(2u64));

        runtime::settle_gem(&storage, ALICE, gem_id, &proof).unwrap();
        iss_amount
    });

    assert_eq!(settled_event(&provider).amountPaid, quoted);
}

#[test]
fn a_position_reports_its_full_terms() {
    with_storage(Some(U256::from(2u64) * six_decimal_unit()), |storage| {
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        let data = runtime::position_data(storage, id).unwrap();
        assert_eq!(data.merchant, ALICE);
        assert_eq!(data.sourceEntryPrice, six_decimal_unit());
        assert_eq!(data.sourceFloorPrice, six_decimal_unit());
        assert_eq!(data.issuanceCurrency, 840);
        assert_eq!(data.referenceCurrency, 840);
        assert_eq!(data.parkedAt, T_NOW);
        assert_eq!(data.expiresAt, T_NOW + POSITION_VALIDITY_SECONDS);
        assert_eq!(data.remainingCapacity, parked_capacity(six_decimal_u128()));
    });
}

#[test]
fn cross_currency_settlement_rejects_a_stale_leg_without_settling_the_gem() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage_paying(Some(rate), STABLE, ALICE, |storage, proof| {
        let eur_pair = outbe_oracle::api::AddressPair::new_coen_to(978);
        outbe_oracle::api::register_pair(storage.clone(), eur_pair).unwrap();
        outbe_oracle::api::set_exchange_rate(
            storage.clone(),
            Address::ZERO,
            eur_pair,
            six_decimal_unit(),
            1,
            T_NOW,
        )
        .unwrap();
        OracleContract::new(storage.clone())
            .reference_currencies
            .push(978)
            .unwrap();
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            978,
        )
        .unwrap();
        gem_api::set_state(storage, gem_id, GemState::Qualified).unwrap();
        outbe_oracle::api::set_exchange_rate(
            storage.clone(),
            Address::ZERO,
            outbe_oracle::api::DAY_TYPE_PAIR,
            rate,
            1,
            T_NOW - outbe_oracle::constants::FX_RATE_MAX_AGE_SECONDS - 1,
        )
        .unwrap();

        let error = runtime::settle_gem(storage, ALICE, gem_id, proof).unwrap_err();

        assert!(error.to_string().contains("stale"), "{error}");
        assert_eq!(
            gem_api::get_gem(storage, gem_id).unwrap().unwrap().state,
            GemState::Qualified as u8
        );
    });
}

#[test]
fn settle_rejects_wrong_settlement_currency() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage_paying(Some(rate), STABLE_EUR, ALICE, |storage, proof| {
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        gem_api::set_state(storage, gem_id, GemState::Qualified).unwrap();
        // Paying a USD gem with a EUR (978) stablecoin matches neither of its
        // currencies, so it reverts before any vault interaction.
        let res = runtime::settle_gem(storage, ALICE, gem_id, proof);
        assert!(err_msg(res).contains("does not match the gem"));
    });
}

#[test]
fn settle_rejects_non_owner() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        gem_api::set_state(storage, gem_id, GemState::Qualified).unwrap();
        let res = runtime::settle_gem(storage, BOB, gem_id, &[]);
        assert!(err_msg(res).contains("not gem owner"));
    });
}

#[test]
fn settle_rejects_non_qualified_state() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        // WALLET is born Issued - settle should reject (must be Qualified).
        let res = runtime::settle_gem(storage, ALICE, gem_id, &[]);
        assert!(err_msg(res).contains("invalid state"));
    });
}

#[test]
fn mine_promis_full_genesis_flow() {
    outbe_promis::enclave_client::test_enclave::install();
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let load = U256::from(10u64) * six_decimal_unit();
        // Genesis is born Qualified. settle now carries a non-zero cost and
        // deposits into the Reserve vault, which the storage-only harness
        // can't service - force `Settled` directly so this test still covers
        // the mine -> burn -> Promis path. The paid settle is exercised on
        // localnet with a real Reserve (see TODO below).
        let gem_id = issue_at_live_rate(storage, ALICE, GemTypes::Genesis, load, 840, 840).unwrap();

        gem_api::set_state(storage, gem_id, GemState::Settled).unwrap();
        let nonce = find_valid_nonce(gem_id);
        let minted =
            runtime::mine_promis(storage, ALICE, gem_id, nonce, promis_auth(ALICE, load, 0))
                .unwrap();
        assert_eq!(minted, load);

        let gem = GemContract::new(storage.clone());
        assert!(gem.get_gem(gem_id).unwrap().is_none());
        assert_eq!(gem.total_supply().unwrap(), 0);

        // Promis is confidential: decrypt the ciphertext balance with the view key.
        let sk = outbe_promis::enclave_client::test_enclave::state_key();
        let vk = derive_view_key(&sk, ALICE).unwrap();
        let blob = outbe_promis::api::balance_ct(storage.clone(), ALICE).unwrap();
        assert_eq!(decrypt_balance(&vk, ALICE, &blob).unwrap(), load);
    });
    outbe_promis::enclave_client::test_enclave::uninstall();
}

// TODO(reserve-config): the paid `settle_gem` path (Reserve vault deposit)
// is not exercisable in the storage-only harness for ANY gem type now that
// Genesis also carries a non-zero cost. Unit coverage forces `Settled` via
// `gem_api::set_state` to reach the mine path; the real paid settle is
// covered on localnet with a configured `RESERVE_ASSET` / `RESERVE_VAULT`.

#[test]
fn mine_promis_rejects_non_settled() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Wallet,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        // WALLET is Issued, not Settled - mine should reject before PoW.
        let res = runtime::mine_promis(storage, ALICE, gem_id, 0, no_auth());
        assert!(err_msg(res).contains("invalid state"));
    });
}

#[test]
fn mine_promis_rejects_non_owner() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let gem_id = issue_at_live_rate(
            storage,
            ALICE,
            GemTypes::Genesis,
            U256::from(10u64) * six_decimal_unit(),
            840,
            840,
        )
        .unwrap();
        // mine_promis checks ownership before state, so no settle needed.
        let res = runtime::mine_promis(storage, BOB, gem_id, 0, no_auth());
        assert!(err_msg(res).contains("not gem owner"));
    });
}

#[test]
fn statistics_track_mint_count() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let base = U256::from(1u64) * six_decimal_unit();
        // `gem_id = keccak(owner || amount || block_number)` - vary `load`
        // per issue so the same (owner, block) pair doesn't collide.
        for i in 0..3 {
            let load = base + U256::from(i as u64);
            issue_at_live_rate(storage, ALICE, GemTypes::Wallet, load, 840, 840).unwrap();
        }
        let factory = GemFactoryContract::new(storage.clone());
        assert_eq!(factory.total_gems_issued.read().unwrap(), U256::from(3u64));
    });
}

// --- Merchant gems ---

fn source_intex_id() -> SeriesId {
    SeriesId::pack(WorldwideDay::new(20_260_212), *b"USD", b'U').unwrap()
}

fn six_decimal_u128() -> u128 {
    1_000_000
}

/// Whole-position capacity for a series with `promis_load` per unit: the stubbed
/// `parkIntex` burns `PARK_UNITS`, so capacity = `promis_load x PARK_UNITS`.
fn parked_capacity(promis_load: u128) -> U256 {
    U256::from(promis_load) * U256::from(PARK_UNITS)
}

/// Seed an Intex series and park the merchant's whole holding into a GemPosition
/// NFT (burn stubbed via `with_storage`). Returns the `position_id`.
fn seed_and_park(storage: &StorageHandle, entry: U256, floor: U256, promis_load: u128) -> U256 {
    outbe_intex::api::create_series(
        storage,
        outbe_intex::CreateSeriesParams {
            series_id: source_intex_id(),
            worldwide_day: WorldwideDay::new(0),
            issued_intex_count: PARK_UNITS as u32,
            promis_load_minor: promis_load,
            entry_price_minor: entry,
            floor_price_minor: floor,
            call_price_minor: U256::ZERO,
            call_trigger: outbe_intex::IntexCallTrigger::default(),
            issued_at: T_NOW as u32,
            issuance_currency: 840,
            reference_currency: 840,
        },
    )
    .unwrap();
    runtime::issue_gem_position(storage, ALICE, source_intex_id(), U256::from(PARK_UNITS)).unwrap()
}

#[test]
fn issue_gem_position_burns_parks_and_issues_nft() {
    with_storage(None, |storage| {
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        let capacity = parked_capacity(six_decimal_u128());

        let factory = GemFactoryContract::new(storage.clone());
        let rec = factory.positions.get(id).unwrap().unwrap();
        assert_eq!(rec.merchant, ALICE);
        assert_eq!(rec.source_intex_id, source_intex_id());
        assert_eq!(rec.remaining_capacity, capacity);
        assert_eq!(rec.source_entry_price, six_decimal_unit());
        assert_eq!(factory.total_intex_parked.read().unwrap(), capacity);

        // Position NFT issued to the merchant.
        assert_eq!(factory.owner_of(id).unwrap(), ALICE);
        assert_eq!(factory.balance_of(ALICE).unwrap(), 1);
        assert_eq!(factory.token_of_owner_by_index(ALICE, 0).unwrap(), id);
    });
}

#[test]
fn parking_marks_the_units_realized_on_the_source_series() {
    with_storage(None, |storage| {
        seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        // Their load lives in the position now, so the source series can no
        // longer forfeit them.
        assert_eq!(
            outbe_intex::api::parked_units(storage, source_intex_id()).unwrap(),
            PARK_UNITS as u32
        );
    });
}

/// The position stays visible afterwards, as the spent object it is.
#[test]
fn an_expired_position_returns_its_remainder() {
    with_storage(None, |storage| {
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        let capacity = parked_capacity(six_decimal_u128());

        let ctx = block_ctx(storage, T_NOW + POSITION_VALIDITY_SECONDS - 1);
        assert_eq!(expired::sweep_expired_positions(&ctx).unwrap(), 0);
        assert_eq!(unallocated(storage), U256::ZERO);

        // At the instant issuing starts reverting, the sweep takes it.
        let ctx = block_ctx(storage, T_NOW + POSITION_VALIDITY_SECONDS);
        assert_eq!(expired::sweep_expired_positions(&ctx).unwrap(), 1);
        assert_eq!(unallocated(storage), capacity);

        let factory = GemFactoryContract::new(storage.clone());
        let record = factory.positions.get(id).unwrap().unwrap();
        assert_eq!(record.remaining_capacity, U256::ZERO);
        assert_eq!(factory.owner_of(id).unwrap(), ALICE);
    });
}

#[test]
fn a_drained_position_leaves_the_queue() {
    with_storage(Some(six_decimal_unit()), |storage| {
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        runtime::issue_merchant_gem(storage, ALICE, id, BOB, parked_capacity(six_decimal_u128()))
            .unwrap();

        let factory = GemFactoryContract::new(storage.clone());
        assert!(factory.live_queue_slot(0).unwrap().is_none());

        let ctx = block_ctx(storage, T_NOW + POSITION_VALIDITY_SECONDS);
        assert_eq!(expired::sweep_expired_positions(&ctx).unwrap(), 0);
        assert_eq!(unallocated(storage), U256::ZERO);
    });
}

fn block_ctx<'a>(storage: &StorageHandle<'a>, now: u64) -> BlockRuntimeContext<'a> {
    BlockRuntimeContext::new(BlockContext::empty_for_tests(1, now, 1), storage.clone())
}

fn unallocated(storage: &StorageHandle) -> U256 {
    outbe_promislimit::PromisLimitContract::new(storage.clone())
        .get_total_unallocated()
        .unwrap()
}

#[test]
fn issue_gem_position_unknown_source_rejects() {
    with_storage(None, |storage| {
        let r =
            runtime::issue_gem_position(storage, ALICE, source_intex_id(), U256::from(PARK_UNITS));
        assert!(err_msg(r).contains("source intex"));
    });
}

#[test]
fn issue_merchant_gem_mints_issued_and_drains_capacity() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        // source entry below coen -> entry follows coen.
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        let capacity = parked_capacity(six_decimal_u128());

        let load = U256::from(10u64) * six_decimal_unit();
        let gem_id = runtime::issue_merchant_gem(storage, ALICE, id, BOB, load).unwrap();

        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        assert_eq!(item.owner, BOB);
        assert_eq!(item.gem_type, GemTypes::Merchant as u8);
        assert_eq!(item.state, GemState::Issued as u8);
        assert_eq!(item.entry_price_minor, rate); // max(coen, source_entry) = coen
        assert_eq!(
            runtime::gem_cost_minor(&item).unwrap(),
            U256::from(20u64) * six_decimal_unit()
        ); // entry * load
        assert_eq!(
            item.floor_price_minor,
            rate * U256::from(108u64) / U256::from(100u64)
        );
        assert_eq!(
            item.call_price_minor,
            rate * U256::from(228u64) / U256::from(100u64)
        );

        let factory = GemFactoryContract::new(storage.clone());
        let rec = factory.positions.get(id).unwrap().unwrap();
        assert_eq!(rec.remaining_capacity, capacity - load);
        assert_eq!(factory.total_gems_issued.read().unwrap(), U256::from(1u64));
    });
}

#[test]
fn issue_merchant_gem_anchors_entry_and_floor_to_source() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        // source entry above coen, source floor above 1.08 * entry -> both dominate.
        let source_entry = U256::from(3u64) * six_decimal_unit();
        let source_floor = U256::from(5u64) * six_decimal_unit();
        let id = seed_and_park(storage, source_entry, source_floor, six_decimal_u128());

        let gem_id =
            runtime::issue_merchant_gem(storage, ALICE, id, BOB, six_decimal_unit()).unwrap();
        let item = gem_api::get_gem(storage, gem_id).unwrap().unwrap();
        assert_eq!(item.entry_price_minor, source_entry);
        assert_eq!(item.floor_price_minor, source_floor);
    });
}

#[test]
fn issue_merchant_gem_rejects_non_merchant() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        // BOB is not the position's merchant (ALICE) - must reject.
        let r = runtime::issue_merchant_gem(storage, BOB, id, BOB, six_decimal_unit());
        assert!(err_msg(r).contains("position owner"));
    });
}

#[test]
fn issue_merchant_gem_over_capacity_rejects() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        let id = seed_and_park(
            storage,
            six_decimal_unit(),
            six_decimal_unit(),
            six_decimal_u128(),
        );
        let over = parked_capacity(six_decimal_u128()) + U256::from(1u64);
        let r = runtime::issue_merchant_gem(storage, ALICE, id, BOB, over);
        assert!(err_msg(r).contains("capacity"));
    });
}

#[test]
fn issue_merchant_gem_after_expiry_rejects() {
    let rate = U256::from(2u64) * six_decimal_unit();
    with_storage(Some(rate), |storage| {
        // Craft a position whose parked_at is already past the validity window.
        let position_id = U256::from(1u64);
        let mut factory = GemFactoryContract::new(storage.clone());
        factory
            .add_position(&GemPosition {
                position_id,
                merchant: ALICE,
                source_intex_id: source_intex_id(),
                remaining_capacity: U256::from(100u64) * six_decimal_unit(),
                source_entry_price: six_decimal_unit(),
                source_floor_price: six_decimal_unit(),
                issuance_currency: 840,
                reference_currency: 840,
                parked_at: T_NOW - POSITION_VALIDITY_SECONDS - 1,
                expires_at: T_NOW - 1,
            })
            .unwrap();

        let r = runtime::issue_merchant_gem(storage, ALICE, position_id, BOB, six_decimal_unit());
        assert!(err_msg(r).contains("expired"));
    });
}
