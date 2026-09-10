//! Shared test harness for the credisfactory crate.
//!
//! The confidential Gratis path runs against the in-process enclave engine
//! (`outbe_gratis::enclave_client::test_enclave`); balances/pledged amounts are
//! asserted by decrypting the ciphertext with the account's view key, exactly as
//! a client would. `HashMapStorageProvider` does not run a real EVM, so the
//! runtime's Rust -> Solidity sub-calls into `IVaultRouter` / `IERC20` are
//! stubbed via `enable_sub_call_stub` (returns `default_success()`).

use alloy_primitives::{address, Address, Bytes, B256, U256};
use outbe_primitives::addresses::CREDIS_FACTORY_ADDRESS;

use outbe_credis::CredisContract;
use outbe_fidelity::enclave_client::test_enclave as fidelity_enclave;
use outbe_gratis::enclave_client::test_enclave;
use outbe_gratisfactory::runtime as gf;
use outbe_oracle::schema::OracleContract;
use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::{Bytecode, StorageHandle};
use outbe_primitives::time::{previous_date_key, timestamp_to_date_key};
use outbe_primitives::units::{checked_protocol_to_native, SCALE_1E6_U256};
use outbe_tee::protocol::{GratisOp, ModifyAuth};
use outbe_tee_enclave::gratis::{
    decrypt_balance, decrypt_pledged, derive_modify_key, derive_view_key, modify_mac,
    pledge_secret, spend_auth_mac,
};

use crate::runtime;

pub const CHAIN_ID: u64 = 1;
pub const CREATED_AT: u64 = 1_700_000_000;
pub const BLOCK_NUMBER: u64 = 42;

/// Issuance currency (ISO 4217) reported by [`asset`]'s stubbed `isoCode()`.
/// Denominates the loan and keys the policy rate.
pub const ISSUANCE_ISO: u16 = 840;

/// Reference currency every position here elects. Deliberately distinct from
/// [`ISSUANCE_ISO`] so a test that passes on the wrong series cannot pass by
/// coincidence. Both pairs are seeded at the same spot rate, so the position
/// geometry (entry 2.0, call 3.28) is unchanged by the choice.
pub const REFERENCE_ISO: u16 = 978;

pub const DAY: u64 = 86_400;

pub fn alice() -> Address {
    address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

pub fn bob() -> Address {
    address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
}

pub fn asset() -> Address {
    address!("0x0000000000000000000000000000000000000888")
}

/// The originating agent. `requestCredis`'s caller is recorded on the position.
pub fn cca() -> Address {
    address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
}

/// Policy rate seeded for USD in these tests (4.30 %, scale 1e6).
pub fn policy_rate() -> U256 {
    U256::from(43_000u64)
}

/// COEN rate these tests seed on BOTH pairs: 2.0 at scale 1e6. The COEN/978 leg
/// is what a position's entry price is struck from, so call = 3.28.
pub fn oracle_rate() -> U256 {
    U256::from(2u64) * SCALE_1E6_U256
}

/// A price below every position's call price (3.28), so such a day is not a breach.
pub fn below_call() -> U256 {
    U256::from(2_200_000u64)
}

/// Exactly every position's call price (3.28). The breach test is strictly `>`,
/// so a day at this value does not count.
pub fn at_call() -> U256 {
    U256::from(3_280_000u64)
}

/// One minor unit above every position's call price (3.28), the tightest price
/// that counts as a breach day.
pub fn above_call() -> U256 {
    at_call() + U256::from(1u64)
}

/// Credit a pledge asks for: $2.00 in 6-decimal minor units. At [`oracle_rate`] that
/// costs exactly [`pledge_cost`] gratis.
pub fn pledge_stables() -> U256 {
    U256::from(2_000_000u64)
}

/// Gratis collateral [`pledge_stables`] costs: `2e6 * 1e6 / 2e6 = 1e6`.
pub fn pledge_cost() -> U256 {
    SCALE_1E6_U256
}

/// Native COEN stake matching [`pledge_cost`] GRATIS one for one by value.
pub fn pledge_stake() -> U256 {
    checked_protocol_to_native(pledge_cost()).expect("pledge fixture fits native U256")
}

/// Pledge [`pledge_stables`] of credit for `who` at op-nonce `nonce` (uncapped), and
/// return the resulting handle. The gratis it costs is derived from the seeded rate.
pub fn pledge(storage: &StorageHandle<'_>, who: Address, nonce: u64) -> B256 {
    let (handle, gratis_cost) = gf::pledge_gratis(
        storage.clone(),
        who,
        pledge_stables(),
        asset(),
        U256::MAX,
        auth(GratisOp::Pledge, who, pledge_stables(), nonce),
    )
    .unwrap();
    assert_eq!(gratis_cost, pledge_cost(), "seeded rate drifted");
    handle
}

/// Pledge and open a position for alice, originated by [`cca`].
pub fn open(storage: &StorageHandle<'_>, nonce: u64) -> U256 {
    open_for(storage, alice(), nonce)
}

/// Pledge and open a position owned by `who`, originated by [`cca`].
pub fn open_for(storage: &StorageHandle<'_>, who: Address, nonce: u64) -> U256 {
    let handle = pledge(storage, who, nonce);
    let spend = credis_spend_auth(who, handle, who);
    fund_stake(storage, pledge_stake());
    let (position_id, _) = runtime::request_credis(
        storage.clone(),
        cca(),
        who,
        handle,
        spend,
        REFERENCE_ISO,
        pledge_stake(),
    )
    .unwrap();
    position_id
}

pub fn chain_b256() -> B256 {
    B256::from(U256::from(CHAIN_ID))
}

/// Registers the `COEN/840` and `COEN/978` pairs, seeds both spot rates, the USD
/// policy rate, and the reference-currency registry `request_credis` validates
/// the elected anchor against. Idempotent - `bootstrap_for` calls it once per owner.
pub fn seed_oracle(storage: StorageHandle<'_>, coen_iso_rate: U256) {
    if outbe_oracle::api::coen_pair_index_opt(storage.clone(), ISSUANCE_ISO)
        .unwrap()
        .is_none()
    {
        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
    }
    register_reference_pair(&storage, REFERENCE_ISO);
    set_coen_rate(&storage, coen_iso_rate);
    set_coen_rate_for(&storage, REFERENCE_ISO, coen_iso_rate);
    let oracle = OracleContract::new(storage);
    oracle
        .policy_rate
        .write(&ISSUANCE_ISO, policy_rate())
        .unwrap();
}

/// Registers `COEN/<iso>` and admits `iso` to the reference-currency registry, so
/// a position may elect it. Idempotent in both halves.
pub fn register_reference_pair(storage: &StorageHandle<'_>, iso: u16) {
    if outbe_oracle::api::coen_pair_index_opt(storage.clone(), iso)
        .unwrap()
        .is_none()
    {
        outbe_oracle::api::register_pair(
            storage.clone(),
            outbe_oracle::api::AddressPair::new_coen_to(iso),
        )
        .unwrap();
    }
    let oracle = OracleContract::new(storage.clone());
    if outbe_oracle::api::check_reference_currency_with_storage(storage.clone(), iso).is_err() {
        oracle.reference_currencies.push(iso).unwrap();
    }
}

/// Re-publishes the COEN/840 spot rate - how these tests move the live price
/// across a floor. Distinct from the finalized daily series ([`set_vwap`]),
/// which is what the daily scan reads.
pub fn set_coen_rate(storage: &StorageHandle<'_>, coen_iso_rate: U256) {
    set_coen_rate_for(storage, ISSUANCE_ISO, coen_iso_rate);
}

/// [`set_coen_rate`] on an arbitrary pair. The COEN/`REFERENCE_ISO` leg is the one
/// `request_credis` strikes a position's entry price from.
pub fn set_coen_rate_for(storage: &StorageHandle<'_>, iso: u16, coen_iso_rate: U256) {
    let timestamp = storage.timestamp().unwrap().to::<u64>();
    outbe_oracle::api::set_exchange_rate(
        storage.clone(),
        Address::ZERO,
        outbe_oracle::api::AddressPair::new_coen_to(iso),
        coen_iso_rate,
        1,
        timestamp,
    )
    .unwrap();
}

// -------------------------------------------------------------------------
// Finalized daily reference series - the only price source the daily scan reads
// -------------------------------------------------------------------------

/// The most recent fully-closed UTC day at `timestamp`, i.e. the day the scan
/// treats as the newest data point.
pub fn last_closed_day(timestamp: u64) -> u32 {
    previous_date_key(timestamp_to_date_key(timestamp))
}

/// Advances the finalization watermark to cover the day closed at `timestamp`
/// without publishing a price for any day. The scan then runs but finds no
/// reference series, so only price-independent transitions (the void) apply.
pub fn finalize_through(storage: &StorageHandle<'_>, timestamp: u64) {
    bump_watermark(storage, last_closed_day(timestamp));
}

/// Publishes a finalized daily reference price for one UTC day on `COEN/<iso>`.
pub fn set_vwap_for(storage: &StorageHandle<'_>, iso: u16, utc_day: u32, value: U256) {
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

/// [`set_vwap_for`] on [`REFERENCE_ISO`] - the series the scan actually reads,
/// since the call threshold is anchored to the position's reference currency.
pub fn set_vwap(storage: &StorageHandle<'_>, utc_day: u32, value: U256) {
    set_vwap_for(storage, REFERENCE_ISO, utc_day, value);
}

/// Sets `days` consecutive closed UTC days ending at `latest` to `value` on the
/// reference series.
pub fn fill_days(storage: &StorageHandle<'_>, latest: u32, days: u32, value: U256) {
    fill_days_for(storage, REFERENCE_ISO, latest, days, value)
}

/// [`fill_days`] on an arbitrary `COEN/<iso>` series.
pub fn fill_days_for(storage: &StorageHandle<'_>, iso: u16, latest: u32, days: u32, value: U256) {
    let mut day = latest;
    for _ in 0..days {
        set_vwap_for(storage, iso, day, value);
        day = previous_date_key(day);
    }
}

/// Mirrors the oracle begin-block hook: the watermark covers every seeded day.
fn bump_watermark(storage: &StorageHandle<'_>, utc_day: u32) {
    let oracle = OracleContract::new(storage.clone());
    if oracle.utc_day_vwap_last_finalized.read().unwrap() < utc_day {
        oracle.utc_day_vwap_last_finalized.write(utc_day).unwrap();
    }
}

/// Runs the daily price-path scan at `timestamp`, returning how many positions
/// it moved.
pub fn scan(storage: &StorageHandle<'_>, timestamp: u64) -> u32 {
    let ctx = BlockRuntimeContext::new(
        BlockContext::empty_for_tests(BLOCK_NUMBER, timestamp, CHAIN_ID),
        storage.clone(),
    );
    crate::called::scan_and_call(&ctx).unwrap()
}

pub fn now_of(storage: &StorageHandle<'_>) -> u64 {
    storage.timestamp().unwrap().to::<u64>()
}

pub fn advance_to(storage: &StorageHandle<'_>, timestamp: u64) {
    storage.set_block_timestamp(U256::from(timestamp)).unwrap();
}

/// Settles exactly the accrued interest plus `principal` of the outstanding
/// balance, and returns the `(principal, interest)` the settlement reported.
pub fn settle_principal(
    storage: &StorageHandle<'_>,
    payer: Address,
    position_id: U256,
    principal: U256,
) -> (U256, U256) {
    let position = CredisContract::new(storage.clone())
        .get_position(position_id)
        .unwrap();
    let interest = CredisContract::accrued_interest(&position, now_of(storage)).unwrap();
    runtime::settle(storage.clone(), payer, position_id, interest + principal).unwrap()
}

/// ABI-encoded `uint16` return for the asset's `isoCode()` static sub-call.
pub fn iso_word(iso: u16) -> Bytes {
    let mut b = vec![0u8; 32];
    b[30..32].copy_from_slice(&iso.to_be_bytes());
    Bytes::from(b)
}

/// 32-byte zero word - the stubbed `uint256` return for the vault sub-calls.
pub fn zero_word() -> Bytes {
    Bytes::from(vec![0u8; 32])
}

/// Positive Fidelity so `gratisfactory::pledge_gratis` clears the eligibility gate.
pub fn seed_fidelity(storage: StorageHandle<'_>, account: Address) {
    const ONE_YEAR_SECS: u64 = 365 * 86_400;
    outbe_fidelity::api::cohort_in(
        storage,
        account,
        U256::from(100u64),
        CREATED_AT - ONE_YEAR_SECS,
    )
    .unwrap();
}

pub fn auth(op: GratisOp, owner: Address, amount: U256, op_nonce: u64) -> ModifyAuth {
    let mk = derive_modify_key(&test_enclave::state_key(), owner).unwrap();
    ModifyAuth {
        mac: modify_mac(&mk, owner, op, amount, op_nonce, chain_b256()),
        op_nonce,
    }
}

pub fn view_balance(s: &StorageHandle<'_>, a: Address) -> U256 {
    let vk = derive_view_key(&test_enclave::state_key(), a).unwrap();
    let blob = outbe_gratis::api::balance_ct(s.clone(), a).unwrap();
    if blob.is_empty() {
        return U256::ZERO;
    }
    decrypt_balance(&vk, a, &blob).unwrap()
}

pub fn view_pledged(s: &StorageHandle<'_>, a: Address) -> U256 {
    let vk = derive_view_key(&test_enclave::state_key(), a).unwrap();
    let blob = outbe_gratis::api::pledged_ct(s.clone(), a).unwrap();
    if blob.is_empty() {
        return U256::ZERO;
    }
    decrypt_pledged(&vk, a, &blob).unwrap()
}

/// The spend authorization the pledger EOA hands to the CCA to bind a pledge to a
/// destination smart account (`HMAC(pledgeSecret, "credis-bind" || bundle)`).
pub fn credis_spend_auth(eoa: Address, handle: B256, bundle: Address) -> [u8; 32] {
    let mk = derive_modify_key(&test_enclave::state_key(), eoa).unwrap();
    spend_auth_mac(&pledge_secret(&mk, handle), bundle)
}

/// Storage set up with the block time, sub-call stubs, and the enclave installed.
pub fn env() -> HashMapStorageProvider {
    test_enclave::install();
    fidelity_enclave::install();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(CREATED_AT));
    storage.set_block_number(BLOCK_NUMBER);
    storage.enable_sub_call_stub();
    storage.stub_sub_call_at(VAULT_ROUTER_ADDRESS, zero_word());
    storage.stub_sub_call_at(asset(), iso_word(ISSUANCE_ISO));
    storage
}

/// Mints `amount` gratis to alice and seeds the fidelity + oracle state a pledge needs.
pub fn bootstrap(storage: &StorageHandle<'_>, amount: U256) {
    bootstrap_for(storage, alice(), amount);
}

/// [`bootstrap`] for an arbitrary owner, so a test can open positions for
/// several distinct accounts.
pub fn bootstrap_for(storage: &StorageHandle<'_>, who: Address, amount: U256) {
    outbe_gratis::api::mint(
        storage.clone(),
        who,
        amount,
        auth(GratisOp::Mint, who, amount, 0),
    )
    .unwrap();
    seed_fidelity(storage.clone(), who);
    seed_oracle(storage.clone(), oracle_rate());
    deploy_smart_account(storage, who);
}

/// Gives `who` non-empty code so `request_credis`'s deployed-account guard passes.
/// The bytes are never executed - `HashMapStorageProvider` runs no EVM - only the
/// code hash is read.
pub fn deploy_smart_account(storage: &StorageHandle<'_>, who: Address) {
    storage
        .set_code(who, Bytecode::new_raw(Bytes::from_static(&[0xef])))
        .unwrap();
}

/// Credits the factory with the stake the payable boundary would have credited.
///
/// Tests drive `runtime::request_credis` directly, below the precompile boundary that
/// moves `msg.value`, so without this the escrow would have a claim with no COEN
/// behind it and the release would underflow.
pub fn fund_stake(storage: &StorageHandle<'_>, amount: U256) {
    storage
        .increase_balance(CREDIS_FACTORY_ADDRESS, amount)
        .unwrap();
}

pub fn teardown() {
    fidelity_enclave::uninstall();
    test_enclave::uninstall();
}
