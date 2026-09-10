use alloy_primitives::{address, keccak256, Address, B256, U256};
use alloy_sol_types::SolCall;
use outbe_intex::SeriesId;
use outbe_oracle::api::AddressPair;
use outbe_oracle::schema::OracleContract;
use outbe_primitives::addresses::INTEX_FACTORY_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::math::constants::REAL_ID_SHIFT;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::time::{date_key_to_utc_timestamp, previous_date_key, timestamp_to_date_key};

use crate::called;
use crate::constants::{
    CALL_RATE, CALL_THRESHOLD, CALL_WINDOW, FLOOR_RATE, MAX_RECIPIENTS_PER_ISSUANCE,
    MAX_SERIES_PER_MESSAGE,
};
use crate::precompile::{self, IIntexFactory};
use crate::qualified;
use crate::runtime;
use crate::schema::{IntexFactoryContract, IssuanceParams};
use crate::state::Group;

/// ISO code every fixture prices in.
const REFERENCE_ISO: u16 = 840;
const DAY: u64 = 24 * 60 * 60;

fn holder() -> Address {
    address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

fn payment_token() -> Address {
    address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
}

const CHAIN_ID: u64 = 1;
const ISSUED_AT: u32 = 1_700_000_000;
const PROMIS_LOAD_MINOR: u128 = 1_000_000; // 1 PROMIS in PROMIS-unit
const CALL_NOTICE_PERIOD: u32 = 7 * 24 * 60 * 60;

// COEN clearing price and the floor/trigger derived from it at issuance.
const ENTRY_PRICE: u64 = 1_000_000;
const EXPECTED_FLOOR: u64 = 1_080_000; // ENTRY_PRICE * 108/100
const EXPECTED_TRIGGER: u64 = 2_280_000; // ENTRY_PRICE * 228/100

fn with_factory<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(ISSUED_AT as u64));
    // Stub IntexNFT1155: void calls succeed; balanceOf returns 0 (32 bytes).
    storage.stub_sub_call_at(
        crate::constants::INTEX_NFT1155_ADDRESS,
        alloy_primitives::Bytes::from(vec![0u8; 32]),
    );
    // Stub OriginRouter: send* calls return bytes32 sendId (32 bytes); the value is ignored.
    storage.stub_sub_call_at(
        crate::constants::ORIGIN_ROUTER_ADDRESS,
        alloy_primitives::Bytes::from(vec![0u8; 32]),
    );
    StorageHandle::enter(&mut storage, |handle| {
        select_prod_profile(&handle);
        f(handle)
    })
}

/// These cases assert the PROD terms; an unset profile resolves by chain id, and
/// the test chain is not mainnet.
fn select_prod_profile(storage: &StorageHandle<'_>) {
    crate::schema::IntexFactoryContract::new(storage.clone())
        .config_profile
        .write(crate::config::PROFILE_PROD)
        .unwrap();
}

/// Test ids carry a fixed USD/U pair; only the day varies.
fn sid(worldwide_day: u32) -> SeriesId {
    SeriesId::pack(WorldwideDay::new(worldwide_day), *b"USD", b'U').unwrap()
}

/// Force-call one group against the protocol call window; how many series moved.
fn call_group(
    s: &StorageHandle<'_>,
    f: &mut IntexFactoryContract,
    oracle: &OracleContract,
    pair: AddressPair,
    group: &Group,
    last_closed_day: u32,
    now_ts: u64,
) -> u32 {
    let mut vwaps = called::DayVwaps::new(oracle.pair_index_of(pair).unwrap());
    let secs_per_day = DAY as u32;
    let Some(window) = called::call_window(
        oracle,
        &mut vwaps,
        last_closed_day,
        CALL_WINDOW / secs_per_day,
        CALL_THRESHOLD / secs_per_day,
    )
    .unwrap() else {
        return 0;
    };
    called::try_call_group(s, f, oracle, &mut vwaps, group, &window, now_ts).unwrap()
}

/// Qualify one day's group in the reference currency; returns how many series moved.
fn qualify_day(
    s: &StorageHandle<'_>,
    f: &mut IntexFactoryContract,
    worldwide_day: u32,
    rate: U256,
) -> u32 {
    let group = f
        .unqualified_group(REFERENCE_ISO, WorldwideDay::new(worldwide_day))
        .unwrap();
    qualified::try_qualify_group(s, f, &group, rate).unwrap()
}

fn sample(worldwide_day: u32) -> IssuanceParams {
    IssuanceParams {
        series_id: sid(worldwide_day),
        worldwide_day: worldwide_day.into(),
        issued_intex_count: 100,
        promis_load_minor: PROMIS_LOAD_MINOR,
        entry_price_minor: U256::from(ENTRY_PRICE),
        issuance_currency: 840,
        reference_currency: 840,
        recipients: vec![],
        quantities: vec![],
        recipient_chains: vec![],
        // One target in the snapshot exercises the per-chain ISSUANCE loop (empty recipients).
        snapshot_chains: vec![1],
    }
}

mod creator_reward;
mod entrypoints;
mod groups;
mod issuance;
mod lifecycle;
mod scans;
mod settlement;

// --- // --- Shared across the test modules ---
const PAIR_ID: u32 = 1;
const EUR_ISO: u16 = 978;
const EUR_PAIR_ID: u32 = 2;

fn word(value: u64) -> alloy_primitives::Bytes {
    alloy_primitives::Bytes::from(U256::from(value).to_be_bytes::<32>().to_vec())
}

fn write_rate(oracle: &OracleContract, iso_code: u16, pair_id: u32, rate: U256) {
    let pair = outbe_oracle::api::AddressPair::new_coen_to(iso_code);
    oracle.pair_to_index.write(&pair, pair_id).unwrap();
    oracle.exchange_rate.write(&pair_id, rate).unwrap();
    oracle
        .exchange_rate_timestamp
        .write(&pair_id, ISSUED_AT as u64)
        .unwrap();
}
