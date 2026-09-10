use alloy_primitives::{U256, U512};

use super::math;
use crate::fixed::FixedValue;

use super::{
    config::{DexMarketConfig, DexProviderConfig, PoolConfig},
    rpc::{Log, Rpc},
    worker::{DexProvider, MarketWorker},
};
use crate::{config::FeederConfig, provider::Provider};
use alloy_primitives::{
    aliases::{I24, U112, U160, U24},
    Address, Bytes, B256, I256,
};
use alloy_sol_types::SolValue;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

fn fp(value: &str) -> FixedValue {
    FixedValue::parse(value).unwrap()
}

#[test]
fn raw_rate_orientation_decimals_and_limits() {
    // Two 18-decimal COEN against six 6-decimal USDC -> 3 USDC/COEN.
    let base = U512::from(2_000_000_000_000_000_000u64);
    let quote = U512::from(6_000_000u64);
    assert_eq!(math::rate(quote, base, 18, 6).unwrap(), fp("3"));
    assert_eq!(
        math::rate(base, quote, 6, 18).unwrap(),
        fp("0.333333333333333333")
    );
    assert_eq!(
        math::base_volume(U256::from(2_000_000u64), 6).unwrap(),
        fp("2")
    );
    assert_eq!(math::base_volume(U256::ZERO, 18).unwrap(), fp("0"));
    assert!(math::rate(U512::ZERO, base, 18, 6).is_err());
    assert!(math::rate(quote, U512::ZERO, 18, 6).is_err());
    assert!(math::rate(U512::MAX, U512::ONE, 18, 6).is_err());
    assert!(math::base_volume(U256::MAX, 0).is_err());
    assert!(math::rate(quote, base, 78, 6).is_err());
    // Largest uint160 square requires 320 bits, beyond U256.
    let sqrt = (U512::ONE << 160) - U512::ONE;
    assert!(math::rate(sqrt * sqrt, U512::ONE << 192, 18, 18).is_ok());
}

#[test]
fn infinity_bin_prices_follow_bin_step_and_reciprocal() {
    let center = 1 << 23;
    let scale = U256::ONE << 128;
    assert_eq!(math::bin_price(center, 25).unwrap(), scale);
    let up = math::bin_price(center + 1, 25).unwrap();
    let down = math::bin_price(center - 1, 25).unwrap();
    // PriceHelper's Q128.128 rounding is just below the exact decimal 1.0025.
    assert_eq!(
        math::rate(U512::from(up), U512::from(scale), 18, 18).unwrap(),
        fp("1.002499999999999999")
    );
    assert_eq!(
        math::rate(U512::from(down), U512::from(scale), 18, 18).unwrap(),
        fp("0.997506234413965087")
    );
    assert!(math::bin_price(center, 0).is_err());
    assert!(math::bin_price(center + 0x10_0000, 25).is_err());
    assert!(math::bin_price(center + 100_000, 65_535).is_err());
}

fn address(n: u8) -> Address {
    Address::from([n; 20])
}
fn hash(n: u64) -> B256 {
    B256::from(U256::from(n).to_be_bytes::<32>())
}

fn market(pool: PoolConfig, reversed: bool) -> DexMarketConfig {
    DexMarketConfig {
        base: "COEN".into(),
        quote: "USDC".into(),
        base_token: address(if reversed { 2 } else { 1 }),
        quote_token: address(if reversed { 1 } else { 2 }),
        pool,
    }
}

fn protocols() -> Vec<PoolConfig> {
    vec![
        PoolConfig::UniswapV2 {
            address: address(3),
        },
        PoolConfig::PancakeswapV2 {
            address: address(3),
        },
        PoolConfig::UniswapV3 {
            address: address(3),
        },
        PoolConfig::PancakeswapV3 {
            address: address(3),
        },
        PoolConfig::UniswapV4 {
            manager: address(3),
            state_view: address(4),
            fee: 3000,
            tick_spacing: 60,
            hooks: address(5),
        },
        PoolConfig::InfinityCl {
            manager: address(3),
            fee: 3000,
            hooks: address(5),
            parameters: hash(60 << 16),
        },
        PoolConfig::InfinityBin {
            manager: address(3),
            fee: 3000,
            hooks: address(5),
            parameters: hash(25 << 16),
        },
    ]
}

fn dex_config(market: DexMarketConfig, endpoint: String) -> DexProviderConfig {
    let uni = matches!(
        market.pool,
        PoolConfig::UniswapV2 { .. } | PoolConfig::UniswapV3 { .. } | PoolConfig::UniswapV4 { .. }
    );
    DexProviderConfig {
        name: if uni { "uniswap" } else { "pancakeswap" }.into(),
        chain_id: if uni { 1 } else { 56 },
        rpc_endpoint: endpoint,
        poll_interval_secs: 1,
        log_chunk_blocks: 2_000,
        max_finalized_age_secs: 1800,
        markets: vec![market],
    }
}

fn swap_log(market: &DexMarketConfig, block: u64, block_hash: B256, base_amount: u64) -> Value {
    let raw = U256::from(base_amount) * fp("1").raw();
    let signed = I256::try_from(raw).unwrap();
    let (a0, a1) = if market.base_is_token0() {
        (signed, -signed * I256::try_from(4).unwrap())
    } else {
        (-signed * I256::try_from(4).unwrap(), signed)
    };
    let sqrt = U160::from(2u64) << 96;
    let data = match market.pool {
        PoolConfig::UniswapV2 { .. } | PoolConfig::PancakeswapV2 { .. } => {
            let zero = U256::ZERO;
            if market.base_is_token0() {
                (raw, zero, zero, raw * U256::from(4)).abi_encode()
            } else {
                (zero, raw, raw * U256::from(4), zero).abi_encode()
            }
        }
        PoolConfig::UniswapV3 { .. } => (a0, a1, sqrt, 1u128, I24::ZERO).abi_encode(),
        PoolConfig::PancakeswapV3 { .. } => {
            (a0, a1, sqrt, 1u128, I24::ZERO, 7u128, 9u128).abi_encode()
        }
        PoolConfig::UniswapV4 { .. } => (
            i128::try_from(a0).unwrap(),
            i128::try_from(a1).unwrap(),
            sqrt,
            1u128,
            I24::ZERO,
            U24::from(3000u16),
        )
            .abi_encode(),
        PoolConfig::InfinityCl { .. } => (
            i128::try_from(a0).unwrap(),
            i128::try_from(a1).unwrap(),
            sqrt,
            1u128,
            I24::ZERO,
            U24::from(3000u16),
            10u16,
        )
            .abi_encode(),
        PoolConfig::InfinityBin { .. } => (
            i128::try_from(a0).unwrap(),
            i128::try_from(a1).unwrap(),
            U24::from(1u32 << 23),
            U24::from(3000u16),
            10u16,
        )
            .abi_encode(),
    };
    json!({"address":market.pool.address(), "topics":[market.pool.swap_topic(), market.pool.pool_id(market).unwrap().unwrap_or_default(), B256::ZERO],
        "data":Bytes::from(data), "blockNumber":format!("0x{block:x}"), "blockHash":block_hash,
        "transactionHash":hash(block + 100), "logIndex":"0x0", "removed":false})
}

struct Fixture {
    market: DexMarketConfig,
    now: u64,
    chain: u64,
    head: AtomicU64,
    fail_logs: AtomicBool,
    empty_logs: AtomicBool,
    corrupt_logs: AtomicBool,
    wrong_chain: AtomicBool,
    wrong_token: AtomicBool,
    stale: AtomicBool,
    reorg: AtomicBool,
    calls: Mutex<Vec<Value>>,
}

impl Fixture {
    fn block(&self, number: u64) -> Value {
        let offset = match number {
            0 => -172_800,
            1 => -86_401,
            2 => -86_400,
            3 => -86_399,
            4 => 0,
            _ => 2,
        };
        let timestamp = self.now.checked_add_signed(offset).unwrap();
        let timestamp = if self.stale.load(Ordering::Relaxed) {
            timestamp - 7200
        } else {
            timestamp
        };
        json!({"number":format!("0x{number:x}"), "hash":self.block_hash(number), "timestamp":format!("0x{timestamp:x}")})
    }

    fn block_hash(&self, number: u64) -> B256 {
        hash(
            number
                + if self.reorg.load(Ordering::Relaxed) {
                    1000
                } else {
                    0
                },
        )
    }

    fn response(&self, request: &Value) -> Value {
        self.calls.lock().unwrap().push(request.clone());
        let method = request["method"].as_str().unwrap();
        let params = &request["params"];
        let result = match method {
            "eth_chainId" => json!(format!(
                "0x{:x}",
                if self.wrong_chain.load(Ordering::Relaxed) {
                    999
                } else {
                    self.chain
                }
            )),
            "eth_getBlockByNumber" => {
                let tag = params[0].as_str().unwrap();
                let number = if tag == "finalized" {
                    self.head.load(Ordering::Relaxed)
                } else {
                    super::rpc::quantity(tag).unwrap()
                };
                self.block(number)
            }
            "eth_call" => {
                assert_eq!(params[1]["requireCanonical"], true);
                assert!(params[1]["blockHash"].is_string());
                let data: Bytes = serde_json::from_value(params[0]["data"].clone()).unwrap();
                let selector = |s: &str| alloy_primitives::keccak256(s).as_slice()[..4].to_vec();
                let output = if data[..4] == selector("decimals()") {
                    U256::from(18u8).abi_encode()
                } else if data[..4] == selector("token0()") {
                    (if self.wrong_token.load(Ordering::Relaxed) {
                        Address::ZERO
                    } else {
                        self.market.tokens().0
                    })
                    .abi_encode()
                } else if data[..4] == selector("token1()") {
                    self.market.tokens().1.abi_encode()
                } else if data[..4] == selector("poolManager()") {
                    self.market.pool.address().abi_encode()
                } else if data[..4] == selector("getReserves()") {
                    (U112::from(1u8), U112::from(4u8), 0u32).abi_encode()
                } else if data[..4] == selector("slot0()") {
                    // Nonzero upper fee bits expose use of the wrong V3 ABI.
                    let fee = if matches!(self.market.pool, PoolConfig::PancakeswapV3 { .. }) {
                        0x10_0000u32
                    } else {
                        0u32
                    };
                    (
                        U160::from(2u64) << 96,
                        I24::ZERO,
                        0u16,
                        0u16,
                        0u16,
                        fee,
                        true,
                    )
                        .abi_encode()
                } else if data[..4] == selector("getSlot0(bytes32)") {
                    let id = self.market.pool.pool_id(&self.market).unwrap().unwrap();
                    assert_eq!(&data[4..], id.as_slice());
                    if matches!(self.market.pool, PoolConfig::InfinityBin { .. }) {
                        (U24::from(1u32 << 23), U24::ZERO, U24::ZERO).abi_encode()
                    } else {
                        (U160::from(2u64) << 96, I24::ZERO, U24::ZERO, U24::ZERO).abi_encode()
                    }
                } else {
                    panic!("unexpected eth_call: {data}");
                };
                json!(Bytes::from(output))
            }
            "eth_getLogs" => {
                let from = super::rpc::quantity(params[0]["fromBlock"].as_str().unwrap()).unwrap();
                let to = super::rpc::quantity(params[0]["toBlock"].as_str().unwrap()).unwrap();
                assert!(to <= self.head.load(Ordering::Relaxed));
                assert_eq!(
                    params[0]["topics"],
                    json!(self.market.log_topics().unwrap())
                );
                if self.fail_logs.load(Ordering::Relaxed) || to - from > 1 {
                    return json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32005,"message":"range limit"}});
                }
                let mut logs = Vec::new();
                if !self.empty_logs.load(Ordering::Relaxed) {
                    for (block, amount) in [(2, 900), (3, 100), (4, 200), (5, 400)] {
                        if (from..=to).contains(&block) {
                            let mut log =
                                swap_log(&self.market, block, self.block_hash(block), amount);
                            if self.corrupt_logs.load(Ordering::Relaxed) && block == 4 {
                                log["blockHash"] = json!(hash(9999));
                            }
                            logs.push(log.clone());
                            logs.push(log); // Duplicate RPC rows must not increase volume.
                        }
                    }
                }
                json!(logs)
            }
            _ => panic!("unexpected RPC method {method}"),
        };
        json!({"jsonrpc":"2.0", "id":request["id"], "result":result})
    }
}

struct Server {
    task: JoinHandle<()>,
    endpoint: String,
    fixture: Arc<Fixture>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(market: DexMarketConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let config = dex_config(market.clone(), endpoint.clone());
        let fixture = Arc::new(Fixture {
            market,
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            chain: config.chain_id,
            head: AtomicU64::new(4),
            fail_logs: AtomicBool::new(false),
            empty_logs: AtomicBool::new(false),
            corrupt_logs: AtomicBool::new(false),
            wrong_chain: AtomicBool::new(false),
            wrong_token: AtomicBool::new(false),
            stale: AtomicBool::new(false),
            reorg: AtomicBool::new(false),
            calls: Mutex::new(vec![]),
        });
        let state = Arc::clone(&fixture);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                // Sequential handling is sufficient: each worker awaits its RPC.
                let mut request = Vec::new();
                let (header_end, length) = loop {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                        let length = headers
                            .lines()
                            .find_map(|s| s.strip_prefix("content-length:"))
                            .unwrap()
                            .trim()
                            .parse::<usize>()
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while request.len() < header_end + length {
                    let mut chunk = [0u8; 4096];
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&chunk[..count]);
                }
                let request: Value =
                    serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
                let body = state.response(&request).to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self {
            task,
            endpoint,
            fixture,
        }
    }

    fn worker(&self) -> MarketWorker {
        MarketWorker::new(
            dex_config(self.fixture.market.clone(), self.endpoint.clone()),
            self.fixture.market.clone(),
            Rpc::new(&self.endpoint).unwrap(),
        )
    }
}

#[tokio::test]
async fn all_protocols_read_finalized_spot_and_base_volume_in_both_orientations() {
    for pool in protocols() {
        for reversed in [false, true] {
            let bin = matches!(pool, PoolConfig::InfinityBin { .. });
            let server = Server::start(market(pool.clone(), reversed)).await;
            let (block, ticker) = server.worker().refresh().await.unwrap();
            assert_eq!(block.number, 4);
            assert_eq!(
                ticker.price,
                fp(if bin {
                    "1"
                } else if reversed {
                    "0.25"
                } else {
                    "4"
                })
            );
            assert_eq!(ticker.volume, fp("300"));
            assert!(server
                .fixture
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["params"][0] == "finalized"));
        }
    }
}

#[tokio::test]
async fn volume_window_retries_restart_and_finalized_history_changes() {
    let server = Server::start(market(protocols()[0].clone(), false)).await;
    let mut worker = server.worker();
    assert_eq!(worker.refresh().await.unwrap().1.volume, fp("300"));
    assert_eq!(worker.refresh().await.unwrap().1.volume, fp("300"));
    assert_eq!(server.worker().refresh().await.unwrap().1.volume, fp("300"));
    server.fixture.head.store(5, Ordering::Relaxed);
    server.fixture.fail_logs.store(true, Ordering::Relaxed);
    assert!(worker.refresh().await.is_err());
    server.fixture.fail_logs.store(false, Ordering::Relaxed);
    // Block 3 is now outside (head_time - 24h, head_time]; block 5 is new.
    assert_eq!(worker.refresh().await.unwrap().1.volume, fp("600"));
    server.fixture.reorg.store(true, Ordering::Relaxed);
    assert!(worker.refresh().await.is_err());
    assert_eq!(worker.refresh().await.unwrap().1.volume, fp("600"));
}

#[tokio::test]
async fn missing_or_invalid_data_is_an_error_but_real_zero_volume_is_valid() {
    let server = Server::start(market(protocols()[2].clone(), false)).await;
    for flag in [
        &server.fixture.fail_logs,
        &server.fixture.corrupt_logs,
        &server.fixture.wrong_chain,
        &server.fixture.wrong_token,
        &server.fixture.stale,
    ] {
        flag.store(true, Ordering::Relaxed);
        assert!(server.worker().refresh().await.is_err());
        flag.store(false, Ordering::Relaxed);
    }
    server.fixture.empty_logs.store(true, Ordering::Relaxed);
    let (_, ticker) = server.worker().refresh().await.unwrap();
    assert_eq!(ticker.price, fp("4"));
    assert_eq!(ticker.volume, fp("0"));
}

#[tokio::test]
async fn invalid_second_log_does_not_commit_or_double_count_the_first() {
    let server = Server::start(market(protocols()[0].clone(), false)).await;
    let mut worker = server.worker();
    server.fixture.corrupt_logs.store(true, Ordering::Relaxed);
    assert!(worker.refresh().await.is_err());
    server.fixture.corrupt_logs.store(false, Ordering::Relaxed);
    assert_eq!(worker.refresh().await.unwrap().1.volume, fp("300"));
}

#[test]
fn example_configuration_and_source_routing_are_validated() {
    let text = include_str!("../../../dex.example.toml");
    let config: FeederConfig = toml::from_str(text).unwrap();
    config.validate().unwrap();
    for invalid in [
        text.replace("protocol = \"uniswap_v3\"", "protocol = \"uniswap_v33\""),
        text.replace("quote = \"840\"", "quote = \"978\""),
        text.replacen("quote = \"USDC\"", "quote = \"USDT\"", 1),
        text.replace("chain_id = 56", "chain_id = 1"),
    ] {
        let result = toml::from_str::<FeederConfig>(&invalid)
            .map_err(eyre::Report::from)
            .and_then(|c| c.validate());
        assert!(result.is_err());
    }
    let mut missing = config;
    missing.dex_providers.clear();
    assert!(missing.validate().is_err());
}

#[test]
fn malformed_events_and_wrong_pool_are_rejected() {
    for pool in protocols() {
        let market = market(pool, false);
        let valid = swap_log(&market, 4, hash(4), 100);
        let log: Log = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(market.swap_volume(&log).unwrap(), fp("100").raw());
        for (field, value) in [
            ("removed", json!(true)),
            ("address", json!(address(99))),
            ("data", json!("0x00")),
            ("topics", json!([hash(1), hash(2), hash(3)])),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            let log: Log = serde_json::from_value(invalid).unwrap();
            assert!(market.swap_volume(&log).is_err());
        }
        if market.pool.pool_id(&market).unwrap().is_some() {
            let mut wrong_pool: Log = serde_json::from_value(valid).unwrap();
            wrong_pool.topics[1] = hash(999);
            assert!(market.swap_volume(&wrong_pool).is_err());
        }
    }
}

#[test]
fn configuration_rejects_ambiguous_or_incompatible_markets() {
    let mut config = dex_config(
        market(protocols()[0].clone(), false),
        "https://example.com".into(),
    );
    config.validate().unwrap();
    config.markets.push(config.markets[0].clone());
    assert!(config.validate().is_err());
    config.markets.pop();
    config.markets[0].pool = protocols()[1].clone();
    assert!(config.validate().is_err());
    config.markets[0].pool = protocols()[0].clone();
    config.chain_id = 56;
    assert!(config.validate().is_err());
    config.chain_id = 1;
    config.markets[0].quote_token = config.markets[0].base_token;
    assert!(config.validate().is_err());
}

#[test]
fn manager_pool_ids_match_independent_solidity_abi_vectors() {
    // Generated with Foundry cast abi-encode + cast keccak, using upstream
    // PoolKey field order. V4 encodes (address,address,uint24,int24,address);
    // Infinity encodes (address,address,address,address,uint24,bytes32).
    let expected = [
        "0x8787d5970950be1209ff037d65ee13414c3cc2482b2b4d04d6a6e4363427ed39",
        "0x0e111086e36b0609319105be4c166ab746fa3570a6eac2fbddf166b413205eb9",
        "0x687ea3289b5a58c94770f0d1f91ab5d18ce13b242c32923473ddcf1f167a2e42",
    ];
    for (pool, expected) in protocols().into_iter().skip(4).zip(expected) {
        for reversed in [false, true] {
            let market = market(pool.clone(), reversed);
            assert_eq!(
                market.pool.pool_id(&market).unwrap(),
                Some(expected.parse::<B256>().unwrap())
            );
        }
    }
}

#[tokio::test]
async fn dex_ticker_flows_through_existing_feeder_as_coen_usd() {
    let server = Server::start(market(protocols()[0].clone(), false)).await;
    let mut pancake_market = market(protocols()[6].clone(), false);
    pancake_market.quote = "USDT".into();
    let pancake = Server::start(pancake_market).await;
    let mut config: FeederConfig = toml::from_str(
        r#"
        [chain]
        rpc_endpoint = "http://localhost:8545"
        chain_id = 676
        [account]
        private_key = "unused"
        validator_address = "1111111111111111111111111111111111111111"
        [oracle]
        [[currency_pairs]]
        base = "COEN"
        quote = "840"
        [[currency_pairs.sources]]
        provider = "uniswap"
        base = "COEN"
        quote = "USDC"
    "#,
    )
    .unwrap();
    config.dex_providers.push(dex_config(
        server.fixture.market.clone(),
        server.endpoint.clone(),
    ));
    config.dex_providers.push(dex_config(
        pancake.fixture.market.clone(),
        pancake.endpoint.clone(),
    ));
    config.currency_pairs[0]
        .sources
        .push(crate::config::CurrencyPairSource {
            provider: "pancakeswap".into(),
            base: "COEN".into(),
            quote: "USDT".into(),
        });
    config.validate().unwrap();
    let providers = crate::provider::create_providers(&config).unwrap();
    let pairs = [
        ("COEN".into(), "USDC".into()),
        ("COEN".into(), "USDT".into()),
    ];
    assert!(providers[0]
        .get_candle_prices(&pairs)
        .await
        .unwrap()
        .is_empty());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut ready = true;
            for provider in &providers {
                ready &= !provider.get_ticker_prices(&pairs).await.unwrap().is_empty();
            }
            let results = crate::aggregator::fetch_and_aggregate(&providers, &config)
                .await
                .unwrap();
            if ready {
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].base, Address::ZERO);
                assert_eq!(results[0].price, U256::from(2_500_000u64));
                assert_eq!(results[0].volume, U256::from(600_000_000u64));
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    // An unavailable venue contributes no invented price/volume, while the
    // other DEX source continues through the same existing aggregator.
    pancake.fixture.fail_logs.store(true, Ordering::Relaxed);
    pancake.fixture.head.store(5, Ordering::Relaxed);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let p = providers
                .iter()
                .find(|p| p.name() == "pancakeswap")
                .unwrap();
            if p.get_ticker_prices(&pairs).await.unwrap().is_empty() {
                let result = crate::aggregator::fetch_and_aggregate(&providers, &config)
                    .await
                    .unwrap();
                assert_eq!(result.len(), 1);
                assert_eq!(result[0].price, U256::from(4_000_000u64));
                assert_eq!(result[0].volume, U256::from(300_000_000u64));
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(providers);

    // No fictitious zero-volume observation while startup history is missing.
    server.fixture.fail_logs.store(true, Ordering::Relaxed);
    let provider = DexProvider::new(&config.dex_providers[0]).unwrap();
    assert!(provider.get_ticker_prices(&pairs).await.unwrap().is_empty());
}
