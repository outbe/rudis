//! Exchange WebSocket transport shared by the streaming price providers.
//!
//! The transport owns connection, subscription, heartbeat, reconnect and
//! in-memory market-data caching. Exchange-specific code is deliberately kept
//! to deterministic symbol mapping, subscription JSON and message decoding.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{U256, U512};
use async_trait::async_trait;
use eyre::{eyre, Result, WrapErr};
use flate2::read::GzDecoder;
use futures::{SinkExt as _, StreamExt as _};
use prost::Message as ProstMessage;
use serde_json::{json, Value};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::{checked_candle, checked_ticker, CandlePrice, Provider, TickerPrice, VolumeInput};
use crate::config::ProviderEndpointConfig;
use crate::fixed::FixedValue;
use outbe_primitives::stablecoin::iso_4217_alpha;
use outbe_primitives::units::SCALE_1E18;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
const STALE_CONNECTION_AFTER: Duration = Duration::from_secs(60);
const STABLE_SESSION_AFTER: Duration = Duration::from_secs(60);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const MAX_CANDLES_PER_PAIR: usize = 60;
const MAX_DECOMPRESSED_MESSAGE_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExchangeKind {
    Binance,
    Kraken,
    Okx,
    Gate,
    Huobi,
    Mexc,
    Coinbase,
}

impl ExchangeKind {
    pub(crate) fn for_name(name: &str) -> Option<Self> {
        match name {
            "binance" => Some(Self::Binance),
            "kraken" => Some(Self::Kraken),
            "okx" => Some(Self::Okx),
            "gate" => Some(Self::Gate),
            "huobi" => Some(Self::Huobi),
            "mexc" => Some(Self::Mexc),
            "coinbase" => Some(Self::Coinbase),
            _ => None,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Binance => "binance",
            Self::Kraken => "kraken",
            Self::Okx => "okx",
            Self::Gate => "gate",
            Self::Huobi => "huobi",
            Self::Mexc => "mexc",
            Self::Coinbase => "coinbase",
        }
    }

    const fn default_url(self) -> &'static str {
        match self {
            Self::Binance => "wss://stream.binance.com:9443/ws",
            Self::Kraken => "wss://ws.kraken.com",
            Self::Okx => "wss://ws.okx.com:8443/ws/v5/public",
            Self::Gate => "wss://api.gateio.ws/ws/v4/",
            Self::Huobi => "wss://api-aws.huobi.pro/ws",
            Self::Mexc => "wss://wbs-api.mexc.com/ws",
            Self::Coinbase => "wss://ws-feed.exchange.coinbase.com",
        }
    }

    const fn default_path(self) -> &'static str {
        match self {
            Self::Binance => "/ws",
            Self::Kraken | Self::Coinbase => "",
            Self::Okx => "/ws/v5/public",
            Self::Gate => "/ws/v4/",
            Self::Huobi => "/ws",
            Self::Mexc => "/ws",
        }
    }

    fn websocket_url(self, endpoint: Option<&ProviderEndpointConfig>) -> String {
        let configured = endpoint
            .map(|value| value.websocket.trim())
            .unwrap_or_default();
        if configured.is_empty() {
            return self.default_url().to_owned();
        }
        if configured.starts_with("ws://") || configured.starts_with("wss://") {
            return configured.to_owned();
        }
        format!("wss://{configured}{}", self.default_path())
    }

    fn pair_route(self, base: &str, quote: &str) -> Option<PairRoute> {
        if base.starts_with("0x") || quote.starts_with("0x") {
            return None;
        }
        let (market_base, market_quote, inverted) =
            if is_iso_symbol(base) && (!is_iso_symbol(quote) || base == "840") {
                (quote, base, true)
            } else {
                (base, quote, false)
            };
        let provider_asset = |asset: &str| -> Option<String> {
            if asset == "840" {
                return Some(match self {
                    Self::Kraken | Self::Coinbase => "USD".to_owned(),
                    _ => "USDT".to_owned(),
                });
            }
            if let Ok(code) = asset.parse::<u16>() {
                return String::from_utf8(iso_4217_alpha(code)?.to_vec()).ok();
            }
            if self == Self::Kraken && asset.eq_ignore_ascii_case("BTC") {
                Some("XBT".to_owned())
            } else {
                Some(asset.to_owned())
            }
        };
        let provider_base = provider_asset(market_base)?;
        let provider_quote = provider_asset(market_quote)?;
        let provider_symbol = match self {
            Self::Kraken => format!("{provider_base}/{provider_quote}"),
            Self::Okx | Self::Coinbase => format!("{provider_base}-{provider_quote}"),
            Self::Gate => format!("{provider_base}_{provider_quote}"),
            Self::Huobi => format!("{provider_base}{provider_quote}").to_ascii_lowercase(),
            Self::Binance | Self::Mexc => {
                format!("{provider_base}{provider_quote}").to_ascii_uppercase()
            }
        };
        Some(PairRoute {
            key: format!("{base}/{quote}"),
            fallback_key: format!("{provider_base}/{provider_quote}"),
            fallback_pair: (provider_base, provider_quote),
            provider_symbol,
            inverted,
        })
    }

    pub(crate) fn supports_any(self, pairs: &[(String, String)]) -> bool {
        pairs
            .iter()
            .any(|(base, quote)| self.pair_route(base, quote).is_some())
    }
}

fn is_iso_symbol(value: &str) -> bool {
    value
        .parse::<u16>()
        .is_ok_and(|code| (1..=999).contains(&code))
}

#[derive(Clone, Debug)]
struct PairRoute {
    key: String,
    fallback_key: String,
    fallback_pair: (String, String),
    provider_symbol: String,
    inverted: bool,
}

impl PairRoute {
    fn matches(&self, symbol: &str) -> bool {
        normalize_symbol(&self.provider_symbol) == normalize_symbol(symbol)
    }

    fn ticker(&self, value: &TickerPrice) -> Option<TickerPrice> {
        let (price, volume) = self.values(value.price, value.volume)?;
        Some(TickerPrice { price, volume })
    }

    fn candles(&self, values: &[CandlePrice]) -> Option<Vec<CandlePrice>> {
        values
            .iter()
            .map(|value| {
                let (price, volume) = self.values(value.price, value.volume)?;
                Some(CandlePrice {
                    price,
                    volume,
                    timestamp: value.timestamp,
                })
            })
            .collect()
    }

    fn values(&self, price: FixedValue, volume: FixedValue) -> Option<(FixedValue, FixedValue)> {
        if !self.inverted {
            return Some((price, volume));
        }
        if price.is_zero() {
            return None;
        }
        let scale = U512::from(SCALE_1E18);
        let inverse = scale
            .checked_mul(scale)?
            .checked_div(U512::from(price.raw()))?;
        let converted_volume = U512::from(volume.raw())
            .checked_mul(U512::from(price.raw()))?
            .checked_div(scale)?;
        if inverse > U512::from(U256::MAX) || converted_volume > U512::from(U256::MAX) {
            return None;
        }
        Some((
            FixedValue::from_raw(inverse.wrapping_to::<U256>()),
            FixedValue::from_raw(converted_volume.wrapping_to::<U256>()),
        ))
    }
}

#[derive(Debug, Default)]
struct MarketCache {
    tickers: HashMap<String, TickerPrice>,
    ticker_updated: HashMap<String, Instant>,
    candles: HashMap<String, Vec<CandlePrice>>,
    candle_updated: HashMap<String, Instant>,
}

type SharedCache = Arc<RwLock<MarketCache>>;

/// A provider facade backed by live WebSocket data with its REST adapter used
/// only until a requested market has appeared in the stream.
pub(crate) struct StreamingProvider {
    kind: ExchangeKind,
    fallback: Box<dyn Provider>,
    cache: SharedCache,
    routes: Vec<PairRoute>,
    allowed_keys: HashSet<String>,
    actors: Vec<JoinHandle<()>>,
}

impl StreamingProvider {
    pub(crate) fn new(
        kind: ExchangeKind,
        endpoint: Option<&ProviderEndpointConfig>,
        pairs: &[(String, String)],
        fallback: Box<dyn Provider>,
    ) -> Option<Self> {
        let routes = pairs
            .iter()
            .filter_map(|(base, quote)| kind.pair_route(base, quote))
            .collect::<Vec<_>>();
        if routes.is_empty() {
            return None;
        }

        let url = kind.websocket_url(endpoint);
        let provider_routes = routes.clone();
        let allowed_keys = routes.iter().map(|route| route.key.clone()).collect();
        let cache = Arc::new(RwLock::new(MarketCache::default()));
        // MEXC permits at most 30 subscriptions on one connection. Each route
        // consumes a mini-ticker and a candle subscription.
        let route_groups = if kind == ExchangeKind::Mexc {
            routes.chunks(15).map(<[_]>::to_vec).collect::<Vec<_>>()
        } else {
            vec![routes]
        };
        let actors = route_groups
            .into_iter()
            .map(|routes| {
                let actor_cache = Arc::clone(&cache);
                let url = url.clone();
                tokio::spawn(async move {
                    run_connection_loop(kind, url, routes, actor_cache).await;
                })
            })
            .collect();
        Some(Self {
            kind,
            fallback,
            cache,
            routes: provider_routes,
            allowed_keys,
            actors,
        })
    }

    fn cached_tickers(&self, pairs: &[(String, String)]) -> HashMap<String, TickerPrice> {
        let cache = self.cache.read().unwrap_or_else(|error| error.into_inner());
        pairs
            .iter()
            .filter(|(base, quote)| self.allowed_keys.contains(&format!("{base}/{quote}")))
            .filter_map(|(base, quote)| {
                let key = format!("{base}/{quote}");
                cache
                    .ticker_updated
                    .get(&key)
                    .is_some_and(|updated| updated.elapsed() < STALE_CONNECTION_AFTER)
                    .then(|| cache.tickers.get(&key).cloned())
                    .flatten()
                    .map(|value| (key, value))
            })
            .collect()
    }

    fn cached_candles(&self, pairs: &[(String, String)]) -> HashMap<String, Vec<CandlePrice>> {
        let cache = self.cache.read().unwrap_or_else(|error| error.into_inner());
        pairs
            .iter()
            .filter(|(base, quote)| self.allowed_keys.contains(&format!("{base}/{quote}")))
            .filter_map(|(base, quote)| {
                let key = format!("{base}/{quote}");
                cache
                    .candle_updated
                    .get(&key)
                    .is_some_and(|updated| updated.elapsed() < STALE_CONNECTION_AFTER)
                    .then(|| cache.candles.get(&key).cloned())
                    .flatten()
                    .map(|value| (key, value))
            })
            .collect()
    }
}

impl Drop for StreamingProvider {
    fn drop(&mut self) {
        for actor in &self.actors {
            actor.abort();
        }
    }
}

#[async_trait]
impl Provider for StreamingProvider {
    fn name(&self) -> &str {
        self.kind.name()
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut values = self.cached_tickers(pairs);
        let missing = pairs
            .iter()
            .filter(|(base, quote)| {
                let key = format!("{base}/{quote}");
                self.allowed_keys.contains(&key) && !values.contains_key(&key)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let routes = missing
                .iter()
                .filter_map(|(base, quote)| {
                    let key = format!("{base}/{quote}");
                    self.routes.iter().find(|route| route.key == key)
                })
                .collect::<Vec<_>>();
            let fallback_pairs = routes
                .iter()
                .map(|route| route.fallback_pair.clone())
                .collect::<Vec<_>>();
            let fallback = self.fallback.get_ticker_prices(&fallback_pairs).await?;
            for route in routes {
                if let Some(value) = fallback
                    .get(&route.fallback_key)
                    .and_then(|value| route.ticker(value))
                {
                    values.insert(route.key.clone(), value);
                }
            }
        }
        Ok(values)
    }

    async fn get_candle_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, Vec<CandlePrice>>> {
        let mut values = self.cached_candles(pairs);
        let missing = pairs
            .iter()
            .filter(|(base, quote)| {
                let key = format!("{base}/{quote}");
                self.allowed_keys.contains(&key) && !values.contains_key(&key)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let routes = missing
                .iter()
                .filter_map(|(base, quote)| {
                    let key = format!("{base}/{quote}");
                    self.routes.iter().find(|route| route.key == key)
                })
                .collect::<Vec<_>>();
            let fallback_pairs = routes
                .iter()
                .map(|route| route.fallback_pair.clone())
                .collect::<Vec<_>>();
            let fallback = self.fallback.get_candle_prices(&fallback_pairs).await?;
            for route in routes {
                if let Some(value) = fallback
                    .get(&route.fallback_key)
                    .and_then(|value| route.candles(value))
                {
                    values.insert(route.key.clone(), value);
                }
            }
        }
        Ok(values)
    }
}

async fn run_connection_loop(
    kind: ExchangeKind,
    url: String,
    routes: Vec<PairRoute>,
    cache: SharedCache,
) {
    let mut reconnect_delay = Duration::from_secs(1);
    loop {
        let mut received_market_data = false;
        let mut connected_for = Duration::ZERO;
        match connect_async(&url).await {
            Ok((socket, _)) => {
                tracing::info!(provider = kind.name(), url, "exchange websocket connected");
                let connected_at = Instant::now();
                if let Err(error) = drive_connection(kind, socket, &routes, &cache).await {
                    connected_for = connected_at.elapsed();
                    tracing::warn!(provider = kind.name(), %error, "exchange websocket disconnected");
                    received_market_data = routes_have_cached_data(&cache, &routes);
                    clear_routes(&cache, &routes);
                }
            }
            Err(error) => {
                tracing::warn!(provider = kind.name(), url, %error, "exchange websocket connection failed");
            }
        }
        reconnect_delay =
            reconnect_delay_after_session(reconnect_delay, received_market_data, connected_for);
        sleep(reconnect_delay).await;
        reconnect_delay = reconnect_delay
            .checked_mul(2)
            .unwrap_or(MAX_RECONNECT_DELAY)
            .min(MAX_RECONNECT_DELAY);
    }
}

fn routes_have_cached_data(cache: &SharedCache, routes: &[PairRoute]) -> bool {
    cache.read().is_ok_and(|cache| {
        routes.iter().any(|route| {
            cache.ticker_updated.contains_key(&route.key)
                || cache.candle_updated.contains_key(&route.key)
        })
    })
}

fn reconnect_delay_after_session(
    current: Duration,
    received_market_data: bool,
    connected_for: Duration,
) -> Duration {
    if received_market_data || connected_for >= STABLE_SESSION_AFTER {
        Duration::from_secs(1)
    } else {
        current
    }
}

async fn drive_connection<S>(
    kind: ExchangeKind,
    socket: tokio_tungstenite::WebSocketStream<S>,
    routes: &[PairRoute],
    cache: &SharedCache,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = socket.split();
    for subscription in subscription_messages(kind, routes)? {
        sink.send(Message::Text(subscription.into())).await?;
    }

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut last_seen = Instant::now();

    loop {
        tokio::select! {
            incoming = stream.next() => {
                let message = incoming.ok_or_else(|| eyre!("websocket stream ended"))??;
                last_seen = Instant::now();
                match message {
                    Message::Text(text) => {
                        if text.as_str() == "pong" {
                            continue;
                        }
                        match process_payload(kind, text.as_bytes(), routes, cache) {
                            Ok(Some(reply)) => sink.send(Message::Text(reply.into())).await?,
                            Ok(None) => {}
                            Err(error) => tracing::warn!(provider = kind.name(), %error, "ignored malformed websocket payload"),
                        }
                    }
                    Message::Binary(bytes) => {
                        let payload = if kind == ExchangeKind::Huobi {
                            decompress_gzip(&bytes).unwrap_or_else(|_| bytes.to_vec())
                        } else {
                            bytes.to_vec()
                        };
                        match process_payload(kind, &payload, routes, cache) {
                            Ok(Some(reply)) => sink.send(Message::Text(reply.into())).await?,
                            Ok(None) => {}
                            Err(error) => tracing::warn!(provider = kind.name(), %error, "ignored malformed websocket payload"),
                        }
                    }
                    Message::Ping(payload) => sink.send(Message::Pong(payload)).await?,
                    Message::Pong(_) => {}
                    Message::Close(frame) => return Err(eyre!("remote closed websocket: {frame:?}")),
                    Message::Frame(_) => {}
                }
            }
            _ = heartbeat.tick() => {
                if last_seen.elapsed() >= STALE_CONNECTION_AFTER {
                    return Err(eyre!("websocket received no data or pong for {STALE_CONNECTION_AFTER:?}"));
                }
                if kind == ExchangeKind::Okx {
                    sink.send(Message::Text("ping".into())).await?;
                } else if kind == ExchangeKind::Mexc {
                    sink.send(Message::Text(r#"{"method":"PING"}"#.into())).await?;
                } else {
                    sink.send(Message::Ping(Vec::new().into())).await?;
                }
            }
        }
    }
}

fn subscription_messages(kind: ExchangeKind, routes: &[PairRoute]) -> Result<Vec<String>> {
    let symbols = routes
        .iter()
        .map(|route| route.provider_symbol.clone())
        .collect::<Vec<_>>();
    let messages = match kind {
        ExchangeKind::Binance => vec![json!({
            "method": "SUBSCRIBE",
            "params": symbols.iter().flat_map(|symbol| {
                let symbol = symbol.to_ascii_lowercase();
                [format!("{symbol}@ticker"), format!("{symbol}@kline_1m")]
            }).collect::<Vec<_>>(),
            "id": 1
        })],
        ExchangeKind::Kraken => vec![
            json!({"event": "subscribe", "pair": symbols, "subscription": {"name": "ticker"}}),
            json!({"event": "subscribe", "pair": symbols, "subscription": {"name": "ohlc"}}),
        ],
        ExchangeKind::Okx => vec![json!({
            "op": "subscribe",
            "args": symbols.iter().flat_map(|symbol| [
                json!({"channel": "tickers", "instId": symbol}),
                json!({"channel": "candle1m", "instId": symbol}),
            ]).collect::<Vec<_>>()
        })],
        ExchangeKind::Gate => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now = i64::try_from(now).unwrap_or(i64::MAX);
            let mut values = vec![json!({
                "time": now,
                "channel": "spot.tickers",
                "event": "subscribe",
                "payload": symbols,
                "id": 1
            })];
            values.extend(symbols.iter().map(|symbol| {
                json!({
                    "time": now,
                    "channel": "spot.candlesticks",
                    "event": "subscribe",
                    "payload": ["1m", symbol],
                    "id": 2
                })
            }));
            values
        }
        ExchangeKind::Huobi => symbols
            .iter()
            .flat_map(|symbol| {
                [
                    json!({"sub": format!("market.{symbol}.ticker")}),
                    json!({"sub": format!("market.{symbol}.kline.1min")}),
                ]
            })
            .collect(),
        ExchangeKind::Mexc => {
            vec![json!({
                "method": "SUBSCRIPTION",
                "params": symbols.iter().flat_map(|symbol| [
                    format!("spot@public.miniTicker.v3.api.pb@{symbol}@UTC+8"),
                    format!("spot@public.kline.v3.api.pb@{symbol}@Min1"),
                ]).collect::<Vec<_>>()
            })]
        }
        ExchangeKind::Coinbase => vec![json!({
            "type": "subscribe",
            "product_ids": symbols,
            "channels": ["ticker"]
        })],
    };
    messages
        .into_iter()
        .map(|message| serde_json::to_string(&message).map_err(Into::into))
        .collect()
}

fn process_payload(
    kind: ExchangeKind,
    payload: &[u8],
    routes: &[PairRoute],
    cache: &SharedCache,
) -> Result<Option<String>> {
    if kind == ExchangeKind::Mexc {
        // Subscription acknowledgements and PONG responses are JSON, while
        // market data is binary Protocol Buffers.
        if payload
            .first()
            .is_some_and(|byte| matches!(byte, b'{' | b'['))
        {
            let _: Value =
                serde_json::from_slice(payload).wrap_err("decode MEXC websocket control JSON")?;
            return Ok(None);
        }
        return parse_mexc(payload, routes, cache);
    }
    let value: Value =
        serde_json::from_slice(payload).wrap_err("decode exchange websocket JSON")?;
    match kind {
        ExchangeKind::Binance => parse_binance(&value, routes, cache),
        ExchangeKind::Kraken => parse_kraken(&value, routes, cache),
        ExchangeKind::Okx => parse_okx(&value, routes, cache),
        ExchangeKind::Gate => parse_gate(&value, routes, cache),
        ExchangeKind::Huobi => parse_huobi(&value, routes, cache),
        ExchangeKind::Mexc => unreachable!("MEXC payload handled before JSON decoding"),
        ExchangeKind::Coinbase => parse_coinbase(&value, routes, cache),
    }
}

fn parse_binance(
    value: &Value,
    routes: &[PairRoute],
    cache: &SharedCache,
) -> Result<Option<String>> {
    if let Some(kline) = value.get("k").and_then(Value::as_object) {
        let symbol = string_field(value, "s").or_else(|| string_map_field(kline, "s"));
        if let Some(route) = symbol.and_then(|symbol| find_route(routes, symbol)) {
            insert_candle(
                cache,
                route,
                decimal_map_field(kline, "c")?,
                decimal_map_field(kline, "v")?,
                integer_map_field(kline, "T")
                    .or_else(|| integer_map_field(kline, "t"))
                    .unwrap_or(0),
            );
        }
        return Ok(None);
    }
    if let Some(route) = string_field(value, "s").and_then(|symbol| find_route(routes, symbol)) {
        insert_ticker(
            cache,
            route,
            decimal_field(value, "c").or_else(|_| decimal_field(value, "lastPrice"))?,
            decimal_field(value, "v").or_else(|_| decimal_field(value, "volume"))?,
        );
    }
    Ok(None)
}

fn parse_kraken(
    value: &Value,
    routes: &[PairRoute],
    cache: &SharedCache,
) -> Result<Option<String>> {
    let Some(message) = value.as_array() else {
        return Ok(None);
    };
    if message.len() != 4 {
        return Ok(None);
    }
    let Some(channel) = message[2].as_str() else {
        return Ok(None);
    };
    let Some(symbol) = message[3].as_str() else {
        return Ok(None);
    };
    let Some(route) = find_route(routes, symbol) else {
        return Ok(None);
    };
    if channel == "ticker" {
        let body = &message[1];
        let price = body["c"]
            .as_array()
            .and_then(|values| values.first())
            .ok_or_else(|| eyre!("kraken ticker has no close"))?;
        let volume = body["v"]
            .as_array()
            .and_then(|values| values.get(1))
            .ok_or_else(|| eyre!("kraken ticker has no 24h volume"))?;
        insert_ticker(cache, route, decimal_value(price)?, decimal_value(volume)?);
    } else if channel.starts_with("ohlc-") {
        let values = message[1]
            .as_array()
            .ok_or_else(|| eyre!("kraken candle is not an array"))?;
        insert_candle(
            cache,
            route,
            decimal_index(values, 5)?,
            decimal_index(values, 7)?,
            integer_index(values, 1).unwrap_or(0),
        );
    }
    Ok(None)
}

fn parse_okx(value: &Value, routes: &[PairRoute], cache: &SharedCache) -> Result<Option<String>> {
    let channel = string_field(&value["arg"], "channel");
    let symbol = string_field(&value["arg"], "instId");
    let Some(route) = symbol.and_then(|symbol| find_route(routes, symbol)) else {
        return Ok(None);
    };
    let Some(data) = value.get("data").and_then(Value::as_array) else {
        return Ok(None);
    };
    if channel == Some("tickers") {
        if let Some(ticker) = data.first() {
            insert_ticker(
                cache,
                route,
                decimal_field(ticker, "last")?,
                decimal_field(ticker, "vol24h")?,
            );
        }
    } else if channel.is_some_and(|channel| channel.starts_with("candle")) {
        if let Some(values) = data.first().and_then(Value::as_array) {
            insert_candle(
                cache,
                route,
                decimal_index(values, 4)?,
                decimal_index(values, 5)?,
                integer_index(values, 0).unwrap_or(0),
            );
        }
    }
    Ok(None)
}

fn parse_gate(value: &Value, routes: &[PairRoute], cache: &SharedCache) -> Result<Option<String>> {
    if string_field(value, "event") != Some("update") {
        return Ok(None);
    }
    let channel = string_field(value, "channel");
    let result = &value["result"];
    if channel == Some("spot.tickers") {
        let Some(route) =
            string_field(result, "currency_pair").and_then(|symbol| find_route(routes, symbol))
        else {
            return Ok(None);
        };
        insert_ticker(
            cache,
            route,
            decimal_field(result, "last")?,
            decimal_field(result, "base_volume")?,
        );
    } else if channel == Some("spot.candlesticks") {
        let Some(name) = string_field(result, "n") else {
            return Ok(None);
        };
        let symbol = name.split_once('_').map_or(name, |(_, pair)| pair);
        let Some(route) = find_route(routes, symbol) else {
            return Ok(None);
        };
        insert_candle(
            cache,
            route,
            decimal_field(result, "c")?,
            decimal_field(result, "v").or_else(|_| decimal_field(result, "a"))?,
            integer_field(result, "t").unwrap_or(0),
        );
    }
    Ok(None)
}

fn parse_huobi(value: &Value, routes: &[PairRoute], cache: &SharedCache) -> Result<Option<String>> {
    if let Some(ping) = value.get("ping").and_then(raw_integer_value) {
        return Ok(Some(json!({"pong": ping}).to_string()));
    }
    let Some(channel) = string_field(value, "ch") else {
        return Ok(None);
    };
    let Some(route) = routes.iter().find(|route| {
        normalize_symbol(channel).contains(&normalize_symbol(&route.provider_symbol))
    }) else {
        return Ok(None);
    };
    let tick = &value["tick"];
    if channel.contains(".kline.") {
        insert_candle(
            cache,
            route,
            decimal_field(tick, "close")?,
            decimal_field(tick, "vol")?,
            integer_field(tick, "id").unwrap_or(0),
        );
    } else if channel.ends_with(".ticker") {
        insert_ticker(
            cache,
            route,
            decimal_field(tick, "lastPrice").or_else(|_| decimal_field(tick, "close"))?,
            decimal_field(tick, "vol")?,
        );
    }
    Ok(None)
}

fn parse_mexc(payload: &[u8], routes: &[PairRoute], cache: &SharedCache) -> Result<Option<String>> {
    let message = MexcPushData::decode(payload).wrap_err("decode MEXC websocket protobuf")?;
    let Some(symbol) = message.symbol.as_deref() else {
        return Ok(None);
    };
    let Some(route) = find_route(routes, symbol) else {
        return Ok(None);
    };
    match message.body {
        Some(mexc_push_data::Body::MiniTicker(ticker)) => insert_ticker(
            cache,
            route,
            FixedValue::parse(&ticker.price)
                .ok_or_else(|| eyre!("invalid MEXC mini-ticker price"))?,
            FixedValue::parse(&ticker.quantity)
                .ok_or_else(|| eyre!("invalid MEXC mini-ticker quantity"))?,
        ),
        Some(mexc_push_data::Body::SpotKline(candle)) => insert_candle(
            cache,
            route,
            FixedValue::parse(&candle.closing_price)
                .ok_or_else(|| eyre!("invalid MEXC candle close"))?,
            FixedValue::parse(&candle.volume).ok_or_else(|| eyre!("invalid MEXC candle volume"))?,
            u64::try_from(candle.window_start).unwrap_or(0),
        ),
        None => {}
    }
    Ok(None)
}

#[derive(Clone, PartialEq, prost::Message)]
struct MexcPushData {
    #[prost(string, tag = "1")]
    channel: String,
    #[prost(oneof = "mexc_push_data::Body", tags = "308, 309")]
    body: Option<mexc_push_data::Body>,
    #[prost(string, optional, tag = "3")]
    symbol: Option<String>,
    #[prost(string, optional, tag = "4")]
    symbol_id: Option<String>,
    #[prost(int64, optional, tag = "5")]
    create_time: Option<i64>,
    #[prost(int64, optional, tag = "6")]
    send_time: Option<i64>,
}

mod mexc_push_data {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Body {
        #[prost(message, tag = "308")]
        SpotKline(super::MexcSpotKline),
        #[prost(message, tag = "309")]
        MiniTicker(super::MexcMiniTicker),
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct MexcMiniTicker {
    #[prost(string, tag = "1")]
    symbol: String,
    #[prost(string, tag = "2")]
    price: String,
    #[prost(string, tag = "3")]
    rate: String,
    #[prost(string, tag = "4")]
    zoned_rate: String,
    #[prost(string, tag = "5")]
    high: String,
    #[prost(string, tag = "6")]
    low: String,
    #[prost(string, tag = "7")]
    volume: String,
    #[prost(string, tag = "8")]
    quantity: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct MexcSpotKline {
    #[prost(string, tag = "1")]
    interval: String,
    #[prost(int64, tag = "2")]
    window_start: i64,
    #[prost(string, tag = "3")]
    opening_price: String,
    #[prost(string, tag = "4")]
    closing_price: String,
    #[prost(string, tag = "5")]
    highest_price: String,
    #[prost(string, tag = "6")]
    lowest_price: String,
    #[prost(string, tag = "7")]
    volume: String,
    #[prost(string, tag = "8")]
    amount: String,
    #[prost(int64, tag = "9")]
    window_end: i64,
}

fn parse_coinbase(
    value: &Value,
    routes: &[PairRoute],
    cache: &SharedCache,
) -> Result<Option<String>> {
    let Some(message_type) = string_field(value, "type") else {
        return Ok(None);
    };
    let Some(route) =
        string_field(value, "product_id").and_then(|symbol| find_route(routes, symbol))
    else {
        return Ok(None);
    };
    if message_type == "ticker" {
        insert_ticker(
            cache,
            route,
            decimal_field(value, "price")?,
            decimal_field(value, "volume_24h")?,
        );
    }
    Ok(None)
}

fn insert_ticker(cache: &SharedCache, route: &PairRoute, price: FixedValue, volume: FixedValue) {
    let Some((price, volume)) = route.values(price, volume) else {
        return;
    };
    let Some(ticker) = checked_ticker(
        "websocket",
        &route.key,
        Some(price),
        VolumeInput::Present(Some(volume)),
    ) else {
        return;
    };
    let mut cache = cache.write().unwrap_or_else(|error| error.into_inner());
    cache.tickers.insert(route.key.clone(), ticker);
    cache
        .ticker_updated
        .insert(route.key.clone(), Instant::now());
}

fn clear_routes(cache: &SharedCache, routes: &[PairRoute]) {
    let mut cache = cache.write().unwrap_or_else(|error| error.into_inner());
    for route in routes {
        cache.tickers.remove(&route.key);
        cache.ticker_updated.remove(&route.key);
        cache.candles.remove(&route.key);
        cache.candle_updated.remove(&route.key);
    }
}

fn insert_candle(
    cache: &SharedCache,
    route: &PairRoute,
    price: FixedValue,
    volume: FixedValue,
    timestamp: u64,
) {
    let Some((price, volume)) = route.values(price, volume) else {
        return;
    };
    let Some(candle) = checked_candle(
        "websocket",
        &route.key,
        Some(price),
        VolumeInput::Present(Some(volume)),
        timestamp,
    ) else {
        return;
    };
    let mut cache = cache.write().unwrap_or_else(|error| error.into_inner());
    let candles = cache.candles.entry(route.key.clone()).or_default();
    if let Some(existing) = candles
        .iter_mut()
        .find(|candle| candle.timestamp == timestamp)
    {
        *existing = candle;
    } else {
        candles.push(candle);
    }
    candles.sort_unstable_by_key(|candle| candle.timestamp);
    if candles.len() > MAX_CANDLES_PER_PAIR {
        candles.drain(..candles.len() - MAX_CANDLES_PER_PAIR);
    }
    cache
        .candle_updated
        .insert(route.key.clone(), Instant::now());
}

fn find_route<'a>(routes: &'a [PairRoute], symbol: &str) -> Option<&'a PairRoute> {
    routes.iter().find(|route| route.matches(symbol))
}

fn normalize_symbol(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect::<String>()
        .replace("XBT", "BTC")
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn string_map_field<'a>(value: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn decimal_field(value: &Value, key: &str) -> Result<FixedValue> {
    decimal_value(
        value
            .get(key)
            .ok_or_else(|| eyre!("missing decimal field `{key}`"))?,
    )
}

fn decimal_map_field(value: &serde_json::Map<String, Value>, key: &str) -> Result<FixedValue> {
    decimal_value(
        value
            .get(key)
            .ok_or_else(|| eyre!("missing decimal field `{key}`"))?,
    )
}

fn decimal_index(values: &[Value], index: usize) -> Result<FixedValue> {
    decimal_value(
        values
            .get(index)
            .ok_or_else(|| eyre!("missing decimal index {index}"))?,
    )
}

fn decimal_value(value: &Value) -> Result<FixedValue> {
    let lexeme = value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string());
    FixedValue::parse(&lexeme).ok_or_else(|| eyre!("invalid fixed-point decimal `{lexeme}`"))
}

fn integer_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(integer_value)
}

fn integer_map_field(value: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    value.get(key).and_then(integer_value)
}

fn integer_index(values: &[Value], index: usize) -> Option<u64> {
    values.get(index).and_then(integer_value)
}

fn integer_value(value: &Value) -> Option<u64> {
    raw_integer_value(value).map(normalize_timestamp)
}

fn raw_integer_value(value: &Value) -> Option<u64> {
    if let Some(value) = value.as_u64() {
        return Some(value);
    }
    let value = value.as_str()?;
    let whole = value.split_once('.').map_or(value, |(whole, _)| whole);
    whole.parse().ok()
}

fn normalize_timestamp(timestamp: u64) -> u64 {
    if timestamp >= 10_000_000_000 {
        timestamp / 1_000
    } else {
        timestamp
    }
}

fn decompress_gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes).take((MAX_DECOMPRESSED_MESSAGE_BYTES + 1) as u64);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    if output.len() > MAX_DECOMPRESSED_MESSAGE_BYTES {
        return Err(eyre!("decompressed websocket message exceeds size limit"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    struct EmptyFallback;

    #[async_trait]
    impl Provider for EmptyFallback {
        fn name(&self) -> &str {
            "binance"
        }

        async fn get_ticker_prices(
            &self,
            _pairs: &[(String, String)],
        ) -> Result<HashMap<String, TickerPrice>> {
            Ok(HashMap::new())
        }
    }

    fn route() -> Vec<PairRoute> {
        vec![PairRoute {
            key: "ETH/840".to_owned(),
            fallback_key: "ETH/USDT".to_owned(),
            fallback_pair: ("ETH".to_owned(), "USDT".to_owned()),
            provider_symbol: "ETHUSDT".to_owned(),
            inverted: false,
        }]
    }

    #[test]
    fn every_exchange_builds_valid_market_subscriptions() {
        for kind in [
            ExchangeKind::Binance,
            ExchangeKind::Kraken,
            ExchangeKind::Okx,
            ExchangeKind::Gate,
            ExchangeKind::Huobi,
            ExchangeKind::Mexc,
            ExchangeKind::Coinbase,
        ] {
            let messages = subscription_messages(kind, &route()).unwrap();
            assert!(!messages.is_empty());
            assert!(messages
                .iter()
                .all(|message| serde_json::from_str::<Value>(message).is_ok()));
        }

        let mexc = subscription_messages(ExchangeKind::Mexc, &route()).unwrap();
        assert!(mexc[0].contains("spot@public.miniTicker.v3.api.pb@ETHUSDT@UTC+8"));
        assert!(mexc[0].contains("spot@public.kline.v3.api.pb@ETHUSDT@Min1"));
    }

    #[test]
    fn reverse_iso_market_uses_exchange_orientation_and_fixed_point_inverse() {
        let route = ExchangeKind::Binance
            .pair_route("840", "BTC")
            .expect("USD/BTC can use the BTC/USDT exchange market");
        assert_eq!(route.provider_symbol, "BTCUSDT");
        assert_eq!(route.fallback_pair, ("BTC".to_owned(), "USDT".to_owned()));
        assert!(route.inverted);

        let cache = Arc::new(RwLock::new(MarketCache::default()));
        insert_ticker(
            &cache,
            &route,
            FixedValue::parse("2").unwrap(),
            FixedValue::parse("3").unwrap(),
        );
        let cache = cache.read().unwrap();
        assert_eq!(
            cache.tickers["840/BTC"].price,
            FixedValue::parse("0.5").unwrap()
        );
        assert_eq!(
            cache.tickers["840/BTC"].volume,
            FixedValue::parse("6").unwrap()
        );

        let eur = ExchangeKind::Coinbase
            .pair_route("978", "BTC")
            .expect("EUR/BTC can use the BTC/EUR exchange market");
        assert_eq!(eur.provider_symbol, "BTC-EUR");

        let eur_usd = ExchangeKind::Binance
            .pair_route("978", "840")
            .expect("EUR/USD maps both ISO codes to exchange symbols");
        assert_eq!(eur_usd.provider_symbol, "EURUSDT");
        assert!(!eur_usd.inverted);
        let usd_eur = ExchangeKind::Binance
            .pair_route("840", "978")
            .expect("USD/EUR uses the liquid EUR/USD direction and inverts it");
        assert_eq!(usd_eur.provider_symbol, "EURUSDT");
        assert!(usd_eur.inverted);
    }

    #[test]
    fn websocket_candle_preserves_literal_zero_volume() {
        let route = &route()[0];
        let cache = Arc::new(RwLock::new(MarketCache::default()));

        insert_candle(
            &cache,
            route,
            FixedValue::parse("100").unwrap(),
            FixedValue::ZERO,
            42,
        );

        let cache = cache.read().unwrap();
        assert_eq!(cache.candles["ETH/840"].len(), 1);
        assert!(cache.candles["ETH/840"][0].volume.is_zero());
    }

    #[test]
    fn coen_provider_symbols_are_valid_websocket_source_markets() {
        let binance = ExchangeKind::Binance
            .pair_route("COEN", "USDT")
            .expect("COEN/USDT is an explicit provider market");
        assert_eq!(binance.key, "COEN/USDT");
        assert_eq!(binance.provider_symbol, "COENUSDT");
        assert!(!binance.inverted);

        let coinbase = ExchangeKind::Coinbase
            .pair_route("COEN", "USDC")
            .expect("COEN/USDC is an explicit provider market");
        assert_eq!(coinbase.provider_symbol, "COEN-USDC");
    }

    #[test]
    fn exchange_decoders_populate_fixed_point_ticker_and_candle_cache() {
        let cases = [
            (
                ExchangeKind::Binance,
                br#"{"s":"ETHUSDT","c":"2500.125","v":"42.5"}"#.as_slice(),
                br#"{"s":"ETHUSDT","k":{"c":"2501.25","v":"3.5","T":1700000000000}}"#.as_slice(),
            ),
            (
                ExchangeKind::Kraken,
                br#"[1,{"c":["2500.125","1"],"v":["1","42.5"]},"ticker","ETH/USDT"]"#.as_slice(),
                br#"[1,["1699999940.0","1700000000.0","1","2","1","2501.25","2","3.5","1"],"ohlc-1","ETH/USDT"]"#.as_slice(),
            ),
            (
                ExchangeKind::Okx,
                br#"{"arg":{"channel":"tickers","instId":"ETHUSDT"},"data":[{"last":"2500.125","vol24h":"42.5"}]}"#.as_slice(),
                br#"{"arg":{"channel":"candle1m","instId":"ETHUSDT"},"data":[["1700000000000","1","2","1","2501.25","3.5"]]}"#.as_slice(),
            ),
            (
                ExchangeKind::Gate,
                br#"{"channel":"spot.tickers","event":"update","result":{"currency_pair":"ETHUSDT","last":"2500.125","base_volume":"42.5"}}"#.as_slice(),
                br#"{"channel":"spot.candlesticks","event":"update","result":{"n":"1m_ETHUSDT","t":"1700000000","c":"2501.25","v":"3.5","a":"8754.375"}}"#.as_slice(),
            ),
            (
                ExchangeKind::Huobi,
                br#"{"ch":"market.ethusdt.ticker","tick":{"lastPrice":"2500.125","vol":"42.5"}}"#.as_slice(),
                br#"{"ch":"market.ethusdt.kline.1min","tick":{"close":"2501.25","vol":"3.5","id":1700000000}}"#.as_slice(),
            ),
        ];

        for (kind, ticker, candle) in cases {
            let cache = Arc::new(RwLock::new(MarketCache::default()));
            process_payload(kind, ticker, &route(), &cache).unwrap();
            process_payload(kind, candle, &route(), &cache).unwrap();
            let cache = cache.read().unwrap();
            assert_eq!(
                cache.tickers["ETH/840"].price,
                FixedValue::parse("2500.125").unwrap(),
                "{kind:?} ticker"
            );
            assert_eq!(
                cache.candles["ETH/840"][0].price,
                FixedValue::parse("2501.25").unwrap(),
                "{kind:?} candle"
            );
        }
    }

    #[test]
    fn mexc_protobuf_decoder_populates_fixed_point_ticker_and_candle_cache() {
        let cache = Arc::new(RwLock::new(MarketCache::default()));
        // Golden wire bytes assembled from MEXC's published .proto tags, not
        // encoded by the Rust types under test. Wrapper body tags are 309 for
        // miniTicker and 308 for kline; wrapper symbol is tag 3.
        let ticker = b"\xaa\x13\x19\x0a\x07ETHUSDT\x12\x082500.125\x42\x0442.5\x1a\x07ETHUSDT";
        let candle = b"\xa2\x13\x14\x0a\x04Min1\x22\x072501.25\x3a\x033.5\x1a\x07ETHUSDT";

        process_payload(ExchangeKind::Mexc, ticker, &route(), &cache).unwrap();
        process_payload(ExchangeKind::Mexc, candle, &route(), &cache).unwrap();

        let cache = cache.read().unwrap();
        assert_eq!(
            cache.tickers["ETH/840"].price,
            FixedValue::parse("2500.125").unwrap()
        );
        assert_eq!(
            cache.candles["ETH/840"][0].price,
            FixedValue::parse("2501.25").unwrap()
        );
    }

    #[test]
    fn coinbase_ticker_decoder_does_not_invent_candles_from_trades() {
        let cache = Arc::new(RwLock::new(MarketCache::default()));
        process_payload(
            ExchangeKind::Coinbase,
            br#"{"type":"ticker","product_id":"ETHUSDT","price":"2500.125","volume_24h":"42.5"}"#,
            &route(),
            &cache,
        )
        .unwrap();
        process_payload(
            ExchangeKind::Coinbase,
            br#"{"type":"match","product_id":"ETHUSDT","price":"2501.25","size":"3.5"}"#,
            &route(),
            &cache,
        )
        .unwrap();

        let cache = cache.read().unwrap();
        assert_eq!(
            cache.tickers["ETH/840"].price,
            FixedValue::parse("2500.125").unwrap()
        );
        assert!(cache.candles.is_empty());
    }

    #[test]
    fn huobi_application_ping_returns_matching_pong() {
        let cache = Arc::new(RwLock::new(MarketCache::default()));
        let response = process_payload(
            ExchangeKind::Huobi,
            br#"{"ping":1492420473027}"#,
            &route(),
            &cache,
        )
        .unwrap();
        assert_eq!(response.as_deref(), Some(r#"{"pong":1492420473027}"#));
    }

    #[test]
    fn huobi_gzip_decoder_rejects_oversized_payloads() {
        use std::io::Write as _;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder
            .write_all(&vec![0; MAX_DECOMPRESSED_MESSAGE_BYTES + 1])
            .unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(decompress_gzip(&compressed).is_err());
    }

    #[test]
    fn reconnect_backoff_resets_only_after_data_or_a_stable_session() {
        let current = Duration::from_secs(8);

        assert_eq!(
            reconnect_delay_after_session(current, false, Duration::from_secs(1)),
            current,
            "a successful handshake followed by an immediate close must retain backoff"
        );
        assert_eq!(
            reconnect_delay_after_session(current, true, Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            reconnect_delay_after_session(current, false, STABLE_SESSION_AFTER),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn reconnects_resubscribes_answers_ping_and_replaces_cached_ticker() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let subscriptions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&subscriptions);
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut finish_rx = Some(finish_rx);
            for (connection, price) in ["2500.125", "2501.25"].into_iter().enumerate() {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = accept_async(stream).await.unwrap();
                let subscription = socket.next().await.unwrap().unwrap();
                assert!(subscription.is_text());
                observed.fetch_add(1, Ordering::SeqCst);
                socket
                    .send(Message::Text(
                        format!(r#"{{"s":"ETHUSDT","c":"{price}","v":"42.5"}}"#).into(),
                    ))
                    .await
                    .unwrap();
                socket.send(Message::Ping(vec![7].into())).await.unwrap();
                loop {
                    match socket.next().await.unwrap().unwrap() {
                        Message::Pong(payload) if payload.as_ref() == [7] => break,
                        _ => {}
                    }
                }
                if connection == 0 {
                    socket.close(None).await.unwrap();
                } else {
                    finish_rx.take().unwrap().await.unwrap();
                    socket.close(None).await.unwrap();
                }
            }
        });

        let endpoint = ProviderEndpointConfig {
            name: "binance".to_owned(),
            rest: String::new(),
            websocket: format!("ws://{address}"),
        };
        let pairs = vec![("ETH".to_owned(), "840".to_owned())];
        let provider = StreamingProvider::new(
            ExchangeKind::Binance,
            Some(&endpoint),
            &pairs,
            Box::new(EmptyFallback),
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let values = provider.cached_tickers(&pairs);
            if values
                .get("ETH/840")
                .is_some_and(|ticker| ticker.price == FixedValue::parse("2501.25").unwrap())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "second streamed ticker was not cached"
            );
            sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(subscriptions.load(Ordering::SeqCst), 2);
        finish_tx.send(()).unwrap();
        server.await.unwrap();
    }
}
