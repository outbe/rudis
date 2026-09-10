//! Price provider trait and implementations.

pub mod binance;
pub mod chainlink;
pub mod coinbase;
pub(crate) mod dex;
pub mod gate;
pub mod huobi;
pub mod kraken;
pub mod mexc;
pub mod mock;
pub mod mock_http;
pub mod okx;
pub mod pyth;
mod websocket;

use eyre::{eyre, Result};
use std::collections::HashMap;

use crate::config::{FeederConfig, ProviderEndpointConfig};
use crate::fixed::FixedValue;

/// Whether an upstream endpoint supplied a volume field.
///
/// `Present(None)` means the field existed but failed deterministic decimal
/// parsing. It must never be conflated with an endpoint that has no volume in
/// its contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeInput {
    Present(Option<FixedValue>),
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationError {
    InvalidPrice,
    ZeroPrice,
    InvalidVolume,
}

impl std::fmt::Display for ObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::InvalidPrice => "invalid price",
            Self::ZeroPrice => "zero price",
            Self::InvalidVolume => "invalid volume",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for ObservationError {}

/// A price data point from a provider.
///
/// Provider decimals are parsed directly from their decimal lexemes into FP18.
#[derive(Debug, Clone)]
pub struct TickerPrice {
    /// Current provider rate at FP18 (pool spot rate for DEX providers).
    pub price: FixedValue,
    /// 24-hour trading volume at FP18.
    pub volume: FixedValue,
}

impl TickerPrice {
    pub(crate) fn from_parsed(
        price: Option<FixedValue>,
        volume: VolumeInput,
    ) -> Result<Self, ObservationError> {
        let price = price.ok_or(ObservationError::InvalidPrice)?;
        if price.is_zero() {
            return Err(ObservationError::ZeroPrice);
        }
        let volume = match volume {
            VolumeInput::Present(volume) => volume.ok_or(ObservationError::InvalidVolume)?,
            VolumeInput::Unavailable => FixedValue::ZERO,
        };
        Ok(Self { price, volume })
    }
}

/// A single candle (OHLCV bar) from a provider.
///
/// Same deterministic FP18 representation as [`TickerPrice`].
#[derive(Debug, Clone)]
pub struct CandlePrice {
    /// Close price of the candle at FP18.
    pub price: FixedValue,
    /// Volume during the candle period at FP18.
    pub volume: FixedValue,
    /// Unix timestamp (seconds) of the candle open.
    /// Currently unused by the aggregator's TVWAP (which treats all candles as
    /// equal-duration), but retained for future time-duration weighting where
    /// each candle's weight is proportional to its actual time span.
    #[allow(dead_code)]
    pub timestamp: u64,
}

impl CandlePrice {
    pub(crate) fn from_parsed(
        price: Option<FixedValue>,
        volume: VolumeInput,
        timestamp: u64,
    ) -> Result<Self, ObservationError> {
        let ticker = TickerPrice::from_parsed(price, volume)?;
        Ok(Self {
            price: ticker.price,
            volume: ticker.volume,
            timestamp,
        })
    }
}

pub(crate) fn checked_ticker(
    provider: &'static str,
    symbol: &str,
    price: Option<FixedValue>,
    volume: VolumeInput,
) -> Option<TickerPrice> {
    match TickerPrice::from_parsed(price, volume) {
        Ok(ticker) => Some(ticker),
        Err(error) => {
            tracing::warn!(provider, symbol, reason = %error, "discarding invalid ticker");
            None
        }
    }
}

pub(crate) fn checked_candle(
    provider: &'static str,
    symbol: &str,
    price: Option<FixedValue>,
    volume: VolumeInput,
    timestamp: u64,
) -> Option<CandlePrice> {
    match CandlePrice::from_parsed(price, volume, timestamp) {
        Ok(candle) => Some(candle),
        Err(error) => {
            tracing::warn!(provider, symbol, reason = %error, "discarding invalid candle");
            None
        }
    }
}

/// Trait for external price data providers.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// Returns the provider name.
    fn name(&self) -> &str;

    /// Fetches current ticker prices for the given pairs.
    /// Keys are `"BASE/QUOTE"` strings.
    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>>;

    /// Fetches recent candle data for the given pairs.
    /// Keys are `"BASE/QUOTE"` strings; values are chronologically ordered candles.
    /// Default returns empty - providers that don't support candles need not override.
    async fn get_candle_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, Vec<CandlePrice>>> {
        let _ = pairs;
        Ok(HashMap::new())
    }
}

/// Creates provider instances from configuration.
pub fn create_providers(config: &FeederConfig) -> Result<Vec<Box<dyn Provider>>> {
    let mut providers: Vec<Box<dyn Provider>> = Vec::new();

    // Collect unique provider names from all configured source markets.
    let mut provider_names: Vec<String> = config
        .currency_pairs
        .iter()
        .flat_map(|pair| pair.sources.iter().map(|source| source.provider.clone()))
        .collect();
    provider_names.sort();
    provider_names.dedup();

    let endpoints: HashMap<&str, &ProviderEndpointConfig> = config
        .provider_endpoints
        .iter()
        .map(|endpoint| (endpoint.name.as_str(), endpoint))
        .collect();

    for name in &provider_names {
        let fallback: Box<dyn Provider> = match name.as_str() {
            "mock" => Box::new(mock::MockProvider::new()),
            "mock_http" => {
                let endpoint = endpoints.get("mock_http").ok_or_else(|| {
                    eyre!("provider mock_http requires a [[provider_endpoints]] entry")
                })?;
                Box::new(mock_http::MockHttpProvider::new(endpoint)?)
            }
            "pyth" => Box::new(pyth::PythProvider::new()?),
            "chainlink" => Box::new(chainlink::ChainlinkProvider::new()?),
            "binance" => Box::new(binance::BinanceProvider::new()?),
            "kraken" => Box::new(kraken::KrakenProvider::new()?),
            "okx" => Box::new(okx::OkxProvider::new()?),
            "gate" => Box::new(gate::GateProvider::new()?),
            "huobi" => Box::new(huobi::HuobiProvider::new()?),
            "mexc" => Box::new(mexc::MexcProvider::new()?),
            "coinbase" => Box::new(coinbase::CoinbaseProvider::new()?),
            "uniswap" | "pancakeswap" => Box::new(dex::DexProvider::new(
                config
                    .dex_providers
                    .iter()
                    .find(|dex| dex.name == *name)
                    .ok_or_else(|| eyre!("provider {name} requires a [[dex_providers]] entry"))?,
            )?),
            other => {
                tracing::warn!(provider = other, "unknown provider, skipping");
                continue;
            }
        };
        let configured_pairs = config
            .currency_pairs
            .iter()
            .flat_map(|pair| &pair.sources)
            .filter(|source| source.provider == *name)
            .map(|source| (source.base.clone(), source.quote.clone()))
            .collect::<Vec<_>>();
        let provider = if let Some(kind) = websocket::ExchangeKind::for_name(name)
            .filter(|kind| kind.supports_any(&configured_pairs))
        {
            let streaming = websocket::StreamingProvider::new(
                kind,
                endpoints.get(name.as_str()).copied(),
                &configured_pairs,
                fallback,
            )
            .expect("supports_any guarantees at least one WebSocket route");
            Box::new(streaming) as Box<dyn Provider>
        } else {
            fallback
        };
        providers.push(provider);
    }

    Ok(providers)
}

#[cfg(test)]
mod tests {
    use super::{CandlePrice, ObservationError, TickerPrice, VolumeInput};
    use crate::fixed::FixedValue;

    #[test]
    fn present_invalid_volume_is_rejected_instead_of_becoming_zero() {
        let result = TickerPrice::from_parsed(
            FixedValue::parse("1"),
            VolumeInput::Present(FixedValue::parse("-1")),
        );

        assert_eq!(result.unwrap_err(), ObservationError::InvalidVolume);
    }

    #[test]
    fn literal_zero_volume_and_unavailable_volume_are_distinct_valid_inputs() {
        let literal_zero = TickerPrice::from_parsed(
            FixedValue::parse("1"),
            VolumeInput::Present(FixedValue::parse("0")),
        )
        .unwrap();
        let unavailable =
            TickerPrice::from_parsed(FixedValue::parse("1"), VolumeInput::Unavailable).unwrap();

        assert!(literal_zero.volume.is_zero());
        assert!(unavailable.volume.is_zero());
    }

    #[test]
    fn invalid_or_zero_price_is_rejected() {
        assert_eq!(
            TickerPrice::from_parsed(
                FixedValue::parse("malformed"),
                VolumeInput::Present(FixedValue::parse("1")),
            )
            .unwrap_err(),
            ObservationError::InvalidPrice
        );
        assert_eq!(
            TickerPrice::from_parsed(
                FixedValue::parse("0"),
                VolumeInput::Present(FixedValue::parse("1")),
            )
            .unwrap_err(),
            ObservationError::ZeroPrice
        );
    }

    #[test]
    fn candle_uses_the_same_validation_contract() {
        assert_eq!(
            CandlePrice::from_parsed(
                FixedValue::parse("1"),
                VolumeInput::Present(FixedValue::parse("broken")),
                42,
            )
            .unwrap_err(),
            ObservationError::InvalidVolume
        );
        let candle = CandlePrice::from_parsed(
            FixedValue::parse("1"),
            VolumeInput::Present(FixedValue::parse("0")),
            42,
        )
        .unwrap();
        assert!(candle.volume.is_zero());
        assert_eq!(candle.timestamp, 42);
    }
}
