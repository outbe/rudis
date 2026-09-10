//! Mock HTTP price provider.
//!
//! Ports the Cosmos feeder `mock_http` provider shape. It reads prices from a
//! configurable REST endpoint:
//! - `GET /api/tickers?symbols=COEN840,ETHUSDC`
//! - `GET /api/candles?symbols=COEN840,ETHUSDC`
//!
//! Responses are expected to use `{ "data": [...] }` with string or numeric
//! price/volume fields.

use async_trait::async_trait;
use eyre::{eyre, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use crate::config::ProviderEndpointConfig;
use crate::fixed::JsonDecimal;

use super::{CandlePrice, Provider, TickerPrice, VolumeInput};

const DEFAULT_MOCK_HTTP_URL: &str = "http://localhost:8000";

#[derive(Debug)]
pub struct MockHttpProvider {
    base_url: String,
    client: reqwest::Client,
}

impl MockHttpProvider {
    pub fn new(endpoint: &ProviderEndpointConfig) -> Result<Self> {
        let base_url = if endpoint.rest.trim().is_empty() {
            DEFAULT_MOCK_HTTP_URL.to_string()
        } else {
            endpoint.rest.trim_end_matches('/').to_string()
        };

        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
        })
    }

    fn url_for(&self, path: &str, pairs: &[(String, String)]) -> String {
        let symbols = pairs
            .iter()
            .map(|(base, quote)| pair_symbol(base, quote))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}/api/{}?symbols={}", self.base_url, path, symbols)
    }
}

#[derive(Debug, Deserialize)]
struct TickerResponse {
    #[serde(default)]
    data: Vec<TickerEntry>,
}

#[derive(Debug, Deserialize)]
struct TickerEntry {
    symbol: String,
    price: JsonDecimal,
    volume: JsonDecimal,
}

#[derive(Debug, Deserialize)]
struct CandleResponse {
    #[serde(default)]
    data: Vec<CandleEntry>,
}

#[derive(Debug, Deserialize)]
struct CandleEntry {
    symbol: String,
    price: JsonDecimal,
    volume: JsonDecimal,
    #[serde(default)]
    timestamp: i64,
}

#[async_trait]
impl Provider for MockHttpProvider {
    fn name(&self) -> &str {
        "mock_http"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let requested = requested_symbols(pairs);
        let url = self.url_for("tickers", pairs);
        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .with_context(|| format!("failed to fetch mock_http tickers from {url}"))?;

        if !response.status().is_success() {
            return Err(eyre!(
                "mock_http ticker endpoint returned status {}",
                response.status()
            ));
        }

        let body: TickerResponse = response
            .json()
            .await
            .with_context(|| "failed to decode mock_http ticker response")?;

        tracing::debug!(url = %url, entries = body.data.len(), "mock_http ticker response");

        let mut prices = HashMap::new();
        for ticker in body.data {
            let symbol = ticker.symbol.to_uppercase();
            let Some(key) = requested.get(&symbol) else {
                continue;
            };
            if prices.contains_key(key) {
                return Err(eyre!("duplicate mock_http ticker for {symbol}"));
            }

            let ticker = TickerPrice::from_parsed(
                ticker.price.fixed(),
                VolumeInput::Present(ticker.volume.fixed()),
            )
            .map_err(|error| eyre!("invalid mock_http ticker for {symbol}: {error}"))?;
            tracing::info!(symbol = %symbol, price = %ticker.price.raw(), volume = %ticker.volume.raw(), "mock_http ticker received");
            prices.insert(key.clone(), ticker);
        }

        for (symbol, key) in &requested {
            if !prices.contains_key(key) {
                return Err(eyre!("missing mock_http ticker for {symbol}"));
            }
        }

        Ok(prices)
    }

    async fn get_candle_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, Vec<CandlePrice>>> {
        let requested = requested_symbols(pairs);
        let url = self.url_for("candles", pairs);
        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .with_context(|| format!("failed to fetch mock_http candles from {url}"))?;

        if !response.status().is_success() {
            return Err(eyre!(
                "mock_http candle endpoint returned status {}",
                response.status()
            ));
        }

        let body: CandleResponse = response
            .json()
            .await
            .with_context(|| "failed to decode mock_http candle response")?;

        tracing::debug!(url = %url, entries = body.data.len(), "mock_http candle response");

        let mut candles: HashMap<String, Vec<CandlePrice>> = HashMap::new();
        for candle in body.data {
            let symbol = candle.symbol.to_uppercase();
            let Some(key) = requested.get(&symbol) else {
                continue;
            };

            let candle = CandlePrice::from_parsed(
                candle.price.fixed(),
                VolumeInput::Present(candle.volume.fixed()),
                candle.timestamp.max(0) as u64,
            )
            .map_err(|error| eyre!("invalid mock_http candle for {symbol}: {error}"))?;

            candles.entry(key.clone()).or_default().push(candle);
        }

        if candles.is_empty() {
            return self.get_ticker_prices(pairs).await.map(|tickers| {
                tickers
                    .into_iter()
                    .map(|(key, ticker)| {
                        (
                            key,
                            vec![CandlePrice {
                                price: ticker.price,
                                volume: ticker.volume,
                                timestamp: 0,
                            }],
                        )
                    })
                    .collect()
            });
        }

        ensure_complete_candle_response(&requested, &candles)?;

        Ok(candles)
    }
}

fn ensure_complete_candle_response(
    requested: &HashMap<String, String>,
    candles: &HashMap<String, Vec<CandlePrice>>,
) -> Result<()> {
    for (symbol, key) in requested {
        if !candles.contains_key(key) {
            return Err(eyre!("missing mock_http candles for {symbol}"));
        }
    }
    Ok(())
}

fn requested_symbols(pairs: &[(String, String)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(base, quote)| (pair_symbol(base, quote), format!("{base}/{quote}")))
        .collect()
}

fn pair_symbol(base: &str, quote: &str) -> String {
    format!("{base}{quote}").to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::FixedValue;

    #[test]
    fn partial_candle_response_is_rejected() {
        let requested = requested_symbols(&[
            ("COEN".to_owned(), "USDT".to_owned()),
            ("COEN".to_owned(), "USDC".to_owned()),
        ]);
        let candles = HashMap::from([(
            "COEN/USDT".to_owned(),
            vec![CandlePrice {
                price: FixedValue::parse("1").unwrap(),
                volume: FixedValue::parse("1").unwrap(),
                timestamp: 1,
            }],
        )]);

        let error = ensure_complete_candle_response(&requested, &candles).unwrap_err();
        assert!(error.to_string().contains("COENUSDC"));
    }
}
