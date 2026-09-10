//! Kraken price provider.

use async_trait::async_trait;
use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::{checked_ticker, Provider, TickerPrice, VolumeInput};
use crate::fixed::FixedValue;

/// Maps a (base, quote) pair to a Kraken pair string.
/// Returns `None` for pairs Kraken doesn't support.
fn map_symbol(base: &str, quote: &str) -> Option<String> {
    if base.starts_with("COEN") || base.starts_with("0x") {
        return None;
    }
    let b = match base {
        "BTC" => "XBT",
        other => other,
    };
    // ISO 4217 numeric quote -> this exchange's stable-pair symbol.
    let q = match quote {
        "840" => "USD",
        other => other,
    };
    Some(format!("{b}{q}"))
}

/// Kraken price provider.
pub struct KrakenProvider {
    client: reqwest::Client,
}

impl KrakenProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct KrakenResponse {
    error: Vec<String>,
    result: Option<HashMap<String, KrakenTickerData>>,
}

#[derive(Debug, Deserialize)]
struct KrakenTickerData {
    /// Last trade: [price, lot volume]
    c: Vec<String>,
    /// Volume: [today, last 24h]
    v: Vec<String>,
}

#[async_trait]
impl Provider for KrakenProvider {
    fn name(&self) -> &str {
        "kraken"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut result = HashMap::new();

        for (base, quote) in pairs {
            let symbol = match map_symbol(base, quote) {
                Some(s) => s,
                None => continue,
            };

            let url = format!("https://api.kraken.com/0/public/Ticker?pair={symbol}");

            let resp = match self
                .client
                .get(&url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        pair = %format!("{base}/{quote}"),
                        "kraken request failed"
                    );
                    continue;
                }
            };

            if !resp.status().is_success() {
                tracing::warn!(
                    status = %resp.status(),
                    pair = %format!("{base}/{quote}"),
                    "kraken API error"
                );
                continue;
            }

            let data: KrakenResponse = match resp
                .json()
                .await
                .with_context(|| format!("failed to parse kraken response for {base}/{quote}"))
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, pair = %format!("{base}/{quote}"), "kraken parse error");
                    continue;
                }
            };

            if !data.error.is_empty() {
                tracing::warn!(
                    errors = ?data.error,
                    pair = %format!("{base}/{quote}"),
                    "kraken returned errors"
                );
                continue;
            }

            if let Some(result_map) = data.result {
                // Kraken uses internal pair names (e.g. XETHZUSD, XXBTZUSD)
                // so we just take the first (and only) entry.
                if let Some(ticker) = result_map.values().next() {
                    let key = format!("{base}/{quote}");
                    if let Some(ticker) = checked_ticker(
                        "kraken",
                        &key,
                        ticker.c.first().and_then(|value| FixedValue::parse(value)),
                        VolumeInput::Present(
                            ticker.v.get(1).and_then(|value| FixedValue::parse(value)),
                        ),
                    ) {
                        result.insert(key, ticker);
                    }
                }
            }
        }

        Ok(result)
    }
}
