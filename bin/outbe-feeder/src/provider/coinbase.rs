//! Coinbase price provider.

use async_trait::async_trait;
use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::{checked_ticker, Provider, TickerPrice, VolumeInput};
use crate::fixed::FixedValue;

/// Maps a (base, quote) pair to a Coinbase price path segment.
/// Returns `None` for pairs Coinbase doesn't support.
fn map_symbol(base: &str, quote: &str) -> Option<String> {
    if base.starts_with("COEN") || base.starts_with("0x") {
        return None;
    }
    // ISO 4217 numeric quote -> this exchange's stable-pair symbol.
    let q = match quote {
        "840" => "USD",
        other => other,
    };
    Some(format!("{base}-{q}"))
}

/// Coinbase price provider.
pub struct CoinbaseProvider {
    client: reqwest::Client,
}

impl CoinbaseProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct CoinbaseResponse {
    data: CoinbasePriceData,
}

#[derive(Debug, Deserialize)]
struct CoinbasePriceData {
    amount: String,
}

#[async_trait]
impl Provider for CoinbaseProvider {
    fn name(&self) -> &str {
        "coinbase"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut result = HashMap::new();

        for (base, quote) in pairs {
            let pair_slug = match map_symbol(base, quote) {
                Some(s) => s,
                None => continue,
            };

            let url = format!("https://api.coinbase.com/v2/prices/{pair_slug}/spot");

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
                        "coinbase request failed"
                    );
                    continue;
                }
            };

            if !resp.status().is_success() {
                tracing::warn!(
                    status = %resp.status(),
                    pair = %format!("{base}/{quote}"),
                    "coinbase API error"
                );
                continue;
            }

            let data: CoinbaseResponse = match resp
                .json()
                .await
                .with_context(|| format!("failed to parse coinbase response for {base}/{quote}"))
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, pair = %format!("{base}/{quote}"), "coinbase parse error");
                    continue;
                }
            };

            let key = format!("{base}/{quote}");
            if let Some(ticker) = checked_ticker(
                "coinbase",
                &key,
                FixedValue::parse(&data.data.amount),
                VolumeInput::Unavailable,
            ) {
                result.insert(key, ticker);
            }
        }

        Ok(result)
    }
}
