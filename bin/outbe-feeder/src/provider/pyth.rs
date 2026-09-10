//! Pyth Network price provider via Hermes REST API.

use async_trait::async_trait;
use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::{checked_ticker, Provider, TickerPrice, VolumeInput};
use crate::fixed::FixedValue;

/// Default Pyth Hermes endpoint.
const DEFAULT_HERMES_URL: &str = "https://hermes.pyth.network";

/// Known Pyth price feed IDs for common assets.
/// See: https://pyth.network/developers/price-feed-ids
fn pyth_feed_id(base: &str, quote: &str) -> Option<&'static str> {
    match (base, quote) {
        ("ETH", "USD" | "840") => {
            Some("0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace")
        }
        ("BTC", "USD" | "840") => {
            Some("0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43")
        }
        _ => None,
    }
}

/// Pyth Network price provider.
pub struct PythProvider {
    client: reqwest::Client,
    hermes_url: String,
}

impl PythProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            hermes_url: DEFAULT_HERMES_URL.to_string(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct PythPriceResponse {
    parsed: Vec<PythParsedPrice>,
}

#[derive(Debug, Deserialize)]
struct PythParsedPrice {
    price: PythPriceData,
}

#[derive(Debug, Deserialize)]
struct PythPriceData {
    price: String,
    expo: i32,
}

#[async_trait]
impl Provider for PythProvider {
    fn name(&self) -> &str {
        "pyth"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut result = HashMap::new();

        for (base, quote) in pairs {
            let feed_id = match pyth_feed_id(base, quote) {
                Some(id) => id,
                None => continue,
            };

            let url = format!(
                "{}/v2/updates/price/latest?ids[]={}",
                self.hermes_url, feed_id
            );

            let resp = self
                .client
                .get(&url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .with_context(|| format!("pyth request failed for {base}/{quote}"))?;

            if !resp.status().is_success() {
                tracing::warn!(
                    status = %resp.status(),
                    pair = %format!("{base}/{quote}"),
                    "pyth API error"
                );
                continue;
            }

            let data: PythPriceResponse = resp
                .json()
                .await
                .with_context(|| "failed to parse pyth response")?;

            if let Some(parsed) = data.parsed.first() {
                let key = format!("{base}/{quote}");
                if let Some(ticker) = checked_ticker(
                    "pyth",
                    &key,
                    FixedValue::parse(&format!("{}e{}", parsed.price.price, parsed.price.expo)),
                    VolumeInput::Unavailable,
                ) {
                    result.insert(key, ticker);
                }
            }
        }

        Ok(result)
    }
}
