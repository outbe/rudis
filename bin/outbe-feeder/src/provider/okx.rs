//! OKX price provider.

use async_trait::async_trait;
use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::{checked_ticker, Provider, TickerPrice, VolumeInput};
use crate::fixed::FixedValue;

/// Maps a (base, quote) pair to an OKX instrument ID.
/// Returns `None` for pairs OKX doesn't support.
fn map_symbol(base: &str, quote: &str) -> Option<String> {
    if base.starts_with("COEN") || base.starts_with("0x") {
        return None;
    }
    // ISO 4217 numeric quote -> this exchange's stable-pair symbol.
    let q = match quote {
        "840" => "USDT",
        other => other,
    };
    Some(format!("{base}-{q}"))
}

/// OKX price provider.
pub struct OkxProvider {
    client: reqwest::Client,
}

impl OkxProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct OkxResponse {
    data: Vec<OkxTickerData>,
}

#[derive(Debug, Deserialize)]
struct OkxTickerData {
    last: String,
    #[serde(rename = "vol24h")]
    vol_24h: String,
}

#[async_trait]
impl Provider for OkxProvider {
    fn name(&self) -> &str {
        "okx"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut result = HashMap::new();

        for (base, quote) in pairs {
            let inst_id = match map_symbol(base, quote) {
                Some(s) => s,
                None => continue,
            };

            let url = format!("https://www.okx.com/api/v5/market/ticker?instId={inst_id}");

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
                        "okx request failed"
                    );
                    continue;
                }
            };

            if !resp.status().is_success() {
                tracing::warn!(
                    status = %resp.status(),
                    pair = %format!("{base}/{quote}"),
                    "okx API error"
                );
                continue;
            }

            let data: OkxResponse = match resp
                .json()
                .await
                .with_context(|| format!("failed to parse okx response for {base}/{quote}"))
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, pair = %format!("{base}/{quote}"), "okx parse error");
                    continue;
                }
            };

            if let Some(ticker) = data.data.first() {
                let key = format!("{base}/{quote}");
                if let Some(ticker) = checked_ticker(
                    "okx",
                    &key,
                    FixedValue::parse(&ticker.last),
                    VolumeInput::Present(FixedValue::parse(&ticker.vol_24h)),
                ) {
                    result.insert(key, ticker);
                }
            }
        }

        Ok(result)
    }
}
