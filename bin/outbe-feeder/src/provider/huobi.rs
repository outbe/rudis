//! Huobi (HTX) price provider.

use async_trait::async_trait;
use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::{checked_ticker, Provider, TickerPrice, VolumeInput};
use crate::fixed::JsonDecimal;

/// Maps a (base, quote) pair to a Huobi symbol (lowercase).
/// Returns `None` for pairs Huobi doesn't support.
fn map_symbol(base: &str, quote: &str) -> Option<String> {
    if base.starts_with("COEN") || base.starts_with("0x") {
        return None;
    }
    // ISO 4217 numeric quote -> this exchange's stable-pair symbol.
    let q = match quote {
        "840" => "usdt",
        other => other,
    };
    Some(format!("{}{}", base.to_lowercase(), q.to_lowercase()))
}

/// Huobi (HTX) price provider.
pub struct HuobiProvider {
    client: reqwest::Client,
}

impl HuobiProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct HuobiResponse {
    status: String,
    tick: Option<HuobiTick>,
}

#[derive(Debug, Deserialize)]
struct HuobiTick {
    close: JsonDecimal,
    vol: JsonDecimal,
}

#[async_trait]
impl Provider for HuobiProvider {
    fn name(&self) -> &str {
        "huobi"
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

            let url = format!("https://api.huobi.pro/market/detail/merged?symbol={symbol}");

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
                        "huobi request failed"
                    );
                    continue;
                }
            };

            if !resp.status().is_success() {
                tracing::warn!(
                    status = %resp.status(),
                    pair = %format!("{base}/{quote}"),
                    "huobi API error"
                );
                continue;
            }

            let data: HuobiResponse = match resp
                .json()
                .await
                .with_context(|| format!("failed to parse huobi response for {base}/{quote}"))
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, pair = %format!("{base}/{quote}"), "huobi parse error");
                    continue;
                }
            };

            if data.status != "ok" {
                tracing::warn!(
                    status = %data.status,
                    pair = %format!("{base}/{quote}"),
                    "huobi returned non-ok status"
                );
                continue;
            }

            if let Some(tick) = data.tick {
                let key = format!("{base}/{quote}");
                if let Some(ticker) = checked_ticker(
                    "huobi",
                    &key,
                    tick.close.fixed(),
                    VolumeInput::Present(tick.vol.fixed()),
                ) {
                    result.insert(key, ticker);
                }
            }
        }

        Ok(result)
    }
}
