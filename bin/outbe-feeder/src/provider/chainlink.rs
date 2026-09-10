//! Chainlink / CryptoCompare price provider.
//!
//! Uses the CryptoCompare REST API (same data source as Cosmos oracle's
//! Chainlink provider) to fetch ticker and candle data.

use async_trait::async_trait;
use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::{checked_candle, checked_ticker, CandlePrice, Provider, TickerPrice, VolumeInput};
use crate::fixed::JsonDecimal;

const CRYPTOCOMPARE_BASE_URL: &str = "https://min-api.cryptocompare.com";

/// Maps a trading pair to CryptoCompare symbol format.
/// Returns `(fsym, tsym)` or None if the pair is not supported.
fn map_symbol(base: &str, quote: &str) -> Option<(String, String)> {
    let fsym = match base {
        "COEN" => return None, // Internal token, not on CryptoCompare
        other => other.to_uppercase(),
    };
    let tsym = match quote {
        // ISO 4217 numeric quote -> the feed's stable-pair symbol.
        "840" => "USD".to_string(),
        other => other.to_uppercase(),
    };
    Some((fsym, tsym))
}

/// Chainlink/CryptoCompare price provider.
pub struct ChainlinkProvider {
    client: reqwest::Client,
}

impl ChainlinkProvider {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct CryptoCompareTickerResponse {
    #[serde(rename = "RAW")]
    raw: Option<HashMap<String, HashMap<String, CryptoCompareRawTicker>>>,
}

#[derive(Debug, Deserialize)]
struct CryptoCompareRawTicker {
    #[serde(rename = "PRICE")]
    price: Option<JsonDecimal>,
    #[serde(rename = "VOLUME24HOUR")]
    volume_24h: Option<JsonDecimal>,
}

#[derive(Debug, Deserialize)]
struct CryptoCompareCandleResponse {
    #[serde(rename = "Data")]
    data: Option<CryptoCompareCandleData>,
}

#[derive(Debug, Deserialize)]
struct CryptoCompareCandleData {
    #[serde(rename = "Data")]
    data: Option<Vec<CryptoCompareCandle>>,
}

#[derive(Debug, Deserialize)]
struct CryptoCompareCandle {
    time: u64,
    close: JsonDecimal,
    volumeto: JsonDecimal,
}

type MappedPair = (String, String, String, String);

fn collect_tickers(
    data: CryptoCompareTickerResponse,
    mapped: &[MappedPair],
) -> HashMap<String, TickerPrice> {
    let mut result = HashMap::new();
    let Some(raw) = data.raw else {
        return result;
    };
    for (base, quote, fsym, tsym) in mapped {
        let Some(ticker) = raw
            .get(fsym.as_str())
            .and_then(|quotes| quotes.get(tsym.as_str()))
        else {
            continue;
        };
        let key = format!("{base}/{quote}");
        if let Some(ticker) = checked_ticker(
            "chainlink",
            &key,
            ticker.price.as_ref().and_then(JsonDecimal::fixed),
            VolumeInput::Present(ticker.volume_24h.as_ref().and_then(JsonDecimal::fixed)),
        ) {
            result.insert(key, ticker);
        }
    }
    result
}

#[async_trait]
impl Provider for ChainlinkProvider {
    fn name(&self) -> &str {
        "chainlink"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let result = HashMap::new();

        // Collect all supported symbols for a batch request
        let mapped: Vec<MappedPair> = pairs
            .iter()
            .filter_map(|(base, quote)| {
                map_symbol(base, quote)
                    .map(|(fsym, tsym)| (base.clone(), quote.clone(), fsym, tsym))
            })
            .collect();

        if mapped.is_empty() {
            return Ok(result);
        }

        // CryptoCompare supports multi-pair queries
        let fsyms: Vec<&str> = mapped.iter().map(|(_, _, f, _)| f.as_str()).collect();
        let tsyms: Vec<&str> = mapped.iter().map(|(_, _, _, t)| t.as_str()).collect();

        let fsyms_str = fsyms.join(",");
        let tsyms_str = tsyms.join(",");

        let url = format!(
            "{}/data/pricemultifull?fsyms={}&tsyms={}",
            CRYPTOCOMPARE_BASE_URL, fsyms_str, tsyms_str
        );

        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .with_context(|| "cryptocompare ticker request failed")?;

        if !resp.status().is_success() {
            tracing::warn!(
                status = %resp.status(),
                "cryptocompare API error"
            );
            return Ok(result);
        }

        let data: CryptoCompareTickerResponse = resp
            .json()
            .await
            .with_context(|| "failed to parse cryptocompare response")?;

        Ok(collect_tickers(data, &mapped))
    }

    async fn get_candle_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, Vec<CandlePrice>>> {
        let mut result = HashMap::new();

        for (base, quote) in pairs {
            let (fsym, tsym) = match map_symbol(base, quote) {
                Some(s) => s,
                None => continue,
            };

            let url = format!(
                "{}/data/v2/histominute?fsym={}&tsym={}&limit=5",
                CRYPTOCOMPARE_BASE_URL, fsym, tsym
            );

            let resp = self
                .client
                .get(&url)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await;

            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, pair = %format!("{base}/{quote}"), "cryptocompare candle request failed");
                    continue;
                }
            };

            if !resp.status().is_success() {
                continue;
            }

            let data: CryptoCompareCandleResponse = match resp.json().await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse cryptocompare candle response");
                    continue;
                }
            };

            if let Some(outer) = data.data {
                if let Some(candles) = outer.data {
                    let key = format!("{base}/{quote}");
                    let entries: Vec<CandlePrice> = candles
                        .into_iter()
                        .filter_map(|c| {
                            checked_candle(
                                "chainlink",
                                &key,
                                c.close.fixed(),
                                VolumeInput::Present(c.volumeto.fixed()),
                                c.time,
                            )
                        })
                        .collect();
                    if !entries.is_empty() {
                        result.insert(key, entries);
                    }
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::FixedValue;

    #[test]
    fn malformed_market_does_not_discard_a_valid_sibling() {
        let payload = serde_json::json!({
            "RAW": {
                "BTC": { "USD": { "PRICE": "100", "VOLUME24HOUR": "-1" } },
                "ETH": { "USD": { "PRICE": "200", "VOLUME24HOUR": "3" } }
            }
        });
        let response: CryptoCompareTickerResponse = serde_json::from_value(payload).unwrap();
        let mapped = vec![
            (
                "BTC".to_owned(),
                "840".to_owned(),
                "BTC".to_owned(),
                "USD".to_owned(),
            ),
            (
                "ETH".to_owned(),
                "840".to_owned(),
                "ETH".to_owned(),
                "USD".to_owned(),
            ),
        ];

        let prices = collect_tickers(response, &mapped);

        assert!(!prices.contains_key("BTC/840"));
        assert_eq!(
            prices["ETH/840"].price.raw(),
            FixedValue::parse("200").unwrap().raw()
        );
    }
}
