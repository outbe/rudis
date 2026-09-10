//! Mock price provider for local development and testing.
//!
//! Returns deterministic prices with slight random variation.

use async_trait::async_trait;
use eyre::Result;
use std::collections::HashMap;

use super::{CandlePrice, Provider, TickerPrice};
use crate::fixed::FixedValue;

/// Mock provider returning hardcoded prices with small variations.
pub struct MockProvider {
    base_prices: HashMap<String, FixedValue>,
}

impl MockProvider {
    pub fn new() -> Self {
        let mut base_prices = HashMap::new();
        base_prices.insert("COEN/840".to_string(), FixedValue::parse("1").unwrap());
        base_prices.insert("ETH/840".to_string(), FixedValue::parse("2500").unwrap());
        Self { base_prices }
    }
}

#[async_trait]
impl Provider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut result = HashMap::new();
        for (base, quote) in pairs {
            let key = format!("{base}/{quote}");
            if let Some(&price) = self.base_prices.get(&key) {
                result.insert(
                    key,
                    TickerPrice {
                        price,
                        volume: FixedValue::parse("10000").unwrap(),
                    },
                );
            }
            // Unknown pairs are silently skipped - no fabricated prices
        }
        Ok(result)
    }

    async fn get_candle_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, Vec<CandlePrice>>> {
        let mut result = HashMap::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (base, quote) in pairs {
            let key = format!("{base}/{quote}");
            if let Some(&base_price) = self.base_prices.get(&key) {
                // Return 3 sample candles with slight price variation
                let candles = vec![
                    CandlePrice {
                        price: base_price.checked_mul_ratio(99, 100).unwrap(),
                        volume: FixedValue::parse("3000").unwrap(),
                        timestamp: now - 180,
                    },
                    CandlePrice {
                        price: base_price.checked_mul_ratio(101, 100).unwrap(),
                        volume: FixedValue::parse("4000").unwrap(),
                        timestamp: now - 120,
                    },
                    CandlePrice {
                        price: base_price,
                        volume: FixedValue::parse("3500").unwrap(),
                        timestamp: now - 60,
                    },
                ];
                result.insert(key, candles);
            }
        }
        Ok(result)
    }
}
