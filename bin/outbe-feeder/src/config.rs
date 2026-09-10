//! TOML configuration for the price-feeder daemon.

use alloy_primitives::{Address, U256};
use eyre::{Context, Result};
use serde::Deserialize;

use crate::fixed::FixedValue;
use outbe_primitives::asset_type::AssetType;
use outbe_primitives::units::SCALE_1E18;

/// Top-level feeder configuration.
#[derive(Debug, Deserialize)]
pub struct FeederConfig {
    pub chain: ChainConfig,
    pub account: AccountConfig,
    pub oracle: OracleConfig,
    #[serde(default)]
    pub currency_pairs: Vec<CurrencyPairConfig>,
    #[serde(default)]
    pub deviation_thresholds: Vec<DeviationThreshold>,
    #[serde(default)]
    pub provider_endpoints: Vec<ProviderEndpointConfig>,
    /// Finalized EVM pool readers; independent of the destination Outbe RPC.
    #[serde(default)]
    pub dex_providers: Vec<crate::provider::dex::DexProviderConfig>,
    /// Health/status HTTP server configuration.
    pub health: Option<HealthConfig>,
}

/// Health server settings.
#[derive(Debug, Deserialize)]
pub struct HealthConfig {
    /// Enable health server (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bind address (default: 0.0.0.0:9002).
    #[serde(default = "default_health_bind")]
    pub bind_address: String,
}

fn default_true() -> bool {
    true
}

fn default_health_bind() -> String {
    "0.0.0.0:9002".to_string()
}

/// Chain connection settings.
#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    /// JSON-RPC endpoint (HTTP).
    pub rpc_endpoint: String,
    /// Chain ID.
    pub chain_id: u64,
    /// Submit validator oracle votes through the guarded ZeroFee txpool policy.
    #[serde(default)]
    pub gasless_oracle_votes: bool,
}

/// Feeder account credentials.
#[derive(Debug, Deserialize)]
pub struct AccountConfig {
    /// Hex-encoded private key of the feeder account.
    /// In production, this should be loaded from a keystore file instead.
    pub private_key: String,
    /// Validator address this feeder acts on behalf of.
    pub validator_address: String,
}

/// Oracle-specific settings.
#[derive(Debug, Deserialize)]
pub struct OracleConfig {
    /// Vote period in blocks (must match on-chain config).
    #[serde(default = "default_vote_period")]
    pub vote_period: u64,
    /// How often to poll for new blocks (seconds).
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

/// A currency pair to feed prices for.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrencyPairConfig {
    /// On-chain Oracle base asset: `COEN`, an ISO numeric code, or an address.
    pub base: String,
    /// On-chain Oracle quote asset: an ISO numeric code or an address.
    pub quote: String,
    /// External markets which are aggregated into this one Oracle observation.
    pub sources: Vec<CurrencyPairSource>,
}

/// One provider-native market used to price an on-chain Oracle pair.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CurrencyPairSource {
    pub provider: String,
    pub base: String,
    pub quote: String,
}

/// Optional REST/WebSocket endpoint overrides for a provider.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEndpointConfig {
    pub name: String,
    #[serde(default)]
    pub rest: String,
    /// Exchange market-stream endpoint. Empty selects the exchange default.
    #[serde(default)]
    pub websocket: String,
}

/// Deviation threshold for outlier filtering.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviationThreshold {
    pub base: String,
    /// Maximum standard deviations from median to accept.
    #[serde(default = "default_deviation")]
    pub threshold: FixedValue,
}

fn default_vote_period() -> u64 {
    2
}
fn default_poll_interval() -> u64 {
    2
}
fn default_deviation() -> FixedValue {
    FixedValue::from_raw(U256::from_limbs([2_000_000_000_000_000_000u64, 0, 0, 0]))
}

impl FeederConfig {
    /// Loads configuration from a TOML file.
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {path}"))?;
        toml::from_str(&content).with_context(|| "failed to parse feeder config")
    }

    /// Known provider names.
    const KNOWN_PROVIDERS: &'static [&'static str] = &[
        "mock",
        "pyth",
        "chainlink",
        "binance",
        "kraken",
        "okx",
        "gate",
        "huobi",
        "mexc",
        "coinbase",
        "mock_http",
        "uniswap",
        "pancakeswap",
    ];

    /// Validates configuration at startup. Returns error for invalid values.
    pub fn validate(&self) -> Result<()> {
        // vote_period must be > 0
        if self.oracle.vote_period == 0 {
            return Err(eyre::eyre!(
                "oracle.vote_period must be > 0, got 0 (would cause division by zero)"
            ));
        }

        // validator_address must parse as a hex address
        let addr = self.account.validator_address.trim_start_matches("0x");
        if addr.len() != 40 || addr.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(eyre::eyre!(
                "account.validator_address is not a valid 20-byte hex address: {}",
                self.account.validator_address
            ));
        }

        let mut oracle_pairs = std::collections::BTreeSet::new();
        for pair in &self.currency_pairs {
            let base = parse_oracle_asset(&pair.base)?;
            let quote = parse_oracle_asset(&pair.quote)?;
            if base == quote {
                return Err(eyre::eyre!(
                    "Oracle pair {}/{} uses the same asset twice",
                    pair.base,
                    pair.quote
                ));
            }
            if matches!(AssetType::from(base), AssetType::IsoCurrency(_))
                && matches!(AssetType::from(quote), AssetType::Native)
            {
                return Err(eyre::eyre!(
                    "ISO/COEN pair {}/{} is invalid; configure COEN/ISO",
                    pair.base,
                    pair.quote
                ));
            }
            let unordered_key = if base < quote {
                (base, quote)
            } else {
                (quote, base)
            };
            if !oracle_pairs.insert(unordered_key) {
                return Err(eyre::eyre!(
                    "duplicate or inverse Oracle pair {}/{}",
                    pair.base,
                    pair.quote
                ));
            }
            if pair.sources.is_empty() {
                return Err(eyre::eyre!(
                    "currency pair {}/{} has no sources configured",
                    pair.base,
                    pair.quote
                ));
            }
            let mut sources = std::collections::BTreeSet::new();
            for source in &pair.sources {
                if source.base.trim().is_empty() || source.quote.trim().is_empty() {
                    return Err(eyre::eyre!(
                        "provider source for {}/{} has an empty market asset",
                        pair.base,
                        pair.quote
                    ));
                }
                if !Self::KNOWN_PROVIDERS.contains(&source.provider.as_str()) {
                    return Err(eyre::eyre!(
                        "unknown provider '{}' for pair {}/{}. Known: {:?}",
                        source.provider,
                        pair.base,
                        pair.quote,
                        Self::KNOWN_PROVIDERS
                    ));
                }
                if !sources.insert((
                    source.provider.as_str(),
                    source.base.as_str(),
                    source.quote.as_str(),
                )) {
                    return Err(eyre::eyre!(
                        "duplicate provider source '{}' {}/{} for pair {}/{}",
                        source.provider,
                        source.base,
                        source.quote,
                        pair.base,
                        pair.quote
                    ));
                }
            }
        }

        let mut endpoint_names = std::collections::BTreeSet::new();
        for endpoint in &self.provider_endpoints {
            if !Self::KNOWN_PROVIDERS.contains(&endpoint.name.as_str()) {
                return Err(eyre::eyre!(
                    "unknown provider endpoint '{}'. Known: {:?}",
                    endpoint.name,
                    Self::KNOWN_PROVIDERS
                ));
            }
            if !endpoint_names.insert(endpoint.name.as_str()) {
                return Err(eyre::eyre!(
                    "duplicate provider endpoint '{}'",
                    endpoint.name
                ));
            }
            if !endpoint.websocket.is_empty() {
                if !matches!(
                    endpoint.name.as_str(),
                    "binance" | "kraken" | "okx" | "gate" | "huobi" | "mexc" | "coinbase"
                ) {
                    return Err(eyre::eyre!(
                        "provider '{}' does not support websocket market streams",
                        endpoint.name
                    ));
                }
                let websocket = endpoint.websocket.trim();
                if websocket.is_empty()
                    || websocket.contains(char::is_whitespace)
                    || (websocket.contains("://")
                        && !websocket.starts_with("ws://")
                        && !websocket.starts_with("wss://"))
                {
                    return Err(eyre::eyre!(
                        "provider '{}' has invalid websocket endpoint '{}'",
                        endpoint.name,
                        endpoint.websocket
                    ));
                }
            }
        }

        crate::provider::dex::validate_config(self)?;
        Ok(())
    }

    /// Returns the deviation threshold for a given base asset, or the default.
    pub fn deviation_for(&self, base: &str) -> FixedValue {
        self.deviation_thresholds
            .iter()
            .find(|d| d.base == base)
            .map(|d| d.threshold)
            .unwrap_or_else(|| FixedValue::from_raw(U256::from(2u64) * SCALE_1E18))
    }
}

impl CurrencyPairConfig {
    pub(crate) fn oracle_pair(&self) -> Result<(Address, Address)> {
        Ok((
            parse_oracle_asset(&self.base)?,
            parse_oracle_asset(&self.quote)?,
        ))
    }
}

fn parse_oracle_asset(symbol: &str) -> Result<Address> {
    let text = symbol.trim();
    if text.eq_ignore_ascii_case("rudis") || text.eq_ignore_ascii_case("COEN") {
        return Ok(Address::ZERO);
    }
    if let Ok(code) = text.parse::<u16>() {
        if (1..=999).contains(&code) {
            return Ok(AssetType::IsoCurrency(code).into());
        }
    }
    text.parse::<Address>()
        .map_err(|_| eyre::eyre!("unknown on-chain Oracle asset '{symbol}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(vote_period: u64) -> FeederConfig {
        FeederConfig {
            chain: ChainConfig {
                rpc_endpoint: "http://localhost:8545".to_string(),
                chain_id: 1,
                gasless_oracle_votes: false,
            },
            account: AccountConfig {
                private_key: "0xdead".to_string(),
                validator_address: "0x1111111111111111111111111111111111111111".to_string(),
            },
            oracle: OracleConfig {
                vote_period,
                poll_interval_secs: 2,
            },
            currency_pairs: vec![],
            deviation_thresholds: vec![],
            provider_endpoints: vec![],
            dex_providers: vec![],
            health: None,
        }
    }

    fn source(provider: &str, base: &str, quote: &str) -> CurrencyPairSource {
        CurrencyPairSource {
            provider: provider.to_owned(),
            base: base.to_owned(),
            quote: quote.to_owned(),
        }
    }

    #[test]
    fn test_validate_rejects_zero_vote_period() {
        let cfg = minimal_config(0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_config_vote_period_zero() {
        let err = minimal_config(0).validate().unwrap_err();
        assert!(err.to_string().contains("vote_period must be > 0"));
    }

    #[test]
    fn test_validate_accepts_valid_vote_period() {
        let cfg = minimal_config(2);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_invalid_validator_address() {
        let mut cfg = minimal_config(2);
        cfg.account.validator_address = "not-an-address".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_empty_sources() {
        let mut cfg = minimal_config(2);
        cfg.currency_pairs.push(CurrencyPairConfig {
            base: "COEN".to_string(),
            quote: "840".to_string(),
            sources: vec![],
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_unknown_provider() {
        let mut cfg = minimal_config(2);
        cfg.currency_pairs.push(CurrencyPairConfig {
            base: "COEN".to_string(),
            quote: "840".to_string(),
            sources: vec![source("nonexistent_exchange", "COEN", "USDT")],
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_accepts_known_provider() {
        let mut cfg = minimal_config(2);
        cfg.currency_pairs.push(CurrencyPairConfig {
            base: "COEN".to_string(),
            quote: "840".to_string(),
            sources: vec![source("mock", "COEN", "USDT")],
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn currency_pair_rejects_removed_chain_denom() {
        let result = toml::from_str::<CurrencyPairConfig>(
            "base = 'COEN'\nquote = '840'\nchain_denom = 'unit'\n[[sources]]\nprovider = 'mock'\nbase = 'COEN'\nquote = 'USDT'",
        );
        assert!(result.is_err());
    }

    #[test]
    fn currency_pair_rejects_the_removed_providers_array() {
        let result = toml::from_str::<CurrencyPairConfig>(
            "base = 'COEN'\nquote = '840'\nproviders = ['mock']",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_accepts_mock_http_provider() {
        let mut cfg = minimal_config(2);
        cfg.provider_endpoints.push(ProviderEndpointConfig {
            name: "mock_http".to_string(),
            rest: "http://localhost:8000".to_string(),
            websocket: String::new(),
        });
        cfg.currency_pairs.push(CurrencyPairConfig {
            base: "COEN".to_string(),
            quote: "840".to_string(),
            sources: vec![source("mock_http", "COEN", "USDT")],
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_exchange_websocket_endpoint() {
        let mut cfg = minimal_config(2);
        cfg.provider_endpoints.push(ProviderEndpointConfig {
            name: "binance".to_string(),
            rest: String::new(),
            websocket: "wss://stream.binance.com:9443/ws".to_string(),
        });
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_websocket_for_rest_only_provider() {
        let mut cfg = minimal_config(2);
        cfg.provider_endpoints.push(ProviderEndpointConfig {
            name: "mock_http".to_string(),
            rest: "http://localhost:8000".to_string(),
            websocket: "ws://localhost:8001".to_string(),
        });
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not support websocket"));
    }

    #[test]
    fn test_validate_rejects_duplicate_provider_endpoints() {
        let mut cfg = minimal_config(2);
        for _ in 0..2 {
            cfg.provider_endpoints.push(ProviderEndpointConfig {
                name: "binance".to_string(),
                rest: String::new(),
                websocket: String::new(),
            });
        }
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate provider endpoint"));
    }

    #[test]
    fn test_validate_rejects_iso_coen_but_preserves_generic_orientation() {
        let mut cfg = minimal_config(2);
        cfg.currency_pairs.push(CurrencyPairConfig {
            base: "840".to_string(),
            quote: "COEN".to_string(),
            sources: vec![source("mock", "USDT", "COEN")],
        });
        assert!(cfg.validate().unwrap_err().to_string().contains("COEN/ISO"));

        cfg.currency_pairs[0].base = "999".to_string();
        assert!(cfg.validate().unwrap_err().to_string().contains("COEN/ISO"));

        cfg.currency_pairs[0].base = "840".to_string();
        cfg.currency_pairs[0].quote = "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599".to_string();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_an_unknown_on_chain_symbol() {
        let mut cfg = minimal_config(2);
        cfg.currency_pairs.push(CurrencyPairConfig {
            base: "BTC".to_string(),
            quote: "840".to_string(),
            sources: vec![source("binance", "BTC", "USDT")],
        });

        let err = cfg.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("unknown on-chain Oracle asset 'BTC'"));
    }

    #[test]
    fn multiple_provider_markets_feed_one_coen_iso_pair() {
        let pair: CurrencyPairConfig = toml::from_str(
            "base = 'COEN'\nquote = '840'\n\
             [[sources]]\nprovider = 'binance'\nbase = 'COEN'\nquote = 'USDT'\n\
             [[sources]]\nprovider = 'binance'\nbase = 'COEN'\nquote = 'USDC'\n\
             [[sources]]\nprovider = 'coinbase'\nbase = 'COEN'\nquote = 'USDC'",
        )
        .unwrap();

        assert_eq!(pair.sources.len(), 3);
        assert_eq!(pair.sources[0], source("binance", "COEN", "USDT"));
        assert_eq!(pair.oracle_pair().unwrap().0, Address::ZERO);
        assert_eq!(
            AssetType::from(pair.oracle_pair().unwrap().1),
            AssetType::IsoCurrency(840)
        );
    }

    #[test]
    fn deviation_threshold_requires_an_exact_decimal_string() {
        let quoted: DeviationThreshold =
            toml::from_str("base = 'ETH'\nthreshold = '2.000000000000000001'").unwrap();
        assert_eq!(
            quoted.threshold.raw(),
            U256::from(2u64) * SCALE_1E18 + U256::ONE
        );

        let numeric = toml::from_str::<DeviationThreshold>("base = 'ETH'\nthreshold = 2.0");
        assert!(numeric.is_err());
    }

    #[test]
    fn test_price_oracle_script_config_loads() {
        let path = format!(
            "{}/../../scripts/price-oracle/config.toml",
            env!("CARGO_MANIFEST_DIR")
        );
        let cfg = FeederConfig::load(&path).unwrap();
        // Canonical localnet chain id (scripts/prepare_network.py DEFAULT_CHAIN_ID).
        assert_eq!(cfg.chain.chain_id, 70860602);
        assert_eq!(cfg.oracle.vote_period, 8);
        // COEN/840 is the only pair the chain registers; the decorative
        // XAU/BTC/ETH/stablecoin entries were dropped because no code read them
        // and they name assets with no on-chain address.
        assert_eq!(cfg.currency_pairs.len(), 1);
        assert_eq!(cfg.currency_pairs[0].base, "rudis");
        assert_eq!(cfg.currency_pairs[0].quote, "840");
        assert!(cfg
            .currency_pairs
            .iter()
            .all(|pair| { pair.sources == vec![source("mock_http", "COEN", "840")] }));
        assert!(cfg.validate().is_ok());
    }
}
