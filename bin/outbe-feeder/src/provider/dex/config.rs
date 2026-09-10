use alloy_primitives::{Address, B256};
use eyre::{ensure, Result};
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::config::FeederConfig;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DexProviderConfig {
    pub name: String,
    pub chain_id: u64,
    pub rpc_endpoint: String,
    #[serde(default = "poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default = "log_chunk")]
    pub log_chunk_blocks: u64,
    /// Wall-clock age of the finalized block, including normal finality delay.
    #[serde(default = "finalized_age")]
    pub max_finalized_age_secs: u64,
    pub(super) markets: Vec<DexMarketConfig>,
}

fn poll_interval() -> u64 {
    2
}
fn log_chunk() -> u64 {
    2_000
}
fn finalized_age() -> u64 {
    1_800
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DexMarketConfig {
    pub base: String,
    pub quote: String,
    pub base_token: Address,
    pub quote_token: Address,
    pub pool: PoolConfig,
}

/// Each variant has its own ABI. Manager pool keys include both token addresses
/// from the enclosing market, sorted in the protocol's currency0/currency1 order.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PoolConfig {
    UniswapV2 {
        address: Address,
    },
    PancakeswapV2 {
        address: Address,
    },
    UniswapV3 {
        address: Address,
    },
    PancakeswapV3 {
        address: Address,
    },
    UniswapV4 {
        manager: Address,
        state_view: Address,
        fee: u32,
        tick_spacing: i32,
        hooks: Address,
    },
    InfinityCl {
        manager: Address,
        fee: u32,
        hooks: Address,
        parameters: B256,
    },
    InfinityBin {
        manager: Address,
        fee: u32,
        hooks: Address,
        parameters: B256,
    },
}

impl DexMarketConfig {
    pub fn key(&self) -> String {
        format!("{}/{}", self.base, self.quote)
    }

    pub fn base_is_token0(&self) -> bool {
        self.base_token < self.quote_token
    }

    pub fn tokens(&self) -> (Address, Address) {
        if self.base_is_token0() {
            (self.base_token, self.quote_token)
        } else {
            (self.quote_token, self.base_token)
        }
    }
}

impl DexProviderConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                (self.name.as_str(), self.chain_id),
                ("uniswap", 1) | ("pancakeswap", 56)
            ),
            "DEX v1 requires uniswap on chain 1 or pancakeswap on chain 56"
        );
        let url = reqwest::Url::parse(&self.rpc_endpoint)
            .map_err(|_| eyre::eyre!("invalid DEX RPC URL"))?;
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "DEX RPC requires HTTP(S)"
        );
        ensure!(
            (1..=10).contains(&self.poll_interval_secs),
            "DEX poll_interval_secs must be 1..=10"
        );
        ensure!(
            (1..=10_000).contains(&self.log_chunk_blocks),
            "DEX log_chunk_blocks must be 1..=10000"
        );
        ensure!(
            self.max_finalized_age_secs > 0,
            "DEX max_finalized_age_secs must be positive"
        );
        ensure!(!self.markets.is_empty(), "DEX provider has no markets");
        let mut markets = BTreeSet::new();
        let mut pools = BTreeSet::new();
        for market in &self.markets {
            ensure!(
                market.base == "COEN" && matches!(market.quote.as_str(), "USDC" | "USDT"),
                "DEX v1 supports COEN/USDC and COEN/USDT"
            );
            ensure!(
                !market.base_token.is_zero()
                    && !market.quote_token.is_zero()
                    && market.base_token != market.quote_token,
                "DEX requires two distinct ERC20 addresses"
            );
            ensure!(
                markets.insert(market.key()),
                "duplicate DEX market {}",
                market.key()
            );
            market.pool.validate(&self.name)?;
            let id = market.pool.pool_id(market)?;
            ensure!(
                pools.insert((market.pool.address(), id)),
                "DEX pool configured more than once"
            );
        }
        Ok(())
    }
}

impl PoolConfig {
    pub fn address(&self) -> Address {
        match *self {
            Self::UniswapV2 { address }
            | Self::PancakeswapV2 { address }
            | Self::UniswapV3 { address }
            | Self::PancakeswapV3 { address } => address,
            Self::UniswapV4 { manager, .. }
            | Self::InfinityCl { manager, .. }
            | Self::InfinityBin { manager, .. } => manager,
        }
    }

    fn validate(&self, provider: &str) -> Result<()> {
        ensure!(
            !self.address().is_zero(),
            "DEX pool/manager address must be nonzero"
        );
        let uniswap = matches!(
            self,
            Self::UniswapV2 { .. } | Self::UniswapV3 { .. } | Self::UniswapV4 { .. }
        );
        ensure!(
            uniswap == (provider == "uniswap"),
            "DEX protocol does not match provider"
        );
        match *self {
            Self::UniswapV4 {
                state_view,
                fee,
                tick_spacing,
                ..
            } => {
                ensure!(!state_view.is_zero(), "Uniswap V4 requires StateView");
                ensure!(
                    (1..=32_767).contains(&tick_spacing),
                    "invalid V4 tick spacing"
                );
                validate_fee(fee)?;
            }
            Self::InfinityCl {
                fee, parameters, ..
            } => {
                validate_fee(fee)?;
                let value = alloy_primitives::U256::from_be_bytes(parameters.0);
                let spacing = (value >> 16) & alloy_primitives::U256::from(0xff_ffffu32);
                ensure!(
                    value >> 40 == alloy_primitives::U256::ZERO
                        && spacing > alloy_primitives::U256::ZERO
                        && spacing <= alloy_primitives::U256::from(32_767u32),
                    "invalid Infinity CL parameters"
                );
            }
            Self::InfinityBin {
                fee, parameters, ..
            } => {
                validate_fee(fee)?;
                let value = alloy_primitives::U256::from_be_bytes(parameters.0);
                ensure!(
                    value >> 32 == alloy_primitives::U256::ZERO && self.bin_step() > 0,
                    "invalid Infinity Bin parameters"
                );
            }
            _ => {}
        }
        Ok(())
    }

    pub fn bin_step(&self) -> u16 {
        match self {
            Self::InfinityBin { parameters, .. } => {
                u16::from_be_bytes([parameters[28], parameters[29]])
            }
            _ => 0,
        }
    }
}

fn validate_fee(fee: u32) -> Result<()> {
    ensure!(fee <= 1_000_000 || fee == 0x80_0000, "invalid pool fee");
    Ok(())
}

pub(crate) fn validate_config(config: &FeederConfig) -> Result<()> {
    let mut names = BTreeSet::new();
    for dex in &config.dex_providers {
        dex.validate()?;
        ensure!(
            names.insert(dex.name.as_str()),
            "duplicate DEX provider {}",
            dex.name
        );
        ensure!(
            !config.provider_endpoints.iter().any(|e| e.name == dex.name),
            "configure DEX RPC in dex_providers, not provider_endpoints"
        );
    }
    for pair in &config.currency_pairs {
        for source in &pair.sources {
            if !matches!(source.provider.as_str(), "uniswap" | "pancakeswap") {
                continue;
            }
            ensure!(
                pair.oracle_pair()?
                    == (
                        Address::ZERO,
                        outbe_primitives::asset_type::AssetType::IsoCurrency(840).into()
                    ),
                "DEX v1 sources must feed rudis/840 (USD parity assumption)"
            );
            let dex = config
                .dex_providers
                .iter()
                .find(|d| d.name == source.provider)
                .ok_or_else(|| eyre::eyre!("missing DEX configuration for {}", source.provider))?;
            ensure!(
                dex.markets
                    .iter()
                    .any(|m| m.base == source.base && m.quote == source.quote),
                "missing DEX market {}/{}",
                source.base,
                source.quote
            );
        }
    }
    Ok(())
}
