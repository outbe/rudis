use alloy_primitives::{
    aliases::{I24, U24},
    keccak256, B256, U256, U512,
};
use alloy_sol_types::{SolEvent, SolValue};
use eyre::{ensure, Result};

use super::{
    abi::*,
    config::{DexMarketConfig, PoolConfig},
    math,
    rpc::{Block, Log, Rpc},
};
use crate::fixed::FixedValue;

#[derive(Clone, Copy)]
pub(super) struct Decimals {
    pub base: u8,
    pub quote: u8,
}

impl PoolConfig {
    pub fn pool_id(&self, market: &DexMarketConfig) -> Result<Option<B256>> {
        let (currency0, currency1) = market.tokens();
        Ok(match *self {
            Self::UniswapV4 {
                fee,
                tick_spacing,
                hooks,
                ..
            } => Some(keccak256(
                UniPoolKey {
                    currency0,
                    currency1,
                    fee: U24::try_from(fee)?,
                    tickSpacing: I24::try_from(tick_spacing)?,
                    hooks,
                }
                .abi_encode(),
            )),
            Self::InfinityCl {
                manager,
                fee,
                hooks,
                parameters,
            }
            | Self::InfinityBin {
                manager,
                fee,
                hooks,
                parameters,
            } => Some(keccak256(
                InfinityPoolKey {
                    currency0,
                    currency1,
                    hooks,
                    poolManager: manager,
                    fee: U24::try_from(fee)?,
                    parameters,
                }
                .abi_encode(),
            )),
            _ => None,
        })
    }

    pub fn swap_topic(&self) -> B256 {
        match self {
            Self::UniswapV2 { .. } | Self::PancakeswapV2 { .. } => Pair::Swap::SIGNATURE_HASH,
            Self::UniswapV3 { .. } => UniV3::Swap::SIGNATURE_HASH,
            Self::PancakeswapV3 { .. } => PancakeV3::Swap::SIGNATURE_HASH,
            Self::UniswapV4 { .. } => UniV4::Swap::SIGNATURE_HASH,
            Self::InfinityCl { .. } => InfinityCl::Swap::SIGNATURE_HASH,
            Self::InfinityBin { .. } => InfinityBin::Swap::SIGNATURE_HASH,
        }
    }
}

impl DexMarketConfig {
    pub async fn read_decimals(&self, rpc: &Rpc, block: &Block) -> Result<Decimals> {
        match self.pool {
            PoolConfig::UniswapV4 {
                manager,
                state_view,
                ..
            } => {
                ensure!(
                    rpc.call(state_view, StateView::poolManagerCall {}, block)
                        .await?
                        == manager,
                    "StateView belongs to a different PoolManager"
                );
            }
            PoolConfig::InfinityCl { .. } | PoolConfig::InfinityBin { .. } => {}
            _ => {
                let address = self.pool.address();
                let token0 = rpc.call(address, Pair::token0Call {}, block).await?;
                let token1 = rpc.call(address, Pair::token1Call {}, block).await?;
                ensure!(
                    (token0, token1) == self.tokens(),
                    "configured DEX tokens do not match pool"
                );
            }
        }
        let base = rpc
            .call(self.base_token, Token::decimalsCall {}, block)
            .await?;
        let quote = rpc
            .call(self.quote_token, Token::decimalsCall {}, block)
            .await?;
        ensure!(
            base <= 77 && quote <= 77,
            "unsupported DEX token decimals (>77)"
        );
        Ok(Decimals { base, quote })
    }

    pub async fn read_rate(
        &self,
        rpc: &Rpc,
        block: &Block,
        decimals: Decimals,
    ) -> Result<FixedValue> {
        let id = self.pool.pool_id(self)?.unwrap_or_default();
        let (numerator, denominator) = match self.pool {
            PoolConfig::UniswapV2 { address } | PoolConfig::PancakeswapV2 { address } => {
                let state = rpc.call(address, Pair::getReservesCall {}, block).await?;
                (U512::from(state.reserve1), U512::from(state.reserve0))
            }
            PoolConfig::UniswapV3 { address } => {
                let state = rpc.call(address, UniV3::slot0Call {}, block).await?;
                sqrt_ratio(U256::from(state.sqrtPriceX96))
            }
            PoolConfig::PancakeswapV3 { address } => {
                let state = rpc.call(address, PancakeV3::slot0Call {}, block).await?;
                sqrt_ratio(U256::from(state.sqrtPriceX96))
            }
            PoolConfig::UniswapV4 { state_view, .. } => {
                let state = rpc
                    .call(state_view, StateView::getSlot0Call { poolId: id }, block)
                    .await?;
                sqrt_ratio(U256::from(state.sqrtPriceX96))
            }
            PoolConfig::InfinityCl { manager, .. } => {
                let state = rpc
                    .call(manager, InfinityCl::getSlot0Call { poolId: id }, block)
                    .await?;
                sqrt_ratio(U256::from(state.sqrtPriceX96))
            }
            PoolConfig::InfinityBin { manager, .. } => {
                let state = rpc
                    .call(manager, InfinityBin::getSlot0Call { poolId: id }, block)
                    .await?;
                // activeId is uint24, so conversion to u32 is lossless.
                (
                    U512::from(math::bin_price(
                        state.activeId.to::<u32>(),
                        self.pool.bin_step(),
                    )?),
                    U512::ONE << 128,
                )
            }
        };
        let (n, d) = if self.base_is_token0() {
            (numerator, denominator)
        } else {
            (denominator, numerator)
        };
        math::rate(n, d, decimals.base, decimals.quote)
    }

    pub fn log_topics(&self) -> Result<Vec<B256>> {
        let mut topics = vec![self.pool.swap_topic()];
        if let Some(id) = self.pool.pool_id(self)? {
            topics.push(id);
        }
        Ok(topics)
    }

    /// Absolute base-token balance delta once per core Swap event. A V2 flash
    /// swap can have both input/output: use its net delta, not double turnover.
    pub fn swap_volume(&self, log: &Log) -> Result<U256> {
        ensure!(
            !log.removed && log.address == self.pool.address(),
            "invalid DEX log address/removal flag"
        );
        ensure!(
            log.topics.len() == 3 && log.topics[0] == self.pool.swap_topic(),
            "invalid DEX Swap topics"
        );
        if let Some(id) = self.pool.pool_id(self)? {
            ensure!(log.topics[1] == id, "DEX Swap belongs to another pool");
        }
        let base0 = self.base_is_token0();
        let amount = match self.pool {
            PoolConfig::UniswapV2 { .. } | PoolConfig::PancakeswapV2 { .. } => {
                let e = Pair::Swap::decode_raw_log_validate(log.topics.iter().copied(), &log.data)?;
                let (input, output) = if base0 {
                    (e.amount0In, e.amount0Out)
                } else {
                    (e.amount1In, e.amount1Out)
                };
                input.abs_diff(output)
            }
            PoolConfig::UniswapV3 { .. } => {
                let e =
                    UniV3::Swap::decode_raw_log_validate(log.topics.iter().copied(), &log.data)?;
                if base0 {
                    e.amount0.unsigned_abs()
                } else {
                    e.amount1.unsigned_abs()
                }
            }
            PoolConfig::PancakeswapV3 { .. } => {
                let e = PancakeV3::Swap::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )?;
                if base0 {
                    e.amount0.unsigned_abs()
                } else {
                    e.amount1.unsigned_abs()
                }
            }
            PoolConfig::UniswapV4 { .. } => {
                let e =
                    UniV4::Swap::decode_raw_log_validate(log.topics.iter().copied(), &log.data)?;
                U256::from(if base0 {
                    e.amount0.unsigned_abs()
                } else {
                    e.amount1.unsigned_abs()
                })
            }
            PoolConfig::InfinityCl { .. } => {
                let e = InfinityCl::Swap::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )?;
                U256::from(if base0 {
                    e.amount0.unsigned_abs()
                } else {
                    e.amount1.unsigned_abs()
                })
            }
            PoolConfig::InfinityBin { .. } => {
                let e = InfinityBin::Swap::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )?;
                U256::from(if base0 {
                    e.amount0.unsigned_abs()
                } else {
                    e.amount1.unsigned_abs()
                })
            }
        };
        Ok(amount)
    }
}

fn sqrt_ratio(sqrt: U256) -> (U512, U512) {
    // sqrt is decoded from uint160; its square fits in 320 bits.
    (U512::from(sqrt) * U512::from(sqrt), U512::ONE << 192)
}
