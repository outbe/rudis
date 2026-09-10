use alloy_primitives::U256;
use async_trait::async_trait;
use eyre::{ensure, eyre, Result};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::RwLock, task::JoinHandle, time::Instant};

use super::{
    config::{DexMarketConfig, DexProviderConfig},
    math,
    pool::Decimals,
    rpc::{quantity, Block, Rpc},
};
use crate::provider::{Provider, TickerPrice};

const WINDOW_SECS: u64 = 86_400;
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

struct Snapshot {
    ticker: TickerPrice,
    block_timestamp: u64,
    acquired_at: Instant,
}

pub(crate) struct DexProvider {
    name: String,
    markets: HashMap<String, Arc<RwLock<Option<Snapshot>>>>,
    tasks: Vec<JoinHandle<()>>,
    max_finalized_age_secs: u64,
}

impl DexProvider {
    pub fn new(config: &DexProviderConfig) -> Result<Self> {
        config.validate()?;
        let runtime = tokio::runtime::Handle::try_current()?;
        let rpc = Rpc::new(&config.rpc_endpoint)?;
        let mut markets = HashMap::new();
        let mut tasks = Vec::new();
        for market in &config.markets {
            let state = Arc::new(RwLock::new(None));
            markets.insert(market.key(), Arc::clone(&state));
            let mut worker = MarketWorker::new(config.clone(), market.clone(), rpc.clone());
            tasks.push(runtime.spawn(async move {
                tracing::info!(provider = %worker.config.name, market = %worker.market.key(), "DEX source warming up");
                loop {
                    let acquired_at = Instant::now();
                    match worker.refresh().await {
                        Ok((block, ticker)) => {
                            tracing::debug!(provider = %worker.config.name, market = %worker.market.key(),
                                block = block.number, hash = %block.hash, "DEX finalized snapshot ready");
                            *state.write().await = Some(Snapshot { ticker, block_timestamp: block.timestamp, acquired_at });
                        }
                        Err(error) => {
                            *state.write().await = None;
                            tracing::warn!(provider = %worker.config.name, market = %worker.market.key(),
                                error = %error, "DEX source unavailable; retrying");
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(worker.config.poll_interval_secs)).await;
                }
            }));
        }
        Ok(Self {
            name: config.name.clone(),
            markets,
            tasks,
            max_finalized_age_secs: config.max_finalized_age_secs,
        })
    }
}

impl Drop for DexProvider {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[async_trait]
impl Provider for DexProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn get_ticker_prices(
        &self,
        pairs: &[(String, String)],
    ) -> Result<HashMap<String, TickerPrice>> {
        let mut tickers = HashMap::new();
        for (base, quote) in pairs {
            let key = format!("{base}/{quote}");
            if let Some(state) = self.markets.get(&key) {
                if let Some(snapshot) = state.read().await.as_ref() {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                    if snapshot.acquired_at.elapsed() <= SNAPSHOT_TTL
                        && now.saturating_sub(snapshot.block_timestamp)
                            <= self.max_finalized_age_secs
                    {
                        tickers.insert(key, snapshot.ticker.clone());
                    }
                }
            }
        }
        Ok(tickers)
    }
}

pub(super) struct MarketWorker {
    config: DexProviderConfig,
    market: DexMarketConfig,
    rpc: Rpc,
    decimals: Option<Decimals>,
    /// Last completely validated log range, even during startup backfill.
    cursor: Option<Block>,
    /// Per-block raw base volume: bounded by the rolling window, not swap count.
    volumes: BTreeMap<u64, (u64, U256)>,
}

impl MarketWorker {
    pub fn new(config: DexProviderConfig, market: DexMarketConfig, rpc: Rpc) -> Self {
        Self {
            config,
            market,
            rpc,
            decimals: None,
            cursor: None,
            volumes: BTreeMap::new(),
        }
    }

    pub async fn refresh(&mut self) -> Result<(Block, TickerPrice)> {
        ensure!(
            self.rpc.chain_id().await? == self.config.chain_id,
            "DEX RPC chain ID mismatch"
        );
        let head = self.rpc.block("finalized").await?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            head.timestamp <= now.saturating_add(30)
                && now.saturating_sub(head.timestamp) <= self.config.max_finalized_age_secs,
            "DEX finalized block is stale or in the future"
        );
        if let Some(cursor) = &self.cursor {
            let canonical = self.rpc.block_at(cursor.number).await?;
            if canonical != *cursor || head.number < cursor.number {
                self.cursor = None;
                self.volumes.clear();
                self.decimals = None;
                return Err(eyre!("DEX finalized history changed; rebuilding volume"));
            }
        }
        let decimals = match self.decimals {
            Some(decimals) => decimals,
            None => {
                let decimals = self.market.read_decimals(&self.rpc, &head).await?;
                self.decimals = Some(decimals);
                decimals
            }
        };
        // Validate initialization before doing a potentially long log backfill.
        let price = self.market.read_rate(&self.rpc, &head, decimals).await?;
        self.collect_volume(&head).await?;
        ensure!(
            self.rpc.block_at(head.number).await? == head,
            "DEX finalized block changed during collection"
        );
        let cutoff = head.timestamp.saturating_sub(WINDOW_SECS);
        self.volumes.retain(|_, (timestamp, _)| *timestamp > cutoff);
        let raw = self
            .volumes
            .values()
            .try_fold(U256::ZERO, |sum, (_, amount)| {
                sum.checked_add(*amount)
                    .ok_or_else(|| eyre!("DEX rolling volume overflow"))
            })?;
        Ok((
            head,
            TickerPrice {
                price,
                volume: math::base_volume(raw, decimals.base)?,
            },
        ))
    }

    async fn collect_volume(&mut self, head: &Block) -> Result<()> {
        let cutoff = head.timestamp.saturating_sub(WINDOW_SECS);
        let mut from = if let Some(cursor) = &self.cursor {
            if cursor.number == head.number {
                return Ok(());
            }
            cursor
                .number
                .checked_add(1)
                .ok_or_else(|| eyre!("DEX block number overflow"))?
        } else {
            self.rpc.first_after(cutoff, head).await?
        };
        let topics = self.market.log_topics()?;
        let mut chunk_size = self.config.log_chunk_blocks;
        while from <= head.number {
            let to = from.saturating_add(chunk_size - 1).min(head.number);
            let logs = match self
                .rpc
                .logs(self.market.pool.address(), &topics, from, to)
                .await
            {
                Ok(logs) => logs,
                Err(_) if chunk_size > 1 => {
                    chunk_size = (chunk_size / 2).max(1);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut seen = BTreeMap::new();
            let mut buckets: BTreeMap<u64, (u64, U256)> = BTreeMap::new();
            let mut blocks: BTreeMap<u64, Block> = BTreeMap::new();
            let end = self.rpc.block_at(to).await?;
            ensure!(
                end.timestamp <= head.timestamp,
                "DEX log range extends past finalized time"
            );
            blocks.insert(to, end.clone());
            for log in logs {
                let number = quantity(&log.block_number)?;
                let index = quantity(&log.log_index)?;
                ensure!(
                    (from..=to).contains(&number),
                    "DEX log outside requested range"
                );
                let amount = self.market.swap_volume(&log)?;
                // A block's log index is globally unique, including singleton
                // managers. Identical duplicates are harmless; conflicts fail.
                let identity = (log.block_hash, index);
                let value = (log.transaction_hash, log.data.clone(), log.topics.clone());
                if let Some(previous) = seen.insert(identity, value.clone()) {
                    ensure!(previous == value, "conflicting duplicate DEX log");
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(entry) = blocks.entry(number) {
                    entry.insert(self.rpc.block_at(number).await?);
                }
                let block = blocks
                    .get(&number)
                    .ok_or_else(|| eyre!("missing DEX log block"))?;
                ensure!(
                    block.hash == log.block_hash && block.timestamp <= head.timestamp,
                    "DEX log is not in the canonical finalized history"
                );
                let bucket = buckets
                    .entry(number)
                    .or_insert((block.timestamp, U256::ZERO));
                bucket.1 = bucket
                    .1
                    .checked_add(amount)
                    .ok_or_else(|| eyre!("DEX block volume overflow"))?;
            }
            // Commit only after validating the entire chunk. Retried requests
            // never append a partially processed chunk or count its logs twice.
            self.volumes.extend(buckets);
            self.volumes.retain(|_, (timestamp, _)| *timestamp > cutoff);
            self.cursor = Some(end);
            if to == head.number {
                break;
            }
            from = to + 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::FixedValue;

    #[tokio::test]
    async fn ticker_cache_expires_from_acquisition_and_finalized_block_time() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let state = Arc::new(RwLock::new(Some(Snapshot {
            ticker: TickerPrice {
                price: FixedValue::parse("1").unwrap(),
                volume: FixedValue::ZERO,
            },
            block_timestamp: now,
            acquired_at: Instant::now(),
        })));
        let provider = DexProvider {
            name: "uniswap".into(),
            markets: HashMap::from([("COEN/USDC".into(), state.clone())]),
            tasks: vec![],
            max_finalized_age_secs: 1800,
        };
        let pairs = [("COEN".into(), "USDC".into())];
        assert_eq!(provider.get_ticker_prices(&pairs).await.unwrap().len(), 1);
        state.write().await.as_mut().unwrap().acquired_at =
            Instant::now() - Duration::from_secs(31);
        assert!(provider.get_ticker_prices(&pairs).await.unwrap().is_empty());
        {
            let mut guard = state.write().await;
            let snapshot = guard.as_mut().unwrap();
            snapshot.acquired_at = Instant::now();
            snapshot.block_timestamp = now - 1801;
        }
        assert!(provider.get_ticker_prices(&pairs).await.unwrap().is_empty());
    }
}
