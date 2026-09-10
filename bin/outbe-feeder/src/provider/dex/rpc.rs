use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::SolCall;
use eyre::{ensure, eyre, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Clone)]
pub(super) struct Rpc {
    client: reqwest::Client,
    endpoint: String,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Block {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: String,
    pub block_hash: B256,
    pub transaction_hash: B256,
    pub log_index: String,
    pub removed: bool,
}

impl Rpc {
    pub fn new(endpoint: &str) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            endpoint: endpoint.to_owned(),
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // RPC URLs may contain credentials. Never include them in errors/logs.
        let mut response = self
            .client
            .post(&self.endpoint)
            .json(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .send()
            .await
            .map_err(reqwest::Error::without_url)?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= 16 * 1024 * 1024,
                "DEX RPC response exceeds 16 MiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value.get("id") == Some(&json!(id)) && value.get("jsonrpc") == Some(&json!("2.0")),
            "invalid DEX RPC response envelope"
        );
        if let Some(error) = value.get("error") {
            return Err(eyre!(
                "DEX RPC {method} error code {:?}",
                error.get("code").and_then(Value::as_i64)
            ));
        }
        value
            .get("result")
            .filter(|v| !v.is_null())
            .cloned()
            .ok_or_else(|| eyre!("DEX RPC {method} returned no result"))
    }

    pub async fn chain_id(&self) -> Result<u64> {
        quantity_value(&self.request("eth_chainId", json!([])).await?)
    }

    pub async fn block(&self, tag: &str) -> Result<Block> {
        let value = self
            .request("eth_getBlockByNumber", json!([tag, false]))
            .await?;
        Ok(Block {
            number: quantity_value(&value["number"])?,
            hash: serde_json::from_value(value["hash"].clone())?,
            timestamp: quantity_value(&value["timestamp"])?,
        })
    }

    pub async fn block_at(&self, number: u64) -> Result<Block> {
        let block = self.block(&format!("0x{number:x}")).await?;
        ensure!(
            block.number == number,
            "DEX RPC returned wrong block number"
        );
        Ok(block)
    }

    pub async fn call<C: SolCall>(
        &self,
        address: Address,
        call: C,
        block: &Block,
    ) -> Result<C::Return> {
        // EIP-1898 pins all state reads to one canonical finalized block hash.
        let value = self
            .request(
                "eth_call",
                json!([
                    {"to":address, "data":Bytes::from(call.abi_encode())},
                    {"blockHash":block.hash, "requireCanonical":true}
                ]),
            )
            .await?;
        let bytes: Bytes = serde_json::from_value(value)?;
        Ok(C::abi_decode_returns_validate(&bytes)?)
    }

    pub async fn logs(
        &self,
        address: Address,
        topics: &[B256],
        from: u64,
        to: u64,
    ) -> Result<Vec<Log>> {
        let value = self
            .request(
                "eth_getLogs",
                json!([{
                    "address":address, "topics":topics,
                    "fromBlock":format!("0x{from:x}"), "toBlock":format!("0x{to:x}")
                }]),
            )
            .await?;
        Ok(serde_json::from_value(value)?)
    }

    /// First block strictly newer than the rolling-window cutoff.
    pub async fn first_after(&self, cutoff: u64, head: &Block) -> Result<u64> {
        let mut low = 0;
        let mut high = head.number;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.block_at(middle).await?.timestamp <= cutoff {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        Ok(low)
    }
}

pub(super) fn quantity(text: &str) -> Result<u64> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| eyre!("invalid RPC quantity prefix"))?;
    Ok(u64::from_str_radix(digits, 16)?)
}

fn quantity_value(value: &Value) -> Result<u64> {
    quantity(
        value
            .as_str()
            .ok_or_else(|| eyre!("missing RPC quantity"))?,
    )
}
