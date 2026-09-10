//! Narrow RPC capability required by finalized TEE lifecycle workflows.

use std::future::Future;

use alloy_primitives::{Address, U256};
use eyre::{Result, WrapErr as _};
use outbe_primitives::tee_operator_v1::TeeRenewalScheduleV1;
use serde_json::Value;

pub trait FinalityRpc {
    fn transaction_receipt(
        &self,
        transaction_hash: &str,
    ) -> impl Future<Output = Result<Option<Value>>> + Send;

    fn logs(
        &self,
        address: Address,
        topics: &[Option<String>],
        from_block: &str,
        to_block: &str,
    ) -> impl Future<Output = Result<Vec<Value>>> + Send;

    fn block_by_number(&self, block: u64) -> impl Future<Output = Result<Value>> + Send;

    fn finalized_block(&self) -> impl Future<Output = Result<Value>> + Send;

    fn call_at(
        &self,
        to: Address,
        data: &[u8],
        block_tag: &str,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

/// RPC surface shared by manual and daemon renewal. Every Registry read is
/// performed with [`FinalityRpc::call_at`] at the height returned by the exact
/// finalized schedule; latest/pending state is used only for relay transport.
pub trait RenewalRpc: FinalityRpc {
    fn chain_id(&self) -> impl Future<Output = Result<u64>> + Send;
    fn gas_price(&self) -> impl Future<Output = Result<U256>> + Send;
    fn transaction_count(&self, address: Address) -> impl Future<Output = Result<u64>> + Send;
    fn balance(&self, address: Address) -> impl Future<Output = Result<U256>> + Send;
    fn send_raw_transaction(
        &self,
        raw_transaction: &[u8],
    ) -> impl Future<Output = Result<String>> + Send;
    fn tee_renewal_schedule_v1(&self) -> impl Future<Output = Result<TeeRenewalScheduleV1>> + Send;
}

/// Small reusable HTTP JSON-RPC transport for node-owned lifecycle workers.
pub struct HttpRenewalRpc {
    url: String,
    client: reqwest::Client,
    id: std::sync::atomic::AtomicU64,
}

impl HttpRenewalRpc {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
            id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let response: Value = self
            .client
            .post(&self.url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": id,
            }))
            .send()
            .await
            .wrap_err_with(|| format!("send {method} RPC request"))?
            .error_for_status()
            .wrap_err_with(|| format!("{method} RPC HTTP status"))?
            .json()
            .await
            .wrap_err_with(|| format!("decode {method} RPC response"))?;
        if response.get("id") != Some(&Value::from(id)) {
            eyre::bail!("{method} RPC response id mismatch");
        }
        if let Some(error) = response.get("error") {
            eyre::bail!("{method} RPC error: {error}");
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| eyre::eyre!("{method} RPC response has no result"))
    }

    async fn optional(&self, method: &str, params: Value) -> Result<Option<Value>> {
        let value = self.call(method, params).await?;
        Ok((!value.is_null()).then_some(value))
    }
}

impl FinalityRpc for HttpRenewalRpc {
    async fn transaction_receipt(&self, transaction_hash: &str) -> Result<Option<Value>> {
        self.optional(
            "eth_getTransactionReceipt",
            serde_json::json!([transaction_hash]),
        )
        .await
    }

    async fn logs(
        &self,
        address: Address,
        topics: &[Option<String>],
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<Value>> {
        serde_json::from_value(
            self.call(
                "eth_getLogs",
                serde_json::json!([{
                    "address": format!("{address:#x}"),
                    "topics": topics,
                    "fromBlock": from_block,
                    "toBlock": to_block,
                }]),
            )
            .await?,
        )
        .wrap_err("decode eth_getLogs result")
    }

    async fn block_by_number(&self, block: u64) -> Result<Value> {
        self.call(
            "eth_getBlockByNumber",
            serde_json::json!([format!("0x{block:x}"), false]),
        )
        .await
    }

    async fn finalized_block(&self) -> Result<Value> {
        self.call(
            "eth_getBlockByNumber",
            serde_json::json!(["finalized", false]),
        )
        .await
    }

    async fn call_at(&self, to: Address, data: &[u8], block_tag: &str) -> Result<Vec<u8>> {
        let value = self
            .call(
                "eth_call",
                serde_json::json!([{
                    "to": format!("{to:#x}"),
                    "data": format!("0x{}", hex::encode(data)),
                }, block_tag]),
            )
            .await?;
        decode_hex_bytes(&value, "eth_call")
    }
}

impl RenewalRpc for HttpRenewalRpc {
    async fn chain_id(&self) -> Result<u64> {
        parse_hex_u64(
            &self.call("eth_chainId", serde_json::json!([])).await?,
            "eth_chainId",
        )
    }

    async fn gas_price(&self) -> Result<U256> {
        parse_hex_u256(
            &self.call("eth_gasPrice", serde_json::json!([])).await?,
            "eth_gasPrice",
        )
    }

    async fn transaction_count(&self, address: Address) -> Result<u64> {
        parse_hex_u64(
            &self
                .call(
                    "eth_getTransactionCount",
                    serde_json::json!([format!("{address:#x}"), "pending"]),
                )
                .await?,
            "eth_getTransactionCount",
        )
    }

    async fn balance(&self, address: Address) -> Result<U256> {
        parse_hex_u256(
            &self
                .call(
                    "eth_getBalance",
                    serde_json::json!([format!("{address:#x}"), "latest"]),
                )
                .await?,
            "eth_getBalance",
        )
    }

    async fn send_raw_transaction(&self, raw_transaction: &[u8]) -> Result<String> {
        self.call(
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(raw_transaction))]),
        )
        .await?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| eyre::eyre!("eth_sendRawTransaction returned a non-string"))
    }

    async fn tee_renewal_schedule_v1(&self) -> Result<TeeRenewalScheduleV1> {
        serde_json::from_value(
            self.call("rudis_teeRenewalScheduleV1", serde_json::json!([]))
                .await?,
        )
        .wrap_err("decode rudis_teeRenewalScheduleV1 result")
        .and_then(|schedule: TeeRenewalScheduleV1| schedule.validate().map_err(eyre::Report::msg))
    }
}

fn parse_hex_u64(value: &Value, method: &str) -> Result<u64> {
    let encoded = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("{method} returned a non-string"))?;
    u64::from_str_radix(encoded.strip_prefix("0x").unwrap_or(encoded), 16)
        .wrap_err_with(|| format!("parse {method} result"))
}

fn parse_hex_u256(value: &Value, method: &str) -> Result<U256> {
    let encoded = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("{method} returned a non-string"))?;
    U256::from_str_radix(encoded.strip_prefix("0x").unwrap_or(encoded), 16)
        .map_err(|error| eyre::eyre!("parse {method} result: {error}"))
}

fn decode_hex_bytes(value: &Value, method: &str) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .ok_or_else(|| eyre::eyre!("{method} returned a non-string"))?;
    hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded))
        .wrap_err_with(|| format!("decode {method} bytes"))
}
