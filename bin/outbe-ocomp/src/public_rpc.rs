//! Bounded blocking JSON-RPC transport for the standalone OCOMP service.
//!
//! Job discovery reads the node's finalized state, while purpose-bound input
//! RPCs return exact request-state material that the caller checks against its
//! durable finalized `JobIntent` binding.

use std::{
    io::Read as _,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use alloy_primitives::{Address, Bytes, LogData, B256};
use alloy_sol_types::SolCall as _;
use outbe_metadosis::precompile::IMetadosis;
use serde_json::{json, Value};
use thiserror::Error;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedRpcBlockV1 {
    pub number: u64,
    pub hash: B256,
    pub state_root: B256,
}

pub struct PublicOcompRpcClientV1 {
    url: String,
    client: reqwest::blocking::Client,
    next_id: AtomicU64,
    max_response_bytes: usize,
}

impl PublicOcompRpcClientV1 {
    pub fn new(url: impl Into<String>, max_response_bytes: usize) -> Result<Self, PublicRpcError> {
        if max_response_bytes == 0 {
            return Err(PublicRpcError::InvalidResponseLimit);
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|error| PublicRpcError::Transport(error.to_string()))?;
        Ok(Self {
            url: url.into(),
            client,
            next_id: AtomicU64::new(1),
            max_response_bytes,
        })
    }

    pub fn finalized_block(&self) -> Result<FinalizedRpcBlockV1, PublicRpcError> {
        parse_block(self.call("eth_getBlockByNumber", json!(["finalized", false]))?)
    }

    pub fn block_by_number(&self, number: u64) -> Result<FinalizedRpcBlockV1, PublicRpcError> {
        parse_block(self.call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )?)
    }

    /// Reads and strictly normalizes every receipt of one exact finalized
    /// block for the backend-neutral off-chain projector.
    pub fn finalized_block_receipts(
        &self,
        number: u64,
    ) -> Result<outbe_offchain_data::FinalizedBlock, PublicRpcError> {
        let block = self.block_by_number(number)?;
        let value = self.call("eth_getBlockReceipts", json!([format!("0x{number:x}")]))?;
        normalize_block_receipts(block, value)
    }

    pub fn job_record_at_hash(
        &self,
        intent_id: B256,
        block_hash: B256,
    ) -> Result<Vec<u8>, PublicRpcError> {
        self.job_record_at_tag(intent_id, exact_block_hash_tag(block_hash))
    }

    pub fn lysis_openings(
        &self,
        intent_id: B256,
        canonical_request: &[u8],
    ) -> Result<Vec<u8>, PublicRpcError> {
        let value = self.call(
            "rudis_getOcompLysisOpeningsV1",
            json!([
                format!("{intent_id:#x}"),
                format!("0x{}", hex::encode(canonical_request))
            ]),
        )?;
        parse_hex_bytes(&value, "rudis_getOcompLysisOpeningsV1")
    }

    fn job_record_at_tag(
        &self,
        intent_id: B256,
        block_tag: Value,
    ) -> Result<Vec<u8>, PublicRpcError> {
        let call = IMetadosis::getOffchainJobCall {
            intentId: intent_id,
        };
        let raw = self.call(
            "eth_call",
            json!([{
                "to": format!("{:#x}", outbe_primitives::addresses::METADOSIS_ADDRESS),
                "data": format!("0x{}", hex::encode(call.abi_encode())),
            }, block_tag]),
        )?;
        let raw = parse_hex_bytes(&raw, "eth_call")?;
        IMetadosis::getOffchainJobCall::abi_decode_returns(&raw)
            .map(|decoded| decoded.to_vec())
            .map_err(|error| PublicRpcError::Malformed {
                method: "eth_call",
                detail: error.to_string(),
            })
    }

    pub fn call(&self, method: &'static str, params: Value) -> Result<Value, PublicRpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            }))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| PublicRpcError::Transport(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(PublicRpcError::ResponseTooLarge);
        }
        let read_cap = self
            .max_response_bytes
            .checked_add(1)
            .ok_or(PublicRpcError::ResponseTooLarge)?;
        let mut body = Vec::new();
        response
            .take(read_cap as u64)
            .read_to_end(&mut body)
            .map_err(|error| PublicRpcError::Transport(error.to_string()))?;
        if body.len() > self.max_response_bytes {
            return Err(PublicRpcError::ResponseTooLarge);
        }
        let envelope: Value =
            serde_json::from_slice(&body).map_err(|error| PublicRpcError::Malformed {
                method,
                detail: error.to_string(),
            })?;
        if envelope.get("id") != Some(&Value::from(id)) {
            return Err(PublicRpcError::ResponseId);
        }
        if let Some(error) = envelope.get("error") {
            return Err(PublicRpcError::Remote {
                method,
                detail: error.to_string(),
            });
        }
        envelope
            .get("result")
            .cloned()
            .ok_or(PublicRpcError::MissingResult(method))
    }
}

fn exact_block_hash_tag(block_hash: B256) -> Value {
    json!({
        "blockHash": format!("{block_hash:#x}"),
        "requireCanonical": true,
    })
}

fn normalize_block_receipts(
    block: FinalizedRpcBlockV1,
    value: Value,
) -> Result<outbe_offchain_data::FinalizedBlock, PublicRpcError> {
    let number = block.number;
    let receipts = value
        .as_array()
        .ok_or_else(|| malformed("eth_getBlockReceipts", "result is not an array"))?;
    let mut normalized = Vec::with_capacity(receipts.len());
    let mut expected_log_index = 0_u64;
    for (position, receipt) in receipts.iter().enumerate() {
        if parse_hex_u64(
            field(receipt, "blockNumber", "eth_getBlockReceipts")?,
            "receipt block number",
        )? != number
            || parse_b256(
                field(receipt, "blockHash", "eth_getBlockReceipts")?,
                "receipt block hash",
            )? != block.hash
        {
            return Err(malformed(
                "eth_getBlockReceipts",
                "receipt belongs to another block",
            ));
        }
        let transaction_index = parse_hex_u64(
            field(receipt, "transactionIndex", "eth_getBlockReceipts")?,
            "transaction index",
        )?;
        if transaction_index != position as u64 {
            return Err(malformed(
                "eth_getBlockReceipts",
                "receipt array is not in canonical transaction order",
            ));
        }
        let tx_hash = parse_b256(
            field(receipt, "transactionHash", "eth_getBlockReceipts")?,
            "transaction hash",
        )?;
        let success = parse_hex_u64(
            field(receipt, "status", "eth_getBlockReceipts")?,
            "receipt status",
        )? == 1;
        let raw_logs = field(receipt, "logs", "eth_getBlockReceipts")?
            .as_array()
            .ok_or_else(|| malformed("eth_getBlockReceipts", "logs is not an array"))?;
        let mut logs = Vec::with_capacity(raw_logs.len());
        for raw in raw_logs {
            if parse_b256(
                field(raw, "blockHash", "eth_getBlockReceipts")?,
                "log block hash",
            )? != block.hash
                || parse_b256(
                    field(raw, "transactionHash", "eth_getBlockReceipts")?,
                    "log transaction hash",
                )? != tx_hash
            {
                return Err(malformed(
                    "eth_getBlockReceipts",
                    "log provenance differs from its receipt",
                ));
            }
            if parse_hex_u64(
                field(raw, "blockNumber", "eth_getBlockReceipts")?,
                "log block number",
            )? != number
                || parse_hex_u64(
                    field(raw, "transactionIndex", "eth_getBlockReceipts")?,
                    "log transaction index",
                )? != transaction_index
            {
                return Err(malformed(
                    "eth_getBlockReceipts",
                    "log position differs from its receipt",
                ));
            }
            let log_index =
                parse_hex_u64(field(raw, "logIndex", "eth_getBlockReceipts")?, "log index")?;
            if log_index != expected_log_index {
                return Err(malformed(
                    "eth_getBlockReceipts",
                    "logs are not in canonical block order",
                ));
            }
            expected_log_index = expected_log_index
                .checked_add(1)
                .ok_or_else(|| malformed("eth_getBlockReceipts", "log index overflow"))?;
            let emitter = field(raw, "address", "eth_getBlockReceipts")?
                .as_str()
                .ok_or_else(|| malformed("eth_getBlockReceipts", "log address is not a string"))?
                .parse::<Address>()
                .map_err(|error| malformed("eth_getBlockReceipts", &error.to_string()))?;
            let topics = field(raw, "topics", "eth_getBlockReceipts")?
                .as_array()
                .ok_or_else(|| malformed("eth_getBlockReceipts", "topics is not an array"))?
                .iter()
                .map(|topic| parse_b256(topic, "log topic"))
                .collect::<Result<Vec<_>, _>>()?;
            let data = Bytes::from(parse_hex_bytes(
                field(raw, "data", "eth_getBlockReceipts")?,
                "eth_getBlockReceipts",
            )?);
            logs.push(outbe_offchain_data::FinalizedLog {
                log_index,
                emitter,
                data: LogData::new_unchecked(topics, data),
            });
        }
        normalized.push(outbe_offchain_data::FinalizedReceipt {
            tx_hash,
            transaction_index,
            success,
            logs,
        });
    }
    Ok(outbe_offchain_data::FinalizedBlock {
        number,
        hash: block.hash,
        receipts: normalized,
    })
}

fn parse_block(value: Value) -> Result<FinalizedRpcBlockV1, PublicRpcError> {
    if value.is_null() {
        return Err(PublicRpcError::MissingBlock);
    }
    Ok(FinalizedRpcBlockV1 {
        number: parse_hex_u64(field(&value, "number", "block")?, "block number")?,
        hash: parse_b256(field(&value, "hash", "block")?, "block hash")?,
        state_root: parse_b256(field(&value, "stateRoot", "block")?, "block state root")?,
    })
}

fn field<'a>(
    value: &'a Value,
    name: &str,
    method: &'static str,
) -> Result<&'a Value, PublicRpcError> {
    value
        .get(name)
        .ok_or_else(|| malformed(method, &format!("missing {name}")))
}

fn parse_hex_bytes(value: &Value, method: &'static str) -> Result<Vec<u8>, PublicRpcError> {
    let encoded = value
        .as_str()
        .ok_or_else(|| malformed(method, "hex value is not a string"))?;
    hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded))
        .map_err(|error| malformed(method, &error.to_string()))
}

fn parse_b256(value: &Value, what: &'static str) -> Result<B256, PublicRpcError> {
    value
        .as_str()
        .ok_or_else(|| malformed("RPC", what))?
        .parse()
        .map_err(|error: alloy_primitives::hex::FromHexError| malformed("RPC", &error.to_string()))
}

fn parse_hex_u64(value: &Value, what: &'static str) -> Result<u64, PublicRpcError> {
    let encoded = value.as_str().ok_or_else(|| malformed("RPC", what))?;
    u64::from_str_radix(encoded.strip_prefix("0x").unwrap_or(encoded), 16)
        .map_err(|error| malformed("RPC", &error.to_string()))
}

fn malformed(method: &'static str, detail: &str) -> PublicRpcError {
    PublicRpcError::Malformed {
        method,
        detail: detail.to_owned(),
    }
}

#[derive(Debug, Error)]
pub enum PublicRpcError {
    #[error("public OCOMP RPC response limit must be non-zero")]
    InvalidResponseLimit,
    #[error("public OCOMP RPC transport failed: {0}")]
    Transport(String),
    #[error("public OCOMP RPC response exceeded the configured bound")]
    ResponseTooLarge,
    #[error("public OCOMP RPC response id mismatch")]
    ResponseId,
    #[error("public OCOMP RPC {method} returned an error: {detail}")]
    Remote {
        method: &'static str,
        detail: String,
    },
    #[error("public OCOMP RPC {0} response has no result")]
    MissingResult(&'static str),
    #[error("public OCOMP RPC returned no block")]
    MissingBlock,
    #[error("public OCOMP RPC {method} response is malformed: {detail}")]
    Malformed {
        method: &'static str,
        detail: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn receipt(
        block: FinalizedRpcBlockV1,
        tx_hash: B256,
        transaction_index: u64,
        status: u64,
        logs: Value,
    ) -> Value {
        json!({
            "blockNumber": format!("0x{:x}", block.number),
            "blockHash": format!("{:#x}", block.hash),
            "transactionHash": format!("{tx_hash:#x}"),
            "transactionIndex": format!("0x{transaction_index:x}"),
            "status": format!("0x{status:x}"),
            "logs": logs,
        })
    }

    #[test]
    fn normalizes_successful_and_reverted_receipts_in_canonical_order() {
        let block = FinalizedRpcBlockV1 {
            number: 17,
            hash: hash(0x11),
            state_root: hash(0x22),
        };
        let first_tx = hash(0x33);
        let log = json!({
            "blockNumber": "0x11",
            "blockHash": format!("{:#x}", block.hash),
            "transactionHash": format!("{first_tx:#x}"),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "address": format!("{:#x}", Address::repeat_byte(0x44)),
            "topics": [format!("{:#x}", hash(0x55))],
            "data": "0x0102",
        });
        let normalized = normalize_block_receipts(
            block,
            json!([
                receipt(block, first_tx, 0, 1, json!([log])),
                receipt(block, hash(0x66), 1, 0, json!([])),
            ]),
        )
        .unwrap();

        assert_eq!(normalized.number, 17);
        assert_eq!(normalized.hash, block.hash);
        assert!(normalized.receipts[0].success);
        assert_eq!(normalized.receipts[0].logs.len(), 1);
        assert!(!normalized.receipts[1].success);
    }

    #[test]
    fn rejects_receipt_and_log_provenance_mismatches() {
        let block = FinalizedRpcBlockV1 {
            number: 17,
            hash: hash(0x11),
            state_root: hash(0x22),
        };
        let tx_hash = hash(0x33);
        let bad_log = json!({
            "blockNumber": "0x11",
            "blockHash": format!("{:#x}", block.hash),
            "transactionHash": format!("{:#x}", hash(0x99)),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "address": format!("{:#x}", Address::repeat_byte(0x44)),
            "topics": [],
            "data": "0x",
        });
        let error = normalize_block_receipts(
            block,
            json!([receipt(block, tx_hash, 0, 1, json!([bad_log]))]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("log provenance"));
    }

    #[test]
    fn finalized_state_reads_use_an_exact_canonical_block_hash() {
        let block_hash = hash(0x77);
        assert_eq!(
            exact_block_hash_tag(block_hash),
            json!({
                "blockHash": format!("{block_hash:#x}"),
                "requireCanonical": true,
            })
        );
    }
}
