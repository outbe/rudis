//! Epoch information commands.

use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::Result;

use crate::abi::{self, IStaking, IValidatorSet, VALIDATOR_SET_ADDR};
use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum EpochCmd {
    /// Show current epoch information
    Info,
    /// Show epoch transition history from event logs
    History {
        /// Number of recent events to show (default: 20)
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show validator set changes (registrations, activations, exits, etc.)
    Transitions {
        /// Number of recent events to show (default: 50)
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

impl EpochCmd {
    pub async fn run(self, client: &(impl Rpc + Sync)) -> Result<()> {
        match self {
            Self::Info => info(client).await,
            Self::History { limit } => history(client, limit).await,
            Self::Transitions { limit } => transitions(client, limit).await,
        }
    }
}

struct EpochInfo {
    epoch: u64,
    epoch_start_timestamp: u64,
    epoch_start_block: u64,
    active_count: u64,
    total_staked: U256,
}

async fn fetch_epoch_info(client: &(impl Rpc + Sync)) -> Result<EpochInfo> {
    let epoch: u64 = {
        let call = IValidatorSet::getEpochNumberCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        let decoded = IValidatorSet::getEpochNumberCall::abi_decode_returns(&result)?;
        decoded
            .try_into()
            .map_err(|_| eyre::eyre!("epoch number exceeds u64"))?
    };

    let epoch_start_timestamp: u64 = {
        let call = IValidatorSet::getEpochStartTimestampCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::getEpochStartTimestampCall::abi_decode_returns(&result)?
    };

    let epoch_start_block: u64 = {
        let call = IValidatorSet::getEpochStartBlockCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::getEpochStartBlockCall::abi_decode_returns(&result)?
    };

    let active_count: u64 = {
        let call = IValidatorSet::activeValidatorCountCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::activeValidatorCountCall::abi_decode_returns(&result)?.into()
    };

    let total_staked: U256 = {
        let call = IStaking::getTotalStakedCall {};
        let result = client
            .eth_call(abi::STAKING_ADDR, &call.abi_encode())
            .await?;
        IStaking::getTotalStakedCall::abi_decode_returns(&result)?
    };

    Ok(EpochInfo {
        epoch,
        epoch_start_timestamp,
        epoch_start_block,
        active_count,
        total_staked,
    })
}

async fn info(client: &(impl Rpc + Sync)) -> Result<()> {
    let ei = fetch_epoch_info(client).await?;
    println!("Epoch Number:       {}", ei.epoch);
    println!("Epoch Start Block:  {}", ei.epoch_start_block);
    println!("Epoch Start Time:   {}", ei.epoch_start_timestamp);
    println!("Active Validators:  {}", ei.active_count);
    println!(
        "Total Staked:       {} rudis",
        super::format_coen_amount(ei.total_staked)
    );
    Ok(())
}

async fn history(client: &(impl Rpc + Sync), limit: usize) -> Result<()> {
    // EpochTransition(uint256 indexed newEpochNumber, uint64 timestamp, uint32 activeValidatorCount)
    let topic = format!(
        "{:?}",
        B256::from(keccak256(b"EpochTransition(uint256,uint64,uint32)",))
    );

    let logs = client
        .eth_get_logs(VALIDATOR_SET_ADDR, &[Some(topic)], "earliest", "latest")
        .await?;

    if logs.is_empty() {
        println!("No epoch transition events found.");
        return Ok(());
    }

    println!(
        "{:<8} {:<14} {:<20} {:<20}",
        "Epoch", "Block", "Timestamp", "Active Validators"
    );
    println!("{}", "-".repeat(62));

    let start = if logs.len() > limit {
        logs.len() - limit
    } else {
        0
    };
    for log in &logs[start..] {
        let block = log["blockNumber"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
            .unwrap_or(0);

        // Indexed newEpochNumber is in topics[1]
        let epoch = log["topics"]
            .as_array()
            .and_then(|t| t.get(1))
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
            .unwrap_or(0);

        // Non-indexed data: timestamp(32) + activeValidatorCount(32)
        let data = log["data"].as_str().unwrap_or("0x");
        let data = data.strip_prefix("0x").unwrap_or(data);
        let bytes = hex::decode(data).unwrap_or_default();

        let timestamp = if bytes.len() >= 32 {
            U256::from_be_slice(&bytes[0..32]).to::<u64>()
        } else {
            0
        };
        let active_count = if bytes.len() >= 64 {
            U256::from_be_slice(&bytes[32..64]).to::<u64>()
        } else {
            0
        };

        println!(
            "{:<8} {:<14} {:<20} {:<20}",
            epoch, block, timestamp, active_count
        );
    }

    Ok(())
}

async fn transitions(client: &(impl Rpc + Sync), limit: usize) -> Result<()> {
    // Query all validator lifecycle events from ValidatorSet contract
    let topic_registered = format!(
        "{:?}",
        B256::from(keccak256(b"ValidatorRegistered(address,uint64)"))
    );
    let topic_activated = format!(
        "{:?}",
        B256::from(keccak256(b"ValidatorActivated(address)"))
    );
    let topic_deactivated = format!(
        "{:?}",
        B256::from(keccak256(b"ValidatorDeactivated(address,uint64)"))
    );
    let topic_forced_exit = format!(
        "{:?}",
        B256::from(keccak256(b"ValidatorForcedExit(address,uint64)"))
    );
    // Fetch all logs from ValidatorSet (no topic filter to get all event types)
    let all_logs = client
        .eth_get_logs(VALIDATOR_SET_ADDR, &[], "earliest", "latest")
        .await?;

    if all_logs.is_empty() {
        println!("No validator transition events found.");
        return Ok(());
    }

    println!("{:<14} {:<14} {:<44} Details", "Block", "Type", "Validator");
    println!("{}", "-".repeat(90));

    let start = if all_logs.len() > limit {
        all_logs.len() - limit
    } else {
        0
    };

    for log in &all_logs[start..] {
        let block = log["blockNumber"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
            .unwrap_or(0);

        let topics = log["topics"].as_array().cloned().unwrap_or_default();
        let topic0 = topics.first().and_then(|v| v.as_str()).unwrap_or("");

        let data = log["data"].as_str().unwrap_or("0x");
        let data_hex = data.strip_prefix("0x").unwrap_or(data);
        let bytes = hex::decode(data_hex).unwrap_or_default();

        if topic0 == topic_registered {
            let validator = topics.get(1).and_then(|v| v.as_str()).unwrap_or("?");
            let index = if bytes.len() >= 32 {
                U256::from_be_slice(&bytes[0..32]).to::<u64>()
            } else {
                0
            };
            println!(
                "{:<14} {:<14} {:<44} index={}",
                block,
                "REGISTERED",
                format_topic_addr(validator),
                index
            );
        } else if topic0 == topic_activated {
            let validator = topics.get(1).and_then(|v| v.as_str()).unwrap_or("?");
            println!(
                "{:<14} {:<14} {:<44}",
                block,
                "ACTIVATED",
                format_topic_addr(validator)
            );
        } else if topic0 == topic_deactivated || topic0 == topic_forced_exit {
            let validator = topics.get(1).and_then(|v| v.as_str()).unwrap_or("?");
            let at_height = if bytes.len() >= 32 {
                U256::from_be_slice(&bytes[0..32]).to::<u64>()
            } else {
                0
            };
            let event_label = if topic0 == topic_forced_exit {
                "FORCED_EXIT"
            } else {
                "DEACTIVATED"
            };
            println!(
                "{:<14} {:<14} {:<44} at_height={}",
                block,
                event_label,
                format_topic_addr(validator),
                at_height
            );
        }
        // Skip EpochTransition and ConsensusSetUpdated - those are in `history`
    }

    Ok(())
}

/// Extracts the last 40 hex chars from a topic (address is zero-padded to 32 bytes).
fn format_topic_addr(topic: &str) -> String {
    let s = topic.strip_prefix("0x").unwrap_or(topic);
    if s.len() >= 40 {
        format!("0x{}", &s[s.len() - 40..])
    } else {
        topic.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_topic_addr_standard_padded() {
        let topic = "0x000000000000000000000000abcdef0123456789abcdef0123456789abcdef01";
        assert_eq!(
            format_topic_addr(topic),
            "0xabcdef0123456789abcdef0123456789abcdef01"
        );
    }

    #[test]
    fn test_format_topic_addr_no_prefix() {
        let topic = "000000000000000000000000abcdef0123456789abcdef0123456789abcdef01";
        assert_eq!(
            format_topic_addr(topic),
            "0xabcdef0123456789abcdef0123456789abcdef01"
        );
    }

    #[test]
    fn test_format_topic_addr_zero_address() {
        let topic = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            format_topic_addr(topic),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_format_topic_addr_short_string_returned_verbatim() {
        assert_eq!(format_topic_addr("0xabc"), "0xabc");
        assert_eq!(format_topic_addr(""), "");
    }

    #[test]
    fn test_format_topic_addr_exactly_40_no_prefix() {
        let topic = "abcdef0123456789abcdef0123456789abcdef01";
        assert_eq!(
            format_topic_addr(topic),
            "0xabcdef0123456789abcdef0123456789abcdef01"
        );
    }

    // --- Mock RPC tests ---
    use crate::rpc::mock::{abi_u256, abi_u64, call_map, MockRpc};
    use alloy_sol_types::SolCall;
    use std::collections::HashMap;

    fn epoch_info_mock(
        epoch: u64,
        ts: u64,
        start_block: u64,
        active: u64,
        staked: U256,
    ) -> MockRpc {
        let mut map = HashMap::new();
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getEpochNumberCall::SELECTOR,
            ),
            abi_u64(epoch),
        );
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getEpochStartTimestampCall::SELECTOR,
            ),
            abi_u64(ts),
        );
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getEpochStartBlockCall::SELECTOR,
            ),
            abi_u64(start_block),
        );
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::activeValidatorCountCall::SELECTOR,
            ),
            abi_u64(active),
        );
        map.insert(
            (abi::STAKING_ADDR, IStaking::getTotalStakedCall::SELECTOR),
            abi_u256(staked),
        );
        MockRpc {
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_fetch_epoch_info_returns_correct_values() {
        let staked = U256::from(1_000_000_000u64);
        let mock = epoch_info_mock(5, 1700000000, 1234, 3, staked);

        let result = fetch_epoch_info(&mock).await.unwrap();
        assert_eq!(result.epoch, 5);
        assert_eq!(result.epoch_start_timestamp, 1700000000);
        assert_eq!(result.epoch_start_block, 1234);
        assert_eq!(result.active_count, 3);
        assert_eq!(result.total_staked, staked);
    }

    #[tokio::test]
    async fn test_fetch_epoch_info_zero_epoch() {
        let mock = epoch_info_mock(0, 0, 0, 0, U256::ZERO);
        let result = fetch_epoch_info(&mock).await.unwrap();
        assert_eq!(result.epoch, 0);
        assert_eq!(result.active_count, 0);
        assert_eq!(result.total_staked, U256::ZERO);
    }

    #[tokio::test]
    async fn test_fetch_epoch_info_rpc_error() {
        let mock = MockRpc::default();
        assert!(fetch_epoch_info(&mock).await.is_err());
    }

    #[tokio::test]
    async fn test_history_empty_logs() {
        let mock = MockRpc {
            logs: Ok(vec![]),
            ..Default::default()
        };
        history(&mock, 20).await.unwrap();
    }

    #[tokio::test]
    async fn test_transitions_empty_logs() {
        let mock = MockRpc {
            logs: Ok(vec![]),
            ..Default::default()
        };
        transitions(&mock, 50).await.unwrap();
    }

    #[tokio::test]
    async fn test_transitions_rpc_error() {
        let mock = MockRpc::default();
        assert!(transitions(&mock, 50).await.is_err());
    }
}
