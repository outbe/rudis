//! Live network monitoring, health checks, and readiness probes.

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::Result;

use crate::abi::{self, IStaking, IValidatorSet};
use crate::rpc::Rpc;

#[cfg(not(test))]
fn exit_process(code: i32) -> ! {
    std::process::exit(code)
}

#[cfg(test)]
fn exit_process(code: i32) -> ! {
    panic!("exit({code})")
}

#[derive(Subcommand)]
pub enum MonitorCmd {
    /// Continuous polling monitor (dashboard view).
    Watch {
        /// Poll interval in seconds.
        #[arg(long, default_value = "10")]
        interval: u64,
    },
    /// Health check - exits with code 0 if the node is healthy, 1 otherwise.
    ///
    /// Checks: RPC reachable, block number advancing, consensus active.
    /// Suitable for k8s liveness probes and systemd health checks.
    Health,
    /// Readiness check - validates that a validator node is ready to participate.
    ///
    /// Checks: node synced, consensus active, threshold shares present,
    /// connected peers > 0, validator registered in active set.
    /// Suitable for k8s readiness probes and pre-flight checks.
    Readiness {
        /// Validator address to check (optional - if omitted, checks node-level readiness only).
        #[arg(long)]
        address: Option<alloy_primitives::Address>,
    },
    /// Fetch and display Prometheus metrics from the node's metrics endpoint.
    ///
    /// Filters for `outbe_` prefixed metrics by default.
    Metrics {
        /// Metrics endpoint URL (default: http://localhost:9001/metrics).
        #[arg(long, default_value = "http://localhost:9001/metrics")]
        endpoint: String,
        /// Show all metrics, not just `outbe_` prefixed ones.
        #[arg(long)]
        all: bool,
    },
}

impl MonitorCmd {
    pub async fn run(self, client: &(impl Rpc + Sync)) -> Result<()> {
        match self {
            MonitorCmd::Watch { interval } => run_watch(client, interval).await,
            MonitorCmd::Health => run_health(client).await,
            MonitorCmd::Readiness { address } => run_readiness(client, address).await,
            MonitorCmd::Metrics { endpoint, all } => run_metrics(&endpoint, all).await,
        }
    }
}

/// Continuous polling dashboard.
async fn run_watch(client: &(impl Rpc + Sync), interval: u64) -> Result<()> {
    loop {
        print!("\x1B[2J\x1B[1;1H");
        watch_tick(client).await?;
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

/// Single dashboard tick - extracted from loop for testability.
async fn watch_tick(client: &(impl Rpc + Sync)) -> Result<()> {
    let block = client.eth_block_number().await?;

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

    let count: u64 = {
        let call = IValidatorSet::activeValidatorCountCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::activeValidatorCountCall::abi_decode_returns(&result)?.into()
    };

    let total: U256 = {
        let call = IStaking::getTotalStakedCall {};
        let result = client
            .eth_call(abi::STAKING_ADDR, &call.abi_encode())
            .await?;
        IStaking::getTotalStakedCall::abi_decode_returns(&result)?
    };

    let validators: Vec<alloy_primitives::Address> = {
        let call = IValidatorSet::getActiveValidatorsCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::getActiveValidatorsCall::abi_decode_returns(&result)?
    };

    println!("=== Outbe Network Monitor ===");
    println!(
        "Block: {block}  |  Epoch: {epoch}  |  Active: {count}  |  Staked: {} rudis",
        super::format_coen_amount(total)
    );
    println!();
    println!(
        "{:<4} {:<44} {:>8} {:>12} {:>10} {:>10}",
        "#", "Address", "Status", "Stake", "Miss.Blk", "Miss.Vote"
    );
    println!("{}", "-".repeat(92));

    for (i, addr) in validators.iter().enumerate() {
        let detail_call = IValidatorSet::validatorByAddressCall { addr: *addr }.abi_encode();
        if let Ok(detail_result) = client.eth_call(abi::VALIDATOR_SET_ADDR, &detail_call).await {
            if let Ok(detail) =
                IValidatorSet::validatorByAddressCall::abi_decode_returns(&detail_result)
            {
                let status_str = match detail.status {
                    0 => "Registered",
                    1 => "Pending",
                    2 => "Active",
                    3 => "Exiting",
                    4 => "Unbonding",
                    5 => "Inactive",
                    6 => "Jailed",
                    _ => "Unknown",
                };
                println!(
                    "{:<4} {:?} {:>8} {:>12} {:>10} {:>10}",
                    i + 1,
                    addr,
                    status_str,
                    super::format_coen_amount(detail.stake),
                    detail.missedBlocks,
                    detail.missedVotes,
                );
            }
        }
    }

    Ok(())
}

/// Health check - exit code 0 if healthy, non-zero otherwise.
async fn run_health(client: &(impl Rpc + Sync)) -> Result<()> {
    let mut healthy = true;

    // 1. Check RPC is reachable and returning block numbers.
    match client.eth_block_number().await {
        Ok(block) => {
            println!("[OK]  RPC reachable, block number: {block}");
        }
        Err(e) => {
            println!("[FAIL] RPC unreachable: {e}");
            healthy = false;
        }
    }

    // 2. Check consensus status (if available).
    match client.outbe_consensus_status().await {
        Ok(status) => {
            let is_active = status
                .get("isActive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let last_finalized = status
                .get("lastFinalizedBlock")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if is_active {
                println!("[OK]  consensus active, last finalized block: {last_finalized}");
            } else {
                println!("[WARN] consensus not active");
            }
        }
        Err(_) => {
            println!("[WARN] consensus status unavailable (non-validator node?)");
        }
    }

    if healthy {
        println!("\nhealth: OK");
        Ok(())
    } else {
        println!("\nhealth: FAIL");
        exit_process(1);
    }
}

/// Readiness check - validates validator node is ready to participate.
async fn run_readiness(
    client: &(impl Rpc + Sync),
    address: Option<alloy_primitives::Address>,
) -> Result<()> {
    let mut ready = true;

    // 1. Check RPC is reachable.
    let block = match client.eth_block_number().await {
        Ok(b) => {
            println!("[OK]  RPC reachable, block: {b}");
            b
        }
        Err(e) => {
            println!("[FAIL] RPC unreachable: {e}");
            exit_process(1);
        }
    };

    // 2. Check consensus status.
    match client.outbe_consensus_status().await {
        Ok(status) => {
            let is_active = status
                .get("isActive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let has_shares = status
                .get("hasThresholdShares")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let peers = status
                .get("connectedPeers")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let last_finalized = status
                .get("lastFinalizedBlock")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if is_active {
                println!("[OK]  consensus active");
            } else {
                println!("[FAIL] consensus not active");
                ready = false;
            }

            if has_shares {
                println!("[OK]  threshold shares present");
            } else {
                println!("[FAIL] threshold shares missing");
                ready = false;
            }

            if peers > 0 {
                println!("[OK]  connected peers: {peers}");
            } else {
                println!("[WARN] no connected peers reported");
            }

            // Check sync: last finalized should be close to current block.
            if block > 0 && last_finalized > 0 {
                let lag = block.saturating_sub(last_finalized);
                if lag <= 5 {
                    println!("[OK]  node synced (lag: {lag} blocks)");
                } else {
                    println!("[FAIL] node behind (lag: {lag} blocks)");
                    ready = false;
                }
            }

            // Enclave canary health (`enclave` object; absent on older nodes).
            match status.get("enclave") {
                Some(enclave) => {
                    let state = enclave
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let enclave_ready = enclave
                        .get("ready")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let latency = enclave.get("lastCanaryLatencyMs").and_then(|v| v.as_u64());
                    match state {
                        _ if enclave_ready => match latency {
                            Some(ms) => println!("[OK]  enclave canary ready (latency {ms}ms)"),
                            None => println!("[OK]  enclave canary ready"),
                        },
                        "degraded" | "unavailable" => {
                            let failure = enclave
                                .get("lastFailureClass")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            println!("[FAIL] enclave canary {state} ({failure})");
                            ready = false;
                        }
                        "starting" => println!("[WARN] enclave canary starting"),
                        "disabled" => println!("[WARN] enclave canary disabled"),
                        other => println!("[WARN] enclave canary state: {other}"),
                    }
                }
                None => println!("[WARN] enclave health not reported by node"),
            }
        }
        Err(_) => {
            println!("[FAIL] consensus status unavailable");
            ready = false;
        }
    }

    // 3. Check validator is in active set (if address provided).
    if let Some(addr) = address {
        let detail_call = IValidatorSet::validatorByAddressCall { addr }.abi_encode();
        match client.eth_call(abi::VALIDATOR_SET_ADDR, &detail_call).await {
            Ok(result) => {
                if let Ok(detail) =
                    IValidatorSet::validatorByAddressCall::abi_decode_returns(&result)
                {
                    let (label, is_ready) = interpret_validator_status(detail.status);
                    if is_ready {
                        println!("[OK]  validator {addr:?} is {label}");
                    } else {
                        println!("[FAIL] validator {addr:?} is {label}");
                        ready = false;
                    }
                }
            }
            Err(e) => {
                println!("[FAIL] cannot query validator status: {e}");
                ready = false;
            }
        }
    }

    if ready {
        println!("\nreadiness: READY");
        Ok(())
    } else {
        println!("\nreadiness: NOT READY");
        exit_process(1);
    }
}

/// Fetch and display Prometheus metrics.
async fn run_metrics(endpoint: &str, show_all: bool) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .get(endpoint)
        .send()
        .await
        .map_err(|e| eyre::eyre!("failed to fetch metrics from {endpoint}: {e}"))?;

    if !resp.status().is_success() {
        eyre::bail!("metrics endpoint returned HTTP {}", resp.status().as_u16());
    }

    let body = resp
        .text()
        .await
        .map_err(|e| eyre::eyre!("failed to read metrics response: {e}"))?;

    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            if show_all {
                println!("{line}");
            } else if line.starts_with('#') {
                // Print comment lines for outbe_ metrics
                if line.contains("outbe_") {
                    println!("{line}");
                }
            }
            continue;
        }
        if show_all || line.starts_with("outbe_") {
            println!("{line}");
        }
    }

    Ok(())
}

/// Interprets a validator status code from the on-chain ValidatorSet.
///
/// Returns (human-readable label, is_ready). Only ACTIVE (2) is considered ready.
/// Corrected status codes matching runtime enum:
///   0=REGISTERED, 1=PENDING, 2=ACTIVE, 3=EXITING, 4=UNBONDING, 5=INACTIVE
fn interpret_validator_status(status: u8) -> (&'static str, bool) {
    match status {
        0 => ("registered (not yet active)", false),
        1 => ("pending", false),
        2 => ("active", true),
        3 => ("exiting", false),
        4 => ("unbonding", false),
        5 => ("inactive", false),
        6 => ("jailed", false),
        _ => ("unknown", false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readiness_status_0_registered_not_ready() {
        let (label, ready) = interpret_validator_status(0);
        assert!(!ready, "REGISTERED must not be ready");
        assert!(label.contains("registered"));
    }

    #[test]
    fn test_readiness_status_1_pending_not_ready() {
        let (label, ready) = interpret_validator_status(1);
        assert!(!ready, "PENDING must not be ready");
        assert!(label.contains("pending"));
    }

    #[test]
    fn test_readiness_status_2_active_ready() {
        let (label, ready) = interpret_validator_status(2);
        assert!(ready, "ACTIVE must be ready");
        assert!(label.contains("active"));
    }

    #[test]
    fn test_readiness_status_3_exiting_not_ready() {
        let (label, ready) = interpret_validator_status(3);
        assert!(!ready, "EXITING must not be ready");
        assert!(label.contains("exiting"));
    }

    #[test]
    fn test_readiness_status_4_unbonding_not_ready() {
        let (label, ready) = interpret_validator_status(4);
        assert!(!ready, "UNBONDING must not be ready");
        assert!(label.contains("unbonding"));
    }

    #[test]
    fn test_readiness_status_5_inactive_not_ready() {
        let (label, ready) = interpret_validator_status(5);
        assert!(!ready, "INACTIVE must not be ready");
        assert!(label.contains("inactive"));
    }

    #[test]
    fn test_readiness_status_unknown_not_ready() {
        let (label, ready) = interpret_validator_status(255);
        assert!(!ready, "unknown status must not be ready");
        assert!(label.contains("unknown"));
    }

    // --- Mock RPC tests ---
    use crate::rpc::mock::{abi_u256, abi_u64, call_map, MockRpc};
    use alloy_sol_types::SolCall;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_run_health_happy() {
        let mock = MockRpc {
            block_number: Ok(100),
            consensus_status: Ok(serde_json::json!({
                "isActive": true,
                "lastFinalizedBlock": 100
            })),
            ..Default::default()
        };
        run_health(&mock).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "exit(1)")]
    async fn test_run_health_unhealthy_exits() {
        let mock = MockRpc::default(); // block_number Err -> unhealthy
        let _ = run_health(&mock).await;
    }

    #[tokio::test]
    #[should_panic(expected = "exit(1)")]
    async fn test_run_readiness_rpc_down_exits() {
        let mock = MockRpc::default(); // block_number Err
        let _ = run_readiness(&mock, None).await;
    }

    #[tokio::test]
    #[should_panic(expected = "exit(1)")]
    async fn test_run_readiness_not_active_exits() {
        let mock = MockRpc {
            block_number: Ok(100),
            consensus_status: Ok(serde_json::json!({
                "isActive": false,
                "hasThresholdShares": false,
                "connectedPeers": 0,
                "lastFinalizedBlock": 0
            })),
            ..Default::default()
        };
        let _ = run_readiness(&mock, None).await;
    }

    #[tokio::test]
    async fn test_run_readiness_happy() {
        let mock = MockRpc {
            block_number: Ok(100),
            consensus_status: Ok(serde_json::json!({
                "isActive": true,
                "hasThresholdShares": true,
                "connectedPeers": 3,
                "lastFinalizedBlock": 99
            })),
            ..Default::default()
        };
        run_readiness(&mock, None).await.unwrap();
    }

    /// An `enclave` object absent from `rudis_consensusStatus` (older node) is
    /// a warning, never a readiness failure - the happy test above covers it.
    /// A ready canary keeps READY; degraded/unavailable flips to NOT READY.
    #[tokio::test]
    async fn test_run_readiness_enclave_ready_happy() {
        let mock = MockRpc {
            block_number: Ok(100),
            consensus_status: Ok(serde_json::json!({
                "isActive": true,
                "hasThresholdShares": true,
                "connectedPeers": 3,
                "lastFinalizedBlock": 99,
                "enclave": {
                    "state": "ready",
                    "ready": true,
                    "offerKeyReady": true,
                    "lastCanaryLatencyMs": 4,
                    "consecutiveFailures": 0
                }
            })),
            ..Default::default()
        };
        run_readiness(&mock, None).await.unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "exit(1)")]
    async fn test_run_readiness_enclave_degraded_exits() {
        let mock = MockRpc {
            block_number: Ok(100),
            consensus_status: Ok(serde_json::json!({
                "isActive": true,
                "hasThresholdShares": true,
                "connectedPeers": 3,
                "lastFinalizedBlock": 99,
                "enclave": {
                    "state": "degraded",
                    "ready": false,
                    "offerKeyReady": true,
                    "consecutiveFailures": 5,
                    "lastFailureClass": "canary decrypt failed: io_timeout"
                }
            })),
            ..Default::default()
        };
        let _ = run_readiness(&mock, None).await;
    }

    /// `starting`/`disabled` states warn without failing readiness.
    #[tokio::test]
    async fn test_run_readiness_enclave_starting_warns_only() {
        let mock = MockRpc {
            block_number: Ok(100),
            consensus_status: Ok(serde_json::json!({
                "isActive": true,
                "hasThresholdShares": true,
                "connectedPeers": 3,
                "lastFinalizedBlock": 99,
                "enclave": { "state": "starting", "ready": false }
            })),
            ..Default::default()
        };
        run_readiness(&mock, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_watch_tick_happy() {
        let mut map = HashMap::new();
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getEpochNumberCall::SELECTOR,
            ),
            abi_u64(5),
        );
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::activeValidatorCountCall::SELECTOR,
            ),
            abi_u64(0),
        );
        map.insert(
            (abi::STAKING_ADDR, IStaking::getTotalStakedCall::SELECTOR),
            abi_u256(U256::ZERO),
        );
        let mut empty_addrs = vec![0u8; 64];
        empty_addrs[31] = 32;
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getActiveValidatorsCall::SELECTOR,
            ),
            empty_addrs,
        );
        let mock = MockRpc {
            block_number: Ok(100),
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        };
        watch_tick(&mock).await.unwrap();
    }

    #[tokio::test]
    async fn test_watch_tick_rpc_error() {
        let mock = MockRpc::default();
        assert!(watch_tick(&mock).await.is_err());
    }
}
