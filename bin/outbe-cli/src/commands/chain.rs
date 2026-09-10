//! Chain information commands.

use alloy_primitives::{Address, U256};
use clap::Subcommand;
use eyre::Result;

use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum ChainCmd {
    /// Show basic chain information (chain ID, block, gas price).
    Info,
    /// Show detailed chain status including consensus and epoch data.
    Status,
    /// Show account balance.
    Balance {
        /// Account address.
        address: Address,
    },
    /// Show block details by number.
    Block {
        /// Block number (omit for latest).
        #[arg(long)]
        number: Option<u64>,
    },
    /// Show finalized consensus status snapshot.
    Consensus,
    /// Show the latest VRF seed.
    VrfSeed,
    /// Show P2P network information (peer count).
    Network,
}

impl ChainCmd {
    pub async fn run(self, client: &(impl Rpc + Sync)) -> Result<()> {
        match self {
            Self::Info => info(client).await,
            Self::Status => status(client).await,
            Self::Balance { address } => balance(client, address).await,
            Self::Block { number } => block(client, number).await,
            Self::Consensus => consensus(client).await,
            Self::VrfSeed => vrf_seed(client).await,
            Self::Network => network(client).await,
        }
    }
}

struct ChainInfo {
    block: u64,
    chain_id: u64,
    gas_price: U256,
}

async fn fetch_chain_info(client: &(impl Rpc + Sync)) -> Result<ChainInfo> {
    let block = client.eth_block_number().await?;
    let chain_id = client.eth_chain_id().await?;
    let gas_price = client.eth_gas_price().await?;
    Ok(ChainInfo {
        block,
        chain_id,
        gas_price,
    })
}

async fn info(client: &(impl Rpc + Sync)) -> Result<()> {
    let ci = fetch_chain_info(client).await?;
    println!("Chain ID:     {}", ci.chain_id);
    println!("Block Number: {}", ci.block);
    println!("Gas Price:    {} unit", ci.gas_price);
    Ok(())
}

async fn status(client: &(impl Rpc + Sync)) -> Result<()> {
    let block_number = client.eth_block_number().await?;
    let chain_id = client.eth_chain_id().await?;
    let gas_price = client.eth_gas_price().await?;

    println!("=== Chain Status ===");
    println!("Chain ID:       {chain_id}");
    println!("Block Number:   {block_number}");
    println!("Gas Price:      {gas_price} unit");

    // Epoch info via outbe RPC.
    if let Ok(epoch_info) = client.outbe_get_epoch_info().await {
        println!();
        println!("=== Epoch ===");
        if let Some(n) = epoch_info.get("epochNumber").and_then(|v| v.as_u64()) {
            println!("Epoch Number:   {n}");
        }
        if let Some(ts) = epoch_info
            .get("epochStartTimestamp")
            .and_then(|v| v.as_u64())
        {
            println!("Epoch Start Time: {ts}");
        }
        if let Some(block) = epoch_info.get("epochStartBlock").and_then(|v| v.as_u64()) {
            println!("Epoch Start Block: {block}");
        }
        if let Some(c) = epoch_info
            .get("activeValidatorCount")
            .and_then(|v| v.as_u64())
        {
            println!("Active Validators: {c}");
        }
        if let Some(s) = epoch_info.get("totalStaked").and_then(|v| v.as_str()) {
            println!("Total Staked:   {s}");
        }
    }

    // Consensus info.
    match client.outbe_consensus_status().await {
        Ok(cs) => {
            println!();
            println!("=== Consensus ===");
            if let Some(v) = cs.get("currentView").and_then(|v| v.as_u64()) {
                println!("Current View:   {v}");
            }
            if let Some(p) = cs.get("connectedPeers").and_then(|v| v.as_u64()) {
                println!("Connected Peers: {p}");
            }
            let active = cs
                .get("isActive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!("Active:         {active}");
            let shares = cs
                .get("hasThresholdShares")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!("Threshold Shares: {shares}");
            if let Some(f) = cs.get("lastFinalizedBlock").and_then(|v| v.as_u64()) {
                println!("Last Finalized: {f}");
                if block_number > 0 && f > 0 {
                    let lag = block_number.saturating_sub(f);
                    println!("Finality Lag:   {lag} blocks");
                }
            }
            if let Some(seed) = cs.get("lastVrfSeed").and_then(|v| v.as_str()) {
                println!("VRF Seed:       {seed}");
            }
        }
        Err(_) => {
            println!();
            println!("=== Consensus ===");
            println!("(unavailable - non-validator node or consensus not started)");
        }
    }

    // Block timing estimate from last two blocks.
    if block_number >= 2 {
        if let (Ok(prev), Ok(curr)) = (
            client.eth_get_block_by_number(block_number - 1).await,
            client.eth_get_block_by_number(block_number).await,
        ) {
            if let (Some(t1), Some(t2)) = (
                prev.get("timestamp")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()),
                curr.get("timestamp")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()),
            ) {
                let block_time = t2.saturating_sub(t1);
                println!();
                println!("=== Timing ===");
                println!("Last Block Time: {block_time}s");
            }
        }
    }

    Ok(())
}

async fn balance(client: &(impl Rpc + Sync), address: Address) -> Result<()> {
    let bal = client.eth_get_balance(address).await?;
    println!(
        "Balance of {:?}: {} rudis",
        address,
        super::format_coen_amount(bal)
    );
    Ok(())
}

async fn block(client: &(impl Rpc + Sync), number: Option<u64>) -> Result<()> {
    let blk = if let Some(n) = number {
        client.eth_get_block_by_number(n).await?
    } else {
        client.eth_get_latest_block().await?
    };

    let num = blk
        .get("number")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
        .unwrap_or(0);
    let hash = blk
        .get("hash")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let parent = blk
        .get("parentHash")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let timestamp = blk
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
        .unwrap_or(0);
    let gas_used = blk.get("gasUsed").and_then(|v| v.as_str()).unwrap_or("0x0");
    let gas_limit = blk
        .get("gasLimit")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0");
    let tx_count = blk
        .get("transactions")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let extra_data = blk
        .get("extraData")
        .and_then(|v| v.as_str())
        .unwrap_or("0x");
    let miner = blk
        .get("miner")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!("Block #{num}");
    println!("  Hash:        {hash}");
    println!("  Parent:      {parent}");
    println!("  Timestamp:   {timestamp}");
    println!("  Miner:       {miner}");
    println!("  Gas Used:    {gas_used}");
    println!("  Gas Limit:   {gas_limit}");
    println!("  Transactions: {tx_count}");

    let extra_len = (extra_data.len().saturating_sub(2)) / 2; // hex bytes
    if extra_len > 0 {
        println!("  Extra Data:  {extra_data} ({extra_len} bytes)");
    }

    Ok(())
}

async fn consensus(client: &(impl Rpc + Sync)) -> Result<()> {
    let cs = client.outbe_consensus_status().await?;

    println!("=== Consensus Status ===");

    if let Some(v) = cs.get("currentView").and_then(|v| v.as_u64()) {
        println!("Current View:     {v}");
    }
    if let Some(p) = cs.get("connectedPeers").and_then(|v| v.as_u64()) {
        println!("Connected Peers:  {p}");
    }
    let active = cs
        .get("isActive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Active:           {active}");
    let shares = cs
        .get("hasThresholdShares")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Threshold Shares: {shares}");
    if let Some(f) = cs.get("lastFinalizedBlock").and_then(|v| v.as_u64()) {
        println!("Last Finalized:   {f}");
    }
    if let Some(seed) = cs.get("lastVrfSeed") {
        if seed.is_null() {
            println!("VRF Seed:         (none)");
        } else if let Some(s) = seed.as_str() {
            println!("VRF Seed:         {s}");
        }
    }

    Ok(())
}

async fn vrf_seed(client: &(impl Rpc + Sync)) -> Result<()> {
    let seed = client.outbe_get_vrf_seed().await?;

    if seed.is_null() {
        println!("VRF Seed: (none - no finalized block with VRF yet)");
    } else if let Some(s) = seed.as_str() {
        println!("VRF Seed: {s}");
    } else {
        println!("VRF Seed: {seed}");
    }

    Ok(())
}

async fn network(client: &(impl Rpc + Sync)) -> Result<()> {
    let peer_count = client.net_peer_count().await?;

    println!("=== Network ===");
    println!("Connected Peers: {peer_count}");

    // Also show consensus-level peer info if available
    if let Ok(cs) = client.outbe_consensus_status().await {
        if let Some(p) = cs.get("connectedPeers").and_then(|v| v.as_u64()) {
            println!("Consensus Peers: {p}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::mock::MockRpc;
    use alloy_primitives::U256;

    #[tokio::test]
    async fn test_fetch_chain_info_returns_correct_values() {
        let mock = MockRpc {
            block_number: Ok(100),
            chain_id: Ok(1337),
            gas_price: Ok(U256::from(alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE)),
            ..Default::default()
        };
        let ci = fetch_chain_info(&mock).await.unwrap();
        assert_eq!(ci.block, 100);
        assert_eq!(ci.chain_id, 1337);
        assert_eq!(
            ci.gas_price,
            U256::from(alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE)
        );
    }

    #[tokio::test]
    async fn test_fetch_chain_info_rpc_error() {
        let mock = MockRpc::default();
        assert!(fetch_chain_info(&mock).await.is_err());
    }

    #[tokio::test]
    async fn test_balance_returns_value() {
        let one_coen = U256::from(1_000_000_000_000_000_000u64);
        let mock = MockRpc {
            balance: Ok(one_coen),
            ..Default::default()
        };
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let bal = mock.eth_get_balance(addr).await.unwrap();
        assert_eq!(bal, one_coen, "balance must match mock");
    }

    #[tokio::test]
    async fn test_balance_rpc_error() {
        let mock = MockRpc::default();
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(balance(&mock, addr).await.is_err());
    }

    #[tokio::test]
    async fn test_consensus_happy() {
        let mock = MockRpc {
            consensus_status: Ok(serde_json::json!({
                "currentView": 42,
                "connectedPeers": 5,
                "isActive": true,
                "hasThresholdShares": true,
                "lastFinalizedBlock": 100,
                "lastVrfSeed": "0xabcd"
            })),
            ..Default::default()
        };
        consensus(&mock).await.unwrap();
    }

    #[tokio::test]
    async fn test_consensus_rpc_error() {
        let mock = MockRpc::default();
        assert!(consensus(&mock).await.is_err());
    }

    #[tokio::test]
    async fn test_network_happy() {
        let mock = MockRpc {
            peer_count: Ok(5),
            consensus_status: Ok(serde_json::json!({"connectedPeers": 3})),
            ..Default::default()
        };
        network(&mock).await.unwrap();
    }

    #[tokio::test]
    async fn test_vrf_seed_null() {
        let mock = MockRpc {
            vrf_seed: Ok(serde_json::Value::Null),
            ..Default::default()
        };
        vrf_seed(&mock).await.unwrap();
    }

    #[tokio::test]
    async fn test_vrf_seed_rpc_error() {
        let mock = MockRpc::default();
        assert!(vrf_seed(&mock).await.is_err());
    }

    #[tokio::test]
    async fn test_block_latest_happy() {
        let mock = MockRpc {
            latest_block: Ok(serde_json::json!({
                "number": "0x64",
                "hash": "0xabc",
                "parentHash": "0xdef",
                "timestamp": "0x60000000",
                "gasUsed": "0x5208",
                "gasLimit": "0x1c9c380",
                "transactions": [],
                "extraData": "0x",
                "miner": "0x0000000000000000000000000000000000000000"
            })),
            ..Default::default()
        };
        block(&mock, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_block_by_number_happy() {
        let mock = MockRpc {
            block_by_number: Ok(serde_json::json!({
                "number": "0xa",
                "hash": "0x123",
                "parentHash": "0x000",
                "timestamp": "0x60000000",
                "gasUsed": "0x0",
                "gasLimit": "0x1c9c380",
                "transactions": ["0xtx1"],
                "extraData": "0xdeadbeef",
                "miner": "0x1111111111111111111111111111111111111111"
            })),
            ..Default::default()
        };
        block(&mock, Some(10)).await.unwrap();
    }
}
