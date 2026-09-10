//! Rewards commands.
//!
//! Validator daily emission is delivered as gems (see the Rewards module's
//! prepare/delivery batch API), not as a claimable native balance, so there is no
//! `claim` / `pending` command here.

use clap::Subcommand;
use eyre::Result;

use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum RewardsCmd {
    /// Show current reward emission parameters
    Emission,
    /// Show reward distribution history from event logs
    History {
        /// Number of recent events to show (default: 20)
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

impl RewardsCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), _private_key: Option<&str>) -> Result<()> {
        match self {
            Self::Emission => emission(client).await,
            Self::History { limit } => history(client, limit).await,
        }
    }
}

async fn emission(client: &(impl Rpc + Sync)) -> Result<()> {
    let info = client.outbe_get_emission_info().await?;

    let validator_pct = info["validatorRewardPercent"].as_u64().unwrap_or(0);
    let escrow_addr = info["feeEscrowAddress"].as_str().unwrap_or("N/A");

    println!("=== Reward Emission Parameters ===");
    println!("Validator Cap:      {validator_pct}%");
    println!("Fee Escrow:         {escrow_addr}");
    println!("Delivery:           validator emission is paid in gems");
    println!("Settlement Source:  finalized block execution summary artifact");

    Ok(())
}

async fn history(_client: &(impl Rpc + Sync), limit: usize) -> Result<()> {
    println!(
        "Validator reward settlement history is committed through block artifacts; receipt-log history is not exposed yet. Requested limit: {limit}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::mock::MockRpc;

    #[tokio::test]
    async fn test_emission_happy() {
        let mock = MockRpc {
            emission_info: Ok(serde_json::json!({
                "validatorRewardPercent": 4,
                "feeEscrowAddress": "0x000000000000000000000000000000000000ee03"
            })),
            ..Default::default()
        };
        // emission() only prints, so verify it doesn't error
        emission(&mock).await.unwrap();
    }

    #[tokio::test]
    async fn test_emission_rpc_error() {
        let mock = MockRpc::default();
        assert!(emission(&mock).await.is_err());
    }

    #[tokio::test]
    async fn test_history_is_currently_informational() {
        let mock = MockRpc::default();
        history(&mock, 20).await.unwrap();
    }
}
