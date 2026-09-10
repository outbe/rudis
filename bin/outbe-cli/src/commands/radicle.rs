//! Commands for the on-chain public Radicle repository registry.

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::{Result, WrapErr};
use outbe_primitives::addresses::RADICLE_REGISTRY_ADDRESS;

use crate::{abi::IRadicleRegistry, rpc::Rpc};

type RepoId = FixedBytes<20>;

fn parse_repo_id(value: &str) -> std::result::Result<RepoId, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| format!("invalid RepoId hex: {error}"))?;
    if bytes.len() != 20 {
        return Err(format!(
            "RepoId must be exactly 20 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(RepoId::from_slice(&bytes))
}

#[derive(Subcommand)]
pub enum RadicleCmd {
    /// Register a public Heartwood RepoId. Registration becomes active after finality.
    RegisterRepository {
        #[arg(long, value_parser = parse_repo_id)]
        repo_id: RepoId,
    },
    /// Enumerate every registered public RepoId.
    Repositories,
    /// Show the EVM account that registered a RepoId, or zero when absent.
    Repository {
        #[arg(long, value_parser = parse_repo_id)]
        repo_id: RepoId,
    },
}

impl RadicleCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::RegisterRepository { repo_id } => {
                let signer = super::require_signer(private_key)?;
                let call = IRadicleRegistry::registerRepositoryCall { repoId: repo_id };
                let tx = signer
                    .send_tx(
                        client,
                        RADICLE_REGISTRY_ADDRESS,
                        call.abi_encode(),
                        U256::ZERO,
                    )
                    .await?;
                println!("Radicle repository registration transaction sent: {tx}");
                Ok(())
            }
            Self::Repositories => list(client).await,
            Self::Repository { repo_id } => show(client, repo_id).await,
        }
    }
}

async fn list(client: &(impl Rpc + Sync)) -> Result<()> {
    let output = client
        .eth_call(
            RADICLE_REGISTRY_ADDRESS,
            &IRadicleRegistry::repositoryCountCall {}.abi_encode(),
        )
        .await
        .wrap_err("Radicle repositoryCount eth_call failed")?;
    let count = IRadicleRegistry::repositoryCountCall::abi_decode_returns(&output)
        .wrap_err("decode Radicle repository count")?;
    for index in 0..count {
        let output = client
            .eth_call(
                RADICLE_REGISTRY_ADDRESS,
                &IRadicleRegistry::repositoryAtCall { index }.abi_encode(),
            )
            .await
            .wrap_err_with(|| format!("Radicle repositoryAt({index}) eth_call failed"))?;
        let repo_id = IRadicleRegistry::repositoryAtCall::abi_decode_returns(&output)
            .wrap_err("decode Radicle RepoId")?;
        println!("{index}: 0x{}", hex::encode(repo_id));
    }
    Ok(())
}

async fn show(client: &(impl Rpc + Sync), repo_id: RepoId) -> Result<()> {
    let output = client
        .eth_call(
            RADICLE_REGISTRY_ADDRESS,
            &IRadicleRegistry::repositoryRegistrantCall { repoId: repo_id }.abi_encode(),
        )
        .await
        .wrap_err("Radicle repositoryRegistrant eth_call failed")?;
    let registrant = IRadicleRegistry::repositoryRegistrantCall::abi_decode_returns(&output)
        .wrap_err("decode Radicle repository registrant")?;
    println!("RepoId: 0x{}", hex::encode(repo_id));
    println!("Registrant: {registrant}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rpc::mock::recording_send_tx_rpc, Cli};
    use clap::Parser;

    static PRIVATE_KEY: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| outbe_primitives::test_keys::hex(1));

    #[test]
    fn parses_registry_commands_and_rejects_wrong_length() {
        let id = "11".repeat(20);
        assert!(Cli::try_parse_from([
            "outbe-cli",
            "radicle",
            "register-repository",
            "--repo-id",
            &id,
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["outbe-cli", "radicle", "repositories"]).is_ok());
        assert!(
            Cli::try_parse_from(["outbe-cli", "radicle", "repository", "--repo-id", "11",])
                .is_err()
        );
    }

    #[tokio::test]
    async fn register_sends_the_exact_precompile_call() {
        let repo_id = RepoId::repeat_byte(0x44);
        let call = IRadicleRegistry::registerRepositoryCall { repoId: repo_id };
        let rpc = recording_send_tx_rpc(
            &PRIVATE_KEY,
            RADICLE_REGISTRY_ADDRESS,
            call.abi_encode(),
            U256::ZERO,
        )
        .unwrap();
        RadicleCmd::RegisterRepository { repo_id }
            .run(&rpc, Some(&PRIVATE_KEY))
            .await
            .unwrap();
    }
}
