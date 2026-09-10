//! Stablecoin Factory V1 operator commands.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use clap::{Subcommand, ValueEnum};
use eyre::{Result, WrapErr};
use outbe_primitives::{
    addresses::{
        STABLECOIN_ADDRESS_PREFIX, STABLECOIN_FACTORY_ADDRESS, STABLECOIN_POLICY_REGISTRY_ADDRESS,
        VOTE_ADDRESS,
    },
    stablecoin::{encode_canonical_stablecoin_create, predict_stablecoin, StablecoinCreatePayload},
    stablecoin_fork::STABLECOIN_CREATE_BOND,
};

use crate::{
    abi::{IStablecoinPolicyRegistry, IVote},
    rpc::Rpc,
};

const NON_ENDORSEMENT_WARNING: &str = "Factory registration is protocol admission, not proof \
of backing, redeemability, price stability, issuer solvency, creditworthiness, fee eligibility, \
or payment-lane eligibility.";

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PolicyKind {
    Whitelist,
    Blacklist,
}

impl PolicyKind {
    const fn as_u8(self) -> u8 {
        match self {
            Self::Whitelist => 2,
            Self::Blacklist => 3,
        }
    }
}

#[derive(Subcommand)]
pub enum StablecoinCmd {
    /// Create a shared Whitelist or Blacklist policy.
    PolicyCreate {
        /// Mutable policy type.
        #[arg(long, value_enum)]
        policy_type: PolicyKind,
        /// Policy admin. Defaults to the transaction signer.
        #[arg(long)]
        admin: Option<Address>,
    },
    /// Predict a token id and reserved-class address without contacting RPC.
    Predict {
        /// EVM chain id included in the token identity.
        #[arg(long)]
        chain_id: u64,
        /// Prospective issuer address.
        #[arg(long)]
        issuer: Address,
        /// Canonical global ticker.
        #[arg(long)]
        ticker: String,
    },
    /// Submit a canonical StablecoinCreate proposal with the exact V1 bond.
    Propose {
        /// Immutable token name (1..64 UTF-8 bytes).
        #[arg(long)]
        name: String,
        /// Canonical global ticker (2..12 ASCII uppercase letters/digits).
        #[arg(long)]
        ticker: String,
        /// ISO-4217 numeric currency code.
        #[arg(long)]
        iso4217: u16,
        /// Token decimals.
        #[arg(long, default_value_t = 6)]
        decimals: u8,
        /// Maximum supply in smallest token units.
        #[arg(long)]
        supply_cap: U256,
        /// Existing shared policy id.
        #[arg(long, default_value = "1")]
        policy_id: U256,
    },
}

impl StablecoinCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::PolicyCreate { policy_type, admin } => {
                create_policy(client, private_key, policy_type, admin).await
            }
            Self::Predict {
                chain_id,
                issuer,
                ticker,
            } => predict(chain_id, issuer, &ticker),
            Self::Propose {
                name,
                ticker,
                iso4217,
                decimals,
                supply_cap,
                policy_id,
            } => {
                propose(
                    client,
                    private_key,
                    ProposalArgs {
                        name,
                        ticker,
                        iso4217,
                        decimals,
                        supply_cap,
                        policy_id,
                    },
                )
                .await
            }
        }
    }
}

async fn create_policy(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    policy_type: PolicyKind,
    admin: Option<Address>,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let admin = admin.unwrap_or_else(|| signer.address());
    if admin.is_zero() {
        eyre::bail!("policy admin must not be the zero address");
    }

    let call = IStablecoinPolicyRegistry::createPolicyCall {
        policyType: policy_type.as_u8(),
        admin,
    };
    let tx_hash = signer
        .send_tx(
            client,
            STABLECOIN_POLICY_REGISTRY_ADDRESS,
            call.abi_encode(),
            U256::ZERO,
        )
        .await?;
    println!(
        "Policy creation transaction sent: {tx_hash} (type={}, admin={admin})",
        policy_type.as_u8()
    );
    Ok(())
}

fn predict(chain_id: u64, issuer: Address, ticker: &str) -> Result<()> {
    let (token_id, token) = predict_identity(chain_id, issuer, ticker)?;
    println!("Token id: {token_id}");
    println!("Token address: {token}");
    Ok(())
}

fn predict_identity(chain_id: u64, issuer: Address, ticker: &str) -> Result<(B256, Address)> {
    predict_stablecoin(
        chain_id,
        STABLECOIN_FACTORY_ADDRESS,
        issuer,
        ticker,
        STABLECOIN_ADDRESS_PREFIX,
    )
    .wrap_err("invalid stablecoin identity")
}

struct ProposalArgs {
    name: String,
    ticker: String,
    iso4217: u16,
    decimals: u8,
    supply_cap: U256,
    policy_id: U256,
}

async fn propose(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    args: ProposalArgs,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let payload = StablecoinCreatePayload {
        issuer: signer.address(),
        name: args.name,
        ticker: args.ticker,
        iso4217: args.iso4217,
        decimals: args.decimals,
        supply_cap: args.supply_cap,
        policy_id: args.policy_id,
    };
    let canonical = encode_canonical_stablecoin_create(&payload)
        .wrap_err("invalid StablecoinCreate proposal")?;
    let canonical_json =
        String::from_utf8(canonical).wrap_err("canonical proposal was not UTF-8")?;

    println!("Canonical proposal: {canonical_json}");
    println!(
        "Canonical bytes: 0x{}",
        hex::encode(canonical_json.as_bytes())
    );
    println!(
        "Supply cap: {} base units ({} {})",
        payload.supply_cap,
        format_token_amount(payload.supply_cap, payload.decimals),
        payload.ticker
    );
    println!("Proposal bond: {STABLECOIN_CREATE_BOND} base units");
    println!("WARNING: {NON_ENDORSEMENT_WARNING}");

    let call = IVote::createProposalCall {
        targetModule: STABLECOIN_FACTORY_ADDRESS,
        payload: canonical_json,
    };
    let tx_hash = signer
        .send_tx(
            client,
            VOTE_ADDRESS,
            call.abi_encode(),
            STABLECOIN_CREATE_BOND,
        )
        .await?;
    println!("Stablecoin proposal transaction sent: {tx_hash}");
    Ok(())
}

fn format_token_amount(value: U256, decimals: u8) -> String {
    if decimals == 0 {
        return value.to_string();
    }

    let divisor = U256::from(10).pow(U256::from(decimals));
    let whole = value / divisor;
    let fraction = value % divisor;
    if fraction.is_zero() {
        return whole.to_string();
    }

    let fraction = format!("{fraction:0>width$}", width = usize::from(decimals));
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rpc::mock::{recording_send_tx_rpc, RecordingRpc},
        Cli,
    };
    use alloy_primitives::address;
    use clap::Parser;

    static PRIVATE_KEY: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| outbe_primitives::test_keys::hex(1));

    #[test]
    fn parses_policy_predict_and_propose_commands() {
        assert!(Cli::try_parse_from([
            "outbe-cli",
            "stablecoin",
            "policy-create",
            "--policy-type",
            "whitelist",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "outbe-cli",
            "stablecoin",
            "predict",
            "--chain-id",
            "1337",
            "--issuer",
            "0x1111111111111111111111111111111111111111",
            "--ticker",
            "EXUSD",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "outbe-cli",
            "stablecoin",
            "propose",
            "--name",
            "Example Dollar",
            "--ticker",
            "EXUSD",
            "--iso4217",
            "840",
            "--supply-cap",
            "1000000000000",
        ])
        .is_ok());
    }

    #[tokio::test]
    async fn policy_create_sends_zero_value_registry_call() {
        let signer = super::super::require_signer(Some(&PRIVATE_KEY)).unwrap();
        let call = IStablecoinPolicyRegistry::createPolicyCall {
            policyType: 2,
            admin: signer.address(),
        };
        let rpc = recording_send_tx_rpc(
            &PRIVATE_KEY,
            STABLECOIN_POLICY_REGISTRY_ADDRESS,
            call.abi_encode(),
            U256::ZERO,
        )
        .unwrap();

        StablecoinCmd::PolicyCreate {
            policy_type: PolicyKind::Whitelist,
            admin: None,
        }
        .run(&rpc, Some(&PRIVATE_KEY))
        .await
        .unwrap();
        rpc.assert_done();
    }

    #[tokio::test]
    async fn proposal_uses_canonical_golden_bytes_and_exact_bond() {
        let signer = super::super::require_signer(Some(&PRIVATE_KEY)).unwrap();
        let golden = "{\"version\":1,\"kind\":\"StablecoinCreate\",\"issuer\":\"__ISSUER__\",\"name\":\"Example Dollar\",\"ticker\":\"EXUSD\",\"iso4217\":840,\"decimals\":6,\"supplyCap\":\"1000000000000\",\"policyId\":\"1\"}".replace("__ISSUER__", &format!("{:#x}", signer.address()));
        let call = IVote::createProposalCall {
            targetModule: STABLECOIN_FACTORY_ADDRESS,
            payload: golden.to_owned(),
        };
        let rpc = recording_send_tx_rpc(
            &PRIVATE_KEY,
            VOTE_ADDRESS,
            call.abi_encode(),
            STABLECOIN_CREATE_BOND,
        )
        .unwrap();

        let cli = Cli::try_parse_from([
            "outbe-cli",
            "--private-key",
            &PRIVATE_KEY,
            "stablecoin",
            "propose",
            "--name",
            "Example Dollar",
            "--ticker",
            "EXUSD",
            "--iso4217",
            "840",
            "--supply-cap",
            "1000000000000",
        ])
        .unwrap();
        let crate::Commands::Stablecoin { cmd } = cli.command else {
            panic!("expected stablecoin command");
        };
        cmd.run(&rpc, cli.private_key.as_deref()).await.unwrap();
        rpc.assert_done();
    }

    #[tokio::test]
    async fn invalid_proposal_fails_before_any_rpc_call() {
        let rpc = RecordingRpc::new([]);
        let error = StablecoinCmd::Propose {
            name: "Example Dollar".to_owned(),
            ticker: "bad".to_owned(),
            iso4217: 840,
            decimals: 6,
            supply_cap: U256::from(1_000_000u64),
            policy_id: U256::from(1),
        }
        .run(&rpc, Some(&PRIVATE_KEY))
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("invalid StablecoinCreate proposal"));
        assert!(rpc.recorded_calls().is_empty());
        rpc.assert_done();
    }

    #[test]
    fn formats_supply_cap_using_token_decimals() {
        assert_eq!(format_token_amount(U256::from(1_000_000u64), 6), "1");
        assert_eq!(format_token_amount(U256::from(1_234_500u64), 6), "1.2345");
        assert_eq!(format_token_amount(U256::from(42u64), 0), "42");
    }

    #[test]
    fn prediction_matches_independent_current_namespace_vector() {
        let (token_id, token) = predict_identity(
            1,
            address!("0x1111111111111111111111111111111111111111"),
            "EXUSD",
        )
        .unwrap();
        assert_eq!(
            token_id,
            "0x2cf34bcaf12fe89ab2f3f6f34667f667dc28c8716bdac45fd1696b34000f2863"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            token,
            address!("0x53c0f667dc28c8716bdac45fd1696b34000f2863")
        );
    }
}
