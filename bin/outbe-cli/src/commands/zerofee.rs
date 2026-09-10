//! ZeroFee paymaster commands.
//!
//! Exposes a connected bootstrap command and an offline-friendly command for
//! signing an EIP-7702 [`Authorization`] tuple that delegates an EOA to the
//! protocol ZeroFee paymaster at
//! [`outbe_primitives::addresses::ZEROFEE_ADDRESS`].
//!
//! The signing path is deliberately *offline-friendly*: it does not
//! contact the RPC node, so an operator can pre-sign authorizations
//! on an air-gapped machine and forward them to a sponsor service
//! over any transport.

use alloy_consensus::TxEip7702;
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Address, Signature, U256};
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::Result;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use serde::Serialize;

use crate::commands::require_signer;
use crate::rpc::Rpc;
use crate::tx::TxSigner;

#[derive(Subcommand)]
pub enum ZeroFeeCmd {
    /// Install the canonical ZeroFee delegation with the one-time
    /// positive-balance bootstrap transaction and print its transaction hash.
    Bootstrap,

    /// Sign an EIP-7702 Authorization delegating the EOA to the
    /// ZeroFee paymaster precompile so it can submit up to
    /// `FREE_TX_DAILY_LIMIT` free transactions per UTC day.
    ///
    /// The output JSON is the inner `SignedAuthorization` body - embed
    /// it in the `authorizationList` of a type-0x04 (Pectra) transaction.
    Eip7702Authorize {
        /// Target address the EOA delegates to. Defaults to the
        /// canonical `ZEROFEE_ADDRESS` precompile; the override
        /// exists for local-testnet scenarios where someone might
        /// re-deploy the paymaster behind a different address.
        #[arg(
            long,
            default_value_t = outbe_primitives::addresses::ZEROFEE_ADDRESS
        )]
        target: Address,

        /// Chain ID for the authorization. Set to 0 for the
        /// "any chain" form, which most production sponsors should
        /// avoid; the default reads from the configured RPC.
        #[arg(long)]
        chain_id: Option<u64>,

        /// EOA nonce to bind the authorization to. The signer's
        /// current nonce on the configured RPC is the safe default -
        /// override only if you know what you are doing.
        #[arg(long)]
        nonce: Option<u64>,
    },
}

impl ZeroFeeCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::Bootstrap => {
                let signer = require_signer(private_key)?;
                let tx_hash = submit_bootstrap(client, &signer).await?;
                println!("{tx_hash}");
                Ok(())
            }
            Self::Eip7702Authorize {
                target,
                chain_id,
                nonce,
            } => {
                let signer = require_signer(private_key)?;
                let chain_id = match chain_id {
                    Some(id) => id,
                    None => fetch_chain_id(client).await?,
                };
                let nonce = match nonce {
                    Some(n) => n,
                    None => fetch_nonce(client, signer.address()).await?,
                };
                sign_and_print_authorization(&signer, target, chain_id, nonce)
            }
        }
    }
}

async fn submit_bootstrap(client: &(impl Rpc + Sync), signer: &TxSigner) -> Result<String> {
    let balance = client.eth_get_balance(signer.address()).await?;
    eyre::ensure!(
        !balance.is_zero(),
        "ZeroFee bootstrap requires a positive balance (at least 0.000001 rudis)"
    );
    let chain_id = client.eth_chain_id().await?;
    let nonce = client.eth_get_transaction_count(signer.address()).await?;
    let raw_transaction = build_bootstrap_raw_transaction(signer, chain_id, nonce)?;
    client.eth_send_raw_transaction(&raw_transaction).await
}

fn build_bootstrap_raw_transaction(
    signer: &TxSigner,
    chain_id: u64,
    nonce: u64,
) -> Result<Vec<u8>> {
    let authorization_nonce = nonce
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("bootstrap authorization nonce overflow"))?;
    let authorization = sign_authorization(
        signer,
        outbe_zerofee::ZEROFEE_ADDRESS,
        chain_id,
        authorization_nonce,
    )?;
    let input = outbe_zerofee::precompile::IZeroFee::authorizeSponsorshipCall {
        signer: signer.address(),
    }
    .abi_encode()
    .into();
    signer.sign_eip7702_tx(TxEip7702 {
        chain_id,
        nonce,
        gas_limit: outbe_zerofee::FREE_TX_BOOTSTRAP_GAS_LIMIT,
        max_fee_per_gas: outbe_zerofee::MIN_FREE_TX_MAX_FEE_PER_GAS,
        max_priority_fee_per_gas: 0,
        to: outbe_zerofee::ZEROFEE_ADDRESS,
        value: U256::ZERO,
        access_list: Default::default(),
        authorization_list: vec![authorization],
        input,
    })
}

/// Wire-format payload that drops verbatim into the `authorizationList`
/// field of a Pectra transaction. Field names match the EIP-7702 JSON
/// schema accepted by viem and `cast wallet sign-auth`. The recovered
/// signer address is intentionally absent - see
/// [`sign_and_print_authorization`] for the rationale.
#[derive(Serialize)]
struct SignedAuthorizationOutput {
    #[serde(rename = "chainId")]
    chain_id: U256,
    address: Address,
    #[serde(rename = "nonce")]
    nonce: u64,
    #[serde(rename = "yParity")]
    y_parity: u8,
    r: U256,
    s: U256,
}

fn sign_and_print_authorization(
    signer: &TxSigner,
    target: Address,
    chain_id: u64,
    nonce: u64,
) -> Result<()> {
    let signed = sign_authorization(signer, target, chain_id, nonce)?;
    let output = SignedAuthorizationOutput {
        chain_id: signed.chain_id,
        address: signed.address,
        nonce: signed.nonce,
        y_parity: signed.y_parity(),
        r: signed.r(),
        s: signed.s(),
    };

    // stdout carries the wire payload only - operators pipe it straight
    // into an `authorizationList` entry. The recovered signer address
    // goes to stderr so it cannot accidentally land in the JSON body
    // (viem 2.x silently ignores unknown fields, which would mask a
    // copy-paste mistake until the malformed tx hits the chain).
    eprintln!(
        "Signed EIP-7702 authorization for signer={} target={}",
        signer.address(),
        target
    );
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn sign_authorization(
    signer: &TxSigner,
    target: Address,
    chain_id: u64,
    nonce: u64,
) -> Result<SignedAuthorization> {
    let auth = Authorization {
        chain_id: U256::from(chain_id),
        address: target,
        nonce,
    };
    let hash = auth.signature_hash();

    let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = signer
        .key()
        .sign_prehash(hash.as_slice())
        .map_err(|e| eyre::eyre!("EIP-7702 authorization signing failed: {e}"))?;

    let sig_bytes = sig.to_bytes();
    let signature =
        Signature::from_bytes_and_parity(&sig_bytes, recid.to_byte() != 0).normalized_s();
    Ok(auth.into_signed(signature))
}

async fn fetch_chain_id(client: &(impl Rpc + Sync)) -> Result<u64> {
    client.eth_chain_id().await
}

async fn fetch_nonce(client: &(impl Rpc + Sync), address: Address) -> Result<u64> {
    client.eth_get_transaction_count(address).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{EthereumTxEnvelope, TxEip4844};
    use alloy_eips::eip2718::Decodable2718 as _;
    use alloy_primitives::address;

    const TEST_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[tokio::test]
    async fn bootstrap_stops_at_zero_balance_before_signing_or_submission() {
        use crate::rpc::mock::{
            ExpectedRpcCall, RecordedRpcCall, RecordedRpcResponse, RecordingRpc,
        };

        let signer = TxSigner::new(TEST_KEY).unwrap();
        let rpc = RecordingRpc::new([ExpectedRpcCall::ok(
            RecordedRpcCall::EthGetBalance {
                address: signer.address(),
            },
            RecordedRpcResponse::U256(U256::ZERO),
        )]);

        let error = submit_bootstrap(&rpc, &signer).await.unwrap_err();
        assert!(error.to_string().contains("at least 0.000001 rudis"));
        rpc.assert_done();
    }

    #[tokio::test]
    async fn bootstrap_reads_state_then_submits_the_exact_raw_transaction() {
        use crate::rpc::mock::{
            ExpectedRpcCall, RecordedRpcCall, RecordedRpcResponse, RecordingRpc,
        };

        let signer = TxSigner::new(TEST_KEY).unwrap();
        let chain_id = 31_337;
        let nonce = 7;
        let raw_tx = build_bootstrap_raw_transaction(&signer, chain_id, nonce).unwrap();
        let rpc = RecordingRpc::new([
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthGetBalance {
                    address: signer.address(),
                },
                RecordedRpcResponse::U256(U256::from(1)),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthChainId,
                RecordedRpcResponse::U64(chain_id),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthGetTransactionCount {
                    address: signer.address(),
                },
                RecordedRpcResponse::U64(nonce),
            ),
            ExpectedRpcCall::ok(
                RecordedRpcCall::EthSendRawTransaction { raw_tx },
                RecordedRpcResponse::Text("0xbootstrap".to_owned()),
            ),
        ]);

        assert_eq!(
            submit_bootstrap(&rpc, &signer).await.unwrap(),
            "0xbootstrap"
        );
        rpc.assert_done();
    }

    #[test]
    fn bootstrap_builder_emits_exact_self_authorized_type4_transaction() {
        let signer = TxSigner::new(TEST_KEY).unwrap();
        let nonce = 7;
        let chain_id = 31_337;
        let raw = build_bootstrap_raw_transaction(&signer, chain_id, nonce).unwrap();
        let mut encoded = raw.as_slice();
        let transaction = EthereumTxEnvelope::<TxEip4844>::decode_2718(&mut encoded).unwrap();
        assert!(encoded.is_empty());
        let EthereumTxEnvelope::Eip7702(signed) = transaction else {
            panic!("bootstrap must be an EIP-7702 type-4 transaction");
        };
        assert_eq!(signed.recover_signer().unwrap(), signer.address());
        let tx = signed.tx();
        assert_eq!(tx.chain_id, chain_id);
        assert_eq!(tx.nonce, nonce);
        assert_eq!(tx.gas_limit, outbe_zerofee::FREE_TX_BOOTSTRAP_GAS_LIMIT);
        assert_eq!(
            tx.max_fee_per_gas,
            outbe_zerofee::MIN_FREE_TX_MAX_FEE_PER_GAS
        );
        assert_eq!(tx.max_priority_fee_per_gas, 0);
        assert_eq!(tx.to, outbe_zerofee::ZEROFEE_ADDRESS);
        assert!(tx.value.is_zero());
        assert!(tx.access_list.is_empty());
        assert_eq!(
            tx.input.as_ref(),
            outbe_zerofee::precompile::IZeroFee::authorizeSponsorshipCall {
                signer: signer.address(),
            }
            .abi_encode()
        );
        let [authorization] = tx.authorization_list.as_slice() else {
            panic!("bootstrap must carry exactly one authorization");
        };
        assert_eq!(authorization.chain_id, U256::from(chain_id));
        assert_eq!(authorization.address, outbe_zerofee::ZEROFEE_ADDRESS);
        assert_eq!(authorization.nonce, nonce + 1);
        assert_eq!(authorization.recover_authority().unwrap(), signer.address());
    }

    #[test]
    fn signed_output_serializes_with_camelcase_keys() {
        let out = SignedAuthorizationOutput {
            chain_id: U256::from(1u8),
            address: address!("0x000000000000000000000000000000000000ee09"),
            nonce: 7,
            y_parity: 1,
            r: U256::from(0x42u8),
            s: U256::from(0x43u8),
        };
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"chainId\""));
        assert!(json.contains("\"yParity\""));
        assert!(json.contains("\"nonce\":7"));
        assert!(
            !json.contains("signer"),
            "signer field must NOT appear in wire payload (paste-into-tx footgun)"
        );
    }
}
