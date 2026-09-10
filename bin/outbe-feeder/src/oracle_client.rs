//! Oracle client for interacting with the chain via alloy provider + signer.
//!
//! Uses alloy's `ProviderBuilder` with a local ECDSA wallet for
//! production-like transaction signing and submission.

use alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use eyre::{Context, Result};

use crate::abi::{IOracle, IValidatorSet};
use crate::config::AccountConfig;

/// Oracle precompile address (0xEE05).
const ORACLE_ADDRESS: Address =
    alloy_primitives::address!("0x000000000000000000000000000000000000EE05");
/// Validator set precompile address (0xEE00).
const VALIDATOR_SET_ADDRESS: Address =
    alloy_primitives::address!("0x000000000000000000000000000000000000EE00");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OracleParams {
    vote_period: u64,
    enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AggregateVoteState {
    exists: bool,
}

/// Creates an EthereumWallet from config. Call once at startup, reuse for all submissions.
pub fn create_wallet(account: &AccountConfig) -> Result<EthereumWallet> {
    let signer: PrivateKeySigner = account
        .private_key
        .parse()
        .with_context(|| "invalid private key")?;
    Ok(EthereumWallet::from(signer))
}

/// Fetches the current block number.
pub async fn get_block_number(rpc_endpoint: &str) -> Result<u64> {
    let provider = ProviderBuilder::new()
        .connect_http(rpc_endpoint.parse().with_context(|| "invalid RPC URL")?);
    let number = provider
        .get_block_number()
        .await
        .with_context(|| "eth_blockNumber failed")?;
    Ok(number)
}

/// Submits an oracle vote as a signed EIP-1559 transaction.
///
/// Uses a pre-created wallet (from `create_wallet`) to avoid re-parsing the
/// private key on every submission.
pub async fn submit_vote(
    rpc_endpoint: &str,
    wallet: &EthereumWallet,
    chain_id: u64,
    calldata: &[u8],
    gasless_oracle_vote: bool,
) -> Result<String> {
    // Build provider with signer
    let provider = ProviderBuilder::new()
        .wallet(wallet.clone())
        .connect_http(rpc_endpoint.parse().with_context(|| "invalid RPC URL")?);

    // Build transaction with explicit chain_id
    let tx = TransactionRequest::default()
        .to(ORACLE_ADDRESS)
        .input(Bytes::copy_from_slice(calldata).into())
        .gas_limit(1_000_000);
    let mut tx = tx;
    tx.set_chain_id(chain_id);

    if gasless_oracle_vote {
        let fee_cap = zero_fee_max_fee_cap(provider.get_gas_price().await.ok());
        tx = tx.max_fee_per_gas(fee_cap).max_priority_fee_per_gas(0);
        tracing::debug!(
            max_fee_per_gas = fee_cap,
            "submitting oracle vote through ZeroFee txpool policy"
        );
    }

    // Send - alloy handles nonce, gas estimation, signing, and broadcasting.
    // Gasless votes remain normal signed EVM transactions. The fee cap is still
    // set high enough for Reth's public txpool protocol checks, while the node's
    // ZeroFee policy waives native fee debit after revalidating signer and state.
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| eyre::eyre!("oracle vote tx failed: {e:#}"))?;

    let tx_hash = *pending.tx_hash();

    // Wait for inclusion to avoid txpool accumulation.
    let receipt = tokio::time::timeout(std::time::Duration::from_secs(30), pending.get_receipt())
        .await
        .map_err(|_| eyre::eyre!("oracle vote tx timed out waiting for receipt: {tx_hash:#x}"))?
        .map_err(|e| eyre::eyre!("oracle vote receipt failed: {e:#}"))?;

    if !receipt.status() {
        return Err(eyre::eyre!("oracle vote tx reverted: {tx_hash:#x}"));
    }

    Ok(format!("{tx_hash:#x}"))
}

fn zero_fee_max_fee_cap(observed_gas_price: Option<u128>) -> u128 {
    observed_gas_price
        .unwrap_or(MIN_PROTOCOL_BASE_FEE as u128)
        .max(MIN_PROTOCOL_BASE_FEE as u128)
}

/// Preflight check result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreflightResult {
    /// Safe to submit vote.
    Ok,
    /// Should skip this period with reason.
    Skip(String),
}

/// Runs preflight checks before vote submission.
pub async fn preflight_check(
    rpc_endpoint: &str,
    expected_vote_period: u64,
    validator_address: &str,
) -> PreflightResult {
    let url = match rpc_endpoint.parse() {
        Ok(u) => u,
        Err(_) => return PreflightResult::Skip("invalid RPC URL".into()),
    };
    let validator = match validator_address.parse::<Address>() {
        Ok(addr) => addr,
        Err(_) => return PreflightResult::Skip("invalid validator address".into()),
    };
    let provider = ProviderBuilder::new().connect_http(url);

    let params = match read_oracle_params(&provider).await {
        Ok(params) => params,
        Err(e) => return PreflightResult::Skip(format!("preflight getParams failed: {e}")),
    };
    match check_vote_penalty_counter(&provider, validator).await {
        Ok(()) => {}
        Err(e) => {
            return PreflightResult::Skip(format!("preflight getVotePenaltyCounter failed: {e}"))
        }
    };
    match check_validator_status(&provider, validator).await {
        Ok(()) => {}
        Err(e) => {
            return PreflightResult::Skip(format!("preflight validatorByAddress failed: {e}"))
        }
    };
    let aggregate_vote = match read_aggregate_vote(&provider, validator).await {
        Ok(vote) => vote,
        Err(e) => return PreflightResult::Skip(format!("preflight getAggregateVote failed: {e}")),
    };

    evaluate_preflight(expected_vote_period, params, aggregate_vote)
}

async fn read_oracle_params<P: Provider>(provider: &P) -> Result<OracleParams> {
    let output = eth_call(
        provider,
        ORACLE_ADDRESS,
        IOracle::getParamsCall {}.abi_encode(),
    )
    .await
    .with_context(|| "oracle getParams eth_call failed")?;
    let result = IOracle::getParamsCall::abi_decode_returns(&output)
        .with_context(|| "oracle getParams decode failed")?;

    Ok(OracleParams {
        vote_period: result.votePeriod,
        enabled: result.enabled,
    })
}

async fn check_vote_penalty_counter<P: Provider>(provider: &P, validator: Address) -> Result<()> {
    let output = eth_call(
        provider,
        ORACLE_ADDRESS,
        IOracle::getVotePenaltyCounterCall { validator }.abi_encode(),
    )
    .await
    .with_context(|| "oracle getVotePenaltyCounter eth_call failed")?;
    IOracle::getVotePenaltyCounterCall::abi_decode_returns(&output)
        .with_context(|| "oracle getVotePenaltyCounter decode failed")?;
    Ok(())
}

async fn read_aggregate_vote<P: Provider>(
    provider: &P,
    validator: Address,
) -> Result<AggregateVoteState> {
    let output = eth_call(
        provider,
        ORACLE_ADDRESS,
        IOracle::getAggregateVoteCall { validator }.abi_encode(),
    )
    .await
    .with_context(|| "oracle getAggregateVote eth_call failed")?;
    let result = IOracle::getAggregateVoteCall::abi_decode_returns(&output)
        .with_context(|| "oracle getAggregateVote decode failed")?;

    Ok(AggregateVoteState {
        exists: result.exists,
    })
}

async fn check_validator_status<P: Provider>(provider: &P, validator: Address) -> Result<()> {
    let output = eth_call(
        provider,
        VALIDATOR_SET_ADDRESS,
        IValidatorSet::validatorByAddressCall { addr: validator }.abi_encode(),
    )
    .await
    .with_context(|| "validatorByAddress eth_call failed")?;
    IValidatorSet::validatorByAddressCall::abi_decode_returns(&output)
        .with_context(|| "validatorByAddress decode failed")?;

    Ok(())
}

async fn eth_call<P: Provider>(provider: &P, to: Address, calldata: Vec<u8>) -> Result<Bytes> {
    let tx = TransactionRequest::default()
        .to(to)
        .input(Bytes::copy_from_slice(&calldata).into());
    provider.call(tx).await.with_context(|| "eth_call failed")
}

fn evaluate_preflight(
    expected_vote_period: u64,
    params: OracleParams,
    aggregate_vote: AggregateVoteState,
) -> PreflightResult {
    if !params.enabled {
        return PreflightResult::Skip("oracle is disabled".into());
    }
    if params.vote_period != expected_vote_period {
        return PreflightResult::Skip(format!(
            "on-chain vote_period={} != config vote_period={}",
            params.vote_period, expected_vote_period
        ));
    }
    if aggregate_vote.exists {
        return PreflightResult::Skip("validator already voted this period".into());
    }

    PreflightResult::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_params() -> OracleParams {
        OracleParams {
            vote_period: 2,
            enabled: true,
        }
    }

    fn no_vote() -> AggregateVoteState {
        AggregateVoteState { exists: false }
    }

    #[test]
    fn preflight_allows_normal_case() {
        let result = evaluate_preflight(2, ok_params(), no_vote());

        assert_eq!(result, PreflightResult::Ok);
    }

    #[test]
    fn zero_fee_fee_cap_never_goes_below_reth_protocol_minimum() {
        assert_eq!(zero_fee_max_fee_cap(None), MIN_PROTOCOL_BASE_FEE as u128);
        assert_eq!(zero_fee_max_fee_cap(Some(0)), MIN_PROTOCOL_BASE_FEE as u128);
        assert_eq!(zero_fee_max_fee_cap(Some(1_000_000_000)), 1_000_000_000);
    }

    #[test]
    fn preflight_skips_disabled_oracle() {
        let result = evaluate_preflight(
            2,
            OracleParams {
                enabled: false,
                ..ok_params()
            },
            no_vote(),
        );

        assert!(matches!(result, PreflightResult::Skip(reason) if reason == "oracle is disabled"));
    }

    #[test]
    fn preflight_skips_vote_period_mismatch() {
        let result = evaluate_preflight(3, ok_params(), no_vote());

        assert!(matches!(
            result,
            PreflightResult::Skip(reason)
                if reason == "on-chain vote_period=2 != config vote_period=3"
        ));
    }

    #[test]
    fn preflight_skips_existing_vote() {
        let result = evaluate_preflight(2, ok_params(), AggregateVoteState { exists: true });

        assert!(matches!(
            result,
            PreflightResult::Skip(reason) if reason == "validator already voted this period"
        ));
    }
}
