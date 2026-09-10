//! Error type for the vaultrouter precompile.
//!
//! Mirrors the custom errors of the Solidity vault-router interfaces plus
//! the `ErrorsLib` reverts the original contract used (`ZeroAddress`,
//! `Unauthorized`). Following the repo convention, precompile reverts carry a
//! string reason rather than an ABI-encoded custom-error selector.

use alloy_primitives::{Address, U256};
use outbe_primitives::error::PrecompileError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VaultRouterError {
    #[error("zero address")]
    ZeroAddress,
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid liquidity source")]
    InvalidLiquiditySource,
    #[error("invalid liquidity target")]
    InvalidLiquidityTarget,
    #[error("reserve vault not configured")]
    ReserveVaultNotConfigured,
    #[error("reserve vault already added")]
    ReserveVaultAlreadyAdded,
    #[error("reserve vault not found")]
    ReserveVaultNotFound,
    #[error("reserve vault owner not renounced: {0}")]
    ReserveVaultOwnerNotRenounced(Address),
    #[error("liquidity source not found")]
    LiquiditySourceNotFound,
    #[error("liquidity target not found")]
    LiquidityTargetNotFound,
    #[error("invalid destination chain")]
    InvalidDestinationChain,
    #[error("crosschain bridge not configured")]
    CrosschainBridgeNotConfigured,
    #[error("crosschain asset not configured")]
    CrosschainAssetNotConfigured,
    #[error("crosschain token bridge not configured")]
    CrosschainTokenBridgeNotConfigured,
    #[error("remote vault router not configured for chain {0}")]
    RemoteVaultRouterNotConfigured(U256),
    #[error("crosschain fee mismatch: provided={provided}, required={required}")]
    CrosschainFeeMismatch { provided: U256, required: U256 },
    #[error("invalid crosschain amount")]
    InvalidCrosschainAmount,
    #[error("crosschain operation not found")]
    CrosschainOperationNotFound,
    #[error("crosschain operation already exists")]
    CrosschainOperationAlreadyExists,
    #[error("crosschain operation already completed")]
    CrosschainOperationAlreadyCompleted,
    #[error("crosschain operations pending: {0}")]
    CrosschainOperationsPending(U256),
    #[error("invalid crosschain sender")]
    InvalidCrosschainSender,
    #[error("invalid crosschain callback")]
    InvalidCrosschainCallback,
    #[error("crosschain domain exceeds uint32")]
    CrosschainDomainTooLarge,
    #[error("insufficient crosschain shares: available={available}, required={required}")]
    InsufficientCrosschainShares { available: U256, required: U256 },
    #[error("insufficient shares for withdraw: available={available}, required={required}")]
    InsufficientSharesForWithdraw { available: U256, required: U256 },
    #[error("token bundle receiver is not a deployed contract")]
    ReceiverNotDeployed,
    #[error("undecodable sub-call return: {0}")]
    UndecodableReturn(&'static str),
    #[error("same vault rebalance")]
    SameVaultRebalance,
    #[error("invalid rebalance amount")]
    InvalidRebalanceAmount,
    #[error("rebalance vault not registered: {0}")]
    RebalanceVaultNotRegistered(Address),
    #[error("rebalance input exceeds max: required={required}, max_amount_to={max_amount_to}")]
    RebalanceInputExceedsMax { required: U256, max_amount_to: U256 },
    #[error("unsupported asset decimals: {0}")]
    UnsupportedAssetDecimals(u8),
    #[error("cca not active: {0}")]
    CcaNotActive(Address),
}

impl From<VaultRouterError> for PrecompileError {
    fn from(err: VaultRouterError) -> Self {
        PrecompileError::Revert(err.to_string())
    }
}
