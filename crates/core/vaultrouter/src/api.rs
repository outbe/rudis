//! Public Solidity ABI of the vaultrouter precompile, plus thin typed helpers
//! that hide the EVM sub-call to `VAULT_ROUTER_ADDRESS`.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolCall};

use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;

sol!("../../../contracts/precompiles/src/IVaultRouter.sol");
sol!("../../../contracts/precompiles/src/IVaultRouterCrosschainExtention.sol");

/// `deposit`: deposit `amount` of `asset` into its reserve vault via an
/// EVM sub-call to the vault router, returning the minted shares.
pub fn deposit(storage: &StorageHandle<'_>, asset: Address, amount: U256) -> Result<U256> {
    let ret = storage.call(
        VAULT_ROUTER_ADDRESS,
        U256::ZERO,
        IVaultRouter::depositCall {
            asset,
            assetsAmount: amount,
        }
        .abi_encode()
        .into(),
    )?;
    IVaultRouter::depositCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("deposit undecodable".into()))
}

/// `referenceCurrencyAssets`: every asset registered under an ISO 4217 code.
/// Read-only, so this uses a staticcall. Order is not stable across removals.
pub fn reference_currency_assets(
    storage: &StorageHandle<'_>,
    iso_code: u16,
) -> Result<Vec<Address>> {
    let ret = storage.staticcall(
        VAULT_ROUTER_ADDRESS,
        IVaultRouter::referenceCurrencyAssetsCall { isoCode: iso_code }
            .abi_encode()
            .into(),
    )?;
    IVaultRouter::referenceCurrencyAssetsCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("referenceCurrencyAssets undecodable".into()))
}

/// `withdraw`: redeem `amount` of `asset` from its reserve vault and top
/// it up into `receiver` via an EVM sub-call to the vault router, returning the
/// burned shares.
pub fn withdraw(
    storage: &StorageHandle<'_>,
    asset: Address,
    amount: U256,
    receiver: Address,
) -> Result<U256> {
    let ret = storage.call(
        VAULT_ROUTER_ADDRESS,
        U256::ZERO,
        IVaultRouter::withdrawCall {
            asset,
            amount,
            receiver,
        }
        .abi_encode()
        .into(),
    )?;
    IVaultRouter::withdrawCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("withdraw undecodable".into()))
}

/// Quotes a WCOEN deposit into the fixed remote vault and previews its
/// operation id.
pub fn quote_crosschain_deposit(
    storage: &StorageHandle<'_>,
    assets_amount: U256,
    destination_gas_limit: U256,
    acknowledgement_gas_limit: U256,
) -> Result<(U256, B256)> {
    let ret = storage.call(
        VAULT_ROUTER_ADDRESS,
        U256::ZERO,
        IVaultRouterCrosschainExtention::quoteCrosschainDepositCall {
            assetsAmount: assets_amount,
            destinationGasLimit: destination_gas_limit,
            acknowledgementGasLimit: acknowledgement_gas_limit,
        }
        .abi_encode()
        .into(),
    )?;
    let decoded =
        IVaultRouterCrosschainExtention::quoteCrosschainDepositCall::abi_decode_returns(&ret)
            .map_err(|_| PrecompileError::Revert("quoteCrosschainDeposit undecodable".into()))?;
    Ok((decoded.nativeFee, decoded.operationId))
}

/// Locks WCOEN on Outbe and starts the fixed remote-vault deposit. `value`
/// must equal the current quoted native token-bridge fee.
pub fn crosschain_deposit(
    storage: &StorageHandle<'_>,
    assets_amount: U256,
    destination_gas_limit: U256,
    acknowledgement_gas_limit: U256,
    value: U256,
) -> Result<(B256, B256)> {
    let ret = storage.call(
        VAULT_ROUTER_ADDRESS,
        value,
        IVaultRouterCrosschainExtention::crosschainDepositCall {
            assetsAmount: assets_amount,
            destinationGasLimit: destination_gas_limit,
            acknowledgementGasLimit: acknowledgement_gas_limit,
        }
        .abi_encode()
        .into(),
    )?;
    let decoded = IVaultRouterCrosschainExtention::crosschainDepositCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("crosschainDeposit undecodable".into()))?;
    Ok((decoded.operationId, decoded.sendId))
}

/// Quotes a 1:1 receipt-share withdrawal from the fixed remote vault and
/// previews its operation id.
pub fn quote_crosschain_withdraw(
    storage: &StorageHandle<'_>,
    shares_amount: U256,
    request_gas_limit: U256,
    return_gas_limit: U256,
) -> Result<(U256, B256)> {
    let ret = storage.call(
        VAULT_ROUTER_ADDRESS,
        U256::ZERO,
        IVaultRouterCrosschainExtention::quoteCrosschainWithdrawCall {
            sharesAmount: shares_amount,
            requestGasLimit: request_gas_limit,
            returnGasLimit: return_gas_limit,
        }
        .abi_encode()
        .into(),
    )?;
    let decoded =
        IVaultRouterCrosschainExtention::quoteCrosschainWithdrawCall::abi_decode_returns(&ret)
            .map_err(|_| PrecompileError::Revert("quoteCrosschainWithdraw undecodable".into()))?;
    Ok((decoded.nativeFee, decoded.operationId))
}

/// Locks/burns the caller's mirrored 1:1 receipt shares and requests the
/// corresponding WCOEN back from the fixed remote vault. `value` must equal
/// the current quoted generic-bridge fee.
pub fn crosschain_withdraw(
    storage: &StorageHandle<'_>,
    shares_amount: U256,
    request_gas_limit: U256,
    return_gas_limit: U256,
    value: U256,
) -> Result<(B256, B256)> {
    let ret = storage.call(
        VAULT_ROUTER_ADDRESS,
        value,
        IVaultRouterCrosschainExtention::crosschainWithdrawCall {
            sharesAmount: shares_amount,
            requestGasLimit: request_gas_limit,
            returnGasLimit: return_gas_limit,
        }
        .abi_encode()
        .into(),
    )?;
    let decoded = IVaultRouterCrosschainExtention::crosschainWithdrawCall::abi_decode_returns(&ret)
        .map_err(|_| PrecompileError::Revert("crosschainWithdraw undecodable".into()))?;
    Ok((decoded.operationId, decoded.sendId))
}
