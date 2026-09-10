//! ABI dispatch for the vaultrouter precompile at `VAULT_ROUTER_ADDRESS`.

#[cfg(test)]
use alloy_primitives::FixedBytes;
use alloy_primitives::{Address, Bytes, U256};
#[cfg(test)]
use alloy_sol_types::SolCall;
use alloy_sol_types::SolInterface;

use outbe_primitives::dispatch::{dispatch_call, mutate, mutate_void, view};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::types::StorageSet;
use outbe_primitives::storage::StorageHandle;

use crate::api::IVaultRouter;
#[cfg(test)]
use crate::api::IVaultRouterCrosschainExtention as CrosschainExt;
#[cfg(test)]
use crate::crosschain;
use crate::runtime;
use crate::schema::VaultRouterContract;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
///
/// Empty because only `dispatch_local` is wired. The crosschain extension
/// declares three payable selectors in its interface and forwards their value on
/// as a bridge fee; enabling it behind the gate below means listing them here
/// and flipping this address to a payable route in the same change.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

pub fn dispatch(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    // TODO(crosschain): Enable `IVaultRouterCrosschainExtention` only through an explicit
    // feature/configuration gate, then route its selectors to `dispatch_crosschain`.
    // Until that opt-in exists, the deployed precompile exposes only `IVaultRouter`.
    dispatch_local(storage, data, caller, value)
}

fn dispatch_local(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    dispatch_call(data, IVaultRouter::IVaultRouterCalls::abi_decode, |call| {
        use IVaultRouter::IVaultRouterCalls::*;
        outbe_primitives::dispatch::reject_value(&value)?;
        match call {
            // --- admin / metadata views ---
            owner(c) => view(c, |_c| {
                let contract = VaultRouterContract::new(storage.clone());
                contract.owner.read()
            }),

            // --- asset and reference-currency enumeration ---
            assetsCount(c) => view(c, |_c| {
                let contract = VaultRouterContract::new(storage.clone());
                Ok(U256::from(contract.assets.len()?))
            }),
            assetAt(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                set_at(&contract.assets, c.index)
            }),
            assetVaultsCount(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                Ok(U256::from(contract.asset_vault_set(c.asset).len()?))
            }),
            assetVaultAt(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                set_at(&contract.asset_vault_set(c.asset), c.index)
            }),
            referenceCurrencyVaultsCount(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                Ok(U256::from(
                    contract.reference_currency_vault_set(c.isoCode).len()?,
                ))
            }),
            referenceCurrencyVaultAt(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                set_at(&contract.reference_currency_vault_set(c.isoCode), c.index)
            }),
            vaultReferenceCurrency(c) => view(c, |c| {
                VaultRouterContract::new(storage.clone())
                    .vault_reference_currencies
                    .read(&c.vault)
            }),
            referenceCurrencyAssets(c) => view(c, |c| {
                runtime::reference_currency_assets(&storage, c.isoCode)
            }),

            // --- liquidity source / target enumeration ---
            liquiditySourcesCount(c) => view(c, |_c| {
                let contract = VaultRouterContract::new(storage.clone());
                Ok(U256::from(contract.liquidity_sources.len()?))
            }),
            liquiditySourceAt(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                let addr = set_at(&contract.liquidity_sources, c.index)?;
                let type_u8 = contract.liquidity_source_types.read(&addr)?;
                Ok(IVaultRouter::liquiditySourceAtReturn {
                    sourceAddress: addr,
                    sourceType: IVaultRouter::StablesSource::try_from(type_u8)
                        .unwrap_or(IVaultRouter::StablesSource::Unknown),
                })
            }),
            liquidityTargetsCount(c) => view(c, |_c| {
                let contract = VaultRouterContract::new(storage.clone());
                Ok(U256::from(contract.liquidity_targets.len()?))
            }),
            liquidityTargetAt(c) => view(c, |c| {
                let contract = VaultRouterContract::new(storage.clone());
                let addr = set_at(&contract.liquidity_targets, c.index)?;
                let type_u8 = contract.liquidity_target_types.read(&addr)?;
                Ok(IVaultRouter::liquidityTargetAtReturn {
                    targetAddress: addr,
                    targetType: IVaultRouter::StablesTarget::try_from(type_u8)
                        .unwrap_or(IVaultRouter::StablesTarget::Unknown),
                })
            }),

            // --- vault management (owner-only) ---
            addVault(c) => mutate_void(c, caller, |sender, c| {
                runtime::add_vault(storage.clone(), sender, c.vault)
            }),
            removeVault(c) => mutate_void(c, caller, |sender, c| {
                runtime::remove_vault(storage.clone(), sender, c.vault)
            }),

            // --- liquidity source / target management (owner-only) ---
            addLiquiditySource(c) => mutate_void(c, caller, |sender, c| {
                runtime::add_liquidity_source(
                    storage.clone(),
                    sender,
                    c.sourceAddress,
                    c.sourceType as u8,
                )
            }),
            removeLiquiditySource(c) => mutate_void(c, caller, |sender, c| {
                runtime::remove_liquidity_source(storage.clone(), sender, c.sourceAddress)
            }),
            addLiquidityTarget(c) => mutate_void(c, caller, |sender, c| {
                runtime::add_liquidity_target(
                    storage.clone(),
                    sender,
                    c.targetAddress,
                    c.targetType as u8,
                )
            }),
            removeLiquidityTarget(c) => mutate_void(c, caller, |sender, c| {
                runtime::remove_liquidity_target(storage.clone(), sender, c.targetAddress)
            }),

            // --- liquidity flow (source/target-gated against the registry) ---
            deposit(c) => mutate(c, caller, |sender, c| {
                let source = runtime::registered_liquidity_source(&storage, sender)?;
                runtime::deposit(storage.clone(), sender, c.asset, c.assetsAmount, source)
            }),
            withdraw(c) => mutate(c, caller, |sender, c| {
                let target = runtime::registered_liquidity_target(&storage, sender)?;
                runtime::withdraw(
                    storage.clone(),
                    sender,
                    c.asset,
                    c.amount,
                    c.receiver,
                    target,
                )
            }),

            // --- views over external state ---
            sharesBalance(c) => view(c, |c| runtime::shares_balance(&storage, c.vault)),

            // --- rebalance (CCA-gated; caller supplies the destination asset) ---
            rebalance(c) => mutate(c, caller, |sender, c| {
                runtime::rebalance(
                    storage.clone(),
                    sender,
                    c.vaultFrom,
                    c.vaultTo,
                    c.assetsAmount,
                    c.maxAmountTo,
                )
            }),
            previewRebalance(c) => view(c, |c| {
                let (asset_from, asset_to, amount_to) =
                    runtime::preview_rebalance(&storage, c.vaultFrom, c.vaultTo, c.assetsAmount)?;
                Ok(IVaultRouter::previewRebalanceReturn {
                    assetFrom: asset_from,
                    assetTo: asset_to,
                    amountTo: amount_to,
                })
            }),
        }
    })
}

#[cfg(test)]
pub(crate) fn dispatch_crosschain(
    storage: StorageHandle<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    dispatch_call(
        data,
        CrosschainExt::IVaultRouterCrosschainExtentionCalls::abi_decode,
        |call| {
            use CrosschainExt::IVaultRouterCrosschainExtentionCalls::*;
            if !matches!(
                &call,
                crosschainDeposit(_) | crosschainWithdraw(_) | receiveMessage(_)
            ) {
                outbe_primitives::dispatch::reject_value(&value)?;
            }
            match call {
                // --- fixed cross-chain peer configuration ---
                crosschainBridge(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .crosschain_bridge
                        .read()
                }),
                remoteVaultRouter(c) => view(c, |c| {
                    VaultRouterContract::new(storage.clone())
                        .remote_vault_routers
                        .read(&c.chainId)
                }),
                setCrosschainBridge(c) => mutate_void(c, caller, |sender, c| {
                    runtime::set_crosschain_bridge(storage.clone(), sender, c.bridge)
                }),
                setRemoteVaultRouter(c) => mutate_void(c, caller, |sender, c| {
                    runtime::set_remote_vault_router(storage.clone(), sender, c.chainId, c.router)
                }),

                // --- fixed cross-chain WCOEN vault flow ---
                crosschainAsset(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .crosschain_asset
                        .read()
                }),
                crosschainTokenBridge(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .crosschain_token_bridge
                        .read()
                }),
                crosschainDestinationChainId(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .crosschain_destination_chain_id
                        .read()
                }),
                setCrosschainAsset(c) => mutate_void(c, caller, |sender, c| {
                    crosschain::set_asset(
                        storage.clone(),
                        sender,
                        c.asset,
                        c.tokenBridge,
                        c.destinationChainId,
                    )
                }),
                crosschainOperationNonce(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .crosschain_operation_nonce
                        .read()
                }),
                pendingCrosschainOperations(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .pending_crosschain_operations
                        .read()
                }),
                crosschainShares(c) => view(c, |c| {
                    VaultRouterContract::new(storage.clone())
                        .crosschain_shares
                        .read(&c.user)
                }),
                totalCrosschainShares(c) => view(c, |_c| {
                    VaultRouterContract::new(storage.clone())
                        .total_crosschain_shares
                        .read()
                }),
                crosschainOperation(c) => view(c, |c| {
                    let contract = VaultRouterContract::new(storage.clone());
                    let kind = contract.operation_kinds.read(&c.operationId)?;
                    let status = contract.operation_statuses.read(&c.operationId)?;
                    Ok(CrosschainExt::crosschainOperationReturn {
                        user: contract.operation_users.read(&c.operationId)?,
                        amount: contract.operation_amounts.read(&c.operationId)?,
                        kind: CrosschainExt::CrosschainOperationKind::try_from(kind)
                            .unwrap_or(CrosschainExt::CrosschainOperationKind::Unknown),
                        status: CrosschainExt::CrosschainOperationStatus::try_from(status)
                            .unwrap_or(CrosschainExt::CrosschainOperationStatus::Unknown),
                    })
                }),
                quoteCrosschainDeposit(c) => view(c, |c| {
                    let (native_fee, operation_id) = crosschain::quote_deposit(
                        &storage,
                        caller,
                        c.assetsAmount,
                        c.destinationGasLimit,
                        c.acknowledgementGasLimit,
                    )?;
                    Ok(CrosschainExt::quoteCrosschainDepositReturn {
                        nativeFee: native_fee,
                        operationId: operation_id,
                    })
                }),
                crosschainDeposit(c) => mutate(c, caller, |user, c| {
                    let (operation_id, send_id) = crosschain::deposit(
                        storage.clone(),
                        user,
                        c.assetsAmount,
                        c.destinationGasLimit,
                        c.acknowledgementGasLimit,
                        value,
                    )?;
                    Ok(CrosschainExt::crosschainDepositReturn {
                        operationId: operation_id,
                        sendId: send_id,
                    })
                }),
                quoteCrosschainWithdraw(c) => view(c, |c| {
                    let (native_fee, operation_id) = crosschain::quote_withdraw(
                        &storage,
                        caller,
                        c.sharesAmount,
                        c.requestGasLimit,
                        c.returnGasLimit,
                    )?;
                    Ok(CrosschainExt::quoteCrosschainWithdrawReturn {
                        nativeFee: native_fee,
                        operationId: operation_id,
                    })
                }),
                crosschainWithdraw(c) => mutate(c, caller, |user, c| {
                    let (operation_id, send_id) = crosschain::withdraw(
                        storage.clone(),
                        user,
                        c.sharesAmount,
                        c.requestGasLimit,
                        c.returnGasLimit,
                        value,
                    )?;
                    Ok(CrosschainExt::crosschainWithdrawReturn {
                        operationId: operation_id,
                        sendId: send_id,
                    })
                }),
                receiveMessage(c) => mutate(c, caller, |_bridge, c| {
                    crosschain::receive_deposit_acknowledgement(
                        storage.clone(),
                        caller,
                        value,
                        &c.sender,
                        &c.payload,
                    )?;
                    Ok(FixedBytes::<4>::from_slice(
                        &CrosschainExt::receiveMessageCall::SELECTOR,
                    ))
                }),
                onCrosschainTokensReceived(c) => mutate(c, caller, |_token_bridge, c| {
                    crosschain::receive_withdrawal_return(
                        storage.clone(),
                        caller,
                        c.sourceDomain,
                        &c.from,
                        c.amount,
                        &c.extraData,
                    )?;
                    Ok(FixedBytes::<4>::from_slice(
                        &CrosschainExt::onCrosschainTokensReceivedCall::SELECTOR,
                    ))
                }),
            }
        },
    )
}

/// Reads the set element at `index`, reverting (like OZ `EnumerableSet.at`) when
/// out of bounds.
fn set_at(set: &StorageSet<'_, Address>, index: U256) -> Result<Address> {
    let idx =
        u32::try_from(index).map_err(|_| PrecompileError::Revert("index out of bounds".into()))?;
    set.at(idx)?
        .ok_or_else(|| PrecompileError::Revert("index out of bounds".into()))
}
