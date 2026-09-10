//! Orchestration logic for the promisfactory precompile.
//!
//! Owns the promis mint/burn orchestration on top of the confidential Promis token
//! (`outbe_promis::api`). Writes are authorized by the caller's Promis modify key
//! (`mac` + `opNonce`). `mint` wraps `outbe_promis::api::mint`; `mine_coen` is the
//! symmetric sale path: it wraps `outbe_promis::api::burn`, mints native COEN 1:1,
//! and emits `RudisMined`. `mine_gratis` is the conversion path: it burns promis and
//! mints the matching Gratis through `outbe_gratisfactory::api::mint`.

use alloy_primitives::{Address, U256};

use crate::precompile::IPromisFactory;
use outbe_primitives::addresses::PROMIS_FACTORY_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::checked_protocol_to_native;
use outbe_promis::api::{self as promis, ModifyAuth};

/// Mint `amount` promis to `account` (authorized by the account owner's modify
/// key). The `PromisMinted` event is emitted by the Promis token.
///
/// Internal cross-module API (not exposed on the precompile ABI). The production
/// callers are GemFactory's and IntexFactory's mine paths, which delegate the
/// matching promis mint here.
pub fn mint(
    storage: StorageHandle<'_>,
    account: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<()> {
    promis::mint(storage, account, amount, auth)
}

/// Burn `amount` promis from `account`, mint the matching native COEN to `account`
/// 1:1, and emit `RudisMined`. Returns the minted native amount. The confidential
/// burn runs inside the enclave and is authorized by the caller's Promis modify
/// key (`auth`).
pub fn mine_coen(
    storage: StorageHandle<'_>,
    account: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<U256> {
    let native_amount = checked_protocol_to_native(amount)
        .ok_or_else(|| PrecompileError::Revert("native rudis amount overflow".into()))?;

    promis::burn(storage.clone(), account, amount, auth)?;

    // PROMIS stays at six decimals; the matching native COEN exits at 18 decimals.
    storage.increase_balance(account, native_amount)?;

    storage.emit_event(
        PROMIS_FACTORY_ADDRESS,
        alloy_sol_types::SolEvent::encode_log_data(&IPromisFactory::RudisMined {
            sender: account,
            amount: native_amount,
        }),
    )?;

    Ok(native_amount)
}

/// Burn `amount` confidential promis from `account` and mint the matching Gratis
/// 1:1. Both tokens are enclave-confidential and independently keyed: the promis
/// burn takes the account owner's **Promis** modify key (`promis_auth`) and the
/// gratis mint takes their **Gratis** modify key (`gratis_auth`). Each `auth`
/// binds `amount` to that ledger's own current op-nonce, so the caller supplies
/// two `mac`/`opNonce` pairs.
pub fn mine_gratis(
    storage: StorageHandle<'_>,
    account: Address,
    amount: U256,
    promis_auth: ModifyAuth,
    gratis_auth: ModifyAuth,
) -> Result<U256> {
    promis::burn(storage.clone(), account, amount, promis_auth)?;

    // The gratis mint records a fresh Fidelity acquisition cohort at the current
    // block time, as every gratis acquisition does.
    outbe_gratisfactory::api::mint(storage, account, amount, gratis_auth)?;

    Ok(amount)
}
