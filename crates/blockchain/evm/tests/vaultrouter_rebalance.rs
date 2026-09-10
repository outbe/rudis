//! EVM-level integration test for `IVaultRouter.rebalance`.
//!
//! The vaultrouter crate's own unit tests stub every sub-call with a fixed
//! payload, so they cannot prove the four real sub-calls `rebalance` makes -
//! `asset.transferFrom`, `vault.deposit`, `vault.withdraw`,
//! `asset.transfer` - actually dispatch through the EVM's own precompile
//! routing and that a failure anywhere in that chain propagates as a revert
//! of the whole call. This test drives the precompile through the actual EVM
//! (`sub_call::run`, which installs the outbe precompile set in the child
//! frame), with two vaults sharing one stubbed asset - `rebalance`'s
//! same-asset path needs no oracle or decimals lookup, so the counterparties
//! can stay minimal raw bytecode, exactly as `paynote_deposit.rs` does for
//! its own counterparties.
//!
//! What this pins that the unit tests cannot:
//!   * a real EOA-style caller reaches `rebalance` through the routed
//!     precompile dispatch, not just through `runtime::rebalance` directly.
//!   * a revert inside the destination asset's `transferFrom` (the caller
//!     has not approved) propagates all the way back as the outer call's
//!     failure, not a silently swallowed error.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
use outbe_compressed_entities::ExecutionScope;
use outbe_evm::sub_call;
use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
use outbe_primitives::{
    block::BlockContext,
    storage::{direct::DirectStorageProvider, StorageHandle, SubCallInput, SubCallStatus},
};
use outbe_vaultrouter::api::IVaultRouter;
use outbe_vaultrouter::VaultRouterContract;
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context,
};

/// The CCA caller. `outbe_cca::api::is_active` is a stub that accepts every
/// address (see its own doc comment), so this needs no registration.
const CCA: Address = Address::new([0x11; 20]);
const ASSET: Address = Address::new([0x33; 20]);
const VAULT_FROM: Address = Address::new([0x55; 20]);
const VAULT_TO: Address = Address::new([0x77; 20]);

const AMOUNT: u64 = 1_000;

/// Minimal ERC-20 stub: returns 32 bytes of `1` for any calldata, i.e.
/// `true` for `transferFrom`/`transfer`.
///
/// `PUSH1 0x01, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN`
const ALWAYS_ONE: [u8; 10] = [0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

/// Reverts unconditionally with an empty reason, for any calldata:
/// `PUSH1 0x00, PUSH1 0x00, REVERT`.
const ALWAYS_REVERT: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];

fn code_account(code: &[u8]) -> AccountInfo {
    let bytecode = Bytecode::new_raw(Bytes::from(code.to_vec()));
    AccountInfo {
        code_hash: bytecode.hash_slow(),
        code: Some(bytecode),
        ..Default::default()
    }
}

/// A vault stub: `asset()` and every other selector (`previewWithdraw`,
/// `balanceOf`, `withdraw`, `deposit`) all answer with the same fixed
/// 32-byte word, encoding `asset`'s address. An address word doubles as a
/// (large but valid) `uint256`, so the same canned reply serves both the
/// asset lookup and every share-count return this test does not otherwise
/// care about: `PUSH32 word, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00,
/// RETURN`.
fn vault_account(asset: Address) -> AccountInfo {
    let mut code = Vec::with_capacity(34 + 8);
    code.push(0x7f); // PUSH32
    code.extend_from_slice(&asset.into_word().0);
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
    code_account(&code)
}

fn block() -> BlockContext {
    BlockContext::new(1, 1, outbe_primitives::chain::CHAIN_ID, CCA, vec![CCA])
}

/// A database with both vaults sharing `ASSET`, and `VAULT_FROM`/`VAULT_TO`
/// registered with the router as production `addVault` would leave them,
/// unless `register_from`/`register_to` say otherwise. `asset_reverts`
/// swaps the asset stub for one that unconditionally reverts, simulating an
/// unapproved caller.
fn seeded_db(register_from: bool, register_to: bool, asset_reverts: bool) -> CacheDB<EmptyDB> {
    let mut database = CacheDB::new(EmptyDB::default());
    let asset_code: &[u8] = if asset_reverts {
        &ALWAYS_REVERT
    } else {
        &ALWAYS_ONE
    };
    database.insert_account_info(ASSET, code_account(asset_code));
    database.insert_account_info(VAULT_FROM, vault_account(ASSET));
    database.insert_account_info(VAULT_TO, vault_account(ASSET));

    let mut provider = DirectStorageProvider::new(&mut database, block());
    StorageHandle::enter(&mut provider, |storage| {
        let router = VaultRouterContract::new(storage.clone());
        if register_from {
            router.asset_vault_set(ASSET).insert(VAULT_FROM).unwrap();
        }
        if register_to {
            router.asset_vault_set(ASSET).insert(VAULT_TO).unwrap();
        }
    });
    provider.flush().unwrap();
    database
}

fn rebalance_calldata(amount: U256, max_amount_to: U256) -> Bytes {
    Bytes::from(
        IVaultRouter::rebalanceCall {
            vaultFrom: VAULT_FROM,
            vaultTo: VAULT_TO,
            assetsAmount: amount,
            maxAmountTo: max_amount_to,
        }
        .abi_encode(),
    )
}

fn evm_ctx(
    db: CacheDB<EmptyDB>,
) -> revm::Context<
    revm::context::BlockEnv,
    revm::context::TxEnv,
    revm::context::CfgEnv,
    CacheDB<EmptyDB>,
> {
    Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| cfg.chain_id = outbe_primitives::chain::CHAIN_ID)
}

macro_rules! run_call {
    ($ctx:expr, $target:expr, $calldata:expr) => {
        sub_call::run(
            $ctx,
            CCA,
            false,
            SpecId::PRAGUE,
            None,
            Arc::new(ExecutionScope::new()),
            SubCallInput {
                target: $target,
                value: U256::ZERO,
                calldata: $calldata,
                gas_limit: 5_000_000,
                is_static: false,
            },
        )
        .expect("sub-call must not fail fatally")
    };
}

#[test]
fn rebalance_moves_liquidity_between_two_vaults_through_real_frames() {
    let mut ctx = evm_ctx(seeded_db(true, true, false));

    let result = run_call!(
        &mut ctx,
        VAULT_ROUTER_ADDRESS,
        rebalance_calldata(U256::from(AMOUNT), U256::MAX)
    );
    assert!(
        matches!(result.status, SubCallStatus::Success),
        "rebalance must succeed, got {:?} returndata 0x{}",
        result.status,
        alloy_primitives::hex::encode(&result.returndata),
    );

    // Same asset prices 1:1: the router pulled exactly `AMOUNT`.
    let amount_to = IVaultRouter::rebalanceCall::abi_decode_returns(&result.returndata).unwrap();
    assert_eq!(amount_to, U256::from(AMOUNT));
}

#[test]
fn rebalance_reverts_atomically_when_the_caller_has_not_approved() {
    let mut ctx = evm_ctx(seeded_db(true, true, true));

    let result = run_call!(
        &mut ctx,
        VAULT_ROUTER_ADDRESS,
        rebalance_calldata(U256::from(AMOUNT), U256::MAX)
    );
    assert!(
        !matches!(result.status, SubCallStatus::Success),
        "a reverting transferFrom must fail the whole rebalance, got {:?}",
        result.status
    );
}

#[test]
fn rebalance_reverts_when_the_destination_vault_is_not_registered() {
    let mut ctx = evm_ctx(seeded_db(true, false, false));

    let result = run_call!(
        &mut ctx,
        VAULT_ROUTER_ADDRESS,
        rebalance_calldata(U256::from(AMOUNT), U256::MAX)
    );
    assert!(
        !matches!(result.status, SubCallStatus::Success),
        "an unregistered destination vault must not accept liquidity, got {:?}",
        result.status
    );
}
