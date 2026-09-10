//! EVM-level integration test for `IPayNote.deposit`.
//!
//! The paynote crate's own tests can only cover `deposit`'s pre-mutation
//! guards: its body performs three real sub-calls — `asset.transferFrom`,
//! `asset.approve`, and `VaultRouter.deposit` — which an in-memory storage
//! provider cannot serve. This test drives the precompile through the actual
//! EVM (`sub_call::run`, which installs the outbe precompile set in the child
//! frame), so those sub-calls dispatch for real: the VaultRouter precompile
//! runs its own liquidity-source gating and vault lookup, and only the two
//! ERC20/ERC4626 counterparties are stubbed.
//!
//! What this pins that unit tests cannot:
//!   * `PAYNOTE_ADDRESS` must be a registered VaultRouter liquidity source —
//!     the `PayNoteDeposit` discriminant seeded at genesis is load-bearing.
//!   * the asset must have a registered reserve vault.
//!   * a revert anywhere in that chain rolls the tree back atomically.
//!   * the appended leaf is the runtime-derived commitment, readable through
//!     the public view ABI.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
use outbe_compressed_entities::ExecutionScope;
use outbe_evm::sub_call;
use outbe_paynote::hash::{field_to_be_bytes, note_commitment, note_sn, Field};
use outbe_paynote::precompile::IPayNote;
use outbe_primitives::addresses::PAYNOTE_ADDRESS;
use outbe_primitives::{
    block::BlockContext,
    storage::{direct::DirectStorageProvider, StorageHandle, SubCallInput, SubCallStatus},
};
use outbe_vaultrouter::VaultRouterContract;
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context,
};

const ALICE: Address = Address::new([0x11; 20]);
const ASSET: Address = Address::new([0x33; 20]);
const VAULT: Address = Address::new([0x55; 20]);
const UNREGISTERED_ASSET: Address = Address::new([0x66; 20]);

/// `StablesSource::PayNoteDeposit` — the discriminant `seed_genesis.py`
/// registers for `PAYNOTE_ADDRESS`.
const PAYNOTE_DEPOSIT_SOURCE: u8 = 4;

const DEPOSIT_AMOUNT: u128 = 1_000;
const SPEND_KEY: u64 = 17;

/// Minimal counterparty stub: returns 32 bytes of `1` for any calldata.
///
/// `PUSH1 0x01, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN`
///
/// That single answer satisfies every call this flow makes on the two
/// counterparties: `transferFrom` and `approve` read it as `true`, and the
/// vault's `deposit` reads it as one minted share.
const ALWAYS_ONE: [u8; 10] = [0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

fn stub_account() -> AccountInfo {
    let bytecode = Bytecode::new_raw(Bytes::from(ALWAYS_ONE.to_vec()));
    AccountInfo {
        code_hash: bytecode.hash_slow(),
        code: Some(bytecode),
        ..Default::default()
    }
}

fn block() -> BlockContext {
    BlockContext::new(1, 1, outbe_primitives::chain::CHAIN_ID, ALICE, vec![ALICE])
}

/// The commitment the runtime must derive for a deposit of `amount` of
/// `asset` under `SPEND_KEY`'s serial — computed independently here.
fn expected_commitment(asset: Address, amount: u128) -> Field {
    expected_commitment_u256(asset, U256::from(amount))
}

fn expected_commitment_u256(asset: Address, amount: U256) -> Field {
    let serial = note_sn(Field::from(SPEND_KEY)).unwrap();
    note_commitment(
        outbe_primitives::chain::CHAIN_ID,
        serial,
        asset.into(),
        amount,
    )
    .unwrap()
}

fn note_serial_word() -> alloy_primitives::B256 {
    alloy_primitives::B256::new(field_to_be_bytes(note_sn(Field::from(SPEND_KEY)).unwrap()))
}

/// A database with the two counterparty stubs deployed and VaultRouter seeded
/// as production genesis would: a vault registered for `ASSET`, and paynote
/// authorized as a `PayNoteDeposit` liquidity source unless `authorize_paynote`
/// says otherwise.
fn seeded_db(register_vault: bool, authorize_paynote: bool) -> CacheDB<EmptyDB> {
    let mut database = CacheDB::new(EmptyDB::default());
    database.insert_account_info(ASSET, stub_account());
    database.insert_account_info(UNREGISTERED_ASSET, stub_account());
    database.insert_account_info(VAULT, stub_account());

    let mut provider = DirectStorageProvider::new(&mut database, block());
    StorageHandle::enter(&mut provider, |storage| {
        let router = VaultRouterContract::new(storage.clone());
        if register_vault {
            router.assets.insert(ASSET).unwrap();
            router.asset_vault_set(ASSET).insert(VAULT).unwrap();
        }
        if authorize_paynote {
            router.liquidity_sources.insert(PAYNOTE_ADDRESS).unwrap();
            router
                .liquidity_source_types
                .write(&PAYNOTE_ADDRESS, PAYNOTE_DEPOSIT_SOURCE)
                .unwrap();
        }
    });
    provider.flush().unwrap();
    database
}

fn deposit_calldata(asset: Address, amount: u128) -> Bytes {
    deposit_calldata_u256(asset, U256::from(amount))
}

fn deposit_calldata_u256(asset: Address, amount: U256) -> Bytes {
    Bytes::from(
        IPayNote::depositCall {
            asset,
            amount,
            noteSn: note_serial_word(),
        }
        .abi_encode(),
    )
}

/// The EVM context the sub-call runs in. `Context::mainnet()` defaults to
/// chain id 1; the runtime folds the live chain id into every note
/// commitment, so the test would otherwise derive a leaf for the wrong chain.
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
    ($ctx:expr, $target:expr, $calldata:expr, $is_static:expr) => {
        sub_call::run(
            $ctx,
            ALICE,
            false,
            SpecId::PRAGUE,
            None,
            Arc::new(ExecutionScope::new()),
            SubCallInput {
                target: $target,
                value: U256::ZERO,
                calldata: $calldata,
                gas_limit: 5_000_000,
                is_static: $is_static,
            },
        )
        .expect("sub-call must not fail fatally")
    };
}

/// The tree must be untouched: a VaultRouter revert has to roll the whole
/// deposit back, leaf and all, not leave a commitment behind for value that
/// never reached a vault.
macro_rules! assert_pristine {
    ($ctx:expr) => {{
        let count = run_call!(
            $ctx,
            PAYNOTE_ADDRESS,
            Bytes::from(IPayNote::leafCountCall {}.abi_encode()),
            true
        );
        assert_eq!(
            IPayNote::leafCountCall::abi_decode_returns(&count.returndata).unwrap(),
            0,
            "a failed deposit must leave no leaf behind"
        );
    }};
}

#[test]
fn deposit_routes_full_width_amount_through_vault_router_and_appends_commitment() {
    let mut ctx = evm_ctx(seeded_db(true, true));
    let amount = (U256::from(1) << 200) + U256::from(DEPOSIT_AMOUNT);

    let result = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        deposit_calldata_u256(ASSET, amount),
        false
    );
    assert!(
        matches!(result.status, SubCallStatus::Success),
        "deposit must succeed, got {:?} returndata 0x{}",
        result.status,
        alloy_primitives::hex::encode(&result.returndata),
    );

    // The tree advanced by exactly one leaf, read back through the public ABI.
    let count = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        Bytes::from(IPayNote::leafCountCall {}.abi_encode()),
        true
    );
    assert_eq!(
        IPayNote::leafCountCall::abi_decode_returns(&count.returndata).unwrap(),
        1
    );

    // And the appended leaf is the commitment the runtime derived from the
    // asset and amount it actually moved — not anything the caller supplied.
    let commitment =
        alloy_primitives::B256::new(field_to_be_bytes(expected_commitment_u256(ASSET, amount)));
    let present = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        Bytes::from(IPayNote::hasCommitmentCall { commitment }.abi_encode()),
        true
    );
    assert!(
        IPayNote::hasCommitmentCall::abi_decode_returns(&present.returndata).unwrap(),
        "the derived commitment must be a leaf of the tree"
    );

    // The post-deposit root is inside the acceptance window, so a proof built
    // against it right now would be spendable.
    let root = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        Bytes::from(IPayNote::currentRootCall {}.abi_encode()),
        true
    );
    let root = IPayNote::currentRootCall::abi_decode_returns(&root.returndata).unwrap();
    let known = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        Bytes::from(IPayNote::isKnownRootCall { root }.abi_encode()),
        true
    );
    assert!(IPayNote::isKnownRootCall::abi_decode_returns(&known.returndata).unwrap());
}

#[test]
fn deposit_reverts_and_leaves_no_leaf_when_paynote_is_not_a_liquidity_source() {
    // Genesis authorization is load-bearing: without the `PayNoteDeposit`
    // source registration, VaultRouter rejects the routed deposit.
    let mut ctx = evm_ctx(seeded_db(true, false));

    let result = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        deposit_calldata(ASSET, DEPOSIT_AMOUNT),
        false
    );
    assert!(
        !matches!(result.status, SubCallStatus::Success),
        "an unauthorized liquidity source must not deposit"
    );

    assert_pristine!(&mut ctx);
}

#[test]
fn deposit_reverts_and_leaves_no_leaf_when_the_asset_has_no_vault() {
    let mut ctx = evm_ctx(seeded_db(false, true));

    let result = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        deposit_calldata(UNREGISTERED_ASSET, DEPOSIT_AMOUNT),
        false
    );
    assert!(
        !matches!(result.status, SubCallStatus::Success),
        "an asset without a reserve vault must not deposit"
    );

    assert_pristine!(&mut ctx);
}

#[test]
fn a_second_identical_deposit_reverts_on_the_duplicate_leaf() {
    // Dedup is on the leaf, not the serial: re-depositing the same amount of
    // the same asset under the same serial rebuilds the identical commitment,
    // which would alias one nullifier onto two notes and lock one up forever.
    let mut ctx = evm_ctx(seeded_db(true, true));

    let first = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        deposit_calldata(ASSET, DEPOSIT_AMOUNT),
        false
    );
    assert!(matches!(first.status, SubCallStatus::Success));

    let second = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        deposit_calldata(ASSET, DEPOSIT_AMOUNT),
        false
    );
    assert!(
        !matches!(second.status, SubCallStatus::Success),
        "a duplicate commitment must be rejected"
    );

    // Still exactly the one leaf from the first deposit.
    let count = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        Bytes::from(IPayNote::leafCountCall {}.abi_encode()),
        true
    );
    assert_eq!(
        IPayNote::leafCountCall::abi_decode_returns(&count.returndata).unwrap(),
        1
    );
}

#[test]
fn a_differing_amount_under_the_same_serial_is_a_distinct_leaf() {
    // The serial is amount-independent, so the same spend key can legitimately
    // fund several notes; each amount must produce its own leaf.
    let mut ctx = evm_ctx(seeded_db(true, true));

    for amount in [DEPOSIT_AMOUNT, DEPOSIT_AMOUNT + 1] {
        let result = run_call!(
            &mut ctx,
            PAYNOTE_ADDRESS,
            deposit_calldata(ASSET, amount),
            false
        );
        assert!(
            matches!(result.status, SubCallStatus::Success),
            "deposit of {amount} must succeed, got {:?}",
            result.status
        );
    }

    let count = run_call!(
        &mut ctx,
        PAYNOTE_ADDRESS,
        Bytes::from(IPayNote::leafCountCall {}.abi_encode()),
        true
    );
    assert_eq!(
        IPayNote::leafCountCall::abi_decode_returns(&count.returndata).unwrap(),
        2
    );

    for amount in [DEPOSIT_AMOUNT, DEPOSIT_AMOUNT + 1] {
        let commitment =
            alloy_primitives::B256::new(field_to_be_bytes(expected_commitment(ASSET, amount)));
        let present = run_call!(
            &mut ctx,
            PAYNOTE_ADDRESS,
            Bytes::from(IPayNote::hasCommitmentCall { commitment }.abi_encode()),
            true
        );
        assert!(
            IPayNote::hasCommitmentCall::abi_decode_returns(&present.returndata).unwrap(),
            "the leaf for amount {amount} must be present"
        );
    }
}
