//! Promisfactory tests driven by the in-process Promis enclave stand-in. Mint/burn
//! are enclave-routed and modify-key authorized, so balances are asserted by
//! decrypting the ciphertext with the account's view key.

use alloy_primitives::{address, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface};

use outbe_fidelity::{MAX_LEAGUE, MIN_LEAGUE};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::{ONE_COEN, SCALE_1E6_U64};
use outbe_promis::api::{self as promis_api, ModifyAuth};
use outbe_promis::enclave_client::test_enclave;
use outbe_tee::protocol::{GratisOp, PromisOp};
use outbe_tee_enclave::promis::{decrypt_balance, derive_modify_key, derive_view_key, modify_mac};

use crate::precompile::{dispatch, IPromisFactory};
use crate::runtime;

const CHAIN_ID: u64 = 1;
const CREATED_AT: u64 = 1_700_000_000;

fn chain_b256() -> B256 {
    B256::from(U256::from(CHAIN_ID))
}
fn alice() -> Address {
    address!("0x1111111111111111111111111111111111111111")
}

/// Build the modify authorization a client would send for `op`.
fn auth(op: PromisOp, account: Address, amount: U256, nonce: u64) -> ModifyAuth {
    let sk = test_enclave::state_key();
    let mk = derive_modify_key(&sk, account).unwrap();
    ModifyAuth {
        mac: modify_mac(&mk, account, op, amount, nonce, chain_b256()),
        op_nonce: nonce,
    }
}

fn view_balance(storage: StorageHandle<'_>, account: Address) -> U256 {
    let sk = test_enclave::state_key();
    let vk = derive_view_key(&sk, account).unwrap();
    let blob = promis_api::balance_ct(storage, account).unwrap();
    if blob.is_empty() {
        return U256::ZERO;
    }
    decrypt_balance(&vk, account, &blob).unwrap()
}

fn with_env<R>(f: impl FnOnce(StorageHandle<'_>) -> R) -> R {
    test_enclave::install();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    let out = StorageHandle::enter(&mut storage, |storage| f(storage.clone()));
    test_enclave::uninstall();
    out
}

fn mine_coen_call(amount: U256, a: &ModifyAuth) -> Bytes {
    Bytes::from(
        IPromisFactory::IPromisFactoryCalls::mineRudis(IPromisFactory::mineRudisCall {
            amount,
            mac: alloy_primitives::FixedBytes(a.mac),
            opNonce: a.op_nonce,
        })
        .abi_encode(),
    )
}

#[test]
fn mine_rejects_zero_amount() {
    with_env(|storage| {
        let err = runtime::mint(
            storage.clone(),
            alice(),
            U256::ZERO,
            auth(PromisOp::Mint, alice(), U256::ZERO, 0),
        )
        .unwrap_err();
        assert!(err.to_string().contains("amount must be positive"));
    });
}

#[test]
fn mine_coen_success_burns_and_mints_native() {
    with_env(|storage| {
        let one_promis = U256::from(SCALE_1E6_U64);
        promis_api::mint(
            storage.clone(),
            alice(),
            one_promis,
            auth(PromisOp::Mint, alice(), one_promis, 0),
        )
        .unwrap();

        let call = mine_coen_call(one_promis, &auth(PromisOp::Burn, alice(), one_promis, 1));
        let output = dispatch(storage.clone(), &call, alice(), U256::ZERO).unwrap();
        let minted = IPromisFactory::mineRudisCall::abi_decode_returns(&output).unwrap();

        // One six-decimal PROMIS becomes one 18-decimal native COEN.
        assert_eq!(minted, ONE_COEN);
        assert_eq!(view_balance(storage.clone(), alice()), U256::ZERO);
        assert_eq!(storage.balance(alice()).unwrap(), ONE_COEN);
    });
}

#[test]
fn mine_coen_rejects_insufficient_balance() {
    with_env(|storage| {
        // Alice holds 100 promis but tries to convert 200.
        promis_api::mint(
            storage.clone(),
            alice(),
            U256::from(100u64),
            auth(PromisOp::Mint, alice(), U256::from(100u64), 0),
        )
        .unwrap();

        let call = mine_coen_call(
            U256::from(200u64),
            &auth(PromisOp::Burn, alice(), U256::from(200u64), 1),
        );
        let err = dispatch(storage.clone(), &call, alice(), U256::ZERO).unwrap_err();
        assert!(err.to_string().contains("insufficient balance"));

        // No native COEN minted, promis untouched (atomic revert).
        assert_eq!(storage.balance(alice()).unwrap(), U256::ZERO);
        assert_eq!(view_balance(storage.clone(), alice()), U256::from(100u64));
    });
}

#[test]
fn supports_interface() {
    with_env(|storage| {
        let call = Bytes::from(
            IPromisFactory::IPromisFactoryCalls::supportsInterface(
                IPromisFactory::supportsInterfaceCall {
                    interfaceId: alloy_primitives::FixedBytes(ERC165_INTERFACE_ID),
                },
            )
            .abi_encode(),
        );
        let out = dispatch(storage.clone(), &call, alice(), U256::ZERO).unwrap();
        assert!(IPromisFactory::supportsInterfaceCall::abi_decode_returns(&out).unwrap());

        let call = Bytes::from(
            IPromisFactory::IPromisFactoryCalls::supportsInterface(
                IPromisFactory::supportsInterfaceCall {
                    interfaceId: alloy_primitives::FixedBytes([0xde, 0xad, 0xbe, 0xef]),
                },
            )
            .abi_encode(),
        );
        let out = dispatch(storage, &call, alice(), U256::ZERO).unwrap();
        assert!(!IPromisFactory::supportsInterfaceCall::abi_decode_returns(&out).unwrap());
    });
}

#[test]
fn rejects_msg_value() {
    with_env(|storage| {
        // Value is rejected before ABI decode, so the auth fields are irrelevant.
        let call = mine_coen_call(
            U256::from(1u64),
            &auth(PromisOp::Burn, alice(), U256::from(1u64), 0),
        );
        let err = dispatch(storage, &call, alice(), U256::from(1u64)).unwrap_err();
        assert!(err.to_string().contains("non-payable"));
    });
}

/// Run `f` with the Promis, Gratis and Fidelity in-process enclaves installed and
/// the block time set - the gratis mint records a Fidelity acquisition cohort at
/// `now`, so a zero timestamp would not exercise it.
fn with_gratis_env<R>(f: impl FnOnce(StorageHandle<'_>) -> R) -> R {
    test_enclave::install();
    outbe_gratis::enclave_client::test_enclave::install();
    outbe_fidelity::enclave_client::test_enclave::install();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(CREATED_AT));
    let out = StorageHandle::enter(&mut storage, |storage| f(storage.clone()));
    outbe_fidelity::enclave_client::test_enclave::uninstall();
    outbe_gratis::enclave_client::test_enclave::uninstall();
    test_enclave::uninstall();
    out
}

/// The Gratis modify authorization for `account` (the confidential gratis ledger is
/// keyed independently from promis).
fn gratis_auth(op: GratisOp, account: Address, amount: U256, nonce: u64) -> ModifyAuth {
    let sk = outbe_gratis::enclave_client::test_enclave::state_key();
    let mk = outbe_tee_enclave::gratis::derive_modify_key(&sk, account).unwrap();
    ModifyAuth {
        mac: outbe_tee_enclave::gratis::modify_mac(&mk, account, op, amount, nonce, chain_b256()),
        op_nonce: nonce,
    }
}

/// Decrypt `account`'s confidential gratis balance with its view key.
fn gratis_view_balance(storage: &StorageHandle<'_>, account: Address) -> U256 {
    let sk = outbe_gratis::enclave_client::test_enclave::state_key();
    let vk = outbe_tee_enclave::gratis::derive_view_key(&sk, account).unwrap();
    let blob = outbe_gratis::api::balance_ct(storage.clone(), account).unwrap();
    if blob.is_empty() {
        return U256::ZERO;
    }
    outbe_tee_enclave::gratis::decrypt_balance(&vk, account, &blob).unwrap()
}

fn mine_gratis_call(amount: U256, promis: &ModifyAuth, gratis: &ModifyAuth) -> Bytes {
    Bytes::from(
        IPromisFactory::IPromisFactoryCalls::mineGratis(IPromisFactory::mineGratisCall {
            amount,
            promisMac: alloy_primitives::FixedBytes(promis.mac),
            promisOpNonce: promis.op_nonce,
            gratisMac: alloy_primitives::FixedBytes(gratis.mac),
            gratisOpNonce: gratis.op_nonce,
        })
        .abi_encode(),
    )
}

#[test]
fn mine_gratis_burns_promis_mints_gratis_creating_fidelity_cohort() {
    const ONE_YEAR_SECS: u64 = 365 * 86_400;
    with_gratis_env(|storage| {
        let amount = U256::from(1_000u64);

        // Seed only (confidential) promis to convert - no Fidelity cohort yet.
        // Promis is fidelity-neutral, so the aged RCFI a year out sits at the floor
        // up front; the post-conversion check then proves the conversion recorded a
        // fresh gratis cohort rather than it having pre-existed.
        promis_api::mint(
            storage.clone(),
            alice(),
            amount,
            auth(PromisOp::Mint, alice(), amount, 0),
        )
        .unwrap();
        let later = CREATED_AT + ONE_YEAR_SECS;
        let league_before =
            outbe_fidelity::api::league_at(storage.clone(), alice(), later).unwrap();
        assert_eq!(league_before, MIN_LEAGUE);

        // Both ledgers are enclave-confidential and independently keyed, so the call
        // carries two modify authorizations at each ledger's current op-nonce: promis
        // already advanced to 1 by the seed mint, gratis is fresh (0).
        let pa = auth(PromisOp::Burn, alice(), amount, 1);
        let ga = gratis_auth(GratisOp::Mint, alice(), amount, 0);
        let call = mine_gratis_call(amount, &pa, &ga);
        let out = dispatch(storage.clone(), &call, alice(), U256::ZERO).unwrap();
        let minted = IPromisFactory::mineGratisCall::abi_decode_returns(&out).unwrap();
        assert_eq!(minted, amount);

        // Promis fully burned; gratis minted 1:1 to the account (decrypt both
        // confidential balances to check; total supplies are public).
        assert_eq!(view_balance(storage.clone(), alice()), U256::ZERO);
        assert_eq!(
            promis_api::total_supply(storage.clone()).unwrap(),
            U256::ZERO
        );
        assert_eq!(gratis_view_balance(&storage, alice()), amount);
        assert_eq!(
            outbe_gratis::api::total_supply(storage.clone()).unwrap(),
            amount
        );

        // A fresh gratis acquisition cohort was recorded at conversion time
        // (CREATED_AT): sole holder, no sales -> top league a year later. If the
        // conversion stopped recording the cohort, this would stay at the floor.
        let league_after = outbe_fidelity::api::league_at(storage.clone(), alice(), later).unwrap();
        assert_eq!(league_after, MAX_LEAGUE);
    });
}

/// The conversion with insufficient balance must fail with no partial state: no
/// promis burned, no gratis minted (atomic revert).
#[test]
fn mine_gratis_rejects_insufficient_balance() {
    with_gratis_env(|storage| {
        // Alice holds 100 (confidential) promis but tries to convert 200.
        promis_api::mint(
            storage.clone(),
            alice(),
            U256::from(100u64),
            auth(PromisOp::Mint, alice(), U256::from(100u64), 0),
        )
        .unwrap();

        // The promis burn fails before the gratis mint is reached; the gratis auth is
        // never checked (zero placeholder), but the promis burn auth must be valid to
        // reach the balance check (op-nonce 1 after the seed mint).
        let pa = auth(PromisOp::Burn, alice(), U256::from(200u64), 1);
        let placeholder = ModifyAuth {
            mac: [0u8; 32],
            op_nonce: 0,
        };
        let call = mine_gratis_call(U256::from(200u64), &pa, &placeholder);
        let err = dispatch(storage.clone(), &call, alice(), U256::ZERO).unwrap_err();
        assert!(
            err.to_string().contains("insufficient balance"),
            "got: {err}"
        );

        // No gratis minted (no ciphertext ever written), promis untouched.
        assert_eq!(view_balance(storage.clone(), alice()), U256::from(100u64));
        assert!(outbe_gratis::api::balance_ct(storage.clone(), alice())
            .unwrap()
            .is_empty());
    });
}
