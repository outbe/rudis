//! Confidential Promis tests driven by the in-process enclave stand-in
//! (`enclave_client::test_enclave`), which runs the real enclave engine against a
//! fixed dev state key. Balances are asserted by decrypting the ciphertext with
//! the account's view key exactly as a client would.

use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::SolCall;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_tee::protocol::{ModifyAuth, PromisOp};
use outbe_tee_enclave::promis::{decrypt_balance, derive_modify_key, derive_view_key, modify_mac};

use crate::api;
use crate::enclave_client::test_enclave;
use crate::precompile::{dispatch, IPromis};
use outbe_primitives::units::SCALE_1E6_U64;

const CHAIN_ID: u64 = 1;

fn chain_b256() -> B256 {
    B256::from(U256::from(CHAIN_ID))
}
fn alice() -> Address {
    address!("0x1111111111111111111111111111111111111111")
}
fn bob() -> Address {
    address!("0x2222222222222222222222222222222222222222")
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
    let blob = api::balance_ct(storage, account).unwrap();
    if blob.is_empty() {
        return U256::ZERO;
    }
    decrypt_balance(&vk, account, &blob).unwrap()
}

/// Run `f` inside a fresh storage scope with the in-process enclave installed.
fn with_env<R>(f: impl FnOnce(StorageHandle<'_>) -> R) -> R {
    test_enclave::install();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    let out = StorageHandle::enter(&mut storage, |storage| f(storage.clone()));
    test_enclave::uninstall();
    out
}

#[test]
fn mine_credits_encrypted_balance() {
    with_env(|storage| {
        let amount = U256::from(SCALE_1E6_U64);
        api::mint(
            storage.clone(),
            alice(),
            amount,
            auth(PromisOp::Mint, alice(), amount, 0),
        )
        .unwrap();

        assert_eq!(view_balance(storage.clone(), alice()), amount);
        assert_eq!(api::total_supply(storage.clone()).unwrap(), amount);
        assert_eq!(api::op_nonce(storage.clone(), alice()).unwrap(), 1);

        // Second mine advances the op nonce and accumulates the (hidden) balance.
        let more = U256::from(SCALE_1E6_U64 / 2);
        api::mint(
            storage.clone(),
            alice(),
            more,
            auth(PromisOp::Mint, alice(), more, 1),
        )
        .unwrap();
        assert_eq!(
            view_balance(storage.clone(), alice()),
            U256::from(SCALE_1E6_U64 + SCALE_1E6_U64 / 2)
        );
        assert_eq!(
            api::total_supply(storage.clone()).unwrap(),
            U256::from(SCALE_1E6_U64 + SCALE_1E6_U64 / 2)
        );
    });
}

#[test]
fn mine_rejects_replayed_op_nonce() {
    with_env(|storage| {
        let amount = U256::from(100u64);
        let a = auth(PromisOp::Mint, alice(), amount, 0);
        api::mint(storage.clone(), alice(), amount, a.clone()).unwrap();
        // Replaying the same (amount, nonce=0, mac) must fail - nonce advanced to 1.
        assert!(api::mint(storage.clone(), alice(), amount, a).is_err());
    });
}

#[test]
fn mine_rejects_forged_auth() {
    with_env(|storage| {
        let amount = U256::from(100u64);
        let mut a = auth(PromisOp::Mint, alice(), amount, 0);
        a.mac[0] ^= 0xff;
        assert!(api::mint(storage.clone(), alice(), amount, a).is_err());
    });
}

#[test]
fn burn_reduces_balance_and_supply() {
    with_env(|storage| {
        api::mint(
            storage.clone(),
            alice(),
            U256::from(1000u64),
            auth(PromisOp::Mint, alice(), U256::from(1000u64), 0),
        )
        .unwrap();

        let remaining = api::burn(
            storage.clone(),
            alice(),
            U256::from(300u64),
            auth(PromisOp::Burn, alice(), U256::from(300u64), 1),
        )
        .unwrap();
        assert_eq!(remaining, U256::from(700u64));
        assert_eq!(view_balance(storage.clone(), alice()), U256::from(700u64));
        assert_eq!(api::op_nonce(storage.clone(), alice()).unwrap(), 2);
    });
}

#[test]
fn burn_insufficient_reverts_atomically() {
    with_env(|storage| {
        api::mint(
            storage.clone(),
            alice(),
            U256::from(100u64),
            auth(PromisOp::Mint, alice(), U256::from(100u64), 0),
        )
        .unwrap();

        let err = api::burn(
            storage.clone(),
            alice(),
            U256::from(200u64),
            auth(PromisOp::Burn, alice(), U256::from(200u64), 1),
        )
        .unwrap_err();
        assert!(matches!(err, PrecompileError::Revert(m) if m == "insufficient balance"));
        // No partial state change: balance + supply intact.
        assert_eq!(view_balance(storage.clone(), alice()), U256::from(100u64));
        assert_eq!(
            api::total_supply(storage.clone()).unwrap(),
            U256::from(100u64)
        );
    });
}

#[test]
fn multiple_users_accumulate_supply() {
    with_env(|storage| {
        api::mint(
            storage.clone(),
            alice(),
            U256::from(1000u64),
            auth(PromisOp::Mint, alice(), U256::from(1000u64), 0),
        )
        .unwrap();
        api::mint(
            storage.clone(),
            bob(),
            U256::from(2000u64),
            auth(PromisOp::Mint, bob(), U256::from(2000u64), 0),
        )
        .unwrap();
        assert_eq!(
            api::total_supply(storage.clone()).unwrap(),
            U256::from(3000u64)
        );
        assert_eq!(view_balance(storage.clone(), alice()), U256::from(1000u64));
        assert_eq!(view_balance(storage.clone(), bob()), U256::from(2000u64));
    });
}

#[test]
fn precompile_balance_of_returns_ciphertext() {
    with_env(|storage| {
        let amount = U256::from(777u64);
        api::mint(
            storage.clone(),
            alice(),
            amount,
            auth(PromisOp::Mint, alice(), amount, 0),
        )
        .unwrap();

        let call = IPromis::balanceOfCall { account: alice() };
        let out = dispatch(
            storage.clone(),
            &call.abi_encode(),
            Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let blob = IPromis::balanceOfCall::abi_decode_returns(&out).unwrap();
        // The ABI surface returns the raw ciphertext blob (fixed 56 bytes), not a
        // plaintext balance; decrypting it with the view key recovers the amount.
        assert_eq!(blob.len(), 56);
        let sk = test_enclave::state_key();
        let vk = derive_view_key(&sk, alice()).unwrap();
        assert_eq!(decrypt_balance(&vk, alice(), &blob).unwrap(), amount);

        // opNonceOf reflects the advanced replay counter.
        let call = IPromis::opNonceOfCall { account: alice() };
        let out = dispatch(
            storage.clone(),
            &call.abi_encode(),
            Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        assert_eq!(IPromis::opNonceOfCall::abi_decode_returns(&out).unwrap(), 1);
    });
}

#[test]
fn never_written_account_returns_empty_blob() {
    with_env(|storage| {
        let call = IPromis::balanceOfCall { account: bob() };
        let out = dispatch(
            storage.clone(),
            &call.abi_encode(),
            Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let blob = IPromis::balanceOfCall::abi_decode_returns(&out).unwrap();
        assert!(blob.is_empty());
        assert_eq!(api::op_nonce(storage.clone(), bob()).unwrap(), 0);
    });
}

#[test]
fn precompile_rejects_value() {
    with_env(|storage| {
        let call = IPromis::totalSupplyCall {};
        assert!(dispatch(
            storage.clone(),
            &call.abi_encode(),
            Address::ZERO,
            U256::from(1)
        )
        .is_err());
    });
}

#[test]
fn mine_rejects_total_supply_overflow_across_accounts() {
    with_env(|storage| {
        let near_max = U256::MAX - U256::from(10u64);
        api::mint(
            storage.clone(),
            alice(),
            near_max,
            auth(PromisOp::Mint, alice(), near_max, 0),
        )
        .unwrap();

        // Minting to bob would push `total_supply` past U256::MAX. The host guards
        // the aggregate with `checked_add` and errors before advancing the supply
        // (a Fatal - the real tx then reverts and rolls the balance write back; the
        // unit harness has no rollback, so we assert the supply invariant, which is
        // what the guard actually protects).
        let err = api::mint(
            storage.clone(),
            bob(),
            U256::from(100u64),
            auth(PromisOp::Mint, bob(), U256::from(100u64), 0),
        )
        .unwrap_err();
        assert!(err.to_string().contains("overflow"));
        assert_eq!(api::total_supply(storage.clone()).unwrap(), near_max);
    });
}

#[test]
fn metadata_and_layout() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let p = crate::Promis::new(storage.clone());
        assert_eq!(p.name(), "promis");
        assert_eq!(p.symbol(), "PROMIS");
        assert_eq!(p.decimals(), 6);
        // Layout: total_supply@0, slot 1 reserved (old plaintext balances),
        // balance_ct@2, op_nonce@3.
        assert_eq!(p.total_supply.slot(), U256::ZERO);
        assert_eq!(p.balance_ct.base_slot(), U256::from(2u64));
        assert_eq!(p.op_nonce.base_slot(), U256::from(3u64));
    });
}

#[test]
fn iface_id_matches_selector_xor() {
    let xor: [u8; 4] = [
        IPromis::nameCall::SELECTOR,
        IPromis::symbolCall::SELECTOR,
        IPromis::decimalsCall::SELECTOR,
        IPromis::totalSupplyCall::SELECTOR,
        IPromis::balanceOfCall::SELECTOR,
        IPromis::opNonceOfCall::SELECTOR,
    ]
    .into_iter()
    .fold([0u8; 4], |acc, sel| {
        [
            acc[0] ^ sel[0],
            acc[1] ^ sel[1],
            acc[2] ^ sel[2],
            acc[3] ^ sel[3],
        ]
    });

    assert_eq!(
        xor,
        crate::precompile::IPROMIS_INTERFACE_ID,
        "IPROMIS_INTERFACE_ID is stale; update it to match the new selector XOR"
    );
}
