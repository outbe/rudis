//! Unit and dispatch tests for the PayNote precompile.
//!
//! The round-trip tests are the load-bearing ones: they prove a real
//! `outbe.paynote@1.1.0` statement from **Rust-computed** public inputs and
//! verify it through the production decoder. If `hash.rs` drifted from the
//! frozen circuit's `paynote.nr`, the Rust root/nullifier would disagree with
//! the in-circuit ones and proving would fail — that is what pins the mirror.
//!
//! `deposit` performs ERC20 and VaultRouter sub-calls, which the in-memory
//! storage provider cannot serve, so only its pre-mutation guards are covered
//! here; the full path belongs in an EVM-level integration test.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use ark_ff::Zero;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_zk_canonical::noir::paynote::{Paynote, PublicInputs};
use outbe_zk_canonical::paynote::{
    COMBINED_LEN as PAYNOTE_COMBINED_LEN, PROOF_WORDS as PAYNOTE_PROOF_WORDS,
};
use outbe_zk_canonical::CircuitId as _;

use crate::hash::{empty_subtrees, field_to_be_bytes, Field};
use crate::precompile::{base_gas, dispatch, IPayNote, PAYABLE_SELECTORS};
use crate::runtime;
use crate::schema::{
    PayNoteContract, PAYNOTE_ROOT_WINDOW, PAYNOTE_TREE_CAPACITY, PAYNOTE_TREE_DEPTH,
};

const CHAIN_ID: u64 = 31_337;
const OTHER_CHAIN_ID: u64 = 19_280_501;

const ALICE: Address = Address::new([0x11; 20]);
const SPENDER: Address = Address::new([0x22; 20]);
const USDC: Address = Address::new([0x33; 20]);
const WBTC: Address = Address::new([0x44; 20]);

fn b256(field: Field) -> B256 {
    B256::new(field_to_be_bytes(field))
}

fn assert_revert<T: std::fmt::Debug>(result: Result<T, PrecompileError>, expected: &str) {
    match result {
        Err(PrecompileError::Revert(message)) => assert_eq!(message, expected),
        other => panic!("expected revert `{expected}`, got {other:?}"),
    }
}
// ---- proving fixtures -----------------------------------------------------
//
// The reference tree, note derivation, proving, and pool seeding live in
// `test_support` so downstream consumers of notes can reuse them.

use crate::test_support::{note, note_and_spend_proof, seed_pool, ReferenceTree};

/// Prove a spend of `spend_amount` out of a single-leaf tree holding `amount`
/// of `asset`, returning the combined proof and the statement it carries.
fn prove_spend(
    chain_id: u64,
    asset: Address,
    amount: u128,
    spend_amount: u128,
) -> (Vec<u8>, PublicInputs, ReferenceTree) {
    let fixture = note_and_spend_proof(
        chain_id,
        asset,
        SPENDER,
        U256::from(amount),
        U256::from(spend_amount),
    );
    (fixture.proof, fixture.public, fixture.tree)
}

// ---- selectors, value policy, gas -----------------------------------------

#[test]
fn paynote_takes_no_native_value() {
    assert_eq!(PAYABLE_SELECTORS, &[] as &[[u8; 4]]);

    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.enter(|storage| {
        let data = IPayNote::currentRootCall {}.abi_encode();
        let result = dispatch(storage, &data, ALICE, U256::from(1u64));
        assert!(
            result.is_err(),
            "a non-payable precompile must reject credited value"
        );
    });
}

#[test]
fn unknown_selector_is_priced_out_of_gas() {
    assert_eq!(base_gas(&[0xde, 0xad, 0xbe, 0xef]), u64::MAX);
    assert_eq!(
        base_gas(&IPayNote::currentRootCall {}.abi_encode()),
        crate::precompile::PAYNOTE_VIEW_BASE_GAS
    );
}

// ---- formula + tree parity ------------------------------------------------

#[test]
fn asset_separates_otherwise_identical_notes() {
    // The whole reason the commitment binds the asset: a note funded in one
    // token must not be spendable as another.
    let usdc = note(CHAIN_ID, 17, USDC, U256::from(100));
    let wbtc = note(CHAIN_ID, 17, WBTC, U256::from(100));
    assert_eq!(usdc.serial, wbtc.serial, "serial is asset-independent");
    assert_ne!(usdc.commitment, wbtc.commitment);
    assert_ne!(usdc.nullifier, wbtc.nullifier);
}

#[test]
fn one_serial_two_amounts_stay_independently_spendable() {
    // The nullifier binds the commitment, not the serial, so two notes sharing
    // a serial do not alias onto one nullifier and lock each other out.
    let a = note(CHAIN_ID, 17, USDC, U256::from(40));
    let b = note(CHAIN_ID, 17, USDC, U256::from(60));
    assert_eq!(a.serial, b.serial);
    assert_ne!(a.commitment, b.commitment);
    assert_ne!(a.nullifier, b.nullifier);
}

#[test]
fn empty_leaf_is_chain_specific_and_nonzero() {
    let here = empty_subtrees(CHAIN_ID, PAYNOTE_TREE_DEPTH).unwrap();
    let there = empty_subtrees(OTHER_CHAIN_ID, PAYNOTE_TREE_DEPTH).unwrap();
    assert!(!here[0].is_zero());
    assert_ne!(here[0], there[0], "empty leaf must bind the chain");
    assert_ne!(
        here[PAYNOTE_TREE_DEPTH], there[PAYNOTE_TREE_DEPTH],
        "so must the empty root"
    );
}

#[test]
fn incremental_append_matches_naive_recompute() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let mut reference = ReferenceTree::new(CHAIN_ID);
    let leaves: Vec<Field> = (0..5)
        .map(|i| note(CHAIN_ID, 100 + i, USDC, U256::from(10 + u128::from(i))).commitment)
        .collect();

    seed_pool(&mut provider, CHAIN_ID, &leaves);
    for leaf in &leaves {
        reference.append(*leaf);
    }

    provider.enter(|storage| {
        let paynote: PayNoteContract<'_> = storage.contract();
        assert_eq!(paynote.leaf_count.read().unwrap(), leaves.len() as u64);
        assert_eq!(
            paynote.current_root.read().unwrap(),
            b256(reference.root()),
            "O(depth) frontier append must agree with recompute-from-leaves"
        );
    });
}

#[test]
fn root_window_retains_only_the_last_entries() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    // One seeded empty root plus enough appends to overflow the window.
    let leaves: Vec<Field> = (0..PAYNOTE_ROOT_WINDOW + 4)
        .map(|i| note(CHAIN_ID, 1_000 + u64::from(i), USDC, U256::from(7)).commitment)
        .collect();
    seed_pool(&mut provider, CHAIN_ID, &leaves);

    provider.enter(|storage| {
        let paynote: PayNoteContract<'_> = storage.contract();
        let roots = paynote.recent_roots.read_all().unwrap();
        assert_eq!(roots.len(), PAYNOTE_ROOT_WINDOW as usize);
        assert!(
            roots.contains(&paynote.current_root.read().unwrap()),
            "the live root must always be acceptable"
        );
    });
}

#[test]
fn tree_capacity_bound_exceeds_u32() {
    // The depth-32 capacity does not fit u32; a u32 leaf counter would wrap on
    // the final append instead of reporting a full tree.
    assert_eq!(PAYNOTE_TREE_CAPACITY, 1u64 << 32);
    assert!(PAYNOTE_TREE_CAPACITY > u64::from(u32::MAX));
}

// ---- deposit guards -------------------------------------------------------

#[test]
fn deposit_guards_fire_before_any_sub_call() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let serial = note(CHAIN_ID, 17, USDC, U256::from(100)).serial;

    provider.enter(|storage| {
        let result = runtime::deposit(storage, ALICE, USDC, U256::from(0), b256(serial));
        assert_revert(result, "PayNote deposit amount must be non-zero");
    });
    provider.enter(|storage| {
        let result = runtime::deposit(storage, ALICE, Address::ZERO, U256::from(100), b256(serial));
        assert_revert(result, "PayNote asset must be non-zero");
    });
    provider.enter(|storage| {
        let result = runtime::deposit(storage, ALICE, USDC, U256::from(100), B256::ZERO);
        assert_revert(result, "PayNote noteSn must be non-zero");
    });
    provider.enter(|storage| {
        // All-ones is above the BN254 modulus, so it is not a canonical word.
        let result = runtime::deposit(
            storage,
            ALICE,
            USDC,
            U256::from(100),
            B256::repeat_byte(0xff),
        );
        assert_revert(result, "PayNote noteSn is not a canonical BN254 field");
    });
}

// ---- consume guards -------------------------------------------------------

#[test]
fn consume_on_a_pristine_pool_reverts() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, _, _) = prove_spend(CHAIN_ID, USDC, 100, 100);
    provider.enter(|storage| {
        assert_revert(
            runtime::consume(&storage, &proof),
            "PayNote is not initialized",
        );
    });
}

#[test]
fn consume_rejects_a_root_outside_the_window() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, _, _) = prove_spend(CHAIN_ID, USDC, 100, 100);
    // A pool holding a different leaf never produced the proof's root.
    seed_pool(
        &mut provider,
        CHAIN_ID,
        &[note(CHAIN_ID, 999, USDC, U256::from(5)).commitment],
    );
    provider.enter(|storage| {
        assert_revert(
            runtime::consume(&storage, &proof),
            "PayNote root is not recent",
        );
    });
}

#[test]
fn consume_rejects_a_foreign_chain_statement() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, _, tree) = prove_spend(OTHER_CHAIN_ID, USDC, 100, 100);
    seed_pool(&mut provider, CHAIN_ID, &tree.leaves);
    provider.enter(|storage| {
        assert_revert(
            runtime::consume(&storage, &proof),
            "PayNote chain ID does not match runtime",
        );
    });
}

#[test]
fn consume_rejects_a_malformed_proof() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    seed_pool(
        &mut provider,
        CHAIN_ID,
        &[note(CHAIN_ID, 999, USDC, U256::from(5)).commitment],
    );
    provider.enter(|storage| {
        let result = runtime::consume(&storage, &[0u8; 8]);
        assert!(
            matches!(result, Err(PrecompileError::Revert(ref m)) if m.starts_with("PayNote proof is malformed")),
            "got {result:?}"
        );
    });
}

// ---- real-proof round trips ----------------------------------------------

#[test]
fn full_spend_round_trip_books_the_nullifier_and_no_change() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, public, tree) = prove_spend(CHAIN_ID, USDC, 100, 100);

    // The frozen circuit's transcript is fixed-length; this is what pins
    // `PAYNOTE_PROOF_WORDS`.
    assert_eq!(
        proof.len(),
        PAYNOTE_COMBINED_LEN,
        "combined proof length must match the pinned frozen wire"
    );
    assert_eq!(proof.len(), 4 + (9 + PAYNOTE_PROOF_WORDS) * 32);
    assert!(
        public.change_commitment.is_zero(),
        "full spend has no change"
    );

    seed_pool(&mut provider, CHAIN_ID, &tree.leaves);
    provider.enter(|storage| {
        let claim = runtime::consume(&storage, &proof).expect("valid full spend");
        assert_eq!(claim.asset, USDC);
        assert_eq!(claim.spender, SPENDER);
        assert_eq!(claim.spend_amount, 100);

        let paynote: PayNoteContract<'_> = storage.contract();
        assert!(paynote
            .spent_nullifiers
            .read(&b256(public.nullifier))
            .unwrap());
        assert_eq!(
            paynote.leaf_count.read().unwrap(),
            1,
            "a full spend appends nothing"
        );
    });
}

#[test]
fn replaying_a_spent_proof_reverts() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, _, tree) = prove_spend(CHAIN_ID, USDC, 100, 100);
    seed_pool(&mut provider, CHAIN_ID, &tree.leaves);

    provider.enter(|storage| {
        runtime::consume(&storage, &proof).expect("first spend");
    });
    provider.enter(|storage| {
        assert_revert(
            runtime::consume(&storage, &proof),
            "PayNote nullifier has already been spent",
        );
    });
}

#[test]
fn partial_spend_appends_exactly_the_circuit_derived_change() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, public, tree) = prove_spend(CHAIN_ID, USDC, 100, 40);
    assert!(
        !public.change_commitment.is_zero(),
        "partial spend must publish change"
    );

    seed_pool(&mut provider, CHAIN_ID, &tree.leaves);
    provider.enter(|storage| {
        let claim = runtime::consume(&storage, &proof).expect("valid partial spend");
        assert_eq!(claim.spend_amount, 40);

        let paynote: PayNoteContract<'_> = storage.contract();
        assert_eq!(
            paynote.leaf_count.read().unwrap(),
            2,
            "the change note is appended"
        );
        assert!(
            paynote
                .commitments
                .read(&b256(public.change_commitment))
                .unwrap(),
            "the appended leaf is the circuit-derived change commitment"
        );

        // And the resulting root must match a recompute over both leaves.
        let mut reference = ReferenceTree::new(CHAIN_ID);
        reference.append(tree.leaves[0]);
        reference.append(public.change_commitment);
        assert_eq!(paynote.current_root.read().unwrap(), b256(reference.root()));
    });
}

#[test]
fn full_width_u256_spend_round_trip() {
    assert_eq!(Paynote::VERSION, "1.1.0");
    assert_eq!(
        Paynote::CIRCUIT_HASH,
        alloy_primitives::hex!("3154da6976ca8ee5f00b228fe821ce0868b189ff73cefb1a9a562d2768a9f9cc")
    );
    assert_eq!(
        Paynote::VK_HASH,
        alloy_primitives::hex!("75454ca024cd3532e24663d7ae14c2d7dc42fdb1291b69f2db17262385d6f34f")
    );

    let note_amount = (U256::from(1) << 200) + U256::from(100);
    let spend_amount = (U256::from(1) << 199) + U256::from(40);
    let fixture = note_and_spend_proof(CHAIN_ID, USDC, SPENDER, note_amount, spend_amount);
    assert_eq!(fixture.proof.len(), PAYNOTE_COMBINED_LEN);

    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    seed_pool(&mut provider, CHAIN_ID, &[fixture.commitment]);
    provider.enter(|storage| {
        let claim = runtime::consume(&storage, &fixture.proof).expect("valid U256 spend");
        assert_eq!(claim.spend_amount, spend_amount);
        let paynote: PayNoteContract<'_> = storage.contract();
        assert!(paynote
            .commitments
            .read(&b256(fixture.public.change_commitment))
            .unwrap());
    });
}

#[test]
fn a_note_cannot_be_spent_as_a_different_asset() {
    // Bind the proof to USDC, then seed a pool whose leaf was built for WBTC:
    // membership fails, so the spend is rejected.
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let (proof, _, _) = prove_spend(CHAIN_ID, USDC, 100, 100);
    seed_pool(
        &mut provider,
        CHAIN_ID,
        &[note(CHAIN_ID, 17, WBTC, U256::from(100)).commitment],
    );
    provider.enter(|storage| {
        assert_revert(
            runtime::consume(&storage, &proof),
            "PayNote root is not recent",
        );
    });
}
