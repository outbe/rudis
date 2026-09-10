//! Unit and dispatch tests for the Emit precompile.
//!
//! Real proofs come from the dev-only `ProofGenerator` fixtures
//! (`instance_id = 0`, matching the production profile); guard tests that run
//! before verification use fabricated well-framed blobs. Burns simulate the
//! EVM value boundary's credit by funding `EMIT_ADDRESS` first.

use alloy_primitives::{Address, Bytes, LogData, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use ark_ff::BigInteger as _;
use ark_ff::PrimeField;
use outbe_primitives::addresses::EMIT_ADDRESS;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_protocol::protocol::zk::ProofGenerator;
use outbe_protocol::OutbeV1;
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::emit_mint::COMBINED_LEN as EMIT_MINT_COMBINED_LEN;
use outbe_zk_canonical::noir::emit_mint::{EmitMint, PublicInputs, Witness};
use outbe_zk_canonical::u256;

use crate::hash::{
    address_field, change_key, empty_subtrees, field_to_be_bytes, merkle_node, note_commitment,
    note_sn as derive_note_sn, nullifier as derive_nullifier, Field,
};
use crate::precompile::{base_gas, dispatch, IEmit, EMIT_VIEW_BASE_GAS, PAYABLE_SELECTORS};
use crate::schema::{EmitContract, EMIT_TREE_CAPACITY, EMIT_TREE_DEPTH};

const CHAIN_ID: u64 = 31_337;
const OTHER_CHAIN_ID: u64 = 19_280_501;

const ALICE: Address = Address::new([0x11; 20]);
const BOB: Address = Address::new([0x22; 20]);
const CAROL: Address = Address::new([0x33; 20]);
const DAVE: Address = Address::new([0x44; 20]);

fn assert_revert(result: Result<(), PrecompileError>, expected: &str) {
    match result {
        Err(PrecompileError::Revert(message)) => assert_eq!(message, expected),
        other => panic!("expected revert `{expected}`, got {other:?}"),
    }
}

fn b256(field: Field) -> B256 {
    B256::new(field_to_be_bytes(field))
}

fn small_word(low_byte: u8) -> B256 {
    let mut word = [0u8; 32];
    word[31] = low_byte;
    B256::new(word)
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    word
}

fn u128_word(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..32].copy_from_slice(&value.to_be_bytes());
    word
}

// ---- selectors, payable policy, gas ---------------------------------------

#[test]
fn selectors_and_gas_are_pinned() {
    assert_eq!(
        alloy_primitives::hex::encode(IEmit::burnCall::SELECTOR),
        "08a1eee1"
    );
    assert_eq!(
        alloy_primitives::hex::encode(IEmit::mintCall::SELECTOR),
        "5b278400"
    );
    assert_eq!(PAYABLE_SELECTORS, &[IEmit::burnCall::SELECTOR]);
    assert_eq!(
        base_gas(&IEmit::burnCall { noteSn: B256::ZERO }.abi_encode()),
        530_000
    );
    assert_eq!(base_gas(&[0xee; 4]), u64::MAX);
    let mint_calldata = IEmit::mintCall {
        payoutRecipient: CAROL,
        root: B256::ZERO,
        nullifier: B256::ZERO,
        noteOwner: BOB,
        mintUnits: U256::ONE,
        changeCommitment: B256::ZERO,
        proof: Bytes::new(),
    }
    .abi_encode();
    assert_eq!(base_gas(&mint_calldata), 3_517_500);
    assert_eq!(
        base_gas(&IEmit::currentRootCall {}.abi_encode()),
        EMIT_VIEW_BASE_GAS
    );
    assert_eq!(
        base_gas(&IEmit::leafCountCall {}.abi_encode()),
        EMIT_VIEW_BASE_GAS
    );
    assert_eq!(
        base_gas(
            &IEmit::isSpentCall {
                nullifier: B256::ZERO
            }
            .abi_encode()
        ),
        EMIT_VIEW_BASE_GAS
    );
    assert_eq!(
        base_gas(
            &IEmit::hasCommitmentCall {
                commitment: B256::ZERO
            }
            .abi_encode()
        ),
        EMIT_VIEW_BASE_GAS
    );
}

// ---- Current circuit golden formula vector -------------------------------

#[test]
fn formulas_match_pinned_circuit_vector() {
    let chain_id = 31_337u64;
    let owner = [0x22u8; 20];
    let key = Field::from(17u64);
    let serial = derive_note_sn(owner, key);
    let commitment = note_commitment(chain_id, serial, U256::from(100));
    let n = derive_nullifier(commitment, key);
    let next_key = change_key(key, n);
    let next_serial = derive_note_sn(owner, next_key);
    let change = note_commitment(chain_id, next_serial, U256::from(60));
    let next_n = derive_nullifier(change, next_key);

    let zeros = empty_subtrees(chain_id, EMIT_TREE_DEPTH);
    let mut root = merkle_node(commitment, zeros[0]);
    for sibling in zeros.iter().take(EMIT_TREE_DEPTH).skip(1) {
        root = merkle_node(root, *sibling);
    }

    let cases: [(Field, &str); 8] = [
        (
            serial,
            "0x0bb7a42dc8456b387d334b2b46ff1833eeda93134e947bcb9759363ebeb15f14",
        ),
        (
            commitment,
            "0x2908a2b4b3d801f4937fa62a77cfdb2c1653fc95f3ccdde6f2c25303241556a6",
        ),
        (
            n,
            "0x1c291f2dda40b80a655cfa18702cf9518993df0c27e864e2ad81809b1d395a33",
        ),
        (
            next_key,
            "0x1cfd27606ce2303a242c5ab395c981e3efad9658384972c98082ad08ae4d6df6",
        ),
        (
            next_serial,
            "0x2632987ca79080b3430ba9f04e4b14032473c0871494e9689a32da0679d94143",
        ),
        (
            change,
            "0x077056529800880c562feca3846bbb34831a16e781aeffce294ec183558efb64",
        ),
        (
            next_n,
            "0x197a0b51419905416c762add627f880dcce358fe120682112f1fca2c6a30f8b1",
        ),
        (
            root,
            "0x286ae1be8815c6c04b6b33e7aafefd79b28f5d5642128242129dfb8aab3fc3a6",
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(format!("{:#x}", b256(actual)), expected);
    }
}
/// Minimal reference tree mirroring the PoC's naive recompute semantics; used
/// to derive witnesses and to cross-check the runtime's stored incremental
/// tree.
struct ReferenceTree {
    leaves: Vec<Field>,
    zeros: Vec<Field>,
}

impl ReferenceTree {
    fn new(chain_id: u64) -> Self {
        Self {
            leaves: Vec::new(),
            zeros: empty_subtrees(chain_id, EMIT_TREE_DEPTH),
        }
    }

    fn append(&mut self, leaf: Field) -> u32 {
        let index = self.leaves.len() as u32;
        self.leaves.push(leaf);
        index
    }

    fn root(&self) -> Field {
        self.root_at(self.leaves.len())
    }

    /// Root as it was with only the first `count` leaves appended.
    fn root_at(&self, count: usize) -> Field {
        let mut nodes = self.leaves[..count].to_vec();
        for level in 0..EMIT_TREE_DEPTH {
            if nodes.len() % 2 == 1 {
                nodes.push(self.zeros[level]);
            }
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| merkle_node(pair[0], pair[1]))
                .collect();
        }
        nodes[0]
    }

    fn path_at(&self, leaf_index: u32) -> [Field; EMIT_TREE_DEPTH] {
        let mut index = leaf_index as usize;
        let mut path = [Field::from(0u64); EMIT_TREE_DEPTH];
        let mut nodes = self.leaves.clone();
        for (level, sibling) in path.iter_mut().enumerate() {
            *sibling = nodes.get(index ^ 1).copied().unwrap_or(self.zeros[level]);
            if nodes.len() % 2 == 1 {
                nodes.push(self.zeros[level]);
            }
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| merkle_node(pair[0], pair[1]))
                .collect();
            index >>= 1;
        }
        path
    }
}

// ---- real-proof fixture ----------------------------------------------------

fn combined_from(public: &PublicInputs, proof_words: &[Vec<u8>]) -> Vec<u8> {
    let fields =
        <EmitMint as outbe_protocol::protocol::zk::Circuit<OutbeV1>>::public_inputs(public);
    let mut combined = Vec::with_capacity(4 + 32 * (fields.len() + proof_words.len()));
    combined.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for f in fields {
        let bytes = f.into_bigint().to_bytes_be();
        combined.resize(combined.len() + 32 - bytes.len(), 0);
        combined.extend_from_slice(&bytes);
    }
    for word in proof_words {
        combined.extend_from_slice(word);
    }
    combined
}

/// Proves `(note_amount, key, leaf_index)` against the tree's root when only
/// `root_leaf_count` leaves existed, for `mint_units`, with the deterministic
/// change commitment (zero for a full mint).
fn prove_mint(
    tree: &ReferenceTree,
    owner: Address,
    key: Field,
    note_amount: u128,
    leaf_index: u32,
    root_leaf_count: usize,
    mint_units: u128,
) -> Vec<u8> {
    prove_mint_u256(
        tree,
        owner,
        key,
        U256::from(note_amount),
        leaf_index,
        root_leaf_count,
        U256::from(mint_units),
    )
}

fn prove_mint_u256(
    tree: &ReferenceTree,
    owner: Address,
    key: Field,
    note_amount: U256,
    leaf_index: u32,
    root_leaf_count: usize,
    mint_units: U256,
) -> Vec<u8> {
    let serial = derive_note_sn(owner.into(), key);
    let commitment = note_commitment(CHAIN_ID, serial, note_amount);
    let nullifier = derive_nullifier(commitment, key);
    let remaining = note_amount.checked_sub(mint_units).expect("mint fits note");
    let change = if remaining.is_zero() {
        Field::from(0u64)
    } else {
        let next_key = change_key(key, nullifier);
        note_commitment(CHAIN_ID, derive_note_sn(owner.into(), next_key), remaining)
    };
    let public = PublicInputs {
        chain_id: CHAIN_ID,
        root: tree.root_at(root_leaf_count),
        nullifier,
        note_owner: address_field(owner.into()),
        mint_units: u256::to_limbs(mint_units),
        change_commitment: change,
    };
    let witness = Witness {
        note_amount: u256::to_limbs(note_amount),
        note_spend_key: key,
        leaf_index,
        auth_path: tree.path_at(leaf_index),
    };
    let proof =
        ProofGenerator::<OutbeV1, EmitMint>::generate(&Barretenberg::default(), &witness, &public)
            .expect("emit mint proof generation");
    combined_from(&public, &proof.proof)
}

/// A combined blob of the frozen exact length embedding exactly the given
/// statement words plus a padded proof tail; passes the decoder but is not a
/// valid proof. Used only for guards that fire before verification.
fn fabricated_statement(
    chain_id: u64,
    root: B256,
    nullifier: B256,
    owner: Address,
    units: u128,
    change: B256,
) -> Vec<u8> {
    let mut combined = Vec::with_capacity(EMIT_MINT_COMBINED_LEN);
    combined.extend_from_slice(&8u32.to_be_bytes());
    combined.extend_from_slice(&u64_word(chain_id));
    for word in [root, nullifier] {
        combined.extend_from_slice(word.as_slice());
    }
    let mut owner_word = [0u8; 32];
    owner_word[12..].copy_from_slice(owner.0.as_slice());
    combined.extend_from_slice(&owner_word);
    for limb in u256::to_limbs(U256::from(units)) {
        combined.extend_from_slice(&u128_word(limb));
    }
    combined.extend_from_slice(change.as_slice());
    // Pad the proof tail to the frozen circuit's exact combined length so
    // the blob passes decoder framing and the guard under test is what fires.
    let tail_words = (EMIT_MINT_COMBINED_LEN - combined.len()) / 32;
    for _ in 0..tail_words {
        combined.extend_from_slice(&[7u8; 32]);
    }
    combined
}

fn burn_calldata(note_sn: B256) -> Vec<u8> {
    IEmit::burnCall { noteSn: note_sn }.abi_encode()
}

fn mint_calldata(
    payout: Address,
    root: B256,
    nullifier: B256,
    owner: Address,
    units: u128,
    change: B256,
    proof: &[u8],
) -> Vec<u8> {
    mint_calldata_u256(
        payout,
        root,
        nullifier,
        owner,
        U256::from(units),
        change,
        proof,
    )
}

fn mint_calldata_u256(
    payout: Address,
    root: B256,
    nullifier: B256,
    owner: Address,
    units: U256,
    change: B256,
    proof: &[u8],
) -> Vec<u8> {
    IEmit::mintCall {
        payoutRecipient: payout,
        root,
        nullifier,
        noteOwner: owner,
        mintUnits: units,
        changeCommitment: change,
        proof: Bytes::copy_from_slice(proof),
    }
    .abi_encode()
}

/// The runtime-level note the plan scenario burns: Bob's serial under key 17.
fn scenario_serial() -> Field {
    derive_note_sn(BOB.into(), Field::from(17u64))
}

/// Simulates the EVM value boundary's credit, then runs a burn through the
/// real dispatch.
fn run_burn(
    provider: &mut HashMapStorageProvider,
    caller: Address,
    value: u128,
    note_sn: B256,
) -> Result<(), PrecompileError> {
    run_burn_u256(provider, caller, U256::from(value), note_sn)
}

fn run_burn_u256(
    provider: &mut HashMapStorageProvider,
    caller: Address,
    value: U256,
    note_sn: B256,
) -> Result<(), PrecompileError> {
    provider.enter(|storage| {
        storage.increase_balance(EMIT_ADDRESS, value)?;
        let data = burn_calldata(note_sn);
        dispatch(storage, &data, caller, value).map(|_| ())
    })
}

/// Runs a burn through dispatch assuming the boundary credit already landed
/// (used by the fault-injection sweeps, which set the fault after crediting).
fn dispatch_credited_burn(
    provider: &mut HashMapStorageProvider,
    caller: Address,
    value: u64,
    note_sn: B256,
) -> Result<(), PrecompileError> {
    provider.enter(|storage| {
        let data = burn_calldata(note_sn);
        dispatch(storage, &data, caller, U256::from(value)).map(|_| ())
    })
}

fn dispatch_mint(
    provider: &mut HashMapStorageProvider,
    caller: Address,
    data: &[u8],
) -> Result<(), PrecompileError> {
    provider.enter(|storage| dispatch(storage, data, caller, U256::ZERO).map(|_| ()))
}

// ---- burn: lazy init, events, guards ---------------------------------------

#[test]
fn burn_initializes_lazily_and_emits_amount_bound_new_note() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let serial = scenario_serial();
    let commitment = note_commitment(CHAIN_ID, serial, U256::from(100));
    let mut reference = ReferenceTree::new(CHAIN_ID);
    reference.append(commitment);

    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();

    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 1);
        assert_eq!(emit.current_root.read().unwrap(), b256(reference.root()));
        assert!(emit.commitments.read(&b256(commitment)).unwrap());
        assert_eq!(emit.recent_roots.read_all().unwrap().len(), 2);
    });
    assert_eq!(provider.get_balance(EMIT_ADDRESS), U256::ZERO);

    let events = provider.get_events(EMIT_ADDRESS);
    assert_eq!(events.len(), 1, "burn emits exactly one NewNote");
    let note = IEmit::NewNote::decode_log_data(&events[0]).unwrap();
    assert_eq!(note.commitment, b256(commitment));
    assert_eq!(note.leafIndex, 0);
    assert_eq!(note.noteAmount, 100);
    assert_eq!(note.rootAfter, b256(reference.root()));
}

#[test]
fn burn_accepts_full_width_u256_amount() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let serial = scenario_serial();
    let amount = (U256::from(1) << 200) + U256::from(7);
    let commitment = note_commitment(CHAIN_ID, serial, amount);

    run_burn_u256(&mut provider, ALICE, amount, b256(serial)).unwrap();

    let note = IEmit::NewNote::decode_log_data(&provider.get_events(EMIT_ADDRESS)[0]).unwrap();
    assert_eq!(note.commitment, b256(commitment));
    assert_eq!(note.noteAmount, amount);
    assert_eq!(provider.get_balance(EMIT_ADDRESS), U256::ZERO);
}

#[test]
fn burn_guards_revert_with_frozen_texts() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.enter(|storage| {
        let data = burn_calldata(b256(scenario_serial()));
        let result = dispatch(storage, &data, ALICE, U256::ZERO).map(|_| ());
        assert_revert(result, "Emit burn value must be non-zero");
    });
    let modulus = B256::new(alloy_primitives::hex!(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
    ));
    provider.enter(|storage| {
        let data = burn_calldata(modulus);
        let result = dispatch(storage, &data, ALICE, U256::from(1u64)).map(|_| ());
        assert_revert(result, "Emit noteSn is not a canonical BN254 field");
    });
    provider.enter(|storage| {
        let data = burn_calldata(B256::ZERO);
        let result = dispatch(storage, &data, ALICE, U256::from(1u64)).map(|_| ());
        assert_revert(result, "Emit noteSn must be non-zero");
    });
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.current_root.read().unwrap(), B256::ZERO);
        assert_eq!(emit.leaf_count.read().unwrap(), 0);
    });
    assert!(provider.get_events(EMIT_ADDRESS).is_empty());
}

#[test]
fn duplicate_burn_keys_the_full_commitment_not_the_serial() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let serial = scenario_serial();
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();

    // Same serial and amount: the identical commitment is rejected.
    let duplicate = run_burn(&mut provider, ALICE, 100, b256(serial));
    assert_revert(duplicate, "Emit commitment already exists");

    // Same serial, different amount: allowed. The nullifier binds the full
    // commitment, so the two notes carry distinct nullifiers and each is
    // independently spendable — no sibling stranding.
    run_burn(&mut provider, ALICE, 60, b256(serial)).unwrap();
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 2);
    });
}

// ---- mint guards (pre-verification paths, fabricated statements) -----------

#[test]
fn mint_before_any_burn_is_not_initialized() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let proof = fabricated_statement(
        CHAIN_ID,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
    );
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit is not initialized");

    // A pristine chain reports `not initialized` even when the embedded
    // statement mismatches calldata or a field is noncanonical: framing is
    // the only check allowed before the initialization gate (frozen matrix).
    let mismatched = mint_calldata(
        CAROL,
        small_word(9), // differs from every embedded word below
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &mismatched);
    assert_revert(result, "Emit is not initialized");
    let noncanonical = mint_calldata(
        CAROL,
        B256::new(alloy_primitives::hex!(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
        )),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &noncanonical);
    assert_revert(result, "Emit is not initialized");
}

#[test]
fn mint_noncanonical_statement_fields_revert_by_name() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    run_burn(&mut provider, ALICE, 100, b256(scenario_serial())).unwrap();
    let modulus = B256::new(alloy_primitives::hex!(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
    ));
    // Head word offsets after the 4-byte selector.
    for (field_name, offset) in [
        ("root", 4 + 32),
        ("nullifier", 4 + 64),
        ("changeCommitment", 4 + 5 * 32),
    ] {
        let proof = fabricated_statement(
            CHAIN_ID,
            small_word(2),
            small_word(3),
            BOB,
            40,
            small_word(25),
        );
        let mut data = mint_calldata(
            CAROL,
            small_word(2),
            small_word(3),
            BOB,
            40,
            small_word(25),
            &proof,
        );
        data[offset..offset + 32].copy_from_slice(modulus.as_slice());
        let result = dispatch_mint(&mut provider, BOB, &data);
        assert_revert(
            result,
            &format!("Emit {field_name} is not a canonical BN254 field"),
        );
    }
}

#[test]
fn malformed_proof_tail_reverts_never_fatal() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let serial = scenario_serial();
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new(CHAIN_ID);
    let leaf = tree.append(note_commitment(CHAIN_ID, serial, U256::from(100)));
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();

    // Every pre-verification guard passes on this real proof — the statement
    // matches calldata, the root is the current root, the nullifier is
    // fresh — until one proof-section word is corrupted past the BN254
    // modulus. The backend rejects it with an Err, which must surface as a
    // user revert, never a fatal verifier error (an attacker controls every
    // byte of this tail).
    let nullifier = derive_nullifier(note_commitment(CHAIN_ID, serial, U256::from(100)), key);
    let change = note_commitment(
        CHAIN_ID,
        derive_note_sn(BOB.into(), change_key(key, nullifier)),
        U256::from(60),
    );
    let mut proof = prove_mint(&tree, BOB, key, 100, leaf, 1, 40);
    let tail = &mut proof[4 + 8 * 32..];
    tail[..32].copy_from_slice(&alloy_primitives::hex!(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
    ));
    let data = mint_calldata(
        CAROL,
        b256(tree.root_at(1)),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    match result {
        Err(PrecompileError::Revert(message)) => assert!(
            message.starts_with("Emit mint proof is malformed: zk verification backend failed"),
            "unexpected revert text: {message}"
        ),
        other => panic!("malformed tail must revert, got {other:?}"),
    }

    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert!(!emit.spent_nullifiers.read(&b256(nullifier)).unwrap());
        assert_eq!(emit.leaf_count.read().unwrap(), 1);
    });
    assert_eq!(provider.get_balance(CAROL), U256::ZERO);
}

#[test]
fn mint_statement_mismatch_and_malformed_framing_revert() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    run_burn(&mut provider, ALICE, 100, b256(scenario_serial())).unwrap();
    let proof = fabricated_statement(
        CHAIN_ID,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
    );

    // Well-framed proof, but the explicit calldata disagrees on mintUnits.
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        41,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit mint proof statement does not match calldata");

    // Malformed framing: wrong public-input count.
    let mut truncated = proof.clone();
    truncated[..4].copy_from_slice(&5u32.to_be_bytes());
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &truncated,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    match result {
        Err(PrecompileError::Revert(message)) => assert!(
            message.starts_with("Emit mint proof is malformed:"),
            "unexpected message {message}"
        ),
        other => panic!("expected malformed revert, got {other:?}"),
    }
}

#[test]
fn mint_wrong_caller_recipient_owner_units_and_chain_id_revert() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    run_burn(&mut provider, ALICE, 100, b256(scenario_serial())).unwrap();

    let matching = |chain_id: u64, owner: Address, units: u128| {
        fabricated_statement(
            chain_id,
            small_word(2),
            small_word(3),
            owner,
            units,
            small_word(25),
        )
    };

    // Caller mismatch: statement owner is BOB, caller is ALICE.
    let proof = matching(CHAIN_ID, BOB, 40);
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, ALICE, &data);
    assert_revert(result, "Emit caller is not note owner");

    // Zero recipient.
    let data = mint_calldata(
        Address::ZERO,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit payout recipient must be non-zero");

    // Zero owner: the fabricated proof embeds the zero owner too, so the
    // statement matches and the owner guard fires.
    let proof = matching(CHAIN_ID, Address::ZERO, 40);
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        Address::ZERO,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, Address::ZERO, &data);
    assert_revert(result, "Emit note owner must be non-zero");

    // Zero units.
    let proof = matching(CHAIN_ID, BOB, 0);
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        0,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit mint units must be non-zero");

    // Chain-ID mismatch: the proof carries a different chain.
    let proof = matching(OTHER_CHAIN_ID, BOB, 40);
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit chain ID does not match runtime");
}

#[test]
fn mint_refuses_value_and_rejects_non_frozen_proof_lengths() {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    run_burn(&mut provider, ALICE, 100, b256(scenario_serial())).unwrap();
    let proof = fabricated_statement(
        CHAIN_ID,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
    );
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &proof,
    );

    // Value on the mint selector is refused even though the route is payable.
    provider.enter(|storage| {
        let result = dispatch(storage, &data, BOB, U256::from(1u64)).map(|_| ());
        assert_revert(result, "non-payable function called with value");
    });

    // ABI framing is Alloy's job now: a non-canonical dynamic offset is a
    // plain decode revert (alloy's own error text) and must not touch state.
    let mut bad_offset = data.clone();
    bad_offset[4 + 6 * 32 + 31] = 8; // offset 8 ≠ 224
    let result = dispatch_mint(&mut provider, BOB, &bad_offset);
    match result {
        Err(PrecompileError::Revert(_)) => {}
        other => panic!("non-canonical offset must decode-revert, got {other:?}"),
    }

    // The frozen circuit's exact proof length is enforced by the decoder and
    // surfaces through the frozen malformed-proof text.
    let mut short = proof.clone();
    short.truncate(short.len() - 32);
    let data = mint_calldata(
        CAROL,
        small_word(2),
        small_word(3),
        BOB,
        40,
        small_word(25),
        &short,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(
        result,
        &format!(
            "Emit mint proof is malformed: zk_verify: combined proof length is {} bytes, expected {}",
            EMIT_MINT_COMBINED_LEN - 32,
            EMIT_MINT_COMBINED_LEN
        ),
    );

    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 1);
    });
}

// ---- real-proof transitions ------------------------------------------------

/// The plan scenario: Alice burns 100 into a Bob-owned serial; Bob partially
/// mints 40 to Carol (change note appended at leaf 1); Bob fully mints the
/// remaining 60 to Dave from the ratcheted change note. Replay of the first
/// mint must fail without moving anything.
#[test]
fn plan_scenario_partial_then_full_mint_with_real_proofs() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let pool = CHAIN_ID;
    let key = Field::from(17u64);

    // Burn.
    let serial = scenario_serial();
    let mut tree = ReferenceTree::new(pool);
    let note_leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
    let root_after_burn = tree.root_at(1);

    // Partial mint of 40 to Carol.
    let partial_proof = prove_mint(&tree, BOB, key, 100, note_leaf, 1, 40);
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let next_key = change_key(key, nullifier);
    let change = note_commitment(pool, derive_note_sn(BOB.into(), next_key), U256::from(60));
    let change_leaf = tree.append(change);
    let root_after_change = tree.root_at(2);

    let partial_data = mint_calldata(
        CAROL,
        b256(root_after_burn),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &partial_proof,
    );
    dispatch_mint(&mut provider, BOB, &partial_data).unwrap();
    assert_eq!(provider.get_balance(CAROL), U256::from(40u64));
    assert_eq!(provider.get_balance(EMIT_ADDRESS), U256::ZERO);

    // Full mint of the remaining 60 from the change note to Dave.
    let full_proof = prove_mint(&tree, BOB, next_key, 60, change_leaf, 2, 60);
    let next_nullifier = derive_nullifier(change, next_key);
    let full_data = mint_calldata(
        DAVE,
        b256(root_after_change),
        b256(next_nullifier),
        BOB,
        60,
        B256::ZERO,
        &full_proof,
    );
    dispatch_mint(&mut provider, BOB, &full_data).unwrap();
    assert_eq!(provider.get_balance(DAVE), U256::from(60u64));

    // Base-unit conservation: 40 + 60 public again, nothing stranded.
    assert_eq!(provider.get_balance(EMIT_ADDRESS), U256::ZERO);
    assert_eq!(
        provider.get_balance(CAROL) + provider.get_balance(DAVE),
        U256::from(100u64)
    );

    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 2);
        assert_eq!(emit.current_root.read().unwrap(), b256(tree.root()));
        assert!(emit.spent_nullifiers.read(&b256(nullifier)).unwrap());
        assert!(emit.spent_nullifiers.read(&b256(next_nullifier)).unwrap());
    });

    // Partial mint emits NoteUsed first, then NewNote(change, index, root, 0).
    let ordered = provider.get_ordered_events();
    let emit_events: Vec<&LogData> = ordered
        .iter()
        .filter(|log| log.address == EMIT_ADDRESS)
        .map(|log| &log.data)
        .collect();
    assert_eq!(
        emit_events.len(),
        4,
        "NewNote(burn), NoteUsed(40), NewNote(change), NoteUsed(60)"
    );
    let burn_note = IEmit::NewNote::decode_log_data(emit_events[0]).unwrap();
    assert_eq!(burn_note.noteAmount, 100);
    let used = IEmit::NoteUsed::decode_log_data(emit_events[1]).unwrap();
    assert_eq!(used.noteOwner, BOB);
    assert_eq!(used.payoutRecipient, CAROL);
    assert_eq!(used.nullifier, b256(nullifier));
    assert_eq!(used.mintAmount, 40);
    let change_note = IEmit::NewNote::decode_log_data(emit_events[2]).unwrap();
    assert_eq!(change_note.commitment, b256(change));
    assert_eq!(change_note.leafIndex, change_leaf);
    assert_eq!(change_note.rootAfter, b256(root_after_change));
    assert_eq!(
        change_note.noteAmount, 0,
        "private change uses the zero sentinel"
    );

    let final_use = IEmit::NoteUsed::decode_log_data(emit_events[3]).unwrap();
    assert_eq!(final_use.noteOwner, BOB);
    assert_eq!(final_use.payoutRecipient, DAVE);
    assert_eq!(final_use.nullifier, b256(next_nullifier));
    assert_eq!(final_use.mintAmount, 60);

    // Replay of the first mint: rejected, nothing moves.
    let result = dispatch_mint(&mut provider, BOB, &partial_data);
    assert_revert(result, "Emit nullifier has already been spent");
    assert_eq!(provider.get_balance(CAROL), U256::from(40u64));
    assert_eq!(provider.get_balance(DAVE), U256::from(60u64));
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 2);
    });
}

/// Full uint256 cutover end to end: burn, partially mint, append change, and
/// fully mint the remainder with values above the old uint128 ceiling.
#[test]
fn amounts_above_the_u128_range_mint_end_to_end() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let serial = scenario_serial();
    let key = Field::from(17u64);
    let note = (U256::from(1) << 200) + U256::from(100);
    let minted = (U256::from(1) << 199) + U256::from(40);
    let remainder = note - minted;

    let mut tree = ReferenceTree::new(CHAIN_ID);
    let note_leaf = tree.append(note_commitment(CHAIN_ID, serial, note));
    run_burn_u256(&mut provider, ALICE, note, b256(serial)).unwrap();
    let root_after_burn = tree.root_at(1);

    let commitment = note_commitment(CHAIN_ID, serial, note);
    let nullifier = derive_nullifier(commitment, key);
    let next_key = change_key(key, nullifier);
    let change = note_commitment(CHAIN_ID, derive_note_sn(BOB.into(), next_key), remainder);
    let partial = prove_mint_u256(&tree, BOB, key, note, note_leaf, 1, minted);
    let data = mint_calldata_u256(
        CAROL,
        b256(root_after_burn),
        b256(nullifier),
        BOB,
        minted,
        b256(change),
        &partial,
    );
    dispatch_mint(&mut provider, BOB, &data).unwrap();
    assert_eq!(provider.get_balance(CAROL), minted);

    let change_leaf = tree.append(change);
    let next_nullifier = derive_nullifier(change, next_key);
    let full = prove_mint_u256(&tree, BOB, next_key, remainder, change_leaf, 2, remainder);
    let data = mint_calldata_u256(
        DAVE,
        b256(tree.root_at(2)),
        b256(next_nullifier),
        BOB,
        remainder,
        B256::ZERO,
        &full,
    );
    dispatch_mint(&mut provider, BOB, &data).unwrap();

    assert_eq!(provider.get_balance(DAVE), remainder);
    assert_eq!(
        provider.get_balance(CAROL) + provider.get_balance(DAVE),
        note
    );
    assert_eq!(provider.get_balance(EMIT_ADDRESS), U256::ZERO);
}

#[test]
fn stale_root_past_the_32_window_is_rejected() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let pool = CHAIN_ID;
    let mut tree = ReferenceTree::new(pool);

    let serial = scenario_serial();
    let leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
    let old_root = tree.root_at(1);
    let proof = prove_mint(&tree, BOB, Field::from(17u64), 100, leaf, 1, 40);
    let nullifier = derive_nullifier(
        note_commitment(pool, serial, U256::from(100)),
        Field::from(17u64),
    );
    let next_key = change_key(Field::from(17u64), nullifier);
    let change = note_commitment(pool, derive_note_sn(BOB.into(), next_key), U256::from(60));

    // 32 further appends evict the burn root from the window.
    for index in 0..32u64 {
        let sn = Field::from(1_000u64 + index);
        tree.append(note_commitment(pool, sn, U256::from(1)));
        run_burn(&mut provider, ALICE, 1, b256(sn)).unwrap();
    }
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert!(!emit
            .recent_roots
            .read_all()
            .unwrap()
            .contains(&b256(old_root)));
    });

    let data = mint_calldata(
        CAROL,
        b256(old_root),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit root is not recent");
}

#[test]
fn payout_overflow_is_a_user_revert_before_mutation() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let pool = CHAIN_ID;
    let serial = scenario_serial();
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new(pool);
    let leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
    let proof = prove_mint(&tree, BOB, key, 100, leaf, 1, 40);
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let change = note_commitment(
        pool,
        derive_note_sn(BOB.into(), change_key(key, nullifier)),
        U256::from(60),
    );

    provider.set_balance(CAROL, U256::MAX);
    let data = mint_calldata(
        CAROL,
        b256(tree.root_at(1)),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit payout balance overflow");
    assert_eq!(provider.get_balance(CAROL), U256::MAX);
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 1);
        assert!(!emit.spent_nullifiers.read(&b256(nullifier)).unwrap());
    });
}

#[test]
fn full_tree_rejects_burns_and_partial_mints() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let pool = CHAIN_ID;
    let serial = scenario_serial();

    // Test-only leaf-count setup: the tree is artificially at capacity.
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        emit.leaf_count.write(EMIT_TREE_CAPACITY as u32).unwrap();
    });

    let result = run_burn(&mut provider, ALICE, 1, b256(Field::from(777u64)));
    assert_revert(result, "Emit commitment tree is full");

    // A partial mint must also refuse to append past capacity; it needs a
    // real proof because the capacity guard for change runs after
    // verification.
    let mut tree = ReferenceTree::new(pool);
    let leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    let proof = prove_mint(&tree, BOB, Field::from(17u64), 100, leaf, 1, 40);
    let nullifier = derive_nullifier(
        note_commitment(pool, serial, U256::from(100)),
        Field::from(17u64),
    );
    let change = note_commitment(
        pool,
        derive_note_sn(BOB.into(), change_key(Field::from(17u64), nullifier)),
        U256::from(60),
    );
    let data = mint_calldata(
        CAROL,
        b256(tree.root_at(1)),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit commitment tree is full");
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), EMIT_TREE_CAPACITY as u32);
        assert!(!emit.spent_nullifiers.read(&b256(nullifier)).unwrap());
    });
}

#[test]
fn deterministic_change_precreation_reverts_partial_mint_atomically() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let pool = CHAIN_ID;
    let serial = scenario_serial();
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new(pool);

    let leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let next_key = change_key(key, nullifier);
    let next_serial = derive_note_sn(BOB.into(), next_key);
    let change = note_commitment(pool, next_serial, U256::from(60));

    // Anyone pre-creates the deterministic change commitment by burning the
    // successor serial with the matching amount.
    let proof = prove_mint(&tree, BOB, key, 100, leaf, 1, 40);
    tree.append(change);
    run_burn(&mut provider, ALICE, 60, b256(next_serial)).unwrap();

    let data = mint_calldata(
        CAROL,
        b256(tree.root_at(1)),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );
    let result = dispatch_mint(&mut provider, BOB, &data);
    assert_revert(result, "Emit commitment already exists");
    assert_eq!(provider.get_balance(CAROL), U256::ZERO);
    provider.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.leaf_count.read().unwrap(), 2);
        assert!(!emit.spent_nullifiers.read(&b256(nullifier)).unwrap());
    });
}

// ---- two-chain separation ---------------------------------------------------

#[test]
fn chains_derive_separate_commitments_and_roots_without_stored_configuration() {
    let chain_id_a = CHAIN_ID;
    let chain_id_b = OTHER_CHAIN_ID;

    let serial = scenario_serial();
    let commitment_a = note_commitment(chain_id_a, serial, U256::from(100));
    let commitment_b = note_commitment(chain_id_b, serial, U256::from(100));
    assert_ne!(commitment_a, commitment_b);

    let mut provider_a = HashMapStorageProvider::new(CHAIN_ID);
    let mut provider_b = HashMapStorageProvider::new(OTHER_CHAIN_ID);
    run_burn(&mut provider_a, ALICE, 100, b256(serial)).unwrap();
    run_burn(&mut provider_b, ALICE, 100, b256(serial)).unwrap();

    // The same serial+amount coexists on both chains with different roots.
    let mut reference_a = ReferenceTree::new(chain_id_a);
    reference_a.append(commitment_a);
    let mut reference_b = ReferenceTree::new(chain_id_b);
    reference_b.append(commitment_b);
    provider_a.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.current_root.read().unwrap(), b256(reference_a.root()));
    });
    provider_b.enter(|storage| {
        let emit: EmitContract<'_> = storage.contract();
        assert_eq!(emit.current_root.read().unwrap(), b256(reference_b.root()));
    });

    // No chain-specific empty-ladder word is persisted as configuration.
    let zeros_a = empty_subtrees(chain_id_a, EMIT_TREE_DEPTH);
    let zeros_b = empty_subtrees(chain_id_b, EMIT_TREE_DEPTH);
    for (name, provider) in [("a", &provider_a), ("b", &provider_b)] {
        for ((address, _slot), value) in provider.storage.iter() {
            if *address != EMIT_ADDRESS {
                continue;
            }
            let word = B256::new(value.to_be_bytes::<32>());
            let as_field = Field::from_be_bytes_mod_order(word.as_slice());
            // Levels 0..20 are configuration the runtime must re-derive.
            // zeros[20] — the empty root — is legitimate protocol data: the
            // root window is seeded with it at initialization.
            for zero in zeros_a
                .iter()
                .take(EMIT_TREE_DEPTH)
                .chain(zeros_b.iter().take(EMIT_TREE_DEPTH))
            {
                assert_ne!(
                    as_field, *zero,
                    "chain {name}: empty-ladder word must not be persisted"
                );
            }
        }
    }
}

// ---- stored layout audit ----------------------------------------------------

#[test]
fn stored_layout_holds_no_leaves_right_nodes_or_ladder() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    let pool = CHAIN_ID;
    let serial = scenario_serial();
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new(pool);
    let leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();

    let proof = prove_mint(&tree, BOB, key, 100, leaf, 1, 40);
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let change = note_commitment(
        pool,
        derive_note_sn(BOB.into(), change_key(key, nullifier)),
        U256::from(60),
    );
    let data = mint_calldata(
        CAROL,
        b256(tree.root_at(1)),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );
    dispatch_mint(&mut provider, BOB, &data).unwrap();

    // Audit the raw slots at EMIT_ADDRESS: direct writes only to the fixed
    // slots 0, 1, 3, 4 (the maps' base slots 2, 5, 6 are never written —
    // their entries live under keccak-derived keys), plus keccak-derived
    // mapping/buffer data slots, and nothing else — no leaves, right nodes,
    // or ladder entries outside those namespaces.
    let mut namespaces = std::collections::BTreeSet::new();
    for ((address, slot), _value) in provider.storage.iter() {
        if *address != EMIT_ADDRESS {
            continue;
        }
        let fixed = slot <= &U256::from(6u64);
        namespaces.insert(if fixed { 1000 + slot.to::<u64>() } else { 100 });
    }
    assert_eq!(
        namespaces,
        [1000u64, 1001, 1003, 1004, 100].into_iter().collect(),
        "unexpected storage namespace at EMIT_ADDRESS"
    );

    // The leaf commitment itself is stored only inside the commitments map
    // (slot 5), never as a tree node slot.
    let leaf_word = b256(note_commitment(pool, serial, U256::from(100)));
    for ((address, slot), value) in provider.storage.iter() {
        if *address != EMIT_ADDRESS {
            continue;
        }
        let word = B256::new(value.to_be_bytes::<32>());
        if word == leaf_word {
            // keccak(5 ++ key) is far above slot 6; the fixed slots are 0..6.
            assert!(
                slot > &U256::from(6u64),
                "the leaf commitment may live only in a mapping namespace"
            );
        }
    }
}

// ---- checkpoint rollback under injected faults ------------------------------

#[test]
fn burn_rolls_back_fully_under_fault_injection_on_pristine_and_active_trees() {
    let pristine_ops = {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.enter(|storage| {
            storage
                .increase_balance(EMIT_ADDRESS, U256::from(100u64))
                .unwrap();
        });
        provider.clear_mutation_failure();
        let result = dispatch_credited_burn(&mut provider, ALICE, 100, b256(scenario_serial()));
        result.unwrap();
        provider.clear_mutation_failure()
    };

    for fault in 0..pristine_ops {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        provider.enter(|storage| {
            storage
                .increase_balance(EMIT_ADDRESS, U256::from(100u64))
                .unwrap();
        });
        provider.fail_after_mutation_at(fault);
        let result = dispatch_credited_burn(&mut provider, ALICE, 100, b256(scenario_serial()));
        assert!(result.is_err(), "fault {fault} must fail the burn");
        provider.enter(|storage| {
            let emit: EmitContract<'_> = storage.contract();
            assert_eq!(
                emit.current_root.read().unwrap(),
                B256::ZERO,
                "fault {fault}"
            );
            assert_eq!(emit.leaf_count.read().unwrap(), 0, "fault {fault}");
            assert!(
                emit.recent_roots.read_all().unwrap().is_empty(),
                "fault {fault}"
            );
        });
        assert!(
            provider.get_events(EMIT_ADDRESS).is_empty(),
            "fault {fault}"
        );
        assert_eq!(
            provider.get_balance(EMIT_ADDRESS),
            U256::from(100u64),
            "fault {fault}: credited value must remain"
        );
    }

    // Active tree: initialize, snapshot, then sweep faults over a second burn.
    let active_ops = {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        run_burn(&mut provider, ALICE, 100, b256(scenario_serial())).unwrap();
        provider.enter(|storage| {
            storage
                .increase_balance(EMIT_ADDRESS, U256::from(7u64))
                .unwrap();
        });
        provider.clear_mutation_failure();
        dispatch_credited_burn(&mut provider, ALICE, 7, b256(Field::from(9u64))).unwrap();
        provider.clear_mutation_failure()
    };
    for fault in 0..active_ops {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        run_burn(&mut provider, ALICE, 100, b256(scenario_serial())).unwrap();
        let baseline = provider.storage.clone();
        let baseline_events = provider.get_events(EMIT_ADDRESS).len();
        provider.enter(|storage| {
            storage
                .increase_balance(EMIT_ADDRESS, U256::from(7u64))
                .unwrap();
        });
        provider.fail_after_mutation_at(fault);
        let result = dispatch_credited_burn(&mut provider, ALICE, 7, b256(Field::from(9u64)));
        assert!(result.is_err(), "fault {fault} must fail the active burn");
        assert_eq!(
            provider.storage, baseline,
            "fault {fault}: storage must match the pre-call snapshot"
        );
        assert_eq!(provider.get_events(EMIT_ADDRESS).len(), baseline_events);
        assert_eq!(provider.get_balance(EMIT_ADDRESS), U256::from(7u64));
    }
}

#[test]
fn mint_rolls_back_fully_under_fault_injection() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let pool = CHAIN_ID;
    let serial = scenario_serial();
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new(pool);
    let leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let change = note_commitment(
        pool,
        derive_note_sn(BOB.into(), change_key(key, nullifier)),
        U256::from(60),
    );

    let proof = prove_mint(&tree, BOB, key, 100, leaf, 1, 40);
    let data = mint_calldata(
        CAROL,
        b256(tree.root_at(1)),
        b256(nullifier),
        BOB,
        40,
        b256(change),
        &proof,
    );

    let mint_ops = {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
        provider.clear_mutation_failure();
        dispatch_mint(&mut provider, BOB, &data).unwrap();
        provider.clear_mutation_failure()
    };

    for fault in 0..mint_ops {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        run_burn(&mut provider, ALICE, 100, b256(serial)).unwrap();
        let baseline = provider.storage.clone();
        let baseline_events = provider.get_events(EMIT_ADDRESS).len();
        provider.fail_after_mutation_at(fault);
        let result = dispatch_mint(&mut provider, BOB, &data);
        assert!(result.is_err(), "fault {fault} must fail the mint");
        assert_eq!(
            provider.storage, baseline,
            "fault {fault}: storage must match the pre-mint snapshot"
        );
        assert_eq!(provider.get_events(EMIT_ADDRESS).len(), baseline_events);
        assert_eq!(provider.get_balance(CAROL), U256::ZERO, "fault {fault}");
    }
}
