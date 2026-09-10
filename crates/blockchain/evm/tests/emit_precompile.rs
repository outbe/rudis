//! Execution-level coverage for the Emit precompile route: the full
//! burn → partial mint → full mint → replay scenario with real generated
//! `outbe.emit.mint@1.5.0` proofs, plus frame/value boundary cases extending
//! the `precompile_value_boundary` patterns.

use alloy_evm::{Evm as _, EvmFactory as _};
use alloy_primitives::{Address, Bytes, LogData, B256, U256};
use alloy_sol_types::{SolCall, SolError, SolEvent};
use outbe_emit::hash::{
    address_field, change_key, empty_subtrees, field_to_be_bytes, merkle_node, note_commitment,
    note_sn as derive_note_sn, nullifier as derive_nullifier, Field,
};
use outbe_emit::precompile::IEmit;
use outbe_emit::schema::{EMIT_TREE_CAPACITY, EMIT_TREE_DEPTH};
use outbe_evm::OutbeEvmFactory;
use outbe_primitives::addresses::EMIT_ADDRESS;
use outbe_protocol::protocol::zk::ProofGenerator;
use outbe_protocol::OutbeV1;
use outbe_zk_backend::barretenberg::Barretenberg;
use outbe_zk_canonical::noir::emit_mint::{EmitMint, PublicInputs, Witness};
use outbe_zk_canonical::u256;
use reth_ethereum::evm::primitives::EvmEnv;
use revm::{
    context::{
        result::{ExecutionResult, Output, ResultAndState},
        BlockEnv, CfgEnv, TxEnv,
    },
    database::{CacheDB, EmptyDB},
    primitives::{hardfork::SpecId, TxKind},
    state::{AccountInfo, Bytecode},
};

const CHAIN_ID: u64 = 1;
const ALICE: Address = Address::new([0x11; 20]);
const BOB: Address = Address::new([0x22; 20]);
const CAROL: Address = Address::new([0x33; 20]);
const DAVE: Address = Address::new([0x44; 20]);
/// Contract that forwards its calldata to a precompile through a chosen
/// opcode (`CALLCODE`, `DELEGATECALL`, or `STATICCALL`).
const BORROWER: Address = Address::new([0xaa; 20]);

fn test_env() -> EvmEnv {
    EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(CHAIN_ID)
            .with_spec_and_mainnet_gas_params(SpecId::PRAGUE),
        block_env: BlockEnv {
            gas_limit: 60_000_000,
            ..Default::default()
        },
    }
}

fn funded(balance: u64) -> AccountInfo {
    AccountInfo {
        balance: U256::from(balance),
        ..Default::default()
    }
}

fn base_db() -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(ALICE, funded(10_000));
    db.insert_account_info(BOB, funded(1_000));
    db.insert_account_info(CAROL, funded(0));
    db.insert_account_info(DAVE, funded(0));
    db
}

fn run(
    mut db: CacheDB<EmptyDB>,
    caller: Address,
    to: Address,
    value: u64,
    gas_limit: u64,
    calldata: Bytes,
) -> ResultAndState {
    use revm::Database;
    let nonce = db
        .basic(caller)
        .expect("caller account loads")
        .map(|info| info.nonce)
        .unwrap_or(0);
    let mut evm = OutbeEvmFactory::new().create_evm(db, test_env());
    let tx = TxEnv::builder()
        .caller(caller)
        .nonce(nonce)
        .kind(TxKind::Call(to))
        .value(U256::from(value))
        .gas_price(0)
        .data(calldata)
        .gas_limit(gas_limit)
        .build()
        .expect("tx builds");
    evm.transact_raw(tx).expect("transaction executes")
}

fn view(db: CacheDB<EmptyDB>, calldata: Bytes) -> Bytes {
    let outcome = run(db, ALICE, EMIT_ADDRESS, 0, 100_000, calldata);
    match outcome.result {
        ExecutionResult::Success {
            output: Output::Call(output),
            ..
        } => output,
        other => panic!("view call failed: {other:?}"),
    }
}

fn revert_reason(result: &ExecutionResult) -> Option<String> {
    let bytes = match result {
        ExecutionResult::Revert { output, .. } => output,
        ExecutionResult::Success {
            output: Output::Call(output),
            ..
        } => output,
        _ => return None,
    };
    alloy_sol_types::Revert::abi_decode(bytes)
        .ok()
        .map(|revert| revert.reason)
}

fn balance_of(outcome: &ResultAndState, address: Address) -> U256 {
    outcome
        .state
        .get(&address)
        .map(|account| account.info.balance)
        .unwrap_or_default()
}

fn storage_writes(outcome: &ResultAndState, address: Address) -> usize {
    outcome
        .state
        .get(&address)
        .map(|account| {
            account
                .storage
                .values()
                .filter(|slot| slot.present_value != slot.original_value)
                .count()
        })
        .unwrap_or(0)
}

fn emit_logs(result: &ExecutionResult) -> Vec<&LogData> {
    match result {
        ExecutionResult::Success { logs, .. } => logs
            .iter()
            .filter(|log| log.address == EMIT_ADDRESS)
            .map(|log| &log.data)
            .collect(),
        _ => Vec::new(),
    }
}

fn gas_used(result: &ExecutionResult) -> u64 {
    match result {
        ExecutionResult::Success { gas, .. }
        | ExecutionResult::Revert { gas, .. }
        | ExecutionResult::Halt { gas, .. } => gas.tx_gas_used(),
    }
}
/// Balance as committed in the chained database — unlike [`balance_of`],
/// not defaulted to zero for accounts a single transaction did not touch.
fn committed_balance(db: &CacheDB<EmptyDB>, address: Address) -> U256 {
    use revm::DatabaseRef;
    db.basic_ref(address)
        .expect("account loads")
        .map(|info| info.balance)
        .unwrap_or_default()
}
/// Committed storage slot of `EMIT_ADDRESS` by slot index.
fn committed_storage(db: &CacheDB<EmptyDB>, slot: u64) -> U256 {
    use revm::DatabaseRef;
    db.storage_ref(EMIT_ADDRESS, U256::from(slot))
        .expect("storage loads")
}

fn b256(field: Field) -> B256 {
    B256::new(field_to_be_bytes(field))
}

// ---- reference tree and proof fixture --------------------------------------

struct ReferenceTree {
    leaves: Vec<Field>,
    zeros: Vec<Field>,
}

impl ReferenceTree {
    fn new() -> Self {
        Self {
            leaves: Vec::new(),
            zeros: empty_subtrees(CHAIN_ID, EMIT_TREE_DEPTH),
        }
    }

    fn append(&mut self, leaf: Field) -> u32 {
        let index = self.leaves.len() as u32;
        self.leaves.push(leaf);
        index
    }

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

fn prove_mint(
    tree: &ReferenceTree,
    owner: Address,
    key: Field,
    note_amount: u128,
    leaf_index: u32,
    root_leaf_count: usize,
    mint_units: u128,
) -> Vec<u8> {
    let serial = derive_note_sn(owner.into(), key);
    let nullifier = derive_nullifier(
        note_commitment(CHAIN_ID, serial, U256::from(note_amount)),
        key,
    );
    let remaining = note_amount - mint_units;
    let change = if remaining > 0 {
        let next_key = change_key(key, nullifier);
        note_commitment(
            CHAIN_ID,
            derive_note_sn(owner.into(), next_key),
            U256::from(remaining),
        )
    } else {
        Field::from(0u64)
    };
    let public = PublicInputs {
        chain_id: CHAIN_ID,
        root: tree.root_at(root_leaf_count),
        nullifier,
        note_owner: address_field(owner.into()),
        mint_units: u256::to_limbs(U256::from(mint_units)),
        change_commitment: change,
    };
    let witness = Witness {
        note_amount: u256::to_limbs(U256::from(note_amount)),
        note_spend_key: key,
        leaf_index,
        auth_path: tree.path_at(leaf_index),
    };
    let backend = Barretenberg::default();
    let proof = ProofGenerator::<OutbeV1, EmitMint>::generate(&backend, &witness, &public)
        .expect("emit mint proof generation");
    let fields =
        <EmitMint as outbe_protocol::protocol::zk::Circuit<OutbeV1>>::public_inputs(&public);
    let mut combined = Vec::with_capacity(4 + 32 * (fields.len() + proof.proof.len()));
    combined.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for f in fields {
        combined.extend_from_slice(&field_to_be_bytes(f));
    }
    for word in &proof.proof {
        combined.extend_from_slice(word);
    }
    combined
}

fn burn_tx(sn: Field) -> Bytes {
    IEmit::burnCall { noteSn: b256(sn) }.abi_encode().into()
}

fn mint_tx(
    payout: Address,
    root: Field,
    nullifier: Field,
    owner: Address,
    units: u128,
    change: Field,
    proof: &[u8],
) -> Bytes {
    IEmit::mintCall {
        payoutRecipient: payout,
        root: b256(root),
        nullifier: b256(nullifier),
        noteOwner: owner,
        mintUnits: U256::from(units),
        changeCommitment: b256(change),
        proof: Bytes::copy_from_slice(proof),
    }
    .abi_encode()
    .into()
}

/// Bytecode that copies its calldata into memory and forwards it to `target`
/// through `opcode` (CALLCODE `0xf2` with the frame's value, DELEGATECALL
/// `0xf4`, or STATICCALL `0xfa`), then bubbles the inner returndata up.
fn borrow_code(opcode: u8, target: Address) -> Bytes {
    let mut code = vec![
        0x36, // CALLDATASIZE          size
        0x60, 0x00, // PUSH1 0         offset
        0x60, 0x00, // PUSH1 0         destOffset
        0x37, // CALLDATACOPY
        0x60, 0x00, // PUSH1 0         retLength
        0x60, 0x00, // PUSH1 0         retOffset
        0x36, // CALLDATASIZE          argsLength
        0x60, 0x00, // PUSH1 0         argsOffset
    ];
    if opcode == 0xf2 {
        code.push(0x34); // CALLVALUE   value
    }
    code.push(0x73); // PUSH20         address
    code.extend_from_slice(target.as_slice());
    code.push(0x5a); // GAS
    code.push(opcode);
    code.extend_from_slice(&[
        0x50, // POP                   drop the success flag
        0x3d, // RETURNDATASIZE        size
        0x60, 0x00, // PUSH1 0         offset
        0x60, 0x00, // PUSH1 0         destOffset
        0x3e, // RETURNDATACOPY
        0x3d, // RETURNDATASIZE        size
        0x60, 0x00, // PUSH1 0         offset
        0xf3, // RETURN                bubble the inner frame's returndata up
    ]);
    Bytes::from(code)
}

fn db_with_borrower(opcode: u8) -> CacheDB<EmptyDB> {
    db_with_borrower_on(opcode, base_db())
}

/// Installs the forwarding borrower on top of an already-chained state, so
/// borrowed-frame cases run against initialized Emit storage.
fn db_with_borrower_on(opcode: u8, mut db: CacheDB<EmptyDB>) -> CacheDB<EmptyDB> {
    let code = Bytecode::new_raw(borrow_code(opcode, EMIT_ADDRESS));
    db.insert_account_info(
        BORROWER,
        AccountInfo {
            balance: U256::from(1_000),
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    db
}

// ---- the plan scenario ------------------------------------------------------

#[test]
fn emit_burn_partial_mint_full_mint_and_replay() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let pool = CHAIN_ID;
    let serial = derive_note_sn(BOB.into(), Field::from(17u64));
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new();

    // Alice burns all 100 units into a Bob-owned note.
    let note_leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    let outcome = run(
        base_db(),
        ALICE,
        EMIT_ADDRESS,
        100,
        5_000_000,
        burn_tx(serial),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Success { .. }),
        "burn must succeed: {:?}",
        revert_reason(&outcome.result)
    );
    assert_eq!(
        balance_of(&outcome, ALICE),
        U256::from(10_000u64 - 100),
        "the boundary debits Alice for exactly the burned value (zero base fee)"
    );
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
    let logs = emit_logs(&outcome.result);
    assert_eq!(logs.len(), 1);
    let new_note = IEmit::NewNote::decode_log_data(logs[0]).unwrap();
    assert_eq!(
        new_note.commitment,
        b256(note_commitment(pool, serial, U256::from(100)))
    );
    assert_eq!(new_note.leafIndex, note_leaf);
    assert_eq!(new_note.noteAmount, 100);
    assert_eq!(new_note.rootAfter, b256(tree.root_at(1)));
    // Routed base gas is selector-sensitive: the burn charge sits between
    // the two pinned constants (a regression to a flat default would leave
    // this window).
    let burn_gas = gas_used(&outcome.result);
    assert!(
        burn_gas > 530_000 && burn_gas < 3_517_500,
        "routed burn gas {burn_gas} must reflect the 530k base"
    );

    // The EVM persists state between transactions only through the shared db:
    // re-run each step against the post-state of the previous one.
    let db = chained_db(base_db(), outcome);
    let root_after_burn = tree.root_at(1);

    // Bob's partial proof mints 40 to Carol; the change note is appended.
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let next_key = change_key(key, nullifier);
    let change = note_commitment(pool, derive_note_sn(BOB.into(), next_key), U256::from(60));
    let partial_proof = prove_mint(&tree, BOB, key, 100, note_leaf, 1, 40);
    let change_leaf = tree.append(change);
    let outcome = run(
        db.clone(),
        BOB,
        EMIT_ADDRESS,
        0,
        20_000_000,
        mint_tx(
            CAROL,
            root_after_burn,
            nullifier,
            BOB,
            40,
            change,
            &partial_proof,
        ),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Success { .. }),
        "partial mint must succeed: {:?}",
        revert_reason(&outcome.result)
    );
    assert_eq!(balance_of(&outcome, CAROL), U256::from(40u64));
    assert_eq!(balance_of(&outcome, BOB), U256::from(1_000u64));
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
    let logs = emit_logs(&outcome.result);
    assert_eq!(logs.len(), 2, "NoteUsed then NewNote(change)");
    let used = IEmit::NoteUsed::decode_log_data(logs[0]).unwrap();
    assert_eq!(used.noteOwner, BOB);
    assert_eq!(used.payoutRecipient, CAROL);
    assert_eq!(used.nullifier, b256(nullifier));
    assert_eq!(used.mintAmount, 40);
    let change_note = IEmit::NewNote::decode_log_data(logs[1]).unwrap();
    assert_eq!(change_note.commitment, b256(change));
    assert_eq!(change_note.leafIndex, change_leaf);
    assert_eq!(change_note.noteAmount, 0);
    assert_eq!(change_note.rootAfter, b256(tree.root_at(2)));
    // The mint selector's fixed base gas dominates the routed charge.
    assert!(gas_used(&outcome.result) >= 3_517_500);
    let db = chained_db(db, outcome);

    // Bob's successor proof mints the remaining 60 to Dave — NoteUsed only.
    let next_nullifier = derive_nullifier(change, next_key);
    let full_proof = prove_mint(&tree, BOB, next_key, 60, change_leaf, 2, 60);
    let outcome = run(
        db.clone(),
        BOB,
        EMIT_ADDRESS,
        0,
        20_000_000,
        mint_tx(
            DAVE,
            tree.root_at(2),
            next_nullifier,
            BOB,
            60,
            Field::from(0u64),
            &full_proof,
        ),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Success { .. }),
        "full mint must succeed: {:?}",
        revert_reason(&outcome.result)
    );
    assert_eq!(balance_of(&outcome, DAVE), U256::from(60u64));
    let logs = emit_logs(&outcome.result);
    assert_eq!(logs.len(), 1, "a full mint emits only NoteUsed");
    let used = IEmit::NoteUsed::decode_log_data(logs[0]).unwrap();
    assert_eq!(used.payoutRecipient, DAVE);
    assert_eq!(used.mintAmount, 60);
    assert_eq!(used.noteOwner, BOB);
    assert_eq!(used.nullifier, b256(next_nullifier));

    // Total known public supply is restored and committed: Carol 40 + Dave
    // 60 = 100 public again, Emit holds nothing, and a full mint neither
    // appends a leaf nor advances the root.
    let db = chained_db(db, outcome);
    assert_eq!(committed_balance(&db, CAROL), U256::from(40u64));
    assert_eq!(committed_balance(&db, DAVE), U256::from(60u64));
    assert_eq!(committed_balance(&db, BOB), U256::from(1_000u64));
    assert_eq!(committed_balance(&db, ALICE), U256::from(9_900u64));
    assert_eq!(
        committed_balance(&db, EMIT_ADDRESS),
        U256::ZERO,
        "Emit holds nothing after the full cycle"
    );
    assert_eq!(
        committed_storage(&db, 1),
        U256::from(2u64),
        "leaf count stays at burn + change; a full mint appends nothing"
    );
    assert_eq!(
        B256::from(committed_storage(&db, 0)),
        b256(tree.root_at(2)),
        "a full mint does not advance the root"
    );

    let output = view(db.clone(), IEmit::currentRootCall {}.abi_encode().into());
    assert_eq!(
        IEmit::currentRootCall::abi_decode_returns(&output).unwrap(),
        b256(tree.root_at(2))
    );
    let output = view(db.clone(), IEmit::leafCountCall {}.abi_encode().into());
    assert_eq!(
        IEmit::leafCountCall::abi_decode_returns(&output).unwrap(),
        2
    );
    let output = view(
        db.clone(),
        IEmit::isSpentCall {
            nullifier: b256(nullifier),
        }
        .abi_encode()
        .into(),
    );
    assert!(IEmit::isSpentCall::abi_decode_returns(&output).unwrap());
    let output = view(
        db.clone(),
        IEmit::hasCommitmentCall {
            commitment: b256(change),
        }
        .abi_encode()
        .into(),
    );
    assert!(IEmit::hasCommitmentCall::abi_decode_returns(&output).unwrap());

    // Replay the first partial mint on a fresh chain state: failed receipt,
    // and — asserted against the chained database, not the replay
    // transaction's own state set — the committed payout, tree, and root of
    // the first mint are untouched.
    let mut db = base_db();
    let burned = run(
        db.clone(),
        ALICE,
        EMIT_ADDRESS,
        100,
        5_000_000,
        burn_tx(serial),
    );
    assert!(matches!(burned.result, ExecutionResult::Success { .. }));
    db = chained_db(db, burned);
    let first = run(
        db.clone(),
        BOB,
        EMIT_ADDRESS,
        0,
        20_000_000,
        mint_tx(
            CAROL,
            root_after_burn,
            nullifier,
            BOB,
            40,
            change,
            &partial_proof,
        ),
    );
    assert!(
        matches!(first.result, ExecutionResult::Success { .. }),
        "the first partial mint must succeed: {:?}",
        revert_reason(&first.result)
    );
    db = chained_db(db, first);
    assert_eq!(
        committed_balance(&db, CAROL),
        U256::from(40u64),
        "the first mint's payout is committed before the replay"
    );
    let replayed = run(
        db.clone(),
        BOB,
        EMIT_ADDRESS,
        0,
        20_000_000,
        mint_tx(
            CAROL,
            root_after_burn,
            nullifier,
            BOB,
            40,
            change,
            &partial_proof,
        ),
    );
    assert!(matches!(replayed.result, ExecutionResult::Revert { .. }));
    assert_eq!(
        revert_reason(&replayed.result).as_deref(),
        Some("Emit nullifier has already been spent")
    );
    assert!(emit_logs(&replayed.result).is_empty());
    assert_eq!(
        committed_balance(&db, CAROL),
        U256::from(40u64),
        "the replay must not reset the committed payout"
    );
    assert_eq!(committed_balance(&db, BOB), U256::from(1_000u64));
    assert_eq!(committed_balance(&db, EMIT_ADDRESS), U256::ZERO);
    assert_eq!(
        committed_storage(&db, 1),
        U256::from(2u64),
        "the replay appends no leaf"
    );
    assert_eq!(
        B256::from(committed_storage(&db, 0)),
        b256(tree.root_at(2)),
        "the replay does not advance the root"
    );
}

/// Overlays a `ResultAndState` onto the running `CacheDB` so the scenario
/// chains real post-state without dropping untouched accounts.
fn chained_db(mut db: CacheDB<EmptyDB>, outcome: ResultAndState) -> CacheDB<EmptyDB> {
    for (address, account) in outcome.state {
        db.insert_account_info(address, account.info);
        for (key, slot) in account.storage {
            db.insert_account_storage(address, key, slot.present_value)
                .expect("storage inserts");
        }
    }
    db
}

#[test]
fn root_evicted_by_32_later_appends_is_stale() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let pool = CHAIN_ID;
    let serial = derive_note_sn(BOB.into(), Field::from(17u64));
    let key = Field::from(17u64);
    let mut tree = ReferenceTree::new();

    let note_leaf = tree.append(note_commitment(pool, serial, U256::from(100)));
    let mut db = base_db();
    let outcome = run(
        db.clone(),
        ALICE,
        EMIT_ADDRESS,
        100,
        5_000_000,
        burn_tx(serial),
    );
    assert!(matches!(outcome.result, ExecutionResult::Success { .. }));
    db = chained_db(db, outcome);
    let old_root = tree.root_at(1);
    let proof = prove_mint(&tree, BOB, key, 100, note_leaf, 1, 40);
    let nullifier = derive_nullifier(note_commitment(pool, serial, U256::from(100)), key);
    let change = note_commitment(
        pool,
        derive_note_sn(BOB.into(), change_key(key, nullifier)),
        U256::from(60),
    );

    // 32 further burns advance the root window past the burn root.
    for index in 0..32u64 {
        let sn = Field::from(1_000u64 + index);
        tree.append(note_commitment(pool, sn, U256::from(1)));
        let outcome = run(db.clone(), ALICE, EMIT_ADDRESS, 1, 5_000_000, burn_tx(sn));
        assert!(matches!(outcome.result, ExecutionResult::Success { .. }));
        db = chained_db(db, outcome);
    }

    let outcome = run(
        db,
        BOB,
        EMIT_ADDRESS,
        0,
        20_000_000,
        mint_tx(CAROL, old_root, nullifier, BOB, 40, change, &proof),
    );
    assert!(matches!(outcome.result, ExecutionResult::Revert { .. }));
    assert_eq!(
        revert_reason(&outcome.result).as_deref(),
        Some("Emit root is not recent")
    );
    assert_eq!(balance_of(&outcome, CAROL), U256::from(0u64));
}

// ---- frame and value boundaries ---------------------------------------------

#[test]
fn value_on_mint_and_borrowed_frames_cannot_reach_emit_state() {
    outbe_zk_backend::barretenberg::init_crs().expect("CRS init");
    let pool = CHAIN_ID;
    let serial = derive_note_sn(BOB.into(), Field::from(17u64));
    let mut tree = ReferenceTree::new();
    tree.append(note_commitment(pool, serial, U256::from(100)));

    // Value on the mint selector: refused before dispatch touches state.
    let proof = prove_mint(&tree, BOB, Field::from(17u64), 100, 0, 1, 40);
    let nullifier = derive_nullifier(
        note_commitment(pool, serial, U256::from(100)),
        Field::from(17u64),
    );
    let change = note_commitment(
        pool,
        derive_note_sn(BOB.into(), change_key(Field::from(17u64), nullifier)),
        U256::from(60),
    );
    let calldata = mint_tx(CAROL, tree.root_at(1), nullifier, BOB, 40, change, &proof);
    let outcome = run(base_db(), BOB, EMIT_ADDRESS, 7, 20_000_000, calldata);
    assert!(matches!(outcome.result, ExecutionResult::Revert { .. }));
    assert_eq!(
        revert_reason(&outcome.result).as_deref(),
        Some("non-payable function called with value")
    );
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
    assert_eq!(balance_of(&outcome, BOB), U256::from(1_000u64));
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);

    // CALLCODE and DELEGATECALL frames are refused outright.
    for opcode in [0xf2u8, 0xf4] {
        let outcome = run(
            db_with_borrower(opcode),
            ALICE,
            BORROWER,
            100,
            5_000_000,
            burn_tx(serial),
        );
        assert_eq!(
            revert_reason(&outcome.result).as_deref(),
            Some("outbe precompile: delegated call frame cannot execute a precompile"),
            "opcode {opcode:#x} must be rejected at the frame boundary"
        );
        assert_eq!(
            storage_writes(&outcome, EMIT_ADDRESS),
            0,
            "opcode {opcode:#x}"
        );
        assert_eq!(
            balance_of(&outcome, EMIT_ADDRESS),
            U256::ZERO,
            "opcode {opcode:#x}"
        );
    }

    // A STATICCALL frame carries no value, so `burn` refuses at its very
    // first guard — a static frame can never move native value into the pool
    // and never reaches a write. The borrower bubbles the inner revert up.
    let outcome = run(
        db_with_borrower(0xfa),
        ALICE,
        BORROWER,
        0,
        5_000_000,
        burn_tx(serial),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Success { .. }),
        "the borrower returns the inner revert bytes: {:?}",
        outcome.result
    );
    assert_eq!(
        revert_reason(&outcome.result).as_deref(),
        Some("Emit burn value must be non-zero")
    );
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);

    // A *mutating* mint under STATICCALL: the note is owned by the borrower
    // so every guard passes and execution reaches the checkpoint's first
    // write, which must halt the static frame. No balances, tree state, or
    // logs may move — this is the write-protection path the zero-value burn
    // case above never reaches.
    {
        let key = Field::from(17u64);
        let owner_serial = derive_note_sn(BORROWER.into(), key);
        let mut owner_tree = ReferenceTree::new();
        let leaf = owner_tree.append(note_commitment(pool, owner_serial, U256::from(100)));
        let mut db = base_db();
        let burned = run(
            db.clone(),
            ALICE,
            EMIT_ADDRESS,
            100,
            5_000_000,
            burn_tx(owner_serial),
        );
        assert!(matches!(burned.result, ExecutionResult::Success { .. }));
        db = chained_db(db, burned);
        let owner_nullifier =
            derive_nullifier(note_commitment(pool, owner_serial, U256::from(100)), key);
        let owner_change = note_commitment(
            pool,
            derive_note_sn(BORROWER.into(), change_key(key, owner_nullifier)),
            U256::from(60),
        );
        let proof = prove_mint(&owner_tree, BORROWER, key, 100, leaf, 1, 40);
        let calldata = mint_tx(
            CAROL,
            owner_tree.root_at(1),
            owner_nullifier,
            BORROWER,
            40,
            owner_change,
            &proof,
        );
        let db = db_with_borrower_on(0xfa, db);
        let outcome = run(db.clone(), ALICE, BORROWER, 0, 20_000_000, calldata);
        assert!(
            matches!(outcome.result, ExecutionResult::Success { .. }),
            "the borrower swallows the inner halt: {:?}",
            outcome.result
        );
        assert_eq!(revert_reason(&outcome.result), None);
        assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);
        assert!(emit_logs(&outcome.result).is_empty());
        assert_eq!(
            committed_balance(&db, CAROL),
            U256::ZERO,
            "a static frame cannot mint"
        );
        assert_eq!(committed_balance(&db, EMIT_ADDRESS), U256::ZERO);
        assert_eq!(
            committed_storage(&db, 1),
            U256::from(1u64),
            "only the burn's leaf exists; the static mint wrote nothing"
        );
    }

    // Sanity: an ordinary funded CALL on the payable burn selector succeeds
    // through the same borrower path (opcode CALL via a direct transaction).
    let outcome = run(
        base_db(),
        ALICE,
        EMIT_ADDRESS,
        100,
        5_000_000,
        burn_tx(serial),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Success { .. }),
        "ordinary funded burn must succeed"
    );
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
}

#[test]
fn funded_malformed_calldata_fails_without_stranding_value() {
    use alloy_primitives::hex;

    // Funded unknown selector: the route's `u64::MAX` base gas halts the
    // call out-of-gas before dispatch — the frame never runs, so the value
    // never leaves the caller.
    let outcome = run(
        base_db(),
        ALICE,
        EMIT_ADDRESS,
        5,
        1_000_000,
        Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Halt { .. }),
        "unknown selector must halt out-of-gas, got {:?}",
        outcome.result
    );
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);

    // Funded empty calldata: same halt — no selector is published, so the
    // base gas is `u64::MAX` and the call dies before the value gate.
    let outcome = run(base_db(), ALICE, EMIT_ADDRESS, 5, 1_000_000, Bytes::new());
    assert!(
        matches!(outcome.result, ExecutionResult::Halt { .. }),
        "empty calldata must halt out-of-gas, got {:?}",
        outcome.result
    );
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);

    // Funded selector-only burn: the selector is payable so the value gate
    // passes and the credited amount rides on the ABI decode failure — the
    // reverting transaction must refund it in full.
    let outcome = run(
        base_db(),
        ALICE,
        EMIT_ADDRESS,
        5,
        1_000_000,
        Bytes::from(IEmit::burnCall::SELECTOR.to_vec()),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Revert { .. }),
        "selector-only burn must fail ABI decoding: {:?}",
        outcome.result
    );
    assert_eq!(balance_of(&outcome, ALICE), U256::from(10_000u64));
    assert_eq!(balance_of(&outcome, EMIT_ADDRESS), U256::ZERO);
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);

    // Zero-value selector-only mint: the route charges the mint base gas
    // before dispatch fails ABI decoding — pinning that the 3,517,500
    // selector-sensitive charge is actually routed.
    let outcome = run(
        base_db(),
        BOB,
        EMIT_ADDRESS,
        0,
        20_000_000,
        Bytes::from(IEmit::mintCall::SELECTOR.to_vec()),
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Revert { .. }),
        "selector-only mint must fail ABI decoding: {:?}",
        outcome.result
    );
    assert!(
        gas_used(&outcome.result) >= 3_517_500,
        "mint selector must route the 3,517,500 base gas, got {}",
        gas_used(&outcome.result)
    );
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);

    // Below-base gas limits halt out-of-gas before dispatch with no state
    // change: mint at base + 30k cannot cover the fixed charge plus the
    // calldata, and burn at base + 5k cannot cover its charge either.
    let mint_head = mint_tx(
        CAROL,
        Field::from(0u64),
        Field::from(0u64),
        BOB,
        1,
        Field::from(0u64),
        hex!("00000000").as_ref(),
    );
    let oog_db = base_db();
    let outcome = run(
        oog_db.clone(),
        BOB,
        EMIT_ADDRESS,
        0,
        3_517_500 + 30_000,
        mint_head,
    );
    assert!(
        !matches!(outcome.result, ExecutionResult::Success { .. }),
        "mint below base+intrinsic gas must not succeed: {:?}",
        outcome.result
    );
    assert_eq!(storage_writes(&outcome, EMIT_ADDRESS), 0);
    assert_eq!(committed_balance(&oog_db, CAROL), U256::ZERO);

    let outcome = run(
        base_db(),
        ALICE,
        EMIT_ADDRESS,
        1,
        530_000 + 5_000,
        burn_tx(Field::from(1u64)),
    );
    assert!(
        !matches!(outcome.result, ExecutionResult::Success { .. }),
        "burn below base+intrinsic gas must not succeed"
    );
    assert!(
        matches!(outcome.result, ExecutionResult::Halt { .. }),
        "expected an out-of-gas halt, got {:?}",
        outcome.result
    );
}

#[test]
fn emit_runtime_marker_is_preserved_and_tree_capacity_is_bounded() {
    // The executor-side marker coverage is pinned by
    // `every_stateful_precompile_preserved_by_marker_or_genesis` in
    // `genesis.rs`; this test pins the module-level facts Emit depends on.
    use outbe_evm::executor::marker_addresses::OUTBE_RUNTIME_MARKER_ADDRESSES;
    assert!(OUTBE_RUNTIME_MARKER_ADDRESSES.contains(&EMIT_ADDRESS));
    assert_eq!(EMIT_TREE_CAPACITY, (1u64 << EMIT_TREE_DEPTH) - 1);
    assert_eq!(EMIT_TREE_DEPTH, 32);
}
