//! End-to-end: one deposited PayNote pays two Nods, the second from its change.
//!
//! A Nod's cost is no longer settled by a transfer - the value reaches the
//! reserve vault when a note is deposited, and `mineGratis` only has to be shown
//! a spend proof. This test drives that whole chain through the real EVM:
//! `IPayNote.deposit` routes an ERC20 into the vault via VaultRouter and appends
//! a leaf, then two `INodFactory.mineGratis` calls spend against that leaf.
//!
//! What it pins that the module tests cannot:
//!   * a note deposited by the real `deposit` path - commitment derived by the
//!     runtime, not handed to it - is spendable by `mineGratis`;
//!   * notes are bearer instruments: `ALICE2` pays for the deposit and `ALICE1`
//!     spends it. Spend authority is knowledge of the note spend key, and
//!     nothing on chain ties the depositor to the Nods the note pays for;
//!   * a partial spend leaves change *in the pool*, and that change note is a
//!     first-class note: it pays the next Nod on its own;
//!   * one note is one payment. Replaying the first proof against the second Nod
//!     reverts, so the change note is the only way to pay it.
//!
//! Only the two ERC20/ERC4626 counterparties are stubbed; VaultRouter, PayNote,
//! NodFactory, Nod, GratisFactory and Gratis all run for real.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use outbe_compressed_entities::{begin_block, ExecutionScope, WwdEntityId};
use outbe_evm::sub_call;
use outbe_gratis::enclave_client::test_enclave;
use outbe_gratis::precompile::IGratis;
use outbe_nod::{NodContract, NodIssueParams, NodRepositoryReader};
use outbe_nodfactory::precompile::INodFactory;
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_offchain_storage::MemoryStorage;
use outbe_paynote::hash::field_to_be_bytes;
use outbe_paynote::precompile::IPayNote;
use outbe_paynote::test_support::{change_note, note, spend_proof, Note, ReferenceTree};
use outbe_primitives::addresses::{
    COMPRESSED_ENTITIES_ADDRESS, GRATIS_ADDRESS, NOD_FACTORY_ADDRESS, PAYNOTE_ADDRESS,
};
use outbe_primitives::chain::CHAIN_ID;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    block::BlockContext,
    storage::{direct::DirectStorageProvider, StorageHandle, SubCallInput, SubCallStatus},
};
use outbe_tee::protocol::GratisOp;
use outbe_tee_enclave::gratis::{derive_modify_key, modify_mac};
use outbe_vaultrouter::VaultRouterContract;
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context,
};

/// Owns both Nods, holds the note spend key, and calls `mineGratis`.
const ALICE1: Address = Address::new([0x11; 20]);
/// Funds the pool. Never appears again: the note it deposits is spent by
/// `ALICE1`, and the chain never learns the two are related.
const ALICE2: Address = Address::new([0x12; 20]);
const ASSET: Address = Address::new([0x33; 20]);
const VAULT: Address = Address::new([0x55; 20]);

/// `StablesSource::PayNoteDeposit` - the discriminant `seed_genesis.py`
/// registers for `PAYNOTE_ADDRESS`.
const PAYNOTE_DEPOSIT_SOURCE: u8 = 4;

const REFERENCE_CURRENCY: u16 = 840;
const NOTE_KEY: u64 = 17;
/// Each Nod costs this; the single deposited note is worth exactly two of them,
/// so the first spend is partial and its change covers the second Nod exactly.
const COST: u128 = 500;
const GRATIS_LOAD: u128 = 1_000;
const BLOCK_TIMESTAMP: u64 = 1_700_000_000;

/// One Nod per owner per day, so two Nods for one owner means two days. They
/// have to share an owner: the note names its spender, and `mineGratis` demands
/// the spender be the Nod's owner. That spender is `ALICE1`, not the depositor.
const DAYS: [u32; 2] = [20_241_220, 20_241_221];

type EvmCtx = revm::Context<
    revm::context::BlockEnv,
    revm::context::TxEnv,
    revm::context::CfgEnv,
    CacheDB<EmptyDB>,
>;

/// A counterparty stub that answers every call with one fixed word.
///
/// `PUSH32 <word>, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN`
///
/// One word is enough for both counterparties: the ERC20 returns `1`, read as
/// `true` by `transferFrom` and `approve`; the vault returns its own asset
/// address, which `asset()` needs verbatim and `deposit()` reads as a share
/// count nothing in this flow inspects.
fn always_returns(word: B256) -> AccountInfo {
    let mut code = vec![0x7f];
    code.extend_from_slice(word.as_slice());
    code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);
    let bytecode = Bytecode::new_raw(Bytes::from(code));
    AccountInfo {
        code_hash: bytecode.hash_slow(),
        code: Some(bytecode),
        ..Default::default()
    }
}

fn nod_params(day: u32) -> NodIssueParams {
    NodIssueParams {
        owner: ALICE1,
        gratis_load_minor: U256::from(GRATIS_LOAD),
        worldwide_day: WorldwideDay::new(day),
        league_id: 1,
        floor_price_minor: U256::from(540),
        // The cost is derived, never stored: entry_price x gratis_load / 1e6.
        entry_price_minor: U256::from(COST * 1_000_000 / GRATIS_LOAD),
        issuance_currency: REFERENCE_CURRENCY,
        reference_currency: REFERENCE_CURRENCY,
    }
}

/// Registers the vault as production genesis would, minus `addVault`'s own
/// ERC20 metadata round-trip: the reserve vault for `ASSET`, its reference
/// currency index, and PayNote as a `PayNoteDeposit` liquidity source.
fn seed_vault_router(storage: &StorageHandle<'_>) {
    let router = VaultRouterContract::new(storage.clone());
    router.assets.insert(ASSET).unwrap();
    router.asset_vault_set(ASSET).insert(VAULT).unwrap();
    router
        .reference_currency_vault_set(REFERENCE_CURRENCY)
        .insert(VAULT)
        .unwrap();
    router
        .vault_reference_currencies
        .write(&VAULT, REFERENCE_CURRENCY)
        .unwrap();
    router.liquidity_sources.insert(PAYNOTE_ADDRESS).unwrap();
    router
        .liquidity_source_types
        .write(&PAYNOTE_ADDRESS, PAYNOTE_DEPOSIT_SOURCE)
        .unwrap();
}

fn seed_compressed_entities_genesis(storage: &StorageHandle<'_>) {
    storage
        .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4_u64))
        .unwrap();
    storage
        .sstore(
            COMPRESSED_ENTITIES_ADDRESS,
            U256::from(1_u64),
            U256::from_be_slice(
                outbe_compressed_entities::sealed_root(B256::ZERO)
                    .unwrap()
                    .as_slice(),
            ),
        )
        .unwrap();
}

/// A chain with the vault registry seeded and two qualified, costed Nods
/// already issued to `ALICE1` - everything the scenario needs before the first
/// note exists.
fn fixture() -> (
    EvmCtx,
    Arc<ExecutionScope>,
    RuntimeBodyReaders,
    [WwdEntityId; 2],
) {
    test_enclave::install();

    let mut database = CacheDB::new(EmptyDB::default());
    database.insert_account_info(ASSET, always_returns(B256::from(U256::from(1))));
    database.insert_account_info(VAULT, always_returns(ASSET.into_word()));

    let adapter = Arc::new(MemoryStorage::new());
    let readers = RuntimeBodyReaders::new(adapter.clone());
    let parent = NodRepositoryReader::new(adapter);
    let scope = Arc::new(ExecutionScope::new());

    let block = BlockContext::new(1, BLOCK_TIMESTAMP, CHAIN_ID, ALICE1, vec![ALICE1]);
    let mut provider = DirectStorageProvider::new(&mut database, block);
    let nods = StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), scope.as_ref()).unwrap();
        seed_vault_router(&storage);
        DAYS.map(|day| {
            let params = nod_params(day);
            let nod_id =
                outbe_nodfactory::api::issue_nod(&storage, &scope, &parent, &params).unwrap();
            let bucket_key = NodContract::bucket_key(
                params.worldwide_day,
                params.floor_price_minor,
                params.reference_currency,
            );
            NodContract::new(storage.clone())
                .qualify_bucket(&scope, &parent, bucket_key)
                .unwrap();
            nod_id
        })
    });
    provider.flush().unwrap();

    let ctx = Context::mainnet()
        .with_db(database)
        .modify_cfg_chained(|cfg| cfg.chain_id = CHAIN_ID);
    (ctx, scope, readers, nods)
}

fn call(
    ctx: &mut EvmCtx,
    scope: Arc<ExecutionScope>,
    readers: Option<RuntimeBodyReaders>,
    caller: Address,
    target: Address,
    calldata: Bytes,
    is_static: bool,
) -> outbe_primitives::storage::SubCallOutput {
    sub_call::run(
        ctx,
        caller,
        false,
        SpecId::PRAGUE,
        readers,
        scope,
        SubCallInput {
            target,
            value: U256::ZERO,
            calldata,
            // `mineGratis` charges `ZK_VERIFY_GAS` (3M) before it reads a byte
            // of storage, so the limit has to clear that with room to spare.
            gas_limit: 20_000_000,
            is_static,
        },
    )
    .expect("sub-call must not fail fatally")
}

fn view<C: SolCall>(
    ctx: &mut EvmCtx,
    scope: &Arc<ExecutionScope>,
    target: Address,
    c: C,
) -> C::Return {
    let out = call(
        ctx,
        scope.clone(),
        None,
        ALICE1,
        target,
        Bytes::from(c.abi_encode()),
        true,
    );
    assert!(
        matches!(out.status, SubCallStatus::Success),
        "view call reverted: {:?}",
        out.status
    );
    C::abi_decode_returns(&out.returndata).expect("canonical view returndata")
}

fn leaf_count(ctx: &mut EvmCtx, scope: &Arc<ExecutionScope>) -> u64 {
    view(ctx, scope, PAYNOTE_ADDRESS, IPayNote::leafCountCall {})
}

fn is_spent(ctx: &mut EvmCtx, scope: &Arc<ExecutionScope>, nullifier: B256) -> bool {
    view(
        ctx,
        scope,
        PAYNOTE_ADDRESS,
        IPayNote::isSpentCall { nullifier },
    )
}

fn word(field: outbe_paynote::hash::Field) -> B256 {
    B256::new(field_to_be_bytes(field))
}

/// Calls `mineGratis` for `nod_id`, authorizing the gratis mint against the
/// account's live op-nonce.
fn mine_gratis(
    ctx: &mut EvmCtx,
    scope: &Arc<ExecutionScope>,
    readers: &RuntimeBodyReaders,
    nod_id: WwdEntityId,
    proof: &[u8],
) -> outbe_primitives::storage::SubCallOutput {
    let op_nonce = view(
        ctx,
        scope,
        GRATIS_ADDRESS,
        IGratis::opNonceOfCall { account: ALICE1 },
    );
    let modify_key = derive_modify_key(&test_enclave::state_key(), ALICE1).unwrap();
    let mac = modify_mac(
        &modify_key,
        ALICE1,
        GratisOp::Mint,
        U256::from(GRATIS_LOAD),
        op_nonce,
        B256::from(U256::from(CHAIN_ID)),
    );
    let nonce = (0_u64..1_000_000)
        .find(|candidate| outbe_nodfactory::runtime::validate_pow(nod_id, *candidate).is_ok())
        .expect("every nod id has a PoW nonce in the bounded search");
    call(
        ctx,
        scope.clone(),
        Some(readers.clone()),
        ALICE1,
        NOD_FACTORY_ADDRESS,
        Bytes::from(
            INodFactory::mineGratisCall {
                nodId: nod_id.to_u256(),
                nonce,
                mac: B256::from(mac),
                opNonce: op_nonce,
                payNoteProof: proof.to_vec().into(),
            }
            .abi_encode(),
        ),
        false,
    )
}

fn assert_mined(out: &outbe_primitives::storage::SubCallOutput, what: &str) -> U256 {
    assert!(
        matches!(out.status, SubCallStatus::Success),
        "{what} reverted: {:?} returndata 0x{}",
        out.status,
        alloy_primitives::hex::encode(&out.returndata),
    );
    INodFactory::mineGratisCall::abi_decode_returns(&out.returndata).expect("minted amount")
}

/// Deposits `note` into the pool through the real `deposit` path, paid for by
/// `depositor` - who need not be the account that will later spend it.
fn deposit(ctx: &mut EvmCtx, scope: &Arc<ExecutionScope>, depositor: Address, note: &Note) {
    let out = call(
        ctx,
        scope.clone(),
        None,
        depositor,
        PAYNOTE_ADDRESS,
        Bytes::from(
            IPayNote::depositCall {
                asset: note.asset,
                amount: note.amount,
                noteSn: word(note.serial),
            }
            .abi_encode(),
        ),
        false,
    );
    assert!(
        matches!(out.status, SubCallStatus::Success),
        "deposit reverted: {:?} returndata 0x{}",
        out.status,
        alloy_primitives::hex::encode(&out.returndata),
    );
}

#[test]
fn one_deposited_note_pays_two_nods_through_its_change() {
    let (mut ctx, scope, readers, nods) = fixture();

    // One deposit funds both Nods, and ALICE2 pays for it. The pool derives the
    // leaf itself from the asset and amount it moved, so the note ALICE1 proves
    // against is only valid because it matches what ALICE2's deposit did.
    let funding = note(CHAIN_ID, NOTE_KEY, ASSET, U256::from(2 * COST));
    deposit(&mut ctx, &scope, ALICE2, &funding);
    assert_eq!(leaf_count(&mut ctx, &scope), 1);

    let mut tree = ReferenceTree::new(CHAIN_ID);
    let leaf = tree.append(funding.commitment);

    // First Nod: spend half the note.
    let first_proof = spend_proof(CHAIN_ID, &tree, leaf, &funding, ALICE1, U256::from(COST));
    let minted = assert_mined(
        &mine_gratis(&mut ctx, &scope, &readers, nods[0], &first_proof),
        "mine the first Nod with the deposited note",
    );
    assert_eq!(minted, U256::from(GRATIS_LOAD));
    assert!(
        is_spent(&mut ctx, &scope, word(funding.nullifier)),
        "paying a Nod must burn the note it was paid with"
    );

    // The unspent half came back as a change leaf, derivable by the spender
    // alone from the key and nullifier they already hold.
    let change =
        change_note(CHAIN_ID, &funding, U256::from(COST)).expect("a half-spent note leaves change");
    assert_eq!(
        leaf_count(&mut ctx, &scope),
        2,
        "the change note must be appended to the pool"
    );
    assert!(
        view(
            &mut ctx,
            &scope,
            PAYNOTE_ADDRESS,
            IPayNote::hasCommitmentCall {
                commitment: word(change.commitment)
            }
        ),
        "the appended leaf must be the change commitment the spender can derive"
    );
    let change_leaf = tree.append(change.commitment);

    // One note is one payment: the first proof cannot pay the second Nod.
    let replay = mine_gratis(&mut ctx, &scope, &readers, nods[1], &first_proof);
    let SubCallStatus::Revert(reason) = replay.status else {
        panic!(
            "a spent note must not pay a second Nod, got {:?}",
            replay.status
        );
    };
    assert!(
        String::from_utf8_lossy(&reason).contains("nullifier has already been spent"),
        "the replay must be refused for the nullifier, not incidentally: 0x{}",
        alloy_primitives::hex::encode(&reason),
    );

    // Second Nod: paid entirely by the change note.
    let change_proof = spend_proof(
        CHAIN_ID,
        &tree,
        change_leaf,
        &change,
        ALICE1,
        U256::from(COST),
    );
    let minted = assert_mined(
        &mine_gratis(&mut ctx, &scope, &readers, nods[1], &change_proof),
        "mine the second Nod with the change note",
    );
    assert_eq!(minted, U256::from(GRATIS_LOAD));
    assert!(
        is_spent(&mut ctx, &scope, word(change.nullifier)),
        "the change note must be burnt once it has paid"
    );
    assert_eq!(
        leaf_count(&mut ctx, &scope),
        2,
        "a full spend leaves no change, so the pool must not grow"
    );
}
