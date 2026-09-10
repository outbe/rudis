//! PayNote transition core — the state machine shared by dispatch, the
//! cross-module API, and tests.
//!
//! Every mutating path runs under [`StorageHandle::with_checkpoint`], making
//! tree, replay, token, and event effects one rollback unit. All guards precede
//! mutation. Guard failures convert from [`PayNoteError`] (which fixes the
//! revert texts and the fatal/revert split) via `From`.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use ark_ff::Zero;
use outbe_primitives::addresses::{PAYNOTE_ADDRESS, VAULT_ROUTER_ADDRESS};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;
use outbe_zk_backend::barretenberg::verify_circuit;
use outbe_zk_canonical::noir::paynote::Paynote;
use outbe_zk_canonical::paynote::{
    decode_public_inputs as decode_paynote_public_inputs, PublicInputs as PayNotePublicInputs,
};

use crate::errors::PayNoteError;
use crate::hash::{
    empty_subtrees, field_from_be_bytes, field_to_be_bytes, merkle_node, note_commitment, Field,
};
use crate::precompile::IPayNote;
use crate::schema::{
    PayNoteContract, PAYNOTE_ROOT_WINDOW, PAYNOTE_TREE_CAPACITY, PAYNOTE_TREE_DEPTH,
};
use crate::sol_ext::IERC20;

/// The validated public claim a spend proof carries, returned to the consuming
/// module. PayNote books the nullifier and any change note; deciding what the
/// released value buys is the caller's job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayNoteClaim {
    pub asset: Address,
    pub spender: Address,
    pub spend_amount: U256,
    /// The canonical nullifier this spend booked. It is the only public
    /// identifier of the payment, so a consuming module can record which note
    /// paid it without learning anything that links back to the depositor.
    pub nullifier: B256,
}

/// Reads the live chain ID and derives its full in-memory empty ladder.
fn chain_state(storage: &StorageHandle<'_>) -> Result<(u64, Vec<Field>)> {
    let chain_id = storage.chain_id()?;
    let zeros = empty_subtrees(chain_id, PAYNOTE_TREE_DEPTH)?;
    Ok((chain_id, zeros))
}

/// Appends `leaf` in O(depth) stored state using the Tornado Cash pattern: for
/// each level, the corresponding `leaf_count` bit decides whether the current
/// node completes a left subtree (store it in `filled_subtrees` and combine
/// with the empty subtree) or joins the stored left subtree (combine as the
/// right node). Finishes with one root/count/root-buffer update and returns
/// `(leaf_index, root_after)`.
///
/// `index` is bounded by [`PAYNOTE_TREE_CAPACITY`] at every call site, so the
/// `u32` narrowing for the returned leaf index cannot truncate.
pub(crate) fn append(
    paynote: &PayNoteContract<'_>,
    zeros: &[Field],
    leaf: Field,
) -> Result<(u32, Field)> {
    let index = paynote.leaf_count.read()?;
    let mut current = leaf;
    for (level, zero) in zeros.iter().enumerate().take(PAYNOTE_TREE_DEPTH) {
        let level_byte = u8::try_from(level).map_err(|_| PayNoteError::CorruptFrontier)?;
        if (index >> level) & 1 == 0 {
            paynote
                .filled_subtrees
                .write(&level_byte, B256::new(field_to_be_bytes(current)))?;
            current = merkle_node(current, *zero)?;
        } else {
            let left = paynote.filled_subtrees.read(&level_byte)?;
            let left = field_from_be_bytes(&left.0).ok_or(PayNoteError::CorruptFrontier)?;
            current = merkle_node(left, current)?;
        }
    }
    let root_after = B256::new(field_to_be_bytes(current));
    paynote.current_root.write(root_after)?;
    paynote.leaf_count.write(index + 1)?;
    paynote.recent_roots.push(root_after)?;
    let leaf_index = u32::try_from(index).map_err(|_| PayNoteError::TreeFull)?;
    Ok((leaf_index, current))
}

/// `deposit(asset, amount, noteSn)` — pull the ERC20, route it into the
/// asset's reserve vault, and append the derived note commitment.
pub(crate) fn deposit(
    storage: StorageHandle<'_>,
    caller: Address,
    asset: Address,
    amount: U256,
    note_sn: B256,
) -> Result<()> {
    // Guards, before any mutation.
    if amount.is_zero() {
        return Err(PayNoteError::InvalidInput("deposit amount must be non-zero".into()).into());
    }
    // `asset != 0` is enforced here such as we do not accept native currency here.
    if asset.is_zero() {
        return Err(PayNoteError::InvalidInput("asset must be non-zero".into()).into());
    }
    let serial = field_from_be_bytes(&note_sn.0).ok_or(PayNoteError::InvalidInput(
        "noteSn is not a canonical BN254 field".into(),
    ))?;
    if serial.is_zero() {
        return Err(PayNoteError::InvalidInput("noteSn must be non-zero".into()).into());
    }

    let (chain_id, zeros) = chain_state(&storage)?;
    let paynote: PayNoteContract<'_> = storage.contract();
    let leaf_count = paynote.leaf_count.read()?;
    if leaf_count >= PAYNOTE_TREE_CAPACITY {
        return Err(PayNoteError::TreeFull.into());
    }

    // The commitment is always derived from the asset and amount this call
    // actually moves — never caller-supplied — so Merkle membership attests
    // both. A caller-chosen leaf would let a depositor fund a note in a cheap
    // token and spend it as an expensive one.
    let commitment = note_commitment(chain_id, serial, asset.into(), amount)?;
    if commitment.is_zero() {
        return Err(PayNoteError::InvalidInput("commitment must be non-zero".into()).into());
    }
    let commitment_word = B256::new(field_to_be_bytes(commitment));
    if paynote.commitments.read(&commitment_word)? {
        return Err(PayNoteError::CommitmentExists.into());
    }

    // One rollback unit: token movement, lazy initialization, append,
    // commitment insert, NewNote. `leaf_count == 0` is the pristine state —
    // initialization and the first append are atomic, so an active tree never
    // observes `leaf_count == 0`.
    storage.with_checkpoint(|| {
        let units = amount;
        // Pull into the pool, then let the router pull from the pool: the
        // router's `deposit` is a `transferFrom(caller, SELF)`, so the pool
        // must both hold the tokens and approve the router.
        storage.call(
            asset,
            U256::ZERO,
            IERC20::transferFromCall {
                from: caller,
                to: PAYNOTE_ADDRESS,
                amount: units,
            }
            .abi_encode()
            .into(),
        )?;
        storage.call(
            asset,
            U256::ZERO,
            IERC20::approveCall {
                spender: VAULT_ROUTER_ADDRESS,
                amount: units,
            }
            .abi_encode()
            .into(),
        )?;
        outbe_vaultrouter::api::deposit(&storage, asset, units)?;

        if leaf_count == 0 {
            let empty_root = B256::new(field_to_be_bytes(zeros[PAYNOTE_TREE_DEPTH]));
            paynote.current_root.write(empty_root)?;
            paynote.recent_roots.setup(PAYNOTE_ROOT_WINDOW)?;
            paynote.recent_roots.push(empty_root)?;
        }
        let (index, root_after) = append(&paynote, &zeros, commitment)?;
        paynote.commitments.write(&commitment_word, true)?;

        storage.emit_event(
            PAYNOTE_ADDRESS,
            IPayNote::NewNote::encode_log_data(&IPayNote::NewNote {
                commitment: commitment_word,
                leafIndex: index,
                rootAfter: root_after_word(root_after),
                asset,
                noteAmount: amount,
            }),
        )?;
        Ok(())
    })
}

fn root_after_word(root: Field) -> B256 {
    B256::new(field_to_be_bytes(root))
}

/// `consume(proof)` — verify a frozen `outbe.paynote@1.1.0` spend proof,
/// nullify the note, append any change commitment, and return the validated
/// claim. Moves no tokens.
///
/// The proof is the single source of truth for the statement: there is no
/// calldata path, so there is nothing to cross-check it against and no
/// statement-mismatch failure mode.
///
/// Notes are bearer instruments — spend authority is knowledge of the spend
/// key, not an address — so there is deliberately no caller check. The circuit
/// binds `spender` as the payout target, so a third party who replays someone
/// else's proof only spends their own gas; the claim still names the intended
/// spender.
pub(crate) fn consume(storage: &StorageHandle<'_>, proof: &[u8]) -> Result<PayNoteClaim> {
    // Framing must decode before any state is touched.
    let claim: PayNotePublicInputs = decode_paynote_public_inputs(proof)
        .map_err(|error| PayNoteError::InvalidInput(format!("proof is malformed: {error}")))?;

    let (runtime_chain_id, zeros) = chain_state(storage)?;
    let paynote: PayNoteContract<'_> = storage.contract();
    if paynote.leaf_count.read()? == 0 {
        return Err(PayNoteError::NotInitialized.into());
    }

    // A proof-supplied chain ID is never trusted.
    if claim.chain_id != runtime_chain_id {
        return Err(PayNoteError::InvalidInput("chain ID does not match runtime".into()).into());
    }

    // `asset != 0` is enforced here such as we do not accept native currency here.
    if claim.asset.is_zero() {
        return Err(PayNoteError::InvalidInput("asset must be non-zero".into()).into());
    }
    if claim.spender.is_zero() {
        return Err(PayNoteError::InvalidInput("spender must be non-zero".into()).into());
    }
    if claim.spend_amount.is_zero() {
        return Err(PayNoteError::InvalidInput("spend_amount must be non-zero".into()).into());
    }

    let nullifier = field_from_be_bytes(&claim.nullifier).ok_or(PayNoteError::InvalidInput(
        "nullifier is not a canonical BN254 field".into(),
    ))?;
    if nullifier.is_zero() {
        return Err(PayNoteError::InvalidInput("nullifier must be non-zero".into()).into());
    }
    let change = field_from_be_bytes(&claim.change_commitment).ok_or(
        PayNoteError::InvalidInput("changeCommitment is not a canonical BN254 field".into()),
    )?;

    let root_word = B256::new(claim.root);
    if !paynote.recent_roots.read_all()?.contains(&root_word) {
        return Err(PayNoteError::RootNotRecent.into());
    }

    let nullifier_word = B256::new(field_to_be_bytes(nullifier));
    if paynote.spent_nullifiers.read(&nullifier_word)? {
        return Err(PayNoteError::NullifierSpent.into());
    }

    match verify_circuit::<Paynote>(proof) {
        Ok(true) => {}
        Ok(false) => return Err(PayNoteError::InvalidInput("proof is invalid".into()).into()),
        Err(error) => {
            return Err(PayNoteError::InvalidInput(format!(
                "proof is malformed: zk verification backend failed: {error}"
            ))
            .into())
        }
    }

    // A full spend requires the zero change sentinel; a partial spend appends
    // exactly the circuit-derived deterministic change.
    let partial = !change.is_zero();
    let change_word = B256::new(field_to_be_bytes(change));
    if partial {
        if paynote.leaf_count.read()? >= PAYNOTE_TREE_CAPACITY {
            return Err(PayNoteError::TreeFull.into());
        }
        // Anyone knowing the current key can pre-create the deterministic
        // change; the resulting duplicate reverts atomically. Accepted DoS
        // exposure — never a fallback to spending without recording change.
        if paynote.commitments.read(&change_word)? {
            return Err(PayNoteError::CommitmentExists.into());
        }
    }

    // One rollback unit: nullifier, optional change append, events.
    storage.with_checkpoint(|| {
        paynote.spent_nullifiers.write(&nullifier_word, true)?;
        let change_receipt = if partial {
            let (index, root_after) = append(&paynote, &zeros, change)?;
            paynote.commitments.write(&change_word, true)?;
            Some((index, root_after))
        } else {
            None
        };
        storage.emit_event(
            PAYNOTE_ADDRESS,
            IPayNote::NoteUsed::encode_log_data(&IPayNote::NoteUsed {
                asset: claim.asset,
                spender: claim.spender,
                nullifier: nullifier_word,
                spendAmount: claim.spend_amount,
            }),
        )?;
        if let Some((index, root_after)) = change_receipt {
            storage.emit_event(
                PAYNOTE_ADDRESS,
                IPayNote::NewNote::encode_log_data(&IPayNote::NewNote {
                    commitment: change_word,
                    leafIndex: index,
                    rootAfter: root_after_word(root_after),
                    asset: claim.asset,
                    // Sentinel: a change note's remaining value is private.
                    noteAmount: U256::ZERO,
                }),
            )?;
        }
        Ok(())
    })?;

    Ok(PayNoteClaim {
        asset: claim.asset,
        spender: claim.spender,
        spend_amount: claim.spend_amount,
        nullifier: nullifier_word,
    })
}
