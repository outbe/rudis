//! Rust mirror of the PayNote hash and tree formulas.
//!
//! Mirrors the frozen circuit formulas in
//! `outbe-paynote-circuit/src/paynote.nr` and
//! `outbe-circuit-core/src/{hash,tags,merkle_tree}.nr`:
//!
//! - BN254 fields use canonical 32-byte big-endian encodings; a word that
//!   would require reduction is invalid input.
//! - `h2(a, b)` / `h3(a, b, c)` are noir's `hash_2` / `hash_3` — the
//!   `outbe-poseidon` sponge at `len = 2` / `len = 3`.
//! - A purpose tag is *folded with the owning domain*:
//!   `tag(base) = h2(PAYNOTE_DOMAIN, base)`, so no PayNote hash can collide
//!   with another domain's hash of the same purpose.
//! - `p(tag, values)` mirrors noir `hash_multi(tag, values)`: absorb the
//!   folded tag, the tuple arity, then the ordered values.
//! - Merkle inner nodes are `h3(PAYNOTE_DOMAIN, left, right)`, where
//!   `PAYNOTE_DOMAIN` is the big-endian ASCII `OUTBE_PAYNOTE`.
//!
//! The commitment binds the **asset** as well as the amount, and the serial
//! does not. That is what lets the pool derive a deposit leaf from the
//! transfer it actually performed: an asset carried in the serial would be
//! user-supplied and unverifiable, letting a depositor fund a note in a cheap
//! token and spend it as an expensive one.

use alloy_primitives::U256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon2, PoseidonHasher};
use outbe_protocol::codec::u256_limbs_be;

use crate::errors::PayNoteError;

/// The proving field — BN254 scalar field, matching the noir circuits.
pub type Field = Fr;

/// Big-endian ASCII tree domain: every PayNote tag and Merkle node hangs off
/// it.
const PAYNOTE_DOMAIN: &str = "OUTBE_PAYNOTE";

// TODO refactor: introduce a base hashing functions and remove these ones.

// Base purpose tags, shared across circuits and folded with the domain above.
const TAG_NOTE_SN: &str = "NOTE_SN";
const TAG_COMMITMENT: &str = "COMMITMENT";
const TAG_NULLIFIER: &str = "NULLIFIER";
const TAG_CHANGE_KEY: &str = "CHANGE_KEY";
const TAG_EMPTY: &str = "EMPTY";

fn ascii_field(value: &str) -> Field {
    Field::from_be_bytes_mod_order(value.as_bytes())
}

/// `h2(left, right) = Poseidon2([left, right])[0]`.
fn h2(left: Field, right: Field) -> Result<Field, PayNoteError> {
    Poseidon2::<Field>::new()
        .hash(&[left, right])
        .map_err(|_| PayNoteError::Hash)
}

/// `h3(a, b, c) = Poseidon2([a, b, c])[0]` — noir's three-input `hash_3`.
fn h3(a: Field, b: Field, c: Field) -> Result<Field, PayNoteError> {
    Poseidon2::<Field>::new()
        .hash(&[a, b, c])
        .map_err(|_| PayNoteError::Hash)
}

/// The PayNote domain as a field element.
pub fn paynote_domain() -> Field {
    ascii_field(PAYNOTE_DOMAIN)
}

/// Mirror of `outbe_circuit_core::tags::tag`: a base purpose tag folded with
/// the domain that owns it.
fn tag(base: &str) -> Result<Field, PayNoteError> {
    h2(paynote_domain(), ascii_field(base))
}

/// Purpose-tagged chaining: `p(tag, values)` = noir `hash_multi(tag, values)`
/// — absorbs the folded tag, the tuple arity, then the ordered values.
pub fn p(tag: Field, values: &[Field]) -> Result<Field, PayNoteError> {
    let mut state = h2(tag, Field::from(values.len() as u64))?;
    for value in values {
        state = h2(state, *value)?;
    }
    Ok(state)
}

/// A 20-byte address absorbed as one big-endian integer, matching the
/// circuit's `EthAddress` newtype (which collapses to a single field leaf).
pub fn address_field(address: [u8; 20]) -> Field {
    Field::from_be_bytes_mod_order(&address)
}

/// `note_sn = P(NOTE_SN, [spend_key])` — a hiding commitment to the spend
/// key. Chain-, asset- and amount-independent, so the pool can accept one at
/// deposit time and build the leaf around it.
pub fn note_sn(note_spend_key: Field) -> Result<Field, PayNoteError> {
    p(tag(TAG_NOTE_SN)?, &[note_spend_key])
}

/// `C = P(COMMITMENT, [chain_id, note_sn, asset, amount_limb_0,
/// amount_limb_1, amount_limb_2])` — the Merkle leaf and the only commitment
/// form the runtime appends. Hashing all canonical radix-2^120 limbs binds the
/// full uint256 amount without field-modulus aliases.
pub fn note_commitment(
    chain_id: u64,
    note_sn: Field,
    asset: [u8; 20],
    note_amount: U256,
) -> Result<Field, PayNoteError> {
    let limbs = u256_limbs_be(&note_amount.to_be_bytes::<32>());
    p(
        tag(TAG_COMMITMENT)?,
        &[
            Field::from(chain_id),
            note_sn,
            address_field(asset),
            Field::from(limbs[0]),
            Field::from(limbs[1]),
            Field::from(limbs[2]),
        ],
    )
}

/// `nullifier = P(NULLIFIER, [commitment, spend_key])` — derived from the
/// commitment rather than the serial, so every leaf has exactly one
/// nullifier. Two leaves sharing a serial carry different amounts, hence
/// different commitments and different nullifiers, and both stay spendable.
pub fn note_nullifier(
    note_commitment: Field,
    note_spend_key: Field,
) -> Result<Field, PayNoteError> {
    p(tag(TAG_NULLIFIER)?, &[note_commitment, note_spend_key])
}

/// `next_key = P(CHANGE_KEY, [spend_key, nullifier])` — the circuit-ratcheted
/// successor key of a partial spend.
pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Result<Field, PayNoteError> {
    p(tag(TAG_CHANGE_KEY)?, &[note_spend_key, note_nullifier])
}

/// Chain-specific empty leaf: `P(EMPTY, [chain_id])`. Deliberately not zero —
/// the circuit's `commitment != 0` assert is what blocks spending a
/// zero-padded slot, and this keeps empty slots distinguishable per chain.
pub fn empty_leaf(chain_id: u64) -> Result<Field, PayNoteError> {
    p(tag(TAG_EMPTY)?, &[Field::from(chain_id)])
}

/// Tagged Merkle inner node: `H3(PAYNOTE_DOMAIN, left, right)`.
pub fn merkle_node(left: Field, right: Field) -> Result<Field, PayNoteError> {
    h3(paynote_domain(), left, right)
}

/// The complete chain-specific empty ladder `zeros[0..=depth]`:
/// `zeros[0] = empty_leaf(chain_id)`,
/// `zeros[i + 1] = H3(PAYNOTE_DOMAIN, zeros[i], zeros[i])`.
/// Derived in memory on every request; never persisted.
pub fn empty_subtrees(chain_id: u64, depth: usize) -> Result<Vec<Field>, PayNoteError> {
    let mut zeros = vec![Field::from(0u64); depth + 1];
    zeros[0] = empty_leaf(chain_id)?;
    for level in 0..depth {
        zeros[level + 1] = merkle_node(zeros[level], zeros[level])?;
    }
    Ok(zeros)
}

/// Canonical 32-byte big-endian encoding of a field element.
pub fn field_to_be_bytes(value: Field) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Parse a canonical 32-byte big-endian field word; `None` when the word
/// would require reduction. Callers attach the ABI field name to the error.
pub fn field_from_be_bytes(bytes: &[u8; 32]) -> Option<Field> {
    let field = Field::from_be_bytes_mod_order(bytes);
    (field_to_be_bytes(field) == *bytes).then_some(field)
}
