//! Rust mirror of the Emit hash and tree formulas.
//!
//! Copied from the frozen circuit formulas in
//! `outbe-emit-mint-circuit/src/emit.nr` and `outbe-circuit-core`'s
//! `hash.nr` / `tags.nr` / `merkle_tree.nr`:
//!
//! - BN254 fields use canonical 32-byte big-endian encodings; a word that
//!   would require reduction is invalid input.
//! - `h2(a, b) = Poseidon2([a, b])[0]` and `h3(a, b, c) = Poseidon2([a, b,
//!   c])[0]` — exactly noir's `hash_2` / `hash_3` (the `outbe-poseidon`
//!   sponge with `len = 2` / `len = 3`).
//! - `p(tag, values)` mirrors noir `hash_multi(tag, values)`: it absorbs
//!   the tag, the tuple arity, then the ordered values.
//! - Every purpose tag is domain-folded — `h2(EMIT_DOMAIN, base)` with the
//!   shared base tags (`NOTE_SN`, `COMMITMENT`, …) — so no Emit hash can
//!   collide with another domain's hash of the same purpose.
//! - Merkle inner nodes are `h3(EMIT_DOMAIN, left, right)` where
//!   `EMIT_DOMAIN` is the big-endian ASCII `OUTBE_EMIT`.

use alloy_primitives::U256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon2, PoseidonHasher};
use outbe_protocol::codec::u256_limbs_be;

/// The proving field — BN254 scalar field, matching the noir circuits.
pub type Field = Fr;

fn ascii_field(value: &str) -> Field {
    Field::from_be_bytes_mod_order(value.as_bytes())
}

/// `h2(left, right) = Poseidon2([left, right])[0]`.
fn h2(left: Field, right: Field) -> Field {
    Poseidon2::<Field>::new()
        .hash(&[left, right])
        .expect("Poseidon2 sponge is infallible")
}

/// `h3(a, b, c) = Poseidon2([a, b, c])[0]` — noir's three-input `hash_3`.
fn h3(a: Field, b: Field, c: Field) -> Field {
    Poseidon2::<Field>::new()
        .hash(&[a, b, c])
        .expect("Poseidon2 sponge is infallible")
}

/// Purpose-tagged chaining: `p(tag, values)` = noir `hash_multi(tag,
/// values)` — absorbs the tag, the tuple arity, then the ordered values.
pub fn p(tag: Field, values: &[Field]) -> Field {
    let mut state = h2(tag, Field::from(values.len() as u64));
    for value in values {
        state = h2(state, *value);
    }
    state
}

pub fn emit_domain() -> Field {
    ascii_field("OUTBE_EMIT")
}

/// Base purpose tags, shared by every circuit (`outbe-circuit-core::tags`).
fn base_tag_note_sn() -> Field {
    ascii_field("NOTE_SN")
}

fn base_tag_commitment() -> Field {
    ascii_field("COMMITMENT")
}

fn base_tag_nullifier() -> Field {
    ascii_field("NULLIFIER")
}

fn base_tag_change_key() -> Field {
    ascii_field("CHANGE_KEY")
}

fn base_tag_empty() -> Field {
    ascii_field("EMPTY")
}

/// Emit's instance of a shared base tag: `H2(EMIT_DOMAIN, base)`.
fn emit_tag(base: Field) -> Field {
    h2(emit_domain(), base)
}

pub fn tag_note_sn() -> Field {
    emit_tag(base_tag_note_sn())
}

pub fn tag_commitment() -> Field {
    emit_tag(base_tag_commitment())
}

pub fn tag_nullifier() -> Field {
    emit_tag(base_tag_nullifier())
}

pub fn tag_change_key() -> Field {
    emit_tag(base_tag_change_key())
}

pub fn tag_empty() -> Field {
    emit_tag(base_tag_empty())
}

/// An owner address absorbed as one big-endian integer, matching the circuit.
pub fn address_field(owner: [u8; 20]) -> Field {
    Field::from_be_bytes_mod_order(&owner)
}

/// `note_sn = P(EMIT_NOTE_SN, [owner, spend_key])`.
pub fn note_sn(note_owner: [u8; 20], note_spend_key: Field) -> Field {
    p(tag_note_sn(), &[address_field(note_owner), note_spend_key])
}

/// `C = P(EMIT_COMMITMENT, [chain_id, note_sn, amount_limb_0,
/// amount_limb_1, amount_limb_2])` — the only commitment form the runtime ever
/// appends. Hashing every canonical radix-2^120 limb keeps the full uint256
/// amount injective across the BN254 field boundary.
pub fn note_commitment(chain_id: u64, note_sn: Field, note_amount: U256) -> Field {
    let limbs = u256_limbs_be(&note_amount.to_be_bytes::<32>());
    p(
        tag_commitment(),
        &[
            Field::from(chain_id),
            note_sn,
            Field::from(limbs[0]),
            Field::from(limbs[1]),
            Field::from(limbs[2]),
        ],
    )
}

/// `nullifier = P(EMIT_NULLIFIER, [note_commitment, spend_key])` — binds the
/// full commitment (chain, serial, and amount), so distinct commitments
/// always yield distinct nullifiers.
pub fn nullifier(note_commitment: Field, note_spend_key: Field) -> Field {
    p(tag_nullifier(), &[note_commitment, note_spend_key])
}

/// `next_key = P(EMIT_CHANGE_KEY, [spend_key, nullifier])` — the
/// circuit-ratcheted successor key of a partial mint.
pub fn change_key(note_spend_key: Field, note_nullifier: Field) -> Field {
    p(tag_change_key(), &[note_spend_key, note_nullifier])
}

/// Chain-specific empty leaf: `P(EMIT_EMPTY, [chain_id])`.
pub fn empty_leaf(chain_id: u64) -> Field {
    p(tag_empty(), &[Field::from(chain_id)])
}

/// Tagged Merkle inner node: `H3(EMIT_DOMAIN, left, right)`.
pub fn merkle_node(left: Field, right: Field) -> Field {
    h3(emit_domain(), left, right)
}

/// The complete chain-specific empty ladder `zeros[0..=depth]`:
/// `zeros[0] = empty_leaf(chain_id)`,
/// `zeros[i+1] = H3(EMIT_DOMAIN, zeros[i], zeros[i])`.
/// Derived in memory on every request; never persisted.
pub fn empty_subtrees(chain_id: u64, depth: usize) -> Vec<Field> {
    let mut zeros = vec![Field::from(0u64); depth + 1];
    zeros[0] = empty_leaf(chain_id);
    for level in 0..depth {
        zeros[level + 1] = merkle_node(zeros[level], zeros[level]);
    }
    zeros
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
