//! Shared construction + verification of the seed-partial identity attestation.
//!
//! Each validator's `bls_seed_partial` is a BLS threshold partial signature,
//! recoverable into the group VRF proof. By itself it carries no binding to the
//! validator's identity key, so "validator i emitted THIS partial" is forgeable
//! by any relay and not reproducible from chain state - making it unslashable.
//!
//! To make it attributable, each `HybridSignature` additionally carries a MinPk
//! identity signature over a domain-separated message binding
//! `(round, vrf_material_version, partial)`. The signer
//! ([`crate::hybrid::HybridScheme::sign`]) and the on-chain SlashIndicator
//! evidence verifier both build the signed bytes through the helpers here, so
//! the two sides cannot drift. A workspace test pins a fixed vector.
//!
//! The bound message is:
//! ```text
//! Round(epoch, view).encode()  ||  version.to_be_bytes()  ||  partial_bytes
//! ```
//! signed under [`OUTBE_SEED_ATTEST_NAMESPACE_V2`]. `Round::encode()` is the
//! exact byte string the partial itself commits to (the seed message), so the
//! identity signature binds the partial to its round.

use std::num::NonZeroU32;

use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode, Read as _};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381::primitives::{
    ops::verify_message,
    sharing::{ModeVersion, Sharing},
    variant::{MinSig, Variant},
};
use commonware_cryptography::{bls12381, Verifier as _};
use commonware_utils::Participant;

use crate::proof::constants::{
    hybrid_seed_namespace, seed_attest_namespace, seed_namespace_and_message,
};

/// Canonical message bound by a seed-partial identity signature.
///
/// `partial_bytes` is the encoded `V::Signature` of the `bls_seed_partial`
/// (48 bytes for `MinSig`). Callers on both the signer and verifier sides MUST
/// pass byte-identical inputs.
pub fn seed_partial_attest_message(
    round_epoch: u64,
    round_view: u64,
    vrf_material_version: u64,
    partial_bytes: &[u8],
) -> Vec<u8> {
    let round = Round::new(Epoch::new(round_epoch), View::new(round_view));
    let round_bytes = round.encode();
    let mut msg = Vec::with_capacity(round_bytes.len() + 8 + partial_bytes.len());
    msg.extend_from_slice(round_bytes.as_ref());
    msg.extend_from_slice(&vrf_material_version.to_be_bytes());
    msg.extend_from_slice(partial_bytes);
    msg
}

/// Verify a seed-partial identity signature against the author's MinPk identity
/// key. Returns `true` iff `signature` is `identity_pubkey`'s signature over
/// [`seed_partial_attest_message`] under [`OUTBE_SEED_ATTEST_NAMESPACE_V2`].
///
/// A `true` result is non-repudiable proof that the holder of `identity_pubkey`
/// deliberately emitted exactly this `(round, version, partial)` triple.
pub fn verify_seed_partial_attest(
    identity_pubkey: &bls12381::PublicKey,
    round_epoch: u64,
    round_view: u64,
    vrf_material_version: u64,
    partial_bytes: &[u8],
    signature: &bls12381::Signature,
) -> bool {
    let message =
        seed_partial_attest_message(round_epoch, round_view, vrf_material_version, partial_bytes);
    identity_pubkey.verify(&seed_attest_namespace(), &message, signature)
}

/// Raw-bytes variant of [`verify_seed_partial_attest`] for on-chain evidence
/// verifiers that hold only wire bytes (e.g. SlashIndicator). `identity_pubkey`
/// must be a 48-byte MinPk public key and `signature` a 96-byte MinPk
/// signature; malformed inputs (wrong length, off-curve) return `false` rather
/// than panicking. Determinism: this is a plain pairing check, no RNG.
pub fn verify_seed_partial_attest_bytes(
    identity_pubkey: &[u8],
    round_epoch: u64,
    round_view: u64,
    vrf_material_version: u64,
    partial_bytes: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(pubkey) =
        <bls12381::PublicKey as DecodeExt<()>>::decode(Bytes::copy_from_slice(identity_pubkey))
    else {
        return false;
    };
    let Ok(sig) = <bls12381::Signature as DecodeExt<()>>::decode(Bytes::copy_from_slice(signature))
    else {
        return false;
    };
    verify_seed_partial_attest(
        &pubkey,
        round_epoch,
        round_view,
        vrf_material_version,
        partial_bytes,
        &sig,
    )
}

/// The single plain-pairing core for threshold-VRF seed signatures.
///
/// Returns `true` iff `signature` is a valid MinSig signature by `pk` over
/// `seed_message` under [`hybrid_seed_namespace`]. No RNG - a deterministic
/// pairing check, so every node reaches the same verdict, which is required on
/// the slashing path ([`verify_seed_partial_against_commitment`], `pk` = the
/// signer's `PK_i`) and the next-height execution gate (`crate::proof::verifier`,
/// `pk` = the committee group key). The BLS-batch path with random scalar
/// weights is intentionally avoided here.
pub fn verify_seed_signature_plain(
    pk: &<MinSig as Variant>::Public,
    seed_message: &[u8],
    signature: &<MinSig as Variant>::Signature,
) -> bool {
    verify_message::<MinSig>(pk, &hybrid_seed_namespace(), seed_message, signature).is_ok()
}

/// Deterministically decide whether a threshold-VRF seed partial is VALID
/// against the committee's full public polynomial commitment.
///
/// Used by SlashIndicator to slash an *invalid* partial: it must confirm the
/// partial does NOT verify before applying a penalty. Returns:
/// - `Some(true)`  - the partial verifies (the validator behaved correctly; NOT
///   slashable),
/// - `Some(false)` - the partial does not verify (slashable),
/// - `None`        - malformed input (undecodable commitment, signer index out
///   of range, or undecodable partial) - the caller must reject, not slash.
///
/// `commitment_bytes` is `commonware_codec::Encode(Sharing<MinSig>)` - the same
/// bytes whose keccak256 is committed in the committee snapshot
/// (`vrf_public_polynomial_hash`); the caller MUST check that hash first so the
/// commitment is authentic. Verification is a single deterministic pairing
/// check (the BLS-batch path with random scalar weights is intentionally
/// avoided), so every node reaches the same verdict - required because the
/// result drives slashing.
pub fn verify_seed_partial_against_commitment(
    commitment_bytes: &[u8],
    signer_index: u32,
    round_epoch: u64,
    round_view: u64,
    partial_bytes: &[u8],
) -> Option<bool> {
    // Cap must cover any real committee; matches the DKG decode bound.
    let max = NonZeroU32::new(crate::bls::MAX_VALIDATORS)?;
    let cfg = (max, ModeVersion::v0());
    let sharing = Sharing::<MinSig>::read_cfg(&mut &commitment_bytes[..], &cfg).ok()?;

    // PK_i = polynomial evaluated at the signer's index.
    let pk_i = sharing
        .partial_public(Participant::new(signer_index))
        .ok()?;

    // The partial is a MinSig threshold signature over
    // (OUTBE_HYBRID_SEED_NAMESPACE_V2, Round.encode()).
    let partial = <<MinSig as Variant>::Signature as DecodeExt<()>>::decode(
        Bytes::copy_from_slice(partial_bytes),
    )
    .ok()?;
    let (_, seed_message) = seed_namespace_and_message(round_epoch, round_view);
    Some(verify_seed_signature_plain(&pk_i, &seed_message, &partial))
}
