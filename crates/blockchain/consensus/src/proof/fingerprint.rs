//! Canonical fingerprint helpers used by V2 Rewards/Slash settlement, the
//! certified-parent proof store, and slashing evidence dedup.
//!
//! Every helper here is part of the V2 on-chain contract: any change to a byte
//! layout is hard-fork-equivalent.
//!
//! `committee_set_hash_v2` / `committee_snapshot_key` and the
//! [`CommitteeSnapshot`] type live in [`crate::committee`] and are re-exported
//! here so every caller can use `outbe_consensus::proof::*` as the single
//! public namespace for V2 fingerprint helpers.

use alloy_primitives::B256;
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::variant::Variant;

use super::hybrid_wire::VrfProof;

pub use super::committee::{
    committee_set_hash_v2, committee_snapshot_key, CommitteeEntry, CommitteeSnapshot,
};

/// Canonical hash of a signer bitmap.
///
/// Layout:
///
/// ```text
/// keccak256( (bitmap.len() as u32).to_be_bytes() || bitmap )
/// ```
///
/// The length prefix makes this hash injective across different bitmap sizes
/// (otherwise `[0u8; 1]` and `[]` would collide after trailing-zero stripping).
pub fn canonical_signer_set_hash(signer_bitmap: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(4 + signer_bitmap.len());
    debug_assert!(
        signer_bitmap.len() <= u32::MAX as usize,
        "signer bitmap length must fit in u32",
    );
    buf.extend_from_slice(&(signer_bitmap.len() as u32).to_be_bytes());
    buf.extend_from_slice(signer_bitmap);
    alloy_primitives::keccak256(&buf)
}

/// Canonical hash of a [`VrfProof`].
///
/// Defined as `keccak256(commonware_codec::Encode::encode(proof))` - this is
/// the AC6 contract: the helper is **exactly** keccak256 over the encoded
/// proof, with no additional framing. Used by Rewards/Slash V2 fingerprints
/// and `invalid_vrf_evidence_hash_v2`.
pub fn canonical_vrf_proof_hash_v2<V: Variant>(proof: &VrfProof<V>) -> B256 {
    let bytes = Encode::encode(proof);
    alloy_primitives::keccak256(bytes)
}

/// Canonical evidence-hash for an invalid VRF slashing submission.
///
/// Layout:
///
/// ```text
/// keccak256( child_hash (32) || phase1_tx_hash (32) )
/// ```
///
/// Used as the dedup key by `SlashIndicator.submitInvalidVrfProofEvidence`
///. Two evidence submissions targeting the same `(child_hash,
/// phase1_tx_hash)` are the same logical event.
///
/// # Design - no version domain separator
///
/// The preimage is intentionally minimal: it does NOT include a
/// version-specific prefix such as `"OUTBE_INVALID_VRF_EVIDENCE_V2"`.
/// Including one would make a future wire-format bump (e.g., a `_v3`
/// endpoint with a richer evidence struct) produce a different dedup
/// hash for the same real offence, which would let the same
/// `(child_hash, phase1_tx_hash)` be slashed twice across versions and
/// directly violate ` - one slash per (child_hash, phase1_tx_hash)`.
/// Keeping the preimage version-independent guarantees cross-version
/// idempotency without state migration. The `_v2` suffix in the function
/// name reflects the V2 protocol family, NOT the hash-formula version.
pub fn invalid_vrf_evidence_hash_v2(child_hash: B256, phase1_tx_hash: B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(child_hash.as_slice());
    buf[32..].copy_from_slice(phase1_tx_hash.as_slice());
    alloy_primitives::keccak256(buf)
}
