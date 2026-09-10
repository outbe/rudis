//! V2 self-contained Hybrid certificate verifier.
//!
//! This crate is intentionally below `outbe-consensus` in the dep tree, so the
//! EVM executor and full-node import path can verify a finalization
//! certificate **without** the validator runtime: no marshal mailbox, no DKG
//! state, no `Mutex`/`RwLock` from `outbe-consensus`.
//!
//! ## Scope
//!
//! This module ships the public API surface and the structural + BLS aggregate
//! + mandatory threshold-VRF rules:
//!
//! * Decode the `HybridCertificate<MinSig>` from raw bytes against an
//!   explicit max-participants bound.
//! * Reject empty signer sets, structurally invalid bitmaps, and certificates
//!   that drop below quorum.
//! * Verify the aggregated BLS MinPk vote signature against the active
//!   committee key set and the canonical vote message.
//! * Verify the mandatory threshold-VRF proof against the active VRF group
//!   public key and the canonical seed message.
//!
//! ## Deferred to
//!
//! The full A4 verifier additionally rejects on:
//!
//! * binding: certificate metadata (epoch/view/parent_view/finalized_block_hash)
//!   versus the proposer-claimed `FinalizedParentCertificateData`,
//! * missed_proposers: any non-empty `missed_proposers` rejects pre-mutation,
//! * canonical signer bitmap reconciliation including extra finalize votes.
//!
//! Those rules require the proposer-side metadata envelope and the elector
//! configuration. They land; this module exposes the entry point
//! they will extend.

use crate::proof::committee_keys::{committee_ordered_set, decode_committee_participants};
use crate::proof::{committee_set_hash_v2, CommitteeSnapshot};
use crate::{digest::Digest as OutbeDigest, hybrid::HybridScheme};
use alloy_primitives::{keccak256, B256};
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_consensus::simplex::types::{Finalization, Notarization};
use commonware_cryptography::bls12381::{
    self,
    primitives::{
        ops::aggregate,
        variant::{MinPk, MinSig, Variant},
    },
};
use commonware_utils::Participant;
use outbe_primitives::consensus_metadata::{
    CertifiedParentAccountingMetadata, ParentParticipationProof,
};
use std::collections::BTreeSet;

use super::constants::{finalize_namespace, notarize_namespace};
use super::error::V2VerifyError;
use super::hybrid_wire::{HybridCertificate, VrfProof};

// =============================================================================
// Public API surface
// =============================================================================

/// Outcome of a successful V2 proof verification.
///
/// All fields are derived from the decoded certificate; none are read from a
/// `Mutex` or background channel. Callers can copy or persist this without
/// holding any lock.
#[derive(Debug, Clone)]
pub struct VerifiedProof {
    /// Encoded signer bitmap (`1` = signed, `0` = absent), one byte per
    /// participant, in the same order as `snapshot.ordered_committee`.
    pub signer_bitmap: Vec<u8>,
    /// `keccak256(VrfProof::encode())` - canonical fingerprint of the VRF
    /// proof carried in this certificate. See
    /// [`crate::canonical_vrf_proof_hash_v2`].
    pub vrf_proof_hash: B256,
    /// Material version of the verified VRF proof. Used by Rewards/Slash V2
    /// settlement to bind to the active VRF material.
    pub vrf_material_version: u64,
}

// `V2VerifyError` lives in [`crate::error`]. The enum
// was split out so the variant taxonomy (21 variants) is the single source
// of truth for both the verifier and the downstream evidence wrappers.

/// Reason why a vote subject is required by the verifier.
///
/// V2 finalization-bound proofs use [`VoteSubject::Finalize`]; notarization
/// fallback proofs (Activity::Certification) use [`VoteSubject::Notarize`].
#[derive(Debug, Clone, Copy)]
pub enum VoteSubject {
    Notarize,
    Finalize,
}

/// Borrowed view of the active committee snapshot at the proof's epoch.
///
/// Field shapes are minimal on purpose: the verifier is self-contained and
/// must not need anything beyond what is required to verify BLS aggregate
/// vote + threshold VRF. The on-chain persistence lives in
/// `CommitteeSnapshotStore` slots 31..40 in `ValidatorSet`; the verifier
/// only requires this borrowed view.
#[derive(Debug, Clone, Copy)]
pub struct CommitteeSnapshotView<'a> {
    /// Per-participant BLS MinPk identity keys, in the same order as the
    /// committee bitmap (`signer_bitmap[i] == 1` <-> `participants[i]` signed).
    pub participants: &'a [bls12381::PublicKey],
    /// Active VRF group public key (BLS MinSig variant). Threshold partial
    /// signatures recover to a signature under this key.
    pub vrf_group_public_key: <MinSig as Variant>::Public,
    /// Active VRF material version. Used downstream (Rewards/Slash) to bind to
    /// a specific DKG/reshare epoch.
    pub vrf_material_version: u64,
}

/// Vote message bytes required to verify the BLS aggregate.
///
/// In Simplex, the BLS aggregate signs `subject.namespace || subject.message()`.
/// For V2 finalization proofs the message is the canonical encoded proposal
/// and the namespace is `notarize_namespace(b"outbe")` /
/// `finalize_namespace(b"outbe")` depending on `subject`. The caller (the V2
/// executor or full-node import path) is responsible for producing the exact
/// bytes - this avoids dragging Simplex's `Subject<D>` enum into the
/// low-level crate.
#[derive(Debug, Clone, Copy)]
pub struct VoteBinding<'a> {
    pub subject: VoteSubject,
    /// Domain-separated namespace bytes for this subject under the active
    /// chain namespace (e.g. `b"outbe_NOTARIZE"` or `b"outbe_FINALIZE"`).
    pub namespace: &'a [u8],
    /// Canonical encoded vote message (e.g. `Proposal::encode()` bytes).
    pub message: &'a [u8],
    /// Canonical encoded seed message for the threshold-VRF check.
    pub seed_message: &'a [u8],
}

/// Low-level Hybrid certificate verifier.
///
/// Used internally by [`verify_v2_proof`] and retained for the
/// smoke-test fixture that drives the BLS+VRF rules in isolation. Callers
/// implementing the V2 protocol should use the metadata-bound
/// [`verify_v2_proof`] instead - it adds the A4 binding rules
/// (missed_proposers, exact-parent, committee_set_hash, signer-bitmap
/// reconciliation, VRF material/group-key binding) on top of the structural
/// + crypto checks performed here.
///
/// ## Rules verified here
///
/// 1. `proof_bytes` decodes into a `HybridCertificate<MinSig>` against
///    `snapshot.participants.len()` as the upper bound.
/// 2. Signer count meets the simplex `N3f1` quorum.
/// 3. Signer bitmap shape (length, indices `< participants.len()`).
/// 4. BLS MinPk aggregate vote verifies under `binding.namespace`/`binding.message`.
/// 5. A threshold-VRF proof is present and verifies against
///    `snapshot.vrf_group_public_key` and [`OUTBE_HYBRID_SEED_NAMESPACE_V2`].
pub fn verify_v2_proof_low_level(
    snapshot: &CommitteeSnapshotView<'_>,
    binding: &VoteBinding<'_>,
    proof_bytes: &[u8],
) -> Result<VerifiedProof, V2VerifyError> {
    let cert = HybridCertificate::<MinSig>::decode_cfg(
        Bytes::copy_from_slice(proof_bytes),
        &snapshot.participants.len(),
    )
    .map_err(V2VerifyError::Decode)?;
    // The structural + crypto checks are shared with the metadata-bound path
    // through the private checker; this public entry adds only the wire decode.
    verify_v2_certificate_low_level(snapshot, binding, &cert)
}

fn verify_v2_certificate_low_level(
    snapshot: &CommitteeSnapshotView<'_>,
    binding: &VoteBinding<'_>,
    cert: &HybridCertificate<MinSig>,
) -> Result<VerifiedProof, V2VerifyError> {
    let participants_len = snapshot.participants.len();

    if cert.signers.len() != participants_len {
        return Err(V2VerifyError::BitmapMismatch {
            reason: "bitmap length does not match committee size",
        });
    }

    let quorum = simplex_n3f1_quorum(participants_len);
    let signer_count = cert.signers.count();
    if signer_count < quorum {
        return Err(V2VerifyError::BelowQuorum {
            signers: signer_count,
            quorum,
        });
    }

    let signer_pubkeys: Vec<&<MinPk as Variant>::Public> = cert
        .signers
        .iter()
        .filter_map(|signer: Participant| {
            let idx = signer.get() as usize;
            snapshot.participants.get(idx).map(AsRef::as_ref)
        })
        .collect();
    if signer_pubkeys.len() != signer_count {
        return Err(V2VerifyError::SignerIndexOutOfRange {
            index: 0,
            committee_size: participants_len,
        });
    }
    let aggregate_pk = aggregate::combine_public_keys::<MinPk, _>(signer_pubkeys);
    aggregate::verify_same_message::<MinPk>(
        &aggregate_pk,
        binding.namespace,
        binding.message,
        &cert.bls_aggregated_vote,
    )
    .map_err(|_| V2VerifyError::BlsAggregateInvalid)?;

    let proof = &cert.vrf_proof;
    verify_threshold_vrf_proof(&snapshot.vrf_group_public_key, binding.seed_message, proof)?;

    let mut signer_bitmap = vec![0u8; participants_len];
    for signer in cert.signers.iter() {
        let signer: Participant = signer;
        let idx = signer.get() as usize;
        if idx >= participants_len {
            return Err(V2VerifyError::SignerIndexOutOfRange {
                index: idx as u32,
                committee_size: participants_len,
            });
        }
        signer_bitmap[idx] = 1;
    }

    let vrf_proof_hash = crate::proof::canonical_vrf_proof_hash_v2(proof);

    Ok(VerifiedProof {
        signer_bitmap,
        vrf_proof_hash,
        vrf_material_version: proof.material_version,
    })
}

/// `N3f1` quorum threshold: `floor(2n/3) + 1`. Matches
/// `commonware_utils::N3f1::quorum(n)` for any `n >= 1`.
pub const fn simplex_n3f1_quorum(n: usize) -> usize {
    (2 * n) / 3 + 1
}

fn verify_threshold_vrf_proof(
    group_pk: &<MinSig as Variant>::Public,
    seed_message: &[u8],
    proof: &VrfProof<MinSig>,
) -> Result<(), V2VerifyError> {
    // Plain-pairing core shared with the slashing path (`seed_partial`); no RNG,
    // so the gate's Result is byte-deterministic across every validator.
    if crate::proof::verify_seed_signature_plain(group_pk, seed_message, &proof.threshold_signature)
    {
        Ok(())
    } else {
        Err(V2VerifyError::InvalidVrfSignature)
    }
}

// =============================================================================
// Metadata-bound public verifier
// =============================================================================

/// self-contained V2 verifier. Verifies a Hybrid finalization /
/// certified-notarization certificate against the proposer-claimed
/// [`CertifiedParentAccountingMetadata`], the active [`CommitteeSnapshot`],
/// and the block-header parent hash. Returns the canonical
/// [`VerifiedProof`] on success; otherwise a precise [`V2VerifyError`]
/// matching the violated rule.
///
/// ## Rules verified
///
/// 1. `metadata.missed_proposers` is empty
///    ([`V2VerifyError::NonEmptyMissedProposers`]).
/// 2. Exact-parent binding: `metadata.finalized_block_hash == header_parent_hash`
///    ([`V2VerifyError::WrongAccountedHash`]).
/// 3. Committee shape: `metadata.ordered_committee.len() == snapshot.committee.len()`
///    and per-position `address` matches
///    ([`V2VerifyError::BitmapMismatch`]).
/// 4. Bitmap shape: `metadata.signer_bitmap.len() == metadata.ordered_committee.len()`
///    ([`V2VerifyError::BitmapMismatch`]).
/// 5. VRF material version binding: metadata == snapshot
///    ([`V2VerifyError::WrongVrfMaterialVersion`]).
/// 6. VRF group public key hash: `metadata.vrf_group_public_key_hash ==
///    keccak256(snapshot.vrf_group_public_key_bytes)`
///    ([`V2VerifyError::WrongVrfGroupKeyHash`]).
/// 7. Committee fingerprint: `metadata.committee_set_hash ==
///    committee_set_hash_v2(metadata.finalized_epoch, snapshot)`
///    ([`V2VerifyError::CommitteeSetHashMismatch`]).
/// 8. Proof bytes equal `metadata.proof` byte-identically
///    ([`V2VerifyError::WrongProofDomain`] with the embedded payload hash if
///    the inner proposal differs from `metadata.finalized_block_hash`).
/// 9. Certificate decodes into `HybridCertificate<MinSig>` and passes the
///    BLS aggregate + threshold VRF rules from [`verify_v2_proof_low_level`]
///    under the canonical namespace + seed for
///    `Round(metadata.finalized_epoch, metadata.finalized_view)` and the
///    canonical Simplex `Proposal::encode()` vote message.
///
/// ## Determinism
///
/// `verify_v2_proof` is a synchronous pure function. It does not read
/// wall-clock time, OS entropy, network state, or any process-local mutable
/// state - same inputs produce the same `Result`, byte-deterministically
/// (proptest `verifier_outcome_deterministic_from_parent_state_and_body`).
pub fn verify_v2_proof(
    metadata: &CertifiedParentAccountingMetadata,
    snapshot: &CommitteeSnapshot,
    proof_bytes: &[u8],
    header_parent_hash: B256,
) -> Result<VerifiedProof, V2VerifyError> {
    // Rule 1 - missed_proposers MUST be empty in V2, ALWAYS, BEFORE any
    // other check. This rejects pre-mutation, applies to both proof kinds.
    if !metadata.missed_proposers.is_empty() {
        return Err(V2VerifyError::NonEmptyMissedProposers {
            count: metadata.missed_proposers.len(),
        });
    }

    // Rule 2 - exact-parent binding. The metadata MUST target the
    // immediate parent of the block under verification.
    if metadata.finalized_block_hash != header_parent_hash {
        return Err(V2VerifyError::WrongAccountedHash {
            expected: header_parent_hash,
            actual: metadata.finalized_block_hash,
        });
    }

    // Rule 3 - committee shape: metadata vs snapshot must agree on size
    // AND per-position address. Disagreement is either a snapshot lookup error
    // by the caller or a malicious metadata.
    if snapshot.committee.is_empty() {
        return Err(V2VerifyError::CommitteeSnapshotMissing);
    }
    if metadata.ordered_committee.len() != snapshot.committee.len() {
        return Err(V2VerifyError::BitmapMismatch {
            reason: "metadata.ordered_committee length differs from snapshot.committee length",
        });
    }
    for (i, (meta_addr, snap_entry)) in metadata
        .ordered_committee
        .iter()
        .zip(snapshot.committee.iter())
        .enumerate()
    {
        if *meta_addr != snap_entry.address {
            // Mismatch at position `i` - log via Display only; the variant is
            // structural ("metadata cannot override consensus pubkeys" - the
            // test `metadata_cannot_override_consensus_pubkeys` pins this).
            let _ = i;
            return Err(V2VerifyError::BitmapMismatch {
                reason: "metadata.ordered_committee[i].address differs from snapshot.committee[i].address",
            });
        }
    }

    // Rule 4 - bitmap shape: length must match committee.
    if metadata.signer_bitmap.len() != metadata.ordered_committee.len() {
        return Err(V2VerifyError::BitmapMismatch {
            reason: "metadata.signer_bitmap length differs from ordered_committee length",
        });
    }

    // Rule 5 - VRF material version binding (metadata == snapshot).
    if metadata.vrf_material_version != snapshot.vrf_material_version {
        return Err(V2VerifyError::WrongVrfMaterialVersion {
            expected: snapshot.vrf_material_version,
            actual: metadata.vrf_material_version,
        });
    }

    // Rule 6 - VRF group public key hash binding.
    let snapshot_group_pk_hash = keccak256(&snapshot.vrf_group_public_key_bytes);
    if metadata.vrf_group_public_key_hash != snapshot_group_pk_hash {
        return Err(V2VerifyError::WrongVrfGroupKeyHash {
            expected: snapshot_group_pk_hash,
            actual: metadata.vrf_group_public_key_hash,
        });
    }

    // Rule 7 - canonical committee_set_hash fingerprint binding.
    let canonical_committee_set_hash = committee_set_hash_v2(metadata.finalized_epoch, snapshot);
    if metadata.committee_set_hash != canonical_committee_set_hash {
        return Err(V2VerifyError::CommitteeSetHashMismatch {
            expected: canonical_committee_set_hash,
            actual: metadata.committee_set_hash,
        });
    }

    // Rule 8 - proof bytes equal metadata.proof byte-identically.
    if proof_bytes != metadata.proof.as_ref() {
        return Err(V2VerifyError::WrongProofDomain {
            expected: metadata.finalized_block_hash,
            actual: B256::ZERO,
        });
    }

    // Build the snapshot view + vote binding from metadata.
    let participants = decode_committee_participants(snapshot)?;
    let vrf_group_public_key = decode_min_sig_public(&snapshot.vrf_group_public_key_bytes)?;
    let view = CommitteeSnapshotView {
        participants: &participants,
        vrf_group_public_key,
        vrf_material_version: snapshot.vrf_material_version,
    };

    let participants_len = snapshot.committee.len();
    let mut proof_reader = metadata.proof.as_ref();
    let (subject, proposal, cert) = match metadata.proof_kind {
        ParentParticipationProof::Finalization => {
            let proof = Finalization::<HybridScheme<MinSig>, OutbeDigest>::read_cfg(
                &mut proof_reader,
                &participants_len,
            )
            .map_err(V2VerifyError::Decode)?;
            (VoteSubject::Finalize, proof.proposal, proof.certificate)
        }
        ParentParticipationProof::CertifiedNotarization => {
            let proof = Notarization::<HybridScheme<MinSig>, OutbeDigest>::read_cfg(
                &mut proof_reader,
                &participants_len,
            )
            .map_err(V2VerifyError::Decode)?;
            (VoteSubject::Notarize, proof.proposal, proof.certificate)
        }
    };
    if !proof_reader.is_empty() {
        return Err(V2VerifyError::TrailingBytes);
    }

    if proposal.round.epoch().get() != metadata.finalized_epoch
        || proposal.round.view().get() != metadata.finalized_view
        || proposal.parent.get() != metadata.parent_view
        || proposal.payload.0 != metadata.finalized_block_hash
    {
        return Err(V2VerifyError::WrongProofDomain {
            expected: metadata.finalized_block_hash,
            actual: proposal.payload.0,
        });
    }

    // vote namespaces bind the ordered committee (same sorted/deduped order as
    // the signer's participant set) so these bytes equal what the signer used.
    let committee_set = committee_ordered_set(&participants);
    let namespace = match subject {
        VoteSubject::Finalize => finalize_namespace(&committee_set),
        VoteSubject::Notarize => notarize_namespace(&committee_set),
    };

    let round = proposal.round;
    let seed_message = round.encode().to_vec();
    let message = proposal.encode().to_vec();

    let binding = VoteBinding {
        subject,
        namespace: &namespace,
        message: &message,
        seed_message: &seed_message,
    };

    // Rule 9 - delegate to the low-level structural + crypto verifier.
    let inner = verify_v2_certificate_low_level(&view, &binding, &cert)?;

    // Rule 5 cross-check: cert's VRF material version must also equal the
    // metadata's (the inner verifier returns it directly from the proof).
    if inner.vrf_material_version != metadata.vrf_material_version {
        return Err(V2VerifyError::WrongVrfMaterialVersion {
            expected: metadata.vrf_material_version,
            actual: inner.vrf_material_version,
        });
    }

    // Rule 8 cross-check: bitmap reconciliation - metadata's bitmap must
    // exactly equal the reconstructed bitmap from the certificate.
    if inner.signer_bitmap != metadata.signer_bitmap {
        return Err(V2VerifyError::BitmapMismatch {
            reason: "metadata.signer_bitmap differs from certificate-reconstructed bitmap",
        });
    }

    // Duplicate-signer / out-of-range checks are enforced by the inner
    // decoder and the bitmap reconstruction loop already; the BTreeSet check
    // here is defence in depth in case the inner decoder ever stops doing it.
    let mut seen = BTreeSet::new();
    for (idx, byte) in metadata.signer_bitmap.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        if *byte != 1 {
            return Err(V2VerifyError::BitmapMismatch {
                reason: "metadata.signer_bitmap has non-binary byte",
            });
        }
        let index = idx as u32;
        if !seen.insert(index) {
            return Err(V2VerifyError::DuplicateSigner { index });
        }
    }

    Ok(inner)
}

/// Decode a `MinSig` BLS group public key (G2 element) from raw bytes.
fn decode_min_sig_public(bytes: &[u8]) -> Result<<MinSig as Variant>::Public, V2VerifyError> {
    use commonware_codec::FixedSize;
    if bytes.len() != <MinSig as Variant>::Public::SIZE {
        return Err(V2VerifyError::WrongVrfGroupKeyHash {
            expected: B256::ZERO,
            actual: keccak256(bytes),
        });
    }
    <MinSig as Variant>::Public::decode(Bytes::copy_from_slice(bytes))
        .map_err(V2VerifyError::Decode)
}
