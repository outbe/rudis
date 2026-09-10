//! Verifier-side committee-key helpers shared by the V2 verifier
//! ([`crate::proof::verifier`]) and the late-finalize verifier
//! ([`crate::proof::late_finalize`]).
//!
//! Deliberately kept OUT of [`crate::proof::committee`]: that module is pure
//! committee data, reused by the EVM executor and full-node import paths. These
//! helpers decode cryptographic keys and surface [`V2VerifyError`] - proof
//! *verification* concerns - so they live on the verifier side of the `proof/`
//! seam, not in the pure-data module.

use bytes::Bytes;
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381;
use commonware_utils::ordered::Set;

use crate::proof::committee::CommitteeSnapshot;
use crate::proof::error::V2VerifyError;

/// Decode the snapshot's committee into typed MinPk consensus public keys, in
/// committee (signer-bitmap) order.
///
/// `CommitteeEntry` stores each key as a fixed-size 48-byte array; this is the
/// single decode recipe shared by the V2 verifier and the late-finalize
/// verifier, so a Commonware MinPk encode-size drift surfaces in exactly one
/// place.
pub(crate) fn decode_committee_participants(
    snapshot: &CommitteeSnapshot,
) -> Result<Vec<bls12381::PublicKey>, V2VerifyError> {
    snapshot
        .committee
        .iter()
        .map(|entry| {
            <bls12381::PublicKey as DecodeExt<()>>::decode(Bytes::copy_from_slice(
                &entry.consensus_pubkey,
            ))
            .map_err(V2VerifyError::Decode)
        })
        .collect()
}

/// Build the canonical deduped `ordered::Set` from committee participants in the
/// same sorted/deduped order the signer used, so the vote/seed namespace bytes
/// derived from it equal what the signer bound.
pub(crate) fn committee_ordered_set(
    participants: &[bls12381::PublicKey],
) -> Set<bls12381::PublicKey> {
    Set::from_iter_dedup(participants.iter().cloned())
}
