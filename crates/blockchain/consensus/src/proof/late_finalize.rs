//! BLS-only late-finalize-credit proof verifier.
//!
//! A late-finalize credit aggregates the individual MinPk finalize signatures a
//! proposer gathered for a recently-finalized block within the `K`-block
//! inclusion window. Unlike the full Hybrid certificate verifier
//! ([`crate::proof::verifier`]) this:
//!
//! - **drops the 2f+1 quorum floor** - a late credit is, by construction, the
//!   sub-quorum tail of validators who signed after the eager quorum froze;
//! - **drops the mandatory threshold-VRF proof** - late credits carry no VRF;
//! - **drops the exact-parent Rule 2** - the target is any in-window finalized
//!   block, not necessarily the header's parent.
//!
//! The finalized-block-hash binding is enforced by the signature itself: the
//! verified message is rebuilt as `Proposal{round, parent, payload = fb_hash}`,
//! and the aggregate verifies only if every signer actually signed exactly that
//! proposal under the committee-bound finalize namespace
//! (`finalize_namespace(committee)`, derived from the snapshot - never from the
//! wire). The committee is pinned by `committee_set_hash`.
//!
//! The whole aggregate is verified FIRST; state-level dedup of already-credited
//! signers happens downstream, after this returns the verified
//! signer set - filtering bits before verification would break the recomputed
//! aggregate public key.

use crate::digest::Digest as OutbeDigest;
use crate::proof::committee::{committee_set_hash_v2, CommitteeSnapshot};
use crate::proof::committee_keys::{committee_ordered_set, decode_committee_participants};
use crate::proof::constants::finalize_namespace;
use crate::proof::error::V2VerifyError;
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::simplex::types::Proposal;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381::primitives::{
    ops::aggregate,
    variant::{MinPk, Variant},
};
use outbe_primitives::reshare_artifact::PerBlockCredit;

/// Verify one late-finalize credit's BLS aggregate against the epoch committee
/// snapshot. On success returns the verified signer indices (into
/// `snapshot.committee`, i.e. the ordered committee), so the caller can map them
/// to addresses and record credits.
pub fn verify_late_finalize_proof(
    snapshot: &CommitteeSnapshot,
    credit: &PerBlockCredit,
) -> Result<Vec<usize>, V2VerifyError> {
    // Pin the proof to the committee it was produced for.
    let expected_set_hash = committee_set_hash_v2(credit.epoch, snapshot);
    if expected_set_hash != credit.committee_set_hash {
        return Err(V2VerifyError::CommitteeSetHashMismatch {
            expected: expected_set_hash,
            actual: credit.committee_set_hash,
        });
    }

    let participants = decode_committee_participants(snapshot)?;
    let n = participants.len();

    // Dense bit-packed bitmap (1 bit per committee member); length = ceil(N/8).
    let expected_bitmap_len = n.div_ceil(8);
    if credit.signer_bitmap.len() != expected_bitmap_len {
        return Err(V2VerifyError::BitmapMismatch {
            reason: "late-finalize bitmap length does not match committee size",
        });
    }

    // Collect signer pubkeys + indices from the set bits. A bit-packed bitmap
    // is inherently duplicate-free, so no per-signer dedup is needed here.
    let mut signer_pubkeys: Vec<&<MinPk as Variant>::Public> = Vec::new();
    let mut signer_indices: Vec<usize> = Vec::new();
    for (byte_idx, byte) in credit.signer_bitmap.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        for bit in 0..8usize {
            if byte & (1u8 << bit) != 0 {
                let idx = byte_idx * 8 + bit;
                if idx >= n {
                    return Err(V2VerifyError::SignerIndexOutOfRange {
                        index: idx as u32,
                        committee_size: n,
                    });
                }
                signer_pubkeys.push(participants[idx].as_ref());
                signer_indices.push(idx);
            }
        }
    }
    if signer_pubkeys.is_empty() {
        return Err(V2VerifyError::BitmapMismatch {
            reason: "empty late-finalize signer bitmap",
        });
    }

    // Rebuild the canonical finalize message. payload == fb_hash by construction;
    // the aggregate only verifies if the signers signed this exact proposal.
    let proposal = Proposal::new(
        Round::new(Epoch::new(credit.epoch), View::new(credit.view)),
        View::new(credit.parent_view),
        OutbeDigest(credit.fb_hash),
    );
    let message = proposal.encode().to_vec();

    let agg_sig = <aggregate::Signature<MinPk> as DecodeExt<()>>::decode(Bytes::copy_from_slice(
        &credit.aggregate_signature,
    ))
    .map_err(V2VerifyError::Decode)?;

    // the late-finalize aggregate is over finalize votes, so it verifies under
    // the committee-bound finalize namespace, built from the same snapshot
    // committee the signers used.
    let committee_set = committee_ordered_set(&participants);
    let aggregate_pk = aggregate::combine_public_keys::<MinPk, _>(signer_pubkeys);
    aggregate::verify_same_message::<MinPk>(
        &aggregate_pk,
        &finalize_namespace(&committee_set),
        &message,
        &agg_sig,
    )
    .map_err(|_| V2VerifyError::BlsAggregateInvalid)?;

    Ok(signer_indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::committee::CommitteeEntry;
    use alloy_primitives::{Address, B256};
    use commonware_cryptography::{bls12381, Signer as _};
    use commonware_math::algebra::Random;

    fn keys(n: usize) -> Vec<bls12381::PrivateKey> {
        (0..n)
            .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
            .collect()
    }

    fn snapshot_for(keys: &[bls12381::PrivateKey]) -> CommitteeSnapshot {
        let committee = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let mut consensus_pubkey = [0u8; 48];
                consensus_pubkey.copy_from_slice(&sk.public_key().encode());
                CommitteeEntry {
                    address: Address::with_last_byte(i as u8 + 1),
                    consensus_pubkey,
                }
            })
            .collect();
        CommitteeSnapshot {
            committee,
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vec![0x11; 96],
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        }
    }

    fn set_bit(bitmap: &mut [u8], idx: usize) {
        bitmap[idx / 8] |= 1u8 << (idx % 8);
    }

    /// Build a valid credit over `signer_idxs` (which may be sub-quorum) for the
    /// given binding. With `corrupt_message`, the signers sign a *different*
    /// proposal so the aggregate must fail to verify.
    #[allow(clippy::too_many_arguments)]
    fn build_credit(
        keys: &[bls12381::PrivateKey],
        snapshot: &CommitteeSnapshot,
        signer_idxs: &[usize],
        fb_hash: B256,
        epoch: u64,
        view: u64,
        parent_view: u64,
        corrupt_message: bool,
    ) -> PerBlockCredit {
        let signed_hash = if corrupt_message {
            B256::repeat_byte(0xEE)
        } else {
            fb_hash
        };
        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent_view),
            OutbeDigest(signed_hash),
        );
        let message = proposal.encode().to_vec();
        // sign under the committee-bound finalize namespace, using the full
        // committee (the same one the verifier rebuilds from the snapshot).
        let committee_set: commonware_utils::ordered::Set<bls12381::PublicKey> =
            commonware_utils::ordered::Set::from_iter_dedup(
                keys.iter().map(|k| bls12381::PublicKey::from(k.clone())),
            );
        // Individual MinPk finalize votes, exactly as a validator produces them
        // (repo pattern: `key.sign(namespace, msg)` then `combine_signatures`).
        let sigs: Vec<bls12381::Signature> = signer_idxs
            .iter()
            .map(|&i| keys[i].sign(&finalize_namespace(&committee_set), &message))
            .collect();
        let agg = aggregate::combine_signatures::<MinPk, _>(sigs.iter().map(|s| s.as_ref()));
        let mut aggregate_signature = [0u8; 96];
        aggregate_signature.copy_from_slice(&agg.encode());

        let mut signer_bitmap = vec![0u8; snapshot.committee.len().div_ceil(8)];
        for &i in signer_idxs {
            set_bit(&mut signer_bitmap, i);
        }

        PerBlockCredit {
            fb_number: 10,
            fb_hash,
            epoch,
            view,
            parent_view,
            committee_set_hash: committee_set_hash_v2(epoch, snapshot),
            signer_bitmap,
            aggregate_signature,
        }
    }

    /// A sub-quorum (2 of 4) aggregate with no VRF proof verifies - proving the
    /// quorum floor and threshold-VRF requirement are dropped.
    #[test]
    fn bls_only_verifier_no_quorum_no_vrf() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x5a);
        let credit = build_credit(&keys, &snapshot, &[0, 2], fb, 3, 9, 8, false);
        let verified = verify_late_finalize_proof(&snapshot, &credit).expect("sub-quorum verifies");
        assert_eq!(verified, vec![0, 2]);
    }

    #[test]
    fn full_attendance_verifies_and_returns_all_indices() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x01);
        let credit = build_credit(&keys, &snapshot, &[0, 1, 2, 3], fb, 1, 2, 1, false);
        assert_eq!(
            verify_late_finalize_proof(&snapshot, &credit).unwrap(),
            vec![0, 1, 2, 3]
        );
    }

    /// the aggregate is verified over the FULL signer bitmap and
    /// the verifier returns every set-bit index - state-level dedup of
    /// already-credited signers happens downstream (in `record_late_credit`),
    /// AFTER this returns. Filtering bits before verify would break the
    /// recomputed aggregate public key, so verify must precede dedup.
    #[test]
    fn verify_precedes_dedup() {
        let keys = keys(6);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x11);
        // Sparse sub-quorum subset: the verifier must return all three indices,
        // unfiltered, in ascending order.
        let credit = build_credit(&keys, &snapshot, &[1, 3, 5], fb, 2, 5, 4, false);
        let verified =
            verify_late_finalize_proof(&snapshot, &credit).expect("sparse subset verifies");
        assert_eq!(
            verified,
            vec![1, 3, 5],
            "verify returns the full bitmap index set before any dedup"
        );
    }

    #[test]
    fn bad_signature_rejected_as_aggregate_invalid() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x5a);
        // Signers signed a different proposal payload -> aggregate must not verify.
        let credit = build_credit(&keys, &snapshot, &[0, 1, 2], fb, 3, 9, 8, true);
        assert!(matches!(
            verify_late_finalize_proof(&snapshot, &credit),
            Err(V2VerifyError::BlsAggregateInvalid)
        ));
    }

    #[test]
    fn wrong_committee_set_hash_rejected() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x5a);
        let mut credit = build_credit(&keys, &snapshot, &[0, 1], fb, 3, 9, 8, false);
        credit.committee_set_hash = B256::repeat_byte(0xAB);
        assert!(matches!(
            verify_late_finalize_proof(&snapshot, &credit),
            Err(V2VerifyError::CommitteeSetHashMismatch { .. })
        ));
    }

    #[test]
    fn empty_bitmap_rejected() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x5a);
        let mut credit = build_credit(&keys, &snapshot, &[0, 1], fb, 3, 9, 8, false);
        credit.signer_bitmap = vec![0u8; 4usize.div_ceil(8)]; // all zero
        assert!(matches!(
            verify_late_finalize_proof(&snapshot, &credit),
            Err(V2VerifyError::BitmapMismatch { .. })
        ));
    }

    #[test]
    fn bitmap_length_mismatch_rejected() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x5a);
        let mut credit = build_credit(&keys, &snapshot, &[0, 1], fb, 3, 9, 8, false);
        credit.signer_bitmap = vec![0x03, 0x00]; // 2 bytes for a 4-member committee
        assert!(matches!(
            verify_late_finalize_proof(&snapshot, &credit),
            Err(V2VerifyError::BitmapMismatch { .. })
        ));
    }

    #[test]
    fn signer_index_out_of_range_rejected() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let fb = B256::repeat_byte(0x5a);
        let mut credit = build_credit(&keys, &snapshot, &[0], fb, 3, 9, 8, false);
        // Set a bit in the padding region of the single bitmap byte (idx 5 >= N=4).
        credit.signer_bitmap = vec![0b0010_0001]; // bits 0 and 5 set
        assert!(matches!(
            verify_late_finalize_proof(&snapshot, &credit),
            Err(V2VerifyError::SignerIndexOutOfRange { .. })
        ));
    }
}
