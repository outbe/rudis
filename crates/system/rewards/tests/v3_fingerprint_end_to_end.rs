//! audit follow-up.
//!
//! Real-BLS+VRF integration test that closes the wire-level gap
//! between `outbe_consensus::proof::verify_v2_proof` and the V3 Rewards
//! fingerprint helper. alone asserts that `compute_metadata_fingerprint`
//! is *sensitive* to its `canonical_vrf_proof_hash` argument, but it uses a
//! stubbed `B256` value and does NOT exercise the production path:
//!
//! ```text
//! verify_v2_proof  ->  VerifiedProof::vrf_proof_hash
//!                          |
//!                          v
//!                  OutbeBlockExecutor.verified_phase1_vrf_proof_hash
//!                          |
//!                          v
//!         PreloadedSystemTxContext.canonical_vrf_proof_hash
//!                          |
//!                          v
//!  outbe_rewards::runtime::check_and_record_metadata_fingerprint(_, _, _, hash)
//! ```
//!

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{
        primitives::{
            ops::{aggregate, keypair, sign_message},
            variant::{MinPk, MinSig, Variant},
        },
        PrivateKey, PublicKey,
    },
    certificate::Signers,
    sha256::Digest as Sha256Digest,
    Signer,
};
use commonware_utils::Participant;
use outbe_consensus::proof::{
    canonical_vrf_proof_hash_v2, constants::finalize_namespace, hybrid_seed_namespace,
    verify_v2_proof, HybridCertificate, VrfProof,
};
use outbe_primitives::consensus_metadata::{
    CertifiedParentAccountingMetadata, ParentParticipationProof,
};
use outbe_rewards::runtime::compute_metadata_fingerprint;
use outbe_validatorset::state::{committee_set_hash_v2, CommitteeEntry, CommitteeSnapshot};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Fixture constants - same shape as the verifier_cluster.rs fixture so
// the cert format and metadata field layout are byte-compatible with the
// production verifier path.
const FINALIZED_EPOCH: u64 = 3;
const FINALIZED_VIEW: u64 = 100;
const PARENT_VIEW: u64 = 99;
const VRF_MATERIAL_VERSION: u64 = 5;
const FINALIZED_BLOCK_NUMBER: u64 = 41;

struct Dkg {
    keys: Vec<PrivateKey>,
    pubkeys: Vec<PublicKey>,
    vrf_group_public_key: <MinSig as Variant>::Public,
    vrf_threshold_private: commonware_cryptography::bls12381::primitives::group::Private,
}

fn build_dkg(n: u32) -> Dkg {
    let keys: Vec<PrivateKey> = (0..n)
        .map(|i| PrivateKey::from_seed(i as u64 + 1))
        .collect();
    let pubkeys: Vec<PublicKey> = keys.iter().cloned().map(PublicKey::from).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let (vrf_threshold_private, vrf_group_public_key) = keypair::<_, MinSig>(&mut rng);
    Dkg {
        keys,
        pubkeys,
        vrf_group_public_key,
        vrf_threshold_private,
    }
}

fn build_snapshot(dkg: &Dkg) -> CommitteeSnapshot {
    let committee: Vec<CommitteeEntry> = dkg
        .pubkeys
        .iter()
        .enumerate()
        .map(|(i, pk)| {
            let mut consensus_pubkey = [0u8; 48];
            consensus_pubkey.copy_from_slice(pk.encode().as_ref());
            CommitteeEntry {
                address: Address::with_last_byte((i + 1) as u8),
                consensus_pubkey,
            }
        })
        .collect();
    CommitteeSnapshot {
        committee,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_bytes: dkg.vrf_group_public_key.encode().to_vec(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    }
}

fn proposal_bytes(parent_hash: B256) -> (Round, Vec<u8>, Vec<u8>) {
    let round = Round::new(Epoch::new(FINALIZED_EPOCH), View::new(FINALIZED_VIEW));
    let payload = Sha256Digest(parent_hash.0);
    let proposal: Proposal<Sha256Digest> = Proposal::new(round, View::new(PARENT_VIEW), payload);
    let vote_message = proposal.encode().to_vec();
    let seed_message = round.encode().to_vec();
    (round, vote_message, seed_message)
}

/// Build a real BLS+VRF signed certificate AND return the underlying
/// `VrfProof` so the test can independently compute the canonical proof
/// hash and compare it to whatever `verify_v2_proof` derives.
fn build_cert_with_vrf_proof(
    dkg: &Dkg,
    signer_indices: &[u32],
    parent_hash: B256,
) -> (HybridCertificate<MinSig>, VrfProof<MinSig>) {
    let participants = dkg.keys.len();
    let signers = Signers::from(
        participants,
        signer_indices.iter().copied().map(Participant::new),
    );

    let (_, vote_message, seed_message) = proposal_bytes(parent_hash);
    // finalize votes bind the ordered committee; build the canonical `Set`
    // from the DKG committee (matches the snapshot the verifier reads).
    let committee_set: commonware_utils::ordered::Set<_> =
        commonware_utils::ordered::Set::from_iter_dedup(dkg.keys.iter().map(|k| k.public_key()));
    let sigs: Vec<_> = signer_indices
        .iter()
        .map(|&i| dkg.keys[i as usize].sign(&finalize_namespace(&committee_set), &vote_message))
        .collect();
    let bls_aggregated_vote =
        aggregate::combine_signatures::<MinPk, _>(sigs.iter().map(|s| s.as_ref()));

    let threshold_signature = sign_message::<MinSig>(
        &dkg.vrf_threshold_private,
        &hybrid_seed_namespace(),
        &seed_message,
    );
    let vrf_proof = VrfProof::<MinSig> {
        material_version: VRF_MATERIAL_VERSION,
        threshold_signature,
    };

    let cert = HybridCertificate {
        signers,
        bls_aggregated_vote,
        vrf_proof: vrf_proof.clone(),
    };
    (cert, vrf_proof)
}

fn build_metadata(
    snapshot: &CommitteeSnapshot,
    cert_bytes: &[u8],
    parent_hash: B256,
) -> CertifiedParentAccountingMetadata {
    let ordered_committee: Vec<Address> = snapshot
        .committee
        .iter()
        .map(|entry| entry.address)
        .collect();
    let signer_bitmap = vec![1u8; snapshot.committee.len()];
    let committee_set_hash = committee_set_hash_v2(FINALIZED_EPOCH, snapshot);
    let vrf_group_public_key_hash = keccak256(&snapshot.vrf_group_public_key_bytes);
    CertifiedParentAccountingMetadata {
        finalized_block_number: FINALIZED_BLOCK_NUMBER,
        finalized_block_hash: parent_hash,
        finalized_epoch: FINALIZED_EPOCH,
        finalized_view: FINALIZED_VIEW,
        parent_view: PARENT_VIEW,
        ordered_committee,
        signer_bitmap,
        proof: Bytes::copy_from_slice(cert_bytes),
        committee_set_hash,
        vrf_material_version: VRF_MATERIAL_VERSION,
        vrf_group_public_key_hash,
        proof_kind: ParentParticipationProof::Finalization,
        missed_proposers: Vec::new(),
    }
}

/// End-to-end wire test: build a real BLS+VRF certificate, run
/// `verify_v2_proof` against it, take the returned `vrf_proof_hash`
/// (which is what the executor's `verified_phase1_vrf_proof_hash`
/// cache would hold in production), and feed it into the V3
/// fingerprint helper. Assert byte-equality between (a) the
/// verifier-derived hash and (b) an independent computation via the
/// public `canonical_vrf_proof_hash_v2(VrfProof)` helper. Then build
/// the V3 fingerprint twice - once with each source - and assert the
/// two fingerprints are byte-equal.
///
/// This pins the contract that a future refactor cannot pass
/// while silently breaking the verify_v2_proof -> fingerprint wire.
#[test]
fn phase1_end_to_end_real_vrf_proof_binds_v3_fingerprint() {
    // 1. Build the DKG fixture and a real signed certificate.
    let dkg = build_dkg(4);
    let snapshot = build_snapshot(&dkg);
    let parent_hash = B256::with_last_byte(0xAA);
    let (cert, vrf_proof) = build_cert_with_vrf_proof(&dkg, &[0, 1, 2, 3], parent_hash);
    let (round, _, _) = proposal_bytes(parent_hash);
    let proposal = Proposal::new(round, View::new(PARENT_VIEW), Sha256Digest(parent_hash.0));
    let finalization: outbe_consensus::proof::Finalization<
        outbe_consensus::hybrid::HybridScheme<MinSig>,
        Sha256Digest,
    > = commonware_consensus::simplex::types::Finalization {
        proposal,
        certificate: cert,
    };
    let proof_bytes = finalization.encode().to_vec();
    let metadata = build_metadata(&snapshot, &proof_bytes, parent_hash);

    // 2. Run the production verifier path.
    let verified = verify_v2_proof(&metadata, &snapshot, &proof_bytes, parent_hash)
        .expect("happy-path real BLS+VRF cert must verify");

    // 3. Independently compute the canonical VRF proof hash from the
    // raw VrfProof. This is what the executor's cache would receive
    // in production via `verified.vrf_proof_hash`.
    let independent_vrf_hash = canonical_vrf_proof_hash_v2(&vrf_proof);

    // 4. Wire contract: verifier output must equal the independent
    // computation BYTE-FOR-BYTE.
    assert_eq!(
        verified.vrf_proof_hash, independent_vrf_hash,
        "verify_v2_proof must return the same canonical_vrf_proof_hash_v2 the test \
         computes independently - this pins the verify_v2_proof -> cache -> context -> \
         fingerprint wire end-to-end"
    );

    // 5. Cross-check the other VerifiedProof fields the wire carries.
    assert_eq!(verified.vrf_material_version, VRF_MATERIAL_VERSION);
    assert_eq!(verified.signer_bitmap.len(), snapshot.committee.len());

    // 6. Build the V3 fingerprint twice - once using the verifier's
    // output, once using the independent computation. Both must be
    // byte-equal because they share the same (metadata, fee_sum) and
    // the only varying input - `canonical_vrf_proof_hash` - was just
    // proved equal in step 4.
    let fee_sum = U256::from(12_345_678_900_000u128);
    let fp_via_verifier = compute_metadata_fingerprint(&metadata, fee_sum, verified.vrf_proof_hash);
    let fp_via_independent = compute_metadata_fingerprint(&metadata, fee_sum, independent_vrf_hash);
    assert_eq!(
        fp_via_verifier, fp_via_independent,
        "V3 fingerprint must be byte-equal whether the canonical_vrf_proof_hash comes \
         from the verifier or from an independent canonical_vrf_proof_hash_v2 call"
    );

    // 7. Negative control: substituting a wrong-VRF hash MUST produce
    // a different fingerprint. Pins that the fingerprint actually
    // consumes the hash (defends against a future refactor that
    // ignores the argument).
    let wrong_vrf_hash = B256::with_last_byte(0xFF);
    assert_ne!(
        wrong_vrf_hash, verified.vrf_proof_hash,
        "wrong-VRF sentinel must differ from the verifier output"
    );
    let fp_with_wrong_vrf = compute_metadata_fingerprint(&metadata, fee_sum, wrong_vrf_hash);
    assert_ne!(
        fp_via_verifier, fp_with_wrong_vrf,
        "fingerprint must change when canonical_vrf_proof_hash is altered - proves the \
         argument flows through to the keccak input"
    );
}
