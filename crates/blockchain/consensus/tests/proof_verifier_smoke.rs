//! Smoke tests for the V2 self-contained verifier shell.
//!
//! These tests exercise the rules owns:
//! decode + structural + quorum + BLS aggregate + mandatory threshold-VRF.
//! Binding and missed_proposers rules are covered.

use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::{
        primitives::{
            ops::{aggregate, keypair, sign_message},
            variant::{MinPk, MinSig, Variant},
        },
        PrivateKey, PublicKey,
    },
    certificate::Signers,
    Signer,
};
use commonware_utils::{Faults as _, N3f1, Participant};
use outbe_consensus::proof::{
    verify_v2_proof_low_level, CommitteeSnapshotView, HybridCertificate, V2VerifyError,
    VoteBinding, VoteSubject, VrfProof,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const VOTE_NAMESPACE: &[u8] = b"outbe_FINALIZE";
const VOTE_MESSAGE: &[u8] = b"finalize-proposal-message";
const SEED_MESSAGE: &[u8] = b"seed-round-1";

struct Committee {
    keys: Vec<PrivateKey>,
    pubkeys: Vec<PublicKey>,
    vrf_group_public_key: <MinSig as Variant>::Public,
    vrf_threshold_private: commonware_cryptography::bls12381::primitives::group::Private,
}

fn build_committee(n: u32) -> Committee {
    let keys: Vec<PrivateKey> = (0..n)
        .map(|i| PrivateKey::from_seed(i as u64 + 1))
        .collect();
    let pubkeys: Vec<PublicKey> = keys.iter().cloned().map(PublicKey::from).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let (vrf_threshold_private, vrf_group_public_key) = keypair::<_, MinSig>(&mut rng);
    Committee {
        keys,
        pubkeys,
        vrf_group_public_key,
        vrf_threshold_private,
    }
}

fn build_certificate(committee: &Committee, signer_indices: &[u32]) -> HybridCertificate<MinSig> {
    let participants = committee.keys.len();
    let signers = Signers::from(
        participants,
        signer_indices.iter().copied().map(Participant::new),
    );

    let sigs: Vec<_> = signer_indices
        .iter()
        .map(|&i| committee.keys[i as usize].sign(VOTE_NAMESPACE, VOTE_MESSAGE))
        .collect();
    let bls_aggregated_vote =
        aggregate::combine_signatures::<MinPk, _>(sigs.iter().map(|s| s.as_ref()));

    let threshold_signature = sign_message::<MinSig>(
        &committee.vrf_threshold_private,
        &outbe_consensus::proof::hybrid_seed_namespace(),
        SEED_MESSAGE,
    );
    let vrf_proof = VrfProof::<MinSig> {
        material_version: 5,
        threshold_signature,
    };

    HybridCertificate {
        signers,
        bls_aggregated_vote,
        vrf_proof,
    }
}

fn snapshot<'a>(committee: &'a Committee) -> CommitteeSnapshotView<'a> {
    CommitteeSnapshotView {
        participants: committee.pubkeys.as_slice(),
        vrf_group_public_key: committee.vrf_group_public_key,
        vrf_material_version: 5,
    }
}

fn binding<'a>() -> VoteBinding<'a> {
    VoteBinding {
        subject: VoteSubject::Finalize,
        namespace: VOTE_NAMESPACE,
        message: VOTE_MESSAGE,
        seed_message: SEED_MESSAGE,
    }
}

#[test]
fn verify_v2_proof_accepts_valid_quorum_certificate() {
    let committee = build_committee(4);
    let cert = build_certificate(&committee, &[0, 1, 2, 3]);
    let bytes = cert.encode();
    let verified = verify_v2_proof_low_level(&snapshot(&committee), &binding(), bytes.as_ref())
        .expect("valid quorum certificate must verify");
    assert_eq!(verified.signer_bitmap, vec![1, 1, 1, 1]);
    assert_eq!(verified.vrf_material_version, 5);
}

#[test]
fn verify_v2_proof_rejects_below_quorum() {
    // 4 participants, 2 signers -> N3f1 quorum is 3, so this rejects.
    let committee = build_committee(4);
    let cert = build_certificate(&committee, &[0, 1]);
    let bytes = cert.encode();
    let err = verify_v2_proof_low_level(&snapshot(&committee), &binding(), bytes.as_ref())
        .expect_err("below quorum must reject");
    match err {
        V2VerifyError::BelowQuorum {
            signers: 2,
            quorum: 3,
        } => {}
        other => panic!("expected BelowQuorum {{2,3}}, got {other:?}"),
    }
}

#[test]
fn verify_v2_proof_rejects_truncated_mandatory_vrf() {
    let committee = build_committee(4);
    let cert = build_certificate(&committee, &[0, 1, 2, 3]);
    let mut bytes = cert.encode().to_vec();
    bytes.truncate(bytes.len() - 56);
    let err = verify_v2_proof_low_level(&snapshot(&committee), &binding(), bytes.as_ref())
        .expect_err("truncated mandatory VRF must fail certificate decoding");
    assert!(matches!(err, V2VerifyError::Decode(_)), "{err:?}");
}

#[test]
fn verify_v2_proof_rejects_wrong_vote_message() {
    let committee = build_committee(4);
    let cert = build_certificate(&committee, &[0, 1, 2, 3]);
    let bytes = cert.encode();
    let mut bad = binding();
    bad.message = b"tampered-finalize-message";
    let err = verify_v2_proof_low_level(&snapshot(&committee), &bad, bytes.as_ref())
        .expect_err("wrong vote message must reject BLS aggregate");
    assert!(matches!(err, V2VerifyError::BlsAggregateInvalid), "{err:?}");
}

#[test]
fn verify_v2_proof_rejects_wrong_seed_message() {
    let committee = build_committee(4);
    let cert = build_certificate(&committee, &[0, 1, 2, 3]);
    let bytes = cert.encode();
    let mut bad = binding();
    bad.seed_message = b"tampered-seed";
    let err = verify_v2_proof_low_level(&snapshot(&committee), &bad, bytes.as_ref())
        .expect_err("wrong seed message must reject threshold VRF");
    assert!(matches!(err, V2VerifyError::InvalidVrfSignature), "{err:?}");
}

#[test]
fn quorum_constant_matches_n3f1() {
    // The exported helper is the single source used by both consensus proof
    // verification and OCOMP attempt construction.
    // commonware_utils::N3f1::quorum for every committee size we test.
    for n in [1usize, 2, 3, 4, 5, 6, 7, 10, 16, 64, 128] {
        let expected = N3f1::quorum(n as u32) as usize;
        let derived = outbe_consensus::proof::simplex_n3f1_quorum(n);
        assert_eq!(derived, expected, "N3f1 quorum mismatch at n={n}");
    }
}
