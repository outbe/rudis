//! - byte-pinned VRF seed-message and namespace test vectors.
//!
//! The V2 verifier computes the seed message as `Round(epoch, view).encode()`
//! via `commonware_codec::Encode`. A future commonware bump could silently
//! change this encoding and produce subtly different VRF inputs across the
//! network - a hard consensus split. These tests pin the byte layout against
//! known `(epoch, view)` pairs so any drift fails the build.
//!
//! Tests:
//! - `round_encode_test_vector_for_vrf_seed_message`
//! - `outbe_hybrid_seed_namespace_v2_byte_pin`
//! - `outbe_notarize_finalize_namespace_byte_pins`

use commonware_codec::Encode;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381;
use commonware_cryptography::Signer as _;
use commonware_utils::ordered::Set;
use outbe_consensus::proof::{
    constants::{finalize_namespace, notarize_namespace},
    hybrid_seed_namespace, participant_set_commitment,
};

#[test]
fn round_encode_test_vector_for_vrf_seed_message() {
    // (epoch=0, view=1) - genesis-adjacent round used by block 1 production.
    // Round encodes via commonware varint: single-byte values < 128 emit one
    // byte directly. So Round(0, 1) -> [0x00, 0x01].
    let r0 = Round::new(Epoch::new(0), View::new(1));
    let bytes0 = r0.encode().to_vec();
    assert_eq!(
        bytes0,
        vec![0x00, 0x01],
        "Round(0, 1).encode() byte-pin: varint epoch=0 || varint view=1"
    );

    // (epoch=12, view=61) - view-61 reproduction round halt.
    // Both fit single-byte varints: 12 = 0x0c, 61 = 0x3d.
    let r1 = Round::new(Epoch::new(12), View::new(61));
    let bytes1 = r1.encode().to_vec();
    assert_eq!(
        bytes1,
        vec![0x0c, 0x3d],
        "Round(12, 61).encode() byte-pin: varint epoch=12 || varint view=61"
    );

    // Determinism across N encode invocations.
    for _ in 0..32 {
        assert_eq!(
            Round::new(Epoch::new(12), View::new(61)).encode().to_vec(),
            bytes1
        );
    }
}

#[test]
fn outbe_hybrid_seed_namespace_v2_byte_pin() {
    // Chain-bound V2 seed namespace: `outbe_app_namespace()
    // || b"_SEED"`, where `outbe_app_namespace() == b"outbe" || chain_id_be`.
    // The signer side (`simplex_namespace().seed`) and the verifier hot path
    // read the identical accessor, so they cannot drift; any change here is a
    // hard-fork-equivalent change to certificate verification.
    let mut expected = outbe_consensus::proof::outbe_app_namespace();
    expected.extend_from_slice(b"_SEED");
    assert_eq!(hybrid_seed_namespace(), expected);
    // 5 (b"outbe") + 8 (chain id) + 5 (b"_SEED").
    assert_eq!(hybrid_seed_namespace().len(), 18);
    assert_ne!(hybrid_seed_namespace().as_slice(), b"outbe_SEED");
}

#[test]
fn outbe_notarize_finalize_namespace_byte_pins() {
    // Committee-bound notarize/finalize sub-namespaces:
    // `outbe_app_namespace() || suffix || participant_set_commitment(committee)`.
    // No longer the chain-independent `b"outbe_NOTARIZE"` a cross-chain replay
    // would match, nor the chain-only form a wrong-committee vote would match.
    let committee: Set<bls12381::PublicKey> = Set::from_iter_dedup(
        (1u64..=3).map(|s| bls12381::PublicKey::from(bls12381::PrivateKey::from_seed(s))),
    );
    let commitment = participant_set_commitment(&committee);
    let with = |suffix: &[u8]| {
        let mut v = outbe_consensus::proof::outbe_app_namespace();
        v.extend_from_slice(suffix);
        v.extend_from_slice(&commitment);
        v
    };
    assert_eq!(notarize_namespace(&committee), with(b"_NOTARIZE"));
    assert_eq!(finalize_namespace(&committee), with(b"_FINALIZE"));
    // 5 + 8 + 9 (b"_NOTARIZE") + 32 (commitment) = 54; finalize is the same.
    assert_eq!(notarize_namespace(&committee).len(), 54);
    assert_eq!(finalize_namespace(&committee).len(), 54);
    assert_ne!(notarize_namespace(&committee).as_slice(), b"outbe_NOTARIZE");
}
