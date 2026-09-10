//! V2 canonical fingerprint helpers.
//!
//! Locks the byte layout from. Any drift is a hard-fork-equivalent
//! change to Rewards / Slash / certified-parent proof store key derivation.

use alloy_primitives::{address, b256, B256};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    ops::{keypair, sign_message},
    variant::MinSig,
};
use outbe_consensus::proof::{
    canonical_signer_set_hash, canonical_vrf_proof_hash_v2, committee_set_hash_v2,
    invalid_vrf_evidence_hash_v2, CommitteeEntry, CommitteeSnapshot, VrfProof,
};
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn sample_vrf_proof(seed: u64, version: u64) -> VrfProof<MinSig> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (private, _public) = keypair::<_, MinSig>(&mut rng);
    let threshold_signature =
        sign_message::<MinSig>(&private, b"OUTBE_VRF_SEED_V2", b"fingerprint-test");
    VrfProof {
        material_version: version,
        threshold_signature,
    }
}

#[test]
fn canonical_vrf_proof_hash_v2_equals_keccak_of_encode() {
    for (seed, version) in [(1u64, 0u64), (2, 1), (3, 42), (4, u64::MAX)] {
        let proof = sample_vrf_proof(seed, version);
        let expected = alloy_primitives::keccak256(Encode::encode(&proof));
        let actual = canonical_vrf_proof_hash_v2(&proof);
        assert_eq!(actual, expected, "fingerprint diverges from keccak(encode)");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn canonical_vrf_proof_hash_v2_equals_keccak_of_encode_proptest(
        seed in any::<u64>(),
        version in any::<u64>(),
    ) {
        let proof = sample_vrf_proof(seed, version);
        let expected = alloy_primitives::keccak256(Encode::encode(&proof));
        let actual = canonical_vrf_proof_hash_v2(&proof);
        prop_assert_eq!(actual, expected);
    }
}

#[test]
fn committee_set_hash_v2_test_vector_matches_plan_a4() {
    // hash test vector:
    //   epoch                       = 0
    //   committee                   = [(0x...01, [0x11; 48])]
    //   vrf_material_version        = 0
    //   vrf_group_public_key_bytes  = [0x22; 96]
    //   expected committee_set_hash = 0x61e5cd9eb3bd1a53545d83ce8462b9f8476dbf95312152b69468d2d34c0032d7
    let snapshot = CommitteeSnapshot {
        committee: vec![CommitteeEntry {
            address: address!("0000000000000000000000000000000000000001"),
            consensus_pubkey: [0x11u8; 48],
        }],
        vrf_material_version: 0,
        vrf_group_public_key_bytes: vec![0x22u8; 96],
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };

    let actual = committee_set_hash_v2(0, &snapshot);

    const A4_FROZEN: B256 =
        b256!("61e5cd9eb3bd1a53545d83ce8462b9f8476dbf95312152b69468d2d34c0032d7");
    assert_eq!(
        actual, A4_FROZEN,
        "hash test vector drift - wire-format-breaking change",
    );
}

#[test]
fn canonical_signer_set_hash_is_length_prefixed() {
    // Empty bitmap and a single zero byte must hash differently because of the
    // length prefix.
    let h_empty = canonical_signer_set_hash(&[]);
    let h_zero = canonical_signer_set_hash(&[0]);
    assert_ne!(h_empty, h_zero, "length prefix must disambiguate sizes");

    // Reproducible layout: keccak256( 3u32.to_be_bytes() || [1, 0, 1] ).
    let bitmap = [1u8, 0, 1];
    let mut input = Vec::new();
    input.extend_from_slice(&(bitmap.len() as u32).to_be_bytes());
    input.extend_from_slice(&bitmap);
    let expected = alloy_primitives::keccak256(&input);
    assert_eq!(canonical_signer_set_hash(&bitmap), expected);
}

#[test]
fn invalid_vrf_evidence_hash_v2_is_concat_keccak() {
    let child = b256!("00000000000000000000000000000000000000000000000000000000000000aa");
    let phase1 = b256!("00000000000000000000000000000000000000000000000000000000000000bb");

    let mut input = [0u8; 64];
    input[..32].copy_from_slice(child.as_slice());
    input[32..].copy_from_slice(phase1.as_slice());
    let expected = alloy_primitives::keccak256(input);
    assert_eq!(invalid_vrf_evidence_hash_v2(child, phase1), expected);

    // Non-commutative: swapping the two arguments changes the hash.
    let swapped = invalid_vrf_evidence_hash_v2(phase1, child);
    assert_ne!(swapped, expected, "evidence hash must be order-sensitive");
}

#[test]
fn outbe_consensus_proof_exports_canonical_fingerprint_helpers() {
    // Compile-time proof that the four helpers are reachable at crate root.
    // Their type signatures are tested by being called with concrete inputs.
    let _: fn(u64, &CommitteeSnapshot) -> B256 = committee_set_hash_v2;
    let _: fn(&[u8]) -> B256 = canonical_signer_set_hash;
    let _: fn(B256, B256) -> B256 = invalid_vrf_evidence_hash_v2;
    let _: fn(&VrfProof<MinSig>) -> B256 = canonical_vrf_proof_hash_v2::<MinSig>;
}
