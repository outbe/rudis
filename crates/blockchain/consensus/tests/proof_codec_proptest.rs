//! Property-based round-trip for the V2 Hybrid certificate wire codec.
//!
//! Generates random signer bitmaps and mandatory VRF proofs, builds a real
//! BLS aggregate from deterministic seeds, then asserts encode->decode->encode is
//! byte-stable. Catches any non-deterministic encoding (e.g. unordered set
//! iteration) before it can ship.

use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    bls12381::{
        primitives::{
            ops::{aggregate, keypair, sign_message},
            variant::{MinPk, MinSig},
        },
        PrivateKey,
    },
    certificate::Signers,
    Signer,
};
use commonware_utils::Participant;
use outbe_consensus::proof::{HybridCertificate, VrfProof};
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Strategy: 1..=128 participants, between 1 and N signer indices (unique,
/// sorted), plus a deterministic VRF seed.
fn cert_strategy() -> impl Strategy<Value = (usize, Vec<u32>, u64)> {
    (1usize..=128usize, any::<u64>()).prop_flat_map(|(participants, vrf_seed)| {
        (
            Just(participants),
            proptest::collection::btree_set(0u32..participants as u32, 1..=participants)
                .prop_map(|set| set.into_iter().collect::<Vec<_>>()),
            Just(vrf_seed),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn phase1_metadata_roundtrip_proptest((participants, signer_indices, vrf_seed) in cert_strategy()) {
        let signers = Signers::from(
            participants,
            signer_indices.iter().copied().map(Participant::new),
        );

        let mut sigs = Vec::with_capacity(signer_indices.len());
        for &i in &signer_indices {
            let sk = PrivateKey::from_seed(i as u64 + 1);
            sigs.push(sk.sign(b"hybrid_codec_proptest", b"vote"));
        }
        let bls_aggregated_vote =
            aggregate::combine_signatures::<MinPk, _>(sigs.iter().map(|s| s.as_ref()));

        let mut rng = ChaCha20Rng::seed_from_u64(vrf_seed);
        let (private, _public) = keypair::<_, MinSig>(&mut rng);
        let threshold_signature =
            sign_message::<MinSig>(&private, b"OUTBE_VRF_SEED_V2", b"proptest");
        let vrf_proof = VrfProof::<MinSig> {
            material_version: vrf_seed,
            threshold_signature,
        };

        let cert = HybridCertificate::<MinSig> {
            signers,
            bls_aggregated_vote,
            vrf_proof,
        };

        let first = cert.encode();
        let decoded = HybridCertificate::<MinSig>::decode_cfg(first.clone(), &participants)
            .expect("decode must succeed");
        let second = decoded.encode();
        prop_assert_eq!(first.as_ref(), second.as_ref(), "wire codec is not byte-stable");
        prop_assert_eq!(cert, decoded, "decoded value differs from original");
    }
}
