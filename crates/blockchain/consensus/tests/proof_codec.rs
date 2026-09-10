//! Encode->decode->encode round-trip for `HybridCertificate` and `VrfProof`.
//!
//! Asserts the wire codec is byte-stable: re-encoding a decoded certificate
//! produces the same bytes. This is the determinism invariant that block hash
//! computation and marshal-archive replay both depend on.

use commonware_codec::{Decode, Encode, EncodeSize, FixedSize};
use commonware_cryptography::{
    bls12381::{
        primitives::{
            ops::{aggregate, keypair, sign_message},
            variant::{MinPk, MinSig, Variant},
        },
        PrivateKey,
    },
    certificate::Signers,
    Signer,
};
use commonware_utils::Participant;
use outbe_consensus::proof::{HybridCertificate, VrfProof};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Build a non-trivial `HybridCertificate<MinSig>` from real BLS keys so the
/// codec exercises actual group elements (not the point at infinity).
fn sample_certificate(participants: usize, signer_indices: &[u32]) -> HybridCertificate<MinSig> {
    assert!(participants >= signer_indices.len());
    let signers_bitmap = Signers::from(
        participants,
        signer_indices.iter().copied().map(Participant::new),
    );

    // Aggregate a real BLS MinPk signature so the encoder sees a valid G1 point.
    let mut signatures = Vec::with_capacity(signer_indices.len().max(1));
    for &i in signer_indices {
        let sk = PrivateKey::from_seed(i as u64 + 1);
        signatures.push(sk.sign(b"hybrid_certificate_codec_test", b"vote"));
    }
    if signatures.is_empty() {
        // Fall back to a single contributor so the aggregate is non-zero.
        let sk = PrivateKey::from_seed(99);
        signatures.push(sk.sign(b"hybrid_certificate_codec_test", b"vote"));
    }
    let bls_aggregated_vote =
        aggregate::combine_signatures::<MinPk, _>(signatures.iter().map(|s| s.as_ref()));

    // Real threshold VRF signature via a one-shot MinSig key.
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (private, _public) = keypair::<_, MinSig>(&mut rng);
    let threshold_signature =
        sign_message::<MinSig>(&private, b"OUTBE_VRF_SEED_V2", b"seed-round-1");
    let vrf_proof = VrfProof::<MinSig> {
        material_version: 42,
        threshold_signature,
    };

    HybridCertificate {
        signers: signers_bitmap,
        bls_aggregated_vote,
        vrf_proof,
    }
}

#[test]
fn phase1_metadata_roundtrip_encode_decode_encode_bit_equal() {
    for (n, signers) in [
        (3usize, &[0u32, 1, 2][..]),
        (16, &[0, 5, 9, 15]),
        (128, &[0, 31, 63, 127]),
    ] {
        let cert = sample_certificate(n, signers);
        let first = cert.encode();
        assert_eq!(
            first.len(),
            cert.encode_size(),
            "encode_size disagrees with actual encoded length (n={n})",
        );

        let decoded = HybridCertificate::<MinSig>::decode_cfg(first.clone(), &n)
            .unwrap_or_else(|err| panic!("decode failed (n={n}): {err}"));
        let second = decoded.encode();

        assert_eq!(
            first.as_ref(),
            second.as_ref(),
            "re-encoded bytes differ (n={n})",
        );
        assert_eq!(cert, decoded, "decoded value differs from original (n={n})",);
    }
}

#[test]
fn vrf_proof_roundtrip_encode_decode_encode_bit_equal() {
    for (material_version, seed) in [(0u64, 1u64), (1, 2), (42, 3), (u64::MAX, 4)] {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let (private, _public) = keypair::<_, MinSig>(&mut rng);
        let threshold_signature =
            sign_message::<MinSig>(&private, b"OUTBE_VRF_SEED_V2", b"seed-round-1");
        let proof = VrfProof::<MinSig> {
            material_version,
            threshold_signature,
        };
        let first = proof.encode();
        let decoded = VrfProof::<MinSig>::decode_cfg(first.clone(), &())
            .expect("VrfProof decode must succeed");
        let second = decoded.encode();
        assert_eq!(first.as_ref(), second.as_ref());
        assert_eq!(proof, decoded);
    }
}

#[test]
fn certificate_wire_has_no_optional_vrf_discriminator() {
    let cert = sample_certificate(4, &[0, 1, 2]);
    let proof = &cert.vrf_proof;
    assert_eq!(
        cert.encode().len(),
        cert.signers.encode_size() + <MinPk as Variant>::Signature::SIZE + proof.encode_size(),
        "clean-genesis certificate wire must encode the mandatory VRF proof directly",
    );
}

#[test]
fn empty_signers_decode_rejected() {
    // Build an empty-signers certificate by manually encoding a zero-count
    // signers bitmap of size 8 followed by zero bytes; the decoder rejects this.
    let zero_signers = Signers::from(8, std::iter::empty::<Participant>());
    let mut cert = sample_certificate(8, &[0, 1]);
    cert.signers = zero_signers;
    let bytes = cert.encode();

    let err = HybridCertificate::<MinSig>::decode_cfg(bytes, &8usize)
        .expect_err("empty signer bitmap must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("certificate contains no signers"),
        "unexpected error: {msg}",
    );
}
