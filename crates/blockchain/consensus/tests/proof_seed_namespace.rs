//! Pin the chain-bound V2 sub-namespace structure and the
//! committee binding of the individual vote namespaces. Each seed
//! sub-namespace is `outbe_app_namespace() || suffix`; each vote sub-namespace is
//! `outbe_app_namespace() || suffix || participant_set_commitment(committee)`,
//! where `outbe_app_namespace() == b"outbe" || chain_id_be`, so every signed
//! consensus message binds the chain and every vote additionally binds the
//! ordered committee. Drift here is a hard-fork-equivalent break of consensus
//! verification. The verifier (this crate) and the signer (`HybridScheme`) read
//! the identical accessors, so they cannot diverge.

use commonware_cryptography::bls12381;
use commonware_cryptography::Signer as _;
use commonware_utils::ordered::Set;
use outbe_consensus::proof::{
    consensus_chain_id, finalize_namespace, hybrid_seed_namespace, notarize_namespace,
    nullify_namespace, outbe_app_namespace, participant_set_commitment,
};

/// `b"outbe" || chain_id_be` for the (default, in this test binary) chain id.
fn base() -> Vec<u8> {
    let mut v = b"outbe".to_vec();
    v.extend_from_slice(&consensus_chain_id().to_be_bytes());
    v
}

fn committee_from(seeds: &[u64]) -> Set<bls12381::PublicKey> {
    Set::from_iter_dedup(
        seeds
            .iter()
            .map(|s| bls12381::PublicKey::from(bls12381::PrivateKey::from_seed(*s))),
    )
}

#[test]
fn app_namespace_binds_chain_id() {
    let ns = outbe_app_namespace();
    assert_eq!(ns, base());
    // b"outbe" (5) || chain_id_be (8).
    assert_eq!(ns.len(), 13);
    assert!(ns.starts_with(b"outbe"));
    assert_eq!(&ns[5..], &consensus_chain_id().to_be_bytes());
    // The chain binding actually changed the bytes vs the old unbound base.
    assert_ne!(ns.as_slice(), b"outbe");
}

#[test]
fn seed_namespace_is_chain_bound_committee_independent() {
    // The threshold seed is already committee-bound by its group key, so its
    // namespace stays chain-only: `outbe_app_namespace() || b"_SEED"`.
    let with = |suffix: &[u8]| {
        let mut v = base();
        v.extend_from_slice(suffix);
        v
    };
    assert_eq!(hybrid_seed_namespace(), with(b"_SEED"));
    assert_ne!(hybrid_seed_namespace().as_slice(), b"outbe_SEED");
}

#[test]
fn vote_namespaces_bind_chain_and_committee() {
    let committee = committee_from(&[1, 2, 3]);
    let commitment = participant_set_commitment(&committee);
    let with = |suffix: &[u8]| {
        let mut v = base();
        v.extend_from_slice(suffix);
        v.extend_from_slice(&commitment);
        v
    };
    assert_eq!(notarize_namespace(&committee), with(b"_NOTARIZE"));
    assert_eq!(nullify_namespace(&committee), with(b"_NULLIFY"));
    assert_eq!(finalize_namespace(&committee), with(b"_FINALIZE"));

    // Not the chain-independent constants a cross-chain replay would match, and
    // not the chain-only (committee-independent) form either.
    assert_ne!(notarize_namespace(&committee).as_slice(), b"outbe_NOTARIZE");
    let mut chain_only = base();
    chain_only.extend_from_slice(b"_NOTARIZE");
    assert_ne!(notarize_namespace(&committee), chain_only);
}

#[test]
fn vote_namespace_changes_with_committee() {
    // a vote signed for committee A cannot verify under committee B - the
    // namespace differs, so the BLS verification fails on the wrong committee.
    let a = committee_from(&[1, 2, 3]);
    let b = committee_from(&[1, 2, 4]);
    assert_ne!(
        participant_set_commitment(&a),
        participant_set_commitment(&b)
    );
    assert_ne!(notarize_namespace(&a), notarize_namespace(&b));
    assert_ne!(finalize_namespace(&a), finalize_namespace(&b));
    assert_ne!(nullify_namespace(&a), nullify_namespace(&b));
    // Same committee, different input order -> identical (Set canonicalizes).
    let a2 = committee_from(&[3, 1, 2]);
    assert_eq!(notarize_namespace(&a), notarize_namespace(&a2));
}
