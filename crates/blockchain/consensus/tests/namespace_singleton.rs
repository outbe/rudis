//! Guards that the process-wide Simplex `Namespace` singleton in
//! `outbe_consensus::config::simplex_namespace()` keeps its chain-bound base and
//! that its SEED sub-namespace matches the verifier-side accessor.
//!
//! Both sides derive from the chain-bound base `outbe_app_namespace()`
//! (`b"outbe" || chain_id_be`,). Since the INDIVIDUAL vote
//! sub-namespaces (notarize/nullify/finalize) are committee-bound and supplied
//! per-scheme (`HybridScheme` overrides them via
//! `crate::proof::constants::*_namespace(participants)`), so the singleton no
//! longer drives live votes - only its chain-only SEED is shared with `elect`.

use commonware_cryptography::bls12381;
use commonware_cryptography::Signer as _;
use commonware_utils::ordered::Set;
use outbe_consensus::config::{outbe_app_namespace, simplex_namespace};
use outbe_consensus::proof::{finalize_namespace, hybrid_seed_namespace, notarize_namespace};

fn committee() -> Set<bls12381::PublicKey> {
    Set::from_iter_dedup(
        (1u64..=3).map(|s| bls12381::PublicKey::from(bls12381::PrivateKey::from_seed(s))),
    )
}

#[test]
fn simplex_namespace_base_is_chain_bound() {
    // b"outbe" (5) || chain_id_be (8) - no longer the bare, chain-independent
    // b"outbe".
    let base = outbe_app_namespace();
    assert!(base.starts_with(b"outbe"));
    assert_eq!(base.len(), 13);
    assert_ne!(base.as_slice(), b"outbe");
}

#[test]
fn simplex_namespace_returns_same_singleton_pointer() {
    let a = simplex_namespace();
    let b = simplex_namespace();
    assert!(
        std::ptr::eq(a, b),
        "simplex_namespace must return the same OnceLock instance",
    );
}

#[test]
fn singleton_seed_matches_accessor_and_votes_are_committee_bound() {
    let ns = simplex_namespace();
    // The seed namespace is chain-only and shared by the signer's `elect` path
    // and the verifier - it MUST match, byte-for-byte.
    assert_eq!(
        ns.seed.as_slice(),
        hybrid_seed_namespace().as_slice(),
        "signer seed namespace diverged from verifier accessor",
    );

    // the live vote namespaces are committee-bound and supplied per-scheme,
    // so they differ from the singleton's chain-only vote fields. (Per-scheme
    // signer<->verifier vote parity is exercised by the m28 fingerprint test and
    // the 4-node localnet lockstep.)
    let committee = committee();
    assert_ne!(
        ns.notarize.as_slice(),
        notarize_namespace(&committee).as_slice(),
        "live notarize namespace must be committee-bound, not the chain-only singleton",
    );
    assert_ne!(
        ns.finalize.as_slice(),
        finalize_namespace(&committee).as_slice(),
        "live finalize namespace must be committee-bound, not the chain-only singleton",
    );
}
