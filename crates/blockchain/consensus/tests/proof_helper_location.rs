//! Asserts the canonical fingerprint helpers live in `outbe-consensus-proof`
//! and not in `outbe-consensus`. If a future refactor moves them back, the
//! cycle they unblocked (EVM<->consensus) returns silently - this test catches
//! that regression at compile time.
//!
//! We do not depend on `outbe-consensus` here on purpose: `outbe-consensus-proof`
//! is the lowest level of the dep tree. The proof of location is therefore the
//! resolvable `use` itself plus a function-pointer assertion.

use alloy_primitives::B256;
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use outbe_consensus::proof::{canonical_vrf_proof_hash_v2, VrfProof};

#[test]
fn vrf_proof_canonical_hash_helper_lives_in_outbe_consensus_proof() {
    // The `use` above resolves only when the symbol is exported from the
    // `outbe-consensus-proof` crate root. The function-pointer assignment
    // additionally locks the signature.
    let _: fn(&VrfProof<MinSig>) -> B256 = canonical_vrf_proof_hash_v2::<MinSig>;
}
