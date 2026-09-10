//! Shared test-only fixtures for the hybrid scheme tests (`hybrid.rs`) and the
//! election tests (`hybrid/election.rs`). Hoisted out of `hybrid.rs`'s inline
//! `mod tests` so both test modules reach the same definitions instead of
//! duplicating them.

use commonware_cryptography::bls12381::{self, primitives::variant::MinSig};
use commonware_cryptography::Signer as _;
use commonware_utils::{ordered::Set, TryCollect as _};

use super::HybridScheme;

pub(crate) const NAMESPACE: &[u8] = b"hybrid-test";

pub(crate) type TestScheme = HybridScheme<MinSig>;

/// Generate `n` BLS MinPk identity keys and return them as an ordered Set.
pub(crate) fn test_participants(n: u8) -> (Vec<bls12381::PrivateKey>, Set<bls12381::PublicKey>) {
    let keys: Vec<bls12381::PrivateKey> = (0..n)
        .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
        .collect();
    let participants: Set<bls12381::PublicKey> = keys
        .iter()
        .map(|sk| bls12381::PublicKey::from(sk.clone()))
        .try_collect()
        .unwrap();
    (keys, participants)
}
