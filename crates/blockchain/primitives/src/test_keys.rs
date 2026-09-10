//! Generated keys for reproducible tests and reference fixtures.
//!
//! Seeds identify test actors, not private key bytes. These keys are public and
//! predictable by design; never use this module for funded accounts or deployed
//! validator identities. Production key generation must use OS entropy.

use k256::ecdsa::SigningKey;
use rand::{rngs::StdRng, SeedableRng};

/// Generate a valid secp256k1 scalar for a reproducible test actor.
pub fn secret(seed: u64) -> [u8; 32] {
    SigningKey::random(&mut StdRng::seed_from_u64(seed))
        .to_bytes()
        .into()
}

/// Encode a generated test key without a prefix for key-file and parser tests.
pub fn hex(seed: u64) -> String {
    hex::encode(secret(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actors_have_valid_distinct_repeatable_keys() {
        let first = SigningKey::from_slice(&secret(1)).unwrap();
        let second = SigningKey::from_slice(&secret(2)).unwrap();
        assert_eq!(secret(1), secret(1));
        assert_ne!(first.verifying_key(), second.verifying_key());
        assert_eq!(hex::decode(hex(1)).unwrap(), secret(1));
    }
}
