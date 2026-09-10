//! Shared cryptographic utilities for `ring`-based AEAD operations.

use ring::aead;

/// Single-use nonce provider for ring's `BoundKey` API.
///
/// Ring requires a `NonceSequence` to supply nonces to `SealingKey` /
/// `OpeningKey`.  This implementation returns the provided nonce exactly
/// once, which is correct for encrypt-then-forget or single-message
/// decrypt operations.
pub struct OneNonce([u8; 12]);

impl OneNonce {
    pub fn new(nonce: [u8; 12]) -> Self {
        Self(nonce)
    }
}

impl aead::NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        Ok(aead::Nonce::assume_unique_for_key(self.0))
    }
}
