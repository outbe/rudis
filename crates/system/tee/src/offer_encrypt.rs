//! Client-side tribute-offer encryption - the single shared implementation used
//! by `outbe-cli`, the enclave throughput bench and the node's canary probe.
//!
//! Recipe (byte-compatible with the enclave decrypt path
//! `outbe_tee_enclave::crypto::ecdhe_tribute_offer_decrypt`): ephemeral X25519 ->
//! ECDHE with the offer public key -> `HKDF-SHA256(salt = OFFER_HKDF_SALT, ikm =
//! shared, info = b"tribute-factory-encryption")` -> ChaCha20Poly1305 with empty
//! AAD. This is client-side crypto over an ephemeral secret and the PUBLIC offer
//! key - no enclave-resident secret material is involved (the crate rule that
//! secret-bearing cryptography lives only in `bin/outbe-tee-enclave` holds).

use crate::OFFER_HKDF_SALT;

/// HKDF info string binding the derived key to the tribute-offer domain.
pub const OFFER_HKDF_INFO: &[u8] = b"tribute-factory-encryption";

/// `(cipher_text, nonce, ephemeral_pub)` produced by [`encrypt_tribute_offer`].
pub type EncryptedOfferParts = (Vec<u8>, [u8; 12], [u8; 32]);

/// Encrypt `plaintext` to `offer_pub` with a fresh ephemeral key and nonce.
/// Returns `(cipher_text, nonce, ephemeral_pub)`.
pub fn encrypt_tribute_offer(
    offer_pub: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedOfferParts, String> {
    use ring::rand::SecureRandom as _;
    let rng = ring::rand::SystemRandom::new();
    // Cryptographic randomness for an offer-encryption ephemeral + nonce; never
    // consensus randomness (the ciphertext is request DATA, decrypted
    // deterministically by every validator's enclave).
    let mut eph_sk = [0u8; 32];
    rng.fill(&mut eph_sk)
        .map_err(|_| "offer encryption rng failure".to_string())?;
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)
        .map_err(|_| "offer encryption rng failure".to_string())?;
    let eph_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(eph_sk));
    let cipher_text = encrypt_tribute_offer_with(offer_pub, eph_sk, nonce, plaintext)?;
    Ok((cipher_text, nonce, eph_pub.to_bytes()))
}

/// Deterministic variant with an explicit ephemeral secret and nonce - for the
/// bench, tests, and any caller that manages its own randomness.
pub fn encrypt_tribute_offer_with(
    offer_pub: &[u8; 32],
    eph_sk: [u8; 32],
    nonce: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let eph_secret = x25519_dalek::StaticSecret::from(eph_sk);
    let shared = eph_secret.diffie_hellman(&x25519_dalek::PublicKey::from(*offer_pub));
    let key = hkdf_sha256(&OFFER_HKDF_SALT, shared.as_bytes(), OFFER_HKDF_INFO)?;
    chacha20poly1305_encrypt(&key, &nonce, plaintext)
}

/// The known-plaintext canary/bench offer payload (1 SU hash, USD). One shared
/// recipe so the canary asserts exactly what the bench measures.
pub fn canary_offer_json(worldwide_day: u32) -> String {
    format!(
        r#"{{
    "creator": "canary",
    "tribute_draft_id": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "worldwide_day": {worldwide_day},
    "currency": 840,
    "amount_base": "100",
    "amount_atto": "0",
    "su_hashes": ["0x2222222222222222222222222222222222222222222222222222222222222222"]
}}"#
    )
}

/// HKDF-SHA256 extract+expand to 32 bytes (matches the enclave).
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    use ring::hkdf;
    struct Len32;
    impl hkdf::KeyType for Len32 {
        fn len(&self) -> usize {
            32
        }
    }
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_refs: &[&[u8]] = &[info];
    let okm = prk
        .expand(info_refs, Len32)
        .map_err(|_| "hkdf expand".to_string())?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| "hkdf fill".to_string())?;
    Ok(out)
}

/// ChaCha20Poly1305 AEAD encrypt with empty AAD (matches the enclave).
fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use ring::aead::{self, BoundKey as _};
    struct OneNonce([u8; 12]);
    impl aead::NonceSequence for OneNonce {
        fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
            Ok(aead::Nonce::assume_unique_for_key(self.0))
        }
    }
    let unbound =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| "aead key".to_string())?;
    let mut sealing = aead::SealingKey::new(unbound, OneNonce(*nonce));
    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| "aead seal".to_string())?;
    Ok(in_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_random_variants_agree() {
        let offer_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            outbe_primitives::test_keys::secret(7),
        ))
        .to_bytes();
        let plaintext = canary_offer_json(20250115);
        let ct = encrypt_tribute_offer_with(
            &offer_pub,
            outbe_primitives::test_keys::secret(9),
            [1u8; 12],
            plaintext.as_bytes(),
        )
        .expect("encrypt");
        // ChaCha20Poly1305 appends a 16-byte tag.
        assert_eq!(ct.len(), plaintext.len() + 16);
        let again = encrypt_tribute_offer_with(
            &offer_pub,
            outbe_primitives::test_keys::secret(9),
            [1u8; 12],
            plaintext.as_bytes(),
        )
        .expect("encrypt");
        assert_eq!(ct, again, "deterministic variant is reproducible");

        let (ct2, _nonce, eph_pub) =
            encrypt_tribute_offer(&offer_pub, plaintext.as_bytes()).expect("encrypt random");
        assert_eq!(ct2.len(), ct.len());
        assert_ne!(eph_pub, [0u8; 32]);
    }
}
