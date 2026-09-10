//! Enclave crypto core (secret-bearing - lives only in the enclave binary).
//!
//! Two responsibilities for slice 1:
//!
//! 1. **Offer decryption primitive** - byte-identical to the host's current
//!    `outbe-tributefactory` `crypto.rs`: ECDHE(X25519) + HKDF-SHA256 +
//!    ChaCha20Poly1305 with the same `b"tribute-factory-encryption"` info
//!    label. This is what `crypto.rs` will call into the enclave for once the
//!    decrypt key is enclave-resident.
//!
//! 2. **Tribute-offer-key derivation** - DKG group threshold signature -> HKDF ->
//!    tribute-offer X25519 keypair, resident in each enclave so every validator
//!    decrypts tribute offers deterministically during block execution.
//!
//! `ring` (HKDF + AEAD) and `x25519-dalek` mirror the existing host code, so
//! ciphertext produced by current clients decrypts identically here.

use ring::{
    aead,
    hkdf::{self, KeyType},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use alloy_primitives::B256;
use outbe_tee::dcap_protocol::{DcapOnboardingArtifactV1, DcapOnboardingContextV1};

use crate::errors::{Result, TeeError};

/// HKDF info label for the offer encryption key. MUST match
/// `outbe-tributefactory::crypto` for byte-identical decryption.
const OFFER_AEAD_INFO: &[u8] = b"tribute-factory-encryption";
/// HKDF info label for deriving the offer X25519 secret from the root seed.
const OFFER_X25519_INFO: &[u8] = b"outbe/tribute/offer-x25519/v1";
/// Offer-key HKDF info prefix: `info = "outbe/tribute/v1/" || epoch`.
const OFFER_SEED_INFO_PREFIX: &[u8] = b"outbe/tribute/v1/";
/// HKDF info label for DKG share sealed-box encryption. TEE infrastructure
/// (not tribute-offer-specific), so the domain is `outbe/tee/...`; distinct from
/// offer encryption so a share key can never be derived as an offer key.
const DKG_SHARE_INFO: &[u8] = b"outbe/tee/dkg-share/v1";

/// HKDF `info` for the deterministic registry-seal nonce, distinct from the AEAD
/// key derivation so the nonce cannot collide with the key.
const REGISTRY_NONCE_INFO: &[u8] = b"outbe/tee/registry-seal-nonce/v1";

/// Purpose-bound onboarding key and nonce domains. They intentionally differ
/// from each other and from both generic DKG share domains above.
pub(crate) const ONBOARDING_KEY_INFO_V1: &[u8] = b"outbe/tee/onboarding-key/v1";
pub(crate) const ONBOARDING_NONCE_INFO_V1: &[u8] = b"outbe/tee/onboarding-nonce/v1";

/// Single-use nonce provider for ring's `BoundKey` API. Replicated locally
/// (mirrors `outbe_primitives::crypto::OneNonce`) to keep enclave dependencies
/// minimal for reproducible `MRENCLAVE`.
pub(crate) struct OneNonce([u8; 12]);

impl OneNonce {
    pub(crate) fn new(nonce: [u8; 12]) -> Self {
        Self(nonce)
    }
}

impl aead::NonceSequence for OneNonce {
    fn advance(&mut self) -> core::result::Result<aead::Nonce, ring::error::Unspecified> {
        Ok(aead::Nonce::assume_unique_for_key(self.0))
    }
}

/// `KeyType` for 32-byte HKDF output.
struct Len32;
impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

/// HKDF-SHA256 extract + expand to 32 bytes.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let info_refs: &[&[u8]] = &[info];
    let okm = prk
        .expand(info_refs, Len32)
        .map_err(|_| TeeError::HkdfFailed)?;
    let mut out = [0u8; 32];
    okm.fill(&mut out).map_err(|_| TeeError::HkdfFailed)?;
    Ok(out)
}

/// ChaCha20Poly1305 AEAD decrypt (empty AAD), matching host semantics.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    use aead::BoundKey;
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .map_err(|_| TeeError::DecryptFailed)?;
    let mut opening = aead::OpeningKey::new(unbound, OneNonce::new(*nonce));
    let mut in_out = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(aead::Aad::empty(), &mut in_out)
        .map_err(|_| TeeError::DecryptFailed)?;
    Ok(plaintext.to_vec())
}

/// ChaCha20Poly1305 AEAD encrypt (empty AAD). Used by the client/host and tests
/// to produce ciphertext; the enclave itself only decrypts offers.
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use aead::BoundKey;
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .map_err(|_| TeeError::EncryptFailed)?;
    let mut sealing = aead::SealingKey::new(unbound, OneNonce::new(*nonce));
    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| TeeError::EncryptFailed)?;
    Ok(in_out)
}

/// Offer decryption primitive: ECDHE(static_secret, ephemeral_pubkey) ->
/// HKDF-SHA256(salt, shared, info) -> ChaCha20Poly1305 decrypt.
///
/// Byte-identical to `outbe-tributefactory::crypto::decrypt_tribute_input`'s
/// cryptographic core (this returns raw plaintext; payload parsing is a later
/// slice).
pub fn ecdhe_tribute_offer_decrypt(
    tribute_offer_private_key: &[u8; 32],
    salt: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(TeeError::InvalidNonce(nonce.len()));
    }
    let secret = StaticSecret::from(*tribute_offer_private_key);
    let peer_public = PublicKey::from(*ephemeral_pubkey);
    let shared_secret = secret.diffie_hellman(&peer_public);

    let encryption_key = hkdf_sha256(salt, shared_secret.as_bytes(), OFFER_AEAD_INFO)?;

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);
    chacha20poly1305_decrypt(&encryption_key, &nonce_arr, ciphertext)
}

/// Derive the tribute-offer X25519 keypair from a 32-byte seed.
///
/// Returns `(secret_bytes, public_bytes)` with the secret already held in
/// zeroizing storage so callers cannot accidentally transport a plain copy.
pub fn derive_tribute_offer_keypair(seed: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let secret_bytes = Zeroizing::new(hkdf_sha256(seed, b"", OFFER_X25519_INFO)?);
    let secret = StaticSecret::from(*secret_bytes);
    let public = PublicKey::from(&secret);
    Ok((secret_bytes, public.to_bytes()))
}

/// Derive the tribute-offer X25519 keypair from the DKG **group threshold
/// signature** `group_sig` - the signature every enclave recovers (via
/// `threshold::recover`) from `2f+1` partial signatures over the fixed offer
/// message. `group_sig` is the shared, deterministic secret material:
/// byte-identical on every honest enclave (so all derive the same tribute-offer
/// key), yet unforgeable without a threshold of DKG shares. `chain_id` + `epoch`
/// are bound into the HKDF for domain separation. The resulting tribute-offer
/// secret is resident in each enclave so every validator decrypts tribute offers
/// deterministically during block execution - an architectural requirement of
/// deterministic local re-execution, not a compromise. Returns
/// `(tribute_offer_secret, tribute_offer_public)` with a zeroizing secret.
pub fn derive_tribute_offer_secret_from_group_sig(
    group_sig: &[u8],
    chain_id: B256,
    epoch: u64,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let mut info = OFFER_SEED_INFO_PREFIX.to_vec();
    info.extend_from_slice(epoch.to_string().as_bytes());
    let seed = Zeroizing::new(hkdf_sha256(chain_id.as_slice(), group_sig, &info)?);
    derive_tribute_offer_keypair(&seed)
}

/// A DKG share sealed to a recipient enclave's X25519 key: a fresh ephemeral
/// public key, a nonce, and the ChaCha20Poly1305 ciphertext. The host only ever
/// relays this opaque blob; the plaintext share exists only inside the dealer's
/// and the recipient's enclaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedShare {
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedShare {
    /// Flat wire encoding `ephemeral_pub(32) || nonce(12) || ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(44 + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_pub);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode the flat wire encoding produced by [`EncryptedShare::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 44 {
            return Err(TeeError::DecryptFailed);
        }
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&bytes[..32]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[32..44]);
        Ok(Self {
            ephemeral_pub,
            nonce,
            ciphertext: bytes[44..].to_vec(),
        })
    }
}

/// Seal `plaintext` (a serialized DKG share) to `recipient_pub` with a fresh
/// ephemeral X25519 keypair (sealed-box). The recipient recovers it with
/// [`decrypt_share`]. The shared key is `HKDF(salt = recipient_pub, ikm = ECDHE,
/// info = DKG_SHARE_INFO)`; a fresh ephemeral key per call makes the key unique,
/// so the random nonce is defense-in-depth.
///
/// `OsRng` here is **transport-encryption** randomness (ephemeral X25519 +
/// nonce) - it is NOT consensus randomness. The encrypted share decrypts to a
/// deterministic plaintext; ciphertext freshness only protects confidentiality
/// in flight, and never feeds VRF/leader-election/state transitions.
pub fn encrypt_share(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedShare> {
    use rand_core::RngCore;
    let mut ephemeral_secret = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut ephemeral_secret);
    let mut nonce = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let eph_secret = StaticSecret::from(ephemeral_secret);
    ephemeral_secret.zeroize();
    let ephemeral_pub = PublicKey::from(&eph_secret).to_bytes();
    let shared = eph_secret.diffie_hellman(&PublicKey::from(*recipient_pub));
    let key = hkdf_sha256(recipient_pub, shared.as_bytes(), DKG_SHARE_INFO)?;
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext)?;
    Ok(EncryptedShare {
        ephemeral_pub,
        nonce,
        ciphertext,
    })
}

/// DETERMINISTIC seal of `plaintext` to `recipient_pub`, suitable for committing
/// the sealed blob ON-CHAIN (an encrypted-seed analog):
/// every enclave holding the same `sender_static_secret` (the resident offer key's
/// X25519 secret, identical across the committee) produces a BYTE-IDENTICAL
/// [`EncryptedShare`] for the same recipient + plaintext, so the result can be a
/// consensus-validated on-chain artifact.
///
/// Unlike [`encrypt_share`] (random ephemeral key + random nonce), this uses
/// static-static ECDH between the sender's static secret and the recipient's
/// static public, and derives the nonce from the shared secret - NO RNG. The
/// recipient opens it with the UNCHANGED [`decrypt_share`] using its own X25519
/// secret and the sender's static public (carried in `ephemeral_pub`, which equals
/// the on-chain `tribute_offer_public_key`). The fixed-per-pair nonce is safe: the
/// AEAD key is unique per (offer-key epoch, recipient) because the offer secret
/// rotates with the key epoch and `recipient_pub` salts both key and nonce.
pub fn encrypt_share_deterministic(
    sender_static_secret: &[u8; 32],
    recipient_pub: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedShare> {
    let sender = StaticSecret::from(*sender_static_secret);
    let sender_pub = PublicKey::from(&sender).to_bytes();
    let shared = sender.diffie_hellman(&PublicKey::from(*recipient_pub));
    let key = hkdf_sha256(recipient_pub, shared.as_bytes(), DKG_SHARE_INFO)?;
    let nonce_okm = hkdf_sha256(recipient_pub, shared.as_bytes(), REGISTRY_NONCE_INFO)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_okm[..12]);
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext)?;
    Ok(EncryptedShare {
        ephemeral_pub: sender_pub,
        nonce,
        ciphertext,
    })
}

/// Open a share sealed by [`encrypt_share`] with the recipient's X25519 private
/// key. The salt (`recipient_pub`) is recomputed from `recipient_secret`, so it
/// matches the sealer without being transmitted.
pub fn decrypt_share(recipient_secret: &[u8; 32], enc: &EncryptedShare) -> Result<Vec<u8>> {
    let secret = StaticSecret::from(*recipient_secret);
    let recipient_pub = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(enc.ephemeral_pub));
    let key = hkdf_sha256(&recipient_pub, shared.as_bytes(), DKG_SHARE_INFO)?;
    chacha20poly1305_decrypt(&key, &enc.nonce, &enc.ciphertext)
}

fn onboarding_aead_material(
    context_hash: B256,
    shared_secret: &[u8; 32],
) -> Result<([u8; 32], [u8; 12])> {
    let key = hkdf_sha256(
        context_hash.as_slice(),
        shared_secret,
        ONBOARDING_KEY_INFO_V1,
    )?;
    let nonce_okm = hkdf_sha256(
        context_hash.as_slice(),
        shared_secret,
        ONBOARDING_NONCE_INFO_V1,
    )?;
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&nonce_okm[..12]);
    Ok((key, nonce))
}

/// Deterministically encrypt the resident founding group signature for one
/// exact accepted registration context. No caller-selected plaintext exists.
pub fn encrypt_onboarding_artifact_v1(
    sender_offer_secret: &[u8; 32],
    context: DcapOnboardingContextV1,
    group_signature: &[u8],
) -> Result<DcapOnboardingArtifactV1> {
    let sender = StaticSecret::from(*sender_offer_secret);
    if PublicKey::from(&sender).to_bytes() != context.tribute_offer_public {
        return Err(TeeError::Dkg(
            "onboarding context offer public does not match resident key".into(),
        ));
    }
    let shared = sender.diffie_hellman(&PublicKey::from(context.recipient_x25519));
    let (key, nonce) = onboarding_aead_material(context.context_hash(), shared.as_bytes())?;
    let ciphertext = chacha20poly1305_encrypt(&key, &nonce, group_signature)?;
    let artifact = DcapOnboardingArtifactV1 {
        context,
        nonce,
        ciphertext,
    };
    artifact
        .encode_canonical()
        .map_err(|_| TeeError::EncryptFailed)?;
    Ok(artifact)
}

/// Open one purpose-bound onboarding artifact. The target derives its recipient
/// public key, context key and nonce locally. A wire nonce mismatch is rejected
/// before AEAD open and is never used as nonce authority.
pub fn decrypt_onboarding_artifact_v1(
    recipient_secret: &[u8; 32],
    artifact: &DcapOnboardingArtifactV1,
) -> Result<Zeroizing<Vec<u8>>> {
    let recipient = StaticSecret::from(*recipient_secret);
    let recipient_public = PublicKey::from(&recipient).to_bytes();
    if recipient_public != artifact.context.recipient_x25519 {
        return Err(TeeError::DecryptFailed);
    }
    let shared = recipient.diffie_hellman(&PublicKey::from(artifact.context.tribute_offer_public));
    let (key, expected_nonce) =
        onboarding_aead_material(artifact.context.context_hash(), shared.as_bytes())?;
    if artifact.nonce != expected_nonce {
        return Err(TeeError::DecryptFailed);
    }
    Ok(Zeroizing::new(chacha20poly1305_decrypt(
        &key,
        &expected_nonce,
        &artifact.ciphertext,
    )?))
}

/// Derive the X25519 public key for a 32-byte X25519 secret (the enclave's DKG
/// share-decryption key). Announced so dealers can seal shares to this enclave.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared client-side encryptor (`outbe_tee::offer_encrypt`, used by
    /// outbe-cli, the bench and the node canary) must round-trip with THIS
    /// decrypt path byte-for-byte - the canary asserts exactly this in prod.
    #[test]
    fn shared_offer_encrypt_helper_round_trips_with_decrypt() {
        let offer_sk = outbe_primitives::test_keys::secret(7);
        let offer_pub = x25519_public(&offer_sk);
        let eph_sk = outbe_primitives::test_keys::secret(9);
        let nonce = [1u8; 12];
        let plaintext = outbe_tee::offer_encrypt::canary_offer_json(20250115);
        let cipher_text = outbe_tee::offer_encrypt::encrypt_tribute_offer_with(
            &offer_pub,
            eph_sk,
            nonce,
            plaintext.as_bytes(),
        )
        .expect("encrypt");
        let eph_pub = x25519_public(&eph_sk);
        let decrypted = ecdhe_tribute_offer_decrypt(
            &offer_sk,
            &outbe_tee::OFFER_HKDF_SALT,
            &eph_pub,
            &nonce,
            &cipher_text,
        )
        .expect("decrypt");
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    fn onboarding_context(
        recipient_x25519: [u8; 32],
        tribute_offer_public: [u8; 32],
    ) -> DcapOnboardingContextV1 {
        DcapOnboardingContextV1 {
            chain_id: [0x21; 32],
            genesis_hash: B256::repeat_byte(0x22),
            intent_hash: B256::repeat_byte(0x23),
            node_id_hash: B256::repeat_byte(0x24),
            enclave_id: B256::repeat_byte(0x25),
            binding_id: B256::repeat_byte(0x26),
            policy_hash: B256::repeat_byte(0x27),
            recipient_x25519,
            tribute_offer_public,
            key_epoch: 3,
            tribute_offer_epoch: 4,
        }
    }

    /// The deterministic registry seal must be byte-identical across calls (so every
    /// committee enclave commits the same on-chain blob) and must round-trip through
    /// the UNCHANGED `decrypt_share` using only the recipient's secret.
    #[test]
    fn encrypt_share_deterministic_is_byte_identical_and_roundtrips() {
        let offer_secret = outbe_primitives::test_keys::secret(7);
        let recipient_secret = outbe_primitives::test_keys::secret(9);
        let recipient_pub = x25519_public(&recipient_secret);
        let plaintext = b"resident group signature bytes";

        let a = encrypt_share_deterministic(&offer_secret, &recipient_pub, plaintext).unwrap();
        let b = encrypt_share_deterministic(&offer_secret, &recipient_pub, plaintext).unwrap();
        assert_eq!(
            a.to_bytes(),
            b.to_bytes(),
            "deterministic seal must be byte-identical for on-chain commit"
        );

        // `ephemeral_pub` carries the sender's STATIC public = the offer public key,
        // so the recipient (with only its own secret) opens it via decrypt_share.
        assert_eq!(a.ephemeral_pub, x25519_public(&offer_secret));
        let opened = decrypt_share(&recipient_secret, &a).unwrap();
        assert_eq!(opened.as_slice(), plaintext);

        // Different recipient -> different blob (key + nonce both salted by recipient).
        let other_pub = x25519_public(&[11u8; 32]);
        let c = encrypt_share_deterministic(&offer_secret, &other_pub, plaintext).unwrap();
        assert_ne!(a.to_bytes(), c.to_bytes());
    }

    #[test]
    fn onboarding_artifact_is_exact_replay_and_context_separated() {
        let offer_secret = outbe_primitives::test_keys::secret(0x31);
        let offer_public = x25519_public(&offer_secret);
        let recipient_secret = outbe_primitives::test_keys::secret(0x32);
        let recipient_public = x25519_public(&recipient_secret);
        let context = onboarding_context(recipient_public, offer_public);
        let plaintext = b"exact founding group signature";

        let first = encrypt_onboarding_artifact_v1(&offer_secret, context, plaintext).unwrap();
        let replay = encrypt_onboarding_artifact_v1(&offer_secret, context, plaintext).unwrap();
        assert_eq!(first, replay);
        assert_eq!(
            decrypt_onboarding_artifact_v1(&recipient_secret, &first)
                .unwrap()
                .as_slice(),
            plaintext
        );

        let mut changed_context = context;
        changed_context.intent_hash = B256::repeat_byte(0x41);
        let changed =
            encrypt_onboarding_artifact_v1(&offer_secret, changed_context, plaintext).unwrap();
        assert_ne!(first.nonce, changed.nonce);
        assert_ne!(first.ciphertext, changed.ciphertext);
    }

    #[test]
    fn onboarding_ingest_rejects_wire_nonce_before_aead_open() {
        let offer_secret = outbe_primitives::test_keys::secret(0x51);
        let offer_public = x25519_public(&offer_secret);
        let recipient_secret = outbe_primitives::test_keys::secret(0x52);
        let recipient_public = x25519_public(&recipient_secret);
        let mut artifact = encrypt_onboarding_artifact_v1(
            &offer_secret,
            onboarding_context(recipient_public, offer_public),
            b"group signature",
        )
        .unwrap();
        artifact.nonce[0] ^= 1;
        assert!(matches!(
            decrypt_onboarding_artifact_v1(&recipient_secret, &artifact),
            Err(TeeError::DecryptFailed)
        ));
    }

    #[test]
    fn onboarding_domains_are_distinct_from_existing_share_domains() {
        assert_ne!(ONBOARDING_KEY_INFO_V1, ONBOARDING_NONCE_INFO_V1);
        assert_ne!(ONBOARDING_KEY_INFO_V1, DKG_SHARE_INFO);
        assert_ne!(ONBOARDING_KEY_INFO_V1, REGISTRY_NONCE_INFO);
        assert_ne!(ONBOARDING_NONCE_INFO_V1, DKG_SHARE_INFO);
        assert_ne!(ONBOARDING_NONCE_INFO_V1, REGISTRY_NONCE_INFO);
    }

    /// Encrypt as a client would (ephemeral_secret x tribute_offer_public), then decrypt
    /// in the enclave (tribute_offer_secret x ephemeral_public). Proves the ECDHE+HKDF+
    /// ChaCha core round-trips, i.e. real client ciphertext decrypts here.
    #[test]
    fn ecdhe_tribute_offer_roundtrip() {
        let tribute_offer_sk = outbe_primitives::test_keys::secret(7);
        let tribute_offer_pub = PublicKey::from(&StaticSecret::from(tribute_offer_sk)).to_bytes();

        let eph_sk = outbe_primitives::test_keys::secret(9);
        let eph_pub = PublicKey::from(&StaticSecret::from(eph_sk)).to_bytes();

        // Client side: shared = eph_sk x tribute_offer_pub.
        let shared = StaticSecret::from(eph_sk).diffie_hellman(&PublicKey::from(tribute_offer_pub));
        let salt = [3u8; 32];
        let key = hkdf_sha256(&salt, shared.as_bytes(), OFFER_AEAD_INFO).unwrap();
        let nonce = [1u8; 12];
        let plaintext = b"{\"hello\":\"tribute\"}";
        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext).unwrap();

        // Enclave side: shared = tribute_offer_sk x eph_pub.
        let decrypted =
            ecdhe_tribute_offer_decrypt(&tribute_offer_sk, &salt, &eph_pub, &nonce, &ciphertext)
                .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn reject_bad_nonce_len() {
        let err = ecdhe_tribute_offer_decrypt(&[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 11], &[])
            .unwrap_err();
        assert!(matches!(err, TeeError::InvalidNonce(11)));
    }

    #[test]
    fn tribute_offer_secret_is_deterministic_and_chain_bound() {
        // The group threshold signature is the shared secret material every
        // enclave recovers identically; HKDF binds chain_id + epoch.
        let sig = b"a-recovered-group-threshold-signature-~48-bytes";
        let cid_a = B256::repeat_byte(0xAA);
        let cid_b = B256::repeat_byte(0xBB);

        let (a1, _) = derive_tribute_offer_secret_from_group_sig(sig, cid_a, 0).unwrap();
        let (a2, _) = derive_tribute_offer_secret_from_group_sig(sig, cid_a, 0).unwrap();
        let (b1, _) = derive_tribute_offer_secret_from_group_sig(sig, cid_b, 0).unwrap();
        assert_eq!(a1, a2, "same inputs -> same offer secret");
        assert_ne!(a1, b1, "different chain_id -> different offer secret");
    }

    #[test]
    fn dkg_share_sealed_box_roundtrips() {
        // Recipient enclave's DKG share-decryption keypair.
        let recipient_sk = outbe_primitives::test_keys::secret(0x33);
        let recipient_pub = x25519_public(&recipient_sk);

        let share = b"a-serialized-dkg-share-scalar-bytes";
        let sealed = encrypt_share(&recipient_pub, share).unwrap();
        // The host never sees the plaintext - only the opaque blob.
        assert_ne!(sealed.ciphertext.as_slice(), share.as_slice());

        let opened = decrypt_share(&recipient_sk, &sealed).unwrap();
        assert_eq!(opened, share);

        // Wire round-trip of the opaque blob.
        let wire = sealed.to_bytes();
        let parsed = EncryptedShare::from_bytes(&wire).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(decrypt_share(&recipient_sk, &parsed).unwrap(), share);
    }

    #[test]
    fn dkg_share_rejects_wrong_recipient() {
        let recipient_pub = x25519_public(&[0x33u8; 32]);
        let wrong_sk = outbe_primitives::test_keys::secret(0x44);
        let sealed = encrypt_share(&recipient_pub, b"share").unwrap();
        // A different recipient key cannot open the sealed share.
        assert!(decrypt_share(&wrong_sk, &sealed).is_err());
    }

    #[test]
    fn dkg_share_from_bytes_rejects_truncated() {
        assert!(EncryptedShare::from_bytes(&[0u8; 43]).is_err());
    }

    #[test]
    fn tribute_offer_keypair_is_deterministic() {
        let seed = [1u8; 32];
        let (sk1, pk1) = derive_tribute_offer_keypair(&seed).unwrap();
        let (sk2, pk2) = derive_tribute_offer_keypair(&seed).unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
        // Public key matches the secret.
        assert_eq!(pk1, PublicKey::from(&StaticSecret::from(*sk1)).to_bytes());
    }

    /// `to_bytes` must lay out exactly `ephemeral_pub(32) || nonce(12) ||
    /// ciphertext`, and `from_bytes` must read those same slices back. Uses
    /// distinct, hand-picked bytes per field so a swapped/overlapping range fails.
    #[test]
    fn encrypted_share_wire_layout_is_exact() {
        let share = EncryptedShare {
            ephemeral_pub: [0xAAu8; 32],
            nonce: [0xBBu8; 12],
            ciphertext: vec![0xCC, 0xDD, 0xEE],
        };
        let wire = share.to_bytes();

        assert_eq!(wire.len(), 44 + 3);
        assert_eq!(&wire[..32], &[0xAAu8; 32]); // ephemeral_pub
        assert_eq!(&wire[32..44], &[0xBBu8; 12]); // nonce
        assert_eq!(&wire[44..], &[0xCC, 0xDD, 0xEE]); // ciphertext

        // Round-trips without touching the crypto path.
        assert_eq!(EncryptedShare::from_bytes(&wire).unwrap(), share);
    }

    /// The length check is `< 44`, so exactly 44 bytes is valid and decodes to an
    /// empty ciphertext - the boundary case.
    #[test]
    fn encrypted_share_from_bytes_accepts_min_len_empty_ciphertext() {
        let share = EncryptedShare {
            ephemeral_pub: [1u8; 32],
            nonce: [2u8; 12],
            ciphertext: Vec::new(),
        };
        let wire = share.to_bytes();
        assert_eq!(wire.len(), 44);
        let parsed = EncryptedShare::from_bytes(&wire).unwrap();
        assert_eq!(parsed, share);
        assert!(parsed.ciphertext.is_empty());
    }

    /// Standalone AEAD round-trip plus tamper detection: flipping any ciphertext
    /// or tag byte, or opening with the wrong nonce/key, must fail closed.
    #[test]
    fn chacha20poly1305_roundtrip_and_tamper_rejected() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"decode me";

        let mut ct = chacha20poly1305_encrypt(&key, &nonce, plaintext).unwrap();
        // seal appends a 16-byte Poly1305 tag.
        assert_eq!(ct.len(), plaintext.len() + 16);
        assert_eq!(
            chacha20poly1305_decrypt(&key, &nonce, &ct).unwrap(),
            plaintext
        );

        // Tampered ciphertext (flip a tag byte) -> DecryptFailed.
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            chacha20poly1305_decrypt(&key, &nonce, &ct),
            Err(TeeError::DecryptFailed)
        ));
        ct[last] ^= 0x01; // restore

        // Wrong nonce and wrong key both fail.
        assert!(chacha20poly1305_decrypt(&key, &[0u8; 12], &ct).is_err());
        assert!(chacha20poly1305_decrypt(&[0u8; 32], &nonce, &ct).is_err());
    }
}
