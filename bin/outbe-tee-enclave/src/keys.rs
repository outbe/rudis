//! Enclave key material + quote assembly (secret-bearing - enclave only).
//!
//! One sealed identity seed deterministically derives the Noise responder,
//! recipient X25519, Ed25519 attestation, TEE-BLS and DKG-decryption keys. The
//! public identity therefore survives restart as one atomic unit. Intent-bound
//! DCAP quotes are generated separately by the initialized NodeHost path; this
//! module retains an unattested response only for the mock/test transport.

use alloy_primitives::{keccak256, B256};
use commonware_codec::Encode as _;
use commonware_cryptography::bls12381::primitives::group::{Private as BlsPrivate, Scalar};
use commonware_cryptography::Signer as _;
use zeroize::{Zeroize as _, Zeroizing};

use outbe_primitives::tee_attestation_v1::NetworkBindingV1;
use outbe_tee::protocol::EnclaveResponse;

use crate::crypto::{hkdf_sha256, x25519_public};
use crate::dkg::PrivKey;
use crate::errors::TeeError;
use crate::gramine::{self, AttestationType};
use crate::process::TributeOfferKeyMaterial;

/// Measurement value used when no SGX hardware quote is available
/// (`gramine-direct`/bare). Zero is not a valid SGX measurement, so it cannot be
/// mistaken for an attested enclave - a strict host policy rejects it.
pub const UNATTESTED_MEASUREMENT: B256 = B256::ZERO;

/// Commonware namespace for the already domain-separated, ceremony-scoped DKG
/// participant announcement digest.
pub const DKG_ENC_BIND_NAMESPACE: &[u8] = b"outbe/tee/dkg-participant-announce/v1";

/// Versioned RFC 9380 domain for the persistent TEE-BLS identity mapping.
/// Changing this value rotates the identity and therefore requires an explicit
/// migration; the known-answer test below pins seed-to-public-key continuity.
const TEE_BLS_IDENTITY_V1_DST: &[u8] = b"OUTBE_TEE_BLS_IDENTITY_V1_XMD:SHA-256";

fn derive_tee_bls_identity_v1(seed: &[u8; 32]) -> Result<PrivKey, String> {
    // Scalar::map is an explicit RFC 9380 expand_message_xmd + field reduction,
    // rather than an RNG implementation detail. The counter handles the
    // negligible zero-scalar case deterministically for every possible seed.
    for counter in 0u8..=u8::MAX {
        let mut input = Zeroizing::new([0u8; 33]);
        input[..32].copy_from_slice(seed);
        input[32] = counter;
        let scalar = Scalar::map(TEE_BLS_IDENTITY_V1_DST, input.as_ref());
        if scalar != Scalar::from_u64(0) {
            return Ok(PrivKey::from(BlsPrivate::new(scalar)));
        }
    }
    Err("TEE-BLS identity v1 mapping produced only zero scalars".to_string())
}

/// Signature type produced by the TEE-BLS identity key.
type TeeBlsSignature = <PrivKey as commonware_cryptography::Signer>::Signature;

/// Verify a complete ceremony-scoped participant announcement. Malformed
/// public keys, signatures or non-canonical ceremony context fail closed.
pub fn verify_dkg_enc_binding(
    bls_pub: &[u8],
    network_binding: &NetworkBindingV1,
    ceremony_id: B256,
    round: u64,
    participant_set_hash: B256,
    dkg_enc_pub: &[u8; 32],
    sig: &[u8],
) -> bool {
    use commonware_codec::ReadExt as _;
    use commonware_cryptography::Verifier as _;
    let mut pk_reader: &[u8] = bls_pub;
    let Ok(pk) = <PrivKey as commonware_cryptography::Signer>::PublicKey::read(&mut pk_reader)
    else {
        return false;
    };
    let mut sig_reader: &[u8] = sig;
    let Ok(signature) = TeeBlsSignature::read(&mut sig_reader) else {
        return false;
    };
    let Ok(digest) = outbe_primitives::tee_attestation_v1::dkg_participant_announce_hash_v1(
        network_binding,
        ceremony_id,
        round,
        participant_set_hash,
        dkg_enc_pub,
    ) else {
        return false;
    };
    pk.verify(DKG_ENC_BIND_NAMESPACE, digest.as_slice(), &signature)
}

/// Enclave-resident key material.
pub struct EnclaveKeys {
    identity_seed: Zeroizing<[u8; 32]>,
    sealed_network_binding: Option<NetworkBindingV1>,
    noise_private: Zeroizing<[u8; 32]>,
    noise_public: [u8; 32],
    /// X25519 offer secret (the decrypt key) + its public (clients encrypt to it).
    tribute_offer_secret: Zeroizing<[u8; 32]>,
    tribute_offer_public: [u8; 32],
    /// Persistent per-enclave Ed25519 attestation signing key.
    attestation_signing: ed25519_dalek::SigningKey,
    /// Cached attestation public key bytes (the verifying key).
    attestation_pub: [u8; 32],
    /// TEE threshold-BLS signing key (this enclave's DKG participant identity).
    tee_bls_key: PrivKey,
    /// X25519 secret used to open DKG shares sealed to this enclave.
    dkg_enc_secret: Zeroizing<[u8; 32]>,
    mrenclave: B256,
    mrsigner: B256,
    isv_prod_id: u16,
    isv_svn: u16,
    /// The real attestation environment detected at startup.
    attest_type: AttestationType,
}

impl EnclaveKeys {
    /// Derive the complete persistent enclave identity from one seed. On SGX the
    /// seed is generated once and sealed by `run::resolve_enclave_identity_seed`; mock
    /// and direct tests pass an explicit seed. `seed` is only the fallback when no
    /// persistent seed is available and is never a production authority.
    pub fn new(seed: [u8; 32], identity_seed_override: Option<[u8; 32]>) -> Result<Self, String> {
        Self::new_with_identity_seed(seed, identity_seed_override.map(Zeroizing::new), None)
    }

    /// Production constructor: keeps a restored or freshly generated identity
    /// seed in zeroizing storage for the complete derivation path.
    pub(crate) fn new_with_identity_seed(
        mut seed: [u8; 32],
        identity_seed_override: Option<Zeroizing<[u8; 32]>>,
        sealed_network_binding: Option<NetworkBindingV1>,
    ) -> Result<Self, String> {
        let identity_seed = identity_seed_override.unwrap_or_else(|| Zeroizing::new(seed));
        seed.zeroize();
        let noise_private = Zeroizing::new(
            hkdf_sha256(identity_seed.as_ref(), b"", b"outbe/tee/noise-static/v1")
                .map_err(|error| error.to_string())?,
        );
        let noise_public = x25519_public(&noise_private);
        let tribute_offer_secret = Zeroizing::new(
            hkdf_sha256(
                identity_seed.as_ref(),
                b"",
                b"outbe/tee/recipient-x25519/v1",
            )
            .map_err(|error| error.to_string())?,
        );
        let tribute_offer_public = x25519_public(&tribute_offer_secret);
        let attestation_secret = Zeroizing::new(
            hkdf_sha256(
                identity_seed.as_ref(),
                b"",
                b"outbe/tee/attestation-ed25519/v1",
            )
            .map_err(|error| error.to_string())?,
        );
        let attestation_signing = ed25519_dalek::SigningKey::from_bytes(&attestation_secret);
        let attestation_pub = attestation_signing.verifying_key().to_bytes();

        let dkg_enc_secret = Zeroizing::new(
            hkdf_sha256(identity_seed.as_ref(), b"", b"outbe/tee/dkg-enc/v1")
                .map_err(|e| e.to_string())?,
        );
        let bls_seed = Zeroizing::new(
            hkdf_sha256(identity_seed.as_ref(), b"", b"outbe/tee/dkg-bls-seed/v1")
                .map_err(|e| e.to_string())?,
        );
        let tee_bls_key = derive_tee_bls_identity_v1(&bls_seed)?;

        // Read local measurements without producing an unauthenticated quote.
        // Intent-bound DCAP generation is restricted to the initialized NodeHost.
        let attest_type = gramine::attestation_type();
        let report_data_b256 =
            Self::report_data_binding(&noise_public, &tribute_offer_public, &attestation_pub);
        let mut report_data_64 = [0u8; 64];
        report_data_64[..32].copy_from_slice(report_data_b256.as_slice());
        let (mrenclave, mrsigner, isv_prod_id, isv_svn) =
            match gramine::local_report_measurements(&report_data_64) {
                Ok(m) => (
                    B256::from(m.mrenclave),
                    B256::from(m.mrsigner),
                    m.isv_prod_id,
                    m.isv_svn,
                ),
                Err(_) => (UNATTESTED_MEASUREMENT, UNATTESTED_MEASUREMENT, 0u16, 0u16),
            };

        Ok(Self {
            identity_seed,
            sealed_network_binding,
            noise_private,
            noise_public,
            tribute_offer_secret,
            tribute_offer_public,
            attestation_signing,
            attestation_pub,
            tee_bls_key,
            dkg_enc_secret,
            mrenclave,
            mrsigner,
            isv_prod_id,
            isv_svn,
            attest_type,
        })
    }

    pub(crate) fn identity_seed(&self) -> &[u8; 32] {
        &self.identity_seed
    }

    pub(crate) fn sealed_network_binding(&self) -> Option<NetworkBindingV1> {
        self.sealed_network_binding
    }

    /// This enclave's TEE threshold-BLS signing key (DKG participant identity).
    pub fn tee_bls_key(&self) -> &PrivKey {
        &self.tee_bls_key
    }

    /// Encoded TEE-BLS public key (the enclave's DKG participant identity bytes).
    pub fn tee_bls_public_bytes(&self) -> Vec<u8> {
        self.tee_bls_key.public_key().encode().to_vec()
    }

    /// This enclave's X25519 share-decryption secret.
    pub fn dkg_enc_secret(&self) -> &[u8; 32] {
        &self.dkg_enc_secret
    }

    /// This enclave's X25519 share-encryption public key (dealers seal to it).
    pub fn dkg_enc_public(&self) -> [u8; 32] {
        x25519_public(&self.dkg_enc_secret)
    }

    pub fn noise_private(&self) -> &[u8] {
        self.noise_private.as_ref()
    }
    pub fn noise_public(&self) -> [u8; 32] {
        self.noise_public
    }
    pub fn tribute_offer_public(&self) -> [u8; 32] {
        self.tribute_offer_public
    }
    /// The X25519 secret behind the one-time onboarding recipient advertised by a
    /// keyless enclave. The finalized registry artifact is sealed to this
    /// REPORT_DATA-bound public key and can be ingested only by this enclave.
    pub fn tribute_offer_x25519_secret(&self) -> &[u8; 32] {
        &self.tribute_offer_secret
    }
    pub fn attestation_pub(&self) -> [u8; 32] {
        self.attestation_pub
    }

    /// Sign `msg` with this enclave's Ed25519 attestation key. Used to
    /// produce the per-offer attestation tag over the offer-attestation preimage;
    /// the host verifies it against [`EnclaveKeys::attestation_pub`].
    pub fn sign_attestation(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.attestation_signing.sign(msg).to_bytes()
    }

    /// Sign this enclave's exact ceremony-scoped DKG announcement.
    pub fn sign_dkg_enc_binding(
        &self,
        network_binding: &NetworkBindingV1,
        ceremony_id: B256,
        round: u64,
        participant_set_hash: B256,
    ) -> crate::errors::Result<Vec<u8>> {
        let digest = outbe_primitives::tee_attestation_v1::dkg_participant_announce_hash_v1(
            network_binding,
            ceremony_id,
            round,
            participant_set_hash,
            &self.dkg_enc_public(),
        )
        .map_err(|error| TeeError::Dkg(format!("invalid DKG announcement context: {error}")))?;
        Ok(self
            .tee_bls_key
            .sign(DKG_ENC_BIND_NAMESPACE, digest.as_slice())
            .encode()
            .to_vec())
    }
    /// The running enclave's ISV SVN (0 when unattested). Consumed by the
    /// seal/unseal boot path for the anti-rollback floor (plan section "Local
    /// Persistence").
    pub fn isv_svn(&self) -> u16 {
        self.isv_svn
    }

    /// Exact SGX code identity of this source enclave. Purpose-bound key
    /// delivery accepts only a target running this same measured release;
    /// caller-supplied policy bytes are never authority for another MRENCLAVE.
    pub(crate) const fn code_identity(&self) -> (B256, B256, u16, u16) {
        (
            self.mrenclave,
            self.mrsigner,
            self.isv_prod_id,
            self.isv_svn,
        )
    }

    /// Borrow the (dev) offer decrypt key material for a batch call. The salt is
    /// the fixed protocol constant [`outbe_tee::OFFER_HKDF_SALT`] (clients use the
    /// same value), so the derived key is identical on every validator.
    pub fn tribute_offer_key_material(&self) -> TributeOfferKeyMaterial<'_> {
        TributeOfferKeyMaterial {
            tribute_offer_private_key: &self.tribute_offer_secret,
            salt: &outbe_tee::OFFER_HKDF_SALT,
        }
    }

    /// Offer decrypt key material using an externally-supplied secret (the
    /// DKG-derived offer secret) with the fixed protocol salt
    /// [`outbe_tee::OFFER_HKDF_SALT`] - the same non-secret domain value clients
    /// use, shared by the dev and DKG-derived offer keys alike.
    pub fn tribute_offer_key_material_with<'a>(
        &'a self,
        secret: &'a [u8; 32],
    ) -> TributeOfferKeyMaterial<'a> {
        TributeOfferKeyMaterial {
            tribute_offer_private_key: secret,
            salt: &outbe_tee::OFFER_HKDF_SALT,
        }
    }

    /// `report_data = keccak256(noise_static_pub || recipient_x25519_pub ||
    /// attestation_pub)` - binds the cleartext quote keys to the attestation. The
    /// first 32 bytes of the SGX 64-byte report_data carry this value, so the
    /// host can verify the binding against the value embedded in the real quote.
    pub fn report_data_binding(
        noise_public: &[u8; 32],
        tribute_offer_public: &[u8; 32],
        attestation_pub: &[u8; 32],
    ) -> B256 {
        let mut preimage = Vec::with_capacity(96);
        preimage.extend_from_slice(noise_public);
        preimage.extend_from_slice(tribute_offer_public);
        preimage.extend_from_slice(attestation_pub);
        keccak256(&preimage)
    }

    fn report_data(&self) -> B256 {
        Self::report_data_binding(
            &self.noise_public,
            &self.tribute_offer_public,
            &self.attestation_pub,
        )
    }

    /// The detected attestation environment (hardware vs unattested).
    pub fn attestation_type(&self) -> &AttestationType {
        &self.attest_type
    }

    /// Build the SGX quote response. The `quote_body` is the real DCAP quote
    /// generated at startup (empty when unattested). `nonce` is unused for
    /// freshness here - the channel's freshness comes from the Noise-IK handshake
    /// that pins the attested static key.
    pub fn quote(&self, _nonce: [u8; 32]) -> EnclaveResponse {
        EnclaveResponse::Quote {
            mrenclave: self.mrenclave,
            mrsigner: self.mrsigner,
            isv_svn: self.isv_svn,
            report_data: self.report_data(),
            recipient_x25519_pub: self.tribute_offer_public,
            attestation_pub: self.attestation_pub,
            noise_static_pub: self.noise_public,
            quote_body: Vec::new(),
            attestation: self.attest_type.label(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off SGX hardware (CI / gramine-direct / bare) the enclave MUST run
    /// unattested: empty quote and zero measurements. It must never fabricate a
    /// quote or measurements (the old mock did exactly
    /// that - `mock-gramine-direct-quote` + `[0xE1;32]`/`[0x51;32]`).
    #[test]
    fn unattested_when_no_sgx_hardware() {
        let keys = EnclaveKeys::new([0x07; 32], Some([0x01; 32])).expect("key init off-hardware");
        assert_eq!(keys.mrenclave, UNATTESTED_MEASUREMENT);
        assert_eq!(keys.mrsigner, UNATTESTED_MEASUREMENT);
        assert_eq!(keys.isv_prod_id, 0);
        assert_eq!(keys.isv_svn, 0);
        match keys.quote([0u8; 32]) {
            EnclaveResponse::Quote {
                quote_body,
                mrenclave,
                ..
            } => {
                assert!(quote_body.is_empty(), "no fabricated quote bytes");
                assert_eq!(mrenclave, UNATTESTED_MEASUREMENT);
            }
            other => panic!("expected Quote, got {other:?}"),
        }
    }

    /// `report_data` binds the cleartext public keys regardless of attestation.
    #[test]
    fn report_data_binds_public_keys() {
        let keys = EnclaveKeys::new([0x09; 32], Some([0x02; 32])).expect("key init off-hardware");
        let expect = EnclaveKeys::report_data_binding(
            &keys.noise_public(),
            &keys.tribute_offer_public(),
            &keys.attestation_pub(),
        );
        match keys.quote([0u8; 32]) {
            EnclaveResponse::Quote { report_data, .. } => assert_eq!(report_data, expect),
            other => panic!("expected Quote, got {other:?}"),
        }
    }

    /// Pin the REPORT_DATA preimage byte order. The canonical layout is
    /// `keccak256(noise_static || recipient_x25519 || attestation)`; the host
    /// (`outbe-tee::client::verify_quote`) recomputes it in the SAME order, so a
    /// drift on either side breaks the channel - this test freezes it.
    #[test]
    fn report_data_preimage_order_is_pinned() {
        let noise = [1u8; 32];
        let offer = [2u8; 32];
        let attest = [3u8; 32];
        let got = EnclaveKeys::report_data_binding(&noise, &offer, &attest);

        let mut canonical = Vec::new();
        canonical.extend_from_slice(&noise);
        canonical.extend_from_slice(&offer);
        canonical.extend_from_slice(&attest);
        assert_eq!(
            got,
            keccak256(&canonical),
            "canonical order is noise||offer||attest"
        );

        // Any other field order yields a different binding.
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&noise);
        swapped.extend_from_slice(&attest);
        swapped.extend_from_slice(&offer);
        assert_ne!(got, keccak256(&swapped));
    }

    /// All public identity keys are persistent for one sealed seed, while a
    /// different seed produces a distinct identity. Ed25519 signatures verify
    /// against the advertised persistent public key.
    #[test]
    fn enclave_identity_keys_are_seed_stable_and_ed25519_is_real() {
        let k1 = EnclaveKeys::new([0x07; 32], Some([0x01; 32])).expect("k1");
        let k2 = EnclaveKeys::new([0x07; 32], Some([0x01; 32])).expect("k2");
        let k3 = EnclaveKeys::new([0x07; 32], Some([0x02; 32])).expect("k3");
        assert_eq!(k1.attestation_pub(), k2.attestation_pub());
        assert_eq!(k1.noise_public(), k2.noise_public());
        assert_eq!(k1.tribute_offer_public(), k2.tribute_offer_public());
        assert_ne!(k1.attestation_pub(), k3.attestation_pub());
        assert_ne!(k1.noise_public(), k3.noise_public());
        assert_ne!(k1.tribute_offer_public(), k3.tribute_offer_public());
        assert_ne!(k1.attestation_pub(), [0u8; 32]);

        // A signature verifies against the advertised public key.
        let msg = b"outbe/tee/test-attestation-msg";
        let tag = k1.sign_attestation(msg);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&k1.attestation_pub()).expect("vk");
        let sig = ed25519_dalek::Signature::from_bytes(&tag);
        vk.verify_strict(msg, &sig)
            .expect("attestation signature verifies");
        // Wrong key must not verify.
        let vk3 = ed25519_dalek::VerifyingKey::from_bytes(&k3.attestation_pub()).expect("vk3");
        assert!(vk3.verify_strict(msg, &sig).is_err());
    }

    #[test]
    fn tee_bls_identity_v1_has_a_known_answer() {
        let keys = EnclaveKeys::new([0x07; 32], Some([0x01; 32])).expect("key init");
        assert_eq!(
            hex::encode(keys.tee_bls_public_bytes()),
            "b6178141d30a5a91df599cf9a9b089651b1f7f25945a51a4cd02542276b43a30815322d7a002335ca563124e86f624ce",
            "seed-to-BLS mapping changed; use an explicit identity migration"
        );
    }
}
