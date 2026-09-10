//! Wire-codec types for the Outbe Hybrid certificate.
//!
//! The codec format is part of the V2 consensus protocol surface: every byte
//! is observed by gossip, block header `extra_data` (via
//! `OutbeBlockArtifacts`), and the marshal archive. This clean-genesis format
//! makes the threshold VRF proof structurally mandatory.
//!
//! Layout (encoded with `commonware-codec`):
//!
//! * [`VrfProof<V>`] - `material_version: u64` (big-endian) || `V::Signature`.
//! * [`HybridCertificate<V>`] - `Signers` bitmap || aggregated BLS MinPk
//!   signature (96 bytes) || `VrfProof<V>`.
//!
//! The decoder rejects an empty signer set and a missing or truncated proof.

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{simplex::scheme::bls12381_threshold::vrf::Seed, types::Round};
use commonware_cryptography::bls12381::{
    self,
    primitives::{
        ops::aggregate,
        variant::{MinPk, Variant},
    },
};
use commonware_cryptography::certificate::Signers;

/// Verified threshold VRF proof sidecar for a consensus certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VrfProof<V: Variant> {
    pub material_version: u64,
    pub threshold_signature: V::Signature,
}

impl<V: Variant> Write for VrfProof<V> {
    fn write(&self, writer: &mut impl BufMut) {
        writer.put_u64(self.material_version);
        self.threshold_signature.write(writer);
    }
}

impl<V: Variant> Read for VrfProof<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        if reader.remaining() < 8 {
            return Err(Error::Invalid("VrfProof", "missing material version"));
        }
        let material_version = reader.get_u64();
        let threshold_signature = V::Signature::read(reader)?;
        Ok(Self {
            material_version,
            threshold_signature,
        })
    }
}

impl<V: Variant> EncodeSize for VrfProof<V> {
    fn encode_size(&self) -> usize {
        8 + V::Signature::SIZE
    }
}

/// Certificate assembled from a quorum of hybrid attestations.
///
/// Contains:
/// - Signer bitmap (who voted)
/// - Single aggregated BLS MinPk vote signature (96 bytes)
/// - Mandatory recovered BLS MinSig threshold VRF proof
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HybridCertificate<V: Variant> {
    /// Bitmap of participants that signed.
    pub signers: Signers,
    /// Aggregated BLS vote signature from individual MinPk signatures.
    pub bls_aggregated_vote: aggregate::Signature<MinPk>,
    /// Recovered threshold VRF proof. Foreign certificates are accepted only
    /// after the epoch-scoped scheme verifies this proof for the exact subject.
    pub vrf_proof: VrfProof<V>,
}

impl<V: Variant> Write for HybridCertificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.bls_aggregated_vote.write(writer);
        self.vrf_proof.write(writer);
    }
}

impl<V: Variant> EncodeSize for HybridCertificate<V> {
    fn encode_size(&self) -> usize {
        self.signers.encode_size()
            + aggregate::Signature::<MinPk>::SIZE
            + self.vrf_proof.encode_size()
    }
}

impl<V: Variant> Read for HybridCertificate<V> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, max_participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "HybridCertificate",
                "certificate contains no signers",
            ));
        }
        let bls_aggregated_vote = aggregate::Signature::<MinPk>::read(reader)?;
        let vrf_proof = VrfProof::<V>::read(reader)?;

        Ok(Self {
            signers,
            bls_aggregated_vote,
            vrf_proof,
        })
    }
}

impl<V: Variant> HybridCertificate<V> {
    /// Extract the VRF seed from this certificate for a given round.
    pub fn seed(&self, round: Round) -> Seed<V> {
        Seed::new(round, self.vrf_proof.threshold_signature)
    }

    /// Encoded raw bytes of the threshold VRF signature for downstream
    /// fingerprinting and degraded leader-selection fallbacks.
    pub fn raw_vrf_seed_bytes(&self) -> Vec<u8> {
        self.vrf_proof.threshold_signature.encode().to_vec()
    }
}

// Suppress an unused-import false positive when only the trait method
// `bls12381::Signature::SIZE` is needed transitively for `FixedSize`.
const _: fn() = || {
    let _ = <bls12381::Signature as FixedSize>::SIZE;
};
