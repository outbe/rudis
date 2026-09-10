//! V2 verifier error taxonomy.
//!
//! Each variant maps to a specific A4 validation-rule failure. Operators
//! depend on the variant names + Display strings for alerting; the `Debug`
//! form is also exposed via the verifier's structured logs.
//!
//! `#[non_exhaustive]` - callers must always include a wildcard arm so a
//! future + variant addition does not require synchronized
//! downstream edits.

use alloy_primitives::B256;

/// Failure modes surfaced by [`crate::verify_v2_proof`].
///
/// Each variant corresponds to a specific validation rule. The set
/// is intentionally narrow so reviewers and downstream evidence wrappers
/// can branch
/// on the exact failure class.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum V2VerifyError {
    // -- Structural / codec ------------------------------------------------
    /// Encoded `HybridCertificate` failed to decode against the active
    /// committee size.
    #[error("certificate decode failed: {0}")]
    Decode(commonware_codec::Error),
    /// Decoded certificate carries trailing bytes after the canonical
    /// `HybridCertificate` body. The verifier forbids any trailing bytes.
    #[error("certificate has trailing bytes after canonical HybridCertificate body")]
    TrailingBytes,
    /// Encoded proof is not a `HybridCertificate` - for example, a bare
    /// `Notarization` wire envelope or a threshold-only certificate. The
    /// V2 verifier accepts only the Hybrid form.
    #[error("proof is not a HybridCertificate: {reason}")]
    NonHybridEncoding { reason: &'static str },

    // -- Quorum / signer-bitmap consistency --------------------------------
    /// Certificate dropped below the simplex `N3f1` quorum required by the
    /// committee size.
    #[error("certificate below quorum: {signers}/{quorum}")]
    BelowQuorum { signers: usize, quorum: usize },
    /// Metadata `signer_bitmap` does not match the bitmap reconstructed
    /// from the decoded certificate's `signers` set.
    #[error("signer bitmap mismatch: {reason}")]
    BitmapMismatch { reason: &'static str },
    /// A signer index referenced by the certificate is outside
    /// `0..committee_size`.
    #[error("signer index {index} out of range for committee of size {committee_size}")]
    SignerIndexOutOfRange { index: u32, committee_size: usize },
    /// The decoded certificate contains the same signer index twice.
    #[error("duplicate signer index in certificate: {index}")]
    DuplicateSigner { index: u32 },

    // -- BLS aggregate vote ------------------------------------------------
    /// Aggregated BLS MinPk vote signature failed verification.
    #[error("BLS aggregate vote signature failed verification")]
    BlsAggregateInvalid,

    // -- VRF threshold proof -----------------------------------------------
    /// `VrfProof` decoded but is structurally malformed (e.g., zero
    /// signature length, version-byte rejection in the payload).
    #[error("VRF proof structurally malformed")]
    MalformedVrfProof,
    /// `cert.vrf_proof.material_version` differs from
    /// `metadata.vrf_material_version` or from `snapshot.vrf_material_version`.
    #[error("VRF material version mismatch: expected {expected}, got {actual}")]
    WrongVrfMaterialVersion { expected: u64, actual: u64 },
    /// `metadata.vrf_group_public_key_hash` differs from
    /// `keccak256(snapshot.vrf_group_public_key_bytes)`.
    #[error("VRF group public key hash mismatch: expected {expected}, got {actual}")]
    WrongVrfGroupKeyHash { expected: B256, actual: B256 },
    /// VRF verification was attempted under a namespace other than
    /// [`crate::hybrid_seed_namespace`] (defence-in-depth - the
    /// verifier hard-codes the namespace, so this only triggers if an
    /// upstream caller smuggled a different one).
    #[error("VRF namespace differs from hybrid_seed_namespace")]
    WrongVrfNamespace,
    /// VRF seed round (`Round(epoch, view).encode()`) differs from the
    /// `(metadata.epoch, metadata.view)` round the verifier expected.
    #[error(
        "VRF seed round mismatch: expected Round(epoch={expected_epoch}, view={expected_view})"
    )]
    WrongVrfSeedRound {
        expected_epoch: u64,
        expected_view: u64,
    },
    /// Threshold VRF proof failed verification against the active VRF
    /// group public key under [`crate::hybrid_seed_namespace`].
    #[error("VRF threshold signature failed verification")]
    InvalidVrfSignature,

    // -- Exact-parent / accounting binding ---------------------------------
    /// `metadata.finalized_block_number` differs from the expected accounted
    /// parent block number (derived from `header_parent_hash` + chain state).
    #[error("accounted parent block number mismatch: expected {expected}, got {actual}")]
    WrongAccountedNumber { expected: u64, actual: u64 },
    /// `metadata.finalized_block_hash` differs from `header_parent_hash`.
    /// Exact-parent rule: the verifier rejects any metadata that
    /// does not target the immediate parent of the block under verification.
    #[error("accounted parent block hash mismatch: expected {expected}, got {actual}")]
    WrongAccountedHash { expected: B256, actual: B256 },

    // -- Proof binding to metadata / committee snapshot --------------------
    /// The certificate's embedded `proposal.payload` differs from
    /// `metadata.finalized_block_hash` - the proof attests a different
    /// payload than the metadata claims.
    #[error("proof domain mismatch: cert payload {actual}, metadata hash {expected}")]
    WrongProofDomain { expected: B256, actual: B256 },
    /// Caller passed no committee snapshot (or an empty one) for the
    /// metadata's `(epoch, committee_set_hash)`.
    #[error("committee snapshot missing for the metadata's epoch/committee_set_hash")]
    CommitteeSnapshotMissing,
    /// `metadata.committee_set_hash` differs from the canonical
    /// `committee_set_hash_v2(metadata.finalized_epoch, snapshot)`.
    #[error("committee_set_hash mismatch: expected {expected}, got {actual}")]
    CommitteeSetHashMismatch { expected: B256, actual: B256 },

    // -- missed_proposers - V2 always empty --------------------------------
    /// V2 protocol invariant: `metadata.missed_proposers` MUST be empty.
    /// Any non-empty list rejects pre-mutation, for BOTH `Finalization`
    /// and `CertifiedNotarization`.
    #[error("metadata.missed_proposers must be empty in V2, got {count} entries")]
    NonEmptyMissedProposers { count: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Pins that every variant has a distinct, non-empty `Display` string.
    /// Operators alert on these strings; collision or empty string would
    /// silently break dashboards.
    #[test]
    fn all_variants_have_distinct_display() {
        let samples: Vec<V2VerifyError> = vec![
            V2VerifyError::Decode(commonware_codec::Error::EndOfBuffer),
            V2VerifyError::TrailingBytes,
            V2VerifyError::NonHybridEncoding {
                reason: "test reason",
            },
            V2VerifyError::BelowQuorum {
                signers: 2,
                quorum: 3,
            },
            V2VerifyError::BitmapMismatch { reason: "len" },
            V2VerifyError::SignerIndexOutOfRange {
                index: 5,
                committee_size: 3,
            },
            V2VerifyError::DuplicateSigner { index: 1 },
            V2VerifyError::BlsAggregateInvalid,
            V2VerifyError::MalformedVrfProof,
            V2VerifyError::WrongVrfMaterialVersion {
                expected: 1,
                actual: 2,
            },
            V2VerifyError::WrongVrfGroupKeyHash {
                expected: B256::ZERO,
                actual: B256::with_last_byte(1),
            },
            V2VerifyError::WrongVrfNamespace,
            V2VerifyError::WrongVrfSeedRound {
                expected_epoch: 0,
                expected_view: 1,
            },
            V2VerifyError::InvalidVrfSignature,
            V2VerifyError::WrongAccountedNumber {
                expected: 41,
                actual: 42,
            },
            V2VerifyError::WrongAccountedHash {
                expected: B256::ZERO,
                actual: B256::with_last_byte(1),
            },
            V2VerifyError::WrongProofDomain {
                expected: B256::ZERO,
                actual: B256::with_last_byte(1),
            },
            V2VerifyError::CommitteeSnapshotMissing,
            V2VerifyError::CommitteeSetHashMismatch {
                expected: B256::ZERO,
                actual: B256::with_last_byte(1),
            },
            V2VerifyError::NonEmptyMissedProposers { count: 1 },
        ];
        assert_eq!(
            samples.len(),
            20,
            "must cover all 20 V2VerifyError variants"
        );

        let mut seen = BTreeSet::new();
        for sample in &samples {
            let display = format!("{sample}");
            assert!(!display.is_empty(), "variant has empty Display: {sample:?}");
            assert!(
                seen.insert(display.clone()),
                "duplicate Display string across variants: {display}"
            );
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn variants_are_send_sync_static() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<V2VerifyError>();
    }
}
