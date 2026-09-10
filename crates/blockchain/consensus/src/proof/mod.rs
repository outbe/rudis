//! Low-level Outbe Hybrid certificate proof submodule.
//!
//! Single source of truth for:
//! * Hybrid certificate wire codec (`HybridCertificate`, `VrfProof`)
//! * V2 self-contained verifier (`verify_v2_proof`) - BLS aggregate vote + mandatory
//!   threshold VRF proof, no validator runtime required
//! * Canonical fingerprint helpers used by Rewards, the certified-parent proof store,
//!   and slashing evidence (`committee_set_hash_v2`, `canonical_signer_set_hash`,
//!   `canonical_vrf_proof_hash_v2`, `invalid_vrf_evidence_hash_v2`)
//! * V2 domain-separation constants (`OUTBE_HYBRID_SEED_NAMESPACE_V2`)
//!
//! This module intentionally avoids any reference to `crate::stack`,
//! `crate::validators`, `crate::hybrid::HybridScheme` private DKG state, or any
//! runtime/mailbox/marshal type so the same code is reused by the EVM executor
//! and full-node import paths via re-export.

pub mod committee;
pub(crate) mod committee_keys;
pub mod constants;
pub mod error;
pub mod fingerprint;
pub mod hybrid_wire;
pub mod late_finalize;
pub mod seed_partial;
pub mod verifier;

pub use committee::{
    build_committee_snapshot, CommitteeEntry, CommitteeSnapshot, SnapshotBuildError,
    OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN, OUTBE_COMMITTEE_SNAPSHOT_KEY_V2_DOMAIN,
    VRF_MATERIAL_VERSION_GENESIS,
};
pub use constants::{
    consensus_chain_id, finalize_namespace, hybrid_seed_namespace, init_consensus_chain_id,
    notarize_namespace, nullify_namespace, outbe_app_namespace, participant_set_commitment,
    seed_attest_namespace, seed_namespace_and_message, simplex_namespace, ConsensusChainIdError,
};
pub use error::V2VerifyError;
pub use fingerprint::{
    canonical_signer_set_hash, canonical_vrf_proof_hash_v2, committee_set_hash_v2,
    committee_snapshot_key, invalid_vrf_evidence_hash_v2,
};
pub use hybrid_wire::{HybridCertificate, VrfProof};
pub use late_finalize::verify_late_finalize_proof;
pub use seed_partial::{
    seed_partial_attest_message, verify_seed_partial_against_commitment,
    verify_seed_partial_attest, verify_seed_partial_attest_bytes, verify_seed_signature_plain,
};
pub use verifier::{
    simplex_n3f1_quorum, verify_v2_proof, verify_v2_proof_low_level, CommitteeSnapshotView,
    VerifiedProof, VoteBinding, VoteSubject,
};

// Generic re-exports of Simplex certificate envelope types. Callers parameterize
// them as `Notarization<HybridScheme<MinSig>, Digest>` /
// `Finalization<HybridScheme<MinSig>, Digest>` from `outbe-consensus`.
pub use commonware_consensus::simplex::types::{Finalization, Notarization};
