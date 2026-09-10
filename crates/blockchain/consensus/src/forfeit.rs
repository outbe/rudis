//! Deterministic proposer-forfeit reason taxonomy.
//!
//! A proposer that cannot legitimately build a block must forfeit its slot
//! with a deterministic, structured reason - the same set of reasons across
//! every validator. The reason drives the `outbe_proposer_forfeit_total{reason}`
//! counter (see [`crate::metrics::record_proposer_forfeit`]).
//!
//! Adding a new variant is a metric-schema change: the label value is part of
//! the observable contract. The `proposer_forfeit_reason_label_is_stable_across_renames`
//! test pins each label string so reviewers see a test failure when a label
//! mutates inadvertently.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProposerForfeitReason {
    /// Direct-parent proof was not available within budget - neither
    /// finalization nor certified-notarization, and the bounded remote fetch
    /// did not return a usable proof in time.
    ParentProofUnavailable,
    /// Genesis bootstrap path: block 1 cannot be proposed because the DKG
    /// boundary artifact for epoch 0 is not yet ready.
    GenesisDkgBoundaryNotReady,
    /// Local `HybridScheme::recover_proof` returned `None` while the
    /// quorum threshold was satisfied. The proposer forfeits rather than
    /// stalling the chain or emitting
    /// proof-less metadata.
    VrfRecoverFailedUnderQuorum,
}

impl ProposerForfeitReason {
    /// Stable metric-label string. **Do not rename without a coordinated
    /// metric-schema change** - operators alert on these values.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ParentProofUnavailable => "parent_proof_unavailable",
            Self::GenesisDkgBoundaryNotReady => "genesis_dkg_boundary_not_ready",
            Self::VrfRecoverFailedUnderQuorum => "vrf_recover_failed_under_quorum",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins every label string. A future variant rename must update this
    /// test and acknowledge the metric-schema change.
    #[test]
    fn proposer_forfeit_reason_label_is_stable_across_renames() {
        assert_eq!(
            ProposerForfeitReason::ParentProofUnavailable.label(),
            "parent_proof_unavailable"
        );
        assert_eq!(
            ProposerForfeitReason::GenesisDkgBoundaryNotReady.label(),
            "genesis_dkg_boundary_not_ready"
        );
        assert_eq!(
            ProposerForfeitReason::VrfRecoverFailedUnderQuorum.label(),
            "vrf_recover_failed_under_quorum"
        );
    }
}
