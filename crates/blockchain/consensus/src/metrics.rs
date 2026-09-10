//! Prometheus metrics for Outbe consensus.
//!
//! These metrics are exposed via reth's `--metrics` endpoint and use the global
//! `metrics` crate recorder. No additional setup is needed beyond reth's built-in
//! Prometheus exporter.

use metrics::{counter, gauge, histogram};
use std::time::Duration;

/// Record a block proposed by this node.
pub fn record_block_proposed(block_number: u64) {
    counter!("outbe_blocks_proposed_total").increment(1);
    gauge!("outbe_proposed_height").set(block_number as f64);
}

/// Record a finalized Simplex view.
pub fn record_block_finalized(view: u64, signers: usize, total: usize) {
    gauge!("outbe_finalized_view").set(view as f64);
    gauge!("outbe_validator_count").set(total as f64);

    if total > 0 {
        let rate = signers as f64 / total as f64;
        gauge!("outbe_participation_rate").set(rate);
    }
}

/// Record skipped views (missed proposers).
pub fn record_views_skipped(count: u64) {
    counter!("outbe_views_skipped_total").increment(count);
}

/// Record the highest Simplex view this node has observed activity for.
///
/// Unlike `outbe_finalized_view` (which freezes during a stall), this gauge
/// advances on every view-bearing activity - notarize/certify/finalize votes and
/// nullification certificates - so it keeps moving while a view-timeout storm
/// nullifies views without finalizing any. The gap
/// `outbe_current_view - outbe_finalized_view` is the primary consensus-stall
/// signal: a sustained non-zero gap means views are advancing but nothing is
/// finalizing. Cheap (one atomic gauge set); safe to call on the voter task.
pub fn record_current_view(view: u64) {
    gauge!("outbe_current_view").set(view as f64);
}

/// Record a nullified (view-timed-out / skipped) Simplex view.
///
/// Incremented when a `Nullification` certificate is observed. A rising rate
/// means leaders are repeatedly failing to deliver proposals in time
/// (network turbulence, an offline/byzantine leader run, or a liveness fault),
/// which `outbe_finalized_view` alone cannot show.
pub fn record_view_nullified() {
    counter!("outbe_views_nullified_total").increment(1);
}

/// Record a finalized event dropped before block resolution.
pub fn record_finalization_dropped(reason: FinalizationDropReason) {
    counter!("outbe_finalization_dropped_total", "reason" => reason.label()).increment(1);
}

/// Record a full marshal-resolution retry cycle that exhausted without
/// resolving a finalized block.
///
/// A finalized block is fetchable from any honest peer, so the actor keeps
/// retrying rather than downing a healthy validator on a transient all-peers
/// P2P stall. A SUSTAINED non-zero rate is the operator alarm: the block is
/// unavailable network-wide or local state has diverged - investigate, because
/// the actor (correctly) cannot advance finalization past an unresolved block.
pub fn record_finalization_resolution_stalled() {
    counter!("outbe_finalization_resolution_stalled_total").increment(1);
}

/// Record a pre-finalization canonical-head reorg at the same height.
///
/// Expected on view timeout / leader rotation; a sustained non-zero rate
/// indicates network turbulence (frequent view changes near the tip).
pub fn record_executor_head_flip() {
    counter!("outbe_executor_head_flip_total").increment(1);
}

/// Record a rejected `update_head` at finalized height with a hash that
/// conflicts with the committed finalized hash. Non-zero is a protocol alarm.
pub fn record_executor_head_finalized_conflict() {
    counter!("outbe_executor_head_finalized_conflict_total").increment(1);
}

/// Record a canonical-head move to a strictly lower height
/// (parent switch onto a shorter pre-finalization branch).
pub fn record_executor_head_rollback() {
    counter!("outbe_executor_head_rollback_total").increment(1);
}

/// Record an attempted finalized rewrite at the current finalized height
/// with a different digest. Always ignored by the executor's monotonic
/// guard; a non-zero value is a protocol-invariant alarm and must be
/// investigated.
pub fn record_executor_finalized_conflict() {
    counter!("outbe_executor_finalized_conflict_total").increment(1);
}

/// Record a stale finalize delivery below the committed finalized height.
/// Always ignored; non-zero indicates duplicate or out-of-order marshal
/// delivery and is mostly informational.
pub fn record_executor_finalized_stale() {
    counter!("outbe_executor_finalized_stale_total").increment(1);
}

/// Record the current epoch number.
pub fn record_epoch(epoch: u64) {
    gauge!("outbe_epoch_number").set(epoch as f64);
}

/// Record the Commonware P2P peer-manager *tracked peer-set* size.
///
/// This is the number of peers the peer-manager has registered/tracked for the
/// current set (primary + secondary tiers), NOT the count of live TCP
/// connections - the commonware network layer does not expose a live-connection
/// count at this seam. Operators must read it as membership, not connectivity:
/// it does not drop when peers disconnect, so it is not a stall/partition
/// signal on its own. Pair it with `outbe_current_view` vs `outbe_finalized_view`
/// for liveness diagnosis.
pub fn record_commonware_p2p_active_peers(count: usize) {
    gauge!("commonware_p2p_tracked_peer_set_size").set(count as f64);
}

/// Record consensus tip vs Reth provider canonical-state readiness.
pub fn record_consensus_reth_state(
    consensus_tip_height: u64,
    reth_head_height: u64,
    hash_match: bool,
) {
    let consensus_ahead = consensus_tip_height.saturating_sub(reth_head_height);
    let reth_ahead = reth_head_height.saturating_sub(consensus_tip_height);
    let readiness_gap =
        consensus_reth_readiness_gap_blocks(consensus_tip_height, reth_head_height, hash_match);

    gauge!("outbe_consensus_tip_block_height").set(consensus_tip_height as f64);
    gauge!("outbe_reth_provider_head_block_height").set(reth_head_height as f64);
    gauge!("outbe_consensus_ahead_blocks").set(consensus_ahead as f64);
    gauge!("outbe_reth_ahead_blocks").set(reth_ahead as f64);
    gauge!("outbe_consensus_reth_height_diff")
        .set(signed_height_diff(consensus_tip_height, reth_head_height) as f64);
    gauge!("outbe_consensus_reth_tip_hash_match").set(if hash_match { 1.0 } else { 0.0 });
    gauge!("outbe_consensus_tip_available_in_reth_provider").set(if hash_match {
        1.0
    } else {
        0.0
    });
    gauge!("outbe_consensus_reth_readiness_gap_blocks").set(readiness_gap as f64);
}

fn signed_height_diff(consensus_tip_height: u64, reth_head_height: u64) -> i64 {
    if consensus_tip_height >= reth_head_height {
        i64::try_from(consensus_tip_height - reth_head_height).unwrap_or(i64::MAX)
    } else {
        i64::try_from(reth_head_height - consensus_tip_height).map_or(i64::MIN, |diff| -diff)
    }
}

pub(crate) fn consensus_reth_readiness_gap_blocks(
    consensus_tip_height: u64,
    reth_head_height: u64,
    hash_match: bool,
) -> u64 {
    if hash_match {
        0
    } else {
        consensus_tip_height.saturating_sub(reth_head_height).max(1)
    }
}

/// Record DKG/reshare status.
/// 0 = idle, 1 = in progress, 2 = completed (then resets to idle), 3 = expired.
pub fn record_dkg_status(status: u8) {
    gauge!("outbe_dkg_status").set(status as f64);
}

/// Record a fail-closed VRF expiry event.
pub fn record_vrf_randomness_expired() {
    counter!("outbe_vrf_randomness_expired_total").increment(1);
    record_dkg_status(3);
}

/// Record a DKG reshare completion event.
pub fn record_reshare_completed() {
    counter!("outbe_reshares_completed_total").increment(1);
}

/// Record validators whose individual DKG/reshare share was publicly REVEALED
/// during the ceremony.
///
/// A validator offline during its DKG/reshare has its share evaluation revealed
/// in plaintext (the `feldman_desmedt` construction reveals a non-acking
/// player's share so the ceremony can still complete), permanently committed
/// on-chain in the `DealerLog` artifacts. A revealed share makes that
/// validator's VRF threshold partial publicly forgeable. This is bounded - VRF
/// drives leader election / fairness, not BFT safety (the BLS individual
/// aggregate vote stays authoritative, and the group secret is safe up to `2f`
/// reveals) - but a non-zero value is the operator's signal to rotate the
/// affected validator's consensus key. The per-validator identities are logged
/// at `WARN` on the `outbe::dkg` target.
pub fn record_dkg_revealed_shares(count: usize) {
    gauge!("outbe_dkg_revealed_shares").set(count as f64);
    counter!("outbe_dkg_revealed_shares_total").increment(count as u64);
}

/// Record deterministic degraded leader election due to missing or invalid VRF.
pub fn record_vrf_degraded_leader_selection() {
    counter!("outbe_vrf_degraded_leader_selection_total").increment(1);
}

/// The closed set of byzantine-equivocation kinds. Each carries its own telemetry
/// label, so the `outbe_byzantine_evidence_total{type=...}` metric and the
/// `outbe::slashing::equivocation` warn! field can only ever take one of these
/// three values - closing the unbounded label-cardinality hole that a free `&str`
/// parameter left open on a slashing-path counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EquivocationKind {
    ConflictingNotarize,
    ConflictingFinalize,
    NullifyFinalize,
}

impl EquivocationKind {
    /// The stable telemetry label (metric `type` value and warn! field). These
    /// strings are an external, operator-facing surface - do not change them.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ConflictingNotarize => "conflicting_notarize",
            Self::ConflictingFinalize => "conflicting_finalize",
            Self::NullifyFinalize => "nullify_finalize",
        }
    }
}

/// Record a byzantine evidence detection event under its typed, closed-set label.
pub fn record_byzantine_evidence(kind: EquivocationKind) {
    counter!("outbe_byzantine_evidence_total", "type" => kind.label()).increment(1);
}

/// Reason a finalized event was dropped before block resolution. Closed set so the
/// `outbe_finalization_dropped_total{reason=...}` label cannot drift or typo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalizationDropReason {
    MailboxClosed,
    StaleRound,
    SameRoundInconsistency,
    DuplicateRound,
}

impl FinalizationDropReason {
    /// Stable telemetry label - operator-facing surface, do not change.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MailboxClosed => "mailbox_closed",
            Self::StaleRound => "stale_round",
            Self::SameRoundInconsistency => "same_round_inconsistency",
            Self::DuplicateRound => "duplicate_round",
        }
    }
}

/// Reason an `Activity::Certification` was dropped by the reporter before
/// persistence. Closed set behind `outbe_certification_dropped_total{reason=...}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificationDropReason {
    VerifyFailed,
    SnapshotBuildFailed,
    MailboxClosed,
    StoreError,
}

impl CertificationDropReason {
    /// Stable telemetry label - operator-facing surface, do not change.
    pub const fn label(self) -> &'static str {
        match self {
            Self::VerifyFailed => "verify_failed",
            Self::SnapshotBuildFailed => "snapshot_build_failed",
            Self::MailboxClosed => "mailbox_closed",
            Self::StoreError => "store_error",
        }
    }
}

/// DKG boundary requirement decision, for proposer/verifier observability behind
/// `outbe_dkg_boundary_requirement_total{decision=...}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgBoundaryDecision {
    AlreadyCommitted,
    MustEmit,
    NoPending,
}

impl DkgBoundaryDecision {
    /// Stable telemetry label - operator-facing surface, do not change.
    pub const fn label(self) -> &'static str {
        match self {
            Self::AlreadyCommitted => "already_committed",
            Self::MustEmit => "must_emit",
            Self::NoPending => "no_pending",
        }
    }
}

/// Reason a DKG boundary requirement could not be derived from the parent
/// snapshot and bounded ancestry. Closed set behind
/// `outbe_dkg_boundary_unavailable_total{reason=...}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DkgBoundaryUnavailableReason {
    GenesisBoundaryNotReady,
    AncestryUnavailable,
}

impl DkgBoundaryUnavailableReason {
    /// Stable telemetry label - operator-facing surface, do not change.
    pub const fn label(self) -> &'static str {
        match self {
            Self::GenesisBoundaryNotReady => "genesis_boundary_not_ready",
            Self::AncestryUnavailable => "ancestry_unavailable",
        }
    }
}

/// Record an invalid threshold-VRF seed partial that was excluded from
/// recovery during attestation verification AND is identity-attributable to its
/// author (the rider identity signature verified). A non-zero value means a
/// committee member deliberately emitted a garbage `bls_seed_partial` on the
/// expected material version (byzantine); the verifier dropped the complete
/// attestation so it cannot poison `recover_proof`, and buffered slashable evidence for an external
/// watcher to submit.
pub fn record_invalid_vrf_partial() {
    counter!("outbe_invalid_vrf_partial_total").increment(1);
}

/// Record an invalid threshold-VRF seed partial whose rider identity signature
/// did NOT verify, so it cannot be attributed to the claimed signer - a
/// probable in-transit relay forgery. Its complete attestation is dropped before
/// quorum admission but never slashed.
pub fn record_forged_seed_partial() {
    counter!("outbe_forged_seed_partial_total").increment(1);
}

/// Record a complete vote+partial pair dropped before quorum admission.
pub fn record_vrf_partial_drop(verdict: &'static str, signer: u32) {
    counter!(
        "outbe_vrf_partial_dropped_total",
        "verdict" => verdict,
        "signer" => signer.to_string(),
    )
    .increment(1);
}

/// Record a finalized certificate whose embedded threshold-VRF proof did not
/// verify against the committee group key for its own round. Under the
/// atomic vote-plus-partial admission in attestation verification this must be zero; a
/// non-zero value is a hard alarm that an unverifiable proof reached the
/// finalized certificate and will fail the next height's mandatory V2 verify.
pub fn record_finalized_cert_invalid_vrf_proof() {
    counter!("outbe_finalized_cert_invalid_vrf_proof_total").increment(1);
}

/// Builder included exact-parent metadata in the Phase 1 system transaction.
pub fn record_parent_cert_included() {
    counter!("outbe_parent_cert_included_total").increment(1);
}

/// Builder produced a valid block without an eligible exact-parent certificate.
pub fn record_parent_cert_missing() {
    counter!("outbe_parent_cert_missing_total").increment(1);
}

/// Current exact-parent certificate handoff store entry count.
pub fn record_parent_cert_store_size(size: usize) {
    gauge!("outbe_parent_cert_store_size").set(size as f64);
}

/// Current `block_cache` entry count. Sampled on every bounded insert
/// so operators can verify the cap is enforced and alert on cache
/// growth that approaches `BLOCK_CACHE_MAX_ENTRIES`.
pub fn record_block_cache_size(size: usize) {
    gauge!("outbe_block_cache_size").set(size as f64);
}

/// Exact-parent certificate records dropped by age prune.
pub fn record_parent_cert_record_pruned(count: usize) {
    if count > 0 {
        counter!("outbe_parent_cert_record_pruned_total").increment(count as u64);
    }
}

/// Current height minus oldest retained exact-parent certificate record.
pub fn record_parent_cert_retained_depth(depth: u64) {
    gauge!("outbe_parent_cert_retained_depth").set(depth as f64);
}

/// `Activity::Certification` admitted by the reporter and persisted to the
/// certified-parent proof store.
pub fn record_certification_persisted() {
    counter!("outbe_certification_persisted_total").increment(1);
}

/// `Activity::Certification` dropped by the reporter before persistence.
/// Reasons:
/// - `"verify_failed"` - Notarization signature did not verify.
/// - `"store_error"` - durable proof-store write returned an error.
pub fn record_certification_dropped(reason: CertificationDropReason) {
    counter!("outbe_certification_dropped_total", "reason" => reason.label()).increment(1);
}

/// deterministic proposer-forfeit metric. See
/// [`crate::forfeit::ProposerForfeitReason`] for the closed reason set.
pub fn record_proposer_forfeit(reason: crate::forfeit::ProposerForfeitReason) {
    counter!("outbe_proposer_forfeit_total", "reason" => reason.label().to_string()).increment(1);
}

/// Convenience: proposer forfeit because no direct
/// parent proof (finalization, certified-notarization, or bounded fetch)
/// was available within budget.
pub fn record_parent_proof_unavailable_forfeit() {
    record_proposer_forfeit(crate::forfeit::ProposerForfeitReason::ParentProofUnavailable);
}

/// Proposer could not find a usable Phase 1 parent proof for the exact parent.
pub fn record_phase1_parent_proof_unavailable() {
    counter!("outbe_phase1_parent_proof_unavailable_total").increment(1);
}

/// the proposer's in-process selection store missed the direct-parent
/// proof but it was recovered from marshal's durable finalization archive,
/// avoiding a slot forfeit (post-restart / late-join / finalization lag).
pub fn record_parent_proof_recovered_from_marshal() {
    counter!("outbe_parent_proof_recovered_from_marshal_total").increment(1);
}

/// Proposer used a locally observed certified-notarization witness after the
/// bounded finalization wait expired.
pub fn record_phase1_used_cn_fallback(epoch: u64, view: u64) {
    counter!(
        "outbe_phase1_used_cn_fallback_total",
        "epoch" => epoch.to_string(),
        "view" => view.to_string()
    )
    .increment(1);
}

/// Time spent waiting for the finalization slot before either finalization won
/// or CN fallback was used.
pub fn record_phase1_finalization_wait_ms(duration: Duration) {
    histogram!("outbe_phase1_finalization_wait_ms").record(duration.as_secs_f64() * 1000.0);
}

/// Finalization arrived after a CN witness had already been observed.
pub fn record_phase1_finalization_record_arrived_after_cn(duration: Duration) {
    histogram!("outbe_phase1_finalization_record_arrived_after_cn_ms")
        .record(duration.as_secs_f64() * 1000.0);
}

/// DKG boundary requirement decision for proposer/verifier observability.
pub fn record_dkg_boundary_requirement(decision: DkgBoundaryDecision) {
    counter!("outbe_dkg_boundary_requirement_total", "decision" => decision.label()).increment(1);
}

/// Boundary requirement could not be derived from the parent snapshot and
/// bounded ancestry.
pub fn record_dkg_boundary_unavailable(reason: DkgBoundaryUnavailableReason) {
    counter!("outbe_dkg_boundary_unavailable_total", "reason" => reason.label()).increment(1);
}

/// A block carried a DKG boundary artifact after the same pending boundary had
/// already been committed in its parent ancestry.
pub fn record_dkg_boundary_duplicate_rejected() {
    counter!("outbe_dkg_boundary_duplicate_rejected_total").increment(1);
}

/// block-1 proposal cannot be built
/// because the DKG boundary artifact for epoch 0 is not ready.
pub fn record_genesis_dkg_boundary_not_ready_forfeit() {
    record_proposer_forfeit(crate::forfeit::ProposerForfeitReason::GenesisDkgBoundaryNotReady);
}

/// `HybridScheme::recover_proof`
/// returned `None` while quorum was met. Proposer forfeits the slot rather
/// than stalling Simplex or emitting proof-less metadata.
pub fn record_vrf_recover_failed_under_quorum() {
    record_proposer_forfeit(crate::forfeit::ProposerForfeitReason::VrfRecoverFailedUnderQuorum);
}

/// Real build + marshal cost of a proposal (elapsed since the proposer's
/// closure-level `propose_start`), before any min-block-time floor pad.
pub fn record_block_build_time(duration: Duration) {
    histogram!("outbe_block_build_time_ms").record(duration.as_secs_f64() * 1000.0);
}

/// Floor pad the proposer sleeps to reach `min_block_time` (the intended pad;
/// `0` on the case-C / floor-already-met no-wait path). Lets operators see, per
/// block, how much of the cadence is real build vs. liveness pacing.
pub fn record_block_wait_time(duration: Duration) {
    histogram!("outbe_block_wait_time_ms").record(duration.as_secs_f64() * 1000.0);
}

#[cfg(test)]
mod tests {
    use super::{
        consensus_reth_readiness_gap_blocks, CertificationDropReason, DkgBoundaryDecision,
        DkgBoundaryUnavailableReason, EquivocationKind, FinalizationDropReason,
    };

    /// Pins the byzantine-evidence telemetry labels. These strings are an external,
    /// operator-facing surface (the `outbe_byzantine_evidence_total{type=...}` metric
    /// and the `outbe::slashing::equivocation` warn! field) shared with dashboards,
    /// so a change must be deliberate, not an accidental rename.
    #[test]
    fn equivocation_kind_labels_are_stable() {
        assert_eq!(
            EquivocationKind::ConflictingNotarize.label(),
            "conflicting_notarize"
        );
        assert_eq!(
            EquivocationKind::ConflictingFinalize.label(),
            "conflicting_finalize"
        );
        assert_eq!(
            EquivocationKind::NullifyFinalize.label(),
            "nullify_finalize"
        );
    }

    /// Pins the drop/decision telemetry labels - external operator-facing surface
    /// (`outbe_finalization_dropped_total`, `outbe_certification_dropped_total`,
    /// `outbe_dkg_boundary_requirement_total`, `outbe_dkg_boundary_unavailable_total`).
    /// A change must be deliberate, not an accidental rename.
    #[test]
    fn telemetry_label_strings_are_stable() {
        assert_eq!(
            FinalizationDropReason::MailboxClosed.label(),
            "mailbox_closed"
        );
        assert_eq!(FinalizationDropReason::StaleRound.label(), "stale_round");
        assert_eq!(
            FinalizationDropReason::SameRoundInconsistency.label(),
            "same_round_inconsistency"
        );
        assert_eq!(
            FinalizationDropReason::DuplicateRound.label(),
            "duplicate_round"
        );

        assert_eq!(
            CertificationDropReason::VerifyFailed.label(),
            "verify_failed"
        );
        assert_eq!(
            CertificationDropReason::SnapshotBuildFailed.label(),
            "snapshot_build_failed"
        );
        assert_eq!(
            CertificationDropReason::MailboxClosed.label(),
            "mailbox_closed"
        );
        assert_eq!(CertificationDropReason::StoreError.label(), "store_error");

        assert_eq!(
            DkgBoundaryDecision::AlreadyCommitted.label(),
            "already_committed"
        );
        assert_eq!(DkgBoundaryDecision::MustEmit.label(), "must_emit");
        assert_eq!(DkgBoundaryDecision::NoPending.label(), "no_pending");

        assert_eq!(
            DkgBoundaryUnavailableReason::GenesisBoundaryNotReady.label(),
            "genesis_boundary_not_ready"
        );
        assert_eq!(
            DkgBoundaryUnavailableReason::AncestryUnavailable.label(),
            "ancestry_unavailable"
        );
    }

    #[test]
    fn readiness_gap_is_zero_when_provider_has_consensus_tip_hash() {
        assert_eq!(consensus_reth_readiness_gap_blocks(203, 201, true), 0);
    }

    #[test]
    fn readiness_gap_tracks_consensus_ahead_when_tip_hash_is_missing() {
        assert_eq!(consensus_reth_readiness_gap_blocks(203, 201, false), 2);
    }

    #[test]
    fn readiness_gap_marks_same_height_hash_mismatch_as_nonzero() {
        assert_eq!(consensus_reth_readiness_gap_blocks(203, 203, false), 1);
    }
}
