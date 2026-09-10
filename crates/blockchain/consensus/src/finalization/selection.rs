//! Direct-parent proof selection for the proposer path.
//!
//! Replaces the V1 `FinalizationSelector::await_parent_cert` polling waiter
//! with an event-driven exact-parent lookup: finalization slot ->
//! certified-notarization slot. A certified-notarization record whose block
//! number is still `0` is a local exact-key witness. The live proposer path
//! waits briefly for the finalization slot to arrive and, only after that
//! bounded wait expires, promotes the owned CN clone with the caller's known
//! parent block number. The store record remains witness-only.
//!
//!, this module no longer calls
//! `validate_finalized_parent_attestation`: the writer side (the
//! [`crate::finalization::actor::FinalizationActor`] for the Finalization slot
//! and [`crate::reporter::OutbeReporter::handle_certification`] for the
//! CertifiedNotarization slot) is the trust boundary, and re-validating on
//! every proposer read added latency without changing the trust model.

use crate::finalization::parent_cert_store::{
    CertifiedParentProofKey, CertifiedParentProofRecord, FinalizedParentCertStore,
    ParentProofSelection,
};
use alloy_primitives::B256;
use std::time::{Duration, Instant};

pub const PHASE1_FINALIZATION_WAIT_MIN: Duration = Duration::from_millis(50);
pub const PHASE1_FINALIZATION_WAIT_DEFAULT: Duration = Duration::from_millis(250);

pub fn clamped_phase1_finalization_wait(requested: Duration, leader_timeout: Duration) -> Duration {
    let max = std::cmp::max(leader_timeout / 2, PHASE1_FINALIZATION_WAIT_MIN);
    std::cmp::min(std::cmp::max(requested, PHASE1_FINALIZATION_WAIT_MIN), max)
}

/// Direct-parent proof selector. Cheap to clone - internally just an `Arc`
/// handle on the underlying [`FinalizedParentCertStore`].
#[derive(Clone)]
pub struct ParentProofSelector {
    parent_cert_store: FinalizedParentCertStore,
}

impl ParentProofSelector {
    pub fn new(parent_cert_store: FinalizedParentCertStore) -> Self {
        Self { parent_cert_store }
    }

    /// Look up the best available direct-parent proof for the proposer.
    ///
    /// Preference order:
    /// 1. [`CertifiedParentProofStore::get_finalization`] - strong proof,
    ///    Simplex `Activity::Finalization`.
    /// 2. [`CertifiedParentProofStore::get_certified_notarization`] -
    ///    fallback proof, Simplex `Activity::Certification`.
    ///
    /// Returns `None` if `parent_block_number == 0` (genesis parent), neither
    /// slot holds a record for `parent_hash`, or the record's
    /// `finalized_block_number` does not equal `parent_block_number`. On a
    /// non-zero block-number mismatch the record is removed. CN records with
    /// block number `0` are retained as local witnesses.
    ///
    /// Non-blocking: this method does not poll, does not sleep, and does not
    /// `await` anything except the in-process store lock. The proposer
    /// (handler) is responsible for orchestrating any bounded remote fetch
    /// fallback and for emitting the
    /// `outbe_proposer_forfeit_total{reason="parent_proof_unavailable"}`
    /// metric on the no-proof terminal.
    pub fn select_direct_parent_proof(
        &self,
        parent_epoch: u64,
        parent_view: u64,
        parent_block_number: u64,
        parent_hash: B256,
    ) -> Option<CertifiedParentProofRecord> {
        let key = CertifiedParentProofKey::new(parent_epoch, parent_view, parent_hash);
        self.select_direct_parent_proof_by_key(key, parent_block_number)
    }

    /// Look up the best direct-parent proof by exact `(epoch, view, hash)` key.
    pub fn select_direct_parent_proof_by_key(
        &self,
        key: CertifiedParentProofKey,
        parent_block_number: u64,
    ) -> Option<CertifiedParentProofRecord> {
        // Genesis parent has no proof - block 1 uses the
        // `ConsensusHeaderArtifact::BoundaryOutcome` bootstrap path, not a
        // certified-parent proof. See handler.rs::build_block.
        if parent_block_number == 0 {
            return None;
        }

        match self
            .parent_cert_store
            .get_best_for_parent(key, parent_block_number)?
        {
            ParentProofSelection::Finalization(record) => {
                self.validate_parent_record(key, parent_block_number, record)
            }
            ParentProofSelection::CertifiedNotarization(_) => {
                tracing::debug!(
                    target: "outbe::finalization",
                    parent_block_number,
                    parent_hash = %key.block_hash,
                    parent_epoch = key.epoch,
                    parent_view = key.view,
                    "certified-notarization parent proof is witness-only until bounded finalization wait expires"
                );
                None
            }
        }
    }

    /// Live proposer selector. Finalization wins deterministically; a
    /// witness-only CN record is used only after an event-driven bounded wait.
    pub async fn select_direct_parent_proof_by_key_with_wait(
        &self,
        clock: &impl commonware_runtime::Clock,
        key: CertifiedParentProofKey,
        parent_block_number: u64,
        requested_wait: Duration,
    ) -> Option<CertifiedParentProofRecord> {
        if parent_block_number == 0 {
            return None;
        }

        // Cap the phase-1 finalization wait at the default leader timeout
        // (`DEFAULT_PROPOSAL_TIMEOUT` == `timing::DEFAULT_LEADER_TIMEOUT_MS`).
        // NOTE: this tracks the compile-time default, not a per-network
        // `genesis.json` `leaderTimeoutMs` override. If a chain widens the leader
        // timeout via genesis, this cap stays at the default; threading the
        // effective `bt.leader_timeout` here is a deliberate follow-up.
        let wait = clamped_phase1_finalization_wait(
            requested_wait,
            crate::config::DEFAULT_PROPOSAL_TIMEOUT,
        );
        let observed_cn_at = Instant::now();

        match self
            .parent_cert_store
            .get_best_for_parent(key, parent_block_number)?
        {
            ParentProofSelection::Finalization(record) => {
                self.validate_parent_record(key, parent_block_number, record)
            }
            ParentProofSelection::CertifiedNotarization(record) => {
                let mut revisions = self.parent_cert_store.subscribe_revisions();

                if let Some(record) = self.parent_cert_store.get_finalization(key) {
                    let elapsed = observed_cn_at.elapsed();
                    crate::metrics::record_phase1_finalization_wait_ms(elapsed);
                    crate::metrics::record_phase1_finalization_record_arrived_after_cn(elapsed);
                    return self.validate_parent_record(key, parent_block_number, record);
                }

                let timeout = clock.sleep(wait);
                let mut timeout = std::pin::pin!(timeout);

                loop {
                    // Biased select (top-to-bottom): the revision wake-up is checked
                    // before the timeout, the deterministic ordering this wait needs.
                    commonware_macros::select! {
                        changed = revisions.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            if let Some(record) = self.parent_cert_store.get_finalization(key) {
                                let elapsed = observed_cn_at.elapsed();
                                crate::metrics::record_phase1_finalization_wait_ms(elapsed);
                                crate::metrics::record_phase1_finalization_record_arrived_after_cn(elapsed);
                                return self.validate_parent_record(key, parent_block_number, record);
                            }
                        },
                        _ = &mut timeout => {
                            break;
                        },
                    }
                }

                let elapsed = observed_cn_at.elapsed();
                crate::metrics::record_phase1_finalization_wait_ms(elapsed);
                crate::metrics::record_phase1_used_cn_fallback(key.epoch, key.view);

                self.validate_parent_record(key, parent_block_number, record)
            }
        }
    }

    fn validate_parent_record(
        &self,
        key: CertifiedParentProofKey,
        parent_block_number: u64,
        record: CertifiedParentProofRecord,
    ) -> Option<CertifiedParentProofRecord> {
        // A `CertifiedNotarization` witness carries no block number - it is
        // resolved to `parent_block_number` at metadata time, so it is always
        // consistent here. A `Finalization` record must match the proposer's
        // parent height.
        if let Some(record_block_number) = record.finalized_block_number() {
            if record_block_number != parent_block_number {
                tracing::warn!(
                    target: "outbe::finalization",
                    parent_block_number,
                    record_block_number,
                    parent_hash = %key.block_hash,
                    parent_epoch = key.epoch,
                    parent_view = key.view,
                    "parent proof record has unexpected finalized_block_number; draining record and returning None"
                );
                if let Err(error) = self.parent_cert_store.remove(key) {
                    tracing::warn!(
                        target: "outbe::finalization",
                        parent_hash = %key.block_hash,
                        parent_epoch = key.epoch,
                        parent_view = key.view,
                        %error,
                        "failed to drain block-number-mismatched parent proof record"
                    );
                }
                return None;
            }
        }

        Some(record)
    }

    /// Access to the underlying store - needed by callers that want to wire a
    /// bounded remote-fetch resolver against the same
    /// proof slots the selector reads.
    pub fn parent_cert_store(&self) -> &FinalizedParentCertStore {
        &self.parent_cert_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalization::parent_cert_store::{
        CertifiedParentProofRecord, CertifiedParentProofStore, ProofKind,
    };
    use alloy_primitives::B256;
    use outbe_primitives::consensus_metadata::ParentParticipationProof;

    fn record(
        parent_hash: B256,
        block_number: u64,
        proof_type: ParentParticipationProof,
    ) -> CertifiedParentProofRecord {
        let kind = match proof_type {
            ParentParticipationProof::Finalization => ProofKind::Finalization {
                finalized_block_number: block_number,
            },
            ParentParticipationProof::CertifiedNotarization => ProofKind::CertifiedNotarization,
        };
        CertifiedParentProofRecord {
            kind,
            finalized_block_hash: parent_hash,
            stored_at_height: block_number,
            ..CertifiedParentProofRecord::default()
        }
    }

    #[test]
    fn select_returns_none_for_genesis_parent() {
        let store = FinalizedParentCertStore::new();
        let selector = ParentProofSelector::new(store);
        assert!(selector
            .select_direct_parent_proof(0, 0, 0, B256::ZERO)
            .is_none());
    }

    #[test]
    fn select_returns_finalization_slot_first() {
        let store = FinalizedParentCertStore::new();
        let hash = B256::with_last_byte(0xAA);
        store
            .put_certified_notarization(record(
                hash,
                7,
                ParentParticipationProof::CertifiedNotarization,
            ))
            .unwrap();
        store
            .put_finalization(record(hash, 7, ParentParticipationProof::Finalization))
            .unwrap();
        let selector = ParentProofSelector::new(store);
        let r = selector.select_direct_parent_proof(0, 0, 7, hash).unwrap();
        assert_eq!(r.proof_kind(), ParentParticipationProof::Finalization);
    }

    #[test]
    fn select_falls_back_to_certified_notarization() {
        let store = FinalizedParentCertStore::new();
        let hash = B256::with_last_byte(0xAA);
        store
            .put_certified_notarization(record(
                hash,
                9,
                ParentParticipationProof::CertifiedNotarization,
            ))
            .unwrap();
        // The store-level fallback returns the CN record when no finalization
        // is present for the exact key - it is the proposer's fallback slot.
        let key = CertifiedParentProofKey::new(0, 0, hash);
        let best = store.get_best_parent_proof(key).unwrap();
        assert_eq!(
            best.proof_kind(),
            ParentParticipationProof::CertifiedNotarization
        );
        // A CN witness carries no block number of its own; the selector
        // resolves its height to the known parent at metadata time.
        assert_eq!(best.finalized_block_number(), None);
        // The non-wait selector treats CN as witness-only and returns None.
        let selector = ParentProofSelector::new(store);
        assert!(selector.select_direct_parent_proof(0, 0, 9, hash).is_none());
    }

    #[test]
    fn select_keeps_zero_number_certified_notarization_as_witness_only() {
        let store = FinalizedParentCertStore::new();
        let hash = B256::with_last_byte(0xAA);
        store
            .put_certified_notarization(record(
                hash,
                0,
                ParentParticipationProof::CertifiedNotarization,
            ))
            .unwrap();
        let selector = ParentProofSelector::new(store);
        assert!(selector.select_direct_parent_proof(0, 0, 9, hash).is_none());
        let key = CertifiedParentProofKey::new(0, 0, hash);
        assert!(selector
            .parent_cert_store()
            .get_certified_notarization(key)
            .is_some());
    }

    #[test]
    fn select_drains_block_number_mismatched_record() {
        let store = FinalizedParentCertStore::new();
        let hash = B256::with_last_byte(0xAA);
        store
            .put_finalization(record(hash, 7, ParentParticipationProof::Finalization))
            .unwrap();
        let selector = ParentProofSelector::new(store);
        assert!(selector
            .select_direct_parent_proof(0, 0, 99, hash)
            .is_none());
        // Record drained from store.
        let key = CertifiedParentProofKey::new(0, 0, hash);
        assert!(selector.parent_cert_store().get_finalization(key).is_none());
    }

    #[test]
    fn select_drains_zero_number_finalization_record() {
        let store = FinalizedParentCertStore::new();
        let hash = B256::with_last_byte(0xAA);
        store
            .put_finalization(record(hash, 0, ParentParticipationProof::Finalization))
            .unwrap();
        let selector = ParentProofSelector::new(store);
        assert!(selector.select_direct_parent_proof(0, 0, 9, hash).is_none());
        // Zero is not a valid finalized parent number for a Phase 1 proof.
        let key = CertifiedParentProofKey::new(0, 0, hash);
        assert!(selector.parent_cert_store().get_finalization(key).is_none());
    }

    #[test]
    fn bounded_wait_promotes_zero_number_cn_clone_only_after_timeout() {
        use commonware_runtime::Runner as _;
        commonware_runtime::deterministic::Runner::timed(Duration::from_secs(5)).start(
            |context| async move {
                let store = FinalizedParentCertStore::new();
                let hash = B256::with_last_byte(0xAA);
                store
                    .put_certified_notarization(record(
                        hash,
                        0,
                        ParentParticipationProof::CertifiedNotarization,
                    ))
                    .unwrap();
                let selector = ParentProofSelector::new(store);
                let key = CertifiedParentProofKey::new(0, 0, hash);

                let r = selector
                    .select_direct_parent_proof_by_key_with_wait(
                        &context,
                        key,
                        9,
                        PHASE1_FINALIZATION_WAIT_MIN,
                    )
                    .await
                    .unwrap();

                assert_eq!(
                    r.proof_kind(),
                    ParentParticipationProof::CertifiedNotarization
                );
                // The CN witness carries no block number of its own; the
                // selector resolves its height to the known parent only at
                // metadata time.
                assert_eq!(r.finalized_block_number(), None);
                assert_eq!(r.to_v2_metadata(9).finalized_block_number, 9);
                // The store record remains a witness with no block number.
                let stored = selector
                    .parent_cert_store()
                    .get_certified_notarization(key)
                    .unwrap();
                assert!(stored.is_certification_witness());
                assert_eq!(stored.finalized_block_number(), None);
            },
        );
    }

    #[test]
    fn bounded_wait_prefers_finalization_if_it_arrives_after_cn() {
        use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _};
        commonware_runtime::deterministic::Runner::timed(Duration::from_secs(5)).start(
            |context| async move {
                let store = FinalizedParentCertStore::new();
                let hash = B256::with_last_byte(0xAA);
                let key = CertifiedParentProofKey::new(0, 0, hash);
                store
                    .put_certified_notarization(record(
                        hash,
                        0,
                        ParentParticipationProof::CertifiedNotarization,
                    ))
                    .unwrap();

                // `Context` is not `Clone` on commonware 2026.5.0; obtain a fresh
                // owned context for the spawned writer via `Supervisor::child`.
                let writer = store.clone();
                context.child("writer").spawn(move |ctx| async move {
                    ctx.sleep(Duration::from_millis(5)).await;
                    writer
                        .put_finalization(record(hash, 9, ParentParticipationProof::Finalization))
                        .unwrap();
                });

                let selector = ParentProofSelector::new(store);
                let r = selector
                    .select_direct_parent_proof_by_key_with_wait(
                        &context,
                        key,
                        9,
                        PHASE1_FINALIZATION_WAIT_DEFAULT,
                    )
                    .await
                    .unwrap();

                assert_eq!(r.proof_kind(), ParentParticipationProof::Finalization);
                assert_eq!(r.finalized_block_number(), Some(9));
            },
        );
    }

    #[test]
    fn finalization_wait_budget_is_clamped() {
        assert_eq!(
            clamped_phase1_finalization_wait(Duration::from_millis(0), Duration::from_millis(1200)),
            PHASE1_FINALIZATION_WAIT_MIN
        );
        assert_eq!(
            clamped_phase1_finalization_wait(
                Duration::from_millis(700),
                Duration::from_millis(1200)
            ),
            Duration::from_millis(600)
        );
    }
}
