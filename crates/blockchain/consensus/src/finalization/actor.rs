//! `FinalizationActor` - single-task consumer of finalization events.
//!
//! Drains its unbounded mailbox in FIFO order and owns the production
//! per-finalization side effects:
//!
//! - Stale-round / duplicate / inconsistency replay classification
//! - Marshal-based block resolution with bounded retries
//! - Durable exact-parent certificate record persistence for Phase 1
//! - VRF seed propagation, forkchoice update, last_finalized bookkeeping
//! - Bridge consensus-status publication
//! - DKG header artifact recording
//! - Block-cache eviction below the new finalized height
//!
//! The actor writes the parent certificate store before publishing the finalized
//! view, so a proposer that can observe the new finalized parent can also recover
//! the exact-parent certificate needed for the successor block's Phase 1 system
//! transaction.

use std::sync::Arc;

use crate::finalization::committee_prelude::build_committee_prelude;
use commonware_cryptography::certificate::Provider as _;
use commonware_runtime::{Clock, Spawner};
use futures::{channel::mpsc, StreamExt};
use outbe_primitives::{
    consensus::{ConsensusData, ConsensusExecutionBridge, ConsensusStatus},
    error::Result,
};
use tracing::{debug, info, warn};

use crate::block::ConsensusBlock;
use crate::config::{FINALIZE_MAX_RETRIES, FINALIZE_RESOLUTION_TIMEOUT, FINALIZE_RETRY_DELAY};
use crate::digest::Digest;
use crate::finalization::ingress::{Finalized, Mailbox, Message};
use crate::finalization::parent_cert_store::{
    CertifiedParentProofRecord, CertifiedParentProofStore, FinalizedParentCertStore, ProofKind,
    CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
};
use crate::finalization::state::FinalizationViewHandle;
use crate::finalization::util::{
    classify_finalization, extract_header_artifact_from_block, retry_with_backoff,
    ReplayClassification,
};
use commonware_consensus::marshal::core::DigestFallback;

/// Bound on consensus-owned exact-parent certificate handoff retention.
///
/// The store is keyed by finalized block hash and only the Simplex context
/// parent is eligible for Phase 1. Retention remains bounded so stale local
/// recovery data cannot grow unbounded across restarts or missed slots.
pub const PARENT_CERT_KEEP_DEPTH: u64 = 256;
use crate::marshal_types::MarshalMailbox;
use crate::ocomp_retention::OcompRetentionHook;
use crate::vrf_safety::VrfSafetyGate;

use crate::finalization::block_cache::BlockCache;

/// Constructor inputs for the finalization actor. Bundled into a
/// single struct so the spawn site in `stack.rs` can be ergonomic.
pub struct FinalizationActorDeps {
    pub view: FinalizationViewHandle,
    pub block_cache: BlockCache,
    /// Marshal mailbox for resolving a finalized block not in the local cache.
    /// `Some` in production; only the rekey unit test (which calls
    /// `process_finalization` directly with an already-resolved block, never
    /// touching marshal) constructs the actor with `None`.
    pub marshal_mailbox: Option<MarshalMailbox>,
    pub bridge: Option<ConsensusExecutionBridge>,
    pub dkg_manager: crate::dkg_manager::Mailbox,
    pub vrf_safety: VrfSafetyGate,
    /// Hash-keyed per-finalized-block exact-parent certificate store.
    ///
    /// The actor writes one record per finalized block; the proposer waits only
    /// for the record whose hash equals the Simplex context parent.
    pub parent_cert_store: FinalizedParentCertStore,
    /// Per-epoch verifier scheme provider. The actor uses this to recompute
    /// canonical `committee_set_hash_v2` / `vrf_material_version` /
    /// `vrf_group_public_key_hash` for the finalized epoch's signer set so the
    /// finalization-slot record carries the same canonical fields that
    /// `OutbeReporter::handle_certification` writes on the certified-notarization
    /// slot. Without this, `get_best_parent_proof` would hand Phase 1 a record
    /// with `committee_set_hash = ZERO`, and snapshot lookup would miss.
    pub certificate_scheme_provider: crate::hybrid::HybridSchemeProvider<
        commonware_cryptography::bls12381::primitives::variant::MinSig,
    >,
    /// shared late-finalize signature store. On each finalization
    /// the actor rekeys the reporter-buffered (view-keyed) votes to the now-known
    /// block number and prunes targets that have left the inclusion window. The
    /// reporter records into it; the application handler reads it to pack the
    /// proposer artifact. Best-effort, process-local - never consensus state.
    pub late_sig_store: crate::finalization::late_sig_store::SharedLateFinalizeStore,
    /// Non-blocking node-local OCOMP finality notification. The production
    /// handle only enqueues the block; proof and journal work run in
    /// the node-owned retention worker.
    pub ocomp_retention: Arc<dyn OcompRetentionHook>,
}

/// FinalizationActor itself. Owns the receiver end of an unbounded
/// channel; the matching `Mailbox` is given to `OutbeReporter` so
/// finalization events flow voter -> reporter -> actor without ever
/// passing through the application handler's bounded mailbox.
pub struct FinalizationActor {
    rx: mpsc::UnboundedReceiver<Message>,
    deps: FinalizationActorDeps,
}

impl FinalizationActor {
    /// Construct an actor + paired mailbox. Both halves are returned
    /// so the caller (typically `stack.rs`) can hand the mailbox to
    /// the reporter and spawn the actor onto the supervisor's runtime.
    pub fn new(deps: FinalizationActorDeps) -> (Self, Mailbox) {
        let (tx, rx) = mpsc::unbounded::<Message>();
        let mailbox = Mailbox::from_sender(tx);
        (Self { rx, deps }, mailbox)
    }

    /// Run the actor's event loop. Returns `Err` on a fatal
    /// finalization error (same-round / same-height inconsistency, or
    /// marshal resolution exhaustion). Returns `Ok(())` if the mailbox
    /// closes cleanly during graceful shutdown.
    pub async fn run<E>(mut self, ctx: E) -> Result<()>
    where
        E: Spawner + Clock + Send + Sync + 'static,
    {
        info!(target: "outbe::finalization", "FinalizationActor started");
        while let Some(msg) = self.rx.next().await {
            match msg {
                Message::Finalized(f) => {
                    if let Err(error) = self.handle_finalized(&ctx, f).await {
                        tracing::error!(
                            target: "outbe::finalization",
                            %error,
                            "fatal finalization error; FinalizationActor shutting down"
                        );
                        return Err(outbe_primitives::error::PrecompileError::Fatal(format!(
                            "FinalizationActor fatal: {error}"
                        )));
                    }
                }
                // durable certified-notarization persistence, moved off the
                // Simplex voter task. The reporter built and verified the record
                // (including the parity-critical committee_set_hash) inline; this
                // actor performs only the synchronous MDBX commit. A write error
                // is metered + logged but NOT fatal - the certified-notarization
                // is a best-effort fallback witness (the proposer prefers the
                // finalization record and can recover from marshal), so dropping
                // one must not crash the single durable writer.
                Message::CertifiedNotarization(record) => {
                    match self
                        .deps
                        .parent_cert_store
                        .put_certified_notarization(record)
                    {
                        Ok(()) => crate::metrics::record_certification_persisted(),
                        Err(error) => {
                            crate::metrics::record_certification_dropped(
                                crate::metrics::CertificationDropReason::StoreError,
                            );
                            tracing::warn!(
                                target: "outbe::finalization",
                                %error,
                                "certified-notarization persist failed (off-thread)"
                            );
                        }
                    }
                }
            }
        }
        info!(target: "outbe::finalization", "FinalizationActor mailbox closed");
        Ok(())
    }

    /// Handle a production finalization notification by resolving the finalized
    /// block through marshal and then applying all finalization side effects in
    /// actor order.
    async fn handle_finalized(&self, clock: &impl Clock, finalized: Finalized) -> eyre::Result<()> {
        let digest = finalized.digest;
        let round = finalized.round;
        let view = round.view().get();
        debug!(?round, view, %digest, "finalization received");

        // Stale-round short-circuit (no marshal lookup needed for
        // historical rounds).
        {
            let view_snapshot = self.deps.view.read();
            if let Some(last_round) = view_snapshot.last_finalized_round {
                if round < last_round {
                    crate::metrics::record_finalization_dropped(
                        crate::metrics::FinalizationDropReason::StaleRound,
                    );
                    info!(
                        ?round,
                        ?last_round,
                        %digest,
                        "dropping stale finalized round before marshal resolution"
                    );
                    return Ok(());
                }
                if round == last_round {
                    if digest.0 != view_snapshot.forkchoice.finalized_block_hash {
                        crate::metrics::record_finalization_dropped(
                            crate::metrics::FinalizationDropReason::SameRoundInconsistency,
                        );
                        tracing::error!(
                            ?round,
                            %digest,
                            finalized_hash = %view_snapshot.forkchoice.finalized_block_hash,
                            "fatal same-round finalization inconsistency; stopping FinalizationActor"
                        );
                        return Err(eyre::eyre!(
                            "same-round finalization inconsistency at {:?}: \
                             new digest {digest} conflicts with finalized hash {}",
                            round,
                            view_snapshot.forkchoice.finalized_block_hash
                        ));
                    }

                    let proof_key =
                        crate::finalization::parent_cert_store::CertifiedParentProofKey::new(
                            round.epoch().get(),
                            round.view().get(),
                            digest.0,
                        );
                    if self
                        .deps
                        .parent_cert_store
                        .get_finalization(proof_key)
                        .is_some()
                    {
                        crate::metrics::record_finalization_dropped(
                            crate::metrics::FinalizationDropReason::DuplicateRound,
                        );
                        debug!(
                            ?round,
                            %digest,
                            "dropping duplicate finalized round before marshal resolution"
                        );
                        return Ok(());
                    }
                    debug!(
                        ?round,
                        %digest,
                        "replaying duplicate finalized round to repair missing parent certificate record"
                    );
                }
            }
        }

        // Fast path: proposer's own block in the shared cache.
        if let Some(block) = self.deps.block_cache.get_and_remove(&digest) {
            return self.process_finalization(finalized, block).await;
        }

        // Resolve via marshal with bounded retries and a per-attempt timeout.
        // `retry_with_backoff` lives in `finalization::util`.
        let Some(marshal) = self.deps.marshal_mailbox.clone() else {
            return Err(eyre::eyre!(
                "marshal mailbox required to resolve finalized block {digest} not in local cache"
            ));
        };

        // a finalized block is fetchable from any honest peer, so a full
        // retry cycle exhausting means an all-peers P2P stall - which is
        // transient. Keep retrying with a metric/alarm rather than returning the
        // node-fatal error that downs an otherwise-healthy validator on a
        // ~1-minute correlated outage. The actor (correctly) cannot advance
        // finalization past an unresolved block, so it stays parked here
        // retrying until the block resolves; a sustained
        // `outbe_finalization_resolution_stalled_total` rate is the operator's
        // signal that the block is unavailable network-wide or local state has
        // diverged. Only a missing marshal mailbox (a config error, above)
        // remains fatal.
        let cycle_budget = FINALIZE_RESOLUTION_TIMEOUT * FINALIZE_MAX_RETRIES
            + FINALIZE_RETRY_DELAY * (FINALIZE_MAX_RETRIES - 1);
        let mut stall_cycles: u64 = 0;
        loop {
            let marshal = marshal.clone();
            let resolve = move || {
                let marshal = marshal.clone();
                async move {
                    // 2026.5.0: `subscribe_by_digest` is SYNC and takes the
                    // digest first with an explicit `DigestFallback`. We have a
                    // trusted finalized round for this digest, so request the
                    // notarized proposal for `round` from peers when it is
                    // missing locally. The returned oneshot receiver is awaited.
                    let waiter =
                        marshal.subscribe_by_digest(digest, DigestFallback::FetchByRound { round });
                    waiter.await.map_err(|_| ())
                }
            };

            match retry_with_backoff(
                clock,
                resolve,
                FINALIZE_MAX_RETRIES,
                FINALIZE_RETRY_DELAY,
                FINALIZE_RESOLUTION_TIMEOUT,
            )
            .await
            {
                Ok(block) => return self.process_finalization(finalized, block).await,
                Err(failure) => {
                    stall_cycles += 1;
                    crate::metrics::record_finalization_resolution_stalled();
                    let last_finalized_number = self.deps.view.read().last_finalized_number;
                    tracing::warn!(
                        %digest,
                        ?round,
                        view,
                        attempts = failure.attempts,
                        last_failure = ?failure.last_kind,
                        stall_cycles,
                        cycle_budget_secs = cycle_budget.as_secs(),
                        last_finalized_number,
                        "finalized block not resolvable from any peer after a full retry cycle; \
                         the validator stays UP and keeps retrying. A sustained stall means \
                         the block is unavailable network-wide or local state has diverged."
                    );
                    // Loop and retry the next cycle. The per-attempt timeout
                    // already spaces attempts, so this is not a tight loop.
                }
            }
        }
    }

    /// Process a finalization for which we have the full block. This is the
    /// single production owner for parent-cert persistence, finalized view
    /// publication, bridge status, DKG artifacts, and finalized block-cache
    /// eviction.
    async fn process_finalization(
        &self,
        finalized: Finalized,
        block: ConsensusBlock,
    ) -> eyre::Result<()> {
        let digest = finalized.digest;
        let block_number = block.number();

        // Replay classification under a write lock so the read-modify-write
        // of the view's finalization fields is atomic.
        let mut view = self.deps.view.write();

        match classify_finalization(
            block_number,
            digest.0,
            view.last_finalized_number,
            view.forkchoice.finalized_block_hash,
        ) {
            ReplayClassification::HistoricalReplay => {
                debug!(
                    block_number,
                    last_finalized = view.last_finalized_number,
                    %digest,
                    "dropping replayed finalization (historical)"
                );
                return Ok(());
            }
            ReplayClassification::DuplicateReplay => {
                let proof_key =
                    crate::finalization::parent_cert_store::CertifiedParentProofKey::new(
                        finalized.round.epoch().get(),
                        finalized.round.view().get(),
                        digest.0,
                    );
                if self
                    .deps
                    .parent_cert_store
                    .get_finalization(proof_key)
                    .is_some()
                {
                    debug!(
                        block_number,
                        %digest,
                        "dropping replayed finalization (duplicate)"
                    );
                    return Ok(());
                }
                debug!(
                    block_number,
                    %digest,
                    "repairing missing parent certificate record for replayed finalization"
                );
            }
            ReplayClassification::FatalInconsistency => {
                tracing::error!(
                    block_number,
                    %digest,
                    finalized_hash = %view.forkchoice.finalized_block_hash,
                    "fatal same-height finalization inconsistency; stopping FinalizationActor"
                );
                return Err(eyre::eyre!(
                    "same-height finalization inconsistency at block {block_number}: \
                     new digest {digest} conflicts with finalized hash {}",
                    view.forkchoice.finalized_block_hash
                ));
            }
            ReplayClassification::New => {}
        }

        // Persist the per-finalized-block parent proof record before publishing
        // the finalized view. This closes the post-finalize / pre-child-build
        // crash window: any proposer that can observe the new finalized parent
        // can also recover its Phase 1 certificate record.
        //
        // The V2 canonical fields `committee_set_hash`, `vrf_material_version`,
        // and `vrf_group_public_key_hash` are computed here from the epoch's
        // `HybridScheme` so the finalization-slot record carries the same
        // canonical fields the certified-notarization writer
        // (`OutbeReporter::handle_certification`) writes via
        // `outbe_consensus::proof::committee_set_hash_v2`.
        // `ParentProofStore::get_best_parent_proof` returns the finalization
        // record first; if `committee_set_hash` here defaulted to `ZERO`, Phase
        // 1's snapshot lookup `committee_snapshot_key(epoch, ZERO)` would miss
        // the snapshot written by `apply_boundary_outcome` under the canonical
        // hash, even when the certified-notarization slot has the right value.
        let consensus_data = finalized.consensus_data.clone();

        // Persist the canonical parent-proof record before publishing the view,
        // closing the post-finalize / pre-child-build crash window. The V2
        // canonical fields match the certified-notarization writer. No `view`
        // access, so this is safe to call while the write guard is held.
        let (committee_set_hash, committee_size) =
            self.persist_finalization_record(&finalized, &consensus_data, digest, block_number)?;

        // Rekey the reporter's view-buffered late-finalize votes to this block
        // number and prune those outside the K-block inclusion window. No `view`
        // access.
        self.rekey_late_finalize_votes(
            &finalized,
            &consensus_data,
            digest,
            block_number,
            committee_set_hash,
            committee_size,
        );

        // Prune old parent-cert records and record store metrics. No `view` access.
        self.prune_parent_cert_store(block_number)?;

        view.last_finalized_round = Some(match view.last_finalized_round {
            Some(last_round) => std::cmp::max(last_round, finalized.round),
            None => finalized.round,
        });

        if let Some(seed) = finalized.vrf_seed {
            view.prev_randao = seed;
        } else {
            self.deps.vrf_safety.mark_degraded();
        }

        view.forkchoice.finalized_block_hash = digest.0;
        view.forkchoice.safe_block_hash = digest.0;
        view.forkchoice.head_block_hash = digest.0;

        view.last_finalized_number = block_number;
        view.last_timestamp_millis =
            std::cmp::max(view.last_timestamp_millis, block.timestamp_millis());

        // Drop the write lock before bridge/dkg work so later `build_block`
        // readers can proceed after the durable parent-cert handoff is visible.
        drop(view);

        self.publish_consensus_status(&finalized, &consensus_data, block_number);
        self.note_finalized_dkg_artifact(&block, digest, block_number);
        self.evict_finalized_block_cache();
        if let Err(error) = self.deps.ocomp_retention.reconcile_finalized(&block) {
            warn!(
                target: "outbe::finalization",
                block_number,
                block_hash = %digest.0,
                %error,
                "OCOMP finality notification failed locally; consensus finalization continues"
            );
        }

        Ok(())
    }

    /// Build and persist the canonical V2 finalization parent-proof record, and
    /// return the `(committee_set_hash, committee_size)` the late-finalize rekey
    /// needs. Does not touch the shared `view`. The V2 canonical fields are
    /// derived from the epoch's `HybridScheme` so the finalization-slot record
    /// matches the certified-notarization writer; a snapshot-build failure is an
    /// encode-invariant violation and fails the finalization deterministically
    /// rather than writing a record whose `committee_set_hash` would diverge.
    fn persist_finalization_record(
        &self,
        finalized: &Finalized,
        consensus_data: &ConsensusData,
        digest: Digest,
        block_number: u64,
    ) -> eyre::Result<(alloy_primitives::B256, usize)> {
        let encoded_certificate = consensus_data
            .finalized_certificate
            .encoded_certificate
            .clone();
        let finalized_epoch = finalized.round.epoch().get();
        let ordered_committee = consensus_data
            .finalized_certificate
            .ordered_committee
            .clone();
        // Captured before `ordered_committee` is moved into the proof record, for
        // the late-finalize store resolve.
        let committee_size = ordered_committee.len();
        let (committee_set_hash, vrf_material_version, vrf_group_public_key_hash) = match self
            .deps
            .certificate_scheme_provider
            .scoped(finalized.round.epoch())
        {
            Some(scheme) => {
                // Single canonical builder (shared with the resolver and reporter;
                // the DKG proposer is distinct - it carries a real polynomial hash).
                // Reconstructed from finalized metadata, so the snapshot's unused
                // `vrf_public_polynomial_hash` is `B256::ZERO` inside the helper.
                let prelude = build_committee_prelude(&scheme, &ordered_committee, finalized_epoch)
                    .map_err(|e| {
                        eyre::eyre!(
                            "finalization committee snapshot build failed at epoch \
                                 {finalized_epoch}: {e}"
                        )
                    })?;
                (
                    prelude.committee_set_hash,
                    prelude.vrf_material_version,
                    prelude.vrf_group_public_key_hash,
                )
            }
            None => {
                warn!(
                    target: "outbe::finalization",
                    epoch = finalized_epoch,
                    "no verifier scheme registered for finalized epoch - finalization \
                     record will carry default V2 canonical fields; Phase 1 snapshot lookup \
                     may miss"
                );
                (
                    alloy_primitives::B256::ZERO,
                    0,
                    alloy_primitives::B256::ZERO,
                )
            }
        };
        let snap = CertifiedParentProofRecord {
            format_version: CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
            kind: ProofKind::Finalization {
                finalized_block_number: block_number,
            },
            finalized_block_hash: digest.0,
            finalized_epoch,
            finalized_view: finalized.round.view().get(),
            parent_view: consensus_data.finalized_certificate.parent_view,
            ordered_committee,
            signer_bitmap: consensus_data.finalized_certificate.signer_bitmap.clone(),
            encoded_proof: encoded_certificate,
            committee_set_hash,
            vrf_material_version,
            vrf_group_public_key_hash,
            stored_at_height: block_number,
        };
        self.deps
            .parent_cert_store
            .put_finalization(snap)
            .map_err(|error| eyre::eyre!("persist finalization parent proof record: {error}"))?;
        Ok((committee_set_hash, committee_size))
    }

    /// Rekey the reporter's view-buffered late-finalize votes to the now-known
    /// `block_number` and prune targets outside the K-block inclusion window.
    /// Best-effort and process-local: a poisoned lock just skips the rekey
    /// (crediting nobody) and never stalls finalization. No `view` access.
    fn rekey_late_finalize_votes(
        &self,
        finalized: &Finalized,
        consensus_data: &ConsensusData,
        digest: Digest,
        block_number: u64,
        committee_set_hash: alloy_primitives::B256,
        committee_size: usize,
    ) {
        if let Ok(mut store) = self.deps.late_sig_store.lock() {
            // Canonical (epoch, view, parent_view) from the finalized certificate
            // so even a pure post-finalization vote (no pending entry) binds
            // correctly.
            store.resolve_finalized(
                finalized.round.epoch().get(),
                finalized.round.view().get(),
                consensus_data.finalized_certificate.parent_view,
                block_number,
                digest.0,
                committee_set_hash,
                committee_size,
            );
        }
    }

    /// Prune parent-cert records below the retention floor and record store
    /// metrics. No `view` access.
    fn prune_parent_cert_store(&self, block_number: u64) -> eyre::Result<()> {
        let pruned = self
            .deps
            .parent_cert_store
            .prune_below_height(block_number.saturating_sub(PARENT_CERT_KEEP_DEPTH))
            .map_err(|error| {
                eyre::eyre!("prune finalization parent certificate records: {error}")
            })?;
        crate::metrics::record_parent_cert_store_size(self.deps.parent_cert_store.len());
        crate::metrics::record_parent_cert_record_pruned(pruned);
        if let Some(oldest) = self.deps.parent_cert_store.oldest_stored_height() {
            crate::metrics::record_parent_cert_retained_depth(block_number.saturating_sub(oldest));
        } else {
            crate::metrics::record_parent_cert_retained_depth(0);
        }
        Ok(())
    }

    /// Publish a fresh `ConsensusStatus` to the bridge for RPC after durable
    /// persistence. The parent-cert store is the consensus handoff; this is only
    /// the RPC status view. Runs after the `view` write lock is released.
    fn publish_consensus_status(
        &self,
        finalized: &Finalized,
        consensus_data: &ConsensusData,
        block_number: u64,
    ) {
        if let Some(ref bridge) = self.deps.bridge {
            let vrf_safety = self.deps.vrf_safety.snapshot();
            let connected_peers = consensus_data
                .finalized_certificate
                .signer_bitmap
                .iter()
                .filter(|signed| **signed != 0)
                .count() as u32;
            bridge.set_consensus_status(ConsensusStatus {
                current_view: finalized.round.view().get(),
                connected_peers,
                last_finalized_block: block_number,
                last_vrf_seed: finalized.vrf_seed,
                randomness_status: vrf_safety.randomness_status,
                vrf_material_version: vrf_safety.vrf_material_version,
                last_dkg_activation_height: vrf_safety.last_dkg_activation_height,
                next_planned_activation_height: vrf_safety.next_planned_activation_height,
                vrf_expiry_height: vrf_safety.vrf_expiry_height,
            });
        }
    }

    /// Record the finalized block's DKG header artifact (if present) with the
    /// DKG manager. A malformed artifact is logged and skipped, never fatal.
    fn note_finalized_dkg_artifact(
        &self,
        block: &ConsensusBlock,
        digest: Digest,
        block_number: u64,
    ) {
        match extract_header_artifact_from_block(block) {
            Ok(artifact) => {
                self.deps.dkg_manager.note_finalized_header_artifact_at(
                    block_number,
                    digest.0,
                    artifact.as_ref(),
                );
            }
            Err(error) => {
                warn!(
                    %digest,
                    %error,
                    "finalized block carries invalid DKG header artifact"
                );
            }
        }
    }

    /// Evict block-cache entries at or below the new finalized height; they can
    /// no longer be needed by any future verify path. Re-reads the view under a
    /// short read lock (the write lock was already released).
    fn evict_finalized_block_cache(&self) {
        let finalized_num = self.deps.view.read().last_finalized_number;
        self.deps.block_cache.evict_at_or_below(finalized_num);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::block::ConsensusBlock;
    use crate::digest::Digest;
    use alloy_primitives::B256;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::{primitives::SealedBlock, Block};

    /// Build a minimal `ConsensusBlock` with the given height and a salt
    /// stored in `extra_data` so distinct salts produce distinct sealed
    /// hashes (and therefore distinct `Digest`s).
    fn make_block(number: u64, salt: u64) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.number = number;
        block.header.extra_data = salt.to_le_bytes().to_vec().into();
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    fn digest_of(block: &ConsensusBlock) -> Digest {
        block.digest()
    }

    /// `FinalizationActor::process_finalization` rekeys the
    /// reporter-buffered (view-keyed) late finalize votes to the now-known block
    /// number. Drives the real actor method directly with an already-resolved
    /// block (no marshal needed - the deps carry `marshal_mailbox: None`).
    #[test]
    fn rekey_via_finalization_actor() {
        use super::{FinalizationActor, FinalizationActorDeps};
        use crate::finalization::ingress::Finalized;
        use crate::finalization::late_sig_store;
        use crate::finalization::parent_cert_store::FinalizedParentCertStore;
        use crate::finalization::state::new_finalization_view;
        use crate::hybrid::HybridSchemeProvider;
        use crate::vrf_safety::VrfSafetyGate;
        use alloy_primitives::{Address, Bytes};
        use commonware_consensus::types::{Epoch, Round, View};
        use commonware_cryptography::{bls12381, Signer as _};
        use commonware_math::algebra::Random as _;
        use commonware_runtime::Runner as _;
        use outbe_primitives::consensus::{ConsensusData, FinalizedParentCertificateData};

        const WINDOW_K: u64 = 3;
        let (epoch, view, parent_view, fb_number) = (0u64, 9u64, 8u64, 10u64);

        // Shared store + a buffered (view-keyed) vote, as the reporter would have
        // recorded it before the block number was known. The signature value is
        // arbitrary here - the rekey path never verifies it.
        let block = make_block(fb_number, 7);
        let digest = digest_of(&block);
        let fb_hash = digest.0;

        let store = late_sig_store::shared(WINDOW_K);
        let key = bls12381::PrivateKey::random(rand_core::OsRng);
        let sig = key.sign(b"x", b"y");
        store.lock().expect("store").record_individual_vote(
            epoch,
            view,
            parent_view,
            fb_hash,
            0,
            &sig,
        );
        assert_eq!(store.lock().expect("store").pending_vote_count(fb_hash), 1);

        let committee: Vec<Address> = (0..4).map(|i| Address::with_last_byte(i + 1)).collect();
        let finalized = Finalized {
            round: Round::new(Epoch::new(epoch), View::new(view)),
            digest,
            vrf_seed: None,
            consensus_data: ConsensusData {
                finalized_block_number: fb_number,
                finalized_block_hash: digest.0,
                finalized_certificate: FinalizedParentCertificateData {
                    epoch,
                    view,
                    parent_view,
                    ordered_committee: committee,
                    signer_bitmap: vec![1, 0, 0, 0],
                    encoded_certificate: Bytes::new(),
                },
                vrf_seed: None,
                missed_proposers: Vec::new(),
            },
        };

        let deps = FinalizationActorDeps {
            view: new_finalization_view(B256::ZERO, 0, None),
            block_cache: crate::finalization::block_cache::BlockCache::new(),
            marshal_mailbox: None,
            bridge: None,
            dkg_manager: crate::dkg_manager::Mailbox::new(),
            vrf_safety: VrfSafetyGate::new(0, 0, 1_000, 100),
            parent_cert_store: FinalizedParentCertStore::new(),
            certificate_scheme_provider: HybridSchemeProvider::default(),
            late_sig_store: store.clone(),
            ocomp_retention: Arc::new(crate::ocomp_retention::NoopOcompRetentionHook),
        };
        let (actor, _mailbox) = FinalizationActor::new(deps);

        commonware_runtime::tokio::Runner::default().start(|_ctx| async move {
            actor
                .process_finalization(finalized, block)
                .await
                .expect("process_finalization should rekey without error");
        });

        // The fb_hash-keyed buffer was rekeyed to the finalized block number.
        let s = store.lock().expect("store");
        assert_eq!(
            s.pending_vote_count(fb_hash),
            0,
            "pending buffer must be drained after rekey"
        );
        assert_eq!(s.resolved_len(), 1, "exactly one target resolved by number");
    }
}
