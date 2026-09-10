//! Simplex Reporter - forwards consensus activities to the FinalizationActor.
//!
//! Implements [`commonware_consensus::Reporter`] to receive finalization events
//! and other consensus activities from the Simplex engine.
//!
//! On finalization:
//! 1. Builds the canonical finalized-parent certificate artifact from the
//!    finalized proposal and its Hybrid certificate
//! 2. Hashes BLS seed signature -> VRF seed (B256) for on-chain randomness
//! 3. Detects view gaps -> missed proposer addresses via elector
//! 4. Sends `Finalized` to the [`FinalizationActor`](crate::finalization::actor),
//!    which durably writes the exact-parent certificate record consumed by the
//!    proposer-side Phase 1 system transaction.
//! 5. Uses an unbounded mailbox - the voter task can never block on this edge.
//!    A closed mailbox is logged + counted but does not panic; the supervisor
//!    handles actor exit through `FinalizationActor::run`'s `Result`.

use crate::metrics::EquivocationKind;
use alloy_primitives::{Address, Bytes, B256};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::types::{Activity, Attributable as _, Finalize, Notarization, Proposal},
    types::{Epoch, View},
    Epochable as _, Reporter, Viewable,
};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, Hasher, Sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::ordered::Quorum as _;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use crate::{
    digest::Digest,
    finalization::finalize_verify::FinalizeVerifyMailbox,
    finalization::ingress::{Finalized as FinalizationFinalized, Mailbox as FinalizationMailbox},
    finalization::parent_cert_store::{
        CertificationWitnessSink, CertifiedParentProofKey, CertifiedParentProofRecord, ProofKind,
        CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
    },
    hybrid::{
        bls_batch_verification_rng, election::HybridRandomElector, HybridCertificate, HybridScheme,
    },
};
use outbe_primitives::consensus::{
    ConsensusData, ConsensusExecutionBridge, FinalizedParentCertificateData,
};

const MAX_MISSED_PROPOSERS: usize = u8::MAX as usize;

/// Reporter that forwards Simplex activities.
///
/// Tracks finalization events to:
/// 1. Forward finalized blocks to the FinalizationActor for durable exact-parent
///    certificate handoff and FCU/status side effects
/// 2. Build finalized-parent certificate facts for Phase 1 system-tx input
/// 3. Detect missed proposers from view gaps
/// 4. Buffer byzantine evidence until a dedicated evidence transport exists
#[derive(Clone)]
pub struct OutbeReporter {
    /// Shared finalized continuity across epoch restarts.
    continuity: ReporterContinuity,
    /// Ordered validator addresses (matching participant indices).
    validator_addresses: Vec<Address>,
    /// FinalizationActor mailbox for sending finalization notifications.
    /// `unbounded_send` keeps this edge non-blocking from the voter task.
    finalization_mailbox: FinalizationMailbox,
    /// Bridge - Half C-parlia step 11 removed the legacy
    /// `refresh_pending_finalized_certificate` call; the field is kept
    /// for the surviving status / cache surface and for follow-up
    /// metrics emission.
    #[allow(dead_code)]
    bridge: Option<ConsensusExecutionBridge>,
    /// Verifier scheme for validating carried finalize votes before inclusion.
    verifier_scheme: HybridScheme<MinSig>,
    /// VRF-based leader elector for missed-proposer detection.
    elector: HybridRandomElector<MinSig>,
    /// Current consensus epoch.
    epoch: Epoch,
    /// Mutable per-view tracking (finalization cursor + byzantine-evidence
    /// buffer), separated from the immutable epoch wiring.
    view_state: ReporterViewState,
    /// Off-thread finalize-vote verifier. `handle_finalize_vote`
    /// enqueues raw votes here instead of verifying `O(committee)` BLS pairings
    /// inline on the Simplex voter task; the actor verifies and admits the
    /// verified votes to `late_sig_store`.
    finalize_verify_mailbox: FinalizeVerifyMailbox,
    /// Narrow, write-only capability onto the certified-parent proof store: the
    /// reporter records the `local_certification_witness` mark for each observed
    /// `Activity::Certification`, but structurally cannot durably write - durable
    /// persistence goes off-thread through the FinalizationActor mailbox (see
    /// `handle_certification`), which stays the single durable writer.
    witness_sink: Arc<dyn CertificationWitnessSink>,
}

/// Mutable per-view state owned by a single `OutbeReporter` instance, separated
/// from the immutable epoch wiring. Holds the finalization cursor (the lower
/// bound for view-gap missed-proposer attribution) and the byzantine-evidence
/// buffer drained on each finalization. Its operations are unit-tested in
/// isolation, so byzantine buffering and the finalization cursor are no longer
/// loose fields threaded through the handlers.
#[derive(Clone, Default)]
struct ReporterViewState {
    last_finalized_view: u64,
    last_certificate: Option<HybridCertificate<MinSig>>,
    pending_byzantine: Vec<Address>,
}

impl ReporterViewState {
    fn last_finalized_view(&self) -> u64 {
        self.last_finalized_view
    }

    fn last_certificate(&self) -> Option<&HybridCertificate<MinSig>> {
        self.last_certificate.as_ref()
    }

    /// Buffer a byzantine validator address until the next finalization drains it.
    fn buffer_byzantine(&mut self, addr: Address) {
        self.pending_byzantine.push(addr);
    }

    /// Drain the buffered byzantine addresses, sorted and deduplicated.
    fn drain_byzantine_sorted(&mut self) -> Vec<Address> {
        let mut drained = std::mem::take(&mut self.pending_byzantine);
        drained.sort_unstable();
        drained.dedup();
        drained
    }

    /// Advance the finalization cursor used by view-gap missed-proposer detection.
    fn record_finalization(&mut self, view: u64, certificate: HybridCertificate<MinSig>) {
        self.last_finalized_view = view;
        self.last_certificate = Some(certificate);
    }
}

#[derive(Clone, Default)]
pub struct ReporterContinuity {
    inner: Arc<Mutex<ReporterContinuityState>>,
}

#[derive(Clone, Default)]
pub struct ReporterContinuityState {
    pub last_finalized_view: u64,
    pub last_certificate: Option<HybridCertificate<MinSig>>,
    pub last_vrf_seed: Option<Vec<u8>>,
}

impl ReporterContinuity {
    pub fn snapshot(&self) -> ReporterContinuityState {
        match self.inner.lock() {
            Ok(state) => state.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn update(
        &self,
        last_finalized_view: u64,
        last_certificate: Option<HybridCertificate<MinSig>>,
        last_vrf_seed: Option<Vec<u8>>,
    ) {
        let mut state = match self.inner.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.last_finalized_view = last_finalized_view;
        state.last_certificate = last_certificate;
        state.last_vrf_seed = last_vrf_seed;
    }
}

/// Type alias for our Simplex activity type - uses HybridScheme<MinSig>.
type OutbeActivity = Activity<HybridScheme<MinSig>, Digest>;

impl OutbeReporter {
    /// Create a new reporter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        continuity: ReporterContinuity,
        validator_addresses: Vec<Address>,
        finalization_mailbox: FinalizationMailbox,
        bridge: Option<ConsensusExecutionBridge>,
        verifier_scheme: HybridScheme<MinSig>,
        elector: HybridRandomElector<MinSig>,
        epoch: Epoch,
        witness_sink: Arc<dyn CertificationWitnessSink>,
        finalize_verify_mailbox: FinalizeVerifyMailbox,
    ) -> Self {
        let persisted = continuity.snapshot();
        Self {
            continuity,
            validator_addresses,
            finalization_mailbox,
            bridge,
            verifier_scheme,
            elector,
            epoch,
            finalize_verify_mailbox,
            view_state: ReporterViewState {
                last_finalized_view: persisted.last_finalized_view,
                last_certificate: persisted.last_certificate,
                pending_byzantine: Vec::new(),
            },
            witness_sink,
        }
    }
}

impl Reporter for OutbeReporter {
    type Activity = OutbeActivity;

    /// Report a consensus activity.
    ///
    /// As of commonware 2026.5.0 this method is SYNC and returns
    /// [`commonware_actor::Feedback`]. The only activity that previously
    /// required `.await` was `Activity::Finalization`, whose handler
    /// (`handle_finalization`) does all of its work synchronously and then
    /// hands the finalization off to the [`FinalizationActor`] through an
    /// unbounded mailbox (`unbounded_send`). No async work runs on this path,
    /// so the migration does NOT spawn a task or block: the finalization is
    /// enqueued into the actor mailbox deterministically, preserving the
    /// single-writer `FinalizedParentCertStore` semantics.
    ///
    /// We return `Feedback::Closed` only when the downstream FinalizationActor
    /// mailbox is gone (finalization could not be delivered); all other paths
    /// return `Feedback::Ok`.
    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        match activity {
            Activity::Finalize(finalize) => {
                self.handle_finalize_vote(finalize);
                commonware_actor::Feedback::Ok
            }
            Activity::Finalization(finalization) => self.handle_finalization(finalization),
            Activity::Notarization(notarization) => {
                // track the current view so the stall gap
                // (current - finalized) is observable even before finalization.
                crate::metrics::record_current_view(notarization.view().get());
                commonware_actor::Feedback::Ok
            }
            Activity::Nullification(nullification) => {
                // a view was nullified (leader timed out / view skipped).
                // The current-view gauge advances on nullifications so it keeps
                // moving during a stall where nothing finalizes.
                crate::metrics::record_view_nullified();
                crate::metrics::record_current_view(nullification.view().get());
                commonware_actor::Feedback::Ok
            }
            Activity::Certification(notarization) => {
                // marshal's mailbox drops `Activity::Certification`
                // via its `_ => return;` arm, so Outbe is the only persistent
                // consumer. Verify before write per the test contract
                // `proof_store_ingestion_verifies_certification_activity_before_write`.
                self.handle_certification(notarization);
                commonware_actor::Feedback::Ok
            }
            Activity::ConflictingNotarize(evidence) => {
                self.handle_byzantine_evidence(
                    EquivocationKind::ConflictingNotarize,
                    evidence.signer(),
                    evidence.epoch(),
                    evidence.view(),
                );
                commonware_actor::Feedback::Ok
            }
            Activity::ConflictingFinalize(evidence) => {
                self.handle_byzantine_evidence(
                    EquivocationKind::ConflictingFinalize,
                    evidence.signer(),
                    evidence.epoch(),
                    evidence.view(),
                );
                commonware_actor::Feedback::Ok
            }
            Activity::NullifyFinalize(evidence) => {
                self.handle_byzantine_evidence(
                    EquivocationKind::NullifyFinalize,
                    evidence.signer(),
                    evidence.epoch(),
                    evidence.view(),
                );
                commonware_actor::Feedback::Ok
            }
            _ => {
                tracing::trace!("activity reported");
                commonware_actor::Feedback::Ok
            }
        }
    }
}

impl OutbeReporter {
    fn handle_finalize_vote(&mut self, finalize: Finalize<HybridScheme<MinSig>, Digest>) {
        // do NOT verify the vote inline on the Simplex voter task. The
        // batcher reports `Activity::Finalize` BEFORE batch-verifying it
        // (monorepo batcher `round.rs::add_network`), so the vote here is
        // unverified and MUST be verified before it can feed the proposer's
        // late-credit aggregate - but verifying `O(committee)` BLS pairings per
        // view on the voter critical path inflated block time. Enqueue the raw
        // vote to the off-thread `FinalizeVerifyActor`, which verifies it and
        // admits only the verified votes to `late_sig_store`. The former
        // synchronous `build_finalized_certificate` re-augmentation here was a
        // V2 no-op (it discarded its result; the canonical bitmap comes from the
        // certificate in `handle_finalization`), so it is dropped with the
        // vestigial `observed_finalizes` / `pending_finalizations` state.
        // finalize votes are the most frequent per-view signal; track the
        // current view so the stall gap stays fresh during normal progress.
        crate::metrics::record_current_view(finalize.view().get());
        self.finalize_verify_mailbox.verify(self.epoch, finalize);
    }

    fn build_finalized_certificate(
        &self,
        proposal: &Proposal<Digest>,
        certificate: &HybridCertificate<MinSig>,
    ) -> FinalizedParentCertificateData {
        // V2 contract uses the certificate's own signer bitmap as
        // the authoritative participation accounting input; the V1
        // supplemental-finalize-vote bitmap extension is dropped.
        // `observed_finalizes` is still maintained for future byzantine
        // equivocation detection but no longer feeds the wire.
        let signer_bitmap = self.build_signer_bitmap(certificate);

        FinalizedParentCertificateData {
            epoch: self.epoch.get(),
            view: proposal.view().get(),
            parent_view: proposal.parent.get(),
            ordered_committee: self.validator_addresses.clone(),
            signer_bitmap,
            encoded_certificate: commonware_consensus::simplex::types::Finalization::<
                HybridScheme<MinSig>,
                Digest,
            > {
                proposal: proposal.clone(),
                certificate: certificate.clone(),
            }
            .encode()
            .into(),
        }
    }

    /// Handle byzantine consensus equivocation evidence
    /// (`ConflictingNotarize` / `ConflictingFinalize` / `NullifyFinalize`).
    ///
    /// Emits a structured signal for an external slashing watcher and records a
    /// metric. The conflicting signed votes themselves are NOT accessible from
    /// the commonware evidence type (its inner votes are private), so the node
    /// signals the attributable facts (signer pubkey + epoch + view + class) and
    /// the watcher - which observes the gossiped votes - packs the two
    /// `EvidenceBlock`s and submits to the SlashIndicator
    /// `submitConflicting{Notarize,Finalize}Evidence` / `submitNullifyFinalizeEvidence`
    /// precompiles. The node does NOT auto-slash (no in-node tx injection), so
    /// the log must not claim it does.
    fn handle_byzantine_evidence(
        &mut self,
        kind: EquivocationKind,
        signer: commonware_utils::Participant,
        epoch: Epoch,
        view: View,
    ) {
        let evidence_type = kind.label();
        let signer_idx = signer.get() as usize;
        if let Some(&addr) = self.validator_addresses.get(signer_idx) {
            let signer_pubkey = self
                .verifier_scheme
                .participants()
                .key(signer)
                .map(|pk| hex::encode(pk.encode()))
                .unwrap_or_default();
            warn!(
                target: "outbe::slashing::equivocation",
                evidence_type,
                signer_idx,
                %addr,
                signer_pubkey,
                epoch = epoch.get(),
                view = view.get(),
                "BYZANTINE: consensus equivocation detected - slashable; external watcher should submit the two conflicting votes"
            );
            self.view_state.buffer_byzantine(addr);
            crate::metrics::record_byzantine_evidence(kind);
        } else {
            warn!(
                evidence_type,
                signer_idx,
                total = self.validator_addresses.len(),
                "BYZANTINE: signer index out of bounds"
            );
        }
    }

    /// Handle a finalization event from the Simplex engine.
    ///
    /// SYNC in 2026.5.0: the handler builds the finalized-parent certificate
    /// artifact, detects missed proposers, updates reporter-local continuity,
    /// and routes the finalization to the [`FinalizationActor`] through its
    /// unbounded mailbox (`notify_finalized` is a non-blocking `unbounded_send`).
    /// No `.await` happens here. Returns [`commonware_actor::Feedback::Closed`]
    /// when the actor mailbox is gone (finalization dropped); otherwise
    /// [`commonware_actor::Feedback::Ok`].
    fn handle_finalization(
        &mut self,
        finalization: commonware_consensus::simplex::types::Finalization<
            HybridScheme<MinSig>,
            Digest,
        >,
    ) -> commonware_actor::Feedback {
        let view = finalization.proposal.view().get();
        let digest = finalization.proposal.payload;
        let certificate = finalization.certificate;

        let signers_count = certificate.signers.count();
        let signers_total = certificate.signers.len();

        // VRF is no longer finality-critical. Use it only if the proof verifies
        // against the versioned material carried by the verifier scheme.
        let mut rng = bls_batch_verification_rng();
        let seed_bytes = self.verifier_scheme.verified_vrf_seed_for_round(
            &mut rng,
            finalization.proposal.round,
            &certificate,
            &Sequential,
        );
        let vrf_seed = seed_bytes.as_ref().map(|seed_bytes| {
            let hash = Sha256::hash(seed_bytes);
            B256::from_slice(hash.as_ref())
        });

        // Defense-in-depth alarm: a finalized certificate must never carry a
        // VRF proof that fails to verify against the committee group key for
        // its own round. Atomic vote-plus-partial admission during attestation
        // verification guarantees recovery only runs over verified partials, so this is unreachable
        // in correct operation. If it ever fires, an unverifiable proof has
        // reached the finalized certificate and will fail the next height's
        // mandatory V2 verify - surface it loudly rather than silently halting.
        if vrf_seed.is_none() {
            crate::metrics::record_finalized_cert_invalid_vrf_proof();
            error!(
                view,
                %digest,
                vrf_material_version = certificate.vrf_proof.material_version,
                "INVARIANT: finalized certificate carries an unverifiable VRF proof; \
                 next-height CertifiedParentAccounting will reject this parent"
            );
        }

        info!(
            view,
            %digest,
            signers = signers_count,
            total = signers_total,
            vrf_proof_present = true,
            vrf_material_version = certificate.vrf_proof.material_version,
            vrf_verified = vrf_seed.is_some(),
            vrf_seed = ?vrf_seed,
            "block finalized"
        );

        // Record finalization metrics.
        crate::metrics::record_block_finalized(view, signers_count, signers_total);
        crate::metrics::record_epoch(self.epoch.get());

        // 1. Build the canonical finalized-parent certificate artifact.
        let finalized_certificate =
            self.build_finalized_certificate(&finalization.proposal, &certificate);

        // 3. Detect missed proposers from view gaps.
        let missed_proposers = self.detect_missed_proposers(view);

        // 4. Drain the per-finalization buffer of locally-attributed byzantine
        // signers - operator observability ONLY, not a transport stage. On-chain
        // slashing is carried by the external watcher (which observes the raw
        // gossiped votes the node cannot reach - commonware hides the inner votes)
        // submitting the two conflicting `EvidenceBlock`s to the SlashIndicator
        // `submitConflicting{Notarize,Finalize}` / `submitNullifyFinalize`
        // precompile, where both signatures are re-verified on-chain (reproducible
        // from chain state). This drain does NOT put evidence on-chain.
        let attributed_byzantine = self.view_state.drain_byzantine_sorted();

        if !attributed_byzantine.is_empty() {
            warn!(
                target: "outbe::slashing::equivocation",
                count = attributed_byzantine.len(),
                "byzantine equivocation attributed this finalization; on-chain slashing requires the external watcher to submit the two conflicting votes to the SlashIndicator precompile"
            );
        }

        // 5. Build full finalization payload for the FinalizationActor (no direct
        // bridge writes). The actor persists the exact-parent cert and applies
        // bridge/status updates only for non-replayed finalizations.
        let consensus_data = ConsensusData {
            finalized_block_number: 0,
            finalized_block_hash: digest.0,
            finalized_certificate,
            vrf_seed,
            missed_proposers,
        };

        // 7. Send full finalization payload to the FinalizationActor.
        // `unbounded_send` cannot back-pressure the voter task. A closed
        // mailbox is logged + counted but not panicked: graceful shutdown
        // closes the receiver before the voter task winds down, and a
        // non-graceful exit is surfaced through `FinalizationActor::run`.
        let mailbox_feedback =
            match self
                .finalization_mailbox
                .notify_finalized(FinalizationFinalized {
                    round: finalization.proposal.round,
                    digest,
                    vrf_seed,
                    consensus_data,
                }) {
                Ok(()) => commonware_actor::Feedback::Ok,
                Err(_closed) => {
                    crate::metrics::record_finalization_dropped(
                        crate::metrics::FinalizationDropReason::MailboxClosed,
                    );
                    tracing::error!(
                        round = %finalization.proposal.round,
                        view,
                        %digest,
                        "FinalizationActor mailbox closed; finalization dropped"
                    );
                    commonware_actor::Feedback::Closed
                }
            };

        // Update tracking state.
        self.view_state.record_finalization(view, certificate);
        self.continuity.update(
            self.view_state.last_finalized_view(),
            self.view_state.last_certificate().cloned(),
            seed_bytes,
        );

        mailbox_feedback
    }

    /// Handle an `Activity::Certification(notarization)` event from the Simplex
    /// engine: verify the notarization certificate, build a
    /// [`CertifiedParentProofRecord`] with `proof_type = CertifiedNotarization`,
    /// and persist it to the certified-parent proof store.
    ///
    /// Verify-before-write is the test contract
    /// `proof_store_ingestion_verifies_certification_activity_before_write`.
    /// Failure modes are exhaustive and never panic; each is metered.
    fn handle_certification(&self, notarization: Notarization<HybridScheme<MinSig>, Digest>) {
        // Step 1 - verify the notarization certificate against the active
        // committee verifier scheme. Simplex already verified before
        // emission, so this is defence in depth, but the
        // requires explicit re-verification before write.
        let mut rng = bls_batch_verification_rng();
        if !notarization.verify(&mut rng, &self.verifier_scheme, &Sequential) {
            crate::metrics::record_certification_dropped(
                crate::metrics::CertificationDropReason::VerifyFailed,
            );
            warn!(
                target: "outbe::reporter",
                epoch = notarization.proposal.round.epoch().get(),
                view = notarization.proposal.round.view().get(),
                payload = %notarization.proposal.payload,
                "Activity::Certification dropped: notarization signature verification failed"
            );
            return;
        }

        // Step 2 - derive V2 canonical fields. `committee_set_hash_v2` and
        // `vrf_material_version` are populated here so 's V2 selector
        // can read them directly via `get_best_parent_proof` without
        // recomputing from the encoded blob.
        //
        // The canonical (PLAN A4) formula binds the **full** committee snapshot
        // (address + 48-byte MinPk pubkey per validator + raw encoded VRF group
        // public key bytes), not just addresses and a pre-hashed VRF pk. Build
        // the snapshot from the verifier scheme so the proposer-side hash
        // matches what `apply_boundary_outcome` writes to `CommitteeSnapshotStore`
        // and what the executor Phase 1 verifier recomputes.
        // Defence-in-depth path: a snapshot build failure is an encode-invariant
        // violation; drop the certification deterministically (metered, never
        // panic) rather than write a record whose committee_set_hash would
        // diverge from the writer's.
        let prelude = match crate::finalization::committee_prelude::build_committee_prelude(
            &self.verifier_scheme,
            &self.validator_addresses,
            notarization.proposal.round.epoch().get(),
        ) {
            Ok(prelude) => prelude,
            Err(error) => {
                crate::metrics::record_certification_dropped(
                    crate::metrics::CertificationDropReason::SnapshotBuildFailed,
                );
                warn!(
                    target: "outbe::reporter",
                    epoch = notarization.proposal.round.epoch().get(),
                    %error,
                    "Activity::Certification dropped: committee snapshot build failed"
                );
                return;
            }
        };
        let signer_bitmap = self.build_signer_bitmap(&notarization.certificate);
        let encoded_proof: Bytes = notarization.encode().into();
        // The notarization carries no block-number context. Store `0` so this
        // record can serve as an exact-key local witness, but the Phase 1
        // selector will not promote it without a real block number. Use the
        // proposal view as a monotone retention proxy so the age-based prune in
        // `actor.rs` keeps the slot bounded.
        let view = notarization.proposal.round.view().get();
        let proof_key = CertifiedParentProofKey::new(
            notarization.proposal.round.epoch().get(),
            view,
            notarization.proposal.payload.0,
        );
        self.witness_sink
            .mark_local_certification_witness(proof_key);
        let record = CertifiedParentProofRecord {
            format_version: CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
            kind: ProofKind::CertifiedNotarization,
            finalized_epoch: notarization.proposal.round.epoch().get(),
            finalized_view: view,
            parent_view: notarization.proposal.parent.get(),
            finalized_block_hash: notarization.proposal.payload.0,
            committee_set_hash: prelude.committee_set_hash,
            vrf_material_version: prelude.vrf_material_version,
            vrf_group_public_key_hash: prelude.vrf_group_public_key_hash,
            ordered_committee: self.validator_addresses.clone(),
            signer_bitmap,
            encoded_proof,
            stored_at_height: view,
        };

        // Step 3 - enqueue the durable write to the FinalizationActor.
        // The synchronous MDBX commit moves off the Simplex voter task; the
        // record (including the parity-critical `committee_set_hash`) was built
        // and verified above and is byte-identical to the inline-written one -
        // only the write moves, and the actor remains the single durable writer
        // to `FinalizedParentCertStore`. The in-memory
        // `mark_local_certification_witness` above stays on-thread (a cheap
        // locked insert). The `record_certification_persisted` metric now fires
        // in the actor on a successful commit. A closed mailbox is metered +
        // logged but never panics the reporter task.
        if let Err(error) = self
            .finalization_mailbox
            .persist_certified_notarization(record)
        {
            crate::metrics::record_certification_dropped(
                crate::metrics::CertificationDropReason::MailboxClosed,
            );
            warn!(
                target: "outbe::reporter",
                epoch = notarization.proposal.round.epoch().get(),
                view,
                payload = %notarization.proposal.payload,
                %error,
                "Activity::Certification dropped: FinalizationActor mailbox closed"
            );
            return;
        }

        debug!(
            target: "outbe::reporter",
            epoch = notarization.proposal.round.epoch().get(),
            view,
            payload = %notarization.proposal.payload,
            "Activity::Certification enqueued for off-thread persistence"
        );
    }

    /// Build a stable one-byte-per-participant signer bitmap from the certificate.
    ///
    /// Producer-side guard with diagnostics; the fill delegates to the canonical
    /// core in [`crate::finalization::util::build_signer_bitmap`]. On a
    /// committee/cert size skew this emits the empty sentinel, matching
    /// [`crate::finalization::util::build_signer_bitmap_guarded`] (the resolver
    /// path); the verify-side structural check rejects that sentinel by length.
    fn build_signer_bitmap(&self, certificate: &HybridCertificate<MinSig>) -> Vec<u8> {
        let n = certificate.signers.len();
        if n != self.validator_addresses.len() {
            warn!(
                cert_len = n,
                validators = self.validator_addresses.len(),
                "signer set size mismatch"
            );
            return Vec::new();
        }

        let signed = crate::finalization::util::build_signer_bitmap(certificate, n);

        debug!(
            signers = certificate.signers.count(),
            committee = n,
            "built finalized-parent signer bitmap"
        );

        signed
    }

    /// Detect missed proposers from view gaps.
    ///
    /// Views between `last_finalized_view + 1` and `current_view - 1` had leaders
    /// who failed to propose. Uses the elector + last certificate to determine
    /// who was the expected leader for each skipped view.
    ///
    /// Important: this is an event list, not a deduplicated validator set.
    /// The same address may appear multiple times if the same proposer missed
    /// multiple distinct views in a row, and post-execution slashing should
    /// account for each missed view separately.
    fn detect_missed_proposers(&self, current_view: u64) -> Vec<Address> {
        let last_finalized_view = self.view_state.last_finalized_view();
        if last_finalized_view == 0 || current_view <= last_finalized_view + 1 {
            return Vec::new();
        }

        let gap = current_view - last_finalized_view - 1;

        // Single source of truth for the view-gap election sequence, shared with
        // the verify-side recompute in `finalization::util` so proposer and
        // validator never disagree on who was the expected leader.
        let leaders = crate::missed_proposers::elected_leaders_for_gap(
            self.epoch,
            &self.elector,
            self.view_state.last_certificate(),
            last_finalized_view,
            current_view,
            MAX_MISSED_PROPOSERS,
        );
        let dropped = gap.saturating_sub(leaders.len() as u64);

        let mut missed = Vec::with_capacity(leaders.len());
        for (offset, leader) in leaders.iter().enumerate() {
            let v = last_finalized_view + 1 + offset as u64;
            let leader_idx = leader.get() as usize;

            if leader_idx < self.validator_addresses.len() {
                let addr = self.validator_addresses[leader_idx];
                debug!(
                    view = v,
                    leader_idx,
                    %addr,
                    "missed proposer detected"
                );
                missed.push(addr);
            } else {
                warn!(
                    view = v,
                    leader_idx,
                    total = self.validator_addresses.len(),
                    "leader index out of bounds"
                );
            }
        }

        if !missed.is_empty() {
            info!(
                gap,
                missed_count = missed.len(),
                dropped_count = dropped,
                from = self.view_state.last_finalized_view() + 1,
                to = current_view - 1,
                "view gap - missed proposers detected"
            );
            if dropped > 0 {
                warn!(
                    gap,
                    emitted = missed.len(),
                    dropped,
                    limit = MAX_MISSED_PROPOSERS,
                    "missed proposer list truncated to wire-format limit"
                );
            }

            // Record skipped views metric.
            crate::metrics::record_views_skipped(gap);
        }

        missed
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use commonware_consensus::{
        simplex::{
            elector::{Config as _, Elector as _},
            types::Subject,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::{self, primitives::variant::MinSig},
        certificate::Scheme as _,
        sha256::Digest as Sha256Digest,
        Hasher as _, Sha256, Signer as _,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{
        ordered::{Quorum as _, Set},
        N3f1, TryCollect as _,
    };
    use futures::channel::mpsc;

    use super::{FinalizeVerifyMailbox, OutbeReporter, ReporterContinuity};
    use crate::{
        bls::bootstrap_dkg,
        finalization::{
            ingress::{Mailbox as FinalizationMailbox, Message as FinalizationMessage},
            parent_cert_store::FinalizedParentCertStore,
        },
        hybrid::{election::HybridRandom, HybridScheme},
    };

    fn test_participants(n: u8) -> (Vec<bls12381::PrivateKey>, Set<bls12381::PublicKey>) {
        let keys: Vec<bls12381::PrivateKey> = (0..n)
            .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
            .collect();
        let participants = keys
            .iter()
            .map(|sk| bls12381::PublicKey::from(sk.clone()))
            .try_collect()
            .unwrap();
        (keys, participants)
    }

    fn sample_certificate() -> crate::hybrid::HybridCertificate<MinSig> {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();
        let schemes: Vec<HybridScheme<MinSig>> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    b"reporter-test",
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();
        let verifier =
            HybridScheme::<MinSig>::verifier(b"reporter-test", participants, dkg.polynomial)
                .unwrap();
        let proposal = commonware_consensus::simplex::types::Proposal::new(
            Round::new(Epoch::new(0), View::new(2)),
            View::new(1),
            Sha256::hash(b"reporter-test"),
        );
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let attestations: Vec<_> = schemes
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap()
    }

    fn sample_verifier_scheme() -> HybridScheme<MinSig> {
        let (_, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();
        HybridScheme::<MinSig>::verifier(b"reporter-test", participants, dkg.polynomial).unwrap()
    }

    /// Build signer schemes AND a matching verifier from ONE DKG, so individual
    /// finalize votes signed by the signers verify against the verifier (required
    /// now that the reporter verifies before recording).
    fn signer_schemes_and_verifier() -> (Vec<HybridScheme<MinSig>>, HybridScheme<MinSig>) {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();
        let signers = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    b"reporter-test",
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();
        let verifier =
            HybridScheme::<MinSig>::verifier(b"reporter-test", participants, dkg.polynomial)
                .unwrap();
        (signers, verifier)
    }

    /// wiring: an observed `Activity::Finalize` is buffered into the
    /// shared late-finalize store (keyed by view, pending number resolution),
    /// proving the reporter extracts the signer's individual MinPk vote.
    #[test]
    fn reporter_records_observed_finalize_vote_into_shared_store() {
        use crate::finalization::finalize_verify::FinalizeVerifyActor;
        use crate::finalization::late_sig_store;
        use crate::hybrid::HybridSchemeProvider;
        use commonware_consensus::simplex::types::{Activity, Finalize, Proposal};
        use commonware_consensus::Reporter as _;

        let store = late_sig_store::shared(outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K);
        // Signers + verifier from ONE DKG so the observed vote actually verifies
        // (the off-thread verify actor verifies before recording).
        let (schemes, verifier) = signer_schemes_and_verifier();

        // register the epoch-0 verifier in the scheme provider and build
        // the off-thread verify actor + mailbox. The reporter enqueues votes to
        // the mailbox; admission happens in the actor.
        let provider: HybridSchemeProvider<MinSig> = HybridSchemeProvider::new();
        assert!(provider.register(Epoch::new(0), verifier.clone()));
        let (mut verify_actor, verify_mailbox) = FinalizeVerifyActor::new(provider, store.clone());

        let (tx, _rx) = mpsc::unbounded::<FinalizationMessage>();
        let participants = test_participants(3).1;
        let mut reporter = OutbeReporter::new(
            ReporterContinuity::default(),
            vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
                address!("0x3333333333333333333333333333333333333333"),
            ],
            FinalizationMailbox::from_sender(tx),
            None,
            verifier,
            HybridRandom::default().build(&participants),
            Epoch::new(0),
            std::sync::Arc::new(FinalizedParentCertStore::new()),
            verify_mailbox,
        );

        let view = 7u64;
        let fb_hash = alloy_primitives::B256::repeat_byte(0x7a);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(view)),
            View::new(view - 1),
            crate::digest::Digest(fb_hash),
        );
        let finalize = Finalize::sign(&schemes[0], proposal).expect("finalize vote");

        // Reporter enqueues (no inline verify on the voter task) ...
        let _ = reporter.report(Activity::Finalize(finalize));
        assert_eq!(
            store.lock().unwrap().pending_vote_count(fb_hash),
            0,
            "reporter must NOT admit on the voter task - admission is off-thread"
        );

        // ... the verify actor verifies it off-thread and admits the verified vote.
        assert!(
            verify_actor.try_process_one(),
            "actor processes the queued vote"
        );
        assert_eq!(
            store.lock().unwrap().pending_vote_count(fb_hash),
            1,
            "verify actor must verify then buffer the individual finalize vote by fb_hash"
        );
        assert_eq!(verify_actor.observed_len(view), 1);
    }

    #[test]
    fn reporter_restores_finalized_state_from_continuity() {
        let continuity = ReporterContinuity::default();
        let certificate = sample_certificate();
        continuity.update(
            17,
            Some(certificate.clone()),
            Some(certificate.raw_vrf_seed_bytes()),
        );

        let (tx, _rx) = mpsc::unbounded::<FinalizationMessage>();
        let reporter = OutbeReporter::new(
            continuity,
            vec![
                address!("0x1111111111111111111111111111111111111111"),
                address!("0x2222222222222222222222222222222222222222"),
                address!("0x3333333333333333333333333333333333333333"),
            ],
            FinalizationMailbox::from_sender(tx),
            None,
            sample_verifier_scheme(),
            HybridRandom::default().build(&test_participants(3).1),
            Epoch::new(1),
            std::sync::Arc::new(FinalizedParentCertStore::new()),
            FinalizeVerifyMailbox::disconnected(),
        );

        assert_eq!(reporter.view_state.last_finalized_view, 17);
        assert_eq!(reporter.view_state.last_certificate, Some(certificate));
    }

    #[test]
    fn view_state_buffers_drains_dedup_and_records_cursor() {
        let mut state = super::ReporterViewState::default();
        assert_eq!(state.last_finalized_view(), 0);
        assert!(state.last_certificate().is_none());

        let a = address!("0x0000000000000000000000000000000000000011");
        let b = address!("0x0000000000000000000000000000000000000022");
        state.buffer_byzantine(b);
        state.buffer_byzantine(a);
        state.buffer_byzantine(a); // duplicate

        let drained = state.drain_byzantine_sorted();
        assert_eq!(
            drained,
            vec![a, b],
            "drained evidence is sorted and deduplicated"
        );
        assert!(
            state.drain_byzantine_sorted().is_empty(),
            "the buffer is emptied by drain"
        );

        let cert = sample_certificate();
        state.record_finalization(17, cert.clone());
        assert_eq!(state.last_finalized_view(), 17);
        assert_eq!(state.last_certificate(), Some(&cert));
    }

    #[test]
    fn reporter_uses_continuity_certificate_for_epoch_boundary_gap_detection() {
        let continuity = ReporterContinuity::default();
        let certificate = sample_certificate();
        continuity.update(
            5,
            Some(certificate.clone()),
            Some(certificate.raw_vrf_seed_bytes()),
        );

        let participants = test_participants(3).1;
        let ordered_addresses = vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ];
        let elector = HybridRandom::default().build(&participants);
        let expected: Vec<_> = (6..8)
            .map(|view| {
                let leader = elector.elect(
                    Round::new(Epoch::new(1), View::new(view)),
                    Some(&certificate),
                );
                ordered_addresses[leader.get() as usize]
            })
            .collect();

        let (tx, _rx) = mpsc::unbounded::<FinalizationMessage>();
        let reporter = OutbeReporter::new(
            continuity,
            ordered_addresses,
            FinalizationMailbox::from_sender(tx),
            None,
            sample_verifier_scheme(),
            elector,
            Epoch::new(1),
            std::sync::Arc::new(FinalizedParentCertStore::new()),
            FinalizeVerifyMailbox::disconnected(),
        );

        assert_eq!(reporter.detect_missed_proposers(8), expected);
    }

    #[test]
    fn reporter_caps_large_missed_proposer_gap_to_wire_limit() {
        let continuity = ReporterContinuity::default();
        let certificate = sample_certificate();
        continuity.update(
            5,
            Some(certificate.clone()),
            Some(certificate.raw_vrf_seed_bytes()),
        );

        let participants = test_participants(3).1;
        let ordered_addresses = vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ];
        let elector = HybridRandom::default().build(&participants);
        let expected: Vec<_> = (6..(6 + super::MAX_MISSED_PROPOSERS as u64))
            .map(|view| {
                let leader = elector.elect(
                    Round::new(Epoch::new(1), View::new(view)),
                    Some(&certificate),
                );
                ordered_addresses[leader.get() as usize]
            })
            .collect();

        let (tx, _rx) = mpsc::unbounded::<FinalizationMessage>();
        let reporter = OutbeReporter::new(
            continuity,
            ordered_addresses,
            FinalizationMailbox::from_sender(tx),
            None,
            sample_verifier_scheme(),
            elector,
            Epoch::new(1),
            std::sync::Arc::new(FinalizedParentCertStore::new()),
            FinalizeVerifyMailbox::disconnected(),
        );

        assert_eq!(reporter.detect_missed_proposers(400), expected);
    }
}
