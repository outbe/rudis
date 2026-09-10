//! Off-thread finalize-vote verification.
//!
//! The Simplex batcher reports `Activity::Finalize` to the reporter **before**
//! it batch-verifies the vote: in the monorepo batcher `round.rs::add_network`
//! calls `reporter.report(Activity::Finalize(..))` and only then
//! `verifier.add(.., /*verified=*/ false)`. The reporter therefore cannot trust
//! those votes - it must verify each one before admitting it to the
//! process-local [`SharedLateFinalizeStore`], or a single forged vote would
//! poison the proposer's late-credit aggregate and get the proposer's own block
//! rejected pre-exec (validators re-verify the aggregate). Dropping the
//! verification is **not** an option here (the audit's "batcher already
//! verified" premise does not hold for the network-vote path).
//!
//! Doing that `O(committee)` sequential BLS pairing verification inline on the
//! Simplex voter task inflated block time and shrank the leader-timeout budget
//! as the committee grew. This actor moves the verification + admission off the
//! voter critical path: [`OutbeReporter`](crate::reporter::OutbeReporter)
//! enqueues raw votes through [`FinalizeVerifyMailbox::verify`] (a non-blocking
//! `unbounded_send`) and this actor verifies them against the epoch's committee
//! scheme and admits only the verified ones. The store/buffer therefore still
//! only ever holds signature-verified votes; the only observable change is that
//! admission happens slightly later (best-effort, process-local - never
//! consensus state).

use std::collections::BTreeMap;

use commonware_consensus::{
    simplex::types::{Attributable as _, Finalize},
    types::Epoch,
    Viewable as _,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, certificate};
use commonware_parallel::Sequential;
use futures::{channel::mpsc, StreamExt};

use crate::{
    digest::Digest,
    finalization::late_sig_store::SharedLateFinalizeStore,
    hybrid::{bls_batch_verification_rng, HybridScheme, HybridSchemeProvider},
};

/// A finalize vote tagged with the consensus epoch it was cast in, so the actor
/// can look up the matching committee verifier scheme.
type Job = (Epoch, Finalize<HybridScheme<MinSig>, Digest>);

/// Number of recent views whose verified finalize votes stay buffered in
/// `observed_finalizes` for future byzantine-equivocation detection. Bounds the
/// buffer; matches the reporter's former prune window.
const OBSERVED_RETAIN_VIEWS: u64 = 32;

/// Non-blocking handle the reporter uses to enqueue finalize votes for
/// off-thread verification. `Clone` so each per-epoch reporter shares the one
/// persistent actor.
#[derive(Clone)]
pub struct FinalizeVerifyMailbox {
    tx: mpsc::UnboundedSender<Job>,
}

impl FinalizeVerifyMailbox {
    /// Enqueue a raw finalize vote for verification + admission. Best-effort:
    /// a closed mailbox (graceful shutdown) silently drops the vote, exactly
    /// like the late-credit store it feeds.
    pub fn verify(&self, epoch: Epoch, finalize: Finalize<HybridScheme<MinSig>, Digest>) {
        let _ = self.tx.unbounded_send((epoch, finalize));
    }

    /// A mailbox whose receiver is already dropped - every `verify` is a no-op.
    /// For unit tests that exercise the reporter without a running actor.
    #[cfg(test)]
    pub fn disconnected() -> Self {
        let (tx, _rx) = mpsc::unbounded();
        Self { tx }
    }
}

/// Persistent actor that verifies finalize votes off the Simplex voter task and
/// admits the verified ones to the late-finalize store. Spawned once for the
/// node's lifetime; it resolves each vote's committee scheme by epoch through
/// the shared [`HybridSchemeProvider`], so it needs no per-epoch restart.
pub struct FinalizeVerifyActor {
    rx: mpsc::UnboundedReceiver<Job>,
    scheme_provider: HybridSchemeProvider<MinSig>,
    late_sig_store: SharedLateFinalizeStore,
    /// Verified finalize votes per view (future byzantine-equivocation
    /// detection). Bounded by [`OBSERVED_RETAIN_VIEWS`].
    observed_finalizes: BTreeMap<u64, Vec<Finalize<HybridScheme<MinSig>, Digest>>>,
}

impl FinalizeVerifyActor {
    /// Construct the actor and its paired mailbox.
    pub fn new(
        scheme_provider: HybridSchemeProvider<MinSig>,
        late_sig_store: SharedLateFinalizeStore,
    ) -> (Self, FinalizeVerifyMailbox) {
        let (tx, rx) = mpsc::unbounded::<Job>();
        (
            Self {
                rx,
                scheme_provider,
                late_sig_store,
                observed_finalizes: BTreeMap::new(),
            },
            FinalizeVerifyMailbox { tx },
        )
    }

    /// Drain the mailbox, verifying and admitting each vote, until the mailbox
    /// closes during graceful shutdown.
    pub async fn run(mut self) {
        while let Some((epoch, finalize)) = self.rx.next().await {
            self.verify_and_admit(epoch, finalize);
        }
    }

    /// Verify one finalize vote against its epoch's committee scheme; on success
    /// record it in the late-finalize store (so the proposer can credit it) and
    /// buffer it for equivocation detection. A vote whose epoch scheme is no
    /// longer registered (epoch already rotated out) or whose signature fails to
    /// verify is dropped - never admitted.
    ///
    /// `pub(crate)` so the reporter's test harness (which can build a real
    /// committee + verifiable finalize) can drive admission directly.
    pub(crate) fn verify_and_admit(
        &mut self,
        epoch: Epoch,
        finalize: Finalize<HybridScheme<MinSig>, Digest>,
    ) {
        let Some(scheme) = certificate::Provider::scoped(&self.scheme_provider, epoch) else {
            return;
        };
        let mut rng = bls_batch_verification_rng();
        if !finalize.verify(&mut rng, scheme.as_ref(), &Sequential) {
            return;
        }

        let view = finalize.proposal.view().get();

        // Record into the late-credit store, carrying the exact binding the vote
        // signed so a cross-view vote for the same `fb_hash` is dropped at
        // resolution instead of poisoning the aggregate.
        if let Some(hybrid_sig) = finalize.attestation.signature.get() {
            if let Ok(mut store) = self.late_sig_store.lock() {
                store.record_individual_vote(
                    finalize.proposal.round.epoch().get(),
                    finalize.proposal.round.view().get(),
                    finalize.proposal.parent.get(),
                    finalize.proposal.payload.0,
                    finalize.signer().get(),
                    &hybrid_sig.bls_individual_vote,
                );
            }
        }

        // Buffer the verified vote for future byzantine-equivocation detection,
        // keeping the buffer bounded to recent views.
        self.observed_finalizes
            .entry(view)
            .or_default()
            .push(finalize);
        let min_view = view.saturating_sub(OBSERVED_RETAIN_VIEWS);
        self.observed_finalizes.retain(|v, _| *v >= min_view);
    }

    /// Number of buffered (verified) votes for `view` - test-only introspection
    /// of `observed_finalizes`.
    #[cfg(test)]
    pub(crate) fn observed_len(&self, view: u64) -> usize {
        self.observed_finalizes.get(&view).map_or(0, Vec::len)
    }

    /// Synchronously process one queued vote if present (test-only), so a test
    /// can exercise the full reporter -> mailbox -> actor path without spawning
    /// the async `run` loop. Returns `true` if a job was processed.
    #[cfg(test)]
    pub(crate) fn try_process_one(&mut self) -> bool {
        match self.rx.try_recv() {
            Ok((epoch, finalize)) => {
                self.verify_and_admit(epoch, finalize);
                true
            }
            Err(_) => false,
        }
    }
}
