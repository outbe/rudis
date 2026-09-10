//! Executor actor - sends forkchoice updates and handles finalization.
//!
//! Tracks the canonical chain head and finalized block, sending FCU updates
//! to Reth's beacon engine. Receives finalized blocks from marshal via the
//! Reporter trait and acknowledges after successful EL processing.
//!
//! Internal forkchoice state is updated only after a successful FCU response
//! from the engine.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ForkchoiceState, PayloadId};
use commonware_consensus::types::Height;
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::acknowledgement::Acknowledgement;
use commonware_utils::channel::oneshot;
use futures::future::BoxFuture;
use futures::StreamExt;
use outbe_primitives::{
    projection::{ProjectionCheckpoint, ProjectionReadinessHandle, WaitOutcome},
    OutbeExecutionData, OutbePayloadAttributes, OutbePayloadTypes,
};
use reth_ethereum::node::api::BeaconForkChoiceUpdateError;
use reth_node_builder::ConsensusEngineHandle;
use tracing::{debug, error, info, warn};

use crate::{ancestry_readiness::AncestryReadiness, digest::Digest};

use super::ingress::{Mailbox, Message};

/// Type alias for the engine handle (standard Ethereum engine types).
type EngineHandle = ConsensusEngineHandle<OutbePayloadTypes>;

/// Exact finalized block identity handed to compressed-storage persistence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedCeBlock {
    pub height: u64,
    pub block_hash: B256,
    pub parent_block_hash: B256,
}

/// Result of one startup-only replay of a recovered finalized forkchoice.
///
/// The caller owns timeout, retry, and durable provider readback. Keeping those
/// concerns out of the actor preserves a single owner for Engine FCU types
/// without turning startup recovery into a second actor lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveredForkchoiceAttempt {
    Valid,
    Syncing,
    Invalid(String),
    Retryable(String),
    Fatal(String),
}

/// Finalization barrier installed by the node integration.
///
/// The returned future completes only after Reth's durable notification,
/// DB-only canonical/root verification, and the atomic CE MDBX commit. The
/// executor deliberately awaits it before acknowledging Marshal.
pub trait FinalizedCeCommitter: Send + Sync {
    fn commit_finalized(&self, block: FinalizedCeBlock) -> BoxFuture<'static, eyre::Result<()>>;
}

/// Immutable forkchoice tracking state.
///
/// Methods return a new `LastCanonicalized` without mutating self.
/// The caller commits by assigning the new value only after a successful FCU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LastCanonicalized {
    forkchoice: ForkchoiceState,
    head_height: Height,
    finalized_height: Height,
}

impl LastCanonicalized {
    fn from_recovered(genesis_hash: B256, finalized_height: u64, finalized_hash: B256) -> Self {
        if finalized_height > 0 {
            info!(
                target: "outbe::executor::recover",
                finalized_height,
                finalized_hash = %finalized_hash,
                "executor state recovered from persisted finalized block"
            );
            Self {
                forkchoice: ForkchoiceState {
                    head_block_hash: finalized_hash,
                    safe_block_hash: finalized_hash,
                    finalized_block_hash: finalized_hash,
                },
                head_height: Height::new(finalized_height),
                finalized_height: Height::new(finalized_height),
            }
        } else {
            info!(
                target: "outbe::executor::recover",
                genesis_hash = %genesis_hash,
                "executor state seeded from genesis (no finalized recovery)"
            );
            Self::new(genesis_hash)
        }
    }

    fn new(genesis_hash: B256) -> Self {
        Self {
            forkchoice: ForkchoiceState {
                head_block_hash: genesis_hash,
                safe_block_hash: genesis_hash,
                finalized_block_hash: genesis_hash,
            },
            head_height: Height::zero(),
            finalized_height: Height::zero(),
        }
    }

    /// Returns new state with updated head.
    ///
    /// Rejects head below finalized height, and rejects head at finalized
    /// height with a hash that conflicts with the committed finalized hash.
    /// Allows rollback to the finalized block itself (view-timeout scenario
    /// where Simplex parent rolls back to the last finalized block).
    ///
    /// Pre-finalization head changes are expected on view timeout / leader
    /// rotation; logging the flip-flop and rollback paths here makes those
    /// otherwise-silent canonical-tip transitions auditable from the logs.
    fn update_head(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height < this.finalized_height {
            return this;
        }
        if height == this.finalized_height && digest.0 != this.forkchoice.finalized_block_hash {
            crate::metrics::record_executor_head_finalized_conflict();
            warn!(
                target: "outbe::executor::head_conflict",
                %height,
                finalized_hash = %this.forkchoice.finalized_block_hash,
                requested_hash = %digest.0,
                "update_head rejected: conflicting hash at finalized height"
            );
            return this;
        }
        if this.head_height == height && this.forkchoice.head_block_hash != digest.0 {
            crate::metrics::record_executor_head_flip();
            warn!(
                target: "outbe::executor::head_flip",
                %height,
                old_head = %this.forkchoice.head_block_hash,
                new_head = %digest.0,
                finalized_height = %this.finalized_height,
                "canonical head reorged at same height (pre-finalization, expected on view timeout)"
            );
        } else if height < this.head_height {
            crate::metrics::record_executor_head_rollback();
            warn!(
                target: "outbe::executor::head_rollback",
                old_height = %this.head_height,
                old_head = %this.forkchoice.head_block_hash,
                new_height = %height,
                new_head = %digest.0,
                finalized_height = %this.finalized_height,
                "canonical head moved to lower height (pre-finalization parent switch)"
            );
        }
        this.head_height = height;
        this.forkchoice.head_block_hash = digest.0;
        this
    }

    /// Returns new state with updated finalized (and head if needed).
    ///
    /// The strict `>` check enforces protocol invariant
    /// "finalization is monotonic". Stale and conflicting attempts are
    /// silently ignored by the check; we log them so that any future bug
    /// or upstream wire-up regression surfaces immediately instead of
    /// silently dropping a finalize message.
    fn update_finalized(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized_height {
            this.finalized_height = height;
            this.forkchoice.safe_block_hash = digest.0;
            this.forkchoice.finalized_block_hash = digest.0;
            if height >= this.head_height {
                this.head_height = height;
                this.forkchoice.head_block_hash = digest.0;
            }
        } else if height == this.finalized_height
            && digest.0 != this.forkchoice.finalized_block_hash
        {
            crate::metrics::record_executor_finalized_conflict();
            tracing::error!(
                target: "outbe::executor::finalized_conflict",
                %height,
                committed = %this.forkchoice.finalized_block_hash,
                attempted = %digest.0,
                "attempted finalized rewrite at same height - protocol invariant violation, ignored"
            );
        } else if height < this.finalized_height {
            crate::metrics::record_executor_finalized_stale();
            warn!(
                target: "outbe::executor::finalized_stale",
                %height,
                committed_height = %this.finalized_height,
                "stale finalized message ignored"
            );
        }
        this
    }
}

fn next_deadline(now: SystemTime, interval: Duration) -> SystemTime {
    match now.checked_add(interval) {
        Some(deadline) => deadline,
        None => now,
    }
}

/// Whether to just canonicalize or also build a payload.
#[allow(clippy::large_enum_variant)]
enum MaybeBuild {
    JustCanonicalize {
        response: oneshot::Sender<eyre::Result<()>>,
    },
    AlsoBuild {
        attributes: OutbePayloadAttributes,
        response: oneshot::Sender<eyre::Result<PayloadId>>,
    },
}

impl MaybeBuild {
    fn attributes(&self) -> Option<&OutbePayloadAttributes> {
        match self {
            Self::JustCanonicalize { .. } => None,
            Self::AlsoBuild { attributes, .. } => Some(attributes),
        }
    }

    fn send_error(self, err: eyre::Report) {
        match self {
            Self::JustCanonicalize { response } => {
                let _ = response.send(Err(err));
            }
            Self::AlsoBuild { response, .. } => {
                let _ = response.send(Err(err));
            }
        }
    }
}

/// Whether to update head or finalized.
enum HeadOrFinalized {
    Head,
    Finalized,
}

async fn wait_for_finalized_parent(
    readiness: ProjectionReadinessHandle,
    required: ProjectionCheckpoint,
) -> eyre::Result<()> {
    match readiness.wait_for(required, std::future::pending()).await {
        WaitOutcome::Ready => Ok(()),
        WaitOutcome::BudgetExpired => Err(eyre::eyre!(
            "finalized parent projection wait expired without a request budget"
        )),
        WaitOutcome::ProjectionAhead => Err(eyre::eyre!(
            "projection is ahead of finalized parent {} at height {}",
            required.block_hash,
            required.block_number
        )),
        WaitOutcome::Fatal(failure) => Err(eyre::eyre!(
            "projection readiness failed ({:?}): {}",
            failure.class,
            failure.message
        )),
    }
}

async fn wait_for_optional_ocomp_parent(
    readiness: Option<ProjectionReadinessHandle>,
    required: ProjectionCheckpoint,
) -> eyre::Result<()> {
    let Some(readiness) = readiness else {
        return Ok(());
    };
    wait_for_finalized_parent(readiness, required)
        .await
        .map_err(|error| eyre::eyre!("FullNode OCOMP readiness failed: {error}"))
}

/// The executor actor.
pub struct ExecutorActor<E> {
    context: E,
    engine: EngineHandle,
    state: LastCanonicalized,
    mailbox_rx: futures::channel::mpsc::UnboundedReceiver<Message>,
    // Intentionally `tokio::sync::mpsc`: this height-signal channel is created and
    // consumed cross-crate by `outbe-engine` (`stack.rs`). It is a plain channel
    // with no timer/spawn dependency - runtime-agnostic, so it does not pull the
    // tokio reactor onto the executor's deterministic-capable path.
    execution_finalized_height_tx: Option<tokio::sync::mpsc::UnboundedSender<u64>>,
    projection_readiness: ProjectionReadinessHandle,
    ocomp_readiness: Option<ProjectionReadinessHandle>,
    finalized_ce_committer: Option<Arc<dyn FinalizedCeCommitter>>,
    ancestry_readiness: Option<AncestryReadiness>,
    fcu_heartbeat_interval: Duration,
    next_fcu_heartbeat_deadline: SystemTime,
    pending_finalized_subscriptions: BTreeMap<Height, Vec<oneshot::Sender<()>>>,
}

impl<E> ExecutorActor<E>
where
    E: Clock + Metrics + Spawner + Send + Sync + 'static,
{
    /// Create a new executor actor with recovered finalized state.
    pub fn new(
        context: E,
        engine: EngineHandle,
        genesis_hash: B256,
        last_finalized_height: u64,
        last_finalized_hash: B256,
        projection_readiness: ProjectionReadinessHandle,
        execution_finalized_height_tx: Option<tokio::sync::mpsc::UnboundedSender<u64>>,
    ) -> (Self, Mailbox) {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        let mailbox = Mailbox::from_sender(tx);
        let state = LastCanonicalized::from_recovered(
            genesis_hash,
            last_finalized_height,
            last_finalized_hash,
        );
        let fcu_heartbeat_interval = crate::config::DEFAULT_FCU_HEARTBEAT_INTERVAL;
        let next_fcu_heartbeat_deadline = next_deadline(context.current(), fcu_heartbeat_interval);
        let actor = Self {
            context,
            engine,
            state,
            mailbox_rx: rx,
            execution_finalized_height_tx,
            projection_readiness,
            ocomp_readiness: None,
            finalized_ce_committer: None,
            ancestry_readiness: None,
            fcu_heartbeat_interval,
            next_fcu_heartbeat_deadline,
            pending_finalized_subscriptions: BTreeMap::new(),
        };
        (actor, mailbox)
    }

    pub fn with_ancestry_readiness(mut self, readiness: AncestryReadiness) -> Self {
        self.ancestry_readiness = Some(readiness);
        self
    }

    /// Installs the FullNode-only OCOMP replay barrier. Validators deliberately
    /// leave this unset, preserving their existing execution path.
    #[must_use]
    pub fn with_ocomp_readiness(mut self, readiness: ProjectionReadinessHandle) -> Self {
        self.ocomp_readiness = Some(readiness);
        self
    }

    /// Reconcile the startup state after marshal has exposed the exact
    /// application finalization record for the canonical execution head.
    ///
    /// Marshal must be started before that record can be queried, while its
    /// reporter needs this actor's mailbox. This startup-only builder closes
    /// that ordering loop without allowing a speculative execution head to be
    /// treated as finalized: the caller is responsible for validating the
    /// recovered finalization digest before invoking it.
    #[must_use]
    pub fn with_recovered_finalized_state(
        mut self,
        genesis_hash: B256,
        finalized_height: u64,
        finalized_hash: B256,
    ) -> Self {
        self.state =
            LastCanonicalized::from_recovered(genesis_hash, finalized_height, finalized_hash);
        self
    }

    /// Installs the mandatory compressed-storage barrier for live node wiring.
    #[must_use]
    pub fn with_finalized_ce_committer(mut self, committer: Arc<dyn FinalizedCeCommitter>) -> Self {
        self.finalized_ce_committer = Some(committer);
        self
    }

    /// Replay the exact recovered forkchoice once before this actor is started.
    ///
    /// This method neither mutates actor state nor starts mailbox or heartbeat
    /// processing. A caller must confirm the durable provider identity before
    /// allowing any downstream startup side effect.
    pub fn replay_recovered_forkchoice_once(
        &self,
        expected: ProjectionCheckpoint,
    ) -> BoxFuture<'static, RecoveredForkchoiceAttempt> {
        let expected_height = Height::new(expected.block_number);
        let forkchoice = self.state.forkchoice;
        if self.state.head_height != expected_height
            || self.state.finalized_height != expected_height
            || forkchoice.head_block_hash != expected.block_hash
            || forkchoice.safe_block_hash != expected.block_hash
            || forkchoice.finalized_block_hash != expected.block_hash
        {
            return Box::pin(async move {
                RecoveredForkchoiceAttempt::Fatal(format!(
                    "executor recovered state does not match startup anchor {}:{}",
                    expected.block_number, expected.block_hash
                ))
            });
        }

        let engine = self.engine.clone();
        Box::pin(async move {
            match engine.fork_choice_updated(forkchoice, None).await {
                Ok(response) if response.is_valid() => RecoveredForkchoiceAttempt::Valid,
                Ok(response) if response.is_syncing() => RecoveredForkchoiceAttempt::Syncing,
                Ok(response) if response.is_invalid() => {
                    RecoveredForkchoiceAttempt::Invalid(format!("{response:?}"))
                }
                Ok(response) => RecoveredForkchoiceAttempt::Fatal(format!(
                    "unexpected recovered forkchoice response: {response:?}"
                )),
                Err(BeaconForkChoiceUpdateError::EngineUnavailable) => {
                    RecoveredForkchoiceAttempt::Retryable(
                        "beacon consensus engine task stopped before its FCU response".to_string(),
                    )
                }
                Err(error @ BeaconForkChoiceUpdateError::ForkchoiceUpdateError(_))
                | Err(error @ BeaconForkChoiceUpdateError::Internal(_)) => {
                    RecoveredForkchoiceAttempt::Fatal(error.to_string())
                }
            }
        })
    }

    /// Start the executor under the Commonware runtime supervision tree.
    pub fn start(
        self,
        marshal: crate::marshal_types::MarshalMailbox,
        last_consensus_finalized: Height,
    ) -> Handle<eyre::Result<()>> {
        let context = self.context.child("executor");
        context.spawn(move |_| self.run(marshal, last_consensus_finalized))
    }

    /// Run the executor event loop with startup backfill.
    ///
    /// Returns `Err` only on an unrecoverable fault: a *finalized* block (already
    /// agreed by consensus) that this node cannot apply locally. That means our
    /// state has diverged from the finalized chain, so the node must fail fast -
    /// the supervisor treats this `Err` as fatal and shuts the node down with the
    /// structured cause, rather than the silent fall-through that previously
    /// surfaced only as an opaque marshal "did not acknowledge" panic.
    async fn run(
        mut self,
        marshal: crate::marshal_types::MarshalMailbox,
        last_consensus_finalized: Height,
    ) -> eyre::Result<()> {
        // Startup backfill: execution behind consensus.
        let execution_height = self.state.finalized_height;
        if let Some(readiness) = &self.ancestry_readiness {
            readiness.set_target_height(last_consensus_finalized.get());
            readiness.note_ready_height(execution_height.get());
        }
        if last_consensus_finalized > execution_height {
            info!(
                execution_height = execution_height.get(),
                consensus_height = last_consensus_finalized.get(),
                "backfilling execution from marshal"
            );
            for h in (execution_height.get() + 1)..=last_consensus_finalized.get() {
                let height = Height::new(h);
                match marshal.get_block(height).await {
                    Some(block) => {
                        let digest = crate::digest::Digest(block.block_hash());
                        match self.handle_finalize_inner(height, digest, block).await {
                            Ok(()) => {
                                self.notify_finalized_subscribers(height);
                                self.notify_execution_finalized(height);
                            }
                            Err(error) => {
                                error!(
                                    %height, %digest, %error,
                                    "backfill: finalized block failed local execution; \
                                     finalized state diverged - failing fast"
                                );
                                return Err(eyre::eyre!(
                                    "executor backfill cannot apply finalized block at \
                                     height {height} digest {digest}: {error}"
                                ));
                            }
                        }
                    }
                    None => {
                        // The backfill range is `(execution_height, last_consensus_finalized]`
                        // - every height here is <= the finalized height marshal itself
                        // reported, so marshal must be able to produce it. A `None` means
                        // marshal's archive is inconsistent (claims finalized to N but cannot
                        // serve M <= N). Skipping would leave a non-contiguous execution gap
                        // (the next block's new_payload fails on the missing parent, or the
                        // node silently stalls below consensus height), so this is an
                        // unrecoverable fault - fail fast like the execution-failure branch.
                        error!(
                            height = h,
                            consensus_height = last_consensus_finalized.get(),
                            "backfill: marshal is missing a finalized block at or below its \
                             reported finalized height; archive is inconsistent - failing fast"
                        );
                        return Err(eyre::eyre!(
                            "executor backfill: marshal missing finalized block at height {h} \
                             (<= reported finalized height {}); cannot reconstruct contiguous \
                             execution state",
                            last_consensus_finalized.get()
                        ));
                    }
                }
            }
            info!("backfill complete");
        } else if execution_height > last_consensus_finalized {
            warn!(
                execution_height = execution_height.get(),
                consensus_height = last_consensus_finalized.get(),
                "execution ahead of consensus - skipping backfill"
            );
        } else {
            info!("execution and consensus at same height - no backfill needed");
        }

        self.run_live_loop().await
    }

    async fn run_live_loop(&mut self) -> eyre::Result<()> {
        // Live event loop. Mailbox messages stay biased ahead of heartbeat so
        // queued marshal updates are not overtaken by timer work.
        loop {
            let heartbeat = self.context.sleep_until(self.next_fcu_heartbeat_deadline);
            let mut heartbeat = std::pin::pin!(heartbeat);

            // `commonware_macros::select!` is biased (top-to-bottom): mailbox
            // messages stay ahead of the heartbeat timer, matching the prior
            // `tokio::select! { biased; .. }`. Runs on both the tokio and the
            // deterministic runtimes (no tokio reactor dependency).
            commonware_macros::select! {
                msg = self.mailbox_rx.next() => {
                    let Some(msg) = msg else {
                        info!("executor actor mailbox closed, exiting");
                        return Ok(());
                    };
                    // A fatal (diverged-finalized-state) message propagates up and
                    // ends the loop, signalling the supervisor to shut the node down.
                    self.handle_message(msg).await?;
                },

                _ = &mut heartbeat => {
                    self.send_fcu_heartbeat().await;
                },
            }
        }
    }

    async fn handle_message(&mut self, msg: Message) -> eyre::Result<()> {
        match msg {
            Message::CanonicalizeHead(req) => {
                self.canonicalize(
                    HeadOrFinalized::Head,
                    req.height,
                    req.digest,
                    MaybeBuild::JustCanonicalize {
                        response: req.response,
                    },
                )
                .await;
                Ok(())
            }
            Message::CanonicalizeAndBuild(req) => {
                self.canonicalize(
                    HeadOrFinalized::Head,
                    req.height,
                    req.digest,
                    MaybeBuild::AlsoBuild {
                        attributes: req.attributes,
                        response: req.response,
                    },
                )
                .await;
                Ok(())
            }
            Message::MarshalUpdate(update) => self.handle_marshal_update(*update).await,
            Message::SubscribeFinalized(req) => {
                self.handle_subscribe_finalized(req.height, req.response);
                Ok(())
            }
        }
    }

    fn handle_subscribe_finalized(&mut self, height: Height, response: oneshot::Sender<()>) {
        if self.state.finalized_height >= height {
            let _ = response.send(());
            return;
        }
        self.pending_finalized_subscriptions
            .entry(height)
            .or_default()
            .push(response);
    }

    fn reset_fcu_heartbeat_deadline(&mut self) {
        self.next_fcu_heartbeat_deadline =
            next_deadline(self.context.current(), self.fcu_heartbeat_interval);
    }

    async fn send_fcu_heartbeat(&mut self) {
        debug!(
            head_block_hash = %self.state.forkchoice.head_block_hash,
            safe_block_hash = %self.state.forkchoice.safe_block_hash,
            finalized_block_hash = %self.state.forkchoice.finalized_block_hash,
            head_height = %self.state.head_height,
            finalized_height = %self.state.finalized_height,
            "sending forkchoice-update heartbeat"
        );

        match self
            .engine
            .fork_choice_updated(self.state.forkchoice, None)
            .await
        {
            Ok(response) if response.is_invalid() => {
                warn!(
                    ?response,
                    "forkchoice-update heartbeat returned invalid status"
                );
            }
            Ok(response) if response.is_syncing() => {
                warn!(
                    ?response,
                    "forkchoice-update heartbeat returned syncing status"
                );
            }
            Ok(response) => {
                debug!(?response, "forkchoice-update heartbeat completed");
            }
            Err(error) => {
                warn!(%error, "forkchoice-update heartbeat failed");
            }
        }
        self.reset_fcu_heartbeat_deadline();
    }

    /// Unified canonicalization method.
    ///
    /// Computes new forkchoice state, sends FCU to engine, and only commits
    /// the state update after a successful response.
    async fn canonicalize(
        &mut self,
        head_or_finalized: HeadOrFinalized,
        height: Height,
        digest: Digest,
        maybe_build: MaybeBuild,
    ) {
        let new_state = match head_or_finalized {
            HeadOrFinalized::Head => self.state.update_head(height, digest),
            HeadOrFinalized::Finalized => self.state.update_finalized(height, digest),
        };

        // Skip FCU if no state change AND we're not building a payload.
        if new_state == self.state {
            if let MaybeBuild::JustCanonicalize { response } = maybe_build {
                let _ = response.send(Ok(()));
                return;
            }
        }

        info!(
            head_block_hash = %new_state.forkchoice.head_block_hash,
            head_height = %new_state.head_height,
            finalized_block_hash = %new_state.forkchoice.finalized_block_hash,
            finalized_height = %new_state.finalized_height,
            "sending forkchoice-update",
        );

        let fcu_response = match self
            .engine
            .fork_choice_updated(new_state.forkchoice, maybe_build.attributes().cloned())
            .await
        {
            Err(e) => {
                self.reset_fcu_heartbeat_deadline();
                warn!(%e, "failed to send forkchoice update");
                maybe_build.send_error(eyre::eyre!("FCU failed: {e}"));
                return;
            }
            Ok(response) => response,
        };
        self.reset_fcu_heartbeat_deadline();

        if fcu_response.is_syncing() {
            warn!(
                ?fcu_response,
                head_block_hash = %new_state.forkchoice.head_block_hash,
                safe_block_hash = %new_state.forkchoice.safe_block_hash,
                finalized_block_hash = %new_state.forkchoice.finalized_block_hash,
                head_height = %new_state.head_height,
                finalized_height = %new_state.finalized_height,
                "forkchoice update returned syncing status"
            );
        } else if fcu_response.is_valid() {
            info!(
                ?fcu_response,
                head_block_hash = %new_state.forkchoice.head_block_hash,
                finalized_block_hash = %new_state.forkchoice.finalized_block_hash,
                head_height = %new_state.head_height,
                finalized_height = %new_state.finalized_height,
                "forkchoice update returned valid status"
            );
        }

        if fcu_response.is_invalid() {
            warn!(?fcu_response, "forkchoice update returned invalid status");
            maybe_build.send_error(eyre::eyre!(
                "FCU returned invalid: {:?}",
                fcu_response.payload_status
            ));
            return;
        }

        // Success - respond and commit.
        match maybe_build {
            MaybeBuild::JustCanonicalize { response } => {
                let _ = response.send(Ok(()));
            }
            MaybeBuild::AlsoBuild { response, .. } => {
                match fcu_response.payload_id {
                    Some(id) => {
                        let _ = response.send(Ok(id));
                    }
                    None => {
                        let _ = response.send(Err(eyre::eyre!(
                            "FCU did not return payload_id: payload_status={:?} latest_valid_hash={:?} head={} safe={} finalized={} head_height={} finalized_height={}",
                            fcu_response.payload_status,
                            fcu_response.payload_status.latest_valid_hash,
                            new_state.forkchoice.head_block_hash,
                            new_state.forkchoice.safe_block_hash,
                            new_state.forkchoice.finalized_block_hash,
                            new_state.head_height,
                            new_state.finalized_height,
                        )));
                        // Don't commit state if we didn't get a payload_id.
                        return;
                    }
                }
            }
        }
        self.state = new_state;
    }

    /// Handle a marshal update (finalized block delivery or tip notification).
    async fn handle_marshal_update(
        &mut self,
        update: crate::marshal_types::MarshalUpdate,
    ) -> eyre::Result<()> {
        match update {
            commonware_consensus::marshal::Update::Block(block, ack) => {
                let height = Height::new(block.number());
                let digest = Digest(block.block_hash());
                if height == self.state.finalized_height
                    && digest.0 == self.state.forkchoice.finalized_block_hash
                {
                    info!(
                        %height,
                        %digest,
                        "marshal-delivered block already canonical after recovery; acknowledging without reexecution"
                    );
                    ack.acknowledge();
                    self.notify_finalized_subscribers(height);
                    self.notify_execution_finalized(height);
                    return Ok(());
                }
                if height == Height::zero() {
                    let expected = self.state.forkchoice.finalized_block_hash;
                    return Err(eyre::eyre!(
                        "marshal delivered unexpected genesis anchor: digest {digest}, \
                         canonical finalized height {}, canonical hash {expected}",
                        self.state.finalized_height
                    ));
                }
                info!(
                    %height,
                    %digest,
                    "marshal-delivered block: handle_finalize_inner start"
                );
                match self.handle_finalize_inner(height, digest, block).await {
                    Ok(()) => {
                        info!(%height, %digest, "marshal-delivered block finalized and acked");
                        // Acknowledge ONLY after the block is durably applied. The
                        // marshal `Exact` waiter resolves once every cloned ack is
                        // acknowledged.
                        ack.acknowledge();
                        self.notify_finalized_subscribers(height);
                        self.notify_execution_finalized(height);
                        Ok(())
                    }
                    Err(error) => {
                        // A finalized block (already agreed by consensus) that we
                        // cannot apply locally means our state has diverged from the
                        // finalized chain - unrecoverable. Fail fast deterministically
                        // with the structured cause. We deliberately do NOT
                        // acknowledge: the block was not processed, and acking would
                        // lie to the marshal's progress tracking (letting it prune a
                        // block we still need).
                        //
                        // Note: the unacknowledged `ack` still cancels on drop, and
                        // upstream marshal `handle_ack` treats a canceled ack as fatal
                        // (`panic!("application did not acknowledge...")`). With the
                        // runtime's `catch_panics`, that panic is CAUGHT (it does not
                        // abort the process) - so it is NOT the shutdown driver and does
                        // NOT pre-empt this path. The authoritative shutdown driver is
                        // the structured `Err` returned here: it propagates out of
                        // run_live_loop/run, the supervisor select treats the executor
                        // exit as fatal, and the node shuts down with the cause below.
                        // The marshal panic may still appear in logs (a caught,
                        // less-informative secondary symptom) - this `error!` precedes
                        // it with the real reason.
                        error!(
                            %height, %digest, %error,
                            "finalized block failed local execution; \
                             finalized state diverged - failing fast"
                        );
                        Err(eyre::eyre!(
                            "executor cannot apply finalized block at \
                             height {height} digest {digest}: {error}"
                        ))
                    }
                }
            }
            commonware_consensus::marshal::Update::Tip(round, height, digest) => {
                debug!(
                    %round, %height, %digest,
                    "marshal tip update"
                );
                Ok(())
            }
        }
    }

    /// Process a finalized block through the execution layer.
    ///
    /// Returns `Err` when the finalized block cannot be applied (execution layer
    /// rejected it, the engine call failed, or canonicalization failed/was
    /// dropped). A `Syncing` payload status is not a failure - it proceeds to
    /// canonicalization like the prior behavior.
    async fn handle_finalize_inner(
        &mut self,
        height: Height,
        digest: crate::digest::Digest,
        block: crate::block::ConsensusBlock,
    ) -> eyre::Result<()> {
        let parent_height = height.get().checked_sub(1).ok_or_else(|| {
            eyre::eyre!(
                "cannot execute finalized genesis block through successor path: digest {digest}"
            )
        })?;
        wait_for_finalized_parent(
            self.projection_readiness.clone(),
            ProjectionCheckpoint {
                block_number: parent_height,
                block_hash: block.parent_hash(),
            },
        )
        .await?;
        wait_for_optional_ocomp_parent(
            self.ocomp_readiness.clone(),
            ProjectionCheckpoint {
                block_number: parent_height,
                block_hash: block.parent_hash(),
            },
        )
        .await?;

        let execution_data =
            OutbeExecutionData::new(std::sync::Arc::new(block.clone().into_inner()));

        if crate::test_faults::should_drop_new_payload_for_test(height) {
            warn!(
                height = %height,
                digest = %digest,
                "test-marshal-drop: skipping finalized new_payload before FCU"
            );
        } else {
            match self.engine.new_payload(execution_data).await {
                Ok(status) => {
                    if status.is_valid() {
                        info!(
                            height = %height,
                            digest = %digest,
                            ?status,
                            "finalized block accepted by execution layer"
                        );
                    } else if status.is_syncing() {
                        warn!(
                            height = %height,
                            digest = %digest,
                            ?status,
                            "execution layer syncing on finalized block"
                        );
                    }
                    if !status.is_valid() && !status.is_syncing() {
                        return Err(eyre::eyre!(
                            "finalized block rejected by execution layer at \
                             height {height} digest {digest}: status={status:?}"
                        ));
                    }
                }
                Err(e) => {
                    return Err(eyre::eyre!(
                        "failed to send finalized block to execution layer at \
                         height {height} digest {digest}: {e}"
                    ));
                }
            }
        }

        // Finalize via the unified canonicalize path (commit-after-success).
        let (response_tx, response_rx) = oneshot::channel();
        self.canonicalize(
            HeadOrFinalized::Finalized,
            height,
            digest,
            MaybeBuild::JustCanonicalize {
                response: response_tx,
            },
        )
        .await;
        match response_rx.await {
            Ok(Ok(())) => {
                if let Some(committer) = &self.finalized_ce_committer {
                    committer
                        .commit_finalized(FinalizedCeBlock {
                            height: height.get(),
                            block_hash: block.block_hash(),
                            parent_block_hash: block.parent_hash(),
                        })
                        .await?;
                }
                Ok(())
            }
            Ok(Err(error)) => Err(eyre::eyre!(
                "failed to canonicalize finalized block at \
                 height {height} digest {digest}: {error}"
            )),
            Err(_) => Err(eyre::eyre!(
                "executor canonicalize response dropped for finalized block at \
                 height {height} digest {digest}"
            )),
        }
    }

    fn notify_execution_finalized(&self, height: Height) {
        if let Some(readiness) = &self.ancestry_readiness {
            let was_ready = readiness.is_ready();
            readiness.note_ready_height(height.get());
            if !was_ready && readiness.is_ready() {
                info!(
                    current_height = height.get(),
                    target_height = readiness.target_height(),
                    "marshal ancestry gate opened after executor finalized required height"
                );
            }
        }
        if let Some(tx) = &self.execution_finalized_height_tx {
            let _ = tx.send(height.get());
        }
    }

    fn notify_finalized_subscribers(&mut self, height: Height) {
        let pending = std::mem::take(&mut self.pending_finalized_subscriptions);
        for (target_height, mut subscribers) in pending {
            if target_height <= height {
                for response in subscribers.drain(..) {
                    let _ = response.send(());
                }
            } else {
                self.pending_finalized_subscriptions
                    .insert(target_height, subscribers);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use alloy_primitives::{Bytes, B256};
    use alloy_rpc_types_engine::{PayloadStatus, PayloadStatusEnum};
    use commonware_consensus::marshal::Update;
    use commonware_consensus::types::Height;
    use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _};
    use commonware_utils::acknowledgement::{Acknowledgement as _, Exact};
    use outbe_primitives::{
        projection::{
            projection_readiness, ProjectionCheckpoint, ProjectionFailure, ProjectionFailureClass,
            ProjectionReadinessHandle, ProjectionReadinessPublisher, ProjectionStatus,
        },
        OutbeHeader,
    };
    use reth_ethereum::node::api::{BeaconEngineMessage, OnForkChoiceUpdated};
    use reth_ethereum::{primitives::SealedBlock, Block};
    use reth_node_builder::ConsensusEngineHandle;

    use super::{FinalizedCeBlock, FinalizedCeCommitter, LastCanonicalized};
    use crate::ancestry_readiness::AncestryReadiness;
    use crate::block::ConsensusBlock;
    use crate::digest::Digest;

    fn executor_test_block(number: u64, seed: u8) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.number = number;
        block.header.extra_data = Bytes::from(vec![seed]);
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    fn ready_projection(
        baseline_hash: B256,
        checkpoint: ProjectionCheckpoint,
    ) -> (ProjectionReadinessPublisher, ProjectionReadinessHandle) {
        projection_readiness(
            ProjectionCheckpoint {
                block_number: 0,
                block_hash: baseline_hash,
            },
            ProjectionStatus::Ready { checkpoint },
        )
    }

    fn ready_projection_for_block(
        genesis_hash: B256,
        block: &ConsensusBlock,
    ) -> (ProjectionReadinessPublisher, ProjectionReadinessHandle) {
        ready_projection(
            genesis_hash,
            ProjectionCheckpoint {
                block_number: block.number().saturating_sub(1),
                block_hash: block.parent_hash(),
            },
        )
    }

    struct GatedCeCommitter {
        called: Mutex<Option<tokio::sync::oneshot::Sender<FinalizedCeBlock>>>,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl FinalizedCeCommitter for GatedCeCommitter {
        fn commit_finalized(
            &self,
            block: FinalizedCeBlock,
        ) -> futures::future::BoxFuture<'static, eyre::Result<()>> {
            self.called
                .lock()
                .expect("called lock")
                .take()
                .expect("single finalized commit")
                .send(block)
                .expect("test must observe commit barrier");
            let release = self
                .release
                .lock()
                .expect("release lock")
                .take()
                .expect("single finalized commit");
            Box::pin(async move {
                release
                    .await
                    .map_err(|_| eyre::eyre!("test release dropped"))?;
                Ok(())
            })
        }
    }

    #[test]
    fn finalized_parent_wait_blocks_until_the_exact_checkpoint_is_published() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let baseline = ProjectionCheckpoint {
                block_number: 0,
                block_hash: B256::ZERO,
            };
            let required = ProjectionCheckpoint {
                block_number: 4,
                block_hash: B256::repeat_byte(0x44),
            };
            let (publisher, readiness) =
                projection_readiness(baseline, ProjectionStatus::CatchingUp { checkpoint: None });
            let wait = super::wait_for_finalized_parent(readiness, required);
            futures::pin_mut!(wait);

            assert!(matches!(
                futures::poll!(&mut wait),
                std::task::Poll::Pending
            ));

            publisher.publish(ProjectionStatus::Ready {
                checkpoint: required,
            });
            wait.await
                .expect("finalized execution must resume at the exact projected parent");
        });
    }

    #[test]
    fn finalized_parent_wait_fails_closed_for_ahead_and_fatal_projection() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let baseline = ProjectionCheckpoint {
                block_number: 0,
                block_hash: B256::ZERO,
            };
            let required = ProjectionCheckpoint {
                block_number: 4,
                block_hash: B256::repeat_byte(0x44),
            };
            let ahead = ProjectionCheckpoint {
                block_number: 5,
                block_hash: B256::repeat_byte(0x55),
            };
            let (_publisher, ahead_readiness) =
                projection_readiness(baseline, ProjectionStatus::Ready { checkpoint: ahead });
            let error = super::wait_for_finalized_parent(ahead_readiness, required)
                .await
                .expect_err("an ahead projection must fail finalized execution closed");
            assert!(error.to_string().contains("projection is ahead"));

            let (_publisher, fatal_readiness) = projection_readiness(
                baseline,
                ProjectionStatus::Fatal {
                    checkpoint: None,
                    error: ProjectionFailure::new(
                        ProjectionFailureClass::CorruptBody,
                        "test corrupt body",
                    ),
                },
            );
            let error = super::wait_for_finalized_parent(fatal_readiness, required)
                .await
                .expect_err("a fatal projection must fail finalized execution closed");
            assert!(error.to_string().contains("test corrupt body"));
        });
    }

    #[test]
    fn optional_full_node_ocomp_gate_waits_for_the_exact_parent() {
        commonware_runtime::deterministic::Runner::default().start(|_| async move {
            let baseline = ProjectionCheckpoint {
                block_number: 0,
                block_hash: B256::ZERO,
            };
            let required = ProjectionCheckpoint {
                block_number: 100,
                block_hash: B256::repeat_byte(0x64),
            };
            super::wait_for_optional_ocomp_parent(None, required)
                .await
                .expect("Validator path has no FullNode OCOMP gate");

            let (publisher, readiness) =
                projection_readiness(baseline, ProjectionStatus::CatchingUp { checkpoint: None });
            let wait = super::wait_for_optional_ocomp_parent(Some(readiness), required);
            futures::pin_mut!(wait);
            assert!(matches!(
                futures::poll!(&mut wait),
                std::task::Poll::Pending
            ));
            publisher.publish(ProjectionStatus::Ready {
                checkpoint: required,
            });
            wait.await
                .expect("FullNode resumes only at the exact OCOMP checkpoint");
        });
    }

    #[test]
    fn update_head_returns_new_state() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);

        let state = state.update_head(Height::new(12), Digest(B256::repeat_byte(0x0C)));
        assert_eq!(state.head_height, Height::new(12));
        assert_eq!(state.forkchoice.head_block_hash, B256::repeat_byte(0x0C));

        let state = state.update_head(Height::new(11), Digest(B256::repeat_byte(0x0B)));
        assert_eq!(state.head_height, Height::new(11));
        assert_eq!(state.forkchoice.head_block_hash, B256::repeat_byte(0x0B));
    }

    #[test]
    fn update_head_flip_flop_at_same_height_is_observable() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);

        let state = state.update_head(Height::new(7), Digest(B256::repeat_byte(0x70)));
        let flipped = state.update_head(Height::new(7), Digest(B256::repeat_byte(0x71)));

        assert_eq!(flipped.head_height, Height::new(7));
        assert_eq!(flipped.forkchoice.head_block_hash, B256::repeat_byte(0x71));
    }

    #[test]
    fn update_finalized_same_height_different_digest_is_noop() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);
        let state = state.update_finalized(Height::new(9), Digest(B256::repeat_byte(0x90)));

        let conflicting = state.update_finalized(Height::new(9), Digest(B256::repeat_byte(0x99)));

        assert_eq!(conflicting.finalized_height, Height::new(9));
        assert_eq!(
            conflicting.forkchoice.finalized_block_hash,
            B256::repeat_byte(0x90)
        );
    }

    #[test]
    fn update_finalized_same_height_conflict_does_not_mutate_head() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);
        let finalized_hash = B256::repeat_byte(0x09);
        let state = state.update_finalized(Height::new(9), Digest(finalized_hash));
        assert_eq!(state.forkchoice.head_block_hash, finalized_hash);

        let conflicting = state.update_finalized(Height::new(9), Digest(B256::repeat_byte(0x99)));
        assert_eq!(conflicting.forkchoice.finalized_block_hash, finalized_hash);
        assert_eq!(conflicting.forkchoice.head_block_hash, finalized_hash);
    }

    #[test]
    fn update_finalized_lower_height_is_noop() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);
        let state = state.update_finalized(Height::new(20), Digest(B256::repeat_byte(0x20)));

        let stale = state.update_finalized(Height::new(10), Digest(B256::repeat_byte(0x10)));

        assert_eq!(stale.finalized_height, Height::new(20));
        assert_eq!(
            stale.forkchoice.finalized_block_hash,
            B256::repeat_byte(0x20)
        );
    }

    #[test]
    fn update_head_rejects_below_finalized() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);
        let state = state.update_finalized(Height::new(5), Digest(B256::repeat_byte(0x05)));

        let same = state.update_head(Height::new(4), Digest(B256::repeat_byte(0x44)));
        assert_eq!(same.head_height, state.head_height);
        assert_eq!(
            same.forkchoice.head_block_hash,
            state.forkchoice.head_block_hash
        );
    }

    #[test]
    fn update_head_rejects_finalized_height_conflicting_hash() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);
        let finalized_hash = B256::repeat_byte(0x05);
        let state = state.update_finalized(Height::new(5), Digest(finalized_hash));
        let state = state.update_head(Height::new(6), Digest(B256::repeat_byte(0x06)));

        let conflicting = B256::repeat_byte(0x55);
        assert_ne!(conflicting, finalized_hash);
        let rejected = state.update_head(Height::new(5), Digest(conflicting));
        assert_eq!(rejected.head_height, Height::new(6));
        assert_eq!(rejected.forkchoice.head_block_hash, B256::repeat_byte(0x06));
    }

    #[test]
    fn update_head_rolls_back_to_finalized_hash() {
        let genesis = B256::repeat_byte(0x01);
        let state = LastCanonicalized::new(genesis);
        let finalized_hash = B256::repeat_byte(0x05);
        let state = state.update_finalized(Height::new(5), Digest(finalized_hash));
        let state = state.update_head(Height::new(6), Digest(B256::repeat_byte(0x06)));
        assert_eq!(state.head_height, Height::new(6));

        let rolled_back = state.update_head(Height::new(5), Digest(finalized_hash));
        assert_eq!(rolled_back.head_height, Height::new(5));
        assert_eq!(rolled_back.forkchoice.head_block_hash, finalized_hash);
    }

    #[test]
    fn fresh_bootstrap_seeds_from_genesis() {
        let genesis = B256::repeat_byte(0xAA);
        let state = LastCanonicalized::from_recovered(genesis, 0, genesis);

        assert_eq!(state.finalized_height, Height::zero());
        assert_eq!(state.head_height, Height::zero());
        assert_eq!(state.forkchoice.finalized_block_hash, genesis);
        assert_eq!(state.forkchoice.head_block_hash, genesis);
    }

    #[test]
    fn restart_seeds_from_recovered_finalized() {
        let genesis = B256::repeat_byte(0xAA);
        let finalized = B256::repeat_byte(0xBB);
        let state = LastCanonicalized::from_recovered(genesis, 100, finalized);

        assert_eq!(state.finalized_height, Height::new(100));
        assert_eq!(state.head_height, Height::new(100));
        assert_eq!(state.forkchoice.finalized_block_hash, finalized);
        assert_eq!(state.forkchoice.head_block_hash, finalized);
        assert_eq!(state.forkchoice.safe_block_hash, finalized);
    }

    #[test]
    fn update_finalized_does_not_regress() {
        let genesis = B256::repeat_byte(0xAA);
        let finalized = B256::repeat_byte(0xBB);
        let state = LastCanonicalized::from_recovered(genesis, 100, finalized);

        let same = state.update_finalized(Height::new(50), Digest(B256::repeat_byte(0xCC)));
        assert_eq!(same.finalized_height, Height::new(100));

        let newer = B256::repeat_byte(0xDD);
        let advanced = state.update_finalized(Height::new(101), Digest(newer));
        assert_eq!(advanced.finalized_height, Height::new(101));
        assert_eq!(advanced.forkchoice.finalized_block_hash, newer);
    }

    #[test]
    fn immutable_update_does_not_mutate_original() {
        let genesis = B256::repeat_byte(0x01);
        let original = LastCanonicalized::new(genesis);

        let updated = original.update_head(Height::new(10), Digest(B256::repeat_byte(0x0A)));
        assert_ne!(original, updated);
        assert_eq!(original.head_height, Height::zero());
        assert_eq!(updated.head_height, Height::new(10));
    }

    #[test]
    fn fcu_heartbeat_interval_is_shorter_than_watchdog_grace() {
        assert!(
            crate::config::DEFAULT_FCU_HEARTBEAT_INTERVAL < crate::config::EXECUTION_WATCHDOG_GRACE,
            "FCU heartbeat must retry before watchdog grace can trip"
        );
    }

    #[test]
    fn heartbeat_sends_fcu_to_last_forkchoice_without_payload_attributes() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let target = B256::repeat_byte(0xAA);
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: genesis,
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );
            actor.state = actor.state.update_finalized(Height::new(7), Digest(target));

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                let Some(message) = engine_rx.recv().await else {
                    panic!("heartbeat must send an FCU message");
                };
                match message {
                    BeaconEngineMessage::ForkchoiceUpdated {
                        state,
                        payload_attrs,
                        tx,
                    } => {
                        assert_eq!(state.head_block_hash, target);
                        assert_eq!(state.finalized_block_hash, target);
                        assert!(payload_attrs.is_none());
                        tx.send(Ok(OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                            PayloadStatusEnum::Valid,
                        ))))
                        .expect("test engine response receiver must be alive");
                    }
                    other => panic!("unexpected engine message: {other:?}"),
                }
            });

            actor.send_fcu_heartbeat().await;
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn recovered_forkchoice_attempt_sends_exact_finalized_identity_without_attributes() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let recovered = ProjectionCheckpoint {
                block_number: 7,
                block_hash: B256::repeat_byte(0x77),
            };
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection(genesis, recovered);
            let (actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                recovered.block_number,
                recovered.block_hash,
                projection_readiness,
                None,
            );

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                let Some(message) = engine_rx.recv().await else {
                    panic!("recovered forkchoice attempt must send an FCU message");
                };
                match message {
                    BeaconEngineMessage::ForkchoiceUpdated {
                        state,
                        payload_attrs,
                        tx,
                    } => {
                        assert_eq!(state.head_block_hash, recovered.block_hash);
                        assert_eq!(state.safe_block_hash, recovered.block_hash);
                        assert_eq!(state.finalized_block_hash, recovered.block_hash);
                        assert!(payload_attrs.is_none());
                        tx.send(Ok(OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                            PayloadStatusEnum::Valid,
                        ))))
                        .expect("test engine response receiver must be alive");
                    }
                    other => panic!("unexpected engine message: {other:?}"),
                }
            });

            let outcome = actor.replay_recovered_forkchoice_once(recovered).await;
            assert_eq!(outcome, super::RecoveredForkchoiceAttempt::Valid);
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn recovered_forkchoice_attempt_rejects_anchor_mismatch_before_engine_io() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let recovered = ProjectionCheckpoint {
                block_number: 7,
                block_hash: B256::repeat_byte(0x77),
            };
            let expected = ProjectionCheckpoint {
                block_number: 8,
                block_hash: B256::repeat_byte(0x88),
            };
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection(genesis, recovered);
            let (actor, _mailbox) = super::ExecutorActor::new(
                context,
                engine,
                genesis,
                recovered.block_number,
                recovered.block_hash,
                projection_readiness,
                None,
            );

            let outcome = actor.replay_recovered_forkchoice_once(expected).await;

            assert!(matches!(
                outcome,
                super::RecoveredForkchoiceAttempt::Fatal(message)
                    if message.contains("does not match startup anchor")
            ));
            assert!(engine_rx.try_recv().is_err());
        });
    }

    #[test]
    fn recovered_forkchoice_attempt_repeats_identical_state_after_syncing() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let recovered = ProjectionCheckpoint {
                block_number: 7,
                block_hash: B256::repeat_byte(0x77),
            };
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection(genesis, recovered);
            let (actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                recovered.block_number,
                recovered.block_hash,
                projection_readiness,
                None,
            );

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                for syncing in [true, false] {
                    let Some(BeaconEngineMessage::ForkchoiceUpdated {
                        state,
                        payload_attrs,
                        tx,
                    }) = engine_rx.recv().await
                    else {
                        panic!("expected recovered FCU attempt");
                    };
                    assert_eq!(state.head_block_hash, recovered.block_hash);
                    assert_eq!(state.safe_block_hash, recovered.block_hash);
                    assert_eq!(state.finalized_block_hash, recovered.block_hash);
                    assert!(payload_attrs.is_none());
                    let response = if syncing {
                        OnForkChoiceUpdated::syncing()
                    } else {
                        OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                            PayloadStatusEnum::Valid,
                        ))
                    };
                    tx.send(Ok(response))
                        .expect("test engine response receiver must be alive");
                }
            });

            assert_eq!(
                actor.replay_recovered_forkchoice_once(recovered).await,
                super::RecoveredForkchoiceAttempt::Syncing,
            );
            assert_eq!(
                actor.replay_recovered_forkchoice_once(recovered).await,
                super::RecoveredForkchoiceAttempt::Valid,
            );
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn recovered_forkchoice_attempt_distinguishes_payload_invalid_from_hard_error() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let recovered = ProjectionCheckpoint {
                block_number: 7,
                block_hash: B256::repeat_byte(0x77),
            };
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection(genesis, recovered);
            let (actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                recovered.block_number,
                recovered.block_hash,
                projection_readiness,
                None,
            );

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                let Some(BeaconEngineMessage::ForkchoiceUpdated { tx, .. }) =
                    engine_rx.recv().await
                else {
                    panic!("expected payload-invalid recovered FCU attempt");
                };
                tx.send(Ok(OnForkChoiceUpdated::with_invalid(
                    PayloadStatus::from_status(PayloadStatusEnum::Invalid {
                        validation_error: "test invalid payload".to_string(),
                    }),
                )))
                .expect("test engine response receiver must be alive");

                let Some(BeaconEngineMessage::ForkchoiceUpdated { tx, .. }) =
                    engine_rx.recv().await
                else {
                    panic!("expected invalid-state recovered FCU attempt");
                };
                tx.send(Ok(OnForkChoiceUpdated::invalid_state()))
                    .expect("test engine response receiver must be alive");
            });

            assert!(matches!(
                actor.replay_recovered_forkchoice_once(recovered).await,
                super::RecoveredForkchoiceAttempt::Invalid(message)
                    if message.contains("test invalid payload")
            ));
            assert!(matches!(
                actor.replay_recovered_forkchoice_once(recovered).await,
                super::RecoveredForkchoiceAttempt::Fatal(message)
                    if message.contains("invalid forkchoice state")
            ));
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn recovered_forkchoice_attempt_can_repeat_after_lost_response() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let recovered = ProjectionCheckpoint {
                block_number: 7,
                block_hash: B256::repeat_byte(0x77),
            };
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection(genesis, recovered);
            let (actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                recovered.block_number,
                recovered.block_hash,
                projection_readiness,
                None,
            );

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                let Some(BeaconEngineMessage::ForkchoiceUpdated { state, tx, .. }) =
                    engine_rx.recv().await
                else {
                    panic!("expected recovered FCU attempt with lost response");
                };
                assert_eq!(state.finalized_block_hash, recovered.block_hash);
                drop(tx);

                let Some(BeaconEngineMessage::ForkchoiceUpdated { state, tx, .. }) =
                    engine_rx.recv().await
                else {
                    panic!("expected repeated recovered FCU attempt");
                };
                assert_eq!(state.finalized_block_hash, recovered.block_hash);
                tx.send(Ok(OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                    PayloadStatusEnum::Valid,
                ))))
                .expect("test engine response receiver must be alive");
            });

            assert!(matches!(
                actor.replay_recovered_forkchoice_once(recovered).await,
                super::RecoveredForkchoiceAttempt::Retryable(_)
            ));
            assert_eq!(
                actor.replay_recovered_forkchoice_once(recovered).await,
                super::RecoveredForkchoiceAttempt::Valid,
            );
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn finalized_syncing_delivery_acks_and_heartbeat_repeats_fcu() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let block = executor_test_block(7, 0x77);
            let finalized_hash = block.block_hash();
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection_for_block(genesis, &block);
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                let Some(message) = engine_rx.recv().await else {
                    panic!("engine channel closed before new_payload");
                };
                match message {
                    BeaconEngineMessage::NewPayload { tx, .. } => tx
                        .send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Syncing)))
                        .expect("new_payload response receiver must be alive"),
                    other => panic!("unexpected first engine message: {other:?}"),
                }

                let Some(message) = engine_rx.recv().await else {
                    panic!("engine channel closed before finalized FCU");
                };
                match message {
                    BeaconEngineMessage::ForkchoiceUpdated {
                        state,
                        payload_attrs,
                        tx,
                    } => {
                        assert_eq!(state.head_block_hash, finalized_hash);
                        assert_eq!(state.finalized_block_hash, finalized_hash);
                        assert!(payload_attrs.is_none());
                        tx.send(Ok(OnForkChoiceUpdated::syncing()))
                            .expect("finalized FCU response receiver must be alive");
                    }
                    other => panic!("unexpected second engine message: {other:?}"),
                }

                let Some(message) = engine_rx.recv().await else {
                    panic!("engine channel closed before heartbeat FCU");
                };
                match message {
                    BeaconEngineMessage::ForkchoiceUpdated {
                        state,
                        payload_attrs,
                        tx,
                    } => {
                        assert_eq!(state.head_block_hash, finalized_hash);
                        assert_eq!(state.finalized_block_hash, finalized_hash);
                        assert!(payload_attrs.is_none());
                        tx.send(Ok(OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                            PayloadStatusEnum::Valid,
                        ))))
                        .expect("heartbeat FCU response receiver must be alive");
                    }
                    other => panic!("unexpected third engine message: {other:?}"),
                }
            });

            let (ack, waiter) = Exact::handle();
            actor
                .handle_marshal_update(Update::Block(block, ack))
                .await
                .expect("finalized Syncing delivery must process without a fatal error");
            waiter
                .await
                .expect("finalized Syncing delivery must acknowledge marshal");
            assert_eq!(actor.state.finalized_height, Height::new(7));
            assert_eq!(actor.state.forkchoice.finalized_block_hash, finalized_hash);

            actor.send_fcu_heartbeat().await;
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn canonical_genesis_anchor_is_acknowledged_without_execution() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let block = executor_test_block(0, 0x00);
            let genesis = block.block_hash();
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: genesis,
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );

            let (ack, waiter) = Exact::handle();
            actor
                .handle_marshal_update(Update::Block(block, ack))
                .await
                .expect("canonical genesis anchor must be accepted");
            waiter
                .await
                .expect("canonical genesis anchor must acknowledge marshal");

            assert_eq!(actor.state.finalized_height, Height::zero());
            assert_eq!(actor.state.forkchoice.finalized_block_hash, genesis);
            assert!(
                engine_rx.try_recv().is_err(),
                "genesis is already canonical and must not be sent through new_payload"
            );
        });
    }

    #[test]
    fn recovered_canonical_block_is_acknowledged_without_reexecution() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let block = executor_test_block(28, 0x28);
            let recovered_hash = block.block_hash();
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            // The durable projection has already consumed the recovered EL head.
            // Re-executing the same marshal delivery would ask it to regress to
            // parent 27 and fail with ProjectionAhead.
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 28,
                    block_hash: recovered_hash,
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                28,
                recovered_hash,
                projection_readiness,
                None,
            );

            let (ack, waiter) = Exact::handle();
            actor
                .handle_marshal_update(Update::Block(block, ack))
                .await
                .expect("exact recovered canonical block must be idempotently accepted");
            waiter
                .await
                .expect("exact recovered canonical block must acknowledge marshal");
            assert!(
                engine_rx.try_recv().is_err(),
                "an already canonical block must not be sent through new_payload"
            );
            assert_eq!(actor.state.finalized_height, Height::new(28));
            assert_eq!(actor.state.forkchoice.finalized_block_hash, recovered_hash);
        });
    }

    #[test]
    fn recovered_height_with_conflicting_hash_still_fails_closed() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let canonical = executor_test_block(28, 0x28);
            let conflicting = executor_test_block(28, 0x29);
            assert_ne!(canonical.block_hash(), conflicting.block_hash());
            let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 28,
                    block_hash: canonical.block_hash(),
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                28,
                canonical.block_hash(),
                projection_readiness,
                None,
            );

            let (ack, waiter) = Exact::handle();
            let result = actor
                .handle_marshal_update(Update::Block(conflicting, ack))
                .await;
            assert!(result.is_err(), "same-height conflicting block must fail");
            assert!(
                waiter.await.is_err(),
                "same-height conflicting block must not acknowledge marshal"
            );
            assert_eq!(actor.state.finalized_height, Height::new(28));
            assert_eq!(
                actor.state.forkchoice.finalized_block_hash,
                canonical.block_hash()
            );
        });
    }

    #[test]
    fn conflicting_genesis_anchor_fails_without_acknowledging_marshal() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let canonical_genesis = B256::repeat_byte(0x01);
            let conflicting = executor_test_block(0, 0xff);
            assert_ne!(conflicting.block_hash(), canonical_genesis);
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) = ready_projection(
                canonical_genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: canonical_genesis,
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                canonical_genesis,
                0,
                canonical_genesis,
                projection_readiness,
                None,
            );

            let (ack, waiter) = Exact::handle();
            let result = actor
                .handle_marshal_update(Update::Block(conflicting, ack))
                .await;

            assert!(result.is_err(), "a conflicting genesis anchor must fail");
            assert!(
                waiter.await.is_err(),
                "a conflicting genesis anchor must not acknowledge marshal"
            );
            assert_eq!(actor.state.finalized_height, Height::zero());
            assert_eq!(
                actor.state.forkchoice.finalized_block_hash,
                canonical_genesis
            );
            assert!(
                engine_rx.try_recv().is_err(),
                "a conflicting genesis anchor must fail before execution"
            );
        });
    }

    #[test]
    fn marshal_ack_waits_for_compressed_storage_commit_barrier() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            use futures::FutureExt as _;

            let genesis = B256::repeat_byte(0x01);
            let block = executor_test_block(7, 0x78);
            let expected = FinalizedCeBlock {
                height: block.number(),
                block_hash: block.block_hash(),
                parent_block_hash: block.parent_hash(),
            };
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection_for_block(genesis, &block);
            let (called_tx, called_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let committer = Arc::new(GatedCeCommitter {
                called: Mutex::new(Some(called_tx)),
                release: Mutex::new(Some(release_rx)),
            });
            let (actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );
            let mut actor = actor.with_finalized_ce_committer(committer);

            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                match engine_rx.recv().await.expect("new payload message") {
                    BeaconEngineMessage::NewPayload { tx, .. } => tx
                        .send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Valid)))
                        .expect("new payload receiver"),
                    other => panic!("unexpected first engine message: {other:?}"),
                }
                match engine_rx.recv().await.expect("finalized FCU message") {
                    BeaconEngineMessage::ForkchoiceUpdated { tx, .. } => tx
                        .send(Ok(OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                            PayloadStatusEnum::Valid,
                        ))))
                        .expect("FCU receiver"),
                    other => panic!("unexpected second engine message: {other:?}"),
                }
            });

            let (ack, waiter) = Exact::handle();
            let mut waiter = Box::pin(waiter);
            let actor_task = context.child("actor_task").spawn(move |_ctx| async move {
                actor.handle_marshal_update(Update::Block(block, ack)).await
            });

            assert_eq!(called_rx.await.expect("commit barrier call"), expected);
            assert!(
                waiter.as_mut().now_or_never().is_none(),
                "Marshal must remain unacknowledged while CE persistence is blocked"
            );
            release_tx.send(()).expect("release commit barrier");
            actor_task
                .await
                .expect("actor task must complete")
                .expect("finalized delivery must succeed after CE commit");
            waiter
                .await
                .expect("Marshal must be acknowledged after CE commit");
            engine_task.await.expect("engine task must complete");
        });
    }

    // bp-2 regression: a *finalized* block the execution layer rejects must fail
    // fast - `handle_marshal_update` returns a structured `Err` (the supervisor
    // shuts the node down) and the marshal `Exact` ack is left UNACKNOWLEDGED
    // (cancels), never silently dropped after a `warn!`. Deleting the fail-fast
    // and going back to acking/ignoring makes this test fail.
    #[test]
    fn rejected_finalized_block_fails_fast_without_acknowledging_marshal() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let block = executor_test_block(7, 0x77);
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) =
                ready_projection_for_block(genesis, &block);
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context.child("test"),
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );

            // Execution layer rejects the finalized block.
            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                let Some(message) = engine_rx.recv().await else {
                    panic!("engine channel closed before new_payload");
                };
                match message {
                    BeaconEngineMessage::NewPayload { tx, .. } => tx
                        .send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Invalid {
                            validation_error: "test: rejected finalized block".to_string(),
                        })))
                        .expect("new_payload response receiver must be alive"),
                    other => panic!("unexpected engine message: {other:?}"),
                }
            });

            let (ack, waiter) = Exact::handle();
            let result = actor.handle_marshal_update(Update::Block(block, ack)).await;

            // Fail-fast: a fatal error propagates (node will shut down deterministically).
            assert!(
                result.is_err(),
                "an unprocessable finalized block must return a fatal error, \
                 not silently continue"
            );
            // The block was not applied, so the marshal ack must NOT be acknowledged:
            // it cancels. Acking here would lie to marshal progress tracking.
            assert!(
                waiter.await.is_err(),
                "rejected finalized block must leave the marshal ack canceled, \
                 not acknowledged"
            );
            // Finalized state did not advance.
            assert_eq!(actor.state.finalized_height, Height::zero());
            engine_task.await.expect("engine task must complete");
        });
    }

    // TC-1 regression: a fatal Err from handle_marshal_update must PROPAGATE out
    // of run_live_loop (via `?`) so run() ends and the supervisor select-arm
    // treats the executor exit as fatal. Without propagation a rejected finalized
    // block would be swallowed and the loop would keep running on diverged state.
    #[test]
    fn run_live_loop_propagates_fatal_executor_error() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let block = executor_test_block(7, 0x77);
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (mailbox_tx, mailbox_rx) = futures::channel::mpsc::unbounded();
            let (_projection_publisher, projection_readiness) =
                ready_projection_for_block(genesis, &block);

            let mut actor = super::ExecutorActor {
                context: context.child("test"),
                engine,
                state: LastCanonicalized::new(genesis),
                mailbox_rx,
                execution_finalized_height_tx: None,
                projection_readiness,
                ocomp_readiness: None,
                finalized_ce_committer: None,
                ancestry_readiness: None,
                // Heartbeat far in the future so the biased mailbox arm wins.
                fcu_heartbeat_interval: std::time::Duration::from_secs(3600),
                next_fcu_heartbeat_deadline: context.current()
                    + std::time::Duration::from_secs(3600),
                pending_finalized_subscriptions: std::collections::BTreeMap::new(),
            };

            // Engine rejects the finalized block -> handle_finalize_inner Err.
            let engine_task = context.child("engine_task").spawn(move |_ctx| async move {
                match engine_rx.recv().await {
                    Some(BeaconEngineMessage::NewPayload { tx, .. }) => {
                        tx.send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Invalid {
                            validation_error: "test: rejected finalized block".to_string(),
                        })))
                        .expect("new_payload response receiver must be alive");
                    }
                    other => panic!("unexpected/absent engine message: {other:?}"),
                }
            });

            let (ack, _waiter) = Exact::handle();
            mailbox_tx
                .unbounded_send(crate::executor::ingress::Message::MarshalUpdate(Box::new(
                    Update::Block(block, ack),
                )))
                .expect("mailbox send must succeed");

            let result = actor.run_live_loop().await;
            assert!(
                result.is_err(),
                "run_live_loop must propagate the executor fail-fast Err so the supervisor \
                 shuts the node down; got {result:?}"
            );
            engine_task.await.expect("engine task must complete");
        });
    }

    #[test]
    fn mailbox_updates_are_processed_before_ready_heartbeat() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let first = B256::repeat_byte(0x11);
            let second = B256::repeat_byte(0x22);
            let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (mailbox_tx, mailbox_rx) = futures::channel::mpsc::unbounded();
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: genesis,
                },
            );

            let mut actor = super::ExecutorActor {
                context: context.child("test"),
                engine,
                state: LastCanonicalized::new(genesis),
                mailbox_rx,
                execution_finalized_height_tx: None,
                projection_readiness,
                ocomp_readiness: None,
                finalized_ce_committer: None,
                ancestry_readiness: None,
                fcu_heartbeat_interval: std::time::Duration::ZERO,
                next_fcu_heartbeat_deadline: context.current(),
                pending_finalized_subscriptions: std::collections::BTreeMap::new(),
            };

            for (height, digest) in [
                (Height::new(1), Digest(first)),
                (Height::new(2), Digest(second)),
            ] {
                let (response, _rx) = commonware_utils::channel::oneshot::channel();
                mailbox_tx
                    .unbounded_send(crate::executor::ingress::Message::CanonicalizeHead(
                        crate::executor::ingress::CanonicalizeHead {
                            height,
                            digest,
                            response,
                        },
                    ))
                    .expect("test mailbox send must succeed");
            }

            let actor_task = context.child("actor_task").spawn(move |_ctx| async move {
                actor
                    .run_live_loop()
                    .await
                    .expect("live loop must exit cleanly on mailbox close");
            });

            let mut heads = Vec::new();
            for _ in 0..3 {
                let Some(message) = engine_rx.recv().await else {
                    panic!("engine channel closed before expected FCUs");
                };
                match message {
                    BeaconEngineMessage::ForkchoiceUpdated {
                        state,
                        payload_attrs,
                        tx,
                    } => {
                        assert!(payload_attrs.is_none());
                        heads.push(state.head_block_hash);
                        tx.send(Ok(OnForkChoiceUpdated::valid(PayloadStatus::from_status(
                            PayloadStatusEnum::Valid,
                        ))))
                        .expect("test engine response receiver must be alive");
                    }
                    other => panic!("unexpected engine message: {other:?}"),
                }
            }

            assert_eq!(heads, vec![first, second, second]);
            drop(mailbox_tx);
            actor_task.await.expect("actor task must complete");
        });
    }

    #[test]
    fn finalized_subscriber_completes_immediately_when_height_already_finalized() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let finalized = B256::repeat_byte(0x07);
            let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: genesis,
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context,
                engine,
                genesis,
                7,
                finalized,
                projection_readiness,
                None,
            );
            let (response, rx) = commonware_utils::channel::oneshot::channel();

            actor.handle_subscribe_finalized(Height::new(7), response);

            rx.await
                .expect("already-finalized subscription must complete");
        });
    }

    #[test]
    fn ancestry_readiness_advances_from_executor_finalized_notifications() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let readiness = AncestryReadiness::new(0, 3);
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: genesis,
                },
            );
            let (actor, _mailbox) = super::ExecutorActor::new(
                context,
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );
            let actor = actor.with_ancestry_readiness(readiness.clone());

            assert!(!readiness.is_ready());
            actor.notify_execution_finalized(Height::new(2));
            assert!(!readiness.is_ready());
            actor.notify_execution_finalized(Height::new(3));
            assert!(readiness.is_ready());
        });
    }

    #[test]
    fn finalized_subscriber_completes_when_later_height_is_notified() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let genesis = B256::repeat_byte(0x01);
            let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
            let engine = ConsensusEngineHandle::new(engine_tx);
            let (_projection_publisher, projection_readiness) = ready_projection(
                genesis,
                ProjectionCheckpoint {
                    block_number: 0,
                    block_hash: genesis,
                },
            );
            let (mut actor, _mailbox) = super::ExecutorActor::new(
                context,
                engine,
                genesis,
                0,
                genesis,
                projection_readiness,
                None,
            );
            let (response, rx) = commonware_utils::channel::oneshot::channel();

            actor.handle_subscribe_finalized(Height::new(3), response);
            assert_eq!(actor.pending_finalized_subscriptions.len(), 1);
            actor.notify_finalized_subscribers(Height::new(3));

            rx.await
                .expect("pending finalized subscription must complete");
            assert!(actor.pending_finalized_subscriptions.is_empty());
        });
    }

    // -----------------------------------------------------------------------
    // TC-2 (backfill fail-fast) helpers and regression test
    // -----------------------------------------------------------------------

    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    // Unique partition prefix per backfill-test marshal so the immutable
    // archives never collide between concurrent test runs.
    static BACKFILL_MARSHAL_ID: AtomicU64 = AtomicU64::new(0);

    /// Block-availability buffer that never has any block: every lookup misses
    /// and every subscription stays pending. Mirrors `EmptyMarshalBuffer` in
    /// `application/handler_tests.rs`. Combined with `NoopResolver` (which never
    /// fetches), an empty archive makes `marshal.get_block(h)` resolve `None`.
    #[derive(Clone, Default)]
    struct EmptyBackfillBuffer;

    impl commonware_consensus::marshal::core::Buffer<crate::marshal_types::Variant>
        for EmptyBackfillBuffer
    {
        type PublicKey = commonware_cryptography::bls12381::PublicKey;

        async fn find_by_digest(&self, _digest: Digest) -> Option<ConsensusBlock> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Digest) -> Option<ConsensusBlock> {
            None
        }

        fn subscribe_by_digest(
            &self,
            _digest: Digest,
        ) -> Option<commonware_utils::channel::oneshot::Receiver<ConsensusBlock>> {
            let (_tx, rx) = commonware_utils::channel::oneshot::channel();
            Some(rx)
        }

        fn subscribe_by_commitment(
            &self,
            _commitment: Digest,
        ) -> Option<commonware_utils::channel::oneshot::Receiver<ConsensusBlock>> {
            let (_tx, rx) = commonware_utils::channel::oneshot::channel();
            Some(rx)
        }

        fn finalized(&self, _commitment: Digest) {}

        fn send(
            &self,
            _round: commonware_consensus::types::Round,
            _block: ConsensusBlock,
            _recipients: commonware_p2p::Recipients<Self::PublicKey>,
        ) {
        }
    }

    /// Reporter that acknowledges delivered blocks. Mirrors the
    /// `AckingMarshalReporter` used by the other marshal harnesses.
    #[derive(Clone, Default)]
    struct AckingBackfillReporter;

    impl commonware_consensus::Reporter for AckingBackfillReporter {
        type Activity = commonware_consensus::marshal::Update<
            ConsensusBlock,
            commonware_utils::acknowledgement::Exact,
        >;

        fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
            if let commonware_consensus::marshal::Update::Block(_, ack) = activity {
                ack.acknowledge();
            }
            commonware_actor::Feedback::Ok
        }
    }

    /// Resolver that never fetches anything. Mirrors the `NoopResolver` used by
    /// the other marshal harnesses; required because `get_block` is local-only
    /// (it never triggers a network fetch) and the resolver only exists so the
    /// marshal actor can start.
    #[derive(Clone, Default)]
    struct NoopBackfillResolver;

    impl commonware_resolver::Resolver for NoopBackfillResolver {
        type Key = commonware_consensus::marshal::resolver::handler::Key<Digest>;
        type Subscriber = commonware_consensus::marshal::resolver::handler::Annotation;

        fn fetch<F>(&mut self, _key: F) -> commonware_actor::Feedback
        where
            F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            commonware_actor::Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _keys: Vec<F>) -> commonware_actor::Feedback
        where
            F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            commonware_actor::Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }
    }

    impl commonware_resolver::TargetedResolver for NoopBackfillResolver {
        type PublicKey = commonware_cryptography::bls12381::PublicKey;

        fn fetch_targeted(
            &mut self,
            _fetch: impl Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: commonware_utils::vec::NonEmptyVec<Self::PublicKey>,
        ) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            _keys: Vec<(F, commonware_utils::vec::NonEmptyVec<Self::PublicKey>)>,
        ) -> commonware_actor::Feedback
        where
            F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            commonware_actor::Feedback::Ok
        }
    }

    /// Build genesis block (height 0) for the marshal `Start::Genesis` anchor.
    fn backfill_genesis_block() -> ConsensusBlock {
        executor_test_block(0, 0x00)
    }

    /// Start an EMPTY marshal actor (no blocks in the archive, no-op resolver,
    /// always-missing buffer) on the tokio runtime and return its mailbox.
    ///
    /// `get_block(h)` on this mailbox resolves `None` for every height, because
    /// the immutable archive is empty and `get_block` is a local-only lookup
    /// (it never asks the network). The actor handle and the resolver handler
    /// keepalive are returned so the caller keeps them alive for the test.
    async fn start_empty_marshal(
        context: commonware_runtime::deterministic::Context,
    ) -> (
        crate::marshal_types::MarshalMailbox,
        commonware_consensus::marshal::resolver::handler::Handler<Digest>,
        commonware_runtime::Handle<()>,
    ) {
        use commonware_cryptography::{bls12381::primitives::variant::MinSig, certificate::Scheme};
        use commonware_runtime::buffer::paged::CacheRef;
        use commonware_storage::archive::immutable;
        use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

        use crate::hybrid::{HybridScheme, HybridSchemeProvider};

        let page_cache = CacheRef::from_pooler(
            &context,
            NonZeroU16::new(1024).expect("non-zero page size"),
            NonZeroUsize::new(10).expect("non-zero cache size"),
        );
        let test_id = BACKFILL_MARSHAL_ID.fetch_add(1, AtomicOrdering::SeqCst);
        let partition_prefix = format!("executor-backfill-{test_id}");
        let items_per_section = NonZeroU64::new(10).expect("non-zero items per section");
        let replay_buffer = NonZeroUsize::new(1024).expect("non-zero replay buffer");
        let write_buffer = NonZeroUsize::new(1024).expect("non-zero write buffer");

        let finalizations_archive = immutable::Archive::init(
            context.child("marshal_finalizations"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-metadata"),
                freezer_table_partition: format!("{partition_prefix}-finalizations-freezer-table"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalizations-freezer-key"),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!("{partition_prefix}-finalizations-freezer-value"),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-ordinal"),
                items_per_section,
                codec_config: HybridScheme::<MinSig>::certificate_codec_config_unbounded(),
                replay_buffer,
                freezer_key_write_buffer: write_buffer,
                freezer_value_write_buffer: write_buffer,
                ordinal_write_buffer: write_buffer,
            },
        )
        .await
        .expect("finalizations archive should initialize");

        let blocks_archive = immutable::Archive::init(
            context.child("marshal_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-blocks-metadata"),
                freezer_table_partition: format!("{partition_prefix}-blocks-freezer-table"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-blocks-freezer-key"),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!("{partition_prefix}-blocks-freezer-value"),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-blocks-ordinal"),
                items_per_section,
                codec_config: (),
                replay_buffer,
                freezer_key_write_buffer: write_buffer,
                freezer_value_write_buffer: write_buffer,
                ordinal_write_buffer: write_buffer,
            },
        )
        .await
        .expect("blocks archive should initialize");

        let (actor, mailbox, _) = commonware_consensus::marshal::core::Actor::init(
            context.child("marshal"),
            finalizations_archive,
            blocks_archive,
            commonware_consensus::marshal::Config {
                provider: HybridSchemeProvider::<MinSig>::new(),
                epocher: commonware_consensus::types::FixedEpocher::new(
                    NonZeroU64::new(10_000).expect("non-zero epoch"),
                ),
                start: commonware_consensus::marshal::Start::Genesis(backfill_genesis_block()),
                partition_prefix,
                mailbox_size: NonZeroUsize::new(32).expect("non-zero mailbox size"),
                view_retention_timeout: commonware_consensus::types::ViewDelta::new(10_000),
                prunable_items_per_section: items_per_section,
                page_cache,
                replay_buffer,
                key_write_buffer: write_buffer,
                value_write_buffer: write_buffer,
                block_codec_config: (),
                max_repair: NonZeroUsize::new(10).expect("non-zero max repair"),
                max_pending_acks: NonZeroUsize::new(1).expect("non-zero pending acks"),
                strategy: commonware_parallel::Sequential,
            },
        )
        .await;

        // The resolver receiver/handler pair: the marshal actor consumes the
        // receiver; the `Handler` is the keepalive (dropping it shuts the actor
        // down). The actor never fetches because `get_block` is local-only.
        let (resolver_rx, resolver_handler) =
            commonware_consensus::marshal::resolver::handler::init::<Digest>(
                context.child("resolver_handler"),
                NonZeroUsize::new(16).expect("non-zero resolver mailbox size"),
            );
        let handle = actor.start(
            AckingBackfillReporter,
            EmptyBackfillBuffer,
            (resolver_rx, NoopBackfillResolver),
        );
        (mailbox, resolver_handler, handle)
    }

    // TC-2 regression (finding TC-2 / F1 fix): the executor STARTUP BACKFILL must
    // FAIL FAST when marshal cannot serve a finalized block at or below its own
    // reported finalized height. `run()` walks `(execution_height,
    // last_consensus_finalized]` calling `marshal.get_block(h)`; an empty marshal
    // returns `None` for height 1, which means marshal's archive is inconsistent
    // (claims finalized to N but cannot serve M <= N). The F1 fix makes that
    // branch `error! + return Err(...)`. If it were reverted to the old
    // `warn! + skip`, the backfill loop would fall through every height and then
    // enter the infinite `run_live_loop`, so `run().await` would NOT return an
    // `Err` (this test would hang on the wrapping timeout and then fail the
    // "must return Err" assertion) - i.e. this test genuinely guards the fix.
    #[test]
    fn run_backfill_fails_fast_when_marshal_missing_finalized_block() {
        // The `Runner::timed` wedge guard replaces the previous outer
        // 20s wall-clock timeout safety net: `run()` must return promptly via
        // the backfill fail-fast branch. A hang here means the missing-block branch
        // fell through to `run_live_loop` (i.e. the F1 fix was reverted to
        // warn! + skip); the wedge guard aborts the test in that case.
        commonware_runtime::deterministic::Runner::timed(std::time::Duration::from_secs(60)).start(
            |context| async move {
                let genesis = B256::repeat_byte(0x01);
                // Dummy engine: branch (A) returns before any engine call, so the
                // receiver is simply never read.
                let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
                let engine = ConsensusEngineHandle::new(engine_tx);

                let (_projection_publisher, projection_readiness) = ready_projection(
                    genesis,
                    ProjectionCheckpoint {
                        block_number: 0,
                        block_hash: genesis,
                    },
                );

                // Executor at finalized height 0 (fresh bootstrap from genesis).
                let (actor, _mailbox) = super::ExecutorActor::new(
                    context.child("exec"),
                    engine,
                    genesis,
                    0,
                    genesis,
                    projection_readiness,
                    None,
                );

                // Empty marshal: get_block(h) -> None for every height.
                let (marshal_mailbox, _resolver_keepalive, _marshal_handle) =
                    start_empty_marshal(context.child("marshal_node")).await;

                // Consensus reports finalized height 3, execution is at 0, so the
                // backfill range is heights 1..=3. Height 1 misses -> fail fast.
                let run_result = actor.run(marshal_mailbox, Height::new(3)).await;

                assert!(
                    run_result.is_err(),
                    "an empty marshal that cannot serve a finalized block at/below its \
                 reported finalized height must make run() fail fast, not silently \
                 skip and continue; got {run_result:?}"
                );
                let message = format!("{:#}", run_result.expect_err("checked is_err above"));
                assert!(
                    message.contains("missing finalized block"),
                    "backfill fail-fast error must identify the missing finalized block; \
                 got: {message}"
                );
            },
        );
    }
}
