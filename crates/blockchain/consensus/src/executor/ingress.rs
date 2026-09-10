//! Executor actor mailbox and message types.

use crate::digest::Digest;
use alloy_rpc_types_engine::PayloadId;
use commonware_consensus::types::Height;
use commonware_utils::channel::oneshot;
use futures::channel::mpsc;
use outbe_primitives::OutbePayloadAttributes;

/// Handle for sending messages to the executor actor.
///
/// sus-1: this mailbox is intentionally **unbounded**. The executor is the sole
/// recovery-critical sink for marshal-delivered finalized blocks, and its inflow
/// is naturally bounded by the consensus block rate (one finalized block per
/// finalized view, plus low-rate canonicalize/heartbeat traffic) - it is not a
/// fan-in hot path. Because it is unbounded, `Reporter::report` here never
/// returns `Feedback::Backoff` (an unbounded `unbounded_send` only fails when the
/// receiver is gone, surfaced as `Feedback::Closed`), so the upstream
/// `let _ = report(...)` sites cannot be silently throttled. A bounded queue with
/// an overflow policy would let marshal/Simplex throttle under sustained
/// pressure; that is deferred - if executor mailbox depth ever becomes a concern,
/// add a depth metric here before switching to a bounded queue. The same holds
/// for the peer_manager and finalization endpoints.
#[derive(Clone)]
pub struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    /// Create from a sender.
    pub fn from_sender(tx: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner: tx }
    }

    /// Request that the given block becomes the canonical chain head.
    ///
    /// Returns `Ok(())` after a successful FCU, or error if FCU failed/invalid.
    pub async fn canonicalize_head(&self, height: Height, digest: Digest) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::CanonicalizeHead(CanonicalizeHead {
                height,
                digest,
                response: tx,
            }))
            .map_err(|_| eyre::eyre!("executor mailbox closed"))?;
        rx.await
            .map_err(|_| eyre::eyre!("executor dropped response"))?
    }

    /// Canonicalize head and request a new payload to be built.
    ///
    /// Sends FCU with payload attributes so the engine starts building a
    /// payload on the correct canonical state (with pool access).
    pub async fn canonicalize_and_build(
        &self,
        height: Height,
        digest: Digest,
        attributes: OutbePayloadAttributes,
    ) -> eyre::Result<PayloadId> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::CanonicalizeAndBuild(CanonicalizeAndBuild {
                height,
                digest,
                attributes,
                response: tx,
            }))
            .map_err(|_| eyre::eyre!("executor mailbox closed"))?;
        rx.await
            .map_err(|_| eyre::eyre!("executor dropped response"))?
    }

    /// Return once executor has processed/finalized at least `height`.
    ///
    /// This is a wakeup signal for secondary consumers such as peer-manager.
    /// It is not a substitute for provider-level canonical hash checks.
    pub async fn subscribe_finalized(&self, height: Height) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message::SubscribeFinalized(SubscribeFinalized {
                height,
                response: tx,
            }))
            .map_err(|_| eyre::eyre!("executor mailbox closed"))?;
        rx.await
            .map_err(|_| eyre::eyre!("executor dropped finalized subscription response"))
    }
}

/// Implement Reporter for marshal block delivery.
///
/// Marshal calls `report(Update::Block(block, ack))` to deliver finalized blocks.
/// The executor processes the block and acknowledges back to marshal, which
/// persists the processed height - the recovery truth on restart.
impl commonware_consensus::Reporter for Mailbox {
    type Activity = crate::marshal_types::MarshalUpdate;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        match &activity {
            commonware_consensus::marshal::Update::Block(block, _) => {
                tracing::debug!(
                    activity_kind = "block",
                    height = block.number(),
                    digest = %block.block_hash(),
                    "marshal report received"
                );
            }
            commonware_consensus::marshal::Update::Tip(round, height, digest) => {
                tracing::debug!(
                    activity_kind = "tip",
                    %round,
                    %height,
                    %digest,
                    "marshal report received"
                );
            }
        }
        // `report` is now synchronous: enqueue the update into the executor
        // actor's mailbox and translate the channel state into `Feedback`.
        // We must not bridge to async work here (no spawn) - the executor
        // drains `Message::MarshalUpdate` on its own loop and acks marshal
        // after successful EL processing, preserving determinism.
        match self
            .inner
            .unbounded_send(Message::MarshalUpdate(Box::new(activity)))
        {
            Ok(()) => commonware_actor::Feedback::Ok,
            Err(_) => commonware_actor::Feedback::Closed,
        }
    }
}

/// Messages handled by the executor actor.
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// Request to make a block the canonical head.
    CanonicalizeHead(CanonicalizeHead),
    /// Canonicalize head and build a new payload (FCU with attributes).
    CanonicalizeAndBuild(CanonicalizeAndBuild),
    /// Finalized block delivered by marshal (with acknowledgment token).
    MarshalUpdate(Box<crate::marshal_types::MarshalUpdate>),
    /// Notify once executor finalization reaches the requested height.
    SubscribeFinalized(SubscribeFinalized),
}

/// Canonicalize head request.
pub struct CanonicalizeHead {
    pub height: Height,
    pub digest: Digest,
    pub response: oneshot::Sender<eyre::Result<()>>,
}

/// Canonicalize head and build payload request.
pub struct CanonicalizeAndBuild {
    pub height: Height,
    pub digest: Digest,
    pub attributes: OutbePayloadAttributes,
    pub response: oneshot::Sender<eyre::Result<PayloadId>>,
}

/// Executor finalized-height subscription request.
pub struct SubscribeFinalized {
    pub height: Height,
    pub response: oneshot::Sender<()>,
}
