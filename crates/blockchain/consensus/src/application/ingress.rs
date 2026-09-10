//! Application actor mailbox and message types.
//!
//! Step 21 of the rewards-economy-mailbox migration removed the
//! `Message::Finalized` variant from this mailbox. Finalization
//! notifications now flow voter -> `OutbeReporter` -> `FinalizationActor`
//! through `crate::finalization::ingress::Mailbox` (an unbounded
//! channel), so a slow finalization consumer can no longer back-pressure
//! the application handler.

use crate::digest::Digest;
use commonware_consensus::{simplex::types::Context, types::Epoch};
use commonware_cryptography::bls12381::PublicKey;
use commonware_utils::channel::oneshot;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

/// Simplex context parameterised for our Digest and PublicKey types.
pub type SimplexContext = Context<Digest, PublicKey>;

/// Handle for sending messages to the application actor.
#[derive(Clone)]
pub struct Mailbox {
    inner: mpsc::Sender<Message>,
}

impl Mailbox {
    /// Create a new mailbox from a channel sender.
    pub fn from_sender(tx: mpsc::Sender<Message>) -> Self {
        Self { inner: tx }
    }

    /// Send a genesis request.
    ///
    /// Applies backpressure if the handler's mailbox is full rather than
    /// dropping the message (genesis is required for correct startup).
    pub async fn genesis(&mut self, epoch: Epoch) -> Digest {
        let (tx, rx) = oneshot::channel();
        let msg = Message::Genesis(Genesis {
            epoch,
            response: tx,
        });
        if let Err(e) = self.inner.send(msg).await {
            error!(%e, "failed to send genesis message - handler closed");
            return Digest::ZERO;
        }
        rx.await.unwrap_or(Digest::ZERO)
    }

    /// Send a propose request.
    ///
    /// Awaits channel capacity so proposals are never silently dropped.
    pub async fn propose(&mut self, context: SimplexContext) -> oneshot::Receiver<Digest> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::Propose(Box::new(Propose {
            context,
            response: tx,
        }));
        if let Err(e) = self.inner.send(msg).await {
            error!(%e, "failed to send propose message - handler closed");
        }
        rx
    }

    /// Send a verify request.
    ///
    /// Awaits channel capacity so verify requests are never silently dropped.
    pub async fn verify(
        &mut self,
        context: SimplexContext,
        payload: Digest,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let msg = Message::Verify(Box::new(Verify {
            context,
            payload,
            response: tx,
        }));
        if let Err(e) = self.inner.send(msg).await {
            error!(%e, "failed to send verify message - handler closed");
        }
        rx
    }
}

/// Messages handled by the application actor.
///
/// `Verify` and `Propose` are boxed to keep the enum small for the
/// bounded mailbox; the per-message payloads contain ~250 bytes of
/// consensus context each, which would otherwise blow up enum size.
pub enum Message {
    /// Request genesis digest for an epoch.
    Genesis(Genesis),
    /// Request a new block proposal.
    Propose(Box<Propose>),
    /// Request block verification.
    Verify(Box<Verify>),
}

/// Genesis request - return the genesis digest for the given epoch.
pub struct Genesis {
    pub epoch: Epoch,
    pub response: oneshot::Sender<Digest>,
}

/// Propose request - build a new block on top of the parent.
pub struct Propose {
    pub context: SimplexContext,
    pub response: oneshot::Sender<Digest>,
}

/// Verify request - validate a proposed block against the execution layer.
pub struct Verify {
    pub context: SimplexContext,
    pub payload: Digest,
    pub response: oneshot::Sender<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use commonware_consensus::types::View;
    use commonware_cryptography::{bls12381, Signer as _};
    use commonware_math::algebra::Random;
    use futures::StreamExt;

    /// Helper: create a mailbox with a given buffer size.
    fn make_mailbox(buffer: usize) -> (Mailbox, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Mailbox::from_sender(tx), rx)
    }

    /// Helper: create a dummy SimplexContext.
    fn dummy_context() -> SimplexContext {
        let key = bls12381::PrivateKey::random(rand_core::OsRng);
        SimplexContext {
            round: Default::default(),
            leader: key.public_key(),
            parent: (View::zero(), Digest::ZERO),
        }
    }

    /// genesis() on a closed channel must return Digest::ZERO, not hang or panic.
    #[test]
    fn test_genesis_closed_returns_zero() {
        use commonware_runtime::Runner as _;
        commonware_runtime::deterministic::Runner::default().start(|_context| async move {
            let (mut mailbox, rx) = make_mailbox(1);
            drop(rx);

            let result = mailbox.genesis(Epoch::new(0)).await;
            assert_eq!(result, Digest::ZERO);
        });
    }

    /// verify() must deliver through backpressure, not drop.
    #[test]
    fn test_verify_delivers_all_messages() {
        use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let (mut mailbox, mut rx) = make_mailbox(1);
            let total = 5usize;

            let sender = context
                .child("verify_sender")
                .spawn(move |_ctx| async move {
                    for i in 0..total {
                        let digest = Digest(B256::with_last_byte(i as u8));
                        let _rx = mailbox.verify(dummy_context(), digest).await;
                    }
                });

            let mut count = 0;
            for _ in 0..total {
                let msg = rx.next().await.expect("channel closed prematurely");
                assert!(matches!(msg, Message::Verify(_)));
                count += 1;
            }

            sender.await.unwrap();
            assert_eq!(count, total);
        });
    }

    /// propose() must deliver through backpressure, not drop.
    #[test]
    fn test_propose_delivers_all_messages() {
        use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let (mut mailbox, mut rx) = make_mailbox(1);
            let total = 5usize;

            let sender = context
                .child("propose_sender")
                .spawn(move |_ctx| async move {
                    for _ in 0..total {
                        let _rx = mailbox.propose(dummy_context()).await;
                    }
                });

            let mut count = 0;
            for _ in 0..total {
                let msg = rx.next().await.expect("channel closed prematurely");
                assert!(matches!(msg, Message::Propose(_)));
                count += 1;
            }

            sender.await.unwrap();
            assert_eq!(count, total);
        });
    }
}
