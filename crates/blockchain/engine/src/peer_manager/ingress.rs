use commonware_actor::Feedback;
use commonware_consensus::{marshal::Update, Reporter};
use commonware_p2p::{
    Address, AddressableManager, AddressableTrackedPeers, PeerSetSubscription, Provider,
    TrackedPeers,
};
use commonware_utils::{channel::oneshot, ordered::Map, Acknowledgement as _};
use futures::channel::mpsc;
use tracing::{error, Span};

use outbe_consensus::block::ConsensusBlock;

pub(crate) type PublicKey = commonware_cryptography::bls12381::PublicKey;

#[derive(Clone, Debug)]
pub(crate) struct Mailbox {
    inner: mpsc::UnboundedSender<MessageWithCause>,
}

impl Mailbox {
    /// Wait until the single oracle writer has published the DKG transport set.
    pub(crate) async fn prepare_dkg(&self, peers: Map<PublicKey, Address>) -> eyre::Result<u64> {
        let (response, receiver) = oneshot::channel();
        self.inner
            .unbounded_send(MessageWithCause::in_current_span(Message::PrepareDkg {
                peers,
                response,
            }))
            .map_err(|_| eyre::eyre!("peer_manager mailbox closed"))?;
        receiver
            .await
            .map_err(|_| eyre::eyre!("peer_manager dropped DKG publication"))?
    }

    pub(crate) fn new(inner: mpsc::UnboundedSender<MessageWithCause>) -> Self {
        Self { inner }
    }
}

pub(crate) struct MessageWithCause {
    pub(crate) cause: Span,
    pub(crate) message: Message,
}

impl MessageWithCause {
    fn in_current_span(message: impl Into<Message>) -> Self {
        Self {
            cause: Span::current(),
            message: message.into(),
        }
    }
}

pub(crate) enum Message {
    Track {
        id: u64,
        peers: AddressableTrackedPeers<PublicKey>,
    },
    PrepareDkg {
        peers: Map<PublicKey, Address>,
        response: oneshot::Sender<eyre::Result<u64>>,
    },
    Overwrite {
        peers: Map<PublicKey, Address>,
    },
    PeerSet {
        id: u64,
        response: oneshot::Sender<Option<TrackedPeers<PublicKey>>>,
    },
    Subscribe {
        response: oneshot::Sender<PeerSetSubscription<PublicKey>>,
    },
    Finalized(Box<Update<ConsensusBlock>>),
}

impl From<Update<ConsensusBlock>> for Message {
    fn from(value: Update<ConsensusBlock>) -> Self {
        Self::Finalized(Box::new(value))
    }
}

impl Provider for Mailbox {
    type PublicKey = PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        let (tx, rx) = oneshot::channel();
        if let Err(error) =
            self.inner
                .unbounded_send(MessageWithCause::in_current_span(Message::PeerSet {
                    id,
                    response: tx,
                }))
        {
            error!(%error, "failed to send message to peer_manager");
            return None;
        }
        rx.await.ok().flatten()
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        let (tx, rx) = oneshot::channel();
        let (_, fallback_rx) = commonware_utils::channel::mpsc::unbounded_channel();
        if let Err(error) =
            self.inner
                .unbounded_send(MessageWithCause::in_current_span(Message::Subscribe {
                    response: tx,
                }))
        {
            error!(%error, "failed to send message to peer_manager");
            return fallback_rx;
        }
        rx.await.unwrap_or(fallback_rx)
    }
}

impl AddressableManager for Mailbox {
    /// As of commonware 2026.5.0 `track` is synchronous, accepts any
    /// `R: Into<AddressableTrackedPeers>`, and returns [`Feedback`]. We enqueue
    /// both admission tiers onto the actor's unbounded mailbox (no `.await`, no
    /// spawn) and map channel state to feedback.
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
    {
        let addressable: AddressableTrackedPeers<Self::PublicKey> = peers.into();
        match self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(Message::Track {
                id,
                peers: addressable,
            })) {
            Ok(()) => Feedback::Ok,
            Err(error) => {
                error!(%error, "failed to send message to peer_manager");
                Feedback::Closed
            }
        }
    }

    /// As of commonware 2026.5.0 `overwrite` is synchronous and returns
    /// [`Feedback`]. We enqueue onto the actor's unbounded mailbox and map
    /// channel state to feedback.
    fn overwrite(&mut self, peers: Map<Self::PublicKey, Address>) -> Feedback {
        match self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(Message::Overwrite {
                peers,
            })) {
            Ok(()) => Feedback::Ok,
            Err(error) => {
                error!(%error, "failed to send message to peer_manager");
                Feedback::Closed
            }
        }
    }
}

impl Reporter for Mailbox {
    type Activity = Update<ConsensusBlock>;

    /// As of commonware 2026.5.0 `report` is synchronous and returns
    /// [`Feedback`]. We enqueue the marshal update onto the actor's unbounded
    /// mailbox (no `.await`, no spawn). On a closed mailbox we acknowledge the
    /// block update so marshal does not stall, then report [`Feedback::Closed`].
    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self
            .inner
            .unbounded_send(MessageWithCause::in_current_span(activity))
        {
            Ok(()) => Feedback::Ok,
            Err(error) => {
                let error_message = error.to_string();
                if let Message::Finalized(update) = error.into_inner().message {
                    if let Update::Block(_, ack) = *update {
                        ack.acknowledge();
                    }
                }
                error!(error = %error_message, "failed to send message to peer_manager");
                Feedback::Closed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use commonware_runtime::{Clock as _, Runner as _};
    use commonware_utils::acknowledgement::{Acknowledgement, Exact};
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::{primitives::SealedBlock, Block};
    use std::time::Duration;

    #[test]
    fn track_preserves_secondary_admission_through_mailbox() {
        use commonware_cryptography::{bls12381::PrivateKey, Signer as _};
        use futures::StreamExt as _;

        futures::executor::block_on(async {
            let (tx, mut rx) = mpsc::unbounded();
            let mut mailbox = Mailbox::new(tx);
            let key = PrivateKey::from_seed(5).public_key();
            let secondary = Map::from_iter_dedup([(
                key.clone(),
                Address::Symmetric("127.0.0.5:30400".parse().unwrap()),
            )]);
            assert_eq!(
                mailbox.track(1, AddressableTrackedPeers::new(Map::default(), secondary)),
                Feedback::Ok
            );
            let Message::Track { peers, .. } = rx.next().await.unwrap().message else {
                panic!("expected tracked admission");
            };
            assert!(
                peers.secondary.keys().position(&key).is_some(),
                "mailbox lost secondary peer"
            );
            assert!(
                peers.primary.is_empty(),
                "secondary peer acquired primary status"
            );
        });
    }

    fn make_test_block(seed: u8) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.extra_data = Bytes::from(vec![seed]);
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    #[test]
    fn report_acknowledges_block_when_mailbox_is_closed() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let (tx, rx) = mpsc::unbounded();
            drop(rx);
            let mut mailbox = Mailbox::new(tx);
            let (ack, waiter) = Exact::handle();

            let _ = mailbox.report(Update::Block(make_test_block(0xA1), ack));

            // The closed mailbox acknowledges the cloned block update inline, so
            // the waiter resolves immediately. Race it against a runtime `Clock`
            // sleep (mirrors `dkg_actor::sim_tests`) instead of a wall-clock async
            // timeout; the safety bound never fires.
            let mut waiter = std::pin::pin!(waiter);
            let mut timeout = std::pin::pin!(context.sleep(Duration::from_secs(1)));
            let result = commonware_macros::select! {
                result = &mut waiter => result,
                _ = &mut timeout => panic!("ack waiter must complete"),
            };
            result.expect("closed peer_manager mailbox must acknowledge cloned block update");
        });
    }
}
