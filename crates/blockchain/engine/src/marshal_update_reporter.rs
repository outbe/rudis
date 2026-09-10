use commonware_consensus::{types::Height, Reporter};
use outbe_consensus::digest::Digest;
use outbe_consensus::executor::Mailbox;
use outbe_consensus::marshal_types::MarshalUpdate;
use tokio::sync::watch;

use crate::peer_manager::Mailbox as PeerManagerMailbox;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsensusTip {
    pub(crate) round: commonware_consensus::types::Round,
    pub(crate) height: Height,
    pub(crate) digest: Digest,
}

#[derive(Clone)]
pub(crate) struct MarshalUpdateReporter {
    executor: Mailbox,
    tip_consumers: Vec<watch::Sender<Option<ConsensusTip>>>,
    block_consumers: Vec<PeerManagerMailbox>,
}

impl MarshalUpdateReporter {
    pub(crate) fn new(executor: Mailbox) -> Self {
        Self {
            executor,
            tip_consumers: Vec::new(),
            block_consumers: Vec::new(),
        }
    }

    pub(crate) fn add_tip_consumer(
        mut self,
        consumer: watch::Sender<Option<ConsensusTip>>,
    ) -> Self {
        self.tip_consumers.push(consumer);
        self
    }

    pub(crate) fn add_block_consumer(mut self, consumer: PeerManagerMailbox) -> Self {
        self.block_consumers.push(consumer);
        self
    }
}

impl Reporter for MarshalUpdateReporter {
    type Activity = MarshalUpdate;

    /// As of commonware 2026.5.0 `Reporter::report` is synchronous and returns
    /// [`commonware_actor::Feedback`]. This reporter fans the marshal update out
    /// to its tip/block consumers and the executor, all of which now enqueue
    /// onto their own unbounded mailboxes synchronously (no `.await`). We report
    /// [`Feedback::Closed`] only when the executor mailbox - the
    /// recovery-critical sink - is gone; downstream consumer mailboxes are
    /// best-effort wakeups and their closure must not stall the voter task.
    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        if let commonware_consensus::marshal::Update::Tip(round, height, digest) = &activity {
            let tip = Some(ConsensusTip {
                round: *round,
                height: *height,
                digest: *digest,
            });
            for consumer in &self.tip_consumers {
                let _ = consumer.send(tip);
            }
        }

        if matches!(&activity, commonware_consensus::marshal::Update::Block(..)) {
            for consumer in &mut self.block_consumers {
                let _ = consumer.report(activity.clone());
            }
        }

        self.executor.report(activity)
    }
}

#[cfg(test)]
mod tests {
    //! Regression coverage for SEC-2: the dual-ack fan-out in
    //! [`MarshalUpdateReporter::report`] for `Update::Block`.
    //!
    //! `report` clones the marshal `Update` for every block consumer (each clone
    //! of [`Exact`] increments the acknowledgement's `remaining` count) and moves
    //! the original into the executor. The marshal's `Exact` waiter therefore
    //! resolves to `Ok` only when *every* copy - executor plus each block
    //! consumer - is acknowledged. If any copy is dropped unacknowledged,
    //! `Exact::drop` cancels the aggregate and the waiter resolves to
    //! `Err(Canceled)`, which upstream marshal treats as fatal. These tests pin
    //! both halves of that contract.

    use super::*;
    use alloy_primitives::Bytes;
    use commonware_consensus::marshal::Update;
    use commonware_runtime::{Clock as _, Runner as _};
    use commonware_utils::acknowledgement::{Acknowledgement, Exact};
    use futures::channel::mpsc;
    use futures::StreamExt;
    use outbe_consensus::block::ConsensusBlock;
    use outbe_consensus::executor::ingress::Message as ExecutorMessage;
    use outbe_consensus::executor::Mailbox as ExecutorMailbox;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::{primitives::SealedBlock, Block};
    use std::time::Duration;

    use crate::peer_manager::ingress::{
        Message as PeerManagerMessage, MessageWithCause as PeerManagerMessageWithCause,
    };

    fn make_test_block(seed: u8) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.number = 1;
        block.header.extra_data = Bytes::from(vec![seed]);
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    /// Drain one `MarshalUpdate` from the executor mailbox channel and return its
    /// [`Exact`] acknowledgement.
    async fn take_executor_ack(rx: &mut mpsc::UnboundedReceiver<ExecutorMessage>) -> Exact {
        match rx.next().await.expect("executor must receive one message") {
            ExecutorMessage::MarshalUpdate(boxed) => match *boxed {
                Update::Block(_, ack) => ack,
                Update::Tip(..) => panic!("expected Update::Block on executor mailbox"),
            },
            _ => panic!("expected Message::MarshalUpdate on executor mailbox"),
        }
    }

    /// Drain one `MarshalUpdate` from the peer-manager mailbox channel and return
    /// its [`Exact`] acknowledgement.
    async fn take_block_consumer_ack(
        rx: &mut mpsc::UnboundedReceiver<PeerManagerMessageWithCause>,
    ) -> Exact {
        let with_cause = rx
            .next()
            .await
            .expect("block consumer must receive one message");
        match with_cause.message {
            PeerManagerMessage::Finalized(boxed) => match *boxed {
                Update::Block(_, ack) => ack,
                Update::Tip(..) => panic!("expected Update::Block on peer_manager mailbox"),
            },
            _ => panic!("expected Message::Finalized on peer_manager mailbox"),
        }
    }

    /// Build a reporter wired to a held executor channel and one held
    /// block-consumer (peer_manager) channel.
    fn build_reporter() -> (
        MarshalUpdateReporter,
        mpsc::UnboundedReceiver<ExecutorMessage>,
        mpsc::UnboundedReceiver<PeerManagerMessageWithCause>,
    ) {
        let (exec_tx, exec_rx) = mpsc::unbounded::<ExecutorMessage>();
        let (pm_tx, pm_rx) = mpsc::unbounded::<PeerManagerMessageWithCause>();

        let reporter = MarshalUpdateReporter::new(ExecutorMailbox::from_sender(exec_tx))
            .add_block_consumer(PeerManagerMailbox::new(pm_tx));

        (reporter, exec_rx, pm_rx)
    }

    /// SEC-2: when every fan-out copy (executor + each block consumer) is
    /// acknowledged, the marshal `Exact` waiter resolves to `Ok(())`.
    ///
    /// Guard sanity: if either copy were left unacknowledged here, its
    /// `Exact::drop` would `cancel()` the shared state and the waiter would
    /// instead resolve to `Err(Canceled)` - so this passing proves the
    /// per-clone `remaining` increment is satisfied only when all copies ack.
    #[test]
    fn all_acks_resolve_waiter_ok() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let (mut reporter, mut exec_rx, mut pm_rx) = build_reporter();
            let (ack, waiter) = Exact::handle();

            let feedback = reporter.report(Update::Block(make_test_block(0x01), ack));
            assert!(
                matches!(feedback, commonware_actor::Feedback::Ok),
                "report must succeed when both mailboxes are open"
            );

            // Both copies are now parked in their respective channels. Acknowledge
            // each one.
            let exec_ack = take_executor_ack(&mut exec_rx).await;
            let block_ack = take_block_consumer_ack(&mut pm_rx).await;
            exec_ack.acknowledge();
            block_ack.acknowledge();

            // The waiter borrows nothing, but mirror the deterministic-runtime
            // pattern in `dkg_actor::sim_tests`: race the resolved waiter against
            // a runtime `Clock` sleep instead of a wall-clock async timeout. The
            // safety bound never fires because the waiter resolves once every
            // copy is acknowledged.
            let mut waiter = std::pin::pin!(waiter);
            let mut timeout = std::pin::pin!(context.sleep(Duration::from_secs(1)));
            let result = commonware_macros::select! {
                result = &mut waiter => result,
                _ = &mut timeout => panic!("waiter must resolve once every copy is acknowledged"),
            };
            assert!(
                result.is_ok(),
                "waiter must resolve Ok when executor and block consumer both ack, got {result:?}"
            );
        });
    }

    /// SEC-2: if a single fan-out copy is dropped without being acknowledged,
    /// the marshal `Exact` waiter resolves to `Err(Canceled)` - the upstream
    /// fatal-panic hazard for a stalled/non-acking consumer.
    ///
    /// Guard sanity: if `Exact::drop` did NOT cancel on an unacknowledged drop,
    /// the executor's ack would leave `remaining == 0` and the waiter would
    /// wrongly resolve to `Ok(())`; this asserting `Err` proves the cancel path.
    #[test]
    fn dropped_block_consumer_copy_cancels_waiter() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let (mut reporter, mut exec_rx, mut pm_rx) = build_reporter();
            let (ack, waiter) = Exact::handle();

            let feedback = reporter.report(Update::Block(make_test_block(0x02), ack));
            assert!(
                matches!(feedback, commonware_actor::Feedback::Ok),
                "report must succeed when both mailboxes are open"
            );

            // Acknowledge only the executor's copy; drop the block consumer's copy
            // without acknowledging it (simulates a stalled/non-acking consumer).
            let exec_ack = take_executor_ack(&mut exec_rx).await;
            let block_ack = take_block_consumer_ack(&mut pm_rx).await;
            exec_ack.acknowledge();
            drop(block_ack);

            // Race the cancelled waiter against a runtime `Clock` sleep (mirrors
            // `dkg_actor::sim_tests`). `Exact::drop` cancels the aggregate so the
            // waiter resolves immediately; the safety bound never fires.
            let mut waiter = std::pin::pin!(waiter);
            let mut timeout = std::pin::pin!(context.sleep(Duration::from_secs(1)));
            let result = commonware_macros::select! {
                result = &mut waiter => result,
                _ = &mut timeout => panic!("waiter must resolve once the dropped copy cancels"),
            };
            assert!(
                result.is_err(),
                "waiter must resolve Err(Canceled) when any fan-out copy is dropped unacknowledged"
            );
        });
    }
}
