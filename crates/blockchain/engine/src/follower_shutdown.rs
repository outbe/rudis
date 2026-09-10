//! Follower-only pre-stop barrier. Marshal must stay alive until accepted
//! execution deliveries and their exact parent proofs have drained.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use commonware_actor::Feedback;
use commonware_consensus::{marshal::Update, Reporter};
use commonware_utils::acknowledgement::Exact;
use eyre::{ensure, eyre, Result};
use outbe_consensus::{executor::Mailbox, marshal_types::MarshalUpdate};
use tokio::sync::oneshot;

#[derive(Default)]
struct Ingress {
    installed: bool,
    quiescing: bool,
    executor: Option<Mailbox>,
    // These deliveries were not accepted by the executor. Do not acknowledge
    // or cancel them while Marshal is alive. Its existing max_pending_acks
    // bounds this collection; the archived blocks remain available on restart.
    withheld: Vec<Exact>,
}

/// NodeHost side of the one-shot barrier, awaited before runtime.stop.
pub struct FollowerDrainControl {
    ingress: Arc<Mutex<Ingress>>,
    completion: oneshot::Receiver<()>,
}

/// Stack side: register ingress before starting execution and acknowledge only
/// after both executor exit and finality-observer persistence succeed.
pub struct FollowerDrain {
    ingress: Arc<Mutex<Ingress>>,
    completion: oneshot::Sender<()>,
}

pub fn follower_drain_pair() -> (FollowerDrainControl, FollowerDrain) {
    let ingress = Arc::new(Mutex::new(Ingress::default()));
    let (tx, rx) = oneshot::channel();
    (
        FollowerDrainControl {
            ingress: Arc::clone(&ingress),
            completion: rx,
        },
        FollowerDrain {
            ingress,
            completion: tx,
        },
    )
}

impl FollowerDrainControl {
    pub async fn drain(self, deadline: Duration) -> Result<()> {
        let installed = {
            let mut ingress = self
                .ingress
                .lock()
                .map_err(|_| eyre!("follower ingress lock poisoned"))?;
            ingress.quiescing = true;
            // Dropping the sole sender closes ingress; executor drains its
            // already accepted queue and closes its height notification stream.
            ingress.executor.take();
            ingress.installed
        };
        if !installed {
            // Registration races with stop under the same lock. A later
            // registration observes quiescing and cannot start execution.
            return Ok(());
        }
        tokio::time::timeout(deadline, self.completion)
            .await
            .map_err(|_| {
                eyre!("follower execution/proof drain deadline exceeded before Marshal stop")
            })?
            .map_err(|_| eyre!("follower execution/proof drain ended without completion"))
    }
}

impl FollowerDrain {
    pub(crate) fn install(&self, executor: Mailbox) -> Result<Option<FollowerReporter>> {
        let mut ingress = self
            .ingress
            .lock()
            .map_err(|_| eyre!("follower ingress lock poisoned"))?;
        ensure!(!ingress.installed, "follower ingress already installed");
        if ingress.quiescing {
            return Ok(None);
        }
        ingress.installed = true;
        ingress.executor = Some(executor);
        Ok(Some(FollowerReporter {
            ingress: Arc::clone(&self.ingress),
        }))
    }

    pub(crate) async fn finish(
        self,
        executor: impl std::future::Future<Output = Result<()>>,
        observer: impl std::future::Future<Output = Result<()>>,
    ) -> Result<()> {
        futures::try_join!(executor, observer)?;
        ensure!(
            self.ingress
                .lock()
                .map_err(|_| eyre!("follower ingress lock poisoned"))?
                .quiescing,
            "follower drained without a shutdown request"
        );
        self.completion
            .send(())
            .map_err(|_| eyre!("follower drain owner disappeared"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{channel::mpsc, FutureExt as _, StreamExt as _};

    #[tokio::test]
    async fn drain_closes_ingress_but_waits_for_both_execution_and_proofs() {
        let (control, drain) = follower_drain_pair();
        let (tx, mut rx) = mpsc::unbounded();
        let reporter = drain.install(Mailbox::from_sender(tx)).unwrap().unwrap();
        let wait = control.drain(Duration::from_secs(1));
        tokio::pin!(wait);
        assert!(wait.as_mut().now_or_never().is_none());
        assert!(reporter.is_quiescing().unwrap());
        assert!(rx.next().await.is_none());
        let (exec_tx, exec_rx) = oneshot::channel();
        let (proof_tx, proof_rx) = oneshot::channel();
        let finish = drain.finish(async { exec_rx.await.unwrap() }, async {
            proof_rx.await.unwrap()
        });
        tokio::pin!(finish);
        exec_tx.send(Ok(())).unwrap();
        assert!(finish.as_mut().now_or_never().is_none());
        assert!(wait.as_mut().now_or_never().is_none());
        proof_tx.send(Ok(())).unwrap();
        finish.await.unwrap();
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_before_registration_prevents_executor_start() {
        let (control, drain) = follower_drain_pair();
        control.drain(Duration::from_secs(1)).await.unwrap();
        let (tx, mut rx) = mpsc::unbounded();
        assert!(drain.install(Mailbox::from_sender(tx)).unwrap().is_none());
        assert!(rx.next().await.is_none());
    }

    #[tokio::test]
    async fn executor_or_proof_failure_never_acknowledges_a_clean_drain() {
        for fail_executor in [false, true] {
            let (control, drain) = follower_drain_pair();
            let (tx, _rx) = mpsc::unbounded();
            let _reporter = drain.install(Mailbox::from_sender(tx)).unwrap().unwrap();
            let wait = control.drain(Duration::from_secs(1));
            tokio::pin!(wait);
            assert!(wait.as_mut().now_or_never().is_none());
            let result = drain
                .finish(
                    async {
                        if fail_executor {
                            Err(eyre!("execution failure"))
                        } else {
                            Ok(())
                        }
                    },
                    async { Err(eyre!("certificate missing or store write failed")) },
                )
                .await;
            let message = result.unwrap_err().to_string();
            assert!(message.contains(if fail_executor {
                "execution failure"
            } else {
                "store write failed"
            }));
            assert!(wait
                .await
                .unwrap_err()
                .to_string()
                .contains("without completion"));
        }
    }

    #[tokio::test]
    async fn post_quiesce_delivery_is_neither_executed_nor_falsely_acknowledged() {
        use commonware_utils::acknowledgement::Acknowledgement as _;
        use outbe_consensus::block::ConsensusBlock;
        use reth_ethereum::{primitives::SealedBlock, Block};
        let (control, drain) = follower_drain_pair();
        let (tx, mut rx) = mpsc::unbounded();
        let mut reporter = drain.install(Mailbox::from_sender(tx)).unwrap().unwrap();
        let wait = control.drain(Duration::from_secs(1));
        tokio::pin!(wait);
        assert!(wait.as_mut().now_or_never().is_none());
        let block = Block::default().map_header(outbe_primitives::OutbeHeader::new);
        let (ack, acknowledged) = Exact::handle();
        tokio::pin!(acknowledged);
        reporter.report(Update::Block(
            ConsensusBlock::from_sealed(SealedBlock::seal_slow(block)),
            ack,
        ));
        assert!(rx.next().await.is_none());
        assert!(acknowledged.as_mut().now_or_never().is_none());
        drain
            .finish(async { Ok(()) }, async { Ok(()) })
            .await
            .unwrap();
        wait.await.unwrap();
        assert!(acknowledged.as_mut().now_or_never().is_none());
        // Marshal owns this reporter until its actor exits. Only then may the
        // unexecuted delivery's acknowledgement be dropped, never acknowledged.
        drop(reporter);
        assert!(acknowledged.await.is_err());
    }

    #[tokio::test]
    async fn lost_completion_or_deadline_is_an_error() {
        let (control, drain) = follower_drain_pair();
        let (tx, _rx) = mpsc::unbounded();
        let _reporter = drain.install(Mailbox::from_sender(tx)).unwrap().unwrap();
        let error = control.drain(Duration::ZERO).await.unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
        drop(drain);
    }
}

#[derive(Clone)]
pub(crate) struct FollowerReporter {
    ingress: Arc<Mutex<Ingress>>,
}

impl FollowerReporter {
    pub(crate) fn is_quiescing(&self) -> Result<bool> {
        Ok(self
            .ingress
            .lock()
            .map_err(|_| eyre!("follower ingress lock poisoned"))?
            .quiescing)
    }
}

impl Reporter for FollowerReporter {
    type Activity = MarshalUpdate;

    fn report(&mut self, activity: MarshalUpdate) -> Feedback {
        let mut ingress = self.ingress.lock().expect("follower ingress lock poisoned");
        if let Some(executor) = ingress.executor.as_mut() {
            return executor.report(activity);
        }
        assert!(
            ingress.quiescing,
            "follower reporter has no executor before shutdown"
        );
        if let Update::Block(_, ack) = activity {
            ingress.withheld.push(ack);
        }
        Feedback::Ok
    }
}
