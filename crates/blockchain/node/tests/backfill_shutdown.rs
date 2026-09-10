//! Component reproduction of cancellation during stock Reth backfill.
//!
//! Only the stage's readiness is controlled. Task spawning/cancellation, the
//! pipeline result channel and fatal-event classification are production Reth.
//! This does not launch the node or reproduce the engine select's scheduling.

use alloy_primitives::B256;
use futures::{FutureExt, StreamExt};
use reth_engine_tree::{
    backfill::{BackfillAction, BackfillEvent, BackfillSync, PipelineSync},
    chain::{ChainEvent, ChainHandler, ChainOrchestrator, FromOrchestrator, HandlerEvent},
};
use reth_provider::test_utils::{create_test_provider_factory, MockNodeTypesWithDB};
use reth_stages_api::{
    ExecInput, ExecOutput, Pipeline, PipelineTarget, Stage, StageError, StageId, UnwindInput,
    UnwindOutput,
};
use reth_static_file::StaticFileProducer;
use reth_tasks::Runtime;
use std::{
    future::poll_fn,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{oneshot, watch};

const WAIT: Duration = Duration::from_secs(5);

struct WaitingStage {
    entered: Option<oneshot::Sender<()>>,
    dropped: Option<oneshot::Sender<()>>,
}

impl Drop for WaitingStage {
    fn drop(&mut self) {
        if let Some(sender) = self.dropped.take() {
            let _ = sender.send(());
        }
    }
}

impl<P> Stage<P> for WaitingStage {
    fn id(&self) -> StageId {
        StageId::Other("BackfillCancellationProbe")
    }

    fn poll_execute_ready(
        &mut self,
        _: &mut Context<'_>,
        _: ExecInput,
    ) -> Poll<Result<(), StageError>> {
        if let Some(sender) = self.entered.take() {
            sender.send(()).expect("readiness observer retained");
        }
        Poll::Pending
    }

    fn execute(&mut self, _: &P, _: ExecInput) -> Result<ExecOutput, StageError> {
        panic!("waiting stage must not execute")
    }

    fn unwind(&mut self, _: &P, _: UnwindInput) -> Result<UnwindOutput, StageError> {
        panic!("waiting stage must not unwind")
    }
}

fn pipeline(
    runtime: &Runtime,
) -> (
    PipelineSync<MockNodeTypesWithDB>,
    oneshot::Receiver<()>,
    oneshot::Receiver<()>,
) {
    let provider = create_test_provider_factory();
    let files = StaticFileProducer::new(provider.clone(), Default::default());
    let (tip, _tip_receiver) = watch::channel(B256::ZERO);
    let (entered_tx, entered) = oneshot::channel();
    let (dropped_tx, dropped) = oneshot::channel();
    let pipeline = Pipeline::builder()
        .add_stage(WaitingStage {
            entered: Some(entered_tx),
            dropped: Some(dropped_tx),
        })
        .with_tip_sender(tip)
        .build(provider, files);
    (
        PipelineSync::new(pipeline, runtime.clone()),
        entered,
        dropped,
    )
}

#[derive(Default)]
struct IdleHandler;

impl ChainHandler for IdleHandler {
    type Event = ();

    fn on_event(&mut self, _: FromOrchestrator) {}

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<HandlerEvent<Self::Event>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn runtime_cancellation_drops_an_active_stock_pipeline() {
    let runtime = Runtime::test();
    let (mut sync, entered, dropped) = pipeline(&runtime);
    sync.on_action(BackfillAction::Start(PipelineTarget::Sync(
        B256::repeat_byte(1),
    )));
    assert!(matches!(
        poll_fn(|cx| sync.poll(cx)).await,
        BackfillEvent::Started(_)
    ));
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    assert!(poll_fn(|cx| sync.poll(cx)).now_or_never().is_none());

    assert!(runtime.graceful_shutdown_with_timeout(Duration::ZERO));
    tokio::time::timeout(WAIT, dropped).await.unwrap().unwrap();
    let event = tokio::time::timeout(WAIT, poll_fn(|cx| sync.poll(cx)))
        .await
        .unwrap();
    assert!(
        matches!(event, BackfillEvent::TaskDropped(_)),
        "actual event: {event:?}"
    );
}

#[tokio::test]
async fn idle_backfill_has_no_fatal_event_after_runtime_shutdown() {
    let runtime = Runtime::test();
    let (sync, _entered, _dropped) = pipeline(&runtime);
    let mut chain = ChainOrchestrator::new(IdleHandler, sync);
    assert!(chain.next().now_or_never().is_none());
    assert!(runtime.graceful_shutdown_with_timeout(Duration::ZERO));
    assert!(chain.next().now_or_never().is_none());
}

// Potential defect, not a confirmed full-node shutdown failure. The owner
// deferred it until the real launcher/signal/restart path is reproduced.
// Keep the assertion red-capable rather than accepting a fatal event as success.
// Manual reproduction (expected to fail on the currently pinned Reth):
// cargo test -p outbe-node --test backfill_shutdown \
//   graceful_shutdown_must_not_report_backfill_fatal -- --ignored --exact
#[tokio::test]
#[ignore = "outbe-chain-7vz.38: forced component interleaving; full-node occurrence and restart impact unverified"]
async fn graceful_shutdown_must_not_report_backfill_fatal() {
    let runtime = Runtime::test();
    let (sync, entered, dropped) = pipeline(&runtime);
    let mut chain = ChainOrchestrator::new(IdleHandler, sync);
    chain.start_backfill_sync(PipelineTarget::Sync(B256::repeat_byte(1)));
    assert!(matches!(
        chain.next().await,
        Some(ChainEvent::BackfillSyncStarted)
    ));
    tokio::time::timeout(WAIT, entered).await.unwrap().unwrap();
    assert!(chain.next().now_or_never().is_none());

    assert!(runtime.graceful_shutdown_with_timeout(Duration::ZERO));
    tokio::time::timeout(WAIT, dropped).await.unwrap().unwrap();
    // Force the legal interleaving where the orchestrator is polled after the
    // ordinary pipeline task is cancelled, before the engine handles shutdown.
    let event = tokio::time::timeout(WAIT, chain.next()).await.unwrap();
    assert!(
        !matches!(event, Some(ChainEvent::FatalError)),
        "graceful shutdown was classified as a backfill failure: {event:?}"
    );
}
