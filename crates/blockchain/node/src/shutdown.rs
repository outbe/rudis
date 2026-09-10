//! Process-owned execution shutdown state, independent of the cancellable launcher.

use eyre::{eyre, Result};
use futures::FutureExt;
use outbe_primitives::OutbePayloadTypes;
use reth_payload_builder_primitives::Events;
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
};
use tokio::sync::{broadcast, Notify};

/// Composes the standard Reth job generator and service while handing the event
/// sender lifetime to the process owner. Payload execution and task supervision
/// remain the existing Reth implementations.
#[derive(Clone, Debug)]
pub struct OutbePayloadServiceBuilder(NodeShutdown);

impl OutbePayloadServiceBuilder {
    pub(crate) fn new(shutdown: NodeShutdown) -> Self {
        Self(shutdown)
    }
}

impl<N, Pool>
    reth_node_builder::components::PayloadServiceBuilder<N, Pool, outbe_evm::OutbeEvmConfig>
    for OutbePayloadServiceBuilder
where
    N: reth_node_builder::FullNodeTypes<Types = crate::OutbeNode>,
    Pool: reth_transaction_pool::TransactionPool<
            Transaction: reth_transaction_pool::PoolTransaction<
                Consensus = outbe_primitives::OutbeTxEnvelope,
            >,
        > + Unpin
        + 'static,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &reth_node_builder::BuilderContext<N>,
        pool: Pool,
        evm_config: outbe_evm::OutbeEvmConfig,
    ) -> Result<reth_payload_builder::PayloadBuilderHandle<OutbePayloadTypes>> {
        use reth_basic_payload_builder::{
            BasicPayloadJobGenerator, BasicPayloadJobGeneratorConfig,
        };
        use reth_node_builder::components::PayloadBuilderBuilder;
        use reth_provider::CanonStateSubscriptions;

        let builder = crate::node::OutbePayloadBuilderBuilder
            .build_payload_builder(ctx, pool, evm_config)
            .await?;
        let config = &ctx.config().builder;
        let jobs = BasicPayloadJobGenerator::with_builder(
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            BasicPayloadJobGeneratorConfig::default()
                .interval(config.interval)
                .deadline(config.deadline)
                .max_payload_tasks(config.max_payload_tasks),
            builder,
        );
        let (service, handle) = reth_payload_builder::PayloadBuilderService::new(
            jobs,
            ctx.provider().canonical_state_stream(),
        );
        self.0
            .retain_payload_events(service.payload_events_handle())?;
        ctx.task_executor()
            .spawn_critical_task("payload builder service", service);
        Ok(handle)
    }
}

/// Retains the payload event sender until the execution engine stops polling it.
/// The process owner must retain this value across the complete Reth CLI run and
/// call `finish` after runtime teardown, including on startup failure.
#[derive(Clone, Default)]
pub struct NodeShutdown {
    inner: Arc<Mutex<State>>,
    changed: Arc<Notify>,
}

#[derive(Default)]
struct State {
    payload_events: Option<broadcast::Sender<Events<OutbePayloadTypes>>>,
    observing: bool,
    engine_result: Option<Result<()>>,
    failures: Vec<eyre::Report>,
}

impl std::fmt::Debug for NodeShutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeShutdown").finish_non_exhaustive()
    }
}

impl NodeShutdown {
    pub(crate) fn retain_payload_events(
        &self,
        sender: broadcast::Sender<Events<OutbePayloadTypes>>,
    ) -> Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| eyre!("shutdown state poisoned"))?;
        eyre::ensure!(
            state.payload_events.is_none(),
            "payload service already registered"
        );
        state.payload_events = Some(sender);
        Ok(())
    }

    /// Observe the real engine outcome without tying its lifetime to the launcher.
    /// This task participates in Reth's graceful drain, not ordinary cancellation:
    /// its guard prevents runtime teardown before the engine result is recorded.
    pub fn observe_engine_exit<F>(&self, executor: &reth_tasks::TaskExecutor, exit: F) -> Result<()>
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        {
            let mut state = self
                .inner
                .lock()
                .map_err(|_| eyre!("shutdown state poisoned"))?;
            eyre::ensure!(!state.observing, "engine exit already observed");
            state.observing = true;
        }
        let owner = self.clone();
        // Registration is synchronous, before returning to the launcher. Keep
        // the unpolled shutdown guard even for an engine that exits before any
        // shutdown signal; observation must not wait for a process stop request.
        drop(
            executor.spawn_with_graceful_shutdown_signal(async move |guard| {
                let result = AssertUnwindSafe(exit)
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|panic| {
                        Err(eyre!(
                            "execution exit observer panicked: {}",
                            panic_message(panic.as_ref())
                        ))
                    });
                match owner.inner.lock() {
                    Ok(mut state) => {
                        state.engine_result = Some(result);
                        // The consumer has exited: producer cancellation can now close
                        // the channel without racing its select_next_some future.
                        state.payload_events.take();
                    }
                    Err(_) => {
                        tracing::error!("shutdown state poisoned while recording engine exit")
                    }
                }
                owner.changed.notify_waiters();
                drop(guard);
            }),
        );
        Ok(())
    }

    /// Wait for notification without consuming the outcome needed after teardown.
    pub async fn engine_exited(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .inner
                .lock()
                .map_or(true, |state| state.engine_result.is_some())
            {
                return;
            }
            changed.await;
        }
    }

    /// Preserve a failure across cancellation of the launcher and its guards.
    pub fn record_failure(&self, error: eyre::Report) {
        match self.inner.lock() {
            Ok(mut state) => state.failures.push(error),
            Err(_) => tracing::error!(%error, "shutdown state poisoned while recording failure"),
        }
    }

    /// Keep a consensus panic observable after its thread has been joined.
    pub fn record_panic(&self, panic: Box<dyn std::any::Any + Send>) {
        self.record_failure(eyre!(
            "consensus thread panicked: {}",
            panic_message(panic.as_ref())
        ));
    }

    /// Publish a task panic before forwarding it to its existing JoinHandle.
    /// A signal may drop the launcher before it joins that handle; the process
    /// owner must still retain failures that have already occurred.
    pub fn track_task<F>(
        &self,
        name: &'static str,
        task: F,
    ) -> impl Future<Output = ()> + Send + 'static
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let owner = self.clone();
        async move {
            if let Err(panic) = AssertUnwindSafe(task).catch_unwind().await {
                owner.record_failure(eyre!("{name} panicked: {}", panic_message(panic.as_ref())));
                std::panic::resume_unwind(panic);
            }
        }
    }

    /// Combine known failures only after the runner has completed runtime teardown.
    /// This is not a persistence certificate: stock Reth may log persistence
    /// errors without forwarding them through its engine-exit future.
    pub fn finish(self, command_result: Result<()>) -> Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| eyre!("shutdown state poisoned"))?;
        let mut failures = Vec::new();
        if let Err(error) = command_result {
            failures.push(error);
        }
        if state.observing {
            match state.engine_result.take() {
                Some(Ok(())) => {}
                Some(Err(error)) => failures.push(error.wrap_err("execution engine failed")),
                None => failures.push(eyre!(
                    "execution engine completion missing after runtime teardown"
                )),
            }
        }
        failures.append(&mut state.failures);
        state.payload_events.take();
        let mut failures = failures.into_iter();
        let Some(mut primary) = failures.next() else {
            return Ok(());
        };
        for secondary in failures {
            primary = primary.wrap_err(format!("additional shutdown failure: {secondary:#}"));
        }
        Err(primary)
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> &str {
    panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[test]
    fn runtime_teardown_waits_for_the_engine_outcome_observer() {
        let runtime = reth_tasks::Runtime::test();
        let owner = NodeShutdown::default();
        let (done, exit) = oneshot::channel();
        runtime.handle().block_on(async {
            owner
                .observe_engine_exit(&runtime, async { exit.await.map_err(Into::into) })
                .unwrap();
        });

        // The engine outcome is deliberately not available yet. No scheduler
        // delay or polling count may let graceful teardown claim completion.
        assert!(!runtime.graceful_shutdown_with_timeout(std::time::Duration::ZERO));
        done.send(()).unwrap();
        runtime.handle().block_on(owner.engine_exited());
        assert!(runtime.graceful_shutdown_with_timeout(std::time::Duration::from_secs(5)));
        drop(runtime);
        owner.finish(Ok(())).unwrap();
    }

    #[tokio::test]
    async fn producer_cancellation_cannot_close_events_before_engine_exit() {
        use futures::StreamExt as _;
        use reth_payload_builder_primitives::PayloadEvents;
        let runtime = reth_tasks::Runtime::test();
        let owner = NodeShutdown::default();
        let (producer, receiver) = broadcast::channel(1);
        let mut events = PayloadEvents { receiver }
            .into_built_payload_stream()
            .fuse();
        owner.retain_payload_events(producer.clone()).unwrap();
        let (done, exit) = oneshot::channel();
        owner
            .observe_engine_exit(&runtime, async { exit.await.map_err(Into::into) })
            .unwrap();
        drop(producer);
        // Poll the same adapter/future used by Reth's engine, not just the
        // underlying broadcast receiver. EOF here would panic select_next_some.
        assert!(events.select_next_some().now_or_never().is_none());
        done.send(()).unwrap();
        owner.engine_exited().await;
        assert!(events.next().await.is_none());
        owner.finish(Ok(())).unwrap();
    }

    #[tokio::test]
    async fn engine_failure_survives_launcher_cancellation_and_cleanup_failure() {
        let runtime = reth_tasks::Runtime::test();
        let owner = NodeShutdown::default();
        owner
            .observe_engine_exit(&runtime, async { Err(eyre!("real engine failure")) })
            .unwrap();
        owner.engine_exited().await;
        owner.record_failure(eyre!("consensus drain failed"));
        let error = owner.finish(Ok(())).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("real engine failure"));
        assert!(message.contains("consensus drain failed"));
    }

    #[tokio::test]
    async fn missing_completion_is_not_success() {
        let runtime = reth_tasks::Runtime::test();
        let owner = NodeShutdown::default();
        owner
            .observe_engine_exit(&runtime, std::future::pending())
            .unwrap();
        assert!(format!("{:#}", owner.finish(Ok(())).unwrap_err()).contains("completion missing"));
    }

    #[test]
    fn startup_error_without_engine_is_preserved() {
        let error = NodeShutdown::default()
            .finish(Err(eyre!("startup failed")))
            .unwrap_err();
        assert!(format!("{error:#}").contains("startup failed"));
    }

    #[tokio::test]
    async fn background_panic_is_recorded_without_consuming_the_join_result() {
        let owner = NodeShutdown::default();
        let handle = tokio::spawn(owner.track_task("lease worker", async { panic!("read panic") }));
        assert!(handle.await.unwrap_err().is_panic());
        assert!(format!("{:#}", owner.finish(Ok(())).unwrap_err())
            .contains("lease worker panicked: read panic"));
    }
}
