//! Own the endpoint task through installation, graceful shutdown and reaping.

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::network::EndpointNetworkResolver;
use crate::manager::ManagerError;

#[derive(Default)]
enum State {
    #[default]
    Unstarted,
    Running(tokio::task::JoinHandle<Result<(), ManagerError>>),
    Closed,
}

#[derive(Default)]
struct OwnedState(State);

impl Drop for OwnedState {
    fn drop(&mut self) {
        if let State::Running(task) = &self.0 {
            task.abort();
        }
    }
}

/// The observer and consensus startup share installation/closure ownership.
/// No task can be installed after shutdown has claimed this owner.
#[derive(Clone, Default)]
pub struct EndpointTaskOwner(Arc<Mutex<OwnedState>>);

impl EndpointTaskOwner {
    /// `false` means shutdown won the startup race; no task was spawned.
    pub fn start(
        &self,
        run: impl Future<Output = Result<(), ManagerError>> + Send + 'static,
    ) -> Result<bool, ManagerError> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| ManagerError::Task("endpoint owner poisoned".into()))?;
        match &state.0 {
            State::Closed => Ok(false),
            State::Running(_) => Err(ManagerError::Task("endpoint already installed".into())),
            State::Unstarted => {
                state.0 = State::Running(tokio::spawn(run));
                Ok(true)
            }
        }
    }

    /// Called only after the manager has drained. An unstarted service needs no
    /// mailbox acknowledgement. A started service must retain its actual result.
    pub async fn shutdown(&self, resolver: &EndpointNetworkResolver) -> Result<(), ManagerError> {
        let task = {
            let mut state = self
                .0
                .lock()
                .map_err(|_| ManagerError::Task("endpoint owner poisoned".into()))?;
            match std::mem::replace(&mut state.0, State::Closed) {
                State::Running(task) => task,
                State::Unstarted => return Ok(()),
                State::Closed => {
                    return Err(ManagerError::Task("endpoint drain already claimed".into()));
                }
            }
        };
        stop_and_join(task, resolver.shutdown()).await
    }
}

async fn stop_and_join(
    mut task: tokio::task::JoinHandle<Result<(), ManagerError>>,
    stop: impl Future<Output = Result<(), ManagerError>>,
) -> Result<(), ManagerError> {
    // Cancellation of this future must not detach a still-running endpoint.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _guard = AbortOnDrop(task.abort_handle());
    if task.is_finished() {
        return task
            .await
            .map_err(|error| ManagerError::Task(format!("endpoint service: {error}")))?;
    }
    let end = tokio::time::Instant::now() + crate::endpoint::HANDLE_DEADLINE;
    let drain_end = end - Duration::from_millis(500);
    let stopped = tokio::time::timeout_at(drain_end, stop)
        .await
        .unwrap_or(Err(ManagerError::ShutdownDeadline("endpoint service")));
    // A closed command mailbox can mean the service is already cleaning up a
    // transport error. Let it return that result before resorting to abort.
    let joined = match tokio::time::timeout_at(drain_end, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(ManagerError::Task(format!("endpoint service: {error}"))),
        Err(_) => {
            task.abort();
            match tokio::time::timeout_at(end, &mut task).await {
                Ok(Err(error)) if !error.is_cancelled() => {
                    Err(ManagerError::Task(format!("endpoint service: {error}")))
                }
                Ok(_) => Err(ManagerError::ShutdownDeadline("endpoint service join")),
                Err(_) => Err(ManagerError::ShutdownDeadline(
                    "endpoint service cancellation",
                )),
            }
        }
    };
    match (stopped, joined) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(stop), Err(join)) => Err(ManagerError::Task(format!(
            "{stop}; endpoint join also failed: {join}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::{EndpointNetwork, RadicleStatusChannel};
    use alloy_primitives::{Address, B256};

    fn endpoint() -> (
        super::super::EndpointNetworkService,
        EndpointNetworkResolver,
    ) {
        let (_, status) = RadicleStatusChannel::enabled(Address::ZERO, [1; 32]);
        let (service, resolver, _) = EndpointNetwork::build(
            crate::endpoint::ChainIdentity {
                chain_id: 1,
                genesis_hash: B256::ZERO,
            },
            status,
        );
        (service, resolver)
    }

    #[tokio::test]
    async fn unstarted_endpoint_needs_no_ack_and_cannot_start_after_drain() {
        let (_service, resolver) = endpoint();
        let owner = EndpointTaskOwner::default();
        owner.shutdown(&resolver).await.unwrap();
        assert!(!owner
            .start(async { panic!("must not run after closure") })
            .unwrap());
    }

    #[tokio::test]
    async fn completed_endpoint_retains_actual_transport_error_or_panic() {
        for panic in [false, true] {
            let (_service, resolver) = endpoint();
            let owner = EndpointTaskOwner::default();
            let (done, completion) = tokio::sync::oneshot::channel::<()>();
            owner
                .start(async move {
                    let _done = done;
                    assert!(!panic, "endpoint panic witness");
                    Err(ManagerError::Endpoint("network failure witness".into()))
                })
                .unwrap();
            assert!(completion.await.is_err());
            // Poll the retained handle to completion via shutdown, never turn a
            // closed mailbox into success or lose the original network error.
            let error = owner.shutdown(&resolver).await.unwrap_err().to_string();
            assert!(error.contains(if panic {
                "endpoint panic witness"
            } else {
                "network failure witness"
            }));
        }
    }

    #[tokio::test]
    async fn closed_ack_is_not_success_even_if_service_exits_cleanly() {
        let (release, stop) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async {
            stop.await.unwrap();
            Ok(())
        });
        let error = stop_and_join(task, async {
            release.send(()).unwrap();
            Err(ManagerError::Endpoint(
                "shutdown acknowledgement closed".into(),
            ))
        })
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("shutdown acknowledgement closed"));
    }

    #[tokio::test(start_paused = true)]
    async fn ack_without_service_exit_is_aborted_and_reaped() {
        let (alive, dropped) = tokio::sync::oneshot::channel::<()>();
        let (entered, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _alive = alive;
            entered.send(()).unwrap();
            std::future::pending::<Result<(), ManagerError>>().await
        });
        started.await.unwrap();
        assert!(matches!(
            stop_and_join(task, async { Ok(()) }).await,
            Err(ManagerError::ShutdownDeadline("endpoint service join"))
        ));
        assert!(dropped.await.is_err());
    }

    #[tokio::test]
    async fn ack_then_panic_preserves_join_failure() {
        let (release, stop) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async {
            stop.await.unwrap();
            panic!("panic after service ack")
        });
        let error = stop_and_join(task, async {
            release.send(()).unwrap();
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("panic after service ack"));
    }
}
