//! Execution runtime lifetime at the synchronous CLI boundary.

use eyre::Result;
use reth_cli_runner::CliRunner;
use reth_ethereum::tasks::{RuntimeConfig, TokioConfig};
use std::time::Duration;

/// The Tokio owner must never be retained by provider/network task clones.
/// Match CliRunner's bounded runtime teardown, including while unwinding.
struct ExecutionRuntimeOwner(Option<tokio::runtime::Runtime>);

impl Drop for ExecutionRuntimeOwner {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(Duration::from_secs(5));
        }
    }
}

/// Called only at the synchronous CLI boundary, before NodeShutdown::finish.
pub(super) fn run_with_execution_runtime(
    mut config: RuntimeConfig,
    run: impl FnOnce(CliRunner) -> Result<()>,
) -> Result<()> {
    let owner = ExecutionRuntimeOwner(match &config.tokio {
        TokioConfig::Owned {
            worker_threads,
            thread_keep_alive,
            thread_name,
        } => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder
                .enable_all()
                .thread_keep_alive(*thread_keep_alive)
                .thread_name(*thread_name);
            if let Some(threads) = worker_threads {
                builder.worker_threads(*threads);
            }
            Some(builder.build()?)
        }
        TokioConfig::ExistingHandle(_) => None,
    });
    if let Some(runtime) = &owner.0 {
        config.tokio = TokioConfig::existing_handle(runtime.handle().clone());
    }
    let result = run(CliRunner::try_with_runtime_config(config)?);
    // The Reth runner retains its normal graceful drain and error supervision.
    // Its final provider clone can now release pools, but not the Tokio owner.
    drop(owner);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{panic::AssertUnwindSafe, sync::mpsc, time::Duration};

    #[test]
    fn late_provider_runtime_clone_can_drop_in_async_task_after_runner_shutdown() {
        let result = run_with_execution_runtime(RuntimeConfig::default(), |runner| {
            // ProviderFactory retains this same Runtime type. Its last clone may
            // outlive the CLI runner and be released by a network task.
            let last_provider_runtime = runner.runtime();
            let handle = last_provider_runtime.handle().clone();
            let (release, released) = tokio::sync::oneshot::channel();
            let (finished, outcome) = mpsc::channel();
            let task = handle.spawn(async move {
                released.await.expect("release late provider");
                let dropped = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    drop(last_provider_runtime);
                }));
                finished
                    .send(dropped.is_ok())
                    .expect("report destructor outcome");
            });
            runner.run_command_until_exit(|_| async { Ok::<(), eyre::Report>(()) })?;
            release.send(()).expect("provider survived CLI shutdown");
            let dropped = outcome
                .recv_timeout(Duration::from_secs(5))
                .expect("late provider drop completed");
            drop(task);
            assert!(
                dropped,
                "late provider drop panicked inside the async context"
            );
            Ok(())
        });
        result.expect("launcher result");
    }

    #[test]
    fn startup_rejection_survives_graceful_runtime_teardown() {
        let shutdown = outbe_node::shutdown::NodeShutdown::default();
        let result = run_with_execution_runtime(RuntimeConfig::default(), |runner| {
            runner.run_command_until_exit(|_| async {
                // Match run_node: retain the admission error, then enter the
                // regular CLI graceful drain instead of bypassing teardown.
                shutdown.record_failure(eyre::eyre!("certified follower recovery required"));
                Ok::<(), eyre::Report>(())
            })
        });
        let error = shutdown
            .finish(result)
            .expect_err("startup must remain rejected");
        assert!(format!("{error:#}").contains("certified follower recovery required"));
    }

    #[test]
    fn cli_error_is_not_converted_to_success() {
        let error = run_with_execution_runtime(RuntimeConfig::default(), |runner| {
            runner.run_command_until_exit(|_| async {
                Err::<(), _>(eyre::eyre!("real execution failure"))
            })
        })
        .expect_err("real CLI failure must propagate");
        assert!(format!("{error:#}").contains("real execution failure"));
    }

    struct TaskDropped(mpsc::Sender<()>);

    impl Drop for TaskDropped {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    #[test]
    fn launcher_unwind_reaps_runtime_tasks_without_hiding_the_panic() {
        let (dropped, reaped) = mpsc::channel();
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = run_with_execution_runtime(RuntimeConfig::default(), |runner| {
                let (started, ready) = mpsc::channel();
                let task = runner.runtime().handle().spawn(async move {
                    let _marker = TaskDropped(dropped);
                    started.send(()).expect("report live task");
                    std::future::pending::<()>().await;
                });
                ready
                    .recv_timeout(Duration::from_secs(5))
                    .expect("task entered");
                drop(task);
                panic!("launcher failure");
            });
        }))
        .expect_err("launcher panic must not be swallowed");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"launcher failure"));
        reaped
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime task reaped on unwind");
    }

    #[test]
    fn existing_runtime_remains_owned_by_its_caller() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let config = RuntimeConfig::default()
            .with_tokio(TokioConfig::existing_handle(runtime.handle().clone()));
        run_with_execution_runtime(config, |runner| {
            runner.run_command_until_exit(|_| async { Ok::<(), eyre::Report>(()) })
        })
        .unwrap();
        assert_eq!(
            runtime.block_on(async { tokio::spawn(async { 42 }).await.unwrap() }),
            42
        );
    }
}
