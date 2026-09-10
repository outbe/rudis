//! Application drain shared by the terminal protocol path and the runtime owner.

use std::{future::Future, panic::AssertUnwindSafe, sync::Arc};

use eyre::Result;
use futures::{
    future::{BoxFuture, Shared},
    FutureExt as _,
};

/// Keeps application dependencies alive until their owners have stopped using
/// them. Clones observe the same drain, including its failure, exactly once.
#[derive(Clone)]
pub struct ApplicationDrain(Shared<BoxFuture<'static, Result<(), Arc<str>>>>);

impl Default for ApplicationDrain {
    fn default() -> Self {
        Self::new(async { Ok(()) })
    }
}

impl ApplicationDrain {
    pub fn new(drain: impl Future<Output = Result<()>> + Send + 'static) -> Self {
        Self(
            async move { drain.await.map_err(|error| Arc::from(format!("{error:#}"))) }
                .boxed()
                .shared(),
        )
    }

    pub async fn drain(&self) -> Result<()> {
        self.0.clone().await.map_err(|error| eyre::eyre!("{error}"))
    }

    /// Run *inside* the retained Commonware supervision task. Catch an inner
    /// panic here, before completing that task aborts its transport descendants.
    pub(crate) async fn finish(&self, protocol: impl Future<Output = Result<()>>) -> Result<()> {
        let result = AssertUnwindSafe(protocol)
            .catch_unwind()
            .await
            .unwrap_or_else(|panic| {
                let message = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic payload");
                Err(eyre::eyre!("consensus stack panicked: {message}"))
            });
        combine(result, self.drain().await)
    }
}

/// Retain the primary error as well as an independent cleanup failure.
pub fn combine(primary: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.wrap_err(format!("application drain also failed: {cleanup:#}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrent_drain_callers_share_one_completed_outcome() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let drain = ApplicationDrain::new(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(eyre::eyre!("manager failed"))
        });
        let (first, second) = tokio::join!(drain.drain(), drain.drain());
        assert!(first.unwrap_err().to_string().contains("manager failed"));
        assert!(second.unwrap_err().to_string().contains("manager failed"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn startup_error_and_panic_both_drain_and_preserve_primary_failure() {
        for panic in [false, true] {
            let drain = ApplicationDrain::new(async { Err(eyre::eyre!("cleanup failed")) });
            let error = drain
                .finish(async {
                    assert!(!panic, "startup panic");
                    Err(eyre::eyre!("startup failed"))
                })
                .await
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains(if panic {
                "startup panic"
            } else {
                "startup failed"
            }));
            assert!(error.contains("cleanup failed"));
        }
    }
}
