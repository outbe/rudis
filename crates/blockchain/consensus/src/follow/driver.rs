//! Follower sync driver.
//!
//! Pulls the upstream's finalized tip and walks the follower's marshal forward
//! to it, one height at a time, by `hint_finalized`-ing each height. The
//! marshal's gap-repair then fetches `Finalized { height }` through the
//! [`FollowResolver`](super::resolver), which verifies the certificate against
//! the epoch committee and hands the block to the executor.
//!
//! The driver never predicts epochs. It hints only through the latest possible
//! boundary allowed by the observed activation plus genesis grace. The resolver
//! authenticates a pre-announce/boundary and advances the shared epocher before
//! handing a boundary block to the marshal.

use std::time::Duration;

use commonware_consensus::types::Height;
use commonware_cryptography::bls12381;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::vec::NonEmptyVec;
use tracing::{debug, info};

use crate::follow::upstream::TipSource;
use crate::follow::FollowerEpocher;
use crate::marshal_types::MarshalMailbox;

/// How often the driver wakes to re-hint the marshal's pull window.
const TIP_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Re-query the upstream tip only every Nth wakeup. Hints re-issue every wakeup
/// (the marshal needs steady re-hinting as its floor advances), but the upstream
/// `rudis_consensusStatus` tip query is throttled to avoid HTTP 429 rate-limits
/// on a busy upstream. Between tip queries the driver drives toward the last
/// known tip.
const TIP_REFRESH_EVERY: u32 = 4;

/// How many heights above the marshal's processed floor to keep hinted at once.
/// The marshal fetches the lowest permitted height and processes in order; a
/// modest window keeps a backlog of in-flight resolver fetches without flooding
/// the bounded handler mailbox. Re-hinting the (sliding) window each tick is
/// idempotent - a height already finalized locally is skipped by the marshal.
const HINT_WINDOW: u64 = 64;

fn hint_range(
    processed: Option<Height>,
    tip: Height,
    ceiling: Option<Height>,
) -> Option<std::ops::RangeInclusive<u64>> {
    let processed = processed?.get();
    let end = tip
        .get()
        .min(processed.saturating_add(HINT_WINDOW))
        .min(ceiling?.get());
    (end > processed).then(|| processed.saturating_add(1)..=end)
}

/// A stub target peer for `hint_finalized`. The follower has no real consensus
/// peers; the resolver ignores targets and serves from the upstream regardless,
/// but `hint_finalized` requires a non-empty target set.
fn stub_targets() -> NonEmptyVec<bls12381::PublicKey> {
    use commonware_cryptography::Signer as _;
    NonEmptyVec::new(bls12381::PrivateKey::from_seed(0).public_key())
}

/// Configuration for the follow driver.
pub(super) struct Config<T> {
    /// Marshal mailbox - receives `hint_finalized` for each height to pull.
    pub(super) marshal: MarshalMailbox,
    /// Upstream tip discovery.
    pub(super) tip: T,
    /// Height->epoch strategy (shared with the marshal).
    pub(super) epocher: FollowerEpocher,
}

/// The follow driver actor.
pub(super) struct Driver<E, T> {
    context: E,
    config: Config<T>,
}

impl<E, T> Driver<E, T>
where
    E: Spawner + Clock + Metrics + Send + Sync + 'static,
    T: TipSource,
{
    pub(super) fn new(context: E, config: Config<T>) -> Self {
        Self { context, config }
    }

    pub(super) fn start(self) -> commonware_runtime::Handle<()> {
        let context = self.context.child("run");
        context.spawn(move |_| self.run())
    }

    async fn run(mut self) {
        info!("follow driver started");
        // Cancellation covers pending upstream and marshal queries as well as
        // the polling sleep. A stopped marshal must never be polled for work.
        let stopped = self.context.stopped();
        tokio::select! {
            biased;
            _ = stopped => info!("follow driver stopped"),
            _ = self.drive() => {},
        }
    }

    async fn drive(&mut self) {
        // Last successfully discovered upstream tip. A fresh tip query can fail
        // transiently (e.g. the upstream RPC rate-limits our poll with HTTP 429);
        // we keep driving the marshal toward the last known tip rather than
        // stalling the whole sync on one failed status call.
        let mut last_tip: Option<Height> = None;
        let mut wakeups: u32 = 0;
        loop {
            // Refresh the tip on the first wakeup and every TIP_REFRESH_EVERY
            // after; otherwise reuse the last known tip and just re-hint.
            if wakeups.is_multiple_of(TIP_REFRESH_EVERY) {
                match self.config.tip.finalized_tip().await {
                    Some(tip) => last_tip = Some(tip),
                    None => debug!("upstream tip query failed; driving to last known tip"),
                }
            }
            wakeups = wakeups.wrapping_add(1);
            if let Some(tip) = last_tip {
                self.pull_to(tip).await;
            }
            self.context.sleep(TIP_POLL_INTERVAL).await;
        }
    }

    /// Drive the marshal forward to `tip`.
    ///
    /// The marshal advances its finalized chain ONE height at a time and only
    /// admits a resolver fetch for a height ABOVE its processed floor (a flooded
    /// batch of out-of-order hints is silently dropped - `hint_finalized` is
    /// fire-and-forget). So each tick we read the marshal's current processed
    /// height and (re-)hint a small contiguous WINDOW just above it, after
    /// ensuring every epoch the window spans has its committee registered. As
    /// the marshal processes the lowest height the floor rises, and the next
    /// tick's window slides up - keeping a bounded backlog of in-flight fetches
    /// without ever leaving a gap unhinted.
    async fn pull_to(&mut self, tip: Height) {
        // Marshal's processed floor (genesis anchor = height 0 on a fresh node).
        let processed = self.config.marshal.get_processed_height().await;
        let Some(range) = hint_range(processed, tip, self.config.epocher.supported_ceiling())
        else {
            debug!(
                tip = tip.get(),
                processed = ?processed,
                "follow driver has no eligible hint range"
            );
            // Missing progress is not genesis or rollback. The engine supervises
            // marshal termination; this driver must not fabricate new work.
            return;
        };

        let targets = stub_targets();
        let hint_start = *range.start();
        let hint_end = *range.end();
        for height in range {
            self.config
                .marshal
                .hint_finalized(Height::new(height), targets.clone());
        }
        debug!(
            tip = tip.get(),
            processed = ?processed,
            hint_start,
            hint_end,
            observed_ceiling = hint_end,
            "follow driver hinted window"
        );
    }
}

#[cfg(test)]
#[path = "driver_tests.rs"]
mod tests;
