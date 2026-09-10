//! Pure leaf helpers shared between the application verify path and the
//! finalization actor.
//!
//! These functions used to live in `crate::application::handler` and moved
//! here in step 17 of the rewards-economy-mailbox migration so the
//! finalization actor can call them without crossing module boundaries the
//! wrong way. The deep finalized-parent attestation validation surface lives
//! in [`crate::finalization::attestation`]; this module keeps only generic
//! leaf helpers: retry, replay classification, header-artifact extraction, and
//! the signer-bitmap fill.

use std::time::Duration;

use alloy_primitives::B256;
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use outbe_primitives::reshare_artifact::{
    decode_consensus_header_artifact, ConsensusHeaderArtifact,
};

use crate::{block::ConsensusBlock, hybrid::HybridCertificate};

/// Result of replay classification for a finalization event.
#[derive(Debug, PartialEq)]
pub enum ReplayClassification {
    /// Block number > last finalized - genuinely new finalization.
    New,
    /// Block number < last finalized - historical journal replay, drop.
    HistoricalReplay,
    /// Same (number, hash) as current finalized - duplicate, drop.
    DuplicateReplay,
    /// Same number but different hash - fatal chain inconsistency.
    FatalInconsistency,
}

/// Classify a finalization event as new, replayed, or inconsistent.
pub fn classify_finalization(
    block_number: u64,
    digest: B256,
    last_finalized_number: u64,
    finalized_head_hash: B256,
) -> ReplayClassification {
    if block_number < last_finalized_number {
        ReplayClassification::HistoricalReplay
    } else if block_number == last_finalized_number && digest == finalized_head_hash {
        ReplayClassification::DuplicateReplay
    } else if block_number == last_finalized_number && digest != finalized_head_hash {
        ReplayClassification::FatalInconsistency
    } else {
        ReplayClassification::New
    }
}

/// Reason a `retry_with_backoff` attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryFailureKind {
    /// Resolver returned `Err(())`.
    Unavailable,
    /// Resolver future did not complete within the per-attempt timeout.
    Timeout,
}

/// Outcome of `retry_with_backoff` after exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryFailure {
    pub attempts: u32,
    pub last_kind: RetryFailureKind,
}

/// Retry an async fallible operation with bounded attempts and a per-attempt timeout.
///
/// Returns `Ok(T)` on the first successful attempt. After `max_retries` failures
/// (`Err` or attempt-timeout), returns `Err(RetryFailure { attempts, last_kind })`.
/// A never-completing future counts as one failed attempt - it cannot wedge the caller.
pub async fn retry_with_backoff<T, F, Fut>(
    clock: &impl commonware_runtime::Clock,
    mut resolve: F,
    max_retries: u32,
    delay: Duration,
    per_attempt_timeout: Duration,
) -> Result<T, RetryFailure>
where
    F: FnMut() -> Fut,
    // `Clock::timeout` requires a `Send + 'static` future; every production and
    // test caller supplies an owned `async move` resolver, so the bound holds.
    Fut: std::future::Future<Output = Result<T, ()>> + Send + 'static,
    T: Send + 'static,
{
    let mut attempts = 0u32;
    loop {
        // `Clock::timeout` returns `Err(commonware_runtime::Error::Timeout)` on
        // expiry; the inner `Ok`/`Err(())` is the resolver's own output, unchanged
        // from the previous timeout-based implementation.
        let last_kind = match clock.timeout(per_attempt_timeout, resolve()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(())) => RetryFailureKind::Unavailable,
            Err(_) => RetryFailureKind::Timeout,
        };
        attempts += 1;
        if attempts >= max_retries {
            return Err(RetryFailure {
                attempts,
                last_kind,
            });
        }
        clock.sleep(delay).await;
    }
}

/// Extract the (optional) consensus header artifact from a block's
/// `extra_data`. Used by both the verify path and the finalization
/// actor to surface DKG boundary / dealer-log payloads.
pub fn extract_header_artifact_from_block(
    block: &ConsensusBlock,
) -> Result<Option<ConsensusHeaderArtifact>, String> {
    let raw_block = block.clone().into_inner().into_block();
    decode_consensus_header_artifact(raw_block.header.inner.extra_data.as_ref())
        .map_err(|error| error.to_string())
}

/// Canonical one-byte-per-participant signer bitmap from a certificate.
///
/// Core (unguarded) form: the caller MUST guarantee
/// `certificate.signers.len() == committee_len`. On the verify path this holds
/// by construction - the certificate is decoded with
/// `Finalization::read_cfg(.., &committee_len)`, which binds the `Signers`
/// width to `committee_len` (see
/// [`crate::finalization::attestation::validate_consensus_metadata`]).
/// `Signers::len()` is the committee size (bitmap width); `Signers::count()` is
/// the number that actually signed (`hybrid.rs`: `Signers::from(participants.len(), ..)`).
///
/// Producer paths holding a live certificate against an independently-sourced
/// committee snapshot must use [`build_signer_bitmap_guarded`] instead.
pub(crate) fn build_signer_bitmap(
    certificate: &HybridCertificate<MinSig>,
    committee_len: usize,
) -> Vec<u8> {
    let mut bitmap = vec![0u8; committee_len];
    for signer in certificate.signers.iter() {
        let idx = signer.get() as usize;
        if idx < committee_len {
            bitmap[idx] = 1;
        }
    }
    bitmap
}

/// Producer-side guarded wrapper around [`build_signer_bitmap`].
///
/// Returns the empty sentinel (`Vec::new()`) when the live certificate's signer
/// width does not match `committee_len` - i.e. the certificate was formed
/// against a different committee than the producer's snapshot. The empty
/// sentinel is rejected downstream by the `signer_bitmap.len() != committee.len()`
/// structural check in
/// [`crate::finalization::attestation::validate_consensus_metadata`], so a size
/// skew can never be silently accepted. Honest proposer/validator paths never
/// reach this branch: `committee_set_hash_v2` binds both to the same committee.
pub(crate) fn build_signer_bitmap_guarded(
    certificate: &HybridCertificate<MinSig>,
    committee_len: usize,
) -> Vec<u8> {
    if certificate.signers.len() != committee_len {
        return Vec::new();
    }
    build_signer_bitmap(certificate, committee_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_finalization_new() {
        assert_eq!(
            classify_finalization(101, B256::repeat_byte(0xBB), 100, B256::repeat_byte(0xAA)),
            ReplayClassification::New,
        );
    }

    #[test]
    fn classify_finalization_historical_replay() {
        assert_eq!(
            classify_finalization(50, B256::repeat_byte(0xBB), 100, B256::repeat_byte(0xAA)),
            ReplayClassification::HistoricalReplay,
        );
    }

    #[test]
    fn classify_finalization_duplicate_replay() {
        let hash = B256::repeat_byte(0xAA);
        assert_eq!(
            classify_finalization(100, hash, 100, hash),
            ReplayClassification::DuplicateReplay,
        );
    }

    #[test]
    fn classify_finalization_fatal_inconsistency() {
        assert_eq!(
            classify_finalization(100, B256::repeat_byte(0xBB), 100, B256::repeat_byte(0xAA)),
            ReplayClassification::FatalInconsistency,
        );
    }

    // the finalization actor's recovery loop calls `retry_with_backoff` per
    // cycle and, on exhaustion, records the stall metric and retries the NEXT
    // cycle instead of returning a node-fatal error (actor.rs `handle_finalized`).
    // The loop can only EXIT via `Ok(..) => process_finalization(..)`, so a
    // persistent failure can never return the fatal error - it parks and retries.
    // These tests pin the building block the loop depends on: exhaustion after
    // exactly `max_retries` and recovery when the resolver clears mid-cycle.

    #[test]
    fn retry_with_backoff_exhausts_after_max_retries_on_persistent_failure() {
        use commonware_runtime::Runner as _;
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };
        commonware_runtime::deterministic::Runner::timed(Duration::from_secs(600)).start(
            |context| async move {
                let calls = Arc::new(AtomicU32::new(0));
                let calls_resolver = calls.clone();
                let resolve = move || {
                    let calls = calls_resolver.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Err::<(), ()>(())
                    }
                };
                let failure = retry_with_backoff(
                    &context,
                    resolve,
                    3,
                    Duration::from_millis(50),
                    Duration::from_millis(100),
                )
                .await
                .expect_err("persistent failure must exhaust the retry budget");
                assert_eq!(failure.attempts, 3, "exactly max_retries attempts");
                assert_eq!(failure.last_kind, RetryFailureKind::Unavailable);
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    3,
                    "resolver invoked exactly max_retries times before Err"
                );
            },
        );
    }

    #[test]
    fn retry_with_backoff_recovers_when_resolver_succeeds_before_exhaustion() {
        use commonware_runtime::Runner as _;
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };
        commonware_runtime::deterministic::Runner::timed(Duration::from_secs(600)).start(
            |context| async move {
                // Fail the first two attempts, succeed on the third - models a
                // transient all-peers stall that clears mid-cycle: the loop
                // resolves and advances rather than staying parked.
                let calls = Arc::new(AtomicU32::new(0));
                let calls_resolver = calls.clone();
                let resolve = move || {
                    let calls = calls_resolver.clone();
                    async move {
                        let n = calls.fetch_add(1, Ordering::SeqCst);
                        if n < 2 {
                            Err::<u64, ()>(())
                        } else {
                            Ok(42)
                        }
                    }
                };
                let value = retry_with_backoff(
                    &context,
                    resolve,
                    5,
                    Duration::from_millis(50),
                    Duration::from_millis(100),
                )
                .await
                .expect("resolver recovering before the budget must yield Ok");
                assert_eq!(value, 42);
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    3,
                    "stopped retrying as soon as the resolver succeeded"
                );
            },
        );
    }
}
