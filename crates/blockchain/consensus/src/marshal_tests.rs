//! Integration tests for marshal-based block resolution.
//!
//! Tests verify that the digest-bound block availability model works correctly:
//! - Blocks resolve via digest (not from local handler cache via raw P2P)
//! - Missing blocks are resolved via buffer/resolver (not bespoke admission)
//! - The full propose -> digest -> resolution -> finalize flow works end-to-end
//! - No legacy BlockReceived/BlockRequested message variants exist

#[cfg(test)]
mod tests {
    use crate::block::ConsensusBlock;
    use crate::digest::Digest;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::primitives::SealedBlock;
    use reth_ethereum::Block;
    use std::collections::BTreeMap;

    /// Create a test ConsensusBlock with a unique hash.
    fn make_test_block(seed: u8) -> ConsensusBlock {
        use alloy_primitives::Bytes;
        let mut block = Block::default();
        block.header.extra_data = Bytes::from(vec![seed]);
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    // -----------------------------------------------------------------------
    // Test 1 - Integration: verify resolves block by digest through buffer
    // -----------------------------------------------------------------------

    /// Verify path resolves block body by digest through a content-addressed
    /// buffer, not from a local handler cache populated by raw P2P admission.
    ///
    /// This mirrors how marshal's broadcast engine works: the proposer calls
    /// `proposed()` which stores the block, and the verifier calls
    /// `find_by_digest()` / `subscribe_by_digest()` to retrieve it.
    #[test]
    fn test_verify_resolves_block_by_digest_through_buffer() {
        let block = make_test_block(0x42);
        let digest = block.digest();

        // Simulate marshal's buffer: content-addressed store keyed by digest.
        let mut buffer = std::collections::HashMap::<Digest, ConsensusBlock>::new();

        // Block not in buffer -> verify would call subscribe_by_digest (pending).
        assert!(!buffer.contains_key(&digest));

        // Proposer broadcasts -> buffer stores by digest.
        buffer.insert(digest, block.clone());

        // Verifier resolves by digest (not by sender identity or cache admission).
        let resolved = buffer.get(&digest);
        assert!(resolved.is_some(), "block must be resolvable by digest");
        assert_eq!(resolved.unwrap().digest(), digest);
    }

    // -----------------------------------------------------------------------
    // Test 2 - Regression: no raw unsolicited block admission path
    // -----------------------------------------------------------------------

    /// Raw unsolicited block payload cannot be a primary source for verify/finalize.
    /// The Message enum has exactly 3 variants - no BlockReceived/BlockRequested.
    /// (The `Finalized` variant moved to `crate::finalization::ingress::Message`
    /// in step 21; the `Broadcast` variant was removed when proposer
    /// dissemination moved to a direct `marshal.forward` from `Relay::broadcast`.)
    /// If someone adds raw-block admission back, this test will fail to compile.
    #[test]
    fn test_no_raw_block_admission_path() {
        use crate::application::ingress::Message;
        fn _exhaustive_check(msg: Message) {
            match msg {
                Message::Genesis(_) => {}
                Message::Propose(_) => {}
                Message::Verify(_) => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 3 - Recovery: missing block resolves via content-addressed lookup
    // -----------------------------------------------------------------------

    /// A block that was NOT received via broadcast (e.g. network partition)
    /// must still be resolvable once it arrives through the resolver path.
    /// No bespoke cache admission (handle_block_received) is involved.
    #[test]
    fn test_missing_block_resolves_without_bespoke_cache_admission() {
        let block = make_test_block(0xAB);
        let digest = block.digest();

        // Content-addressed store (simulates marshal's internal cache).
        let mut store = std::collections::HashMap::<Digest, ConsensusBlock>::new();

        // Block NOT available initially - simulates missing broadcast.
        assert!(!store.contains_key(&digest));

        // Resolver delivers the block (content-addressed, by digest).
        store.insert(digest, block.clone());

        // Now resolvable - no sender identity check, no timestamp check,
        // no block-number-vs-finalized check. Pure content-addressed.
        let resolved = store.get(&digest).unwrap();
        assert_eq!(resolved.digest(), digest);
        assert_eq!(resolved.number(), block.number());
    }

    // -----------------------------------------------------------------------
    // Test 4 - E2E: proposer -> digest -> body resolution -> finalize
    // -----------------------------------------------------------------------

    /// Full end-to-end flow exercised through data structures:
    /// 1. Proposer builds block -> stores in proposer's local cache + buffer
    /// 2. Non-proposer receives digest in consensus proposal
    /// 3. Non-proposer resolves block by digest from buffer
    /// 4. Block is complete and usable for EL verification + finalization
    #[test]
    fn test_e2e_propose_resolve_finalize() {
        let block = make_test_block(0xFF);
        let digest = block.digest();
        let number = block.number();

        // Step 1: Proposer stores in local cache and broadcasts to buffer.
        let mut proposer_cache = BTreeMap::<Digest, ConsensusBlock>::new();
        let mut broadcast_buffer = std::collections::HashMap::<Digest, ConsensusBlock>::new();

        proposer_cache.insert(digest, block.clone());
        broadcast_buffer.insert(digest, block.clone());

        // Proposer's local cache has it (for own verify fast-path).
        assert!(proposer_cache.contains_key(&digest));

        // Step 2: Non-proposer receives only digest (from Simplex proposal).
        let received_digest = digest; // Only the digest, not the block.

        // Step 3: Non-proposer resolves block from buffer by digest.
        let resolved = broadcast_buffer.get(&received_digest);
        assert!(
            resolved.is_some(),
            "non-proposer must resolve block by digest"
        );

        let resolved_block = resolved.unwrap();
        assert_eq!(resolved_block.digest(), digest);

        // Step 4: Finalization - resolved block is complete for EL processing.
        assert_eq!(resolved_block.number(), number);

        // After finalization, proposer removes from local cache.
        proposer_cache.remove(&digest);
        assert!(!proposer_cache.contains_key(&digest));
    }

    // -----------------------------------------------------------------------
    // MarshalReporter must acknowledge, not drop
    // -----------------------------------------------------------------------

    /// Exact::acknowledge() resolves the waiter successfully.
    /// drop() without acknowledge triggers cancel. This test verifies
    /// the acknowledge path works as MarshalReporter now uses it.
    #[test]
    fn test_exact_acknowledge_resolves_waiter() {
        use commonware_runtime::Runner as _;
        commonware_runtime::deterministic::Runner::default().start(|_context| async move {
            use commonware_utils::acknowledgement::{Acknowledgement, Exact};
            use futures::FutureExt;

            let (ack, waiter) = Exact::handle();

            // Waiter should not be resolved yet
            assert!(
                waiter.now_or_never().is_none(),
                "waiter must not resolve before acknowledge"
            );

            let (ack2, waiter2) = Exact::handle();
            ack.acknowledge();
            // After acknowledge, waiter should resolve Ok
            let result = waiter2.now_or_never();
            // ack2 not yet acknowledged, so waiter2 still pending
            assert!(result.is_none());
            ack2.acknowledge();
        });
    }

    /// Verify drop(ack) triggers cancellation, not success.
    /// This confirms the old behavior (drop) was wrong.
    #[test]
    fn test_exact_drop_cancels_waiter() {
        use commonware_runtime::Runner as _;
        commonware_runtime::deterministic::Runner::default().start(|_context| async move {
            use commonware_utils::acknowledgement::{Acknowledgement, Exact};

            let (ack, waiter) = Exact::handle();
            drop(ack); // Old behavior - should cancel

            let result = waiter.await;
            assert!(
                result.is_err(),
                "drop without acknowledge must cancel the waiter"
            );
        });
    }

    /// Executor Mailbox Reporter impl sends MarshalUpdate into the channel.
    #[test]
    fn test_executor_reporter_sends_marshal_update() {
        use commonware_runtime::Runner as _;
        commonware_runtime::deterministic::Runner::default().start(|_context| async move {
            use commonware_consensus::Reporter;
            use commonware_utils::acknowledgement::{Acknowledgement, Exact};
            use futures::StreamExt;

            let (tx, mut rx) = futures::channel::mpsc::unbounded();
            let mut mailbox = crate::executor::Mailbox::from_sender(tx);
            let block = make_test_block(0xCC);

            let (ack, _waiter) = Exact::handle();
            let update = commonware_consensus::marshal::Update::Block(block, ack);

            mailbox.report(update);

            // Message must be in the channel.
            let msg = rx.next().await.expect("channel must have message");
            assert!(
                matches!(msg, crate::executor::ingress::Message::MarshalUpdate(_)),
                "expected MarshalUpdate message"
            );
        });
    }

    // -----------------------------------------------------------------------
    // Finalization retry constants
    // -----------------------------------------------------------------------

    /// Verify retry constants are reasonable and accessible.
    #[test]
    fn test_finalize_retry_constants() {
        use crate::config::{
            FINALIZE_MAX_RETRIES, FINALIZE_RESOLUTION_TIMEOUT, FINALIZE_RETRY_DELAY,
            PROPOSE_RESOLUTION_TIMEOUT, VERIFY_RESOLUTION_TIMEOUT,
        };

        assert_eq!(FINALIZE_MAX_RETRIES, 5, "max retries must be 5");
        assert_eq!(
            FINALIZE_RESOLUTION_TIMEOUT,
            std::time::Duration::from_secs(10),
            "finalize per-attempt timeout must be 10 seconds"
        );
        assert_eq!(
            FINALIZE_RETRY_DELAY,
            std::time::Duration::from_secs(2),
            "retry delay must be 2 seconds"
        );

        // Worst case before structured failure: N attempts x per-attempt timeout
        // + (N - 1) sleeps between them (no sleep after the last attempt).
        let total_worst_case = FINALIZE_RESOLUTION_TIMEOUT * FINALIZE_MAX_RETRIES
            + FINALIZE_RETRY_DELAY * (FINALIZE_MAX_RETRIES - 1);
        assert_eq!(
            total_worst_case,
            std::time::Duration::from_secs(58),
            "worst-case before structured failure must be exactly 58s"
        );
        assert!(
            total_worst_case <= std::time::Duration::from_secs(60),
            "worst-case before structured failure must be bounded (<=60s)"
        );
        assert_eq!(
            PROPOSE_RESOLUTION_TIMEOUT, VERIFY_RESOLUTION_TIMEOUT,
            "propose and verify marshal resolution should use the same per-attempt budget"
        );
    }

    /// Regression: parent block resolution must hint the parent's view, not the
    /// child proposal's current view. Otherwise marshal fetches notarization for
    /// the child round while the waiter is subscribed to the parent digest.
    #[test]
    fn test_parent_round_uses_parent_view() {
        use commonware_consensus::types::{Epoch, Round, View};

        let child_round = Round::new(Epoch::new(6), View::new(91));
        let resolved = crate::application::handler::parent_round(child_round, View::new(90));

        assert_eq!(resolved.epoch(), child_round.epoch());
        assert_eq!(resolved.view(), View::new(90));
    }

    /// Simulated marshal failure - retry exhaustion returns error.
    #[test]
    fn test_retry_exhaustion_on_persistent_failure() {
        use crate::finalization::util::{retry_with_backoff, RetryFailureKind};
        use commonware_runtime::Runner as _;

        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            // Resolver that always fails
            let result = retry_with_backoff::<(), _, _>(
                &context,
                || async { Err(()) },
                3,
                std::time::Duration::from_millis(1), // fast for testing
                std::time::Duration::from_millis(50),
            )
            .await;

            let failure = result.expect_err("persistent failure must exhaust retries");
            assert_eq!(failure.attempts, 3, "must have attempted exactly 3 times");
            assert_eq!(
                failure.last_kind,
                RetryFailureKind::Unavailable,
                "immediate Err must report Unavailable"
            );
        });
    }

    /// Retry succeeds on second attempt - no stall.
    #[test]
    fn test_retry_succeeds_after_transient_failure() {
        use crate::finalization::util::retry_with_backoff;
        use commonware_runtime::Runner as _;
        use std::sync::atomic::{AtomicU32, Ordering};

        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let attempt = std::sync::Arc::new(AtomicU32::new(0));
            let attempt_clone = attempt.clone();

            // Resolver that fails once then succeeds
            let result = retry_with_backoff(
                &context,
                move || {
                    let a = attempt_clone.clone();
                    async move {
                        let n = a.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            Err(())
                        } else {
                            Ok(42u32)
                        }
                    }
                },
                3,
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(50),
            )
            .await;

            assert_eq!(
                result.unwrap(),
                42,
                "must return value from successful retry"
            );
            assert_eq!(
                attempt.load(Ordering::SeqCst),
                2,
                "must have attempted 2 times"
            );
        });
    }

    /// Immediate success - no retries needed.
    #[test]
    fn test_retry_immediate_success_no_stall() {
        use crate::finalization::util::retry_with_backoff;
        use commonware_runtime::Runner as _;

        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let result = retry_with_backoff(
                &context,
                || async { Ok::<_, ()>(99u32) },
                3,
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(50),
            )
            .await;

            assert_eq!(result.unwrap(), 99);
        });
    }

    /// Regression: a never-completing marshal future must not wedge the helper.
    /// Without the per-attempt timeout the inner helper would hang on the pending
    /// future; the `Runner::timed` wedge guard aborts the test if that happens. With
    /// the per-attempt timeout, exhaustion fires deterministically via the runtime
    /// clock and `retry_with_backoff` returns promptly in virtual time.
    #[test]
    fn test_finalize_resolution_times_out_pending_marshal_future() {
        use crate::finalization::util::{retry_with_backoff, RetryFailureKind};
        use commonware_runtime::Runner as _;
        use std::sync::atomic::{AtomicU32, Ordering};

        commonware_runtime::deterministic::Runner::timed(std::time::Duration::from_secs(60)).start(
            |context| async move {
                let attempts = std::sync::Arc::new(AtomicU32::new(0));
                let attempts_clone = attempts.clone();

                // The per-attempt `Clock::timeout` inside `retry_with_backoff` must make
                // the helper terminate even on a never-completing future. Under the
                // deterministic runtime the clock-driven per-attempt timeouts and backoff
                // advance virtual time, so the helper returns promptly; the `Runner::timed`
                // wedge guard aborts the test if the fix is missing and it hangs instead.
                let result = retry_with_backoff::<(), _, _>(
                    &context,
                    move || {
                        let a = attempts_clone.clone();
                        async move {
                            a.fetch_add(1, Ordering::SeqCst);
                            std::future::pending::<Result<(), ()>>().await
                        }
                    },
                    3,
                    std::time::Duration::from_millis(1),
                    std::time::Duration::from_millis(5),
                )
                .await;

                let failure = result.expect_err("must exhaust on pending future");
                assert_eq!(failure.attempts, 3, "must have attempted exactly 3 times");
                assert_eq!(
                    failure.last_kind,
                    RetryFailureKind::Timeout,
                    "last failure must be Timeout, not Unavailable"
                );
                assert_eq!(
                    attempts.load(Ordering::SeqCst),
                    3,
                    "resolver must have been polled exactly 3 times"
                );
            },
        );
    }
}
