//! Periodic TEE-enclave canary: a known-plaintext decrypt through the REAL
//! consensus path (`ProcessTributeOfferBatch`) plus the `Health` telemetry
//! probe, published to [`TeeEnclaveHealthChannel`] and Prometheus.
//!
//! Signal only - a failing canary never gates consensus participation; it
//! surfaces through `rudis_consensusStatus.enclave`, `outbe-cli monitor
//! readiness` and the `outbe_tee_canary_*` / `outbe_tee_heap_*` metric series.
//!
//! The probe uses a separate connection to the same pinned enclave identity;
//! it never holds the execution session's mutex. The blocking round-trip runs
//! on `spawn_blocking`; an `in_flight`
//! latch guarantees at most one outstanding probe, so a wedged enclave wedges
//! one canary task, never a growing pile of mutex waiters.
//! Shutdown stops observing the read-only probe without waiting for enclave I/O.
//! An already running socket operation retains its transport deadline; it cannot
//! start another request after cancellation or publish a late health result.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use alloy_primitives::{Address, U256};
use metrics::{counter, gauge, histogram};
use outbe_tee::canary::{TeeEnclaveHealthChannel, TeeEnclaveHealthSnapshot, TeeEnclaveHealthState};
use outbe_tee::errors::TransportError;
use outbe_tee::protocol::{
    inputs_canonical_hash, EnclaveHealthStatusV1, EnclaveRequest, EnclaveResponse,
    EncryptedTributeOffer, TributeOfferStatus, WorldwideDay,
};
use tokio_util::sync::CancellationToken;

/// Fixed canary identity: a marker owner address and a fixed worldwide day so
/// the payload (and its Poseidon `token_id`) is identical on every tick and
/// every validator. The offer is never submitted as a transaction - it exists
/// only inside the probe request.
const CANARY_OWNER: Address = Address::repeat_byte(0xCA);
const CANARY_DAY: u32 = 20250115;
const CANARY_EPH_SK: [u8; 32] = [0xC5; 32];
const CANARY_NONCE: [u8; 12] = [0xC6; 12];
const CANARY_PRICE_MINOR: u64 = 2_000_000;

/// How many consecutive skipped ticks (probe still in flight) before the
/// snapshot degrades to `Unavailable` ("probe stuck").
const STUCK_SKIPPED_TICKS: u64 = 2;

#[derive(Clone, Copy, Debug)]
pub struct TeeCanaryConfig {
    pub interval: Duration,
    /// Consecutive canary failures before `Degraded` (probe-unreachable is
    /// `Unavailable` immediately).
    pub failure_threshold: u64,
}

/// Injection seam over the process-global enclave session so unit tests run
/// against a scripted fake instead of the global.
pub trait EnclaveRequester: Send + Sync + 'static {
    fn request(&self, req: &EnclaveRequest) -> Result<EnclaveResponse, TransportError>;
    /// The pinned enclave attestation key; `None` when no session is installed.
    fn attestation_pub(&self) -> Option<[u8; 32]>;
}

/// The production requester uses the dedicated canary connection.
pub struct GlobalEnclaveRequester;

impl EnclaveRequester for GlobalEnclaveRequester {
    fn request(&self, req: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        outbe_tee::client_global::canary_request(req)
    }

    fn attestation_pub(&self) -> Option<[u8; 32]> {
        outbe_tee::client_global::canary_attestation_pub()
    }
}

/// Do not start the next phase of a probe after node shutdown. The in-progress
/// blocking socket operation still owns its connection until it returns.
struct ShutdownAwareRequester<R> {
    inner: R,
    shutdown: CancellationToken,
}

impl<R: EnclaveRequester> EnclaveRequester for ShutdownAwareRequester<R> {
    fn request(&self, req: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        if self.shutdown.is_cancelled() {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "canary stopped",
            )));
        }
        self.inner.request(req)
    }

    fn attestation_pub(&self) -> Option<[u8; 32]> {
        self.inner.attestation_pub()
    }
}

/// Outcome of one canary tick, input to the pure [`canary_state`] decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanaryTickOutcome {
    /// Canary decrypt round-tripped and validated.
    Success { latency_ms: u64 },
    /// The enclave answers but the permanent offer key is not resident yet
    /// (pre-DKG) - not a failure.
    OfferKeyNotReady,
    /// The probe failed. `unreachable` = transport-level (connect/socket/session
    /// revoked) as opposed to a bad answer.
    Failure { unreachable: bool, reason: String },
}

/// Pure state decision (ExecutionWatchdogDecision style): failures below the
/// threshold keep the previous state (grace); reaching it is `Degraded`;
/// transport-unreachable is `Unavailable` immediately.
pub fn canary_state(
    previous: TeeEnclaveHealthState,
    outcome: &CanaryTickOutcome,
    consecutive_failures: u64,
    failure_threshold: u64,
) -> TeeEnclaveHealthState {
    match outcome {
        CanaryTickOutcome::Success { .. } => TeeEnclaveHealthState::Ready,
        CanaryTickOutcome::OfferKeyNotReady => TeeEnclaveHealthState::Starting,
        CanaryTickOutcome::Failure {
            unreachable: true, ..
        } => TeeEnclaveHealthState::Unavailable,
        CanaryTickOutcome::Failure {
            unreachable: false, ..
        } => {
            if consecutive_failures >= failure_threshold {
                TeeEnclaveHealthState::Degraded
            } else if previous == TeeEnclaveHealthState::Disabled {
                TeeEnclaveHealthState::Starting
            } else {
                previous
            }
        }
    }
}

/// One blocking probe pass: Health (feature-detected), offer-key state, canary
/// decrypt. Pure with respect to the requester - unit-testable with a fake.
pub fn run_canary_probe(
    requester: &dyn EnclaveRequester,
    health_supported: Option<bool>,
) -> (
    CanaryTickOutcome,
    Option<bool>,
    Option<EnclaveHealthStatusV1>,
) {
    // 1. Health telemetry, unless feature detection already ruled it out. An
    //    old enclave binary kills the connection on the unknown variant, so a
    //    Health error alone is ambiguous - GetPublicKeys below disambiguates.
    let mut health_supported = health_supported;
    let mut health_payload = None;
    if health_supported != Some(false) {
        match requester.request(&EnclaveRequest::Health) {
            Ok(EnclaveResponse::HealthStatus { status }) => {
                health_supported = Some(true);
                health_payload = Some(*status);
            }
            Ok(_) | Err(_) if health_supported.is_none() => {
                // First attempt failed: decide via GetPublicKeys whether the
                // enclave is alive-but-old (=> unsupported, never retried) or
                // simply down (=> keep detecting next tick).
                if requester.request(&EnclaveRequest::GetPublicKeys).is_ok() {
                    health_supported = Some(false);
                }
            }
            Ok(_) | Err(_) => {}
        }
    }

    // 2. Offer-key state (fresh each tick, so key epochs are followed).
    let offer_pub = match requester.request(&EnclaveRequest::GetPublicKeys) {
        Ok(EnclaveResponse::PublicKeys {
            offer_key_ready,
            recipient_x25519_pub,
            ..
        }) => {
            if !offer_key_ready {
                return (
                    CanaryTickOutcome::OfferKeyNotReady,
                    health_supported,
                    health_payload,
                );
            }
            recipient_x25519_pub
        }
        Ok(other) => {
            return (
                CanaryTickOutcome::Failure {
                    unreachable: false,
                    reason: format!("unexpected GetPublicKeys response: {other:?}"),
                },
                health_supported,
                health_payload,
            );
        }
        Err(error) => {
            return (
                CanaryTickOutcome::Failure {
                    unreachable: error.is_connection_fault()
                        || matches!(
                            error,
                            TransportError::SessionRevoked(_) | TransportError::EnclaveError(_)
                        ),
                    reason: format!("GetPublicKeys failed: {}", error.metric_class()),
                },
                health_supported,
                health_payload,
            );
        }
    };

    // 3. Known-plaintext canary decrypt through the real consensus request.
    let plaintext = outbe_tee::offer_encrypt::canary_offer_json(CANARY_DAY);
    let cipher_text = match outbe_tee::offer_encrypt::encrypt_tribute_offer_with(
        &offer_pub,
        CANARY_EPH_SK,
        CANARY_NONCE,
        plaintext.as_bytes(),
    ) {
        Ok(cipher_text) => cipher_text,
        Err(reason) => {
            return (
                CanaryTickOutcome::Failure {
                    unreachable: false,
                    reason: format!("canary encryption failed: {reason}"),
                },
                health_supported,
                health_payload,
            );
        }
    };
    let eph_pub =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(CANARY_EPH_SK)).to_bytes();
    let offers = vec![EncryptedTributeOffer {
        owner: CANARY_OWNER,
        cipher_text,
        nonce: CANARY_NONCE.to_vec(),
        ephemeral_pubkey: U256::from_be_bytes(eph_pub),
        worldwide_day: WorldwideDay::new(CANARY_DAY),
        tribute_currency: 840,
        reference_currency: 840,
        exclude_from_intex_issuance: false,
        issuance_wwd_vwap_minor: U256::from(CANARY_PRICE_MINOR),
        reference_wwd_vwap_minor: U256::from(CANARY_PRICE_MINOR),
        reference_scurve_minor: U256::ZERO,
        zk_context: None,
    }];
    let started = SystemTime::now();
    let response = requester.request(&EnclaveRequest::ProcessTributeOfferBatch {
        offers: offers.clone(),
    });
    let latency_ms = SystemTime::now()
        .duration_since(started)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    let outcome = match response {
        Ok(EnclaveResponse::TributeOfferBatch {
            results,
            inputs_canonical_hash: reported_hash,
            attestation_tag,
        }) => validate_canary_batch(
            requester,
            &offers,
            &results,
            reported_hash,
            &attestation_tag,
            latency_ms,
        ),
        Ok(other) => CanaryTickOutcome::Failure {
            unreachable: false,
            reason: format!("unexpected canary response: {other:?}"),
        },
        Err(error) => CanaryTickOutcome::Failure {
            unreachable: error.is_connection_fault()
                || matches!(error, TransportError::SessionRevoked(_)),
            reason: format!("canary decrypt failed: {}", error.metric_class()),
        },
    };
    (outcome, health_supported, health_payload)
}

fn validate_canary_batch(
    requester: &dyn EnclaveRequester,
    offers: &[EncryptedTributeOffer],
    results: &[outbe_tee::protocol::TributeOfferResult],
    reported_hash: alloy_primitives::B256,
    attestation_tag: &[u8],
    latency_ms: u64,
) -> CanaryTickOutcome {
    let fail = |reason: String| CanaryTickOutcome::Failure {
        unreachable: false,
        reason,
    };
    if results.len() != 1 {
        return fail(format!("canary expected 1 result, got {}", results.len()));
    }
    let result = &results[0];
    if let TributeOfferStatus::Rejected { reason } = &result.status {
        return fail(format!("canary offer rejected: {reason}"));
    }
    if result.owner != CANARY_OWNER {
        return fail("canary result echoes a different owner".to_string());
    }
    if reported_hash != inputs_canonical_hash(offers) {
        return fail("canary inputs_canonical_hash mismatch (non-determinism)".to_string());
    }
    let Some(attestation_pub) = requester.attestation_pub() else {
        return fail("no pinned attestation key".to_string());
    };
    if let Err(error) = outbe_tee::verify_tribute_offer_attestation(
        &attestation_pub,
        reported_hash,
        results,
        attestation_tag,
    ) {
        return fail(format!("canary attestation tag invalid: {error}"));
    }
    CanaryTickOutcome::Success { latency_ms }
}

/// Fold one tick outcome into the published snapshot + metrics.
fn apply_tick(
    snapshot: &mut TeeEnclaveHealthSnapshot,
    outcome: CanaryTickOutcome,
    failure_threshold: u64,
) {
    match &outcome {
        CanaryTickOutcome::Success { latency_ms } => {
            snapshot.consecutive_failures = 0;
            snapshot.last_failure = None;
            snapshot.offer_key_ready = true;
            snapshot.last_canary_latency_ms = Some(*latency_ms);
            snapshot.last_ok_unix_ms = unix_now_ms();
            histogram!("outbe_tee_canary_latency_ms").record(*latency_ms as f64);
            if let Some(ms) = snapshot.last_ok_unix_ms {
                gauge!("outbe_tee_canary_last_ok_timestamp_seconds").set((ms / 1000) as f64);
            }
        }
        CanaryTickOutcome::OfferKeyNotReady => {
            snapshot.offer_key_ready = false;
        }
        CanaryTickOutcome::Failure { reason, .. } => {
            snapshot.consecutive_failures = snapshot.consecutive_failures.saturating_add(1);
            snapshot.last_failure = Some(reason.clone());
            counter!("outbe_tee_canary_failures_total").increment(1);
        }
    }
    snapshot.state = canary_state(
        snapshot.state,
        &outcome,
        snapshot.consecutive_failures,
        failure_threshold,
    );
    gauge!("outbe_tee_canary_consecutive_failures").set(snapshot.consecutive_failures as f64);
}

fn publish_health_gauges(status: &EnclaveHealthStatusV1) {
    gauge!("outbe_tee_heap_bytes", "kind" => "current").set(status.heap_current_bytes as f64);
    gauge!("outbe_tee_heap_bytes", "kind" => "peak").set(status.heap_peak_bytes as f64);
    gauge!("outbe_tee_enclave_uptime_seconds").set(status.uptime_s as f64);
    gauge!("outbe_tee_requests_errored_total").set(status.requests_errored as f64);
}

fn unix_now_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
}

/// Long-running canary loop; spawn with `tokio::spawn`, stop via `shutdown`.
pub async fn run_tee_canary_worker(
    requester: impl EnclaveRequester,
    config: TeeCanaryConfig,
    status: TeeEnclaveHealthChannel,
    shutdown: CancellationToken,
) {
    let requester = Arc::new(ShutdownAwareRequester {
        inner: requester,
        shutdown: shutdown.clone(),
    });
    let in_flight = Arc::new(AtomicBool::new(false));
    let mut interval = tokio::time::interval(config.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut snapshot = TeeEnclaveHealthSnapshot {
        state: TeeEnclaveHealthState::Starting,
        ..TeeEnclaveHealthSnapshot::default()
    };
    status.publish(snapshot.clone());
    let mut skipped_while_in_flight: u64 = 0;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {}
        }
        if in_flight.load(Ordering::Acquire) {
            // A previous probe is still blocked (wedged enclave holding the
            // session mutex). Never stack a second one; degrade by staleness.
            skipped_while_in_flight = skipped_while_in_flight.saturating_add(1);
            if skipped_while_in_flight >= STUCK_SKIPPED_TICKS {
                snapshot.state = TeeEnclaveHealthState::Unavailable;
                snapshot.last_failure = Some("canary probe stuck (enclave not answering)".into());
                status.publish(snapshot.clone());
            }
            continue;
        }
        skipped_while_in_flight = 0;
        let requester_for_probe = Arc::clone(&requester);
        let in_flight_guard = Arc::clone(&in_flight);
        in_flight.store(true, Ordering::Release);
        let health_supported = snapshot.health_probe_supported;
        let mut probe = tokio::task::spawn_blocking(move || {
            let result = run_canary_probe(requester_for_probe.as_ref(), health_supported);
            in_flight_guard.store(false, Ordering::Release);
            result
        });
        let result = tokio::select! {
            biased;
            result = &mut probe => result,
            _ = shutdown.cancelled() => {
                // Abort prevents a queued probe from starting, but cannot stop
                // a running blocking call. Never wait for that signal-only I/O
                // here: launcher return must be able to initiate Reth shutdown.
                probe.abort();
                tracing::debug!("TEE canary worker stopped with a probe in flight");
                break;
            }
        };
        match result {
            Ok((outcome, health_supported, health_payload)) => {
                snapshot.health_probe_supported = health_supported;
                if let Some(payload) = health_payload {
                    publish_health_gauges(&payload);
                    snapshot.enclave = Some(payload);
                }
                apply_tick(&mut snapshot, outcome, config.failure_threshold);
                status.publish(snapshot.clone());
            }
            Err(join_error) => {
                // The blocking probe panicked or was cancelled; the in_flight
                // latch may still be set - clear it so the canary keeps going.
                in_flight.store(false, Ordering::Release);
                snapshot.last_failure = Some(format!("canary probe task failed: {join_error}"));
                snapshot.consecutive_failures = snapshot.consecutive_failures.saturating_add(1);
                counter!("outbe_tee_canary_failures_total").increment(1);
                status.publish(snapshot.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test]
    async fn shutdown_does_not_wait_for_an_in_flight_canary_request() {
        struct BlockedRequester {
            entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
            finished: Option<tokio::sync::oneshot::Sender<()>>,
            calls: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl Drop for BlockedRequester {
            fn drop(&mut self) {
                if let Some(finished) = self.finished.take() {
                    let _ = finished.send(());
                }
            }
        }

        impl EnclaveRequester for BlockedRequester {
            fn request(&self, _: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(entered) = self.entered.lock().expect("entered lock").take() {
                    entered.send(()).expect("test awaits request entry");
                    self.release
                        .lock()
                        .expect("release lock")
                        .recv()
                        .expect("release request");
                }
                Err(TransportError::Io(std::io::Error::other(
                    "enclave unavailable",
                )))
            }

            fn attestation_pub(&self) -> Option<[u8; 32]> {
                None
            }
        }

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let status = TeeEnclaveHealthChannel::default();
        let shutdown = CancellationToken::new();
        let mut worker = tokio::spawn(run_tee_canary_worker(
            BlockedRequester {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(release_rx),
                finished: Some(finished_tx),
                calls: Arc::clone(&calls),
            },
            TeeCanaryConfig {
                interval: Duration::from_secs(60),
                failure_threshold: 3,
            },
            status.clone(),
            shutdown.clone(),
        ));
        entered_rx.await.expect("probe entered the transport");
        shutdown.cancel();
        let stopped = tokio::time::timeout(Duration::from_secs(1), &mut worker).await;

        // Always release the transport before asserting, including on the red
        // path: the test must not strand a Tokio blocking thread during teardown.
        release_tx.send(()).expect("release blocked transport");
        if stopped.is_err() {
            (&mut worker)
                .await
                .expect("worker eventually stops after I/O returns");
        }
        finished_rx
            .await
            .expect("blocking probe released its requester");
        assert!(
            stopped.is_ok(),
            "shutdown waited for the blocked canary transport"
        );
        stopped
            .expect("worker stopped")
            .expect("worker did not panic");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no next request after shutdown"
        );
        assert_eq!(
            status.snapshot().consecutive_failures,
            0,
            "no late health publication"
        );
        assert!(status.snapshot().last_failure.is_none());
    }

    #[tokio::test]
    async fn already_cancelled_worker_does_not_start_a_probe() {
        struct NeverCalled;

        impl EnclaveRequester for NeverCalled {
            fn request(&self, _: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
                panic!("cancelled worker started enclave I/O");
            }

            fn attestation_pub(&self) -> Option<[u8; 32]> {
                panic!("cancelled worker started a probe");
            }
        }

        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let status = TeeEnclaveHealthChannel::default();
        run_tee_canary_worker(
            NeverCalled,
            TeeCanaryConfig {
                interval: Duration::from_secs(60),
                failure_threshold: 3,
            },
            status.clone(),
            shutdown,
        )
        .await;
        assert!(
            status.snapshot().last_failure.is_none(),
            "probe panic was not hidden"
        );
    }

    struct FakeRequester {
        /// Scripted responses per request label, popped front-first.
        script: Mutex<Vec<(&'static str, Result<EnclaveResponse, TransportError>)>>,
        seen: Mutex<Vec<&'static str>>,
        attestation: Option<[u8; 32]>,
    }

    impl FakeRequester {
        fn new(script: Vec<(&'static str, Result<EnclaveResponse, TransportError>)>) -> Self {
            Self {
                script: Mutex::new(script),
                seen: Mutex::new(Vec::new()),
                attestation: Some([0xAA; 32]),
            }
        }

        fn seen(&self) -> Vec<&'static str> {
            match self.seen.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    impl EnclaveRequester for FakeRequester {
        fn request(&self, req: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
            let label = req.label();
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(label);
            }
            let mut script = match self.script.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if script.is_empty() {
                return Err(TransportError::EnclaveError("script exhausted".into()));
            }
            let (expected, response) = script.remove(0);
            assert_eq!(expected, label, "unexpected request order");
            response
        }

        fn attestation_pub(&self) -> Option<[u8; 32]> {
            self.attestation
        }
    }

    fn public_keys_response(offer_key_ready: bool) -> EnclaveResponse {
        EnclaveResponse::PublicKeys {
            offer_key_ready,
            recipient_x25519_pub: [0x0B; 32],
            attestation_pub: [0xAA; 32],
            noise_static_pub: [0x0C; 32],
            tee_bls_pub: Vec::new(),
            dkg_enc_pub: [0x0D; 32],
            dkg_enc_sig: Vec::new(),
        }
    }

    fn codec_error() -> TransportError {
        TransportError::Codec("unknown variant".into())
    }

    #[test]
    fn canary_state_decision_table() {
        use TeeEnclaveHealthState as S;
        let ok = CanaryTickOutcome::Success { latency_ms: 3 };
        let not_ready = CanaryTickOutcome::OfferKeyNotReady;
        let soft_fail = CanaryTickOutcome::Failure {
            unreachable: false,
            reason: "x".into(),
        };
        let dead = CanaryTickOutcome::Failure {
            unreachable: true,
            reason: "x".into(),
        };
        assert_eq!(canary_state(S::Starting, &ok, 0, 3), S::Ready);
        assert_eq!(canary_state(S::Ready, &not_ready, 0, 3), S::Starting);
        assert_eq!(canary_state(S::Ready, &soft_fail, 1, 3), S::Ready, "grace");
        assert_eq!(canary_state(S::Ready, &soft_fail, 3, 3), S::Degraded);
        assert_eq!(canary_state(S::Ready, &dead, 1, 3), S::Unavailable);
        assert_eq!(canary_state(S::Disabled, &soft_fail, 1, 3), S::Starting);
    }

    #[test]
    fn probe_reports_offer_key_not_ready_as_starting_input() {
        let fake = FakeRequester::new(vec![
            ("health", Err(codec_error())),
            ("get_public_keys", Ok(public_keys_response(false))),
            ("get_public_keys", Ok(public_keys_response(false))),
        ]);
        let (outcome, supported, _) = run_canary_probe(&fake, None);
        assert_eq!(outcome, CanaryTickOutcome::OfferKeyNotReady);
        assert_eq!(
            supported,
            Some(false),
            "enclave alive but Health unknown => unsupported"
        );
    }

    #[test]
    fn health_unsupported_detection_never_resends_health() {
        let fake = FakeRequester::new(vec![
            // No "health" entry: probing with Some(false) must skip it.
            ("get_public_keys", Ok(public_keys_response(false))),
        ]);
        let (outcome, supported, _) = run_canary_probe(&fake, Some(false));
        assert_eq!(outcome, CanaryTickOutcome::OfferKeyNotReady);
        assert_eq!(supported, Some(false));
        assert!(
            !fake.seen().contains(&"health"),
            "Health must not be re-sent once detected unsupported"
        );
    }

    #[test]
    fn health_down_enclave_keeps_feature_detection_open() {
        let fake = FakeRequester::new(vec![
            (
                "health",
                Err(TransportError::Io(std::io::Error::other("down"))),
            ),
            (
                "get_public_keys",
                Err(TransportError::Io(std::io::Error::other("down"))),
            ),
            (
                "get_public_keys",
                Err(TransportError::Io(std::io::Error::other("down"))),
            ),
        ]);
        let (outcome, supported, _) = run_canary_probe(&fake, None);
        assert!(matches!(
            outcome,
            CanaryTickOutcome::Failure {
                unreachable: true,
                ..
            }
        ));
        assert_eq!(supported, None, "down enclave: keep detecting next tick");
    }

    #[test]
    fn wrong_canonical_hash_is_a_failure() {
        let bad_batch = EnclaveResponse::TributeOfferBatch {
            results: vec![outbe_tee::protocol::TributeOfferResult {
                token_id: alloy_primitives::B256::repeat_byte(1),
                owner: CANARY_OWNER,
                issuance_amount_minor: U256::from(1u64),
                nominal_amount_minor: U256::from(1u64),
                effective_reference_price_minor: U256::from(CANARY_PRICE_MINOR),
                su_hashes: Vec::new(),
                wallet_addresses: Vec::new(),
                sra_addresses: Vec::new(),
                zk_expected_hashes: None,
                status: TributeOfferStatus::Created,
            }],
            inputs_canonical_hash: alloy_primitives::B256::repeat_byte(0xFF),
            attestation_tag: Vec::new(),
        };
        let fake = FakeRequester::new(vec![
            ("get_public_keys", Ok(public_keys_response(true))),
            ("process_tribute_offer_batch", Ok(bad_batch)),
        ]);
        let (outcome, _, _) = run_canary_probe(&fake, Some(false));
        match outcome {
            CanaryTickOutcome::Failure {
                unreachable,
                reason,
            } => {
                assert!(!unreachable);
                assert!(
                    reason.contains("inputs_canonical_hash"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected failure, got {other:?}"),
        }
    }
}
