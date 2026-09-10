//! Prometheus series for the node-side enclave channel, emitted through the
//! global `metrics` recorder (exposed by reth's `--metrics` exporter - same
//! pattern as `outbe-consensus`'s metrics module).

use std::time::Duration;

use metrics::{counter, gauge, histogram};

/// One attempt's round-trip duration, labelled by the request's stable
/// [`crate::protocol::EnclaveRequest::label`]. A retried request records two
/// samples - one per attempt.
pub(crate) fn record_request_duration(request: &'static str, duration: Duration) {
    histogram!("outbe_tee_request_duration_ms", "request" => request)
        .record(duration.as_secs_f64() * 1000.0);
}

/// One failed attempt, labelled by request and
/// [`crate::errors::TransportError::metric_class`].
pub(crate) fn record_request_error(request: &'static str, class: &'static str) {
    counter!("outbe_tee_request_errors_total", "request" => request, "class" => class).increment(1);
}

/// One reconnect attempt outcome: `ok` | `connect_failed` | `identity_mismatch`.
pub(crate) fn record_reconnect(result: &'static str) {
    counter!("outbe_tee_reconnect_total", "result" => result).increment(1);
}

/// The session generation (bumped on every successful reconnect); a step here
/// with no node restart marks an enclave-side restart or connection loss.
pub(crate) fn record_session_generation(generation: u64) {
    // u64 -> f64 is lossless for any realistic reconnect count (< 2^53).
    gauge!("outbe_tee_session_generation").set(generation as f64);
}
