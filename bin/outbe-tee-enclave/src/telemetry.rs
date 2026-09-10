//! Enclave-side request telemetry: per-request stderr log lines, process-global
//! request counters, uptime, and heap accounting via a counting allocator.
//!
//! Everything here is observability only - no wire data, no key material, no
//! consensus input. Counters are relaxed atomics; exact cross-thread ordering
//! is not required. Timing uses `SystemTime` (the production-precedent clock
//! source under Gramine - see `set_remote_read_deadline`); a negative elapsed
//! from clock adjustment clamps to zero.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

/// Outcome of one dispatched request, for the log line and counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestOutcome {
    Ok,
    Err,
    Denied,
}

impl RequestOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Err => "err",
            Self::Denied => "denied",
        }
    }
}

/// Request class as counted by [`EnclaveHealthStatusV1`]'s fixed fields.
/// Mirrors the private `CommandClass` capability matrix in `initialization.rs`
/// (which stays the single authorization authority - this enum only names the
/// health-counter buckets).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestClassLabel {
    Initialized,
    FoundingKeyless,
    KeylessOnboarding,
    Ready,
    DevSourceSeal,
    DevRecipientIngest,
    Never,
}

static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUESTS_ERRORED: AtomicU64 = AtomicU64::new(0);
static REQUESTS_DENIED: AtomicU64 = AtomicU64::new(0);
static CLASS_INITIALIZED: AtomicU64 = AtomicU64::new(0);
static CLASS_FOUNDING_KEYLESS: AtomicU64 = AtomicU64::new(0);
static CLASS_KEYLESS_ONBOARDING: AtomicU64 = AtomicU64::new(0);
static CLASS_READY: AtomicU64 = AtomicU64::new(0);
static CLASS_DEV_SOURCE_SEAL: AtomicU64 = AtomicU64::new(0);
static CLASS_DEV_RECIPIENT_INGEST: AtomicU64 = AtomicU64::new(0);

static PROCESS_START: OnceLock<SystemTime> = OnceLock::new();

/// Record the process start time. Idempotent; the first call wins.
pub fn mark_process_start() {
    let _ = PROCESS_START.set(SystemTime::now());
}

/// Whole seconds since [`mark_process_start`]; 0 when never marked or when the
/// clock stepped backwards.
pub fn uptime_s() -> u64 {
    PROCESS_START
        .get()
        .and_then(|start| SystemTime::now().duration_since(*start).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bump the process-global request counters for one dispatched request.
pub fn record_request(class: RequestClassLabel, outcome: RequestOutcome) {
    REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    match outcome {
        RequestOutcome::Ok => {}
        RequestOutcome::Err => {
            REQUESTS_ERRORED.fetch_add(1, Ordering::Relaxed);
        }
        RequestOutcome::Denied => {
            REQUESTS_DENIED.fetch_add(1, Ordering::Relaxed);
        }
    }
    let class_counter = match class {
        RequestClassLabel::Initialized => &CLASS_INITIALIZED,
        RequestClassLabel::FoundingKeyless => &CLASS_FOUNDING_KEYLESS,
        RequestClassLabel::KeylessOnboarding => &CLASS_KEYLESS_ONBOARDING,
        RequestClassLabel::Ready => &CLASS_READY,
        RequestClassLabel::DevSourceSeal => &CLASS_DEV_SOURCE_SEAL,
        RequestClassLabel::DevRecipientIngest => &CLASS_DEV_RECIPIENT_INGEST,
        RequestClassLabel::Never => return,
    };
    class_counter.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of the request counters in [`EnclaveHealthStatusV1`] field order:
/// `(total, errored, denied, initialized, founding_keyless, keyless_onboarding,
/// ready, dev_source_seal, dev_recipient_ingest)`.
#[allow(clippy::type_complexity)]
pub fn counters_snapshot() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        REQUESTS_TOTAL.load(Ordering::Relaxed),
        REQUESTS_ERRORED.load(Ordering::Relaxed),
        REQUESTS_DENIED.load(Ordering::Relaxed),
        CLASS_INITIALIZED.load(Ordering::Relaxed),
        CLASS_FOUNDING_KEYLESS.load(Ordering::Relaxed),
        CLASS_KEYLESS_ONBOARDING.load(Ordering::Relaxed),
        CLASS_READY.load(Ordering::Relaxed),
        CLASS_DEV_SOURCE_SEAL.load(Ordering::Relaxed),
        CLASS_DEV_RECIPIENT_INGEST.load(Ordering::Relaxed),
    )
}

/// `(unix_now_seconds, elapsed_ms_since(started))`, both clamped to zero on a
/// backwards clock step.
pub fn now_unix_and_elapsed_ms(started: SystemTime) -> (u64, u64) {
    let now = SystemTime::now();
    let ts = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed_ms = now
        .duration_since(started)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0);
    (ts, elapsed_ms)
}

/// One stable, greppable stderr line per dispatched request. The `req=` prefix
/// is the grep anchor; values never contain spaces. Deliberately free of the
/// words the e2e log audit flags (`fatal`, `panic`).
pub fn format_request_log(
    ts_s: u64,
    label: &str,
    peer: &'static str,
    outcome: RequestOutcome,
    duration_ms: u64,
) -> String {
    format!(
        "outbe-tee-enclave: req={label} peer={peer} outcome={} dur_ms={duration_ms} ts={ts_s}",
        outcome.label()
    )
}

// --- Heap accounting -------------------------------------------------------

static HEAP_CURRENT: AtomicU64 = AtomicU64::new(0);
static HEAP_PEAK: AtomicU64 = AtomicU64::new(0);

/// `(current_bytes, peak_bytes)` as seen by [`CountingAllocator`]. Both zero
/// when the counting allocator is not installed (library/tests/benches).
pub fn heap_snapshot() -> (u64, u64) {
    (
        HEAP_CURRENT.load(Ordering::Relaxed),
        HEAP_PEAK.load(Ordering::Relaxed),
    )
}

fn heap_add(bytes: usize) {
    let new = HEAP_CURRENT.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
    // CAS-max: peak only moves up. Racy interleavings can miss a transient
    // maximum by a few allocations, which is fine for a growth/leak signal.
    let mut peak = HEAP_PEAK.load(Ordering::Relaxed);
    while new > peak {
        match HEAP_PEAK.compare_exchange_weak(peak, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

fn heap_sub(bytes: usize) {
    // Saturating: a dealloc raced against process start can otherwise wrap.
    // Nightly renames `fetch_update` to `try_update`; the replacement is not
    // on stable 1.96 yet, so silence the nightly-only deprecation until then.
    #[allow(deprecated)]
    let _ = HEAP_CURRENT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(bytes as u64))
    });
}

/// Global allocator wrapper that tracks current/peak heap bytes as a proxy for
/// EPC pressure (Gramine's procfs gives no trustworthy RSS from inside the
/// enclave). Installed via `#[global_allocator]` only in the binary roots
/// (`main.rs`, `mock_main.rs`) so library users, tests and benches are
/// unaffected. Blind spots: thread stacks (bounded by `sgx.max_threads`),
/// allocator overhead/fragmentation, and direct mmaps.
pub struct CountingAllocator;

// `GlobalAlloc` is an inherently `unsafe` trait - there is no safe way to
// provide a global allocator. This is the crate's documented exception to the
// no-unsafe rule: the impl delegates every allocation verbatim to `System`
// (upholding its contract unchanged) and only adds relaxed atomic bookkeeping,
// which cannot allocate or unwind.
#[allow(unsafe_code)]
// SAFETY: see above - pure delegation to `System` plus lock-free counters.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: caller upholds `GlobalAlloc::alloc`'s contract; forwarded as-is.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            heap_add(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: caller upholds `GlobalAlloc::dealloc`'s contract; forwarded as-is.
        unsafe { System.dealloc(ptr, layout) };
        heap_sub(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: caller upholds `GlobalAlloc::realloc`'s contract; forwarded as-is.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            heap_sub(layout.size());
            heap_add(new_size);
        }
        new_ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: caller upholds `GlobalAlloc::alloc_zeroed`'s contract; forwarded as-is.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            heap_add(layout.size());
        }
        ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_request_log_is_stable() {
        let line = format_request_log(
            1_755_861_234,
            "process_tribute_offer_batch",
            "local",
            RequestOutcome::Ok,
            3,
        );
        assert_eq!(
            line,
            "outbe-tee-enclave: req=process_tribute_offer_batch peer=local outcome=ok dur_ms=3 ts=1755861234"
        );
    }

    #[test]
    fn counters_accumulate_by_class_and_outcome() {
        let before = counters_snapshot();
        record_request(RequestClassLabel::Ready, RequestOutcome::Ok);
        record_request(RequestClassLabel::Ready, RequestOutcome::Err);
        record_request(RequestClassLabel::Initialized, RequestOutcome::Denied);
        record_request(RequestClassLabel::Never, RequestOutcome::Ok);
        let after = counters_snapshot();
        assert_eq!(after.0 - before.0, 4, "total counts every request");
        assert_eq!(after.1 - before.1, 1, "one errored");
        assert_eq!(after.2 - before.2, 1, "one denied");
        assert_eq!(after.3 - before.3, 1, "one initialized-class");
        assert_eq!(after.6 - before.6, 2, "two ready-class");
    }

    #[test]
    fn heap_accounting_tracks_current_and_peak() {
        let (current0, _) = heap_snapshot();
        heap_add(1024);
        let (current1, peak1) = heap_snapshot();
        assert_eq!(current1 - current0, 1024);
        assert!(peak1 >= current1);
        heap_sub(1024);
        let (current2, peak2) = heap_snapshot();
        assert_eq!(current2, current0);
        assert_eq!(peak2, peak1, "peak never decreases");
    }

    #[test]
    fn elapsed_clamps_and_uptime_defaults_to_zero_pre_mark() {
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        let (_, elapsed) = now_unix_and_elapsed_ms(future);
        assert_eq!(elapsed, 0, "backwards clock clamps to zero");
    }
}
