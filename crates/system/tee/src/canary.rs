//! Shared status cell for the node's periodic enclave canary probe.
//!
//! The canary worker (in `outbe-node`) publishes snapshots; the RPC layer reads
//! them into `rudis_consensusStatus.enclave` and `outbe-cli monitor readiness`
//! consumes that. Signal only - nothing here gates consensus participation.

use std::sync::{Arc, RwLock};

use crate::protocol::EnclaveHealthStatusV1;

/// Canary-observed enclave health state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TeeEnclaveHealthState {
    /// The canary worker is not running (`--tee-canary.interval-secs 0`, or a
    /// consumer built without the channel).
    #[default]
    Disabled,
    /// The worker runs but has not yet observed a successful canary decrypt
    /// (startup, or the offer key is not yet resident - pre-DKG).
    Starting,
    /// The last canary decrypt succeeded.
    Ready,
    /// Consecutive canary failures at or above the configured threshold while
    /// the enclave still answers something.
    Degraded,
    /// The probe cannot reach the enclave at all (or an in-flight probe has
    /// been stuck past its deadline).
    Unavailable,
}

impl TeeEnclaveHealthState {
    /// Stable lowercase label used by the RPC surface and metrics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One published canary observation.
#[derive(Clone, Debug, Default)]
pub struct TeeEnclaveHealthSnapshot {
    pub state: TeeEnclaveHealthState,
    /// Unix milliseconds of the last successful canary decrypt.
    pub last_ok_unix_ms: Option<u64>,
    /// Round-trip of the last successful canary `ProcessTributeOfferBatch`.
    pub last_canary_latency_ms: Option<u64>,
    pub consecutive_failures: u64,
    /// Class/short description of the last failure (never key material).
    pub last_failure: Option<String>,
    pub offer_key_ready: bool,
    /// `None` until Health feature detection ran; `Some(false)` = the enclave
    /// binary predates `EnclaveRequest::Health` (canary-decrypt-only mode).
    pub health_probe_supported: Option<bool>,
    /// The last `Health` payload (uptime/heap/request counters), when supported.
    pub enclave: Option<EnclaveHealthStatusV1>,
}

/// Cloneable handle around the latest snapshot (single-writer canary worker,
/// many readers). Mirrors the radicle status-channel shape.
#[derive(Clone, Default)]
pub struct TeeEnclaveHealthChannel(Arc<RwLock<TeeEnclaveHealthSnapshot>>);

impl TeeEnclaveHealthChannel {
    /// A channel that permanently reports [`TeeEnclaveHealthState::Disabled`]
    /// (until some worker publishes into it).
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Read the latest snapshot. A poisoned lock (a reader/writer panicked)
    /// degrades to the poisoned value rather than propagating the panic -
    /// health reporting must never take the node down.
    pub fn snapshot(&self) -> TeeEnclaveHealthSnapshot {
        match self.0.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Publish a new snapshot (canary worker only).
    pub fn publish(&self, snapshot: TeeEnclaveHealthSnapshot) {
        match self.0.write() {
            Ok(mut guard) => *guard = snapshot,
            Err(poisoned) => *poisoned.into_inner() = snapshot,
        }
    }
}
