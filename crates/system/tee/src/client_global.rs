//! Process-global enclave client shared by every enclave-using module.
//!
//! Production installs an [`AuthorizedEnclaveClient`] after node-signed,
//! write-once initialization; the separate dev/mock path may install the development
//! [`EnclaveClient`]. Both expose only requests and the manifest/quote-bound
//! attestation key needed by runtime consumers. The offer-decrypt and key-delivery
//! paths reach the single connection through [`try_with_enclave`]. TEE transport
//! infrastructure lives here rather than in a business module.
//!
//! Determinism: the enclave returns byte-identical output across validators (same
//! resident keys), so routing a request through this global does not affect
//! consensus determinism. The call is a blocking UDS/TCP round-trip made straight
//! from the execution path; it never holds a `StorageHandle` across it and never
//! spawns a thread.

use std::sync::{Mutex, OnceLock};

use alloy_primitives::B256;

use crate::client::{AuthorizedEnclaveClient, EnclaveClient, GeneratedDcapQuoteV1};
use crate::dcap_protocol::{
    DcapOnboardingArtifactV1, DcapOnboardingContextV1, DcapOnboardingVerificationResultV1,
    DcapVerificationOutcomeV1,
};
use crate::errors::TransportError;
use crate::protocol::{EnclaveRequest, EnclaveResponse};
use crate::session::EnclaveSession;
use outbe_primitives::tee_attestation_v1::RegistrationIntentV1;

// Stored once in a process-global OnceLock<Mutex<_>> - a single instance for the
// node's lifetime, never passed by value in bulk, so boxing the larger variant
// would add indirection for no benefit.
#[allow(clippy::large_enum_variant)]
pub enum RuntimeEnclaveClient {
    Development(Box<EnclaveClient>),
    Production(AuthorizedEnclaveClient),
}

impl RuntimeEnclaveClient {
    pub fn request(&mut self, request: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        let label = request.label();
        let started = std::time::Instant::now();
        let result = match self {
            Self::Development(client) => client.request(request),
            Self::Production(client) => client.request(request),
        };
        // Per-attempt telemetry: a session-level retry records two samples.
        // Short-lived DKG/bootstrap/CLI clients report through the same series.
        crate::metrics::record_request_duration(label, started.elapsed());
        if let Err(error) = &result {
            crate::metrics::record_request_error(label, error.metric_class());
        }
        result
    }

    pub fn attestation_pub(&self) -> [u8; 32] {
        match self {
            Self::Development(client) => client.attestation_pub(),
            Self::Production(client) => client.attestation_pub(),
        }
    }
}

/// Install-time failure for the process-global enclave session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InstallError {
    #[error("enclave client already initialized")]
    AlreadyInitialized,
    #[error("enclave install probe failed: {0}")]
    Probe(#[from] TransportError),
}

/// Installed atomically so canary and execution always share the same pinned
/// identity, but never the same connection or lock.
pub(crate) struct EnclaveSessions {
    execution: Mutex<EnclaveSession>,
    canary: Mutex<EnclaveSession>,
    attestation_pub: [u8; 32],
}

impl EnclaveSessions {
    pub(crate) fn new(session: EnclaveSession) -> Self {
        Self {
            attestation_pub: session.attestation_pub(),
            canary: Mutex::new(session.fork_connection()),
            execution: Mutex::new(session),
        }
    }

    pub(crate) fn with_execution<R>(&self, f: impl FnOnce(&mut EnclaveSession) -> R) -> R {
        with_session(&self.execution, f)
    }

    pub(crate) fn canary_request(
        &self,
        request: &EnclaveRequest,
    ) -> Result<EnclaveResponse, TransportError> {
        if !matches!(
            request,
            EnclaveRequest::Health
                | EnclaveRequest::GetPublicKeys
                | EnclaveRequest::ProcessTributeOfferBatch { .. }
        ) {
            return Err(TransportError::EnclaveError(
                "request is not permitted on the canary connection".into(),
            ));
        }
        with_session(&self.canary, |session| session.request(request))
    }
}

static ENCLAVE_SESSION: OnceLock<EnclaveSessions> = OnceLock::new();

/// True once a process-global enclave session is installed.
pub fn is_enclave_configured() -> bool {
    ENCLAVE_SESSION.get().is_some()
}

/// Install the separate dev/mock client once. `endpoint` is retained so the
/// session can reconnect (with identity re-validation) after an enclave
/// sidecar restart.
pub fn install_enclave_client(client: EnclaveClient, endpoint: String) -> Result<(), InstallError> {
    let session = EnclaveSession::development(client, endpoint)?;
    ENCLAVE_SESSION
        .set(EnclaveSessions::new(session))
        .map_err(|_| InstallError::AlreadyInitialized)
}

/// Install a production NodeHost-authorized client once. Initialization and
/// manifest validation are completed by `AuthorizedEnclaveClient` before this;
/// `manifest` + `node_host` are the committed session material
/// (`committed_node_host_session_material`) the session reconnects with.
pub fn install_authorized_enclave_client(
    client: AuthorizedEnclaveClient,
    endpoint: String,
    node_data_dir: std::path::PathBuf,
    manifest: outbe_primitives::tee_attestation_v1::EnclaveInitializationManifestV1,
    node_host: crate::client::NodeHostNoiseKey,
) -> Result<(), InstallError> {
    let session = EnclaveSession::production(client, endpoint, node_data_dir, manifest, node_host)?;
    ENCLAVE_SESSION
        .set(EnclaveSessions::new(session))
        .map_err(|_| InstallError::AlreadyInitialized)
}

/// Run `f` against the process-global enclave session. Returns `None` ONLY when
/// no session is configured. A poisoned mutex is recovered: the interrupted
/// request's connection is dropped once and the next request reconnects cleanly
/// (poison no longer masquerades as "not configured").
///
/// TODO(tee-perf): every enclave call - consensus-path ops (gratis/promis,
/// begin-block sweeps, per-WWD snapshot batches) and read-only queries (e.g.
/// eth_call fidelity index with signed auth) - serializes on this single
/// Mutex-guarded blocking connection, and a request that times out (30s),
/// reconnects and retries can hold it for two timeout windows. A query storm on
/// an RPC node can stall block execution behind it. Future optimization: split
/// read-only traffic onto a separate enclave connection (or a small pool),
/// and/or rate-limit query-path calls so consensus-path requests never queue
/// behind them.
pub fn try_with_enclave<R>(f: impl FnOnce(&mut EnclaveSession) -> R) -> Option<R> {
    Some(ENCLAVE_SESSION.get()?.with_execution(f))
}

/// Run only the canary's existing read-only probes on its own authenticated
/// connection. No execution-session mutex is acquired, including reconnects.
pub fn canary_request(request: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
    ENCLAVE_SESSION
        .get()
        .ok_or_else(|| TransportError::EnclaveError("enclave session is not configured".into()))?
        .canary_request(request)
}

/// Read the install-time attestation pin without waiting for enclave I/O.
pub fn canary_attestation_pub() -> Option<[u8; 32]> {
    Some(ENCLAVE_SESSION.get()?.attestation_pub)
}

fn with_session<R>(mutex: &Mutex<EnclaveSession>, f: impl FnOnce(&mut EnclaveSession) -> R) -> R {
    let mut session = match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.recover_from_poison();
            guard
        }
    };
    f(&mut session)
}

/// Invoke the full verifier only through a production NodeHost-authorized
/// Gramine enclave. Missing/development clients are local fatal inputs to the
/// consensus caller, never deterministic evidence rejection.
pub fn verify_dcap_evidence_v1(
    evidence: &[u8],
    policy: &[u8],
    block_timestamp: u64,
) -> Result<DcapVerificationOutcomeV1, TransportError> {
    let Some(result) = try_with_enclave(|session| {
        session.verify_dcap_evidence_v1(evidence, policy, block_timestamp)
    }) else {
        return Err(TransportError::DcapVerification(
            "production enclave client is not configured".into(),
        ));
    };
    result
}

/// Generate one intent-bound quote through the already installed production
/// NodeHost session. The lifecycle worker cannot create a second enclave
/// identity or fall back to the development transport.
pub fn generate_dcap_quote_v1(
    intent: &RegistrationIntentV1,
) -> Result<GeneratedDcapQuoteV1, TransportError> {
    let Some(result) = try_with_enclave(|session| session.generate_dcap_quote(intent)) else {
        return Err(TransportError::Attestation(
            "production enclave client is not configured".into(),
        ));
    };
    result
}

/// Invoke the dedicated purpose-bound `RegisterEnclave` verifier and obtain
/// its deterministic one-time onboarding artifact from a production enclave.
#[allow(clippy::too_many_arguments)]
pub fn verify_dcap_registration_and_seal_v1(
    evidence: &[u8],
    policy: &[u8],
    block_timestamp: u64,
    node_signature: &[u8; 65],
    enclave_signature: &[u8; 64],
    expected_tribute_offer_public: [u8; 32],
    key_epoch: u64,
    tribute_offer_epoch: u64,
) -> Result<DcapOnboardingVerificationResultV1, TransportError> {
    let Some(result) = try_with_enclave(|session| {
        session.verify_dcap_registration_and_seal_v1(
            evidence,
            policy,
            block_timestamp,
            node_signature,
            enclave_signature,
            expected_tribute_offer_public,
            key_epoch,
            tribute_offer_epoch,
        )
    }) else {
        return Err(TransportError::DcapVerification(
            "production enclave client is not configured".into(),
        ));
    };
    result
}

pub fn prepare_gramine_direct_dev_onboarding_artifact_v1(
    context: DcapOnboardingContextV1,
) -> Result<DcapOnboardingArtifactV1, TransportError> {
    let Some(result) = try_with_enclave(|session| {
        session.prepare_gramine_direct_dev_onboarding_artifact_v1(context)
    }) else {
        return Err(TransportError::EnclaveError(
            "production enclave client is not configured".into(),
        ));
    };
    result
}

/// Read whether the permanent tribute-offer key is ready in the mandatory local
/// enclave. `None` is a fresh/keyless state, not a replacement or recovery path.
pub fn resident_offer_public_key_state_v1() -> Result<Option<B256>, TransportError> {
    let Some(result) = try_with_enclave(|session| session.request(&EnclaveRequest::GetPublicKeys))
    else {
        return Err(TransportError::EnclaveError(
            "mandatory enclave client is not configured".into(),
        ));
    };
    match result? {
        EnclaveResponse::PublicKeys {
            offer_key_ready,
            recipient_x25519_pub,
            ..
        } => {
            if !offer_key_ready {
                return Ok(None);
            }
            let public = B256::from(recipient_x25519_pub);
            if public.is_zero() {
                return Err(TransportError::EnclaveError(
                    "local enclave reports a ready but zero permanent offer key".into(),
                ));
            }
            Ok(Some(public))
        }
        EnclaveResponse::Error { message } => Err(TransportError::EnclaveError(message)),
        _ => Err(TransportError::UnexpectedResponse),
    }
}

/// Require the permanent tribute-offer key. A keyless enclave is fatal to an
/// existing identity and never triggers recovery, replacement, or fallback.
pub fn resident_offer_public_key_v1() -> Result<B256, TransportError> {
    resident_offer_public_key_state_v1()?.ok_or_else(|| {
        TransportError::EnclaveError(
            "local enclave permanent offer key is not ready; no recovery or fallback exists".into(),
        )
    })
}
