//! Process-global enclave session: the reconnect-capable wrapper around the
//! pinned [`RuntimeEnclaveClient`].
//!
//! The node installs one session at startup. When a request fails with a
//! connection-class fault ([`TransportError::is_connection_fault`]) the session
//! performs ONE bounded reconnect with identity re-validation and re-sends the
//! request once - only when [`EnclaveRequest::is_idempotent`] allows it. A
//! reconnected peer must present the byte-identical identity that was pinned at
//! install; any mismatch permanently revokes the session (fail-closed), because
//! every later attestation-tag check would otherwise validate against the
//! impostor's own key.
//!
//! Locking stays with the caller ([`crate::client_global::try_with_enclave`]):
//! the session is single-threaded under that mutex, so a reconnect can never
//! interleave with another caller's request.

use std::path::PathBuf;
use std::time::Instant;

use alloy_primitives::B256;

use crate::client::NodeHostNoiseKey;
use crate::client::{AuthorizedEnclaveClient, EnclaveClient, GeneratedDcapQuoteV1};
use crate::client_global::RuntimeEnclaveClient;
use crate::dcap_protocol::{
    DcapOnboardingArtifactV1, DcapOnboardingContextV1, DcapOnboardingVerificationResultV1,
    DcapVerificationOutcomeV1,
};
use crate::errors::TransportError;
use crate::protocol::{EnclaveRequest, EnclaveResponse};
use outbe_primitives::tee_attestation_v1::{EnclaveInitializationManifestV1, RegistrationIntentV1};

/// Identity pinned from a development client's structurally validated quote at
/// install time; a reconnected peer must match every field byte-for-byte.
#[derive(Clone, Debug)]
struct DevPinnedIdentity {
    mrenclave: B256,
    mrsigner: B256,
    isv_svn: u16,
    attestation_pub: [u8; 32],
    attestation_label: String,
    noise_static_pub: [u8; 32],
}

impl DevPinnedIdentity {
    fn pin(client: &EnclaveClient) -> Self {
        let (mrenclave, mrsigner, isv_svn) = client.measurements();
        Self {
            mrenclave,
            mrsigner,
            isv_svn,
            attestation_pub: client.attestation_pub(),
            attestation_label: client.attestation_label().to_string(),
            noise_static_pub: client.noise_static_pub(),
        }
    }

    /// Exact-equality identity check (including the attestation label, so a
    /// `dcap` peer can never be replaced by a `none` peer).
    fn matches(&self, client: &EnclaveClient) -> Result<(), String> {
        let (mrenclave, mrsigner, isv_svn) = client.measurements();
        if (mrenclave, mrsigner, isv_svn) != (self.mrenclave, self.mrsigner, self.isv_svn) {
            return Err("enclave measurements changed across reconnect".into());
        }
        if client.attestation_pub() != self.attestation_pub {
            return Err("enclave attestation key changed across reconnect".into());
        }
        if client.noise_static_pub() != self.noise_static_pub {
            return Err("enclave Noise static key changed across reconnect".into());
        }
        if client.attestation_label() != self.attestation_label {
            return Err("enclave attestation environment changed across reconnect".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
enum SessionContext {
    Development {
        endpoint: String,
        pinned: DevPinnedIdentity,
    },
    Production {
        endpoint: String,
        /// Retained for operator diagnostics; reconnect deliberately does NOT
        /// re-read NodeHost state (see `committed_node_host_session_material`).
        #[allow(dead_code)]
        node_data_dir: PathBuf,
        manifest: EnclaveInitializationManifestV1,
        node_host: NodeHostNoiseKey,
    },
}

/// The process-global enclave session (see module docs).
pub struct EnclaveSession {
    /// `None` = disconnected; the next request forces a clean reconnect.
    client: Option<RuntimeEnclaveClient>,
    context: SessionContext,
    /// The resident permanent offer public key observed most recently. `None`
    /// until the enclave reports `offer_key_ready` (legal pre-DKG state).
    pinned_offer_public: Option<B256>,
    /// Bumped on every successful reconnect. Generation 1 is the installed
    /// connection.
    generation: u64,
    /// A permanently revoked session refuses every request (fail-closed).
    revoked: Option<&'static str>,
    /// First-poison latch: recovery from a poisoned mutex drops the client
    /// exactly once (the interrupted request left the Noise state unknown).
    poison_recovered: bool,
}

impl EnclaveSession {
    /// Open a separate connection on first use, retaining the installed identity
    /// and credentials. Never clone live Noise state or reconnect under the
    /// execution session's mutex.
    pub(crate) fn fork_connection(&self) -> Self {
        Self {
            client: None,
            context: self.context.clone(),
            pinned_offer_public: self.pinned_offer_public,
            generation: 0,
            revoked: self.revoked,
            poison_recovered: false,
        }
    }

    /// Wrap an installed development client. Probes `GetPublicKeys` once to pin
    /// the resident offer key state.
    pub fn development(client: EnclaveClient, endpoint: String) -> Result<Self, TransportError> {
        let pinned = DevPinnedIdentity::pin(&client);
        let mut client = RuntimeEnclaveClient::Development(Box::new(client));
        let pinned_offer_public = probe_offer_key(&mut client)?;
        Ok(Self {
            client: Some(client),
            context: SessionContext::Development { endpoint, pinned },
            pinned_offer_public,
            generation: 1,
            revoked: None,
            poison_recovered: false,
        })
    }

    /// Wrap an installed production client together with the committed session
    /// material loaded once at startup (`committed_node_host_session_material`).
    pub fn production(
        client: AuthorizedEnclaveClient,
        endpoint: String,
        node_data_dir: PathBuf,
        manifest: EnclaveInitializationManifestV1,
        node_host: NodeHostNoiseKey,
    ) -> Result<Self, TransportError> {
        let mut client = RuntimeEnclaveClient::Production(client);
        let pinned_offer_public = probe_offer_key(&mut client)?;
        Ok(Self {
            client: Some(client),
            context: SessionContext::Production {
                endpoint,
                node_data_dir,
                manifest,
                node_host,
            },
            pinned_offer_public,
            generation: 1,
            revoked: None,
            poison_recovered: false,
        })
    }

    /// The pinned enclave attestation key. Sourced from install-time identity
    /// (dev: quote pin; production: committed manifest), NOT from the live
    /// connection - so post-reconnect attestation-tag checks verify against the
    /// identity the operator installed, not whatever peer answered last.
    pub fn attestation_pub(&self) -> [u8; 32] {
        match &self.context {
            SessionContext::Development { pinned, .. } => pinned.attestation_pub,
            SessionContext::Production { manifest, .. } => manifest.attestation_ed25519,
        }
    }

    /// Current session generation (1 = the installed connection).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// True once poison recovery ran (see [`Self::recover_from_poison`]).
    pub fn poison_recovered(&self) -> bool {
        self.poison_recovered
    }

    /// Recover after a caller panicked while holding the session mutex: the
    /// interrupted request left the Noise cipher state unknown, so drop the
    /// client and force a clean reconnect on next use. Latched - later lock
    /// acquisitions must not tear down a healthy reconnected client.
    pub fn recover_from_poison(&mut self) {
        if !self.poison_recovered {
            self.poison_recovered = true;
            self.client = None;
        }
    }

    /// Send one request with the session's reconnect-and-retry-once policy.
    pub fn request(&mut self, req: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        if matches!(
            req,
            EnclaveRequest::BeginDcapVerificationV1 { .. }
                | EnclaveRequest::BeginDcapOnboardingVerificationV1 { .. }
                | EnclaveRequest::DcapVerificationChunkV1 { .. }
                | EnclaveRequest::FinishDcapVerificationV1 { .. }
                | EnclaveRequest::BeginDcapOnboardingArtifactIngestV1 { .. }
                | EnclaveRequest::DcapOnboardingArtifactChunkV1 { .. }
                | EnclaveRequest::CommitDcapOnboardingArtifactRecordV1 { .. }
                | EnclaveRequest::FinishDcapOnboardingArtifactIngestV1 { .. }
        ) {
            return Err(TransportError::DcapVerification(
                "multi-frame enclave requests must use a whole-operation session API".into(),
            ));
        }
        if let Some(reason) = self.revoked {
            return Err(TransportError::SessionRevoked(reason));
        }
        if self.client.is_none() {
            self.reconnect()?;
        }
        let Some(client) = self.client.as_mut() else {
            // Unreachable in practice (reconnect either installs a client or
            // errors), kept as a structured error per the no-panic rule.
            return Err(TransportError::EnclaveError(
                "enclave session has no connection after reconnect".into(),
            ));
        };
        let first = client.request(req);
        let first_err = match first {
            Ok(response) => return Ok(response),
            Err(error) if !error.is_connection_fault() => return Err(error),
            Err(error) => error,
        };
        self.client = None;
        self.reconnect()?;
        if !req.is_idempotent() {
            // The session is healed for the next caller, but this request may
            // already have executed inside the enclave - surface the original
            // fault instead of risking a double apply.
            return Err(first_err);
        }
        match self.client.as_mut() {
            Some(client) => client.request(req),
            None => Err(TransportError::EnclaveError(
                "enclave session has no connection after reconnect".into(),
            )),
        }
    }

    /// Whole-operation wrapper for the production-only DCAP flows: run the
    /// operation once; on a connection fault reconnect once and rerun the WHOLE
    /// operation (a multi-frame upload restarts from `Begin` on the fresh
    /// session - the enclave keys upload state per connection).
    fn with_production_retry<T>(
        &mut self,
        op_label: &'static str,
        dev_rejection: impl Fn() -> TransportError,
        op: impl Fn(&mut AuthorizedEnclaveClient) -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        if let Some(reason) = self.revoked {
            return Err(TransportError::SessionRevoked(reason));
        }
        if self.client.is_none() {
            self.reconnect()?;
        }
        let started = Instant::now();
        let first = match self.client.as_mut() {
            Some(RuntimeEnclaveClient::Production(client)) => op(client),
            Some(RuntimeEnclaveClient::Development(_)) => return Err(dev_rejection()),
            None => {
                return Err(TransportError::EnclaveError(
                    "enclave session has no connection after reconnect".into(),
                ));
            }
        };
        let result = match first {
            Err(error) if error.is_connection_fault() => {
                self.client = None;
                self.reconnect()?;
                match self.client.as_mut() {
                    Some(RuntimeEnclaveClient::Production(client)) => op(client),
                    _ => Err(error),
                }
            }
            other => other,
        };
        crate::metrics::record_request_duration(op_label, started.elapsed());
        if let Err(error) = &result {
            crate::metrics::record_request_error(op_label, error.metric_class());
        }
        result
    }

    /// Production-only: verify DCAP evidence (whole-operation retry). The
    /// development rejection mirrors the pre-session behavior verbatim.
    pub fn verify_dcap_evidence_v1(
        &mut self,
        evidence: &[u8],
        policy: &[u8],
        block_timestamp: u64,
    ) -> Result<DcapVerificationOutcomeV1, TransportError> {
        self.with_production_retry(
            "verify_dcap_evidence_v1",
            || {
                TransportError::DcapVerification(
                    "development enclave client cannot verify consensus DCAP evidence".into(),
                )
            },
            |client| client.verify_dcap_evidence_v1(evidence, policy, block_timestamp),
        )
    }

    /// Production-only: `RegisterEnclave` verify-and-seal (whole-operation retry).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_dcap_registration_and_seal_v1(
        &mut self,
        evidence: &[u8],
        policy: &[u8],
        block_timestamp: u64,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        expected_tribute_offer_public: [u8; 32],
        key_epoch: u64,
        tribute_offer_epoch: u64,
    ) -> Result<DcapOnboardingVerificationResultV1, TransportError> {
        self.with_production_retry(
            "verify_dcap_registration_and_seal_v1",
            || {
                TransportError::DcapVerification(
                    "development enclave client cannot issue DCAP onboarding artifacts".into(),
                )
            },
            |client| {
                client.verify_dcap_registration_and_seal_v1(
                    evidence,
                    policy,
                    block_timestamp,
                    node_signature,
                    enclave_signature,
                    expected_tribute_offer_public,
                    key_epoch,
                    tribute_offer_epoch,
                )
            },
        )
    }

    pub fn prepare_gramine_direct_dev_onboarding_artifact_v1(
        &mut self,
        context: DcapOnboardingContextV1,
    ) -> Result<DcapOnboardingArtifactV1, TransportError> {
        self.with_production_retry(
            "prepare_gramine_direct_dev_onboarding_artifact_v1",
            || {
                TransportError::EnclaveError(
                    "development enclave client cannot issue DirectDev onboarding artifacts".into(),
                )
            },
            |client| client.prepare_gramine_direct_dev_onboarding_artifact_v1(context),
        )
    }

    /// Production-only: intent-bound quote generation (whole-operation retry).
    pub fn generate_dcap_quote(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<GeneratedDcapQuoteV1, TransportError> {
        self.with_production_retry(
            "generate_dcap_quote",
            || {
                TransportError::Attestation(
                    "development enclave client cannot generate production renewal quotes".into(),
                )
            },
            |client| client.generate_dcap_quote(intent),
        )
    }

    /// One bounded reconnect: fresh transport, identity re-validation, offer-key
    /// pin check. Success installs the client and bumps the generation; an
    /// identity or offer-key mismatch revokes the session permanently.
    fn reconnect(&mut self) -> Result<(), TransportError> {
        if let Some(reason) = self.revoked {
            return Err(TransportError::SessionRevoked(reason));
        }
        // Drop any broken half-session first so its socket closes.
        self.client = None;
        let mut client = match &self.context {
            SessionContext::Development { endpoint, pinned } => {
                let client = match EnclaveClient::connect_endpoint(endpoint) {
                    Ok(client) => client,
                    Err(error) => {
                        crate::metrics::record_reconnect("connect_failed");
                        return Err(error);
                    }
                };
                if let Err(mismatch) = pinned.matches(&client) {
                    crate::metrics::record_reconnect("identity_mismatch");
                    return Err(self.revoke("enclave identity changed across reconnect", mismatch));
                }
                RuntimeEnclaveClient::Development(Box::new(client))
            }
            SessionContext::Production {
                endpoint,
                manifest,
                node_host,
                ..
            } => {
                // Noise-IK against `manifest.noise_responder_x25519` IS the
                // identity check: an impostor can never complete the handshake.
                // Handshake failure therefore stays retryable (connect_failed),
                // never a revocation - a legitimately replaced enclave keeps
                // failing here until the operator restarts the node, which the
                // replacement flow already requires.
                match AuthorizedEnclaveClient::connect_endpoint(endpoint, manifest, node_host) {
                    Ok(client) => RuntimeEnclaveClient::Production(client),
                    Err(error) => {
                        crate::metrics::record_reconnect("connect_failed");
                        return Err(error);
                    }
                }
            }
        };
        // Offer-key pin: the resident permanent key must never change or
        // disappear across a reconnect; appearing (pre-DKG -> post-DKG) is the
        // one legal upgrade.
        let fresh = match probe_offer_key(&mut client) {
            Ok(fresh) => fresh,
            Err(error) => {
                crate::metrics::record_reconnect("connect_failed");
                return Err(error);
            }
        };
        match (self.pinned_offer_public, fresh) {
            (Some(pinned), Some(observed)) if pinned == observed => {}
            (None, observed) => self.pinned_offer_public = observed,
            (Some(pinned), observed) => {
                crate::metrics::record_reconnect("identity_mismatch");
                return Err(self.revoke(
                    "resident offer key changed across reconnect",
                    format!("pinned {pinned}, reconnected enclave reports {observed:?}"),
                ));
            }
        }
        self.client = Some(client);
        self.generation += 1;
        crate::metrics::record_reconnect("ok");
        crate::metrics::record_session_generation(self.generation);
        Ok(())
    }

    fn revoke(&mut self, reason: &'static str, detail: String) -> TransportError {
        self.revoked = Some(reason);
        self.client = None;
        TransportError::IdentityMismatch(format!("{reason}: {detail}"))
    }
}

/// `GetPublicKeys` probe shared by install and reconnect: `Ok(None)` is the
/// legal keyless (pre-DKG) state; a ready-but-zero key is an enclave fault.
fn probe_offer_key(client: &mut RuntimeEnclaveClient) -> Result<Option<B256>, TransportError> {
    match client.request(&EnclaveRequest::GetPublicKeys)? {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_request, encode_response};
    use crate::codec::{read_frame, write_frame};
    use alloy_primitives::keccak256;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    /// Scriptable fake dev enclave: real cleartext-quote + Noise-IK responder
    /// wire, per-connection behavior driven by [`ServerScript`].
    struct FakeEnclave {
        noise_private: Vec<u8>,
        noise_public: [u8; 32],
        recipient: [u8; 32],
        attestation_pub: [u8; 32],
        script: Arc<ServerScript>,
    }

    #[derive(Default)]
    struct ServerScript {
        /// Hold a Health response until the test releases it. Other connections
        /// must remain usable while this request is in flight.
        health_gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
        /// Offer pubkey reported by `GetPublicKeys`; `None` = keyless.
        offer_key: Mutex<Option<[u8; 32]>>,
        /// Drop the connection after serving this many post-handshake requests
        /// (0 = unlimited).
        drop_after_requests: AtomicU64,
        /// Answer every non-GetPublicKeys request with `EnclaveResponse::Error`.
        error_mode: std::sync::atomic::AtomicBool,
        /// Labels of every post-handshake request served, across connections.
        served: Mutex<Vec<&'static str>>,
    }

    impl FakeEnclave {
        fn generate(script: Arc<ServerScript>) -> Self {
            let builder = snow::Builder::new(crate::NOISE_PARAMS.parse().expect("noise params"));
            let keys = builder.generate_keypair().expect("keypair");
            let noise_public: [u8; 32] = keys.public.as_slice().try_into().expect("32-byte key");
            Self {
                noise_private: keys.private,
                noise_public,
                recipient: [0x0B; 32],
                attestation_pub: [0xAA; 32],
                script,
            }
        }

        fn quote_response(&self) -> EnclaveResponse {
            let mut preimage = Vec::with_capacity(96);
            preimage.extend_from_slice(&self.noise_public);
            preimage.extend_from_slice(&self.recipient);
            preimage.extend_from_slice(&self.attestation_pub);
            EnclaveResponse::Quote {
                mrenclave: alloy_primitives::B256::repeat_byte(0x01),
                mrsigner: alloy_primitives::B256::repeat_byte(0x02),
                isv_svn: 1,
                report_data: keccak256(&preimage),
                recipient_x25519_pub: self.recipient,
                attestation_pub: self.attestation_pub,
                noise_static_pub: self.noise_public,
                quote_body: Vec::new(),
                attestation: "none (session-test)".to_string(),
            }
        }

        fn serve_connection(&self, mut stream: UnixStream) -> Result<(), String> {
            // 1. Cleartext GetQuote.
            let frame = read_frame(&mut stream).map_err(|e| e.to_string())?;
            let request = decode_request(&frame).map_err(|e| e.to_string())?;
            if !matches!(request, EnclaveRequest::GetQuote { .. }) {
                return Err("expected GetQuote".into());
            }
            let body = encode_response(&self.quote_response()).map_err(|e| e.to_string())?;
            write_frame(&mut stream, &body).map_err(|e| e.to_string())?;
            // 2. Noise-IK responder handshake.
            let mut handshake = snow::Builder::new(
                crate::NOISE_PARAMS
                    .parse()
                    .map_err(|_| "params".to_string())?,
            )
            .local_private_key(&self.noise_private)
            .build_responder()
            .map_err(|e| e.to_string())?;
            let msg1 = read_frame(&mut stream).map_err(|e| e.to_string())?;
            let mut buf = [0u8; 1024];
            handshake
                .read_message(&msg1, &mut buf)
                .map_err(|e| e.to_string())?;
            let n = handshake
                .write_message(&[], &mut buf)
                .map_err(|e| e.to_string())?;
            write_frame(&mut stream, &buf[..n]).map_err(|e| e.to_string())?;
            let mut noise = handshake.into_transport_mode().map_err(|e| e.to_string())?;
            // 3. Encrypted request loop.
            let mut served_here: u64 = 0;
            loop {
                let Ok(frame) = read_frame(&mut stream) else {
                    return Ok(()); // client closed
                };
                let mut pt = vec![0u8; frame.len()];
                let n = noise
                    .read_message(&frame, &mut pt)
                    .map_err(|e| e.to_string())?;
                let request = decode_request(&pt[..n]).map_err(|e| e.to_string())?;
                if let Ok(mut served) = self.script.served.lock() {
                    served.push(request.label());
                }
                if matches!(request, EnclaveRequest::Health) {
                    let gate = self.script.health_gate.lock().expect("health gate").take();
                    if let Some((entered, release)) = gate {
                        entered.send(()).map_err(|e| e.to_string())?;
                        release.recv().map_err(|e| e.to_string())?;
                    }
                }
                served_here += 1;
                let drop_after = self.script.drop_after_requests.load(Ordering::Relaxed);
                if drop_after != 0 && served_here > drop_after {
                    return Ok(()); // simulate a mid-session connection loss
                }
                let response = match &request {
                    EnclaveRequest::GetPublicKeys => {
                        let offer = *self
                            .script
                            .offer_key
                            .lock()
                            .map_err(|_| "offer_key lock".to_string())?;
                        EnclaveResponse::PublicKeys {
                            offer_key_ready: offer.is_some(),
                            recipient_x25519_pub: offer.unwrap_or(self.recipient),
                            attestation_pub: self.attestation_pub,
                            noise_static_pub: self.noise_public,
                            tee_bls_pub: Vec::new(),
                            dkg_enc_pub: [0x0D; 32],
                            dkg_enc_sig: Vec::new(),
                        }
                    }
                    _ if self.script.error_mode.load(Ordering::Relaxed) => EnclaveResponse::Error {
                        message: "scripted deterministic error".to_string(),
                    },
                    _ => EnclaveResponse::Ack,
                };
                let plain = encode_response(&response).map_err(|e| e.to_string())?;
                let mut ct = vec![0u8; plain.len() + 64];
                let n = noise
                    .write_message(&plain, &mut ct)
                    .map_err(|e| e.to_string())?;
                write_frame(&mut stream, &ct[..n]).map_err(|e| e.to_string())?;
            }
        }
    }

    struct RunningServer {
        endpoint: String,
        stop: Arc<std::sync::atomic::AtomicBool>,
        _dir: tempfile::TempDir,
    }

    fn spawn_server(enclave: Arc<FakeEnclave>) -> RunningServer {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enclave.sock");
        let endpoint = path.to_string_lossy().into_owned();
        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).ok();
                        let enclave = Arc::clone(&enclave);
                        std::thread::spawn(move || {
                            let _ = enclave.serve_connection(stream);
                        });
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        RunningServer {
            endpoint,
            stop,
            _dir: dir,
        }
    }

    fn ready_script() -> Arc<ServerScript> {
        let script = Arc::new(ServerScript::default());
        if let Ok(mut key) = script.offer_key.lock() {
            *key = Some([0x0E; 32]);
        }
        script
    }

    fn connect_session(server: &RunningServer) -> EnclaveSession {
        let client = EnclaveClient::connect_endpoint(&server.endpoint).expect("connect");
        EnclaveSession::development(client, server.endpoint.clone()).expect("session")
    }

    #[test]
    fn blocked_canary_does_not_block_execution_connection() {
        use crate::client_global::EnclaveSessions;
        use std::sync::mpsc::channel;
        use std::time::Duration;

        let script = ready_script();
        let server = spawn_server(Arc::new(FakeEnclave::generate(Arc::clone(&script))));
        let sessions = Arc::new(EnclaveSessions::new(connect_session(&server)));
        let (entered_tx, entered_rx) = channel();
        let (release_tx, release_rx) = channel();
        *script.health_gate.lock().unwrap() = Some((entered_tx, release_rx));
        let canary_sessions = Arc::clone(&sessions);
        let canary =
            std::thread::spawn(move || canary_sessions.canary_request(&EnclaveRequest::Health));
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("canary in flight");
        let execution_sessions = Arc::clone(&sessions);
        let (finished_tx, finished_rx) = channel();
        let execution = std::thread::spawn(move || {
            let result = execution_sessions
                .with_execution(|session| session.request(&EnclaveRequest::GetPublicKeys));
            finished_tx.send(result).unwrap();
        });
        let completed_while_canary_blocked = finished_rx.recv_timeout(Duration::from_secs(5));
        // Release before asserting so a broken implementation cannot strand
        // either request thread holding a session lock.
        release_tx.send(()).unwrap();
        canary.join().unwrap().expect("canary response");
        execution.join().unwrap();
        assert!(matches!(
            completed_while_canary_blocked.unwrap().unwrap(),
            EnclaveResponse::PublicKeys { .. }
        ));
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn canary_rejects_non_probe_requests_without_transport_io() {
        let script = ready_script();
        let server = spawn_server(Arc::new(FakeEnclave::generate(Arc::clone(&script))));
        let sessions = crate::client_global::EnclaveSessions::new(connect_session(&server));
        let before = script.served.lock().unwrap().clone();
        let error = sessions
            .canary_request(&EnclaveRequest::GetQuote { nonce: [0; 32] })
            .expect_err("not a canary probe");
        assert!(matches!(error, TransportError::EnclaveError(_)));
        assert_eq!(*script.served.lock().unwrap(), before);
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn forked_connection_preserves_offer_key_pin_and_revocation() {
        let script = ready_script();
        let server = spawn_server(Arc::new(FakeEnclave::generate(Arc::clone(&script))));
        let installed = connect_session(&server);
        let mut fork = installed.fork_connection();
        assert_eq!(fork.attestation_pub(), installed.attestation_pub());
        *script.offer_key.lock().unwrap() = Some([0x99; 32]);
        assert!(matches!(
            fork.request(&EnclaveRequest::GetPublicKeys),
            Err(TransportError::IdentityMismatch(_))
        ));
        assert!(matches!(
            fork.request(&EnclaveRequest::Health),
            Err(TransportError::SessionRevoked(_))
        ));
        assert!(matches!(
            fork.fork_connection().request(&EnclaveRequest::Health),
            Err(TransportError::SessionRevoked(_))
        ));
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn transport_fault_reconnects_and_retries_idempotent_request() {
        let script = ready_script();
        script.drop_after_requests.store(2, Ordering::Relaxed);
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let mut session = connect_session(&server);
        assert_eq!(session.generation(), 1);
        // Install consumed request #1 (the probe); #2 succeeds; #3 gets the
        // connection dropped mid-request -> reconnect (fresh connection, its own
        // probe) -> retry succeeds.
        let first = session.request(&EnclaveRequest::GetPublicKeys).expect("ok");
        assert!(matches!(first, EnclaveResponse::PublicKeys { .. }));
        // Request #3 on connection 1 exceeds the per-connection budget -> the
        // server drops it mid-request; the reconnect's fresh connection serves
        // its probe + the retry within the same budget.
        let retried = session
            .request(&EnclaveRequest::GetPublicKeys)
            .expect("retried after reconnect");
        assert!(matches!(retried, EnclaveResponse::PublicKeys { .. }));
        assert_eq!(session.generation(), 2, "exactly one reconnect");
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn failed_reconnect_returns_error_without_revoking() {
        let script = ready_script();
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let mut session = connect_session(&server);
        // Kill the listener; the pinned connection dies with the next fault.
        server.stop.store(true, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(server);
        // The old connection is still alive server-side (thread-per-conn), so
        // force a fresh reconnect target by dropping the client state:
        session.client = None;
        let error = session
            .request(&EnclaveRequest::GetPublicKeys)
            .expect_err("reconnect target is gone");
        assert!(
            !matches!(error, TransportError::SessionRevoked(_)),
            "connect failure must stay retryable, got: {error}"
        );
        // A new server at the SAME endpoint path cannot be rebuilt (tempdir
        // dropped); the point above - no revocation - is the invariant.
    }

    #[test]
    fn identity_mismatch_on_reconnect_revokes_permanently() {
        let script = ready_script();
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enclave.sock");
        let endpoint = path.to_string_lossy().into_owned();

        // Server #1: original identity.
        let listener = UnixListener::bind(&path).expect("bind");
        let enclave1 = Arc::clone(&enclave);
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = enclave1.serve_connection(stream);
            }
            // one connection only, then stop accepting
        });
        let client = EnclaveClient::connect_endpoint(&endpoint).expect("connect");
        let mut session = EnclaveSession::development(client, endpoint.clone()).expect("session");

        // Server #2 on the same path: DIFFERENT identity keys.
        std::fs::remove_file(&path).expect("remove socket");
        let impostor = Arc::new(FakeEnclave::generate(ready_script()));
        let listener = UnixListener::bind(&path).expect("rebind");
        let impostor_for_conn = Arc::clone(&impostor);
        std::thread::spawn(move || {
            while let Ok((stream, _)) = listener.accept() {
                let enclave = Arc::clone(&impostor_for_conn);
                std::thread::spawn(move || {
                    let _ = enclave.serve_connection(stream);
                });
            }
        });

        session.client = None; // force reconnect against the impostor
        let error = session
            .request(&EnclaveRequest::GetPublicKeys)
            .expect_err("identity mismatch");
        assert!(
            matches!(error, TransportError::IdentityMismatch(_)),
            "got: {error}"
        );
        // Fail-closed: every later request refuses fast, no new connection.
        let error = session
            .request(&EnclaveRequest::GetPublicKeys)
            .expect_err("revoked");
        assert!(matches!(error, TransportError::SessionRevoked(_)));
    }

    #[test]
    fn offer_key_pin_upgrades_from_keyless_but_revokes_on_change() {
        // Start keyless.
        let script = Arc::new(ServerScript::default());
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let mut session = connect_session(&server);
        assert!(session.pinned_offer_public.is_none());

        // Key appears (post-DKG): reconnect upgrades the pin.
        if let Ok(mut key) = script.offer_key.lock() {
            *key = Some([0x0E; 32]);
        }
        session.client = None;
        session.request(&EnclaveRequest::GetPublicKeys).expect("ok");
        assert_eq!(
            session.pinned_offer_public,
            Some(B256::from([0x0E; 32])),
            "None -> Some upgrades the pin"
        );

        // Key changes: reconnect must revoke.
        if let Ok(mut key) = script.offer_key.lock() {
            *key = Some([0x0F; 32]);
        }
        session.client = None;
        let error = session
            .request(&EnclaveRequest::GetPublicKeys)
            .expect_err("offer key changed");
        assert!(matches!(error, TransportError::IdentityMismatch(_)));
        assert!(matches!(
            session.request(&EnclaveRequest::GetPublicKeys),
            Err(TransportError::SessionRevoked(_))
        ));
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn non_idempotent_request_is_not_resent_after_reconnect() {
        let script = ready_script();
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let mut session = connect_session(&server);
        // Drop the connection at the next (non-idempotent) request.
        script.drop_after_requests.store(1, Ordering::Relaxed);
        // Reset so the NEXT connection (reconnect) is unlimited again.
        let request = EnclaveRequest::DkgStartDealer {
            ceremony_id: alloy_primitives::B256::repeat_byte(0x33),
        };
        assert!(!request.is_idempotent());
        let before_generation = session.generation();
        let error = session.request(&request);
        // Restore unlimited serving for the reconnect probe.
        script.drop_after_requests.store(0, Ordering::Relaxed);
        assert!(error.is_err(), "original transport error must propagate");
        let served = script.served.lock().expect("served").clone();
        assert_eq!(
            served
                .iter()
                .filter(|label| **label == "dkg_start_dealer")
                .count(),
            1,
            "non-idempotent request must never be re-sent: {served:?}"
        );
        // The session healed for the next caller (reconnect happened).
        assert!(session.generation() > before_generation);
        let ok = session.request(&EnclaveRequest::GetPublicKeys);
        assert!(ok.is_ok(), "session must be healed: {ok:?}");
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn enclave_error_response_does_not_reconnect() {
        let script = ready_script();
        script.error_mode.store(true, Ordering::Relaxed);
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let mut session = connect_session(&server);
        let generation = session.generation();
        let error = session
            .request(&EnclaveRequest::Health)
            .expect_err("scripted error");
        assert!(matches!(error, TransportError::EnclaveError(_)));
        assert_eq!(session.generation(), generation, "no reconnect");
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn poison_recovery_forces_one_clean_reconnect() {
        let script = ready_script();
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let session = connect_session(&server);
        let mutex = Arc::new(Mutex::new(session));
        // Poison the mutex.
        let poisoner = Arc::clone(&mutex);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("lock");
            panic!("poison");
        })
        .join();
        assert!(mutex.lock().is_err(), "mutex must be poisoned");
        // Recovery path (mirrors client_global::try_with_enclave).
        let mut guard = match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.recover_from_poison();
                guard
            }
        };
        assert!(guard.client.is_none(), "poison drops the connection once");
        assert!(guard.poison_recovered());
        let response = guard.request(&EnclaveRequest::GetPublicKeys);
        assert!(
            response.is_ok(),
            "clean reconnect after poison: {response:?}"
        );
        assert_eq!(guard.generation(), 2);
        // The latch: a second recovery call must not drop the healed client.
        guard.recover_from_poison();
        assert!(
            guard.client.is_some(),
            "latch protects the reconnected client"
        );
        server.stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn multi_frame_dcap_requests_are_guarded() {
        let script = ready_script();
        let enclave = Arc::new(FakeEnclave::generate(Arc::clone(&script)));
        let server = spawn_server(Arc::clone(&enclave));
        let mut session = connect_session(&server);
        let error = session
            .request(&EnclaveRequest::FinishDcapVerificationV1 {
                request_hash: alloy_primitives::B256::ZERO,
            })
            .expect_err("guarded");
        assert!(matches!(error, TransportError::DcapVerification(_)));
        server.stop.store(true, Ordering::Relaxed);
    }
}
