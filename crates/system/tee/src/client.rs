//! Blocking node-side client for the enclave channel (Noise-IK over framed UDS).
//!
//! Production first discovers an initialization challenge, submits one canonical
//! node-signed manifest, and proves possession of its persistent `NodeHost` Noise
//! initiator key. Later connections use `OpenSession` plus the same key. The
//! legacy `EnclaveClient` GetQuote flow remains for the separate dev/mock
//! transport and is not accepted by the production enclave.
//!
//! The client is fully synchronous: it is meant to be driven straight from the
//! `offerTributeBatch` precompile path with a blocking UDS round-trip - no
//! async, no `spawn`, nothing that would capture a `StorageHandle`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

use alloy_primitives::{keccak256, B256};
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, AttestationOperationV1, EnclaveInitializationManifestV1, RegistrationIntentV1,
    TransitionKeyReadyProofV1,
};
use rand::RngCore as _;
use zeroize::Zeroizing;

use crate::codec::{decode_response, encode_request, read_frame, write_frame};
use crate::dcap_protocol::{
    dcap_onboarding_attestation_preimage, dcap_onboarding_request_hash,
    dcap_verification_attestation_preimage, dcap_verification_request_hash,
    DcapOnboardingArtifactV1, DcapOnboardingContextV1, DcapOnboardingVerificationResultV1,
    DcapVerificationOutcomeV1, MAX_DCAP_VERIFICATION_CHUNK_BYTES,
};
use crate::errors::TransportError;
use crate::finalized_admission::{
    onboarding_artifact_ingest_request_hash_v1, MAX_ONBOARDING_INGEST_CHUNK_BYTES,
};
use crate::protocol::{EnclaveRequest, EnclaveResponse};
use crate::remote_session::RemoteSessionAdmissionV1;
use crate::NOISE_PARAMS;

/// The byte carrier under the Noise-IK session: a local Unix domain socket
/// (native sidecar) or TCP (used when the enclave runs under Gramine, whose
/// pathname UDS are process-internal). Noise authenticates + encrypts every
/// byte regardless, so the carrier does not change the channel's security.
enum Transport {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.read(buf),
            Transport::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Unix(s) => s.write(buf),
            Transport::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Unix(s) => s.flush(),
            Transport::Tcp(s) => s.flush(),
        }
    }
}

/// The enclave identity fields captured from the quote response at connect time.
#[derive(Debug, Clone)]
struct QuoteIdentity {
    mrenclave: B256,
    mrsigner: B256,
    isv_svn: u16,
    attestation_pub: [u8; 32],
    /// The enclave's Noise static key as pinned by [`verify_quote`] - the key
    /// the Noise-IK handshake actually authenticated. Retained so a session
    /// reconnect can require the byte-identical peer.
    noise_static_pub: [u8; 32],
    /// The attestation environment the enclave self-reported (e.g.
    /// `none (gramine-direct / no SGX)`).
    attestation: String,
}

/// Blocking client for one enclave session.
pub struct EnclaveClient {
    stream: Transport,
    noise: snow::TransportState,
    identity: QuoteIdentity,
    /// The raw `EnclaveResponse::Quote` this session verified at connect. Retained
    /// for development/bootstrap flows that must relay the exact quote bytes after
    /// local verification; it grants no key-delivery capability by itself.
    raw_quote: EnclaveResponse,
}

/// Persistent Noise IK initiator identity authorized by one enclave manifest.
/// The private bytes are zeroized on drop and are never exposed by this API.
#[derive(Clone)]
pub struct NodeHostNoiseKey {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl core::fmt::Debug for NodeHostNoiseKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NodeHostNoiseKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl NodeHostNoiseKey {
    /// Construct from bytes loaded by the node's persistent secret store.
    pub fn from_private(private: [u8; 32]) -> Self {
        Self::from_zeroizing(Zeroizing::new(private))
    }

    fn from_zeroizing(private: Zeroizing<[u8; 32]>) -> Self {
        let static_secret = x25519_dalek::StaticSecret::from(*private);
        let public = x25519_dalek::PublicKey::from(&static_secret).to_bytes();
        Self { private, public }
    }

    /// Create the NodeHost identity exactly once with owner-only permissions.
    /// Existing files reject; callers must never rotate this key implicitly.
    pub fn create_new(path: &Path) -> Result<Self, TransportError> {
        let mut private = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *private);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(private.as_ref())?;
        file.sync_all()?;
        if let Some(parent) = path.parent().filter(|value| !value.as_os_str().is_empty()) {
            File::open(parent)?.sync_all()?;
        }
        Ok(Self::from_zeroizing(private))
    }

    /// Load the one existing NodeHost identity. Missing, truncated, symlinked or
    /// over-permissive/foreign-owned files fail closed; loss never triggers key
    /// regeneration. `O_NOFOLLOW` and metadata from the opened descriptor avoid
    /// a path-check/read race.
    pub fn load(path: &Path) -> Result<Self, TransportError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(TransportError::Codec(
                "NodeHost key path must be a regular non-symlink file".to_string(),
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(TransportError::Codec(
                "NodeHost key file mode must be exactly 0600".to_string(),
            ));
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(TransportError::Codec(
                "NodeHost key file must be owned by the current effective user".to_string(),
            ));
        }
        let mut private = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut *private)?;
        let mut trailing = [0u8; 1];
        if file.read(&mut trailing)? != 0 {
            return Err(TransportError::Codec(
                "NodeHost key must be exactly 32 bytes".to_string(),
            ));
        }
        Ok(Self::from_zeroizing(private))
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnclaveInitializationChallenge {
    pub challenge: [u8; 32],
    pub recipient_x25519: [u8; 32],
    pub attestation_ed25519: [u8; 32],
    pub noise_responder_x25519: [u8; 32],
}

/// Quote material returned only after the host has verified the enclave's
/// exact intent echo and persistent Ed25519 proof of possession.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedDcapQuoteV1 {
    pub quote_body: Vec<u8>,
    pub enclave_signature: [u8; 64],
    pub transition_key_ready_proof: Option<TransitionKeyReadyProofV1>,
}

/// Production session authenticated by the sealed NodeHost initiator key.
pub struct AuthorizedEnclaveClient {
    stream: Transport,
    noise: snow::TransportState,
    attestation_pub: [u8; 32],
}

/// One unpredictable, one-use authorization installed by the target's local
/// NodeHost after finalized Registry verification. It contains no secret key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemoteSessionTicketV1 {
    ticket_id: B256,
    initiator_static_x25519: [u8; 32],
    responder_static_x25519: [u8; 32],
    deadline: u64,
    finalized_block_hash: B256,
}

impl RemoteSessionTicketV1 {
    #[must_use]
    pub const fn ticket_id(&self) -> B256 {
        self.ticket_id
    }

    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    #[must_use]
    pub const fn finalized_block_hash(&self) -> B256 {
        self.finalized_block_hash
    }
}

/// Remote peer session. Its intentionally small interface exposes only the
/// non-secret public-key request; owner and secret-bearing commands are not
/// part of this client surface and remain denied by the enclave matrix.
pub struct RemoteEnclaveClient {
    stream: Transport,
    noise: snow::TransportState,
}

/// Public, non-secret target enclave keys available to a remote peer. Keeping
/// this result typed prevents the narrow remote client from exposing the full
/// owner protocol response enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEnclavePublicKeysV1 {
    pub offer_key_ready: bool,
    pub recipient_x25519_pub: [u8; 32],
    pub attestation_pub: [u8; 32],
    pub noise_static_pub: [u8; 32],
    pub tee_bls_pub: Vec<u8>,
    pub dkg_enc_pub: [u8; 32],
    pub dkg_enc_sig: Vec<u8>,
}

/// Bound on a single blocking enclave read/write: a wedged enclave that accepts
/// the connection but never responds surfaces as a timeout error instead of hanging
/// the caller (e.g. node startup) forever. Generous - every real enclave op (quote,
/// Noise handshake, seal, offer-batch decrypt) completes well within this.
const DEFAULT_ENCLAVE_IO_TIMEOUT_SECS: u64 = 30;

/// Hardware SGX can spend substantially longer than gramine-direct servicing a
/// request while EPC pages are reclaimed. The default remains fail-fast for
/// production/dev, while SGX stress/E2E runners may raise the bound explicitly.
fn enclave_io_timeout() -> std::time::Duration {
    static TIMEOUT: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        let value = std::env::var("OUTBE_TEE_IO_TIMEOUT_SECS").ok();
        let seconds = timeout_seconds_from(value.as_deref());
        std::time::Duration::from_secs(seconds)
    })
}

fn timeout_seconds_from(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_ENCLAVE_IO_TIMEOUT_SECS)
}

fn with_io_phase<T>(
    result: Result<T, TransportError>,
    operation: &'static str,
) -> Result<T, TransportError> {
    result.map_err(|error| match error {
        TransportError::Io(source)
            if matches!(
                source.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            TransportError::IoTimeout {
                operation,
                timeout_secs: enclave_io_timeout().as_secs(),
            }
        }
        other => other,
    })
}

impl EnclaveClient {
    /// Connect to the enclave over a Unix domain socket (native sidecar), then
    /// validate its key bindings, pin the enclave Noise static key, and complete
    /// the Noise-IK handshake.
    pub fn connect(path: &Path) -> Result<Self, TransportError> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(enclave_io_timeout()))?;
        stream.set_write_timeout(Some(enclave_io_timeout()))?;
        Self::from_transport(Transport::Unix(stream))
    }

    /// Connect to the enclave over TCP (`host:port`) - used when the enclave runs
    /// under Gramine, whose pathname UDS cannot be reached from a host process.
    pub fn connect_tcp(addr: &str) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(addr)?;
        let _ = stream.set_nodelay(true);
        stream.set_read_timeout(Some(enclave_io_timeout()))?;
        stream.set_write_timeout(Some(enclave_io_timeout()))?;
        Self::from_transport(Transport::Tcp(stream))
    }

    /// True when the enclave reports a DCAP/EPID attestation type. This structural
    /// connect path does not verify the quote signature or establish production
    /// admission; those guarantees come from native QVL and TeeRegistry. Under
    /// gramine-sgx with `sgx.remote_attestation = "none"` the enclave reports REAL measurements
    /// (read from the local SGX report) but produces no quote, so it is confidential
    /// and measured yet unattested. False under gramine-direct / bare too. Gate
    /// quote-dependent trust on this, not on non-zero measurements.
    pub fn is_hardware_attested(&self) -> bool {
        let a = &self.identity.attestation;
        a.starts_with("dcap") || a.starts_with("epid")
    }

    /// The connected enclave's measurements `(mrenclave, mrsigner, isv_svn)`.
    pub fn measurements(&self) -> (B256, B256, u16) {
        (
            self.identity.mrenclave,
            self.identity.mrsigner,
            self.identity.isv_svn,
        )
    }

    /// The exact attestation environment the enclave self-reported (e.g.
    /// `dcap (gramine-sgx)` or `none (gramine-direct / no SGX)`).
    pub fn attestation_label(&self) -> &str {
        &self.identity.attestation
    }

    /// The enclave's Ed25519 attestation public key, pinned from this session's
    /// structurally validated quote response. Used to verify
    /// per-offer attestation tags (`verify_tribute_offer_attestation`) - a local
    /// verify-then-discard check that binds a batch's results to the peer holding
    /// this session key. Production enclave identity is established separately.
    pub fn attestation_pub(&self) -> [u8; 32] {
        self.identity.attestation_pub
    }

    /// The enclave Noise static key this session's handshake authenticated,
    /// pinned from the structurally validated quote at connect time.
    pub fn noise_static_pub(&self) -> [u8; 32] {
        self.identity.noise_static_pub
    }

    /// Connect using an endpoint string: `host:port` -> TCP, otherwise a UDS path.
    pub fn connect_endpoint(endpoint: &str) -> Result<Self, TransportError> {
        if endpoint.contains(':') {
            Self::connect_tcp(endpoint)
        } else {
            Self::connect(Path::new(endpoint))
        }
    }

    /// Run GetQuote, structural binding validation, and the Noise-IK handshake
    /// over an established transport.
    fn from_transport(mut stream: Transport) -> Result<Self, TransportError> {
        // 1. GetQuote (cleartext, pre-handshake) with a fresh nonce.
        let nonce: [u8; 32] = rand::random();
        with_io_phase(
            write_frame(
                &mut stream,
                &encode_request(&EnclaveRequest::GetQuote { nonce })?,
            ),
            "quote request write",
        )?;
        let quote = decode_response(&with_io_phase(
            read_frame(&mut stream),
            "quote response read",
        )?)?;
        let enclave_static = verify_quote(&quote)?;
        let identity = quote_identity(&quote, enclave_static)?;

        // 2. Noise-IK handshake (initiator). The host static key is ephemeral
        //    per connection; the enclave static key is the bound, pinned one.
        let params = NOISE_PARAMS
            .parse()
            .map_err(|e| TransportError::Noise(format!("{e:?}")))?;
        let builder = snow::Builder::new(params);
        let host_keys = builder
            .generate_keypair()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let mut handshake = builder
            .local_private_key(&host_keys.private)
            .remote_public_key(&enclave_static)
            .build_initiator()
            .map_err(|e| TransportError::Handshake(e.to_string()))?;

        let mut buf = [0u8; 1024];
        let n = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| TransportError::Handshake(e.to_string()))?;
        with_io_phase(
            write_frame(&mut stream, &buf[..n]),
            "Noise handshake request write",
        )?;

        let msg2 = with_io_phase(read_frame(&mut stream), "Noise handshake response read")?;
        handshake
            .read_message(&msg2, &mut buf)
            .map_err(|e| TransportError::Handshake(e.to_string()))?;

        let noise = handshake
            .into_transport_mode()
            .map_err(|e| TransportError::Handshake(e.to_string()))?;
        Ok(Self {
            stream,
            noise,
            identity,
            raw_quote: quote,
        })
    }

    /// This session's quote response, structurally validated at connect.
    pub fn quote(&self) -> &EnclaveResponse {
        &self.raw_quote
    }

    /// Send one request, read one response, encrypted under the session.
    pub fn request(&mut self, req: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        let plain = encode_request(req)?;
        let mut ct = vec![0u8; plain.len() + 64];
        let n = self
            .noise
            .write_message(&plain, &mut ct)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        with_io_phase(
            write_frame(&mut self.stream, &ct[..n]),
            "encrypted enclave request write",
        )?;

        let resp_ct = with_io_phase(
            read_frame(&mut self.stream),
            "encrypted enclave response read",
        )?;
        let mut pt = vec![0u8; resp_ct.len()];
        let n = self
            .noise
            .read_message(&resp_ct, &mut pt)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let resp = decode_response(&pt[..n])?;
        if let EnclaveResponse::Error { message } = &resp {
            return Err(TransportError::EnclaveError(message.clone()));
        }
        Ok(resp)
    }

    /// Ask the enclave to sign one exact canonical GramineDirectDev
    /// registration intent. This development transport never produces a quote
    /// or DCAP verdict.
    pub fn sign_registration_intent_dev_v1(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<[u8; 64], TransportError> {
        let attestation_pub = self.attestation_pub();
        request_gramine_direct_dev_signature(attestation_pub, intent, |request| {
            self.request(request)
        })
    }
}

impl AuthorizedEnclaveClient {
    /// Fetch the one-time production initialization challenge and persistent
    /// enclave public keys. The discovery connection closes after this response.
    pub fn discover_endpoint(
        endpoint: &str,
    ) -> Result<EnclaveInitializationChallenge, TransportError> {
        let mut stream = connect_endpoint_transport(endpoint)?;
        with_io_phase(
            write_frame(
                &mut stream,
                &encode_request(&EnclaveRequest::GetInitializationChallenge)?,
            ),
            "initialization challenge write",
        )?;
        let response = decode_response(&with_io_phase(
            read_frame(&mut stream),
            "initialization challenge read",
        )?)?;
        match response {
            EnclaveResponse::InitializationChallenge {
                challenge,
                recipient_x25519_pub,
                attestation_pub,
                noise_static_pub,
            } => Ok(EnclaveInitializationChallenge {
                challenge,
                recipient_x25519: recipient_x25519_pub,
                attestation_ed25519: attestation_pub,
                noise_responder_x25519: noise_static_pub,
            }),
            EnclaveResponse::Error { message } => Err(TransportError::EnclaveError(message)),
            _ => Err(TransportError::UnexpectedResponse),
        }
    }

    /// Commit one canonical signed initialization manifest. The enclave accepts
    /// it only if Noise message 1 proves the exact NodeHost key embedded in it.
    pub fn initialize_endpoint(
        endpoint: &str,
        manifest: &EnclaveInitializationManifestV1,
        node_signature: &[u8; 65],
        node_host: &NodeHostNoiseKey,
    ) -> Result<Self, TransportError> {
        if manifest.node_host_noise_x25519 != node_host.public() {
            return Err(TransportError::Handshake(
                "initialization manifest does not bind the supplied NodeHost key".to_string(),
            ));
        }
        let manifest_bytes = manifest
            .encode_canonical()
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        let preamble = EnclaveRequest::Initialize {
            manifest: manifest_bytes,
            node_signature: node_signature.to_vec(),
        };
        let mut client = Self::connect_with_preamble(
            endpoint,
            &preamble,
            manifest.noise_responder_x25519,
            node_host,
            manifest.attestation_ed25519,
        )?;
        let response = client.receive_response("initialization acknowledgement read")?;
        let expected_enclave_id = manifest
            .enclave_id()
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        let expected_node_host_authorization_hash = manifest
            .node_host_authorization_hash()
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        match response {
            EnclaveResponse::Initialized {
                enclave_id,
                node_host_authorization_hash,
                sealed_loaded: false,
            } if enclave_id == expected_enclave_id
                && node_host_authorization_hash == expected_node_host_authorization_hash =>
            {
                Ok(client)
            }
            EnclaveResponse::Error { message } => Err(TransportError::EnclaveError(message)),
            _ => Err(TransportError::UnexpectedResponse),
        }
    }

    /// Reconnect to an initialized production enclave using the same manifest and
    /// persistent NodeHost key. No quote is generated for this local session.
    pub fn connect_endpoint(
        endpoint: &str,
        manifest: &EnclaveInitializationManifestV1,
        node_host: &NodeHostNoiseKey,
    ) -> Result<Self, TransportError> {
        if manifest.node_host_noise_x25519 != node_host.public() {
            return Err(TransportError::Handshake(
                "sealed manifest does not bind the supplied NodeHost key".to_string(),
            ));
        }
        manifest
            .encode_canonical()
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        Self::connect_with_preamble(
            endpoint,
            &EnclaveRequest::OpenSession,
            manifest.noise_responder_x25519,
            node_host,
            manifest.attestation_ed25519,
        )
    }

    fn connect_with_preamble(
        endpoint: &str,
        preamble: &EnclaveRequest,
        enclave_static: [u8; 32],
        node_host: &NodeHostNoiseKey,
        attestation_pub: [u8; 32],
    ) -> Result<Self, TransportError> {
        let mut stream = connect_endpoint_transport(endpoint)?;
        with_io_phase(
            write_frame(&mut stream, &encode_request(preamble)?),
            "production preamble write",
        )?;
        let params = NOISE_PARAMS
            .parse()
            .map_err(|error| TransportError::Noise(format!("{error:?}")))?;
        let mut handshake = snow::Builder::new(params)
            .local_private_key(node_host.private.as_ref())
            .remote_public_key(&enclave_static)
            .build_initiator()
            .map_err(|error| TransportError::Handshake(error.to_string()))?;
        let mut buffer = [0u8; 1024];
        let length = handshake
            .write_message(&[], &mut buffer)
            .map_err(|error| TransportError::Handshake(error.to_string()))?;
        with_io_phase(
            write_frame(&mut stream, &buffer[..length]),
            "Noise handshake request write",
        )?;
        let message = with_io_phase(read_frame(&mut stream), "Noise handshake response read")?;
        handshake
            .read_message(&message, &mut buffer)
            .map_err(|error| TransportError::Handshake(error.to_string()))?;
        let noise = handshake
            .into_transport_mode()
            .map_err(|error| TransportError::Handshake(error.to_string()))?;
        Ok(Self {
            stream,
            noise,
            attestation_pub,
        })
    }

    fn receive_response(
        &mut self,
        operation: &'static str,
    ) -> Result<EnclaveResponse, TransportError> {
        let ciphertext = with_io_phase(read_frame(&mut self.stream), operation)?;
        let mut plaintext = vec![0u8; ciphertext.len()];
        let length = self
            .noise
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|error| TransportError::Noise(error.to_string()))?;
        let response = decode_response(&plaintext[..length])?;
        if let EnclaveResponse::Error { message } = &response {
            return Err(TransportError::EnclaveError(message.clone()));
        }
        Ok(response)
    }

    /// Sends an ordinary authenticated owner request. Remote-ticket
    /// installation is reserved for the opaque finalized-admission route.
    pub fn request(&mut self, request: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        if matches!(request, EnclaveRequest::AuthorizeRemoteSessionV1 { .. }) {
            return Err(TransportError::Handshake(
                "remote session authorization requires a finalized admission capability".into(),
            ));
        }
        if matches!(
            request,
            EnclaveRequest::BeginDcapOnboardingArtifactIngestV1 { .. }
                | EnclaveRequest::DcapOnboardingArtifactChunkV1 { .. }
                | EnclaveRequest::CommitDcapOnboardingArtifactRecordV1 { .. }
                | EnclaveRequest::FinishDcapOnboardingArtifactIngestV1 { .. }
        ) {
            return Err(TransportError::DcapVerification(
                "multi-frame onboarding ingest must use the whole-operation client API".into(),
            ));
        }
        self.request_internal(request)
    }

    /// Upload and install one exact finalized onboarding admission over this
    /// authenticated owner connection. There is no per-frame retry: after any
    /// fault the caller must reconnect and restart from `Begin`.
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_finalized_admission_v1(
        &mut self,
        artifact: &[u8],
        anchor_outcome: &[u8],
        committee_transitions: &[Vec<u8>],
        finalized_admission_witness: &[u8],
        expected_intent_hash: B256,
        expected_tribute_offer_public: [u8; 32],
        expected_key_epoch: u64,
        expected_tribute_offer_epoch: u64,
    ) -> Result<[u8; 32], TransportError> {
        let request_hash = self.begin_finalized_admission_v1(
            artifact,
            anchor_outcome,
            expected_intent_hash,
            expected_tribute_offer_public,
            expected_key_epoch,
            expected_tribute_offer_epoch,
        )?;
        for transition in committee_transitions {
            self.upload_finalized_admission_record_v1(
                request_hash,
                crate::finalized_admission::FinalizedAdmissionRecordKindV1::CommitteeTransition,
                transition,
            )?;
        }
        self.upload_finalized_admission_record_v1(
            request_hash,
            crate::finalized_admission::FinalizedAdmissionRecordKindV1::Admission,
            finalized_admission_witness,
        )?;
        self.finish_finalized_admission_v1(request_hash, expected_tribute_offer_public)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin_finalized_admission_v1(
        &mut self,
        artifact: &[u8],
        anchor_outcome: &[u8],
        expected_intent_hash: B256,
        expected_tribute_offer_public: [u8; 32],
        expected_key_epoch: u64,
        expected_tribute_offer_epoch: u64,
    ) -> Result<B256, TransportError> {
        let request_hash = onboarding_artifact_ingest_request_hash_v1(
            artifact,
            anchor_outcome,
            expected_intent_hash,
            expected_tribute_offer_public,
            expected_key_epoch,
            expected_tribute_offer_epoch,
        )
        .map_err(|error| TransportError::DcapVerification(error.to_string()))?;
        match self.request_internal(&EnclaveRequest::BeginDcapOnboardingArtifactIngestV1 {
            request_hash,
            artifact: artifact.to_vec(),
            anchor_outcome: anchor_outcome.to_vec(),
            expected_intent_hash,
            expected_tribute_offer_public,
            expected_key_epoch,
            expected_tribute_offer_epoch,
        })? {
            EnclaveResponse::DcapOnboardingArtifactIngestStartedV1 {
                request_hash: echoed,
            } if echoed == request_hash => Ok(request_hash),
            _ => Err(TransportError::DcapVerification(
                "enclave did not acknowledge the exact onboarding ingest".into(),
            )),
        }
    }

    pub fn finish_finalized_admission_v1(
        &mut self,
        request_hash: B256,
        expected_tribute_offer_public: [u8; 32],
    ) -> Result<[u8; 32], TransportError> {
        match self.request_internal(&EnclaveRequest::FinishDcapOnboardingArtifactIngestV1 {
            request_hash,
        })? {
            EnclaveResponse::FinalizedAdmissionIngestedV1 {
                request_hash: echoed,
                tribute_offer_public,
            } if echoed == request_hash
                && tribute_offer_public == expected_tribute_offer_public =>
            {
                Ok(tribute_offer_public)
            }
            _ => Err(TransportError::DcapVerification(
                "enclave finalized a different onboarding admission".into(),
            )),
        }
    }

    pub fn upload_finalized_admission_record_v1(
        &mut self,
        request_hash: B256,
        kind: crate::finalized_admission::FinalizedAdmissionRecordKindV1,
        record: &[u8],
    ) -> Result<(), TransportError> {
        if record.is_empty() {
            return Err(TransportError::DcapVerification(
                "finalized admission record is empty".into(),
            ));
        }
        let mut offset = 0usize;
        for chunk in record.chunks(MAX_ONBOARDING_INGEST_CHUNK_BYTES) {
            let wire_offset = u32::try_from(offset).map_err(|_| {
                TransportError::DcapVerification(
                    "finalized admission proof offset exceeds u32".into(),
                )
            })?;
            let next = offset.checked_add(chunk.len()).ok_or_else(|| {
                TransportError::DcapVerification("finalized admission proof offset overflow".into())
            })?;
            let expected_next = u32::try_from(next).map_err(|_| {
                TransportError::DcapVerification(
                    "finalized admission proof offset exceeds u32".into(),
                )
            })?;
            match self.request_internal(&EnclaveRequest::DcapOnboardingArtifactChunkV1 {
                request_hash,
                kind,
                offset: wire_offset,
                bytes: chunk.to_vec(),
            })? {
                EnclaveResponse::DcapOnboardingArtifactChunkAcceptedV1 {
                    request_hash: echoed,
                    next_offset,
                } if echoed == request_hash && next_offset == expected_next => {}
                _ => {
                    return Err(TransportError::DcapVerification(
                        "enclave acknowledged a different onboarding proof chunk".into(),
                    ))
                }
            }
            offset = next;
        }
        match self.request_internal(&EnclaveRequest::CommitDcapOnboardingArtifactRecordV1 {
            request_hash,
            kind,
        })? {
            EnclaveResponse::DcapOnboardingArtifactRecordAcceptedV1 {
                request_hash: echoed,
                kind: echoed_kind,
            } if echoed == request_hash && echoed_kind == kind => Ok(()),
            _ => Err(TransportError::DcapVerification(
                "enclave did not accept the exact finalized admission record".into(),
            )),
        }
    }

    fn request_internal(
        &mut self,
        request: &EnclaveRequest,
    ) -> Result<EnclaveResponse, TransportError> {
        let plaintext = encode_request(request)?;
        let mut ciphertext = vec![0u8; plaintext.len() + 64];
        let length = self
            .noise
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|error| TransportError::Noise(error.to_string()))?;
        with_io_phase(
            write_frame(&mut self.stream, &ciphertext[..length]),
            "encrypted enclave request write",
        )?;
        self.receive_response("encrypted enclave response read")
    }

    /// Installs one one-use remote admission after the caller has verified its
    /// source and target bindings from local or anchored finalized state.
    /// Production node code uses the finalized facade in `outbe-node`; this
    /// low-level transport method remains public only across the crate seam.
    #[doc(hidden)]
    pub fn authorize_remote_session(
        &mut self,
        admission: &RemoteSessionAdmissionV1,
    ) -> Result<RemoteSessionTicketV1, TransportError> {
        let now = unix_time_seconds()?;
        if admission.deadline() <= now {
            return Err(TransportError::Handshake(
                "remote session admission is already expired".into(),
            ));
        }
        let mut ticket_bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ticket_bytes);
        if ticket_bytes == [0; 32] {
            return Err(TransportError::Handshake(
                "remote session ticket RNG returned zero".into(),
            ));
        }
        let ticket = RemoteSessionTicketV1 {
            ticket_id: B256::from(ticket_bytes),
            initiator_static_x25519: admission.initiator_static_x25519(),
            responder_static_x25519: admission.responder_static_x25519(),
            deadline: admission.deadline(),
            finalized_block_hash: admission.finalized_view().block_hash,
        };
        let response = self.request_internal(&EnclaveRequest::AuthorizeRemoteSessionV1 {
            ticket_id: ticket.ticket_id,
            initiator_static_x25519: ticket.initiator_static_x25519,
            responder_static_x25519: ticket.responder_static_x25519,
            deadline: ticket.deadline,
            finalized_block_hash: ticket.finalized_block_hash,
        })?;
        match response {
            EnclaveResponse::RemoteSessionAuthorizedV1 { ticket_id }
                if ticket_id == ticket.ticket_id =>
            {
                Ok(ticket)
            }
            _ => Err(TransportError::UnexpectedResponse),
        }
    }

    /// Generate one quote for the exact canonical intent and authenticate the
    /// enclave proof before returning anything to registration assembly.
    pub fn generate_dcap_quote(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<GeneratedDcapQuoteV1, TransportError> {
        if intent.attestation_ed25519 != self.attestation_pub {
            return Err(TransportError::Attestation(
                "registration intent does not bind the initialized enclave attestation key".into(),
            ));
        }
        let canonical_intent = intent
            .encode_canonical()
            .map_err(|error| TransportError::Codec(error.to_string()))?;
        let response = self.request(&EnclaveRequest::GenerateDcapQuote {
            intent: canonical_intent.clone(),
        })?;
        validate_generated_dcap_quote(intent, &canonical_intent, self.attestation_pub, response)
    }

    /// Sign GramineDirectDev evidence through the authenticated production
    /// NodeHost session. The enclave itself permits this only while running in
    /// real SGX with remote attestation disabled (`SgxNoAttest`).
    pub fn sign_registration_intent_dev_v1(
        &mut self,
        intent: &RegistrationIntentV1,
    ) -> Result<[u8; 64], TransportError> {
        let attestation_pub = self.attestation_pub;
        request_gramine_direct_dev_signature(attestation_pub, intent, |request| {
            self.request(request)
        })
    }

    /// Verify exact canonical evidence against exact canonical policy and
    /// consensus time inside the initialized Gramine enclave. The bounded
    /// multi-frame protocol is hidden from callers.
    pub fn verify_dcap_evidence_v1(
        &mut self,
        evidence: &[u8],
        policy: &[u8],
        block_timestamp: u64,
    ) -> Result<DcapVerificationOutcomeV1, TransportError> {
        let request_hash = dcap_verification_request_hash(evidence, policy, block_timestamp)
            .map_err(|code| {
                TransportError::DcapVerification(format!(
                    "invalid verifier input dimensions: {:#06x}",
                    code.code()
                ))
            })?;
        let response = self.upload_dcap_verification_v1(
            evidence,
            policy,
            request_hash,
            EnclaveRequest::BeginDcapVerificationV1 {
                request_hash,
                evidence_len: u32::try_from(evidence.len()).map_err(|_| {
                    TransportError::DcapVerification("evidence length exceeds u32".into())
                })?,
                policy_len: u32::try_from(policy.len()).map_err(|_| {
                    TransportError::DcapVerification("policy length exceeds u32".into())
                })?,
                block_timestamp,
            },
        )?;
        validate_dcap_verification_response(self.attestation_pub, request_hash, response)
    }

    /// Verify one exact `RegisterEnclave` request and request the deterministic
    /// one-time offer-key artifact from a resident source enclave.
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
        let request_hash = dcap_onboarding_request_hash(
            evidence,
            policy,
            block_timestamp,
            node_signature,
            enclave_signature,
            &expected_tribute_offer_public,
            key_epoch,
            tribute_offer_epoch,
        )
        .map_err(|code| {
            TransportError::DcapVerification(format!(
                "invalid onboarding verifier input dimensions: {:#06x}",
                code.code()
            ))
        })?;
        let response = self.upload_dcap_verification_v1(
            evidence,
            policy,
            request_hash,
            EnclaveRequest::BeginDcapOnboardingVerificationV1 {
                request_hash,
                evidence_len: u32::try_from(evidence.len()).map_err(|_| {
                    TransportError::DcapVerification("evidence length exceeds u32".into())
                })?,
                policy_len: u32::try_from(policy.len()).map_err(|_| {
                    TransportError::DcapVerification("policy length exceeds u32".into())
                })?,
                block_timestamp,
                node_signature: node_signature.to_vec(),
                enclave_signature: enclave_signature.to_vec(),
                expected_tribute_offer_public,
                key_epoch,
                tribute_offer_epoch,
            },
        )?;
        validate_dcap_onboarding_response(self.attestation_pub, request_hash, response)
    }

    pub fn prepare_gramine_direct_dev_onboarding_artifact_v1(
        &mut self,
        context: DcapOnboardingContextV1,
    ) -> Result<DcapOnboardingArtifactV1, TransportError> {
        let request_hash = context.context_hash();
        let response = self.request(
            &EnclaveRequest::PrepareGramineDirectDevOnboardingArtifactV1 {
                request_hash,
                context: context.encode_canonical(),
            },
        )?;
        let EnclaveResponse::GramineDirectDevOnboardingArtifactPreparedV1 {
            request_hash: actual_request_hash,
            onboarding_artifact,
        } = response
        else {
            return Err(TransportError::UnexpectedResponse);
        };
        if actual_request_hash != request_hash {
            return Err(TransportError::EnclaveError(
                "GramineDirectDev onboarding response context hash mismatch".into(),
            ));
        }
        let artifact =
            DcapOnboardingArtifactV1::decode_canonical(&onboarding_artifact).map_err(|code| {
                TransportError::EnclaveError(format!(
                    "GramineDirectDev onboarding artifact is non-canonical: {:#06x}",
                    code.code()
                ))
            })?;
        if artifact.context != context {
            return Err(TransportError::EnclaveError(
                "GramineDirectDev onboarding artifact context mismatch".into(),
            ));
        }
        Ok(artifact)
    }

    fn upload_dcap_verification_v1(
        &mut self,
        evidence: &[u8],
        policy: &[u8],
        request_hash: B256,
        begin: EnclaveRequest,
    ) -> Result<EnclaveResponse, TransportError> {
        match self.request(&begin)? {
            EnclaveResponse::DcapVerificationStartedV1 {
                request_hash: echoed,
            } if echoed == request_hash => {}
            _ => {
                return Err(TransportError::DcapVerification(
                    "enclave did not acknowledge the exact verifier request".into(),
                ))
            }
        }

        let mut offset = 0usize;
        for chunk in evidence
            .chunks(MAX_DCAP_VERIFICATION_CHUNK_BYTES)
            .chain(policy.chunks(MAX_DCAP_VERIFICATION_CHUNK_BYTES))
        {
            if chunk.is_empty() {
                continue;
            }
            let wire_offset = u32::try_from(offset).map_err(|_| {
                TransportError::DcapVerification("verification offset exceeds u32".into())
            })?;
            let next = offset.checked_add(chunk.len()).ok_or_else(|| {
                TransportError::DcapVerification("verification offset overflow".into())
            })?;
            let expected_next = u32::try_from(next).map_err(|_| {
                TransportError::DcapVerification("verification offset exceeds u32".into())
            })?;
            match self.request(&EnclaveRequest::DcapVerificationChunkV1 {
                request_hash,
                offset: wire_offset,
                bytes: chunk.to_vec(),
            })? {
                EnclaveResponse::DcapVerificationChunkAcceptedV1 {
                    request_hash: echoed,
                    next_offset,
                } if echoed == request_hash && next_offset == expected_next => {}
                _ => {
                    return Err(TransportError::DcapVerification(
                        "enclave acknowledged a different verifier chunk".into(),
                    ))
                }
            }
            offset = next;
        }

        self.request(&EnclaveRequest::FinishDcapVerificationV1 { request_hash })
    }

    pub fn attestation_pub(&self) -> [u8; 32] {
        self.attestation_pub
    }
}

fn request_gramine_direct_dev_signature(
    attestation_pub: [u8; 32],
    intent: &RegistrationIntentV1,
    request: impl FnOnce(&EnclaveRequest) -> Result<EnclaveResponse, TransportError>,
) -> Result<[u8; 64], TransportError> {
    if intent.attestation_mode != AttestationMode::GramineDirectDev
        || intent.attestation_ed25519 != attestation_pub
    {
        return Err(TransportError::Attestation(
            "GramineDirectDev registration intent does not bind this enclave and mode".into(),
        ));
    }
    let canonical = intent
        .encode_canonical()
        .map_err(|error| TransportError::Codec(error.to_string()))?;
    match request(&EnclaveRequest::SignRegistrationIntentDevV1 {
        intent: canonical.clone(),
    })? {
        EnclaveResponse::RegistrationIntentSignedDevV1 {
            intent: echoed,
            enclave_signature,
        } if echoed == canonical => {
            let signature: [u8; 64] = enclave_signature.try_into().map_err(|_| {
                TransportError::Attestation(
                    "enclave returned a non-canonical GramineDirectDev Ed25519 signature".into(),
                )
            })?;
            if !intent.verify_enclave_signature(&signature) {
                return Err(TransportError::Attestation(
                    "enclave returned an invalid GramineDirectDev intent signature".into(),
                ));
            }
            Ok(signature)
        }
        _ => Err(TransportError::UnexpectedResponse),
    }
}

impl RemoteEnclaveClient {
    pub fn connect_endpoint(
        endpoint: &str,
        ticket: &RemoteSessionTicketV1,
        node_host: &NodeHostNoiseKey,
    ) -> Result<Self, TransportError> {
        if ticket.initiator_static_x25519 != node_host.public() {
            return Err(TransportError::Handshake(
                "remote ticket does not bind the supplied source NodeHost key".into(),
            ));
        }
        if ticket.deadline <= unix_time_seconds()? {
            return Err(TransportError::Handshake(
                "remote session ticket is expired".into(),
            ));
        }
        let client = AuthorizedEnclaveClient::connect_with_preamble(
            endpoint,
            &EnclaveRequest::OpenRemoteSessionV1 {
                ticket_id: ticket.ticket_id,
            },
            ticket.responder_static_x25519,
            node_host,
            [0; 32],
        )?;
        Ok(Self {
            stream: client.stream,
            noise: client.noise,
        })
    }

    pub fn public_keys(&mut self) -> Result<RemoteEnclavePublicKeysV1, TransportError> {
        match self.request(&EnclaveRequest::GetPublicKeys)? {
            EnclaveResponse::PublicKeys {
                offer_key_ready,
                recipient_x25519_pub,
                attestation_pub,
                noise_static_pub,
                tee_bls_pub,
                dkg_enc_pub,
                dkg_enc_sig,
            } => Ok(RemoteEnclavePublicKeysV1 {
                offer_key_ready,
                recipient_x25519_pub,
                attestation_pub,
                noise_static_pub,
                tee_bls_pub,
                dkg_enc_pub,
                dkg_enc_sig,
            }),
            _ => Err(TransportError::UnexpectedResponse),
        }
    }

    fn request(&mut self, request: &EnclaveRequest) -> Result<EnclaveResponse, TransportError> {
        let plaintext = encode_request(request)?;
        let mut ciphertext = vec![0_u8; plaintext.len() + 64];
        let length = self
            .noise
            .write_message(&plaintext, &mut ciphertext)
            .map_err(|error| TransportError::Noise(error.to_string()))?;
        with_io_phase(
            write_frame(&mut self.stream, &ciphertext[..length]),
            "remote encrypted enclave request write",
        )?;
        let ciphertext = with_io_phase(
            read_frame(&mut self.stream),
            "remote encrypted enclave response read",
        )?;
        let mut plaintext = vec![0_u8; ciphertext.len()];
        let length = self
            .noise
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|error| TransportError::Noise(error.to_string()))?;
        let response = decode_response(&plaintext[..length])?;
        if let EnclaveResponse::Error { message } = response {
            return Err(TransportError::EnclaveError(message));
        }
        Ok(response)
    }
}

fn unix_time_seconds() -> Result<u64, TransportError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TransportError::Handshake("system time precedes Unix epoch".into()))
}

fn validate_dcap_verification_response(
    attestation_pub: [u8; 32],
    expected_request_hash: B256,
    response: EnclaveResponse,
) -> Result<DcapVerificationOutcomeV1, TransportError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let EnclaveResponse::DcapVerificationFinishedV1 {
        request_hash,
        outcome,
        attestation_tag,
    } = response
    else {
        return Err(TransportError::UnexpectedResponse);
    };
    if request_hash != expected_request_hash {
        return Err(TransportError::DcapVerification(
            "enclave response request commitment mismatch".into(),
        ));
    }
    let canonical = DcapVerificationOutcomeV1::decode_canonical(&outcome).map_err(|code| {
        TransportError::DcapVerification(format!(
            "enclave response outcome is non-canonical: {:#06x}",
            code.code()
        ))
    })?;
    let preimage =
        dcap_verification_attestation_preimage(request_hash, &outcome).map_err(|code| {
            TransportError::DcapVerification(format!(
                "enclave response outcome is oversized: {:#06x}",
                code.code()
            ))
        })?;
    let verifying_key = VerifyingKey::from_bytes(&attestation_pub).map_err(|error| {
        TransportError::DcapVerification(format!("invalid enclave attestation key: {error}"))
    })?;
    let signature_bytes: [u8; 64] = attestation_tag.try_into().map_err(|tag: Vec<u8>| {
        TransportError::DcapVerification(format!(
            "invalid enclave verification tag length {}",
            tag.len()
        ))
    })?;
    verifying_key
        .verify_strict(&preimage, &Signature::from_bytes(&signature_bytes))
        .map_err(|error| {
            TransportError::DcapVerification(format!(
                "enclave verification tag is invalid: {error}"
            ))
        })?;
    Ok(canonical)
}

fn validate_dcap_onboarding_response(
    attestation_pub: [u8; 32],
    expected_request_hash: B256,
    response: EnclaveResponse,
) -> Result<DcapOnboardingVerificationResultV1, TransportError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let EnclaveResponse::DcapOnboardingVerificationFinishedV1 {
        request_hash,
        outcome,
        onboarding_artifact,
        attestation_tag,
    } = response
    else {
        return Err(TransportError::UnexpectedResponse);
    };
    if request_hash != expected_request_hash {
        return Err(TransportError::DcapVerification(
            "enclave onboarding response request commitment mismatch".into(),
        ));
    }
    let canonical = DcapVerificationOutcomeV1::decode_canonical(&outcome).map_err(|code| {
        TransportError::DcapVerification(format!(
            "enclave onboarding outcome is non-canonical: {:#06x}",
            code.code()
        ))
    })?;
    let artifact = if onboarding_artifact.is_empty() {
        None
    } else {
        Some(
            DcapOnboardingArtifactV1::decode_canonical(&onboarding_artifact).map_err(|code| {
                TransportError::DcapVerification(format!(
                    "enclave onboarding artifact is non-canonical: {:#06x}",
                    code.code()
                ))
            })?,
        )
    };
    match (&canonical, &artifact) {
        (DcapVerificationOutcomeV1::Accepted(_), Some(_))
        | (DcapVerificationOutcomeV1::Rejected(_), None) => {}
        _ => {
            return Err(TransportError::DcapVerification(
                "enclave onboarding outcome/artifact combination is invalid".into(),
            ))
        }
    }
    let preimage =
        dcap_onboarding_attestation_preimage(request_hash, &outcome, &onboarding_artifact)
            .map_err(|code| {
                TransportError::DcapVerification(format!(
                    "enclave onboarding response is oversized: {:#06x}",
                    code.code()
                ))
            })?;
    let verifying_key = VerifyingKey::from_bytes(&attestation_pub).map_err(|error| {
        TransportError::DcapVerification(format!("invalid enclave attestation key: {error}"))
    })?;
    let signature_bytes: [u8; 64] = attestation_tag.try_into().map_err(|tag: Vec<u8>| {
        TransportError::DcapVerification(format!(
            "invalid enclave onboarding tag length {}",
            tag.len()
        ))
    })?;
    verifying_key
        .verify_strict(&preimage, &Signature::from_bytes(&signature_bytes))
        .map_err(|error| {
            TransportError::DcapVerification(format!("enclave onboarding tag is invalid: {error}"))
        })?;
    Ok(DcapOnboardingVerificationResultV1 {
        outcome: canonical,
        artifact,
    })
}

fn validate_generated_dcap_quote(
    intent: &RegistrationIntentV1,
    canonical_intent: &[u8],
    expected_attestation_pub: [u8; 32],
    response: EnclaveResponse,
) -> Result<GeneratedDcapQuoteV1, TransportError> {
    if intent.attestation_ed25519 != expected_attestation_pub {
        return Err(TransportError::Attestation(
            "DCAP quote response key does not match the initialized enclave".into(),
        ));
    }
    let EnclaveResponse::DcapQuote {
        intent: echoed_intent,
        quote_body,
        enclave_signature,
        transition_key_ready_proof,
    } = response
    else {
        return Err(TransportError::UnexpectedResponse);
    };
    if echoed_intent != canonical_intent {
        return Err(TransportError::Attestation(
            "DCAP quote response echoed a different registration intent".into(),
        ));
    }
    if quote_body.is_empty() {
        return Err(TransportError::Attestation(
            "DCAP quote response is empty".into(),
        ));
    }
    let enclave_signature: [u8; 64] = enclave_signature.try_into().map_err(|_| {
        TransportError::Attestation(
            "DCAP quote enclave proof-of-possession signature must be 64 bytes".into(),
        )
    })?;
    if !intent.verify_enclave_signature(&enclave_signature) {
        return Err(TransportError::Attestation(
            "DCAP quote enclave proof of possession is invalid".into(),
        ));
    }
    let transition_key_ready_proof = if transition_key_ready_proof.is_empty() {
        None
    } else {
        Some(
            TransitionKeyReadyProofV1::decode_canonical(&transition_key_ready_proof)
                .map_err(|error| TransportError::Codec(error.to_string()))?,
        )
    };
    match (intent.operation, transition_key_ready_proof.as_ref()) {
        (AttestationOperationV1::TransitionEnclaveMeasurement, Some(proof)) => proof
            .verify_for_transition(intent, proof.resident_offer_public)
            .map_err(|error| TransportError::Attestation(error.to_string()))?,
        (AttestationOperationV1::TransitionEnclaveMeasurement, None) => {
            return Err(TransportError::Attestation(
                "transition quote response is missing its key-ready proof".into(),
            ));
        }
        (_, Some(_)) => {
            return Err(TransportError::Attestation(
                "non-transition quote response carries a key-ready proof".into(),
            ));
        }
        (_, None) => {}
    }
    Ok(GeneratedDcapQuoteV1 {
        quote_body,
        enclave_signature,
        transition_key_ready_proof,
    })
}

fn connect_endpoint_transport(endpoint: &str) -> Result<Transport, TransportError> {
    if endpoint.contains(':') {
        let stream = TcpStream::connect(endpoint)?;
        let _ = stream.set_nodelay(true);
        stream.set_read_timeout(Some(enclave_io_timeout()))?;
        stream.set_write_timeout(Some(enclave_io_timeout()))?;
        Ok(Transport::Tcp(stream))
    } else {
        let stream = UnixStream::connect(endpoint)?;
        stream.set_read_timeout(Some(enclave_io_timeout()))?;
        stream.set_write_timeout(Some(enclave_io_timeout()))?;
        Ok(Transport::Unix(stream))
    }
}

/// Extract the enclave identity fields from the quote response.
fn quote_identity(
    quote: &EnclaveResponse,
    noise_static_pub: [u8; 32],
) -> Result<QuoteIdentity, TransportError> {
    let EnclaveResponse::Quote {
        mrenclave,
        mrsigner,
        isv_svn,
        attestation_pub,
        attestation,
        ..
    } = quote
    else {
        return Err(TransportError::UnexpectedResponse);
    };
    Ok(QuoteIdentity {
        mrenclave: *mrenclave,
        mrsigner: *mrsigner,
        isv_svn: *isv_svn,
        attestation_pub: *attestation_pub,
        noise_static_pub,
        attestation: attestation.clone(),
    })
}

/// Public keys carried in a quote response and bound together through REPORT_DATA.
/// This structural validation does not perform DCAP signature verification or
/// establish production enclave admission. Returned by [`verify_peer_quote`].
#[derive(Clone, Copy, Debug)]
pub struct AttestedPeerKeys {
    pub recipient_x25519: [u8; 32],
    pub attestation_pub: [u8; 32],
    pub noise_static_pub: [u8; 32],
}

/// Validate an enclave quote response and return its bound keys. The connect
/// path pins `noise_static_pub`; callers may also bind a one-time registration
/// recipient without gaining any peer key-recovery surface.
///
/// Chain: (1) the cleartext public keys must hash to `report_data` (key
/// binding); (2) for a non-empty quote, cleartext measurements and report_data
/// must match the fields parsed from the quote. Empty quotes are accepted for
/// development transports. Production attestation is enforced separately by
/// the enclave-resident native QVL and TeeRegistry.
pub fn verify_peer_quote(quote: &EnclaveResponse) -> Result<AttestedPeerKeys, TransportError> {
    let EnclaveResponse::Quote {
        mrenclave,
        mrsigner,
        isv_svn,
        report_data,
        recipient_x25519_pub,
        attestation_pub,
        noise_static_pub,
        quote_body,
        attestation: _,
    } = quote
    else {
        return Err(TransportError::UnexpectedResponse);
    };

    // (1) REPORT_DATA binds the cleartext public keys to the attestation.
    let mut preimage = Vec::with_capacity(96);
    preimage.extend_from_slice(noise_static_pub);
    preimage.extend_from_slice(recipient_x25519_pub);
    preimage.extend_from_slice(attestation_pub);
    let binding = keccak256(&preimage);
    if binding != *report_data {
        return Err(TransportError::Attestation(
            "report_data key binding mismatch".to_string(),
        ));
    }

    // (2) A non-empty quote must be structurally consistent with the cleartext
    // fields. Signature and TCB verification belongs to the native QVL path.
    if !quote_body.is_empty() {
        let m = crate::quote::parse_quote_measurements(quote_body)
            .map_err(|e| TransportError::Attestation(format!("quote parse: {e}")))?;
        if B256::from(m.mrenclave) != *mrenclave
            || B256::from(m.mrsigner) != *mrsigner
            || m.isv_svn != *isv_svn
        {
            return Err(TransportError::Attestation(
                "cleartext measurements do not match the quote".to_string(),
            ));
        }
        if m.report_data[..32] != binding.as_slice()[..] {
            return Err(TransportError::Attestation(
                "quote report_data does not match the key binding".to_string(),
            ));
        }
    }

    Ok(AttestedPeerKeys {
        recipient_x25519: *recipient_x25519_pub,
        attestation_pub: *attestation_pub,
        noise_static_pub: *noise_static_pub,
    })
}

/// Validate the quote bindings and return the enclave Noise static public key to
/// pin in the connect path. Thin wrapper over [`verify_peer_quote`].
fn verify_quote(quote: &EnclaveResponse) -> Result<[u8; 32], TransportError> {
    Ok(verify_peer_quote(quote)?.noise_static_pub)
}

/// Verify a per-offer attestation tag - an Ed25519 signature over
/// [`crate::protocol::tribute_offer_attestation_preimage`] - against the peer's
/// session attestation public key, which [`verify_peer_quote`] binds to the quote
/// report data. This proves that the session-key holder signed the results; it is
/// not an independent enclave-attestation verdict. The tag is never persisted.
/// Returns a typed error on any mismatch.
pub fn verify_tribute_offer_attestation(
    attestation_pub: &[u8; 32],
    inputs_canonical_hash: B256,
    results: &[crate::protocol::TributeOfferResult],
    tag: &[u8],
) -> Result<(), TransportError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = VerifyingKey::from_bytes(attestation_pub).map_err(|e| {
        TransportError::TributeOfferAttestation(format!("bad attestation key: {e}"))
    })?;
    let sig_bytes: [u8; 64] = tag.try_into().map_err(|_| {
        TransportError::TributeOfferAttestation(format!("bad tag length {}", tag.len()))
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    let preimage =
        crate::protocol::tribute_offer_attestation_preimage(inputs_canonical_hash, results);
    vk.verify_strict(&preimage, &sig)
        .map_err(|e| TransportError::TributeOfferAttestation(format!("signature invalid: {e}")))
}

/// Verify a Gratis-op attestation tag - an Ed25519 signature over
/// [`crate::protocol::gratis_op_attestation_preimage`] - against the peer's
/// session attestation key. Same session-key-holder and verify-then-discard
/// semantics as [`verify_tribute_offer_attestation`]; the tag is never persisted.
pub fn verify_gratis_op_attestation(
    attestation_pub: &[u8; 32],
    inputs_canonical_hash: B256,
    result: &crate::protocol::GratisOpResult,
    tag: &[u8],
) -> Result<(), TransportError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = VerifyingKey::from_bytes(attestation_pub)
        .map_err(|e| TransportError::GratisOpAttestation(format!("bad attestation key: {e}")))?;
    let sig_bytes: [u8; 64] = tag.try_into().map_err(|_| {
        TransportError::GratisOpAttestation(format!("bad tag length {}", tag.len()))
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    let preimage = crate::protocol::gratis_op_attestation_preimage(inputs_canonical_hash, result);
    vk.verify_strict(&preimage, &sig)
        .map_err(|e| TransportError::GratisOpAttestation(format!("signature invalid: {e}")))
}

/// Verify a Promis-op attestation tag - the [`verify_gratis_op_attestation`]
/// analogue over [`crate::protocol::promis_op_attestation_preimage`]. Same
/// session-key-holder and verify-then-discard semantics; the tag is never
/// persisted.
pub fn verify_promis_op_attestation(
    attestation_pub: &[u8; 32],
    inputs_canonical_hash: B256,
    result: &crate::protocol::PromisOpResult,
    tag: &[u8],
) -> Result<(), TransportError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = VerifyingKey::from_bytes(attestation_pub)
        .map_err(|e| TransportError::PromisOpAttestation(format!("bad attestation key: {e}")))?;
    let sig_bytes: [u8; 64] = tag.try_into().map_err(|_| {
        TransportError::PromisOpAttestation(format!("bad tag length {}", tag.len()))
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    let preimage = crate::protocol::promis_op_attestation_preimage(inputs_canonical_hash, result);
    vk.verify_strict(&preimage, &sig)
        .map_err(|e| TransportError::PromisOpAttestation(format!("signature invalid: {e}")))
}

fn verify_fidelity_tag(
    attestation_pub: &[u8; 32],
    preimage: &[u8],
    tag: &[u8],
) -> Result<(), TransportError> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let vk = VerifyingKey::from_bytes(attestation_pub)
        .map_err(|e| TransportError::FidelityAttestation(format!("bad attestation key: {e}")))?;
    let sig_bytes: [u8; 64] = tag.try_into().map_err(|_| {
        TransportError::FidelityAttestation(format!("bad tag length {}", tag.len()))
    })?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(preimage, &sig)
        .map_err(|e| TransportError::FidelityAttestation(format!("signature invalid: {e}")))
}

/// Verify a standalone Fidelity cohort-op attestation tag. Same
/// verify-then-discard semantics as [`verify_gratis_op_attestation`].
pub fn verify_fidelity_cohort_attestation(
    attestation_pub: &[u8; 32],
    inputs_canonical_hash: B256,
    result: &crate::protocol::FidelityCohortResult,
    tag: &[u8],
) -> Result<(), TransportError> {
    let preimage =
        crate::protocol::fidelity_cohort_attestation_preimage(inputs_canonical_hash, result);
    verify_fidelity_tag(attestation_pub, &preimage, tag)
}

/// Verify a Fidelity league-snapshot attestation tag.
pub fn verify_fidelity_snapshot_attestation(
    attestation_pub: &[u8; 32],
    inputs_canonical_hash: B256,
    leagues: &[crate::protocol::FidelityLeagueEntry],
    tag: &[u8],
) -> Result<(), TransportError> {
    let preimage =
        crate::protocol::fidelity_snapshot_attestation_preimage(inputs_canonical_hash, leagues);
    verify_fidelity_tag(attestation_pub, &preimage, tag)
}

/// Verify a Fidelity index-query attestation tag.
pub fn verify_fidelity_query_attestation(
    attestation_pub: &[u8; 32],
    inputs_canonical_hash: B256,
    result: &crate::protocol::FidelityQueryResult,
    tag: &[u8],
) -> Result<(), TransportError> {
    let preimage =
        crate::protocol::fidelity_query_attestation_preimage(inputs_canonical_hash, result);
    verify_fidelity_tag(attestation_pub, &preimage, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration_intent(attestation_ed25519: [u8; 32]) -> RegistrationIntentV1 {
        use outbe_primitives::tee_attestation_v1::{
            AttestationMode, AttestationOperationV1, NodeIdV1,
        };

        let reth_p2p_public = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x14)).into(),
        )
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

        let mut intent = RegistrationIntentV1 {
            chain_id: [0x11; 32],
            genesis_hash: B256::repeat_byte(0x12),
            operation: AttestationOperationV1::RegisterEnclave,
            attestation_mode: AttestationMode::DcapRequired,
            policy_hash: B256::repeat_byte(0x13),
            node_id: NodeIdV1 { reth_p2p_public },
            enclave_id: B256::repeat_byte(0x16),
            binding_id: B256::repeat_byte(0x17),
            binding_version: 1,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: 0,
            requested_valid_until: 7_200,
            recipient_x25519: [0x18; 32],
            attestation_ed25519,
            noise_responder_x25519: [0x19; 32],
            node_host_authorization_hash: B256::repeat_byte(0x1a),
        };
        intent.enclave_id = intent.derived_enclave_id().unwrap();
        intent
    }

    fn dcap_response(canonical_intent: Vec<u8>, enclave_signature: Vec<u8>) -> EnclaveResponse {
        EnclaveResponse::DcapQuote {
            intent: canonical_intent,
            quote_body: vec![0x51; 512],
            enclave_signature,
            transition_key_ready_proof: Vec::new(),
        }
    }

    #[test]
    fn generated_dcap_quote_requires_exact_echo_and_enclave_pop() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signer = SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x21));
        let intent = registration_intent(signer.verifying_key().to_bytes());
        let canonical = intent.encode_canonical().unwrap();
        let signature = signer
            .sign(intent.intent_hash().unwrap().as_slice())
            .to_bytes()
            .to_vec();

        let accepted = validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            dcap_response(canonical.clone(), signature.clone()),
        )
        .unwrap();
        assert_eq!(accepted.quote_body.len(), 512);
        assert_eq!(accepted.enclave_signature.as_slice(), signature);

        let mut wrong_echo = canonical.clone();
        wrong_echo.push(0);
        assert!(validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            dcap_response(wrong_echo, signature.clone()),
        )
        .is_err());
        assert!(validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            dcap_response(canonical.clone(), vec![0; 63]),
        )
        .is_err());
        let mut bad_signature = signature;
        bad_signature[0] ^= 1;
        assert!(validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            dcap_response(canonical.clone(), bad_signature),
        )
        .is_err());
        assert!(validate_generated_dcap_quote(
            &intent,
            &canonical,
            [0x22; 32],
            EnclaveResponse::Error {
                message: "not trusted".into(),
            },
        )
        .is_err());
    }

    #[test]
    fn generated_transition_quote_requires_valid_key_ready_proof() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signer = SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x23));
        let mut intent = registration_intent(signer.verifying_key().to_bytes());
        intent.operation = AttestationOperationV1::TransitionEnclaveMeasurement;
        intent.registration_version = 1;
        intent.transition_nonce = 4;
        let canonical = intent.encode_canonical().unwrap();
        let enclave_signature = signer
            .sign(intent.intent_hash().unwrap().as_slice())
            .to_bytes()
            .to_vec();
        let mut proof = TransitionKeyReadyProofV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            transition_intent_hash: intent.intent_hash().unwrap(),
            candidate_manifest_hash: B256::repeat_byte(0x24),
            transition_nonce: intent.transition_nonce,
            resident_offer_public: [0x25; 32],
            candidate_attestation_signature: [0; 64],
        };
        proof.candidate_attestation_signature = signer
            .sign(proof.signing_hash().unwrap().as_slice())
            .to_bytes();
        let response = EnclaveResponse::DcapQuote {
            intent: canonical.clone(),
            quote_body: vec![0x51; 512],
            enclave_signature: enclave_signature.clone(),
            transition_key_ready_proof: proof.encode_canonical().unwrap(),
        };
        let accepted = validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            response,
        )
        .unwrap();
        assert_eq!(accepted.transition_key_ready_proof, Some(proof));

        assert!(validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            dcap_response(canonical.clone(), enclave_signature.clone()),
        )
        .is_err());
        proof.resident_offer_public[0] ^= 1;
        assert!(validate_generated_dcap_quote(
            &intent,
            &canonical,
            signer.verifying_key().to_bytes(),
            EnclaveResponse::DcapQuote {
                intent: canonical.clone(),
                quote_body: vec![0x51; 512],
                enclave_signature,
                transition_key_ready_proof: proof.encode_canonical().unwrap(),
            },
        )
        .is_err());
    }

    #[test]
    fn dcap_verification_response_requires_exact_hash_canonical_outcome_and_signature() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signer = SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x71));
        let public = signer.verifying_key().to_bytes();
        let request_hash = B256::repeat_byte(0x72);
        let outcome = DcapVerificationOutcomeV1::Rejected(
            crate::dcap_protocol::DcapRejectCodeV1::PlatformTcbRejected,
        )
        .encode_canonical()
        .unwrap();
        let tag = signer
            .sign(&dcap_verification_attestation_preimage(request_hash, &outcome).unwrap())
            .to_bytes()
            .to_vec();
        let response = || EnclaveResponse::DcapVerificationFinishedV1 {
            request_hash,
            outcome: outcome.clone(),
            attestation_tag: tag.clone(),
        };
        assert_eq!(
            validate_dcap_verification_response(public, request_hash, response()).unwrap(),
            DcapVerificationOutcomeV1::Rejected(
                crate::dcap_protocol::DcapRejectCodeV1::PlatformTcbRejected
            )
        );

        assert!(
            validate_dcap_verification_response(public, B256::repeat_byte(0x73), response())
                .is_err()
        );
        let mut bad_outcome = response();
        if let EnclaveResponse::DcapVerificationFinishedV1 { outcome, .. } = &mut bad_outcome {
            outcome.push(0);
        }
        assert!(validate_dcap_verification_response(public, request_hash, bad_outcome).is_err());
        let mut bad_tag = response();
        if let EnclaveResponse::DcapVerificationFinishedV1 {
            attestation_tag, ..
        } = &mut bad_tag
        {
            attestation_tag[0] ^= 1;
        }
        assert!(validate_dcap_verification_response(public, request_hash, bad_tag).is_err());
    }

    #[test]
    fn onboarding_response_requires_signed_exact_artifact_and_valid_pairing() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let signer = SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x31));
        let public = signer.verifying_key().to_bytes();
        let request_hash = B256::repeat_byte(0x32);
        let outcome = DcapVerificationOutcomeV1::Accepted(crate::dcap_protocol::DcapVerdictV1 {
            mrenclave: B256::repeat_byte(0x33),
            mrsigner: B256::repeat_byte(0x34),
            isv_prod_id: 1,
            isv_svn: 2,
            pck_ca: crate::dcap_protocol::DcapPckCaV1::Processor,
            fmspc: [0x35; 6],
            pce_id: 3,
            platform_tcb_status: crate::dcap_protocol::DcapPlatformTcbStatusV1::UpToDate,
            advisory_ids: Vec::new(),
            tcb_evaluation_data_number: 4,
            qe_tcb_evaluation_data_number: 5,
            collateral_valid_until: 6,
        })
        .encode_canonical()
        .unwrap();
        let artifact = DcapOnboardingArtifactV1 {
            context: crate::dcap_protocol::DcapOnboardingContextV1 {
                chain_id: [0x41; 32],
                genesis_hash: B256::repeat_byte(0x42),
                intent_hash: B256::repeat_byte(0x43),
                node_id_hash: B256::repeat_byte(0x44),
                enclave_id: B256::repeat_byte(0x45),
                binding_id: B256::repeat_byte(0x4a),
                policy_hash: B256::repeat_byte(0x4b),
                recipient_x25519: [0x46; 32],
                tribute_offer_public: [0x47; 32],
                key_epoch: 7,
                tribute_offer_epoch: 8,
            },
            nonce: [0x48; 12],
            ciphertext: vec![0x49; 112],
        }
        .encode_canonical()
        .unwrap();
        let tag = signer
            .sign(&dcap_onboarding_attestation_preimage(request_hash, &outcome, &artifact).unwrap())
            .to_bytes()
            .to_vec();
        let response = || EnclaveResponse::DcapOnboardingVerificationFinishedV1 {
            request_hash,
            outcome: outcome.clone(),
            onboarding_artifact: artifact.clone(),
            attestation_tag: tag.clone(),
        };
        let result = validate_dcap_onboarding_response(public, request_hash, response()).unwrap();
        assert!(matches!(
            result.outcome,
            DcapVerificationOutcomeV1::Accepted(_)
        ));
        assert!(result.artifact.is_some());

        let mut tampered = response();
        if let EnclaveResponse::DcapOnboardingVerificationFinishedV1 {
            onboarding_artifact,
            ..
        } = &mut tampered
        {
            let last = onboarding_artifact.len() - 1;
            onboarding_artifact[last] ^= 1;
        }
        assert!(validate_dcap_onboarding_response(public, request_hash, tampered).is_err());

        let rejected_with_artifact = EnclaveResponse::DcapOnboardingVerificationFinishedV1 {
            request_hash,
            outcome: DcapVerificationOutcomeV1::Rejected(
                crate::dcap_protocol::DcapRejectCodeV1::NodeSignatureInvalid,
            )
            .encode_canonical()
            .unwrap(),
            onboarding_artifact: artifact,
            attestation_tag: tag,
        };
        assert!(
            validate_dcap_onboarding_response(public, request_hash, rejected_with_artifact)
                .is_err()
        );
    }

    #[test]
    fn enclave_timeout_is_bounded_and_configurable_for_sgx() {
        assert_eq!(timeout_seconds_from(None), 30);
        assert_eq!(timeout_seconds_from(Some("120")), 120);
        assert_eq!(timeout_seconds_from(Some("0")), 30);
        assert_eq!(timeout_seconds_from(Some("invalid")), 30);
    }

    #[test]
    fn socket_eagain_is_reported_as_a_phase_timeout() {
        let error = TransportError::Io(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        let mapped = with_io_phase::<()>(Err(error), "DKG response read").unwrap_err();
        assert!(matches!(
            mapped,
            TransportError::IoTimeout {
                operation: "DKG response read",
                timeout_secs: 30
            }
        ));
    }
    use crate::quote::MIN_QUOTE_LEN;

    const RB: usize = 48; // report-body offset inside the quote

    /// Build a Quote response with a correct report_data key binding.
    fn quote_with(
        noise: [u8; 32],
        offer: [u8; 32],
        attest: [u8; 32],
        mrenclave: B256,
        mrsigner: B256,
        isv_svn: u16,
        quote_body: Vec<u8>,
    ) -> EnclaveResponse {
        let mut p = Vec::new();
        p.extend_from_slice(&noise);
        p.extend_from_slice(&offer);
        p.extend_from_slice(&attest);
        EnclaveResponse::Quote {
            mrenclave,
            mrsigner,
            isv_svn,
            report_data: keccak256(&p),
            recipient_x25519_pub: offer,
            attestation_pub: attest,
            noise_static_pub: noise,
            quote_body,
            attestation: "none (test)".to_string(),
        }
    }

    /// gramine-direct/bare: an empty quote is accepted and the bound key is the
    /// enclave Noise static key.
    #[test]
    fn accepts_unattested_empty_quote() {
        let q = quote_with([1; 32], [2; 32], [3; 32], B256::ZERO, B256::ZERO, 0, vec![]);
        let pinned = verify_quote(&q).unwrap();
        assert_eq!(pinned, [1u8; 32]);
    }

    /// A valid per-offer attestation tag verifies; tampering with the
    /// results, the inputs hash, the key, or the tag length is rejected.
    #[test]
    fn verify_tribute_offer_attestation_accepts_valid_rejects_tampering() {
        use crate::protocol::{TributeOfferResult, TributeOfferStatus};
        use alloy_primitives::{Address, U256};
        use ed25519_dalek::{Signer, SigningKey};

        let results = vec![TributeOfferResult {
            token_id: B256::repeat_byte(0x11),
            owner: Address::repeat_byte(0x22),
            issuance_amount_minor: U256::from(1_000u64),
            nominal_amount_minor: U256::from(2_000u64),
            effective_reference_price_minor: U256::from(3_000u64),
            su_hashes: vec!["0xabc".to_string()],
            wallet_addresses: vec![],
            sra_addresses: vec![],
            zk_expected_hashes: None,
            status: TributeOfferStatus::Created,
        }];
        let hash = B256::repeat_byte(0xAB);

        let sk = SigningKey::from_bytes(&outbe_primitives::test_keys::secret(7));
        let pk = sk.verifying_key().to_bytes();
        let preimage = crate::protocol::tribute_offer_attestation_preimage(hash, &results);
        let tag = sk.sign(&preimage).to_bytes();

        // Happy path.
        verify_tribute_offer_attestation(&pk, hash, &results, &tag).expect("valid tag verifies");

        // Tampered result -> reject.
        let mut tampered = results.clone();
        tampered[0].effective_reference_price_minor += U256::ONE;
        assert!(verify_tribute_offer_attestation(&pk, hash, &tampered, &tag).is_err());

        // Tampered inputs hash -> reject.
        assert!(
            verify_tribute_offer_attestation(&pk, B256::repeat_byte(0xCD), &results, &tag).is_err()
        );

        // Wrong key -> reject.
        let other = SigningKey::from_bytes(&outbe_primitives::test_keys::secret(8))
            .verifying_key()
            .to_bytes();
        assert!(verify_tribute_offer_attestation(&other, hash, &results, &tag).is_err());

        // Bad tag length -> reject.
        assert!(verify_tribute_offer_attestation(&pk, hash, &results, &[0u8; 10]).is_err());
    }

    /// Pin the REPORT_DATA preimage byte order on the host side. The host
    /// binds `keccak256(noise || recipient || attestation)`; a quote whose
    /// report_data uses any other field order must fail the binding. Mirrors the
    /// enclave's `report_data_preimage_order_is_pinned`.
    #[test]
    fn report_data_preimage_order_is_pinned_host() {
        let (noise, offer, attest) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        // Wrong order (noise || attest || offer) must NOT satisfy the binding.
        let mut wrong = Vec::new();
        wrong.extend_from_slice(&noise);
        wrong.extend_from_slice(&attest);
        wrong.extend_from_slice(&offer);
        let q = EnclaveResponse::Quote {
            mrenclave: B256::ZERO,
            mrsigner: B256::ZERO,
            isv_svn: 0,
            report_data: keccak256(&wrong),
            recipient_x25519_pub: offer,
            attestation_pub: attest,
            noise_static_pub: noise,
            quote_body: vec![],
            attestation: "none (test)".to_string(),
        };
        assert!(
            verify_quote(&q).is_err(),
            "a non-canonical preimage order must fail the report_data binding"
        );
    }

    /// A tampered cleartext public key breaks the report_data binding.
    #[test]
    fn rejects_report_data_binding_mismatch() {
        let mut q = quote_with([1; 32], [2; 32], [3; 32], B256::ZERO, B256::ZERO, 0, vec![]);
        if let EnclaveResponse::Quote {
            noise_static_pub, ..
        } = &mut q
        {
            *noise_static_pub = [9; 32]; // no longer hashes to report_data
        }
        assert!(verify_quote(&q).is_err());
    }

    /// Cleartext measurements that disagree with the quote are rejected (the
    /// quote bytes are the source of truth for this structural check).
    #[test]
    fn rejects_cleartext_measurements_not_matching_quote() {
        let (noise, offer, attest) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let mut body = vec![0u8; MIN_QUOTE_LEN];
        body[RB + 64..RB + 96].copy_from_slice(&[0xAA; 32]); // quote mrenclave
        body[RB + 128..RB + 160].copy_from_slice(&[0xBB; 32]); // quote mrsigner
        let mut p = Vec::new();
        p.extend_from_slice(&noise);
        p.extend_from_slice(&offer);
        p.extend_from_slice(&attest);
        let binding = keccak256(&p);
        body[RB + 320..RB + 352].copy_from_slice(binding.as_slice()); // quote report_data
                                                                      // cleartext claims mrenclave=CC, but the quote says AA -> reject.
        let q = quote_with(
            noise,
            offer,
            attest,
            B256::from([0xCC; 32]),
            B256::from([0xBB; 32]),
            0,
            body,
        );
        assert!(verify_quote(&q).is_err());
    }

    #[test]
    fn node_host_key_store_is_write_once_owner_only_and_never_regenerates() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("node-host-noise.key");
        let created = NodeHostNoiseKey::create_new(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            NodeHostNoiseKey::load(&path).unwrap().public(),
            created.public()
        );

        let create_error = NodeHostNoiseKey::create_new(&path).unwrap_err();
        assert!(matches!(
            create_error,
            TransportError::Io(ref error)
                if error.kind() == std::io::ErrorKind::AlreadyExists
        ));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NodeHostNoiseKey::load(&path)
            .unwrap_err()
            .to_string()
            .contains("exactly 0600"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0x11; 31]).unwrap();
        assert!(NodeHostNoiseKey::load(&path).is_err());
        std::fs::write(&path, [0x11; 33]).unwrap();
        assert!(NodeHostNoiseKey::load(&path)
            .unwrap_err()
            .to_string()
            .contains("exactly 32 bytes"));

        std::fs::remove_file(&path).unwrap();
        let target = root.path().join("node-host-noise-target.key");
        std::fs::write(&target, [0x22; 32]).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(NodeHostNoiseKey::load(&path).is_err());
        std::fs::remove_file(&path).unwrap();

        assert!(matches!(
            NodeHostNoiseKey::load(&path),
            Err(TransportError::Io(ref error))
                if error.kind() == std::io::ErrorKind::NotFound
        ));
    }
}
