//! `outbe-tee` - host-side TEE integration crate for the Tribute SGX enclave PoC.
//!
//! Architecture the DKG actor and all
//! gossip / ceremony bookkeeping live on the **node (host)**; the secret
//! material and key assembly live **inside the enclave**. This crate is the
//! host-side half: the neutral wire-protocol types, the framed-UDS + Noise-IK
//! codec, and the blocking client used from the precompile path.
//!
//! This crate MUST NOT contain secret-bearing cryptography - that lives only in
//! `bin/outbe-tee-enclave`. Here we keep the message contract and transport.

pub mod canary;
pub mod client;
pub mod client_global;
pub mod codec;
pub mod dcap_protocol;
#[cfg(feature = "native-dcap")]
pub mod dcap_v1;
pub mod errors;
pub mod finalized_admission;
pub mod host_collateral;
mod metrics;
#[cfg(feature = "native-dcap")]
pub mod native_qvl;
pub mod node_host;
pub mod offer_encrypt;
pub mod protocol;
pub mod quote;
pub mod release_dcap_artifacts;
pub mod remote_session;
pub mod session;
pub mod tee_dkg;

pub use canary::{TeeEnclaveHealthChannel, TeeEnclaveHealthSnapshot, TeeEnclaveHealthState};
pub use client::{
    verify_fidelity_cohort_attestation, verify_fidelity_query_attestation,
    verify_fidelity_snapshot_attestation, verify_gratis_op_attestation, verify_peer_quote,
    verify_promis_op_attestation, verify_tribute_offer_attestation, AttestedPeerKeys,
    AuthorizedEnclaveClient, EnclaveClient, EnclaveInitializationChallenge, GeneratedDcapQuoteV1,
    NodeHostNoiseKey, RemoteEnclaveClient, RemoteEnclavePublicKeysV1, RemoteSessionTicketV1,
};
pub use client_global::{
    generate_dcap_quote_v1, install_authorized_enclave_client, install_enclave_client,
    is_enclave_configured, prepare_gramine_direct_dev_onboarding_artifact_v1,
    resident_offer_public_key_state_v1, resident_offer_public_key_v1, try_with_enclave,
    verify_dcap_evidence_v1, verify_dcap_registration_and_seal_v1, InstallError,
    RuntimeEnclaveClient,
};
#[cfg(feature = "native-dcap")]
pub use dcap_v1::{dcap_collateral_validity_window_v1, DcapCollateralValidityWindowV1};
pub use errors::TransportError;
pub use host_collateral::acquire_dcap_collateral_v1;
pub use node_host::{
    clear_committed_join_checkpoint, connect_committed_node_host_enclave,
    connect_or_initialize_node_host_enclave, construct_finalized_replacement_authorization_v1,
    load_committed_enclave_manifest_v1, load_committed_join_relay, load_committed_join_submission,
    load_finalized_join_admission_anchor, load_replacement_candidate_relay,
    load_replacement_candidate_submission, persist_committed_join_relay,
    persist_committed_join_submission, persist_finalized_join_admission_anchor,
    persist_replacement_candidate_relay, persist_replacement_candidate_submission,
    prepare_node_host_enclave_replacement_candidate, promote_replacement_candidate,
    CommittedJoinRelayV1, CommittedJoinSubmissionV1, FinalizedJoinAdmissionAnchorV1,
    FinalizedReplacementAuthorizationV1, FinalizedReplacementBindingV1, NodeHostIdentityV1,
    ReplacementCandidateEnclaveV1, ReplacementCandidateRelayV1, ReplacementCandidateSubmissionV1,
};
pub use remote_session::{
    admit_remote_session_v1, admit_rpc_trusted_remote_session_v1, FinalizedRegistryBindingV1,
    FinalizedRegistryViewV1, RemoteSessionAdmissionError, RemoteSessionAdmissionV1,
    RemoteSessionExpectationV1, RpcTrustedRemoteSessionV1,
};
pub use session::EnclaveSession;
pub use tee_dkg::{CeremonyCoordinator, CeremonyOutcome, EnclaveChannel};

/// Noise pattern for the node <-> enclave channel: **IK** (the responder/enclave
/// static key is known to the initiator/host via the attested quote), with
/// X25519 + ChaChaPoly + SHA256.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Version of the enclave's durable, network-bound sealed-state payload.
/// Release metadata and the enclave decoder use this single constant.
pub const SEALED_STATE_SCHEMA_V1: u8 = 3;

/// Fixed, **public** HKDF-SHA256 salt for the tribute offer encryption key.
///
/// An HKDF salt provides domain separation, not confidentiality - it is not a
/// secret. It is a single protocol constant (the same for every enclave and every
/// client), so the derived ChaCha20Poly1305 key is deterministic across all
/// validators. A client encrypts an offer with
/// `key = HKDF-SHA256(salt = OFFER_HKDF_SALT, ikm = ECDHE(ephemeral, tribute_offer_pub),
/// info = b"tribute-factory-encryption")` and ChaCha20Poly1305 over the JSON
/// payload - the only public input the client must know besides the on-chain
/// offer public key. Value: ASCII `"outbe/tribute/offer-salt/v1"`, zero-padded.
pub const OFFER_HKDF_SALT: [u8; 32] = *b"outbe/tribute/offer-salt/v1\0\0\0\0\0";
