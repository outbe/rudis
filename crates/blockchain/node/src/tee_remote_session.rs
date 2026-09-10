//! Node-local finalized Registry authority for remote TEE sessions.
//!
//! Every local operation reads the current finality marker from the same
//! provider that supplies the canonical header and historical Registry state.
//! The production facade then installs the resulting one-use admission in the
//! local enclave. Peer discovery and ticket delivery are consumer wiring, not
//! another authority or finality protocol.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256, U256};
use outbe_primitives::{
    header::OutbeHeader,
    storage::{
        readonly::{ReadOnlyStorageProvider, StorageReader},
        StorageHandle,
    },
    tee_attestation_v1::{
        AttestationEvidenceV1, NodeHostAuthorizationWitnessV1, NodeIdV1, TeePolicyV1,
    },
};
use outbe_tee::{
    admit_remote_session_v1, construct_finalized_replacement_authorization_v1,
    load_replacement_candidate_submission, AuthorizedEnclaveClient, FinalizedRegistryBindingV1,
    FinalizedRegistryViewV1, FinalizedReplacementAuthorizationV1, FinalizedReplacementBindingV1,
    RemoteSessionAdmissionError, RemoteSessionAdmissionV1, RemoteSessionExpectationV1,
    RemoteSessionTicketV1, TransportError,
};
use outbe_teeregistry::{NodeEnclaveBindingV1, TeeRegistry};
use reth_provider::{BlockIdReader, HeaderProvider, StateProviderFactory};
use reth_storage_api::StateProvider;
use std::collections::BTreeMap;
use std::path::Path;

use crate::ocomp::finality::{verify_public_account_proof, PublicAccountProofV1};

/// Exact consensus-finalized number/hash read inside one node-owned Registry
/// operation. It is deliberately private so callers cannot retain a once-valid
/// marker and submit it after the node's finalized head has advanced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsensusFinalizedBlockV1 {
    number: u64,
    hash: B256,
}

impl ConsensusFinalizedBlockV1 {
    fn read(provider: &impl BlockIdReader) -> Result<Self, LocalRegistryAdmissionError> {
        let finalized = provider
            .finalized_block_num_hash()
            .map_err(provider_error)?
            .ok_or(LocalRegistryAdmissionError::FinalizedBlockUnavailable)?;
        if finalized.number == 0 || finalized.hash.is_zero() {
            return Err(LocalRegistryAdmissionError::MalformedFinalizedBlock);
        }
        let canonical_hash = provider
            .block_hash(finalized.number)
            .map_err(provider_error)?
            .ok_or(LocalRegistryAdmissionError::FinalizedBlockUnavailable)?;
        let canonical_number = provider
            .block_number(finalized.hash)
            .map_err(provider_error)?
            .ok_or(LocalRegistryAdmissionError::FinalizedBlockUnavailable)?;
        if canonical_hash != finalized.hash || canonical_number != finalized.number {
            return Err(LocalRegistryAdmissionError::FinalizedBlockNotCanonical);
        }
        Ok(Self {
            number: finalized.number,
            hash: finalized.hash,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LocalRegistryAdmissionError {
    #[error("local consensus-finalized block is unavailable")]
    FinalizedBlockUnavailable,
    #[error("local consensus-finalized block identity is malformed")]
    MalformedFinalizedBlock,
    #[error("local consensus-finalized block is not canonical")]
    FinalizedBlockNotCanonical,
    #[error("local finalized header is unavailable")]
    FinalizedHeaderUnavailable,
    #[error("local finalized header does not match the consensus-finalized marker")]
    FinalizedHeaderMismatch,
    #[error("local finalized state provider failed: {0}")]
    Provider(String),
    #[error("finalized Registry state is invalid: {0}")]
    Registry(String),
    #[error("source has no active V1 Registry binding in finalized state")]
    SourceBindingMissing,
    #[error("target has no active V1 Registry binding in finalized state")]
    TargetBindingMissing,
    #[error("replacement has no active V1 Registry binding in finalized state")]
    ReplacementBindingMissing,
    #[error("finalized replacement authorization failed: {0}")]
    ReplacementAuthorization(String),
    #[error("local enclave remote-session authorization failed: {0}")]
    Enclave(#[from] TransportError),
    #[error(transparent)]
    Admission(#[from] RemoteSessionAdmissionError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFinalizedSuccessorStatusV1 {
    pub view: FinalizedRegistryViewV1,
    pub staged_proposal_id: Option<U256>,
    pub staged_policy: Option<TeePolicyV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalFinalizedReplacementAuthorizationV1 {
    pub authorization: FinalizedReplacementAuthorizationV1,
    pub view: FinalizedRegistryViewV1,
    pub successor_activation_height: Option<u64>,
}

/// A finalized state root already authenticated by the caller's Outbe light
/// client. Construction is an explicit trust declaration: this module verifies
/// the Registry MPT against the root but does not advance or emulate that light
/// client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedFinalizedRegistryCheckpointV1 {
    view: FinalizedRegistryViewV1,
}

impl TrustedFinalizedRegistryCheckpointV1 {
    pub fn from_light_client(
        view: FinalizedRegistryViewV1,
    ) -> Result<Self, ExternalRegistryAdmissionError> {
        if view.chain_id == [0; 32]
            || view.genesis_hash.is_zero()
            || view.block_number == 0
            || view.block_hash.is_zero()
            || view.state_root.is_zero()
            || view.consensus_timestamp == 0
        {
            return Err(ExternalRegistryAdmissionError::MalformedCheckpoint);
        }
        Ok(Self { view })
    }

    #[must_use]
    pub const fn view(self) -> FinalizedRegistryViewV1 {
        self.view
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExternalRegistryAdmissionError {
    #[error("trusted finalized Registry checkpoint is malformed")]
    MalformedCheckpoint,
    #[error("external Registry proof slot plan is invalid: {0}")]
    SlotPlan(String),
    #[error("external Registry MPT proof rejected: {0}")]
    Proof(String),
    #[error("external Registry state is invalid: {0}")]
    Registry(String),
    #[error("source has no active V1 Registry binding in anchored state")]
    SourceBindingMissing,
    #[error("target has no active V1 Registry binding in anchored state")]
    TargetBindingMissing,
    #[error(transparent)]
    Admission(#[from] RemoteSessionAdmissionError),
}

/// Production node-local route for authorizing one remote session.
///
/// This deep module owns the complete authority sequence: it resolves the
/// node's current consensus-finalized head, reads both exact Registry bindings,
/// validates the source witness and lease, and installs one bounded one-use
/// ticket in the local enclave. Transporting that ticket to the already chosen
/// peer is deliberately outside this interface and carries no authority.
pub fn authorize_local_finalized_remote_session_v1<P>(
    provider: &P,
    local_enclave: &mut AuthorizedEnclaveClient,
    chain_id: u64,
    genesis_hash: B256,
    expected: RemoteSessionExpectationV1,
    source_witness: &NodeHostAuthorizationWitnessV1,
    target_node: &NodeIdV1,
) -> Result<RemoteSessionTicketV1, LocalRegistryAdmissionError>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    let admission = admit_local_finalized_remote_session_v1(
        provider,
        chain_id,
        genesis_hash,
        expected,
        source_witness,
        target_node,
    )?;
    local_enclave
        .authorize_remote_session(&admission)
        .map_err(Into::into)
}

/// Low-level inspection seam used by the production authorization facade and
/// node integration tests. The caller cannot supply or retain a finalized
/// marker: this operation reads the node's current marker itself.
#[doc(hidden)]
pub fn admit_local_finalized_remote_session_v1<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: B256,
    expected: RemoteSessionExpectationV1,
    source_witness: &NodeHostAuthorizationWitnessV1,
    target_node: &NodeIdV1,
) -> Result<RemoteSessionAdmissionV1, LocalRegistryAdmissionError>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    with_local_finalized_registry(provider, chain_id, genesis_hash, |view, registry| {
        let source = registry
            .node_enclave_binding_for_identity_v1(&source_witness.node_id)
            .map_err(registry_error)?
            .ok_or(LocalRegistryAdmissionError::SourceBindingMissing)?;
        let target = registry
            .node_enclave_binding_for_identity_v1(target_node)
            .map_err(registry_error)?
            .ok_or(LocalRegistryAdmissionError::TargetBindingMissing)?;

        admit_remote_session_v1(
            expected,
            source_witness,
            registry_binding(view, source),
            registry_binding(view, target),
        )
        .map_err(Into::into)
    })
}

/// Issues the I5 opaque promotion capability from this node's exact
/// consensus-finalized Registry state. There is intentionally no RPC-trusted
/// counterpart: replacement promotion is a local node authority decision.
pub fn construct_local_finalized_replacement_authorization_v1<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: B256,
    node_data_dir: &Path,
    node_id: &NodeIdV1,
) -> Result<FinalizedReplacementAuthorizationV1, LocalRegistryAdmissionError>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    construct_local_finalized_replacement_authorization_with_view_v1(
        provider,
        chain_id,
        genesis_hash,
        node_data_dir,
        node_id,
    )
    .map(|result| result.authorization)
}

/// Same authority constructor as
/// [`construct_local_finalized_replacement_authorization_v1`], with the exact
/// finalized marker needed by the node-owned durable promotion watcher.
pub fn construct_local_finalized_replacement_authorization_with_view_v1<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: B256,
    node_data_dir: &Path,
    node_id: &NodeIdV1,
) -> Result<LocalFinalizedReplacementAuthorizationV1, LocalRegistryAdmissionError>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    with_local_finalized_registry(provider, chain_id, genesis_hash, |view, registry| {
        let binding = registry
            .node_enclave_binding_for_identity_v1(node_id)
            .map_err(registry_error)?
            .ok_or(LocalRegistryAdmissionError::ReplacementBindingMissing)?;
        let submission = load_replacement_candidate_submission(node_data_dir).map_err(|error| {
            LocalRegistryAdmissionError::ReplacementAuthorization(error.to_string())
        })?;
        let submission = submission.ok_or_else(|| {
            LocalRegistryAdmissionError::ReplacementAuthorization(
                "durable replacement submission is missing".into(),
            )
        })?;
        let AttestationEvidenceV1::Dcap(dcap) =
            AttestationEvidenceV1::decode_canonical(submission.evidence()).map_err(|error| {
                LocalRegistryAdmissionError::ReplacementAuthorization(error.to_string())
            })?
        else {
            return Err(LocalRegistryAdmissionError::ReplacementAuthorization(
                "durable replacement evidence is not DCAP".into(),
            ));
        };
        let intent_hash = dcap.intent.intent_hash().map_err(|error| {
            LocalRegistryAdmissionError::ReplacementAuthorization(error.to_string())
        })?;
        if binding.intent_hash != intent_hash
            || binding.enclave_id != dcap.intent.enclave_id
            || binding.binding_id != dcap.intent.binding_id
            || binding.binding_version != dcap.intent.binding_version
            || binding.registration_version != dcap.intent.registration_version
            || binding.transition_nonce != dcap.intent.transition_nonce
        {
            return Err(LocalRegistryAdmissionError::ReplacementBindingMissing);
        }
        let finalized_binding = FinalizedReplacementBindingV1 {
            view,
            node_id_hash: binding.node_id_hash,
            enclave_id: binding.enclave_id,
            binding_id: binding.binding_id,
            intent_hash: binding.intent_hash,
            binding_version: binding.binding_version,
            registration_version: binding.registration_version,
            valid_until: binding.valid_until,
            recipient_x25519: binding.recipient_x25519.into(),
            attestation_ed25519: binding.attestation_ed25519.into(),
            noise_responder_x25519: binding.noise_responder_x25519.into(),
            node_host_authorization_hash: binding.node_host_authorization_hash,
        };
        let authorization =
            construct_finalized_replacement_authorization_v1(node_data_dir, &finalized_binding)
                .map_err(|error| {
                    LocalRegistryAdmissionError::ReplacementAuthorization(error.to_string())
                })?;
        let successor_activation_height = registry
            .staged_successor_policy_v1()
            .map_err(registry_error)?
            .map(|(_, policy)| policy.activation_height);
        Ok(LocalFinalizedReplacementAuthorizationV1 {
            authorization,
            view,
            successor_activation_height,
        })
    })
}

/// Inspect only node-local consensus-finalized rollout state. This supplies
/// deadline alerts and terminal-cutoff decisions; it cannot authorize
/// candidate promotion.
pub fn inspect_local_finalized_successor_status_v1<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: B256,
) -> Result<LocalFinalizedSuccessorStatusV1, LocalRegistryAdmissionError>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    with_local_finalized_registry(provider, chain_id, genesis_hash, |view, registry| {
        let staged = registry
            .staged_successor_policy_v1()
            .map_err(registry_error)?;
        let (staged_proposal_id, staged_policy) = staged
            .map(|(proposal_id, policy)| (Some(proposal_id), Some(policy)))
            .unwrap_or((None, None));
        Ok(LocalFinalizedSuccessorStatusV1 {
            view,
            staged_proposal_id,
            staged_policy,
        })
    })
}

fn with_local_finalized_registry<P, T>(
    provider: &P,
    chain_id: u64,
    genesis_hash: B256,
    inspect: impl FnOnce(
        FinalizedRegistryViewV1,
        &TeeRegistry<'_>,
    ) -> Result<T, LocalRegistryAdmissionError>,
) -> Result<T, LocalRegistryAdmissionError>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    let finalized = ConsensusFinalizedBlockV1::read(provider)?;
    let canonical_hash = provider
        .block_hash(finalized.number)
        .map_err(provider_error)?
        .ok_or(LocalRegistryAdmissionError::FinalizedHeaderUnavailable)?;
    let canonical_number = provider
        .block_number(finalized.hash)
        .map_err(provider_error)?
        .ok_or(LocalRegistryAdmissionError::FinalizedHeaderUnavailable)?;
    if canonical_hash != finalized.hash || canonical_number != finalized.number {
        return Err(LocalRegistryAdmissionError::FinalizedHeaderMismatch);
    }
    let header = provider
        .sealed_header_by_hash(finalized.hash)
        .map_err(provider_error)?
        .ok_or(LocalRegistryAdmissionError::FinalizedHeaderUnavailable)?;
    if header.hash() != finalized.hash
        || header.number() != finalized.number
        || header.state_root().is_zero()
        || header.timestamp() == 0
    {
        return Err(LocalRegistryAdmissionError::FinalizedHeaderMismatch);
    }
    let state = provider
        .state_by_block_hash(finalized.hash)
        .map_err(provider_error)?;
    let reader = RethStateReader {
        state: state.as_ref(),
    };
    let mut storage =
        ReadOnlyStorageProvider::new_with_chain_identity(reader, chain_id, genesis_hash);
    let registry = TeeRegistry::new(StorageHandle::new(&mut storage));
    let view = FinalizedRegistryViewV1 {
        chain_id: chain_id_word(chain_id),
        genesis_hash,
        block_number: finalized.number,
        block_hash: finalized.hash,
        state_root: header.state_root(),
        consensus_timestamp: header.timestamp(),
    };
    inspect(view, &registry)
}

/// Verifies one exact Registry account/storage proof against a state root the
/// caller's light client has already recognized as finalized.
pub fn admit_anchored_remote_session_v1(
    checkpoint: TrustedFinalizedRegistryCheckpointV1,
    proof: &PublicAccountProofV1,
    expected: RemoteSessionExpectationV1,
    source_witness: &NodeHostAuthorizationWitnessV1,
    target_node: &NodeIdV1,
) -> Result<RemoteSessionAdmissionV1, ExternalRegistryAdmissionError> {
    let chain_id = chain_id_u64(checkpoint.view.chain_id)?;
    let mut layout_storage = ReadOnlyStorageProvider::new_with_chain_identity(
        ProofStorageReader {
            values: BTreeMap::new(),
        },
        chain_id,
        checkpoint.view.genesis_hash,
    );
    let layout_registry = TeeRegistry::new(StorageHandle::new(&mut layout_storage));
    let mut slots = layout_registry
        .node_enclave_binding_storage_slots_v1(&source_witness.node_id)
        .map_err(|error| ExternalRegistryAdmissionError::SlotPlan(error.to_string()))?;
    slots.extend(
        layout_registry
            .node_enclave_binding_storage_slots_v1(target_node)
            .map_err(|error| ExternalRegistryAdmissionError::SlotPlan(error.to_string()))?,
    );
    slots.sort_unstable();
    slots.dedup();
    verify_public_account_proof(
        proof,
        outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
        &slots,
        checkpoint.view.state_root,
    )
    .map_err(|error| ExternalRegistryAdmissionError::Proof(error.to_string()))?;

    let values = proof
        .storage_proofs
        .iter()
        .map(|entry| (entry.key, entry.value))
        .collect::<BTreeMap<_, _>>();
    let reader = ProofStorageReader { values };
    let mut storage = ReadOnlyStorageProvider::new_with_chain_identity(
        reader,
        chain_id,
        checkpoint.view.genesis_hash,
    );
    let registry = TeeRegistry::new(StorageHandle::new(&mut storage));
    let source = registry
        .node_enclave_binding_for_identity_v1(&source_witness.node_id)
        .map_err(|error| ExternalRegistryAdmissionError::Registry(error.to_string()))?
        .ok_or(ExternalRegistryAdmissionError::SourceBindingMissing)?;
    let target = registry
        .node_enclave_binding_for_identity_v1(target_node)
        .map_err(|error| ExternalRegistryAdmissionError::Registry(error.to_string()))?
        .ok_or(ExternalRegistryAdmissionError::TargetBindingMissing)?;
    admit_remote_session_v1(
        expected,
        source_witness,
        registry_binding(checkpoint.view, source),
        registry_binding(checkpoint.view, target),
    )
    .map_err(Into::into)
}

fn registry_binding(
    view: FinalizedRegistryViewV1,
    binding: NodeEnclaveBindingV1,
) -> FinalizedRegistryBindingV1 {
    FinalizedRegistryBindingV1 {
        view,
        node_id_hash: binding.node_id_hash,
        enclave_id: binding.enclave_id,
        binding_id: binding.binding_id,
        intent_hash: binding.intent_hash,
        valid_until: binding.valid_until,
        noise_responder_x25519: binding.noise_responder_x25519.into(),
        node_host_authorization_hash: binding.node_host_authorization_hash,
    }
}

struct RethStateReader<'a> {
    state: &'a dyn StateProvider,
}

struct ProofStorageReader {
    values: BTreeMap<B256, U256>,
}

impl StorageReader for ProofStorageReader {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        if address != outbe_primitives::addresses::TEE_REGISTRY_ADDRESS {
            return Err(outbe_primitives::error::PrecompileError::Storage(
                "anchored proof reader is restricted to TeeRegistry".into(),
            ));
        }
        Ok(self.values.get(&key).copied().unwrap_or_default())
    }
}

impl StorageReader for RethStateReader<'_> {
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage(address, key)
            .map(|value| value.unwrap_or(U256::ZERO))
            .map_err(|error| {
                outbe_primitives::error::PrecompileError::Storage(format!(
                    "finalized state read failed: {error}"
                ))
            })
    }
}

fn chain_id_word(chain_id: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&chain_id.to_be_bytes());
    word
}

fn chain_id_u64(chain_id: [u8; 32]) -> Result<u64, ExternalRegistryAdmissionError> {
    if chain_id[..24] != [0; 24] {
        return Err(ExternalRegistryAdmissionError::MalformedCheckpoint);
    }
    Ok(u64::from_be_bytes(chain_id[24..].try_into().map_err(
        |_| ExternalRegistryAdmissionError::MalformedCheckpoint,
    )?))
}

fn provider_error(error: impl core::fmt::Display) -> LocalRegistryAdmissionError {
    LocalRegistryAdmissionError::Provider(error.to_string())
}

fn registry_error(error: impl core::fmt::Display) -> LocalRegistryAdmissionError {
    LocalRegistryAdmissionError::Registry(error.to_string())
}
