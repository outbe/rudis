//! Finalized-state admission for remote Noise IK sessions.
//!
//! This module returns only the initiator pin, responder pin, finalized view and
//! exclusive deadline needed by transport. It does not grant an owner role or
//! authorize any secret-bearing command.

use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::NodeHostAuthorizationWitnessV1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedRegistryViewV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub block_number: u64,
    pub block_hash: B256,
    pub state_root: B256,
    pub consensus_timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedRegistryBindingV1 {
    pub view: FinalizedRegistryViewV1,
    pub node_id_hash: B256,
    pub enclave_id: B256,
    pub binding_id: B256,
    pub intent_hash: B256,
    pub valid_until: u64,
    pub noise_responder_x25519: [u8; 32],
    pub node_host_authorization_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteSessionExpectationV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub source_node_id_hash: B256,
    pub target_node_id_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteSessionAdmissionV1 {
    initiator_static_x25519: [u8; 32],
    responder_static_x25519: [u8; 32],
    deadline: u64,
    finalized_view: FinalizedRegistryViewV1,
}

/// Structurally checked Registry data accepted only because the caller
/// explicitly trusts its RPC provider. This deliberately cannot be passed as a
/// [`RemoteSessionAdmissionV1`]; enclave/server admission requires the local or
/// anchored finalized-state paths instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcTrustedRemoteSessionV1 {
    admission: RemoteSessionAdmissionV1,
}

impl RpcTrustedRemoteSessionV1 {
    #[must_use]
    pub const fn initiator_static_x25519(&self) -> [u8; 32] {
        self.admission.initiator_static_x25519()
    }

    #[must_use]
    pub const fn responder_static_x25519(&self) -> [u8; 32] {
        self.admission.responder_static_x25519()
    }

    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.admission.deadline()
    }

    /// View claimed by the trusted RPC provider; unlike an anchored admission,
    /// this method name makes the trust downgrade visible at every call site.
    #[must_use]
    pub const fn rpc_claimed_view(&self) -> FinalizedRegistryViewV1 {
        self.admission.finalized_view()
    }
}

impl RemoteSessionAdmissionV1 {
    #[must_use]
    pub const fn initiator_static_x25519(&self) -> [u8; 32] {
        self.initiator_static_x25519
    }

    #[must_use]
    pub const fn responder_static_x25519(&self) -> [u8; 32] {
        self.responder_static_x25519
    }

    /// Exclusive Unix timestamp deadline. No frame is admitted at or after it.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    #[must_use]
    pub const fn finalized_view(&self) -> FinalizedRegistryViewV1 {
        self.finalized_view
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoteSessionAdmissionError {
    #[error("finalized registry view is malformed")]
    MalformedFinalizedView,
    #[error("source and target bindings do not share one exact finalized view")]
    MixedFinalizedViews,
    #[error("finalized binding is malformed")]
    MalformedBinding,
    #[error("remote session proof is for another chain")]
    WrongChain,
    #[error("remote session proof is for another genesis")]
    WrongGenesis,
    #[error("remote session source node does not match")]
    WrongSourceNode,
    #[error("remote session target node does not match")]
    WrongTargetNode,
    #[error("NodeHost authorization witness is malformed")]
    MalformedSourceWitness,
    #[error("NodeHost authorization witness does not match the finalized source binding")]
    WrongSourceWitness,
    #[error("source registration lease is expired")]
    SourceExpired,
    #[error("target registration lease is expired")]
    TargetExpired,
}

/// Applies the common binding/lease checks after the caller has authenticated
/// both Registry bindings as one exact finalized view. Production server code
/// uses the node-local or anchored adapters rather than passing RPC values here;
/// this pre-authenticated inspection seam does not prove how the supplied view
/// obtained finality.
#[doc(hidden)]
pub fn admit_remote_session_v1(
    expected: RemoteSessionExpectationV1,
    source_witness: &NodeHostAuthorizationWitnessV1,
    source: FinalizedRegistryBindingV1,
    target: FinalizedRegistryBindingV1,
) -> Result<RemoteSessionAdmissionV1, RemoteSessionAdmissionError> {
    validate_view(source.view)?;
    if source.view != target.view {
        return Err(RemoteSessionAdmissionError::MixedFinalizedViews);
    }
    validate_binding(source)?;
    validate_binding(target)?;

    if source.view.chain_id != expected.chain_id {
        return Err(RemoteSessionAdmissionError::WrongChain);
    }
    if source.view.genesis_hash != expected.genesis_hash {
        return Err(RemoteSessionAdmissionError::WrongGenesis);
    }
    if source.node_id_hash != expected.source_node_id_hash {
        return Err(RemoteSessionAdmissionError::WrongSourceNode);
    }
    if target.node_id_hash != expected.target_node_id_hash {
        return Err(RemoteSessionAdmissionError::WrongTargetNode);
    }

    let witness_node_id_hash = source_witness
        .node_id
        .node_id_hash()
        .map_err(|_| RemoteSessionAdmissionError::MalformedSourceWitness)?;
    let witness_authorization_hash = source_witness
        .authorization_hash()
        .map_err(|_| RemoteSessionAdmissionError::MalformedSourceWitness)?;
    if source_witness.chain_id != expected.chain_id
        || source_witness.genesis_hash != expected.genesis_hash
        || witness_node_id_hash != expected.source_node_id_hash
        || witness_authorization_hash != source.node_host_authorization_hash
    {
        return Err(RemoteSessionAdmissionError::WrongSourceWitness);
    }

    if source.valid_until <= source.view.consensus_timestamp {
        return Err(RemoteSessionAdmissionError::SourceExpired);
    }
    if target.valid_until <= source.view.consensus_timestamp {
        return Err(RemoteSessionAdmissionError::TargetExpired);
    }

    Ok(RemoteSessionAdmissionV1 {
        initiator_static_x25519: source_witness.node_host_noise_x25519,
        responder_static_x25519: target.noise_responder_x25519,
        deadline: source.valid_until.min(target.valid_until),
        finalized_view: source.view,
    })
}

/// Explicit client-only downgrade for users that have no finalized anchor and
/// choose to trust one RPC provider. The distinct result type prevents this
/// path from silently becoming server/enclave admission authority.
pub fn admit_rpc_trusted_remote_session_v1(
    expected: RemoteSessionExpectationV1,
    source_witness: &NodeHostAuthorizationWitnessV1,
    source: FinalizedRegistryBindingV1,
    target: FinalizedRegistryBindingV1,
) -> Result<RpcTrustedRemoteSessionV1, RemoteSessionAdmissionError> {
    admit_remote_session_v1(expected, source_witness, source, target)
        .map(|admission| RpcTrustedRemoteSessionV1 { admission })
}

fn validate_view(view: FinalizedRegistryViewV1) -> Result<(), RemoteSessionAdmissionError> {
    if view.chain_id == [0; 32]
        || view.genesis_hash.is_zero()
        || view.block_number == 0
        || view.block_hash.is_zero()
        || view.state_root.is_zero()
        || view.consensus_timestamp == 0
    {
        return Err(RemoteSessionAdmissionError::MalformedFinalizedView);
    }
    Ok(())
}

fn validate_binding(
    binding: FinalizedRegistryBindingV1,
) -> Result<(), RemoteSessionAdmissionError> {
    if binding.node_id_hash.is_zero()
        || binding.enclave_id.is_zero()
        || binding.binding_id.is_zero()
        || binding.intent_hash.is_zero()
        || binding.valid_until == 0
        || binding.noise_responder_x25519 == [0; 32]
        || binding.node_host_authorization_hash.is_zero()
    {
        return Err(RemoteSessionAdmissionError::MalformedBinding);
    }
    Ok(())
}
