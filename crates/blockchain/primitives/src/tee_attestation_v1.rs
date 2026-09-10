//! Inactive V1 DCAP/remote-attestation protocol primitives.
//!
//! This module is compiled only for direct protocol harnesses until the
//! production activation stage. It deliberately defines no selector, storage
//! layout, dispatch route, or active ChainSpec field.

use alloy_primitives::{keccak256, B256};

pub const PROTOCOL_VERSION_V1: u8 = 1;

pub const POLICY_DOMAIN_V1: &[u8] = b"outbe/tee/policy/v1";
pub const POLICY_SCHEDULE_DOMAIN_V1: &[u8] = b"outbe/tee/policy-schedule/v1";
pub const TEE_REGISTRY_GAS_SCHEDULE_DOMAIN_V1: &[u8] = b"outbe/tee-registry-gas-schedule/v1";
pub const SYSTEM_GAS_SCHEDULE_DOMAIN_V1: &[u8] = b"outbe/system-gas-schedule/v1";
pub const RESOURCE_SCHEDULE_DOMAIN_V1: &[u8] = b"outbe/resource-schedule/v1";
pub const NODE_ID_DOMAIN_V1: &[u8] = b"outbe/tee/node-id/v1";
pub const VALIDATOR_NODE_BINDING_DOMAIN_V1: &[u8] = b"outbe/tee/validator-node-binding/v1";
pub const REGISTRATION_INTENT_DOMAIN_V1: &[u8] = b"outbe/tee/registration-intent/v1";
pub const ATTESTATION_EVIDENCE_DOMAIN_V1: &[u8] = b"outbe/tee/attestation-evidence/v1";
pub const ENCLAVE_ID_DOMAIN_V1: &[u8] = b"outbe/tee/enclave-id/v1";
pub const INITIALIZATION_MANIFEST_DOMAIN_V1: &[u8] = b"outbe/tee/initialization-manifest/v1";
pub const NODE_HOST_AUTHORIZATION_DOMAIN_V1: &[u8] = b"outbe/tee/node-host-authorization/v1";
pub const NETWORK_BINDING_DOMAIN_V1: &[u8] = b"outbe/tee/network-binding/v1";
pub const TRUSTED_NETWORK_DESCRIPTOR_DOMAIN_V1: &[u8] = b"outbe/tee/trusted-network-descriptor/v1";
pub const DKG_PARTICIPANT_SET_DOMAIN_V1: &[u8] = b"outbe/tee/dkg-participant-set/v1";
pub const DKG_CEREMONY_DOMAIN_V1: &[u8] = b"outbe/tee/dkg-ceremony/v1";
pub const DKG_PARTICIPANT_ANNOUNCE_DOMAIN_V1: &[u8] = b"outbe/tee/dkg-participant-announce/v1";
pub const TRANSITION_KEY_READY_PROOF_DOMAIN_V1: &[u8] = b"outbe/tee/transition-key-ready-proof/v1";
/// Maximum canonical size of one stable NodeHost authorization witness.
pub const MAX_NODE_HOST_AUTHORIZATION_WITNESS_BYTES: usize = 136;
pub const REPORT_POLICY_DOMAIN_V1: &[u8] = b"outbe/tee/report-policy/v1";

pub const MAX_QUOTE_BYTES: usize = 16 * 1024;
pub const MAX_COLLATERAL_COMPONENT_BYTES: usize = 896 * 1024;
pub const MAX_ATTESTATION_EVIDENCE_BYTES: usize = 896 * 1024;
pub const MAX_EVIDENCE_CALL_FRAMING_BYTES: usize = 16 * 1024;
pub const MAX_ACTIVE_MEASUREMENT_RULES: usize = 64;
pub const MAX_TEE_POLICY_BYTES: usize = 32 * 1024;
pub const MAX_TEE_POLICY_SCHEDULE_ENTRIES: usize = 64;
pub const MAX_TEE_BOOTSTRAP_BYTES: usize = 1_310_720;
pub use crate::system_tx::{BOOTSTRAP_BLOCK_GAS_LIMIT, STEADY_BLOCK_GAS_LIMIT};

/// The stage-I0 feature exposes codecs to direct harnesses only.
///
/// I9 replaces `None` with the ChainSpec-selected production manifest after
/// all preceding acceptance gates pass.
pub const ACTIVE_TEE_ATTESTATION_V1_MANIFEST: Option<TeeAttestationManifestV1> = None;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeeAttestationManifestV1 {
    pub activation_height: u64,
    pub policy_schedule_hash: B256,
    pub resource_schedule_hash: B256,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("unexpected end of canonical input")]
    UnexpectedEof,
    #[error("unsupported {field} version {value}")]
    UnsupportedVersion { field: &'static str, value: u8 },
    #[error("unknown {field} discriminant {value:#04x}")]
    UnknownDiscriminant { field: &'static str, value: u8 },
    #[error("{field} length {actual} exceeds limit {limit}")]
    LimitExceeded {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("non-canonical {0}")]
    NonCanonical(&'static str),
    #[error("{0} trailing bytes")]
    TrailingBytes(usize),
    #[error("checked arithmetic overflow")]
    ArithmeticOverflow,
    #[error("chain identity mismatch")]
    ChainIdentityMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestationMode {
    DcapRequired = 0x01,
    GramineDirectDev = 0x02,
}

impl AttestationMode {
    pub(crate) fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::DcapRequired),
            0x02 => Ok(Self::GramineDirectDev),
            value => Err(CodecError::UnknownDiscriminant {
                field: "attestation mode",
                value,
            }),
        }
    }
}

/// Immutable public identity of one TEE network. The binding is selected by the
/// ChainSpec and sealed by the enclave; it is never inferred from a host runtime
/// fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkBindingV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub attestation_mode: AttestationMode,
}

impl NetworkBindingV1 {
    pub const CANONICAL_LEN: usize = 1 + 32 + 32 + 1;

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(Self::CANONICAL_LEN);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.push(self.attestation_mode as u8);
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("NetworkBindingV1")?;
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            attestation_mode: AttestationMode::decode(decoder.u8()?)?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn binding_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            NETWORK_BINDING_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.chain_id == [0; 32] || self.genesis_hash.is_zero() {
            return Err(CodecError::NonCanonical(
                "network binding contains a zero chain identity",
            ));
        }
        Ok(())
    }
}

/// Release-measured authority for one production DCAP network.
///
/// The ordinary [`NetworkBindingV1`] is carried through node/enclave protocol
/// messages. A modified NodeHost can choose those bytes, so they are not by
/// themselves a trust root. Production DCAP bundles additionally measure this
/// descriptor as a Gramine trusted file. The enclave accepts an initialization
/// manifest only when its network binding equals this descriptor exactly.
///
/// `genesis_consensus_keys` are derived from that same final ChainSpec. The
/// sorted MinPk keys are the epoch-0 finality trust root; every later committee
/// must be authenticated by a certificate from its predecessor. The active TEE
/// policy is deliberately not measured here: it contains `MRENCLAVE`, while a
/// Gramine trusted file contributes to `MRENCLAVE`. Instead, onboarding proves
/// the active policy hash from finalized TeeRegistry state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedNetworkDescriptorV1 {
    pub network_binding: NetworkBindingV1,
    pub genesis_consensus_keys: Vec<[u8; 48]>,
}

impl TrustedNetworkDescriptorV1 {
    pub const FIXED_CANONICAL_LEN: usize = NetworkBindingV1::CANONICAL_LEN + 2;
    pub const MAX_GENESIS_CONSENSUS_KEYS: usize = 256;

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = self.network_binding.encode_canonical()?;
        out.extend_from_slice(&(self.genesis_consensus_keys.len() as u16).to_be_bytes());
        for key in &self.genesis_consensus_keys {
            out.extend_from_slice(key);
        }
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        if input.len() < Self::FIXED_CANONICAL_LEN {
            return Err(CodecError::NonCanonical(
                "trusted network descriptor length",
            ));
        }
        let mut decoder = Decoder::new(&input[NetworkBindingV1::CANONICAL_LEN..]);
        let network_binding =
            NetworkBindingV1::decode_canonical(&input[..NetworkBindingV1::CANONICAL_LEN])?;
        let key_count = usize::from(decoder.u16()?);
        if key_count == 0 || key_count > Self::MAX_GENESIS_CONSENSUS_KEYS {
            return Err(CodecError::NonCanonical(
                "trusted network descriptor genesis committee size",
            ));
        }
        let mut genesis_consensus_keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            genesis_consensus_keys.push(decoder.array::<48>()?);
        }
        decoder.finish()?;
        let value = Self {
            network_binding,
            genesis_consensus_keys,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn descriptor_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            TRUSTED_NETWORK_DESCRIPTOR_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    fn validate(&self) -> Result<(), CodecError> {
        self.network_binding.validate()?;
        if self.network_binding.attestation_mode != AttestationMode::DcapRequired {
            return Err(CodecError::NonCanonical(
                "trusted production network descriptor is not DCAP-required",
            ));
        }
        if self.genesis_consensus_keys.is_empty()
            || self.genesis_consensus_keys.len() > Self::MAX_GENESIS_CONSENSUS_KEYS
        {
            return Err(CodecError::NonCanonical(
                "trusted network descriptor genesis committee size",
            ));
        }
        if self
            .genesis_consensus_keys
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(CodecError::NonCanonical(
                "trusted network descriptor genesis committee order",
            ));
        }
        Ok(())
    }
}

/// Hash a non-empty DKG participant set in canonical BLS-public-key order.
/// Duplicate identities are rejected before any ceremony-specific signature is
/// produced or accepted.
pub fn dkg_participant_set_hash_v1(participant_bls: &[Vec<u8>]) -> Result<B256, CodecError> {
    if participant_bls.is_empty() {
        return Err(CodecError::NonCanonical("empty DKG participant set"));
    }
    let mut ordered = participant_bls.to_vec();
    ordered.sort();
    if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CodecError::NonCanonical(
            "duplicate DKG participant identity",
        ));
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        &u32::try_from(ordered.len())
            .map_err(|_| CodecError::ArithmeticOverflow)?
            .to_be_bytes(),
    );
    for public_key in ordered {
        encoded.extend_from_slice(
            &u32::try_from(public_key.len())
                .map_err(|_| CodecError::ArithmeticOverflow)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&public_key);
    }
    Ok(domain_hash(DKG_PARTICIPANT_SET_DOMAIN_V1, &encoded))
}

/// Derive the only accepted ceremony id for a network, round and exact
/// participant set. A host cannot reuse an announcement in another network or
/// silently open a different committee under the same id.
pub fn dkg_ceremony_id_v1(
    network_binding: &NetworkBindingV1,
    round: u64,
    participant_set_hash: B256,
) -> Result<B256, CodecError> {
    if participant_set_hash.is_zero() {
        return Err(CodecError::NonCanonical("zero DKG participant set hash"));
    }
    let mut encoded = network_binding.encode_canonical()?;
    encoded.extend_from_slice(&round.to_be_bytes());
    encoded.extend_from_slice(participant_set_hash.as_slice());
    Ok(domain_hash(DKG_CEREMONY_DOMAIN_V1, &encoded))
}

/// Exact digest signed by a DKG participant when announcing its share-recipient
/// key. Every ceremony discriminator is inside the signature.
pub fn dkg_participant_announce_hash_v1(
    network_binding: &NetworkBindingV1,
    ceremony_id: B256,
    round: u64,
    participant_set_hash: B256,
    dkg_enc_pub: &[u8; 32],
) -> Result<B256, CodecError> {
    let expected_ceremony = dkg_ceremony_id_v1(network_binding, round, participant_set_hash)?;
    if ceremony_id != expected_ceremony {
        return Err(CodecError::NonCanonical("non-canonical DKG ceremony id"));
    }
    let mut encoded = network_binding.encode_canonical()?;
    encoded.extend_from_slice(ceremony_id.as_slice());
    encoded.extend_from_slice(&round.to_be_bytes());
    encoded.extend_from_slice(participant_set_hash.as_slice());
    encoded.extend_from_slice(dkg_enc_pub);
    Ok(domain_hash(DKG_PARTICIPANT_ANNOUNCE_DOMAIN_V1, &encoded))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestationOperationV1 {
    RegisterEnclave = 0x01,
    RenewEnclave = 0x02,
    TransitionEnclaveMeasurement = 0x03,
    ReplaceEnclaveBinding = 0x04,
}

impl AttestationOperationV1 {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::RegisterEnclave),
            0x02 => Ok(Self::RenewEnclave),
            0x03 => Ok(Self::TransitionEnclaveMeasurement),
            0x04 => Ok(Self::ReplaceEnclaveBinding),
            value => Err(CodecError::UnknownDiscriminant {
                field: "attestation operation",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIdV1 {
    pub reth_p2p_public: [u8; 33],
}

impl NodeIdV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(38);
        self.encode_into(&mut out);
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub fn node_id_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(NODE_ID_DOMAIN_V1, &self.encode_canonical()?))
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(PROTOCOL_VERSION_V1);
        put_u32(out, 33);
        out.extend_from_slice(&self.reth_p2p_public);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        decoder.version("NodeIdV1")?;
        let payload_len = decoder.declared_len("node id payload", 33)?;
        if payload_len != 33 {
            return Err(CodecError::NonCanonical("node id length"));
        }
        let value = Self {
            reth_p2p_public: decoder.array()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if matches!(self.reth_p2p_public[0], 0x02 | 0x03)
            && self.reth_p2p_public[1..] != [0; 32]
            && k256::PublicKey::from_sec1_bytes(&self.reth_p2p_public).is_ok()
        {
            Ok(())
        } else {
            Err(CodecError::NonCanonical(
                "node id is not canonical compressed secp256k1",
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorNodeBindingV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub validator: [u8; 20],
    pub node_id_hash: B256,
}

impl ValidatorNodeBindingV1 {
    pub const CANONICAL_LEN: usize = 1 + 32 + 32 + 20 + 32;

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(Self::CANONICAL_LEN);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(self.node_id_hash.as_slice());
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        if input.len() != Self::CANONICAL_LEN {
            return Err(CodecError::NonCanonical(
                "validator NodeHost binding length",
            ));
        }
        let mut decoder = Decoder::new(input);
        decoder.version("ValidatorNodeBindingV1")?;
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            validator: decoder.array()?,
            node_id_hash: B256::from(decoder.array::<32>()?),
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn binding_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            VALIDATOR_NODE_BINDING_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    pub fn validate_chain_identity(
        &self,
        chain_id: [u8; 32],
        genesis_hash: B256,
    ) -> Result<(), CodecError> {
        if self.chain_id != chain_id || self.genesis_hash != genesis_hash {
            return Err(CodecError::ChainIdentityMismatch);
        }
        Ok(())
    }

    pub fn verify_validator_signature(&self, signature: &[u8; 65]) -> bool {
        let Ok(hash) = self.binding_hash() else {
            return false;
        };
        crate::tee_signatures::recover_signer(&hash, signature)
            .map(|recovered| recovered.as_slice() == self.validator)
            .unwrap_or(false)
    }

    pub fn verify_node_signature(&self, signature: &[u8; 65]) -> bool {
        let Ok(hash) = self.binding_hash() else {
            return false;
        };
        crate::tee_signatures::recover_signer_public_key(&hash, signature)
            .ok()
            .and_then(|reth_p2p_public| NodeIdV1 { reth_p2p_public }.node_id_hash().ok())
            == Some(self.node_id_hash)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.chain_id == [0; 32]
            || self.genesis_hash.is_zero()
            || self.validator == [0; 20]
            || self.node_id_hash.is_zero()
        {
            return Err(CodecError::NonCanonical(
                "validator NodeHost binding contains a zero identity or commitment",
            ));
        }
        Ok(())
    }
}

/// Bounded canonical preimage of the stable `NodeHost` authorization committed
/// by every registration. Remote peers disclose this public witness so the
/// target can recover the exact Noise IK initiator static from finalized state
/// without accepting a full initialization manifest or a host assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeHostAuthorizationWitnessV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub attestation_mode: AttestationMode,
    pub node_id: NodeIdV1,
    pub node_host_noise_x25519: [u8; 32],
}

impl NodeHostAuthorizationWitnessV1 {
    pub fn from_manifest(manifest: &EnclaveInitializationManifestV1) -> Result<Self, CodecError> {
        manifest.validate()?;
        Ok(Self {
            chain_id: manifest.chain_id,
            genesis_hash: manifest.genesis_hash,
            attestation_mode: manifest.attestation_mode,
            node_id: manifest.node_id.clone(),
            node_host_noise_x25519: manifest.node_host_noise_x25519,
        })
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(MAX_NODE_HOST_AUTHORIZATION_WITNESS_BYTES);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.push(self.attestation_mode as u8);
        self.node_id.encode_into(&mut out);
        out.extend_from_slice(&self.node_host_noise_x25519);
        enforce_limit(
            "NodeHost authorization witness",
            MAX_NODE_HOST_AUTHORIZATION_WITNESS_BYTES,
            out.len(),
        )?;
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        enforce_limit(
            "NodeHost authorization witness",
            MAX_NODE_HOST_AUTHORIZATION_WITNESS_BYTES,
            input.len(),
        )?;
        let mut decoder = Decoder::new(input);
        decoder.version("NodeHostAuthorizationWitnessV1")?;
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            attestation_mode: AttestationMode::decode(decoder.u8()?)?,
            node_id: NodeIdV1::decode_from(&mut decoder)?,
            node_host_noise_x25519: decoder.array()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn authorization_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            NODE_HOST_AUTHORIZATION_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    fn validate(&self) -> Result<(), CodecError> {
        self.node_id.validate()?;
        if self.chain_id == [0; 32]
            || self.genesis_hash.is_zero()
            || self.node_host_noise_x25519 == [0; 32]
        {
            return Err(CodecError::NonCanonical(
                "NodeHost authorization witness contains a zero identity or commitment",
            ));
        }
        Ok(())
    }
}

/// The single exact initialization manifest an enclave accepts before sealing
/// its V1 identity. The node signature is carried separately from this canonical
/// payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnclaveInitializationManifestV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub attestation_mode: AttestationMode,
    pub node_id: NodeIdV1,
    pub initialization_challenge: [u8; 32],
    pub node_host_noise_x25519: [u8; 32],
    pub recipient_x25519: [u8; 32],
    pub attestation_ed25519: [u8; 32],
    pub noise_responder_x25519: [u8; 32],
}

impl EnclaveInitializationManifestV1 {
    pub const fn network_binding(&self) -> NetworkBindingV1 {
        NetworkBindingV1 {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            attestation_mode: self.attestation_mode,
        }
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(300);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.push(self.attestation_mode as u8);
        self.node_id.encode_into(&mut out);
        out.extend_from_slice(&self.initialization_challenge);
        out.extend_from_slice(&self.node_host_noise_x25519);
        out.extend_from_slice(&self.recipient_x25519);
        out.extend_from_slice(&self.attestation_ed25519);
        out.extend_from_slice(&self.noise_responder_x25519);
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("EnclaveInitializationManifestV1")?;
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            attestation_mode: AttestationMode::decode(decoder.u8()?)?,
            node_id: NodeIdV1::decode_from(&mut decoder)?,
            initialization_challenge: decoder.array()?,
            node_host_noise_x25519: decoder.array()?,
            recipient_x25519: decoder.array()?,
            attestation_ed25519: decoder.array()?,
            noise_responder_x25519: decoder.array()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn authorization_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            INITIALIZATION_MANIFEST_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    /// Stable authority shared by successive enclave initializations for one
    /// node. Fresh initialization challenges and enclave keys are deliberately
    /// excluded; changing the persistent NodeHost key or node identity changes
    /// this commitment.
    pub fn node_host_authorization_hash(&self) -> Result<B256, CodecError> {
        NodeHostAuthorizationWitnessV1::from_manifest(self)?.authorization_hash()
    }

    /// Stable enclave identity derived from the three persistent public keys
    /// committed by every registration and renewal intent.
    pub fn enclave_id(&self) -> Result<B256, CodecError> {
        self.validate()?;
        let mut keys = [0u8; 96];
        keys[..32].copy_from_slice(&self.recipient_x25519);
        keys[32..64].copy_from_slice(&self.attestation_ed25519);
        keys[64..].copy_from_slice(&self.noise_responder_x25519);
        Ok(domain_hash(ENCLAVE_ID_DOMAIN_V1, &keys))
    }

    /// Verify the node proof of possession over the exact canonical manifest.
    /// Validators authorize with their EVM key; full nodes authorize with the
    /// compressed secp256k1 key already used as their Reth P2P identity.
    pub fn verify_node_signature(&self, signature: &[u8; 65]) -> bool {
        let Ok(hash) = self.authorization_hash() else {
            return false;
        };
        crate::tee_signatures::recover_signer_public_key(&hash, signature)
            .map(|recovered| recovered == self.node_id.reth_p2p_public)
            .unwrap_or(false)
    }

    /// Ensure a requested quote is for this exact initialized identity. Dynamic
    /// operation/version/nonce/lease/policy fields remain part of the intent and
    /// may change; node, chain, profile and persistent key authority may not.
    pub fn validate_intent_binding(&self, intent: &RegistrationIntentV1) -> Result<(), CodecError> {
        self.validate()?;
        intent.validate()?;
        if intent.chain_id != self.chain_id
            || intent.genesis_hash != self.genesis_hash
            || intent.attestation_mode != self.attestation_mode
            || intent.node_id != self.node_id
            || intent.enclave_id != self.enclave_id()?
            || intent.recipient_x25519 != self.recipient_x25519
            || intent.attestation_ed25519 != self.attestation_ed25519
            || intent.noise_responder_x25519 != self.noise_responder_x25519
            || intent.node_host_authorization_hash != self.node_host_authorization_hash()?
        {
            return Err(CodecError::NonCanonical(
                "registration intent does not match initialized enclave",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), CodecError> {
        self.node_id.validate()?;
        if self.chain_id == [0; 32]
            || self.genesis_hash.is_zero()
            || self.initialization_challenge == [0; 32]
            || self.node_host_noise_x25519 == [0; 32]
            || self.recipient_x25519 == [0; 32]
            || self.attestation_ed25519 == [0; 32]
            || self.noise_responder_x25519 == [0; 32]
        {
            return Err(CodecError::NonCanonical(
                "initialization manifest contains a zero identity or commitment",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationIntentV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub operation: AttestationOperationV1,
    pub attestation_mode: AttestationMode,
    pub policy_hash: B256,
    pub node_id: NodeIdV1,
    pub enclave_id: B256,
    pub binding_id: B256,
    pub binding_version: u64,
    pub registration_version: u64,
    pub renewal_nonce: u64,
    pub transition_nonce: u64,
    pub requested_valid_until: u64,
    pub recipient_x25519: [u8; 32],
    pub attestation_ed25519: [u8; 32],
    pub noise_responder_x25519: [u8; 32],
    pub node_host_authorization_hash: B256,
}

impl RegistrationIntentV1 {
    pub const fn network_binding(&self) -> NetworkBindingV1 {
        NetworkBindingV1 {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            attestation_mode: self.attestation_mode,
        }
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(352);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.push(self.operation as u8);
        out.push(self.attestation_mode as u8);
        out.extend_from_slice(self.policy_hash.as_slice());
        self.node_id.encode_into(&mut out);
        out.extend_from_slice(self.enclave_id.as_slice());
        out.extend_from_slice(self.binding_id.as_slice());
        put_u64(&mut out, self.binding_version);
        put_u64(&mut out, self.registration_version);
        put_u64(&mut out, self.renewal_nonce);
        put_u64(&mut out, self.transition_nonce);
        put_u64(&mut out, self.requested_valid_until);
        out.extend_from_slice(&self.recipient_x25519);
        out.extend_from_slice(&self.attestation_ed25519);
        out.extend_from_slice(&self.noise_responder_x25519);
        out.extend_from_slice(self.node_host_authorization_hash.as_slice());
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("RegistrationIntentV1")?;
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            operation: AttestationOperationV1::decode(decoder.u8()?)?,
            attestation_mode: AttestationMode::decode(decoder.u8()?)?,
            policy_hash: B256::from(decoder.array::<32>()?),
            node_id: NodeIdV1::decode_from(&mut decoder)?,
            enclave_id: B256::from(decoder.array::<32>()?),
            binding_id: B256::from(decoder.array::<32>()?),
            binding_version: decoder.u64()?,
            registration_version: decoder.u64()?,
            renewal_nonce: decoder.u64()?,
            transition_nonce: decoder.u64()?,
            requested_valid_until: decoder.u64()?,
            recipient_x25519: decoder.array()?,
            attestation_ed25519: decoder.array()?,
            noise_responder_x25519: decoder.array()?,
            node_host_authorization_hash: B256::from(decoder.array::<32>()?),
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn intent_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            REGISTRATION_INTENT_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    /// Verify the NodeHost proof of possession over this exact registration
    /// authorization. TeeRegistry separately authenticates the EVM caller
    /// against the canonical address-to-NodeHost association.
    pub fn verify_node_signature(&self, signature: &[u8; 65]) -> bool {
        let Ok(hash) = self.intent_hash() else {
            return false;
        };
        crate::tee_signatures::recover_signer_public_key(&hash, signature)
            .map(|recovered| recovered == self.node_id.reth_p2p_public)
            .unwrap_or(false)
    }

    /// Verify that the quote-bound enclave attestation key signed the same
    /// canonical authorization as the node identity.
    pub fn verify_enclave_signature(&self, signature: &[u8; 64]) -> bool {
        let Ok(hash) = self.intent_hash() else {
            return false;
        };
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, self.attestation_ed25519)
            .verify(hash.as_slice(), signature)
            .is_ok()
    }

    /// Derive the stable enclave identity from the three persistent public
    /// keys carried by this intent. Registry code uses this instead of trusting
    /// a caller-selected `enclave_id` as the one-to-one reverse-map key.
    pub fn derived_enclave_id(&self) -> Result<B256, CodecError> {
        self.validate()?;
        let mut keys = [0u8; 96];
        keys[..32].copy_from_slice(&self.recipient_x25519);
        keys[32..64].copy_from_slice(&self.attestation_ed25519);
        keys[64..].copy_from_slice(&self.noise_responder_x25519);
        Ok(domain_hash(ENCLAVE_ID_DOMAIN_V1, &keys))
    }

    pub fn report_policy_hash(&self) -> B256 {
        let mut canonical = [0u8; 96];
        canonical[..32].copy_from_slice(self.genesis_hash.as_slice());
        canonical[32..64].copy_from_slice(self.policy_hash.as_slice());
        canonical[64..].copy_from_slice(self.node_host_authorization_hash.as_slice());
        domain_hash(REPORT_POLICY_DOMAIN_V1, &canonical)
    }

    pub fn report_data(&self) -> Result<[u8; 64], CodecError> {
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(self.intent_hash()?.as_slice());
        report_data[32..].copy_from_slice(self.report_policy_hash().as_slice());
        Ok(report_data)
    }

    pub fn validate_chain_identity(
        &self,
        chain_id: [u8; 32],
        genesis_hash: B256,
    ) -> Result<(), CodecError> {
        if self.chain_id != chain_id || self.genesis_hash != genesis_hash {
            return Err(CodecError::ChainIdentityMismatch);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), CodecError> {
        self.node_id.validate()?;
        if self.genesis_hash.is_zero()
            || self.policy_hash.is_zero()
            || self.enclave_id.is_zero()
            || self.binding_id.is_zero()
            || self.node_host_authorization_hash.is_zero()
        {
            return Err(CodecError::NonCanonical(
                "registration intent contains a zero commitment",
            ));
        }
        if self.recipient_x25519 == [0; 32]
            || self.attestation_ed25519 == [0; 32]
            || self.noise_responder_x25519 == [0; 32]
        {
            return Err(CodecError::NonCanonical(
                "registration intent contains a zero public key",
            ));
        }
        if self.binding_version == 0 || self.requested_valid_until == 0 {
            return Err(CodecError::NonCanonical(
                "registration intent contains a zero version or lease",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DcapCollateralKind {
    PckCertificateChain = 0x01,
    PckCrl = 0x02,
    PckCrlIssuerChain = 0x03,
    RootCaCrl = 0x04,
    TcbInfo = 0x05,
    TcbInfoIssuerChain = 0x06,
    QeIdentity = 0x07,
    QeIdentityIssuerChain = 0x08,
}

impl TryFrom<u8> for DcapCollateralKind {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::PckCertificateChain),
            0x02 => Ok(Self::PckCrl),
            0x03 => Ok(Self::PckCrlIssuerChain),
            0x04 => Ok(Self::RootCaCrl),
            0x05 => Ok(Self::TcbInfo),
            0x06 => Ok(Self::TcbInfoIssuerChain),
            0x07 => Ok(Self::QeIdentity),
            0x08 => Ok(Self::QeIdentityIssuerChain),
            value => Err(CodecError::UnknownDiscriminant {
                field: "DCAP collateral component",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapCollateralComponentV1 {
    pub kind: DcapCollateralKind,
    pub bytes: Vec<u8>,
}

/// Candidate-enclave proof that a measurement successor already holds the
/// chain's permanent offer key before Registry binding mutation.
///
/// The candidate computes its own initialized-manifest hash and signs the
/// exact transition context with the quote-bound Ed25519 key. Registry can
/// independently verify every field except the local manifest journal link;
/// NodeHost additionally compares `candidate_manifest_hash` with its durable
/// candidate before persisting or promoting the submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionKeyReadyProofV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub transition_intent_hash: B256,
    pub candidate_manifest_hash: B256,
    pub transition_nonce: u64,
    pub resident_offer_public: [u8; 32],
    pub candidate_attestation_signature: [u8; 64],
}

impl TransitionKeyReadyProofV1 {
    pub const CANONICAL_LEN: usize = 1 + 32 + 32 + 32 + 32 + 8 + 32 + 64;

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(Self::CANONICAL_LEN);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.extend_from_slice(self.transition_intent_hash.as_slice());
        out.extend_from_slice(self.candidate_manifest_hash.as_slice());
        put_u64(&mut out, self.transition_nonce);
        out.extend_from_slice(&self.resident_offer_public);
        out.extend_from_slice(&self.candidate_attestation_signature);
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        if input.len() != Self::CANONICAL_LEN {
            return Err(CodecError::NonCanonical(
                "transition key-ready proof length",
            ));
        }
        let mut decoder = Decoder::new(input);
        decoder.version("TransitionKeyReadyProofV1")?;
        let value = Self {
            chain_id: decoder.array()?,
            genesis_hash: B256::from(decoder.array::<32>()?),
            transition_intent_hash: B256::from(decoder.array::<32>()?),
            candidate_manifest_hash: B256::from(decoder.array::<32>()?),
            transition_nonce: decoder.u64()?,
            resident_offer_public: decoder.array()?,
            candidate_attestation_signature: decoder.array()?,
        };
        decoder.finish()?;
        value.validate_shape()?;
        Ok(value)
    }

    /// Hash signed by the initialized candidate enclave. The signature itself
    /// is deliberately excluded from the preimage.
    pub fn signing_hash(&self) -> Result<B256, CodecError> {
        self.validate_shape()?;
        let mut canonical = Vec::with_capacity(Self::CANONICAL_LEN - 64);
        canonical.push(PROTOCOL_VERSION_V1);
        canonical.extend_from_slice(&self.chain_id);
        canonical.extend_from_slice(self.genesis_hash.as_slice());
        canonical.extend_from_slice(self.transition_intent_hash.as_slice());
        canonical.extend_from_slice(self.candidate_manifest_hash.as_slice());
        put_u64(&mut canonical, self.transition_nonce);
        canonical.extend_from_slice(&self.resident_offer_public);
        Ok(domain_hash(
            TRANSITION_KEY_READY_PROOF_DOMAIN_V1,
            &canonical,
        ))
    }

    /// Verify the proof against the exact transition intent and Registry offer
    /// public key. No host-supplied candidate or chain value is trusted.
    pub fn verify_for_transition(
        &self,
        intent: &RegistrationIntentV1,
        expected_offer_public: [u8; 32],
    ) -> Result<(), CodecError> {
        self.validate_shape()?;
        if intent.operation != AttestationOperationV1::TransitionEnclaveMeasurement
            || self.chain_id != intent.chain_id
            || self.genesis_hash != intent.genesis_hash
            || self.transition_intent_hash != intent.intent_hash()?
            || self.transition_nonce != intent.transition_nonce
            || self.resident_offer_public != expected_offer_public
        {
            return Err(CodecError::NonCanonical(
                "transition key-ready proof binding mismatch",
            ));
        }
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            intent.attestation_ed25519,
        )
        .verify(
            self.signing_hash()?.as_slice(),
            &self.candidate_attestation_signature,
        )
        .map_err(|_| CodecError::NonCanonical("transition key-ready proof signature"))
    }

    fn validate_shape(&self) -> Result<(), CodecError> {
        if self.chain_id == [0; 32]
            || self.genesis_hash.is_zero()
            || self.transition_intent_hash.is_zero()
            || self.candidate_manifest_hash.is_zero()
            || self.transition_nonce == 0
            || self.resident_offer_public == [0; 32]
        {
            return Err(CodecError::NonCanonical(
                "transition key-ready proof contains a zero commitment",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapEvidenceV1 {
    pub intent: RegistrationIntentV1,
    pub quote: Vec<u8>,
    pub components: Vec<DcapCollateralComponentV1>,
    pub transition_key_ready_proof: Option<TransitionKeyReadyProofV1>,
}

impl DcapEvidenceV1 {
    fn encode_payload(&self) -> Result<Vec<u8>, CodecError> {
        if self.intent.attestation_mode != AttestationMode::DcapRequired {
            return Err(CodecError::NonCanonical(
                "DCAP evidence intent mode mismatch",
            ));
        }
        enforce_limit("SGX quote", MAX_QUOTE_BYTES, self.quote.len())?;
        if self.quote.is_empty() {
            return Err(CodecError::NonCanonical("empty SGX quote"));
        }
        self.validate_components()?;
        self.validate_transition_proof_presence()?;

        let intent = self.intent.encode_canonical()?;
        let mut payload_len = checked_add_usize(1, 4)?;
        payload_len = checked_add_usize(payload_len, intent.len())?;
        payload_len = checked_add_usize(payload_len, 4)?;
        payload_len = checked_add_usize(payload_len, self.quote.len())?;
        payload_len = checked_add_usize(payload_len, 2)?;
        for component in &self.components {
            payload_len = checked_add_usize(payload_len, 5)?;
            payload_len = checked_add_usize(payload_len, component.bytes.len())?;
        }
        payload_len = checked_add_usize(payload_len, 1)?;
        let transition_proof = self
            .transition_key_ready_proof
            .as_ref()
            .map(TransitionKeyReadyProofV1::encode_canonical)
            .transpose()?;
        if let Some(proof) = &transition_proof {
            payload_len = checked_add_usize(payload_len, 2)?;
            payload_len = checked_add_usize(payload_len, proof.len())?;
        }
        let complete_len = checked_add_usize(6, payload_len)?;
        enforce_limit(
            "attestation evidence",
            MAX_ATTESTATION_EVIDENCE_BYTES,
            complete_len,
        )?;

        let mut out = Vec::with_capacity(payload_len);
        out.push(PROTOCOL_VERSION_V1);
        put_len_u32(&mut out, intent.len())?;
        out.extend_from_slice(&intent);
        put_len_u32(&mut out, self.quote.len())?;
        out.extend_from_slice(&self.quote);
        put_u16(&mut out, 8);
        for component in &self.components {
            out.push(component.kind as u8);
            put_len_u32(&mut out, component.bytes.len())?;
            out.extend_from_slice(&component.bytes);
        }
        match transition_proof {
            None => out.push(0),
            Some(proof) => {
                out.push(1);
                put_u16(
                    &mut out,
                    u16::try_from(proof.len()).map_err(|_| CodecError::ArithmeticOverflow)?,
                );
                out.extend_from_slice(&proof);
            }
        }
        Ok(out)
    }

    fn decode_payload(input: &[u8]) -> Result<Self, CodecError> {
        enforce_limit(
            "attestation evidence payload",
            MAX_ATTESTATION_EVIDENCE_BYTES,
            input.len(),
        )?;
        let mut decoder = Decoder::new(input);
        decoder.version("DcapEvidenceV1")?;
        let intent_len =
            decoder.declared_len("registration intent", MAX_EVIDENCE_CALL_FRAMING_BYTES)?;
        let intent = RegistrationIntentV1::decode_canonical(decoder.take(intent_len)?)?;
        if intent.attestation_mode != AttestationMode::DcapRequired {
            return Err(CodecError::NonCanonical(
                "DCAP evidence intent mode mismatch",
            ));
        }
        let quote_len = decoder.declared_len("SGX quote", MAX_QUOTE_BYTES)?;
        if quote_len == 0 {
            return Err(CodecError::NonCanonical("empty SGX quote"));
        }
        let quote = decoder.take(quote_len)?.to_vec();
        let component_count = decoder.u16()?;
        if component_count != 8 {
            return Err(CodecError::NonCanonical(
                "DCAP component count must be exactly eight",
            ));
        }
        let mut components = Vec::with_capacity(8);
        for expected_kind in 1u8..=8 {
            let kind = DcapCollateralKind::try_from(decoder.u8()?)?;
            if kind as u8 != expected_kind {
                return Err(CodecError::NonCanonical(
                    "DCAP component kinds must be exactly 0x01..=0x08",
                ));
            }
            let component_len = decoder
                .declared_len("DCAP collateral component", MAX_COLLATERAL_COMPONENT_BYTES)?;
            if component_len == 0 {
                return Err(CodecError::NonCanonical("empty DCAP collateral component"));
            }
            components.push(DcapCollateralComponentV1 {
                kind,
                bytes: decoder.take(component_len)?.to_vec(),
            });
        }
        let transition_key_ready_proof = match decoder.u8()? {
            0 => None,
            1 => {
                let proof_len = usize::from(decoder.u16()?);
                if proof_len != TransitionKeyReadyProofV1::CANONICAL_LEN {
                    return Err(CodecError::NonCanonical(
                        "transition key-ready proof length",
                    ));
                }
                Some(TransitionKeyReadyProofV1::decode_canonical(
                    decoder.take(proof_len)?,
                )?)
            }
            _ => {
                return Err(CodecError::NonCanonical(
                    "transition key-ready proof presence flag",
                ))
            }
        };
        decoder.finish()?;
        let value = Self {
            intent,
            quote,
            components,
            transition_key_ready_proof,
        };
        value.validate_transition_proof_presence()?;
        Ok(value)
    }

    fn validate_components(&self) -> Result<(), CodecError> {
        if self.components.len() != 8 {
            return Err(CodecError::NonCanonical(
                "DCAP component count must be exactly eight",
            ));
        }
        for (index, component) in self.components.iter().enumerate() {
            enforce_limit(
                "DCAP collateral component",
                MAX_COLLATERAL_COMPONENT_BYTES,
                component.bytes.len(),
            )?;
            if component.bytes.is_empty() {
                return Err(CodecError::NonCanonical("empty DCAP collateral component"));
            }
            if component.kind as u8 != (index + 1) as u8 {
                return Err(CodecError::NonCanonical(
                    "DCAP component kinds must be exactly 0x01..=0x08",
                ));
            }
        }
        Ok(())
    }

    fn validate_transition_proof_presence(&self) -> Result<(), CodecError> {
        let is_transition =
            self.intent.operation == AttestationOperationV1::TransitionEnclaveMeasurement;
        if is_transition != self.transition_key_ready_proof.is_some() {
            return Err(CodecError::NonCanonical(
                "transition key-ready proof presence does not match operation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GramineDirectEvidenceV1 {
    pub intent: RegistrationIntentV1,
    pub dev_attestation_public: [u8; 32],
    pub dev_signature: [u8; 64],
}

impl GramineDirectEvidenceV1 {
    fn encode_payload(&self) -> Result<Vec<u8>, CodecError> {
        if self.intent.attestation_mode != AttestationMode::GramineDirectDev {
            return Err(CodecError::NonCanonical(
                "Gramine evidence intent mode mismatch",
            ));
        }
        if self.dev_attestation_public == [0; 32] {
            return Err(CodecError::NonCanonical(
                "zero Gramine development attestation key",
            ));
        }
        let intent = self.intent.encode_canonical()?;
        let mut out = Vec::new();
        out.push(PROTOCOL_VERSION_V1);
        put_len_u32(&mut out, intent.len())?;
        out.extend_from_slice(&intent);
        out.extend_from_slice(&self.dev_attestation_public);
        out.extend_from_slice(&self.dev_signature);
        Ok(out)
    }

    fn decode_payload(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("GramineDirectEvidenceV1")?;
        let intent_len =
            decoder.declared_len("registration intent", MAX_EVIDENCE_CALL_FRAMING_BYTES)?;
        let value = Self {
            intent: RegistrationIntentV1::decode_canonical(decoder.take(intent_len)?)?,
            dev_attestation_public: decoder.array()?,
            dev_signature: decoder.array()?,
        };
        decoder.finish()?;
        if value.intent.attestation_mode != AttestationMode::GramineDirectDev {
            return Err(CodecError::NonCanonical(
                "Gramine evidence intent mode mismatch",
            ));
        }
        if value.dev_attestation_public == [0; 32] {
            return Err(CodecError::NonCanonical(
                "zero Gramine development attestation key",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationEvidenceV1 {
    Dcap(DcapEvidenceV1),
    GramineDirectDev(GramineDirectEvidenceV1),
}

impl AttestationEvidenceV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        let (mode, payload) = match self {
            Self::Dcap(value) => (AttestationMode::DcapRequired, value.encode_payload()?),
            Self::GramineDirectDev(value) => {
                (AttestationMode::GramineDirectDev, value.encode_payload()?)
            }
        };
        let mut out = Vec::new();
        out.push(PROTOCOL_VERSION_V1);
        out.push(mode as u8);
        put_len_u32(&mut out, payload.len())?;
        out.extend_from_slice(&payload);
        enforce_limit(
            "attestation evidence",
            MAX_ATTESTATION_EVIDENCE_BYTES,
            out.len(),
        )?;
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        enforce_limit(
            "attestation evidence",
            MAX_ATTESTATION_EVIDENCE_BYTES,
            input.len(),
        )?;
        let mut decoder = Decoder::new(input);
        decoder.version("AttestationEvidenceV1")?;
        let mode = AttestationMode::decode(decoder.u8()?)?;
        let payload_len = decoder.declared_len(
            "attestation evidence payload",
            MAX_ATTESTATION_EVIDENCE_BYTES,
        )?;
        let payload = decoder.take(payload_len)?;
        let value = match mode {
            AttestationMode::DcapRequired => Self::Dcap(DcapEvidenceV1::decode_payload(payload)?),
            AttestationMode::GramineDirectDev => {
                Self::GramineDirectDev(GramineDirectEvidenceV1::decode_payload(payload)?)
            }
        };
        decoder.finish()?;
        Ok(value)
    }

    pub fn evidence_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            ATTESTATION_EVIDENCE_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    pub const fn mode(&self) -> AttestationMode {
        match self {
            Self::Dcap(_) => AttestationMode::DcapRequired,
            Self::GramineDirectDev(_) => AttestationMode::GramineDirectDev,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QvlTcbStatusV1 {
    UpToDate = 0x01,
}

impl QvlTcbStatusV1 {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::UpToDate),
            value => Err(CodecError::UnknownDiscriminant {
                field: "accepted QVL TCB status",
                value,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PlatformTcbStatusSetV1 {
    /// Admit only Intel `UpToDate`.
    UpToDateOnly = 0x01,
    /// Admit `UpToDate`, `SWHardeningNeeded`, or
    /// `ConfigurationAndSWHardeningNeeded` while preserving the exact verdict.
    UpToDateOrHardeningNeeded = 0x02,
}

impl PlatformTcbStatusSetV1 {
    fn decode(value: u8) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::UpToDateOnly),
            0x02 => Ok(Self::UpToDateOrHardeningNeeded),
            value => Err(CodecError::UnknownDiscriminant {
                field: "accepted Platform TCB status set",
                value,
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeeMeasurementRuleV1 {
    pub mrenclave: B256,
    pub mrsigner: B256,
    pub isv_prod_id: u16,
    pub minimum_isv_svn: u16,
    pub admit_from_height: u64,
    pub admit_until_height_exclusive: u64,
}

impl TeeMeasurementRuleV1 {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        self.validate()?;
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(self.mrenclave.as_slice());
        out.extend_from_slice(self.mrsigner.as_slice());
        put_u16(out, self.isv_prod_id);
        put_u16(out, self.minimum_isv_svn);
        put_u64(out, self.admit_from_height);
        put_u64(out, self.admit_until_height_exclusive);
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, CodecError> {
        decoder.version("TeeMeasurementRuleV1")?;
        let value = Self {
            mrenclave: B256::from(decoder.array::<32>()?),
            mrsigner: B256::from(decoder.array::<32>()?),
            isv_prod_id: decoder.u16()?,
            minimum_isv_svn: decoder.u16()?,
            admit_from_height: decoder.u64()?,
            admit_until_height_exclusive: decoder.u64()?,
        };
        value.validate()?;
        Ok(value)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(85);
        self.encode_into(&mut out)?;
        Ok(out)
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.mrenclave.is_zero() || self.mrsigner.is_zero() {
            return Err(CodecError::NonCanonical(
                "measurement rule contains a zero measurement",
            ));
        }
        if self.admit_from_height >= self.admit_until_height_exclusive {
            return Err(CodecError::NonCanonical(
                "measurement admission interval is empty",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeePolicyV1 {
    pub policy_version: u64,
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub activation_height: u64,
    pub predecessor_policy_hash: B256,
    pub attestation_mode: AttestationMode,
    pub intel_root_der_hash: B256,
    pub quote_version: u16,
    pub tee_type: u32,
    pub attestation_key_type: u16,
    pub qe_vendor_id: [u8; 16],
    pub certification_data_type: u16,
    pub tcb_info_schema_version: u8,
    pub qe_identity_schema_version: u8,
    pub minimum_tcb_evaluation_data_number: u32,
    pub accepted_platform_tcb_statuses: PlatformTcbStatusSetV1,
    pub accepted_qe_tcb_status: QvlTcbStatusV1,
    pub minimum_lease: u64,
    pub maximum_lease: u64,
    pub collateral_margin: u64,
    pub resource_schedule_hash: B256,
    pub measurement_rules: Vec<TeeMeasurementRuleV1>,
}

impl TeePolicyV1 {
    pub const fn network_binding(&self) -> NetworkBindingV1 {
        NetworkBindingV1 {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            attestation_mode: self.attestation_mode,
        }
    }

    /// Counts rules that admit one authenticated enclave measurement at a
    /// height. Consensus admission requires the result to equal exactly one;
    /// zero and overlapping matches are both fail-closed.
    pub fn measurement_rule_match_count(
        &self,
        mrenclave: B256,
        mrsigner: B256,
        isv_prod_id: u16,
        isv_svn: u16,
        height: u64,
    ) -> usize {
        self.measurement_rules
            .iter()
            .filter(|rule| {
                rule.mrenclave == mrenclave
                    && rule.mrsigner == mrsigner
                    && rule.isv_prod_id == isv_prod_id
                    && isv_svn >= rule.minimum_isv_svn
                    && height >= rule.admit_from_height
                    && height < rule.admit_until_height_exclusive
            })
            .count()
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::new();
        out.push(PROTOCOL_VERSION_V1);
        put_u64(&mut out, self.policy_version);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        put_u64(&mut out, self.activation_height);
        out.extend_from_slice(self.predecessor_policy_hash.as_slice());
        out.push(self.attestation_mode as u8);
        out.extend_from_slice(self.intel_root_der_hash.as_slice());
        put_u16(&mut out, self.quote_version);
        put_u32(&mut out, self.tee_type);
        put_u16(&mut out, self.attestation_key_type);
        out.extend_from_slice(&self.qe_vendor_id);
        put_u16(&mut out, self.certification_data_type);
        out.push(self.tcb_info_schema_version);
        out.push(self.qe_identity_schema_version);
        put_u32(&mut out, self.minimum_tcb_evaluation_data_number);
        out.push(self.accepted_platform_tcb_statuses as u8);
        out.push(self.accepted_qe_tcb_status as u8);
        put_u64(&mut out, self.minimum_lease);
        put_u64(&mut out, self.maximum_lease);
        put_u64(&mut out, self.collateral_margin);
        out.extend_from_slice(self.resource_schedule_hash.as_slice());
        put_u16(
            &mut out,
            u16::try_from(self.measurement_rules.len())
                .map_err(|_| CodecError::ArithmeticOverflow)?,
        );
        for rule in &self.measurement_rules {
            rule.encode_into(&mut out)?;
        }
        enforce_limit("TEE policy", MAX_TEE_POLICY_BYTES, out.len())?;
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        enforce_limit("TEE policy", MAX_TEE_POLICY_BYTES, input.len())?;
        let mut decoder = Decoder::new(input);
        decoder.version("TeePolicyV1")?;
        let policy_version = decoder.u64()?;
        let chain_id = decoder.array()?;
        let genesis_hash = B256::from(decoder.array::<32>()?);
        let activation_height = decoder.u64()?;
        let predecessor_policy_hash = B256::from(decoder.array::<32>()?);
        let attestation_mode = AttestationMode::decode(decoder.u8()?)?;
        let intel_root_der_hash = B256::from(decoder.array::<32>()?);
        let quote_version = decoder.u16()?;
        let tee_type = decoder.u32()?;
        let attestation_key_type = decoder.u16()?;
        let qe_vendor_id = decoder.array()?;
        let certification_data_type = decoder.u16()?;
        let tcb_info_schema_version = decoder.u8()?;
        let qe_identity_schema_version = decoder.u8()?;
        let minimum_tcb_evaluation_data_number = decoder.u32()?;
        let accepted_platform_tcb_statuses = PlatformTcbStatusSetV1::decode(decoder.u8()?)?;
        let accepted_qe_tcb_status = QvlTcbStatusV1::decode(decoder.u8()?)?;
        let minimum_lease = decoder.u64()?;
        let maximum_lease = decoder.u64()?;
        let collateral_margin = decoder.u64()?;
        let resource_schedule_hash = B256::from(decoder.array::<32>()?);
        let rule_count = usize::from(decoder.u16()?);
        enforce_limit(
            "active measurement rules",
            MAX_ACTIVE_MEASUREMENT_RULES,
            rule_count,
        )?;
        if rule_count == 0 {
            return Err(CodecError::NonCanonical(
                "TEE policy has no measurement rules",
            ));
        }
        let mut measurement_rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            measurement_rules.push(TeeMeasurementRuleV1::decode_from(&mut decoder)?);
        }
        decoder.finish()?;
        let value = Self {
            policy_version,
            chain_id,
            genesis_hash,
            activation_height,
            predecessor_policy_hash,
            attestation_mode,
            intel_root_der_hash,
            quote_version,
            tee_type,
            attestation_key_type,
            qe_vendor_id,
            certification_data_type,
            tcb_info_schema_version,
            qe_identity_schema_version,
            minimum_tcb_evaluation_data_number,
            accepted_platform_tcb_statuses,
            accepted_qe_tcb_status,
            minimum_lease,
            maximum_lease,
            collateral_margin,
            resource_schedule_hash,
            measurement_rules,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn policy_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(POLICY_DOMAIN_V1, &self.encode_canonical()?))
    }

    fn validate(&self) -> Result<(), CodecError> {
        const INTEL_QE_VENDOR_ID: [u8; 16] = [
            0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
            0x06, 0x07,
        ];
        if self.policy_version == 0 || self.activation_height == 0 {
            return Err(CodecError::NonCanonical(
                "policy version and activation height must be nonzero",
            ));
        }
        if self.genesis_hash.is_zero()
            || self.intel_root_der_hash.is_zero()
            || self.resource_schedule_hash.is_zero()
        {
            return Err(CodecError::NonCanonical(
                "TEE policy contains a zero commitment",
            ));
        }
        if self.quote_version != 3
            || self.tee_type != 0
            || self.attestation_key_type != 2
            || self.qe_vendor_id != INTEL_QE_VENDOR_ID
            || self.certification_data_type != 5
            || self.tcb_info_schema_version != 3
            || self.qe_identity_schema_version != 2
        {
            return Err(CodecError::NonCanonical(
                "unsupported SGX DCAP policy profile",
            ));
        }
        if self.minimum_tcb_evaluation_data_number == 0 {
            return Err(CodecError::NonCanonical(
                "minimum TCB evaluation data number must be nonzero",
            ));
        }
        if self.minimum_lease < 3_600
            || self.maximum_lease > 2_592_000
            || self.minimum_lease > self.maximum_lease
            || !self.maximum_lease.is_multiple_of(2)
            || self.collateral_margin != 3_600
        {
            return Err(CodecError::NonCanonical("invalid TEE lease policy"));
        }
        if self.measurement_rules.is_empty() {
            return Err(CodecError::NonCanonical(
                "TEE policy has no measurement rules",
            ));
        }
        enforce_limit(
            "active measurement rules",
            MAX_ACTIVE_MEASUREMENT_RULES,
            self.measurement_rules.len(),
        )?;
        let mut previous: Option<Vec<u8>> = None;
        for rule in &self.measurement_rules {
            let bytes = rule.canonical_bytes()?;
            if previous.as_ref().is_some_and(|value| value >= &bytes) {
                return Err(CodecError::NonCanonical(
                    "measurement rules must be strictly sorted and unique",
                ));
            }
            previous = Some(bytes);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeePolicyScheduleEntryV1 {
    pub activation_height: u64,
    pub policy: TeePolicyV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeePolicyScheduleV1 {
    pub chain_id: [u8; 32],
    pub genesis_hash: B256,
    pub entries: Vec<TeePolicyScheduleEntryV1>,
}

impl TeePolicyScheduleV1 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::new();
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(self.genesis_hash.as_slice());
        put_u16(
            &mut out,
            u16::try_from(self.entries.len()).map_err(|_| CodecError::ArithmeticOverflow)?,
        );
        for entry in &self.entries {
            let policy = entry.policy.encode_canonical()?;
            put_u64(&mut out, entry.activation_height);
            put_len_u32(&mut out, policy.len())?;
            out.extend_from_slice(&policy);
            out.extend_from_slice(entry.policy.policy_hash()?.as_slice());
        }
        enforce_limit(
            "TEE policy schedule",
            MAX_TEE_POLICY_SCHEDULE_BYTES,
            out.len(),
        )?;
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        enforce_limit(
            "TEE policy schedule",
            MAX_TEE_POLICY_SCHEDULE_BYTES,
            input.len(),
        )?;
        let mut decoder = Decoder::new(input);
        decoder.version("TeePolicyScheduleV1")?;
        let chain_id = decoder.array()?;
        let genesis_hash = B256::from(decoder.array::<32>()?);
        let entry_count = usize::from(decoder.u16()?);
        enforce_limit(
            "TEE policy schedule entries",
            MAX_TEE_POLICY_SCHEDULE_ENTRIES,
            entry_count,
        )?;
        if entry_count == 0 {
            return Err(CodecError::NonCanonical("TEE policy schedule is empty"));
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let activation_height = decoder.u64()?;
            let policy_len = decoder.declared_len("TEE policy", MAX_TEE_POLICY_BYTES)?;
            let policy = TeePolicyV1::decode_canonical(decoder.take(policy_len)?)?;
            let cached_hash = B256::from(decoder.array::<32>()?);
            if cached_hash != policy.policy_hash()? {
                return Err(CodecError::NonCanonical("cached policy hash mismatch"));
            }
            entries.push(TeePolicyScheduleEntryV1 {
                activation_height,
                policy,
            });
        }
        decoder.finish()?;
        let value = Self {
            chain_id,
            genesis_hash,
            entries,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn schedule_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            POLICY_SCHEDULE_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    pub fn active_policy(&self, height: u64) -> Result<&TeePolicyV1, CodecError> {
        self.validate()?;
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.activation_height <= height)
            .map(|entry| &entry.policy)
            .ok_or(CodecError::NonCanonical(
                "no active TEE policy at requested height",
            ))
    }

    fn validate(&self) -> Result<(), CodecError> {
        if self.genesis_hash.is_zero() {
            return Err(CodecError::NonCanonical(
                "TEE policy schedule has zero genesis hash",
            ));
        }
        if self.entries.is_empty() {
            return Err(CodecError::NonCanonical("TEE policy schedule is empty"));
        }
        enforce_limit(
            "TEE policy schedule entries",
            MAX_TEE_POLICY_SCHEDULE_ENTRIES,
            self.entries.len(),
        )?;
        let first = &self.entries[0];
        if first.activation_height != 1
            || first.policy.activation_height != 1
            || first.policy.policy_version != 1
            || !first.policy.predecessor_policy_hash.is_zero()
        {
            return Err(CodecError::NonCanonical(
                "first TEE policy must be version one at block one",
            ));
        }
        let mut previous_hash = first.policy.policy_hash()?;
        let mut previous_version = first.policy.policy_version;
        let mut previous_height = first.activation_height;
        self.validate_entry_identity(first)?;
        for entry in self.entries.iter().skip(1) {
            self.validate_entry_identity(entry)?;
            if entry.activation_height <= previous_height
                || entry.policy.activation_height != entry.activation_height
            {
                return Err(CodecError::NonCanonical(
                    "policy activations must be strictly increasing",
                ));
            }
            let expected_version = previous_version
                .checked_add(1)
                .ok_or(CodecError::ArithmeticOverflow)?;
            if entry.policy.policy_version != expected_version {
                return Err(CodecError::NonCanonical(
                    "policy versions must increase by one",
                ));
            }
            if entry.policy.predecessor_policy_hash != previous_hash {
                return Err(CodecError::NonCanonical("policy predecessor hash mismatch"));
            }
            previous_hash = entry.policy.policy_hash()?;
            previous_version = entry.policy.policy_version;
            previous_height = entry.activation_height;
        }
        Ok(())
    }

    fn validate_entry_identity(&self, entry: &TeePolicyScheduleEntryV1) -> Result<(), CodecError> {
        if entry.policy.chain_id != self.chain_id || entry.policy.genesis_hash != self.genesis_hash
        {
            return Err(CodecError::ChainIdentityMismatch);
        }
        Ok(())
    }
}

pub const MAX_TEE_POLICY_SCHEDULE_BYTES: usize =
    1 + 32 + 32 + 2 + MAX_TEE_POLICY_SCHEDULE_ENTRIES * (8 + 4 + MAX_TEE_POLICY_BYTES + 32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryMutatorV1 {
    RegisterEnclave,
    RenewEnclave,
    TransitionEnclaveMeasurement,
    ReplaceEnclaveBinding,
}

/// Canonical dimensions used to charge one block-1 `OST3` system call.
///
/// `full_calldata_len` includes the four-byte selector and one-byte version.
/// Collateral deduplication affects that encoded length only: every entry in
/// `logical_evidence_lengths` is charged as a complete QVL verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeeBootstrapGasInputV1<'a> {
    pub full_calldata_len: usize,
    pub logical_evidence_lengths: &'a [usize],
    pub active_rule_count: usize,
    pub collateral_component_count: usize,
    pub committee_signature_count: usize,
}

/// Focused canonical system-gas schedule for the V1 `OST3` bootstrap path.
///
/// The fixed/count terms include the bounded state mutation work. Storage is
/// not charged a second time on top of this protocol precharge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemGasScheduleV1 {
    tee_bootstrap_fixed: u64,
    tee_bootstrap_input_byte: u64,
    tee_bootstrap_participant: u64,
    tee_bootstrap_collateral_component: u64,
    tee_bootstrap_committee_signature: u64,
}

impl SystemGasScheduleV1 {
    pub const fn normative() -> Self {
        Self {
            tee_bootstrap_fixed: 300_000,
            tee_bootstrap_input_byte: 1,
            tee_bootstrap_participant: 100_000,
            tee_bootstrap_collateral_component: 15_000,
            tee_bootstrap_committee_signature: 10_000,
        }
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(41);
        out.push(PROTOCOL_VERSION_V1);
        for value in self.values() {
            put_u64(&mut out, value);
        }
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("SystemGasScheduleV1")?;
        let schedule = Self {
            tee_bootstrap_fixed: decoder.u64()?,
            tee_bootstrap_input_byte: decoder.u64()?,
            tee_bootstrap_participant: decoder.u64()?,
            tee_bootstrap_collateral_component: decoder.u64()?,
            tee_bootstrap_committee_signature: decoder.u64()?,
        };
        decoder.finish()?;
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn schedule_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            SYSTEM_GAS_SCHEDULE_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    pub fn tee_bootstrap_precharge(
        &self,
        tee_registry: &TeeRegistryGasScheduleV1,
        input: TeeBootstrapGasInputV1<'_>,
    ) -> Result<u64, CodecError> {
        enforce_limit(
            "TeeBootstrapV2 full calldata",
            MAX_TEE_BOOTSTRAP_BYTES,
            input.full_calldata_len,
        )?;
        let participant_count = checked_usize(input.logical_evidence_lengths.len())?;
        let qvl =
            input
                .logical_evidence_lengths
                .iter()
                .try_fold(0_u64, |total, evidence_len| {
                    total
                        .checked_add(tee_registry.qvl_dcap(*evidence_len, input.active_rule_count)?)
                        .ok_or(CodecError::ArithmeticOverflow)
                })?;
        checked_sum(&[
            self.tee_bootstrap_fixed,
            checked_mul(
                self.tee_bootstrap_input_byte,
                checked_usize(input.full_calldata_len)?,
            )?,
            checked_mul(self.tee_bootstrap_participant, participant_count)?,
            qvl,
            checked_mul(
                self.tee_bootstrap_collateral_component,
                checked_usize(input.collateral_component_count)?,
            )?,
            checked_mul(
                self.tee_bootstrap_committee_signature,
                checked_usize(input.committee_signature_count)?,
            )?,
        ])
    }

    fn values(&self) -> [u64; 5] {
        [
            self.tee_bootstrap_fixed,
            self.tee_bootstrap_input_byte,
            self.tee_bootstrap_participant,
            self.tee_bootstrap_collateral_component,
            self.tee_bootstrap_committee_signature,
        ]
    }

    fn validate(&self) -> Result<(), CodecError> {
        if *self != Self::normative() {
            return Err(CodecError::NonCanonical(
                "non-normative system gas schedule",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeeRegistryGasScheduleV1 {
    pub input_byte: u64,
    pub qvl_dcap_fixed: u64,
    pub qvl_dev_fixed: u64,
    pub qvl_component_byte: u64,
    pub qvl_certificate: u64,
    pub qvl_crl: u64,
    pub qvl_signed_json: u64,
    pub qvl_measurement_rule: u64,
    pub secp256k1_verify: u64,
    pub ed25519_verify: u64,
    pub register_fixed: u64,
    pub renew_fixed: u64,
    pub measurement_transition_fixed: u64,
    pub profile_replacement_fixed: u64,
    pub delivery_fixed: u64,
    pub view_fixed: u64,
    pub view_output_byte: u64,
}

impl TeeRegistryGasScheduleV1 {
    pub const fn normative() -> Self {
        Self {
            input_byte: 4,
            qvl_dcap_fixed: 1_500_000,
            qvl_dev_fixed: 200_000,
            qvl_component_byte: 6,
            qvl_certificate: 120_000,
            qvl_crl: 180_000,
            qvl_signed_json: 160_000,
            qvl_measurement_rule: 10_000,
            secp256k1_verify: 40_000,
            ed25519_verify: 25_000,
            register_fixed: 600_000,
            renew_fixed: 500_000,
            measurement_transition_fixed: 700_000,
            profile_replacement_fixed: 900_000,
            delivery_fixed: 400_000,
            view_fixed: 100_000,
            view_output_byte: 4,
        }
    }

    /// Hash-committed portion of `register_fixed` reserved for production
    /// warm-SLOAD and SSTORE-reset charges. No independent consensus constant
    /// exists: changing the allowance requires changing the canonical schedule.
    pub const fn register_storage_gas_allowance(&self) -> u64 {
        self.register_fixed / 2
    }

    /// Hash-committed storage allowance for each evidence-bearing registry
    /// mutation. It remains part of the corresponding fixed charge.
    pub const fn mutator_storage_gas_allowance(&self, kind: RegistryMutatorV1) -> u64 {
        match kind {
            RegistryMutatorV1::RegisterEnclave => self.register_fixed / 2,
            RegistryMutatorV1::RenewEnclave => self.renew_fixed / 2,
            RegistryMutatorV1::TransitionEnclaveMeasurement => {
                self.measurement_transition_fixed / 2
            }
            RegistryMutatorV1::ReplaceEnclaveBinding => self.profile_replacement_fixed / 2,
        }
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        if *self != Self::normative() {
            return Err(CodecError::NonCanonical(
                "non-normative TeeRegistry gas schedule",
            ));
        }
        let mut out = Vec::with_capacity(137);
        out.push(PROTOCOL_VERSION_V1);
        for value in self.values() {
            put_u64(&mut out, value);
        }
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("TeeRegistryGasScheduleV1")?;
        let schedule = Self {
            input_byte: decoder.u64()?,
            qvl_dcap_fixed: decoder.u64()?,
            qvl_dev_fixed: decoder.u64()?,
            qvl_component_byte: decoder.u64()?,
            qvl_certificate: decoder.u64()?,
            qvl_crl: decoder.u64()?,
            qvl_signed_json: decoder.u64()?,
            qvl_measurement_rule: decoder.u64()?,
            secp256k1_verify: decoder.u64()?,
            ed25519_verify: decoder.u64()?,
            register_fixed: decoder.u64()?,
            renew_fixed: decoder.u64()?,
            measurement_transition_fixed: decoder.u64()?,
            profile_replacement_fixed: decoder.u64()?,
            delivery_fixed: decoder.u64()?,
            view_fixed: decoder.u64()?,
            view_output_byte: decoder.u64()?,
        };
        decoder.finish()?;
        if schedule != Self::normative() {
            return Err(CodecError::NonCanonical(
                "non-normative TeeRegistry gas schedule",
            ));
        }
        Ok(schedule)
    }

    pub fn schedule_hash(&self) -> Result<B256, CodecError> {
        Ok(domain_hash(
            TEE_REGISTRY_GAS_SCHEDULE_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    pub fn qvl_dcap(
        &self,
        evidence_len: usize,
        active_rule_count: usize,
    ) -> Result<u64, CodecError> {
        validate_qvl_dimensions(evidence_len, active_rule_count)?;
        checked_sum(&[
            self.qvl_dcap_fixed,
            checked_mul(self.qvl_component_byte, checked_usize(evidence_len)?)?,
            checked_mul(self.qvl_certificate, 9)?,
            checked_mul(self.qvl_crl, 2)?,
            checked_mul(self.qvl_signed_json, 2)?,
            checked_mul(self.qvl_measurement_rule, checked_usize(active_rule_count)?)?,
        ])
    }

    pub fn qvl_dev(
        &self,
        evidence_len: usize,
        active_rule_count: usize,
    ) -> Result<u64, CodecError> {
        validate_qvl_dimensions(evidence_len, active_rule_count)?;
        checked_sum(&[
            self.qvl_dev_fixed,
            checked_mul(self.qvl_component_byte, checked_usize(evidence_len)?)?,
            self.ed25519_verify,
            checked_mul(self.qvl_measurement_rule, checked_usize(active_rule_count)?)?,
        ])
    }

    pub fn maximum_transaction_gas(
        &self,
        kind: RegistryMutatorV1,
        input_len: usize,
        evidence_len: usize,
        active_rule_count: usize,
        mode: AttestationMode,
    ) -> Result<u64, CodecError> {
        if input_len < evidence_len {
            return Err(CodecError::NonCanonical(
                "registry input shorter than evidence",
            ));
        }
        let framing_len = input_len - evidence_len;
        enforce_limit(
            "evidence call framing",
            MAX_EVIDENCE_CALL_FRAMING_BYTES,
            framing_len,
        )?;
        let qvl = match mode {
            AttestationMode::DcapRequired => self.qvl_dcap(evidence_len, active_rule_count)?,
            AttestationMode::GramineDirectDev => self.qvl_dev(evidence_len, active_rule_count)?,
        };
        let input_charge = checked_mul(self.input_byte, checked_usize(input_len)?)?;
        let protocol_precharge = match kind {
            RegistryMutatorV1::RegisterEnclave => checked_sum(&[
                self.register_fixed,
                input_charge,
                qvl,
                // Initial registration authenticates the NodeHost intent and
                // both sides of the address-to-NodeHost association.
                checked_mul(self.secp256k1_verify, 3)?,
                self.ed25519_verify,
            ])?,
            RegistryMutatorV1::RenewEnclave => checked_sum(&[
                self.renew_fixed,
                input_charge,
                qvl,
                self.secp256k1_verify,
                self.ed25519_verify,
            ])?,
            RegistryMutatorV1::TransitionEnclaveMeasurement => checked_sum(&[
                self.measurement_transition_fixed,
                input_charge,
                qvl,
                self.secp256k1_verify,
                checked_mul(self.ed25519_verify, 2)?,
            ])?,
            RegistryMutatorV1::ReplaceEnclaveBinding => checked_sum(&[
                self.profile_replacement_fixed,
                input_charge,
                qvl,
                checked_mul(self.secp256k1_verify, 2)?,
                checked_mul(self.ed25519_verify, 2)?,
            ])?,
        };
        self.maximum_calldata_intrinsic_gas(input_len)?
            .checked_add(protocol_precharge)
            .ok_or(CodecError::ArithmeticOverflow)
    }

    pub fn maximum_calldata_intrinsic_gas(&self, input_len: usize) -> Result<u64, CodecError> {
        checked_mul(16, checked_usize(input_len)?)?
            .checked_add(21_000)
            .ok_or(CodecError::ArithmeticOverflow)
    }

    fn values(&self) -> [u64; 17] {
        [
            self.input_byte,
            self.qvl_dcap_fixed,
            self.qvl_dev_fixed,
            self.qvl_component_byte,
            self.qvl_certificate,
            self.qvl_crl,
            self.qvl_signed_json,
            self.qvl_measurement_rule,
            self.secp256k1_verify,
            self.ed25519_verify,
            self.register_fixed,
            self.renew_fixed,
            self.measurement_transition_fixed,
            self.profile_replacement_fixed,
            self.delivery_fixed,
            self.view_fixed,
            self.view_output_byte,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceScheduleV1 {
    pub system_gas_schedule_hash: B256,
    pub tee_registry_gas_schedule_hash: B256,
    pub bootstrap_block_gas_limit: u64,
    pub steady_block_gas_limit: u64,
}

impl ResourceScheduleV1 {
    pub fn normative() -> Result<Self, CodecError> {
        Ok(Self {
            system_gas_schedule_hash: SystemGasScheduleV1::normative().schedule_hash()?,
            tee_registry_gas_schedule_hash: TeeRegistryGasScheduleV1::normative()
                .schedule_hash()?,
            bootstrap_block_gas_limit: BOOTSTRAP_BLOCK_GAS_LIMIT,
            steady_block_gas_limit: STEADY_BLOCK_GAS_LIMIT,
        })
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut out = Vec::with_capacity(81);
        out.push(PROTOCOL_VERSION_V1);
        out.extend_from_slice(self.system_gas_schedule_hash.as_slice());
        out.extend_from_slice(self.tee_registry_gas_schedule_hash.as_slice());
        put_u64(&mut out, self.bootstrap_block_gas_limit);
        put_u64(&mut out, self.steady_block_gas_limit);
        Ok(out)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        let mut decoder = Decoder::new(input);
        decoder.version("ResourceScheduleV1")?;
        let value = Self {
            system_gas_schedule_hash: B256::from(decoder.array::<32>()?),
            tee_registry_gas_schedule_hash: B256::from(decoder.array::<32>()?),
            bootstrap_block_gas_limit: decoder.u64()?,
            steady_block_gas_limit: decoder.u64()?,
        };
        decoder.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub fn schedule_hash(&self) -> Result<B256, CodecError> {
        self.validate()?;
        Ok(domain_hash(
            RESOURCE_SCHEDULE_DOMAIN_V1,
            &self.encode_canonical()?,
        ))
    }

    fn validate(&self) -> Result<(), CodecError> {
        let normative = Self::normative()?;
        if self.system_gas_schedule_hash != normative.system_gas_schedule_hash
            || self.tee_registry_gas_schedule_hash != normative.tee_registry_gas_schedule_hash
        {
            return Err(CodecError::NonCanonical(
                "non-normative resource schedule hashes",
            ));
        }
        if self.bootstrap_block_gas_limit != BOOTSTRAP_BLOCK_GAS_LIMIT
            || self.steady_block_gas_limit != STEADY_BLOCK_GAS_LIMIT
        {
            return Err(CodecError::NonCanonical("non-normative block gas limits"));
        }
        Ok(())
    }
}

fn validate_qvl_dimensions(
    evidence_len: usize,
    active_rule_count: usize,
) -> Result<(), CodecError> {
    enforce_limit(
        "attestation evidence",
        MAX_ATTESTATION_EVIDENCE_BYTES,
        evidence_len,
    )?;
    enforce_limit(
        "active measurement rules",
        MAX_ACTIVE_MEASUREMENT_RULES,
        active_rule_count,
    )
}

fn enforce_limit(field: &'static str, limit: usize, actual: usize) -> Result<(), CodecError> {
    if actual > limit {
        return Err(CodecError::LimitExceeded {
            field,
            limit,
            actual,
        });
    }
    Ok(())
}

fn checked_usize(value: usize) -> Result<u64, CodecError> {
    u64::try_from(value).map_err(|_| CodecError::ArithmeticOverflow)
}

fn checked_add_usize(left: usize, right: usize) -> Result<usize, CodecError> {
    left.checked_add(right)
        .ok_or(CodecError::ArithmeticOverflow)
}

fn checked_mul(left: u64, right: u64) -> Result<u64, CodecError> {
    left.checked_mul(right)
        .ok_or(CodecError::ArithmeticOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, CodecError> {
    values.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value)
            .ok_or(CodecError::ArithmeticOverflow)
    })
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> B256 {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    keccak256(preimage)
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_len_u32(out: &mut Vec<u8>, value: usize) -> Result<(), CodecError> {
    let value = u32::try_from(value).map_err(|_| CodecError::ArithmeticOverflow)?;
    put_u32(out, value);
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn version(&mut self, field: &'static str) -> Result<(), CodecError> {
        let value = self.u8()?;
        if value != PROTOCOL_VERSION_V1 {
            return Err(CodecError::UnsupportedVersion { field, value });
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CodecError::UnexpectedEof)
    }

    fn declared_len(&mut self, field: &'static str, limit: usize) -> Result<usize, CodecError> {
        let actual = usize::try_from(self.u32()?).map_err(|_| CodecError::ArithmeticOverflow)?;
        enforce_limit(field, limit, actual)?;
        if actual > self.remaining() {
            return Err(CodecError::UnexpectedEof);
        }
        Ok(actual)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(CodecError::ArithmeticOverflow)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.position = end;
        Ok(value)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn finish(self) -> Result<(), CodecError> {
        if self.remaining() != 0 {
            return Err(CodecError::TrailingBytes(self.remaining()));
        }
        Ok(())
    }
}
