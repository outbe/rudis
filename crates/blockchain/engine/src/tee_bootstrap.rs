//! Consensus-thread TEE bootstrap: run the one-time committee coordination at
//! startup (exactly like the consensus DKG), assemble the canonical OST3 payload,
//! and hand it to the payload builder via the bridge so the **block-1** proposer
//! injects it (slice 5.1). `committee_snapshot_block` is the fixed block 1 - the
//! known injection target, mirroring how `BoundaryOutcome` lands at block 1 - so
//! there is no run-time block-number ambiguity.
//!
//! The secret operations stay in the enclave; this glue only adapts the
//! consensus P2P channel to [`BootstrapGossip`] and signs the payload with the
//! validator's EVM key.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use alloy_primitives::{keccak256, Address, B256};
use commonware_codec::Encode as _;
use commonware_cryptography::bls12381;
use commonware_p2p::{Receiver as P2pReceiver, Recipients, Sender as P2pSender};
use commonware_runtime::Clock;

use outbe_primitives::signer::OutbeEvmSigner;
use outbe_primitives::tee_attestation_v1::{
    AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapEvidenceV1,
    EnclaveInitializationManifestV1, GramineDirectEvidenceV1, NodeIdV1, RegistrationIntentV1,
    TeePolicyV1, ValidatorNodeBindingV1, ENCLAVE_ID_DOMAIN_V1, MAX_ATTESTATION_EVIDENCE_BYTES,
};
use outbe_primitives::tee_bootstrap_v2::{
    TeeBootstrapAuthorityV2, TeeBootstrapParticipantSubmissionV2, TeeBootstrapV2,
};
use outbe_primitives::tee_signatures::recover_signer;
use outbe_tee::protocol::{EnclaveRequest, EnclaveResponse};
use outbe_tee::tee_dkg::{
    run_tee_dkg_ceremony, CeremonyCoordinator, CeremonyError, DkgGossip, DkgWireMessage,
};
use outbe_tee::{acquire_dcap_collateral_v1, RuntimeEnclaveClient};

/// Minimal opaque carrier used by the one-time OST3 startup coordinator.
#[allow(async_fn_in_trait)]
pub trait BootstrapGossip {
    async fn broadcast(&mut self, bytes: Vec<u8>) -> Result<(), CeremonyError>;
    async fn recv(&mut self) -> Option<Vec<u8>>;
}

const DELIVERY_DATA: u8 = 0xd0;
const DELIVERY_ACK: u8 = 0xd1;
const DELIVERY_ID_LEN: usize = 32;
const DELIVERY_INITIAL_RETRY_TICKS: u32 = 1;
const DELIVERY_MAX_RETRY_TICKS: u32 = 16;
const DELIVERY_MAX_PENDING_MESSAGES: usize = 1024;
const DELIVERY_MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;
const DELIVERY_ID_DOMAIN: &[u8] = b"outbe:tee-delivery:v1";
const OST3_SUBMISSION: u8 = 0x30;
const OST3_SIGNATURE: u8 = 0x31;
const OST3_SUBMISSION_FIXED_BYTES: usize =
    1 + 4 + ValidatorNodeBindingV1::CANONICAL_LEN + 65 + 65 + 65 + 64;
const OST3_SIGNATURE_BYTES: usize = 1 + 32 + 20 + 65;
const OST3_SCOPE_DOMAIN: &[u8] = b"outbe/tee/bootstrap-v2-gossip/v1";
const OST3_DEV_NODE_HOST_DOMAIN: &[u8] = b"outbe/tee/dev-node-host/v1";
const OST3_BINDING_ID_DOMAIN: &[u8] = b"outbe/tee/bootstrap-binding/v1";

// Bootstrap-only gossip message, built and consumed immediately during node
// join (not a steady-state hot path), so boxing the larger variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ost3WireMessage {
    Submission(Box<TeeBootstrapParticipantSubmissionV2>),
    Signature {
        signing_hash: B256,
        validator: Address,
        signature: [u8; 65],
    },
}

impl Ost3WireMessage {
    fn encode(&self) -> eyre::Result<Vec<u8>> {
        match self {
            Self::Submission(submission) => {
                let evidence = submission
                    .evidence
                    .encode_canonical()
                    .map_err(|error| eyre::eyre!("cannot encode OST3 evidence: {error}"))?;
                let evidence_len = u32::try_from(evidence.len())
                    .map_err(|_| eyre::eyre!("OST3 evidence length exceeds u32"))?;
                let mut out = Vec::with_capacity(OST3_SUBMISSION_FIXED_BYTES + evidence.len());
                out.push(OST3_SUBMISSION);
                out.extend_from_slice(&evidence_len.to_be_bytes());
                out.extend_from_slice(&evidence);
                out.extend_from_slice(
                    &submission
                        .validator_binding
                        .encode_canonical()
                        .map_err(|error| eyre::eyre!("cannot encode OST3 binding: {error}"))?,
                );
                out.extend_from_slice(&submission.validator_signature);
                out.extend_from_slice(&submission.node_binding_signature);
                out.extend_from_slice(&submission.node_signature);
                out.extend_from_slice(&submission.enclave_signature);
                Ok(out)
            }
            Self::Signature {
                signing_hash,
                validator,
                signature,
            } => {
                let mut out = Vec::with_capacity(OST3_SIGNATURE_BYTES);
                out.push(OST3_SIGNATURE);
                out.extend_from_slice(signing_hash.as_slice());
                out.extend_from_slice(validator.as_slice());
                out.extend_from_slice(signature);
                Ok(out)
            }
        }
    }

    fn decode(input: &[u8]) -> Option<Self> {
        match input.first().copied()? {
            OST3_SUBMISSION => {
                if input.len() < OST3_SUBMISSION_FIXED_BYTES {
                    return None;
                }
                let evidence_len =
                    usize::try_from(u32::from_be_bytes(input.get(1..5)?.try_into().ok()?)).ok()?;
                if evidence_len > MAX_ATTESTATION_EVIDENCE_BYTES
                    || input.len() != OST3_SUBMISSION_FIXED_BYTES.checked_add(evidence_len)?
                {
                    return None;
                }
                let evidence_end = 5usize.checked_add(evidence_len)?;
                let evidence =
                    AttestationEvidenceV1::decode_canonical(input.get(5..evidence_end)?).ok()?;
                let binding_end =
                    evidence_end.checked_add(ValidatorNodeBindingV1::CANONICAL_LEN)?;
                let validator_binding =
                    ValidatorNodeBindingV1::decode_canonical(input.get(evidence_end..binding_end)?)
                        .ok()?;
                let validator_signature_end = binding_end.checked_add(65)?;
                let validator_signature = input
                    .get(binding_end..validator_signature_end)?
                    .try_into()
                    .ok()?;
                let node_binding_signature_end = validator_signature_end.checked_add(65)?;
                let node_binding_signature = input
                    .get(validator_signature_end..node_binding_signature_end)?
                    .try_into()
                    .ok()?;
                let node_signature_end = node_binding_signature_end.checked_add(65)?;
                let node_signature = input
                    .get(node_binding_signature_end..node_signature_end)?
                    .try_into()
                    .ok()?;
                let enclave_signature = input.get(node_signature_end..)?.try_into().ok()?;
                Some(Self::Submission(Box::new(
                    TeeBootstrapParticipantSubmissionV2 {
                        evidence,
                        validator_binding,
                        validator_signature,
                        node_binding_signature,
                        node_signature,
                        enclave_signature,
                    },
                )))
            }
            OST3_SIGNATURE if input.len() == OST3_SIGNATURE_BYTES => {
                let signing_hash = B256::from_slice(input.get(1..33)?);
                let validator = Address::from_slice(input.get(33..53)?);
                let signature = input.get(53..118)?.try_into().ok()?;
                Some(Self::Signature {
                    signing_hash,
                    validator,
                    signature,
                })
            }
            _ => None,
        }
    }
}

fn evidence_intent(evidence: &AttestationEvidenceV1) -> &RegistrationIntentV1 {
    match evidence {
        AttestationEvidenceV1::Dcap(value) => &value.intent,
        AttestationEvidenceV1::GramineDirectDev(value) => &value.intent,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootstrapEvidenceKind {
    Dcap,
    GramineDirectDev,
}

fn bootstrap_evidence_kind(
    policy: AttestationMode,
    production_session: bool,
) -> eyre::Result<BootstrapEvidenceKind> {
    match (policy, production_session) {
        (AttestationMode::DcapRequired, true) => Ok(BootstrapEvidenceKind::Dcap),
        (AttestationMode::DcapRequired, false) => Err(eyre::eyre!(
            "DcapRequired genesis policy cannot use a development enclave session"
        )),
        (AttestationMode::GramineDirectDev, _) => Ok(BootstrapEvidenceKind::GramineDirectDev),
    }
}

fn submission_validator(submission: &TeeBootstrapParticipantSubmissionV2) -> eyre::Result<Address> {
    Ok(Address::from(submission.validator_binding.validator))
}

fn validate_submission(
    submission: &TeeBootstrapParticipantSubmissionV2,
    policy: &TeePolicyV1,
    committee: &BTreeSet<Address>,
) -> eyre::Result<Address> {
    let intent = evidence_intent(&submission.evidence);
    let validator = submission_validator(submission)?;
    let policy_hash = policy
        .policy_hash()
        .map_err(|error| eyre::eyre!("invalid OST3 policy: {error}"))?;
    if !committee.contains(&validator)
        || submission.evidence.mode() != policy.attestation_mode
        || intent.operation != AttestationOperationV1::RegisterEnclave
        || intent.attestation_mode != policy.attestation_mode
        || intent.policy_hash != policy_hash
        || intent.chain_id != policy.chain_id
        || intent.genesis_hash != policy.genesis_hash
        || intent.binding_version != 1
        || intent.registration_version != 0
        || intent.renewal_nonce != 0
        || intent.transition_nonce != 0
        || !intent.verify_node_signature(&submission.node_signature)
        || !intent.verify_enclave_signature(&submission.enclave_signature)
        || submission.validator_binding.chain_id != policy.chain_id
        || submission.validator_binding.genesis_hash != policy.genesis_hash
        || submission.validator_binding.node_id_hash
            != intent
                .node_id
                .node_id_hash()
                .map_err(|error| eyre::eyre!("invalid OST3 NodeHost identity: {error}"))?
        || !submission
            .validator_binding
            .verify_validator_signature(&submission.validator_signature)
        || !submission
            .validator_binding
            .verify_node_signature(&submission.node_binding_signature)
    {
        return Err(eyre::eyre!(
            "OST3 submission does not prove one canonical committee registration"
        ));
    }
    if let AttestationEvidenceV1::GramineDirectDev(dev) = &submission.evidence {
        if dev.dev_attestation_public != intent.attestation_ed25519
            || dev.dev_signature != submission.enclave_signature
        {
            return Err(eyre::eyre!(
                "OST3 GramineDirectDev evidence does not match the outer enclave proof"
            ));
        }
    }
    Ok(validator)
}

/// Build this validator's complete block-1 OST3 submission. Production quote
/// generation is available only through the NodeHost-authorized enclave and
/// collateral acquisition is host-only startup work. The separate development
/// mode signs an explicit GramineDirectDev intent and never creates a DCAP
/// verdict or hardware-attestation claim.
#[allow(clippy::too_many_arguments)]
pub fn build_local_tee_bootstrap_submission_v2(
    client: &mut RuntimeEnclaveClient,
    production_manifest: Option<&EnclaveInitializationManifestV1>,
    node_id: NodeIdV1,
    policy: &TeePolicyV1,
    requested_valid_until: u64,
    evm_signer: &OutbeEvmSigner,
    sign_node_hash: impl Fn(B256) -> Result<[u8; 65], String>,
) -> eyre::Result<TeeBootstrapParticipantSubmissionV2> {
    let policy_hash = policy
        .policy_hash()
        .map_err(|error| eyre::eyre!("invalid OST3 policy: {error}"))?;

    let (
        recipient_x25519,
        attestation_ed25519,
        noise_responder_x25519,
        enclave_id,
        node_host_authorization_hash,
    ) = match (policy.attestation_mode, &mut *client) {
        (
            AttestationMode::DcapRequired | AttestationMode::GramineDirectDev,
            RuntimeEnclaveClient::Production(_),
        ) => {
            let manifest = production_manifest.ok_or_else(|| {
                eyre::eyre!("production OST3 requires one committed NodeHost manifest")
            })?;
            if manifest.chain_id != policy.chain_id
                || manifest.genesis_hash != policy.genesis_hash
                || manifest.node_id != node_id
            {
                return Err(eyre::eyre!(
                    "committed NodeHost manifest does not match OST3 chain or persistent P2P identity"
                ));
            }
            (
                manifest.recipient_x25519,
                manifest.attestation_ed25519,
                manifest.noise_responder_x25519,
                manifest
                    .enclave_id()
                    .map_err(|error| eyre::eyre!("invalid committed enclave identity: {error}"))?,
                manifest.node_host_authorization_hash().map_err(|error| {
                    eyre::eyre!("invalid committed NodeHost authorization: {error}")
                })?,
            )
        }
        (AttestationMode::GramineDirectDev, RuntimeEnclaveClient::Development(dev)) => {
            let EnclaveResponse::Quote {
                recipient_x25519_pub,
                attestation_pub,
                noise_static_pub,
                ..
            } = dev.quote()
            else {
                return Err(eyre::eyre!(
                    "GramineDirectDev session did not retain its enclave identity quote"
                ));
            };
            let mut enclave_keys = [0_u8; 96];
            enclave_keys[..32].copy_from_slice(recipient_x25519_pub);
            enclave_keys[32..64].copy_from_slice(attestation_pub);
            enclave_keys[64..].copy_from_slice(noise_static_pub);
            let enclave_id = {
                let mut preimage = Vec::with_capacity(ENCLAVE_ID_DOMAIN_V1.len() + 96);
                preimage.extend_from_slice(ENCLAVE_ID_DOMAIN_V1);
                preimage.extend_from_slice(&enclave_keys);
                keccak256(preimage)
            };
            let node_id_hash = node_id
                .node_id_hash()
                .map_err(|error| eyre::eyre!("invalid OST3 node identity: {error}"))?;
            let node_host_authorization_hash = {
                let mut preimage = Vec::with_capacity(
                    OST3_DEV_NODE_HOST_DOMAIN.len() + 32 + 32 + 32 + enclave_keys.len(),
                );
                preimage.extend_from_slice(OST3_DEV_NODE_HOST_DOMAIN);
                preimage.extend_from_slice(&policy.chain_id);
                preimage.extend_from_slice(policy.genesis_hash.as_slice());
                preimage.extend_from_slice(node_id_hash.as_slice());
                preimage.extend_from_slice(&enclave_keys);
                keccak256(preimage)
            };
            (
                *recipient_x25519_pub,
                *attestation_pub,
                *noise_static_pub,
                enclave_id,
                node_host_authorization_hash,
            )
        }
        (AttestationMode::DcapRequired, RuntimeEnclaveClient::Development(_)) => {
            return Err(eyre::eyre!(
                "DcapRequired genesis policy cannot use a development enclave session"
            ));
        }
    };

    let node_id_hash = node_id
        .node_id_hash()
        .map_err(|error| eyre::eyre!("invalid OST3 node identity: {error}"))?;
    let binding_id = {
        let mut preimage = Vec::with_capacity(OST3_BINDING_ID_DOMAIN.len() + 96);
        preimage.extend_from_slice(OST3_BINDING_ID_DOMAIN);
        preimage.extend_from_slice(node_id_hash.as_slice());
        preimage.extend_from_slice(enclave_id.as_slice());
        preimage.extend_from_slice(policy_hash.as_slice());
        keccak256(preimage)
    };
    let intent = RegistrationIntentV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: policy.attestation_mode,
        policy_hash,
        node_id,
        enclave_id,
        binding_id,
        binding_version: 1,
        registration_version: 0,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until,
        recipient_x25519,
        attestation_ed25519,
        noise_responder_x25519,
        node_host_authorization_hash,
    };
    let intent_hash = intent
        .intent_hash()
        .map_err(|error| eyre::eyre!("invalid OST3 registration intent: {error}"))?;
    let node_signature = sign_node_hash(intent_hash)
        .map_err(|error| eyre::eyre!("cannot sign OST3 registration intent: {error}"))?;
    let validator_binding = ValidatorNodeBindingV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        validator: evm_signer.address().into_array(),
        node_id_hash,
    };
    let binding_hash = validator_binding
        .binding_hash()
        .map_err(|error| eyre::eyre!("invalid validator NodeHost binding: {error}"))?;
    let validator_signature = evm_signer
        .sign_hash(&binding_hash)
        .map_err(|error| eyre::eyre!("cannot sign validator NodeHost binding: {error}"))?;
    let node_binding_signature = sign_node_hash(binding_hash)
        .map_err(|error| eyre::eyre!("cannot sign NodeHost validator binding: {error}"))?;

    let evidence_kind = bootstrap_evidence_kind(
        policy.attestation_mode,
        matches!(client, RuntimeEnclaveClient::Production(_)),
    )?;
    let (evidence, enclave_signature) = match (evidence_kind, client) {
        (BootstrapEvidenceKind::Dcap, RuntimeEnclaveClient::Production(production)) => {
            let generated = production
                .generate_dcap_quote(&intent)
                .map_err(|error| eyre::eyre!("production OST3 quote generation failed: {error}"))?;
            let components =
                acquire_dcap_collateral_v1(&generated.quote_body).map_err(|error| {
                    eyre::eyre!("production OST3 collateral acquisition failed: {error}")
                })?;
            let enclave_signature = generated.enclave_signature;
            (
                AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
                    intent,
                    quote: generated.quote_body,
                    components,
                    transition_key_ready_proof: generated.transition_key_ready_proof,
                }),
                enclave_signature,
            )
        }
        (BootstrapEvidenceKind::Dcap, RuntimeEnclaveClient::Development(_)) => {
            return Err(eyre::eyre!(
                "DcapRequired genesis policy cannot use a development enclave session"
            ));
        }
        (BootstrapEvidenceKind::GramineDirectDev, RuntimeEnclaveClient::Production(production)) => {
            let enclave_signature = production
                .sign_registration_intent_dev_v1(&intent)
                .map_err(|error| {
                    eyre::eyre!("production SGX-no-attest OST3 intent signing failed: {error}")
                })?;
            (
                AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                    intent,
                    dev_attestation_public: attestation_ed25519,
                    dev_signature: enclave_signature,
                }),
                enclave_signature,
            )
        }
        (
            BootstrapEvidenceKind::GramineDirectDev,
            RuntimeEnclaveClient::Development(development),
        ) => {
            let enclave_signature = development
                .sign_registration_intent_dev_v1(&intent)
                .map_err(|error| eyre::eyre!("development OST3 intent signing failed: {error}"))?;
            (
                AttestationEvidenceV1::GramineDirectDev(GramineDirectEvidenceV1 {
                    intent,
                    dev_attestation_public: attestation_ed25519,
                    dev_signature: enclave_signature,
                }),
                enclave_signature,
            )
        }
    };
    evidence
        .encode_canonical()
        .map_err(|error| eyre::eyre!("local OST3 evidence is not canonical: {error}"))?;
    Ok(TeeBootstrapParticipantSubmissionV2 {
        evidence,
        validator_binding,
        validator_signature,
        node_binding_signature,
        node_signature,
        enclave_signature,
    })
}

fn insert_submission(
    submissions: &mut BTreeMap<Address, TeeBootstrapParticipantSubmissionV2>,
    submission: TeeBootstrapParticipantSubmissionV2,
    policy: &TeePolicyV1,
    committee: &BTreeSet<Address>,
) -> eyre::Result<()> {
    let validator = validate_submission(&submission, policy, committee)?;
    if let Some(existing) = submissions.get(&validator) {
        if existing != &submission {
            return Err(eyre::eyre!(
                "validator {validator} equivocated between two valid OST3 submissions"
            ));
        }
        return Ok(());
    }
    submissions.insert(validator, submission);
    Ok(())
}

/// Coordinate complete canonical OST3 participant evidence and committee
/// signatures over one deterministic body. The enclosing startup timeout is
/// the liveness bound; malformed or unauthenticated gossip is ignored.
pub async fn coordinate_tee_bootstrap_v2<G: BootstrapGossip>(
    local_submission: TeeBootstrapParticipantSubmissionV2,
    authority: TeeBootstrapAuthorityV2,
    committee: &BTreeSet<Address>,
    evm_signer: &OutbeEvmSigner,
    gossip: &mut G,
) -> eyre::Result<TeeBootstrapV2> {
    if committee.is_empty() || committee.len() > 256 {
        return Err(eyre::eyre!(
            "OST3 committee size is outside protocol bounds"
        ));
    }
    let local_validator = validate_submission(&local_submission, &authority.policy, committee)?;
    if local_validator != evm_signer.address() {
        return Err(eyre::eyre!("OST3 local submission and EVM signer differ"));
    }

    gossip
        .broadcast(Ost3WireMessage::Submission(Box::new(local_submission.clone())).encode()?)
        .await
        .map_err(|error| eyre::eyre!("OST3 submission broadcast failed: {error}"))?;
    let mut submissions = BTreeMap::new();
    insert_submission(
        &mut submissions,
        local_submission,
        &authority.policy,
        committee,
    )?;
    let mut early_signatures = Vec::new();
    while submissions.len() < committee.len() {
        let bytes = gossip
            .recv()
            .await
            .ok_or_else(|| eyre::eyre!("OST3 gossip closed before all submissions arrived"))?;
        match Ost3WireMessage::decode(&bytes) {
            Some(Ost3WireMessage::Submission(submission)) => {
                if validate_submission(&submission, &authority.policy, committee).is_ok() {
                    insert_submission(&mut submissions, *submission, &authority.policy, committee)?;
                }
            }
            Some(signature @ Ost3WireMessage::Signature { .. }) => {
                early_signatures.push(signature);
            }
            None => {}
        }
    }

    let mut payload =
        TeeBootstrapV2::assemble_unsigned(authority, submissions.into_values().collect())
            .map_err(|error| eyre::eyre!("OST3 unsigned assembly failed: {error}"))?;
    let signing_hash = payload
        .signing_hash()
        .map_err(|error| eyre::eyre!("OST3 signing hash failed: {error}"))?;
    let local_signature = evm_signer
        .sign_hash(&signing_hash)
        .map_err(|error| eyre::eyre!("OST3 local signature failed: {error}"))?;
    gossip
        .broadcast(
            Ost3WireMessage::Signature {
                signing_hash,
                validator: local_validator,
                signature: local_signature,
            }
            .encode()?,
        )
        .await
        .map_err(|error| eyre::eyre!("OST3 signature broadcast failed: {error}"))?;

    let mut signatures = BTreeMap::from([(local_validator, local_signature)]);
    let accept_signature =
        |message: Ost3WireMessage, signatures: &mut BTreeMap<Address, [u8; 65]>| {
            let Ost3WireMessage::Signature {
                signing_hash: received_hash,
                validator,
                signature,
            } = message
            else {
                return Ok(());
            };
            if received_hash != signing_hash
                || !committee.contains(&validator)
                || recover_signer(&signing_hash, &signature).ok() != Some(validator)
            {
                return Ok(());
            }
            if let Some(existing) = signatures.get(&validator) {
                if existing != &signature {
                    return Err(eyre::eyre!(
                        "validator {validator} equivocated between OST3 signatures"
                    ));
                }
                return Ok(());
            }
            signatures.insert(validator, signature);
            Ok(())
        };
    for message in early_signatures {
        accept_signature(message, &mut signatures)?;
    }
    while signatures.len() < committee.len() {
        let bytes = gossip
            .recv()
            .await
            .ok_or_else(|| eyre::eyre!("OST3 gossip closed before all signatures arrived"))?;
        if let Some(message) = Ost3WireMessage::decode(&bytes) {
            accept_signature(message, &mut signatures)?;
        }
    }
    for record in &mut payload.committee_signatures {
        record.signature = *signatures
            .get(&record.validator)
            .ok_or_else(|| eyre::eyre!("OST3 signature set is incomplete"))?;
    }
    payload
        .preflight()
        .map_err(|error| eyre::eyre!("signed OST3 payload failed preflight: {error}"))?;
    Ok(payload)
}

/// Bind the generic OST3 coordinator to the dedicated bounded Commonware
/// bootstrap channel. The scope commits to the complete authority namespace so
/// delivery acknowledgements from another chain, policy or ceremony cannot be
/// replayed here.
#[allow(clippy::too_many_arguments)]
pub async fn run_tee_bootstrap_v2_at_startup<S, R, C>(
    local_submission: TeeBootstrapParticipantSubmissionV2,
    authority: TeeBootstrapAuthorityV2,
    committee: BTreeSet<Address>,
    evm_signer: &OutbeEvmSigner,
    allowed_remote_peers: BTreeSet<bls12381::PublicKey>,
    sender: S,
    receiver: R,
    clock: C,
) -> eyre::Result<TeeBootstrapV2>
where
    S: P2pSender<PublicKey = bls12381::PublicKey>,
    R: P2pReceiver<PublicKey = bls12381::PublicKey>,
    C: Clock,
{
    let policy_hash = authority
        .policy
        .policy_hash()
        .map_err(|error| eyre::eyre!("invalid OST3 startup policy: {error}"))?;
    let mut scope = Vec::with_capacity(OST3_SCOPE_DOMAIN.len() + 32 * 4 + 8);
    scope.extend_from_slice(OST3_SCOPE_DOMAIN);
    scope.extend_from_slice(&authority.policy.chain_id);
    scope.extend_from_slice(authority.policy.genesis_hash.as_slice());
    scope.extend_from_slice(policy_hash.as_slice());
    scope.extend_from_slice(authority.committee_snapshot_hash.as_slice());
    scope.extend_from_slice(&authority.committee_snapshot_block.to_be_bytes());
    scope.extend_from_slice(authority.tribute_offer_public_key.as_slice());
    let mut gossip = CommonwareBootstrapGossip {
        sender,
        receiver,
        clock,
        delivery: DeliveryTracker::new(keccak256(scope), allowed_remote_peers),
    };
    coordinate_tee_bootstrap_v2(
        local_submission,
        authority,
        &committee,
        evm_signer,
        &mut gossip,
    )
    .await
}

#[derive(Debug)]
struct PendingDelivery {
    envelope: Vec<u8>,
    broadcast: bool,
    recipients: BTreeSet<bls12381::PublicKey>,
    acknowledged: BTreeSet<bls12381::PublicKey>,
    retry_in_ticks: u32,
    retry_every_ticks: u32,
}

/// Per-message delivery state. It is intentionally process-local: the enclosing
/// startup ceremony has one existing deadline and a failed startup is retried by
/// restarting the node. P2P sender identities authenticate receipts.
#[derive(Debug)]
struct DeliveryTracker {
    scope: B256,
    allowed_peers: BTreeSet<bls12381::PublicKey>,
    known_peers: BTreeSet<bls12381::PublicKey>,
    pending: BTreeMap<B256, PendingDelivery>,
    pending_bytes: usize,
}

impl DeliveryTracker {
    fn new(scope: B256, allowed_peers: BTreeSet<bls12381::PublicKey>) -> Self {
        Self {
            scope,
            allowed_peers,
            known_peers: BTreeSet::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
        }
    }

    fn message_id(&self, payload: &[u8]) -> B256 {
        let mut preimage = Vec::with_capacity(DELIVERY_ID_DOMAIN.len() + 32 + payload.len());
        preimage.extend_from_slice(DELIVERY_ID_DOMAIN);
        preimage.extend_from_slice(self.scope.as_slice());
        preimage.extend_from_slice(payload);
        keccak256(preimage)
    }

    fn envelope(
        &mut self,
        recipients: Recipients<bls12381::PublicKey>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, CeremonyError> {
        let id = self.message_id(&payload);
        if let Some(existing) = self.pending.get_mut(&id) {
            match recipients {
                Recipients::All => existing.broadcast = true,
                Recipients::One(peer) => {
                    existing.recipients.insert(peer);
                }
                _ => {
                    return Err(CeremonyError::Delivery(
                        "unsupported recipient mode for tracked delivery".to_string(),
                    ));
                }
            }
            return Ok(existing.envelope.clone());
        }
        let (broadcast, recipients) = match recipients {
            Recipients::All => (true, BTreeSet::new()),
            Recipients::One(peer) => (false, [peer].into_iter().collect()),
            _ => {
                return Err(CeremonyError::Delivery(
                    "unsupported recipient mode for tracked delivery".to_string(),
                ));
            }
        };
        let mut envelope = Vec::with_capacity(1 + DELIVERY_ID_LEN + payload.len());
        envelope.push(DELIVERY_DATA);
        envelope.extend_from_slice(id.as_slice());
        envelope.extend_from_slice(&payload);
        if self.pending.len() >= DELIVERY_MAX_PENDING_MESSAGES
            || self.pending_bytes.saturating_add(envelope.len()) > DELIVERY_MAX_PENDING_BYTES
        {
            return Err(CeremonyError::Delivery(format!(
                "pending delivery budget exceeded: messages={}, bytes={}",
                self.pending.len(),
                self.pending_bytes
            )));
        }
        self.pending_bytes += envelope.len();
        self.pending.insert(
            id,
            PendingDelivery {
                envelope: envelope.clone(),
                broadcast,
                recipients,
                acknowledged: BTreeSet::new(),
                retry_in_ticks: DELIVERY_INITIAL_RETRY_TICKS,
                retry_every_ticks: DELIVERY_INITIAL_RETRY_TICKS,
            },
        );
        Ok(envelope)
    }

    fn observe_peer(&mut self, peer: bls12381::PublicKey) -> bool {
        if self.allowed_peers.contains(&peer) {
            self.known_peers.insert(peer);
            true
        } else {
            false
        }
    }

    fn acknowledge(&mut self, peer: &bls12381::PublicKey, id: B256) {
        let complete = if let Some(pending) = self.pending.get_mut(&id) {
            pending.acknowledged.insert(peer.clone());
            if pending.broadcast {
                self.known_peers.len() >= self.allowed_peers.len()
                    && self
                        .known_peers
                        .iter()
                        .all(|known| pending.acknowledged.contains(known))
            } else {
                pending
                    .recipients
                    .iter()
                    .all(|expected| pending.acknowledged.contains(expected))
            }
        } else {
            false
        };
        if complete {
            if let Some(removed) = self.pending.remove(&id) {
                self.pending_bytes = self.pending_bytes.saturating_sub(removed.envelope.len());
            }
        }
    }

    fn retry_batch(&mut self) -> Vec<(Recipients<bls12381::PublicKey>, Vec<u8>)> {
        let mut retry = Vec::new();
        for pending in self.pending.values_mut() {
            if pending.retry_in_ticks > 1 {
                pending.retry_in_ticks -= 1;
                continue;
            }
            if pending.broadcast && self.known_peers.len() >= self.allowed_peers.len() {
                for peer in self.known_peers.difference(&pending.acknowledged) {
                    retry.push((Recipients::One(peer.clone()), pending.envelope.clone()));
                }
            } else if pending.broadcast {
                retry.push((Recipients::All, pending.envelope.clone()));
            } else {
                for peer in pending.recipients.difference(&pending.acknowledged) {
                    retry.push((Recipients::One(peer.clone()), pending.envelope.clone()));
                }
            }
            pending.retry_every_ticks = pending
                .retry_every_ticks
                .saturating_mul(2)
                .min(DELIVERY_MAX_RETRY_TICKS);
            pending.retry_in_ticks = pending.retry_every_ticks;
        }
        retry
    }

    fn decode<'a>(&self, bytes: &'a [u8]) -> Option<(u8, B256, &'a [u8])> {
        if bytes.len() < 1 + DELIVERY_ID_LEN {
            return None;
        }
        let tag = bytes[0];
        if tag != DELIVERY_DATA && tag != DELIVERY_ACK {
            return None;
        }
        let id = B256::from_slice(&bytes[1..1 + DELIVERY_ID_LEN]);
        let payload = &bytes[1 + DELIVERY_ID_LEN..];
        match tag {
            DELIVERY_DATA if self.message_id(payload) == id => Some((tag, id, payload)),
            DELIVERY_ACK if payload.is_empty() => Some((tag, id, payload)),
            _ => None,
        }
    }

    fn ack_envelope(id: B256) -> Vec<u8> {
        let mut ack = Vec::with_capacity(1 + DELIVERY_ID_LEN);
        ack.push(DELIVERY_ACK);
        ack.extend_from_slice(id.as_slice());
        ack
    }
}

/// Adapts the consensus P2P channel (commonware `Sender`/`Receiver`) to the
/// [`BootstrapGossip`] surface the coordination needs. Messages are opaque bytes.
pub struct CommonwareBootstrapGossip<S, R, C> {
    pub sender: S,
    pub receiver: R,
    clock: C,
    delivery: DeliveryTracker,
}

impl<S, R, C> BootstrapGossip for CommonwareBootstrapGossip<S, R, C>
where
    S: P2pSender<PublicKey = bls12381::PublicKey>,
    R: P2pReceiver<PublicKey = bls12381::PublicKey>,
    C: Clock,
{
    async fn broadcast(&mut self, bytes: Vec<u8>) -> Result<(), CeremonyError> {
        let envelope = self.delivery.envelope(Recipients::All, bytes)?;
        let _ = self.sender.send(Recipients::All, envelope, true);
        Ok(())
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        const RETRY_POLL: std::time::Duration = std::time::Duration::from_millis(750);
        loop {
            commonware_macros::select! {
                recv = self.receiver.recv() => {
                    return match recv {
                        Ok((from, raw)) => {
                            if !self.delivery.observe_peer(from.clone()) {
                                continue;
                            }
                            match self.delivery.decode(raw.as_ref()) {
                                Some((DELIVERY_DATA, id, payload)) => {
                                    let _ = self.sender.send(
                                        Recipients::One(from),
                                        DeliveryTracker::ack_envelope(id),
                                        true,
                                    );
                                    Some(payload.to_vec())
                                }
                                Some((DELIVERY_ACK, id, _)) => {
                                    self.delivery.acknowledge(&from, id);
                                    continue;
                                }
                                _ => continue,
                            }
                        }
                        Err(_) => None,
                    };
                },
                _ = self.clock.sleep(RETRY_POLL) => {
                    for (recipients, bytes) in self.delivery.retry_batch() {
                        let _ = self.sender.send(recipients, bytes, true);
                    }
                },
            }
        }
    }
}

/// Envelope tag for a ceremony [`DkgWireMessage`] on the TEE-DKG channel.
const DKG_ENV_CEREMONY: u8 = 0x00;
/// Envelope tag for an enclave-identity announcement on the TEE-DKG channel.
const DKG_ENV_IDENTITY: u8 = 0x01;

/// Adapts the consensus P2P channel to the TEE-DKG [`DkgGossip`] surface, and runs
/// the pre-ceremony enclave-identity exchange.
///
/// Two message kinds share the channel, distinguished by a 1-byte envelope tag:
/// ceremony messages ([`DkgWireMessage`]) and identity announcements
/// (`tee_bls || dkg_enc`). The ceremony addresses dealer->player bundles by the
/// recipient's *enclave* BLS key, but P2P routes by the *consensus* BLS key, so a
/// `tee_bls -> consensus_pubkey` routing map is built during identity exchange
/// (from the authenticated sender of each identity message) and used to address
/// sends. Broadcasting addressed bundles instead would make every non-recipient
/// enclave fail to open the share (it is sealed to one recipient) and abort the
/// ceremony.
pub struct CommonwareDkgGossip<S, R, C> {
    sender: S,
    receiver: R,
    clock: C,
    /// `tee_bls -> consensus P2P pubkey` for addressed ceremony sends.
    routing: BTreeMap<Vec<u8>, bls12381::PublicKey>,
    /// Ceremony messages received during the identity-exchange phase, replayed
    /// before reading new ones so the phase race loses nothing.
    buffered: VecDeque<(Vec<u8>, DkgWireMessage)>,
    /// Signed announcements can arrive during preliminary BLS discovery. Once
    /// ACKed they must survive the phase transition; the sender may stop retrying.
    /// Bounded by the expected participant count of this startup exchange.
    early_signed_identities: BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)>,
    /// Typed, bounded delivery state. Transport acknowledgements suppress
    /// retries per message and peer; the enclosing startup timeout remains the
    /// ceremony deadline.
    delivery: DeliveryTracker,
}

impl<S, R, C> CommonwareDkgGossip<S, R, C>
where
    S: P2pSender<PublicKey = bls12381::PublicKey>,
    R: P2pReceiver<PublicKey = bls12381::PublicKey>,
    C: Clock,
{
    pub fn new(
        sender: S,
        receiver: R,
        clock: C,
        scope: B256,
        allowed_peers: BTreeSet<bls12381::PublicKey>,
    ) -> Self {
        Self {
            sender,
            receiver,
            clock,
            routing: BTreeMap::new(),
            buffered: VecDeque::new(),
            early_signed_identities: BTreeMap::new(),
            delivery: DeliveryTracker::new(scope, allowed_peers),
        }
    }

    fn send_ceremony(
        &mut self,
        recipients: Recipients<bls12381::PublicKey>,
        msg: &DkgWireMessage,
    ) -> Result<(), CeremonyError> {
        let mut env = Vec::with_capacity(1 + 8);
        env.push(DKG_ENV_CEREMONY);
        env.extend_from_slice(&msg.to_bytes());
        let envelope = self.delivery.envelope(recipients.clone(), env)?;
        let _ = self.sender.send(recipients, envelope, true);
        Ok(())
    }

    /// Announce this enclave's `(tee_bls, dkg_enc)` identity and collect all `n`
    /// participants' identities, buffering any ceremony messages that arrive
    /// early and recording the `tee_bls -> consensus_pubkey` routing. Returns the
    /// identities sorted canonically by `tee_bls` (so every node derives the same
    /// ceremony id and participant order).
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_identities(
        &mut self,
        my_bls: Vec<u8>,
        my_enc: [u8; 32],
        my_sig: Vec<u8>,
        ceremony_id: B256,
        round: u64,
        participant_set_hash: B256,
        n: usize,
    ) -> eyre::Result<Vec<outbe_tee::protocol::ParticipantAnnounce>> {
        let require_scoped_announcement = !my_sig.is_empty();
        let mut ids = if require_scoped_announcement {
            std::mem::take(&mut self.early_signed_identities)
        } else {
            BTreeMap::new()
        };
        ids.insert(my_bls.clone(), (my_enc, my_sig.clone()));

        let mut env = vec![DKG_ENV_IDENTITY];
        env.extend_from_slice(&(my_bls.len() as u32).to_be_bytes());
        env.extend_from_slice(&my_bls);
        env.extend_from_slice(&my_enc);
        env.extend_from_slice(&(my_sig.len() as u32).to_be_bytes());
        env.extend_from_slice(&my_sig);
        let delivery_env = self
            .delivery
            .envelope(Recipients::All, env.clone())
            .map_err(|error| eyre::eyre!(error))?;
        let _ = self.sender.send(Recipients::All, delivery_env, true);

        // Re-broadcast our identity periodically until every peer's identity is
        // collected. The muxed sub-channel drops messages addressed to a round a
        // peer has not yet registered, so a node that announces before its peers
        // register would otherwise be lost and the exchange would hang. Retrying
        // makes the exchange robust to that registration race on every round.
        // The poll cadence is measured on the consensus runtime `Clock` (the same
        // time source the deterministic test runtime can mock and advance), not
        // tokio's wall-clock - keeping the identity-exchange re-announce loop
        // reproducible and free of a direct async-runtime timer dependency. `select!`
        // is biased top-to-bottom, so a ready message is preferred over the tick;
        // on the tick arm the in-flight `recv` future is dropped (cancel-safe on
        // this receiver, so no buffered message is lost).
        const POLL: std::time::Duration = std::time::Duration::from_millis(750);
        let mut idle_ticks = 0u32;
        while ids.len() < n {
            commonware_macros::select! {
                recv = self.receiver.recv() => {
                    match recv {
                        Ok((from, raw)) => {
                            if !self.delivery.observe_peer(from.clone()) {
                                continue;
                            }
                            let bytes = match self.delivery.decode(raw.as_ref()) {
                                Some((DELIVERY_DATA, id, payload)) => {
                                    let _ = self.sender.send(
                                        Recipients::One(from.clone()),
                                        DeliveryTracker::ack_envelope(id),
                                        true,
                                    );
                                    payload
                                }
                                Some((DELIVERY_ACK, id, _)) => {
                                    self.delivery.acknowledge(&from, id);
                                    continue;
                                }
                                _ => continue,
                            };
                            match bytes.first().copied() {
                                Some(DKG_ENV_IDENTITY) => {
                                    if let Some((bls, enc, sig)) = parse_identity(&bytes[1..]) {
                                        if require_scoped_announcement && sig.is_empty() {
                                            continue;
                                        }
                                        if !require_scoped_announcement && !sig.is_empty() {
                                            if !self.early_signed_identities.contains_key(&bls)
                                                && self.early_signed_identities.len() >= n
                                            {
                                                return Err(eyre::eyre!(
                                                    "TEE DKG early signed identity budget exceeded: {n}"
                                                ));
                                            }
                                            self.early_signed_identities
                                                .insert(bls.clone(), (enc, sig.clone()));
                                        }
                                        self.routing.insert(bls.clone(), from);
                                        ids.insert(bls, (enc, sig));
                                    }
                                }
                                Some(DKG_ENV_CEREMONY) => {
                                    if let Ok(msg) = DkgWireMessage::from_bytes(&bytes[1..]) {
                                        self.buffered.push_back((from.encode().to_vec(), msg));
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(_) => {
                            return Err(eyre::eyre!(
                                "TEE DKG identity gossip closed before all {n} identities collected"
                            ));
                        }
                    }
                },
                _ = self.clock.sleep(POLL) => {
                    // Timeout with no new identity: re-announce so peers that
                    // registered the round late still receive us. Bound the wait.
                    idle_ticks += 1;
                    if idle_ticks > 120 {
                        return Err(eyre::eyre!(
                            "TEE DKG identity exchange timed out: collected {}/{n}",
                            ids.len()
                        ));
                    }
                    for (recipients, bytes) in self.delivery.retry_batch() {
                        let _ = self.sender.send(recipients, bytes, true);
                    }
                },
            }
        }
        Ok(ids
            .into_iter()
            .map(
                |(bls, (enc, sig))| outbe_tee::protocol::ParticipantAnnounce {
                    bls_pub: bls,
                    enc_pub: enc,
                    ceremony_id,
                    round,
                    participant_set_hash,
                    enc_sig: sig,
                },
            )
            .collect())
    }
}

impl<S, R, C> DkgGossip for CommonwareDkgGossip<S, R, C>
where
    S: P2pSender<PublicKey = bls12381::PublicKey>,
    R: P2pReceiver<PublicKey = bls12381::PublicKey>,
    C: Clock,
{
    async fn send(&mut self, to: &[u8], msg: DkgWireMessage) -> Result<(), CeremonyError> {
        match self.routing.get(to).cloned() {
            Some(peer) => self.send_ceremony(Recipients::One(peer), &msg)?,
            // No route (should not happen post identity-exchange): broadcast so the
            // recipient still receives it; non-recipients ignore foreign shares.
            None => self.send_ceremony(Recipients::All, &msg)?,
        }
        Ok(())
    }

    async fn broadcast(&mut self, msg: DkgWireMessage) -> Result<(), CeremonyError> {
        self.send_ceremony(Recipients::All, &msg)?;
        Ok(())
    }

    async fn recv(&mut self) -> Option<(Vec<u8>, DkgWireMessage)> {
        if let Some(buffered) = self.buffered.pop_front() {
            return Some(buffered);
        }
        const RETRY_POLL: std::time::Duration = std::time::Duration::from_millis(750);
        loop {
            commonware_macros::select! {
                recv = self.receiver.recv() => {
                    let (from, raw) = recv.ok()?;
                    if !self.delivery.observe_peer(from.clone()) {
                        continue;
                    }
                    let bytes = match self.delivery.decode(raw.as_ref()) {
                        Some((DELIVERY_DATA, id, payload)) => {
                            let _ = self.sender.send(
                                Recipients::One(from.clone()),
                                DeliveryTracker::ack_envelope(id),
                                true,
                            );
                            payload
                        }
                        Some((DELIVERY_ACK, id, _)) => {
                            self.delivery.acknowledge(&from, id);
                            continue;
                        }
                        _ => continue,
                    };
                    match bytes.first().copied() {
                        Some(DKG_ENV_CEREMONY) => match DkgWireMessage::from_bytes(&bytes[1..]) {
                            Ok(msg) => return Some((from.encode().to_vec(), msg)),
                            Err(_) => continue,
                        },
                        // Late identity announcement (a peer still in its exchange phase):
                        // ignore and keep reading.
                        _ => continue,
                    }
                },
                _ = self.clock.sleep(RETRY_POLL) => {
                    for (recipients, env) in self.delivery.retry_batch() {
                        let _ = self.sender.send(recipients, env, true);
                    }
                },
            }
        }
    }
}

/// Parse an identity announcement body
/// `bls_len(u32 BE) || bls || enc(32) || sig_len(u32 BE) || sig`.
fn parse_identity(body: &[u8]) -> Option<(Vec<u8>, [u8; 32], Vec<u8>)> {
    if body.len() < 4 {
        return None;
    }
    let bls_len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let enc_start = 4usize.checked_add(bls_len)?;
    let enc_end = enc_start.checked_add(32)?;
    let sig_len_end = enc_end.checked_add(4)?;
    if body.len() < sig_len_end {
        return None;
    }
    let sig_len = u32::from_be_bytes([
        body[enc_end],
        body[enc_end + 1],
        body[enc_end + 2],
        body[enc_end + 3],
    ]) as usize;
    let sig_end = sig_len_end.checked_add(sig_len)?;
    if sig_end != body.len() {
        return None;
    }
    let bls = body[4..enc_start].to_vec();
    let mut enc = [0u8; 32];
    enc.copy_from_slice(&body[enc_start..enc_end]);
    let sig = body[sig_len_end..sig_end].to_vec();
    Some((bls, enc, sig))
}

/// Run the one-time TEE DKG ceremony at startup and return the **shared offer
/// public key** derived from the group threshold signature (Seam F). Connects
/// this node's enclave, exchanges enclave identities across the committee,
/// drives the dealer/player ceremony + the offer-key partial-signature round
/// entirely through the enclave seams, and returns the byte-identical
/// `tribute_offer_public` every honest node derives. The offer *secret* never leaves the
/// enclave; it is stored resident there and used to decrypt offers.
///
/// `n` is the committee size; `chain_id`/`tribute_offer_epoch` bind the derived offer
/// key. Runs before [`run_tee_bootstrap_v2_at_startup`], whose OST3 payload registers the
/// returned key on-chain at block 1.
#[allow(clippy::too_many_arguments)]
pub async fn run_tee_dkg_at_startup<E, S, R, C>(
    client: &mut E,
    clock: C,
    n: usize,
    network_binding: outbe_primitives::tee_attestation_v1::NetworkBindingV1,
    tribute_offer_epoch: u64,
    allowed_remote_peers: BTreeSet<bls12381::PublicKey>,
    sender: S,
    receiver: R,
) -> eyre::Result<([u8; 32], Vec<u8>)>
where
    E: outbe_tee::tee_dkg::EnclaveChannel,
    S: P2pSender<PublicKey = bls12381::PublicKey>,
    R: P2pReceiver<PublicKey = bls12381::PublicKey>,
    C: Clock,
{
    let my_bls = match client
        .request(&EnclaveRequest::GetPublicKeys)
        .map_err(|e| eyre::eyre!("TEE DKG GetPublicKeys failed: {e}"))?
    {
        EnclaveResponse::PublicKeys { tee_bls_pub, .. } => tee_bls_pub,
        other => return Err(eyre::eyre!("unexpected GetPublicKeys response: {other:?}")),
    };

    let chain_id = B256::from(network_binding.chain_id);

    let mut dkg_scope = Vec::with_capacity(32 + 8 + 7);
    dkg_scope.extend_from_slice(chain_id.as_slice());
    dkg_scope.extend_from_slice(&tribute_offer_epoch.to_be_bytes());
    dkg_scope.extend_from_slice(b"tee-dkg");
    let mut gossip = CommonwareDkgGossip::new(
        sender,
        receiver,
        clock,
        keccak256(dkg_scope),
        allowed_remote_peers,
    );
    // First exchange only the public BLS identities. The resulting exact set is
    // then network-bound inside each enclave before any share-recipient key is
    // trusted.
    let preliminary = gossip
        .exchange_identities(
            my_bls.clone(),
            [0; 32],
            Vec::new(),
            B256::ZERO,
            0,
            B256::ZERO,
            n,
        )
        .await?;
    let participant_bls = preliminary
        .iter()
        .map(|participant| participant.bls_pub.clone())
        .collect::<Vec<_>>();
    let participant_set_hash =
        outbe_primitives::tee_attestation_v1::dkg_participant_set_hash_v1(&participant_bls)
            .map_err(|error| eyre::eyre!("invalid TEE DKG participant set: {error}"))?;
    let ceremony_id = outbe_primitives::tee_attestation_v1::dkg_ceremony_id_v1(
        &network_binding,
        0,
        participant_set_hash,
    )
    .map_err(|error| eyre::eyre!("invalid TEE DKG ceremony binding: {error}"))?;
    let my_announcement = match client
        .request(&EnclaveRequest::DkgParticipantAnnounceV1 {
            ceremony_id,
            round: 0,
            participant_bls,
        })
        .map_err(|error| eyre::eyre!("TEE DKG announcement failed: {error}"))?
    {
        EnclaveResponse::DkgParticipantAnnounceV1 { participant } => participant,
        other => {
            return Err(eyre::eyre!(
                "unexpected DKG announcement response: {other:?}"
            ))
        }
    };
    let identities = gossip
        .exchange_identities(
            my_announcement.bls_pub.clone(),
            my_announcement.enc_pub,
            my_announcement.enc_sig,
            ceremony_id,
            0,
            participant_set_hash,
            n,
        )
        .await?;
    let coord = CeremonyCoordinator::new(ceremony_id, 0, my_bls, identities);

    let outcome = run_tee_dkg_ceremony(
        &coord,
        client,
        &mut gossip,
        n,
        chain_id,
        tribute_offer_epoch,
    )
    .await
    .map_err(|e| eyre::eyre!("TEE DKG ceremony failed: {e}"))?;

    Ok((
        outcome.tribute_offer_public,
        outcome.tribute_offer_group_public_key,
    ))
}

/// Read the permanent offer public key only after the enclave marks it ready.
/// Before readiness the recipient field is exclusively an onboarding key and
/// must never be compared with canonical OST3 state.
pub fn query_enclave_offer_public<E>(client: &mut E) -> eyre::Result<B256>
where
    E: outbe_tee::tee_dkg::EnclaveChannel,
{
    match client
        .request(&EnclaveRequest::GetPublicKeys)
        .map_err(|e| eyre::eyre!("TEE GetPublicKeys failed: {e}"))?
    {
        EnclaveResponse::PublicKeys {
            offer_key_ready,
            recipient_x25519_pub,
            ..
        } => {
            if !offer_key_ready {
                return Err(eyre::eyre!(
                    "local enclave permanent offer key is not ready; no recovery or fallback exists"
                ));
            }
            let public = B256::from(recipient_x25519_pub);
            if public.is_zero() {
                return Err(eyre::eyre!(
                    "local enclave reports a ready but zero permanent offer key"
                ));
            }
            Ok(public)
        }
        other => Err(eyre::eyre!("unexpected GetPublicKeys response: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{bootstrap_evidence_kind, BootstrapEvidenceKind, DeliveryTracker};
    use alloy_primitives::B256;
    use commonware_cryptography::{bls12381, Signer as _};
    use commonware_p2p::Recipients;
    use outbe_primitives::tee_attestation_v1::AttestationMode;

    /// Only transport ordering and time are controlled. Both exchanges and
    /// delivery acknowledgements use the production implementation.
    mod identity_phase_regression {
        use super::*;
        use crate::tee_bootstrap::{CommonwareDkgGossip, DELIVERY_ACK, DKG_ENV_IDENTITY};
        use commonware_actor::{Feedback, Unreliable};
        use commonware_codec::Encode as _;
        use commonware_p2p::{CheckedSender, LimitedSender, Message, Receiver};
        use commonware_runtime::{deterministic, IoBufs, Runner as _};
        use std::{
            collections::VecDeque,
            convert::Infallible,
            sync::{Arc, Mutex},
            time::{Duration, SystemTime},
        };

        type Sent = Arc<Mutex<Vec<(Vec<bls12381::PublicKey>, Vec<u8>)>>>;

        #[derive(Clone)]
        struct RecordingSender {
            peers: Vec<bls12381::PublicKey>,
            sent: Sent,
        }

        struct RecordingCheckedSender {
            peers: Vec<bls12381::PublicKey>,
            sent: Sent,
        }

        impl CheckedSender for RecordingCheckedSender {
            type PublicKey = bls12381::PublicKey;

            fn recipients(&self) -> Vec<Self::PublicKey> {
                self.peers.clone()
            }

            fn send(self, message: impl Into<IoBufs> + Send, _: bool) -> Unreliable<Feedback> {
                self.sent
                    .lock()
                    .unwrap()
                    .push((self.peers, message.into().coalesce().as_ref().to_vec()));
                Unreliable::Outcome(Feedback::Ok)
            }
        }

        impl LimitedSender for RecordingSender {
            type PublicKey = bls12381::PublicKey;
            type Checked<'a> = RecordingCheckedSender;

            fn check(
                &mut self,
                recipients: Recipients<Self::PublicKey>,
            ) -> Result<Self::Checked<'_>, SystemTime> {
                let peers = match recipients {
                    Recipients::All => self.peers.clone(),
                    Recipients::Some(peers) => peers,
                    Recipients::One(peer) => vec![peer],
                };
                Ok(RecordingCheckedSender {
                    peers,
                    sent: self.sent.clone(),
                })
            }
        }

        #[derive(Debug)]
        struct OrderedReceiver(Arc<Mutex<VecDeque<Message<bls12381::PublicKey>>>>);

        impl Receiver for OrderedReceiver {
            type Error = Infallible;
            type PublicKey = bls12381::PublicKey;

            async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
                let message = self.0.lock().unwrap().pop_front();
                match message {
                    Some(message) => Ok(message),
                    // Keep the channel open: the production identity timeout,
                    // not a closed test channel, must expose missing delivery.
                    None => std::future::pending().await,
                }
            }
        }

        fn announcement(tracker: &mut DeliveryTracker, bls: &[u8], signed: bool) -> Vec<u8> {
            // Signature contents are opaque at this transport seam. Enclave
            // signature verification is deliberately not claimed by this test.
            let sig = if signed { vec![0x55; 96] } else { Vec::new() };
            let mut payload = vec![DKG_ENV_IDENTITY];
            payload.extend_from_slice(&(bls.len() as u32).to_be_bytes());
            payload.extend_from_slice(bls);
            payload.extend_from_slice(&[if signed { 0x22 } else { 0 }; 32]);
            payload.extend_from_slice(&(sig.len() as u32).to_be_bytes());
            payload.extend_from_slice(&sig);
            tracker.envelope(Recipients::All, payload).unwrap()
        }

        fn exchange_with_order(early_signed: bool) {
            deterministic::Runner::timed(Duration::from_secs(100)).start(|context| async move {
                let peers: Vec<_> = (201..205).map(|seed| bls12381::PrivateKey::from_seed(seed).public_key()).collect();
                let bls: Vec<_> = (301..305).map(|seed| bls12381::PrivateKey::from_seed(seed).public_key().encode().to_vec()).collect();
                let scope = B256::repeat_byte(0x31);
                let mut trackers: Vec<_> = (1..4).map(|sender| {
                    DeliveryTracker::new(scope, peers.iter().enumerate().filter(|(i, _)| *i != sender).map(|(_, peer)| peer.clone()).collect())
                }).collect();
                let preliminary: Vec<_> = (1..4).map(|i| announcement(&mut trackers[i - 1], &bls[i], false)).collect();
                let signed: Vec<_> = (1..4).map(|i| announcement(&mut trackers[i - 1], &bls[i], true)).collect();
                let inbox = Arc::new(Mutex::new(VecDeque::new()));
                // A receives B's signed announcement while still waiting for
                // C and D's preliminary identities. No packet is dropped.
                for i in 1..4 {
                    inbox.lock().unwrap().push_back((peers[i].clone(), preliminary[i - 1].clone().into()));
                    if i == 1 && early_signed {
                        inbox.lock().unwrap().push_back((peers[i].clone(), signed[0].clone().into()));
                    }
                }
                let sent = Sent::default();
                let mut gossip = CommonwareDkgGossip::new(
                    RecordingSender { peers: peers[1..].to_vec(), sent: sent.clone() },
                    OrderedReceiver(inbox.clone()), context, scope, peers[1..].iter().cloned().collect(),
                );
                let first = gossip.exchange_identities(bls[0].clone(), [0; 32], Vec::new(), B256::ZERO, 0, B256::ZERO, 4).await.unwrap();
                assert_eq!(first.len(), 4, "preliminary exchange must complete");

                if early_signed {
                    let (_, signed_id, _) = trackers[0].decode(&signed[0]).unwrap();
                    let ack = sent.lock().unwrap().iter().find_map(|(to, bytes)| {
                        let (tag, id, _) = trackers[0].decode(bytes)?;
                        (to == &vec![peers[1].clone()] && tag == DELIVERY_ACK && id == signed_id).then_some(id)
                    }).expect("A must have ACKed B's signed announcement during preliminary exchange");
                    // The other recipients have also acknowledged B. Feeding
                    // A's actual ACK makes production delivery stop retrying B.
                    for peer in [&peers[2], &peers[3], &peers[0]] {
                        assert!(trackers[0].observe_peer(peer.clone()));
                        trackers[0].acknowledge(peer, ack);
                    }
                    for _ in 0..=120 {
                        assert!(trackers[0].retry_batch().iter().all(|(_, bytes)| bytes != &signed[0]), "an ACKed announcement must not be retransmitted");
                    }
                }
                for i in 1..4 {
                    if i != 1 || !early_signed {
                        inbox.lock().unwrap().push_back((peers[i].clone(), signed[i - 1].clone().into()));
                    }
                }
                let result = gossip.exchange_identities(bls[0].clone(), [0x22; 32], vec![0x55; 96], B256::repeat_byte(0x41), 0, B256::repeat_byte(0x42), 4).await;
                let identities = result.expect("all four signed identities were delivered; an ACKed early announcement must survive the phase transition");
                assert_eq!(identities.len(), 4);
                for (identity, expected_bls) in identities.iter().zip(bls.iter().collect::<std::collections::BTreeSet<_>>()) {
                    assert_eq!(&identity.bls_pub, expected_bls);
                    assert_eq!(identity.enc_pub, [0x22; 32]);
                    assert_eq!(identity.enc_sig, vec![0x55; 96]);
                }
            });
        }

        #[test]
        fn signed_identities_arriving_in_their_phase_complete() {
            exchange_with_order(false);
        }

        #[test]
        fn early_acked_signed_identity_survives_phase_transition() {
            exchange_with_order(true);
        }
    }

    #[test]
    fn bootstrap_evidence_depends_on_policy_not_local_session_security() {
        assert_eq!(
            bootstrap_evidence_kind(AttestationMode::DcapRequired, true).unwrap(),
            BootstrapEvidenceKind::Dcap
        );
        assert_eq!(
            bootstrap_evidence_kind(AttestationMode::GramineDirectDev, true).unwrap(),
            BootstrapEvidenceKind::GramineDirectDev
        );
        assert_eq!(
            bootstrap_evidence_kind(AttestationMode::GramineDirectDev, false).unwrap(),
            BootstrapEvidenceKind::GramineDirectDev
        );
        assert!(bootstrap_evidence_kind(AttestationMode::DcapRequired, false).is_err());
    }

    #[test]
    fn delivery_tracker_retries_only_unacknowledged_peers() {
        let peer_a = bls12381::PrivateKey::from_seed(101).public_key();
        let peer_b = bls12381::PrivateKey::from_seed(102).public_key();
        let mut tracker = DeliveryTracker::new(
            B256::repeat_byte(0x11),
            [peer_a.clone(), peer_b.clone()].into_iter().collect(),
        );
        assert!(tracker.observe_peer(peer_a.clone()));
        assert!(tracker.observe_peer(peer_b.clone()));
        let envelope = tracker
            .envelope(Recipients::All, b"registration".to_vec())
            .unwrap();
        let (_, id, _) = tracker.decode(&envelope).unwrap();

        assert_eq!(tracker.retry_batch().len(), 2);
        tracker.acknowledge(&peer_a, id);
        assert!(tracker.retry_batch().is_empty());
        let retry = tracker.retry_batch();
        assert_eq!(retry.len(), 1);
        assert!(matches!(&retry[0].0, Recipients::One(peer) if peer == &peer_b));

        tracker.acknowledge(&peer_b, id);
        assert!(tracker.pending.is_empty());
        assert!(tracker.retry_batch().is_empty());
    }

    #[test]
    fn delivery_tracker_uses_capped_exponential_backoff() {
        let peer = bls12381::PrivateKey::from_seed(103).public_key();
        let mut tracker = DeliveryTracker::new(
            B256::repeat_byte(0x22),
            [peer.clone()].into_iter().collect(),
        );
        assert!(tracker.observe_peer(peer));
        tracker
            .envelope(Recipients::All, b"signature".to_vec())
            .unwrap();

        let mut sends = Vec::new();
        for tick in 1..=31 {
            if !tracker.retry_batch().is_empty() {
                sends.push(tick);
            }
        }
        assert_eq!(sends, vec![1, 3, 7, 15, 31]);
    }

    #[test]
    fn delivery_tracker_merges_recipients_for_identical_payloads() {
        let peer_a = bls12381::PrivateKey::from_seed(104).public_key();
        let peer_b = bls12381::PrivateKey::from_seed(105).public_key();
        let mut tracker = DeliveryTracker::new(
            B256::repeat_byte(0x33),
            [peer_a.clone(), peer_b.clone()].into_iter().collect(),
        );
        assert!(tracker.observe_peer(peer_a.clone()));
        assert!(tracker.observe_peer(peer_b.clone()));

        let first = tracker
            .envelope(Recipients::One(peer_a.clone()), b"same".to_vec())
            .unwrap();
        let second = tracker
            .envelope(Recipients::One(peer_b.clone()), b"same".to_vec())
            .unwrap();
        assert_eq!(first, second);

        let retry = tracker.retry_batch();
        assert_eq!(retry.len(), 2);
        let (_, id, _) = tracker.decode(&first).unwrap();
        tracker.acknowledge(&peer_a, id);
        assert!(!tracker.pending.is_empty());
        tracker.acknowledge(&peer_b, id);
        assert!(tracker.pending.is_empty());
    }
}
