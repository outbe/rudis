use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolCall, SolEvent};
use ed25519_dalek::Signer as _;
use k256::ecdsa::signature::hazmat::PrehashSigner as _;
use outbe_primitives::{
    chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID},
    error::PrecompileError,
    signer::OutbeEvmSigner,
    storage::{hashmap::HashMapStorageProvider, PrecompileStorageProvider, StorageHandle},
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapCollateralComponentV1,
        DcapCollateralKind, DcapEvidenceV1, EnclaveInitializationManifestV1, NodeIdV1,
        PlatformTcbStatusSetV1, QvlTcbStatusV1, RegistrationIntentV1, RegistryMutatorV1,
        TeeMeasurementRuleV1, TeePolicyV1, TeeRegistryGasScheduleV1, TransitionKeyReadyProofV1,
        ValidatorNodeBindingV1,
    },
};
use outbe_tee::dcap_protocol::{
    DcapOnboardingArtifactV1, DcapOnboardingContextV1, DcapPckCaV1, DcapPlatformTcbStatusV1,
    DcapVerdictV1,
};
use outbe_tee::finalized_admission::{
    TEE_REGISTRY_KEY_EPOCH_SLOT_V1, TEE_REGISTRY_NODE_BINDING_ID_SLOT_V1,
    TEE_REGISTRY_NODE_ENCLAVE_ID_SLOT_V1, TEE_REGISTRY_NODE_INTENT_HASH_SLOT_V1,
    TEE_REGISTRY_NODE_POLICY_HASH_SLOT_V1, TEE_REGISTRY_NODE_RECIPIENT_X25519_SLOT_V1,
    TEE_REGISTRY_NODE_VALID_UNTIL_SLOT_V1, TEE_REGISTRY_OFFER_EPOCH_SLOT_V1,
    TEE_REGISTRY_OFFER_PUBLIC_SLOT_V1,
};
use outbe_validatorset::contract::ValidatorSet;

use crate::{
    runtime::TeeBootstrapData,
    schema::TeeRegistry,
    v1::{
        OfferKeySealedForRegistryV1, PostVerifierDcapCapabilityV1, V1OnboardingOutcome,
        V1RegistrationOutcome,
    },
    v1_precompile::{
        dispatch_register_after_verifier_for_test,
        dispatch_register_with_onboarding_after_verifier_for_test,
        dispatch_renew_after_verifier_for_test, dispatch_replace_after_verifier_for_test,
        dispatch_transition_after_verifier_for_test,
    },
};

sol! {
    interface IRegisterEnclaveV1Test {
        function registerEnclave(
            bytes calldata evidence,
            bytes calldata nodeSignature,
            bytes calldata enclaveSignature,
            bytes calldata validatorNodeBinding,
            bytes calldata validatorSignature,
            bytes calldata nodeBindingSignature
        ) external returns (bool);

        function renewEnclave(
            bytes calldata evidence,
            bytes calldata nodeSignature,
            bytes calldata enclaveSignature
        ) external returns (bool);

        function replaceEnclaveBinding(
            bytes calldata evidence,
            bytes calldata nodeSignature,
            bytes calldata enclaveSignature
        ) external returns (bool);

        function transitionEnclaveMeasurement(
            bytes calldata evidence,
            bytes calldata nodeSignature,
            bytes calldata enclaveSignature
        ) external returns (bool);
    }
}

const CHAIN_ID: u64 = TESTNET_CHAIN_ID;
const NOW: u64 = 10_000;
const MRENCLAVE: B256 = B256::repeat_byte(0x81);
const MRSIGNER: B256 = B256::repeat_byte(0x82);
const CONSENSUS_KEY: [u8; 48] = [0x32; 48];
const NODE_HOST_NOISE_X25519: [u8; 32] = [0xa5; 32];
const OFFER_PUBLIC: [u8; 32] = [0xb1; 32];

fn policy(genesis_hash: B256, statuses: PlatformTcbStatusSetV1) -> TeePolicyV1 {
    TeePolicyV1 {
        policy_version: 1,
        chain_id: U256::from(CHAIN_ID).to_be_bytes(),
        genesis_hash,
        activation_height: 1,
        predecessor_policy_hash: B256::ZERO,
        attestation_mode: AttestationMode::DcapRequired,
        intel_root_der_hash: B256::repeat_byte(0x71),
        quote_version: 3,
        tee_type: 0,
        attestation_key_type: 2,
        qe_vendor_id: [
            0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
            0x06, 0x07,
        ],
        certification_data_type: 5,
        tcb_info_schema_version: 3,
        qe_identity_schema_version: 2,
        minimum_tcb_evaluation_data_number: 1,
        accepted_platform_tcb_statuses: statuses,
        accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
        minimum_lease: 3_600,
        maximum_lease: 604_800,
        collateral_margin: 3_600,
        resource_schedule_hash: B256::repeat_byte(0x72),
        measurement_rules: vec![TeeMeasurementRuleV1 {
            mrenclave: MRENCLAVE,
            mrsigner: MRSIGNER,
            isv_prod_id: 7,
            minimum_isv_svn: 3,
            admit_from_height: 1,
            admit_until_height_exclusive: 100,
        }],
    }
}

fn storage(genesis_hash: B256) -> HashMapStorageProvider {
    storage_for_chain(CHAIN_ID, genesis_hash)
}

fn storage_for_chain(chain_id: u64, genesis_hash: B256) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_chain_identity(chain_id, genesis_hash);
    storage.set_block_number(10);
    storage.set_timestamp(U256::from(NOW));
    storage
}

#[test]
fn finalized_admission_slot_contract_matches_the_physical_registry_layout() {
    let mut provider = storage(B256::repeat_byte(0x44));
    StorageHandle::enter(&mut provider, |storage| {
        let registry = TeeRegistry::new(storage);
        assert_eq!(
            registry.tribute_offer_public_key.slot(),
            U256::from(TEE_REGISTRY_OFFER_PUBLIC_SLOT_V1)
        );
        assert_eq!(
            registry.key_epoch.slot(),
            U256::from(TEE_REGISTRY_KEY_EPOCH_SLOT_V1)
        );
        assert_eq!(
            registry.tribute_offer_epoch.slot(),
            U256::from(TEE_REGISTRY_OFFER_EPOCH_SLOT_V1)
        );
        assert_eq!(
            registry.v1_node_enclave_id.base_slot(),
            U256::from(TEE_REGISTRY_NODE_ENCLAVE_ID_SLOT_V1)
        );
        assert_eq!(
            registry.v1_node_binding_id.base_slot(),
            U256::from(TEE_REGISTRY_NODE_BINDING_ID_SLOT_V1)
        );
        assert_eq!(
            registry.v1_node_intent_hash.base_slot(),
            U256::from(TEE_REGISTRY_NODE_INTENT_HASH_SLOT_V1)
        );
        assert_eq!(
            registry.v1_node_policy_hash.base_slot(),
            U256::from(TEE_REGISTRY_NODE_POLICY_HASH_SLOT_V1)
        );
        assert_eq!(
            registry.v1_node_valid_until.base_slot(),
            U256::from(TEE_REGISTRY_NODE_VALID_UNTIL_SLOT_V1)
        );
        assert_eq!(
            registry.v1_node_recipient_x25519.base_slot(),
            U256::from(TEE_REGISTRY_NODE_RECIPIENT_X25519_SLOT_V1)
        );
        Ok::<(), PrecompileError>(())
    })
    .unwrap();
}

fn sealed_offer_artifact(intent: &RegistrationIntentV1, offer_public: B256, fill: u8) -> Vec<u8> {
    DcapOnboardingArtifactV1 {
        context: DcapOnboardingContextV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            intent_hash: intent.intent_hash().unwrap(),
            node_id_hash: intent.node_id.node_id_hash().unwrap(),
            enclave_id: intent.derived_enclave_id().unwrap(),
            binding_id: intent.binding_id,
            policy_hash: intent.policy_hash,
            recipient_x25519: intent.recipient_x25519,
            tribute_offer_public: offer_public.0,
            key_epoch: 0,
            tribute_offer_epoch: 0,
        },
        nonce: [fill; 12],
        ciphertext: vec![fill; 112],
    }
    .encode_canonical()
    .unwrap()
}

fn register_validator(
    storage: StorageHandle<'_>,
    signer: &OutbeEvmSigner,
    consensus_key: [u8; 48],
) {
    ValidatorSet::new(storage)
        .register_validator(Address::ZERO, signer.address(), &consensus_key)
        .expect("genesis-owner validator registration");
}

fn reth_p2p_public_for_evm_signer(node_signer: &OutbeEvmSigner) -> [u8; 33] {
    let proof_hash = B256::repeat_byte(0xA7);
    let proof = node_signer.sign_hash(&proof_hash).unwrap();
    let proof_signature = k256::ecdsa::Signature::from_slice(&proof[..64]).unwrap();
    let proof_recovery = k256::ecdsa::RecoveryId::from_byte(proof[64]).unwrap();
    k256::ecdsa::VerifyingKey::recover_from_prehash(
        proof_hash.as_slice(),
        &proof_signature,
        proof_recovery,
    )
    .unwrap()
    .to_encoded_point(true)
    .as_bytes()
    .try_into()
    .unwrap()
}

fn initialization_manifest_for_intent(
    intent: &RegistrationIntentV1,
    challenge: [u8; 32],
) -> EnclaveInitializationManifestV1 {
    EnclaveInitializationManifestV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        attestation_mode: intent.attestation_mode,
        node_id: intent.node_id.clone(),
        initialization_challenge: challenge,
        node_host_noise_x25519: NODE_HOST_NOISE_X25519,
        recipient_x25519: intent.recipient_x25519,
        attestation_ed25519: intent.attestation_ed25519,
        noise_responder_x25519: intent.noise_responder_x25519,
    }
}

fn bind_reachable_node_host_authorization(intent: &mut RegistrationIntentV1, challenge: [u8; 32]) {
    let manifest = initialization_manifest_for_intent(intent, challenge);
    intent.node_host_authorization_hash = manifest.node_host_authorization_hash().unwrap();
    manifest.validate_intent_binding(intent).unwrap();
}

fn registration_intent(
    policy: &TeePolicyV1,
    node_signer: &OutbeEvmSigner,
    _consensus_key: [u8; 48],
    enclave_signer: &ed25519_dalek::SigningKey,
    binding_seed: u8,
    key_seed: u8,
) -> RegistrationIntentV1 {
    let mut intent = RegistrationIntentV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: policy.policy_hash().unwrap(),
        node_id: NodeIdV1 {
            reth_p2p_public: reth_p2p_public_for_evm_signer(node_signer),
        },
        enclave_id: B256::repeat_byte(0x01),
        binding_id: B256::repeat_byte(binding_seed),
        binding_version: 1,
        registration_version: 0,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until: NOW + 3_600,
        recipient_x25519: [key_seed; 32],
        attestation_ed25519: enclave_signer.verifying_key().to_bytes(),
        noise_responder_x25519: [key_seed.wrapping_add(1); 32],
        node_host_authorization_hash: B256::repeat_byte(1),
    };
    intent.enclave_id = intent.derived_enclave_id().unwrap();
    bind_reachable_node_host_authorization(&mut intent, [0xa6; 32]);
    intent
}

fn full_node_registration_intent(
    policy: &TeePolicyV1,
    node_signer: &k256::ecdsa::SigningKey,
    enclave_signer: &ed25519_dalek::SigningKey,
    binding_seed: u8,
    key_seed: u8,
) -> RegistrationIntentV1 {
    let reth_p2p_public = node_signer.verifying_key().to_encoded_point(true);
    let mut intent = RegistrationIntentV1 {
        chain_id: policy.chain_id,
        genesis_hash: policy.genesis_hash,
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: policy.policy_hash().unwrap(),
        node_id: NodeIdV1 {
            reth_p2p_public: reth_p2p_public.as_bytes().try_into().unwrap(),
        },
        enclave_id: B256::repeat_byte(0x01),
        binding_id: B256::repeat_byte(binding_seed),
        binding_version: 1,
        registration_version: 0,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until: NOW + 3_600,
        recipient_x25519: [key_seed; 32],
        attestation_ed25519: enclave_signer.verifying_key().to_bytes(),
        noise_responder_x25519: [key_seed.wrapping_add(1); 32],
        node_host_authorization_hash: B256::repeat_byte(1),
    };
    intent.enclave_id = intent.derived_enclave_id().unwrap();
    bind_reachable_node_host_authorization(&mut intent, [0xa6; 32]);
    intent
}

fn full_node_signatures(
    intent: &RegistrationIntentV1,
    node_signer: &k256::ecdsa::SigningKey,
    enclave_signer: &ed25519_dalek::SigningKey,
) -> ([u8; 65], [u8; 64]) {
    let hash = intent.intent_hash().unwrap();
    let (signature, recovery): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = node_signer
        .sign_prehash(hash.as_slice())
        .expect("test P2P key signs registration intent");
    let mut node_signature = [0_u8; 65];
    node_signature[..64].copy_from_slice(signature.to_bytes().as_slice());
    node_signature[64] = recovery.to_byte();
    (
        node_signature,
        enclave_signer.sign(hash.as_slice()).to_bytes(),
    )
}

fn validator_node_binding_authorization_for_p2p_node(
    intent: &RegistrationIntentV1,
    admission_signer: &OutbeEvmSigner,
    node_signer: &k256::ecdsa::SigningKey,
) -> (ValidatorNodeBindingV1, [u8; 65], [u8; 65]) {
    let binding = ValidatorNodeBindingV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        validator: admission_signer.address().into_array(),
        node_id_hash: intent.node_id.node_id_hash().unwrap(),
    };
    let binding_hash = binding.binding_hash().unwrap();
    let validator_signature = admission_signer.sign_hash(&binding_hash).unwrap();
    let (signature, recovery) = node_signer.sign_prehash(binding_hash.as_slice()).unwrap();
    let mut node_signature = [0_u8; 65];
    node_signature[..64].copy_from_slice(signature.to_bytes().as_slice());
    node_signature[64] = recovery.to_byte();
    (binding, validator_signature, node_signature)
}

fn validator_node_binding_authorization_for_evm_node(
    intent: &RegistrationIntentV1,
    admission_signer: &OutbeEvmSigner,
    node_signer: &OutbeEvmSigner,
) -> (ValidatorNodeBindingV1, [u8; 65], [u8; 65]) {
    let binding = ValidatorNodeBindingV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        validator: admission_signer.address().into_array(),
        node_id_hash: intent.node_id.node_id_hash().unwrap(),
    };
    let binding_hash = binding.binding_hash().unwrap();
    (
        binding,
        admission_signer.sign_hash(&binding_hash).unwrap(),
        node_signer.sign_hash(&binding_hash).unwrap(),
    )
}

fn full_node_public(intent: &RegistrationIntentV1) -> [u8; 33] {
    intent.node_id.reth_p2p_public
}

fn signatures(
    intent: &RegistrationIntentV1,
    node_signer: &OutbeEvmSigner,
    enclave_signer: &ed25519_dalek::SigningKey,
) -> ([u8; 65], [u8; 64]) {
    let hash = intent.intent_hash().unwrap();
    (
        node_signer.sign_hash(&hash).unwrap(),
        enclave_signer.sign(hash.as_slice()).to_bytes(),
    )
}

fn register_same_key_node_for_lifecycle_test(
    registry: &mut TeeRegistry<'_>,
    intent: &RegistrationIntentV1,
    node_signer: &OutbeEvmSigner,
    node_signature: &[u8; 65],
    enclave_signature: &[u8; 64],
    capability: PostVerifierDcapCapabilityV1,
) -> Result<V1RegistrationOutcome, PrecompileError> {
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(intent, node_signer, node_signer);
    registry.register_enclave_and_bind_after_verifier_for_test(
        intent,
        node_signature,
        enclave_signature,
        &binding,
        &validator_signature,
        &node_binding_signature,
        capability,
    )
}

fn verdict(status: DcapPlatformTcbStatusV1) -> DcapVerdictV1 {
    DcapVerdictV1 {
        mrenclave: MRENCLAVE,
        mrsigner: MRSIGNER,
        isv_prod_id: 7,
        isv_svn: 4,
        pck_ca: DcapPckCaV1::Processor,
        fmspc: [0x91; 6],
        pce_id: 2,
        platform_tcb_status: status,
        advisory_ids: Vec::new(),
        tcb_evaluation_data_number: 17,
        qe_tcb_evaluation_data_number: 17,
        collateral_valid_until: NOW + 7_200,
    }
}

fn renewal_intent(
    current: &RegistrationIntentV1,
    requested_valid_until: u64,
) -> RegistrationIntentV1 {
    let mut intent = current.clone();
    intent.operation = AttestationOperationV1::RenewEnclave;
    intent.registration_version += 1;
    intent.renewal_nonce += 1;
    intent.requested_valid_until = requested_valid_until;
    intent
}

fn same_enclave_rejoin_intent(
    current: &RegistrationIntentV1,
    binding_seed: u8,
    requested_valid_until: u64,
) -> RegistrationIntentV1 {
    let mut intent = current.clone();
    intent.operation = AttestationOperationV1::RegisterEnclave;
    intent.binding_id = B256::repeat_byte(binding_seed);
    intent.binding_version += 1;
    intent.registration_version += 1;
    intent.requested_valid_until = requested_valid_until;
    intent
}

fn new_enclave_rejoin_intent(
    current: &RegistrationIntentV1,
    enclave_signer: &ed25519_dalek::SigningKey,
    binding_seed: u8,
    key_seed: u8,
    requested_valid_until: u64,
) -> RegistrationIntentV1 {
    let mut intent = replacement_intent(
        current,
        enclave_signer,
        binding_seed,
        key_seed,
        requested_valid_until,
    );
    intent.operation = AttestationOperationV1::RegisterEnclave;
    intent
}

fn replacement_intent(
    current: &RegistrationIntentV1,
    enclave_signer: &ed25519_dalek::SigningKey,
    binding_seed: u8,
    key_seed: u8,
    requested_valid_until: u64,
) -> RegistrationIntentV1 {
    let mut intent = current.clone();
    intent.operation = AttestationOperationV1::ReplaceEnclaveBinding;
    intent.binding_id = B256::repeat_byte(binding_seed);
    intent.binding_version += 1;
    intent.registration_version += 1;
    intent.requested_valid_until = requested_valid_until;
    intent.recipient_x25519 = [key_seed; 32];
    intent.attestation_ed25519 = enclave_signer.verifying_key().to_bytes();
    intent.noise_responder_x25519 = [key_seed.wrapping_add(1); 32];
    intent.enclave_id = intent.derived_enclave_id().unwrap();
    let manifest = initialization_manifest_for_intent(&intent, [0xa7; 32]);
    assert_eq!(
        manifest.node_host_authorization_hash().unwrap(),
        current.node_host_authorization_hash
    );
    manifest.validate_intent_binding(&intent).unwrap();
    intent
}

fn measurement_transition_intent(
    current: &RegistrationIntentV1,
    next_policy: &TeePolicyV1,
    enclave_signer: &ed25519_dalek::SigningKey,
    binding_seed: u8,
    key_seed: u8,
    requested_valid_until: u64,
) -> RegistrationIntentV1 {
    let mut intent = replacement_intent(
        current,
        enclave_signer,
        binding_seed,
        key_seed,
        requested_valid_until,
    );
    intent.operation = AttestationOperationV1::TransitionEnclaveMeasurement;
    intent.transition_nonce += 1;
    intent.policy_hash = next_policy.policy_hash().unwrap();
    intent
}

fn transition_evidence(
    intent: &RegistrationIntentV1,
    enclave_signer: &ed25519_dalek::SigningKey,
) -> Vec<u8> {
    let candidate_manifest = initialization_manifest_for_intent(intent, [0xa7; 32]);
    let mut proof = TransitionKeyReadyProofV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        transition_intent_hash: intent.intent_hash().unwrap(),
        candidate_manifest_hash: candidate_manifest.authorization_hash().unwrap(),
        transition_nonce: intent.transition_nonce,
        resident_offer_public: OFFER_PUBLIC,
        candidate_attestation_signature: [0; 64],
    };
    proof.candidate_attestation_signature = enclave_signer
        .sign(proof.signing_hash().unwrap().as_slice())
        .to_bytes();
    AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
        intent: intent.clone(),
        quote: vec![0x51],
        components: (1_u8..=8)
            .map(|kind| DcapCollateralComponentV1 {
                kind: DcapCollateralKind::try_from(kind).unwrap(),
                bytes: vec![kind],
            })
            .collect(),
        transition_key_ready_proof: Some(proof),
    })
    .encode_canonical()
    .unwrap()
}

fn install_offer_key(registry: &mut TeeRegistry<'_>, policy: &TeePolicyV1) {
    registry
        .write_bootstrap(&TeeBootstrapData {
            tribute_offer_public_key: B256::from(OFFER_PUBLIC),
            policy_hash: policy.policy_hash().unwrap(),
            key_epoch: 0,
            tribute_offer_epoch: 0,
            dkg_transcript_hash: B256::repeat_byte(0xb2),
            committee_snapshot_block: 1,
            committee_snapshot_hash: B256::repeat_byte(0xb3),
            tribute_offer_group_public_key: vec![0xb4; 96].into(),
        })
        .unwrap();
}

fn revert_message(error: PrecompileError) -> String {
    match error {
        PrecompileError::Revert(message) => message,
        other => panic!("expected deterministic revert, got {other:?}"),
    }
}

#[test]
fn initial_role_neutral_registration_atomically_records_the_address_association_without_a_role() {
    let genesis_hash = B256::repeat_byte(0xA1);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let validator_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0xA2)).unwrap();
    let node_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0xA3)).into())
            .unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0xA4));
    let intent =
        full_node_registration_intent(&active_policy, &node_signer, &enclave_signer, 0xA5, 0xA6);
    let (node_registration_signature, enclave_signature) =
        full_node_signatures(&intent, &node_signer, &enclave_signer);
    let node_id_hash = intent.node_id.node_id_hash().unwrap();
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_p2p_node(&intent, &validator_signer, &node_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test(
                    &intent,
                    &node_registration_signature,
                    &enclave_signature,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );

        assert!(ValidatorSet::new(storage.clone())
            .get_validator(validator_signer.address())
            .unwrap()
            .is_none());
        assert!(!registry
            .is_validator_enclave_ready_v1(validator_signer.address())
            .unwrap());
        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test(
                    &intent,
                    &node_registration_signature,
                    &enclave_signature,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap(),
            V1RegistrationOutcome::Idempotent
        );
        register_validator(storage, &validator_signer, CONSENSUS_KEY);
        assert!(registry
            .is_validator_enclave_ready_v1(validator_signer.address())
            .unwrap());
        assert_eq!(
            registry
                .validator_v1_node_hash
                .read(&validator_signer.address())
                .unwrap(),
            node_id_hash
        );
    });
}

#[test]
fn atomic_initial_registration_is_active_idempotent_and_expires_without_relay_authority() {
    let genesis_hash = B256::repeat_byte(0x11);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x61)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x62));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x41,
        0x51,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&intent, &node_signer, &node_signer);
    let accepted_verdict = verdict(DcapPlatformTcbStatusV1::SWHardeningNeeded);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        assert!(!registry
            .is_validator_enclave_ready_v1(node_signer.address())
            .unwrap());

        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted_verdict.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        assert!(registry
            .is_validator_enclave_ready_v1(node_signer.address())
            .unwrap());
        let stored_binding = registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .unwrap();
        assert_eq!(stored_binding.enclave_id, intent.enclave_id);
        assert_eq!(stored_binding.binding_id, intent.binding_id);
        assert_eq!(stored_binding.intent_hash, intent.intent_hash().unwrap());
        assert_eq!(stored_binding.evidence_hash, B256::repeat_byte(0xEC));
        assert_eq!(stored_binding.valid_until, intent.requested_valid_until);
        assert_ne!(stored_binding.verdict_hash, B256::ZERO);

        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted_verdict.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Idempotent
        );

        let conflict = registry
            .register_enclave_and_bind_after_verifier_for_test(
                &intent,
                &node_signature,
                &enclave_signature,
                &binding,
                &validator_signature,
                &node_binding_signature,
                PostVerifierDcapCapabilityV1::with_evidence_hash(
                    accepted_verdict,
                    B256::repeat_byte(0xED),
                ),
            )
            .unwrap_err();
        assert!(revert_message(conflict).contains("not an exact evidence replay"));

        storage
            .set_block_timestamp(U256::from(intent.requested_valid_until))
            .unwrap();
        assert!(!registry
            .is_validator_enclave_ready_v1(node_signer.address())
            .unwrap());
    });

    assert_eq!(
        provider
            .get_events(outbe_primitives::addresses::TEE_REGISTRY_ADDRESS)
            .len(),
        2,
        "initial registration emits node plus association exactly once"
    );
}

#[test]
fn bootstrap_fixture_registers_exactly_thirty_two_validators_after_private_verifier() {
    let genesis_hash = B256::repeat_byte(0x19);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let fixtures = (1_u8..=32)
        .map(|index| {
            let node_signer = OutbeEvmSigner::from_secret_bytes(
                outbe_primitives::test_keys::secret((index) as u64),
            )
            .unwrap();
            let enclave_signer = ed25519_dalek::SigningKey::from_bytes(
                &outbe_primitives::test_keys::secret((index.wrapping_add(64)) as u64),
            );
            let consensus_key = [index; 48];
            let intent = registration_intent(
                &active_policy,
                &node_signer,
                consensus_key,
                &enclave_signer,
                index,
                index.wrapping_add(96),
            );
            let (node_signature, enclave_signature) =
                signatures(&intent, &node_signer, &enclave_signer);
            (
                node_signer,
                consensus_key,
                intent,
                node_signature,
                enclave_signature,
            )
        })
        .collect::<Vec<_>>();
    let mut provider = storage(genesis_hash);
    provider.set_block_number(1);

    StorageHandle::enter(&mut provider, |storage| {
        for (node_signer, consensus_key, ..) in &fixtures {
            register_validator(storage.clone(), node_signer, *consensus_key);
        }
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();

        let started = std::time::Instant::now();
        for (index, (node_signer, _, intent, node_signature, enclave_signature)) in
            fixtures.iter().enumerate()
        {
            assert_eq!(
                register_same_key_node_for_lifecycle_test(
                    &mut registry,
                    intent,
                    node_signer,
                    node_signature,
                    enclave_signature,
                    PostVerifierDcapCapabilityV1::with_evidence_hash(
                        verdict(DcapPlatformTcbStatusV1::UpToDate),
                        B256::repeat_byte(u8::try_from(index + 1).unwrap()),
                    ),
                )
                .unwrap(),
                V1RegistrationOutcome::Created
            );
            assert!(registry
                .is_validator_enclave_ready_v1(node_signer.address())
                .unwrap());
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "hardware-free post-verifier bootstrap fixture exceeded its test budget"
        );
    });
}

#[test]
fn invalid_or_conflicting_initial_association_rolls_back_the_node_registration() {
    let genesis_hash = B256::repeat_byte(0x21);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let admission_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x22)).unwrap();
    let first_node =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x23)).into())
            .unwrap();
    let second_node =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x24)).into())
            .unwrap();
    let first_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x25));
    let second_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x26));
    let first_intent =
        full_node_registration_intent(&active_policy, &first_node, &first_enclave, 0x27, 0x28);
    let second_intent =
        full_node_registration_intent(&active_policy, &second_node, &second_enclave, 0x29, 0x2A);
    let (first_node_signature, first_enclave_signature) =
        full_node_signatures(&first_intent, &first_node, &first_enclave);
    let (second_node_signature, second_enclave_signature) =
        full_node_signatures(&second_intent, &second_node, &second_enclave);
    let (first_binding, first_validator_signature, first_binding_node_signature) =
        validator_node_binding_authorization_for_p2p_node(
            &first_intent,
            &admission_signer,
            &first_node,
        );
    let (second_binding, second_validator_signature, second_binding_node_signature) =
        validator_node_binding_authorization_for_p2p_node(
            &second_intent,
            &admission_signer,
            &second_node,
        );
    let second_admission_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x2B)).unwrap();
    let (
        second_node_own_binding,
        second_node_own_validator_signature,
        second_node_own_binding_signature,
    ) = validator_node_binding_authorization_for_p2p_node(
        &second_intent,
        &second_admission_signer,
        &second_node,
    );
    let first_node_hash = first_intent.node_id.node_id_hash().unwrap();
    let second_node_hash = second_intent.node_id.node_id_hash().unwrap();
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&active_policy).unwrap();

        let mut invalid_validator_signature = first_validator_signature;
        invalid_validator_signature[0] ^= 1;
        let invalid = registry
            .register_enclave_and_bind_after_verifier_for_test(
                &first_intent,
                &first_node_signature,
                &first_enclave_signature,
                &first_binding,
                &invalid_validator_signature,
                &first_binding_node_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap_err();
        assert!(revert_message(invalid).contains("proof of possession"));
        assert!(registry
            .node_host_enclave_binding_v1(first_intent.node_id.reth_p2p_public)
            .unwrap()
            .is_none());
        assert_eq!(
            registry
                .validator_v1_node_hash
                .read(&admission_signer.address())
                .unwrap(),
            B256::ZERO
        );

        registry
            .register_enclave_and_bind_after_verifier_for_test(
                &second_intent,
                &second_node_signature,
                &second_enclave_signature,
                &second_node_own_binding,
                &second_node_own_validator_signature,
                &second_node_own_binding_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap();
        let mismatched_target = registry
            .register_enclave_and_bind_after_verifier_for_test(
                &first_intent,
                &first_node_signature,
                &first_enclave_signature,
                &second_binding,
                &second_validator_signature,
                &second_binding_node_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap_err();
        assert!(revert_message(mismatched_target).contains("same NodeHost"));
        assert!(registry
            .node_host_enclave_binding_v1(first_intent.node_id.reth_p2p_public)
            .unwrap()
            .is_none());
        assert_eq!(
            registry
                .validator_v1_node_hash
                .read(&admission_signer.address())
                .unwrap(),
            B256::ZERO
        );

        registry
            .register_enclave_and_bind_after_verifier_for_test(
                &first_intent,
                &first_node_signature,
                &first_enclave_signature,
                &first_binding,
                &first_validator_signature,
                &first_binding_node_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap();
        let conflict = registry
            .register_enclave_and_bind_after_verifier_for_test(
                &second_intent,
                &second_node_signature,
                &second_enclave_signature,
                &second_binding,
                &second_validator_signature,
                &second_binding_node_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap_err();
        assert!(revert_message(conflict).contains("not associated with the existing NodeHost"));
        assert_eq!(
            registry
                .validator_v1_node_hash
                .read(&admission_signer.address())
                .unwrap(),
            first_node_hash
        );
        assert_ne!(first_node_hash, second_node_hash);
        assert!(registry
            .node_host_enclave_binding_v1(second_intent.node_id.reth_p2p_public)
            .unwrap()
            .is_some());
        assert_eq!(
            registry
                .validator_v1_node_hash
                .read(&second_admission_signer.address())
                .unwrap(),
            second_node_hash
        );
    });
}

#[test]
fn proposer_validator_and_follower_apply_identical_full_state_verdict_and_gas() {
    let genesis_hash = B256::repeat_byte(0x18);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x68)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x69));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x48,
        0x58,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&intent, &node_signer, &node_signer);
    let accepted_verdict = verdict(DcapPlatformTcbStatusV1::SWHardeningNeeded);
    let evidence = vec![0xA5; 4_096];
    let call = IRegisterEnclaveV1Test::registerEnclaveCall {
        evidence: evidence.clone().into(),
        nodeSignature: node_signature.to_vec().into(),
        enclaveSignature: enclave_signature.to_vec().into(),
        validatorNodeBinding: binding.encode_canonical().unwrap().into(),
        validatorSignature: validator_signature.to_vec().into(),
        nodeBindingSignature: node_binding_signature.to_vec().into(),
    }
    .abi_encode();
    let schedule = TeeRegistryGasScheduleV1::normative();
    let storage_allowance = schedule.register_storage_gas_allowance();
    let maximum = schedule
        .maximum_transaction_gas(
            RegistryMutatorV1::RegisterEnclave,
            call.len(),
            evidence.len(),
            active_policy.measurement_rules.len(),
            AttestationMode::DcapRequired,
        )
        .unwrap();
    let intrinsic = schedule.maximum_calldata_intrinsic_gas(call.len()).unwrap();

    let execute_replica = || {
        let mut provider = storage(genesis_hash);
        StorageHandle::enter(&mut provider, |storage| {
            register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
            TeeRegistry::new(storage)
                .install_initial_policy_v1(&active_policy)
                .unwrap();
        });
        provider.enable_production_storage_gas_metering();
        provider.set_gas_limit(u64::MAX);
        let outcome = StorageHandle::enter(&mut provider, |storage| {
            dispatch_register_after_verifier_for_test(
                storage,
                node_signer.address(),
                &call,
                &intent,
                PostVerifierDcapCapabilityV1::new(accepted_verdict.clone()),
            )
            .unwrap()
        });
        (provider, outcome)
    };

    let (proposer, proposer_outcome) = execute_replica();
    let (validator, validator_outcome) = execute_replica();
    let (follower, follower_outcome) = execute_replica();
    assert_eq!(proposer_outcome, V1RegistrationOutcome::Created);
    assert_eq!(validator_outcome, proposer_outcome);
    assert_eq!(follower_outcome, proposer_outcome);
    let expected_operations = proposer.metered_storage_operations();
    let (reads, writes) = expected_operations;
    assert!(reads > 0);
    assert_eq!(writes, 25, "fresh V1 binding storage schema drifted");
    let storage_gas = reads * 100 + writes * 5_000;
    assert!(storage_gas <= storage_allowance);
    assert_eq!(
        intrinsic + 200 + proposer.gas_used(),
        maximum - storage_allowance + storage_gas
    );
    assert!(intrinsic + 200 + proposer.gas_used() <= maximum);

    for replica in [&validator, &follower] {
        assert_eq!(replica.storage, proposer.storage);
        assert_eq!(replica.get_ordered_events(), proposer.get_ordered_events());
        assert_eq!(replica.metered_storage_operations(), expected_operations);
        assert_eq!(replica.gas_used(), proposer.gas_used());
    }
}

#[test]
fn full_node_proposer_validator_and_follower_apply_identical_abi_state_and_gas() {
    let genesis_hash = B256::repeat_byte(0x1A);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x7A)).into())
            .unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x7B));
    let intent =
        full_node_registration_intent(&active_policy, &node_signer, &enclave_signer, 0x4A, 0x5A);
    let (node_signature, enclave_signature) =
        full_node_signatures(&intent, &node_signer, &enclave_signer);
    let admission_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x7C)).unwrap();
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_p2p_node(&intent, &admission_signer, &node_signer);
    let accepted_verdict = verdict(DcapPlatformTcbStatusV1::SWHardeningNeeded);
    let evidence = vec![0xA6; 4_096];
    let call = IRegisterEnclaveV1Test::registerEnclaveCall {
        evidence: evidence.clone().into(),
        nodeSignature: node_signature.to_vec().into(),
        enclaveSignature: enclave_signature.to_vec().into(),
        validatorNodeBinding: binding.encode_canonical().unwrap().into(),
        validatorSignature: validator_signature.to_vec().into(),
        nodeBindingSignature: node_binding_signature.to_vec().into(),
    }
    .abi_encode();
    let schedule = TeeRegistryGasScheduleV1::normative();
    let storage_allowance = schedule.register_storage_gas_allowance();
    let maximum = schedule
        .maximum_transaction_gas(
            RegistryMutatorV1::RegisterEnclave,
            call.len(),
            evidence.len(),
            active_policy.measurement_rules.len(),
            AttestationMode::DcapRequired,
        )
        .unwrap();
    let intrinsic = schedule.maximum_calldata_intrinsic_gas(call.len()).unwrap();

    let execute_replica = || {
        let mut provider = storage(genesis_hash);
        StorageHandle::enter(&mut provider, |storage| {
            TeeRegistry::new(storage)
                .install_initial_policy_v1(&active_policy)
                .unwrap();
        });
        provider.enable_production_storage_gas_metering();
        provider.set_gas_limit(u64::MAX);
        let outcome = StorageHandle::enter(&mut provider, |storage| {
            dispatch_register_after_verifier_for_test(
                storage,
                admission_signer.address(),
                &call,
                &intent,
                PostVerifierDcapCapabilityV1::new(accepted_verdict.clone()),
            )
            .unwrap()
        });
        (provider, outcome)
    };

    let (proposer, proposer_outcome) = execute_replica();
    let (validator, validator_outcome) = execute_replica();
    let (follower, follower_outcome) = execute_replica();
    assert_eq!(proposer_outcome, V1RegistrationOutcome::Created);
    assert_eq!(validator_outcome, proposer_outcome);
    assert_eq!(follower_outcome, proposer_outcome);
    let expected_operations = proposer.metered_storage_operations();
    let (reads, writes) = expected_operations;
    assert!(reads > 0);
    assert_eq!(
        writes, 25,
        "fresh FullNode V1 binding storage schema drifted"
    );
    let storage_gas = reads * 100 + writes * 5_000;
    assert!(storage_gas <= storage_allowance);
    assert_eq!(
        intrinsic + 200 + proposer.gas_used(),
        maximum - storage_allowance + storage_gas
    );
    assert!(intrinsic + 200 + proposer.gas_used() <= maximum);

    for replica in [&validator, &follower] {
        assert_eq!(replica.storage, proposer.storage);
        assert_eq!(replica.get_ordered_events(), proposer.get_ordered_events());
        assert_eq!(replica.metered_storage_operations(), expected_operations);
        assert_eq!(replica.gas_used(), proposer.gas_used());
    }
}

#[test]
fn public_v1_registration_emits_onboarding_only_for_created_binding() {
    let genesis_hash = B256::repeat_byte(0x2A);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x31)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x32));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x33,
        0x34,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&intent, &node_signer, &node_signer);
    let call = IRegisterEnclaveV1Test::registerEnclaveCall {
        evidence: vec![0xA8; 4_096].into(),
        nodeSignature: node_signature.to_vec().into(),
        enclaveSignature: enclave_signature.to_vec().into(),
        validatorNodeBinding: binding.encode_canonical().unwrap().into(),
        validatorSignature: validator_signature.to_vec().into(),
        nodeBindingSignature: node_binding_signature.to_vec().into(),
    }
    .abi_encode();
    let offer_public = B256::repeat_byte(0x41);
    let sealed = sealed_offer_artifact(&intent, offer_public, 0x42);
    let node_id_hash = intent.node_id.node_id_hash().unwrap();
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&active_policy).unwrap();
        registry
            .tribute_offer_public_key
            .write(offer_public)
            .unwrap();
    });

    let created = StorageHandle::enter(&mut provider, |storage| {
        dispatch_register_with_onboarding_after_verifier_for_test(
            storage,
            node_signer.address(),
            &call,
            &intent,
            PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            |recipient| {
                assert_eq!(recipient, intent.recipient_x25519);
                Ok(Some(sealed.clone()))
            },
        )
        .unwrap()
    });
    assert_eq!(created, V1RegistrationOutcome::Created);

    let onboarding = provider
        .get_ordered_events()
        .iter()
        .filter(|log| log.topics().first() == Some(&OfferKeySealedForRegistryV1::SIGNATURE_HASH))
        .collect::<Vec<_>>();
    assert_eq!(onboarding.len(), 1);
    let decoded = OfferKeySealedForRegistryV1::decode_log(onboarding[0]).unwrap();
    assert_eq!(decoded.nodeIdHash, node_id_hash);
    assert_eq!(decoded.sealedOfferKey.as_ref(), sealed.as_slice());

    let idempotent = StorageHandle::enter(&mut provider, |storage| {
        dispatch_register_with_onboarding_after_verifier_for_test(
            storage,
            node_signer.address(),
            &call,
            &intent,
            PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            |_| panic!("idempotent registration must not ask the enclave to reseal the offer key"),
        )
        .unwrap()
    });
    assert_eq!(idempotent, V1RegistrationOutcome::Idempotent);
    assert_eq!(
        provider
            .get_ordered_events()
            .iter()
            .filter(|log| {
                log.topics().first() == Some(&OfferKeySealedForRegistryV1::SIGNATURE_HASH)
            })
            .count(),
        1,
        "idempotent replay must not redeliver the permanent offer key"
    );
}

#[test]
fn verified_onboarding_artifact_must_match_the_committed_binding_exactly() {
    let genesis_hash = B256::repeat_byte(0x91);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x92)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x93));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x94,
        0x95,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let node_id_hash = intent.node_id.node_id_hash().unwrap();
    let offer_public = B256::repeat_byte(0x96);
    let artifact = DcapOnboardingArtifactV1 {
        context: DcapOnboardingContextV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            intent_hash: intent.intent_hash().unwrap(),
            node_id_hash,
            enclave_id: intent.derived_enclave_id().unwrap(),
            binding_id: intent.binding_id,
            policy_hash: intent.policy_hash,
            recipient_x25519: intent.recipient_x25519,
            tribute_offer_public: offer_public.0,
            key_epoch: 0,
            tribute_offer_epoch: 0,
        },
        nonce: [0x97; 12],
        ciphertext: vec![0x98; 112],
    };
    let mut provider = storage(genesis_hash);
    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&active_policy).unwrap();
        registry
            .tribute_offer_public_key
            .write(offer_public)
            .unwrap();
        let registration = registry
            .register_enclave_after_verifier_for_test(
                &intent,
                &node_signature,
                &enclave_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap();
        registry
            .emit_verified_onboarding_artifact_v1(
                &V1OnboardingOutcome {
                    registration,
                    artifact: Some(artifact.clone()),
                },
                node_id_hash,
            )
            .unwrap();
    });
    let events = provider
        .get_ordered_events()
        .iter()
        .filter(|event| {
            event.topics().first() == Some(&OfferKeySealedForRegistryV1::SIGNATURE_HASH)
        })
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(
        OfferKeySealedForRegistryV1::decode_log(events[0])
            .unwrap()
            .sealedOfferKey
            .as_ref(),
        artifact.encode_canonical().unwrap().as_slice()
    );

    let error = StorageHandle::enter(&mut provider, |storage| {
        let mut wrong = artifact;
        wrong.context.intent_hash = B256::repeat_byte(0xff);
        TeeRegistry::new(storage)
            .emit_verified_onboarding_artifact_v1(
                &V1OnboardingOutcome {
                    registration: V1RegistrationOutcome::Created,
                    artifact: Some(wrong),
                },
                node_id_hash,
            )
            .unwrap_err()
    });
    assert!(matches!(error, PrecompileError::Fatal(_)));
}

#[test]
fn full_node_binding_is_idempotent_expires_and_rejects_validator_credentials() {
    let genesis_hash = B256::repeat_byte(0x19);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x6A)).into())
            .unwrap();
    let other_node =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x6C)).into())
            .unwrap();
    let validator_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x6D)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x6B));
    let other_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x6E));
    let intent =
        full_node_registration_intent(&active_policy, &node_signer, &enclave_signer, 0x49, 0x59);
    let reth_p2p_public = full_node_public(&intent);
    let (node_signature, enclave_signature) =
        full_node_signatures(&intent, &node_signer, &enclave_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        assert!(!registry
            .is_node_host_enclave_ready_v1(reth_p2p_public)
            .unwrap());
        assert_eq!(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(
                        DcapPlatformTcbStatusV1::SWHardeningNeeded,
                    )),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        assert!(registry
            .is_node_host_enclave_ready_v1(reth_p2p_public)
            .unwrap());
        let binding = registry
            .node_host_enclave_binding_v1(reth_p2p_public)
            .unwrap()
            .unwrap();
        assert_eq!(binding.enclave_id, intent.enclave_id);
        assert_eq!(binding.intent_hash, intent.intent_hash().unwrap());

        assert_eq!(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(
                        DcapPlatformTcbStatusV1::SWHardeningNeeded,
                    )),
                )
                .unwrap(),
            V1RegistrationOutcome::Idempotent
        );

        let (wrong_p2p_signature, _) = full_node_signatures(&intent, &other_node, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &wrong_p2p_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("node proof"));

        let validator_signature = validator_signer
            .sign_hash(&intent.intent_hash().unwrap())
            .unwrap();
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &validator_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("node proof"));

        let wrong_enclave_signature = other_enclave
            .sign(intent.intent_hash().unwrap().as_slice())
            .to_bytes();
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &wrong_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("enclave proof"));

        let mut stale = intent.clone();
        stale.renewal_nonce = 1;
        let (stale_node_signature, stale_enclave_signature) =
            full_node_signatures(&stale, &node_signer, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &stale,
                    &stale_node_signature,
                    &stale_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("must renew"));

        let mut wrong_measurement = verdict(DcapPlatformTcbStatusV1::UpToDate);
        wrong_measurement.mrenclave = B256::repeat_byte(0x99);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(wrong_measurement),
                )
                .unwrap_err()
        )
        .contains("measurement rule"));

        let mut excessive_lease = intent.clone();
        excessive_lease.requested_valid_until = NOW + active_policy.maximum_lease + 1;
        let (lease_node_signature, lease_enclave_signature) =
            full_node_signatures(&excessive_lease, &node_signer, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &excessive_lease,
                    &lease_node_signature,
                    &lease_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("must renew"));

        let same_enclave_other_node =
            full_node_registration_intent(&active_policy, &other_node, &enclave_signer, 0x4B, 0x59);
        assert_eq!(same_enclave_other_node.enclave_id, intent.enclave_id);
        let (other_node_signature, same_enclave_signature) =
            full_node_signatures(&same_enclave_other_node, &other_node, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &same_enclave_other_node,
                    &other_node_signature,
                    &same_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("already bound to another node"));

        let conflict = registry
            .register_enclave_after_verifier_for_test(
                &intent,
                &node_signature,
                &enclave_signature,
                PostVerifierDcapCapabilityV1::with_evidence_hash(
                    verdict(DcapPlatformTcbStatusV1::UpToDate),
                    B256::repeat_byte(0xED),
                ),
            )
            .unwrap_err();
        assert!(revert_message(conflict).contains("not an exact evidence replay"));

        storage
            .set_block_timestamp(U256::from(intent.requested_valid_until))
            .unwrap();
        assert!(!registry
            .is_node_host_enclave_ready_v1(reth_p2p_public)
            .unwrap());
    });

    assert_eq!(
        provider
            .get_events(outbe_primitives::addresses::TEE_REGISTRY_ADDRESS)
            .len(),
        1
    );
}

#[test]
fn full_node_renewal_and_replacement_follow_the_shared_lease_lifecycle() {
    let genesis_hash = B256::repeat_byte(0x25);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.maximum_lease = 3_600;
    let node_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x7B)).into())
            .unwrap();
    let old_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x7C));
    let new_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x7D));
    let initial =
        full_node_registration_intent(&active_policy, &node_signer, &old_enclave, 0x6D, 0x6E);
    let renewal = renewal_intent(
        &initial,
        initial.requested_valid_until + active_policy.maximum_lease,
    );
    let replacement = replacement_intent(&renewal, &new_enclave, 0x6F, 0x70, NOW + 6_000);
    let (initial_node, initial_enclave) =
        full_node_signatures(&initial, &node_signer, &old_enclave);
    let (renewal_node, renewal_enclave) =
        full_node_signatures(&renewal, &node_signer, &old_enclave);
    let (replacement_node, replacement_enclave) =
        full_node_signatures(&replacement, &node_signer, &new_enclave);
    let p2p_public = full_node_public(&initial);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 12_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        registry
            .register_enclave_after_verifier_for_test(
                &initial,
                &initial_node,
                &initial_enclave,
                PostVerifierDcapCapabilityV1::new(accepted.clone()),
            )
            .unwrap();
        storage
            .set_block_timestamp(U256::from(NOW + 2_400))
            .unwrap();
        registry
            .renew_enclave_after_verifier_for_test(
                &renewal,
                &renewal_node,
                &renewal_enclave,
                PostVerifierDcapCapabilityV1::new(accepted.clone()),
            )
            .unwrap();
        registry
            .replace_enclave_binding_after_verifier_for_test(
                &replacement,
                &replacement_node,
                &replacement_enclave,
                PostVerifierDcapCapabilityV1::new(accepted),
            )
            .unwrap();

        let binding = registry
            .node_host_enclave_binding_v1(p2p_public)
            .unwrap()
            .unwrap();
        assert_eq!(binding.enclave_id, replacement.enclave_id);
        assert_eq!(binding.binding_version, 2);
        assert_eq!(binding.registration_version, 2);
        assert_eq!(binding.renewal_nonce, 1);
        assert!(registry.is_node_host_enclave_ready_v1(p2p_public).unwrap());
    });
}

#[test]
fn role_neutral_registration_rejects_node_enclave_nonce_and_measurement_errors() {
    let genesis_hash = B256::repeat_byte(0x12);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x63)).unwrap();
    let other_node =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x64)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x65));
    let other_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x66));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x42,
        0x52,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&active_policy).unwrap();

        let wrong_node_signature = other_node
            .sign_hash(&intent.intent_hash().unwrap())
            .unwrap();
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &wrong_node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("node proof"));

        let full_node_signer = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x6E)).into(),
        )
        .unwrap();
        let (full_node_signature, _) =
            full_node_signatures(&intent, &full_node_signer, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &full_node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
                )
                .unwrap_err()
        )
        .contains("node proof"));

        let wrong_enclave_signature = other_enclave
            .sign(intent.intent_hash().unwrap().as_slice())
            .to_bytes();
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &wrong_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("enclave proof"));

        let mut stale = intent.clone();
        stale.renewal_nonce = 1;
        let (stale_node_signature, stale_enclave_signature) =
            signatures(&stale, &node_signer, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &stale,
                    &stale_node_signature,
                    &stale_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("versions and nonces"));

        let mut wrong_measurement = verdict(DcapPlatformTcbStatusV1::UpToDate);
        wrong_measurement.mrenclave = B256::repeat_byte(0x99);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(wrong_measurement),
                )
                .unwrap_err()
        )
        .contains("measurement rule"));

        assert!(registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .is_none());
    });
}

#[test]
fn one_to_one_binding_and_strict_platform_policy_reject_conflicts() {
    let genesis_hash = B256::repeat_byte(0x13);
    let broad_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let first_node =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x67)).unwrap();
    let second_node =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x68)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x69));
    let replacement_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x6a));
    let first = registration_intent(
        &broad_policy,
        &first_node,
        CONSENSUS_KEY,
        &enclave_signer,
        0x44,
        0x54,
    );
    let (first_node_signature, first_enclave_signature) =
        signatures(&first, &first_node, &enclave_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &first_node, CONSENSUS_KEY);
        register_validator(storage.clone(), &second_node, [0x34; 48]);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&broad_policy).unwrap();
        registry
            .register_enclave_after_verifier_for_test(
                &first,
                &first_node_signature,
                &first_enclave_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap();

        let second_enclave = registration_intent(
            &broad_policy,
            &first_node,
            CONSENSUS_KEY,
            &replacement_enclave,
            0x45,
            0x55,
        );
        let (second_enclave_node_sig, second_enclave_sig) =
            signatures(&second_enclave, &first_node, &replacement_enclave);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &second_enclave,
                    &second_enclave_node_sig,
                    &second_enclave_sig,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("must renew"));

        let mut same_enclave_other_node = registration_intent(
            &broad_policy,
            &second_node,
            [0x34; 48],
            &enclave_signer,
            0x46,
            0x54,
        );
        same_enclave_other_node.recipient_x25519 = first.recipient_x25519;
        same_enclave_other_node.noise_responder_x25519 = first.noise_responder_x25519;
        same_enclave_other_node.node_host_authorization_hash = first.node_host_authorization_hash;
        same_enclave_other_node.enclave_id = same_enclave_other_node.derived_enclave_id().unwrap();
        assert_eq!(same_enclave_other_node.enclave_id, first.enclave_id);
        let (second_node_signature, same_enclave_signature) =
            signatures(&same_enclave_other_node, &second_node, &enclave_signer);
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &same_enclave_other_node,
                    &second_node_signature,
                    &same_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("already bound to another node"));
    });

    let strict_policy = policy(genesis_hash, PlatformTcbStatusSetV1::UpToDateOnly);
    let strict_node =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x6b)).unwrap();
    let strict_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x6c));
    let strict_intent = registration_intent(
        &strict_policy,
        &strict_node,
        CONSENSUS_KEY,
        &strict_enclave,
        0x47,
        0x57,
    );
    let (strict_node_signature, strict_enclave_signature) =
        signatures(&strict_intent, &strict_node, &strict_enclave);
    let mut strict_provider = storage(genesis_hash);
    StorageHandle::enter(&mut strict_provider, |storage| {
        register_validator(storage.clone(), &strict_node, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&strict_policy).unwrap();
        for status in [
            DcapPlatformTcbStatusV1::SWHardeningNeeded,
            DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded,
        ] {
            assert!(revert_message(
                registry
                    .register_enclave_after_verifier_for_test(
                        &strict_intent,
                        &strict_node_signature,
                        &strict_enclave_signature,
                        PostVerifierDcapCapabilityV1::new(verdict(status)),
                    )
                    .unwrap_err()
            )
            .contains("stricter than active policy"));
        }
    });
}

#[test]
fn initial_policy_is_state_authority_and_is_write_once() {
    let genesis_hash = B256::repeat_byte(0x14);
    let first = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut provider = storage(genesis_hash);
    let bootstrap_policy_hash = B256::repeat_byte(0xD1);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage);
        registry.policy_hash.write(bootstrap_policy_hash).unwrap();
        registry.install_initial_policy_v1(&first).unwrap();
        registry.install_initial_policy_v1(&first).unwrap();
        assert_eq!(registry.active_policy_v1().unwrap(), first);
        assert_eq!(registry.policy_hash.read().unwrap(), bootstrap_policy_hash);
        assert_eq!(
            registry.active_v1_policy_hash.read().unwrap(),
            first.policy_hash().unwrap()
        );

        let mut conflicting = first.clone();
        conflicting.minimum_tcb_evaluation_data_number = 2;
        assert!(revert_message(
            registry
                .install_initial_policy_v1(&conflicting)
                .unwrap_err()
        )
        .contains("already installed"));
    });

    let mut wrong_chain_provider = storage(genesis_hash);
    let mut wrong_chain = first;
    wrong_chain.chain_id = U256::from(2).to_be_bytes();
    StorageHandle::enter(&mut wrong_chain_provider, |storage| {
        assert!(revert_message(
            TeeRegistry::new(storage)
                .install_initial_policy_v1(&wrong_chain)
                .unwrap_err()
        )
        .contains("chain identity mismatch"));
    });
}

#[test]
fn initial_policy_rejects_direct_dev_on_mainnet_before_registry_writes() {
    let genesis_hash = B256::repeat_byte(0x19);
    let mut direct = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    direct.chain_id = U256::from(MAINNET_CHAIN_ID).to_be_bytes();
    direct.attestation_mode = AttestationMode::GramineDirectDev;
    let mut provider = storage_for_chain(MAINNET_CHAIN_ID, genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage);
        assert!(
            revert_message(registry.install_initial_policy_v1(&direct).unwrap_err())
                .contains("attestation mode")
        );
        assert_eq!(registry.active_v1_policy_len.read().unwrap(), 0);
        assert!(registry.active_v1_policy_hash.read().unwrap().is_zero());
    });
}

#[test]
fn initial_policy_accepts_both_non_mainnet_modes_and_mainnet_dcap() {
    for (chain_id, mode) in [
        (DEVNET_CHAIN_ID, AttestationMode::DcapRequired),
        (DEVNET_CHAIN_ID, AttestationMode::GramineDirectDev),
        (TESTNET_CHAIN_ID, AttestationMode::DcapRequired),
        (TESTNET_CHAIN_ID, AttestationMode::GramineDirectDev),
        (MAINNET_CHAIN_ID, AttestationMode::DcapRequired),
    ] {
        let genesis_hash = B256::from(U256::from(chain_id).to_be_bytes());
        let mut initial = policy(
            genesis_hash,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        );
        initial.chain_id = U256::from(chain_id).to_be_bytes();
        initial.attestation_mode = mode;
        let mut provider = storage_for_chain(chain_id, genesis_hash);
        StorageHandle::enter(&mut provider, |storage| {
            let mut registry = TeeRegistry::new(storage);
            registry.install_initial_policy_v1(&initial).unwrap();
            assert_eq!(registry.active_policy_v1().unwrap(), initial);
        });
    }
}

#[test]
fn initial_policy_rejects_both_modes_on_an_unknown_chain_before_registry_writes() {
    const UNKNOWN_CHAIN_ID: u64 = TESTNET_CHAIN_ID + 1;

    for mode in [
        AttestationMode::DcapRequired,
        AttestationMode::GramineDirectDev,
    ] {
        let genesis_hash = B256::repeat_byte(mode as u8);
        let mut initial = policy(
            genesis_hash,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        );
        initial.chain_id = U256::from(UNKNOWN_CHAIN_ID).to_be_bytes();
        initial.attestation_mode = mode;
        let mut provider = storage_for_chain(UNKNOWN_CHAIN_ID, genesis_hash);

        StorageHandle::enter(&mut provider, |storage| {
            let mut registry = TeeRegistry::new(storage);
            assert!(
                revert_message(registry.install_initial_policy_v1(&initial).unwrap_err())
                    .contains("attestation mode")
            );
            assert_eq!(registry.active_v1_policy_len.read().unwrap(), 0);
            assert!(registry.active_v1_policy_hash.read().unwrap().is_zero());
        });
    }
}

#[test]
fn stages_exactly_one_predecessor_bound_successor_policy() {
    let genesis_hash = B256::repeat_byte(0x15);
    let current = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut successor = current.clone();
    successor.policy_version = 2;
    successor.activation_height = 50;
    successor.predecessor_policy_hash = current.policy_hash().unwrap();
    successor.accepted_platform_tcb_statuses = PlatformTcbStatusSetV1::UpToDateOnly;
    for rule in &mut successor.measurement_rules {
        rule.mrenclave = B256::repeat_byte(0x91);
        rule.admit_from_height = 50;
        rule.admit_until_height_exclusive = 500;
    }

    let mut provider = storage(genesis_hash);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&current).unwrap();

        let mut wrong_genesis = successor.clone();
        wrong_genesis.genesis_hash = B256::repeat_byte(0xee);
        assert!(revert_message(
            registry
                .stage_successor_policy_v1(U256::from(5), &wrong_genesis)
                .unwrap_err()
        )
        .contains("chain identity"));

        let mut wrong_version = successor.clone();
        wrong_version.policy_version = 3;
        assert!(revert_message(
            registry
                .stage_successor_policy_v1(U256::from(6), &wrong_version)
                .unwrap_err()
        )
        .contains("current plus one"));

        let mut wrong_mode = successor.clone();
        wrong_mode.attestation_mode = AttestationMode::GramineDirectDev;
        assert!(revert_message(
            registry
                .stage_successor_policy_v1(U256::from(6), &wrong_mode)
                .unwrap_err()
        )
        .contains("attestation mode"));
        assert_eq!(registry.staged_successor_policy_v1().unwrap(), None);

        registry
            .stage_successor_policy_v1(U256::from(7), &successor)
            .unwrap();
        registry
            .stage_successor_policy_v1(U256::from(7), &successor)
            .unwrap();
        assert_eq!(
            registry.staged_successor_policy_v1().unwrap(),
            Some((U256::from(7), successor.clone()))
        );

        let mut conflicting = successor.clone();
        conflicting.minimum_tcb_evaluation_data_number = 2;
        assert!(revert_message(
            registry
                .stage_successor_policy_v1(U256::from(8), &conflicting)
                .unwrap_err()
        )
        .contains("already staged"));

        let mut wrong_predecessor = successor.clone();
        wrong_predecessor.predecessor_policy_hash = B256::repeat_byte(0xee);
        assert!(revert_message(
            TeeRegistry::new(registry.storage.clone())
                .stage_successor_policy_v1(U256::from(9), &wrong_predecessor)
                .unwrap_err()
        )
        .contains("predecessor"));
    });
}

#[test]
fn successor_policy_rejects_both_attestation_mode_switch_directions() {
    for active_mode in [
        AttestationMode::DcapRequired,
        AttestationMode::GramineDirectDev,
    ] {
        let genesis_hash = B256::repeat_byte(active_mode as u8);
        let mut current = policy(
            genesis_hash,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        );
        current.attestation_mode = active_mode;
        let mut successor = current.clone();
        successor.policy_version = 2;
        successor.activation_height = 50;
        successor.predecessor_policy_hash = current.policy_hash().unwrap();
        successor.attestation_mode = match active_mode {
            AttestationMode::DcapRequired => AttestationMode::GramineDirectDev,
            AttestationMode::GramineDirectDev => AttestationMode::DcapRequired,
        };
        let mut provider = storage(genesis_hash);
        StorageHandle::enter(&mut provider, |storage| {
            let mut registry = TeeRegistry::new(storage);
            registry.install_initial_policy_v1(&current).unwrap();
            assert!(revert_message(
                registry
                    .stage_successor_policy_v1(U256::from(20), &successor)
                    .unwrap_err()
            )
            .contains("attestation mode"));
            assert_eq!(registry.staged_successor_policy_v1().unwrap(), None);
            assert_eq!(registry.active_policy_v1().unwrap(), current);
        });
    }
}

#[test]
fn promotes_staged_successor_exactly_at_activation_height_and_replays_idempotently() {
    for mode in [
        AttestationMode::DcapRequired,
        AttestationMode::GramineDirectDev,
    ] {
        let genesis_hash = B256::repeat_byte(mode as u8);
        let mut current = policy(
            genesis_hash,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        );
        current.attestation_mode = mode;
        let mut successor = current.clone();
        successor.policy_version = 2;
        successor.activation_height = 50;
        successor.predecessor_policy_hash = current.policy_hash().unwrap();
        successor.accepted_platform_tcb_statuses = PlatformTcbStatusSetV1::UpToDateOnly;
        for rule in &mut successor.measurement_rules {
            rule.admit_from_height = 50;
            rule.admit_until_height_exclusive = 500;
        }
        let proposal_id = U256::from(8);
        let mut provider = storage(genesis_hash);

        StorageHandle::enter(&mut provider, |storage| {
            let mut registry = TeeRegistry::new(storage);
            registry.install_initial_policy_v1(&current).unwrap();
            registry
                .stage_successor_policy_v1(proposal_id, &successor)
                .unwrap();
            registry
                .stage_successor_policy_v1(proposal_id, &successor)
                .unwrap();
            assert_eq!(registry.active_policy_v1().unwrap(), current);
        });

        provider.set_block_number(50);
        StorageHandle::enter(&mut provider, |storage| {
            let mut registry = TeeRegistry::new(storage);
            registry
                .promote_staged_successor_policy_v1(proposal_id, 50)
                .unwrap();
            registry
                .promote_staged_successor_policy_v1(proposal_id, 50)
                .unwrap();
            assert_eq!(registry.active_policy_v1().unwrap(), successor);
            assert_eq!(registry.staged_successor_policy_v1().unwrap(), None);
        });
    }
}

#[test]
fn promotion_rejects_a_preexisting_cross_mode_successor() {
    for active_mode in [
        AttestationMode::DcapRequired,
        AttestationMode::GramineDirectDev,
    ] {
        let genesis_hash = B256::repeat_byte(active_mode as u8);
        let mut current = policy(
            genesis_hash,
            PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
        );
        current.attestation_mode = active_mode;
        let mut successor = current.clone();
        successor.policy_version = 2;
        successor.activation_height = 50;
        successor.predecessor_policy_hash = current.policy_hash().unwrap();
        successor.attestation_mode = match active_mode {
            AttestationMode::DcapRequired => AttestationMode::GramineDirectDev,
            AttestationMode::GramineDirectDev => AttestationMode::DcapRequired,
        };
        let canonical = successor.encode_canonical().unwrap();
        let policy_hash = successor.policy_hash().unwrap();
        let proposal_id = U256::from(18);
        let mut provider = storage(genesis_hash);

        StorageHandle::enter(&mut provider, |storage| {
            let mut registry = TeeRegistry::new(storage);
            registry.install_initial_policy_v1(&current).unwrap();
            for (index, chunk) in canonical.chunks(32).enumerate() {
                let mut word = [0u8; 32];
                word[..chunk.len()].copy_from_slice(chunk);
                registry
                    .staged_v1_policy_chunk
                    .write(&(index as u32), B256::from(word))
                    .unwrap();
            }
            registry
                .staged_v1_policy_len
                .write(canonical.len() as u32)
                .unwrap();
            registry.staged_v1_policy_hash.write(policy_hash).unwrap();
            registry
                .staged_v1_policy_proposal_id
                .write(proposal_id)
                .unwrap();
            registry
                .staged_v1_policy_activation_height
                .write(successor.activation_height)
                .unwrap();

            assert!(format!(
                "{}",
                registry
                    .promote_staged_successor_policy_v1(proposal_id, 50)
                    .unwrap_err()
            )
            .contains("attestation mode"));
            assert_eq!(registry.active_policy_v1().unwrap(), current);
            assert_eq!(
                registry.staged_successor_policy_v1().unwrap(),
                Some((proposal_id, successor))
            );
        });
    }
}

#[test]
fn ambiguous_measurement_rules_reject_at_the_registry_boundary() {
    let genesis_hash = B256::repeat_byte(0x1a);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut overlapping = active_policy.measurement_rules[0].clone();
    overlapping.minimum_isv_svn = 2;
    active_policy.measurement_rules.insert(0, overlapping);
    active_policy.encode_canonical().unwrap();

    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x3a)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x3b));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x58,
        0x68,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&active_policy).unwrap();
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &intent,
                    &node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("exactly one"));
    });
}

#[test]
fn existing_validator_transitions_to_staged_measurement_before_activation() {
    let genesis_hash = B256::repeat_byte(0x16);
    let current = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut successor = current.clone();
    successor.policy_version = 2;
    successor.activation_height = 50;
    successor.predecessor_policy_hash = current.policy_hash().unwrap();
    for rule in &mut successor.measurement_rules {
        rule.mrenclave = B256::repeat_byte(0x92);
        rule.admit_from_height = 50;
        rule.admit_until_height_exclusive = 500;
    }

    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x31)).unwrap();
    let old_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x32));
    let new_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x33));
    let initial = registration_intent(
        &current,
        &node_signer,
        CONSENSUS_KEY,
        &old_enclave,
        0x51,
        0x61,
    );
    let transition =
        measurement_transition_intent(&initial, &successor, &new_enclave, 0x52, 0x62, NOW + 3_600);
    let (initial_node, initial_enclave) = signatures(&initial, &node_signer, &old_enclave);
    let (transition_node, transition_enclave) = signatures(&transition, &node_signer, &new_enclave);
    let transition_evidence = transition_evidence(&transition, &new_enclave);
    let call = IRegisterEnclaveV1Test::transitionEnclaveMeasurementCall {
        evidence: transition_evidence.clone().into(),
        nodeSignature: transition_node.to_vec().into(),
        enclaveSignature: transition_enclave.to_vec().into(),
    }
    .abi_encode();
    let mut next_verdict = verdict(DcapPlatformTcbStatusV1::UpToDate);
    next_verdict.mrenclave = B256::repeat_byte(0x92);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&current).unwrap();
        install_offer_key(&mut registry, &current);
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
        )
        .unwrap();
        registry
            .stage_successor_policy_v1(U256::from(7), &successor)
            .unwrap();

        let mut wrong_offer =
            AttestationEvidenceV1::decode_canonical(&transition_evidence).unwrap();
        let AttestationEvidenceV1::Dcap(wrong_offer) = &mut wrong_offer else {
            unreachable!();
        };
        let proof = wrong_offer.transition_key_ready_proof.as_mut().unwrap();
        proof.resident_offer_public = [0xc1; 32];
        proof.candidate_attestation_signature = new_enclave
            .sign(proof.signing_hash().unwrap().as_slice())
            .to_bytes();
        let wrong_call = IRegisterEnclaveV1Test::transitionEnclaveMeasurementCall {
            evidence: AttestationEvidenceV1::Dcap(wrong_offer.clone())
                .encode_canonical()
                .unwrap()
                .into(),
            nodeSignature: transition_node.to_vec().into(),
            enclaveSignature: transition_enclave.to_vec().into(),
        }
        .abi_encode();
        assert!(dispatch_transition_after_verifier_for_test(
            storage.clone(),
            node_signer.address(),
            &wrong_call,
            &transition,
            PostVerifierDcapCapabilityV1::new(next_verdict.clone()),
        )
        .is_err());
        assert_eq!(
            registry
                .validator_enclave_binding_v1(node_signer.address())
                .unwrap()
                .unwrap()
                .enclave_id,
            initial.enclave_id
        );
        dispatch_transition_after_verifier_for_test(
            storage.clone(),
            node_signer.address(),
            &call,
            &transition,
            PostVerifierDcapCapabilityV1::new(next_verdict),
        )
        .unwrap();

        let registry = TeeRegistry::new(storage);
        let binding = registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .unwrap();
        assert_eq!(binding.enclave_id, transition.enclave_id);
        assert_eq!(binding.mrenclave, B256::repeat_byte(0x92));
        assert_eq!(binding.transition_nonce, 1);
        assert_eq!(binding.policy_hash, successor.policy_hash().unwrap());
        assert_eq!(registry.active_policy_v1().unwrap(), current);
    });
}

#[test]
fn activation_preserves_old_lease_but_old_policy_cannot_register_renew_or_replace() {
    let genesis_hash = B256::repeat_byte(0x19);
    let current = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut successor = current.clone();
    successor.policy_version = 2;
    successor.activation_height = 50;
    successor.predecessor_policy_hash = current.policy_hash().unwrap();
    for rule in &mut successor.measurement_rules {
        rule.mrenclave = B256::repeat_byte(0x94);
        rule.admit_from_height = 50;
        rule.admit_until_height_exclusive = 500;
    }
    let proposal_id = U256::from(10);
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x37)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x38));
    let initial = registration_intent(
        &current,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x55,
        0x65,
    );
    let renewal = renewal_intent(&initial, NOW + 6_000);
    let replacement_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x39));
    let replacement = replacement_intent(&initial, &replacement_enclave, 0x56, 0x66, NOW + 6_000);
    let newcomer_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x3c)).unwrap();
    let newcomer_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x3d));
    let newcomer_consensus_key = [0x3e; 48];
    let newcomer = registration_intent(
        &current,
        &newcomer_signer,
        newcomer_consensus_key,
        &newcomer_enclave,
        0x57,
        0x67,
    );
    let (initial_node, initial_enclave) = signatures(&initial, &node_signer, &enclave_signer);
    let (renewal_node, renewal_enclave) = signatures(&renewal, &node_signer, &enclave_signer);
    let (replacement_node, replacement_signature) =
        signatures(&replacement, &node_signer, &replacement_enclave);
    let (newcomer_node, newcomer_signature) =
        signatures(&newcomer, &newcomer_signer, &newcomer_enclave);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&current).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
        )
        .unwrap();
        registry
            .stage_successor_policy_v1(proposal_id, &successor)
            .unwrap();
    });

    provider.set_block_number(50);
    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &newcomer_signer, newcomer_consensus_key);
        let mut registry = TeeRegistry::new(storage);
        registry
            .promote_staged_successor_policy_v1(proposal_id, 50)
            .unwrap();
        assert!(registry
            .is_validator_enclave_ready_v1(node_signer.address())
            .unwrap());
        assert!(revert_message(
            registry
                .register_enclave_after_verifier_for_test(
                    &newcomer,
                    &newcomer_node,
                    &newcomer_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("authoritative V1 policy"));
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("authoritative V1 policy"));
        assert!(revert_message(
            registry
                .replace_enclave_binding_after_verifier_for_test(
                    &replacement,
                    &replacement_node,
                    &replacement_signature,
                    PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate,)),
                )
                .unwrap_err()
        )
        .contains("authoritative V1 policy"));
    });
}

#[test]
fn full_node_uses_the_same_bounded_transition_abi_and_staged_policy() {
    let genesis_hash = B256::repeat_byte(0x18);
    let current = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut successor = current.clone();
    successor.policy_version = 2;
    successor.activation_height = 50;
    successor.predecessor_policy_hash = current.policy_hash().unwrap();
    for rule in &mut successor.measurement_rules {
        rule.mrenclave = B256::repeat_byte(0x93);
        rule.admit_from_height = 50;
        rule.admit_until_height_exclusive = 500;
    }

    let node_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x34)).into())
            .unwrap();
    let admission_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x37)).unwrap();
    let old_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x35));
    let new_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x36));
    let initial = full_node_registration_intent(&current, &node_signer, &old_enclave, 0x53, 0x63);
    let transition =
        measurement_transition_intent(&initial, &successor, &new_enclave, 0x54, 0x64, NOW + 3_600);
    let (initial_node, initial_enclave) =
        full_node_signatures(&initial, &node_signer, &old_enclave);
    let (node_binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_p2p_node(
            &initial,
            &admission_signer,
            &node_signer,
        );
    let (transition_node, transition_enclave) =
        full_node_signatures(&transition, &node_signer, &new_enclave);
    let call = IRegisterEnclaveV1Test::transitionEnclaveMeasurementCall {
        evidence: transition_evidence(&transition, &new_enclave).into(),
        nodeSignature: transition_node.to_vec().into(),
        enclaveSignature: transition_enclave.to_vec().into(),
    }
    .abi_encode();
    let mut next_verdict = verdict(DcapPlatformTcbStatusV1::UpToDate);
    next_verdict.mrenclave = B256::repeat_byte(0x93);
    let p2p_public = full_node_public(&initial);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&current).unwrap();
        install_offer_key(&mut registry, &current);
        registry
            .register_enclave_and_bind_after_verifier_for_test(
                &initial,
                &initial_node,
                &initial_enclave,
                &node_binding,
                &validator_signature,
                &node_binding_signature,
                PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
            )
            .unwrap();
        registry
            .stage_successor_policy_v1(U256::from(9), &successor)
            .unwrap();
        dispatch_transition_after_verifier_for_test(
            storage.clone(),
            admission_signer.address(),
            &call,
            &transition,
            PostVerifierDcapCapabilityV1::new(next_verdict),
        )
        .unwrap();

        let binding = TeeRegistry::new(storage)
            .node_host_enclave_binding_v1(p2p_public)
            .unwrap()
            .unwrap();
        assert_eq!(binding.enclave_id, transition.enclave_id);
        assert_eq!(binding.mrenclave, B256::repeat_byte(0x93));
        assert_eq!(binding.transition_nonce, 1);
        assert_eq!(binding.policy_hash, successor.policy_hash().unwrap());
    });
}

#[test]
fn an_existing_lease_is_not_retroactively_filtered_by_the_policy_anchor() {
    let genesis_hash = B256::repeat_byte(0x26);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.maximum_lease = 3_600;
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x7E)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x7F));
    let intent = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x71,
        0x72,
    );
    let (node_signature, enclave_signature) = signatures(&intent, &node_signer, &enclave_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage);
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &intent,
            &node_signer,
            &node_signature,
            &enclave_signature,
            PostVerifierDcapCapabilityV1::new(verdict(DcapPlatformTcbStatusV1::UpToDate)),
        )
        .unwrap();
        let admitted_policy_hash = active_policy.policy_hash().unwrap();
        registry
            .active_v1_policy_hash
            .write(B256::repeat_byte(0xEE))
            .unwrap();

        assert!(registry
            .is_validator_enclave_ready_v1(node_signer.address())
            .unwrap());
        assert_eq!(
            registry
                .validator_enclave_binding_v1(node_signer.address())
                .unwrap()
                .unwrap()
                .policy_hash,
            admitted_policy_hash
        );
    });
}

#[test]
fn renewal_window_is_half_open_extends_from_deadline_and_does_not_drift() {
    let genesis_hash = B256::repeat_byte(0x21);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x71)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x72));
    let initial = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x61,
        0x62,
    );
    let (initial_node, initial_enclave) = signatures(&initial, &node_signer, &enclave_signer);
    let renewal = renewal_intent(&initial, initial.requested_valid_until + 3_600);
    let (renewal_node, renewal_enclave) = signatures(&renewal, &node_signer, &enclave_signer);
    let mut fresh_verdict = verdict(DcapPlatformTcbStatusV1::UpToDate);
    fresh_verdict.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
        )
        .unwrap();

        storage
            .set_block_timestamp(U256::from(NOW + 1_799))
            .unwrap();
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
                )
                .unwrap_err()
        )
        .contains("renewal window"));

        storage
            .set_block_timestamp(U256::from(NOW + 1_800))
            .unwrap();
        assert_eq!(
            registry
                .renew_enclave_after_verifier_for_test(
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        assert_eq!(
            registry
                .renew_enclave_after_verifier_for_test(
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Idempotent
        );
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::with_evidence_hash(
                        fresh_verdict.clone(),
                        B256::repeat_byte(0xED),
                    ),
                )
                .unwrap_err()
        )
        .contains("exact evidence replay"));
        let binding = registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .unwrap();
        assert_eq!(binding.registration_version, 1);
        assert_eq!(binding.renewal_nonce, 1);
        assert_eq!(binding.lease_started_at, NOW + 1_800);
        assert_eq!(
            binding.valid_until,
            initial.requested_valid_until + active_policy.maximum_lease
        );

        let mut stale = renewal.clone();
        stale.registration_version = 0;
        stale.renewal_nonce = 0;
        let (stale_node, stale_enclave) = signatures(&stale, &node_signer, &enclave_signer);
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &stale,
                    &stale_node,
                    &stale_enclave,
                    PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
                )
                .unwrap_err()
        )
        .contains("next renewal"));
    });

    let mut late_provider = storage(genesis_hash);
    StorageHandle::enter(&mut late_provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
        )
        .unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();
        let expired_renewal = renewal_intent(
            &initial,
            initial.requested_valid_until + active_policy.maximum_lease,
        );
        let (node_signature, enclave_signature) =
            signatures(&expired_renewal, &node_signer, &enclave_signer);
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &expired_renewal,
                    &node_signature,
                    &enclave_signature,
                    PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
                )
                .unwrap_err()
        )
        .contains("expired"));
    });

    let mut no_drift_provider = storage(genesis_hash);
    StorageHandle::enter(&mut no_drift_provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
        )
        .unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until - 1))
            .unwrap();
        registry
            .renew_enclave_after_verifier_for_test(
                &renewal,
                &renewal_node,
                &renewal_enclave,
                PostVerifierDcapCapabilityV1::new(fresh_verdict.clone()),
            )
            .unwrap();

        let second = renewal_intent(
            &renewal,
            renewal.requested_valid_until + active_policy.maximum_lease,
        );
        let (second_node, second_enclave) = signatures(&second, &node_signer, &enclave_signer);
        let second_opens_at = renewal.requested_valid_until - active_policy.maximum_lease / 2;
        storage
            .set_block_timestamp(U256::from(second_opens_at))
            .unwrap();
        registry
            .renew_enclave_after_verifier_for_test(
                &second,
                &second_node,
                &second_enclave,
                PostVerifierDcapCapabilityV1::new(fresh_verdict),
            )
            .unwrap();
        assert_eq!(
            registry
                .validator_enclave_binding_v1(node_signer.address())
                .unwrap()
                .unwrap()
                .valid_until,
            initial.requested_valid_until + 2 * active_policy.maximum_lease
        );
    });
}

#[test]
fn renewal_rejects_the_wrong_evm_caller_before_replay_or_state_change() {
    let genesis_hash = B256::repeat_byte(0x2C);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x2D)).unwrap();
    let wrong =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x2E)).unwrap();
    let enclave = ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x2F));
    let initial = registration_intent(&active_policy, &owner, CONSENSUS_KEY, &enclave, 0x30, 0x31);
    let renewal = renewal_intent(&initial, initial.requested_valid_until + 3_600);
    let (initial_node, initial_enclave) = signatures(&initial, &owner, &enclave);
    let (renewal_node, renewal_enclave) = signatures(&renewal, &owner, &enclave);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        storage
            .set_block_timestamp(U256::from(NOW + 1_800))
            .unwrap();
        let before = registry
            .validator_enclave_binding_v1(owner.address())
            .unwrap()
            .unwrap();

        let error = registry
            .renew_enclave_after_verifier_for_test_as(
                wrong.address(),
                &renewal,
                &renewal_node,
                &renewal_enclave,
                PostVerifierDcapCapabilityV1::new(accepted.clone()),
            )
            .unwrap_err();
        assert!(revert_message(error).contains("caller"));
        assert_eq!(
            registry
                .validator_enclave_binding_v1(owner.address())
                .unwrap()
                .unwrap(),
            before
        );

        assert_eq!(
            registry
                .renew_enclave_after_verifier_for_test_as(
                    owner.address(),
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(accepted.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test_as(
                    wrong.address(),
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap_err()
        )
        .contains("caller"));
    });
}

#[test]
fn expired_same_enclave_rejoin_is_authorized_monotonic_and_idempotent() {
    let genesis_hash = B256::repeat_byte(0x32);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x33)).unwrap();
    let wrong =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x34)).unwrap();
    let enclave = ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x35));
    let initial = registration_intent(&active_policy, &owner, CONSENSUS_KEY, &enclave, 0x36, 0x37);
    let rejoin = same_enclave_rejoin_intent(&initial, 0x38, NOW + 7_200);
    let (initial_node, initial_enclave) = signatures(&initial, &owner, &enclave);
    let (rejoin_node, rejoin_enclave) = signatures(&rejoin, &owner, &enclave);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&rejoin, &owner, &owner);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        let node_hash = initial.node_id.node_id_hash().unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();

        assert!(revert_message(
            registry
                .register_enclave_and_bind_after_verifier_for_test_as(
                    wrong.address(),
                    &rejoin,
                    &rejoin_node,
                    &rejoin_enclave,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted.clone()),
                )
                .unwrap_err()
        )
        .contains("caller"));
        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test_as(
                    owner.address(),
                    &rejoin,
                    &rejoin_node,
                    &rejoin_enclave,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        let stored = registry
            .validator_enclave_binding_v1(owner.address())
            .unwrap()
            .unwrap();
        assert_eq!(stored.binding_id, rejoin.binding_id);
        assert_eq!(stored.binding_version, initial.binding_version + 1);
        assert_eq!(
            stored.registration_version,
            initial.registration_version + 1
        );
        assert_eq!(stored.renewal_nonce, initial.renewal_nonce);
        assert_eq!(stored.transition_nonce, initial.transition_nonce);
        assert_eq!(stored.valid_until, NOW + 7_200);
        assert_eq!(
            registry
                .validator_v1_node_hash
                .read(&owner.address())
                .unwrap(),
            node_hash
        );
        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test_as(
                    owner.address(),
                    &rejoin,
                    &rejoin_node,
                    &rejoin_enclave,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap(),
            V1RegistrationOutcome::Idempotent
        );
    });
}

#[test]
fn expired_new_enclave_rejoin_preserves_historical_reverse_ownership() {
    let genesis_hash = B256::repeat_byte(0x39);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x3A)).unwrap();
    let initial_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x3B));
    let next_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x3C));
    let initial = registration_intent(
        &active_policy,
        &owner,
        CONSENSUS_KEY,
        &initial_enclave,
        0x3D,
        0x3E,
    );
    let rejoin = new_enclave_rejoin_intent(&initial, &next_enclave, 0x3F, 0x40, NOW + 7_200);
    let (initial_node, initial_enclave_signature) = signatures(&initial, &owner, &initial_enclave);
    let (rejoin_node, rejoin_enclave_signature) = signatures(&rejoin, &owner, &next_enclave);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&rejoin, &owner, &owner);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave_signature,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        let node_hash = initial.node_id.node_id_hash().unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();

        assert_eq!(
            registry
                .register_enclave_and_bind_after_verifier_for_test_as(
                    owner.address(),
                    &rejoin,
                    &rejoin_node,
                    &rejoin_enclave_signature,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        let stored = registry
            .validator_enclave_binding_v1(owner.address())
            .unwrap()
            .unwrap();
        assert_eq!(stored.enclave_id, rejoin.enclave_id);
        assert_eq!(stored.binding_id, rejoin.binding_id);
        assert_eq!(stored.binding_version, initial.binding_version + 1);
        assert_eq!(
            stored.registration_version,
            initial.registration_version + 1
        );
        assert_eq!(
            registry
                .v1_enclave_node_hash
                .read(&initial.enclave_id)
                .unwrap(),
            node_hash
        );
        assert_eq!(
            registry
                .v1_binding_node_hash
                .read(&initial.binding_id)
                .unwrap(),
            node_hash
        );
        assert_eq!(
            registry
                .v1_enclave_node_hash
                .read(&rejoin.enclave_id)
                .unwrap(),
            node_hash
        );
        assert_eq!(
            registry
                .v1_binding_node_hash
                .read(&rejoin.binding_id)
                .unwrap(),
            node_hash
        );
    });
}

#[test]
fn expired_new_enclave_rejoin_abi_fits_normative_register_gas() {
    let genesis_hash = B256::repeat_byte(0x52);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x53)).unwrap();
    let initial_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x54));
    let next_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x55));
    let initial = registration_intent(
        &active_policy,
        &owner,
        CONSENSUS_KEY,
        &initial_enclave,
        0x56,
        0x57,
    );
    let rejoin = new_enclave_rejoin_intent(&initial, &next_enclave, 0x58, 0x59, NOW + 7_200);
    let (initial_node, initial_enclave_signature) = signatures(&initial, &owner, &initial_enclave);
    let (rejoin_node, rejoin_enclave_signature) = signatures(&rejoin, &owner, &next_enclave);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&rejoin, &owner, &owner);
    let evidence = vec![0xD1; 4_096];
    let call = IRegisterEnclaveV1Test::registerEnclaveCall {
        evidence: evidence.clone().into(),
        nodeSignature: rejoin_node.to_vec().into(),
        enclaveSignature: rejoin_enclave_signature.to_vec().into(),
        validatorNodeBinding: binding.encode_canonical().unwrap().into(),
        validatorSignature: validator_signature.to_vec().into(),
        nodeBindingSignature: node_binding_signature.to_vec().into(),
    }
    .abi_encode();
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);
    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave_signature,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();
    });
    provider.enable_production_storage_gas_metering();
    provider.set_gas_limit(u64::MAX);
    let outcome = StorageHandle::enter(&mut provider, |storage| {
        dispatch_register_after_verifier_for_test(
            storage,
            owner.address(),
            &call,
            &rejoin,
            PostVerifierDcapCapabilityV1::new(accepted),
        )
        .unwrap()
    });
    assert_eq!(outcome, V1RegistrationOutcome::Created);

    let schedule = TeeRegistryGasScheduleV1::normative();
    let allowance = schedule.register_storage_gas_allowance();
    let maximum = schedule
        .maximum_transaction_gas(
            RegistryMutatorV1::RegisterEnclave,
            call.len(),
            evidence.len(),
            active_policy.measurement_rules.len(),
            active_policy.attestation_mode,
        )
        .unwrap();
    let intrinsic = schedule.maximum_calldata_intrinsic_gas(call.len()).unwrap();
    let (reads, writes) = provider.metered_storage_operations();
    let storage_gas = reads * 100 + writes * 5_000;
    assert!(storage_gas <= allowance);
    assert_eq!(
        intrinsic + 200 + provider.gas_used(),
        maximum - allowance + storage_gas
    );
    assert!(intrinsic + 200 + provider.gas_used() <= maximum);
}

#[test]
fn expired_rejoin_fails_closed_on_corrupt_current_reverse_ownership() {
    let genesis_hash = B256::repeat_byte(0x5A);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x5B)).unwrap();
    let enclave = ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x5C));
    let initial = registration_intent(&active_policy, &owner, CONSENSUS_KEY, &enclave, 0x5D, 0x5E);
    let rejoin = same_enclave_rejoin_intent(&initial, 0x5F, NOW + 7_200);
    let (initial_node, initial_enclave) = signatures(&initial, &owner, &enclave);
    let (rejoin_node, rejoin_enclave) = signatures(&rejoin, &owner, &enclave);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&rejoin, &owner, &owner);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();
        let before = registry
            .validator_enclave_binding_v1(owner.address())
            .unwrap()
            .unwrap();
        registry
            .v1_binding_node_hash
            .write(&initial.binding_id, B256::ZERO)
            .unwrap();

        assert!(matches!(
            registry
                .register_enclave_and_bind_after_verifier_for_test_as(
                    owner.address(),
                    &rejoin,
                    &rejoin_node,
                    &rejoin_enclave,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap_err(),
            PrecompileError::Fatal(message) if message.contains("reverse ownership")
        ));
        assert_eq!(
            registry
                .validator_enclave_binding_v1(owner.address())
                .unwrap()
                .unwrap(),
            before
        );
    });
}

#[test]
fn expired_jailed_validator_must_unjail_before_rejoin() {
    let genesis_hash = B256::repeat_byte(0x41);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.minimum_lease = 3_600;
    active_policy.maximum_lease = 3_600;
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x42)).unwrap();
    let enclave = ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x43));
    let initial = registration_intent(&active_policy, &owner, CONSENSUS_KEY, &enclave, 0x44, 0x45);
    let rejoin = same_enclave_rejoin_intent(&initial, 0x46, NOW + 7_200);
    let (initial_node, initial_enclave) = signatures(&initial, &owner, &enclave);
    let (rejoin_node, rejoin_enclave) = signatures(&rejoin, &owner, &enclave);
    let (binding, validator_signature, node_binding_signature) =
        validator_node_binding_authorization_for_evm_node(&rejoin, &owner, &owner);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &owner, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        let mut validators = ValidatorSet::new(storage.clone());
        validators
            .activate_validator_via_boundary_for_test(owner.address())
            .unwrap();
        validators.jail_validator(owner.address()).unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();
        let before = registry
            .validator_enclave_binding_v1(owner.address())
            .unwrap()
            .unwrap();

        assert!(revert_message(
            registry
                .register_enclave_and_bind_after_verifier_for_test_as(
                    owner.address(),
                    &rejoin,
                    &rejoin_node,
                    &rejoin_enclave,
                    &binding,
                    &validator_signature,
                    &node_binding_signature,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap_err()
        )
        .contains("unjail"));
        assert_eq!(
            registry
                .validator_enclave_binding_v1(owner.address())
                .unwrap()
                .unwrap(),
            before
        );
    });
}

#[test]
fn expired_binding_rejects_replace_and_transition_without_state_change() {
    let genesis_hash = B256::repeat_byte(0x47);
    let current = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let mut successor = current.clone();
    successor.policy_version = 2;
    successor.activation_height = 50;
    successor.predecessor_policy_hash = current.policy_hash().unwrap();
    for rule in &mut successor.measurement_rules {
        rule.mrenclave = B256::repeat_byte(0x94);
        rule.admit_from_height = 50;
        rule.admit_until_height_exclusive = 500;
    }
    let owner =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x48)).unwrap();
    let initial_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x49));
    let replacement_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x4A));
    let transition_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x4B));
    let initial = registration_intent(
        &current,
        &owner,
        CONSENSUS_KEY,
        &initial_enclave,
        0x4C,
        0x4D,
    );
    let replacement = replacement_intent(&initial, &replacement_enclave, 0x4E, 0x4F, NOW + 7_200);
    let transition = measurement_transition_intent(
        &initial,
        &successor,
        &transition_enclave,
        0x50,
        0x51,
        NOW + 7_200,
    );
    let (initial_node, initial_enclave_signature) = signatures(&initial, &owner, &initial_enclave);
    let (replacement_node, replacement_enclave_signature) =
        signatures(&replacement, &owner, &replacement_enclave);
    let (transition_node, transition_enclave_signature) =
        signatures(&transition, &owner, &transition_enclave);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 20_000;
    let mut transition_verdict = accepted.clone();
    transition_verdict.mrenclave = B256::repeat_byte(0x94);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&current).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &owner,
            &initial_node,
            &initial_enclave_signature,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        registry
            .stage_successor_policy_v1(U256::from(11), &successor)
            .unwrap();
        storage
            .set_block_timestamp(U256::from(initial.requested_valid_until))
            .unwrap();
        let before = registry
            .validator_enclave_binding_v1(owner.address())
            .unwrap()
            .unwrap();

        assert!(revert_message(
            registry
                .replace_enclave_binding_after_verifier_with_active_policy_for_test(
                    owner.address(),
                    &replacement,
                    &replacement_node,
                    &replacement_enclave_signature,
                    &current,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap_err()
        )
        .contains("expired"));
        assert!(revert_message(
            registry
                .transition_enclave_measurement_after_verifier_for_test(
                    owner.address(),
                    &transition,
                    &transition_node,
                    &transition_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(transition_verdict),
                )
                .unwrap_err()
        )
        .contains("expired"));
        assert_eq!(
            registry
                .validator_enclave_binding_v1(owner.address())
                .unwrap()
                .unwrap(),
            before
        );
    });
}

#[test]
fn renewal_rejects_collateral_margin_underflow_without_extending_state() {
    let genesis_hash = B256::repeat_byte(0x22);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.maximum_lease = 3_600;
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x73)).unwrap();
    let enclave_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x74));
    let initial = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &enclave_signer,
        0x63,
        0x64,
    );
    let (initial_node, initial_enclave) = signatures(&initial, &node_signer, &enclave_signer);
    let renewal = renewal_intent(
        &initial,
        initial.requested_valid_until + active_policy.maximum_lease,
    );
    let (renewal_node, renewal_enclave) = signatures(&renewal, &node_signer, &enclave_signer);
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        let mut initial_verdict = verdict(DcapPlatformTcbStatusV1::UpToDate);
        initial_verdict.collateral_valid_until = NOW + 12_000;
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(initial_verdict),
        )
        .unwrap();
        storage
            .set_block_timestamp(U256::from(NOW + 2_400))
            .unwrap();
        let before = registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .unwrap();
        let mut underflow = verdict(DcapPlatformTcbStatusV1::UpToDate);
        underflow.collateral_valid_until = active_policy.collateral_margin - 1;
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &renewal,
                    &renewal_node,
                    &renewal_enclave,
                    PostVerifierDcapCapabilityV1::new(underflow),
                )
                .unwrap_err()
        )
        .contains("safety margin"));
        assert_eq!(
            registry
                .validator_enclave_binding_v1(node_signer.address())
                .unwrap()
                .unwrap(),
            before
        );
    });
}

#[test]
fn candidate_generated_quote_intent_reaches_registry_replacement_exactly() {
    use std::{
        os::unix::net::UnixListener,
        sync::{Arc, OnceLock},
    };

    use outbe_primitives::tee_attestation_v1::{
        AttestationEvidenceV1, DcapCollateralComponentV1, DcapCollateralKind, DcapEvidenceV1,
    };
    use outbe_tee::{
        connect_or_initialize_node_host_enclave, load_replacement_candidate_submission,
        persist_replacement_candidate_submission, prepare_node_host_enclave_replacement_candidate,
        NodeHostIdentityV1,
    };
    use outbe_tee_enclave::{
        initialization::InitializationState,
        keys::EnclaveKeys,
        seal::EnclaveBootConfig,
        transport::{serve_connection_with_synthetic_dcap, SharedTributeOfferKey},
    };

    let genesis_hash = B256::repeat_byte(0x23);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x75)).unwrap();
    let identity = NodeHostIdentityV1 {
        network_binding: active_policy.network_binding(),
        reth_p2p_public: reth_p2p_public_for_evm_signer(&node_signer),
    };
    let sign = |hash: B256| {
        node_signer
            .sign_hash(&hash)
            .map_err(|error| error.to_string())
    };

    let root = tempfile::tempdir().unwrap();
    let socket_a = root.path().join("active-enclave.sock");
    let socket_b = root.path().join("candidate-enclave.sock");
    let endpoint_a = socket_a.to_str().unwrap().to_owned();
    let endpoint_b = socket_b.to_str().unwrap().to_owned();
    let boot_a = Arc::new(EnclaveBootConfig::new(
        active_policy.chain_id,
        root.path().join("active-enclave-state"),
        0,
    ));
    let boot_b = Arc::new(EnclaveBootConfig::new(
        active_policy.chain_id,
        root.path().join("candidate-enclave-state"),
        0,
    ));
    std::fs::create_dir(&boot_a.tee_dir).unwrap();
    std::fs::create_dir(&boot_b.tee_dir).unwrap();
    let keys_a = Arc::new(EnclaveKeys::new([0x76; 32], Some([0x76; 32])).unwrap());
    let keys_b = Arc::new(EnclaveKeys::new([0x77; 32], Some([0x77; 32])).unwrap());
    let initialization_a = Arc::new(
        InitializationState::production_with_synthetic_dcap_for_test(boot_a.clone(), &keys_a)
            .unwrap(),
    );
    let initialization_b = Arc::new(
        InitializationState::production_with_synthetic_dcap_for_test(boot_b.clone(), &keys_b)
            .unwrap(),
    );

    let listener_a = UnixListener::bind(&socket_a).unwrap();
    let server_keys_a = keys_a.clone();
    let server_a = std::thread::spawn(move || {
        let offer_key: SharedTributeOfferKey = Arc::new(OnceLock::new());
        for _ in 0..2 {
            let (stream, _) = listener_a.accept().unwrap();
            serve_connection_with_synthetic_dcap(
                stream,
                &server_keys_a,
                &offer_key,
                Some(&boot_a),
                &initialization_a,
            )
            .unwrap();
        }
    });
    let listener_b = UnixListener::bind(&socket_b).unwrap();
    let server_keys_b = keys_b.clone();
    let server_b = std::thread::spawn(move || {
        let offer_key: SharedTributeOfferKey = Arc::new(OnceLock::new());
        for _ in 0..2 {
            let (stream, _) = listener_b.accept().unwrap();
            serve_connection_with_synthetic_dcap(
                stream,
                &server_keys_b,
                &offer_key,
                Some(&boot_b),
                &initialization_b,
            )
            .unwrap();
        }
    });

    let node_data_dir = root.path().join("node-data");
    std::fs::create_dir(&node_data_dir).unwrap();
    drop(
        connect_or_initialize_node_host_enclave(&endpoint_a, &node_data_dir, identity, sign)
            .unwrap(),
    );
    let active_manifest_bytes = std::fs::read(
        node_data_dir
            .join(outbe_tee::node_host::NODE_HOST_DIRECTORY_V1)
            .join(outbe_tee::node_host::NODE_HOST_MANIFEST_V1),
    )
    .unwrap();
    let active_manifest =
        EnclaveInitializationManifestV1::decode_canonical(&active_manifest_bytes).unwrap();
    let initial = RegistrationIntentV1 {
        chain_id: active_manifest.chain_id,
        genesis_hash: active_manifest.genesis_hash,
        operation: AttestationOperationV1::RegisterEnclave,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: active_policy.policy_hash().unwrap(),
        node_id: active_manifest.node_id.clone(),
        enclave_id: active_manifest.enclave_id().unwrap(),
        binding_id: B256::repeat_byte(0x66),
        binding_version: 1,
        registration_version: 0,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until: NOW + 3_600,
        recipient_x25519: active_manifest.recipient_x25519,
        attestation_ed25519: active_manifest.attestation_ed25519,
        noise_responder_x25519: active_manifest.noise_responder_x25519,
        node_host_authorization_hash: active_manifest.node_host_authorization_hash().unwrap(),
    };
    active_manifest.validate_intent_binding(&initial).unwrap();
    let initial_hash = initial.intent_hash().unwrap();
    let initial_node_signature = node_signer.sign_hash(&initial_hash).unwrap();
    let initial_enclave_signature = keys_a.sign_attestation(initial_hash.as_slice());

    let mut candidate = prepare_node_host_enclave_replacement_candidate(
        &endpoint_b,
        &node_data_dir,
        identity,
        sign,
    )
    .unwrap();
    let candidate_manifest = candidate.manifest().clone();
    let mut replacement = initial.clone();
    replacement.operation = AttestationOperationV1::ReplaceEnclaveBinding;
    replacement.enclave_id = candidate_manifest.enclave_id().unwrap();
    replacement.binding_id = B256::repeat_byte(0x68);
    replacement.binding_version = 2;
    replacement.registration_version = 1;
    replacement.requested_valid_until = NOW + 3_600;
    replacement.recipient_x25519 = candidate_manifest.recipient_x25519;
    replacement.attestation_ed25519 = candidate_manifest.attestation_ed25519;
    replacement.noise_responder_x25519 = candidate_manifest.noise_responder_x25519;
    replacement.node_host_authorization_hash =
        candidate_manifest.node_host_authorization_hash().unwrap();
    candidate_manifest
        .validate_intent_binding(&replacement)
        .unwrap();
    assert_eq!(
        replacement.node_host_authorization_hash,
        initial.node_host_authorization_hash
    );

    let generated = candidate.generate_dcap_quote(&replacement).unwrap();
    let replacement_hash = replacement.intent_hash().unwrap();
    let replacement_node_signature = node_signer.sign_hash(&replacement_hash).unwrap();
    let evidence = AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
        intent: replacement.clone(),
        quote: generated.quote_body.clone(),
        components: (1_u8..=8)
            .map(|kind| DcapCollateralComponentV1 {
                kind: DcapCollateralKind::try_from(kind).unwrap(),
                bytes: vec![kind],
            })
            .collect(),
        transition_key_ready_proof: None,
    });
    let exact_evidence = evidence.encode_canonical().unwrap();
    let submission = persist_replacement_candidate_submission(
        &node_data_dir,
        &evidence,
        &replacement_node_signature,
        &generated.enclave_signature,
    )
    .unwrap();
    assert_eq!(submission.evidence(), exact_evidence);
    assert_eq!(
        load_replacement_candidate_submission(&node_data_dir)
            .unwrap()
            .unwrap(),
        submission
    );
    let AttestationEvidenceV1::Dcap(submitted) =
        AttestationEvidenceV1::decode_canonical(submission.evidence()).unwrap()
    else {
        unreachable!();
    };
    assert_eq!(
        submitted.intent.encode_canonical().unwrap(),
        replacement.encode_canonical().unwrap()
    );
    assert_eq!(submitted.quote, generated.quote_body);

    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 12_000;
    let mut provider = storage(genesis_hash);
    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node_signature,
            &initial_enclave_signature,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        assert_eq!(
            registry
                .replace_enclave_binding_after_verifier_for_test(
                    &submitted.intent,
                    submission.node_signature(),
                    submission.enclave_signature(),
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        let binding = registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .unwrap();
        assert_eq!(binding.enclave_id, candidate_manifest.enclave_id().unwrap());
        assert_eq!(binding.binding_id, replacement.binding_id);
        assert_eq!(binding.binding_version, replacement.binding_version);
        assert_eq!(
            binding.registration_version,
            replacement.registration_version
        );
    });

    drop(candidate);
    server_a.join().unwrap();
    server_b.join().unwrap();
}

#[test]
fn replacement_candidate_intent_reaches_registry_unchanged_and_never_reuses_consumed_ids() {
    let genesis_hash = B256::repeat_byte(0x23);
    let active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x75)).unwrap();
    let old_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x76));
    let new_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x77));
    let initial = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &old_enclave,
        0x65,
        0x66,
    );
    let replacement = replacement_intent(&initial, &new_enclave, 0x67, 0x68, NOW + 3_600);
    let active_manifest = initialization_manifest_for_intent(&initial, [0xa6; 32]);
    let candidate_manifest = initialization_manifest_for_intent(&replacement, [0xa7; 32]);
    assert_ne!(
        active_manifest.authorization_hash().unwrap(),
        candidate_manifest.authorization_hash().unwrap()
    );
    assert_eq!(
        active_manifest.node_host_authorization_hash().unwrap(),
        candidate_manifest.node_host_authorization_hash().unwrap()
    );
    candidate_manifest
        .validate_intent_binding(&replacement)
        .unwrap();
    let candidate_intent_bytes = replacement.encode_canonical().unwrap();
    let (initial_node, initial_enclave) = signatures(&initial, &node_signer, &old_enclave);
    let (replacement_node, replacement_enclave) =
        signatures(&replacement, &node_signer, &new_enclave);
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 12_000;
    let mut provider = storage(genesis_hash);

    StorageHandle::enter(&mut provider, |storage| {
        register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
        let mut registry = TeeRegistry::new(storage.clone());
        registry.install_initial_policy_v1(&active_policy).unwrap();
        register_same_key_node_for_lifecycle_test(
            &mut registry,
            &initial,
            &node_signer,
            &initial_node,
            &initial_enclave,
            PostVerifierDcapCapabilityV1::new(accepted.clone()),
        )
        .unwrap();
        assert_eq!(
            registry
                .replace_enclave_binding_after_verifier_for_test(
                    &replacement,
                    &replacement_node,
                    &replacement_enclave,
                    PostVerifierDcapCapabilityV1::new(accepted.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Created
        );
        assert_eq!(
            registry
                .replace_enclave_binding_after_verifier_for_test(
                    &replacement,
                    &replacement_node,
                    &replacement_enclave,
                    PostVerifierDcapCapabilityV1::new(accepted.clone()),
                )
                .unwrap(),
            V1RegistrationOutcome::Idempotent
        );
        let binding = registry
            .validator_enclave_binding_v1(node_signer.address())
            .unwrap()
            .unwrap();
        assert_eq!(binding.enclave_id, replacement.enclave_id);
        assert_eq!(binding.binding_id, replacement.binding_id);
        assert_eq!(binding.binding_version, 2);
        assert_eq!(binding.registration_version, 1);
        assert_eq!(
            replacement.encode_canonical().unwrap(),
            candidate_intent_bytes
        );

        let old_renewal = renewal_intent(&initial, NOW + 6_000);
        let (old_node, old_enclave_signature) =
            signatures(&old_renewal, &node_signer, &old_enclave);
        storage
            .set_block_timestamp(U256::from(NOW + 2_400))
            .unwrap();
        assert!(revert_message(
            registry
                .renew_enclave_after_verifier_for_test(
                    &old_renewal,
                    &old_node,
                    &old_enclave_signature,
                    PostVerifierDcapCapabilityV1::new(accepted.clone()),
                )
                .unwrap_err()
        )
        .contains("superseded"));

        let current = replacement.clone();
        let attempted_reuse = replacement_intent(&current, &old_enclave, 0x65, 0x66, NOW + 6_000);
        let (reuse_node, reuse_enclave) = signatures(&attempted_reuse, &node_signer, &old_enclave);
        assert!(revert_message(
            registry
                .replace_enclave_binding_after_verifier_for_test(
                    &attempted_reuse,
                    &reuse_node,
                    &reuse_enclave,
                    PostVerifierDcapCapabilityV1::new(accepted),
                )
                .unwrap_err()
        )
        .contains("already been used"));
    });
}

#[test]
fn renew_and_replace_abi_are_replica_deterministic_and_fit_normative_gas() {
    let genesis_hash = B256::repeat_byte(0x24);
    let mut active_policy = policy(
        genesis_hash,
        PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
    );
    active_policy.maximum_lease = 3_600;
    let node_signer =
        OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(0x78)).unwrap();
    let old_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x79));
    let new_enclave =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x7A));
    let initial = registration_intent(
        &active_policy,
        &node_signer,
        CONSENSUS_KEY,
        &old_enclave,
        0x69,
        0x6A,
    );
    let renewal = renewal_intent(
        &initial,
        initial.requested_valid_until + active_policy.maximum_lease,
    );
    let replacement = replacement_intent(&renewal, &new_enclave, 0x6B, 0x6C, NOW + 6_000);
    let (initial_node, initial_enclave) = signatures(&initial, &node_signer, &old_enclave);
    let (renewal_node, renewal_enclave) = signatures(&renewal, &node_signer, &old_enclave);
    let (replacement_node, replacement_enclave) =
        signatures(&replacement, &node_signer, &new_enclave);
    let evidence = vec![0xA7; 4_096];
    let renewal_call = IRegisterEnclaveV1Test::renewEnclaveCall {
        evidence: evidence.clone().into(),
        nodeSignature: renewal_node.to_vec().into(),
        enclaveSignature: renewal_enclave.to_vec().into(),
    }
    .abi_encode();
    let replacement_call = IRegisterEnclaveV1Test::replaceEnclaveBindingCall {
        evidence: evidence.clone().into(),
        nodeSignature: replacement_node.to_vec().into(),
        enclaveSignature: replacement_enclave.to_vec().into(),
    }
    .abi_encode();
    let mut accepted = verdict(DcapPlatformTcbStatusV1::UpToDate);
    accepted.collateral_valid_until = NOW + 12_000;

    let execute = || {
        let mut provider = storage(genesis_hash);
        StorageHandle::enter(&mut provider, |storage| {
            register_validator(storage.clone(), &node_signer, CONSENSUS_KEY);
            let mut registry = TeeRegistry::new(storage.clone());
            registry.install_initial_policy_v1(&active_policy).unwrap();
            register_same_key_node_for_lifecycle_test(
                &mut registry,
                &initial,
                &node_signer,
                &initial_node,
                &initial_enclave,
                PostVerifierDcapCapabilityV1::new(accepted.clone()),
            )
            .unwrap();
            storage
                .set_block_timestamp(U256::from(NOW + 2_400))
                .unwrap();
        });
        provider.enable_production_storage_gas_metering();
        provider.set_gas_limit(u64::MAX);
        StorageHandle::enter(&mut provider, |storage| {
            dispatch_renew_after_verifier_for_test(
                storage.clone(),
                node_signer.address(),
                &renewal_call,
                &renewal,
                PostVerifierDcapCapabilityV1::new(accepted.clone()),
            )
            .unwrap();
            dispatch_replace_after_verifier_for_test(
                storage,
                node_signer.address(),
                &replacement_call,
                &replacement,
                PostVerifierDcapCapabilityV1::new(accepted.clone()),
            )
            .unwrap();
        });
        provider
    };
    let proposer = execute();
    let validator = execute();
    let follower = execute();
    for replica in [&validator, &follower] {
        assert_eq!(replica.storage, proposer.storage);
        assert_eq!(replica.get_ordered_events(), proposer.get_ordered_events());
        assert_eq!(
            replica.metered_storage_operations(),
            proposer.metered_storage_operations()
        );
        assert_eq!(replica.gas_used(), proposer.gas_used());
    }

    let schedule = TeeRegistryGasScheduleV1::normative();
    let mut maximum_total = 0_u64;
    let mut intrinsic_total = 0_u64;
    let mut allowance_total = 0_u64;
    for (kind, call) in [
        (RegistryMutatorV1::RenewEnclave, &renewal_call),
        (RegistryMutatorV1::ReplaceEnclaveBinding, &replacement_call),
    ] {
        let maximum = schedule
            .maximum_transaction_gas(
                kind,
                call.len(),
                evidence.len(),
                active_policy.measurement_rules.len(),
                AttestationMode::DcapRequired,
            )
            .unwrap();
        assert!(maximum < 30_000_000);
        maximum_total += maximum;
        intrinsic_total += schedule.maximum_calldata_intrinsic_gas(call.len()).unwrap();
        allowance_total += schedule.mutator_storage_gas_allowance(kind);
    }
    let (reads, writes) = proposer.metered_storage_operations();
    let storage_gas = reads * 100 + writes * 5_000;
    assert!(storage_gas <= allowance_total);
    assert_eq!(
        intrinsic_total + 2 * 200 + proposer.gas_used(),
        maximum_total - allowance_total + storage_gas
    );
    assert!(intrinsic_total + 2 * 200 + proposer.gas_used() <= maximum_total);
}
