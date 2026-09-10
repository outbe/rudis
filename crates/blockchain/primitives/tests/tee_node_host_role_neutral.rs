#![cfg(feature = "tee-attestation-v1")]

use alloy_primitives::{Address, B256};
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, SigningKey};
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, EnclaveInitializationManifestV1, NodeIdV1, ValidatorNodeBindingV1,
};

fn compressed_public(key: &SigningKey) -> [u8; 33] {
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap()
}

fn recoverable_signature(key: &SigningKey, hash: B256) -> [u8; 65] {
    let (signature, recovery_id) = key.sign_prehash(hash.as_slice()).unwrap();
    let mut out = [0_u8; 65];
    out[..64].copy_from_slice(signature.to_bytes().as_slice());
    out[64] = recovery_id.to_byte();
    out
}

#[test]
fn node_host_identity_is_only_the_persistent_reth_p2p_key() {
    let node_key =
        SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x41)).into()).unwrap();
    let node_id = NodeIdV1 {
        reth_p2p_public: compressed_public(&node_key),
    };
    let manifest = EnclaveInitializationManifestV1 {
        chain_id: [0x11; 32],
        genesis_hash: B256::repeat_byte(0x12),
        attestation_mode: AttestationMode::DcapRequired,
        node_id: node_id.clone(),
        initialization_challenge: [0x13; 32],
        node_host_noise_x25519: [0x14; 32],
        recipient_x25519: [0x15; 32],
        attestation_ed25519: [0x16; 32],
        noise_responder_x25519: [0x17; 32],
    };

    let encoded = node_id.encode_canonical().unwrap();
    assert_eq!(NodeIdV1::decode_canonical(&encoded).unwrap(), node_id);
    let signature = recoverable_signature(&node_key, manifest.authorization_hash().unwrap());
    assert!(manifest.verify_node_signature(&signature));

    let mut restarted = manifest.clone();
    restarted.initialization_challenge = [0x23; 32];
    assert_eq!(restarted.node_id, manifest.node_id);
    assert_eq!(
        restarted.node_id.node_id_hash(),
        manifest.node_id.node_id_hash()
    );
}

#[test]
fn validator_role_is_a_separate_two_party_binding_to_the_node_host() {
    let node_key =
        SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x51)).into()).unwrap();
    let validator_key =
        SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x52)).into()).unwrap();
    let validator_public = validator_key.verifying_key().to_encoded_point(false);
    let validator_hash = alloy_primitives::keccak256(&validator_public.as_bytes()[1..]);
    let validator = Address::from_slice(&validator_hash[12..]);
    let node_id = NodeIdV1 {
        reth_p2p_public: compressed_public(&node_key),
    };
    let binding = ValidatorNodeBindingV1 {
        chain_id: [0x61; 32],
        genesis_hash: B256::repeat_byte(0x62),
        validator: validator.into_array(),
        node_id_hash: node_id.node_id_hash().unwrap(),
    };
    let binding_hash = binding.binding_hash().unwrap();
    let validator_signature = recoverable_signature(&validator_key, binding_hash);
    let node_signature = recoverable_signature(&node_key, binding_hash);

    assert!(binding.verify_validator_signature(&validator_signature));
    assert!(binding.verify_node_signature(&node_signature));

    let mut another_validator = binding.clone();
    another_validator.validator[0] ^= 1;
    assert!(!another_validator.verify_validator_signature(&validator_signature));
    assert!(!another_validator.verify_node_signature(&node_signature));
}
