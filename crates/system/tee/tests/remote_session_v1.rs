use alloy_primitives::B256;
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, NodeHostAuthorizationWitnessV1, NodeIdV1,
};
use outbe_tee::{
    admit_remote_session_v1, admit_rpc_trusted_remote_session_v1, FinalizedRegistryBindingV1,
    FinalizedRegistryViewV1, RemoteSessionAdmissionError, RemoteSessionExpectationV1,
};

fn node(seed: u8) -> NodeIdV1 {
    let signing = k256::ecdsa::SigningKey::from_bytes(
        (&outbe_primitives::test_keys::secret((seed) as u64)).into(),
    )
    .unwrap();
    NodeIdV1 {
        reth_p2p_public: signing
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
    }
}

#[test]
fn exact_finalized_source_and_target_admit_one_bounded_session() {
    let source_node = node(0x11);
    let target_node = node(0x21);
    let chain_id = [0x31; 32];
    let genesis_hash = B256::repeat_byte(0x32);
    let view = FinalizedRegistryViewV1 {
        chain_id,
        genesis_hash,
        block_number: 90,
        block_hash: B256::repeat_byte(0x33),
        state_root: B256::repeat_byte(0x34),
        consensus_timestamp: 1_000,
    };
    let source_witness = NodeHostAuthorizationWitnessV1 {
        chain_id,
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: source_node.clone(),
        node_host_noise_x25519: [0x41; 32],
    };
    let source = FinalizedRegistryBindingV1 {
        view,
        node_id_hash: source_node.node_id_hash().unwrap(),
        enclave_id: B256::repeat_byte(0x42),
        binding_id: B256::repeat_byte(0x43),
        intent_hash: B256::repeat_byte(0x44),
        valid_until: 1_500,
        noise_responder_x25519: [0x45; 32],
        node_host_authorization_hash: source_witness.authorization_hash().unwrap(),
    };
    let target = FinalizedRegistryBindingV1 {
        view,
        node_id_hash: target_node.node_id_hash().unwrap(),
        enclave_id: B256::repeat_byte(0x52),
        binding_id: B256::repeat_byte(0x53),
        intent_hash: B256::repeat_byte(0x54),
        valid_until: 1_400,
        noise_responder_x25519: [0x55; 32],
        node_host_authorization_hash: B256::repeat_byte(0x56),
    };

    let admitted = admit_remote_session_v1(
        RemoteSessionExpectationV1 {
            chain_id,
            genesis_hash,
            source_node_id_hash: source.node_id_hash,
            target_node_id_hash: target.node_id_hash,
        },
        &source_witness,
        source,
        target,
    )
    .unwrap();

    assert_eq!(admitted.initiator_static_x25519(), [0x41; 32]);
    assert_eq!(admitted.responder_static_x25519(), [0x55; 32]);
    assert_eq!(admitted.deadline(), 1_400);
    assert_eq!(admitted.finalized_view(), view);
}

#[test]
fn rpc_trust_is_an_explicit_non_finality_verified_result_type() {
    let source_node = node(0x61);
    let target_node = node(0x71);
    let chain_id = [0x81; 32];
    let genesis_hash = B256::repeat_byte(0x82);
    let view = FinalizedRegistryViewV1 {
        chain_id,
        genesis_hash,
        block_number: 100,
        block_hash: B256::repeat_byte(0x83),
        state_root: B256::repeat_byte(0x84),
        consensus_timestamp: 2_000,
    };
    let source_witness = NodeHostAuthorizationWitnessV1 {
        chain_id,
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: source_node.clone(),
        node_host_noise_x25519: [0x91; 32],
    };
    let source = FinalizedRegistryBindingV1 {
        view,
        node_id_hash: source_node.node_id_hash().unwrap(),
        enclave_id: B256::repeat_byte(0x92),
        binding_id: B256::repeat_byte(0x93),
        intent_hash: B256::repeat_byte(0x94),
        valid_until: 2_500,
        noise_responder_x25519: [0x95; 32],
        node_host_authorization_hash: source_witness.authorization_hash().unwrap(),
    };
    let target = FinalizedRegistryBindingV1 {
        view,
        node_id_hash: target_node.node_id_hash().unwrap(),
        enclave_id: B256::repeat_byte(0xA2),
        binding_id: B256::repeat_byte(0xA3),
        intent_hash: B256::repeat_byte(0xA4),
        valid_until: 2_400,
        noise_responder_x25519: [0xA5; 32],
        node_host_authorization_hash: B256::repeat_byte(0xA6),
    };
    let rpc_trusted = admit_rpc_trusted_remote_session_v1(
        RemoteSessionExpectationV1 {
            chain_id,
            genesis_hash,
            source_node_id_hash: source.node_id_hash,
            target_node_id_hash: target.node_id_hash,
        },
        &source_witness,
        source,
        target,
    )
    .unwrap();

    assert_eq!(rpc_trusted.initiator_static_x25519(), [0x91; 32]);
    assert_eq!(rpc_trusted.responder_static_x25519(), [0xA5; 32]);
    assert_eq!(rpc_trusted.deadline(), 2_400);
    assert_eq!(rpc_trusted.rpc_claimed_view(), view);
}

#[test]
fn stale_mixed_chain_genesis_and_nodehost_key_substitutions_reject() {
    let (expected, source_witness, source, target) = admission_fixture();

    let mut stale_source = source;
    stale_source.valid_until = source.view.consensus_timestamp;
    assert_eq!(
        admit_remote_session_v1(expected, &source_witness, stale_source, target),
        Err(RemoteSessionAdmissionError::SourceExpired)
    );
    let mut stale_target = target;
    stale_target.valid_until = target.view.consensus_timestamp;
    assert_eq!(
        admit_remote_session_v1(expected, &source_witness, source, stale_target),
        Err(RemoteSessionAdmissionError::TargetExpired)
    );

    let mut mixed = target;
    mixed.view.block_hash = B256::repeat_byte(0xE1);
    assert_eq!(
        admit_remote_session_v1(expected, &source_witness, source, mixed),
        Err(RemoteSessionAdmissionError::MixedFinalizedViews)
    );

    let mut wrong_chain = expected;
    wrong_chain.chain_id = [0xE2; 32];
    assert_eq!(
        admit_remote_session_v1(wrong_chain, &source_witness, source, target),
        Err(RemoteSessionAdmissionError::WrongChain)
    );
    let mut wrong_genesis = expected;
    wrong_genesis.genesis_hash = B256::repeat_byte(0xE3);
    assert_eq!(
        admit_remote_session_v1(wrong_genesis, &source_witness, source, target),
        Err(RemoteSessionAdmissionError::WrongGenesis)
    );

    let mut wrong_nodehost = source_witness;
    wrong_nodehost.node_host_noise_x25519 = [0xE4; 32];
    assert_eq!(
        admit_remote_session_v1(expected, &wrong_nodehost, source, target),
        Err(RemoteSessionAdmissionError::WrongSourceWitness)
    );
}

fn admission_fixture() -> (
    RemoteSessionExpectationV1,
    NodeHostAuthorizationWitnessV1,
    FinalizedRegistryBindingV1,
    FinalizedRegistryBindingV1,
) {
    let source_node = node(0xB1);
    let target_node = node(0xC1);
    let chain_id = [0xD1; 32];
    let genesis_hash = B256::repeat_byte(0xD2);
    let view = FinalizedRegistryViewV1 {
        chain_id,
        genesis_hash,
        block_number: 110,
        block_hash: B256::repeat_byte(0xD3),
        state_root: B256::repeat_byte(0xD4),
        consensus_timestamp: 3_000,
    };
    let source_witness = NodeHostAuthorizationWitnessV1 {
        chain_id,
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: source_node.clone(),
        node_host_noise_x25519: [0xD5; 32],
    };
    let source = FinalizedRegistryBindingV1 {
        view,
        node_id_hash: source_node.node_id_hash().unwrap(),
        enclave_id: B256::repeat_byte(0xD6),
        binding_id: B256::repeat_byte(0xD7),
        intent_hash: B256::repeat_byte(0xD8),
        valid_until: 3_500,
        noise_responder_x25519: [0xD9; 32],
        node_host_authorization_hash: source_witness.authorization_hash().unwrap(),
    };
    let target = FinalizedRegistryBindingV1 {
        view,
        node_id_hash: target_node.node_id_hash().unwrap(),
        enclave_id: B256::repeat_byte(0xDA),
        binding_id: B256::repeat_byte(0xDB),
        intent_hash: B256::repeat_byte(0xDC),
        valid_until: 3_400,
        noise_responder_x25519: [0xDD; 32],
        node_host_authorization_hash: B256::repeat_byte(0xDE),
    };
    (
        RemoteSessionExpectationV1 {
            chain_id,
            genesis_hash,
            source_node_id_hash: source.node_id_hash,
            target_node_id_hash: target.node_id_hash,
        },
        source_witness,
        source,
        target,
    )
}
