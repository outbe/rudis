use alloy_consensus::{Header, Sealable as _};
use alloy_eips::{BlockNumHash, BlockNumberOrTag};
use alloy_primitives::{keccak256, Address, BlockHash, BlockNumber, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, KECCAK_EMPTY};
use outbe_node::ocomp::finality::{PublicAccountProofV1, PublicStorageProofV1};
use outbe_node::tee_remote_session::{
    admit_anchored_remote_session_v1, admit_local_finalized_remote_session_v1,
    authorize_local_finalized_remote_session_v1,
    construct_local_finalized_replacement_authorization_v1,
    construct_local_finalized_replacement_authorization_with_view_v1,
    ExternalRegistryAdmissionError, LocalRegistryAdmissionError,
    TrustedFinalizedRegistryCheckpointV1,
};
use outbe_primitives::{
    header::{OutbeHeader, OutbePrimitives},
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapCollateralComponentV1,
        DcapCollateralKind, DcapEvidenceV1, EnclaveInitializationManifestV1,
        NodeHostAuthorizationWitnessV1, NodeIdV1, RegistrationIntentV1,
    },
};
use outbe_tee::{
    persist_replacement_candidate_submission, promote_replacement_candidate,
    AuthorizedEnclaveClient, FinalizedRegistryViewV1, NodeHostNoiseKey, RemoteEnclaveClient,
    RemoteSessionExpectationV1,
};
use outbe_tee_enclave::{
    initialization::InitializationState,
    keys::EnclaveKeys,
    seal::EnclaveBootConfig,
    transport::{serve_connection_with, SharedTributeOfferKey},
};
use outbe_teeregistry::TeeRegistry;
use reth_chainspec::{ChainInfo, ChainSpec, ChainSpecBuilder};
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    test_utils::{ExtendedAccount, MockEthProvider},
    BlockHashReader, BlockIdReader, BlockNumReader, HeaderProvider, ProviderResult,
    StateProviderBox, StateProviderFactory,
};
use std::{
    ops::RangeBounds,
    sync::{Arc, OnceLock, RwLock},
};

const CHAIN_ID: u64 = 31_337;
const CONSENSUS_TIMESTAMP: u64 = 1_700_000_000;

type TestProvider = MockEthProvider<OutbePrimitives, ChainSpec<OutbeHeader>>;

#[test]
fn current_finalized_registry_admits_role_neutral_nodes_and_rejects_superseded_state() {
    for (case, source_node, target_node) in [
        (0_u8, validator(0x11), validator(0x21)),
        (1_u8, full_node(0x31), full_node(0x41)),
    ] {
        let genesis_hash = B256::repeat_byte(0x31 + case);
        let source_witness = NodeHostAuthorizationWitnessV1 {
            chain_id: chain_id_word(CHAIN_ID),
            genesis_hash,
            attestation_mode: AttestationMode::DcapRequired,
            node_id: source_node.clone(),
            node_host_noise_x25519: [0x41; 32],
        };
        let source_hash = source_node.node_id_hash().unwrap();
        let target_hash = target_node.node_id_hash().unwrap();
        let source_host_hash = source_witness.authorization_hash().unwrap();

        let mut seed = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
        StorageHandle::enter(&mut seed, |storage| {
            let registry = TeeRegistry::new(storage);
            seed_binding(
                &registry,
                &source_node,
                SeedBindingIds {
                    enclave_id: B256::repeat_byte(0x42),
                    binding_id: B256::repeat_byte(0x43),
                    intent_hash: B256::repeat_byte(0x44),
                },
                1_700_000_500,
                [0x45; 32],
                source_host_hash,
            );
            seed_binding(
                &registry,
                &target_node,
                SeedBindingIds {
                    enclave_id: B256::repeat_byte(0x52),
                    binding_id: B256::repeat_byte(0x53),
                    intent_hash: B256::repeat_byte(0x54),
                },
                1_700_000_400,
                [0x55; 32],
                B256::repeat_byte(0x56),
            );
        });

        let chain_spec = ChainSpecBuilder::mainnet()
            .build()
            .map_header(OutbeHeader::new);
        let provider = MockEthProvider::<OutbePrimitives>::new().with_chain_spec(chain_spec);
        let mut account_storage = Vec::new();
        for ((address, slot), value) in seed.storage {
            assert_eq!(address, outbe_primitives::addresses::TEE_REGISTRY_ADDRESS);
            account_storage.push((B256::from(slot.to_be_bytes::<32>()), value));
        }
        provider.add_account(
            outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO)
                .with_bytecode(Bytes::from_static(&[0xef]))
                .extend_storage(account_storage),
        );
        let header = OutbeHeader::new(Header {
            number: 90,
            timestamp: CONSENSUS_TIMESTAMP,
            state_root: B256::repeat_byte(0x34),
            ..Default::default()
        });
        let block_hash = header.hash_slow();
        provider.add_header(block_hash, header);
        let next_header = OutbeHeader::new(Header {
            number: 91,
            timestamp: CONSENSUS_TIMESTAMP + 1,
            state_root: B256::repeat_byte(0x35),
            ..Default::default()
        });
        let next_block_hash = next_header.hash_slow();
        provider.add_header(next_block_hash, next_header);

        let finalized_source =
            FinalizedMockProvider::new(provider.clone(), BlockNumHash::new(90, block_hash));
        let empty_chain_spec = ChainSpecBuilder::mainnet()
            .build()
            .map_header(OutbeHeader::new);
        let empty_next_state =
            MockEthProvider::<OutbePrimitives>::new().with_chain_spec(empty_chain_spec);
        finalized_source.override_state(next_block_hash, empty_next_state);
        let admitted = admit_local_finalized_remote_session_v1(
            &finalized_source,
            CHAIN_ID,
            genesis_hash,
            RemoteSessionExpectationV1 {
                chain_id: chain_id_word(CHAIN_ID),
                genesis_hash,
                source_node_id_hash: source_hash,
                target_node_id_hash: target_hash,
            },
            &source_witness,
            &target_node,
        )
        .unwrap();

        assert_eq!(admitted.initiator_static_x25519(), [0x41; 32]);
        assert_eq!(admitted.responder_static_x25519(), [0x55; 32]);
        assert_eq!(admitted.deadline(), 1_700_000_400);
        assert_eq!(admitted.finalized_view().block_hash, block_hash);
        assert_eq!(
            admitted.finalized_view().consensus_timestamp,
            CONSENSUS_TIMESTAMP
        );
        let missing_candidate_dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            construct_local_finalized_replacement_authorization_v1(
                &finalized_source,
                CHAIN_ID,
                genesis_hash,
                missing_candidate_dir.path(),
                &source_node,
            ),
            Err(LocalRegistryAdmissionError::ReplacementAuthorization(_))
        ));

        finalized_source.set_finalized(BlockNumHash::new(91, next_block_hash));
        assert!(matches!(
            admit_local_finalized_remote_session_v1(
                &finalized_source,
                CHAIN_ID,
                genesis_hash,
                RemoteSessionExpectationV1 {
                    chain_id: chain_id_word(CHAIN_ID),
                    genesis_hash,
                    source_node_id_hash: source_hash,
                    target_node_id_hash: target_hash,
                },
                &source_witness,
                &target_node,
            ),
            Err(LocalRegistryAdmissionError::SourceBindingMissing)
        ));
        assert!(matches!(
            construct_local_finalized_replacement_authorization_v1(
                &finalized_source,
                CHAIN_ID,
                genesis_hash,
                missing_candidate_dir.path(),
                &source_node,
            ),
            Err(LocalRegistryAdmissionError::ReplacementBindingMissing)
        ));

        let unfinalized =
            FinalizedMockProvider::new(provider, BlockNumHash::new(92, B256::repeat_byte(0xF1)));
        assert!(matches!(
            admit_local_finalized_remote_session_v1(
                &unfinalized,
                CHAIN_ID,
                genesis_hash,
                RemoteSessionExpectationV1 {
                    chain_id: chain_id_word(CHAIN_ID),
                    genesis_hash,
                    source_node_id_hash: source_hash,
                    target_node_id_hash: target_hash,
                },
                &source_witness,
                &target_node,
            ),
            Err(LocalRegistryAdmissionError::FinalizedBlockUnavailable)
        ));
    }
}

#[test]
fn production_facade_installs_current_finalized_ticket_in_live_enclave() {
    let chain_id = outbe_primitives::chain::TESTNET_CHAIN_ID;
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("facade-enclave.sock");
    let endpoint = socket.to_str().unwrap().to_owned();
    let genesis_hash = B256::repeat_byte(0x91);
    let boot = Arc::new(EnclaveBootConfig::new(
        chain_id_word(chain_id),
        root.path().to_path_buf(),
        0,
    ));
    let keys = Arc::new(EnclaveKeys::new([0x92; 32], Some([0x92; 32])).unwrap());
    let initialization = Arc::new(
        InitializationState::production_with_synthetic_dcap_for_test(boot.clone(), &keys).unwrap(),
    );
    let challenge = match initialization.challenge_response(&keys).unwrap() {
        outbe_tee::protocol::EnclaveResponse::InitializationChallenge { challenge, .. } => {
            challenge
        }
        response => panic!("unexpected initialization response: {response:?}"),
    };
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let server_keys = keys.clone();
    let server_boot = boot.clone();
    let server_initialization = initialization.clone();
    let server = std::thread::spawn(move || {
        let offer_key: SharedTributeOfferKey = Arc::new(OnceLock::new());
        let mut connections = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let keys = server_keys.clone();
            let boot = server_boot.clone();
            let initialization = server_initialization.clone();
            let offer_key = offer_key.clone();
            connections.push(std::thread::spawn(move || {
                serve_connection_with(stream, &keys, &offer_key, Some(&boot), &initialization)
            }));
        }
        connections
            .into_iter()
            .map(|connection| connection.join().unwrap())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    });

    let target_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x61)).into())
            .unwrap();
    let target_node = validator_node_for_signer(&target_signer, 0x93);
    let target_owner = NodeHostNoiseKey::create_new(&root.path().join("target-owner.key")).unwrap();
    let target_manifest = outbe_primitives::tee_attestation_v1::EnclaveInitializationManifestV1 {
        chain_id: chain_id_word(chain_id),
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: target_node.clone(),
        initialization_challenge: challenge,
        node_host_noise_x25519: target_owner.public(),
        recipient_x25519: keys.tribute_offer_public(),
        attestation_ed25519: keys.attestation_pub(),
        noise_responder_x25519: keys.noise_public(),
    };
    let target_signature = recoverable_signature_for_hash(
        &target_signer,
        target_manifest.authorization_hash().unwrap(),
    );
    let mut target_client = AuthorizedEnclaveClient::initialize_endpoint(
        &endpoint,
        &target_manifest,
        &target_signature,
        &target_owner,
    )
    .unwrap();

    let source_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x62)).into())
            .unwrap();
    let source_node = validator_node_for_signer(&source_signer, 0x94);
    let source_host = NodeHostNoiseKey::create_new(&root.path().join("source-host.key")).unwrap();
    let source_witness = NodeHostAuthorizationWitnessV1 {
        chain_id: chain_id_word(chain_id),
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: source_node.clone(),
        node_host_noise_x25519: source_host.public(),
    };
    let source_hash = source_node.node_id_hash().unwrap();
    let target_hash = target_node.node_id_hash().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut seed = HashMapStorageProvider::new_with_chain_identity(chain_id, genesis_hash);
    StorageHandle::enter(&mut seed, |storage| {
        let registry = TeeRegistry::new(storage);
        seed_binding(
            &registry,
            &source_node,
            SeedBindingIds {
                enclave_id: B256::repeat_byte(0x95),
                binding_id: B256::repeat_byte(0x96),
                intent_hash: B256::repeat_byte(0x97),
            },
            now + 600,
            [0x98; 32],
            source_witness.authorization_hash().unwrap(),
        );
        seed_binding(
            &registry,
            &target_node,
            SeedBindingIds {
                enclave_id: target_manifest.enclave_id().unwrap(),
                binding_id: B256::repeat_byte(0x99),
                intent_hash: B256::repeat_byte(0x9A),
            },
            now + 500,
            target_manifest.noise_responder_x25519,
            target_manifest.node_host_authorization_hash().unwrap(),
        );
    });
    let chain_spec = ChainSpecBuilder::mainnet()
        .build()
        .map_header(OutbeHeader::new);
    let provider = MockEthProvider::<OutbePrimitives>::new().with_chain_spec(chain_spec);
    let account_storage = seed
        .storage
        .into_iter()
        .map(|((address, slot), value)| {
            assert_eq!(address, outbe_primitives::addresses::TEE_REGISTRY_ADDRESS);
            (B256::from(slot.to_be_bytes::<32>()), value)
        })
        .collect::<Vec<_>>();
    provider.add_account(
        outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
        ExtendedAccount::new(0, U256::ZERO)
            .with_bytecode(Bytes::from_static(&[0xef]))
            .extend_storage(account_storage),
    );
    let header = OutbeHeader::new(Header {
        number: 101,
        timestamp: now.saturating_sub(1),
        state_root: B256::repeat_byte(0x9B),
        ..Default::default()
    });
    let block_hash = header.hash_slow();
    provider.add_header(block_hash, header);
    let finalized = FinalizedMockProvider::new(provider, BlockNumHash::new(101, block_hash));

    let ticket = authorize_local_finalized_remote_session_v1(
        &finalized,
        &mut target_client,
        chain_id,
        genesis_hash,
        RemoteSessionExpectationV1 {
            chain_id: chain_id_word(chain_id),
            genesis_hash,
            source_node_id_hash: source_hash,
            target_node_id_hash: target_hash,
        },
        &source_witness,
        &target_node,
    )
    .unwrap();
    assert_eq!(ticket.finalized_block_hash(), block_hash);
    assert_eq!(ticket.deadline(), now + 500);
    let mut remote = RemoteEnclaveClient::connect_endpoint(&endpoint, &ticket, &source_host)
        .expect("current-finalized facade ticket must open the exact Noise IK session");
    let public_keys = remote.public_keys().unwrap();
    assert_eq!(public_keys.noise_static_pub, keys.noise_public());
    assert_eq!(public_keys.attestation_pub, keys.attestation_pub());
    drop(remote);
    drop(target_client);
    server.join().unwrap();
}

#[test]
fn current_finalized_registry_constructs_exact_replacement_authorization() {
    use ed25519_dalek::Signer as _;
    use std::os::unix::fs::DirBuilderExt as _;

    let root = tempfile::tempdir().unwrap();
    let node_data_dir = root.path().join("node-data");
    std::fs::create_dir(&node_data_dir).unwrap();
    let node_host_dir = node_data_dir.join(outbe_tee::node_host::NODE_HOST_DIRECTORY_V1);
    let mut directory = std::fs::DirBuilder::new();
    directory.mode(0o700).create(&node_host_dir).unwrap();
    let node_host = NodeHostNoiseKey::create_new(
        &node_host_dir.join(outbe_tee::node_host::NODE_HOST_NOISE_KEY_V1),
    )
    .unwrap();
    let node_signer =
        k256::ecdsa::SigningKey::from_bytes((&outbe_primitives::test_keys::secret(0x71)).into())
            .unwrap();
    let node_id = validator_node_for_signer(&node_signer, 0x72);
    let chain_id = 19_u64;
    let genesis_hash = B256::repeat_byte(0x73);
    let active = EnclaveInitializationManifestV1 {
        chain_id: chain_id_word(chain_id),
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: node_id.clone(),
        initialization_challenge: [0x74; 32],
        node_host_noise_x25519: node_host.public(),
        recipient_x25519: [0x75; 32],
        attestation_ed25519: [0x76; 32],
        noise_responder_x25519: [0x77; 32],
    };
    let candidate_signer =
        ed25519_dalek::SigningKey::from_bytes(&outbe_primitives::test_keys::secret(0x78));
    let candidate = EnclaveInitializationManifestV1 {
        initialization_challenge: [0x79; 32],
        recipient_x25519: [0x7A; 32],
        attestation_ed25519: candidate_signer.verifying_key().to_bytes(),
        noise_responder_x25519: [0x7B; 32],
        ..active.clone()
    };
    write_private_test_file(
        &node_host_dir.join(outbe_tee::node_host::NODE_HOST_MANIFEST_V1),
        &active.encode_canonical().unwrap(),
    );
    let candidate_manifest = candidate.encode_canonical().unwrap();
    let mut candidate_record = Vec::with_capacity(35 + candidate_manifest.len());
    candidate_record.push(1);
    candidate_record.extend_from_slice(active.authorization_hash().unwrap().as_slice());
    candidate_record.extend_from_slice(
        &u16::try_from(candidate_manifest.len())
            .unwrap()
            .to_be_bytes(),
    );
    candidate_record.extend_from_slice(&candidate_manifest);
    write_private_test_file(
        &node_host_dir.join(outbe_tee::node_host::NODE_HOST_REPLACEMENT_CANDIDATE_V1),
        &candidate_record,
    );

    let intent = RegistrationIntentV1 {
        chain_id: candidate.chain_id,
        genesis_hash: candidate.genesis_hash,
        operation: AttestationOperationV1::ReplaceEnclaveBinding,
        attestation_mode: AttestationMode::DcapRequired,
        policy_hash: B256::repeat_byte(0x7C),
        node_id: node_id.clone(),
        enclave_id: candidate.enclave_id().unwrap(),
        binding_id: B256::repeat_byte(0x7D),
        binding_version: 2,
        registration_version: 1,
        renewal_nonce: 0,
        transition_nonce: 0,
        requested_valid_until: 20_000,
        recipient_x25519: candidate.recipient_x25519,
        attestation_ed25519: candidate.attestation_ed25519,
        noise_responder_x25519: candidate.noise_responder_x25519,
        node_host_authorization_hash: candidate.node_host_authorization_hash().unwrap(),
    };
    let intent_hash = intent.intent_hash().unwrap();
    let node_signature = recoverable_signature_for_hash(&node_signer, intent_hash);
    let enclave_signature = candidate_signer.sign(intent_hash.as_slice()).to_bytes();
    let evidence = AttestationEvidenceV1::Dcap(DcapEvidenceV1 {
        intent: intent.clone(),
        quote: vec![0x7E],
        components: (1_u8..=8)
            .map(|kind| DcapCollateralComponentV1 {
                kind: DcapCollateralKind::try_from(kind).unwrap(),
                bytes: vec![kind],
            })
            .collect(),
        transition_key_ready_proof: None,
    });
    persist_replacement_candidate_submission(
        &node_data_dir,
        &evidence,
        &node_signature,
        &enclave_signature,
    )
    .unwrap();

    let mut seed = HashMapStorageProvider::new_with_chain_identity(chain_id, genesis_hash);
    StorageHandle::enter(&mut seed, |storage| {
        let registry = TeeRegistry::new(storage);
        seed_binding(
            &registry,
            &node_id,
            SeedBindingIds {
                enclave_id: intent.enclave_id,
                binding_id: intent.binding_id,
                intent_hash,
            },
            intent.requested_valid_until,
            intent.noise_responder_x25519,
            intent.node_host_authorization_hash,
        );
        let node_hash = node_id.node_id_hash().unwrap();
        registry
            .v1_node_binding_version
            .write(&node_hash, intent.binding_version)
            .unwrap();
        registry
            .v1_node_registration_version
            .write(&node_hash, intent.registration_version)
            .unwrap();
        registry
            .v1_node_recipient_x25519
            .write(&node_hash, B256::from(intent.recipient_x25519))
            .unwrap();
        registry
            .v1_node_attestation_ed25519
            .write(&node_hash, B256::from(intent.attestation_ed25519))
            .unwrap();
    });
    let chain_spec = ChainSpecBuilder::mainnet()
        .build()
        .map_header(OutbeHeader::new);
    let provider = MockEthProvider::<OutbePrimitives>::new().with_chain_spec(chain_spec);
    let account_storage = seed
        .storage
        .into_iter()
        .map(|((address, slot), value)| {
            assert_eq!(address, outbe_primitives::addresses::TEE_REGISTRY_ADDRESS);
            (B256::from(slot.to_be_bytes::<32>()), value)
        })
        .collect::<Vec<_>>();
    provider.add_account(
        outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
        ExtendedAccount::new(0, U256::ZERO)
            .with_bytecode(Bytes::from_static(&[0xef]))
            .extend_storage(account_storage),
    );
    let header = OutbeHeader::new(Header {
        number: 90,
        timestamp: 19_000,
        state_root: B256::repeat_byte(0x7F),
        ..Default::default()
    });
    let block_hash = header.hash_slow();
    provider.add_header(block_hash, header);
    let finalized = FinalizedMockProvider::new(provider, BlockNumHash::new(90, block_hash));

    let authorized = construct_local_finalized_replacement_authorization_with_view_v1(
        &finalized,
        chain_id,
        genesis_hash,
        &node_data_dir,
        &node_id,
    )
    .unwrap();
    assert_eq!(authorized.view.block_number, 90);
    assert_eq!(authorized.view.block_hash, block_hash);
    assert_eq!(authorized.successor_activation_height, None);
    let authorization = construct_local_finalized_replacement_authorization_v1(
        &finalized,
        chain_id,
        genesis_hash,
        &node_data_dir,
        &node_id,
    )
    .unwrap();
    assert_eq!(authorization, authorized.authorization);
    assert_eq!(
        promote_replacement_candidate(&node_data_dir, &authorization).unwrap(),
        candidate
    );
}

#[test]
fn external_light_client_checkpoint_authenticates_the_exact_registry_storage_proof() {
    let genesis_hash = B256::repeat_byte(0x61);
    let source_node = validator(0x12);
    let target_node = validator(0x22);
    let source_witness = NodeHostAuthorizationWitnessV1 {
        chain_id: chain_id_word(CHAIN_ID),
        genesis_hash,
        attestation_mode: AttestationMode::DcapRequired,
        node_id: source_node.clone(),
        node_host_noise_x25519: [0x71; 32],
    };
    let source_hash = source_node.node_id_hash().unwrap();
    let target_hash = target_node.node_id_hash().unwrap();
    let mut seed = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, genesis_hash);
    let slot_keys = StorageHandle::enter(&mut seed, |storage| {
        let registry = TeeRegistry::new(storage);
        seed_binding(
            &registry,
            &source_node,
            SeedBindingIds {
                enclave_id: B256::repeat_byte(0x72),
                binding_id: B256::repeat_byte(0x73),
                intent_hash: B256::repeat_byte(0x74),
            },
            1_700_000_600,
            [0x75; 32],
            source_witness.authorization_hash().unwrap(),
        );
        seed_binding(
            &registry,
            &target_node,
            SeedBindingIds {
                enclave_id: B256::repeat_byte(0x82),
                binding_id: B256::repeat_byte(0x83),
                intent_hash: B256::repeat_byte(0x84),
            },
            1_700_000_450,
            [0x85; 32],
            B256::repeat_byte(0x86),
        );
        let mut slots = registry
            .node_enclave_binding_storage_slots_v1(&source_node)
            .unwrap();
        slots.extend(
            registry
                .node_enclave_binding_storage_slots_v1(&target_node)
                .unwrap(),
        );
        slots.sort_unstable();
        slots.dedup();
        slots
    });
    let words = seed
        .storage
        .into_iter()
        .map(|((address, slot), value)| {
            assert_eq!(address, outbe_primitives::addresses::TEE_REGISTRY_ADDRESS);
            (B256::from(slot.to_be_bytes::<32>()), value)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let requested_words = slot_keys
        .iter()
        .map(|slot| {
            (
                U256::from_be_bytes(slot.0),
                words.get(slot).copied().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let (storage_root, storage_nodes) = storage_trie(&requested_words);
    let trie_account = TrieAccount {
        nonce: 0,
        balance: U256::ZERO,
        storage_root,
        code_hash: KECCAK_EMPTY,
    };
    let (state_root, account_nodes) = account_trie(&[(
        outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
        trie_account,
    )]);
    let proof = PublicAccountProofV1 {
        address: outbe_primitives::addresses::TEE_REGISTRY_ADDRESS,
        nonce: 0,
        balance: U256::ZERO,
        storage_root,
        code_hash: KECCAK_EMPTY,
        account_nodes: account_nodes[&outbe_primitives::addresses::TEE_REGISTRY_ADDRESS].clone(),
        storage_proofs: slot_keys
            .iter()
            .zip(storage_nodes)
            .map(|(key, nodes)| PublicStorageProofV1 {
                key: *key,
                value: words.get(key).copied().unwrap_or_default(),
                nodes,
            })
            .collect(),
    };
    let view = FinalizedRegistryViewV1 {
        chain_id: chain_id_word(CHAIN_ID),
        genesis_hash,
        block_number: 91,
        block_hash: B256::repeat_byte(0x63),
        state_root,
        consensus_timestamp: CONSENSUS_TIMESTAMP,
    };
    let checkpoint = TrustedFinalizedRegistryCheckpointV1::from_light_client(view).unwrap();
    let expected = RemoteSessionExpectationV1 {
        chain_id: chain_id_word(CHAIN_ID),
        genesis_hash,
        source_node_id_hash: source_hash,
        target_node_id_hash: target_hash,
    };
    let admitted = admit_anchored_remote_session_v1(
        checkpoint,
        &proof,
        expected,
        &source_witness,
        &target_node,
    )
    .unwrap();

    assert_eq!(admitted.initiator_static_x25519(), [0x71; 32]);
    assert_eq!(admitted.responder_static_x25519(), [0x85; 32]);
    assert_eq!(admitted.deadline(), 1_700_000_450);
    assert_eq!(admitted.finalized_view(), view);

    let mut tampered = proof;
    let nonzero = tampered
        .storage_proofs
        .iter_mut()
        .find(|entry| !entry.value.is_zero())
        .expect("real Registry proof fixture must contain a nonzero word");
    nonzero.value = nonzero.value.checked_add(U256::from(1)).unwrap();
    assert!(matches!(
        admit_anchored_remote_session_v1(
            checkpoint,
            &tampered,
            expected,
            &source_witness,
            &target_node,
        ),
        Err(ExternalRegistryAdmissionError::Proof(_))
    ));
}

fn validator(seed: u8) -> NodeIdV1 {
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

fn validator_node_for_signer(signer: &k256::ecdsa::SigningKey, _bls_seed: u8) -> NodeIdV1 {
    NodeIdV1 {
        reth_p2p_public: signer
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
    }
}

fn recoverable_signature_for_hash(signer: &k256::ecdsa::SigningKey, hash: B256) -> [u8; 65] {
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;

    let (signature, recovery): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        signer.sign_prehash(hash.as_slice()).unwrap();
    let mut bytes = [0_u8; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_slice());
    bytes[64] = recovery.to_byte();
    bytes
}

fn write_private_test_file(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn full_node(seed: u8) -> NodeIdV1 {
    let signing = k256::ecdsa::SigningKey::from_bytes(
        (&outbe_primitives::test_keys::secret((seed) as u64)).into(),
    )
    .unwrap();
    let reth_p2p_public = signing
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    NodeIdV1 { reth_p2p_public }
}

struct SeedBindingIds {
    enclave_id: B256,
    binding_id: B256,
    intent_hash: B256,
}

fn seed_binding(
    registry: &TeeRegistry<'_>,
    node: &NodeIdV1,
    ids: SeedBindingIds,
    valid_until: u64,
    noise_responder_x25519: [u8; 32],
    node_host_authorization_hash: B256,
) {
    let SeedBindingIds {
        enclave_id,
        binding_id,
        intent_hash,
    } = ids;
    let node_hash = node.node_id_hash().unwrap();
    registry
        .v1_node_enclave_id
        .write(&node_hash, enclave_id)
        .unwrap();
    registry
        .v1_node_binding_id
        .write(&node_hash, binding_id)
        .unwrap();
    registry
        .v1_node_intent_hash
        .write(&node_hash, intent_hash)
        .unwrap();
    registry
        .v1_node_valid_until
        .write(&node_hash, valid_until)
        .unwrap();
    registry
        .v1_node_noise_responder_x25519
        .write(&node_hash, B256::from(noise_responder_x25519))
        .unwrap();
    registry
        .v1_node_host_authorization_hash
        .write(&node_hash, node_host_authorization_hash)
        .unwrap();
}

fn chain_id_word(chain_id: u64) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&chain_id.to_be_bytes());
    word
}

struct FinalizedMockProvider {
    inner: TestProvider,
    finalized: Arc<RwLock<BlockNumHash>>,
    historical_states: Arc<RwLock<std::collections::BTreeMap<B256, TestProvider>>>,
}

impl FinalizedMockProvider {
    fn new(inner: TestProvider, finalized: BlockNumHash) -> Self {
        Self {
            inner,
            finalized: Arc::new(RwLock::new(finalized)),
            historical_states: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        }
    }

    fn set_finalized(&self, finalized: BlockNumHash) {
        *self.finalized.write().unwrap() = finalized;
    }

    fn override_state(&self, block_hash: B256, state: TestProvider) {
        self.historical_states
            .write()
            .unwrap()
            .insert(block_hash, state);
    }
}

impl BlockHashReader for FinalizedMockProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        self.inner.canonical_hashes_range(start, end)
    }
}

impl BlockNumReader for FinalizedMockProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        self.inner.chain_info()
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        self.inner.best_block_number()
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        self.inner.last_block_number()
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        self.inner.block_number(hash)
    }
}

impl BlockIdReader for FinalizedMockProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(None)
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(*self.finalized.read().unwrap()))
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(*self.finalized.read().unwrap()))
    }
}

impl HeaderProvider for FinalizedMockProvider {
    type Header = OutbeHeader;

    fn header(&self, block_hash: BlockHash) -> ProviderResult<Option<Self::Header>> {
        self.inner.header(block_hash)
    }

    fn header_by_number(&self, number: u64) -> ProviderResult<Option<Self::Header>> {
        self.inner.header_by_number(number)
    }

    fn headers_range(
        &self,
        range: impl RangeBounds<BlockNumber>,
    ) -> ProviderResult<Vec<Self::Header>> {
        self.inner.headers_range(range)
    }

    fn sealed_header(
        &self,
        number: BlockNumber,
    ) -> ProviderResult<Option<SealedHeader<Self::Header>>> {
        self.inner.sealed_header(number)
    }

    fn sealed_headers_while(
        &self,
        range: impl RangeBounds<BlockNumber>,
        predicate: impl FnMut(&SealedHeader<Self::Header>) -> bool,
    ) -> ProviderResult<Vec<SealedHeader<Self::Header>>> {
        self.inner.sealed_headers_while(range, predicate)
    }
}

impl StateProviderFactory for FinalizedMockProvider {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        self.inner.latest()
    }

    fn state_by_block_number_or_tag(
        &self,
        number_or_tag: BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        self.inner.state_by_block_number_or_tag(number_or_tag)
    }

    fn history_by_block_number(&self, block: BlockNumber) -> ProviderResult<StateProviderBox> {
        self.inner.history_by_block_number(block)
    }

    fn history_by_block_hash(&self, block: BlockHash) -> ProviderResult<StateProviderBox> {
        self.inner.history_by_block_hash(block)
    }

    fn state_by_block_hash(&self, block: BlockHash) -> ProviderResult<StateProviderBox> {
        if let Some(state) = self.historical_states.read().unwrap().get(&block).cloned() {
            return Ok(Box::new(state));
        }
        self.inner.state_by_block_hash(block)
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.inner.pending()
    }

    fn pending_state_by_hash(&self, block_hash: B256) -> ProviderResult<Option<StateProviderBox>> {
        self.inner.pending_state_by_hash(block_hash)
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        self.inner.maybe_pending()
    }
}

fn storage_trie(slots: &[(U256, U256)]) -> (B256, Vec<Vec<Bytes>>) {
    let targets = slots
        .iter()
        .map(|(slot, _)| Nibbles::unpack(keccak256(slot.to_be_bytes::<32>())))
        .collect::<Vec<_>>();
    let mut leaves = std::collections::BTreeMap::new();
    for ((_, word), target) in slots.iter().zip(&targets) {
        if !word.is_zero() {
            leaves.insert(*target, alloy_rlp::encode_fixed_size(word).to_vec());
        }
    }
    let mut builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets.clone()));
    for (path, value) in leaves {
        builder.add_leaf(path, &value);
    }
    let root = builder.root();
    let retained = builder.take_proof_nodes();
    let proofs = targets
        .iter()
        .map(|target| {
            retained
                .matching_nodes_sorted(target)
                .into_iter()
                .map(|(_, node)| node)
                .collect()
        })
        .collect();
    (root, proofs)
}

fn account_trie(
    accounts: &[(Address, TrieAccount)],
) -> (B256, std::collections::BTreeMap<Address, Vec<Bytes>>) {
    let targets = accounts
        .iter()
        .map(|(address, _)| (*address, Nibbles::unpack(keccak256(address))))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut builder = HashBuilder::default()
        .with_proof_retainer(ProofRetainer::from_iter(targets.values().copied()));
    let mut leaves = accounts
        .iter()
        .map(|(address, account)| (targets[address], alloy_rlp::encode(*account)))
        .collect::<Vec<_>>();
    leaves.sort_by_key(|(path, _)| *path);
    for (path, value) in leaves {
        builder.add_leaf(path, &value);
    }
    let root = builder.root();
    let retained = builder.take_proof_nodes();
    let proofs = targets
        .into_iter()
        .map(|(address, target)| {
            (
                address,
                retained
                    .matching_nodes_sorted(&target)
                    .into_iter()
                    .map(|(_, node)| node)
                    .collect(),
            )
        })
        .collect();
    (root, proofs)
}
