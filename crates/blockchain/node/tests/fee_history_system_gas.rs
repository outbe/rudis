//! RPC-level regression for Outbe system-tx gas visibility in `eth_feeHistory`.
//!
//! The executor has a separate internal execution budget for Outbe system
//! calls. Public Ethereum RPC gas accounting must expose only the committed
//! header gas actually used by the visible transaction envelopes.

use std::{path::PathBuf, process::Command, sync::Arc};

use alloy_consensus::Transaction as _;
use alloy_genesis::Genesis;
use alloy_primitives::{keccak256, Address, Bytes, B256};
use alloy_provider::{Provider, ProviderBuilder};
use eyre::{bail, Context};
use outbe_chain_constants::GenesisProtocolParametersV1;
use outbe_compressed_entities::{
    CandidateCacheLimits, CeMdbx, CompressedTreeService, EnvironmentIdentity, FinalizedMarker,
    ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
};
use outbe_evm::OutbeEvmSigner;
use outbe_metadosis::test_support::ForkInstallScenario;
use outbe_node::OutbeNode;
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_offchain_storage::MemoryStorage;
use outbe_primitives::{
    addresses::REWARDS_ADDRESS,
    chain::DEVNET_CHAIN_ID,
    consensus::{ConsensusExecutionBridge, DkgBoundaryArtifact, ReshareResult},
    reshare_artifact::{
        encode_outbe_block_artifacts, ConsensusHeaderArtifact, OutbeBlockArtifacts,
    },
    system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT,
    tee_test_utils::{
        gramine_direct_bootstrap_v2, gramine_direct_policy_v1, tee_attestation_v1_extra_field,
        DevValidatorV1,
    },
    OutbeHeader, OutbePayloadAttributes,
};
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use reth_e2e_test_utils::node::NodeTestContext;
use reth_node_api::TreeConfig;
use reth_node_builder::{EngineNodeLauncher, Node as _, NodeBuilder, NodeConfig, NodeHandle};
use reth_node_core::args::{DiscoveryArgs, NetworkArgs, RpcServerArgs};
use reth_payload_primitives::BuiltPayload as _;
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_provider::providers::BlockchainProvider;
use reth_rpc_server_types::RpcModuleSelection;
use reth_tasks::Runtime;

const GENESIS_VALIDATOR_PUBKEY: &str =
    "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
const GENESIS_VALIDATOR_RADICLE_NODE_ID: &str =
    "2121212121212121212121212121212121212121212121212121212121212121";

/// Block-1 timestamp the reth payload harness generates: it starts at the
/// genesis timestamp (`0x65f1b057`) and increments by one per block, so the
/// first post-genesis block is `genesis + 1`. The OST3 lease is anchored to it.
const BLOCK_ONE_TIMESTAMP_SECS: u64 = 0x65f1_b057 + 1;

fn workspace_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../..");
    path.canonicalize().expect("workspace root should exist")
}

fn seed_single_validator_genesis(signer: &OutbeEvmSigner) -> eyre::Result<Genesis> {
    let tmp = tempfile::TempDir::new().wrap_err("create temp genesis dir")?;
    let genesis_path = tmp.path().join("genesis.json");
    let seed_path = tmp.path().join("seed.json");
    let validators_path = tmp.path().join("validators.json");
    let output_path = tmp.path().join("out.json");

    std::fs::write(
        &genesis_path,
        format!(
            r#"{{
              "config": {{ "chainId": {DEVNET_CHAIN_ID}, "epochLengthBlocks": 120 }},
              "timestamp": "0x65f1b057",
              "gasLimit": "0x1c9c380",
              "difficulty": "0x0",
              "alloc": {{}}
            }}"#
        ),
    )?;
    // Seed the COEN/840 oracle pair + a 1.0 rate (scale 1e6) so the begin-block
    // NOD/GEM/INTEX floor-price promotion reads a registered pair instead of
    // reverting "pair not registered" (which would abort pre-execution and leave
    // every payload empty). Production genesis always seeds oracle pairs; the
    // oracle itself is left uninitialized so its own begin-block tally/s-curve
    // stays inert - the same minimal state the executor tests use.
    std::fs::write(
        &seed_path,
        r#"{
          "oracle": {
            "config": { "initialized": false },
            "pairs": [
              { "base": "COEN", "quote": "840", "initial_rate": "1000000" }
            ]
          }
        }"#,
    )?;
    std::fs::write(
        &validators_path,
        format!(
            r#"[{{ "address": "0x{addr:x}", "public_key": "{GENESIS_VALIDATOR_PUBKEY}", "radicle_node_id": "{GENESIS_VALIDATOR_RADICLE_NODE_ID}" }}]"#,
            addr = signer.address()
        ),
    )?;

    let status = Command::new("python3")
        .arg(workspace_root().join("scripts").join("seed_genesis.py"))
        .arg("--genesis")
        .arg(&genesis_path)
        .arg("--seed")
        .arg(&seed_path)
        .arg("--validators")
        .arg(&validators_path)
        .arg("--output")
        .arg(&output_path)
        .status()
        .wrap_err("run scripts/seed_genesis.py")?;

    if !status.success() {
        bail!("scripts/seed_genesis.py exited with {status}");
    }

    let raw = std::fs::read_to_string(&output_path).wrap_err("read seeded genesis")?;
    let genesis: serde_json::Value =
        serde_json::from_str(&raw).wrap_err("parse seeded genesis JSON")?;
    GenesisProtocolParametersV1::from_genesis(&genesis)
        .wrap_err("validate test genesis protocol parameters")?;
    serde_json::from_value(genesis).wrap_err("decode seeded genesis")
}

fn chain_spec_with_genesis(genesis: Genesis) -> Arc<ChainSpec<OutbeHeader>> {
    Arc::new(
        ChainSpecBuilder::default()
            .chain(Chain::from_id(DEVNET_CHAIN_ID))
            .genesis(genesis)
            .cancun_activated()
            .build()
            .map_header(OutbeHeader::new),
    )
}

fn genesis_validator_pubkey() -> [u8; 48] {
    hex::decode(GENESIS_VALIDATOR_PUBKEY)
        .expect("test validator pubkey should be valid hex")
        .try_into()
        .expect("test validator pubkey should be 48 bytes")
}

fn boundary_active_set_hash(addresses: &[Address]) -> B256 {
    let mut bytes = Vec::with_capacity(8 + addresses.len() * 20);
    bytes.extend_from_slice(&(addresses.len() as u64).to_be_bytes());
    for address in addresses {
        bytes.extend_from_slice(address.as_slice());
    }
    keccak256(bytes)
}

fn boundary_for_single_validator(proposer: Address) -> DkgBoundaryArtifact {
    let new_active_set = vec![proposer];
    let vrf_group_public_key_bytes = vec![0x42u8; 96];
    let snapshot = outbe_validatorset::CommitteeSnapshot {
        committee: vec![outbe_validatorset::CommitteeEntry {
            address: proposer,
            consensus_pubkey: genesis_validator_pubkey(),
        }],
        vrf_material_version: 0,
        vrf_group_public_key_bytes: vrf_group_public_key_bytes.clone(),
        vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
    };
    DkgBoundaryArtifact {
        epoch: 0,
        dkg_cycle: 0,
        freeze_height: 0,
        planned_activation_height: 1,
        target_set_hash: B256::ZERO,
        vrf_material_version: 0,
        vrf_group_public_key: keccak256(&vrf_group_public_key_bytes),
        vrf_group_public_key_bytes: Bytes::from(vrf_group_public_key_bytes),
        committee_set_hash: outbe_validatorset::committee_set_hash_v2(0, &snapshot),
        is_validator_set_change: true,
        outcome: Bytes::new(),
        is_full_dkg: false,
        tee_recipient_pubkeys: Vec::new(),
        tee_expired_target_exclusions: Vec::new(),
        tee_expired_target_exclusions_hash: B256::ZERO,
        reshare: ReshareResult {
            active_set_hash: boundary_active_set_hash(&new_active_set),
            new_active_set,
        },
    }
}

fn payload_attributes(timestamp: u64, proposer: Address) -> OutbePayloadAttributes {
    let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
        execution_summary: None,
        consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(
            boundary_for_single_validator(proposer),
        )),
        timestamp_millis_part: 0,
        late_finalize_credits: None,
        compressed_entities_root: None,
    })
    .expect("Outbe boundary artifacts should encode");
    OutbePayloadAttributes::new(
        REWARDS_ADDRESS,
        timestamp.saturating_mul(1000),
        B256::ZERO,
        Some(B256::ZERO),
        extra_data,
        None,
        Some(proposer),
    )
}

#[tokio::test]
async fn gas_14_rpc_fee_history_uses_visible_system_gas() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let signer = Arc::new(OutbeEvmSigner::from_secret_bytes(
        outbe_primitives::test_keys::secret((1u8) as u64),
    )?);
    let proposer = signer.address();

    // Block 1 now mandates the canonical OST3 TEE-bootstrap system tx. The genesis
    // config must carry the GramineDirectDev `teeAttestationV1` activation manifest
    // (the ChainSpec authority the executor checks the payload's policy against),
    // and the proposer must inject the bootstrap payload via the consensus bridge.
    // Adding the config field does not change the genesis block hash, so the policy
    // can bind the hash computed from the seeded genesis alloc.
    let mut genesis = seed_single_validator_genesis(&signer)?;
    let genesis_hash = chain_spec_with_genesis(genesis.clone()).genesis_hash();
    let tee_policy = gramine_direct_policy_v1(DEVNET_CHAIN_ID, genesis_hash)
        .expect("GramineDirectDev devnet TEE policy is canonical");
    genesis.config.extra_fields.insert(
        "teeAttestationV1".to_owned(),
        tee_attestation_v1_extra_field(&tee_policy)
            .expect("GramineDirectDev TEE activation manifest is canonical"),
    );
    let chain_spec = chain_spec_with_genesis(genesis);
    let ce_directory = tempfile::tempdir()?;

    // The OST3 payload binds the epoch-0 committee snapshot that the block-1
    // BoundaryOutcome writes before TeeBootstrap runs - the same hash the boundary
    // artifact carries - and is signed by the single genesis validator.
    let bridge = ConsensusExecutionBridge::new();
    bridge.set_pending_tee_bootstrap(
        gramine_direct_bootstrap_v2(
            tee_policy,
            boundary_for_single_validator(proposer).committee_set_hash,
            1,
            BLOCK_ONE_TIMESTAMP_SECS + 3_600,
            &[DevValidatorV1 {
                evm_secret: outbe_primitives::test_keys::secret(1),
                bls_minpk_public: genesis_validator_pubkey(),
            }],
        )
        .expect("GramineDirectDev OST3 bootstrap payload is canonical"),
    );
    let ocomp_fork_install = Arc::new(
        ForkInstallScenario::measurement_at(1, DEVNET_CHAIN_ID, genesis_hash)
            .expect("fresh-devnet OCOMP install fixture is canonical")
            .with_founder_validators(&[(proposer, genesis_validator_pubkey())])
            .expect("OCOMP founder registration matches the seeded validator")
            .into_install(),
    );
    let ce_db = CeMdbx::open(
        ce_directory.path(),
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: DEVNET_CHAIN_ID,
            genesis_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: outbe_compressed_entities::CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        },
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: genesis_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
        },
    )?;
    let compressed_tree_service = Arc::new(CompressedTreeService::new(
        ce_db,
        CandidateCacheLimits {
            max_candidates: usize::MAX,
            max_encoded_bytes: usize::MAX,
        },
    )?);
    let runtime = Runtime::test();

    let network_config = NetworkArgs {
        discovery: DiscoveryArgs {
            disable_discovery: true,
            ..DiscoveryArgs::default()
        },
        ..NetworkArgs::default()
    };
    let node_config = NodeConfig::new(chain_spec.clone())
        .with_network(network_config)
        .with_unused_ports()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        )
        .set_dev(true);

    let outbe_node = OutbeNode {
        shutdown: Default::default(),
        bridge: Some(bridge),
        evm_signer: Some(signer),
        runtime_body_readers: RuntimeBodyReaders::new(Arc::new(MemoryStorage::new())),
        compressed_tree_service,
        ocomp_fork_install: Some(ocomp_fork_install),
    };
    let NodeHandle {
        node,
        node_exit_future: _node_exit_future,
    } = NodeBuilder::new(node_config)
        .testing_node(runtime.clone())
        .with_types_and_provider::<OutbeNode, BlockchainProvider<_>>()
        .with_components(outbe_node.components_builder())
        .with_add_ons(outbe_node.add_ons())
        .launch_with_fn(|builder| {
            let launcher = EngineNodeLauncher::new(
                builder.task_executor().clone(),
                builder.config().datadir(),
                TreeConfig::default().with_cross_block_cache_size(1024 * 1024),
            );
            builder.launch_with(launcher)
        })
        .await?;

    let mut node = NodeTestContext::new(node, move |timestamp| {
        payload_attributes(timestamp, proposer)
    })
    .await?;
    let genesis_number = chain_spec.genesis_header().number();
    let genesis_hash = node.block_hash(genesis_number);
    node.update_forkchoice(genesis_hash, genesis_hash).await?;

    let payload = node.advance_block().await?;
    let system_transactions = payload
        .block()
        .body()
        .transactions()
        .map(|tx| (*tx.tx_hash(), tx.gas_limit()))
        .collect::<Vec<_>>();
    let visible_system_gas_limit: u64 = system_transactions
        .iter()
        .map(|(_, gas_limit)| gas_limit)
        .sum();
    assert!(
        visible_system_gas_limit > 0,
        "system-only block must include system transaction envelopes"
    );

    let rpc_url = node
        .inner
        .rpc_server_handle()
        .http_url()
        .expect("HTTP RPC must be enabled")
        .parse()
        .expect("HTTP RPC URL should parse");
    let provider = ProviderBuilder::new().connect_http(rpc_url);
    let latest = provider.get_block_number().await?;
    assert_eq!(
        latest, 1,
        "test should inspect the first post-genesis block"
    );

    let rpc_block = provider
        .get_block_by_number(latest.into())
        .await?
        .expect("latest block should be available through RPC");
    let mut receipt_gas_used = 0u64;
    let mut final_cumulative_gas_used = 0u64;
    for (tx_hash, gas_limit) in system_transactions {
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await?
            .expect("system transaction receipt should be available through RPC");
        assert!(
            receipt.gas_used <= gas_limit,
            "system transaction gas used must not exceed its signed envelope limit"
        );
        receipt_gas_used = receipt_gas_used.saturating_add(receipt.gas_used);
        final_cumulative_gas_used = receipt.inner.cumulative_gas_used();
    }
    assert_eq!(
        final_cumulative_gas_used, receipt_gas_used,
        "final system receipt cumulative gas must equal the sum of actual receipt gas"
    );
    assert!(
        rpc_block.header.gas_limit < SYSTEM_TX_ARTIFACT_GAS_LIMIT,
        "RPC block gasLimit must stay in the user/block lane, not the internal system execution budget"
    );
    assert_eq!(
        rpc_block.header.gas_used, final_cumulative_gas_used,
        "RPC block gasUsed must equal the final receipt cumulative gas"
    );
    assert!(
        rpc_block.header.gas_used < visible_system_gas_limit,
        "actual RPC block gasUsed must remain below the reserved system envelope limits"
    );
    assert!(
        rpc_block.header.gas_used < SYSTEM_TX_ARTIFACT_GAS_LIMIT,
        "RPC block gasUsed must not expose the 100M internal system execution budget"
    );

    let fee_history = provider.get_fee_history(1, latest.into(), &[]).await?;
    assert_eq!(fee_history.gas_used_ratio.len(), 1);
    let expected_ratio = rpc_block.header.gas_used as f64 / rpc_block.header.gas_limit as f64;
    let actual_ratio = fee_history.gas_used_ratio[0];
    assert!(
        (actual_ratio - expected_ratio).abs() < f64::EPSILON,
        "eth_feeHistory gasUsedRatio must be computed from visible header gas: expected {expected_ratio}, got {actual_ratio}"
    );
    assert!(
        actual_ratio > 0.0 && actual_ratio < 0.01,
        "eth_feeHistory must expose small visible system gas, got {actual_ratio}"
    );
    assert!(
        actual_ratio <= 1.0,
        "eth_feeHistory must not leak a 100M system budget over the 30M block gas limit"
    );

    Ok(())
}
