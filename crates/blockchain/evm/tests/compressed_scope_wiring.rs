use std::sync::Arc;

use alloy_evm::{block::BlockExecutor, eth::EthBlockExecutionCtx};
use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_compressed_entities::{
    CandidateCacheLimits, CeMdbx, CompressedTreeService, EnvironmentIdentity, FinalizedMarker,
    ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
};
use outbe_evm::{OutbeBlockExecutionCtx, OutbeEvmConfig};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS, units::SCALE_1E6_U256, OutbeHeader,
};
use reth_ethereum::{
    chainspec::{ChainSpec, EthChainSpec, MAINNET},
    evm::revm::db::State,
};
use reth_evm::{execute::ProviderError, ConfigureEvm, EvmEnv};
use revm::{
    context::{BlockEnv, CfgEnv},
    database::CacheDB,
    database_interface::EmptyDBTyped,
    primitives::hardfork::SpecId,
    state::AccountInfo,
};

fn test_chain_spec() -> Arc<ChainSpec<OutbeHeader>> {
    MAINNET.as_ref().clone().map_header(OutbeHeader::new).into()
}

fn execution_db(proposer: Address, parent_root: B256) -> CacheDB<EmptyDBTyped<ProviderError>> {
    let mut seeded = HashMapStorageProvider::new(MAINNET.chain().id());
    StorageHandle::enter(&mut seeded, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_bytes(parent_root.0),
            )
            .unwrap();

        let owner = Address::repeat_byte(0x11);
        let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        validators.config_owner.write(owner).unwrap();
        validators.set_config_max_validators(128).unwrap();
        validators.config_epoch_length_blocks.write(60).unwrap();
        validators.config_is_initialized.write(true).unwrap();
        let mut public_key = [0_u8; 48];
        public_key[0] = 0xa2;
        validators
            .test_register_validator_without_pop(proposer, &public_key)
            .unwrap();
        validators
            .activate_validator_via_boundary_for_test(proposer)
            .unwrap();

        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        outbe_oracle::api::set_exchange_rate(
            storage,
            Address::ZERO,
            outbe_oracle::api::DAY_TYPE_PAIR,
            SCALE_1E6_U256,
            0,
            0,
        )
        .unwrap();
    });

    let mut db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
    let entries: Vec<_> = seeded.storage.into_iter().collect();
    let mut addresses: Vec<_> = entries.iter().map(|((address, _), _)| *address).collect();
    addresses.sort_unstable();
    addresses.dedup();
    for address in addresses {
        db.insert_account_info(
            address,
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
        );
    }
    for ((address, slot), value) in entries {
        db.insert_account_storage(address, slot, value).unwrap();
    }
    db
}

#[test]
fn create_executor_activates_the_factory_scope_against_the_exact_parent_tree() {
    let parent_hash = B256::repeat_byte(0x42);
    let parent_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let db = CeMdbx::open(
        directory.path(),
        EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: MAINNET.chain().id(),
            genesis_hash: parent_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: outbe_compressed_entities::CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".into(),
            vendor_revision: "scope-wiring-regression".into(),
        },
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: parent_hash,
            parent_block_hash: B256::ZERO,
            parent_root: B256::ZERO,
            new_root: parent_root,
        },
    )
    .unwrap();
    let service = Arc::new(
        CompressedTreeService::new(
            db,
            CandidateCacheLimits {
                max_candidates: 1,
                max_encoded_bytes: 1,
            },
        )
        .unwrap(),
    );
    let config = OutbeEvmConfig::new(test_chain_spec()).with_compressed_tree_service(service);

    let proposer = Address::repeat_byte(0x22);
    let db = execution_db(proposer, parent_root);
    let mut state = State::builder()
        .with_database(db)
        .with_bundle_update()
        .build();
    let env = EvmEnv {
        cfg_env: CfgEnv::new()
            .with_chain_id(MAINNET.chain().id())
            .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
        block_env: BlockEnv {
            number: U256::from(1_u64),
            gas_limit: 30_000_000,
            beneficiary: outbe_primitives::addresses::REWARDS_ADDRESS,
            timestamp: U256::from(1_u64),
            ..Default::default()
        },
    };
    let evm = config.evm_with_env(&mut state, env);
    let ctx = OutbeBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash,
            parent_beacon_block_root: None,
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(0),
            slot_number: None,
        },
        timestamp_millis_part: 0,
        block_hash: None,
        block_state_root: None,
        expected_begin_system_txs: Vec::new(),
        expected_end_system_txs: Vec::new(),
        system_layout_error: None,
        parent_consensus_metadata: None,
        proposer_evm_address: Some(proposer),
        execute_outbe_block_hooks: true,
        prebuilt_phase1_tx: None,
        parent_artifact_hint: None,
        pending_tee_bootstrap: None,
        execution_read_budget: None,
    };

    let mut executor = config.create_executor(evm, ctx);
    executor.apply_pre_execution_changes().unwrap();

    // `execution_scope()` is the Arc captured when OutbeEvmFactory installed
    // the precompile dispatch closure. Seeing the lifecycle activation and the
    // non-empty exact-parent root here proves create_executor configured and
    // activated that same instance, rather than a second executor-only scope.
    let precompile_scope = executor.evm().execution_scope();
    assert_eq!(precompile_scope.parent_root().unwrap(), parent_root);
    precompile_scope.ce_work_checkpoint().unwrap();
}
