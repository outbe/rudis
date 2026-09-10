use alloy_evm::{block::BlockExecutor, Evm, RecoveredTx};
use outbe_primitives::{
    consensus::ConsensusExecutionBridge,
    reshare_artifact::{
        decode_outbe_block_artifacts, encode_outbe_block_artifacts, CompressedEntitiesRootArtifact,
    },
    OutbeHeader, OutbePrimitives,
};
use reth_ethereum::evm::revm::primitives::hardfork::SpecId;
use reth_ethereum::trie::updates::TrieUpdates;
use reth_ethereum::{
    evm::{primitives::Database, revm::db::State},
    TransactionSigned,
};
use reth_evm::execute::{
    BlockAssembler, BlockAssemblerInput, BlockBuilder, BlockBuilderOutcome, BlockExecutionError,
    ExecutorTx,
};
use reth_primitives_traits::{Recovered, RecoveredBlock, SealedHeader};
use reth_provider::StateProvider;
use revm::context::BlockEnv;
use revm::database::states::bundle_state::BundleRetention;

use crate::{
    config::{OutbeBlockAssembler, OutbeBlockExecutionCtx},
    executor::OutbeBlockExecutor,
};

pub(crate) fn encode_final_header_artifacts(
    prefinal_extra_data: &[u8],
    execution_summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact,
    timestamp_millis_part: u64,
    compressed_root: alloy_primitives::B256,
) -> Result<alloy_primitives::Bytes, BlockExecutionError> {
    let mut artifacts = decode_outbe_block_artifacts(prefinal_extra_data)
        .map_err(|e| BlockExecutionError::msg(e.to_string()))?;
    artifacts.execution_summary = Some(execution_summary);
    artifacts.timestamp_millis_part = timestamp_millis_part;
    artifacts.compressed_entities_root = Some(CompressedEntitiesRootArtifact {
        commitment_scheme_version: outbe_compressed_entities::ACTIVE_COMMITMENT_SCHEME,
        r_sealed: compressed_root,
    });
    encode_outbe_block_artifacts(&artifacts).map_err(|e| BlockExecutionError::msg(e.to_string()))
}

pub struct OutbeBlockBuilder<'a, EVM>
where
    EVM: Evm,
{
    pub executor: OutbeBlockExecutor<'a, EVM>,
    pub transactions: Vec<Recovered<TransactionSigned>>,
    pub ctx: OutbeBlockExecutionCtx<'a>,
    pub bridge: Option<ConsensusExecutionBridge>,
    pub parent: &'a SealedHeader<OutbeHeader>,
    pub assembler: &'a OutbeBlockAssembler,
}

impl<'a, EVM> OutbeBlockBuilder<'a, EVM>
where
    EVM: Evm,
{
    pub fn new(
        executor: OutbeBlockExecutor<'a, EVM>,
        ctx: OutbeBlockExecutionCtx<'a>,
        bridge: Option<ConsensusExecutionBridge>,
        assembler: &'a OutbeBlockAssembler,
        parent: &'a SealedHeader<OutbeHeader>,
    ) -> Self {
        Self {
            executor,
            transactions: Vec::new(),
            ctx,
            bridge,
            parent,
            assembler,
        }
    }

    /// Encodes all execution-produced header artifacts from the single stored
    /// CE seal. Payload building calls this before either state-root path; the
    /// final `finish` call repeats it idempotently as a defensive invariant.
    pub fn finalize_header_artifacts(&mut self) -> Result<(), BlockExecutionError> {
        let compressed_seal_output = self
            .executor
            .compressed_entities_seal_output()
            .ok_or_else(|| BlockExecutionError::msg("missing compressed-entities SealOutput"))?;
        self.ctx.inner.extra_data = encode_final_header_artifacts(
            self.ctx.inner.extra_data.as_ref(),
            self.executor.current_execution_summary(),
            self.ctx.timestamp_millis_part,
            compressed_seal_output.new_root,
        )?;
        self.executor
            .set_final_extra_data(self.ctx.inner.extra_data.clone());
        Ok(())
    }
}

impl<'a, DB, EVM> BlockBuilder for OutbeBlockBuilder<'a, EVM>
where
    DB: Database + 'a,
    OutbeBlockExecutor<'a, EVM>:
        BlockExecutor<Evm = EVM, Transaction = TransactionSigned, Receipt = reth_ethereum::Receipt>,
    EVM: Evm<
            DB = &'a mut State<DB>,
            Spec = SpecId,
            BlockEnv = BlockEnv,
            Tx = reth_ethereum::evm::revm::context::TxEnv,
        > + crate::executor::ZeroFeeCfgAccess,
{
    type Primitives = OutbePrimitives;
    type Executor = OutbeBlockExecutor<'a, EVM>;

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.executor.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutorTx<Self::Executor>,
        f: impl FnOnce(&<Self::Executor as BlockExecutor>::Result) -> alloy_evm::block::CommitChanges,
    ) -> Result<Option<alloy_evm::block::GasOutput>, BlockExecutionError> {
        let (tx_env, tx) = tx.into_parts();
        let include_preexecuted_phase1_witness =
            self.executor.is_preexecuted_phase1_witness(tx.tx());

        if let Some(gas_used) = self
            .executor
            .execute_transaction_with_commit_condition((tx_env, &tx), f)?
        {
            self.transactions.push(tx);
            Ok(Some(gas_used))
        } else if include_preexecuted_phase1_witness {
            self.transactions.push(tx);
            Ok(None)
        } else {
            Ok(None)
        }
    }

    fn finish(
        mut self,
        state: impl StateProvider,
        state_root_precomputed: Option<(alloy_primitives::B256, TrieUpdates)>,
    ) -> Result<BlockBuilderOutcome<OutbePrimitives>, BlockExecutionError> {
        // Seal CE exactly once before encoding any execution-produced header
        // fields. This must happen while the parallel state hook is attached.
        self.executor.finalize_compressed_entities()?;
        // finalized-parent metadata travels through payload
        // attributes into the begin-zone Phase 1 system transaction body.
        // Header `extra_data` here carries only execution summary,
        // timestamp millis, and DKG/header artifacts; the legacy header
        // attestation tag is not produced by the proposer path.
        let execution_summary = self.executor.current_execution_summary();
        // Sub-second timestamp travels in `extra_data` under tag 0x05 so
        // the block hash stays Ethereum-spec-compliant
        // (`keccak256(rlp(standard_header))`). The execution-context
        // value is the canonical source for this block; whatever the
        // proposer placed in `extra_data` earlier is overwritten here.
        self.finalize_header_artifacts()?;
        let compressed_seal_output = self
            .executor
            .compressed_entities_seal_output()
            .ok_or_else(|| BlockExecutionError::msg("missing compressed-entities SealOutput"))?;

        // Proposer execution does not know the block hash until assembly. Seal
        // first, retain the immutable provisional batch across assembly, then
        // publish it under the exact computed hash. Validator execution uses
        // the known hash path in `OutbeBlockExecutor::finish`.
        let compressed_tree_service = self.executor.compressed_tree_service();

        let (evm, result) = self.executor.finish()?;
        let (db, evm_env) = evm.finish();

        db.merge_transitions(BundleRetention::Reverts);

        let hashed_state = state.hashed_post_state(&db.bundle_state);
        let (state_root, trie_updates) = match state_root_precomputed {
            Some(precomputed) => precomputed,
            None => state
                .state_root_with_updates(hashed_state.clone())
                .map_err(BlockExecutionError::other)?,
        };

        let (transactions, senders): (Vec<_>, Vec<_>) = self
            .transactions
            .into_iter()
            .map(|tx| tx.into_parts())
            .unzip();

        let block = self.assembler.assemble_block(BlockAssemblerInput::<
            crate::config::OutbeEvmConfig,
            OutbeHeader,
        >::new(
            evm_env,
            self.ctx,
            self.parent,
            transactions,
            &result,
            &db.bundle_state,
            &state,
            state_root,
        ))?;

        let block = RecoveredBlock::new_unhashed(block, senders);
        if let Some(service) = compressed_tree_service {
            service
                .publish_candidate(block.hash(), compressed_seal_output.staged_tree_batch)
                .map_err(|error| BlockExecutionError::msg(error.to_string()))?;
        }
        if let Some(bridge) = &self.bridge {
            bridge.record_execution_summary_with_state_root(
                block.header().inner.number,
                block.hash(),
                execution_summary,
                block.header().inner.timestamp,
                block.header().inner.state_root,
            );
        }

        Ok(BlockBuilderOutcome {
            execution_result: result,
            hashed_state,
            trie_updates,
            block,
        })
    }

    fn executor_mut(&mut self) -> &mut Self::Executor {
        &mut self.executor
    }

    fn executor(&self) -> &Self::Executor {
        &self.executor
    }

    fn into_executor(self) -> Self::Executor {
        self.executor
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_evm::{block::CommitChanges, RecoveredTx};
    use alloy_primitives::{Address, Bytes, StorageKey, StorageValue, B256, U256};
    use outbe_compressed_entities::{
        CandidateCacheLimits, CeMdbx, CompressedTreeService, EnvironmentIdentity, FinalizedMarker,
        ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
    };
    use outbe_primitives::addresses::REWARDS_ADDRESS;
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
    use outbe_primitives::consensus::ConsensusExecutionBridge;
    use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
    use outbe_primitives::reshare_artifact::{
        decode_outbe_block_artifacts, encode_outbe_block_artifacts, CompressedEntitiesRootArtifact,
        ConsensusHeaderArtifact, ExecutionSummaryArtifact, OutbeBlockArtifacts,
    };
    use outbe_primitives::storage::{
        direct::DirectStorageProvider, hashmap::HashMapStorageProvider,
        MetadosisMutationPurposeTag, StorageHandle,
    };
    use outbe_primitives::tee_genesis_v1::GRAMINE_DIRECT_DEV_CHAIN_ID;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::chainspec::ChainSpec;
    use reth_ethereum::{
        chainspec::MAINNET,
        evm::revm::db::State,
        primitives::{Account, Bytecode, Header, SealedHeader},
        trie::{
            updates::TrieUpdates, AccountProof, HashedPostState, HashedStorage, KeccakKeyHasher,
            MultiProof, MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
        },
    };
    use reth_evm::{
        execute::{BlockBuilder, Executor, ProviderError},
        ConfigureEvm, NextBlockEnvAttributes,
    };
    use reth_primitives_traits::RecoveredBlock;
    use reth_provider::{
        AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, ProviderResult,
        StateProofProvider, StateProvider, StateRootProvider, StorageRootProvider,
    };
    use reth_trie::test_utils::{state_root_prehashed, storage_root_prehashed};
    use revm::{
        database::CacheDB,
        database_interface::EmptyDBTyped,
        state::{AccountInfo, Bytecode as RevmBytecode},
    };

    use crate::{
        config::{OutbeEvmConfig, OutbeNextBlockEnvAttributes},
        signer::OutbeEvmSigner,
    };

    fn genesis_owner() -> Address {
        test_evm_signer().address()
    }
    const TEST_BLOCK_ONE_TIMESTAMP: u64 = 1_700_000_001;

    #[test]
    fn final_artifact_adapter_overwrites_untrusted_root_and_preserves_consensus_fields() {
        let prefinal = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: Some(ExecutionSummaryArtifact {
                validator_fee_sum: U256::from(999),
            }),
            consensus_header_artifact: Some(ConsensusHeaderArtifact::DealerLog(
                Bytes::from_static(b"dealer"),
            )),
            timestamp_millis_part: 999,
            compressed_entities_root: Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: 77,
                r_sealed: B256::repeat_byte(0xDD),
            }),
            ..Default::default()
        })
        .unwrap();
        let local_root = B256::repeat_byte(0xAB);
        let encoded = super::encode_final_header_artifacts(
            &prefinal,
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::from(7),
            },
            321,
            local_root,
        )
        .unwrap();
        let decoded = decode_outbe_block_artifacts(&encoded).unwrap();
        assert_eq!(
            decoded.consensus_header_artifact,
            Some(ConsensusHeaderArtifact::DealerLog(Bytes::from_static(
                b"dealer"
            )))
        );
        assert_eq!(
            decoded.execution_summary.unwrap().validator_fee_sum,
            U256::from(7)
        );
        assert_eq!(decoded.timestamp_millis_part, 321);
        assert_eq!(
            decoded.compressed_entities_root,
            Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                r_sealed: local_root,
            })
        );

        let other = super::encode_final_header_artifacts(
            &prefinal,
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::from(7),
            },
            321,
            B256::repeat_byte(0xAC),
        )
        .unwrap();
        let first = SealedHeader::seal_slow(OutbeHeader::new(Header {
            extra_data: encoded,
            ..Default::default()
        }));
        let second = SealedHeader::seal_slow(OutbeHeader::new(Header {
            extra_data: other,
            ..Default::default()
        }));
        assert_ne!(first.hash(), second.hash());
    }

    #[derive(Debug, Default, Clone)]
    struct DeterministicEmptyStateProvider;

    impl AccountReader for DeterministicEmptyStateProvider {
        fn basic_account(&self, _address: &Address) -> ProviderResult<Option<Account>> {
            Ok(None)
        }
    }

    impl BlockHashReader for DeterministicEmptyStateProvider {
        fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
            Ok(None)
        }

        fn canonical_hashes_range(&self, _start: u64, _end: u64) -> ProviderResult<Vec<B256>> {
            Ok(Vec::new())
        }
    }

    impl StateRootProvider for DeterministicEmptyStateProvider {
        fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
            Ok(compute_state_root(hashed_state))
        }

        fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
            Ok(B256::ZERO)
        }

        fn state_root_with_updates(
            &self,
            hashed_state: HashedPostState,
        ) -> ProviderResult<(B256, TrieUpdates)> {
            Ok((compute_state_root(hashed_state), TrieUpdates::default()))
        }

        fn state_root_from_nodes_with_updates(
            &self,
            _input: TrieInput,
        ) -> ProviderResult<(B256, TrieUpdates)> {
            Ok((B256::ZERO, TrieUpdates::default()))
        }
    }

    impl StorageRootProvider for DeterministicEmptyStateProvider {
        fn storage_root(
            &self,
            _address: Address,
            hashed_storage: HashedStorage,
        ) -> ProviderResult<B256> {
            let slots = hashed_storage.storage.into_iter().collect::<Vec<_>>();
            Ok(storage_root_prehashed(slots))
        }

        fn storage_proof(
            &self,
            _address: Address,
            slot: B256,
            _hashed_storage: HashedStorage,
        ) -> ProviderResult<StorageProof> {
            Ok(StorageProof::new(slot))
        }

        fn storage_multiproof(
            &self,
            _address: Address,
            _slots: &[B256],
            _hashed_storage: HashedStorage,
        ) -> ProviderResult<StorageMultiProof> {
            Ok(StorageMultiProof::empty())
        }
    }

    impl StateProofProvider for DeterministicEmptyStateProvider {
        fn proof(
            &self,
            _input: TrieInput,
            address: Address,
            _slots: &[B256],
        ) -> ProviderResult<AccountProof> {
            Ok(AccountProof::new(address))
        }

        fn multiproof(
            &self,
            _input: TrieInput,
            _targets: MultiProofTargets,
        ) -> ProviderResult<MultiProof> {
            Ok(MultiProof::default())
        }

        fn witness(
            &self,
            _input: TrieInput,
            _target: HashedPostState,
            _mode: reth_trie::ExecutionWitnessMode,
        ) -> ProviderResult<Vec<Bytes>> {
            Ok(Vec::new())
        }
    }

    impl HashedPostStateProvider for DeterministicEmptyStateProvider {
        fn hashed_post_state(&self, bundle_state: &revm::database::BundleState) -> HashedPostState {
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state())
        }
    }

    impl StateProvider for DeterministicEmptyStateProvider {
        fn storage(
            &self,
            _account: Address,
            _storage_key: StorageKey,
        ) -> ProviderResult<Option<StorageValue>> {
            Ok(None)
        }
    }

    impl BytecodeReader for DeterministicEmptyStateProvider {
        fn bytecode_by_hash(&self, _code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
            Ok(None)
        }
    }

    fn compute_state_root(hashed_state: HashedPostState) -> B256 {
        let sorted = hashed_state.into_sorted();
        let storages = sorted.storages;
        let accounts = sorted
            .accounts
            .into_iter()
            .filter_map(|(hashed_address, maybe_account)| {
                maybe_account.map(|account| {
                    let storage = storages
                        .get(&hashed_address)
                        .map(|hashed_storage| hashed_storage.storage_slots.clone())
                        .unwrap_or_default();
                    (hashed_address, (account, storage))
                })
            });
        state_root_prehashed(accounts)
    }

    fn test_bridge() -> ConsensusExecutionBridge {
        ConsensusExecutionBridge::new()
    }

    fn test_evm_signer() -> Arc<OutbeEvmSigner> {
        Arc::new(
            OutbeEvmSigner::from_hex(&outbe_primitives::test_keys::hex(1))
                .expect("test EVM signer must be valid"),
        )
    }

    fn genesis_dev_tee_bootstrap(
        committee_snapshot_hash: B256,
    ) -> outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2 {
        use outbe_primitives::tee_test_utils::{
            gramine_direct_bootstrap_v2, gramine_direct_policy_v1, DevValidatorV1,
        };

        let secret = outbe_primitives::test_keys::secret(1);
        let mut consensus_public = [0_u8; 48];
        consensus_public[0] = 1;
        let policy = gramine_direct_policy_v1(GRAMINE_DIRECT_DEV_CHAIN_ID, MAINNET.genesis_hash())
            .expect("test GramineDirectDev policy is canonical");
        gramine_direct_bootstrap_v2(
            policy,
            committee_snapshot_hash,
            1,
            TEST_BLOCK_ONE_TIMESTAMP + 3_600,
            &[DevValidatorV1 {
                evm_secret: secret,
                bls_minpk_public: consensus_public,
            }],
        )
        .expect("test GramineDirectDev OST3 payload is canonical")
    }

    fn test_config(bridge: ConsensusExecutionBridge) -> OutbeEvmConfig {
        OutbeEvmConfig::new_with_bridge(test_chain_spec(), bridge)
            .with_evm_signer(test_evm_signer())
    }

    fn test_tree_service(parent_hash: B256) -> (tempfile::TempDir, Arc<CompressedTreeService>) {
        // This fixture isolates validator non-publication after Reth root
        // rejection while retaining the final ADR-010 empty authority.
        let directory = tempfile::tempdir().expect("CE test directory must be created");
        let db = CeMdbx::open(
            directory.path(),
            EnvironmentIdentity {
                local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
                chain_id: GRAMINE_DIRECT_DEV_CHAIN_ID,
                genesis_hash: parent_hash,
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                topology: outbe_compressed_entities::CeTopologyV1.encode(),
                tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
                vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
            },
            FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: 0,
                block_hash: parent_hash,
                parent_block_hash: B256::ZERO,
                parent_root: B256::ZERO,
                new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
            },
        )
        .expect("CE test MDBX must open");
        let service = CompressedTreeService::new(
            db,
            CandidateCacheLimits {
                max_candidates: 4,
                max_encoded_bytes: 1_000_000,
            },
        )
        .expect("CE test service must open");
        (directory, Arc::new(service))
    }

    fn test_chain_spec() -> Arc<ChainSpec<OutbeHeader>> {
        use outbe_primitives::tee_test_utils::{
            gramine_direct_policy_v1, tee_attestation_v1_extra_field,
        };

        let mut spec = MAINNET.as_ref().clone();
        spec.chain = GRAMINE_DIRECT_DEV_CHAIN_ID.into();
        spec.genesis.config.chain_id = GRAMINE_DIRECT_DEV_CHAIN_ID;
        let policy = gramine_direct_policy_v1(spec.chain().id(), spec.genesis_hash())
            .expect("test GramineDirectDev policy is canonical");
        spec.genesis.config.extra_fields.insert(
            "teeAttestationV1".to_owned(),
            tee_attestation_v1_extra_field(&policy)
                .expect("test TEE activation manifest is canonical"),
        );
        spec.map_header(OutbeHeader::new).into()
    }

    fn test_parent() -> SealedHeader<OutbeHeader> {
        SealedHeader::seal_slow(OutbeHeader::new(Header::default()))
    }

    fn test_parent_at(number: u64) -> SealedHeader<OutbeHeader> {
        SealedHeader::seal_slow(OutbeHeader::new(Header {
            number,
            ..Default::default()
        }))
    }

    fn next_block_attrs(extra_data: Bytes) -> OutbeNextBlockEnvAttributes {
        OutbeNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: TEST_BLOCK_ONE_TIMESTAMP,
                suggested_fee_recipient: REWARDS_ADDRESS,
                prev_randao: B256::ZERO,
                gas_limit: 30_000_000,
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data,
                slot_number: None,
            },
            timestamp_millis_part: 0,
            parent_consensus_metadata: None,
            proposer_evm_address: Some(genesis_owner()),
            execute_outbe_block_hooks: true,
            prebuilt_phase1_tx: None,
            parent_artifact_hint: None,
            pending_tee_bootstrap: None,
            execution_read_budget: None,
        }
    }

    type TestDb = CacheDB<EmptyDBTyped<ProviderError>>;

    fn seed_active_validators(db: &mut TestDb, validators: &[Address]) {
        let chain_spec = test_chain_spec();
        let founders = validators
            .iter()
            .copied()
            .enumerate()
            .map(|(idx, validator)| {
                let mut consensus_key = [0u8; 48];
                consensus_key[0] = idx as u8 + 1;
                (validator, consensus_key)
            })
            .collect::<Vec<_>>();
        let install = outbe_metadosis::test_support::ForkInstallScenario::measurement_at(
            1,
            chain_spec.chain().id(),
            chain_spec.genesis_hash(),
        )
        .unwrap()
        .with_founder_validators(&founders)
        .unwrap()
        .into_install();
        let mut metadosis_genesis = HashMapStorageProvider::new_with_chain_identity(
            chain_spec.chain().id(),
            chain_spec.genesis_hash(),
        );
        metadosis_genesis.set_block_number(1);
        metadosis_genesis.enter(|storage| {
            let root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
            storage
                .sstore(
                    outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                    U256::ZERO,
                    U256::from(4),
                )
                .unwrap();
            storage
                .sstore(
                    outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
                    U256::from(1),
                    U256::from_be_slice(root.as_slice()),
                )
                .unwrap();
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(Address::ZERO).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_epoch_length_blocks.write(60).unwrap();
            vs.config_is_initialized.write(true).unwrap();

            for ((validator, consensus_key), registration) in
                founders.iter().zip(&install.founder_registrations)
            {
                vs.register_validator(Address::ZERO, *validator, consensus_key)
                    .unwrap();
                vs.mark_pending(*validator).unwrap();
                let encoded = registration
                    .encode_canonical(&outbe_metadosis::config::poc_schema_limits())
                    .unwrap();
                vs.confirm_validator_ready(*validator, &encoded).unwrap();
                vs.activate_validator_via_boundary_for_test(*validator)
                    .unwrap();
            }
            // Seed the COEN/840 oracle pair + a 1.0 rate so begin-block
            // NOD/GEM/INTEX floor-price promotion resolves a live rate instead
            // of soft-skipping the scan. The qualifiers derive the pair from the
            // ISO code, so registering the pair is sufficient.
            outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .unwrap();
            outbe_oracle::api::set_exchange_rate(
                storage.clone(),
                Address::ZERO,
                outbe_oracle::api::DAY_TYPE_PAIR,
                U256::from(1_000_000u64),
                0,
                0,
            )
            .unwrap();
        });
        metadosis_genesis.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::ForkProfile);
        metadosis_genesis.enter(|storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, 1_700_000_001, chain_spec.chain().id()),
                storage,
            );
            outbe_metadosis::commands::install_fork_profile(&ctx, &install).unwrap();
        });
        for ((address, slot), value) in metadosis_genesis.storage {
            db.insert_account_storage(address, slot, value)
                .expect("production-route genesis seed must install");
        }

        let marker_code = RevmBytecode::new_legacy([0xef].into());
        db.insert_account_info(
            outbe_primitives::addresses::VALIDATOR_SET_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::ORACLE_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::METADOSIS_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code.clone()),
                ..Default::default()
            },
        );
        db.insert_account_info(
            outbe_primitives::addresses::OCOMP_REGISTRY_ADDRESS,
            AccountInfo {
                code_hash: marker_code.hash_slow(),
                code: Some(marker_code),
                ..Default::default()
            },
        );
    }

    fn assert_seeded_validators(db: &mut TestDb, validators: &[Address]) {
        let ctx = BlockContext::new(
            0,
            0,
            MAINNET.chain().id(),
            genesis_owner(),
            validators.to_vec(),
        );
        let mut provider = DirectStorageProvider::new(db, ctx);
        StorageHandle::enter(&mut provider, |storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            for validator in validators {
                let record = vs
                    .get_validator(*validator)
                    .unwrap()
                    .expect("seeded validator must exist");
                assert_eq!(record.status, outbe_validatorset::logic::status::ACTIVE);
                assert!(record.has_bls_share);
            }
        });
    }

    #[test]
    fn builder_keeps_preexecuted_phase1_witness_in_block_body() {
        let bridge = test_bridge();
        let parent = test_parent_at(1);
        bridge.record_execution_summary_with_state_root(
            1,
            parent.hash(),
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            parent.header().inner.timestamp,
            parent.header().inner.state_root,
        );
        let config = test_config(bridge);
        let provider = DeterministicEmptyStateProvider;
        let mut proposer_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut proposer_db, &[genesis_owner()]);
        let mut proposer_state = State::builder()
            .with_database(proposer_db)
            .with_bundle_update()
            .build();

        let mut attrs = next_block_attrs(Bytes::new());
        let metadata = CertifiedParentAccountingMetadata {
            finalized_block_number: 1,
            finalized_block_hash: parent.hash(),
            ..Default::default()
        };
        attrs.parent_consensus_metadata = Some(metadata);

        let phase1 = config
            .build_signed_phase1_tx(
                2,
                GRAMINE_DIRECT_DEV_CHAIN_ID,
                parent.hash(),
                attrs.parent_consensus_metadata.clone(),
                attrs.proposer_evm_address,
            )
            .expect("Phase 1 prebuild must succeed")
            .expect("block 2 must prebuild Phase 1");
        let phase1_hash = phase1.tx().signature_hash();

        let evm_env = config
            .next_evm_env(&parent, &attrs)
            .expect("next block EVM env must build");
        let ctx = config
            .context_for_next_block(&parent, attrs)
            .expect("next block context must build");
        let evm = config.evm_with_env(&mut proposer_state, evm_env);
        let mut builder = config.create_block_builder(evm, &parent, ctx);
        crate::executor::with_phase1_verify_disabled(|| builder.apply_pre_execution_changes())
            .expect("Phase 1 must be pre-executed before witness validation");
        builder
            .executor_mut()
            .force_preexecuted_phase1_witness_for_test(phase1_hash);

        let gas_used = builder
            .execute_transaction_with_commit_condition(phase1.clone(), |_| CommitChanges::Yes)
            .expect("pre-executed Phase 1 witness must validate");

        assert!(
            gas_used.is_none(),
            "Phase 1 witness validation must not commit or charge gas twice"
        );
        let outcome = builder
            .finish(&provider, None)
            .expect("block with retained Phase 1 witness must finish");
        assert_eq!(
            outcome.block.body().transactions.len(),
            1,
            "finished block body must retain the Phase 1 witness tx"
        );
        assert_eq!(
            outcome.block.body().transactions[0].signature_hash(),
            phase1_hash,
            "body[0] must be the exact pre-executed Phase 1 witness"
        );
    }

    // V2 base-block proposer/validator state-root parity.
    //
    // A "base block" carries NO consensus-header artifact. Under V2 that is
    // only a `block_number >= 2` block: block 0 has no begin-zone txs, and
    // block 1 mandatorily carries a `BoundaryOutcome` (genesis DKG boundary).
    // So this test builds a valid block 2 whose begin-zone is the standard
    // `CertifiedParentAccounting` (Phase 1) + `CycleTick` + `OracleSlashWindow`
    // sequence, proposer-builds it through `builder_for_next_block` + `finish`,
    // then re-executes it on the validator path via `batch_executor` /
    // `execute_one`, and asserts the two state roots match.
    //
    // The parent (block 1) summary is recorded into the consensus bridge so the
    // executor's `AccountedParentArtifactProvider` resolves the
    // `CertifiedParentAccounting` finalized-summary on both paths. The Phase 1
    // `verify_v2_proof` preflight is opted out via the crate-only test escape
    // hatch (`with_phase1_verify_disabled`): this fixture exercises base-block
    // begin-zone determinism, not the certificate verifier itself, and so does
    // not seed a matching `(epoch, committee_set_hash)` committee snapshot. The
    // opt-out wraps every execution entry point (proposer
    // `apply_pre_execution_changes` and validator `execute_one`) so both paths
    // run identically. Block-1 parity (WITH a `BoundaryOutcome`) is covered by
    // `genesis_block_with_header_artifact_reexecutes_deterministically` below.
    #[test]
    fn base_block_height2_reexecutes_with_same_state_root() {
        use outbe_primitives::reshare_artifact::ExecutionSummaryArtifact;

        let active_set = [genesis_owner()];
        // Parent is block 1 with a non-zero hash; Phase 1 metadata targets it.
        let parent = test_parent_at(1);

        // Record the parent (block 1) execution summary into the bridge so the
        // cache-backed `AccountedParentArtifactProvider` (installed by
        // `new_with_bridge`) resolves the finalized-parent summary that the
        // `CertifiedParentAccounting` system tx requires on both build and
        // re-execute paths.
        let bridge = test_bridge();
        bridge.record_execution_summary_with_state_root(
            1,
            parent.hash(),
            ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            },
            1,
            parent.header().inner.state_root,
        );
        let config = test_config(bridge);
        let provider = DeterministicEmptyStateProvider;

        // Phase 1 metadata for block 2 targets the immediate parent (block 1).
        // An empty committee / bitmap is structurally valid (no voters, no
        // slashing) and keeps the fixture minimal.
        let metadata = CertifiedParentAccountingMetadata {
            finalized_block_number: 1,
            finalized_block_hash: parent.hash(),
            ..CertifiedParentAccountingMetadata::default()
        };

        // Proposer path: build block 2.
        let mut proposer_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut proposer_db, &active_set);
        assert_seeded_validators(&mut proposer_db, &active_set);
        let mut proposer_state = State::builder()
            .with_database(proposer_db)
            .with_bundle_update()
            .build();

        let mut attrs = next_block_attrs(Bytes::new());
        attrs.parent_consensus_metadata = Some(metadata.clone());

        let built_block = crate::executor::with_phase1_verify_disabled(|| {
            let mut builder = config
                .builder_for_next_block(&mut proposer_state, &parent, attrs.clone())
                .expect("builder must be created");
            builder
                .apply_pre_execution_changes()
                .expect("pre-execution changes must succeed");
            let begin_system_txs = config
                .build_begin_system_txs(
                    2,
                    GRAMINE_DIRECT_DEV_CHAIN_ID,
                    30_000_000,
                    parent.hash(),
                    &attrs.inner.extra_data,
                    attrs.parent_consensus_metadata.clone(),
                    attrs.proposer_evm_address,
                    None,
                    None,
                )
                .expect("begin-zone system txs must build");
            // Base block: no BoundaryOutcome, so the begin-zone is exactly
            // CertifiedParentAccounting + LateFinalizeCredits + CycleTick +
            // RewardsGemDelivery + OracleSlashWindow + HookEvents.
            assert_eq!(
                begin_system_txs.len(),
                6,
                "block 2 base-block begin-zone must include RewardsGemDelivery after CycleTick",
            );
            for tx in begin_system_txs {
                builder
                    .execute_transaction(tx)
                    .expect("begin-zone system tx must execute through builder tx loop");
            }
            builder
                .finish(&provider, None)
                .expect("proposer path must build a block")
                .block
        });
        let built_root = built_block.header().inner.state_root;

        // The base block must carry no consensus-header artifact, only the
        // proposer-injected execution summary.
        let built_artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
            built_block.header().inner.extra_data.as_ref(),
        )
        .expect("built header extra_data must decode");
        assert!(
            built_artifacts.consensus_header_artifact.is_none(),
            "base block must not carry a consensus-header artifact",
        );
        assert_eq!(
            built_artifacts.execution_summary,
            Some(ExecutionSummaryArtifact {
                validator_fee_sum: U256::ZERO,
            }),
            "proposer finish must inject execution summary into final header extra_data",
        );

        // Validator path: re-execute the built block.
        let mut validator_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut validator_db, &active_set);
        let validator_state = State::builder()
            .with_database(validator_db)
            .with_bundle_update()
            .build();
        let validator_state = crate::executor::with_phase1_verify_disabled(|| {
            let mut validator_executor = config.batch_executor(validator_state);
            validator_executor
                .execute_one(&built_block)
                .expect("validator path must re-execute the built block");
            validator_executor.into_state()
        });

        let reexecuted_hashed_state = provider.hashed_post_state(&validator_state.bundle_state);
        let (reexecuted_root, _) = provider
            .state_root_with_updates(reexecuted_hashed_state)
            .expect("re-executed state root must be computed");

        assert_eq!(
            built_root, reexecuted_root,
            "locally built base block must re-execute to the same state root on validator path",
        );
    }

    /// Regression test: header artifact (DKG boundary) must be present during
    /// state-root computation on the proposer, not attached after. The bridge
    /// injects the artifact via `context_for_next_block` so that proposer and
    /// validator execute with identical `extra_data`.
    #[test]
    fn genesis_block_with_header_artifact_reexecutes_deterministically() {
        use outbe_primitives::{
            consensus::{DkgBoundaryArtifact, ReshareResult},
            reshare_artifact::{encode_consensus_header_artifact, ConsensusHeaderArtifact},
        };

        let bridge = test_bridge();

        // The seeded active set is `[genesis_owner()]`; the boundary artifact must
        // carry the canonical hashes the executor recomputes in
        // `apply_boundary_outcome`, otherwise the begin-zone BoundaryOutcome
        // system tx is rejected (active_set_hash / VRF / committee_set_hash
        // checks). Derive each value from the same canonical layout the executor
        // uses rather than stubbing magic bytes.
        let new_active_set = vec![genesis_owner()];

        // `hash_boundary_active_set`: keccak256(len_be_u64 || addr_20_bytes...).
        let active_set_hash = {
            let mut bytes = Vec::with_capacity(8 + new_active_set.len() * 20);
            bytes.extend_from_slice(&(new_active_set.len() as u64).to_be_bytes());
            for address in &new_active_set {
                bytes.extend_from_slice(address.as_slice());
            }
            alloy_primitives::keccak256(bytes)
        };

        // VRF group public key commitment is keccak256 of the raw 96-byte key.
        let vrf_group_public_key_bytes = Bytes::from_static(&[0xBBu8; 96]);
        let vrf_group_public_key = alloy_primitives::keccak256(vrf_group_public_key_bytes.as_ref());

        // committee_set_hash_v2 binds the seeded consensus pubkey for
        // genesis_owner(). `seed_active_validators` registers index-0 validators
        // with pubkey byte[0] = idx + 1, rest zero.
        let mut genesis_consensus_pubkey = [0u8; 48];
        genesis_consensus_pubkey[0] = 1;
        let committee_snapshot = outbe_validatorset::CommitteeSnapshot {
            committee: vec![outbe_validatorset::CommitteeEntry {
                address: genesis_owner(),
                consensus_pubkey: genesis_consensus_pubkey,
            }],
            vrf_material_version: 0,
            vrf_group_public_key_bytes: vrf_group_public_key_bytes.to_vec(),
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        let committee_set_hash = outbe_validatorset::committee_set_hash_v2(0, &committee_snapshot);

        // Simulate the handler injecting a boundary artifact before building.
        let artifact = DkgBoundaryArtifact {
            epoch: 0,
            dkg_cycle: 0,
            freeze_height: 0,
            planned_activation_height: 0,
            target_set_hash: active_set_hash,
            vrf_material_version: 0,
            vrf_group_public_key,
            vrf_group_public_key_bytes,
            committee_set_hash,
            is_validator_set_change: true,
            outcome: Bytes::from_static(b"test-outcome"),
            is_full_dkg: true,
            tee_recipient_pubkeys: Vec::new(),
            tee_expired_target_exclusions: Vec::new(),
            tee_expired_target_exclusions_hash: B256::ZERO,
            reshare: ReshareResult {
                new_active_set,
                active_set_hash,
            },
        };
        let active_set = artifact.reshare.new_active_set.clone();
        let encoded =
            encode_consensus_header_artifact(&ConsensusHeaderArtifact::BoundaryOutcome(artifact))
                .expect("artifact encoding must succeed");

        let config = test_config(bridge);
        let parent = test_parent();
        let provider = DeterministicEmptyStateProvider;

        // Proposer path: build block (executor sees artifact via extra_data).
        let mut proposer_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut proposer_db, &active_set);
        assert_seeded_validators(&mut proposer_db, &active_set);
        let mut proposer_state = State::builder()
            .with_database(proposer_db)
            .with_bundle_update()
            .build();

        let mut attrs = next_block_attrs(encoded);
        attrs.inner.gas_limit = outbe_primitives::system_tx::protocol_block_gas_limit(1);
        attrs.pending_tee_bootstrap = Some(genesis_dev_tee_bootstrap(committee_set_hash));
        let mut builder = config
            .builder_for_next_block(&mut proposer_state, &parent, attrs.clone())
            .expect("builder must be created");
        builder
            .apply_pre_execution_changes()
            .expect("pre-execution changes must succeed");
        let begin_system_txs = config
            .build_begin_system_txs(
                1,
                GRAMINE_DIRECT_DEV_CHAIN_ID,
                outbe_primitives::system_tx::protocol_block_gas_limit(1),
                parent.hash(),
                &attrs.inner.extra_data,
                attrs.parent_consensus_metadata.clone(),
                attrs.proposer_evm_address,
                None,
                attrs.pending_tee_bootstrap.clone(),
            )
            .expect("begin-zone system txs must build");
        for tx in begin_system_txs {
            builder
                .execute_transaction(tx)
                .expect("begin-zone system tx must execute through builder tx loop");
        }

        let outcome = builder
            .finish(&provider, None)
            .expect("proposer path must build a block");
        let built_block = outcome.block;
        let built_root = built_block.header().inner.state_root;

        // The block header must carry the artifact.
        assert!(
            !built_block.header().inner.extra_data.is_empty(),
            "built block must carry the header artifact in extra_data",
        );

        // Validator path: re-execute the built block.
        let mut validator_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut validator_db, &active_set);
        let validator_state = State::builder()
            .with_database(validator_db)
            .with_bundle_update()
            .build();
        let mut validator_executor = config.batch_executor(validator_state);
        validator_executor
            .execute_one(&built_block)
            .expect("validator path must re-execute the built block");

        let validator_state = validator_executor.into_state();
        let reexecuted_hashed_state = provider.hashed_post_state(&validator_state.bundle_state);
        let (reexecuted_root, _) = provider
            .state_root_with_updates(reexecuted_hashed_state)
            .expect("re-executed state root must be computed");

        assert_eq!(
            built_root, reexecuted_root,
            "block with header artifact must re-execute to the same state root",
        );

        // Reth validates receipt and state roots only after `execute_one`
        // returns. Validator execution must therefore retain no CE candidate,
        // even when execution itself succeeds for a header that the following
        // post-execution check rejects.
        let mut wrong_receipt_block = built_block.clone().into_block();
        wrong_receipt_block.header.inner.receipts_root = B256::repeat_byte(0x71);
        let wrong_receipt_block =
            RecoveredBlock::new_unhashed(wrong_receipt_block, built_block.senders().to_vec());
        let (_receipt_directory, receipt_service) = test_tree_service(parent.hash());
        let receipt_config = config
            .clone()
            .with_compressed_tree_service(receipt_service.clone());
        let mut receipt_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut receipt_db, &active_set);
        let receipt_state = State::builder()
            .with_database(receipt_db)
            .with_bundle_update()
            .build();
        let mut receipt_executor = receipt_config.batch_executor(receipt_state);
        let receipt_result = receipt_executor
            .execute_one(&wrong_receipt_block)
            .expect("wrong receipt root is checked after successful execution");
        let receipt_validation_spec = reth_ethereum::chainspec::ChainSpecBuilder::from(&*MAINNET)
            .byzantium_activated()
            .build();
        assert!(
            reth_ethereum::consensus::validate_block_post_execution(
                &wrong_receipt_block,
                &receipt_validation_spec,
                &receipt_result,
                None,
            )
            .is_err(),
            "the fixture must reach Reth's receipt-root rejection seam",
        );
        assert!(
            receipt_service
                .candidate(
                    wrong_receipt_block.header().inner.number,
                    wrong_receipt_block.hash(),
                )
                .unwrap()
                .is_none(),
            "receipt-invalid validator execution must not publish a CE candidate",
        );

        let mut wrong_state_block = built_block.clone().into_block();
        wrong_state_block.header.inner.state_root = B256::repeat_byte(0x72);
        let wrong_state_block =
            RecoveredBlock::new_unhashed(wrong_state_block, built_block.senders().to_vec());
        let (_state_directory, state_service) = test_tree_service(parent.hash());
        let state_config = config
            .clone()
            .with_compressed_tree_service(state_service.clone());
        let mut state_db = CacheDB::<EmptyDBTyped<ProviderError>>::default();
        seed_active_validators(&mut state_db, &active_set);
        let state = State::builder()
            .with_database(state_db)
            .with_bundle_update()
            .build();
        let mut state_executor = state_config.batch_executor(state);
        state_executor
            .execute_one(&wrong_state_block)
            .expect("wrong state root is checked after successful execution");
        let state = state_executor.into_state();
        let reexecuted_hashed_state = provider.hashed_post_state(&state.bundle_state);
        let (actual_state_root, _) = provider
            .state_root_with_updates(reexecuted_hashed_state)
            .expect("state root must be computed at Reth's validation seam");
        assert_ne!(
            wrong_state_block.header().inner.state_root,
            actual_state_root,
            "the fixture must reach Reth's state-root rejection seam",
        );
        assert!(
            state_service
                .candidate(
                    wrong_state_block.header().inner.number,
                    wrong_state_block.hash(),
                )
                .unwrap()
                .is_none(),
            "state-root-invalid validator execution must not publish a CE candidate",
        );
    }
}
