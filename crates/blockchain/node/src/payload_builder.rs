use std::sync::Arc;

use alloy_consensus::Transaction as _;
use alloy_primitives::{B256, U256};
use alloy_rlp::Encodable as _;
use either::Either;
use outbe_evm::{AccountedParentArtifact, OutbeEvmConfig, OutbeNextBlockEnvAttributes};
use outbe_primitives::{
    consensus::OUTBE_MAX_BLOCK_SIZE,
    error::PrecompileError,
    reshare_artifact::{decode_outbe_block_artifacts, sanitize_prefinal_outbe_block_artifacts},
    runtime_audit_v1::{
        process_instance_id, BODY_READ_REQUEST_DEADLINE, OTHER_PAYLOAD_EXECUTION_FAILURE,
        PAYLOAD_EXECUTION_FAILED, SCHEMA_VERSION,
    },
    system_tx::GENESIS_BOOTSTRAP_BLOCK_NUMBER,
    OutbeBuiltPayload, OutbeHeader, OutbePayloadAttributes, OutbePrimitives, OutbeTxEnvelope,
};
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_chainspec::{ChainSpec, ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_errors::{BlockExecutionError, BlockValidationError, ConsensusError};
use reth_ethereum_payload_builder::EthereumBuilderConfig;
use reth_evm::{
    execute::{BlockBuilder, BlockBuilderOutcome, BlockExecutionOutput, BlockExecutor},
    ConfigureEvm, Evm, NextBlockEnvAttributes, RecoveredTx,
};
use reth_payload_builder::{BlobSidecars, EthBuiltPayload};
use reth_payload_primitives::{BuiltPayloadExecutedBlock, PayloadBuilderError};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_primitives_traits::AlloyBlockHeader as _;
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    error::{Eip4844PoolTransactionError, InvalidPoolTransactionError},
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction,
};
use revm::context_interface::Block as _;
use tracing::{debug, trace, warn};

#[derive(Debug, Clone)]
pub struct OutbePayloadBuilder<Pool, Provider> {
    pool: Pool,
    provider: Provider,
    evm_config: OutbeEvmConfig,
    builder_config: EthereumBuilderConfig,
}

impl<Pool, Provider> OutbePayloadBuilder<Pool, Provider> {
    pub const fn new(
        provider: Provider,
        pool: Pool,
        evm_config: OutbeEvmConfig,
        builder_config: EthereumBuilderConfig,
    ) -> Self {
        Self {
            pool,
            provider,
            evm_config,
            builder_config,
        }
    }
}

impl<Pool, Provider> PayloadBuilder for OutbePayloadBuilder<Pool, Provider>
where
    Provider: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec<OutbeHeader>> + Clone,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = OutbeTxEnvelope>>,
{
    type Attributes = OutbePayloadAttributes;
    type BuiltPayload = OutbeBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        self.build_payload(args, |attrs| {
            self.pool.best_transactions_with_attributes(attrs)
        })
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        MissingPayloadBehaviour::AwaitInProgress
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes, OutbeHeader>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        self.build_payload(
            BuildArguments::new(
                Default::default(),
                Default::default(),
                None,
                config,
                Default::default(),
                None,
            ),
            |_| core::iter::empty(),
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

impl<Pool, Provider> OutbePayloadBuilder<Pool, Provider>
where
    Provider: StateProviderFactory + ChainSpecProvider<ChainSpec = ChainSpec<OutbeHeader>>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = OutbeTxEnvelope>>,
{
    fn build_payload<Txs>(
        &self,
        args: BuildArguments<OutbePayloadAttributes, OutbeBuiltPayload>,
        best_txs: impl FnOnce(BestTransactionsAttributes) -> Txs,
    ) -> Result<BuildOutcome<OutbeBuiltPayload>, PayloadBuilderError>
    where
        Txs: BestTransactions<Item = Arc<ValidPoolTransaction<Pool::Transaction>>>,
    {
        let BuildArguments {
            mut cached_reads,
            execution_cache: _,
            trie_handle,
            config,
            cancel,
            best_payload,
        } = args;
        let PayloadConfig {
            parent_header,
            attributes,
            payload_id,
        } = config;

        let state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        let state = StateProviderDatabase::new(state_provider.as_ref());
        let mut db = State::builder()
            .with_database(cached_reads.as_db_mut(state))
            .with_bundle_update()
            .build();

        let chain_spec = self.provider.chain_spec();
        let inner = attributes.inner();
        let block_number = parent_header.number().saturating_add(1);
        let prefinal_extra_data = sanitize_prefinal_outbe_block_artifacts(attributes.extra_data())
            .map_err(PayloadBuilderError::other)?;

        // / / prebuild and sign the Phase 1
        // (CertifiedParentAccounting) body[0] tx BEFORE the executor enters
        // `apply_pre_execution_changes`. The same `Recovered` is then handed
        // to `build_begin_system_txs` for body[0] so the pre-exec commit
        // witness and the body[0] tx are byte-identical (hash match). For
        // `block_number <= OutbeProtocolSchedule.genesis_bootstrap_block_number`
        // (greenfield: block 0 / block 1) the helper returns `None` and
        // Phase 1 is skipped entirely.
        let prebuilt_phase1_tx = self
            .evm_config
            .build_signed_phase1_tx(
                block_number,
                chain_spec.chain().id(),
                parent_header.hash(),
                attributes.parent_consensus_metadata().cloned(),
                attributes.proposer_evm_address(),
            )
            .map_err(|err| {
                warn!(target: "payload_builder", %err, "failed to prebuild Phase 1 system tx");
                PayloadBuilderError::Internal(err.into())
            })?;

        // decode the parent's accounted-parent artifact from
        // `parent_header.extra_data` so the executor has a fallback when the
        // [`AccountedParentArtifactProvider`] cannot see the parent (e.g.,
        // unfinalized side-chain whose header hasn't been indexed yet). The
        // executor validates this hint against the Phase 1 metadata's
        // `(finalized_block_number, finalized_block_hash)` before accepting it.
        let parent_artifact_hint =
            decode_outbe_block_artifacts(parent_header.extra_data().as_ref())
                .ok()
                .and_then(|artifacts| artifacts.execution_summary)
                .map(|summary| AccountedParentArtifact {
                    summary,
                    timestamp: parent_header.timestamp(),
                    state_root: Some(parent_header.state_root()),
                });

        // One-time TEE bootstrap: the consensus thread's TEE DKG coordination
        // stashes the assembled `TeeBootstrapV2` in the bridge; the proposer
        // clones it here and injects it into the begin-zone (slice 5.1). Only
        // the proposer's bridge is read; validators verify the body-carried
        // payload (slice 5.2). Candidate construction is retryable, so a rejected
        // first candidate must not consume the only copy needed by later views.
        //
        // Guard to block 1 (the fixed `committee_snapshot_block` target): every
        // node stashes its pending payload at startup, but only the block-1
        // proposer must inject it. Without this guard a node that did not propose
        // block 1 would still hold its pending payload and inject a stale
        // `TeeBootstrap` when it later proposes block N > 1 - which the executor
        // rejects (`committee_snapshot_block` mismatch / already bootstrapped),
        // stalling that slot.
        let pending_tee_bootstrap = if block_number == 1 {
            self.evm_config
                .bridge
                .as_ref()
                .and_then(|bridge| bridge.pending_tee_bootstrap())
        } else {
            None
        };

        let mut builder = self
            .evm_config
            .builder_for_next_block(
                &mut db,
                &parent_header,
                OutbeNextBlockEnvAttributes {
                    inner: NextBlockEnvAttributes {
                        timestamp: inner.timestamp,
                        suggested_fee_recipient: inner.suggested_fee_recipient,
                        prev_randao: inner.prev_randao,
                        gas_limit: outbe_primitives::system_tx::protocol_block_gas_limit(
                            block_number,
                        ),
                        parent_beacon_block_root: inner.parent_beacon_block_root,
                        withdrawals: inner.withdrawals.clone().map(Into::into),
                        extra_data: prefinal_extra_data.clone(),
                        slot_number: inner.slot_number,
                    },
                    timestamp_millis_part: attributes.timestamp_millis_part(),
                    parent_consensus_metadata: attributes.parent_consensus_metadata().cloned(),
                    proposer_evm_address: attributes.proposer_evm_address(),
                    execute_outbe_block_hooks: true,
                    prebuilt_phase1_tx: prebuilt_phase1_tx.clone(),
                    parent_artifact_hint,
                    // Clone: the executor branch (expected begin-zone order /
                    // `block_has_tee_bootstrap`) needs the same payload the body
                    // builder injects below, so both deterministic paths agree.
                    pending_tee_bootstrap: pending_tee_bootstrap.clone(),
                    execution_read_budget: attributes.execution_read_budget().cloned(),
                },
            )
            .map_err(PayloadBuilderError::other)?;
        let compressed_tree_service = self.evm_config.compressed_tree_service();

        debug!(
            target: "payload_builder",
            id = %payload_id,
            parent_hash = ?parent_header.hash(),
            parent_number = parent_header.number(),
            timestamp_millis = attributes.timestamp_millis(),
            "building Outbe payload"
        );

        let mut cumulative_gas_used = 0u64;
        let block_gas_limit = builder.evm_mut().block().gas_limit();
        let base_fee = builder.evm_mut().block().basefee();

        let mut best_txs = best_txs(BestTransactionsAttributes::new(
            base_fee,
            builder
                .evm_mut()
                .block()
                .blob_gasprice()
                .map(|gasprice| gasprice as u64),
        ));
        let mut total_fees = U256::ZERO;

        if let Some(ref handle) = trie_handle {
            builder
                .executor_mut()
                .set_state_hook(Some(Box::new(handle.state_hook())));
        }

        if let Err(err) = builder.apply_pre_execution_changes() {
            if ce_local_readiness_error(&err) {
                // This attempt raced finalization and cannot use the in-place
                // materialization for its old parent. Report a retryable build
                // failure: Reth reserves `BuildOutcome::Cancelled` for futures
                // whose supplied cancel signal actually fired and treats any
                // other use as an unreachable invariant violation.
                debug!(target: "payload_builder", %err, "payload exact-parent data is no longer locally available; retrying on the next build tick");
                return Err(PayloadBuilderError::Internal(err.into()));
            }
            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
            return Err(PayloadBuilderError::Internal(err.into()));
        }

        let mut blob_sidecars = BlobSidecars::Empty;
        let mut block_blob_count = 0u64;
        let mut block_transactions_rlp_length = 0usize;
        let blob_params = chain_spec.blob_params_at_timestamp(inner.timestamp);
        let protocol_max_blob_count = blob_params
            .as_ref()
            .map(|params| params.max_blob_count)
            .unwrap_or_default();
        let max_blob_count = self
            .builder_config
            .max_blobs_per_block
            .map(|user_limit| std::cmp::min(user_limit, protocol_max_blob_count).max(1))
            .unwrap_or(protocol_max_blob_count);
        let is_osaka = chain_spec.is_osaka_active_at_timestamp(inner.timestamp);
        let withdrawals_rlp_length = inner
            .withdrawals
            .as_ref()
            .map(|withdrawals| withdrawals.length())
            .unwrap_or(0);

        let begin_system_txs = self
            .evm_config
            .build_begin_system_txs(
                block_number,
                chain_spec.chain().id(),
                block_gas_limit,
                parent_header.hash(),
                &prefinal_extra_data,
                attributes.parent_consensus_metadata().cloned(),
                attributes.proposer_evm_address(),
                // reuse the prebuilt body[0] tx
                // byte-for-byte. `build_begin_system_txs` validates
                // calldata + signer match before substitution.
                prebuilt_phase1_tx,
                // The same bootstrap payload the executor branch above received,
                // so the injected body matches the expected begin-zone order
                // (TeeBootstrap at begin_order 3, before OracleSlashWindow).
                pending_tee_bootstrap,
            )
            .map_err(|err| {
                warn!(target: "payload_builder", %err, "failed to build begin system transactions");
                PayloadBuilderError::Internal(err.into())
            })?;
        let begin_system_tx_count = begin_system_txs.len();
        let end_system_txs = self
            .evm_config
            .build_end_system_txs(
                block_number,
                chain_spec.chain().id(),
                begin_system_tx_count,
                attributes.proposer_evm_address(),
            )
            .map_err(|err| {
                warn!(target: "payload_builder", %err, "failed to build end system transactions");
                PayloadBuilderError::Internal(err.into())
            })?;
        let reserved_end_gas = end_system_txs
            .iter()
            .try_fold(0u64, |total, tx| total.checked_add(tx.tx().gas_limit()))
            .ok_or_else(|| {
                PayloadBuilderError::other(std::io::Error::other(
                    "end system transaction gas overflow",
                ))
            })?;
        let reserved_end_rlp_length = end_system_txs
            .iter()
            .try_fold(0usize, |total, tx| total.checked_add(tx.inner().length()))
            .ok_or_else(|| {
                PayloadBuilderError::other(std::io::Error::other(
                    "end system transaction size overflow",
                ))
            })?;
        for tx in begin_system_txs {
            if cancel.is_cancelled() {
                return Ok(BuildOutcome::Cancelled);
            }
            let tx_rlp_len = tx.inner().length();
            let gas_used = builder
                .execute_transaction(tx)
                .map_err(|err| {
                    warn!(target: "payload_builder", %err, "failed to execute begin system transaction");
                    PayloadBuilderError::Internal(err.into())
                })?
                .tx_gas_used();
            block_transactions_rlp_length += tx_rlp_len;
            cumulative_gas_used = cumulative_gas_used.saturating_add(gas_used);
            trace!(
                target: "payload_builder",
                gas_used,
                "included begin system transaction"
            );
        }

        if block_number != GENESIS_BOOTSTRAP_BLOCK_NUMBER {
            while let Some(pool_tx) = best_txs.next() {
                if cumulative_gas_used
                    .saturating_add(pool_tx.gas_limit())
                    .saturating_add(reserved_end_gas)
                    > block_gas_limit
                {
                    best_txs.mark_invalid(
                        &pool_tx,
                        &InvalidPoolTransactionError::ExceedsGasLimit(
                            pool_tx.gas_limit(),
                            block_gas_limit,
                        ),
                    );
                    continue;
                }

                if cancel.is_cancelled() {
                    return Ok(BuildOutcome::Cancelled);
                }

                let tx = pool_tx.to_consensus();
                let tx_rlp_len = tx.inner().length();
                let estimated_block_size = block_transactions_rlp_length
                    + tx_rlp_len
                    + reserved_end_rlp_length
                    + withdrawals_rlp_length
                    + 1024;

                if is_osaka && estimated_block_size > MAX_RLP_BLOCK_SIZE {
                    best_txs.mark_invalid(
                        &pool_tx,
                        &InvalidPoolTransactionError::OversizedData {
                            size: estimated_block_size,
                            limit: MAX_RLP_BLOCK_SIZE,
                        },
                    );
                    continue;
                }

                // Outbe transport cap (always on, independent of the Osaka fork): a
                // block must fit one consensus P2P message. Skip txs that would push
                // the block over `OUTBE_MAX_BLOCK_SIZE` so the proposer never builds
                // a block validators would reject as undisseminable.
                if estimated_block_size > OUTBE_MAX_BLOCK_SIZE {
                    best_txs.mark_invalid(
                        &pool_tx,
                        &InvalidPoolTransactionError::OversizedData {
                            size: estimated_block_size,
                            limit: OUTBE_MAX_BLOCK_SIZE,
                        },
                    );
                    continue;
                }

                let mut blob_tx_sidecar = None;
                let tx_blob_count = tx.blob_count();
                if let Some(tx_blob_count) = tx_blob_count {
                    if block_blob_count + tx_blob_count > max_blob_count {
                        best_txs.mark_invalid(
                            &pool_tx,
                            &InvalidPoolTransactionError::Eip4844(
                                Eip4844PoolTransactionError::TooManyEip4844Blobs {
                                    have: block_blob_count + tx_blob_count,
                                    permitted: max_blob_count,
                                },
                            ),
                        );
                        continue;
                    }

                    let sidecar = match self
                        .pool
                        .get_blob(*tx.hash())
                        .map_err(PayloadBuilderError::other)?
                    {
                        Some(sidecar) if is_osaka && sidecar.is_eip7594() => Some(sidecar),
                        Some(sidecar) if !is_osaka && sidecar.is_eip4844() => Some(sidecar),
                        Some(sidecar) if is_osaka && !sidecar.is_eip7594() => {
                            best_txs.mark_invalid(
                                &pool_tx,
                                &InvalidPoolTransactionError::Eip4844(
                                    Eip4844PoolTransactionError::UnexpectedEip4844SidecarAfterOsaka,
                                ),
                            );
                            trace!(target: "payload_builder", ?sidecar, "skipping unexpected pre-Osaka sidecar");
                            continue;
                        }
                        Some(_) => {
                            best_txs.mark_invalid(
                            &pool_tx,
                            &InvalidPoolTransactionError::Eip4844(
                                Eip4844PoolTransactionError::UnexpectedEip7594SidecarBeforeOsaka,
                            ),
                        );
                            continue;
                        }
                        None => {
                            best_txs.mark_invalid(
                                &pool_tx,
                                &InvalidPoolTransactionError::Eip4844(
                                    Eip4844PoolTransactionError::MissingEip4844BlobSidecar,
                                ),
                            );
                            continue;
                        }
                    };
                    blob_tx_sidecar = sidecar;
                }

                let miner_fee = tx.effective_tip_per_gas(base_fee);
                let tx_hash = *tx.tx_hash();
                let gas_used = match builder.execute_transaction(tx) {
                    Ok(gas_used) => gas_used.tx_gas_used(),
                    Err(err)
                        if matches!(
                            ce_work_admission_error(&err),
                            Some(PrecompileError::BlockCeWorkCapacityExhausted)
                        ) =>
                    {
                        trace!(target: "payload_builder", ?tx_hash, "deferring transaction because the payload CE work budget is exhausted");
                        continue;
                    }
                    Err(err)
                        if matches!(
                            ce_work_admission_error(&err),
                            Some(PrecompileError::TransactionCeWorkLimitExceeded)
                        ) =>
                    {
                        trace!(target: "payload_builder", ?tx_hash, "skipping transaction that cannot fit the full CE work limit");
                        continue;
                    }
                    Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                        error,
                        ..
                    })) => {
                        if !error.is_nonce_too_low() {
                            best_txs.mark_invalid(
                                &pool_tx,
                                &InvalidPoolTransactionError::Consensus(
                                    InvalidTransactionError::TxTypeNotSupported,
                                ),
                            );
                        }
                        trace!(target: "payload_builder", %error, ?tx_hash, "skipping invalid transaction");
                        continue;
                    }
                    Err(err) => {
                        let failure_kind = payload_execution_failure_kind(&err);
                        debug!(
                            target: "payload_builder",
                            audit_schema = SCHEMA_VERSION,
                            audit_event = %PAYLOAD_EXECUTION_FAILED,
                            process_instance = %process_instance_id(),
                            payload_id = %payload_id,
                            ?tx_hash,
                            failure_kind = %failure_kind,
                            %err,
                            "payload transaction execution failed"
                        );
                        return Err(PayloadBuilderError::evm(err));
                    }
                };

                if let Some(blob_count) = tx_blob_count {
                    block_blob_count += blob_count;
                    if block_blob_count == max_blob_count {
                        best_txs.skip_blobs();
                    }
                }

                block_transactions_rlp_length += tx_rlp_len;
                let miner_fee = miner_fee.unwrap_or_default();
                total_fees += U256::from(miner_fee) * U256::from(gas_used);
                cumulative_gas_used += gas_used;

                if let Some(sidecar) = blob_tx_sidecar {
                    blob_sidecars.push_sidecar_variant(sidecar.as_ref().clone());
                }
            }
        }

        if !is_better_payload(best_payload.as_ref(), total_fees) {
            drop(builder);
            return Ok(BuildOutcome::Aborted {
                fees: total_fees,
                cached_reads,
            });
        }

        for tx in end_system_txs {
            if cancel.is_cancelled() {
                return Ok(BuildOutcome::Cancelled);
            }
            let gas_used = builder
                .execute_transaction(tx)
                .map_err(|err| {
                    warn!(target: "payload_builder", %err, "failed to execute end system transaction");
                    PayloadBuilderError::Internal(err.into())
                })?
                .tx_gas_used();
            cumulative_gas_used = cumulative_gas_used.saturating_add(gas_used);
            trace!(
                target: "payload_builder",
                gas_used,
                "included end system transaction"
            );
        }

        let outcome = if let Some(mut handle) = trie_handle {
            // CE end-block cleanup is consensus state. Deliver its zeroing
            // changes to the parallel trie task before detaching the hook and
            // freezing the precomputed root.
            if !self.evm_config.ocomp_lifecycle_active_at(block_number) {
                builder
                    .executor_mut()
                    .finalize_compressed_entities()
                    .map_err(PayloadBuilderError::evm)?;
            }
            builder
                .executor_mut()
                .prepare_final_header_artifacts(attributes.timestamp_millis_part())
                .map_err(PayloadBuilderError::evm)?;
            builder.executor_mut().set_state_hook(None);
            match handle.state_root() {
                Ok(outcome) => builder.finish(
                    state_provider.as_ref(),
                    Some((
                        outcome.state_root,
                        Arc::unwrap_or_clone(outcome.trie_updates),
                    )),
                )?,
                Err(err) => {
                    warn!(target: "payload_builder", id=%payload_id, %err, "sparse trie failed, falling back to sync state root");
                    builder.finish(state_provider.as_ref(), None)?
                }
            }
        } else {
            builder.finish(state_provider.as_ref(), None)?
        };

        let BlockBuilderOutcome {
            execution_result,
            hashed_state,
            trie_updates,
            block,
        } = outcome;

        let requests = chain_spec
            .is_prague_active_at_timestamp(inner.timestamp)
            .then_some(execution_result.requests.clone());

        // capture the full execution result of the block we just built so
        // the proposer does NOT re-execute and re-root it at finalize time.
        // `builder` only borrowed `&mut db`, so after `finish` the merged
        // post-state bundle is back on our local `db` and can be taken here.
        // Reth's launch loop inserts `executed_block()` into the engine tree, so
        // `ExecutorActor`'s finalize-time `new_payload` becomes a cache hit
        // (validators already get this via their verify-time `new_payload`).
        // This is the SAME execution that produced the sealed block below, so the
        // cached state matches the sealed block hash exactly - no proposer/
        // validator divergence.
        let recovered_block = Arc::new(block);
        let execution_output = Arc::new(BlockExecutionOutput {
            state: db.take_bundle(),
            result: execution_result,
        });
        let executed_block = BuiltPayloadExecutedBlock::<OutbePrimitives> {
            recovered_block: recovered_block.clone(),
            execution_output,
            hashed_state: Either::Left(Arc::new(hashed_state)),
            trie_updates: Either::Left(Arc::new(trie_updates)),
        };

        let sealed_block = Arc::new(recovered_block.sealed_block().clone());

        if is_osaka && sealed_block.rlp_length() > MAX_RLP_BLOCK_SIZE {
            discard_failed_payload_candidate(
                compressed_tree_service.as_ref(),
                recovered_block.header().inner.number,
                recovered_block.hash(),
            )?;
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: sealed_block.rlp_length(),
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        // Outbe transport cap (always on): the sealed block must fit one
        // consensus P2P message. Final guard in case the per-tx estimate
        // undershot (e.g. system txs / extra_data added after selection).
        if sealed_block.rlp_length() > OUTBE_MAX_BLOCK_SIZE {
            discard_failed_payload_candidate(
                compressed_tree_service.as_ref(),
                recovered_block.header().inner.number,
                recovered_block.hash(),
            )?;
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: sealed_block.rlp_length(),
                max_rlp_length: OUTBE_MAX_BLOCK_SIZE,
            }));
        }

        let inner =
            EthBuiltPayload::<OutbePrimitives>::new(sealed_block, total_fees, requests, None)
                .with_sidecars(blob_sidecars);
        let payload = OutbeBuiltPayload::new(inner, Some(executed_block));

        Ok(BuildOutcome::Better {
            payload,
            cached_reads,
        })
    }
}

fn discard_failed_payload_candidate(
    service: Option<&Arc<outbe_compressed_entities::CompressedTreeService>>,
    block_number: u64,
    block_hash: B256,
) -> Result<(), PayloadBuilderError> {
    if let Some(service) = service {
        service
            .discard_candidate(block_number, block_hash)
            .map_err(PayloadBuilderError::other)?;
    }
    Ok(())
}

fn ce_work_admission_error(error: &BlockExecutionError) -> Option<&PrecompileError> {
    error.as_internal()?.downcast_other::<PrecompileError>()
}

fn payload_execution_failure_kind(error: &BlockExecutionError) -> &'static str {
    if matches!(
        ce_work_admission_error(error),
        Some(PrecompileError::BodyReadRequestDeadline)
    ) {
        BODY_READ_REQUEST_DEADLINE
    } else {
        OTHER_PAYLOAD_EXECUTION_FAILURE
    }
}

fn ce_local_readiness_error(error: &BlockExecutionError) -> bool {
    matches!(
        ce_work_admission_error(error),
        Some(PrecompileError::TreeUnavailable(_))
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    use super::*;
    use alloy_consensus::{SignableTransaction as _, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{address, keccak256, Bytes, Signature, TxKind};
    use alloy_rpc_types_engine::PayloadId;
    use outbe_compressed_entities::{
        CandidateCacheLimits, CeMdbx, CompressedTreeService, EnvironmentIdentity,
        ExactParentIdentity, FinalizedMarker, ACTIVE_COMMITMENT_SCHEME,
        LOCAL_STORAGE_SCHEMA_VERSION,
    };
    use outbe_primitives::runtime_audit_v1::{
        BODY_READ_REQUEST_DEADLINE, OTHER_PAYLOAD_EXECUTION_FAILURE,
    };

    use outbe_evm::{
        system_tx::{split_system_layout, system_tx_intrinsic_gas, SystemTxKind},
        OutbeEvmSigner,
    };
    use outbe_metadosis::test_support::ForkInstallScenario;
    use outbe_offchain_data::RuntimeBodyReaders;
    use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
    use outbe_primitives::{
        addresses::{COMPRESSED_ENTITIES_ADDRESS, REWARDS_ADDRESS},
        block::{BlockContext, BlockRuntimeContext},
        consensus::{ConsensusExecutionBridge, DkgBoundaryArtifact, ReshareResult},
        projection::ExecutionReadBudget,
        reshare_artifact::{
            encode_outbe_block_artifacts, ConsensusHeaderArtifact, OutbeBlockArtifacts,
        },
        storage::{hashmap::HashMapStorageProvider, MetadosisMutationPurposeTag, StorageHandle},
        tee_genesis_v1::GRAMINE_DIRECT_DEV_CHAIN_ID,
        units::SCALE_1E6_U256,
    };
    use reth_chainspec::{ChainSpecBuilder, EthereumHardfork, ForkCondition};
    use reth_evm::execute::Executor as _;
    use reth_payload_primitives::BuiltPayload as _;
    use reth_primitives_traits::{SealedHeader, SignedTransaction as _};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        identifier::{SenderId, TransactionId},
        noop::NoopTransactionPool,
        EthPooledTransaction, TransactionOrigin,
    };

    type TestPool = NoopTransactionPool<EthPooledTransaction>;
    type TestProvider = MockEthProvider<OutbePrimitives, ChainSpec<OutbeHeader>>;
    const TEST_CONSENSUS_PUBLIC_KEY: [u8; 48] = [0x11; 48];

    #[test]
    fn payload_failure_kind_is_structural_and_stable() {
        let deadline = BlockExecutionError::other(PrecompileError::BodyReadRequestDeadline);
        let other = BlockExecutionError::msg("unclassified payload failure");

        assert_eq!(
            payload_execution_failure_kind(&deadline),
            BODY_READ_REQUEST_DEADLINE
        );
        assert_eq!(
            payload_execution_failure_kind(&other),
            OTHER_PAYLOAD_EXECUTION_FAILURE
        );
    }

    struct TestBestTransactions {
        transactions: std::vec::IntoIter<Arc<ValidPoolTransaction<EthPooledTransaction>>>,
        rejected: Arc<AtomicUsize>,
    }

    impl TestBestTransactions {
        fn one(
            transaction: Arc<ValidPoolTransaction<EthPooledTransaction>>,
            rejected: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                transactions: vec![transaction].into_iter(),
                rejected,
            }
        }
    }

    impl Iterator for TestBestTransactions {
        type Item = Arc<ValidPoolTransaction<EthPooledTransaction>>;

        fn next(&mut self) -> Option<Self::Item> {
            self.transactions.next()
        }
    }

    impl BestTransactions for TestBestTransactions {
        fn mark_invalid(&mut self, _transaction: &Self::Item, kind: &InvalidPoolTransactionError) {
            assert!(
                matches!(kind, InvalidPoolTransactionError::ExceedsGasLimit(_, _)),
                "boundary transaction must only be rejected by the gas reservation: {kind}"
            );
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }

        fn no_updates(&mut self) {}

        fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
    }

    fn active_set_hash(addresses: &[alloy_primitives::Address]) -> B256 {
        let mut bytes = Vec::with_capacity(8 + addresses.len() * 20);
        bytes.extend_from_slice(&(addresses.len() as u64).to_be_bytes());
        for address in addresses {
            bytes.extend_from_slice(address.as_slice());
        }
        keccak256(bytes)
    }

    fn genesis_boundary_artifacts(proposer: alloy_primitives::Address) -> (Bytes, B256) {
        let active_set = vec![proposer];
        let vrf_group_public_key_bytes = vec![0x42u8; 96];
        let snapshot = outbe_validatorset::CommitteeSnapshot {
            committee: vec![outbe_validatorset::CommitteeEntry {
                address: proposer,
                consensus_pubkey: TEST_CONSENSUS_PUBLIC_KEY,
            }],
            vrf_material_version: 0,
            vrf_group_public_key_bytes: vrf_group_public_key_bytes.clone(),
            vrf_public_polynomial_hash: B256::ZERO,
        };
        let committee_snapshot_hash = outbe_validatorset::committee_set_hash_v2(0, &snapshot);
        let artifacts = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            execution_summary: None,
            consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(
                DkgBoundaryArtifact {
                    epoch: 0,
                    dkg_cycle: 0,
                    freeze_height: 0,
                    planned_activation_height: 1,
                    target_set_hash: B256::ZERO,
                    vrf_material_version: 0,
                    vrf_group_public_key: keccak256(&vrf_group_public_key_bytes),
                    vrf_group_public_key_bytes: Bytes::from(vrf_group_public_key_bytes),
                    committee_set_hash: committee_snapshot_hash,
                    is_validator_set_change: true,
                    outcome: Bytes::new(),
                    is_full_dkg: false,
                    tee_recipient_pubkeys: Vec::new(),
                    tee_expired_target_exclusions: Vec::new(),
                    tee_expired_target_exclusions_hash: B256::ZERO,
                    reshare: ReshareResult {
                        active_set_hash: active_set_hash(&active_set),
                        new_active_set: active_set,
                    },
                },
            )),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        })
        .expect("genesis boundary artifacts encode");
        (artifacts, committee_snapshot_hash)
    }

    fn genesis_dev_tee_bootstrap(
        chain_id: u64,
        genesis_hash: B256,
        committee_snapshot_hash: B256,
    ) -> outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2 {
        use outbe_primitives::tee_test_utils::{
            gramine_direct_bootstrap_v2, gramine_direct_policy_v1, DevValidatorV1,
        };

        let policy = gramine_direct_policy_v1(chain_id, genesis_hash)
            .expect("test GramineDirectDev policy is canonical");
        gramine_direct_bootstrap_v2(
            policy,
            committee_snapshot_hash,
            1,
            ACTIVE_PAYLOAD_BLOCK_TIMESTAMP + 7_200,
            &[DevValidatorV1 {
                evm_secret: outbe_primitives::test_keys::secret(1),
                bls_minpk_public: TEST_CONSENSUS_PUBLIC_KEY,
            }],
        )
        .expect("test GramineDirectDev OST3 payload is canonical")
    }

    fn active_ocomp_provider(
        chain_spec: &Arc<ChainSpec<OutbeHeader>>,
        proposer: alloy_primitives::Address,
        funded_user: alloy_primitives::Address,
        genesis_hash: B256,
    ) -> TestProvider {
        const OWNER: alloy_primitives::Address =
            address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

        let mut seed =
            HashMapStorageProvider::new_with_chain_identity(chain_spec.chain().id(), genesis_hash);
        seed.set_block_number(1);
        seed.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::ForkProfile);
        StorageHandle::enter(&mut seed, |storage| {
            let root = outbe_compressed_entities::sealed_root(B256::ZERO)
                .expect("CE genesis root is deterministic");
            storage
                .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
                .expect("CE schema version seed succeeds");
            storage
                .sstore(
                    COMPRESSED_ENTITIES_ADDRESS,
                    U256::from(1),
                    U256::from_be_slice(root.as_slice()),
                )
                .expect("CE genesis root seed succeeds");

            let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            validators
                .config_owner
                .write(OWNER)
                .expect("validator owner seed succeeds");
            validators
                .config_max_validators
                .write(128)
                .expect("validator capacity seed succeeds");
            validators
                .config_epoch_length_blocks
                .write(60)
                .expect("validator epoch seed succeeds");
            validators
                .config_is_initialized
                .write(true)
                .expect("validator initialization seed succeeds");
            validators
                .register_validator(OWNER, proposer, &TEST_CONSENSUS_PUBLIC_KEY)
                .expect("proposer registration seed succeeds");
            validators
                .activate_validator_via_boundary_for_test(proposer)
                .expect("active proposer reaches production boundary activation");
            let founder_registration = validators
                .ocomp_registration(proposer)
                .expect("active proposer OCOMP registration is readable")
                .expect("active proposer has OCOMP registration");

            let mut install =
                ForkInstallScenario::measurement_at(1, chain_spec.chain().id(), genesis_hash)
                    .expect("fresh-devnet OCOMP install fixture is canonical")
                    .into_install();
            install.founder_registrations = vec![founder_registration];
            let install_ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(
                    1,
                    ACTIVE_PAYLOAD_BLOCK_TIMESTAMP,
                    chain_spec.chain().id(),
                ),
                storage.clone(),
            );
            // Fork installation validates the required day-type pair, so the
            // test genesis must register it before installing the profile.
            outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .expect("oracle pair seed succeeds");
            outbe_metadosis::commands::install_fork_profile(&install_ctx, &install)
                .expect("fresh-devnet OCOMP profile installs through the production command");

            outbe_oracle::api::set_exchange_rate(
                storage,
                alloy_primitives::Address::ZERO,
                outbe_oracle::api::DAY_TYPE_PAIR,
                SCALE_1E6_U256,
                0,
                0,
            )
            .expect("oracle rate seed succeeds");
        });

        let provider =
            MockEthProvider::<OutbePrimitives>::new().with_chain_spec(chain_spec.as_ref().clone());
        let mut accounts: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for ((account, slot), value) in seed.storage {
            accounts
                .entry(account)
                .or_default()
                .push((B256::from(slot.to_be_bytes::<32>()), value));
        }
        for (account, storage) in accounts {
            provider.add_account(
                account,
                ExtendedAccount::new(0, U256::ZERO)
                    .with_bytecode(Bytes::from_static(&[0xef]))
                    .extend_storage(storage),
            );
        }
        provider.add_account(
            funded_user,
            ExtendedAccount::new(0, U256::from(100_000_000_000_000_000_000u128)),
        );
        provider
    }

    const ACTIVE_PAYLOAD_BLOCK_GAS_LIMIT: u64 = 500_000_000;
    const ACTIVE_PAYLOAD_BLOCK_TIMESTAMP: u64 = 1_700_000_000;

    struct ActivePayloadCase {
        payloads: Vec<OutbeBuiltPayload>,
        evm_config: OutbeEvmConfig,
        provider: TestProvider,
        rejected: Arc<AtomicUsize>,
    }

    fn build_active_payload_case(
        user_gas_over_boundary: u64,
        proposal_attempts: usize,
    ) -> ActivePayloadCase {
        assert!(
            proposal_attempts > 0,
            "test must build at least one proposal"
        );
        use outbe_primitives::tee_test_utils::{
            gramine_direct_policy_v1, tee_attestation_v1_extra_field,
        };

        let mut chain_spec = ChainSpecBuilder::mainnet()
            .with_fork(EthereumHardfork::Paris, ForkCondition::Block(0))
            .build();
        chain_spec.chain = GRAMINE_DIRECT_DEV_CHAIN_ID.into();
        chain_spec.genesis.config.chain_id = GRAMINE_DIRECT_DEV_CHAIN_ID;
        let policy = gramine_direct_policy_v1(chain_spec.chain().id(), chain_spec.genesis_hash())
            .expect("test GramineDirectDev policy is canonical");
        chain_spec.genesis.config.extra_fields.insert(
            "teeAttestationV1".to_owned(),
            tee_attestation_v1_extra_field(&policy)
                .expect("test TEE activation manifest is canonical"),
        );
        let chain_spec: Arc<ChainSpec<OutbeHeader>> =
            chain_spec.map_header(OutbeHeader::new).into();
        let signer = Arc::new(
            OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(1))
                .expect("test proposer key is valid"),
        );
        let proposer = signer.address();
        let (prefinal_extra_data, committee_snapshot_hash) = genesis_boundary_artifacts(proposer);
        let bridge = ConsensusExecutionBridge::new();
        let bootstrap = genesis_dev_tee_bootstrap(
            chain_spec.chain().id(),
            chain_spec.genesis_hash(),
            committee_snapshot_hash,
        );
        bridge.set_pending_tee_bootstrap(bootstrap.clone());
        let body_storage: StorageReaderHandle = Arc::new(MemoryStorage::new());
        let evm_config = OutbeEvmConfig::new_with_bridge_and_runtime_body_readers(
            chain_spec.clone(),
            bridge,
            RuntimeBodyReaders::new(body_storage),
        )
        .with_evm_signer(signer);
        let parent = Arc::new(SealedHeader::seal_slow(OutbeHeader::new(
            alloy_consensus::Header {
                number: 0,
                gas_limit: ACTIVE_PAYLOAD_BLOCK_GAS_LIMIT,
                timestamp: ACTIVE_PAYLOAD_BLOCK_TIMESTAMP - 1,
                base_fee_per_gas: Some(1_000_000_000),
                ..Default::default()
            },
        )));

        let begin = evm_config
            .build_begin_system_txs(
                1,
                chain_spec.chain().id(),
                ACTIVE_PAYLOAD_BLOCK_GAS_LIMIT,
                parent.hash(),
                &prefinal_extra_data,
                None,
                Some(proposer),
                None,
                Some(bootstrap),
            )
            .expect("active begin zone builds");
        let end = evm_config
            .build_end_system_txs(1, chain_spec.chain().id(), begin.len(), Some(proposer))
            .expect("active terminal zone builds");
        assert!(end.is_empty());
        let begin_visible_gas = begin
            .iter()
            .map(|transaction| {
                system_tx_intrinsic_gas(transaction.tx().input().as_ref())
                    .expect("system transaction has valid intrinsic gas")
            })
            .sum::<u64>();
        let admission_boundary_gas = ACTIVE_PAYLOAD_BLOCK_GAS_LIMIT
            .checked_sub(begin_visible_gas)
            .expect("system zones fit inside the block gas limit");
        let candidate_gas_limit = admission_boundary_gas
            .checked_add(user_gas_over_boundary)
            .expect("test boundary delta fits u64");

        let user_tx: reth_ethereum::TransactionSigned = TxEip1559 {
            chain_id: chain_spec.chain().id(),
            nonce: 0,
            gas_limit: candidate_gas_limit,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")),
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into();
        let encoded_length = user_tx.encode_2718_len();
        let recovered_user = user_tx
            .try_into_recovered()
            .expect("test user signature recovers");
        let user_sender = alloy_primitives::Address::from(*recovered_user.signer());
        let pooled_user = Arc::new(ValidPoolTransaction {
            transaction: EthPooledTransaction::new(recovered_user, encoded_length),
            transaction_id: TransactionId::new(SenderId::from(1), 0),
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::Local,
            authority_ids: None,
        });

        let provider = active_ocomp_provider(&chain_spec, proposer, user_sender, parent.hash());
        let payload_builder = OutbePayloadBuilder::new(
            provider.clone(),
            TestPool::new(),
            evm_config.clone(),
            EthereumBuilderConfig::new().with_gas_limit(ACTIVE_PAYLOAD_BLOCK_GAS_LIMIT),
        );
        let attributes = OutbePayloadAttributes::new(
            REWARDS_ADDRESS,
            ACTIVE_PAYLOAD_BLOCK_TIMESTAMP * 1000,
            B256::repeat_byte(0x44),
            None,
            prefinal_extra_data,
            None,
            Some(proposer),
        )
        .with_execution_read_budget(ExecutionReadBudget::new());
        let payload_config = PayloadConfig::new(parent, attributes, PayloadId::new([0x07; 8]));
        let rejected = Arc::new(AtomicUsize::new(0));
        let mut payloads = Vec::with_capacity(proposal_attempts);
        for _ in 0..proposal_attempts {
            let rejected_by_builder = rejected.clone();
            let pooled_user = pooled_user.clone();
            let outcome = payload_builder
                .build_payload(
                    BuildArguments::new(
                        Default::default(),
                        Default::default(),
                        None,
                        payload_config.clone(),
                        Default::default(),
                        None,
                    ),
                    |_| TestBestTransactions::one(pooled_user, rejected_by_builder),
                )
                .expect("every block-1 proposal attempt must retain the OST3 payload");
            payloads.push(
                outcome
                    .into_payload()
                    .expect("production payload builder returns a payload"),
            );
        }

        ActivePayloadCase {
            payloads,
            evm_config,
            provider,
            rejected,
        }
    }

    #[test]
    fn bootstrap_payload_builder_ignores_nonempty_pool_and_replays_exactly() {
        let case = build_active_payload_case(0, 1);
        let payload = &case.payloads[0];
        let body = &payload.block().body().transactions;
        let layout = split_system_layout(body).expect("built payload has canonical system layout");

        assert_eq!(
            layout.begin_block_kinds().expect("begin inputs decode"),
            vec![
                SystemTxKind::CycleTick,
                SystemTxKind::RewardsGemDelivery,
                SystemTxKind::BoundaryOutcome,
                SystemTxKind::TeeBootstrap,
                SystemTxKind::OracleSlashWindow,
                SystemTxKind::HookEvents,
            ]
        );
        assert!(layout.user.is_empty());
        assert!(layout.end.is_empty());

        let executed = payload
            .executed_block()
            .expect("builder exposes the exact executed payload");
        let receipts = &executed.execution_output.result.receipts;
        assert_eq!(receipts.len(), body.len());
        assert_eq!(receipts.len(), 6);
        assert_eq!(case.rejected.load(Ordering::Relaxed), 0);

        let replay = case
            .evm_config
            .executor(StateProviderDatabase::new(&case.provider))
            .execute(executed.recovered_block.as_ref())
            .expect("validator replay succeeds");
        assert_eq!(
            replay, *executed.execution_output,
            "proposer and validator replay must produce identical receipts, gas, requests, and state"
        );
    }

    #[test]
    fn bootstrap_payload_builder_does_not_even_evaluate_oversized_pool_candidate() {
        let case = build_active_payload_case(1, 1);
        let payload = &case.payloads[0];
        let body = &payload.block().body().transactions;
        let layout = split_system_layout(body).expect("built payload has canonical system layout");

        assert!(
            layout.user.is_empty(),
            "the candidate that consumes one unit of OSR2 reserve must not enter the block"
        );
        assert!(layout.end.is_empty());
        assert_eq!(case.rejected.load(Ordering::Relaxed), 0);

        let executed = payload
            .executed_block()
            .expect("builder exposes the exact executed payload");
        let replay = case
            .evm_config
            .executor(StateProviderDatabase::new(&case.provider))
            .execute(executed.recovered_block.as_ref())
            .expect("validator replay succeeds");
        assert_eq!(
            replay, *executed.execution_output,
            "the block that rejected the boundary+1 user must replay exactly"
        );
    }

    #[test]
    fn bootstrap_payload_survives_repeated_block_one_proposal_attempts() {
        let case = build_active_payload_case(0, 2);
        let first_body = &case.payloads[0].block().body().transactions;
        let retry_body = &case.payloads[1].block().body().transactions;

        assert_eq!(
            retry_body, first_body,
            "a rejected block-1 candidate must not consume the mandatory OST3 payload"
        );
        assert_eq!(
            split_system_layout(retry_body)
                .expect("retry payload has canonical system layout")
                .begin_block_kinds()
                .expect("retry begin inputs decode"),
            vec![
                SystemTxKind::CycleTick,
                SystemTxKind::RewardsGemDelivery,
                SystemTxKind::BoundaryOutcome,
                SystemTxKind::TeeBootstrap,
                SystemTxKind::OracleSlashWindow,
                SystemTxKind::HookEvents,
            ]
        );
    }

    fn tree_service() -> (tempfile::TempDir, Arc<CompressedTreeService>) {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x11);
        let db = CeMdbx::open(
            directory.path(),
            EnvironmentIdentity {
                local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
                chain_id: 1,
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
        )
        .unwrap();
        let service = CompressedTreeService::new(
            db,
            CandidateCacheLimits {
                max_candidates: 4,
                max_encoded_bytes: 1_000_000,
            },
        )
        .unwrap();
        (directory, Arc::new(service))
    }

    #[test]
    fn typed_ce_capacity_errors_survive_the_executor_boundary() {
        for expected in [
            PrecompileError::BlockCeWorkCapacityExhausted,
            PrecompileError::TransactionCeWorkLimitExceeded,
        ] {
            let expected_message = expected.to_string();
            let error = BlockExecutionError::other(expected);
            assert_eq!(
                ce_work_admission_error(&error).map(ToString::to_string),
                Some(expected_message)
            );
        }
        assert!(ce_work_admission_error(&BlockExecutionError::msg("other")).is_none());
    }

    #[test]
    fn exact_parent_readiness_remains_typed_for_retry_without_an_alarm() {
        let readiness = BlockExecutionError::other(PrecompileError::TreeUnavailable(
            "finalized marker advanced past the payload parent".to_owned(),
        ));
        assert!(ce_local_readiness_error(&readiness));
        assert!(!ce_local_readiness_error(&BlockExecutionError::other(
            PrecompileError::Fatal("same-height parent hash mismatch".to_owned()),
        )));
    }

    #[test]
    fn late_payload_rejection_removes_its_published_candidate() {
        let (_directory, service) = tree_service();
        let genesis_hash = B256::repeat_byte(0x11);
        let block_hash = B256::repeat_byte(0x22);
        let genesis_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();
        let provisional = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: genesis_root,
            })
            .unwrap()
            .prepare_seal(1, &[], &[])
            .unwrap();
        service.publish_candidate(block_hash, provisional).unwrap();

        discard_failed_payload_candidate(Some(&service), 1, block_hash).unwrap();

        assert!(service.candidate(1, block_hash).unwrap().is_none());
        assert_eq!(service.finalized_marker().unwrap().height, 0);
    }
}
