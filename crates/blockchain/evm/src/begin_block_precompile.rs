//! Begin-block orchestration precompile system transactions.
//!
//! The precompile is called through `transact_system_call` with
//! `SYSTEM_ADDRESS` as the EVM caller. It decodes a versioned
//! [`SystemTxInputV2`](crate::system_tx::SystemTxInputV2) payload and routes to
//! the begin_block system tx body so runtime events are emitted through the
//! EVM journal and become receipt-visible.

use alloy_primitives::{Address, Bytes, B256, U256};

use outbe_primitives::{
    addresses::SYSTEM_ADDRESS,
    block::{BlockContext, BlockLifecycle, BlockRuntimeContext},
    consensus::{DkgBoundaryArtifact, LATE_FINALIZE_WINDOW_K},
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::{PrecompileError, Result},
    reshare_artifact::{LateFinalizeCreditsArtifact, PerBlockCredit},
    storage::StorageHandle,
};

use crate::{
    executor::{apply_boundary_outcome, validate_finalized_metadata, AccountedParentArtifact},
    system_tx::SystemTxInputV2,
};

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// Execution context preloaded by the executor before calling the
/// begin-block precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreloadedSystemTxContext {
    pub proposer: Address,
    pub finalized_summary: Option<AccountedParentArtifact>,
    /// True only for a block carrying a validator-set-changing BoundaryOutcome
    /// whose target set includes `proposer`. This lets the activation block be
    /// produced by a next-epoch leader before BoundaryOutcome updates parent-state
    /// consensus membership.
    pub allow_boundary_proposer: bool,
    /// canonical hash of the VRF proof carried in the verified
    /// parent certificate (`keccak256(VrfProof::encode())`). Derived by
    /// the executor's Phase 1 preflight from
    /// `outbe_consensus::proof::VerifiedProof::vrf_proof_hash` and fed
    /// into the V3 Rewards fingerprint so that two parent certificates
    /// with different VRF proofs cannot collide. `B256::ZERO` when the
    /// preflight was skipped (genesis bootstrap / test-only opt-out).
    pub canonical_vrf_proof_hash: B256,
}

thread_local! {
    static PRELOADED_SYSTEM_TX_CONTEXT: std::cell::RefCell<Option<PreloadedSystemTxContext>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `f` with explicit non-calldata context visible to the system
/// precompile on the current thread.
///
/// This keeps CertifiedParentAccounting money fields out of signed calldata while
/// still giving the precompile an explicit deterministic data path for the
/// parent block's committed execution summary. The executor sets this only
/// around a single `transact_system_call`, and the guard restores the previous
/// value on exit.
pub(crate) fn with_preloaded_system_tx_context<R>(
    context: PreloadedSystemTxContext,
    f: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<PreloadedSystemTxContext>);

    impl Drop for Reset {
        fn drop(&mut self) {
            PRELOADED_SYSTEM_TX_CONTEXT.with(|slot| {
                *slot.borrow_mut() = self.0;
            });
        }
    }

    let previous = PRELOADED_SYSTEM_TX_CONTEXT.with(|slot| slot.replace(Some(context)));
    let _reset = Reset(previous);
    f()
}

fn current_preloaded_system_tx_context() -> Option<PreloadedSystemTxContext> {
    PRELOADED_SYSTEM_TX_CONTEXT.with(|slot| *slot.borrow())
}

/// Exact finalized state root carried by the executor-owned Phase 1 context.
///
/// This is visible only to the sibling provider-route classifier. Calldata
/// cannot set it, and the guard clears it after the one system transaction.
pub(super) fn preloaded_certified_parent_state_root() -> Option<B256> {
    current_preloaded_system_tx_context()
        .and_then(|context| context.finalized_summary)
        .and_then(|summary| summary.state_root)
}

/// Dispatch entrypoint registered at [`OUTBE_SYSTEM_TX_ADDRESS`].
pub fn dispatch(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    dispatch_inner(
        storage,
        data,
        caller,
        value,
        None,
        None,
        &crate::tee_attestation_activation::TeeAttestationChainSpecStateV1::Unbound,
    )
}

/// Dispatches begin-block work with explicit read-only body authority.
pub fn dispatch_with_readers(
    storage: StorageHandle,
    scope: &outbe_compressed_entities::ExecutionScope,
    parent: &outbe_offchain_data::RuntimeBodyReaders,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    dispatch_inner(
        storage,
        data,
        caller,
        value,
        Some((scope, parent)),
        None,
        &crate::tee_attestation_activation::TeeAttestationChainSpecStateV1::Unbound,
    )
}

/// Dispatches begin-block work without body readers while preserving the
/// immutable TEE authority derived from ChainSpec. Offline/component execution
/// does not install [`RuntimeBodyReaders`], but it must verify block-1 OST3
/// against the same genesis-fixed authority as the live node.
pub fn dispatch_with_tee_attestation(
    storage: StorageHandle,
    tee_attestation_v1: &crate::tee_attestation_activation::TeeAttestationChainSpecStateV1,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    dispatch_inner(storage, data, caller, value, None, None, tee_attestation_v1)
}

/// Production dispatch with both finalized body readers and the immutable
/// chain-manifest fork authority.
pub(crate) struct SystemTxRuntime<'a> {
    pub(crate) scope: &'a outbe_compressed_entities::ExecutionScope,
    pub(crate) parent: &'a outbe_offchain_data::RuntimeBodyReaders,
    pub(crate) ocomp_fork_install: Option<&'a outbe_metadosis::config::OcompForkInstallV1>,
    pub(crate) tee_attestation_v1:
        &'a crate::tee_attestation_activation::TeeAttestationChainSpecStateV1,
}

pub(crate) fn dispatch_with_readers_and_ocomp_install(
    storage: StorageHandle,
    runtime: SystemTxRuntime<'_>,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    let SystemTxRuntime {
        scope,
        parent,
        ocomp_fork_install,
        tee_attestation_v1,
    } = runtime;
    dispatch_inner(
        storage,
        data,
        caller,
        value,
        Some((scope, parent)),
        ocomp_fork_install,
        tee_attestation_v1,
    )
}

fn dispatch_inner(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
    body_readers: Option<(
        &outbe_compressed_entities::ExecutionScope,
        &outbe_offchain_data::RuntimeBodyReaders,
    )>,
    ocomp_fork_install: Option<&outbe_metadosis::config::OcompForkInstallV1>,
    tee_attestation_v1: &crate::tee_attestation_activation::TeeAttestationChainSpecStateV1,
) -> Result<Bytes> {
    if caller != SYSTEM_ADDRESS {
        return Err(PrecompileError::Revert(
            "system precompile can only be called by SYSTEM_ADDRESS".into(),
        ));
    }
    if !value.is_zero() {
        return Err(PrecompileError::Revert(
            "system precompile does not accept native token value".into(),
        ));
    }

    let input = SystemTxInputV2::decode(data)
        .map_err(|error| PrecompileError::Fatal(format!("invalid system tx input: {error}")))?;

    match input {
        SystemTxInputV2::CertifiedParentAccounting { metadata } => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            run_finalization_and_slashing(&ctx, &metadata)?;
        }
        SystemTxInputV2::LateFinalizeCredits { artifact } => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            run_late_finalize_credits(&ctx, &artifact)?;
        }
        SystemTxInputV2::OcompLifecycleBegin => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            let (scope, _) = body_readers.ok_or_else(|| {
                PrecompileError::Fatal(
                    "OcompLifecycleBegin requires the active compressed-entity scope".into(),
                )
            })?;
            run_ocomp_lifecycle_begin(&ctx, scope, ocomp_fork_install)?;
        }
        SystemTxInputV2::CycleTick => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            let metadosis_genesis_activation_height = ocomp_fork_install
                .map(|install| install.activation_height)
                .unwrap_or(1);
            match body_readers {
                Some((scope, parent)) => {
                    run_cycle_tick_with_readers_at_activation(
                        &ctx,
                        scope,
                        parent,
                        metadosis_genesis_activation_height,
                    )?;
                }
                None => {
                    run_cycle_tick_at_activation(&ctx, metadosis_genesis_activation_height)?;
                }
            }
        }
        SystemTxInputV2::RewardsGemDelivery => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            outbe_rewards::api::deliver_oldest_reward_gem_batch(&ctx)?;
        }
        SystemTxInputV2::BoundaryOutcome { artifact } => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            run_boundary_outcome(&ctx, &artifact)?;
        }
        SystemTxInputV2::TeeBootstrap { payload } => {
            let ctx = block_runtime_context_from_storage(storage, true)?;
            prepare_tee_bootstrap(&ctx, &payload, tee_attestation_v1)?;
            run_tee_bootstrap_v1(&ctx, &payload)?;
        }
        SystemTxInputV2::OracleSlashWindow => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            run_oracle_slash_window(&ctx)?;
        }
        SystemTxInputV2::HookEvents => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            run_hook_events(&ctx)?;
        }
        SystemTxInputV2::OcompTerminalRequest => {
            let ctx = block_runtime_context_from_storage(storage, false)?;
            let (scope, _) = body_readers.ok_or_else(|| {
                PrecompileError::Fatal(
                    "OCOMP terminal request requires execution seal authority".into(),
                )
            })?;
            run_ocomp_terminal_request(&ctx, scope)?;
        }
    }

    Ok(Bytes::new())
}

fn prepare_tee_bootstrap(
    ctx: &BlockRuntimeContext,
    payload: &outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2,
    state: &crate::tee_attestation_activation::TeeAttestationChainSpecStateV1,
) -> Result<()> {
    let activation = state.activation().map_err(|error| {
        PrecompileError::Fatal(format!("invalid TEE ChainSpec authority: {error}"))
    })?;
    if ctx.block.block_number < activation.manifest.activation_height {
        return Err(PrecompileError::Revert(
            "OST3 is not active at the current block".into(),
        ));
    }
    let expected_policy = activation
        .policy_at(ctx.block.block_number)
        .map_err(|error| PrecompileError::Fatal(format!("invalid active TEE policy: {error}")))?;
    if &payload.policy != expected_policy {
        return Err(PrecompileError::Revert(
            "OST3 policy does not match the active ChainSpec schedule".into(),
        ));
    }
    outbe_teeregistry::TeeRegistry::new(ctx.storage.clone())
        .install_initial_policy_v1(expected_policy)?;
    Ok(())
}

/// DCAP block-1 bootstrap. The canonical payload already proves bounded shape;
/// this handler binds it to the exact active committee and epoch-0 snapshot,
/// verifies every validator through the production enclave-resident QVL path,
/// and only then finalizes the existing offer-key bootstrap state.
pub(crate) fn run_tee_bootstrap_v1(
    ctx: &BlockRuntimeContext,
    payload: &outbe_primitives::tee_bootstrap_v2::TeeBootstrapV2,
) -> Result<()> {
    use outbe_primitives::tee_signatures::recover_signer;
    use outbe_teeregistry::{TeeBootstrapData, TeeRegistry};
    use std::collections::BTreeSet;

    let mut registry = TeeRegistry::new(ctx.storage.clone());
    if registry.is_bootstrapped()? {
        return Err(PrecompileError::Revert(
            "TeeBootstrapV2: registry already bootstrapped".into(),
        ));
    }
    if payload.committee_snapshot_block != ctx.block.block_number {
        return Err(PrecompileError::Revert(format!(
            "TeeBootstrapV2: committee snapshot block {} does not equal current block {}",
            payload.committee_snapshot_block, ctx.block.block_number
        )));
    }

    let active_policy = registry.active_policy_v1()?;
    if active_policy != payload.policy {
        return Err(PrecompileError::Revert(
            "TeeBootstrapV2: payload policy is not the authoritative active V1 policy".into(),
        ));
    }

    let committee: BTreeSet<Address> =
        outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone())
            .get_active_consensus_set()?
            .into_iter()
            .map(|record| record.validator_address)
            .collect();
    if committee.is_empty() {
        return Err(PrecompileError::Revert(
            "TeeBootstrapV2: active consensus committee is empty".into(),
        ));
    }
    let participant_validators = payload
        .participants
        .iter()
        .map(|participant| Address::from(participant.validator_binding.validator))
        .collect::<BTreeSet<_>>();
    if participant_validators != committee || payload.participants.len() != committee.len() {
        return Err(PrecompileError::Revert(
            "TeeBootstrapV2: participants must equal the complete active consensus committee"
                .into(),
        ));
    }

    let signing_hash = payload.signing_hash().map_err(|error| {
        PrecompileError::Fatal(format!(
            "canonical TeeBootstrapV2 cannot produce its signing hash: {error}"
        ))
    })?;
    for signature in &payload.committee_signatures {
        let recovered = recover_signer(&signing_hash, &signature.signature)?;
        if recovered != signature.validator || !committee.contains(&signature.validator) {
            return Err(PrecompileError::Revert(format!(
                "TeeBootstrapV2: invalid committee signature for {}",
                signature.validator
            )));
        }
    }

    let snapshot =
        outbe_validatorset::state::read_committee_snapshot_for_epoch(ctx.storage.clone(), 0)?
            .ok_or_else(|| {
                PrecompileError::Revert(
                    "TeeBootstrapV2: epoch-0 committee snapshot is missing".into(),
                )
            })?;
    let committee_snapshot_hash = outbe_validatorset::committee_set_hash_v2(0, &snapshot);
    if payload.committee_snapshot_hash != committee_snapshot_hash {
        return Err(PrecompileError::Revert(
            "TeeBootstrapV2: committee snapshot hash mismatch".into(),
        ));
    }

    for (index, participant) in payload.participants.iter().enumerate() {
        let evidence = payload
            .logical_evidence(index)
            .and_then(|evidence| evidence.encode_canonical())
            .map_err(|error| {
                PrecompileError::Fatal(format!(
                    "canonical TeeBootstrapV2 cannot reconstruct evidence {index}: {error}"
                ))
            })?;
        registry.register_enclave_v1(
            Address::from(participant.validator_binding.validator),
            &evidence,
            &participant.node_signature,
            &participant.enclave_signature,
            &participant.validator_binding,
            &participant.validator_signature,
            &participant.node_binding_signature,
        )?;
    }

    let policy_hash = payload.policy.policy_hash().map_err(|error| {
        PrecompileError::Fatal(format!(
            "authoritative TeeBootstrapV2 policy cannot be hashed: {error}"
        ))
    })?;
    registry.write_bootstrap(&TeeBootstrapData {
        tribute_offer_public_key: payload.tribute_offer_public_key,
        policy_hash,
        key_epoch: payload.key_epoch,
        tribute_offer_epoch: payload.tribute_offer_epoch,
        dkg_transcript_hash: payload.dkg_transcript_hash,
        committee_snapshot_block: payload.committee_snapshot_block,
        committee_snapshot_hash,
        tribute_offer_group_public_key: payload.tribute_offer_group_public_key.clone(),
    })
}

/// CertifiedParentAccounting system tx: apply the immediate parent's finalization
/// facts, participation, fee settlement, and deterministic slashing.
pub(crate) fn run_finalization_and_slashing(
    ctx: &BlockRuntimeContext,
    metadata: &CertifiedParentAccountingMetadata,
) -> Result<()> {
    if ctx.block.block_number < 2 {
        return Err(PrecompileError::Fatal(
            "CertifiedParentAccounting system tx requires block_number >= 2".into(),
        ));
    }
    let expected_parent_number = ctx
        .block
        .block_number
        .checked_sub(1)
        .ok_or_else(|| PrecompileError::Fatal("block number underflow".into()))?;
    if metadata.finalized_block_number != expected_parent_number {
        return Err(PrecompileError::Fatal(format!(
            "CertifiedParentAccounting metadata must target immediate parent: expected {}, got {}",
            expected_parent_number, metadata.finalized_block_number
        )));
    }
    if metadata.finalized_block_hash.is_zero() {
        return Err(PrecompileError::Fatal(
            "CertifiedParentAccounting metadata has zero finalized block hash".into(),
        ));
    }

    validate_finalized_metadata(ctx.storage.clone(), metadata)?;

    let finalized = read_preloaded_finalized_summary(&ctx.storage)?.ok_or_else(|| {
        PrecompileError::Fatal(format!(
            "missing preloaded execution summary for finalized block {} ({})",
            metadata.finalized_block_number, metadata.finalized_block_hash
        ))
    })?;

    // OCOMP finality is derived only from an actual consensus finalization
    // certificate for the exact request parent. Certified notarization remains
    // sufficient for ordinary parent accounting, but cannot create a JobId or
    // open a result-vote window.
    if metadata.proof_kind
        == outbe_primitives::consensus_metadata::ParentParticipationProof::Finalization
    {
        let finalized_state_root = finalized.state_root.ok_or_else(|| {
            PrecompileError::Fatal(
                "certified Metadosis finality requires the verified parent state root".into(),
            )
        })?;
        let certified = outbe_primitives::storage::MetadosisCertifiedFinalityBinding::new(
            ctx.block.chain_id,
            ctx.block.block_number,
            metadata.finalized_block_number,
            metadata.finalized_block_hash,
            finalized_state_root,
        );
        outbe_metadosis::commands::record_certified_parent_finality(ctx, &certified)?;
    }

    // the V3 Rewards fingerprint binds the canonical VRF proof
    // hash from the verified parent certificate. The executor's Phase 1
    // preflight (`apply_pre_execution_changes::verify_phase1_in_preexec`)
    // captured this value from `outbe_consensus::proof::VerifiedProof::vrf_proof_hash`
    // and stashed it in the preloaded context. A zero hash here would
    // pass the gate but produces a degenerate fingerprint; in production
    // the preflight always populates a real value for `block_number >= 2`.
    let canonical_vrf_proof_hash = current_preloaded_system_tx_context()
        .map(|context| context.canonical_vrf_proof_hash)
        .unwrap_or(B256::ZERO);

    let last_accounted = outbe_accounting::read_last_accounted_block_number(ctx)?;
    match outbe_rewards::runtime::check_and_record_metadata_fingerprint(
        ctx,
        metadata,
        finalized.summary.validator_fee_sum,
        canonical_vrf_proof_hash,
    )? {
        outbe_rewards::runtime::MetadataFingerprintOutcome::IdenticalReplay => {
            if last_accounted != expected_parent_number {
                return Err(PrecompileError::Fatal(format!(
                    "CertifiedParentAccounting identical replay at unexpected progress: last_accounted={last_accounted}, expected={expected_parent_number}"
                )));
            }
            tracing::warn!(
                target: "outbe::system_tx",
                block_number = ctx.block.block_number,
                parent_block_number = expected_parent_number,
                "CertifiedParentAccounting identical replay accepted",
            );
            return Ok(());
        }
        outbe_rewards::runtime::MetadataFingerprintOutcome::Fresh => {
            let required_previous = expected_parent_number.saturating_sub(1);
            if last_accounted != required_previous {
                return Err(PrecompileError::Fatal(format!(
                    "CertifiedParentAccounting progress gap: last_accounted={last_accounted}, expected_previous={required_previous}, accounting_parent={expected_parent_number}"
                )));
            }
        }
    }

    // Base voters = the k=0 quorum (direct-parent signers); they seed the fee
    // escrow at k=0. The FULL absentee set and its miss / slashing accounting are
    // deferred to the inclusion-window close at N+K (`record_window_close_absentees`
    // in the LateFinalizeCredits phase), so a slow-but-honest validator credited at
    // k=1..K is not counted "missed" or slashed.
    let mut voters = Vec::new();
    for (addr, did_sign) in metadata
        .ordered_committee
        .iter()
        .copied()
        .zip(metadata.signer_bitmap.iter().copied())
    {
        if did_sign == 1 {
            voters.push(addr);
        }
    }

    outbe_rewards::finalized_metadata_hook::on_finalized_metadata(
        ctx,
        metadata,
        finalized.summary.validator_fee_sum,
        finalized.timestamp,
        &voters,
    )?;

    // Missed-proposer slashing: idempotent + bounded via the per-`fb_hash`
    // `proposer_window_slashed` guard. The whole event list for this
    // finalized parent is processed atomically; duplicate proposers across
    // skipped views are each slashed within the one pass.
    let missed_validators: Vec<Address> = metadata
        .missed_proposers
        .iter()
        .map(|m| m.validator)
        .collect();
    outbe_slashindicator::hooks::slash_window_proposers(
        ctx.storage.clone(),
        metadata.finalized_block_hash,
        &missed_validators,
    )?;

    // advance the slash-guard prune ring once per finalized block. Phase 1
    // sees every finalized block exactly once (as a direct parent), so this
    // bounds both window guards to the last SLASH_GUARD_RETAIN finalized blocks.
    outbe_slashindicator::hooks::prune_slash_guards(
        ctx.storage.clone(),
        metadata.finalized_block_hash,
    )?;

    outbe_accounting::record_phase1_progress(ctx, expected_parent_number)?;

    Ok(())
}

fn run_cycle_tick_at_activation(
    ctx: &BlockRuntimeContext,
    _metadosis_genesis_activation_height: u64,
) -> Result<()> {
    validate_and_record_cycle_proposer(ctx)?;
    enforce_tee_lease_deadlines(ctx)?;

    #[cfg(test)]
    {
        use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
        use std::sync::Arc;

        let storage: StorageReaderHandle = Arc::new(MemoryStorage::new());
        let parent = outbe_offchain_data::RuntimeBodyReaders::new(storage);
        let scope = outbe_compressed_entities::ExecutionScope::new();
        let compressed =
            outbe_compressed_entities::CompressedEntitiesLifecycleContext::new(ctx.clone(), &scope);
        <outbe_compressed_entities::CompressedEntitiesLifecycle as BlockLifecycle>::begin_block(
            &compressed,
        )?;
        let lifecycle =
            outbe_cycle::lifecycle::CycleLifecycleContext::new(ctx.clone(), &scope, &parent)
                .with_metadosis_genesis_activation_height(_metadosis_genesis_activation_height);
        <outbe_cycle::lifecycle::CycleLifecycle as BlockLifecycle>::begin_block(&lifecycle)?;
        <outbe_compressed_entities::CompressedEntitiesLifecycle as BlockLifecycle>::end_block(
            &compressed,
        )
        .map(|_| ())?;
        run_ocomp_recovery_sweep(ctx)
    }

    #[cfg(not(test))]
    Err(PrecompileError::Fatal(
        "Cycle execution body read authority was not supplied".into(),
    ))
}

fn run_cycle_tick_with_readers_at_activation(
    ctx: &BlockRuntimeContext,
    scope: &outbe_compressed_entities::ExecutionScope,
    parent: &outbe_offchain_data::RuntimeBodyReaders,
    metadosis_genesis_activation_height: u64,
) -> Result<()> {
    validate_and_record_cycle_proposer(ctx)?;
    enforce_tee_lease_deadlines(ctx)?;
    // This body mutation must consume system-transaction gas and appear in its
    // receipt. Keep its old ordering before Cycle/Lysis so freshly issued Nod
    // buckets are not qualified until the following block.
    let nod_lifecycle = outbe_nod::hooks::NodLifecycleContext::new(ctx.clone(), scope, parent);
    <outbe_nod::hooks::NodLifecycle as BlockLifecycle>::begin_block(&nod_lifecycle)?;
    let cycle_lifecycle =
        outbe_cycle::lifecycle::CycleLifecycleContext::new(ctx.clone(), scope, parent)
            .with_metadosis_genesis_activation_height(metadosis_genesis_activation_height);
    <outbe_cycle::lifecycle::CycleLifecycle as BlockLifecycle>::begin_block(&cycle_lifecycle)?;
    // Keep non-transactional punishment observability behind every other
    // fallible CycleTick lifecycle. Once this succeeds, the precompile returns
    // immediately and the critical system transaction can commit as one unit.
    run_ocomp_recovery_sweep(ctx)
}

/// Resolve due OCOMP recovery windows in the mandatory per-block `CycleTick`.
/// `CycleTick` is consensus-critical, so every accepted block at height >= 1
/// has executed this sweep successfully.
fn run_ocomp_recovery_sweep(ctx: &BlockRuntimeContext) -> Result<()> {
    outbe_staking::contract::Staking::new(ctx.storage.clone())
        .close_due_ocomp_recovery_windows()
        .map(|_| ())
}

/// Applies the canonical post-bootstrap TEE lease deadline to the bounded ACTIVE
/// validator set. The sweep is part of receipt-visible `CycleTick`, before any
/// user transaction in the block. Block 1 is excluded because its later
/// `TeeBootstrap` system transaction creates the founder bindings atomically.
fn enforce_tee_lease_deadlines(ctx: &BlockRuntimeContext) -> Result<usize> {
    if ctx.block.block_number
        <= crate::tee_attestation_activation::TEE_ATTESTATION_V1_ACTIVATION_HEIGHT
    {
        return Ok(0);
    }

    let active = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone())
        .get_active_validators()?;
    let registry = outbe_teeregistry::TeeRegistry::new(ctx.storage.clone());
    let mut overdue = Vec::new();
    for validator in active {
        let binding = registry.validator_enclave_binding_v1(validator.validator_address)?;
        if binding.is_none_or(|binding| binding.valid_until <= ctx.block.timestamp) {
            overdue.push(validator.validator_address);
        }
    }

    let mut validator_set = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
    let mut jailed = 0usize;
    for validator in overdue {
        if validator_set.jail_validator_for_tee_expiry(validator)? {
            jailed += 1;
        }
    }
    Ok(jailed)
}

fn validate_and_record_cycle_proposer(ctx: &BlockRuntimeContext) -> Result<()> {
    let allow_boundary_proposer = current_preloaded_system_tx_context()
        .map(|context| context.allow_boundary_proposer)
        .unwrap_or(false);
    let mut vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
    if vs.is_consensus_participant(ctx.block.proposer)? {
        vs.record_proposer(ctx.block.proposer)?;
    } else if allow_boundary_proposer && vs.is_validator(ctx.block.proposer)? {
        // The block is the activation block for a validator-set-changing
        // BoundaryOutcome and was proposed by a next-epoch validator. The
        // proposer becomes a consensus participant in BoundaryOutcome, at which
        // point `run_boundary_outcome` records this proposal exactly once.
    } else {
        return Err(PrecompileError::Fatal(format!(
            "proposer is not a current consensus participant: {}",
            ctx.block.proposer
        )));
    }
    Ok(())
}

/// BoundaryOutcome system tx: activate a DKG/reshare boundary before user transactions.
pub(crate) fn run_boundary_outcome(
    ctx: &BlockRuntimeContext,
    artifact: &DkgBoundaryArtifact,
) -> Result<()> {
    let was_participant = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone())
        .is_consensus_participant(ctx.block.proposer)?;
    apply_boundary_outcome(
        ctx.storage.clone(),
        artifact,
        ctx.block.block_number,
        ctx.block.timestamp,
    )?;
    if !was_participant {
        let mut vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
        if vs.is_consensus_participant(ctx.block.proposer)? {
            vs.record_proposer(ctx.block.proposer)?;
        }
    }
    // Record the TEE recipient X25519 pubkeys announced through this boundary
    // (the `BoundaryOutcome` key-delivery channel - README "Consensus Artifact
    // Transport"). These ride in `header.extra_data` and are part of the
    // hash-committed `OutbeBlockArtifacts`, so every validator records the same
    // ordered set deterministically. Empty for boundaries that announce none.
    if !artifact.tee_recipient_pubkeys.is_empty() {
        outbe_teeregistry::TeeRegistry::new(ctx.storage.clone())
            .record_boundary_recipient_keys(&artifact.tee_recipient_pubkeys)?;
    }
    Ok(())
}

/// authentication: verify a late-finalize `credit`'s
/// proposer-supplied `fb_number`/`epoch`/`committee_set_hash` against the
/// canonical binding escrowed for that finalized block (keyed by `fb_number` in
/// `Rewards`). The BLS proof binds only `fb_hash`, so this is what prevents a
/// proposer from spoofing `fb_number` (to shrink the inclusion distance `k` and
/// inflate decay weight) or referencing a wrong committee. FATAL on a missing
/// escrow or any mismatch. Shared by the begin-zone body and the pre-exec gate.
pub(crate) fn authenticate_late_credit(
    storage: &StorageHandle,
    credit: &PerBlockCredit,
) -> Result<()> {
    let rewards = storage.contract::<outbe_rewards::contract::Rewards<'_>>();
    let escrowed_hash = rewards.pending_fb_hash_at.read(&credit.fb_number)?;
    if escrowed_hash == B256::ZERO {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: no escrow for fb_number {} (credit fb_hash {})",
            credit.fb_number, credit.fb_hash
        )));
    }
    if escrowed_hash != credit.fb_hash {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: fb_hash mismatch for fb_number {} (escrow {escrowed_hash}, credit {})",
            credit.fb_number, credit.fb_hash
        )));
    }
    let escrowed_epoch = rewards.pending_epoch_at.read(&credit.fb_number)?;
    if escrowed_epoch != credit.epoch {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: epoch mismatch for fb_number {} (escrow {escrowed_epoch}, credit {})",
            credit.fb_number, credit.epoch
        )));
    }
    let escrowed_csh = rewards
        .pending_committee_set_hash_at
        .read(&credit.fb_number)?;
    if escrowed_csh != credit.committee_set_hash {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: committee_set_hash mismatch for fb_number {} (escrow {escrowed_csh}, credit {})",
            credit.fb_number, credit.committee_set_hash
        )));
    }
    // Pin the rest of the signed binding (view, parent_view) to the canonical
    // certificate, so a credit whose aggregate is over a non-canonical view of the
    // same fb_hash (cross-view equivocation) is rejected here, not only by the
    // pre-exec BLS verify (which ties the credit's view to its signatures, not to
    // the finalized view). full binding.
    let escrowed_view = rewards.pending_view_at.read(&credit.fb_number)?;
    if escrowed_view != credit.view {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: view mismatch for fb_number {} (escrow {escrowed_view}, credit {})",
            credit.fb_number, credit.view
        )));
    }
    let escrowed_parent_view = rewards.pending_parent_view_at.read(&credit.fb_number)?;
    if escrowed_parent_view != credit.parent_view {
        return Err(PrecompileError::Fatal(format!(
            "LateFinalizeCredits: parent_view mismatch for fb_number {} (escrow {escrowed_parent_view}, credit {})",
            credit.fb_number, credit.parent_view
        )));
    }
    Ok(())
}

/// LateFinalizeCredits system tx: record the verified
/// late-finalize voters of each in-window batch at their inclusion distance
/// `k`, then close the window that just matured (`settle_matured` for block
/// `N - K`). The escrow residue is burned for mint/burn parity inside
/// `settle_window`; here we additionally route that same residue to terminal
/// Metadosis emission headroom (`emission_sink::apply`), recycling unpaid fees
/// instead of permanently destroying them.
///
/// Determinism: every batch's BLS aggregate was already FATAL-verified in the
/// executor's pre-exec preflight (`verify_late_finalize_credits_in_preexec`),
/// proposer and validator alike. This body re-resolves the committee snapshot
/// only to map the verified signer indices to addresses; the re-`verify`
/// is the single source of truth for the bitmap->index decoding and yields the
/// same indices on every node. Empty artifacts (no gathered credits) reduce to
/// the window-close `settle_matured`, which is a no-op until block `K+1`.
pub(crate) fn run_late_finalize_credits(
    ctx: &BlockRuntimeContext,
    artifact: &LateFinalizeCreditsArtifact,
) -> Result<()> {
    use outbe_consensus::proof::verify_late_finalize_proof;
    use outbe_validatorset::state::{committee_snapshot_key, read_committee_snapshot};

    let block_number = ctx.block.block_number;

    for credit in &artifact.batches {
        // Inclusion distance k = block_number - fb_number, range-checked
        // `1 <= k <= K` on the *executed body* artifact (the pre-exec preflight
        // range-checks the header; the stateless validator binds header<->body -
        // but this path must stand on its own: a credit outside the window must
        // never be recorded). Checked FIRST, before the expensive snapshot read
        // + BLS verify, so an out-of-window credit is rejected cheaply.
        let k_u64 = block_number.checked_sub(credit.fb_number).ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "LateFinalizeCredits: fb_number {} >= block {block_number}",
                credit.fb_number
            ))
        })?;
        if k_u64 == 0 || k_u64 > LATE_FINALIZE_WINDOW_K {
            return Err(PrecompileError::Fatal(format!(
                "LateFinalizeCredits: fb_number {} outside inclusion window \
                 (distance {k_u64}, K={LATE_FINALIZE_WINDOW_K}) for block {block_number}",
                credit.fb_number
            )));
        }
        let k = u8::try_from(k_u64).map_err(|_| {
            PrecompileError::Fatal(format!(
                "LateFinalizeCredits: inclusion distance {k_u64} exceeds u8 for block {block_number}"
            ))
        })?;

        // bind the proposer-supplied
        // fb_number/epoch/committee_set_hash to the escrowed canonical binding for
        // this finalized block before recording. The BLS proof binds only fb_hash,
        // so without this a proposer could spoof fb_number (shrink k -> inflate
        // weight) or reference a wrong committee.
        authenticate_late_credit(&ctx.storage, credit)?;

        // Re-resolve the epoch committee the proof was produced for, to map
        // verified signer indices -> addresses, and re-verify the BLS aggregate
        // (FATAL on failure - never a soft receipt). The snapshot must exist (the
        // pre-exec preflight already read and verified against it).
        let snapshot_key = committee_snapshot_key(credit.epoch, credit.committee_set_hash);
        let snapshot = read_committee_snapshot(ctx.storage.clone(), snapshot_key)?.ok_or_else(
            || {
                PrecompileError::Fatal(format!(
                    "LateFinalizeCredits: missing committee snapshot for epoch={} key={snapshot_key}",
                    credit.epoch
                ))
            },
        )?;

        let signer_indices = verify_late_finalize_proof(&snapshot, credit).map_err(|error| {
            PrecompileError::Fatal(format!(
                "LateFinalizeCredits: proof verify failed for fb={}: {error}",
                credit.fb_hash
            ))
        })?;

        for idx in signer_indices {
            let voter = snapshot
                .committee
                .get(idx)
                .map(|entry| entry.address)
                .ok_or_else(|| {
                    PrecompileError::Fatal(format!(
                        "LateFinalizeCredits: signer index {idx} out of committee range"
                    ))
                })?;
            outbe_rewards::late_settlement::record_late_credit(ctx, credit.fb_hash, voter, k)?;
        }
    }

    // Window-close miss & slashing pass: record misses and apply
    // punitive slashing for every committee member who never voted within K, using
    // the FINAL credited set. Must run BEFORE `settle_matured`, which frees the
    // `late_voter_*` credited set.
    record_window_close_absentees(ctx, block_number)?;

    // Window close: settle block N - K (the window that just matured). No-op
    // before block K+1 or when nothing was escrowed at that number. The residue
    // burn + terminal-Metadosis recycle and the per-window state cleanup happen
    // inside `settle_window`; nothing further is needed here.
    outbe_rewards::late_settlement::settle_matured(ctx, block_number, LATE_FINALIZE_WINDOW_K)?;

    Ok(())
}

/// Window-close miss & slashing pass. For the
/// window maturing at this block (`fb_number = block_number - K`), every committee
/// member that never voted within `K` - `committee(fb_number) \ credited` - has its
/// finalized-participation miss recorded and `slash_voter` applied (force-exit +
/// stake slash once the felony threshold is crossed).
///
/// Determinism: the committee snapshot and credited set are committed chain state;
/// absentees are emitted in committee order. Idempotent via the per-`fb_hash`
/// guards inside the validatorset / slashindicator hooks. The committee snapshot
/// is written at the epoch boundary and never pruned, so it is always present in
/// production; a missing snapshot fails open (skip) rather than halting the block.
///
/// Runs BEFORE `settle_matured`, which frees the `late_voter_*` credited set.
fn record_window_close_absentees(ctx: &BlockRuntimeContext, block_number: u64) -> Result<()> {
    use outbe_validatorset::state::{committee_snapshot_key, read_committee_snapshot};
    use std::collections::BTreeSet;

    let Some(fb_number) = block_number.checked_sub(LATE_FINALIZE_WINDOW_K) else {
        return Ok(());
    };
    if fb_number == 0 {
        return Ok(());
    }
    let Some(info) = outbe_rewards::late_settlement::window_close_credited(ctx, fb_number)? else {
        return Ok(());
    };

    let snapshot_key = committee_snapshot_key(info.epoch, info.committee_set_hash);
    let Some(snapshot) = read_committee_snapshot(ctx.storage.clone(), snapshot_key)? else {
        // Always present in production (written at the epoch boundary, never
        // pruned). Fail open rather than halt the block on a slashing-accounting
        // input that is missing only in degenerate/under-seeded states.
        tracing::warn!(
            target: "outbe::slashing",
            fb_number,
            epoch = info.epoch,
            "window-close absentee pass: committee snapshot missing; skipping",
        );
        return Ok(());
    };

    let credited: BTreeSet<Address> = info.credited.into_iter().collect();
    // Absentees = committee members who never voted within `K`, restricted to
    // currently-registered validators. Committee members are always registered in
    // production (the snapshot IS the validator set, and none can fully deregister
    // within `K` blocks), so the filter is a no-op there; it only guards a stray
    // non-registered binding from reverting the whole settlement phase via
    // `record_finalized_participation`'s strict registered-validator contract.
    let vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
    let mut absentees: Vec<Address> = Vec::new();
    for entry in &snapshot.committee {
        if credited.contains(&entry.address) {
            continue;
        }
        if vs.is_validator(entry.address)? {
            absentees.push(entry.address);
        }
    }
    if absentees.is_empty() {
        return Ok(());
    }

    // Metric (E8 relocation): count val_missed_votes against the true absentee set
    // at window close. Idempotent via `finalized_participation_recorded[fb_hash]`.
    outbe_validatorset::hooks::record_finalized_participation(
        ctx.storage.clone(),
        info.fb_hash,
        &[],
        &absentees,
    )?;

    // Punitive: increment voter_miss_count and force-exit + slash at the felony
    // threshold. Idempotent + bounded via the per-`fb_hash` `voter_window_slashed`
    // guard; this whole absentee pass is atomic per finalized block.
    outbe_slashindicator::hooks::slash_window_voters(
        ctx.storage.clone(),
        info.fb_hash,
        &absentees,
    )?;

    Ok(())
}

/// OracleSlashWindow system tx: run Oracle slash-window penalties after any
/// same-block boundary activation but before user transactions observe state.
pub(crate) fn run_oracle_slash_window(ctx: &BlockRuntimeContext) -> Result<()> {
    outbe_oracle::lifecycle::run_slash_window(ctx)
}

/// HookEvents system tx: no-op marker. Whitelisted pre-exec hook logs are
/// attached to this phase's receipt by the executor without re-running hooks.
pub(crate) fn run_hook_events(_ctx: &BlockRuntimeContext) -> Result<()> {
    Ok(())
}

/// Reserved OCOMP expiry/reset slot. OCM-08 wires the bounded Metadosis
/// lifecycle handler into this already receipt-visible phase.
pub(crate) fn run_ocomp_lifecycle_begin(
    ctx: &BlockRuntimeContext,
    scope: &outbe_compressed_entities::ExecutionScope,
    fork_install: Option<&outbe_metadosis::config::OcompForkInstallV1>,
) -> Result<()> {
    if let Some(install) = fork_install {
        if ctx.block.block_number == install.activation_height {
            outbe_metadosis::commands::install_fork_profile(ctx, install)?;
        }
    }
    outbe_metadosis::commands::run_ocomp_lifecycle_begin_with_scope(ctx, scope)
}

/// Reserved terminal request slot. It consumes executor-owned provisional CE
/// roots while the scope remains active for terminal failure retirement.
pub(crate) fn run_ocomp_terminal_request(
    ctx: &BlockRuntimeContext,
    scope: &outbe_compressed_entities::ExecutionScope,
) -> Result<()> {
    outbe_metadosis::commands::run_ocomp_terminal_request(ctx, scope)
}

fn block_runtime_context_from_storage(
    storage: StorageHandle,
    include_validator_snapshot: bool,
) -> Result<BlockRuntimeContext> {
    let block_number = storage.block_number()?;
    let timestamp = u256_to_u64("block timestamp", storage.timestamp()?)?;
    let chain_id = storage.chain_id()?;
    let genesis_hash = storage.genesis_hash()?;
    let proposer = current_preloaded_system_tx_context()
        .map(|context| context.proposer)
        .unwrap_or(storage.beneficiary()?);

    let validators = if include_validator_snapshot {
        let vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
        let mut validators: Vec<Address> = vs
            .get_active_consensus_set()?
            .into_iter()
            .map(|record| record.validator_address)
            .collect();
        validators.sort();
        validators
    } else {
        // OracleSlashWindow only uses block number/timestamp plus storage. Avoid
        // charging a mandatory no-op system tx for an unrelated active-set snapshot.
        Vec::new()
    };

    Ok(BlockRuntimeContext::new(
        BlockContext::new_with_genesis_hash(
            block_number,
            timestamp,
            chain_id,
            genesis_hash,
            proposer,
            validators,
        ),
        storage,
    ))
}

fn read_preloaded_finalized_summary(
    _storage: &StorageHandle<'_>,
) -> Result<Option<AccountedParentArtifact>> {
    Ok(current_preloaded_system_tx_context().and_then(|context| context.finalized_summary))
}

fn u256_to_u64(name: &str, value: U256) -> Result<u64> {
    if value > U256::from(u64::MAX) {
        return Err(PrecompileError::Fatal(format!(
            "{name} exceeds u64 range: {value}"
        )));
    }
    Ok(value.to::<u64>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, keccak256, B256};
    use outbe_primitives::{consensus::ReshareResult, storage::hashmap::HashMapStorageProvider};

    const CHAIN_ID: u64 = outbe_primitives::tee_genesis_v1::GRAMINE_DIRECT_DEV_CHAIN_ID;
    const GENESIS_HASH: B256 = B256::repeat_byte(0x11);
    const OWNER: Address = address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const VALIDATOR: Address = address!("0x1111111111111111111111111111111111111111");

    fn metadata() -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number: 1,
            finalized_block_hash: B256::repeat_byte(0x11),
            finalized_epoch: 1,
            finalized_view: 2,
            parent_view: 1,
            ordered_committee: vec![VALIDATOR],
            signer_bitmap: vec![1],
            proof: Bytes::from_static(b"cert"),
            committee_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key_hash: B256::ZERO,
            proof_kind:
                outbe_primitives::consensus_metadata::ParentParticipationProof::Finalization,
            missed_proposers: Vec::new(),
        }
    }

    fn metadata_for_parent(
        parent_number: u64,
        parent_hash: B256,
    ) -> CertifiedParentAccountingMetadata {
        let mut metadata = metadata();
        metadata.finalized_block_number = parent_number;
        metadata.finalized_block_hash = parent_hash;
        metadata.finalized_view = parent_number.saturating_add(1);
        metadata.parent_view = parent_number;
        metadata
    }

    fn active_set_hash(addresses: &[Address]) -> B256 {
        let mut bytes = Vec::with_capacity(8 + addresses.len() * 20);
        bytes.extend_from_slice(&(addresses.len() as u64).to_be_bytes());
        for address in addresses {
            bytes.extend_from_slice(address.as_slice());
        }
        keccak256(bytes)
    }

    fn boundary_noop() -> DkgBoundaryArtifact {
        let vrf_group_public_key_bytes = vec![0x42u8; 96];
        let snapshot = outbe_validatorset::CommitteeSnapshot {
            committee: vec![outbe_validatorset::CommitteeEntry {
                address: VALIDATOR,
                consensus_pubkey: [7u8; 48],
            }],
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vrf_group_public_key_bytes.clone(),
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        };
        DkgBoundaryArtifact {
            epoch: 1,
            dkg_cycle: 1,
            freeze_height: 1,
            planned_activation_height: 2,
            target_set_hash: B256::ZERO,
            vrf_material_version: 1,
            vrf_group_public_key: keccak256(&vrf_group_public_key_bytes),
            vrf_group_public_key_bytes: Bytes::from(vrf_group_public_key_bytes),
            committee_set_hash: outbe_validatorset::committee_set_hash_v2(1, &snapshot),
            is_validator_set_change: false,
            outcome: Bytes::new(),
            is_full_dkg: false,
            tee_recipient_pubkeys: Vec::new(),
            tee_expired_target_exclusions: Vec::new(),
            tee_expired_target_exclusions_hash: B256::ZERO,
            reshare: ReshareResult {
                new_active_set: vec![VALIDATOR],
                active_set_hash: active_set_hash(&[VALIDATOR]),
            },
        }
    }

    #[test]
    fn mandatory_cycle_tick_sweep_closes_due_ocomp_recovery_when_lifecycle_is_disabled() {
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS_HASH);
        provider.set_block_number(1);
        StorageHandle::enter(&mut provider, |storage| {
            let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            validators.config_owner.write(OWNER).unwrap();
            validators.set_config_max_validators(1).unwrap();
            validators
                .register_validator(OWNER, VALIDATOR, &[0x41; 48])
                .unwrap();
            validators
                .test_activate_validator_canonically(
                    VALIDATOR,
                    outbe_validatorset::StakeProjection::new(U256::from(1_000), None),
                    U256::from(1_000),
                )
                .unwrap();

            let mut staking = outbe_staking::contract::Staking::new(storage.clone());
            staking.config_min_stake.write(U256::from(1_000)).unwrap();
            staking
                .stake_amount
                .write(&VALIDATOR, U256::from(1_000))
                .unwrap();
            staking.total_staked.write(U256::from(1_000)).unwrap();
            storage
                .set_balance(
                    outbe_primitives::addresses::STAKING_ADDRESS,
                    U256::from(1_000),
                )
                .unwrap();
            staking.record_ocomp_miss(VALIDATOR).unwrap();
        });

        provider.set_block_number(43_201);
        StorageHandle::enter(&mut provider, |storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(43_201, 1_000, CHAIN_ID),
                storage.clone(),
            );
            run_ocomp_recovery_sweep(&ctx).unwrap();
            assert!(matches!(
                outbe_validatorset::contract::ValidatorSet::new(storage)
                    .validator_lifecycle(VALIDATOR)
                    .unwrap(),
                outbe_validatorset::ValidatorLifecycle::JailRetained(_)
            ));
        });
    }

    fn configured_storage(block_number: u64, timestamp: u64) -> HashMapStorageProvider {
        let consensus_key = [7u8; 48];
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS_HASH);
        provider.set_block_number(block_number);
        provider.set_timestamp(U256::from(timestamp));
        provider.set_beneficiary(VALIDATOR);
        let install = outbe_metadosis::test_support::ForkInstallScenario::measurement_at(
            1,
            CHAIN_ID,
            GENESIS_HASH,
        )
        .unwrap()
        .with_founder_validators(&[(VALIDATOR, consensus_key)])
        .unwrap()
        .into_install();
        provider.enter(|storage| {
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
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_epoch_length_blocks.write(10).unwrap();
            vs.register_validator(OWNER, VALIDATOR, &consensus_key)
                .unwrap();
            vs.mark_pending(VALIDATOR).unwrap();
            let registration = install.founder_registrations[0]
                .encode_canonical(&outbe_metadosis::config::poc_schema_limits())
                .unwrap();
            vs.confirm_validator_ready(VALIDATOR, &registration)
                .unwrap();
            vs.activate_validator_via_boundary_for_test(VALIDATOR)
                .unwrap();

            outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .unwrap();
        });
        provider.set_block_number(1);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::ForkProfile,
        );
        provider.enter(|storage| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(1, timestamp, CHAIN_ID),
                storage,
            );
            outbe_metadosis::commands::install_fork_profile(&ctx, &install).unwrap();
        });
        provider.set_block_number(block_number);
        provider
    }

    fn provider_from_storage(
        block_number: u64,
        timestamp: u64,
        storage: std::collections::HashMap<(Address, U256), U256>,
    ) -> HashMapStorageProvider {
        let mut provider = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS_HASH);
        provider.set_block_number(block_number);
        provider.set_timestamp(U256::from(timestamp));
        provider.set_beneficiary(VALIDATOR);
        provider.storage = storage;
        provider
    }

    fn runtime_ctx(storage: StorageHandle<'_>) -> BlockRuntimeContext<'_> {
        BlockRuntimeContext::new(
            BlockContext::new(
                storage.block_number().unwrap(),
                storage.timestamp().unwrap().to::<u64>(),
                storage.chain_id().unwrap(),
                VALIDATOR,
                vec![VALIDATOR],
            ),
            storage,
        )
    }

    fn install_validator_lease(provider: &mut HashMapStorageProvider, valid_until: u64) {
        provider.enter(|storage| {
            let registry = outbe_teeregistry::TeeRegistry::new(storage);
            let node_hash = B256::repeat_byte(0x61);
            registry
                .validator_v1_node_hash
                .write(&VALIDATOR, node_hash)
                .unwrap();
            registry
                .v1_node_enclave_id
                .write(&node_hash, B256::repeat_byte(0x62))
                .unwrap();
            registry
                .v1_node_binding_id
                .write(&node_hash, B256::repeat_byte(0x63))
                .unwrap();
            registry
                .v1_node_intent_hash
                .write(&node_hash, B256::repeat_byte(0x64))
                .unwrap();
            registry
                .v1_node_valid_until
                .write(&node_hash, valid_until)
                .unwrap();
        });
    }

    fn read_progress(provider: &mut HashMapStorageProvider) -> u64 {
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            outbe_accounting::read_last_accounted_block_number(&ctx).unwrap()
        })
    }

    fn record_progress(provider: &mut HashMapStorageProvider, block_number: u64) {
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            outbe_accounting::record_phase1_progress(&ctx, block_number).unwrap();
        });
    }

    fn dispatch_phase1(
        provider: &mut HashMapStorageProvider,
        metadata: CertifiedParentAccountingMetadata,
    ) -> Result<Bytes> {
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
        );
        provider.enter(|storage| {
            let input = SystemTxInputV2::CertifiedParentAccounting { metadata }
                .encode()
                .unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: Some(AccountedParentArtifact {
                        summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                            validator_fee_sum: U256::ZERO,
                        },
                        timestamp: 1_699_999_990,
                        state_root: Some(B256::repeat_byte(0x91)),
                    }),
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::repeat_byte(0xEF),
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
        })
    }

    #[test]
    fn dispatch_rejects_external_caller_before_state_mutation() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CycleTick.encode().unwrap();
            let err = dispatch(storage, &input, VALIDATOR, U256::ZERO).unwrap_err();
            assert!(matches!(err, PrecompileError::Revert(_)));
        });
    }

    #[test]
    fn dispatch_rejects_native_value() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CycleTick.encode().unwrap();
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::from(1u64)).unwrap_err();
            assert!(matches!(err, PrecompileError::Revert(_)));
        });
    }

    #[test]
    fn dispatch_rejects_unknown_selector() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let input = [
                0xff,
                0xff,
                0xff,
                0xff,
                crate::system_tx::SYSTEM_TX_INPUT_VERSION,
            ];
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap_err();
            assert!(matches!(err, PrecompileError::Fatal(_)));
            assert!(err.to_string().contains("unknown system tx selector"));
        });
    }

    #[test]
    fn dispatch_rejects_wrong_version() {
        let mut provider = configured_storage(1, 1);
        provider.enter(|storage| {
            let mut input = SystemTxInputV2::CycleTick.encode().unwrap().to_vec();
            input[4] = crate::system_tx::SYSTEM_TX_INPUT_VERSION.saturating_add(1);
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap_err();
            assert!(matches!(err, PrecompileError::Fatal(_)));
            assert!(err
                .to_string()
                .contains("unsupported system tx input version"));
        });
    }

    #[test]
    fn dispatch_cycle_tick_records_preloaded_proposer() {
        let mut provider = configured_storage(1, 1_700_000_000);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CycleLifecycle,
        );
        provider.enter(|storage| {
            let input = SystemTxInputV2::CycleTick.encode().unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: None,
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::ZERO,
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
            .unwrap();
        });

        provider.enter(|storage| {
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let record = vs.get_validator(VALIDATOR).unwrap().unwrap();
            assert_eq!(record.blocks_proposed, 1);
        });
    }

    #[test]
    fn tee_lease_sweep_skips_bootstrap_then_jails_at_exact_deadline_once() {
        let deadline = 1_700_000_100;
        let mut bootstrap = configured_storage(1, deadline);
        bootstrap.enter(|storage| {
            let ctx = runtime_ctx(storage.clone());
            assert_eq!(enforce_tee_lease_deadlines(&ctx).unwrap(), 0);
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            assert_eq!(
                vs.get_validator(VALIDATOR).unwrap().unwrap().status,
                outbe_validatorset::runtime::status::ACTIVE
            );
        });

        let mut before = configured_storage(2, deadline - 1);
        install_validator_lease(&mut before, deadline);
        before.enter(|storage| {
            let ctx = runtime_ctx(storage.clone());
            assert_eq!(enforce_tee_lease_deadlines(&ctx).unwrap(), 0);
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            assert_eq!(
                vs.get_validator(VALIDATOR).unwrap().unwrap().status,
                outbe_validatorset::runtime::status::ACTIVE
            );
        });

        let mut at_deadline = configured_storage(2, deadline);
        install_validator_lease(&mut at_deadline, deadline);
        at_deadline.enter(|storage| {
            let ctx = runtime_ctx(storage.clone());
            assert_eq!(enforce_tee_lease_deadlines(&ctx).unwrap(), 1);
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let jailed = vs.get_validator(VALIDATOR).unwrap().unwrap();
            assert_eq!(jailed.status, outbe_validatorset::runtime::status::JAILED);
            assert_eq!(jailed.slash_count, 0);
            assert_eq!(enforce_tee_lease_deadlines(&ctx).unwrap(), 0);
            assert_eq!(vs.get_validator(VALIDATOR).unwrap().unwrap(), jailed);
        });
    }

    #[test]
    fn tee_lease_sweep_treats_missing_post_bootstrap_binding_as_overdue() {
        let mut provider = configured_storage(2, 1_700_000_200);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage.clone());
            assert_eq!(enforce_tee_lease_deadlines(&ctx).unwrap(), 1);
            let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
            let jailed = vs.get_validator(VALIDATOR).unwrap().unwrap();
            assert_eq!(jailed.status, outbe_validatorset::runtime::status::JAILED);
            assert_eq!(jailed.slash_count, 0);
        });
    }

    #[test]
    fn tee_lease_sweep_reexecution_and_timestamp_jump_are_deterministic() {
        let deadline = 1_700_000_100;
        let jumped_timestamp = deadline + 10 * 1_209_600;
        let mut base = configured_storage(12, jumped_timestamp);
        install_validator_lease(&mut base, deadline);
        let parent = base.storage.clone();

        let run = || {
            let mut provider = provider_from_storage(12, jumped_timestamp, parent.clone());
            let jailed = provider.enter(|storage| {
                let ctx = runtime_ctx(storage);
                enforce_tee_lease_deadlines(&ctx).unwrap()
            });
            (jailed, provider.storage)
        };

        let first = run();
        let replay = run();
        assert_eq!(first.0, 1);
        assert_eq!(first, replay);
    }

    #[test]
    fn dispatch_boundary_outcome_roundtrip_noop() {
        let mut provider = configured_storage(2, 2);
        provider.enter(|storage| {
            let input = SystemTxInputV2::BoundaryOutcome {
                artifact: boundary_noop(),
            }
            .encode()
            .unwrap();
            dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap();
        });
    }

    #[test]
    fn boundary_outcome_records_announced_tee_recipient_pubkeys() {
        let mut provider = configured_storage(2, 2);
        let recipient = B256::repeat_byte(0x7A);
        let offer_public_key = B256::repeat_byte(0x7B);
        let node_hash = B256::repeat_byte(0x7C);

        provider.enter(|storage| {
            let reg = outbe_teeregistry::TeeRegistry::new(storage.clone());
            reg.tribute_offer_public_key
                .write(offer_public_key)
                .unwrap();
            reg.validator_v1_node_hash
                .write(&VALIDATOR, node_hash)
                .unwrap();
            assert_eq!(reg.announced_recipient_key(VALIDATOR).unwrap(), B256::ZERO);

            let mut artifact = boundary_noop();
            artifact.tee_recipient_pubkeys = vec![(VALIDATOR, recipient)];
            let input = SystemTxInputV2::BoundaryOutcome { artifact }
                .encode()
                .unwrap();
            dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap();
        });

        // The boundary-announced recipient key is now readable from the registry.
        provider.enter(|storage| {
            let reg = outbe_teeregistry::TeeRegistry::new(storage);
            assert_eq!(reg.announced_recipient_key(VALIDATOR).unwrap(), recipient);
            assert_eq!(reg.offer_public_key().unwrap(), offer_public_key);
            assert_eq!(
                reg.validator_v1_node_hash.read(&VALIDATOR).unwrap(),
                node_hash
            );
        });
    }

    #[test]
    fn dispatch_finalization_uses_preloaded_summary_not_calldata_money() {
        let mut provider = configured_storage(2, 1_700_000_000);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
        );
        provider.enter(|storage| {
            let input = SystemTxInputV2::CertifiedParentAccounting {
                metadata: metadata(),
            }
            .encode()
            .unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: Some(AccountedParentArtifact {
                        summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                            validator_fee_sum: U256::ZERO,
                        },
                        timestamp: 1_699_999_990,
                        state_root: Some(B256::repeat_byte(0x92)),
                    }),
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::ZERO,
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
            .unwrap();
        });
    }

    #[test]
    fn phase1_reorg_same_height_uses_parent_state_progress_not_abandoned_post_state() {
        const CHILD_BLOCK: u64 = 27;
        const PARENT_BLOCK: u64 = CHILD_BLOCK - 1;
        const REQUIRED_PREVIOUS: u64 = PARENT_BLOCK - 1;

        let mut base = configured_storage(CHILD_BLOCK, 1_700_000_000);
        record_progress(&mut base, REQUIRED_PREVIOUS);
        let parent_state = base.storage.clone();

        let mut branch_a = provider_from_storage(CHILD_BLOCK, 1_700_000_000, parent_state.clone());
        dispatch_phase1(
            &mut branch_a,
            metadata_for_parent(PARENT_BLOCK, B256::repeat_byte(0xA1)),
        )
        .expect("branch A phase1 commits");
        assert_eq!(read_progress(&mut branch_a), PARENT_BLOCK);

        let mut branch_b_from_parent =
            provider_from_storage(CHILD_BLOCK, 1_700_000_000, parent_state);
        dispatch_phase1(
            &mut branch_b_from_parent,
            metadata_for_parent(PARENT_BLOCK, B256::repeat_byte(0xB2)),
        )
        .expect("same-height branch B must commit from its own parent state");
        assert_eq!(read_progress(&mut branch_b_from_parent), PARENT_BLOCK);

        let mut branch_b_from_abandoned_post_state =
            provider_from_storage(CHILD_BLOCK, 1_700_000_000, branch_a.storage.clone());
        let err = dispatch_phase1(
            &mut branch_b_from_abandoned_post_state,
            metadata_for_parent(PARENT_BLOCK, B256::repeat_byte(0xB2)),
        )
        .expect_err("branch B must not use abandoned branch A post-state");
        assert!(
            err.to_string()
                .contains("CertifiedParentAccounting progress gap"),
            "expected progress-gap failure, got {err}"
        );
    }

    #[test]
    fn dispatch_finalization_counts_duplicate_missed_proposer_events_by_index() {
        let mut provider = configured_storage(2, 1_700_000_000);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
        );
        provider.enter(|storage| {
            let mut metadata = metadata();
            metadata.missed_proposers = vec![
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 1,
                    validator: VALIDATOR,
                },
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 2,
                    validator: VALIDATOR,
                },
            ];
            let input = SystemTxInputV2::CertifiedParentAccounting { metadata }
                .encode()
                .unwrap();
            with_preloaded_system_tx_context(
                PreloadedSystemTxContext {
                    proposer: VALIDATOR,
                    finalized_summary: Some(AccountedParentArtifact {
                        summary: outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                            validator_fee_sum: U256::ZERO,
                        },
                        timestamp: 1_699_999_990,
                        state_root: Some(B256::repeat_byte(0x93)),
                    }),
                    allow_boundary_proposer: false,
                    canonical_vrf_proof_hash: B256::ZERO,
                },
                || dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO),
            )
            .unwrap();
        });

        provider.enter(|storage| {
            let si = outbe_slashindicator::contract::SlashIndicator::new(storage);
            assert_eq!(si.proposer_miss_count.read(&VALIDATOR).unwrap(), 2);
        });
    }

    #[test]
    fn finalization_rejects_non_parent_metadata_before_summary_use() {
        let mut provider = configured_storage(3, 1_700_000_000);
        provider.enter(|storage| {
            let input = SystemTxInputV2::CertifiedParentAccounting {
                metadata: metadata(),
            }
            .encode()
            .unwrap();
            let err = dispatch(storage, &input, SYSTEM_ADDRESS, U256::ZERO).unwrap_err();
            assert!(err
                .to_string()
                .contains("CertifiedParentAccounting metadata must target immediate parent"));
        });
    }

    // ---- Phase 3b: TeeBootstrap handler verification ----

    use outbe_primitives::{
        tee_attestation_v1::{
            AttestationMode, AttestationOperationV1, DcapCollateralComponentV1, DcapCollateralKind,
            NodeIdV1, PlatformTcbStatusSetV1, QvlTcbStatusV1, RegistrationIntentV1,
            ResourceScheduleV1, TeeAttestationManifestV1, TeeMeasurementRuleV1,
            TeePolicyScheduleEntryV1, TeePolicyScheduleV1, TeePolicyV1, ValidatorNodeBindingV1,
        },
        tee_bootstrap_v2::{
            TeeBootstrapCommitteeSignatureV2, TeeBootstrapParticipantEvidenceV2,
            TeeBootstrapParticipantV2, TeeBootstrapV2,
        },
        tee_test_utils::{gramine_direct_bootstrap_v2, gramine_direct_policy_v1, DevValidatorV1},
    };

    fn tee_signing_key(seed: u8) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&outbe_primitives::test_keys::secret((seed) as u64))
            .expect("non-zero scalar")
    }

    fn tee_evm_address(key: &k256::ecdsa::SigningKey) -> Address {
        let point = key.verifying_key().to_encoded_point(false);
        Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
    }

    fn tee_sign(key: &k256::ecdsa::SigningKey, prehash: &B256) -> [u8; 65] {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            key.sign_prehash(prehash.as_slice()).expect("sign prehash");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(sig.to_bytes().as_slice());
        out[64] = recid.to_byte();
        out
    }

    /// Storage seeded with `members` as ACTIVE consensus participants (status
    /// ACTIVE + BLS share present), which is exactly `get_active_consensus_set`.
    fn tee_committee_storage(block_number: u64, members: &[Address]) -> HashMapStorageProvider {
        let mut provider =
            HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, B256::repeat_byte(0x11));
        provider.set_block_number(block_number);
        provider.set_timestamp(U256::from(block_number.max(1)));
        provider.set_beneficiary(members[0]);
        provider.enter(|storage| {
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(OWNER).unwrap();
            vs.set_config_max_validators(128).unwrap();
            vs.config_epoch_length_blocks.write(10).unwrap();
            for (i, member) in members.iter().enumerate() {
                // Distinct consensus pubkey per member (uniqueness is enforced).
                let mut pubkey = [7u8; 48];
                pubkey[0] = i as u8;
                vs.register_validator(OWNER, *member, &pubkey).unwrap();
                vs.activate_validator_via_boundary_for_test(*member)
                    .unwrap();
            }
        });
        provider
    }

    fn is_bootstrapped(provider: &mut HashMapStorageProvider) -> bool {
        provider.enter(|storage| {
            outbe_teeregistry::TeeRegistry::new(storage)
                .is_bootstrapped()
                .unwrap()
        })
    }

    fn keys(seeds: &[u8]) -> Vec<k256::ecdsa::SigningKey> {
        seeds.iter().map(|s| tee_signing_key(*s)).collect()
    }

    fn members(keys: &[k256::ecdsa::SigningKey]) -> Vec<Address> {
        keys.iter().map(tee_evm_address).collect()
    }

    /// Write an epoch-0 `CommitteeSnapshot` (as block 1's `BoundaryOutcome` would)
    /// and return its canonical V2 identity hash.
    fn write_epoch0_snapshot(provider: &mut HashMapStorageProvider, members: &[Address]) -> B256 {
        use outbe_consensus::proof::{CommitteeEntry, CommitteeSnapshot};
        let snapshot = CommitteeSnapshot {
            committee: members
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    let mut pk = [7u8; 48];
                    pk[0] = i as u8;
                    CommitteeEntry {
                        address: *a,
                        consensus_pubkey: pk,
                    }
                })
                .collect(),
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vec![0x11; 96],
            vrf_public_polynomial_hash: B256::ZERO,
        };
        provider.enter(|storage| {
            outbe_validatorset::state::write_committee_snapshot(storage, 0, &snapshot).unwrap();
        });
        outbe_validatorset::committee_set_hash_v2(0, &snapshot)
    }

    fn tee_policy_v1() -> TeePolicyV1 {
        TeePolicyV1 {
            policy_version: 1,
            chain_id: U256::from(CHAIN_ID).to_be_bytes(),
            genesis_hash: B256::repeat_byte(0x11),
            activation_height: 1,
            predecessor_policy_hash: B256::ZERO,
            attestation_mode: AttestationMode::DcapRequired,
            intel_root_der_hash: B256::repeat_byte(0x72),
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
            accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
            accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
            minimum_lease: 3_600,
            maximum_lease: 604_800,
            collateral_margin: 3_600,
            resource_schedule_hash: ResourceScheduleV1::normative()
                .unwrap()
                .schedule_hash()
                .unwrap(),
            measurement_rules: vec![TeeMeasurementRuleV1 {
                mrenclave: B256::repeat_byte(0x81),
                mrsigner: B256::repeat_byte(0x82),
                isv_prod_id: 1,
                minimum_isv_svn: 2,
                admit_from_height: 1,
                admit_until_height_exclusive: 1_000,
            }],
        }
    }

    fn tee_payload_v1(
        block_number: u64,
        keys: &[k256::ecdsa::SigningKey],
        policy: TeePolicyV1,
        committee_snapshot_hash: B256,
    ) -> TeeBootstrapV2 {
        let mut ordered = keys.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|key| tee_evm_address(key));
        let policy_hash = policy.policy_hash().unwrap();
        let collateral_pool = (1_u8..=8)
            .map(|kind| DcapCollateralComponentV1 {
                kind: DcapCollateralKind::try_from(kind).unwrap(),
                bytes: vec![kind],
            })
            .collect();
        let participants = ordered
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let validator = tee_evm_address(key);
                let intent = RegistrationIntentV1 {
                    chain_id: U256::from(CHAIN_ID).to_be_bytes(),
                    genesis_hash: B256::repeat_byte(0x11),
                    operation: AttestationOperationV1::RegisterEnclave,
                    attestation_mode: AttestationMode::DcapRequired,
                    policy_hash,
                    node_id: NodeIdV1 {
                        reth_p2p_public: key
                            .verifying_key()
                            .to_encoded_point(true)
                            .as_bytes()
                            .try_into()
                            .unwrap(),
                    },
                    enclave_id: B256::repeat_byte(0x41 + index as u8),
                    binding_id: B256::repeat_byte(0x51 + index as u8),
                    binding_version: 1,
                    registration_version: 0,
                    renewal_nonce: 0,
                    transition_nonce: 0,
                    requested_valid_until: 7_200,
                    recipient_x25519: [0x61 + index as u8; 32],
                    attestation_ed25519: [0x71 + index as u8; 32],
                    noise_responder_x25519: [0x81 + index as u8; 32],
                    node_host_authorization_hash: B256::repeat_byte(0x91 + index as u8),
                };
                let validator_binding = ValidatorNodeBindingV1 {
                    chain_id: U256::from(CHAIN_ID).to_be_bytes(),
                    genesis_hash: B256::repeat_byte(0x11),
                    validator: validator.into_array(),
                    node_id_hash: intent.node_id.node_id_hash().unwrap(),
                };
                let binding_hash = validator_binding.binding_hash().unwrap();
                TeeBootstrapParticipantV2 {
                    validator_binding,
                    validator_signature: tee_sign(key, &binding_hash),
                    node_binding_signature: tee_sign(key, &binding_hash),
                    intent,
                    evidence: TeeBootstrapParticipantEvidenceV2::Dcap {
                        quote: vec![0xA1 + index as u8; 64],
                        collateral_component_indices: [0, 1, 2, 3, 4, 5, 6, 7],
                    },
                    node_signature: [0xB1 + index as u8; 65],
                    enclave_signature: [0xC1 + index as u8; 64],
                }
            })
            .collect::<Vec<_>>();
        let committee_signatures = ordered
            .iter()
            .map(|key| TeeBootstrapCommitteeSignatureV2 {
                validator: tee_evm_address(key),
                signature: [0; 65],
            })
            .collect();
        let mut payload = TeeBootstrapV2 {
            policy,
            committee_snapshot_hash,
            committee_snapshot_block: block_number,
            key_epoch: 0,
            tribute_offer_epoch: 0,
            dkg_transcript_hash: B256::ZERO,
            tribute_offer_public_key: B256::repeat_byte(0x23),
            tribute_offer_group_public_key: Bytes::from(vec![0x24; 96]),
            collateral_pool,
            participants,
            committee_signatures,
        };
        let signing_hash = payload.signing_hash().unwrap();
        for (signature, key) in payload.committee_signatures.iter_mut().zip(ordered) {
            signature.signature = tee_sign(key, &signing_hash);
        }
        payload
    }

    fn run_bootstrap_v1(
        provider: &mut HashMapStorageProvider,
        payload: TeeBootstrapV2,
    ) -> Result<()> {
        let policy_schedule = TeePolicyScheduleV1 {
            chain_id: payload.policy.chain_id,
            genesis_hash: payload.policy.genesis_hash,
            entries: vec![TeePolicyScheduleEntryV1 {
                activation_height: payload.policy.activation_height,
                policy: payload.policy.clone(),
            }],
        };
        let activation = crate::tee_attestation_activation::TeeAttestationChainSpecStateV1::Active(
            std::sync::Arc::new(
                crate::tee_attestation_activation::TeeAttestationActivationV1 {
                    manifest: TeeAttestationManifestV1 {
                        activation_height: 1,
                        policy_schedule_hash: policy_schedule.schedule_hash().unwrap(),
                        resource_schedule_hash: payload.policy.resource_schedule_hash,
                    },
                    policy_schedule,
                },
            ),
        );
        provider.enter(|storage| {
            let input = SystemTxInputV2::TeeBootstrap { payload }.encode().unwrap();
            dispatch_inner(
                storage,
                &input,
                SYSTEM_ADDRESS,
                U256::ZERO,
                None,
                None,
                &activation,
            )
            .map(|_| ())
        })
    }

    #[test]
    fn tee_bootstrap_v1_rejects_committee_subset_before_qvl_and_writes_nothing() {
        let all_keys = keys(&[0x11, 0x22, 0x33]);
        let mut sorted_members = members(&all_keys);
        sorted_members.sort();
        let mut provider = tee_committee_storage(1, &sorted_members);
        let snapshot_hash = write_epoch0_snapshot(&mut provider, &sorted_members);
        let policy = tee_policy_v1();
        let payload = tee_payload_v1(1, &all_keys[..2], policy, snapshot_hash);

        let error = run_bootstrap_v1(&mut provider, payload)
            .expect_err("a committee subset must fail before DCAP verification");
        assert!(error
            .to_string()
            .contains("complete active consensus committee"));
        assert!(!is_bootstrapped(&mut provider));
        provider.enter(|storage| {
            let registry = outbe_teeregistry::TeeRegistry::new(storage);
            for validator in sorted_members {
                assert!(registry
                    .validator_enclave_binding_v1(validator)
                    .unwrap()
                    .is_none());
            }
        });
    }

    #[test]
    fn tee_bootstrap_v1_routes_canonical_invalid_evidence_and_writes_nothing() {
        let all_keys = keys(&[0x11]);
        let mut sorted_members = members(&all_keys);
        sorted_members.sort();
        let mut provider = tee_committee_storage(1, &sorted_members);
        let snapshot_hash = write_epoch0_snapshot(&mut provider, &sorted_members);
        let policy = tee_policy_v1();
        let payload = tee_payload_v1(1, &all_keys, policy, snapshot_hash);

        run_bootstrap_v1(&mut provider, payload)
            .expect_err("synthetic quote must reach and fail the public DCAP verifier");
        assert!(!is_bootstrapped(&mut provider));
        provider.enter(|storage| {
            assert!(outbe_teeregistry::TeeRegistry::new(storage)
                .validator_enclave_binding_v1(sorted_members[0])
                .unwrap()
                .is_none());
        });
        assert!(outbe_primitives::system_tx::SystemTxKind::TeeBootstrap.revert_fails_block());
    }

    #[test]
    fn gramine_direct_ost3_bootstraps_once_through_the_activated_dispatch() {
        let seeds = [0x11_u8, 0x22, 0x33];
        let signing_keys = keys(&seeds);
        let committee = members(&signing_keys);
        let mut provider = tee_committee_storage(1, &committee);
        let snapshot_hash = write_epoch0_snapshot(&mut provider, &committee);
        let policy = gramine_direct_policy_v1(CHAIN_ID, B256::repeat_byte(0x11)).unwrap();
        let validators = seeds
            .iter()
            .enumerate()
            .map(|(index, seed)| {
                let mut bls_minpk_public = [7_u8; 48];
                bls_minpk_public[0] = index as u8;
                DevValidatorV1 {
                    evm_secret: outbe_primitives::test_keys::secret((*seed) as u64),
                    bls_minpk_public,
                }
            })
            .collect::<Vec<_>>();
        let payload =
            gramine_direct_bootstrap_v2(policy, snapshot_hash, 1, 7_201, &validators).unwrap();

        run_bootstrap_v1(&mut provider, payload.clone()).unwrap();
        assert!(is_bootstrapped(&mut provider));
        provider.enter(|storage| {
            let registry = outbe_teeregistry::TeeRegistry::new(storage);
            for validator in &committee {
                assert!(registry
                    .validator_enclave_binding_v1(*validator)
                    .unwrap()
                    .is_some());
            }
        });

        let error = run_bootstrap_v1(&mut provider, payload).unwrap_err();
        assert!(
            error.to_string().contains("already bootstrapped"),
            "{error}"
        );
    }

    #[test]
    fn gramine_direct_ost3_rejects_a_signed_wrong_snapshot_hash() {
        let seeds = [0x11_u8];
        let signing_keys = keys(&seeds);
        let committee = members(&signing_keys);
        let mut provider = tee_committee_storage(1, &committee);
        let snapshot_hash = write_epoch0_snapshot(&mut provider, &committee);
        let policy = gramine_direct_policy_v1(CHAIN_ID, B256::repeat_byte(0x11)).unwrap();
        let validators = [DevValidatorV1 {
            evm_secret: outbe_primitives::test_keys::secret((seeds[0]) as u64),
            bls_minpk_public: [7_u8; 48],
        }];
        let payload = gramine_direct_bootstrap_v2(
            policy,
            snapshot_hash ^ B256::repeat_byte(1),
            1,
            7_201,
            &validators,
        )
        .unwrap();

        let error = run_bootstrap_v1(&mut provider, payload).unwrap_err();
        assert!(
            error.to_string().contains("snapshot hash mismatch"),
            "{error}"
        );
        assert!(!is_bootstrapped(&mut provider));
    }

    /// Phase 7b glue: `run_late_finalize_credits` at block `N+K` closes the
    /// matured window - pays the escrowed voters, marks `fee_settled`, and routes
    /// the unpaid residue through the active-profile carry-over sink.
    /// Uses an empty credit artifact so the assertion isolates the
    /// `settle_matured` + residue-recycle wiring (the BLS batch path is covered
    /// by the verifier and `late_settlement` unit tests).
    #[test]
    fn late_finalize_window_close_settles_and_recycles_residue() {
        use outbe_primitives::addresses::REWARDS_ADDRESS;

        const V0: Address = address!("0x00000000000000000000000000000000000000A0");
        const V1: Address = address!("0x00000000000000000000000000000000000000A1");
        const V2: Address = address!("0x00000000000000000000000000000000000000A2");
        const V3: Address = address!("0x00000000000000000000000000000000000000A3");
        let fb_hash = B256::repeat_byte(0xAB);
        let timestamp = 1_700_000_000u64;

        // Block N+K = 13 settles block N = 10 (K = LATE_FINALIZE_WINDOW_K = 3).
        let mut provider = configured_storage(13, timestamp);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
        );
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);

            let committee_size = 4u32;
            let pool = U256::from(4_000u64); // divisible by committee
            ctx.storage.increase_balance(REWARDS_ADDRESS, pool).unwrap();
            // Escrow block 10; only 3 of 4 voters credited at k=0 (one absent).
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                10,
                fb_hash,
                pool,
                committee_size,
                0, // epoch
                0, // view
                0, // parent_view
                B256::ZERO,
                &[V0, V1, V2],
            )
            .unwrap();

            // Empty artifact: the mandatory phase still closes block 10's window.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

            let each = pool / U256::from(committee_size); // 1000, unchanged by exclusion
            assert_eq!(ctx.storage.balance(V0).unwrap(), each);
            assert_eq!(ctx.storage.balance(V1).unwrap(), each);
            assert_eq!(ctx.storage.balance(V2).unwrap(), each);
            assert_eq!(
                ctx.storage.balance(V3).unwrap(),
                U256::ZERO,
                "absent voter earns nothing"
            );
            // distributed (3*each) left REWARDS; residue (each) burned for parity.
            assert_eq!(
                ctx.storage.balance(REWARDS_ADDRESS).unwrap(),
                U256::ZERO,
                "REWARDS fully drained (3 paid + residue burned)"
            );
            assert!(
                ctx.storage
                    .contract::<outbe_rewards::schema::Rewards>()
                    .fee_settled
                    .read(&fb_hash)
                    .unwrap(),
                "window marked settled"
            );

            assert_eq!(
                outbe_promislimit::PromisLimitContract::new(ctx.storage.clone())
                    .get_total_unallocated()
                    .unwrap(),
                each,
                "late-settlement residue is credited exactly once to carry-over"
            );
        });
    }

    /// at the inclusion-window close, a registered committee member
    /// that never voted within `K` (`committee \ credited`) gets a voter miss
    /// recorded in BOTH counters; a credited member does not. Proves the relocated,
    /// now-punitive miss accounting runs against the FINAL credited set.
    #[test]
    fn window_close_records_miss_for_absent_committee_voter_only() {
        use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot};

        const V0: Address = address!("0x00000000000000000000000000000000000000B0");
        const V1: Address = address!("0x00000000000000000000000000000000000000B1");
        let timestamp = 1_700_000_000u64;
        let epoch = 0u64;
        let fb_hash = B256::repeat_byte(0xE8);

        // Block N+K = 13 closes block N = 10 (K = LATE_FINALIZE_WINDOW_K = 3).
        let mut provider = configured_storage(13, timestamp);
        provider.enable_metadosis_mutation_frames(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
            2,
        );
        provider.enter(|storage| {
            // Register both committee members so the strict registered-validator
            // contract of `record_finalized_participation` accepts them.
            {
                let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                vs.register_validator(OWNER, V0, &[0xB0; 48]).unwrap();
                vs.activate_validator_via_boundary_for_test(V0).unwrap();
                vs.register_validator(OWNER, V1, &[0xB1; 48]).unwrap();
                vs.activate_validator_via_boundary_for_test(V1).unwrap();
            }

            // Committee snapshot [V0, V1] under (epoch, csh); escrow must bind csh.
            let snapshot = CommitteeSnapshot {
                committee: vec![
                    CommitteeEntry {
                        address: V0,
                        consensus_pubkey: [0xB0; 48],
                    },
                    CommitteeEntry {
                        address: V1,
                        consensus_pubkey: [0xB1; 48],
                    },
                ],
                vrf_material_version: 1,
                vrf_group_public_key_bytes: vec![0x11; 96],
                vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
            };
            let csh = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
            outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                .unwrap();

            let ctx = runtime_ctx(storage);
            // Escrow block 10: committee of 2; only V0 credited at k=0 (V1 absent).
            ctx.storage
                .increase_balance(
                    outbe_primitives::addresses::REWARDS_ADDRESS,
                    U256::from(2_000u64),
                )
                .unwrap();
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                10,
                fb_hash,
                U256::from(2_000u64),
                2,
                epoch,
                0,
                0,
                csh,
                &[V0],
            )
            .unwrap();

            // Close block 10's window: the absentee pass runs before settle.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

            let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
            assert_eq!(
                si.get_voter_miss_count(V1).unwrap(),
                1,
                "absent committee voter is counted missed at window close"
            );
            assert_eq!(
                si.get_voter_miss_count(V0).unwrap(),
                0,
                "credited voter is not counted missed"
            );
            let vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
            assert_eq!(vs.participation(V1).unwrap().missed_votes, 1);
            assert_eq!(vs.participation(V0).unwrap().missed_votes, 0);

            // Replay the closed window: settle freed the escrow and the per-fb_hash
            // guards short-circuit, so re-running must not double-count.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();
            assert_eq!(
                si.get_voter_miss_count(V1).unwrap(),
                1,
                "replay must not double-count the absentee miss"
            );
            assert_eq!(vs.participation(V1).unwrap().missed_votes, 1);
        });
    }

    /// Determinism: the window-close absentee pass is computed purely from committed
    /// chain state (committee snapshot + `late_voter_*`) in committee order, with no
    /// proposer-chosen input - so two independent executions of the same closed
    /// window reach byte-identical slashing state (the proposer/validator guarantee).
    /// Multiple absentees exercise ordering.
    #[test]
    fn window_close_absentee_pass_is_deterministic_and_correct() {
        use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot};

        const C0: Address = address!("0x00000000000000000000000000000000000000C0");
        const C1: Address = address!("0x00000000000000000000000000000000000000C1");
        const C2: Address = address!("0x00000000000000000000000000000000000000C2");
        const C3: Address = address!("0x00000000000000000000000000000000000000C3");
        let epoch = 0u64;
        let fb_hash = B256::repeat_byte(0xD7);
        let members = [C0, C1, C2, C3];

        let run = || -> Vec<(u64, u64)> {
            let mut provider = configured_storage(13, 1_700_000_000);
            provider.enable_metadosis_mutation_frame(
                outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
            );
            let mut out = Vec::new();
            provider.enter(|storage| {
                {
                    let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                    for (i, a) in members.iter().enumerate() {
                        vs.test_register_validator_without_pop(*a, &[0xC0u8 + i as u8; 48])
                            .unwrap();
                        vs.activate_validator_via_boundary_for_test(*a).unwrap();
                    }
                }
                let snapshot = CommitteeSnapshot {
                    committee: members
                        .iter()
                        .enumerate()
                        .map(|(i, a)| CommitteeEntry {
                            address: *a,
                            consensus_pubkey: [0xC0u8 + i as u8; 48],
                        })
                        .collect(),
                    vrf_material_version: 1,
                    vrf_group_public_key_bytes: vec![0x11; 96],
                    vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
                };
                let csh = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
                outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                    .unwrap();

                let ctx = runtime_ctx(storage);
                ctx.storage
                    .increase_balance(
                        outbe_primitives::addresses::REWARDS_ADDRESS,
                        U256::from(4_000u64),
                    )
                    .unwrap();
                // Credit C0 and C2 at k=0; C1 and C3 absent.
                outbe_rewards::late_settlement::escrow_block_fee(
                    &ctx,
                    10,
                    fb_hash,
                    U256::from(4_000u64),
                    4,
                    epoch,
                    0,
                    0,
                    csh,
                    &[C0, C2],
                )
                .unwrap();

                run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

                let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
                let vs = outbe_validatorset::contract::ValidatorSet::new(ctx.storage.clone());
                for a in members {
                    out.push((
                        si.get_voter_miss_count(a).unwrap(),
                        vs.participation(a).unwrap().missed_votes,
                    ));
                }
            });
            out
        };

        let first = run();
        let second = run();
        assert_eq!(
            first, second,
            "window-close absentee pass must be deterministic across executions"
        );
        // C0, C2 credited -> no miss; C1, C3 absent -> miss in both counters.
        assert_eq!(
            first,
            vec![(0, 0), (1, 1), (0, 0), (1, 1)],
            "only the two absent committee members are missed"
        );
    }

    /// Boundary ordering: a block carrying certified `BoundaryOutcome` prepares
    /// its per-epoch counter reset before the receipt-visible
    /// `LateFinalizeCredits` body tx. The later BoundaryOutcome advances the
    /// epoch/set/snapshot without resetting the freshly recorded absentee miss.
    #[test]
    fn window_close_miss_survives_epoch_boundary_reset() {
        use outbe_validatorset::{CommitteeEntry, CommitteeSnapshot};

        const A: Address = address!("0x00000000000000000000000000000000000000E0"); // credited
        const B: Address = address!("0x00000000000000000000000000000000000000E1"); // absent
        let epoch = 0u64;
        let fb_hash = B256::repeat_byte(0xE9);

        // Block 13 is an epoch boundary: configured_storage sets epoch_length=10,
        // epoch_start=0, so `is_epoch_boundary(13)` is true (13 >= 0 + 10).
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enable_metadosis_mutation_frame(
            outbe_primitives::storage::MetadosisMutationPurposeTag::CertifiedFinality,
        );
        provider.enter(|storage| {
            {
                let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
                vs.register_validator(OWNER, A, &[0xE0; 48]).unwrap();
                vs.activate_validator_via_boundary_for_test(A).unwrap();
                vs.register_validator(OWNER, B, &[0xE1; 48]).unwrap();
                vs.activate_validator_via_boundary_for_test(B).unwrap();
            }
            let snapshot = CommitteeSnapshot {
                committee: vec![
                    CommitteeEntry {
                        address: A,
                        consensus_pubkey: [0xE0; 48],
                    },
                    CommitteeEntry {
                        address: B,
                        consensus_pubkey: [0xE1; 48],
                    },
                ],
                vrf_material_version: 1,
                vrf_group_public_key_bytes: vec![0x11; 96],
                vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
            };
            let csh = outbe_validatorset::committee_set_hash_v2(epoch, &snapshot);
            outbe_validatorset::write_committee_snapshot(storage.clone(), epoch, &snapshot)
                .unwrap();

            let ctx = runtime_ctx(storage);
            ctx.storage
                .increase_balance(
                    outbe_primitives::addresses::REWARDS_ADDRESS,
                    U256::from(2_000u64),
                )
                .unwrap();
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                10,
                fb_hash,
                U256::from(2_000u64),
                2,
                epoch,
                0,
                0,
                csh,
                &[A],
            )
            .unwrap();

            // B carries 5 misses accumulated earlier in the epoch.
            {
                let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
                si.voter_miss_count.write(&B, 5).unwrap();
            }

            // Real begin-zone order for a block that actually carries the
            // certified boundary: boundary-conditioned pre-block reset first...
            crate::executor::prepare_boundary_epoch_counters(
                ctx.storage.clone(),
                &boundary_noop(),
                ctx.block.block_number,
            )
            .unwrap();
            // ...then the begin-zone window-close increments.
            run_late_finalize_credits(&ctx, &LateFinalizeCreditsArtifact::default()).unwrap();

            let si = outbe_slashindicator::contract::SlashIndicator::new(ctx.storage.clone());
            assert_eq!(
                si.get_voter_miss_count(B).unwrap(),
                1,
                "absentee miss is recorded AFTER the reset (survives), not lost"
            );
            assert_eq!(si.get_voter_miss_count(A).unwrap(), 0);
        });
    }

    fn dummy_credit(fb_number: u64) -> outbe_primitives::reshare_artifact::PerBlockCredit {
        outbe_primitives::reshare_artifact::PerBlockCredit {
            fb_number,
            fb_hash: B256::repeat_byte(0xCD),
            epoch: 0,
            view: 9,
            parent_view: 8,
            committee_set_hash: B256::repeat_byte(0xEF),
            signer_bitmap: vec![0x01],
            aggregate_signature: [0u8; 96],
        }
    }

    /// #2 defense-in-depth: a body credit whose target is outside the K-block
    /// inclusion window is FATAL (rejected before the snapshot read / BLS verify,
    /// so no snapshot seeding is needed). distance = 13 - 5 = 8 > K = 3.
    #[test]
    fn late_finalize_out_of_window_credit_is_fatal() {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![dummy_credit(5)],
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(
                matches!(err, PrecompileError::Fatal(_)),
                "out-of-window credit must be Fatal, got {err:?}"
            );
            assert!(
                err.to_string().contains("outside inclusion window"),
                "{err}"
            );
        });
    }

    /// bad/unverifiable proof: an in-window, escrow-authenticated credit whose
    /// committee snapshot does not exist is FATAL (the block aborts - never a soft
    /// receipt). distance = 13 - 11 = 2 (in window); the escrow binding matches so
    /// authentication passes and the snapshot lookup is reached and fails.
    #[test]
    fn late_finalize_unverifiable_credit_is_fatal() {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            let credit = dummy_credit(11);
            // Seed an escrow binding that matches the credit so it passes
            // authentication and reaches the (missing) snapshot lookup.
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                credit.fb_number,
                credit.fb_hash,
                U256::from(1_000u64),
                4,
                credit.epoch,
                credit.view,
                credit.parent_view,
                credit.committee_set_hash,
                &[],
            )
            .unwrap();
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![credit],
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(
                matches!(err, PrecompileError::Fatal(_)),
                "unverifiable credit must be Fatal, got {err:?}"
            );
            assert!(
                err.to_string().contains("missing committee snapshot"),
                "{err}"
            );
        });
    }

    /// a credit referencing a finalized block with no
    /// escrow is rejected (the in-window distance passes, but there is nothing to
    /// authenticate against).
    #[test]
    fn no_escrow_credit_rejected() {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![dummy_credit(11)], // in window, but no escrow seeded
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(err.to_string().contains("no escrow for fb_number"), "{err}");
        });
    }

    /// Seed an escrow binding `(11 -> fb_hash 0xCD, epoch 7, csh 0xEF)` and run a
    /// credit that mismatches one field - each must be FATAL.
    fn assert_auth_mismatch_fatal(
        mut mutate: impl FnMut(&mut outbe_primitives::reshare_artifact::PerBlockCredit),
        needle: &str,
    ) {
        let mut provider = configured_storage(13, 1_700_000_000);
        provider.enter(|storage| {
            let ctx = runtime_ctx(storage);
            // Canonical escrow for fb_number 11 (view/parent_view match dummy_credit).
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                11,
                B256::repeat_byte(0xCD),
                U256::from(1_000u64),
                4,
                7, // epoch
                9, // view (dummy_credit default)
                8, // parent_view (dummy_credit default)
                B256::repeat_byte(0xEF),
                &[],
            )
            .unwrap();
            // Also escrow fb_number 12 (a different block) so a spoofed fb_number
            // hits a populated-but-wrong binding rather than an empty one.
            outbe_rewards::late_settlement::escrow_block_fee(
                &ctx,
                12,
                B256::repeat_byte(0xAA),
                U256::from(1_000u64),
                4,
                7, // epoch
                9, // view
                8, // parent_view
                B256::repeat_byte(0xEF),
                &[],
            )
            .unwrap();
            let mut credit = dummy_credit(11); // fb_hash 0xCD, epoch 0, csh 0xEF
            credit.epoch = 7; // match canonical unless the test overrides
            mutate(&mut credit);
            let artifact = LateFinalizeCreditsArtifact {
                batches: vec![credit],
            };
            let err = run_late_finalize_credits(&ctx, &artifact).unwrap_err();
            assert!(err.to_string().contains(needle), "{err}");
        });
    }

    /// BUG-2: spoofing `fb_number` (to shrink `k`) hits a wrong fb_hash binding.
    #[test]
    fn fb_number_mismatch_rejected() {
        // Real block (fb_hash 0xCD) is escrowed at 11; proposer claims fb_number
        // 12 (in window, distance 1) where a different block (0xAA) is escrowed.
        assert_auth_mismatch_fatal(|c| c.fb_number = 12, "fb_hash mismatch");
    }

    /// BUG-5: wrong epoch is rejected.
    #[test]
    fn wrong_epoch_rejected() {
        assert_auth_mismatch_fatal(|c| c.epoch = 9, "epoch mismatch");
    }

    /// BUG-5: wrong committee_set_hash is rejected.
    #[test]
    fn wrong_committee_set_hash_rejected() {
        assert_auth_mismatch_fatal(
            |c| c.committee_set_hash = B256::repeat_byte(0x99),
            "committee_set_hash mismatch",
        );
    }

    /// Review #1b (full binding): a credit with correct fb_number/fb_hash/epoch/
    /// committee_set_hash but a non-canonical `view` is rejected at body auth -
    /// closing the cross-view equivocation credit the pre-exec BLS verify (which
    /// only ties the credit's view to its signatures) would otherwise let through.
    #[test]
    fn wrong_view_rejected() {
        assert_auth_mismatch_fatal(|c| c.view = 99, "view mismatch");
    }

    /// Review #1b (full binding): a non-canonical `parent_view` is rejected.
    #[test]
    fn wrong_parent_view_rejected() {
        assert_auth_mismatch_fatal(|c| c.parent_view = 99, "parent_view mismatch");
    }
}
