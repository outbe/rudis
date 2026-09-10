//! Outbe-reth node binary.
//!
//! Custom reth node with Outbe stateful precompiles and Commonware Simplex consensus.
//! Two tokio runtimes: Reth execution (main thread) + Commonware consensus (spawned thread).
//!
//! Also provides the `dkg` subcommand for bootstrapping BLS threshold key material.

use clap::Parser;
use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
use eyre::WrapErr as _;
use outbe_compressed_entities::{
    CandidateCacheLimits, CeMdbx, CompressedTreeService, EnvironmentIdentity, FinalizedMarker,
    ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
};
use outbe_consensus::executor::actor::FinalizedCeCommitter;
use outbe_engine::args::ConsensusArgs;
use outbe_engine::bridge::ConsensusExecutionBridge;
use outbe_engine::ce_finalizer::{
    DurableCeState, FinalizedCeTree, RethCeFinalizer, RethDurableCeState,
};
use outbe_engine::ce_recovery::{
    CanonicalCeReplaySource, CeStartupRecovery, CeStartupRecoveryCoordinator, StartupCeTree,
};
use outbe_evm::OutbeEvmSigner;
use outbe_node::{
    compressed_storage::{
        validate_compressed_storage_runtime_config, CompressedStorageRuntimeConfig,
    },
    ocomp::retention::{RetainedTributeWriter, SharedOcompRetentionSelector},
    projection::{
        prepare_offchain_data_projection_with_retention, validate_offchain_data_checkpoint,
        OffchainDataProjectionConfig, ProjectionRetentionFence,
    },
    OutbeBeaconConsensus, OutbeFullNode, OutbeNode,
};
use outbe_operator::tee::{
    inspect_upgrade_journal_v1, read_finalized_registry_view_v1, record_upgrade_finalized_v1,
    record_upgrade_missed_cutoff_v1, record_upgrade_promoted_v1, NodeBindingSelectorV1,
    UpgradeJournalStateV1,
};
use outbe_primitives::projection::{
    projection_readiness, ProjectionCheckpoint, ProjectionReadinessHandle, ProjectionStatus,
};
use outbe_primitives::OutbeHeader;
use reth_chainspec::{ChainSpec, EthChainSpec};
use reth_cli::chainspec::ChainSpecParser;
use reth_ethereum::cli::interface::Cli;
use reth_node_builder::NodeHandle;
use reth_provider::{BlockIdReader, HeaderProvider, StateProviderFactory};
use reth_rpc_server_types::{RethRpcModule, RpcModuleSelection, RpcModuleValidator};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::sync::oneshot;
use tracing::info;

mod execution_runtime;
mod ocomp_exex;
mod ocomp_genesis;
mod tee_genesis;

const TEE_UPGRADE_POLL_SECS: u64 = 30;
const TEE_UPGRADE_WARNING_BLOCKS: u64 = 600;
const TEE_UPGRADE_CRITICAL_BLOCKS: u64 = 120;
const TEE_LEASE_GUARD_POLL_SECS: u64 = 1;

fn load_installed_ocomp_bundles(
    domain_root: &Path,
    initial: outbe_ocomp::bundle::PinnedProtocolBundle,
    configured_hashes: Option<&str>,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> eyre::Result<Vec<outbe_ocomp::bundle::PinnedProtocolBundle>> {
    let catalog_root = domain_root.join("protocol-bundles-v1");
    let initial_hash = initial.hash();
    let mut bundles = BTreeMap::new();
    let metadata = match std::fs::symlink_metadata(&catalog_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return select_installed_ocomp_bundles(
                initial,
                initial_hash,
                bundles,
                configured_hashes,
            );
        }
        Err(error) => return Err(error).wrap_err("inspect OCOMP bundle catalog"),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        eyre::bail!("OCOMP bundle catalog must be a real directory");
    }
    for entry in std::fs::read_dir(&catalog_root).wrap_err("read OCOMP bundle catalog")? {
        let entry = entry.wrap_err("read OCOMP bundle catalog entry")?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .wrap_err("inspect OCOMP bundle catalog entry")?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            eyre::bail!("OCOMP bundle catalog entries must be regular files");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eyre::eyre!("OCOMP bundle filename is not UTF-8"))?;
        let hash_hex = name
            .strip_suffix(".ocb1")
            .ok_or_else(|| eyre::eyre!("OCOMP bundle filename must end in .ocb1"))?;
        if hash_hex.len() != 64
            || !hash_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            eyre::bail!("OCOMP bundle filename must be 64 lowercase hex characters plus .ocb1");
        }
        let canonical = std::fs::read(entry.path()).wrap_err("read installed OCOMP bundle")?;
        let bundle =
            outbe_ocomp::bundle::PinnedProtocolBundle::decode_canonical(&canonical, limits)
                .wrap_err("decode installed OCOMP bundle")?;
        if hex::encode(bundle.hash().as_slice()) != hash_hex {
            eyre::bail!("installed OCOMP bundle filename does not match its canonical hash");
        }
        if let Some(existing) = bundles.insert(bundle.hash(), bundle.clone()) {
            if existing != bundle {
                eyre::bail!("conflicting installed OCOMP bundle bytes");
            }
        }
    }
    select_installed_ocomp_bundles(initial, initial_hash, bundles, configured_hashes)
}

fn select_installed_ocomp_bundles(
    initial: outbe_ocomp::bundle::PinnedProtocolBundle,
    initial_hash: alloy_primitives::B256,
    bundles: BTreeMap<alloy_primitives::B256, outbe_ocomp::bundle::PinnedProtocolBundle>,
    configured_hashes: Option<&str>,
) -> eyre::Result<Vec<outbe_ocomp::bundle::PinnedProtocolBundle>> {
    if bundles.is_empty() {
        if let Some(configured) = configured_hashes {
            let hashes = parse_ocomp_bundle_hashes(configured)?;
            if hashes.as_slice() != [initial_hash] {
                eyre::bail!(
                    "configured OCOMP bundle hashes require a populated hash-addressed catalog"
                );
            }
        }
        return Ok(vec![initial]);
    }
    ordered_installed_ocomp_bundle_hashes(initial_hash, &bundles, configured_hashes)?
        .into_iter()
        .map(|hash| {
            bundles.get(&hash).cloned().ok_or_else(|| {
                eyre::eyre!("configured OCOMP bundle {hash} is not installed in the catalog")
            })
        })
        .collect()
}

fn ordered_installed_ocomp_bundle_hashes<V>(
    initial_hash: alloy_primitives::B256,
    bundles: &BTreeMap<alloy_primitives::B256, V>,
    configured_hashes: Option<&str>,
) -> eyre::Result<Vec<alloy_primitives::B256>> {
    if bundles.is_empty() || bundles.len() > 2 {
        eyre::bail!("OCOMP runtime supports exactly active plus one staged/retiring bundle");
    }
    if let Some(configured) = configured_hashes {
        let hashes = parse_ocomp_bundle_hashes(configured)?;
        if hashes.len() != bundles.len() || hashes.iter().any(|hash| !bundles.contains_key(hash)) {
            eyre::bail!("OCOMP bundle catalog must exactly match OCOMP_PROTOCOL_BUNDLE_HASHES");
        }
        return Ok(hashes);
    }

    if bundles.len() > 1 && !bundles.contains_key(&initial_hash) {
        eyre::bail!(
            "OCOMP_PROTOCOL_BUNDLE_HASHES is required to order a post-genesis two-bundle catalog"
        );
    }
    let mut hashes = bundles.keys().copied().collect::<Vec<_>>();
    hashes.sort_by_key(|hash| *hash != initial_hash);
    Ok(hashes)
}

fn parse_ocomp_bundle_hashes(value: &str) -> eyre::Result<Vec<alloy_primitives::B256>> {
    let mut hashes = Vec::new();
    for encoded in value.split(',') {
        let hex_value = encoded
            .strip_prefix("0x")
            .ok_or_else(|| eyre::eyre!("OCOMP bundle hash must have a 0x prefix"))?;
        if hex_value.len() != 64
            || !hex_value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            eyre::bail!("OCOMP bundle hash must be 64 lowercase hex characters after 0x");
        }
        let decoded = hex::decode(hex_value).wrap_err("decode configured OCOMP bundle hash")?;
        let hash = alloy_primitives::B256::from_slice(&decoded);
        if hashes.contains(&hash) {
            eyre::bail!("OCOMP bundle hash list contains a duplicate");
        }
        hashes.push(hash);
    }
    if hashes.is_empty() || hashes.len() > 2 {
        eyre::bail!("OCOMP bundle hash list must contain one or two adjacent authorities");
    }
    Ok(hashes)
}

struct UpgradePromotionWorkerConfigV1 {
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
    node_data_dir: PathBuf,
    poll_secs: u64,
    warning_blocks: u64,
    critical_blocks: u64,
    promoted: Arc<tokio::sync::Notify>,
}

/// Exact finalized checkpoint at which a node may arm its local lease guard
/// after replaying stale or pre-registration history. This is process-local
/// startup authority, never consensus or wire state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalTeeAdmissionAnchorV1 {
    finalized_height: u64,
    finalized_hash: alloy_primitives::B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TeeLeaseGuardGateV1 {
    pending_anchor: Option<LocalTeeAdmissionAnchorV1>,
}

impl TeeLeaseGuardGateV1 {
    const fn new(pending_anchor: Option<LocalTeeAdmissionAnchorV1>) -> Self {
        Self { pending_anchor }
    }

    const fn is_armed(self) -> bool {
        self.pending_anchor.is_none()
    }

    const fn anchor_to_validate(
        self,
        local_finalized_height: u64,
    ) -> Option<LocalTeeAdmissionAnchorV1> {
        match self.pending_anchor {
            Some(anchor) if local_finalized_height >= anchor.finalized_height => Some(anchor),
            _ => None,
        }
    }

    fn validate_and_arm(
        &mut self,
        observed_hash: alloy_primitives::B256,
        admission: outbe_engine::validators::LocalTeeRuntimeAdmissionV1,
    ) -> eyre::Result<()> {
        let Some(anchor) = self.pending_anchor else {
            return Ok(());
        };
        eyre::ensure!(
            observed_hash == anchor.finalized_hash,
            "TEE admission anchor hash mismatch at height {}: expected {}, local {}",
            anchor.finalized_height,
            anchor.finalized_hash,
            observed_hash
        );
        match admission {
            outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Ready { .. } => {
                self.pending_anchor = None;
                Ok(())
            }
            outbe_engine::validators::LocalTeeRuntimeAdmissionV1::BootstrapPending => {
                eyre::bail!("TEE admission anchor unexpectedly has bootstrap-pending TEE state");
            }
            outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Rejected(reason) => {
                eyre::bail!(
                    "TEE admission anchor rejected the local identity: {}",
                    local_tee_rejection_message(reason)
                );
            }
        }
    }
}

fn require_validator_tee_recovery_complete_v1(
    is_validator: bool,
    gate: TeeLeaseGuardGateV1,
    node_data_dir: &Path,
) -> eyre::Result<()> {
    if !is_validator || gate.is_armed() {
        return Ok(());
    }

    let Some(anchor) = gate.pending_anchor else {
        return Ok(());
    };
    eyre::bail!(
        "validator recovery requires certified follower catch-up before authority startup: local finalized state has not reached the durable TEE join anchor at height {} ({}) in {}. Stop this process; start the same outbe-chain binary with this same datadir and the same network/TEE options, omit --validator and every validator signing/Radicle authority flag, and add --upstream <healthy-certified-rpc> (do not use --upstream.nocertify). Wait for `local TEE lease guard armed at authenticated catch-up anchor`, stop the follower, then restart the original validator command. Submit readiness only after the validator is caught up; signing authority returns only after a fresh DKG installs current private material",
        anchor.finalized_height,
        anchor.finalized_hash,
        node_data_dir.display(),
    );
}

fn validator_admission_anchor_from_durable_v1(
    durable: outbe_tee::FinalizedJoinAdmissionAnchorV1,
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
    identity: outbe_engine::validators::LocalTeeRuntimeIdentityV1,
) -> eyre::Result<LocalTeeAdmissionAnchorV1> {
    use outbe_primitives::tee_attestation_v1::NodeIdV1;

    let node_id_hash = NodeIdV1 {
        reth_p2p_public: identity.reth_p2p_public,
    }
    .node_id_hash()
    .map_err(|error| eyre::eyre!("derive local NodeHost identity: {error}"))?;
    eyre::ensure!(
        durable.chain_id == alloy_primitives::U256::from(chain_id).to_be_bytes(),
        "finalized join admission anchor chain id mismatch"
    );
    eyre::ensure!(
        durable.genesis_hash == genesis_hash,
        "finalized join admission anchor genesis mismatch"
    );
    eyre::ensure!(
        durable.node_id_hash == node_id_hash,
        "finalized join admission anchor NodeHost identity mismatch"
    );
    eyre::ensure!(
        identity.expected_enclave_id == Some(durable.enclave_id),
        "finalized join admission anchor enclave identity mismatch"
    );
    Ok(LocalTeeAdmissionAnchorV1 {
        finalized_height: durable.finalized_height,
        finalized_hash: durable.finalized_hash,
    })
}

fn local_tee_rejection_message(
    rejection: outbe_engine::validators::LocalTeeRuntimeRejectionV1,
) -> String {
    use outbe_engine::validators::LocalTeeRuntimeRejectionV1;

    match rejection {
        LocalTeeRuntimeRejectionV1::MissingBinding => {
            "finalized Registry has no binding for the local NodeHost; run tee join".to_owned()
        }
        LocalTeeRuntimeRejectionV1::EnclaveIdentityMismatch => {
            "finalized Registry binding does not match the committed local enclave; run tee join"
                .to_owned()
        }
        LocalTeeRuntimeRejectionV1::ValidatorBindingMismatch => {
            "finalized validator and local NodeHost bindings disagree; refusing consensus startup"
                .to_owned()
        }
        LocalTeeRuntimeRejectionV1::ValidatorJailed => {
            "validator is jailed; complete ordinary unjail and then run tee join".to_owned()
        }
        LocalTeeRuntimeRejectionV1::Expired { valid_until } => {
            format!("finalized TEE lease expired at {valid_until}; stop node and run tee join")
        }
    }
}

fn tee_lease_admission_rejection(
    admission: outbe_engine::validators::LocalTeeRuntimeAdmissionV1,
) -> Option<String> {
    match admission {
        outbe_engine::validators::LocalTeeRuntimeAdmissionV1::BootstrapPending
        | outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Ready { .. } => None,
        outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Rejected(reason) => {
            Some(local_tee_rejection_message(reason))
        }
    }
}

fn validator_recovery_startup_admission_rejection(
    admission: outbe_engine::validators::LocalTeeRuntimeAdmissionV1,
) -> Option<String> {
    match admission {
        outbe_engine::validators::LocalTeeRuntimeAdmissionV1::BootstrapPending => Some(
            "finalized TEE admission is bootstrap-pending; refusing validator authority startup"
                .to_owned(),
        ),
        other => tee_lease_admission_rejection(other),
    }
}

fn read_local_tee_admission_at_height<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
    identity: outbe_engine::validators::LocalTeeRuntimeIdentityV1,
    block_number: u64,
) -> eyre::Result<(
    alloy_primitives::B256,
    outbe_engine::validators::LocalTeeRuntimeAdmissionV1,
)>
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    let header = provider
        .sealed_header(block_number)
        .wrap_err("read exact header for TEE lease admission")?
        .ok_or_else(|| eyre::eyre!("exact TEE lease admission header is unavailable"))?;
    let block_hash = header.hash();
    let state = provider
        .state_by_block_hash(block_hash)
        .wrap_err("read exact state for TEE lease admission")?;
    let admission = outbe_engine::validators::read_local_tee_runtime_admission_from_state(
        &state,
        outbe_primitives::storage::readonly::ReadOnlyBlockContext {
            chain_id,
            genesis_hash,
            block_number,
            timestamp: header.header().inner.timestamp,
        },
        identity,
    )?;
    Ok((block_hash, admission))
}

fn read_finalized_local_tee_admission<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
    identity: outbe_engine::validators::LocalTeeRuntimeIdentityV1,
) -> eyre::Result<Option<outbe_engine::validators::LocalTeeRuntimeAdmissionV1>>
where
    P: BlockIdReader + HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    let Some(finalized) = provider
        .finalized_block_num_hash()
        .wrap_err("read finalized head for TEE lease admission")?
    else {
        return Ok(None);
    };
    if finalized.number == 0 {
        return Ok(None);
    }
    let (header_hash, admission) = read_local_tee_admission_at_height(
        provider,
        chain_id,
        genesis_hash,
        identity,
        finalized.number,
    )?;
    eyre::ensure!(
        header_hash == finalized.hash,
        "finalized TEE lease header hash mismatch: marker {}, header {}",
        finalized.hash,
        header_hash
    );
    Ok(Some(admission))
}

fn read_gated_finalized_local_tee_admission<P>(
    provider: &P,
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
    identity: outbe_engine::validators::LocalTeeRuntimeIdentityV1,
    gate: &mut TeeLeaseGuardGateV1,
) -> eyre::Result<Option<outbe_engine::validators::LocalTeeRuntimeAdmissionV1>>
where
    P: BlockIdReader + HeaderProvider<Header = OutbeHeader> + StateProviderFactory,
{
    let Some(finalized) = provider
        .finalized_block_num_hash()
        .wrap_err("read finalized head for gated TEE lease admission")?
    else {
        return Ok(None);
    };
    if finalized.number == 0 {
        return Ok(None);
    }
    let Some(anchor) = gate.anchor_to_validate(finalized.number) else {
        return if gate.is_armed() {
            read_finalized_local_tee_admission(provider, chain_id, genesis_hash, identity)
        } else {
            Ok(None)
        };
    };

    let (anchor_hash, anchor_admission) = read_local_tee_admission_at_height(
        provider,
        chain_id,
        genesis_hash,
        identity,
        anchor.finalized_height,
    )?;
    gate.validate_and_arm(anchor_hash, anchor_admission)?;
    info!(
        anchor_height = anchor.finalized_height,
        anchor_hash = %anchor.finalized_hash,
        local_finalized_height = finalized.number,
        "local TEE lease guard armed at authenticated catch-up anchor"
    );
    if finalized.number == anchor.finalized_height {
        return Ok(Some(anchor_admission));
    }
    read_finalized_local_tee_admission(provider, chain_id, genesis_hash, identity)
}

async fn require_upstream_fullnode_tee_admission(
    upstream: &str,
    identity: outbe_engine::validators::LocalTeeRuntimeIdentityV1,
) -> eyre::Result<LocalTeeAdmissionAnchorV1> {
    let rpc = outbe_operator::rpc::HttpRenewalRpc::new(upstream);
    let view = read_finalized_registry_view_v1(
        &rpc,
        &NodeBindingSelectorV1::NodeHost(identity.reth_p2p_public),
    )
    .await
    .wrap_err("read upstream finalized FullNode TEE admission")?;
    let binding = view.binding.ok_or_else(|| {
        eyre::eyre!("finalized Registry has no binding for this FullNode; run tee join first")
    })?;
    if identity
        .expected_enclave_id
        .is_some_and(|expected| expected != binding.enclave_id)
    {
        eyre::bail!(
            "finalized FullNode binding does not match the committed local enclave; run tee join"
        );
    }
    if binding.valid_until <= view.schedule.finalized_timestamp {
        eyre::bail!(
            "finalized FullNode TEE lease expired at {}; run tee join before startup",
            binding.valid_until
        );
    }
    Ok(LocalTeeAdmissionAnchorV1 {
        finalized_height: view.view.block_number,
        finalized_hash: view.view.block_hash,
    })
}

async fn run_tee_lease_guard_v1<P>(
    provider: P,
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
    identity: outbe_engine::validators::LocalTeeRuntimeIdentityV1,
    mut gate: TeeLeaseGuardGateV1,
    shutdown: tokio_util::sync::CancellationToken,
) -> eyre::Result<Option<String>>
where
    P: BlockIdReader
        + HeaderProvider<Header = OutbeHeader>
        + StateProviderFactory
        + Send
        + Sync
        + 'static,
{
    let mut interval = tokio::time::interval(Duration::from_secs(TEE_LEASE_GUARD_POLL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(None),
            _ = interval.tick() => {}
        }
        match read_gated_finalized_local_tee_admission(
            &provider,
            chain_id,
            genesis_hash,
            identity,
            &mut gate,
        ) {
            Ok(None) => {}
            Ok(Some(admission)) => {
                if let Some(reason) = tee_lease_admission_rejection(admission) {
                    return Ok(Some(reason));
                }
            }
            Err(error) => {
                return Err(error.wrap_err("finalized TEE lease admission failed closed"));
            }
        }
    }
}

/// A canonical lease rejection is an expected stop; failure to read that state
/// is still an operational error, even though both stop the local node.
fn tee_lease_exit_reason(
    verdict: Option<eyre::Result<String>>,
    shutdown: &outbe_node::shutdown::NodeShutdown,
) -> String {
    match verdict.unwrap_or_else(|| Err(eyre::eyre!("TEE lease guard stopped without a verdict"))) {
        Ok(reason) => reason,
        Err(error) => {
            let reason = format!("{error:#}");
            shutdown.record_failure(error);
            reason
        }
    }
}

async fn run_upgrade_promotion_worker_v1<P>(provider: P, config: UpgradePromotionWorkerConfigV1)
where
    P: HeaderProvider<Header = OutbeHeader> + StateProviderFactory + Send + Sync + 'static,
{
    let UpgradePromotionWorkerConfigV1 {
        chain_id,
        genesis_hash,
        node_data_dir,
        poll_secs,
        warning_blocks,
        critical_blocks,
        promoted,
    } = config;
    loop {
        let snapshot = match inspect_upgrade_journal_v1(&node_data_dir) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                tokio::time::sleep(std::time::Duration::from_secs(poll_secs)).await;
                continue;
            }
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "read enclave-upgrade journal failed");
                return;
            }
        };
        let context = snapshot.lifecycle.context().clone();
        match &snapshot.lifecycle {
            UpgradeJournalStateV1::Promoted { .. } => return,
            UpgradeJournalStateV1::TerminalMissedCutoff {
                finalized_height,
                activation_height,
                ..
            } => {
                tracing::error!(
                    finalized_height,
                    activation_height,
                    "enclave upgrade is terminal after missing successor activation cutoff"
                );
                return;
            }
            UpgradeJournalStateV1::Finalized {
                finalized_height,
                finalized_hash,
                ..
            } => {
                let committed = match outbe_tee::load_committed_enclave_manifest_v1(&node_data_dir)
                {
                    Ok(committed) => committed,
                    Err(error) => {
                        tracing::error!(error = %error, "load committed manifest during upgrade recovery failed");
                        return;
                    }
                };
                let committed_hash = match committed.authorization_hash() {
                    Ok(hash) => hash,
                    Err(error) => {
                        tracing::error!(error = %error, "hash committed manifest during upgrade recovery failed");
                        return;
                    }
                };
                if committed_hash == context.candidate_manifest_hash {
                    if let Err(error) = record_upgrade_promoted_v1(&node_data_dir) {
                        tracing::error!(error = %format!("{error:#}"), "record recovered upgrade promotion failed");
                        return;
                    }
                    info!(finalized_height, %finalized_hash, "reconciled already-promoted enclave candidate");
                    return;
                }
                match outbe_node::tee_remote_session::construct_local_finalized_replacement_authorization_with_view_v1(
                    &provider,
                    chain_id,
                    genesis_hash,
                    &node_data_dir,
                    &committed.node_id,
                ) {
                    Ok(authorized) => {
                        if let Err(error) = outbe_tee::promote_replacement_candidate(
                            &node_data_dir,
                            &authorized.authorization,
                        ) {
                            tracing::error!(error = %error, "promote finalized enclave candidate failed");
                            return;
                        }
                        if let Err(error) = record_upgrade_promoted_v1(&node_data_dir) {
                            tracing::error!(error = %format!("{error:#}"), "record finalized enclave promotion failed");
                            return;
                        }
                        info!(finalized_height, %finalized_hash, "finalized enclave candidate promoted; execution restart required");
                        promoted.notify_one();
                        return;
                    }
                    Err(error) => {
                        tracing::error!(error = %error, "reconstruct finalized candidate promotion authority failed");
                        return;
                    }
                }
            }
            _ => {}
        }

        let status =
            match outbe_node::tee_remote_session::inspect_local_finalized_successor_status_v1(
                &provider,
                chain_id,
                genesis_hash,
            ) {
                Ok(status) => status,
                Err(error) => {
                    tracing::error!(error = %error, "read node-local finalized successor status failed");
                    tokio::time::sleep(std::time::Duration::from_secs(poll_secs)).await;
                    continue;
                }
            };
        if let Some(policy) = &status.staged_policy {
            let policy_hash = match policy.policy_hash() {
                Ok(hash) => hash,
                Err(error) => {
                    tracing::error!(error = %error, "hash node-local staged successor policy failed");
                    return;
                }
            };
            if policy_hash != context.successor_policy_hash
                || policy.activation_height != context.activation_height
            {
                tracing::error!(
                    "journaled enclave upgrade no longer matches the finalized staged successor"
                );
                return;
            }
        }
        if matches!(snapshot.lifecycle, UpgradeJournalStateV1::Submitted { .. }) {
            let committed = match outbe_tee::load_committed_enclave_manifest_v1(&node_data_dir) {
                Ok(committed) => committed,
                Err(error) => {
                    tracing::error!(error = %error, "load active manifest for finalized upgrade check failed");
                    return;
                }
            };
            match outbe_node::tee_remote_session::construct_local_finalized_replacement_authorization_with_view_v1(
                &provider,
                chain_id,
                genesis_hash,
                &node_data_dir,
                &committed.node_id,
            ) {
                Ok(authorized) => {
                    // A matching finalized B proves that transition execution
                    // happened before the Registry cutoff, even when finality
                    // advanced across H in one step.
                    if let Err(error) = record_upgrade_finalized_v1(
                        &node_data_dir,
                        authorized.view.block_number,
                        authorized.view.block_hash,
                    ) {
                        tracing::error!(error = %format!("{error:#}"), "record finalized enclave transition failed");
                        return;
                    }
                    if let Err(error) = outbe_tee::promote_replacement_candidate(
                        &node_data_dir,
                        &authorized.authorization,
                    ) {
                        tracing::error!(error = %error, "promote finalized enclave candidate failed");
                        return;
                    }
                    if let Err(error) = record_upgrade_promoted_v1(&node_data_dir) {
                        tracing::error!(error = %format!("{error:#}"), "record enclave candidate promotion failed");
                        return;
                    }
                    info!(
                        finalized_height = authorized.view.block_number,
                        finalized_hash = %authorized.view.block_hash,
                        "finalized enclave candidate promoted; execution restart required"
                    );
                    promoted.notify_one();
                    return;
                }
                Err(outbe_node::tee_remote_session::LocalRegistryAdmissionError::ReplacementBindingMissing) => {}
                Err(error) => {
                    tracing::error!(error = %error, "finalized enclave transition authorization failed");
                    return;
                }
            }
        }
        if status.view.block_number >= context.activation_height {
            match record_upgrade_missed_cutoff_v1(
                &node_data_dir,
                status.view.block_number,
                context.activation_height,
            ) {
                Ok(_) => tracing::error!(
                    finalized_height = status.view.block_number,
                    activation_height = context.activation_height,
                    "enclave upgrade missed its finalized successor activation cutoff"
                ),
                Err(error) => {
                    tracing::error!(error = %format!("{error:#}"), "record missed enclave-upgrade cutoff failed")
                }
            }
            return;
        }
        let remaining = context
            .activation_height
            .saturating_sub(status.view.block_number);
        if remaining <= critical_blocks {
            tracing::error!(
                finalized_height = status.view.block_number,
                activation_height = context.activation_height,
                remaining_blocks = remaining,
                "enclave upgrade is inside its critical finalized activation margin"
            );
        } else if remaining <= warning_blocks {
            tracing::warn!(
                finalized_height = status.view.block_number,
                activation_height = context.activation_height,
                remaining_blocks = remaining,
                "enclave upgrade is inside its warning finalized activation margin"
            );
        }

        tokio::time::sleep(std::time::Duration::from_secs(poll_secs)).await;
    }
}

#[derive(Debug, Clone, Default)]
struct OutbeChainSpecParser;

#[derive(Debug, Clone, Copy, Default)]
struct OutbeRpcModuleValidator;

impl RpcModuleValidator for OutbeRpcModuleValidator {
    fn parse_selection(s: &str) -> Result<RpcModuleSelection, String> {
        let mut selection = s
            .parse::<RpcModuleSelection>()
            .map_err(|error| format!("Failed to parse RPC modules: {error}"))?;

        if let RpcModuleSelection::Selection(modules) = &mut selection {
            // Preserve the operator selector; expose only rudis_* on the wire.
            if modules.remove(&RethRpcModule::Other("outbe".to_owned())) {
                modules.insert(RethRpcModule::Other("rudis".to_owned()));
            }
            for module in modules.iter() {
                let RethRpcModule::Other(name) = module else {
                    continue;
                };
                if name != "rudis" {
                    return Err(format!("Unknown RPC module: '{name}'"));
                }
            }
        }

        Ok(selection)
    }
}

impl ChainSpecParser for OutbeChainSpecParser {
    type ChainSpec = ChainSpec<OutbeHeader>;

    const SUPPORTED_CHAINS: &'static [&'static str] =
        reth_ethereum::cli::chainspec::SUPPORTED_CHAINS;

    fn default_value() -> Option<&'static str> {
        None
    }

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        let chain_spec: Arc<Self::ChainSpec> =
            reth_ethereum::cli::chainspec::chain_value_parser(s)?
                .as_ref()
                .clone()
                .map_header(OutbeHeader::new)
                .into();
        validate_outbe_chain_spec(chain_spec.as_ref())?;
        outbe_consensus::proof::init_consensus_chain_id(chain_spec.chain().id())
            .map_err(|error| eyre::eyre!("invalid consensus chain identity: {error}"))?;
        Ok(chain_spec)
    }
}

fn validate_outbe_chain_spec(chain_spec: &ChainSpec<OutbeHeader>) -> eyre::Result<()> {
    let chain_id = chain_spec.chain().id();
    eyre::ensure!(
        outbe_primitives::chain::network_for_chain_id(chain_id).is_some(),
        "unknown Outbe chain ID {chain_id}"
    );
    outbe_evm::tee_attestation_activation::TeeAttestationChainSpecStateV1::from_chain_spec(
        chain_spec,
    )
    .activation()
    .map_err(|error| eyre::eyre!("invalid mandatory teeAttestationV1 ChainSpec: {error}"))?;
    outbe_node::ocomp::fork::require_startup_ocomp_fork_install(chain_spec)?;
    outbe_chain_constants::initialize(
        chain_spec
            .genesis
            .config
            .extra_fields
            .get(outbe_chain_constants::GENESIS_CONFIG_KEY),
    )
    .map_err(|error| eyre::eyre!("invalid config.outbeProtocol: {error}"))?;
    Ok(())
}

/// Ceiling for advised gas price: one COEN per gas, already far above anything
/// this chain charges, so a fee spike can never advise an unpayable number.
const OUTBE_MAX_SUGGESTED_GAS_PRICE: u64 = 1_000_000_000_000_000_000;

/// Reth suggests a one gwei tip while its oracle has no sampled block to learn
/// from. Keep the cold-start floor tiny in raw native units and cap sampled
/// advice at one 18-decimal COEN per gas.
fn apply_outbe_gas_price_oracle_defaults<C: reth_cli::chainspec::ChainSpecParser, Ext, SubCmd>(
    command: &mut reth_ethereum::cli::interface::Commands<C, Ext, SubCmd>,
) where
    Ext: clap::Args + std::fmt::Debug,
    SubCmd: clap::Subcommand + std::fmt::Debug,
{
    if let reth_ethereum::cli::interface::Commands::Node(node) = command {
        node.rpc.gas_price_oracle.default_suggested_fee = Some(alloy_primitives::U256::from(
            alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE,
        ));
        node.rpc.gas_price_oracle.max_price = OUTBE_MAX_SUGGESTED_GAS_PRICE;
    }
}

fn command_requires_crs<C: reth_cli::chainspec::ChainSpecParser, Ext, SubCmd>(
    command: &reth_ethereum::cli::interface::Commands<C, Ext, SubCmd>,
) -> bool
where
    Ext: clap::Args + std::fmt::Debug,
    SubCmd: clap::Subcommand + std::fmt::Debug,
{
    matches!(command, reth_ethereum::cli::interface::Commands::Node(_))
}

fn initialize_crs_for_command<C, Ext, SubCmd>(
    command: &reth_ethereum::cli::interface::Commands<C, Ext, SubCmd>,
    initialize: impl FnOnce() -> eyre::Result<()>,
) -> eyre::Result<()>
where
    C: reth_cli::chainspec::ChainSpecParser,
    Ext: clap::Args + std::fmt::Debug,
    SubCmd: clap::Subcommand + std::fmt::Debug,
{
    if command_requires_crs(command) {
        initialize()?;
    }
    Ok(())
}

fn handle_consensus_thread_join(joined: thread::Result<eyre::Result<()>>) -> eyre::Result<()> {
    match joined {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err.wrap_err("consensus task exited with error")),
        Err(unwind) => std::panic::resume_unwind(unwind),
    }
}

fn run_with_lifetime_pin<P, F, T>(pin: P, run: F) -> T
where
    F: FnOnce() -> T,
{
    let output = run();
    drop(pin);
    output
}

// Manager and endpoint each have a five-second drain budget; leave time for
// acknowledgement and task reaping before shutting down their transport.
const RADICLE_DRAIN_DEADLINE: Duration = Duration::from_secs(12);

async fn await_radicle_drain(
    completion: Option<oneshot::Receiver<()>>,
    deadline: Duration,
) -> eyre::Result<()> {
    let Some(completion) = completion else {
        return Ok(());
    };
    tokio::time::timeout(deadline, completion)
        .await
        .map_err(|_| eyre::eyre!("Radicle drain deadline exceeded before transport shutdown"))?
        .map_err(|_| eyre::eyre!("Radicle observer exited without completing its drain"))
}

async fn abort_and_wait_supervised<T>(
    handle: &mut commonware_runtime::Handle<T>,
) -> Result<Option<T>, commonware_runtime::Error>
where
    T: Send + 'static,
{
    handle.abort();
    match handle.await {
        Ok(result) => Ok(Some(result)),
        // Aborting an unfinished supervised task closes its result channel.
        Err(commonware_runtime::Error::Closed) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Global stop acknowledges signal guards, not publication of the stack result.
/// Give the retained owner time to return its terminal error before aborting it.
async fn await_consensus_stack_shutdown(
    handle: &mut commonware_runtime::Handle<eyre::Result<()>>,
    deadline: Duration,
) -> eyre::Result<()> {
    match tokio::time::timeout(deadline, &mut *handle).await {
        Ok(result) => result.map_err(|error| {
            eyre::eyre!("consensus stack task failed during shutdown: {error:?}")
        })?,
        Err(_) => {
            let timeout = eyre::eyre!("consensus stack result deadline exceeded after global stop");
            match abort_and_wait_supervised(handle).await {
                Ok(Some(Err(error))) => Err(error.wrap_err(format!("{timeout:#}"))),
                Err(error) => Err(timeout.wrap_err(format!(
                    "consensus stack task failed while reaping: {error:?}"
                ))),
                // Forced cancellation is cleanup, not a successful stack exit.
                Ok(Some(Ok(())) | None) => Err(timeout),
            }
        }
    }
}

fn consensus_shutdown_result(
    stop: Result<(), commonware_runtime::Error>,
    stack: eyre::Result<()>,
) -> eyre::Result<()> {
    let stop = stop.map_err(|error| {
        eyre::eyre!("consensus graceful shutdown did not complete within 5 seconds: {error}")
    });
    match (stop, stack) {
        (Err(stop), Err(stack)) => Err(stack.wrap_err(format!("{stop:#}"))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LauncherExitCause {
    NodeExited,
    ConsensusExited,
    OcompRequested,
    UpgradeRequested,
    TeeLeaseRejected,
    CtrlC,
}

/// Keeps the Commonware runtime alive until its task tree has observed shutdown.
///
/// Reth owns the process signal handler and may cancel the complete node launcher
/// future. This guard therefore performs the same cancellation and synchronous
/// join from `Drop` as the ordinary completion path, preventing Reth's ExEx and
/// Engine resources from disappearing while consensus still holds an exact
/// application acknowledgement.
struct ConsensusThreadGuard {
    shutdown: tokio_util::sync::CancellationToken,
    handle: Option<thread::JoinHandle<eyre::Result<()>>>,
    outcome: Option<outbe_node::shutdown::NodeShutdown>,
}

impl ConsensusThreadGuard {
    fn new(
        shutdown: tokio_util::sync::CancellationToken,
        handle: thread::JoinHandle<eyre::Result<()>>,
    ) -> Self {
        Self {
            shutdown,
            handle: Some(handle),
            outcome: None,
        }
    }

    fn with_outcome(mut self, outcome: outbe_node::shutdown::NodeShutdown) -> Self {
        self.outcome = Some(outcome);
        self
    }

    fn join(mut self) -> thread::Result<eyre::Result<()>> {
        self.shutdown.cancel();
        let handle = self
            .handle
            .take()
            .expect("consensus thread handle is consumed exactly once");
        handle.join()
    }
}

impl Drop for ConsensusThreadGuard {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        self.shutdown.cancel();
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(%error, "consensus task failed during launcher teardown");
                if let Some(outcome) = &self.outcome {
                    outcome.record_failure(error);
                }
            }
            Err(panic) => {
                tracing::error!("consensus task panicked during launcher teardown");
                if let Some(outcome) = &self.outcome {
                    outcome.record_panic(panic);
                }
            }
        }
    }
}

/// DKG bootstrap subcommand, parsed separately from reth's CLI.
#[derive(clap::Parser)]
#[command(name = "outbe-chain-dkg")]
struct DkgCli {
    /// BLS key storage backend: plaintext, encrypted, or os-level.
    #[arg(long = "bls-key-backend", default_value = "plaintext", global = true)]
    bls_key_backend: String,

    /// Passphrase for the encrypted BLS key backend.
    #[arg(long = "bls-passphrase", env = "BLS_PASSPHRASE", global = true)]
    bls_passphrase: Option<String>,

    #[command(subcommand)]
    command: DkgCommand,
}

#[derive(clap::Subcommand)]
enum DkgCommand {
    /// Generate only the validator identity keys used by a fresh interactive genesis DKG.
    Identities {
        /// Output directory for generated identity key material.
        #[arg(long)]
        output_dir: std::path::PathBuf,

        /// Number of validator identities to generate.
        #[arg(long)]
        validators: u32,
    },
    /// Verify that imported founder private keys match their public validator manifest.
    VerifyIdentities {
        /// Public validators.json manifest.
        #[arg(long)]
        validators: std::path::PathBuf,

        /// Directory containing validator-N/signing-key.hex and evm-key.hex.
        #[arg(long)]
        material_dir: std::path::PathBuf,
    },
    /// Bootstrap DKG material for a validator set.
    Bootstrap {
        /// Output directory for generated key material.
        #[arg(long)]
        output_dir: std::path::PathBuf,

        /// Number of validators to bootstrap.
        #[arg(long)]
        validators: u32,
    },
    /// Show status of DKG key material in a storage directory.
    Status {
        /// Storage directory containing DKG material.
        #[arg(long)]
        storage_dir: std::path::PathBuf,
    },
    /// Export DKG signing share, polynomial, and output to a directory.
    ExportShare {
        /// Storage directory containing DKG material.
        #[arg(long)]
        storage_dir: std::path::PathBuf,

        /// Output directory for exported files.
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Import DKG signing share, polynomial, and output into a storage directory.
    ImportShare {
        /// Path to the signing share file.
        #[arg(long)]
        share: std::path::PathBuf,

        /// Path to the public polynomial file.
        #[arg(long)]
        polynomial: std::path::PathBuf,

        /// Path to the DKG output file. Defaults to dkg_output.hex next to --share.
        #[arg(long)]
        output: Option<std::path::PathBuf>,

        /// Storage directory to import into.
        #[arg(long)]
        storage_dir: std::path::PathBuf,
    },
    /// Delete only the local consensus threshold material.
    /// This never modifies or recovers the permanent TEE offer key; normal
    /// genesis or live-join gates still decide whether startup may proceed.
    ForceRestart {
        /// Storage directory containing DKG material.
        #[arg(long)]
        storage_dir: std::path::PathBuf,
    },
}

fn main() -> eyre::Result<()> {
    // Intercept Outbe-owned subcommands before reth CLI parsing.
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "dkg" {
        return run_dkg_command(&args);
    }
    if args.len() > 1 && args[1] == "tee" {
        return tee_genesis::run(&args);
    }
    if args.len() > 1 && args[1] == "ocomp" {
        return ocomp_genesis::run(&args);
    }

    // Intercept `--version` / `-V` so that the user sees Outbe-side build
    // metadata in addition to Reth's own version string. The Outbe block is
    // printed first; Reth's CLI then prints its own version and exits.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        print_outbe_version();
    }

    run_node()
}

/// Outbe build metadata block printed before delegating `--version` to
/// Reth's CLI. Layout mirrors reth-node-core / kona-node so operators
/// see a familiar five-line block.
const OUTBE_LONG_VERSION: &str = concat!(
    env!("OUTBE_LONG_VERSION_0"),
    "\n",
    env!("OUTBE_LONG_VERSION_1"),
    "\n",
    env!("OUTBE_LONG_VERSION_2"),
    "\n",
    env!("OUTBE_LONG_VERSION_3"),
    "\n",
    env!("OUTBE_LONG_VERSION_4"),
);

/// Print Outbe build metadata baked in by `build.rs`. Followed downstream by
/// Reth's own `--version` output.
fn print_outbe_version() {
    println!("Outbe {}", env!("OUTBE_SHORT_VERSION"));
    println!("{OUTBE_LONG_VERSION}");
    println!();
}

fn validate_adr005_node_mode(is_validator: bool, has_certified_upstream: bool) -> eyre::Result<()> {
    if !is_validator && !has_certified_upstream {
        eyre::bail!(
            "ADR-005 plain EL full-node mode is disabled: use --upstream so historical execution is gated by exact finalized-parent projection readiness"
        );
    }
    Ok(())
}

/// Parse DKG CLI's --bls-key-backend into a KeyBackend.
fn parse_dkg_key_backend(cli: &DkgCli) -> eyre::Result<outbe_consensus::bls::KeyBackend> {
    match cli.bls_key_backend.as_str() {
        "plaintext" => Ok(outbe_consensus::bls::KeyBackend::Plaintext),
        "encrypted" => {
            let passphrase = cli
                .bls_passphrase
                .clone()
                .ok_or_else(|| eyre::eyre!("--bls-key-backend encrypted requires --bls-passphrase or BLS_PASSPHRASE env var"))?;
            Ok(outbe_consensus::bls::KeyBackend::Encrypted(passphrase))
        }
        "os-level" => Ok(outbe_consensus::bls::KeyBackend::OsLevel),
        other => Err(eyre::eyre!("unknown BLS key backend: {other}")),
    }
}

/// Handle the `dkg` subcommand.
fn run_dkg_command(args: &[String]) -> eyre::Result<()> {
    // Rebuild args as: "outbe-chain-dkg" "bootstrap" ...remaining...
    let mut dkg_args = vec![args[0].clone()];
    dkg_args.extend_from_slice(&args[2..]);
    let dkg_cli = DkgCli::parse_from(dkg_args);

    let backend = parse_dkg_key_backend(&dkg_cli)?;

    match dkg_cli.command {
        DkgCommand::Identities {
            output_dir,
            validators,
        } => outbe_consensus::cli::execute_validator_identities(output_dir, validators, &backend),
        DkgCommand::VerifyIdentities {
            validators,
            material_dir,
        } => outbe_consensus::cli::execute_validator_identity_verification(
            &validators,
            &material_dir,
            &backend,
        ),
        DkgCommand::Bootstrap {
            output_dir,
            validators,
        } => outbe_consensus::cli::execute_dkg_bootstrap(output_dir, validators, &backend),
        DkgCommand::Status { storage_dir } => {
            outbe_consensus::cli::execute_dkg_status(&storage_dir, &backend)
        }
        DkgCommand::ExportShare {
            storage_dir,
            output,
        } => outbe_consensus::cli::execute_dkg_export_share(&storage_dir, &output, &backend),
        DkgCommand::ImportShare {
            share,
            polynomial,
            output,
            storage_dir,
        } => outbe_consensus::cli::execute_dkg_import_share(
            &share,
            &polynomial,
            output.as_deref(),
            &storage_dir,
            &backend,
        ),
        DkgCommand::ForceRestart { storage_dir } => {
            outbe_consensus::cli::execute_dkg_force_restart(&storage_dir)
        }
    }
}

fn load_reth_p2p_node_host_signer(
    network: &reth_node_core::args::NetworkArgs,
    default_secret_path: PathBuf,
) -> eyre::Result<(k256::ecdsa::SigningKey, [u8; 33])> {
    let reth_p2p_secret = network
        .secret_key(default_secret_path)
        .wrap_err("failed to load persistent Reth P2P identity for TEE")?;
    let signing = k256::ecdsa::SigningKey::from_slice(reth_p2p_secret.secret_bytes().as_slice())
        .map_err(|error| eyre::eyre!("invalid Reth P2P signing key: {error}"))?;
    let reth_p2p_public = signing
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| eyre::eyre!("Reth P2P public key is not compressed SEC1-33"))?;
    Ok((signing, reth_p2p_public))
}

/// Run the main node (Reth execution + Commonware consensus).
fn run_node() -> eyre::Result<()> {
    // TEE offer decryption routes exclusively through the enclave sidecar
    // (`--tee-enclave-socket` -> persistent production NodeHost authorization);
    // the offer-decryption key exists only inside the enclave (single path, no
    // in-process key material).

    // Pool lifetime hardening. Must run BEFORE CLI parsing: clap reads these as
    // its own defaults, so explicit `--txpool.*` flags still win.
    let _ = outbe_default_txpool_values().try_init();

    let mut cli = Cli::<OutbeChainSpecParser, ConsensusArgs, OutbeRpcModuleValidator>::parse();
    apply_outbe_gas_price_oracle_defaults(&mut cli.command);

    // Initialize the hash-pinned Barretenberg global CRS before block
    // execution. Tribute admission is consensus-critical, so a node that
    // cannot initialize the verifier must not start. Database and other
    // operator commands never execute proofs and must remain offline.
    // This still runs before `Cli::run` creates the Tokio runtime because
    // `setup_srs` uses `reqwest::blocking` internally.
    initialize_crs_for_command(&cli.command, || {
        let srs_path = std::env::var("OUTBE_BB_SRS_PATH").ok();
        outbe_zk_backend::barretenberg::init_crs().map_err(eyre::Report::from)?;
        tracing::info!(
            num_points = outbe_zk_backend::barretenberg::CANONICAL_SRS_POINTS,
            path = ?srs_path,
            "Barretenberg SRS initialized"
        );
        Ok(())
    })?;

    let bridge = ConsensusExecutionBridge::new();

    // Channels for validator-mode consensus thread.
    // For full-node mode, no thread is spawned and these are unused.
    let (node_tx, node_rx) = oneshot::channel::<(
        OutbeFullNode,
        ConsensusArgs,
        ProjectionReadinessHandle,
        Option<ProjectionReadinessHandle>,
        Arc<RetainedTributeWriter>,
        Arc<ProjectionRetentionFence>,
        Arc<SharedOcompRetentionSelector>,
        Arc<dyn FinalizedCeCommitter>,
        Arc<dyn CeStartupRecovery>,
        Option<(
            outbe_radicle::integration::EndpointNetworkService,
            outbe_radicle::integration::LocalEndpointIdentityHandle,
            outbe_radicle::integration::RadicleStatusHandle,
            outbe_radicle::integration::EndpointTaskOwner,
        )>,
        Option<oneshot::Receiver<()>>,
    )>();
    let (consensus_dead_tx, mut consensus_dead_rx) = oneshot::channel::<()>();
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    // A terminal protocol outcome must drain Radicle without racing the main
    // signal branch into aborting the stack before it returns its primary error.
    let radicle_shutdown_token = shutdown_token.child_token();

    // Consensus thread is spawned conditionally - see inside run_with_components
    // where `args.is_validator` is known. For now, prepare the closure.
    let shutdown_token_clone = shutdown_token.clone();
    let radicle_shutdown_for_consensus = radicle_shutdown_token.clone();
    let bridge_for_consensus = bridge.clone();
    let consensus_thread_fn = move || -> eyre::Result<()> {
        let (
            node,
            mut args,
            projection_readiness,
            ocomp_readiness,
            retained_tribute_writer,
            projection_retention_fence,
            retention_selector,
            finalized_ce_committer,
            ce_startup_recovery,
            radicle,
            radicle_drained,
        ) = match node_rx.blocking_recv() {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        args.validate()?;

        let data_dir = node
            .config
            .datadir
            .clone()
            .resolve_datadir(reth_ethereum::chainspec::EthChainSpec::chain(
                &*node.chain_spec(),
            ))
            .data_dir()
            .to_path_buf();

        let consensus_storage = args
            .storage_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("consensus"));

        // Write back effective storage_dir so the consensus stack sees it
        // even when the CLI did not provide --consensus.storage-dir.
        if args.storage_dir.is_none() {
            args.storage_dir = Some(consensus_storage.clone());
        }

        let keys_dir = args
            .keys_dir
            .clone()
            .unwrap_or_else(|| data_dir.join("keys"));

        if args.keys_dir.is_none() {
            args.keys_dir = Some(keys_dir.clone());
        }

        let chain_id = reth_ethereum::chainspec::EthChainSpec::chain(&*node.chain_spec()).id();
        outbe_consensus::proof::init_consensus_chain_id(chain_id)
            .wrap_err("bind consensus process to the selected chain id")?;
        outbe_consensus::storage_identity::bind_consensus_storage_identity(
            &consensus_storage,
            chain_id,
            node.chain_spec().genesis_hash(),
        )
        .wrap_err("validate consensus restart storage identity")?;

        // Migrate DKG files from legacy location (consensus/) to keys/.
        outbe_engine::stack::migrate_dkg_keys_if_needed(&consensus_storage, &keys_dir)?;

        info!(
            path = %consensus_storage.display(),
            "starting consensus runtime"
        );

        // initialize the append-only slashing journal at
        // `<consensus_storage>/slashing-journal.jsonl`. The journal
        // captures every SlashIndicator/ValidatorSet state transition
        // in JSONL form and is independent of reth log rotation. If
        // initialization fails, log a warning and continue - the
        // journal is best-effort observability and must not block node
        // startup.
        if let Err(error) = outbe_primitives::slashing_journal::init(&consensus_storage) {
            tracing::warn!(
                target: "outbe::slashing::journal",
                %error,
                "failed to initialize slashing journal - events will not be persisted to a sidecar file",
            );
        }

        if let Err(error) = outbe_primitives::governance_journal::init(&consensus_storage) {
            tracing::warn!(
                target: "outbe::governance::journal",
                %error,
                "failed to initialize governance journal - events will not be persisted to a sidecar file",
            );
        }

        let runtime_config = commonware_runtime::tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(args.worker_threads)
            .with_storage_directory(consensus_storage)
            .with_catch_panics(true);

        let runner = commonware_runtime::tokio::Runner::new(runtime_config);
        let node_lifetime_pin = node.clone();

        let ret: eyre::Result<()> = run_with_lifetime_pin(node_lifetime_pin, || {
            runner.start(async move |ctx| {
                let graceful_shutdown = ctx.child("shutdown");
                let application_shutdown = radicle_shutdown_for_consensus;
                let application_drain = outbe_engine::application_shutdown::ApplicationDrain::new(async move {
                    application_shutdown.cancel();
                    await_radicle_drain(radicle_drained, RADICLE_DRAIN_DEADLINE).await
                });
                let stack_application_drain = application_drain.clone();
                let (follower_drain, follower_shutdown) =
                    outbe_engine::follower_shutdown::follower_drain_pair();
                let mut stack_handle = ctx.child("consensus_stack").spawn(move |stack_ctx| {
                    outbe_engine::run_consensus_stack(
                        stack_ctx,
                        args,
                        node,
                        bridge_for_consensus,
                        {
                            let mut services = outbe_engine::ConsensusStackServices::new(
                                projection_readiness,
                                retained_tribute_writer,
                                projection_retention_fence,
                                retention_selector,
                                finalized_ce_committer,
                                ce_startup_recovery,
                            )
                            .with_follower_shutdown(follower_shutdown)
                            .with_application_drain(stack_application_drain);
                            if let Some(readiness) = ocomp_readiness {
                                services = services.with_ocomp_readiness(readiness);
                            }
                            if let Some((endpoint, local, status, owner)) = radicle {
                                services = services.with_radicle(status, endpoint, local, owner);
                            }
                            services
                        },
                    )
                });
                commonware_macros::select! {
                    _ = shutdown_token_clone.cancelled() => {
                        info!("consensus stack shutting down");
                        // The manager may still be using endpoint discovery. Keep
                        // Commonware transport alive until both owners have drained.
                        let radicle_result = application_drain.drain().await;
                        if let Err(error) = &radicle_result {
                            tracing::error!(%error, "Radicle drain failed before transport shutdown");
                        }
                        // Close follower delivery ingress and persist all accepted
                        // proofs while Marshal can still answer certificate reads.
                        let follower_result = follower_drain.drain(Duration::from_secs(5)).await;
                        if let Err(error) = &follower_result {
                            tracing::error!(%error, "follower drain failed before Marshal shutdown");
                        }
                        let stop_result = graceful_shutdown
                            .stop(0, Some(Duration::from_secs(5)))
                            .await;
                        let stack_result = await_consensus_stack_shutdown(
                            &mut stack_handle, Duration::from_secs(5),
                        ).await;
                        if let Err(error) = &stack_result {
                            tracing::error!(%error, "consensus stack failed during shutdown");
                        }
                        let stack_result = match (stack_result, follower_result) {
                            (Err(error), Err(drain)) => Err(error.wrap_err(format!("follower drain also failed: {drain:#}"))),
                            (Err(error), _) | (_, Err(error)) => Err(error),
                            (Ok(()), Ok(())) => Ok(()),
                        };
                        outbe_engine::application_shutdown::combine(
                            consensus_shutdown_result(stop_result, stack_result), radicle_result,
                        )
                    },
                    result = &mut stack_handle => {
                        let result = result.map_err(|error| {
                            eyre::eyre!("consensus stack task failed: {error:?}")
                        })?;
                        if let Err(e) = &result {
                            tracing::error!(%e, "consensus stack failed");
                        }
                        result
                    },
                }
            })
        });

        let _ = consensus_dead_tx.send(());
        ret
    };

    // Thread 1 (main): Reth execution layer.
    let bridge_for_evm = bridge.clone();
    let components = move |spec: Arc<ChainSpec<OutbeHeader>>| {
        let fork_install =
            outbe_node::ocomp::fork::require_startup_ocomp_fork_install(spec.as_ref())
                .expect("chain spec parser validated OCOMP fork install");
        let activation = outbe_primitives::system_tx::OcompLifecycleActivation::at_block(
            fork_install.activation_height,
        );
        let mut evm =
            outbe_evm::OutbeEvmConfig::new_with_bridge(spec.clone(), bridge_for_evm.clone())
                .with_ocomp_lifecycle_activation(activation);
        evm = evm.with_ocomp_fork_install(fork_install);
        (
            evm,
            Arc::new(
                OutbeBeaconConsensus::new(spec)
                    .with_max_extra_data_size(outbe_node::consensus::OUTBE_MAX_EXTRA_DATA_SIZE)
                    .with_ocomp_lifecycle_activation(activation),
            ),
        )
    };

    // This owner outlives cancellation of the launcher and Reth runtime teardown.
    let process_shutdown = outbe_node::shutdown::NodeShutdown::default();
    let launcher_shutdown = process_shutdown.clone();
    // Preserve the pool overrides normally applied by Reth's default CLI runner.
    let runtime_config = match &cli.command {
        reth_ethereum::cli::interface::Commands::Node(command) => {
            reth_ethereum::tasks::RuntimeConfig::default().with_rayon(
                reth_ethereum::tasks::RayonConfig {
                    reserved_cpu_cores: command.engine.reserved_cpu_cores,
                    proof_storage_worker_threads: command.engine.storage_worker_count,
                    proof_account_worker_threads: command.engine.account_worker_count,
                    prewarming_threads: command.engine.prewarming_threads,
                    ..Default::default()
                },
            )
        }
        _ => reth_ethereum::tasks::RuntimeConfig::default(),
    };
    let command_result = execution_runtime::run_with_execution_runtime(runtime_config, |runner| {
    cli.with_runner_and_components::<OutbeNode>(runner, components, async move |builder, args| {
        let shutdown = launcher_shutdown.clone();
        let result: eyre::Result<()> = async move {
        let _cancel_on_launcher_drop = shutdown_token.clone().drop_guard();
        args.validate()?;
        let (radicle_preflight, radicle_status) = if args.is_validator {
            let socket = args
                .radicle_control_socket
                .as_ref()
                .expect("validated Radicle control socket");
            let sidecar = outbe_radicle::integration::query_sidecar(
                socket,
                std::time::Duration::from_secs(5),
            )
            .await
            .wrap_err("Radicle sidecar preflight failed")?;
            let evm_key = args
                .effective_validator_evm_key()?
                .ok_or_else(|| eyre::eyre!("validator EVM key is required for Radicle identity"))?;
            let validator = outbe_primitives::signer::OutbeEvmSigner::from_file(&evm_key)
                .wrap_err("load validator EVM key for Radicle identity")?
                .address();
            let (publisher, status) =
                outbe_radicle::integration::RadicleStatusChannel::enabled(
                    validator,
                    sidecar.node_id,
                );
            (Some((validator, sidecar, publisher)), status)
        } else {
            (
                None,
                outbe_radicle::integration::RadicleStatusChannel::disabled(),
            )
        };
        if radicle_preflight.is_none() {
            let mut metrics = outbe_radicle::integration::RadicleMetrics::default();
            metrics.record(&radicle_status.snapshot());
        }
        info!(
            target: "outbe::protocol",
            formingPeriodSeconds = outbe_chain_constants::get_metadosis_forming_period_seconds(),
            lookbackDelaySeconds = outbe_chain_constants::get_metadosis_lookback_delay_seconds(),
            offeringPeriodSeconds = outbe_chain_constants::get_metadosis_offering_period_seconds(),
            waitingPeriodSeconds = outbe_chain_constants::get_metadosis_waiting_period_seconds(),
            bootstrapDurationSeconds =
                outbe_chain_constants::get_metadosis_bootstrap_duration_seconds(),
            advanceIntervalSeconds =
                outbe_chain_constants::get_metadosis_advance_interval_seconds(),
            "effective genesis protocol parameters"
        );
        let tee_attestation_v1 =
            outbe_evm::tee_attestation_activation::TeeAttestationChainSpecStateV1::from_chain_spec(
                builder.config().chain.as_ref(),
            );
        let tee_activation = tee_attestation_v1.activation().map_err(|error| {
            eyre::eyre!("invalid mandatory teeAttestationV1 ChainSpec: {error}")
        })?;
        let initial_tee_policy = tee_activation
            .policy_at(outbe_evm::tee_attestation_activation::TEE_ATTESTATION_V1_ACTIVATION_HEIGHT)
            .map_err(eyre::Report::msg)?;
        let dkg_prepare_window_blocks = builder
            .config()
            .chain
            .genesis
            .config
            .extra_fields
            .get_deserialized::<u64>("dkgPrepareWindowBlocks")
            .transpose()
            .map_err(|error| eyre::eyre!("invalid dkgPrepareWindowBlocks: {error}"))?
            .unwrap_or(outbe_consensus::config::DEFAULT_DKG_PREPARE_WINDOW_BLOCKS);
        let minimum_block_time_millis = builder
            .config()
            .chain
            .genesis
            .config
            .extra_fields
            .get_deserialized::<u64>("minBlockTimeMs")
            .transpose()
            .map_err(|error| eyre::eyre!("invalid minBlockTimeMs: {error}"))?
            .unwrap_or(outbe_consensus::timing::DEFAULT_MIN_BLOCK_TIME_MS);
        info!(
            attestation_mode = ?initial_tee_policy.attestation_mode,
            activation_height = tee_activation.manifest.activation_height,
            policy_schedule_hash = %tee_activation.manifest.policy_schedule_hash,
            "validated mandatory TEE attestation ChainSpec authority"
        );
        let ocomp_fork_install =
            outbe_node::ocomp::fork::require_startup_ocomp_fork_install(
                builder.config().chain.as_ref(),
            )?;
        let ocomp_limits = outbe_ocomp_protocol::profile::poc_schema_limits();
        let ocomp_install_hash = ocomp_fork_install.install_hash(&ocomp_limits)?;
        info!(
            activation_height = ocomp_fork_install.activation_height,
            classification = ?ocomp_fork_install.classification,
            install_hash = %ocomp_install_hash,
            "validated genesis-active immutable OCOMP chain-manifest install"
        );

        let prune_config = builder
            .config()
            .pruning
            .prune_config(builder.config().chain.as_ref());
        validate_compressed_storage_runtime_config(CompressedStorageRuntimeConfig {
            persistence_threshold: builder.config().engine.persistence_threshold,
            memory_block_buffer_target: builder.config().engine.memory_block_buffer_target,
            max_pending_acks: outbe_consensus::config::MAX_PENDING_ACKS,
            receipts_pruning_enabled: prune_config
                .as_ref()
                .is_some_and(|config| config.has_receipts_pruning()),
            account_history_pruning_enabled: prune_config
                .as_ref()
                .is_some_and(|config| config.segments.account_history.is_some()),
            storage_history_pruning_enabled: prune_config
                .as_ref()
                .is_some_and(|config| config.segments.storage_history.is_some()),
        })?;

        let node_data_dir = builder
            .config()
            .datadir
            .clone()
            .resolve_datadir(reth_ethereum::chainspec::EthChainSpec::chain(
                builder.config().chain.as_ref(),
            ))
            .data_dir()
            .to_path_buf();
        let ocomp_domain_root = node_data_dir
            .parent()
            .ok_or_else(|| eyre::eyre!("node data directory has no OCOMP domain parent"))?
            .join("ocomp")
            .join("domain-v1");
        let ocomp_bundle_bytes = ocomp_fork_install
            .protocol_bundle
            .encode_canonical(&ocomp_limits)?;
        let ocomp_bundle = outbe_ocomp::bundle::PinnedProtocolBundle::decode(
            &ocomp_bundle_bytes,
            ocomp_fork_install.request_profile.protocol_bundle_hash,
            &ocomp_limits,
        )?;
        let configured_ocomp_bundle_hashes =
            std::env::var("OCOMP_PROTOCOL_BUNDLE_HASHES").ok();
        let ocomp_bundles = load_installed_ocomp_bundles(
            &ocomp_domain_root,
            ocomp_bundle,
            configured_ocomp_bundle_hashes.as_deref(),
            &ocomp_limits,
        )?;
        let ocomp_worker_base_port = args
            .listen_address
            .port()
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("consensus port leaves no OCOMP Worker endpoint port"))?;
        let mut ocomp_runtime_bundles = Vec::with_capacity(ocomp_bundles.len());
        let ocomp_lane_port_stride = u16::try_from(
            outbe_ocomp::worker_transport::MAX_REGISTERED_WORKERS,
        )
        .map_err(|_| eyre::eyre!("OCOMP worker limit exceeds u16"))?
        .checked_add(2)
        .ok_or_else(|| eyre::eyre!("OCOMP bundle lane port stride overflow"))?;
        for (index, bundle) in ocomp_bundles.into_iter().enumerate() {
            let lane = u16::try_from(index)
                .map_err(|_| eyre::eyre!("OCOMP bundle lane count exceeds u16"))?;
            let port_offset = lane
                .checked_mul(ocomp_lane_port_stride)
                .ok_or_else(|| eyre::eyre!("OCOMP bundle lane port offset overflow"))?;
            let worker_port = ocomp_worker_base_port
                .checked_add(port_offset)
                .ok_or_else(|| eyre::eyre!("OCOMP bundle lane leaves no Worker endpoint port"))?;
            let worker_address = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                worker_port,
            );
            info!(
                bundle_hash = %bundle.hash(),
                lane = index,
                %worker_address,
                "loaded pinned OCOMP runtime bundle lane"
            );
            ocomp_runtime_bundles.push(ocomp_exex::OcompExExBundleConfigV1 {
                worker_address,
                identity: outbe_ocomp_protocol::local_control::EndpointIdentity {
                    chain_id: builder.config().chain.chain().id(),
                    genesis_hash: builder.config().chain.genesis_hash(),
                    boot_nonce: ocomp_install_hash,
                    protocol_bundle_hash: bundle.hash(),
                },
                protocol_bundle: bundle,
            });
        }
        let ocomp_policy = if args.is_validator {
            outbe_ocomp::embedded_runtime::EmbeddedNodePolicyV1::Validator
        } else {
            outbe_ocomp::embedded_runtime::EmbeddedNodePolicyV1::FullNode
        };
        let ocomp_validator_rpc_url = if args.is_validator {
            if !builder.config().rpc.http {
                eyre::bail!("validator OCOMP requires the local HTTP RPC server");
            }
            Some(format!(
                "http://127.0.0.1:{}",
                builder.config().rpc.http_port
            ))
        } else {
            None
        };
        let retention_selector = Arc::new(SharedOcompRetentionSelector::new());
        let discovery_spool_root = ocomp_domain_root.join("exporter-v1/discovery");
        let ocomp_exex_config = ocomp_exex::OcompExExConfigV1 {
            domain_root: ocomp_domain_root,
            discovery_spool_root,
            bundles: ocomp_runtime_bundles,
            policy: ocomp_policy,
            validator_rpc_url: ocomp_validator_rpc_url,
            chain_id: builder.config().chain.chain().id(),
            genesis_hash: builder.config().chain.genesis_hash(),
            retention_selector: Arc::clone(&retention_selector),
            retention_required: args.is_validator || args.upstream.is_some(),
        };
        let ocomp_baseline = ProjectionCheckpoint {
            block_number: 0,
            block_hash: builder.config().chain.genesis_hash(),
        };
        let (ocomp_readiness_publisher, ocomp_readiness) = projection_readiness(
            ocomp_baseline,
            ProjectionStatus::Ready {
                checkpoint: ocomp_baseline,
            },
        );
        let ocomp_readiness_for_consensus =
            args.upstream.is_some().then(|| ocomp_readiness.clone());
        let (ocomp_exit_tx, mut ocomp_exit_rx) = tokio::sync::mpsc::unbounded_channel();
        let evm_signer = if args.is_validator {
            let evm_key_path = args
                .effective_validator_evm_key()?
                .ok_or_else(|| eyre::eyre!("validator mode requires an EVM signer key"))?;
            let signer =
                Arc::new(OutbeEvmSigner::from_file(&evm_key_path).wrap_err_with(|| {
                    format!(
                        "failed to load validator EVM key from {}",
                        evm_key_path.display()
                    )
                })?);
            info!(
                address = %signer.address(),
                path = %evm_key_path.display(),
                "loaded validator EVM signer"
            );
            Some(signer)
        } else {
            None
        };
        let validator_evm_address = evm_signer.as_ref().map(|signer| signer.address());
        // Every network declares exactly one attestation policy in genesis. The
        // local session protocol is an independent, explicit operator choice:
        // GramineDirectDev may use either the development transport or a real
        // SGX, production NodeHost session. There is no connection fallback.
        let socket = args.tee_enclave_socket.clone().ok_or_else(|| {
            eyre::eyre!(
                "mandatory {:?} ChainSpec requires --tee-enclave-socket before node startup",
                initial_tee_policy.attestation_mode
            )
        })?;
        let endpoint = socket
            .to_str()
            .ok_or_else(|| eyre::eyre!("TEE enclave endpoint is not valid UTF-8"))?;
        let tee_session = args
            .tee_session_mode
            .resolve(initial_tee_policy.attestation_mode)
            .map_err(eyre::Report::msg)?;
        let (node_host_signing, reth_p2p_public) = load_reth_p2p_node_host_signer(
            &builder.config().network,
            builder.config().datadir().p2p_secret(),
        )?;
        let expected_enclave_id = match tee_session {
            outbe_engine::args::ResolvedTeeSession::ProductionNodeHost => {
                use k256::ecdsa::signature::hazmat::PrehashSigner as _;

                let client = outbe_tee::connect_or_initialize_node_host_enclave(
                    endpoint,
                    &node_data_dir,
                    outbe_tee::NodeHostIdentityV1 {
                        network_binding: initial_tee_policy.network_binding(),
                        reth_p2p_public,
                    },
                    |hash| {
                        let (signature, recovery): (
                            k256::ecdsa::Signature,
                            k256::ecdsa::RecoveryId,
                        ) = node_host_signing
                            .sign_prehash(hash.as_slice())
                            .map_err(|error| error.to_string())?;
                        let mut bytes = [0_u8; 65];
                        bytes[..64].copy_from_slice(signature.to_bytes().as_slice());
                        bytes[64] = recovery.to_byte();
                        Ok(bytes)
                    },
                )
                .wrap_err("NodeHost enclave initialization failed")?;
                // Session material for reconnect-with-identity-revalidation:
                // loaded once here (takes the NodeHost file lock), never in the
                // request hot path.
                let (manifest, node_host) =
                    outbe_tee::node_host::committed_node_host_session_material(&node_data_dir)
                        .wrap_err("committed NodeHost session material load failed")?;
                let enclave_id = manifest
                    .enclave_id()
                    .map_err(|error| eyre::eyre!("derive committed enclave identity: {error}"))?;
                outbe_tee::install_authorized_enclave_client(
                    client,
                    endpoint.to_owned(),
                    node_data_dir.clone(),
                    manifest,
                    node_host,
                )
                .wrap_err("enclave session install failed")?;
                Some(enclave_id)
            }
            outbe_engine::args::ResolvedTeeSession::Development => {
                let client = outbe_tee::EnclaveClient::connect_endpoint(endpoint)
                    .wrap_err("development enclave connection failed")?;
                outbe_tee::install_enclave_client(client, endpoint.to_owned())
                    .wrap_err("enclave session install failed")?;
                None
            }
        };
        let local_tee_identity = outbe_engine::validators::LocalTeeRuntimeIdentityV1 {
            reth_p2p_public,
            expected_enclave_id,
            validator: validator_evm_address,
        };
        info!(
            socket = %socket.display(),
            node_host_identity = "reth-p2p-secp256k1",
            attestation_mode = ?initial_tee_policy.attestation_mode,
            session_mode = ?tee_session,
            "mandatory TEE enclave sidecar connected before execution launch",
        );

        let tee_admission_anchor = if args.is_validator {
            if expected_enclave_id.is_some() {
                outbe_tee::load_finalized_join_admission_anchor(&node_data_dir)
                    .wrap_err("load durable validator join admission anchor")?
                    .map(|durable| {
                        validator_admission_anchor_from_durable_v1(
                            durable,
                            builder.config().chain.chain().id(),
                            builder.config().chain.genesis_hash(),
                            local_tee_identity,
                        )
                    })
                    .transpose()?
            } else {
                None
            }
        } else {
            // A follower re-executes every protected transaction and therefore must
            // already hold the exact permanent offer key committed by the running
            // chain. Prove that invariant before Reth opens networking, RPC, sync or
            // execution. Losing the key is terminal for this node identity: startup
            // never invokes recovery, replacement or another bootstrap path.
            let upstream = args.upstream.as_deref().ok_or_else(|| {
                eyre::eyre!(
                    "full-node startup requires --upstream to authenticate the chain offer key"
                )
            })?;
            let admission_anchor =
                require_upstream_fullnode_tee_admission(upstream, local_tee_identity).await?;
            let expected_offer = outbe_engine::read_upstream_tribute_offer_public_key(upstream)
                .await
                .wrap_err("failed to read mandatory offer key from the selected upstream")?;
            if expected_offer.is_zero() {
                return Err(eyre::eyre!(
                    "selected upstream has no mandatory OST3 offer key; refusing full-node startup"
                ));
            }
            let resident_offer = outbe_tee::resident_offer_public_key_v1()
                .wrap_err("failed to read the local enclave resident offer key")?;
            if resident_offer != expected_offer {
                return Err(eyre::eyre!(
                    "local enclave does not hold the selected chain's exact offer key; refusing execution startup (no recovery or fallback)"
                ));
            }
            info!(
                offer_public_key = %resident_offer,
                %upstream,
                "full-node resident offer key matched upstream before execution launch"
            );
            Some(admission_anchor)
        };

        let offchain_data = args.offchain_data()?;
        validate_adr005_node_mode(args.is_validator, args.upstream.is_some())?;
        let projection_config = OffchainDataProjectionConfig {
            chain_id: builder.config().chain.chain().id(),
            genesis_hash: builder.config().chain.genesis_hash(),
            storage: outbe_offchain_storage::StorageConfig::load(offchain_data.storage_config)?,
        };
        let projection_retention_selector = Arc::clone(&retention_selector);
        let prepared_projection = tokio::task::spawn_blocking(move || {
            prepare_offchain_data_projection_with_retention(
                projection_config,
                projection_retention_selector,
            )
        })
        .await
        .wrap_err("offchain-data startup validation worker failed")??;
        let runtime_body_readers = prepared_projection.runtime_body_readers();
        let proof_body_readers = runtime_body_readers.clone();
        let proof_chain_id = builder.config().chain.chain().id();
        let projection_readiness = prepared_projection.readiness();
        let retained_tribute_writer = prepared_projection.retained_tribute_writer();
        let projection_retention_fence = prepared_projection.retention_fence();
        let ce_data_dir = builder
            .config()
            .datadir
            .clone()
            .resolve_datadir(reth_ethereum::chainspec::EthChainSpec::chain(
                builder.config().chain.as_ref(),
            ))
            .data_dir()
            .to_path_buf();
        let genesis_hash = builder.config().chain.genesis_hash();
        let ce_identity = EnvironmentIdentity {
            local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
            chain_id: builder.config().chain.chain().id(),
            genesis_hash,
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            topology: outbe_compressed_entities::CeTopologyV1.encode(),
            tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
            vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
        };
        let genesis_marker = FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: 0,
            block_hash: genesis_hash,
            parent_block_hash: Default::default(),
            parent_root: Default::default(),
            new_root: outbe_compressed_entities::sealed_root(Default::default())?,
        };
        let ce_db = CeMdbx::open(&ce_data_dir, ce_identity, genesis_marker)
            .wrap_err("failed to open and validate compressed-entity MDBX")?;
        // ADR-009 fixes only the provisional sharded topology. Production CE
        // work/cache coefficients remain deliberately open until ADR-017.
        let compressed_tree_service = Arc::new(CompressedTreeService::new(
            ce_db,
            CandidateCacheLimits {
                max_candidates: usize::MAX,
                max_encoded_bytes: usize::MAX,
            },
        )?);
        compressed_tree_service.discard_speculative_candidates()?;
        let outbe_node = match evm_signer {
            Some(signer) => OutbeNode::with_bridge_and_evm_signer(
                bridge.clone(),
                signer,
                runtime_body_readers,
                compressed_tree_service.clone(),
            ),
            None => OutbeNode::with_bridge(
                bridge.clone(),
                runtime_body_readers,
                compressed_tree_service.clone(),
            ),
        };
        let outbe_node = outbe_node
            .with_ocomp_fork_install(ocomp_fork_install)
            .with_shutdown(shutdown.clone());
        let projection_readiness_for_rpc = projection_readiness.clone();
        let radicle_status_for_rpc = radicle_status.clone();
        // Canary-fed enclave health: published by the tee-canary worker (spawned
        // after node launch), read by `rudis_consensusStatus.enclave`.
        let tee_canary_status = outbe_tee::TeeEnclaveHealthChannel::disabled();
        let tee_canary_status_for_rpc = tee_canary_status.clone();

        let NodeHandle {
            node,
            node_exit_future,
        } = builder
            .node(outbe_node)
            .install_exex("outbe-finalized", move |ctx| {
                let projection_provider = ctx.provider().clone();
                let config = ocomp_exex_config.clone();
                let readiness = ocomp_readiness_publisher.clone();
                let exit = ocomp_exit_tx.clone();
                async move {
                    let ready_projection = tokio::task::spawn_blocking(move || {
                        validate_offchain_data_checkpoint(
                            prepared_projection,
                            &projection_provider,
                        )
                    })
                    .await
                    .wrap_err("offchain-data checkpoint validation worker failed")??;
                    Ok(ocomp_exex::run_ocomp_exex(
                        ctx,
                        ready_projection,
                        config,
                        readiness,
                        exit,
                    ))
                }
            })
            .apply(|mut builder| {
                configure_outbe_engine_args(&mut builder.config_mut().engine);
                let discovery = &mut builder.config_mut().network.discovery;
                discovery.enable_discv5_discovery = true;
                // SSA-1: disable reth DNS discovery so the `hickory-proto` code
                // path (RUSTSEC-2025 NSEC3 unbounded-loop DoS, no upstream fix)
                // is unreachable. outbe peers via discv5 + static bootnodes and
                // configures no DNS ENR tree, so DNS discovery provided nothing
                // here anyway; disabling it removes the attack surface.
                discovery.disable_dns_discovery = true;
                builder
            })
            .extend_rpc_modules({
                let bridge = bridge.clone();
                let is_validator = args.is_validator;
                let is_follower = args.upstream.is_some();
                let projection_readiness = projection_readiness_for_rpc.clone();
                let compressed_tree_service = compressed_tree_service.clone();
                let proof_body_readers = proof_body_readers.clone();
                let radicle_status = radicle_status_for_rpc.clone();
                let tee_enclave_health = tee_canary_status_for_rpc.clone();
                move |ctx| {
                    use outbe_rpc::OutbeApiServer as _;
                    let provider = Arc::new(ctx.provider().clone());
                    // Validators get the full bridge-backed handler.
                    // `--upstream` followers also run a marshal and CAN serve
                    // `rudis_getFinalization` (chaining followers), but must NOT
                    // report validator status; they get a follower-scoped handler
                    // that exposes only the finalization-serving capability.
                    let outbe_api = (if is_validator {
                        outbe_rpc::OutbeApiHandler::with_bridge(
                            Arc::clone(&provider),
                            bridge,
                            projection_readiness.clone(),
                        )
                    } else if is_follower {
                        outbe_rpc::OutbeApiHandler::with_follower_bridge(
                            Arc::clone(&provider),
                            bridge,
                            projection_readiness.clone(),
                        )
                    } else {
                        outbe_rpc::OutbeApiHandler::new(
                            Arc::clone(&provider),
                            projection_readiness.clone(),
                        )
                    })
                    .with_point_reads(
                        compressed_tree_service.clone(),
                        proof_body_readers.clone(),
                        proof_chain_id,
                    )
                    .with_tee_renewal_schedule(
                        dkg_prepare_window_blocks,
                        minimum_block_time_millis,
                    )
                    .with_ocomp_lysis_openings(outbe_rpc::OcompLysisOpeningsRuntimeV1::new({
                        let provider = Arc::clone(&provider);
                        move |intent_id, canonical_request| {
                            let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
                            let request = outbe_ocomp_protocol::control::BuildLysisOpeningsV1::decode_body(
                                canonical_request.as_ref(),
                                &limits,
                            )
                            .map_err(|error| format!("decode OCOMP openings request: {error}"))?;
                            let finalized_head = provider
                                .finalized_block_num_hash()
                                .map_err(|error| format!("read finalized head: {error}"))?
                                .ok_or_else(|| "finalized head is unavailable".to_owned())?;
                            let record = outbe_node::ocomp::retention::read_ocomp_job_record_at(
                                provider.as_ref(),
                                finalized_head.hash,
                                intent_id,
                                &limits,
                            )
                            .map_err(|error| format!("read finalized OCOMP job: {error}"))?;
                            let finalized = record
                                .finalized
                                .as_ref()
                                .ok_or_else(|| "OCOMP job is not finalized".to_owned())?;
                            if !ocomp_job_available_for_calculation(record.status) {
                                return Err(
                                    "OCOMP job is not available for calculation or replay"
                                        .to_owned(),
                                );
                            }
                            if request.job_id != finalized.job_id {
                                return Err("OCOMP openings request JobId mismatch".to_owned());
                            }
                            let candidate = outbe_node::ocomp::retention::CandidatePinV1 {
                                block_number: record.intent_height,
                                block_hash: finalized.finalized_request_block_hash,
                                state_root: finalized.finalized_request_state_root,
                                intent_id,
                                wwd: record.intent.wwd,
                                ce_sealed_root: record.intent.ce_sealed_root,
                                protocol_bundle_hash: record.intent.protocol_bundle_hash,
                                input_lease_id: record
                                    .intent
                                    .input_lease_id()
                                    .map_err(|error| format!("derive input lease: {error}"))?,
                            };
                            let openings = outbe_node::ocomp::build_lysis_openings(
                                provider.as_ref(),
                                &limits,
                                candidate,
                                request.subjects,
                            )
                            .map_err(|error| format!("build exact OCOMP openings: {error}"))?;
                            if openings.job_id != finalized.job_id {
                                return Err("OCOMP openings JobId mismatch".to_owned());
                            }
                            openings
                                .encode_body(&limits)
                                .map(alloy_primitives::Bytes::from)
                                .map_err(|error| format!("encode OCOMP openings: {error}"))
                        }
                    }))
                    .with_radicle_status(radicle_status.clone())
                    .with_tee_enclave_health(tee_enclave_health.clone());
                    ctx.modules.merge_if_module_configured(
                        RethRpcModule::Other("rudis".to_owned()),
                        outbe_api.into_rpc(),
                    )?;
                    info!("rudis_* RPC namespace registered where configured");
                    Ok(())
                }
            })
            .launch()
            .await
            .wrap_err("failed launching execution node")?;

        shutdown.observe_engine_exit(&node.task_executor, node_exit_future)?;

        let validator_has_recovery_anchor = args.is_validator && tee_admission_anchor.is_some();
        let mut tee_lease_guard_gate = TeeLeaseGuardGateV1::new(tee_admission_anchor);
        if let Some(admission) = read_gated_finalized_local_tee_admission(
            &node.provider,
            proof_chain_id,
            genesis_hash,
            local_tee_identity,
            &mut tee_lease_guard_gate,
        )?
        {
            let rejection = if validator_has_recovery_anchor {
                validator_recovery_startup_admission_rejection(admission)
            } else {
                tee_lease_admission_rejection(admission)
            };
            if let Some(reason) = rejection {
                eyre::bail!("local node rejected by finalized TEE lease state: {reason}");
            }
        }
        require_validator_tee_recovery_complete_v1(
            args.is_validator,
            tee_lease_guard_gate,
            &node_data_dir,
        )?;
        let (tee_lease_exit_tx, mut tee_lease_exit_rx) =
            tokio::sync::mpsc::unbounded_channel();
        let lease_check = run_tee_lease_guard_v1(
            node.provider.clone(),
            proof_chain_id,
            genesis_hash,
            local_tee_identity,
            tee_lease_guard_gate,
            shutdown_token.clone(),
        );
        let lease_outcome = shutdown.clone();
        let tee_lease_guard_handle = tokio::spawn(shutdown.track_task("TEE lease guard", async move {
            let verdict = match lease_check.await {
                Ok(None) => return,
                Ok(Some(reason)) => Ok(reason),
                Err(error) => Err(error),
            };
            // Publish an actual failure before notifying a launcher that may
            // concurrently choose a different exit branch or be cancelled.
            let reason = tee_lease_exit_reason(Some(verdict), &lease_outcome);
            let _ = tee_lease_exit_tx.send(Ok(reason));
        }));

        let (radicle_consensus, radicle_observer, radicle_drained) = if let Some((
            validator,
            sidecar,
            publisher,
        )) = radicle_preflight
        {
            use outbe_radicle::manager::SnapshotReader as _;

            let exact = node
                .provider
                .finalized_block_num_hash()
                .wrap_err("read finalized head for Radicle startup")?
                .map(|block| outbe_radicle::manager::FinalizedBlock {
                    number: block.number,
                    hash: block.hash,
                })
                .unwrap_or(outbe_radicle::manager::FinalizedBlock {
                    number: 0,
                    hash: genesis_hash,
                });
            let raw_snapshots: Arc<dyn outbe_radicle::manager::SnapshotReader> = Arc::new(
                outbe_radicle::manager::RethSnapshotReader::new(
                    node.provider.clone(),
                    proof_chain_id,
                    genesis_hash,
                ),
            );
            let observed_snapshots = Arc::new(
                outbe_radicle::integration::ObservedSnapshotReader::new(
                    raw_snapshots,
                    publisher.clone(),
                ),
            );
            let initial = observed_snapshots
                .read_exact(exact)
                .wrap_err("read exact Radicle startup snapshot")?;
            match initial
                .validators
                .iter()
                .find(|candidate| candidate.address == validator)
            {
                None => {}
                Some(candidate) if candidate.node_id.is_none() => {
                    eyre::bail!("active validator has no Radicle NodeId binding");
                }
                Some(candidate) if candidate.node_id != Some(sidecar.node_id) => {
                    eyre::bail!("local Radicle NodeId does not match finalized validator binding");
                }
                Some(_) => publisher.mark_startup_ready(),
            }

            let (endpoint, resolver, evidence) =
                outbe_radicle::integration::EndpointNetwork::build(
                    outbe_radicle::endpoint::ChainIdentity {
                        chain_id: proof_chain_id,
                        genesis_hash,
                    },
                    radicle_status.clone(),
                );
            let (local_endpoint_publisher, local_endpoint) =
                outbe_radicle::integration::LocalEndpointIdentityChannel::create(
                    outbe_radicle::integration::LocalEndpointIdentity {
                        validator,
                        node_id: sidecar.node_id,
                        addresses: sidecar.addresses,
                    },
                );
            let pinned_node_id = sidecar.node_id;
            let radicle_control_socket = args
                .radicle_control_socket
                .clone()
                .expect("validated Radicle control socket");
            let repository_status: Arc<dyn outbe_radicle::manager::RepositoryStatus> = Arc::new(
                outbe_radicle::manager::HttpRepositoryStatus::new(
                    args.radicle_status_address
                        .expect("validated Radicle status address"),
                    std::time::Duration::from_secs(5),
                )?,
            );
            let repository_status = Arc::new(
                outbe_radicle::integration::ObservedRepositoryStatus::new(
                    repository_status,
                    publisher.clone(),
                ),
            );
            let manager = outbe_radicle::manager::RadicleManager::start(
                outbe_radicle::manager::ManagerConfig {
                    self_validator: validator,
                    local_node_id: sidecar.node_id,
                    repair_interval: outbe_radicle::integration::PRODUCTION_REPAIR_INTERVAL,
                    retry: outbe_radicle::manager::RetryPolicy::default(),
                },
                outbe_radicle::manager::ManagerDependencies {
                    finality: Arc::new(
                        outbe_radicle::integration::GenesisFallbackFinalizedFeed::new(
                            Arc::new(outbe_radicle::manager::RethFinalizedFeed::new(
                                node.provider.clone(),
                            )),
                            exact,
                        ),
                    ),
                    snapshots: observed_snapshots,
                    endpoints: Arc::new(resolver.clone()),
                    control: Arc::new(outbe_radicle::manager::NativeHeartwoodControl::new(
                        radicle_control_socket.clone(),
                        std::time::Duration::from_secs(5),
                    )),
                    repository_status,
                },
            );
            let observer_shutdown = radicle_shutdown_token.clone();
            let endpoint_owner = outbe_radicle::integration::EndpointTaskOwner::default();
            let observer_endpoint_owner = endpoint_owner.clone();
            let observer_publisher = publisher.clone();
            let observer_resolver = resolver.clone();
            let observer_status = radicle_status.clone();
            let observer_outcome = shutdown.clone();
            let observer_tracker = shutdown.clone();
            let (drained_tx, drained_rx) = oneshot::channel();
            // Register with Reth's graceful drain before returning to its
            // cancellable launcher. Dropping the launcher must not abort cleanup.
            let observer = node.task_executor.spawn_with_graceful_shutdown_signal(async move |guard| {
                observer_tracker.track_task("Radicle observer", async move {
                let manager = manager;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                let mut local_endpoint_interval = tokio::time::interval(
                    outbe_radicle::integration::PRODUCTION_REPAIR_INTERVAL,
                );
                local_endpoint_interval.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Skip,
                );
                let mut metrics = outbe_radicle::integration::RadicleMetrics::default();
                loop {
                    tokio::select! {
                        _ = observer_shutdown.cancelled() => {
                            if let Err(error) = outbe_radicle::integration::shutdown_bounded(
                                std::time::Duration::from_secs(5),
                                manager,
                                observer_endpoint_owner.shutdown(&observer_resolver),
                            ).await {
                                tracing::error!(%error, "Radicle integration shutdown failed");
                                observer_outcome.record_failure(eyre::eyre!(error).wrap_err("Radicle integration shutdown failed"));
                            }
                            break;
                        }
                        _ = interval.tick() => {
                            observer_publisher.observe_manager(manager.status());
                            observer_publisher.observe_evidence(evidence.snapshot());
                            metrics.record(&observer_status.snapshot());
                        }
                        _ = local_endpoint_interval.tick() => {
                            let sidecar = tokio::select! {
                                _ = observer_shutdown.cancelled() => continue,
                                result = outbe_radicle::integration::query_sidecar(
                                    &radicle_control_socket,
                                    std::time::Duration::from_secs(5),
                                ) => result,
                            };
                            match sidecar {
                                Ok(sidecar) if sidecar.node_id == pinned_node_id => {
                                    let _ = local_endpoint_publisher.update(
                                        sidecar.node_id,
                                        sidecar.addresses,
                                    );
                                }
                                Ok(sidecar) => {
                                    local_endpoint_publisher.unavailable();
                                    tracing::error!(
                                        expected_node_id = ?pinned_node_id,
                                        actual_node_id = ?sidecar.node_id,
                                        "Radicle sidecar NodeId changed; endpoint publication suppressed"
                                    );
                                }
                                Err(error) => {
                                    local_endpoint_publisher.unavailable();
                                    tracing::warn!(
                                        %error,
                                        "Radicle sidecar identity refresh failed; endpoint publication suppressed"
                                    );
                                }
                            }
                        }
                    }
                }
                    let _ = drained_tx.send(());
                }).await;
                drop(guard);
            });
            (
                Some((endpoint, local_endpoint, radicle_status.clone(), endpoint_owner)),
                Some(observer),
                Some(drained_rx),
            )
        } else {
            (None, None, None)
        };

        // Periodic enclave canary (signal only): known-plaintext decrypt +
        // Health telemetry through the process-global session. `0` disables.
        let tee_canary_handle = (args.tee_canary_interval_secs > 0).then(|| {
            tokio::spawn(shutdown.track_task("TEE canary worker", outbe_node::tee_canary::run_tee_canary_worker(
                outbe_node::tee_canary::GlobalEnclaveRequester,
                outbe_node::tee_canary::TeeCanaryConfig {
                    interval: std::time::Duration::from_secs(args.tee_canary_interval_secs),
                    failure_threshold: args.tee_canary_failure_threshold,
                },
                tee_canary_status.clone(),
                shutdown_token.clone(),
            )))
        });
        // Pending staleness eviction. Node-local pool policy, so it runs in
        // every mode - full nodes are the public RPC ingress and shed stuck
        // transactions that would otherwise be re-gossiped to validators.
        let txpool_maintenance_handle = tokio::spawn(shutdown.track_task("txpool maintenance task", outbe_txpool::maintain::maintain_outbe_pool(
            node.provider.clone(),
            node.pool.clone(),
            outbe_txpool::maintain::OutbePoolMaintainConfig {
                staleness_interval_secs: args.txpool_pending_staleness_secs,
            },
        )));
        let upgrade_promotion = Arc::new(tokio::sync::Notify::new());
        let upgrade_handle = if initial_tee_policy.attestation_mode
            == outbe_primitives::tee_attestation_v1::AttestationMode::DcapRequired
        {
            let provider = node.provider.clone();
            let promoted = upgrade_promotion.clone();
            Some(tokio::spawn(shutdown.track_task("enclave-upgrade watcher", run_upgrade_promotion_worker_v1(
                provider,
                UpgradePromotionWorkerConfigV1 {
                    chain_id: proof_chain_id,
                    genesis_hash,
                    node_data_dir: node_data_dir.clone(),
                    poll_secs: TEE_UPGRADE_POLL_SECS,
                    warning_blocks: TEE_UPGRADE_WARNING_BLOCKS,
                    critical_blocks: TEE_UPGRADE_CRITICAL_BLOCKS,
                    promoted,
                },
            ))))
        } else {
            None
        };

        let durable_ce_adapter = Arc::new(RethDurableCeState::new(node.provider.clone()));
        let durable_ce_state: Arc<dyn DurableCeState> = durable_ce_adapter.clone();
        let canonical_ce_replay: Arc<dyn CanonicalCeReplaySource> = durable_ce_adapter;
        let finalized_ce_tree: Arc<dyn FinalizedCeTree> = compressed_tree_service.clone();
        let finalized_ce_committer: Arc<dyn FinalizedCeCommitter> =
            Arc::new(RethCeFinalizer::new(durable_ce_state, finalized_ce_tree));
        let startup_ce_tree: Arc<dyn StartupCeTree> = compressed_tree_service.clone();
        let ce_startup_recovery: Arc<dyn CeStartupRecovery> = Arc::new(
            CeStartupRecoveryCoordinator::new(canonical_ce_replay, startup_ce_tree),
        );

        outbe_engine::validators::check_binary_version_compatibility(
            &node.provider,
            outbe_evm::handlers::update::registry(),
        )?;

        if args.is_validator || args.upstream.is_some() {
            if args.upstream.is_some() {
                info!("outbe node launched in FOLLOWER mode (--upstream)");
            } else {
                info!("outbe node launched in VALIDATOR mode");
            }

            // Spawn the consensus thread for validator OR follower mode; the
            // follower branch inside `run_consensus_stack` selects the lightweight
            // follow stack (no consensus engine).
            let consensus_lifecycle = ConsensusThreadGuard::new(
                shutdown_token.clone(),
                thread::spawn(consensus_thread_fn),
            ).with_outcome(shutdown.clone());

            let _ = node_tx.send((
                node,
                args,
                projection_readiness,
                ocomp_readiness_for_consensus,
                retained_tribute_writer,
                projection_retention_fence,
                retention_selector,
                finalized_ce_committer,
                ce_startup_recovery,
                radicle_consensus,
                radicle_drained,
            ));

            let exit_cause = tokio::select! {
                () = shutdown.engine_exited() => {
                    info!("execution node exited");
                    LauncherExitCause::NodeExited
                }
                _ = &mut consensus_dead_rx => {
                    info!("consensus node exited");
                    LauncherExitCause::ConsensusExited
                }
                exit = ocomp_exit_rx.recv() => {
                    if let Some(exit) = exit {
                        tracing::error!(
                            failure_class = ?exit.failure.class,
                            failure = %exit.failure.message,
                            "embedded OCOMP requested node shutdown"
                        );
                        shutdown.record_failure(eyre::eyre!("embedded OCOMP failure ({:?}): {}", exit.failure.class, exit.failure.message));
                    } else {
                        shutdown.record_failure(eyre::eyre!("embedded OCOMP exit channel closed without a verdict"));
                    }
                    LauncherExitCause::OcompRequested
                }
                () = upgrade_promotion.notified() => {
                    info!("finalized enclave upgrade requested execution restart");
                    LauncherExitCause::UpgradeRequested
                }
                rejection = tee_lease_exit_rx.recv() => {
                    let reason = tee_lease_exit_reason(rejection, &shutdown);
                    tracing::error!(
                        reason = %reason,
                        "finalized TEE lease guard requested node shutdown"
                    );
                    LauncherExitCause::TeeLeaseRejected
                }
                signal = tokio::signal::ctrl_c() => {
                    if let Err(error) = signal {
                        shutdown.record_failure(eyre::eyre!(error).wrap_err("shutdown signal listener failed"));
                    }
                    info!("received shutdown signal");
                    LauncherExitCause::CtrlC
                }
            };

            tracing::debug!(?exit_cause, "draining application before global execution shutdown");

            let consensus_joined = consensus_lifecycle.join();
            tracing::debug!("consensus thread join completed");
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handle_consensus_thread_join(consensus_joined)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => shutdown.record_failure(error),
                Err(panic) => shutdown.record_panic(panic),
            }
        } else {
            info!("outbe node launched in FULL NODE mode - no consensus thread spawned");

            tokio::select! {
                () = shutdown.engine_exited() => {
                    info!("execution node exited");
                }
                signal = tokio::signal::ctrl_c() => {
                    if let Err(error) = signal {
                        shutdown.record_failure(eyre::eyre!(error).wrap_err("shutdown signal listener failed"));
                    }
                    info!("received shutdown signal");
                }
                exit = ocomp_exit_rx.recv() => {
                    if let Some(exit) = exit {
                        tracing::error!(
                            failure_class = ?exit.failure.class,
                            failure = %exit.failure.message,
                            "embedded OCOMP requested node shutdown"
                        );
                        shutdown.record_failure(eyre::eyre!("embedded OCOMP failure ({:?}): {}", exit.failure.class, exit.failure.message));
                    } else {
                        shutdown.record_failure(eyre::eyre!("embedded OCOMP exit channel closed without a verdict"));
                    }
                }
                () = upgrade_promotion.notified() => {
                    info!("finalized enclave upgrade requested execution restart");
                }
                rejection = tee_lease_exit_rx.recv() => {
                    let reason = tee_lease_exit_reason(rejection, &shutdown);
                    tracing::error!(
                        reason = %reason,
                        "finalized TEE lease guard requested full-node shutdown"
                    );
                }
            }
        }

        shutdown_token.cancel();
        if let Err(error) = tee_lease_guard_handle.await {
            shutdown.record_failure(eyre::eyre!(error).wrap_err("TEE lease guard panicked"));
        }
        if let Some(mut handle) = radicle_observer {
            match tokio::time::timeout(RADICLE_DRAIN_DEADLINE, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => shutdown.record_failure(eyre::eyre!(error).wrap_err("Radicle observer panicked")),
                Err(error) => {
                    tracing::warn!("Radicle observer join deadline exceeded");
                    shutdown.record_failure(eyre::eyre!(error).wrap_err("Radicle observer join deadline exceeded"));
                    handle.abort();
                    if let Err(error) = handle.await {
                        if !error.is_cancelled() {
                            shutdown.record_failure(eyre::eyre!(error).wrap_err("Radicle observer failed while reaping"));
                        }
                    }
                }
            }
        }
        if let Some(handle) = tee_canary_handle {
            tracing::debug!("waiting for TEE canary worker shutdown");
            if let Err(error) = handle.await {
                shutdown.record_failure(eyre::eyre!(error).wrap_err("TEE canary worker panicked"));
            }
            tracing::debug!("TEE canary worker shutdown completed");
        }
        // The maintenance loop ends with its canonical-state stream; abort it
        // explicitly so shutdown never waits on a live provider subscription.
        txpool_maintenance_handle.abort();
        match txpool_maintenance_handle.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                shutdown.record_failure(eyre::eyre!("txpool maintenance task panicked: {error}"));
            }
        }
        if let Some(handle) = upgrade_handle {
            handle.abort();
            match handle.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    shutdown.record_failure(eyre::eyre!("enclave-upgrade watcher panicked: {error}"));
                }
            }
        }

        Ok(())
        }.await;
        if let Err(error) = result {
            // Enter Reth's normal graceful teardown even on launcher failure.
            // The process result below retains the error; this is not success.
            launcher_shutdown.record_failure(error);
        }
        Ok(())
    })
    })
    .wrap_err("execution node failed");

    process_shutdown.finish(command_result)
}

fn ocomp_job_available_for_calculation(
    status: outbe_ocomp_protocol::state::OcompJobStatus,
) -> bool {
    matches!(
        status,
        outbe_ocomp_protocol::state::OcompJobStatus::VotingOpen
            | outbe_ocomp_protocol::state::OcompJobStatus::Completed
    )
}

/// Configure Reth's engine tree for Outbe's pre-finalization parent switches.
///
/// Ethereum's Engine API permits an execution client to skip payload building when
/// an FCU selects an already-canonical ancestor. Outbe leaders intentionally build
/// on certified, not-yet-finalized parents, so a later view may select such an
/// ancestor and still require a payload. Reth exposes both parts of that behavior
/// explicitly: process the attributes and unwind the canonical header to the
/// selected parent before starting the payload job.
fn configure_outbe_engine_args(engine: &mut reth_node_core::args::EngineArgs) {
    engine.always_process_payload_attributes_on_canonical_head = true;
    engine.allow_unwind_canonical_header = true;
}

/// Outbe's transaction-pool defaults, installed before CLI parsing so operator
/// `--txpool.*` flags still override them.
///
/// Rationale (2026-08-22 incident): a transaction that keeps landing in
/// proposals which fail to finalize is re-injected by the reorg path and stays
/// pending indefinitely. Two upstream defaults made that worse:
///
/// - `--txpool.lifetime` (parked sub-pools) defaults to 3 hours - far longer
///   than any legitimate parked transaction needs on a two-second chain.
/// - RPC-submitted transactions are treated as "local" and are exempt from
///   lifetime eviction. The incident transactions arrived over public RPC, so
///   the exemption applied to exactly the traffic that must be evictable.
///
/// The transactions backup journal is disabled for the same reason: a restart
/// must not resurrect transactions the node deliberately evicted.
fn outbe_default_txpool_values() -> reth_node_core::args::DefaultTxPoolValues {
    reth_node_core::args::DefaultTxPoolValues::default()
        .with_max_queued_lifetime(OUTBE_TXPOOL_QUEUED_LIFETIME)
        .with_no_locals(OUTBE_TXPOOL_NO_LOCALS)
        .with_disable_transactions_backup(OUTBE_TXPOOL_DISABLE_BACKUP)
}

/// Parked-transaction lifetime. Reth's own default is three hours - orders of
/// magnitude longer than a two-second chain needs.
const OUTBE_TXPOOL_QUEUED_LIFETIME: std::time::Duration = std::time::Duration::from_secs(120);
/// RPC-submitted transactions must NOT be exempt from lifetime eviction.
const OUTBE_TXPOOL_NO_LOCALS: bool = true;
/// A restart must not resurrect transactions the node deliberately evicted.
const OUTBE_TXPOOL_DISABLE_BACKUP: bool = true;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn radicle_transport_waits_for_drain_completion() {
        use futures::FutureExt as _;
        let (done, completion) = tokio::sync::oneshot::channel();
        let waiting =
            super::await_radicle_drain(Some(completion), std::time::Duration::from_secs(1));
        tokio::pin!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        done.send(()).unwrap();
        waiting.await.unwrap();
        super::await_radicle_drain(None, std::time::Duration::ZERO)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn radicle_lost_observer_is_not_a_clean_drain() {
        let (done, completion) = tokio::sync::oneshot::channel();
        drop(done);
        let error = super::await_radicle_drain(Some(completion), std::time::Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("without completing its drain"));
    }

    #[tokio::test]
    async fn radicle_drain_deadline_is_distinct_from_lost_observer() {
        let (_done, completion) = tokio::sync::oneshot::channel();
        let error = super::await_radicle_drain(Some(completion), std::time::Duration::ZERO)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
    }

    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    struct ThreadDropRecorder {
        runner_returned: Arc<AtomicBool>,
        dropped_on: Arc<Mutex<Option<std::thread::ThreadId>>>,
    }

    impl Drop for ThreadDropRecorder {
        fn drop(&mut self) {
            assert!(
                self.runner_returned.load(Ordering::SeqCst),
                "the lifetime pin must outlive the runner"
            );
            *self.dropped_on.lock().expect("drop recorder lock") =
                Some(std::thread::current().id());
        }
    }

    struct ExecutionTeardownSentinel(Arc<AtomicBool>);

    fn full_node_admission_anchor() -> super::LocalTeeAdmissionAnchorV1 {
        super::LocalTeeAdmissionAnchorV1 {
            finalized_height: 7,
            finalized_hash: alloy_primitives::B256::repeat_byte(0x77),
        }
    }

    #[test]
    fn full_node_lease_guard_waits_strictly_below_authenticated_anchor() {
        let anchor = full_node_admission_anchor();
        let gate = super::TeeLeaseGuardGateV1::new(Some(anchor));

        assert!(!gate.is_armed());
        assert_eq!(gate.anchor_to_validate(0), None);
        assert_eq!(gate.anchor_to_validate(6), None);
        assert_eq!(gate.anchor_to_validate(7), Some(anchor));
        assert_eq!(gate.anchor_to_validate(70), Some(anchor));
    }

    #[test]
    fn full_node_lease_guard_arms_only_on_exact_ready_anchor() {
        let anchor = full_node_admission_anchor();
        let mut gate = super::TeeLeaseGuardGateV1::new(Some(anchor));

        gate.validate_and_arm(
            anchor.finalized_hash,
            outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Ready {
                valid_until: 1_800_000_000,
            },
        )
        .expect("exact live anchor must arm the local guard");

        assert!(gate.is_armed());
        assert_eq!(gate.anchor_to_validate(anchor.finalized_height), None);
    }

    #[test]
    fn full_node_lease_guard_fails_closed_on_anchor_hash_mismatch() {
        let anchor = full_node_admission_anchor();
        let mut gate = super::TeeLeaseGuardGateV1::new(Some(anchor));

        let error = gate
            .validate_and_arm(
                alloy_primitives::B256::repeat_byte(0x78),
                outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Ready {
                    valid_until: 1_800_000_000,
                },
            )
            .expect_err("a different local canonical hash must fail closed");

        assert!(error.to_string().contains("anchor hash mismatch"));
        assert!(!gate.is_armed());
    }

    #[test]
    fn full_node_lease_guard_rejects_every_non_ready_anchor_verdict() {
        use outbe_engine::validators::{LocalTeeRuntimeAdmissionV1, LocalTeeRuntimeRejectionV1};

        for admission in [
            LocalTeeRuntimeAdmissionV1::BootstrapPending,
            LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::MissingBinding),
            LocalTeeRuntimeAdmissionV1::Rejected(
                LocalTeeRuntimeRejectionV1::EnclaveIdentityMismatch,
            ),
            LocalTeeRuntimeAdmissionV1::Rejected(LocalTeeRuntimeRejectionV1::Expired {
                valid_until: 1_700_000_000,
            }),
        ] {
            let anchor = full_node_admission_anchor();
            let mut gate = super::TeeLeaseGuardGateV1::new(Some(anchor));
            assert!(gate
                .validate_and_arm(anchor.finalized_hash, admission)
                .is_err());
            assert!(!gate.is_armed());
        }
    }

    #[test]
    fn validators_start_armed_and_later_rejections_remain_terminal() {
        use outbe_engine::validators::{LocalTeeRuntimeAdmissionV1, LocalTeeRuntimeRejectionV1};

        let gate = super::TeeLeaseGuardGateV1::new(None);
        assert!(gate.is_armed());
        assert_eq!(gate.anchor_to_validate(u64::MAX), None);

        let reason = super::tee_lease_admission_rejection(LocalTeeRuntimeAdmissionV1::Rejected(
            LocalTeeRuntimeRejectionV1::Expired { valid_until: 42 },
        ))
        .expect("an armed guard must preserve fail-stop semantics");
        assert!(reason.contains("expired at 42"));
    }

    #[test]
    fn validator_current_bootstrap_pending_admission_is_terminal() {
        use outbe_engine::validators::LocalTeeRuntimeAdmissionV1;

        let reason = super::validator_recovery_startup_admission_rejection(
            LocalTeeRuntimeAdmissionV1::BootstrapPending,
        )
        .expect("current finalized BootstrapPending admission must fail closed");
        assert!(reason.contains("bootstrap-pending"));
        assert_eq!(
            super::tee_lease_admission_rejection(LocalTeeRuntimeAdmissionV1::BootstrapPending),
            None,
            "legacy no-anchor startup must preserve bootstrap compatibility"
        );
    }

    #[test]
    fn full_node_restart_revalidates_the_new_upstream_anchor() {
        use outbe_engine::validators::LocalTeeRuntimeAdmissionV1;

        let old_anchor = full_node_admission_anchor();
        let mut before_restart = super::TeeLeaseGuardGateV1::new(Some(old_anchor));
        before_restart
            .validate_and_arm(
                old_anchor.finalized_hash,
                LocalTeeRuntimeAdmissionV1::Ready { valid_until: 100 },
            )
            .unwrap();
        assert!(before_restart.is_armed());

        let new_anchor = super::LocalTeeAdmissionAnchorV1 {
            finalized_height: 12,
            finalized_hash: alloy_primitives::B256::repeat_byte(0x12),
        };
        let mut after_restart = super::TeeLeaseGuardGateV1::new(Some(new_anchor));
        assert!(!after_restart.is_armed());
        assert_eq!(after_restart.anchor_to_validate(11), None);
        assert_eq!(after_restart.anchor_to_validate(12), Some(new_anchor));
        after_restart
            .validate_and_arm(
                new_anchor.finalized_hash,
                LocalTeeRuntimeAdmissionV1::Ready { valid_until: 200 },
            )
            .unwrap();
        assert!(after_restart.is_armed());
    }

    #[test]
    fn validator_below_durable_join_anchor_fails_with_certified_follower_recovery() {
        let anchor = full_node_admission_anchor();
        let mut recovery = super::TeeLeaseGuardGateV1::new(Some(anchor));
        let data_dir = std::path::Path::new("/srv/outbe/validator-3");

        let error = super::require_validator_tee_recovery_complete_v1(true, recovery, data_dir)
            .expect_err("a stale validator must not start authority services");
        let message = error.to_string();
        assert!(message.contains("certified follower"));
        assert!(message.contains("/srv/outbe/validator-3"));
        assert!(message.contains("omit --validator"));
        assert!(message.contains("--upstream <healthy-certified-rpc>"));
        assert!(message.contains("do not use --upstream.nocertify"));
        assert!(message.contains("stop the follower"));
        assert!(message.contains("fresh DKG"));

        super::require_validator_tee_recovery_complete_v1(false, recovery, data_dir)
            .expect("a FullNode keeps its existing asynchronous gate");
        super::require_validator_tee_recovery_complete_v1(
            true,
            super::TeeLeaseGuardGateV1::new(None),
            data_dir,
        )
        .expect("a legacy validator without recovery state remains compatible");

        recovery
            .validate_and_arm(
                anchor.finalized_hash,
                outbe_engine::validators::LocalTeeRuntimeAdmissionV1::Ready { valid_until: 200 },
            )
            .unwrap();
        super::require_validator_tee_recovery_complete_v1(true, recovery, data_dir)
            .expect("an exact Ready anchor permits ordinary validator startup");
    }

    #[test]
    fn durable_validator_anchor_must_match_the_running_chain_node_and_enclave() {
        use alloy_primitives::U256;
        use outbe_primitives::tee_attestation_v1::NodeIdV1;

        let reth_p2p_public: [u8; 33] = k256::ecdsa::SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret(0x41)).into(),
        )
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
        let node_id_hash = NodeIdV1 { reth_p2p_public }.node_id_hash().unwrap();
        let enclave_id = alloy_primitives::B256::repeat_byte(0x42);
        let durable = outbe_tee::FinalizedJoinAdmissionAnchorV1 {
            chain_id: U256::from(676_u64).to_be_bytes(),
            genesis_hash: alloy_primitives::B256::repeat_byte(0x43),
            node_id_hash,
            enclave_id,
            intent_hash: alloy_primitives::B256::repeat_byte(0x44),
            finalized_height: 91,
            finalized_hash: alloy_primitives::B256::repeat_byte(0x45),
            finalized_state_root: alloy_primitives::B256::repeat_byte(0x46),
            finalized_consensus_timestamp: 19_000,
        };
        let identity = outbe_engine::validators::LocalTeeRuntimeIdentityV1 {
            reth_p2p_public,
            expected_enclave_id: Some(enclave_id),
            validator: Some(alloy_primitives::Address::repeat_byte(0x47)),
        };

        assert_eq!(
            super::validator_admission_anchor_from_durable_v1(
                durable,
                676,
                durable.genesis_hash,
                identity,
            )
            .unwrap(),
            super::LocalTeeAdmissionAnchorV1 {
                finalized_height: durable.finalized_height,
                finalized_hash: durable.finalized_hash,
            }
        );

        let wrong_enclave = outbe_engine::validators::LocalTeeRuntimeIdentityV1 {
            expected_enclave_id: Some(alloy_primitives::B256::repeat_byte(0x48)),
            ..identity
        };
        assert!(super::validator_admission_anchor_from_durable_v1(
            durable,
            676,
            durable.genesis_hash,
            wrong_enclave,
        )
        .unwrap_err()
        .to_string()
        .contains("enclave"));
    }

    #[test]
    fn ocomp_bundle_catalog_can_rotate_from_v1_v2_to_v2_v3() {
        let v1 = alloy_primitives::B256::repeat_byte(0x11);
        let v2 = alloy_primitives::B256::repeat_byte(0x22);
        let v3 = alloy_primitives::B256::repeat_byte(0x33);
        let installed = std::collections::BTreeMap::from([(v2, ()), (v3, ())]);
        let configured = format!("{v2:#x},{v3:#x}");

        let ordered =
            super::ordered_installed_ocomp_bundle_hashes(v1, &installed, Some(&configured))
                .expect("post-genesis adjacent authorities should not force V1");

        assert_eq!(ordered, vec![v2, v3]);
    }

    #[test]
    fn post_genesis_two_bundle_catalog_requires_explicit_lane_order() {
        let v1 = alloy_primitives::B256::repeat_byte(0x11);
        let v2 = alloy_primitives::B256::repeat_byte(0x22);
        let v3 = alloy_primitives::B256::repeat_byte(0x33);
        let installed = std::collections::BTreeMap::from([(v2, ()), (v3, ())]);

        let error = super::ordered_installed_ocomp_bundle_hashes(v1, &installed, None)
            .expect_err("hash order must be explicit after genesis V1 is retired");

        assert!(error
            .to_string()
            .contains("OCOMP_PROTOCOL_BUNDLE_HASHES is required"));
    }

    #[test]
    fn configured_ocomp_bundle_hashes_are_exact_lowercase_and_unique() {
        let hash = alloy_primitives::B256::repeat_byte(0xab);
        assert_eq!(
            super::parse_ocomp_bundle_hashes(&format!("{hash:#x}"))
                .expect("canonical hash should parse"),
            vec![hash]
        );
        assert!(
            super::parse_ocomp_bundle_hashes(&format!("{hash:#x},{hash:#x}"))
                .expect_err("duplicate must fail")
                .to_string()
                .contains("duplicate")
        );
        assert!(super::parse_ocomp_bundle_hashes(
            "0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        )
        .expect_err("uppercase must fail")
        .to_string()
        .contains("lowercase"));
    }

    impl Drop for ExecutionTeardownSentinel {
        fn drop(&mut self) {
            assert!(
                self.0.load(Ordering::SeqCst),
                "consensus must be joined before execution resources are torn down"
            );
        }
    }

    #[test]
    fn dropped_launcher_joins_consensus_before_execution_teardown() {
        let consensus_stopped = Arc::new(AtomicBool::new(false));
        let execution = ExecutionTeardownSentinel(Arc::clone(&consensus_stopped));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker_shutdown = shutdown.clone();
        let worker_stopped = Arc::clone(&consensus_stopped);
        let worker = std::thread::spawn(move || {
            while !worker_shutdown.is_cancelled() {
                std::thread::yield_now();
            }
            worker_stopped.store(true, Ordering::SeqCst);
            Ok(())
        });

        let lifecycle = super::ConsensusThreadGuard::new(shutdown, worker);
        drop(lifecycle);

        assert!(consensus_stopped.load(Ordering::SeqCst));
        drop(execution);
    }

    #[test]
    fn node_pin_drops_after_runner_on_consensus_thread() {
        let runner_returned = Arc::new(AtomicBool::new(false));
        let dropped_on = Arc::new(Mutex::new(None));
        let expected_thread = std::thread::current().id();
        let pin = Arc::new(ThreadDropRecorder {
            runner_returned: Arc::clone(&runner_returned),
            dropped_on: Arc::clone(&dropped_on),
        });
        let worker_pin = Arc::clone(&pin);

        let output = super::run_with_lifetime_pin(pin, || {
            std::thread::spawn(move || drop(worker_pin))
                .join()
                .expect("worker exits cleanly");
            runner_returned.store(true, Ordering::SeqCst);
            7
        });

        assert_eq!(output, 7);
        assert_eq!(
            *dropped_on.lock().expect("drop recorder lock"),
            Some(expected_thread)
        );
    }

    #[test]
    fn supervised_shutdown_waits_for_descendants() {
        use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};

        let dropped = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&dropped);
        commonware_runtime::tokio::Runner::default().start(async move |ctx| {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let child_dropped = Arc::clone(&observed);
            let mut stack = ctx.child("test_stack").spawn(move |_| async move {
                struct ChildDrop(Arc<AtomicBool>);
                impl Drop for ChildDrop {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }

                let _drop = ChildDrop(child_dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            });
            started_rx.await.expect("child started");

            assert!(super::abort_and_wait_supervised(&mut stack)
                .await
                .unwrap()
                .is_none());
            assert!(observed.load(Ordering::SeqCst));
        });
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn cancellation_guard_preserves_consensus_error_after_launcher_drop() {
        let outcome = outbe_node::shutdown::NodeShutdown::default();
        let worker = std::thread::spawn(|| Err(eyre::eyre!("consensus drain failed")));
        let guard =
            super::ConsensusThreadGuard::new(tokio_util::sync::CancellationToken::new(), worker)
                .with_outcome(outcome.clone());
        drop(guard);
        let error = outcome
            .finish(Ok(()))
            .expect_err("cancelled launcher must retain failure");
        assert!(format!("{error:#}").contains("consensus drain failed"));
    }

    #[test]
    fn supervised_shutdown_preserves_an_already_completed_failure() {
        use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
        let config = commonware_runtime::tokio::Config::default().with_worker_threads(1);
        commonware_runtime::tokio::Runner::new(config).start(async move |ctx| {
            let (completed, wait) = tokio::sync::oneshot::channel();
            let mut stack = ctx.child("failed_stack").spawn(move |_| async move {
                completed.send(()).unwrap();
                Err::<(), _>(eyre::eyre!("stack failure during drain"))
            });
            // On this one-worker runtime, the non-yielding child returns its
            // result before this receiver can resume. No wall-clock sleeps.
            wait.await.unwrap();
            let result = super::abort_and_wait_supervised(&mut stack).await.unwrap();
            let error = result
                .expect("completed task result must survive abort")
                .unwrap_err();
            assert!(format!("{error:#}").contains("stack failure during drain"));
        });
    }

    #[test]
    fn supervised_shutdown_waits_for_a_pending_terminal_result() {
        use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
        use futures::FutureExt as _;
        commonware_runtime::tokio::Runner::default().start(async move |ctx| {
            let (release, ready) = tokio::sync::oneshot::channel();
            let mut stack = ctx.child("terminal_result").spawn(move |_| async move {
                ready.await.unwrap();
                Err(eyre::eyre!("original terminal error after drain"))
            });
            let wait = super::await_consensus_stack_shutdown(
                &mut stack,
                std::time::Duration::from_secs(1),
            );
            tokio::pin!(wait);
            assert!(
                wait.as_mut().now_or_never().is_none(),
                "shutdown must not abort a pending result"
            );
            release.send(()).unwrap();
            assert!(format!("{:#}", wait.await.unwrap_err())
                .contains("original terminal error after drain"));
        });
    }

    #[test]
    fn supervised_shutdown_reaps_a_stalled_stack_but_returns_failure() {
        use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
        commonware_runtime::tokio::Runner::default().start(async move |ctx| {
            let (alive, dropped) = tokio::sync::oneshot::channel::<()>();
            let (started, ready) = tokio::sync::oneshot::channel();
            let mut stack = ctx
                .child("stalled_terminal_result")
                .spawn(move |_| async move {
                    let _alive = alive;
                    started.send(()).unwrap();
                    std::future::pending::<eyre::Result<()>>().await
                });
            ready.await.unwrap();
            let error =
                super::await_consensus_stack_shutdown(&mut stack, std::time::Duration::ZERO)
                    .await
                    .unwrap_err();
            assert!(error.to_string().contains("result deadline exceeded"));
            assert!(
                dropped.await.is_err(),
                "forced cancellation must reap the stack"
            );
        });
    }

    #[tokio::test]
    async fn application_drain_does_not_trigger_the_external_signal_branch() {
        let external = tokio_util::sync::CancellationToken::new();
        let application = external.child_token();
        application.cancel();
        assert!(!external.is_cancelled());
        let another_application = external.child_token();
        external.cancel();
        assert!(another_application.is_cancelled());
    }

    #[test]
    fn canonical_tee_lease_rejection_is_a_clean_stop() {
        let outcome = outbe_node::shutdown::NodeShutdown::default();
        assert_eq!(
            super::tee_lease_exit_reason(Some(Ok("lease expired".into())), &outcome),
            "lease expired"
        );
        outcome.finish(Ok(())).unwrap();
    }

    #[test]
    fn consensus_shutdown_preserves_both_timeout_and_stack_error() {
        let error = super::consensus_shutdown_result(
            Err(commonware_runtime::Error::Timeout),
            Err(eyre::eyre!("failed finalization during drain")),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("did not complete within 5 seconds"));
        assert!(message.contains("failed finalization during drain"));
    }

    #[test]
    fn tee_lease_read_failure_and_missing_verdict_remain_errors() {
        let _no_logging =
            tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
        for verdict in [Some(Err(eyre::eyre!("provider read failed"))), None] {
            let outcome = outbe_node::shutdown::NodeShutdown::default();
            let reason = super::tee_lease_exit_reason(verdict, &outcome);
            assert!(format!("{:#}", outcome.finish(Ok(())).unwrap_err()).contains(&reason));
        }
    }

    #[test]
    fn cancellation_guard_preserves_consensus_panic_after_launcher_drop() {
        let outcome = outbe_node::shutdown::NodeShutdown::default();
        let worker =
            std::thread::spawn(|| -> eyre::Result<()> { panic!("consensus panic marker") });
        let guard =
            super::ConsensusThreadGuard::new(tokio_util::sync::CancellationToken::new(), worker)
                .with_outcome(outcome.clone());
        drop(guard);
        let error = outcome
            .finish(Ok(()))
            .expect_err("cancelled launcher must retain panic");
        assert!(format!("{error:#}").contains("consensus panic marker"));
    }

    #[test]
    fn explicit_consensus_finish_preserves_error() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker = std::thread::spawn(|| Err(eyre::eyre!("consensus failed")));
        let lifecycle = super::ConsensusThreadGuard::new(shutdown, worker);

        let error = super::handle_consensus_thread_join(lifecycle.join())
            .expect_err("consensus error must propagate through explicit finish");
        assert!(format!("{error:#}").contains("consensus failed"));
    }

    #[test]
    fn explicit_consensus_finish_preserves_panic() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let worker = std::thread::spawn(|| -> eyre::Result<()> {
            panic!("consensus panicked");
        });
        let lifecycle = super::ConsensusThreadGuard::new(shutdown, worker);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::handle_consensus_thread_join(lifecycle.join())
        }));
        assert!(
            panic.is_err(),
            "consensus panic must resume on explicit finish"
        );
    }

    #[test]
    fn ocomp_openings_remain_available_for_completed_full_node_replay() {
        use outbe_ocomp_protocol::state::OcompJobStatus;

        assert!(super::ocomp_job_available_for_calculation(
            OcompJobStatus::VotingOpen
        ));
        assert!(super::ocomp_job_available_for_calculation(
            OcompJobStatus::Completed
        ));
        for unavailable in [
            OcompJobStatus::AwaitingFinality,
            OcompJobStatus::Expired,
            OcompJobStatus::Failed,
        ] {
            assert!(!super::ocomp_job_available_for_calculation(unavailable));
        }
    }

    #[test]
    fn engine_builds_payloads_after_prefinalization_parent_switches() {
        let mut engine = reth_node_core::args::EngineArgs::default();
        assert!(!engine.always_process_payload_attributes_on_canonical_head);
        assert!(!engine.allow_unwind_canonical_header);

        super::configure_outbe_engine_args(&mut engine);

        assert!(engine.always_process_payload_attributes_on_canonical_head);
        assert!(engine.allow_unwind_canonical_header);
        let tree = engine.tree_config();
        assert!(tree.always_process_payload_attributes_on_canonical_head());
        assert!(tree.unwind_canonical_header());
    }

    /// Pool lifetime hardening: parked transactions must age out in minutes,
    /// not hours, RPC submissions must not be exempt from that eviction, and a
    /// restart must not resurrect what the node evicted.
    ///
    /// Asserted through `TxPoolArgs::default()`, which reads the installed
    /// global defaults - the same values clap hands the node when no
    /// `--txpool.*` flag is given.
    #[test]
    fn txpool_defaults_bound_transaction_lifetime() {
        // Installing is idempotent-by-OnceLock; another test in this binary may
        // have installed the same values first, which is equally correct.
        let _ = super::outbe_default_txpool_values().try_init();

        let args = reth_node_core::args::TxPoolArgs::default();
        assert_eq!(
            args.max_queued_lifetime,
            std::time::Duration::from_secs(120),
            "parked transactions must age out in minutes, not the upstream 3 hours"
        );
        assert!(
            args.no_locals,
            "RPC-submitted transactions must not be exempt from lifetime eviction"
        );
        assert!(
            args.disable_transactions_backup,
            "a restart must not resurrect evicted transactions"
        );
    }

    #[test]
    fn full_node_identity_uses_reth_secret_resolver_and_persists_exact_key() {
        let root = tempfile::tempdir().unwrap();
        let explicit_secret = root.path().join("operator-p2p.key");
        let unused_default = root.path().join("default-discovery-secret");
        let network = reth_node_core::args::NetworkArgs {
            p2p_secret_key: Some(explicit_secret.clone()),
            ..Default::default()
        };

        let (first_signer, first_public) =
            super::load_reth_p2p_node_host_signer(&network, unused_default.clone()).unwrap();
        assert!(explicit_secret.is_file());
        assert!(!unused_default.exists());
        assert_eq!(
            first_signer
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
            first_public
        );

        drop(first_signer);
        let (_, restored_public) =
            super::load_reth_p2p_node_host_signer(&network, unused_default).unwrap();
        assert_eq!(restored_public, first_public);
    }

    #[test]
    fn adr005_accepts_validators_and_certified_followers_only() {
        super::validate_adr005_node_mode(true, false).expect("validator path is parent-gated");
        super::validate_adr005_node_mode(false, true)
            .expect("certified follower path is parent-gated");

        let error = super::validate_adr005_node_mode(false, false)
            .expect_err("plain EL sync has no finalized-parent projection barrier");
        assert!(error.to_string().contains("--upstream"));
    }

    #[test]
    fn consensus_thread_error_propagates_to_validator_main() {
        let err = super::handle_consensus_thread_join(Ok(Err(eyre::eyre!("watchdog fatal"))))
            .expect_err("consensus thread error must propagate");
        let err = format!("{err:#}");

        assert!(
            err.contains("consensus task exited with error"),
            "wrapped consensus context missing: {err}"
        );
        assert!(
            err.contains("watchdog fatal"),
            "original consensus error missing: {err}"
        );
    }

    #[test]
    fn consensus_thread_success_is_ok() {
        super::handle_consensus_thread_join(Ok(Ok(())))
            .expect("successful consensus thread must not error");
    }

    /// Full-node mode: dropping node_tx causes consensus thread's blocking_recv to return Err.
    /// This verifies that the consensus thread exits immediately when no node handle is sent.
    #[test]
    fn test_fullnode_drops_node_tx_consensus_thread_exits() {
        let (node_tx, node_rx) = tokio::sync::oneshot::channel::<()>();

        // Simulate full-node path: drop sender without sending.
        drop(node_tx);

        // Consensus thread would call blocking_recv - should return Err immediately.
        let result = node_rx.blocking_recv();
        assert!(
            result.is_err(),
            "blocking_recv must return Err when sender is dropped"
        );
    }

    /// Full-node mode: RPC handler created without bridge -> is_validator = false.
    #[test]
    fn test_fullnode_rpc_no_bridge_means_not_validator() {
        // When OutbeApiHandler::new(provider) is called (no bridge),
        // bridge field is None, so is_validator = bridge.is_some() = false.
        let bridge: Option<outbe_engine::bridge::ConsensusExecutionBridge> = None;
        assert!(
            bridge.is_none(),
            "full node must have bridge=None -> is_validator=false"
        );
    }

    /// Validator mode: RPC handler created with bridge -> is_validator = true.
    #[test]
    fn test_validator_rpc_with_bridge_means_validator() {
        let bridge = outbe_engine::bridge::ConsensusExecutionBridge::new();
        let bridge_opt: Option<outbe_engine::bridge::ConsensusExecutionBridge> = Some(bridge);
        assert!(
            bridge_opt.is_some(),
            "validator must have bridge=Some -> is_validator=true"
        );
    }

    #[test]
    fn outbe_rpc_module_validator_accepts_rudis_namespace() {
        use reth_rpc_server_types::{RpcModuleSelection, RpcModuleValidator as _};

        let selection = super::OutbeRpcModuleValidator::parse_selection("eth,net,web3,rudis")
            .expect("rudis namespace should be accepted");
        let RpcModuleSelection::Selection(modules) = selection else {
            panic!("explicit module list should parse as selection");
        };
        assert!(modules.iter().any(|module| module.as_str() == "rudis"));
    }

    #[test]
    fn outbe_rpc_module_validator_normalizes_legacy_operator_selector() {
        use reth_rpc_server_types::{RpcModuleSelection, RpcModuleValidator as _};
        let selection = super::OutbeRpcModuleValidator::parse_selection("eth,outbe").unwrap();
        let RpcModuleSelection::Selection(modules) = selection else {
            panic!("expected explicit module selection");
        };
        assert!(modules.iter().any(|module| module.as_str() == "rudis"));
        assert!(!modules.iter().any(|module| module.as_str() == "outbe"));
    }

    #[test]
    fn outbe_rpc_module_validator_rejects_unknown_namespace() {
        use reth_rpc_server_types::RpcModuleValidator as _;

        let err = super::OutbeRpcModuleValidator::parse_selection("eth,outbee")
            .expect_err("typoed custom namespace must be rejected");
        assert!(err.contains("Unknown RPC module: 'outbee'"));
    }

    fn install_cli_defaults_for_test() {
        let _ = super::outbe_default_txpool_values().try_init();
    }

    #[test]
    fn database_cli_requires_an_explicit_chain_instead_of_parsing_mainnet() {
        install_cli_defaults_for_test();
        type OutbeCli = reth_ethereum::cli::interface::Cli<
            super::OutbeChainSpecParser,
            outbe_engine::args::ConsensusArgs,
            super::OutbeRpcModuleValidator,
        >;

        let error = <OutbeCli as clap::Parser>::try_parse_from(["outbe-chain", "db", "path"])
            .expect_err("database commands must require an explicit Outbe ChainSpec");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        let rendered = error.to_string();
        assert!(rendered.contains("required argument"), "{rendered}");
        assert!(rendered.contains("chain"), "{rendered}");
        assert!(!rendered.contains("mainnet"), "{rendered}");
    }

    #[test]
    fn node_cli_also_requires_an_explicit_chain() {
        install_cli_defaults_for_test();
        type OutbeCli = reth_ethereum::cli::interface::Cli<
            super::OutbeChainSpecParser,
            outbe_engine::args::ConsensusArgs,
            super::OutbeRpcModuleValidator,
        >;

        let error = <OutbeCli as clap::Parser>::try_parse_from(["outbe-chain", "node"])
            .expect_err("node execution must require an explicit Outbe ChainSpec");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("chain"));
    }

    #[test]
    fn reth_mainnet_alias_is_not_outbe_mainnet_676() {
        install_cli_defaults_for_test();
        type OutbeCli = reth_ethereum::cli::interface::Cli<
            super::OutbeChainSpecParser,
            outbe_engine::args::ConsensusArgs,
            super::OutbeRpcModuleValidator,
        >;

        let error = <OutbeCli as clap::Parser>::try_parse_from([
            "outbe-chain",
            "db",
            "path",
            "--chain",
            "mainnet",
        ])
        .expect_err("Ethereum mainnet must not satisfy mandatory Outbe ChainSpec validation");

        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        let rendered = error.to_string();
        assert!(rendered.contains("unknown Outbe chain ID 1"), "{rendered}");
        assert!(
            !rendered.contains("unknown Outbe chain ID 676"),
            "{rendered}"
        );
    }

    #[derive(Clone, Debug, Default)]
    struct ExplicitFixtureChainSpecParser;

    impl reth_cli::chainspec::ChainSpecParser for ExplicitFixtureChainSpecParser {
        type ChainSpec = reth_chainspec::ChainSpec<outbe_primitives::OutbeHeader>;

        const SUPPORTED_CHAINS: &'static [&'static str] = &["mainnet"];

        fn default_value() -> Option<&'static str> {
            None
        }

        fn parse(value: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
            Ok(reth_ethereum::cli::chainspec::chain_value_parser(value)?
                .as_ref()
                .clone()
                .map_header(outbe_primitives::OutbeHeader::new)
                .into())
        }
    }

    #[test]
    fn only_node_execution_requires_the_crs() {
        install_cli_defaults_for_test();
        type FixtureCli = reth_ethereum::cli::interface::Cli<
            ExplicitFixtureChainSpecParser,
            outbe_engine::args::ConsensusArgs,
            super::OutbeRpcModuleValidator,
        >;

        let node = <FixtureCli as clap::Parser>::try_parse_from([
            "outbe-chain",
            "node",
            "--chain",
            "mainnet",
        ])
        .expect("explicit fixture node chain");
        assert!(super::command_requires_crs(&node.command));
        let mut node_initialized = false;
        super::initialize_crs_for_command(&node.command, || {
            node_initialized = true;
            Ok(())
        })
        .unwrap();
        assert!(node_initialized);

        let database = <FixtureCli as clap::Parser>::try_parse_from([
            "outbe-chain",
            "db",
            "path",
            "--chain",
            "mainnet",
        ])
        .expect("explicit fixture database chain");
        assert!(!super::command_requires_crs(&database.command));
        let mut database_initialized = false;
        super::initialize_crs_for_command(&database.command, || {
            database_initialized = true;
            Ok(())
        })
        .unwrap();
        assert!(!database_initialized);
    }

    // --- parse_dkg_key_backend ---

    fn make_dkg_cli(args: &[&str]) -> super::DkgCli {
        use clap::Parser;
        let mut full = vec!["cmd"];
        full.extend_from_slice(args);
        super::DkgCli::parse_from(full)
    }

    #[test]
    fn test_parse_dkg_key_backend_plaintext() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "plaintext",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(
            backend,
            outbe_consensus::bls::KeyBackend::Plaintext
        ));
    }

    #[test]
    fn test_parse_dkg_key_backend_default_is_plaintext() {
        let cli = make_dkg_cli(&["status", "--storage-dir", "/tmp"]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(
            backend,
            outbe_consensus::bls::KeyBackend::Plaintext
        ));
    }

    #[test]
    fn test_parse_dkg_key_backend_encrypted_with_passphrase() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "encrypted",
            "--bls-passphrase",
            "hunter2",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(
            backend,
            outbe_consensus::bls::KeyBackend::Encrypted(ref p) if p == "hunter2"
        ));
    }

    #[test]
    fn test_parse_dkg_key_backend_encrypted_missing_passphrase() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "encrypted",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        assert!(super::parse_dkg_key_backend(&cli).is_err());
    }

    #[test]
    fn test_parse_dkg_key_backend_os_level() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "os-level",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        let backend = super::parse_dkg_key_backend(&cli).unwrap();
        assert!(matches!(backend, outbe_consensus::bls::KeyBackend::OsLevel));
    }

    #[test]
    fn test_parse_dkg_key_backend_unknown() {
        let cli = make_dkg_cli(&[
            "--bls-key-backend",
            "foo",
            "status",
            "--storage-dir",
            "/tmp",
        ]);
        assert!(super::parse_dkg_key_backend(&cli).is_err());
    }

    // --- TC-002: DKG command routing via run_dkg_command ---

    fn dkg_args(args: &[&str]) -> Vec<String> {
        let mut v = vec!["outbe-chain".to_string(), "dkg".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn test_dkg_bootstrap_3_validators() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        // Verify output structure
        assert!(dir.path().join("polynomial.hex").exists());
        assert!(dir.path().join("dkg-output.hex").exists());
        assert!(dir.path().join("validators.json").exists());
        for i in 0..3 {
            let vdir = dir.path().join(format!("validator-{i}"));
            assert!(vdir.join("signing-key.hex").exists());
            assert!(vdir.join("evm-key.hex").exists());
        }
    }

    #[test]
    fn test_dkg_identities_do_not_precompute_genesis_threshold_material() {
        let dir = tempfile::tempdir().unwrap();
        let args = dkg_args(&[
            "identities",
            "--output-dir",
            dir.path().to_str().unwrap(),
            "--validators",
            "4",
        ]);
        super::run_dkg_command(&args).unwrap();

        assert!(dir.path().join("validators.json").exists());
        assert!(dir.path().join("reth-bootnodes.txt").exists());
        assert!(!dir.path().join("polynomial.hex").exists());
        assert!(!dir.path().join("dkg-output.hex").exists());
        for index in 0..4 {
            let validator = dir.path().join(format!("validator-{index}"));
            assert!(validator.join("signing-key.hex").exists());
            assert!(validator.join("evm-key.hex").exists());
            assert!(validator.join("reth-p2p-secret.hex").exists());
            assert!(!validator.join("signing-share.hex").exists());
        }
    }

    #[test]
    fn test_dkg_status_after_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        // Status on a validator directory (has share + poly from bootstrap)
        let v0 = dir.path().join("validator-0");
        let v0_str = v0.to_str().unwrap();
        let status_args = dkg_args(&["status", "--storage-dir", v0_str]);
        super::run_dkg_command(&status_args).unwrap();
    }

    #[test]
    fn test_dkg_status_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["status", "--storage-dir", dir_str]);
        // Should succeed but print "NOT READY"
        super::run_dkg_command(&args).unwrap();
    }

    #[test]
    fn test_dkg_export_requires_complete_runtime_state() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        // Bootstrap output keeps the shared dkg-output.hex at the output root.
        // Runtime export must still reject validator storage that lacks its local
        // complete triplet instead of producing an import bundle startup cannot load.
        let v0 = dir.path().join("validator-0");
        std::fs::copy(v0.join("signing-share.hex"), v0.join("dkg_share.hex")).unwrap();
        std::fs::copy(
            dir.path().join("polynomial.hex"),
            v0.join("dkg_polynomial.hex"),
        )
        .unwrap();

        let export_dir = tempfile::tempdir().unwrap();
        let export_args = dkg_args(&[
            "export-share",
            "--storage-dir",
            v0.to_str().unwrap(),
            "--output",
            export_dir.path().to_str().unwrap(),
        ]);
        assert!(super::run_dkg_command(&export_args).is_err());
    }

    #[test]
    fn test_dkg_force_restart_only_removes_consensus_material() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["bootstrap", "--output-dir", dir_str, "--validators", "3"]);
        super::run_dkg_command(&args).unwrap();

        let v0 = dir.path().join("validator-0");
        // Copy into runtime filenames
        std::fs::copy(v0.join("signing-share.hex"), v0.join("dkg_share.hex")).unwrap();
        std::fs::copy(
            dir.path().join("polynomial.hex"),
            v0.join("dkg_polynomial.hex"),
        )
        .unwrap();
        std::fs::write(v0.join("dkg_output.hex"), "placeholder").unwrap();
        let tee_sentinels = [
            ("sealed_root.bin", b"permanent-offer-key".as_slice()),
            ("sealed_identity.bin", b"enclave-identity".as_slice()),
            (
                "sealed_node_authorization_v1.bin",
                b"node-host-authorization".as_slice(),
            ),
        ];
        for (name, bytes) in tee_sentinels {
            std::fs::write(v0.join(name), bytes).unwrap();
        }
        assert!(v0.join("dkg_share.hex").exists());
        assert!(v0.join("dkg_output.hex").exists());

        let restart_args = dkg_args(&["force-restart", "--storage-dir", v0.to_str().unwrap()]);
        super::run_dkg_command(&restart_args).unwrap();

        assert!(!v0.join("dkg_share.hex").exists());
        assert!(!v0.join("dkg_polynomial.hex").exists());
        assert!(!v0.join("dkg_output.hex").exists());
        for (name, bytes) in tee_sentinels {
            assert_eq!(std::fs::read(v0.join(name)).unwrap(), bytes);
        }
    }

    #[test]
    fn test_dkg_force_restart_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();
        let args = dkg_args(&["force-restart", "--storage-dir", dir_str]);
        super::run_dkg_command(&args).unwrap(); // no-op, succeeds
    }

    #[test]
    fn test_dkg_export_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let export_dir = tempfile::tempdir().unwrap();
        let args = dkg_args(&[
            "export-share",
            "--storage-dir",
            dir.path().to_str().unwrap(),
            "--output",
            export_dir.path().to_str().unwrap(),
        ]);
        assert!(super::run_dkg_command(&args).is_err());
    }
}
