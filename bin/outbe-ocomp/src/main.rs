use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

use alloy_primitives::{keccak256, B256};
use clap::{Args, Parser, Subcommand};
use outbe_consensus::config::init_consensus_chain_id;
#[cfg(test)]
use outbe_consensus::proof::constants::consensus_chain_id;
use outbe_ocomp::bundle::PinnedProtocolBundle;
use outbe_ocomp::cas::CasLimits;
use outbe_ocomp::control::{effective_uid, poc_schema_limits, EndpointIdentity};
use outbe_ocomp::discovery_spool::{AckPutOutcomeV1, DiscoverySpoolV1, PendingDiscoveryV1};
use outbe_ocomp::inbox::WorkerInboxLimits;
use outbe_ocomp::rpc_input_exporter::{RpcInputExporterConfigV1, RpcInputExporterV1};
use outbe_ocomp::supervisor::DiscoveryRecord;
use outbe_ocomp::worker::{run_worker, WorkerConfig};
use outbe_ocomp::worker_observability::SnapshotExporterObservabilityServerV1;
use outbe_ocomp::worker_transport::MAX_REGISTERED_WORKERS;
use outbe_offchain_storage::StorageConfig;
use outbe_primitives::signer::OutbeEvmSigner;

#[derive(Debug, Parser)]
#[command(name = "outbe-ocomp")]
#[command(about = "Fixed Off-chain Computation PoC process roles")]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Debug, Subcommand)]
enum Role {
    SnapshotExporter(RuntimeArgs),
    Worker(WorkerArgs),
    /// Print the address of the role-delegated OCOMP transaction signer.
    SignerAddress(RuntimeArgs),
}

#[derive(Clone, Debug, Args)]
struct WorkerArgs {
    #[command(flatten)]
    runtime: RuntimeArgs,
    #[arg(long)]
    chain_id: u64,
    #[arg(long)]
    genesis_hash: B256,
    #[arg(long)]
    boot_nonce: B256,
    #[arg(long)]
    protocol_bundle_hash: B256,
    /// Stable ordinal of this Worker process on the host (0..4 exclusive).
    #[arg(long, default_value_t = 0)]
    worker_ordinal: u8,
}

#[derive(Clone, Debug, Args)]
struct RuntimeArgs {
    /// Unprivileged OCM measurement namespace; accepted only by debug builds.
    #[arg(long, hide = true, value_name = "PATH")]
    development_root: Option<PathBuf>,
    /// Loopback Supervisor endpoint where OCOMP workers register for work.
    #[arg(long, value_name = "IP:PORT", default_value = "127.0.0.1:30401")]
    supervisor_address: SocketAddr,
}

const BASE_PATH_ENV: &str = "OUTBE_OCOMP_BASE_PATH";
const VALIDATOR_INDEX_ENV: &str = "OCOMP_VALIDATOR_INDEX";
const CAS_MAX_OBJECT_BYTES: u64 = 1_048_576;
const WORKER_INBOX_MAX_ARTIFACT_BYTES: u64 = 1_048_576;
const WORKER_INBOX_MAX_TOTAL_BYTES: u64 = 67_108_864;
const OCOMP_RPC_MAX_RESPONSE_BYTES: usize = 33_554_432;
const EXPORTER_RECONCILE_INTERVAL: Duration = Duration::from_secs(1);
const OCOMP_TRIBUTE_PAGE_LIMIT: usize = 256;
const PROTOCOL_BUNDLE_HASHES_ENV: &str = "OCOMP_PROTOCOL_BUNDLE_HASHES";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionConfig {
    base_path: PathBuf,
    validator_index: u16,
}

impl ProductionConfig {
    fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_lookup(|name| env::var_os(name))
    }

    fn from_lookup(
        mut lookup: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let base_path = lookup(BASE_PATH_ENV)
            .map(PathBuf::from)
            .ok_or("OUTBE_OCOMP_BASE_PATH is required")?;
        let validator_index = lookup(VALIDATOR_INDEX_ENV)
            .ok_or("OCOMP_VALIDATOR_INDEX is required")?
            .into_string()
            .map_err(|_| "OCOMP_VALIDATOR_INDEX must be valid UTF-8")?
            .parse::<u16>()
            .map_err(|_| "OCOMP_VALIDATOR_INDEX must be an unsigned 16-bit integer")?;
        Ok(Self {
            base_path,
            validator_index,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductionLayout {
    cas_root: PathBuf,
    worker_inbox_root: PathBuf,
    snapshot_exporter_journal_root: PathBuf,
    snapshot_exporter_input_ref_root: PathBuf,
    snapshot_exporter_receipt_root: PathBuf,
    ocomp_evm_key_path: PathBuf,
    protocol_bundle_path: PathBuf,
    protocol_bundle_catalog: PathBuf,
}

impl ProductionLayout {
    fn from_base(
        base_path: &Path,
        validator_index: u16,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !base_path.is_absolute() || base_path.parent().is_none() || base_path == Path::new("/") {
            return Err("OCOMP base path must be a non-root absolute path".into());
        }

        let domain_root = base_path
            .join(format!("validator-{validator_index}"))
            .join("ocomp")
            .join("domain-v1");
        let exporter_root = domain_root.join("exporter-v1");
        Ok(Self {
            cas_root: domain_root.join("cas-v1"),
            worker_inbox_root: domain_root.join("worker-inbox-v1"),
            snapshot_exporter_journal_root: exporter_root.join("discovery"),
            snapshot_exporter_input_ref_root: exporter_root.join("input-refs"),
            snapshot_exporter_receipt_root: exporter_root.join("receipts"),
            ocomp_evm_key_path: domain_root.join("ocomp-evm-key.hex"),
            protocol_bundle_path: domain_root.join("protocol-bundle-v1.ocb1"),
            protocol_bundle_catalog: domain_root.join("protocol-bundles-v1"),
        })
    }
}

#[derive(Clone, Debug)]
struct RuntimeProfile {
    owner_uid: u32,
    supervisor_address: SocketAddr,
    cas_root: PathBuf,
    worker_inbox_root: PathBuf,
    snapshot_exporter_journal_root: PathBuf,
    snapshot_exporter_input_ref_root: PathBuf,
    snapshot_exporter_receipt_root: PathBuf,
    ocomp_evm_key_path: PathBuf,
    protocol_bundle_path: PathBuf,
    protocol_bundle_catalog: PathBuf,
}

impl RuntimeProfile {
    fn resolve(args: &RuntimeArgs) -> Result<Self, Box<dyn std::error::Error>> {
        if !args.supervisor_address.ip().is_loopback() || args.supervisor_address.port() == 0 {
            return Err(
                "--supervisor-address must be a nonzero loopback registration endpoint".into(),
            );
        }
        let Some(root) = args.development_root.as_ref() else {
            let production = ProductionConfig::from_environment()?;
            let layout =
                ProductionLayout::from_base(&production.base_path, production.validator_index)?;
            return Ok(Self {
                owner_uid: effective_uid()?,
                supervisor_address: args.supervisor_address,
                cas_root: layout.cas_root,
                worker_inbox_root: layout.worker_inbox_root,
                snapshot_exporter_journal_root: layout.snapshot_exporter_journal_root,
                snapshot_exporter_input_ref_root: layout.snapshot_exporter_input_ref_root,
                snapshot_exporter_receipt_root: layout.snapshot_exporter_receipt_root,
                ocomp_evm_key_path: layout.ocomp_evm_key_path,
                protocol_bundle_path: layout.protocol_bundle_path,
                protocol_bundle_catalog: layout.protocol_bundle_catalog,
            });
        };

        if !cfg!(debug_assertions) {
            return Err("--development-root is unavailable in release outbe-ocomp builds".into());
        }
        if !root.is_absolute() || root.parent().is_none() || root == std::path::Path::new("/") {
            return Err("--development-root must be a non-root absolute path".into());
        }
        let metadata = std::fs::symlink_metadata(root)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err("--development-root must name an existing real directory".into());
        }
        let uid = effective_uid()?;
        Ok(Self {
            owner_uid: uid,
            supervisor_address: args.supervisor_address,
            cas_root: root.join("cas-v1"),
            worker_inbox_root: root.join("worker-inbox-v1"),
            snapshot_exporter_journal_root: root.join("exporter-v1").join("discovery"),
            snapshot_exporter_input_ref_root: root.join("exporter-v1").join("input-refs"),
            snapshot_exporter_receipt_root: root.join("exporter-v1").join("receipts"),
            ocomp_evm_key_path: root.join("ocomp-evm-key.hex"),
            protocol_bundle_path: root.join("protocol-bundle-v1.ocb1"),
            protocol_bundle_catalog: root.join("protocol-bundles-v1"),
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().role {
        Role::Worker(args) => {
            install_consensus_domain(args.chain_id)?;
            let runtime = RuntimeProfile::resolve(&args.runtime)?;
            let limits = poc_schema_limits();
            let canonical_bundle = std::fs::read(protocol_bundle_path_for_hash(
                &runtime,
                args.protocol_bundle_hash,
            )?)?;
            let protocol_bundle = PinnedProtocolBundle::decode(
                &canonical_bundle,
                args.protocol_bundle_hash,
                &limits,
            )?;
            run_worker(WorkerConfig {
                identity: EndpointIdentity {
                    chain_id: args.chain_id,
                    genesis_hash: args.genesis_hash,
                    boot_nonce: worker_process_nonce(args.boot_nonce, args.worker_ordinal)?,
                    protocol_bundle_hash: args.protocol_bundle_hash,
                },
                supervisor_address: runtime.supervisor_address,
                observability_address: worker_observability_address(
                    runtime.supervisor_address,
                    args.worker_ordinal,
                )?,
                cas_root: runtime.cas_root,
                cas_limits: CasLimits {
                    max_object_bytes: CAS_MAX_OBJECT_BYTES,
                    // CAS is disk-backed and chunked. Capacity is governed by the
                    // filesystem/operator, never by a product-level total-job cap.
                    max_total_bytes: u64::MAX,
                },
                inbox_root: runtime
                    .worker_inbox_root
                    .join(hex::encode(args.protocol_bundle_hash.as_slice())),
                inbox_limits: WorkerInboxLimits {
                    max_artifact_bytes: WORKER_INBOX_MAX_ARTIFACT_BYTES,
                    max_total_bytes: WORKER_INBOX_MAX_TOTAL_BYTES,
                },
                protocol_bundle,
            })?;
            Ok(())
        }
        Role::SnapshotExporter(args) => run_snapshot_exporter(&args),
        Role::SignerAddress(args) => print_signer_address(&args),
    }
}

fn worker_process_nonce(host_boot_nonce: B256, worker_ordinal: u8) -> Result<B256, &'static str> {
    if usize::from(worker_ordinal) >= MAX_REGISTERED_WORKERS {
        return Err("worker ordinal exceeds the supported per-Supervisor worker count");
    }
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(b"OCOMP_WORKER_PROCESS_NONCE_V1");
    preimage.extend_from_slice(host_boot_nonce.as_slice());
    preimage.push(worker_ordinal);
    let nonce = keccak256(preimage);
    if nonce.is_zero() {
        Err("derived worker process nonce is reserved zero")
    } else {
        Ok(nonce)
    }
}

fn worker_observability_address(
    supervisor_address: SocketAddr,
    worker_ordinal: u8,
) -> Result<SocketAddr, &'static str> {
    if usize::from(worker_ordinal) >= MAX_REGISTERED_WORKERS {
        return Err("worker ordinal exceeds the supported per-Supervisor worker count");
    }
    let offset = 2_u16
        .checked_add(u16::from(worker_ordinal))
        .ok_or("worker observability port offset overflow")?;
    let port = supervisor_address
        .port()
        .checked_add(offset)
        .ok_or("worker observability port overflow")?;
    Ok(SocketAddr::new(supervisor_address.ip(), port))
}

fn snapshot_exporter_observability_address(
    supervisor_address: SocketAddr,
) -> Result<SocketAddr, &'static str> {
    // Two six-port Supervisor/transport/Worker lane windows are reserved for
    // the active and staged-successor protocol bundles.
    let offset = 12_u16;
    let port = supervisor_address
        .port()
        .checked_add(offset)
        .ok_or("snapshot exporter observability port overflow")?;
    Ok(SocketAddr::new(supervisor_address.ip(), port))
}

fn print_signer_address(args: &RuntimeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeProfile::resolve(args)?;
    let signer = OutbeEvmSigner::from_strict_file(runtime.ocomp_evm_key_path, runtime.owner_uid)?;
    println!("{}", signer.address());
    Ok(())
}

fn run_snapshot_exporter(args: &RuntimeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = RuntimeProfile::resolve(args)?;
    let observability = Arc::new(SnapshotExporterObservabilityServerV1::start(
        snapshot_exporter_observability_address(runtime.supervisor_address)?,
    )?);
    let limits = poc_schema_limits();
    let chain_id = required_env("OCOMP_CHAIN_ID")?.parse()?;
    let genesis_hash = required_env("OCOMP_GENESIS_HASH")?.parse()?;
    let bundle_hashes = required_protocol_bundle_hashes()?;
    install_consensus_domain(chain_id)?;
    let rpc_url = required_env("OUTBE_OCOMP_RPC_URL")?;
    let storage = StorageConfig::load(required_env("OUTBE_OCOMP_STORAGE_CONFIG")?)?;
    let mut lanes = BTreeMap::new();
    for protocol_bundle_hash in bundle_hashes {
        let protocol_bundle = PinnedProtocolBundle::decode(
            &std::fs::read(protocol_bundle_path_for_hash(
                &runtime,
                protocol_bundle_hash,
            )?)?,
            protocol_bundle_hash,
            &limits,
        )?;
        let exporter_config = RpcInputExporterConfigV1 {
            rpc_url: rpc_url.clone(),
            rpc_max_response_bytes: OCOMP_RPC_MAX_RESPONSE_BYTES,
            storage: storage.clone(),
            tribute_page_limit: OCOMP_TRIBUTE_PAGE_LIMIT,
            chain_id,
            genesis_hash,
            fork_id: protocol_bundle.bundle().fork_id,
            protocol_bundle_hash,
            cas_root: runtime.cas_root.clone(),
            cas_limits: CasLimits {
                max_object_bytes: CAS_MAX_OBJECT_BYTES,
                // CAS is disk-backed and chunked. Capacity is governed by the
                // filesystem/operator, never by a product-level total-job cap.
                max_total_bytes: u64::MAX,
            },
            input_ref_root: runtime.snapshot_exporter_input_ref_root.clone(),
            receipt_root: runtime.snapshot_exporter_receipt_root.clone(),
            protocol_bundle: protocol_bundle.clone(),
            limits,
        };
        let exporter = retry_snapshot_exporter_startup(
            || RpcInputExporterV1::open(exporter_config.clone()),
            |error| error.is_retryable_startup(),
            |error| {
                observability.startup_error(error.to_string());
                eprintln!("OCOMP snapshot exporter startup retry: {error}");
                std::thread::sleep(EXPORTER_RECONCILE_INTERVAL);
            },
        )?;
        let spool = DiscoverySpoolV1::open(
            discovery_spool_path(
                &runtime.snapshot_exporter_journal_root,
                protocol_bundle_hash,
            ),
            chain_id,
            genesis_hash,
            limits,
        )?;
        lanes.insert(
            protocol_bundle_hash,
            SnapshotExporterLaneV1 {
                protocol_bundle,
                exporter,
                spool,
            },
        );
    }
    let (lanes, completions) = spawn_snapshot_exporter_lanes(lanes, Arc::clone(&observability))?;

    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    async_runtime.block_on(run_snapshot_exporter_reconciler(
        lanes,
        completions,
        observability,
    ))
}

struct SnapshotExporterLaneV1 {
    protocol_bundle: PinnedProtocolBundle,
    exporter: RpcInputExporterV1,
    spool: DiscoverySpoolV1,
}

struct SnapshotExporterLaneControlV1 {
    spool: DiscoverySpoolV1,
    trigger: mpsc::SyncSender<()>,
}

enum SnapshotExporterCompletionV1 {
    Failed {
        bundle_hash: B256,
        observation_id: Option<B256>,
        detail: String,
    },
    Cycle {
        bundle_hash: B256,
        failed: bool,
    },
}

type SnapshotExporterLaneControlsV1 = BTreeMap<B256, SnapshotExporterLaneControlV1>;
type SnapshotExporterCompletionReceiverV1 =
    tokio::sync::mpsc::UnboundedReceiver<SnapshotExporterCompletionV1>;
type SnapshotExporterLaneSpawnResultV1 = Result<
    (
        SnapshotExporterLaneControlsV1,
        SnapshotExporterCompletionReceiverV1,
    ),
    Box<dyn std::error::Error>,
>;

fn spawn_snapshot_exporter_lanes(
    lanes: BTreeMap<B256, SnapshotExporterLaneV1>,
    observability: Arc<SnapshotExporterObservabilityServerV1>,
) -> SnapshotExporterLaneSpawnResultV1 {
    let (completion_tx, completion_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut controls = BTreeMap::new();
    for (bundle_hash, mut lane) in lanes {
        let (trigger, wakeups) = mpsc::sync_channel(1);
        let spool = lane.spool.clone();
        let lane_observability = Arc::clone(&observability);
        let lane_completion = completion_tx.clone();
        std::thread::Builder::new()
            .name(format!(
                "ocomp-export-{}",
                hex::encode(&bundle_hash.as_slice()[..4])
            ))
            .spawn(move || {
                while wakeups.recv().is_ok() {
                    drain_snapshot_exporter_lane(
                        bundle_hash,
                        &mut lane,
                        &lane_observability,
                        &lane_completion,
                    );
                }
            })?;
        trigger
            .try_send(())
            .map_err(|error| runtime_error(format!("wake snapshot exporter lane: {error}")))?;
        controls.insert(
            bundle_hash,
            SnapshotExporterLaneControlV1 { spool, trigger },
        );
    }
    Ok((controls, completion_rx))
}

fn drain_snapshot_exporter_lane(
    bundle_hash: B256,
    lane: &mut SnapshotExporterLaneV1,
    observability: &SnapshotExporterObservabilityServerV1,
    completions: &tokio::sync::mpsc::UnboundedSender<SnapshotExporterCompletionV1>,
) {
    let mut cycle_failed = false;
    match lane.spool.pending_cursor() {
        Ok(cursor) => {
            for pending in cursor {
                let pending = match pending {
                    Ok(pending) => pending,
                    Err(error) => {
                        cycle_failed = true;
                        let detail = error.to_string();
                        observability.discovery_error(detail.clone());
                        let _ = completions.send(SnapshotExporterCompletionV1::Failed {
                            bundle_hash,
                            observation_id: None,
                            detail,
                        });
                        continue;
                    }
                };
                match export_pending_discovery(lane, &pending, observability) {
                    Ok(()) => {}
                    Err(error) => {
                        cycle_failed = true;
                        let detail = error.to_string();
                        observability.export_error(detail.clone());
                        let _ = completions.send(SnapshotExporterCompletionV1::Failed {
                            bundle_hash,
                            observation_id: Some(pending.reference.observation_id),
                            detail,
                        });
                    }
                }
            }
        }
        Err(error) => {
            cycle_failed = true;
            let detail = error.to_string();
            observability.discovery_error(detail.clone());
            let _ = completions.send(SnapshotExporterCompletionV1::Failed {
                bundle_hash,
                observation_id: None,
                detail,
            });
        }
    }
    let _ = completions.send(SnapshotExporterCompletionV1::Cycle {
        bundle_hash,
        failed: cycle_failed,
    });
}

fn export_pending_discovery(
    lane: &mut SnapshotExporterLaneV1,
    pending: &PendingDiscoveryV1,
    observability: &SnapshotExporterObservabilityServerV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_hash = pending.spec.summary.protocol_bundle_hash;
    if lane.protocol_bundle.hash() != bundle_hash {
        return Err(runtime_error(format!(
            "discovery offer references unconfigured protocol bundle {bundle_hash}"
        )));
    }
    let record = DiscoveryRecord {
        generation: pending.reference.generation,
        cursor: pending.spec.summary.cursor,
        spec: pending.spec.clone(),
    };
    let job_id = record.spec.summary.job_id;
    observability.exporting(bundle_hash.to_string(), job_id.to_string());
    let receipt = lane
        .exporter
        .export_observing(&record, || observability.export_progress())?;
    // The fsynced ACK is the sole cross-process completion authority. The
    // embedded reader observes it from the same durable spool independently.
    match lane
        .spool
        .put_ack(&pending.reference, &receipt, lane.protocol_bundle.bundle())?
    {
        AckPutOutcomeV1::Committed { .. } => {
            observability.committed();
            eprintln!(
                "OCOMP snapshot exporter committed finalized input for {job_id} using {bundle_hash}"
            );
        }
        AckPutOutcomeV1::Retired => {
            observability.late_ack_ignored();
            eprintln!(
                "OCOMP snapshot exporter ignored a late commit for retired job {job_id} using {bundle_hash}"
            );
        }
    }
    Ok(())
}

async fn run_snapshot_exporter_reconciler(
    lanes: BTreeMap<B256, SnapshotExporterLaneControlV1>,
    mut completions: tokio::sync::mpsc::UnboundedReceiver<SnapshotExporterCompletionV1>,
    observability: Arc<SnapshotExporterObservabilityServerV1>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wake = tokio::time::interval(EXPORTER_RECONCILE_INTERVAL);
    wake.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing_lanes = BTreeSet::new();
    loop {
        tokio::select! {
            _ = wake.tick() => {
                observability.begin_reconcile();
                for (bundle_hash, lane) in &lanes {
                    match lane.trigger.try_send(()) {
                        Ok(()) | Err(mpsc::TrySendError::Full(())) => {}
                        Err(mpsc::TrySendError::Disconnected(())) => {
                            return Err(runtime_error(format!(
                                "snapshot exporter lane {bundle_hash} exited"
                            )));
                        }
                    }
                }
            }
            completion = completions.recv() => {
                let completion = completion.ok_or_else(|| {
                    runtime_error("all snapshot exporter lane workers exited")
                })?;
                match completion {
                    SnapshotExporterCompletionV1::Failed {
                        bundle_hash,
                        observation_id,
                        detail,
                    } => {
                        observability.discovery_error(detail.clone());
                        eprintln!(
                            "OCOMP snapshot exporter lane {bundle_hash} failed for {observation_id:?}: {detail}"
                        );
                    }
                    SnapshotExporterCompletionV1::Cycle { bundle_hash, failed } => {
                        if failed {
                            failing_lanes.insert(bundle_hash);
                        } else {
                            failing_lanes.remove(&bundle_hash);
                        }
                        let pending = pending_discovery_count(&lanes).unwrap_or(1);
                        if failing_lanes.is_empty() {
                            observability.reconcile_succeeded(pending);
                        } else {
                            observability.reconcile_failed(pending);
                        }
                    }
                }
            }
        }
    }
}

fn pending_discovery_count(
    lanes: &BTreeMap<B256, SnapshotExporterLaneControlV1>,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut count = 0_u64;
    for lane in lanes.values() {
        count = count
            .checked_add(lane.spool.pending_count()?)
            .ok_or_else(|| runtime_error("discovery pending count overflow"))?;
    }
    Ok(count)
}

fn discovery_spool_path(root: &Path, protocol_bundle_hash: B256) -> PathBuf {
    root.join(hex::encode(protocol_bundle_hash.as_slice()))
}

fn runtime_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(message.into()).into()
}

fn required_protocol_bundle_hashes() -> Result<Vec<B256>, Box<dyn std::error::Error>> {
    let encoded = env::var(PROTOCOL_BUNDLE_HASHES_ENV)
        .or_else(|_| env::var("OCOMP_PROTOCOL_BUNDLE_HASH"))
        .map_err(|_| {
            format!("required environment variable {PROTOCOL_BUNDLE_HASHES_ENV} is missing")
        })?;
    let mut unique = BTreeSet::new();
    for item in encoded.split(',') {
        if item.is_empty() || item.trim() != item {
            return Err("OCOMP protocol bundle hash list is not canonical".into());
        }
        unique.insert(item.parse::<B256>()?);
    }
    if unique.is_empty() || unique.len() > 2 || unique.iter().any(B256::is_zero) {
        return Err(
            "OCOMP protocol bundle hash list must contain one or two non-zero hashes".into(),
        );
    }
    Ok(unique.into_iter().collect())
}

fn protocol_bundle_path_for_hash(
    runtime: &RuntimeProfile,
    protocol_bundle_hash: B256,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let catalog_path = runtime.protocol_bundle_catalog.join(format!(
        "{}.ocb1",
        hex::encode(protocol_bundle_hash.as_slice())
    ));
    if catalog_path.is_file() {
        return Ok(catalog_path);
    }
    if runtime.protocol_bundle_path.is_file() {
        return Ok(runtime.protocol_bundle_path.clone());
    }
    Err(format!("OCOMP protocol bundle {protocol_bundle_hash} is not installed").into())
}

fn retry_snapshot_exporter_startup<T, E>(
    mut open: impl FnMut() -> Result<T, E>,
    retryable: impl Fn(&E) -> bool,
    mut on_retry: impl FnMut(&E),
) -> Result<T, E> {
    loop {
        match open() {
            Ok(value) => return Ok(value),
            Err(error) if retryable(&error) => on_retry(&error),
            Err(error) => return Err(error),
        }
    }
}

fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("required environment variable {name} is missing").into())
}

fn install_consensus_domain(chain_id: u64) -> Result<(), Box<dyn std::error::Error>> {
    init_consensus_chain_id(chain_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn snapshot_exporter_startup_retries_only_retryable_failures() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum StartupError {
            Busy,
            Fatal,
        }

        let mut attempts = 0_u8;
        let mut retries = 0_u8;
        let opened = retry_snapshot_exporter_startup(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(StartupError::Busy)
                } else {
                    Ok(0xA5_u8)
                }
            },
            |error| *error == StartupError::Busy,
            |_| retries += 1,
        )
        .unwrap();
        assert_eq!(opened, 0xA5);
        assert_eq!(attempts, 3);
        assert_eq!(retries, 2);

        let mut fatal_attempts = 0_u8;
        assert_eq!(
            retry_snapshot_exporter_startup(
                || {
                    fatal_attempts += 1;
                    Err::<(), _>(StartupError::Fatal)
                },
                |error| *error == StartupError::Busy,
                |_| panic!("fatal startup errors cannot enter the retry loop"),
            ),
            Err(StartupError::Fatal)
        );
        assert_eq!(fatal_attempts, 1);
    }

    #[test]
    fn removed_uid_cli_options_are_rejected() {
        assert!(Cli::try_parse_from([
            "outbe-ocomp",
            "supervisor",
            "--expected-effective-user",
            "attacker"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "outbe-ocomp",
            "worker",
            "--expected-effective-user",
            "attacker",
            "--expected-supervisor-user",
            "attacker",
            "--chain-id",
            "1",
            "--genesis-hash",
            HASH,
            "--boot-nonce",
            HASH,
            "--protocol-bundle-hash",
            HASH,
            "--session-generation",
            "1",
            "--cas-root",
            "/tmp/attacker-cas",
            "--cas-max-object-bytes",
            "1",
            "--cas-max-total-bytes",
            "1",
            "--connection-fd",
            "9",
        ])
        .is_err());
    }

    #[test]
    fn operational_subcommands_are_limited_to_external_roles() {
        assert!(Cli::try_parse_from(["outbe-ocomp", "supervisor"]).is_err());
    }

    #[test]
    fn development_profile_is_rooted_and_does_not_relax_release_defaults() {
        let root = tempfile::tempdir().unwrap();
        let args = RuntimeArgs {
            development_root: Some(root.path().to_path_buf()),
            supervisor_address: "127.0.0.1:30401".parse().unwrap(),
        };
        let resolved = RuntimeProfile::resolve(&args);
        #[cfg(debug_assertions)]
        {
            let profile = resolved.expect("debug builds accept an explicit development root");
            assert_eq!(profile.owner_uid, effective_uid().unwrap());
            assert!(profile.cas_root.starts_with(root.path()));
            assert!(profile.protocol_bundle_path.starts_with(root.path()));
        }
        #[cfg(not(debug_assertions))]
        {
            let error = match resolved {
                Ok(_) => panic!("release builds must reject --development-root"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("unavailable in release outbe-ocomp builds"));
        }

        let relative = RuntimeArgs {
            development_root: Some(PathBuf::from("relative-domain")),
            supervisor_address: "127.0.0.1:30401".parse().unwrap(),
        };
        assert!(RuntimeProfile::resolve(&relative).is_err());
    }

    #[test]
    fn worker_ordinals_derive_four_distinct_process_nonces() {
        let host_boot_nonce = B256::repeat_byte(0x44);
        let nonces = (0_u8..4)
            .map(|ordinal| worker_process_nonce(host_boot_nonce, ordinal).unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(nonces.len(), 4);
        assert!(worker_process_nonce(host_boot_nonce, 4).is_err());
    }

    #[test]
    fn worker_observability_ports_follow_the_worker_ordinal() {
        let supervisor = "127.0.0.1:30401".parse().unwrap();
        assert_eq!(
            worker_observability_address(supervisor, 0).unwrap(),
            "127.0.0.1:30403".parse().unwrap()
        );
        assert_eq!(
            worker_observability_address(supervisor, 3).unwrap(),
            "127.0.0.1:30406".parse().unwrap()
        );
        assert!(worker_observability_address(supervisor, 4).is_err());
        assert_eq!(
            snapshot_exporter_observability_address(supervisor).unwrap(),
            "127.0.0.1:30413".parse().unwrap()
        );
    }

    #[test]
    fn production_layout_is_isolated_under_the_selected_validator_directory() {
        let base = tempfile::tempdir().unwrap();
        let config = ProductionConfig::from_lookup(|name| match name {
            "OUTBE_OCOMP_BASE_PATH" => Some(base.path().as_os_str().to_owned()),
            "OCOMP_VALIDATOR_INDEX" => Some("7".into()),
            _ => None,
        })
        .unwrap();
        let layout =
            ProductionLayout::from_base(&config.base_path, config.validator_index).unwrap();
        let domain = base
            .path()
            .join("validator-7")
            .join("ocomp")
            .join("domain-v1");

        assert_eq!(
            layout.protocol_bundle_path,
            domain.join("protocol-bundle-v1.ocb1")
        );
        assert_eq!(layout.ocomp_evm_key_path, domain.join("ocomp-evm-key.hex"));
        assert_eq!(
            layout.snapshot_exporter_journal_root,
            domain.join("exporter-v1").join("discovery")
        );
        assert_eq!(
            discovery_spool_path(
                &layout.snapshot_exporter_journal_root,
                B256::repeat_byte(0xAB)
            ),
            domain
                .join("exporter-v1")
                .join("discovery")
                .join("ab".repeat(32))
        );
    }

    #[test]
    fn production_config_requires_explicit_base_path_and_validator_index() {
        let base = tempfile::tempdir().unwrap();
        assert!(ProductionConfig::from_lookup(|_| None).is_err());
        assert!(ProductionConfig::from_lookup(|name| {
            (name == "OUTBE_OCOMP_BASE_PATH").then(|| base.path().as_os_str().to_owned())
        })
        .is_err());
        assert!(ProductionLayout::from_base(std::path::Path::new("/"), 0).is_err());
        assert!(ProductionLayout::from_base(std::path::Path::new("relative"), 0).is_err());
    }

    #[test]
    fn process_consensus_domain_is_bound_to_the_role_chain() {
        const ROLE_CHAIN_ID: u64 = 42;

        install_consensus_domain(ROLE_CHAIN_ID).unwrap();

        assert_eq!(consensus_chain_id(), ROLE_CHAIN_ID);
        assert_eq!(
            outbe_consensus::config::outbe_app_namespace(),
            [b"outbe".as_slice(), ROLE_CHAIN_ID.to_be_bytes().as_slice()].concat()
        );
    }
}
