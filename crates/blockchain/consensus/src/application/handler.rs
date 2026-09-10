//! Application handler - processes messages from the Automaton/Relay side.
//!
//! This is the "server side" that reads from the mpsc channel populated by
//! [`OutbeApplication`](super::actor::OutbeApplication). It bridges Simplex
//! consensus with Reth's execution layer via `beacon_engine_handle` and
//! `payload_builder_handle`.
//!
//! Block availability uses Commonware's marshal actor:
//! - Proposer disseminates blocks via `buffered::Engine` (broadcast)
//! - Non-proposers resolve blocks via `marshal::resolver` (on-demand P2P)
//! - No ad-hoc block propagation channel or local cache admission

use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::PayloadId;
use outbe_primitives::runtime_audit_v1::{
    process_instance_id, PROPOSAL_VIEW_CANCELLED, SCHEMA_VERSION,
};

// Marshal block-resolution timing constants (FINALIZE_*, VERIFY_RESOLUTION_TIMEOUT,
// PROPOSE_RESOLUTION_TIMEOUT) moved to `crate::config` - they are read cross-module
// by the finalization actor, verify, and epoch-boundary resolution paths.
use crate::config::{PROPOSE_RESOLUTION_TIMEOUT, VERIFY_RESOLUTION_TIMEOUT};

/// Delay between Engine API retries while execution reports temporary SYNCING.
pub(crate) const VERIFY_SYNCING_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Log-rate window for repeated critical proposal failures.
pub(crate) const PROPOSAL_FAILURE_LOG_WINDOW: Duration = Duration::from_secs(5);
/// epoch boundary: bounded wait inside `handle_genesis` for the
/// finalization view to expose a continuity anchor for the new epoch.
///
/// If Commonware Simplex queries `Automaton::genesis(epoch>0)` faster than the
/// finalization actor publishes the boundary block's anchor into
/// `FinalizationView`, we wait up to this deadline before declaring the
/// terminal failure path. The companion `stack.rs` pre-restart guard should
/// normally make sure this never trips in practice.
pub(crate) const GENESIS_ANCHOR_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval used by the bounded waits in `handle_genesis` and the
/// `stack.rs` pre-restart preconditions.
pub(crate) const GENESIS_ANCHOR_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Explicit source of proposer wall-clock time.
///
/// Production injects [`SystemUnixTimeSource`]. Localnet tests may inject an
/// [`OffsetUnixTimeSource`] through the explicitly testnet-scoped CLI option;
/// consensus code never consults ambient process environment for logical time.
pub trait UnixTimeSource: Send + Sync {
    fn now_millis(&self) -> eyre::Result<u64>;
}

#[derive(Debug, Default)]
pub struct SystemUnixTimeSource;

impl UnixTimeSource for SystemUnixTimeSource {
    fn now_millis(&self) -> eyre::Result<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| eyre::eyre!("system clock before UNIX_EPOCH: {e}"))?
            .as_millis()
            .try_into()
            .map_err(|_| eyre::eyre!("system clock millis does not fit in u64"))
    }
}

#[derive(Debug)]
pub struct OffsetUnixTimeSource {
    base: SystemUnixTimeSource,
    offset_secs: i64,
}

impl OffsetUnixTimeSource {
    #[must_use]
    pub const fn new(offset_secs: i64) -> Self {
        Self {
            base: SystemUnixTimeSource,
            offset_secs,
        }
    }
}

impl UnixTimeSource for OffsetUnixTimeSource {
    fn now_millis(&self) -> eyre::Result<u64> {
        apply_unix_time_offset_millis(self.base.now_millis()?, self.offset_secs)
    }
}

fn apply_unix_time_offset_millis(now: u64, offset_secs: i64) -> eyre::Result<u64> {
    let shifted = i128::from(now) + i128::from(offset_secs) * 1_000;
    u64::try_from(shifted)
        .map_err(|_| eyre::eyre!("Unix time offset {offset_secs} moves timestamp outside u64"))
}

/// Clamp a proposer's block timestamp (ms) into the deterministic drift band
/// `[parent + min_advance, parent + band]`, with the genesis-child exception.
///
/// When `parent_timestamp_millis == 0` there is no finalized parent yet (the
/// `finalization_view` is unseeded at genesis - it does NOT carry the genesis
/// header timestamp), so the band is meaningless: capping at `0 + band` would
/// clamp the real wall-clock time far below the genesis timestamp and reth
/// would reject the payload as a past timestamp, stalling at block 0. In that
/// case only monotonicity is enforced (`max(now, parent + 1)`), mirroring the
/// validator-side genesis exemption (`parent.number() == 0`). For every real
/// parent the full two-sided band applies, mirroring the validator-side
/// `validate_against_parent_timestamp_millis`:
/// - lower bound `parent + min_advance`: if the proposer's clock has not
///   advanced `min_advance` past the parent, the timestamp is clamped *up* so
///   the block still satisfies the validator minimum-advance rule and is never
///   rejected; this is what denies a colluding leader majority the
///   `parent + 1 ms` timestamp freeze.
/// - upper bound `parent + band` (C-01): an honest proposer never emits an
///   over-drifted block, and a long stall self-heals by ratcheting forward at
///   most one band per block.
fn clamp_proposed_timestamp_millis(
    parent_timestamp_millis: u64,
    now_millis: u64,
    band_millis: u64,
    min_advance_millis: u64,
) -> u64 {
    if parent_timestamp_millis == 0 {
        return std::cmp::max(now_millis, parent_timestamp_millis.saturating_add(1));
    }
    let min_timestamp_millis = parent_timestamp_millis.saturating_add(min_advance_millis);
    let max_timestamp_millis = parent_timestamp_millis.saturating_add(band_millis);
    std::cmp::max(now_millis, min_timestamp_millis).min(max_timestamp_millis)
}

/// Derive the proposal timestamp from the exact resolved parent block.
///
/// A missing parent is the existing genesis-child case. For every later block,
/// the parent header is the sole source of the timestamp band: process-local
/// observations from earlier build attempts cannot move it.
fn proposal_timestamp_millis(
    parent_block: Option<&ConsensusBlock>,
    now_millis: u64,
    band_millis: u64,
    min_advance_millis: u64,
) -> u64 {
    let parent_timestamp_millis = parent_block.map_or(0, ConsensusBlock::timestamp_millis);
    clamp_proposed_timestamp_millis(
        parent_timestamp_millis,
        now_millis,
        band_millis,
        min_advance_millis,
    )
}

fn finalized_parent_attestation_from_phase1_system_tx(
    block: &ConsensusBlock,
) -> eyre::Result<Option<FinalizedParentAttestation>> {
    if block.number() < 2 {
        return Ok(None);
    }

    let raw_block = block.clone().into_inner().into_block();
    let layout = outbe_primitives::system_tx::split_system_layout(&raw_block.body.transactions)
        .map_err(|error| {
            eyre::eyre!("invalid system tx layout while extracting Phase 1: {error}")
        })?;
    let phase1 = *layout.begin.first().ok_or_else(|| {
        eyre::eyre!(
            "missing Phase 1 finalization system transaction for block {}",
            block.number()
        )
    })?;
    let input = outbe_primitives::system_tx::SystemTxInputV2::decode(phase1.input().as_ref())
        .map_err(|error| eyre::eyre!("decode Phase 1 system transaction input: {error}"))?;
    let outbe_primitives::system_tx::SystemTxInputV2::CertifiedParentAccounting { metadata } =
        input
    else {
        return Err(eyre::eyre!(
            "expected Phase 1 finalization system transaction at begin ordinal 0"
        ));
    };

    Ok(Some(FinalizedParentAttestation {
        finalized_block_number: metadata.finalized_block_number,
        finalized_block_hash: metadata.finalized_block_hash,
        finalized_epoch: metadata.finalized_epoch,
        finalized_view: metadata.finalized_view,
        parent_view: metadata.parent_view,
        ordered_committee: metadata.ordered_committee,
        signer_bitmap: metadata.signer_bitmap,
        certificate: metadata.proof,
        // V2 `missed_proposers: Vec<MissedProposerEvent>` always
        // empty under the verifier rule; the V1 attestation surface
        // keeps the legacy `Vec<Address>` shape for backwards-compat callers.
        missed_proposers: metadata
            .missed_proposers
            .into_iter()
            .map(|ev| ev.validator)
            .collect(),
    }))
}

use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, Bytes, B256};
use commonware_consensus::types::{Height, Round, View};
use commonware_cryptography::{
    bls12381::{primitives::variant::MinSig, PublicKey},
    certificate::Provider as _,
};
use commonware_utils::channel::oneshot;
use futures::StreamExt;
use outbe_primitives::{
    addresses::REWARDS_ADDRESS,
    projection::{
        ExecutionReadBudget, ProjectionCheckpoint, ProjectionReadinessHandle, WaitOutcome,
    },
    reshare_artifact::{
        encode_outbe_block_artifacts, ConsensusHeaderArtifact, FinalizedParentAttestation,
        OutbeBlockArtifacts,
    },
    system_tx::OcompLifecycleActivation,
    OutbeExecutionData, OutbePayloadAttributes, OutbePayloadTypes,
};
use reth_node_builder::{BuiltPayload as _, ConsensusEngineHandle};
use reth_payload_builder::PayloadBuilderHandle;
use tracing::{debug, error, info, warn};

use crate::{
    ancestry_readiness::AncestryReadiness,
    block::ConsensusBlock,
    committee_provider::CommitteeProvider,
    digest::Digest,
    dkg_manager::{AncestryReader, BoundaryRequirement},
    executor,
    finalization::{
        block_cache::BlockCache,
        parent_cert_store::{CertifiedParentProofKey, CertifiedParentProofRecord},
        state::{FinalizationViewAccess, FinalizationViewHandle},
    },
    hybrid::{election::HybridElectorConfigProvider, HybridSchemeProvider},
    ocomp_retention::{after_durable_candidate, OcompRetentionHook},
    validators::ValidatorSet,
    vrf_safety::VrfSafetyGate,
};

use super::ingress::Message;

/// Type alias for engine types used in Outbe.
type EngineHandle = ConsensusEngineHandle<OutbePayloadTypes>;
type PayloadBuilder = PayloadBuilderHandle<OutbePayloadTypes>;

/// The application handler that processes consensus messages.
///
/// Reads from the mpsc channel and calls `beacon_engine_handle` / `payload_builder_handle`
/// to propose and verify blocks. Finalization side effects are owned by
/// `FinalizationActor`; this handler only observes the finalized view while
/// preparing proposals.
///
/// Block resolution uses marshal's digest-bound model:
/// - `handle_verify()` resolves blocks via `marshal_mailbox.subscribe_by_digest()`
/// - `FinalizationActor` resolves finalized blocks via marshal (or proposer's local cache)
/// - No separate block propagation channel or raw block admission path
///
// `ReplayClassification`, `classify_finalization`,
// `extract_consensus_metadata_from_block`,
// `extract_header_artifact_from_block`, `retry_with_backoff`,
// `RetryFailure`, and `RetryFailureKind` live in
// `crate::finalization::util` (relocated in step 17). After step 21 the
// application handler no longer runs the finalization side effects, so
// it only consumes the metadata + header-artifact extractors on the
// verify path.
use crate::finalization::util::extract_header_artifact_from_block;

use crate::application::epoch_boundary::{self, ApplicationEpochFence, EpochBoundaryParentError};
use crate::application::validation::{
    validate_context_parent_binding, validate_rewards_beneficiary,
    validate_system_tx_leader_binding_for_activation,
};
use crate::application::verify_resolution::{resolve_for_verify, VerifyResolveTarget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposeOutcome {
    Proposed(Digest),
    ParentProofUnavailable,
    EpochStale,
    BoundaryUnavailable,
    ProjectionUnavailable,
    RetentionUnavailable,
}

#[derive(Clone, Debug, Default)]
struct ProposalPayloadTrace {
    payload_id: Arc<std::sync::OnceLock<PayloadId>>,
}

impl ProposalPayloadTrace {
    fn record(&self, payload_id: PayloadId) {
        let _ = self.payload_id.set(payload_id);
    }

    fn payload_id(&self) -> Option<PayloadId> {
        self.payload_id.get().copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentProjectionGate {
    Ready,
    Withhold,
}

async fn wait_for_projected_parent<F>(
    readiness: ProjectionReadinessHandle,
    required: ProjectionCheckpoint,
    budget_expired: F,
) -> eyre::Result<ParentProjectionGate>
where
    F: std::future::Future<Output = ()>,
{
    match readiness.wait_for(required, budget_expired).await {
        WaitOutcome::Ready => Ok(ParentProjectionGate::Ready),
        WaitOutcome::BudgetExpired | WaitOutcome::ProjectionAhead => {
            Ok(ParentProjectionGate::Withhold)
        }
        WaitOutcome::Fatal(failure) => Err(eyre::eyre!(
            "projection readiness failed ({:?}): {}",
            failure.class,
            failure.message
        )),
    }
}

/// Pure min-block-time floor arithmetic: remaining pad = `min - elapsed`
/// (`saturating_sub`). A zero result means the floor is already met - send the
/// digest immediately with no wait (case C / heavy block).
fn floor_remaining(
    min_block_time: std::time::Duration,
    elapsed: std::time::Duration,
) -> std::time::Duration {
    min_block_time.saturating_sub(elapsed)
}

/// Proposer-side minimum block-time pacing.
///
/// Holds the already-sealed `digest` until the floor (`min_block_time`) elapses,
/// then hands it to Simplex via `response`. If the view is cancelled first
/// (Simplex drops the proposal receiver), the `select!` aborts on
/// `response.closed()` and nothing is sent. Liveness pacing only - it never
/// touches block bytes/hash/validation, so it is invisible to validators.
///
/// `propose_start` is the closure-level instant captured before `handle_propose`;
/// `elapsed` therefore subsumes the whole build + marshal path, making the floor
/// a total ceiling (`max(floor, build)`), not an additive delay.
async fn pace_and_send<C>(
    ctx: &C,
    mut response: oneshot::Sender<Digest>,
    digest: Digest,
    min_block_time: std::time::Duration,
    propose_start: std::time::SystemTime,
) where
    C: commonware_runtime::Clock,
{
    let elapsed = ctx
        .current()
        .duration_since(propose_start)
        .unwrap_or_default();
    let remaining = floor_remaining(min_block_time, elapsed);
    crate::metrics::record_block_build_time(elapsed);
    crate::metrics::record_block_wait_time(remaining);
    if remaining.is_zero() {
        // Case C (elapsed >= min): send now, control-flow identical to pre-pacing.
        let _ = response.send(digest);
    } else {
        // Biased select!: cancellation wins over a near-simultaneous sleep
        // completion, so we never send into a closed channel.
        commonware_macros::select! {
            () = response.closed() => {
                debug!("view cancelled during min-block-time pacing; dropping proposal");
            },
            _ = ctx.sleep(remaining) => {
                let _ = response.send(digest);
            },
        }
    }
}

// `Built` carries the full `ConsensusBlock`; the other variants are unit. This is
// an internal result returned once per propose and consumed immediately - boxing
// the block would only add an allocation on the hot proposer path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum BuildBlockOutcome {
    Built(Digest, ConsensusBlock),
    ParentProofUnavailable,
    EpochStale,
    BoundaryUnavailable,
}

// Like `BuildBlockOutcome` above: an internal direct-parent proof lookup result,
// produced once per proposal in `select_parent_proof_for_proposal` and consumed
// immediately at the single match site. `Found` is the common case, so boxing the
// record would only add a heap allocation on the hot proposer path for no benefit.
#[allow(clippy::large_enum_variant)]
enum ParentProofLookup {
    NoProofNeeded,
    Found(CertifiedParentProofRecord),
    Unavailable,
}

pub struct ApplicationHandler {
    /// Receiver for messages from the Automaton/Relay side.
    rx: futures::channel::mpsc::Receiver<Message>,

    pub(crate) shared: ApplicationShared,
}

#[derive(Clone)]
pub(crate) struct ApplicationShared {
    /// Explicit proposer wall-clock source. Never derived from ambient env.
    unix_time_source: Arc<dyn UnixTimeSource>,

    /// Engine handle for new_payload / fork_choice_updated.
    engine: EngineHandle,

    /// Payload builder handle for building new blocks.
    payload_builder: PayloadBuilder,

    /// Executor mailbox for forwarding finalized blocks.
    executor_mailbox: executor::Mailbox,

    /// Genesis block hash (block 0).
    genesis_hash: B256,

    /// Current active validator set.
    #[allow(dead_code)]
    validators: ValidatorSet,

    /// Active EVM chain id used to rebuild deterministic system-tx envelopes
    /// during consensus prechecks before Engine status is trusted.
    chain_id: u64,

    /// Immutable chain-manifest activation used by the pre-Engine consensus
    /// system-transaction verifier. This must match the payload builder and
    /// execution configuration so every validator expects the same layout at H.
    ocomp_lifecycle_activation: OcompLifecycleActivation,

    /// Marshal mailbox for digest-bound block resolution.
    pub(crate) marshal_mailbox: crate::marshal_types::MarshalMailbox,

    /// Epoch-scoped verifier schemes for carried finalized-parent certificates.
    certificate_scheme_provider: HybridSchemeProvider<MinSig>,

    /// Epoch-scoped leader elector configs. removed the
    /// stateful verify-time elector use; kept on the surface for ctor
    /// stability with `stack.rs` and for the upcoming V2 verifier hook.
    #[allow(dead_code)]
    elector_config_provider: HybridElectorConfigProvider<MinSig>,

    /// Epoch-scoped ordered committee snapshots.
    committee_provider: CommitteeProvider,

    /// DKG artifact manager for boundary outcomes and dealer logs.
    dkg_manager: crate::dkg_manager::Mailbox,

    /// Fail-closed guard for VRF/DKG freshness.
    vrf_safety: VrfSafetyGate,

    /// DKG activation boundary guard shared with the stack epoch loop.
    epoch_fence: ApplicationEpochFence,

    /// Fast local readiness bit for startup/crash backfill. When false,
    /// ancestry checks fail before opening marshal subscriptions that would
    /// otherwise wait until timeout while the executor is replaying durable
    /// consensus blocks into Reth.
    ancestry_readiness: AncestryReadiness,

    /// Exact durable Mongo projection checkpoint used to gate every execution
    /// read of a consensus parent.
    projection_readiness: ProjectionReadinessHandle,

    /// Time to give the payload builder to execute transactions before resolving.
    payload_resolve_time: std::time::Duration,

    /// Proposer-side minimum block-time floor (liveness pacing only; never
    /// affects block contents or validation). Read in the `Message::Propose`
    /// closure via `shared.min_block_time`. Always > 0 (validated at startup).
    min_block_time: std::time::Duration,

    /// Proposer EVM identity used to sign system transaction artifacts.
    proposer_evm_address: Option<Address>,

    /// Rate limiter for repeated critical proposal failure logs.
    proposal_failure_log_limiter: Arc<crate::util::rate_limit::LogRateLimiter>,

    /// Shared canonical view of the last finalization (forkchoice,
    /// `last_finalized_*`, `prev_randao`, monotonic clock floor).
    /// Written by the FinalizationActor; read here for `build_block`.
    finalization_view: FinalizationViewHandle,

    /// Shared block cache: proposer inserts on local build, the
    /// FinalizationActor evicts entries below the new finalized height.
    block_cache: BlockCache,

    /// Proposer-side exact-parent certificate selector.
    ///
    /// It waits for the finalized-parent certificate record matching the
    /// Simplex context parent, then carries the metadata in the Phase 1
    /// begin-zone system transaction rather than in `header.extra_data`.
    finalization_selector: crate::finalization::selection::ParentProofSelector,

    /// Disaster-recovery flag (`--testnet.trust-el-head`). When true and
    /// `FinalizationView` has a non-zero execution head, `handle_genesis`
    /// uses the execution head as the Simplex anchor instead of the chain
    /// genesis hash. This allows blocks to resume from the existing
    /// execution state after a force-DKG restart.
    trust_el_head: bool,

    /// shared late-finalize signature store. On proposal the
    /// handler reads it (`build_artifact`) to pack the in-window
    /// `LateFinalizeCreditsArtifact` into `header.extra_data`. The reporter
    /// writes votes into it and the `FinalizationActor` resolves them. Best-
    /// effort, process-local - the resulting artifact is re-verified by every
    /// validator, so it never affects determinism.
    late_sig_store: crate::finalization::late_sig_store::SharedLateFinalizeStore,

    /// Node-local durable OCOMP candidate retention. It may forfeit this
    /// validator's proposal/vote but never changes block validity.
    ocomp_retention: Arc<dyn OcompRetentionHook>,
}

/// Named dependencies for [`ApplicationHandler::new`].
///
/// Replaces a 25-positional-argument constructor (mirrors `FinalizationActorDeps`,
/// used a few lines later in `stack.rs`), so the single production caller and the
/// test fixtures cannot transpose arguments - the wiring order lives in the type
/// system rather than in a call-site convention.
pub struct ApplicationDeps {
    pub unix_time_source: Arc<dyn UnixTimeSource>,
    pub rx: futures::channel::mpsc::Receiver<Message>,
    pub engine: EngineHandle,
    pub payload_builder: PayloadBuilder,
    pub executor_mailbox: executor::Mailbox,
    pub genesis_hash: B256,
    pub validators: ValidatorSet,
    pub chain_id: u64,
    pub ocomp_lifecycle_activation: OcompLifecycleActivation,
    pub marshal_mailbox: crate::marshal_types::MarshalMailbox,
    pub certificate_scheme_provider: HybridSchemeProvider<MinSig>,
    pub elector_config_provider: HybridElectorConfigProvider<MinSig>,
    pub committee_provider: CommitteeProvider,
    pub dkg_manager: crate::dkg_manager::Mailbox,
    pub vrf_safety: VrfSafetyGate,
    pub epoch_fence: ApplicationEpochFence,
    pub ancestry_readiness: AncestryReadiness,
    pub projection_readiness: ProjectionReadinessHandle,
    pub finalization_view: FinalizationViewHandle,
    pub block_cache: BlockCache,
    pub finalization_selector: crate::finalization::selection::ParentProofSelector,
    pub payload_resolve_time: std::time::Duration,
    pub min_block_time: std::time::Duration,
    pub proposer_evm_address: Option<Address>,
    pub trust_el_head: bool,
    pub late_sig_store: crate::finalization::late_sig_store::SharedLateFinalizeStore,
    pub ocomp_retention: Arc<dyn OcompRetentionHook>,
}

impl ApplicationHandler {
    /// Create a new handler.
    ///
    /// The application no longer owns a private finalization view copy.
    /// Forkchoice / last-finalized / prev-randao / monotonic-clock-floor
    /// state lives in the shared [`FinalizationViewHandle`], written by
    /// the `FinalizationActor` and read here under a short-lived guard.
    /// Recovery is performed by `new_finalization_view(...)` at the call
    /// site (`stack.rs`); this constructor takes the already-initialized
    /// handle.
    pub fn new(deps: ApplicationDeps) -> Self {
        let ApplicationDeps {
            unix_time_source,
            rx,
            engine,
            payload_builder,
            executor_mailbox,
            genesis_hash,
            validators,
            chain_id,
            ocomp_lifecycle_activation,
            marshal_mailbox,
            certificate_scheme_provider,
            elector_config_provider,
            committee_provider,
            dkg_manager,
            vrf_safety,
            epoch_fence,
            ancestry_readiness,
            projection_readiness,
            finalization_view,
            block_cache,
            finalization_selector,
            payload_resolve_time,
            min_block_time,
            proposer_evm_address,
            trust_el_head,
            late_sig_store,
            ocomp_retention,
        } = deps;
        Self {
            rx,
            shared: ApplicationShared {
                unix_time_source,
                engine,
                payload_builder,
                executor_mailbox,
                genesis_hash,
                validators,
                chain_id,
                ocomp_lifecycle_activation,
                marshal_mailbox,
                certificate_scheme_provider,
                elector_config_provider,
                committee_provider,
                dkg_manager,
                vrf_safety,
                epoch_fence,
                ancestry_readiness,
                projection_readiness,
                payload_resolve_time,
                min_block_time,
                proposer_evm_address,
                proposal_failure_log_limiter: Arc::new(
                    crate::util::rate_limit::LogRateLimiter::new(PROPOSAL_FAILURE_LOG_WINDOW),
                ),
                finalization_view,
                block_cache,
                finalization_selector,
                trust_el_head,
                late_sig_store,
                ocomp_retention,
            },
        }
    }

    /// Run the handler event loop.
    pub async fn run<E>(mut self, context: E) -> eyre::Result<()>
    where
        E: commonware_runtime::Metrics
            + commonware_runtime::Spawner
            + commonware_runtime::Clock
            + Send
            + Sync
            + 'static,
    {
        info!("application handler started");

        // Step 21: the per-finalization side effects no longer run in
        // this handler. Finalization events flow voter -> OutbeReporter ->
        // FinalizationActor (via the unbounded
        // `finalization::ingress::Mailbox`); the application handler's
        // mailbox handles only Genesis / Propose / Verify / Broadcast.
        loop {
            let msg = match self.rx.next().await {
                Some(m) => m,
                None => {
                    info!("application handler mailbox closed, exiting");
                    return Ok(());
                }
            };
            match msg {
                Message::Genesis(genesis) => {
                    context.child("genesis").spawn({
                        let shared = self.shared.clone();
                        move |ctx| async move {
                            shared.handle_genesis(&ctx, genesis).await;
                        }
                    });
                }
                Message::Propose(propose) => {
                    context.child("propose").spawn({
                        let shared = self.shared.clone();
                        move |ctx| async move {
                            let propose = *propose;
                            let mut response = propose.response;
                            let execution_read_budget = ExecutionReadBudget::new();
                            let payload_trace = ProposalPayloadTrace::default();
                            // Closure-level instant covering the whole build + marshal path,
                            // used only for proposer-side min-block-time pacing.
                            let propose_start = ctx.current();
                            let handle = Box::pin(shared.handle_propose(
                                &ctx,
                                propose.context,
                                propose_start,
                                execution_read_budget.clone(),
                                payload_trace.clone(),
                            ));
                            let cancelled = Box::pin(response.closed());
                            let outcome = match futures::future::select(handle, cancelled).await {
                                futures::future::Either::Left((outcome, _)) => outcome,
                                futures::future::Either::Right(((), _)) => {
                                    execution_read_budget.cancel();
                                    if let Some(payload_id) = payload_trace.payload_id() {
                                        debug!(
                                            audit_schema = SCHEMA_VERSION,
                                            audit_event = %PROPOSAL_VIEW_CANCELLED,
                                            process_instance = %process_instance_id(),
                                            %payload_id,
                                            "view cancelled during proposal execution"
                                        );
                                    } else {
                                        debug!(
                                            payload_id = "unassigned",
                                            "view cancelled during proposal execution"
                                        );
                                    }
                                    return;
                                }
                            };
                            match outcome {
                                Ok(ProposeOutcome::Proposed(digest)) => {
                                    // Proposer-side liveness pacing only: hold the already-sealed
                                    // digest until the min-block-time floor elapses, then hand it
                                    // to Simplex (or abort if the view is cancelled first). Never
                                    // touches block bytes/hash/validation.
                                    pace_and_send(
                                        &ctx,
                                        response,
                                        digest,
                                        shared.min_block_time,
                                        propose_start,
                                    )
                                    .await;
                                }
                                Ok(ProposeOutcome::ParentProofUnavailable) => {
                                    debug!(
                                        "proposal task completed without response: exact parent proof unavailable"
                                    );
                                }
                                Ok(ProposeOutcome::EpochStale) => {
                                    debug!(
                                        "proposal task completed without response for stale epoch work"
                                    );
                                }
                                Ok(ProposeOutcome::BoundaryUnavailable) => {
                                    debug!(
                                        "proposal task completed without response: DKG boundary requirement unavailable"
                                    );
                                }
                                Ok(ProposeOutcome::ProjectionUnavailable) => {
                                    debug!(
                                        "proposal task completed without response: exact parent is not projected"
                                    );
                                }
                                Ok(ProposeOutcome::RetentionUnavailable) => {
                                    debug!(
                                        "proposal task completed without response: OCOMP tentative pin is not durable"
                                    );
                                }
                                Err(error) => {
                                    if let Some(suppressed_since_last) =
                                        shared.proposal_failure_log_limiter.check()
                                    {
                                        tracing::error!(
                                            %error,
                                            suppressed_since_last,
                                            "critical proposal failure; stopping proposal task"
                                        );
                                    }
                                }
                            }
                        }
                    });
                }
                Message::Verify(verify) => {
                    context.child("verify").spawn({
                        let shared = self.shared.clone();
                        move |ctx| async move {
                            let verify = *verify;
                            let response = verify.response;
                            let execution_read_budget = ExecutionReadBudget::new();
                            match shared
                                .handle_verify(
                                    &ctx,
                                    verify.context,
                                    verify.payload,
                                    response,
                                    execution_read_budget,
                                )
                                .await
                            {
                                Ok(()) => {}
                                Err(error) => {
                                    info!(
                                        %error,
                                        "could not decide proposal validity; dropping verify response channel"
                                    );
                                }
                            }
                        }
                    });
                }
            }
        }
    }
}

/// Outcome of a `new_payload` execution validation with SYNCING retry. The single
/// source of truth for how a verify path classifies execution status, so the
/// parent and block validations can never drift in their SYNCING/retry policy.
enum PayloadVerification {
    /// Execution accepted the payload. `saw_syncing` is true if SYNCING was
    /// observed before acceptance - in that case the verify request may have been
    /// superseded by a view timeout, so the caller skips its side effects.
    Valid { saw_syncing: bool },
    /// Execution rejected the payload; the caller votes `false`.
    Invalid,
    /// The single-shot verify response channel closed while waiting; the caller
    /// returns without side effects.
    ChannelClosed,
}

#[derive(Debug, thiserror::Error)]
enum BuiltCandidatePreparationError {
    #[error("locally built payload was not accepted by execution: {0}")]
    Execution(String),
    #[error("node-local OCOMP retention is unavailable: {0}")]
    Retention(#[from] crate::ocomp_retention::OcompRetentionHookError),
}

/// Import a locally built candidate into Reth before its retention source reads
/// receipts and exact post-state by block hash.
async fn prepare_built_candidate(
    engine: &EngineHandle,
    retention: &dyn OcompRetentionHook,
    block: &ConsensusBlock,
    execution_read_budget: ExecutionReadBudget,
) -> Result<(), BuiltCandidatePreparationError> {
    let execution_data = OutbeExecutionData::new(std::sync::Arc::new(block.clone().into_inner()))
        .with_execution_read_budget(execution_read_budget);
    let status = engine
        .new_payload(execution_data)
        .await
        .map_err(|error| BuiltCandidatePreparationError::Execution(error.to_string()))?;
    if !status.is_valid() {
        return Err(BuiltCandidatePreparationError::Execution(format!(
            "{status:?}"
        )));
    }
    retention.prepare_candidate(block)?;
    Ok(())
}

impl ApplicationShared {
    /// Handle genesis request - return the parent digest for `view = 1` of
    /// `genesis.epoch`.
    ///
    /// ** epoch continuity:**
    /// - `epoch == 0` - return the chain genesis hash, as before.
    /// - `epoch > 0` - return the last finalized block's hash from
    ///   `FinalizationView`. That value is the *continuity anchor*: the
    ///   first block produced in the new epoch must extend it.
    ///
    /// Commonware Simplex caches the value returned here as the parent of
    /// `view = 1` for the duration of the engine instance. Returning a stale
    /// or default value (e.g. `B256::ZERO`) would permanently lock the
    /// engine on a non-existent parent and cause every proposal to be
    /// rejected. To avoid that:
    ///   1. We bound-wait up to `GENESIS_ANCHOR_WAIT_TIMEOUT` for the
    ///      finalization view to publish the anchor.
    ///   2. The `stack.rs` pre-restart guard ensures the anchor is already
    ///      present before `engine.start(...)` runs, so the wait below
    ///      should resolve immediately in steady-state operation.
    ///   3. If the wait expires we log `error!` and respond with
    ///      `B256::ZERO` as a terminal-failure signal. The node operator
    ///      is expected to investigate; the bounded wait keeps the
    ///      handler responsive instead of stalling Simplex indefinitely.
    async fn handle_genesis(
        &self,
        clock: &impl commonware_runtime::Clock,
        genesis: super::ingress::Genesis,
    ) {
        debug!(epoch = %genesis.epoch, "genesis requested");
        let epoch = genesis.epoch;
        if epoch.get() == 0 {
            if self.trust_el_head {
                let anchor = self.finalization_view.finalized_anchor();
                if anchor.number > 0 && anchor.finalized_head_hash != B256::ZERO {
                    debug!(
                        finalized_number = anchor.number,
                        finalized_hash = %anchor.finalized_head_hash,
                        "handle_genesis(epoch=0): using execution head as anchor (--testnet.trust-el-head)"
                    );
                    let _ = genesis.response.send(Digest(anchor.finalized_head_hash));
                    return;
                }
            }
            let _ = genesis.response.send(Digest(self.genesis_hash));
            return;
        }

        // Bounded wait driven by the runtime clock so the deadline and the poll
        // sleep below share one time source (works on both the tokio and the
        // deterministic runtimes; no wall-clock on the consensus path).
        let deadline = clock.current() + GENESIS_ANCHOR_WAIT_TIMEOUT;
        loop {
            let anchor = self.finalization_view.finalized_anchor();
            let (height, hash) = (anchor.number, anchor.finalized_head_hash);
            if height > 0 && hash != B256::ZERO {
                debug!(
                    %epoch,
                    finalized_number = height,
                    finalized_hash = %hash,
                    "handle_genesis: continuity anchor"
                );
                let _ = genesis.response.send(Digest(hash));
                return;
            }
            if clock.current() >= deadline {
                error!(
                    %epoch,
                    timeout_ms = GENESIS_ANCHOR_WAIT_TIMEOUT.as_millis(),
                    "handle_genesis: epoch>0 without finalized continuity anchor after timeout; \
                     terminal failure - Simplex will lock parent_view=0 to B256::ZERO. \
                     Investigate why FinalizationView lacks last_finalized_number/hash; \
                     stack.rs pre-restart guard should have prevented this."
                );
                let _ = genesis.response.send(Digest(B256::ZERO));
                return;
            }
            clock.sleep(GENESIS_ANCHOR_POLL_INTERVAL).await;
        }
    }

    /// Handle propose request strict wait.
    ///
    /// 1. Resolve parent block (local cache or marshal)
    /// 2. Send parent to execution layer via new_payload (ensure Reth knows it)
    /// 3. Canonicalize parent as head (FCU)
    /// 4. Build next block
    async fn handle_propose(
        &self,
        clock: &(impl commonware_runtime::Clock + commonware_runtime::Supervisor),
        context: super::ingress::SimplexContext,
        propose_start: std::time::SystemTime,
        execution_read_budget: ExecutionReadBudget,
        payload_trace: ProposalPayloadTrace,
    ) -> eyre::Result<ProposeOutcome> {
        let (parent_view, parent) = context.parent;
        let parent_digest = Digest(parent.0);
        let round = context.round;
        debug!(%round, %parent_view, parent = %parent_digest.0, "propose requested");

        // epoch continuity: special-case the first proposal of a
        // new Simplex epoch (`epoch > 0`, `parent_view = 0`) before the chain
        // genesis path. `Ok(None)` means "not an epoch boundary"; caller falls
        // through to the chain genesis / cache / marshal-by-digest branches.
        let maybe_epoch_anchor = match epoch_boundary::resolve_epoch_boundary_parent(
            &self.finalization_view,
            &self.marshal_mailbox,
            clock,
            round,
            parent_view,
            parent_digest,
        )
        .await
        {
            Ok(opt) => opt,
            Err(error) => {
                warn!(
                    %round,
                    parent = %parent_digest.0,
                    %error,
                    "propose: epoch boundary parent resolution failed; forfeiting slot"
                );
                return Ok(ProposeOutcome::ParentProofUnavailable);
            }
        };
        debug_assert!(
            !(round.epoch().get() > 0
                && parent_view == View::new(0)
                && maybe_epoch_anchor.is_none()),
            "resolve_epoch_boundary_parent invariant: epoch>0 && parent_view=0 must \
             resolve to Some(EpochBoundaryParent) or return an explicit error"
        );

        let (parent_height, parent_block, parent_proof_key) =
            if let Some(anchor) = maybe_epoch_anchor {
                (anchor.height, Some(anchor.block), Some(anchor.proof_key))
            } else if parent_digest.0 == self.genesis_hash {
                (Height::zero(), None, None)
            } else {
                let cached_parent = self.block_cache.get_and_remove(&parent_digest);
                let parent_block = if let Some(block) = cached_parent {
                    block
                } else {
                    // Parent from another proposer - resolve via marshal.
                    let marshal = self.marshal_mailbox.clone();
                    let block_future = marshal.subscribe_by_digest(
                        parent_digest,
                        commonware_consensus::marshal::core::DigestFallback::FetchByRound {
                            round: parent_round(round, parent_view),
                        },
                    );
                    match clock
                        .timeout(PROPOSE_RESOLUTION_TIMEOUT, block_future)
                        .await
                    {
                        Ok(Ok(block)) => block,
                        Ok(Err(_)) => {
                            return Err(eyre::eyre!(
                                "failed to resolve parent block {} for proposal",
                                parent_digest.0
                            ));
                        }
                        Err(_) => {
                            return Err(eyre::eyre!(
                                "timed out resolving parent block {} for proposal",
                                parent_digest.0
                            ));
                        }
                    }
                };

                let parent_height = Height::new(parent_block.number());
                (
                    parent_height,
                    Some(parent_block),
                    Some(CertifiedParentProofKey::new(
                        parent_round(round, parent_view).epoch().get(),
                        parent_view.get(),
                        parent_digest.0,
                    )),
                )
            };

        let next_block_number = parent_height.get().saturating_add(1);
        if let Err(rejection) = self.epoch_fence.check(round, next_block_number) {
            debug!(
                %round,
                parent = %parent_digest.0,
                next_block_number,
                ?rejection,
                "dropping stale proposal before Engine API work"
            );
            return Ok(ProposeOutcome::EpochStale);
        }

        let required_parent = ProjectionCheckpoint {
            block_number: parent_height.get(),
            block_hash: parent_digest.0,
        };
        if wait_for_projected_parent(
            self.projection_readiness.clone(),
            required_parent,
            std::future::pending(),
        )
        .await?
            == ParentProjectionGate::Withhold
        {
            return Ok(ProposeOutcome::ProjectionUnavailable);
        }

        if let Some(parent_block) = parent_block.as_ref() {
            // Step 2: Send parent to execution layer via new_payload.
            let execution_data =
                OutbeExecutionData::new(std::sync::Arc::new(parent_block.clone().into_inner()))
                    .with_execution_read_budget(execution_read_budget.clone());

            if crate::test_faults::should_drop_new_payload_for_test(parent_height) {
                warn!(
                    height = %parent_height,
                    parent = %parent_digest.0,
                    "test-marshal-drop: skipping propose parent new_payload"
                );
            } else {
                match self.engine.new_payload(execution_data).await {
                    Ok(status) if status.is_valid() || status.is_syncing() => {
                        debug!(parent = %parent_digest.0, ?status, "parent verified by execution layer");
                    }
                    Ok(status) => {
                        return Err(eyre::eyre!(
                            "parent {} rejected by execution layer: {status:?}",
                            parent_digest.0
                        ));
                    }
                    Err(e) => {
                        return Err(eyre::eyre!(
                            "new_payload failed for parent {}: {e}",
                            parent_digest.0
                        ));
                    }
                }
            }

            self.finalization_view
                .advance_timestamp_floor(parent_block.timestamp_millis());
        }

        self.vrf_safety
            .ensure_block_allowed(next_block_number)
            .map_err(|error| eyre::eyre!("refusing proposal above VRF expiry: {error}"))?;

        // Steps 3+4: Canonicalize parent as head and build next block.
        // Uses FCU-based flow: canonicalize_and_build sends
        // FCU with payload attributes so the engine starts building a payload
        // on the correct canonical state with access to the txpool.
        let candidate_execution_budget = execution_read_budget.clone();
        match self
            .build_block(
                clock,
                round,
                parent_height,
                parent_digest,
                parent_block.clone(),
                parent_proof_key,
                propose_start,
                execution_read_budget,
                payload_trace,
            )
            .await
        {
            Ok(BuildBlockOutcome::Built(digest, block)) => {
                if let Err(error) = self
                    .prepare_built_candidate(&block, candidate_execution_budget)
                    .await
                {
                    warn!(
                        %round,
                        digest = %digest.0,
                        %error,
                        "withholding proposal because its execution-valid OCOMP source is not durable"
                    );
                    return Ok(ProposeOutcome::RetentionUnavailable);
                }
                // Cache the proposed block into marshal NOW, at propose time, so
                // the proposer can always SERVE it on demand (verifiers pull via
                // subscribe_by_digest) - independent of whether the later
                // `Relay::broadcast` wire-push succeeds. commonware 2026.5.0
                // split dissemination: `proposed` caches + stashes locally;
                // `forward` (driven from `Relay::broadcast`) does the wire-push.
                // Decoupling cache from push makes a dropped push recoverable via
                // pull instead of losing the view (bp-1).
                let durable = self.marshal_mailbox.proposed(round, block).await;
                if !durable {
                    // `proposed()` returns false only when the marshal actor's ack
                    // channel is closed - i.e. marshal is gone/shutting down. The
                    // block is then NOT durably cached (not servable on pull, not
                    // stashed for `forward`), so this proposal cannot be resolved by
                    // verifiers (bp-1 pull-recovery does not help - nothing to serve).
                    // Surface it loudly rather than silently treating the proposal as
                    // durable. A persistent marshal failure is the supervisor's
                    // concern: the marshal handle is monitored (SSA-8) and a dead
                    // marshal fails the node fast.
                    warn!(
                        %round,
                        digest = %digest.0,
                        "marshal did not acknowledge proposed block (mailbox closed); \
                         proposal is not durably cached"
                    );
                }
                Ok(ProposeOutcome::Proposed(digest))
            }
            Ok(BuildBlockOutcome::ParentProofUnavailable) => {
                Ok(ProposeOutcome::ParentProofUnavailable)
            }
            Ok(BuildBlockOutcome::EpochStale) => Ok(ProposeOutcome::EpochStale),
            Ok(BuildBlockOutcome::BoundaryUnavailable) => Ok(ProposeOutcome::BoundaryUnavailable),
            Err(e) => Err(eyre::eyre!("failed to build block for proposal: {e}")),
        }
    }

    async fn prepare_built_candidate(
        &self,
        block: &ConsensusBlock,
        execution_read_budget: ExecutionReadBudget,
    ) -> Result<(), BuiltCandidatePreparationError> {
        prepare_built_candidate(
            &self.engine,
            self.ocomp_retention.as_ref(),
            block,
            execution_read_budget,
        )
        .await
    }

    /// Canonicalize parent and build a block on top of it.
    ///
    /// recover the direct parent's canonical Finalization parent-proof
    /// record from marshal's durable finalization archive when the in-process
    /// selection store missed it (restart / late-join / brief finalization lag).
    ///
    /// `get_finalization` is a LOCAL archive read - it never triggers a network
    /// fetch, so this cannot block consensus on a peer; the archive is the same
    /// durable store marshal repopulates during sync. The rebuilt record mirrors
    /// the live [`FinalizationActor`](crate::finalization::actor) writer
    /// field-for-field (pinned by the `record_builder_parity` test), so the
    /// proposer's Phase 1 metadata stays canonical and every validator accepts
    /// it. Returns `None` when the archive has no finalization for `parent_height`,
    /// the recovered finalization does not finalize this exact parent, or the
    /// finalized epoch's committee scheme / ordered addresses are not registered.
    // `pub(crate)` for the regression test in `handler_tests` (a sibling
    // module): exercises the selection-store-miss recovery branch directly.
    pub(crate) async fn recover_parent_proof_from_marshal(
        &self,
        parent_proof_key: crate::finalization::parent_cert_store::CertifiedParentProofKey,
        parent_height: u64,
    ) -> Option<crate::finalization::parent_cert_store::CertifiedParentProofRecord> {
        use commonware_codec::Encode as _;

        let finalization = self
            .marshal_mailbox
            .get_finalization(Height::new(parent_height))
            .await?;
        // Hash-exact: the recovered finalization must finalize THIS parent.
        if finalization.proposal.payload.0 != parent_proof_key.block_hash {
            return None;
        }
        let epoch = finalization.proposal.round.epoch();
        let scheme = self.certificate_scheme_provider.scoped(epoch)?;
        let ordered = self.committee_provider.ordered_committee(epoch)?;
        let encoded: alloy_primitives::Bytes = finalization.encode().into();
        match crate::finalization::resolver::build_finalization_record_from_recovered(
            epoch.get(),
            finalization.proposal.round.view().get(),
            finalization.proposal.parent.get(),
            parent_height,
            finalization.proposal.payload.0,
            ordered.as_ref(),
            &finalization.certificate,
            encoded,
            scheme.as_ref(),
        ) {
            Ok(record) => Some(record),
            Err(error) => {
                // Encode-invariant violation on the marshal-recovery path: no
                // canonical record can be produced, so recovery is unavailable
                // (deterministic; never a wrong proof). Logged, not fatal.
                tracing::warn!(
                    target: "outbe::application",
                    epoch = epoch.get(),
                    parent_height,
                    %error,
                    "marshal-recovered finalization record build failed; \
                     no Phase 1 recovery record available"
                );
                None
            }
        }
    }

    async fn select_parent_proof_for_proposal(
        &self,
        clock: &(impl commonware_runtime::Clock + commonware_runtime::Supervisor),
        round: Round,
        parent_digest: Digest,
        parent_height: Height,
        parent_proof_key: Option<CertifiedParentProofKey>,
    ) -> ParentProofLookup {
        if parent_height.get() == 0 {
            return ParentProofLookup::NoProofNeeded;
        }
        let Some(parent_proof_key) = parent_proof_key else {
            warn!(
                %round,
                parent = %parent_digest.0,
                parent_height = parent_height.get(),
                "non-genesis proposal missing exact parent proof key"
            );
            crate::metrics::record_parent_cert_missing();
            crate::metrics::record_parent_proof_unavailable_forfeit();
            crate::metrics::record_phase1_parent_proof_unavailable();
            return ParentProofLookup::Unavailable;
        };
        match self
            .finalization_selector
            .select_direct_parent_proof_by_key_with_wait(
                clock,
                parent_proof_key,
                parent_height.get(),
                crate::finalization::selection::PHASE1_FINALIZATION_WAIT_DEFAULT,
            )
            .await
        {
            Some(record) => ParentProofLookup::Found(record),
            None => {
                // The in-process selection store missed the direct parent's proof
                // (post-restart, late-joining validator, or brief finalization lag),
                // but marshal's DURABLE finalization archive may still hold the
                // parent's finalization locally. Recover it and rebuild the
                // canonical Finalization parent-proof record before forfeiting the
                // slot.
                match self
                    .recover_parent_proof_from_marshal(parent_proof_key, parent_height.get())
                    .await
                {
                    Some(record) => {
                        crate::metrics::record_parent_proof_recovered_from_marshal();
                        info!(
                            %round,
                            parent = %parent_digest.0,
                            parent_height = parent_height.get(),
                            "recovered direct-parent proof from marshal archive; slot not forfeited"
                        );
                        ParentProofLookup::Found(record)
                    }
                    None => {
                        crate::metrics::record_parent_cert_missing();
                        crate::metrics::record_parent_proof_unavailable_forfeit();
                        crate::metrics::record_phase1_parent_proof_unavailable();
                        ParentProofLookup::Unavailable
                    }
                }
            }
        }
    }

    /// Uses an FCU-based flow: sends fork_choice_updated with payload
    /// attributes through the executor actor, so the engine starts building
    /// a payload on the correct canonical state with txpool access.
    #[allow(clippy::too_many_arguments)]
    async fn build_block(
        &self,
        clock: &(impl commonware_runtime::Clock + commonware_runtime::Supervisor),
        round: Round,
        parent_height: Height,
        parent_digest: Digest,
        parent_block: Option<ConsensusBlock>,
        parent_proof_key: Option<CertifiedParentProofKey>,
        propose_start: std::time::SystemTime,
        execution_read_budget: ExecutionReadBudget,
        payload_trace: ProposalPayloadTrace,
    ) -> eyre::Result<BuildBlockOutcome> {
        let next_block_number = parent_height.get().saturating_add(1);
        if let Err(rejection) = self.epoch_fence.check(round, next_block_number) {
            debug!(
                %round,
                parent = %parent_digest.0,
                next_block_number,
                ?rejection,
                "dropping stale proposal before payload build"
            );
            return Ok(BuildBlockOutcome::EpochStale);
        }

        if crate::test_faults::should_drop_new_payload_for_test(Height::new(next_block_number)) {
            warn!(
                %round,
                parent = %parent_digest.0,
                next_block_number,
                "test-marshal-drop: skipping local proposal for dropped height"
            );
            return Ok(BuildBlockOutcome::EpochStale);
        }

        let now_millis = self.unix_time_source.now_millis()?;
        // Clamp the proposed timestamp into the deterministic two-sided drift band
        // `[parent + MIN_BLOCK_TIMESTAMP_ADVANCE_MILLIS,
        // parent + MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS]`. The lower bound
        // forces each block to advance chain time, denying a colluding leader
        // majority the `parent + 1 ms` timestamp freeze that stalls emission and
        // unbonding maturity; the upper bound (C-01) mirrors the validator check
        // in `outbe-node`'s `validate_against_parent_timestamp_millis`, so an
        // honest proposer never emits a block validators would reject as
        // over-drifted. Both bounds match the validator rule exactly, so the
        // clamp only ever shifts the timestamp into the accepted band - never out
        // of it. After a long stall `now_millis` may exceed the cap; the chain
        // self-heals, ratcheting time forward by at most one band per block until
        // it catches up to real time.
        //
        // Exception - the genesis child has no resolved consensus parent block,
        // so the band is meaningless and only monotonicity is enforced. The
        // validator side exempts the genesis parent (`parent.number() == 0`) from
        // both band bounds, so block 1 (~= genesis + now) always validates and no
        // unbonding-lock bypass is possible at the first block.
        let timestamp_millis = proposal_timestamp_millis(
            parent_block.as_ref(),
            now_millis,
            outbe_primitives::consensus::MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS,
            outbe_primitives::consensus::MIN_BLOCK_TIMESTAMP_ADVANCE_MILLIS,
        );
        let prev_randao = self.finalization_view.prev_randao();

        // build header.extra_data only from consensus header
        // artifacts that affect block hashing (DKG boundary/dealer-log).
        // Exact-parent finalization facts are carried in the begin-zone
        // Phase 1 system transaction body, not as a header attestation
        // backlog tag.
        //
        //(proposed_height == 1,
        // parent_height == 0) MUST carry `ConsensusHeaderArtifact::BoundaryOutcome`
        // in `extra_data`. If the epoch has no pending boundary for block 1,
        // the proposer forfeits the slot deterministically with the
        // `genesis_dkg_boundary_not_ready` reason - never propose block 1
        // without a real boundary artifact.
        let proposed_height = parent_height.get().saturating_add(1);
        let pending_boundary = self
            .dkg_manager
            .pending_boundary_artifact(round.epoch())
            .await;
        let ancestry = super::ancestry::marshal_ancestry_reader(
            self.marshal_mailbox.clone(),
            self.block_cache.clone(),
            self.ancestry_readiness.clone(),
            Some(round),
            PROPOSE_RESOLUTION_TIMEOUT,
            clock.child("ancestry"),
        );
        let consensus_header_artifact = match self
            .dkg_manager
            .resolve_boundary(parent_block.as_ref(), pending_boundary.as_ref(), &ancestry)
            .await
        {
            Ok(BoundaryRequirement::AlreadyCommitted) => {
                crate::metrics::record_dkg_boundary_requirement(
                    crate::metrics::DkgBoundaryDecision::AlreadyCommitted,
                );
                None
            }
            Ok(BoundaryRequirement::MustEmit) => {
                let Some(boundary) = pending_boundary else {
                    return Err(eyre::eyre!(
                        "boundary requirement requested emission without pending artifact"
                    ));
                };
                crate::metrics::record_dkg_boundary_requirement(
                    crate::metrics::DkgBoundaryDecision::MustEmit,
                );
                Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary))
            }
            Ok(BoundaryRequirement::NoPending) if proposed_height == 1 => {
                debug!(
                    %round,
                    proposed_height,
                    "block 1 proposal forfeited: DKG boundary artifact for epoch 0 not ready"
                );
                crate::metrics::record_genesis_dkg_boundary_not_ready_forfeit();
                crate::metrics::record_dkg_boundary_unavailable(
                    crate::metrics::DkgBoundaryUnavailableReason::GenesisBoundaryNotReady,
                );
                return Ok(BuildBlockOutcome::BoundaryUnavailable);
            }
            Ok(BoundaryRequirement::NoPending) => {
                crate::metrics::record_dkg_boundary_requirement(
                    crate::metrics::DkgBoundaryDecision::NoPending,
                );
                // If the DKG for the NEXT epoch has completed (its boundary is
                // pending) but this is not yet its activation block, PRE-ANNOUNCE
                // that committee in this E-1 block so a follower authenticates it via
                // the already-trusted E-1 committee - before the self-finalized
                // activation boundary at E*L+1 (Path A committee-chaining). Otherwise
                // a DKG is still in flight, so emit a dealer log.
                if let Some(boundary) = self
                    .dkg_manager
                    .pending_next_epoch_artifact(round.epoch())
                    .await
                {
                    Some(ConsensusHeaderArtifact::CommitteePreAnnounce {
                        epoch: boundary.epoch,
                        outcome: boundary.outcome,
                    })
                } else {
                    self.dkg_manager
                        .get_dealer_log(round.epoch())
                        .await
                        .map(ConsensusHeaderArtifact::DealerLog)
                }
            }
            Err(error) => {
                warn!(
                    %round,
                    proposed_height,
                    %error,
                    "block proposal forfeited: DKG boundary requirement unavailable"
                );
                if error.is_unavailable() {
                    crate::metrics::record_dkg_boundary_unavailable(
                        crate::metrics::DkgBoundaryUnavailableReason::AncestryUnavailable,
                    );
                }
                return Ok(BuildBlockOutcome::BoundaryUnavailable);
            }
        };

        // Non-blocking direct-parent proof selection
        // (finalization first -> certified-notarization -> marshal-archive
        // recovery -> forfeit). The request budget does not gate this lookup -
        // the selector returns synchronously. On a selection-store
        // miss the None branch recovers the parent's finalization from marshal's
        // durable archive (, `recover_parent_proof_from_marshal`); only if
        // that also misses does the slot forfeit deterministically with the
        // parent-proof-unavailable metric.
        let parent_proof_record = match self
            .select_parent_proof_for_proposal(
                clock,
                round,
                parent_digest,
                parent_height,
                parent_proof_key,
            )
            .await
        {
            ParentProofLookup::NoProofNeeded => None,
            ParentProofLookup::Found(record) => Some(record),
            ParentProofLookup::Unavailable => return Ok(BuildBlockOutcome::ParentProofUnavailable),
        };
        // V2 wire-format swap landed. Build the V2
        // `CertifiedParentAccountingMetadata` directly from the proof record
        // via [`CertifiedParentProofRecord::to_v2_metadata`]. Both
        // finalization and certified-notarization records project into V2
        // metadata's `ParentProofSelector::select_direct_parent_proof`
        // is the upstream caller that decides which record (if any) to feed
        // into Phase 1.
        // The selector guarantees the chosen record's height resolves to
        // `parent_height` (Finalization validated to match; CertifiedNotarization
        // carries no height of its own and is resolved to the parent here).
        let parent_consensus_metadata = parent_proof_record
            .as_ref()
            .map(|record| record.to_v2_metadata(parent_height.get()));
        if parent_consensus_metadata.is_some() {
            crate::metrics::record_parent_cert_included();
        }

        // pack the in-window late-finalize credits this node has
        // locally observed for blocks `proposed_height - K ..= proposed_height - 1`.
        // Best-effort and process-local: every validator re-verifies each batch
        // (pre-exec FATAL) and re-derives the same artifact via header<->calldata
        // parity, so the contents never affect determinism - an empty store just
        // credits nobody. A poisoned lock degrades to no credits.
        let late_finalize_credits = match self.late_sig_store.lock() {
            Ok(store) => {
                let artifact = store.build_artifact(proposed_height);
                if artifact.batches.is_empty() {
                    None
                } else {
                    Some(artifact)
                }
            }
            Err(_) => None,
        };

        let header_extra_data =
            if consensus_header_artifact.is_none() && late_finalize_credits.is_none() {
                Bytes::new()
            } else {
                encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                    execution_summary: None,
                    consensus_header_artifact,
                    // The sub-second timestamp part is recomputed by the
                    // payload builder from `OutbeBlockExecutionCtx` and
                    // re-encoded into `extra_data` before sealing; we
                    // intentionally leave it at 0 here.
                    timestamp_millis_part: 0,
                    late_finalize_credits,
                    compressed_entities_root: None,
                })
                .map_err(|e| eyre::eyre!(e.to_string()))?
            };

        let attrs = OutbePayloadAttributes::new(
            REWARDS_ADDRESS,
            timestamp_millis,
            prev_randao,
            Some(B256::ZERO),
            header_extra_data,
            parent_consensus_metadata,
            self.proposer_evm_address,
        )
        .with_execution_read_budget(execution_read_budget);

        if let Err(rejection) = self.epoch_fence.check(round, next_block_number) {
            debug!(
                %round,
                parent = %parent_digest.0,
                next_block_number,
                ?rejection,
                "dropping stale proposal before FCU payload build"
            );
            return Ok(BuildBlockOutcome::EpochStale);
        }

        // FCU-based payload building: canonicalize parent and start building
        // in one atomic operation via the executor actor.
        let payload_id = self
            .executor_mailbox
            .canonicalize_and_build(parent_height, parent_digest, attrs)
            .await
            .map_err(|e| eyre::eyre!("canonicalize_and_build failed: {e}"))?;
        payload_trace.record(payload_id);

        debug!(%payload_id, "payload building started via FCU");

        // Give the payload builder a bounded chance to execute transactions before
        // resolving. Elapsed is measured against the runtime clock (same source as
        // the sleep below), so it is correct on the deterministic runtime too.
        let elapsed = clock
            .current()
            .duration_since(propose_start)
            .unwrap_or_default();
        let remaining_resolve = self.payload_resolve_time.saturating_sub(elapsed);

        clock.sleep(remaining_resolve).await;

        if let Err(rejection) = self.epoch_fence.check(round, next_block_number) {
            debug!(
                %round,
                parent = %parent_digest.0,
                next_block_number,
                ?rejection,
                "dropping stale proposal after payload build started"
            );
            return Ok(BuildBlockOutcome::EpochStale);
        }

        let payload = self
            .payload_builder
            .resolve_kind(
                payload_id,
                reth_payload_builder::PayloadKind::WaitForPending,
            )
            .await
            .ok_or_else(|| eyre::eyre!("payload resolution returned None"))?
            .map_err(|e| eyre::eyre!("payload resolution failed: {e}"))?;

        let sealed_block = payload.block().clone();

        let consensus_block = ConsensusBlock::from_sealed(sealed_block);
        let digest = consensus_block.digest();
        let block_number = consensus_block.number();
        debug!(%digest, number = block_number, "block built");

        crate::metrics::record_block_proposed(block_number);

        self.block_cache
            .insert_bounded(digest, consensus_block.clone());

        Ok(BuildBlockOutcome::Built(digest, consensus_block))
    }

    /// Drive `engine.new_payload` to a terminal verdict, retrying while execution
    /// reports SYNCING. Owns the SYNCING/retry policy for both verify paths
    /// (parent and proposed block) so they cannot diverge. Bails to
    /// [`PayloadVerification::ChannelClosed`] if the single-shot verify response
    /// channel closes mid-wait; `kind`/`digest` only scope the diagnostics.
    async fn verify_payload_with_syncing_retry(
        &self,
        clock: &impl commonware_runtime::Clock,
        kind: &'static str,
        digest: Digest,
        execution_data: OutbeExecutionData,
        response: &mut oneshot::Sender<bool>,
        execution_read_budget: &ExecutionReadBudget,
    ) -> eyre::Result<PayloadVerification> {
        let mut saw_syncing = false;
        loop {
            if response.is_closed() {
                execution_read_budget.cancel();
                debug!(
                    kind,
                    target = %digest.0,
                    "verify response channel closed while waiting for execution validation"
                );
                return Ok(PayloadVerification::ChannelClosed);
            }
            let execution = Box::pin(self.engine.new_payload(execution_data.clone()));
            let cancelled = Box::pin(response.closed());
            let status = match futures::future::select(execution, cancelled).await {
                futures::future::Either::Left((status, _)) => status,
                futures::future::Either::Right(((), _)) => {
                    execution_read_budget.cancel();
                    return Ok(PayloadVerification::ChannelClosed);
                }
            };
            match status {
                Ok(status) if status.is_valid() => {
                    debug!(kind, target = %digest.0, ?status, "payload accepted during verify");
                    return Ok(PayloadVerification::Valid { saw_syncing });
                }
                Ok(status) if status.is_syncing() => {
                    saw_syncing = true;
                    warn!(
                        kind,
                        target = %digest.0,
                        ?status,
                        "new_payload returned SYNCING during verify; keeping verification pending until execution validates"
                    );
                    clock.sleep(VERIFY_SYNCING_RETRY_DELAY).await;
                }
                Ok(status) => {
                    warn!(kind, target = %digest.0, ?status, "payload rejected during verify");
                    return Ok(PayloadVerification::Invalid);
                }
                Err(e) => {
                    return Err(eyre::eyre!(
                        "new_payload failed in verify: kind={kind} target={} error={e}",
                        digest.0
                    ));
                }
            }
        }
    }

    /// Handle verify request.
    ///
    /// 1. Resolve proposed block (cache or marshal)
    /// 2. Resolve parent block and send new_payload to Reth
    /// 3. Canonicalize parent
    /// 4. Send new_payload for proposed block
    /// 5. Respond with execution validity
    /// 6. If valid, canonicalize proposed block
    async fn handle_verify(
        &self,
        clock: &(impl commonware_runtime::Clock + commonware_runtime::Supervisor),
        context: super::ingress::SimplexContext,
        payload_digest: Digest,
        mut response: oneshot::Sender<bool>,
        execution_read_budget: ExecutionReadBudget,
    ) -> eyre::Result<()> {
        let round = context.round;
        let (parent_view, parent) = context.parent;
        let parent_digest = Digest(parent.0);

        debug!(
            %round,
            %parent_view,
            digest = %payload_digest.0,
            parent = %parent_digest.0,
            "verify requested"
        );

        if let Err(rejection) = self.epoch_fence.check(round, 0) {
            debug!(
                %round,
                digest = %payload_digest.0,
                ?rejection,
                "dropping stale verify before block resolution"
            );
            let _ = response.send(false);
            return Ok(());
        }

        // epoch continuity: special-case epoch boundary parent
        // before falling back to chain-genesis / generic verify resolution.
        let maybe_epoch_anchor = match epoch_boundary::resolve_epoch_boundary_parent(
            &self.finalization_view,
            &self.marshal_mailbox,
            clock,
            round,
            parent_view,
            parent_digest,
        )
        .await
        {
            Ok(opt) => opt,
            Err(EpochBoundaryParentError::ParentMismatch { .. }) => {
                // Invalid proposal: proposer chose a parent that does not match
                // the committed continuity anchor. Deterministic reject.
                warn!(
                    %round,
                    parent = %parent_digest.0,
                    "verify: epoch boundary parent mismatch with finalized anchor"
                );
                let _ = response.send(false);
                return Ok(());
            }
            Err(error) => {
                // Local infrastructure issue (missing anchor / marshal miss / hash mismatch).
                // Do NOT vote false - a validator with a temporarily lagging finalization view
                // or marshal store must not reject a block that is in fact valid. Bubble Err
                // so the response channel drops, matching existing `resolve_for_verify`
                // behaviour for local timeouts.
                return Err(eyre::eyre!(
                    "could not resolve epoch boundary parent: {error}"
                ));
            }
        };
        debug_assert!(
            !(round.epoch().get() > 0
                && parent_view == View::new(0)
                && maybe_epoch_anchor.is_none()),
            "resolve_epoch_boundary_parent invariant: epoch>0 && parent_view=0 must \
             resolve to Some(EpochBoundaryParent) or return an explicit error"
        );

        let block_resolution = resolve_for_verify(
            &self.block_cache,
            &self.marshal_mailbox,
            clock,
            round,
            payload_digest,
            VerifyResolveTarget::Block,
        );
        let parent_resolution = async {
            if let Some(anchor) = maybe_epoch_anchor {
                Ok(Some(anchor.block))
            } else if parent_digest.0 == self.genesis_hash {
                Ok(None)
            } else {
                resolve_for_verify(
                    &self.block_cache,
                    &self.marshal_mailbox,
                    clock,
                    parent_round(round, parent_view),
                    parent_digest,
                    VerifyResolveTarget::Parent,
                )
                .await
                .map(Some)
            }
        };

        // `futures::try_join!` is runtime-agnostic (no tokio reactor needed); it polls
        // both resolutions concurrently and short-circuits on the first `Err`,
        // identical to the prior `tokio::try_join!`.
        let (block, parent_block) = match futures::try_join!(block_resolution, parent_resolution) {
            Ok(result) => result,
            Err(error) => {
                return Err(eyre::eyre!(
                    "failed to resolve verify payload or parent: error={error:?} round={round} digest={} parent={}",
                    payload_digest.0,
                    parent_digest.0
                ));
            }
        };

        if let Err(error) = validate_context_parent_binding(
            &block,
            parent_block.as_ref(),
            parent_digest,
            self.genesis_hash,
        ) {
            warn!(
                digest = %payload_digest.0,
                round = %round,
                block_number = block.number(),
                parent = %parent_digest.0,
                %error,
                "proposed block does not extend Simplex context parent"
            );
            let _ = response.send(false);
            return Ok(());
        }

        if let Err(rejection) = self.epoch_fence.check(round, block.number()) {
            debug!(
                %round,
                digest = %payload_digest.0,
                block_number = block.number(),
                ?rejection,
                "dropping stale verify before Engine API work"
            );
            let _ = response.send(false);
            return Ok(());
        }

        if let Err(error) = self.vrf_safety.ensure_block_allowed(block.number()) {
            warn!(
                digest = %payload_digest.0,
                round = %round,
                block_number = block.number(),
                %error,
                "proposed block is above VRF expiry"
            );
            let _ = response.send(false);
            return Ok(());
        }

        let ancestry = super::ancestry::marshal_ancestry_reader(
            self.marshal_mailbox.clone(),
            self.block_cache.clone(),
            self.ancestry_readiness.clone(),
            Some(round),
            VERIFY_RESOLUTION_TIMEOUT,
            clock.child("ancestry"),
        );
        if let Err(error) = validate_header_consensus_artifacts_for_activation(
            &block,
            parent_block.as_ref(),
            round,
            &context.leader,
            self.chain_id,
            self.ocomp_lifecycle_activation,
            ValidatorRole::from_proposer_evm_address(self.proposer_evm_address),
            &self.certificate_scheme_provider,
            &self.committee_provider,
            &self.dkg_manager,
            &ancestry,
        )
        .await
        {
            if error.contains("DKG boundary ancestry unavailable")
                || error.contains("DKG boundary ancestry scan exceeded")
            {
                crate::metrics::record_dkg_boundary_unavailable(
                    crate::metrics::DkgBoundaryUnavailableReason::AncestryUnavailable,
                );
                return Err(eyre::eyre!("DKG boundary requirement unavailable: {error}"));
            }
            warn!(
                digest = %payload_digest.0,
                round = %round,
                %error,
                "proposed block carries invalid header consensus artifact"
            );
            let _ = response.send(false);
            return Ok(());
        }

        // `handle_verify` performs ONLY structural
        // checks - Phase 1 system tx decode succeeds, header artifacts well-
        // formed, parent binding correct, VRF window not expired. It does NOT
        // perform BLS decode/verify on the carried certificate, does not
        // perform accounting checks, and does not look up committee snapshots.
        // The full V2 cryptographic verify is delegated to the EVM-side V2
        // verifier (`outbe-consensus-proof::verify_v2_proof`, consumed by
        // class verifier wiring), keeping `handle_verify` cheap and
        // stateless across every validator.
        if let Err(error) = finalized_parent_attestation_from_phase1_system_tx(&block) {
            warn!(
                digest = %payload_digest.0,
                round = %round,
                %error,
                "failed to decode Phase 1 finalized-parent metadata structure during verify"
            );
            let _ = response.send(false);
            return Ok(());
        }

        let required_parent = ProjectionCheckpoint {
            block_number: parent_block.as_ref().map_or(0, ConsensusBlock::number),
            block_hash: parent_digest.0,
        };
        let projection_budget = execution_read_budget.clone();
        if wait_for_projected_parent(self.projection_readiness.clone(), required_parent, async {
            response.closed().await;
            projection_budget.cancel();
        })
        .await?
            == ParentProjectionGate::Withhold
        {
            return Ok(());
        }

        if let Some(parent_block) = parent_block {
            let parent_height = Height::new(parent_block.number());
            let execution_data =
                OutbeExecutionData::new(std::sync::Arc::new(parent_block.clone().into_inner()))
                    .with_execution_read_budget(execution_read_budget.clone());

            let parent_saw_syncing =
                if crate::test_faults::should_drop_new_payload_for_test(parent_height) {
                    warn!(
                        height = %parent_height,
                        parent = %parent_digest.0,
                        "test-marshal-drop: skipping verify parent new_payload"
                    );
                    false
                } else {
                    match self
                        .verify_payload_with_syncing_retry(
                            clock,
                            "parent",
                            parent_digest,
                            execution_data,
                            &mut response,
                            &execution_read_budget,
                        )
                        .await?
                    {
                        PayloadVerification::ChannelClosed => return Ok(()),
                        PayloadVerification::Invalid => {
                            let _ = response.send(false);
                            return Ok(());
                        }
                        PayloadVerification::Valid { saw_syncing } => saw_syncing,
                    }
                };

            if response.is_closed() || parent_saw_syncing {
                debug!(
                    parent = %parent_digest.0,
                    parent_saw_syncing,
                    "skipping verify parent side effects after pending/cancelable execution validation"
                );
            } else if let Err(rejection) = self.epoch_fence.check(round, block.number()) {
                debug!(
                    %round,
                    parent = %parent_digest.0,
                    block_number = block.number(),
                    ?rejection,
                    "skipping verify parent side effects after stale epoch transition"
                );
            } else {
                if let Err(e) = self
                    .executor_mailbox
                    .canonicalize_head(parent_height, parent_digest)
                    .await
                {
                    return Err(eyre::eyre!(
                        "canonicalize_head failed for parent during verify: parent={} error={e}",
                        parent_digest.0
                    ));
                }

                self.finalization_view
                    .advance_timestamp_floor(parent_block.timestamp_millis());
            }
        }

        // Step 3: new_payload for proposed block.
        let execution_data =
            OutbeExecutionData::new(std::sync::Arc::new(block.clone().into_inner()))
                .with_execution_read_budget(execution_read_budget.clone());

        let block_height = Height::new(block.number());
        let (valid, block_saw_syncing) =
            if crate::test_faults::should_drop_new_payload_for_test(block_height) {
                warn!(
                    height = %block_height,
                    digest = %payload_digest.0,
                    "test-marshal-drop: skipping verify block new_payload"
                );
                (true, false)
            } else {
                match self
                    .verify_payload_with_syncing_retry(
                        clock,
                        "block",
                        payload_digest,
                        execution_data,
                        &mut response,
                        &execution_read_budget,
                    )
                    .await?
                {
                    PayloadVerification::ChannelClosed => return Ok(()),
                    PayloadVerification::Invalid => (false, false),
                    PayloadVerification::Valid { saw_syncing } => (true, saw_syncing),
                }
            };

        // Step 4: If valid, canonicalize the proposed block only while the
        // single-shot Simplex verify request is still live. A SYNCING retry can
        // outlive the view timeout; once the receiver is gone, all side effects
        // for this verify request must be suppressed.
        if !valid {
            let _ = response.send(false);
            return Ok(());
        }
        if let Err(rejection) = self.epoch_fence.check(round, block.number()) {
            debug!(
                %round,
                digest = %payload_digest.0,
                block_number = block.number(),
                ?rejection,
                "skipping verify block side effects after stale epoch transition"
            );
            return Ok(());
        }
        if response.is_closed() {
            debug!(
                digest = %payload_digest.0,
                "verify response channel closed before execution-valid side effects"
            );
            return Ok(());
        }
        let positive_vote = match after_durable_candidate(
            self.ocomp_retention.as_ref(),
            &block,
            || response.send(true),
        ) {
            Ok(result) => result,
            Err(error) => {
                warn!(
                    %round,
                    digest = %payload_digest.0,
                    block_number = block.number(),
                    %error,
                    "withholding local positive vote because the OCOMP tentative pin is not durable"
                );
                return Ok(());
            }
        };
        if positive_vote.is_err() {
            debug!(
                digest = %payload_digest.0,
                "verify response receiver dropped before execution-valid side effects"
            );
            return Ok(());
        }
        if block_saw_syncing {
            debug!(
                digest = %payload_digest.0,
                "skipping verify block side effects after pending/cancelable execution validation"
            );
            return Ok(());
        }
        let _ = self.marshal_mailbox.verified(round, block.clone()).await;
        let _ = self
            .executor_mailbox
            .canonicalize_head(block_height, payload_digest)
            .await;
        self.finalization_view
            .advance_timestamp_floor(block.timestamp_millis());

        Ok(())
    }
}

// Marshal-based block resolution tests are in `crate::marshal_tests`.

pub(crate) fn parent_round(round: Round, parent_view: View) -> Round {
    Round::new(round.epoch(), parent_view)
}

// `retry_with_backoff`, `RetryFailure`, `RetryFailureKind` moved to
// `crate::finalization::util` in step 17. Imported at the top of this file.

// `extract_consensus_metadata_from_block` and
// `extract_header_artifact_from_block` moved to
// `crate::finalization::util` in step 17. Imported at the top of this file.

/// Whether the local node validates live proposals. A share-less verifier (a TEE
/// full-node with no proposer EVM address) follows FINALIZED blocks only and skips
/// the leader-binding / DKG-boundary checks (polynomial/DKG-view-dependent, would
/// diverge on a verifier's stale post-rotation state). Replaces a boolean-blind
/// `is_verifier` flag so the role choice is explicit in the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValidatorRole {
    Signer,
    VerifierOnly,
}

impl ValidatorRole {
    /// A node with no proposer EVM address is a share-less verifier-only follower.
    fn from_proposer_evm_address(proposer_evm_address: Option<Address>) -> Self {
        match proposer_evm_address {
            Some(_) => Self::Signer,
            None => Self::VerifierOnly,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn validate_header_consensus_artifacts_for_activation(
    block: &ConsensusBlock,
    parent_block: Option<&ConsensusBlock>,
    round: Round,
    proposer: &PublicKey,
    chain_id: u64,
    ocomp_lifecycle_activation: OcompLifecycleActivation,
    role: ValidatorRole,
    certificate_scheme_provider: &HybridSchemeProvider<MinSig>,
    committee_provider: &CommitteeProvider,
    dkg_manager: &crate::dkg_manager::Mailbox,
    ancestry: &impl AncestryReader,
) -> Result<(), String> {
    // Finalized-follower rule: a share-less verifier (a TEE full-node, no
    // `proposer_evm_address`) does NOT validate live proposals - it follows
    // FINALIZED blocks, whose threshold certificate is verified by the reporter
    // against the GROUP public key (preserved across reshares). The leader-binding
    // and DKG-boundary checks below are polynomial/DKG-view-dependent and would
    // diverge on a verifier's stale post-rotation state, so they are skipped here;
    // consensus safety for the follower comes from the finalization certificate, not
    // from re-deriving the live proposal's leader. The verifier never votes (`me()`
    // is None), so accepting the proposal here cannot affect the committee's quorum.
    if role == ValidatorRole::VerifierOnly {
        return Ok(());
    }
    validate_rewards_beneficiary(block)?;
    validate_system_tx_leader_binding_for_activation(
        block,
        round,
        proposer,
        chain_id,
        ocomp_lifecycle_activation,
        certificate_scheme_provider,
        committee_provider,
    )?;

    let expected_boundary = dkg_manager.pending_boundary_artifact(round.epoch()).await;
    let artifact = extract_header_artifact_from_block(block)?;

    match dkg_manager
        .resolve_boundary(parent_block, expected_boundary.as_ref(), ancestry)
        .await
        .map_err(|error| error.to_string())?
    {
        BoundaryRequirement::NoPending => {}
        BoundaryRequirement::AlreadyCommitted => {
            if matches!(artifact, Some(ConsensusHeaderArtifact::BoundaryOutcome(_))) {
                crate::metrics::record_dkg_boundary_duplicate_rejected();
                return Err(
                    "duplicate DKG BoundaryOutcome after parent ancestry already committed it"
                        .to_string(),
                );
            }
            crate::metrics::record_dkg_boundary_requirement(
                crate::metrics::DkgBoundaryDecision::AlreadyCommitted,
            );
            return Ok(());
        }
        BoundaryRequirement::MustEmit => {
            let Some(expected_boundary) = expected_boundary else {
                return Err(
                    "boundary requirement requested emission without pending artifact".to_string(),
                );
            };

            let Some(ConsensusHeaderArtifact::BoundaryOutcome(boundary)) = artifact else {
                return Err("block omitted pending DKG BoundaryOutcome".to_string());
            };
            if boundary != expected_boundary {
                return Err("block BoundaryOutcome does not match pending DKG boundary".to_string());
            }
            return dkg_manager
                .verify_pending_boundary_artifact(round.epoch(), &boundary)
                .await
                .map_err(|error| error.to_string());
        }
    }

    let Some(artifact) = artifact else {
        return Ok(());
    };

    match artifact {
        ConsensusHeaderArtifact::BoundaryOutcome(_) => {
            crate::metrics::record_dkg_boundary_duplicate_rejected();
            Err("block carried DKG BoundaryOutcome without pending boundary".to_string())
        }
        ConsensusHeaderArtifact::DealerLog(bytes) => {
            dkg_manager
                .verify_dealer_log(round.epoch(), bytes.to_vec())
                .await
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        ConsensusHeaderArtifact::CommitteePreAnnounce { epoch, outcome } => {
            // Path A committee pre-announce, emitted during E-1 after the DKG
            // completes. Validate its carried outcome against this node's OWN
            // reconstructed DKG output for the incoming epoch - fail-closed if this
            // node has no pending boundary to compare against, so a forged
            // pre-announce cannot ride a finalized block.
            dkg_manager
                .verify_preannounce_outcome(
                    commonware_consensus::types::Epoch::new(epoch),
                    outcome.as_ref(),
                )
                .await
                .map_err(|error| error.to_string())?;
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn validate_header_consensus_artifacts(
    block: &ConsensusBlock,
    parent_block: Option<&ConsensusBlock>,
    round: Round,
    proposer: &PublicKey,
    chain_id: u64,
    role: ValidatorRole,
    certificate_scheme_provider: &HybridSchemeProvider<MinSig>,
    committee_provider: &CommitteeProvider,
    dkg_manager: &crate::dkg_manager::Mailbox,
    ancestry: &impl AncestryReader,
) -> Result<(), String> {
    validate_header_consensus_artifacts_for_activation(
        block,
        parent_block,
        round,
        proposer,
        chain_id,
        OcompLifecycleActivation::Disabled,
        role,
        certificate_scheme_provider,
        committee_provider,
        dkg_manager,
        ancestry,
    )
    .await
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod handler_tests;

#[cfg(test)]
mod clamp_tests {
    use super::{
        apply_unix_time_offset_millis, clamp_proposed_timestamp_millis, proposal_timestamp_millis,
    };
    use alloy_primitives::Bytes;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::{primitives::SealedBlock, Block};

    const BAND: u64 = 60 * 60 * 1_000; // 1h, matches MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS
    const MIN: u64 = 1_000; // matches MIN_BLOCK_TIMESTAMP_ADVANCE_MILLIS

    #[test]
    fn injected_clock_offset_is_explicit_and_checked() {
        assert_eq!(
            apply_unix_time_offset_millis(1_000_000, 60).unwrap(),
            1_060_000
        );
        assert_eq!(
            apply_unix_time_offset_millis(1_000_000, -60).unwrap(),
            940_000
        );
        assert!(apply_unix_time_offset_millis(0, -1).is_err());
    }

    #[test]
    fn genesis_child_uses_wall_clock_not_band() {
        // Regression: at genesis the finalization_view is unseeded (parent==0).
        // The real wall-clock (~=1.78e12 ms) must NOT be clamped to 0+band, which
        // would put block 1 before the genesis timestamp and stall the chain. The
        // min-advance lower bound is also skipped at genesis (monotonic-only).
        let now = 1_781_255_987_000u64;
        assert_eq!(clamp_proposed_timestamp_millis(0, now, BAND, MIN), now);
    }

    #[test]
    fn real_parent_applies_band() {
        let parent = 1_781_255_987_000u64;
        // within band, above min advance -> wall clock used
        assert_eq!(
            clamp_proposed_timestamp_millis(parent, parent + 2_000, BAND, MIN),
            parent + 2_000
        );
        // far-future now -> capped at parent + band
        assert_eq!(
            clamp_proposed_timestamp_millis(parent, parent + 10 * BAND, BAND, MIN),
            parent + BAND
        );
    }

    #[test]
    fn lagging_clock_clamps_up_to_min_advance() {
        // when the proposer's clock has not advanced `MIN` past the parent
        // (or is in the past), the timestamp is clamped UP to `parent + MIN` so
        // the block satisfies the validator minimum-advance rule and is accepted,
        // rather than emitting `parent + 1` which validators would now reject.
        let parent = 1_781_255_987_000u64;
        // now in the past -> parent + MIN (not parent + 1).
        assert_eq!(
            clamp_proposed_timestamp_millis(parent, parent - 5, BAND, MIN),
            parent + MIN
        );
        // now between parent+1 and parent+MIN -> clamped up to parent + MIN.
        assert_eq!(
            clamp_proposed_timestamp_millis(parent, parent + 500, BAND, MIN),
            parent + MIN
        );
        // now exactly at the min-advance boundary -> unchanged.
        assert_eq!(
            clamp_proposed_timestamp_millis(parent, parent + MIN, BAND, MIN),
            parent + MIN
        );
    }

    #[test]
    fn proposal_timestamp_is_derived_from_the_exact_parent_block() {
        let parent_timestamp = 1_781_255_987_000u64;
        let mut parent = Block::default();
        parent.header.number = 42;
        parent.header.timestamp = parent_timestamp / 1_000;
        parent.header.extra_data = Bytes::from_static(b"exact-parent");
        let parent = parent.map_header(OutbeHeader::new);
        let parent = super::ConsensusBlock::from_sealed(SealedBlock::seal_slow(parent));

        assert_eq!(
            proposal_timestamp_millis(Some(&parent), parent_timestamp + 10 * BAND, BAND, MIN,),
            parent_timestamp + BAND,
        );
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, Address, Bytes, B256};
    use commonware_codec::Encode as _;
    use commonware_consensus::{
        simplex::types::{Finalization, Proposal, Subject},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::{self, primitives::variant::MinSig},
        certificate::Scheme as _,
        Hasher, Sha256, Signer as _,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Quorum as _, N3f1};
    use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
    use outbe_primitives::reshare_artifact::ConsensusHeaderArtifact;

    use crate::dkg_manager::{self, Mailbox as DkgManagerMailbox};
    use crate::finalization::attestation::{validate_consensus_metadata, AttestationVerdict};
    use crate::finalization::util::build_signer_bitmap;
    use crate::hybrid::{HybridScheme, HybridSchemeProvider};

    use super::{validate_header_consensus_artifacts, CommitteeProvider, Digest, ValidatorRole};
    use crate::test_fixtures::*;

    const OUTSIDER: Address = address!("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead");

    #[test]
    fn proposal_payload_trace_exposes_the_exact_fcu_payload_id() {
        let trace = super::ProposalPayloadTrace::default();
        let payload_id = alloy_rpc_types_engine::PayloadId::new([0x85; 8]);

        assert_eq!(trace.payload_id(), None);
        trace.record(payload_id);
        assert_eq!(trace.payload_id(), Some(payload_id));
    }

    // `valid_metadata_with_supplemental_finalize_vote` and the
    // V1 supplemental-finalize-vote tests below are retired. V2 contract
    // uses the certificate's own signer bitmap as the sole participation
    // input; there is no supplemental-vote bitmap-extension path to test.

    fn valid_metadata() -> (
        CertifiedParentAccountingMetadata,
        HybridSchemeProvider<MinSig>,
        CommitteeProvider,
    ) {
        let (keys, participants) = participants();
        let dkg = crate::bls::bootstrap_dkg(3).expect("bootstrap dkg should succeed");
        let schemes: Vec<HybridScheme<MinSig>> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).expect("participant index");
                HybridScheme::signer(
                    &crate::config::outbe_app_namespace(),
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .expect("signer scheme should build")
            })
            .collect();
        let verifier = HybridScheme::<MinSig>::verifier(
            &crate::config::outbe_app_namespace(),
            participants.clone(),
            dkg.polynomial,
        )
        .expect("verifier scheme should build");

        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(5)),
            View::new(4),
            Digest(B256::from_slice(Sha256::hash(b"handler-finalize").as_ref())),
        );
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestations: Vec<_> = schemes
            .iter()
            .map(|scheme| {
                scheme
                    .sign::<Digest>(subject)
                    .expect("finalize attestation")
            })
            .collect();
        let certificate = verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("certificate should assemble");

        let scheme_provider = HybridSchemeProvider::new();
        let committee_provider = CommitteeProvider::new();
        let committee = vec![V1, V2, V3];
        let _ = scheme_provider.register(Epoch::new(0), verifier);
        let _ = committee_provider.register(Epoch::new(0), committee.clone());

        let envelope = Finalization::<HybridScheme<MinSig>, Digest> {
            proposal: proposal.clone(),
            certificate: certificate.clone(),
        };

        (
            CertifiedParentAccountingMetadata {
                finalized_block_number: 5,
                finalized_block_hash: proposal.payload.0,
                finalized_epoch: 0,
                finalized_view: 5,
                parent_view: 4,
                ordered_committee: committee,
                signer_bitmap: build_signer_bitmap(&certificate, 3),
                proof: Bytes::from(envelope.encode()),
                ..Default::default()
            },
            scheme_provider,
            committee_provider,
        )
    }

    #[test]
    fn metadata_is_optional_for_verify() {
        let scheme_provider = HybridSchemeProvider::<MinSig>::new();
        let committee_provider = CommitteeProvider::new();
        assert_eq!(
            validate_consensus_metadata(None, &scheme_provider, &committee_provider),
            AttestationVerdict::AcceptNone
        );
    }

    #[test]
    fn valid_finalized_parent_certificate_is_accepted() {
        let (metadata, scheme_provider, committee_provider) = valid_metadata();
        assert_eq!(
            validate_consensus_metadata(Some(&metadata), &scheme_provider, &committee_provider),
            AttestationVerdict::AcceptValid
        );
    }

    #[test]
    fn finalized_parent_sentinel_metadata_is_rejected_when_present() {
        let (mut metadata, scheme_provider, committee_provider) = valid_metadata();
        metadata.finalized_block_number = 0;
        assert_eq!(
            validate_consensus_metadata(Some(&metadata), &scheme_provider, &committee_provider),
            AttestationVerdict::RejectStructural
        );

        let (mut metadata, scheme_provider, committee_provider) = valid_metadata();
        metadata.finalized_block_hash = B256::ZERO;
        assert_eq!(
            validate_consensus_metadata(Some(&metadata), &scheme_provider, &committee_provider),
            AttestationVerdict::RejectStructural
        );
    }

    // `supplemental_finalize_vote_extends_signer_bitmap` and
    // `supplemental_finalize_vote_is_required_for_extended_bitmap` were
    // V1-only tests of the legacy `build_signer_bitmap_with_finalize_votes`
    // reconciliation. Under V2 the certificate's own bitmap is authoritative;
    // these tests are retired in lockstep with the helper they exercised.

    #[test]
    fn mismatched_ordered_committee_is_rejected() {
        let (mut metadata, scheme_provider, committee_provider) = valid_metadata();
        metadata.ordered_committee.swap(0, 1);
        assert_eq!(
            validate_consensus_metadata(Some(&metadata), &scheme_provider, &committee_provider),
            AttestationVerdict::RejectStructural
        );
    }

    #[test]
    fn outsider_missed_proposer_is_rejected() {
        let (mut metadata, scheme_provider, committee_provider) = valid_metadata();
        metadata
            .missed_proposers
            .push(outbe_primitives::consensus_metadata::MissedProposerEvent {
                view: 1,
                validator: OUTSIDER,
            });
        assert_eq!(
            validate_consensus_metadata(Some(&metadata), &scheme_provider, &committee_provider),
            AttestationVerdict::RejectStructural
        );
    }

    #[test]
    fn tampered_signer_bitmap_is_rejected() {
        let (mut metadata, scheme_provider, committee_provider) = valid_metadata();
        metadata.signer_bitmap[0] = 0;
        assert_eq!(
            validate_consensus_metadata(Some(&metadata), &scheme_provider, &committee_provider),
            AttestationVerdict::RejectCertificate
        );
    }

    #[tokio::test]
    async fn boundary_header_artifact_must_match_dkg_manager() {
        let (keys, _participants, output, _polynomial, _dealer_log) = dkg_runtime_artifacts();
        let validator_set = validator_set_from_keys(&keys);
        let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
            epoch: Epoch::new(0),
            validator_set: &validator_set,
            output: &output,
            is_full_dkg: true,
            dkg_cycle: 0,
            freeze_height: 0,
            planned_activation_height: 0,
            vrf_material_version: 0,
            is_validator_set_change: true,
            tee_expired_target_exclusions: Vec::new(),
        })
        .unwrap();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let manager = DkgManagerMailbox::new();
        manager.note_bootstrap_outcome(artifact.clone());
        let block = block_with_header_artifact(&ConsensusHeaderArtifact::BoundaryOutcome(artifact));
        let ancestry = TestAncestryReader::ready();

        assert!(validate_header_consensus_artifacts(
            &block,
            None,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            ValidatorRole::Signer,
            &scheme_provider,
            &committee_provider,
            &manager,
            &ancestry,
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn pending_boundary_must_be_included_exactly() {
        let (keys, _participants, output, _polynomial, dealer_log) = dkg_runtime_artifacts();
        let validator_set = validator_set_from_keys(&keys);
        let artifact = dkg_manager::build_boundary_artifact(dkg_manager::BoundaryArtifactInput {
            epoch: Epoch::new(0),
            validator_set: &validator_set,
            output: &output,
            is_full_dkg: true,
            dkg_cycle: 0,
            freeze_height: 0,
            planned_activation_height: 0,
            vrf_material_version: 0,
            is_validator_set_change: true,
            tee_expired_target_exclusions: Vec::new(),
        })
        .unwrap();
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let manager = DkgManagerMailbox::new();
        manager.note_bootstrap_outcome(artifact);
        let ancestry = TestAncestryReader::ready();

        let missing = validate_header_consensus_artifacts(
            &block_with_number(0),
            None,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            ValidatorRole::Signer,
            &scheme_provider,
            &committee_provider,
            &manager,
            &ancestry,
        )
        .await
        .unwrap_err();
        assert!(missing.contains("omitted pending DKG BoundaryOutcome"));

        let dealer_log_block =
            block_with_header_artifact(&ConsensusHeaderArtifact::DealerLog(dealer_log));
        let wrong_kind = validate_header_consensus_artifacts(
            &dealer_log_block,
            None,
            Round::new(Epoch::new(0), View::new(1)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            ValidatorRole::Signer,
            &scheme_provider,
            &committee_provider,
            &manager,
            &ancestry,
        )
        .await
        .unwrap_err();
        assert!(wrong_kind.contains("omitted pending DKG BoundaryOutcome"));
    }

    #[tokio::test]
    async fn dealer_log_header_artifact_allows_foreign_valid_dealer() {
        let (keys, participants, _output, _polynomial, dealer_log) = dkg_runtime_artifacts();
        let validator_set = validator_set_from_keys(&keys);
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let manager = DkgManagerMailbox::new();
        manager
            .note_ceremony_started(Epoch::new(0), 7, None, participants)
            .unwrap();
        let block = block_with_header_artifact(&ConsensusHeaderArtifact::DealerLog(dealer_log));
        let ancestry = TestAncestryReader::ready();

        assert!(validate_header_consensus_artifacts(
            &block,
            None,
            Round::new(Epoch::new(0), View::new(2)),
            &keys[0].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            ValidatorRole::Signer,
            &scheme_provider,
            &committee_provider,
            &manager,
            &ancestry,
        )
        .await
        .is_ok());
        assert!(validate_header_consensus_artifacts(
            &block,
            None,
            Round::new(Epoch::new(0), View::new(2)),
            &keys[1].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            ValidatorRole::Signer,
            &scheme_provider,
            &committee_provider,
            &manager,
            &ancestry,
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn dealer_log_header_artifact_rejects_wrong_ceremony() {
        let (keys, participants, _output, _polynomial, dealer_log) = dkg_runtime_artifacts();
        let validator_set = validator_set_from_keys(&keys);
        let (scheme_provider, committee_provider) =
            leader_binding_providers(Epoch::new(0), &validator_set);
        let manager = DkgManagerMailbox::new();
        manager
            .note_ceremony_started(Epoch::new(0), 8, None, participants)
            .unwrap();
        let block = block_with_header_artifact(&ConsensusHeaderArtifact::DealerLog(dealer_log));
        let ancestry = TestAncestryReader::ready();

        assert!(validate_header_consensus_artifacts(
            &block,
            None,
            Round::new(Epoch::new(0), View::new(2)),
            &keys[1].public_key(),
            outbe_primitives::chain::CHAIN_ID,
            ValidatorRole::Signer,
            &scheme_provider,
            &committee_provider,
            &manager,
            &ancestry,
        )
        .await
        .is_err());
    }

    // Finalizer fatal forwarding and `ReplayClassification` tests moved.
    // - The forwarding tests are gone with the deleted finalizer worker.
    // - The replay-classification tests were ported alongside the helper
    //   into `crate::finalization::util` (step 17). See
    //   `finalization/util.rs::tests` for the same coverage.
}
