use alloy_primitives::{Address, Bytes, B256};
use alloy_rpc_types_engine::{PayloadStatus, PayloadStatusEnum};
use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::{
    marshal::{self, core::Buffer, resolver::handler, Start, Update},
    simplex::types::{Activity, Finalization, Finalize, Proposal},
    types::{Epoch, FixedEpocher, Round, View, ViewDelta},
    Reporter,
};
use commonware_cryptography::{
    bls12381::{self, primitives::variant::MinSig},
    certificate::Scheme as _,
    Signer as _,
};
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_resolver::Resolver;
use commonware_resolver::TargetedResolver;
use commonware_runtime::{buffer::paged::CacheRef, Clock as _, Runner as _, Supervisor as _};
use commonware_storage::archive::immutable;
use commonware_utils::{
    acknowledgement::Acknowledgement,
    channel::oneshot,
    ordered::{Quorum, Set},
    vec::NonEmptyVec,
    N3f1, TryCollect as _,
};
use outbe_primitives::projection::{
    projection_readiness, ProjectionCheckpoint, ProjectionFailure, ProjectionFailureClass,
    ProjectionReadinessPublisher, ProjectionStatus,
};
use outbe_primitives::{consensus_metadata::CertifiedParentAccountingMetadata, OutbeHeader};
use reth_ethereum::{primitives::SealedBlock, Block};
use std::{
    io,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};

use crate::ancestry_readiness::AncestryReadiness;
use crate::dkg_manager::Mailbox as DkgManagerMailbox;
use crate::finalization::attestation::{
    validate_consensus_metadata_for_verify, AttestationValidationContext, AttestationVerdict,
};
use crate::finalization::state::FinalizationViewAccess;
use crate::finalization::util::build_signer_bitmap;
use crate::hybrid::election::{HybridElectorConfigProvider, HybridRandom};
use crate::hybrid::{HybridScheme, HybridSchemeProvider};
use crate::ocomp_retention::{OcompRetentionHook, OcompRetentionHookError};
use crate::validators::ValidatorSet;
use crate::vrf_safety::VrfSafetyGate;

use super::{ApplicationShared, CommitteeProvider, ConsensusBlock, Digest};
use crate::application::epoch_boundary::{
    resolve_epoch_boundary_parent, ApplicationEpochFence, EpochBoundaryParentError,
};

struct TestApplicationShared {
    shared: ApplicationShared,
    _projection_publisher: ProjectionReadinessPublisher,
}

struct FixedUnixTimeSource(u64);

impl super::UnixTimeSource for FixedUnixTimeSource {
    fn now_millis(&self) -> eyre::Result<u64> {
        Ok(self.0)
    }
}

impl std::ops::Deref for TestApplicationShared {
    type Target = ApplicationShared;

    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}

static MARSHAL_TEST_ID: AtomicU64 = AtomicU64::new(0);

async fn metadata_verify_verdict(
    clock: &impl commonware_runtime::Clock,
    metadata: &CertifiedParentAccountingMetadata,
    provider: &HybridSchemeProvider<MinSig>,
    elector_provider: &HybridElectorConfigProvider<MinSig>,
    committee_provider: &CommitteeProvider,
    marshal_mailbox: &crate::marshal_types::MarshalMailbox,
    proposed_block_number: u64,
) -> AttestationVerdict {
    validate_consensus_metadata_for_verify(
        clock,
        Some(metadata),
        &AttestationValidationContext {
            certificate_scheme_provider: provider,
            elector_config_provider: elector_provider,
            committee_provider,
            marshal_mailbox,
            proposed_block_number,
        },
    )
    .await
}

#[derive(Clone, Default)]
struct CapturedLogWriter {
    bytes: Arc<StdMutex<Vec<u8>>>,
}

impl CapturedLogWriter {
    fn contents(&self) -> String {
        let bytes = self
            .bytes
            .lock()
            .expect("captured log writer mutex must not be poisoned")
            .clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

struct CapturedLogGuard {
    bytes: Arc<StdMutex<Vec<u8>>>,
}

impl io::Write for CapturedLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .expect("captured log writer mutex must not be poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogWriter {
    type Writer = CapturedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogGuard {
            bytes: self.bytes.clone(),
        }
    }
}

#[derive(Clone, Default)]
struct EmptyMarshalBuffer {
    pending_digest_subscribers: Arc<StdMutex<Vec<oneshot::Sender<ConsensusBlock>>>>,
    pending_commitment_subscribers: Arc<StdMutex<Vec<oneshot::Sender<ConsensusBlock>>>>,
}

impl Buffer<crate::marshal_types::Variant> for EmptyMarshalBuffer {
    // commonware 2026.5.0 dropped `type CachedBlock` (the block type is now
    // `V::Block`) and added `type PublicKey`.
    type PublicKey = bls12381::PublicKey;

    async fn find_by_digest(&self, _digest: Digest) -> Option<ConsensusBlock> {
        None
    }

    async fn find_by_commitment(&self, _commitment: Digest) -> Option<ConsensusBlock> {
        None
    }

    // `subscribe_by_*` are now SYNC and return `Option<oneshot::Receiver<..>>`.
    // We retain the pending sender (so the receiver never resolves) and hand
    // back `Some(rx)`, preserving the "block is never available" semantics this
    // empty buffer represents.
    fn subscribe_by_digest(&self, _digest: Digest) -> Option<oneshot::Receiver<ConsensusBlock>> {
        let (tx, rx) = oneshot::channel();
        self.pending_digest_subscribers
            .lock()
            .expect("pending digest subscriber mutex must not be poisoned")
            .push(tx);
        Some(rx)
    }

    fn subscribe_by_commitment(
        &self,
        _commitment: Digest,
    ) -> Option<oneshot::Receiver<ConsensusBlock>> {
        let (tx, rx) = oneshot::channel();
        self.pending_commitment_subscribers
            .lock()
            .expect("pending commitment subscriber mutex must not be poisoned")
            .push(tx);
        Some(rx)
    }

    // `finalized` is now SYNC; `proposed` was removed and replaced by `send`.
    fn finalized(&self, _commitment: Digest) {}

    fn send(
        &self,
        _round: Round,
        _block: ConsensusBlock,
        _recipients: Recipients<Self::PublicKey>,
    ) {
    }
}

/// Marshal buffer that records every `send` (the wire-broadcast hook).
///
/// commonware 2026.5.0 routes `marshal.forward(round, commitment, recipients)`
/// to `buffer.send(round, block, recipients)`, whereas `marshal.proposed(..)`
/// only caches locally. Recording `send` lets a test prove the broadcast
/// actually fired (BUG-A: the proposer kept the block only in its local cache).
#[derive(Clone, Default)]
struct RecordingMarshalBuffer {
    /// (round, block commitment, was Recipients::All) for each `send`.
    sends: Arc<StdMutex<Vec<(Round, Digest, bool)>>>,
}

impl Buffer<crate::marshal_types::Variant> for RecordingMarshalBuffer {
    type PublicKey = bls12381::PublicKey;

    async fn find_by_digest(&self, _digest: Digest) -> Option<ConsensusBlock> {
        None
    }

    async fn find_by_commitment(&self, _commitment: Digest) -> Option<ConsensusBlock> {
        None
    }

    fn subscribe_by_digest(&self, _digest: Digest) -> Option<oneshot::Receiver<ConsensusBlock>> {
        let (_tx, rx) = oneshot::channel();
        Some(rx)
    }

    fn subscribe_by_commitment(
        &self,
        _commitment: Digest,
    ) -> Option<oneshot::Receiver<ConsensusBlock>> {
        let (_tx, rx) = oneshot::channel();
        Some(rx)
    }

    fn finalized(&self, _commitment: Digest) {}

    fn send(&self, round: Round, block: ConsensusBlock, recipients: Recipients<Self::PublicKey>) {
        self.sends
            .lock()
            .expect("recording buffer sends mutex must not be poisoned")
            .push((round, block.digest(), matches!(recipients, Recipients::All)));
    }
}

#[derive(Clone, Default)]
struct AckingMarshalReporter;

impl Reporter for AckingMarshalReporter {
    type Activity = Update<ConsensusBlock, commonware_utils::acknowledgement::Exact>;

    // `report` is now SYNC and returns `Feedback` (commonware 2026.5.0). The
    // body is unchanged work (acknowledge delivered blocks); we always return
    // `Feedback::Ok` because this test reporter has no downstream mailbox that
    // can close.
    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = activity {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

#[derive(Clone, Default)]
struct NoopResolver;

// commonware 2026.5.0 split the resolver surface: the base `Resolver` keeps
// `fetch`/`fetch_all`/`retain` (now SYNC, returning `Feedback`, generic over
// `Into<Fetch<Key, Subscriber>>`) and gained `type Subscriber`; `cancel`/`clear`
// were removed; the targeted methods moved to `TargetedResolver`. The marshal
// actor requires `Key = handler::Key<Commitment>` and `Subscriber =
// handler::Annotation`.
impl Resolver for NoopResolver {
    type Key = handler::Key<Digest>;
    type Subscriber = handler::Annotation;

    fn fetch<F>(&mut self, _key: F) -> Feedback
    where
        F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }

    fn fetch_all<F>(&mut self, _keys: Vec<F>) -> Feedback
    where
        F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }

    fn retain(
        &mut self,
        _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        Feedback::Ok
    }
}

impl TargetedResolver for NoopResolver {
    type PublicKey = bls12381::PublicKey;

    fn fetch_targeted(
        &mut self,
        _fetch: impl Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        Feedback::Ok
    }

    fn fetch_all_targeted<F>(&mut self, _keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        Feedback::Ok
    }
}

/// Start the marshal actor wired to a no-op resolver.
///
/// commonware 2026.5.0 changed the resolver handoff: the marshal actor now
/// takes `(handler::Receiver<Commitment>, R)` where `R: TargetedResolver`,
/// instead of a raw `mpsc::Sender<handler::Message>` (now a private type, so
/// it cannot be named or constructed by tests). The receiver is produced by
/// `handler::init`, which also yields a `Handler` (the Consumer/Producer the
/// p2p resolver engine would normally drive). For these availability-driven
/// tests the resolver never delivers, so we keep the `Handler` alive as the
/// keepalive: dropping it closes `handler::Receiver`, which makes the marshal
/// actor's `run` loop shut down ("handler closed").
///
/// The previous `make_resolver`/generic `R` indirection is removed because
/// every call site used `NoopResolver`.
async fn start_marshal_with_resolver<B>(
    context: commonware_runtime::deterministic::Context,
    provider: HybridSchemeProvider<MinSig>,
    buffer: B,
) -> (
    crate::marshal_types::MarshalMailbox,
    handler::Handler<Digest>,
    commonware_runtime::Handle<()>,
)
where
    B: Buffer<crate::marshal_types::Variant, PublicKey = bls12381::PublicKey>,
{
    let page_cache = CacheRef::from_pooler(
        &context,
        NonZeroU16::new(1024).expect("non-zero page size"),
        NonZeroUsize::new(10).expect("non-zero cache size"),
    );
    let test_id = MARSHAL_TEST_ID.fetch_add(1, Ordering::SeqCst);
    let partition_prefix = format!("handler-finalized-regression-{test_id}");
    let items_per_section = NonZeroU64::new(10).expect("non-zero items per section");
    let replay_buffer = NonZeroUsize::new(1024).expect("non-zero replay buffer");
    let write_buffer = NonZeroUsize::new(1024).expect("non-zero write buffer");

    let finalizations_archive = immutable::Archive::init(
        context.child("marshal_finalizations"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-finalizations-metadata"),
            freezer_table_partition: format!("{partition_prefix}-finalizations-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-finalizations-freezer-key"),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!("{partition_prefix}-finalizations-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-finalizations-ordinal"),
            items_per_section,
            codec_config: HybridScheme::<MinSig>::certificate_codec_config_unbounded(),
            replay_buffer,
            freezer_key_write_buffer: write_buffer,
            freezer_value_write_buffer: write_buffer,
            ordinal_write_buffer: write_buffer,
        },
    )
    .await
    .expect("finalizations archive should initialize");

    let blocks_archive = immutable::Archive::init(
        context.child("marshal_blocks"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-blocks-metadata"),
            freezer_table_partition: format!("{partition_prefix}-blocks-freezer-table"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 10,
            freezer_table_resize_chunk_size: 10,
            freezer_key_partition: format!("{partition_prefix}-blocks-freezer-key"),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!("{partition_prefix}-blocks-freezer-value"),
            freezer_value_target_size: 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition_prefix}-blocks-ordinal"),
            items_per_section,
            codec_config: (),
            replay_buffer,
            freezer_key_write_buffer: write_buffer,
            freezer_value_write_buffer: write_buffer,
            ordinal_write_buffer: write_buffer,
        },
    )
    .await
    .expect("blocks archive should initialize");

    let (actor, mailbox, _) = marshal::core::Actor::init(
        context.child("marshal"),
        finalizations_archive,
        blocks_archive,
        marshal::Config {
            provider,
            epocher: FixedEpocher::new(NonZeroU64::new(10_000).expect("non-zero epoch")),
            // 2026.5.0: the floor/genesis anchor is now an explicit `Start`.
            // A fresh epoch starts from the height-0 genesis block (the actor
            // asserts the anchor height is zero).
            start: Start::Genesis(consensus_block_with_number(0x00, 0)),
            partition_prefix,
            // `mailbox_size` is now `NonZeroUsize`.
            mailbox_size: NonZeroUsize::new(32).expect("non-zero mailbox size"),
            view_retention_timeout: ViewDelta::new(10_000),
            prunable_items_per_section: items_per_section,
            page_cache,
            replay_buffer,
            key_write_buffer: write_buffer,
            value_write_buffer: write_buffer,
            block_codec_config: (),
            max_repair: NonZeroUsize::new(10).expect("non-zero max repair"),
            max_pending_acks: NonZeroUsize::new(1).expect("non-zero pending acks"),
            strategy: Sequential,
        },
    )
    .await;

    // 2026.5.0: build the resolver receiver/handler pair via `handler::init`.
    // The `Handler` is returned as the keepalive; the marshal actor receives
    // `(receiver, NoopResolver)`.
    let (resolver_rx, resolver_handler) = handler::init::<Digest>(
        context.child("resolver_handler"),
        NonZeroUsize::new(16).expect("non-zero resolver mailbox size"),
    );
    let handle = actor.start(AckingMarshalReporter, buffer, (resolver_rx, NoopResolver));
    (mailbox, resolver_handler, handle)
}

async fn start_marshal_without_available_block(
    context: commonware_runtime::deterministic::Context,
) -> (
    crate::marshal_types::MarshalMailbox,
    handler::Handler<Digest>,
    commonware_runtime::Handle<()>,
) {
    start_marshal_with_resolver(
        context,
        HybridSchemeProvider::<MinSig>::new(),
        EmptyMarshalBuffer::default(),
    )
    .await
}

/// Construct an `ApplicationShared` for verify-path tests.
///
/// After step 21 the application handler no longer owns the
/// finalization-side state (forkchoice / `last_finalized_*` / VRF seed),
/// so the helper is reduced: the only inputs needed for verify-side
/// coverage are the marshal mailbox and the certificate scheme
/// provider. Finalization-side regressions live in
/// `crate::finalization::actor` (shared `FinalizationView` + actor
/// handle_finalized).
fn finalizer_test_shared(
    marshal_mailbox: crate::marshal_types::MarshalMailbox,
    provider: HybridSchemeProvider<MinSig>,
) -> TestApplicationShared {
    let (engine_tx, _engine_rx) = tokio::sync::mpsc::unbounded_channel();
    let engine: super::EngineHandle = super::EngineHandle::new(engine_tx);
    let payload_builder: super::PayloadBuilder = super::PayloadBuilder::noop();
    let (executor_tx, _executor_rx) = futures::channel::mpsc::unbounded();
    let finalization_view = crate::finalization::state::new_finalization_view(B256::ZERO, 0, None);
    let finalization_block_cache = crate::finalization::block_cache::BlockCache::new();
    let baseline = ProjectionCheckpoint {
        block_number: 0,
        block_hash: B256::ZERO,
    };
    let (projection_publisher, projection_readiness) = projection_readiness(
        baseline,
        ProjectionStatus::Ready {
            checkpoint: baseline,
        },
    );

    let elector_config_provider = HybridElectorConfigProvider::new();
    let committee_provider = CommitteeProvider::new();
    let selector = crate::finalization::selection::ParentProofSelector::new(
        crate::finalization::parent_cert_store::FinalizedParentCertStore::new(),
    );
    let _ = (
        provider.clone(),
        elector_config_provider.clone(),
        committee_provider.clone(),
        marshal_mailbox.clone(),
    );

    let shared = ApplicationShared {
        unix_time_source: Arc::new(super::SystemUnixTimeSource),
        engine,
        payload_builder,
        executor_mailbox: crate::executor::Mailbox::from_sender(executor_tx),
        genesis_hash: B256::ZERO,
        validators: ValidatorSet {
            public_keys: Vec::new(),
            addresses: Vec::new(),
            p2p_addresses: Vec::new(),
        },
        chain_id: outbe_primitives::chain::CHAIN_ID,
        ocomp_lifecycle_activation: outbe_primitives::system_tx::OcompLifecycleActivation::Disabled,
        marshal_mailbox,
        certificate_scheme_provider: provider,
        elector_config_provider,
        committee_provider,
        dkg_manager: DkgManagerMailbox::new(),
        vrf_safety: VrfSafetyGate::new(4, 0, 10_000, 100),
        epoch_fence: ApplicationEpochFence::new(Epoch::new(0)),
        ancestry_readiness: AncestryReadiness::new(0, 0),
        projection_readiness,
        payload_resolve_time: Duration::from_millis(1),
        min_block_time: Duration::from_millis(1),
        proposer_evm_address: None,
        proposal_failure_log_limiter: Arc::new(crate::util::rate_limit::LogRateLimiter::new(
            super::PROPOSAL_FAILURE_LOG_WINDOW,
        )),
        finalization_view,
        block_cache: finalization_block_cache,
        finalization_selector: selector,
        trust_el_head: false,
        late_sig_store: crate::finalization::late_sig_store::shared(
            outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K,
        ),
        ocomp_retention: Arc::new(crate::ocomp_retention::NoopOcompRetentionHook),
    };
    TestApplicationShared {
        shared,
        _projection_publisher: projection_publisher,
    }
}

#[test]
fn projected_parent_gate_uses_existing_response_closure_as_its_budget() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let baseline = ProjectionCheckpoint {
            block_number: 0,
            block_hash: B256::ZERO,
        };
        let (_publisher, readiness) =
            projection_readiness(baseline, ProjectionStatus::CatchingUp { checkpoint: None });
        let (mut response, receiver) = oneshot::channel::<bool>();
        drop(receiver);

        let outcome = super::wait_for_projected_parent(
            readiness,
            ProjectionCheckpoint {
                block_number: 1,
                block_hash: B256::repeat_byte(0x11),
            },
            response.closed(),
        )
        .await
        .expect("a closed request budget must withhold instead of failing");

        assert_eq!(outcome, super::ParentProjectionGate::Withhold);
    });
}

#[test]
fn projected_parent_gate_requires_the_exact_checkpoint() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        let required = ProjectionCheckpoint {
            block_number: 1,
            block_hash: B256::repeat_byte(0x11),
        };
        let baseline = ProjectionCheckpoint {
            block_number: 0,
            block_hash: B256::ZERO,
        };
        let (_publisher, ready) = projection_readiness(
            baseline,
            ProjectionStatus::Ready {
                checkpoint: required,
            },
        );
        assert_eq!(
            super::wait_for_projected_parent(ready, required, std::future::pending())
                .await
                .expect("the exact projected parent must be ready"),
            super::ParentProjectionGate::Ready
        );

        let ahead = ProjectionCheckpoint {
            block_number: 2,
            block_hash: B256::repeat_byte(0x22),
        };
        let (_publisher, ahead_readiness) =
            projection_readiness(baseline, ProjectionStatus::Ready { checkpoint: ahead });
        assert_eq!(
            super::wait_for_projected_parent(ahead_readiness, required, std::future::pending())
                .await
                .expect("an ahead projection must withhold instead of voting"),
            super::ParentProjectionGate::Withhold
        );

        let (_publisher, fatal_readiness) = projection_readiness(
            baseline,
            ProjectionStatus::Fatal {
                checkpoint: None,
                error: ProjectionFailure::new(
                    ProjectionFailureClass::CheckpointMismatch,
                    "test checkpoint mismatch",
                ),
            },
        );
        let error =
            super::wait_for_projected_parent(fatal_readiness, required, std::future::pending())
                .await
                .expect_err("a fatal projection state must propagate to the existing error path");
        assert!(error.to_string().contains("test checkpoint mismatch"));
    });
}

struct ImportedBeforeRetentionHook {
    imported: Arc<AtomicBool>,
    prepared: Arc<AtomicBool>,
}

impl OcompRetentionHook for ImportedBeforeRetentionHook {
    fn prepare_candidate(&self, _block: &ConsensusBlock) -> Result<(), OcompRetentionHookError> {
        if !self.imported.load(Ordering::SeqCst) {
            return Err(OcompRetentionHookError::new(
                "candidate execution was not imported before retention",
            ));
        }
        self.prepared.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn reconcile_finalized(&self, _block: &ConsensusBlock) -> Result<(), OcompRetentionHookError> {
        Ok(())
    }
}

#[test]
fn locally_built_candidate_is_execution_visible_before_retention_ack() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        use reth_ethereum::node::api::BeaconEngineMessage;

        let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
        let engine = super::EngineHandle::new(engine_tx);
        let imported = Arc::new(AtomicBool::new(false));
        let prepared = Arc::new(AtomicBool::new(false));
        let hook = ImportedBeforeRetentionHook {
            imported: imported.clone(),
            prepared: prepared.clone(),
        };
        let block = consensus_block_with_number(0x71, 9);

        let prepare = super::prepare_built_candidate(
            &engine,
            &hook,
            &block,
            outbe_primitives::projection::ExecutionReadBudget::new(),
        );
        let execution = async {
            let message = engine_rx
                .recv()
                .await
                .expect("candidate import reaches the execution engine");
            let BeaconEngineMessage::NewPayload { payload, tx } = message else {
                panic!("candidate preparation must use new_payload");
            };
            assert_eq!(
                reth_node_builder::ExecutionPayload::block_hash(&payload),
                block.block_hash()
            );
            imported.store(true, Ordering::SeqCst);
            tx.send(Ok(PayloadStatus::new(
                PayloadStatusEnum::Valid,
                Some(block.block_hash()),
            )))
            .expect("execution status receiver remains live");
        };

        let (prepared_result, ()) = futures::join!(prepare, execution);
        prepared_result.expect("VALID execution is followed by durable retention");
        assert!(prepared.load(Ordering::SeqCst));
    });
}

#[test]
fn locally_built_candidate_is_not_retained_when_execution_is_not_ready() {
    commonware_runtime::deterministic::Runner::default().start(|_| async move {
        use reth_ethereum::node::api::BeaconEngineMessage;

        let (engine_tx, mut engine_rx) = tokio::sync::mpsc::unbounded_channel();
        let engine = super::EngineHandle::new(engine_tx);
        let imported = Arc::new(AtomicBool::new(false));
        let prepared = Arc::new(AtomicBool::new(false));
        let hook = ImportedBeforeRetentionHook {
            imported,
            prepared: prepared.clone(),
        };
        let block = consensus_block_with_number(0x72, 10);

        let prepare = super::prepare_built_candidate(
            &engine,
            &hook,
            &block,
            outbe_primitives::projection::ExecutionReadBudget::new(),
        );
        let execution = async {
            let BeaconEngineMessage::NewPayload { tx, .. } = engine_rx
                .recv()
                .await
                .expect("candidate import reaches the execution engine")
            else {
                panic!("candidate preparation must use new_payload");
            };
            tx.send(Ok(PayloadStatus::from_status(PayloadStatusEnum::Syncing)))
                .expect("execution status receiver remains live");
        };

        let (prepared_result, ()) = futures::join!(prepare, execution);
        assert!(prepared_result.is_err());
        assert!(!prepared.load(Ordering::SeqCst));
    });
}

/// bp-1 / BUG-A regression: opt3 dissemination. The proposer caches its block
/// into marshal at propose time (`handle_propose` -> `marshal.proposed`, making
/// it servable on demand), and `Relay::broadcast` then wire-pushes it by calling
/// `marshal.forward(round, commitment, Recipients::All)` DIRECTLY - never via
/// the bounded application mailbox (which could drop the trigger under
/// saturation). With a recording buffer we assert `Relay::broadcast` reaches the
/// `Buffer::send` wire-broadcast hook to ALL peers. If `Relay::broadcast`ever
/// stops forwarding (e.g. reverts to the droppable mailbox hop), this fails.
#[test]
fn relay_broadcast_forwards_proposed_block_directly_to_all_peers() {
    // Runs on the deterministic runtime (mirrors `marshal_resolver_p2p_tests.rs`)
    // so the marshal storage-thread-pool teardown does not produce nextest
    // "(N leaky)" false-positives under load (TC-6).
    commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            let provider = HybridSchemeProvider::<MinSig>::new();
            let recorder = RecordingMarshalBuffer::default();
            let sends = recorder.sends.clone();
            let (marshal_mailbox, _keepalive, _actor) =
                start_marshal_with_resolver(context.child("marshal"), provider, recorder).await;

            // Propose-time caching (what handle_propose does): the block is stashed
            // in marshal so it is servable and `forward` has something to take.
            let round = Round::new(Epoch::new(0), View::new(1));
            let block = consensus_block_with_number(0xAB, 7);
            let digest = block.digest();
            let _durable = marshal_mailbox.proposed(round, block).await;

            // Relay::broadcast must forward DIRECTLY to marshal (no app-mailbox hop).
            let (mut app, _app_rx) =
                crate::application::actor::OutbeApplication::new(16, marshal_mailbox.clone());
            use commonware_consensus::Relay as _;
            let _feedback = app.broadcast(
                digest,
                commonware_consensus::simplex::Plan::Propose { round },
            );

            // `forward()` is fire-and-forget; wait (bounded) for the marshal actor to
            // process Message::Forward -> Buffer::send.
            let mut forwarded_to_all = false;
            for _ in 0..400 {
                let found = sends
                    .lock()
                    .expect("recording buffer sends mutex must not be poisoned")
                    .iter()
                    .any(|(_, sent, is_all)| *sent == digest && *is_all);
                if found {
                    forwarded_to_all = true;
                    break;
                }
                context.sleep(Duration::from_millis(5)).await;
            }
            assert!(
                forwarded_to_all,
                "Relay::broadcast must call marshal.forward(.., Recipients::All) so the proposed \
             block is broadcast to all peers (bp-1/BUG-A); no wire-push was observed"
            );
        },
    );
}

/// SD-6: `forward()` WITHOUT a prior `proposed()` is a safe no-op - marshal has
/// nothing stashed for `take_proposed`, so `Buffer::send` is never called (no
/// panic, no wrong send). In opt3 `handle_propose` always proposes before
/// `Relay::broadcast` forwards, so this guards the fallback. A follow-up
/// `proposed()`+`forward()` then DOES reach `Buffer::send`, proving the marshal
/// is alive and the earlier no-op was specifically the no-prior-proposed case.
#[test]
fn forward_without_prior_proposed_is_safe_noop() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_consensus::Relay as _;
            let provider = HybridSchemeProvider::<MinSig>::new();
            let recorder = RecordingMarshalBuffer::default();
            let sends = recorder.sends.clone();
            let (marshal_mailbox, _keepalive, _actor) =
                start_marshal_with_resolver(context.child("marshal"), provider, recorder).await;
            let (mut app, _app_rx) =
                crate::application::actor::OutbeApplication::new(16, marshal_mailbox.clone());

            let round = Round::new(Epoch::new(0), View::new(1));
            let block = consensus_block_with_number(0xCD, 9);
            let digest = block.digest();

            // forward WITHOUT a prior proposed(): nothing stashed -> no-op.
            let _ = app.broadcast(
                digest,
                commonware_consensus::simplex::Plan::Propose { round },
            );
            for _ in 0..40 {
                context.sleep(Duration::from_millis(5)).await;
            }
            assert!(
                sends
                    .lock()
                    .expect("sends mutex must not be poisoned")
                    .is_empty(),
                "forward() without a prior proposed() must be a no-op (nothing to take_proposed)"
            );

            // proposed() THEN forward() -> a send is recorded (marshal alive; no-op above
            // was the no-prior-proposed fallback, not a dead actor).
            let _durable = marshal_mailbox.proposed(round, block).await;
            let _ = app.broadcast(
                digest,
                commonware_consensus::simplex::Plan::Propose { round },
            );
            let mut sent = false;
            for _ in 0..400 {
                if sends
                    .lock()
                    .expect("sends mutex must not be poisoned")
                    .iter()
                    .any(|(_, d, all)| *d == digest && *all)
                {
                    sent = true;
                    break;
                }
                context.sleep(Duration::from_millis(5)).await;
            }
            assert!(
                sent,
                "after proposed(), forward() must reach Buffer::send to all peers"
            );
        },
    );
}

#[test]
fn exact_parent_wait_drains_block_number_mismatch() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let drained = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            let (marshal_mailbox, _resolver_keepalive, actor_handle) =
                start_marshal_without_available_block(context).await;
            use crate::finalization::parent_cert_store::{
                CertifiedParentProofKey, CertifiedParentProofRecord, CertifiedParentProofStore,
                FinalizedParentCertStore, ProofKind,
            };
            let store = FinalizedParentCertStore::new();
            let parent_hash = B256::with_last_byte(0xAA);
            store
                .put_finalization(CertifiedParentProofRecord {
                    kind: ProofKind::Finalization {
                        finalized_block_number: 41,
                    },
                    finalized_block_hash: parent_hash,
                    finalized_epoch: 1,
                    finalized_view: 7,
                    parent_view: 6,
                    ordered_committee: vec![Address::with_last_byte(1)],
                    signer_bitmap: vec![1],
                    encoded_proof: Bytes::from_static(b"cert"),
                    stored_at_height: 41,
                    ..CertifiedParentProofRecord::default()
                })
                .unwrap();

            let selector = crate::finalization::selection::ParentProofSelector::new(store.clone());
            let _ = marshal_mailbox;
            let result = selector.select_direct_parent_proof(1, 7, 42, parent_hash);

            actor_handle.abort();
            let _ = actor_handle.await;
            result.is_none()
                && store
                    .get_finalization(CertifiedParentProofKey::new(1, 7, parent_hash))
                    .is_none()
        },
    );

    assert!(
        drained,
        "block-number-mismatched exact-parent records must be drained fail-closed"
    );
}

#[test]
fn epoch_boundary_parent_uses_finalized_round_for_exact_proof_key() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let resolved = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            // `Supervisor::child` yields an owned clock before `context` is moved
            // into `start_marshal_*`; `Context` is not `Clone` on 2026.5.0.
            use commonware_runtime::Supervisor as _;
            let clock = context.child("verify");
            let (marshal_mailbox, resolver_keepalive, actor_handle) =
                start_marshal_without_available_block(context).await;
            let shared = finalizer_test_shared(
                marshal_mailbox.clone(),
                HybridSchemeProvider::<MinSig>::new(),
            );

            let finalized_round = Round::new(Epoch::new(0), View::new(241));
            let parent_block = consensus_block_with_number(0x42, 120);
            let parent_digest = parent_block.digest();
            let _ = marshal_mailbox
                .proposed(finalized_round, parent_block.clone())
                .await;

            {
                let mut view = shared.finalization_view.write();
                view.last_finalized_number = parent_block.number();
                view.forkchoice.finalized_block_hash = parent_digest.0;
                view.forkchoice.safe_block_hash = parent_digest.0;
                view.forkchoice.head_block_hash = parent_digest.0;
                view.last_finalized_round = Some(finalized_round);
            }

            let child_round = Round::new(Epoch::new(1), View::new(1));
            let anchor = resolve_epoch_boundary_parent(
                &shared.finalization_view,
                &shared.marshal_mailbox,
                &clock,
                child_round,
                View::new(0),
                parent_digest,
            )
            .await
            .unwrap()
            .unwrap();
            let expected_key = crate::finalization::parent_cert_store::CertifiedParentProofKey::new(
                finalized_round.epoch().get(),
                finalized_round.view().get(),
                parent_digest.0,
            );
            let ok = anchor.height.get() == parent_block.number()
                && anchor.block.digest() == parent_digest
                && anchor.proof_key == expected_key;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            ok
        },
    );

    assert!(
        resolved,
        "epoch-boundary parent must carry the finalized block's original proof key"
    );
}

/// marshal-4 regression: epoch-boundary anchor resolution uses
/// `DigestFallback::Wait` (local-only). When `FinalizationView` already exposes
/// the anchor hash but the marshal store has not yet durably stored the block
/// (the lagging-store race at the first slot of a new epoch), the `Wait`
/// subscription times out and `resolve_epoch_boundary_parent` returns
/// `MissingMarshalBlock` - a deterministic forfeit signal. This must NOT hang
/// or panic; the proposer simply forfeits the boundary slot until marshal
/// catches up.
#[test]
fn epoch_boundary_anchor_wait_miss_forfeits_slot_not_stall() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let outcome = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let clock = context.child("verify");
            let (marshal_mailbox, resolver_keepalive, actor_handle) =
                start_marshal_without_available_block(context).await;
            let shared = finalizer_test_shared(
                marshal_mailbox.clone(),
                HybridSchemeProvider::<MinSig>::new(),
            );

            let finalized_round = Round::new(Epoch::new(0), View::new(241));
            let parent_block = consensus_block_with_number(0x42, 120);
            let parent_digest = parent_block.digest();

            // FinalizationView has the anchor hash, but we deliberately do NOT
            // `marshal.proposed(parent_block)` - the marshal store lags behind
            // FinalizationView (the epoch-boundary first-slot race).
            {
                let mut view = shared.finalization_view.write();
                view.last_finalized_number = parent_block.number();
                view.forkchoice.finalized_block_hash = parent_digest.0;
                view.last_finalized_round = Some(finalized_round);
            }

            let child_round = Round::new(Epoch::new(1), View::new(1));
            let outcome = resolve_epoch_boundary_parent(
                &shared.finalization_view,
                &shared.marshal_mailbox,
                &clock,
                child_round,
                View::new(0),
                parent_digest,
            )
            .await;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            outcome
        },
    );

    // Deterministic forfeit (MissingMarshalBlock), not a hang or a panic, and
    // not a false `Ok(Some(_))` against a block the store does not have.
    assert!(
        matches!(
            outcome,
            Err(EpochBoundaryParentError::MissingMarshalBlock { height }) if height == 120
        ),
        "epoch-boundary anchor miss must forfeit via MissingMarshalBlock; got {outcome:?}"
    );
}

fn consensus_block_with_number(seed: u8, number: u64) -> ConsensusBlock {
    let mut block = Block::default();
    block.header.number = number;
    block.header.extra_data = Bytes::from(vec![seed]);
    let block = block.map_header(OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

fn consensus_block_with_timestamp(seed: u8, number: u64, timestamp_millis: u64) -> ConsensusBlock {
    assert_eq!(timestamp_millis % 1_000, 0);
    let mut block = Block::default();
    block.header.number = number;
    block.header.timestamp = timestamp_millis / 1_000;
    block.header.extra_data = Bytes::from(vec![seed]);
    let block = block.map_header(OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

#[test]
fn forfeited_build_does_not_advance_retry_timestamp_source() {
    const BAND: u64 = outbe_primitives::consensus::MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS;
    let parent_timestamp = 1_781_255_987_000u64;

    commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let clock = context.child("timestamp_retry");
            let (marshal_mailbox, resolver_keepalive, actor_handle) =
                start_marshal_without_available_block(context).await;
            let mut shared =
                finalizer_test_shared(marshal_mailbox, HybridSchemeProvider::<MinSig>::new());
            shared.shared.unix_time_source = Arc::new(FixedUnixTimeSource(
                parent_timestamp.saturating_add(10 * BAND),
            ));
            shared
                .finalization_view
                .advance_timestamp_floor(parent_timestamp);

            let parent = consensus_block_with_timestamp(0x54, 42, parent_timestamp);
            let parent_digest = parent.digest();
            let proof_key = crate::finalization::parent_cert_store::CertifiedParentProofKey::new(
                0,
                1,
                parent_digest.0,
            );
            let round = Round::new(Epoch::new(0), View::new(2));

            for _ in 0..2 {
                let outcome = shared
                    .build_block(
                        &clock,
                        round,
                        commonware_consensus::types::Height::new(parent.number()),
                        parent_digest,
                        Some(parent.clone()),
                        Some(proof_key),
                        std::time::SystemTime::now(),
                        outbe_primitives::projection::ExecutionReadBudget::default(),
                        super::ProposalPayloadTrace::default(),
                    )
                    .await
                    .expect("missing parent proof must forfeit without a handler failure");
                assert!(matches!(
                    outcome,
                    super::BuildBlockOutcome::ParentProofUnavailable
                ));
                assert_eq!(shared.finalization_view.timestamp_floor(), parent_timestamp);
            }

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
        },
    );
}

fn finalization_metadata_fixture(
    block: &ConsensusBlock,
    round: Round,
) -> (
    HybridSchemeProvider<MinSig>,
    CommitteeProvider,
    CertifiedParentAccountingMetadata,
    Finalization<HybridScheme<MinSig>, Digest>,
) {
    let parent = round.view().previous().unwrap_or(View::zero());
    finalization_metadata_fixture_with_parent(block, round, parent)
}

fn finalization_metadata_fixture_with_parent(
    block: &ConsensusBlock,
    round: Round,
    parent: View,
) -> (
    HybridSchemeProvider<MinSig>,
    CommitteeProvider,
    CertifiedParentAccountingMetadata,
    Finalization<HybridScheme<MinSig>, Digest>,
) {
    let FinalizationMetadataContext {
        scheme_provider,
        committee_provider,
        signers,
        verifier,
        committee,
    } = finalization_metadata_context(round.epoch());
    let (metadata, finalization) =
        finalization_metadata_from_context(block, round, parent, &signers, &verifier, committee);

    (scheme_provider, committee_provider, metadata, finalization)
}

struct FinalizationMetadataContext {
    scheme_provider: HybridSchemeProvider<MinSig>,
    committee_provider: CommitteeProvider,
    signers: Vec<HybridScheme<MinSig>>,
    verifier: HybridScheme<MinSig>,
    committee: Vec<Address>,
}

fn finalization_metadata_context(epoch: Epoch) -> FinalizationMetadataContext {
    let keys: Vec<bls12381::PrivateKey> = (0..3)
        .map(|i| bls12381::PrivateKey::from_seed(i + 1))
        .collect();
    let participants: Set<bls12381::PublicKey> = keys
        .iter()
        .map(|sk| bls12381::PublicKey::from(sk.clone()))
        .try_collect()
        .expect("participants should build");
    let dkg = crate::bls::bootstrap_dkg(3).expect("bootstrap dkg should succeed");
    let signers: Vec<HybridScheme<MinSig>> = keys
        .iter()
        .map(|key| {
            let pk = bls12381::PublicKey::from(key.clone());
            let idx = participants.index(&pk).expect("participant should exist");
            HybridScheme::signer(
                &crate::config::outbe_app_namespace(),
                participants.clone(),
                key.clone(),
                dkg.polynomial.clone(),
                dkg.shares[idx.get() as usize].clone(),
            )
            .expect("signer should build")
        })
        .collect();

    let verifier = HybridScheme::<MinSig>::verifier(
        &crate::config::outbe_app_namespace(),
        participants,
        dkg.polynomial.clone(),
    )
    .expect("verifier should build");
    let scheme_provider = HybridSchemeProvider::<MinSig>::new();
    let committee_provider = CommitteeProvider::new();
    let committee = vec![
        Address::with_last_byte(1),
        Address::with_last_byte(2),
        Address::with_last_byte(3),
    ];
    let _ = scheme_provider.register(epoch, verifier.clone());
    let _ = committee_provider.register(epoch, committee.clone());

    FinalizationMetadataContext {
        scheme_provider,
        committee_provider,
        signers,
        verifier,
        committee,
    }
}

fn finalization_metadata_from_context(
    block: &ConsensusBlock,
    round: Round,
    parent: View,
    signers: &[HybridScheme<MinSig>],
    verifier: &HybridScheme<MinSig>,
    committee: Vec<Address>,
) -> (
    CertifiedParentAccountingMetadata,
    Finalization<HybridScheme<MinSig>, Digest>,
) {
    let proposal = Proposal::new(round, parent, block.digest());
    let finalizes = signers
        .iter()
        .map(|signer| Finalize::sign(signer, proposal.clone()).expect("finalize vote"))
        .collect::<Vec<_>>();
    let certificate = verifier
        .assemble::<_, N3f1>(
            finalizes
                .iter()
                .map(|finalize| finalize.attestation.clone()),
            &Sequential,
        )
        .expect("finalization certificate should assemble");

    let finalization = Finalization {
        proposal: proposal.clone(),
        certificate: certificate.clone(),
    };
    let metadata = CertifiedParentAccountingMetadata {
        finalized_block_number: block.number(),
        finalized_block_hash: block.digest().0,
        finalized_epoch: round.epoch().get(),
        finalized_view: round.view().get(),
        parent_view: parent.get(),
        ordered_committee: committee,
        signer_bitmap: build_signer_bitmap(&certificate, 3),
        proof: Bytes::from(finalization.encode()),
        ..Default::default()
    };

    (metadata, finalization)
}

async fn wait_for_marshal_info(
    clock: &impl commonware_runtime::Clock,
    mailbox: &crate::marshal_types::MarshalMailbox,
    digest: Digest,
) -> Option<(commonware_consensus::types::Height, Digest)> {
    // Runtime-clock bounded poll (deterministic-runtime friendly): poll the
    // marshal mapping until it appears or the deadline elapses. A wall-clock async
    // timer does not advance under the deterministic runtime, so use `Clock` here.
    let deadline = clock.current() + Duration::from_secs(2);
    loop {
        if let Some(info) = mailbox.get_info(&digest).await {
            return Some(info);
        }
        if clock.current() >= deadline {
            return None;
        }
        clock.sleep(Duration::from_millis(10)).await;
    }
}

#[test]
fn consensus_metadata_verify_accepts_canonical_marshal_mapping() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let accepted = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let round = Round::new(Epoch::new(0), View::new(5));
            let block = consensus_block_with_number(0x51, 5);
            let digest = block.digest();
            let (provider, committee_provider, metadata, finalization) =
                finalization_metadata_fixture(&block, round);
            let elector_provider = HybridElectorConfigProvider::<MinSig>::new();
            let clock = context.child("verify");
            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            let _ = marshal_mailbox.proposed(round, block).await;
            let mut reporter = marshal_mailbox.clone();
            // 2026.5.0: `Reporter::report` is SYNC and returns `Feedback`.
            let _ = reporter.report(Activity::Finalization(finalization));
            let info = wait_for_marshal_info(&clock, &marshal_mailbox, digest).await;

            let accepted = info.is_some()
                && metadata_verify_verdict(
                    &clock,
                    &metadata,
                    &provider,
                    &elector_provider,
                    &committee_provider,
                    &marshal_mailbox,
                    6,
                )
                .await
                    == AttestationVerdict::AcceptValid;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            accepted
        },
    );

    assert!(
        accepted,
        "metadata whose hash maps to the same finalized height in marshal must pass"
    );
}

// regression: the proposer's in-process selection store can miss the direct
// parent's proof (post-restart, late-joining validator, brief finalization lag),
// but marshal's DURABLE finalization archive may still hold it locally. Recovery
// rebuilds the canonical parent-proof record so the slot is NOT forfeited. This
// drives `recover_parent_proof_from_marshal` - the exact branch `build_block`
// takes on a selection-store miss - and asserts: happy path recovers, the
// hash-exact guard rejects a different parent, and a missing archive entry yields
// None (deterministic forfeit, not a fabricated record).
#[test]
fn parent_proof_recovered_from_marshal_archive_on_selection_miss() {
    use crate::finalization::parent_cert_store::CertifiedParentProofKey;
    commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let epoch = Epoch::new(0);
            let round = Round::new(epoch, View::new(5));
            let parent_height = 4u64;
            let block = consensus_block_with_number(0x71, parent_height);
            let digest = block.digest();
            let (scheme_provider, committee_provider, _metadata, finalization) =
                finalization_metadata_fixture(&block, round);
            let committee = (*committee_provider
                .ordered_committee(epoch)
                .expect("fixture registers the committee"))
            .clone();
            let clock = context.child("recover");

            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                scheme_provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            // Seed marshal's durable archive: propose the parent block (servable)
            // and report its finalization, so `get_finalization(height)` returns it
            // - the post-restart state where the in-process selection store is
            // empty but marshal still holds the parent.
            let _ = marshal_mailbox.proposed(round, block.clone()).await;
            let mut reporter = marshal_mailbox.clone();
            let _ = reporter.report(Activity::Finalization(finalization));
            let info = wait_for_marshal_info(&clock, &marshal_mailbox, digest).await;
            assert!(
                info.is_some(),
                "marshal must hold the seeded parent finalization before recovery"
            );

            let shared = finalizer_test_shared(marshal_mailbox.clone(), scheme_provider);
            // Recovery resolves the committee for the finalization's epoch.
            let _ = shared.committee_provider.register(epoch, committee);

            // Happy path: key hash matches the seeded finalization -> recovered.
            let key_ok = CertifiedParentProofKey::new(epoch.get(), round.view().get(), digest.0);
            let recovered = shared
                .recover_parent_proof_from_marshal(key_ok, parent_height)
                .await
                .expect("matching parent finalization in marshal must be recovered, not forfeited");
            assert_eq!(recovered.finalized_block_hash, digest.0);
            assert_eq!(recovered.finalized_block_number(), Some(parent_height));

            // Hash-exact guard: a finalization for a DIFFERENT parent hash must not
            // be accepted (prevents recovering the wrong parent).
            let key_wrong_hash = CertifiedParentProofKey::new(
                epoch.get(),
                round.view().get(),
                B256::repeat_byte(0xEE),
            );
            assert!(
                shared
                    .recover_parent_proof_from_marshal(key_wrong_hash, parent_height)
                    .await
                    .is_none(),
                "hash-exact guard must reject a finalization for a different parent"
            );

            // Missing height: nothing in the archive -> None (deterministic forfeit).
            assert!(
                shared
                    .recover_parent_proof_from_marshal(key_ok, parent_height + 99)
                    .await
                    .is_none(),
                "absent finalization must yield None (forfeit), not a fabricated record"
            );

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
        },
    );
}

// P4-T4 unit-seam regression: after a crash where the executor/Reth finalized
// parent N but FinalizationActor had not yet persisted the local
// FinalizedParentCertStore record, restart sees an empty in-process selection
// store while marshal's durable archive still contains N's finalization. The
// proposal selector must take the same recovery branch that build_block uses and
// return a canonical exact-parent proof instead of forfeiting the N+1 slot.
#[test]
fn parent_proof_selector_recovers_from_marshal_after_empty_store_restart() {
    use crate::finalization::parent_cert_store::CertifiedParentProofKey;
    commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let epoch = Epoch::new(0);
            let finalized_round = Round::new(epoch, View::new(5));
            let child_round = Round::new(epoch, View::new(6));
            let parent_height = 4u64;
            let parent_block = consensus_block_with_number(0x74, parent_height);
            let parent_digest = parent_block.digest();
            let (scheme_provider, committee_provider, _metadata, finalization) =
                finalization_metadata_fixture(&parent_block, finalized_round);
            let committee = (*committee_provider
                .ordered_committee(epoch)
                .expect("fixture registers the committee"))
            .clone();
            let clock = context.child("p4_t4_selector_recovery");

            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                scheme_provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            // Crash-window seed: marshal archive is durable/retained, but the
            // post-restart ApplicationShared below has a fresh empty
            // FinalizedParentCertStore via finalizer_test_shared(...).
            let _ = marshal_mailbox
                .proposed(finalized_round, parent_block.clone())
                .await;
            let mut reporter = marshal_mailbox.clone();
            let _ = reporter.report(Activity::Finalization(finalization));
            assert!(
                wait_for_marshal_info(&clock, &marshal_mailbox, parent_digest)
                    .await
                    .is_some(),
                "marshal must retain the finalized parent archive entry"
            );

            let shared = finalizer_test_shared(marshal_mailbox.clone(), scheme_provider);
            let _ = shared.committee_provider.register(epoch, committee);
            let key = CertifiedParentProofKey::new(
                epoch.get(),
                finalized_round.view().get(),
                parent_digest.0,
            );

            let lookup = shared
                .select_parent_proof_for_proposal(
                    &clock,
                    child_round,
                    parent_digest,
                    commonware_consensus::types::Height::new(parent_height),
                    Some(key),
                )
                .await;
            let record = match lookup {
                super::ParentProofLookup::Found(record) => record,
                super::ParentProofLookup::NoProofNeeded => {
                    panic!("non-genesis parent must require a proof")
                }
                super::ParentProofLookup::Unavailable => {
                    panic!("marshal archive recovery must prevent parent-proof forfeit")
                }
            };
            assert_eq!(record.finalized_block_hash, parent_digest.0);
            assert_eq!(record.finalized_block_number(), Some(parent_height));
            let metadata = record.to_v2_metadata(parent_height);
            assert_eq!(metadata.finalized_block_hash, parent_digest.0);
            assert_eq!(metadata.finalized_block_number, parent_height);

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
        },
    );
}

#[test]
fn consensus_metadata_verify_accepts_canonical_missed_proposers() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let accepted = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let epoch = Epoch::new(0);
            let FinalizationMetadataContext {
                scheme_provider: provider,
                committee_provider,
                signers,
                verifier,
                committee,
            } = finalization_metadata_context(epoch);
            let elector_provider = HybridElectorConfigProvider::<MinSig>::new();
            let _ = elector_provider.register(epoch, HybridRandom::default());
            let clock = context.child("verify");

            let previous_round = Round::new(epoch, View::new(5));
            let previous_block = consensus_block_with_number(0x61, 4);
            let (_, previous_finalization) = finalization_metadata_from_context(
                &previous_block,
                previous_round,
                View::new(4),
                &signers,
                &verifier,
                committee.clone(),
            );

            let current_round = Round::new(epoch, View::new(8));
            let current_block = consensus_block_with_number(0x62, 5);
            let current_digest = current_block.digest();
            let (mut metadata, current_finalization) = finalization_metadata_from_context(
                &current_block,
                current_round,
                View::new(5),
                &signers,
                &verifier,
                committee,
            );
            metadata.missed_proposers = vec![
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 1,
                    validator: Address::with_last_byte(1),
                },
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 2,
                    validator: Address::with_last_byte(2),
                },
            ];

            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            let _ = marshal_mailbox
                .proposed(previous_round, previous_block.clone())
                .await;
            let mut reporter = marshal_mailbox.clone();
            // 2026.5.0: `Reporter::report` is SYNC and returns `Feedback`.
            let _ = reporter.report(Activity::Finalization(previous_finalization));
            let _ = marshal_mailbox.proposed(current_round, current_block).await;
            // 2026.5.0: `Reporter::report` is SYNC and returns `Feedback`.
            let _ = reporter.report(Activity::Finalization(current_finalization));

            let current_info =
                wait_for_marshal_info(&clock, &marshal_mailbox, current_digest).await;
            let previous_info =
                wait_for_marshal_info(&clock, &marshal_mailbox, previous_block.digest()).await;
            let accepted = current_info.is_some()
                && previous_info.is_some()
                && metadata_verify_verdict(
                    &clock,
                    &metadata,
                    &provider,
                    &elector_provider,
                    &committee_provider,
                    &marshal_mailbox,
                    6,
                )
                .await
                    == AttestationVerdict::AcceptValid;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            accepted
        },
    );

    assert!(
        accepted,
        "canonical missed proposer list must pass verify-time metadata validation"
    );
}

#[test]
fn consensus_metadata_verify_rejects_forged_missed_proposers() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let rejected = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let epoch = Epoch::new(0);
            let FinalizationMetadataContext {
                scheme_provider: provider,
                committee_provider,
                signers,
                verifier,
                committee,
            } = finalization_metadata_context(epoch);
            let elector_provider = HybridElectorConfigProvider::<MinSig>::new();
            let _ = elector_provider.register(epoch, HybridRandom::default());
            let clock = context.child("verify");

            let previous_round = Round::new(epoch, View::new(5));
            let previous_block = consensus_block_with_number(0x63, 4);
            let (_, previous_finalization) = finalization_metadata_from_context(
                &previous_block,
                previous_round,
                View::new(4),
                &signers,
                &verifier,
                committee.clone(),
            );

            let current_round = Round::new(epoch, View::new(8));
            let current_block = consensus_block_with_number(0x64, 5);
            let current_digest = current_block.digest();
            let (mut metadata, current_finalization) = finalization_metadata_from_context(
                &current_block,
                current_round,
                View::new(5),
                &signers,
                &verifier,
                committee,
            );
            metadata.missed_proposers = vec![
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 1,
                    validator: Address::with_last_byte(2),
                },
                outbe_primitives::consensus_metadata::MissedProposerEvent {
                    view: 2,
                    validator: Address::with_last_byte(1),
                },
            ];

            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            let _ = marshal_mailbox
                .proposed(previous_round, previous_block.clone())
                .await;
            let mut reporter = marshal_mailbox.clone();
            // 2026.5.0: `Reporter::report` is SYNC and returns `Feedback`.
            let _ = reporter.report(Activity::Finalization(previous_finalization));
            let _ = marshal_mailbox.proposed(current_round, current_block).await;
            // 2026.5.0: `Reporter::report` is SYNC and returns `Feedback`.
            let _ = reporter.report(Activity::Finalization(current_finalization));

            let current_info =
                wait_for_marshal_info(&clock, &marshal_mailbox, current_digest).await;
            let previous_info =
                wait_for_marshal_info(&clock, &marshal_mailbox, previous_block.digest()).await;
            let rejected = current_info.is_some()
                && previous_info.is_some()
                && metadata_verify_verdict(
                    &clock,
                    &metadata,
                    &provider,
                    &elector_provider,
                    &committee_provider,
                    &marshal_mailbox,
                    6,
                )
                .await
                    != AttestationVerdict::AcceptValid;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            rejected
        },
    );

    assert!(
        rejected,
        "non-canonical missed proposer order/content must be rejected"
    );
}

#[test]
fn consensus_metadata_verify_rejects_inflated_finalized_number() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let rejected = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let round = Round::new(Epoch::new(0), View::new(5));
            let block = consensus_block_with_number(0x52, 5);
            let digest = block.digest();
            let (provider, committee_provider, mut metadata, finalization) =
                finalization_metadata_fixture(&block, round);
            let elector_provider = HybridElectorConfigProvider::<MinSig>::new();
            let clock = context.child("verify");
            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            let _ = marshal_mailbox.proposed(round, block).await;
            let mut reporter = marshal_mailbox.clone();
            // 2026.5.0: `Reporter::report` is SYNC and returns `Feedback`.
            let _ = reporter.report(Activity::Finalization(finalization));
            let info = wait_for_marshal_info(&clock, &marshal_mailbox, digest).await;
            metadata.finalized_block_number = 6;

            let rejected = info.is_some()
                && metadata_verify_verdict(
                    &clock,
                    &metadata,
                    &provider,
                    &elector_provider,
                    &committee_provider,
                    &marshal_mailbox,
                    7,
                )
                .await
                    != AttestationVerdict::AcceptValid;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            rejected
        },
    );

    assert!(
        rejected,
        "valid cert/hash with forged finalized number must fail marshal canonical check"
    );
}

#[test]
fn consensus_metadata_verify_rejects_missing_marshal_mapping() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let rejected = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            use commonware_runtime::Supervisor as _;
            let round = Round::new(Epoch::new(0), View::new(5));
            let block = consensus_block_with_number(0x53, 5);
            let (provider, committee_provider, metadata, _finalization) =
                finalization_metadata_fixture(&block, round);
            let elector_provider = HybridElectorConfigProvider::<MinSig>::new();
            let clock = context.child("verify");
            let (marshal_mailbox, resolver_keepalive, actor_handle) = start_marshal_with_resolver(
                context,
                provider.clone(),
                EmptyMarshalBuffer::default(),
            )
            .await;

            let rejected = metadata_verify_verdict(
                &clock,
                &metadata,
                &provider,
                &elector_provider,
                &committee_provider,
                &marshal_mailbox,
                6,
            )
            .await
                != AttestationVerdict::AcceptValid;

            drop(resolver_keepalive);
            actor_handle.abort();
            let _ = actor_handle.await;
            rejected
        },
    );

    assert!(
        rejected,
        "metadata must not pass when the finalized hash is absent from marshal history"
    );
}

#[test]
fn resolve_for_verify_timeout_logs_full_context() {
    // Deterministic runtime (TC-6): avoids marshal teardown leaky false-positives.
    let (resolved_as_timeout, logs) = commonware_runtime::deterministic::Runner::timed(
        Duration::from_secs(30),
    )
    .start(|context| async move {
        use commonware_runtime::Supervisor as _;
        let log_writer = CapturedLogWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(log_writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let clock = context.child("verify");
        let (marshal_mailbox, resolver_keepalive, actor_handle) =
            start_marshal_without_available_block(context).await;
        let shared = finalizer_test_shared(marshal_mailbox, HybridSchemeProvider::<MinSig>::new());

        let round = Round::new(Epoch::new(0), View::new(1201));
        let digest = Digest(B256::repeat_byte(0xA7));
        let result = crate::application::verify_resolution::resolve_for_verify(
            &shared.block_cache,
            &shared.marshal_mailbox,
            &clock,
            round,
            digest,
            crate::application::verify_resolution::VerifyResolveTarget::Block,
        )
        .await;

        drop(resolver_keepalive);
        actor_handle.abort();
        let _ = actor_handle.await;

        (
            matches!(
                result,
                Err(crate::application::verify_resolution::VerifyResolveError::Timeout)
            ),
            log_writer.contents(),
        )
    });

    assert!(
        resolved_as_timeout,
        "verify resolve must exercise the Timeout branch"
    );
    assert!(
        logs.contains("verify resolve started"),
        "start log missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("verify resolve finished"),
        "finish log missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("target=\"block\""),
        "target missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("source=\"marshal\""),
        "source missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("result=\"Timeout\""),
        "result missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("elapsed_ms="),
        "elapsed missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("round=(0, 1201)"),
        "round missing; logs:\n{logs}"
    );
    assert!(
        logs.contains("digest=0xa7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"),
        "digest missing; logs:\n{logs}"
    );
}

// ---------------------------------------------------------------------------
// Minimum-block-time pacing (proposer-side liveness floor).
// ---------------------------------------------------------------------------

/// Tests 1-4: pure floor arithmetic (`min - elapsed`, saturating).
#[test]
fn floor_remaining_arithmetic() {
    use super::floor_remaining;
    // Case A - empty/fast block: most of the floor remains.
    assert_eq!(
        floor_remaining(Duration::from_millis(2000), Duration::from_millis(250)),
        Duration::from_millis(1750)
    );
    // Case B - exec < min: wait the remainder.
    assert_eq!(
        floor_remaining(Duration::from_millis(2000), Duration::from_millis(1300)),
        Duration::from_millis(700)
    );
    // Case C - exec >= min: no wait (saturates to zero).
    assert_eq!(
        floor_remaining(Duration::from_millis(2000), Duration::from_millis(2400)),
        Duration::ZERO
    );
    // Zero floor: always zero (mechanism level; min=0 is rejected at config).
    assert_eq!(
        floor_remaining(Duration::ZERO, Duration::from_millis(123)),
        Duration::ZERO
    );
}

/// Test 5: with a held receiver and a non-trivial floor, `pace_and_send` waits
/// ~`remaining` of virtual time and then delivers the digest.
#[test]
fn floor_sends_after_remainder() {
    let (received, waited) = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(
        30,
    ))
    .start(|context| async move {
        let (tx, rx) = oneshot::channel::<Digest>();
        let t0 = context.current();
        super::pace_and_send(
            &context,
            tx,
            Digest(B256::ZERO),
            Duration::from_millis(2000),
            t0,
        )
        .await;
        let waited = context.current().duration_since(t0).unwrap_or_default();
        (rx.await.ok(), waited)
    });
    assert_eq!(received, Some(Digest(B256::ZERO)));
    assert!(
        waited >= Duration::from_millis(2000),
        "expected to wait the floor, waited {waited:?}"
    );
}

/// Test 6 (the `select!` guard): if the proposal receiver is dropped (view
/// cancelled), `pace_and_send` aborts promptly via `response.closed()` and does
/// not sleep the full floor.
#[test]
fn floor_aborts_on_closed_receiver() {
    let waited = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
        |context| async move {
            let (tx, rx) = oneshot::channel::<Digest>();
            drop(rx); // Simplex dropped the proposal receiver on a view change.
            let t0 = context.current();
            super::pace_and_send(
                &context,
                tx,
                Digest(B256::ZERO),
                Duration::from_millis(2000),
                t0,
            )
            .await;
            context.current().duration_since(t0).unwrap_or_default()
        },
    );
    assert!(
        waited < Duration::from_millis(2000),
        "aborted pacing must not sleep the full floor, waited {waited:?}"
    );
}

/// Test 7: zero remaining (case C / floor already met) sends immediately with no
/// sleep - control-flow identical to pre-pacing behavior.
#[test]
fn floor_zero_sends_immediately() {
    let (received, waited) = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(
        30,
    ))
    .start(|context| async move {
        let (tx, rx) = oneshot::channel::<Digest>();
        let t0 = context.current();
        super::pace_and_send(&context, tx, Digest(B256::ZERO), Duration::ZERO, t0).await;
        let waited = context.current().duration_since(t0).unwrap_or_default();
        (rx.await.ok(), waited)
    });
    assert_eq!(received, Some(Digest(B256::ZERO)));
    assert_eq!(waited, Duration::ZERO);
}

/// Test 13 (pacing-invisibility parity, unit level): the proposer hands Simplex a
/// byte-identical digest regardless of the min-block-time floor. The build path is
/// structurally floor-agnostic - `build_block` / `handle_propose` take no
/// `min_block_time`, so the floor cannot influence block bytes - and
/// `pace_and_send` only delays delivery of the already-sealed digest. This loops
/// over the no-wait (case C, floor 0) and wait paths (250ms..5s) and asserts the
/// delivered digest never changes.
///
/// Full proposer/validator EVM parity (equal post-block state root, event log,
/// balance deltas, and block hash) requires a running node and is exercised by the
/// localnet smoke run (Test 15); there is no in-process build harness to seal a
/// real EVM block (handler_tests builds with `PayloadBuilder::noop()`).
#[test]
fn pacing_delivers_identical_digest_for_any_floor() {
    let digest = Digest(B256::repeat_byte(0x5a));
    for floor_ms in [0u64, 250, 2000, 5000] {
        let delivered = commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30))
            .start(|context| async move {
                let (tx, rx) = oneshot::channel::<Digest>();
                let t0 = context.current();
                super::pace_and_send(&context, tx, digest, Duration::from_millis(floor_ms), t0)
                    .await;
                rx.await.ok()
            });
        assert_eq!(
            delivered,
            Some(digest),
            "floor {floor_ms}ms must deliver the byte-identical digest"
        );
    }
}
