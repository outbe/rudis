//! Multi-node deterministic Simplex harness for cross-node Mux race
//! tests.
//!
//! What it models, faithfully:
//!
//! - `simulated::Network<deterministic::Context, bls12381::PublicKey>`
//!   peer fabric - same shape as production's authenticated::lookup
//!   network from outside the engine.
//! - Per-node `Muxer::new(...)` over each of three physical channels
//!   (vote=0, cert=1, res=2). **No `.with_backup()`** - matches
//!   production's stack.rs:516-534.
//! - `HybridScheme::<MinSig>::signer(...)` from outbe-consensus' own
//!   `crate::hybrid` module - the actual signer construction.
//! - `simplex::Engine::new(...)` driven by `RoundRobin` elector with
//!   leader = `(epoch + view) % n`.
//! - The harness invokes `crate::epoch_subchannels::register_epoch_subchannels`
//!   and `crate::epoch_subchannels::take_or_register_current` - the
//!   exact functions production calls in stack.rs at DKG completion
//!   and the top of `'epoch_loop` respectively. Toggling
//!   `CycleOptions::use_pre_registration` switches between the
//!   pre-fix lazy path and the post-fix pre-register path.
//!
//! What is mocked locally (not via `commonware_consensus::simplex::mocks`,
//! which is feature-gated and would propagate via cargo feature
//! unification):
//!
//! - `MockAutomaton` (Automaton + CertifiableAutomaton) - deterministic
//!   propose/verify/certify, no payload latency.
//! - `MockRelay` (Relay) - shared digest -> bytes broadcast store; the
//!   digest remains self-describing for the mock automaton.
//! - `MockReporter` (Reporter) - records `Finalization` activities by
//!   view and exposes `view_finalized(View) -> bool` so tests can
//!   ask the precise question "did view N finalize on this node?",
//!   insulated from later-view recovery.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use commonware_codec::Encode as _;
use commonware_consensus::simplex::types::{Activity, Context};
use commonware_consensus::simplex::Engine;
use commonware_consensus::types::{Epoch, Round, View, ViewDelta};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay as ConsensusRelay, Reporter as ConsensusReporter,
    Viewable as _,
};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_cryptography::{bls12381, Hasher as _, Sha256, Signer as _};
use commonware_p2p::simulated::{Config as SimConfig, Link, Network};
use commonware_p2p::utils::mux::Muxer;
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{deterministic, Clock, Quota, Spawner, Supervisor as _};
use commonware_utils::channel::fallible::OneshotExt as _;
use commonware_utils::channel::{mpsc, oneshot};
use commonware_utils::ordered::Set as OrderedSet;
use commonware_utils::sync::Mutex as CommonwareMutex;
use commonware_utils::TryCollect as _;
use std::num::NonZeroU32;
use tokio::sync::Mutex as TokioMutex;

use crate::bls::bootstrap_dkg;
use crate::epoch_subchannels::{
    register_epoch_subchannels, take_or_register_current, EpochSubchannels,
};
use crate::hybrid::HybridScheme;

fn namespace() -> Vec<u8> {
    crate::config::outbe_app_namespace()
}
const VOTES_CHANNEL: u64 = crate::config::VOTES_CHANNEL;
const CERTIFICATES_CHANNEL: u64 = crate::config::CERTIFICATES_CHANNEL;
const RESOLVER_CHANNEL: u64 = crate::config::RESOLVER_CHANNEL;
const MUXER_MAILBOX: usize = 64;
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const PAGE_SIZE: NonZeroU16 = match NonZeroU16::new(1024) {
    Some(n) => n,
    None => unreachable!(),
};
const PAGE_CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(10) {
    Some(n) => n,
    None => unreachable!(),
};
const REPLAY_BUFFER: NonZeroUsize = match NonZeroUsize::new(1024 * 1024) {
    Some(n) => n,
    None => unreachable!(),
};
const WRITE_BUFFER: NonZeroUsize = match NonZeroUsize::new(64 * 1024) {
    Some(n) => n,
    None => unreachable!(),
};

// ------------------------------------------------------------------
// Local mocks
// ------------------------------------------------------------------

#[derive(Clone)]
pub struct MockAutomaton {
    me: bls12381::PublicKey,
}

impl MockAutomaton {
    pub fn new(me: bls12381::PublicKey) -> Self {
        Self { me }
    }
}

/// Genesis digest for `epoch`. Preserves the exact pre-image the removed
/// `Automaton::genesis` produced so `Floor::Genesis(mock_genesis(epoch))`
/// stays byte-identical to the pre-2026.5.0 genesis digest.
pub fn mock_genesis(epoch: Epoch) -> Sha256Digest {
    let mut hasher = Sha256::default();
    hasher.update(b"outbe-test-harness/genesis");
    hasher.update(&epoch.get().to_be_bytes());
    hasher.finalize()
}

impl Automaton for MockAutomaton {
    type Context = Context<Sha256Digest, bls12381::PublicKey>;
    type Digest = Sha256Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let mut hasher = Sha256::default();
        hasher.update(b"outbe-test-harness/propose");
        hasher.update(&context.round.epoch().get().to_be_bytes());
        hasher.update(&context.round.view().get().to_be_bytes());
        hasher.update(&context.parent.0.get().to_be_bytes());
        hasher.update(&context.parent.1.encode());
        hasher.update(&context.leader.encode());
        let digest = hasher.finalize();
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(digest);
        rx
    }

    async fn verify(
        &mut self,
        _context: Self::Context,
        _payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(true);
        rx
    }
}

impl CertifiableAutomaton for MockAutomaton {
    async fn certify(&mut self, _round: Round, _payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(true);
        rx
    }
}

#[derive(Clone, Default)]
pub struct MockRelay {
    payloads: Arc<CommonwareMutex<HashMap<Sha256Digest, bytes::Bytes>>>,
}

impl MockRelay {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConsensusRelay for MockRelay {
    type Digest = Sha256Digest;
    type PublicKey = commonware_cryptography::bls12381::PublicKey;
    type Plan = commonware_consensus::simplex::Plan<commonware_cryptography::bls12381::PublicKey>;

    fn broadcast(
        &mut self,
        payload: Self::Digest,
        _plan: Self::Plan,
    ) -> commonware_actor::Feedback {
        // The mock store is in-memory and never closes; with
        // `ForwardingPolicy::Disabled` the engine only emits
        // `Plan::Propose`, so storing the self-describing digest for
        // every plan is behaviour-preserving. Always accepted.
        self.payloads
            .lock()
            .insert(payload, bytes::Bytes::copy_from_slice(payload.as_ref()));
        commonware_actor::Feedback::Ok
    }
}

#[derive(Clone, Default)]
pub struct MockReporter {
    finalized_views: Arc<CommonwareMutex<std::collections::HashSet<View>>>,
    latest_view: Arc<CommonwareMutex<View>>,
    finalized_signers: Arc<CommonwareMutex<HashMap<View, Vec<u32>>>>,
}

impl MockReporter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn view_finalized(&self, view: View) -> bool {
        self.finalized_views.lock().contains(&view)
    }

    pub fn latest_finalized_view(&self) -> View {
        *self.latest_view.lock()
    }

    pub fn finalized_signers(&self, view: View) -> Vec<u32> {
        self.finalized_signers
            .lock()
            .get(&view)
            .cloned()
            .unwrap_or_default()
    }
}

impl ConsensusReporter for MockReporter {
    type Activity = Activity<HybridScheme<MinSig>, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        if let Activity::Finalization(finalization) = activity {
            let view = finalization.view();
            self.finalized_signers.lock().insert(
                view,
                finalization
                    .certificate
                    .signers
                    .iter()
                    .map(|signer| signer.get())
                    .collect(),
            );
            let mut finalized = self.finalized_views.lock();
            finalized.insert(view);
            let mut latest = self.latest_view.lock();
            if view > *latest {
                *latest = view;
            }
        }
        // In-memory sink, never closes.
        commonware_actor::Feedback::Ok
    }
}

// ------------------------------------------------------------------
// Per-node state
// ------------------------------------------------------------------

type SimSender = commonware_p2p::simulated::Sender<bls12381::PublicKey, deterministic::Context>;
type SimReceiver = commonware_p2p::simulated::Receiver<bls12381::PublicKey>;
type Mux = commonware_p2p::utils::mux::MuxHandle<SimSender, SimReceiver>;
/// Mux handles cannot be `Clone` because `simulated::Receiver` is
/// not `Clone` (mpsc::UnboundedReceiver is single-consumer). Wrap in
/// `Arc<TokioMutex>` so per-node tasks can register sub-channels
/// concurrently without taking ownership.
type SharedMux = Arc<TokioMutex<Mux>>;
type Stash = Option<EpochSubchannels<SimSender, SimReceiver>>;

struct Node {
    signing_key: bls12381::PrivateKey,
    pubkey: bls12381::PublicKey,
    vote_mux: SharedMux,
    cert_mux: SharedMux,
    res_mux: SharedMux,
    blocker: commonware_p2p::simulated::Control<bls12381::PublicKey, deterministic::Context>,
    reporter: MockReporter,
    relay: MockRelay,
    automaton: MockAutomaton,
}

// ------------------------------------------------------------------
// Public harness API
// ------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CycleOptions {
    pub dkg_completion_delay_per_node: HashMap<usize, Duration>,
    pub activation_delay_per_node: HashMap<usize, Duration>,
    pub use_pre_registration: bool,
    pub leader_timeout: Duration,
    pub run_for: Duration,
}

impl Default for CycleOptions {
    fn default() -> Self {
        Self {
            dkg_completion_delay_per_node: HashMap::new(),
            activation_delay_per_node: HashMap::new(),
            use_pre_registration: true,
            leader_timeout: Duration::from_millis(500),
            run_for: Duration::from_millis(1000),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CycleOutcome {
    pub finalized_view_per_node: Vec<View>,
    pub view_finalized_per_node: Vec<bool>,
    pub view_one_signers_per_node: Vec<Vec<u32>>,
    pub leader_index: usize,
}

impl CycleOutcome {
    pub fn followers(&self) -> impl Iterator<Item = usize> + '_ {
        let leader = self.leader_index;
        (0..self.finalized_view_per_node.len()).filter(move |i| *i != leader)
    }

    pub fn all_finalized_view_one(&self) -> bool {
        self.view_finalized_per_node.iter().all(|f| *f)
    }
}

pub struct Harness {
    ctx: deterministic::Context,
    nodes: Vec<Node>,
    polynomial: commonware_cryptography::bls12381::primitives::sharing::Sharing<MinSig>,
    shares: Vec<commonware_cryptography::bls12381::primitives::group::Share>,
    participants: OrderedSet<bls12381::PublicKey>,
    invalid_seed_partial_nodes: HashSet<usize>,
}

impl Harness {
    pub async fn new(ctx: &deterministic::Context, n: usize) -> Self {
        assert!(n >= 2, "harness needs at least 2 nodes");

        // 1. Generate n BLS private keys, then sort by encoded public key
        // bytes - matches `ordered::Set` ordering, which is the
        // ordering simplex/HybridScheme indexes by.
        let mut keys: Vec<bls12381::PrivateKey> = (0u64..n as u64)
            .map(|seed| bls12381::PrivateKey::from_seed(seed.wrapping_add(1)))
            .collect();
        keys.sort_by(|a, b| {
            commonware_codec::Encode::encode(&a.public_key())
                .cmp(&commonware_codec::Encode::encode(&b.public_key()))
        });

        let participants: OrderedSet<bls12381::PublicKey> = keys
            .iter()
            .map(|k| k.public_key())
            .try_collect()
            .expect("participants must build from sorted unique keys");

        // 2. Bootstrap DKG. `bootstrap_dkg(n)` produces shares whose
        // `share.index` matches the participant position by
        // construction - the keys are already sorted, so shares[i]
        // corresponds to participants.index(keys[i].public_key()).
        let dkg = bootstrap_dkg(n as u32).expect("bootstrap_dkg");
        let polynomial = dkg.polynomial.clone();
        let shares = dkg.shares.clone();

        // 3. Build the simulated network.
        let (network, oracle) = Network::new(
            ctx.child("network"),
            SimConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: commonware_utils::NZUsize!(4),
            },
        );
        network.start();

        // 4. Create per-node muxers and link all peers bidirectionally.
        let shared_relay = MockRelay::new();
        let mut nodes = Vec::with_capacity(n);
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let pubkey = keys[i].public_key();
            let control = oracle.control(pubkey.clone());
            let (votes_tx, votes_rx) = control
                .register(VOTES_CHANNEL, TEST_QUOTA)
                .await
                .expect("register vote physical channel");
            let (certs_tx, certs_rx) = control
                .register(CERTIFICATES_CHANNEL, TEST_QUOTA)
                .await
                .expect("register cert physical channel");
            let (res_tx, res_rx) = control
                .register(RESOLVER_CHANNEL, TEST_QUOTA)
                .await
                .expect("register res physical channel");

            let (vote_muxer, vote_mux) = Muxer::new(
                ctx.child("vote_mux").with_attribute("index", i),
                votes_tx,
                votes_rx,
                MUXER_MAILBOX,
            );
            vote_muxer.start();
            let (cert_muxer, cert_mux) = Muxer::new(
                ctx.child("cert_mux").with_attribute("index", i),
                certs_tx,
                certs_rx,
                MUXER_MAILBOX,
            );
            cert_muxer.start();
            let (res_muxer, res_mux) = Muxer::new(
                ctx.child("res_mux").with_attribute("index", i),
                res_tx,
                res_rx,
                MUXER_MAILBOX,
            );
            res_muxer.start();

            nodes.push(Node {
                signing_key: keys[i].clone(),
                pubkey: pubkey.clone(),
                vote_mux: Arc::new(TokioMutex::new(vote_mux)),
                cert_mux: Arc::new(TokioMutex::new(cert_mux)),
                res_mux: Arc::new(TokioMutex::new(res_mux)),
                blocker: control,
                reporter: MockReporter::new(),
                relay: shared_relay.clone(),
                automaton: MockAutomaton::new(pubkey),
            });
        }

        // Link all pairs bidirectionally.
        let link = Link {
            latency: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                oracle
                    .add_link(keys[i].public_key(), keys[j].public_key(), link.clone())
                    .await
                    .expect("link peers");
            }
        }

        // commonware 2026.4.0: the simulated network only routes to peers in a
        // tracked peer set; `add_link` alone no longer enables routing (it did
        // pre-2026.4.0). Track the full validator set at index 0 so consensus
        // vote/cert/resolver sends resolve to recipients.
        {
            use commonware_p2p::Manager as _;
            let peers = commonware_utils::ordered::Set::from_iter_dedup(
                keys.iter().map(|k| k.public_key()),
            );
            let _ = oracle.manager().track(0, peers);
        }

        Self {
            ctx: ctx.child("harness"),
            nodes,
            polynomial,
            shares,
            participants,
            invalid_seed_partial_nodes: HashSet::new(),
        }
    }

    /// Configure one node to emit a valid vote paired with an
    /// identity-attributable seed partial over the wrong message.
    pub fn inject_invalid_seed_partial(&mut self, node: usize) {
        assert!(
            node < self.nodes.len(),
            "fault node must belong to the committee"
        );
        self.invalid_seed_partial_nodes.insert(node);
    }

    /// Compute the leader for view 1 of `epoch` using the harness's
    /// RoundRobin elector. Test authors call this BEFORE building
    /// `CycleOptions` so timing knobs can be expressed in terms of
    /// leader / followers.
    pub fn leader_for_view_one(&self, epoch: Epoch) -> usize {
        let n = self.participants.len() as u64;
        ((epoch.get() + 1) % n) as usize
    }

    pub async fn run_cycle(&mut self, epoch: Epoch, options: CycleOptions) -> CycleOutcome {
        // Sanity check delays: activation must be >= dkg_completion.
        for (i, &activation) in &options.activation_delay_per_node {
            let dkg = options
                .dkg_completion_delay_per_node
                .get(i)
                .copied()
                .unwrap_or_default();
            assert!(
                activation >= dkg,
                "node {i} activation_delay ({:?}) must be >= dkg_completion_delay ({:?})",
                activation,
                dkg
            );
        }

        let leader_index = self.leader_for_view_one(epoch);
        let n = self.nodes.len();

        // Channel for each node to deliver its final reporter snapshot
        // back to the harness driver.
        let (result_tx, mut result_rx) = mpsc::channel::<(usize, MockReporter)>(n);

        // Kick a per-node task that performs (1) sleep until DKG
        // completion, (2) optional pre-register, (3) sleep until
        // activation, (4) take or register, (5) build scheme + engine,
        // (6) start engine, (7) run for `options.run_for`.
        for i in 0..n {
            let node = &mut self.nodes[i];
            let dkg_delay = options
                .dkg_completion_delay_per_node
                .get(&i)
                .copied()
                .unwrap_or_default();
            let activation_delay = options
                .activation_delay_per_node
                .get(&i)
                .copied()
                .unwrap_or_default();
            let use_pre_register = options.use_pre_registration;
            let leader_timeout = options.leader_timeout;
            let run_for = options.run_for;
            let participants = self.participants.clone();
            let polynomial = self.polynomial.clone();
            let share = self.shares[i].clone();
            let signing_key = node.signing_key.clone();
            let blocker = node.blocker.clone();
            let reporter = node.reporter.clone();
            let relay = node.relay.clone();
            let automaton = node.automaton.clone();
            let vote_mux = node.vote_mux.clone();
            let cert_mux = node.cert_mux.clone();
            let res_mux = node.res_mux.clone();
            let result_tx = result_tx.clone();
            let task_ctx = self.ctx.child("node").with_attribute("index", i);
            let inject_invalid_seed_partial = self.invalid_seed_partial_nodes.contains(&i);

            self.ctx
                .child("driver")
                .with_attribute("index", i)
                .spawn(move |_| async move {
                    // (1) DKG completion delay.
                    if !dkg_delay.is_zero() {
                        task_ctx.sleep(dkg_delay).await;
                    }
                    let mut stash: Stash = None;
                    // (2) Optional pre-register at modeled DKG completion.
                    if use_pre_register {
                        let mut vote_g = vote_mux.lock().await;
                        let mut cert_g = cert_mux.lock().await;
                        let mut res_g = res_mux.lock().await;
                        let registered = register_epoch_subchannels(
                            epoch,
                            &mut *vote_g,
                            &mut *cert_g,
                            &mut *res_g,
                        )
                        .await
                        .expect("pre-register subchannels");
                        stash = Some(registered);
                    }
                    // (3) Activation delay.
                    let remaining = activation_delay.saturating_sub(dkg_delay);
                    if !remaining.is_zero() {
                        task_ctx.sleep(remaining).await;
                    }
                    // (4) Take or register at activation time.
                    let subch = {
                        let mut vote_g = vote_mux.lock().await;
                        let mut cert_g = cert_mux.lock().await;
                        let mut res_g = res_mux.lock().await;
                        take_or_register_current(
                            epoch,
                            &mut stash,
                            &mut *vote_g,
                            &mut *cert_g,
                            &mut *res_g,
                        )
                        .await
                        .expect("take or register subchannels")
                    };
                    // (5) Build HybridScheme signer for this node.
                    let mut scheme = HybridScheme::<MinSig>::signer(
                        &namespace(),
                        participants.clone(),
                        signing_key,
                        polynomial.clone(),
                        share,
                    )
                    .expect("HybridScheme::signer");
                    if inject_invalid_seed_partial {
                        scheme = scheme.with_invalid_seed_partial_for_test();
                    }
                    // (6) Build & start Engine.
                    let elector_cfg =
                        commonware_consensus::simplex::elector::RoundRobin::<Sha256>::default();
                    let cfg = commonware_consensus::simplex::Config {
                        scheme,
                        elector: elector_cfg,
                        blocker,
                        automaton,
                        relay,
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        forwarding: commonware_consensus::simplex::ForwardingPolicy::Disabled,
                        partition: format!("harness_n{i}_e{}", epoch.get()),
                        mailbox_size: NonZeroUsize::new(256).expect("nonzero"),
                        epoch,
                        floor: commonware_consensus::simplex::Floor::Genesis(mock_genesis(epoch)),
                        replay_buffer: REPLAY_BUFFER,
                        write_buffer: WRITE_BUFFER,
                        page_cache: CacheRef::from_pooler(&task_ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                        leader_timeout,
                        certification_timeout: leader_timeout * 2,
                        timeout_retry: leader_timeout * 4,
                        activity_timeout: ViewDelta::new(64),
                        skip_timeout: ViewDelta::new(8),
                        fetch_timeout: leader_timeout,
                        fetch_concurrent: NonZeroUsize::new(2).expect("nonzero"),
                    };
                    let engine = Engine::new(
                        task_ctx
                            .child("engine")
                            .with_attribute("epoch", epoch.get()),
                        cfg,
                    );
                    let handle = engine.start(subch.vote, subch.cert, subch.res);

                    // (7) Run window: sleep until run_for elapsed from t=0.
                    // The activation point inside this task is at
                    // `dkg_delay + remaining = activation_delay`; we
                    // need to sleep an additional `run_for -
                    // activation_delay`.
                    let already_elapsed = activation_delay;
                    if run_for > already_elapsed {
                        task_ctx.sleep(run_for - already_elapsed).await;
                    }

                    // Stop engine and report.
                    handle.abort();
                    let _ = result_tx.try_send((i, reporter));
                });
        }

        // Drive the runtime forward until all per-node tasks finish.
        // Collect reporter snapshots in node-index order.
        drop(result_tx); // close so recv loop terminates after all nodes report
        let mut snapshots: Vec<Option<MockReporter>> = (0..n).map(|_| None).collect();
        let deadline = options.run_for + Duration::from_millis(200);
        let timeout_at = self.ctx.current() + deadline;
        loop {
            tokio::select! {
                Some((idx, reporter)) = result_rx.recv() => {
                    snapshots[idx] = Some(reporter);
                    if snapshots.iter().all(|s| s.is_some()) {
                        break;
                    }
                }
                _ = self.ctx.sleep_until(timeout_at) => {
                    break;
                }
            }
        }

        // Backfill any missing snapshots with the live reporter (per-task
        // didn't deliver in time - pull the reporter directly).
        let mut finalized_view_per_node = Vec::with_capacity(n);
        let mut view_finalized_per_node = Vec::with_capacity(n);
        let mut view_one_signers_per_node = Vec::with_capacity(n);
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let reporter = snapshots[i]
                .clone()
                .unwrap_or_else(|| self.nodes[i].reporter.clone());
            finalized_view_per_node.push(reporter.latest_finalized_view());
            view_finalized_per_node.push(reporter.view_finalized(View::new(1)));
            view_one_signers_per_node.push(reporter.finalized_signers(View::new(1)));
        }
        CycleOutcome {
            finalized_view_per_node,
            view_finalized_per_node,
            view_one_signers_per_node,
            leader_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::Runner as _;

    #[test]
    fn honest_simplex_nodes_exclude_invalid_seed_partial_and_finalize_with_clean_quorum() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|ctx| async move {
            let epoch = Epoch::new(2);
            let mut harness = Harness::new(&ctx, 4).await;
            let faulty = harness.leader_for_view_one(epoch);
            harness.inject_invalid_seed_partial(faulty);

            let outcome = harness
                .run_cycle(
                    epoch,
                    CycleOptions {
                        leader_timeout: Duration::from_millis(500),
                        run_for: Duration::from_millis(2_000),
                        ..Default::default()
                    },
                )
                .await;

            for (node, finalized) in outcome.view_finalized_per_node.iter().enumerate() {
                if node == faulty {
                    continue;
                }
                assert!(
                    finalized,
                    "honest node {node} must finalize from the three clean pairs: {:?}",
                    outcome.view_finalized_per_node
                );
            }
            for (node, signers) in outcome.view_one_signers_per_node.iter().enumerate() {
                if node == faulty {
                    // A Byzantine process may accept its own malformed local
                    // activity. The contract under test is what honest peers
                    // admit through the real network batcher/certificate gate.
                    continue;
                }
                assert_eq!(
                    signers.len(),
                    3,
                    "n=4 quorum must contain three clean pairs"
                );
                assert!(
                    !signers.contains(&(faulty as u32)),
                    "the invalid vote+partial pair must not enter the certificate"
                );
            }
        });
    }
}
