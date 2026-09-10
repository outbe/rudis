//! Two-node integration test for the REAL commonware marshal P2P resolver
//! pull/serve path (finding #6 / prf-5).
//!
//! # What this guards
//!
//! The marshal `resolver::p2p` `Recipients::One` pull/serve path is the only
//! consensus path with no automated in-repo coverage prior to this test. Every
//! other marshal test in this crate stubs the resolver (`NoopResolver`) and the
//! broadcast buffer (`EmptyMarshalBuffer` / `RecordingMarshalBuffer`), so they
//! never exercise the actual on-the-wire fetch where one node asks a peer for a
//! block it is missing and the peer serves it. That real path was previously
//! only exercised by the localnet (multi-process) harness.
//!
//! # What this test does
//!
//! Two marshal actors (node A and node B) run on a single `commonware_runtime`
//! deterministic runtime, connected by an in-process
//! `commonware_p2p::simulated::Network`. Each node runs the production wiring:
//! a real `marshal::resolver::p2p` resolver (registered on `MARSHAL_CHANNEL`)
//! and a real `commonware_broadcast::buffered::Engine` buffer (registered on
//! `BROADCAST_CHANNEL`), mirroring `crates/blockchain/engine/src/stack.rs`.
//!
//! Node A proposes + verifies a block and is told the matching notarization, so
//! it can serve the block when asked for the notarized proposal at that round.
//! Node B (which has never seen the block) calls
//! `subscribe_by_digest(digest, DigestFallback::FetchByRound { round })`. Its
//! resolver issues a `Notarized { round }` request over the simulated network;
//! node A's resolver serve-side answers with `(notarization, block)`; node B
//! verifies the threshold notarization against the shared epoch-0
//! `HybridScheme` verifier and delivers the block. The test asserts the
//! delivered block's digest equals node A's block digest - proving the real
//! `Recipients::One` resolver pull/serve path works end to end.

use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::time::Duration;

use commonware_broadcast::buffered;
use commonware_codec::Encode as _;
use commonware_consensus::{
    marshal::{self, core::DigestFallback, Start},
    simplex::types::{Activity, Notarization, Notarize, Proposal},
    types::{Epoch, FixedEpocher, Round, View, ViewDelta},
    Reporter as _,
};
use commonware_cryptography::{
    bls12381::{self, primitives::variant::MinSig},
    certificate::Scheme as _,
    Signer as _,
};
use commonware_p2p::{
    simulated::{Config as SimConfig, Link, Network},
    Manager as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Clock as _, Quota, Runner as _, Supervisor as _,
};
use commonware_storage::archive::immutable;
use commonware_utils::{
    ordered::{Quorum as _, Set},
    NZUsize, TryCollect as _, NZU32,
};

use alloy_primitives::Bytes;
use reth_ethereum::{primitives::SealedBlock, Block};

use crate::block::ConsensusBlock;
use crate::digest::Digest;
use crate::hybrid::{HybridScheme, HybridSchemeProvider};
use crate::marshal_types::MarshalMailbox;

fn namespace() -> Vec<u8> {
    crate::config::outbe_app_namespace()
}
const MARSHAL_CHANNEL: u64 = crate::config::MARSHAL_CHANNEL;
const BROADCAST_CHANNEL: u64 = crate::config::BROADCAST_CHANNEL;
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1024));
const NUM_VALIDATORS: usize = 3;

/// Build a test `ConsensusBlock` identical in shape to the handler-test helper.
fn consensus_block_with_number(seed: u8, number: u64) -> ConsensusBlock {
    let mut block = Block::default();
    block.header.number = number;
    block.header.extra_data = Bytes::from(vec![seed]);
    let block = block.map_header(outbe_primitives::OutbeHeader::new);
    ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
}

/// One marshal node started on the simulated network: its mailbox plus the
/// actor handle (kept alive for the duration of the test).
struct MarshalNode {
    mailbox: MarshalMailbox,
    _actor_handle: commonware_runtime::Handle<()>,
}

/// Threshold-signing material shared by both nodes: per-node signers and the
/// common verifier registered into each node's scheme provider.
struct SchemeFixture {
    signers: Vec<HybridScheme<MinSig>>,
    verifier: HybridScheme<MinSig>,
}

/// Build a `HybridScheme` signer set and verifier from a bootstrapped DKG,
/// mirroring `finalization_metadata_context` in `application/handler_tests.rs`.
fn build_scheme_fixture() -> SchemeFixture {
    let keys: Vec<bls12381::PrivateKey> = (0..NUM_VALIDATORS as u64)
        .map(|i| bls12381::PrivateKey::from_seed(i + 1))
        .collect();
    let participants: Set<bls12381::PublicKey> = keys
        .iter()
        .map(|sk| bls12381::PublicKey::from(sk.clone()))
        .try_collect()
        .expect("participants should build");
    let dkg =
        crate::bls::bootstrap_dkg(NUM_VALIDATORS as u32).expect("bootstrap dkg should succeed");
    let signers: Vec<HybridScheme<MinSig>> = keys
        .iter()
        .map(|key| {
            let pk = bls12381::PublicKey::from(key.clone());
            let idx = participants.index(&pk).expect("participant should exist");
            HybridScheme::signer(
                &namespace(),
                participants.clone(),
                key.clone(),
                dkg.polynomial.clone(),
                dkg.shares[idx.get() as usize].clone(),
            )
            .expect("signer should build")
        })
        .collect();
    let verifier =
        HybridScheme::<MinSig>::verifier(&namespace(), participants, dkg.polynomial.clone())
            .expect("verifier should build");
    SchemeFixture { signers, verifier }
}

/// Assemble a threshold `Notarization` over `proposal` from a quorum of signers.
fn make_notarization(
    fixture: &SchemeFixture,
    proposal: Proposal<Digest>,
) -> Notarization<HybridScheme<MinSig>, Digest> {
    let notarizes: Vec<Notarize<HybridScheme<MinSig>, Digest>> = fixture
        .signers
        .iter()
        .map(|signer| Notarize::sign(signer, proposal.clone()).expect("notarize vote"))
        .collect();
    Notarization::from_notarizes(&fixture.signers[0], &notarizes, &Sequential)
        .expect("notarization certificate should assemble")
}

/// Start one marshal node with the production resolver + broadcast wiring on the
/// simulated network. Mirrors `crates/blockchain/engine/src/stack.rs`.
async fn start_marshal_node(
    context: &deterministic::Context,
    oracle: &commonware_p2p::simulated::Oracle<bls12381::PublicKey, deterministic::Context>,
    signing_key: &bls12381::PrivateKey,
    scheme_provider: HybridSchemeProvider<MinSig>,
    label: &str,
) -> MarshalNode {
    let public_key = signing_key.public_key();
    let control = oracle.control(public_key.clone());

    // Resolver channel (marshal on-demand block backfill).
    let marshal_channel = control
        .register(MARSHAL_CHANNEL, TEST_QUOTA)
        .await
        .expect("register marshal resolver channel");
    // Broadcast channel (buffered block dissemination engine).
    let broadcast_channel = control
        .register(BROADCAST_CHANNEL, TEST_QUOTA)
        .await
        .expect("register broadcast channel");

    let page_cache = CacheRef::from_pooler(
        context,
        NonZeroU16::new(1024).expect("non-zero page size"),
        NonZeroUsize::new(10).expect("non-zero cache size"),
    );
    let items_per_section = NonZeroU64::new(10).expect("non-zero items per section");
    let replay_buffer = NonZeroUsize::new(1024).expect("non-zero replay buffer");
    let write_buffer = NonZeroUsize::new(1024).expect("non-zero write buffer");
    let partition_prefix = format!("marshal-resolver-p2p-{label}");

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

    let (actor, mailbox, _height) = marshal::core::Actor::init(
        context.child("marshal"),
        finalizations_archive,
        blocks_archive,
        marshal::Config {
            provider: scheme_provider,
            epocher: FixedEpocher::new(NonZeroU64::new(10_000).expect("non-zero epoch")),
            start: Start::Genesis(consensus_block_with_number(0x00, 0)),
            partition_prefix,
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

    // Real broadcast buffer (block dissemination), mirroring stack.rs.
    let (broadcast_engine, broadcast_mailbox) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: public_key.clone(),
            mailbox_size: NonZeroUsize::new(crate::config::ENGINE_MAILBOX_SIZE)
                .expect("non-zero engine mailbox size"),
            deque_size: crate::config::BROADCAST_DEQUE_SIZE,
            peer_provider: oracle.manager(),
            priority: true,
            codec_config: (),
        },
    );
    broadcast_engine.start(broadcast_channel);

    // Real P2P resolver (on-demand block resolution / backfill), mirroring stack.rs.
    let resolver = marshal::resolver::p2p::init(
        context.child("marshal_resolver"),
        marshal::resolver::p2p::Config {
            public_key,
            peer_provider: oracle.manager(),
            blocker: control,
            mailbox_size: NonZeroUsize::new(crate::config::ENGINE_MAILBOX_SIZE)
                .expect("non-zero engine mailbox size"),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
        marshal_channel,
    );

    let actor_handle = actor.start(AckingMarshalReporter, broadcast_mailbox, resolver);

    MarshalNode {
        mailbox,
        _actor_handle: actor_handle,
    }
}

/// Reporter that acknowledges delivered blocks (mirrors the handler-test
/// `AckingMarshalReporter`). The marshal actor delivers fetched/finalized
/// blocks through this reporter; acking lets the actor make progress.
#[derive(Clone, Default)]
struct AckingMarshalReporter;

impl commonware_consensus::Reporter for AckingMarshalReporter {
    type Activity = marshal::Update<ConsensusBlock, commonware_utils::acknowledgement::Exact>;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        if let marshal::Update::Block(_, ack) = activity {
            use commonware_utils::acknowledgement::Acknowledgement as _;
            ack.acknowledge();
        }
        commonware_actor::Feedback::Ok
    }
}

/// Finding #6 / prf-5: prove the REAL commonware marshal `Recipients::One`
/// resolver pull/serve path. Node B fetches a block from node A's marshal
/// serve-side over an in-process simulated P2P network.
///
/// This is the only marshal path with no other automated in-repo coverage;
/// all sibling marshal tests stub the resolver and broadcast buffer.
#[test]
fn node_b_fetches_block_from_node_a_via_recipients_one_resolver() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|context| async move {
        // Sort keys by encoded public key so participant indices line up with
        // the ordered `Set` used by `HybridScheme` (same ordering used by the
        // multi-node consensus harness).
        let mut keys: Vec<bls12381::PrivateKey> = (0..NUM_VALIDATORS as u64)
            .map(|i| bls12381::PrivateKey::from_seed(i + 1))
            .collect();
        keys.sort_by_cached_key(|k| k.public_key().encode());

        let fixture = build_scheme_fixture();

        // Build the simulated network connecting all participants.
        let (network, oracle) = Network::new(
            context.child("network"),
            SimConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(4),
            },
        );
        network.start();

        // Register the epoch-0 verifier into each node's scheme provider so the
        // serve-side notarization can be verified on the receiving node.
        let epoch = Epoch::new(0);
        let provider_a = HybridSchemeProvider::<MinSig>::new();
        let provider_b = HybridSchemeProvider::<MinSig>::new();
        assert!(provider_a.register(epoch, fixture.verifier.clone()));
        assert!(provider_b.register(epoch, fixture.verifier.clone()));

        // Node A is the serving node; node B is the fetching node.
        let node_a = start_marshal_node(&context, &oracle, &keys[0], provider_a, "node-a").await;
        let node_b = start_marshal_node(&context, &oracle, &keys[1], provider_b, "node-b").await;

        // Link all peer pairs bidirectionally with a perfect link.
        let link = Link {
            latency: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        for i in 0..NUM_VALIDATORS {
            for j in 0..NUM_VALIDATORS {
                if i == j {
                    continue;
                }
                oracle
                    .add_link(keys[i].public_key(), keys[j].public_key(), link.clone())
                    .await
                    .expect("link peers");
            }
        }

        // commonware 2026.x routes only to peers in a tracked peer set;
        // `add_link` alone no longer enables routing. Track the full set so the
        // resolver/broadcast sends actually resolve to recipients.
        {
            let peers = Set::from_iter_dedup(keys.iter().map(|k| k.public_key()));
            let _ = oracle.manager().track(0, peers);
        }

        // The block node B will fetch, at round (epoch 0, view 5).
        let round = Round::new(epoch, View::new(5));
        let block = consensus_block_with_number(0x51, 5);
        let want_digest = block.digest();

        // Node B subscribes for the block's digest with a round-keyed fetch
        // fallback BEFORE node A makes it available, so the resolver must pull
        // it from a peer once it appears.
        let subscription_rx = node_b
            .mailbox
            .subscribe_by_digest(want_digest, DigestFallback::FetchByRound { round });

        // Node A makes the block locally available (proposed + verified) so it
        // can be found by commitment, and is told the matching notarization so
        // its resolver serve-side can answer a `Notarized { round }` request.
        let _ = node_a.mailbox.proposed(round, block.clone()).await;
        let _ = node_a.mailbox.verified(round, block.clone()).await;

        let proposal = Proposal::new(round, View::zero(), want_digest);
        let notarization = make_notarization(&fixture, proposal);
        let mut reporter_a = node_a.mailbox.clone();
        let _ = reporter_a.report(Activity::Notarization(notarization));

        // Drive deterministic time forward until node B's resolver fetches the
        // block from node A, or fail with a clear message on the time budget.
        let received = tokio::select! {
            result = subscription_rx => {
                result.expect("resolver subscription should deliver the fetched block")
            },
            _ = context.sleep(Duration::from_secs(30)) => {
                panic!(
                    "node B did not receive the block from node A's resolver serve-side \
                     within the deterministic time budget (Recipients::One pull/serve path)"
                );
            },
        };

        assert_eq!(
            received.digest(),
            want_digest,
            "block fetched over the real P2P resolver must match node A's block digest"
        );
        assert_eq!(received.number(), 5, "fetched block height must match");
    });
}

/// SEC-4 negative path: prove node B REJECTS a forged notarization served by a
/// peer over the same real `Recipients::One` resolver pull/serve path, instead
/// of delivering a block under the requested digest.
///
/// # Why this is a genuine rejection, not an unrelated timeout
///
/// The test runs two fetches over the *same* two-node harness, against the same
/// serve-side wiring:
///
/// 1. **Control (happy) fetch.** Round/view `5`, block digest `D_good`. Node A
///    is told the *correct* notarization (quorum signature over `D_good`).
///    Node B subscribes by `D_good` with `FetchByRound { round }`. The
///    subscription DELIVERS the block. This proves node A genuinely serves a
///    `(notarization, block)` response on this path and that B's verify/deliver
///    pipeline is wired correctly.
///
/// 2. **Forged fetch.** Round/view `7`, block digest `D_bad`. Node A proposes +
///    verifies the real `D_bad` block (so it is locally available to serve), and
///    is told a *forged* notarization built by
///    [`make_notarization_with_mismatched_proposal`]: its quorum vote signatures
///    were produced over a *different* payload (`D_other`), but its carried
///    `proposal` advertises round `7` and `D_bad`. Node A's serve-side
///    (`handle_produce` for `Key::Notarized { round }`) caches this notarization
///    by round, finds the `D_bad` block by the carried payload commitment, and
///    genuinely serves `(forged_notarization, D_bad_block)` to node B - the same
///    code path the control fetch exercised. Node B decodes the certificate
///    (codec config matches: identical participant count), passes the structural
///    checks (`notarization.round() == round`, `commitment(block) == payload`),
///    then runs the threshold certificate verification: the aggregated BLS vote
///    signature was made over `D_other`'s message but is checked against
///    `D_bad`'s message, so verification fails and the marshal core rejects the
///    delivery (`response.send_lossy(false)`), never caching/notifying the
///    block. Node B's subscription does NOT resolve.
///
/// The only difference between the two fetches is the forged certificate, and
/// only the forged fetch fails to deliver - so the timeout in phase 2 is caused
/// by the forgery being rejected, not by node A failing to serve.
///
/// Note on the chosen mismatch: a wrong-DKG / wrong-verifier forgery would NOT
/// be rejected by this scheme, because `HybridScheme::verify_certificate`
/// authenticates the certificate via the aggregated individual BLS vote
/// The negative phase keeps the advertised proposal and MinPk quorum aggregate
/// valid, but swaps in a threshold VRF proof for a different subject. This
/// isolates the foreign-certificate consumer gate exercised by Marshal.
#[test]
fn node_b_rejects_foreign_notarization_with_wrong_subject_vrf() {
    let runner = deterministic::Runner::timed(Duration::from_secs(90));
    runner.start(|context| async move {
        let mut keys: Vec<bls12381::PrivateKey> = (0..NUM_VALIDATORS as u64)
            .map(|i| bls12381::PrivateKey::from_seed(i + 1))
            .collect();
        keys.sort_by_cached_key(|k| k.public_key().encode());

        let fixture = build_scheme_fixture();

        let (network, oracle) = Network::new(
            context.child("network"),
            SimConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(4),
            },
        );
        network.start();

        let epoch = Epoch::new(0);
        let provider_a = HybridSchemeProvider::<MinSig>::new();
        let provider_b = HybridSchemeProvider::<MinSig>::new();
        assert!(provider_a.register(epoch, fixture.verifier.clone()));
        assert!(provider_b.register(epoch, fixture.verifier.clone()));

        let node_a =
            start_marshal_node(&context, &oracle, &keys[0], provider_a, "neg-node-a").await;
        let node_b =
            start_marshal_node(&context, &oracle, &keys[1], provider_b, "neg-node-b").await;

        let link = Link {
            latency: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        for i in 0..NUM_VALIDATORS {
            for j in 0..NUM_VALIDATORS {
                if i == j {
                    continue;
                }
                oracle
                    .add_link(keys[i].public_key(), keys[j].public_key(), link.clone())
                    .await
                    .expect("link peers");
            }
        }
        {
            let peers = Set::from_iter_dedup(keys.iter().map(|k| k.public_key()));
            let _ = oracle.manager().track(0, peers);
        }

        // ---- Phase 1: control / happy fetch proves A genuinely serves. ----
        let good_round = Round::new(epoch, View::new(5));
        let good_block = consensus_block_with_number(0x51, 5);
        let good_digest = good_block.digest();

        let good_rx = node_b.mailbox.subscribe_by_digest(
            good_digest,
            DigestFallback::FetchByRound { round: good_round },
        );

        let _ = node_a
            .mailbox
            .proposed(good_round, good_block.clone())
            .await;
        let _ = node_a
            .mailbox
            .verified(good_round, good_block.clone())
            .await;

        let good_proposal = Proposal::new(good_round, View::zero(), good_digest);
        let good_notarization = make_notarization(&fixture, good_proposal);
        let mut reporter_a = node_a.mailbox.clone();
        let _ = reporter_a.report(Activity::Notarization(good_notarization));

        let control = tokio::select! {
            result = good_rx => {
                result.expect("control fetch should deliver the correctly-notarized block")
            },
            _ = context.sleep(Duration::from_secs(30)) => {
                panic!(
                    "control fetch did not deliver: node A failed to serve the happy-path \
                     block, so the negative case below would be an unrelated timeout"
                );
            },
        };
        assert_eq!(
            control.digest(),
            good_digest,
            "control fetch must deliver node A's correctly-notarized block"
        );

        // ---- Phase 2: forged fetch must NOT deliver (genuine rejection). ----
        let bad_round = Round::new(epoch, View::new(7));
        let bad_block = consensus_block_with_number(0x71, 7);
        let bad_digest = bad_block.digest();

        // A different subject supplies a cryptographically valid threshold
        // proof which must not verify for `bad_round` + `bad_digest`.
        let other_digest = consensus_block_with_number(0x72, 7).digest();
        assert_ne!(
            bad_digest, other_digest,
            "forged signed payload must differ from the advertised payload"
        );

        let forged_rx = node_b.mailbox.subscribe_by_digest(
            bad_digest,
            DigestFallback::FetchByRound { round: bad_round },
        );

        // Node A holds the real block under `bad_digest` so its serve-side can
        // find and serve it for the forged notarization's carried payload.
        let _ = node_a.mailbox.proposed(bad_round, bad_block.clone()).await;
        let _ = node_a.mailbox.verified(bad_round, bad_block.clone()).await;

        let carried_proposal = Proposal::new(bad_round, View::zero(), bad_digest);
        let mut forged_notarization = make_notarization(&fixture, carried_proposal);
        let other_round = Round::new(epoch, View::new(8));
        let other_proposal = Proposal::new(other_round, View::new(7), other_digest);
        forged_notarization.certificate.vrf_proof = make_notarization(&fixture, other_proposal)
            .certificate
            .vrf_proof;
        let _ = reporter_a.report(Activity::Notarization(forged_notarization));

        tokio::select! {
            result = forged_rx => {
                match result {
                    Ok(block) => panic!(
                        "node B delivered a block (digest {:?}, number {}) for a forged \
                         notarization; the forged certificate must be rejected and no block \
                         delivered under the requested digest",
                        block.digest(),
                        block.number(),
                    ),
                    Err(_) => panic!(
                        "forged subscription channel closed unexpectedly; expected it to stay \
                         pending (no delivery) until the time budget, proving rejection"
                    ),
                }
            },
            _ = context.sleep(Duration::from_secs(30)) => {
                // Expected: the forged notarization is served by node A but
                // rejected by node B's certificate verification, so the
                // subscription never resolves. The control fetch above proved
                // the serve path itself works, so this timeout is the rejection.
            },
        }
    });
}
