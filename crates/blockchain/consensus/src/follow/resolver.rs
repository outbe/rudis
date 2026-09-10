//! Follower resolver: serves the marshal's gap-repair backfill requests from
//! the local execution layer and an upstream node, WITHOUT P2P.
//!
//! The marshal issues backfill [`Request`](handler::Request)s through a
//! [`TargetedResolver`]. In the validator path that resolver is
//! `commonware_resolver::p2p`, which talks to consensus peers. A follower has no
//! consensus peers, so this resolver instead:
//!
//! * `Request::Block(digest)` -> reads the block from the local EL
//!   ([`LocalBlockSource`]) and delivers it back to the marshal.
//! * `Request::Finalized { height }` -> fetches the certificate + block from the
//!   upstream ([`FinalizedSource`]) and delivers the concatenated
//!   `(Finalization, ConsensusBlock)` bytes, which the marshal decodes and
//!   verifies against the epoch committee.
//! * `Request::Notarized { .. }` -> ignored (the follower only consumes finalized
//!   data; notarizations are a validator-internal concern).
//!
//! **Actor + mailbox split.** The runtime's `Context` is not `Clone`, but the
//! marshal requires the resolver it holds to be `Clone`. So the spawnable half
//! (which owns the context + sources) is a [`ResolverActor`] spawned once, and
//! the marshal-facing half is [`FollowResolver`] - a cheap `Clone` mailbox that
//! forwards each fetch to the actor over an unbounded channel. This mirrors the
//! p2p resolver's `Engine` + `Mailbox` shape.
//!
//! Delivery is via the marshal's [`handler::Handler`] (a `Consumer`): the actor
//! resolves the value bytes, then calls
//! [`Consumer::deliver`](commonware_resolver::Consumer::deliver) so the marshal
//! validates and stores it. This is the same `Handler`/`Receiver` pair the
//! marshal `start` consumes, obtained from [`handler::init`].

use std::sync::{Arc, Mutex};

use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::marshal::resolver::handler::{self, Annotation, Key};
use commonware_consensus::types::Height;
use commonware_cryptography::bls12381;
use commonware_resolver::{Consumer as _, Delivery, Fetch, Resolver, TargetedResolver};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::vec::NonEmptyVec;
use futures::StreamExt as _;
use tracing::{debug, warn};

use crate::digest::Digest;
use crate::follow::upstream::{CertifiedFinalizedBlock, FinalizedSource, LocalBlockSource};
use crate::follow::{CommitteeChain, FollowerEpocher};

/// The marshal backfill key type for outbe blocks (commitment = block digest).
pub(super) type ResolverKey = Key<Digest>;

type FetchTx = futures::channel::mpsc::UnboundedSender<Fetch<ResolverKey, Annotation>>;
type FetchRx = futures::channel::mpsc::UnboundedReceiver<Fetch<ResolverKey, Annotation>>;

/// The marshal-facing resolver: a cheap `Clone` mailbox forwarding fetches to
/// the spawned [`ResolverActor`]. Implements [`TargetedResolver`].
#[derive(Clone)]
pub(super) struct FollowResolver {
    tx: FetchTx,
}

/// The spawned half of the resolver: owns the context + sources and resolves
/// each fetch, delivering the result to the marshal's `Handler`.
pub(super) struct ResolverActor<E, F, L> {
    context: E,
    handler: handler::Handler<Digest>,
    upstream: F,
    local: L,
    /// Shared committee-chaining verifier. A finalized fetch is independently
    /// authenticated before any pre-announce or boundary observation is applied;
    /// the marshal then verifies the same certificate again on delivery.
    chain: Arc<Mutex<CommitteeChain>>,
    /// Shared authenticated height-to-epoch map used by the marshal.
    epocher: FollowerEpocher,
    rx: FetchRx,
}

/// Build the resolver actor + its marshal-facing mailbox.
pub(super) fn init<E, F, L>(
    context: E,
    handler: handler::Handler<Digest>,
    upstream: F,
    local: L,
    chain: Arc<Mutex<CommitteeChain>>,
    epocher: FollowerEpocher,
) -> (ResolverActor<E, F, L>, FollowResolver) {
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let actor = ResolverActor {
        context,
        handler,
        upstream,
        local,
        chain,
        epocher,
        rx,
    };
    (actor, FollowResolver { tx })
}

impl<E, F, L> ResolverActor<E, F, L>
where
    E: Spawner + Clock + Metrics + Send + Sync + 'static,
    F: FinalizedSource,
    L: LocalBlockSource,
{
    /// Spawn the actor's receive loop. Each fetch is resolved on its own child
    /// task so a slow upstream fetch never blocks others.
    pub(super) fn start(self) -> commonware_runtime::Handle<()> {
        self.context
            .child("follow_resolver")
            .spawn(move |_| async move {
                let ResolverActor {
                    context,
                    handler,
                    upstream,
                    local,
                    chain,
                    epocher,
                    mut rx,
                } = self;
                while let Some(fetch) = rx.next().await {
                    let task_ctx = context.child("follow_fetch");
                    let handler = handler.clone();
                    let upstream = upstream.clone();
                    let local = local.clone();
                    let chain = chain.clone();
                    let epocher = epocher.clone();
                    task_ctx.spawn(move |_| {
                        resolve_one(fetch, handler, upstream, local, chain, epocher)
                    });
                }
            })
    }
}

/// Resolve a single fetch and deliver the value to the marshal.
async fn resolve_one<F, L>(
    fetch: Fetch<ResolverKey, Annotation>,
    mut handler: handler::Handler<Digest>,
    upstream: F,
    local: L,
    chain: Arc<Mutex<CommitteeChain>>,
    epocher: FollowerEpocher,
) where
    F: FinalizedSource,
    L: LocalBlockSource,
{
    let Fetch { key, subscriber } = fetch;
    debug!(%key, "resolver received fetch");
    let value = match &key {
        Key::Block(commitment) => {
            // First try the local EL (a block the follower already imported).
            if let Some(block) = local.get_block_by_digest(*commitment).await {
                block.encode()
            } else if let Some(height) = block_request_height(&subscriber) {
                // The follower has no block P2P, so a parent/ancestor block the
                // marshal needs for chain repair must come from the UPSTREAM.
                // The annotation carries the block's height; fetch that height's
                // finalized block and verify its digest matches the requested
                // commitment (the marshal re-checks too).
                match upstream.get_finalization(height).await {
                    Some(CertifiedFinalizedBlock { block, .. })
                        if block.digest() == *commitment =>
                    {
                        block.encode()
                    }
                    Some(_) => {
                        debug!(%key, %height, "upstream block at height did not match requested commitment; dropping fetch");
                        return;
                    }
                    None => {
                        debug!(%key, %height, "upstream did not have requested block; dropping fetch");
                        return;
                    }
                }
            } else {
                // A round-bound (`ByRound`/`Notarization`) block request has no
                // height; the follower cannot map it to an upstream height. The
                // marshal re-requests finalized-chain blocks by height, so this
                // is a benign drop.
                debug!(%key, "block request without a height annotation; dropping fetch");
                return;
            }
        }
        Key::Finalized { height } => match upstream.get_finalization(*height).await {
            Some(certified) => {
                if let Err(error) = super::engine::authenticate_live_finalized(
                    &chain, &epocher, *height, &certified,
                ) {
                    warn!(%key, %error, "failed to authenticate follower finalized delivery; dropping fetch");
                    return;
                }
                // Wire format the marshal expects for a `Finalized` delivery: the
                // finalization certificate immediately followed by the block.
                let mut buf = certified.finalization.encode().to_vec();
                buf.extend_from_slice(certified.block.encode().as_ref());
                buf.into()
            }
            None => {
                debug!(%key, "upstream did not have requested finalization; dropping fetch");
                return;
            }
        },
        Key::Notarized { .. } => {
            debug!(%key, "ignoring notarized backfill request (follower)");
            return;
        }
    };

    let delivery = Delivery {
        key,
        subscribers: NonEmptyVec::new(subscriber),
    };
    // AWAIT the marshal's validation response. Dropping the returned receiver is
    // the resolver-protocol CANCELLATION signal: the marshal checks
    // `response.is_closed()` at dequeue and silently skips a delivery whose
    // receiver is gone (see `handler::Message::response_closed`). Since this
    // fetch runs on its own spawned task, holding the receiver open until the
    // marshal answers costs nothing - and the answer tells us whether the value
    // was accepted. We do not retry on rejection (the marshal re-requests if it
    // still needs the height).
    match handler.deliver(delivery, value).await {
        Ok(true) => debug!(%key, "delivery accepted by marshal"),
        Ok(false) => warn!(%key, "delivery rejected by marshal"),
        Err(_) => debug!(%key, "marshal dropped delivery response (shutdown or batch prune)"),
    }
}

/// The block height a `Request::Block` annotation pins, if any. Height-bound
/// annotations (`Certified { height }`, `Finalized(ByHeight { height })`) map a
/// block-commitment request to an upstream `getFinalization(height)`. Round-bound
/// annotations carry no height and return `None`.
fn block_request_height(annotation: &Annotation) -> Option<Height> {
    match annotation {
        Annotation::Certified { height } => Some(*height),
        Annotation::Finalized(handler::Finalized::ByHeight { height }) => Some(*height),
        Annotation::Finalized(handler::Finalized::ByRound { .. })
        | Annotation::Notarization { .. } => None,
    }
}

impl FollowResolver {
    fn enqueue(&self, fetch: Fetch<ResolverKey, Annotation>) -> Feedback {
        match self.tx.unbounded_send(fetch) {
            Ok(()) => Feedback::Ok,
            Err(_) => Feedback::Closed,
        }
    }
}

impl Resolver for FollowResolver {
    type Key = ResolverKey;
    type Subscriber = Annotation;

    fn fetch<Fr>(&mut self, key: Fr) -> Feedback
    where
        Fr: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.enqueue(key.into())
    }

    fn fetch_all<Fr>(&mut self, keys: Vec<Fr>) -> Feedback
    where
        Fr: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let mut feedback = Feedback::Ok;
        for key in keys {
            if self.enqueue(key.into()) == Feedback::Closed {
                feedback = Feedback::Closed;
            }
        }
        feedback
    }

    fn retain(
        &mut self,
        _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        // Each fetch is a fire-and-forget task that either delivers or drops;
        // there is no persistent in-flight request table to prune. A task whose
        // height is already processed has its delivery ignored by the marshal as
        // stale, so retain is a no-op. (A cancellation table can be added later
        // if long gaps prove too chatty; it is not required for correctness.)
        Feedback::Ok
    }
}

impl TargetedResolver for FollowResolver {
    type PublicKey = bls12381::PublicKey;

    fn fetch_targeted(
        &mut self,
        fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _targets: NonEmptyVec<bls12381::PublicKey>,
    ) -> Feedback {
        // The follower has a single upstream; target hints (which consensus peer
        // to ask) are meaningless here. Resolve from the upstream/EL regardless.
        self.enqueue(fetch.into())
    }

    fn fetch_all_targeted<Fr>(
        &mut self,
        keys: Vec<(Fr, NonEmptyVec<bls12381::PublicKey>)>,
    ) -> Feedback
    where
        Fr: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let mut feedback = Feedback::Ok;
        for (key, _targets) in keys {
            if self.enqueue(key.into()) == Feedback::Closed {
                feedback = Feedback::Closed;
            }
        }
        feedback
    }
}
