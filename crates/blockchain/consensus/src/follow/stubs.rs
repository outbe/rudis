//! Stub implementations for running the marshal in follower mode.
//!
//! In follower mode the node never broadcasts blocks (it has no consensus
//! peers and no signing key admitted to the validators' `authenticated::lookup`
//! network - transport A, the upstream-RPC model). The marshal's `start`
//! nonetheless requires a `buffered::Mailbox` for its broadcast buffer. This
//! module provides a null broadcast: a [`buffered::Engine`] over a random
//! ephemeral key with an empty static peer set, so nothing is ever sent.
//!
//! The stubs are keyed by `bls12381::PublicKey`, Outbe's consensus identity.

use std::num::NonZeroUsize;

use commonware_broadcast::buffered;
use commonware_cryptography::bls12381::{self, PrivateKey};
use commonware_cryptography::Signer as _;
use commonware_p2p::utils::StaticProvider;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner};
use commonware_utils::ordered::Set;

use crate::block::ConsensusBlock;

/// Build a null broadcast mailbox for the follower marshal.
///
/// The returned mailbox is the same type the validator path hands to
/// `marshal_actor.start(..)` ([`BroadcastMailbox`](crate::marshal_types::BroadcastMailbox)),
/// but it is backed by an engine that has no peers, so the follower never
/// disseminates anything. The engine handle is dropped intentionally: the
/// follower drives block ingestion entirely through the resolver + upstream,
/// not the broadcast path.
pub(super) fn null_broadcast<E>(
    context: E,
    mailbox_size: NonZeroUsize,
) -> buffered::Mailbox<bls12381::PublicKey, ConsensusBlock>
where
    E: Clock + Spawner + Metrics + BufferPooler,
{
    // Deterministic ephemeral key - never used to sign, never admitted anywhere.
    let private_key = PrivateKey::from_seed(0);
    let public_key = private_key.public_key();

    let config = buffered::Config {
        public_key,
        mailbox_size,
        deque_size: 0,
        priority: false,
        codec_config: (),
        peer_provider: StaticProvider::new(0, Set::default()),
    };

    let (_engine, mailbox) = buffered::Engine::new(context, config);
    mailbox
}
