//! Application actor - handles propose/verify/finalize via beacon_engine_handle.
//!
//! Implements the consensus `Automaton` and `Relay` traits, bridging
//! Commonware Simplex with Reth's execution layer.

use commonware_consensus::{Automaton, CertifiableAutomaton, Relay};
use commonware_cryptography::bls12381;
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;

use super::ingress::{Mailbox, Message, SimplexContext};
use crate::digest::Digest;
use crate::marshal_types::MarshalMailbox;

/// The application actor that bridges consensus and execution.
///
/// Implements [`Automaton`]/[`CertifiableAutomaton`] so Simplex can call
/// `propose()`, `verify()`, and `certify()` (the genesis digest now feeds
/// `simplex::Config.floor` instead of an `Automaton::genesis` call).
/// Implements [`Relay`] so Simplex can broadcast proposals.
#[derive(Clone)]
pub struct OutbeApplication {
    mailbox: Mailbox,
    /// Marshal mailbox used to disseminate a proposed block directly.
    ///
    /// The block is cached into marshal at propose time (`handle_propose` calls
    /// `marshal.proposed`), so [`Relay::broadcast`] only needs the synchronous
    /// `marshal.forward` wire-push - it does not hop through the bounded
    /// application mailbox (which could drop the trigger under saturation).
    marshal_mailbox: MarshalMailbox,
}

impl OutbeApplication {
    /// Create a new application actor with its mailbox.
    pub fn new(
        mailbox_size: usize,
        marshal_mailbox: MarshalMailbox,
    ) -> (Self, futures::channel::mpsc::Receiver<Message>) {
        let (tx, rx) = futures::channel::mpsc::channel(mailbox_size);
        let mailbox = Mailbox::from_sender(tx);
        (
            Self {
                mailbox,
                marshal_mailbox,
            },
            rx,
        )
    }

    /// Get a clone of the mailbox for use by the reporter.
    pub fn reporter_mailbox(&self) -> Mailbox {
        self.mailbox.clone()
    }
}

impl Automaton for OutbeApplication {
    type Context = SimplexContext;
    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Digest> {
        self.mailbox.propose(context).await
    }

    async fn verify(&mut self, context: Self::Context, payload: Digest) -> oneshot::Receiver<bool> {
        self.mailbox.verify(context, payload).await
    }
}

impl CertifiableAutomaton for OutbeApplication {
    // Use default implementation - always certify.
}

impl Relay for OutbeApplication {
    type Digest = Digest;
    type PublicKey = bls12381::PublicKey;
    type Plan = commonware_consensus::simplex::Plan<bls12381::PublicKey>;

    /// Disseminate a proposed block to the network.
    ///
    /// commonware 2026.5.0 made this trait method synchronous and split marshal
    /// dissemination: `marshal.proposed` only caches the block locally;
    /// `marshal.forward` performs the wire-push (`Buffer::send`). The block was
    /// already cached at propose time (`handle_propose` -> `marshal.proposed`),
    /// so here we call `marshal.forward` DIRECTLY - no hop through the bounded
    /// application mailbox. This is drop-proof for the push trigger and keeps
    /// the proposer's block servable on demand even if `forward` itself is
    /// throttled (verifiers can pull it). Dissemination is networking, not a
    /// consensus state transition, so this does not affect determinism.
    ///
    /// The Simplex engine runs with `ForwardingPolicy::Disabled`, so `plan` is
    /// always `Plan::Propose`; the relay forwards the proposer's own block to
    /// all peers regardless of the plan variant.
    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> commonware_actor::Feedback {
        // Honor the plan's intended recipients: `Propose` is a fresh broadcast to
        // all peers; `Forward` targets a specific subset (under ForwardingPolicy
        // ::Disabled the batcher never emits `Forward`, but if a future policy
        // enables targeted forwarding we must NOT silently widen it to All).
        let (round, recipients) = match plan {
            commonware_consensus::simplex::Plan::Propose { round } => (round, Recipients::All),
            commonware_consensus::simplex::Plan::Forward { round, recipients } => {
                (round, recipients)
            }
        };
        tracing::debug!(payload = %payload.0, %round, "relay forwarding proposed block");
        self.marshal_mailbox.forward(round, payload, recipients)
    }
}
