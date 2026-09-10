//! `FinalizationActor` mailbox + message types.
//!
//! The mailbox is an `UnboundedSender<Message>` so the voter-side
//! Reporter callback never blocks. Closure of the receiver is treated
//! as a fatal supervisor event, surfaced via the
//! [`FinalizationMailboxClosed`] error.

use crate::digest::Digest;
use crate::finalization::parent_cert_store::CertifiedParentProofRecord;
use alloy_primitives::B256;
use commonware_consensus::types::Round;
use futures::channel::mpsc;
use outbe_primitives::consensus::ConsensusData;

/// Returned by [`Mailbox::notify_finalized`] when the
/// `FinalizationActor` has exited and its receiver has been dropped.
/// Caller MUST log + increment a metric on this error; silently
/// dropping a finalization breaks settlement liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizationMailboxClosed;

impl core::fmt::Display for FinalizationMailboxClosed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FinalizationActor mailbox closed; finalization dropped")
    }
}

impl std::error::Error for FinalizationMailboxClosed {}

/// Messages accepted by the `FinalizationActor`.
///
/// `Finalized` carries a finalization notification; `CertifiedNotarization`
/// carries a pre-built certified-parent witness record for off-thread
/// durable persistence. Routing the certified-notarization write through this
/// actor (a) moves the synchronous MDBX commit off the Simplex voter task and
/// (b) keeps the actor the single durable writer to `FinalizedParentCertStore`
/// (the reporter previously wrote it inline on the voter thread). The
/// parity-critical record (including `committee_set_hash`) is built by the
/// reporter before enqueue and is byte-identical to before - only the write
/// moves - so there is no proposer/validator divergence risk.
pub enum Message {
    Finalized(Finalized),
    CertifiedNotarization(CertifiedParentProofRecord),
}

/// Finalization notification routed from the consensus voter (via
/// `OutbeReporter`) into the FinalizationActor. The actor is the production
/// consumer for exact-parent cert persistence, forkchoice/status publication,
/// and finalized block-cache eviction.
pub struct Finalized {
    /// The consensus round of the finalized block.
    pub round: Round,
    /// The digest (block hash) of the finalized block.
    pub digest: Digest,
    /// VRF seed derived from the BLS threshold signature (if available).
    pub vrf_seed: Option<B256>,
    /// Full consensus data used by the actor to persist parent-cert facts and publish status.
    pub consensus_data: ConsensusData,
}

/// Handle for sending finalization events to the actor.
///
/// `notify_finalized` returns immediately via `unbounded_send`. Voter
/// task cannot block on this edge.
#[derive(Clone)]
pub struct Mailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl Mailbox {
    pub fn from_sender(tx: mpsc::UnboundedSender<Message>) -> Self {
        Self { inner: tx }
    }

    /// Returns `Err(FinalizationMailboxClosed)` if the actor has exited.
    /// Caller (see `OutbeReporter::handle_finalization`) MUST log and
    /// increment the `consensus_finalization_dropped{reason="mailbox_closed"}`
    /// metric on Err.
    pub fn notify_finalized(&self, f: Finalized) -> Result<(), FinalizationMailboxClosed> {
        self.inner
            .unbounded_send(Message::Finalized(f))
            .map_err(|_| FinalizationMailboxClosed)
    }

    /// enqueue a pre-built certified-parent witness record for off-thread
    /// durable persistence. Returns immediately via `unbounded_send`, so the
    /// Simplex voter task no longer blocks on the synchronous MDBX commit. The
    /// caller (`OutbeReporter::handle_certification`) logs + meters on `Err`.
    pub fn persist_certified_notarization(
        &self,
        record: CertifiedParentProofRecord,
    ) -> Result<(), FinalizationMailboxClosed> {
        self.inner
            .unbounded_send(Message::CertifiedNotarization(record))
            .map_err(|_| FinalizationMailboxClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;
    use alloy_primitives::B256;
    use commonware_consensus::types::{Epoch, Round, View};
    use futures::StreamExt;
    use outbe_primitives::consensus::ConsensusData;

    fn dummy_finalized() -> Finalized {
        Finalized {
            round: Round::new(Epoch::new(1), View::new(1)),
            digest: Digest(B256::with_last_byte(0xAA)),
            vrf_seed: Some(B256::with_last_byte(0xBB)),
            consensus_data: ConsensusData::default(),
        }
    }

    #[tokio::test]
    async fn notify_finalized_delivers_to_receiver() {
        let (tx, mut rx) = mpsc::unbounded::<Message>();
        let mailbox = Mailbox::from_sender(tx);

        mailbox.notify_finalized(dummy_finalized()).unwrap();

        let received = rx.next().await.expect("message delivered");
        match received {
            Message::Finalized(f) => {
                assert_eq!(f.digest.0, B256::with_last_byte(0xAA));
            }
            Message::CertifiedNotarization(_) => panic!("expected Finalized"),
        }
    }

    // certified-notarization persistence is routed off-thread through the
    // same mailbox as a distinct message variant.
    #[tokio::test]
    async fn persist_certified_notarization_delivers_record() {
        let (tx, mut rx) = mpsc::unbounded::<Message>();
        let mailbox = Mailbox::from_sender(tx);

        mailbox
            .persist_certified_notarization(CertifiedParentProofRecord::default())
            .unwrap();

        let received = rx.next().await.expect("message delivered");
        assert!(matches!(received, Message::CertifiedNotarization(_)));
    }

    #[tokio::test]
    async fn persist_certified_notarization_returns_err_on_closed_receiver() {
        let (tx, rx) = mpsc::unbounded::<Message>();
        let mailbox = Mailbox::from_sender(tx);
        drop(rx);

        let err = mailbox
            .persist_certified_notarization(CertifiedParentProofRecord::default())
            .unwrap_err();
        assert_eq!(err, FinalizationMailboxClosed);
    }

    #[tokio::test]
    async fn notify_finalized_returns_err_on_closed_receiver() {
        let (tx, rx) = mpsc::unbounded::<Message>();
        let mailbox = Mailbox::from_sender(tx);
        drop(rx);

        let err = mailbox.notify_finalized(dummy_finalized()).unwrap_err();
        assert_eq!(err, FinalizationMailboxClosed);
    }

    #[tokio::test]
    async fn notify_finalized_is_non_blocking_for_burst() {
        // 10_000 sends with no concurrent receiver - unbounded_send
        // returns instantly each time. Reads happen after.
        let (tx, mut rx) = mpsc::unbounded::<Message>();
        let mailbox = Mailbox::from_sender(tx);

        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            mailbox.notify_finalized(dummy_finalized()).unwrap();
        }
        let burst_elapsed = start.elapsed();
        assert!(
            burst_elapsed < std::time::Duration::from_millis(500),
            "10k unbounded_send burst took {:?} - should be sub-second",
            burst_elapsed
        );

        let mut count = 0;
        while rx.next().await.is_some() {
            count += 1;
            if count == 10_000 {
                break;
            }
        }
        assert_eq!(count, 10_000);
    }
}
