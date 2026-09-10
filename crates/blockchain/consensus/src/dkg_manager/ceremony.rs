//! Explicit, deterministic DKG ceremony state machine, plus the separate
//! non-consensus dealer-log gossip buffer.
//!
//! Two concerns that used to be tangled inside `dkg_manager`'s `CeremonyState`
//! are split here by trust level:
//!
//! - [`DkgCeremony`] - the **canonical** state. It is driven *only* by
//!   chain-finalized dealer logs (deterministic, consensus-ordered) and is a
//!   pure fold: the recovered group [`Output`] is a function of the *set* of
//!   finalized dealer logs, independent of arrival order and of the `OsRng`
//!   used for batch verification (RNG only gates accept/reject of a signature,
//!   never the recovered value). After a crash the canonical state is rebuilt
//!   by replaying the same on-chain logs. The state machine has two phases:
//!   `Collecting` -> `Reconstructed(output)`; the transition is one-way and
//!   happens once (the output is frozen on first successful reconstruction).
//!
//! - [`DealerLogGossip`] - the **non-consensus** emit buffer (this node's own
//!   dealer log plus P2P-received candidates). It is an abuse/prod-influenced
//!   mempool of "what to gossip/emit next" and never feeds canonical state; a
//!   chain-finalized log only prunes the corresponding gossip entry.
//!
//! Neither type performs I/O, takes a lock, or logs: the methods return plain
//! values/outcomes and the imperative shell in `dkg_manager.rs` performs the
//! effects (channel send, tracing) from those outcomes.

use std::collections::{btree_map::Entry, BTreeMap};
use std::num::NonZeroU32;

use alloy_primitives::Bytes;
use commonware_codec::Read as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::{
    self,
    dkg::feldman_desmedt::{observe, DealerLog, Info, Logs, Output, SignedDealerLog},
    primitives::variant::MinSig,
    Batch,
};
use commonware_parallel::Sequential;
use commonware_utils::{
    ordered::{Quorum as _, Set},
    N3f1,
};
use eyre::{ensure, Result, WrapErr};

/// A signed dealer log that passed cryptographic verification against the
/// ceremony's `info` and committee.
pub(crate) struct VerifiedDealerLog {
    pub dealer: bls12381::PublicKey,
    pub log: DealerLog<MinSig, bls12381::PublicKey>,
}

/// Explicit phase of the canonical DKG ceremony state machine.
///
/// `Collecting` accumulates chain-finalized dealer logs; `Reconstructed` holds
/// the frozen canonical group output. The finalized-log set lives as a sibling
/// field of [`DkgCeremony`] (not inside this enum) because it keeps growing in
/// both phases - only the *reconstruction* is one-shot.
#[derive(Debug)]
pub(crate) enum DkgCeremonyPhase {
    Collecting,
    Reconstructed(Output<MinSig, bls12381::PublicKey>),
}

/// Outcome of recording a chain-finalized dealer log into the canonical set.
pub(crate) enum FinalizedLogOutcome {
    /// Newly recorded; the dealer was not previously present.
    Recorded {
        dealer: bls12381::PublicKey,
        logs_len: usize,
    },
    /// The dealer already had a finalized log; ignored (idempotent).
    DuplicateFinalized { dealer: bls12381::PublicKey },
}

/// Outcome of attempting canonical reconstruction after a new finalized log.
pub(crate) enum ReconstructOutcome {
    /// Already reconstructed earlier; the output is frozen and not recomputed.
    AlreadyReconstructed,
    /// First successful reconstruction; carries the newly frozen output.
    Reconstructed(Output<MinSig, bls12381::PublicKey>),
    /// Not enough usable logs yet; carries the reason for diagnostics.
    Pending(String),
}

/// Canonical DKG ceremony state machine. Pure: no lock, no I/O, no logging.
#[derive(Debug)]
pub(crate) struct DkgCeremony {
    pub epoch: Epoch,
    info: Info<MinSig, bls12381::PublicKey>,
    max_players: NonZeroU32,
    dealers: Set<bls12381::PublicKey>,
    finalized_dealer_logs: BTreeMap<bls12381::PublicKey, DealerLog<MinSig, bls12381::PublicKey>>,
    phase: DkgCeremonyPhase,
}

impl DkgCeremony {
    pub fn new(
        epoch: Epoch,
        info: Info<MinSig, bls12381::PublicKey>,
        max_players: NonZeroU32,
        dealers: Set<bls12381::PublicKey>,
    ) -> Self {
        Self {
            epoch,
            info,
            max_players,
            dealers,
            finalized_dealer_logs: BTreeMap::new(),
            phase: DkgCeremonyPhase::Collecting,
        }
    }

    /// Decode and cryptographically verify a signed dealer log against this
    /// ceremony's `info` and committee. Pure (crypto check, no state change).
    pub fn verify_dealer_log(&self, bytes: &[u8]) -> Result<VerifiedDealerLog> {
        let mut reader = bytes;
        let signed_log = SignedDealerLog::<MinSig, bls12381::PrivateKey>::read_cfg(
            &mut reader,
            &self.max_players,
        )
        .wrap_err("failed decoding signed dealer log")?;
        ensure!(reader.is_empty(), "trailing bytes after signed dealer log");

        let (dealer, log) = signed_log
            .check(&self.info)
            .ok_or_else(|| eyre::eyre!("signed dealer log failed cryptographic verification"))?;
        ensure!(
            self.dealers.index(&dealer).is_some(),
            "signed dealer log dealer is not in ceremony committee"
        );
        Ok(VerifiedDealerLog { dealer, log })
    }

    /// True if a finalized dealer log is already recorded for `dealer`.
    pub fn is_finalized(&self, dealer: &bls12381::PublicKey) -> bool {
        self.finalized_dealer_logs.contains_key(dealer)
    }

    /// Record a verified chain-finalized dealer log. Idempotent per dealer.
    /// Pure: only the finalized-log set is mutated; reconstruction is a
    /// separate step ([`Self::try_reconstruct_if_needed`]).
    pub fn apply_finalized_dealer_log(
        &mut self,
        verified: VerifiedDealerLog,
    ) -> FinalizedLogOutcome {
        if self.finalized_dealer_logs.contains_key(&verified.dealer) {
            return FinalizedLogOutcome::DuplicateFinalized {
                dealer: verified.dealer,
            };
        }
        let dealer = verified.dealer.clone();
        self.finalized_dealer_logs
            .insert(verified.dealer, verified.log);
        FinalizedLogOutcome::Recorded {
            dealer,
            logs_len: self.finalized_dealer_logs.len(),
        }
    }

    /// Attempt canonical reconstruction. One-shot: only attempts while
    /// `Collecting`, and on first success transitions to `Reconstructed` and
    /// freezes the output (later finalized logs never recompute it).
    pub fn try_reconstruct_if_needed(&mut self) -> ReconstructOutcome {
        if !matches!(self.phase, DkgCeremonyPhase::Collecting) {
            return ReconstructOutcome::AlreadyReconstructed;
        }
        match try_reconstruct(&self.info, &self.finalized_dealer_logs) {
            Ok(output) => {
                self.phase = DkgCeremonyPhase::Reconstructed(output.clone());
                ReconstructOutcome::Reconstructed(output)
            }
            Err(error) => ReconstructOutcome::Pending(error.to_string()),
        }
    }

    /// The canonical group output, present iff the ceremony is `Reconstructed`.
    pub fn output(&self) -> Option<&Output<MinSig, bls12381::PublicKey>> {
        match &self.phase {
            DkgCeremonyPhase::Reconstructed(output) => Some(output),
            DkgCeremonyPhase::Collecting => None,
        }
    }

    #[cfg(test)]
    pub fn finalized_len(&self) -> usize {
        self.finalized_dealer_logs.len()
    }

    #[cfg(test)]
    pub(crate) fn dealers(&self) -> &Set<bls12381::PublicKey> {
        &self.dealers
    }

    /// Test-only: shrink the dealer committee (to exercise rejection of a log
    /// from a dealer no longer in the committee).
    #[cfg(test)]
    pub(crate) fn remove_dealer_for_test(&mut self, dealer: &bls12381::PublicKey) {
        use commonware_utils::TryCollect as _;
        self.dealers = self
            .dealers
            .iter()
            .filter(|candidate| *candidate != dealer)
            .cloned()
            .try_collect()
            .expect("committee remains non-empty");
    }
}

/// Deterministic reconstruction of the canonical group output from the set of
/// finalized dealer logs. The recovered value depends only on `info` and the
/// log set; `OsRng` is used solely for Commonware's batch-verification weights
/// (it gates accept/reject of signatures, never the recovered output value).
fn try_reconstruct(
    info: &Info<MinSig, bls12381::PublicKey>,
    finalized_dealer_logs: &BTreeMap<bls12381::PublicKey, DealerLog<MinSig, bls12381::PublicKey>>,
) -> Result<Output<MinSig, bls12381::PublicKey>> {
    let mut logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info.clone());
    for (dealer, log) in finalized_dealer_logs.clone() {
        logs.record(dealer, log);
    }
    observe::<MinSig, bls12381::PublicKey, N3f1, Batch>(&mut rand_core::OsRng, logs, &Sequential)
        .map_err(|error| eyre::eyre!("{error}"))
}

/// Outcome of offering a P2P dealer-log candidate to the gossip buffer.
pub(crate) enum PendingDealerLogOutcome {
    Stored,
    DuplicateSame,
    DuplicateDifferent {
        dealer: bls12381::PublicKey,
    },
    /// The dealer already has a chain-finalized log; the candidate is dropped.
    IgnoredFinalized,
    /// No active ceremony for the candidate's epoch (shell-only verdict).
    IgnoredNoActiveCeremony,
}

/// Non-consensus dealer-log emit buffer: this node's own dealer log plus
/// P2P-received candidates. Never feeds canonical state. Pure: no I/O.
#[derive(Default, Debug)]
pub(crate) struct DealerLogGossip {
    local: Option<Bytes>,
    pending: BTreeMap<bls12381::PublicKey, Bytes>,
}

impl DealerLogGossip {
    /// Record this node's own (locally produced) dealer log, superseding any
    /// pending candidate from the same dealer.
    pub fn record_local(&mut self, dealer: &bls12381::PublicKey, bytes: Bytes) {
        self.pending.remove(dealer);
        self.local = Some(bytes);
    }

    /// Offer a P2P-received dealer-log candidate. `already_finalized` is the
    /// canonical machine's verdict for this dealer (chain-finalized logs win).
    pub fn record_pending(
        &mut self,
        dealer: bls12381::PublicKey,
        bytes: Bytes,
        already_finalized: bool,
    ) -> PendingDealerLogOutcome {
        if already_finalized {
            return PendingDealerLogOutcome::IgnoredFinalized;
        }
        if self.local.as_ref() == Some(&bytes) {
            return PendingDealerLogOutcome::DuplicateSame;
        }
        match self.pending.entry(dealer.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(bytes);
                PendingDealerLogOutcome::Stored
            }
            Entry::Occupied(entry) if entry.get() == &bytes => {
                PendingDealerLogOutcome::DuplicateSame
            }
            Entry::Occupied(_) => PendingDealerLogOutcome::DuplicateDifferent { dealer },
        }
    }

    /// The best dealer log to emit next: this node's own log, else the first
    /// pending candidate by dealer order.
    pub fn best_to_emit(&self) -> Option<Bytes> {
        self.local
            .clone()
            .or_else(|| self.pending.values().next().cloned())
    }

    /// Drop the gossip entry for a dealer whose log just chain-finalized
    /// (`bytes` is the finalized log, used to clear the local slot if it
    /// matches). Stops re-gossiping what is now on-chain.
    pub fn prune_finalized(&mut self, dealer: &bls12381::PublicKey, bytes: &Bytes) {
        if self.local.as_ref() == Some(bytes) {
            self.local = None;
        }
        self.pending.remove(dealer);
    }

    /// Clear the whole emit buffer (boundary committed / ceremony completed).
    pub fn clear(&mut self) {
        self.local = None;
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::PublicKey;
    use commonware_cryptography::Signer as _;

    fn pk(seed: u64) -> PublicKey {
        bls12381::PrivateKey::from_seed(seed).public_key()
    }

    #[test]
    fn gossip_local_supersedes_pending_same_dealer() {
        let d = pk(1);
        let mut g = DealerLogGossip::default();
        assert!(matches!(
            g.record_pending(d.clone(), Bytes::from_static(b"p"), false),
            PendingDealerLogOutcome::Stored
        ));
        g.record_local(&d, Bytes::from_static(b"local"));
        // local wins for emission and the pending entry for d was removed.
        assert_eq!(g.best_to_emit(), Some(Bytes::from_static(b"local")));
    }

    #[test]
    fn gossip_record_pending_dedup_and_conflict() {
        let d = pk(1);
        let mut g = DealerLogGossip::default();
        assert!(matches!(
            g.record_pending(d.clone(), Bytes::from_static(b"a"), false),
            PendingDealerLogOutcome::Stored
        ));
        assert!(matches!(
            g.record_pending(d.clone(), Bytes::from_static(b"a"), false),
            PendingDealerLogOutcome::DuplicateSame
        ));
        assert!(matches!(
            g.record_pending(d.clone(), Bytes::from_static(b"b"), false),
            PendingDealerLogOutcome::DuplicateDifferent { .. }
        ));
    }

    #[test]
    fn gossip_already_finalized_is_ignored() {
        let d = pk(1);
        let mut g = DealerLogGossip::default();
        assert!(matches!(
            g.record_pending(d, Bytes::from_static(b"x"), true),
            PendingDealerLogOutcome::IgnoredFinalized
        ));
        assert_eq!(g.best_to_emit(), None);
    }

    #[test]
    fn gossip_duplicate_same_against_local() {
        let d = pk(1);
        let mut g = DealerLogGossip::default();
        g.record_local(&d, Bytes::from_static(b"same"));
        assert!(matches!(
            g.record_pending(pk(2), Bytes::from_static(b"same"), false),
            PendingDealerLogOutcome::DuplicateSame
        ));
    }

    #[test]
    fn gossip_prune_finalized_clears_local_and_pending() {
        let d1 = pk(1);
        let d2 = pk(2);
        let mut g = DealerLogGossip::default();
        g.record_local(&d1, Bytes::from_static(b"L"));
        let _ = g.record_pending(d2.clone(), Bytes::from_static(b"P"), false);
        g.prune_finalized(&d1, &Bytes::from_static(b"L"));
        // local cleared (bytes matched) -> next best is the pending candidate.
        assert_eq!(g.best_to_emit(), Some(Bytes::from_static(b"P")));
        g.prune_finalized(&d2, &Bytes::from_static(b"P"));
        assert_eq!(g.best_to_emit(), None);
    }

    #[test]
    fn gossip_best_to_emit_prefers_local_then_first_pending() {
        let mut g = DealerLogGossip::default();
        assert_eq!(g.best_to_emit(), None);
        let _ = g.record_pending(pk(5), Bytes::from_static(b"five"), false);
        let _ = g.record_pending(pk(9), Bytes::from_static(b"nine"), false);
        // first pending by dealer order (BTreeMap) - deterministic.
        assert!(g.best_to_emit().is_some());
        g.record_local(&pk(1), Bytes::from_static(b"L"));
        assert_eq!(g.best_to_emit(), Some(Bytes::from_static(b"L")));
        g.clear();
        assert_eq!(g.best_to_emit(), None);
    }
}
