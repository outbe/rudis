//! Canonical view-gap leader election for missed-proposer attribution.
//!
//! Both the proposer side (`reporter::detect_missed_proposers`, which feeds the
//! Phase 1 system transaction) and the verify side
//! (`finalization::attestation::canonical_missed_proposers`, which recomputes and
//! validates that metadata) must elect the *same* leader for every skipped
//! view - otherwise a proposer's `missed_proposers` list would be rejected by
//! validators and consensus would diverge. This module is the single source of
//! truth for that election sequence; callers keep their own guards, index ->
//! address mapping, out-of-bounds policy, logging, and metrics.

use commonware_consensus::simplex::elector::Elector as _;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_utils::Participant;

use crate::hybrid::election::HybridRandomElector;
use crate::hybrid::HybridCertificate;

/// Elect the expected leader for each skipped view in the open range
/// `(last_view, current_view)` (i.e. `last_view + 1 ..= current_view - 1`),
/// stopping after `cap` entries.
///
/// Returns one [`Participant`] per elected view, in view order. Mapping the
/// participant index to a validator address, and deciding what to do when that
/// index is out of range, is the caller's responsibility - the two call sites
/// deliberately differ there (the reporter skips, the verifier rejects).
pub(crate) fn elected_leaders_for_gap(
    epoch: Epoch,
    elector: &HybridRandomElector<MinSig>,
    certificate: Option<&HybridCertificate<MinSig>>,
    last_view: u64,
    current_view: u64,
    cap: usize,
) -> Vec<Participant> {
    let span = current_view.saturating_sub(last_view).saturating_sub(1);
    let mut leaders = Vec::with_capacity((span as usize).min(cap));
    for v in (last_view + 1)..current_view {
        if leaders.len() >= cap {
            break;
        }
        let round = Round::new(epoch, View::new(v));
        leaders.push(elector.elect(round, certificate));
    }
    leaders
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::election::HybridRandom;
    use crate::hybrid::test_support::test_participants;
    use commonware_consensus::simplex::elector::Config as _;

    fn round_robin_elector(n: u8) -> HybridRandomElector<MinSig> {
        let (_, participants) = test_participants(n);
        HybridRandom::default().build(&participants)
    }

    #[test]
    fn no_gap_returns_empty() {
        let elector = round_robin_elector(3);
        // current_view <= last_view + 1 => no skipped views.
        assert!(elected_leaders_for_gap(Epoch::new(0), &elector, None, 5, 6, 255).is_empty());
        assert!(elected_leaders_for_gap(Epoch::new(0), &elector, None, 5, 5, 255).is_empty());
    }

    #[test]
    fn elects_round_robin_leader_per_skipped_view() {
        let n = 3u8;
        let epoch = Epoch::new(0);
        let elector = round_robin_elector(n);
        // Default elector with no certificate falls back to round-robin:
        // leader index = (epoch + view) % n. Gap is views 6,7,8,9 for
        // last_view=5, current_view=10.
        let leaders = elected_leaders_for_gap(epoch, &elector, None, 5, 10, 255);
        let expected: Vec<Participant> = (6..10)
            .map(|v| Participant::new(((epoch.get() + v) % n as u64) as u32))
            .collect();
        assert_eq!(leaders, expected);
    }

    #[test]
    fn caps_to_limit() {
        let elector = round_robin_elector(3);
        // Gap of 400 views capped to 255 entries.
        let leaders = elected_leaders_for_gap(Epoch::new(0), &elector, None, 0, 401, 255);
        assert_eq!(leaders.len(), 255);
    }
}
