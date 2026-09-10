//! Height->epoch strategy for the follower, derived from authenticated on-chain
//! committee boundaries.
//!
//! Validator activation can be delayed inside the configured grace window, and
//! every subsequent plan is measured from that actual activation. Therefore
//! neither `FixedEpocher` nor `(height-1)/L` is authoritative after the first
//! delayed rotation. [`FollowerEpocher`] records exact, authenticated
//! `BoundaryOutcome` carrier heights and derives every completed interval from
//! adjacent observations. Length and activation grace only bound discovery of
//! the next boundary; they never select the active committee.

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use commonware_consensus::types::{Epoch, EpochInfo, Epocher, Height};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BoundaryObservationError {
    #[error("epoch length must be non-zero")]
    ZeroEpochLength,
    #[error("observed epoch {observed} is not the next epoch after {current}")]
    NonSequential { current: u64, observed: u64 },
    #[error("epoch {epoch} was already observed at height {existing}, not {observed}")]
    ConflictingReplay {
        epoch: u64,
        existing: u64,
        observed: u64,
    },
    #[error("epoch {epoch} boundary height {observed} is outside {earliest}..={latest}")]
    OutsideActivationWindow {
        epoch: u64,
        observed: u64,
        earliest: u64,
        latest: u64,
    },
    #[error("epoch boundary arithmetic overflow")]
    Overflow,
}

#[derive(Debug)]
struct ObservedBoundaries {
    length: u64,
    activation_grace: u64,
    /// Actual activation carrier by epoch. Epoch zero activates in block 1;
    /// genesis height zero is mapped to epoch zero as a special trust anchor.
    activations: BTreeMap<u64, u64>,
}

/// Shared observed-boundary epocher for the follower marshal, resolver, and
/// driver. Epoch zero also owns genesis height zero as the local trust anchor.
#[derive(Clone, Debug)]
pub struct FollowerEpocher {
    inner: Arc<RwLock<ObservedBoundaries>>,
}

impl FollowerEpocher {
    /// Create an observed-boundary epocher. Length and grace only bound the next
    /// boundary; they never select an epoch.
    pub fn new(length: u64, activation_grace: u64) -> Self {
        assert!(length > 0, "follower epoch length must be non-zero");
        Self {
            inner: Arc::new(RwLock::new(ObservedBoundaries {
                length,
                activation_grace,
                activations: BTreeMap::from([(0, 1)]),
            })),
        }
    }

    /// Record an authenticated activating boundary. Exact replay is idempotent;
    /// conflicts, jumps, and activations outside the validator grace window fail.
    pub fn observe_boundary(
        &self,
        epoch: Epoch,
        height: Height,
    ) -> Result<(), BoundaryObservationError> {
        let epoch = epoch.get();
        let observed = height.get();
        let mut inner = self.inner.write().expect("follower epocher lock poisoned");
        if inner.length == 0 {
            return Err(BoundaryObservationError::ZeroEpochLength);
        }
        if let Some(existing) = inner.activations.get(&epoch).copied() {
            return if existing == observed {
                Ok(())
            } else {
                Err(BoundaryObservationError::ConflictingReplay {
                    epoch,
                    existing,
                    observed,
                })
            };
        }

        let (&current, &previous_height) = inner
            .activations
            .last_key_value()
            .expect("epoch-zero activation is always present");
        if epoch != current.saturating_add(1) {
            return Err(BoundaryObservationError::NonSequential {
                current,
                observed: epoch,
            });
        }
        let earliest = previous_height
            .checked_add(inner.length)
            .ok_or(BoundaryObservationError::Overflow)?;
        let latest = earliest
            .checked_add(inner.activation_grace)
            .ok_or(BoundaryObservationError::Overflow)?;
        if !(earliest..=latest).contains(&observed) {
            return Err(BoundaryObservationError::OutsideActivationWindow {
                epoch,
                observed,
                earliest,
                latest,
            });
        }
        inner.activations.insert(epoch, observed);
        Ok(())
    }

    /// Highest height that can still belong to the latest observed epoch.
    pub fn supported_ceiling(&self) -> Option<Height> {
        let inner = self.inner.read().expect("follower epocher lock poisoned");
        let (_, activation) = inner.activations.last_key_value()?;
        Some(Height::new(
            activation
                .checked_add(inner.length)?
                .checked_add(inner.activation_grace)?,
        ))
    }

    /// Actual activation carrier for a known epoch (epoch zero is block 1).
    pub fn activation_height(&self, epoch: Epoch) -> Option<Height> {
        self.inner
            .read()
            .expect("follower epocher lock poisoned")
            .activations
            .get(&epoch.get())
            .copied()
            .map(Height::new)
    }

    /// Inclusive height window in which the next activation may occur.
    pub fn next_boundary_window(&self, epoch: Epoch) -> Option<(Height, Height)> {
        let inner = self.inner.read().expect("follower epocher lock poisoned");
        let activation = *inner.activations.get(&epoch.get())?;
        let earliest = activation.checked_add(inner.length)?;
        let latest = earliest.checked_add(inner.activation_grace)?;
        Some((Height::new(earliest), Height::new(latest)))
    }

    /// `(first, last)` height bounds for an observed epoch.
    fn bounds(&self, epoch: Epoch) -> Option<(Height, Height)> {
        let inner = self.inner.read().expect("follower epocher lock poisoned");
        let e = epoch.get();
        let activation = *inner.activations.get(&e)?;
        let first = if e == 0 { 0 } else { activation };
        let last = if let Some(next) = inner.activations.get(&e.checked_add(1)?) {
            next.checked_sub(1)?
        } else {
            activation
                .checked_add(inner.length)?
                .checked_add(inner.activation_grace)?
        };
        Some((Height::new(first), Height::new(last)))
    }
}

impl Epocher for FollowerEpocher {
    fn containing(&self, height: Height) -> Option<EpochInfo> {
        let h = height.get();
        let inner = self.inner.read().expect("follower epocher lock poisoned");
        let (&epoch, _) = inner
            .activations
            .iter()
            .rev()
            .find(|(_, activation)| **activation <= h.max(1))?;
        drop(inner);
        let epoch = Epoch::new(epoch);
        let (first, last) = self.bounds(epoch)?;
        if h < first.get() || h > last.get() {
            return None;
        }
        Some(EpochInfo::new(epoch, height, first, last))
    }

    fn first(&self, epoch: Epoch) -> Option<Height> {
        self.bounds(epoch).map(|(first, _)| first)
    }

    fn last(&self, epoch: Epoch) -> Option<Height> {
        self.bounds(epoch).map(|(_, last)| last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin `containing(height).epoch()` against the live-localnet ground truth
    /// (`L=60`): block 60 -> cert epoch 0, 61 -> 1, 120 -> 1, 121 -> 2. With this
    /// mapping the marshal's `finalization.epoch() == containing(height)` check
    /// holds for every certified block, so a follower can verify boundary blocks.
    #[test]
    fn containing_matches_onchain_cert_epochs() {
        let e = FollowerEpocher::new(60, 0);
        e.observe_boundary(Epoch::new(1), Height::new(61)).unwrap();
        e.observe_boundary(Epoch::new(2), Height::new(121)).unwrap();
        e.observe_boundary(Epoch::new(3), Height::new(181)).unwrap();
        let epoch_of = |h: u64| e.containing(Height::new(h)).unwrap().epoch().get();
        assert_eq!(epoch_of(0), 0, "genesis anchor is epoch 0");
        assert_eq!(epoch_of(1), 0);
        assert_eq!(epoch_of(59), 0);
        assert_eq!(epoch_of(60), 0, "block 60 is the LAST block of epoch 0");
        assert_eq!(
            epoch_of(61),
            1,
            "block 61 (boundary) is the FIRST of epoch 1"
        );
        assert_eq!(epoch_of(120), 1, "block 120 is the LAST block of epoch 1");
        assert_eq!(epoch_of(121), 2);
        assert_eq!(epoch_of(180), 2);
        assert_eq!(epoch_of(181), 3);
    }

    /// `first(E)` lands on epoch `E`'s boundary-outcome block (1, 61, 121, ...) -
    /// exactly where the driver fetches to register epoch `E`'s committee.
    #[test]
    fn first_lands_on_boundary_block() {
        let e = FollowerEpocher::new(60, 0);
        e.observe_boundary(Epoch::new(1), Height::new(61)).unwrap();
        e.observe_boundary(Epoch::new(2), Height::new(121)).unwrap();
        e.observe_boundary(Epoch::new(3), Height::new(181)).unwrap();
        // first(0) = 0 (genesis anchor); epoch 0's boundary outcome rides block 1.
        assert_eq!(e.first(Epoch::new(0)).unwrap().get(), 0);
        assert_eq!(e.first(Epoch::new(1)).unwrap().get(), 61);
        assert_eq!(e.first(Epoch::new(2)).unwrap().get(), 121);
        assert_eq!(e.first(Epoch::new(3)).unwrap().get(), 181);
    }

    /// `last(E)` is the block `(E+1)*L` (60, 120, 180) - the last block epoch `E`
    /// signs, contiguous with `first(E+1) - 1`.
    #[test]
    fn last_is_epoch_final_block() {
        let e = FollowerEpocher::new(60, 0);
        e.observe_boundary(Epoch::new(1), Height::new(61)).unwrap();
        e.observe_boundary(Epoch::new(2), Height::new(121)).unwrap();
        e.observe_boundary(Epoch::new(3), Height::new(181)).unwrap();
        e.observe_boundary(Epoch::new(4), Height::new(241)).unwrap();
        e.observe_boundary(Epoch::new(5), Height::new(301)).unwrap();
        assert_eq!(e.last(Epoch::new(0)).unwrap().get(), 60);
        assert_eq!(e.last(Epoch::new(1)).unwrap().get(), 120);
        assert_eq!(e.last(Epoch::new(2)).unwrap().get(), 180);
        // Contiguity: last(E) + 1 == first(E+1) for E >= 1.
        for ep in 1..5u64 {
            assert_eq!(
                e.last(Epoch::new(ep)).unwrap().get() + 1,
                e.first(Epoch::new(ep + 1)).unwrap().get()
            );
        }
    }

    #[test]
    fn observed_non_grid_boundary_defines_the_epoch_instead_of_the_formula() {
        let e = FollowerEpocher::new(60, 10);

        e.observe_boundary(Epoch::new(1), Height::new(63))
            .expect("delayed boundary within activation grace must be accepted");

        assert_eq!(
            e.containing(Height::new(62)).unwrap().epoch(),
            Epoch::new(0)
        );
        assert_eq!(
            e.containing(Height::new(63)).unwrap().epoch(),
            Epoch::new(1)
        );
        assert_eq!(e.first(Epoch::new(1)), Some(Height::new(63)));
        assert_eq!(e.last(Epoch::new(0)), Some(Height::new(62)));
    }

    #[test]
    fn observed_boundaries_accumulate_drift_from_the_previous_activation() {
        let e = FollowerEpocher::new(60, 10);
        e.observe_boundary(Epoch::new(1), Height::new(63)).unwrap();
        e.observe_boundary(Epoch::new(2), Height::new(126)).unwrap();

        assert_eq!(
            e.containing(Height::new(125)).unwrap().epoch(),
            Epoch::new(1)
        );
        assert_eq!(
            e.containing(Height::new(126)).unwrap().epoch(),
            Epoch::new(2)
        );
        assert_eq!(e.first(Epoch::new(2)), Some(Height::new(126)));
        assert_eq!(e.last(Epoch::new(1)), Some(Height::new(125)));
    }

    #[test]
    fn boundary_observation_is_exactly_idempotent_and_rejects_conflicts() {
        let e = FollowerEpocher::new(60, 10);
        e.observe_boundary(Epoch::new(1), Height::new(63)).unwrap();
        e.observe_boundary(Epoch::new(1), Height::new(63))
            .expect("exact replay must be idempotent");

        assert!(
            e.observe_boundary(Epoch::new(1), Height::new(64)).is_err(),
            "the same epoch cannot move to another height"
        );
        assert!(
            e.observe_boundary(Epoch::new(2), Height::new(134)).is_err(),
            "a boundary beyond activation grace must be rejected"
        );
        assert_eq!(e.first(Epoch::new(1)), Some(Height::new(63)));
        assert_eq!(e.first(Epoch::new(2)), None);
    }
}
