//! Epoch-continuity guard and boundary-parent resolution for the application
//! handler.
//!
//! Owns the whole epoch-boundary concern lifted out of `handler.rs`:
//! - [`ApplicationEpochFence`] - the activation-boundary state machine (active
//!   epoch + an optional armed boundary) consulted on every propose/verify so a
//!   stale Simplex epoch cannot submit Engine work past a DKG activation.
//! - [`resolve_epoch_boundary_parent`] - the anchor-based parent resolver for
//!   the first proposal of `epoch > 0`. It takes the finalization-view and
//!   marshal seams as explicit parameters instead of `&self`, so the resolution
//!   logic reads and tests independently of the handler.

use std::sync::{Arc, Mutex as StdMutex};

use alloy_primitives::B256;
use commonware_consensus::types::{Epoch, Height, Round, View};

use crate::block::ConsensusBlock;
use crate::config::PROPOSE_RESOLUTION_TIMEOUT;
use crate::digest::Digest;
use crate::finalization::parent_cert_store::CertifiedParentProofKey;
use crate::finalization::state::{FinalizationViewAccess, FinalizationViewHandle};
use crate::marshal_types::MarshalMailbox;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EpochFenceRejection {
    StaleEpoch { active_epoch: Epoch },
    FutureEpoch { active_epoch: Epoch },
    BeyondBoundary { max_block_height: u64 },
}

#[derive(Debug, Clone, Copy)]
struct EpochFenceState {
    active_epoch: Epoch,
    boundary: Option<EpochBoundaryFence>,
}

#[derive(Debug, Clone, Copy)]
struct EpochBoundaryFence {
    epoch: Epoch,
    max_block_height: u64,
}

/// epoch continuity anchor for the first proposal of `epoch > 0`.
///
/// Built by [`resolve_epoch_boundary_parent`] and consumed
/// by both `handle_propose` and `handle_verify` to bypass the `parent_view = 0`
/// chain-genesis path for non-zero epochs.
#[derive(Debug, Clone)]
pub(crate) struct EpochBoundaryParent {
    pub(crate) height: Height,
    pub(crate) block: ConsensusBlock,
    pub(crate) proof_key: CertifiedParentProofKey,
}

/// Typed error returned by [`resolve_epoch_boundary_parent`].
///
/// The variants distinguish *invalid proposal* (the proposer chose a parent
/// that does not match the canonical anchor) from *local infrastructure issue*
/// (the validator cannot decide locally because the finalization view or the
/// marshal store has not caught up). Verify path votes `false` only in the
/// first case; the rest bubble up as `Err` and drop the response channel, to
/// match the existing `resolve_for_verify` semantics for local timeouts.
#[derive(Debug)]
pub(crate) enum EpochBoundaryParentError {
    /// Simplex parent does not match the committed continuity anchor.
    ParentMismatch {
        expected: B256,
        got: B256,
        epoch: u64,
    },
    /// `FinalizationView` has no anchor for `epoch > 0`. Caller waited as long
    /// as it could; this is a local-infrastructure failure, not a vote.
    MissingAnchor { epoch: u64 },
    /// Marshal store cannot return the anchor block.
    MissingMarshalBlock { height: u64 },
    /// Marshal returned a block whose digest does not match the anchor.
    MarshalHashMismatch {
        height: u64,
        expected: B256,
        got: B256,
    },
}

impl std::fmt::Display for EpochBoundaryParentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentMismatch {
                expected,
                got,
                epoch,
            } => write!(
                f,
                "epoch boundary parent mismatch: simplex parent {got} != finalized anchor {expected} (epoch={epoch})",
            ),
            Self::MissingAnchor { epoch } => write!(
                f,
                "broken epoch continuity: epoch={epoch} but no finalized anchor in finalization_view",
            ),
            Self::MissingMarshalBlock { height } => write!(
                f,
                "epoch boundary parent block at height {height} not found in marshal",
            ),
            Self::MarshalHashMismatch {
                height,
                expected,
                got,
            } => write!(
                f,
                "marshal block at height {height} has digest {got} != simplex parent {expected}",
            ),
        }
    }
}

impl std::error::Error for EpochBoundaryParentError {}

/// Guards application work during DKG activation so an old Simplex epoch cannot
/// submit Engine API work past the activation boundary while the epoch restarts.
#[derive(Debug, Clone)]
pub struct ApplicationEpochFence {
    state: Arc<StdMutex<EpochFenceState>>,
}

impl ApplicationEpochFence {
    pub fn new(active_epoch: Epoch) -> Self {
        Self {
            state: Arc::new(StdMutex::new(EpochFenceState {
                active_epoch,
                boundary: None,
            })),
        }
    }

    pub fn arm_activation_boundary(&self, epoch: Epoch, max_block_height: u64) {
        let mut state = self.lock_state();
        state.boundary = Some(EpochBoundaryFence {
            epoch,
            max_block_height,
        });
    }

    pub fn advance_epoch(&self, next_epoch: Epoch) {
        let mut state = self.lock_state();
        state.active_epoch = next_epoch;
        state.boundary = state.boundary.filter(|fence| fence.epoch >= next_epoch);
    }

    pub(crate) fn check(
        &self,
        round: Round,
        candidate_block_height: u64,
    ) -> Result<(), EpochFenceRejection> {
        let state = self.lock_state();
        let round_epoch = round.epoch();
        if round_epoch < state.active_epoch {
            return Err(EpochFenceRejection::StaleEpoch {
                active_epoch: state.active_epoch,
            });
        }
        if round_epoch > state.active_epoch {
            return Err(EpochFenceRejection::FutureEpoch {
                active_epoch: state.active_epoch,
            });
        }
        if let Some(fence) = state.boundary {
            if fence.epoch == round_epoch && candidate_block_height > fence.max_block_height {
                return Err(EpochFenceRejection::BeyondBoundary {
                    max_block_height: fence.max_block_height,
                });
            }
        }
        Ok(())
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, EpochFenceState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

pub(crate) async fn resolve_epoch_boundary_parent(
    finalization_view: &FinalizationViewHandle,
    marshal_mailbox: &MarshalMailbox,
    clock: &impl commonware_runtime::Clock,
    round: Round,
    parent_view: View,
    parent_digest: Digest,
) -> Result<Option<EpochBoundaryParent>, EpochBoundaryParentError> {
    if round.epoch().get() == 0 || parent_view != View::new(0) {
        return Ok(None);
    }

    let anchor = finalization_view.finalized_anchor();
    let (expected_height, expected_hash, finalized_round) =
        (anchor.number, anchor.finalized_head_hash, anchor.round);
    let Some(finalized_round) = finalized_round else {
        return Err(EpochBoundaryParentError::MissingAnchor {
            epoch: round.epoch().get(),
        });
    };
    if expected_height == 0 || expected_hash == B256::ZERO {
        return Err(EpochBoundaryParentError::MissingAnchor {
            epoch: round.epoch().get(),
        });
    }
    if parent_digest.0 != expected_hash {
        return Err(EpochBoundaryParentError::ParentMismatch {
            expected: expected_hash,
            got: parent_digest.0,
            epoch: round.epoch().get(),
        });
    }

    // Marshal exposes only digest-based lookup. Since we just confirmed
    // `parent_digest == expected_hash`, looking up by digest yields the
    // committed anchor block; we then sanity-check the height to catch
    // a corrupted local store.
    let block_future = marshal_mailbox.clone().subscribe_by_digest(
        parent_digest,
        commonware_consensus::marshal::core::DigestFallback::Wait,
    );
    // `Clock::timeout` returns `Err(Error::Timeout)` on expiry; the inner
    // `Ok`/`Err` is the marshal waiter's own result, unchanged.
    let block = match clock
        .timeout(PROPOSE_RESOLUTION_TIMEOUT, block_future)
        .await
    {
        Ok(Ok(block)) => block,
        Ok(Err(_)) | Err(_) => {
            return Err(EpochBoundaryParentError::MissingMarshalBlock {
                height: expected_height,
            });
        }
    };
    if block.number() != expected_height {
        return Err(EpochBoundaryParentError::MarshalHashMismatch {
            height: expected_height,
            expected: parent_digest.0,
            got: block.digest().0,
        });
    }
    Ok(Some(EpochBoundaryParent {
        height: Height::new(expected_height),
        block,
        proof_key: CertifiedParentProofKey::new(
            finalized_round.epoch().get(),
            finalized_round.view().get(),
            expected_hash,
        ),
    }))
}

#[cfg(test)]
mod tests {
    use super::{ApplicationEpochFence, EpochFenceRejection};
    use commonware_consensus::types::{Epoch, Round, View};

    #[test]
    fn epoch_fence_allows_old_epoch_at_boundary_height() {
        let fence = ApplicationEpochFence::new(Epoch::new(2));
        fence.arm_activation_boundary(Epoch::new(2), 360);

        assert_eq!(
            fence.check(Round::new(Epoch::new(2), View::new(120)), 360),
            Ok(())
        );
    }

    #[test]
    fn epoch_fence_rejects_old_epoch_above_boundary_height() {
        let fence = ApplicationEpochFence::new(Epoch::new(2));
        fence.arm_activation_boundary(Epoch::new(2), 360);

        assert_eq!(
            fence.check(Round::new(Epoch::new(2), View::new(121)), 361),
            Err(EpochFenceRejection::BeyondBoundary {
                max_block_height: 360,
            })
        );
    }

    #[test]
    fn epoch_fence_rejects_old_epoch_after_advance() {
        let fence = ApplicationEpochFence::new(Epoch::new(2));
        fence.arm_activation_boundary(Epoch::new(2), 360);
        fence.advance_epoch(Epoch::new(3));

        assert_eq!(
            fence.check(Round::new(Epoch::new(2), View::new(1)), 361),
            Err(EpochFenceRejection::StaleEpoch {
                active_epoch: Epoch::new(3),
            })
        );
        assert_eq!(
            fence.check(Round::new(Epoch::new(3), View::new(1)), 361),
            Ok(())
        );
    }
}
