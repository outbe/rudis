//! Proposer-side VRF/DKG freshness gate.
//!
//! `VrfSafetyGate` is a *proposer-side* hygiene check - it gates whether the
//! local node may continue to propose blocks given the freshness of the
//! active VRF material. It is **not** a verifier:
//!
//! - **Do not import** [`VrfSafetyGate`] into import-time paths (the block
//!   import pipeline must consult the state-backed canonical
//!   `CommitteeSnapshotStore` instead - this gate is process-local and would
//!   diverge from the snapshot on restart).
//! - **Do not import** it into the V2 verifier (`outbe-consensus-proof`)
//!   either; verifier inputs come from chain state, not from local
//!   bookkeeping.
//! - Legitimate importers:
//!   1. [`crate::application::handler`] - proposer emission path
//!      (`build_block` and `ensure_block_allowed` guard).
//!   2. [`crate::finalization::actor`] - post-finalization side effects
//!      (`mark_degraded` after a missing VRF seed, `snapshot` for the bridge
//!      `ConsensusStatus`). These run on the consensus actor task, NOT the
//!      block-import path, and so do not violate the narrowing.
//! - Any new importer that runs during block import or in the verifier MUST
//!   first re-derive its values from the canonical
//!   `CommitteeSnapshotStore` rather than reading [`VrfSafetyGate`] state.

use std::sync::{Arc, Mutex};

use eyre::{ensure, Result};
use outbe_primitives::consensus::RandomnessStatus;

#[derive(Debug, Clone)]
pub struct VrfSafetySnapshot {
    pub randomness_status: RandomnessStatus,
    pub vrf_material_version: u64,
    pub last_dkg_activation_height: u64,
    pub next_planned_activation_height: u64,
    pub vrf_expiry_height: u64,
}

#[derive(Debug, Clone)]
struct VrfSafetyState {
    snapshot: VrfSafetySnapshot,
}

#[derive(Debug, Clone)]
pub struct VrfSafetyGate {
    inner: Arc<Mutex<VrfSafetyState>>,
}

impl VrfSafetyGate {
    pub fn new(
        vrf_material_version: u64,
        last_dkg_activation_height: u64,
        next_planned_activation_height: u64,
        activation_grace_blocks: u64,
    ) -> Self {
        let vrf_expiry_height =
            next_planned_activation_height.saturating_add(activation_grace_blocks);
        Self {
            inner: Arc::new(Mutex::new(VrfSafetyState {
                snapshot: VrfSafetySnapshot {
                    randomness_status: RandomnessStatus::Healthy,
                    vrf_material_version,
                    last_dkg_activation_height,
                    next_planned_activation_height,
                    vrf_expiry_height,
                },
            })),
        }
    }

    pub fn snapshot(&self) -> VrfSafetySnapshot {
        self.with_state(|state| state.snapshot.clone())
    }

    pub fn note_preparing(
        &self,
        dkg_cycle: u64,
        freeze_height: u64,
        planned_activation_height: u64,
        activation_grace_blocks: u64,
    ) {
        tracing::info!(
            dkg_cycle,
            freeze_height,
            planned_activation_height,
            "VRF/DKG rotation entered prepare window"
        );
        self.update_status(
            RandomnessStatus::Preparing,
            planned_activation_height,
            activation_grace_blocks,
        );
    }

    pub fn note_pending_activation(
        &self,
        planned_activation_height: u64,
        activation_grace_blocks: u64,
    ) {
        self.update_status(
            RandomnessStatus::PendingActivation,
            planned_activation_height,
            activation_grace_blocks,
        );
    }

    pub fn note_grace(&self, planned_activation_height: u64, activation_grace_blocks: u64) {
        self.update_status(
            RandomnessStatus::Grace,
            planned_activation_height,
            activation_grace_blocks,
        );
    }

    pub fn note_activated(
        &self,
        vrf_material_version: u64,
        activation_height: u64,
        next_planned_activation_height: u64,
        activation_grace_blocks: u64,
    ) {
        let next_expiry_height =
            next_planned_activation_height.saturating_add(activation_grace_blocks);
        self.with_state(|state| {
            if state.snapshot.randomness_status == RandomnessStatus::Expired {
                return;
            }
            state.snapshot = VrfSafetySnapshot {
                randomness_status: RandomnessStatus::Healthy,
                vrf_material_version,
                last_dkg_activation_height: activation_height,
                next_planned_activation_height,
                vrf_expiry_height: next_expiry_height,
            };
        });
    }

    pub fn mark_degraded(&self) {
        self.with_state(|state| {
            if state.snapshot.randomness_status != RandomnessStatus::Expired {
                state.snapshot.randomness_status = RandomnessStatus::Degraded;
            }
        });
    }

    pub fn mark_expired(&self, current_height: u64) {
        self.with_state(|state| {
            state.snapshot.randomness_status = RandomnessStatus::Expired;
        });
        crate::metrics::record_vrf_randomness_expired();
        tracing::error!(
            current_height,
            "VRF material expired before DKG activation; validator progress must stop"
        );
    }

    pub fn ensure_block_allowed(&self, block_height: u64) -> Result<()> {
        let snapshot = self.snapshot();
        ensure!(
            snapshot.randomness_status != RandomnessStatus::Expired
                && block_height <= snapshot.vrf_expiry_height,
            "VRF material expired: block {block_height} exceeds expiry height {}",
            snapshot.vrf_expiry_height
        );
        Ok(())
    }

    fn update_status(
        &self,
        status: RandomnessStatus,
        planned_activation_height: u64,
        activation_grace_blocks: u64,
    ) {
        let expiry_height = planned_activation_height.saturating_add(activation_grace_blocks);
        self.with_state(|state| {
            if state.snapshot.randomness_status == RandomnessStatus::Expired {
                return;
            }
            state.snapshot.randomness_status = status;
            state.snapshot.next_planned_activation_height = planned_activation_height;
            state.snapshot.vrf_expiry_height = expiry_height;
        });
    }

    fn with_state<T>(&self, f: impl FnOnce(&mut VrfSafetyState) -> T) -> T {
        let mut state = match self.inner.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                tracing::error!("VrfSafetyGate mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        f(&mut state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_rejects_blocks_after_expiry() {
        let gate = VrfSafetyGate::new(0, 0, 10, 2);
        assert!(gate.ensure_block_allowed(12).is_ok());
        assert!(gate.ensure_block_allowed(13).is_err());
    }

    #[test]
    fn activation_resets_expiry() {
        let gate = VrfSafetyGate::new(0, 0, 10, 2);
        gate.note_activated(1, 11, 21, 2);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.randomness_status, RandomnessStatus::Healthy);
        assert_eq!(snapshot.vrf_material_version, 1);
        assert_eq!(snapshot.last_dkg_activation_height, 11);
        assert_eq!(snapshot.next_planned_activation_height, 21);
        assert_eq!(snapshot.vrf_expiry_height, 23);
    }

    #[test]
    fn expired_status_is_sticky_across_forward_notes() {
        let gate = VrfSafetyGate::new(0, 0, 10, 2);
        gate.mark_expired(13);

        gate.note_preparing(1, 14, 20, 3);
        assert_eq!(gate.snapshot().randomness_status, RandomnessStatus::Expired);

        gate.note_pending_activation(20, 3);
        assert_eq!(gate.snapshot().randomness_status, RandomnessStatus::Expired);

        gate.note_grace(20, 3);
        assert_eq!(gate.snapshot().randomness_status, RandomnessStatus::Expired);

        gate.note_activated(1, 20, 30, 3);
        let snapshot = gate.snapshot();
        assert_eq!(snapshot.randomness_status, RandomnessStatus::Expired);
        assert_eq!(snapshot.vrf_material_version, 0);
        assert_eq!(snapshot.last_dkg_activation_height, 0);
        assert_eq!(snapshot.next_planned_activation_height, 10);
        assert_eq!(snapshot.vrf_expiry_height, 12);
    }
}
