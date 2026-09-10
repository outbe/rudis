//! Module-structure standard layout:
//! - `schema.rs` - storage schema for the `ValidatorSet` facade.
//! - `state.rs` - `CommitteeSnapshotStore` helpers.
//! - `runtime.rs` - validator-set use-cases and the raw-storage adapter.
//! - `state_machine/` - typed validator lifecycle, transitions and storage adapter.
//! - `hooks.rs` - per-finalized-block guard wrappers.
//! - `precompile.rs` - ABI dispatch.
//! - `errors.rs` - module-local activation error type.
//!
//! `pub use` re-exports below preserve the old `contract` / `logic`
//! paths for external callers; migrate them opportunistically.
pub mod delegation;
pub mod errors;
pub mod hooks;
pub mod metrics;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod state;
pub mod state_machine;

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub mod test_support;

#[cfg(test)]
mod tests;

pub mod contract {
    pub use crate::schema::*;
}
pub mod logic {
    pub use crate::runtime::*;
}

pub use errors::ActivationError;
pub use runtime::{EpochSnapshot, ValidatorParticipation, ValidatorRecord};
pub use state::{
    clear_committee_snapshot, committee_set_hash_v2, committee_snapshot_key,
    next_vrf_material_version, ocomp_binding_hash_v1, read_committee_snapshot,
    read_committee_snapshot_for_epoch, read_ocomp_snapshot_extension,
    read_ocomp_snapshot_extension_at_epoch, read_ocomp_snapshot_extension_for_binding,
    read_ocomp_snapshot_member_at, snapshot_identity, write_committee_snapshot, CommitteeEntry,
    CommitteeSnapshot, OcompSnapshotExtensionV1, OcompSnapshotMemberV1,
    COMMITTEE_SNAPSHOT_RETAIN_EPOCHS, OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN,
    OUTBE_COMMITTEE_SNAPSHOT_KEY_V2_DOMAIN, OUTBE_OCOMP_SNAPSHOT_BINDING_V1_DOMAIN,
    VRF_MATERIAL_VERSION_GENESIS,
};
pub use state_machine::{
    Active, ConsensusPubkey, Exiting, Inactive, Jail, JailRetained, Joining, P2pInfo,
    StakeProjection, Unbonding, ValidatorHistory, ValidatorLifecycle, ValidatorState,
    WaitingForReadiness, WaitingForStake,
};
