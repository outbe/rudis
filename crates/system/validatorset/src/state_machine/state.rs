use std::num::NonZeroU64;

use alloy_primitives::{Address, U256};
use outbe_primitives::consensus_p2p::P2pAddress;

/// Canonical BLS12-381 MinPk public key used to identify a validator.
pub type ConsensusPubkey = [u8; 48];

/// A validator address together with its complete canonical lifecycle.
///
/// Every field whose meaning depends on the lifecycle is owned by the
/// corresponding lifecycle payload. `address` remains outside the enum because
/// it identifies both an absent registry slot and every registered state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorState {
    pub(super) address: Address,
    pub(super) lifecycle: ValidatorLifecycle,
}

/// Canonical validator lifecycle. Several variants intentionally map to the
/// same persisted status byte because the coupled fields distinguish real
/// protocol states that the legacy `uint8` status cannot express by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorLifecycle {
    /// `address_to_index == 0`; all validator-owned storage is empty.
    Absent,

    /// Persisted `REGISTERED`: identity exists, but bonded stake has not
    /// admitted the validator to the readiness path.
    WaitingForStake(WaitingForStake),

    /// Persisted `PENDING` with readiness not yet confirmed.
    WaitingForReadiness(WaitingForReadiness),

    /// Persisted `PENDING` with readiness confirmed; eligible for the next
    /// canonical DKG target but not a current consensus participant.
    Joining(Joining),

    /// Persisted `ACTIVE`; always owns a live committee share.
    Active(Active),

    /// Persisted `JAILED` while its old live share remains accountable until
    /// the exclusion boundary.
    JailRetained(JailRetained),

    /// Persisted `JAILED` after a successful boundary cleared the old share.
    Jail(Jail),

    /// Persisted `EXITING`; always retained in the current committee until the
    /// exclusion boundary.
    Exiting(Exiting),

    /// Persisted `UNBONDING`; consensus membership is already cleared while
    /// Staking drains residual bonded value and live claims.
    Unbonding(Unbonding),

    /// Persisted `INACTIVE`; bonded stake and the compatibility unbonding hint
    /// are both zero, while registry identity remains until re-registration or
    /// bounded cleanup.
    Inactive(Inactive),
}

/// Versioned validator P2P information. P2P publication is informational and
/// is not a lifecycle prerequisite, so every registered state can carry
/// `Unset`. Unknown persisted versions remain opaque so state readers can
/// preserve forward-compatible registry entries without admitting them as
/// usable peers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum P2pInfo {
    #[default]
    Unset,
    V1(P2pAddress),
    Opaque {
        version: u8,
        payload: Vec<u8>,
    },
}

impl P2pInfo {
    pub const fn address(&self) -> Option<&P2pAddress> {
        match self {
            Self::Unset | Self::Opaque { .. } => None,
            Self::V1(address) => Some(address),
        }
    }
}

/// ABI-compatible projection of the stake fields mirrored in ValidatorSet.
/// Staking remains authoritative for bonded value and the list of live claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeProjection {
    pub(super) bonded: U256,
    pub(super) unbonding_end_hint: Option<u64>,
}

impl StakeProjection {
    pub const fn new(bonded: U256, unbonding_end_hint: Option<u64>) -> Self {
        Self {
            bonded,
            unbonding_end_hint,
        }
    }

    pub const fn zero() -> Self {
        Self::new(U256::ZERO, None)
    }

    pub const fn bonded(&self) -> U256 {
        self.bonded
    }

    pub const fn unbonding_end_hint(&self) -> Option<u64> {
        self.unbonding_end_hint
    }
}

/// Historical and per-epoch counters retained for the entire lifetime of a
/// registry entry. The full history remains present in both jailed states
/// because finalized-parent accounting may update historical members even
/// after a boundary has excluded them from the live committee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorHistory {
    pub(super) joined_at_height: u64,
    pub(super) last_deactivated_at_height: Option<u64>,
    pub(super) slash_count: u64,
    pub(super) missed_blocks: u64,
    pub(super) missed_votes: u64,
    pub(super) blocks_proposed: u64,
}

impl ValidatorHistory {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        joined_at_height: u64,
        last_deactivated_at_height: Option<u64>,
        slash_count: u64,
        missed_blocks: u64,
        missed_votes: u64,
        blocks_proposed: u64,
    ) -> Self {
        Self {
            joined_at_height,
            last_deactivated_at_height,
            slash_count,
            missed_blocks,
            missed_votes,
            blocks_proposed,
        }
    }

    pub const fn fresh(joined_at_height: u64) -> Self {
        Self::new(joined_at_height, None, 0, 0, 0, 0)
    }

    pub const fn joined_at_height(&self) -> u64 {
        self.joined_at_height
    }

    pub const fn last_deactivated_at_height(&self) -> Option<u64> {
        self.last_deactivated_at_height
    }

    pub const fn slash_count(&self) -> u64 {
        self.slash_count
    }

    pub const fn missed_blocks(&self) -> u64 {
        self.missed_blocks
    }

    pub const fn missed_votes(&self) -> u64 {
        self.missed_votes
    }

    pub const fn blocks_proposed(&self) -> u64 {
        self.blocks_proposed
    }

    pub const fn with_last_deactivated_at_height(
        mut self,
        last_deactivated_at_height: Option<u64>,
    ) -> Self {
        self.last_deactivated_at_height = last_deactivated_at_height;
        self
    }

    pub(super) const fn with_missed_counters_cleared(mut self) -> Self {
        self.missed_blocks = 0;
        self.missed_votes = 0;
        self
    }

    pub const fn is_zero(&self) -> bool {
        self.joined_at_height == 0
            && self.last_deactivated_at_height.is_none()
            && self.slash_count == 0
            && self.missed_blocks == 0
            && self.missed_votes == 0
            && self.blocks_proposed == 0
    }
}

macro_rules! validator_payload {
    ($name:ident, stake) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub(super) registry_index: NonZeroU64,
            pub(super) consensus_pubkey: ConsensusPubkey,
            pub(super) p2p: P2pInfo,
            pub(super) stake: StakeProjection,
            pub(super) history: ValidatorHistory,
        }
    };
    ($name:ident, stake, jailed_at) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub(super) registry_index: NonZeroU64,
            pub(super) consensus_pubkey: ConsensusPubkey,
            pub(super) p2p: P2pInfo,
            pub(super) stake: StakeProjection,
            pub(super) history: ValidatorHistory,
            pub(super) jailed_at: u64,
        }
    };
    ($name:ident, no_stake) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            pub(super) registry_index: NonZeroU64,
            pub(super) consensus_pubkey: ConsensusPubkey,
            pub(super) p2p: P2pInfo,
            pub(super) history: ValidatorHistory,
        }
    };
}

validator_payload!(WaitingForStake, stake);
validator_payload!(WaitingForReadiness, stake);
validator_payload!(Joining, stake);
validator_payload!(Active, stake);
validator_payload!(JailRetained, stake, jailed_at);
validator_payload!(Jail, stake, jailed_at);
validator_payload!(Exiting, stake);
validator_payload!(Unbonding, stake);
validator_payload!(Inactive, no_stake);
