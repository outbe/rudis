use std::num::NonZeroU64;

use alloy_primitives::{Address, U256};
use outbe_primitives::consensus_p2p::{decode_versioned, encode_v1, P2P_ADDRESS_VERSION_V1};
use outbe_primitives::error::{PrecompileError, Result};

use crate::runtime::status::{ACTIVE, EXITING, INACTIVE, JAILED, PENDING, REGISTERED, UNBONDING};

use super::state::{
    Active, ConsensusPubkey, Exiting, Inactive, Jail, JailRetained, Joining, P2pInfo,
    StakeProjection, Unbonding, ValidatorHistory, ValidatorLifecycle, ValidatorState,
    WaitingForReadiness, WaitingForStake,
};

macro_rules! lifecycle_ref {
    ($lifecycle:expr, $field:ident) => {
        match $lifecycle {
            ValidatorLifecycle::Absent => None,
            ValidatorLifecycle::WaitingForStake(state) => Some(&state.$field),
            ValidatorLifecycle::WaitingForReadiness(state) => Some(&state.$field),
            ValidatorLifecycle::Joining(state) => Some(&state.$field),
            ValidatorLifecycle::Active(state) => Some(&state.$field),
            ValidatorLifecycle::JailRetained(state) => Some(&state.$field),
            ValidatorLifecycle::Jail(state) => Some(&state.$field),
            ValidatorLifecycle::Exiting(state) => Some(&state.$field),
            ValidatorLifecycle::Unbonding(state) => Some(&state.$field),
            ValidatorLifecycle::Inactive(state) => Some(&state.$field),
        }
    };
}

impl P2pInfo {
    /// Decodes the two persisted P2P fields as one atomic value.
    pub(crate) fn decode_stored(validator: Address, version: u8, payload: &[u8]) -> Result<Self> {
        if version == 0 && payload.is_empty() {
            return Ok(Self::Unset);
        }
        if version == 0 || payload.is_empty() {
            return Err(corrupt_state(
                validator,
                "P2P version and payload must be both set or both empty",
            ));
        }
        if version != P2P_ADDRESS_VERSION_V1 {
            return Ok(Self::Opaque {
                version,
                payload: payload.to_vec(),
            });
        }
        let address = decode_versioned(version, payload).map_err(|error| {
            corrupt_state(
                validator,
                format_args!("invalid persisted P2P address: {error}"),
            )
        })?;
        Ok(Self::V1(address))
    }

    /// Encodes both persisted P2P fields as one atomic value.
    pub(crate) fn encode_stored(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Unset => (0, Vec::new()),
            Self::V1(address) => (P2P_ADDRESS_VERSION_V1, encode_v1(address)),
            Self::Opaque { version, payload } => (*version, payload.clone()),
        }
    }
}

impl ValidatorState {
    pub const fn absent(address: Address) -> Self {
        Self {
            address,
            lifecycle: ValidatorLifecycle::Absent,
        }
    }

    /// The sole raw-storage-to-type-state adapter.
    ///
    /// Raw status tags remain ABI-compatible, while every coupled-field
    /// combination outside the canonical state machine fails closed. Stake
    /// threshold checks remain at the Staking transition seam because Staking,
    /// not ValidatorSet, owns the authoritative minimum and bonded ledger.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decode_stored(
        address: Address,
        registry_index: u64,
        consensus_pubkey: ConsensusPubkey,
        stake: StakeProjection,
        stored_status: u8,
        p2p_version: u8,
        p2p_payload: &[u8],
        history: ValidatorHistory,
        has_bls_share: bool,
        join_confirmed: bool,
        jailed_at: u64,
    ) -> Result<Self> {
        validate_hint(address, stake)?;
        let p2p = P2pInfo::decode_stored(address, p2p_version, p2p_payload)?;

        let Some(registry_index) = NonZeroU64::new(registry_index) else {
            if consensus_pubkey != [0; 48]
                || !stake.bonded.is_zero()
                || stake.unbonding_end_hint.is_some()
                || stored_status != REGISTERED
                || !matches!(p2p, P2pInfo::Unset)
                || !history.is_zero()
                || has_bls_share
                || join_confirmed
                || jailed_at != 0
            {
                return Err(corrupt_state(
                    address,
                    "absent validator retains registry, stake, or lifecycle data",
                ));
            }
            return Ok(Self::absent(address));
        };

        ValidatorLifecycle::validate_stored_status(stored_status)?;
        if consensus_pubkey == [0; 48] {
            return Err(corrupt_state(
                address,
                "registered validator is missing its consensus public key",
            ));
        }
        if stored_status != JAILED && jailed_at != 0 {
            return Err(corrupt_state(
                address,
                "jail height is present outside a jailed lifecycle",
            ));
        }

        macro_rules! payload {
            ($name:ident) => {
                $name {
                    registry_index,
                    consensus_pubkey,
                    p2p,
                    stake,
                    history,
                }
            };
            ($name:ident, jailed_at) => {
                $name {
                    registry_index,
                    consensus_pubkey,
                    p2p,
                    stake,
                    history,
                    jailed_at,
                }
            };
        }

        let lifecycle = match stored_status {
            REGISTERED if !has_bls_share && !join_confirmed => {
                ValidatorLifecycle::WaitingForStake(payload!(WaitingForStake))
            }
            PENDING if !has_bls_share && !join_confirmed => {
                ValidatorLifecycle::WaitingForReadiness(payload!(WaitingForReadiness))
            }
            PENDING if !has_bls_share && join_confirmed => {
                ValidatorLifecycle::Joining(payload!(Joining))
            }
            ACTIVE if has_bls_share && !join_confirmed => {
                ValidatorLifecycle::Active(payload!(Active))
            }
            EXITING if has_bls_share && !join_confirmed => {
                ValidatorLifecycle::Exiting(payload!(Exiting))
            }
            UNBONDING if !has_bls_share && !join_confirmed => {
                ValidatorLifecycle::Unbonding(payload!(Unbonding))
            }
            INACTIVE if !has_bls_share && !join_confirmed => {
                if !stake.bonded.is_zero() || stake.unbonding_end_hint.is_some() {
                    return Err(corrupt_state(
                        address,
                        "inactive validator retains bonded stake or an unbonding hint",
                    ));
                }
                ValidatorLifecycle::Inactive(Inactive {
                    registry_index,
                    consensus_pubkey,
                    p2p,
                    history,
                })
            }
            JAILED if has_bls_share && !join_confirmed => {
                ValidatorLifecycle::JailRetained(payload!(JailRetained, jailed_at))
            }
            JAILED if !has_bls_share && !join_confirmed => {
                ValidatorLifecycle::Jail(payload!(Jail, jailed_at))
            }
            _ => {
                return Err(corrupt_state(
                    address,
                    format_args!(
                        "non-canonical coupled fields: status={stored_status}, share={has_bls_share}, readiness={join_confirmed}, jailed_at={jailed_at}"
                    ),
                ));
            }
        };

        let state = Self { address, lifecycle };
        state.validate()?;
        Ok(state)
    }

    pub const fn address(&self) -> Address {
        self.address
    }

    pub const fn lifecycle(&self) -> &ValidatorLifecycle {
        &self.lifecycle
    }

    pub fn into_lifecycle(self) -> ValidatorLifecycle {
        self.lifecycle
    }

    pub(crate) fn from_lifecycle(address: Address, lifecycle: ValidatorLifecycle) -> Result<Self> {
        let state = Self { address, lifecycle };
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn with_lifecycle(self, lifecycle: ValidatorLifecycle) -> Result<Self> {
        Self::from_lifecycle(self.address, lifecycle)
    }

    pub const fn is_registered(&self) -> bool {
        !matches!(self.lifecycle, ValidatorLifecycle::Absent)
    }

    pub fn registry_index(&self) -> Option<NonZeroU64> {
        self.lifecycle.registry_index()
    }

    pub fn consensus_pubkey(&self) -> Option<&ConsensusPubkey> {
        self.lifecycle.consensus_pubkey()
    }

    pub fn p2p(&self) -> Option<&P2pInfo> {
        self.lifecycle.p2p()
    }

    /// Compatibility accessor for the ValidatorSet stake mirror. `None` is an
    /// encoded zero for `Absent` and `Inactive`.
    pub fn stake(&self) -> Option<&StakeProjection> {
        self.lifecycle.stake()
    }

    pub fn bonded_stake(&self) -> U256 {
        self.stake().map_or(U256::ZERO, StakeProjection::bonded)
    }

    pub fn unbonding_end_hint(&self) -> Option<u64> {
        self.stake().and_then(StakeProjection::unbonding_end_hint)
    }

    pub fn history(&self) -> Option<&ValidatorHistory> {
        self.lifecycle.history()
    }

    pub fn has_bls_share(&self) -> bool {
        self.lifecycle.has_bls_share()
    }

    pub fn join_confirmed(&self) -> bool {
        self.lifecycle.join_confirmed()
    }

    pub fn stored_status(&self) -> Option<u8> {
        self.lifecycle.stored_status()
    }

    pub fn stored_jailed_at(&self) -> u64 {
        self.lifecycle.stored_jailed_at()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.lifecycle.validate(self.address)
    }
}

impl ValidatorLifecycle {
    pub(crate) fn validate_stored_status(status: u8) -> Result<()> {
        if status <= JAILED {
            Ok(())
        } else {
            Err(PrecompileError::Fatal(format!(
                "unknown validator status {status}"
            )))
        }
    }

    pub fn stored_status(&self) -> Option<u8> {
        match self {
            Self::Absent => None,
            Self::WaitingForStake(_) => Some(REGISTERED),
            Self::WaitingForReadiness(_) | Self::Joining(_) => Some(PENDING),
            Self::Active(_) => Some(ACTIVE),
            Self::Exiting(_) => Some(EXITING),
            Self::Unbonding(_) => Some(UNBONDING),
            Self::Inactive(_) => Some(INACTIVE),
            Self::JailRetained(_) | Self::Jail(_) => Some(JAILED),
        }
    }

    pub const fn has_bls_share(&self) -> bool {
        matches!(
            self,
            Self::Active(_) | Self::JailRetained(_) | Self::Exiting(_)
        )
    }

    pub const fn join_confirmed(&self) -> bool {
        matches!(self, Self::Joining(_))
    }

    pub const fn stored_jailed_at(&self) -> u64 {
        match self {
            Self::JailRetained(state) => state.jailed_at,
            Self::Jail(state) => state.jailed_at,
            _ => 0,
        }
    }

    pub const fn is_active_status(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::WaitingForReadiness(_) | Self::Joining(_))
    }

    pub const fn is_registered_status(&self) -> bool {
        matches!(self, Self::WaitingForStake(_))
    }

    pub const fn is_current_consensus_participant(&self) -> bool {
        matches!(
            self,
            Self::Active(_) | Self::Exiting(_) | Self::JailRetained(_)
        )
    }

    pub const fn is_reshare_target(&self) -> bool {
        matches!(self, Self::Active(_) | Self::Joining(_))
    }

    pub const fn is_secondary_admission(&self) -> bool {
        matches!(
            self,
            Self::WaitingForStake(_)
                | Self::WaitingForReadiness(_)
                | Self::Joining(_)
                | Self::JailRetained(_)
                | Self::Jail(_)
        )
    }

    pub fn registry_index(&self) -> Option<NonZeroU64> {
        lifecycle_ref!(self, registry_index).copied()
    }

    pub fn consensus_pubkey(&self) -> Option<&ConsensusPubkey> {
        lifecycle_ref!(self, consensus_pubkey)
    }

    pub fn p2p(&self) -> Option<&P2pInfo> {
        lifecycle_ref!(self, p2p)
    }

    pub fn stake(&self) -> Option<&StakeProjection> {
        match self {
            Self::WaitingForStake(state) => Some(&state.stake),
            Self::WaitingForReadiness(state) => Some(&state.stake),
            Self::Joining(state) => Some(&state.stake),
            Self::Active(state) => Some(&state.stake),
            Self::JailRetained(state) => Some(&state.stake),
            Self::Jail(state) => Some(&state.stake),
            Self::Exiting(state) => Some(&state.stake),
            Self::Unbonding(state) => Some(&state.stake),
            Self::Absent | Self::Inactive(_) => None,
        }
    }

    pub fn history(&self) -> Option<&ValidatorHistory> {
        lifecycle_ref!(self, history)
    }

    pub(crate) fn validate(&self, address: Address) -> Result<()> {
        if let Some(key) = self.consensus_pubkey() {
            if *key == [0; 48] {
                return Err(corrupt_state(
                    address,
                    "registered validator has a zero key",
                ));
            }
        }
        if let Some(stake) = self.stake() {
            validate_hint(address, *stake)?;
        }
        if self
            .history()
            .is_some_and(|history| history.last_deactivated_at_height == Some(0))
        {
            return Err(corrupt_state(
                address,
                "deactivation height uses a non-canonical zero sentinel",
            ));
        }
        match self {
            Self::Active(state) if state.history.last_deactivated_at_height.is_some() => {
                return Err(corrupt_state(
                    address,
                    "active validator retains a deactivation height",
                ));
            }
            Self::Exiting(state) if state.history.last_deactivated_at_height.is_none() => {
                return Err(corrupt_state(
                    address,
                    "exiting validator is missing its deactivation height",
                ));
            }
            Self::Unbonding(state) if state.history.last_deactivated_at_height.is_none() => {
                return Err(corrupt_state(
                    address,
                    "unbonding validator is missing its deactivation height",
                ));
            }
            Self::Inactive(state) if state.history.last_deactivated_at_height.is_none() => {
                return Err(corrupt_state(
                    address,
                    "inactive validator is missing its deactivation height",
                ));
            }
            Self::JailRetained(state)
                if state.jailed_at == 0
                    || state.history.last_deactivated_at_height != Some(state.jailed_at) =>
            {
                return Err(corrupt_state(
                    address,
                    "retained jail height and history deactivation height disagree",
                ));
            }
            Self::Jail(state)
                if state.jailed_at == 0
                    || state.history.last_deactivated_at_height != Some(state.jailed_at) =>
            {
                return Err(corrupt_state(
                    address,
                    "jail height and history deactivation height disagree",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn validate_hint(address: Address, stake: StakeProjection) -> Result<()> {
    if stake.unbonding_end_hint == Some(0) {
        return Err(corrupt_state(
            address,
            "unbonding-end hint uses a non-canonical zero sentinel",
        ));
    }
    Ok(())
}

fn corrupt_state(address: Address, detail: impl std::fmt::Display) -> PrecompileError {
    PrecompileError::Fatal(format!("corrupt validator state for {address}: {detail}"))
}
