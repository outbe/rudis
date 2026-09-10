mod adapter;
mod state;

#[cfg(test)]
mod tests;

pub use state::{
    Active, ConsensusPubkey, Exiting, Inactive, Jail, JailRetained, Joining, P2pInfo,
    StakeProjection, Unbonding, ValidatorHistory, ValidatorLifecycle, ValidatorState,
    WaitingForReadiness, WaitingForStake,
};

use std::num::NonZeroU64;

use alloy_primitives::U256;
use outbe_primitives::error::{PrecompileError, Result};

/// Creates the first registered lifecycle bundle for an absent address.
pub(crate) fn register(
    state: ValidatorState,
    registry_index: NonZeroU64,
    consensus_pubkey: ConsensusPubkey,
    joined_at_height: u64,
) -> Result<ValidatorState> {
    if !matches!(state.lifecycle, ValidatorLifecycle::Absent) {
        return Err(PrecompileError::Revert(
            "validator is already registered".into(),
        ));
    }
    if consensus_pubkey == [0; 48] {
        return Err(PrecompileError::Revert(
            "consensus public key must not be zero".into(),
        ));
    }
    state.with_lifecycle(ValidatorLifecycle::WaitingForStake(WaitingForStake {
        registry_index,
        consensus_pubkey,
        p2p: P2pInfo::Unset,
        stake: StakeProjection::zero(),
        history: ValidatorHistory::fresh(joined_at_height),
    }))
}

/// Re-registers an inactive record in-place, retaining its dense index while
/// replacing identity material and clearing lifecycle-owned residue.
pub fn reregister(
    state: Inactive,
    consensus_pubkey: ConsensusPubkey,
    joined_at_height: u64,
) -> Result<WaitingForStake> {
    if consensus_pubkey == [0; 48] {
        return Err(PrecompileError::Revert(
            "consensus public key must not be zero".into(),
        ));
    }
    Ok(WaitingForStake {
        registry_index: state.registry_index,
        consensus_pubkey,
        p2p: P2pInfo::Unset,
        stake: StakeProjection::zero(),
        history: ValidatorHistory::fresh(joined_at_height),
    })
}

/// Moves a registered validator into the readiness path after Staking reports
/// an authoritative bonded amount at or above the minimum.
pub fn reach_minimum(
    state: WaitingForStake,
    stake: StakeProjection,
    minimum: U256,
) -> Result<WaitingForReadiness> {
    require_at_least_minimum(stake, minimum)?;
    Ok(WaitingForReadiness {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake,
        history: state.history,
    })
}

/// Records the validator operator's readiness confirmation.
pub fn confirm_ready(state: WaitingForReadiness) -> Joining {
    Joining {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history,
    }
}

/// Demotes an unconfirmed pending validator after its bonded stake falls below
/// the minimum.
pub fn demote_waiting_for_readiness(
    state: WaitingForReadiness,
    stake: StakeProjection,
    minimum: U256,
) -> Result<WaitingForStake> {
    require_below_minimum(stake, minimum)?;
    Ok(WaitingForStake {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake,
        history: state.history,
    })
}

/// Demotes a ready joiner and consumes its readiness confirmation.
pub fn demote_joining(
    state: Joining,
    stake: StakeProjection,
    minimum: U256,
) -> Result<WaitingForStake> {
    require_below_minimum(stake, minimum)?;
    Ok(WaitingForStake {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake,
        history: state.history,
    })
}

/// Activates an included, readiness-confirmed joiner at a validated boundary.
pub fn activate_at_boundary(state: Joining) -> Active {
    Active {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history.with_last_deactivated_at_height(None),
    }
}

/// Retains an existing active validator across a valid same-member boundary.
pub fn retain_active_at_boundary(state: Active) -> Active {
    state
}

/// Invalidates an active validator's readiness after its TEE lease expired.
/// The validator keeps its identity and stake, but must confirm readiness again
/// before it can join a later DKG target.
pub fn expire_active_tee(state: Active) -> WaitingForReadiness {
    WaitingForReadiness {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history,
    }
}

/// Consumes a joiner's readiness confirmation after its TEE lease expired.
pub fn expire_joining_tee(state: Joining) -> WaitingForReadiness {
    WaitingForReadiness {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history,
    }
}

/// Starts voluntary or forced exit while retaining current committee
/// accountability until the next validated boundary.
pub fn begin_exit(
    state: Active,
    stake: StakeProjection,
    deactivated_at_height: u64,
) -> Result<Exiting> {
    require_canonical_stake(stake)?;
    if deactivated_at_height == 0 {
        return Err(PrecompileError::Fatal(
            "validator deactivation height must be non-zero".into(),
        ));
    }
    Ok(Exiting {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake,
        history: state
            .history
            .with_last_deactivated_at_height(Some(deactivated_at_height)),
    })
}

/// Jails an active validator without clearing the old committee share.
pub fn jail(state: Active, jailed_at: u64) -> Result<JailRetained> {
    if jailed_at == 0 {
        return Err(PrecompileError::Fatal(
            "validator jail height must be non-zero".into(),
        ));
    }
    Ok(JailRetained {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state
            .history
            .with_last_deactivated_at_height(Some(jailed_at)),
        jailed_at,
    })
}

/// Clears a jailed validator's old committee accountability and current miss
/// slate at a validated exclusion boundary. The full history shape remains so
/// late finalized-parent accounting can record historical misses afterward.
pub fn exclude_jailed_at_boundary(state: JailRetained) -> Jail {
    Jail {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history.with_missed_counters_cleared(),
        jailed_at: state.jailed_at,
    }
}

/// A retained jailed validator may request permanent exit only by fully
/// unstaking. It remains accountable as `Exiting` until the boundary.
pub fn full_exit_jailed_retained(state: JailRetained, stake: StakeProjection) -> Result<Exiting> {
    require_fully_unstaked(stake)?;
    Ok(Exiting {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake,
        // Preserve the jail height: that is when future-committee eligibility
        // changed. A later unstake must not make a stale boundary include it.
        history: state.history,
    })
}

/// Returns an already-excluded jailed validator to the unconfirmed readiness
/// state after the cooldown and minimum-stake checks. Missed counters are reset
/// again because historical finalized-parent accounting may have populated them
/// after the exclusion boundary.
pub fn unjail(
    state: Jail,
    current_height: u64,
    cooldown_blocks: u64,
    minimum: U256,
) -> Result<WaitingForReadiness> {
    require_at_least_minimum(state.stake, minimum)?;
    let ready_at = state
        .jailed_at
        .checked_add(cooldown_blocks)
        .ok_or_else(|| PrecompileError::Fatal("unjail cooldown height overflow".into()))?;
    if current_height < ready_at {
        return Err(PrecompileError::Revert(format!(
            "unjail cooldown not elapsed: ready at {ready_at}, current {current_height}"
        )));
    }
    Ok(WaitingForReadiness {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history.with_missed_counters_cleared(),
    })
}

/// An already-excluded jailed validator does not need a second committee
/// boundary. Full unstake therefore enters `Unbonding` directly instead of
/// introducing an `EXITING` state without a share.
pub fn full_exit_jailed(state: Jail, stake: StakeProjection) -> Result<Unbonding> {
    require_fully_unstaked(stake)?;
    Ok(Unbonding {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake,
        history: state.history,
    })
}

/// Clears an exiting validator's live share at a validated boundary.
pub fn exclude_exiting_at_boundary(state: Exiting) -> Unbonding {
    Unbonding {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        stake: state.stake,
        history: state.history,
    }
}

/// Completes economic exit after Staking has proved zero bonded value and no
/// remaining live claim, represented here by a cleared compatibility hint.
pub fn complete_unbonding(state: Unbonding) -> Result<Inactive> {
    if !state.stake.bonded.is_zero() || state.stake.unbonding_end_hint.is_some() {
        return Err(PrecompileError::Revert(
            "cannot complete unbonding while bonded value or a live-claim hint remains".into(),
        ));
    }
    Ok(Inactive {
        registry_index: state.registry_index,
        consensus_pubkey: state.consensus_pubkey,
        p2p: state.p2p,
        history: state.history,
    })
}

/// Consumes an inactive registry entry after storage cleanup has repaired the
/// dense and reverse indexes.
pub fn cleanup(_state: Inactive) -> ValidatorLifecycle {
    ValidatorLifecycle::Absent
}

/// Replaces the ValidatorSet stake mirror without changing lifecycle meaning.
/// Threshold-crossing callers must use the specific transition functions above.
pub(crate) fn with_stake(
    mut lifecycle: ValidatorLifecycle,
    stake: StakeProjection,
) -> Result<ValidatorLifecycle> {
    require_canonical_stake(stake)?;
    match &mut lifecycle {
        ValidatorLifecycle::WaitingForStake(state) => state.stake = stake,
        ValidatorLifecycle::WaitingForReadiness(state) => state.stake = stake,
        ValidatorLifecycle::Joining(state) => state.stake = stake,
        ValidatorLifecycle::Active(state) => state.stake = stake,
        ValidatorLifecycle::JailRetained(state) => state.stake = stake,
        ValidatorLifecycle::Jail(state) => state.stake = stake,
        ValidatorLifecycle::Exiting(state) => state.stake = stake,
        ValidatorLifecycle::Unbonding(state) => state.stake = stake,
        ValidatorLifecycle::Absent => {
            return Err(PrecompileError::Revert(
                "cannot stake before validator registration".into(),
            ));
        }
        ValidatorLifecycle::Inactive(_) => {
            return Err(PrecompileError::Revert(
                "inactive validator must re-register before staking".into(),
            ));
        }
    }
    Ok(lifecycle)
}

/// Updates informational P2P data without changing lifecycle eligibility.
pub(crate) fn with_p2p(
    mut lifecycle: ValidatorLifecycle,
    p2p: P2pInfo,
) -> Result<ValidatorLifecycle> {
    match &mut lifecycle {
        ValidatorLifecycle::WaitingForStake(state) => state.p2p = p2p,
        ValidatorLifecycle::WaitingForReadiness(state) => state.p2p = p2p,
        ValidatorLifecycle::Joining(state) => state.p2p = p2p,
        ValidatorLifecycle::Active(state) => state.p2p = p2p,
        ValidatorLifecycle::JailRetained(state) => state.p2p = p2p,
        ValidatorLifecycle::Jail(state) => state.p2p = p2p,
        ValidatorLifecycle::Exiting(state) => state.p2p = p2p,
        ValidatorLifecycle::Unbonding(state) => state.p2p = p2p,
        ValidatorLifecycle::Inactive(state) => state.p2p = p2p,
        ValidatorLifecycle::Absent => {
            return Err(PrecompileError::Revert("validator not registered".into()));
        }
    }
    Ok(lifecycle)
}

/// Updates retained history without permitting a lifecycle rewrite.
pub(crate) fn with_history(
    mut lifecycle: ValidatorLifecycle,
    history: ValidatorHistory,
) -> Result<ValidatorLifecycle> {
    if history.last_deactivated_at_height == Some(0) {
        return Err(PrecompileError::Fatal(
            "deactivation height must not use the zero sentinel".into(),
        ));
    }
    match &mut lifecycle {
        ValidatorLifecycle::WaitingForStake(state) => state.history = history,
        ValidatorLifecycle::WaitingForReadiness(state) => state.history = history,
        ValidatorLifecycle::Joining(state) => state.history = history,
        ValidatorLifecycle::Active(state) => {
            if history.last_deactivated_at_height.is_some() {
                return Err(PrecompileError::Fatal(
                    "active history must not contain a deactivation height".into(),
                ));
            }
            state.history = history;
        }
        ValidatorLifecycle::JailRetained(state) => {
            if history.last_deactivated_at_height != Some(state.jailed_at) {
                return Err(PrecompileError::Fatal(
                    "retained jail history must match the jail height".into(),
                ));
            }
            state.history = history;
        }
        ValidatorLifecycle::Jail(state) => {
            if history.last_deactivated_at_height != Some(state.jailed_at) {
                return Err(PrecompileError::Fatal(
                    "jail history must match the jail height".into(),
                ));
            }
            state.history = history;
        }
        ValidatorLifecycle::Exiting(state) => {
            if history.last_deactivated_at_height.is_none() {
                return Err(PrecompileError::Fatal(
                    "exiting history requires a deactivation height".into(),
                ));
            }
            state.history = history;
        }
        ValidatorLifecycle::Unbonding(state) => {
            if history.last_deactivated_at_height.is_none() {
                return Err(PrecompileError::Fatal(
                    "unbonding history requires a deactivation height".into(),
                ));
            }
            state.history = history;
        }
        ValidatorLifecycle::Inactive(state) => {
            if history.last_deactivated_at_height.is_none() {
                return Err(PrecompileError::Fatal(
                    "inactive history requires a deactivation height".into(),
                ));
            }
            state.history = history;
        }
        ValidatorLifecycle::Absent => {
            return Err(PrecompileError::Revert("validator not registered".into()));
        }
    }
    Ok(lifecycle)
}

fn require_at_least_minimum(stake: StakeProjection, minimum: U256) -> Result<()> {
    require_canonical_stake(stake)?;
    if stake.bonded < minimum {
        return Err(PrecompileError::Revert(format!(
            "bonded stake {} is below minimum {minimum}",
            stake.bonded
        )));
    }
    Ok(())
}

fn require_below_minimum(stake: StakeProjection, minimum: U256) -> Result<()> {
    require_canonical_stake(stake)?;
    if stake.bonded >= minimum {
        return Err(PrecompileError::Revert(format!(
            "bonded stake {} has not fallen below minimum {minimum}",
            stake.bonded
        )));
    }
    Ok(())
}

fn require_fully_unstaked(stake: StakeProjection) -> Result<()> {
    require_canonical_stake(stake)?;
    if !stake.bonded.is_zero() {
        return Err(PrecompileError::Revert(
            "jailed validator must fully unstake before permanent exit".into(),
        ));
    }
    Ok(())
}

fn require_canonical_stake(stake: StakeProjection) -> Result<()> {
    if stake.unbonding_end_hint == Some(0) {
        return Err(PrecompileError::Fatal(
            "unbonding-end hint must not use the zero sentinel".into(),
        ));
    }
    Ok(())
}
