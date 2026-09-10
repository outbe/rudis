use alloy_primitives::{Address, U256};
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::runtime::{
    DeferredValidatorPunishment, OcompMissRecord, OcompRecoveryOutcome,
};
use outbe_validatorset::ValidatorLifecycle;

use crate::contract::Staking;

pub const OCOMP_MISS_SLASH_PERCENT: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcompMissPenalty {
    pub first_in_window: bool,
    pub miss_count: u64,
    pub recovery_deadline: u64,
    pub slashed_bonded: U256,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OcompRecoverySweep {
    pub open_windows: u32,
    pub restored: u32,
    pub jailed: u32,
    pub closed_non_active: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcompRecoveryResolution {
    NotOpen,
    NotDue {
        recovery_deadline: u64,
    },
    Restored {
        recovery_deadline: u64,
    },
    Jailed {
        recovery_deadline: u64,
        observability: DeferredValidatorPunishment,
    },
    ClosedNonActive {
        recovery_deadline: u64,
    },
}

impl OcompRecoveryResolution {
    #[must_use]
    pub const fn recovery_deadline(self) -> Option<u64> {
        match self {
            Self::NotOpen => None,
            Self::NotDue { recovery_deadline }
            | Self::Restored { recovery_deadline }
            | Self::Jailed {
                recovery_deadline, ..
            }
            | Self::ClosedNonActive { recovery_deadline } => Some(recovery_deadline),
        }
    }
}

impl Staking<'_> {
    /// Stakes `amount` on behalf of `validator`.
    ///
    /// - Adds amount to stake_amount[validator] and total_staked.
    /// - If the validator is registered in ValidatorSet and the new stake meets
    ///   min_stake, activates the validator (Phase 1 auto-activation).
    /// - Enforces max_stake_percent if configured.
    /// - Updates val_stake in ValidatorSet.
    pub fn stake(&mut self, caller: Address, validator: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Err(PrecompileError::Revert("amount must be non-zero".into()));
        }

        // Enforce self-stake only - no third-party delegation.
        // Without full delegation accounting, a delegator's funds would be
        // locked with no protocol-level withdrawal mechanism.
        if caller != validator {
            return Err(PrecompileError::Revert(
                "third-party staking not supported: caller must be validator".into(),
            ));
        }

        // Do NOT call transfer_balance here. For payable precompile calls,
        // the EVM already transfers msg.value from caller to STAKING_ADDRESS
        // via CallValue::Transfer. A second transfer would double-charge the caller.

        // Update staking contract state
        let current = self.stake_amount.read(&validator)?;
        let new_stake = current + amount;

        // Enforce max_stake_percent if configured
        let max_pct = self.config_max_stake_percent.read()?;
        if max_pct > 0 && max_pct < 100 {
            let total = self.total_staked.read()?;
            if total.is_zero() {
                self.stake_amount.write(&validator, new_stake)?;

                self.total_staked.write(amount)?;

                let min_stake = self.config_min_stake.read()?;
                let mut val_set = ValidatorSet::new(self.storage.clone());
                val_set.record_stake_increase(validator, new_stake, min_stake)?;

                return Ok(());
            }
            let new_total = total + amount;
            // Check: new_stake / new_total <= max_pct / 100
            // Equivalent to: new_stake * 100 <= max_pct * new_total
            if new_stake * U256::from(100u64) > U256::from(max_pct) * new_total {
                return Err(PrecompileError::Revert(
                    "stake would exceed max_stake_percent".into(),
                ));
            }
        }

        self.stake_amount.write(&validator, new_stake)?;

        let total = self.total_staked.read()?;
        self.total_staked.write(total + amount)?;

        // PoS staking: when a REGISTERED validator reaches min_stake it becomes
        // PENDING (admitted to the validator set, syncing, not yet voting). The next
        // DKG reshare grants it a share and activate_reshared_set promotes
        // PENDING->ACTIVE. The ValidatorSet facade also mirrors the authoritative
        // bonded value and raises pending_set_change when the threshold is crossed.
        let min_stake = self.config_min_stake.read()?;
        let mut val_set = ValidatorSet::new(self.storage.clone());
        val_set.record_stake_increase(validator, new_stake, min_stake)?;

        Ok(())
    }

    fn checked_complete_time(&self, timestamp: u64, period: u64) -> Result<u64> {
        timestamp.checked_add(period).ok_or_else(|| {
            PrecompileError::Revert("unbonding completion timestamp overflow".into())
        })
    }

    fn slashed_withdrawal_delay(&self) -> Result<u64> {
        let configured = self.config_slashed_withdrawal_delay.read()?;
        if configured > 0 {
            return Ok(configured);
        }
        let unbonding_period = self.config_unbonding_period.read()?;
        unbonding_period
            .checked_mul(2)
            .ok_or_else(|| PrecompileError::Revert("slashed withdrawal delay overflow".into()))
    }

    fn enqueue_unbonding(
        &mut self,
        validator: Address,
        amount: U256,
        complete_time: u64,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let idx = self.unbonding_count.read()?;
        self.unbonding_validator.write(&idx, validator)?;
        self.unbonding_amount.write(&idx, amount)?;
        self.unbonding_complete_time.write(&idx, complete_time)?;
        self.unbonding_count.write(idx + 1)?;

        let prev_head_stored = self.per_val_unbonding_head.read(&validator)?;
        self.unbonding_next.write(&idx, prev_head_stored)?;
        self.per_val_unbonding_head.write(&validator, idx + 1)?;

        Ok(())
    }

    fn has_pending_unbonding(&self, validator: Address) -> Result<bool> {
        let mut current_stored = self.per_val_unbonding_head.read(&validator)?;
        while current_stored != 0 {
            let idx = current_stored - 1;
            if !self.unbonding_amount.read(&idx)?.is_zero() {
                return Ok(true);
            }
            current_stored = self.unbonding_next.read(&idx)?;
        }
        Ok(false)
    }

    fn finalize_inactive_if_complete(
        &self,
        val_set: &mut ValidatorSet,
        validator: Address,
    ) -> Result<()> {
        if matches!(
            val_set.validator_lifecycle(validator)?,
            ValidatorLifecycle::Unbonding(_)
        ) && self.stake_amount.read(&validator)?.is_zero()
            && !self.has_pending_unbonding(validator)?
        {
            val_set.complete_unbonding(validator)?;
        }
        Ok(())
    }

    /// Unstakes `amount` from the caller (self-unstake only).
    ///
    /// - Reduces stake_amount[caller] and total_staked by amount.
    /// - If stake falls below min_stake and validator is ACTIVE, transitions
    ///   to EXITING (awaiting DKG reshare to exclude from consensus set).
    /// - Enqueues an unbonding entry with complete_time = now + unbonding_period.
    /// - Updates val_stake in ValidatorSet.
    pub fn unstake(&mut self, caller: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Err(PrecompileError::Revert("amount must be non-zero".into()));
        }

        let current = self.stake_amount.read(&caller)?;
        if amount > current {
            return Err(PrecompileError::Revert("insufficient staked amount".into()));
        }

        let timestamp = self.storage.timestamp()?.to::<u64>();
        let unbonding_period = self.config_unbonding_period.read()?;
        let complete_time = self.checked_complete_time(timestamp, unbonding_period)?;
        let min_stake = self.config_min_stake.read()?;
        let new_stake = current - amount;
        self.stake_amount.write(&caller, new_stake)?;

        let total = self.total_staked.read()?;
        self.total_staked.write(total - amount)?;

        // Staking owns the accounting and queue. The ValidatorSet facade records
        // the complete projection only after those authoritative writes succeed;
        // the outer call-frame checkpoint keeps the sequence atomic on failure.
        self.enqueue_unbonding(caller, amount, complete_time)?;
        let mut val_set = ValidatorSet::new(self.storage.clone());
        val_set.record_unstake(caller, new_stake, min_stake, complete_time)?;

        Ok(())
    }

    /// Unjails the caller's JAILED validator back to PENDING. Requires the
    /// caller's bonded stake to be >= min_stake (top up via `stake` first if a
    /// felony slash dropped it below). The JAILED->PENDING transition, the unjail
    /// cooldown, the readiness reset, and the reshare signal live in ValidatorSet
    /// (`unjail_after_stake_check`); afterwards the validator re-confirms readiness
    /// and is promoted PENDING->ACTIVE by the next DKG reshare. Self-only: `caller`
    /// is the validator (the precompile passes the tx sender).
    pub fn unjail_validator(&mut self, caller: Address) -> Result<()> {
        let stake = self.stake_amount.read(&caller)?;
        let min_stake = self.config_min_stake.read()?;
        if stake < min_stake {
            return Err(PrecompileError::Revert(format!(
                "unjailValidator requires stake >= min_stake: have {stake}, need {min_stake}"
            )));
        }
        let mut val_set = ValidatorSet::new(self.storage.clone());
        val_set.unjail_after_stake_check(caller)
    }

    /// Claims matured unbonding entries for the caller.
    ///
    /// Walks the per-validator linked list (O(k) where k = caller's entries),
    /// zeroes out mature entries, rebuilds the list without them,
    /// and transfers the total claimable amount to the caller.
    pub fn claim_unbonded(&mut self, caller: Address) -> Result<()> {
        let timestamp = self.storage.timestamp()?.to::<u64>();
        let mut total_claimable = U256::ZERO;

        // Walk per-validator linked list (stored = idx + 1, 0 = empty/end)
        let mut current_stored = self.per_val_unbonding_head.read(&caller)?;
        let mut new_head_stored: u32 = 0;
        let mut pending_tail_stored: u32 = 0;

        while current_stored != 0 {
            let idx = current_stored - 1;
            let next_stored = self.unbonding_next.read(&idx)?;
            let complete_time = self.unbonding_complete_time.read(&idx)?;

            if timestamp >= complete_time {
                // Mature - claim it
                let amount = self.unbonding_amount.read(&idx)?;
                total_claimable += amount;
                // Zero out entry (for tail-trim compaction by process_unbonding)
                self.unbonding_validator.write(&idx, Address::ZERO)?;
                self.unbonding_amount.write(&idx, U256::ZERO)?;
                self.unbonding_complete_time.write(&idx, 0)?;
                self.unbonding_next.write(&idx, 0)?;
            } else {
                // Not mature - keep in list
                if new_head_stored == 0 {
                    new_head_stored = current_stored;
                } else {
                    // Link previous pending entry to this one
                    self.unbonding_next
                        .write(&(pending_tail_stored - 1), current_stored)?;
                }
                pending_tail_stored = current_stored;
            }
            current_stored = next_stored;
        }

        // Terminate the rebuilt list
        if pending_tail_stored != 0 {
            self.unbonding_next.write(&(pending_tail_stored - 1), 0)?;
        }
        self.per_val_unbonding_head
            .write(&caller, new_head_stored)?;

        // Transfer accumulated claimable amount from staking contract to caller
        if !total_claimable.is_zero() {
            self.storage
                .transfer_balance(STAKING_ADDRESS, caller, total_claimable)?;
        }

        let mut val_set = ValidatorSet::new(self.storage.clone());
        self.finalize_inactive_if_complete(&mut val_set, caller)?;

        Ok(())
    }

    /// Slashes a validator by `percent` of their staked amount and unbonding entries.
    ///
    /// - Reduces stake_amount[validator] and total_staked by the slash amount.
    /// - Also proportionally reduces pending unbonding entries.
    /// - Burns slashed tokens from STAKING_ADDRESS native balance.
    /// - Updates val_stake in ValidatorSet.
    /// - Returns the total slashed amount (for evidence reward calculation).
    /// - Does NOT change validator status - severe faults are handled by
    ///   `SlashIndicator::slash_proposer()` via `force_exit_validator()`.
    pub fn slash_stake(&mut self, validator: Address, percent: u64) -> Result<U256> {
        if percent > 100 {
            return Err(PrecompileError::Revert(
                "slash percent must be <= 100".into(),
            ));
        }

        let current = self.stake_amount.read(&validator)?;
        let mut total_slashed = U256::ZERO;

        // Slash active stake
        if !current.is_zero() {
            let slash = current * U256::from(percent) / U256::from(100u64);
            let new_stake = current - slash;
            self.stake_amount.write(&validator, new_stake)?;
            let total = self.total_staked.read()?;
            self.total_staked.write(total - slash)?;
            total_slashed += slash;
        }

        // Slash unbonding entries proportionally.
        // Walk the per-validator linked list and reduce each pending entry.
        let mut current_stored = self.per_val_unbonding_head.read(&validator)?;
        let slash_complete_time = self.checked_complete_time(
            self.storage.timestamp()?.to::<u64>(),
            self.slashed_withdrawal_delay()?,
        )?;
        while current_stored != 0 {
            let idx = current_stored - 1;
            let amount = self.unbonding_amount.read(&idx)?;
            if !amount.is_zero() {
                let unbonding_slash = amount * U256::from(percent) / U256::from(100u64);
                if !unbonding_slash.is_zero() {
                    self.unbonding_amount
                        .write(&idx, amount - unbonding_slash)?;
                    total_slashed += unbonding_slash;
                }
                let complete_time = self.unbonding_complete_time.read(&idx)?;
                if complete_time < slash_complete_time {
                    self.unbonding_complete_time
                        .write(&idx, slash_complete_time)?;
                }
            }
            current_stored = self.unbonding_next.read(&idx)?;
        }

        // Burn slashed tokens from STAKING_ADDRESS so native balance stays
        // in sync with accounting. Without this, slashed amounts become orphaned.
        if !total_slashed.is_zero() {
            self.storage
                .decrease_balance(STAKING_ADDRESS, total_slashed)?;
        }

        // Cross-call: mirror the authoritative stake after all stake, claim, and
        // burn accounting has succeeded. Preserve the existing unbonding-end hint;
        // individual Staking claim timestamps remain authoritative.
        let remaining_stake = self.stake_amount.read(&validator)?;
        let min_stake = self.config_min_stake.read()?;
        let mut val_set = ValidatorSet::new(self.storage.clone());
        val_set.record_stake_slash(validator, remaining_stake, min_stake, None)?;

        Ok(total_slashed)
    }

    /// Records an OCOMP result-vote miss and applies the recovery policy.
    /// Only the first miss in the fixed window slashes, and that slash touches
    /// bonded stake only. The ordinary felony slash path remains unchanged.
    pub fn record_ocomp_miss(&mut self, validator: Address) -> Result<OcompMissPenalty> {
        let guard = self.storage.checkpoint_guard();
        let mut validators = ValidatorSet::new(self.storage.clone());
        let miss = validators.record_ocomp_miss(validator)?;
        let (first_in_window, miss_count, recovery_deadline) = match miss {
            OcompMissRecord::Opened {
                miss_count,
                recovery_deadline,
            } => (true, miss_count, recovery_deadline),
            OcompMissRecord::Repeated {
                miss_count,
                recovery_deadline,
            } => (false, miss_count, recovery_deadline),
        };

        let slashed_bonded = if first_in_window {
            let bonded = self.stake_amount.read(&validator)?;
            // The policy is exactly 10%, so dividing by ten is equivalent to
            // `bonded * 10 / 100` without introducing an artificial U256
            // overflow for otherwise valid bonded balances.
            let slash = bonded / U256::from(OCOMP_MISS_SLASH_PERCENT);
            let remaining = bonded - slash;
            let total = self.total_staked.read()?;
            if slash > total {
                return Err(PrecompileError::Fatal(
                    "OCOMP bonded slash exceeds total staked".into(),
                ));
            }
            self.stake_amount.write(&validator, remaining)?;
            self.total_staked.write(total - slash)?;
            if !slash.is_zero() {
                self.storage.decrease_balance(STAKING_ADDRESS, slash)?;
            }
            validators.record_ocomp_bonded_slash(validator, remaining)?;
            slash
        } else {
            U256::ZERO
        };

        guard.commit();
        Ok(OcompMissPenalty {
            first_in_window,
            miss_count,
            recovery_deadline,
            slashed_bonded,
        })
    }

    /// Resolves one recovery window only when its fixed deadline is due. This
    /// narrow seam is also used immediately before recording a same-height new
    /// OCOMP miss, so an expired window cannot suppress the next first slash.
    pub fn resolve_due_ocomp_recovery_window(
        &mut self,
        validator: Address,
    ) -> Result<OcompRecoveryResolution> {
        let guard = self.storage.checkpoint_guard();
        let at_height = self.storage.block_number()?;
        let minimum = self.config_min_stake.read()?;
        let mut validators = ValidatorSet::new(self.storage.clone());
        let Some(window) = validators.ocomp_recovery_window(validator)? else {
            return Ok(OcompRecoveryResolution::NotOpen);
        };
        if at_height < window.recovery_deadline {
            return Ok(OcompRecoveryResolution::NotDue {
                recovery_deadline: window.recovery_deadline,
            });
        }

        let bonded = self.stake_amount.read(&validator)?;
        let lifecycle = validators.validator_lifecycle(validator)?;
        let resolution = if !matches!(lifecycle, ValidatorLifecycle::Active(_)) {
            validators.resolve_ocomp_recovery_window(
                validator,
                window.recovery_deadline,
                bonded,
                OcompRecoveryOutcome::NonActive,
            )?;
            OcompRecoveryResolution::ClosedNonActive {
                recovery_deadline: window.recovery_deadline,
            }
        } else if bonded >= minimum {
            validators.resolve_ocomp_recovery_window(
                validator,
                window.recovery_deadline,
                bonded,
                OcompRecoveryOutcome::Restored,
            )?;
            OcompRecoveryResolution::Restored {
                recovery_deadline: window.recovery_deadline,
            }
        } else {
            let observability =
                validators
                    .jail_validator_deferred(validator)?
                    .ok_or_else(|| {
                        PrecompileError::Fatal(
                            "active OCOMP recovery validator was not jailed".into(),
                        )
                    })?;
            validators.resolve_ocomp_recovery_window(
                validator,
                window.recovery_deadline,
                bonded,
                OcompRecoveryOutcome::Jailed,
            )?;
            OcompRecoveryResolution::Jailed {
                recovery_deadline: window.recovery_deadline,
                observability,
            }
        };
        guard.commit();
        Ok(resolution)
    }

    /// Checks every open OCOMP recovery window once per block. Valid registry
    /// state is bounded by the existing consensus committee/codec maximum; a
    /// corrupt over-bound count fails before address materialization.
    pub fn close_due_ocomp_recovery_windows(&mut self) -> Result<OcompRecoverySweep> {
        let guard = self.storage.checkpoint_guard();
        let current_block = self.storage.block_number()?;
        let validators = ValidatorSet::new(self.storage.clone());
        let validator_count = validators.validator_count()?;
        if validator_count > outbe_validatorset::runtime::CONSENSUS_VALIDATOR_BOUND {
            return Err(PrecompileError::Fatal(format!(
                "validator registry exceeds consensus bound: {validator_count} > {}",
                outbe_validatorset::runtime::CONSENSUS_VALIDATOR_BOUND
            )));
        }
        let addresses = validators.registered_validator_addresses()?;
        let mut sweep = OcompRecoverySweep::default();
        let mut open_deadlines = Vec::new();
        let mut resolutions = Vec::new();
        let mut punishments = Vec::new();

        for validator in addresses {
            let Some(_window) = validators.ocomp_recovery_window(validator)? else {
                continue;
            };
            sweep.open_windows = sweep.open_windows.checked_add(1).ok_or_else(|| {
                PrecompileError::Fatal("OCOMP recovery open-window count overflow".into())
            })?;
            match self.resolve_due_ocomp_recovery_window(validator)? {
                OcompRecoveryResolution::NotOpen => {}
                OcompRecoveryResolution::NotDue { recovery_deadline } => {
                    open_deadlines.push((validator, recovery_deadline));
                }
                OcompRecoveryResolution::Restored { .. } => {
                    sweep.restored = sweep.restored.checked_add(1).ok_or_else(|| {
                        PrecompileError::Fatal("OCOMP restored count overflow".into())
                    })?;
                    resolutions.push((validator, "restored"));
                }
                OcompRecoveryResolution::Jailed { observability, .. } => {
                    sweep.jailed = sweep.jailed.checked_add(1).ok_or_else(|| {
                        PrecompileError::Fatal("OCOMP jailed count overflow".into())
                    })?;
                    resolutions.push((validator, "jailed"));
                    punishments.push(observability);
                }
                OcompRecoveryResolution::ClosedNonActive { .. } => {
                    sweep.closed_non_active =
                        sweep.closed_non_active.checked_add(1).ok_or_else(|| {
                            PrecompileError::Fatal("OCOMP non-active close count overflow".into())
                        })?;
                    resolutions.push((validator, "non_active"));
                }
            }
        }

        guard.commit();
        for (validator, recovery_deadline) in open_deadlines {
            outbe_validatorset::metrics::record_ocomp_recovery_deadline(
                validator,
                recovery_deadline,
            );
        }
        for punishment in punishments {
            punishment.record();
        }
        let resolved_count = sweep
            .restored
            .saturating_add(sweep.jailed)
            .saturating_add(sweep.closed_non_active);
        for (validator, outcome) in resolutions {
            outbe_validatorset::metrics::record_ocomp_recovery_resolution(validator, outcome);
        }
        outbe_validatorset::metrics::record_ocomp_recovery_sweep(
            current_block,
            sweep.open_windows.saturating_sub(resolved_count),
        );
        Ok(sweep)
    }

    /// Maximum compaction operations per `process_unbonding` call.
    /// Prevents unbounded gas cost if the queue grows large.
    pub const MAX_COMPACTION_PER_BLOCK: u32 = 64;

    /// Processes validator lifecycle transitions and trims zeroed tail entries.
    ///
    /// Called each block in pre-execution. Does NOT zero out mature entries -
    /// that is done by [`claim_unbonded`] when the validator claims their funds.
    /// This function only trims zeroed tail entries to reclaim queue space.
    ///
    /// Uses tail-trim instead of swap-remove to preserve stable indices for
    /// the per-validator linked list.
    ///
    /// Capped at [`MAX_COMPACTION_PER_BLOCK`] operations per call to bound
    /// per-block cost. Remaining entries are trimmed in subsequent blocks.
    pub fn process_unbonding(&mut self, timestamp: u64) -> Result<()> {
        let mut val_set = ValidatorSet::new(self.storage.clone());
        let validators = val_set.registered_validator_addresses()?;
        for validator in validators {
            let state = val_set.validator_state(validator)?;
            if !matches!(state.lifecycle(), ValidatorLifecycle::Unbonding(_)) {
                continue;
            }

            let stake = self.stake_amount.read(&validator)?;
            if !stake.is_zero() {
                let total = self.total_staked.read()?;
                if stake > total {
                    return Err(PrecompileError::Revert(format!(
                        "stake accounting underflow for validator {}",
                        validator
                    )));
                }
                self.stake_amount.write(&validator, U256::ZERO)?;
                self.total_staked.write(total - stake)?;

                let slash_count = state
                    .history()
                    .ok_or_else(|| {
                        PrecompileError::Fatal("registered validator is missing history".into())
                    })?
                    .slash_count();
                let period = if slash_count > 0 {
                    self.slashed_withdrawal_delay()?
                } else {
                    self.config_unbonding_period.read()?
                };
                let complete_time = self.checked_complete_time(timestamp, period)?;
                self.enqueue_unbonding(validator, stake, complete_time)?;
                val_set.record_unstake(validator, U256::ZERO, U256::ZERO, complete_time)?;
            } else {
                self.finalize_inactive_if_complete(&mut val_set, validator)?;
            }
        }

        let mut count = self.unbonding_count.read()?;
        let mut ops: u32 = 0;

        // Trim zeroed entries from tail only (preserves linked list indices)
        while count > 0 && ops < Self::MAX_COMPACTION_PER_BLOCK {
            let validator = self.unbonding_validator.read(&(count - 1))?;
            if !validator.is_zero() {
                break;
            }
            count -= 1;
            ops += 1;
        }

        self.unbonding_count.write(count)?;

        Ok(())
    }

    /// Returns the staked amount for a validator.
    pub fn get_stake(&self, validator: Address) -> Result<U256> {
        self.stake_amount.read(&validator)
    }

    /// Returns the total staked amount across all validators.
    pub fn get_total_staked(&self) -> Result<U256> {
        self.total_staked.read()
    }
}
