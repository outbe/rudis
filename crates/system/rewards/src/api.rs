//! Public cross-module API surface for the Rewards module.
//!
//! Exposes the read-only and write entrypoints that other modules
//! (EmissionLimit, AgentReward) call as part of the daily Cycle dispatch
//! chain (`Cycle -> EmissionLimit -> AgentReward -> Rewards`). Until this
//! refactor lands, day-boundary settle was owned by `RewardsLifecycle`
//! and triggered from `on_finalized_metadata`; with Phase 3
//! that responsibility moves out of Rewards and Rewards becomes a pure
//! storage + accounting layer that exposes the data the new orchestrator
//! needs:
//!
//! * [`read_daily_fee_sum_raw`] - locked-in raw fee total per UTC day,
//!   used by AgentReward to choose between forwarding the validator
//!   pool to Metadosis or emitting a topup.
//! * [`read_voters_for_day`] - ordered (Address, participation count)
//!   pairs for a UTC day; first-seen-on-day order is deterministic.
//! * [`prepare_daily_validator_gem_batch`] - freezes the exact validator Gem
//!   obligations for a UTC day without consulting Oracle state.
//! * [`deliver_oldest_reward_gem_batch`] - delivers one complete FIFO batch
//!   when a fresh canonical price exists.

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_gemfactory::GemTypes;
use outbe_primitives::{
    block::BlockRuntimeContext,
    error::{PrecompileError, Result},
};

use crate::constants::REWARD_GEM_CURRENCY;
use crate::runtime::day_number_since_genesis;
use crate::schema::Rewards;

/// Returns the raw fee total accumulated for the given UTC day. This is
/// the value `on_finalized_metadata` writes per finalized block via
/// `daily_fee_sum_raw[day] += validator_fee_sum`. Returns `U256::ZERO`
/// if no finalized metadata has been processed yet for `day`.
pub fn read_daily_fee_sum_raw(ctx: &BlockRuntimeContext, day: u32) -> Result<U256> {
    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();
    rewards.daily_fee_sum_raw.read(&day)
}

/// Returns the deterministic, first-seen-on-day list of voter
/// participations for `day`. The vector length matches
/// `daily_voter_count[day]`; entries are ordered by the index recorded
/// in `daily_voter_at[day][i]` (i.e., the order in which the voter's
/// first finalized-block bit was observed for that day).
///
/// Each entry is `(voter_address, participation_count)` where the count
/// is the number of finalized blocks from `day` in which the voter
/// participated. Returns an empty vector if no voters have been
/// recorded for `day`.
pub fn read_voters_for_day(ctx: &BlockRuntimeContext, day: u32) -> Result<Vec<(Address, u64)>> {
    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();
    let count = rewards.daily_voter_count.read(&day)?;
    let voter_at = rewards.daily_voter_at.get_nested(&day);
    let participation = rewards.daily_participation.get_nested(&day);
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let voter = voter_at.read(&i)?;
        let p = participation.read(&voter)?;
        out.push((voter, p));
    }
    Ok(out)
}

/// Immutable summary of one UTC day's prepared validator reward Gem batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedRewardGemBatch {
    pub reward_utc_day: u32,
    /// Exact COEN-denominated Gem load amount reserved by the daily allocation.
    pub planned_promis_load_amount: U256,
    pub recipient_count: u32,
    pub digest: B256,
}

/// Result of preparing a validator reward Gem obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewardGemPreparationOutcome {
    Prepared(PreparedRewardGemBatch),
    AlreadyPrepared(PreparedRewardGemBatch),
    NoPayableShares(PreparedRewardGemBatch),
}

/// Result of attempting to deliver the oldest prepared reward Gem batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewardGemDeliveryOutcome {
    Empty,
    PendingRate {
        reward_utc_day: u32,
    },
    Delivered {
        reward_utc_day: u32,
        recipient_count: u32,
        /// Exact COEN-denominated Gem load amount minted by this delivery.
        delivered_promis_load_amount: U256,
    },
}

const REWARD_GEM_BATCH_DIGEST_DOMAIN: &[u8] = b"OUTBE_REWARD_GEM_BATCH_V1";

fn reward_gem_retryable_error(message: impl Into<String>) -> PrecompileError {
    let message = message.into();
    tracing::error!(
        target: "outbe::rewards",
        error = %message,
        "validator reward Gem batch remains pending"
    );
    PrecompileError::Revert(message)
}

/// Whether every known block's participation window for a UTC day has closed.
/// Cycle executes before LateFinalizeCredits, so equality is still too early:
/// the final admissible votes at the close height have not executed yet.
pub fn day_participation_complete(ctx: &BlockRuntimeContext, utc_day: u32) -> Result<bool> {
    let last_close = ctx
        .storage
        .contract::<Rewards>()
        .daily_last_window_close
        .read(&utc_day)?;
    Ok(last_close == 0 || ctx.block.block_number > last_close)
}

/// Calculates and stores one exact validator reward Gem obligation without
/// consulting a live Oracle price or minting a Gem. The first preparation owns
/// the immutable FIFO append; an exact replay returns the stored summary.
pub fn prepare_daily_validator_gem_batch(
    ctx: &BlockRuntimeContext,
    utc_day: u32,
    validator_topup_amount: U256,
    voters: &[(Address, u64)],
) -> Result<RewardGemPreparationOutcome> {
    ctx.with_checkpoint(|| {
        prepare_daily_validator_gem_batch_inner(ctx, utc_day, validator_topup_amount, voters)
    })
}

fn prepare_daily_validator_gem_batch_inner(
    ctx: &BlockRuntimeContext,
    utc_day: u32,
    validator_topup_amount: U256,
    voters: &[(Address, u64)],
) -> Result<RewardGemPreparationOutcome> {
    if !day_participation_complete(ctx, utc_day)? {
        return Err(PrecompileError::Fatal(
            "GEM preparation before reward participation windows close".into(),
        ));
    }
    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();
    let gem_type = if day_number_since_genesis(ctx, utc_day)? < 21 {
        GemTypes::Genesis
    } else {
        GemTypes::Validator
    };

    let total_count = voters.iter().try_fold(0u64, |total, (_, count)| {
        total.checked_add(*count).ok_or_else(|| {
            reward_gem_retryable_error("validator reward participation total overflow")
        })
    })?;
    let mut recipients = Vec::new();
    let mut planned_promis_load_amount = U256::ZERO;
    if !validator_topup_amount.is_zero() && total_count != 0 {
        let denominator = U256::from(total_count);
        for (owner, count) in voters {
            if *count == 0 {
                continue;
            }
            let load = validator_topup_amount
                .checked_mul(U256::from(*count))
                .ok_or_else(|| {
                    reward_gem_retryable_error("validator reward share multiply overflow")
                })?
                / denominator;
            if load.is_zero() {
                continue;
            }
            if owner.is_zero() {
                return Err(reward_gem_retryable_error(
                    "validator reward Gem owner is zero",
                ));
            }
            planned_promis_load_amount =
                planned_promis_load_amount
                    .checked_add(load)
                    .ok_or_else(|| {
                        reward_gem_retryable_error("validator reward planned total overflow")
                    })?;
            recipients.push((*owner, load));
        }
    }
    if recipients.len() > outbe_consensus::bls::MAX_VALIDATORS as usize {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem batch exceeds validator bound: count={} max={}",
            recipients.len(),
            outbe_consensus::bls::MAX_VALIDATORS
        )));
    }
    let recipient_count = u32::try_from(recipients.len())
        .map_err(|_| reward_gem_retryable_error("validator reward Gem recipient count overflow"))?;
    let digest = reward_gem_batch_digest(
        utc_day,
        gem_type as u8,
        REWARD_GEM_CURRENCY,
        REWARD_GEM_CURRENCY,
        planned_promis_load_amount,
        &recipients,
    );
    let summary = PreparedRewardGemBatch {
        reward_utc_day: utc_day,
        planned_promis_load_amount,
        recipient_count,
        digest,
    };

    if rewards.daily_topup_prepared.read(&utc_day)? {
        let stored_digest = rewards.reward_gem_batch_digest.read(&utc_day)?;
        let stored_amount = rewards.reward_gem_planned_load_amount.read(&utc_day)?;
        if stored_digest != digest || stored_amount != planned_promis_load_amount {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem preparation replay contradicts UTC day {utc_day}"
            )));
        }
        require_prepared_reward_gem_batch_replay_consistency(
            &rewards,
            utc_day,
            gem_type as u8,
            &recipients,
        )?;
        return Ok(RewardGemPreparationOutcome::AlreadyPrepared(summary));
    }
    if rewards.daily_topup_settled.read(&utc_day)? {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem UTC day {utc_day} is settled without a preparation"
        )));
    }

    rewards.reward_gem_batch_digest.write(&utc_day, digest)?;
    rewards
        .reward_gem_planned_load_amount
        .write(&utc_day, planned_promis_load_amount)?;
    rewards.reward_gem_type.write(&utc_day, gem_type as u8)?;
    rewards
        .reward_gem_issuance_currency
        .write(&utc_day, REWARD_GEM_CURRENCY)?;
    rewards
        .reward_gem_reference_currency
        .write(&utc_day, REWARD_GEM_CURRENCY)?;

    if recipients.is_empty() {
        rewards.daily_topup_prepared.write(&utc_day, true)?;
        rewards.daily_topup_settled.write(&utc_day, true)?;
        return Ok(RewardGemPreparationOutcome::NoPayableShares(summary));
    }

    outbe_oracle::api::require_coen_pair(ctx.storage.clone(), REWARD_GEM_CURRENCY).map_err(
        |error| {
            reward_gem_retryable_error(format!(
                "validator reward Gem currency is not registered: {error}"
            ))
        },
    )?;
    let head = rewards.reward_gem_queue_head.read()?;
    let tail = rewards.reward_gem_queue_tail.read()?;
    let pending_batch_count = require_reward_gem_queue_consistency(&rewards, head, tail)?;
    let next_tail = tail
        .checked_add(1)
        .ok_or_else(|| reward_gem_retryable_error("validator reward Gem FIFO sequence overflow"))?;
    let next_pending_batch_count = pending_batch_count.checked_add(1).ok_or_else(|| {
        reward_gem_retryable_error("validator reward Gem pending batch count overflow")
    })?;
    if rewards.reward_gem_queue_sequence_plus_one.read(&utc_day)? != 0 {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem UTC day {utc_day} is already present in the FIFO"
        )));
    }

    let owners = rewards.reward_gem_owner_at.get_nested(&utc_day);
    let loads = rewards.reward_promis_load_at.get_nested(&utc_day);
    for (index, (owner, load)) in recipients.iter().copied().enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            reward_gem_retryable_error("validator reward Gem recipient index overflow")
        })?;
        owners.write(&index, owner)?;
        loads.write(&index, load)?;
    }
    rewards
        .reward_gem_recipient_count
        .write(&utc_day, recipient_count)?;
    rewards
        .reward_gem_utc_day_by_sequence
        .write(&tail, utc_day)?;
    rewards
        .reward_gem_queue_sequence_plus_one
        .write(&utc_day, next_tail)?;
    rewards.reward_gem_queue_tail.write(next_tail)?;
    rewards
        .reward_gem_pending_batch_count
        .write(next_pending_batch_count)?;
    rewards.daily_topup_prepared.write(&utc_day, true)?;
    Ok(RewardGemPreparationOutcome::Prepared(summary))
}

fn require_prepared_reward_gem_batch_replay_consistency(
    rewards: &Rewards<'_>,
    utc_day: u32,
    expected_gem_type: u8,
    expected_recipients: &[(Address, U256)],
) -> Result<()> {
    let recipient_count = rewards.reward_gem_recipient_count.read(&utc_day)?;
    let is_settled = rewards.daily_topup_settled.read(&utc_day)?;
    let sequence_plus_one = rewards.reward_gem_queue_sequence_plus_one.read(&utc_day)?;

    if expected_recipients.is_empty() {
        if !is_settled || recipient_count != 0 || sequence_plus_one != 0 {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem no-payable replay has corrupt state for UTC day {utc_day}"
            )));
        }
        return Ok(());
    }

    let expected_count = u32::try_from(expected_recipients.len())
        .map_err(|_| reward_gem_retryable_error("validator reward Gem recipient count overflow"))?;
    if rewards.reward_gem_type.read(&utc_day)? != expected_gem_type
        || rewards.reward_gem_issuance_currency.read(&utc_day)? != REWARD_GEM_CURRENCY
        || rewards.reward_gem_reference_currency.read(&utc_day)? != REWARD_GEM_CURRENCY
    {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem preparation replay has corrupt metadata for UTC day {utc_day}"
        )));
    }

    if is_settled {
        if recipient_count != 0 || sequence_plus_one != 0 {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem delivered replay retains live state for UTC day {utc_day}"
            )));
        }
        return Ok(());
    }
    if recipient_count != expected_count {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem preparation replay has corrupt recipient count for UTC day {utc_day}"
        )));
    }

    let head = rewards.reward_gem_queue_head.read()?;
    let tail = rewards.reward_gem_queue_tail.read()?;
    require_reward_gem_queue_consistency(rewards, head, tail)?;
    let sequence = sequence_plus_one.checked_sub(1).ok_or_else(|| {
        reward_gem_retryable_error(format!(
            "validator reward Gem preparation replay lost FIFO linkage for UTC day {utc_day}"
        ))
    })?;
    if head > tail
        || sequence < head
        || sequence >= tail
        || rewards.reward_gem_utc_day_by_sequence.read(&sequence)? != utc_day
    {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem preparation replay has corrupt FIFO linkage for UTC day {utc_day}"
        )));
    }

    let owners = rewards.reward_gem_owner_at.get_nested(&utc_day);
    let loads = rewards.reward_promis_load_at.get_nested(&utc_day);
    for (index, (expected_owner, expected_load)) in expected_recipients.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            reward_gem_retryable_error("validator reward Gem recipient index overflow")
        })?;
        if owners.read(&index)? != *expected_owner || loads.read(&index)? != *expected_load {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem preparation replay has corrupt recipient {index} for UTC day {utc_day}"
            )));
        }
    }
    Ok(())
}

fn require_reward_gem_queue_consistency(
    rewards: &Rewards<'_>,
    head: u64,
    tail: u64,
) -> Result<u64> {
    let span = tail
        .checked_sub(head)
        .ok_or_else(|| reward_gem_retryable_error("validator reward Gem FIFO head exceeds tail"))?;
    let pending_batch_count = rewards.reward_gem_pending_batch_count.read()?;
    if pending_batch_count != span {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem pending batch count {pending_batch_count} disagrees with FIFO span {span}"
        )));
    }
    Ok(pending_batch_count)
}

/// Attempts to deliver exactly one complete FIFO head batch. Missing or stale
/// price data is a successful no-op. A mint failure leaves atomic rollback to
/// this checkpoint and to the enclosing system transaction.
pub fn deliver_oldest_reward_gem_batch(
    ctx: &BlockRuntimeContext,
) -> Result<RewardGemDeliveryOutcome> {
    ctx.with_checkpoint(|| deliver_oldest_reward_gem_batch_inner(ctx))
}

fn deliver_oldest_reward_gem_batch_inner(
    ctx: &BlockRuntimeContext,
) -> Result<RewardGemDeliveryOutcome> {
    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();
    let head = rewards.reward_gem_queue_head.read()?;
    let tail = rewards.reward_gem_queue_tail.read()?;
    let pending_batch_count = require_reward_gem_queue_consistency(&rewards, head, tail)?;
    if head == tail {
        if rewards.reward_gem_utc_day_by_sequence.read(&head)? != 0 {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem empty FIFO has a live UTC day at sequence {head}"
            )));
        }
        return Ok(RewardGemDeliveryOutcome::Empty);
    }

    let reward_utc_day = rewards.reward_gem_utc_day_by_sequence.read(&head)?;
    if reward_utc_day == 0 {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem FIFO head {head} has no reward UTC day"
        )));
    }
    let expected_sequence = head
        .checked_add(1)
        .ok_or_else(|| reward_gem_retryable_error("validator reward Gem FIFO sequence overflow"))?;
    if rewards
        .reward_gem_queue_sequence_plus_one
        .read(&reward_utc_day)?
        != expected_sequence
    {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem FIFO reverse index disagrees for UTC day {reward_utc_day}"
        )));
    }
    if !rewards.daily_topup_prepared.read(&reward_utc_day)?
        || rewards.daily_topup_settled.read(&reward_utc_day)?
    {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem FIFO UTC day {reward_utc_day} has an illegal state"
        )));
    }

    let recipient_count = rewards.reward_gem_recipient_count.read(&reward_utc_day)?;
    if recipient_count == 0 || recipient_count > outbe_consensus::bls::MAX_VALIDATORS {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem UTC day {reward_utc_day} has invalid recipient count {recipient_count}"
        )));
    }
    let gem_type_raw = rewards.reward_gem_type.read(&reward_utc_day)?;
    let gem_type = match gem_type_raw {
        value if value == GemTypes::Genesis as u8 => GemTypes::Genesis,
        value if value == GemTypes::Validator as u8 => GemTypes::Validator,
        _ => {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem UTC day {reward_utc_day} has unsupported type {gem_type_raw}"
            )));
        }
    };
    let issuance_currency = rewards.reward_gem_issuance_currency.read(&reward_utc_day)?;
    let reference_currency = rewards
        .reward_gem_reference_currency
        .read(&reward_utc_day)?;
    if issuance_currency != REWARD_GEM_CURRENCY || reference_currency != REWARD_GEM_CURRENCY {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem UTC day {reward_utc_day} has invalid currencies {issuance_currency}/{reference_currency}"
        )));
    }

    let owners = rewards.reward_gem_owner_at.get_nested(&reward_utc_day);
    let loads = rewards.reward_promis_load_at.get_nested(&reward_utc_day);
    let mut recipients = Vec::with_capacity(recipient_count as usize);
    let mut delivered_promis_load_amount = U256::ZERO;
    for index in 0..recipient_count {
        let owner = owners.read(&index)?;
        let load = loads.read(&index)?;
        if owner.is_zero() || load.is_zero() {
            return Err(reward_gem_retryable_error(format!(
                "validator reward Gem UTC day {reward_utc_day} has an empty recipient at index {index}"
            )));
        }
        delivered_promis_load_amount =
            delivered_promis_load_amount
                .checked_add(load)
                .ok_or_else(|| {
                    reward_gem_retryable_error("validator reward Gem delivery total overflow")
                })?;
        recipients.push((owner, load));
    }
    if delivered_promis_load_amount
        != rewards
            .reward_gem_planned_load_amount
            .read(&reward_utc_day)?
    {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem UTC day {reward_utc_day} total disagrees with its preparation"
        )));
    }
    let digest = reward_gem_batch_digest(
        reward_utc_day,
        gem_type_raw,
        issuance_currency,
        reference_currency,
        delivered_promis_load_amount,
        &recipients,
    );
    if digest != rewards.reward_gem_batch_digest.read(&reward_utc_day)? {
        return Err(reward_gem_retryable_error(format!(
            "validator reward Gem UTC day {reward_utc_day} digest disagrees with its preparation"
        )));
    }

    outbe_oracle::api::require_coen_pair(ctx.storage.clone(), reference_currency).map_err(
        |error| {
            reward_gem_retryable_error(format!(
                "validator reward Gem currency is not registered: {error}"
            ))
        },
    )?;
    let Some(entry_price) = resolve_reward_entry_price(ctx, reward_utc_day, reference_currency)?
    else {
        tracing::warn!(
            target: "outbe::rewards",
            reward_utc_day,
            "validator reward Gem batch has no usable price yet, staying queued"
        );
        return Ok(RewardGemDeliveryOutcome::PendingRate { reward_utc_day });
    };

    for (owner, load) in recipients {
        outbe_gemfactory::api::issue_gem(
            &ctx.storage,
            owner,
            gem_type,
            load,
            issuance_currency,
            reference_currency,
            entry_price,
        )?;
    }
    for index in 0..recipient_count {
        owners.write(&index, Address::ZERO)?;
        loads.write(&index, U256::ZERO)?;
    }
    rewards
        .reward_gem_recipient_count
        .write(&reward_utc_day, 0)?;
    rewards.reward_gem_utc_day_by_sequence.write(&head, 0)?;
    rewards
        .reward_gem_queue_sequence_plus_one
        .write(&reward_utc_day, 0)?;
    rewards.daily_topup_settled.write(&reward_utc_day, true)?;
    rewards.reward_gem_queue_head.write(expected_sequence)?;
    rewards.reward_gem_pending_batch_count.write(
        pending_batch_count.checked_sub(1).ok_or_else(|| {
            reward_gem_retryable_error("validator reward Gem pending batch count underflow")
        })?,
    )?;

    Ok(RewardGemDeliveryOutcome::Delivered {
        reward_utc_day,
        recipient_count,
        delivered_promis_load_amount,
    })
}

/// The COEN price a batch for `reward_utc_day` mints at.
///
/// The reward belongs to its day, so that day's finalized VWAP is the answer.
/// A day the oracle closed empty falls back to the live quote - today's rule -
/// so no reward is ever lost to a day that carries no price. `None` means the
/// day is not closed yet: the batch waits, exactly as it does today.
fn resolve_reward_entry_price(
    ctx: &BlockRuntimeContext,
    reward_utc_day: u32,
    reference_currency: u16,
) -> Result<Option<U256>> {
    let oracle = outbe_oracle::schema::OracleContract::new(ctx.storage.clone());
    if reward_utc_day > oracle.utc_day_vwap_last_finalized.read()? {
        return Ok(None);
    }

    if let Some(index) =
        outbe_oracle::api::coen_pair_index_opt(ctx.storage.clone(), reference_currency)?
    {
        if let Some(vwap) =
            outbe_oracle::api::get_utc_day_vwap(ctx.storage.clone(), reward_utc_day, index)?
        {
            return Ok(Some(vwap));
        }
    }

    outbe_oracle::api::fresh_coen_rate_for_opt(ctx.storage.clone(), reference_currency)
}

fn reward_gem_batch_digest(
    reward_utc_day: u32,
    gem_type: u8,
    issuance_currency: u16,
    reference_currency: u16,
    planned_promis_load_amount: U256,
    recipients: &[(Address, U256)],
) -> B256 {
    let mut bytes = Vec::with_capacity(
        REWARD_GEM_BATCH_DIGEST_DOMAIN.len() + 4 + 1 + 2 + 2 + 4 + 32 + recipients.len() * 52,
    );
    bytes.extend_from_slice(REWARD_GEM_BATCH_DIGEST_DOMAIN);
    bytes.extend_from_slice(&reward_utc_day.to_be_bytes());
    bytes.push(gem_type);
    bytes.extend_from_slice(&issuance_currency.to_be_bytes());
    bytes.extend_from_slice(&reference_currency.to_be_bytes());
    bytes.extend_from_slice(&(recipients.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&planned_promis_load_amount.to_be_bytes::<32>());
    for (owner, load) in recipients {
        bytes.extend_from_slice(owner.as_slice());
        bytes.extend_from_slice(&load.to_be_bytes::<32>());
    }
    keccak256(bytes)
}

/// Marks `day` as fully settled so `on_finalized_metadata` rejects any
/// late finalized metadata for that day. Owned by the daily Cycle
/// orchestrator: once the orchestrator has finished
/// dispatching the day's pools (validator topup, AgentReward pools,
/// Metadosis terminal credit), it calls this to flip the late-after-
/// settle guard. Idempotent.
pub fn mark_day_settled(ctx: &BlockRuntimeContext, day: u32) -> Result<()> {
    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();
    rewards.daily_settled.write(&day, true)
}

/// Whether `day` has already been fully settled by the daily Cycle
/// orchestrator (counterpart to [`mark_day_settled`]). The orchestrator reads
/// this before doing any minting so a re-fire for an already-settled day is a
/// no-op rather than a double-mint (idempotency).
pub fn is_day_settled(ctx: &BlockRuntimeContext, day: u32) -> Result<bool> {
    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();
    rewards.daily_settled.read(&day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256, Bytes, B256};
    use outbe_primitives::addresses::REWARDS_ADDRESS;
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
    use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;

    use crate::finalized_metadata_hook::on_finalized_metadata;
    use crate::runtime;

    const CHAIN_ID: u64 = 1;
    const GENESIS_TS: u64 = 1_704_067_200; // 2024-01-01 UTC

    const VAL_X: Address = address!("0x00000000000000000000000000000000000000A1");
    const VAL_Y: Address = address!("0x00000000000000000000000000000000000000B2");
    const VAL_Z: Address = address!("0x00000000000000000000000000000000000000C3");

    const FB_HASH_A: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const FB_HASH_B: B256 =
        b256!("0x2222222222222222222222222222222222222222222222222222222222222222");

    fn block_ctx(block_number: u64, timestamp: u64) -> BlockContext {
        BlockContext::new(block_number, timestamp, CHAIN_ID, Address::ZERO, Vec::new())
    }

    fn meta_with_hash(fb_hash: B256, fb_number: u64) -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number: fb_number,
            finalized_block_hash: fb_hash,
            finalized_epoch: 1,
            finalized_view: 1,
            parent_view: 0,
            ordered_committee: vec![],
            signer_bitmap: vec![],
            proof: Bytes::new(),
            committee_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key_hash: B256::ZERO,
            proof_kind:
                outbe_primitives::consensus_metadata::ParentParticipationProof::Finalization,
            missed_proposers: vec![],
        }
    }

    fn bootstrap_genesis(ctx: &BlockRuntimeContext) {
        runtime::ensure_genesis_anchor(ctx).unwrap();
    }

    fn fund_rewards(ctx: &BlockRuntimeContext, amount: U256) {
        ctx.storage
            .increase_balance(REWARDS_ADDRESS, amount)
            .unwrap();
    }

    /// Seeds COEN/840 oracle pair at `rate_6`. Required because
    /// `deliver_oldest_reward_gem_batch` -> `issue_gem` resolves `coen_rate` for floor
    /// price + entry_price at mint time.
    fn seed_oracle(ctx: &BlockRuntimeContext, rate_6: U256) {
        outbe_oracle::api::register_pair(ctx.storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        outbe_oracle::api::set_exchange_rate(
            ctx.storage.clone(),
            Address::ZERO,
            outbe_oracle::api::DAY_TYPE_PAIR,
            rate_6,
            ctx.block.block_number,
            ctx.block.timestamp,
        )
        .unwrap();
        // Register ISO 840 (USD) so issue_gem currency-validation passes.
        let oracle = outbe_oracle::schema::OracleContract::new(ctx.storage.clone());
        oracle.reference_currencies.push(840u16).unwrap();
        // Close every reward day these tests use: none carries a VWAP, so
        // delivery takes the live quote seeded above.
        oracle.utc_day_vwap_last_finalized.write(29991231).unwrap();
    }

    fn one_coen840() -> U256 {
        U256::from(1_000_000u64)
    }

    /// Collects all gem loads owned by `voter` from the gem entity store.
    /// Returns empty Vec if voter holds no gems.
    fn voter_promis_loads(ctx: &BlockRuntimeContext, voter: Address) -> Vec<U256> {
        let gem = outbe_gem::GemContract::new(ctx.storage.clone());
        let count = gem.balance_of(voter).unwrap();
        (0..count)
            .map(|i| {
                let gem_id = gem.token_of_owner_by_index(voter, i).unwrap();
                outbe_gem::api::get_gem(&ctx.storage, gem_id)
                    .unwrap()
                    .unwrap()
                    .promis_load_minor
            })
            .collect()
    }

    #[test]
    fn read_daily_fee_sum_raw_returns_zero_when_unrecorded() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);

            assert_eq!(read_daily_fee_sum_raw(&ctx, 20240101).unwrap(), U256::ZERO);
        });
    }

    #[test]
    fn read_daily_fee_sum_raw_round_trips_after_finalized_metadata() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            fund_rewards(&ctx, U256::from(300u64));

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(101u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_B, 2),
                U256::from(199u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            // 101 + 199 = 300 raw.
            assert_eq!(
                read_daily_fee_sum_raw(&ctx, 20240101).unwrap(),
                U256::from(300u64)
            );
            // Untouched day stays zero.
            assert_eq!(read_daily_fee_sum_raw(&ctx, 20240102).unwrap(), U256::ZERO);
        });
    }

    #[test]
    fn read_voters_for_day_orders_by_first_seen() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            fund_rewards(&ctx, U256::from(400u64));

            // FB_HASH_A: Y first, then X (first-seen-on-day = Y, X)
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_Y, VAL_X],
            )
            .unwrap();
            // FB_HASH_B (same day): Z is new, X already seen
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_B, 2),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Z],
            )
            .unwrap();

            let voters = read_voters_for_day(&ctx, 20240101).unwrap();
            // First-seen order: Y (block A), X (block A), Z (block B).
            assert_eq!(voters.len(), 3);
            assert_eq!(voters[0].0, VAL_Y);
            assert_eq!(voters[0].1, 1);
            assert_eq!(voters[1].0, VAL_X);
            assert_eq!(voters[1].1, 2); // X participated in both A and B
            assert_eq!(voters[2].0, VAL_Z);
            assert_eq!(voters[2].1, 1);
        });
    }

    #[test]
    fn read_voters_for_day_empty_when_no_metadata() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);

            let voters = read_voters_for_day(&ctx, 20240101).unwrap();
            assert!(voters.is_empty());
        });
    }

    #[test]
    fn prepare_daily_validator_gem_batch_stores_exact_shares_without_minting() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, U256::from(2u64) * one_coen840());

            // counts 1 + 3 = 4; topup 400 -> VAL_X 100, VAL_Y 300.
            let voters = vec![(VAL_X, 1u64), (VAL_Y, 3u64)];
            let outcome =
                prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(400u64), &voters)
                    .unwrap();
            let RewardGemPreparationOutcome::Prepared(batch) = outcome else {
                panic!("fresh day must prepare one batch: {outcome:?}");
            };
            assert_eq!(batch.reward_utc_day, 20240101);
            assert_eq!(batch.planned_promis_load_amount, U256::from(400u64));
            assert_eq!(batch.recipient_count, 2);

            assert!(voter_promis_loads(&ctx, VAL_X).is_empty());
            assert!(voter_promis_loads(&ctx, VAL_Y).is_empty());

            let rewards = ctx.storage.contract::<Rewards>();
            assert!(rewards.daily_topup_prepared.read(&20240101).unwrap());
            assert!(!rewards.daily_topup_settled.read(&20240101).unwrap());
            assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
            assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
            assert_eq!(
                rewards.reward_gem_utc_day_by_sequence.read(&0).unwrap(),
                20240101
            );
            assert_eq!(
                rewards.reward_gem_recipient_count.read(&20240101).unwrap(),
                2
            );
            assert_eq!(
                rewards
                    .reward_gem_owner_at
                    .get_nested(&20240101)
                    .read(&0)
                    .unwrap(),
                VAL_X
            );
            assert_eq!(
                rewards
                    .reward_promis_load_at
                    .get_nested(&20240101)
                    .read(&0)
                    .unwrap(),
                U256::from(100u64)
            );
            assert_eq!(
                rewards
                    .reward_gem_owner_at
                    .get_nested(&20240101)
                    .read(&1)
                    .unwrap(),
                VAL_Y
            );
            assert_eq!(
                rewards
                    .reward_promis_load_at
                    .get_nested(&20240101)
                    .read(&1)
                    .unwrap(),
                U256::from(300u64)
            );
        });
    }

    #[test]
    fn prepared_reward_gem_batch_freezes_reward_utc_day_type_for_delivery() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, U256::from(2u64) * one_coen840());

            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(50u64), &[(VAL_X, 1)])
                .unwrap();
            prepare_daily_validator_gem_batch(&ctx, 20240201, U256::from(70u64), &[(VAL_Y, 1)])
                .unwrap();

            let first = deliver_oldest_reward_gem_batch(&ctx).unwrap();
            assert!(matches!(
                first,
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240101,
                    ..
                }
            ));
            let second = deliver_oldest_reward_gem_batch(&ctx).unwrap();
            assert!(matches!(
                second,
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240201,
                    ..
                }
            ));

            let gem = outbe_gem::GemContract::new(ctx.storage.clone());

            assert_eq!(gem.balance_of(VAL_X).unwrap(), 1);
            let x_gem_id = gem.token_of_owner_by_index(VAL_X, 0).unwrap();
            let x_item = outbe_gem::api::get_gem(&ctx.storage, x_gem_id)
                .unwrap()
                .unwrap();
            assert_eq!(x_item.gem_type, GemTypes::Genesis as u8);
            assert_eq!(
                x_item.state,
                outbe_gem::GemState::Qualified as u8,
                "Genesis gem is born Qualified"
            );

            assert_eq!(gem.balance_of(VAL_Y).unwrap(), 1);
            let y_gem_id = gem.token_of_owner_by_index(VAL_Y, 0).unwrap();
            let y_item = outbe_gem::api::get_gem(&ctx.storage, y_gem_id)
                .unwrap()
                .unwrap();
            assert_eq!(y_item.gem_type, GemTypes::Validator as u8);
            assert_eq!(
                y_item.state,
                outbe_gem::GemState::Issued as u8,
                "Post-genesis Validator gem is born Issued"
            );
        });
    }

    #[test]
    fn identical_preparation_replay_does_not_append_a_second_batch() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            let voters = [(VAL_X, 1), (VAL_Y, 2)];

            let first =
                prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(300u64), &voters)
                    .unwrap();
            let replay =
                prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(300u64), &voters)
                    .unwrap();
            let rewards = ctx.storage.contract::<Rewards>();

            assert!(matches!(first, RewardGemPreparationOutcome::Prepared(_)));
            assert!(matches!(
                replay,
                RewardGemPreparationOutcome::AlreadyPrepared(_)
            ));
            assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
            assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
        });
    }

    #[test]
    fn delivered_preparation_replay_ignores_dead_recipient_rows() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            let voters = [(VAL_X, 1)];

            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(100u64), &voters).unwrap();
            assert!(matches!(
                deliver_oldest_reward_gem_batch(&ctx).unwrap(),
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240101,
                    ..
                }
            ));

            // A delivered batch is authoritative from its settled marker and
            // lack of live FIFO linkage. Dead recipient rows are not replay
            // inputs and therefore cannot halt Cycle or mint a second Gem.
            let rewards = ctx.storage.contract::<Rewards>();
            rewards
                .reward_gem_owner_at
                .get_nested(&20240101)
                .write(&0, VAL_Y)
                .unwrap();
            rewards
                .reward_promis_load_at
                .get_nested(&20240101)
                .write(&0, U256::from(999u64))
                .unwrap();

            let replay =
                prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(100u64), &voters)
                    .unwrap();
            assert!(matches!(
                replay,
                RewardGemPreparationOutcome::AlreadyPrepared(_)
            ));
            assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 1);
            assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
            assert_eq!(rewards.reward_gem_pending_batch_count.read().unwrap(), 0);
            assert_eq!(voter_promis_loads(&ctx, VAL_X).len(), 1);
        });
    }

    #[test]
    fn prepared_batch_with_lost_fifo_linkage_is_retryable_without_writes() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            let voters = [(VAL_X, 1)];
            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(100u64), &voters).unwrap();

            let rewards = ctx.storage.contract::<Rewards>();
            rewards.reward_gem_queue_tail.write(0).unwrap();

            let replay_error =
                prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(100u64), &voters)
                    .unwrap_err();
            assert!(
                matches!(replay_error, PrecompileError::Revert(_)),
                "prepared obligation without a live FIFO link must fail closed: {replay_error:?}"
            );

            let delivery_error = deliver_oldest_reward_gem_batch(&ctx).unwrap_err();
            assert!(
                matches!(delivery_error, PrecompileError::Revert(_)),
                "an empty queue cannot hide a prepared unsettled obligation: {delivery_error:?}"
            );
            assert!(voter_promis_loads(&ctx, VAL_X).is_empty());
        });
    }

    #[test]
    fn contradictory_preparation_replay_is_retryable_without_writes() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(100u64), &[(VAL_X, 1)])
                .unwrap();
            let rewards = ctx.storage.contract::<Rewards>();
            let before_tail = rewards.reward_gem_queue_tail.read().unwrap();
            let before_digest = rewards.reward_gem_batch_digest.read(&20240101).unwrap();

            let err = ctx
                .with_checkpoint(|| {
                    prepare_daily_validator_gem_batch(
                        &ctx,
                        20240101,
                        U256::from(101u64),
                        &[(VAL_X, 1)],
                    )
                })
                .unwrap_err();
            assert!(matches!(err, PrecompileError::Revert(_)), "{err:?}");
            assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), before_tail);
            assert_eq!(
                rewards.reward_gem_batch_digest.read(&20240101).unwrap(),
                before_digest
            );
        });
    }

    #[test]
    fn stale_delivery_preserves_fifo_head_without_minting() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(100u64), &[(VAL_X, 1)])
                .unwrap();
            let (_, pair_index) =
                outbe_oracle::api::require_coen_pair(ctx.storage.clone(), 840).unwrap();
            outbe_oracle::schema::OracleContract::new(ctx.storage.clone())
                .exchange_rate_timestamp
                .write(&pair_index, 0)
                .unwrap();

            assert_eq!(
                deliver_oldest_reward_gem_batch(&ctx).unwrap(),
                RewardGemDeliveryOutcome::PendingRate {
                    reward_utc_day: 20240101
                }
            );
            assert_eq!(
                deliver_oldest_reward_gem_batch(&ctx).unwrap(),
                RewardGemDeliveryOutcome::PendingRate {
                    reward_utc_day: 20240101
                }
            );
            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
            assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
            assert!(voter_promis_loads(&ctx, VAL_X).is_empty());
        });
    }

    #[test]
    fn fresh_delivery_mints_the_head_exactly_once() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            prepare_daily_validator_gem_batch(
                &ctx,
                20240101,
                U256::from(400u64),
                &[(VAL_X, 1), (VAL_Y, 3)],
            )
            .unwrap();

            assert_eq!(
                deliver_oldest_reward_gem_batch(&ctx).unwrap(),
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240101,
                    recipient_count: 2,
                    delivered_promis_load_amount: U256::from(400u64),
                }
            );
            assert_eq!(voter_promis_loads(&ctx, VAL_X), vec![U256::from(100u64)]);
            assert_eq!(voter_promis_loads(&ctx, VAL_Y), vec![U256::from(300u64)]);
            assert_eq!(
                deliver_oldest_reward_gem_batch(&ctx).unwrap(),
                RewardGemDeliveryOutcome::Empty
            );
            assert_eq!(voter_promis_loads(&ctx, VAL_X), vec![U256::from(100u64)]);
            assert_eq!(voter_promis_loads(&ctx, VAL_Y), vec![U256::from(300u64)]);
        });
    }

    #[test]
    fn failed_delivery_rolls_back_every_gem_and_retries_the_same_batch() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            prepare_daily_validator_gem_batch(
                &ctx,
                20240101,
                U256::from(200u64),
                &[(VAL_X, 1), (VAL_Y, 1)],
            )
            .unwrap();
            let factory = outbe_gemfactory::schema::GemFactoryContract::new(ctx.storage.clone());
            factory
                .total_gems_issued
                .write(U256::MAX - U256::ONE)
                .unwrap();

            let err = ctx
                .with_checkpoint(|| deliver_oldest_reward_gem_batch(&ctx))
                .unwrap_err();
            assert!(matches!(err, PrecompileError::Revert(_)), "{err:?}");
            assert!(voter_promis_loads(&ctx, VAL_X).is_empty());
            assert!(voter_promis_loads(&ctx, VAL_Y).is_empty());
            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);

            factory.total_gems_issued.write(U256::ZERO).unwrap();
            assert!(matches!(
                deliver_oldest_reward_gem_batch(&ctx).unwrap(),
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240101,
                    ..
                }
            ));
            assert_eq!(voter_promis_loads(&ctx, VAL_X), vec![U256::from(100u64)]);
            assert_eq!(voter_promis_loads(&ctx, VAL_Y), vec![U256::from(100u64)]);
        });
    }

    #[test]
    fn two_reward_utc_days_deliver_fifo_one_batch_per_call() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(10u64), &[(VAL_X, 1)])
                .unwrap();
            prepare_daily_validator_gem_batch(&ctx, 20240102, U256::from(20u64), &[(VAL_Y, 1)])
                .unwrap();

            let first = deliver_oldest_reward_gem_batch(&ctx).unwrap();
            assert!(matches!(
                first,
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240101,
                    ..
                }
            ));
            assert_eq!(voter_promis_loads(&ctx, VAL_X), vec![U256::from(10u64)]);
            assert!(voter_promis_loads(&ctx, VAL_Y).is_empty());

            let second = deliver_oldest_reward_gem_batch(&ctx).unwrap();
            assert!(matches!(
                second,
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240102,
                    ..
                }
            ));
            assert_eq!(voter_promis_loads(&ctx, VAL_Y), vec![U256::from(20u64)]);
        });
    }

    #[test]
    fn pending_reward_gem_batch_survives_storage_reopen() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            seed_oracle(&ctx, one_coen840());
            prepare_daily_validator_gem_batch(&ctx, 20240101, U256::from(90u64), &[(VAL_Z, 1)])
                .unwrap();
        });

        storage.enter(|handle| {
            let reopened = BlockRuntimeContext::new(block_ctx(2, GENESIS_TS + 120), handle);
            let rewards = reopened.storage.contract::<Rewards>();
            assert!(rewards.daily_topup_prepared.read(&20240101).unwrap());
            assert_eq!(rewards.reward_gem_queue_head.read().unwrap(), 0);
            assert_eq!(rewards.reward_gem_queue_tail.read().unwrap(), 1);
            assert!(matches!(
                deliver_oldest_reward_gem_batch(&reopened).unwrap(),
                RewardGemDeliveryOutcome::Delivered {
                    reward_utc_day: 20240101,
                    delivered_promis_load_amount,
                    ..
                } if delivered_promis_load_amount == U256::from(90u64)
            ));
            assert_eq!(
                voter_promis_loads(&reopened, VAL_Z),
                vec![U256::from(90u64)]
            );
            assert!(rewards.daily_topup_settled.read(&20240101).unwrap());
        });
    }
}
