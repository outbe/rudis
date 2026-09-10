//! Per-block fee escrow + participation accumulation hook.
//!
//! Invoked from the executor's post-exec block AFTER the top-level
//! fingerprint check (step 9) and `record_finalized_participation` have
//! run. Performs the idempotent per-finalized-block work:
//!
//! 1. Lazily initialize `last_settled_utc_day` on the first finalized
//!    day observed (so the day-settle eligibility window opens correctly).
//! 2. Per-block accumulation: `daily_fee_sum_raw`, `daily_fee_dust`,
//!    guarded by `block_metadata_counted[fb_hash]`.
//! 3. Per-block fee ESCROW + participation count, guarded by `fb_hash` /
//!    `(fb_hash, voter)` composite keys. Fees are NOT paid eagerly: the
//!    block's `validator_fee_sum` is escrowed via
//!    `late_settlement::escrow_block_fee` (`pending_fees[fb_hash]`, base
//!    2f+1 seeded at `k=0`) and settled at `N+K` over the inclusion-window
//!    voter set. The daily emission top-up lands later at
//!    the day-boundary settle (step 11).
//! 4. Advance `max_observed_finalized_day` (monotonic).
//!

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::{
    block::BlockRuntimeContext,
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::{PrecompileError, Result},
    time::{previous_date_key, timestamp_to_date_key},
};

use crate::schema::Rewards;

/// number of recent finalized blocks whose per-`fb_hash` guard maps
/// (`block_metadata_counted`, `metadata_fingerprint_for_block`,
/// `fee_dust_counted_for_block`, `fee_settled`) stay live. The replay/settle
/// horizon is the K-block late-finalize window
/// ([`LATE_FINALIZE_WINDOW_K`](outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K) = 3),
/// so retaining the last 64 finalized blocks is generous; older guard flags
/// are pruned by [`prune_block_guards`]. Changing it is a hard fork.
pub const BLOCK_GUARD_RETAIN: u64 = 64;

/// Record `fb_hash` in the prune ring and clear the four per-`fb_hash` guard
/// maps of the finalized block evicted `BLOCK_GUARD_RETAIN` records ago.
///
/// Without this, `block_metadata_counted`, `metadata_fingerprint_for_block`,
/// `fee_dust_counted_for_block`, and `fee_settled` grow by one entry per
/// finalized block forever. The evicted block is `BLOCK_GUARD_RETAIN` >> K
/// blocks old, so it can no longer be re-counted or settled and clearing its
/// guards cannot weaken replay protection for any block still in the window.
/// The nested `participation_counted_for_block[fb_hash]` map is freed at
/// settlement instead (see `late_settlement::settle_window`), where the
/// credited voter set is known.
fn prune_block_guards(rewards: &Rewards<'_>, fb_hash: B256) -> Result<()> {
    let seq = rewards.block_guard_ring_seq.read()?;
    let idx = seq % BLOCK_GUARD_RETAIN;
    let evicted = rewards.block_guard_ring.read(&idx)?;
    if evicted != B256::ZERO && evicted != fb_hash {
        rewards.block_metadata_counted.write(&evicted, false)?;
        rewards
            .metadata_fingerprint_for_block
            .write(&evicted, B256::ZERO)?;
        rewards.fee_dust_counted_for_block.write(&evicted, false)?;
        rewards.fee_settled.write(&evicted, false)?;
    }
    rewards.block_guard_ring.write(&idx, fb_hash)?;
    rewards.block_guard_ring_seq.write(
        seq.checked_add(1)
            .ok_or_else(|| PrecompileError::Revert("block_guard_ring_seq overflow".into()))?,
    )?;
    Ok(())
}

/// Per-block fee escrow and participation/cap accumulation.
///
/// Caller must have already:
/// - run `check_and_record_metadata_fingerprint` and seen `Fresh`
///   (identical replay short-circuits upstream),
/// - called `record_finalized_participation`,
/// - resolved the finalized parent's `validator_fee_sum` and timestamp.
///
/// `voters` is the list of validator addresses whose `signer_bitmap`
/// bit was set; the slashing wrappers handle the absent set separately.
///
/// `validator_fee_sum` is read from
/// `finalized.summary.validator_fee_sum` and represents the raw fees
/// escrowed on `REWARDS_ADDRESS` for the finalized parent block.
///
/// `finalized_block_timestamp` is the timestamp of the finalized parent
/// block, used to compute the UTC day key (`fb_day`).
pub fn on_finalized_metadata(
    ctx: &BlockRuntimeContext,
    metadata: &CertifiedParentAccountingMetadata,
    validator_fee_sum: U256,
    finalized_block_timestamp: u64,
    voters: &[Address],
) -> Result<()> {
    let fb_hash = metadata.finalized_block_hash;
    let fb_day = timestamp_to_date_key(finalized_block_timestamp);

    let rewards: Rewards<'_> = ctx.storage.contract::<Rewards<'_>>();

    // first sight of this finalized block? `block_metadata_counted` is the
    // durable per-`fb_hash` first-seen signal, so the prune ring advances exactly
    // once per finalized block even if the hook is re-entered for the same hash.
    let first_seen = !rewards.block_metadata_counted.read(&fb_hash)?;

    // 1. Lazy init of `last_settled_utc_day` on first finalized day observed.
    if rewards.last_settled_utc_day.read()? == 0 {
        rewards
            .last_settled_utc_day
            .write(previous_date_key(fb_day))?;
    }

    // per-day raw fee accumulation still feeds the daily-emission cap,
    // but the fees themselves are now ESCROWED per finalized block (not paid
    // eagerly) and settled at N+K. Idempotent via `block_metadata_counted`.
    if first_seen {
        let closes_at = metadata
            .finalized_block_number
            .checked_add(outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K)
            .ok_or_else(|| PrecompileError::Fatal("reward window height overflow".into()))?;
        rewards.pending_reward_day.write(&fb_hash, fb_day)?;
        let previous_close = rewards.daily_last_window_close.read(&fb_day)?;
        rewards
            .daily_last_window_close
            .write(&fb_day, previous_close.max(closes_at))?;
        let prev_raw = rewards.daily_fee_sum_raw.read(&fb_day)?;
        let next_raw = prev_raw
            .checked_add(validator_fee_sum)
            .ok_or_else(|| PrecompileError::Revert("daily_fee_sum_raw overflow".into()))?;
        rewards.daily_fee_sum_raw.write(&fb_day, next_raw)?;
        rewards.block_metadata_counted.write(&fb_hash, true)?;
    }

    // per-block fee escrow (replaces the former eager per-voter
    // `transfer_balance`): record `pending_fees[fb_hash]` and seed the base 2f+1
    // (the eager finalize signers) at inclusion distance k=0. The fee is settled
    // at N+K by the `LateFinalizeCredits` begin-zone phase over the full credited
    // voter set (decay-weighted, fixed denominator); residue burns.
    // Committee size = ordered_committee length, bounded by MAX_VALIDATORS (256),
    // so it always fits u32 (clamp is a defensive no-panic guard, never hit).
    let committee_size = u32::try_from(metadata.ordered_committee.len()).unwrap_or(u32::MAX);
    crate::late_settlement::escrow_block_fee(
        ctx,
        metadata.finalized_block_number,
        fb_hash,
        validator_fee_sum,
        committee_size,
        metadata.finalized_epoch,
        metadata.finalized_view,
        metadata.parent_view,
        metadata.committee_set_hash,
        voters,
    )?;

    // Base and authenticated late voters share one per-block participation guard.
    for voter in voters {
        record_reward_participation(ctx, fb_hash, fb_day, *voter)?;
    }

    // 4. Advance max observed finalized day (monotonic).
    let prev_max = rewards.max_observed_finalized_day.read()?;
    if fb_day > prev_max {
        rewards.max_observed_finalized_day.write(fb_day)?;
    }

    // Bound finalized-block replay guards, well beyond the late-credit window.
    if first_seen {
        prune_block_guards(&rewards, fb_hash)?;
    }
    Ok(())
}

/// Count one verified participant, independent of whether it arrived in the
/// base certificate or in the canonical late-credit window. The reward belongs
/// to the finalized block's day, never to the credit's inclusion day.
pub(crate) fn record_reward_participation(
    ctx: &BlockRuntimeContext,
    fb_hash: B256,
    fb_day: u32,
    voter: Address,
) -> Result<()> {
    let rewards = ctx.storage.contract::<Rewards>();
    let participation_guard = rewards.participation_counted_for_block.get_nested(&fb_hash);
    let day_participation = rewards.daily_participation.get_nested(&fb_day);
    let day_voter_at = rewards.daily_voter_at.get_nested(&fb_day);

    if !participation_guard.read(&voter)? {
        if rewards.daily_topup_prepared.read(&fb_day)? {
            return Err(PrecompileError::Fatal(
                "reward participation arrived after GEM batch preparation".into(),
            ));
        }
        let prev_count = day_participation.read(&voter)?;
        if prev_count == 0 {
            // First time we see this voter for this day -> append to
            // the deterministic ordered voter list.
            let idx = rewards.daily_voter_count.read(&fb_day)?;
            day_voter_at.write(&idx, voter)?;
            let next_idx = idx
                .checked_add(1)
                .ok_or_else(|| PrecompileError::Revert("daily_voter_count overflow".into()))?;
            rewards.daily_voter_count.write(&fb_day, next_idx)?;
        }
        let next_count = prev_count
            .checked_add(1)
            .ok_or_else(|| PrecompileError::Revert("daily_participation overflow".into()))?;
        day_participation.write(&voter, next_count)?;

        let prev_total = rewards.daily_total_participation.read(&fb_day)?;
        let next_total = prev_total
            .checked_add(1)
            .ok_or_else(|| PrecompileError::Revert("daily_total_participation overflow".into()))?;
        rewards
            .daily_total_participation
            .write(&fb_day, next_total)?;

        participation_guard.write(&voter, true)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime;
    use alloy_primitives::{address, b256, Bytes, B256};
    use outbe_primitives::addresses::REWARDS_ADDRESS;
    use outbe_primitives::block::BlockContext;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;

    const CHAIN_ID: u64 = 1;
    // Genesis at midnight UTC of 2024-01-01.
    const GENESIS_TS: u64 = 1_704_067_200;
    const SECONDS_PER_DAY: u64 = 86_400;

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

    /// Lock in genesis_utc_day so day_number_since_genesis works in the hook
    /// (kept in test setup for forward-compat with day-based settlement).
    fn bootstrap_genesis(ctx: &BlockRuntimeContext) {
        runtime::ensure_genesis_anchor(ctx).unwrap();
    }

    /// Pre-fund REWARDS_ADDRESS with `amount` so transfer_balance succeeds.
    fn fund_rewards(ctx: &BlockRuntimeContext, amount: U256) {
        ctx.storage
            .increase_balance(REWARDS_ADDRESS, amount)
            .unwrap();
    }

    const FB_HASH_A: B256 =
        b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
    const FB_HASH_B: B256 =
        b256!("0x2222222222222222222222222222222222222222222222222222222222222222");
    const VAL_X: Address = address!("0x00000000000000000000000000000000000000A1");
    const VAL_Y: Address = address!("0x00000000000000000000000000000000000000B2");

    #[test]
    fn late_vote_across_midnight_counts_once_for_the_original_reward_day() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(11, GENESIS_TS + SECONDS_PER_DAY), handle);
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 10),
                U256::ZERO,
                GENESIS_TS + SECONDS_PER_DAY - 1,
                &[VAL_X],
            )
            .unwrap();
            crate::late_settlement::record_late_credit(&ctx, FB_HASH_A, VAL_Y, 1).unwrap();
            crate::late_settlement::record_late_credit(&ctx, FB_HASH_A, VAL_Y, 2).unwrap();
            crate::late_settlement::record_late_credit(&ctx, FB_HASH_A, VAL_X, 1).unwrap();
            assert_eq!(
                crate::api::read_voters_for_day(&ctx, 20240101).unwrap(),
                vec![(VAL_X, 1), (VAL_Y, 1)]
            );
            assert!(crate::api::read_voters_for_day(&ctx, 20240102)
                .unwrap()
                .is_empty());
        });
    }

    #[test]
    fn escrows_block_fees_and_seeds_base_voters_at_k0() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);

            let fees = U256::from(101u64);
            fund_rewards(&ctx, fees);

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                fees,
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            // fees are ESCROWED, not paid eagerly - voter balances stay
            // zero and the full fee remains on REWARDS until settle at N+K.
            assert_eq!(ctx.storage.balance(VAL_X).unwrap(), U256::ZERO);
            assert_eq!(ctx.storage.balance(VAL_Y).unwrap(), U256::ZERO);
            assert_eq!(ctx.storage.balance(REWARDS_ADDRESS).unwrap(), fees);

            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(rewards.pending_fees.read(&FB_HASH_A).unwrap(), fees);
            assert!(!rewards.fee_settled.read(&FB_HASH_A).unwrap());
            // Base 2f+1 seeded at k=0 (stored k+1 == 1).
            let kmap = rewards.late_voter_k_plus1.get_nested(&FB_HASH_A);
            assert_eq!(kmap.read(&VAL_X).unwrap(), 1);
            assert_eq!(kmap.read(&VAL_Y).unwrap(), 1);
            assert_eq!(rewards.late_voter_count.read(&FB_HASH_A).unwrap(), 2);
            // Daily raw fee accounting (emission-cap input) still accumulates.
            assert_eq!(rewards.daily_fee_sum_raw.read(&20240101).unwrap(), fees);
        });
    }

    #[test]
    fn records_per_voter_participation_and_voter_list() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            fund_rewards(&ctx, U256::from(100u64));

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            let rewards = ctx.storage.contract::<Rewards>();
            let day_participation = rewards.daily_participation.get_nested(&20240101);
            assert_eq!(day_participation.read(&VAL_X).unwrap(), 1);
            assert_eq!(day_participation.read(&VAL_Y).unwrap(), 1);
            assert_eq!(
                rewards.daily_total_participation.read(&20240101).unwrap(),
                2
            );
            assert_eq!(rewards.daily_voter_count.read(&20240101).unwrap(), 2);

            let day_voter_at = rewards.daily_voter_at.get_nested(&20240101);
            // First-seen order: VAL_X at idx 0, VAL_Y at idx 1.
            assert_eq!(day_voter_at.read(&0u32).unwrap(), VAL_X);
            assert_eq!(day_voter_at.read(&1u32).unwrap(), VAL_Y);
        });
    }

    #[test]
    fn replay_for_same_fb_hash_is_idempotent() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            fund_rewards(&ctx, U256::from(100u64));

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            // Replay: escrow, base-voter seeding, raw-fee and participation are
            // all idempotent.
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            // No eager payout; escrow holds the full fee once.
            assert_eq!(ctx.storage.balance(VAL_X).unwrap(), U256::ZERO);
            assert_eq!(ctx.storage.balance(VAL_Y).unwrap(), U256::ZERO);

            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(
                rewards.pending_fees.read(&FB_HASH_A).unwrap(),
                U256::from(100u64)
            );
            assert_eq!(
                rewards.late_voter_count.read(&FB_HASH_A).unwrap(),
                2,
                "replay must not duplicate base voters"
            );
            assert_eq!(
                rewards.daily_fee_sum_raw.read(&20240101).unwrap(),
                U256::from(100u64),
                "replay must not double-count raw fees"
            );
            assert_eq!(
                rewards.daily_total_participation.read(&20240101).unwrap(),
                2,
                "replay must not double-count participation"
            );
        });
    }

    #[test]
    fn distinct_fb_hashes_for_same_day_aggregate() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            fund_rewards(&ctx, U256::from(200u64));

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_B, 2),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            let rewards = ctx.storage.contract::<Rewards>();
            // Both blocks contributed 100 -> 200 raw (emission-cap input).
            assert_eq!(
                rewards.daily_fee_sum_raw.read(&20240101).unwrap(),
                U256::from(200u64)
            );
            // Each finalized block is escrowed separately under its own fb_hash.
            assert_eq!(
                rewards.pending_fees.read(&FB_HASH_A).unwrap(),
                U256::from(100u64)
            );
            assert_eq!(
                rewards.pending_fees.read(&FB_HASH_B).unwrap(),
                U256::from(100u64)
            );
            // No eager payouts - fees stay escrowed until settle.
            assert_eq!(ctx.storage.balance(VAL_X).unwrap(), U256::ZERO);
            assert_eq!(ctx.storage.balance(VAL_Y).unwrap(), U256::ZERO);
            // Participation: 2 blocks x 2 voters = 4.
            assert_eq!(
                rewards.daily_total_participation.read(&20240101).unwrap(),
                4
            );
            assert_eq!(
                rewards
                    .daily_participation
                    .get_nested(&20240101)
                    .read(&VAL_X)
                    .unwrap(),
                2
            );
        });
    }

    #[test]
    fn first_call_initializes_last_settled_utc_day_to_previous_day() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);

            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(rewards.last_settled_utc_day.read().unwrap(), 0);

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::ZERO,
                GENESIS_TS, // fb_day = 20240101
                &[VAL_X],
            )
            .unwrap();

            // Initialized to previous_date_key(20240101) = 20231231.
            assert_eq!(rewards.last_settled_utc_day.read().unwrap(), 20231231);
            assert_eq!(rewards.max_observed_finalized_day.read().unwrap(), 20240101);
        });
    }

    #[test]
    fn metadata_for_settled_day_is_not_fatal_under_sync_phase_ordering() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);

            // `daily_settled` is a Cycle-owned completion marker.
            // makes finalized metadata synchronous Phase 1 input before Cycle
            // runs, so the old late-after-settle fatal guard is removed.
            ctx.storage
                .contract::<Rewards>()
                .daily_settled
                .write(&20240101, true)
                .unwrap();

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::ZERO,
                GENESIS_TS,
                &[VAL_X],
            )
            .unwrap();

            let rewards = ctx.storage.contract::<Rewards>();
            assert!(rewards.block_metadata_counted.read(&FB_HASH_A).unwrap());
            assert_eq!(
                rewards
                    .daily_participation
                    .get_nested(&20240101)
                    .read(&VAL_X)
                    .unwrap(),
                1
            );
        });
    }

    #[test]
    fn no_voters_escrows_full_fee_with_no_base_seed() {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);

            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[],
            )
            .unwrap();

            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(
                rewards.daily_fee_sum_raw.read(&20240101).unwrap(),
                U256::from(100u64)
            );
            // Whole fee escrowed; no base voters -> the entire pool becomes
            // burnable residue at settle.
            assert_eq!(
                rewards.pending_fees.read(&FB_HASH_A).unwrap(),
                U256::from(100u64)
            );
            assert_eq!(rewards.late_voter_count.read(&FB_HASH_A).unwrap(), 0);
            assert_eq!(
                rewards.daily_total_participation.read(&20240101).unwrap(),
                0
            );
        });
    }

    #[test]
    fn cross_day_block_advances_max_observed_without_settle() {
        // on_finalized_metadata does not trigger day-boundary
        // settlement. The hook only updates the per-day fee
        // accumulators, per-voter participation, and the monotonic
        // `max_observed_finalized_day` watermark. Day-boundary settle
        // is owned by the new Cycle orchestrator and
        // fires via `crate::api::prepare_daily_validator_gem_batch`, not from this
        // hook.
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            fund_rewards(&ctx, U256::from(200u64));

            // Block from day D=20240101.
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_A, 1),
                U256::from(100u64),
                GENESIS_TS,
                &[VAL_X, VAL_Y],
            )
            .unwrap();
            // Block from day D+2=20240103.
            on_finalized_metadata(
                &ctx,
                &meta_with_hash(FB_HASH_B, 2),
                U256::from(100u64),
                GENESIS_TS + 2 * SECONDS_PER_DAY,
                &[VAL_X, VAL_Y],
            )
            .unwrap();

            let rewards = ctx.storage.contract::<Rewards>();
            // max_observed_finalized_day still advances monotonically:
            // it is the watermark consumed by the orchestrator.
            assert_eq!(rewards.max_observed_finalized_day.read().unwrap(), 20240103);
            // No settle: every day's marker stays false until the
            // orchestrator runs.
            assert!(!rewards.daily_settled.read(&20240101).unwrap());
            assert!(!rewards.daily_settled.read(&20240102).unwrap());
            assert!(!rewards.daily_settled.read(&20240103).unwrap());
            // `last_settled_utc_day` is lazy-initialized on the very
            // first observed finalized day to `previous_date_key(fb_day)`
            // and is no longer advanced by the hook.
            assert_eq!(rewards.last_settled_utc_day.read().unwrap(), 20231231);
        });
    }

    // -- Step 23: idempotency property test -----------------------------
    //
    // Replay-safety contract: applying a canonical sequence of finalized
    // metadata events, then re-applying any subset of those events any
    // number of times, must produce a state byte-equal to the
    // canonical-only baseline. This is the structural justification for
    // removing the `<= applied_number` watermark in step 12.
    //
    // The test only exercises *duplicate* replays of already-applied
    // events. Re-ordering distinct events is intentionally NOT covered:
    // `daily_voter_at[day][i]` records first-seen order, so a different
    // order produces a different (still valid) storage layout.

    use proptest::prelude::*;

    /// Snapshot of every Rewards slot the hook may touch, plus voter and
    /// REWARDS balances. Equality on this struct is the byte-equality
    /// contract the watermark-removal proof relies on.
    #[derive(Debug, PartialEq, Eq)]
    struct ReplaySnapshot {
        last_settled_utc_day: u32,
        max_observed_finalized_day: u32,
        rewards_balance: U256,
        // Per-day aggregates.
        daily_fee_sum_raw: std::collections::BTreeMap<u32, U256>,
        daily_fees_paid: std::collections::BTreeMap<u32, U256>,
        daily_fee_dust: std::collections::BTreeMap<u32, U256>,
        daily_total_participation: std::collections::BTreeMap<u32, u64>,
        daily_voter_count: std::collections::BTreeMap<u32, u32>,
        daily_voter_at: std::collections::BTreeMap<(u32, u32), Address>,
        daily_participation_per_voter: std::collections::BTreeMap<(u32, Address), u64>,
        // Per-fb_hash guards.
        block_metadata_counted: std::collections::BTreeMap<B256, bool>,
        // Per-voter balances.
        voter_balances: std::collections::BTreeMap<Address, U256>,
    }

    fn snapshot(
        ctx: &BlockRuntimeContext,
        days: &[u32],
        voters: &[Address],
        fb_hashes: &[B256],
    ) -> ReplaySnapshot {
        let rewards = ctx.storage.contract::<Rewards>();
        let mut daily_fee_sum_raw = std::collections::BTreeMap::new();
        let mut daily_fees_paid = std::collections::BTreeMap::new();
        let mut daily_fee_dust = std::collections::BTreeMap::new();
        let mut daily_total_participation = std::collections::BTreeMap::new();
        let mut daily_voter_count = std::collections::BTreeMap::new();
        let mut daily_voter_at = std::collections::BTreeMap::new();
        let mut daily_participation_per_voter = std::collections::BTreeMap::new();
        for &d in days {
            daily_fee_sum_raw.insert(d, rewards.daily_fee_sum_raw.read(&d).unwrap());
            daily_fees_paid.insert(d, rewards.daily_fees_paid.read(&d).unwrap());
            daily_fee_dust.insert(d, rewards.daily_fee_dust.read(&d).unwrap());
            daily_total_participation
                .insert(d, rewards.daily_total_participation.read(&d).unwrap());
            let count = rewards.daily_voter_count.read(&d).unwrap();
            daily_voter_count.insert(d, count);
            let voter_at = rewards.daily_voter_at.get_nested(&d);
            for i in 0..count {
                daily_voter_at.insert((d, i), voter_at.read(&i).unwrap());
            }
            let participation = rewards.daily_participation.get_nested(&d);
            for &v in voters {
                daily_participation_per_voter.insert((d, v), participation.read(&v).unwrap());
            }
        }
        let mut block_metadata_counted = std::collections::BTreeMap::new();
        for &h in fb_hashes {
            block_metadata_counted.insert(h, rewards.block_metadata_counted.read(&h).unwrap());
        }
        let mut voter_balances = std::collections::BTreeMap::new();
        for &v in voters {
            voter_balances.insert(v, ctx.storage.balance(v).unwrap());
        }
        ReplaySnapshot {
            last_settled_utc_day: rewards.last_settled_utc_day.read().unwrap(),
            max_observed_finalized_day: rewards.max_observed_finalized_day.read().unwrap(),
            rewards_balance: ctx.storage.balance(REWARDS_ADDRESS).unwrap(),
            daily_fee_sum_raw,
            daily_fees_paid,
            daily_fee_dust,
            daily_total_participation,
            daily_voter_count,
            daily_voter_at,
            daily_participation_per_voter,
            block_metadata_counted,
            voter_balances,
        }
    }

    /// One canonical event in a replay scenario.
    #[derive(Debug, Clone)]
    struct Event {
        fb_hash: B256,
        fb_number: u64,
        fb_timestamp: u64,
        fees: U256,
        voter_mask: [bool; 3], // which of (VAL_X, VAL_Y, VAL_Z) signed
    }

    const VAL_Z: Address = address!("0x00000000000000000000000000000000000000C3");

    fn voters_for(mask: [bool; 3]) -> Vec<Address> {
        let pool = [VAL_X, VAL_Y, VAL_Z];
        pool.iter()
            .zip(mask.iter())
            .filter_map(|(v, &m)| if m { Some(*v) } else { None })
            .collect()
    }

    fn fb_hash_for(idx: u8) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[31] = idx + 1;
        B256::from(bytes)
    }

    /// Apply a canonical event sequence to a fresh storage and return the
    /// snapshot. Replay schedule = list of indices into `events` that
    /// will be re-applied (in order, as duplicates) immediately after
    /// the canonical event at the same index. The schedule is empty for
    /// the baseline run.
    fn run_scenario(
        events: &[Event],
        replay_after: &std::collections::BTreeMap<usize, u32>,
    ) -> ReplaySnapshot {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        let mut snap = None;
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            bootstrap_genesis(&ctx);
            // Pre-fund REWARDS with the canonical total fees (replays are
            // no-ops, so they cannot consume additional balance).
            let total_fees: U256 = events.iter().map(|e| e.fees).fold(U256::ZERO, |a, b| a + b);
            fund_rewards(&ctx, total_fees);

            for (i, e) in events.iter().enumerate() {
                let voters = voters_for(e.voter_mask);
                on_finalized_metadata(
                    &ctx,
                    &meta_with_hash(e.fb_hash, e.fb_number),
                    e.fees,
                    e.fb_timestamp,
                    &voters,
                )
                .unwrap();
                if let Some(&n) = replay_after.get(&i) {
                    for _ in 0..n {
                        on_finalized_metadata(
                            &ctx,
                            &meta_with_hash(e.fb_hash, e.fb_number),
                            e.fees,
                            e.fb_timestamp,
                            &voters,
                        )
                        .unwrap();
                    }
                }
            }

            let days: Vec<u32> = events
                .iter()
                .map(|e| outbe_primitives::time::timestamp_to_date_key(e.fb_timestamp))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            let voters: Vec<Address> = vec![VAL_X, VAL_Y, VAL_Z];
            let fb_hashes: Vec<B256> = events.iter().map(|e| e.fb_hash).collect();
            snap = Some(snapshot(&ctx, &days, &voters, &fb_hashes));
        });
        snap.expect("snapshot must be captured inside enter()")
    }

    fn arb_event(idx: u8) -> impl Strategy<Value = Event> {
        // All 4 events share UTC day 20240101 (timestamps within
        // [GENESIS_TS, GENESIS_TS + 86_400)). This isolates the
        // replay-idempotency property from the late-after-settle guard:
        // out-of-order arrivals across UTC days are a *separate* contract
        // already covered by `late_metadata_after_settle_is_fatal`.
        (any::<u8>(), 0u64..86_400u64)
            .prop_filter("at least one voter", |(m, _)| m & 0b111 != 0)
            .prop_map(move |(m, offset)| Event {
                fb_hash: fb_hash_for(idx),
                fb_number: idx as u64 + 1,
                fb_timestamp: GENESIS_TS + offset,
                // Fees in [0, 1785]; fee=0 is a legal "no-fee" block.
                fees: U256::from((m as u64) * 7),
                voter_mask: [(m & 0b001) != 0, (m & 0b010) != 0, (m & 0b100) != 0],
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 64,
            ..ProptestConfig::default()
        })]

        /// Canonical sequence of 4 events, with arbitrary duplicate-replay
        /// counts (0..=3) inserted after each. The replay-augmented run
        /// must produce a state byte-equal to the canonical-only baseline.
        #[test]
        fn replay_idempotency_property(
            ev0 in arb_event(0),
            ev1 in arb_event(1),
            ev2 in arb_event(2),
            ev3 in arb_event(3),
            replays in proptest::collection::vec(0u32..=3, 4),
        ) {
            let events = vec![ev0, ev1, ev2, ev3];
            let mut schedule = std::collections::BTreeMap::new();
            for (i, &n) in replays.iter().enumerate() {
                if n > 0 {
                    schedule.insert(i, n);
                }
            }

            let baseline = run_scenario(&events, &std::collections::BTreeMap::new());
            let with_replays = run_scenario(&events, &schedule);

            prop_assert_eq!(
                baseline,
                with_replays,
                "replay-augmented state must equal canonical-only state"
            );
        }
    }

    /// a finalized block evicted from the prune ring has all four of its
    /// per-`fb_hash` guard maps cleared, while blocks still inside the retention
    /// window keep theirs.
    #[test]
    fn block_guard_ring_evicts_and_clears_old_guards() {
        fn fb(i: u64) -> B256 {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&i.to_be_bytes());
            B256::from(b)
        }

        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(block_ctx(1, GENESIS_TS + 60), handle);
            let rewards = ctx.storage.contract::<Rewards>();

            // `victim` carries all four live per-fb_hash guards; `survivor` is a
            // block recorded one step later that must stay live.
            let victim = fb(1);
            let survivor = fb(2);
            for h in [victim, survivor] {
                rewards.block_metadata_counted.write(&h, true).unwrap();
                rewards
                    .metadata_fingerprint_for_block
                    .write(&h, fb(0xdead))
                    .unwrap();
                rewards.fee_dust_counted_for_block.write(&h, true).unwrap();
                rewards.fee_settled.write(&h, true).unwrap();
            }

            // Record victim, then survivor, then fill the ring with RETAIN-1 more
            // fresh blocks so victim (and only victim) reaches the eviction slot.
            prune_block_guards(&rewards, victim).unwrap();
            prune_block_guards(&rewards, survivor).unwrap();
            for i in 0..(BLOCK_GUARD_RETAIN - 1) {
                prune_block_guards(&rewards, fb(1000 + i)).unwrap();
            }

            // Victim evicted -> every guard reset to its default.
            assert!(!rewards.block_metadata_counted.read(&victim).unwrap());
            assert_eq!(
                rewards
                    .metadata_fingerprint_for_block
                    .read(&victim)
                    .unwrap(),
                B256::ZERO
            );
            assert!(!rewards.fee_dust_counted_for_block.read(&victim).unwrap());
            assert!(!rewards.fee_settled.read(&victim).unwrap());

            // Survivor is still inside the window -> guards intact.
            assert!(rewards.block_metadata_counted.read(&survivor).unwrap());
            assert!(rewards.fee_settled.read(&survivor).unwrap());
        });
    }
}
