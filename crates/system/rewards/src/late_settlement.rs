//! per-block fee escrow + inclusion-window settlement (Phase 6).
//!
//! The fees of block `N` are **escrowed** (recorded, not paid eagerly) and, once
//! the `K`-block inclusion window closes at `N+K`, split across the full credited
//! voter set with a **decay-weighted, fixed-denominator** payout:
//!
//! ```text
//! payout_i = pending_fees[N] * w(k_i) / D       D = committee_size * w_max
//! ```
//!
//! `D` is constant per block (independent of who voted), so excluding a peer
//! enriches nobody - there is no censorship incentive. The
//! residue (`pending - sum payout` = absentees + decay gap + division remainders)
//! burns, keeping mint/burn parity (`sum payout + residue == pending`).
//!
//! These are deterministic storage functions over an explicit
//! [`BlockRuntimeContext`]; the executor wires them into the begin-zone CPA
//! (escrow) and `LateFinalizeCredits` (record + settle) phases. At settle the
//! residue is burned from `REWARDS_ADDRESS` (parity) **and** recycled into
//! terminal Metadosis emission headroom via the canonical
//! [`outbe_emissionlimit::block::dispatch_terminal_remainder_at`]; the
//! per-window state (`pending_fees`, `late_voter_*`, the by-number lookups) is
//! then freed, leaving only the `fee_settled` tombstone (no state bloat).

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::{
    addresses::REWARDS_ADDRESS,
    block::BlockRuntimeContext,
    error::{PrecompileError, Result},
};

use crate::constants::{decay_weight, fixed_denominator};
use crate::schema::Rewards;

/// Record one credited voter for `fb_hash` at inclusion distance `k`, keeping the
/// **smallest** `k` ever seen. First credit appends to the
/// enumerable voter list; a later, larger `k` is a no-op; a later, smaller `k`
/// improves the stored distance without re-appending.
pub fn record_late_credit(
    ctx: &BlockRuntimeContext,
    fb_hash: B256,
    voter: Address,
    k: u8,
) -> Result<()> {
    let rewards = ctx.storage.contract::<Rewards<'_>>();
    if rewards.fee_settled.read(&fb_hash)? {
        // Window already closed; nothing more can be credited.
        return Ok(());
    }
    if k > outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K as u8 {
        return Err(PrecompileError::Fatal(
            "reward credit outside inclusion window".into(),
        ));
    }
    if k > 0 {
        let day = rewards.pending_reward_day.read(&fb_hash)?;
        if day == 0 {
            return Err(PrecompileError::Fatal(
                "late reward credit has no canonical UTC day".into(),
            ));
        }
        crate::finalized_metadata_hook::record_reward_participation(ctx, fb_hash, day, voter)?;
    }
    let kmap = rewards.late_voter_k_plus1.get_nested(&fb_hash);
    let stored = kmap.read(&voter)?; // 0 = absent, else k+1
    if stored == 0 {
        let idx = rewards.late_voter_count.read(&fb_hash)?;
        rewards
            .late_voter_at
            .get_nested(&fb_hash)
            .write(&idx, voter)?;
        let next = idx
            .checked_add(1)
            .ok_or_else(|| PrecompileError::Revert("late_voter_count overflow".into()))?;
        rewards.late_voter_count.write(&fb_hash, next)?;
        kmap.write(&voter, k + 1)?;
    } else {
        let current_k = stored - 1;
        if k < current_k {
            kmap.write(&voter, k + 1)?;
        }
    }
    Ok(())
}

/// Escrow block `N`'s fees (key `fb_hash`) and seed the base 2f+1 CPA signers at
/// `k = 0`, so a later re-inclusion of a base voter at `k >= 1` cannot worsen its
/// distance. Idempotent: re-escrowing the same block is a no-op once settled, and
/// re-seeding a base voter is a no-op (smallest-k rule).
#[allow(clippy::too_many_arguments)]
pub fn escrow_block_fee(
    ctx: &BlockRuntimeContext,
    fb_number: u64,
    fb_hash: B256,
    fee_sum: U256,
    committee_size: u32,
    canonical_epoch: u64,
    canonical_view: u64,
    canonical_parent_view: u64,
    canonical_committee_set_hash: B256,
    base_voters: &[Address],
) -> Result<()> {
    let rewards = ctx.storage.contract::<Rewards<'_>>();
    if rewards.fee_settled.read(&fb_hash)? {
        return Ok(());
    }
    rewards.pending_fees.write(&fb_hash, fee_sum)?;
    // Settle-trigger lookup by number (so block N+K can find block N's escrow)
    // and the canonical binding the Late phase authenticates each credit against
    // number -> {fb_hash, epoch, view, parent_view,
    // committee_set_hash}. The full signed binding is pinned so a credit whose
    // aggregate is over a non-canonical view of the same fb_hash is rejected.
    rewards.pending_fb_hash_at.write(&fb_number, fb_hash)?;
    rewards
        .pending_committee_size_at
        .write(&fb_number, committee_size)?;
    rewards
        .pending_epoch_at
        .write(&fb_number, canonical_epoch)?;
    rewards.pending_view_at.write(&fb_number, canonical_view)?;
    rewards
        .pending_parent_view_at
        .write(&fb_number, canonical_parent_view)?;
    rewards
        .pending_committee_set_hash_at
        .write(&fb_number, canonical_committee_set_hash)?;
    for voter in base_voters {
        record_late_credit(ctx, fb_hash, *voter, 0)?;
    }
    Ok(())
}

/// Window-close side effect run by the `LateFinalizeCredits` begin-zone phase at
/// `current_block`: settle the target whose inclusion window just closed
/// (`fb_number = current_block - K`), looked up by number. No-op when nothing was
/// escrowed at that number (e.g. block 0, or a block with no fees recorded yet).
pub fn settle_matured(
    ctx: &BlockRuntimeContext,
    current_block: u64,
    window_k: u64,
) -> Result<(U256, U256)> {
    let Some(fb_number) = current_block.checked_sub(window_k) else {
        return Ok((U256::ZERO, U256::ZERO));
    };
    if fb_number == 0 {
        // Block 0 produces no validator fees (settlement skips it).
        return Ok((U256::ZERO, U256::ZERO));
    }
    let rewards = ctx.storage.contract::<Rewards<'_>>();
    let fb_hash = rewards.pending_fb_hash_at.read(&fb_number)?;
    if fb_hash == B256::ZERO {
        return Ok((U256::ZERO, U256::ZERO));
    }
    let committee_size = u64::from(rewards.pending_committee_size_at.read(&fb_number)?);
    let result = settle_window(ctx, fb_hash, committee_size)?;

    // Free the number-keyed lookups now that the window is settled (the
    // hash-keyed state is freed inside `settle_window`). This runs exactly once:
    // a replay reads `pending_fb_hash_at[fb_number] == ZERO` above and returns
    // early before reaching here. `fee_settled[fb_hash]` is the durable guard.
    rewards.pending_fb_hash_at.write(&fb_number, B256::ZERO)?;
    rewards.pending_committee_size_at.write(&fb_number, 0)?;
    rewards.pending_epoch_at.write(&fb_number, 0)?;
    rewards.pending_view_at.write(&fb_number, 0)?;
    rewards.pending_parent_view_at.write(&fb_number, 0)?;
    rewards
        .pending_committee_set_hash_at
        .write(&fb_number, B256::ZERO)?;
    Ok(result)
}

/// Settle the matured window for `fb_hash` exactly once: pay each credited voter
/// `pending * w(k_i) / D` from `REWARDS_ADDRESS`, burn the residue, and assert
/// `sum payout + residue == pending`. Returns `(distributed, residue)`.
pub fn settle_window(
    ctx: &BlockRuntimeContext,
    fb_hash: B256,
    committee_size: u64,
) -> Result<(U256, U256)> {
    let rewards = ctx.storage.contract::<Rewards<'_>>();
    if rewards.fee_settled.read(&fb_hash)? {
        return Ok((U256::ZERO, U256::ZERO));
    }

    let pending = rewards.pending_fees.read(&fb_hash)?;
    let denominator = fixed_denominator(committee_size);
    if denominator.is_zero() {
        return Err(PrecompileError::Revert(
            "late settle denominator is zero (empty committee)".into(),
        ));
    }

    let count = rewards.late_voter_count.read(&fb_hash)?;
    let kmap = rewards.late_voter_k_plus1.get_nested(&fb_hash);
    let at = rewards.late_voter_at.get_nested(&fb_hash);

    let mut distributed = U256::ZERO;
    for idx in 0..count {
        let voter = at.read(&idx)?;
        let stored = kmap.read(&voter)?;
        if stored == 0 {
            continue;
        }
        let weight = decay_weight(u64::from(stored - 1));
        if weight.is_zero() {
            continue;
        }
        let payout = pending
            .checked_mul(weight)
            .ok_or_else(|| PrecompileError::Revert("late payout multiply overflow".into()))?
            / denominator;
        if payout.is_zero() {
            continue;
        }
        ctx.storage
            .transfer_balance(REWARDS_ADDRESS, voter, payout)?;
        distributed = distributed
            .checked_add(payout)
            .ok_or_else(|| PrecompileError::Revert("late distributed overflow".into()))?;
    }

    // Solvency: full attendance pays at most the pool (D = N*w_max), so
    // distributed <= pending; checked_sub guards any violation.
    let residue = pending.checked_sub(distributed).ok_or_else(|| {
        PrecompileError::Revert("late settle insolvent: distributed exceeds escrow".into())
    })?;
    if !residue.is_zero() {
        // Mint/burn parity: burn the residue from REWARDS, then recycle the same
        // amount into terminal Metadosis emission headroom via the purpose-bound
        // dispatcher. Under OCOMP this credits carry-over rather than racing the
        // daily base-limit formation; pre-OCOMP behavior remains unchanged.
        ctx.storage.decrease_balance(REWARDS_ADDRESS, residue)?;
        outbe_emissionlimit::block::dispatch_late_settlement_residue_at(
            ctx,
            residue,
            ctx.block.timestamp,
        )?;
    }

    // Parity invariant (checked once): sum payout + residue == pending.
    if distributed
        .checked_add(residue)
        .ok_or_else(|| PrecompileError::Revert("late parity overflow".into()))?
        != pending
    {
        return Err(PrecompileError::Revert(
            "late settle parity violated".into(),
        ));
    }

    rewards.fee_settled.write(&fb_hash, true)?;

    //  free the per-window state now that it is settled. After
    // `fee_settled = true`, `record_late_credit` short-circuits, so nothing more
    // is written for this `fb_hash` and the data is dead - freeing it here
    // prevents unbounded state growth. `fee_settled` is the immediate
    // double-settle / re-escrow guard; it is itself pruned later by the
    // ring in `on_finalized_metadata` (`BLOCK_GUARD_RETAIN` blocks after the
    // block was first counted, long past the K-block window) so it is bounded,
    // not permanent.
    //
    // the nested `participation_counted_for_block[fb_hash]` map is freed
    // here too. `late_voter_at` is a superset of the participation-counted
    // voters (every base voter passed to `escrow_block_fee` is seeded into it at
    // k=0), so clearing the guard for each credited voter clears every entry;
    // any non-counted late voter is a harmless write of the default `false`.
    let participation_guard = rewards.participation_counted_for_block.get_nested(&fb_hash);
    for idx in 0..count {
        let voter = at.read(&idx)?;
        kmap.write(&voter, 0)?;
        at.write(&idx, Address::ZERO)?;
        participation_guard.write(&voter, false)?;
    }
    rewards.late_voter_count.write(&fb_hash, 0)?;
    rewards.pending_fees.write(&fb_hash, U256::ZERO)?;
    rewards.pending_reward_day.write(&fb_hash, 0)?;

    Ok((distributed, residue))
}

/// Canonical binding + full credited voter set for the window maturing at
/// `fb_number`, used by the begin-zone window-close miss/slashing pass.
///
/// `credited` is the union of base voters (k=0, seeded at escrow) and late voters
/// (k>=1) - i.e. every committee member who voted within `K`. Callers compute the
/// absentee set as `committee(fb_number) \ credited`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCloseInfo {
    pub fb_hash: B256,
    pub epoch: u64,
    pub committee_set_hash: B256,
    pub credited: Vec<Address>,
}

/// Read the [`WindowCloseInfo`] for the window that matures at `fb_number`, or
/// `None` when nothing was escrowed there (block 0, or a block with no fees).
///
/// Pure read over committed chain state - deterministic across proposer and
/// validator. **Must run before [`settle_matured`]**, which frees `late_voter_*`.
pub fn window_close_credited(
    ctx: &BlockRuntimeContext,
    fb_number: u64,
) -> Result<Option<WindowCloseInfo>> {
    let rewards = ctx.storage.contract::<Rewards<'_>>();
    let fb_hash = rewards.pending_fb_hash_at.read(&fb_number)?;
    if fb_hash == B256::ZERO {
        return Ok(None);
    }
    let epoch = rewards.pending_epoch_at.read(&fb_number)?;
    let committee_set_hash = rewards.pending_committee_set_hash_at.read(&fb_number)?;
    let count = rewards.late_voter_count.read(&fb_hash)?;
    let at = rewards.late_voter_at.get_nested(&fb_hash);
    let mut credited = Vec::new();
    for idx in 0..count {
        credited.push(at.read(&idx)?);
    }
    Ok(Some(WindowCloseInfo {
        fb_hash,
        epoch,
        committee_set_hash,
        credited,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::LATE_FINALIZE_W_MAX;
    use alloy_primitives::address;
    use outbe_metadosis::test_support::ForkInstallScenario;
    use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, MetadosisMutationPurposeTag};
    use outbe_primitives::time::WorldwideDay;
    use outbe_promislimit::PromisLimitContract;

    const CHAIN_ID: u64 = 1;
    const GENESIS_HASH: B256 = B256::repeat_byte(0x11);
    const CONSENSUS_KEY: [u8; 48] = [7; 48];
    const FB: B256 = B256::repeat_byte(0xAB);
    const V0: Address = address!("0x00000000000000000000000000000000000000A0");
    const V1: Address = address!("0x00000000000000000000000000000000000000A1");
    const V2: Address = address!("0x00000000000000000000000000000000000000A2");
    const V3: Address = address!("0x00000000000000000000000000000000000000A3");

    fn install_ocomp_profile(storage: &mut HashMapStorageProvider) {
        let install = ForkInstallScenario::measurement_at(156, CHAIN_ID, GENESIS_HASH)
            .unwrap()
            .with_founder_validators(&[(V0, CONSENSUS_KEY)])
            .unwrap()
            .into_install();
        let registration = install.founder_registrations[0]
            .encode_canonical(&outbe_metadosis::config::poc_schema_limits())
            .unwrap();
        storage.enter(|handle| {
            let mut validators = outbe_validatorset::contract::ValidatorSet::new(handle.clone());
            validators.set_config_max_validators(1).unwrap();
            validators
                .register_validator(Address::ZERO, V0, &CONSENSUS_KEY)
                .unwrap();
            validators.mark_pending(V0).unwrap();
            validators
                .confirm_validator_ready(V0, &registration)
                .unwrap();
            validators
                .activate_validator_via_boundary_for_test(V0)
                .unwrap();
            outbe_oracle::api::register_pair(handle, outbe_oracle::api::DAY_TYPE_PAIR).unwrap();
        });
        storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::ForkProfile);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::new(156, 100, CHAIN_ID, Address::ZERO, Vec::new()),
                handle,
            );
            outbe_metadosis::commands::install_fork_profile(&ctx, &install).unwrap();
        });
    }

    fn run(f: impl FnOnce(&BlockRuntimeContext)) {
        let mut storage = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS_HASH);
        storage.set_block_number(156);
        install_ocomp_profile(&mut storage);
        storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CertifiedFinality);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::new(156, 100, CHAIN_ID, Address::ZERO, Vec::new()),
                handle,
            );
            // Fee-only fixtures bypass CPA; supply the canonical day CPA binds.
            ctx.storage
                .contract::<Rewards>()
                .pending_reward_day
                .write(&FB, 19700101)
                .unwrap();
            f(&ctx);
        });
    }

    fn fund(ctx: &BlockRuntimeContext, amount: U256) {
        ctx.storage
            .increase_balance(REWARDS_ADDRESS, amount)
            .unwrap();
    }

    /// Full k=0 attendance pays exactly the pool; REWARDS is fully drained;
    /// parity holds with zero residue.
    #[test]
    fn full_attendance_pays_exactly_pool_no_residue() {
        run(|ctx| {
            let committee = 4u64;
            let pending = U256::from(committee) * U256::from(1_000u64); // divisible by N
            fund(ctx, pending);
            escrow_block_fee(
                ctx,
                10,
                FB,
                pending,
                4,
                0,
                0,
                0,
                B256::ZERO,
                &[V0, V1, V2, V3],
            )
            .unwrap();

            let (distributed, residue) = settle_window(ctx, FB, committee).unwrap();
            assert_eq!(distributed, pending);
            assert_eq!(residue, U256::ZERO);
            for v in [V0, V1, V2, V3] {
                assert_eq!(
                    ctx.storage.balance(v).unwrap(),
                    pending / U256::from(committee)
                );
            }
            assert_eq!(ctx.storage.balance(REWARDS_ADDRESS).unwrap(), U256::ZERO);
        });
    }

    /// settling a window frees the nested
    /// `participation_counted_for_block[fb_hash]` guard for every credited voter,
    /// so it does not grow unbounded across finalized blocks.
    #[test]
    fn settle_window_clears_participation_guard() {
        run(|ctx| {
            let committee = 4u64;
            let pending = U256::from(committee) * U256::from(1_000u64);
            fund(ctx, pending);
            let rewards = ctx.storage.contract::<Rewards>();
            // Simulate the participation count `on_finalized_metadata` records.
            let guard = rewards.participation_counted_for_block.get_nested(&FB);
            for v in [V0, V1, V2, V3] {
                guard.write(&v, true).unwrap();
            }
            escrow_block_fee(
                ctx,
                10,
                FB,
                pending,
                4,
                0,
                0,
                0,
                B256::ZERO,
                &[V0, V1, V2, V3],
            )
            .unwrap();

            settle_window(ctx, FB, committee).unwrap();

            let guard = rewards.participation_counted_for_block.get_nested(&FB);
            for v in [V0, V1, V2, V3] {
                assert!(
                    !guard.read(&v).unwrap(),
                    "participation guard for {v} must be freed at settlement"
                );
            }
        });
    }

    /// Excluding a voter does NOT raise anyone else's payout (fixed denominator);
    /// the absent share becomes burned residue.
    #[test]
    fn fixed_denominator_no_redistribution() {
        run(|ctx| {
            let committee = 4u64;
            let pending = U256::from(committee) * U256::from(1_000u64);
            fund(ctx, pending);
            // Only 3 of 4 voters credited (one excluded).
            escrow_block_fee(ctx, 10, FB, pending, 4, 0, 0, 0, B256::ZERO, &[V0, V1, V2]).unwrap();

            let (distributed, residue) = settle_window(ctx, FB, committee).unwrap();
            let each = pending / U256::from(committee); // unchanged by exclusion
            assert_eq!(ctx.storage.balance(V0).unwrap(), each);
            assert_eq!(ctx.storage.balance(V1).unwrap(), each);
            assert_eq!(ctx.storage.balance(V2).unwrap(), each);
            assert_eq!(ctx.storage.balance(V3).unwrap(), U256::ZERO);
            assert_eq!(distributed, each * U256::from(3u64));
            assert_eq!(
                residue, each,
                "excluded voter's share is residue, not redistributed"
            );
            assert_eq!(distributed + residue, pending, "parity");
        });
    }

    #[test]
    fn ocomp_late_settlement_residue_waits_for_daily_limit_formation() {
        let mut storage = HashMapStorageProvider::new_with_chain_identity(CHAIN_ID, GENESIS_HASH);
        storage.set_block_number(156);
        install_ocomp_profile(&mut storage);
        let wwd = WorldwideDay::new(20_260_728);
        let timestamp = wwd.start_timestamp();
        let expected_residue = U256::from(1_000);
        storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CertifiedFinality);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::new(156, timestamp, CHAIN_ID, Address::ZERO, Vec::new()),
                handle,
            );
            let pending = U256::from(4_000);
            fund(&ctx, pending);
            escrow_block_fee(
                &ctx,
                153,
                FB,
                pending,
                4,
                0,
                0,
                0,
                B256::ZERO,
                &[V0, V1, V2],
            )
            .unwrap();

            let (distributed, residue) = settle_window(&ctx, FB, 4).unwrap();
            assert_eq!(distributed, U256::from(3_000));
            assert_eq!(residue, expected_residue);
            assert!(
                outbe_metadosis::api::day_limit_formation_receipt(ctx.storage.clone(), wwd,)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                PromisLimitContract::new(ctx.storage.clone())
                    .get_total_unallocated()
                    .unwrap(),
                expected_residue
            );
        });

        storage.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        storage.enter(|handle| {
            let ctx = BlockRuntimeContext::new(
                BlockContext::new(156, timestamp, CHAIN_ID, Address::ZERO, Vec::new()),
                handle,
            );
            let daily_base = U256::from(10_000);
            outbe_emissionlimit::block::dispatch_terminal_remainder_at(&ctx, daily_base, timestamp)
                .unwrap();

            let outbe_metadosis::DayLimitFormationReceipt::Formed(formation) =
                outbe_metadosis::api::day_limit_formation_receipt(ctx.storage.clone(), wwd)
                    .unwrap()
                    .unwrap();
            assert_eq!(formation.base_limit, daily_base);
            // Formation forms the day against its own emission and leaves the accumulator alone.
            assert_eq!(formation.carry_over_taken, U256::ZERO);
            assert_eq!(
                outbe_metadosis::api::worldwide_day(ctx.storage.clone(), wwd)
                    .unwrap()
                    .unwrap()
                    .metadosis_limit_amount,
                daily_base
            );
            assert_eq!(
                PromisLimitContract::new(ctx.storage.clone())
                    .get_total_unallocated()
                    .unwrap(),
                expected_residue,
                "the residue stays in the accumulator for whichever day draws on it"
            );
        });
    }

    /// A voter first seen at k=K (weight 0) earns nothing; its share burns.
    #[test]
    fn cliff_voter_at_k_equals_k_earns_zero() {
        run(|ctx| {
            let committee = 4u64;
            let pending = U256::from(committee) * U256::from(1_000u64);
            fund(ctx, pending);
            escrow_block_fee(ctx, 10, FB, pending, 4, 0, 0, 0, B256::ZERO, &[V0]).unwrap(); // base at k=0
            record_late_credit(ctx, FB, V1, 3).unwrap(); // k = K = 3, weight 0

            let (distributed, residue) = settle_window(ctx, FB, committee).unwrap();
            let each = pending / U256::from(committee);
            assert_eq!(ctx.storage.balance(V0).unwrap(), each);
            assert_eq!(ctx.storage.balance(V1).unwrap(), U256::ZERO, "k=K weight 0");
            assert_eq!(distributed, each);
            assert_eq!(distributed + residue, pending);
        });
    }

    /// A base voter (k=0) cannot be worsened by a later k>=1 re-inclusion.
    #[test]
    fn base_voter_k0_not_worsened_by_later_inclusion() {
        run(|ctx| {
            escrow_block_fee(
                ctx,
                10,
                FB,
                U256::from(4_000u64),
                4,
                0,
                0,
                0,
                B256::ZERO,
                &[V0],
            )
            .unwrap();
            record_late_credit(ctx, FB, V0, 2).unwrap(); // attempt to push to k=2
            let rewards = ctx.storage.contract::<Rewards>();
            // Stored k+1 stays 1 (k=0).
            assert_eq!(
                rewards
                    .late_voter_k_plus1
                    .get_nested(&FB)
                    .read(&V0)
                    .unwrap(),
                1
            );
            assert_eq!(
                rewards.late_voter_count.read(&FB).unwrap(),
                1,
                "no re-append"
            );
        });
    }

    /// Duplicate credit at a smaller k improves the distance (no re-append); at a
    /// larger k it is a no-op.
    #[test]
    fn smallest_k_dedup() {
        run(|ctx| {
            record_late_credit(ctx, FB, V1, 2).unwrap();
            record_late_credit(ctx, FB, V1, 1).unwrap(); // improve to k=1
            record_late_credit(ctx, FB, V1, 3).unwrap(); // no-op (larger)
            let rewards = ctx.storage.contract::<Rewards>();
            assert_eq!(
                rewards
                    .late_voter_k_plus1
                    .get_nested(&FB)
                    .read(&V1)
                    .unwrap(),
                2,
                "k+1 == 2 i.e. smallest k = 1"
            );
            assert_eq!(rewards.late_voter_count.read(&FB).unwrap(), 1);
        });
    }

    /// Settle is idempotent: a second settle pays nobody and changes nothing.
    #[test]
    fn settle_is_idempotent() {
        run(|ctx| {
            let committee = 4u64;
            let pending = U256::from(4_000u64);
            fund(ctx, pending);
            escrow_block_fee(
                ctx,
                10,
                FB,
                pending,
                4,
                0,
                0,
                0,
                B256::ZERO,
                &[V0, V1, V2, V3],
            )
            .unwrap();
            let (d1, _) = settle_window(ctx, FB, committee).unwrap();
            let bal_after_first = ctx.storage.balance(V0).unwrap();
            let (d2, r2) = settle_window(ctx, FB, committee).unwrap();
            assert_eq!(d2, U256::ZERO);
            assert_eq!(r2, U256::ZERO);
            assert_eq!(ctx.storage.balance(V0).unwrap(), bal_after_first);
            assert_eq!(d1, pending);
        });
    }

    /// Denominator is `committee_size * w_max`.
    #[test]
    fn denominator_matches_spec() {
        assert_eq!(fixed_denominator(7), U256::from(7u64) * LATE_FINALIZE_W_MAX);
    }

    /// `settle_matured` settles block `N` exactly at `N+K`, looked up by number,
    /// and is a no-op before maturity and after the one settle.
    #[test]
    fn settle_matured_settles_target_at_n_plus_k() {
        run(|ctx| {
            let pending = U256::from(4_000u64);
            fund(ctx, pending);
            // Escrow block N=10 (committee 4, all 4 base voters at k=0).
            escrow_block_fee(
                ctx,
                10,
                FB,
                pending,
                4,
                0,
                0,
                0,
                B256::ZERO,
                &[V0, V1, V2, V3],
            )
            .unwrap();

            // Before maturity: block 12 would settle number 9 - nothing escrowed.
            assert_eq!(
                settle_matured(ctx, 12, 3).unwrap(),
                (U256::ZERO, U256::ZERO)
            );

            // At N+K = 13: settles block 10's escrow.
            let (distributed, residue) = settle_matured(ctx, 13, 3).unwrap();
            assert_eq!(distributed, pending);
            assert_eq!(residue, U256::ZERO);
            assert!(ctx
                .storage
                .contract::<Rewards>()
                .fee_settled
                .read(&FB)
                .unwrap());

            // Idempotent.
            assert_eq!(
                settle_matured(ctx, 13, 3).unwrap(),
                (U256::ZERO, U256::ZERO)
            );
        });
    }

    /// after settle, all per-window state is freed (no state
    /// bloat); only the `fee_settled` tombstone is retained.
    #[test]
    fn settle_frees_window_state() {
        run(|ctx| {
            let pending = U256::from(4_000u64);
            fund(ctx, pending);
            // Escrow block 10 (committee 4): V0/V1/V2 base at k=0, V3 late at k=1.
            // Non-zero view/parent_view so freeing them at settle is observable.
            escrow_block_fee(ctx, 10, FB, pending, 4, 0, 9, 8, B256::ZERO, &[V0, V1, V2]).unwrap();
            record_late_credit(ctx, FB, V3, 1).unwrap();
            assert_eq!(
                ctx.storage
                    .contract::<Rewards>()
                    .late_voter_count
                    .read(&FB)
                    .unwrap(),
                4
            );

            // Settle the matured window at N+K = 13.
            let (distributed, _residue) = settle_matured(ctx, 13, 3).unwrap();
            assert_eq!(distributed, pending); // all four paid (w(0)=w(1)=w_max)

            let rewards = ctx.storage.contract::<Rewards>();
            // Tombstone retained (double-settle / re-escrow guard).
            assert!(rewards.fee_settled.read(&FB).unwrap());
            // All hash-keyed + number-keyed per-window state is freed.
            assert_eq!(rewards.pending_fees.read(&FB).unwrap(), U256::ZERO);
            assert_eq!(rewards.late_voter_count.read(&FB).unwrap(), 0);
            assert_eq!(rewards.pending_fb_hash_at.read(&10).unwrap(), B256::ZERO);
            assert_eq!(rewards.pending_committee_size_at.read(&10).unwrap(), 0);
            assert_eq!(rewards.pending_epoch_at.read(&10).unwrap(), 0);
            assert_eq!(rewards.pending_view_at.read(&10).unwrap(), 0);
            assert_eq!(rewards.pending_parent_view_at.read(&10).unwrap(), 0);
            assert_eq!(
                rewards.pending_committee_set_hash_at.read(&10).unwrap(),
                B256::ZERO
            );
            let kmap = rewards.late_voter_k_plus1.get_nested(&FB);
            let at = rewards.late_voter_at.get_nested(&FB);
            for (idx, v) in [V0, V1, V2, V3].into_iter().enumerate() {
                assert_eq!(kmap.read(&v).unwrap(), 0, "k+1 freed for voter");
                assert_eq!(
                    at.read(&(idx as u32)).unwrap(),
                    Address::ZERO,
                    "voter slot freed"
                );
            }

            // Second settle is a pure no-op (number lookup zeroed + tombstone).
            assert_eq!(
                settle_matured(ctx, 13, 3).unwrap(),
                (U256::ZERO, U256::ZERO)
            );
        });
    }
}
