//! NOD price-qualifier block hook.
//!
//! Mirrors the Cosmos reference (`x/nod/abci.go::EndBlocker` +
//! `x/nod/keeper/qualification.go::QualifyBucketsByOracleRate`): every
//! block, read each reference currency's current COEN rate from the oracle and
//! promote any unqualified bucket whose `floor_price_minor < rate`. The
//! comparison is strict - a bucket priced exactly at the rate stays
//! unqualified until the rate moves strictly above its floor.
//! Qualification is a monotonic latch - once a bucket is qualified it stays
//! that way, so `mine_gratis` only has to read the cached `is_qualified` bit.
//!
//! Implementation (PancakeSwap-Liquidity-Book bin index):
//! - `floor_price_minor` is mapped to a 24-bit `bin_id` on a log-spaced
//!   ladder (`BIN_STEP_BP = 25` => 0.25% per bin) via `state::price_to_bin`.
//! - Unqualified buckets are stored in `unqualified_bin_count` /
//!   `unqualified_bin_buckets`, and a 3-level radix-256 bitmap trie
//!   (`bin_tree_root`/`bin_tree_mid`/`bin_tree_leaf`) marks non-empty bins.
//! - Each block: walk set bins in ascending `bin_id` order via
//!   `bin_tree::find_first_left_inclusive`. Bins strictly below `r_bin` hold
//!   only floors `< rate` (any floor equal to the rate maps into `r_bin`), so
//!   they drain wholesale; the tail bin (`bin_id == r_bin`) checks each
//!   bucket's exact `floor_price_minor < rate` so a coarse bin neither
//!   qualifies a bucket above the rate nor one priced exactly at it.
//!
//! Multi-currency: a floor is only comparable to the rate of its own
//! `reference_currency`, so every bin column is namespaced by ISO code and
//! each reference currency walks an independent trie. The block reads the
//! oracle's whole reference-currency registry in order, prices each one, and
//! shares a single `MAX_BUCKET_QUALIFICATIONS_PER_BLOCK` budget across them;
//! each currency resumes from its own per-bin cursor next block. A currency
//! whose COEN pair is unregistered, unpriced or stale is skipped for the block
//! rather than halting it. Qualification is a one-way latch, so the rate that
//! arms a bucket's call clock must be a live one: the read enforces the same
//! `FX_RATE_MAX_AGE_SECONDS` bound Gem and Intex qualify under.

use alloy_primitives::U256;
use outbe_compressed_entities::{
    ExecutionScope, ParentBodySource, ParentBodySourceRef, WwdEntityId,
};
use outbe_oracle::api::{fresh_coen_rate_for_opt, get_all_reference_currencies};
use outbe_primitives::{
    block::{BlockLifecycle, BlockRuntimeContext},
    error::Result,
    math::{constants::MAX_BIN_ID, tree_math},
};

use crate::{
    api, constants::MAX_BUCKET_QUALIFICATIONS_PER_BLOCK, schema::NodContract, state::CurrencyBins,
};

pub struct NodLifecycle;

/// Explicit body authorities required by receipt-visible Nod qualification.
pub struct NodLifecycleContext<'a, 'storage> {
    pub runtime: BlockRuntimeContext<'storage>,
    pub scope: &'a ExecutionScope,
    parent: ParentBodySourceRef<'a>,
}

impl<'a, 'storage> NodLifecycleContext<'a, 'storage> {
    #[must_use]
    pub fn new(
        runtime: BlockRuntimeContext<'storage>,
        scope: &'a ExecutionScope,
        parent: &'a dyn ParentBodySource,
    ) -> Self {
        Self {
            runtime,
            scope,
            parent: ParentBodySourceRef::new(parent),
        }
    }
}

impl BlockLifecycle for NodLifecycle {
    type Context<'a, 'storage> = NodLifecycleContext<'a, 'storage>;
    type EndBlockResult = ();

    fn begin_block(ctx: &Self::Context<'_, '_>) -> Result<()> {
        qualify_nods(&ctx.runtime, ctx.scope, &ctx.parent)
    }

    fn end_block(_ctx: &Self::Context<'_, '_>) -> Result<Self::EndBlockResult> {
        Ok(())
    }
}

/// Qualifies Nod buckets using the same block scope and parent source as transactions.
///
/// Reads every reference currency the oracle knows about and qualifies each
/// one's buckets against its own COEN rate. An uninitialized registry does no
/// work. A currency whose COEN pair is unregistered, carries no published rate
/// or carries one older than `FX_RATE_MAX_AGE_SECONDS` is skipped for this
/// block rather than halting it - the registry lists currencies independently
/// of whether a pair has been priced yet, and a stale rate must not arm a
/// latch that never reopens.
pub fn qualify_nods(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<()> {
    let mut budget = MAX_BUCKET_QUALIFICATIONS_PER_BLOCK;
    for iso_code in get_all_reference_currencies(ctx)? {
        if budget == 0 {
            break;
        }
        let Some(rate) = fresh_coen_rate_for_opt(ctx.storage.clone(), iso_code)? else {
            continue;
        };
        let inspected = qualify_buckets_with_rate(ctx, scope, parent, iso_code, rate, budget)?;
        budget = budget.saturating_sub(inspected);
    }
    Ok(())
}

/// Qualifies one reference currency's buckets, inspecting at most `budget`
/// bucket bodies. Returns how many it inspected so the caller can share one
/// per-block budget across currencies.
///
/// Entry point used by the block executor and behavioral tests.
pub fn qualify_buckets_with_rate(
    ctx: &BlockRuntimeContext,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    iso_code: u16,
    rate: U256,
    budget: u32,
) -> Result<u32> {
    let r_bin = NodContract::price_to_bin(rate)?;
    let mut nod = NodContract::new(ctx.storage.clone());
    let mut bin_cursor = 0_u32;
    let mut inspected = 0_u32;
    loop {
        if inspected == budget {
            break;
        }
        let next = match tree_math::find_first_left_inclusive(
            &CurrencyBins(&nod, iso_code),
            bin_cursor,
        )? {
            Some(bin) if bin <= r_bin => bin,
            _ => break,
        };
        let scoped = NodContract::scoped(iso_code, next);
        let strict = next < r_bin;
        let mut count = nod.unqualified_bin_count.read(&scoped)?;
        if count == 0 {
            return Err(
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Nod bin tree references empty bin {iso_code}:{next}"
                )),
            );
        }
        let mut index = nod.unqualified_bin_scan_cursor.read(&scoped)?;
        if index >= count {
            index = 0;
        }
        while index < count && inspected < budget {
            let key = NodContract::bin_index_key(iso_code, next, index);
            let bucket_key = nod.unqualified_bin_buckets.read(&key)?;
            if bucket_key.is_zero() {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Nod unqualified-bin entry {iso_code}:{next}:{index} has an empty bucket key"
                    )),
                );
            }
            let worldwide_day = nod.bucket_worldwide_day.read(&bucket_key)?;
            let bucket_id = WwdEntityId::from_day_and_digest(worldwide_day, bucket_key.0);
            let loaded =
                api::load_bucket(&ctx.storage, scope, parent, bucket_id)?.ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Nod unqualified-bin entry {iso_code}:{next}:{index} references missing bucket {bucket_id}"
                ))
                })?;
            let bucket = loaded.body();
            if bucket.is_qualified
                || bucket.reference_currency != iso_code
                || NodContract::price_to_bin(bucket.floor_price_minor)? != next
            {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Nod unqualified-bin entry {iso_code}:{next}:{index} mismatches bucket {bucket_key}"
                    )),
                );
            }
            if !strict && bucket.floor_price_minor >= rate {
                index += 1;
                inspected += 1;
                continue;
            }
            nod.qualify_bucket_loaded(scope, loaded)?;
            let last = count.checked_sub(1).ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Nod bin {iso_code}:{next} count underflow"
                ))
            })?;
            if index != last {
                let replacement = nod
                    .unqualified_bin_buckets
                    .read(&NodContract::bin_index_key(iso_code, next, last))?;
                if replacement.is_zero() {
                    return Err(
                        outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                            "Nod unqualified-bin entry {iso_code}:{next}:{last} has an empty bucket key"
                        )),
                    );
                }
                nod.unqualified_bin_buckets.write(&key, replacement)?;
            }
            nod.unqualified_bin_buckets.write(
                &NodContract::bin_index_key(iso_code, next, last),
                alloy_primitives::B256::ZERO,
            )?;
            count = last;
            inspected += 1;
        }

        nod.unqualified_bin_count.write(&scoped, count)?;
        if count == 0 {
            nod.unqualified_bin_scan_cursor.write(&scoped, 0)?;
            tree_math::remove(&CurrencyBins(&nod, iso_code), next)?;
        } else if index >= count {
            nod.unqualified_bin_scan_cursor.write(&scoped, 0)?;
        } else {
            nod.unqualified_bin_scan_cursor.write(&scoped, index)?;
            break;
        }

        bin_cursor = match next.checked_add(1) {
            Some(next) if next <= MAX_BIN_ID => next,
            _ => break,
        };
    }
    Ok(inspected)
}
