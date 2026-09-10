//! Marshal-backed [`AncestryReader`] adapter.
//!
//! `dkg_manager` (the consumer) declares the [`AncestryReader`] interface it
//! needs to walk a certified ancestry chain when resolving the DKG boundary;
//! this module supplies the production adapter that satisfies it. Keeping the
//! adapter here - beside the propose/verify call sites that own the marshal
//! mailbox, block cache, readiness gate, and runtime clock - instead of inline
//! in `handler.rs` keeps the 2000-line handler free of block-walk/timeout
//! policy and gives the adapter its own test surface.
//!
//! The seam has two adapters: this `MarshalAncestryReader` (production) and the
//! `TestAncestryReader` fake in `crate::test_fixtures` (consumer tests in
//! `dkg_manager::tests::boundary`). Callers cross the seam through
//! [`marshal_ancestry_reader`], which returns an opaque `impl AncestryReader`.

use std::time::Duration;

use alloy_primitives::B256;
use commonware_consensus::types::{Height, Round};

use crate::ancestry_readiness::AncestryReadiness;
use crate::digest::Digest;
use crate::dkg_manager::{AncestryReader, BlockLookupFuture};
use crate::finalization::block_cache::BlockCache;
use crate::marshal_types::MarshalMailbox;

/// Production [`AncestryReader`]: block cache first, marshal on miss, bounded by
/// the runtime clock.
///
/// `marshal` is an `Option` purely as a testability affordance - mirroring
/// `finalization::actor`'s `Option<MarshalMailbox>`. Production always wires it
/// `Some(..)` via [`marshal_ancestry_reader`]; the `None` arm lets cache-hit /
/// `is_ready` unit tests construct the adapter without standing up a marshal
/// actor (whose `Mailbox::new` is `pub(crate)` upstream and so cannot be built
/// from a bare channel here). On a cache miss with `marshal: None` the lookup
/// resolves deterministically to `None` (unresolvable), never blocking.
struct MarshalAncestryReader<C: commonware_runtime::Clock> {
    marshal: Option<MarshalMailbox>,
    block_cache: BlockCache,
    readiness: AncestryReadiness,
    round: Option<Round>,
    timeout: Duration,
    // Owned runtime clock used to bound the marshal lookups. Cloned cheaply from
    // the spawn's context so the trait methods (which carry no context) can apply
    // a runtime-agnostic timeout without pulling in the tokio reactor.
    clock: C,
}

impl<C: commonware_runtime::Clock> AncestryReader for MarshalAncestryReader<C> {
    fn get_block_by_height(&self, height: u64) -> BlockLookupFuture<'_> {
        let cached = self.block_cache.get_by_number(height);
        if cached.is_some() {
            return Box::pin(async move { cached });
        }
        let Some(marshal) = self.marshal.clone() else {
            // No marshal mailbox (test / degraded wiring): a cache miss is
            // unresolvable. Resolve deterministically to `None` rather than block.
            return Box::pin(async move { None });
        };
        // `Clock::sleep` returns an owned `'static` future, so we build it from the
        // borrowed clock here and move it into the lookup future - no clone of the
        // (non-`Clone`) runtime context needed.
        let sleep = self.clock.sleep(self.timeout);
        Box::pin(async move {
            // `marshal.get_block(..)` borrows `marshal`, so it is not `'static` and
            // cannot use `Clock::timeout`. Inline the same biased race the default
            // `Clock::timeout` uses: prefer the resolved block over the timeout.
            let lookup = marshal.get_block(Height::new(height));
            let mut lookup = std::pin::pin!(lookup);
            let mut sleep = std::pin::pin!(sleep);
            commonware_macros::select! {
                block = &mut lookup => block,
                _ = &mut sleep => None,
            }
        })
    }

    fn get_block_by_hash(&self, hash: B256) -> BlockLookupFuture<'_> {
        let digest = Digest(hash);
        let cached = self.block_cache.get(&digest);
        if cached.is_some() {
            return Box::pin(async move { cached });
        }
        let Some(marshal) = self.marshal.clone() else {
            // No marshal mailbox (test / degraded wiring): a cache miss is
            // unresolvable. Resolve deterministically to `None` rather than block.
            return Box::pin(async move { None });
        };
        let round = self.round;
        // Owned `'static` sleep future built from the borrowed clock (no clone).
        let sleep = self.clock.sleep(self.timeout);
        Box::pin(async move {
            let fallback = match round {
                Some(round) => {
                    commonware_consensus::marshal::core::DigestFallback::FetchByRound { round }
                }
                None => commonware_consensus::marshal::core::DigestFallback::Wait,
            };
            let block_future = marshal.subscribe_by_digest(digest, fallback);
            // Biased race, preferring the resolved block over the timeout
            // (the `block_future` borrows `marshal`, so it is not `'static`).
            let mut block_future = std::pin::pin!(block_future);
            let mut sleep = std::pin::pin!(sleep);
            commonware_macros::select! {
                result = &mut block_future => result.ok(),
                _ = &mut sleep => None,
            }
        })
    }

    fn is_ready(&self) -> bool {
        self.readiness.is_ready()
    }
}

/// Build the production [`AncestryReader`] adapter backed by the marshal mailbox.
///
/// The returned reader is short-lived - one propose/verify boundary resolution.
/// The concrete type is hidden behind `impl AncestryReader`, so callers (and
/// `resolve_boundary`) learn one function instead of a six-field constructor.
pub(crate) fn marshal_ancestry_reader<C: commonware_runtime::Clock>(
    marshal: MarshalMailbox,
    block_cache: BlockCache,
    readiness: AncestryReadiness,
    round: Option<Round>,
    timeout: Duration,
    clock: C,
) -> impl AncestryReader {
    MarshalAncestryReader {
        marshal: Some(marshal),
        block_cache,
        readiness,
        round,
        timeout,
        clock,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::ConsensusBlock;
    use commonware_runtime::Runner as _;

    /// Build a `marshal: None` adapter over a preloaded cache + readiness gate.
    /// Exercises the fast paths (cache hit / degraded miss / `is_ready`) without
    /// standing up a marshal actor. `clock` is unused on these paths.
    fn reader_without_marshal<C: commonware_runtime::Clock>(
        cache: BlockCache,
        readiness: AncestryReadiness,
        clock: C,
    ) -> MarshalAncestryReader<C> {
        MarshalAncestryReader {
            marshal: None,
            block_cache: cache,
            readiness,
            round: None,
            timeout: Duration::from_secs(1),
            clock,
        }
    }

    fn cache_with(blocks: &[ConsensusBlock]) -> BlockCache {
        let cache = BlockCache::new();
        for block in blocks {
            cache.insert_bounded(Digest(block.block_hash()), block.clone());
        }
        cache
    }

    #[test]
    fn cache_hit_by_height_resolves_without_marshal() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let block = crate::test_fixtures::block_with_number(5);
            let cache = cache_with(std::slice::from_ref(&block));
            let reader = reader_without_marshal(cache, AncestryReadiness::new(1, 0), context);

            let found = reader.get_block_by_height(5).await;
            assert_eq!(found.map(|b| b.number()), Some(5));
        });
    }

    #[test]
    fn cache_hit_by_hash_resolves_without_marshal() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let block = crate::test_fixtures::block_with_number(7);
            let hash = block.block_hash();
            let cache = cache_with(std::slice::from_ref(&block));
            let reader = reader_without_marshal(cache, AncestryReadiness::new(1, 0), context);

            let found = reader.get_block_by_hash(hash).await;
            assert_eq!(found.map(|b| b.block_hash()), Some(hash));
        });
    }

    #[test]
    fn cache_miss_without_marshal_resolves_to_none() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let cache = cache_with(&[]);
            let reader = reader_without_marshal(cache, AncestryReadiness::new(1, 0), context);

            assert!(reader.get_block_by_height(9).await.is_none());
            assert!(reader
                .get_block_by_hash(B256::with_last_byte(0xAB))
                .await
                .is_none());
        });
    }

    #[test]
    fn is_ready_delegates_to_readiness() {
        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let cache = cache_with(&[]);
            let ready =
                reader_without_marshal(cache.clone(), AncestryReadiness::new(1, 0), context);
            assert!(ready.is_ready());
        });

        commonware_runtime::deterministic::Runner::default().start(|context| async move {
            let cache = cache_with(&[]);
            let not_ready = reader_without_marshal(cache, AncestryReadiness::new(0, 1), context);
            assert!(!not_ready.is_ready());
        });
    }
}
