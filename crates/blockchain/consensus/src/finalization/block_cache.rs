//! Process-local block cache shared between the proposer (writer) and the
//! finalization actor (evicts on finalize).
//!
//! This is an availability/performance cache, NOT consensus state: a miss is
//! always resolvable via marshal, and its contents never feed a deterministic
//! state transition. It is sealed behind named operations so callers cannot
//! hold the raw lock or reach the inner `BTreeMap` - the lock-poison recovery
//! and the size metric live in one place.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use crate::block::ConsensusBlock;
use crate::digest::Digest;

/// Sliding-window depth for the block cache.
///
/// This process-local availability/performance cache is intentionally
/// independent from exact-parent certificate handoff retention so changes to
/// `PARENT_CERT_KEEP_DEPTH` do not make block-cache retention unbounded or
/// semantically tied to settlement transport.
pub const BLOCK_CACHE_KEEP_DEPTH: u64 = 256;

/// Hard cap on block-cache entries. The cache is keyed by [`Digest`], not
/// height, so a height-only window does not bound count under fork spam at the
/// same height. This cap is the safety floor.
pub const BLOCK_CACHE_MAX_ENTRIES: usize = 1024;

/// Shared, process-local block cache between the proposer (writer) and the
/// finalization actor (evicts on finalize). Cloning shares the same underlying
/// `Arc<Mutex<..>>`; the inner `BTreeMap` is never exposed, so every access goes
/// through one of the named operations below, which centralize lock-poison
/// recovery and the `outbe_block_cache_size` metric.
#[derive(Clone, Default)]
pub struct BlockCache {
    inner: Arc<StdMutex<BTreeMap<Digest, ConsensusBlock>>>,
}

impl BlockCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the inner map, recovering the guard if a previous holder panicked.
    /// The critical sections here are panic-free single map operations, so the
    /// map is always left structurally consistent and recovery is safe.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<Digest, ConsensusBlock>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remove and return the block for `digest` (proposer parent take / finalize
    /// fast-path - the block is consumed once resolved).
    pub fn get_and_remove(&self, digest: &Digest) -> Option<ConsensusBlock> {
        self.lock().remove(digest)
    }

    /// Clone-return the block for `digest` (read-only resolution path).
    pub fn get(&self, digest: &Digest) -> Option<ConsensusBlock> {
        self.lock().get(digest).cloned()
    }

    /// Clone-return the first cached block at `number` (ancestry-by-height; the
    /// cache is digest-keyed, so this is a scan).
    pub fn get_by_number(&self, number: u64) -> Option<ConsensusBlock> {
        self.lock()
            .values()
            .find(|block| block.number() == number)
            .cloned()
    }

    /// Insert `block` keyed by `digest`, pruning to the height window and hard
    /// entry cap, then record the size metric.
    pub fn insert_bounded(&self, digest: Digest, block: ConsensusBlock) {
        let mut cache = self.lock();
        insert_block_cache_bounded(&mut cache, digest, block);
    }

    /// Drop every entry at or below `finalized_number` (finalize eviction), then
    /// record the size metric.
    pub fn evict_at_or_below(&self, finalized_number: u64) {
        let mut cache = self.lock();
        cache.retain(|_, cached_block| cached_block.number() > finalized_number);
        crate::metrics::record_block_cache_size(cache.len());
    }
}

/// Insert `block` keyed by `digest` and prune the cache to enforce height-window
/// and hard-entry-cap invariants. Pure map operation (no lock) so the pruning
/// invariants can be unit-tested directly.
///
/// Bounded by height window so the cache cannot grow during a chain stall, and
/// by hard entry cap so fork spam at a single height (which is keyed by digest,
/// not height) cannot grow the cache.
fn insert_block_cache_bounded(
    cache: &mut BTreeMap<Digest, ConsensusBlock>,
    digest: Digest,
    block: ConsensusBlock,
) {
    let inserted_number = block.number();
    cache.insert(digest, block);

    // Step 1: height window - drop entries below the keep-depth floor.
    if let Some(floor) = inserted_number.checked_sub(BLOCK_CACHE_KEEP_DEPTH) {
        cache.retain(|_, b| b.number() > floor);
    }

    // Step 2: hard entry cap - under fork spam at the same height, the
    // height window cannot bound `len()`. Drop the entry with the
    // lowest `(number, digest)` until `len() <= MAX_ENTRIES`.
    while cache.len() > BLOCK_CACHE_MAX_ENTRIES {
        let victim = cache
            .iter()
            .min_by(|(d1, b1), (d2, b2)| b1.number().cmp(&b2.number()).then(d1.cmp(d2)))
            .map(|(d, _)| *d);
        match victim {
            Some(d) => {
                cache.remove(&d);
            }
            None => break,
        }
    }

    crate::metrics::record_block_cache_size(cache.len());
}

#[cfg(test)]
mod tests {
    use super::{insert_block_cache_bounded, BLOCK_CACHE_KEEP_DEPTH, BLOCK_CACHE_MAX_ENTRIES};
    use crate::block::ConsensusBlock;
    use crate::digest::Digest;
    use alloy_primitives::B256;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::{primitives::SealedBlock, Block};
    use std::collections::BTreeMap;

    /// Build a minimal `ConsensusBlock` with the given height and a salt
    /// stored in `extra_data` so distinct salts produce distinct sealed
    /// hashes (and therefore distinct `Digest`s).
    fn make_block(number: u64, salt: u64) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.number = number;
        block.header.extra_data = salt.to_le_bytes().to_vec().into();
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    fn digest_of(block: &ConsensusBlock) -> Digest {
        block.digest()
    }

    #[test]
    fn insert_block_cache_bounded_height_progression() {
        // Drive 10_000 inserts with monotonically increasing block
        // numbers and distinct digests; the height window must keep
        // `cache.len()` bounded by `BLOCK_CACHE_KEEP_DEPTH`.
        let mut cache: BTreeMap<Digest, ConsensusBlock> = BTreeMap::new();
        for n in 0..10_000_u64 {
            let block = make_block(n, n);
            let digest = digest_of(&block);
            insert_block_cache_bounded(&mut cache, digest, block);
        }
        assert!(
            cache.len() <= BLOCK_CACHE_KEEP_DEPTH as usize,
            "height window failed to bound cache: len={}, keep_depth={}",
            cache.len(),
            BLOCK_CACHE_KEEP_DEPTH
        );
        // All survivors must lie in the keep-depth window above the
        // final inserted number (9999).
        let floor = 9_999 - BLOCK_CACHE_KEEP_DEPTH;
        assert!(
            cache.values().all(|b| b.number() > floor),
            "survivor outside keep-depth window: floor={floor}"
        );
    }

    #[test]
    fn insert_block_cache_bounded_fork_spam() {
        // Drive 10_000 inserts all at the SAME height with distinct
        // digests (fork spam). Height window cannot bound this - the
        // hard entry cap must kick in.
        const SAME_HEIGHT: u64 = BLOCK_CACHE_KEEP_DEPTH + 100;
        let mut cache: BTreeMap<Digest, ConsensusBlock> = BTreeMap::new();
        for salt in 0..10_000_u64 {
            let block = make_block(SAME_HEIGHT, salt);
            let digest = digest_of(&block);
            insert_block_cache_bounded(&mut cache, digest, block);
        }
        assert!(
            cache.len() <= BLOCK_CACHE_MAX_ENTRIES,
            "hard cap failed under fork spam: len={}, max_entries={}",
            cache.len(),
            BLOCK_CACHE_MAX_ENTRIES
        );
    }

    #[test]
    fn insert_block_cache_bounded_below_keep_depth_does_not_drop() {
        // When inserted_number < KEEP_DEPTH the height window is a
        // no-op; verify that small chains under MAX_ENTRIES retain
        // every entry.
        let mut cache: BTreeMap<Digest, ConsensusBlock> = BTreeMap::new();
        for n in 0..16_u64 {
            let block = make_block(n, 0);
            let digest = digest_of(&block);
            insert_block_cache_bounded(&mut cache, digest, block);
        }
        assert_eq!(cache.len(), 16);
    }

    #[test]
    fn insert_block_cache_bounded_emits_size_metric() {
        // Verifies the helper emits `outbe_block_cache_size` on every
        // insert. Uses a thread-local recorder so the assertion is
        // independent of the global recorder used in production.
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let mut cache: BTreeMap<Digest, ConsensusBlock> = BTreeMap::new();
            for n in 0..3_u64 {
                let block = make_block(n, 0);
                let digest = digest_of(&block);
                insert_block_cache_bounded(&mut cache, digest, block);
            }
        });

        let snapshot = snapshotter.snapshot().into_vec();
        let entry = snapshot
            .iter()
            .find(|(key, _, _, _)| key.key().name() == "outbe_block_cache_size")
            .expect("outbe_block_cache_size gauge should be emitted");
        // Final gauge value reflects post-3rd-insert size = 3.
        match &entry.3 {
            DebugValue::Gauge(v) => {
                assert!(
                    (v.into_inner() - 3.0).abs() < f64::EPSILON,
                    "expected gauge=3.0 after 3 inserts, got {v:?}"
                );
            }
            other => panic!("expected gauge value, got {other:?}"),
        }
    }

    #[test]
    fn insert_block_cache_bounded_overlapping_height_and_fork() {
        // Mixed scenario: a moving height plus same-height forks at
        // each step. Must stay within MAX_ENTRIES regardless.
        let mut cache: BTreeMap<Digest, ConsensusBlock> = BTreeMap::new();
        for n in 0..2_000_u64 {
            for fork_salt in 0..3_u64 {
                let block = make_block(n, fork_salt + 1);
                let digest = digest_of(&block);
                insert_block_cache_bounded(&mut cache, digest, block);
            }
        }
        assert!(
            cache.len() <= BLOCK_CACHE_MAX_ENTRIES,
            "mixed height+fork exceeded max: len={}",
            cache.len()
        );
        // Sanity: distinct B256 hashes confirm forks really diverged.
        let unique_hashes: std::collections::HashSet<B256> = cache.keys().map(|d| d.0).collect();
        assert_eq!(unique_hashes.len(), cache.len());
    }
}
