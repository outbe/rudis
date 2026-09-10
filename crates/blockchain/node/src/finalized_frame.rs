//! Production primitives for the single bounded finalized-data reader.

use std::{error::Error, sync::Arc};

use alloy_eips::BlockNumHash;
use alloy_primitives::B256;
use alloy_rlp::{Decodable, Encodable};
use eyre::{bail, Context};
use reth_ethereum::{Block, Receipt};
use reth_provider::{BlockHashReader, BlockReader, ProviderError, ReceiptProvider};

/// Maximum number of finalized heights read during one scheduler turn.
pub const MAX_FINALIZED_FRAMES_PER_TURN: u64 = 100;

/// Inclusive bounded range selected for one finalized-reader turn.
///
/// This type is deliberately independent from ExEx and provider concerns so the
/// scheduling invariant can be tested before production routing is switched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedWalkPlan {
    first: u64,
    last: u64,
    finalized_target: u64,
}

impl FinalizedWalkPlan {
    /// Selects at most [`MAX_FINALIZED_FRAMES_PER_TURN`] heights from the backlog.
    #[must_use]
    pub fn new(next_height: u64, finalized_target: u64) -> Option<Self> {
        if next_height > finalized_target {
            return None;
        }
        let last = next_height
            .saturating_add(MAX_FINALIZED_FRAMES_PER_TURN - 1)
            .min(finalized_target);
        Some(Self {
            first: next_height,
            last,
            finalized_target,
        })
    }

    #[must_use]
    pub const fn first(self) -> u64 {
        self.first
    }

    #[must_use]
    pub const fn last(self) -> u64 {
        self.last
    }

    #[must_use]
    pub const fn height_count(self) -> u64 {
        self.last - self.first + 1
    }

    #[must_use]
    pub const fn has_more(self) -> bool {
        self.last < self.finalized_target
    }

    #[must_use]
    pub const fn next_height(self) -> Option<u64> {
        self.last.checked_add(1)
    }
}

/// Minimal provider boundary owned by the unified finalized reader.
pub trait FinalizedFrameSource {
    type Error: Error + Send + Sync + 'static;

    fn canonical_hash(&self, height: u64) -> Result<Option<B256>, Self::Error>;
    fn block_by_hash(&self, hash: B256) -> Result<Option<Block>, Self::Error>;
    fn receipts_by_hash(&self, hash: B256) -> Result<Option<Vec<Receipt>>, Self::Error>;
}

/// Production adapter from a Reth provider to the exact finalized-frame read boundary.
///
/// Keeping this wrapper explicit prevents unrelated provider reads from becoming part of the
/// shared reader interface during the production cutover.
#[derive(Clone, Debug)]
pub struct RethFinalizedFrameSource<P> {
    provider: P,
}

impl<P> RethFinalizedFrameSource<P> {
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> FinalizedFrameSource for RethFinalizedFrameSource<P>
where
    P: BlockHashReader + BlockReader + ReceiptProvider<Receipt = Receipt>,
{
    type Error = ProviderError;

    fn canonical_hash(&self, height: u64) -> Result<Option<B256>, Self::Error> {
        self.provider.block_hash(height)
    }

    fn block_by_hash(&self, hash: B256) -> Result<Option<Block>, Self::Error> {
        let Some(block) = self.provider.block_by_hash(hash)? else {
            return Ok(None);
        };

        // Outbe's production block uses an OutbeHeader wrapper whose RLP is deliberately
        // byte-for-byte Ethereum-compatible. Normalize at this adapter boundary so callers stay
        // independent of the generic node provider's associated block type.
        let mut encoded = Vec::with_capacity(block.length());
        block.encode(&mut encoded);
        let mut input = encoded.as_slice();
        let block = Block::decode(&mut input).map_err(ProviderError::Rlp)?;
        if !input.is_empty() {
            return Err(ProviderError::Rlp(alloy_rlp::Error::UnexpectedLength));
        }
        Ok(Some(block))
    }

    fn receipts_by_hash(&self, hash: B256) -> Result<Option<Vec<Receipt>>, Self::Error> {
        self.provider.receipts_by_block(hash.into())
    }
}

/// One canonical block and its receipts, loaded once and shared by every consumer.
#[derive(Clone, Debug)]
pub struct FinalizedFrame {
    identity: BlockNumHash,
    parent_hash: B256,
    state_root: B256,
    block: Arc<Block>,
    receipts: Arc<[Receipt]>,
}

impl FinalizedFrame {
    #[cfg(test)]
    pub(crate) fn for_test(
        identity: BlockNumHash,
        parent_hash: B256,
        state_root: B256,
        block: Block,
        receipts: Vec<Receipt>,
    ) -> Self {
        Self {
            identity,
            parent_hash,
            state_root,
            block: Arc::new(block),
            receipts: receipts.into(),
        }
    }

    #[must_use]
    pub const fn identity(&self) -> BlockNumHash {
        self.identity
    }

    #[must_use]
    pub const fn parent_hash(&self) -> B256 {
        self.parent_hash
    }

    #[must_use]
    pub const fn state_root(&self) -> B256 {
        self.state_root
    }

    #[must_use]
    pub fn block(&self) -> &Block {
        &self.block
    }

    #[must_use]
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }
}

/// Frames loaded during one bounded scheduler turn.
#[derive(Clone, Debug)]
pub struct FinalizedFrameBatch {
    plan: FinalizedWalkPlan,
    frames: Vec<FinalizedFrame>,
}

impl FinalizedFrameBatch {
    #[must_use]
    pub fn frames(&self) -> &[FinalizedFrame] {
        &self.frames
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.plan.has_more()
    }

    #[must_use]
    pub const fn next_height(&self) -> Option<u64> {
        self.plan.next_height()
    }
}

/// Loads one bounded turn without routing it into production consumers yet.
pub fn read_bounded_finalized_frames<S>(
    source: &S,
    next_height: u64,
    finalized_target: BlockNumHash,
) -> eyre::Result<Option<FinalizedFrameBatch>>
where
    S: FinalizedFrameSource,
{
    let Some(plan) = FinalizedWalkPlan::new(next_height, finalized_target.number) else {
        return Ok(None);
    };
    let mut frames = Vec::new();
    for height in plan.first()..=plan.last() {
        let canonical_hash = source
            .canonical_hash(height)
            .wrap_err_with(|| format!("load canonical hash for finalized block {height}"))?
            .ok_or_else(|| eyre::eyre!("canonical finalized block {height} is unavailable"))?;
        let block = source
            .block_by_hash(canonical_hash)
            .wrap_err_with(|| {
                format!("load canonical finalized block {height} ({canonical_hash})")
            })?
            .ok_or_else(|| {
                eyre::eyre!(
                    "canonical finalized block {height} ({canonical_hash}) is unavailable by hash"
                )
            })?;
        if block.header.number != height {
            bail!(
                "provider returned finalized block {} while height {height} was requested",
                block.header.number
            );
        }
        let block_hash = block.header.hash_slow();
        if block_hash != canonical_hash {
            bail!(
                "finalized block at height {height} recomputed to {block_hash}, expected {canonical_hash}"
            );
        }
        if height == finalized_target.number && block_hash != finalized_target.hash {
            bail!(
                "canonical block hash {block_hash} conflicts with finalized hash {} at height {height}",
                finalized_target.hash
            );
        }
        let receipts = source
            .receipts_by_hash(canonical_hash)
            .wrap_err_with(|| format!("load receipts for finalized block {height}"))?
            .ok_or_else(|| eyre::eyre!("receipts for finalized block {height} are unavailable"))?;
        if block.body.transactions.len() != receipts.len() {
            bail!(
                "finalized block {height} has {} transactions but {} receipts",
                block.body.transactions.len(),
                receipts.len()
            );
        }
        frames.push(FinalizedFrame {
            identity: BlockNumHash::new(height, block_hash),
            parent_hash: block.header.parent_hash,
            state_root: block.header.state_root,
            block: Arc::new(block),
            receipts: Arc::from(receipts),
        });
    }
    Ok(Some(FinalizedFrameBatch { plan, frames }))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        convert::Infallible,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use super::{
        read_bounded_finalized_frames, FinalizedFrameSource, FinalizedWalkPlan,
        RethFinalizedFrameSource, MAX_FINALIZED_FRAMES_PER_TURN,
    };
    use alloy_consensus::{Header, Sealable};
    use alloy_eips::BlockNumHash;
    use alloy_primitives::B256;
    use reth_ethereum::{Block, Receipt};
    use reth_provider::test_utils::MockEthProvider;

    #[derive(Clone, Default)]
    struct ReadCounts {
        hashes: Arc<AtomicUsize>,
        blocks: Arc<AtomicUsize>,
        receipts: Arc<AtomicUsize>,
    }

    struct CountingSource {
        hashes: HashMap<u64, B256>,
        blocks: HashMap<B256, Block>,
        counts: ReadCounts,
    }

    impl FinalizedFrameSource for CountingSource {
        type Error = Infallible;

        fn canonical_hash(&self, height: u64) -> Result<Option<B256>, Self::Error> {
            self.counts.hashes.fetch_add(1, Ordering::Relaxed);
            Ok(self.hashes.get(&height).copied())
        }

        fn block_by_hash(&self, hash: B256) -> Result<Option<Block>, Self::Error> {
            self.counts.blocks.fetch_add(1, Ordering::Relaxed);
            Ok(self.blocks.get(&hash).cloned())
        }

        fn receipts_by_hash(&self, _hash: B256) -> Result<Option<Vec<Receipt>>, Self::Error> {
            self.counts.receipts.fetch_add(1, Ordering::Relaxed);
            Ok(Some(Vec::new()))
        }
    }

    fn counting_source(last_height: u64) -> (CountingSource, ReadCounts) {
        let counts = ReadCounts::default();
        let mut hashes = HashMap::new();
        let mut blocks = HashMap::new();
        let mut parent_hash = B256::ZERO;
        for height in 1..=last_height {
            let block = Block {
                header: Header {
                    number: height,
                    parent_hash,
                    ..Default::default()
                },
                body: Default::default(),
            };
            let hash = block.header.hash_slow();
            hashes.insert(height, hash);
            blocks.insert(hash, block);
            parent_hash = hash;
        }
        (
            CountingSource {
                hashes,
                blocks,
                counts: counts.clone(),
            },
            counts,
        )
    }

    #[test]
    fn finalized_walk_plan_splits_a_101_block_backlog_into_100_then_one() {
        let first = FinalizedWalkPlan::new(1, 101).unwrap();
        assert_eq!(first.first(), 1);
        assert_eq!(first.last(), MAX_FINALIZED_FRAMES_PER_TURN);
        assert_eq!(first.height_count(), MAX_FINALIZED_FRAMES_PER_TURN);
        assert!(first.has_more());

        let second = FinalizedWalkPlan::new(first.next_height().unwrap(), 101).unwrap();
        assert_eq!(second.first(), 101);
        assert_eq!(second.last(), 101);
        assert_eq!(second.height_count(), 1);
        assert!(!second.has_more());
    }

    #[test]
    fn bounded_reader_loads_each_block_and_receipts_once_across_turns() {
        let (source, counts) = counting_source(101);
        let target = BlockNumHash::new(101, source.hashes[&101]);

        let first = read_bounded_finalized_frames(&source, 1, target)
            .unwrap()
            .unwrap();
        assert_eq!(first.frames().len(), 100);
        assert!(first.has_more());
        assert_eq!(counts.blocks.load(Ordering::Relaxed), 100);
        assert_eq!(counts.receipts.load(Ordering::Relaxed), 100);

        let second = read_bounded_finalized_frames(&source, first.next_height().unwrap(), target)
            .unwrap()
            .unwrap();
        assert_eq!(second.frames().len(), 1);
        assert!(!second.has_more());
        assert_eq!(counts.hashes.load(Ordering::Relaxed), 101);
        assert_eq!(counts.blocks.load(Ordering::Relaxed), 101);
        assert_eq!(counts.receipts.load(Ordering::Relaxed), 101);
    }

    #[test]
    fn bounded_reader_rejects_a_conflicting_finalized_target_hash() {
        let (source, _) = counting_source(1);
        let error = read_bounded_finalized_frames(
            &source,
            1,
            BlockNumHash::new(1, B256::repeat_byte(0xEE)),
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts with finalized hash"));
    }

    #[test]
    fn reth_provider_adapter_supplies_the_exact_block_and_receipts() {
        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new();
        let header = Header {
            number: 1,
            ..Default::default()
        };
        let hash = header.hash_slow();
        provider.add_block(hash, Block::new(header, Default::default()));
        provider.add_receipts(1, Vec::new());
        let source = RethFinalizedFrameSource::new(provider);

        let batch = read_bounded_finalized_frames(&source, 1, BlockNumHash::new(1, hash))
            .unwrap()
            .unwrap();

        assert_eq!(batch.frames().len(), 1);
        assert_eq!(batch.frames()[0].identity(), BlockNumHash::new(1, hash));
        assert!(batch.frames()[0].receipts().is_empty());
    }

    #[test]
    fn reth_provider_adapter_normalizes_the_production_outbe_block() {
        let provider = MockEthProvider::<outbe_primitives::OutbePrimitives>::new();
        let header = outbe_primitives::OutbeHeader::new(Header {
            number: 1,
            ..Default::default()
        });
        let hash = header.hash_slow();
        provider.add_block(
            hash,
            outbe_primitives::OutbeBlock::new(header, Default::default()),
        );
        provider.add_receipts(1, Vec::new());
        let source = RethFinalizedFrameSource::new(provider);

        let batch = read_bounded_finalized_frames(&source, 1, BlockNumHash::new(1, hash))
            .unwrap()
            .unwrap();

        assert_eq!(batch.frames().len(), 1);
        assert_eq!(batch.frames()[0].identity(), BlockNumHash::new(1, hash));
        assert_eq!(batch.frames()[0].block().header.number, 1);
        assert!(batch.frames()[0].receipts().is_empty());
    }
}
