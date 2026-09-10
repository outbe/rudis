//! Fail-closed compressed-tree startup classification and canonical replay.
//!
//! This boundary runs after Marshal exposes durable consensus finality and
//! before the executor/consensus actors participate. It accepts only an exact
//! marker or a contiguous replay whose every root matches historical EVM slot
//! 1. Local candidates are never a restart input.

// Recovery conflicts deliberately retain both complete marker identities in
// the typed error so operators can diagnose the fail-closed startup decision.
#![allow(clippy::result_large_err)]

use std::{collections::BTreeMap, sync::Arc, time::Instant};

use alloy_primitives::B256;
use outbe_compressed_entities::{
    classify_restart, reconstruct_effective_final_mutations, CanonicalBodyEvent,
    CompressedTreeService, DurableFinalizedCheckpoint, ExactParentIdentity, FinalizedMarker,
    PartitionRef, RestartClassification, ACTIVE_COMMITMENT_SCHEME,
};
use thiserror::Error;

/// One durable canonical replay input, normalized in receipt/log order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCeReplayBlock {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub parent_root: B256,
    pub new_root: B256,
    pub events: Vec<CanonicalBodyEvent>,
    pub retirements: Vec<PartitionRef>,
}

/// DB-only canonical history needed before consensus participation.
pub trait CanonicalCeReplaySource: Send + Sync {
    fn durable_checkpoint(
        &self,
        consensus_finalized_height: u64,
    ) -> eyre::Result<Option<DurableFinalizedCheckpoint>>;

    fn replay_block(&self, height: u64) -> eyre::Result<Option<CanonicalCeReplayBlock>>;
}

/// Narrow authenticated-tree seam for behavior tests and production replay.
pub trait StartupCeTree: Send + Sync {
    fn marker(&self) -> eyre::Result<FinalizedMarker>;
    fn discard_speculative_candidates(&self) -> eyre::Result<()>;
    fn apply_replayed(&self, block: &CanonicalCeReplayBlock) -> eyre::Result<FinalizedMarker>;
}

impl StartupCeTree for CompressedTreeService {
    fn marker(&self) -> eyre::Result<FinalizedMarker> {
        self.finalized_marker().map_err(Into::into)
    }

    fn discard_speculative_candidates(&self) -> eyre::Result<()> {
        CompressedTreeService::discard_speculative_candidates(self).map_err(Into::into)
    }

    fn apply_replayed(&self, block: &CanonicalCeReplayBlock) -> eyre::Result<FinalizedMarker> {
        apply_replayed_block(self, block)
    }
}

/// Reconstructs one exact finalized batch from canonical durable receipts and
/// applies it through the normal candidate/marker transaction. This is shared
/// by startup catch-up and the live finalizer when validator execution did not
/// retain speculative state before Reth post-execution validation.
pub(crate) fn apply_replayed_block(
    tree: &CompressedTreeService,
    block: &CanonicalCeReplayBlock,
) -> eyre::Result<FinalizedMarker> {
    let parent = tree.open_parent(ExactParentIdentity {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        block_number: block.number.saturating_sub(1),
        block_hash: block.parent_hash,
        root: block.parent_root,
    })?;

    let mut parent_leaves = BTreeMap::new();
    for event in &block.events {
        if parent_leaves.contains_key(&event.entity) {
            continue;
        }
        let leaf = parent.read_leaf_verified(event.entity, block.parent_root)?;
        parent_leaves.insert(event.entity, leaf);
    }
    let mutations = reconstruct_effective_final_mutations(&block.events, &parent_leaves)?;
    let provisional = parent.prepare_seal(block.number, &mutations, &block.retirements)?;
    if provisional.block_number() != block.number
        || provisional.parent_block_hash() != block.parent_hash
        || provisional.parent_root() != block.parent_root
        || provisional.new_root() != block.new_root
    {
        eyre::bail!(
            "replayed CE root/identity mismatch at {}/{}: expected parent {}/{}, root {}; computed {:?}",
            block.number,
            block.hash,
            block.parent_hash,
            block.parent_root,
            block.new_root,
            provisional
        );
    }
    tree.publish_candidate(block.hash, provisional)?;
    tree.apply_finalized(block.number, block.hash, block.new_root)
        .map(|outcome| outcome.marker())
        .map_err(Into::into)
}

/// Startup gate passed into both validator and certified-follower stacks.
pub trait CeStartupRecovery: Send + Sync {
    fn recover_before_participation(
        &self,
        consensus_finalized_height: u64,
    ) -> Result<FinalizedMarker, CeStartupRecoveryError>;
}

pub struct CeStartupRecoveryCoordinator {
    source: Arc<dyn CanonicalCeReplaySource>,
    tree: Arc<dyn StartupCeTree>,
}

impl std::fmt::Debug for CeStartupRecoveryCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CeStartupRecoveryCoordinator")
            .finish_non_exhaustive()
    }
}

impl CeStartupRecoveryCoordinator {
    pub fn new(source: Arc<dyn CanonicalCeReplaySource>, tree: Arc<dyn StartupCeTree>) -> Self {
        Self { source, tree }
    }
}

impl CeStartupRecovery for CeStartupRecoveryCoordinator {
    fn recover_before_participation(
        &self,
        consensus_finalized_height: u64,
    ) -> Result<FinalizedMarker, CeStartupRecoveryError> {
        // Restart candidates have no authority and cannot be used to bridge a
        // missing durable-history row.
        self.tree
            .discard_speculative_candidates()
            .map_err(tree_error)?;
        let marker = self.tree.marker().map_err(tree_error)?;
        let checkpoint = self
            .source
            .durable_checkpoint(consensus_finalized_height)
            .map_err(source_error)?
            .ok_or(CeStartupRecoveryError::DurableCheckpointUnavailable {
                consensus_finalized_height,
            })?;
        if checkpoint.height != consensus_finalized_height
            || checkpoint.consensus_finalized_height != consensus_finalized_height
        {
            return Err(CeStartupRecoveryError::CheckpointHeightMismatch {
                requested: consensus_finalized_height,
                durable: checkpoint.height,
                consensus: checkpoint.consensus_finalized_height,
            });
        }

        match classify_restart(marker, checkpoint) {
            RestartClassification::Equal => Ok(marker),
            RestartClassification::Ahead => {
                Err(CeStartupRecoveryError::MarkerAhead { marker, checkpoint })
            }
            RestartClassification::Conflict => {
                Err(CeStartupRecoveryError::MarkerConflict { marker, checkpoint })
            }
            RestartClassification::Behind {
                first_missing,
                target,
            } => {
                let started = Instant::now();
                let recovered = self.replay(marker, first_missing, target, checkpoint)?;
                let replayed_blocks = target - first_missing + 1;
                let elapsed_micros =
                    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                tracing::info!(
                    first_missing,
                    target_height = target,
                    target_hash = %checkpoint.block_hash,
                    replayed_blocks,
                    elapsed_micros,
                    "compressed-entity startup replay completed"
                );
                Ok(recovered)
            }
        }
    }
}

impl CeStartupRecoveryCoordinator {
    fn replay(
        &self,
        mut current: FinalizedMarker,
        first_missing: u64,
        target: u64,
        checkpoint: DurableFinalizedCheckpoint,
    ) -> Result<FinalizedMarker, CeStartupRecoveryError> {
        for height in first_missing..=target {
            let block = self
                .source
                .replay_block(height)
                .map_err(source_error)?
                .ok_or(CeStartupRecoveryError::ReplayGap { height })?;
            if block.number != height {
                return Err(CeStartupRecoveryError::ReplayHeightMismatch {
                    requested: height,
                    actual: block.number,
                });
            }
            if block.parent_hash != current.block_hash || block.parent_root != current.new_root {
                return Err(CeStartupRecoveryError::ReplayParentMismatch {
                    height,
                    expected_hash: current.block_hash,
                    actual_hash: block.parent_hash,
                    expected_root: current.new_root,
                    actual_root: block.parent_root,
                });
            }
            let applied = self.tree.apply_replayed(&block).map_err(tree_error)?;
            if applied.commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME
                || applied.height != height
                || applied.block_hash != block.hash
                || applied.parent_block_hash != block.parent_hash
                || applied.parent_root != block.parent_root
                || applied.new_root != block.new_root
            {
                return Err(CeStartupRecoveryError::AppliedMarkerMismatch { height, applied });
            }
            current = applied;
        }

        if current.height != checkpoint.height
            || current.block_hash != checkpoint.block_hash
            || current.new_root != checkpoint.root
            || current.commitment_scheme_version != checkpoint.commitment_scheme_version
        {
            return Err(CeStartupRecoveryError::ReplayTargetMismatch {
                marker: current,
                checkpoint,
            });
        }
        Ok(current)
    }
}

fn source_error(error: eyre::Report) -> CeStartupRecoveryError {
    CeStartupRecoveryError::CanonicalHistory(error.to_string())
}

fn tree_error(error: eyre::Report) -> CeStartupRecoveryError {
    CeStartupRecoveryError::Tree(error.to_string())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CeStartupRecoveryError {
    #[error("durable Reth checkpoint at consensus-finalized height {consensus_finalized_height} is unavailable")]
    DurableCheckpointUnavailable { consensus_finalized_height: u64 },
    #[error("startup checkpoint heights disagree: requested {requested}, durable {durable}, consensus {consensus}")]
    CheckpointHeightMismatch {
        requested: u64,
        durable: u64,
        consensus: u64,
    },
    #[error("CE marker is ahead of durable EVM/consensus finality: marker {marker:?}, checkpoint {checkpoint:?}")]
    MarkerAhead {
        marker: FinalizedMarker,
        checkpoint: DurableFinalizedCheckpoint,
    },
    #[error("CE marker conflicts with durable EVM finality: marker {marker:?}, checkpoint {checkpoint:?}")]
    MarkerConflict {
        marker: FinalizedMarker,
        checkpoint: DurableFinalizedCheckpoint,
    },
    #[error("canonical CE replay is missing finalized block {height}")]
    ReplayGap { height: u64 },
    #[error("canonical CE replay returned height {actual} for requested height {requested}")]
    ReplayHeightMismatch { requested: u64, actual: u64 },
    #[error("canonical CE replay block {height} does not extend the current marker")]
    ReplayParentMismatch {
        height: u64,
        expected_hash: B256,
        actual_hash: B256,
        expected_root: B256,
        actual_root: B256,
    },
    #[error("CE replay apply returned a conflicting marker at height {height}: {applied:?}")]
    AppliedMarkerMismatch {
        height: u64,
        applied: FinalizedMarker,
    },
    #[error("CE replay did not reach the exact durable target: marker {marker:?}, checkpoint {checkpoint:?}")]
    ReplayTargetMismatch {
        marker: FinalizedMarker,
        checkpoint: DurableFinalizedCheckpoint,
    },
    #[error("canonical Reth history is unavailable or malformed: {0}")]
    CanonicalHistory(String),
    #[error("compressed-tree recovery failed: {0}")]
    Tree(String),
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct CapturedLogWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogWriter {
        fn contents(&self) -> String {
            String::from_utf8(
                self.bytes
                    .lock()
                    .expect("captured CE recovery log mutex")
                    .clone(),
            )
            .expect("CE recovery log is UTF-8")
        }
    }

    struct CapturedLogGuard {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogGuard {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("captured CE recovery log mutex")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogWriter {
        type Writer = CapturedLogGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogGuard {
                bytes: self.bytes.clone(),
            }
        }
    }

    fn hash(value: u8) -> B256 {
        B256::from([value; 32])
    }

    fn marker(height: u64) -> FinalizedMarker {
        FinalizedMarker {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height,
            block_hash: hash(height as u8),
            parent_block_hash: hash(height.saturating_sub(1) as u8),
            parent_root: hash(100 + height.saturating_sub(1) as u8),
            new_root: hash(100 + height as u8),
        }
    }

    fn block(height: u64) -> CanonicalCeReplayBlock {
        let next = marker(height);
        CanonicalCeReplayBlock {
            number: height,
            hash: next.block_hash,
            parent_hash: next.parent_block_hash,
            parent_root: next.parent_root,
            new_root: next.new_root,
            events: Vec::new(),
            retirements: Vec::new(),
        }
    }

    struct MemorySource {
        checkpoint: DurableFinalizedCheckpoint,
        blocks: BTreeMap<u64, CanonicalCeReplayBlock>,
    }

    impl CanonicalCeReplaySource for MemorySource {
        fn durable_checkpoint(
            &self,
            _consensus_finalized_height: u64,
        ) -> eyre::Result<Option<DurableFinalizedCheckpoint>> {
            Ok(Some(self.checkpoint))
        }

        fn replay_block(&self, height: u64) -> eyre::Result<Option<CanonicalCeReplayBlock>> {
            Ok(self.blocks.get(&height).cloned())
        }
    }

    struct MemoryTree {
        marker: Mutex<FinalizedMarker>,
        applied: Mutex<Vec<u64>>,
        discarded: Mutex<u64>,
    }

    impl StartupCeTree for MemoryTree {
        fn marker(&self) -> eyre::Result<FinalizedMarker> {
            Ok(*self.marker.lock().unwrap())
        }

        fn discard_speculative_candidates(&self) -> eyre::Result<()> {
            *self.discarded.lock().unwrap() += 1;
            Ok(())
        }

        fn apply_replayed(&self, block: &CanonicalCeReplayBlock) -> eyre::Result<FinalizedMarker> {
            let next = FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: block.number,
                block_hash: block.hash,
                parent_block_hash: block.parent_hash,
                parent_root: block.parent_root,
                new_root: block.new_root,
            };
            *self.marker.lock().unwrap() = next;
            self.applied.lock().unwrap().push(block.number);
            Ok(next)
        }
    }

    fn coordinator(
        current: FinalizedMarker,
        target: FinalizedMarker,
        blocks: BTreeMap<u64, CanonicalCeReplayBlock>,
    ) -> (CeStartupRecoveryCoordinator, Arc<MemoryTree>) {
        let source = Arc::new(MemorySource {
            checkpoint: DurableFinalizedCheckpoint {
                commitment_scheme_version: target.commitment_scheme_version,
                height: target.height,
                block_hash: target.block_hash,
                root: target.new_root,
                parent_block_hash: target.parent_block_hash,
                parent_root: target.parent_root,
                consensus_finalized_height: target.height,
            },
            blocks,
        });
        let tree = Arc::new(MemoryTree {
            marker: Mutex::new(current),
            applied: Mutex::new(Vec::new()),
            discarded: Mutex::new(0),
        });
        (
            CeStartupRecoveryCoordinator::new(source, tree.clone()),
            tree,
        )
    }

    #[test]
    fn equal_marker_resumes_without_replay_and_restart_discards_candidates() {
        let (recovery, tree) = coordinator(marker(3), marker(3), BTreeMap::new());
        assert_eq!(recovery.recover_before_participation(3).unwrap(), marker(3));
        assert!(tree.applied.lock().unwrap().is_empty());
        assert_eq!(*tree.discarded.lock().unwrap(), 1);
    }

    #[test]
    fn behind_marker_replays_every_contiguous_finalized_block() {
        let blocks = BTreeMap::from([(2, block(2)), (3, block(3)), (4, block(4))]);
        let (recovery, tree) = coordinator(marker(1), marker(4), blocks);
        assert_eq!(recovery.recover_before_participation(4).unwrap(), marker(4));
        assert_eq!(*tree.applied.lock().unwrap(), vec![2, 3, 4]);
    }

    #[test]
    fn successful_startup_replay_emits_its_complete_canonical_span() {
        let writer = CapturedLogWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let blocks = BTreeMap::from([(2, block(2)), (3, block(3)), (4, block(4))]);
        let (recovery, _) = coordinator(marker(1), marker(4), blocks);

        assert_eq!(recovery.recover_before_participation(4).unwrap(), marker(4));

        let log = writer.contents();
        assert!(log.contains("compressed-entity startup replay completed"));
        assert!(log.contains("first_missing=2"));
        assert!(log.contains("target_height=4"));
        assert!(log.contains(&format!("target_hash={}", marker(4).block_hash)));
        assert!(log.contains("replayed_blocks=3"));
        assert!(log.contains("elapsed_micros="));
    }

    #[test]
    fn ahead_and_same_height_conflict_fail_before_any_replay() {
        let (ahead, ahead_tree) = coordinator(marker(4), marker(3), BTreeMap::new());
        assert!(matches!(
            ahead.recover_before_participation(3),
            Err(CeStartupRecoveryError::MarkerAhead { .. })
        ));
        assert!(ahead_tree.applied.lock().unwrap().is_empty());

        let mut conflict = marker(3);
        conflict.block_hash = hash(99);
        let (conflicting, conflict_tree) = coordinator(conflict, marker(3), BTreeMap::new());
        assert!(matches!(
            conflicting.recover_before_participation(3),
            Err(CeStartupRecoveryError::MarkerConflict { .. })
        ));
        assert!(conflict_tree.applied.lock().unwrap().is_empty());
    }

    #[test]
    fn gap_wrong_height_and_wrong_parent_fail_at_the_exact_row() {
        let (gap, gap_tree) = coordinator(marker(1), marker(3), BTreeMap::from([(2, block(2))]));
        assert_eq!(
            gap.recover_before_participation(3),
            Err(CeStartupRecoveryError::ReplayGap { height: 3 })
        );
        assert_eq!(*gap_tree.applied.lock().unwrap(), vec![2]);

        let mut wrong_height = block(2);
        wrong_height.number = 7;
        let (height, height_tree) =
            coordinator(marker(1), marker(2), BTreeMap::from([(2, wrong_height)]));
        assert_eq!(
            height.recover_before_participation(2),
            Err(CeStartupRecoveryError::ReplayHeightMismatch {
                requested: 2,
                actual: 7,
            })
        );
        assert!(height_tree.applied.lock().unwrap().is_empty());

        let mut wrong_parent = block(2);
        wrong_parent.parent_hash = hash(77);
        let (parent, parent_tree) =
            coordinator(marker(1), marker(2), BTreeMap::from([(2, wrong_parent)]));
        assert!(matches!(
            parent.recover_before_participation(2),
            Err(CeStartupRecoveryError::ReplayParentMismatch { height: 2, .. })
        ));
        assert!(parent_tree.applied.lock().unwrap().is_empty());
    }

    #[test]
    fn consensus_finality_is_an_enforced_upper_bound() {
        let target = marker(4);
        let source = Arc::new(MemorySource {
            checkpoint: DurableFinalizedCheckpoint {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: 4,
                block_hash: target.block_hash,
                root: target.new_root,
                parent_block_hash: target.parent_block_hash,
                parent_root: target.parent_root,
                consensus_finalized_height: 3,
            },
            blocks: BTreeMap::new(),
        });
        let tree = Arc::new(MemoryTree {
            marker: Mutex::new(marker(3)),
            applied: Mutex::new(Vec::new()),
            discarded: Mutex::new(0),
        });
        let recovery = CeStartupRecoveryCoordinator::new(source, tree);
        assert_eq!(
            recovery.recover_before_participation(3),
            Err(CeStartupRecoveryError::CheckpointHeightMismatch {
                requested: 3,
                durable: 4,
                consensus: 3,
            })
        );
    }
}
