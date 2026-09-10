//! Durable Reth -> CE-MDBX finalization barrier.
//!
//! This module is deliberately outside the executor actor. The actor only owns
//! Marshal ordering; this adapter owns Reth's persistence notification, the
//! DB-only canonical/root check, and the CE tree commit which must all complete
//! before the actor may acknowledge the finalized block.

use std::{sync::Arc, time::Duration};

use alloy_consensus::{BlockHeader as _, TxReceipt};
use alloy_eips::BlockNumHash;
use alloy_primitives::{B256, U256};
use futures::{future::BoxFuture, stream::BoxStream, FutureExt, StreamExt};
use outbe_compressed_entities::{
    decode_canonical_body_event, decode_partition_retirement, CompressedTreeService,
    DurableFinalizedCheckpoint, FinalizedCandidateOutcome, FinalizedMarker, StagedTreeBatch,
    ACTIVE_COMMITMENT_SCHEME,
};
use outbe_consensus::executor::actor::{FinalizedCeBlock, FinalizedCeCommitter};
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS,
    reshare_artifact::{decode_outbe_block_artifacts, CompressedEntitiesRootArtifact},
    OutbeHeader,
};
use reth_chain_state::PersistedBlockSubscriptions;
use reth_provider::{
    BlockHashReader, DatabaseProviderFactory, HeaderProvider, ProviderError, ReceiptProvider,
};
use reth_storage_api::TryIntoHistoricalStateProvider;

use crate::ce_recovery::{CanonicalCeReplayBlock, CanonicalCeReplaySource};

/// The authoritative compressed-entity root is storage slot 1 at `0xEE0D`.
const CE_ROOT_SLOT: B256 = B256::new(U256::from_limbs([1, 0, 0, 0]).to_be_bytes::<32>());
/// Poll durable Reth state while an advisory persistence notification is absent.
const CE_PERSISTENCE_RECHECK_INTERVAL: Duration = Duration::from_secs(1);
/// A finalized delivery must recover or fail before it can stall the executor forever.
const CE_PERSISTENCE_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
struct CePersistenceWaitPolicy {
    recheck_interval: Duration,
    deadline: Duration,
}

impl Default for CePersistenceWaitPolicy {
    fn default() -> Self {
        Self {
            recheck_interval: CE_PERSISTENCE_RECHECK_INTERVAL,
            deadline: CE_PERSISTENCE_DEADLINE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableCeProbe {
    Absent,
    DifferentHash(B256),
    Exact(B256),
}

fn is_pending_executed_state(error: &ProviderError, height: u64) -> bool {
    matches!(
        error,
        ProviderError::BlockNotExecuted { requested, .. } if *requested == height
    )
}

fn validate_durable_header_evidence(
    height: u64,
    evidence: DurableCeEvidence,
) -> eyre::Result<B256> {
    if height == 0 {
        if evidence.header_root.is_some() {
            eyre::bail!("genesis durable header unexpectedly carries a CE root artifact");
        }
        return Ok(evidence.evm_root);
    }
    let header_root = evidence.header_root.ok_or_else(|| {
        eyre::eyre!(
            "durable canonical header is missing CE root artifact at {height}/{}",
            evidence.block_hash
        )
    })?;
    if header_root.commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME {
        eyre::bail!(
            "durable canonical header CE scheme mismatch at {height}/{}: header={}, active={}",
            evidence.block_hash,
            header_root.commitment_scheme_version,
            ACTIVE_COMMITMENT_SCHEME
        );
    }
    if header_root.r_sealed != evidence.evm_root {
        eyre::bail!(
            "durable canonical header/EVM CE root mismatch at {height}/{}: header={}, evm={}",
            evidence.block_hash,
            header_root.r_sealed,
            evidence.evm_root
        );
    }
    Ok(header_root.r_sealed)
}

/// Narrow, behavior-testable view of Reth's durable storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableCeEvidence {
    pub block_hash: B256,
    pub evm_root: B256,
    pub header_root: Option<CompressedEntitiesRootArtifact>,
}

pub trait DurableCeState: Send + Sync {
    /// Subscribe before finalized processing starts so no persistence edge is missed.
    fn persisted_blocks(&self) -> BoxStream<'static, BlockNumHash>;

    /// Reads only durable canonical data. `None` means this height is not yet on disk.
    fn block_and_root(&self, height: u64) -> eyre::Result<Option<DurableCeEvidence>>;

    /// Reads and authenticates the canonical receipt history needed to
    /// reconstruct one exact finalized tree batch.
    fn replay_block(&self, height: u64) -> eyre::Result<Option<CanonicalCeReplayBlock>>;
}

/// Production Reth adapter. The block identity is checked through a fresh
/// read-only DB provider before historical state is opened for the same durable
/// hash, preventing an in-memory candidate from satisfying the barrier.
#[derive(Clone, Debug)]
pub struct RethDurableCeState<P> {
    provider: P,
}

impl<P> RethDurableCeState<P> {
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> DurableCeState for RethDurableCeState<P>
where
    P: PersistedBlockSubscriptions + DatabaseProviderFactory + Clone + Send + Sync + 'static,
    P::Provider: BlockHashReader
        + HeaderProvider<Header = OutbeHeader>
        + ReceiptProvider
        + TryIntoHistoricalStateProvider,
{
    fn persisted_blocks(&self) -> BoxStream<'static, BlockNumHash> {
        self.provider.persisted_block_stream().boxed()
    }

    fn block_and_root(&self, height: u64) -> eyre::Result<Option<DurableCeEvidence>> {
        let durable = self
            .provider
            .database_provider_ro()
            .map_err(|error| eyre::eyre!("failed to open Reth DB-only provider: {error}"))?;
        let Some(block_hash) = durable
            .block_hash(height)
            .map_err(|error| eyre::eyre!("failed to read durable block {height}: {error}"))?
        else {
            return Ok(None);
        };
        let header = durable
            .sealed_header(height)
            .map_err(|error| eyre::eyre!("failed to read durable header {height}: {error}"))?
            .ok_or_else(|| eyre::eyre!("durable header {height}/{block_hash} is missing"))?;
        if header.hash() != block_hash {
            eyre::bail!(
                "durable header/hash index conflict at height {height}: index={block_hash}, header={}",
                header.hash()
            );
        }
        let header_root = decode_outbe_block_artifacts(header.extra_data().as_ref())
            .map_err(|error| {
                eyre::eyre!(
                    "failed to decode durable header artifacts for {height}/{block_hash}: {error}"
                )
            })?
            .compressed_entities_root;
        // Consume this exact read-only transaction into the historical state
        // view. No in-memory blockchain-tree provider participates.
        let state = match durable.try_into_history_at_block(height) {
            Ok(state) => state,
            Err(error) if is_pending_executed_state(&error, height) => {
                // The block row can become visible just before Reth advances its
                // durable executed-state tip. Treat that narrow window exactly
                // like an absent block and wait for the persistence notification.
                return Ok(None);
            }
            Err(error) => {
                return Err(eyre::eyre!(
                    "failed to open durable historical state for {height}/{block_hash}: {error}"
                ));
            }
        };
        let root = state
            .storage(COMPRESSED_ENTITIES_ADDRESS, CE_ROOT_SLOT)
            .map_err(|error| {
                eyre::eyre!("failed to read durable CE root for {height}/{block_hash}: {error}")
            })?
            .map_or(B256::ZERO, |value| B256::from(value.to_be_bytes::<32>()));
        Ok(Some(DurableCeEvidence {
            block_hash,
            evm_root: root,
            header_root,
        }))
    }

    fn replay_block(&self, height: u64) -> eyre::Result<Option<CanonicalCeReplayBlock>> {
        CanonicalCeReplaySource::replay_block(self, height)
    }
}

impl<P> CanonicalCeReplaySource for RethDurableCeState<P>
where
    P: PersistedBlockSubscriptions + DatabaseProviderFactory + Clone + Send + Sync + 'static,
    P::Provider: BlockHashReader
        + HeaderProvider<Header = OutbeHeader>
        + ReceiptProvider
        + TryIntoHistoricalStateProvider,
{
    fn durable_checkpoint(
        &self,
        consensus_finalized_height: u64,
    ) -> eyre::Result<Option<DurableFinalizedCheckpoint>> {
        let Some(evidence) = self.block_and_root(consensus_finalized_height)? else {
            return Ok(None);
        };
        let root = validate_durable_header_evidence(consensus_finalized_height, evidence)?;
        let (parent_block_hash, parent_root) = if consensus_finalized_height == 0 {
            (B256::ZERO, B256::ZERO)
        } else {
            let parent = self
                .block_and_root(consensus_finalized_height - 1)?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "durable parent checkpoint {} is missing",
                        consensus_finalized_height - 1
                    )
                })?;
            (
                parent.block_hash,
                validate_durable_header_evidence(consensus_finalized_height - 1, parent)?,
            )
        };
        Ok(Some(DurableFinalizedCheckpoint {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            height: consensus_finalized_height,
            block_hash: evidence.block_hash,
            root,
            parent_block_hash,
            parent_root,
            consensus_finalized_height,
        }))
    }

    fn replay_block(&self, height: u64) -> eyre::Result<Option<CanonicalCeReplayBlock>> {
        if height == 0 {
            eyre::bail!("height 0 is the CE replay baseline, not a replay block");
        }
        let Some(evidence) = self.block_and_root(height)? else {
            return Ok(None);
        };
        let Some(parent) = self.block_and_root(height - 1)? else {
            eyre::bail!(
                "durable canonical parent {} is unavailable while replaying {height}/{}",
                height - 1,
                evidence.block_hash
            );
        };
        let hash = evidence.block_hash;
        let new_root = validate_durable_header_evidence(height, evidence)?;
        let parent_hash = parent.block_hash;
        let parent_root = validate_durable_header_evidence(height - 1, parent)?;

        // Receipts are read from a fresh DB-only provider. Blockchain-tree or
        // ExEx memory cannot fill a pruned/missing replay row.
        let durable = self
            .provider
            .database_provider_ro()
            .map_err(|error| eyre::eyre!("failed to open DB-only receipt provider: {error}"))?;
        let receipts = durable
            .receipts_by_block(hash.into())
            .map_err(|error| {
                eyre::eyre!("failed to read durable receipts for {height}/{hash}: {error}")
            })?
            .ok_or_else(|| eyre::eyre!("durable receipts missing for {height}/{hash}"))?;
        let mut events = Vec::new();
        let mut retirements = Vec::new();
        for receipt in receipts {
            if !receipt.status() {
                continue;
            }
            for log in receipt.logs() {
                if let Some(event) = decode_canonical_body_event(log.address, &log.data)? {
                    events.push(event);
                }
                if let Some(retirement) = decode_partition_retirement(log.address, &log.data)? {
                    retirements.push(retirement);
                }
            }
        }

        Ok(Some(CanonicalCeReplayBlock {
            number: height,
            hash,
            parent_hash,
            parent_root,
            new_root,
            events,
            retirements,
        }))
    }
}

/// Narrow tree ownership seam used to test ordering and failure behavior.
pub trait FinalizedCeTree: Send + Sync {
    fn finalized_marker(&self) -> eyre::Result<FinalizedMarker>;

    fn candidate(&self, height: u64, hash: B256) -> eyre::Result<Option<Arc<StagedTreeBatch>>>;

    fn apply_finalized(
        &self,
        height: u64,
        hash: B256,
        authoritative_root: B256,
    ) -> eyre::Result<FinalizedMarker>;

    fn apply_replayed(&self, block: &CanonicalCeReplayBlock) -> eyre::Result<FinalizedMarker>;
}

impl FinalizedCeTree for CompressedTreeService {
    fn finalized_marker(&self) -> eyre::Result<FinalizedMarker> {
        CompressedTreeService::finalized_marker(self).map_err(Into::into)
    }

    fn candidate(&self, height: u64, hash: B256) -> eyre::Result<Option<Arc<StagedTreeBatch>>> {
        CompressedTreeService::candidate(self, height, hash).map_err(Into::into)
    }

    fn apply_finalized(
        &self,
        height: u64,
        hash: B256,
        authoritative_root: B256,
    ) -> eyre::Result<FinalizedMarker> {
        CompressedTreeService::apply_finalized(self, height, hash, authoritative_root)
            .map(FinalizedCandidateOutcome::marker)
            .map_err(Into::into)
    }

    fn apply_replayed(&self, block: &CanonicalCeReplayBlock) -> eyre::Result<FinalizedMarker> {
        crate::ce_recovery::apply_replayed_block(self, block)
    }
}

/// Single serialized finalization coordinator shared by validator/follower
/// executor wiring.
pub struct RethCeFinalizer {
    state: Arc<dyn DurableCeState>,
    persisted: Arc<futures::lock::Mutex<BoxStream<'static, BlockNumHash>>>,
    tree: Arc<dyn FinalizedCeTree>,
    finalization: Arc<futures::lock::Mutex<()>>,
    wait_policy: CePersistenceWaitPolicy,
}

impl std::fmt::Debug for RethCeFinalizer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RethCeFinalizer")
            .finish_non_exhaustive()
    }
}

impl RethCeFinalizer {
    /// Captures the persistence subscription eagerly, before any finalized
    /// delivery can enter the executor actor.
    pub fn new(state: Arc<dyn DurableCeState>, tree: Arc<dyn FinalizedCeTree>) -> Self {
        Self::with_wait_policy(state, tree, CePersistenceWaitPolicy::default())
    }

    fn with_wait_policy(
        state: Arc<dyn DurableCeState>,
        tree: Arc<dyn FinalizedCeTree>,
        wait_policy: CePersistenceWaitPolicy,
    ) -> Self {
        debug_assert!(!wait_policy.recheck_interval.is_zero());
        debug_assert!(!wait_policy.deadline.is_zero());
        let persisted = state.persisted_blocks();
        Self {
            state,
            persisted: Arc::new(futures::lock::Mutex::new(persisted)),
            tree,
            finalization: Arc::new(futures::lock::Mutex::new(())),
            wait_policy,
        }
    }

    async fn commit(&self, block: FinalizedCeBlock) -> eyre::Result<()> {
        let _serial = self.finalization.lock().await;
        let current = self.tree.finalized_marker()?;
        if current.height == block.height {
            if current.commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME
                || current.block_hash != block.block_hash
                || current.parent_block_hash != block.parent_block_hash
            {
                eyre::bail!(
                    "redelivered finalized CE block conflicts with the durable marker at {}/{}: {current:?}",
                    block.height,
                    block.block_hash
                );
            }
            let authoritative_root = match self.verify_durable(block)? {
                Some(root) => root,
                None => {
                    self.wait_for_exact_persistence(block).await?;
                    self.verify_durable(block)?.ok_or_else(|| {
                        eyre::eyre!(
                            "Reth emitted persistence for redelivered block {}/{}, but DB-only state is absent",
                            block.height,
                            block.block_hash
                        )
                    })?
                }
            };
            if current.new_root != authoritative_root {
                eyre::bail!(
                    "redelivered finalized CE block root conflicts with the durable marker at {}/{}: Reth={}, marker={}",
                    block.height,
                    block.block_hash,
                    authoritative_root,
                    current.new_root
                );
            }
            let durable_parent = self
                .state
                .block_and_root(block.height.saturating_sub(1))?
                .ok_or_else(|| {
                    eyre::eyre!(
                        "durable parent is absent while validating redelivered finalized CE block {}/{}",
                        block.height,
                        block.block_hash
                    )
                })?;
            let durable_parent_root =
                validate_durable_header_evidence(block.height.saturating_sub(1), durable_parent)?;
            if current.parent_block_hash != durable_parent.block_hash
                || current.parent_root != durable_parent_root
            {
                eyre::bail!(
                    "redelivered finalized CE block parent identity conflicts with the durable marker at {}/{}: Reth=({}, {}), marker=({}, {})",
                    block.height,
                    block.block_hash,
                    durable_parent.block_hash,
                    durable_parent_root,
                    current.parent_block_hash,
                    current.parent_root
                );
            }
            return Ok(());
        }
        if current.height > block.height {
            eyre::bail!(
                "redelivered finalized CE block is behind the durable marker: block={}/{}, marker={current:?}",
                block.height,
                block.block_hash
            );
        }
        let authoritative_root = match self.probe_durable(block)? {
            DurableCeProbe::Exact(root) => root,
            DurableCeProbe::Absent | DurableCeProbe::DifferentHash(_) => {
                self.wait_for_exact_persistence(block).await?;
                self.verify_durable(block)?.ok_or_else(|| {
                    eyre::eyre!(
                        "Reth emitted persistence for {}/{}, but DB-only state is absent",
                        block.height,
                        block.block_hash
                    )
                })?
            }
        };
        let durable_parent = self
            .state
            .block_and_root(block.height.saturating_sub(1))?
            .ok_or_else(|| {
                eyre::eyre!(
                    "durable parent is absent for finalized CE block {}/{}",
                    block.height,
                    block.block_hash
                )
            })?;
        let durable_parent_root =
            validate_durable_header_evidence(block.height.saturating_sub(1), durable_parent)?;
        if durable_parent.block_hash != block.parent_block_hash
            || durable_parent.block_hash != current.block_hash
            || durable_parent_root != current.new_root
        {
            eyre::bail!(
                "durable parent/header conflicts with finalized CE parent at {}/{}: actor=({}, {}), marker=({}, {})",
                block.height,
                block.block_hash,
                block.parent_block_hash,
                durable_parent_root,
                current.block_hash,
                current.new_root
            );
        }

        let marker = if let Some(candidate) = self.tree.candidate(block.height, block.block_hash)? {
            if candidate.parent_block_hash() != block.parent_block_hash {
                eyre::bail!(
                    "finalized CE candidate parent conflict at {}/{}: actor={}, candidate={}",
                    block.height,
                    block.block_hash,
                    block.parent_block_hash,
                    candidate.parent_block_hash()
                );
            }
            if candidate.new_root() != authoritative_root {
                eyre::bail!(
                    "durable EVM/CE candidate root conflict at {}/{}: evm={}, candidate={}",
                    block.height,
                    block.block_hash,
                    authoritative_root,
                    candidate.new_root()
                );
            }
            self.tree
                .apply_finalized(block.height, block.block_hash, authoritative_root)?
        } else {
            // Validator/import execution must not publish before Reth's receipt
            // and state-root checks. Once the block is durable and exact, rebuild
            // the same batch from its canonical receipts instead of trusting a
            // speculative executor artifact.
            let replay = self.state.replay_block(block.height)?.ok_or_else(|| {
                eyre::eyre!(
                    "durable canonical CE replay missing for finalized block {}/{}",
                    block.height,
                    block.block_hash
                )
            })?;
            if replay.number != block.height
                || replay.hash != block.block_hash
                || replay.parent_hash != block.parent_block_hash
                || replay.new_root != authoritative_root
                || replay.parent_hash != current.block_hash
                || replay.parent_root != current.new_root
            {
                eyre::bail!(
                    "durable canonical CE replay identity/root conflict for finalized block {}/{}: current={current:?}, replay={replay:?}, authoritative_root={authoritative_root}",
                    block.height,
                    block.block_hash
                );
            }
            self.tree.apply_replayed(&replay)?
        };
        if marker.commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME
            || marker.height != block.height
            || marker.block_hash != block.block_hash
            || marker.parent_block_hash != block.parent_block_hash
            || marker.parent_root != current.new_root
            || marker.new_root != authoritative_root
        {
            eyre::bail!(
                "CE MDBX returned conflicting finalized marker for {}/{}: {marker:?}",
                block.height,
                block.block_hash
            );
        }
        Ok(())
    }

    fn verify_durable(&self, block: FinalizedCeBlock) -> eyre::Result<Option<B256>> {
        match self.probe_durable(block)? {
            DurableCeProbe::Absent => Ok(None),
            DurableCeProbe::Exact(root) => Ok(Some(root)),
            DurableCeProbe::DifferentHash(actual) => {
                eyre::bail!(
                    "durable canonical conflict at height {}: finalized={}, Reth={}",
                    block.height,
                    block.block_hash,
                    actual
                );
            }
        }
    }

    fn probe_durable(&self, block: FinalizedCeBlock) -> eyre::Result<DurableCeProbe> {
        let Some(evidence) = self.state.block_and_root(block.height)? else {
            return Ok(DurableCeProbe::Absent);
        };
        if evidence.block_hash != block.block_hash {
            return Ok(DurableCeProbe::DifferentHash(evidence.block_hash));
        }
        Ok(DurableCeProbe::Exact(validate_durable_header_evidence(
            block.height,
            evidence,
        )?))
    }

    async fn wait_for_exact_persistence(&self, block: FinalizedCeBlock) -> eyre::Result<()> {
        let mut persisted = self.persisted.lock().await;
        let deadline = tokio::time::sleep(self.wait_policy.deadline);
        tokio::pin!(deadline);
        let first_recheck = tokio::time::Instant::now() + self.wait_policy.recheck_interval;
        let mut rechecks =
            tokio::time::interval_at(first_recheck, self.wait_policy.recheck_interval);
        rechecks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = &mut deadline => {
                    // Resolve the boundary race in favor of durable proof: a block
                    // becoming visible at the deadline still completes online.
                    if matches!(self.probe_durable(block)?, DurableCeProbe::Exact(_)) {
                        return Ok(());
                    }
                    eyre::bail!(
                        "finalized CE persistence deadline exceeded for {}/{} after {:?}",
                        block.height,
                        block.block_hash,
                        self.wait_policy.deadline
                    );
                }
                _ = rechecks.tick() => {
                    if matches!(self.probe_durable(block)?, DurableCeProbe::Exact(_)) {
                        return Ok(());
                    }
                }
                notification = persisted.next() => {
                    let Some(notification) = notification else {
                        return Err(eyre::eyre!(
                            "Reth persistence stream ended before finalized CE block {}/{}",
                            block.height,
                            block.block_hash
                        ));
                    };
                    if notification.number < block.height {
                        continue;
                    }
                    if notification.number == block.height
                        && notification.hash == block.block_hash
                    {
                        // Notifications are advisory. Accept the wake only after
                        // the exact target is visible through a fresh DB-only read.
                        if matches!(self.probe_durable(block)?, DurableCeProbe::Exact(_)) {
                            return Ok(());
                        }
                        continue;
                    }
                    if notification.number == block.height {
                        // Reth can persist a speculative canonical head at H before
                        // consensus finalizes a different block at the same H. The
                        // finalized block was already submitted through newPayload and
                        // FCU, so wait for its replacement persistence notification.
                        // Treating the old same-height hash as "passed" kills an honest
                        // validator during an ordinary pre-finalization reorg.
                        continue;
                    }
                    if matches!(self.probe_durable(block)?, DurableCeProbe::Exact(_)) {
                        // This is a watch stream, so a slow receiver may observe a
                        // later durable tip. The target is accepted only after a fresh
                        // DB-only transaction proves its exact canonical identity.
                        return Ok(());
                    }
                    eyre::bail!(
                        "Reth persistence passed finalized CE block {}/{} with {}/{}",
                        block.height,
                        block.block_hash,
                        notification.number,
                        notification.hash
                    );
                }
            }
        }
    }
}

impl FinalizedCeCommitter for RethCeFinalizer {
    fn commit_finalized(&self, block: FinalizedCeBlock) -> BoxFuture<'static, eyre::Result<()>> {
        let this = Self {
            state: Arc::clone(&self.state),
            persisted: Arc::clone(&self.persisted),
            tree: Arc::clone(&self.tree),
            finalization: Arc::clone(&self.finalization),
            wait_policy: self.wait_policy,
        };
        async move { this.commit(block).await }.boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Mutex};

    use futures::channel::mpsc;
    use outbe_compressed_entities::{
        CandidateCacheLimits, CeMdbx, Commitment, CompressedTreeService, EntityRef,
        EnvironmentIdentity, ExactParentIdentity, FinalLeafMutation, WwdEntityId,
        ACTIVE_COMMITMENT_SCHEME, LOCAL_STORAGE_SCHEMA_VERSION,
    };

    use super::*;

    #[test]
    fn block_row_visible_before_executed_state_is_transient() {
        assert!(is_pending_executed_state(
            &ProviderError::BlockNotExecuted {
                requested: 159,
                executed: 158,
            },
            159,
        ));
        assert!(!is_pending_executed_state(
            &ProviderError::BlockNotExecuted {
                requested: 160,
                executed: 158,
            },
            159,
        ));
        assert!(!is_pending_executed_state(
            &ProviderError::StateAtBlockPruned(159),
            159,
        ));
    }

    fn hash(last: u8) -> B256 {
        let mut value = [0_u8; 32];
        value[31] = last;
        B256::from(value)
    }

    fn finalized_block() -> FinalizedCeBlock {
        FinalizedCeBlock {
            height: 1,
            block_hash: hash(2),
            parent_block_hash: hash(1),
        }
    }

    fn candidate() -> Arc<StagedTreeBatch> {
        Arc::new(
            outbe_compressed_entities::ProvisionalTreeBatch::new_identity(1, hash(1), B256::ZERO)
                .unwrap()
                .freeze(hash(2)),
        )
    }

    fn real_tree_service() -> (tempfile::TempDir, Arc<CompressedTreeService>) {
        let directory = tempfile::tempdir().unwrap();
        let db = CeMdbx::open(
            directory.path(),
            EnvironmentIdentity {
                local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
                chain_id: 1,
                genesis_hash: hash(1),
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                topology: outbe_compressed_entities::CeTopologyV1.encode(),
                tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".to_owned(),
                vendor_revision: "ad555350c866b2265d87d2d7fbd146fbc918bfe5".to_owned(),
            },
            FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: 0,
                block_hash: hash(1),
                parent_block_hash: B256::ZERO,
                parent_root: B256::ZERO,
                new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
            },
        )
        .unwrap();
        let service = CompressedTreeService::new(
            db,
            CandidateCacheLimits {
                max_candidates: 4,
                max_encoded_bytes: 1_000_000,
            },
        )
        .unwrap();
        (directory, Arc::new(service))
    }

    struct FakeDurableState {
        stream: Mutex<Option<mpsc::UnboundedReceiver<BlockNumHash>>>,
        blocks: Mutex<BTreeMap<u64, DurableCeEvidence>>,
        replay: Mutex<BTreeMap<u64, CanonicalCeReplayBlock>>,
    }

    impl FakeDurableState {
        fn new() -> (Arc<Self>, mpsc::UnboundedSender<BlockNumHash>) {
            let (tx, rx) = mpsc::unbounded();
            let mut blocks = BTreeMap::new();
            blocks.insert(
                0,
                DurableCeEvidence {
                    block_hash: hash(1),
                    evm_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
                    header_root: None,
                },
            );
            (
                Arc::new(Self {
                    stream: Mutex::new(Some(rx)),
                    blocks: Mutex::new(blocks),
                    replay: Mutex::new(BTreeMap::new()),
                }),
                tx,
            )
        }

        fn set(&self, height: u64, block_hash: B256, root: B256) {
            self.blocks.lock().unwrap().insert(
                height,
                DurableCeEvidence {
                    block_hash,
                    evm_root: root,
                    header_root: (height > 0).then_some(CompressedEntitiesRootArtifact {
                        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                        r_sealed: root,
                    }),
                },
            );
        }

        fn set_header_root(
            &self,
            height: u64,
            header_root: Option<CompressedEntitiesRootArtifact>,
        ) {
            self.blocks
                .lock()
                .unwrap()
                .get_mut(&height)
                .expect("fake durable block must exist")
                .header_root = header_root;
        }

        fn set_replay(&self, block: CanonicalCeReplayBlock) {
            self.replay.lock().unwrap().insert(block.number, block);
        }
    }

    impl DurableCeState for FakeDurableState {
        fn persisted_blocks(&self) -> BoxStream<'static, BlockNumHash> {
            self.stream.lock().unwrap().take().unwrap().boxed()
        }

        fn block_and_root(&self, height: u64) -> eyre::Result<Option<DurableCeEvidence>> {
            Ok(self.blocks.lock().unwrap().get(&height).copied())
        }

        fn replay_block(&self, height: u64) -> eyre::Result<Option<CanonicalCeReplayBlock>> {
            Ok(self.replay.lock().unwrap().get(&height).cloned())
        }
    }

    struct FakeTree {
        candidate: Option<Arc<StagedTreeBatch>>,
        marker: FinalizedMarker,
        attempts: Mutex<Vec<(u64, B256, B256)>>,
        apply_error: bool,
    }

    impl FakeTree {
        fn new(candidate: Option<Arc<StagedTreeBatch>>) -> Arc<Self> {
            Arc::new(Self {
                candidate,
                marker: FinalizedMarker {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    height: 0,
                    block_hash: hash(1),
                    parent_block_hash: B256::ZERO,
                    parent_root: B256::ZERO,
                    new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
                },
                attempts: Mutex::new(Vec::new()),
                apply_error: false,
            })
        }

        fn committed() -> Arc<Self> {
            Arc::new(Self {
                candidate: None,
                marker: candidate().marker(ACTIVE_COMMITMENT_SCHEME),
                attempts: Mutex::new(Vec::new()),
                apply_error: false,
            })
        }

        fn failing(candidate: Arc<StagedTreeBatch>) -> Arc<Self> {
            Arc::new(Self {
                candidate: Some(candidate),
                marker: FinalizedMarker {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    height: 0,
                    block_hash: hash(1),
                    parent_block_hash: B256::ZERO,
                    parent_root: B256::ZERO,
                    new_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
                },
                attempts: Mutex::new(Vec::new()),
                apply_error: true,
            })
        }

        fn attempts(&self) -> usize {
            self.attempts.lock().unwrap().len()
        }
    }

    impl FinalizedCeTree for FakeTree {
        fn finalized_marker(&self) -> eyre::Result<FinalizedMarker> {
            Ok(self.marker)
        }

        fn candidate(&self, height: u64, hash: B256) -> eyre::Result<Option<Arc<StagedTreeBatch>>> {
            Ok(self
                .candidate
                .as_ref()
                .filter(|candidate| {
                    candidate.block_number() == height && candidate.block_hash() == hash
                })
                .cloned())
        }

        fn apply_finalized(
            &self,
            height: u64,
            hash: B256,
            authoritative_root: B256,
        ) -> eyre::Result<FinalizedMarker> {
            self.attempts
                .lock()
                .unwrap()
                .push((height, hash, authoritative_root));
            if self.apply_error {
                eyre::bail!("injected uncertain commit outcome");
            }
            let candidate = self.candidate.as_ref().unwrap();
            Ok(candidate.marker(ACTIVE_COMMITMENT_SCHEME))
        }

        fn apply_replayed(&self, block: &CanonicalCeReplayBlock) -> eyre::Result<FinalizedMarker> {
            self.attempts
                .lock()
                .unwrap()
                .push((block.number, block.hash, block.new_root));
            Ok(FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: block.number,
                block_hash: block.hash,
                parent_block_hash: block.parent_hash,
                parent_root: block.parent_root,
                new_root: block.new_root,
            })
        }
    }

    fn finalizer(state: Arc<FakeDurableState>, tree: Arc<FakeTree>) -> RethCeFinalizer {
        let state: Arc<dyn DurableCeState> = state;
        let tree: Arc<dyn FinalizedCeTree> = tree;
        RethCeFinalizer::new(state, tree)
    }

    fn finalizer_with_wait_policy(
        state: Arc<FakeDurableState>,
        tree: Arc<FakeTree>,
        recheck_interval: Duration,
        deadline: Duration,
    ) -> RethCeFinalizer {
        let state: Arc<dyn DurableCeState> = state;
        let tree: Arc<dyn FinalizedCeTree> = tree;
        RethCeFinalizer::with_wait_policy(
            state,
            tree,
            CePersistenceWaitPolicy {
                recheck_interval,
                deadline,
            },
        )
    }

    #[tokio::test]
    async fn waits_for_exact_persistence_before_applying_tree() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, persisted_tx) = FakeDurableState::new();
        let tree = FakeTree::new(Some(staged));
        let finalizer = Arc::new(finalizer(state.clone(), tree.clone()));

        let task = {
            let finalizer = finalizer.clone();
            tokio::spawn(async move { finalizer.commit(finalized_block()).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(tree.attempts(), 0);

        state.set(1, hash(2), root);
        persisted_tx
            .unbounded_send(BlockNumHash::new(1, hash(2)))
            .unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(tree.attempts(), 1);
    }

    #[tokio::test]
    async fn missing_persistence_notification_recovers_from_durable_state() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, _persisted_tx_kept_open) = FakeDurableState::new();
        let tree = FakeTree::new(Some(staged));
        let finalizer = Arc::new(finalizer_with_wait_policy(
            state.clone(),
            tree.clone(),
            Duration::from_millis(5),
            Duration::from_millis(100),
        ));

        let commit = {
            let finalizer = finalizer.clone();
            tokio::spawn(async move { finalizer.commit(finalized_block()).await })
        };
        tokio::task::yield_now().await;

        // Model a lost/coalesced persistence notification: the canonical block
        // is now DB-visible, but no stream item wakes the already-waiting
        // finalizer to perform its DB-only recheck.
        state.set(1, hash(2), root);
        assert!(state.block_and_root(1).unwrap().is_some());

        tokio::time::timeout(Duration::from_millis(250), commit)
            .await
            .expect("durable DB recheck must produce a bounded outcome")
            .expect("commit task must not panic")
            .expect("exact durable state must recover online");
        assert_eq!(tree.attempts(), 1);
    }

    #[tokio::test]
    async fn persistence_notification_before_db_visibility_waits_for_durable_state() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, persisted_tx) = FakeDurableState::new();
        let tree = FakeTree::new(Some(staged));
        let finalizer = Arc::new(finalizer_with_wait_policy(
            state.clone(),
            tree.clone(),
            Duration::from_millis(5),
            Duration::from_millis(100),
        ));

        let commit = {
            let finalizer = finalizer.clone();
            tokio::spawn(async move { finalizer.commit(finalized_block()).await })
        };
        tokio::task::yield_now().await;
        persisted_tx
            .unbounded_send(BlockNumHash::new(1, hash(2)))
            .unwrap();
        tokio::task::yield_now().await;
        assert!(!commit.is_finished());
        assert_eq!(tree.attempts(), 0);

        state.set(1, hash(2), root);
        tokio::time::timeout(Duration::from_millis(250), commit)
            .await
            .expect("DB recheck must observe state published after its notification")
            .expect("commit task must not panic")
            .expect("exact durable state must complete the finalization");
        assert_eq!(tree.attempts(), 1);
    }

    #[tokio::test]
    async fn missing_durable_persistence_fails_at_deadline_without_tree_apply() {
        let staged = candidate();
        let (state, _persisted_tx_kept_open) = FakeDurableState::new();
        let tree = FakeTree::new(Some(staged));
        let finalizer = finalizer_with_wait_policy(
            state,
            tree.clone(),
            Duration::from_millis(5),
            Duration::from_millis(25),
        );

        let error = tokio::time::timeout(
            Duration::from_millis(250),
            finalizer.commit(finalized_block()),
        )
        .await
        .expect("missing durable state must fail within its configured deadline")
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("finalized CE persistence deadline exceeded"));
        assert!(message.contains("after 25ms"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn coalesced_later_notification_rechecks_exact_target_in_db() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, persisted_tx) = FakeDurableState::new();
        let tree = FakeTree::new(Some(staged));
        let finalizer = Arc::new(finalizer(state.clone(), tree.clone()));

        let task = {
            let finalizer = finalizer.clone();
            tokio::spawn(async move { finalizer.commit(finalized_block()).await })
        };
        tokio::task::yield_now().await;
        state.set(1, hash(2), root);
        persisted_tx
            .unbounded_send(BlockNumHash::new(4, hash(4)))
            .unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(tree.attempts(), 1);
    }

    #[tokio::test]
    async fn same_height_speculative_persistence_waits_for_finalized_replacement() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, persisted_tx) = FakeDurableState::new();
        state.set(1, hash(9), root);
        let tree = FakeTree::new(Some(staged));
        let finalizer = Arc::new(finalizer_with_wait_policy(
            state.clone(),
            tree.clone(),
            Duration::from_millis(5),
            Duration::from_millis(100),
        ));

        let task = {
            let finalizer = finalizer.clone();
            tokio::spawn(async move { finalizer.commit(finalized_block()).await })
        };
        tokio::task::yield_now().await;

        // Reth may durably publish a speculative block at the target height
        // before consensus canonicalizes a different block at that height.
        persisted_tx
            .unbounded_send(BlockNumHash::new(1, hash(9)))
            .unwrap();
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "old same-height fork must not be fatal"
        );
        assert_eq!(tree.attempts(), 0);

        state.set(1, hash(2), root);
        persisted_tx
            .unbounded_send(BlockNumHash::new(1, hash(2)))
            .unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(tree.attempts(), 1);
    }

    #[tokio::test]
    async fn same_height_speculative_state_fails_only_at_deadline() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, _persisted_tx_kept_open) = FakeDurableState::new();
        state.set(1, hash(7), root);
        let tree = FakeTree::new(Some(staged));
        let error = finalizer_with_wait_policy(
            state,
            tree.clone(),
            Duration::from_millis(5),
            Duration::from_millis(25),
        )
        .commit(finalized_block())
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("finalized CE persistence deadline exceeded"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn redelivery_with_durable_hash_conflict_fails_before_tree_apply() {
        let root = candidate().new_root();
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(7), root);
        let tree = FakeTree::committed();
        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("canonical conflict"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn durable_root_mismatch_fails_before_tree_apply() {
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), hash(8));
        let tree = FakeTree::new(Some(candidate()));
        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("root conflict"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn missing_durable_header_root_fails_before_tree_apply() {
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), hash(7));
        state.set_header_root(1, None);
        let tree = FakeTree::new(Some(candidate()));
        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("missing CE root artifact"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn wrong_durable_header_scheme_fails_before_tree_apply() {
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), hash(7));
        state.set_header_root(
            1,
            Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME + 1,
                r_sealed: hash(7),
            }),
        );
        let tree = FakeTree::new(Some(candidate()));
        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("scheme mismatch"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn durable_header_evm_root_mismatch_fails_before_tree_apply() {
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), hash(7));
        state.set_header_root(
            1,
            Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                r_sealed: hash(8),
            }),
        );
        let tree = FakeTree::new(Some(candidate()));
        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("header/EVM CE root mismatch"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn missing_validator_candidate_is_reconstructed_from_durable_receipts() {
        let (state, _tx) = FakeDurableState::new();
        let root = hash(9);
        state.set(1, hash(2), root);
        state.set_replay(CanonicalCeReplayBlock {
            number: 1,
            hash: hash(2),
            parent_hash: hash(1),
            parent_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
            new_root: root,
            events: Vec::new(),
            retirements: Vec::new(),
        });
        let tree = FakeTree::new(None);
        finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap();
        assert_eq!(tree.attempts(), 1);
    }

    #[tokio::test]
    async fn durable_replay_applies_a_real_event_through_smt_and_mdbx() {
        let (_directory, service) = real_tree_service();
        let mut id_bytes = [7_u8; 32];
        id_bytes[..4].copy_from_slice(&1_u32.to_be_bytes());
        let entity = EntityRef::Tribute(WwdEntityId::try_from(id_bytes.as_slice()).unwrap());
        let commitment = Commitment::try_from([3_u8; 32]).unwrap();
        let parent = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: hash(1),
                root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
            })
            .unwrap();
        let expected_root = parent
            .prepare_seal(
                1,
                &[FinalLeafMutation {
                    entity,
                    final_leaf: Some(commitment),
                }],
                &[],
            )
            .unwrap()
            .new_root();

        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), expected_root);
        state.set_replay(CanonicalCeReplayBlock {
            number: 1,
            hash: hash(2),
            parent_hash: hash(1),
            parent_root: outbe_compressed_entities::sealed_root(B256::ZERO).unwrap(),
            new_root: expected_root,
            events: vec![outbe_compressed_entities::CanonicalBodyEvent {
                entity,
                previous: None,
                next: Some(commitment),
            }],
            retirements: Vec::new(),
        });
        let tree: Arc<dyn FinalizedCeTree> = service.clone();
        RethCeFinalizer::new(state, tree)
            .commit(finalized_block())
            .await
            .unwrap();

        assert_eq!(service.finalized_marker().unwrap().new_root, expected_root);
        let reopened = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 1,
                block_hash: hash(2),
                root: expected_root,
            })
            .unwrap();
        assert_eq!(
            reopened.read_leaf_verified(entity, expected_root).unwrap(),
            Some(commitment)
        );
    }

    #[test]
    fn durable_replay_reconstructs_partition_retirement_through_smt_and_mdbx() {
        let (_directory, service) = real_tree_service();
        let mut id_bytes = [7_u8; 32];
        id_bytes[..4].copy_from_slice(&20_260_717_u32.to_be_bytes());
        let id = WwdEntityId::try_from(id_bytes.as_slice()).unwrap();
        let day = id.worldwide_day();
        let entity = EntityRef::Tribute(id);
        let commitment = Commitment::try_from([3_u8; 32]).unwrap();
        let genesis_root = outbe_compressed_entities::sealed_root(B256::ZERO).unwrap();

        let block_one_root = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: hash(1),
                root: genesis_root,
            })
            .unwrap()
            .prepare_seal(
                1,
                &[FinalLeafMutation {
                    entity,
                    final_leaf: Some(commitment),
                }],
                &[],
            )
            .unwrap()
            .new_root();
        crate::ce_recovery::apply_replayed_block(
            &service,
            &CanonicalCeReplayBlock {
                number: 1,
                hash: hash(2),
                parent_hash: hash(1),
                parent_root: genesis_root,
                new_root: block_one_root,
                events: vec![outbe_compressed_entities::CanonicalBodyEvent {
                    entity,
                    previous: None,
                    next: Some(commitment),
                }],
                retirements: Vec::new(),
            },
        )
        .unwrap();

        let block_two_root = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 1,
                block_hash: hash(2),
                root: block_one_root,
            })
            .unwrap()
            .prepare_seal(
                2,
                &[],
                &[outbe_compressed_entities::PartitionRef::TributeWwd(day)],
            )
            .unwrap()
            .new_root();
        crate::ce_recovery::apply_replayed_block(
            &service,
            &CanonicalCeReplayBlock {
                number: 2,
                hash: hash(3),
                parent_hash: hash(2),
                parent_root: block_one_root,
                new_root: block_two_root,
                events: Vec::new(),
                retirements: vec![outbe_compressed_entities::PartitionRef::TributeWwd(day)],
            },
        )
        .unwrap();

        assert_eq!(service.finalized_marker().unwrap().new_root, block_two_root);
        let reopened = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 2,
                block_hash: hash(3),
                root: block_two_root,
            })
            .unwrap();
        assert_eq!(
            reopened.read_leaf_verified(entity, block_two_root).unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn redelivery_after_ce_commit_before_ack_is_idempotent_without_candidate() {
        let root = candidate().new_root();
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), root);
        let tree = FakeTree::committed();

        finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap();

        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn redelivery_rejects_a_corrupted_marker_parent_root() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), root);
        let mut marker = staged.marker(ACTIVE_COMMITMENT_SCHEME);
        marker.parent_root = hash(8);
        let tree = Arc::new(FakeTree {
            candidate: None,
            marker,
            attempts: Mutex::new(Vec::new()),
            apply_error: false,
        });

        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("parent identity conflicts"));
        assert_eq!(tree.attempts(), 0);
    }

    #[tokio::test]
    async fn tree_apply_failure_is_propagated_without_success() {
        let staged = candidate();
        let root = staged.new_root();
        let (state, _tx) = FakeDurableState::new();
        state.set(1, hash(2), root);
        let tree = FakeTree::failing(staged);
        let error = finalizer(state, tree.clone())
            .commit(finalized_block())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("uncertain commit outcome"));
        assert_eq!(tree.attempts(), 1);
    }
}
