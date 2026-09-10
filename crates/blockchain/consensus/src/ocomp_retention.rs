//! Node-local OCOMP retention notifications emitted by consensus.
//!
//! This seam can withhold only this validator's proposal or positive vote. It
//! must never turn local retention health into block-invalidity or alter the
//! network quorum rule.

use crate::block::ConsensusBlock;

/// Failure to make a node-local OCOMP retention transition durable.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct OcompRetentionHookError {
    message: String,
}

impl OcompRetentionHookError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Narrow consensus-to-node seam for the one-entry PoC retention lifecycle.
pub trait OcompRetentionHook: Send + Sync {
    /// Make every OCOMP source pin in an execution-valid candidate durable
    /// before this validator advertises the proposal or emits a positive vote.
    fn prepare_candidate(&self, block: &ConsensusBlock) -> Result<(), OcompRetentionHookError>;

    /// Notify the node-owned retention worker that consensus finalized `block`.
    ///
    /// Production implementations must only enqueue the notification;
    /// provider reads, proof construction and journal I/O must run outside the
    /// consensus finalization actor. Enqueue failures are local OCOMP
    /// availability failures and never invalidate the finalized block.
    fn reconcile_finalized(&self, block: &ConsensusBlock) -> Result<(), OcompRetentionHookError>;
}

/// Run `ready` only after the node-local candidate transition is durable.
///
/// The verify path passes its positive-vote send as `ready`; tests use the
/// same function with a deterministic local consensus driver.
pub fn after_durable_candidate<T>(
    hook: &dyn OcompRetentionHook,
    block: &ConsensusBlock,
    ready: impl FnOnce() -> T,
) -> Result<T, OcompRetentionHookError> {
    hook.prepare_candidate(block)?;
    Ok(ready())
}

/// Default for consensus-only fixtures and nodes with OCOMP intentionally
/// unavailable. It does not change consensus behavior.
#[derive(Debug, Default)]
pub struct NoopOcompRetentionHook;

impl OcompRetentionHook for NoopOcompRetentionHook {
    fn prepare_candidate(&self, _block: &ConsensusBlock) -> Result<(), OcompRetentionHookError> {
        Ok(())
    }

    fn reconcile_finalized(&self, _block: &ConsensusBlock) -> Result<(), OcompRetentionHookError> {
        Ok(())
    }
}
