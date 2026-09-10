use alloy_primitives::{Address, B256};
use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::schema::ValidatorSet;
use crate::state::{self, CommitteeSnapshot};

/// Returns `true` if an epoch boundary has been reached at the given block height.
///
/// Does NOT transition the epoch - the caller is responsible for orchestrating
/// the full epoch transition sequence (distribute rewards, reset slash counters,
/// then call `transition_epoch`).
pub fn is_epoch_boundary(storage: StorageHandle, block_number: u64) -> Result<bool> {
    let vs = ValidatorSet::new(storage);
    let epoch_start_block = vs.epoch_start_block.read()?;
    let epoch_length_blocks = vs.config_epoch_length_blocks.read()?;

    if epoch_length_blocks == 0 {
        return Ok(false);
    }

    Ok(block_number >= epoch_start_block.saturating_add(epoch_length_blocks as u64))
}

/// Transitions to a new epoch: resets per-epoch counters, increments epoch number.
///
/// Should be called AFTER reward distribution and slash counter resets.
pub fn transition_epoch(storage: StorageHandle, timestamp: u64, block_number: u64) -> Result<()> {
    let mut vs = ValidatorSet::new(storage);
    vs.update_epoch(timestamp, block_number)
}

/// Resets ValidatorSet-owned outgoing-epoch counters without changing the
/// activated epoch anchor.
pub fn reset_epoch_counters(storage: StorageHandle) -> Result<()> {
    ValidatorSet::new(storage).reset_epoch_counters()
}

/// Advances the activated epoch anchor after its counters were reset by the
/// boundary-conditioned pre-execution path.
pub fn advance_epoch(storage: StorageHandle, timestamp: u64, block_number: u64) -> Result<()> {
    ValidatorSet::new(storage).advance_epoch(timestamp, block_number)
}

/// Called from post-execution: record the block's proposer.
pub fn record_proposer(storage: StorageHandle, beneficiary: Address) -> Result<()> {
    let mut vs = ValidatorSet::new(storage);
    // Only record if this address is a registered validator
    if vs.is_validator(beneficiary)? {
        vs.record_proposer(beneficiary)?;
    }
    Ok(())
}

/// Called from post-execution: record voter participation.
pub fn record_participation(
    storage: StorageHandle,
    voters: &[Address],
    absent: &[Address],
) -> Result<()> {
    if absent.is_empty() {
        return Ok(());
    }
    let mut vs = ValidatorSet::new(storage);
    vs.record_participation(voters, absent)?;
    Ok(())
}

/// Called from post-execution: record voter participation for a
/// historical (finalized-parent) committee. Accepts registered
/// validators that may no longer be current consensus participants.
///
/// Idempotent under metadata-tx replays: the
/// `finalized_participation_recorded[fb_hash]` guard short-circuits
/// the inner counter update so replays of the same metadata-tx do not
/// double-increment `val_missed_votes`. `fb_hash` is the finalized
/// block hash (`metadata.finalized_block_hash`).
pub fn record_finalized_participation(
    storage: StorageHandle,
    fb_hash: B256,
    voters: &[Address],
    absent: &[Address],
) -> Result<()> {
    if voters.is_empty() && absent.is_empty() {
        return Ok(());
    }
    let mut vs = ValidatorSet::new(storage);
    if vs.finalized_participation_recorded.read(&fb_hash)? {
        return Ok(());
    }
    vs.record_finalized_participation(voters, absent)?;
    vs.finalized_participation_recorded.write(&fb_hash, true)?;

    // Prune ring: bound the guard (slot 30) to the last
    // FINALIZED_PARTICIPATION_RETAIN finalized blocks. A finalized block older than
    // the K-block late-finalize window can never be replayed, so clearing the guard
    // flag of the block RETAIN records ago reclaims its slot without weakening the
    // replay protection for any block still inside the window.
    let seq = vs.finalized_participation_ring_seq.read()?;
    let idx = seq % FINALIZED_PARTICIPATION_RETAIN;
    let evicted = vs.finalized_participation_ring.read(&idx)?;
    if evicted != B256::ZERO && evicted != fb_hash {
        vs.finalized_participation_recorded.write(&evicted, false)?;
    }
    vs.finalized_participation_ring.write(&idx, fb_hash)?;
    vs.finalized_participation_ring_seq
        .write(seq.checked_add(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::Fatal(
                "finalized participation ring sequence overflow".into(),
            )
        })?)?;
    Ok(())
}

/// Number of recent finalized blocks whose participation guard (slot 30) stays
/// live. The replay horizon is the K-block late-finalize window, so retaining the
/// last `FINALIZED_PARTICIPATION_RETAIN` blocks is generous; older guard flags are
/// pruned by [`record_finalized_participation`]. Changing it is a hard fork.
pub const FINALIZED_PARTICIPATION_RETAIN: u64 = 64;

/// Inputs for the V2 atomic boundary activation hook.
///
/// `outgoing` is the snapshot of the committee that signed up to and
/// including the boundary block (epoch `outgoing_epoch`). It is `None`
/// for the genesis boundary (block 1), where there is no preceding epoch.
///
/// `incoming` is the snapshot of the committee that takes over after the
/// boundary (epoch `incoming_epoch`).
#[derive(Debug, Clone)]
pub struct BoundaryActivationInputs {
    pub outgoing: Option<(u64, CommitteeSnapshot)>,
    pub incoming_epoch: u64,
    pub incoming: CommitteeSnapshot,
    /// Historical EVM height at which consensus froze the target committee.
    /// Runtime transition validation uses this to distinguish a validator that
    /// exited or was jailed after the freeze from a malformed boundary that
    /// includes a validator already ineligible at the freeze height.
    pub freeze_height: u64,
    pub new_active_set: Vec<Address>,
    pub active_set_hash: B256,
    pub tee_expired_target_exclusions: Vec<Address>,
}

/// V2 atomic boundary activation.
///
///
///   1. Open a journal checkpoint (RAII guard).
///   2. Write the outgoing committee snapshot for epoch `N` (if any).
///   3. Apply the validated boundary transition to validator-set membership.
///   4. Write the incoming committee snapshot for epoch `N + 1`.
///   5. Commit the checkpoint.
///
/// If any step returns an error the guard drops without committing, so:
///
/// * no partial snapshot bytes survive,
/// * `active_consensus_set_hash` is not advanced,
/// * `pending_set_change` is not cleared.
///
/// Returns `(outgoing_snapshot_key, incoming_snapshot_key)`. The outgoing
/// key is `B256::ZERO` for the genesis boundary.
pub fn activate_boundary_atomic(
    storage: StorageHandle,
    inputs: &BoundaryActivationInputs,
) -> Result<(B256, B256)> {
    let guard = storage.checkpoint_guard();

    let outgoing_key = if let Some((outgoing_epoch, ref outgoing_snapshot)) = inputs.outgoing {
        let (_, key) =
            state::write_committee_snapshot(storage.clone(), outgoing_epoch, outgoing_snapshot)?;
        key
    } else {
        B256::ZERO
    };

    {
        let mut vs = ValidatorSet::new(storage.clone());
        vs.activate_validated_boundary_set_with_expiry_exclusions(
            &inputs.new_active_set,
            inputs.active_set_hash,
            inputs.freeze_height,
            &inputs.tee_expired_target_exclusions,
        )?;
    }

    let (_, incoming_key) =
        state::write_committee_snapshot(storage, inputs.incoming_epoch, &inputs.incoming)?;

    guard.commit();
    Ok((outgoing_key, incoming_key))
}
