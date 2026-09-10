use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::contract::Staking;

/// Called from pre-execution: processes matured unbonding entries.
///
/// All entries whose complete_time <= timestamp are zeroed out and
/// the queue is compacted via swap-remove.
pub fn process_unbonding(storage: StorageHandle, timestamp: u64) -> Result<()> {
    let mut staking = Staking::new(storage);
    staking.process_unbonding(timestamp)
}
