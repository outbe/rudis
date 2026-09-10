//! Startup invariants required by the finalized compressed-entity tree.

use thiserror::Error;

/// Reth/Marshal settings that determine whether a finalized CE batch can be
/// committed only after a real per-block execution persistence barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedStorageRuntimeConfig {
    pub persistence_threshold: u64,
    pub memory_block_buffer_target: u64,
    pub max_pending_acks: usize,
    pub receipts_pruning_enabled: bool,
    pub account_history_pruning_enabled: bool,
    pub storage_history_pruning_enabled: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CompressedStorageConfigError {
    #[error("compressed storage requires --engine.persistence-threshold=0, got {actual}")]
    PersistenceThreshold { actual: u64 },
    #[error("compressed storage requires --engine.memory-block-buffer-target=0, got {actual}")]
    MemoryBlockBufferTarget { actual: u64 },
    #[error("compressed storage requires consensus MAX_PENDING_ACKS=1, got {actual}")]
    PendingAcks { actual: usize },
    #[error("compressed storage recovery requires receipt pruning to be disabled")]
    ReceiptsPruningEnabled,
    #[error("compressed storage recovery requires account-history pruning to be disabled")]
    AccountHistoryPruningEnabled,
    #[error("compressed storage recovery requires storage-history pruning to be disabled")]
    StorageHistoryPruningEnabled,
}

/// Rejects configurations that could acknowledge finalization before both
/// durable Reth state and the CE tree marker have advanced for the same block.
pub fn validate_compressed_storage_runtime_config(
    config: CompressedStorageRuntimeConfig,
) -> Result<(), CompressedStorageConfigError> {
    if config.persistence_threshold != 0 {
        return Err(CompressedStorageConfigError::PersistenceThreshold {
            actual: config.persistence_threshold,
        });
    }
    if config.memory_block_buffer_target != 0 {
        return Err(CompressedStorageConfigError::MemoryBlockBufferTarget {
            actual: config.memory_block_buffer_target,
        });
    }
    if config.max_pending_acks != 1 {
        return Err(CompressedStorageConfigError::PendingAcks {
            actual: config.max_pending_acks,
        });
    }
    if config.receipts_pruning_enabled {
        return Err(CompressedStorageConfigError::ReceiptsPruningEnabled);
    }
    if config.account_history_pruning_enabled {
        return Err(CompressedStorageConfigError::AccountHistoryPruningEnabled);
    }
    if config.storage_history_pruning_enabled {
        return Err(CompressedStorageConfigError::StorageHistoryPruningEnabled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> CompressedStorageRuntimeConfig {
        CompressedStorageRuntimeConfig {
            persistence_threshold: 0,
            memory_block_buffer_target: 0,
            max_pending_acks: 1,
            receipts_pruning_enabled: false,
            account_history_pruning_enabled: false,
            storage_history_pruning_enabled: false,
        }
    }

    #[test]
    fn exact_per_block_barrier_without_pruning_is_accepted() {
        validate_compressed_storage_runtime_config(valid()).unwrap();
    }

    #[test]
    fn every_incompatible_durability_setting_fails_startup() {
        let mut cases = Vec::new();

        let mut persistence = valid();
        persistence.persistence_threshold = 1;
        cases.push((
            persistence,
            CompressedStorageConfigError::PersistenceThreshold { actual: 1 },
        ));

        let mut memory = valid();
        memory.memory_block_buffer_target = 1;
        cases.push((
            memory,
            CompressedStorageConfigError::MemoryBlockBufferTarget { actual: 1 },
        ));

        let mut pending = valid();
        pending.max_pending_acks = 2;
        cases.push((
            pending,
            CompressedStorageConfigError::PendingAcks { actual: 2 },
        ));

        let mut receipts = valid();
        receipts.receipts_pruning_enabled = true;
        cases.push((
            receipts,
            CompressedStorageConfigError::ReceiptsPruningEnabled,
        ));

        let mut accounts = valid();
        accounts.account_history_pruning_enabled = true;
        cases.push((
            accounts,
            CompressedStorageConfigError::AccountHistoryPruningEnabled,
        ));

        let mut storage = valid();
        storage.storage_history_pruning_enabled = true;
        cases.push((
            storage,
            CompressedStorageConfigError::StorageHistoryPruningEnabled,
        ));

        for (config, expected) in cases {
            assert_eq!(
                validate_compressed_storage_runtime_config(config),
                Err(expected)
            );
        }
    }
}
