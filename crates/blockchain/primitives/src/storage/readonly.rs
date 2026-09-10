//! Read-only storage provider backed by a Reth StateProvider.
//!
//! Used by the consensus layer to read precompile state (e.g., the ValidatorSet
//! contract) at a specific block height without going through the EVM.
//! Only `sload()` is functional; all write operations are no-ops.

use alloy_primitives::{Address, LogData, B256, U256};
use revm::{
    context::journaled_state::JournalCheckpoint,
    state::{AccountInfo, Bytecode},
};

use crate::error::{PrecompileError, Result};

/// Trait for reading storage values - abstracts over Reth's `StateProvider`.
///
/// Introduced so `ReadOnlyStorageProvider` doesn't depend on Reth directly
/// (keeping `outbe-primitives` lightweight).
pub trait StorageReader {
    /// Read a storage value. Returns `U256::ZERO` if the slot is empty.
    fn read_storage(&self, address: Address, key: B256) -> Result<U256>;

    /// Read the canonical block hash for `number`, or `None` if `number`
    /// is outside the chain's canonical-history window (e.g. ahead of the
    /// current head, or pruned past retention).
    ///
    /// this is read-only access used by RPC views that
    /// want to expose canonical history. The default returns `Ok(None)`
    /// because most `StorageReader` users (txpool admission, consensus
    /// validator-set reads) do not bridge block hashes at all and answering
    /// "I don't know" through this surface is honest - the canonical
    /// answer for `submit_invalid_vrf_evidence` lives on
    /// `PrecompileStorageProvider::canonical_block_hash`, which has no
    /// default and must be implemented by every production provider.
    fn read_canonical_block_hash(&self, _number: u64) -> Result<Option<B256>> {
        Ok(None)
    }
}

/// Read-only [`PrecompileStorageProvider`](super::PrecompileStorageProvider) for
/// consensus-layer reads of precompile state.
///
/// Exact immutable block context for state reads whose answer depends on the
/// execution environment as well as storage slots.
///
/// Callers must source every field from the same canonical block and the
/// immutable chain specification. A zero/default context is intentionally kept
/// distinct from this type so consensus-sensitive readers can reject it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnlyBlockContext {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub block_number: u64,
    pub timestamp: u64,
}

impl ReadOnlyBlockContext {
    #[must_use]
    pub fn is_complete(self) -> bool {
        self.chain_id != 0
            && !self.genesis_hash.is_zero()
            && self.block_number != 0
            && self.timestamp != 0
    }
}

/// Only `sload()` works - all write operations are rejected. Context-free
/// constructors retain zero block fields for pure storage reads; readers whose
/// answer depends on time or height must require [`ReadOnlyBlockContext`].
pub struct ReadOnlyStorageProvider<R> {
    reader: R,
    chain_id: u64,
    genesis_hash: B256,
    block_number: u64,
    timestamp: u64,
}

impl<R: StorageReader> ReadOnlyStorageProvider<R> {
    /// Create a new read-only provider from a storage reader.
    pub fn new(reader: R) -> Self {
        Self::new_with_chain_identity(reader, 0, B256::ZERO)
    }

    /// Create a read-only provider bound to an explicit immutable chain
    /// identity. Consensus/follower callers that need contextual views use
    /// this constructor with values sourced from ChainSpec.
    pub fn new_with_chain_identity(reader: R, chain_id: u64, genesis_hash: B256) -> Self {
        Self {
            reader,
            chain_id,
            genesis_hash,
            block_number: 0,
            timestamp: 0,
        }
    }

    /// Create a read-only provider bound to one exact canonical block context.
    #[must_use]
    pub const fn new_with_block_context(reader: R, context: ReadOnlyBlockContext) -> Self {
        Self {
            reader,
            chain_id: context.chain_id,
            genesis_hash: context.genesis_hash,
            block_number: context.block_number,
            timestamp: context.timestamp,
        }
    }
}

impl<R: StorageReader> super::PrecompileStorageProvider for ReadOnlyStorageProvider<R> {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn genesis_hash(&self) -> B256 {
        self.genesis_hash
    }

    fn timestamp(&self) -> U256 {
        U256::from(self.timestamp)
    }

    fn beneficiary(&self) -> Address {
        Address::ZERO
    }

    fn block_number(&self) -> u64 {
        self.block_number
    }

    fn canonical_block_hash(&mut self, number: u64) -> Result<Option<B256>> {
        self.reader.read_canonical_block_hash(number)
    }

    fn set_code(&mut self, _address: Address, _code: Bytecode) -> Result<()> {
        Err(PrecompileError::Fatal(
            "read-only: set_code not supported".into(),
        ))
    }

    fn account_info(&mut self, _address: Address) -> Result<AccountInfo> {
        Ok(AccountInfo::default())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
        let key_b256 = B256::from(key.to_be_bytes());
        self.reader.read_storage(address, key_b256)
    }

    fn tload(&mut self, _address: Address, _key: U256) -> Result<U256> {
        Ok(U256::ZERO)
    }

    fn sstore(&mut self, _address: Address, _key: U256, _value: U256) -> Result<()> {
        Err(PrecompileError::Fatal(
            "read-only: sstore not supported".into(),
        ))
    }

    fn tstore(&mut self, _address: Address, _key: U256, _value: U256) -> Result<()> {
        Err(PrecompileError::Fatal(
            "read-only: tstore not supported".into(),
        ))
    }

    fn emit_event(&mut self, _address: Address, _event: LogData) -> Result<()> {
        Ok(())
    }

    fn deduct_gas(&mut self, _gas: u64) -> Result<()> {
        Ok(())
    }

    fn refund_gas(&mut self, _gas: i64) {}

    fn gas_used(&self) -> u64 {
        0
    }

    fn gas_refunded(&self) -> i64 {
        0
    }

    fn is_static(&self) -> bool {
        true
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        JournalCheckpoint {
            journal_i: 0,
            log_i: 0,
            selfdestructed_i: 0,
        }
    }

    fn checkpoint_commit(&mut self) {}

    fn checkpoint_revert(&mut self, _checkpoint: JournalCheckpoint) {}

    fn transfer_balance(&mut self, _from: Address, _to: Address, _amount: U256) -> Result<()> {
        Err(PrecompileError::Fatal(
            "read-only: transfer_balance not supported".into(),
        ))
    }

    fn increase_balance(&mut self, _address: Address, _amount: U256) -> Result<()> {
        Err(PrecompileError::Fatal(
            "read-only: increase_balance not supported".into(),
        ))
    }

    fn decrease_balance(&mut self, _address: Address, _amount: U256) -> Result<()> {
        Err(PrecompileError::Fatal(
            "read-only: decrease_balance not supported".into(),
        ))
    }
}
