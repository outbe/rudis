pub mod direct;
pub mod dsl;
pub mod evm;
pub mod gas;
pub mod handle;
pub mod hashmap;
pub mod lysis_activation;
mod metadosis_mutation;
pub mod readonly;
pub mod types;

pub use handle::StorageHandle;
pub use lysis_activation::CertifiedLysisActivation;
pub use metadosis_mutation::{
    metadosis_advance_due_binding, metadosis_cycle_allocation_binding,
    metadosis_init_genesis_binding, metadosis_late_settlement_binding,
    metadosis_ocomp_lifecycle_begin_binding, metadosis_ocomp_terminal_request_binding,
    metadosis_process_ready_binding, metadosis_verified_vote_binding, MetadosisCertifiedFinality,
    MetadosisCertifiedFinalityBinding, MetadosisCycleLifecycle, MetadosisForkProfile,
    MetadosisMutationEntitlements, MetadosisMutationPurpose, MetadosisMutationPurposeTag,
    MetadosisOcompLifecycle, MetadosisVerifiedResultVote,
};
pub use revm::state::{AccountInfo, Bytecode};
pub use types::{Mapping, Slot, Storable, StorableType, StorageKey, StorageOps};

use alloy_primitives::{Address, Bytes, LogData, B256, U256};
use revm::{context::journaled_state::JournalCheckpoint, context::result::HaltReason};

use crate::error::Result;

// === Sub-call API surface (T(-0.5) stub types) ===
//
// Compile-only types shipped to lock the API contract for
// outbe-precompile authors integrating sub-call code in parallel with the
// backend implementation (T0..T7). Real bodies for `StorageHandle::call` /
// `staticcall` land in T4 (STATICCALL driver) and T6 (CALL driver) without
// changing the signatures defined here.

/// Input to a sub-call dispatched from a Rust precompile.
///
/// Placeholder shape; T1 may add fields. Real sub-call driver consumes this in
/// `run_sub_call_impl(ctx, input, ...)` (T4/T5).
#[derive(Debug, Clone)]
pub struct SubCallInput {
    /// Target contract address.
    pub target: Address,
    /// Native token value to transfer (zero for STATICCALL).
    pub value: U256,
    /// ABI-encoded calldata for the target.
    pub calldata: Bytes,
    /// Gas limit to forward to the child frame (`u64::MAX` requests
    /// EIP-150 forward-all behaviour).
    pub gas_limit: u64,
    /// Whether the child frame must execute under STATICCALL semantics.
    pub is_static: bool,
}

/// Outcome of a sub-call as observed by the caller.
#[derive(Debug, Clone)]
pub enum SubCallStatus {
    /// Child frame returned normally.
    Success,
    /// Child frame reverted; raw returndata preserved.
    Revert(Bytes),
    /// Child frame halted; structured reason forwarded.
    Halt(SubCallError),
}

/// Result of a sub-call, including status, returndata and gas accounting.
#[derive(Debug, Clone)]
pub struct SubCallOutput {
    /// Terminal status of the sub-call.
    pub status: SubCallStatus,
    /// Bytes returned by the child frame (may be empty).
    pub returndata: Bytes,
    /// Gas consumed by the child frame.
    pub gas_used: u64,
    /// Refund accumulated by the child frame on Success (zero on Revert/Halt).
    pub gas_refunded: i64,
}

impl SubCallOutput {
    /// Constructs the stub-default success output:
    /// `{ status: Success, returndata: empty, gas_used: 0, gas_refunded: 0 }`.
    ///
    /// Used by T(-0.5) stub methods on `StorageHandle` until T4/T6 land real
    /// behaviour. MUST NOT be used in production sub-call paths.
    pub fn default_success() -> Self {
        Self {
            status: SubCallStatus::Success,
            returndata: Bytes::new(),
            gas_used: 0,
            gas_refunded: 0,
        }
    }
}

/// Sub-call failure modes.
///
/// Intentionally NOT marked `#[non_exhaustive]` at T(-0.5); T4/T6 may revisit
/// once real dispatch is wired.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SubCallError {
    /// Provider does not implement sub-call (default trait method).
    #[error("sub-call not available")]
    NotAvailable,
    /// `StorageHandle::with_provider` re-entered through the sub-call callback.
    #[error("storage provider already borrowed")]
    ProviderBorrowed,
    /// Underlying database error from the child frame.
    #[error("database error: {0}")]
    DatabaseError(String),
    /// Unrecoverable error in the sub-call driver.
    #[error("fatal: {0}")]
    Fatal(String),
    /// Child frame ran out of gas.
    #[error("out of gas")]
    OutOfGas,
    /// Call stack would exceed `CALL_STACK_LIMIT` (1024).
    #[error("depth limit exceeded")]
    DepthLimitExceeded,
    /// Attempted `Call` with `value > 0` inside outer static context.
    #[error("static context violation")]
    StaticContextViolation,
    /// Target address is invalid for the requested call kind.
    #[error("invalid target")]
    InvalidTarget,
    /// Sub-call feature gated by an activation block not yet reached.
    /// Reserved for the future "Sub-call activation gate (mainnet migration)" Epic.
    #[error("sub-call not activated")]
    NotActivated,
    /// Child frame attempted state mutation under STATICCALL.
    #[error("state change during static call")]
    StateChangeDuringStaticCall,
    /// Child frame halted with a revm halt reason.
    #[error("evm halt: {0:?}")]
    EvmHalt(HaltReason),
}

/// RAII guard for atomic state mutation batching.
///
/// On drop, automatically reverts all state changes made since the checkpoint
/// unless [`CheckpointGuard::commit`] was called.
pub struct CheckpointGuard<'storage> {
    storage: StorageHandle<'storage>,
    checkpoint: Option<revm::context::journaled_state::JournalCheckpoint>,
}

impl<'storage> CheckpointGuard<'storage> {
    pub(crate) fn new(
        storage: StorageHandle<'storage>,
        checkpoint: revm::context::journaled_state::JournalCheckpoint,
    ) -> Self {
        Self {
            storage,
            checkpoint: Some(checkpoint),
        }
    }

    pub fn commit(mut self) {
        if self.checkpoint.take().is_some() {
            self.storage.checkpoint_commit();
        }
    }
}

impl Drop for CheckpointGuard<'_> {
    fn drop(&mut self) {
        if let Some(checkpoint) = self.checkpoint.take() {
            self.storage.checkpoint_revert(checkpoint);
        }
    }
}

/// Typed facade that can be constructed from explicit runtime storage.
///
/// The `#[contract]` macro implements this trait for module contract/storage
/// facades with a fixed default address. Runtime code can then use
/// [`StorageHandle::contract`] without hiding the storage dependency.
pub trait StorageBacked<'storage>: Sized {
    const DEFAULT_ADDRESS: Address;

    fn at(storage: StorageHandle<'storage>, address: Address) -> Self;

    fn new(storage: StorageHandle<'storage>) -> Self {
        Self::at(storage, Self::DEFAULT_ADDRESS)
    }
}

/// Low-level storage provider for interacting with the EVM.
///
/// # Implementations
///
/// - [`evm::EvmStorageProvider`] - Production EVM storage via `EvmInternals`
/// - [`hashmap::HashMapStorageProvider`] - Test storage
///
/// Runtime code reaches providers through explicit [`StorageHandle`] values
/// created by precompile, transaction, or block lifecycle entrypoints.
pub trait PrecompileStorageProvider {
    /// Opens one exact Metadosis mutation frame for the current executor route.
    ///
    /// Providers deny this by default. Implementations must reject nested
    /// mutation and any purpose not entitled by the authenticated route.
    fn begin_metadosis_mutation_frame(
        &mut self,
        _purpose: MetadosisMutationPurposeTag,
        _binding: B256,
        _chain_id: u64,
        _block_number: u64,
    ) -> Result<()> {
        Err(crate::error::PrecompileError::Fatal(
            "Metadosis mutation frame is not available".into(),
        ))
    }

    /// Closes the exact Metadosis mutation frame opened above.
    fn finish_metadosis_mutation_frame(
        &mut self,
        _purpose: MetadosisMutationPurposeTag,
        _binding: B256,
        _completed: bool,
    ) -> Result<()> {
        Err(crate::error::PrecompileError::Fatal(
            "Metadosis mutation frame is not available".into(),
        ))
    }

    /// Opens the private execution lease for one certified Lysis activation.
    ///
    /// Providers deny this by default. The production EVM execution context
    /// grants the lease only from the fork-pinned activation dispatch.
    fn begin_lysis_activation_frame(&mut self, _activation_call_id: B256) -> Result<()> {
        Err(crate::error::PrecompileError::Fatal(
            "certified Lysis activation frame is not available".into(),
        ))
    }

    /// Closes a previously granted Lysis activation lease.
    ///
    /// `completed` is true only after the fixed Nod, contributor, carry-over,
    /// Tribute and terminal cursor has been consumed in order.
    fn finish_lysis_activation_frame(
        &mut self,
        _activation_call_id: B256,
        _completed: bool,
    ) -> Result<()> {
        Err(crate::error::PrecompileError::Fatal(
            "certified Lysis activation frame is not available".into(),
        ))
    }

    /// Returns the chain ID.
    fn chain_id(&self) -> u64;

    /// Returns the immutable genesis block hash for this execution context.
    ///
    /// Production providers source this from the canonical `ChainSpec`; it is
    /// never accepted from transaction calldata or mutable contract storage.
    fn genesis_hash(&self) -> B256;

    /// Returns the current block timestamp.
    fn timestamp(&self) -> U256;

    /// Test fixtures only: advance the provider's reported block timestamp.
    ///
    /// Production providers (EVM) own block time and ignore this call; the
    /// default no-op preserves that invariant. The in-memory test provider
    /// (`HashMapStorageProvider`) overrides this to drive `timestamp()` from
    /// inside a `StorageHandle::enter` scope, so per-block lifecycle tests can
    /// advance time without splitting the enter block.
    fn set_block_timestamp(&mut self, _timestamp: U256) {}

    /// Returns the current block beneficiary (coinbase).
    fn beneficiary(&self) -> Address;

    /// Returns the current block number.
    fn block_number(&self) -> u64;

    /// Returns the canonical block hash for `number`, or `None` if `number`
    /// is outside the chain's canonical-history window (e.g. ahead of the
    /// current head, or pruned past retention).
    ///
    /// `SlashIndicator::submit_invalid_vrf_evidence`
    /// rejects evidence whose `parent_block_hash` is not the canonical hash
    /// at `parent_block_number`. No default impl on purpose - every storage
    /// provider must answer this question explicitly so a missing override
    /// cannot silently accept side-chain evidence.
    fn canonical_block_hash(&mut self, number: u64) -> Result<Option<alloy_primitives::B256>>;

    /// Sets the bytecode at the given address.
    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()>;

    /// Returns the account info for the given address.
    fn account_info(&mut self, address: Address) -> Result<AccountInfo>;

    /// Performs an SLOAD operation (persistent storage read).
    fn sload(&mut self, address: Address, key: U256) -> Result<U256>;

    /// Performs a TLOAD operation (transient storage read).
    fn tload(&mut self, address: Address, key: U256) -> Result<U256>;

    /// Performs an SSTORE operation (persistent storage write).
    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()>;

    /// Performs a TSTORE operation (transient storage write).
    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()>;

    /// Emits an event from the given contract address.
    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()>;

    /// Deducts gas from the remaining gas and returns an error if insufficient.
    fn deduct_gas(&mut self, gas: u64) -> Result<()>;

    /// Add refund to the refund gas counter.
    fn refund_gas(&mut self, gas: i64);

    /// Returns the gas used so far.
    fn gas_used(&self) -> u64;

    /// Returns the gas refunded so far.
    fn gas_refunded(&self) -> i64;

    /// Returns whether the current call context is static.
    fn is_static(&self) -> bool;

    /// Creates a new journal checkpoint.
    fn checkpoint(&mut self) -> JournalCheckpoint;

    /// Commits all state changes since the last checkpoint.
    fn checkpoint_commit(&mut self);

    /// Reverts all state changes back to the given checkpoint.
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint);

    /// Transfers native token balance from one address to another.
    ///
    /// Decrements `from` balance by `amount` and increments `to` balance by `amount`.
    /// Returns an error if `from` has insufficient balance.
    fn transfer_balance(&mut self, from: Address, to: Address, amount: U256) -> Result<()>;

    /// Increases the native token balance of an address (minting).
    ///
    /// Used by system hooks (e.g., block reward emission) to mint new tokens
    /// to a contract address. No source is debited - this creates new supply.
    fn increase_balance(&mut self, address: Address, amount: U256) -> Result<()>;

    /// Decreases the native token balance of an address (burning).
    ///
    /// Used by slashing and other system hooks to destroy tokens.
    /// Returns an error if the address has insufficient balance.
    fn decrease_balance(&mut self, address: Address, amount: U256) -> Result<()>;

    /// Synchronous Rust -> Solidity sub-call.
    ///
    /// Default body returns [`SubCallError::NotAvailable`]; concrete
    /// providers wired to the sub-call driver override with a real implementation that
    /// routes through `run_sub_call_impl`. Test / read-only / block-level
    /// providers may keep the default.
    fn sub_call(
        &mut self,
        _input: SubCallInput,
    ) -> std::result::Result<SubCallOutput, SubCallError> {
        Err(SubCallError::NotAvailable)
    }
}

/// Storage operations for a given (contract) address.
///
/// Abstracts over persistent storage (SLOAD/SSTORE) and transient storage (TLOAD/TSTORE).
pub trait StorageOpsTrait {
    /// Stores a value at the provided slot.
    fn store(&mut self, slot: U256, value: U256) -> Result<()>;
    /// Loads a value from the provided slot.
    fn load(&self, slot: U256) -> Result<U256>;
}
