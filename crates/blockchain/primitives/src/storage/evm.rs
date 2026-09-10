use alloy_evm::EvmInternals;
use alloy_primitives::{Address, Log, LogData, B256, U256};
use revm::context::journaled_state::JournalCheckpoint;
use revm::context::Block;
use revm::context_interface::cfg::gas::{SSTORE_RESET, WARM_STORAGE_READ_COST};
use revm::state::{AccountInfo, Bytecode};
use revm::Database;

use crate::error::{PrecompileError, Result};
use crate::storage::gas::GasTracker;
use crate::storage::PrecompileStorageProvider;

/// Production EVM storage provider wrapping `EvmInternals` from alloy-evm.
///
/// Provides journaled access to persistent storage (sload/sstore), transient
/// storage (tload/tstore), logs, and balance movement for stateful precompiles.
///
/// Gas model: every sload/sstore is metered with the flat per-op costs
/// defined in [`crate::storage::gas`]. The precompile dispatcher in
/// `outbe-evm` charges [`crate::storage::gas::PRECOMPILE_BASE_GAS`] up front
/// and constructs the provider with the remaining gas budget via
/// [`EvmStorageProvider::new_with_gas`]. Dispatch code then derives actual
/// per-call gas used from [`EvmStorageProvider::gas_remaining`].
pub struct EvmStorageProvider<'a> {
    internals: EvmInternals<'a>,
    gas: GasTracker,
    is_static: bool,
    genesis_hash: B256,
}

impl<'a> EvmStorageProvider<'a> {
    /// Creates a provider without a bounded gas budget.
    ///
    /// Intended for call sites that do not need to meter the caller: the
    /// tracker starts at `u64::MAX`, so [`PrecompileStorageProvider::gas_used`]
    /// still reports the per-op total that was actually deducted. Static
    /// flag defaults to `false`; use [`Self::new_with_is_static`] to
    /// propagate the caller's STATICCALL context.
    pub fn new(internals: EvmInternals<'a>) -> Self {
        Self::new_with_is_static(internals, u64::MAX, false)
    }

    /// Creates a provider with an explicit remaining gas budget.
    ///
    /// Used by the precompile dispatcher to pass the caller-visible gas
    /// remaining after the base-dispatch charge. Static flag defaults to
    /// `false`; use [`Self::new_with_is_static`] to propagate STATICCALL.
    pub fn new_with_gas(internals: EvmInternals<'a>, gas_limit: u64) -> Self {
        Self::new_with_is_static(internals, gas_limit, false)
    }

    /// Creates a provider with an explicit gas budget and the
    /// caller-supplied STATICCALL flag.
    ///
    /// The dispatcher in `outbe-evm` reads the flag from
    /// [`alloy_evm::precompiles::PrecompileInput::is_static_call`] and
    /// propagates it so [`crate::storage::StorageHandle`] can refuse
    /// mutating operations during STATICCALL with
    /// [`PrecompileError::WriteProtection`].
    pub fn new_with_is_static(
        internals: EvmInternals<'a>,
        gas_limit: u64,
        is_static: bool,
    ) -> Self {
        Self::new_with_is_static_and_genesis_hash(internals, gas_limit, is_static, B256::ZERO)
    }

    /// Creates a provider bound to the immutable genesis hash from ChainSpec.
    pub fn new_with_is_static_and_genesis_hash(
        internals: EvmInternals<'a>,
        gas_limit: u64,
        is_static: bool,
        genesis_hash: B256,
    ) -> Self {
        Self {
            internals,
            gas: GasTracker::new(gas_limit),
            is_static,
            genesis_hash,
        }
    }

    /// Returns the remaining gas budget.
    ///
    /// Dispatch code computes per-call gas used as
    /// `initial_limit - gas_remaining()`.
    pub fn gas_remaining(&self) -> u64 {
        self.gas.remaining()
    }
}

impl PrecompileStorageProvider for EvmStorageProvider<'_> {
    fn chain_id(&self) -> u64 {
        self.internals.chain_id()
    }

    fn genesis_hash(&self) -> B256 {
        self.genesis_hash
    }

    fn timestamp(&self) -> U256 {
        self.internals.block_timestamp()
    }

    fn beneficiary(&self) -> Address {
        self.internals.block_env().beneficiary()
    }

    fn block_number(&self) -> u64 {
        self.internals.block_env().number().to::<u64>()
    }

    fn canonical_block_hash(&mut self, number: u64) -> Result<Option<B256>> {
        // Reth's `StateProviderDatabase::block_hash` returns the canonical
        // hash for any `number` within stored history and `B256::ZERO`
        // for blocks outside the window (or ahead of the current head).
        // We map ZERO back to `None` so callers see a clean "unknown"
        // signal - genuine canonical hashes are statistically never zero.
        let hash =
            self.internals.db_mut().block_hash(number).map_err(|e| {
                PrecompileError::Storage(format!("block_hash({number}) failed: {e}"))
            })?;
        Ok((!hash.is_zero()).then_some(hash))
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        self.internals
            .set_code(address, code)
            .map_err(|e| PrecompileError::Storage(e.to_string()))
    }

    fn account_info(&mut self, address: Address) -> Result<AccountInfo> {
        let account = self
            .internals
            .load_account_code(address)
            .map_err(|e| PrecompileError::Storage(e.to_string()))?;
        Ok(account.data.account().info.clone())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
        // EIP-2929 warm read price; Outbe bills every read at this rate.
        self.gas.deduct(WARM_STORAGE_READ_COST)?;
        let value = self
            .internals
            .sload(address, key)
            .map_err(|e| PrecompileError::Storage(e.to_string()))?;
        Ok(value.data)
    }

    fn tload(&mut self, address: Address, key: U256) -> Result<U256> {
        Ok(self.internals.tload(address, key))
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        // EIP-2929 SSTORE_RESET; Outbe has no refund model, so every write
        // is billed at the reset price (no SSTORE_SET distinction).
        self.gas.deduct(SSTORE_RESET)?;
        self.internals
            .sstore(address, key, value)
            .map_err(|e| PrecompileError::Storage(e.to_string()))?;
        Ok(())
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        self.internals.tstore(address, key, value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        self.internals.log(Log {
            address,
            data: event,
        });
        Ok(())
    }

    fn deduct_gas(&mut self, gas: u64) -> Result<()> {
        self.gas.deduct(gas)
    }

    fn refund_gas(&mut self, gas: i64) {
        self.gas.refund(gas);
    }

    fn gas_used(&self) -> u64 {
        self.gas.used()
    }

    fn gas_refunded(&self) -> i64 {
        self.gas.refunded()
    }

    fn is_static(&self) -> bool {
        self.is_static
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        self.internals.checkpoint()
    }

    fn checkpoint_commit(&mut self) {
        self.internals.checkpoint_commit()
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.internals.checkpoint_revert(checkpoint)
    }

    fn transfer_balance(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        // Use journal transfer which handles both balance changes atomically.
        // Returns Ok(Some(TransferError)) on insufficient balance,
        // Ok(None) on success, Err on DB error.
        match self.internals.transfer(from, to, amount) {
            Ok(None) => Ok(()),
            Ok(Some(_transfer_error)) => Err(PrecompileError::Fatal(format!(
                "insufficient balance for transfer from {from}: needs {amount}"
            ))),
            Err(e) => Err(PrecompileError::Storage(format!("transfer failed: {e}"))),
        }
    }

    fn increase_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        self.internals
            .balance_incr(address, amount)
            .map_err(|e| PrecompileError::Storage(format!("balance_incr failed: {e}")))?;
        Ok(())
    }

    fn decrease_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let account = self
            .internals
            .load_account(address)
            .map_err(|e| PrecompileError::Storage(format!("burn account load failed: {e}")))?;
        let balance = account.data.info.balance;
        let new_balance = balance.checked_sub(amount).ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "insufficient balance for burn from {address}: has {balance} but needs {amount}"
            ))
        })?;

        self.internals
            .set_balance(address, new_balance)
            .map_err(|e| PrecompileError::Storage(format!("burn set_balance failed: {e}")))?;
        Ok(())
    }
}
