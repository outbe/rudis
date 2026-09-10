use std::collections::HashMap;

use alloy_evm::block::StateDB;
use alloy_primitives::{map::AddressMap, Address, Log, LogData, B256, U256};
use revm::{
    context::journaled_state::JournalCheckpoint,
    database::Database,
    state::{Account, AccountInfo, Bytecode, EvmStorage, EvmStorageSlot},
};

use crate::block::BlockContext;
use crate::error::{PrecompileError, Result};
use crate::storage::PrecompileStorageProvider;

/// Storage provider for block-level hooks, wrapping a mutable [`StateDB`].
///
/// Reads go directly to the provided database.
/// Writes accumulate in a pending [`HashMap`] and are committed to the
/// underlying state when [`DirectStorageProvider::flush`] is called.
///
/// All state mutations (storage writes and balance transfers) are tracked
/// so callers can retrieve the complete [`EvmState`] change set via
/// [`DirectStorageProvider::take_committed_changes`] for notifying reth's
/// parallel state root task.
///
/// This is the block-hook counterpart to [`super::evm::EvmStorageProvider`],
/// which requires `EvmInternals` (only available inside a precompile call).
/// Block-level hooks such as `apply_pre_execution_changes()` can use any
/// mutable database that supports reads plus `commit()`.
pub struct DirectStorageProvider<'a, DB: StateDB> {
    state: &'a mut DB,
    /// Pending storage writes: address -> (slot -> new_value).
    pending: HashMap<Address, HashMap<U256, U256>>,
    /// Pending account-info updates such as hook-level balance transfers/burns.
    pending_accounts: AddressMap<AccountInfo>,
    /// Accumulated state changes committed by `flush()`.
    /// Used to notify reth's state root hook after all hooks complete.
    committed_changes: AddressMap<Account>,
    /// Events emitted by block-level hooks. Not journaled into EVM receipts,
    /// but collected so the executor can log them via tracing for observability.
    events: Vec<Log>,
    snapshots: Vec<DirectSnapshot>,
    ctx: BlockContext,
}

struct DirectSnapshot {
    pending: HashMap<Address, HashMap<U256, U256>>,
    pending_accounts: AddressMap<AccountInfo>,
    events: Vec<Log>,
}

impl<'a, DB: StateDB> DirectStorageProvider<'a, DB> {
    /// Creates a new provider wrapping the given state and block context.
    pub fn new(state: &'a mut DB, ctx: BlockContext) -> Self {
        Self {
            state,
            pending: HashMap::new(),
            pending_accounts: AddressMap::default(),
            committed_changes: AddressMap::default(),
            events: Vec::new(),
            snapshots: Vec::new(),
            ctx,
        }
    }

    fn effective_account_info(&mut self, address: Address) -> Result<AccountInfo>
    where
        <DB as Database>::Error: std::fmt::Display,
    {
        if let Some(info) = self.pending_accounts.get(&address) {
            return Ok(info.clone());
        }

        self.state
            .basic(address)
            .map_err(|e| PrecompileError::Storage(format!("basic({address}): {e}")))
            .map(|info| info.unwrap_or_default())
    }

    /// Returns all events emitted by block-level hooks.
    ///
    /// These are not part of EVM transaction receipts but can be logged
    /// via tracing for operator observability (tally results, slashing, etc.).
    pub fn take_events(&mut self) -> Vec<Log> {
        std::mem::take(&mut self.events)
    }

    /// Commits all pending writes accumulated via [`sstore`](Self::sstore) to
    /// the underlying [`State<DB>`].
    ///
    /// Must be called after the contract logic completes so that writes are
    /// visible to subsequent block processing steps.
    ///
    /// # Errors
    ///
    /// Returns [`PrecompileError::Storage`] if reading the original slot value
    /// from the database fails.
    pub fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() && self.pending_accounts.is_empty() {
            return Ok(());
        }

        // Collect writes first to release borrows before calling into `state`.
        let mut writes: HashMap<Address, Vec<(U256, U256)>> = self
            .pending
            .drain()
            .map(|(addr, slots)| (addr, slots.into_iter().collect()))
            .collect();
        let pending_accounts = std::mem::take(&mut self.pending_accounts);

        for addr in pending_accounts.keys() {
            writes.entry(*addr).or_default();
        }

        let mut changes: AddressMap<Account> =
            AddressMap::with_capacity_and_hasher(writes.len(), Default::default());

        for (addr, slots) in writes {
            // Load existing account info so the commit does not accidentally
            // wipe the nonce / balance / code of the contract.
            let info = match pending_accounts.get(&addr) {
                Some(info) => info.clone(),
                None => self
                    .state
                    .basic(addr)
                    .map_err(|e| PrecompileError::Storage(format!("basic({addr}): {e}")))?
                    .unwrap_or_default(),
            };

            // Build the EvmStorage map, reading the original slot value for
            // each write so that the journal can produce correct reverts.
            let mut storage = EvmStorage::default();
            for (key, new_value) in slots {
                let original = self
                    .state
                    .storage(addr, key)
                    .map_err(|e| PrecompileError::Storage(format!("storage({addr},{key}): {e}")))?;
                storage.insert(key, EvmStorageSlot::new_changed(original, new_value, 0));
            }

            let mut account = Account::from(info);
            account.storage = storage;
            account.mark_touch();

            changes.insert(addr, account);
        }

        // Track for state root hook notification.
        self.merge_into_committed(&changes);
        self.state.commit(changes);
        Ok(())
    }

    /// Returns all accumulated state changes from `flush()` for notifying
    /// reth's parallel state root task
    /// via the `OnStateHook`. Must be called after `flush()`.
    pub fn take_committed_changes(&mut self) -> AddressMap<Account> {
        std::mem::take(&mut self.committed_changes)
    }

    /// Merge account changes into the accumulated committed_changes,
    /// combining storage slots when the same address appears multiple times.
    fn merge_into_committed(&mut self, changes: &AddressMap<Account>) {
        for (addr, account) in changes {
            match self.committed_changes.entry(*addr) {
                revm::primitives::map::hash_map::Entry::Vacant(e) => {
                    e.insert(account.clone());
                }
                revm::primitives::map::hash_map::Entry::Occupied(mut e) => {
                    let existing = e.get_mut();
                    // Merge storage: new slots override existing
                    for (key, slot) in &account.storage {
                        existing.storage.insert(*key, slot.clone());
                    }
                    // Update account info to latest
                    existing.info = account.info.clone();
                }
            }
        }
    }
}

impl<DB: StateDB> PrecompileStorageProvider for DirectStorageProvider<'_, DB>
where
    <DB as Database>::Error: std::fmt::Display,
{
    fn chain_id(&self) -> u64 {
        self.ctx.chain_id
    }

    fn genesis_hash(&self) -> B256 {
        self.ctx.genesis_hash
    }

    fn timestamp(&self) -> U256 {
        U256::from(self.ctx.timestamp)
    }

    fn beneficiary(&self) -> Address {
        self.ctx.proposer
    }

    fn block_number(&self) -> u64 {
        self.ctx.block_number
    }

    fn canonical_block_hash(&mut self, number: u64) -> Result<Option<B256>> {
        // Reth's `StateProviderDatabase::block_hash` returns the canonical
        // hash for any in-window block and `B256::ZERO` otherwise. Map ZERO
        // to `None` so callers see a clean "unknown" signal.
        let hash = self
            .state
            .block_hash(number)
            .map_err(|e| PrecompileError::Storage(format!("block_hash({number}) failed: {e}")))?;
        Ok((!hash.is_zero()).then_some(hash))
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        let mut info = self.effective_account_info(address)?;
        info.code_hash = code.hash_slow();
        info.code = Some(code);
        self.pending_accounts.insert(address, info);
        Ok(())
    }

    fn account_info(&mut self, address: Address) -> Result<AccountInfo> {
        self.effective_account_info(address)
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
        // Pending writes shadow the committed state.
        if let Some(value) = self.pending.get(&address).and_then(|s| s.get(&key)) {
            return Ok(*value);
        }
        self.state
            .storage(address, key)
            .map_err(|e| PrecompileError::Storage(format!("storage({address},{key}): {e}")))
    }

    fn tload(&mut self, _address: Address, _key: U256) -> Result<U256> {
        // Transient storage does not apply in block-level hooks.
        Ok(U256::ZERO)
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        self.pending.entry(address).or_default().insert(key, value);
        Ok(())
    }

    fn tstore(&mut self, _address: Address, _key: U256, _value: U256) -> Result<()> {
        // No-op: transient storage does not apply in block-level hooks.
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        self.events.push(Log {
            address,
            data: event,
        });
        Ok(())
    }

    fn deduct_gas(&mut self, _gas: u64) -> Result<()> {
        // No gas accounting in block-level hooks.
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
        // DirectStorageProvider serves block-level hooks (begin_block /
        // end_block) that are by construction non-STATICCALL contexts.
        // Always `false`; if a hook were ever invoked from a static
        // frame the executor would route through a different provider.
        false
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        let idx = self.snapshots.len();
        self.snapshots.push(DirectSnapshot {
            pending: self.pending.clone(),
            pending_accounts: self.pending_accounts.clone(),
            events: self.events.clone(),
        });
        JournalCheckpoint {
            log_i: 0,
            journal_i: idx,
            selfdestructed_i: 0,
        }
    }

    fn checkpoint_commit(&mut self) {
        self.snapshots.pop();
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        if let Some(snapshot) = self.snapshots.drain(checkpoint.journal_i..).next() {
            self.pending = snapshot.pending;
            self.pending_accounts = snapshot.pending_accounts;
            self.events = snapshot.events;
        }
    }

    fn transfer_balance(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        // Self-transfer is a no-op - prevents double-insert overwrite
        // that would create tokens out of nothing.
        if from == to {
            return Ok(());
        }

        let mut from_info = self.effective_account_info(from)?;

        if from_info.balance < amount {
            return Err(PrecompileError::Fatal(format!(
                "insufficient balance: {from} has {} but needs {amount}",
                from_info.balance
            )));
        }

        let mut to_info = self.effective_account_info(to)?;
        let credited = to_info.balance.checked_add(amount).ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "balance overflow: crediting {amount} to {to} with balance {}",
                to_info.balance
            ))
        })?;
        from_info.balance -= amount;
        to_info.balance = credited;
        self.pending_accounts.insert(from, from_info);
        self.pending_accounts.insert(to, to_info);
        Ok(())
    }

    fn increase_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let mut info = self.effective_account_info(address)?;
        info.balance = info.balance.checked_add(amount).ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "balance overflow: increasing {address} by {amount} from {}",
                info.balance
            ))
        })?;
        self.pending_accounts.insert(address, info);
        Ok(())
    }

    fn decrease_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let mut info = self.effective_account_info(address)?;

        if info.balance < amount {
            return Err(PrecompileError::Fatal(format!(
                "insufficient balance for burn: {address} has {} but needs {amount}",
                info.balance
            )));
        }

        info.balance -= amount;
        self.pending_accounts.insert(address, info);
        Ok(())
    }
}
