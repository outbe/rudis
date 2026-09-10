use alloy_primitives::{Address, Bytes, LogData, B256, U256};
use revm::{
    context::journaled_state::JournalCheckpoint,
    state::{AccountInfo, Bytecode},
};
use std::{cell::RefCell, rc::Rc};

use crate::{
    error::{PrecompileError, Result},
    storage::{
        CertifiedLysisActivation, CheckpointGuard, PrecompileStorageProvider, StorageBacked,
        SubCallError, SubCallInput, SubCallOutput, SubCallStatus,
    },
};

/// Scoped handle to the current execution storage provider.
///
/// The handle is tied to the lifetime of one precompile, transaction, or block
/// lifecycle execution scope. It is intentionally single-threaded through
/// `Rc<RefCell<_>>`; do not store contract/storage facades beyond that scope.
///
/// `StorageHandle` is invariant in `'storage` because it wraps `&mut` provider
/// access. It cannot be reborrowed into a shorter independent execution scope.
#[derive(Clone)]
pub struct StorageHandle<'storage> {
    pub(crate) inner: Rc<RefCell<&'storage mut dyn PrecompileStorageProvider>>,
}

struct LysisActivationFrameGuard<'storage> {
    storage: StorageHandle<'storage>,
    activation_call_id: B256,
    closed: bool,
}

impl<'storage> LysisActivationFrameGuard<'storage> {
    fn open(storage: &StorageHandle<'storage>, activation_call_id: B256) -> Result<Self> {
        storage
            .with_provider(|provider| provider.begin_lysis_activation_frame(activation_call_id))?;
        Ok(Self {
            storage: storage.clone(),
            activation_call_id,
            closed: false,
        })
    }

    fn close(mut self, completed: bool) -> Result<()> {
        self.closed = true;
        self.storage.with_provider(|provider| {
            provider.finish_lysis_activation_frame(self.activation_call_id, completed)
        })
    }
}

impl Drop for LysisActivationFrameGuard<'_> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.storage.with_provider(|provider| {
                provider.finish_lysis_activation_frame(self.activation_call_id, false)
            });
        }
    }
}

impl<'storage> StorageHandle<'storage> {
    pub fn new(provider: &'storage mut dyn PrecompileStorageProvider) -> Self {
        Self {
            inner: Rc::new(RefCell::new(provider)),
        }
    }

    pub fn enter<T, R>(provider: &'storage mut T, f: impl FnOnce(StorageHandle<'storage>) -> R) -> R
    where
        T: PrecompileStorageProvider + 'storage,
    {
        let storage = Self::new(provider);
        f(storage)
    }

    pub fn contract<C: StorageBacked<'storage>>(&self) -> C {
        C::new(self.clone())
    }

    pub fn contract_at<C: StorageBacked<'storage>>(&self, address: Address) -> C {
        C::at(self.clone(), address)
    }

    pub(super) fn with_provider<R>(
        &self,
        f: impl FnOnce(&mut dyn PrecompileStorageProvider) -> Result<R>,
    ) -> Result<R> {
        let mut provider = self.inner.try_borrow_mut().map_err(|_| {
            crate::error::PrecompileError::Fatal(
                "storage provider is already mutably borrowed".into(),
            )
        })?;
        f(&mut **provider)
    }

    pub fn chain_id(&self) -> Result<u64> {
        self.with_provider(|provider| Ok(provider.chain_id()))
    }

    pub fn genesis_hash(&self) -> Result<B256> {
        self.with_provider(|provider| Ok(provider.genesis_hash()))
    }

    pub fn timestamp(&self) -> Result<U256> {
        self.with_provider(|provider| Ok(provider.timestamp()))
    }

    /// Test fixtures only: advance the provider's reported block timestamp.
    /// Production providers (EVM) ignore this; see
    /// [`PrecompileStorageProvider::set_block_timestamp`].
    pub fn set_block_timestamp(&self, timestamp: U256) -> Result<()> {
        self.with_provider(|provider| {
            provider.set_block_timestamp(timestamp);
            Ok(())
        })
    }

    pub fn beneficiary(&self) -> Result<Address> {
        self.with_provider(|provider| Ok(provider.beneficiary()))
    }

    pub fn block_number(&self) -> Result<u64> {
        self.with_provider(|provider| Ok(provider.block_number()))
    }

    /// Returns the canonical block hash for `number`, or `None` if `number`
    /// is outside the chain's canonical-history window.
    ///
    /// backed by
    /// [`PrecompileStorageProvider::canonical_block_hash`].
    pub fn canonical_block_hash(&self, number: u64) -> Result<Option<B256>> {
        self.with_provider(|provider| provider.canonical_block_hash(number))
    }

    pub fn with_account_info<T>(
        &self,
        address: Address,
        mut f: impl FnMut(&AccountInfo) -> Result<T>,
    ) -> Result<T> {
        let info = self.with_provider(|provider| provider.account_info(address))?;
        f(&info)
    }

    pub fn balance(&self, address: Address) -> Result<U256> {
        self.with_account_info(address, |info| Ok(info.balance))
    }

    pub fn set_balance(&self, address: Address, balance: U256) -> Result<()> {
        // refuse balance mutation in STATICCALL
        // context up front so the underlying `balance(..)` read does
        // not run a wasted journal lookup before the inner gate fires.
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            Ok(())
        })?;
        let current = self.balance(address)?;
        match balance.cmp(&current) {
            std::cmp::Ordering::Greater => self.increase_balance(address, balance - current),
            std::cmp::Ordering::Less => self.decrease_balance(address, current - balance),
            std::cmp::Ordering::Equal => Ok(()),
        }
    }

    pub fn sload(&self, address: Address, key: U256) -> Result<U256> {
        self.with_provider(|provider| provider.sload(address, key))
    }

    pub fn tload(&self, address: Address, key: U256) -> Result<U256> {
        self.with_provider(|provider| provider.tload(address, key))
    }

    pub fn sstore(&self, address: Address, key: U256, value: U256) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.sstore(address, key, value)
        })
    }

    pub fn tstore(&self, address: Address, key: U256, value: U256) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.tstore(address, key, value)
        })
    }

    pub fn emit_event(&self, address: Address, event: LogData) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.emit_event(address, event)
        })
    }

    pub fn transfer_balance(&self, from: Address, to: Address, amount: U256) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.transfer_balance(from, to, amount)
        })
    }

    pub fn increase_balance(&self, address: Address, amount: U256) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.increase_balance(address, amount)
        })
    }

    pub fn decrease_balance(&self, address: Address, amount: U256) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.decrease_balance(address, amount)
        })
    }

    /// Deploys bytecode at `address`.
    ///
    /// Honors the STATICCALL static gate: returns
    /// [`PrecompileError::WriteProtection`] if the provider is in a
    /// static context. Providers that do not support code deployment return
    /// [`PrecompileError::Unsupported`].
    pub fn set_code(&self, address: Address, code: Bytecode) -> Result<()> {
        self.with_provider(|provider| {
            if provider.is_static() {
                return Err(PrecompileError::WriteProtection);
            }
            provider.set_code(address, code)
        })
    }

    pub fn checkpoint(&self) -> JournalCheckpoint {
        let mut provider = self.inner.borrow_mut();
        provider.checkpoint()
    }

    pub fn checkpoint_guard(&self) -> CheckpointGuard<'storage> {
        CheckpointGuard::new(self.clone(), self.checkpoint())
    }

    /// Runs storage mutations under a journal checkpoint.
    ///
    /// The checkpoint is committed only when the closure returns `Ok`.
    /// On `Err` or early return, [`CheckpointGuard`] drops without commit and
    /// reverts all writes made in this scope.
    pub fn with_checkpoint<R>(&self, f: impl FnOnce() -> Result<R>) -> Result<R> {
        let checkpoint = self.checkpoint_guard();
        let result = f()?;
        checkpoint.commit();
        Ok(result)
    }

    /// Runs the fixed Lysis activation owner sequence under a provider-granted
    /// execution-frame lease.
    ///
    /// The capability cannot escape the closure or be cloned. A successful
    /// return is accepted only after all owner steps and the terminal step
    /// have consumed the cursor in order.
    pub fn with_lysis_activation_frame<R>(
        &self,
        activation_call_id: B256,
        f: impl for<'frame> FnOnce(&mut CertifiedLysisActivation<'frame>) -> Result<R>,
    ) -> Result<R> {
        let frame = LysisActivationFrameGuard::open(self, activation_call_id)?;
        let mut capability = CertifiedLysisActivation::new(activation_call_id);
        let outcome = f(&mut capability);
        let completed = outcome.is_ok() && capability.is_complete();
        frame.close(completed)?;
        match outcome {
            Ok(value) if completed => Ok(value),
            Ok(_) => Err(PrecompileError::Fatal(
                "certified Lysis activation frame returned before terminal completion".into(),
            )),
            Err(error) => Err(error),
        }
    }

    pub fn checkpoint_commit(&self) {
        let mut provider = self.inner.borrow_mut();
        provider.checkpoint_commit();
    }

    pub fn checkpoint_revert(&self, checkpoint: JournalCheckpoint) {
        let mut provider = self.inner.borrow_mut();
        provider.checkpoint_revert(checkpoint);
    }

    pub fn deduct_gas(&self, gas: u64) -> Result<()> {
        self.with_provider(|provider| provider.deduct_gas(gas))
    }

    pub fn refund_gas(&self, gas: i64) {
        let mut provider = self.inner.borrow_mut();
        provider.refund_gas(gas);
    }

    pub fn gas_used(&self) -> Result<u64> {
        self.with_provider(|provider| Ok(provider.gas_used()))
    }

    pub fn gas_refunded(&self) -> Result<i64> {
        self.with_provider(|provider| Ok(provider.gas_refunded()))
    }

    pub fn is_static(&self) -> Result<bool> {
        self.with_provider(|provider| Ok(provider.is_static()))
    }

    // === Sub-call API stubs ===
    //
    // STUB until T4/T6 lands real behavior; returns Ok(empty). Signatures
    // here are the public contract - T4 (STATICCALL) and T6 (CALL) MUST swap
    // bodies only, never types.

    /// Invokes a child CALL frame and returns the raw returndata.
    ///
    /// Maps `SubCallStatus::Success -> Ok(bytes)`,
    /// `Revert(bytes) -> Err(RevertBytes(bytes))`,
    /// `Halt(err) -> Err(SubCall(err))`.
    pub fn call(
        &self,
        target: Address,
        value: U256,
        calldata: Bytes,
    ) -> std::result::Result<Bytes, PrecompileError> {
        self.call_with_gas(target, value, calldata, u64::MAX)
    }

    /// Invokes a child STATICCALL frame.
    pub fn staticcall(
        &self,
        target: Address,
        calldata: Bytes,
    ) -> std::result::Result<Bytes, PrecompileError> {
        self.staticcall_with_gas(target, calldata, u64::MAX)
    }

    /// Invokes a child CALL frame with an explicit gas cap.
    pub fn call_with_gas(
        &self,
        target: Address,
        value: U256,
        calldata: Bytes,
        gas_limit: u64,
    ) -> std::result::Result<Bytes, PrecompileError> {
        let output = self.try_call_with_gas(target, value, calldata, gas_limit)?;
        subcall_status_to_bytes(output)
    }

    /// Invokes a child STATICCALL frame with an explicit gas cap.
    pub fn staticcall_with_gas(
        &self,
        target: Address,
        calldata: Bytes,
        gas_limit: u64,
    ) -> std::result::Result<Bytes, PrecompileError> {
        let output = self.try_staticcall_with_gas(target, calldata, gas_limit)?;
        subcall_status_to_bytes(output)
    }

    /// Lower-level variant that returns the full [`SubCallOutput`] (gas
    /// accounting, status, returndata).
    pub fn try_call(
        &self,
        target: Address,
        value: U256,
        calldata: Bytes,
    ) -> std::result::Result<SubCallOutput, SubCallError> {
        self.try_call_with_gas(target, value, calldata, u64::MAX)
    }

    /// Lower-level STATICCALL variant.
    pub fn try_staticcall(
        &self,
        target: Address,
        calldata: Bytes,
    ) -> std::result::Result<SubCallOutput, SubCallError> {
        self.try_staticcall_with_gas(target, calldata, u64::MAX)
    }

    /// Lower-level CALL with an explicit gas cap.
    pub fn try_call_with_gas(
        &self,
        target: Address,
        value: U256,
        calldata: Bytes,
        gas_limit: u64,
    ) -> std::result::Result<SubCallOutput, SubCallError> {
        self.do_sub_call(SubCallInput {
            target,
            value,
            calldata,
            gas_limit,
            is_static: false,
        })
    }

    /// Lower-level STATICCALL with an explicit gas cap.
    pub fn try_staticcall_with_gas(
        &self,
        target: Address,
        calldata: Bytes,
        gas_limit: u64,
    ) -> std::result::Result<SubCallOutput, SubCallError> {
        self.do_sub_call(SubCallInput {
            target,
            value: U256::ZERO,
            calldata,
            gas_limit,
            is_static: true,
        })
    }

    /// Internal helper: invokes the provider's [`PrecompileStorageProvider::sub_call`]
    /// via the `Rc<RefCell<...>>` interior-mut handle.
    ///
    /// Re-entry into `do_sub_call` during the dispatch closure (i.e. the
    /// callback already holds the inner borrow) returns
    /// `SubCallError::ProviderBorrowed` rather than panicking. In practice
    /// the production [`crate::storage::evm::EvmStorageProvider`] and
    /// `outbe_evm::storage::CtxStorageProvider` provider impls only release
    /// the borrow after `sub_call` returns, so a hostile re-entry from
    /// inside the child frame is observable as a structured error.
    fn do_sub_call(&self, input: SubCallInput) -> std::result::Result<SubCallOutput, SubCallError> {
        let mut guard = self
            .inner
            .try_borrow_mut()
            .map_err(|_| SubCallError::ProviderBorrowed)?;
        guard.sub_call(input)
    }
}

fn subcall_status_to_bytes(output: SubCallOutput) -> std::result::Result<Bytes, PrecompileError> {
    match output.status {
        SubCallStatus::Success => Ok(output.returndata),
        SubCallStatus::Revert(bytes) => Err(PrecompileError::RevertBytes(bytes)),
        SubCallStatus::Halt(err) => Err(PrecompileError::SubCall(err)),
    }
}

impl<'storage, T> From<&'storage mut T> for StorageHandle<'storage>
where
    T: PrecompileStorageProvider + 'storage,
{
    fn from(provider: &'storage mut T) -> Self {
        Self::new(provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hashmap::HashMapStorageProvider;

    #[test]
    #[should_panic(expected = "already borrowed")]
    fn nested_borrow_within_single_scope_panics() {
        let mut provider = HashMapStorageProvider::new(1);
        let handle = StorageHandle::new(&mut provider);
        let _outer = handle.inner.borrow_mut();
        let _inner = handle.inner.borrow_mut();
    }

    #[test]
    fn sequential_borrows_across_handles_work() {
        let mut provider = HashMapStorageProvider::new(1);
        let handle = StorageHandle::new(&mut provider);
        let other = handle.clone();

        assert_eq!(handle.chain_id().unwrap(), 1);
        assert_eq!(other.chain_id().unwrap(), 1);
    }
}
