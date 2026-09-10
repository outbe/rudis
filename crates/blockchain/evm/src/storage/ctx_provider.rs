//! `CtxStorageProvider` - sub-call-driver-aware `PrecompileStorageProvider`.
//!
//! Holds `&'a mut EthEvmContext<DB>` directly so the `sub_call` body can hand
//! the full `&mut Context` to `revm_handler::EthFrame::make_call_frame` (via
//! the [`crate::sub_call`] driver) without losing access to journaled state
//! between storage ops.
//!
//! For non-sub-call storage operations (sload/sstore/balance/log/...) the
//! provider constructs an `alloy_evm::EvmInternals` from `self.ctx` on each
//! call. The construction is cheap (one `Box<dyn EvmInternalsTr>` allocation
//! per op) and is the standard cost of going through the `EvmInternals`
//! facade that revm's `PrecompileInput.internals` exposes.
//!
//! Sub-call hands `self.ctx` to the driver in [`crate::sub_call`].
//!
//! ## Coexistence with `EvmStorageProvider`
//!
//! The legacy [`outbe_primitives::storage::evm::EvmStorageProvider`] which
//! holds `EvmInternals<'a>` is still used by the read-only / non-sub-call
//! dispatch path inside [`crate::precompiles::extend_outbe_precompiles`].
//! `CtxStorageProvider` is constructed by the ctx-dispatch hook
//! whenever the dispatch needs sub-call. Both providers must agree
//! byte-for-byte on non-sub-call semantics - they share the same upstream
//! `EvmInternals` primitives.

use alloy_evm::{eth::EthEvmContext, EvmInternals};
use alloy_primitives::{Address, Log, LogData, B256, U256};
use core::fmt::Debug;
use outbe_compressed_entities::ExecutionScope;
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::{
        MetadosisMutationEntitlements, MetadosisMutationPurposeTag, PrecompileStorageProvider,
        SubCallError, SubCallInput, SubCallOutput,
    },
};
use revm::{
    context::journaled_state::JournalCheckpoint,
    context_interface::{
        cfg::gas::{SSTORE_RESET, WARM_STORAGE_READ_COST},
        Block as _, Cfg as _, ContextTr,
    },
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Database,
};
use std::{cell::RefCell, sync::Arc};

use crate::{gas::SubcallGasMeter, precompiles::OcompActivationBlockMeter, sub_call};
use outbe_metadosis::api::OcompFinalizedIntentAuthority;
use outbe_offchain_data::RuntimeBodyReaders;

thread_local! {
    /// Per-thread reentrancy stack tracking which outbe precompile addresses
    /// are currently dispatched on this call chain. revm processes one
    /// transaction synchronously per thread, so a thread-local stack is the
    /// natural scope: it lives exactly as long as the active tx execution
    /// and is reset (empty) at the end of every dispatch chain by RAII Drop
    /// on [`ReentrancyGuard`].
    static REENTRANCY_STACK: RefCell<Vec<Address>> = const { RefCell::new(Vec::new()) };
}

/// Zero-sized marker preserved as a [`CtxStorageProvider`] field so the
/// struct layout from is not disturbed. The actual stack lives
/// in the thread-local [`struct@REENTRANCY_STACK`].
#[derive(Debug, Default, Clone, Copy)]
pub struct ReentrancyStack;

impl ReentrancyStack {
    /// Attempts to push `addr` onto the active reentrancy stack.
    ///
    /// Returns `Some(ReentrancyGuard)` on first entry; `None` if `addr` is
    /// already on the stack (caller must reject the dispatch).
    pub fn try_enter(addr: Address) -> Option<ReentrancyGuard> {
        REENTRANCY_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.contains(&addr) {
                None
            } else {
                stack.push(addr);
                Some(ReentrancyGuard { addr })
            }
        })
    }

    /// Returns true if `addr` is currently on the active reentrancy stack
    /// for this thread.
    #[doc(hidden)]
    pub fn contains(addr: Address) -> bool {
        REENTRANCY_STACK.with(|s| s.borrow().contains(&addr))
    }

    /// Returns the current stack depth for this thread.
    #[doc(hidden)]
    pub fn depth() -> usize {
        REENTRANCY_STACK.with(|s| s.borrow().len())
    }
}

/// RAII guard returned by [`ReentrancyStack::try_enter`]. Pops the registered
/// address from the thread-local reentrancy stack on Drop.
#[derive(Debug)]
pub struct ReentrancyGuard {
    addr: Address,
}

impl Drop for ReentrancyGuard {
    fn drop(&mut self) {
        REENTRANCY_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if let Some(pos) = stack.iter().rposition(|a| a == &self.addr) {
                stack.remove(pos);
            }
        });
    }
}

/// Sub-call-driver-aware [`PrecompileStorageProvider`] over a borrowed
/// [`alloy_evm::eth::EthEvmContext`].
///
/// `DB: Debug` is required because [`alloy_evm::EvmInternals::from_context`]
/// has a `Journal: Debug` bound (Journal<DB> Debug-derives over DB).
pub struct CtxStorageProvider<'a, DB: Database + Debug> {
    /// Borrowed EVM context. Sub-call hands this to
    /// [`crate::sub_call::run`]; non-sub-call ops derive an
    /// [`alloy_evm::EvmInternals`] facade on-the-fly per call.
    pub ctx: &'a mut EthEvmContext<DB>,
    /// Per-call gas meter (mirrors `revm::Gas`).
    pub gas: SubcallGasMeter,
    /// STATICCALL flag forwarded from the outer dispatcher.
    pub is_static: bool,
    /// Address of the outbe precompile the dispatcher is currently running.
    pub self_address: Address,
    /// Reentrancy stack marker (real state lives in thread-local).
    pub reentrancy_stack: ReentrancyStack,
    /// EVM spec id, captured at provider construction time.
    pub spec: SpecId,
    /// Immutable genesis hash sourced from the canonical ChainSpec.
    pub genesis_hash: B256,
    /// Least-authority off-chain body readers propagated to nested precompiles.
    pub runtime_body_readers: Option<RuntimeBodyReaders>,
    /// The same block-scoped lifecycle capability used by the outer EVM.
    pub execution_scope: Arc<ExecutionScope>,
    /// Production finalized-Intent authority propagated to nested precompile calls.
    pub ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
    /// The same block-scoped activation meter used by the outer dispatcher.
    pub ocomp_activation_block_meter: Arc<OcompActivationBlockMeter>,
    /// Whether the OCOMP measurement/final profile is active in this block.
    pub ocomp_lifecycle_active: bool,
    /// One-shot runtime lease state for the exact public Lysis activation call.
    lysis_activation_lease: LysisActivationLease,
    /// Purpose-bound Metadosis mutation authority for this exact dispatch.
    metadosis_mutation_frame: MetadosisMutationFrameState,
}

pub(crate) struct CtxStorageProviderConfig {
    pub(crate) is_static: bool,
    pub(crate) self_address: Address,
    pub(crate) reentrancy_stack: ReentrancyStack,
    pub(crate) spec: SpecId,
    pub(crate) genesis_hash: B256,
    pub(crate) runtime_body_readers: Option<RuntimeBodyReaders>,
    pub(crate) execution_scope: Arc<ExecutionScope>,
    pub(crate) ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
    pub(crate) ocomp_activation_block_meter: Arc<OcompActivationBlockMeter>,
    pub(crate) ocomp_lifecycle_active: bool,
    pub(crate) lysis_activation_entitled: bool,
    pub(crate) metadosis_mutation_entitlements: MetadosisMutationEntitlements,
}

#[derive(Debug)]
struct LysisActivationLease {
    entitled: bool,
    attempted: bool,
    active_call_id: Option<B256>,
}

#[derive(Debug)]
struct MetadosisMutationFrameState {
    entitlements: MetadosisMutationEntitlements,
    active: Option<(MetadosisMutationPurposeTag, B256, u64, u64)>,
}

impl MetadosisMutationFrameState {
    const fn new(entitlements: MetadosisMutationEntitlements) -> Self {
        Self {
            entitlements,
            active: None,
        }
    }

    fn begin(
        &mut self,
        purpose: MetadosisMutationPurposeTag,
        binding: B256,
        chain_id: u64,
        block_number: u64,
    ) -> outbe_primitives::error::Result<()> {
        if self.active.is_some() || !self.entitlements.consume(purpose, binding) {
            return Err(outbe_primitives::error::PrecompileError::Fatal(format!(
                "Metadosis mutation purpose is not entitled for this EVM call: \
                     purpose={purpose:?} binding={binding:#x} remaining={:?}",
                self.entitlements
            )));
        }
        self.active = Some((purpose, binding, chain_id, block_number));
        Ok(())
    }

    fn finish(
        &mut self,
        purpose: MetadosisMutationPurposeTag,
        binding: B256,
    ) -> outbe_primitives::error::Result<()> {
        let Some((active_purpose, active_binding, _, _)) = self.active.as_ref().copied() else {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "Metadosis mutation frame is not active".into(),
            ));
        };
        if active_purpose != purpose || active_binding != binding {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "Metadosis mutation frame identity mismatch".into(),
            ));
        }
        self.active = None;
        Ok(())
    }
}

impl LysisActivationLease {
    const fn new(entitled: bool) -> Self {
        Self {
            entitled,
            attempted: false,
            active_call_id: None,
        }
    }

    fn begin(&mut self, activation_call_id: B256) -> outbe_primitives::error::Result<()> {
        if !self.entitled || self.attempted || self.active_call_id.is_some() {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "certified Lysis activation frame is not entitled for this EVM call".into(),
            ));
        }
        self.attempted = true;
        self.active_call_id = Some(activation_call_id);
        Ok(())
    }

    fn finish(
        &mut self,
        activation_call_id: B256,
        _completed: bool,
    ) -> outbe_primitives::error::Result<()> {
        if self.active_call_id != Some(activation_call_id) {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "certified Lysis activation frame identity mismatch".into(),
            ));
        }
        self.active_call_id = None;
        Ok(())
    }
}

impl<'a, DB: Database + Debug> CtxStorageProvider<'a, DB> {
    /// Constructor.
    pub(crate) fn new(
        ctx: &'a mut EthEvmContext<DB>,
        gas: SubcallGasMeter,
        config: CtxStorageProviderConfig,
    ) -> Self {
        Self {
            ctx,
            gas,
            is_static: config.is_static,
            self_address: config.self_address,
            reentrancy_stack: config.reentrancy_stack,
            spec: config.spec,
            genesis_hash: config.genesis_hash,
            runtime_body_readers: config.runtime_body_readers,
            execution_scope: config.execution_scope,
            ocomp_finality_authority: config.ocomp_finality_authority,
            ocomp_activation_block_meter: config.ocomp_activation_block_meter,
            ocomp_lifecycle_active: config.ocomp_lifecycle_active,
            lysis_activation_lease: LysisActivationLease::new(config.lysis_activation_entitled),
            metadosis_mutation_frame: MetadosisMutationFrameState::new(
                config.metadosis_mutation_entitlements,
            ),
        }
    }

    /// Installs the exact route inventory after a provider-backed read has
    /// resolved consensus state needed to derive it. This is used by
    /// ProtocolCycle, whose daily allocation decision depends on Cycle's
    /// persisted UTC cursor rather than on untrusted calldata.
    pub(crate) fn replace_metadosis_mutation_entitlements(
        &mut self,
        entitlements: MetadosisMutationEntitlements,
    ) {
        self.metadosis_mutation_frame = MetadosisMutationFrameState::new(entitlements);
    }

    /// Constructs a fresh `EvmInternals` view of `self.ctx` for one
    /// storage operation. Reborrows `self.ctx`; the returned facade is
    /// valid only within the calling method scope.
    #[inline]
    fn internals(&mut self) -> EvmInternals<'_> {
        EvmInternals::from_context(&mut *self.ctx)
    }
}

impl<'a, DB: Database + Debug> PrecompileStorageProvider for CtxStorageProvider<'a, DB> {
    fn begin_metadosis_mutation_frame(
        &mut self,
        purpose: MetadosisMutationPurposeTag,
        binding: B256,
        chain_id: u64,
        block_number: u64,
    ) -> outbe_primitives::error::Result<()> {
        if ContextTr::cfg(self.ctx).chain_id() != chain_id
            || ContextTr::block(self.ctx).number().saturating_to::<u64>() != block_number
        {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "Metadosis mutation frame execution scope mismatch".into(),
            ));
        }
        self.metadosis_mutation_frame
            .begin(purpose, binding, chain_id, block_number)
    }

    fn finish_metadosis_mutation_frame(
        &mut self,
        purpose: MetadosisMutationPurposeTag,
        binding: B256,
        _completed: bool,
    ) -> outbe_primitives::error::Result<()> {
        self.metadosis_mutation_frame.finish(purpose, binding)
    }

    fn begin_lysis_activation_frame(
        &mut self,
        activation_call_id: B256,
    ) -> outbe_primitives::error::Result<()> {
        self.lysis_activation_lease.begin(activation_call_id)
    }

    fn finish_lysis_activation_frame(
        &mut self,
        activation_call_id: B256,
        completed: bool,
    ) -> outbe_primitives::error::Result<()> {
        self.lysis_activation_lease
            .finish(activation_call_id, completed)
    }

    fn chain_id(&self) -> u64 {
        ContextTr::cfg(self.ctx).chain_id()
    }

    fn genesis_hash(&self) -> B256 {
        self.genesis_hash
    }

    fn timestamp(&self) -> U256 {
        ContextTr::block(self.ctx).timestamp()
    }

    fn beneficiary(&self) -> Address {
        ContextTr::block(self.ctx).beneficiary()
    }

    fn block_number(&self) -> u64 {
        ContextTr::block(self.ctx).number().saturating_to::<u64>()
    }

    fn canonical_block_hash(&mut self, number: u64) -> Result<Option<B256>> {
        let hash =
            self.internals().db_mut().block_hash(number).map_err(|e| {
                PrecompileError::Storage(format!("block_hash({number}) failed: {e}"))
            })?;
        Ok((!hash.is_zero()).then_some(hash))
    }

    fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
        self.internals()
            .set_code(address, code)
            .map_err(|e| PrecompileError::Storage(e.to_string()))
    }

    fn account_info(&mut self, address: Address) -> Result<AccountInfo> {
        let mut internals = self.internals();
        let account = internals
            .load_account_code(address)
            .map_err(|e| PrecompileError::Storage(e.to_string()))?;
        Ok(account.data.account().info.clone())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
        if !self.gas.record_regular_cost(WARM_STORAGE_READ_COST) {
            return Err(PrecompileError::OutOfGas);
        }
        let mut internals = self.internals();
        let value = internals
            .sload(address, key)
            .map_err(|e| PrecompileError::Storage(e.to_string()))?;
        Ok(value.data)
    }

    fn tload(&mut self, address: Address, key: U256) -> Result<U256> {
        Ok(self.internals().tload(address, key))
    }

    fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        if !self.gas.record_regular_cost(SSTORE_RESET) {
            return Err(PrecompileError::OutOfGas);
        }
        let mut internals = self.internals();
        internals
            .sstore(address, key, value)
            .map_err(|e| PrecompileError::Storage(e.to_string()))?;
        Ok(())
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
        self.internals().tstore(address, key, value);
        Ok(())
    }

    fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
        self.internals().log(Log {
            address,
            data: event,
        });
        Ok(())
    }

    fn deduct_gas(&mut self, cost: u64) -> Result<()> {
        if self.gas.record_regular_cost(cost) {
            Ok(())
        } else {
            Err(PrecompileError::OutOfGas)
        }
    }

    fn refund_gas(&mut self, refund: i64) {
        self.gas.record_refund(refund);
    }

    fn gas_used(&self) -> u64 {
        self.gas.limit().saturating_sub(self.gas.remaining())
    }

    fn gas_refunded(&self) -> i64 {
        self.gas.refunded()
    }

    fn is_static(&self) -> bool {
        self.is_static
    }

    fn checkpoint(&mut self) -> JournalCheckpoint {
        self.internals().checkpoint()
    }

    fn checkpoint_commit(&mut self) {
        self.internals().checkpoint_commit()
    }

    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.internals().checkpoint_revert(checkpoint)
    }

    fn transfer_balance(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        match self.internals().transfer(from, to, amount) {
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
        self.internals()
            .balance_incr(address, amount)
            .map_err(|e| PrecompileError::Storage(format!("balance_incr failed: {e}")))?;
        Ok(())
    }

    fn decrease_balance(&mut self, address: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        let balance = {
            let mut internals = self.internals();
            let account = internals
                .load_account(address)
                .map_err(|e| PrecompileError::Storage(format!("burn account load failed: {e}")))?;
            account.data.info.balance
        };
        let new_balance = balance.checked_sub(amount).ok_or_else(|| {
            PrecompileError::Fatal(format!(
                "insufficient balance for burn from {address}: has {balance} but needs {amount}"
            ))
        })?;
        let mut internals = self.internals();
        internals
            .set_balance(address, new_balance)
            .map_err(|e| PrecompileError::Storage(format!("burn set_balance failed: {e}")))?;
        Ok(())
    }

    fn sub_call(
        &mut self,
        input: SubCallInput,
    ) -> std::result::Result<SubCallOutput, SubCallError> {
        sub_call::run_with_ocomp_context(
            self.ctx,
            self.self_address,
            self.is_static,
            self.spec,
            self.genesis_hash,
            self.runtime_body_readers.clone(),
            self.execution_scope.clone(),
            self.ocomp_finality_authority.clone(),
            self.ocomp_activation_block_meter.clone(),
            self.ocomp_lifecycle_active,
            input,
        )
    }
}

#[cfg(test)]
mod lysis_activation_lease_tests {
    use super::LysisActivationLease;
    use alloy_primitives::B256;

    #[test]
    fn denied_call_cannot_open_activation_frame() {
        let mut lease = LysisActivationLease::new(false);
        assert!(lease.begin(B256::repeat_byte(1)).is_err());
    }

    #[test]
    fn entitled_call_gets_one_exact_activation_frame() {
        let call_id = B256::repeat_byte(2);
        let mut lease = LysisActivationLease::new(true);

        lease.begin(call_id).unwrap();
        lease.finish(call_id, true).unwrap();

        assert!(lease.begin(call_id).is_err());
    }

    #[test]
    fn wrong_frame_identity_cannot_close_or_replace_active_frame() {
        let call_id = B256::repeat_byte(3);
        let mut lease = LysisActivationLease::new(true);
        lease.begin(call_id).unwrap();

        assert!(lease.finish(B256::repeat_byte(4), false).is_err());
        lease.finish(call_id, false).unwrap();
        assert!(lease.begin(call_id).is_err());
    }
}

#[cfg(test)]
mod metadosis_mutation_frame_tests {
    use super::MetadosisMutationFrameState;
    use alloy_primitives::B256;
    use outbe_primitives::storage::{
        MetadosisCertifiedFinalityBinding, MetadosisMutationEntitlements,
        MetadosisMutationPurposeTag as Purpose,
    };

    #[test]
    fn denied_or_wrong_purpose_cannot_open_frame() {
        let mut denied = MetadosisMutationFrameState::new(MetadosisMutationEntitlements::NONE);
        assert!(denied
            .begin(Purpose::CycleLifecycle, B256::repeat_byte(1), 1, 2)
            .is_err());

        let mut wrong = MetadosisMutationFrameState::new(MetadosisMutationEntitlements::only(
            Purpose::CertifiedFinality,
        ));
        assert!(wrong
            .begin(Purpose::CycleLifecycle, B256::repeat_byte(1), 1, 2)
            .is_err());
        wrong
            .begin(Purpose::CertifiedFinality, B256::repeat_byte(2), 1, 2)
            .unwrap();
    }

    #[test]
    fn nesting_and_wrong_close_preserve_the_active_frame() {
        let purpose = Purpose::CycleLifecycle;
        let binding = B256::repeat_byte(3);
        let mut frame =
            MetadosisMutationFrameState::new(MetadosisMutationEntitlements::only(purpose).union(
                MetadosisMutationEntitlements::only(Purpose::CertifiedFinality),
            ));
        frame.begin(purpose, binding, 7, 11).unwrap();

        assert!(frame
            .begin(Purpose::CertifiedFinality, B256::repeat_byte(4), 7, 11,)
            .is_err());
        assert!(frame.finish(purpose, B256::repeat_byte(5)).is_err());
        frame.finish(purpose, binding).unwrap();

        // A rejected nested attempt did not consume the other entitlement.
        frame
            .begin(Purpose::CertifiedFinality, B256::repeat_byte(6), 7, 11)
            .unwrap();
    }

    #[test]
    fn one_route_entitlement_cannot_be_reused() {
        let purpose = Purpose::VerifiedResultVote;
        let binding = B256::repeat_byte(7);
        let mut frame =
            MetadosisMutationFrameState::new(MetadosisMutationEntitlements::only(purpose));
        frame.begin(purpose, binding, 7, 11).unwrap();
        frame.finish(purpose, binding).unwrap();

        assert!(frame.begin(purpose, binding, 7, 11).is_err());
    }

    #[test]
    fn exact_bounded_route_budget_is_consumed_one_lease_at_a_time() {
        let purpose = Purpose::CycleLifecycle;
        let mut frame =
            MetadosisMutationFrameState::new(MetadosisMutationEntitlements::repeated(purpose, 2));
        for binding in [B256::repeat_byte(8), B256::repeat_byte(9)] {
            frame.begin(purpose, binding, 7, 11).unwrap();
            frame.finish(purpose, binding).unwrap();
        }
        assert!(frame.begin(purpose, B256::repeat_byte(10), 7, 11).is_err());
    }

    #[test]
    fn exact_authority_binding_rejects_mismatch_without_consuming_grant() {
        let purpose = Purpose::CertifiedFinality;
        let finalized_hash = B256::repeat_byte(11);
        let expected = MetadosisCertifiedFinalityBinding::new(
            7,
            11,
            10,
            finalized_hash,
            B256::repeat_byte(12),
        );
        let wrong_root = MetadosisCertifiedFinalityBinding::new(
            7,
            11,
            10,
            finalized_hash,
            B256::repeat_byte(13),
        );
        assert_ne!(expected.binding(), wrong_root.binding());
        let mut frame = MetadosisMutationFrameState::new(MetadosisMutationEntitlements::exact(
            purpose,
            expected.binding(),
        ));

        assert!(frame.begin(purpose, wrong_root.binding(), 7, 11).is_err());
        frame.begin(purpose, expected.binding(), 7, 11).unwrap();
        frame.finish(purpose, expected.binding()).unwrap();
        assert!(frame.begin(purpose, expected.binding(), 7, 11).is_err());
    }
}
