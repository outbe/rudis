//! Custom EVM factory for Outbe.
//!
//! `OutbeEvmFactory` creates EVM instances with Outbe precompiles registered
//! via `set_precompile_lookup`. The factory is wired into reth's node via
//! `OutbeExecutorBuilder` (defined in `crate::config`).

use alloy_evm::{
    eth::EthEvmContext,
    precompiles::PrecompilesMap,
    revm::handler::{instructions::EthInstructions, EthFrame, EthPrecompiles, PrecompileProvider},
    Evm, EvmFactory,
};
use alloy_primitives::{Address, Bytes, TxKind, B256};
use core::ops::{Deref, DerefMut};
use outbe_compressed_entities::ExecutionScope;
use outbe_metadosis::{api::OcompFinalizedIntentAuthority, config::OcompForkInstallV1};
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_primitives::system_tx::OcompLifecycleActivation;
use reth_ethereum::evm::{
    primitives::{Database, EvmEnv},
    revm::{
        context::{BlockEnv, CfgEnv, Context, Evm as RevmEvm, TxEnv},
        context_interface::{
            result::{EVMError, HaltReason, ResultAndState},
            ContextSetters,
        },
        inspector::{Inspector, NoOpInspector},
        interpreter::{interpreter::EthInterpreter, InterpreterResult},
        primitives::hardfork::SpecId,
        ExecuteEvm, MainBuilder, MainContext, SystemCallEvm,
    },
};
use revm::handler::{Handler, MainnetHandler};
use revm::inspector::InspectorHandler;
use std::sync::Arc;

use crate::{
    create_guard::{self, ReservedNamespaceHandler},
    precompiles::{extend_outbe_precompiles, OutbePrecompileExecutionContext},
    tee_attestation_activation::TeeAttestationChainSpecStateV1,
};

#[cfg(test)]
use reth_ethereum::evm::revm::context_interface::result::{
    ExecutionResult, OutOfGasError, ResultGas,
};

#[cfg(test)]
thread_local! {
    static FORCE_OUTBE_SYSTEM_CALL_ERROR: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static FORCE_OUTBE_SYSTEM_CALL_OOG_HALT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static FORCE_OUTBE_SYSTEM_CALL_REVERT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn with_forced_outbe_system_call_error<R>(f: impl FnOnce() -> R) -> R {
    struct ResetForcedOutbeSystemCallError;

    impl Drop for ResetForcedOutbeSystemCallError {
        fn drop(&mut self) {
            FORCE_OUTBE_SYSTEM_CALL_ERROR.with(|cell| cell.set(false));
        }
    }

    FORCE_OUTBE_SYSTEM_CALL_ERROR.with(|cell| cell.set(true));
    let _guard = ResetForcedOutbeSystemCallError;
    f()
}

#[cfg(test)]
pub(crate) fn with_forced_outbe_system_call_oog_halt<R>(f: impl FnOnce() -> R) -> R {
    struct ResetForcedOutbeSystemCallOogHalt;

    impl Drop for ResetForcedOutbeSystemCallOogHalt {
        fn drop(&mut self) {
            FORCE_OUTBE_SYSTEM_CALL_OOG_HALT.with(|cell| cell.set(false));
        }
    }

    FORCE_OUTBE_SYSTEM_CALL_OOG_HALT.with(|cell| cell.set(true));
    let _guard = ResetForcedOutbeSystemCallOogHalt;
    f()
}

#[cfg(test)]
pub(crate) fn with_forced_outbe_system_call_revert<R>(f: impl FnOnce() -> R) -> R {
    struct ResetForcedOutbeSystemCallRevert;

    impl Drop for ResetForcedOutbeSystemCallRevert {
        fn drop(&mut self) {
            FORCE_OUTBE_SYSTEM_CALL_REVERT.with(|cell| cell.set(false));
        }
    }

    FORCE_OUTBE_SYSTEM_CALL_REVERT.with(|cell| cell.set(true));
    let _guard = ResetForcedOutbeSystemCallRevert;
    f()
}

/// Outbe EVM wrapper.
///
/// Upstream `EthEvm::transact_system_call` delegates to revm's EIP system-call
/// helper, which builds a 30M-gas tx. Outbe begin-zone system transactions are
/// protocol transactions with their own 10B-gas execution lane, so calls into
/// `OUTBE_SYSTEM_TX_ADDRESS` build the system-call `TxEnv` locally with
/// `SYSTEM_TX_ARTIFACT_GAS_LIMIT`. Other system calls keep upstream semantics.
#[expect(missing_debug_implementations)]
pub struct OutbeEvm<DB: Database, I, PRECOMPILE = EthPrecompiles> {
    inner: RevmEvm<
        EthEvmContext<DB>,
        I,
        EthInstructions<EthInterpreter, EthEvmContext<DB>>,
        PRECOMPILE,
        EthFrame,
    >,
    inspect: bool,
    runtime_body_readers: Option<RuntimeBodyReaders>,
    execution_scope: Arc<ExecutionScope>,
}

impl<DB: Database, I, PRECOMPILE> OutbeEvm<DB, I, PRECOMPILE> {
    /// Creates a new Outbe EVM instance.
    pub const fn new(
        evm: RevmEvm<
            EthEvmContext<DB>,
            I,
            EthInstructions<EthInterpreter, EthEvmContext<DB>>,
            PRECOMPILE,
            EthFrame,
        >,
        inspect: bool,
        runtime_body_readers: Option<RuntimeBodyReaders>,
        execution_scope: Arc<ExecutionScope>,
    ) -> Self {
        Self {
            inner: evm,
            inspect,
            runtime_body_readers,
            execution_scope,
        }
    }

    /// Readers scoped to this concrete EVM instance and its nested calls.
    pub const fn runtime_body_readers(&self) -> Option<&RuntimeBodyReaders> {
        self.runtime_body_readers.as_ref()
    }

    /// Block-scoped compressed-entity lifecycle capability shared with every
    /// top-level and nested precompile dispatch in this EVM.
    pub fn execution_scope(&self) -> &Arc<ExecutionScope> {
        &self.execution_scope
    }

    /// Consumes self and returns the inner revm instance.
    pub fn into_inner(
        self,
    ) -> RevmEvm<
        EthEvmContext<DB>,
        I,
        EthInstructions<EthInterpreter, EthEvmContext<DB>>,
        PRECOMPILE,
        EthFrame,
    > {
        self.inner
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &EthEvmContext<DB> {
        &self.inner.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub const fn ctx_mut(&mut self) -> &mut EthEvmContext<DB> {
        &mut self.inner.ctx
    }
}

impl<DB: Database, I, PRECOMPILE> Deref for OutbeEvm<DB, I, PRECOMPILE> {
    type Target = EthEvmContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, PRECOMPILE> DerefMut for OutbeEvm<DB, I, PRECOMPILE> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I, PRECOMPILE> Evm for OutbeEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
    PRECOMPILE: PrecompileProvider<EthEvmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PRECOMPILE;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn cfg_env(&self) -> &CfgEnv<Self::Spec> {
        &self.cfg
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.ctx.set_tx(tx);
        let mut handler: ReservedNamespaceHandler<_, EVMError<DB::Error>> = Default::default();
        let output = if self.inspect {
            handler.inspect_run(&mut self.inner)
        } else {
            handler.run(&mut self.inner)
        };
        let state = self.inner.finalize();
        Ok(ResultAndState::new(output?, state))
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if contract != outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS {
            return self.inner.system_call_with_caller(caller, contract, data);
        }

        #[cfg(test)]
        if FORCE_OUTBE_SYSTEM_CALL_ERROR.with(|cell| cell.get()) {
            return Err(EVMError::Custom(
                "forced Outbe system-call error for regression test".into(),
            ));
        }
        #[cfg(test)]
        if FORCE_OUTBE_SYSTEM_CALL_OOG_HALT.with(|cell| cell.get()) {
            return Ok(ResultAndState::new(
                ExecutionResult::Halt {
                    reason: HaltReason::OutOfGas(OutOfGasError::Precompile),
                    gas: ResultGas::new_with_state_gas(
                        outbe_primitives::system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT,
                        0,
                        0,
                        0,
                    ),
                    logs: Vec::new(),
                },
                Default::default(),
            ));
        }
        #[cfg(test)]
        if FORCE_OUTBE_SYSTEM_CALL_REVERT.with(|cell| cell.get()) {
            return Ok(ResultAndState::new(
                ExecutionResult::Revert {
                    gas: ResultGas::new_with_state_gas(42_000, 0, 0, 0),
                    logs: Vec::new(),
                    output: Bytes::from_static(b"forced Outbe system-call revert"),
                },
                Default::default(),
            ));
        }

        let tx = TxEnv::builder()
            .caller(caller)
            .kind(TxKind::Call(contract))
            .data(data)
            .gas_limit(outbe_primitives::system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT)
            .build_fill();

        self.inner.ctx.set_tx(tx);
        let mut handler: MainnetHandler<_, EVMError<DB::Error>, EthFrame> =
            MainnetHandler::default();
        let result = handler.run_system_call(&mut self.inner)?;
        let state = self.inner.finalize();

        Ok(ResultAndState::new(result, state))
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context {
            block: block_env,
            cfg: cfg_env,
            journaled_state,
            ..
        } = self.inner.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.ctx.journaled_state.database,
            &self.inner.inspector,
            &self.inner.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.ctx.journaled_state.database,
            &mut self.inner.inspector,
            &mut self.inner.precompiles,
        )
    }
}

/// Custom EVM factory that registers Outbe stateful precompiles.
#[derive(Clone, Default)]
pub struct OutbeEvmFactory {
    /// Immutable chain identity installed by `OutbeEvmConfig`.
    genesis_hash: B256,
    tee_attestation_v1: TeeAttestationChainSpecStateV1,
    runtime_body_readers: Option<RuntimeBodyReaders>,
    compressed_tree_service:
        Arc<std::sync::RwLock<Option<Arc<outbe_compressed_entities::CompressedTreeService>>>>,
    ocomp_finality_authority:
        Arc<std::sync::RwLock<Option<Arc<dyn OcompFinalizedIntentAuthority>>>>,
    ocomp_lifecycle_activation: Arc<std::sync::RwLock<OcompLifecycleActivation>>,
    ocomp_fork_install: Arc<std::sync::RwLock<Option<Arc<OcompForkInstallV1>>>>,
}

impl core::fmt::Debug for OutbeEvmFactory {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OutbeEvmFactory")
            .field("genesis_hash", &self.genesis_hash)
            .field("tee_attestation_v1", &self.tee_attestation_v1)
            .field("runtime_body_readers", &self.runtime_body_readers.is_some())
            .field(
                "compressed_tree_service",
                &self
                    .compressed_tree_service
                    .read()
                    .is_ok_and(|v| v.is_some()),
            )
            .field(
                "ocomp_finality_authority",
                &self
                    .ocomp_finality_authority
                    .read()
                    .is_ok_and(|authority| authority.is_some()),
            )
            .field(
                "ocomp_lifecycle_activation",
                &self
                    .ocomp_lifecycle_activation
                    .read()
                    .map_or(OcompLifecycleActivation::Disabled, |value| *value),
            )
            .field(
                "ocomp_fork_install",
                &self
                    .ocomp_fork_install
                    .read()
                    .is_ok_and(|install| install.is_some()),
            )
            .finish()
    }
}

impl OutbeEvmFactory {
    /// Constructs an EVM factory without off-chain runtime body readers.
    ///
    /// This transitional constructor supports focused tests and offline tools.
    /// Live node construction installs the required readers through
    /// [`Self::with_runtime_body_readers`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds every EVM/precompile context created by this factory to the
    /// canonical genesis hash from ChainSpec.
    #[must_use]
    pub fn with_genesis_hash(mut self, genesis_hash: B256) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    /// Returns the immutable genesis hash installed for every EVM context.
    #[must_use]
    pub const fn genesis_hash(&self) -> B256 {
        self.genesis_hash
    }

    #[must_use]
    pub fn with_tee_attestation_v1(mut self, state: TeeAttestationChainSpecStateV1) -> Self {
        self.tee_attestation_v1 = state;
        self
    }

    /// Constructs an EVM factory with read-only Tribute and Nod body authority.
    #[must_use]
    pub fn with_runtime_body_readers(runtime_body_readers: RuntimeBodyReaders) -> Self {
        Self {
            genesis_hash: B256::ZERO,
            tee_attestation_v1: TeeAttestationChainSpecStateV1::Unbound,
            runtime_body_readers: Some(runtime_body_readers),
            compressed_tree_service: Arc::default(),
            ocomp_finality_authority: Arc::default(),
            ocomp_lifecycle_activation: Arc::default(),
            ocomp_fork_install: Arc::default(),
        }
    }

    /// Returns the typed runtime body readers installed in this factory.
    #[must_use]
    pub const fn runtime_body_readers(&self) -> Option<&RuntimeBodyReaders> {
        self.runtime_body_readers.as_ref()
    }

    pub fn install_compressed_tree_service(
        &self,
        service: Arc<outbe_compressed_entities::CompressedTreeService>,
    ) {
        *self
            .compressed_tree_service
            .write()
            .expect("compressed tree service lock") = Some(service);
    }

    pub(crate) fn install_ocomp_finality_authority(
        &self,
        authority: Arc<dyn OcompFinalizedIntentAuthority>,
    ) {
        *self
            .ocomp_finality_authority
            .write()
            .expect("OCOMP finality authority lock") = Some(authority);
    }

    pub fn install_ocomp_lifecycle_activation(&self, activation: OcompLifecycleActivation) {
        *self
            .ocomp_lifecycle_activation
            .write()
            .expect("OCOMP lifecycle activation lock") = activation;
    }

    pub fn install_ocomp_fork_install(&self, install: Arc<OcompForkInstallV1>) {
        *self
            .ocomp_fork_install
            .write()
            .expect("OCOMP fork install lock") = Some(install);
    }
}

impl EvmFactory for OutbeEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>, EthInterpreter>> =
        OutbeEvm<DB, I, Self::Precompiles>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Context<DB: Database> = EthEvmContext<DB>;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        let spec = input.cfg_env.spec;
        let block_number = input.block_env.number.saturating_to::<u64>();
        let ocomp_lifecycle_active = self
            .ocomp_lifecycle_activation
            .read()
            .is_ok_and(|activation| activation.is_active_at(block_number));
        let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::new(spec).precompiles);
        let runtime_body_readers = self
            .runtime_body_readers
            .as_ref()
            .map(RuntimeBodyReaders::fork_execution);
        let rpc_tree_service = self
            .compressed_tree_service
            .read()
            .ok()
            .and_then(|service| service.clone());
        let execution_scope = rpc_tree_service
            .and_then(|service| {
                service.finalized_marker().ok().map(|marker| {
                    Arc::new(ExecutionScope::for_finalized_rpc(
                        service,
                        marker.commitment_scheme_version,
                        marker.height,
                        marker.block_hash,
                    ))
                })
            })
            .unwrap_or_else(|| Arc::new(ExecutionScope::new()));
        let ocomp_finality_authority = self
            .ocomp_finality_authority
            .read()
            .ok()
            .and_then(|authority| authority.clone());
        let ocomp_fork_install = self
            .ocomp_fork_install
            .read()
            .ok()
            .and_then(|install| install.clone());

        // Register Outbe stateful precompiles via dynamic lookup.
        extend_outbe_precompiles::<DB>(
            &mut precompiles,
            OutbePrecompileExecutionContext::new(spec, self.genesis_hash)
                .with_tee_attestation_v1(self.tee_attestation_v1.clone()),
            crate::precompiles::OutbePrecompileRuntime::new(
                runtime_body_readers.clone(),
                execution_scope.clone(),
                ocomp_finality_authority,
                ocomp_lifecycle_active,
            ),
            ocomp_fork_install,
        );

        let mut evm = Context::mainnet()
            .with_db(db)
            .with_cfg(input.cfg_env)
            .with_block(input.block_env)
            .build_mainnet_with_inspector(NoOpInspector {})
            .with_precompiles(precompiles);
        create_guard::install(&mut evm.instruction);

        OutbeEvm::new(evm, false, runtime_body_readers, execution_scope)
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>, EthInterpreter>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let evm = self.create_evm(db, input);
        let runtime_body_readers = evm.runtime_body_readers().cloned();
        let execution_scope = evm.execution_scope().clone();
        OutbeEvm::new(
            evm.into_inner().with_inspector(inspector),
            true,
            runtime_body_readers,
            execution_scope,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use outbe_offchain_data::RuntimeBodyReaders;
    use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle, StorageWriterHandle};
    use outbe_primitives::time::WorldwideDay;
    use outbe_tribute::{TributeData, TributeRepositoryWriter};
    use revm::database_interface::EmptyDB;
    use std::sync::Arc;

    const USER_BLOCK_GAS_LIMIT: u64 = 30_000_000;

    fn test_env() -> EvmEnv {
        EvmEnv {
            cfg_env: CfgEnv::new()
                .with_chain_id(1)
                .with_spec_and_mainnet_gas_params(SpecId::SHANGHAI),
            block_env: BlockEnv {
                gas_limit: USER_BLOCK_GAS_LIMIT,
                ..Default::default()
            },
        }
    }

    #[test]
    fn runtime_body_reader_clone_reaches_evm_factory_construction() {
        let storage = Arc::new(MemoryStorage::new());
        let reader: StorageReaderHandle = storage.clone();
        let writer: StorageWriterHandle = storage;
        let readers = RuntimeBodyReaders::new(reader.clone());
        let factory = OutbeEvmFactory::with_runtime_body_readers(readers.clone());
        let _evm = factory.create_evm(EmptyDB::default(), test_env());
        let worldwide_day = WorldwideDay::new(20_260_715);
        let tribute_id =
            outbe_nod::NodContract::generate_nod_id(Address::repeat_byte(0x11), worldwide_day)
                .unwrap();

        assert!(readers.tribute().get(tribute_id).unwrap().is_none());

        TributeRepositoryWriter::new(reader, writer)
            .put(&TributeData {
                tribute_id,
                owner: Address::repeat_byte(0x11),
                worldwide_day,
                issuance_amount_minor: U256::from(100),
                issuance_currency: 840,
                nominal_amount_minor: U256::from(90),
                reference_currency: 978,
                tribute_price_minor: U256::from(3),
                exclude_from_intex_issuance: true,
            })
            .unwrap();

        let stored = factory
            .runtime_body_readers()
            .expect("runtime body readers installed")
            .tribute()
            .get(tribute_id)
            .unwrap()
            .expect("factory clone observes the shared adapter");
        assert_eq!(stored.tribute_id, tribute_id);
        assert_eq!(stored.owner, Address::repeat_byte(0x11));
    }

    #[test]
    fn outbe_system_call_uses_artifact_gas_limit_without_changing_block_limit() {
        let factory = OutbeEvmFactory::new();
        let mut evm = factory.create_evm(EmptyDB::default(), test_env());

        let _ = evm.transact_system_call(
            outbe_primitives::addresses::SYSTEM_ADDRESS,
            outbe_primitives::addresses::OUTBE_SYSTEM_TX_ADDRESS,
            Bytes::new(),
        );

        assert_eq!(
            evm.ctx().tx.gas_limit,
            outbe_primitives::system_tx::SYSTEM_TX_ARTIFACT_GAS_LIMIT
        );
        assert_eq!(evm.ctx().block.gas_limit, USER_BLOCK_GAS_LIMIT);
    }

    #[test]
    fn non_outbe_system_call_keeps_upstream_gas_limit() {
        let factory = OutbeEvmFactory::new();
        let mut evm = factory.create_evm(EmptyDB::default(), test_env());

        let _ = evm.transact_system_call(
            outbe_primitives::addresses::SYSTEM_ADDRESS,
            Address::repeat_byte(0x42),
            Bytes::new(),
        );

        assert_eq!(evm.ctx().tx.gas_limit, USER_BLOCK_GAS_LIMIT);
        assert_eq!(evm.ctx().block.gas_limit, USER_BLOCK_GAS_LIMIT);
    }
}
