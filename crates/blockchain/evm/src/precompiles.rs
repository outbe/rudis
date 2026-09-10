//! Outbe precompile registration.
//!
//! Routes outbe stateful precompile addresses through
//! `PrecompilesMap::set_ctx_dispatch_hook` (outbe fork extension on alloy-evm)
//! so the dispatch closure receives a raw pointer to the unbroken
//! `&mut EthEvmContext<DB>`. The closure casts the pointer back to the
//! concrete context type for the current `DB`, builds a [`CtxStorageProvider`]
//! borrowing that context, and dispatches via [`StorageHandle`]. Sub-call
//! invocations from the precompile body hand the same `&mut ctx` to the
//! sub-call driver in [`crate::sub_call`].

use alloy_evm::{eth::EthEvmContext, precompiles::PrecompilesMap};
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{Revert, SolError};
use core::fmt::Debug;
use core::marker::PhantomData;
use outbe_compressed_entities::ExecutionScope;
use outbe_metadosis::{api::OcompFinalizedIntentAuthority, config::OcompForkInstallV1};
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_primitives::addresses::{
    FIDELITY_ADDRESS, METADOSIS_ADDRESS, ORACLE_ADDRESS, OUTBE_SYSTEM_TX_ADDRESS, SYSTEM_ADDRESS,
};
use outbe_primitives::storage::gas::PRECOMPILE_BASE_GAS;
use outbe_primitives::storage::{
    metadosis_cycle_allocation_binding, metadosis_init_genesis_binding,
    metadosis_late_settlement_binding, metadosis_ocomp_lifecycle_begin_binding,
    metadosis_ocomp_terminal_request_binding, metadosis_process_ready_binding,
    metadosis_verified_vote_binding, MetadosisCertifiedFinalityBinding,
    MetadosisMutationEntitlements, MetadosisMutationPurposeTag, StorageHandle,
};
use revm::{
    handler::{precompile_output_to_interpreter_result, EthPrecompiles, PrecompileProvider},
    interpreter::{CallInputs, CallScheme, InterpreterResult},
    precompile::{PrecompileHalt, PrecompileOutput, PrecompileResult},
    primitives::hardfork::SpecId,
    Database,
};
use std::sync::Arc;

use crate::{
    gas::SubcallGasMeter,
    precompile_routes::{self, ValuePolicy},
    storage::{CtxStorageProvider, CtxStorageProviderConfig, ReentrancyStack},
    tee_attestation_activation::TeeAttestationChainSpecStateV1,
};

/// Shared marker retained in the sub-call context while q-forming apply
/// accounting is migrated to the direct result-vote path.
#[derive(Debug, Default)]
pub struct OcompActivationBlockMeter;
/// ABI-encode a revert reason as the Solidity-standard `Error(string)`
/// (selector `0x08c379a0` followed by `abi.encode(reason)`).
fn encode_revert_reason(msg: String) -> Bytes {
    Bytes::from(Revert::from(msg).abi_encode())
}

/// Classification of a call's native value at the precompile boundary.
#[derive(Debug, PartialEq, Eq)]
enum BoundaryValue {
    /// Value revm has already moved into the precompile account, safe to credit.
    Credited(U256),
    /// Value that must not reach dispatch, with the reason to revert with.
    Rejected(&'static str),
}

/// Decide how much native value a precompile call may credit.
///
/// Only a non-delegated frame reaches this: dispatch refuses `DELEGATECALL` and
/// `CALLCODE` outright, so revm has already moved any `CallValue::Transfer` into
/// the account whose storage dispatch is about to mutate.
///
/// The `CallValue::Apparent` arm is therefore unreachable. It is not a fallback
/// for the delegated-frame guard and must not be read as one: `CALLCODE` carries
/// a `Transfer`, so removing that guard would leave this function crediting a
/// self-transfer that moved nothing. The guard is the only thing standing there.
///
/// A route that declares `ValuePolicy::Reject` then refuses any credited amount,
/// so a call that would strand funds at a precompile stops before touching state.
fn classify_boundary_value(
    policy: ValuePolicy,
    value: &revm::interpreter::CallValue,
) -> BoundaryValue {
    let credited = match *value {
        revm::interpreter::CallValue::Transfer(v) | revm::interpreter::CallValue::Apparent(v) => v,
    };
    if credited.is_zero() {
        return BoundaryValue::Credited(U256::ZERO);
    }
    if matches!(*value, revm::interpreter::CallValue::Apparent(_)) {
        return BoundaryValue::Rejected("outbe precompile: apparent value is not a transfer");
    }
    if policy == ValuePolicy::Reject {
        return BoundaryValue::Rejected("outbe precompile: non-payable address called with value");
    }
    BoundaryValue::Credited(credited)
}

/// Translate the outbe-level [`outbe_primitives::error::PrecompileError`] (the
/// flat error type returned from every outbe precompile dispatch function)
/// into a revm [`PrecompileResult`] that the EVM interpreter understands.
///
/// `actual_gas` is the total gas charge attributed to this precompile call
/// (`PRECOMPILE_BASE_GAS` plus any storage-op gas). It is reported on
/// success and `Revert*` paths so the interpreter charges the caller
/// correctly; `Halt(OOG)` reports zero gas because revm treats OOG halts
/// as "consume everything" via `spend_all` in
/// `revm-handler::precompile_output_to_interpreter_result`.
///
/// The mapping is exhaustive over `PrecompileError`'s declared variants;
/// the trailing wildcard arm exists only to satisfy `#[non_exhaustive]`
/// from outbe-primitives and surfaces unknown variants as `Fatal` rather
/// than panicking. refine the `SubCall(_)`
/// arm to per-variant halt mappings once the sub-call body produces those
/// errors at runtime.
#[doc(hidden)]
pub fn map_outbe_precompile_result(
    result: outbe_primitives::error::Result<Bytes>,
    actual_gas: u64,
) -> PrecompileResult {
    match result {
        Ok(bytes) => Ok(PrecompileOutput::new(actual_gas, bytes, 0)),
        Err(outbe_primitives::error::PrecompileError::OutOfGas) => {
            Ok(PrecompileOutput::halt(PrecompileHalt::OutOfGas, 0))
        }
        Err(outbe_primitives::error::PrecompileError::Revert(msg)) => Ok(PrecompileOutput::revert(
            actual_gas,
            encode_revert_reason(msg),
            0,
        )),
        Err(outbe_primitives::error::PrecompileError::RevertBytes(bytes)) => {
            Ok(PrecompileOutput::revert(actual_gas, bytes, 0))
        }
        Err(outbe_primitives::error::PrecompileError::WriteProtection) => Ok(
            PrecompileOutput::halt(PrecompileHalt::other("state change during static call"), 0),
        ),
        Err(outbe_primitives::error::PrecompileError::SubCall(err)) => Err(
            revm::precompile::PrecompileError::Fatal(format!("sub-call error: {err:?}")),
        ),
        Err(outbe_primitives::error::PrecompileError::Unsupported) => Err(
            revm::precompile::PrecompileError::Fatal("precompile reported Unsupported".to_string()),
        ),
        Err(e) => Err(revm::precompile::PrecompileError::Fatal(e.to_string())),
    }
}

fn is_lysis_result_vote_call(address: Address, data: &[u8], is_static: bool, value: U256) -> bool {
    address == outbe_ocomp_protocol::abi::METADOSIS_ADDRESS
        && data.get(..4).is_some_and(|selector| {
            selector == outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR
        })
        && !is_static
        && value.is_zero()
}

struct MetadosisMutationCall<'a> {
    address: Address,
    data: &'a [u8],
    caller: Address,
    is_static: bool,
    value: U256,
    ocomp_lifecycle_active: bool,
    chain_id: u64,
    block_number: u64,
    timestamp: u64,
    cycle_active_utc_day: Option<u32>,
    preloaded_certified_state_root: Option<alloy_primitives::B256>,
    ocomp_fork_install: Option<&'a OcompForkInstallV1>,
}

fn metadosis_mutation_entitlements(
    call: MetadosisMutationCall<'_>,
) -> MetadosisMutationEntitlements {
    let MetadosisMutationCall {
        address,
        data,
        caller,
        is_static,
        value,
        ocomp_lifecycle_active,
        chain_id,
        block_number,
        timestamp,
        cycle_active_utc_day,
        preloaded_certified_state_root,
        ocomp_fork_install,
    } = call;
    use MetadosisMutationPurposeTag as Purpose;

    if is_static || !value.is_zero() {
        return MetadosisMutationEntitlements::NONE;
    }
    if is_lysis_result_vote_call(address, data, is_static, value) && ocomp_lifecycle_active {
        return MetadosisMutationEntitlements::exact(
            Purpose::VerifiedResultVote,
            metadosis_verified_vote_binding(data),
        );
    }
    if address != OUTBE_SYSTEM_TX_ADDRESS || caller != SYSTEM_ADDRESS {
        return MetadosisMutationEntitlements::NONE;
    }
    let Ok(input) = crate::system_tx::SystemTxInputV2::decode(data) else {
        return MetadosisMutationEntitlements::NONE;
    };
    match input {
        crate::system_tx::SystemTxInputV2::CertifiedParentAccounting { metadata }
            if metadata.proof_kind
                == outbe_primitives::consensus_metadata::ParentParticipationProof::Finalization =>
        {
            let Some(finalized_state_root) = preloaded_certified_state_root else {
                return MetadosisMutationEntitlements::NONE;
            };
            let certified = MetadosisCertifiedFinalityBinding::new(
                chain_id,
                block_number,
                metadata.finalized_block_number,
                metadata.finalized_block_hash,
                finalized_state_root,
            );
            MetadosisMutationEntitlements::exact(Purpose::CertifiedFinality, certified.binding())
        }
        crate::system_tx::SystemTxInputV2::LateFinalizeCredits { .. } => {
            MetadosisMutationEntitlements::exact(
                Purpose::CertifiedFinality,
                metadosis_late_settlement_binding(chain_id, block_number, timestamp),
            )
        }
        // Exact command identities cover genesis, one contiguous daily
        // allocation when due, and the single hourly Metadosis pass. The cursor
        // is read from Cycle storage by the provider; it is never accepted from
        // calldata. Multi-day gaps grant no missed-day economic authority.
        crate::system_tx::SystemTxInputV2::CycleTick => {
            let genesis_activation_height =
                ocomp_fork_install.map_or(1, |install| install.activation_height);
            let mut entitlements = MetadosisMutationEntitlements::NONE;
            if block_number == genesis_activation_height {
                entitlements = entitlements.union(MetadosisMutationEntitlements::exact(
                    Purpose::CycleLifecycle,
                    metadosis_init_genesis_binding(chain_id, block_number, timestamp),
                ));
            }
            let Some(active_utc_day) = cycle_active_utc_day else {
                return entitlements;
            };
            let block_utc_day = outbe_primitives::time::timestamp_to_date_key(timestamp);
            let Ok(day_action) =
                outbe_cycle::handler::protocol_day_action(active_utc_day, block_utc_day)
            else {
                return entitlements;
            };
            if let outbe_cycle::handler::ProtocolDayAction::SettlePrevious { day } = day_action {
                entitlements = entitlements.union(MetadosisMutationEntitlements::exact(
                    Purpose::CycleLifecycle,
                    metadosis_cycle_allocation_binding(
                        chain_id,
                        block_number,
                        outbe_primitives::time::date_key_to_utc_timestamp(day),
                    ),
                ));
            }
            entitlements.union(MetadosisMutationEntitlements::exact(
                Purpose::CycleLifecycle,
                metadosis_process_ready_binding(chain_id, block_number, timestamp),
            ))
        }
        crate::system_tx::SystemTxInputV2::OcompLifecycleBegin if ocomp_lifecycle_active => {
            let lifecycle = MetadosisMutationEntitlements::exact(
                Purpose::OcompLifecycle,
                metadosis_ocomp_lifecycle_begin_binding(chain_id, block_number, timestamp),
            );
            let Some(install) =
                ocomp_fork_install.filter(|install| install.activation_height == block_number)
            else {
                return lifecycle;
            };
            let Ok(install_hash) =
                install.install_hash(&outbe_metadosis::config::poc_schema_limits())
            else {
                return lifecycle;
            };
            lifecycle.union(MetadosisMutationEntitlements::exact(
                Purpose::ForkProfile,
                install_hash,
            ))
        }
        crate::system_tx::SystemTxInputV2::OcompTerminalRequest if ocomp_lifecycle_active => {
            MetadosisMutationEntitlements::exact(
                Purpose::OcompLifecycle,
                metadosis_ocomp_terminal_request_binding(chain_id, block_number, timestamp),
            )
        }
        _ => MetadosisMutationEntitlements::NONE,
    }
}

/// Returns the list of outbe precompile addresses registered by
/// [`extend_outbe_precompiles`].
///
/// Lookup and enumeration are generated from the same compact declaration in
/// [`crate::precompile_routes`], so dispatch-recognized exact routes cannot be omitted
/// from this list.
pub fn outbe_precompile_addresses() -> &'static [Address] {
    precompile_routes::EXACT_ADDRESSES
}

/// Immutable protocol context shared by every Outbe precompile dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutbePrecompileExecutionContext {
    spec: SpecId,
    genesis_hash: B256,
    tee_attestation_v1: TeeAttestationChainSpecStateV1,
}

impl OutbePrecompileExecutionContext {
    #[must_use]
    pub const fn new(spec: SpecId, genesis_hash: B256) -> Self {
        Self {
            spec,
            genesis_hash,
            tee_attestation_v1: TeeAttestationChainSpecStateV1::Unbound,
        }
    }

    #[must_use]
    pub fn with_tee_attestation_v1(mut self, state: TeeAttestationChainSpecStateV1) -> Self {
        self.tee_attestation_v1 = state;
        self
    }
}

#[derive(Clone)]
pub struct OutbePrecompileRuntime {
    runtime_body_readers: Option<RuntimeBodyReaders>,
    execution_scope: Arc<ExecutionScope>,
    ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
    ocomp_lifecycle_active: bool,
}

impl OutbePrecompileRuntime {
    pub fn new(
        runtime_body_readers: Option<RuntimeBodyReaders>,
        execution_scope: Arc<ExecutionScope>,
        ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
        ocomp_lifecycle_active: bool,
    ) -> Self {
        Self {
            runtime_body_readers,
            execution_scope,
            ocomp_finality_authority,
            ocomp_lifecycle_active,
        }
    }
}

/// Register outbe stateful precompile dispatch on the given [`PrecompilesMap`]
/// via the `set_ctx_dispatch_hook` fork extension.
///
/// The hook receives a raw pointer to the unbroken `&mut EthEvmContext<DB>`
/// before revm destructures it into `EvmInternals`. The dispatch closure
/// casts the pointer back to `&mut EthEvmContext<DB>` (safe because the
/// `EvmFactory` impl that called us is specialised for the same DB), builds a
/// [`CtxStorageProvider`] borrowing that context, and dispatches the outbe
/// precompile through a [`StorageHandle`]. Sub-call from precompile body
/// reaches `sub_call::run` through the provider's `sub_call` method.
/// Registers Outbe precompiles with an executor-owned compressed-entity scope.
pub fn extend_outbe_precompiles<DB>(
    precompiles: &mut PrecompilesMap,
    execution_context: OutbePrecompileExecutionContext,
    runtime: OutbePrecompileRuntime,
    ocomp_fork_install: Option<Arc<OcompForkInstallV1>>,
) where
    DB: Database + Debug,
    DB::Error: Debug,
{
    let OutbePrecompileExecutionContext {
        spec,
        genesis_hash,
        tee_attestation_v1,
    } = execution_context;
    let OutbePrecompileRuntime {
        runtime_body_readers,
        execution_scope,
        ocomp_finality_authority,
        ocomp_lifecycle_active,
    } = runtime;
    let ocomp_activation_block_meter = Arc::new(OcompActivationBlockMeter);
    precompiles.set_ctx_dispatch_hook(
        // handles: claim every outbe address.
        |addr: &Address| precompile_routes::resolve(addr).is_some(),
        // dispatch: ctx_ptr is `*mut EthEvmContext<DB>` (cast in our caller, see
        // `PrecompileProvider::run` in the fork's `precompiles.rs`).
        move |ctx_ptr, inputs| {
            #[allow(unsafe_code)] // sole audited unsafe site; justified below.
            // SAFETY: alloy-evm fork's `PrecompileProvider::run` for
            // PrecompilesMap (specialised at impl site for our `Context<DB>`)
            // casts `&mut Context<...>` to `*mut c_void` and feeds it here.
            // The `DB` generic of this closure is the same `DB` of the
            // `Context<...>` the impl is specialised for (set at
            // `OutbeEvmFactory::create_evm<DB>` call site).
            let ctx: &mut EthEvmContext<DB> = unsafe { &mut *(ctx_ptr as *mut _) };
            outbe_ctx_dispatch::<DB>(
                ctx,
                inputs,
                OutbeDispatchRuntime {
                    spec,
                    genesis_hash,
                    tee_attestation_v1: &tee_attestation_v1,
                    runtime_body_readers: runtime_body_readers.as_ref(),
                    execution_scope: &execution_scope,
                    ocomp_finality_authority: ocomp_finality_authority.clone(),
                    ocomp_activation_block_meter: ocomp_activation_block_meter.clone(),
                    ocomp_lifecycle_active,
                    ocomp_fork_install: ocomp_fork_install.clone(),
                },
            )
        },
    );
}

/// Executor-owned runtime authorities carried into one Outbe dispatch.
struct OutbeDispatchRuntime<'a> {
    spec: SpecId,
    genesis_hash: B256,
    tee_attestation_v1: &'a TeeAttestationChainSpecStateV1,
    runtime_body_readers: Option<&'a RuntimeBodyReaders>,
    execution_scope: &'a Arc<ExecutionScope>,
    ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
    ocomp_activation_block_meter: Arc<OcompActivationBlockMeter>,
    ocomp_lifecycle_active: bool,
    ocomp_fork_install: Option<Arc<OcompForkInstallV1>>,
}

/// Dispatch one outbe precompile call with full context access.
fn outbe_ctx_dispatch<DB>(
    ctx: &mut EthEvmContext<DB>,
    inputs: &CallInputs,
    runtime: OutbeDispatchRuntime<'_>,
) -> Result<Option<InterpreterResult>, String>
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    let OutbeDispatchRuntime {
        spec,
        genesis_hash,
        tee_attestation_v1,
        runtime_body_readers,
        execution_scope,
        ocomp_finality_authority,
        ocomp_activation_block_meter,
        ocomp_lifecycle_active,
        ocomp_fork_install,
    } = runtime;

    use revm::context_interface::{Block as _, ContextTr};

    let address = inputs.bytecode_address;
    let Some(route) = precompile_routes::resolve(&address) else {
        return Ok(None);
    };
    let block_number = ctx.block().number().saturating_to::<u64>();
    let chain_id = ctx.cfg().chain_id;
    let timestamp = ctx.block().timestamp().saturating_to::<u64>();

    // Materialize the exact calldata before choosing the consensus gas charge.
    // Contract -> precompile calls arrive as SharedBuffer and must pay the same
    // activation charge as top-level Bytes calls.
    let data: Bytes = inputs.input.bytes_local(ctx.local());

    // Per-precompile base gas, floored at PRECOMPILE_BASE_GAS so the
    // existing flat-cost contract still holds for default precompiles.
    let is_active_result_vote_selector = ocomp_lifecycle_active
        && address == METADOSIS_ADDRESS
        && data.get(..4).is_some_and(|selector| {
            selector == outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR
        });
    let base_gas = route.base_gas(data.as_ref()).max(PRECOMPILE_BASE_GAS);
    if inputs.gas_limit < base_gas {
        let out = PrecompileOutput::halt(PrecompileHalt::OutOfGas, 0);
        return Ok(Some(precompile_output_to_interpreter_result(
            out,
            inputs.gas_limit,
        )));
    }

    // A precompile's state is keyed by its own address, so a `DELEGATECALL` or
    // `CALLCODE` frame cannot give it the borrowed-code semantics those opcodes
    // promise: dispatch would read and write the precompile's own storage while
    // `caller` stays the frame's inherited caller. Any contract could then take
    // caller-authenticated actions - unstaking, voting, spending - as whoever
    // called it. Refuse the frame instead of executing it under a caller it does
    // not belong to.
    //
    // Matching the scheme rather than comparing addresses states the rule the
    // opcodes define; the address divergence those two produce is a consequence
    // of it, and one that a self-referential frame would not exhibit.
    if matches!(
        inputs.scheme,
        CallScheme::DelegateCall | CallScheme::CallCode
    ) {
        let out = PrecompileOutput::revert(
            base_gas,
            encode_revert_reason(
                "outbe precompile: delegated call frame cannot execute a precompile".to_string(),
            ),
            0,
        );
        return Ok(Some(precompile_output_to_interpreter_result(
            out,
            inputs.gas_limit,
        )));
    }

    // Reentrancy guard: refuse re-entry into the same outbe address on the
    // active thread's call chain.
    let Some(_reentrancy) = ReentrancyStack::try_enter(address) else {
        let out = PrecompileOutput::revert(
            base_gas,
            encode_revert_reason("outbe precompile reentrancy denied".to_string()),
            0,
        );
        return Ok(Some(precompile_output_to_interpreter_result(
            out,
            inputs.gas_limit,
        )));
    };

    let is_static = inputs.is_static;
    let caller = inputs.caller;
    if caller == METADOSIS_ADDRESS && matches!(address, FIDELITY_ADDRESS | ORACLE_ADDRESS) {
        let selector = data.get(..4).map(alloy_primitives::hex::encode);
        tracing::warn!(
            target: "outbe::ocomp::trace",
            "OCOMP_TRACE_V1 kind=forbidden_calculation_entry block={block_number} \
             target={address:#x} selector={}",
            selector.as_deref().unwrap_or("missing")
        );
    }
    let value = match classify_boundary_value(route.value_policy(), &inputs.value) {
        BoundaryValue::Credited(v) => v,
        BoundaryValue::Rejected(reason) => {
            let out =
                PrecompileOutput::revert(base_gas, encode_revert_reason(reason.to_string()), 0);
            return Ok(Some(precompile_output_to_interpreter_result(
                out,
                inputs.gas_limit,
            )));
        }
    };
    let gas_budget = inputs.gas_limit - base_gas;
    let gas_meter = SubcallGasMeter::new(gas_budget);
    let protocol_cycle_call = matches!(
        crate::system_tx::SystemTxInputV2::decode(data.as_ref()),
        Ok(crate::system_tx::SystemTxInputV2::CycleTick)
    );

    tracing::debug!(
        target: "outbe::precompile::gas",
        ?address,
        gas_limit = inputs.gas_limit,
        base_gas,
        gas_budget,
        "precompile dispatch entry"
    );

    let mut provider = CtxStorageProvider::new(
        ctx,
        gas_meter,
        CtxStorageProviderConfig {
            is_static,
            self_address: address,
            reentrancy_stack: ReentrancyStack,
            spec,
            genesis_hash,
            runtime_body_readers: runtime_body_readers.cloned(),
            execution_scope: execution_scope.clone(),
            ocomp_finality_authority: ocomp_finality_authority.clone(),
            ocomp_activation_block_meter: ocomp_activation_block_meter.clone(),
            ocomp_lifecycle_active,
            lysis_activation_entitled: is_lysis_result_vote_call(
                address,
                data.as_ref(),
                is_static,
                value,
            ) && ocomp_lifecycle_active,
            metadosis_mutation_entitlements: metadosis_mutation_entitlements(
                MetadosisMutationCall {
                    address,
                    data: data.as_ref(),
                    caller,
                    is_static,
                    value,
                    ocomp_lifecycle_active,
                    chain_id,
                    block_number,
                    timestamp,
                    cycle_active_utc_day: None,
                    preloaded_certified_state_root:
                        crate::begin_block_precompile::preloaded_certified_parent_state_root(),
                    ocomp_fork_install: ocomp_fork_install.as_deref(),
                },
            ),
        },
    );
    if protocol_cycle_call {
        let active_utc_day = {
            let storage = StorageHandle::new(&mut provider);
            storage
                .contract::<outbe_cycle::schema::Cycle<'_>>()
                .active_utc_day
                .read()
                .map_err(|error| error.to_string())?
        };
        provider.replace_metadosis_mutation_entitlements(metadosis_mutation_entitlements(
            MetadosisMutationCall {
                address,
                data: data.as_ref(),
                caller,
                is_static,
                value,
                ocomp_lifecycle_active,
                chain_id,
                block_number,
                timestamp,
                cycle_active_utc_day: Some(active_utc_day),
                preloaded_certified_state_root:
                    crate::begin_block_precompile::preloaded_certified_parent_state_root(),
                ocomp_fork_install: ocomp_fork_install.as_deref(),
            },
        ));
    }
    let storage = StorageHandle::new(&mut provider);
    let result = if is_active_result_vote_selector {
        outbe_metadosis::commands::submit_verified_result_vote(
            storage,
            execution_scope.as_ref(),
            data.as_ref(),
            value,
            is_static,
        )
    } else if address == OUTBE_SYSTEM_TX_ADDRESS {
        if let Some(readers) = runtime_body_readers {
            crate::begin_block_precompile::dispatch_with_readers_and_ocomp_install(
                storage,
                crate::begin_block_precompile::SystemTxRuntime {
                    scope: execution_scope.as_ref(),
                    parent: readers,
                    ocomp_fork_install: ocomp_fork_install.as_deref(),
                    tee_attestation_v1,
                },
                data.as_ref(),
                caller,
                value,
            )
        } else {
            crate::begin_block_precompile::dispatch_with_tee_attestation(
                storage,
                tee_attestation_v1,
                data.as_ref(),
                caller,
                value,
            )
        }
    } else {
        route.dispatch(
            storage,
            execution_scope.as_ref(),
            runtime_body_readers,
            precompile_routes::RouteCall {
                callee: address,
                data: data.as_ref(),
                caller,
                value,
            },
        )
    };
    if result.is_ok() && is_active_result_vote_selector {
        tracing::info!(
            target: "outbe::ocomp::trace",
            "OCOMP_TRACE_V1 kind=result_vote_committed block={block_number} caller={caller:#x}"
        );
    }
    if let Some(readers) = runtime_body_readers {
        if let Err(error) = &result {
            readers.report_precompile_error(error);
        }
    }

    let storage_gas = gas_budget.saturating_sub(provider.gas.remaining());
    let actual_gas = base_gas + storage_gas;

    tracing::debug!(
        target: "outbe::precompile::gas",
        ?address,
        storage_gas,
        actual_gas,
        gas_remaining = provider.gas.remaining(),
        is_err = result.is_err(),
        "precompile dispatch exit"
    );

    let precompile_result = map_outbe_precompile_result(result, actual_gas);

    let interp_result = match precompile_result {
        Ok(precompile_output) => {
            precompile_output_to_interpreter_result(precompile_output, inputs.gas_limit)
        }
        // Both Fatal(String) and FatalAny(_) propagate as Err(String). At
        // revm 38 these are the only variants; the wildcard is defensive.
        Err(other) => return Err(other.to_string()),
    };

    Ok(Some(interp_result))
}

/// Precompile provider for the borrow-mode sub-call `Evm`
/// (`CTX = &mut EthEvmContext<DB>`), used by [`crate::sub_call`].
///
/// Mirrors the top-level [`PrecompilesMap`] semantics so a sub-call to any
/// outbe precompile behaves exactly like a top-level call: outbe stateful
/// precompiles dispatch through [`outbe_ctx_dispatch`], and everything else
/// (Ethereum precompiles `0x01..0x0a`, ordinary contract calls) falls back to
/// the standard [`EthPrecompiles`].
pub(crate) struct OutbeSubCallPrecompiles<DB> {
    /// Fallback provider for the Ethereum precompiles `0x01..0x0a`.
    eth: EthPrecompiles,
    /// EVM spec id, forwarded to [`outbe_ctx_dispatch`].
    spec: SpecId,
    genesis_hash: B256,
    tee_attestation_v1: TeeAttestationChainSpecStateV1,
    runtime_body_readers: Option<RuntimeBodyReaders>,
    execution_scope: Arc<ExecutionScope>,
    ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
    ocomp_activation_block_meter: Arc<OcompActivationBlockMeter>,
    ocomp_lifecycle_active: bool,
    _db: PhantomData<fn() -> DB>,
}

impl<DB> OutbeSubCallPrecompiles<DB> {
    pub(crate) fn new(
        execution_context: OutbePrecompileExecutionContext,
        runtime: OutbePrecompileRuntime,
        ocomp_activation_block_meter: Arc<OcompActivationBlockMeter>,
    ) -> Self {
        let OutbePrecompileExecutionContext {
            spec,
            genesis_hash,
            tee_attestation_v1,
        } = execution_context;
        let OutbePrecompileRuntime {
            runtime_body_readers,
            execution_scope,
            ocomp_finality_authority,
            ocomp_lifecycle_active,
        } = runtime;
        Self {
            eth: EthPrecompiles::new(spec),
            spec,
            genesis_hash,
            tee_attestation_v1,
            runtime_body_readers,
            execution_scope,
            ocomp_finality_authority,
            ocomp_activation_block_meter,
            ocomp_lifecycle_active,
            _db: PhantomData,
        }
    }
}

impl<DB> PrecompileProvider<&mut EthEvmContext<DB>> for OutbeSubCallPrecompiles<DB>
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: SpecId) -> bool {
        self.spec = spec;
        <EthPrecompiles as PrecompileProvider<&mut EthEvmContext<DB>>>::set_spec(
            &mut self.eth,
            spec,
        )
    }

    fn run(
        &mut self,
        context: &mut &mut EthEvmContext<DB>,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        // Outbe stateful precompiles first. `outbe_ctx_dispatch` returns
        // `Ok(None)` for any non-outbe address, so this is a cheap no-op for
        // Ethereum precompiles and ordinary contract targets.
        if let Some(result) = outbe_ctx_dispatch::<DB>(
            &mut **context,
            inputs,
            OutbeDispatchRuntime {
                spec: self.spec,
                genesis_hash: self.genesis_hash,
                tee_attestation_v1: &self.tee_attestation_v1,
                runtime_body_readers: self.runtime_body_readers.as_ref(),
                execution_scope: &self.execution_scope,
                ocomp_finality_authority: self.ocomp_finality_authority.clone(),
                ocomp_activation_block_meter: self.ocomp_activation_block_meter.clone(),
                ocomp_lifecycle_active: self.ocomp_lifecycle_active,
                ocomp_fork_install: None,
            },
        )? {
            return Ok(Some(result));
        }
        // Standard Ethereum precompiles `0x01..0x0a`; `Ok(None)` here lets the
        // caller push a real interpreter frame for ordinary contract targets.
        <EthPrecompiles as PrecompileProvider<&mut EthEvmContext<DB>>>::run(
            &mut self.eth,
            context,
            inputs,
        )
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        self.eth.warm_addresses()
    }

    fn contains(&self, address: &Address) -> bool {
        self.eth.contains(address)
    }
}

#[cfg(test)]
mod boundary_value_tests {
    use super::{classify_boundary_value, BoundaryValue::Credited, BoundaryValue::Rejected};
    use crate::precompile_routes::{self, ValuePolicy};
    use alloy_primitives::{Address, U256};
    use outbe_primitives::addresses::{
        CREDIS_FACTORY_ADDRESS, DESIS_ADDRESS, EMIT_ADDRESS, GRATIS_ADDRESS, INTEX_FACTORY_ADDRESS,
        STAKING_ADDRESS, VOTE_ADDRESS,
    };
    use revm::interpreter::CallValue;

    const PAYABLE: [Address; 5] = [
        STAKING_ADDRESS,
        INTEX_FACTORY_ADDRESS,
        VOTE_ADDRESS,
        // requestCredis takes the originating CCA's matching COEN stake.
        CREDIS_FACTORY_ADDRESS,
        // burn is the pool's only value-carrying entry point.
        EMIT_ADDRESS,
    ];

    fn policy(address: Address) -> ValuePolicy {
        precompile_routes::resolve(&address)
            .expect("address must be a routed precompile")
            .value_policy()
    }

    /// Apparent value names an amount that was never transferred. Delegated
    /// frames are refused before this point, so the arm is defensive.
    #[test]
    fn apparent_value_is_never_credited() {
        for address in PAYABLE {
            assert_eq!(
                classify_boundary_value(policy(address), &CallValue::Apparent(U256::from(7u64))),
                Rejected("outbe precompile: apparent value is not a transfer"),
            );
        }
    }

    #[test]
    fn zero_value_dispatches_whatever_the_policy() {
        for address in [GRATIS_ADDRESS, DESIS_ADDRESS, STAKING_ADDRESS] {
            for value in [
                CallValue::Transfer(U256::ZERO),
                CallValue::Apparent(U256::ZERO),
            ] {
                assert_eq!(
                    classify_boundary_value(policy(address), &value),
                    Credited(U256::ZERO),
                );
            }
        }
    }

    /// `staking.stake`, `intexfactory.distribute` and `vote.createProposal` are
    /// the payable selectors, so their addresses must still receive funded calls.
    #[test]
    fn transferred_value_is_credited_to_payable_routes() {
        let amount = U256::from(5u64);
        for address in PAYABLE {
            assert_eq!(
                classify_boundary_value(policy(address), &CallValue::Transfer(amount)),
                Credited(amount),
            );
        }
    }

    /// Desis dropped its payable `clearAuction`, so value sent there now has no
    /// accounting path and must not strand at the address.
    #[test]
    fn transferred_value_to_a_reject_route_is_refused() {
        let amount = U256::from(5u64);
        for address in [GRATIS_ADDRESS, DESIS_ADDRESS] {
            assert_eq!(
                classify_boundary_value(policy(address), &CallValue::Transfer(amount)),
                Rejected("outbe precompile: non-payable address called with value"),
            );
        }
    }

    /// Reserving the stablecoin address class must not make native value
    /// unspendable there; the class dispatch decides which addresses may keep it.
    #[test]
    fn the_stablecoin_class_permits_value() {
        let token: Address = "0x53c0000000000000000000000000000000000001"
            .parse()
            .expect("valid stablecoin class address");
        let amount = U256::from(5u64);
        assert_eq!(policy(token), ValuePolicy::Payable);
        assert_eq!(
            classify_boundary_value(policy(token), &CallValue::Transfer(amount)),
            Credited(amount),
        );
    }

    /// Pins which exact routes declare `Payable`. This catches an edit to the
    /// route table. A module that grows a payable selector without publishing it
    /// has that selector's funded calls refused - by the route before dispatch
    /// and again by the module - so the omission shows up as its own broken
    /// entrypoint rather than as stranded value.
    #[test]
    fn only_the_expected_routes_accept_value_among_exact_routes() {
        for address in precompile_routes::EXACT_ADDRESSES {
            assert_eq!(
                policy(*address) == ValuePolicy::Payable,
                PAYABLE.contains(address),
                "unexpected value policy for {address:#x}"
            );
        }
    }
}

#[cfg(test)]
mod lysis_activation_entitlement_tests {
    use super::{
        is_lysis_result_vote_call, map_outbe_precompile_result, metadosis_mutation_entitlements,
        MetadosisMutationCall,
    };
    use alloy_primitives::{Address, Bytes, B256, U256};
    use outbe_ocomp_protocol::abi::{
        GET_OFFCHAIN_JOB_SELECTOR, METADOSIS_ADDRESS, SUBMIT_LYSIS_RESULT_SELECTOR,
    };
    use outbe_primitives::{
        addresses::{OUTBE_SYSTEM_TX_ADDRESS, SYSTEM_ADDRESS},
        consensus::{DkgBoundaryArtifact, ReshareResult},
        consensus_metadata::CertifiedParentAccountingMetadata,
        reshare_artifact::LateFinalizeCreditsArtifact,
        storage::{
            metadosis_cycle_allocation_binding, metadosis_init_genesis_binding,
            metadosis_late_settlement_binding, metadosis_ocomp_lifecycle_begin_binding,
            metadosis_ocomp_terminal_request_binding, metadosis_process_ready_binding,
            metadosis_verified_vote_binding, MetadosisCertifiedFinalityBinding,
            MetadosisMutationEntitlements, MetadosisMutationPurposeTag as Purpose,
        },
        system_tx::SystemTxInputV2,
    };

    const TEST_CHAIN_ID: u64 = 42;
    const TEST_BLOCK_NUMBER: u64 = 9;
    const TEST_TIMESTAMP: u64 = 1_704_067_200;

    fn certified_root() -> B256 {
        B256::repeat_byte(0xa1)
    }

    fn encoded(input: SystemTxInputV2) -> Bytes {
        input.encode().expect("valid system-tx fixture")
    }

    fn boundary() -> DkgBoundaryArtifact {
        DkgBoundaryArtifact {
            epoch: 8,
            dkg_cycle: 2,
            freeze_height: 40,
            planned_activation_height: 42,
            target_set_hash: B256::repeat_byte(0x33),
            vrf_material_version: 3,
            vrf_group_public_key: B256::repeat_byte(0x44),
            vrf_group_public_key_bytes: Bytes::from(vec![0x44; 96]),
            committee_set_hash: B256::repeat_byte(0x66),
            is_validator_set_change: true,
            outcome: Bytes::from_static(b"boundary"),
            is_full_dkg: false,
            reshare: ReshareResult {
                new_active_set: vec![Address::repeat_byte(0x33)],
                active_set_hash: B256::repeat_byte(0x55),
            },
            tee_recipient_pubkeys: Vec::new(),
            tee_expired_target_exclusions: Vec::new(),
            tee_expired_target_exclusions_hash: B256::ZERO,
        }
    }

    fn system_entitlements(
        input: SystemTxInputV2,
        lifecycle_active: bool,
    ) -> MetadosisMutationEntitlements {
        let cycle_active_utc_day = matches!(input, SystemTxInputV2::CycleTick).then(|| {
            outbe_primitives::time::previous_date_key(
                outbe_primitives::time::timestamp_to_date_key(TEST_TIMESTAMP),
            )
        });
        let data = encoded(input);
        metadosis_mutation_entitlements(MetadosisMutationCall {
            address: OUTBE_SYSTEM_TX_ADDRESS,
            data: data.as_ref(),
            caller: SYSTEM_ADDRESS,
            is_static: false,
            value: U256::ZERO,
            ocomp_lifecycle_active: lifecycle_active,
            chain_id: TEST_CHAIN_ID,
            block_number: TEST_BLOCK_NUMBER,
            timestamp: TEST_TIMESTAMP,
            cycle_active_utc_day,
            preloaded_certified_state_root: Some(certified_root()),
            ocomp_fork_install: None,
        })
    }

    fn expected_cycle_entitlements() -> MetadosisMutationEntitlements {
        let current_day = outbe_primitives::time::timestamp_to_date_key(TEST_TIMESTAMP);
        let previous_day = outbe_primitives::time::previous_date_key(current_day);
        let allocation_timestamp = outbe_primitives::time::date_key_to_utc_timestamp(previous_day);
        MetadosisMutationEntitlements::exact(
            Purpose::CycleLifecycle,
            metadosis_cycle_allocation_binding(
                TEST_CHAIN_ID,
                TEST_BLOCK_NUMBER,
                allocation_timestamp,
            ),
        )
        .union(MetadosisMutationEntitlements::exact(
            Purpose::CycleLifecycle,
            metadosis_process_ready_binding(TEST_CHAIN_ID, TEST_BLOCK_NUMBER, TEST_TIMESTAMP),
        ))
    }

    #[test]
    fn protocol_cycle_entitles_genesis_initialization_at_fallback_activation_height() {
        let data = encoded(SystemTxInputV2::CycleTick);
        let entitlements = metadosis_mutation_entitlements(MetadosisMutationCall {
            address: OUTBE_SYSTEM_TX_ADDRESS,
            data: data.as_ref(),
            caller: SYSTEM_ADDRESS,
            is_static: false,
            value: U256::ZERO,
            ocomp_lifecycle_active: false,
            chain_id: TEST_CHAIN_ID,
            block_number: 1,
            timestamp: TEST_TIMESTAMP,
            cycle_active_utc_day: Some(outbe_primitives::time::timestamp_to_date_key(
                TEST_TIMESTAMP,
            )),
            preloaded_certified_state_root: None,
            ocomp_fork_install: None,
        });

        assert!(entitlements.expects(
            Purpose::CycleLifecycle,
            metadosis_init_genesis_binding(TEST_CHAIN_ID, 1, TEST_TIMESTAMP),
        ));
    }

    #[test]
    fn inactive_lysis_selector_does_not_abort_block_execution() {
        use alloy_sol_types::SolCall;
        use outbe_primitives::storage::gas::PRECOMPILE_BASE_GAS;
        use outbe_primitives::storage::hashmap::HashMapStorageProvider;
        use outbe_primitives::storage::StorageHandle;

        let call = outbe_metadosis::precompile::IMetadosis::submitLysisResultCall {
            resultVoteV1: Bytes::from(vec![0_u8; 8]),
        };
        let mut provider = HashMapStorageProvider::new(TEST_CHAIN_ID);
        let result = StorageHandle::enter(&mut provider, |storage| {
            outbe_metadosis::precompile::dispatch(
                storage,
                &call.abi_encode(),
                Address::ZERO,
                U256::ZERO,
            )
        });

        // With the OCOMP lifecycle inactive, the selector reaches the view
        // dispatcher. The mapped outcome must be an ordinary revert output -
        // an `Err` here becomes a revm `Fatal` that aborts the whole payload
        // build for a transaction any external account can submit.
        let output = map_outbe_precompile_result(result, PRECOMPILE_BASE_GAS)
            .expect("inactive lysis vote must map to a revert, not a block-aborting error");
        assert!(output.is_revert());
        let mut expected = Vec::with_capacity(36);
        expected.extend_from_slice(&outbe_ocomp_protocol::abi::OCOMP_RESULT_VOTE_REJECTED_SELECTOR);
        expected.extend_from_slice(&U256::from(5_u64).to_be_bytes::<32>());
        assert_eq!(output.bytes, Bytes::from(expected));
    }

    #[test]
    fn only_exact_non_static_value_free_metadosis_result_vote_is_entitled() {
        assert!(is_lysis_result_vote_call(
            METADOSIS_ADDRESS,
            &SUBMIT_LYSIS_RESULT_SELECTOR,
            false,
            U256::ZERO,
        ));
        assert!(!is_lysis_result_vote_call(
            Address::repeat_byte(1),
            &SUBMIT_LYSIS_RESULT_SELECTOR,
            false,
            U256::ZERO,
        ));
        assert!(!is_lysis_result_vote_call(
            METADOSIS_ADDRESS,
            &GET_OFFCHAIN_JOB_SELECTOR,
            false,
            U256::ZERO,
        ));
        assert!(!is_lysis_result_vote_call(
            METADOSIS_ADDRESS,
            &SUBMIT_LYSIS_RESULT_SELECTOR,
            true,
            U256::ZERO,
        ));
        assert!(!is_lysis_result_vote_call(
            METADOSIS_ADDRESS,
            &SUBMIT_LYSIS_RESULT_SELECTOR,
            false,
            U256::from(1),
        ));
    }

    #[test]
    fn exact_production_causes_receive_only_their_purpose() {
        let metadata = CertifiedParentAccountingMetadata::default();
        let certified = MetadosisCertifiedFinalityBinding::new(
            TEST_CHAIN_ID,
            TEST_BLOCK_NUMBER,
            metadata.finalized_block_number,
            metadata.finalized_block_hash,
            certified_root(),
        );
        assert_eq!(
            system_entitlements(
                SystemTxInputV2::CertifiedParentAccounting { metadata },
                false,
            ),
            MetadosisMutationEntitlements::exact(Purpose::CertifiedFinality, certified.binding(),),
        );
        assert_eq!(
            system_entitlements(SystemTxInputV2::CycleTick, false),
            expected_cycle_entitlements(),
        );
        assert_eq!(
            system_entitlements(
                SystemTxInputV2::LateFinalizeCredits {
                    artifact: LateFinalizeCreditsArtifact::default(),
                },
                false,
            ),
            MetadosisMutationEntitlements::exact(
                Purpose::CertifiedFinality,
                metadosis_late_settlement_binding(TEST_CHAIN_ID, TEST_BLOCK_NUMBER, TEST_TIMESTAMP,),
            ),
        );
        assert_eq!(
            system_entitlements(SystemTxInputV2::OcompLifecycleBegin, true),
            MetadosisMutationEntitlements::exact(
                Purpose::OcompLifecycle,
                metadosis_ocomp_lifecycle_begin_binding(
                    TEST_CHAIN_ID,
                    TEST_BLOCK_NUMBER,
                    TEST_TIMESTAMP,
                ),
            ),
        );
        assert_eq!(
            system_entitlements(SystemTxInputV2::OcompTerminalRequest, true),
            MetadosisMutationEntitlements::exact(
                Purpose::OcompLifecycle,
                metadosis_ocomp_terminal_request_binding(
                    TEST_CHAIN_ID,
                    TEST_BLOCK_NUMBER,
                    TEST_TIMESTAMP,
                ),
            ),
        );
        assert_eq!(
            system_entitlements(
                SystemTxInputV2::BoundaryOutcome {
                    artifact: boundary(),
                },
                false,
            ),
            MetadosisMutationEntitlements::NONE,
        );
        assert_eq!(
            metadosis_mutation_entitlements(MetadosisMutationCall {
                address: METADOSIS_ADDRESS,
                data: &SUBMIT_LYSIS_RESULT_SELECTOR,
                caller: Address::repeat_byte(0x99),
                is_static: false,
                value: U256::ZERO,
                ocomp_lifecycle_active: true,
                chain_id: TEST_CHAIN_ID,
                block_number: TEST_BLOCK_NUMBER,
                timestamp: TEST_TIMESTAMP,
                cycle_active_utc_day: None,
                preloaded_certified_state_root: None,
                ocomp_fork_install: None,
            }),
            MetadosisMutationEntitlements::exact(
                Purpose::VerifiedResultVote,
                metadosis_verified_vote_binding(&SUBMIT_LYSIS_RESULT_SELECTOR),
            ),
        );
    }

    #[test]
    fn protocol_cycle_grants_no_daily_allocation_after_a_multi_day_halt() {
        let block_day = outbe_primitives::time::timestamp_to_date_key(TEST_TIMESTAMP);
        let mut active_day = block_day;
        for _ in 0..6 {
            active_day = outbe_primitives::time::previous_date_key(active_day);
        }
        let data = encoded(SystemTxInputV2::CycleTick);
        let entitlements = metadosis_mutation_entitlements(MetadosisMutationCall {
            address: OUTBE_SYSTEM_TX_ADDRESS,
            data: data.as_ref(),
            caller: SYSTEM_ADDRESS,
            is_static: false,
            value: U256::ZERO,
            ocomp_lifecycle_active: false,
            chain_id: TEST_CHAIN_ID,
            block_number: TEST_BLOCK_NUMBER,
            timestamp: TEST_TIMESTAMP,
            cycle_active_utc_day: Some(active_day),
            preloaded_certified_state_root: None,
            ocomp_fork_install: None,
        });

        let mut day = active_day;
        while day < block_day {
            assert!(!entitlements.expects(
                Purpose::CycleLifecycle,
                metadosis_cycle_allocation_binding(
                    TEST_CHAIN_ID,
                    TEST_BLOCK_NUMBER,
                    outbe_primitives::time::date_key_to_utc_timestamp(day),
                ),
            ));
            day = outbe_primitives::time::next_date_key(day);
        }
        assert!(entitlements.expects(
            Purpose::CycleLifecycle,
            metadosis_process_ready_binding(TEST_CHAIN_ID, TEST_BLOCK_NUMBER, TEST_TIMESTAMP),
        ));
    }

    #[test]
    fn route_or_envelope_mismatch_grants_no_mutation_authority() {
        let cycle = encoded(SystemTxInputV2::CycleTick);
        for (address, caller, is_static, value) in [
            (Address::repeat_byte(1), SYSTEM_ADDRESS, false, U256::ZERO),
            (
                OUTBE_SYSTEM_TX_ADDRESS,
                Address::repeat_byte(2),
                false,
                U256::ZERO,
            ),
            (OUTBE_SYSTEM_TX_ADDRESS, SYSTEM_ADDRESS, true, U256::ZERO),
            (
                OUTBE_SYSTEM_TX_ADDRESS,
                SYSTEM_ADDRESS,
                false,
                U256::from(1),
            ),
        ] {
            assert_eq!(
                metadosis_mutation_entitlements(MetadosisMutationCall {
                    address,
                    data: cycle.as_ref(),
                    caller,
                    is_static,
                    value,
                    ocomp_lifecycle_active: false,
                    chain_id: TEST_CHAIN_ID,
                    block_number: TEST_BLOCK_NUMBER,
                    timestamp: TEST_TIMESTAMP,
                    cycle_active_utc_day: None,
                    preloaded_certified_state_root: None,
                    ocomp_fork_install: None,
                }),
                MetadosisMutationEntitlements::NONE,
            );
        }

        assert_eq!(
            metadosis_mutation_entitlements(MetadosisMutationCall {
                address: OUTBE_SYSTEM_TX_ADDRESS,
                data: b"malformed",
                caller: SYSTEM_ADDRESS,
                is_static: false,
                value: U256::ZERO,
                ocomp_lifecycle_active: false,
                chain_id: TEST_CHAIN_ID,
                block_number: TEST_BLOCK_NUMBER,
                timestamp: TEST_TIMESTAMP,
                cycle_active_utc_day: None,
                preloaded_certified_state_root: None,
                ocomp_fork_install: None,
            }),
            MetadosisMutationEntitlements::NONE,
        );
        assert_eq!(
            system_entitlements(SystemTxInputV2::OracleSlashWindow, false),
            MetadosisMutationEntitlements::NONE,
        );
        assert_eq!(
            system_entitlements(SystemTxInputV2::OcompLifecycleBegin, false),
            MetadosisMutationEntitlements::NONE,
        );
        assert_eq!(
            system_entitlements(SystemTxInputV2::OcompTerminalRequest, false),
            MetadosisMutationEntitlements::NONE,
        );
        assert_eq!(
            metadosis_mutation_entitlements(MetadosisMutationCall {
                address: METADOSIS_ADDRESS,
                data: &SUBMIT_LYSIS_RESULT_SELECTOR,
                caller: Address::repeat_byte(3),
                is_static: false,
                value: U256::ZERO,
                ocomp_lifecycle_active: false,
                chain_id: TEST_CHAIN_ID,
                block_number: TEST_BLOCK_NUMBER,
                timestamp: TEST_TIMESTAMP,
                cycle_active_utc_day: None,
                preloaded_certified_state_root: None,
                ocomp_fork_install: None,
            }),
            MetadosisMutationEntitlements::NONE,
        );
        assert_eq!(
            metadosis_mutation_entitlements(MetadosisMutationCall {
                address: METADOSIS_ADDRESS,
                data: &GET_OFFCHAIN_JOB_SELECTOR,
                caller: Address::repeat_byte(3),
                is_static: false,
                value: U256::ZERO,
                ocomp_lifecycle_active: true,
                chain_id: TEST_CHAIN_ID,
                block_number: TEST_BLOCK_NUMBER,
                timestamp: TEST_TIMESTAMP,
                cycle_active_utc_day: None,
                preloaded_certified_state_root: None,
                ocomp_fork_install: None,
            }),
            MetadosisMutationEntitlements::NONE,
        );
    }
}
