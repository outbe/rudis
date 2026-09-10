//! Sub-call driver.
//!
//! Drives a child CALL/STATICCALL frame from inside an outbe Rust precompile
//! by constructing a fresh borrow-mode
//! `Evm<&mut EthEvmContext<DB>, (), EthInstructions<...>, EthPrecompiles,
//! EthFrame<...>>` and mirroring revm's canonical
//! [`Handler::run_exec_loop`](https://docs.rs/revm-handler/18.1.0/src/revm_handler/handler.rs.html)
//! pattern until the child terminates.
//!
//! Child frame uses [`crate::precompiles::OutbeSubCallPrecompiles`], so both
//! the Ethereum precompiles `0x01..0x0a` AND the outbe stateful precompiles are
//! reachable from the child frame.
//!
//! Atomicity is provided by the OUTER caller wrapping
//! `storage.call(...)` / `storage.staticcall(...)` in `StorageHandle::with_checkpoint`.
//! The driver itself does NOT take an extra checkpoint - `make_call_frame`
//! handles per-frame journal checkpoints internally.

use alloy_evm::eth::EthEvmContext;
use alloy_primitives::{Address, B256, U256};
use core::fmt::Debug;
use outbe_compressed_entities::ExecutionScope;
use outbe_metadosis::api::OcompFinalizedIntentAuthority;
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_primitives::storage::{SubCallError, SubCallInput, SubCallOutput, SubCallStatus};
use revm::{
    context::Evm,
    context_interface::{journaled_state::account::JournaledAccountTr, ContextTr, JournalTr},
    handler::{instructions::EthInstructions, EthFrame, EvmTr, FrameResult, ItemOrResult},
    interpreter::{
        interpreter::EthInterpreter,
        interpreter_action::{CallInputs, FrameInit, FrameInput},
        CallInput, CallOutcome, CallScheme, CallValue, InstructionResult, InterpreterResult,
        SharedMemory,
    },
    primitives::hardfork::SpecId,
    state::Bytecode,
    Database,
};
use std::sync::Arc;

/// Runs a sub-call with the executor-owned compressed-entity lifecycle scope.
///
/// `outer_is_static = true` forces the child to STATICCALL regardless of the
/// caller's `input.is_static` field (outer STATIC propagates inward).
pub fn run<DB>(
    ctx: &mut EthEvmContext<DB>,
    self_address: Address,
    outer_is_static: bool,
    spec: SpecId,
    runtime_body_readers: Option<RuntimeBodyReaders>,
    execution_scope: Arc<ExecutionScope>,
    input: SubCallInput,
) -> std::result::Result<SubCallOutput, SubCallError>
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    run_with_ocomp_context(
        ctx,
        self_address,
        outer_is_static,
        spec,
        B256::ZERO,
        runtime_body_readers,
        execution_scope,
        None,
        Arc::new(crate::precompiles::OcompActivationBlockMeter),
        false,
        input,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_ocomp_context<DB>(
    ctx: &mut EthEvmContext<DB>,
    self_address: Address,
    outer_is_static: bool,
    spec: SpecId,
    genesis_hash: B256,
    runtime_body_readers: Option<RuntimeBodyReaders>,
    execution_scope: Arc<ExecutionScope>,
    ocomp_finality_authority: Option<Arc<dyn OcompFinalizedIntentAuthority>>,
    ocomp_activation_block_meter: Arc<crate::precompiles::OcompActivationBlockMeter>,
    ocomp_lifecycle_active: bool,
    input: SubCallInput,
) -> std::result::Result<SubCallOutput, SubCallError>
where
    DB: Database + Debug,
    DB::Error: Debug,
{
    let effective_is_static = outer_is_static || input.is_static;

    // Static context + non-zero value -> reject early.
    if effective_is_static && !input.value.is_zero() {
        return Err(SubCallError::StateChangeDuringStaticCall);
    }

    // Depth check via journal.
    if ctx.journal().depth() >= 1024 {
        return Err(SubCallError::DepthLimitExceeded);
    }

    // Pre-load bytecode (mirror revm-handler-18.1.0/src/execution.rs:22-37).
    // Handles EIP-7702 delegation by re-loading from the delegate's address.
    let (bytecode_hash, bytecode) = load_target_bytecode(ctx, input.target)?;

    // Build CallInputs.
    let call_inputs = CallInputs {
        input: CallInput::Bytes(input.calldata.clone()),
        return_memory_offset: 0..0,
        gas_limit: input.gas_limit,
        reservoir: 0,
        bytecode_address: input.target,
        known_bytecode: (bytecode_hash, bytecode),
        target_address: input.target,
        caller: self_address,
        value: if effective_is_static {
            CallValue::Transfer(U256::ZERO)
        } else {
            CallValue::Transfer(input.value)
        },
        scheme: if effective_is_static {
            CallScheme::StaticCall
        } else {
            CallScheme::Call
        },
        is_static: effective_is_static,
    };

    // Construct fresh borrow-mode Evm wrapping &mut ctx.
    // CTX = &mut EthEvmContext<DB> impls ContextTr via #[auto_impl(&mut, Box)]
    // on the trait.
    let mut instructions =
        EthInstructions::<EthInterpreter, &mut EthEvmContext<DB>>::new_mainnet_with_spec(spec);
    crate::create_guard::install(&mut instructions);
    let precompiles = crate::precompiles::OutbeSubCallPrecompiles::<DB>::new(
        crate::precompiles::OutbePrecompileExecutionContext::new(spec, genesis_hash),
        crate::precompiles::OutbePrecompileRuntime::new(
            runtime_body_readers,
            execution_scope,
            ocomp_finality_authority,
            ocomp_lifecycle_active,
        ),
        ocomp_activation_block_meter,
    );
    #[allow(clippy::type_complexity)]
    let mut evm: Evm<
        &mut EthEvmContext<DB>,
        (),
        EthInstructions<EthInterpreter, &mut EthEvmContext<DB>>,
        crate::precompiles::OutbeSubCallPrecompiles<DB>,
        EthFrame<EthInterpreter>,
    > = Evm::new(ctx, instructions, precompiles);

    let frame_input = FrameInit {
        depth: 0,
        memory: SharedMemory::new(),
        frame_input: FrameInput::Call(Box::new(call_inputs)),
    };

    // Canonical handler frame loop
    // (revm-handler-18.1.0/src/handler.rs:416-446).
    let frame_result = run_exec_loop(&mut evm, frame_input)?;

    // Translate FrameResult -> SubCallOutput.
    let call_outcome = match frame_result {
        FrameResult::Call(outcome) => outcome,
        FrameResult::Create(_) => {
            return Err(SubCallError::Fatal(
                "sub-call returned CREATE outcome (impossible for Call frame_input)".to_string(),
            ));
        }
    };
    Ok(call_outcome_to_subcall_output(
        call_outcome,
        input.gas_limit,
    ))
}

/// Pre-load target bytecode + hash. Mirrors revm-handler's
/// `create_init_frame` logic for EIP-7702 delegation.
fn load_target_bytecode<DB>(
    ctx: &mut EthEvmContext<DB>,
    target: Address,
) -> std::result::Result<(B256, Bytecode), SubCallError>
where
    DB: Database,
    DB::Error: Debug,
{
    // First pass: read info from target (info + delegate decision).
    let (delegate, hash, code) = {
        let journal = ctx.journal_mut();
        let account = journal
            .load_account_with_code_mut(target)
            .map_err(|e| SubCallError::DatabaseError(format!("{e:?}")))?;
        let info = &account.data.account().info;
        let delegate = info.code.as_ref().and_then(Bytecode::eip7702_address);
        (
            delegate,
            info.code_hash,
            info.code.clone().unwrap_or_default(),
        )
    };

    // EIP-7702 delegate handling: re-load from the delegate address.
    if let Some(delegate_addr) = delegate {
        let journal = ctx.journal_mut();
        let account = journal
            .load_account_with_code_mut(delegate_addr)
            .map_err(|e| SubCallError::DatabaseError(format!("{e:?}")))?;
        let info = &account.data.account().info;
        return Ok((info.code_hash, info.code.clone().unwrap_or_default()));
    }

    Ok((hash, code))
}

/// Mirrors revm-handler-18.1.0's [`run_exec_loop`].
///
/// Runs the frame stack inside `evm` to completion for `first_frame_input`,
/// returning the top-level [`FrameResult`].
fn run_exec_loop<E>(
    evm: &mut E,
    first_frame_input: FrameInit,
) -> std::result::Result<FrameResult, SubCallError>
where
    E: EvmTr<Frame = EthFrame<EthInterpreter>>,
    <E as EvmTr>::Context: ContextTr,
{
    let res = evm
        .frame_init(first_frame_input)
        .map_err(|e| SubCallError::Fatal(format!("frame_init: {e:?}")))?;
    if let ItemOrResult::Result(frame_result) = res {
        return Ok(frame_result);
    }

    loop {
        let call_or_result = evm
            .frame_run()
            .map_err(|e| SubCallError::Fatal(format!("frame_run: {e:?}")))?;
        let result = match call_or_result {
            ItemOrResult::Item(init) => match evm
                .frame_init(init)
                .map_err(|e| SubCallError::Fatal(format!("frame_init nested: {e:?}")))?
            {
                ItemOrResult::Item(_) => continue,
                ItemOrResult::Result(r) => r,
            },
            ItemOrResult::Result(r) => r,
        };
        if let Some(r) = evm
            .frame_return_result(result)
            .map_err(|e| SubCallError::Fatal(format!("frame_return_result: {e:?}")))?
        {
            return Ok(r);
        }
    }
}

/// Convert revm's [`CallOutcome`] (terminal frame state) into outbe's
/// [`SubCallOutput`].
fn call_outcome_to_subcall_output(outcome: CallOutcome, original_gas_limit: u64) -> SubCallOutput {
    let CallOutcome { result, .. } = outcome;
    let InterpreterResult {
        result: instr,
        output,
        gas,
    } = result;

    let gas_used = original_gas_limit.saturating_sub(gas.remaining());
    let gas_refunded = gas.refunded();

    let status = match instr {
        InstructionResult::Return | InstructionResult::Stop => SubCallStatus::Success,
        InstructionResult::Revert => SubCallStatus::Revert(output.clone()),
        InstructionResult::CallTooDeep => SubCallStatus::Halt(SubCallError::DepthLimitExceeded),
        InstructionResult::OutOfGas
        | InstructionResult::MemoryOOG
        | InstructionResult::MemoryLimitOOG
        | InstructionResult::PrecompileOOG
        | InstructionResult::InvalidOperandOOG
        | InstructionResult::ReentrancySentryOOG => SubCallStatus::Halt(SubCallError::OutOfGas),
        InstructionResult::CallNotAllowedInsideStatic
        | InstructionResult::StateChangeDuringStaticCall => {
            SubCallStatus::Halt(SubCallError::StateChangeDuringStaticCall)
        }
        // Anything else: surface as a typed Fatal so the precompile can
        // decide whether to revert.
        other => SubCallStatus::Halt(SubCallError::Fatal(format!(
            "child frame halted: {other:?}"
        ))),
    };

    SubCallOutput {
        status,
        returndata: output,
        gas_used,
        gas_refunded,
    }
}
