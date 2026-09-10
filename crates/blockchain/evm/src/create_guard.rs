//! Genesis-active reservation of the Stablecoin dynamic address class.
//!
//! The guard deliberately reuses revm's normal `CreateCollision` path.  Once a
//! reserved destination has been derived and warmed, the create input is
//! redirected to the already-existing caller account.  revm then performs its
//! normal nonce bump, collision result, gas accounting and journal handling.

use outbe_primitives::addresses::is_stablecoin_address;
use revm::{
    context::{Cfg, ContextTr, Database, JournalTr, LocalContextTr},
    context_interface::journaled_state::account::JournaledAccountTr,
    handler::{execution, instructions::EthInstructions, EthFrame, EvmTr, EvmTrError, Handler},
    inspector::{Inspector, InspectorEvmTr, InspectorHandler},
    interpreter::{
        instructions::contract::create,
        interpreter::EthInterpreter,
        interpreter_action::{FrameInit, FrameInput},
        interpreter_types::LoopControl,
        CreateScheme, Host, Instruction, InstructionContext, InterpreterAction, InterpreterTypes,
        SharedMemory,
    },
    state::EvmState,
};
use std::marker::PhantomData;

const CREATE_OPCODE: u8 = 0xf0;
const CREATE2_OPCODE: u8 = 0xf5;

/// Mainnet handler with one additional rule for a top-level create transaction.
pub(crate) struct ReservedNamespaceHandler<EVM, ERROR>(PhantomData<(EVM, ERROR)>);

impl<EVM, ERROR> Default for ReservedNamespaceHandler<EVM, ERROR> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<EVM, ERROR> Handler for ReservedNamespaceHandler<EVM, ERROR>
where
    EVM: EvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
    >,
    ERROR: EvmTrError<EVM>,
{
    type Evm = EVM;
    type Error = ERROR;
    type HaltReason = revm::context_interface::result::HaltReason;

    fn first_frame_input(
        &mut self,
        evm: &mut Self::Evm,
        gas_limit: u64,
        reservoir: u64,
    ) -> Result<FrameInit, Self::Error> {
        let ctx = evm.ctx_mut();
        let mut memory = SharedMemory::new_with_buffer(ctx.local().shared_memory_buffer().clone());
        memory.set_memory_limit(ctx.cfg().memory_limit());

        let mut frame_input = execution::create_init_frame(ctx, gas_limit, reservoir)?;
        guard_top_level_create(ctx, &mut frame_input)?;

        Ok(FrameInit {
            depth: 0,
            memory,
            frame_input,
        })
    }
}

impl<EVM, ERROR> InspectorHandler for ReservedNamespaceHandler<EVM, ERROR>
where
    EVM: InspectorEvmTr<
        Context: ContextTr<Journal: JournalTr<State = EvmState>>,
        Frame = EthFrame<EthInterpreter>,
        Inspector: Inspector<<<Self as Handler>::Evm as EvmTr>::Context, EthInterpreter>,
    >,
    ERROR: EvmTrError<EVM>,
{
    type IT = EthInterpreter;
}

/// Installs the nested `CREATE` and `CREATE2` guards into an instruction table.
pub(crate) fn install<WIRE, HOST>(instructions: &mut EthInstructions<WIRE, HOST>)
where
    WIRE: InterpreterTypes,
    HOST: Host,
{
    let create_gas = instructions.instruction_table[CREATE_OPCODE as usize].static_gas();
    let create2_gas = instructions.instruction_table[CREATE2_OPCODE as usize].static_gas();
    instructions.insert_instruction(
        CREATE_OPCODE,
        Instruction::new(guarded_create::<WIRE, HOST, false>, create_gas),
    );
    instructions.insert_instruction(
        CREATE2_OPCODE,
        Instruction::new(guarded_create::<WIRE, HOST, true>, create2_gas),
    );
}

fn guard_top_level_create<CTX>(
    ctx: &mut CTX,
    frame_input: &mut FrameInput,
) -> Result<(), <<CTX::Journal as JournalTr>::Database as Database>::Error>
where
    CTX: ContextTr,
{
    let FrameInput::Create(inputs) = frame_input else {
        return Ok(());
    };

    let caller = inputs.caller();
    let nonce = ctx.journal_mut().load_account_mut(caller)?.nonce();
    let destination = inputs.created_address(nonce);
    if !is_stablecoin_address(destination) {
        return Ok(());
    }

    // Canonical CREATE collision handling warms the attempted destination before
    // deciding that creation failed. Preserve that observable access-list state.
    ctx.journal_mut().load_account(destination)?;
    inputs.set_scheme(CreateScheme::Custom { address: caller });
    Ok(())
}

fn guarded_create<WIRE, HOST, const IS_CREATE2: bool>(context: InstructionContext<'_, HOST, WIRE>)
where
    WIRE: InterpreterTypes,
    HOST: Host + ?Sized,
{
    create::<WIRE, IS_CREATE2, HOST>(InstructionContext {
        interpreter: &mut *context.interpreter,
        host: &mut *context.host,
    });

    let action = context.interpreter.take_next_action();
    let InterpreterAction::NewFrame(FrameInput::Create(mut inputs)) = action else {
        context.interpreter.bytecode.set_action(action);
        return;
    };

    let Some(caller_info) = context
        .host
        .load_account_info_skip_cold_load(inputs.caller(), false, false)
        .ok()
    else {
        context
            .interpreter
            .bytecode
            .set_action(InterpreterAction::NewFrame(FrameInput::Create(inputs)));
        return;
    };
    let destination = inputs.created_address(caller_info.account.nonce);
    if is_stablecoin_address(destination) {
        // As in revm's normal collision path, warm the real attempted address.
        // A database failure is retained by the host context and aborts execution.
        let _ = context
            .host
            .load_account_info_skip_cold_load(destination, false, false);
        inputs.set_scheme(CreateScheme::Custom {
            address: inputs.caller(),
        });
    }

    context
        .interpreter
        .bytecode
        .set_action(InterpreterAction::NewFrame(FrameInput::Create(inputs)));
}
