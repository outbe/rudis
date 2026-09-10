use outbe_primitives::{
    block::{BlockContext, BlockLifecycle, BlockRuntimeContext},
    error::Result,
    storage::StorageHandle,
};

use crate::{
    api::{EntityRef, ExecutionScope, FinalLeafMutation},
    schema::Collection,
    state::State,
    ProvisionalTreeBatch,
};

/// Zero-sized storage-lifecycle marker used by the explicit executor ordering.
pub struct CompressedEntitiesLifecycle;

/// Typed provisional tree result retained by the executor until the final
/// block hash is known. No persistent tree state has been changed yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealOutput {
    pub parent_root: alloy_primitives::B256,
    pub new_root: alloy_primitives::B256,
    pub staged_tree_batch: ProvisionalTreeBatch,
}

/// Explicit authorities consumed by the compressed-entity block boundary.
pub struct CompressedEntitiesLifecycleContext<'a, 'storage> {
    pub runtime: BlockRuntimeContext<'storage>,
    pub scope: &'a ExecutionScope,
}

impl<'a, 'storage> CompressedEntitiesLifecycleContext<'a, 'storage> {
    #[must_use]
    pub fn new(runtime: BlockRuntimeContext<'storage>, scope: &'a ExecutionScope) -> Self {
        Self { runtime, scope }
    }
}

impl BlockLifecycle for CompressedEntitiesLifecycle {
    type Context<'a, 'storage> = CompressedEntitiesLifecycleContext<'a, 'storage>;
    type EndBlockResult = SealOutput;

    fn begin_block(ctx: &Self::Context<'_, '_>) -> Result<()> {
        begin_storage(ctx.runtime.storage.clone())?;
        let evm_root = State::new(ctx.runtime.storage.clone()).root()?;
        ctx.scope.open_exact_parent(evm_root)?;
        if ctx.scope.parent_root()? != evm_root {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "exact parent tree root does not match compressed-entity EVM root".into(),
            ));
        }
        ctx.scope.activate()
    }

    fn end_block(ctx: &Self::Context<'_, '_>) -> Result<Self::EndBlockResult> {
        let output = prepare_seal_output(ctx)?;
        let state = State::new(ctx.runtime.storage.clone());
        ctx.runtime.storage.clone().with_checkpoint(|| {
            state.write_root(output.new_root)?;
            state.cleanup()
        })?;
        // Close every precompile capability only after the complete root and
        // overlay cleanup change set succeeds.
        ctx.scope.finish_with_seal(&output)?;
        Ok(output)
    }
}

/// Prepares the exact CE seal visible to terminal system phases without
/// writing the root, cleaning the overlay, or closing the execution scope.
pub fn preview_end_block(ctx: &CompressedEntitiesLifecycleContext<'_, '_>) -> Result<SealOutput> {
    let output = prepare_seal_output(ctx)?;
    ctx.scope.record_provisional_seal(&output)?;
    Ok(output)
}

fn prepare_seal_output(ctx: &CompressedEntitiesLifecycleContext<'_, '_>) -> Result<SealOutput> {
    ctx.scope.require_active()?;
    let state = State::new(ctx.runtime.storage.clone());
    let mutations = state
        .final_body_mutations()?
        .into_iter()
        .map(|(collection, entity_id, final_leaf)| FinalLeafMutation {
            entity: match collection {
                Collection::Tribute => EntityRef::Tribute(entity_id),
                Collection::NodItem => EntityRef::NodItem(entity_id),
                Collection::NodBucket => EntityRef::NodBucket(entity_id),
            },
            final_leaf,
        })
        .collect::<Vec<_>>();
    let retirements = state.retirements()?;
    let parent_root = state.root()?;
    let staged_tree_batch =
        ctx.scope
            .prepare_tree_seal(ctx.runtime.block.block_number, &mutations, &retirements)?;
    if staged_tree_batch.parent_root() != parent_root {
        return Err(outbe_primitives::error::PrecompileError::Fatal(
            "prepared compressed-entity tree batch has the wrong parent root".into(),
        ));
    }
    let new_root = staged_tree_batch.new_root();
    Ok(SealOutput {
        parent_root,
        new_root,
        staged_tree_batch,
    })
}

pub(crate) fn begin_block(storage: StorageHandle<'_>, scope: &ExecutionScope) -> Result<()> {
    let block = BlockContext::empty_for_tests(storage.block_number()?, 0, storage.chain_id()?);
    let runtime = BlockRuntimeContext::new(block, storage);
    let lifecycle = CompressedEntitiesLifecycleContext::new(runtime, scope);
    <CompressedEntitiesLifecycle as BlockLifecycle>::begin_block(&lifecycle)
}

pub(crate) fn end_block(storage: StorageHandle<'_>, scope: &ExecutionScope) -> Result<SealOutput> {
    let block = BlockContext::empty_for_tests(storage.block_number()?, 0, storage.chain_id()?);
    let runtime = BlockRuntimeContext::new(block, storage);
    let lifecycle = CompressedEntitiesLifecycleContext::new(runtime, scope);
    <CompressedEntitiesLifecycle as BlockLifecycle>::end_block(&lifecycle)
}

pub(crate) fn preview_end_block_for_storage(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
) -> Result<SealOutput> {
    let block = BlockContext::empty_for_tests(storage.block_number()?, 0, storage.chain_id()?);
    let runtime = BlockRuntimeContext::new(block, storage);
    let lifecycle = CompressedEntitiesLifecycleContext::new(runtime, scope);
    preview_end_block(&lifecycle)
}

fn begin_storage(storage: StorageHandle<'_>) -> Result<()> {
    State::new(storage).assert_clean_begin()
}
