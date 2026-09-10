//! Cross-module NodFactory API.

use alloy_primitives::{Address, U256};
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, WwdEntityId};
use outbe_nod::schema::NodIssueParams;
use outbe_ocomp_protocol::{nod_materialization::NodMaterializationBatchV1, SchemaLimits};
use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::runtime;

pub use crate::runtime::MineGratisRequest;

pub use crate::certified::{install_certified_generation, CertifiedNodGenerationV1};
pub use crate::materialization::NodMaterializationOutcomeV1;

pub fn issue_nod(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    params: &NodIssueParams,
) -> Result<WwdEntityId> {
    runtime::issue_nod(storage, scope, parent, params)
}

pub fn mine_gratis(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    request: MineGratisRequest<'_>,
) -> Result<U256> {
    runtime::mine_gratis(storage, scope, parent, request)
}

/// Authorizes and atomically applies one canonical certified-NOD batch.
pub fn materialize_certified_nods(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    caller: Address,
    batch: &NodMaterializationBatchV1,
    limits: &SchemaLimits,
) -> Result<NodMaterializationOutcomeV1> {
    crate::materialization::authorize_materializer(storage.clone(), caller)?;
    let profile = outbe_chain_constants::NodMaterializationProfileV1 {
        batch_subtree_height: outbe_chain_constants::get_nod_materialization_batch_subtree_height(),
        retry_interval_blocks: outbe_chain_constants::get_nod_materialization_retry_interval_blocks(
        ),
        max_attempts_per_block:
            outbe_chain_constants::get_nod_materialization_max_attempts_per_block(),
    };
    crate::materialization::materialize_certified_nods_authorized(
        storage, scope, parent, batch, profile, limits,
    )
}
