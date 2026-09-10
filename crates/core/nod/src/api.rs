//! Cross-module API for the Nod entity store.

use alloy_primitives::{Address, U256};
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, VerifiedBody, WwdEntityId};
use outbe_primitives::math::scaled_math::checked_mul_div_floor;
use outbe_primitives::units::SCALE_1E6_U256;
use outbe_primitives::{error::Result, storage::StorageHandle};

use crate::schema::{NodBucketState, NodContract, NodItemState};

/// The Nod's cost: `floor(entry_price_minor * gratis_load_minor / 1e6)`.
///
/// Derived rather than stored — the entry price lives on the Nod's bucket and
/// the load on the Nod itself, and lysis mints the Nod from exactly this
/// formula.
pub fn cost_amount_minor(entry_price_minor: U256, gratis_load_minor: U256) -> Result<U256> {
    checked_mul_div_floor(entry_price_minor, gratis_load_minor, SCALE_1E6_U256)
}

/// A decoded Nod item paired with the exact generic capability that verified it.
pub struct LoadedNodItem {
    body: NodItemState,
    current: VerifiedBody,
}

impl LoadedNodItem {
    #[must_use]
    pub const fn body(&self) -> &NodItemState {
        &self.body
    }

    #[must_use]
    pub(crate) fn into_parts(self) -> (NodItemState, VerifiedBody) {
        (self.body, self.current)
    }
}

/// A decoded Nod bucket paired with the exact generic capability that verified it.
pub struct LoadedNodBucket {
    body: NodBucketState,
    current: VerifiedBody,
}

impl LoadedNodBucket {
    #[must_use]
    pub const fn body(&self) -> &NodBucketState {
        &self.body
    }

    #[must_use]
    pub(crate) fn into_parts(self) -> (NodBucketState, VerifiedBody) {
        (self.body, self.current)
    }
}

/// Inserts a Nod item and creates or updates its bucket atomically.
pub fn add_nod(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    item: &NodItemState,
    entry_price_minor: U256,
) -> Result<()> {
    let mut nod = NodContract::new(storage.clone());
    storage
        .clone()
        .with_checkpoint(|| nod.record_nod_issued(scope, parent, item, entry_price_minor))
}

/// Removes a previously loaded Nod item and updates or deletes its loaded bucket atomically.
pub fn remove_nod(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    item: LoadedNodItem,
    bucket: LoadedNodBucket,
) -> Result<()> {
    let mut nod = NodContract::new(storage.clone());
    storage
        .clone()
        .with_checkpoint(|| nod.record_nod_removed(scope, item, bucket))
}

/// Loads a Nod item while retaining its verified generic mutation capability.
pub fn load_item(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    nod_id: WwdEntityId,
) -> Result<Option<LoadedNodItem>> {
    let nod = NodContract::new(storage.clone());
    nod.get_item_verified(scope, parent, nod_id)?
        .map(|current| {
            crate::state::nod_item_from_verified(&current)
                .map(|body| LoadedNodItem { body, current })
        })
        .transpose()
}

/// Loads a Nod bucket while retaining its verified generic mutation capability.
pub fn load_bucket(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    bucket_id: WwdEntityId,
) -> Result<Option<LoadedNodBucket>> {
    let nod = NodContract::new(storage.clone());
    nod.get_bucket_verified(scope, parent, bucket_id)?
        .map(|current| {
            crate::state::nod_bucket_from_verified(&current)
                .map(|body| LoadedNodBucket { body, current })
        })
        .transpose()
}

/// Fetches a Nod item state by ID.
pub fn get_item(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    nod_id: WwdEntityId,
) -> Result<Option<NodItemState>> {
    load_item(storage, scope, parent, nod_id)
        .map(|loaded| loaded.map(|loaded| loaded.into_parts().0))
}

/// Fetches a Nod bucket state by ID.
pub fn get_bucket(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    bucket_id: WwdEntityId,
) -> Result<Option<NodBucketState>> {
    load_bucket(storage, scope, parent, bucket_id)
        .map(|loaded| loaded.map(|loaded| loaded.into_parts().0))
}

/// Loads the complete Nod collection with overlay-correct membership.
pub fn list_all(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
) -> Result<Vec<NodItemState>> {
    NodContract::new(storage.clone()).read_all(scope, parent, None)
}

/// Loads one owner's Nod collection with overlay-correct membership.
pub fn list_by_owner(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    owner: Address,
) -> Result<Vec<NodItemState>> {
    NodContract::new(storage.clone()).read_all(scope, parent, Some(owner))
}
