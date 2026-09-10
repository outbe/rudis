use alloy_primitives::U256;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::errors::GemError;
use crate::schema::{GemAddParams, GemContract, GemData, GemState};

pub fn add_gem(storage: &StorageHandle<'_>, params: GemAddParams) -> Result<U256> {
    if params.owner.is_zero() {
        return Err(GemError::InvalidOwner.into());
    }

    let mut gem = GemContract::new(storage.clone());
    let params_profile = crate::config::read_from(&gem, storage.chain_id()?)?;
    let gem_id = GemContract::generate_gem_id(
        params.owner,
        params.promis_load_minor,
        storage.block_number()?,
    );

    // A gem born past Issued reached those states at issuance, so backfill the
    // lifecycle timestamps from `issued_at` (the scan stamps them otherwise).
    let (qualified_at, settled_at) = match params.initial_state {
        GemState::Issued => (0u64, 0u64),
        GemState::Qualified | GemState::Called => (params.issued_at, 0),
        GemState::Settled => (params.issued_at, params.issued_at),
    };

    let item = GemData {
        gem_id,
        owner: params.owner,
        gem_type: params.gem_type,
        promis_load_minor: params.promis_load_minor,
        entry_price_minor: params.entry_price_minor,
        floor_price_minor: params.floor_price_minor,
        call_price_minor: params.call_price_minor,
        call_rate: params.call_rate,
        call_window: params_profile.call_window,
        call_threshold: params_profile.call_threshold,
        issuance_currency: params.issuance_currency,
        reference_currency: params.reference_currency,
        state: params.initial_state as u8,
        issued_at: params.issued_at,
        called_at: 0,
        call_notice_period: params_profile.call_notice_period,
        qualified_at,
        settled_at,
    };
    gem.add_gem(&item)?;
    Ok(gem_id)
}

/// Burn a settled gem (promis mining). Forfeit burns of Called gems go through
/// the internal `GemContract::burn` from the daily scan, not this entry point.
pub fn burn(storage: &StorageHandle<'_>, gem_id: U256) -> Result<()> {
    let mut gem = GemContract::new(storage.clone());
    let item = gem.gem_items.get(gem_id)?.ok_or(GemError::GemNotFound)?;
    if item.state != GemState::Settled as u8 {
        return Err(GemError::InvalidState.into());
    }
    gem.burn(&item)
}

pub fn set_state(storage: &StorageHandle<'_>, gem_id: U256, new_state: GemState) -> Result<()> {
    let mut gem = GemContract::new(storage.clone());
    gem.set_state(gem_id, new_state)
}

pub fn get_gem(storage: &StorageHandle<'_>, gem_id: U256) -> Result<Option<GemData>> {
    let gem = GemContract::new(storage.clone());
    gem.get_gem(gem_id)
}
