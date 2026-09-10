use alloy_primitives::{Address, U256};
use outbe_intex::SeriesId;
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::runtime;
use crate::schema::GemTypes;

pub fn issue_gem(
    storage: &StorageHandle<'_>,
    owner: Address,
    gem_type: GemTypes,
    promis_load: U256,
    issuance_currency: u16,
    reference_currency: u16,
    entry_price: U256,
) -> Result<U256> {
    runtime::issue_gem(
        storage,
        owner,
        gem_type,
        promis_load,
        issuance_currency,
        reference_currency,
        entry_price,
    )
}

pub fn issue_gem_position(
    storage: &StorageHandle<'_>,
    caller: Address,
    source_intex_id: SeriesId,
    amount: U256,
) -> Result<U256> {
    runtime::issue_gem_position(storage, caller, source_intex_id, amount)
}

pub fn issue_merchant_gem(
    storage: &StorageHandle<'_>,
    caller: Address,
    position_id: U256,
    owner: Address,
    promis_load: U256,
) -> Result<U256> {
    runtime::issue_merchant_gem(storage, caller, position_id, owner, promis_load)
}

pub fn settle_gem(
    storage: &StorageHandle<'_>,
    caller: Address,
    gem_id: U256,
    paynote_proof: &[u8],
) -> Result<()> {
    runtime::settle_gem(storage, caller, gem_id, paynote_proof)
}

pub fn mine_promis(
    storage: &StorageHandle<'_>,
    caller: Address,
    gem_id: U256,
    nonce: u64,
    auth: outbe_promisfactory::api::ModifyAuth,
) -> Result<U256> {
    runtime::mine_promis(storage, caller, gem_id, nonce, auth)
}
