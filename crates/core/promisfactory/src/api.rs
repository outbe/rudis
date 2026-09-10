//! Cross-module API for the Promisfactory module.

use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

pub use outbe_promis::api::ModifyAuth;

/// Mint `amount` promis to `account`, authorized by the account owner's Promis
/// modify key.
pub fn mint(
    storage: StorageHandle<'_>,
    account: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<()> {
    crate::runtime::mint(storage, account, amount, auth)
}
