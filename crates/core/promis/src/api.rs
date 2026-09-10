//! Cross-module API for the confidential Promis token.

use alloy_primitives::{Address, U256};

use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

pub use outbe_tee::protocol::ModifyAuth;

use crate::runtime;
use crate::schema::Promis;

// --- Reads ---

/// Encrypted balance blob for `account`; decrypt client-side with the view key.
pub fn balance_ct(storage: StorageHandle<'_>, account: Address) -> Result<Vec<u8>> {
    Promis::new(storage).balance_ct_of(account)
}

/// The account's current modify-auth replay counter (the value the client's next
/// write authorization must bind).
pub fn op_nonce(storage: StorageHandle<'_>, account: Address) -> Result<u64> {
    Promis::new(storage).op_nonce_of(account)
}

/// Public total circulating supply (aggregate; per-account balances hidden).
pub fn total_supply(storage: StorageHandle<'_>) -> Result<U256> {
    Promis::new(storage).total_supply()
}

// --- Owner-authorized mutations ---

/// Mint `amount` promis to `caller`.
pub fn mint(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<()> {
    runtime::mint(storage, caller, amount, auth)
}

/// Burn `amount` promis from `caller`. Returns the remaining total supply.
pub fn burn(
    storage: StorageHandle<'_>,
    caller: Address,
    amount: U256,
    auth: ModifyAuth,
) -> Result<U256> {
    runtime::burn(storage, caller, amount, auth)
}
