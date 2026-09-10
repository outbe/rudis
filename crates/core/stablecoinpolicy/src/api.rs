//! Narrow read-only surface used by stablecoin ledgers.

use alloy_primitives::{Address, U256};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::schema::{PolicyLane, StablecoinPolicyRegistryContract};

pub fn policy_exists(storage: StorageHandle<'_>, policy_id: U256) -> Result<bool> {
    StablecoinPolicyRegistryContract::new(storage).policy_exists(policy_id)
}

pub fn can_send(storage: StorageHandle<'_>, policy_id: U256, account: Address) -> Result<bool> {
    StablecoinPolicyRegistryContract::new(storage).can(policy_id, account, PolicyLane::Send)
}

pub fn can_receive(storage: StorageHandle<'_>, policy_id: U256, account: Address) -> Result<bool> {
    StablecoinPolicyRegistryContract::new(storage).can(policy_id, account, PolicyLane::Receive)
}

pub fn can_mint(storage: StorageHandle<'_>, policy_id: U256, account: Address) -> Result<bool> {
    StablecoinPolicyRegistryContract::new(storage).can(policy_id, account, PolicyLane::Mint)
}
