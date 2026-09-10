use alloy_primitives::{Address, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::STABLECOIN_POLICY_REGISTRY_ADDRESS;
use outbe_primitives::storage::types::{StorageKey, StorageSet};

use crate::errors::PolicyRegistryError;

pub const DENY_ALL_POLICY_ID: U256 = U256::ZERO;
pub const ALLOW_ALL_POLICY_ID: U256 = U256::from_limbs([1, 0, 0, 0]);
pub(crate) const FIRST_MUTABLE_POLICY_ID: U256 = U256::from_limbs([2, 0, 0, 0]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyType {
    DenyAll = 0,
    AllowAll = 1,
    Whitelist = 2,
    Blacklist = 3,
    Directional = 4,
}

impl PolicyType {
    pub const fn is_simple(self) -> bool {
        matches!(self, Self::Whitelist | Self::Blacklist)
    }
}

impl TryFrom<u8> for PolicyType {
    type Error = PolicyRegistryError;

    fn try_from(policy_type: u8) -> Result<Self, Self::Error> {
        match policy_type {
            0 => Ok(Self::DenyAll),
            1 => Ok(Self::AllowAll),
            2 => Ok(Self::Whitelist),
            3 => Ok(Self::Blacklist),
            4 => Ok(Self::Directional),
            _ => Err(PolicyRegistryError::InvalidPolicyType { policy_type }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyLane {
    Send,
    Receive,
    Mint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[storage_record(exists_field = exists)]
pub struct PolicyDescriptor {
    #[key]
    pub policy_id: U256,

    #[attribute(order = 0)]
    pub exists: bool,

    #[attribute(order = 1)]
    pub policy_type: u8,

    #[attribute(order = 2)]
    pub admin: Address,

    #[attribute(order = 3)]
    pub pending_admin: Address,

    #[attribute(order = 4)]
    pub send_policy_id: U256,

    #[attribute(order = 5)]
    pub receive_policy_id: U256,

    #[attribute(order = 6)]
    pub mint_policy_id: U256,
}

impl PolicyDescriptor {
    pub(crate) fn builtin(policy_id: U256, policy_type: PolicyType) -> Self {
        Self {
            policy_id,
            exists: true,
            policy_type: policy_type as u8,
            admin: Address::ZERO,
            pending_admin: Address::ZERO,
            send_policy_id: U256::ZERO,
            receive_policy_id: U256::ZERO,
            mint_policy_id: U256::ZERO,
        }
    }
}

/// Stable V1 layout:
///
/// - slot 0: next policy id (`0` means pristine and therefore next id `2`);
/// - slots 1..=7: descriptor mapping bases;
/// - slot 8: per-policy enumerable member-set mapping base.
#[storage_schema]
#[contract(addr = STABLECOIN_POLICY_REGISTRY_ADDRESS)]
pub struct StablecoinPolicyRegistryContract {
    #[attribute(order = 0)]
    pub next_policy_id: outbe_primitives::storage::dsl::Value<U256>,

    #[attribute(order = 1)]
    pub policies: outbe_primitives::storage::dsl::Map<U256, PolicyDescriptor>,

    /// The mapped value is unused directly. Its per-key mapping slot is the
    /// base of an enumerable `StorageSet<Address>`.
    #[attribute(order = 2)]
    pub member_sets: outbe_primitives::storage::dsl::Map<U256, U256>,
}

impl<'storage> StablecoinPolicyRegistryContract<'storage> {
    pub(crate) fn member_set(&self, policy_id: U256) -> StorageSet<'storage, Address> {
        let base = policy_id.mapping_slot(self.member_sets.base_slot());
        StorageSet::new(base, self.address, self.storage.clone())
    }
}
