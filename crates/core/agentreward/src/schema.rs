use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::AGENT_REWARD_ADDRESS;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::types::StorageKey;
use outbe_primitives::time::WorldwideDay;

/// EVM storage layout for the Agent Reward contract.
///
/// Tracks tribute counts per address/reward UTC day, claimable reward balances
/// per address and pool, and per-day address lists for the WAA (wallet) and SRA
/// (signer-of-record) participant pools. A reward day is the calendar day when
/// an offer executes, not the Tribute's target WorldwideDay.
///
/// Naming history: `wallet_*` was renamed to `waa_*` and `sfa_*` to
/// `sra_*` as part (Phase 2 of the Cycle epic) so the on-chain
/// identifiers match the README and external documentation.
#[storage_schema]
#[contract(addr = AGENT_REWARD_ADDRESS)]
pub struct AgentRewardContract {
    // slot 0: WAA tribute count per day+address (key: B256 = keccak(day, addr))
    #[attribute(order = 0)]
    pub waa_tribute_counts: outbe_primitives::storage::dsl::Map<B256, u64>,

    // slot 1: SRA tribute count per day+address (key: B256 = keccak(day, addr))
    #[attribute(order = 1)]
    pub sra_tribute_counts: outbe_primitives::storage::dsl::Map<B256, u64>,

    // slot 2: claimable WAA reward per address
    #[attribute(order = 2)]
    pub waa_claimable_rewards: outbe_primitives::storage::dsl::Map<Address, U256>,

    // slot 3: WAA address count per day
    #[attribute(order = 3)]
    pub waa_address_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // slot 4: WAA address list - key = keccak(day, index), value = address
    #[attribute(order = 4)]
    pub waa_addresses: outbe_primitives::storage::dsl::Map<B256, Address>,

    // slot 5: SRA address count per day
    #[attribute(order = 5)]
    pub sra_address_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // slot 6: SRA address list - key = keccak(day, index), value = address
    #[attribute(order = 6)]
    pub sra_addresses: outbe_primitives::storage::dsl::Map<B256, Address>,

    // slot 7: claimable SRA reward per address
    #[attribute(order = 7)]
    pub sra_claimable_rewards: outbe_primitives::storage::dsl::Map<Address, U256>,
}

/// Pool a claimable balance belongs to. The pool decides the Gem class a
/// claim issues, so WAA and SRA balances are kept apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RewardPool {
    Waa = 0,
    Sra = 1,
}

impl RewardPool {
    pub fn from_abi(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Waa),
            1 => Ok(Self::Sra),
            _ => Err(PrecompileError::Revert(format!(
                "agentreward unknown reward pool {value}"
            ))),
        }
    }
}

impl AgentRewardContract<'_> {
    /// Computes the composite key for per-address per-day tribute counts.
    pub fn tribute_count_key(day: WorldwideDay, address: Address) -> B256 {
        use alloy_primitives::keccak256;
        let mut buf = [0u8; 24]; // 4 + 20
        buf[0..4].copy_from_slice(day.key_bytes().as_slice());
        buf[4..24].copy_from_slice(address.as_slice());
        keccak256(buf)
    }

    /// Computes the composite key for per-day address index lists.
    pub fn address_index_key(day: WorldwideDay, index: u32) -> B256 {
        use alloy_primitives::keccak256;
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(day.key_bytes().as_slice());
        buf[4..8].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }
}
