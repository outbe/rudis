use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
use outbe_primitives::storage::types::{StorageKey, StorageSet};

/// `StablesSource`/`StablesTarget` enum sentinel for "not set". Matches
/// `IVaultRouter.StablesSource.Unknown == 0` and
/// `IVaultRouter.StablesTarget.Unknown == 0`.
pub const UNKNOWN: u8 = 0;

/// EVM storage layout for the vaultrouter precompile.
#[storage_schema]
#[contract(addr = VAULT_ROUTER_ADDRESS)]
pub struct VaultRouterContract {
    /// slot 0: owner (admin). Seeded at genesis; gates the `add*`/`remove*`
    /// management methods. Replaces `OwnableUpgradeable`.
    #[attribute(order = 0)]
    pub owner: outbe_primitives::storage::dsl::Value<Address>,

    /// slots 1-2: set of assets that have at least one registered vault.
    #[attribute(order = 1)]
    pub assets: outbe_primitives::storage::dsl::Set<Address>,

    /// slot 3: base slot of the per-asset vault sets. The value mapping is
    /// unused directly; `asset_vault_set(asset)` derives an enumerable
    /// `Set<Address>` at this mapping's per-key slot.
    #[attribute(order = 2)]
    pub asset_vaults: outbe_primitives::storage::dsl::Map<Address, U256>,

    /// slots 4-5: set of authorized liquidity-source accounts.
    #[attribute(order = 3)]
    pub liquidity_sources: outbe_primitives::storage::dsl::Set<Address>,

    /// slot 6: `account -> StablesSource` (stored as `u8`).
    #[attribute(order = 4)]
    pub liquidity_source_types: outbe_primitives::storage::dsl::Map<Address, u8>,

    /// slots 7-8: set of authorized liquidity-target accounts.
    #[attribute(order = 5)]
    pub liquidity_targets: outbe_primitives::storage::dsl::Set<Address>,

    /// slot 9: `account -> StablesTarget` (stored as `u8`).
    #[attribute(order = 6)]
    pub liquidity_target_types: outbe_primitives::storage::dsl::Map<Address, u8>,

    /// slot 10: Outbe ERC-7786 bridge used for remote management commands.
    #[attribute(order = 7)]
    pub crosschain_bridge: outbe_primitives::storage::dsl::Value<Address>,

    /// slot 11: `chainId -> remote VaultRouter` executor.
    #[attribute(order = 8)]
    pub remote_vault_routers: outbe_primitives::storage::dsl::Map<U256, Address>,

    /// slot 12: monotonic nonce used to derive cross-chain operation ids.
    /// Kept at its existing slot for upgrade compatibility.
    #[attribute(order = 9)]
    pub crosschain_operation_nonce: outbe_primitives::storage::dsl::Value<U256>,

    /// slot 13: reserved legacy pause flag. Kept to preserve storage layout;
    /// no VaultRouter function reads or writes it.
    #[attribute(order = 10)]
    pub reserved_legacy_pause: outbe_primitives::storage::dsl::Value<bool>,

    /// slot 14: Outbe WCOEN used by the cross-chain vault flow.
    #[attribute(order = 11)]
    pub crosschain_asset: outbe_primitives::storage::dsl::Value<Address>,

    /// slot 15: local WCOEN ERC-7786 token bridge.
    #[attribute(order = 12)]
    pub crosschain_token_bridge: outbe_primitives::storage::dsl::Value<Address>,

    /// slot 16: fixed destination chain hosting the BNB vault adapter.
    #[attribute(order = 13)]
    pub crosschain_destination_chain_id: outbe_primitives::storage::dsl::Value<U256>,

    /// slot 17: finalized 1:1 remote vault receipt shares per Outbe user.
    #[attribute(order = 14)]
    pub crosschain_shares: outbe_primitives::storage::dsl::Map<Address, U256>,

    /// slot 18: aggregate finalized Outbe receipt shares.
    #[attribute(order = 15)]
    pub total_crosschain_shares: outbe_primitives::storage::dsl::Value<U256>,

    /// slots 19-22: flat operation records keyed by operation id.
    #[attribute(order = 16)]
    pub operation_users: outbe_primitives::storage::dsl::Map<B256, Address>,

    #[attribute(order = 17)]
    pub operation_amounts: outbe_primitives::storage::dsl::Map<B256, U256>,

    #[attribute(order = 18)]
    pub operation_kinds: outbe_primitives::storage::dsl::Map<B256, u8>,

    #[attribute(order = 19)]
    pub operation_statuses: outbe_primitives::storage::dsl::Map<B256, u8>,

    /// slot 23: number of sent operations whose authenticated completion has
    /// not arrived yet. Cross-chain configuration is frozen while non-zero.
    #[attribute(order = 20)]
    pub pending_crosschain_operations: outbe_primitives::storage::dsl::Value<U256>,

    /// slot 24: base slot of the per-ISO-4217 vault sets. Appended after the
    /// existing cross-chain layout to preserve every deployed slot.
    #[attribute(order = 21)]
    pub reference_currency_vaults: outbe_primitives::storage::dsl::Map<u16, U256>,

    /// slot 25: vault -> ISO-4217 code captured at registration time.
    #[attribute(order = 22)]
    pub vault_reference_currencies: outbe_primitives::storage::dsl::Map<Address, u16>,
}

impl<'storage> VaultRouterContract<'storage> {
    /// Returns the enumerable vault set for `asset`, laid out exactly as
    /// Solidity's `mapping(address => EnumerableSet.AddressSet)` - the set's
    /// base slot is the `asset_vaults` mapping's per-key slot.
    pub fn asset_vault_set(&self, asset: Address) -> StorageSet<'storage, Address> {
        let base = asset.mapping_slot(self.asset_vaults.base_slot());
        StorageSet::new(base, self.address, self.storage.clone())
    }

    /// Returns the enumerable vault set for `iso_code`.
    pub fn reference_currency_vault_set(&self, iso_code: u16) -> StorageSet<'storage, Address> {
        let base = iso_code.mapping_slot(self.reference_currency_vaults.base_slot());
        StorageSet::new(base, self.address, self.storage.clone())
    }

    /// First vault registered for `asset`, or `None` if the asset has no vault.
    pub fn first_vault(&self, asset: Address) -> outbe_primitives::error::Result<Option<Address>> {
        self.asset_vault_set(asset).at(0)
    }
}
