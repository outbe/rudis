use alloy_primitives::{b256, keccak256, Address, B256, U256};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::storage::types::StorageBytes;

/// Canonical role ids pinned by ADR-C-TOK-003.
pub const ADMIN_ROLE: B256 =
    b256!("df8b4c520ffe197c5343c6f5aec59570151ef9a492f2c624fd45ddde6135ec42");
pub const ISSUER_ROLE: B256 =
    b256!("76afa8a5929fef1b4c03674b2152ae5aaad1d974b8a4021c59477bcc846ccc1e");
pub const CAP_MANAGER_ROLE: B256 =
    b256!("ea85ad40095d48558c82add51498fcc17c0bbd84883ea60f8230c6b6b494ea40");
pub const GUARDIAN_ROLE: B256 =
    b256!("8b5b16d04624687fcf0d0228f19993c9157c1ed07b41d8d430fd9100eb099fe8");
pub const COMPLIANCE_ROLE: B256 =
    b256!("a67a057d728d16e162a15912cbf6e8d4fcd69e5b7b0d1f849a0a10ca6e14741c");
pub const ENFORCER_ROLE: B256 =
    b256!("98151564cba5aa82ec81644cc0eefc457cbd612a3d0184596373eb688d514497");

pub const OPERATIONAL_ROLES: [B256; 5] = [
    ISSUER_ROLE,
    CAP_MANAGER_ROLE,
    GUARDIAN_ROLE,
    COMPLIANCE_ROLE,
    ENFORCER_ROLE,
];

/// Stable V1 per-token layout. The macro intentionally has no default address:
/// dynamic dispatch supplies the actual callee to [`StablecoinContract::new`].
///
/// Root slots:
///
/// - 0: schema version
/// - 1: creation protocol version
/// - 2: full Factory token id
/// - 3: name bytes
/// - 4: symbol bytes
/// - 5: ISO-4217 numeric currency
/// - 6: decimals
/// - 7: issuer
/// - 8: supply cap
/// - 9: total supply
/// - 10: policy id
/// - 11: paused
/// - 12: admin
/// - 13: pending admin
/// - 14: balances mapping
/// - 15: allowances mapping
/// - 16: permit nonces mapping
/// - 17: role memberships mapping
/// - 18: frozen amounts mapping
#[storage_schema]
#[contract]
pub struct StablecoinContract {
    #[attribute(order = 0)]
    pub schema_version: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 1)]
    pub creation_protocol_version: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 2)]
    pub token_id: outbe_primitives::storage::dsl::Value<B256>,
    #[attribute(order = 3)]
    pub name: StorageBytes,
    #[attribute(order = 4)]
    pub symbol: StorageBytes,
    #[attribute(order = 5)]
    pub currency: outbe_primitives::storage::dsl::Value<u16>,
    #[attribute(order = 6)]
    pub decimals: outbe_primitives::storage::dsl::Value<u8>,
    #[attribute(order = 7)]
    pub issuer: outbe_primitives::storage::dsl::Value<Address>,
    #[attribute(order = 8)]
    pub supply_cap: outbe_primitives::storage::dsl::Value<U256>,
    #[attribute(order = 9)]
    pub total_supply: outbe_primitives::storage::dsl::Value<U256>,
    #[attribute(order = 10)]
    pub policy_id: outbe_primitives::storage::dsl::Value<U256>,
    #[attribute(order = 11)]
    pub paused: outbe_primitives::storage::dsl::Value<bool>,
    #[attribute(order = 12)]
    pub admin: outbe_primitives::storage::dsl::Value<Address>,
    #[attribute(order = 13)]
    pub pending_admin: outbe_primitives::storage::dsl::Value<Address>,
    #[attribute(order = 14)]
    pub balances: outbe_primitives::storage::dsl::Map<Address, U256>,
    #[attribute(order = 15)]
    pub allowances: outbe_primitives::storage::dsl::Map<B256, U256>,
    #[attribute(order = 16)]
    pub nonces: outbe_primitives::storage::dsl::Map<Address, U256>,
    #[attribute(order = 17)]
    pub roles: outbe_primitives::storage::dsl::Map<B256, bool>,
    #[attribute(order = 18)]
    pub frozen: outbe_primitives::storage::dsl::Map<Address, U256>,
}

pub fn allowance_key(owner: Address, spender: Address) -> B256 {
    let mut input = [0u8; 40];
    input[..20].copy_from_slice(owner.as_slice());
    input[20..].copy_from_slice(spender.as_slice());
    keccak256(input)
}

pub fn role_key(role: B256, account: Address) -> B256 {
    let mut input = [0u8; 52];
    input[..32].copy_from_slice(role.as_slice());
    input[32..].copy_from_slice(account.as_slice());
    keccak256(input)
}
