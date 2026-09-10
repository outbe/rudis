//! Storage schema for the Credis contract.

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::CREDIS_ADDRESS;

use crate::errors::CredisError;

/// Position lifecycle state.
///
/// A position is settleable from the moment it opens; `Open -> Called` is the
/// sustained-breach trigger. Both `Settled` (fully repaid) and `Void` (call
/// window lapsed with a remainder) are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CredisState {
    Open = 0,
    Called = 1,
    Settled = 2,
    Void = 3,
}

impl CredisState {
    pub fn from_u8(value: u8) -> Result<Self, CredisError> {
        match value {
            0 => Ok(Self::Open),
            1 => Ok(Self::Called),
            2 => Ok(Self::Settled),
            3 => Ok(Self::Void),
            other => Err(CredisError::InvalidStateValue(other)),
        }
    }

    /// True once the position can no longer change: fully repaid or voided.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Void)
    }
}

/// Position record. Keyed by `position_id = keccak256(pledge_handle || smart_account)`.
///
/// Every term - both currency codes included - is sealed at opening and never
/// changes afterwards; only `outstanding`, `collateral_locked`,
/// `last_settled_at`, `called_at` and `state` move over the position's life.
#[derive(Debug, Clone, PartialEq, Eq)]
#[storage_record(exists_field = smart_account)]
pub struct Position {
    #[key]
    pub position_id: U256,

    /// The card bundle the loan was disbursed to.
    #[attribute(order = 0)]
    pub smart_account: Address,

    /// The agent that originated the position. Carries the accountability for
    /// how it resolves.
    #[attribute(order = 1)]
    pub cca: Address,

    /// The stablecoin the position is denominated and disbursed in.
    #[attribute(order = 2)]
    pub asset: Address,

    /// ISO 4217 numeric code of `asset` (e.g. 840 = USD), read at opening.
    /// Denominates the position and keys its policy rate. NOT the call
    /// threshold anchor - see [`Self::reference_currency`].
    #[attribute(order = 3)]
    pub issuance_currency: u16,

    /// The pledger EOA sealed under the enclave state key (`nonce || ct`, produced by
    /// gratis `ConsumePledge`). Stored as ciphertext so external observers cannot link the
    /// EOA to `smart_account`; settlement and the void recover the plaintext EOA
    /// via a `RevealOwner` enclave round-trip to key the right `pledged_ct` and fidelity
    /// cohort. Never a plaintext address on-chain.
    #[attribute(order = 4)]
    pub eoa_ct: Vec<u8>,

    /// `P` - stablecoin minor units disbursed. Fixed.
    #[attribute(order = 5)]
    pub principal: U256,

    /// `P_out` - outstanding principal. Reaching zero closes the position.
    #[attribute(order = 6)]
    pub outstanding: U256,

    /// `G` - pledged Gratis, valued 1:1 against principal at the pledge quote
    /// rate (COEN/`issuance_currency`, sealed into the ticket). Fixed.
    #[attribute(order = 7)]
    pub collateral: U256,

    /// The share of `G` still locked. Released principal-proportionally.
    #[attribute(order = 8)]
    pub collateral_locked: U256,

    /// `r` - the currency's annual official policy rate (scale `1e6`) times the
    /// policy-rate factor, pinned at opening for the position's life.
    #[attribute(order = 9)]
    pub policy_rate: U256,

    /// `P0` - COEN price in the position's **reference** currency (scale `1e6`),
    /// snapshotted at origination. The threshold geometry is measured here, not
    /// in the issuance currency the position is denominated in.
    #[attribute(order = 10)]
    pub entry_price: U256,

    /// `P0 + 64%`. The price whose sustained breach on the
    /// COEN/`reference_currency` daily series triggers the call.
    #[attribute(order = 11)]
    pub call_price: U256,

    #[attribute(order = 12)]
    pub originated_at: u64,

    /// Start of the current accrual period. Equals `originated_at` until the
    /// first settlement, then advances by the whole days each settlement
    /// charges - not to the settlement timestamp, so a sub-day remainder
    /// carries forward instead of being discarded.
    #[attribute(order = 13)]
    pub last_settled_at: u64,

    /// 0 until the position is called.
    #[attribute(order = 14, default = 0)]
    pub called_at: u64,

    /// Lifecycle state as `u8`; decode via [`CredisState::from_u8`].
    #[attribute(order = 15)]
    pub state: u8,

    /// ISO 4217 numeric code of the reference currency elected at origination
    /// and fixed for the position's life. Its sole function is to anchor the
    /// threshold: `entry_price` / `call_price` are quoted here and the daily
    /// breach scan reads the COEN/`reference_currency` series. It does not
    /// denominate the position and carries no FX exposure.
    #[attribute(order = 16)]
    pub reference_currency: u16,
}

impl Position {
    pub fn lifecycle_state(&self) -> Result<CredisState, CredisError> {
        CredisState::from_u8(self.state)
    }
}

/// EVM storage layout for the Credis position contract.
///
/// `address_position_*` and `total_positions` / `position_id_at_index` provide
/// dense, no-`Vec` enumeration in the same shape as `outbe-nod`'s owner index
/// (`crates/core/nod/src/schema.rs`). Slot assignment is macro-generated: a
/// `Map<K, V>` over a record reserves `V::SLOTS` top-level slots, so the
/// positions map alone spans as many slots as `Position` has attributes.
#[storage_schema]
#[contract(addr = CREDIS_ADDRESS)]
pub struct CredisContract {
    /// Position record keyed by position_id.
    #[attribute(order = 0)]
    pub positions: outbe_primitives::storage::dsl::Map<U256, Position>,

    /// Per-account count of positions ever created.
    #[attribute(order = 1)]
    pub address_position_counts: outbe_primitives::storage::dsl::Map<Address, u32>,

    /// Per-account index - keccak(addr ++ idx_be32) -> position_id.
    #[attribute(order = 2)]
    pub address_position_ids: outbe_primitives::storage::dsl::Map<B256, U256>,

    /// Total positions ever created (backs `totalSupply` / `positionByIndex`).
    #[attribute(order = 3)]
    pub total_positions: outbe_primitives::storage::dsl::Value<u64>,

    /// Dense index - index -> position_id.
    #[attribute(order = 4)]
    pub position_id_at_index: outbe_primitives::storage::dsl::Map<u64, U256>,

    /// Dense index of the positions still on the price path - those in `Open`
    /// or `Called`. Membership invariant: a position is listed iff
    /// its state is non-terminal, so the daily scan visits only the positions
    /// that can still transition instead of the whole book.
    #[attribute(order = 5)]
    pub active_positions: outbe_primitives::storage::dsl::List<U256>,

    /// position_id -> its slot in [`Self::active_positions`], for O(1) swap-remove.
    #[attribute(order = 6)]
    pub active_position_index: outbe_primitives::storage::dsl::Map<U256, u32>,

    /// Per-account count of positions currently `Called`, backing the
    /// `hasCalledPosition` view.
    #[attribute(order = 7)]
    pub called_position_counts: outbe_primitives::storage::dsl::Map<Address, u32>,
}

impl CredisContract<'_> {
    /// position_id derivation: `keccak256(pledge_handle || smart_account)`.
    pub fn position_id(handle_id: U256, smart_account: Address) -> U256 {
        let mut buf = [0u8; 52];
        buf[0..32].copy_from_slice(&handle_id.to_be_bytes::<32>());
        buf[32..52].copy_from_slice(smart_account.as_slice());
        U256::from_be_bytes(keccak256(buf).0)
    }

    /// Composite key for per-address position index: `keccak256(addr ++ idx_be32)`.
    pub fn address_index_key(account: Address, index: u32) -> B256 {
        let mut buf = [0u8; 24];
        buf[0..20].copy_from_slice(account.as_slice());
        buf[20..24].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }
}
