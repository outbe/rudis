//! Storage schema for the Desis module.

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_macros::{contract, storage_schema};
use outbe_primitives::addresses::DESIS_ADDRESS;
use outbe_primitives::time::WorldwideDay;

/// Auction lifecycle stage, in order: a day is `Briefed`, `Started` for the
/// commit window, `Revealing` for the reveal window, `Clearing` while the
/// fan-in aggregates bids, then terminal `Cleared` / `Cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AuctionStage {
    #[default]
    None = 0,
    Briefed = 1,
    Started = 2,
    Revealing = 3,
    Clearing = 4,
    Cleared = 5,
    Cancelled = 6,
}

impl AuctionStage {
    pub fn from_u8(value: u8) -> Result<Self, crate::DesisError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Briefed),
            2 => Ok(Self::Started),
            3 => Ok(Self::Revealing),
            4 => Ok(Self::Clearing),
            5 => Ok(Self::Cleared),
            6 => Ok(Self::Cancelled),
            _ => Err(crate::DesisError::InvalidStageTransition),
        }
    }
}

/// Call-trigger parameters carried alongside the auction config; sourced from
/// the genesis `IntexParams` at auction start and relayed to the target chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IntexCallTrigger {
    /// Rolling VWAP window evaluated for the call condition (seconds).
    pub call_window: u32,
    /// Breach time within the window required to trigger a call (seconds).
    pub call_threshold: u32,
    /// Notice a holder gets to settle after the series is Called (seconds).
    pub call_notice_period: u32,
}

/// Entry price of one reference currency, captured at the brief.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceCurrencyPrice {
    pub iso_code: u16,
    /// Per-unit entry price in ISO stable-units (1e6); floor and call derive from it.
    pub entry_price_minor: U256,
}

/// Auction configuration (demand side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuctionConfig {
    /// PROMIS-units per Intex unit (1e6); bounded by uint128.
    pub promis_load_minor: u128,
    /// Call-trigger parameters sourced from genesis `IntexParams`.
    pub call_trigger: IntexCallTrigger,
    /// Minimum acceptable bid rate (1e6 fixed-point, % of the escrow basis). 0 -> no floor.
    pub min_intex_bid_rate: u32,
    /// Minimum bid quantity (Intex units); 4% of the prior series' issued count.
    pub min_intex_bid_quantity: u16,
    /// Commit-entry bond in 18-decimal WCOEN units; 0 disables the bond.
    pub commit_bond_minor: u128,
    /// One row per reference currency the oracle could price for this day.
    pub reference_prices: Vec<ReferenceCurrencyPrice>,
}

impl AuctionConfig {
    /// Build the demand-side config from the day's per-reference entry prices and
    /// the load the day was briefed at. `min_intex_bid_rate = 0` means no bid
    /// floor. `call_trigger`, `min_intex_bid_quantity` and `commit_bond_minor` are
    /// left at their defaults here and populated at auction start
    /// (`start_auction`), where the genesis `IntexParams` and the prior-clearing
    /// count are in reach.
    pub fn from_reference_prices(
        reference_prices: Vec<ReferenceCurrencyPrice>,
        promis_load_minor: u128,
    ) -> Self {
        Self {
            promis_load_minor,
            call_trigger: IntexCallTrigger::default(),
            min_intex_bid_rate: 0,
            min_intex_bid_quantity: 0,
            commit_bond_minor: 0,
            reference_prices,
        }
    }

    /// The day's entry price for one reference currency.
    pub fn entry_price_for(&self, iso_code: u16) -> Option<U256> {
        self.reference_prices
            .iter()
            .find(|row| row.iso_code == iso_code)
            .map(|row| row.entry_price_minor)
    }

    /// Per-Intex escrow basis = `promis_load` COEN, which the day is briefed at. The escrow
    /// pays wCOEN, so the bid rate applies against this. entry_price feeds only floor/call.
    pub fn escrow_basis_minor(&self) -> u128 {
        self.promis_load_minor
    }
}

/// One bid relayed from a target chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BidData {
    pub bidder_address: Address,
    /// Bid rate (1e6 fixed-point, % of the escrow basis).
    pub intex_bid_rate: u32,
    /// Bid timestamp (ordering only).
    pub timestamp: u32,
    /// Requested quantity (Intex units).
    pub intex_quantity: u16,
    /// Declared issuance currency (ISO numeric).
    pub issuance_currency: u16,
    /// Reference currency the bid prices in (ISO numeric).
    pub reference_currency: u16,
}

/// Auction clearing result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClearingResult {
    pub issued_intex_count: u32,
    pub clearing_rate: u32,
    pub winners: Vec<Address>,
    pub winner_quantities: Vec<U256>,
    /// Source chain of each winning bid (parallel to `winners`).
    pub winner_chains: Vec<u32>,
    /// `(issuance, reference)` ISO pair of each winning bid (parallel to `winners`);
    /// the day issues one series per distinct pair.
    pub winner_currencies: Vec<(u16, u16)>,
    pub all_bidders: Vec<Address>,
    pub refunded_amounts: Vec<u128>,
    pub paid_amounts: Vec<u128>,
    /// Source chain of each bid (parallel to `all_bidders`).
    pub bidder_chains: Vec<u32>,
}

/// EVM storage layout for the Desis module.
///
/// Per-series: auction config, stage, bid-batch metadata, pending clearing
/// inputs. Bids and clearing results are stored in separate vec-maps.
///
/// Attribute orders are append-only once the chain is live: renumbering or
/// reusing an order changes the slot derivation and needs a chain wipe.
#[storage_schema]
#[contract(addr = DESIS_ADDRESS)]
pub struct DesisContract {
    // --- Auction config (per series) ---
    /// worldwide_day -> promis_load_minor.
    #[attribute(order = 0)]
    pub config_promis_load_minor: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,
    #[attribute(order = 1)]
    pub config_min_bid_rate: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,
    #[attribute(order = 2)]
    pub config_min_bid_quantity: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Auction stage ---
    /// worldwide_day -> AuctionStage (u8).
    #[attribute(order = 4)]
    pub auction_stage: outbe_primitives::storage::dsl::Map<WorldwideDay, u8>,

    // --- Bid storage (per chain) ---
    /// keccak256(worldwide_day_be32 ++ chain_be32 ++ index_be32) -> bidder address.
    #[attribute(order = 5)]
    pub bid_bidder: outbe_primitives::storage::dsl::Map<B256, Address>,
    /// Packed bid fields: limbs[0]=rate(u32); limbs[1]=issuance(u16)<<48|
    /// quantity(u16)<<32|timestamp(u32); limbs[2]=reference(u16).
    #[attribute(order = 6)]
    pub bid_packed: outbe_primitives::storage::dsl::Map<B256, U256>,

    // --- Pending clearing ---
    /// worldwide_day -> supply (Intex units) pending at clearing stage.
    #[attribute(order = 7)]
    pub pending_supply_intex: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Global clearing state ---
    /// Most recently cleared worldwide_day (for minBidQty 4% derivation).
    #[attribute(order = 8)]
    pub last_cleared_worldwide_day: outbe_primitives::storage::dsl::Value<WorldwideDay>,
    /// issuedIntexCount from the most recent clearing (for minBidQty 4% derivation).
    #[attribute(order = 9)]
    pub last_clearing_issued_count: outbe_primitives::storage::dsl::Value<u32>,

    /// worldwide_day -> 1 once `arm_clearing` has run; lets `force_clear` tell a
    /// genuine zero supply from a clearing that was never initiated.
    #[attribute(order = 10)]
    pub clearing_initiated: outbe_primitives::storage::dsl::Map<WorldwideDay, u8>,

    // --- Extended auction config ---
    /// worldwide_day -> call-trigger window (whole days).
    #[attribute(order = 13)]
    pub config_call_window: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,
    /// worldwide_day -> call-trigger threshold (whole days).
    #[attribute(order = 14)]
    pub config_call_threshold: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,
    /// worldwide_day -> call cooldown (seconds).
    #[attribute(order = 15)]
    pub config_call_notice_period: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    /// worldwide_day -> commit-entry bond (payment-token minor units).
    #[attribute(order = 16)]
    pub config_commit_bond_minor: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,

    /// series/day -> scheduled auction timestamp, recorded at start (bounded until 2106).
    #[attribute(order = 17)]
    pub auction_at: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Per-chain bid intake (keyed keccak256(worldwide_day_be32 ++ chain_be32)) ---
    /// Highest accepted bid-relay generation for the chain.
    #[attribute(order = 18)]
    pub chain_last_generation: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// totalBatches carried by the chain's batches for the current generation.
    #[attribute(order = 19)]
    pub chain_total_batches: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// Bitmap of arrived batchIndices for the current generation (bit i = batchIndex i seen).
    #[attribute(order = 20)]
    pub chain_arrived_mask: outbe_primitives::storage::dsl::Map<B256, U256>,
    /// Bids accepted from the chain for the current generation.
    #[attribute(order = 21)]
    pub chain_bid_count: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// 1 once the chain's intake is complete (marker + all batches + totals match).
    #[attribute(order = 22)]
    pub chain_done: outbe_primitives::storage::dsl::Map<B256, u8>,
    /// totalBatches claimed by the chain's BIDS_DONE marker (0 = no marker yet).
    #[attribute(order = 23)]
    pub chain_done_batches: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// totalBids claimed by the chain's BIDS_DONE marker.
    #[attribute(order = 24)]
    pub chain_done_bids: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// worldwide_day -> bids accepted across all chains (getBidsCount view).
    #[attribute(order = 25)]
    pub day_bid_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Clearing fan-in gate ---
    /// worldwide_day -> deadline after which clearing proceeds without the missing chains.
    #[attribute(order = 26)]
    pub clearing_deadline: outbe_primitives::storage::dsl::Map<WorldwideDay, u64>,
    /// Days awaiting the clearing gate (dense active set for the begin-block tick).
    #[attribute(order = 27)]
    pub gate_active_count: outbe_primitives::storage::dsl::Value<u32>,
    /// dense index -> worldwide_day. Raw `u32` on the value side: the contract
    /// macro treats a non-scalar map value as a `StorageRecord` and would size the
    /// slot span from it, so the day is converted at the read/write sites.
    #[attribute(order = 28)]
    pub gate_active_at: outbe_primitives::storage::dsl::Map<u32, u32>,
    /// worldwide_day -> (active index + 1); 0 = not active.
    #[attribute(order = 29)]
    pub gate_active_slot: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Auction brief ---
    /// worldwide_day -> auction supply in raw PROMIS minor units.
    #[attribute(order = 30)]
    pub pending_supply_promis: outbe_primitives::storage::dsl::Map<WorldwideDay, U256>,
    /// worldwide_day -> 1 for a green day.
    #[attribute(order = 31)]
    pub brief_green: outbe_primitives::storage::dsl::Map<WorldwideDay, u8>,
    /// Days with a scheduled auction (dense active set for the begin-block tick).
    #[attribute(order = 32)]
    pub sched_active_count: outbe_primitives::storage::dsl::Value<u32>,
    /// dense index -> worldwide_day. Raw `u32` on the value side: the contract
    /// macro treats a non-scalar map value as a `StorageRecord` and would size the
    /// slot span from it, so the day is converted at the read/write sites.
    #[attribute(order = 33)]
    pub sched_active_at: outbe_primitives::storage::dsl::Map<u32, u32>,
    /// worldwide_day -> (active index + 1); 0 = not active.
    #[attribute(order = 34)]
    pub sched_active_slot: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,

    // --- Entry price per reference currency, captured at the brief ---
    /// worldwide_day -> number of priced reference currencies.
    #[attribute(order = 35)]
    pub reference_price_count: outbe_primitives::storage::dsl::Map<WorldwideDay, u32>,
    /// keccak256(worldwide_day_be32 ++ index_be32) -> reference currency ISO code.
    #[attribute(order = 36)]
    pub reference_price_iso: outbe_primitives::storage::dsl::Map<B256, u32>,
    /// keccak256(worldwide_day_be32 ++ index_be32) -> entry price in ISO stable-units (1e6).
    /// Floor and call derive from it, so only the anchor is stored.
    #[attribute(order = 37)]
    pub reference_price_entry: outbe_primitives::storage::dsl::Map<B256, U256>,

    // --- PROMIS load ladder ---
    /// Exponent `k` of the current load, `promis_load_minor = 10^k`. Zero until the
    /// chain has briefed a day it could price, which the deadband has nothing to hold.
    #[attribute(order = 38)]
    pub promis_load_exponent: outbe_primitives::storage::dsl::Value<u32>,
    /// Digits of the launch pair the ladder re-anchors against, captured on the first
    /// day the chain could price the anchor currency. Zero until captured.
    #[attribute(order = 39)]
    pub promis_load_anchor_digits: outbe_primitives::storage::dsl::Value<u32>,
}

impl DesisContract<'_> {
    /// Composite key for per-(day, chain) fields: `keccak256(worldwide_day_be32 ++ chain_be32)`.
    pub fn chain_key(worldwide_day: WorldwideDay, chain_id: u32) -> B256 {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&worldwide_day.value().to_be_bytes());
        buf[4..8].copy_from_slice(&chain_id.to_be_bytes());
        keccak256(buf)
    }

    /// Composite key for per-(day, row) price fields.
    pub fn reference_price_key(worldwide_day: WorldwideDay, index: u32) -> B256 {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&worldwide_day.value().to_be_bytes());
        buf[4..8].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }

    /// Composite key for per-bid fields: `keccak256(worldwide_day_be32 ++ chain_be32 ++ index_be32)`.
    pub fn bid_key(worldwide_day: WorldwideDay, chain_id: u32, index: u32) -> B256 {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&worldwide_day.value().to_be_bytes());
        buf[4..8].copy_from_slice(&chain_id.to_be_bytes());
        buf[8..12].copy_from_slice(&index.to_be_bytes());
        keccak256(buf)
    }
}
