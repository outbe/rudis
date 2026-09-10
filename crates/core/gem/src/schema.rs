use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::GEM_ADDRESS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GemState {
    Issued = 0,
    Qualified = 1,
    Called = 2,
    Settled = 3,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GemAddParams {
    pub owner: Address,
    pub gem_type: u8,
    pub promis_load_minor: U256,
    pub entry_price_minor: U256,
    pub floor_price_minor: U256,
    pub call_price_minor: U256,
    pub call_rate: u16,
    pub issuance_currency: u16,
    pub reference_currency: u16,
    pub initial_state: GemState,
    pub issued_at: u64,
}

#[storage_record(exists_field = owner)]
pub struct GemData {
    #[key]
    pub gem_id: U256,

    #[attribute(order = 0)]
    pub owner: Address,

    #[attribute(order = 1)]
    pub gem_type: u8,

    #[attribute(order = 2)]
    pub promis_load_minor: U256,

    #[attribute(order = 3)]
    pub entry_price_minor: U256,

    #[attribute(order = 4)]
    pub floor_price_minor: U256,

    #[attribute(order = 5)]
    pub issuance_currency: u16,

    #[attribute(order = 6)]
    pub reference_currency: u16,

    #[attribute(order = 7)]
    pub state: u8,

    #[attribute(order = 8)]
    pub issued_at: u64,

    /// Coen price level (Reference Currency) whose breach arms a Call Event.
    /// `entry_price_minor * (1 + call_rate)`; call rate is 128% for agent gems.
    #[attribute(order = 9)]
    pub call_price_minor: U256,

    /// Block timestamp when the gem was force-called; `0` until Called.
    #[attribute(order = 10, default = 0)]
    pub called_at: u64,

    /// Call Notice Period in seconds: after a Called gem passes
    /// `called_at + call_notice_period` it is forfeit-burned. Snapshot of the
    /// protocol constant at issuance.
    #[attribute(order = 11, default = 0)]
    pub call_notice_period: u32,

    /// Call-price markup percent (snapshot of `CALL_RATE` at issuance);
    /// `call_price_minor = entry_price_minor * (100 + call_rate) / 100`
    /// (128 => 2.28x).
    #[attribute(order = 12, default = 0)]
    pub call_rate: u16,

    /// Call-trigger evaluation window in seconds (snapshot of `CALL_WINDOW` at
    /// issuance); the trailing span scanned for Call Price breaches.
    #[attribute(order = 13, default = 0)]
    pub call_window: u32,

    /// Breach threshold in seconds (snapshot of `CALL_THRESHOLD` at issuance);
    /// divided by 86400 to get the required breach-day count.
    #[attribute(order = 14, default = 0)]
    pub call_threshold: u32,

    /// Block timestamp when the gem became Qualified; `0` until Qualified.
    #[attribute(order = 15, default = 0)]
    pub qualified_at: u64,

    /// Block timestamp when the gem was Settled; `0` until Settled.
    #[attribute(order = 16, default = 0)]
    pub settled_at: u64,
}

#[storage_schema]
#[contract(addr = GEM_ADDRESS)]
pub struct GemContract {
    #[attribute(order = 0)]
    pub total_supply: outbe_primitives::storage::dsl::Value<u64>,

    #[attribute(order = 1)]
    pub gem_items: outbe_primitives::storage::dsl::Map<U256, GemData>,

    #[attribute(order = 2)]
    pub owner_gem_counts: outbe_primitives::storage::dsl::Map<Address, u32>,

    #[attribute(order = 3)]
    pub owner_gem_ids: outbe_primitives::storage::dsl::Map<B256, U256>,

    #[attribute(order = 4)]
    pub all_gem_ids: outbe_primitives::storage::dsl::List<U256>,

    #[attribute(order = 5)]
    pub gem_index: outbe_primitives::storage::dsl::Map<U256, u32>,

    // --- Unqualified-gem bin index (PancakeSwap LB-style 3-level radix-256 trie) ---
    //
    // A floor price is only comparable to the COEN rate of its own reference
    // currency, so every column here is namespaced by ISO code and each currency
    // walks an independent trie. See `state::CurrencyBins`.
    #[attribute(order = 6)]
    pub bin_tree_root: outbe_primitives::storage::dsl::Map<u16, U256>,

    // Keyed by `state::scoped(iso, trie key)`.
    #[attribute(order = 7)]
    pub bin_tree_mid: outbe_primitives::storage::dsl::Map<u64, U256>,

    #[attribute(order = 8)]
    pub bin_tree_leaf: outbe_primitives::storage::dsl::Map<u64, U256>,

    #[attribute(order = 9)]
    pub unqualified_bin_count: outbe_primitives::storage::dsl::Map<u64, u32>,

    #[attribute(order = 10)]
    pub unqualified_bin_gems: outbe_primitives::storage::dsl::Map<B256, U256>,

    // --- Qualified-gem bin index, by call_price_minor: the price pass enters
    // only the bins a breach could have reached.
    #[attribute(order = 11)]
    pub qualified_bin_tree_root: outbe_primitives::storage::dsl::Map<u16, U256>,

    #[attribute(order = 12)]
    pub qualified_bin_tree_mid: outbe_primitives::storage::dsl::Map<u64, U256>,

    #[attribute(order = 13)]
    pub qualified_bin_tree_leaf: outbe_primitives::storage::dsl::Map<u64, U256>,

    #[attribute(order = 14)]
    pub qualified_bin_count: outbe_primitives::storage::dsl::Map<u64, u32>,

    #[attribute(order = 15)]
    pub qualified_bin_gems: outbe_primitives::storage::dsl::Map<B256, U256>,

    #[attribute(order = 16)]
    pub call_currency_cursor: outbe_primitives::storage::dsl::Value<u32>,

    #[attribute(order = 17)]
    pub call_scan_cursor: outbe_primitives::storage::dsl::Map<u16, u32>,

    /// Next bin the qualify scan visits, per reference currency. Non-zero only
    /// while a sweep was cut short by the per-block budget.
    #[attribute(order = 18)]
    pub qualify_scan_cursor: outbe_primitives::storage::dsl::Map<u16, u32>,

    /// Where the next qualify scan starts, so a heavy currency cannot starve the
    /// ones behind it when the per-block budget runs out.
    #[attribute(order = 19)]
    pub qualify_currency_cursor: outbe_primitives::storage::dsl::Value<u32>,

    // --- Called gems, bucketed by the hour their notice period closes in. Calling is
    // driven by price and expiry only by time, so the two stages stay separate.
    #[attribute(order = 20)]
    pub expiry_tree_root: outbe_primitives::storage::dsl::Value<U256>,
    #[attribute(order = 21)]
    pub expiry_tree_mid: outbe_primitives::storage::dsl::Map<u32, U256>,
    #[attribute(order = 22)]
    pub expiry_tree_leaf: outbe_primitives::storage::dsl::Map<u32, U256>,
    /// Gem id -> `(bucket << 32) | slot`; 0 = not queued.
    #[attribute(order = 23)]
    pub called_bucket_slot: outbe_primitives::storage::dsl::Map<U256, u64>,
    /// Held off the record so the head check costs no record load.
    #[attribute(order = 24)]
    pub called_deadline: outbe_primitives::storage::dsl::Map<U256, u64>,

    /// UTC day an unfinished call sweep is pinned to, so its later slices decide
    /// against the prices it opened with. 0 = none in flight; a date key is never 0.
    #[attribute(order = 25)]
    pub call_sweep_day: outbe_primitives::storage::dsl::Value<u32>,

    // Genesis parameter-profile selector (0 = prod, 1 = dev); see crate::config.
    #[attribute(order = 26)]
    pub config_profile: outbe_primitives::storage::dsl::Value<u8>,

    /// Widest window ever issued in a currency; it only grows, so the span the scan
    /// collects always covers a gem whose record outruns the live profile.
    #[attribute(order = 27)]
    pub max_call_window: outbe_primitives::storage::dsl::Map<u16, u32>,

    /// Slots ever used in a bucket; retired ones are zeroed in place, not compacted.
    #[attribute(order = 28)]
    pub expiry_bucket_len: outbe_primitives::storage::dsl::Map<u32, u32>,
    #[attribute(order = 29)]
    pub expiry_bucket_live: outbe_primitives::storage::dsl::Map<u32, u32>,
    /// `keccak256(bucket_be32 ++ slot_be32)` -> gem id.
    #[attribute(order = 30)]
    pub expiry_bucket_at: outbe_primitives::storage::dsl::Map<B256, U256>,
    #[attribute(order = 31)]
    pub expiry_sweep_day: outbe_primitives::storage::dsl::Value<u32>,
    #[attribute(order = 32)]
    pub expiry_cursor: outbe_primitives::storage::dsl::Value<u32>,
}

impl GemContract<'_> {
    /// `gem_id = keccak256("gem" || owner || amount_be || block_number_be)`.
    /// `amount` is the gem's `promis_load_minor` (reward principal).
    pub fn generate_gem_id(owner: Address, amount: U256, block_number: u64) -> U256 {
        use alloy_primitives::keccak256;
        let mut buf = [0u8; 3 + 20 + 32 + 8];
        buf[0..3].copy_from_slice(b"gem");
        buf[3..23].copy_from_slice(owner.as_slice());
        buf[23..55].copy_from_slice(&amount.to_be_bytes::<32>());
        buf[55..63].copy_from_slice(&block_number.to_be_bytes());
        U256::from_be_bytes(keccak256(buf).0)
    }
}
