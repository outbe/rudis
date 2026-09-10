use alloy_primitives::{Address, B256, U256};
use outbe_macros::{contract, storage_record, storage_schema};
use outbe_primitives::addresses::GOVERNANCE_ADDRESS;
use outbe_primitives::storage::types::{Mapping, StorageBytes, StorageSet};

/// An Outbe Improvement Proposal - a protocol-level change proposal.
///
/// The `text` field lives in-record via the String-in-record DSL support:
/// one length/base slot in the record layout, payload in a keccak-derived
/// data run.
#[storage_record(exists_field = author)]
pub struct Oip {
    #[key]
    pub id: U256,

    #[attribute(order = 0)]
    pub author: Address,

    #[attribute(order = 1)]
    pub status: u8,

    #[attribute(order = 2)]
    pub created_block: u64,

    #[attribute(order = 3)]
    pub updated_block: u64,

    #[attribute(order = 4)]
    pub text_hash: B256,

    #[attribute(order = 5)]
    pub text: String,
}

/// A Governance Improvement Proposal - a proposal to change the canon and/or
/// meta-canon. Field set is identical to [`Oip`] for now (per design decision);
/// the two are separate record types so they can diverge independently when GIP
/// gains its git-style semantics.
#[storage_record(exists_field = author)]
pub struct Gip {
    #[key]
    pub id: U256,

    #[attribute(order = 0)]
    pub author: Address,

    #[attribute(order = 1)]
    pub status: u8,

    #[attribute(order = 2)]
    pub created_block: u64,

    #[attribute(order = 3)]
    pub updated_block: u64,

    #[attribute(order = 4)]
    pub text_hash: B256,

    #[attribute(order = 5)]
    pub text: String,
}

#[storage_schema]
#[contract(addr = GOVERNANCE_ADDRESS)]
pub struct GovernanceContract {
    // --- meta-canon: constitutional text, no status model ---
    #[attribute(order = 0)]
    pub meta_canon: StorageBytes,
    #[attribute(order = 1)]
    pub meta_canon_version: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 2)]
    pub meta_canon_hash: outbe_primitives::storage::dsl::Value<B256>,
    #[attribute(order = 3)]
    pub meta_canon_revisions: outbe_primitives::storage::dsl::Map<u64, B256>,

    // --- canon: active protocol norms, no status model ---
    #[attribute(order = 4)]
    pub canon: StorageBytes,
    #[attribute(order = 5)]
    pub canon_version: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 6)]
    pub canon_hash: outbe_primitives::storage::dsl::Value<B256>,
    #[attribute(order = 7)]
    pub canon_revisions: outbe_primitives::storage::dsl::Map<u64, B256>,

    // --- proposal id counters + authorities: all one slot each ---
    //
    // These fixed-width fields are ordered BEFORE the record maps on purpose: a
    // `Map<K, Record>` reserves `Record::SLOTS` contiguous base slots (one per
    // record field, for keccak namespacing), so placing `oips`/`gips` last keeps
    // every seeded slot (texts, versions, hashes, revisions, counters,
    // authorities) at a fixed index regardless of how the record types grow.
    // `scripts/seed_genesis.py` depends on this stability; the
    // `storage_layout_matches_seeder` test pins it.
    #[attribute(order = 8)]
    pub next_oip_id: outbe_primitives::storage::dsl::Value<u64>,
    #[attribute(order = 9)]
    pub next_gip_id: outbe_primitives::storage::dsl::Value<u64>,

    // --- authorities: PoC write-gate (validator addresses, seeded at genesis) ---
    #[attribute(order = 10)]
    pub authorities: outbe_primitives::storage::dsl::Map<Address, bool>,

    // --- proposals: OIP and GIP, separate maps and id sequences (each reserves
    //     Oip::SLOTS / Gip::SLOTS base slots) ---
    #[attribute(order = 11)]
    pub oips: outbe_primitives::storage::dsl::Map<U256, Oip>,
    #[attribute(order = 12)]
    pub gips: outbe_primitives::storage::dsl::Map<U256, Gip>,

    // --- indexes, per kind (appended last so genesis-seeded slots (<=10) never
    //     shift). Author list uses the tribute owner-index idiom (count map +
    //     hashed-key id map). Status uses one enumerable StorageSet per status
    //     value via `mapping(status => set)` (the OZ `mapping(role => members)`
    //     pattern): submit inserts into Draft; a status change moves the id from
    //     the old set to the new one; `getByStatus` reads only that set. ---
    #[attribute(order = 13)]
    pub oip_author_count: outbe_primitives::storage::dsl::Map<Address, u32>,
    #[attribute(order = 14)]
    pub oip_author_ids: outbe_primitives::storage::dsl::Map<B256, U256>,
    #[attribute(order = 15)]
    pub oip_by_status: Mapping<u8, StorageSet<U256>>,
    #[attribute(order = 16)]
    pub gip_author_count: outbe_primitives::storage::dsl::Map<Address, u32>,
    #[attribute(order = 17)]
    pub gip_author_ids: outbe_primitives::storage::dsl::Map<B256, U256>,
    #[attribute(order = 18)]
    pub gip_by_status: Mapping<u8, StorageSet<U256>>,
}
