//! Storage schema for the credisfactory precompile.
//!
//! The positions themselves (terms, state, the pledger EOA) live in the
//! `outbe_credis` crate. The pledger's own collateral stays in its confidential Gratis
//! `pledged_ct` for the whole life of the position (no escrow account), and the
//! originating CCA's matching COEN passes straight through to the borrower's smart
//! account at origination - so all this precompile keeps is the daily price-path scan's
//! cursor.

use outbe_macros::contract;
use outbe_primitives::addresses::CREDIS_FACTORY_ADDRESS;
use outbe_primitives::storage::types::Slot;

/// EVM storage layout for the credisfactory precompile.
///
/// Storage slots:
///   0: u32 - daily price-path scan cursor, stored as `index + 1` into the credis
///      active-position index. 0 means the last pass completed and the next run
///      starts a fresh one from the top.
#[contract(addr = CREDIS_FACTORY_ADDRESS)]
pub struct CredisFactoryContract {
    pub call_scan_cursor: Slot<u32>,
}
