//! Desis: Intex auction/clearing engine on Outbe (demand side).
//!
//! Drives the auction schedule from a Metadosis brief, collects the bid batches
//! relayed by the target chains via OriginRouter, clears the auction, and hands
//! issuance to IntexFactory.

pub mod api;
pub mod constants;
pub mod errors;
pub mod ocomp_budget;
pub mod precompile;
pub(crate) mod runtime;
pub mod schema;
pub(crate) mod sol_ext;
pub(crate) mod state;

#[cfg(test)]
mod tests;

pub use errors::DesisError;
pub use runtime::{tick_gate, tick_schedule};
pub use schema::{
    AuctionConfig, AuctionStage, BidData, ClearingResult, DesisContract, ReferenceCurrencyPrice,
};
