//! Governed Stablecoin Factory V1 state and typed internal API.

pub mod api;
pub mod errors;
pub mod precompile;
pub mod schema;

mod abi;
mod state;

pub use api::{FactoryReservation, StablecoinFactoryApi, ValidatedStablecoinCreate};
pub use schema::{ReservationRecord, StablecoinFactoryContract};

#[cfg(test)]
mod tests;
