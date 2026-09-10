//! Consensus job lifecycle owned by Metadosis.
//!
//! The PoC exposes one closed Lysis V1 request/expiry lifecycle. Local worker
//! progress is deliberately absent from these types.

pub mod activation;
mod authority;
mod codec;
pub mod expiry;
pub mod fork;
mod index;
mod profile;
pub mod request;
pub mod schema;
mod snapshot;
pub mod state;
mod store;
mod terminal_index;
mod transitions;
pub mod views;
pub mod vote;

pub(crate) use index::ResponseDeadlineKey;
pub(crate) use profile::poc_schema_limits;
#[cfg(test)]
pub(crate) use terminal_index::terminal_entry_key;
