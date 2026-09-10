//! Consensus-facing binary and commitment primitives for OCOMP.
//!
//! It owns the closed OCOMP V1 object registry, OCB1 framing, bounded canonical
//! fields, registered hash domains, ordered-list roots and typed validation.
//! It is deliberately not a general-purpose serialization framework.

pub mod abi;
pub mod activation;
pub mod capacity;
pub mod codec;
pub mod committee;
pub mod common;
pub mod control;
pub mod error;
pub mod generated_shape;
pub mod hash;
pub mod input;
pub mod intent;
pub mod league_snapshot;
pub mod list;
pub mod local_control;
pub mod nod_materialization;
pub mod opening;
pub mod profile;
pub mod receipts;
pub mod registry;
pub mod result;
mod schema;
pub mod shuffle;
pub mod state;
pub mod system_carrier;
pub mod unit;
pub mod vote;

pub use codec::{
    decode_envelope, encode_envelope, ensure_strictly_increasing, require_canonical_reencoding,
    AllocationStats, CanonicalReader, CanonicalWriter, CodecLimits, DecodedEnvelope,
    OCB1_HEADER_LEN, OCB1_MAGIC, OCB1_SCHEMA_VERSION,
};
pub use control::*;
pub use error::ProtocolError;
pub use hash::{framed_preimage, hash_framed, verify_framed_hash};
pub use list::{
    ordered_list_root, verify_ordered_list_membership, OrderedListLimits, StreamingOrderedListRoot,
};
pub use registry::{HashDomain, ListKind, ObjectKind};
pub use schema::SchemaLimits;
