mod actor;
mod address;
mod authority;
mod pending;
mod wire;

pub use actor::{EndpointActor, EndpointHandle, HandleError};
pub use address::{AddressError, EndpointAddress};
pub use authority::{
    sign_response, verify_response, AnchorError, AnchorSnapshot, AuthorityRecord, PeerId,
    VerificationContext, VerifiedEndpoint, VerifyError,
};
pub use pending::{
    EndpointProtocol, IdError, OsRequestIds, ProtocolError, ProtocolStats, ReceiveOutcome,
    RequestIdSource, ResolvedResponse,
};
pub use wire::{
    EndpointFrame, EndpointRequest, EndpointResponseBody, SignedEndpointResponse, WireError,
};

use alloy_primitives::B256;
use std::time::Duration;

pub const RADICLE_ENDPOINT_WIRE_VERSION: u8 = 1;
pub const RADICLE_ENDPOINT_REQUEST_TAG: u8 = 0;
pub const RADICLE_ENDPOINT_RESPONSE_TAG: u8 = 1;
pub const RADICLE_ENDPOINT_MAGIC: [u8; 4] = *b"ORAD";
pub const MAX_ADDRESSES: usize = 16;
pub const MAX_DNS_LENGTH: usize = 253;
pub const MAX_ENDPOINT_FRAME_BYTES: usize = 4_387;
pub const MAX_ENDPOINT_TTL_BLOCKS: u64 = 256;
pub const MAX_FUTURE_ANCHOR_DISTANCE: u64 = 256;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT_MS: u64 = 5_000;
pub const UNKNOWN_ANCHOR_TIMEOUT: Duration = Duration::from_secs(30);
pub const UNKNOWN_ANCHOR_TIMEOUT_MS: u64 = 30_000;
pub const MAX_PENDING_REQUESTS: usize = 256;
pub const MAX_UNKNOWN_ANCHORS: usize = 256;
pub const MAX_UNKNOWN_ANCHOR_BYTES: usize = 1_123_072;
pub const ACTOR_MAILBOX_CAPACITY: usize = 256;
pub const HANDLE_DEADLINE: Duration = Duration::from_secs(5);
pub const REQUEST_ID_GENERATION_ATTEMPTS: usize = 8;
pub const ENDPOINT_SIGNATURE_NAMESPACE: &[u8] = b"OUTBE_RADICLE_ENDPOINT_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainIdentity {
    pub chain_id: u64,
    pub genesis_hash: B256,
}
