//! Consensus configuration constants.

use std::time::Duration;

/// Chain-bound consensus namespace source of truth lives in
/// [`crate::proof::constants`] so the signer (this crate) and the deterministic
/// V2 verifier read the identical chain-bound bytes. Re-exported here for the
/// historical `config::*` call sites.
///
/// `outbe_app_namespace()` returns `b"outbe" || chain_id_be`; the chain id is
/// installed once at startup via `init_consensus_chain_id`.
pub use crate::proof::constants::{
    init_consensus_chain_id, outbe_app_namespace, simplex_namespace,
};

/// Channel identifiers for Commonware P2P.
pub const VOTES_CHANNEL: u64 = 0;
pub const CERTIFICATES_CHANNEL: u64 = 1;
pub const RESOLVER_CHANNEL: u64 = 2;
/// P2P channel for block dissemination via buffered broadcast engine.
pub const BROADCAST_CHANNEL: u64 = 3;
/// P2P channel for marshal's resolver (on-demand block resolution / backfill).
pub const MARSHAL_CHANNEL: u64 = 4;
/// P2P channel for DKG ceremony messages.
pub const DKG_CHANNEL: u64 = 5;
/// P2P channel for the one-time TEE bootstrap coordination (registration +
/// signature exchange), run once at startup like the DKG.
pub const TEE_BOOTSTRAP_CHANNEL: u64 = 6;
/// P2P channel for the one-time TEE DKG ceremony (enclave identity exchange +
/// dealer/player gossip + offer-key partial-signature exchange), run once at
/// startup to derive the shared tribute offer key. Distinct from the consensus
/// DKG channel (5) and the TEE bootstrap channel (6).
pub const TEE_DKG_CHANNEL: u64 = 7;
/// Signed Radicle endpoint request/response channel.
pub const RADICLE_ENDPOINT_CHANNEL: u64 = 8;
/// Per-peer signed Radicle endpoint messages accepted per second.
pub const RADICLE_ENDPOINT_CHANNEL_QUOTA: u32 = 32;
/// Maximum extra_data size in block headers (bytes).
/// Enough for 128-validator participation bitmap (23 bytes) with room to grow.
pub const MAX_EXTRA_DATA_SIZE: usize = 256;

/// Default timeouts for Simplex consensus.
///
/// These re-export the single source of truth in [`crate::timing`] so the values
/// (and the gas<->consensus-timeout contract) are documented in one place. The
/// live values come from `genesis.json` with these as fallbacks; there is no CLI
/// override. `DEFAULT_PROPOSAL_TIMEOUT_MS` == `timing::DEFAULT_LEADER_TIMEOUT_MS`
/// (leader window); `DEFAULT_NOTARIZATION_TIMEOUT_MS` ==
/// `timing::DEFAULT_CERTIFICATION_TIMEOUT_MS` (certification window).
pub const DEFAULT_PROPOSAL_TIMEOUT_MS: u64 = crate::timing::DEFAULT_LEADER_TIMEOUT_MS;
pub const DEFAULT_NOTARIZATION_TIMEOUT_MS: u64 = crate::timing::DEFAULT_CERTIFICATION_TIMEOUT_MS;
pub const DEFAULT_PROPOSAL_TIMEOUT: Duration = Duration::from_millis(DEFAULT_PROPOSAL_TIMEOUT_MS);
pub const DEFAULT_NOTARIZATION_TIMEOUT: Duration =
    Duration::from_millis(DEFAULT_NOTARIZATION_TIMEOUT_MS);
pub const DEFAULT_NULLIFY_REBROADCAST: Duration = Duration::from_secs(10);
pub const DEFAULT_PEER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_FCU_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const EXECUTION_WATCHDOG_INTERVAL: Duration = Duration::from_secs(30);
pub const EXECUTION_WATCHDOG_GRACE: Duration = Duration::from_secs(30);
pub const EXECUTION_WATCHDOG_LAG_BLOCKS: u64 = 30;
pub const EXECUTION_WATCHDOG_STARTUP_GRACE_SEC: u64 = 120;
pub const STARTUP_GENESIS_FORMATION_PROBE_INTERVAL: Duration = Duration::from_secs(1);
pub const STARTUP_GENESIS_FORMATION_PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Time to give the payload builder to execute transactions before resolving.
/// The production default is 200ms.
pub const DEFAULT_PAYLOAD_RESOLVE_TIME: Duration = Duration::from_millis(200);

/// Minimum time before sending a proposal (keeps block times stable).
/// The production default is 450ms.
pub const DEFAULT_PAYLOAD_RETURN_TIME: Duration = Duration::from_millis(450);

/// Maximum P2P message size (2 MB - enough for max block + overhead).
pub const MAX_P2P_MESSAGE_SIZE: u32 = 2 * 1024 * 1024;
/// Internal mailbox size for consensus engine actors.
pub const ENGINE_MAILBOX_SIZE: usize = 256;
/// Channel message backlog for P2P channels.
pub const CHANNEL_BACKLOG: usize = 16_384;

/// Default epoch length in blocks, used when genesis.json does not specify
/// `config.epochLengthBlocks`. ~1 hour at a ~3s block - the cadence for DKG
/// reshare, active-set rotation, and the per-epoch slash-counter reset. A felony
/// threshold must stay below this (see `outbe_slashindicator`). The DKG
/// prepare/grace windows below are lookback/fallback bounds and stay < this epoch;
/// the operational windows come from `config.dkg{Prepare,Grace}*` in genesis.
pub const DEFAULT_EPOCH_LENGTH_BLOCKS: u32 = 1_200;

/// Activity timeout in views (track this many behind finalized tip).
pub const ACTIVITY_TIMEOUT: u32 = 1000;
/// Skip timeout in views (skip lazy leader after this many inactive views).
pub const SKIP_TIMEOUT: u32 = 5;
/// Number of concurrent certificate fetch requests.
pub const FETCH_CONCURRENT: usize = 3;

/// Default DKG prepare window before planned activation (~10 minutes at ~1s/block).
pub const DEFAULT_DKG_PREPARE_WINDOW_BLOCKS: u64 = 600;
/// Default late activation grace window after planned activation.
pub const DEFAULT_DKG_ACTIVATION_GRACE_BLOCKS: u64 = 600;

/// Replay buffer size for journal (1 MB).
pub const REPLAY_BUFFER: usize = 1024 * 1024;
/// Write buffer size for journal (64 KB).
pub const WRITE_BUFFER: usize = 64 * 1024;
/// Page cache size for journal (32 MB).
pub const PAGE_CACHE_SIZE: usize = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Marshal block-resolution timing
//
// Read cross-module by the application handler, finalization actor, and the
// verify / epoch-boundary resolution paths - so they live here rather than
// inside the handler implementation module.
// ---------------------------------------------------------------------------

/// Maximum retry attempts for marshal block resolution before structured application failure.
pub const FINALIZE_MAX_RETRIES: u32 = 5;
/// Delay between retry attempts for marshal block resolution.
pub const FINALIZE_RETRY_DELAY: Duration = Duration::from_secs(2);
/// Maximum time to wait for marshal block resolution during verify.
pub const VERIFY_RESOLUTION_TIMEOUT: Duration = DEFAULT_PEER_RESPONSE_TIMEOUT;
/// Maximum time to wait for marshal parent resolution during proposal.
pub const PROPOSE_RESOLUTION_TIMEOUT: Duration = DEFAULT_PEER_RESPONSE_TIMEOUT;
/// Per-attempt time budget for marshal block resolution during finalization.
///
/// Without this bound, a `subscribe_by_digest` waiter that never completes can
/// wedge the application handler's serial event loop, blocking propose/verify
/// indefinitely (see `retry_with_backoff` comment for the wedge mechanism).
/// Exhaustion is surfaced as a structured application failure, not a direct
/// process kill from inside the handler.
pub const FINALIZE_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Marshal storage constants used by Outbe production nodes
// ---------------------------------------------------------------------------

/// Items per section in immutable archive.
pub const IMMUTABLE_ITEMS_PER_SECTION: u64 = 262_144;
/// Items per section in prunable cache.
pub const PRUNABLE_ITEMS_PER_SECTION: u64 = 4_096;
/// Freezer table resize frequency.
pub const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
/// Freezer table resize chunk size (~3 MB).
pub const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 1 << 16;
/// Freezer table initial size (~2 MB).
pub const FREEZER_TABLE_INITIAL_SIZE: u32 = 1 << 21;
/// Freezer value target size (1 GB).
pub const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024;
/// Freezer value compression level (zstd level 3).
pub const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);
/// Marshal replay buffer size (8 MB).
pub const MARSHAL_REPLAY_BUFFER: usize = 8 * 1024 * 1024;
/// Marshal write buffer size (1 MB).
pub const MARSHAL_WRITE_BUFFER: usize = 1024 * 1024;
/// Marshal max repair (pending block backfill count).
pub const MAX_REPAIR: usize = 20;
/// Marshal max pending acks (1 = sequential block delivery).
pub const MAX_PENDING_ACKS: usize = 1;
/// Broadcast engine deque size per peer.
pub const BROADCAST_DEQUE_SIZE: usize = 64;
/// Marshal view retention timeout multiplier.
pub const VIEW_RETENTION_MULTIPLIER: u64 = 10;

#[cfg(test)]
mod size_cap_tests {
    use super::MAX_P2P_MESSAGE_SIZE;
    use outbe_primitives::consensus::OUTBE_MAX_BLOCK_SIZE;

    /// The block-size cap MUST stay below the P2P message cap, with margin for
    /// the message envelope and the marshal's `(notarization, block)` co-send.
    #[test]
    fn max_block_size_fits_under_p2p_message_cap() {
        assert!(
            OUTBE_MAX_BLOCK_SIZE < MAX_P2P_MESSAGE_SIZE as usize,
            "OUTBE_MAX_BLOCK_SIZE ({OUTBE_MAX_BLOCK_SIZE}) must be < MAX_P2P_MESSAGE_SIZE ({MAX_P2P_MESSAGE_SIZE})"
        );
        assert!(
            MAX_P2P_MESSAGE_SIZE as usize - OUTBE_MAX_BLOCK_SIZE >= 64 * 1024,
            "reserve >= 64 KiB for envelope + certificate"
        );
    }
}
