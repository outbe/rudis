//! Verify-side block resolution for the application handler.
//!
//! [`resolve_for_verify`] is the fetch strategy used while verifying a proposal:
//! try the local block cache first, then subscribe to the marshal by digest
//! (falling back to fetch-by-round) under a bounded timeout. Lifted out of
//! `handler.rs` so the strategy - and its cache/marshal/timeout/telemetry
//! shape - reads and tests independently of the verify event loop; it takes the
//! block-cache and marshal seams as explicit parameters instead of `&self`.

use std::time::Instant;

use commonware_consensus::types::Round;
use tracing::debug;

use crate::block::ConsensusBlock;
use crate::config::VERIFY_RESOLUTION_TIMEOUT;
use crate::digest::Digest;
use crate::finalization::block_cache::BlockCache;
use crate::marshal_types::MarshalMailbox;

#[derive(Debug, Clone, Copy)]
pub(crate) enum VerifyResolveError {
    Timeout,
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum VerifyResolveTarget {
    Block,
    Parent,
}

impl VerifyResolveTarget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Parent => "parent",
        }
    }
}

/// Resolve a block needed during verify: local cache first, then marshal by
/// digest (fallback fetch-by-round) under [`VERIFY_RESOLUTION_TIMEOUT`].
pub(crate) async fn resolve_for_verify(
    block_cache: &BlockCache,
    marshal_mailbox: &MarshalMailbox,
    clock: &impl commonware_runtime::Clock,
    round: Round,
    digest: Digest,
    target: VerifyResolveTarget,
) -> Result<ConsensusBlock, VerifyResolveError> {
    let started_at = Instant::now();
    debug!(
        %round,
        digest = %digest.0,
        target = target.as_str(),
        "verify resolve started"
    );
    let cached = block_cache.get(&digest);
    if let Some(block) = cached {
        debug!(
            %round,
            digest = %digest.0,
            target = target.as_str(),
            source = "cache",
            result = "Resolved",
            elapsed_ms = started_at.elapsed().as_millis(),
            "verify resolve finished"
        );
        return Ok(block);
    }

    let marshal = marshal_mailbox.clone();
    let block_future = marshal.subscribe_by_digest(
        digest,
        commonware_consensus::marshal::core::DigestFallback::FetchByRound { round },
    );
    match clock.timeout(VERIFY_RESOLUTION_TIMEOUT, block_future).await {
        Ok(Ok(block)) => {
            debug!(
                %round,
                digest = %digest.0,
                target = target.as_str(),
                source = "marshal",
                result = "Resolved",
                elapsed_ms = started_at.elapsed().as_millis(),
                "verify resolve finished"
            );
            Ok(block)
        }
        Ok(Err(_)) => {
            debug!(
                %round,
                digest = %digest.0,
                target = target.as_str(),
                source = "marshal",
                result = "Unavailable",
                elapsed_ms = started_at.elapsed().as_millis(),
                "verify resolve finished"
            );
            Err(VerifyResolveError::Unavailable)
        }
        Err(_) => {
            debug!(
                %round,
                digest = %digest.0,
                target = target.as_str(),
                source = "marshal",
                result = "Timeout",
                elapsed_ms = started_at.elapsed().as_millis(),
                "verify resolve finished"
            );
            Err(VerifyResolveError::Timeout)
        }
    }
}
