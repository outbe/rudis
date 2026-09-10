//! Transport seam for the follower: where finalized blocks come from.
//!
//! The follower never runs consensus and is never admitted to the validators'
//! `authenticated::lookup` P2P network because it has no registered signing key.
//! Instead it pulls already-finalized blocks
//! from an UPSTREAM node over RPC. This module defines the abstract seam so the
//! verification core (marshal + `CommitteeChain` + resolver + driver) can be
//! wired and compiled independently of any concrete RPC client.
//!
//! Two sources are needed by the marshal's gap-repair resolver:
//!
//! * [`FinalizedSource`] - serves `Request::Finalized { height }` from the
//!   upstream: returns the finalization certificate plus the finalized block
//!   for a height. The marshal verifies the certificate itself via its
//!   per-epoch verifier provider (the [`CommitteeChain`](super::CommitteeChain)
//!   provider), so this transport is trusted only to *deliver bytes*, never to
//!   assert finality.
//! * [`LocalBlockSource`] - serves `Request::Block { digest }` from the local
//!   execution layer (a block the follower already imported). No certificate is
//!   involved; the marshal validates the response by commitment.
//!
//! A concrete implementation (jsonrpsee WS/HTTP client against an upstream
//! node's consensus RPC + a reth provider for local blocks) lives in the engine
//! layer, which already depends on jsonrpsee and the reth node handle. Keeping
//! the trait here lets `outbe-consensus` stay free of the RPC stack.

use std::future::Future;

use commonware_codec::Read as _;
use commonware_consensus::types::Height;

use crate::block::ConsensusBlock;
use crate::marshal_types::Finalization;

/// A finalized block together with the finalization certificate that proves it.
///
/// The certificate is NOT trusted by the transport; the marshal re-verifies it
/// against the epoch committee registered by the driver before the block is
/// accepted.
#[derive(Clone)]
pub struct CertifiedFinalizedBlock {
    /// The finalization certificate for this height (committee-bound).
    pub finalization: Finalization,
    /// The finalized consensus block.
    pub block: ConsensusBlock,
}

#[derive(Debug, thiserror::Error)]
pub enum PublicFinalizedBlockDecodeError {
    #[error("invalid Commonware finalization bytes: {0}")]
    Finalization(String),
    #[error("trailing bytes after Commonware finalization")]
    TrailingFinalization,
    #[error("invalid finalized consensus block bytes: {0}")]
    Block(String),
    #[error("trailing bytes after finalized consensus block")]
    TrailingBlock,
    #[error("finalization committee decode bound must be non-zero")]
    ZeroCommitteeBound,
}

/// Canonically decode the two byte strings exposed by
/// `rudis_getFinalization(height)`.
///
/// Decoding establishes structure only. Callers must still authenticate the
/// certificate against the historical committee before treating it as
/// finality authority.
pub fn decode_public_finalized_block(
    finalization_bytes: &[u8],
    block_bytes: &[u8],
    max_committee_members: usize,
) -> Result<CertifiedFinalizedBlock, PublicFinalizedBlockDecodeError> {
    if max_committee_members == 0 {
        return Err(PublicFinalizedBlockDecodeError::ZeroCommitteeBound);
    }
    let finalization = decode_public_finalization(finalization_bytes, max_committee_members)?;

    let mut block_reader = block_bytes;
    let block = ConsensusBlock::read_cfg(&mut block_reader, &())
        .map_err(|error| PublicFinalizedBlockDecodeError::Block(error.to_string()))?;
    if !block_reader.is_empty() {
        return Err(PublicFinalizedBlockDecodeError::TrailingBlock);
    }
    Ok(CertifiedFinalizedBlock {
        finalization,
        block,
    })
}

/// Canonically decode one public Commonware finalization without trusting it.
/// The caller must verify the returned certificate against the exact historical
/// committee and bind its proposal payload to the authenticated header hash.
pub fn decode_public_finalization(
    finalization_bytes: &[u8],
    max_committee_members: usize,
) -> Result<Finalization, PublicFinalizedBlockDecodeError> {
    if max_committee_members == 0 {
        return Err(PublicFinalizedBlockDecodeError::ZeroCommitteeBound);
    }
    let mut reader = finalization_bytes;
    let finalization = Finalization::read_cfg(&mut reader, &max_committee_members)
        .map_err(|error| PublicFinalizedBlockDecodeError::Finalization(error.to_string()))?;
    if !reader.is_empty() {
        return Err(PublicFinalizedBlockDecodeError::TrailingFinalization);
    }
    Ok(finalization)
}

/// Source of finalized blocks + certificates, by height, from an upstream node.
pub trait FinalizedSource: Clone + Send + Sync + 'static {
    /// Fetch the finalization + block for `height` from the upstream.
    ///
    /// Returns `None` when the upstream does not (yet) have it, or the request
    /// fails; the marshal resolver will retry.
    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<CertifiedFinalizedBlock>> + Send;
}

/// Source of already-imported blocks, by digest, from the local execution layer.
pub trait LocalBlockSource: Clone + Send + Sync + 'static {
    /// Look up a block the follower already imported, by its consensus digest
    /// (== EL block hash). Returns `None` if not present locally.
    fn get_block_by_digest(
        &self,
        digest: crate::digest::Digest,
    ) -> impl Future<Output = Option<ConsensusBlock>> + Send;
}

/// Discovers how far the upstream has finalized, so the follower knows which
/// heights to pull. Backed by the upstream's
/// `rudis_consensusStatus().last_finalized_block`.
pub trait TipSource: Clone + Send + Sync + 'static {
    /// The upstream's latest finalized block height, or `None` if unreachable.
    fn finalized_tip(&self) -> impl Future<Output = Option<Height>> + Send;
}
