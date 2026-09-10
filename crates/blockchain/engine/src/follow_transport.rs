//! Engine-layer transport implementations for the follower.
//!
//! `outbe-consensus` defines the transport seam ([`FinalizedSource`],
//! [`LocalBlockSource`], [`TipSource`]). This module provides the concrete
//! implementations the engine layer can build, because they need the reth node
//! handle (local block reads) and an RPC client (upstream finalized blocks +
//! tip discovery) - neither of which `outbe-consensus` depends on. Both halves
//! are wired: a follower fetches finalized blocks from a validator's
//! `rudis_getFinalization` and verifies them against the epoch committee.
//!
//! * [`RethLocalBlockSource`] - REAL: reads already-imported blocks from the
//!   reth execution DB by hash. Used to serve the marshal's `Request::Block`.
//! * [`UpstreamRpcClient`] - the upstream finalized-block + tip transport: a
//!   jsonrpsee HTTP client. Tip discovery calls `rudis_consensusStatus`;
//!   finalized-block fetch calls `rudis_getFinalization(height)` and decodes the
//!   returned `(finalizationHex, blockHex)` into a [`CertifiedFinalizedBlock`].
//!   The certificate is decoded with the UNBOUNDED committee codec config (a
//!   permissive length upper bound - the same the marshal's archive uses), so
//!   the client does not need the epoch committee size to decode; the marshal
//!   re-verifies the certificate against the actual committee afterwards.

use std::future::Future;
use std::sync::Arc;

use alloy_primitives::B256;
use commonware_codec::Read as _;
use commonware_consensus::types::Height;
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_cryptography::certificate::Scheme as _;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use outbe_consensus::block::ConsensusBlock;
use outbe_consensus::follow::{
    CertifiedFinalizedBlock, FinalizedSource, LocalBlockSource, TipSource,
};
use outbe_consensus::hybrid::HybridScheme;
use outbe_consensus::marshal_types::Finalization;
use outbe_node::OutbeFullNode;
use reth_ethereum::storage::{BlockReader, TransactionVariant};
use tracing::{debug, warn};

/// Reads already-imported blocks from the local reth execution DB by hash.
///
/// The follower imports finalized blocks through the executor (FCU + newPayload),
/// so by the time the marshal asks to backfill a `Request::Block(digest)` the
/// block is in the EL DB. This is the same lookup the validator path's resolver
/// performs against peers, but sourced locally.
#[derive(Clone)]
pub struct RethLocalBlockSource {
    node: OutbeFullNode,
}

impl RethLocalBlockSource {
    pub fn new(node: OutbeFullNode) -> Self {
        Self { node }
    }
}

impl LocalBlockSource for RethLocalBlockSource {
    fn get_block_by_digest(
        &self,
        digest: outbe_consensus::digest::Digest,
    ) -> impl Future<Output = Option<ConsensusBlock>> + Send {
        let node = self.node.clone();
        async move {
            let hash: B256 = digest.0;
            match node
                .provider
                .recovered_block(hash.into(), TransactionVariant::NoHash)
            {
                Ok(Some(recovered)) => {
                    Some(ConsensusBlock::from_sealed(recovered.into_sealed_block()))
                }
                Ok(None) => {
                    debug!(%hash, "local EL has no block for requested digest");
                    None
                }
                Err(error) => {
                    debug!(%hash, %error, "failed reading block from local EL");
                    None
                }
            }
        }
    }
}

/// Minimal view of the upstream's `rudis_consensusStatus` response - we only
/// need the finalized tip for sync progress. Deserializing a subset keeps this
/// independent of the full `ConsensusStatusInfo` shape.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamConsensusStatus {
    last_finalized_block: u64,
}

/// The upstream's `rudis_getFinalization` response (mirrors `FinalizationProof`
/// in `outbe-rpc`): hex of the encoded finalization cert + the encoded block.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamFinalizationProof {
    finalization_hex: String,
    block_hex: String,
}

/// The upstream finalized-block + tip transport: a jsonrpsee HTTP client against
/// an upstream node's `rudis_*` RPC.
///
/// * Tip discovery -> `rudis_consensusStatus.lastFinalizedBlock`.
/// * Finalized-block fetch -> `rudis_getFinalization(height)`, decoded into a
///   [`CertifiedFinalizedBlock`]. The certificate is decoded with the UNBOUNDED
///   committee codec config (a permissive length bound, the same the marshal's
///   archive uses), so the client needs no committee-size knowledge; the marshal
///   re-verifies the cert against the actual epoch committee.
#[derive(Clone)]
pub struct UpstreamRpcClient {
    client: Arc<HttpClient>,
    url: String,
}

impl UpstreamRpcClient {
    /// Build an HTTP client for `url`. Accepts `http://host:port` (or `host:port`,
    /// which is prefixed with `http://`).
    pub fn new(url: &str) -> eyre::Result<Self> {
        let normalized = if url.contains("://") {
            url.to_string()
        } else {
            format!("http://{url}")
        };
        let client = HttpClientBuilder::default()
            .build(&normalized)
            .map_err(|e| {
                eyre::eyre!("failed to build upstream RPC client for {normalized}: {e}")
            })?;
        Ok(Self {
            client: Arc::new(client),
            url: normalized,
        })
    }

    /// Query the upstream's on-chain tribute offer public key
    /// (`TeeRegistry.tributeOfferPublicKey()`, selector `0x1b640a92`). A non-zero
    /// value means the chain is TEE-bootstrapped, so a follower re-executing
    /// offer / enclave-registration txs needs a local enclave holding the offer
    /// key. Read from the UPSTREAM, not the follower's local state: the follower
    /// starts at genesis, where the bootstrap tx that sets this key has not run
    /// yet, so a local read would spuriously report a non-TEE chain.
    pub async fn tribute_offer_public_key(&self) -> eyre::Result<alloy_primitives::B256> {
        let call = serde_json::json!({
            "to": "0x000000000000000000000000000000000000ee0a",
            "data": "0x1b640a92",
        });
        let result: String = self
            .client
            .request("eth_call", rpc_params![call, "latest"])
            .await
            .map_err(|e| eyre::eyre!("upstream eth_call tributeOfferPublicKey failed: {e}"))?;
        let bytes = alloy_primitives::hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| eyre::eyre!("malformed eth_call result from upstream: {e}"))?;
        decode_tribute_offer_public_key(&bytes)
    }
}

fn decode_tribute_offer_public_key(bytes: &[u8]) -> eyre::Result<B256> {
    if bytes.len() != 32 {
        return Err(eyre::eyre!(
            "upstream tributeOfferPublicKey returned {} bytes instead of one ABI word",
            bytes.len()
        ));
    }
    Ok(B256::from_slice(bytes))
}

/// Decode an `rudis_getFinalization` proof into a `CertifiedFinalizedBlock`.
///
/// The certificate is decoded with the unbounded committee config (a permissive
/// upper bound on length). Trust is NOT established here - the marshal verifies
/// the cert against the epoch committee. `None` on any malformed field.
fn decode_finalization_proof(proof: &UpstreamFinalizationProof) -> Option<CertifiedFinalizedBlock> {
    let fin_bytes = alloy_primitives::hex::decode(proof.finalization_hex.trim_start_matches("0x"))
        .inspect_err(|error| debug!(%error, "malformed finalizationHex from upstream"))
        .ok()?;
    let block_bytes = alloy_primitives::hex::decode(proof.block_hex.trim_start_matches("0x"))
        .inspect_err(|error| debug!(%error, "malformed blockHex from upstream"))
        .ok()?;

    let cert_cfg = HybridScheme::<MinSig>::certificate_codec_config_unbounded();
    let mut fin_reader: &[u8] = &fin_bytes;
    let finalization = Finalization::read_cfg(&mut fin_reader, &cert_cfg)
        .inspect_err(|error| debug!(%error, "failed to decode upstream finalization"))
        .ok()?;
    if !fin_reader.is_empty() {
        debug!("trailing bytes after upstream finalization");
        return None;
    }

    let mut block_reader: &[u8] = &block_bytes;
    let block = ConsensusBlock::read_cfg(&mut block_reader, &())
        .inspect_err(|error| debug!(%error, "failed to decode upstream block"))
        .ok()?;
    if !block_reader.is_empty() {
        debug!("trailing bytes after upstream block");
        return None;
    }

    Some(CertifiedFinalizedBlock {
        finalization,
        block,
    })
}

impl FinalizedSource for UpstreamRpcClient {
    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<CertifiedFinalizedBlock>> + Send {
        let client = self.client.clone();
        let url = self.url.clone();
        async move {
            let proof: UpstreamFinalizationProof = match client
                .request("rudis_getFinalization", rpc_params![height.get()])
                .await
            {
                Ok(proof) => proof,
                Err(error) => {
                    // A "not available" upstream answer is expected while the
                    // upstream catches up; downgrade to debug, retry happens via
                    // the driver/marshal.
                    debug!(%url, height = height.get(), %error, "upstream getFinalization failed");
                    return None;
                }
            };
            decode_finalization_proof(&proof)
        }
    }
}

impl TipSource for UpstreamRpcClient {
    fn finalized_tip(&self) -> impl Future<Output = Option<Height>> + Send {
        let client = self.client.clone();
        let url = self.url.clone();
        async move {
            match client
                .request::<UpstreamConsensusStatus, _>("rudis_consensusStatus", rpc_params![])
                .await
            {
                Ok(status) => Some(Height::new(status.last_finalized_block)),
                Err(error) => {
                    warn!(%url, %error, "failed to query upstream consensus status (tip)");
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_tribute_offer_public_key;
    use alloy_primitives::B256;

    #[test]
    fn offer_key_rpc_word_is_exactly_32_bytes() {
        let expected = B256::repeat_byte(0x42);
        assert_eq!(
            decode_tribute_offer_public_key(expected.as_slice()).unwrap(),
            expected
        );
        for malformed in [vec![], vec![0x42; 31], vec![0x42; 33]] {
            assert!(decode_tribute_offer_public_key(&malformed).is_err());
        }
    }
}
