//! Block wrapper for Commonware consensus.
//!
//! Wraps Reth's `SealedBlock` so it can be used as a Commonware consensus block.

use alloy_primitives::B256;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Read, Write};
use commonware_consensus::{types::Height, Heightable};
use commonware_cryptography::{Committable, Digestible};
use outbe_primitives::OutbeBlock;
use reth_ethereum::primitives::{AlloyBlockHeader, Block as RethBlockTrait, SealedBlock};
use std::sync::Arc;

use crate::digest::Digest;

/// Consensus-aware block wrapper.
///
/// Wraps a sealed Ethereum block and implements Commonware's consensus traits
/// so blocks can flow through the Simplex engine.
///
/// the inner `SealedBlock` is `Arc`-backed so that cloning a
/// `ConsensusBlock` - which happens on every propose/verify/finalize hop, in the
/// shared block cache, and across mailbox channels - is a cheap refcount bump
/// instead of a full deep block copy. `Clone`/`PartialEq`/`Eq`/`Debug` keep
/// value semantics (`Arc`'s `PartialEq` compares the pointed-to value, and the
/// codec encodes the inner block), so this is observationally identical to the
/// previous by-value wrapper - only cheaper. A genuine owned `SealedBlock` is
/// still recoverable via [`ConsensusBlock::into_inner`] (which clones only when
/// the `Arc` is shared).
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct ConsensusBlock(Arc<SealedBlock<OutbeBlock>>);

impl ConsensusBlock {
    /// Create from a Reth sealed block.
    pub fn from_sealed(block: SealedBlock<OutbeBlock>) -> Self {
        Self(Arc::new(block))
    }

    /// Unwrap into the inner sealed block.
    ///
    /// Returns the owned `SealedBlock` without copying when this is the sole
    /// holder of the `Arc`; otherwise clones the inner block once (the same deep
    /// copy the old by-value wrapper always paid).
    pub fn into_inner(self) -> SealedBlock<OutbeBlock> {
        Arc::try_unwrap(self.0).unwrap_or_else(|arc| (*arc).clone())
    }

    /// Block hash.
    pub fn block_hash(&self) -> B256 {
        self.0.hash()
    }

    /// Block number.
    pub fn number(&self) -> u64 {
        self.0.number()
    }

    /// Block timestamp.
    pub fn timestamp(&self) -> u64 {
        self.0.timestamp()
    }

    /// Block timestamp in milliseconds.
    pub fn timestamp_millis(&self) -> u64 {
        self.0.header().timestamp_millis()
    }

    /// Parent block hash.
    pub fn parent_hash(&self) -> B256 {
        self.0.parent_hash()
    }

    /// Digest (block hash wrapped).
    pub fn digest(&self) -> Digest {
        Digest(self.block_hash())
    }

    /// Parent digest.
    pub fn parent_digest(&self) -> Digest {
        Digest(self.parent_hash())
    }
}

impl std::ops::Deref for ConsensusBlock {
    type Target = SealedBlock<OutbeBlock>;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

// --- Commonware trait implementations  ---

impl Write for ConsensusBlock {
    fn write(&self, buf: &mut impl BufMut) {
        use alloy_rlp::Encodable as _;
        // Encode the inner SealedBlock explicitly (not the Arc wrapper) so the
        // wire bytes are byte-identical to the pre-Arc wrapper - consensus codec
        // determinism.
        self.0.as_ref().encode(buf);
    }
}

impl Read for ConsensusBlock {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let header = alloy_rlp::Header::decode(&mut buf.chunk()).map_err(|rlp_err| {
            commonware_codec::Error::Wrapped("reading RLP header", rlp_err.into())
        })?;

        if header.length_with_payload() > buf.remaining() {
            return Err(commonware_codec::Error::EndOfBuffer);
        }
        let bytes = buf.copy_to_bytes(header.length_with_payload());

        let inner: OutbeBlock =
            alloy_rlp::Decodable::decode(&mut bytes.as_ref()).map_err(|rlp_err| {
                commonware_codec::Error::Wrapped("reading RLP encoded block", rlp_err.into())
            })?;

        Ok(Self::from_sealed(inner.seal_slow()))
    }
}

impl EncodeSize for ConsensusBlock {
    fn encode_size(&self) -> usize {
        use alloy_rlp::Encodable as _;
        self.0.as_ref().length()
    }
}

impl Committable for ConsensusBlock {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        self.digest()
    }
}

impl Digestible for ConsensusBlock {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        self.digest()
    }
}

impl Heightable for ConsensusBlock {
    fn height(&self) -> Height {
        Height::new(self.number())
    }
}

impl commonware_consensus::Block for ConsensusBlock {
    fn parent(&self) -> Digest {
        self.parent_digest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use commonware_codec::Encode as _;
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::Block;

    fn sample_block(number: u64, extra: &[u8]) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.number = number;
        block.header.extra_data = Bytes::copy_from_slice(extra);
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    /// marshal-2: the marshal genesis anchor is a `ConsensusBlock` whose
    /// commitment the marshal re-derives via THIS codec round-trip (RLP encode
    /// -> RLP decode -> `seal_slow`) and compares in `ensure_genesis_anchor`,
    /// which panics on mismatch at the SECOND boot. A header/extra_data encoding
    /// change that did not round-trip losslessly would compile clean but crash a
    /// restarted node. This pins that `digest() == commitment() == block_hash()`
    /// survives the round-trip, including non-empty `extra_data` (genesis carries
    /// it via `OutbeBlockArtifacts`).
    #[test]
    fn consensus_block_codec_round_trip_preserves_commitment() {
        for (number, extra) in [
            (0u64, b"genesis-anchor".as_slice()),
            (7, b"".as_slice()),
            (12_345, [0xEEu8; 64].as_slice()),
        ] {
            let original = sample_block(number, extra);

            // digest == commitment == sealed block hash.
            assert_eq!(original.digest().0, original.block_hash());
            assert_eq!(original.commitment(), original.digest());

            let encoded = original.encode();
            let mut buf = encoded.as_ref();
            let decoded = ConsensusBlock::read_cfg(&mut buf, &())
                .expect("genesis-anchor ConsensusBlock must RLP round-trip");

            assert_eq!(
                decoded.digest(),
                original.digest(),
                "codec round-trip must preserve digest - marshal ensure_genesis_anchor \
                 compares this commitment and panics on mismatch (second boot)"
            );
            assert_eq!(decoded.commitment(), original.commitment());
            assert_eq!(decoded.block_hash(), original.block_hash());
            assert_eq!(decoded.number(), original.number());
            assert!(
                buf.is_empty(),
                "decode must consume exactly the encoded block bytes"
            );
        }
    }

    /// cloning a `ConsensusBlock` must be a cheap `Arc` refcount bump, not
    /// a deep block copy, while keeping value semantics (equality, digest, and
    /// byte-identical encoding) identical to the previous by-value wrapper.
    #[test]
    fn clone_is_arc_shared_and_preserves_value_semantics() {
        let original = sample_block(42, b"arc-backed");
        assert_eq!(Arc::strong_count(&original.0), 1);

        let cloned = original.clone();
        assert_eq!(
            Arc::strong_count(&original.0),
            2,
            "clone must share the Arc, not deep-copy the block"
        );

        // Value semantics preserved across the shared clone.
        assert_eq!(cloned, original);
        assert_eq!(cloned.digest(), original.digest());
        assert_eq!(
            cloned.encode(),
            original.encode(),
            "encoding is the inner block's RLP, unaffected by Arc backing"
        );

        // into_inner on a shared Arc yields an owned, equal SealedBlock (the one
        // deep copy the old wrapper always paid) and releases the clone's ref.
        let inner = cloned.into_inner();
        assert_eq!(inner.hash(), original.block_hash());
        assert_eq!(
            Arc::strong_count(&original.0),
            1,
            "consuming the clone releases its Arc ref"
        );
    }
}
