use alloy_consensus::{BlockHeader, Header, Sealable};
use alloy_primitives::{keccak256, Address, BlockNumber, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::{Decodable, Encodable};
use reth_primitives_traits::{InMemorySize, NodePrimitives};

use crate::reshare_artifact::decode_outbe_block_artifacts;

/// Outbe block header.
///
/// Layout is **byte-for-byte identical** to a standard Ethereum header so
/// `keccak256(rlp(OutbeHeader)) == keccak256(rlp(Header))`. The sub-second
/// part of the consensus timestamp lives inside `header.extra_data` under
/// the `OutbeBlockArtifacts` codec (tag 0x05); see
/// [`Self::timestamp_millis_part`] and [`Self::timestamp_millis`].
///
/// `block.timestamp` (the inner Ethereum field) keeps the usual EVM
/// semantics: seconds since the Unix epoch.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    reth_codecs::Compact,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct OutbeHeader {
    /// Inner Ethereum header. The Outbe wrapper exposes no additional
    /// RLP-encoded fields, which is what makes the hash Ethereum-compatible.
    pub inner: Header,
}

// Manual RLP impls - we derive `Default`, `Compact`, etc. but RLP must
// be byte-for-byte identical to the inner Ethereum `Header`. A blanket
// `RlpEncodable` derive on a single-field struct would still wrap
// `inner` in an outer RLP list, breaking hash compatibility with any
// L1 consumer (kona, op-node, light clients) that recomputes
// `keccak256(rlp(header))`.
impl Encodable for OutbeHeader {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.inner.encode(out);
    }

    fn length(&self) -> usize {
        self.inner.length()
    }
}

impl Decodable for OutbeHeader {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            inner: Header::decode(buf)?,
        })
    }
}

impl OutbeHeader {
    /// Wrap an Ethereum header.
    ///
    /// Sub-second timestamp must already be encoded inside
    /// `inner.extra_data` (via `encode_outbe_block_artifacts`) - this
    /// constructor does not synthesise it.
    pub const fn new(inner: Header) -> Self {
        Self { inner }
    }

    /// Sub-second millisecond portion of the consensus timestamp,
    /// decoded from `extra_data` under tag 0x05. Returns `0` if absent
    /// or if the artifact envelope is missing/unparseable - callers
    /// that require strict validation should decode the artifacts
    /// directly via [`crate::reshare_artifact::decode_outbe_block_artifacts`].
    pub fn timestamp_millis_part(&self) -> u64 {
        decode_outbe_block_artifacts(self.inner.extra_data().as_ref())
            .map(|a| a.timestamp_millis_part)
            .unwrap_or(0)
    }

    /// Returns the full consensus timestamp in milliseconds.
    pub fn timestamp_millis(&self) -> u64 {
        self.inner
            .timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timestamp_millis_part())
    }

    /// Decompose a millisecond timestamp into `(seconds, millis_part)`.
    pub const fn split_timestamp_millis(timestamp_millis: u64) -> (u64, u64) {
        (timestamp_millis / 1000, timestamp_millis % 1000)
    }

    /// Consume this header and return the wrapped Ethereum header.
    pub fn into_inner(self) -> Header {
        self.inner
    }
}

impl AsRef<Self> for OutbeHeader {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl BlockHeader for OutbeHeader {
    fn parent_hash(&self) -> B256 {
        self.inner.parent_hash()
    }

    fn ommers_hash(&self) -> B256 {
        self.inner.ommers_hash()
    }

    fn beneficiary(&self) -> Address {
        self.inner.beneficiary()
    }

    fn state_root(&self) -> B256 {
        self.inner.state_root()
    }

    fn transactions_root(&self) -> B256 {
        self.inner.transactions_root()
    }

    fn receipts_root(&self) -> B256 {
        self.inner.receipts_root()
    }

    fn withdrawals_root(&self) -> Option<B256> {
        self.inner.withdrawals_root()
    }

    fn logs_bloom(&self) -> Bloom {
        self.inner.logs_bloom()
    }

    fn difficulty(&self) -> U256 {
        self.inner.difficulty()
    }

    fn number(&self) -> BlockNumber {
        self.inner.number()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_used(&self) -> u64 {
        self.inner.gas_used()
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn mix_hash(&self) -> Option<B256> {
        self.inner.mix_hash()
    }

    fn nonce(&self) -> Option<B64> {
        self.inner.nonce()
    }

    fn base_fee_per_gas(&self) -> Option<u64> {
        self.inner.base_fee_per_gas()
    }

    fn blob_gas_used(&self) -> Option<u64> {
        self.inner.blob_gas_used()
    }

    fn excess_blob_gas(&self) -> Option<u64> {
        self.inner.excess_blob_gas()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn requests_hash(&self) -> Option<B256> {
        self.inner.requests_hash()
    }

    fn block_access_list_hash(&self) -> Option<B256> {
        self.inner.block_access_list_hash()
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number()
    }

    fn extra_data(&self) -> &Bytes {
        self.inner.extra_data()
    }
}

impl Sealable for OutbeHeader {
    fn hash_slow(&self) -> B256 {
        keccak256(alloy_rlp::encode(self))
    }
}

impl InMemorySize for OutbeHeader {
    fn size(&self) -> usize {
        self.inner.size()
    }
}

impl reth_primitives_traits::BlockHeader for OutbeHeader {}

reth_codecs::impl_compression_for_compact!(OutbeHeader);

impl reth_rpc_traits::FromConsensusHeader<OutbeHeader> for alloy_rpc_types_eth::Header {
    fn from_consensus_header(
        header: reth_primitives_traits::SealedHeader<OutbeHeader>,
        block_size: usize,
    ) -> Self {
        let hash = header.hash();
        let inner = header.into_header().into_inner();
        <Self as reth_rpc_traits::FromConsensusHeader<Header>>::from_consensus_header(
            reth_primitives_traits::SealedHeader::new(inner, hash),
            block_size,
        )
    }
}

impl reth_primitives_traits::header::HeaderMut for OutbeHeader {
    fn set_parent_hash(&mut self, hash: B256) {
        self.inner.set_parent_hash(hash);
    }

    fn set_block_number(&mut self, number: BlockNumber) {
        self.inner.set_block_number(number);
    }

    fn set_timestamp(&mut self, timestamp: u64) {
        self.inner.set_timestamp(timestamp);
    }

    fn set_state_root(&mut self, state_root: B256) {
        self.inner.set_state_root(state_root);
    }

    fn set_difficulty(&mut self, difficulty: U256) {
        self.inner.set_difficulty(difficulty);
    }

    fn set_mix_hash(&mut self, hash: B256) {
        self.inner.set_mix_hash(hash);
    }

    fn set_extra_data(&mut self, extra_data: Bytes) {
        self.inner.set_extra_data(extra_data);
    }

    fn set_parent_beacon_block_root(&mut self, root: Option<B256>) {
        self.inner.set_parent_beacon_block_root(root);
    }
}

pub type OutbeTxEnvelope = reth_ethereum::TransactionSigned;
pub type OutbeTxType = reth_ethereum::TxType;
pub type OutbeReceipt = reth_ethereum::Receipt;
pub type OutbeBlock = alloy_consensus::Block<OutbeTxEnvelope, OutbeHeader>;
pub type OutbeBlockBody = alloy_consensus::BlockBody<OutbeTxEnvelope, OutbeHeader>;

/// Marker type for Outbe node primitives.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct OutbePrimitives;

impl NodePrimitives for OutbePrimitives {
    type Block = OutbeBlock;
    type BlockHeader = OutbeHeader;
    type BlockBody = OutbeBlockBody;
    type SignedTx = OutbeTxEnvelope;
    type Receipt = OutbeReceipt;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reshare_artifact::{encode_outbe_block_artifacts, OutbeBlockArtifacts};

    fn extra_data_with_millis(part: u64) -> Bytes {
        encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            timestamp_millis_part: part,
            late_finalize_credits: None,
            ..Default::default()
        })
        .expect("encode artifacts")
    }

    #[test]
    fn timestamp_millis_combines_seconds_and_part_from_extra_data() {
        let inner = Header {
            timestamp: 42,
            extra_data: extra_data_with_millis(123),
            ..Default::default()
        };
        let header = OutbeHeader::new(inner);
        assert_eq!(header.timestamp_millis_part(), 123);
        assert_eq!(header.timestamp_millis(), 42_123);
    }

    #[test]
    fn timestamp_millis_part_defaults_to_zero_when_absent() {
        let inner = Header {
            timestamp: 7,
            ..Default::default()
        };
        let header = OutbeHeader::new(inner);
        assert_eq!(header.timestamp_millis_part(), 0);
        assert_eq!(header.timestamp_millis(), 7_000);
    }

    #[test]
    fn header_hash_matches_standard_ethereum_hash() {
        // The Outbe wrapper must be a transparent passthrough at the
        // RLP level - same bytes in, same hash out - otherwise external
        // L1 consumers (kona, op-node, light clients) that recompute
        // `keccak256(rlp(header))` will see a mismatch with what the
        // RPC reports.
        let inner = Header {
            timestamp: 42,
            number: 7,
            extra_data: extra_data_with_millis(123),
            ..Default::default()
        };
        let outbe = OutbeHeader::new(inner.clone());
        assert_eq!(outbe.hash_slow(), inner.hash_slow());
    }

    #[test]
    fn hash_changes_when_millis_part_changes_via_extra_data() {
        let inner_a = Header {
            extra_data: extra_data_with_millis(1),
            ..Default::default()
        };
        let inner_b = Header {
            extra_data: extra_data_with_millis(2),
            ..Default::default()
        };
        let a = OutbeHeader::new(inner_a);
        let b = OutbeHeader::new(inner_b);
        assert_ne!(a.hash_slow(), b.hash_slow());
    }

    /// / T6.3 observer compat: an `OutbeHeader` serialised through
    /// our `Encodable` impl must decode through the standard
    /// `alloy_consensus::Header::decode` path (the path an op-node-style
    /// external L1 observer takes) and `keccak256(rlp(header))` must match.
    ///
    /// This guards the EPIC invariant: the on-chain fix added by
    /// the failure-receipt work does not introduce any wire-format change
    /// detectable by external observers.
    #[test]
    fn observer_compat_header_rlp_roundtrip_matches_block_hash() {
        let inner = Header {
            parent_hash: B256::from([0x11u8; 32]),
            beneficiary: Address::from([0x22u8; 20]),
            state_root: B256::from([0x33u8; 32]),
            transactions_root: B256::from([0x44u8; 32]),
            receipts_root: B256::from([0x55u8; 32]),
            logs_bloom: Bloom::from([0x66u8; 256]),
            difficulty: U256::from(7u64),
            number: 241771,
            gas_limit: 30_000_000,
            gas_used: 21_000,
            timestamp: 1778826267,
            extra_data: extra_data_with_millis(344),
            mix_hash: B256::from([0x77u8; 32]),
            nonce: B64::from(8u64.to_be_bytes()),
            ..Default::default()
        };
        let outbe = OutbeHeader::new(inner.clone());
        let outbe_hash = outbe.hash_slow();

        // Serialise via our `Encodable` impl (the path proposer/validator follow).
        let bytes = alloy_rlp::encode(&outbe);

        // Decode the same bytes through the STANDARD `alloy_consensus::Header`
        // path - this is what op-node, light clients, blockchair indexers do.
        let mut slice = bytes.as_slice();
        let decoded = Header::decode(&mut slice)
            .expect("standard Header::decode must accept OutbeHeader bytes");
        assert!(slice.is_empty(), "no trailing bytes after standard decode");

        // The decoded standard header must reproduce the same hash and the
        // same field-by-field content as the inner.
        assert_eq!(decoded, inner);
        assert_eq!(decoded.hash_slow(), outbe_hash);
        // And the bytes-to-hash path also matches:
        assert_eq!(keccak256(&bytes), outbe_hash);
    }
}
