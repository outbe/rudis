use std::sync::Arc;

use alloy_eips::eip7685::Requests;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rlp::Encodable as _;
use alloy_rpc_types_engine::{PayloadAttributes as EthPayloadAttributes, PayloadId};
use alloy_rpc_types_eth::Withdrawal;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_builder::PayloadTypes;
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{AlloyBlockHeader as _, BlockBody as _, SealedBlock};
use serde::{Deserialize, Serialize};

use crate::{
    consensus_metadata::CertifiedParentAccountingMetadata, projection::ExecutionReadBudget,
    OutbeBlock, OutbeHeader, OutbePrimitives,
};

/// Outbe does not use EIP-4895 withdrawals as a native-COEN issuance path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("non-empty EIP-4895 withdrawals are unsupported on Outbe")]
pub struct NonEmptyWithdrawalsError;

/// Accepts an absent or empty EIP-4895 list and rejects every non-empty list.
///
/// The Ethereum wire shape remains intact; callers adapt this protocol verdict
/// into their local Engine, consensus, or execution error domain.
pub fn validate_outbe_withdrawals(
    withdrawals: Option<&[Withdrawal]>,
) -> Result<(), NonEmptyWithdrawalsError> {
    match withdrawals {
        Some(withdrawals) if !withdrawals.is_empty() => Err(NonEmptyWithdrawalsError),
        _ => Ok(()),
    }
}

/// RPC payload attributes extended with an encoded millisecond timestamp remainder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutbePayloadAttributes {
    #[serde(flatten)]
    inner: EthPayloadAttributes,
    timestamp_millis_part: u64,
    extra_data: Bytes,
    parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
    proposer_evm_address: Option<Address>,
    #[serde(skip)]
    execution_read_budget: Option<ExecutionReadBudget>,
}

impl OutbePayloadAttributes {
    pub fn new(
        suggested_fee_recipient: Address,
        timestamp_millis: u64,
        prev_randao: B256,
        parent_beacon_block_root: Option<B256>,
        extra_data: Bytes,
        parent_consensus_metadata: Option<CertifiedParentAccountingMetadata>,
        proposer_evm_address: Option<Address>,
    ) -> Self {
        let (timestamp, timestamp_millis_part) =
            OutbeHeader::split_timestamp_millis(timestamp_millis);
        Self {
            inner: EthPayloadAttributes {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals: Some(Vec::new()),
                parent_beacon_block_root,
                slot_number: None,
            },
            timestamp_millis_part,
            extra_data,
            parent_consensus_metadata,
            proposer_evm_address,
            execution_read_budget: None,
        }
    }

    pub const fn timestamp_millis_part(&self) -> u64 {
        self.timestamp_millis_part
    }

    pub fn timestamp_millis(&self) -> u64 {
        self.inner
            .timestamp
            .saturating_mul(1000)
            .saturating_add(self.timestamp_millis_part)
    }

    pub const fn inner(&self) -> &EthPayloadAttributes {
        &self.inner
    }

    pub const fn extra_data(&self) -> &Bytes {
        &self.extra_data
    }

    pub const fn parent_consensus_metadata(&self) -> Option<&CertifiedParentAccountingMetadata> {
        self.parent_consensus_metadata.as_ref()
    }

    pub const fn proposer_evm_address(&self) -> Option<Address> {
        self.proposer_evm_address
    }

    /// Installs the caller's remaining local execution-read budget.
    #[must_use]
    pub fn with_execution_read_budget(mut self, budget: ExecutionReadBudget) -> Self {
        self.execution_read_budget = Some(budget);
        self
    }

    /// Returns local-only execution metadata excluded from payload identity and serialization.
    pub const fn execution_read_budget(&self) -> Option<&ExecutionReadBudget> {
        self.execution_read_budget.as_ref()
    }
}

impl From<EthPayloadAttributes> for OutbePayloadAttributes {
    fn from(inner: EthPayloadAttributes) -> Self {
        Self {
            inner,
            timestamp_millis_part: 0,
            extra_data: Bytes::new(),
            parent_consensus_metadata: None,
            proposer_evm_address: None,
            execution_read_budget: None,
        }
    }
}

impl reth_node_builder::PayloadAttributes for OutbePayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        outbe_payload_id(parent_hash, self)
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals.as_ref()
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number
    }
}

#[derive(Debug, Clone)]
pub struct OutbeBuiltPayload {
    inner: EthBuiltPayload<OutbePrimitives>,
    executed_block: Option<BuiltPayloadExecutedBlock<OutbePrimitives>>,
}

impl OutbeBuiltPayload {
    pub const fn new(
        inner: EthBuiltPayload<OutbePrimitives>,
        executed_block: Option<BuiltPayloadExecutedBlock<OutbePrimitives>>,
    ) -> Self {
        Self {
            inner,
            executed_block,
        }
    }
}

impl BuiltPayload for OutbeBuiltPayload {
    type Primitives = OutbePrimitives;

    fn block(&self) -> &SealedBlock<OutbeBlock> {
        self.inner.block()
    }

    fn fees(&self) -> U256 {
        self.inner.fees()
    }

    fn executed_block(&self) -> Option<BuiltPayloadExecutedBlock<Self::Primitives>> {
        self.executed_block.clone()
    }

    fn requests(&self) -> Option<Requests> {
        self.inner.requests()
    }
}

/// In-process execution payload. It intentionally carries the full sealed
/// Outbe block so `timestamp_millis_part` never gets lost through Ethereum
/// Engine API payload conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutbeExecutionData {
    pub block: Arc<SealedBlock<OutbeBlock>>,
    /// Local-only request budget; it is never encoded into block bytes.
    #[serde(skip)]
    pub execution_read_budget: Option<ExecutionReadBudget>,
}

impl OutbeExecutionData {
    #[must_use]
    pub fn new(block: Arc<SealedBlock<OutbeBlock>>) -> Self {
        Self {
            block,
            execution_read_budget: None,
        }
    }

    #[must_use]
    pub fn with_execution_read_budget(mut self, budget: ExecutionReadBudget) -> Self {
        self.execution_read_budget = Some(budget);
        self
    }
}

impl reth_node_builder::ExecutionPayload for OutbeExecutionData {
    fn parent_hash(&self) -> B256 {
        self.block.parent_hash()
    }

    fn block_hash(&self) -> B256 {
        self.block.hash()
    }

    fn block_number(&self) -> u64 {
        self.block.number()
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.block
            .body()
            .withdrawals
            .as_ref()
            .map(|withdrawals| &withdrawals.0)
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.block.parent_beacon_block_root()
    }

    fn timestamp(&self) -> u64 {
        self.block.timestamp()
    }

    fn transaction_count(&self) -> usize {
        self.block.body().transaction_count()
    }

    fn gas_used(&self) -> u64 {
        self.block.gas_used()
    }

    fn gas_limit(&self) -> u64 {
        self.block.gas_limit()
    }

    fn block_access_list(&self) -> Option<&alloy_primitives::Bytes> {
        None
    }

    fn slot_number(&self) -> Option<u64> {
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OutbePayloadTypes;

impl PayloadTypes for OutbePayloadTypes {
    type ExecutionData = OutbeExecutionData;
    type BuiltPayload = OutbeBuiltPayload;
    type PayloadAttributes = OutbePayloadAttributes;

    fn block_to_payload(block: SealedBlock<OutbeBlock>) -> Self::ExecutionData {
        Self::ExecutionData::new(Arc::new(block))
    }
}

fn outbe_payload_id(parent: &B256, attributes: &OutbePayloadAttributes) -> PayloadId {
    use alloy_primitives::B64;
    use ring::digest::{Context, SHA256};

    let mut hasher = Context::new(&SHA256);
    hasher.update(parent.as_slice());
    hasher.update(&attributes.inner.timestamp.to_be_bytes());
    hasher.update(&attributes.timestamp_millis_part.to_be_bytes());
    hasher.update(attributes.inner.prev_randao.as_slice());
    hasher.update(attributes.inner.suggested_fee_recipient.as_slice());
    hasher.update(&(attributes.extra_data.len() as u64).to_be_bytes());
    hasher.update(attributes.extra_data.as_ref());
    match attributes.proposer_evm_address {
        Some(address) => {
            hasher.update(&[1]);
            hasher.update(address.as_slice());
        }
        None => hasher.update(&[0]),
    }
    match &attributes.parent_consensus_metadata {
        Some(metadata) => match metadata.encode() {
            Ok(encoded) => {
                hasher.update(&[1]);
                hasher.update(&(encoded.len() as u64).to_be_bytes());
                hasher.update(encoded.as_ref());
            }
            Err(error) => {
                // `payload_id` cannot return a fallible result through Reth's
                // trait. Hash the deterministic error text instead of
                // panicking; valid consensus-produced metadata always takes
                // the `Ok` branch.
                let error = error.to_string();
                hasher.update(&[0xFF]);
                hasher.update(&(error.len() as u64).to_be_bytes());
                hasher.update(error.as_bytes());
            }
        },
        None => hasher.update(&[0]),
    }
    if let Some(withdrawals) = &attributes.inner.withdrawals {
        let mut buf = Vec::new();
        withdrawals.encode(&mut buf);
        hasher.update(&buf);
    }
    if let Some(root) = attributes.inner.parent_beacon_block_root {
        hasher.update(root.as_slice());
    }
    if let Some(slot) = attributes.inner.slot_number {
        hasher.update(&slot.to_be_bytes());
    }

    let digest = hasher.finish();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_ref()[..8]);
    PayloadId(B64::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_payload_primitives::PayloadAttributes as _;

    fn sample_metadata() -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number: 7,
            finalized_block_hash: B256::repeat_byte(0x77),
            finalized_epoch: 1,
            finalized_view: 9,
            parent_view: 8,
            ordered_committee: vec![Address::repeat_byte(0x11)],
            signer_bitmap: vec![1],
            proof: Bytes::from_static(b"cert"),
            committee_set_hash: B256::repeat_byte(0x33),
            vrf_material_version: 1,
            vrf_group_public_key_hash: B256::repeat_byte(0x44),
            proof_kind: crate::consensus_metadata::ParentParticipationProof::Finalization,
            // V2 contract requires `missed_proposers` to be empty.
            missed_proposers: Vec::new(),
        }
    }

    #[test]
    fn payload_attributes_split_millis() {
        let attrs = OutbePayloadAttributes::new(
            Address::ZERO,
            42_123,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            None,
        );
        assert_eq!(attrs.timestamp(), 42);
        assert_eq!(attrs.timestamp_millis_part(), 123);
        assert_eq!(attrs.timestamp_millis(), 42_123);
    }

    #[test]
    fn outbe_withdrawals_allow_only_absent_or_empty_lists() {
        assert_eq!(validate_outbe_withdrawals(None), Ok(()));

        let empty: [Withdrawal; 0] = [];
        assert_eq!(validate_outbe_withdrawals(Some(&empty)), Ok(()));

        for amount in [0, 1, 1_000, u64::MAX] {
            let withdrawals = [Withdrawal {
                index: 0,
                validator_index: 0,
                address: Address::ZERO,
                amount,
            }];
            assert_eq!(
                validate_outbe_withdrawals(Some(&withdrawals)),
                Err(NonEmptyWithdrawalsError),
                "amount {amount} must not affect the non-empty-list verdict"
            );
        }
    }

    #[test]
    fn payload_id_changes_with_millis_and_extra_data() {
        let parent = B256::repeat_byte(0x11);
        let base = OutbePayloadAttributes::new(
            Address::ZERO,
            42_123,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            None,
        );
        let different_millis = OutbePayloadAttributes::new(
            Address::ZERO,
            42_124,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            None,
        );
        let different_extra = OutbePayloadAttributes::new(
            Address::ZERO,
            42_123,
            B256::ZERO,
            None,
            Bytes::from_static(b"dkg"),
            None,
            None,
        );

        assert_ne!(
            base.payload_id(&parent),
            different_millis.payload_id(&parent)
        );
        assert_ne!(
            base.payload_id(&parent),
            different_extra.payload_id(&parent)
        );
    }

    #[test]
    fn payload_id_changes_with_parent_metadata_and_proposer() {
        let parent = B256::repeat_byte(0x11);
        let base = OutbePayloadAttributes::new(
            Address::ZERO,
            42_123,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            None,
        );
        let with_metadata = OutbePayloadAttributes::new(
            Address::ZERO,
            42_123,
            B256::ZERO,
            None,
            Bytes::new(),
            Some(sample_metadata()),
            None,
        );
        let with_proposer = OutbePayloadAttributes::new(
            Address::ZERO,
            42_123,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            Some(Address::repeat_byte(0x33)),
        );

        assert_ne!(base.payload_id(&parent), with_metadata.payload_id(&parent));
        assert_ne!(base.payload_id(&parent), with_proposer.payload_id(&parent));
    }

    #[test]
    fn payload_attributes_json_roundtrip_with_parent_metadata_and_proposer() {
        let attrs = OutbePayloadAttributes::new(
            Address::repeat_byte(0x44),
            42_123,
            B256::repeat_byte(0x55),
            Some(B256::repeat_byte(0x66)),
            Bytes::from_static(b"extra"),
            Some(sample_metadata()),
            Some(Address::repeat_byte(0x33)),
        );
        let encoded = serde_json::to_string(&attrs).expect("payload attrs serialize");
        let decoded: OutbePayloadAttributes =
            serde_json::from_str(&encoded).expect("payload attrs deserialize");

        assert_eq!(decoded.timestamp_millis(), attrs.timestamp_millis());
        assert_eq!(decoded.extra_data(), attrs.extra_data());
        assert_eq!(
            decoded.parent_consensus_metadata(),
            attrs.parent_consensus_metadata()
        );
        assert_eq!(decoded.proposer_evm_address(), attrs.proposer_evm_address());
    }
}
