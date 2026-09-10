use std::sync::Arc;

use alloy_consensus::BlockHeader as _;
use alloy_rpc_types_engine::PayloadError;
use outbe_primitives::{
    consensus::OUTBE_MAX_EXTRA_DATA_SIZE, payload::validate_outbe_withdrawals, OutbeBlock,
    OutbeExecutionData, OutbeHeader, OutbePayloadAttributes, OutbePayloadTypes, OutbePrimitives,
};
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
use reth_ethereum::primitives::SealedBlock;
use reth_node_builder::{
    rpc::PayloadValidatorBuilder, AddOnsContext, FullNodeComponents, NodeTypes,
};
use reth_payload_primitives::{
    validate_version_specific_fields, EngineApiMessageVersion, EngineObjectValidationError,
    InvalidPayloadAttributesError, NewPayloadError, PayloadOrAttributes,
};

#[derive(Debug, Clone)]
pub struct OutbeEngineValidator<ChainSpec = reth_chainspec::ChainSpec> {
    chain_spec: Arc<ChainSpec>,
}

impl<ChainSpec> OutbeEngineValidator<ChainSpec> {
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }

    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }
}

impl<ChainSpec> PayloadValidator<OutbePayloadTypes> for OutbeEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    type Block = OutbeBlock;

    fn validate_payload_attributes_against_header(
        &self,
        attr: &OutbePayloadAttributes,
        header: &OutbeHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        validate_outbe_withdrawals(attr.inner().withdrawals.as_deref())
            .map_err(|error| InvalidPayloadAttributesError::InvalidParams(Box::new(error)))?;
        if attr.timestamp_millis() <= header.timestamp_millis() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }

    fn convert_payload_to_block(
        &self,
        payload: OutbeExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        validate_outbe_withdrawals(
            payload
                .block
                .body()
                .withdrawals
                .as_ref()
                .map(|withdrawals| withdrawals.0.as_slice()),
        )
        .map_err(NewPayloadError::other)?;
        let block = (*payload.block).clone();
        let extra_data = block.header().extra_data();
        if extra_data.len() > OUTBE_MAX_EXTRA_DATA_SIZE {
            return Err(NewPayloadError::Eth(PayloadError::ExtraData(
                extra_data.clone(),
            )));
        }
        Ok(block)
    }
}

impl<ChainSpec> EngineApiValidator<OutbePayloadTypes> for OutbeEngineValidator<ChainSpec>
where
    ChainSpec: EthChainSpec + EthereumHardforks + 'static,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, OutbeExecutionData, OutbePayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_outbe_withdrawals(payload_or_attrs.withdrawals().map(Vec::as_slice))
            .map_err(EngineObjectValidationError::invalid_params)?;
        validate_version_specific_fields(self.chain_spec(), version, payload_or_attrs)
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &OutbePayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_outbe_withdrawals(attributes.inner().withdrawals.as_deref())
            .map_err(EngineObjectValidationError::invalid_params)?;
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<OutbeExecutionData, OutbePayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct OutbeEngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for OutbeEngineValidatorBuilder
where
    Types: NodeTypes<
        ChainSpec: Hardforks + EthereumHardforks + Clone + 'static,
        Payload = OutbePayloadTypes,
        Primitives = OutbePrimitives,
    >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = OutbeEngineValidator<Types::ChainSpec>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(OutbeEngineValidator::new(ctx.config.chain.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_consensus::{constants::EMPTY_TRANSACTIONS, BlockBody, BlockHeader as _, Header};
    use alloy_eips::eip4895::{Withdrawal, Withdrawals};
    use alloy_primitives::{Bloom, Bytes, B256, U256};
    use alloy_rpc_types_engine::{PayloadAttributes as EthPayloadAttributes, PayloadError};
    use outbe_primitives::{OutbeExecutionData, OutbeHeader, OutbePayloadAttributes};
    use reth_chainspec::MAINNET;
    use reth_engine_primitives::{EngineApiValidator, PayloadValidator};
    use reth_payload_primitives::{
        EngineApiMessageVersion, InvalidPayloadAttributesError, PayloadOrAttributes,
    };
    use reth_primitives_traits::Block as _;

    use super::{OutbeEngineValidator, OUTBE_MAX_EXTRA_DATA_SIZE};

    fn payload_with_extra_data_len(extra_len: usize) -> OutbeExecutionData {
        payload_with_extra_data_and_withdrawals(extra_len, None)
    }

    fn payload_with_extra_data_and_withdrawals(
        extra_len: usize,
        withdrawals: Option<Vec<Withdrawal>>,
    ) -> OutbeExecutionData {
        let block = outbe_primitives::OutbeBlock {
            header: OutbeHeader::new(Header {
                parent_hash: B256::ZERO,
                beneficiary: alloy_primitives::Address::ZERO,
                state_root: B256::ZERO,
                transactions_root: EMPTY_TRANSACTIONS,
                receipts_root: B256::ZERO,
                withdrawals_root: None,
                logs_bloom: Bloom::default(),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1,
                mix_hash: B256::ZERO,
                base_fee_per_gas: Some(1),
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_hash: None,
                block_access_list_hash: None,
                slot_number: None,
                extra_data: Bytes::from(vec![0xAA; extra_len]),
                ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
                difficulty: U256::ZERO,
                nonce: Default::default(),
            }),
            body: BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: withdrawals.map(Withdrawals::new),
            },
        };

        OutbeExecutionData {
            block: Arc::new(block.seal_slow()),
            execution_read_budget: None,
        }
    }

    fn header_with_timestamp(timestamp_seconds: u64, timestamp_millis_part: u64) -> OutbeHeader {
        let extra_data = outbe_primitives::reshare_artifact::encode_outbe_block_artifacts(
            &outbe_primitives::reshare_artifact::OutbeBlockArtifacts {
                timestamp_millis_part,
                late_finalize_credits: None,
                ..Default::default()
            },
        )
        .expect("encode artifacts");
        OutbeHeader::new(Header {
            timestamp: timestamp_seconds,
            extra_data,
            ..Header::default()
        })
    }

    #[test]
    fn accepts_extra_data_above_ethereum_limit() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let payload = payload_with_extra_data_len(147);

        let block = validator.convert_payload_to_block(payload).unwrap();
        assert_eq!(block.header().extra_data().len(), 147);
    }

    #[test]
    fn rejects_extra_data_above_outbe_limit() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let payload = payload_with_extra_data_len(OUTBE_MAX_EXTRA_DATA_SIZE + 1);

        let err = validator.convert_payload_to_block(payload).unwrap_err();
        assert!(matches!(
            err,
            reth_payload_primitives::NewPayloadError::Eth(PayloadError::ExtraData(_))
        ));
    }

    #[test]
    fn rejects_non_empty_withdrawals_in_execution_payload() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let payload = payload_with_extra_data_and_withdrawals(
            0,
            Some(vec![Withdrawal {
                index: 0,
                validator_index: 0,
                address: alloy_primitives::Address::ZERO,
                amount: 1_000,
            }]),
        );

        assert!(matches!(
            validator.convert_payload_to_block(payload).unwrap_err(),
            reth_payload_primitives::NewPayloadError::Other(_)
        ));
    }

    #[test]
    fn validates_payload_attributes_against_header_millis() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let header = header_with_timestamp(100, 900);
        let valid_attrs = OutbePayloadAttributes::new(
            alloy_primitives::Address::ZERO,
            100_901,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            None,
        );
        let invalid_attrs = OutbePayloadAttributes::new(
            alloy_primitives::Address::ZERO,
            100_900,
            B256::ZERO,
            None,
            Bytes::new(),
            None,
            None,
        );

        validator
            .validate_payload_attributes_against_header(&valid_attrs, &header)
            .unwrap();
        assert!(matches!(
            validator
                .validate_payload_attributes_against_header(&invalid_attrs, &header)
                .unwrap_err(),
            InvalidPayloadAttributesError::InvalidTimestamp
        ));
    }

    #[test]
    fn rejects_non_empty_withdrawals_in_payload_attributes() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let header = header_with_timestamp(100, 900);
        let attributes = OutbePayloadAttributes::from(EthPayloadAttributes {
            timestamp: 101,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: alloy_primitives::Address::ZERO,
            withdrawals: Some(vec![Withdrawal {
                index: 0,
                validator_index: 0,
                address: alloy_primitives::Address::ZERO,
                amount: 1_000,
            }]),
            parent_beacon_block_root: None,
            slot_number: None,
        });

        assert!(matches!(
            validator
                .validate_payload_attributes_against_header(&attributes, &header)
                .unwrap_err(),
            InvalidPayloadAttributesError::InvalidParams(_)
        ));
    }

    #[test]
    fn rejects_non_empty_withdrawals_in_well_formed_engine_attributes() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let attributes = OutbePayloadAttributes::from(EthPayloadAttributes {
            timestamp: 2_000_000_000,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: alloy_primitives::Address::ZERO,
            withdrawals: Some(vec![Withdrawal {
                index: 0,
                validator_index: 0,
                address: alloy_primitives::Address::ZERO,
                amount: 1,
            }]),
            parent_beacon_block_root: Some(B256::ZERO),
            slot_number: None,
        });

        assert!(matches!(
            validator
                .ensure_well_formed_attributes(EngineApiMessageVersion::V3, &attributes)
                .unwrap_err(),
            reth_payload_primitives::EngineObjectValidationError::InvalidParams(_)
        ));
    }

    #[test]
    fn version_specific_validation_rejects_non_empty_withdrawals() {
        let validator = OutbeEngineValidator::new(MAINNET.clone());
        let attributes = OutbePayloadAttributes::from(EthPayloadAttributes {
            timestamp: 2_000_000_000,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: alloy_primitives::Address::ZERO,
            withdrawals: Some(vec![Withdrawal {
                index: 0,
                validator_index: 0,
                address: alloy_primitives::Address::ZERO,
                amount: u64::MAX,
            }]),
            parent_beacon_block_root: Some(B256::ZERO),
            slot_number: None,
        });

        assert!(matches!(
            validator
                .validate_version_specific_fields(
                    EngineApiMessageVersion::V3,
                    PayloadOrAttributes::PayloadAttributes(&attributes),
                )
                .unwrap_err(),
            reth_payload_primitives::EngineObjectValidationError::InvalidParams(_)
        ));
    }
}
