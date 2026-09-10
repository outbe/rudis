use alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE;
use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use outbe_intexfactory::precompile::IIntexFactory;
use outbe_primitives::addresses::INTEX_FACTORY_ADDRESS;
use outbe_primitives::storage::StorageHandle;

use crate::hooks::{
    ZeroFeeAuthorization, ZeroFeeCandidate, ZeroFeeHook, ZeroFeeHookId, ZeroFeePolicyError,
    ZeroFeeTransaction,
};

/// Exact ABI envelope cap for a full batch: selector, four head words, then a
/// 256-leaf array of four-word structs and a 24-hash proof.
pub const MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES: usize =
    4 + 4 * 32 + (32 + 256 * 4 * 32) + (32 + 24 * 32);

/// Only explicit storage ops are metered inside precompiles (reads 100,
/// writes 5000); transfers and events are journal ops outside metering, so a
/// full batch executes in tens of thousands of gas.
pub const MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT: u64 =
    21_000 + 16 * MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES as u64 + 500_000;

/// Public txpool compatibility floor. The executor waives the actual debit
/// only after stateful validator authorization.
pub const MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS: u128 = MIN_PROTOCOL_BASE_FEE as u128;

#[derive(Debug, Clone, Copy)]
pub struct IntexFactoryPayContributorBatchHook;

impl ZeroFeeHook for IntexFactoryPayContributorBatchHook {
    fn id(&self) -> ZeroFeeHookId {
        ZeroFeeHookId::IntexFactoryPayContributorBatch
    }

    fn classify(
        &self,
        tx: &ZeroFeeTransaction<'_>,
    ) -> Result<Option<ZeroFeeCandidate>, ZeroFeePolicyError> {
        if tx.to != Some(INTEX_FACTORY_ADDRESS) {
            return Ok(None);
        }
        if tx.input.get(..4) != Some(IIntexFactory::payContributorBatchCall::SELECTOR.as_slice()) {
            return Ok(None);
        }
        if tx.max_priority_fee_per_gas != Some(0) {
            return Ok(None);
        }
        if tx.max_fee_per_gas < MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS {
            return Err(ZeroFeePolicyError::FeeCapTooLow {
                max_fee_per_gas: tx.max_fee_per_gas,
                minimum: MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS,
            });
        }
        if tx.value != U256::ZERO {
            return Err(ZeroFeePolicyError::NonZeroValue);
        }
        if tx.input.len() > MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES {
            return Err(ZeroFeePolicyError::CalldataTooLarge {
                size: tx.input.len(),
                limit: MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES,
            });
        }
        if tx.gas_limit > MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT {
            return Err(ZeroFeePolicyError::GasLimitTooHigh {
                gas_limit: tx.gas_limit,
                limit: MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT,
            });
        }
        // Decoding is bounded by the caps above, and it is the only way to reject
        // a head that points outside the payload.
        if IIntexFactory::payContributorBatchCall::abi_decode(tx.input).is_err() {
            return Err(ZeroFeePolicyError::MalformedCalldata(
                "payContributorBatch decode failed".to_string(),
            ));
        }
        Ok(Some(ZeroFeeCandidate::new(self.id(), tx.signer)))
    }

    fn authorize_fee_waiver(
        &self,
        storage: StorageHandle,
        candidate: ZeroFeeCandidate,
    ) -> Result<ZeroFeeAuthorization, ZeroFeePolicyError> {
        let validators = outbe_validatorset::contract::ValidatorSet::new(storage);
        let validator = validators
            .resolve_validator_for_role(
                candidate.signer,
                outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
            )?
            .ok_or(ZeroFeePolicyError::UnauthorizedSigner)?;
        Ok(ZeroFeeAuthorization {
            hook: self.id(),
            subject: validator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Address, B256};
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};

    const VALIDATOR: Address = address!("0x1111111111111111111111111111111111111111");
    const DELEGATE: Address = address!("0x2222222222222222222222222222222222222222");

    fn calldata(leaves: usize, proof: usize) -> Vec<u8> {
        IIntexFactory::payContributorBatchCall {
            worldwideDay: 20_260_725,
            startIndex: 0,
            leaves: (0..leaves)
                .map(|i| IIntexFactory::ContributorLeaf {
                    owner: Address::repeat_byte(u8::try_from(i % 251).unwrap()),
                    sourceTributeId: U256::from_be_bytes(B256::repeat_byte(7).0),
                    nominal: U256::from(1_u64),
                })
                .collect(),
            proof: vec![B256::repeat_byte(9); proof],
        }
        .abi_encode()
    }

    fn tx_from(signer: Address, input: &[u8]) -> ZeroFeeTransaction<'_> {
        ZeroFeeTransaction {
            signer,
            to: Some(INTEX_FACTORY_ADDRESS),
            value: U256::ZERO,
            input,
            gas_limit: MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT,
            max_fee_per_gas: MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS,
            max_priority_fee_per_gas: Some(0),
        }
    }

    fn tx(input: &[u8]) -> ZeroFeeTransaction<'_> {
        tx_from(VALIDATOR, input)
    }

    #[test]
    fn a_full_batch_fits_the_envelope() {
        let input = calldata(256, 24);
        assert!(
            input.len() <= MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES,
            "full batch is {} bytes, cap is {}",
            input.len(),
            MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES
        );
        let candidate = crate::registry().classify(&tx(&input)).unwrap().unwrap();
        assert_eq!(
            candidate.hook,
            ZeroFeeHookId::IntexFactoryPayContributorBatch
        );
    }

    #[test]
    fn only_the_exact_zero_fee_envelope_is_claimed() {
        let input = calldata(1, 1);

        let mut foreign_target = tx(&input);
        foreign_target.to = Some(Address::ZERO);
        assert!(crate::registry()
            .classify(&foreign_target)
            .unwrap()
            .is_none());

        let other_selector = IIntexFactory::distributeCall {
            worldwideDay: 1,
            srcChainId: 1,
        }
        .abi_encode();
        assert!(crate::registry()
            .classify(&tx(&other_selector))
            .unwrap()
            .is_none());

        // A tip-paying sender keeps the normal fee market.
        let mut tipped = tx(&input);
        tipped.max_priority_fee_per_gas = Some(1);
        assert!(crate::registry().classify(&tipped).unwrap().is_none());
    }

    #[test]
    fn value_oversize_and_malformed_calldata_are_rejected() {
        let input = calldata(1, 1);

        let mut funded = tx(&input);
        funded.value = U256::from(1_u64);
        assert_eq!(
            crate::registry().classify(&funded).unwrap_err(),
            ZeroFeePolicyError::NonZeroValue
        );

        let mut greedy = tx(&input);
        greedy.gas_limit = MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT + 1;
        assert!(matches!(
            crate::registry().classify(&greedy).unwrap_err(),
            ZeroFeePolicyError::GasLimitTooHigh { .. }
        ));

        let mut cheap = tx(&input);
        cheap.max_fee_per_gas = MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS - 1;
        assert!(matches!(
            crate::registry().classify(&cheap).unwrap_err(),
            ZeroFeePolicyError::FeeCapTooLow { .. }
        ));

        let mut oversized = calldata(256, 24);
        oversized.resize(MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES + 1, 0);
        assert!(matches!(
            crate::registry().classify(&tx(&oversized)).unwrap_err(),
            ZeroFeePolicyError::CalldataTooLarge { .. }
        ));

        let mut truncated = input.clone();
        truncated.truncate(40);
        assert!(matches!(
            crate::registry().classify(&tx(&truncated)).unwrap_err(),
            ZeroFeePolicyError::MalformedCalldata(_)
        ));
    }

    #[test]
    fn active_validator_or_its_ocomp_delegate_receives_fee_waiver() {
        let input = calldata(1, 1);
        let candidate = crate::registry().classify(&tx(&input)).unwrap().unwrap();
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            assert_eq!(
                crate::registry()
                    .authorize_fee_waiver(storage.clone(), candidate)
                    .unwrap_err(),
                ZeroFeePolicyError::UnauthorizedSigner
            );

            let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            validators
                .config_owner
                .write(address!("0xffffffffffffffffffffffffffffffffffffffff"))
                .unwrap();
            validators.config_max_validators.write(1).unwrap();
            validators
                .test_register_validator_without_pop(VALIDATOR, &[1; 48])
                .unwrap();
            validators
                .test_activate_validator_canonically(
                    VALIDATOR,
                    outbe_validatorset::StakeProjection::new(U256::from(1), None),
                    U256::from(1),
                )
                .unwrap();
            validators
                .set_delegate(
                    VALIDATOR,
                    outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
                    DELEGATE,
                )
                .unwrap();

            let delegated = crate::registry()
                .classify(&tx_from(DELEGATE, &input))
                .unwrap()
                .unwrap();
            let authorization = crate::registry()
                .authorize_fee_waiver(storage, delegated)
                .unwrap();
            assert_eq!(authorization.subject, VALIDATOR);
        });
    }
}
