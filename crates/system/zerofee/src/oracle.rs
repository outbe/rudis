use alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE;
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use outbe_primitives::{addresses::ORACLE_ADDRESS, storage::StorageHandle};

use crate::hooks::{
    ZeroFeeAuthorization, ZeroFeeCandidate, ZeroFeeHook, ZeroFeeHookId, ZeroFeePolicyError,
    ZeroFeeTransaction,
};
use outbe_oracle::precompile::IOracle;
use outbe_validatorset::ValidatorLifecycle;

/// Maximum calldata bytes accepted for a zero-fee oracle vote.
pub const MAX_ZERO_FEE_ORACLE_CALLDATA_BYTES: usize = 16 * 1024;

/// Maximum gas limit accepted for a zero-fee oracle vote.
pub const MAX_ZERO_FEE_ORACLE_GAS_LIMIT: u64 = 1_500_000;

/// Minimum EIP-1559 fee cap accepted by Reth's public txpool.
pub const MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS: u128 = MIN_PROTOCOL_BASE_FEE as u128;

/// Zero-fee hook for validator oracle vote transactions.
#[derive(Debug, Clone, Copy)]
pub struct OracleSubmitVoteHook;

impl ZeroFeeHook for OracleSubmitVoteHook {
    fn id(&self) -> ZeroFeeHookId {
        ZeroFeeHookId::OracleSubmitVote
    }

    fn classify(
        &self,
        tx: &ZeroFeeTransaction<'_>,
    ) -> Result<Option<ZeroFeeCandidate>, ZeroFeePolicyError> {
        if tx.to != Some(ORACLE_ADDRESS) {
            return Ok(None);
        }

        if !tx.input.starts_with(&IOracle::submitVoteCall::SELECTOR) {
            return Ok(None);
        }

        if tx.max_priority_fee_per_gas != Some(0) {
            return Ok(None);
        }

        if tx.max_fee_per_gas < MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS {
            return Err(ZeroFeePolicyError::FeeCapTooLow {
                max_fee_per_gas: tx.max_fee_per_gas,
                minimum: MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS,
            });
        }

        if tx.value != U256::ZERO {
            return Err(ZeroFeePolicyError::NonZeroValue);
        }

        if tx.input.len() > MAX_ZERO_FEE_ORACLE_CALLDATA_BYTES {
            return Err(ZeroFeePolicyError::CalldataTooLarge {
                size: tx.input.len(),
                limit: MAX_ZERO_FEE_ORACLE_CALLDATA_BYTES,
            });
        }

        if tx.gas_limit > MAX_ZERO_FEE_ORACLE_GAS_LIMIT {
            return Err(ZeroFeePolicyError::GasLimitTooHigh {
                gas_limit: tx.gas_limit,
                limit: MAX_ZERO_FEE_ORACLE_GAS_LIMIT,
            });
        }

        if IOracle::submitVoteCall::abi_decode(tx.input).is_err() {
            return Err(ZeroFeePolicyError::MalformedCalldata(
                "submitVote(ExchangeRateTuple[]) decode failed".to_string(),
            ));
        }

        Ok(Some(ZeroFeeCandidate::new(self.id(), tx.signer)))
    }

    fn authorize_fee_waiver(
        &self,
        storage: StorageHandle,
        candidate: ZeroFeeCandidate,
    ) -> Result<ZeroFeeAuthorization, ZeroFeePolicyError> {
        validate_oracle_submit_vote_state(storage, candidate.signer).map(|validator| {
            ZeroFeeAuthorization {
                hook: self.id(),
                subject: validator,
            }
        })
    }
}

fn validate_oracle_submit_vote_state(
    storage: StorageHandle,
    signer: Address,
) -> Result<Address, ZeroFeePolicyError> {
    let vs = outbe_validatorset::contract::ValidatorSet::new(storage);
    let validator = vs
        .resolve_validator_for_role(
            signer,
            outbe_validatorset::delegation::ValidatorDelegateRole::Oracle,
        )?
        .ok_or(ZeroFeePolicyError::UnauthorizedSigner)?;
    if !matches!(
        vs.validator_lifecycle(validator)?,
        ValidatorLifecycle::Active(_)
    ) {
        return Err(ZeroFeePolicyError::UnauthorizedSigner);
    }

    let oracle = outbe_oracle::schema::OracleContract::new(vs.storage.clone());
    if oracle.vote_exists.read(&validator)? {
        return Err(ZeroFeePolicyError::AlreadyVoted);
    }

    Ok(validator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Bytes};
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};

    const VALIDATOR: Address = address!("0x1111111111111111111111111111111111111111");
    const FEEDER: Address = address!("0x2222222222222222222222222222222222222222");

    fn vote_calldata() -> Bytes {
        IOracle::submitVoteCall {
            tuples: vec![IOracle::ExchangeRateTuple {
                base: outbe_oracle::api::COEN_ASSET,
                quote: outbe_oracle::api::currency_address(840),
                exchangeRate: U256::from(18_820_648_000_000_000u128),
                volume: U256::from(1_000_000u64),
            }],
        }
        .abi_encode()
        .into()
    }

    fn oracle_vote_tx(
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: Option<u128>,
        input: &[u8],
    ) -> ZeroFeeTransaction<'_> {
        ZeroFeeTransaction {
            signer: FEEDER,
            to: Some(ORACLE_ADDRESS),
            value: U256::ZERO,
            input,
            gas_limit: 1_000_000,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }

    #[test]
    fn registry_classifies_oracle_submit_vote_shape() {
        let input = vote_calldata();
        let tx = oracle_vote_tx(MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS, Some(0), input.as_ref());
        let candidate = crate::registry().classify(&tx).unwrap().unwrap();

        assert_eq!(candidate.hook, ZeroFeeHookId::OracleSubmitVote);
        assert_eq!(candidate.signer, FEEDER);
    }

    #[test]
    fn paid_oracle_vote_uses_normal_fee_path() {
        let input = vote_calldata();
        let tx = oracle_vote_tx(1_000_000_000, Some(1), input.as_ref());

        assert_eq!(crate::registry().classify(&tx).unwrap(), None);
    }

    #[test]
    fn malformed_zero_fee_vote_is_rejected_by_hook() {
        let tx = oracle_vote_tx(
            MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS,
            Some(0),
            &IOracle::submitVoteCall::SELECTOR,
        );
        let err = crate::registry().classify(&tx).unwrap_err();

        assert!(matches!(err, ZeroFeePolicyError::MalformedCalldata(_)));
    }

    #[test]
    fn zero_fee_vote_requires_protocol_minimum_fee_cap() {
        let input = vote_calldata();
        let tx = oracle_vote_tx(0, Some(0), input.as_ref());
        let err = crate::registry().classify(&tx).unwrap_err();

        assert_eq!(
            err,
            ZeroFeePolicyError::FeeCapTooLow {
                max_fee_per_gas: 0,
                minimum: MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS,
            }
        );
    }

    #[test]
    fn delegated_feeder_passes_until_validator_votes() {
        let mut storage = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut storage, |storage| {
            let owner = address!("0xffffffffffffffffffffffffffffffffffffffff");
            let mut vs = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
            vs.config_owner.write(owner).unwrap();
            vs.config_max_validators.write(1).unwrap();
            vs.test_register_validator_without_pop(VALIDATOR, &[1; 48])
                .unwrap();
            vs.test_activate_validator_canonically(
                VALIDATOR,
                outbe_validatorset::StakeProjection::new(U256::from(1), None),
                U256::from(1),
            )
            .unwrap();

            vs.set_delegate(
                VALIDATOR,
                outbe_validatorset::delegation::ValidatorDelegateRole::Oracle,
                FEEDER,
            )
            .unwrap();

            let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
            let input = vote_calldata();
            let tx = oracle_vote_tx(MIN_ZERO_FEE_ORACLE_MAX_FEE_PER_GAS, Some(0), input.as_ref());
            let candidate = crate::registry().classify(&tx).unwrap().unwrap();
            let auth = crate::registry()
                .authorize_fee_waiver(storage.clone(), candidate)
                .unwrap();
            assert_eq!(auth.subject, VALIDATOR);

            oracle.vote_exists.write(&VALIDATOR, true).unwrap();
            let err = crate::registry()
                .authorize_fee_waiver(storage.clone(), candidate)
                .unwrap_err();
            assert_eq!(err, ZeroFeePolicyError::AlreadyVoted);
        });
    }
}
