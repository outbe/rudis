use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};
use outbe_primitives::dispatch::{dispatch_call, metadata, mutate_void, reject_value, view};
use outbe_primitives::error::{PrecompileError, Result};

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IValidatorSet.sol"
);

/// Dispatches an ABI-encoded call to the ValidatorSet precompile.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(
        data,
        IValidatorSet::IValidatorSetCalls::abi_decode,
        |call| {
            let mut vs = crate::schema::ValidatorSet::new(storage);
            use IValidatorSet::IValidatorSetCalls::*;
            match call {
                getValidators(_) => metadata::<IValidatorSet::getValidatorsCall>(|| {
                    let validators = vs.get_all_validators()?;
                    Ok(validators
                        .iter()
                        .map(|v| v.validator_address)
                        .collect::<Vec<_>>())
                }),
                getActiveValidators(_) => {
                    metadata::<IValidatorSet::getActiveValidatorsCall>(|| {
                        let validators = vs.get_active_validators()?;
                        Ok(validators
                            .iter()
                            .map(|v| v.validator_address)
                            .collect::<Vec<_>>())
                    })
                }
                getActiveConsensusSet(_) => {
                    metadata::<IValidatorSet::getActiveConsensusSetCall>(|| {
                        let validators = vs.get_active_consensus_set()?;
                        Ok(validators
                            .iter()
                            .map(|v| v.validator_address)
                            .collect::<Vec<_>>())
                    })
                }
                validatorByAddress(c) => view(c, |c| {
                    let v = vs
                        .get_validator(c.addr)?
                        .ok_or_else(|| PrecompileError::Revert("validator not found".into()))?;
                    Ok((
                        v.validator_address,
                        Bytes::copy_from_slice(&v.consensus_pubkey),
                        v.stake,
                        v.status,
                        v.slash_count,
                        v.missed_blocks,
                        v.missed_votes,
                        v.blocks_proposed,
                        v.joined_at_height,
                        v.deactivated_at_height,
                        v.unbonding_end,
                        v.has_bls_share,
                    )
                        .into())
                }),
                validatorByIndex(c) => view(c, |c| {
                    let addr = vs.validator_address_at(c.index)?.ok_or_else(|| {
                        PrecompileError::Revert("validator not found at index".into())
                    })?;
                    let v = vs
                        .get_validator(addr)?
                        .ok_or_else(|| PrecompileError::Revert("validator not found".into()))?;
                    Ok((
                        v.validator_address,
                        Bytes::copy_from_slice(&v.consensus_pubkey),
                        v.stake,
                        v.status,
                        v.slash_count,
                        v.missed_blocks,
                        v.missed_votes,
                        v.blocks_proposed,
                        v.joined_at_height,
                        v.deactivated_at_height,
                        v.unbonding_end,
                        v.has_bls_share,
                    )
                        .into())
                }),
                validatorCount(_) => {
                    metadata::<IValidatorSet::validatorCountCall>(|| vs.validator_count())
                }
                activeValidatorCount(_) => {
                    metadata::<IValidatorSet::activeValidatorCountCall>(|| {
                        vs.active_validator_count()
                    })
                }
                activeConsensusCount(_) => {
                    metadata::<IValidatorSet::activeConsensusCountCall>(|| {
                        vs.active_consensus_count()
                    })
                }
                isValidator(c) => view(c, |c| vs.is_validator(c.addr)),
                isConsensusParticipant(c) => view(c, |c| vs.is_consensus_participant(c.addr)),
                hasPendingSetChange(_) => {
                    metadata::<IValidatorSet::hasPendingSetChangeCall>(|| {
                        vs.has_pending_set_change()
                    })
                }
                getEpochNumber(_) => {
                    metadata::<IValidatorSet::getEpochNumberCall>(|| vs.epoch_number.read())
                }
                getEpochStartTimestamp(_) => {
                    metadata::<IValidatorSet::getEpochStartTimestampCall>(|| {
                        vs.epoch_start_timestamp.read()
                    })
                }
                getEpochStartBlock(_) => metadata::<IValidatorSet::getEpochStartBlockCall>(|| {
                    vs.epoch_start_block.read()
                }),
                setDelegate(c) => mutate_void(c, caller, |sender, c| {
                    let role = crate::delegation::ValidatorDelegateRole::try_from(c.role)?;
                    vs.set_delegate(sender, role, c.delegate)
                }),
                revokeDelegate(c) => mutate_void(c, caller, |sender, c| {
                    let role = crate::delegation::ValidatorDelegateRole::try_from(c.role)?;
                    vs.revoke_delegate(sender, role)
                }),
                getDelegate(c) => view(c, |c| {
                    let role = crate::delegation::ValidatorDelegateRole::try_from(c.role)?;
                    vs.get_delegate(c.validator, role)
                }),
                resolveValidator(c) => view(c, |c| {
                    let role = crate::delegation::ValidatorDelegateRole::try_from(c.role)?;
                    Ok(vs
                        .resolve_validator_for_role(c.signer, role)?
                        .unwrap_or(Address::ZERO))
                }),
                getRadicleNodeId(c) => view(c, |c| vs.get_radicle_node_id(c.validator)),
                validatorByRadicleNodeId(c) => {
                    view(c, |c| vs.validator_by_radicle_node_id(c.nodeId))
                }
                registerValidator(c) => mutate_void(c, caller, |sender, c| {
                    if c.consensusPubkey.len() != 48 {
                        return Err(PrecompileError::Revert(
                            "consensus pubkey must be 48 bytes".into(),
                        ));
                    }
                    let pubkey: [u8; 48] = c.consensusPubkey[..48].try_into().map_err(|_| {
                        PrecompileError::Revert("consensus pubkey conversion failed".into())
                    })?;
                    let sig: &[u8; 96] = if c.blsRegistrationSignature.len() == 96 {
                        c.blsRegistrationSignature[..96].try_into().map_err(|_| {
                            PrecompileError::Revert("BLS signature conversion failed".into())
                        })?
                    } else {
                        return Err(PrecompileError::Revert(
                            "BLS proof of possession must be exactly 96 bytes".into(),
                        ));
                    };
                    vs.register_validator_with_sig(
                        sender,
                        c.validatorAddress,
                        &pubkey,
                        c.radicleNodeId,
                        Some(sig),
                    )
                }),
                setP2pAddress(c) => mutate_void(c, caller, |sender, c| {
                    vs.set_p2p_address(sender, c.validatorAddress, c.version, &c.encoded)
                }),
                getP2pAddress(c) => view(c, |c| {
                    let (version, encoded) = vs
                        .get_p2p_address(c.validatorAddress)?
                        .unwrap_or((0, Vec::new()));
                    Ok((version, Bytes::from(encoded)).into())
                }),
                deactivateValidator(c) => mutate_void(c, caller, |sender, c| {
                    vs.deactivate_validator(sender, c.validatorAddress)
                }),
                confirmValidatorReady(c) => mutate_void(c, caller, |sender, c| {
                    vs.confirm_validator_ready(sender, &c.registration)
                }),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use alloy_sol_types::SolCall as _;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::validators::{
        validator_registration_message, VALIDATOR_REGISTRATION_DST,
    };

    #[test]
    fn registration_v2_and_radicle_getters_round_trip_through_public_abi() {
        let chain_id = 70860602;
        let validator = Address::repeat_byte(0x61);
        let node_id = B256::repeat_byte(0x71);
        let secret = blst::min_pk::SecretKey::key_gen(&[0x41; 32], &[]).unwrap();
        let public_key = secret.sk_to_pk().to_bytes();
        let signature = secret
            .sign(
                &validator_registration_message(chain_id, validator, node_id),
                VALIDATOR_REGISTRATION_DST,
                &[],
            )
            .to_bytes();
        let mut provider = HashMapStorageProvider::new(chain_id);
        provider.set_block_number(1);

        StorageHandle::enter(&mut provider, |storage| {
            let vs = crate::schema::ValidatorSet::new(storage.clone());
            vs.config_owner.write(validator).unwrap();
            vs.config_max_validators.write(10).unwrap();

            dispatch(
                storage.clone(),
                &IValidatorSet::registerValidatorCall {
                    validatorAddress: validator,
                    consensusPubkey: Bytes::copy_from_slice(&public_key),
                    radicleNodeId: node_id,
                    blsRegistrationSignature: Bytes::copy_from_slice(&signature),
                }
                .abi_encode(),
                validator,
                U256::ZERO,
            )
            .unwrap();

            let forward = dispatch(
                storage.clone(),
                &IValidatorSet::getRadicleNodeIdCall { validator }.abi_encode(),
                validator,
                U256::ZERO,
            )
            .unwrap();
            assert_eq!(
                IValidatorSet::getRadicleNodeIdCall::abi_decode_returns(&forward).unwrap(),
                node_id
            );

            let reverse = dispatch(
                storage,
                &IValidatorSet::validatorByRadicleNodeIdCall { nodeId: node_id }.abi_encode(),
                validator,
                U256::ZERO,
            )
            .unwrap();
            assert_eq!(
                IValidatorSet::validatorByRadicleNodeIdCall::abi_decode_returns(&reverse).unwrap(),
                validator
            );
        });
    }
}
