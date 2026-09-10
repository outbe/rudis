//! Validator-vote target for L2Registry mutations.

use std::str::FromStr;

use alloy_primitives::{Address, U256};
use outbe_primitives::addresses::L2_REGISTRY_ADDRESS;
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_vote::handlers::{TargetExecutionOutcome, VoteTarget, VoteTargetContext};
use serde::Deserialize;

use crate::errors::L2RegistryError;
use crate::runtime::decode_public_key;
use crate::schema::{L2RegistryContract, BLS_PUBLIC_KEY_LEN};

#[derive(Debug, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum L2RegistryVotePayloadJsonV1 {
    Register {
        chain_id: u64,
        l1_address: String,
        public_key: String,
        zk_enabled: bool,
    },
    SetZkEnabled {
        chain_id: u64,
        enabled: bool,
    },
}

/// Typed form of the strict JSON stored by an L2Registry vote proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2RegistryVotePayloadV1 {
    Register {
        chain_id: u64,
        l1_address: Address,
        public_key: [u8; BLS_PUBLIC_KEY_LEN],
        zk_enabled: bool,
    },
    SetZkEnabled {
        chain_id: u64,
        enabled: bool,
    },
}

impl L2RegistryVotePayloadV1 {
    pub fn decode_json(payload: &[u8]) -> std::result::Result<Self, L2RegistryError> {
        let decoded: L2RegistryVotePayloadJsonV1 =
            serde_json::from_slice(payload).map_err(|_| L2RegistryError::InvalidProposalPayload)?;
        match decoded {
            L2RegistryVotePayloadJsonV1::Register {
                chain_id,
                l1_address,
                public_key,
                zk_enabled,
            } => {
                if chain_id == 0 {
                    return Err(L2RegistryError::InvalidChainId);
                }
                let l1_address = Address::from_str(&l1_address)
                    .map_err(|_| L2RegistryError::InvalidProposalPayload)?;
                if l1_address.is_zero() {
                    return Err(L2RegistryError::InvalidL1Address);
                }
                let encoded = public_key
                    .strip_prefix("0x")
                    .ok_or(L2RegistryError::InvalidPublicKeyEncoding)?;
                let mut public_key = [0u8; BLS_PUBLIC_KEY_LEN];
                hex::decode_to_slice(encoded, &mut public_key).map_err(|_| {
                    L2RegistryError::InvalidPublicKeyLength {
                        length: encoded.len() / 2,
                    }
                })?;
                decode_public_key(&public_key).map_err(|_| L2RegistryError::InvalidPublicKey)?;
                Ok(Self::Register {
                    chain_id,
                    l1_address,
                    public_key,
                    zk_enabled,
                })
            }
            L2RegistryVotePayloadJsonV1::SetZkEnabled { chain_id, enabled } => {
                if chain_id == 0 {
                    return Err(L2RegistryError::InvalidChainId);
                }
                Ok(Self::SetZkEnabled { chain_id, enabled })
            }
        }
    }

    fn apply(&self, registry: &mut L2RegistryContract<'_>) -> Result<()> {
        match self {
            Self::Register {
                chain_id,
                l1_address,
                public_key,
                zk_enabled,
            } => registry.register_network_with_zk(*chain_id, *l1_address, public_key, *zk_enabled),
            Self::SetZkEnabled { chain_id, enabled } => {
                registry.set_zk_enabled(*chain_id, *enabled)
            }
        }
    }
}

/// Compile-time Vote adapter owned by L2Registry.
pub struct L2RegistryVoteTarget;

impl VoteTarget for L2RegistryVoteTarget {
    fn target_module(&self) -> Address {
        L2_REGISTRY_ADDRESS
    }

    fn validate(&self, payload: &[u8], _context: VoteTargetContext) -> Result<()> {
        L2RegistryVotePayloadV1::decode_json(payload)
            .map(|_| ())
            .map_err(Into::into)
    }

    fn handle_approved(
        &self,
        ctx: &BlockRuntimeContext,
        _proposal_id: U256,
        payload: &[u8],
        _context: VoteTargetContext,
    ) -> Result<TargetExecutionOutcome> {
        let decoded = match L2RegistryVotePayloadV1::decode_json(payload) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Ok(TargetExecutionOutcome::Error {
                    reason: error.to_string(),
                });
            }
        };
        let mut registry = L2RegistryContract::new(ctx.storage.clone());
        match decoded.apply(&mut registry) {
            Ok(()) => Ok(TargetExecutionOutcome::Applied),
            Err(PrecompileError::Revert(reason)) => Ok(TargetExecutionOutcome::Error { reason }),
            Err(PrecompileError::RevertBytes(reason)) => Ok(TargetExecutionOutcome::Error {
                reason: format!("0x{}", hex::encode(reason)),
            }),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;
    use commonware_codec::Encode;
    use commonware_cryptography::bls12381::primitives::{ops, variant::MinSig};
    use outbe_primitives::block::BlockContext;
    use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};

    use super::*;

    fn valid_public_key_hex() -> String {
        let (_, public) = ops::keypair::<_, MinSig>(&mut rand_core::OsRng);
        format!("0x{}", hex::encode(public.encode()))
    }

    fn register_json(extra: &str) -> String {
        format!(
            r#"{{"operation":"register","chainId":4242,"l1Address":"0x1111111111111111111111111111111111111111","publicKey":"{}","zkEnabled":true{extra}}}"#,
            valid_public_key_hex()
        )
    }

    fn vote_context() -> VoteTargetContext {
        VoteTargetContext {
            proposer: Address::repeat_byte(0xa1),
            attached_value: U256::ZERO,
            block_number: 7,
            chain_id: 1,
        }
    }

    #[test]
    fn strict_register_json_decodes_to_typed_fields() {
        let payload = register_json("");
        let decoded = L2RegistryVotePayloadV1::decode_json(payload.as_bytes()).unwrap();
        assert!(matches!(
            decoded,
            L2RegistryVotePayloadV1::Register {
                chain_id: 4242,
                l1_address,
                zk_enabled: true,
                ..
            } if l1_address == Address::repeat_byte(0x11)
        ));
    }

    #[test]
    fn unknown_or_operation_specific_fields_are_rejected() {
        assert!(
            L2RegistryVotePayloadV1::decode_json(register_json(",\"name\":\"x\"").as_bytes())
                .is_err()
        );
        assert!(L2RegistryVotePayloadV1::decode_json(
            br#"{"operation":"remove","chainId":4242,"enabled":true}"#
        )
        .is_err());
        assert!(
            L2RegistryVotePayloadV1::decode_json(br#"{"operation":"remove","chainId":4242}"#)
                .is_err()
        );
    }

    #[test]
    fn malformed_register_identity_and_key_are_rejected() {
        let zero = register_json("").replace(
            "0x1111111111111111111111111111111111111111",
            "0x0000000000000000000000000000000000000000",
        );
        assert!(matches!(
            L2RegistryVotePayloadV1::decode_json(zero.as_bytes()),
            Err(L2RegistryError::InvalidL1Address)
        ));

        let malformed = String::from(
            r#"{"operation":"register","chainId":4242,"l1Address":"0x1111111111111111111111111111111111111111","publicKey":"0x01","zkEnabled":true}"#,
        );
        assert!(L2RegistryVotePayloadV1::decode_json(malformed.as_bytes()).is_err());
    }

    #[test]
    fn approved_target_applies_once_and_classifies_a_duplicate_as_proposal_error() {
        let payload = register_json("");
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let target = L2RegistryVoteTarget;
            target.validate(payload.as_bytes(), vote_context()).unwrap();
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(30, 1_700_000_000, 1),
                storage.clone(),
            );
            assert_eq!(
                target
                    .handle_approved(&ctx, U256::from(1u64), payload.as_bytes(), vote_context(),)
                    .unwrap(),
                TargetExecutionOutcome::Applied
            );
            assert!(
                L2RegistryContract::new(storage.clone())
                    .load_network(4242)
                    .unwrap()
                    .zk_enabled
            );
            assert!(matches!(
                target
                    .handle_approved(&ctx, U256::from(2u64), payload.as_bytes(), vote_context(),)
                    .unwrap(),
                TargetExecutionOutcome::Error { .. }
            ));
            let record = L2RegistryContract::new(storage).load_network(4242).unwrap();
            assert_eq!(record.l1_address, Address::repeat_byte(0x11));
            assert!(record.zk_enabled);
        });
    }

    #[test]
    fn approved_toggle_uses_the_same_target_path() {
        let register = register_json("");
        let disable = br#"{"operation":"setZkEnabled","chainId":4242,"enabled":false}"#;
        let mut provider = HashMapStorageProvider::new(1);
        StorageHandle::enter(&mut provider, |storage| {
            let target = L2RegistryVoteTarget;
            let ctx = BlockRuntimeContext::new(
                BlockContext::empty_for_tests(30, 1_700_000_000, 1),
                storage.clone(),
            );
            for (id, payload) in [register.as_bytes(), disable].into_iter().enumerate() {
                assert_eq!(
                    target
                        .handle_approved(
                            &ctx,
                            U256::from((id + 1) as u64),
                            payload,
                            vote_context(),
                        )
                        .unwrap(),
                    TargetExecutionOutcome::Applied
                );
            }
            let record = L2RegistryContract::new(storage).load_network(4242).unwrap();
            assert!(!record.zk_enabled);
        });
    }
}
