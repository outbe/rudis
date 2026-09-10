use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolError;
use outbe_primitives::error::PrecompileError;
use thiserror::Error;

use crate::abi::IStablecoinPolicyRegistry;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyRegistryError {
    #[error("unexpected value {value}")]
    UnexpectedValue { value: U256 },

    #[error("invalid policy type {policy_type}")]
    InvalidPolicyType { policy_type: u8 },

    #[error("unknown policy {policy_id}")]
    UnknownPolicy { policy_id: U256 },

    #[error("policy {policy_id} is immutable")]
    ImmutablePolicy { policy_id: U256 },

    #[error("policy admin must be non-zero, got {admin}")]
    InvalidPolicyAdmin { admin: Address },

    #[error("caller {caller} is not admin of policy {policy_id}")]
    UnauthorizedPolicyAdmin { policy_id: U256, caller: Address },

    #[error("policy {policy_id} is not a valid directional child")]
    InvalidDirectionalChild { policy_id: U256 },

    #[error("directional policy {policy_id} has no direct membership")]
    DirectionalMembershipUnsupported { policy_id: U256 },

    #[error("policy member must be non-zero, got {account}")]
    InvalidMember { account: Address },

    #[error("member batch must not be empty")]
    EmptyMemberBatch,

    #[error("member batch length {length} exceeds maximum {maximum}")]
    MemberBatchTooLarge { length: usize, maximum: usize },

    #[error("duplicate member {account}")]
    DuplicateMember { account: Address },

    #[error("membership of {account} in policy {policy_id} is already {member}")]
    MembershipUnchanged {
        policy_id: U256,
        account: Address,
        member: bool,
    },

    #[error("invalid pending policy admin {candidate}")]
    InvalidPendingPolicyAdmin { candidate: Address },

    #[error("caller {caller} is not pending admin of policy {policy_id}")]
    NotPendingPolicyAdmin { policy_id: U256, caller: Address },

    #[error("policy id space is exhausted")]
    PolicyIdExhausted,

    #[error("list limit {limit} must be between 1 and {maximum}")]
    InvalidListLimit { limit: U256, maximum: usize },

    #[error("policy {policy_id} of type {policy_type} cannot enumerate members")]
    PolicyMemberEnumerationUnsupported { policy_id: U256, policy_type: u8 },
}

impl From<PolicyRegistryError> for PrecompileError {
    fn from(error: PolicyRegistryError) -> Self {
        use IStablecoinPolicyRegistry as I;

        let encoded = match error {
            PolicyRegistryError::UnexpectedValue { value } => {
                I::UnexpectedValue { value }.abi_encode()
            }
            PolicyRegistryError::InvalidPolicyType { policy_type } => I::InvalidPolicyType {
                policyType: policy_type,
            }
            .abi_encode(),
            PolicyRegistryError::UnknownPolicy { policy_id } => I::UnknownPolicy {
                policyId: policy_id,
            }
            .abi_encode(),
            PolicyRegistryError::ImmutablePolicy { policy_id } => I::ImmutablePolicy {
                policyId: policy_id,
            }
            .abi_encode(),
            PolicyRegistryError::InvalidPolicyAdmin { admin } => {
                I::InvalidPolicyAdmin { admin }.abi_encode()
            }
            PolicyRegistryError::UnauthorizedPolicyAdmin { policy_id, caller } => {
                I::UnauthorizedPolicyAdmin {
                    policyId: policy_id,
                    caller,
                }
                .abi_encode()
            }
            PolicyRegistryError::InvalidDirectionalChild { policy_id } => {
                I::InvalidDirectionalChild {
                    policyId: policy_id,
                }
                .abi_encode()
            }
            PolicyRegistryError::DirectionalMembershipUnsupported { policy_id } => {
                I::DirectionalMembershipUnsupported {
                    policyId: policy_id,
                }
                .abi_encode()
            }
            PolicyRegistryError::InvalidMember { account } => {
                I::InvalidMember { account }.abi_encode()
            }
            PolicyRegistryError::EmptyMemberBatch => I::EmptyMemberBatch {}.abi_encode(),
            PolicyRegistryError::MemberBatchTooLarge { length, maximum } => {
                I::MemberBatchTooLarge {
                    length: U256::from(length),
                    maximum: U256::from(maximum),
                }
                .abi_encode()
            }
            PolicyRegistryError::DuplicateMember { account } => {
                I::DuplicateMember { account }.abi_encode()
            }
            PolicyRegistryError::MembershipUnchanged {
                policy_id,
                account,
                member,
            } => I::MembershipUnchanged {
                policyId: policy_id,
                account,
                member,
            }
            .abi_encode(),
            PolicyRegistryError::InvalidPendingPolicyAdmin { candidate } => {
                I::InvalidPendingPolicyAdmin { candidate }.abi_encode()
            }
            PolicyRegistryError::NotPendingPolicyAdmin { policy_id, caller } => {
                I::NotPendingPolicyAdmin {
                    policyId: policy_id,
                    caller,
                }
                .abi_encode()
            }
            PolicyRegistryError::PolicyIdExhausted => I::PolicyIdExhausted {}.abi_encode(),
            PolicyRegistryError::InvalidListLimit { limit, maximum } => I::InvalidListLimit {
                limit,
                maximum: U256::from(maximum),
            }
            .abi_encode(),
            PolicyRegistryError::PolicyMemberEnumerationUnsupported {
                policy_id,
                policy_type,
            } => I::PolicyMemberEnumerationUnsupported {
                policyId: policy_id,
                policyType: policy_type,
            }
            .abi_encode(),
        };
        PrecompileError::RevertBytes(Bytes::from(encoded))
    }
}
