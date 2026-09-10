use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolInterface;
use outbe_primitives::dispatch::{dispatch_call, mutate, mutate_void, view};
use outbe_primitives::error::Result;

pub use crate::abi::IStablecoinPolicyRegistry;
use crate::errors::PolicyRegistryError;
use crate::schema::StablecoinPolicyRegistryContract;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    if value != U256::ZERO {
        return Err(PolicyRegistryError::UnexpectedValue { value }.into());
    }
    dispatch_call(
        data,
        |input| {
            let call = IStablecoinPolicyRegistry::IStablecoinPolicyRegistryCalls::abi_decode(input)
                .map_err(|error| error.to_string())?;
            if call.abi_encode().as_slice() != input {
                return Err("non-canonical ABI calldata or trailing bytes".to_owned());
            }
            Ok(call)
        },
        |call| {
            use IStablecoinPolicyRegistry::IStablecoinPolicyRegistryCalls::*;

            let mut registry = StablecoinPolicyRegistryContract::new(storage);
            match call {
                createPolicy(call) => mutate(call, caller, |actor, call| {
                    registry.create_policy(actor, call.policyType, call.admin)
                }),
                createDirectionalPolicy(call) => mutate(call, caller, |actor, call| {
                    registry.create_directional_policy(
                        actor,
                        call.admin,
                        call.sendPolicyId,
                        call.receivePolicyId,
                        call.mintPolicyId,
                    )
                }),
                addMembers(call) => mutate_void(call, caller, |actor, call| {
                    registry.add_members(call.policyId, actor, &call.accounts)
                }),
                removeMembers(call) => mutate_void(call, caller, |actor, call| {
                    registry.remove_members(call.policyId, actor, &call.accounts)
                }),
                beginPolicyAdminTransfer(call) => mutate_void(call, caller, |actor, call| {
                    registry.begin_policy_admin_transfer(call.policyId, actor, call.candidate)
                }),
                cancelPolicyAdminTransfer(call) => mutate_void(call, caller, |actor, call| {
                    registry.cancel_policy_admin_transfer(call.policyId, actor)
                }),
                acceptPolicyAdminTransfer(call) => mutate_void(call, caller, |actor, call| {
                    registry.accept_policy_admin_transfer(call.policyId, actor)
                }),
                policyExists(call) => view(call, |call| registry.policy_exists(call.policyId)),
                policyType(call) => view(call, |call| {
                    registry
                        .policy_type(call.policyId)
                        .map(|policy_type| policy_type as u8)
                }),
                policyAdmin(call) => view(call, |call| registry.policy_admin(call.policyId)),
                pendingPolicyAdmin(call) => {
                    view(call, |call| registry.pending_policy_admin(call.policyId))
                }
                isMember(call) => {
                    view(call, |call| registry.is_member(call.policyId, call.account))
                }
                policyMemberCount(call) => {
                    view(call, |call| registry.policy_member_count(call.policyId))
                }
                listPolicyMembers(call) => view(call, |call| {
                    registry.list_policy_members(call.policyId, call.offset, call.limit)
                }),
                canSend(call) => view(call, |call| {
                    registry.can(call.policyId, call.account, crate::PolicyLane::Send)
                }),
                canReceive(call) => view(call, |call| {
                    registry.can(call.policyId, call.account, crate::PolicyLane::Receive)
                }),
                canMint(call) => view(call, |call| {
                    registry.can(call.policyId, call.account, crate::PolicyLane::Mint)
                }),
            }
        },
    )
}
