use std::collections::HashSet;

use alloy_primitives::{Address, U256};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::stablecoin_fork::{
    STABLECOIN_LIST_PAGE_CAP, STABLECOIN_POLICY_MEMBER_BATCH_CAP,
};

use crate::abi::IStablecoinPolicyRegistry;
use crate::errors::PolicyRegistryError;
use crate::schema::{
    PolicyDescriptor, PolicyLane, PolicyType, StablecoinPolicyRegistryContract,
    ALLOW_ALL_POLICY_ID, DENY_ALL_POLICY_ID, FIRST_MUTABLE_POLICY_ID,
};

impl StablecoinPolicyRegistryContract<'_> {
    pub fn policy_exists(&self, policy_id: U256) -> Result<bool> {
        if matches!(policy_id, DENY_ALL_POLICY_ID | ALLOW_ALL_POLICY_ID) {
            return Ok(true);
        }
        self.policies.exists(policy_id)
    }

    pub fn descriptor(&self, policy_id: U256) -> Result<PolicyDescriptor> {
        match policy_id {
            DENY_ALL_POLICY_ID => Ok(PolicyDescriptor::builtin(
                DENY_ALL_POLICY_ID,
                PolicyType::DenyAll,
            )),
            ALLOW_ALL_POLICY_ID => Ok(PolicyDescriptor::builtin(
                ALLOW_ALL_POLICY_ID,
                PolicyType::AllowAll,
            )),
            _ => self
                .policies
                .get(policy_id)?
                .ok_or_else(|| PolicyRegistryError::UnknownPolicy { policy_id }.into()),
        }
    }

    pub fn policy_type(&self, policy_id: U256) -> Result<PolicyType> {
        self.descriptor_type(&self.descriptor(policy_id)?)
    }

    pub fn policy_admin(&self, policy_id: U256) -> Result<Address> {
        Ok(self.descriptor(policy_id)?.admin)
    }

    pub fn pending_policy_admin(&self, policy_id: U256) -> Result<Address> {
        Ok(self.descriptor(policy_id)?.pending_admin)
    }

    pub fn is_member(&self, policy_id: U256, account: Address) -> Result<bool> {
        let Some(descriptor) = self.optional_descriptor(policy_id)? else {
            return Ok(false);
        };
        let policy_type = match PolicyType::try_from(descriptor.policy_type) {
            Ok(policy_type) => policy_type,
            Err(_) => return Ok(false),
        };
        if !policy_type.is_simple() {
            return Ok(false);
        }
        self.member_set(policy_id).contains(&account)
    }

    pub fn policy_member_count(&self, policy_id: U256) -> Result<U256> {
        let policy_type = self.policy_type(policy_id)?;
        self.require_enumerable(policy_id, policy_type)?;
        self.member_set(policy_id).len().map(U256::from)
    }

    pub fn list_policy_members(
        &self,
        policy_id: U256,
        offset: U256,
        limit: U256,
    ) -> Result<Vec<Address>> {
        if limit == U256::ZERO || limit > U256::from(STABLECOIN_LIST_PAGE_CAP) {
            return Err(PolicyRegistryError::InvalidListLimit {
                limit,
                maximum: STABLECOIN_LIST_PAGE_CAP,
            }
            .into());
        }
        let policy_type = self.policy_type(policy_id)?;
        self.require_enumerable(policy_id, policy_type)?;

        let members = self.member_set(policy_id);
        let count = members.len()?;
        if offset >= U256::from(count) {
            return Ok(Vec::new());
        }

        let start = offset.to::<u32>();
        let requested = limit.to::<u32>();
        let end = start.saturating_add(requested).min(count);
        let mut page = Vec::with_capacity((end - start) as usize);
        for index in start..end {
            let member = members.at(index)?.ok_or_else(|| {
                PrecompileError::Fatal("policy member set length/data mismatch".into())
            })?;
            page.push(member);
        }
        Ok(page)
    }

    pub fn can(&self, policy_id: U256, account: Address, lane: PolicyLane) -> Result<bool> {
        let descriptor = match self.optional_descriptor(policy_id)? {
            Some(descriptor) => descriptor,
            None => return Ok(false),
        };
        let policy_type = match PolicyType::try_from(descriptor.policy_type) {
            Ok(policy_type) => policy_type,
            Err(_) => return Ok(false),
        };
        match policy_type {
            PolicyType::DenyAll => Ok(false),
            PolicyType::AllowAll => Ok(true),
            PolicyType::Whitelist => self.member_set(policy_id).contains(&account),
            PolicyType::Blacklist => self.member_set(policy_id).contains(&account).map(|v| !v),
            PolicyType::Directional => {
                let child = match lane {
                    PolicyLane::Send => descriptor.send_policy_id,
                    PolicyLane::Receive => descriptor.receive_policy_id,
                    PolicyLane::Mint => descriptor.mint_policy_id,
                };
                self.can_simple_child(child, account)
            }
        }
    }

    pub fn create_policy(
        &mut self,
        actor: Address,
        policy_type: u8,
        admin: Address,
    ) -> Result<U256> {
        let policy_type = PolicyType::try_from(policy_type)?;
        if !policy_type.is_simple() {
            return Err(PolicyRegistryError::InvalidPolicyType {
                policy_type: policy_type as u8,
            }
            .into());
        }
        self.validate_admin(admin)?;
        self.create_descriptor(actor, policy_type, admin, [U256::ZERO; 3])
    }

    pub fn create_directional_policy(
        &mut self,
        actor: Address,
        admin: Address,
        send_policy_id: U256,
        receive_policy_id: U256,
        mint_policy_id: U256,
    ) -> Result<U256> {
        self.validate_admin(admin)?;
        for child in [send_policy_id, receive_policy_id, mint_policy_id] {
            let Some(descriptor) = self.optional_descriptor(child)? else {
                return Err(
                    PolicyRegistryError::InvalidDirectionalChild { policy_id: child }.into(),
                );
            };
            if self.descriptor_type(&descriptor)? == PolicyType::Directional {
                return Err(
                    PolicyRegistryError::InvalidDirectionalChild { policy_id: child }.into(),
                );
            }
        }
        self.create_descriptor(
            actor,
            PolicyType::Directional,
            admin,
            [send_policy_id, receive_policy_id, mint_policy_id],
        )
    }

    pub fn add_members(
        &mut self,
        policy_id: U256,
        caller: Address,
        accounts: &[Address],
    ) -> Result<()> {
        self.mutate_members(policy_id, caller, accounts, true)
    }

    pub fn remove_members(
        &mut self,
        policy_id: U256,
        caller: Address,
        accounts: &[Address],
    ) -> Result<()> {
        self.mutate_members(policy_id, caller, accounts, false)
    }

    pub fn begin_policy_admin_transfer(
        &mut self,
        policy_id: U256,
        caller: Address,
        candidate: Address,
    ) -> Result<()> {
        let mut descriptor = self.mutable_descriptor_for_admin(policy_id, caller)?;
        if candidate == Address::ZERO || candidate == descriptor.admin {
            return Err(PolicyRegistryError::InvalidPendingPolicyAdmin { candidate }.into());
        }
        let current_admin = descriptor.admin;
        descriptor.pending_admin = candidate;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.policies.update(&descriptor)?;
            self.emit(IStablecoinPolicyRegistry::PolicyAdminTransferStarted {
                policyId: policy_id,
                currentAdmin: current_admin,
                pendingAdmin: candidate,
            })
        })
    }

    pub fn cancel_policy_admin_transfer(&mut self, policy_id: U256, caller: Address) -> Result<()> {
        let mut descriptor = self.mutable_descriptor_for_admin(policy_id, caller)?;
        if descriptor.pending_admin == Address::ZERO {
            return Err(PolicyRegistryError::InvalidPendingPolicyAdmin {
                candidate: Address::ZERO,
            }
            .into());
        }
        let cancelled_pending_admin = descriptor.pending_admin;
        descriptor.pending_admin = Address::ZERO;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.policies.update(&descriptor)?;
            self.emit(IStablecoinPolicyRegistry::PolicyAdminTransferCancelled {
                policyId: policy_id,
                admin: caller,
                cancelledPendingAdmin: cancelled_pending_admin,
            })
        })
    }

    pub fn accept_policy_admin_transfer(&mut self, policy_id: U256, caller: Address) -> Result<()> {
        let mut descriptor = self.mutable_descriptor(policy_id)?;
        if descriptor.pending_admin != caller {
            return Err(PolicyRegistryError::NotPendingPolicyAdmin { policy_id, caller }.into());
        }
        let previous_admin = descriptor.admin;
        descriptor.admin = caller;
        descriptor.pending_admin = Address::ZERO;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.policies.update(&descriptor)?;
            self.emit(IStablecoinPolicyRegistry::PolicyAdminTransferred {
                policyId: policy_id,
                previousAdmin: previous_admin,
                newAdmin: caller,
            })
        })
    }

    fn optional_descriptor(&self, policy_id: U256) -> Result<Option<PolicyDescriptor>> {
        match policy_id {
            DENY_ALL_POLICY_ID => Ok(Some(PolicyDescriptor::builtin(
                DENY_ALL_POLICY_ID,
                PolicyType::DenyAll,
            ))),
            ALLOW_ALL_POLICY_ID => Ok(Some(PolicyDescriptor::builtin(
                ALLOW_ALL_POLICY_ID,
                PolicyType::AllowAll,
            ))),
            _ => self.policies.get(policy_id),
        }
    }

    fn can_simple_child(&self, policy_id: U256, account: Address) -> Result<bool> {
        let Some(descriptor) = self.optional_descriptor(policy_id)? else {
            return Ok(false);
        };
        match PolicyType::try_from(descriptor.policy_type) {
            Ok(PolicyType::DenyAll) => Ok(false),
            Ok(PolicyType::AllowAll) => Ok(true),
            Ok(PolicyType::Whitelist) => self.member_set(policy_id).contains(&account),
            Ok(PolicyType::Blacklist) => self.member_set(policy_id).contains(&account).map(|v| !v),
            Ok(PolicyType::Directional) | Err(_) => Ok(false),
        }
    }

    fn require_enumerable(&self, policy_id: U256, policy_type: PolicyType) -> Result<()> {
        if policy_type.is_simple() {
            Ok(())
        } else {
            Err(PolicyRegistryError::PolicyMemberEnumerationUnsupported {
                policy_id,
                policy_type: policy_type as u8,
            }
            .into())
        }
    }

    fn descriptor_type(&self, descriptor: &PolicyDescriptor) -> Result<PolicyType> {
        PolicyType::try_from(descriptor.policy_type).map_err(|_| {
            PrecompileError::Fatal(format!(
                "policy {} has unknown stored descriptor {}",
                descriptor.policy_id, descriptor.policy_type
            ))
        })
    }

    fn validate_admin(&self, admin: Address) -> Result<()> {
        if admin == Address::ZERO {
            return Err(PolicyRegistryError::InvalidPolicyAdmin { admin }.into());
        }
        Ok(())
    }

    fn next_id(&self) -> Result<U256> {
        let stored = self.next_policy_id.read()?;
        if stored == U256::ZERO {
            return Ok(FIRST_MUTABLE_POLICY_ID);
        }
        if stored < FIRST_MUTABLE_POLICY_ID {
            return Err(PrecompileError::Fatal(
                "stablecoin policy next id is corrupt".into(),
            ));
        }
        Ok(stored)
    }

    fn create_descriptor(
        &mut self,
        actor: Address,
        policy_type: PolicyType,
        admin: Address,
        children: [U256; 3],
    ) -> Result<U256> {
        let policy_id = self.next_id()?;
        if self.policies.exists(policy_id)? {
            return Err(PrecompileError::Fatal(
                "stablecoin policy next id collides with an existing descriptor".into(),
            ));
        }
        let next = policy_id
            .checked_add(U256::from(1u64))
            .ok_or(PolicyRegistryError::PolicyIdExhausted)?;
        let descriptor = PolicyDescriptor {
            policy_id,
            exists: true,
            policy_type: policy_type as u8,
            admin,
            pending_admin: Address::ZERO,
            send_policy_id: children[0],
            receive_policy_id: children[1],
            mint_policy_id: children[2],
        };
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.policies.create(&descriptor)?;
            self.next_policy_id.write(next)?;
            self.emit(IStablecoinPolicyRegistry::PolicyCreated {
                policyId: policy_id,
                actor,
                admin,
                policyType: policy_type as u8,
                sendPolicyId: children[0],
                receivePolicyId: children[1],
                mintPolicyId: children[2],
            })
        })?;
        Ok(policy_id)
    }

    fn mutable_descriptor(&self, policy_id: U256) -> Result<PolicyDescriptor> {
        if matches!(policy_id, DENY_ALL_POLICY_ID | ALLOW_ALL_POLICY_ID) {
            return Err(PolicyRegistryError::ImmutablePolicy { policy_id }.into());
        }
        self.descriptor(policy_id)
    }

    fn mutable_descriptor_for_admin(
        &self,
        policy_id: U256,
        caller: Address,
    ) -> Result<PolicyDescriptor> {
        let descriptor = self.mutable_descriptor(policy_id)?;
        if descriptor.admin != caller {
            return Err(PolicyRegistryError::UnauthorizedPolicyAdmin { policy_id, caller }.into());
        }
        Ok(descriptor)
    }

    fn validate_member_batch(&self, accounts: &[Address]) -> Result<()> {
        if accounts.is_empty() {
            return Err(PolicyRegistryError::EmptyMemberBatch.into());
        }
        if accounts.len() > STABLECOIN_POLICY_MEMBER_BATCH_CAP {
            return Err(PolicyRegistryError::MemberBatchTooLarge {
                length: accounts.len(),
                maximum: STABLECOIN_POLICY_MEMBER_BATCH_CAP,
            }
            .into());
        }
        let mut unique = HashSet::with_capacity(accounts.len());
        for account in accounts {
            if *account == Address::ZERO {
                return Err(PolicyRegistryError::InvalidMember { account: *account }.into());
            }
            if !unique.insert(*account) {
                return Err(PolicyRegistryError::DuplicateMember { account: *account }.into());
            }
        }
        Ok(())
    }

    fn mutate_members(
        &mut self,
        policy_id: U256,
        caller: Address,
        accounts: &[Address],
        add: bool,
    ) -> Result<()> {
        let descriptor = self.mutable_descriptor_for_admin(policy_id, caller)?;
        let policy_type = self.descriptor_type(&descriptor)?;
        if !policy_type.is_simple() {
            return Err(PolicyRegistryError::DirectionalMembershipUnsupported { policy_id }.into());
        }
        self.validate_member_batch(accounts)?;

        let members = self.member_set(policy_id);
        for account in accounts {
            if members.contains(account)? == add {
                return Err(PolicyRegistryError::MembershipUnchanged {
                    policy_id,
                    account: *account,
                    member: add,
                }
                .into());
            }
        }

        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            for account in accounts {
                let changed = if add {
                    members.insert(*account)?
                } else {
                    members.remove(account)?
                };
                if !changed {
                    return Err(PrecompileError::Fatal(
                        "validated policy membership changed during mutation".into(),
                    ));
                }
                if add {
                    self.emit(IStablecoinPolicyRegistry::PolicyMemberAdded {
                        policyId: policy_id,
                        account: *account,
                        actor: caller,
                    })?;
                } else {
                    self.emit(IStablecoinPolicyRegistry::PolicyMemberRemoved {
                        policyId: policy_id,
                        account: *account,
                        actor: caller,
                    })?;
                }
            }
            Ok(())
        })
    }
}
