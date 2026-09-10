use std::string::String;

use alloy_primitives::{b256, keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey};
use outbe_primitives::addresses::{STABLECOIN_ADDRESS_PREFIX, STABLECOIN_FACTORY_ADDRESS};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::stablecoin::{
    encode_canonical_stablecoin_create, stablecoin_address, stablecoin_token_id,
};
use outbe_primitives::stablecoin_fork::STABLECOIN_V1_SCHEMA_VERSION;
use outbe_stablecoinpolicy::api::{
    can_mint as policy_can_mint, can_receive as policy_can_receive, can_send as policy_can_send,
    policy_exists,
};

use crate::abi::IStablecoin;
use crate::api::{FactoryTokenInitialization, TokenIdentity};
use crate::errors::StablecoinStateError;
use crate::schema::{
    allowance_key, role_key, StablecoinContract, ADMIN_ROLE, CAP_MANAGER_ROLE, GUARDIAN_ROLE,
    ISSUER_ROLE, OPERATIONAL_ROLES,
};

const ROOT_SLOT_COUNT: u64 = 19;
const EIP712_DOMAIN_TYPEHASH: B256 =
    b256!("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");
const EIP712_VERSION_HASH: B256 =
    b256!("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6");
const PERMIT_TYPEHASH: B256 =
    b256!("6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9");

impl StablecoinContract<'_> {
    pub(crate) fn initialize_from_factory(
        &self,
        initialization: &FactoryTokenInitialization,
    ) -> Result<()> {
        let stored_schema = self.schema_version.read()?;
        if stored_schema != 0 {
            return Err(
                if stored_schema == u64::from(STABLECOIN_V1_SCHEMA_VERSION) {
                    StablecoinStateError::AlreadyInitialized.into()
                } else {
                    PrecompileError::Fatal(format!(
                    "stablecoin Factory initialization reached incompatible schema {stored_schema}"
                ))
                },
            );
        }
        self.validate_pristine_root()?;
        self.validate_initialization(initialization)?;

        let payload = &initialization.payload;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.creation_protocol_version
                .write(initialization.creation_protocol_version)?;
            self.token_id.write(initialization.token_id)?;
            self.name.write_string(&payload.name)?;
            self.symbol.write_string(&payload.ticker)?;
            self.currency.write(payload.iso4217)?;
            self.decimals.write(payload.decimals)?;
            self.issuer.write(payload.issuer)?;
            self.supply_cap.write(payload.supply_cap)?;
            self.policy_id.write(payload.policy_id)?;
            self.admin.write(payload.issuer)?;
            self.roles
                .write(&role_key(ADMIN_ROLE, payload.issuer), true)?;
            for role in OPERATIONAL_ROLES {
                self.roles.write(&role_key(role, payload.issuer), true)?;
            }
            // The schema marker is the final write: schema 1 always denotes a
            // completely initialized zero-supply ledger.
            self.schema_version
                .write(u64::from(STABLECOIN_V1_SCHEMA_VERSION))
        })
    }

    pub(crate) fn validated_schema_version(&self) -> Result<u64> {
        let stored = self.schema_version.read()?;
        match stored {
            0 => Err(StablecoinStateError::Uninitialized.into()),
            value if value == u64::from(STABLECOIN_V1_SCHEMA_VERSION) => Ok(value),
            value => Err(StablecoinStateError::MigrationRequired {
                stored_schema_version: value,
                active_schema_version: u64::from(STABLECOIN_V1_SCHEMA_VERSION),
            }
            .into()),
        }
    }

    pub(crate) fn identity(&self) -> Result<TokenIdentity> {
        self.validated_schema_version()?;
        let name = String::from_utf8(self.name.read()?)
            .map_err(|_| PrecompileError::Fatal("stablecoin name storage is not UTF-8".into()))?;
        let symbol = String::from_utf8(self.symbol.read()?)
            .map_err(|_| PrecompileError::Fatal("stablecoin symbol storage is not UTF-8".into()))?;
        Ok(TokenIdentity {
            token_id: self.token_id.read()?,
            name,
            symbol,
            currency: self.currency.read()?,
            decimals: self.decimals.read()?,
            issuer: self.issuer.read()?,
            creation_protocol_version: self.creation_protocol_version.read()?,
        })
    }

    pub fn name_value(&self) -> Result<String> {
        self.validated_schema_version()?;
        String::from_utf8(self.name.read()?)
            .map_err(|_| PrecompileError::Fatal("stablecoin name storage is not UTF-8".into()))
    }

    pub fn symbol_value(&self) -> Result<String> {
        self.validated_schema_version()?;
        String::from_utf8(self.symbol.read()?)
            .map_err(|_| PrecompileError::Fatal("stablecoin symbol storage is not UTF-8".into()))
    }

    pub fn decimals_value(&self) -> Result<u8> {
        self.validated_schema_version()?;
        self.decimals.read()
    }

    pub fn total_supply(&self) -> Result<U256> {
        self.validated_schema_version()?;
        self.total_supply.read()
    }

    pub fn balance_of(&self, account: Address) -> Result<U256> {
        self.validated_schema_version()?;
        self.balances.read(&account)
    }

    pub fn allowance_of(&self, owner: Address, spender: Address) -> Result<U256> {
        self.validated_schema_version()?;
        self.allowances.read(&allowance_key(owner, spender))
    }

    pub fn domain_separator(&self) -> Result<B256> {
        self.validated_schema_version()?;
        let name_hash = keccak256(self.name.read()?);
        let chain_id = U256::from(self.storage.chain_id()?);
        Ok(keccak256(
            (
                EIP712_DOMAIN_TYPEHASH,
                name_hash,
                EIP712_VERSION_HASH,
                chain_id,
                self.address,
            )
                .abi_encode(),
        ))
    }

    pub fn has_role(&self, role: B256, account: Address) -> Result<bool> {
        self.validated_schema_version()?;
        if role != ADMIN_ROLE && !OPERATIONAL_ROLES.contains(&role) {
            return Ok(false);
        }
        let member = self.roles.read(&role_key(role, account))?;
        if role == ADMIN_ROLE {
            let admin = self.admin.read()?;
            if member != (account == admin) {
                return Err(PrecompileError::Fatal(
                    "stablecoin ADMIN slot/role membership mismatch".into(),
                ));
            }
        }
        Ok(member)
    }

    pub fn grant_role(&mut self, actor: Address, role: B256, account: Address) -> Result<()> {
        self.require_role(ADMIN_ROLE, actor)?;
        self.require_operational_role(role)?;
        self.require_nonzero(account)?;
        let key = role_key(role, account);
        if self.roles.read(&key)? {
            return Ok(());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.roles.write(&key, true)?;
            self.emit(IStablecoin::RoleGranted {
                role,
                account,
                actor,
            })
        })
    }

    pub fn revoke_role(&mut self, actor: Address, role: B256, account: Address) -> Result<()> {
        self.require_role(ADMIN_ROLE, actor)?;
        self.require_operational_role(role)?;
        self.require_nonzero(account)?;
        let key = role_key(role, account);
        if !self.roles.read(&key)? {
            return Ok(());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.roles.write(&key, false)?;
            self.emit(IStablecoin::RoleRevoked {
                role,
                account,
                actor,
            })
        })
    }

    pub fn begin_admin_transfer(&mut self, actor: Address, candidate: Address) -> Result<()> {
        self.require_role(ADMIN_ROLE, actor)?;
        if candidate == Address::ZERO || candidate == actor {
            return Err(StablecoinStateError::InvalidPendingAdmin { candidate }.into());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.pending_admin.write(candidate)?;
            self.emit(IStablecoin::AdminTransferStarted {
                currentAdmin: actor,
                pendingAdmin: candidate,
            })
        })
    }

    pub fn cancel_admin_transfer(&mut self, actor: Address) -> Result<()> {
        self.require_role(ADMIN_ROLE, actor)?;
        let pending = self.pending_admin.read()?;
        if pending == Address::ZERO {
            return Err(StablecoinStateError::InvalidPendingAdmin {
                candidate: Address::ZERO,
            }
            .into());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.pending_admin.write(Address::ZERO)?;
            self.emit(IStablecoin::AdminTransferCancelled {
                admin: actor,
                cancelledPendingAdmin: pending,
            })
        })
    }

    pub fn accept_admin_transfer(&mut self, actor: Address) -> Result<()> {
        self.validated_schema_version()?;
        let pending = self.pending_admin.read()?;
        if actor == Address::ZERO || actor != pending {
            return Err(StablecoinStateError::NotPendingAdmin { caller: actor }.into());
        }
        let previous = self.admin.read()?;
        if previous == Address::ZERO
            || !self.roles.read(&role_key(ADMIN_ROLE, previous))?
            || self.roles.read(&role_key(ADMIN_ROLE, actor))?
        {
            return Err(PrecompileError::Fatal(
                "stablecoin admin transfer reached inconsistent role state".into(),
            ));
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.roles.write(&role_key(ADMIN_ROLE, previous), false)?;
            self.roles.write(&role_key(ADMIN_ROLE, actor), true)?;
            self.admin.write(actor)?;
            self.pending_admin.write(Address::ZERO)?;
            self.emit(IStablecoin::AdminTransferred {
                previousAdmin: previous,
                newAdmin: actor,
            })
        })
    }

    pub fn pause(&mut self, actor: Address) -> Result<()> {
        self.require_role(GUARDIAN_ROLE, actor)?;
        if self.paused.read()? {
            return Err(StablecoinStateError::TokenPaused.into());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.paused.write(true)?;
            self.emit(IStablecoin::Paused { actor })
        })
    }

    pub fn unpause(&mut self, actor: Address) -> Result<()> {
        self.require_role(ADMIN_ROLE, actor)?;
        if !self.paused.read()? {
            return Err(StablecoinStateError::TokenNotPaused.into());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.paused.write(false)?;
            self.emit(IStablecoin::Unpaused { actor })
        })
    }

    pub fn set_supply_cap(&mut self, actor: Address, new_cap: U256) -> Result<()> {
        self.require_role(CAP_MANAGER_ROLE, actor)?;
        let supply = self.total_supply.read()?;
        if new_cap < supply {
            return Err(StablecoinStateError::SupplyCapBelowSupply {
                requested_cap: new_cap,
                total_supply: supply,
            }
            .into());
        }
        let previous = self.supply_cap.read()?;
        if previous == new_cap {
            return Ok(());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.supply_cap.write(new_cap)?;
            self.emit(IStablecoin::SupplyCapChanged {
                previousCap: previous,
                newCap: new_cap,
                actor,
            })
        })
    }

    pub fn set_policy_id(&mut self, actor: Address, new_policy_id: U256) -> Result<()> {
        self.require_role(crate::schema::COMPLIANCE_ROLE, actor)?;
        if !policy_exists(self.storage.clone(), new_policy_id)? {
            return Err(StablecoinStateError::UnknownPolicy {
                policy_id: new_policy_id,
            }
            .into());
        }
        let previous = self.policy_id.read()?;
        if previous == new_policy_id {
            return Ok(());
        }
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.policy_id.write(new_policy_id)?;
            self.emit(IStablecoin::PolicyChanged {
                previousPolicyId: previous,
                newPolicyId: new_policy_id,
                actor,
            })
        })
    }

    pub fn frozen_tokens(&self, account: Address) -> Result<U256> {
        self.validated_schema_version()?;
        self.frozen.read(&account)
    }

    pub fn set_frozen_tokens(
        &mut self,
        actor: Address,
        account: Address,
        amount: U256,
    ) -> Result<()> {
        self.require_role(crate::schema::COMPLIANCE_ROLE, actor)?;
        self.require_nonzero(account)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.frozen.write(&account, amount)?;
            self.emit(IStablecoin::Frozen { account, amount })
        })
    }

    pub fn can_send(&self, account: Address) -> Result<bool> {
        self.validated_schema_version()?;
        if self.paused.read()? || account == Address::ZERO {
            return Ok(false);
        }
        policy_can_send(self.storage.clone(), self.policy_id.read()?, account)
    }

    pub fn can_receive(&self, account: Address) -> Result<bool> {
        self.validated_schema_version()?;
        if self.paused.read()? || account == Address::ZERO {
            return Ok(false);
        }
        policy_can_receive(self.storage.clone(), self.policy_id.read()?, account)
    }

    pub fn can_transfer(&self, from: Address, to: Address, value: U256) -> Result<bool> {
        self.validated_schema_version()?;
        if self.paused.read()? || from == Address::ZERO || to == Address::ZERO {
            return Ok(false);
        }
        let policy_id = self.policy_id.read()?;
        if !policy_can_send(self.storage.clone(), policy_id, from)?
            || !policy_can_receive(self.storage.clone(), policy_id, to)?
        {
            return Ok(false);
        }
        let balance = self.balances.read(&from)?;
        let frozen = self.frozen.read(&from)?;
        Ok(frozen.is_zero() || value <= Self::unfrozen(balance, frozen))
    }

    pub fn approve(&mut self, owner: Address, spender: Address, value: U256) -> Result<()> {
        self.validated_schema_version()?;
        self.require_nonzero(owner)?;
        self.require_nonzero(spender)?;
        self.validate_allowance_update(owner, spender, value)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| self.write_approval(owner, spender, value))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn permit(
        &mut self,
        owner: Address,
        spender: Address,
        value: U256,
        deadline: U256,
        v: u8,
        r: B256,
        s: B256,
    ) -> Result<()> {
        self.validated_schema_version()?;
        self.require_nonzero(owner)?;
        self.require_nonzero(spender)?;
        if self.storage.timestamp()? > deadline {
            return Err(StablecoinStateError::PermitExpired { deadline }.into());
        }

        let nonce = self.nonces.read(&owner)?;
        let struct_hash =
            keccak256((PERMIT_TYPEHASH, owner, spender, value, nonce, deadline).abi_encode());
        let domain_separator = self.domain_separator()?;
        let mut payload = [0u8; 66];
        payload[..2].copy_from_slice(&[0x19, 0x01]);
        payload[2..34].copy_from_slice(domain_separator.as_slice());
        payload[34..].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(payload);
        if recover_permit_signer(digest, v, r, s)? != owner {
            return Err(StablecoinStateError::InvalidPermitSignature.into());
        }

        self.validate_allowance_update(owner, spender, value)?;
        let next_nonce = nonce
            .checked_add(U256::from(1))
            .ok_or_else(|| PrecompileError::Fatal("stablecoin permit nonce overflow".into()))?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.nonces.write(&owner, next_nonce)?;
            self.write_approval(owner, spender, value)
        })
    }

    pub fn transfer(&mut self, from: Address, to: Address, value: U256) -> Result<()> {
        self.validated_schema_version()?;
        self.require_not_paused()?;
        self.require_nonzero(from)?;
        self.require_nonzero(to)?;
        self.require_can_send(from)?;
        self.require_can_receive(to)?;
        let from_balance = self.balances.read(&from)?;
        if from_balance < value {
            return Err(StablecoinStateError::InsufficientBalance {
                account: from,
                available: from_balance,
                required: value,
            }
            .into());
        }
        self.require_unfrozen(from, from_balance, value)?;

        let next_to = if from == to {
            from_balance
        } else {
            self.balances.read(&to)?.checked_add(value).ok_or_else(|| {
                PrecompileError::Fatal("stablecoin recipient balance overflow".into())
            })?
        };
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            if from != to {
                self.balances.write(&from, from_balance - value)?;
                self.balances.write(&to, next_to)?;
            }
            self.emit(IStablecoin::Transfer { from, to, value })
        })
    }

    pub fn transfer_from(
        &mut self,
        spender: Address,
        from: Address,
        to: Address,
        value: U256,
    ) -> Result<()> {
        self.validated_schema_version()?;
        self.require_not_paused()?;
        self.require_nonzero(spender)?;
        self.require_nonzero(from)?;
        self.require_nonzero(to)?;
        self.require_can_send(from)?;
        self.require_can_receive(to)?;

        let key = allowance_key(from, spender);
        let allowance = self.allowances.read(&key)?;
        if allowance < value {
            return Err(StablecoinStateError::InsufficientAllowance {
                owner: from,
                spender,
                available: allowance,
                required: value,
            }
            .into());
        }
        let from_balance = self.balances.read(&from)?;
        if from_balance < value {
            return Err(StablecoinStateError::InsufficientBalance {
                account: from,
                available: from_balance,
                required: value,
            }
            .into());
        }
        self.require_unfrozen(from, from_balance, value)?;
        let next_to = if from == to {
            from_balance
        } else {
            self.balances.read(&to)?.checked_add(value).ok_or_else(|| {
                PrecompileError::Fatal("stablecoin recipient balance overflow".into())
            })?
        };

        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            if allowance != U256::MAX {
                self.allowances.write(&key, allowance - value)?;
            }
            if from != to {
                self.balances.write(&from, from_balance - value)?;
                self.balances.write(&to, next_to)?;
            }
            self.emit(IStablecoin::Transfer { from, to, value })
        })
    }

    pub fn mint(&mut self, actor: Address, to: Address, amount: U256) -> Result<()> {
        self.require_role(ISSUER_ROLE, actor)?;
        self.require_not_paused()?;
        self.require_nonzero(to)?;
        self.require_can_mint(to)?;
        self.mint_core(to, amount)
    }

    pub fn burn(&mut self, actor: Address, amount: U256) -> Result<()> {
        self.require_role(ISSUER_ROLE, actor)?;
        self.require_not_paused()?;
        self.require_nonzero_amount(amount)?;
        let balance = self.balances.read(&actor)?;
        if balance < amount {
            return Err(StablecoinStateError::InsufficientBalance {
                account: actor,
                available: balance,
                required: amount,
            }
            .into());
        }
        let frozen = self.frozen.read(&actor)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.consume_frozen(actor, balance, frozen, amount)?;
            self.burn_core(actor, amount)
        })
    }

    pub fn burn_from(&mut self, spender: Address, from: Address, amount: U256) -> Result<()> {
        self.validated_schema_version()?;
        self.require_not_paused()?;
        self.require_nonzero(spender)?;
        self.require_nonzero(from)?;
        self.require_nonzero_amount(amount)?;
        self.require_can_send(from)?;

        let key = allowance_key(from, spender);
        let allowance = self.allowances.read(&key)?;
        if allowance < amount {
            return Err(StablecoinStateError::InsufficientAllowance {
                owner: from,
                spender,
                available: allowance,
                required: amount,
            }
            .into());
        }
        let balance = self.balances.read(&from)?;
        if balance < amount {
            return Err(StablecoinStateError::InsufficientBalance {
                account: from,
                available: balance,
                required: amount,
            }
            .into());
        }
        self.require_unfrozen(from, balance, amount)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.burn_core(from, amount)?;
            if allowance != U256::MAX {
                self.allowances.write(&key, allowance - amount)?;
            }
            Ok(())
        })
    }

    pub fn forced_transfer(
        &mut self,
        actor: Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<()> {
        self.require_role(crate::schema::ENFORCER_ROLE, actor)?;
        self.require_not_paused()?;
        self.require_nonzero(from)?;
        self.require_nonzero(to)?;
        self.require_nonzero_amount(amount)?;
        if from == to {
            return Err(StablecoinStateError::ForcedSelfTransfer.into());
        }
        self.require_can_receive(to)?;
        let from_balance = self.balances.read(&from)?;
        if from_balance < amount {
            return Err(StablecoinStateError::InsufficientBalance {
                account: from,
                available: from_balance,
                required: amount,
            }
            .into());
        }
        let to_balance = self.balances.read(&to)?;
        let next_to = to_balance.checked_add(amount).ok_or_else(|| {
            PrecompileError::Fatal("stablecoin forced-transfer recipient overflow".into())
        })?;
        let frozen = self.frozen.read(&from)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.consume_frozen(from, from_balance, frozen, amount)?;
            self.balances.write(&from, from_balance - amount)?;
            self.balances.write(&to, next_to)?;
            self.emit(IStablecoin::Transfer {
                from,
                to,
                value: amount,
            })?;
            self.emit(IStablecoin::ForcedTransfer { from, to, amount })
        })?;
        Ok(())
    }

    pub fn transfer_with_memo(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.with_memo(from, to, amount, memo, |token| {
            token.transfer(from, to, amount)
        })
    }

    pub fn transfer_from_with_memo(
        &mut self,
        spender: Address,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.with_memo(from, to, amount, memo, |token| {
            token.transfer_from(spender, from, to, amount)
        })
    }

    pub fn mint_with_memo(
        &mut self,
        actor: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.with_memo(Address::ZERO, to, amount, memo, |token| {
            token.mint(actor, to, amount)
        })
    }

    pub fn burn_with_memo(&mut self, actor: Address, amount: U256, memo: B256) -> Result<()> {
        self.with_memo(actor, Address::ZERO, amount, memo, |token| {
            token.burn(actor, amount)
        })
    }

    pub fn burn_from_with_memo(
        &mut self,
        spender: Address,
        from: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.with_memo(from, Address::ZERO, amount, memo, |token| {
            token.burn_from(spender, from, amount)
        })
    }

    pub fn forced_transfer_with_memo(
        &mut self,
        actor: Address,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
    ) -> Result<()> {
        self.with_memo(from, to, amount, memo, |token| {
            token.forced_transfer(actor, from, to, amount)
        })
    }

    pub(crate) fn mint_core(&mut self, to: Address, amount: U256) -> Result<()> {
        self.validated_schema_version()?;
        self.require_nonzero(to)?;
        self.require_nonzero_amount(amount)?;

        let supply = self.total_supply.read()?;
        let supply_cap = self.supply_cap.read()?;
        if supply > supply_cap {
            return Err(PrecompileError::Fatal(
                "stablecoin total supply exceeds its stored cap".into(),
            ));
        }
        let requested_supply = supply.checked_add(amount).ok_or_else(|| {
            PrecompileError::from(StablecoinStateError::SupplyCapExceeded {
                supply_cap,
                requested_supply: U256::MAX,
            })
        })?;
        if requested_supply > supply_cap {
            return Err(StablecoinStateError::SupplyCapExceeded {
                supply_cap,
                requested_supply,
            }
            .into());
        }
        let balance = self.balances.read(&to)?;
        let next_balance = balance
            .checked_add(amount)
            .ok_or_else(|| PrecompileError::Fatal("stablecoin balance overflow".into()))?;

        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.total_supply.write(requested_supply)?;
            self.balances.write(&to, next_balance)?;
            self.emit(IStablecoin::Transfer {
                from: Address::ZERO,
                to,
                value: amount,
            })
        })
    }

    pub(crate) fn burn_core(&mut self, from: Address, amount: U256) -> Result<()> {
        self.validated_schema_version()?;
        self.require_nonzero(from)?;
        self.require_nonzero_amount(amount)?;
        let balance = self.balances.read(&from)?;
        if balance < amount {
            return Err(StablecoinStateError::InsufficientBalance {
                account: from,
                available: balance,
                required: amount,
            }
            .into());
        }
        let supply = self.total_supply.read()?;
        let next_supply = supply.checked_sub(amount).ok_or_else(|| {
            PrecompileError::Fatal("stablecoin supply/balance invariant is corrupted".into())
        })?;

        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            self.balances.write(&from, balance - amount)?;
            self.total_supply.write(next_supply)?;
            self.emit(IStablecoin::Transfer {
                from,
                to: Address::ZERO,
                value: amount,
            })
        })
    }

    fn require_nonzero(&self, account: Address) -> Result<()> {
        if account == Address::ZERO {
            return Err(StablecoinStateError::InvalidAddress { account }.into());
        }
        Ok(())
    }

    fn require_nonzero_amount(&self, amount: U256) -> Result<()> {
        if amount.is_zero() {
            return Err(StablecoinStateError::InvalidAmount.into());
        }
        Ok(())
    }

    fn require_not_paused(&self) -> Result<()> {
        if self.paused.read()? {
            return Err(StablecoinStateError::TokenPaused.into());
        }
        Ok(())
    }

    fn require_role(&self, role: B256, caller: Address) -> Result<()> {
        if !self.has_role(role, caller)? {
            return Err(StablecoinStateError::Unauthorized { role, caller }.into());
        }
        Ok(())
    }

    fn validate_allowance_update(
        &self,
        owner: Address,
        spender: Address,
        value: U256,
    ) -> Result<()> {
        let current = self.allowances.read(&allowance_key(owner, spender))?;
        if !self.frozen.read(&owner)?.is_zero() && value > current {
            return Err(StablecoinStateError::FrozenAllowanceIncrease {
                owner,
                current_allowance: current,
                requested_allowance: value,
            }
            .into());
        }
        Ok(())
    }

    fn write_approval(&mut self, owner: Address, spender: Address, value: U256) -> Result<()> {
        self.allowances
            .write(&allowance_key(owner, spender), value)?;
        self.emit(IStablecoin::Approval {
            owner,
            spender,
            value,
        })
    }

    fn with_memo(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
        memo: B256,
        operation: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            operation(self)?;
            self.emit(IStablecoin::TransferWithMemo {
                from,
                to,
                amount,
                memo,
            })
        })
    }

    fn require_can_send(&self, account: Address) -> Result<()> {
        let policy_id = self.policy_id.read()?;
        if !policy_can_send(self.storage.clone(), policy_id, account)? {
            return Err(StablecoinStateError::ERC7943CannotSend { account }.into());
        }
        Ok(())
    }

    fn require_can_receive(&self, account: Address) -> Result<()> {
        let policy_id = self.policy_id.read()?;
        if !policy_can_receive(self.storage.clone(), policy_id, account)? {
            return Err(StablecoinStateError::ERC7943CannotReceive { account }.into());
        }
        Ok(())
    }

    fn require_can_mint(&self, account: Address) -> Result<()> {
        let policy_id = self.policy_id.read()?;
        if !policy_can_mint(self.storage.clone(), policy_id, account)? {
            return Err(StablecoinStateError::ERC7943CannotReceive { account }.into());
        }
        Ok(())
    }

    fn require_unfrozen(&self, account: Address, balance: U256, amount: U256) -> Result<()> {
        let available = Self::unfrozen(balance, self.frozen.read(&account)?);
        if amount > available {
            return Err(StablecoinStateError::ERC7943InsufficientUnfrozenBalance {
                account,
                amount,
                unfrozen: available,
            }
            .into());
        }
        Ok(())
    }

    fn consume_frozen(
        &mut self,
        account: Address,
        balance: U256,
        frozen: U256,
        amount: U256,
    ) -> Result<()> {
        let available = Self::unfrozen(balance, frozen);
        let consumed = if amount > available {
            amount - available
        } else {
            U256::ZERO
        };
        if consumed.is_zero() {
            return Ok(());
        }
        let next_frozen = frozen.checked_sub(consumed).ok_or_else(|| {
            PrecompileError::Fatal("stablecoin frozen-balance invariant is corrupted".into())
        })?;
        self.frozen.write(&account, next_frozen)?;
        self.emit(IStablecoin::Frozen {
            account,
            amount: next_frozen,
        })
    }

    fn unfrozen(balance: U256, frozen: U256) -> U256 {
        balance.saturating_sub(frozen)
    }

    fn require_operational_role(&self, role: B256) -> Result<()> {
        if !OPERATIONAL_ROLES.contains(&role) {
            return Err(StablecoinStateError::UnsupportedRole { role }.into());
        }
        Ok(())
    }

    fn validate_pristine_root(&self) -> Result<()> {
        for slot in 1..ROOT_SLOT_COUNT {
            if !self
                .storage
                .sload(self.address, U256::from(slot))?
                .is_zero()
            {
                return Err(StablecoinStateError::NonPristineRoot { slot }.into());
            }
        }
        Ok(())
    }

    fn validate_initialization(&self, initialization: &FactoryTokenInitialization) -> Result<()> {
        if initialization.token_address != self.address
            || initialization.token_address == Address::ZERO
            || initialization.token_id == B256::ZERO
        {
            return Err(StablecoinStateError::InvalidInitializationIdentity.into());
        }

        // This validates all immutable metadata fields even when a trusted Rust
        // caller constructed StablecoinCreatePayload directly.
        encode_canonical_stablecoin_create(&initialization.payload)
            .map_err(|_| StablecoinStateError::InvalidInitializationIdentity)?;

        let chain_id = self.storage.chain_id()?;
        let expected_id = stablecoin_token_id(
            chain_id,
            STABLECOIN_FACTORY_ADDRESS,
            initialization.payload.issuer,
            &initialization.payload.ticker,
        )
        .map_err(|_| StablecoinStateError::InvalidInitializationIdentity)?;
        let expected_address = stablecoin_address(expected_id, STABLECOIN_ADDRESS_PREFIX);
        if expected_id != initialization.token_id || expected_address != self.address {
            return Err(StablecoinStateError::InvalidInitializationIdentity.into());
        }
        if !policy_exists(self.storage.clone(), initialization.payload.policy_id)? {
            return Err(StablecoinStateError::UnknownInitializationPolicy {
                policy_id: initialization.payload.policy_id,
            }
            .into());
        }
        Ok(())
    }
}

fn recover_permit_signer(digest: B256, v: u8, r: B256, s: B256) -> Result<Address> {
    let recovery_id = match v {
        27 | 28 => RecoveryId::from_byte(v - 27),
        _ => None,
    }
    .ok_or_else(|| PrecompileError::from(StablecoinStateError::InvalidPermitSignature))?;

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(r.as_slice());
    signature_bytes[32..].copy_from_slice(s.as_slice());
    let signature = EcdsaSignature::from_slice(&signature_bytes)
        .map_err(|_| PrecompileError::from(StablecoinStateError::InvalidPermitSignature))?;
    if signature.normalize_s().is_some() {
        return Err(StablecoinStateError::InvalidPermitSignature.into());
    }
    let verifying_key =
        VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recovery_id)
            .map_err(|_| PrecompileError::from(StablecoinStateError::InvalidPermitSignature))?;
    let encoded = verifying_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    let hash = keccak256(&public_key[1..]);
    Ok(Address::from_slice(&hash[12..]))
}
