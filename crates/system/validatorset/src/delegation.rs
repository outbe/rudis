use alloy_primitives::Address;
use outbe_primitives::error::{PrecompileError, Result};

use crate::{precompile::IValidatorSet, runtime::status, schema::ValidatorSet};

/// Stable protocol role identifiers for validator-owned operational keys.
///
/// Adding a role is a protocol change: unknown ids remain rejected until every
/// consumer knows the role's exact authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ValidatorDelegateRole {
    Oracle = 1,
    Ocomp = 2,
}

impl ValidatorDelegateRole {
    pub const ALL: [Self; 2] = [Self::Oracle, Self::Ocomp];

    pub const fn id(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ValidatorDelegateRole {
    type Error = PrecompileError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Oracle),
            2 => Ok(Self::Ocomp),
            _ => Err(PrecompileError::Revert(
                "unsupported validator delegate role".into(),
            )),
        }
    }
}

impl ValidatorSet<'_> {
    /// Assigns one operational key to the caller's validator identity for
    /// exactly one role.
    ///
    /// This does not grant validator lifecycle, stake, governance, reward, or
    /// further delegation authority. Those modules continue to authorize the
    /// validator address directly.
    pub fn set_delegate(
        &mut self,
        validator: Address,
        role: ValidatorDelegateRole,
        delegate: Address,
    ) -> Result<()> {
        self.ensure_registered_validator(validator)?;
        if delegate.is_zero() {
            return Err(PrecompileError::Revert(
                "delegate address must not be zero".into(),
            ));
        }
        if delegate == validator {
            return Err(PrecompileError::Revert(
                "delegate must differ from validator".into(),
            ));
        }
        if self.get_validator(delegate)?.is_some() {
            return Err(PrecompileError::Revert(
                "delegate must not be a registered validator".into(),
            ));
        }

        let role_id = role.id();
        let reverse = self.validator_by_role_delegate.get_nested(&role_id);
        let assigned_validator = reverse.read(&delegate)?;
        if !assigned_validator.is_zero() && assigned_validator != validator {
            return Err(PrecompileError::Revert(
                "delegate already assigned for role".into(),
            ));
        }

        let forward = self.delegate_by_validator_role.get_nested(&validator);
        let previous = forward.read(&role_id)?;
        if previous == delegate {
            return Ok(());
        }

        if !previous.is_zero() {
            reverse.write(&previous, Address::ZERO)?;
        }
        forward.write(&role_id, delegate)?;
        reverse.write(&delegate, validator)?;

        self.emit(IValidatorSet::ValidatorDelegateSet {
            validator,
            role: role_id,
            delegate,
        })
    }

    /// Revokes the caller's explicit operational key for one role.
    ///
    /// Revocation is idempotent. With no explicit delegate, the active
    /// validator address remains the backwards-compatible signer for the role.
    pub fn revoke_delegate(
        &mut self,
        validator: Address,
        role: ValidatorDelegateRole,
    ) -> Result<()> {
        self.ensure_registered_validator(validator)?;

        let role_id = role.id();
        let forward = self.delegate_by_validator_role.get_nested(&validator);
        let previous = forward.read(&role_id)?;
        if previous.is_zero() {
            return Ok(());
        }

        forward.write(&role_id, Address::ZERO)?;
        self.validator_by_role_delegate
            .get_nested(&role_id)
            .write(&previous, Address::ZERO)?;

        self.emit(IValidatorSet::ValidatorDelegateRevoked {
            validator,
            role: role_id,
            delegate: previous,
        })
    }

    pub fn get_delegate(&self, validator: Address, role: ValidatorDelegateRole) -> Result<Address> {
        self.delegate_by_validator_role
            .get_nested(&validator)
            .read(&role.id())
    }

    /// Resolves an active consensus validator for a role-scoped signer.
    ///
    /// When an explicit delegate exists, the validator address itself is no
    /// longer accepted for that role. This preserves key separation while a
    /// revoked role falls back to the validator address for compatibility.
    pub fn resolve_validator_for_role(
        &self,
        signer: Address,
        role: ValidatorDelegateRole,
    ) -> Result<Option<Address>> {
        if let Some(record) = self.get_validator(signer)? {
            let explicit = self.get_delegate(signer, role)?;
            if explicit.is_zero() && record.status == status::ACTIVE && record.has_bls_share {
                return Ok(Some(signer));
            }
            return Ok(None);
        }

        let validator = self
            .validator_by_role_delegate
            .get_nested(&role.id())
            .read(&signer)?;
        if validator.is_zero() || self.get_delegate(validator, role)? != signer {
            return Ok(None);
        }

        let Some(record) = self.get_validator(validator)? else {
            return Ok(None);
        };
        if record.status != status::ACTIVE || !record.has_bls_share {
            return Ok(None);
        }
        Ok(Some(validator))
    }

    fn ensure_registered_validator(&self, validator: Address) -> Result<()> {
        if self.get_validator(validator)?.is_none() {
            return Err(PrecompileError::Revert(
                "caller is not a registered validator".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure_not_operational_delegate(&self, address: Address) -> Result<()> {
        for role in ValidatorDelegateRole::ALL {
            let validator = self
                .validator_by_role_delegate
                .get_nested(&role.id())
                .read(&address)?;
            if !validator.is_zero() {
                return Err(PrecompileError::Revert(
                    "validator address is already assigned as an operational delegate".into(),
                ));
            }
        }
        Ok(())
    }
}
