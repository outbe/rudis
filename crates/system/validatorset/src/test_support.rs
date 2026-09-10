//! Shared test setup that reaches ACTIVE state only through the production
//! certified-boundary hook.
//!
//! This module is deliberately feature-gated. Production callers must use the
//! named lifecycle commands in [`crate::runtime`], while cross-crate tests use
//! semantic fixture seams without receiving raw storage-slot handles.

use alloy_primitives::{keccak256, Address, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, Signature, SigningKey};
use outbe_ocomp_protocol::{
    committee::{
        validator_identity_hash_v1, OcompKeyRegistrationCoreV1, OcompKeyRegistrationV1,
        POC_KEY_EPOCH, RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    profile::poc_schema_limits,
};
use outbe_primitives::error::{PrecompileError, Result};

use crate::{
    hooks::{activate_boundary_atomic, BoundaryActivationInputs},
    runtime::status,
    schema::ValidatorSet,
    state::{CommitteeEntry, CommitteeSnapshot},
    state_machine::{self, StakeProjection, ValidatorHistory, ValidatorLifecycle},
    EpochSnapshot,
};

const TEST_OCOMP_KEY_DOMAIN: &[u8] = b"OUTBE_TEST_OCOMP_KEY_V1";

fn test_ocomp_signing_key(identity: B256) -> Result<SigningKey> {
    let mut preimage = Vec::with_capacity(TEST_OCOMP_KEY_DOMAIN.len() + 32);
    preimage.extend_from_slice(TEST_OCOMP_KEY_DOMAIN);
    preimage.extend_from_slice(identity.as_slice());
    let mut candidate = keccak256(preimage).0;
    for _ in 0..16 {
        if let Ok(key) = SigningKey::from_bytes((&candidate).into()) {
            return Ok(key);
        }
        candidate = keccak256(candidate).0;
    }
    Err(PrecompileError::Fatal(
        "failed to derive deterministic test OCOMP signing key".into(),
    ))
}

fn test_ocomp_registration(
    validator: Address,
    consensus_pubkey: &[u8; 48],
    chain_id: u64,
    genesis_hash: B256,
) -> Result<Vec<u8>> {
    let identity = validator_identity_hash_v1(validator, consensus_pubkey).map_err(|error| {
        PrecompileError::Fatal(format!("cannot derive test validator identity: {error}"))
    })?;
    let signing_key = test_ocomp_signing_key(identity)?;
    let mut registration = OcompKeyRegistrationV1 {
        core: OcompKeyRegistrationCoreV1 {
            chain_id,
            genesis_hash,
            validator_identity_hash: identity,
            ocomp_public_key_sec1: signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .map_err(|_| {
                    PrecompileError::Fatal("test OCOMP SEC1 key is not 33 bytes".into())
                })?,
            key_epoch: POC_KEY_EPOCH,
            allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
        },
        proof_of_possession: [0; 64],
    };
    let limits = poc_schema_limits();
    let digest = registration
        .proof_of_possession_digest(&limits)
        .map_err(|error| PrecompileError::Fatal(format!("test OCOMP PoP digest: {error}")))?;
    let signature: Signature = signing_key
        .sign_prehash(digest.as_slice())
        .map_err(|error| PrecompileError::Fatal(format!("test OCOMP PoP signing: {error}")))?;
    registration.proof_of_possession = signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into();
    registration
        .encode_canonical(&limits)
        .map_err(|error| PrecompileError::Fatal(format!("test OCOMP registration encode: {error}")))
}

/// Move one registered test validator through the real admission transitions,
/// stopping at confirmed PENDING so a separately-constructed boundary artifact
/// can promote it.
pub fn admit_validator_for_boundary(
    validators: &mut ValidatorSet<'_>,
    validator: Address,
) -> Result<()> {
    let record = validators
        .get_validator(validator)?
        .ok_or_else(|| PrecompileError::Revert("test validator is not registered".into()))?;
    match record.status {
        status::REGISTERED => validators.mark_pending(validator)?,
        status::PENDING | status::ACTIVE => {}
        other => {
            return Err(PrecompileError::Revert(format!(
                "test boundary activation cannot admit validator status {other}"
            )))
        }
    }

    if validators.val_status.read(&validator)? == status::PENDING
        && !validators.val_join_confirmed.read(&validator)?
    {
        let encoded = match validators.ocomp_registration(validator)? {
            Some(registration) => registration
                .encode_canonical(&poc_schema_limits())
                .map_err(|error| {
                    PrecompileError::Fatal(format!(
                        "stored test OCOMP registration encode: {error}"
                    ))
                })?,
            None => test_ocomp_registration(
                validator,
                &record.consensus_pubkey,
                validators.storage.chain_id()?,
                validators.storage.genesis_hash()?,
            )?,
        };
        validators.confirm_validator_ready(validator, &encoded)?;
    }
    Ok(())
}

/// Promote one registered test validator by running the same atomic boundary
/// hook used by production. Existing active validators remain in the incoming
/// set; participant order is the canonical BLS-public-key order.
pub fn activate_validator_via_boundary(
    validators: &mut ValidatorSet<'_>,
    validator: Address,
) -> Result<B256> {
    admit_validator_for_boundary(validators, validator)?;

    let mut incoming: Vec<_> = validators
        .get_active_consensus_set()?
        .into_iter()
        .filter(|member| member.status == status::ACTIVE)
        .collect();
    if !incoming
        .iter()
        .any(|member| member.validator_address == validator)
    {
        incoming.push(
            validators
                .get_validator(validator)?
                .ok_or_else(|| PrecompileError::Fatal("test validator disappeared".into()))?,
        );
    }
    incoming.sort_by_key(|member| member.consensus_pubkey);
    let new_active_set: Vec<Address> = incoming
        .iter()
        .map(|member| member.validator_address)
        .collect();
    let snapshot = CommitteeSnapshot {
        committee: incoming
            .iter()
            .map(|member| CommitteeEntry {
                address: member.validator_address,
                consensus_pubkey: member.consensus_pubkey,
            })
            .collect(),
        vrf_material_version: 0,
        vrf_group_public_key_bytes: Vec::new(),
        vrf_public_polynomial_hash: B256::ZERO,
    };
    let mut active_hash_preimage = Vec::with_capacity(8 + new_active_set.len() * 20);
    active_hash_preimage.extend_from_slice(&(new_active_set.len() as u64).to_be_bytes());
    for address in &new_active_set {
        active_hash_preimage.extend_from_slice(address.as_slice());
    }
    let active_set_hash = keccak256(active_hash_preimage);
    let incoming_epoch = validators.current_epoch_u64()?;
    let freeze_height = validators.storage.block_number()?;
    let storage = validators.storage.clone();
    let (_, incoming_key) = activate_boundary_atomic(
        storage,
        &BoundaryActivationInputs {
            outgoing: None,
            incoming_epoch,
            incoming: snapshot,
            freeze_height,
            new_active_set,
            active_set_hash,
            tee_expired_target_exclusions: Vec::new(),
        },
    )?;
    Ok(incoming_key)
}

impl ValidatorSet<'_> {
    /// Admission-only form for tests whose subject is a separately encoded
    /// certified boundary artifact.
    pub fn admit_validator_for_boundary_for_test(&mut self, validator: Address) -> Result<()> {
        admit_validator_for_boundary(self, validator)
    }

    /// Inherent form used to migrate legacy workspace fixtures without giving
    /// each crate its own activation setup.
    pub fn activate_validator_via_boundary_for_test(&mut self, validator: Address) -> Result<B256> {
        activate_validator_via_boundary(self, validator)
    }
}

impl ValidatorSet<'_> {
    /// Registers a fixture through the explicit bootstrap-only no-PoP seam.
    ///
    /// The underlying registration path is unavailable in production builds;
    /// ordinary callers must submit a valid proof of possession.
    pub fn test_register_validator_without_pop(
        &mut self,
        validator: Address,
        consensus_pubkey: &[u8; 48],
    ) -> Result<()> {
        let owner = self.config_owner.read()?;
        self.register_validator(owner, validator, consensus_pubkey)
    }

    /// Moves a registered fixture through the canonical typed join path.
    ///
    /// This intentionally does not expose constructors for lifecycle payloads:
    /// identity, P2P data and history are carried forward from the current
    /// registered state by the real transition functions.
    pub fn test_activate_validator_canonically(
        &mut self,
        address: Address,
        stake: StakeProjection,
        minimum: U256,
    ) -> Result<()> {
        if stake.bonded() < minimum {
            return Err(PrecompileError::Revert(format!(
                "fixture activation stake {} is below minimum {minimum}",
                stake.bonded()
            )));
        }

        let before = self.validator_state(address)?;
        let with_stake = state_machine::with_stake(before.lifecycle().clone(), stake)?;
        let active = match with_stake {
            ValidatorLifecycle::WaitingForStake(waiting) => {
                let waiting = state_machine::reach_minimum(waiting, stake, minimum)?;
                state_machine::activate_at_boundary(state_machine::confirm_ready(waiting))
            }
            ValidatorLifecycle::WaitingForReadiness(waiting) => {
                state_machine::activate_at_boundary(state_machine::confirm_ready(waiting))
            }
            ValidatorLifecycle::Joining(joining) => state_machine::activate_at_boundary(joining),
            ValidatorLifecycle::Active(active) => active,
            lifecycle => {
                return Err(PrecompileError::Revert(format!(
                    "fixture activation requires a join-path lifecycle, got status {:?}",
                    lifecycle.stored_status()
                )));
            }
        };
        let after = before
            .clone()
            .with_lifecycle(ValidatorLifecycle::Active(active))?;
        self.persist_validator_state_delta(&before, &after)
    }

    /// Calls the consensus-validated boundary seam from a test without
    /// exposing it in production or falling back to the legacy owner path.
    pub fn test_activate_validated_boundary_set(
        &mut self,
        new_active_set: &[Address],
        active_set_hash: B256,
        freeze_height: u64,
    ) -> Result<()> {
        self.activate_validated_boundary_set(new_active_set, active_set_hash, freeze_height)
    }

    /// Calls the consensus-validated boundary seam with certified TEE-expiry
    /// exclusions from a test without exposing it in production.
    pub fn test_activate_validated_boundary_set_with_expiry_exclusions(
        &mut self,
        new_active_set: &[Address],
        active_set_hash: B256,
        freeze_height: u64,
        tee_expired_target_exclusions: &[Address],
    ) -> Result<()> {
        self.activate_validated_boundary_set_with_expiry_exclusions(
            new_active_set,
            active_set_hash,
            freeze_height,
            tee_expired_target_exclusions,
        )
    }

    /// Replaces the ValidatorSet stake mirror; Staking remains authoritative.
    pub fn test_set_stake_projection(
        &mut self,
        address: Address,
        stake: StakeProjection,
    ) -> Result<()> {
        let before = self.validator_state(address)?;
        let lifecycle = state_machine::with_stake(before.lifecycle().clone(), stake)?;
        let after = before.clone().with_lifecycle(lifecycle)?;
        self.persist_validator_state_delta(&before, &after)
    }

    /// Replaces retained historical counters/heights for a registered fixture.
    pub fn test_set_history(&mut self, address: Address, history: ValidatorHistory) -> Result<()> {
        let before = self.validator_state(address)?;
        if !before.is_registered() {
            return Err(PrecompileError::Fatal(
                "test fixture history requires a registered validator".into(),
            ));
        }
        let lifecycle = state_machine::with_history(before.lifecycle().clone(), history)?;
        let after = before.clone().with_lifecycle(lifecycle)?;
        self.persist_validator_state_delta(&before, &after)
    }

    /// Replaces epoch metadata as one test fixture bundle.
    pub fn test_set_epoch_snapshot(&mut self, epoch: EpochSnapshot) -> Result<()> {
        self.epoch_number.write(epoch.number)?;
        self.epoch_start_timestamp.write(epoch.start_timestamp)?;
        self.epoch_start_block.write(epoch.start_block)?;
        self.config_epoch_length_blocks.write(epoch.length_blocks)
    }

    pub fn test_set_pending_set_change(&mut self, pending: bool) -> Result<()> {
        self.pending_set_change.write(pending)
    }

    pub fn test_set_active_consensus_set_hash(&mut self, hash: B256) -> Result<()> {
        self.active_consensus_set_hash.write(hash)
    }

    /// Deliberately installs malformed P2P storage for a fail-closed corruption
    /// test. Normal fixtures must use `set_p2p_address`.
    pub fn test_corrupt_p2p_storage(
        &mut self,
        address: Address,
        version: u8,
        payload: &[u8],
    ) -> Result<()> {
        self.val_p2p_address_version.write(&address, version)?;
        self.val_p2p_address_payload
            .get_bytes(&address)
            .write(payload)
    }
}
