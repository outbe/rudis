use std::{
    collections::{BTreeSet, HashSet},
    num::NonZeroU64,
};

use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_ocomp_protocol::{
    committee::{validator_identity_hash_v1, OcompKeyRegistrationV1},
    profile::poc_schema_limits,
};
use outbe_primitives::consensus_p2p::{
    decode_versioned, MAX_P2P_ADDRESS_ENCODED_LEN, P2P_ADDRESS_VERSION_V1,
};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::slashing_journal::{iso8601_now, record as journal_record, JournalRecord};
use outbe_primitives::validators::{validator_registration_message, VALIDATOR_REGISTRATION_DST};
use tracing::{info, warn};

use crate::precompile::IValidatorSet;
use crate::schema::ValidatorSet;
use crate::state_machine::{
    self, P2pInfo, StakeProjection, ValidatorHistory, ValidatorLifecycle, ValidatorState,
};

/// Stable ABI status constants. The effective Rust states are richer: PENDING
/// distinguishes readiness from joining, and JAILED distinguishes retained from
/// boundary-excluded. See [`ValidatorLifecycle`].
pub mod status {
    pub const REGISTERED: u8 = 0;
    pub const PENDING: u8 = 1;
    pub const ACTIVE: u8 = 2;
    pub const EXITING: u8 = 3;
    pub const UNBONDING: u8 = 4;
    pub const INACTIVE: u8 = 5;
    pub const JAILED: u8 = 6;
}

/// maximum number of validators that may be in the `REGISTERED`
/// (self-registered, not-yet-staked) state at once.
///
/// `REGISTERED` self-registration is permissionless and free on the ZeroFee
/// chain, and a `REGISTERED` node is intentionally admitted to the consensus
/// P2P secondary tier so a TEE verifier full-node can sync and execute offer
/// blocks before staking (see
/// [`ValidatorSet::get_admitted_non_consensus_validators`]). That admission is
/// by design, but without a bound an attacker can self-register up to
/// `config_max_validators` free Sybil identities - consuming registration slots
/// (griefing legitimate staked joins with "max validators reached") and
/// consensus-P2P connection / handshake / decode slots. This caps the unstaked
/// self-registration surface well below `config_max_validators` (default 128),
/// so legitimate verifiers (few) still register while Sybils cannot fill the
/// validator set. The owner (`config_owner`) is NOT subject to this cap and may
/// register validators directly beyond it.
pub const MAX_SELF_REGISTERED_UNSTAKED: u32 = 32;

/// Canonical committee/codec bound shared by every validator-registry scan.
/// This is not a configurable product capacity.
pub const CONSENSUS_VALIDATOR_BOUND: u32 = outbe_consensus::bls::MAX_VALIDATORS;

/// One day at the protocol's two-second block target. This is a recovery
/// deadline, not a polling interval: the recovery sweep runs every block.
pub const OCOMP_RECOVERY_WINDOW_BLOCKS: u64 = 43_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcompMissRecord {
    Opened {
        miss_count: u64,
        recovery_deadline: u64,
    },
    Repeated {
        miss_count: u64,
        recovery_deadline: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcompRecoveryWindow {
    pub miss_count: u64,
    pub recovery_deadline: u64,
}

/// Non-transactional observability produced by a committed punitive validator
/// transition. Callers that wrap the transition in a wider checkpoint defer
/// this report until that outer checkpoint commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredValidatorPunishment {
    addr: Address,
    target: u8,
    target_label: &'static str,
    jailed: bool,
    block_number: u64,
}

impl DeferredValidatorPunishment {
    pub fn record(self) {
        crate::metrics::record_validator_status(self.addr, self.target);
        crate::metrics::record_validator_force_exit(self.addr);
        crate::metrics::record_pending_set_change(true);
        journal_record(JournalRecord::ValidatorForcedExit {
            wall_clock: iso8601_now(),
            block_number: self.block_number,
            validator: format!("{:?}", self.addr),
            status_before: "ACTIVE".into(),
            status_after: self.target_label.into(),
        });
        warn!(
            target: "outbe::validatorset",
            event = if self.jailed { "validator_jailed" } else { "validator_force_exit" },
            validator = %self.addr,
            status_after = self.target_label,
            block_number = self.block_number,
            "validator punished from ACTIVE (force-exit/jail)",
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OcompRecoveryOutcome {
    Restored = 1,
    Jailed = 2,
    NonActive = 3,
}

/// Legacy flat read/ABI projection.
///
/// Lifecycle decisions must use [`ValidatorState`] or [`ValidatorLifecycle`].
/// This shape remains public for compatibility with existing Rust consumers
/// and the Solidity `validatorByAddress` / `validatorByIndex` tuples.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorRecord {
    pub validator_address: Address,
    /// 48-byte BLS MinPk consensus public key.
    pub consensus_pubkey: [u8; 48],
    pub stake: U256,
    pub status: u8,
    pub slash_count: u64,
    pub missed_blocks: u64,
    pub missed_votes: u64,
    pub blocks_proposed: u64,
    pub joined_at_height: u64,
    pub deactivated_at_height: u64,
    pub unbonding_end: u64,
    pub has_bls_share: bool,
}

impl ValidatorSet<'_> {
    /// Store the configured validator cap only when it fits the canonical
    /// consensus codec/committee bound. OCOMP reads this consensus limit and
    /// does not define a second participant ceiling.
    pub fn set_config_max_validators(&mut self, max_validators: u32) -> Result<()> {
        if max_validators > CONSENSUS_VALIDATOR_BOUND {
            return Err(PrecompileError::Revert(format!(
                "max validators exceeds consensus bound: {max_validators} > {}",
                CONSENSUS_VALIDATOR_BOUND
            )));
        }
        self.config_max_validators.write(max_validators)
    }

    /// Returns the canonical OCOMP registration admitted for `addr`.
    /// Stored bytes that no longer decode are consensus-state corruption.
    pub fn ocomp_registration(&self, addr: Address) -> Result<Option<OcompKeyRegistrationV1>> {
        let bytes = self.val_ocomp_registration.get_bytes(&addr).read()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        OcompKeyRegistrationV1::decode_canonical(&bytes, &poc_schema_limits())
            .map(Some)
            .map_err(|error| {
                PrecompileError::Fatal(format!(
                    "stored OCOMP registration for {addr} is invalid: {error}"
                ))
            })
    }
}

/// Read-only epoch metadata exposed without leaking raw storage slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSnapshot {
    pub number: U256,
    pub start_timestamp: u64,
    pub start_block: u64,
    pub length_blocks: u32,
}

/// Read-only participation counters exposed independently of lifecycle writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidatorParticipation {
    pub blocks_proposed: u64,
    pub missed_blocks: u64,
    pub missed_votes: u64,
}

fn registered_status(lifecycle: &ValidatorLifecycle) -> Result<u8> {
    lifecycle.stored_status().ok_or_else(|| {
        PrecompileError::Fatal("Unregistered lifecycle has no persisted status".into())
    })
}

impl ValidatorSet<'_> {
    /// Reads the 48-byte BLS MinPk consensus pubkey from two storage slots.
    fn read_consensus_pubkey(&self, addr: &Address) -> Result<[u8; 48]> {
        let lo: B256 = self.val_consensus_pubkey_lo.read(addr)?;
        let hi: B256 = self.val_consensus_pubkey_hi.read(addr)?;
        let mut pubkey = [0u8; 48];
        pubkey[..32].copy_from_slice(&lo.0);
        pubkey[32..48].copy_from_slice(&hi.0[..16]);
        Ok(pubkey)
    }

    /// Writes the 48-byte BLS MinPk consensus pubkey across two storage slots.
    fn write_consensus_pubkey(&mut self, addr: &Address, pubkey: &[u8; 48]) -> Result<()> {
        let lo = B256::from_slice(&pubkey[..32]);
        let mut hi_bytes = [0u8; 32];
        hi_bytes[..16].copy_from_slice(&pubkey[32..48]);
        let hi = B256::from(hi_bytes);
        self.val_consensus_pubkey_lo.write(addr, lo)?;
        self.val_consensus_pubkey_hi.write(addr, hi)?;
        Ok(())
    }

    /// Returns the complete typed state for an address.
    ///
    /// Unlike [`Self::get_validator`], this also represents an absent address as
    /// [`ValidatorLifecycle::Absent`]. Unknown status bytes and malformed coupled
    /// storage fail closed.
    pub fn validator_state(&self, addr: Address) -> Result<ValidatorState> {
        let registry_index = self.address_to_index.read(&addr)?;
        let stored_status = self.val_status.read(&addr)?;

        let consensus_pubkey = self.read_consensus_pubkey(&addr)?;
        let bonded = self.val_stake.read(&addr)?;
        let unbonding_end = self.val_unbonding_end.read(&addr)?;
        let stake = StakeProjection::new(bonded, (unbonding_end != 0).then_some(unbonding_end));
        let slash_count = self.val_slash_count.read(&addr)?;
        let missed_blocks = self.val_missed_blocks.read(&addr)?;
        let missed_votes = self.val_missed_votes.read(&addr)?;
        let blocks_proposed = self.val_blocks_proposed.read(&addr)?;
        let joined_at_height = self.val_joined_at_height.read(&addr)?;
        let deactivated_at_height = self.val_deactivated_at_height.read(&addr)?;
        let has_bls_share = self.val_has_bls_share.read(&addr)?;
        let join_confirmed = self.val_join_confirmed.read(&addr)?;
        let jailed_at = self.val_jailed_at_height.read(&addr)?;
        let p2p_version = self.val_p2p_address_version.read(&addr)?;
        let p2p_payload = self.val_p2p_address_payload.get_bytes(&addr).read()?;

        let history = ValidatorHistory::new(
            joined_at_height,
            (deactivated_at_height != 0).then_some(deactivated_at_height),
            slash_count,
            missed_blocks,
            missed_votes,
            blocks_proposed,
        );
        let state = ValidatorState::decode_stored(
            addr,
            registry_index,
            consensus_pubkey,
            stake,
            stored_status,
            p2p_version,
            &p2p_payload,
            history,
            has_bls_share,
            join_confirmed,
            jailed_at,
        )?;

        if let Some(index) = state.registry_index() {
            let index = index.get();
            let count = u64::from(self.validator_count.read()?);
            if index > count {
                return Err(PrecompileError::Fatal(format!(
                    "validator {addr} registry index {index} exceeds validator_count {count}"
                )));
            }
            let indexed_address = self.index_to_address.read(&index)?;
            if indexed_address != addr {
                return Err(PrecompileError::Fatal(format!(
                    "validator registry forward index mismatch at {index}: expected {addr}, got {indexed_address}"
                )));
            }
            let pubkey = state.consensus_pubkey().ok_or_else(|| {
                PrecompileError::Fatal("registered validator is missing consensus pubkey".into())
            })?;
            let pubkey_owner = self
                .consensus_pubkey_hash_to_address
                .read(&Self::consensus_pubkey_hash(pubkey))?;
            if pubkey_owner != addr {
                return Err(PrecompileError::Fatal(format!(
                    "validator consensus pubkey reverse mapping mismatch for {addr}: got {pubkey_owner}"
                )));
            }
        }

        Ok(state)
    }

    /// Returns the lifecycle from the fully validated validator aggregate.
    ///
    /// Hydrating the complete aggregate is intentional: lifecycle payloads own
    /// registry identity, stake, P2P data, and history, so every query observes
    /// the same coupled-field and index invariants.
    pub fn validator_lifecycle(&self, addr: Address) -> Result<ValidatorLifecycle> {
        Ok(self.validator_state(addr)?.into_lifecycle())
    }

    /// Writes only changed fields of an already-decoded validator aggregate.
    /// Registry identity is deliberately excluded: registration, re-registration,
    /// and cleanup own the dense-index and consensus-key invariants.
    pub(crate) fn persist_validator_state_delta(
        &mut self,
        before: &ValidatorState,
        after: &ValidatorState,
    ) -> Result<()> {
        self.persist_validator_state_delta_inner(before, after, false)
    }

    fn persist_registry_state_delta(
        &mut self,
        before: &ValidatorState,
        after: &ValidatorState,
    ) -> Result<()> {
        self.persist_validator_state_delta_inner(before, after, true)
    }

    fn persist_validator_state_delta_inner(
        &mut self,
        before: &ValidatorState,
        after: &ValidatorState,
        allow_registry_identity_change: bool,
    ) -> Result<()> {
        before.validate()?;
        after.validate()?;
        if before.address() != after.address()
            || (!allow_registry_identity_change
                && (before.registry_index() != after.registry_index()
                    || before.consensus_pubkey() != after.consensus_pubkey()))
        {
            return Err(PrecompileError::Fatal(
                "validator lifecycle transition attempted to change registry identity".into(),
            ));
        }

        if allow_registry_identity_change {
            let pubkey = after.consensus_pubkey().ok_or_else(|| {
                PrecompileError::Fatal("registered validator is missing consensus pubkey".into())
            })?;
            if after.registry_index().is_none() {
                return Err(PrecompileError::Fatal(
                    "registered validator is missing registry index".into(),
                ));
            }
            if before.consensus_pubkey() != Some(pubkey) {
                self.write_consensus_pubkey(&after.address(), pubkey)?;
            }
        }

        let addr = after.address();
        if before.bonded_stake() != after.bonded_stake() {
            self.val_stake.write(&addr, after.bonded_stake())?;
        }
        if before.stored_status() != after.stored_status() {
            let status = after.stored_status().ok_or_else(|| {
                PrecompileError::Fatal(
                    "generic validator persistence cannot write an absent lifecycle".into(),
                )
            })?;
            self.val_status.write(&addr, status)?;
        }

        let before_history = before.history();
        let after_history = after.history();
        let before_slash_count = before_history.map_or(0, ValidatorHistory::slash_count);
        let after_slash_count = after_history.map_or(0, ValidatorHistory::slash_count);
        if before_slash_count != after_slash_count {
            self.val_slash_count.write(&addr, after_slash_count)?;
        }
        let before_missed_blocks = before_history.map_or(0, ValidatorHistory::missed_blocks);
        let after_missed_blocks = after_history.map_or(0, ValidatorHistory::missed_blocks);
        if before_missed_blocks != after_missed_blocks {
            self.val_missed_blocks.write(&addr, after_missed_blocks)?;
        }
        let before_missed_votes = before_history.map_or(0, ValidatorHistory::missed_votes);
        let after_missed_votes = after_history.map_or(0, ValidatorHistory::missed_votes);
        if before_missed_votes != after_missed_votes {
            self.val_missed_votes.write(&addr, after_missed_votes)?;
        }
        let before_blocks_proposed = before_history.map_or(0, ValidatorHistory::blocks_proposed);
        let after_blocks_proposed = after_history.map_or(0, ValidatorHistory::blocks_proposed);
        if before_blocks_proposed != after_blocks_proposed {
            self.val_blocks_proposed
                .write(&addr, after_blocks_proposed)?;
        }
        let before_joined_at = before_history.map_or(0, ValidatorHistory::joined_at_height);
        let after_joined_at = after_history.map_or(0, ValidatorHistory::joined_at_height);
        if before_joined_at != after_joined_at {
            self.val_joined_at_height.write(&addr, after_joined_at)?;
        }
        let before_deactivated_at = before_history
            .and_then(ValidatorHistory::last_deactivated_at_height)
            .unwrap_or(0);
        let after_deactivated_at = after_history
            .and_then(ValidatorHistory::last_deactivated_at_height)
            .unwrap_or(0);
        if before_deactivated_at != after_deactivated_at {
            self.val_deactivated_at_height
                .write(&addr, after_deactivated_at)?;
        }
        let before_unbonding_end = before.unbonding_end_hint().unwrap_or(0);
        let after_unbonding_end = after.unbonding_end_hint().unwrap_or(0);
        if before_unbonding_end != after_unbonding_end {
            self.val_unbonding_end.write(&addr, after_unbonding_end)?;
        }
        if before.has_bls_share() != after.has_bls_share() {
            self.val_has_bls_share.write(&addr, after.has_bls_share())?;
        }
        if before.join_confirmed() != after.join_confirmed() {
            self.val_join_confirmed
                .write(&addr, after.join_confirmed())?;
        }
        if before.stored_jailed_at() != after.stored_jailed_at() {
            self.val_jailed_at_height
                .write(&addr, after.stored_jailed_at())?;
        }
        let before_p2p = before.p2p().map_or((0, Vec::new()), P2pInfo::encode_stored);
        let after_p2p = after.p2p().map_or((0, Vec::new()), P2pInfo::encode_stored);
        if before_p2p != after_p2p {
            self.val_p2p_address_version.write(&addr, after_p2p.0)?;
            if after_p2p.1.is_empty() {
                self.val_p2p_address_payload.get_bytes(&addr).clear()?;
            } else {
                self.val_p2p_address_payload
                    .get_bytes(&addr)
                    .write(&after_p2p.1)?;
            }
        }

        Ok(())
    }

    /// Returns the keccak256 hash of a 48-byte consensus pubkey (for reverse lookup).
    pub fn consensus_pubkey_hash(pubkey: &[u8; 48]) -> B256 {
        keccak256(pubkey)
    }

    fn read_validator_record(&self, addr: Address) -> Result<ValidatorRecord> {
        let state = self.validator_state(addr)?;
        let stored_status = state.stored_status().ok_or_else(|| {
            PrecompileError::Fatal("cannot project absent validator into ValidatorRecord".into())
        })?;
        let history = state.history().ok_or_else(|| {
            PrecompileError::Fatal("registered validator is missing history".into())
        })?;
        let consensus_pubkey = state.consensus_pubkey().copied().ok_or_else(|| {
            PrecompileError::Fatal("registered validator is missing consensus public key".into())
        })?;
        Ok(ValidatorRecord {
            validator_address: addr,
            consensus_pubkey,
            stake: state.bonded_stake(),
            status: stored_status,
            slash_count: history.slash_count(),
            missed_blocks: history.missed_blocks(),
            missed_votes: history.missed_votes(),
            blocks_proposed: history.blocks_proposed(),
            joined_at_height: history.joined_at_height(),
            deactivated_at_height: history.last_deactivated_at_height().unwrap_or(0),
            unbonding_end: state.unbonding_end_hint().unwrap_or(0),
            has_bls_share: state.has_bls_share(),
        })
    }

    /// Returns the full ABI-compatible record for a validator address, or
    /// `None` if it has no registry identity. Unknown status bytes fail closed.
    pub fn get_validator(&self, addr: Address) -> Result<Option<ValidatorRecord>> {
        if self.address_to_index.read(&addr)? == 0 {
            return Ok(None);
        }
        Ok(Some(self.read_validator_record(addr)?))
    }

    /// Returns all registered validators, including inactive and exiting ones.
    pub fn get_all_validators(&self) -> Result<Vec<ValidatorRecord>> {
        let addresses = self.registered_validator_addresses()?;
        let mut result = Vec::with_capacity(addresses.len());
        for addr in addresses {
            result.push(self.read_validator_record(addr)?);
        }
        Ok(result)
    }

    fn validator_addresses_matching(
        &self,
        predicate: impl Fn(&ValidatorLifecycle) -> bool,
    ) -> Result<Vec<Address>> {
        let mut result = Vec::new();
        for addr in self.registered_validator_addresses()? {
            if predicate(&self.validator_lifecycle(addr)?) {
                result.push(addr);
            }
        }
        Ok(result)
    }

    fn get_validators_matching(
        &self,
        predicate: impl Fn(&ValidatorLifecycle) -> bool,
    ) -> Result<Vec<ValidatorRecord>> {
        self.validator_addresses_matching(predicate)?
            .into_iter()
            .map(|addr| self.read_validator_record(addr))
            .collect()
    }

    /// Returns only validators with `status == ACTIVE`.
    pub fn get_active_validators(&self) -> Result<Vec<ValidatorRecord>> {
        self.get_validators_matching(ValidatorLifecycle::is_active_status)
    }

    /// Returns validators eligible for the NEXT consensus committee: `Active`
    /// plus readiness-confirmed `Joining`. `WaitingForReadiness`, `Exiting`, and
    /// both jailed phases are excluded. Boundary activation grants each included
    /// joiner a share while changing it to `Active` atomically.
    pub fn get_reshare_target_set(&self) -> Result<Vec<ValidatorRecord>> {
        let all = self.get_validators_matching(ValidatorLifecycle::is_reshare_target)?;
        let mut target = Vec::new();
        for v in all {
            if v.status == status::ACTIVE
                || (v.status == status::PENDING
                    && self.ocomp_registration(v.validator_address)?.is_some())
            {
                target.push(v);
            }
        }
        Ok(target)
    }

    /// Returns validators with `status == PENDING` - staked joiners admitted to the
    /// validator set but not yet granted a threshold share. Used to admit them to
    /// consensus P2P as SECONDARY peers so they can sync to head before the reshare
    /// that makes them signers; they are NOT consensus participants (no share).
    pub fn get_pending_validators(&self) -> Result<Vec<ValidatorRecord>> {
        self.get_validators_matching(ValidatorLifecycle::is_pending)
    }

    /// Returns validators admitted to consensus P2P as secondary peers:
    /// `WaitingForStake`, both pending phases, and both jailed phases. This view
    /// controls network admission only; the current-participant predicate remains
    /// independently gated by a live share. Peers without P2P information are
    /// dropped downstream.
    pub fn get_admitted_non_consensus_validators(&self) -> Result<Vec<ValidatorRecord>> {
        self.get_validators_matching(ValidatorLifecycle::is_secondary_admission)
    }

    /// Returns validators in the current consensus set.
    ///
    /// `Exiting` and `JailRetained` validators retain consensus accountability
    /// until a successful boundary excludes them and clears their BLS share.
    pub fn get_active_consensus_set(&self) -> Result<Vec<ValidatorRecord>> {
        self.get_validators_matching(ValidatorLifecycle::is_current_consensus_participant)
    }

    /// Returns the number of active validators.
    pub fn active_validator_count(&self) -> Result<u32> {
        let count: u32 = self
            .validator_addresses_matching(ValidatorLifecycle::is_active_status)?
            .len()
            .try_into()
            .map_err(|_| PrecompileError::Revert("active validator count exceeds u32".into()))?;
        Ok(count)
    }

    /// number of validators currently in the `REGISTERED` (self-registered,
    /// not-yet-staked) state. Used to bound the free, permissionless
    /// self-registration Sybil surface; see [`MAX_SELF_REGISTERED_UNSTAKED`].
    pub fn registered_count(&self) -> Result<u32> {
        let count: u32 = self
            .validator_addresses_matching(ValidatorLifecycle::is_registered_status)?
            .len()
            .try_into()
            .map_err(|_| {
                PrecompileError::Revert("registered validator count exceeds u32".into())
            })?;
        Ok(count)
    }

    /// Returns the number of validators in the active consensus set.
    pub fn active_consensus_count(&self) -> Result<u32> {
        let count: u32 = self
            .validator_addresses_matching(ValidatorLifecycle::is_current_consensus_participant)?
            .len()
            .try_into()
            .map_err(|_| PrecompileError::Revert("active consensus count exceeds u32".into()))?;
        Ok(count)
    }

    /// Returns true if the validator is a current consensus participant.
    pub fn is_consensus_participant(&self, addr: Address) -> Result<bool> {
        Ok(self
            .validator_lifecycle(addr)?
            .is_current_consensus_participant())
    }

    /// Returns whether there is a pending validator set change that consensus should detect.
    pub fn has_pending_set_change(&self) -> Result<bool> {
        self.pending_set_change.read()
    }

    /// Returns the number of entries in the dense validator registry.
    pub fn validator_count(&self) -> Result<u32> {
        self.validator_count.read()
    }

    /// Returns the persisted active-set hash without exposing its storage slot.
    pub fn active_consensus_set_hash(&self) -> Result<B256> {
        self.active_consensus_set_hash.read()
    }

    /// Returns the current epoch as `u64`; an oversized persisted value is
    /// deterministic state corruption and therefore fails closed.
    pub fn current_epoch_u64(&self) -> Result<u64> {
        self.epoch_number
            .read()?
            .try_into()
            .map_err(|_| PrecompileError::Fatal("ValidatorSet.epoch_number exceeds u64".into()))
    }

    /// Returns all public epoch metadata as one consistent read projection.
    pub fn epoch_snapshot(&self) -> Result<EpochSnapshot> {
        Ok(EpochSnapshot {
            number: self.epoch_number.read()?,
            start_timestamp: self.epoch_start_timestamp.read()?,
            start_block: self.epoch_start_block.read()?,
            length_blocks: self.config_epoch_length_blocks.read()?,
        })
    }

    /// Returns registered addresses in dense registry-index order.
    pub fn registered_validator_addresses(&self) -> Result<Vec<Address>> {
        let count = self.validator_count.read()?;
        let mut addresses = Vec::with_capacity(count as usize);
        for index in 1..=u64::from(count) {
            let address = self.validator_address_at(index)?.ok_or_else(|| {
                PrecompileError::Fatal(format!(
                    "validator registry index {index} is empty below validator_count {count}"
                ))
            })?;
            addresses.push(address);
        }
        Ok(addresses)
    }

    /// Resolves a one-based dense registry index and checks its reverse mapping.
    pub fn validator_address_at(&self, index: u64) -> Result<Option<Address>> {
        let count = u64::from(self.validator_count.read()?);
        if index == 0 || index > count {
            return Ok(None);
        }
        let address = self.index_to_address.read(&index)?;
        if address.is_zero() {
            return Err(PrecompileError::Fatal(format!(
                "validator registry index {index} is empty below validator_count {count}"
            )));
        }
        let reverse_index = self.address_to_index.read(&address)?;
        if reverse_index != index {
            return Err(PrecompileError::Fatal(format!(
                "validator registry reverse index mismatch for {address}: expected {index}, got {reverse_index}"
            )));
        }
        Ok(Some(address))
    }

    /// Returns the registered validator's consensus identity key.
    pub fn consensus_pubkey_of(&self, addr: Address) -> Result<Option<[u8; 48]>> {
        Ok(self.validator_state(addr)?.consensus_pubkey().copied())
    }

    /// Returns participation counters, preserving the legacy all-zero result for
    /// an address that has no registry history.
    pub fn participation(&self, addr: Address) -> Result<ValidatorParticipation> {
        let state = self.validator_state(addr)?;
        let Some(history) = state.history() else {
            return Ok(ValidatorParticipation::default());
        };
        Ok(ValidatorParticipation {
            blocks_proposed: history.blocks_proposed(),
            missed_blocks: history.missed_blocks(),
            missed_votes: history.missed_votes(),
        })
    }

    /// Stores a validator's versioned Commonware P2P address payload.
    ///
    /// The stable ABI is Outbe-owned `(version, bytes)`, not Commonware's raw
    /// codec. The payload is fully validated before any storage write.
    pub fn set_p2p_address(
        &mut self,
        caller: Address,
        validator_addr: Address,
        version: u8,
        encoded: &[u8],
    ) -> Result<()> {
        let owner = self.config_owner.read()?;
        if caller != owner && caller != validator_addr {
            return Err(PrecompileError::Revert(
                "unauthorized: caller must be owner or validator itself".into(),
            ));
        }
        if self.address_to_index.read(&validator_addr)? == 0 {
            return Err(PrecompileError::Revert("validator not registered".into()));
        }
        if version != P2P_ADDRESS_VERSION_V1 {
            return Err(PrecompileError::Revert(format!(
                "unsupported p2p address version {version}"
            )));
        }
        if encoded.len() > MAX_P2P_ADDRESS_ENCODED_LEN {
            return Err(PrecompileError::Revert(format!(
                "p2p address payload exceeds max length {}",
                MAX_P2P_ADDRESS_ENCODED_LEN
            )));
        }
        let decoded = decode_versioned(version, encoded)
            .map_err(|err| PrecompileError::Revert(format!("invalid p2p address: {err}")))?;

        let before = self.validator_state(validator_addr)?;
        let lifecycle = state_machine::with_p2p(before.lifecycle().clone(), P2pInfo::V1(decoded))?;
        let after = before.clone().with_lifecycle(lifecycle)?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        guard.commit();
        Ok(())
    }

    /// Returns the stored versioned P2P address payload, if one is registered.
    pub fn get_p2p_address(&self, validator_addr: Address) -> Result<Option<(u8, Vec<u8>)>> {
        let state = self.validator_state(validator_addr)?;
        let Some(p2p) = state.p2p() else {
            return Err(PrecompileError::Revert("validator not registered".into()));
        };
        if matches!(p2p, P2pInfo::Unset) {
            return Ok(None);
        }
        Ok(Some(p2p.encode_stored()))
    }

    /// Registers a new validator.
    ///
    /// The caller must be either the config owner or the validator address itself.
    /// The address must not already be registered, and the count must be below max.
    /// Initial state is `WaitingForStake` (`REGISTERED`); reaching the minimum,
    /// confirming readiness, and boundary activation are separate transitions.
    ///
    /// `consensus_pubkey` is a 48-byte BLS12-381 MinPk public key.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn register_validator(
        &mut self,
        caller: Address,
        validator_addr: Address,
        consensus_pubkey: &[u8; 48],
    ) -> Result<()> {
        let radicle_node_id = keccak256(validator_addr.as_slice());
        self.register_validator_inner(
            caller,
            validator_addr,
            consensus_pubkey,
            radicle_node_id,
            None,
            true,
        )
    }

    /// Registers a new validator with BLS proof-of-possession verification.
    ///
    /// When `bls_signature` is `Some`, verifies that the BLS MinPk key was used to
    /// sign the chain-bound registration message under the "outbe_REGISTER"
    /// namespace.
    /// `None` is rejected by this production API. Genesis is storage-seeded;
    /// feature-gated tests use [`Self::register_validator`] explicitly.
    ///
    /// `consensus_pubkey` is a 48-byte BLS12-381 MinPk public key.
    /// `bls_signature` is an optional 96-byte BLS MinPk signature.
    pub fn register_validator_with_sig(
        &mut self,
        caller: Address,
        validator_addr: Address,
        consensus_pubkey: &[u8; 48],
        radicle_node_id: B256,
        bls_signature: Option<&[u8; 96]>,
    ) -> Result<()> {
        self.register_validator_inner(
            caller,
            validator_addr,
            consensus_pubkey,
            radicle_node_id,
            bls_signature,
            false,
        )
    }

    fn register_validator_inner(
        &mut self,
        caller: Address,
        validator_addr: Address,
        consensus_pubkey: &[u8; 48],
        radicle_node_id: B256,
        bls_signature: Option<&[u8; 96]>,
        allow_bootstrap_without_pop: bool,
    ) -> Result<()> {
        let owner = self.config_owner.read()?;
        if *consensus_pubkey == [0; 48] {
            return Err(PrecompileError::Revert(
                "consensus public key must not be zero".into(),
            ));
        }

        // Authorization: owner or self-registration
        if caller != owner && caller != validator_addr {
            return Err(PrecompileError::Revert(
                "unauthorized: caller must be owner or validator itself".into(),
            ));
        }
        self.ensure_not_operational_delegate(validator_addr)?;
        if radicle_node_id.is_zero() {
            return Err(PrecompileError::Revert(
                "Radicle NodeId must not be zero".into(),
            ));
        }

        let radicle_owner = self.radicle_node_id_to_validator.read(&radicle_node_id)?;
        if !radicle_owner.is_zero() && radicle_owner != validator_addr {
            return Err(PrecompileError::Revert(
                "Radicle NodeId already registered by another validator".into(),
            ));
        }

        // Every runtime registration requires proof of possession. The only
        // no-PoP path is the feature-gated bootstrap/test helper above; normal
        // owner authority does not weaken the consensus-key invariant.
        if let Some(sig_bytes) = bls_signature {
            verify_bls_registration_sig(
                consensus_pubkey,
                sig_bytes,
                self.storage.chain_id()?,
                validator_addr,
                radicle_node_id,
            )?;
        } else if !allow_bootstrap_without_pop {
            return Err(PrecompileError::Revert(
                "validator registration requires BLS proof-of-possession signature".into(),
            ));
        }

        // bound the free, permissionless self-registration Sybil surface.
        // A self-registered REGISTERED node is admitted to the consensus P2P
        // secondary tier (the TEE verifier flow), so cap how many unstaked
        // REGISTERED validators can exist at once - far below
        // `config_max_validators` - so an attacker cannot fill the validator set
        // (or the consensus P2P set) with free Sybils. Owner registrations
        // (`caller == owner`) bypass this cap. Checked before any state mutation
        // (including the re-registration path), so an over-cap self-registration
        // never consumes a registration slot.
        if caller == validator_addr && self.registered_count()? >= MAX_SELF_REGISTERED_UNSTAKED {
            return Err(PrecompileError::Revert(
                "self-registration limit reached: too many unstaked REGISTERED validators \
                 (owner may register directly)"
                    .into(),
            ));
        }

        // Verify BLS pubkey is not already used by another validator.
        // Without this check, two validators could register the same BLS key,
        // causing undefined behavior during DKG/reshare.
        let pk_hash = Self::consensus_pubkey_hash(consensus_pubkey);
        let existing_owner = self.consensus_pubkey_hash_to_address.read(&pk_hash)?;
        if !existing_owner.is_zero() && existing_owner != validator_addr {
            return Err(PrecompileError::Revert(
                "BLS consensus pubkey already registered by another validator".into(),
            ));
        }

        // Decode registry presence and lifecycle before selecting first-time vs
        // re-registration. This is the sole raw-to-typed construction boundary.
        let existing_state = self.validator_state(validator_addr)?;
        let block_number = self.storage.block_number()?;
        if let Some(existing_index) = existing_state.registry_index() {
            let inactive = match existing_state.lifecycle().clone() {
                ValidatorLifecycle::Inactive(inactive) => inactive,
                _ => {
                    return Err(PrecompileError::Revert(
                        "validator already registered".into(),
                    ));
                }
            };
            let stored_node_id = self.val_radicle_node_id.read(&validator_addr)?;
            if stored_node_id != radicle_node_id {
                return Err(PrecompileError::Revert(
                    "inactive validator must keep its Radicle NodeId until final cleanup".into(),
                ));
            }
            if radicle_owner != validator_addr {
                return Err(PrecompileError::Fatal(
                    "registered validator has inconsistent Radicle NodeId reverse binding".into(),
                ));
            }
            // Re-registration path: check cooldown then reuse existing index
            let cooldown = self.config_reregistration_cooldown.read()?;
            if cooldown > 0 {
                let deactivated_at = existing_state
                    .history()
                    .ok_or_else(|| {
                        PrecompileError::Fatal("registered validator is missing history".into())
                    })?
                    .last_deactivated_at_height();
                let ready_at = deactivated_at
                    .map(|height| {
                        height.checked_add(u64::from(cooldown)).ok_or_else(|| {
                            PrecompileError::Fatal(
                                "re-registration cooldown height overflow".into(),
                            )
                        })
                    })
                    .transpose()?;
                if ready_at.is_some_and(|height| block_number < height) {
                    return Err(PrecompileError::Revert(
                        "re-registration cooldown not expired".into(),
                    ));
                }
            }

            let old_pubkey = existing_state.consensus_pubkey().ok_or_else(|| {
                PrecompileError::Fatal("registered validator is missing consensus pubkey".into())
            })?;
            let old_pk_hash = Self::consensus_pubkey_hash(old_pubkey);
            let pk_hash = Self::consensus_pubkey_hash(consensus_pubkey);
            let lifecycle = ValidatorLifecycle::WaitingForStake(state_machine::reregister(
                inactive,
                *consensus_pubkey,
                block_number,
            )?);
            let after = existing_state.clone().with_lifecycle(lifecycle)?;
            if self.val_ocomp_recovery_deadline.read(&validator_addr)? != 0 {
                return Err(PrecompileError::Revert(
                    "cannot re-register while an OCOMP recovery window is open".into(),
                ));
            }

            let guard = self.storage.checkpoint_guard();
            self.consensus_pubkey_hash_to_address
                .write(&old_pk_hash, Address::ZERO)?;
            self.consensus_pubkey_hash_to_address
                .write(&pk_hash, validator_addr)?;
            self.persist_registry_state_delta(&existing_state, &after)?;
            self.pending_set_change.write(true)?;
            self.emit(IValidatorSet::ValidatorRegistered {
                validator: validator_addr,
                index: existing_index.get(),
            })?;
            guard.commit();

            crate::metrics::record_validator_status(validator_addr, status::REGISTERED);
            crate::metrics::record_validator_register(validator_addr, true);
            crate::metrics::record_pending_set_change(true);
            journal_record(JournalRecord::ValidatorReregistered {
                wall_clock: iso8601_now(),
                block_number,
                validator: format!("{validator_addr:?}"),
                index: existing_index.get(),
            });

            info!(
                target: "outbe::validatorset",
                event = "validator_reregistered",
                validator = %validator_addr,
                index = existing_index.get(),
                block_number,
                "validator re-registered (was INACTIVE, lifecycle metadata reset)",
            );

            return Ok(());
        }

        // Check capacity
        let count = self.validator_count.read()?;
        let max = self.config_max_validators.read()?;
        if max > 0 && count >= max {
            return Err(PrecompileError::Revert("max validators reached".into()));
        }

        // Assign 1-based index
        let new_index = count
            .checked_add(1)
            .ok_or_else(|| PrecompileError::Fatal("validator count overflow".into()))?;
        let new_index_u64 = new_index as u64;

        // Construct and persist the complete first-time registry bundle. The
        // typed decoder guarantees that absent addresses carry no stake residue.
        let registered_state = state_machine::register(
            existing_state.clone(),
            NonZeroU64::new(new_index_u64).ok_or_else(|| {
                PrecompileError::Fatal("validator registry index must be non-zero".into())
            })?,
            *consensus_pubkey,
            block_number,
        )?;

        let guard = self.storage.checkpoint_guard();
        if radicle_owner == validator_addr {
            return Err(PrecompileError::Fatal(
                "unregistered validator retains a Radicle NodeId reservation".into(),
            ));
        }
        self.address_to_index
            .write(&validator_addr, new_index_u64)?;
        self.index_to_address
            .write(&new_index_u64, validator_addr)?;
        self.persist_registry_state_delta(&existing_state, &registered_state)?;

        // Pubkey reverse lookup (keyed by keccak256 of full 48-byte pubkey)
        let pk_hash = Self::consensus_pubkey_hash(consensus_pubkey);
        self.consensus_pubkey_hash_to_address
            .write(&pk_hash, validator_addr)?;
        self.val_radicle_node_id
            .write(&validator_addr, radicle_node_id)?;
        self.radicle_node_id_to_validator
            .write(&radicle_node_id, validator_addr)?;

        // Increment count
        self.validator_count.write(new_index)?;

        // Signal pending set change so consensus detects the new validator
        self.pending_set_change.write(true)?;
        self.emit(IValidatorSet::ValidatorRegistered {
            validator: validator_addr,
            index: new_index as u64,
        })?;
        guard.commit();

        crate::metrics::record_validator_status(validator_addr, status::REGISTERED);
        crate::metrics::record_validator_register(validator_addr, false);
        crate::metrics::record_pending_set_change(true);

        journal_record(JournalRecord::ValidatorRegistered {
            wall_clock: iso8601_now(),
            block_number,
            validator: format!("{validator_addr:?}"),
            index: new_index as u64,
        });

        info!(
            target: "outbe::validatorset",
            event = "validator_registered",
            validator = %validator_addr,
            index = new_index as u64,
            block_number,
            "validator registered (first-time)",
        );

        Ok(())
    }

    /// Records a successful stake increase from Staking and performs the
    /// REGISTERED -> PENDING threshold transition when required.
    ///
    /// Staking owns the authoritative balance. This method is the only
    /// production write seam for the ValidatorSet mirror and its coupled
    /// lifecycle fields.
    pub fn record_stake_increase(
        &mut self,
        addr: Address,
        bonded: U256,
        minimum: U256,
    ) -> Result<()> {
        let before = self.validator_state(addr)?;
        let stake = StakeProjection::new(bonded, before.unbonding_end_hint());
        let (lifecycle, became_pending) = match before.lifecycle().clone() {
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert(
                    "cannot stake before validator registration".into(),
                ));
            }
            ValidatorLifecycle::Inactive(_) => {
                return Err(PrecompileError::Revert(
                    "inactive validator must re-register before staking".into(),
                ));
            }
            ValidatorLifecycle::Exiting(_) | ValidatorLifecycle::Unbonding(_) => {
                return Err(PrecompileError::Revert(
                    "cannot increase stake while validator is exiting or unbonding".into(),
                ));
            }
            ValidatorLifecycle::WaitingForStake(waiting) if bonded >= minimum => (
                ValidatorLifecycle::WaitingForReadiness(state_machine::reach_minimum(
                    waiting, stake, minimum,
                )?),
                true,
            ),
            lifecycle => (state_machine::with_stake(lifecycle, stake)?, false),
        };
        let after = before.clone().with_lifecycle(lifecycle)?;

        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        if became_pending {
            self.pending_set_change.write(true)?;
        }
        guard.commit();
        if became_pending {
            crate::metrics::record_validator_status(addr, status::PENDING);
            crate::metrics::record_pending_set_change(true);
        }
        Ok(())
    }

    /// Records a voluntary withdrawal and applies the complete coupled lifecycle
    /// transition. Readiness is consumed on demotion, and a jailed validator may
    /// leave only after fully unstaking.
    pub fn record_unstake(
        &mut self,
        addr: Address,
        bonded: U256,
        minimum: U256,
        unbonding_end_hint: u64,
    ) -> Result<()> {
        let before = self.validator_state(addr)?;
        let lifecycle = before.lifecycle().clone();
        let stake = StakeProjection::new(
            bonded,
            (unbonding_end_hint != 0).then_some(unbonding_end_hint),
        );
        let mut set_change = false;
        let height = self.storage.block_number()?;
        let next = match lifecycle {
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            ValidatorLifecycle::Inactive(_) => {
                return Err(PrecompileError::Revert("validator is inactive".into()));
            }
            ValidatorLifecycle::WaitingForReadiness(waiting) if bonded < minimum => {
                set_change = true;
                ValidatorLifecycle::WaitingForStake(state_machine::demote_waiting_for_readiness(
                    waiting, stake, minimum,
                )?)
            }
            ValidatorLifecycle::Joining(joining) if bonded < minimum => {
                set_change = true;
                ValidatorLifecycle::WaitingForStake(state_machine::demote_joining(
                    joining, stake, minimum,
                )?)
            }
            ValidatorLifecycle::Active(active) if bonded < minimum => {
                set_change = true;
                ValidatorLifecycle::Exiting(state_machine::begin_exit(active, stake, height)?)
            }
            ValidatorLifecycle::JailRetained(jailed) if bonded.is_zero() => {
                set_change = true;
                ValidatorLifecycle::Exiting(state_machine::full_exit_jailed_retained(
                    jailed, stake,
                )?)
            }
            ValidatorLifecycle::Jail(jailed) if bonded.is_zero() => {
                ValidatorLifecycle::Unbonding(state_machine::full_exit_jailed(jailed, stake)?)
            }
            lifecycle => state_machine::with_stake(lifecycle, stake)?,
        };
        let after = before.clone().with_lifecycle(next)?;

        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        if set_change {
            self.pending_set_change.write(true)?;
        }
        guard.commit();
        if set_change {
            crate::metrics::record_pending_set_change(true);
        }
        Ok(())
    }

    /// Records a stake slash. This is intentionally distinct from voluntary
    /// withdrawal: a JAILED validator remains JAILED after the slash.
    pub fn record_stake_slash(
        &mut self,
        addr: Address,
        bonded: U256,
        minimum: U256,
        unbonding_end_hint: Option<u64>,
    ) -> Result<()> {
        let before = self.validator_state(addr)?;
        let lifecycle = before.lifecycle().clone();
        let hint = unbonding_end_hint.or(before.unbonding_end_hint());
        let stake = StakeProjection::new(bonded, hint);
        let mut set_change = false;
        let below_minimum = !minimum.is_zero() && bonded < minimum;
        let height = self.storage.block_number()?;
        let next = match lifecycle {
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            ValidatorLifecycle::Inactive(_) => {
                return Err(PrecompileError::Revert("validator is inactive".into()));
            }
            ValidatorLifecycle::WaitingForReadiness(waiting) if below_minimum => {
                set_change = true;
                ValidatorLifecycle::WaitingForStake(state_machine::demote_waiting_for_readiness(
                    waiting, stake, minimum,
                )?)
            }
            ValidatorLifecycle::Joining(joining) if below_minimum => {
                set_change = true;
                ValidatorLifecycle::WaitingForStake(state_machine::demote_joining(
                    joining, stake, minimum,
                )?)
            }
            ValidatorLifecycle::Active(active) if below_minimum => {
                set_change = true;
                ValidatorLifecycle::Exiting(state_machine::begin_exit(active, stake, height)?)
            }
            lifecycle => state_machine::with_stake(lifecycle, stake)?,
        };
        let after = before.clone().with_lifecycle(next)?;

        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        if set_change {
            self.pending_set_change.write(true)?;
        }
        guard.commit();
        if set_change {
            crate::metrics::record_pending_set_change(true);
        }
        Ok(())
    }

    /// Records one missing OCOMP result vote. The first miss opens a fixed
    /// recovery window; later misses count accountability but neither extend
    /// the deadline nor authorize another bonded slash.
    pub fn record_ocomp_miss(&mut self, addr: Address) -> Result<OcompMissRecord> {
        let state = self.validator_state(addr)?;
        if !matches!(state.lifecycle(), ValidatorLifecycle::Active(_)) {
            return Err(PrecompileError::Revert(
                "OCOMP miss requires an active validator".into(),
            ));
        }

        let miss_count = self
            .val_ocomp_miss_count
            .read(&addr)?
            .checked_add(1)
            .ok_or_else(|| PrecompileError::Fatal("OCOMP miss count overflow".into()))?;
        let existing_deadline = self.val_ocomp_recovery_deadline.read(&addr)?;
        let guard = self.storage.checkpoint_guard();
        self.val_ocomp_miss_count.write(&addr, miss_count)?;
        let outcome = if existing_deadline == 0 {
            let recovery_deadline = self
                .storage
                .block_number()?
                .checked_add(OCOMP_RECOVERY_WINDOW_BLOCKS)
                .ok_or_else(|| PrecompileError::Fatal("OCOMP recovery deadline overflow".into()))?;
            self.val_ocomp_recovery_deadline
                .write(&addr, recovery_deadline)?;
            OcompMissRecord::Opened {
                miss_count,
                recovery_deadline,
            }
        } else {
            OcompMissRecord::Repeated {
                miss_count,
                recovery_deadline: existing_deadline,
            }
        };
        guard.commit();
        Ok(outcome)
    }

    /// Mirrors the authoritative bonded stake after the one OCOMP recovery
    /// slash. This path is intentionally narrow: it requires an open recovery
    /// window and preserves ACTIVE even when the new bonded amount is below the
    /// ordinary minimum-stake threshold.
    pub fn record_ocomp_bonded_slash(&mut self, addr: Address, bonded: U256) -> Result<()> {
        if self.val_ocomp_recovery_deadline.read(&addr)? == 0 {
            return Err(PrecompileError::Revert(
                "OCOMP bonded slash requires an open recovery window".into(),
            ));
        }
        let before = self.validator_state(addr)?;
        if !matches!(before.lifecycle(), ValidatorLifecycle::Active(_)) {
            return Err(PrecompileError::Revert(
                "OCOMP bonded slash requires an active validator".into(),
            ));
        }
        let stake = StakeProjection::new(bonded, before.unbonding_end_hint());
        let lifecycle = state_machine::with_stake(before.lifecycle().clone(), stake)?;
        let after = before.clone().with_lifecycle(lifecycle)?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        guard.commit();
        Ok(())
    }

    /// Returns the durable OCOMP recovery state for one validator.
    pub fn ocomp_recovery_window(&self, addr: Address) -> Result<Option<OcompRecoveryWindow>> {
        let recovery_deadline = self.val_ocomp_recovery_deadline.read(&addr)?;
        if recovery_deadline == 0 {
            return Ok(None);
        }
        Ok(Some(OcompRecoveryWindow {
            miss_count: self.val_ocomp_miss_count.read(&addr)?,
            recovery_deadline,
        }))
    }

    /// Closes one recovery window while preserving cumulative accountability.
    pub fn close_ocomp_recovery_window(&mut self, addr: Address) -> Result<()> {
        self.val_ocomp_recovery_deadline.write(&addr, 0)
    }

    /// Closes one due window and emits its consensus-visible resolution.
    pub fn resolve_ocomp_recovery_window(
        &mut self,
        addr: Address,
        recovery_deadline: u64,
        bonded_stake: U256,
        outcome: OcompRecoveryOutcome,
    ) -> Result<()> {
        if self.val_ocomp_recovery_deadline.read(&addr)? != recovery_deadline {
            return Err(PrecompileError::Fatal(
                "OCOMP recovery resolution deadline mismatch".into(),
            ));
        }
        let guard = self.storage.checkpoint_guard();
        self.close_ocomp_recovery_window(addr)?;
        self.emit(IValidatorSet::OcompRecoveryResolved {
            validator: addr,
            recoveryDeadline: recovery_deadline,
            bondedStake: bonded_stake,
            outcome: outcome as u8,
        })?;
        guard.commit();
        Ok(())
    }

    /// Completes UNBONDING after Staking has verified zero bonded stake and no
    /// remaining live claims.
    pub fn complete_unbonding(&mut self, addr: Address) -> Result<()> {
        let before = self.validator_state(addr)?;
        let unbonding = match before.lifecycle().clone() {
            ValidatorLifecycle::Unbonding(unbonding) => unbonding,
            _ => return Ok(()),
        };
        let cleared = match state_machine::with_stake(
            ValidatorLifecycle::Unbonding(unbonding),
            StakeProjection::new(before.bonded_stake(), None),
        )? {
            ValidatorLifecycle::Unbonding(unbonding) => unbonding,
            _ => unreachable!("with_stake preserves lifecycle variant"),
        };
        let inactive = state_machine::complete_unbonding(cleared)?;
        let after = before
            .clone()
            .with_lifecycle(ValidatorLifecycle::Inactive(inactive))?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        guard.commit();
        Ok(())
    }

    /// Test-only compatibility helper for moving `WaitingForStake` to
    /// `WaitingForReadiness`. Production Staking uses [`Self::record_stake_increase`]
    /// with the authoritative minimum.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn mark_pending(&mut self, addr: Address) -> Result<()> {
        let before = self.validator_state(addr)?;
        let waiting = match before.lifecycle().clone() {
            ValidatorLifecycle::WaitingForStake(waiting) => waiting,
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            _ => return Ok(()),
        };
        let stake = *before.stake().ok_or_else(|| {
            PrecompileError::Fatal("registered validator is missing stake projection".into())
        })?;
        let lifecycle = ValidatorLifecycle::WaitingForReadiness(state_machine::reach_minimum(
            waiting,
            stake,
            U256::ZERO,
        )?);
        let after = before.clone().with_lifecycle(lifecycle)?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        // Signal consensus to include this validator in the next reshare target.
        self.pending_set_change.write(true)?;
        guard.commit();

        crate::metrics::record_validator_status(addr, status::PENDING);
        crate::metrics::record_pending_set_change(true);

        Ok(())
    }

    /// Stale-join guard: a PENDING joiner confirms, on-chain, that its node has
    /// caught up to head and is ready to be frozen into the next DKG reshare
    /// target. The operator sends this only after `rudis_syncStatus` shows the
    /// node at the finalized tip; until then the joiner stays PENDING and is
    /// excluded from [`Self::get_reshare_target_set`]. Caller must be the
    /// validator itself and currently PENDING.
    pub fn confirm_validator_ready(
        &mut self,
        caller: Address,
        encoded_registration: &[u8],
    ) -> Result<()> {
        let before = self.validator_state(caller)?;
        let lifecycle = match before.lifecycle().clone() {
            ValidatorLifecycle::WaitingForReadiness(waiting) => {
                ValidatorLifecycle::Joining(state_machine::confirm_ready(waiting))
            }
            ValidatorLifecycle::Joining(joining) => ValidatorLifecycle::Joining(joining),
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            lifecycle => {
                return Err(PrecompileError::Revert(format!(
                    "confirmValidatorReady requires PENDING status, got {}",
                    registered_status(&lifecycle)?
                )))
            }
        };
        let limits = poc_schema_limits();
        let registration = OcompKeyRegistrationV1::decode_canonical(encoded_registration, &limits)
            .map_err(|error| {
                PrecompileError::Revert(format!("invalid OCOMP registration: {error}"))
            })?;
        if registration.core.chain_id != self.storage.chain_id()? {
            return Err(PrecompileError::Revert(
                "OCOMP registration chain id mismatch".into(),
            ));
        }
        if registration.core.genesis_hash != self.storage.genesis_hash()? {
            return Err(PrecompileError::Revert(
                "OCOMP registration genesis hash mismatch".into(),
            ));
        }
        let consensus_pubkey = before.consensus_pubkey().ok_or_else(|| {
            PrecompileError::Fatal("registered validator is missing consensus pubkey".into())
        })?;
        let expected_identity = validator_identity_hash_v1(caller, consensus_pubkey)
            .map_err(|error| PrecompileError::Fatal(format!("validator identity hash: {error}")))?;
        if registration.core.validator_identity_hash != expected_identity {
            return Err(PrecompileError::Revert(
                "OCOMP registration validator identity mismatch".into(),
            ));
        }

        let existing_registration = self.ocomp_registration(caller)?;
        let key_hash = keccak256(registration.core.ocomp_public_key_sec1);
        if let Some(existing) = existing_registration.as_ref() {
            let pinned_key_hash = keccak256(existing.core.ocomp_public_key_sec1);
            if pinned_key_hash != key_hash {
                return Err(PrecompileError::Revert(
                    "OCOMP public key is immutable in key_epoch 1".into(),
                ));
            }
            let pinned_owner = self.ocomp_key_hash_to_validator.read(&pinned_key_hash)?;
            if pinned_owner != caller {
                return Err(PrecompileError::Fatal(format!(
                    "OCOMP key reservation for {caller} is inconsistent"
                )));
            }
        }
        let existing_owner = self.ocomp_key_hash_to_validator.read(&key_hash)?;
        if !existing_owner.is_zero() && existing_owner != caller {
            return Err(PrecompileError::Revert(
                "OCOMP public key already registered by another validator".into(),
            ));
        }

        let guard = self.storage.checkpoint_guard();
        self.val_ocomp_registration
            .get_bytes(&caller)
            .write(encoded_registration)?;
        self.ocomp_key_hash_to_validator.write(&key_hash, caller)?;
        let after = before.clone().with_lifecycle(lifecycle)?;
        self.persist_validator_state_delta(&before, &after)?;
        // Re-signal so consensus schedules a reshare now that a confirmed joiner
        // is eligible (the stake-time signal may already have lapsed).
        self.pending_set_change.write(true)?;
        guard.commit();
        crate::metrics::record_pending_set_change(true);
        Ok(())
    }

    /// Imports the chain-manifest OCOMP key material for the ordered genesis
    /// ACTIVE set. The manifest vector is not membership authority: it must
    /// cover the already-persisted ACTIVE ValidatorSet exactly and in order.
    ///
    /// This is purpose-built for the one-time OCOMP lifecycle activation. A
    /// byte-identical replay is accepted; partial or conflicting pre-existing
    /// state is fatal rather than repaired.
    pub fn initialize_founder_ocomp_registrations(
        &mut self,
        registrations: &[OcompKeyRegistrationV1],
    ) -> Result<()> {
        let active = self.get_active_validators()?;
        if active.is_empty() || active.len() != registrations.len() {
            return Err(PrecompileError::Fatal(format!(
                "OCOMP founder registrations must exactly cover ACTIVE ValidatorSet: {} registrations for {} validators",
                registrations.len(),
                active.len()
            )));
        }

        let chain_id = self.storage.chain_id()?;
        let genesis_hash = self.storage.genesis_hash()?;
        let limits = poc_schema_limits();
        let mut identities = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(registrations.len())
            .map_err(|_| PrecompileError::Fatal("allocate OCOMP founder import".into()))?;

        let mut exact_existing = 0usize;
        for (validator, registration) in active.iter().zip(registrations) {
            registration
                .validate_proof_of_possession(&limits)
                .map_err(|error| {
                    PrecompileError::Fatal(format!(
                        "invalid OCOMP founder proof of possession: {error}"
                    ))
                })?;
            if registration.core.chain_id != chain_id
                || registration.core.genesis_hash != genesis_hash
            {
                return Err(PrecompileError::Fatal(
                    "OCOMP founder registration chain binding mismatch".into(),
                ));
            }
            let expected_identity = validator_identity_hash_v1(
                validator.validator_address,
                &validator.consensus_pubkey,
            )
            .map_err(|error| {
                PrecompileError::Fatal(format!("derive OCOMP founder validator identity: {error}"))
            })?;
            if registration.core.validator_identity_hash != expected_identity {
                return Err(PrecompileError::Fatal(format!(
                    "OCOMP founder registration identity mismatch for {}",
                    validator.validator_address
                )));
            }
            if !identities.insert(expected_identity)
                || !keys.insert(registration.core.ocomp_public_key_sec1)
            {
                return Err(PrecompileError::Fatal(
                    "OCOMP founder registrations contain duplicate identity or key".into(),
                ));
            }

            let encoded = registration.encode_canonical(&limits).map_err(|error| {
                PrecompileError::Fatal(format!(
                    "encode canonical OCOMP founder registration: {error}"
                ))
            })?;
            let key_hash = keccak256(registration.core.ocomp_public_key_sec1);
            let stored = self.ocomp_registration(validator.validator_address)?;
            let owner = self.ocomp_key_hash_to_validator.read(&key_hash)?;
            match stored {
                Some(existing)
                    if existing == *registration && owner == validator.validator_address =>
                {
                    exact_existing += 1;
                }
                None if owner.is_zero() => {}
                _ => {
                    return Err(PrecompileError::Fatal(format!(
                        "partial or conflicting OCOMP founder state for {}",
                        validator.validator_address
                    )));
                }
            }
            prepared.push((validator.validator_address, key_hash, encoded));
        }

        if exact_existing == registrations.len() {
            return Ok(());
        }
        if exact_existing != 0 {
            return Err(PrecompileError::Fatal(
                "partial OCOMP founder registration import is fatal".into(),
            ));
        }

        let guard = self.storage.checkpoint_guard();
        for (validator, key_hash, encoded) in prepared {
            self.val_ocomp_registration
                .get_bytes(&validator)
                .write(&encoded)?;
            self.ocomp_key_hash_to_validator
                .write(&key_hash, validator)?;
        }
        guard.commit();
        Ok(())
    }

    /// Test-only fixture activation through the canonical join transitions.
    /// Production activation is system-boundary-only.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn activate_validator(&mut self, addr: Address) -> Result<()> {
        let before = self.validator_state(addr)?;
        let active = match before.lifecycle().clone() {
            ValidatorLifecycle::Active(_) => return Ok(()),
            ValidatorLifecycle::Joining(joining) => state_machine::activate_at_boundary(joining),
            ValidatorLifecycle::WaitingForReadiness(waiting) => {
                state_machine::activate_at_boundary(state_machine::confirm_ready(waiting))
            }
            ValidatorLifecycle::WaitingForStake(waiting) => {
                let stake = *before.stake().ok_or_else(|| {
                    PrecompileError::Fatal(
                        "registered validator is missing stake projection".into(),
                    )
                })?;
                let ready = state_machine::reach_minimum(waiting, stake, U256::ZERO)?;
                state_machine::activate_at_boundary(state_machine::confirm_ready(ready))
            }
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            lifecycle => {
                return Err(PrecompileError::Revert(format!(
                    "cannot activate validator with status {}: only REGISTERED or PENDING allowed in test fixtures",
                    registered_status(&lifecycle)?
                )))
            }
        };
        let after = before
            .clone()
            .with_lifecycle(ValidatorLifecycle::Active(active))?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        self.pending_set_change.write(true)?;
        crate::metrics::record_validator_status(addr, status::ACTIVE);
        crate::metrics::record_pending_set_change(true);
        self.emit(IValidatorSet::ValidatorActivated { validator: addr })?;
        guard.commit();
        Ok(())
    }

    /// Deactivates a validator - transitions to EXITING (awaiting DKG reshare to exclude).
    ///
    /// The caller must be the config owner or the validator itself.
    pub fn deactivate_validator(&mut self, caller: Address, addr: Address) -> Result<()> {
        let owner = self.config_owner.read()?;
        if caller != owner && caller != addr {
            return Err(PrecompileError::Revert(
                "unauthorized: caller must be owner or validator itself".into(),
            ));
        }
        let before = self.validator_state(addr)?;
        let active = match before.lifecycle().clone() {
            ValidatorLifecycle::Active(active) => active,
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()))
            }
            _ => {
                return Err(PrecompileError::Revert(
                    "can only deactivate an active validator".into(),
                ))
            }
        };
        let height = self.storage.block_number()?;
        let stake = *before.stake().ok_or_else(|| {
            PrecompileError::Fatal("active validator is missing stake projection".into())
        })?;
        let lifecycle =
            ValidatorLifecycle::Exiting(state_machine::begin_exit(active, stake, height)?);
        let after = before.clone().with_lifecycle(lifecycle)?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;

        // Signal pending set change so consensus triggers DKG reshare to exclude
        self.pending_set_change.write(true)?;

        self.emit(IValidatorSet::ValidatorDeactivated {
            validator: addr,
            atHeight: height,
        })?;
        guard.commit();

        crate::metrics::record_validator_status(addr, status::EXITING);
        crate::metrics::record_validator_deactivate(addr);
        crate::metrics::record_pending_set_change(true);

        journal_record(JournalRecord::ValidatorDeactivated {
            wall_clock: iso8601_now(),
            block_number: height,
            validator: format!("{addr:?}"),
            caller: format!("{caller:?}"),
            self_initiated: caller == addr,
        });

        info!(
            target: "outbe::validatorset",
            event = "validator_deactivated",
            validator = %addr,
            %caller,
            self_initiated = (caller == addr),
            block_number = height,
            "validator transitioned ACTIVE -> EXITING (voluntary deactivation)",
        );

        Ok(())
    }

    /// Forces a validator out of consensus because of a severe fault.
    ///
    /// The validator enters EXITING and is removed from consensus on the next
    /// successful reshare. Stake withdrawal is handled by Staking after the
    /// validator reaches UNBONDING.
    pub fn force_exit_validator(&mut self, addr: Address) -> Result<()> {
        if let Some(observability) = self.punish_validator(addr, false)? {
            observability.record();
        }
        Ok(())
    }

    /// Jails a validator for a severe consensus/oracle fault (felony). Unlike
    /// [`Self::force_exit_validator`], the validator is NOT removed from the
    /// registry: it is frozen in JAILED, excluded from the next reshare target
    /// (so the reshare clears its share), and may later return via
    /// `unjailValidator` (`Jail -> WaitingForReadiness -> Joining -> Active`) or,
    /// after boundary exclusion, leave via a full unstake
    /// (`Jail -> Unbonding -> Inactive`). The slash itself is applied by the caller
    /// AFTER this call (`slash_stake` leaves a jailed lifecycle untouched).
    /// Increments `slash_count` once. Repeated punishment of the same lifecycle
    /// is a no-op even if a caller bypasses SlashIndicator's replay guard.
    pub fn jail_validator(&mut self, addr: Address) -> Result<()> {
        if let Some(observability) = self.punish_validator(addr, true)? {
            observability.record();
        }
        Ok(())
    }

    /// Applies the jail transition but leaves metrics, journal and tracing to
    /// the caller so a wider atomic transition cannot publish rolled-back state.
    pub fn jail_validator_deferred(
        &mut self,
        addr: Address,
    ) -> Result<Option<DeferredValidatorPunishment>> {
        self.punish_validator(addr, true)
    }

    /// Jails an ACTIVE validator whose canonical TEE lease reached its deadline.
    ///
    /// This is an availability/safety transition, not a slash: bonded stake and
    /// `slash_count` are preserved exactly. The old committee share remains
    /// accountable in `JailRetained` until the normal validated boundary removes
    /// it. Re-execution after the first transition is an idempotent no-op.
    pub fn jail_validator_for_tee_expiry(&mut self, addr: Address) -> Result<bool> {
        let before = self.validator_state(addr)?;
        let active = match before.lifecycle().clone() {
            ValidatorLifecycle::Active(active) => active,
            ValidatorLifecycle::JailRetained(_) | ValidatorLifecycle::Jail(_) => {
                return Ok(false);
            }
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            lifecycle => {
                return Err(PrecompileError::Fatal(format!(
                    "TEE expiry sweep selected validator {addr} with ineligible status {}",
                    registered_status(&lifecycle)?
                )));
            }
        };
        let block_number = self.storage.block_number()?;
        let next = ValidatorLifecycle::JailRetained(state_machine::jail(active, block_number)?);
        let after = before.clone().with_lifecycle(next)?;

        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;
        self.pending_set_change.write(true)?;
        self.emit(IValidatorSet::ValidatorJailed {
            validator: addr,
            atHeight: block_number,
        })?;
        guard.commit();

        crate::metrics::record_validator_status(addr, status::JAILED);
        crate::metrics::record_validator_tee_expiry(addr, "deadline_jailed");
        crate::metrics::record_pending_set_change(true);
        warn!(
            target: "outbe::validatorset",
            event = "validator_tee_lease_expired",
            validator = %addr,
            block_number,
            "validator jailed without slashing after TEE lease deadline",
        );
        Ok(true)
    }

    /// Shared punitive transition for [`Self::force_exit_validator`] (`jail =
    /// false` -> ACTIVE->EXITING, the validator leaves the registry via UNBONDING)
    /// and [`Self::jail_validator`] (`jail = true` -> ACTIVE->JAILED, the validator
    /// is frozen in the registry). Both signal a reshare and bump `slash_count`
    /// exactly once.
    fn punish_validator(
        &mut self,
        addr: Address,
        jail: bool,
    ) -> Result<Option<DeferredValidatorPunishment>> {
        let before = self.validator_state(addr)?;
        let lifecycle = before.lifecycle().clone();
        if matches!(lifecycle, ValidatorLifecycle::Absent) {
            return Err(PrecompileError::Revert("validator not registered".into()));
        }
        let current_status = registered_status(&lifecycle)?;
        let block_number = self.storage.block_number()?;
        let (target, target_label, action) = if jail {
            (status::JAILED, "JAILED", "jail")
        } else {
            (status::EXITING, "EXITING", "force-exit")
        };

        let history = before.history().copied().ok_or_else(|| {
            PrecompileError::Fatal("registered validator is missing history".into())
        })?;
        let active = match lifecycle {
            ValidatorLifecycle::Active(active) => active,
            ValidatorLifecycle::JailRetained(_) | ValidatorLifecycle::Jail(_) if jail => {
                return Ok(None)
            }
            ValidatorLifecycle::Exiting(_)
            | ValidatorLifecycle::Unbonding(_)
            | ValidatorLifecycle::Inactive(_) => return Ok(None),
            _ => {
                return Err(PrecompileError::Revert(format!(
                    "cannot {action} validator with status {current_status}: only ACTIVE, EXITING, UNBONDING, or INACTIVE allowed"
                )));
            }
        };
        let stake = *before.stake().ok_or_else(|| {
            PrecompileError::Fatal("active validator is missing stake projection".into())
        })?;
        let next = if jail {
            ValidatorLifecycle::JailRetained(state_machine::jail(active, block_number)?)
        } else {
            ValidatorLifecycle::Exiting(state_machine::begin_exit(active, stake, block_number)?)
        };
        let next = state_machine::with_history(
            next,
            ValidatorHistory::new(
                history.joined_at_height(),
                Some(block_number),
                history
                    .slash_count()
                    .checked_add(1)
                    .ok_or_else(|| PrecompileError::Fatal("slash count overflow".into()))?,
                history.missed_blocks(),
                history.missed_votes(),
                history.blocks_proposed(),
            ),
        )?;
        let after = before.clone().with_lifecycle(next)?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;

        self.pending_set_change.write(true)?;
        if jail {
            self.emit(IValidatorSet::ValidatorJailed {
                validator: addr,
                atHeight: block_number,
            })?;
        } else {
            self.emit(IValidatorSet::ValidatorDeactivated {
                validator: addr,
                atHeight: block_number,
            })?;
            self.emit(IValidatorSet::ValidatorForcedExit {
                validator: addr,
                atHeight: block_number,
            })?;
        }
        guard.commit();

        Ok(Some(DeferredValidatorPunishment {
            addr,
            target,
            target_label,
            jailed: jail,
            block_number,
        }))
    }

    /// Unjails a JAILED validator back to PENDING. Called by Staking's
    /// `unjailValidator` (which first verifies the caller's stake >= min_stake);
    /// the caller must be the validator itself. Enforces the unjail cooldown,
    /// clears missed-block/vote counters, and signals a reshare. Identity,
    /// deactivation, slash and proposal history remain intact.
    pub fn unjail_after_stake_check(&mut self, addr: Address) -> Result<()> {
        let before = self.validator_state(addr)?;
        let jailed = match before.lifecycle().clone() {
            ValidatorLifecycle::Jail(jailed) => jailed,
            ValidatorLifecycle::JailRetained(_) => {
                return Err(PrecompileError::Revert(
                    "jailed validator is still retained in the current committee".into(),
                ));
            }
            ValidatorLifecycle::Absent => {
                return Err(PrecompileError::Revert("validator not registered".into()));
            }
            lifecycle => {
                return Err(PrecompileError::Revert(format!(
                    "unjailValidator requires JAILED status, got {}",
                    registered_status(&lifecycle)?
                )));
            }
        };
        let block_number = self.storage.block_number()?;
        let cooldown = self.unjail_cooldown_blocks()?;
        // Staking checked its authoritative minimum before entering this facade.
        let pending = state_machine::unjail(jailed, block_number, cooldown, before.bonded_stake())?;
        let after = before
            .clone()
            .with_lifecycle(ValidatorLifecycle::WaitingForReadiness(pending))?;
        let guard = self.storage.checkpoint_guard();
        self.persist_validator_state_delta(&before, &after)?;

        // Re-joining requires a fresh readiness confirmation before DKG.
        self.pending_set_change.write(true)?;

        self.emit(IValidatorSet::ValidatorUnjailed {
            validator: addr,
            atHeight: block_number,
        })?;
        guard.commit();

        crate::metrics::record_validator_status(addr, status::PENDING);
        crate::metrics::record_pending_set_change(true);
        Ok(())
    }

    /// Compatibility wrapper retained while callers migrate to the named
    /// Staking-checked transition.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn unjail_to_pending(&mut self, addr: Address) -> Result<()> {
        self.unjail_after_stake_check(addr)
    }

    /// Unjail cooldown in blocks (default 0 - immediate unjail allowed).
    pub fn unjail_cooldown_blocks(&self) -> Result<u64> {
        self.config_unjail_cooldown_blocks.read()
    }

    /// Test-only compatibility entrypoint. Production activation is reachable
    /// exclusively through the consensus boundary hook.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn activate_reshared_set(
        &mut self,
        new_active_set: &[Address],
        active_set_hash: B256,
    ) -> Result<()> {
        self.activate_validated_boundary_set(new_active_set, active_set_hash, u64::MAX)
    }

    /// Applies inputs already validated against the locally expected consensus
    /// boundary artifact. Snapshot/hash validation remains in the EVM boundary
    /// orchestrator; this method owns only the ValidatorSet state transition.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn activate_validated_boundary_set(
        &mut self,
        new_active_set: &[Address],
        active_set_hash: B256,
        freeze_height: u64,
    ) -> Result<()> {
        self.activate_validated_boundary_set_with_expiry_exclusions(
            new_active_set,
            active_set_hash,
            freeze_height,
            &[],
        )
    }

    /// Applies a validated boundary and its certified TEE-expiry exclusions.
    pub(crate) fn activate_validated_boundary_set_with_expiry_exclusions(
        &mut self,
        new_active_set: &[Address],
        active_set_hash: B256,
        freeze_height: u64,
        tee_expired_target_exclusions: &[Address],
    ) -> Result<()> {
        if tee_expired_target_exclusions.is_empty() {
            return self.apply_reshared_set(new_active_set, active_set_hash, freeze_height, &[]);
        }
        if tee_expired_target_exclusions.len()
            > outbe_primitives::validators::MAX_TEE_EXPIRED_TARGET_EXCLUSIONS
        {
            return Err(PrecompileError::Fatal(format!(
                "TEE expiry exclusions exceed protocol cap: {} > {}",
                tee_expired_target_exclusions.len(),
                outbe_primitives::validators::MAX_TEE_EXPIRED_TARGET_EXCLUSIONS
            )));
        }
        let mut unique_exclusions = std::collections::BTreeSet::new();
        for address in tee_expired_target_exclusions {
            if address.is_zero() || !unique_exclusions.insert(*address) {
                return Err(PrecompileError::Fatal(
                    "TEE expiry exclusions must contain unique non-zero validators".into(),
                ));
            }
            if new_active_set.contains(address) {
                return Err(PrecompileError::Fatal(format!(
                    "TEE-expired validator {address} is also present in the new active set"
                )));
            }
            if self.address_to_index.read(address)? == 0 {
                return Err(PrecompileError::Fatal(format!(
                    "TEE expiry exclusions contain unregistered validator {address}"
                )));
            }
        }
        self.apply_reshared_set(
            new_active_set,
            active_set_hash,
            freeze_height,
            tee_expired_target_exclusions,
        )
    }

    fn apply_reshared_set(
        &mut self,
        new_active_set: &[Address],
        active_set_hash: B256,
        freeze_height: u64,
        tee_expired_target_exclusions: &[Address],
    ) -> Result<()> {
        let active_count: u32 = new_active_set
            .len()
            .try_into()
            .map_err(|_| PrecompileError::Revert("active set count exceeds u32".into()))?;
        let addresses = self.registered_validator_addresses()?;
        let mut states = Vec::with_capacity(addresses.len());
        for addr in addresses {
            states.push(self.validator_state(addr)?);
        }

        // Plan the entire state transition before the first write. Canonical
        // Commonware order and the address hash are validated by the executor
        // against the incoming snapshot; this layer validates unique membership
        // and lifecycle eligibility.
        let mut transitions = Vec::with_capacity(states.len());
        let mut transitioned_to_unbonding = Vec::new();
        let mut tee_expired_active = Vec::new();
        let mut tee_expired_pending = Vec::new();
        for before in states {
            let included = new_active_set.contains(&before.address());
            let tee_expired = tee_expired_target_exclusions.contains(&before.address());
            let changed_at = before
                .history()
                .and_then(ValidatorHistory::last_deactivated_at_height);
            let lifecycle = match (before.lifecycle().clone(), included, tee_expired) {
                (ValidatorLifecycle::Active(active), false, true) => {
                    tee_expired_active.push(before.address());
                    ValidatorLifecycle::WaitingForReadiness(state_machine::expire_active_tee(
                        active,
                    ))
                }
                (ValidatorLifecycle::Joining(joining), false, true) => {
                    tee_expired_pending.push(before.address());
                    ValidatorLifecycle::WaitingForReadiness(state_machine::expire_joining_tee(
                        joining,
                    ))
                }
                (ValidatorLifecycle::WaitingForReadiness(waiting), false, true) => {
                    tee_expired_pending.push(before.address());
                    ValidatorLifecycle::WaitingForReadiness(waiting)
                }
                (ValidatorLifecycle::Joining(joining), true, false) => {
                    if self.ocomp_registration(before.address())?.is_none() {
                        return Err(PrecompileError::Fatal(format!(
                            "certified active set contains validator {} without OCOMP admission",
                            before.address()
                        )));
                    }
                    ValidatorLifecycle::Active(state_machine::activate_at_boundary(joining))
                }
                (ValidatorLifecycle::Active(active), true, false) => {
                    ValidatorLifecycle::Active(state_machine::retain_active_at_boundary(active))
                }
                (ValidatorLifecycle::Active(_), false, false) => {
                    return Err(PrecompileError::Fatal(format!(
                        "validated boundary omitted active validator {}",
                        before.address()
                    )));
                }
                (ValidatorLifecycle::Exiting(exiting), true, false) => {
                    let changed_at = changed_at.ok_or_else(|| {
                        PrecompileError::Fatal(format!(
                            "exiting validator {} has no deactivation height",
                            before.address()
                        ))
                    })?;
                    if changed_at <= freeze_height {
                        return Err(PrecompileError::Fatal(format!(
                            "validated boundary retained validator {} that exited at {changed_at} before freeze {freeze_height}",
                            before.address()
                        )));
                    }
                    ValidatorLifecycle::Exiting(exiting)
                }
                (ValidatorLifecycle::Exiting(exiting), false, false) => {
                    let changed_at = changed_at.ok_or_else(|| {
                        PrecompileError::Fatal(format!(
                            "exiting validator {} has no deactivation height",
                            before.address()
                        ))
                    })?;
                    if changed_at > freeze_height {
                        return Err(PrecompileError::Fatal(format!(
                            "validated boundary omitted validator {} that exited at {changed_at} after freeze {freeze_height}",
                            before.address()
                        )));
                    }
                    transitioned_to_unbonding.push(before.address());
                    ValidatorLifecycle::Unbonding(state_machine::exclude_exiting_at_boundary(
                        exiting,
                    ))
                }
                (ValidatorLifecycle::JailRetained(jailed), true, false) => {
                    let jailed_at = before.stored_jailed_at();
                    if jailed_at <= freeze_height {
                        return Err(PrecompileError::Fatal(format!(
                            "validated boundary retained validator {} jailed at {jailed_at} before freeze {freeze_height}",
                            before.address()
                        )));
                    }
                    ValidatorLifecycle::JailRetained(jailed)
                }
                (ValidatorLifecycle::JailRetained(jailed), false, false) => {
                    let jailed_at = before.stored_jailed_at();
                    if jailed_at > freeze_height {
                        return Err(PrecompileError::Fatal(format!(
                            "validated boundary omitted validator {} jailed at {jailed_at} after freeze {freeze_height}",
                            before.address()
                        )));
                    }
                    ValidatorLifecycle::Jail(state_machine::exclude_jailed_at_boundary(jailed))
                }
                (ValidatorLifecycle::Joining(joining), false, false) => {
                    ValidatorLifecycle::Joining(joining)
                }
                (lifecycle, false, false) => lifecycle,
                (lifecycle, true, false) => {
                    return Err(PrecompileError::Fatal(format!(
                        "validated boundary included ineligible validator {} with status {}",
                        before.address(),
                        registered_status(&lifecycle)?
                    )));
                }
                (lifecycle, _, true) => {
                    return Err(PrecompileError::Fatal(format!(
                        "TEE expiry exclusion contains validator {} with ineligible status {}",
                        before.address(),
                        registered_status(&lifecycle)?
                    )));
                }
            };
            let after = before.clone().with_lifecycle(lifecycle)?;
            transitions.push((before, after));
        }

        let planned_participants: Vec<_> = transitions
            .iter()
            .filter_map(|(_, after)| {
                after
                    .lifecycle()
                    .is_current_consensus_participant()
                    .then_some(after.address())
            })
            .collect();
        let unique_artifact_members: HashSet<_> = new_active_set.iter().copied().collect();
        if unique_artifact_members.len() != new_active_set.len()
            || planned_participants.len() != new_active_set.len()
            || planned_participants
                .iter()
                .any(|address| !unique_artifact_members.contains(address))
        {
            return Err(PrecompileError::Fatal(format!(
                "validated boundary participant membership mismatch: planned {planned_participants:?}, artifact {new_active_set:?}"
            )));
        }

        let pending = transitions.iter().any(|(_, after)| {
            matches!(
                after.lifecycle(),
                ValidatorLifecycle::WaitingForReadiness(_)
                    | ValidatorLifecycle::Joining(_)
                    | ValidatorLifecycle::Exiting(_)
                    | ValidatorLifecycle::JailRetained(_)
            )
        });

        // The planner above performs every fallible semantic check before this
        // checkpoint. Storage writes, hash, repair flag, and event commit as one
        // bundle even for direct legacy calls.
        let guard = self.storage.checkpoint_guard();
        for (before, after) in &transitions {
            self.persist_validator_state_delta(before, after)?;
        }
        self.active_consensus_set_hash.write(active_set_hash)?;
        self.pending_set_change.write(pending)?;
        self.emit(IValidatorSet::ConsensusSetUpdated {
            activeCount: active_count,
        })?;
        guard.commit();

        crate::metrics::record_reshared_set_activated(
            active_count,
            transitioned_to_unbonding.len(),
        );
        crate::metrics::record_pending_set_change(pending);
        for (_, after) in &transitions {
            if let Some(stored_status) = after.stored_status() {
                crate::metrics::record_validator_status(after.address(), stored_status);
            }
        }
        for addr in &tee_expired_active {
            crate::metrics::record_validator_status(*addr, status::PENDING);
            crate::metrics::record_validator_tee_expiry(*addr, "active_demoted");
        }
        for addr in &tee_expired_pending {
            crate::metrics::record_validator_tee_expiry(*addr, "pending_cleared");
        }
        crate::metrics::record_tee_expiry_exclusions(
            tee_expired_active.len(),
            tee_expired_pending.len(),
        );

        let block_number = self.storage.block_number().unwrap_or(0);
        journal_record(JournalRecord::ResharedSetActivated {
            wall_clock: iso8601_now(),
            block_number,
            active_count,
            transitioned_to_unbonding: transitioned_to_unbonding.len() as u64,
            pending_set_change: pending,
            active_set_hash: format!("{active_set_hash:?}"),
        });
        for addr in &transitioned_to_unbonding {
            journal_record(JournalRecord::ValidatorUnbonding {
                wall_clock: iso8601_now(),
                block_number,
                validator: format!("{addr:?}"),
            });
        }

        let mut active = 0usize;
        let mut exiting = 0usize;
        let mut unbonding = 0usize;
        for (_, after) in &transitions {
            match after.lifecycle() {
                ValidatorLifecycle::Active(_) => active += 1,
                ValidatorLifecycle::Exiting(_) => exiting += 1,
                ValidatorLifecycle::Unbonding(_) => unbonding += 1,
                _ => {}
            }
        }
        crate::metrics::record_aggregate_status_counts(active, exiting, unbonding);

        info!(
            target: "outbe::validatorset",
            event = "reshared_set_activated",
            active_count,
            transitioned_to_unbonding = transitioned_to_unbonding.len(),
            pending_set_change = pending,
            block_number,
            active_set_hash = %active_set_hash,
            "DKG reshare activated; new active set committed",
        );
        for addr in &transitioned_to_unbonding {
            info!(
                target: "outbe::validatorset",
                event = "validator_unbonding",
                validator = %addr,
                block_number,
                "validator transitioned EXITING -> UNBONDING (excluded from new set)",
            );
        }
        for addr in &tee_expired_active {
            warn!(
                target: "outbe::validatorset",
                event = "validator_tee_expired_demoted",
                validator = %addr,
                block_number = self.storage.block_number().unwrap_or(0),
                "certified freeze-height TEE expiry demoted ACTIVE validator to PENDING"
            );
        }
        for addr in &tee_expired_pending {
            warn!(
                target: "outbe::validatorset",
                event = "validator_tee_expired_readiness_cleared",
                validator = %addr,
                block_number = self.storage.block_number().unwrap_or(0),
                "certified freeze-height TEE expiry cleared PENDING validator readiness"
            );
        }

        Ok(())
    }

    /// Records a block proposal by the given validator.
    ///
    /// Increments `blocks_proposed` for a current consensus participant.
    pub fn record_proposer(&mut self, addr: Address) -> Result<()> {
        if !self.is_consensus_participant(addr)? {
            return Err(PrecompileError::Revert(format!(
                "proposer is not a current consensus participant: {addr}"
            )));
        }
        let proposed = self.val_blocks_proposed.read(&addr)?;
        self.val_blocks_proposed.write(
            &addr,
            proposed
                .checked_add(1)
                .ok_or_else(|| PrecompileError::Fatal("blocks proposed overflow".into()))?,
        )?;

        Ok(())
    }

    /// Records a missed block for the given validator.
    pub fn record_missed_block(&mut self, addr: Address) -> Result<()> {
        let missed = self.val_missed_blocks.read(&addr)?;
        self.val_missed_blocks.write(
            &addr,
            missed
                .checked_add(1)
                .ok_or_else(|| PrecompileError::Fatal("missed blocks overflow".into()))?,
        )?;
        Ok(())
    }

    /// Records vote participation: increments `missed_votes` for each absent validator.
    pub fn record_participation(&mut self, voters: &[Address], absent: &[Address]) -> Result<()> {
        for addr in voters {
            if !self.is_consensus_participant(*addr)? {
                return Err(PrecompileError::Revert(format!(
                    "voter is not a current consensus participant: {addr}"
                )));
            }
        }
        for addr in absent {
            if !self.is_consensus_participant(*addr)? {
                return Err(PrecompileError::Revert(format!(
                    "absent voter is not a current consensus participant: {addr}"
                )));
            }
            let missed = self.val_missed_votes.read(addr)?;
            self.val_missed_votes.write(
                addr,
                missed
                    .checked_add(1)
                    .ok_or_else(|| PrecompileError::Fatal("missed votes overflow".into()))?,
            )?;
        }
        Ok(())
    }

    /// Records vote participation for a historical (finalized-parent) committee.
    ///
    /// Finalized-parent metadata describes a committee captured at a previous
    /// finalized block. By the time it is applied here, some members may no
    /// longer be current consensus participants (e.g. transitioned to
    /// `UNBONDING` after a reshare). This entrypoint validates that every
    /// supplied address is a registered validator but does not require current
    /// `ACTIVE`/`EXITING` + `has_bls_share` membership.
    pub fn record_finalized_participation(
        &mut self,
        voters: &[Address],
        absent: &[Address],
    ) -> Result<()> {
        for addr in voters {
            if !self.is_validator(*addr)? {
                return Err(PrecompileError::Revert(format!(
                    "finalized voter is not a registered validator: {addr}"
                )));
            }
        }
        for addr in absent {
            if !self.is_validator(*addr)? {
                return Err(PrecompileError::Revert(format!(
                    "finalized absent voter is not a registered validator: {addr}"
                )));
            }
            let missed = self.val_missed_votes.read(addr)?;
            self.val_missed_votes.write(
                addr,
                missed
                    .checked_add(1)
                    .ok_or_else(|| PrecompileError::Fatal("missed votes overflow".into()))?,
            )?;
        }
        Ok(())
    }

    /// Resets ValidatorSet-owned per-epoch counters for the outgoing committee.
    ///
    /// Kept separate from [`Self::advance_epoch`] because certified-parent and
    /// late-finalization accounting execute before the receipt-visible boundary
    /// activation. The executor resets only for a block that actually carries a
    /// certified BoundaryOutcome, then advances the epoch later in that block.
    pub fn reset_epoch_counters(&mut self) -> Result<()> {
        for addr in self.registered_validator_addresses()? {
            // Only reset counters for validators that accumulate them.
            // Include EXITING - they still participate in consensus
            // until reshare completes and accumulate per-epoch counters.
            // JailRetained is likewise still in the live committee until the
            // next reshare clears its share, so reset its counters too. Jail is
            // already excluded; late historical counters are cleared on unjail.
            if !matches!(
                self.validator_lifecycle(addr)?,
                ValidatorLifecycle::Active(_)
                    | ValidatorLifecycle::Exiting(_)
                    | ValidatorLifecycle::JailRetained(_)
            ) {
                continue;
            }
            self.val_missed_blocks.write(&addr, 0)?;
            self.val_missed_votes.write(&addr, 0)?;
            self.val_blocks_proposed.write(&addr, 0)?;
        }

        Ok(())
    }

    /// Advances the activated epoch anchor without resetting counters.
    pub fn advance_epoch(&mut self, timestamp: u64, block_number: u64) -> Result<()> {
        let epoch = self.epoch_number.read()?;
        let new_epoch = epoch
            .checked_add(U256::from(1))
            .ok_or_else(|| PrecompileError::Fatal("epoch number overflow".into()))?;
        self.epoch_number.write(new_epoch)?;
        self.epoch_start_timestamp.write(timestamp)?;
        self.epoch_start_block.write(block_number)?;

        let active_count = self.active_validator_count()?;
        self.emit(IValidatorSet::EpochTransition {
            newEpochNumber: new_epoch,
            timestamp,
            activeValidatorCount: active_count,
        })?;

        Ok(())
    }

    /// Resets per-epoch counters and advances the epoch.
    ///
    /// This combined form remains the module-level convenience API. Production
    /// boundary execution uses the two explicit halves to preserve the
    /// LateFinalizeCredits ordering contract.
    pub fn update_epoch(&mut self, timestamp: u64, block_number: u64) -> Result<()> {
        self.reset_epoch_counters()?;
        self.advance_epoch(timestamp, block_number)
    }

    /// Removes INACTIVE validator entries from the registry via swap-remove.
    ///
    /// `max_removals` caps how many entries are cleaned per call (0 = unlimited).
    /// Returns the number of entries removed.
    pub fn cleanup_inactive_validators(&mut self, max_removals: u32) -> Result<u32> {
        let guard = self.storage.checkpoint_guard();
        let mut count = self.validator_count.read()?;
        let mut removed = 0u32;
        let mut i = 1u64;
        let current_height = self.storage.block_number()?;
        let cooldown = u64::from(self.config_reregistration_cooldown.read()?);

        while i <= count as u64 {
            if max_removals > 0 && removed >= max_removals {
                break;
            }
            let addr = self.index_to_address.read(&i)?;
            if addr.is_zero() {
                i += 1;
                continue;
            }
            let state = self.validator_state(addr)?;
            let ValidatorLifecycle::Inactive(inactive) = state.lifecycle().clone() else {
                i += 1;
                continue;
            };
            let deactivated_at = state
                .history()
                .and_then(ValidatorHistory::last_deactivated_at_height)
                .ok_or_else(|| {
                    PrecompileError::Fatal(format!(
                        "inactive validator {addr} has no deactivation height"
                    ))
                })?;
            let cleanup_at = deactivated_at
                .checked_add(cooldown)
                .ok_or_else(|| PrecompileError::Fatal("inactive cleanup height overflow".into()))?;
            if current_height < cleanup_at {
                i += 1;
                continue;
            }

            if self.val_ocomp_recovery_deadline.read(&addr)? != 0 {
                i += 1;
                continue;
            }
            debug_assert_eq!(state_machine::cleanup(inactive), ValidatorLifecycle::Absent);
            // Clear all per-validator storage
            self.clear_validator_storage(&addr)?;

            // Swap with last entry
            let count_u64 = count as u64;
            if i < count_u64 {
                let last_addr = self.index_to_address.read(&count_u64)?;
                self.index_to_address.write(&i, last_addr)?;
                self.address_to_index.write(&last_addr, i)?;
            }
            // Clear the last slot
            self.index_to_address.write(&count_u64, Address::ZERO)?;
            self.address_to_index.write(&addr, 0)?;
            count -= 1;
            removed += 1;
            // Don't increment i - the swapped-in entry needs checking
        }

        self.validator_count.write(count)?;
        guard.commit();
        Ok(removed)
    }

    /// Clears all per-validator storage fields for an address.
    fn clear_validator_storage(&mut self, addr: &Address) -> Result<()> {
        let pubkey = self.read_consensus_pubkey(addr)?;
        let pk_hash = Self::consensus_pubkey_hash(&pubkey);
        self.consensus_pubkey_hash_to_address
            .write(&pk_hash, Address::ZERO)?;
        let radicle_node_id = self.val_radicle_node_id.read(addr)?;
        if !radicle_node_id.is_zero() {
            self.radicle_node_id_to_validator
                .write(&radicle_node_id, Address::ZERO)?;
        }
        self.val_radicle_node_id.write(addr, B256::ZERO)?;

        self.write_consensus_pubkey(addr, &[0u8; 48])?;
        self.val_stake.write(addr, U256::ZERO)?;
        self.val_status.write(addr, 0)?;
        self.val_slash_count.write(addr, 0)?;
        self.val_missed_blocks.write(addr, 0)?;
        self.val_missed_votes.write(addr, 0)?;
        self.val_blocks_proposed.write(addr, 0)?;
        self.val_joined_at_height.write(addr, 0)?;
        self.val_deactivated_at_height.write(addr, 0)?;
        self.val_unbonding_end.write(addr, 0)?;
        self.val_has_bls_share.write(addr, false)?;
        self.val_p2p_address_version.write(addr, 0)?;
        self.val_p2p_address_payload.get_bytes(addr).clear()?;
        // Stale-join + jail per-validator state must be cleared too, so a future
        // re-registration at the same address starts clean (a leaked
        // `val_join_confirmed = true` would bypass the stale-join guard). The
        // admitted V1 OCOMP key and reverse reservation deliberately survive:
        // key_epoch=1 has no rotation, loss, or recovery path.
        self.val_join_confirmed.write(addr, false)?;
        self.val_jailed_at_height.write(addr, 0)?;
        self.val_ocomp_miss_count.write(addr, 0)?;
        self.val_ocomp_recovery_deadline.write(addr, 0)?;
        Ok(())
    }

    /// Returns `true` if the address is a registered validator.
    pub fn is_validator(&self, addr: Address) -> Result<bool> {
        Ok(self.validator_state(addr)?.is_registered())
    }

    /// Looks up a validator address by consensus pubkey hash.
    ///
    /// The hash is `keccak256(48-byte BLS MinPk pubkey)`.
    pub fn lookup_by_pubkey_hash(&self, pubkey_hash: B256) -> Result<Address> {
        self.consensus_pubkey_hash_to_address.read(&pubkey_hash)
    }

    /// Returns the Radicle NodeId bound to `validator`, or zero when absent.
    pub fn get_radicle_node_id(&self, validator: Address) -> Result<B256> {
        self.val_radicle_node_id.read(&validator)
    }

    /// Returns the validator that owns `node_id`, or zero when unbound.
    pub fn validator_by_radicle_node_id(&self, node_id: B256) -> Result<Address> {
        self.radicle_node_id_to_validator.read(&node_id)
    }
}

/// Verifies a BLS MinPk registration signature.
///
/// Uses the `blst` crate directly to verify the signature without needing
/// the full commonware cryptography stack in the EVM precompile crate.
///
/// The signed message is `chain_id (u64 big-endian) || validator address`.
fn verify_bls_registration_sig(
    pubkey_bytes: &[u8; 48],
    sig_bytes: &[u8; 96],
    chain_id: u64,
    validator_addr: Address,
    radicle_node_id: B256,
) -> Result<()> {
    use blst::min_pk::{PublicKey, Signature};
    use blst::BLST_ERROR;

    let pk = PublicKey::from_bytes(pubkey_bytes)
        .map_err(|_| PrecompileError::Revert("invalid BLS public key".into()))?;
    let sig = Signature::from_bytes(sig_bytes)
        .map_err(|_| PrecompileError::Revert("invalid BLS signature".into()))?;

    let message = validator_registration_message(chain_id, validator_addr, radicle_node_id);
    let result = sig.verify(true, &message, VALIDATOR_REGISTRATION_DST, &[], &pk, true);
    if result != BLST_ERROR::BLST_SUCCESS {
        return Err(PrecompileError::Revert(
            "invalid BLS registration signature".into(),
        ));
    }
    Ok(())
}
