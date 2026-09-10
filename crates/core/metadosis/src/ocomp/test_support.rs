//! Rust-only fixture for cross-crate OCOMP activation tests.
//!
//! This module is available only through the explicit `test-utils` feature.
//! It builds consensus-valid activation bytes and seeds the real Metadosis and
//! owner storage APIs; it does not provide a production activation shortcut.

#[cfg(test)]
use std::cell::Cell;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_primitives::{keccak256, Address, Bytes, Log, B256, U256};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use outbe_compressed_entities::{
    begin_block, partition_collection_key, AuthenticatedParentTree, CeWorkCheckpoint, CeWorkConfig,
    EntityRef, ExecutionScope, FinalLeafMutation, PartitionRef, ProvisionalTreeBatch,
};
#[cfg(test)]
use outbe_lysis::activation_v1::LysisOwnerReceiptsV1;
use outbe_nod::schema::NodContract;
#[cfg(test)]
use outbe_ocomp_protocol::league_snapshot::league_snapshot_key;
#[cfg(test)]
use outbe_ocomp_protocol::state::OcompJobStatus;
use outbe_ocomp_protocol::{
    committee::{
        validator_identity_hash_v1, OcompKeyRegistrationCoreV1, OcompKeyRegistrationV1,
        RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    common::{BoundedBytes, ProofBytes},
    hash::hash_framed,
    intent::{
        intent_storage_key, ActivationPreconditionsV1, AuctionEntryPriceSource,
        CertifiedParentAccountingMetadataV2, ContributorTargetPreconditionV1, DayType,
        ExpectedFinalizedIntentBindingV1, FinalizedIntentProofV1, FinalizedIntentVerificationError,
        FinalizedRequestBindingV1, FrozenMetadosisValuesV1, JobIntentV1,
        MetadosisAttemptPreconditionV1, MetadosisExpectedStatus, NodTargetPreconditionV1,
        ParentProofKind, ReferenceEntryPriceV1, TributeInputBindingV1, VerifiedFinalizedIntentV1,
    },
    profile::{CapacityProfileV1, ProtocolBundleV1},
    receipts::{
        desis_request_brief_hash, ActivationOutcome, BudgetSplitDestination,
        RequestBudgetSplitReceiptV1,
    },
    registry::HashDomain,
    result::{
        lysis_v1_empty_semantic_event_root, CarryOverCreditActionV1, CarryOverReason,
        CompletionStatus, ConservationTotalsV1, ExactCountsV1, LysisArithmeticSummaryV1,
        LysisResultV1, MetadosisCompletionSummaryV1, ResultRootsV1,
    },
    state::RESULT_VOTE_MIN_FINALITY_DEPTH,
    vote::ResultVoteV1,
    SchemaLimits,
};
#[cfg(test)]
use outbe_primitives::addresses::STAKING_ADDRESS;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::{COMPRESSED_ENTITIES_ADDRESS, METADOSIS_ADDRESS},
    error::{PrecompileError, Result as PrecompileResult},
    storage::{hashmap::HashMapStorageProvider, MetadosisMutationPurposeTag, StorageHandle},
};
use outbe_tribute::{DayPreAdmission, DayTotals, TributeContract};
use outbe_validatorset::{
    contract::ValidatorSet, read_ocomp_snapshot_extension, OcompSnapshotExtensionV1,
};

#[cfg(test)]
use crate::errors::MetadosisError;
#[cfg(test)]
use crate::schema::{
    DayLimitFormationReceiptStateEntryExt, OcompDayLimitFormationStateEntryExt,
    WorldwideDayEntryExt,
};
use crate::{
    constants::{FORMING_PERIOD_HOURS, MAX_ACTIVE_WWDS, SECONDS_PER_HOUR, WAITING_PERIOD_HOURS},
    ocomp::{
        activation::{OcompFinalityAuthorityError, OcompFinalizedIntentAuthority},
        fork::{OcompForkInstallClassification, OcompForkInstallV1},
        schema::{poc_schema_limits, OcompRequestProfile},
    },
    schema::{day_type, status, MetadosisContract, WorldwideDay as WorldwideDayRecord},
};
pub const TEST_WWD: WorldwideDay = WorldwideDay::new(20_260_723);
pub const TEST_REQUEST_HEIGHT: u64 = 10;
pub const TEST_LOGICAL_TIME: u64 = 1_000;

/// Closed, test-only receipt corruptions retained from the original atomic
/// activation regression suite. The enum never crosses the private fixture
/// kernel or becomes part of the public semantic facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum ActivationReceiptFault {
    Nod,
    Contributor,
    Tribute,
    CarryOver,
    RequestSplit,
}

#[cfg(test)]
thread_local! {
    static ACTIVATION_RECEIPT_FAULT: Cell<Option<ActivationReceiptFault>> =
        const { Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn inject_receipt_fault(
    request_receipt: &mut RequestBudgetSplitReceiptV1,
    receipts: &mut LysisOwnerReceiptsV1,
) {
    match ACTIVATION_RECEIPT_FAULT.with(Cell::take) {
        Some(ActivationReceiptFault::Nod) => receipts.nod.nod_root = hash(210),
        Some(ActivationReceiptFault::Contributor) => {
            receipts.contributor.contributor_count += 1;
        }
        Some(ActivationReceiptFault::Tribute) => receipts.tribute.retired_generation += 1,
        Some(ActivationReceiptFault::CarryOver) => {
            receipts.carry_over.credited_unused_lysis += U256::from(1);
            receipts.carry_over.after_value += U256::from(1);
        }
        Some(ActivationReceiptFault::RequestSplit) => {
            request_receipt.logical_anchor += 1;
        }
        None => {}
    }
}

/// Crate-private raw fixture kernel.
///
/// Production mutations must never use this trait. It exists only in test or
/// `test-utils` builds so predecessor state and intentional corruption remain
/// owned by one private module instead of leaking through `MetadosisContract`.
pub(crate) trait FixtureKernelExt {
    fn create_worldwide_day(
        &mut self,
        wwd: WorldwideDay,
        forming_start: u64,
        lookback_delay_hours: u64,
        offering_period_hours: u64,
    ) -> PrecompileResult<()>;

    #[cfg(test)]
    fn delete_worldwide_day(&mut self, wwd: WorldwideDay) -> PrecompileResult<()>;

    #[cfg(test)]
    fn set_metadosis_limit(&mut self, wwd: WorldwideDay, amount: U256) -> PrecompileResult<()>;

    #[cfg(test)]
    fn fixture_set_wwd_status(
        &mut self,
        wwd: WorldwideDay,
        status: crate::WwdStatus,
    ) -> PrecompileResult<()>;

    fn fixture_create_ready_day(
        &mut self,
        wwd: WorldwideDay,
        day_limit: U256,
        previous_vwap: U256,
        current_vwap: U256,
    ) -> PrecompileResult<()>;

    #[cfg(test)]
    fn corrupt_wwd_status_tag(&mut self, wwd: WorldwideDay, tag: u8) -> PrecompileResult<()>;

    #[cfg(test)]
    fn corrupt_wwd_day_type_tag(&mut self, wwd: WorldwideDay, tag: u8) -> PrecompileResult<()>;

    #[cfg(test)]
    fn fixture_seed_day_limit_formation(&mut self, wwd: WorldwideDay) -> PrecompileResult<()>;

    #[cfg(test)]
    fn fixture_set_scheduled_process_time(
        &mut self,
        wwd: WorldwideDay,
        scheduled_process_time: u64,
    ) -> PrecompileResult<()>;

    #[cfg(test)]
    fn fixture_write_league_snapshot(
        &mut self,
        wwd: u32,
        owner: Address,
        value: u16,
    ) -> PrecompileResult<()>;

    #[cfg(test)]
    fn corrupt_ocomp_job_record(
        &mut self,
        intent_id: B256,
        encoded_record: &[u8],
    ) -> PrecompileResult<()>;

    #[cfg(test)]
    fn fixture_set_wwd_status_from_timestamp(
        &mut self,
        wwd: WorldwideDay,
        block_time: u64,
    ) -> PrecompileResult<crate::WwdStatus>;

    #[cfg(test)]
    fn set_wwd_day_type(
        &mut self,
        wwd: WorldwideDay,
        day_type: crate::WwdDayType,
    ) -> PrecompileResult<()>;

    #[cfg(test)]
    fn set_wwd_vwap(&mut self, wwd: WorldwideDay, vwap: U256) -> PrecompileResult<()>;

    fn add_active_wwd(&mut self, wwd: WorldwideDay) -> PrecompileResult<()>;

    #[cfg(test)]
    fn remove_active_wwd(&mut self, wwd: WorldwideDay) -> PrecompileResult<()>;
}

impl FixtureKernelExt for MetadosisContract<'_> {
    fn create_worldwide_day(
        &mut self,
        wwd: WorldwideDay,
        forming_start: u64,
        lookback_delay_hours: u64,
        offering_period_hours: u64,
    ) -> PrecompileResult<()> {
        let seconds = |hours: u64, label: &str| {
            hours.checked_mul(SECONDS_PER_HOUR).ok_or_else(|| {
                PrecompileError::Revert(format!("Metadosis {label} duration overflow"))
            })
        };
        let forming_end = forming_start
            .checked_add(seconds(FORMING_PERIOD_HOURS, "forming")?)
            .ok_or_else(|| PrecompileError::Revert("Metadosis forming window overflow".into()))?;
        let lookback_end = forming_end
            .checked_add(seconds(lookback_delay_hours, "lookback")?)
            .ok_or_else(|| PrecompileError::Revert("Metadosis lookback window overflow".into()))?;
        let offering_end = lookback_end
            .checked_add(seconds(offering_period_hours, "offering")?)
            .ok_or_else(|| PrecompileError::Revert("Metadosis offering window overflow".into()))?;
        let scheduled_process_time = offering_end
            .checked_add(seconds(WAITING_PERIOD_HOURS, "waiting")?)
            .ok_or_else(|| PrecompileError::Revert("Metadosis waiting window overflow".into()))?;

        self.worldwide_days.create(&WorldwideDayRecord {
            wwd,
            status: crate::WwdStatus::Forming.as_u8(),
            day_type: crate::WwdDayType::Unknown.as_u8(),
            forming_start,
            forming_end,
            lookback_end,
            offering_end,
            scheduled_process_time,
            metadosis_limit_amount: U256::ZERO,
            previous_vwap: U256::ZERO,
            current_vwap: U256::ZERO,
        })
    }

    #[cfg(test)]
    fn delete_worldwide_day(&mut self, wwd: WorldwideDay) -> PrecompileResult<()> {
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            if self.worldwide_day_terminal_receipts.get(wwd)?.is_some() {
                self.worldwide_day_terminal_receipts.delete(wwd)?;
            }
            if self.capacity_forfeiture_receipts.get(wwd)?.is_some() {
                self.capacity_forfeiture_receipts.delete(wwd)?;
            }
            self.worldwide_days.delete(wwd)?;
            if self.ocomp_day_limit_formations.entry(wwd).formed().read()? {
                self.ocomp_day_limit_formations.delete(wwd)?;
            }
            if self
                .day_limit_formation_receipts
                .entry(wwd)
                .formed()
                .read()?
            {
                self.day_limit_formation_receipts.delete(wwd)?;
            }
            Ok(())
        })
    }

    #[cfg(test)]
    fn set_metadosis_limit(&mut self, wwd: WorldwideDay, amount: U256) -> PrecompileResult<()> {
        if self.ocomp_day_limit_formations.entry(wwd).formed().read()? {
            return Err(PrecompileError::Revert(
                "formed OCOMP day limit is immutable".into(),
            ));
        }
        self.worldwide_days
            .entry(wwd)
            .metadosis_limit_amount()
            .write(amount)
    }

    #[cfg(test)]
    fn fixture_set_wwd_status(
        &mut self,
        wwd: WorldwideDay,
        status: crate::WwdStatus,
    ) -> PrecompileResult<()> {
        self.worldwide_days
            .entry(wwd)
            .status()
            .write(status.as_u8())
    }

    fn fixture_create_ready_day(
        &mut self,
        wwd: WorldwideDay,
        day_limit: U256,
        previous_vwap: U256,
        current_vwap: U256,
    ) -> PrecompileResult<()> {
        self.worldwide_days.create(&WorldwideDayRecord {
            wwd,
            status: crate::WwdStatus::Ready.as_u8(),
            day_type: crate::WwdDayType::Green.as_u8(),
            forming_start: 1,
            forming_end: 2,
            lookback_end: 3,
            offering_end: 4,
            scheduled_process_time: 5,
            metadosis_limit_amount: day_limit,
            previous_vwap,
            current_vwap,
        })
    }

    #[cfg(test)]
    fn corrupt_wwd_status_tag(&mut self, wwd: WorldwideDay, tag: u8) -> PrecompileResult<()> {
        self.worldwide_days.entry(wwd).status().write(tag)
    }

    #[cfg(test)]
    fn corrupt_wwd_day_type_tag(&mut self, wwd: WorldwideDay, tag: u8) -> PrecompileResult<()> {
        self.worldwide_days.entry(wwd).day_type().write(tag)
    }

    #[cfg(test)]
    fn fixture_seed_day_limit_formation(&mut self, wwd: WorldwideDay) -> PrecompileResult<()> {
        let day_limit = self
            .worldwide_days
            .entry(wwd)
            .metadosis_limit_amount()
            .read()?;
        let formation = self.ocomp_day_limit_formations.entry(wwd);
        formation.carry_over_taken().write(U256::ZERO)?;
        formation.formed().write(true)?;
        let receipt = self.day_limit_formation_receipts.entry(wwd);
        receipt.base_limit().write(day_limit)?;
        receipt.carry_over_before().write(U256::ZERO)?;
        receipt.carry_over_taken().write(U256::ZERO)?;
        receipt.carry_over_after().write(U256::ZERO)?;
        receipt.formed_day_limit().write(day_limit)?;
        receipt.block_number().write(1)?;
        receipt.formed().write(true)
    }

    #[cfg(test)]
    fn fixture_set_scheduled_process_time(
        &mut self,
        wwd: WorldwideDay,
        scheduled_process_time: u64,
    ) -> PrecompileResult<()> {
        self.worldwide_days
            .entry(wwd)
            .scheduled_process_time()
            .write(scheduled_process_time)
    }

    #[cfg(test)]
    fn fixture_write_league_snapshot(
        &mut self,
        wwd: u32,
        owner: Address,
        value: u16,
    ) -> PrecompileResult<()> {
        self.ocomp_fidelity_league_snapshot
            .write(&league_snapshot_key(wwd, owner), value)
    }

    #[cfg(test)]
    fn corrupt_ocomp_job_record(
        &mut self,
        intent_id: B256,
        encoded_record: &[u8],
    ) -> PrecompileResult<()> {
        let key = intent_storage_key(intent_id).map_err(|error| {
            PrecompileError::Fatal(format!("fixture OCOMP intent key is invalid: {error}"))
        })?;
        self.ocomp_job_records.get_bytes(&key).write(encoded_record)
    }

    #[cfg(test)]
    fn fixture_set_wwd_status_from_timestamp(
        &mut self,
        wwd: WorldwideDay,
        block_time: u64,
    ) -> PrecompileResult<crate::WwdStatus> {
        let day = self.worldwide_days.entry(wwd);
        let current = crate::WwdStatus::try_from(day.status().read()?)?;
        if current.is_terminal() {
            return Ok(current);
        }
        let next = if block_time < day.forming_end().read()? {
            crate::WwdStatus::Forming
        } else if block_time < day.lookback_end().read()? {
            crate::WwdStatus::LookbackDelay
        } else if block_time < day.offering_end().read()? {
            crate::WwdStatus::Offering
        } else if block_time < day.scheduled_process_time().read()? {
            crate::WwdStatus::Waiting
        } else {
            crate::WwdStatus::Ready
        };
        if next != current {
            day.status().write(next.as_u8())?;
        }
        Ok(next)
    }

    #[cfg(test)]
    fn set_wwd_day_type(
        &mut self,
        wwd: WorldwideDay,
        day_type: crate::WwdDayType,
    ) -> PrecompileResult<()> {
        self.worldwide_days
            .entry(wwd)
            .day_type()
            .write(day_type.as_u8())
    }

    #[cfg(test)]
    fn set_wwd_vwap(&mut self, wwd: WorldwideDay, vwap: U256) -> PrecompileResult<()> {
        if vwap.is_zero() {
            return Err(MetadosisError::VwapMustBeNonZero.into());
        }
        self.worldwide_days.entry(wwd).current_vwap().write(vwap)
    }

    fn add_active_wwd(&mut self, wwd: WorldwideDay) -> PrecompileResult<()> {
        let active = self.active_wwd.read_all()?;
        if active.contains(&wwd) {
            return Ok(());
        }
        if active.len() >= MAX_ACTIVE_WWDS {
            return Err(PrecompileError::Fatal(format!(
                "Metadosis active WWD cap {MAX_ACTIVE_WWDS} reached before inserting {wwd}"
            )));
        }
        self.active_wwd.insert(wwd).map(|_| ())
    }

    #[cfg(test)]
    fn remove_active_wwd(&mut self, wwd: WorldwideDay) -> PrecompileResult<()> {
        self.active_wwd.remove(&wwd).map(|_| ())
    }
}

fn hash(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn tribute_collection_key() -> B256 {
    let (_, key) = partition_collection_key(PartitionRef::TributeWwd(TEST_WWD)).unwrap();
    B256::from(*key.as_bytes())
}

fn capacity_profile() -> CapacityProfileV1 {
    CapacityProfileV1 {
        profile_id: hash(13),
        max_tributes_per_work_shard: 256,
        max_workers_per_domain: 4,
        max_intents_per_block: 1,
        max_activations_per_block: 1,
        max_ready_inspections_per_block: 1,
        max_expirations_per_block: 1,
        ready_backoff_blocks: 1,
        max_reference_currencies: 256,
        max_oracle_wwd_pair_entries: 256,
        max_active_scurve_entries: 256,
        result_deadline_blocks: outbe_chain_constants::DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
        source_retention_after_terminal_blocks: 64,
        generated_limits_manifest_hash: hash(23),
    }
}

fn bundle() -> ProtocolBundleV1 {
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(21),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: outbe_ocomp_protocol::registry::TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: outbe_ocomp_protocol::registry::FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: outbe_ocomp_protocol::registry::ORACLE_OPENING_CODEC_ID,
        result_codec_id: hash(4),
        action_codec_id: hash(5),
        activation_codec_id: hash(6),
        evidence_codec_id: hash(7),
        request_semantics_version: 1,
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: hash(9),
        effect_contract_registry_hash: hash(10),
        object_codec_registry_hash: hash(11),
        correctness_profile_id: hash(12),
        capacity_profile_id: hash(13),
        result_signature_profile_id: hash(14),
        finality_verifier_and_vote_domain_id: hash(15),
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: hash(16),
        mode_pause_revocation_semantics_hash: hash(17),
        upgrade_fsm_semantics_hash: hash(18),
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: hash(19),
        release_requirement_catalog_parent_hash: hash(20),
        release_gate_authority_envelope_hash: hash(22),
        release_approval_policy_hash: hash(24),
        release_validator_command_artifact_hash: hash(25),
        consensus_state_schema_version: 1,
        migration_manifest_hash: hash(26),
        required_upgrade_handler_set_hash: hash(27),
    }
}

fn signing_key(index: u8) -> SigningKey {
    SigningKey::from_bytes((&outbe_primitives::test_keys::secret((index + 1) as u64)).into())
        .unwrap()
}

fn ocomp_key_hash(index: u8) -> B256 {
    keccak256(
        signing_key(index)
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    )
}

fn sign(key: &SigningKey, digest: B256) -> [u8; 64] {
    let signature: Signature = key.sign_prehash(digest.as_slice()).unwrap();
    signature.to_bytes().into()
}

pub(crate) fn founder_registrations_for_validators(
    validators: &[(Address, [u8; 48])],
    chain_id: u64,
    genesis_hash: B256,
    limits: &SchemaLimits,
) -> PrecompileResult<Vec<OcompKeyRegistrationV1>> {
    let mut registrations = Vec::with_capacity(validators.len());
    for (index, (validator, consensus_pubkey)) in validators.iter().enumerate() {
        let index = u8::try_from(index).map_err(|_| {
            PrecompileError::Fatal("test founder validator index exceeds u8".into())
        })?;
        let key = signing_key(index);
        let mut registration = OcompKeyRegistrationV1 {
            core: OcompKeyRegistrationCoreV1 {
                chain_id,
                genesis_hash,
                validator_identity_hash: validator_identity_hash_v1(*validator, consensus_pubkey)
                    .map_err(|error| {
                    PrecompileError::Fatal(format!(
                        "test founder validator identity failed: {error}"
                    ))
                })?,
                ocomp_public_key_sec1: key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .map_err(|_| {
                        PrecompileError::Fatal("test founder OCOMP key is not 33 bytes".into())
                    })?,
                key_epoch: 1,
                allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
            },
            proof_of_possession: [0; 64],
        };
        registration.proof_of_possession = sign(
            &key,
            registration
                .proof_of_possession_digest(limits)
                .map_err(|error| {
                    PrecompileError::Fatal(format!("test founder PoP digest failed: {error}"))
                })?,
        );
        registrations.push(registration);
    }
    Ok(registrations)
}

pub(crate) fn seed_validator_snapshot(
    storage: StorageHandle<'_>,
    limits: &SchemaLimits,
    member_count: u8,
) -> OcompSnapshotExtensionV1 {
    assert!(member_count > 0);
    let chain_id = storage.chain_id().unwrap();
    let genesis_hash = storage.genesis_hash().unwrap();
    let owner = Address::repeat_byte(0xE0);
    let mut validators = ValidatorSet::new(storage.clone());
    validators.config_owner.write(owner).unwrap();
    validators
        .set_config_max_validators(u32::from(member_count))
        .unwrap();
    let mut snapshot_key = B256::ZERO;
    for index in 0..member_count {
        let validator = Address::repeat_byte(0xB0 + index);
        let consensus_pubkey = [0x30 + index; 48];
        validators
            .register_validator(owner, validator, &consensus_pubkey)
            .unwrap();
        validators.mark_pending(validator).unwrap();
        let key = signing_key(index);
        let mut registration = OcompKeyRegistrationV1 {
            core: OcompKeyRegistrationCoreV1 {
                chain_id,
                genesis_hash,
                validator_identity_hash: validator_identity_hash_v1(validator, &consensus_pubkey)
                    .unwrap(),
                ocomp_public_key_sec1: key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                key_epoch: 1,
                allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
            },
            proof_of_possession: [0; 64],
        };
        let digest = registration.proof_of_possession_digest(limits).unwrap();
        registration.proof_of_possession = sign(&key, digest);
        validators
            .confirm_validator_ready(validator, &registration.encode_canonical(limits).unwrap())
            .unwrap();
        snapshot_key = validators
            .activate_validator_via_boundary_for_test(validator)
            .unwrap();
    }
    read_ocomp_snapshot_extension(storage, snapshot_key)
        .unwrap()
        .unwrap()
}

/// Builds a fully valid immutable fork-install artifact for behavioral tests.
///
/// This creates only canonical manifest bytes. It does not seed chain state or
/// bypass the production lifecycle.
pub fn fork_install_fixture(
    classification: OcompForkInstallClassification,
    activation_height: u64,
    chain_id: u64,
    genesis_hash: B256,
) -> OcompForkInstallV1 {
    let limits = poc_schema_limits();
    let protocol_bundle = bundle();
    let bundle_hash = protocol_bundle.protocol_bundle_hash(&limits).unwrap();
    let founder_key = signing_key(0);
    let mut founder_registration = OcompKeyRegistrationV1 {
        core: OcompKeyRegistrationCoreV1 {
            chain_id,
            genesis_hash,
            validator_identity_hash: validator_identity_hash_v1(
                Address::repeat_byte(0xB0),
                &[0x30; 48],
            )
            .unwrap(),
            ocomp_public_key_sec1: founder_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            key_epoch: 1,
            allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
        },
        proof_of_possession: [0; 64],
    };
    founder_registration.proof_of_possession = sign(
        &founder_key,
        founder_registration
            .proof_of_possession_digest(&limits)
            .unwrap(),
    );
    OcompForkInstallV1 {
        classification,
        activation_height,
        request_profile: OcompRequestProfile {
            chain_id,
            genesis_hash,
            fork_id: hash(21),
            protocol_bundle_hash: bundle_hash,
            correctness_profile_id: hash(12),
            capacity_profile: capacity_profile(),
            source_availability_policy_id: hash(44),
        },
        protocol_bundle,
        founder_registrations: vec![founder_registration],
    }
}

fn request_receipt(bundle_hash: B256) -> RequestBudgetSplitReceiptV1 {
    RequestBudgetSplitReceiptV1 {
        protocol_bundle_hash: bundle_hash,
        wwd: TEST_WWD.value(),
        pending_nonce: 0,
        day_type: DayType::Green,
        day_limit: U256::from(100),
        lysis_budget: U256::from(60),
        auction_base: U256::from(40),
        destination: BudgetSplitDestination::DesisAuction,
        desis_brief_hash: Some(
            desis_request_brief_hash(
                bundle_hash,
                TEST_WWD.value(),
                U256::from(40),
                &test_entry_prices(),
                TEST_LOGICAL_TIME,
            )
            .unwrap(),
        ),
        carry_over_credit: U256::ZERO,
        auction_entry_prices: test_entry_prices(),
        logical_anchor: TEST_LOGICAL_TIME,
    }
}

/// The day's frozen price table used across these fixtures: one dollar row.
pub(crate) fn test_entry_prices() -> Vec<ReferenceEntryPriceV1> {
    vec![ReferenceEntryPriceV1 {
        reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
        entry_price_minor: U256::from(9),
        source: AuctionEntryPriceSource::LastClosedDayVwap,
        source_day: TEST_WWD.value(),
    }]
}

fn intent(
    bundle_hash: B256,
    snapshot: &OcompSnapshotExtensionV1,
    request_receipt_hash: B256,
) -> JobIntentV1 {
    JobIntentV1 {
        chain_id: 1,
        genesis_hash: hash(17),
        fork_id: hash(21),
        wwd: TEST_WWD.value(),
        pending_nonce: 0,
        attempt: 0,
        protocol_bundle_hash: bundle_hash,
        ce_sealed_root: hash(42),
        sealed_tribute_collection_key: tribute_collection_key(),
        sealed_tribute_collection_root: hash(31),
        authenticated_day_count: 2,
        authenticated_day_nominal: U256::from(1_000),
        pre_admission_envelope_hash: hash(43),
        source_availability_policy_id: hash(44),
        frozen_metadosis_values: FrozenMetadosisValuesV1 {
            day_type: DayType::Green,
            day_limit: U256::from(100),
            previous_vwap: U256::from(8),
            current_vwap: U256::from(10),
            gratis_demand: U256::from(60),
            gratis_supply: U256::from(60),
            lysis_budget: U256::from(60),
            auction_base: U256::from(40),
            auction_entry_prices: test_entry_prices(),
            request_budget_split_receipt_hash: request_receipt_hash,
        },
        logical_evaluation_height: TEST_REQUEST_HEIGHT,
        logical_evaluation_time: TEST_LOGICAL_TIME,
        activation_preconditions: ActivationPreconditionsV1 {
            tribute: TributeInputBindingV1 {
                wwd: TEST_WWD.value(),
                source_generation: 0,
                collection_key: tribute_collection_key(),
                sealed_collection_root: hash(31),
                exact_count: 2,
                exact_nominal_total: U256::from(1_000),
            },
            nod: NodTargetPreconditionV1 {
                wwd: TEST_WWD.value(),
                target_generation: 0,
                namespace_root_before: B256::ZERO,
                max_nod_count: 2,
            },
            contributors: ContributorTargetPreconditionV1 {
                worldwide_day: TEST_WWD.value(),
                expected_series_version: 0,
                max_contributor_count: 2,
                max_eligible_nominal_total: U256::from(1_000),
            },
            metadosis: MetadosisAttemptPreconditionV1 {
                wwd: TEST_WWD.value(),
                pending_nonce: 0,
                expected_status: MetadosisExpectedStatus::OffchainPending,
                state_version: 1,
            },
        },
        result_validator_set_epoch: snapshot.epoch,
        result_committee_set_hash: snapshot.committee_set_hash,
        result_ocomp_binding_hash: snapshot.ocomp_binding_hash,
        result_member_count: snapshot.member_count,
        result_quorum_threshold: u16::try_from(outbe_consensus::proof::simplex_n3f1_quorum(
            usize::from(snapshot.member_count),
        ))
        .unwrap(),
        custody_committee_epoch_hash: None,
    }
}

fn result(bundle_hash: B256, job_id: B256, limits: &SchemaLimits) -> LysisResultV1 {
    let roots = ResultRootsV1 {
        nod_root: hash(50),
        bucket_root: hash(51),
        contributor_root: hash(52),
        output_manifest_root: hash(53),
    };
    let counts = ExactCountsV1 {
        tribute_count: 2,
        nod_count: 2,
        bucket_count: 1,
        contributor_count: 1,
        semantic_event_count: 0,
    };
    let conservation = ConservationTotalsV1 {
        tribute_nominal_total: U256::from(1_000),
        eligible_nominal_total: U256::from(600),
        day_limit: U256::from(100),
        gratis_demand: U256::from(60),
        gratis_supply: U256::from(60),
        lysis_budget: U256::from(60),
        auction_base: U256::from(40),
        nod_gratis_consumed: U256::from(45),
        unused_lysis: U256::from(15),
        carry_over_credit: U256::from(15),
        nod_cost_total: U256::from(300),
    };
    let summary = LysisArithmeticSummaryV1 {
        input_manifest_hash: hash(54),
        plan_hash: hash(55),
        unit_artifact_root: hash(56),
        fidelity_fraction_root: hash(57),
        gratis_prefix_root: hash(58),
        roots: roots.clone(),
        counts: counts.clone(),
        conservation: conservation.clone(),
        first_error_ordinal: None,
    };
    LysisResultV1 {
        protocol_bundle_hash: bundle_hash,
        job_id,
        attempt: 0,
        input_manifest_hash: summary.input_manifest_hash,
        plan_hash: summary.plan_hash,
        unit_artifact_root: summary.unit_artifact_root,
        fidelity_fraction_root: summary.fidelity_fraction_root,
        gratis_prefix_root: summary.gratis_prefix_root,
        result_chunk_count: 2,
        result_chunk_list_root: hash(61),
        carry_over_credit: CarryOverCreditActionV1 {
            source_wwd: TEST_WWD.value(),
            reason: CarryOverReason::UnusedLysis,
            amount: U256::from(15),
        },
        metadosis_completion_summary: MetadosisCompletionSummaryV1 {
            wwd: TEST_WWD.value(),
            pending_nonce: 0,
            day_type: DayType::Green,
            tribute_nominal_total: U256::from(1_000),
            day_limit: U256::from(100),
            gratis_demand: U256::from(60),
            gratis_supply: U256::from(60),
            lysis_budget: U256::from(60),
            auction_base: U256::from(40),
            nod_gratis_consumed: U256::from(45),
            unused_lysis: U256::from(15),
            carry_over_credit: U256::from(15),
            status: CompletionStatus::Completed,
            logical_evaluation_height: TEST_REQUEST_HEIGHT,
            logical_evaluation_time: TEST_LOGICAL_TIME,
        },
        tribute_count: 2,
        tribute_nominal_total: U256::from(1_000),
        unused_lysis: U256::from(15),
        roots,
        counts,
        conservation,
        arithmetic_commitment: hash_framed(
            HashDomain::LysisArithmetic,
            &summary.encode_canonical(limits).unwrap(),
        )
        .unwrap(),
        event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
    }
}

/// Builds one production-valid, bounded result for an already persisted test
/// intent. The result keeps every scalar bound anchored to the intent while
/// using deterministic non-zero commitments for the off-chain artifacts.
#[must_use]
pub fn lysis_result_for_intent(
    intent: &JobIntentV1,
    job_id: B256,
    limits: &SchemaLimits,
) -> LysisResultV1 {
    let frozen = &intent.frozen_metadosis_values;
    let roots = ResultRootsV1 {
        nod_root: hash(150),
        bucket_root: hash(151),
        contributor_root: hash(152),
        output_manifest_root: hash(153),
    };
    let counts = ExactCountsV1 {
        tribute_count: intent.authenticated_day_count,
        nod_count: intent.authenticated_day_count,
        bucket_count: u32::from(intent.authenticated_day_count > 0),
        contributor_count: 0,
        semantic_event_count: 0,
    };
    let conservation = ConservationTotalsV1 {
        tribute_nominal_total: intent.authenticated_day_nominal,
        eligible_nominal_total: U256::ZERO,
        day_limit: frozen.day_limit,
        gratis_demand: frozen.gratis_demand,
        gratis_supply: frozen.gratis_supply,
        lysis_budget: frozen.lysis_budget,
        auction_base: frozen.auction_base,
        nod_gratis_consumed: U256::ZERO,
        unused_lysis: frozen.lysis_budget,
        carry_over_credit: frozen.lysis_budget,
        nod_cost_total: U256::ZERO,
    };
    let summary = LysisArithmeticSummaryV1 {
        input_manifest_hash: hash(154),
        plan_hash: hash(155),
        unit_artifact_root: hash(156),
        fidelity_fraction_root: hash(157),
        gratis_prefix_root: hash(158),
        roots: roots.clone(),
        counts: counts.clone(),
        conservation: conservation.clone(),
        first_error_ordinal: None,
    };
    let result = LysisResultV1 {
        protocol_bundle_hash: intent.protocol_bundle_hash,
        job_id,
        attempt: intent.attempt,
        input_manifest_hash: summary.input_manifest_hash,
        plan_hash: summary.plan_hash,
        unit_artifact_root: summary.unit_artifact_root,
        fidelity_fraction_root: summary.fidelity_fraction_root,
        gratis_prefix_root: summary.gratis_prefix_root,
        result_chunk_count: 1,
        result_chunk_list_root: hash(159),
        carry_over_credit: CarryOverCreditActionV1 {
            source_wwd: intent.wwd,
            reason: CarryOverReason::UnusedLysis,
            amount: frozen.lysis_budget,
        },
        metadosis_completion_summary: MetadosisCompletionSummaryV1 {
            wwd: intent.wwd,
            pending_nonce: intent.pending_nonce,
            day_type: frozen.day_type,
            tribute_nominal_total: intent.authenticated_day_nominal,
            day_limit: frozen.day_limit,
            gratis_demand: frozen.gratis_demand,
            gratis_supply: frozen.gratis_supply,
            lysis_budget: frozen.lysis_budget,
            auction_base: frozen.auction_base,
            nod_gratis_consumed: U256::ZERO,
            unused_lysis: frozen.lysis_budget,
            carry_over_credit: frozen.lysis_budget,
            status: CompletionStatus::Completed,
            logical_evaluation_height: intent.logical_evaluation_height,
            logical_evaluation_time: intent.logical_evaluation_time,
        },
        tribute_count: intent.authenticated_day_count,
        tribute_nominal_total: intent.authenticated_day_nominal,
        unused_lysis: frozen.lysis_budget,
        roots,
        counts,
        conservation,
        arithmetic_commitment: hash_framed(
            HashDomain::LysisArithmetic,
            &summary.encode_canonical(limits).unwrap(),
        )
        .unwrap(),
        event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
    };
    result.validate_finalized_intent(intent).unwrap();
    result.validate_semantics(limits).unwrap();
    result
}

/// Signs one deterministic fixture-committee vote for a caller-supplied
/// persisted intent/result pair. The returned vote still has to pass the real
/// public selector and block executor.
#[must_use]
pub fn signed_result_vote_for_intent(
    intent: &JobIntentV1,
    result: &LysisResultV1,
    validator_index: u8,
    limits: &SchemaLimits,
) -> ResultVoteV1 {
    let mut vote = ResultVoteV1 {
        protocol_bundle_hash: intent.protocol_bundle_hash,
        job_id: result.job_id,
        attempt: intent.attempt,
        result_validator_set_epoch: intent.result_validator_set_epoch,
        result_committee_set_hash: intent.result_committee_set_hash,
        result_ocomp_binding_hash: intent.result_ocomp_binding_hash,
        ocomp_key_hash: ocomp_key_hash(validator_index),
        key_epoch: 1,
        result: result.clone(),
        signature_rs: [0; 64],
    };
    vote.signature_rs = sign(
        &signing_key(validator_index),
        vote.signing_digest(intent, limits).unwrap(),
    );
    vote
}

fn finality_proof(intent: &JobIntentV1, limits: &SchemaLimits) -> FinalizedIntentProofV1 {
    FinalizedIntentProofV1 {
        chain_id: intent.chain_id,
        genesis_hash: intent.genesis_hash,
        fork_id: intent.fork_id,
        protocol_bundle_hash: intent.protocol_bundle_hash,
        canonical_request_header_rlp: ProofBytes(vec![1, 2]),
        parent_accounting: CertifiedParentAccountingMetadataV2 {
            finalized_block_number: 9,
            finalized_block_hash: hash(46),
            finalized_epoch: 2,
            finalized_view: 3,
            parent_view: 2,
            ordered_committee: vec![BoundedBytes(vec![1])],
            signer_bitmap: BoundedBytes(vec![1]),
            canonical_commonware_finalization_proof: ProofBytes(vec![2]),
            committee_set_hash: hash(47),
            vrf_material_version: 1,
            vrf_group_public_key_hash: hash(48),
            proof_kind: ParentProofKind::Finalization,
            missed_proposers: Vec::new(),
        },
        historical_committee_membership_proof: ProofBytes(vec![3]),
        canonical_job_intent: BoundedBytes(intent.encode_canonical(limits).unwrap()),
        intent_account_proof: ProofBytes(vec![4]),
        intent_storage_proof: ProofBytes(vec![5]),
    }
}

#[derive(Clone)]
pub struct FixedFinality {
    expected: ExpectedFinalizedIntentBindingV1,
    verified: VerifiedFinalizedIntentV1,
    calls: Arc<AtomicUsize>,
}

impl OcompFinalizedIntentAuthority for FixedFinality {
    fn verify(
        &self,
        _proof: &FinalizedIntentProofV1,
        expected: ExpectedFinalizedIntentBindingV1,
        _limits: &SchemaLimits,
    ) -> Result<VerifiedFinalizedIntentV1, OcompFinalityAuthorityError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if expected != self.expected {
            return Err(FinalizedIntentVerificationError::WrongProtocolBundle.into());
        }
        Ok(self.verified.clone())
    }
}

#[derive(Debug)]
struct TributePartitionTree {
    parent_root: B256,
}

impl AuthenticatedParentTree for TributePartitionTree {
    fn parent_block_hash(&self) -> B256 {
        hash(90)
    }

    fn parent_root(&self) -> B256 {
        self.parent_root
    }

    fn read_leaf_verified(
        &self,
        _entity: EntityRef,
        _expected_parent_root: B256,
    ) -> PrecompileResult<Option<outbe_compressed_entities::Commitment>> {
        Ok(None)
    }

    fn partition_present_verified(
        &self,
        partition: PartitionRef,
        expected_parent_root: B256,
    ) -> PrecompileResult<bool> {
        if expected_parent_root != self.parent_root
            || partition != PartitionRef::TributeWwd(TEST_WWD)
        {
            return Err(PrecompileError::Fatal(
                "activation fixture parent partition binding mismatch".into(),
            ));
        }
        Ok(true)
    }

    fn partition_root_verified(
        &self,
        partition: PartitionRef,
        expected_parent_root: B256,
    ) -> PrecompileResult<Option<B256>> {
        if expected_parent_root != self.parent_root
            || partition != PartitionRef::TributeWwd(TEST_WWD)
        {
            return Err(PrecompileError::Fatal(
                "activation fixture parent partition binding mismatch".into(),
            ));
        }
        Ok(Some(hash(31)))
    }

    fn prepare_seal(
        &self,
        _block_number: u64,
        _mutations: &[FinalLeafMutation],
        _retirements: &[PartitionRef],
    ) -> PrecompileResult<ProvisionalTreeBatch> {
        Err(PrecompileError::Fatal(
            "activation fixture does not seal its synthetic parent".into(),
        ))
    }
}

fn begin_activation_scope(provider: &mut HashMapStorageProvider) -> ExecutionScope {
    let parent_root = hash(80);
    let scope = ExecutionScope::with_parent_tree(
        Arc::new(TributePartitionTree { parent_root }),
        CeWorkConfig::new(0, 0, u64::MAX),
    );
    StorageHandle::enter(provider, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(parent_root.as_slice()),
            )
            .unwrap();
        begin_block(storage, &scope).unwrap();
    });
    scope
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackSnapshot {
    storage: HashMap<(Address, U256), U256>,
    events: Vec<Log>,
    ce_work: CeWorkCheckpoint,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticSnapshot {
    pub job_status: OcompJobStatus,
    pub worldwide_day_status: u8,
    pub active_job_id: B256,
    pub active_nod_root: B256,
    pub nod: outbe_nod::schema::NodCertifiedGenerationProjection,
    pub contributor: outbe_intex::schema::CertifiedContributorGenerationProjection,
    pub tribute_generation: u64,
    pub tribute_count: u32,
    pub tribute_nominal: U256,
    pub tribute_total_supply: u64,
    pub carry_over: U256,
    pub owner_events: Vec<Log>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationMetadata {
    pub activated_at_height: u64,
    pub activated_at_time: u64,
}

pub struct ActivationFixture {
    pub provider: HashMapStorageProvider,
    pub scope: ExecutionScope,
    pub result: LysisResultV1,
    pub finality: FixedFinality,
    pub intent_id: B256,
    pub limits: SchemaLimits,
    pub request_receipt: RequestBudgetSplitReceiptV1,
}

impl ActivationFixture {
    #[must_use]
    pub fn new(current_height: u64, current_time: u64, seed_targets: bool) -> Self {
        Self::new_with_initial_votes(current_height, current_time, seed_targets, 4, 2)
    }

    /// Builds the default production-valid fixture before any validator vote
    /// is recorded, without injecting quorum state.
    #[cfg(test)]
    #[must_use]
    pub fn new_voting(current_height: u64, current_time: u64, seed_targets: bool) -> Self {
        Self::new_voting_with_member_count(current_height, current_time, seed_targets, 4)
    }

    /// Builds a production-valid voting fixture for the requested ValidatorSet
    /// size without introducing an OCOMP-specific membership authority.
    #[cfg(test)]
    #[must_use]
    pub fn new_voting_with_member_count(
        current_height: u64,
        current_time: u64,
        seed_targets: bool,
        member_count: u8,
    ) -> Self {
        Self::new_with_initial_votes(current_height, current_time, seed_targets, member_count, 0)
    }

    /// Seeds the Staking-owned bonded balances used by recovery-policy tests.
    #[cfg(test)]
    pub fn seed_ocomp_recovery_stake_for_test(&mut self) {
        StorageHandle::enter(&mut self.provider, |storage| {
            let validators = ValidatorSet::new(storage.clone())
                .registered_validator_addresses()
                .unwrap();
            let bonded = U256::from(1_000u64);
            let staking = outbe_staking::contract::Staking::new(storage.clone());
            staking.config_min_stake.write(bonded).unwrap();
            staking
                .total_staked
                .write(bonded * U256::from(validators.len()))
                .unwrap();
            storage
                .set_balance(STAKING_ADDRESS, bonded * U256::from(validators.len()))
                .unwrap();
            let mut validator_set = ValidatorSet::new(storage.clone());
            for validator in validators {
                staking.stake_amount.write(&validator, bonded).unwrap();
                validator_set
                    .record_stake_increase(validator, bonded, bonded)
                    .unwrap();
            }
        });
    }

    /// Adds the next validator through registration, OCOMP readiness and the
    /// certified-boundary test hook, returning the newly persisted snapshot.
    #[cfg(test)]
    pub fn activate_additional_validator_for_test(
        &mut self,
        index: u8,
    ) -> OcompSnapshotExtensionV1 {
        StorageHandle::enter(&mut self.provider, |storage| {
            let chain_id = storage.chain_id().unwrap();
            let genesis_hash = storage.genesis_hash().unwrap();
            let owner = Address::repeat_byte(0xE0);
            let validator = Address::repeat_byte(0xB0 + index);
            let consensus_pubkey = [0x30 + index; 48];
            let mut validators = ValidatorSet::new(storage.clone());
            assert_eq!(validators.validator_count().unwrap(), u32::from(index));
            validators
                .set_config_max_validators(u32::from(index) + 1)
                .unwrap();
            validators
                .register_validator(owner, validator, &consensus_pubkey)
                .unwrap();
            validators.mark_pending(validator).unwrap();

            let key = signing_key(index);
            let mut registration = OcompKeyRegistrationV1 {
                core: OcompKeyRegistrationCoreV1 {
                    chain_id,
                    genesis_hash,
                    validator_identity_hash: validator_identity_hash_v1(
                        validator,
                        &consensus_pubkey,
                    )
                    .unwrap(),
                    ocomp_public_key_sec1: key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                    key_epoch: 1,
                    allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
                },
                proof_of_possession: [0; 64],
            };
            let digest = registration
                .proof_of_possession_digest(&self.limits)
                .unwrap();
            registration.proof_of_possession = sign(&key, digest);
            validators
                .confirm_validator_ready(
                    validator,
                    &registration.encode_canonical(&self.limits).unwrap(),
                )
                .unwrap();
            let timestamp: u64 = storage.timestamp().unwrap().try_into().unwrap();
            outbe_validatorset::hooks::transition_epoch(
                storage.clone(),
                timestamp,
                storage.block_number().unwrap(),
            )
            .unwrap();
            let snapshot_key = validators
                .activate_validator_via_boundary_for_test(validator)
                .unwrap();
            read_ocomp_snapshot_extension(storage, snapshot_key)
                .unwrap()
                .unwrap()
        })
    }

    fn new_with_initial_votes(
        current_height: u64,
        current_time: u64,
        seed_targets: bool,
        member_count: u8,
        initial_vote_count: u8,
    ) -> Self {
        assert!(member_count > 0);
        assert!(initial_vote_count < member_count);
        let limits = poc_schema_limits();
        let bundle = bundle();
        let bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
        let mut provider = HashMapStorageProvider::new_with_chain_identity(1, hash(17));
        let snapshot = StorageHandle::enter(&mut provider, |storage| {
            seed_validator_snapshot(storage, &limits, member_count)
        });
        let request_receipt = request_receipt(bundle_hash);
        let request_receipt_hash = request_receipt.receipt_hash(&limits).unwrap();
        let intent = intent(bundle_hash, &snapshot, request_receipt_hash);
        let intent_id = intent.intent_id(&limits).unwrap();
        let proof = finality_proof(&intent, &limits);
        let request_state_root = hash(98);
        let job_id = intent
            .job_id(
                proof.parent_accounting.finalized_block_hash,
                request_state_root,
                &limits,
            )
            .unwrap();
        let result = result(bundle_hash, job_id, &limits);
        let expected = ExpectedFinalizedIntentBindingV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            fork_id: intent.fork_id,
            protocol_bundle_hash: intent.protocol_bundle_hash,
        };
        let finality = FixedFinality {
            expected,
            verified: VerifiedFinalizedIntentV1 {
                intent: intent.clone(),
                intent_id,
                intent_storage_key: intent_storage_key(intent_id).unwrap(),
                job_id,
                request: FinalizedRequestBindingV1 {
                    block_number: 9,
                    block_hash: hash(46),
                    state_root: request_state_root,
                },
            },
            calls: Arc::new(AtomicUsize::new(0)),
        };

        provider.set_block_number(current_height);
        provider.set_timestamp(U256::from(current_time));
        let scope = begin_activation_scope(&mut provider);
        StorageHandle::enter(&mut provider, |storage| {
            let nod = NodContract::new(storage.clone());
            nod.ocomp_materialization_head_sequence.write(1).unwrap();
            nod.ocomp_materialization_tail_sequence.write(1).unwrap();

            if seed_targets {
                let tribute = TributeContract::new(storage.clone());
                tribute.ocomp_profile_ready.write(true).unwrap();
                tribute.total_supply.write(2).unwrap();
                let mut totals = DayTotals::with_key(TEST_WWD);
                totals.initialized = true;
                totals.is_sealed = true;
                totals.tribute_count = 2;
                totals.tribute_nominal_amount = U256::from(1_000);
                tribute.day_totals.create(&totals).unwrap();
                let mut admission = DayPreAdmission::with_key(TEST_WWD);
                admission.initialized = true;
                admission.is_sealed = true;
                admission.sealed_collection_root = hash(31);
                admission.sealed_tribute_count = 2;
                admission.sealed_tribute_nominal_amount = U256::from(1_000);
                admission.source_generation = 0;
                tribute.day_pre_admission.create(&admission).unwrap();
            }

            let mut contract = MetadosisContract::new(storage.clone());
            if seed_targets {
                contract.initialize_ocomp_pre_admission(TEST_WWD).unwrap();
            }
            contract
                .worldwide_days
                .create(&WorldwideDayRecord {
                    wwd: TEST_WWD,
                    status: status::READY,
                    day_type: day_type::GREEN,
                    forming_start: 1,
                    forming_end: 2,
                    lookback_end: 3,
                    offering_end: 4,
                    scheduled_process_time: 5,
                    metadosis_limit_amount: U256::from(100),
                    previous_vwap: U256::from(8),
                    current_vwap: U256::from(10),
                })
                .unwrap();
            contract.active_wwd.insert(TEST_WWD).unwrap();
            contract
                .enqueue_ocomp_ready(TEST_WWD, TEST_REQUEST_HEIGHT)
                .unwrap();
            let profile = OcompRequestProfile {
                chain_id: 1,
                genesis_hash: hash(17),
                fork_id: hash(21),
                protocol_bundle_hash: bundle_hash,
                correctness_profile_id: hash(12),
                capacity_profile: capacity_profile(),
                source_availability_policy_id: hash(44),
            };
            contract
                .initialize_ocomp_request_profile(&profile, &limits)
                .unwrap();
            contract
                .initialize_ocomp_activation_authority(&bundle, &limits)
                .unwrap();
            let outer_transition = crate::commit::plan_outer_transition_for_test_fixture(
                &contract,
                TEST_WWD,
                crate::reducer::OuterWwdEvent::OcompRequestCommitted,
            )
            .unwrap();
            // A real request credits what Lysis left of the day's emission before the auction is
            // sized, so the accumulator holds at least what this receipt says the auction draws.
            outbe_promislimit::PromisLimitContract::new(storage.clone())
                .checked_add_carry_over(request_receipt.auction_base)
                .unwrap();
            contract
                .commit_ocomp_request(&outer_transition, &intent, &request_receipt, &limits)
                .unwrap();
            let finalized = contract
                .record_ocomp_finality(
                    intent_id,
                    hash(46),
                    request_state_root,
                    TEST_REQUEST_HEIGHT,
                    capacity_profile().result_deadline_blocks,
                    &limits,
                )
                .unwrap();
            assert_eq!(
                finalized.open_height,
                TEST_REQUEST_HEIGHT + RESULT_VOTE_MIN_FINALITY_DEPTH
            );
            contract
                .open_due_ocomp_voting(finalized.open_height, &limits)
                .unwrap();
            for index in 0..initial_vote_count {
                let mut vote = ResultVoteV1 {
                    protocol_bundle_hash: bundle_hash,
                    job_id,
                    attempt: intent.attempt,
                    result_validator_set_epoch: intent.result_validator_set_epoch,
                    result_committee_set_hash: intent.result_committee_set_hash,
                    result_ocomp_binding_hash: intent.result_ocomp_binding_hash,
                    ocomp_key_hash: ocomp_key_hash(index),
                    key_epoch: 1,
                    result: result.clone(),
                    signature_rs: [0; 64],
                };
                let signing_digest = vote.signing_digest(&intent, &limits).unwrap();
                vote.signature_rs = sign(&signing_key(index), signing_digest);
                contract
                    .record_ocomp_result_vote(
                        &vote,
                        finalized.open_height + u64::from(index),
                        &scope,
                        &limits,
                    )
                    .unwrap();
            }
        });
        provider.clear_events(METADOSIS_ADDRESS);

        Self {
            provider,
            scope,
            result,
            finality,
            intent_id,
            limits,
            request_receipt,
        }
    }

    /// Creates the canonical node-attested vote for one fixture committee
    /// member. The returned bytes still have to pass the production public
    /// dispatch and consensus transition.
    #[must_use]
    pub fn signed_result_vote(&self, validator_index: u8) -> ResultVoteV1 {
        let intent = &self.finality.verified.intent;
        let mut vote = ResultVoteV1 {
            protocol_bundle_hash: intent.protocol_bundle_hash,
            job_id: self.result.job_id,
            attempt: intent.attempt,
            result_validator_set_epoch: intent.result_validator_set_epoch,
            result_committee_set_hash: intent.result_committee_set_hash,
            result_ocomp_binding_hash: intent.result_ocomp_binding_hash,
            ocomp_key_hash: ocomp_key_hash(validator_index),
            key_epoch: 1,
            result: self.result.clone(),
            signature_rs: [0; 64],
        };
        vote.signature_rs = sign(
            &signing_key(validator_index),
            vote.signing_digest(intent, &self.limits).unwrap(),
        );
        vote
    }

    pub fn apply(&mut self) -> PrecompileResult<Bytes> {
        self.provider.enable_lysis_activation_frame();
        self.dispatch_current()
    }

    #[cfg(test)]
    pub(crate) fn apply_with_receipt_fault(
        &mut self,
        fault: ActivationReceiptFault,
    ) -> PrecompileResult<Bytes> {
        ACTIVATION_RECEIPT_FAULT.with(|slot| {
            assert!(
                slot.replace(Some(fault)).is_none(),
                "nested activation receipt fault"
            );
        });
        let result = self.apply();
        ACTIVATION_RECEIPT_FAULT.with(|slot| slot.set(None));
        result
    }

    #[must_use]
    pub fn calldata(&self) -> Bytes {
        Bytes::from(
            outbe_ocomp_protocol::abi::encode_submit_lysis_result_calldata(
                &self.signed_result_vote(2),
                &self.limits,
            )
            .unwrap(),
        )
    }

    pub fn dispatch_current(&mut self) -> PrecompileResult<Bytes> {
        self.dispatch_current_with()
    }

    fn dispatch_current_with(&mut self) -> PrecompileResult<Bytes> {
        let calldata = self.calldata();
        self.provider
            .enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::VerifiedResultVote);
        StorageHandle::enter(&mut self.provider, |storage| {
            crate::commands::submit_verified_result_vote(
                storage,
                &self.scope,
                calldata.as_ref(),
                U256::ZERO,
                false,
            )
        })
    }

    pub fn terminal_outcome(&mut self) -> ActivationOutcome {
        StorageHandle::enter(&mut self.provider, |storage| {
            MetadosisContract::new(storage)
                .ocomp_job_record(self.intent_id, &self.limits)
                .unwrap()
                .unwrap()
                .terminal
                .unwrap()
                .completed_binding
                .unwrap()
                .terminal_receipt
                .outcome
        })
    }

    pub fn replace_request_receipt(&mut self, receipt: &RequestBudgetSplitReceiptV1) {
        let encoded = receipt.encode_canonical(&self.limits).unwrap();
        StorageHandle::enter(&mut self.provider, |storage| {
            MetadosisContract::new(storage)
                .ocomp_request_budget_receipts
                .get_bytes(&TEST_WWD)
                .write(&encoded)
                .unwrap();
        });
    }

    pub(crate) fn corrupt_request_receipt_mismatch(&mut self) {
        let mut mismatched = self.request_receipt.clone();
        mismatched.logical_anchor = mismatched
            .logical_anchor
            .checked_add(1)
            .expect("fixture logical anchor must admit one mismatch step");
        self.replace_request_receipt(&mismatched);
    }

    pub fn rollback_snapshot(&mut self) -> RollbackSnapshot {
        RollbackSnapshot {
            storage: self.provider.storage.clone(),
            events: self.provider.get_ordered_events().to_vec(),
            ce_work: self.scope.ce_work_checkpoint().unwrap(),
        }
    }

    #[cfg(test)]
    pub fn semantic_snapshot(&mut self) -> SemanticSnapshot {
        let owner_events = self
            .provider
            .get_ordered_events()
            .iter()
            .filter(|event| event.address != METADOSIS_ADDRESS)
            .cloned()
            .collect();
        StorageHandle::enter(&mut self.provider, |storage| {
            let contract = MetadosisContract::new(storage.clone());
            let job = contract
                .ocomp_job_record(self.intent_id, &self.limits)
                .unwrap()
                .unwrap();
            let active = contract
                .active_lysis_generation(TEST_WWD, &self.limits)
                .unwrap()
                .unwrap();
            let nod = outbe_nod::schema::NodContract::new(storage.clone())
                .ocomp_certified_generation(TEST_WWD)
                .unwrap()
                .unwrap();
            let contributor =
                outbe_intex::api::certified_contributor_generation(&storage, TEST_WWD)
                    .unwrap()
                    .unwrap();
            let tribute = TributeContract::new(storage.clone());
            let admission = tribute.pre_admission_projection(TEST_WWD).unwrap();
            let totals = tribute.get_day_totals(TEST_WWD).unwrap();
            SemanticSnapshot {
                job_status: job.status,
                worldwide_day_status: contract.get_wwd_status(TEST_WWD).unwrap().as_u8(),
                active_job_id: active.job_id,
                active_nod_root: active.nod_root,
                nod,
                contributor,
                tribute_generation: admission.source_generation,
                tribute_count: totals.tribute_count,
                tribute_nominal: totals.tribute_nominal_amount,
                tribute_total_supply: tribute.total_supply.read().unwrap(),
                carry_over: outbe_promislimit::PromisLimitContract::new(storage)
                    .total_unallocated
                    .read()
                    .unwrap(),
                owner_events,
            }
        })
    }

    #[cfg(test)]
    pub fn activation_metadata(&mut self) -> ActivationMetadata {
        StorageHandle::enter(&mut self.provider, |storage| {
            let job = MetadosisContract::new(storage)
                .ocomp_job_record(self.intent_id, &self.limits)
                .unwrap()
                .unwrap();
            let receipt = &job
                .terminal
                .unwrap()
                .completed_binding
                .unwrap()
                .terminal_receipt;
            ActivationMetadata {
                activated_at_height: receipt.activated_at_height,
                activated_at_time: receipt.activated_at_time,
            }
        })
    }
}
