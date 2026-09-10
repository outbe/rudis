//! Consensus-state admission for direct validator `ResultVoteV1` records.
//!
//! The public transaction supplies one canonical signed vote. This module
//! resolves the finalized job from the bounded response-window index, verifies
//! the inner OCOMP signature against the pinned historical ValidatorSet and owns
//! the atomic pinned-ValidatorSet vote transition. It never executes Lysis.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use outbe_compressed_entities::ExecutionScope;
use outbe_ocomp_protocol::{
    error::ProtocolError,
    state::OcompJobStatus,
    vote::{OcompQuorumV1, RecordVoteOutcomeV1, ResultVotePrefixV1, ResultVoteV1},
    SchemaLimits,
};
use outbe_primitives::{
    error::{PrecompileError, Result},
    storage::StorageHandle,
};

use crate::{
    aggregate::ValidatedWwdAggregate,
    errors::{
        caller_rejection as reject, result_vote_rejection as vote_reject,
        storage_corruption_message, vote_rejection_code::*,
    },
    precompile::IMetadosis,
    reducer::{reduce_outer_wwd, OuterWwdEvent},
    schema::MetadosisContract,
};

use super::schema::remove_response_deadline_key;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedResultVoteV1 {
    pub outcome: RecordVoteOutcomeV1,
    pub quorum: Option<OcompQuorumV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedHistoricalResultVoteMemberV1 {
    validator_address: Address,
    validator_index: u16,
    key_epoch: u64,
    ocomp_public_key_sec1: [u8; 33],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseWindowCloseV1 {
    NotDue,
    NoQuorum { intent_id: alloy_primitives::B256 },
    QuorumPreserved { intent_id: alloy_primitives::B256 },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct OcompPenaltyMetrics {
    recovery_resolutions: Vec<(Address, &'static str)>,
    misses: Vec<(Address, bool, u64)>,
    punishments: Vec<outbe_validatorset::runtime::DeferredValidatorPunishment>,
}

impl OcompPenaltyMetrics {
    pub(crate) fn record(self) {
        for punishment in self.punishments {
            punishment.record();
        }
        for (validator, outcome) in self.recovery_resolutions {
            outbe_validatorset::metrics::record_ocomp_recovery_resolution(validator, outcome);
            match outcome {
                "jailed" => tracing::warn!(
                    %validator,
                    outcome,
                    "OCOMP recovery window expired below minimum bonded stake"
                ),
                _ => tracing::info!(
                    %validator,
                    outcome,
                    "OCOMP recovery window closed"
                ),
            }
        }
        for (validator, first_in_window, recovery_deadline) in self.misses {
            outbe_validatorset::metrics::record_ocomp_miss(
                validator,
                first_in_window,
                recovery_deadline,
            );
            tracing::warn!(
                %validator,
                first_in_window,
                recovery_deadline,
                "validator missed an OCOMP result vote"
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResponseWindowCloseReport {
    pub(crate) close: ResponseWindowCloseV1,
    pub(crate) metrics: OcompPenaltyMetrics,
}

impl ResponseWindowCloseReport {
    fn not_due() -> Self {
        Self {
            close: ResponseWindowCloseV1::NotDue,
            metrics: OcompPenaltyMetrics::default(),
        }
    }
}

/// Dispatches one normal public EVM transaction containing a canonical signed
/// `ResultVoteV1`. The outer caller is intentionally not protocol authority:
/// eligibility and fee classification are separate, while this transition is
/// authorized only by the inner committee signature.
pub fn dispatch_public_result_vote(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    data: &[u8],
    value: U256,
    is_static: bool,
) -> Result<Bytes> {
    if !value.is_zero() || is_static {
        return Err(vote_reject(CALL_MODE));
    }
    let limits = super::schema::poc_schema_limits();
    let vote_bytes = preflight_result_vote_calldata(data, &limits)?;
    let vote = ResultVoteV1::decode_canonical(vote_bytes, &limits)
        .map_err(|_| vote_reject(MALFORMED_ENCODING))?;
    let inclusion_height = storage.block_number()?;
    MetadosisContract::new(storage)
        .record_ocomp_result_vote(&vote, inclusion_height, scope, &limits)
        .map_err(map_vote_transition_error)?;
    Ok(Bytes::new())
}

fn preflight_result_vote_calldata<'a>(data: &'a [u8], limits: &SchemaLimits) -> Result<&'a [u8]> {
    outbe_ocomp_protocol::vote::decode_submit_lysis_result_prefix(data, limits).map_err(
        |error| {
            vote_reject(if matches!(error, ProtocolError::CapacityExceeded { .. }) {
                LIMIT_EXCEEDED
            } else {
                MALFORMED_ENCODING
            })
        },
    )?;
    let payload_len = usize::try_from(U256::from_be_slice(&data[36..68]))
        .map_err(|_| vote_reject(LIMIT_EXCEEDED))?;
    outbe_ocomp_protocol::capacity::result_vote_internal_work(payload_len)
        .map_err(|_| vote_reject(LIMIT_EXCEEDED))?;
    let payload_end = 68 + payload_len;
    Ok(&data[68..payload_end])
}

fn map_vote_transition_error(error: PrecompileError) -> PrecompileError {
    if crate::errors::is_business_failure(&error) {
        return error;
    }
    if is_deadline_passed_result_vote_revert(&error) {
        return error;
    }
    match error {
        PrecompileError::Revert(_) | PrecompileError::RevertBytes(_) => vote_reject(PROTOCOL_VOTE),
        other => other,
    }
}

#[must_use]
pub fn is_deadline_passed_result_vote_revert(error: &PrecompileError) -> bool {
    matches!(error, PrecompileError::RevertBytes(data) if is_deadline_passed_result_vote_revert_data(data))
}

#[must_use]
pub fn is_deadline_passed_result_vote_revert_data(data: &[u8]) -> bool {
    data == deadline_passed_result_vote_revert_data().as_ref()
}

#[must_use]
pub fn deadline_passed_result_vote_revert_data() -> Bytes {
    let PrecompileError::RevertBytes(expected) = vote_reject(DEADLINE_PASSED) else {
        unreachable!("vote_reject always returns RevertBytes");
    };
    expected
}

/// Resolves the validator represented by one canonical OCOMP vote prefix from
/// the exact historical ValidatorSet snapshot pinned by its open job.
///
/// Current ValidatorSet status is deliberately not consulted: membership for
/// an already-open attempt is immutable. Missing, evicted or mismatched
/// caller-selected state is an ordinary `None`, never a fallback to the current
/// snapshot.
pub fn resolve_historical_result_vote_participant(
    storage: StorageHandle<'_>,
    prefix: &ResultVotePrefixV1,
    limits: &SchemaLimits,
) -> Result<Option<Address>> {
    let contract = MetadosisContract::new(storage.clone());
    let member_count = if let Some(response) = contract.response_window_for_job(prefix.job_id)? {
        let Some(record) = contract.ocomp_job_record(response.intent_id, limits)? else {
            return Err(storage_corruption_message(
                "OCOMP response index points to a missing job",
            ));
        };
        let Some(finalized) = record.finalized.as_ref() else {
            return Err(storage_corruption_message(
                "OCOMP response-window job is not finalized",
            ));
        };
        if finalized.job_id != response.job_id
            || finalized.deadline_height != response.deadline_height
            || !matches!(
                record.status,
                OcompJobStatus::VotingOpen | OcompJobStatus::Completed
            )
        {
            return Err(storage_corruption_message(
                "OCOMP response index/job binding mismatch",
            ));
        }
        if prefix.protocol_bundle_hash != record.intent.protocol_bundle_hash
            || prefix.attempt != record.intent.attempt
            || prefix.result_validator_set_epoch != record.intent.result_validator_set_epoch
            || prefix.result_committee_set_hash != record.intent.result_committee_set_hash
            || prefix.result_ocomp_binding_hash != record.intent.result_ocomp_binding_hash
        {
            return Ok(None);
        }
        record.intent.result_member_count
    } else {
        let Some(accountability) = contract.result_vote_accountability(prefix.job_id, limits)?
        else {
            return Ok(None);
        };
        if accountability.closed_summary.is_none()
            || prefix.result_validator_set_epoch != accountability.result_validator_set_epoch
            || prefix.result_committee_set_hash != accountability.result_committee_set_hash
            || prefix.result_ocomp_binding_hash != accountability.result_ocomp_binding_hash
        {
            return Ok(None);
        }
        accountability.member_count
    };
    let Some(snapshot) = outbe_validatorset::read_ocomp_snapshot_extension_for_binding(
        storage.clone(),
        prefix.result_validator_set_epoch,
        prefix.result_committee_set_hash,
        prefix.result_ocomp_binding_hash,
    )?
    else {
        return Ok(None);
    };
    if snapshot.member_count != member_count {
        return Ok(None);
    }
    let snapshot_key = outbe_validatorset::committee_snapshot_key(
        prefix.result_validator_set_epoch,
        prefix.result_committee_set_hash,
    );
    Ok(resolve_historical_result_vote_member(
        storage,
        snapshot_key,
        member_count,
        prefix.ocomp_key_hash,
        prefix.key_epoch,
    )?
    .map(|member| member.validator_address))
}

fn resolve_historical_result_vote_member(
    storage: StorageHandle<'_>,
    snapshot_key: B256,
    member_count: u16,
    ocomp_key_hash: B256,
    key_epoch: u64,
) -> Result<Option<ResolvedHistoricalResultVoteMemberV1>> {
    let validators = outbe_validatorset::contract::ValidatorSet::new(storage.clone());
    let validator_address = validators
        .ocomp_key_hash_to_validator
        .read(&ocomp_key_hash)?;
    if validator_address.is_zero() {
        return Ok(None);
    }

    for validator_index in 0..member_count {
        let member = outbe_validatorset::read_ocomp_snapshot_member_at(
            storage.clone(),
            snapshot_key,
            validator_index,
        )?
        .ok_or_else(|| storage_corruption_message("OCOMP historical snapshot member is missing"))?;
        if member.validator_address != validator_address {
            continue;
        }
        if member.key_epoch != key_epoch
            || keccak256(member.ocomp_public_key_sec1) != ocomp_key_hash
        {
            return Ok(None);
        }
        return Ok(Some(ResolvedHistoricalResultVoteMemberV1 {
            validator_address,
            validator_index,
            key_epoch: member.key_epoch,
            ocomp_public_key_sec1: member.ocomp_public_key_sec1,
        }));
    }
    Ok(None)
}

/// Resolves and authorizes the outer EVM signer of an OCOMP system carrier.
///
/// The represented validator comes exclusively from the exact historical
/// snapshot pinned by the vote. Its own address is accepted only when no OCOMP
/// delegate is configured; otherwise only the current reverse-verified OCOMP
/// delegate is accepted. Current ACTIVE status is deliberately irrelevant for
/// an already-open historical job.
pub fn resolve_historical_result_vote_carrier_signer(
    storage: StorageHandle<'_>,
    prefix: &ResultVotePrefixV1,
    signer: Address,
    limits: &SchemaLimits,
) -> Result<Option<Address>> {
    let Some(historical_validator) =
        resolve_historical_result_vote_participant(storage.clone(), prefix, limits)?
    else {
        return Ok(None);
    };
    let validators = outbe_validatorset::contract::ValidatorSet::new(storage);
    let role = outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp;
    let explicit = validators.get_delegate(historical_validator, role)?;
    if signer == historical_validator {
        return Ok(explicit.is_zero().then_some(historical_validator));
    }
    if explicit != signer {
        return Ok(None);
    }
    let reverse = validators
        .validator_by_role_delegate
        .get_nested(&role.id())
        .read(&signer)?;
    Ok((reverse == historical_validator).then_some(historical_validator))
}

impl MetadosisContract<'_> {
    /// Verifies and records one direct result vote at its canonical inclusion
    /// height. The response-window index, job record, vote slots and immutable
    /// quorum transition are committed in one storage checkpoint.
    pub fn record_ocomp_result_vote(
        &mut self,
        vote: &ResultVoteV1,
        inclusion_height: u64,
        scope: &ExecutionScope,
        limits: &SchemaLimits,
    ) -> Result<RecordedResultVoteV1> {
        let storage = self.storage.clone();
        let outcome = (|| {
            let response = match self.response_window_for_job(vote.job_id)? {
                Some(response) => response,
                None => {
                    let deadline_closed = self
                        .result_vote_accountability(vote.job_id, limits)?
                        .is_some_and(|accountability| accountability.closed_summary.is_some());
                    if deadline_closed {
                        return Err(vote_reject(DEADLINE_PASSED));
                    }
                    return Err(reject("OCOMP result vote has no open response window"));
                }
            };
            let record = self
                .ocomp_job_record(response.intent_id, limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP response index points to a missing job")
                })?;
            let finalized = record.finalized.as_ref().ok_or_else(|| {
                storage_corruption_message("OCOMP response-window job is not finalized")
            })?;
            if finalized.job_id != response.job_id
                || finalized.deadline_height != response.deadline_height
            {
                return Err(storage_corruption_message(
                    "OCOMP response index/job binding mismatch",
                ));
            }
            if !matches!(
                record.status,
                OcompJobStatus::VotingOpen | OcompJobStatus::Completed
            ) {
                return Err(reject(
                    "OCOMP result vote requires an open or quorum-certified job",
                ));
            }
            if vote.protocol_bundle_hash != record.intent.protocol_bundle_hash
                || vote.attempt != record.intent.attempt
                || vote.result_validator_set_epoch != record.intent.result_validator_set_epoch
                || vote.result_committee_set_hash != record.intent.result_committee_set_hash
                || vote.result_ocomp_binding_hash != record.intent.result_ocomp_binding_hash
            {
                return Err(reject(
                    "OCOMP result vote does not match pinned job binding",
                ));
            }
            let snapshot = outbe_validatorset::read_ocomp_snapshot_extension_for_binding(
                storage.clone(),
                record.intent.result_validator_set_epoch,
                record.intent.result_committee_set_hash,
                record.intent.result_ocomp_binding_hash,
            )?
            .filter(|snapshot| snapshot.member_count == record.intent.result_member_count)
            .ok_or_else(|| reject("OCOMP result vote historical snapshot is missing"))?;
            let snapshot_key = outbe_validatorset::committee_snapshot_key(
                record.intent.result_validator_set_epoch,
                record.intent.result_committee_set_hash,
            );
            let member = resolve_historical_result_vote_member(
                storage.clone(),
                snapshot_key,
                snapshot.member_count,
                vote.ocomp_key_hash,
                vote.key_epoch,
            )?
            .ok_or_else(|| reject("OCOMP result vote member is missing"))?;
            vote.verify_historical_member(
                &record.intent,
                finalized.job_id,
                snapshot.member_count,
                member.key_epoch,
                &member.ocomp_public_key_sec1,
                inclusion_height,
                finalized.open_height,
                finalized.deadline_height,
                limits,
            )
            .map_err(|error| reject(format!("invalid OCOMP result vote: {error}")))?;

            let mut accountability = self
                .result_vote_accountability(finalized.job_id, limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP response-window vote slots are missing")
                })?;
            if accountability.quorum != finalized.quorum {
                return Err(storage_corruption_message(
                    "OCOMP job/accountability quorum mismatch",
                ));
            }
            let had_quorum = accountability.quorum.is_some();
            let outcome = accountability
                .record_verified_vote(member.validator_index, vote, inclusion_height, limits)
                .map_err(|error| reject(format!("invalid OCOMP vote transition: {error}")))?;
            let quorum = accountability.quorum.clone();

            if !had_quorum {
                // Uncertified jobs still require their installed authority.
                // Completed jobs may receive verified votes after retirement;
                // those votes must not require or reapply that authority.
                let authority = self
                    .read_ocomp_activation_authority_for_bundle(
                        record.intent.protocol_bundle_hash,
                        limits,
                    )?
                    .ok_or_else(|| {
                        storage_corruption_message("OCOMP activation authority is not installed")
                    })?;
                if let Some(formed) = &quorum {
                    if record.status != OcompJobStatus::VotingOpen {
                        return Err(storage_corruption_message(
                            "OCOMP quorum formed outside the voting-open transition",
                        ));
                    }
                    let current_time = storage.timestamp()?.try_into().map_err(|_| {
                        storage_corruption_message("OCOMP block timestamp does not fit u64")
                    })?;
                    let worldwide_day =
                        outbe_primitives::time::WorldwideDay::new(record.intent.wwd);
                    let aggregate = ValidatedWwdAggregate::load_and_validate(storage.clone())?;
                    let outer = aggregate.record(worldwide_day).ok_or_else(|| {
                        storage_corruption_message(
                            "OCOMP q-forming vote has no persisted outer WorldwideDay",
                        )
                    })?;
                    let completed_transition =
                        reduce_outer_wwd(Some(outer), OuterWwdEvent::OcompCompleted)?;
                    let apply_context = super::activation::QuorumApplyContext::new(
                        &storage,
                        scope,
                        &completed_transition,
                        inclusion_height,
                        current_time,
                        limits,
                    );
                    super::activation::apply_quorum_result(
                        apply_context,
                        self,
                        super::activation::QuorumResultInput::new(
                            response.intent_id,
                            &record,
                            &vote.result,
                            formed,
                            &authority,
                        ),
                    )?;
                    let applied = self
                        .ocomp_job_record(response.intent_id, limits)?
                        .ok_or_else(|| {
                            storage_corruption_message("OCOMP q-forming apply removed the job")
                        })?;
                    if !matches!(applied.status, OcompJobStatus::Completed)
                        || applied
                            .finalized
                            .as_ref()
                            .and_then(|finalized| finalized.quorum.as_ref())
                            != Some(formed)
                    {
                        return Err(storage_corruption_message(
                            "OCOMP q-forming apply did not commit terminal quorum state",
                        ));
                    }
                }
            } else if finalized.quorum != quorum {
                return Err(storage_corruption_message("OCOMP immutable quorum changed"));
            }

            self.write_result_vote_accountability(&accountability, limits)?;
            Ok(RecordedResultVoteV1 { outcome, quorum })
        })();
        outcome
    }

    /// Closes the one due response window and persists the objective bounded
    /// accountability summary for the pinned ValidatorSet. A timely quorum is
    /// never erased; callers expire only the returned `NoQuorum` live attempt.
    pub(crate) fn close_due_ocomp_response_window(
        &mut self,
        at_height: u64,
        limits: &SchemaLimits,
    ) -> Result<ResponseWindowCloseReport> {
        (|| {
            let mut index = self.read_response_deadline_index()?;
            let Some(key) = index.first().copied() else {
                return Ok(ResponseWindowCloseReport::not_due());
            };
            if at_height < key.deadline_height {
                return Ok(ResponseWindowCloseReport::not_due());
            }
            let record = self
                .ocomp_job_record(key.intent_id, limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP response index points to a missing job")
                })?;
            let finalized = record.finalized.as_ref().ok_or_else(|| {
                storage_corruption_message("OCOMP response-window job is not finalized")
            })?;
            if finalized.job_id != key.job_id || finalized.deadline_height != key.deadline_height {
                return Err(storage_corruption_message(
                    "OCOMP response deadline/job binding mismatch",
                ));
            }

            let mut accountability = self
                .result_vote_accountability(key.job_id, limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP response-window vote slots are missing")
                })?;
            if accountability.quorum != finalized.quorum {
                return Err(storage_corruption_message(
                    "OCOMP job/accountability quorum mismatch at close",
                ));
            }
            accountability.close(at_height, limits).map_err(|error| {
                storage_corruption_message(format!("close OCOMP vote accountability: {error}"))
            })?;
            let snapshot = outbe_validatorset::read_ocomp_snapshot_extension_for_binding(
                self.storage.clone(),
                record.intent.result_validator_set_epoch,
                record.intent.result_committee_set_hash,
                record.intent.result_ocomp_binding_hash,
            )?
            .filter(|snapshot| snapshot.member_count == accountability.member_count)
            .ok_or_else(|| {
                storage_corruption_message("OCOMP deadline historical snapshot is missing")
            })?;
            let snapshot_key = outbe_validatorset::committee_snapshot_key(
                snapshot.epoch,
                snapshot.committee_set_hash,
            );
            let validators = outbe_validatorset::contract::ValidatorSet::new(self.storage.clone());
            let mut staking = outbe_staking::contract::Staking::new(self.storage.clone());
            let mut metrics = OcompPenaltyMetrics::default();
            for (index, slot) in accountability.slots.iter().enumerate() {
                if slot.is_some() {
                    continue;
                }
                let participant_index = u16::try_from(index).map_err(|_| {
                    storage_corruption_message("OCOMP missing participant index exceeds u16")
                })?;
                let member = outbe_validatorset::read_ocomp_snapshot_member_at(
                    self.storage.clone(),
                    snapshot_key,
                    participant_index,
                )?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP deadline snapshot member is missing")
                })?;
                let resolution = staking
                    .resolve_due_ocomp_recovery_window(member.validator_address)
                    .map_err(|error| match error {
                        PrecompileError::Revert(_) | PrecompileError::RevertBytes(_) => {
                            storage_corruption_message(format!(
                                "resolve due OCOMP recovery for participant {participant_index}: {error}"
                            ))
                        }
                        other => other,
                    })?;
                let outcome = match resolution {
                    outbe_staking::logic::OcompRecoveryResolution::Restored { .. } => {
                        Some("restored")
                    }
                    outbe_staking::logic::OcompRecoveryResolution::Jailed {
                        observability, ..
                    } => {
                        metrics.punishments.push(observability);
                        Some("jailed")
                    }
                    outbe_staking::logic::OcompRecoveryResolution::ClosedNonActive { .. } => {
                        Some("non_active")
                    }
                    outbe_staking::logic::OcompRecoveryResolution::NotOpen
                    | outbe_staking::logic::OcompRecoveryResolution::NotDue { .. } => None,
                };
                if let Some(outcome) = outcome {
                    metrics
                        .recovery_resolutions
                        .push((member.validator_address, outcome));
                }
                let current = validators.get_validator(member.validator_address)?;
                if current.is_some_and(|record| {
                    record.status == outbe_validatorset::runtime::status::ACTIVE
                }) {
                    let penalty = staking
                        .record_ocomp_miss(member.validator_address)
                        .map_err(|error| match error {
                            PrecompileError::Revert(_) | PrecompileError::RevertBytes(_) => {
                                storage_corruption_message(format!(
                                    "record ACTIVE missing OCOMP validator {participant_index}: {error}"
                                ))
                            }
                            other => other,
                        })?;
                    self.emit(IMetadosis::OcompVoteMissed {
                        validator: member.validator_address,
                        jobId: key.job_id,
                        missCount: penalty.miss_count,
                        slashedBonded: penalty.slashed_bonded,
                        recoveryDeadline: penalty.recovery_deadline,
                        firstInWindow: penalty.first_in_window,
                    })?;
                    metrics.misses.push((
                        member.validator_address,
                        penalty.first_in_window,
                        penalty.recovery_deadline,
                    ));
                }
            }
            self.write_result_vote_accountability(&accountability, limits)?;
            remove_response_deadline_key(&mut index, key)?;
            self.write_response_deadline_index(&index)?;

            let close = match record.status {
                OcompJobStatus::VotingOpen if finalized.quorum.is_none() => {
                    ResponseWindowCloseV1::NoQuorum {
                        intent_id: key.intent_id,
                    }
                }
                OcompJobStatus::Completed if finalized.quorum.is_some() => {
                    ResponseWindowCloseV1::QuorumPreserved {
                        intent_id: key.intent_id,
                    }
                }
                _ => {
                    return Err(storage_corruption_message(
                        "OCOMP response close found an invalid job status",
                    ))
                }
            };
            Ok(ResponseWindowCloseReport { close, metrics })
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_ocomp_protocol::{
        abi::SUBMIT_LYSIS_RESULT_SELECTOR, encode_envelope, registry::ObjectKind, OCB1_HEADER_LEN,
    };

    fn dynamic_bytes_calldata(payload_len: usize) -> Vec<u8> {
        assert!(payload_len >= OCB1_HEADER_LEN + 150);
        let payload = encode_envelope(
            ObjectKind::ResultVoteV1,
            &vec![0_u8; payload_len - OCB1_HEADER_LEN],
            super::super::schema::poc_schema_limits().codec,
        )
        .unwrap();
        let padded_len = (payload_len + 31) & !31;
        let mut data = vec![0_u8; 68 + padded_len];
        data[..4].copy_from_slice(&SUBMIT_LYSIS_RESULT_SELECTOR);
        data[4..36].copy_from_slice(&U256::from(32).to_be_bytes::<32>());
        data[36..68].copy_from_slice(&U256::from(payload_len).to_be_bytes::<32>());
        data[68..68 + payload_len].copy_from_slice(&payload);
        data
    }

    #[test]
    fn result_vote_preflight_accepts_cap_minus_one_and_cap_and_rejects_cap_plus_one() {
        let cap = usize::try_from(
            outbe_ocomp_protocol::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1
                .max_result_vote_bytes,
        )
        .unwrap();
        let limits = super::super::schema::poc_schema_limits();
        for accepted in [cap - 1, cap] {
            let data = dynamic_bytes_calldata(accepted);
            assert_eq!(
                preflight_result_vote_calldata(&data, &limits)
                    .unwrap()
                    .len(),
                accepted
            );
        }

        let rejected = dynamic_bytes_calldata(cap + 1);
        assert!(matches!(
            preflight_result_vote_calldata(&rejected, &limits),
            Err(PrecompileError::RevertBytes(_))
        ));
    }

    #[test]
    fn result_vote_preflight_rejects_nonzero_abi_padding() {
        let mut data = dynamic_bytes_calldata(OCB1_HEADER_LEN + 150);
        *data.last_mut().unwrap() = 1;
        assert!(matches!(
            preflight_result_vote_calldata(&data, &super::super::schema::poc_schema_limits()),
            Err(PrecompileError::RevertBytes(_))
        ));
    }
}
