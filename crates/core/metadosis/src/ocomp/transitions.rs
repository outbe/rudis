use alloy_primitives::{B256, U256};
use outbe_lysis::activation_v1::LysisTerminalPermitV1;
use outbe_ocomp_protocol::{
    intent::{intent_storage_key, JobIntentV1},
    receipts::{ActivationOutcome, AggregateActivationReceiptV1, RequestBudgetSplitReceiptV1},
    state::{
        ActiveGenerationV1, LysisTerminalV1, OcompCompletedBindingV1, OcompFinalizedJobV1,
        OcompJobRecordV1, OcompJobStatus, OcompTerminalOutcome, RESULT_VOTE_MIN_FINALITY_DEPTH,
    },
    vote::OcompVoteAccountabilityV1,
    SchemaLimits,
};
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::{
    aggregate::WwdStatus,
    commit::commit_outer_transition,
    errors::storage_corruption_message,
    precompile::IMetadosis,
    reducer::{OuterWwdTransition, OuterWwdTransitionKind},
    schema::{MetadosisContract, WorldwideDayEntryExt},
};

use super::{
    index::{insert_response_deadline_key, remove_ready_key, ReadyIndexKey, ResponseDeadlineKey},
    state::{JobFsmCommand, OCOMP_AWAITING_FINALITY_DEADLINE_BLOCKS},
};

impl MetadosisContract<'_> {
    /// Removes a READY scheduler entry when Metadosis fails before committing
    /// a canonical OCOMP job.
    ///
    /// Once a job exists, only its own deadline may make it terminal. In
    /// particular, this outer failure path must never construct the reserved
    /// `Failed` OCOMP outcome.
    pub(crate) fn clear_ready_ocomp_for_failed_day(
        &mut self,
        wwd: WorldwideDay,
        schema_limits: &SchemaLimits,
    ) -> Result<()> {
        if self.ocomp_fsm_states.get_bytes(&wwd).is_empty()? {
            return Ok(());
        }
        let state = self.ocomp_fsm_state(wwd, schema_limits)?;
        let projection = state.projection();
        if projection.live_intent_id.is_some() {
            return Err(storage_corruption_message(
                "Metadosis failure cannot replace a live canonical OCOMP job",
            ));
        }
        let ready_key = ReadyIndexKey::from_projection(projection)?;
        let mut ready_index = self.read_ready_index()?;
        remove_ready_key(&mut ready_index, ready_key)?;
        self.write_ready_index(&ready_index)?;
        self.ocomp_fsm_states.get_bytes(&wwd).clear()
    }

    /// Commits one canonical live job and all Metadosis-owned indexes.
    ///
    /// The caller has already applied or replay-validated the owner budget
    /// effect. This method nevertheless requires and stores the exact receipt,
    /// closing the persisted receipt/state equivalence.
    pub(crate) fn commit_ocomp_request(
        &mut self,
        outer_transition: &OuterWwdTransition,
        intent: &JobIntentV1,
        receipt: &RequestBudgetSplitReceiptV1,
        schema_limits: &SchemaLimits,
    ) -> Result<()> {
        (|| {
            super::authority::require_current_ocomp_attempt_snapshot(self.storage.clone(), intent)?;
            if !matches!(
                outer_transition.kind(),
                OuterWwdTransitionKind::OcompRequestCommitted
            ) {
                return Err(storage_corruption_message(
                    "OCOMP request requires the typed outer request transition",
                ));
            }
            intent.validate_semantics().map_err(|error| {
                storage_corruption_message(format!("invalid OCOMP intent: {error}"))
            })?;
            receipt.validate_semantics().map_err(|error| {
                storage_corruption_message(format!("invalid OCOMP request receipt: {error}"))
            })?;
            let wwd = WorldwideDay::new(intent.wwd);
            if WwdStatus::try_from(self.worldwide_days.entry(wwd).status().read()?)?
                != WwdStatus::Ready
            {
                return Err(storage_corruption_message(
                    "OCOMP request requires READY WorldwideDay",
                ));
            }

            let receipt_hash = receipt.receipt_hash(schema_limits).map_err(|error| {
                storage_corruption_message(format!("hash OCOMP request receipt: {error}"))
            })?;
            if receipt_hash
                != intent
                    .frozen_metadosis_values
                    .request_budget_split_receipt_hash
                || receipt.wwd != intent.wwd
                || receipt.pending_nonce > intent.pending_nonce
                || receipt.protocol_bundle_hash != intent.protocol_bundle_hash
                || receipt.lysis_budget != intent.frozen_metadosis_values.lysis_budget
            {
                return Err(storage_corruption_message(
                    "OCOMP intent/request receipt binding mismatch",
                ));
            }
            let mut state = self.ocomp_fsm_state(wwd, schema_limits)?;
            let ready_key = ReadyIndexKey::from_projection(state.projection())?;
            let existing_receipt = self.request_budget_receipt(wwd, schema_limits)?;
            if matches!(existing_receipt, Some(ref existing) if existing != receipt) {
                return Err(storage_corruption_message(
                    "immutable OCOMP request receipt changed",
                ));
            }
            let intent_id = intent.intent_id(schema_limits).map_err(|error| {
                storage_corruption_message(format!("hash OCOMP intent: {error}"))
            })?;
            let awaiting_finality_deadline = intent
                .logical_evaluation_height
                .checked_add(OCOMP_AWAITING_FINALITY_DEADLINE_BLOCKS)
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP awaiting-finality deadline overflow")
                })?;
            let storage_key = intent_storage_key(intent_id).map_err(|error| {
                storage_corruption_message(format!("derive OCOMP intent storage key: {error}"))
            })?;
            if !self.ocomp_job_records.get_bytes(&storage_key).is_empty()? {
                return Err(storage_corruption_message(
                    "OCOMP IntentId already has a job record",
                ));
            }
            state
                .apply(JobFsmCommand::Request {
                    at_height: intent.logical_evaluation_height,
                    deadline_height: awaiting_finality_deadline,
                    intent_id,
                    lysis_budget: intent.frozen_metadosis_values.lysis_budget,
                    request_budget_receipt_hash: receipt_hash,
                })
                .map_err(|error| storage_corruption_message(error.to_string()))?;

            if existing_receipt.is_none() {
                self.ocomp_request_budget_receipts.get_bytes(&wwd).write(
                    &receipt.encode_canonical(schema_limits).map_err(|error| {
                        storage_corruption_message(format!("encode request receipt: {error}"))
                    })?,
                )?;
            }
            let record = OcompJobRecordV1 {
                intent: intent.clone(),
                intent_height: intent.logical_evaluation_height,
                status: OcompJobStatus::AwaitingFinality,
                finalized: None,
                terminal: None,
            };
            self.write_ocomp_job_record(intent_id, &record, schema_limits)?;
            commit_outer_transition(
                self,
                wwd,
                outer_transition,
                intent.logical_evaluation_height,
            )?;
            let mut ready_index = self.read_ready_index()?;
            remove_ready_key(&mut ready_index, ready_key)?;
            self.write_ready_index(&ready_index)?;
            self.write_ocomp_state(&state)?;
            self.write_live_scheduler(&state)
        })()
    }

    /// Records the consensus-certified request block and derives the voting
    /// window. The request itself carries no deadline.
    pub fn record_ocomp_finality(
        &mut self,
        intent_id: B256,
        finalized_request_block_hash: B256,
        finalized_request_state_root: B256,
        finality_recorded_height: u64,
        response_window_blocks: u64,
        schema_limits: &SchemaLimits,
    ) -> Result<OcompFinalizedJobV1> {
        (|| {
            let mut record = self
                .ocomp_job_record(intent_id, schema_limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP finality record has no matching intent")
                })?;
            if record.status != OcompJobStatus::AwaitingFinality || record.terminal.is_some() {
                return Err(storage_corruption_message(
                    "OCOMP finality requires AWAITING_FINALITY",
                ));
            }
            let awaiting_finality_deadline = record
                .intent_height
                .checked_add(OCOMP_AWAITING_FINALITY_DEADLINE_BLOCKS)
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP awaiting-finality deadline overflow")
                })?;
            let profile = self
                .read_ocomp_request_profile(schema_limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP finality has no request profile")
                })?;
            if finality_recorded_height < record.intent_height
                || finality_recorded_height > awaiting_finality_deadline
                || response_window_blocks != profile.capacity_profile.result_deadline_blocks
            {
                return Err(storage_corruption_message(
                    "OCOMP finality/window height is invalid",
                ));
            }
            let open_height = finality_recorded_height
                .checked_add(RESULT_VOTE_MIN_FINALITY_DEPTH)
                .ok_or_else(|| storage_corruption_message("OCOMP voting open height overflow"))?;
            let deadline_height = open_height
                .checked_add(response_window_blocks)
                .ok_or_else(|| storage_corruption_message("OCOMP response deadline overflow"))?;
            let finalized = OcompFinalizedJobV1 {
                job_id: record
                    .intent
                    .job_id(
                        finalized_request_block_hash,
                        finalized_request_state_root,
                        schema_limits,
                    )
                    .map_err(|error| {
                        storage_corruption_message(format!("derive finalized OCOMP JobId: {error}"))
                    })?,
                finalized_request_block_hash,
                finalized_request_state_root,
                finality_recorded_height,
                open_height,
                deadline_height,
                quorum: None,
            };
            finalized.validate_semantics().map_err(|error| {
                storage_corruption_message(format!("invalid finalized OCOMP job: {error}"))
            })?;
            if let Some(existing) = &record.finalized {
                if existing == &finalized {
                    return Ok(existing.clone());
                }
                return Err(storage_corruption_message("OCOMP finality binding changed"));
            }
            record.finalized = Some(finalized.clone());
            self.write_ocomp_job_record(intent_id, &record, schema_limits)?;
            Ok(finalized)
        })()
    }

    /// Opens a finalized job once its open height has been reached while
    /// preserving the immutable response deadline.
    ///
    /// A delayed lifecycle tick may catch up before that deadline. At or after
    /// the deadline the caller must retire the still-unopened job as Expired.
    pub(crate) fn open_due_ocomp_voting(
        &mut self,
        at_height: u64,
        schema_limits: &SchemaLimits,
    ) -> Result<bool> {
        (|| {
            let mut selected = None;
            for state in self.live_ocomp_fsm_states(schema_limits)? {
                let intent_id = state.projection().live_intent_id.ok_or_else(|| {
                    storage_corruption_message("OCOMP live scheduler has no IntentId")
                })?;
                let record = self
                    .ocomp_job_record(intent_id, schema_limits)?
                    .ok_or_else(|| {
                        storage_corruption_message("OCOMP live scheduler job is missing")
                    })?;
                if record.status != OcompJobStatus::AwaitingFinality {
                    continue;
                }
                let Some(finalized) = record.finalized.clone() else {
                    continue;
                };
                if at_height < finalized.open_height {
                    continue;
                }
                if at_height >= finalized.deadline_height {
                    return Err(storage_corruption_message(
                        "OCOMP voting cannot open at or after its deadline",
                    ));
                }
                if selected
                    .replace((state, intent_id, record, finalized))
                    .is_some()
                {
                    return Err(storage_corruption_message(
                        "multiple OCOMP jobs are due at one bounded open height",
                    ));
                }
            }
            let Some((mut state, intent_id, mut record, finalized)) = selected else {
                return Ok(false);
            };
            state
                .apply(JobFsmCommand::OpenVoting {
                    at_height,
                    deadline_height: finalized.deadline_height,
                })
                .map_err(|error| storage_corruption_message(error.to_string()))?;
            let accountability = OcompVoteAccountabilityV1::empty(
                finalized.job_id,
                record.intent.result_validator_set_epoch,
                record.intent.result_committee_set_hash,
                record.intent.result_ocomp_binding_hash,
                record.intent.result_member_count,
                record.intent.result_quorum_threshold,
            )
            .map_err(|error| {
                storage_corruption_message(format!("create OCOMP vote slots: {error}"))
            })?;
            let slot = self.ocomp_vote_accountability.get_bytes(&finalized.job_id);
            if !slot.is_empty()? {
                return Err(storage_corruption_message(
                    "OCOMP vote accountability already exists",
                ));
            }
            slot.write(
                &accountability
                    .encode_canonical(schema_limits)
                    .map_err(|error| {
                        storage_corruption_message(format!("encode OCOMP vote slots: {error}"))
                    })?,
            )?;
            let mut response_index = self.read_response_deadline_index()?;
            insert_response_deadline_key(
                &mut response_index,
                ResponseDeadlineKey {
                    deadline_height: finalized.deadline_height,
                    job_id: finalized.job_id,
                    intent_id,
                },
            )?;
            record.status = OcompJobStatus::VotingOpen;
            self.write_ocomp_job_record(intent_id, &record, schema_limits)?;
            self.write_ocomp_state(&state)?;
            self.write_live_scheduler(&state)?;
            self.write_response_deadline_index(&response_index)?;
            Ok(true)
        })()
    }

    /// Applies the exclusive begin-zone expiry to the exact live index.
    ///
    /// The explicit arguments are the complete authorization, outer-FSM, time,
    /// schema, and inner-FSM boundary for one atomic expiry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expire_ocomp_job(
        &mut self,
        outer_transition: &OuterWwdTransition,
        intent_id: B256,
        at_height: u64,
        at_time: u64,
        schema_limits: &SchemaLimits,
    ) -> Result<U256> {
        (|| {
            if !matches!(
                outer_transition.kind(),
                OuterWwdTransitionKind::OcompExpired
            ) {
                return Err(storage_corruption_message(
                    "OCOMP expiry requires the typed outer expiry transition",
                ));
            }
            let mut state = self
                .live_ocomp_fsm_state_by_intent(intent_id, schema_limits)?
                .ok_or_else(|| storage_corruption_message("OCOMP expiry index is empty"))?;
            let live_intent_id = state.projection().live_intent_id.ok_or_else(|| {
                storage_corruption_message("OCOMP expiry index has no live intent")
            })?;
            if live_intent_id != intent_id {
                return Err(storage_corruption_message(
                    "OCOMP expiry selected a different live job",
                ));
            }
            let mut record = self
                .ocomp_job_record(live_intent_id, schema_limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP live index points to a missing job")
                })?;
            let wwd = WorldwideDay::new(record.intent.wwd);
            state
                .apply(JobFsmCommand::Expire { at_height, at_time })
                .map_err(|error| storage_corruption_message(error.to_string()))?;
            let terminal = state.terminal_attempts().last().copied().ok_or_else(|| {
                storage_corruption_message("OCOMP expiry produced no terminal evidence")
            })?;
            if terminal.intent_id != live_intent_id
                || terminal.pending_nonce != record.intent.pending_nonce
                || state.projection().phase != super::state::DayPhase::Terminal
            {
                return Err(storage_corruption_message(
                    "OCOMP terminal evidence is inconsistent",
                ));
            }
            let indexed_terminal = self.terminal_intent_count(wwd)?;
            if indexed_terminal != 0 {
                return Err(storage_corruption_message(
                    "OCOMP WorldwideDay already has a terminal job",
                ));
            }
            let retained_lysis_budget = terminal.retained_lysis_budget;
            if retained_lysis_budget != record.intent.frozen_metadosis_values.lysis_budget {
                return Err(storage_corruption_message(
                    "expired OCOMP job retained budget mismatch",
                ));
            }

            record.status = OcompJobStatus::Expired;
            record.terminal = Some(LysisTerminalV1 {
                outcome: OcompTerminalOutcome::Expired,
                terminal_height: terminal.terminal_height,
                terminal_time: terminal.terminal_time,
                completed_binding: None,
            });
            self.write_ocomp_job_record(live_intent_id, &record, schema_limits)?;
            self.push_terminal_intent(wwd, live_intent_id)?;
            self.release_ocomp_lineage(live_intent_id, at_height, schema_limits)?;
            Ok(retained_lysis_budget)
        })()
    }

    /// Commits the certified terminal receipt and active generation after all
    /// four owner receipts have been verified in the same activation frame.
    ///
    /// The one-shot terminal permit is advanced only after every consensus
    /// write and event succeeds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_ocomp_completed(
        &mut self,
        outer_transition: &OuterWwdTransition,
        intent_id: B256,
        active_generation: ActiveGenerationV1,
        result_evidence_hash: B256,
        nod_gratis_consumed: U256,
        unused_lysis: U256,
        activated_at_height: u64,
        activated_at_time: u64,
        permit: LysisTerminalPermitV1<'_, '_>,
        quorum: &outbe_ocomp_protocol::vote::OcompQuorumV1,
        schema_limits: &SchemaLimits,
    ) -> Result<OcompCompletedBindingV1> {
        (|| {
            if !matches!(
                outer_transition.kind(),
                OuterWwdTransitionKind::OcompCompleted
            ) {
                return Err(storage_corruption_message(
                    "OCOMP completion requires the typed completed outer transition",
                ));
            }
            let state = self
                .live_ocomp_fsm_state_by_intent(intent_id, schema_limits)?
                .ok_or_else(|| storage_corruption_message("OCOMP completion has no live job"))?;
            let projection = state.projection();
            if projection.live_intent_id != Some(intent_id) {
                return Err(storage_corruption_message(
                    "OCOMP completion IntentId is not the live job",
                ));
            }
            let mut record = self
                .ocomp_job_record(intent_id, schema_limits)?
                .ok_or_else(|| {
                    storage_corruption_message("OCOMP completion job record is missing")
                })?;
            if record.status != OcompJobStatus::VotingOpen || record.terminal.is_some() {
                return Err(storage_corruption_message(
                    "OCOMP completion requires a voting-open job",
                ));
            }
            if record
                .finalized
                .as_ref()
                .and_then(|finalized| finalized.quorum.as_ref())
                .is_some()
            {
                return Err(storage_corruption_message(
                    "OCOMP completion job already has a quorum",
                ));
            }
            // Lockstep with the persisted per-day index; see `expire_ocomp_job`.
            let wwd = WorldwideDay::new(record.intent.wwd);
            let indexed_terminal = self.terminal_intent_count(wwd)?;
            if indexed_terminal != 0 || projection.terminal_records != 0 {
                return Err(storage_corruption_message(
                    "OCOMP WorldwideDay already has a terminal job",
                ));
            }

            let activation_preconditions_hash = record
                .intent
                .activation_preconditions
                .activation_preconditions_hash(schema_limits)
                .map_err(|error| {
                    storage_corruption_message(format!(
                        "hash OCOMP activation preconditions: {error}"
                    ))
                })?;
            let binding = permit.binding().clone();
            if binding.intent_id != intent_id
                || binding.job_id != active_generation.job_id
                || binding.attempt != record.intent.attempt
                || binding.protocol_bundle_hash != record.intent.protocol_bundle_hash
                || binding.activation_preconditions_hash != activation_preconditions_hash
                || permit.request_budget_split_receipt_hash()
                    != record
                        .intent
                        .frozen_metadosis_values
                        .request_budget_split_receipt_hash
                || unused_lysis > record.intent.frozen_metadosis_values.lysis_budget
                || nod_gratis_consumed.checked_add(unused_lysis)
                    != Some(record.intent.frozen_metadosis_values.lysis_budget)
            {
                return Err(storage_corruption_message(
                    "OCOMP terminal permit is not bound to the live job",
                ));
            }
            if result_evidence_hash.is_zero() {
                return Err(storage_corruption_message(
                    "OCOMP result evidence hash is zero",
                ));
            }
            if active_generation.result_evidence_hash != result_evidence_hash {
                return Err(storage_corruption_message(
                    "active Lysis generation differs from result evidence",
                ));
            }

            if self.active_lysis_generation(wwd, schema_limits)?.is_some() {
                return Err(storage_corruption_message(
                    "active Lysis generation cannot be overwritten",
                ));
            }
            let active_generation_hash = active_generation
                .active_generation_hash(schema_limits)
                .map_err(|error| {
                    storage_corruption_message(format!("hash active Lysis generation: {error}"))
                })?;
            let receipt = AggregateActivationReceiptV1 {
                binding: binding.clone(),
                outcome: ActivationOutcome::Applied,
                nod_receipt_hash: Some(permit.nod_receipt_hash()),
                contributor_receipt_hash: Some(permit.contributor_receipt_hash()),
                tribute_receipt_hash: Some(permit.tribute_receipt_hash()),
                carry_over_receipt_hash: Some(permit.carry_over_receipt_hash()),
                request_budget_split_receipt_hash: permit.request_budget_split_receipt_hash(),
                active_generation_hash: Some(active_generation_hash),
                effect_commitment: permit.effect_commitment(),
                event_summary_hash: permit.event_summary_hash(),
                activated_at_height,
                activated_at_time,
            };
            receipt.validate_semantics().map_err(|error| {
                storage_corruption_message(format!("invalid applied terminal receipt: {error}"))
            })?;
            let terminal_receipt_hash =
                receipt
                    .terminal_receipt_hash(schema_limits)
                    .map_err(|error| {
                        storage_corruption_message(format!(
                            "hash applied terminal receipt: {error}"
                        ))
                    })?;
            let completed_binding = OcompCompletedBindingV1 {
                job_id: binding.job_id,
                activation_call_id: permit.activation_call_id(),
                result_digest: binding.result_digest,
                quorum_height: quorum.quorum_height,
                quorum_signer_bitmap: quorum.signer_bitmap.clone(),
                quorum_evidence_hash: quorum.evidence_hash,
                result_evidence_hash,
                terminal_receipt_hash,
                terminal_receipt: receipt,
            };
            completed_binding
                .validate_semantics(quorum, schema_limits)
                .map_err(|error| {
                    storage_corruption_message(format!("invalid OCOMP completed binding: {error}"))
                })?;

            self.ocomp_active_lysis_generations.get_bytes(&wwd).write(
                &active_generation
                    .encode_canonical(schema_limits)
                    .map_err(|error| {
                        storage_corruption_message(format!(
                            "encode active Lysis generation: {error}"
                        ))
                    })?,
            )?;
            record
                .finalized
                .as_mut()
                .ok_or_else(|| storage_corruption_message("OCOMP completion job is not finalized"))?
                .quorum = Some(quorum.clone());
            record.status = OcompJobStatus::Completed;
            record.terminal = Some(LysisTerminalV1 {
                outcome: OcompTerminalOutcome::Completed,
                terminal_height: activated_at_height,
                terminal_time: activated_at_time,
                completed_binding: Some(completed_binding.clone()),
            });
            self.write_ocomp_job_record(intent_id, &record, schema_limits)?;
            self.push_terminal_intent(wwd, intent_id)?;
            commit_outer_transition(self, wwd, outer_transition, activated_at_height)?;
            self.remove_live_scheduler(intent_id)?;
            self.ocomp_fsm_states.get_bytes(&wwd).clear()?;
            self.release_ocomp_lineage(intent_id, activated_at_height, schema_limits)?;

            let frozen = &record.intent.frozen_metadosis_values;
            self.emit(IMetadosis::MetadosisExecuted {
                worldwideDay: record.intent.wwd,
                tributeTotals: record.intent.authenticated_day_nominal,
                dayGratisDemand: frozen.gratis_demand,
                dayGratisLimit: frozen.gratis_supply,
                dayGratisAllocation: frozen.lysis_budget,
                dayGratisAllocationRemainder: unused_lysis,
                netDayGratisAllocation: nod_gratis_consumed,
                dayMetadosisLimitRemainder: unused_lysis,
                status: "COMPLETED".into(),
                blockNumber: activated_at_height,
            })?;
            self.emit(IMetadosis::LysisActivated {
                intentId: intent_id,
                jobId: binding.job_id,
                activationCallId: permit.activation_call_id(),
                resultDigest: binding.result_digest,
                terminalReceiptHash: terminal_receipt_hash,
                wwd: record.intent.wwd,
            })?;
            permit.commit_terminal().map_err(|error| {
                storage_corruption_message(format!("commit Lysis terminal permit: {error}"))
            })?;
            Ok(completed_binding)
        })()
    }

    fn release_ocomp_lineage(
        &mut self,
        lineage: B256,
        at_height: u64,
        schema_limits: &SchemaLimits,
    ) -> Result<()> {
        let mut registry = outbe_ocompregistry::OcompRegistry::new(self.storage.clone());
        if registry.active_authority(schema_limits)?.is_none() {
            #[cfg(any(test, feature = "test-utils"))]
            return Ok(());
            #[cfg(not(any(test, feature = "test-utils")))]
            return Err(storage_corruption_message(
                "terminal OCOMP WWD has no active Registry authority",
            ));
        }
        let released = registry.release_lineage(lineage, at_height, schema_limits)?;
        if !released {
            return Err(storage_corruption_message(
                "terminal OCOMP WWD has no Registry lineage pin",
            ));
        }
        Ok(())
    }
}
