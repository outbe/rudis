use alloy_primitives::U256;
use outbe_ocompregistry::{poc_schema_limits, OcompRegistry};
use outbe_primitives::block::BlockRuntimeContext;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_teeregistry::TeeRegistry;
use serde_json::Value;

use crate::constants::{
    max_activatable_version, min_activation_buffer, MAX_WAITING_FOR_ACTIVATION_UPDATES,
};
use crate::errors::UpdateError;
use crate::handlers::UpgradeHandlerRegistry;
use crate::payload::decode_schedule_update_json;
use crate::precompile::IUpdate;
use crate::schema::{ScheduledUpdateStatus, Update};
use crate::version::format_protocol_version;
use crate::ProtocolVersion;

impl Update<'_> {
    /// Schedules an update from an approved vote proposal payload.
    pub fn schedule_update_from_propose(
        &mut self,
        proposal_id: U256,
        payload: &Value,
        current_height: u64,
    ) -> Result<()> {
        self.schedule_update_from_propose_classified(proposal_id, payload, current_height)?
            .map_err(Into::into)
    }

    /// Schedules an approved Vote payload while preserving the boundary between
    /// deterministic domain rejection and storage/provider failure.
    pub(crate) fn schedule_update_from_propose_classified(
        &mut self,
        proposal_id: U256,
        payload: &Value,
        current_height: u64,
    ) -> Result<std::result::Result<(), UpdateError>> {
        let (version, activation_height, info) = match decode_schedule_update_json(payload) {
            Ok(decoded) => decoded,
            Err(err) => return Ok(Err(err)),
        };
        self.schedule_update_from_propose_fields_classified(
            proposal_id,
            version,
            activation_height,
            &info,
            current_height,
        )
    }

    fn schedule_update_from_propose_fields_classified(
        &mut self,
        proposal_id: U256,
        version: ProtocolVersion,
        activation_height: u64,
        info: &str,
        current_height: u64,
    ) -> Result<std::result::Result<(), UpdateError>> {
        if self.read_scheduled_update(proposal_id)?.is_some() {
            return Ok(Err(UpdateError::ScheduledUpdateAlreadyExists));
        }

        if version.is_zero() {
            return Ok(Err(UpdateError::InvalidVersion));
        }

        let active = self.get_active_version()?;
        if version <= active {
            return Ok(Err(UpdateError::DowngradeNotAllowed));
        }

        let chain_id = self.storage.chain_id()?;
        let min_activation = current_height.saturating_add(min_activation_buffer(chain_id));
        if activation_height < min_activation {
            return Ok(Err(UpdateError::HeightInPast));
        }

        if self.scheduled_activation_conflict(activation_height)? {
            return Ok(Err(UpdateError::ActivationConflict));
        }

        let waiting_len = self.waiting_for_activation_proposal_ids.len()?;
        if waiting_len >= MAX_WAITING_FOR_ACTIVATION_UPDATES {
            return Ok(Err(UpdateError::TooManyWaitingForActivation));
        }

        self.write_scheduled_update(proposal_id, version, activation_height, info)?;
        self.emit(IUpdate::ScheduledUpdateCreated {
            proposalId: proposal_id,
            version: version.raw(),
            activationHeight: activation_height,
            info: info.as_bytes().to_vec().into(),
        })?;
        Ok(Ok(()))
    }

    /// Activates scheduled updates at the current block height using `registry`.
    pub fn process_begin_block_with_handlers(
        &mut self,
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
    ) -> Result<()> {
        let block_number = ctx.block.block_number;
        let waiting_ids = self.list_waiting_for_activation_proposal_ids()?;
        for proposal_id in waiting_ids {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                return Err(UpdateError::ScheduledUpdateNotFound.into());
            };
            if scheduled.status == ScheduledUpdateStatus::Scheduled
                && block_number >= scheduled.activation_height
            {
                self.activate_scheduled_update(ctx, registry, proposal_id)?;
            }
        }
        OcompRegistry::new(ctx.storage.clone())
            .try_retire_predecessor(block_number, &poc_schema_limits())?;
        Ok(())
    }

    fn activate_scheduled_update(
        &mut self,
        ctx: &BlockRuntimeContext,
        registry: &UpgradeHandlerRegistry,
        proposal_id: U256,
    ) -> Result<()> {
        let scheduled = self
            .read_scheduled_update(proposal_id)?
            .ok_or(UpdateError::ScheduledUpdateNotFound)?;
        if scheduled.status != ScheduledUpdateStatus::Scheduled {
            return Ok(());
        }
        let active = self.get_active_version()?;
        if scheduled.version <= active {
            return self.cancel_scheduled_update(proposal_id);
        }

        let ceiling = max_activatable_version(self.storage.chain_id()?);
        if scheduled.version > ceiling {
            return Err(PrecompileError::Fatal(format!(
                "cannot activate protocol version {}: binary supports at most {}",
                format_protocol_version(scheduled.version),
                format_protocol_version(ceiling),
            )));
        }

        ctx.with_checkpoint(|| {
            for handler in registry.lookup(scheduled.version) {
                handler.handle(ctx, &scheduled).map_err(|err| match err {
                    PrecompileError::Fatal(message) => PrecompileError::Fatal(message),
                    other => PrecompileError::Fatal(format!(
                        "upgrade handler '{}' failed: {other}",
                        handler.label()
                    )),
                })?;
            }

            self.reconcile_staged_tee_policy(ctx, &scheduled)?;
            self.reconcile_staged_ocomp_successor(ctx, &scheduled)?;

            self.set_active_version(scheduled.version, scheduled.activation_height)?;
            self.set_scheduled_update_status(proposal_id, ScheduledUpdateStatus::Activated)?;
            self.emit(IUpdate::UpgradeActivated {
                version: scheduled.version.raw(),
                activationHeight: scheduled.activation_height,
            })?;
            self.cancel_outdated_waiting_updates(scheduled.version)
        })
    }

    fn reconcile_staged_tee_policy(
        &mut self,
        ctx: &BlockRuntimeContext,
        activating: &crate::state::ScheduledUpdateInfo,
    ) -> Result<()> {
        let mut tee_registry = TeeRegistry::new(self.storage.clone());
        let Some((staged_proposal_id, _)) = tee_registry.staged_successor_policy_v1()? else {
            return Ok(());
        };
        if staged_proposal_id == activating.proposal_id {
            return tee_registry
                .promote_staged_successor_policy_v1(staged_proposal_id, ctx.block.block_number)
                .map_err(|err| fatal_tee_policy_activation(err, staged_proposal_id));
        }

        let staged_update = self
            .read_scheduled_update(staged_proposal_id)?
            .ok_or_else(|| {
                PrecompileError::Fatal(format!(
                    "staged TEE policy references missing Update proposal {staged_proposal_id}"
                ))
            })?;
        if staged_update.status != ScheduledUpdateStatus::Scheduled
            || staged_update.version <= activating.version
        {
            tee_registry
                .discard_staged_successor_policy_v1(staged_proposal_id)
                .map_err(|err| fatal_tee_policy_activation(err, staged_proposal_id))?;
        }
        Ok(())
    }

    fn reconcile_staged_ocomp_successor(
        &mut self,
        ctx: &BlockRuntimeContext,
        activating: &crate::state::ScheduledUpdateInfo,
    ) -> Result<()> {
        let mut registry = OcompRegistry::new(self.storage.clone());
        let Some((staged_proposal_id, _)) = registry.staged_successor(&poc_schema_limits())? else {
            return Ok(());
        };
        if staged_proposal_id == activating.proposal_id {
            return registry.promote_staged_successor(
                staged_proposal_id,
                ctx.block.block_number,
                &poc_schema_limits(),
            );
        }
        let staged_update = self
            .read_scheduled_update(staged_proposal_id)?
            .ok_or_else(|| {
                PrecompileError::Fatal(format!(
                "staged OCOMP successor references missing Update proposal {staged_proposal_id}"
            ))
            })?;
        if staged_update.status != ScheduledUpdateStatus::Scheduled
            || staged_update.version <= activating.version
        {
            registry.discard_staged_successor(staged_proposal_id)?;
        }
        Ok(())
    }

    fn cancel_scheduled_update(&mut self, proposal_id: U256) -> Result<()> {
        let scheduled = self
            .read_scheduled_update(proposal_id)?
            .ok_or(UpdateError::ScheduledUpdateNotFound)?;
        if scheduled.status != ScheduledUpdateStatus::Scheduled {
            return Ok(());
        }

        self.set_scheduled_update_status(proposal_id, ScheduledUpdateStatus::Canceled)?;
        self.emit(IUpdate::UpgradeCanceled {
            proposalId: proposal_id,
            version: scheduled.version.raw(),
            activationHeight: scheduled.activation_height,
        })
    }

    fn cancel_outdated_waiting_updates(
        &mut self,
        active_version: crate::ProtocolVersion,
    ) -> Result<()> {
        let waiting_ids = self.list_waiting_for_activation_proposal_ids()?;
        for proposal_id in waiting_ids {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                continue;
            };
            if scheduled.status == ScheduledUpdateStatus::Scheduled
                && scheduled.version <= active_version
            {
                self.cancel_scheduled_update(proposal_id)?;
            }
        }
        Ok(())
    }

    fn scheduled_activation_conflict(&self, activation_height: u64) -> Result<bool> {
        for proposal_id in self.list_waiting_for_activation_proposal_ids()? {
            let Some(scheduled) = self.read_scheduled_update(proposal_id)? else {
                continue;
            };
            if scheduled.status == ScheduledUpdateStatus::Scheduled
                && scheduled.activation_height == activation_height
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn fatal_tee_policy_activation(err: PrecompileError, proposal_id: U256) -> PrecompileError {
    match err {
        PrecompileError::Fatal(message) => PrecompileError::Fatal(message),
        other => PrecompileError::Fatal(format!(
            "TEE policy activation for Update proposal {proposal_id} failed: {other}"
        )),
    }
}
