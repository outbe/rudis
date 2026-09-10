use outbe_ocomp_protocol::{intent::PreAdmissionEnvelopeV1, SchemaLimits};
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::schema::{MetadosisContract, WorldwideDayEntryExt};
use crate::{aggregate::WwdStatus, errors::storage_corruption_message};

use super::state::{JobFsmCommand, JobFsmState};

pub(crate) use super::authority::require_active_ocomp_profile;
use super::codec::{max_canonical_object_bytes, read_canonical_optional};
#[cfg(test)]
pub(crate) use super::index::ResponseDeadlineKey;
use super::index::{insert_ready_key, remove_ready_key};
pub(crate) use super::index::{remove_response_deadline_key, ReadyIndexKey};
pub use super::profile::{poc_schema_limits, OcompRequestProfile};

impl MetadosisContract<'_> {
    /// Inserts one bounded ordered READY key without scanning active
    /// WorldwideDays. Repeating the exact enqueue is idempotent.
    pub(crate) fn enqueue_ocomp_ready(
        &mut self,
        wwd: WorldwideDay,
        next_check_height: u64,
    ) -> Result<()> {
        (|| {
            let status_value =
                WwdStatus::try_from(self.worldwide_days.entry(wwd).status().read()?)?;
            if status_value != WwdStatus::Ready {
                return Err(storage_corruption_message(format!(
                    "cannot enqueue OCOMP WWD {wwd} from status {status_value:?}"
                )));
            }
            if self.ocomp_fsm_states.get_bytes(&wwd).is_empty()? {
                let state = JobFsmState::initial_ready(wwd, next_check_height);
                state
                    .validate()
                    .map_err(|error| storage_corruption_message(error.to_string()))?;
                let key = ReadyIndexKey::from_projection(state.projection())?;
                let mut index = self.read_ready_index()?;
                insert_ready_key(&mut index, key)?;
                self.write_ocomp_state(&state)?;
                return self.write_ready_index(&index);
            }

            let existing = self.ocomp_fsm_state(wwd, &poc_schema_limits())?;
            let projection = existing.projection();
            if projection.phase != super::state::DayPhase::Ready {
                return Err(storage_corruption_message(
                    "cannot enqueue a WWD while its OCOMP intent is live",
                ));
            }
            let key = ReadyIndexKey::from_projection(projection)?;
            if key.next_check_height != next_check_height {
                return Err(storage_corruption_message(
                    "idempotent OCOMP enqueue changed the due height",
                ));
            }
            if self.read_ready_index()?.binary_search(&key).is_err() {
                return Err(storage_corruption_message(
                    "OCOMP READY state has no exact due-index key",
                ));
            }
            Ok(())
        })()
    }

    /// Moves only the READY due key after a deterministic deferred admission.
    pub(crate) fn defer_ocomp_ready(
        &mut self,
        wwd: WorldwideDay,
        at_height: u64,
        next_check_height: u64,
        schema_limits: &SchemaLimits,
    ) -> Result<()> {
        (|| {
            let mut state = self.ocomp_fsm_state(wwd, schema_limits)?;
            let old_key = ReadyIndexKey::from_projection(state.projection())?;
            state
                .apply(JobFsmCommand::Defer {
                    at_height,
                    next_check_height,
                })
                .map_err(|error| storage_corruption_message(error.to_string()))?;
            let new_key = ReadyIndexKey::from_projection(state.projection())?;
            let mut index = self.read_ready_index()?;
            remove_ready_key(&mut index, old_key)?;
            insert_ready_key(&mut index, new_key)?;
            self.write_ocomp_state(&state)?;
            self.write_ready_index(&index)
        })()
    }

    /// Returns only the first exact READY key in canonical due order.
    ///
    /// Terminal request processing calls this once per block; it never scans
    /// the active WorldwideDay set.
    pub(crate) fn next_ocomp_ready(
        &self,
        schema_limits: &SchemaLimits,
    ) -> Result<Option<super::state::JobFsmProjection>> {
        let Some(key) = self.read_ready_index()?.first().copied() else {
            return Ok(None);
        };
        let projection = self
            .ocomp_fsm_state(key.worldwide_day, schema_limits)?
            .projection();
        if ReadyIndexKey::from_projection(projection)? != key {
            return Err(storage_corruption_message(
                "OCOMP READY index/FSM key mismatch",
            ));
        }
        Ok(Some(projection))
    }

    /// Commits the exact owner-projection envelope once and retains its
    /// canonical bytes for finalized job reconstruction. An exact retry is
    /// idempotent; any different envelope is invariant corruption.
    pub(crate) fn commit_pre_admission_envelope(
        &mut self,
        wwd: WorldwideDay,
        envelope: &PreAdmissionEnvelopeV1,
        limits: &SchemaLimits,
    ) -> Result<crate::MetadosisPreAdmissionProjection> {
        (|| {
            let encoded = envelope.encode_canonical(limits).map_err(|error| {
                storage_corruption_message(format!("encode OCOMP pre-admission envelope: {error}"))
            })?;
            let expected_hash = envelope.envelope_hash(limits).map_err(|error| {
                storage_corruption_message(format!("hash OCOMP pre-admission envelope: {error}"))
            })?;
            let existing = self.read_pre_admission_envelope(wwd, limits)?;
            let projection = self.ocomp_pre_admission_projection(wwd)?;

            match (existing, projection.envelope_hash.is_zero()) {
                (None, true) => {
                    let sealed = self.seal_pre_admission_envelope(wwd, envelope, limits)?;
                    if sealed.envelope_hash != expected_hash {
                        return Err(storage_corruption_message(
                            "OCOMP pre-admission seal/hash mismatch",
                        ));
                    }
                    self.ocomp_pre_admission_envelopes
                        .get_bytes(&wwd)
                        .write(&encoded)?;
                    if self.read_pre_admission_envelope(wwd, limits)?.as_ref() != Some(envelope) {
                        return Err(storage_corruption_message(
                            "OCOMP pre-admission envelope write/read mismatch",
                        ));
                    }
                    Ok(sealed)
                }
                (Some(existing), false)
                    if existing == *envelope && projection.envelope_hash == expected_hash =>
                {
                    Ok(projection)
                }
                _ => Err(storage_corruption_message(
                    "immutable OCOMP pre-admission envelope changed",
                )),
            }
        })()
    }

    pub(crate) fn read_pre_admission_envelope(
        &self,
        wwd: WorldwideDay,
        limits: &SchemaLimits,
    ) -> Result<Option<PreAdmissionEnvelopeV1>> {
        let bytes = self.ocomp_pre_admission_envelopes.get_bytes(&wwd);
        read_canonical_optional(
            &bytes,
            max_canonical_object_bytes(limits)?,
            |encoded| PreAdmissionEnvelopeV1::decode_canonical(encoded, limits),
            "OCOMP pre-admission envelope",
        )
    }
}
