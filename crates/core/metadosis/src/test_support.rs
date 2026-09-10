//! Semantic, feature-gated scenarios for cross-crate Metadosis tests.
//!
//! This interface deliberately hides storage providers, execution scopes,
//! schema entries, and mutation permits. Raw setup remains an implementation
//! detail of the crate-private fixture kernel while actions under test cross a
//! production command seam.

use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_ocomp_protocol::{
    intent::JobIntentV1, receipts::ActivationOutcome, result::LysisResultV1, vote::ResultVoteV1,
    SchemaLimits,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{error::Result, storage::StorageHandle};
use std::fmt;

use crate::OcompForkInstallV1;

/// Seeds an exact retained READY population for cross-crate capacity tests.
///
/// The helper owns only predecessor construction. The capacity decision under
/// test must still enter through the production lifecycle command.
pub fn seed_ready_worldwide_days_for_capacity(
    storage: StorageHandle<'_>,
    worldwide_days: &[WorldwideDay],
) -> Result<()> {
    use crate::fixture_kernel::FixtureKernelExt;

    if worldwide_days.len() > crate::constants::MAX_RETAINED_WWDS {
        return Err(outbe_primitives::error::PrecompileError::Fatal(
            "capacity fixture exceeds MAX_RETAINED_WWDS".into(),
        ));
    }
    let mut contract = crate::schema::MetadosisContract::new(storage);
    for worldwide_day in worldwide_days {
        if !worldwide_day.is_valid() {
            return Err(outbe_primitives::error::PrecompileError::Fatal(
                "capacity fixture contains an invalid WorldwideDay".into(),
            ));
        }
        contract.fixture_create_ready_day(*worldwide_day, U256::ZERO, U256::ZERO, U256::ZERO)?;
        contract.add_active_wwd(*worldwide_day)?;
    }
    Ok(())
}

/// Test/evidence-only sentinel probe for a fresh-devnet genesis snapshot.
///
/// This is intentionally absent from the production API. The named sentinel
/// is checked across every per-day durable surface without exposing raw keys
/// or mutation access to the harness.
pub fn fresh_devnet_sentinel_is_pristine(
    storage: StorageHandle<'_>,
    sentinel_day: WorldwideDay,
) -> Result<bool> {
    let contract = crate::schema::MetadosisContract::new(storage.clone());
    Ok(crate::api::worldwide_days(storage.clone())?.is_empty()
        && contract.ocomp_scheduler.is_empty()?
        && contract.ocomp_ready_index.is_empty()?
        && contract.ocomp_response_deadline_index.is_empty()?
        && contract.terminal_intent_count(sentinel_day)? == 0
        && contract
            .ocomp_fsm_states
            .get_bytes(&sentinel_day)
            .is_empty()?
        && contract
            .ocomp_request_budget_receipts
            .get_bytes(&sentinel_day)
            .is_empty()?
        && contract
            .ocomp_pre_admission_envelopes
            .get_bytes(&sentinel_day)
            .is_empty()?
        && contract
            .ocomp_active_lysis_generations
            .get_bytes(&sentinel_day)
            .is_empty()?
        && contract
            .ocomp_job_records
            .get_bytes(&B256::ZERO)
            .is_empty()?
        && contract
            .ocomp_vote_accountability
            .get_bytes(&B256::ZERO)
            .is_empty()?
        && crate::api::missed_offering_receipt(storage.clone(), sentinel_day)?.is_none()
        && crate::api::capacity_forfeiture_receipt(storage.clone(), sentinel_day)?.is_none()
        && crate::api::day_limit_formation_receipt(storage, sentinel_day)?.is_none())
}

mod kernel {
    use alloy_primitives::{Address, Bytes, B256};
    use outbe_ocomp_protocol::{
        committee::OcompKeyRegistrationV1, intent::JobIntentV1, receipts::ActivationOutcome,
        result::LysisResultV1, vote::ResultVoteV1, SchemaLimits,
    };
    use outbe_primitives::time::WorldwideDay;
    use outbe_primitives::{
        error::{PrecompileError, Result},
        storage::{hashmap::HashMapStorageProvider, MetadosisMutationPurposeTag},
    };

    use crate::{
        aggregate::{ValidatedWwdAggregate, WwdMembership, WwdStatus},
        fixture_kernel::{
            fork_install_fixture, ActivationFixture, FixtureKernelExt, RollbackSnapshot,
        },
        ocomp::schema::poc_schema_limits,
        schema::MetadosisContract,
        OcompForkInstallClassification, OcompForkInstallV1,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) struct ActivationCheckpointState(RollbackSnapshot);

    pub(super) struct ActivationKernel {
        inner: ActivationFixture,
    }

    pub(super) struct EmergencyFailKernel {
        provider: HashMapStorageProvider,
        worldwide_day: WorldwideDay,
    }

    impl EmergencyFailKernel {
        pub(super) fn forming(
            worldwide_day: WorldwideDay,
            chain_id: u64,
            block_number: u64,
        ) -> Result<Self> {
            if !worldwide_day.is_valid() {
                return Err(PrecompileError::Revert(
                    "emergency fixture requires a valid WorldwideDay".into(),
                ));
            }
            let mut provider = HashMapStorageProvider::new(chain_id);
            provider.set_block_number(block_number);
            provider.enter(|storage| {
                let mut metadosis = MetadosisContract::new(storage);
                metadosis.create_worldwide_day(worldwide_day, 1, 1, 1)?;
                metadosis.add_active_wwd(worldwide_day)
            })?;
            Ok(Self {
                provider,
                worldwide_day,
            })
        }

        pub(super) fn fail(&mut self) -> Result<()> {
            self.provider
                .enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
            self.provider
                .enter(|storage| crate::commit::commit_emergency_fail(storage, self.worldwide_day))
        }

        pub(super) fn observation(&mut self) -> Result<(WwdStatus, WwdMembership)> {
            self.provider.enter(|storage| {
                let aggregate = ValidatedWwdAggregate::load_and_validate(storage)?;
                let projection = aggregate.record(self.worldwide_day).ok_or_else(|| {
                    PrecompileError::Fatal("emergency fixture WWD disappeared".into())
                })?;
                Ok((projection.status, projection.membership))
            })
        }
    }

    impl ActivationKernel {
        pub(super) fn q_forming_success(current_height: u64, current_time: u64) -> Self {
            Self {
                inner: ActivationFixture::new(current_height, current_time, true),
            }
        }

        pub(super) fn submit_q_forming_vote(&mut self) -> Result<Bytes> {
            self.inner.apply()
        }

        pub(super) fn corrupt_request_receipt_mismatch(&mut self) {
            self.inner.corrupt_request_receipt_mismatch();
        }

        pub(super) fn checkpoint(&mut self) -> ActivationCheckpointState {
            ActivationCheckpointState(self.inner.rollback_snapshot())
        }

        pub(super) fn terminal_outcome(&mut self) -> ActivationOutcome {
            self.inner.terminal_outcome()
        }
    }

    pub(super) fn fork_install(
        classification: OcompForkInstallClassification,
        activation_height: u64,
        chain_id: u64,
        genesis_hash: B256,
    ) -> Result<OcompForkInstallV1> {
        let install =
            fork_install_fixture(classification, activation_height, chain_id, genesis_hash);
        install.validate_for_chain(chain_id, genesis_hash, &poc_schema_limits())?;
        Ok(install)
    }

    pub(super) fn founder_registrations(
        validators: &[(Address, [u8; 48])],
        chain_id: u64,
        genesis_hash: B256,
    ) -> Result<Vec<OcompKeyRegistrationV1>> {
        crate::fixture_kernel::founder_registrations_for_validators(
            validators,
            chain_id,
            genesis_hash,
            &poc_schema_limits(),
        )
    }

    pub(super) fn result_for_intent(
        intent: &JobIntentV1,
        job_id: B256,
    ) -> (LysisResultV1, SchemaLimits) {
        let limits = poc_schema_limits();
        let result = crate::fixture_kernel::lysis_result_for_intent(intent, job_id, &limits);
        (result, limits)
    }

    pub(super) fn signed_vote(
        intent: &JobIntentV1,
        result: &LysisResultV1,
        validator_index: u8,
        limits: &SchemaLimits,
    ) -> ResultVoteV1 {
        crate::fixture_kernel::signed_result_vote_for_intent(
            intent,
            result,
            validator_index,
            limits,
        )
    }
}

/// Named invariant violations supported by the activation scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationCorruption {
    /// The persisted request-split receipt no longer matches the certified
    /// result binding.
    RequestReceiptMismatch,
}

/// Opaque equality snapshot of all journaled activation state.
#[derive(Clone, Eq, PartialEq)]
pub struct ActivationCheckpoint(kernel::ActivationCheckpointState);

impl fmt::Debug for ActivationCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ActivationCheckpoint")
            .field(&"<opaque>")
            .finish()
    }
}

/// Typed durable observation of the commit-owned emergency transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmergencyFailObservation {
    pub status: crate::WwdStatus,
    pub membership: crate::WwdMembership,
}

/// Opaque scenario for the broad, private emergency terminalization command.
pub struct EmergencyFailScenario {
    inner: kernel::EmergencyFailKernel,
}

impl EmergencyFailScenario {
    /// Creates one valid active FORMING predecessor without exposing storage.
    pub fn forming(worldwide_day: WorldwideDay, chain_id: u64, block_number: u64) -> Result<Self> {
        Ok(Self {
            inner: kernel::EmergencyFailKernel::forming(worldwide_day, chain_id, block_number)?,
        })
    }

    /// Executes the commit-owned production emergency command.
    pub fn fail(&mut self) -> Result<()> {
        self.inner.fail()
    }

    /// Reads only the typed outer status and membership after the command.
    pub fn observation(&mut self) -> Result<EmergencyFailObservation> {
        let (status, membership) = self.inner.observation()?;
        Ok(EmergencyFailObservation { status, membership })
    }
}

/// Opaque builder for one immutable, production-valid fork-install artifact.
pub struct ForkInstallScenario {
    install: OcompForkInstallV1,
}

impl ForkInstallScenario {
    /// Builds a production-valid final fork-install artifact.
    pub fn final_at(activation_height: u64, chain_id: u64, genesis_hash: B256) -> Result<Self> {
        Ok(Self {
            install: kernel::fork_install(
                crate::OcompForkInstallClassification::Final,
                activation_height,
                chain_id,
                genesis_hash,
            )?,
        })
    }

    /// Builds a production-valid measurement fork-install artifact.
    pub fn measurement_at(
        activation_height: u64,
        chain_id: u64,
        genesis_hash: B256,
    ) -> Result<Self> {
        Ok(Self {
            install: kernel::fork_install(
                crate::OcompForkInstallClassification::Measurement,
                activation_height,
                chain_id,
                genesis_hash,
            )?,
        })
    }

    /// Rebinds the test artifact to the exact ordered validator snapshot used
    /// by [`ResultVotingScenario`]. The registration keys and result-vote keys
    /// share one deterministic index mapping, so cross-crate fixtures exercise
    /// real signature verification rather than a bypass.
    pub fn with_founder_validators(mut self, validators: &[(Address, [u8; 48])]) -> Result<Self> {
        self.install.founder_registrations = kernel::founder_registrations(
            validators,
            self.install.request_profile.chain_id,
            self.install.request_profile.genesis_hash,
        )?;
        self.install.validate_for_chain(
            self.install.request_profile.chain_id,
            self.install.request_profile.genesis_hash,
            &crate::ocomp::schema::poc_schema_limits(),
        )?;
        Ok(self)
    }

    /// Borrows the immutable artifact consumed by production genesis/config
    /// adapters.
    #[must_use]
    pub const fn install(&self) -> &OcompForkInstallV1 {
        &self.install
    }

    /// Consumes the scenario into the immutable artifact.
    #[must_use]
    pub fn into_install(self) -> OcompForkInstallV1 {
        self.install
    }
}

/// Opaque deterministic result/vote material for a persisted production job.
pub struct ResultVotingScenario {
    intent: JobIntentV1,
    result: LysisResultV1,
    limits: SchemaLimits,
}

impl ResultVotingScenario {
    #[must_use]
    pub fn for_intent(intent: &JobIntentV1, job_id: B256) -> Self {
        let (result, limits) = kernel::result_for_intent(intent, job_id);
        Self {
            intent: intent.clone(),
            result,
            limits,
        }
    }

    #[must_use]
    pub const fn result(&self) -> &LysisResultV1 {
        &self.result
    }

    #[must_use]
    pub fn signed_vote(&self, validator_index: u8) -> ResultVoteV1 {
        kernel::signed_vote(&self.intent, &self.result, validator_index, &self.limits)
    }
}

/// Opaque q-forming activation scenario.
pub struct ActivationScenario {
    inner: kernel::ActivationKernel,
}

impl ActivationScenario {
    /// Creates a production-valid state in which the next result vote forms
    /// quorum and all certified owner effects can succeed.
    #[must_use]
    pub fn q_forming_success(current_height: u64, current_time: u64) -> Self {
        Self {
            inner: kernel::ActivationKernel::q_forming_success(current_height, current_time),
        }
    }

    /// Submits the q-forming vote through the production Metadosis command.
    pub fn submit_q_forming_vote(&mut self) -> Result<Bytes> {
        self.inner.submit_q_forming_vote()
    }

    /// Applies one explicitly named invalid precondition through the private
    /// fixture kernel.
    pub fn corrupt(&mut self, corruption: ActivationCorruption) {
        match corruption {
            ActivationCorruption::RequestReceiptMismatch => {
                self.inner.corrupt_request_receipt_mismatch();
            }
        }
    }

    /// Captures opaque journaled state for rollback and retry assertions.
    pub fn checkpoint(&mut self) -> ActivationCheckpoint {
        ActivationCheckpoint(self.inner.checkpoint())
    }

    /// Returns the durable typed terminal outcome after successful submission.
    pub fn terminal_outcome(&mut self) -> ActivationOutcome {
        self.inner.terminal_outcome()
    }
}
