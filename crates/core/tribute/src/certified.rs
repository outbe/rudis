//! Certified OCOMP consume and logical-retirement boundary for Tribute.
//!
//! The owner transition is constant-size: it authenticates the already sealed
//! collection aggregate, retires that CE collection, and advances one source
//! generation. It never traverses Tribute records or deletes projection bodies.

use alloy_primitives::{B256, U256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    partition_collection_key, ExecutionScope, PartitionRef, RetirementOutcome,
};
use outbe_ocomp_protocol::{
    intent::TributeInputBindingV1,
    receipts::{
        tribute_state_event_digest, EffectBindingV1, TributeReceiptV1,
        TributeStateEventProjectionV1,
    },
    SchemaLimits,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::TRIBUTE_ADDRESS,
    error::{PrecompileError, Result},
    storage::{CertifiedLysisActivation, StorageHandle},
};

use crate::{precompile::ITribute, TributeContract};

/// Closed, constant-size Tribute owner input derived from a verified Lysis
/// apply plan. Raw values do not grant mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedTributeRetirementV1 {
    pub binding: EffectBindingV1,
    pub input_binding: TributeInputBindingV1,
    pub consumed_count: u32,
    pub consumed_nominal_total: U256,
    pub retired_generation: u64,
}

/// Fully validated, mutation-free preparation for one certified retirement.
/// Its fields are private so only this module can authorize the apply step.
pub struct PreparedCertifiedTributeRetirementV1 {
    input: CertifiedTributeRetirementV1,
    receipt: TributeReceiptV1,
    day: WorldwideDay,
    state_event_digest: B256,
}

impl PreparedCertifiedTributeRetirementV1 {
    #[must_use]
    pub const fn receipt(&self) -> &TributeReceiptV1 {
        &self.receipt
    }
}

/// Validates the complete certified Tribute input and constructs its receipt
/// without mutating Tribute or compressed-entity state.
pub fn prepare_certified_partition_retirement(
    storage: &StorageHandle<'_>,
    capability: &CertifiedLysisActivation<'_>,
    input: &CertifiedTributeRetirementV1,
    limits: &SchemaLimits,
) -> Result<PreparedCertifiedTributeRetirementV1> {
    validate_input(capability, input)?;

    let day = WorldwideDay::new(input.input_binding.wwd);
    let partition = PartitionRef::TributeWwd(day);
    let (_, collection_key) =
        partition_collection_key(partition).map_err(|error| protocol_error(error.to_string()))?;
    if B256::from(*collection_key.as_bytes()) != input.input_binding.collection_key {
        return Err(revert("certified Tribute collection key mismatch"));
    }

    let tribute = TributeContract::new(storage.clone());
    let current = tribute.pre_admission_projection(day)?;
    if !current.profile_ready
        || !current.is_sealed
        || current.source_generation != input.input_binding.source_generation
        || current.sealed_collection_root != input.input_binding.sealed_collection_root
        || current.tribute_count != input.input_binding.exact_count
        || current.tribute_nominal_amount != input.input_binding.exact_nominal_total
    {
        return Err(revert(
            "certified Tribute input differs from the sealed generation",
        ));
    }
    if current.source_generation != 0 {
        return Err(revert("certified Tribute generation is already retired"));
    }

    let state_projection = TributeStateEventProjectionV1 {
        wwd: input.input_binding.wwd,
        source_generation: input.input_binding.source_generation,
        sealed_collection_root: input.input_binding.sealed_collection_root,
        consumed_count: input.consumed_count,
        consumed_nominal_total: input.consumed_nominal_total,
        retired_generation: input.retired_generation,
    };
    let state_event_digest = tribute_state_event_digest(&input.binding, &state_projection, limits)
        .map_err(|error| protocol_error(error.to_string()))?;
    let receipt = TributeReceiptV1 {
        binding: input.binding.clone(),
        tribute_input_binding: input.input_binding.clone(),
        sealed_collection_root: input.input_binding.sealed_collection_root,
        consumed_count: input.consumed_count,
        consumed_nominal_total: input.consumed_nominal_total,
        retired_generation: input.retired_generation,
        state_event_digest,
    };
    receipt
        .validate_projection(&state_projection, limits)
        .map_err(|error| protocol_error(error.to_string()))?;
    receipt
        .receipt_hash(limits)
        .map_err(|error| protocol_error(error.to_string()))?;

    Ok(PreparedCertifiedTributeRetirementV1 {
        input: input.clone(),
        receipt,
        day,
        state_event_digest,
    })
}

/// Consumes one exact sealed Tribute generation and requests its authenticated
/// CE collection retirement. Physical body retention/release remains node
/// owned and is deliberately outside this consensus transition.
pub fn retire_certified_partition(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    capability: &mut CertifiedLysisActivation<'_>,
    input: &CertifiedTributeRetirementV1,
    limits: &SchemaLimits,
) -> Result<TributeReceiptV1> {
    let prepared = prepare_certified_partition_retirement(storage, capability, input, limits)?;
    retire_prepared_certified_partition(storage, scope, capability, prepared)
}

/// Applies a previously validated retirement. Callers prepare and verify every
/// receipt gate before invoking this final compressed-entity owner mutation.
pub fn retire_prepared_certified_partition(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    capability: &mut CertifiedLysisActivation<'_>,
    prepared: PreparedCertifiedTributeRetirementV1,
) -> Result<TributeReceiptV1> {
    let PreparedCertifiedTributeRetirementV1 {
        input,
        receipt,
        day,
        state_event_digest,
    } = prepared;
    let mut tribute = TributeContract::new(storage.clone());

    storage.with_checkpoint(|| {
        tribute.consume_lysis_partition_inner(
            day,
            input.consumed_count,
            input.consumed_nominal_total,
        )?;
        if tribute.retire_completed_partition_inner(scope, day)? != RetirementOutcome::Requested {
            return Err(PrecompileError::Fatal(
                "sealed Tribute projection contradicts the authenticated CE generation".into(),
            ));
        }

        let mut admission = tribute
            .day_pre_admission
            .get(day)?
            .ok_or_else(|| revert("certified Tribute pre-admission record is absent"))?;
        if admission.source_generation != input.input_binding.source_generation {
            return Err(revert(
                "certified Tribute source generation changed during activation",
            ));
        }
        admission.source_generation = input.retired_generation;
        tribute.store_day_pre_admission(&admission)?;

        storage.emit_event(
            TRIBUTE_ADDRESS,
            ITribute::CertifiedTributePartitionRetired {
                activationCallId: input.binding.activation_call_id,
                worldwideDay: input.input_binding.wwd,
                sourceGeneration: input.input_binding.source_generation,
                sealedCollectionRoot: input.input_binding.sealed_collection_root,
                consumedCount: input.consumed_count,
                consumedNominalTotal: input.consumed_nominal_total,
                retiredGeneration: input.retired_generation,
                stateEventDigest: state_event_digest,
            }
            .encode_log_data(),
        )?;
        // The cursor is not journaled. Advance only after every consensus write
        // and event succeeds, so caught failures cannot skip the Tribute owner.
        capability.authorize_tribute_retirement()?;
        Ok(())
    })?;

    Ok(receipt)
}

fn validate_input(
    capability: &CertifiedLysisActivation<'_>,
    input: &CertifiedTributeRetirementV1,
) -> Result<()> {
    if capability.activation_call_id() != input.binding.activation_call_id {
        return Err(revert("certified Tribute activation binding mismatch"));
    }
    if input.input_binding.sealed_collection_root.is_zero()
        || input.input_binding.exact_count == 0
        || input.input_binding.source_generation != 0
        || input.consumed_count != input.input_binding.exact_count
        || input.consumed_nominal_total != input.input_binding.exact_nominal_total
        || input.retired_generation != 1
    {
        return Err(revert("invalid certified Tribute retirement aggregate"));
    }
    Ok(())
}

fn protocol_error(message: String) -> PrecompileError {
    PrecompileError::Fatal(format!(
        "invalid certified Tribute protocol value: {message}"
    ))
}

fn revert(reason: &'static str) -> PrecompileError {
    PrecompileError::Revert(reason.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::{Address, LogData};
    use alloy_sol_types::SolEvent;
    use outbe_compressed_entities::{
        begin_block, AuthenticatedParentTree, CeWorkConfig, EntityRef, FinalLeafMutation,
        ProvisionalTreeBatch,
    };
    use outbe_ocomp_protocol::profile::poc_schema_limits;
    use outbe_primitives::{
        addresses::COMPRESSED_ENTITIES_ADDRESS,
        storage::{
            hashmap::HashMapStorageProvider, PrecompileStorageProvider, SubCallError, SubCallInput,
            SubCallOutput,
        },
    };
    use revm::{
        context::journaled_state::JournalCheckpoint,
        state::{AccountInfo, Bytecode},
    };

    use crate::{DayPreAdmission, DayTotals};

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum ParentMode {
        Present,
        Absent,
        Failure,
    }

    #[derive(Debug)]
    struct PartitionTree {
        parent_root: B256,
        mode: ParentMode,
    }

    impl AuthenticatedParentTree for PartitionTree {
        fn parent_block_hash(&self) -> B256 {
            B256::repeat_byte(90)
        }

        fn parent_root(&self) -> B256 {
            self.parent_root
        }

        fn read_leaf_verified(
            &self,
            _entity: EntityRef,
            _expected_parent_root: B256,
        ) -> Result<Option<outbe_compressed_entities::Commitment>> {
            Ok(None)
        }

        fn partition_present_verified(
            &self,
            partition: PartitionRef,
            expected_parent_root: B256,
        ) -> Result<bool> {
            if expected_parent_root != self.parent_root
                || partition != PartitionRef::TributeWwd(WorldwideDay::new(20_260_725))
            {
                return Err(PrecompileError::Fatal(
                    "test parent partition binding mismatch".into(),
                ));
            }
            match self.mode {
                ParentMode::Present => Ok(true),
                ParentMode::Absent => Ok(false),
                ParentMode::Failure => Err(PrecompileError::Fatal(
                    "injected authenticated CE retirement failure".into(),
                )),
            }
        }

        fn prepare_seal(
            &self,
            _block_number: u64,
            _mutations: &[FinalLeafMutation],
            _retirements: &[PartitionRef],
        ) -> Result<ProvisionalTreeBatch> {
            Err(PrecompileError::Fatal(
                "test does not seal the synthetic parent".into(),
            ))
        }
    }

    struct ActivationTestProvider {
        inner: HashMapStorageProvider,
        active_call: Option<B256>,
    }

    impl ActivationTestProvider {
        fn new() -> Self {
            Self {
                inner: HashMapStorageProvider::new(1),
                active_call: None,
            }
        }
    }

    impl PrecompileStorageProvider for ActivationTestProvider {
        fn begin_lysis_activation_frame(&mut self, activation_call_id: B256) -> Result<()> {
            if self.active_call.replace(activation_call_id).is_some() {
                return Err(PrecompileError::Fatal(
                    "test activation lease is already active".into(),
                ));
            }
            Ok(())
        }

        fn finish_lysis_activation_frame(
            &mut self,
            activation_call_id: B256,
            _completed: bool,
        ) -> Result<()> {
            if self.active_call.take() != Some(activation_call_id) {
                return Err(PrecompileError::Fatal(
                    "test activation lease identity mismatch".into(),
                ));
            }
            Ok(())
        }

        fn chain_id(&self) -> u64 {
            self.inner.chain_id()
        }

        fn genesis_hash(&self) -> B256 {
            self.inner.genesis_hash()
        }

        fn timestamp(&self) -> U256 {
            self.inner.timestamp()
        }

        fn set_block_timestamp(&mut self, timestamp: U256) {
            self.inner.set_block_timestamp(timestamp);
        }

        fn beneficiary(&self) -> Address {
            self.inner.beneficiary()
        }

        fn block_number(&self) -> u64 {
            self.inner.block_number()
        }

        fn canonical_block_hash(&mut self, number: u64) -> Result<Option<B256>> {
            self.inner.canonical_block_hash(number)
        }

        fn set_code(&mut self, address: Address, code: Bytecode) -> Result<()> {
            self.inner.set_code(address, code)
        }

        fn account_info(&mut self, address: Address) -> Result<AccountInfo> {
            self.inner.account_info(address)
        }

        fn sload(&mut self, address: Address, key: U256) -> Result<U256> {
            self.inner.sload(address, key)
        }

        fn tload(&mut self, address: Address, key: U256) -> Result<U256> {
            self.inner.tload(address, key)
        }

        fn sstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
            self.inner.sstore(address, key, value)
        }

        fn tstore(&mut self, address: Address, key: U256, value: U256) -> Result<()> {
            self.inner.tstore(address, key, value)
        }

        fn emit_event(&mut self, address: Address, event: LogData) -> Result<()> {
            self.inner.emit_event(address, event)
        }

        fn deduct_gas(&mut self, gas: u64) -> Result<()> {
            self.inner.deduct_gas(gas)
        }

        fn refund_gas(&mut self, gas: i64) {
            self.inner.refund_gas(gas);
        }

        fn gas_used(&self) -> u64 {
            self.inner.gas_used()
        }

        fn gas_refunded(&self) -> i64 {
            self.inner.gas_refunded()
        }

        fn is_static(&self) -> bool {
            self.inner.is_static()
        }

        fn checkpoint(&mut self) -> JournalCheckpoint {
            self.inner.checkpoint()
        }

        fn checkpoint_commit(&mut self) {
            self.inner.checkpoint_commit();
        }

        fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
            self.inner.checkpoint_revert(checkpoint);
        }

        fn transfer_balance(&mut self, from: Address, to: Address, amount: U256) -> Result<()> {
            self.inner.transfer_balance(from, to, amount)
        }

        fn increase_balance(&mut self, address: Address, amount: U256) -> Result<()> {
            self.inner.increase_balance(address, amount)
        }

        fn decrease_balance(&mut self, address: Address, amount: U256) -> Result<()> {
            self.inner.decrease_balance(address, amount)
        }

        fn sub_call(
            &mut self,
            input: SubCallInput,
        ) -> std::result::Result<SubCallOutput, SubCallError> {
            self.inner.sub_call(input)
        }
    }

    struct Fixture {
        provider: ActivationTestProvider,
        scope: ExecutionScope,
    }

    impl Fixture {
        fn new(expected: &CertifiedTributeRetirementV1, mode: ParentMode) -> Self {
            let parent_root = B256::repeat_byte(80);
            let scope = ExecutionScope::with_parent_tree(
                Arc::new(PartitionTree { parent_root, mode }),
                CeWorkConfig::new(0, 0, u64::MAX),
            );
            let mut provider = ActivationTestProvider::new();
            StorageHandle::enter(&mut provider, |storage| {
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
                begin_block(storage.clone(), &scope).unwrap();

                let day = WorldwideDay::new(expected.input_binding.wwd);
                let mut tribute = TributeContract::new(storage);
                tribute.ocomp_profile_ready.write(true).unwrap();
                tribute
                    .total_supply
                    .write(u64::from(expected.input_binding.exact_count))
                    .unwrap();

                let mut totals = DayTotals::with_key(day);
                totals.initialized = true;
                totals.is_sealed = true;
                totals.tribute_count = expected.input_binding.exact_count;
                totals.tribute_nominal_amount = expected.input_binding.exact_nominal_total;
                tribute.store_day_totals(&totals).unwrap();

                let mut admission = DayPreAdmission::with_key(day);
                admission.initialized = true;
                admission.is_sealed = true;
                admission.sealed_collection_root = expected.input_binding.sealed_collection_root;
                admission.sealed_tribute_count = expected.input_binding.exact_count;
                admission.sealed_tribute_nominal_amount =
                    expected.input_binding.exact_nominal_total;
                admission.source_generation = expected.input_binding.source_generation;
                tribute.store_day_pre_admission(&admission).unwrap();
            });
            Self { provider, scope }
        }

        fn run(&mut self, input: &CertifiedTributeRetirementV1) -> Result<TributeReceiptV1> {
            StorageHandle::enter(&mut self.provider, |storage| {
                storage.with_lysis_activation_frame(
                    input.binding.activation_call_id,
                    |capability| {
                        capability.authorize_nod_installation()?;
                        capability.authorize_contributor_installation()?;
                        capability.authorize_carry_over_credit()?;
                        let receipt = retire_certified_partition(
                            &storage,
                            &self.scope,
                            capability,
                            input,
                            &poc_schema_limits(),
                        )?;
                        capability.authorize_terminal_receipt()?;
                        Ok(receipt)
                    },
                )
            })
        }

        fn state(&mut self, day: WorldwideDay) -> (u64, u32, U256, bool, u64) {
            StorageHandle::enter(&mut self.provider, |storage| {
                let tribute = TributeContract::new(storage);
                let generation = tribute
                    .pre_admission_projection(day)
                    .unwrap()
                    .source_generation;
                let totals = tribute.get_day_totals(day).unwrap();
                (
                    tribute.total_supply.read().unwrap(),
                    totals.tribute_count,
                    totals.tribute_nominal_amount,
                    totals.is_sealed,
                    generation,
                )
            })
        }
    }

    fn binding(call: u8) -> EffectBindingV1 {
        EffectBindingV1 {
            intent_id: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 3,
            protocol_bundle_hash: B256::repeat_byte(4),
            result_digest: B256::repeat_byte(5),
            activation_preconditions_hash: B256::repeat_byte(6),
            activation_call_id: B256::repeat_byte(call),
        }
    }

    fn input(call: u8) -> CertifiedTributeRetirementV1 {
        let day = WorldwideDay::new(20_260_725);
        let (_, collection_key) = partition_collection_key(PartitionRef::TributeWwd(day)).unwrap();
        CertifiedTributeRetirementV1 {
            binding: binding(call),
            input_binding: TributeInputBindingV1 {
                wwd: day.value(),
                source_generation: 0,
                collection_key: B256::from(*collection_key.as_bytes()),
                sealed_collection_root: B256::repeat_byte(31),
                exact_count: 3,
                exact_nominal_total: U256::from(900),
            },
            consumed_count: 3,
            consumed_nominal_total: U256::from(900),
            retired_generation: 1,
        }
    }

    #[test]
    fn valid_capability_consumes_exact_generation_and_emits_canonical_receipt() {
        let input = input(21);
        let mut fixture = Fixture::new(&input, ParentMode::Present);
        let receipt = fixture.run(&input).unwrap();

        let (supply, count, nominal, is_sealed, generation) =
            fixture.state(WorldwideDay::new(input.input_binding.wwd));
        assert_eq!(supply, 0);
        assert_eq!(count, 0);
        assert_eq!(nominal, U256::ZERO);
        assert!(is_sealed);
        assert_eq!(generation, 1);
        assert_eq!(receipt.tribute_input_binding, input.input_binding);
        assert_eq!(receipt.consumed_count, input.consumed_count);
        assert_eq!(receipt.consumed_nominal_total, input.consumed_nominal_total);
        assert_eq!(receipt.retired_generation, 1);
        assert!(!receipt
            .receipt_hash(&poc_schema_limits())
            .unwrap()
            .is_zero());

        let events = fixture.provider.inner.get_ordered_events();
        assert_eq!(events.len(), 2);
        ITribute::TributePartitionRetired::decode_log(&events[0]).unwrap();
        let certified = ITribute::CertifiedTributePartitionRetired::decode_log(&events[1]).unwrap();
        assert_eq!(
            certified.data.activationCallId,
            input.binding.activation_call_id
        );
        assert_eq!(certified.data.worldwideDay, input.input_binding.wwd);
        assert_eq!(certified.data.sourceGeneration, 0);
        assert_eq!(
            certified.data.sealedCollectionRoot,
            input.input_binding.sealed_collection_root
        );
        assert_eq!(certified.data.consumedCount, input.consumed_count);
        assert_eq!(
            certified.data.consumedNominalTotal,
            input.consumed_nominal_total
        );
        assert_eq!(certified.data.retiredGeneration, 1);
        assert_eq!(certified.data.stateEventDigest, receipt.state_event_digest);
    }

    #[test]
    fn wrong_root_count_nominal_or_generation_is_side_effect_free() {
        let expected = input(22);
        for mutation in 0..5 {
            let mut candidate = expected.clone();
            match mutation {
                0 => candidate.input_binding.sealed_collection_root = B256::repeat_byte(99),
                1 => {
                    candidate.input_binding.exact_count += 1;
                    candidate.consumed_count += 1;
                }
                2 => {
                    candidate.input_binding.exact_nominal_total += U256::from(1);
                    candidate.consumed_nominal_total += U256::from(1);
                }
                3 => {
                    candidate.input_binding.source_generation = 1;
                    candidate.retired_generation = 2;
                }
                4 => candidate.input_binding.collection_key = B256::repeat_byte(98),
                _ => unreachable!(),
            }
            let mut fixture = Fixture::new(&expected, ParentMode::Present);
            let before = fixture.state(WorldwideDay::new(expected.input_binding.wwd));
            assert!(fixture.run(&candidate).is_err());
            assert_eq!(
                fixture.state(WorldwideDay::new(expected.input_binding.wwd)),
                before
            );
            assert!(fixture.provider.inner.get_ordered_events().is_empty());
        }
    }

    #[test]
    fn ce_absence_or_failure_rolls_back_bulk_accounting_and_generation() {
        let input = input(23);
        for mode in [ParentMode::Absent, ParentMode::Failure] {
            let mut fixture = Fixture::new(&input, mode);
            let before = fixture.state(WorldwideDay::new(input.input_binding.wwd));
            assert!(fixture.run(&input).is_err());
            assert_eq!(
                fixture.state(WorldwideDay::new(input.input_binding.wwd)),
                before
            );
            assert!(fixture.provider.inner.get_ordered_events().is_empty());
        }
    }

    #[test]
    fn every_storage_and_event_failure_rolls_back_and_allows_exact_retry() {
        let input = input(24);
        let mut probe = Fixture::new(&input, ParentMode::Present);
        probe.provider.inner.fail_after_mutation_at(usize::MAX);
        probe.run(&input).unwrap();
        let mutation_count = probe.provider.inner.clear_mutation_failure();
        assert!(
            mutation_count >= 2,
            "certified retirement must include storage and event mutations"
        );

        for operation in 0..mutation_count {
            let mut fixture = Fixture::new(&input, ParentMode::Present);
            let day = WorldwideDay::new(input.input_binding.wwd);
            let before_state = fixture.state(day);
            let before_storage = fixture.provider.inner.storage.clone();
            fixture.provider.inner.fail_after_mutation_at(operation);

            assert!(fixture.run(&input).is_err());
            assert_eq!(
                fixture.provider.inner.clear_mutation_failure(),
                operation + 1
            );
            assert_eq!(fixture.state(day), before_state);
            assert_eq!(fixture.provider.inner.storage, before_storage);
            assert!(fixture.provider.inner.get_ordered_events().is_empty());

            let receipt = fixture.run(&input).unwrap();
            assert_eq!(receipt.consumed_count, input.consumed_count);
            assert_eq!(fixture.state(day).4, 1);
            assert_eq!(fixture.provider.inner.get_ordered_events().len(), 2);
        }
    }

    #[test]
    fn caught_late_failure_or_wrong_phase_cannot_skip_the_tribute_cursor() {
        let input = input(25);
        let mut probe = Fixture::new(&input, ParentMode::Present);
        probe.provider.inner.fail_after_mutation_at(usize::MAX);
        probe.run(&input).unwrap();
        let final_mutation = probe
            .provider
            .inner
            .clear_mutation_failure()
            .checked_sub(1)
            .expect("certified retirement must mutate state");

        let mut late_failure = Fixture::new(&input, ParentMode::Present);
        late_failure
            .provider
            .inner
            .fail_after_mutation_at(final_mutation);
        let receipt = StorageHandle::enter(&mut late_failure.provider, |storage| {
            storage.with_lysis_activation_frame(input.binding.activation_call_id, |capability| {
                capability.authorize_nod_installation()?;
                capability.authorize_contributor_installation()?;
                capability.authorize_carry_over_credit()?;
                assert!(retire_certified_partition(
                    &storage,
                    &late_failure.scope,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )
                .is_err());
                let receipt = retire_certified_partition(
                    &storage,
                    &late_failure.scope,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
        .unwrap();
        assert_eq!(receipt.consumed_count, input.consumed_count);
        assert_eq!(late_failure.provider.inner.get_ordered_events().len(), 2);

        let mut wrong_phase = Fixture::new(&input, ParentMode::Present);
        let receipt = StorageHandle::enter(&mut wrong_phase.provider, |storage| {
            storage.with_lysis_activation_frame(input.binding.activation_call_id, |capability| {
                capability.authorize_nod_installation()?;
                assert!(retire_certified_partition(
                    &storage,
                    &wrong_phase.scope,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )
                .is_err());
                capability.authorize_contributor_installation()?;
                capability.authorize_carry_over_credit()?;
                let receipt = retire_certified_partition(
                    &storage,
                    &wrong_phase.scope,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
        .unwrap();
        assert_eq!(receipt.consumed_count, input.consumed_count);
        assert_eq!(wrong_phase.provider.inner.get_ordered_events().len(), 2);
    }

    #[test]
    fn exact_retry_cannot_consume_or_retire_twice() {
        let input = input(26);
        let mut fixture = Fixture::new(&input, ParentMode::Present);
        fixture.run(&input).unwrap();
        let state = fixture.state(WorldwideDay::new(input.input_binding.wwd));
        let events = fixture.provider.inner.get_ordered_events().to_vec();

        assert!(fixture.run(&input).is_err());
        assert_eq!(
            fixture.state(WorldwideDay::new(input.input_binding.wwd)),
            state
        );
        assert_eq!(fixture.provider.inner.get_ordered_events(), events);
    }

    #[test]
    fn populated_postfork_partition_rejects_legacy_consume_and_retire() {
        let input = input(27);
        let mut fixture = Fixture::new(&input, ParentMode::Present);
        StorageHandle::enter(&mut fixture.provider, |storage| {
            let mut tribute = TributeContract::new(storage);
            assert!(tribute
                .consume_lysis_partition(
                    WorldwideDay::new(input.input_binding.wwd),
                    input.consumed_count,
                    input.consumed_nominal_total,
                )
                .is_err());
            assert!(tribute
                .retire_completed_partition(
                    &fixture.scope,
                    WorldwideDay::new(input.input_binding.wwd),
                )
                .is_err());
        });
        let (supply, count, nominal, is_sealed, generation) =
            fixture.state(WorldwideDay::new(input.input_binding.wwd));
        assert_eq!(supply, u64::from(input.input_binding.exact_count));
        assert_eq!(count, input.input_binding.exact_count);
        assert_eq!(nominal, input.input_binding.exact_nominal_total);
        assert!(is_sealed);
        assert_eq!(generation, 0);
        assert!(fixture.provider.inner.get_ordered_events().is_empty());
    }
}
