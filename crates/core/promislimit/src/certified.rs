//! Certified OCOMP carry-over credit boundary for PromisLimit.

use alloy_primitives::U256;
use alloy_sol_types::SolEvent;
use outbe_ocomp_protocol::{
    receipts::{
        carry_over_state_event_digest, CarryOverReceiptV1, CarryOverStateEventProjectionV1,
        EffectBindingV1,
    },
    SchemaLimits,
};
use outbe_primitives::{
    addresses::PROMIS_LIMIT_ADDRESS,
    error::{PrecompileError, Result},
    storage::{CertifiedLysisActivation, StorageHandle},
};

use crate::{precompile::IPromisLimit, PromisLimitContract};

/// Closed, constant-size PromisLimit owner input derived from a verified Lysis
/// apply plan. Raw values do not grant mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedCarryOverCreditV1 {
    pub binding: EffectBindingV1,
    pub source_wwd: u32,
    pub lysis_budget: U256,
    pub nod_gratis_consumed: U256,
    pub unused_lysis: U256,
}

/// Adds the exact certified unused-Lysis amount to the live carry-over
/// accumulator and returns the canonical owner receipt.
///
/// The method is Rust-visible for the Metadosis activation coordinator, but
/// unreachable from ABI dispatch and cannot succeed without the private
/// execution-frame capability.
pub fn credit_certified_carry_over(
    storage: &StorageHandle<'_>,
    capability: &mut CertifiedLysisActivation<'_>,
    input: &CertifiedCarryOverCreditV1,
    limits: &SchemaLimits,
) -> Result<CarryOverReceiptV1> {
    validate_input(capability, input)?;

    storage.with_checkpoint(|| {
        let mut promis_limit = PromisLimitContract::new(storage.clone());
        let credit = promis_limit.checked_add_carry_over(input.unused_lysis)?;
        let state_projection = CarryOverStateEventProjectionV1 {
            source_wwd: input.source_wwd,
            before_value: credit.before,
            credited_unused_lysis: credit.credited,
            after_value: credit.after,
        };
        let state_event_digest =
            carry_over_state_event_digest(&input.binding, &state_projection, limits)
                .map_err(protocol_error)?;
        let receipt = CarryOverReceiptV1 {
            binding: input.binding.clone(),
            source_wwd: input.source_wwd,
            before_value: credit.before,
            credited_unused_lysis: credit.credited,
            after_value: credit.after,
            state_event_digest,
        };
        receipt
            .validate_projection(&state_projection, limits)
            .map_err(protocol_error)?;
        receipt.receipt_hash(limits).map_err(protocol_error)?;

        storage.emit_event(
            PROMIS_LIMIT_ADDRESS,
            IPromisLimit::CertifiedCarryOverCredited {
                activationCallId: input.binding.activation_call_id,
                sourceWorldwideDay: input.source_wwd,
                beforeValue: credit.before,
                creditedUnusedLysis: credit.credited,
                afterValue: credit.after,
                stateEventDigest: state_event_digest,
            }
            .encode_log_data(),
        )?;
        // The cursor is not journaled. Advance only after the accumulator and
        // event both succeed, so a caught failure cannot skip this owner.
        capability.authorize_carry_over_credit()?;
        Ok(receipt)
    })
}

fn validate_input(
    capability: &CertifiedLysisActivation<'_>,
    input: &CertifiedCarryOverCreditV1,
) -> Result<()> {
    if capability.activation_call_id() != input.binding.activation_call_id {
        return Err(revert("certified carry-over activation binding mismatch"));
    }
    if input.nod_gratis_consumed.checked_add(input.unused_lysis) != Some(input.lysis_budget) {
        return Err(revert("invalid certified carry-over budget conservation"));
    }
    Ok(())
}

fn protocol_error(error: impl std::fmt::Display) -> PrecompileError {
    PrecompileError::Fatal(format!(
        "invalid certified carry-over protocol value: {error}"
    ))
}

fn revert(reason: &'static str) -> PrecompileError {
    PrecompileError::Revert(reason.into())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, LogData, B256, U256};
    use alloy_sol_types::SolEvent;
    use outbe_ocomp_protocol::profile::poc_schema_limits;
    use outbe_primitives::{
        error::{PrecompileError, Result},
        storage::{
            hashmap::HashMapStorageProvider, PrecompileStorageProvider, StorageHandle,
            SubCallError, SubCallInput, SubCallOutput,
        },
    };
    use revm::{
        context::journaled_state::JournalCheckpoint,
        state::{AccountInfo, Bytecode},
    };

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

    use crate::{precompile::IPromisLimit, PromisLimitContract};

    use super::*;

    fn input(call: u8, consumed: u64, unused: u64) -> CertifiedCarryOverCreditV1 {
        CertifiedCarryOverCreditV1 {
            binding: EffectBindingV1 {
                intent_id: B256::repeat_byte(1),
                job_id: B256::repeat_byte(2),
                attempt: 3,
                protocol_bundle_hash: B256::repeat_byte(4),
                result_digest: B256::repeat_byte(5),
                activation_preconditions_hash: B256::repeat_byte(6),
                activation_call_id: B256::repeat_byte(call),
            },
            source_wwd: 20_260_725,
            lysis_budget: U256::from(consumed + unused),
            nod_gratis_consumed: U256::from(consumed),
            unused_lysis: U256::from(unused),
        }
    }

    fn run(
        provider: &mut ActivationTestProvider,
        input: &CertifiedCarryOverCreditV1,
    ) -> Result<CarryOverReceiptV1> {
        run_at_call(provider, input.binding.activation_call_id, input)
    }

    fn run_at_call(
        provider: &mut ActivationTestProvider,
        activation_call_id: B256,
        input: &CertifiedCarryOverCreditV1,
    ) -> Result<CarryOverReceiptV1> {
        StorageHandle::enter(provider, |storage| {
            storage.with_lysis_activation_frame(activation_call_id, |capability| {
                capability.authorize_nod_installation()?;
                capability.authorize_contributor_installation()?;
                let receipt =
                    credit_certified_carry_over(&storage, capability, input, &poc_schema_limits())?;
                capability.authorize_tribute_retirement()?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
    }

    fn seed(provider: &mut ActivationTestProvider, value: U256) {
        StorageHandle::enter(provider, |storage| {
            PromisLimitContract::new(storage)
                .checked_add_carry_over(value)
                .unwrap();
        });
    }

    fn current(provider: &mut ActivationTestProvider) -> U256 {
        StorageHandle::enter(provider, |storage| {
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap()
        })
    }

    #[test]
    fn certified_credit_adds_unused_lysis_to_actual_current_value() {
        let input = input(31, 8, 2);
        let mut provider = ActivationTestProvider::new();
        seed(&mut provider, U256::from(40));
        let receipt = run(&mut provider, &input).unwrap();

        assert_eq!(receipt.source_wwd, input.source_wwd);
        assert_eq!(receipt.before_value, U256::from(40));
        assert_eq!(receipt.credited_unused_lysis, U256::from(2));
        assert_eq!(receipt.after_value, U256::from(42));
        assert_eq!(current(&mut provider), U256::from(42));
        let expected_projection = CarryOverStateEventProjectionV1 {
            source_wwd: input.source_wwd,
            before_value: U256::from(40),
            credited_unused_lysis: U256::from(2),
            after_value: U256::from(42),
        };
        assert_eq!(
            receipt.state_event_digest,
            carry_over_state_event_digest(
                &input.binding,
                &expected_projection,
                &poc_schema_limits()
            )
            .unwrap()
        );

        let events = provider.inner.get_ordered_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].address, PROMIS_LIMIT_ADDRESS);
        let event = IPromisLimit::CertifiedCarryOverCredited::decode_log(&events[0]).unwrap();
        assert_eq!(
            event.data.activationCallId,
            input.binding.activation_call_id
        );
        assert_eq!(event.data.sourceWorldwideDay, input.source_wwd);
        assert_eq!(event.data.beforeValue, U256::from(40));
        assert_eq!(event.data.creditedUnusedLysis, U256::from(2));
        assert_eq!(event.data.afterValue, U256::from(42));
        assert_eq!(event.data.stateEventDigest, receipt.state_event_digest);
        assert!(!receipt
            .receipt_hash(&poc_schema_limits())
            .unwrap()
            .is_zero());
    }

    #[test]
    fn zero_unused_lysis_preserves_the_accumulator_and_returns_exact_receipt() {
        let input = input(32, 10, 0);
        let mut provider = ActivationTestProvider::new();
        seed(&mut provider, U256::from(17));

        let receipt = run(&mut provider, &input).unwrap();

        assert_eq!(receipt.before_value, U256::from(17));
        assert_eq!(receipt.credited_unused_lysis, U256::ZERO);
        assert_eq!(receipt.after_value, U256::from(17));
        assert_eq!(current(&mut provider), U256::from(17));
        assert_eq!(provider.inner.get_ordered_events().len(), 1);
    }

    #[test]
    fn wrong_binding_or_budget_conservation_is_side_effect_free() {
        let expected = input(33, 8, 2);

        let mut wrong_binding = ActivationTestProvider::new();
        seed(&mut wrong_binding, U256::from(9));
        assert!(run_at_call(&mut wrong_binding, B256::repeat_byte(99), &expected).is_err());
        assert_eq!(current(&mut wrong_binding), U256::from(9));
        assert!(wrong_binding.inner.get_ordered_events().is_empty());

        let mut wrong_budget_input = expected.clone();
        wrong_budget_input.lysis_budget += U256::from(1);
        let mut wrong_budget = ActivationTestProvider::new();
        seed(&mut wrong_budget, U256::from(9));
        assert!(run(&mut wrong_budget, &wrong_budget_input).is_err());
        assert_eq!(current(&mut wrong_budget), U256::from(9));
        assert!(wrong_budget.inner.get_ordered_events().is_empty());

        let mut overflowing_split_input = expected;
        overflowing_split_input.nod_gratis_consumed = U256::MAX;
        overflowing_split_input.unused_lysis = U256::from(1);
        overflowing_split_input.lysis_budget = U256::ZERO;
        let mut overflowing_split = ActivationTestProvider::new();
        seed(&mut overflowing_split, U256::from(9));
        assert!(run(&mut overflowing_split, &overflowing_split_input).is_err());
        assert_eq!(current(&mut overflowing_split), U256::from(9));
        assert!(overflowing_split.inner.get_ordered_events().is_empty());
    }

    #[test]
    fn accumulator_overflow_rolls_back_without_receipt_event() {
        let input = input(34, 8, 2);
        let mut provider = ActivationTestProvider::new();
        let before = U256::MAX - U256::from(1);
        seed(&mut provider, before);

        assert!(run(&mut provider, &input).is_err());

        assert_eq!(current(&mut provider), before);
        assert!(provider.inner.get_ordered_events().is_empty());
    }

    #[test]
    fn every_storage_and_event_failure_rolls_back_and_allows_exact_retry() {
        let input = input(35, 8, 2);
        let mut probe = ActivationTestProvider::new();
        seed(&mut probe, U256::from(40));
        probe.inner.fail_after_mutation_at(usize::MAX);
        run(&mut probe, &input).unwrap();
        let mutation_count = probe.inner.clear_mutation_failure();
        assert_eq!(
            mutation_count, 2,
            "certified credit must perform one accumulator write and one event"
        );

        for operation in 0..mutation_count {
            let mut provider = ActivationTestProvider::new();
            seed(&mut provider, U256::from(40));
            let before_storage = provider.inner.storage.clone();
            provider.inner.fail_after_mutation_at(operation);

            assert!(run(&mut provider, &input).is_err());
            assert_eq!(provider.inner.clear_mutation_failure(), operation + 1);
            assert_eq!(provider.inner.storage, before_storage);
            assert_eq!(current(&mut provider), U256::from(40));
            assert!(provider.inner.get_ordered_events().is_empty());

            let receipt = run(&mut provider, &input).unwrap();
            assert_eq!(receipt.before_value, U256::from(40));
            assert_eq!(receipt.after_value, U256::from(42));
            assert_eq!(provider.inner.get_ordered_events().len(), 1);
        }
    }

    #[test]
    fn caught_failure_or_wrong_phase_cannot_skip_the_carry_over_cursor() {
        let input = input(36, 8, 2);
        let mut late_failure = ActivationTestProvider::new();
        seed(&mut late_failure, U256::from(40));
        late_failure.inner.fail_after_mutation_at(1);
        let receipt = StorageHandle::enter(&mut late_failure, |storage| {
            storage.with_lysis_activation_frame(input.binding.activation_call_id, |capability| {
                capability.authorize_nod_installation()?;
                capability.authorize_contributor_installation()?;
                assert!(credit_certified_carry_over(
                    &storage,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )
                .is_err());
                let receipt = credit_certified_carry_over(
                    &storage,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )?;
                capability.authorize_tribute_retirement()?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
        .unwrap();
        late_failure.inner.clear_mutation_failure();
        assert_eq!(receipt.before_value, U256::from(40));
        assert_eq!(current(&mut late_failure), U256::from(42));
        assert_eq!(late_failure.inner.get_ordered_events().len(), 1);

        let mut wrong_phase = ActivationTestProvider::new();
        seed(&mut wrong_phase, U256::from(40));
        let receipt = StorageHandle::enter(&mut wrong_phase, |storage| {
            storage.with_lysis_activation_frame(input.binding.activation_call_id, |capability| {
                capability.authorize_nod_installation()?;
                capability.authorize_contributor_installation()?;
                assert!(capability.authorize_tribute_retirement().is_err());
                let receipt = credit_certified_carry_over(
                    &storage,
                    capability,
                    &input,
                    &poc_schema_limits(),
                )?;
                capability.authorize_tribute_retirement()?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
        .unwrap();
        assert_eq!(receipt.before_value, U256::from(40));
        assert_eq!(current(&mut wrong_phase), U256::from(42));
        assert_eq!(wrong_phase.inner.get_ordered_events().len(), 1);
    }
}
