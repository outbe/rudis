//! Certified OCOMP contributor-root installation for Intex.
//!
//! Activation stores one constant-size proof authority. It never receives or
//! writes the contributor owner list and exposes no public write selector.

use alloy_primitives::{B256, U256};
use alloy_sol_types::SolEvent;
use outbe_ocomp_protocol::{
    intent::ContributorTargetPreconditionV1,
    receipts::{
        contributor_state_event_digest, ContributorReceiptV1, ContributorStateEventProjectionV1,
        EffectBindingV1,
    },
    SchemaLimits,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::INTEX_ADDRESS,
    error::{PrecompileError, Result},
    storage::{CertifiedLysisActivation, StorageHandle},
};

use crate::{
    api,
    precompile::IIntex,
    schema::{CertifiedContributorGenerationProjection, IntexContract},
};

/// Closed, constant-size contributor owner input derived from the verified
/// Lysis apply plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedContributorRootV1 {
    pub binding: EffectBindingV1,
    pub precondition: ContributorTargetPreconditionV1,
    pub contributor_root: B256,
    pub contributor_count: u32,
    pub eligible_nominal_total: U256,
}

/// Compare-and-set one certified contributor root without per-owner writes.
pub fn install_certified_contributor_root(
    storage: &StorageHandle<'_>,
    capability: &mut CertifiedLysisActivation<'_>,
    input: &CertifiedContributorRootV1,
    limits: &SchemaLimits,
) -> Result<ContributorReceiptV1> {
    validate_input(capability, input)?;

    let current = api::ocomp_contributor_target_projection(
        storage,
        WorldwideDay::new(input.precondition.worldwide_day),
    )?;
    if current.expected_series_version != input.precondition.expected_series_version {
        return Err(revert("certified contributor target version changed"));
    }
    if current.contributor_count != 0 || !current.contributor_total.is_zero() {
        return Err(revert("certified contributor target is not empty"));
    }

    let intex = IntexContract::new(storage.clone());
    if intex
        .ocomp_certified_contributor_generation(WorldwideDay::new(
            input.precondition.worldwide_day,
        ))?
        .is_some()
    {
        return Err(revert("certified contributor root cannot be overwritten"));
    }
    let next_version = current
        .expected_series_version
        .checked_add(1)
        .ok_or_else(|| revert("certified contributor series version overflow"))?;

    let state_projection = ContributorStateEventProjectionV1 {
        worldwide_day: input.precondition.worldwide_day,
        series_version_before: input.precondition.expected_series_version,
        series_version_after: next_version,
        contributor_count: input.contributor_count,
        contributor_root: input.contributor_root,
        eligible_nominal_total: input.eligible_nominal_total,
    };
    let state_event_digest =
        contributor_state_event_digest(&input.binding, &state_projection, limits)
            .map_err(protocol_error)?;
    let receipt = ContributorReceiptV1 {
        binding: input.binding.clone(),
        contributor_target_precondition: input.precondition.clone(),
        contributor_count: input.contributor_count,
        contributor_root: input.contributor_root,
        eligible_nominal_total: input.eligible_nominal_total,
        state_event_digest,
    };
    receipt
        .validate_projection(&state_projection, limits)
        .map_err(protocol_error)?;
    receipt.receipt_hash(limits).map_err(protocol_error)?;

    let installed = CertifiedContributorGenerationProjection {
        worldwide_day: input.precondition.worldwide_day,
        series_version: next_version,
        contributor_root: input.contributor_root,
        contributor_count: input.contributor_count,
        eligible_nominal_total: input.eligible_nominal_total,
    };
    storage.with_checkpoint(|| {
        intex.ocomp_contributor_root.write(
            &WorldwideDay::new(installed.worldwide_day),
            installed.contributor_root,
        )?;
        intex.ocomp_eligible_nominal_total.write(
            &WorldwideDay::new(installed.worldwide_day),
            installed.eligible_nominal_total,
        )?;
        // Metadata contains the version selector and switches only after the
        // root and total are durable.
        intex.ocomp_contributor_metadata.write(
            &WorldwideDay::new(installed.worldwide_day),
            installed.metadata_word(),
        )?;
        storage.emit_event(
            INTEX_ADDRESS,
            IIntex::CertifiedContributorRootInstalled {
                activationCallId: input.binding.activation_call_id,
                worldwideDay: input.precondition.worldwide_day,
                seriesVersionBefore: input.precondition.expected_series_version,
                seriesVersionAfter: next_version,
                contributorCount: input.contributor_count,
                contributorRoot: input.contributor_root,
                eligibleNominalTotal: input.eligible_nominal_total,
                stateEventDigest: state_event_digest,
            }
            .encode_log_data(),
        )?;
        // As with every owner step, advance the non-journaled cursor only after
        // all journaled state and event writes have succeeded.
        capability.authorize_contributor_installation()?;
        Ok(())
    })?;

    Ok(receipt)
}

fn validate_input(
    capability: &CertifiedLysisActivation<'_>,
    input: &CertifiedContributorRootV1,
) -> Result<()> {
    if capability.activation_call_id() != input.binding.activation_call_id {
        return Err(revert("certified contributor activation binding mismatch"));
    }
    if input.contributor_root.is_zero() {
        return Err(revert("certified contributor root is zero"));
    }
    if input.contributor_count > input.precondition.max_contributor_count
        || input.eligible_nominal_total > input.precondition.max_eligible_nominal_total
        || (input.contributor_count == 0) != input.eligible_nominal_total.is_zero()
    {
        return Err(revert("certified contributor aggregate exceeds its bound"));
    }
    Ok(())
}

fn protocol_error(error: outbe_ocomp_protocol::ProtocolError) -> PrecompileError {
    PrecompileError::Fatal(format!(
        "invalid certified contributor protocol value: {error}"
    ))
}

fn revert(reason: &'static str) -> PrecompileError {
    PrecompileError::Revert(reason.into())
}

#[cfg(test)]
mod tests {
    use crate::schema::SeriesId;
    use alloy_primitives::{Address, LogData};
    use alloy_sol_types::SolEvent;

    use outbe_ocomp_protocol::{
        profile::poc_schema_limits,
        receipts::{ContributorStateEventProjectionV1, EffectBindingV1},
        result::ContributorActionV1,
        ListKind, StreamingOrderedListRoot,
    };
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

    use super::*;

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

        fn run(&mut self, input: &CertifiedContributorRootV1) -> Result<ContributorReceiptV1> {
            StorageHandle::enter(self, |storage| {
                storage.with_lysis_activation_frame(
                    input.binding.activation_call_id,
                    |capability| {
                        capability.authorize_nod_installation()?;
                        let receipt = install_certified_contributor_root(
                            &storage,
                            capability,
                            input,
                            &poc_schema_limits(),
                        )?;
                        capability.authorize_carry_over_credit()?;
                        capability.authorize_tribute_retirement()?;
                        capability.authorize_terminal_receipt()?;
                        Ok(receipt)
                    },
                )
            })
        }

        fn generation(
            &mut self,
            series_id: u32,
        ) -> Option<CertifiedContributorGenerationProjection> {
            StorageHandle::enter(self, |storage| {
                api::certified_contributor_generation(&storage, WorldwideDay::new(series_id))
                    .unwrap()
            })
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

    fn binding(call: u8) -> EffectBindingV1 {
        EffectBindingV1 {
            intent_id: B256::repeat_byte(1),
            job_id: B256::repeat_byte(2),
            attempt: 0,
            protocol_bundle_hash: B256::repeat_byte(3),
            result_digest: B256::repeat_byte(4),
            activation_preconditions_hash: B256::repeat_byte(5),
            activation_call_id: B256::repeat_byte(call),
        }
    }

    /// Test ids carry a fixed USD/U pair; only the day varies.
    fn test_sid(worldwide_day: u32) -> SeriesId {
        SeriesId::pack(WorldwideDay::new(worldwide_day), *b"USD", b'U').unwrap()
    }

    fn input(worldwide_day: u32, call: u8) -> CertifiedContributorRootV1 {
        CertifiedContributorRootV1 {
            binding: binding(call),
            precondition: ContributorTargetPreconditionV1 {
                worldwide_day,
                expected_series_version: 0,
                max_contributor_count: 4,
                max_eligible_nominal_total: U256::from(100_000_000_u128),
            },
            contributor_root: B256::repeat_byte(31),
            contributor_count: 3,
            eligible_nominal_total: U256::from(75_000_000_u128),
        }
    }

    fn contributor(index: u32, nominal_amount_minor: u128) -> ContributorActionV1 {
        let mut owner = [0_u8; 20];
        owner[16..].copy_from_slice(&(index + 1).to_be_bytes());
        let mut source_tribute_id = [0_u8; 32];
        source_tribute_id[28..].copy_from_slice(&index.to_be_bytes());
        ContributorActionV1 {
            owner: Address::from(owner),
            source_tribute_id: B256::from(source_tribute_id),
            nominal_amount_minor: U256::from(nominal_amount_minor),
        }
    }

    fn contributor_root(records: &[ContributorActionV1]) -> B256 {
        let limits = poc_schema_limits();
        let mut root =
            StreamingOrderedListRoot::new(ListKind::ContributorActions, records.len() as u32)
                .unwrap();
        for record in records {
            root.push(
                &record.encode_canonical_record(&limits).unwrap(),
                limits.max_bounded_bytes,
            )
            .unwrap();
        }
        root.finish().unwrap()
    }

    #[test]
    fn mixed_exclusion_fixture_installs_only_eligible_contributor_commitment() {
        let eligible = [
            contributor(0, 20_000_000),
            contributor(1, 25_000_000),
            contributor(3, 30_000_000),
        ];
        let excluded = contributor(2, 40_000_000);
        let mut provider = ActivationTestProvider::new();
        let mut input = input(20_260_723, 21);
        input.contributor_root = contributor_root(&eligible);
        input.contributor_count = eligible.len() as u32;
        input.eligible_nominal_total = eligible
            .iter()
            .map(|record| record.nominal_amount_minor)
            .sum();
        let receipt = provider.run(&input).unwrap();

        assert_eq!(eligible.len() + 1, 4);
        assert_eq!(input.contributor_count, 3);
        assert!(!eligible
            .iter()
            .any(|record| record.source_tribute_id == excluded.source_tribute_id));
        assert_ne!(
            input.contributor_root,
            contributor_root(&[
                eligible[0].clone(),
                eligible[1].clone(),
                excluded,
                eligible[2].clone(),
            ])
        );
        assert_eq!(
            provider.generation(input.precondition.worldwide_day),
            Some(CertifiedContributorGenerationProjection {
                worldwide_day: input.precondition.worldwide_day,
                series_version: 1,
                contributor_root: input.contributor_root,
                contributor_count: input.contributor_count,
                eligible_nominal_total: input.eligible_nominal_total,
            })
        );
        let (series_exists, legacy_contributors, target) =
            StorageHandle::enter(&mut provider, |storage| {
                (
                    api::series_exists(&storage, test_sid(input.precondition.worldwide_day))
                        .unwrap(),
                    api::read_contributors(
                        &storage,
                        WorldwideDay::new(input.precondition.worldwide_day),
                    )
                    .unwrap(),
                    api::ocomp_contributor_target_projection(
                        &storage,
                        WorldwideDay::new(input.precondition.worldwide_day),
                    )
                    .unwrap(),
                )
            });
        assert!(!series_exists);
        assert!(legacy_contributors.is_empty());
        assert_eq!(target.expected_series_version, 1);
        assert_eq!(target.contributor_count, input.contributor_count);
        assert_eq!(target.contributor_total, input.eligible_nominal_total);

        let projection = ContributorStateEventProjectionV1 {
            worldwide_day: input.precondition.worldwide_day,
            series_version_before: 0,
            series_version_after: 1,
            contributor_count: input.contributor_count,
            contributor_root: input.contributor_root,
            eligible_nominal_total: input.eligible_nominal_total,
        };
        receipt
            .validate_projection(&projection, &poc_schema_limits())
            .unwrap();
        assert_eq!(receipt.contributor_count, 3);
        assert_eq!(receipt.eligible_nominal_total, U256::from(75_000_000_u128));

        let events = provider.inner.get_ordered_events();
        assert_eq!(events.len(), 1);
        let event = IIntex::CertifiedContributorRootInstalled::decode_log(&events[0]).unwrap();
        assert_eq!(event.data.seriesVersionBefore, 0);
        assert_eq!(event.data.seriesVersionAfter, 1);
        assert_eq!(event.data.contributorRoot, input.contributor_root);
        assert_eq!(event.data.contributorCount, 3);
        assert_eq!(
            event.data.eligibleNominalTotal,
            input.eligible_nominal_total
        );
        assert_eq!(event.data.stateEventDigest, receipt.state_event_digest);
    }

    #[test]
    fn all_excluded_fixture_installs_the_canonical_empty_contributor_commitment() {
        let excluded = contributor(0, 40_000_000);
        let mut provider = ActivationTestProvider::new();
        let mut input = input(20_260_730, 28);
        input.contributor_root = contributor_root(&[]);
        input.contributor_count = 0;
        input.eligible_nominal_total = U256::ZERO;

        let receipt = provider.run(&input).unwrap();
        let generation = provider
            .generation(input.precondition.worldwide_day)
            .unwrap();
        assert!(!excluded.nominal_amount_minor.is_zero());
        assert_eq!(generation.contributor_count, 0);
        assert_eq!(generation.eligible_nominal_total, U256::ZERO);
        assert_eq!(generation.contributor_root, input.contributor_root);
        assert_eq!(receipt.contributor_count, 0);
        assert_eq!(receipt.eligible_nominal_total, U256::ZERO);
    }

    #[test]
    fn existing_series_version_advances_once_and_exact_replay_is_side_effect_free() {
        let mut provider = ActivationTestProvider::new();
        let series_id = 20_260_724;
        StorageHandle::enter(&mut provider, |storage| {
            api::create_series(
                &storage,
                crate::CreateSeriesParams {
                    series_id: test_sid(series_id),
                    worldwide_day: series_id.into(),
                    issued_intex_count: 1,
                    promis_load_minor: 1,
                    entry_price_minor: U256::from(1),
                    floor_price_minor: U256::from(1),
                    call_price_minor: U256::from(1),
                    call_trigger: crate::IntexCallTrigger {
                        call_window: 24 * 60 * 60,
                        call_threshold: 24 * 60 * 60,
                        call_notice_period: 1,
                    },
                    issued_at: 1,
                    issuance_currency: 840,
                    reference_currency: 840,
                },
            )
            .unwrap();
        });

        let mut input = input(series_id, 22);
        input.precondition.expected_series_version = 1;
        provider.run(&input).unwrap();
        assert_eq!(provider.generation(series_id).unwrap().series_version, 2);

        let state = provider.inner.storage.clone();
        let events = provider.inner.get_ordered_events().to_vec();
        assert!(provider.run(&input).is_err());
        assert_eq!(provider.inner.storage, state);
        assert_eq!(provider.inner.get_ordered_events(), events);
    }

    #[test]
    fn certified_generation_blocks_legacy_contributors_but_allows_later_series_creation() {
        let mut provider = ActivationTestProvider::new();
        let value = input(20_260_731, 29);
        provider.run(&value).unwrap();
        let state = provider.inner.storage.clone();
        let events = provider.inner.get_ordered_events().to_vec();

        let legacy_contributors = [(Address::repeat_byte(7), U256::from(75_000_000_u128))];
        let record_result = StorageHandle::enter(&mut provider, |storage| {
            api::record_contributors(
                &storage,
                WorldwideDay::new(value.precondition.worldwide_day),
                &legacy_contributors,
            )
        });
        assert!(record_result.is_err());
        assert_eq!(provider.inner.storage, state);
        assert_eq!(provider.inner.get_ordered_events(), events);

        StorageHandle::enter(&mut provider, |storage| {
            api::create_series(
                &storage,
                crate::CreateSeriesParams {
                    series_id: test_sid(value.precondition.worldwide_day),
                    worldwide_day: value.precondition.worldwide_day.into(),
                    issued_intex_count: 1,
                    promis_load_minor: 1,
                    entry_price_minor: U256::from(1),
                    floor_price_minor: U256::from(1),
                    call_price_minor: U256::from(1),
                    call_trigger: crate::IntexCallTrigger {
                        call_window: 24 * 60 * 60,
                        call_threshold: 24 * 60 * 60,
                        call_notice_period: 1,
                    },
                    issued_at: 1,
                    issuance_currency: 840,
                    reference_currency: 840,
                },
            )
            .unwrap();
            assert!(
                api::series_exists(&storage, test_sid(value.precondition.worldwide_day)).unwrap()
            );
            assert!(api::read_contributors(
                &storage,
                WorldwideDay::new(value.precondition.worldwide_day)
            )
            .unwrap()
            .is_empty());
            assert_eq!(
                api::certified_contributor_generation(
                    &storage,
                    WorldwideDay::new(value.precondition.worldwide_day)
                )
                .unwrap()
                .unwrap()
                .series_version,
                1
            );
        });
    }

    #[test]
    fn invalid_root_version_count_nominal_and_binding_never_mutate_state() {
        let base = input(20_260_725, 23);
        let mut invalid = Vec::new();

        let mut value = base.clone();
        value.contributor_root = B256::ZERO;
        invalid.push(value);

        let mut value = base.clone();
        value.precondition.expected_series_version = 1;
        invalid.push(value);

        let mut value = base.clone();
        value.contributor_count = 5;
        invalid.push(value);

        let mut value = base.clone();
        value.eligible_nominal_total =
            value.precondition.max_eligible_nominal_total + U256::from(1);
        invalid.push(value);

        let mut value = base.clone();
        value.contributor_count = 0;
        invalid.push(value);

        let mut value = base;
        value.binding.activation_call_id = B256::repeat_byte(99);
        invalid.push(value);

        for value in invalid {
            let mut provider = ActivationTestProvider::new();
            let call_id = if value.binding.activation_call_id == B256::repeat_byte(99) {
                B256::repeat_byte(23)
            } else {
                value.binding.activation_call_id
            };
            let result = StorageHandle::enter(&mut provider, |storage| {
                storage.with_lysis_activation_frame(call_id, |capability| {
                    capability.authorize_nod_installation()?;
                    install_certified_contributor_root(
                        &storage,
                        capability,
                        &value,
                        &poc_schema_limits(),
                    )
                })
            });
            assert!(result.is_err());
            assert!(provider.inner.storage.is_empty());
            assert!(provider.inner.get_ordered_events().is_empty());
        }
    }

    #[test]
    fn every_storage_and_event_failure_rolls_back_the_contributor_installation() {
        for operation in 0..=3 {
            let mut provider = ActivationTestProvider::new();
            provider.inner.fail_after_mutation_at(operation);
            assert!(provider.run(&input(20_260_726, 24)).is_err());
            assert!(provider.inner.storage.is_empty());
            assert!(provider.inner.get_ordered_events().is_empty());
            assert_eq!(provider.inner.clear_mutation_failure(), operation + 1);
        }
    }

    #[test]
    fn caught_owner_failure_cannot_skip_the_contributor_cursor() {
        let value = input(20_260_727, 25);
        let mut provider = ActivationTestProvider::new();
        provider.inner.fail_after_mutation_at(0);

        let receipt = StorageHandle::enter(&mut provider, |storage| {
            storage.with_lysis_activation_frame(value.binding.activation_call_id, |capability| {
                capability.authorize_nod_installation()?;
                assert!(install_certified_contributor_root(
                    &storage,
                    capability,
                    &value,
                    &poc_schema_limits(),
                )
                .is_err());
                let receipt = install_certified_contributor_root(
                    &storage,
                    capability,
                    &value,
                    &poc_schema_limits(),
                )?;
                capability.authorize_carry_over_credit()?;
                capability.authorize_tribute_retirement()?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
        .unwrap();

        assert_eq!(receipt.contributor_root, value.contributor_root);
        assert_eq!(
            provider
                .generation(value.precondition.worldwide_day)
                .unwrap()
                .series_version,
            1
        );
        assert_eq!(provider.inner.get_ordered_events().len(), 1);
    }

    #[test]
    fn contributor_receipt_hash_is_stable_across_activation_block_times() {
        let value = input(20_260_728, 26);
        let mut first = ActivationTestProvider::new();
        first.inner.set_timestamp(U256::from(1));
        let first_receipt = first.run(&value).unwrap();

        let mut second = ActivationTestProvider::new();
        second.inner.set_timestamp(U256::from(u64::MAX));
        let second_receipt = second.run(&value).unwrap();

        assert_eq!(first_receipt, second_receipt);
        let receipt_hash = first_receipt.receipt_hash(&poc_schema_limits()).unwrap();
        assert_eq!(
            receipt_hash,
            alloy_primitives::b256!(
                "a1172d14957d7ef87497a4fa7bc4bf57bc0a9a8e4348b3e8aff858b91cbd0074"
            )
        );
        assert_eq!(
            receipt_hash,
            second_receipt.receipt_hash(&poc_schema_limits()).unwrap()
        );
    }

    #[test]
    fn every_contributor_receipt_field_mutation_changes_its_commitment() {
        let value = input(20_260_729, 27);
        let mut provider = ActivationTestProvider::new();
        let receipt = provider.run(&value).unwrap();
        let canonical = receipt.receipt_hash(&poc_schema_limits()).unwrap();

        let mut mutations = Vec::new();
        let mut mutated = receipt.clone();
        mutated.contributor_count += 1;
        mutations.push(mutated);
        let mut mutated = receipt.clone();
        mutated.contributor_root = B256::repeat_byte(91);
        mutations.push(mutated);
        let mut mutated = receipt.clone();
        mutated.eligible_nominal_total += U256::from(1);
        mutations.push(mutated);
        let mut mutated = receipt.clone();
        mutated
            .contributor_target_precondition
            .expected_series_version += 1;
        mutations.push(mutated);
        let mut mutated = receipt;
        mutated.state_event_digest = B256::repeat_byte(92);
        mutations.push(mutated);

        for mutated in mutations {
            assert_ne!(
                mutated.receipt_hash(&poc_schema_limits()).unwrap(),
                canonical
            );
        }
    }
}
