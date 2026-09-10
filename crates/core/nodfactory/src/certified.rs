//! Certified OCOMP installation boundary for Nod generations.
//!
//! This path installs only constant-size root authority and metadata. It never
//! decodes or iterates `NodActionV1`, and it has no public precompile selector.

use alloy_primitives::U256;
use alloy_sol_types::SolEvent;
use outbe_nod::{NodCertifiedGenerationProjection, NodContract};
use outbe_ocomp_protocol::{
    intent::NodTargetPreconditionV1,
    receipts::{
        nod_state_event_digest, EffectBindingV1, NodBatchReceiptV1, NodStateEventProjectionV1,
    },
    result::{ExactCountsV1, ResultRootsV1},
    SchemaLimits,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::NOD_FACTORY_ADDRESS,
    error::{PrecompileError, Result},
    storage::{CertifiedLysisActivation, StorageHandle},
};

use crate::precompile::INodFactory;

/// Closed, constant-size Nod owner input derived from a verified Lysis apply
/// plan. The raw values carry no authority; installation additionally requires
/// the runtime-only [`CertifiedLysisActivation`] capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedNodGenerationV1 {
    pub binding: EffectBindingV1,
    pub program_semantics_hash: alloy_primitives::B256,
    pub precondition: NodTargetPreconditionV1,
    pub roots: ResultRootsV1,
    pub counts: ExactCountsV1,
    pub nod_amount_total: U256,
    pub nod_gratis_consumed: U256,
    pub issued_at: u64,
}

/// Compare-and-set one certified per-WWD Nod generation.
///
/// The method is Rust-visible for the Metadosis activation coordinator, but is
/// unreachable from ABI dispatch and cannot succeed without the private
/// execution-frame capability.
pub fn install_certified_generation(
    storage: &StorageHandle<'_>,
    capability: &mut CertifiedLysisActivation<'_>,
    input: &CertifiedNodGenerationV1,
    limits: &SchemaLimits,
) -> Result<NodBatchReceiptV1> {
    validate_input(capability, input)?;

    let worldwide_day = WorldwideDay::new(input.precondition.wwd);
    let nod = NodContract::new(storage.clone());
    let next_generation = input
        .precondition
        .target_generation
        .checked_add(1)
        .ok_or_else(|| revert("certified Nod generation overflow"))?;
    let state_projection = NodStateEventProjectionV1 {
        wwd: input.precondition.wwd,
        target_generation: input.precondition.target_generation,
        namespace_root_before: input.precondition.namespace_root_before,
        nod_count: input.counts.nod_count,
        nod_root: input.roots.nod_root,
        nod_amount_total: input.nod_amount_total,
        nod_gratis_consumed: input.nod_gratis_consumed,
        issued_at: input.issued_at,
    };
    let state_event_digest = nod_state_event_digest(&input.binding, &state_projection, limits)
        .map_err(protocol_error)?;
    let receipt = NodBatchReceiptV1 {
        binding: input.binding.clone(),
        nod_target_precondition: input.precondition.clone(),
        nod_count: input.counts.nod_count,
        nod_root: input.roots.nod_root,
        nod_amount_total: input.nod_amount_total,
        nod_gratis_consumed: input.nod_gratis_consumed,
        issued_at: input.issued_at,
        state_event_digest,
    };
    receipt
        .validate_projection(&state_projection, limits)
        .map_err(protocol_error)?;
    receipt.receipt_hash(limits).map_err(protocol_error)?;

    if let Some(existing) = nod.ocomp_certified_generation(worldwide_day)? {
        if generation_matches(&existing, input, next_generation) {
            capability.authorize_nod_installation()?;
            return Ok(receipt);
        }
        return Err(revert(
            "a different certified Nod generation already exists for this WWD",
        ));
    }
    if input.precondition.target_generation != 0
        || !input.precondition.namespace_root_before.is_zero()
    {
        return Err(revert("certified Nod target precondition changed"));
    }

    let raw_head = nod.ocomp_materialization_head_sequence.read()?;
    let raw_tail = nod.ocomp_materialization_tail_sequence.read()?;
    let tail_sequence = match (raw_head, raw_tail) {
        (head, tail) if head != 0 && tail != 0 && head <= tail => {
            if head < tail {
                nod.ocomp_materialization_head()?;
            }
            tail
        }
        _ => {
            return Err(PrecompileError::Fatal(
                "Nod materialization FIFO bounds are malformed".into(),
            ))
        }
    };
    let queued_wwd = nod.ocomp_materialization_queue_wwd.read(&tail_sequence)?;
    if queued_wwd.value() != 0 {
        return Err(PrecompileError::Fatal(
            "Nod materialization FIFO tail entry is occupied".into(),
        ));
    }
    let next_tail = tail_sequence
        .checked_add(1)
        .ok_or_else(|| PrecompileError::Fatal("Nod materialization FIFO tail overflow".into()))?;
    let activation_height = storage.block_number()?;

    let installed = NodCertifiedGenerationProjection {
        worldwide_day,
        generation: next_generation,
        job_id: input.binding.job_id,
        protocol_bundle_hash: input.binding.protocol_bundle_hash,
        program_semantics_hash: input.program_semantics_hash,
        nod_root: input.roots.nod_root,
        bucket_root: input.roots.bucket_root,
        output_manifest_root: input.roots.output_manifest_root,
        tribute_count: input.counts.tribute_count,
        nod_count: input.counts.nod_count,
        bucket_count: input.counts.bucket_count,
        nod_amount_total: input.nod_amount_total,
        nod_gratis_consumed: input.nod_gratis_consumed,
        issued_at: input.issued_at,
        next_nod_ordinal: 0,
        last_progress_height: activation_height,
    };

    storage.with_checkpoint(|| {
        nod.ocomp_namespace_root
            .write(&worldwide_day, installed.nod_root)?;
        nod.ocomp_bucket_root
            .write(&worldwide_day, installed.bucket_root)?;
        nod.ocomp_output_manifest_root
            .write(&worldwide_day, installed.output_manifest_root)?;
        nod.ocomp_generation_metadata
            .write(&worldwide_day, installed.metadata_word())?;
        nod.ocomp_nod_amount_total
            .write(&worldwide_day, installed.nod_amount_total)?;
        nod.ocomp_nod_gratis_consumed
            .write(&worldwide_day, installed.nod_gratis_consumed)?;
        nod.ocomp_materialization_job_id
            .write(&worldwide_day, installed.job_id)?;
        nod.ocomp_materialization_protocol_bundle_hash
            .write(&worldwide_day, installed.protocol_bundle_hash)?;
        nod.ocomp_materialization_program_semantics_hash
            .write(&worldwide_day, installed.program_semantics_hash)?;
        nod.ocomp_materialization_next_nod_ordinal
            .write(&worldwide_day, installed.next_nod_ordinal)?;
        nod.ocomp_materialization_last_progress_height
            .write(&worldwide_day, installed.last_progress_height)?;
        nod.ocomp_materialization_queue_wwd
            .write(&tail_sequence, worldwide_day)?;
        nod.ocomp_materialization_tail_sequence.write(next_tail)?;
        // The generation is the active-state selector and therefore switches
        // only after every root and scalar has been written successfully.
        nod.ocomp_target_generation
            .write(&worldwide_day, installed.generation)?;
        storage.emit_event(
            NOD_FACTORY_ADDRESS,
            INodFactory::CertifiedNodGenerationInstalled {
                activationCallId: input.binding.activation_call_id,
                worldwideDay: input.precondition.wwd,
                targetGeneration: input.precondition.target_generation,
                namespaceRootBefore: input.precondition.namespace_root_before,
                tributeCount: input.counts.tribute_count,
                nodCount: input.counts.nod_count,
                bucketCount: input.counts.bucket_count,
                nodRoot: input.roots.nod_root,
                bucketRoot: input.roots.bucket_root,
                outputManifestRoot: input.roots.output_manifest_root,
                nodAmountTotal: input.nod_amount_total,
                nodGratisConsumed: input.nod_gratis_consumed,
                issuedAt: input.issued_at,
                stateEventDigest: state_event_digest,
            }
            .encode_log_data(),
        )?;
        // The capability cursor is not journaled storage. Advance it only
        // after every owner write and event has succeeded, so a caught
        // mutation failure cannot skip the Nod owner step.
        capability.authorize_nod_installation()?;
        Ok(())
    })?;

    Ok(receipt)
}

fn generation_matches(
    existing: &NodCertifiedGenerationProjection,
    input: &CertifiedNodGenerationV1,
    expected_generation: u64,
) -> bool {
    existing.generation == expected_generation
        && existing.job_id == input.binding.job_id
        && existing.program_semantics_hash == input.program_semantics_hash
        && existing.nod_root == input.roots.nod_root
        && existing.bucket_root == input.roots.bucket_root
        && existing.output_manifest_root == input.roots.output_manifest_root
        && existing.tribute_count == input.counts.tribute_count
        && existing.nod_count == input.counts.nod_count
        && existing.bucket_count == input.counts.bucket_count
        && existing.nod_amount_total == input.nod_amount_total
        && existing.nod_gratis_consumed == input.nod_gratis_consumed
        && existing.issued_at == input.issued_at
}

fn validate_input(
    capability: &CertifiedLysisActivation<'_>,
    input: &CertifiedNodGenerationV1,
) -> Result<()> {
    if capability.activation_call_id() != input.binding.activation_call_id {
        return Err(revert("certified Nod activation binding mismatch"));
    }
    if input.issued_at == 0 {
        return Err(revert("certified Nod logical issuance time is zero"));
    }
    if input.binding.job_id.is_zero()
        || input.binding.protocol_bundle_hash.is_zero()
        || input.program_semantics_hash.is_zero()
    {
        return Err(revert("certified Nod materialization binding is zero"));
    }
    if input.roots.nod_root.is_zero()
        || input.roots.bucket_root.is_zero()
        || input.roots.output_manifest_root.is_zero()
    {
        return Err(revert("certified Nod generation contains a zero root"));
    }
    if input.counts.tribute_count == 0
        || input.counts.nod_count != input.counts.tribute_count
        || input.counts.nod_count != input.precondition.max_nod_count
        || input.counts.bucket_count > input.counts.nod_count
    {
        return Err(revert("certified Nod generation count mismatch"));
    }
    Ok(())
}

fn protocol_error(error: outbe_ocomp_protocol::ProtocolError) -> PrecompileError {
    PrecompileError::Fatal(format!("invalid certified Nod protocol value: {error}"))
}

fn revert(reason: &'static str) -> PrecompileError {
    PrecompileError::Revert(reason.into())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, LogData, B256};
    use alloy_sol_types::SolEvent;
    use outbe_ocomp_protocol::{
        nod_materialization::NodMaterializationHeadV1,
        profile::poc_schema_limits,
        receipts::{EffectBindingV1, NodStateEventProjectionV1},
        result::{ExactCountsV1, ResultRootsV1},
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
            let mut provider = Self {
                inner: HashMapStorageProvider::new(1),
                active_call: None,
            };
            provider.inner.set_block_number(1);
            StorageHandle::enter(&mut provider, |storage| {
                let nod = NodContract::new(storage);
                nod.ocomp_materialization_head_sequence.write(1)?;
                nod.ocomp_materialization_tail_sequence.write(1)?;
                Ok::<_, PrecompileError>(())
            })
            .unwrap();
            provider
        }

        fn run(&mut self, input: &CertifiedNodGenerationV1) -> Result<NodBatchReceiptV1> {
            StorageHandle::enter(self, |storage| {
                storage.with_lysis_activation_frame(
                    input.binding.activation_call_id,
                    |capability| {
                        let receipt = install_certified_generation(
                            &storage,
                            capability,
                            input,
                            &poc_schema_limits(),
                        )?;
                        capability.authorize_contributor_installation()?;
                        capability.authorize_carry_over_credit()?;
                        capability.authorize_tribute_retirement()?;
                        capability.authorize_terminal_receipt()?;
                        Ok(receipt)
                    },
                )
            })
        }

        fn generation(&mut self, wwd: WorldwideDay) -> Option<NodCertifiedGenerationProjection> {
            StorageHandle::enter(self, |storage| {
                NodContract::new(storage)
                    .ocomp_certified_generation(wwd)
                    .unwrap()
            })
        }

        fn materialization_head(&mut self) -> Option<NodMaterializationHeadV1> {
            StorageHandle::enter(self, |storage| {
                NodContract::new(storage)
                    .ocomp_materialization_head()
                    .unwrap()
            })
        }

        fn queue_bounds(&mut self) -> (u64, u64) {
            StorageHandle::enter(self, |storage| {
                let nod = NodContract::new(storage);
                (
                    nod.ocomp_materialization_head_sequence.read().unwrap(),
                    nod.ocomp_materialization_tail_sequence.read().unwrap(),
                )
            })
        }

        fn set_queue_bounds(&mut self, head: u64, tail: u64) {
            StorageHandle::enter(self, |storage| {
                let nod = NodContract::new(storage);
                nod.ocomp_materialization_head_sequence.write(head)?;
                nod.ocomp_materialization_tail_sequence.write(tail)
            })
            .unwrap();
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
            attempt: 3,
            protocol_bundle_hash: B256::repeat_byte(4),
            result_digest: B256::repeat_byte(5),
            activation_preconditions_hash: B256::repeat_byte(6),
            activation_call_id: B256::repeat_byte(call),
        }
    }

    fn input(wwd: u32, call: u8) -> CertifiedNodGenerationV1 {
        CertifiedNodGenerationV1 {
            binding: binding(call),
            program_semantics_hash: B256::repeat_byte(7),
            precondition: NodTargetPreconditionV1 {
                wwd,
                target_generation: 0,
                namespace_root_before: B256::ZERO,
                max_nod_count: 3,
            },
            roots: ResultRootsV1 {
                nod_root: B256::repeat_byte(11),
                bucket_root: B256::repeat_byte(12),
                contributor_root: B256::repeat_byte(13),
                output_manifest_root: B256::repeat_byte(14),
            },
            counts: ExactCountsV1 {
                tribute_count: 3,
                nod_count: 3,
                bucket_count: 2,
                contributor_count: 2,
                semantic_event_count: 0,
            },
            nod_amount_total: U256::from(700),
            nod_gratis_consumed: U256::from(500),
            issued_at: 1_700_000_123,
        }
    }

    #[test]
    fn valid_capability_installs_exact_generation_receipt_and_event() {
        let mut provider = ActivationTestProvider::new();
        provider.inner.set_timestamp(U256::from(1_900_000_000));
        let input = input(20_260_725, 21);
        let receipt = provider.run(&input).unwrap();

        assert_eq!(
            provider.generation(WorldwideDay::new(input.precondition.wwd)),
            Some(NodCertifiedGenerationProjection {
                worldwide_day: WorldwideDay::new(input.precondition.wwd),
                generation: 1,
                job_id: input.binding.job_id,
                protocol_bundle_hash: input.binding.protocol_bundle_hash,
                program_semantics_hash: input.program_semantics_hash,
                nod_root: input.roots.nod_root,
                bucket_root: input.roots.bucket_root,
                output_manifest_root: input.roots.output_manifest_root,
                tribute_count: input.counts.tribute_count,
                nod_count: input.counts.nod_count,
                bucket_count: input.counts.bucket_count,
                nod_amount_total: input.nod_amount_total,
                nod_gratis_consumed: input.nod_gratis_consumed,
                issued_at: input.issued_at,
                next_nod_ordinal: 0,
                last_progress_height: 1,
            })
        );
        assert_eq!(receipt.issued_at, input.issued_at);
        assert_ne!(receipt.issued_at, 1_900_000_000);
        assert_eq!(receipt.nod_count, input.counts.nod_count);
        assert_eq!(receipt.nod_root, input.roots.nod_root);
        assert_eq!(receipt.nod_amount_total, input.nod_amount_total);
        assert_eq!(receipt.nod_gratis_consumed, input.nod_gratis_consumed);
        assert_eq!(provider.queue_bounds(), (1, 2));
        assert_eq!(
            provider.materialization_head(),
            Some(NodMaterializationHeadV1 {
                queue_sequence: 1,
                job_id: input.binding.job_id,
                program_semantics_hash: input.program_semantics_hash,
                worldwide_day: input.precondition.wwd,
                generation: 1,
                nod_root: input.roots.nod_root,
                nod_count: input.counts.nod_count,
                next_nod_ordinal: 0,
                last_progress_height: 1,
            })
        );

        let projection = NodStateEventProjectionV1 {
            wwd: input.precondition.wwd,
            target_generation: 0,
            namespace_root_before: B256::ZERO,
            nod_count: input.counts.nod_count,
            nod_root: input.roots.nod_root,
            nod_amount_total: input.nod_amount_total,
            nod_gratis_consumed: input.nod_gratis_consumed,
            issued_at: input.issued_at,
        };
        receipt
            .validate_projection(&projection, &poc_schema_limits())
            .unwrap();
        assert!(!receipt
            .receipt_hash(&poc_schema_limits())
            .unwrap()
            .is_zero());

        let events = provider.inner.get_ordered_events();
        assert_eq!(events.len(), 1);
        let event = INodFactory::CertifiedNodGenerationInstalled::decode_log(&events[0]).unwrap();
        assert_eq!(
            event.data.activationCallId,
            input.binding.activation_call_id
        );
        assert_eq!(event.data.worldwideDay, input.precondition.wwd);
        assert_eq!(event.data.targetGeneration, 0);
        assert_eq!(event.data.namespaceRootBefore, B256::ZERO);
        assert_eq!(event.data.tributeCount, input.counts.tribute_count);
        assert_eq!(event.data.nodCount, input.counts.nod_count);
        assert_eq!(event.data.bucketCount, input.counts.bucket_count);
        assert_eq!(event.data.nodRoot, input.roots.nod_root);
        assert_eq!(event.data.bucketRoot, input.roots.bucket_root);
        assert_eq!(
            event.data.outputManifestRoot,
            input.roots.output_manifest_root
        );
        assert_eq!(event.data.nodAmountTotal, input.nod_amount_total);
        assert_eq!(event.data.nodGratisConsumed, input.nod_gratis_consumed);
        assert_eq!(event.data.issuedAt, input.issued_at);
        assert_eq!(event.data.stateEventDigest, receipt.state_event_digest);
    }

    #[test]
    fn exact_replay_is_idempotent_and_wrong_generation_is_side_effect_free() {
        let mut provider = ActivationTestProvider::new();
        let first = input(20_260_726, 22);
        let first_receipt = provider.run(&first).unwrap();
        let state_after_first = provider.inner.storage.clone();
        let events_after_first = provider.inner.get_ordered_events().to_vec();

        assert_eq!(provider.run(&first).unwrap(), first_receipt);
        assert_eq!(provider.inner.storage, state_after_first);
        assert_eq!(provider.inner.get_ordered_events(), events_after_first);

        let mut wrong = input(20_260_727, 23);
        wrong.precondition.target_generation = 7;
        wrong.precondition.namespace_root_before = B256::repeat_byte(77);
        let empty_state = provider.inner.storage.clone();
        let empty_events = provider.inner.get_ordered_events().to_vec();
        assert!(provider.run(&wrong).is_err());
        assert_eq!(provider.inner.storage, empty_state);
        assert_eq!(provider.inner.get_ordered_events(), empty_events);
    }

    #[test]
    fn a_distinct_second_generation_for_the_same_wwd_is_rejected() {
        let mut provider = ActivationTestProvider::new();
        let first = input(20_260_733, 29);
        provider.run(&first).unwrap();
        let state_after_first = provider.inner.storage.clone();
        let events_after_first = provider.inner.get_ordered_events().to_vec();

        let mut next = input(first.precondition.wwd, 30);
        next.precondition.target_generation = 1;
        next.precondition.namespace_root_before = first.roots.nod_root;
        next.roots.nod_root = B256::repeat_byte(41);
        next.roots.bucket_root = B256::repeat_byte(42);
        next.roots.output_manifest_root = B256::repeat_byte(43);
        next.nod_amount_total = U256::from(701);
        next.nod_gratis_consumed = U256::from(501);
        next.issued_at += 1;

        assert!(provider.run(&next).is_err());
        assert_eq!(provider.inner.storage, state_after_first);
        assert_eq!(provider.inner.get_ordered_events(), events_after_first);
    }

    #[test]
    fn invalid_roots_counts_binding_and_time_never_mutate_state() {
        let base = input(20_260_728, 24);
        let mut invalid = Vec::new();

        let mut value = base.clone();
        value.roots.nod_root = B256::ZERO;
        invalid.push(value);

        let mut value = base.clone();
        value.counts.nod_count = 2;
        invalid.push(value);

        let mut value = base.clone();
        value.counts.bucket_count = 4;
        invalid.push(value);

        let mut value = base.clone();
        value.issued_at = 0;
        invalid.push(value);

        let mut value = base;
        value.binding.activation_call_id = B256::repeat_byte(99);
        invalid.push(value);

        for value in invalid {
            let mut provider = ActivationTestProvider::new();
            let state_before = provider.inner.storage.clone();
            let call_id = if value.binding.activation_call_id == B256::repeat_byte(99) {
                B256::repeat_byte(24)
            } else {
                value.binding.activation_call_id
            };
            let result = StorageHandle::enter(&mut provider, |storage| {
                storage.with_lysis_activation_frame(call_id, |capability| {
                    install_certified_generation(&storage, capability, &value, &poc_schema_limits())
                })
            });
            assert!(result.is_err());
            assert_eq!(provider.inner.storage, state_before);
            assert!(provider.inner.get_ordered_events().is_empty());
        }
    }

    #[test]
    fn storage_and_event_failures_roll_back_every_owner_write() {
        for operation in 0..32 {
            let mut provider = ActivationTestProvider::new();
            let state_before = provider.inner.storage.clone();
            provider.inner.fail_after_mutation_at(operation);
            if provider.run(&input(20_260_729, 25)).is_err() {
                assert_eq!(provider.inner.storage, state_before, "mutation {operation}");
                assert!(provider.inner.get_ordered_events().is_empty());
            }
            provider.inner.clear_mutation_failure();
        }
    }

    #[test]
    fn fifo_tail_overflow_rejects_installation_without_partial_state() {
        let mut provider = ActivationTestProvider::new();
        provider.set_queue_bounds(1, u64::MAX);
        let state_before = provider.inner.storage.clone();
        let events_before = provider.inner.get_ordered_events().to_vec();

        assert!(provider.run(&input(20_260_735, 32)).is_err());
        assert_eq!(provider.inner.storage, state_before);
        assert_eq!(provider.inner.get_ordered_events(), events_before);
        assert_eq!(provider.queue_bounds(), (1, u64::MAX));
    }

    #[test]
    fn caught_owner_failure_cannot_advance_the_activation_cursor() {
        let value = input(20_260_734, 31);
        let mut provider = ActivationTestProvider::new();
        provider.inner.fail_after_mutation_at(0);

        let receipt = StorageHandle::enter(&mut provider, |storage| {
            storage.with_lysis_activation_frame(value.binding.activation_call_id, |capability| {
                assert!(install_certified_generation(
                    &storage,
                    capability,
                    &value,
                    &poc_schema_limits(),
                )
                .is_err());

                let receipt = install_certified_generation(
                    &storage,
                    capability,
                    &value,
                    &poc_schema_limits(),
                )?;
                capability.authorize_contributor_installation()?;
                capability.authorize_carry_over_credit()?;
                capability.authorize_tribute_retirement()?;
                capability.authorize_terminal_receipt()?;
                Ok(receipt)
            })
        })
        .unwrap();

        assert_eq!(receipt.nod_root, value.roots.nod_root);
        assert_eq!(
            provider
                .generation(WorldwideDay::new(value.precondition.wwd))
                .unwrap()
                .generation,
            1
        );
        assert_eq!(provider.inner.get_ordered_events().len(), 1);
    }

    #[test]
    fn generations_are_isolated_by_worldwide_day() {
        let mut provider = ActivationTestProvider::new();
        let first = input(20_260_730, 26);
        let mut second = input(20_260_731, 27);
        second.roots.nod_root = B256::repeat_byte(31);
        second.roots.bucket_root = B256::repeat_byte(32);
        second.roots.output_manifest_root = B256::repeat_byte(33);

        provider.run(&first).unwrap();
        provider.run(&second).unwrap();

        assert_eq!(provider.queue_bounds(), (1, 3));
        assert_eq!(
            provider.materialization_head().unwrap().worldwide_day,
            first.precondition.wwd,
            "certified generations must remain FIFO"
        );

        assert_eq!(
            provider
                .generation(WorldwideDay::new(first.precondition.wwd))
                .unwrap()
                .nod_root,
            first.roots.nod_root
        );
        assert_eq!(
            provider
                .generation(WorldwideDay::new(second.precondition.wwd))
                .unwrap()
                .nod_root,
            second.roots.nod_root
        );
    }

    #[test]
    fn receipt_hash_is_stable_across_activation_block_times() {
        let input = input(20_260_732, 28);
        let mut first = ActivationTestProvider::new();
        first.inner.set_timestamp(U256::from(1));
        let first_receipt = first.run(&input).unwrap();

        let mut second = ActivationTestProvider::new();
        second.inner.set_timestamp(U256::from(u64::MAX));
        let second_receipt = second.run(&input).unwrap();

        assert_eq!(first_receipt, second_receipt);
        let receipt_hash = first_receipt.receipt_hash(&poc_schema_limits()).unwrap();
        assert_eq!(
            receipt_hash,
            alloy_primitives::b256!(
                "f71abea87390788dcbafe1eedc5a3f5c0e3f4c1df4c06833eba6e3badd5a62b8"
            )
        );
        assert_eq!(
            receipt_hash,
            second_receipt.receipt_hash(&poc_schema_limits()).unwrap()
        );
    }
}
