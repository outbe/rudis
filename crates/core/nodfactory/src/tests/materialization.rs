use super::*;

use outbe_chain_constants::NodMaterializationProfileV1;
use outbe_ocomp_protocol::{
    list::{ordered_list_root, streaming_ordered_list_membership_proof, OrderedListLimits},
    nod_materialization::{NodMaterializationBatchV1, NodMaterializationHeadV1},
    profile::poc_schema_limits,
    result::NodActionV1,
    ListKind,
};

const MATERIALIZATION_WWD: u32 = 20_260_812;

fn profile() -> NodMaterializationProfileV1 {
    NodMaterializationProfileV1 {
        batch_subtree_height: 3,
        retry_interval_blocks: 30,
        max_attempts_per_block: 1,
    }
}

fn action_for(materialization_wwd: u32, ordinal: u32) -> NodActionV1 {
    let owner = Address::from_word(B256::from(U256::from(ordinal + 1)));
    let worldwide_day = WorldwideDay::new(materialization_wwd);
    let floor_price_minor = U256::from(500);
    let tribute_id =
        WwdEntityId::from_day_and_digest(worldwide_day, B256::from(U256::from(ordinal + 1_000)));
    let nod_id = NodContract::generate_nod_id(owner, worldwide_day).unwrap();
    NodActionV1 {
        raw_ordinal: ordinal,
        tribute_id: *tribute_id,
        nod_id: *nod_id,
        owner,
        wwd: materialization_wwd,
        league_id: 1,
        floor_price_minor,
        gratis_load_minor: U256::from(1_000),
        entry_price_minor: U256::from(500_000),
        cost_amount_minor: U256::from(500),
        issuance_currency: 840,
        reference_currency: 840,
        issued_at: 1_600_000_000,
        bucket_key: NodContract::bucket_key(worldwide_day, floor_price_minor, 840),
    }
}

fn ledger_entity(id: B256) -> WwdEntityId {
    WwdEntityId::from(id)
}

struct Population {
    actions: Vec<NodActionV1>,
    root: B256,
    proofs: Vec<Vec<B256>>,
}

fn population(count: u32) -> Population {
    population_for(MATERIALIZATION_WWD, count)
}

fn population_for(materialization_wwd: u32, count: u32) -> Population {
    let limits = poc_schema_limits();
    let actions = (0..count)
        .map(|ordinal| action_for(materialization_wwd, ordinal))
        .collect::<Vec<_>>();
    let encoded = actions
        .iter()
        .map(|action| action.encode_canonical_record(&limits).unwrap())
        .collect::<Vec<_>>();
    let root = ordered_list_root(
        ListKind::NodActions,
        &encoded,
        OrderedListLimits::new(512, limits.max_bounded_bytes, 1 << 20),
    )
    .unwrap();
    let proofs = (0..count)
        .map(|ordinal| {
            streaming_ordered_list_membership_proof(
                ListKind::NodActions,
                count,
                ordinal,
                encoded.iter(),
                limits.max_bounded_bytes,
            )
            .unwrap()
        })
        .collect();
    Population {
        actions,
        root,
        proofs,
    }
}

fn batch(population: &Population, first: u32, count: usize) -> NodMaterializationBatchV1 {
    batch_for_sequence(population, 1, first, count)
}

fn batch_for_sequence(
    population: &Population,
    queue_sequence: u64,
    first: u32,
    count: usize,
) -> NodMaterializationBatchV1 {
    NodMaterializationBatchV1 {
        queue_sequence,
        first_nod_ordinal: first,
        actions: population.actions[first as usize..first as usize + count].to_vec(),
        root_path: population.proofs[first as usize][3..].to_vec(),
    }
}

fn seed_generation(world: &mut World, population: &Population) {
    seed_projection(world, MATERIALIZATION_WWD, 1, population);
    world
        .enter(|storage, _, _| {
            let nod = NodContract::new(storage);
            nod.ocomp_materialization_head_sequence.write(1)?;
            nod.ocomp_materialization_tail_sequence.write(2)?;
            nod.ocomp_materialization_queue_wwd
                .write(&1, WorldwideDay::new(MATERIALIZATION_WWD))?;
            Ok::<_, PrecompileError>(())
        })
        .unwrap();
}

fn seed_projection(
    world: &mut World,
    materialization_wwd: u32,
    generation: u64,
    population: &Population,
) {
    world
        .enter(|storage, _, _| {
            let worldwide_day = WorldwideDay::new(materialization_wwd);
            let nod = NodContract::new(storage);
            let projection = outbe_nod::NodCertifiedGenerationProjection {
                worldwide_day,
                generation,
                job_id: B256::repeat_byte(0x11),
                protocol_bundle_hash: B256::repeat_byte(0x5b),
                program_semantics_hash: B256::repeat_byte(0x22),
                nod_root: population.root,
                bucket_root: B256::repeat_byte(0x33),
                output_manifest_root: B256::repeat_byte(0x44),
                tribute_count: population.actions.len() as u32,
                nod_count: population.actions.len() as u32,
                bucket_count: 1,
                nod_amount_total: U256::from(10_000),
                nod_gratis_consumed: U256::from(10_000),
                issued_at: 1_600_000_000,
                next_nod_ordinal: 0,
                last_progress_height: 1,
            };
            nod.ocomp_target_generation
                .write(&worldwide_day, projection.generation)?;
            nod.ocomp_namespace_root
                .write(&worldwide_day, projection.nod_root)?;
            nod.ocomp_bucket_root
                .write(&worldwide_day, projection.bucket_root)?;
            nod.ocomp_output_manifest_root
                .write(&worldwide_day, projection.output_manifest_root)?;
            nod.ocomp_generation_metadata
                .write(&worldwide_day, projection.metadata_word())?;
            nod.ocomp_nod_amount_total
                .write(&worldwide_day, projection.nod_amount_total)?;
            nod.ocomp_nod_gratis_consumed
                .write(&worldwide_day, projection.nod_gratis_consumed)?;
            nod.ocomp_materialization_job_id
                .write(&worldwide_day, projection.job_id)?;
            nod.ocomp_materialization_protocol_bundle_hash
                .write(&worldwide_day, projection.protocol_bundle_hash)?;
            nod.ocomp_materialization_program_semantics_hash
                .write(&worldwide_day, projection.program_semantics_hash)?;
            nod.ocomp_materialization_next_nod_ordinal
                .write(&worldwide_day, 0)?;
            nod.ocomp_materialization_last_progress_height
                .write(&worldwide_day, 1)?;
            Ok::<_, PrecompileError>(())
        })
        .unwrap();
}

fn assert_projection_present(world: &mut World, materialization_wwd: u32) {
    world
        .enter(|storage, _, _| {
            assert!(NodContract::new(storage)
                .ocomp_certified_generation(WorldwideDay::new(materialization_wwd))?
                .is_some());
            Ok::<_, PrecompileError>(())
        })
        .unwrap();
}

fn assert_projection_cleared(world: &mut World, materialization_wwd: u32) {
    world
        .enter(|storage, _, _| {
            let worldwide_day = WorldwideDay::new(materialization_wwd);
            let nod = NodContract::new(storage);
            assert_eq!(nod.ocomp_target_generation.read(&worldwide_day)?, 0);
            assert_eq!(nod.ocomp_namespace_root.read(&worldwide_day)?, B256::ZERO);
            assert_eq!(nod.ocomp_bucket_root.read(&worldwide_day)?, B256::ZERO);
            assert_eq!(
                nod.ocomp_output_manifest_root.read(&worldwide_day)?,
                B256::ZERO
            );
            assert_eq!(
                nod.ocomp_generation_metadata.read(&worldwide_day)?,
                U256::ZERO
            );
            assert_eq!(nod.ocomp_nod_amount_total.read(&worldwide_day)?, U256::ZERO);
            assert_eq!(
                nod.ocomp_nod_gratis_consumed.read(&worldwide_day)?,
                U256::ZERO
            );
            assert_eq!(
                nod.ocomp_materialization_job_id.read(&worldwide_day)?,
                B256::ZERO
            );
            assert_eq!(
                nod.ocomp_materialization_program_semantics_hash
                    .read(&worldwide_day)?,
                B256::ZERO
            );
            assert_eq!(
                nod.ocomp_materialization_next_nod_ordinal
                    .read(&worldwide_day)?,
                0
            );
            assert_eq!(
                nod.ocomp_materialization_last_progress_height
                    .read(&worldwide_day)?,
                0
            );
            assert!(nod.ocomp_certified_generation(worldwide_day)?.is_none());
            Ok::<_, PrecompileError>(())
        })
        .unwrap();
}

fn apply(
    world: &mut World,
    batch: &NodMaterializationBatchV1,
) -> Result<crate::materialization::NodMaterializationOutcomeV1, PrecompileError> {
    world.enter(|storage, scope, parent| {
        crate::materialization::materialize_certified_nods_authorized(
            &storage,
            scope,
            parent,
            batch,
            profile(),
            &poc_schema_limits(),
        )
    })
}

fn head(world: &mut World) -> Option<NodMaterializationHeadV1> {
    head_result(world).unwrap()
}

fn head_result(world: &mut World) -> Result<Option<NodMaterializationHeadV1>, PrecompileError> {
    world.enter(|storage, _, _| NodContract::new(storage).ocomp_materialization_head())
}

#[test]
fn the_public_selector_rejects_a_caller_without_the_active_ocomp_role() {
    let mut world = World::new();
    let population = population(8);
    seed_generation(&mut world, &population);
    let error = world
        .enter(|storage, scope, parent| {
            api::materialize_certified_nods(
                &storage,
                scope,
                parent,
                Address::repeat_byte(0xee),
                &batch(&population, 0, 8),
                &poc_schema_limits(),
            )
        })
        .unwrap_err();
    assert!(matches!(
        error,
        PrecompileError::Revert(ref reason)
            if reason == &NodFactoryError::UnauthorizedMaterializer.to_string()
    ));
}

#[test]
fn the_public_selector_accepts_only_the_delegate_of_an_active_validator() {
    let mut world = World::new();
    let population = population(8);
    seed_generation(&mut world, &population);
    let validator = Address::repeat_byte(0x41);
    let delegate = Address::repeat_byte(0x42);
    world
        .enter(|storage, _, _| {
            let mut validators = outbe_validatorset::contract::ValidatorSet::new(storage);
            let config_owner = Address::repeat_byte(0x40);
            validators.config_owner.write(config_owner)?;
            validators.set_config_max_validators(128)?;
            validators.config_epoch_length_blocks.write(60)?;
            validators.config_is_initialized.write(true)?;
            validators.register_validator(config_owner, validator, &[0x51; 48])?;
            validators.activate_validator_via_boundary_for_test(validator)?;
            validators.set_delegate(
                validator,
                outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
                delegate,
            )?;
            Ok::<_, PrecompileError>(())
        })
        .unwrap();

    let outcome = world
        .enter(|storage, scope, parent| {
            api::materialize_certified_nods(
                &storage,
                scope,
                parent,
                delegate,
                &batch(&population, 0, 8),
                &poc_schema_limits(),
            )
        })
        .unwrap();
    assert_eq!(outcome.next_nod_ordinal, 8);
    assert!(outcome.completed);
}

#[test]
fn corrupt_fifo_bounds_or_missing_head_projection_are_fatal() {
    let population = population(8);

    let mut zero_head = World::new();
    seed_generation(&mut zero_head, &population);
    zero_head
        .enter(|storage, _, _| {
            NodContract::new(storage)
                .ocomp_materialization_head_sequence
                .write(0)
        })
        .unwrap();
    assert!(matches!(
        head_result(&mut zero_head),
        Err(PrecompileError::Fatal(_))
    ));

    let mut reversed = World::new();
    seed_generation(&mut reversed, &population);
    reversed
        .enter(|storage, _, _| {
            let nod = NodContract::new(storage);
            nod.ocomp_materialization_head_sequence.write(3)?;
            nod.ocomp_materialization_tail_sequence.write(2)
        })
        .unwrap();
    assert!(matches!(
        head_result(&mut reversed),
        Err(PrecompileError::Fatal(_))
    ));

    let mut missing_entry = World::new();
    seed_generation(&mut missing_entry, &population);
    missing_entry
        .enter(|storage, _, _| {
            NodContract::new(storage)
                .ocomp_materialization_queue_wwd
                .write(&1, WorldwideDay::new(0))
        })
        .unwrap();
    assert!(matches!(
        head_result(&mut missing_entry),
        Err(PrecompileError::Fatal(_))
    ));

    let mut missing_projection = World::new();
    seed_generation(&mut missing_projection, &population);
    missing_projection
        .enter(|storage, _, _| {
            NodContract::new(storage)
                .ocomp_materialization_queue_wwd
                .write(&1, WorldwideDay::new(MATERIALIZATION_WWD + 1))
        })
        .unwrap();
    assert!(matches!(
        head_result(&mut missing_projection),
        Err(PrecompileError::Fatal(_))
    ));
}

#[test]
fn multiple_batches_create_ordinary_nods_and_advance_fifo_atomically() {
    let mut world = World::new();
    let population = population(10);
    seed_generation(&mut world, &population);

    let first = apply(&mut world, &batch(&population, 0, 8)).unwrap();
    assert_eq!(first.next_nod_ordinal, 8);
    assert!(!first.completed);
    assert_eq!(
        world
            .enter(|storage, scope, parent| nod_api::list_all(&storage, scope, parent))
            .unwrap()
            .len(),
        8
    );
    assert_eq!(head(&mut world).unwrap().next_nod_ordinal, 8);
    assert_projection_present(&mut world, MATERIALIZATION_WWD);

    world.provider.set_block_number(2);
    let final_batch = apply(&mut world, &batch(&population, 8, 2)).unwrap();
    assert_eq!(final_batch.next_nod_ordinal, 10);
    assert!(final_batch.completed);
    assert!(head(&mut world).is_none());
    assert_projection_cleared(&mut world, MATERIALIZATION_WWD);
    assert_eq!(
        world
            .enter(|storage, scope, parent| nod_api::list_all(&storage, scope, parent))
            .unwrap()
            .len(),
        10
    );

    let first_item = world
        .enter(|storage, scope, parent| {
            nod_api::get_item(
                &storage,
                scope,
                parent,
                ledger_entity(population.actions[0].nod_id),
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(first_item.issued_at, 1_700_000_000);
    assert_ne!(first_item.issued_at, population.actions[0].issued_at);
    assert_eq!(
        world
            .enter(|storage, scope, parent| {
                nod_api::list_by_owner(&storage, scope, parent, population.actions[0].owner)
            })
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_second_attempt_in_one_block_is_rejected_before_proof_work() {
    let mut world = World::new();
    let population = population(10);
    seed_generation(&mut world, &population);
    apply(&mut world, &batch(&population, 0, 8)).unwrap();
    let storage_after_first = world.provider.storage.clone();

    let mut malformed = batch(&population, 8, 2);
    malformed.root_path.clear();
    let error = apply(&mut world, &malformed).unwrap_err();
    assert!(matches!(
        error,
        PrecompileError::Revert(ref reason)
            if reason == &NodFactoryError::MaterializationAttemptLimit.to_string()
    ));
    assert_eq!(world.provider.storage, storage_after_first);
}

#[test]
fn a_duplicate_batch_after_cursor_progress_is_a_soft_stale_race() {
    let mut world = World::new();
    let population = population(10);
    seed_generation(&mut world, &population);
    let first = batch(&population, 0, 8);
    apply(&mut world, &first).unwrap();
    let storage_after_first = world.provider.storage.clone();

    world.provider.set_block_number(2);
    let error = apply(&mut world, &first).unwrap_err();
    assert!(matches!(
        error,
        PrecompileError::Revert(ref reason)
            if reason == &NodFactoryError::StaleMaterializationCursor.to_string()
    ));
    assert_eq!(world.provider.storage, storage_after_first);
}

#[test]
fn a_duplicate_final_batch_after_projection_cleanup_is_a_soft_stale_queue_race() {
    let mut world = World::new();
    let population = population(8);
    seed_generation(&mut world, &population);
    let final_batch = batch(&population, 0, 8);
    apply(&mut world, &final_batch).unwrap();
    let storage_after_completion = world.provider.storage.clone();
    let events_after_completion = world.provider.get_ordered_events().to_vec();

    world.provider.set_block_number(2);
    let error = apply(&mut world, &final_batch).unwrap_err();
    assert!(matches!(
        error,
        PrecompileError::Revert(ref reason)
            if reason == &NodFactoryError::StaleMaterializationQueue.to_string()
    ));
    assert_eq!(world.provider.storage, storage_after_completion);
    assert_eq!(world.provider.get_ordered_events(), events_after_completion);
}

#[test]
fn completing_one_queued_generation_clears_only_its_projection() {
    let mut world = World::new();
    let first = population(8);
    let second_wwd = MATERIALIZATION_WWD + 1;
    let second = population_for(second_wwd, 8);
    seed_generation(&mut world, &first);
    seed_projection(&mut world, second_wwd, 2, &second);
    world
        .enter(|storage, _, _| {
            let nod = NodContract::new(storage);
            nod.ocomp_materialization_tail_sequence.write(3)?;
            nod.ocomp_materialization_queue_wwd
                .write(&2, WorldwideDay::new(second_wwd))?;
            Ok::<_, PrecompileError>(())
        })
        .unwrap();

    assert!(apply(&mut world, &batch(&first, 0, 8)).unwrap().completed);
    assert_projection_cleared(&mut world, MATERIALIZATION_WWD);
    assert_projection_present(&mut world, second_wwd);
    let next = head(&mut world).unwrap();
    assert_eq!(next.queue_sequence, 2);
    assert_eq!(next.worldwide_day, second_wwd);

    world.provider.set_block_number(2);
    assert!(
        apply(&mut world, &batch_for_sequence(&second, 2, 0, 8))
            .unwrap()
            .completed
    );
    assert_projection_cleared(&mut world, second_wwd);
    assert!(head(&mut world).is_none());
}

#[test]
fn failure_while_issuing_any_action_rolls_back_items_indexes_buckets_and_cursor() {
    let population = population(8);
    for failure_at in 0..24 {
        let mut world = World::new();
        seed_generation(&mut world, &population);
        let before = world.provider.storage.clone();
        let events_before = world.provider.get_ordered_events().to_vec();
        world.provider.fail_after_mutation_at(failure_at);

        if apply(&mut world, &batch(&population, 0, 8)).is_err() {
            assert_eq!(world.provider.storage, before, "mutation {failure_at}");
            assert_eq!(
                world.provider.get_ordered_events(),
                events_before,
                "event {failure_at}"
            );
        }
    }
}

#[test]
fn every_final_batch_cleanup_failure_rolls_back_nods_projection_fifo_and_events() {
    let population = population(10);
    let final_batch = batch(&population, 8, 2);
    let mut probe = World::new();
    seed_generation(&mut probe, &population);
    apply(&mut probe, &batch(&population, 0, 8)).unwrap();
    probe.provider.set_block_number(2);
    probe.provider.fail_after_mutation_at(usize::MAX);
    apply(&mut probe, &final_batch).unwrap();
    let mutation_count = probe.provider.clear_mutation_failure();

    for failure_at in 0..mutation_count {
        let mut world = World::new();
        seed_generation(&mut world, &population);
        apply(&mut world, &batch(&population, 0, 8)).unwrap();
        world.provider.set_block_number(2);
        let before = world.provider.storage.clone();
        let events_before = world.provider.get_ordered_events().to_vec();
        world.provider.fail_after_mutation_at(failure_at);

        assert!(apply(&mut world, &final_batch).is_err());
        assert_eq!(world.provider.storage, before, "mutation {failure_at}");
        assert_eq!(
            world.provider.get_ordered_events(),
            events_before,
            "event {failure_at}"
        );
    }
}

#[test]
fn certified_nods_cannot_be_mined_until_the_generation_is_complete() {
    let mut world = World::new();
    let population = population(10);
    seed_generation(&mut world, &population);
    apply(&mut world, &batch(&population, 0, 8)).unwrap();
    let nod_id = ledger_entity(population.actions[0].nod_id);
    let error = world
        .enter(|storage, scope, parent| {
            api::mine_gratis(
                &storage,
                scope,
                parent,
                api::MineGratisRequest {
                    caller: population.actions[0].owner,
                    nod_id,
                    nonce: 0,
                    auth: dummy_auth(),
                    paynote_proof: &[],
                },
            )
        })
        .unwrap_err();
    assert!(matches!(
        error,
        PrecompileError::Revert(ref reason)
            if reason == &NodFactoryError::NodGenerationNotMaterialized.to_string()
    ));

    world.provider.set_block_number(2);
    apply(&mut world, &batch(&population, 8, 2)).unwrap();
    world.qualify(nod_id);
    world.register_reference_currency_asset(NOTE_ASSET);
    let cost = outbe_nod::api::cost_amount_minor(
        population.actions[0].entry_price_minor,
        population.actions[0].gratis_load_minor,
    )
    .unwrap()
    .to::<u128>();
    let paynote_proof = world
        .fund_note(NOTE_ASSET, population.actions[0].owner, cost.max(1), cost)
        .0;
    let nonce = find_valid_nonce(nod_id);
    assert_eq!(
        world
            .enter(|storage, scope, parent| {
                api::mine_gratis(
                    &storage,
                    scope,
                    parent,
                    api::MineGratisRequest {
                        caller: population.actions[0].owner,
                        nod_id,
                        nonce,
                        auth: mine_auth(
                            population.actions[0].owner,
                            population.actions[0].gratis_load_minor,
                        ),
                        paynote_proof: &paynote_proof,
                    },
                )
            })
            .unwrap(),
        population.actions[0].gratis_load_minor
    );
}
