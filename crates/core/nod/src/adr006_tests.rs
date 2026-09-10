use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolCall;
use outbe_compressed_entities::WwdEntityId;
use outbe_compressed_entities::{begin_block, ExecutionScope};
use outbe_offchain_storage::MemoryStorage;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS,
    error::{PrecompileError, Result},
    math::constants::REAL_ID_SHIFT,
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

fn seed_compressed_entities_genesis(storage: &StorageHandle<'_>) {
    storage
        .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
        .unwrap();
    storage
        .sstore(
            COMPRESSED_ENTITIES_ADDRESS,
            U256::from(1),
            U256::from_be_slice(
                outbe_compressed_entities::sealed_root(B256::ZERO)
                    .unwrap()
                    .as_slice(),
            ),
        )
        .unwrap();
}

use outbe_oracle::api::AddressPair;

use crate::{
    api, NodCertifiedGenerationProjection, NodContract, NodItemState, NodRepositoryReader,
};

fn item(owner: Address) -> NodItemState {
    let worldwide_day = WorldwideDay::new(20_260_715);
    NodItemState {
        nod_id: NodContract::generate_nod_id(owner, worldwide_day).unwrap(),
        owner,
        gratis_load_minor: U256::from(11),
        worldwide_day,
        league_id: 4,
        floor_price_minor: U256::from(13),
        bucket_key: NodContract::bucket_key(worldwide_day, U256::from(13), 978),
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 1_752_534_000,
    }
}

#[test]
fn coen_iso_one_maps_to_the_center_price_bin_at_six_decimals() {
    assert_eq!(
        NodContract::price_to_bin(U256::from(1_000_000u64)).unwrap(),
        REAL_ID_SHIFT as u32
    );
}

#[test]
fn reverted_issuance_rolls_back_overlay_compact_state_and_events() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let body = item(Address::repeat_byte(0x66));
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let outcome: Result<()> = storage.with_checkpoint(|| {
            api::add_nod(&storage, &scope, &parent, &body, U256::from(5))?;
            assert!(api::get_item(&storage, &scope, &parent, body.nod_id)?.is_some());
            Err(PrecompileError::Revert("nested caller reverted".into()))
        });
        assert!(outcome.is_err());
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        assert!(api::get_item(&storage, &scope, &parent, body.nod_id)
            .unwrap()
            .is_none());
    });
}

#[test]
fn nod_identity_and_abi_boundary_preserve_exact_32_bytes() {
    let body = item(Address::repeat_byte(0x33));
    let encoded = body.nod_id.to_string();
    assert_eq!(NodContract::parse_nod_id(&encoded).unwrap(), body.nod_id);
    assert!(NodContract::parse_nod_id(&encoded[..62]).is_err());

    // The ABI carries the identity as one word, so a wrong-width id is no
    // longer representable: the round trip through `uint256` is total, and the
    // old "invalid bytes length" revert has no input that can reach it.
    let word = body.nod_id.to_u256();
    assert_eq!(WwdEntityId::from(word), body.nod_id);
    assert_eq!(word.to_be_bytes::<32>(), body.nod_id.0 .0);
}

#[test]
fn materialization_fifo_slots_match_the_genesis_seeder() {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let nod = NodContract::new(storage);
        assert_eq!(
            nod.ocomp_materialization_head_sequence.slot(),
            U256::from(19)
        );
        assert_eq!(
            nod.ocomp_materialization_tail_sequence.slot(),
            U256::from(20)
        );
    });
}

/// Slot assignment is dense in `order` sequence, so inserting a field rather
/// than appending one silently reassigns the meaning of every slot after it -
/// including the two the genesis alloc seeds. New fields must append.
#[test]
fn nod_contract_slot_layout_is_pinned() {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let nod = NodContract::new(storage);
        assert_eq!(nod.total_supply.slot(), U256::ZERO);
        assert_eq!(nod.bin_tree_root.base_slot(), U256::from(1));
        assert_eq!(nod.unqualified_bin_scan_cursor.base_slot(), U256::from(6));
        assert_eq!(nod.bucket_worldwide_day.base_slot(), U256::from(7));
        assert_eq!(nod.ocomp_target_generation.base_slot(), U256::from(8));
        assert_eq!(
            nod.ocomp_materialization_attempt_count.slot(),
            U256::from(23)
        );
        // Call-event columns, appended after the OCOMP block.
        assert_eq!(nod.bucket_nod_count.base_slot(), U256::from(24));
        assert_eq!(nod.bucket_nods.base_slot(), U256::from(25));
        assert_eq!(nod.bucket_nod_index.base_slot(), U256::from(26));
        // `callable_buckets` sits at 27. `StorageVec` exposes no slot accessor,
        // but slots are dense, so pinning 26 and 28 pins it too.
        assert_eq!(nod.callable_bucket_index.base_slot(), U256::from(28));
        assert_eq!(nod.callable_bucket_call_price.base_slot(), U256::from(29));
        assert_eq!(nod.callable_bucket_currency.base_slot(), U256::from(30));
        assert_eq!(nod.bucket_called_at.base_slot(), U256::from(31));
        assert_eq!(nod.call_scan_cursor.slot(), U256::from(32));
    });
}

#[test]
fn certified_generation_is_available_through_the_public_nod_abi() {
    let worldwide_day = WorldwideDay::new(20_260_726);
    let generation = NodCertifiedGenerationProjection {
        worldwide_day,
        generation: 9,
        job_id: B256::repeat_byte(0x44),
        protocol_bundle_hash: B256::repeat_byte(0x5b),
        program_semantics_hash: B256::repeat_byte(0x55),
        nod_root: B256::repeat_byte(0x11),
        bucket_root: B256::repeat_byte(0x22),
        output_manifest_root: B256::repeat_byte(0x33),
        tribute_count: 257,
        nod_count: 257,
        bucket_count: 13,
        nod_amount_total: U256::from(50_000),
        nod_gratis_consumed: U256::from(7_000),
        issued_at: 1_753_488_000,
        next_nod_ordinal: 129,
        last_progress_height: 4_096,
    };
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        let nod = NodContract::new(storage.clone());
        nod.ocomp_target_generation
            .write(&worldwide_day, generation.generation)
            .unwrap();
        nod.ocomp_namespace_root
            .write(&worldwide_day, generation.nod_root)
            .unwrap();
        nod.ocomp_bucket_root
            .write(&worldwide_day, generation.bucket_root)
            .unwrap();
        nod.ocomp_output_manifest_root
            .write(&worldwide_day, generation.output_manifest_root)
            .unwrap();
        nod.ocomp_generation_metadata
            .write(&worldwide_day, generation.metadata_word())
            .unwrap();
        nod.ocomp_nod_amount_total
            .write(&worldwide_day, generation.nod_amount_total)
            .unwrap();
        nod.ocomp_nod_gratis_consumed
            .write(&worldwide_day, generation.nod_gratis_consumed)
            .unwrap();
        nod.ocomp_materialization_job_id
            .write(&worldwide_day, generation.job_id)
            .unwrap();
        nod.ocomp_materialization_protocol_bundle_hash
            .write(&worldwide_day, generation.protocol_bundle_hash)
            .unwrap();
        nod.ocomp_materialization_program_semantics_hash
            .write(&worldwide_day, generation.program_semantics_hash)
            .unwrap();
        nod.ocomp_materialization_next_nod_ordinal
            .write(&worldwide_day, generation.next_nod_ordinal)
            .unwrap();
        nod.ocomp_materialization_last_progress_height
            .write(&worldwide_day, generation.last_progress_height)
            .unwrap();

        let call = crate::precompile::INod::certifiedGenerationCall {
            worldwideDay: worldwide_day.into(),
        }
        .abi_encode();
        let output = crate::precompile::dispatch(
            storage.clone(),
            &scope,
            &parent,
            &call,
            Address::ZERO,
            U256::ZERO,
        )
        .unwrap();
        let actual =
            crate::precompile::INod::certifiedGenerationCall::abi_decode_returns(&output).unwrap();

        assert!(actual.exists);
        assert_eq!(actual.worldwideDay, worldwide_day.value());
        assert_eq!(actual.generation, generation.generation);
        assert_eq!(actual.nodRoot, generation.nod_root);
        assert_eq!(actual.bucketRoot, generation.bucket_root);
        assert_eq!(actual.outputManifestRoot, generation.output_manifest_root);
        assert_eq!(actual.tributeCount, generation.tribute_count);
        assert_eq!(actual.nodCount, generation.nod_count);
        assert_eq!(actual.bucketCount, generation.bucket_count);
        assert_eq!(actual.nodAmountTotal, generation.nod_amount_total);
        assert_eq!(actual.nodGratisConsumed, generation.nod_gratis_consumed);
        assert_eq!(actual.issuedAt, generation.issued_at);
    });
}

#[test]
fn absent_certified_generation_has_an_explicit_public_abi_result() {
    let worldwide_day = WorldwideDay::new(20_260_727);
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let scope = ExecutionScope::new();
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        let call = crate::precompile::INod::certifiedGenerationCall {
            worldwideDay: worldwide_day.into(),
        }
        .abi_encode();
        let output =
            crate::precompile::dispatch(storage, &scope, &parent, &call, Address::ZERO, U256::ZERO)
                .unwrap();
        let actual =
            crate::precompile::INod::certifiedGenerationCall::abi_decode_returns(&output).unwrap();

        assert!(!actual.exists);
        assert_eq!(actual.worldwideDay, worldwide_day.value());
        assert_eq!(actual.generation, 0);
        assert_eq!(actual.nodRoot, B256::ZERO);
        assert_eq!(actual.bucketRoot, B256::ZERO);
        assert_eq!(actual.outputManifestRoot, B256::ZERO);
        assert_eq!(actual.tributeCount, 0);
        assert_eq!(actual.nodCount, 0);
        assert_eq!(actual.bucketCount, 0);
        assert_eq!(actual.nodAmountTotal, U256::ZERO);
        assert_eq!(actual.nodGratisConsumed, U256::ZERO);
        assert_eq!(actual.issuedAt, 0);
    });
}

/// Seeds one unqualified bucket denominated in `iso` and returns its identity.
fn seed_bucket(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &NodRepositoryReader,
    owner: Address,
    iso: u16,
) -> WwdEntityId {
    let mut body = item(owner);
    body.reference_currency = iso;
    body.bucket_key = NodContract::bucket_key(body.worldwide_day, body.floor_price_minor, iso);
    api::add_nod(storage, scope, parent, &body, U256::from(5)).unwrap();
    WwdEntityId::from_day_and_digest(body.worldwide_day, body.bucket_key)
}

/// Block timestamp every qualification-hook test runs at.
const NOW: u64 = 1_752_534_000;

/// Publishes `rate` at `published_at` on pair `index` and moves the block clock
/// to [`NOW`], which is what the hook measures the rate's age against.
fn publish_rate(storage: &StorageHandle<'_>, index: u32, rate: U256, published_at: u64) {
    let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
    oracle.exchange_rate.write(&index, rate).unwrap();
    oracle
        .exchange_rate_timestamp
        .write(&index, published_at)
        .unwrap();
    storage.set_block_timestamp(U256::from(NOW)).unwrap();
}

fn is_qualified(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &NodRepositoryReader,
    bucket_id: WwdEntityId,
) -> bool {
    api::get_bucket(storage, scope, parent, bucket_id)
        .unwrap()
        .unwrap()
        .is_qualified
}

/// A reference currency whose COEN pair was never registered must skip the
/// block's scan, not halt it — the registry lists currencies independently of
/// whether their pair has been priced. The bucket stays parked, ready for the
/// block after the pair appears.
#[test]
fn an_unregistered_reference_pair_is_skipped_without_halting_the_block() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
        oracle.reference_currencies.push(978).unwrap();
        let bucket_id = seed_bucket(&storage, &scope, &parent, Address::repeat_byte(0x66), 978);

        let ctx = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, 1_752_534_000, 1),
            storage.clone(),
        );
        crate::hooks::qualify_nods(&ctx, &scope, &parent).unwrap();
        assert!(!is_qualified(&storage, &scope, &parent, bucket_id));
    });
}

/// A registered pair carrying no published rate must also skip, rather than
/// qualify every bucket against a zero rate.
#[test]
fn a_registered_reference_pair_with_no_published_rate_is_skipped() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
        oracle.reference_currencies.push(978).unwrap();
        // Registered, but `exchange_rate` is left at zero.
        oracle
            .pair_to_index
            .write(&AddressPair::new_coen_to(978), 1)
            .unwrap();
        let bucket_id = seed_bucket(&storage, &scope, &parent, Address::repeat_byte(0x66), 978);

        let ctx = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, 1_752_534_000, 1),
            storage.clone(),
        );
        crate::hooks::qualify_nods(&ctx, &scope, &parent).unwrap();
        assert!(!is_qualified(&storage, &scope, &parent, bucket_id));
    });
}

/// One unpriceable currency must not stop the currencies after it. This fails
/// if the soft read is implemented as an early return instead of a per-currency
/// `continue`.
#[test]
fn a_priced_currency_still_qualifies_when_a_sibling_currency_is_unpriced() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
        // 978 comes first and is never priced; 840 follows and is.
        oracle.reference_currencies.push(978).unwrap();
        oracle.reference_currencies.push(840).unwrap();
        oracle
            .pair_to_index
            .write(&AddressPair::new_coen_to(840), 1)
            .unwrap();
        publish_rate(&storage, 1, U256::from(14), NOW);

        let unpriced = seed_bucket(&storage, &scope, &parent, Address::repeat_byte(0x66), 978);
        let priced = seed_bucket(&storage, &scope, &parent, Address::repeat_byte(0x77), 840);

        let ctx = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, NOW, 1),
            storage.clone(),
        );
        crate::hooks::qualify_nods(&ctx, &scope, &parent).unwrap();
        assert!(is_qualified(&storage, &scope, &parent, priced));
        assert!(!is_qualified(&storage, &scope, &parent, unpriced));
    });
}

/// Qualification is a one-way latch that snapshots the call price and arms the
/// call clock, so it must read a live rate, on the same freshness bound Gem and
/// Intex qualify under. A rate that went stale above the floor must leave the
/// bucket waiting rather than qualify it permanently.
#[test]
fn a_stale_rate_does_not_qualify_a_bucket() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
        oracle.reference_currencies.push(978).unwrap();
        oracle
            .pair_to_index
            .write(&AddressPair::new_coen_to(978), 1)
            .unwrap();
        let bucket_id = seed_bucket(&storage, &scope, &parent, Address::repeat_byte(0x66), 978);

        // The rate clears the bucket's floor of 13; it is only its age that
        // disqualifies it.
        let stale_at = NOW - outbe_oracle::constants::FX_RATE_MAX_AGE_SECONDS - 1;
        publish_rate(&storage, 1, U256::from(14), stale_at);

        let ctx = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, NOW, 1),
            storage.clone(),
        );
        crate::hooks::qualify_nods(&ctx, &scope, &parent).unwrap();
        assert!(!is_qualified(&storage, &scope, &parent, bucket_id));

        // The same rate republished now qualifies it.
        publish_rate(&storage, 1, U256::from(14), NOW);
        crate::hooks::qualify_nods(&ctx, &scope, &parent).unwrap();
        assert!(is_qualified(&storage, &scope, &parent, bucket_id));
    });
}

/// A bucket denominated in a currency absent from the oracle registry is never
/// visited: it stays parked and intact rather than being qualified against
/// some other currency's rate, and it never faults the block. This is the
/// accepted consequence of not validating `reference_currency` against mutable
/// oracle state at issue time.
#[test]
fn a_bucket_in_an_unlisted_currency_stays_unqualified_and_intact() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
        oracle.reference_currencies.push(840).unwrap();
        oracle
            .pair_to_index
            .write(&AddressPair::new_coen_to(840), 1)
            .unwrap();
        publish_rate(&storage, 1, U256::from(14), NOW);

        let unlisted = seed_bucket(&storage, &scope, &parent, Address::repeat_byte(0x66), 978);
        let ctx = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, NOW, 1),
            storage.clone(),
        );
        for _ in 0..3 {
            crate::hooks::qualify_nods(&ctx, &scope, &parent).unwrap();
        }
        assert!(!is_qualified(&storage, &scope, &parent, unlisted));

        let nod = NodContract::new(storage.clone());
        let bin = NodContract::price_to_bin(U256::from(13)).unwrap();
        assert_eq!(
            nod.unqualified_bin_count
                .read(&NodContract::scoped(978, bin))
                .unwrap(),
            1,
            "the unlisted currency's bin entry must survive untouched"
        );
    });
}

#[test]
fn the_certified_bundle_survives_a_read_and_leaves_nothing_behind_when_cleared() {
    let worldwide_day = WorldwideDay::new(20_260_726);
    let bundle = B256::repeat_byte(0x5b);
    let mut provider = HashMapStorageProvider::new(1);

    StorageHandle::enter(&mut provider, |storage| {
        let nod = NodContract::new(storage.clone());
        nod.ocomp_target_generation
            .write(&worldwide_day, 9)
            .unwrap();
        nod.ocomp_materialization_job_id
            .write(&worldwide_day, B256::repeat_byte(0x44))
            .unwrap();
        nod.ocomp_materialization_protocol_bundle_hash
            .write(&worldwide_day, bundle)
            .unwrap();
        nod.ocomp_materialization_program_semantics_hash
            .write(&worldwide_day, B256::repeat_byte(0x55))
            .unwrap();
        nod.ocomp_namespace_root
            .write(&worldwide_day, B256::repeat_byte(0x11))
            .unwrap();
        nod.ocomp_bucket_root
            .write(&worldwide_day, B256::repeat_byte(0x22))
            .unwrap();
        nod.ocomp_output_manifest_root
            .write(&worldwide_day, B256::repeat_byte(0x33))
            .unwrap();
        let shape = NodCertifiedGenerationProjection {
            worldwide_day,
            generation: 9,
            job_id: B256::repeat_byte(0x44),
            protocol_bundle_hash: bundle,
            program_semantics_hash: B256::repeat_byte(0x55),
            nod_root: B256::repeat_byte(0x11),
            bucket_root: B256::repeat_byte(0x22),
            output_manifest_root: B256::repeat_byte(0x33),
            tribute_count: 7,
            nod_count: 7,
            bucket_count: 2,
            nod_amount_total: U256::from(50_000),
            nod_gratis_consumed: U256::from(7_000),
            issued_at: 1_753_488_000,
            next_nod_ordinal: 0,
            last_progress_height: 4_096,
        };
        nod.ocomp_generation_metadata
            .write(&worldwide_day, shape.metadata_word())
            .unwrap();
        nod.ocomp_nod_amount_total
            .write(&worldwide_day, shape.nod_amount_total)
            .unwrap();
        nod.ocomp_nod_gratis_consumed
            .write(&worldwide_day, shape.nod_gratis_consumed)
            .unwrap();
        nod.ocomp_materialization_last_progress_height
            .write(&worldwide_day, shape.last_progress_height)
            .unwrap();

        let read = nod
            .ocomp_certified_generation(worldwide_day)
            .unwrap()
            .expect("a generation with a non-zero number is present");
        assert_eq!(
            read.protocol_bundle_hash, bundle,
            "materialization reads the bundle from the chain, so it has to come back"
        );

        nod.clear_ocomp_certified_generation(worldwide_day).unwrap();
        assert!(
            nod.ocomp_certified_generation(worldwide_day)
                .unwrap()
                .is_none(),
            "clearing has to wipe the bundle too, or the day reads as residual state"
        );
    });
}
