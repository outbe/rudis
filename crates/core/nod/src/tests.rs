//! Currency-aware bucket qualification: storage layout, key derivation, bin
//! namespacing, and the issuance guards that keep a bucket reachable.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{begin_block, ExecutionScope, WwdEntityId};
use outbe_offchain_storage::MemoryStorage;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS,
    math::{constants::MAX_BIN_ID, tree_math},
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

use crate::{api, hooks, state::CurrencyBins, NodContract, NodItemState, NodRepositoryReader};

const USD: u16 = 840;
const EUR: u16 = 978;

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

/// A Nod whose `bucket_key` is derived the way `record_nod_issued` requires.
fn item(owner: Address, floor: U256, reference_currency: u16) -> NodItemState {
    let worldwide_day = WorldwideDay::new(20_260_715);
    NodItemState {
        nod_id: NodContract::generate_nod_id(owner, worldwide_day).unwrap(),
        owner,
        gratis_load_minor: U256::from(11),
        worldwide_day,
        league_id: 4,
        floor_price_minor: floor,
        bucket_key: NodContract::bucket_key(worldwide_day, floor, reference_currency),
        issuance_currency: 840,
        reference_currency,
        issued_at: 1_752_534_000,
    }
}

/// Dense `order`-packing puts these fields at contiguous offsets 0..=14. The
/// per-currency bin re-keying changed field *types* but must not move a single
/// slot; nothing else in CI guards this layout.
#[test]
fn nod_contract_slot_layout_is_pinned() {
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let nod = NodContract::new(storage);
        for (index, actual) in [
            nod.total_supply.slot(),
            nod.bin_tree_root.base_slot(),
            nod.bin_tree_mid.base_slot(),
            nod.bin_tree_leaf.base_slot(),
            nod.unqualified_bin_count.base_slot(),
            nod.unqualified_bin_buckets.base_slot(),
            nod.unqualified_bin_scan_cursor.base_slot(),
            nod.bucket_worldwide_day.base_slot(),
            nod.ocomp_target_generation.base_slot(),
            nod.ocomp_namespace_root.base_slot(),
            nod.ocomp_bucket_root.base_slot(),
            nod.ocomp_output_manifest_root.base_slot(),
            nod.ocomp_generation_metadata.base_slot(),
            nod.ocomp_nod_amount_total.base_slot(),
            nod.ocomp_nod_gratis_consumed.base_slot(),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                actual,
                U256::from(index),
                "NodContract field #{index} moved slot"
            );
        }
    });
}

#[test]
fn bucket_key_binds_the_reference_currency() {
    let day = WorldwideDay::new(20_260_715);
    let floor = U256::from(13);
    assert_ne!(
        NodContract::bucket_key(day, floor, USD),
        NodContract::bucket_key(day, floor, EUR),
        "same day and floor in two currencies must not share a bucket"
    );

    // The ISO occupies the trailing two bytes of a 38-byte preimage.
    let mut expected = [0u8; 38];
    expected[0..4].copy_from_slice(&20_260_715u32.to_be_bytes());
    expected[4..36].copy_from_slice(&floor.to_be_bytes::<32>());
    expected[36..38].copy_from_slice(&USD.to_be_bytes());
    assert_eq!(
        NodContract::bucket_key(day, floor, USD),
        alloy_primitives::keccak256(expected)
    );
}

/// Why the bin columns had to widen to `u64`: mapping keys are left-padded to
/// 32 bytes before hashing, so integer width alone namespaces nothing — the
/// ISO has to occupy real high bits, and those bits do not fit in a `u32`
/// alongside a 24-bit bin id.
#[test]
fn currency_scoped_bin_keys_do_not_alias() {
    assert!(u32::try_from(NodContract::scoped(u16::MAX, MAX_BIN_ID)).is_err());
    assert_ne!(NodContract::scoped(USD, 7), NodContract::scoped(EUR, 7));
    assert_ne!(
        NodContract::bin_index_key(USD, 7, 0),
        NodContract::bin_index_key(EUR, 7, 0)
    );

    // ISO 0 is the one value that aliases the un-namespaced key. Issuance
    // rejects it (`zero_reference_currency_is_rejected_at_issuance`) precisely
    // because this collision cannot be detected downstream.
    assert_eq!(NodContract::scoped(0, 7), 7u64);
}

/// The headline regression: two Nods sharing a worldwide day and an identical
/// `floor_price_minor` but denominated differently are two buckets in two
/// independent bin tries, and a rate only qualifies its own currency.
#[test]
fn same_day_and_floor_in_two_currencies_are_two_buckets_in_two_bins() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let floor = U256::from(500_000_000_000_000_000u128);
    let usd = item(Address::repeat_byte(0x11), floor, USD);
    let eur = item(Address::repeat_byte(0x22), floor, EUR);
    assert_ne!(usd.bucket_key, eur.bucket_key);

    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        api::add_nod(&storage, &scope, &parent, &usd, U256::from(5)).unwrap();
        api::add_nod(&storage, &scope, &parent, &eur, U256::from(5)).unwrap();

        let nod = NodContract::new(storage.clone());
        let bin = NodContract::price_to_bin(floor).unwrap();

        // Identical floors land in the same bin id under different namespaces.
        assert_eq!(
            nod.unqualified_bin_count
                .read(&NodContract::scoped(USD, bin))
                .unwrap(),
            1
        );
        assert_eq!(
            nod.unqualified_bin_count
                .read(&NodContract::scoped(EUR, bin))
                .unwrap(),
            1
        );
        // Negative control: nothing landed in the un-namespaced (ISO 0) key.
        assert_eq!(nod.unqualified_bin_count.read(&u64::from(bin)).unwrap(), 0);
        assert!(tree_math::contains(&CurrencyBins(&nod, USD), bin).unwrap());
        assert!(tree_math::contains(&CurrencyBins(&nod, EUR), bin).unwrap());

        // Qualify USD only, at a rate strictly above the shared floor value.
        let context = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, 1_752_534_000, 1),
            storage.clone(),
        );
        let inspected = hooks::qualify_buckets_with_rate(
            &context,
            &scope,
            &parent,
            USD,
            floor + U256::from(1),
            crate::constants::MAX_BUCKET_QUALIFICATIONS_PER_BLOCK,
        )
        .unwrap();
        assert_eq!(inspected, 1);

        let usd_bucket = api::get_bucket(
            &storage,
            &scope,
            &parent,
            WwdEntityId::from_day_and_digest(usd.worldwide_day, usd.bucket_key),
        )
        .unwrap()
        .unwrap();
        let eur_bucket = api::get_bucket(
            &storage,
            &scope,
            &parent,
            WwdEntityId::from_day_and_digest(eur.worldwide_day, eur.bucket_key),
        )
        .unwrap()
        .unwrap();
        assert!(usd_bucket.is_qualified);
        assert!(
            !eur_bucket.is_qualified,
            "a COEN/USD rate must not qualify a EUR-denominated floor"
        );
        assert_eq!(usd_bucket.reference_currency, USD);
        assert_eq!(eur_bucket.reference_currency, EUR);

        // USD's trie is drained; EUR's is untouched.
        assert_eq!(
            nod.unqualified_bin_count
                .read(&NodContract::scoped(USD, bin))
                .unwrap(),
            0
        );
        assert!(!tree_math::contains(&CurrencyBins(&nod, USD), bin).unwrap());
        assert_eq!(
            nod.unqualified_bin_count
                .read(&NodContract::scoped(EUR, bin))
                .unwrap(),
            1
        );
        assert!(tree_math::contains(&CurrencyBins(&nod, EUR), bin).unwrap());
    });
}

/// The scan stops at its budget and resumes mid-bin on the next call via the
/// per-bin cursor. `qualify_nods` shares one budget across currencies, so an
/// over-run here would be unbounded work in `begin_block`.
#[test]
fn the_scan_stops_at_its_budget_and_resumes_from_the_bin_cursor() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let base = U256::from(1_000_000_000_000_000_000u128);
    // Floors within one 0.25% bin, so all three share a bin and the run has to
    // resume through `unqualified_bin_scan_cursor` rather than the trie walk.
    let bodies: Vec<NodItemState> = (0..3u8)
        .map(|i| item(Address::repeat_byte(0x40 + i), base + U256::from(i), USD))
        .collect();
    let bin = NodContract::price_to_bin(base).unwrap();
    for body in &bodies {
        assert_eq!(
            NodContract::price_to_bin(body.floor_price_minor).unwrap(),
            bin
        );
    }

    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        for body in &bodies {
            api::add_nod(&storage, &scope, &parent, body, U256::from(5)).unwrap();
        }
        let context = outbe_primitives::block::BlockRuntimeContext::new(
            outbe_primitives::block::BlockContext::empty_for_tests(1, 1_752_534_000, 1),
            storage.clone(),
        );
        let rate = base + U256::from(10);
        let qualified = |storage: &StorageHandle<'_>| {
            bodies
                .iter()
                .filter(|body| {
                    api::get_bucket(
                        storage,
                        &scope,
                        &parent,
                        WwdEntityId::from_day_and_digest(body.worldwide_day, body.bucket_key),
                    )
                    .unwrap()
                    .unwrap()
                    .is_qualified
                })
                .count()
        };

        let first =
            hooks::qualify_buckets_with_rate(&context, &scope, &parent, USD, rate, 2).unwrap();
        assert_eq!(first, 2, "must inspect exactly the budget");
        assert_eq!(qualified(&storage), 2);
        assert_eq!(
            NodContract::new(storage.clone())
                .unqualified_bin_count
                .read(&NodContract::scoped(USD, bin))
                .unwrap(),
            1
        );

        let second =
            hooks::qualify_buckets_with_rate(&context, &scope, &parent, USD, rate, 2).unwrap();
        assert_eq!(second, 1, "only the remaining bucket is left to inspect");
        assert_eq!(qualified(&storage), 3);
        assert!(
            !tree_math::contains(&CurrencyBins(&NodContract::new(storage.clone()), USD), bin)
                .unwrap()
        );
    });
}

/// ISO 0 would be parked in a namespace the qualifier loop never visits, so
/// the funnel rejects it before any write.
#[test]
fn zero_reference_currency_is_rejected_at_issuance() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let body = item(Address::repeat_byte(0x66), U256::from(13), 0);
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let error = api::add_nod(&storage, &scope, &parent, &body, U256::from(5)).unwrap_err();
        assert!(
            error.to_string().contains("reference currency"),
            "unexpected error: {error}"
        );

        let nod = NodContract::new(storage.clone());
        assert_eq!(nod.total_supply().unwrap(), 0);
        let bin = NodContract::price_to_bin(body.floor_price_minor).unwrap();
        assert_eq!(nod.unqualified_bin_count.read(&u64::from(bin)).unwrap(), 0);
    });
}

/// The bucket key is derived, not supplied: a caller whose key disagrees with
/// `(day, floor, currency)` is rejected, so the on-chain and Lysis derivations
/// cannot drift apart silently.
#[test]
fn a_bucket_key_that_does_not_match_its_inputs_is_rejected() {
    let parent = NodRepositoryReader::new(Arc::new(MemoryStorage::new()));
    let mut body = item(Address::repeat_byte(0x66), U256::from(13), EUR);
    body.bucket_key = NodContract::bucket_key(body.worldwide_day, U256::from(13), USD);
    let mut provider = HashMapStorageProvider::new(1);
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let error = api::add_nod(&storage, &scope, &parent, &body, U256::from(5)).unwrap_err();
        assert!(
            error.to_string().contains("bucket identity mismatch"),
            "unexpected error: {error}"
        );
        assert_eq!(NodContract::new(storage).total_supply().unwrap(), 0);
    });
}
