use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use alloy_primitives::{address, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    begin_block, decode_tribute_v1, derive_poseidon_entity_id, encode_tribute_v1, end_block,
    ExecutionScope, PartitionRef, WwdEntityId,
};
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle, StorageWriterHandle};
use outbe_primitives::addresses::{COMPRESSED_ENTITIES_ADDRESS, TRIBUTE_ADDRESS};
use outbe_primitives::error::{PrecompileError, Result as PrecompileResult};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::{TributeContract, TributeData, TributeRepositoryReader, TributeRepositoryWriter};

struct TestTribute<'a, 'scope> {
    contract: TributeContract<'a>,
    scope: &'scope ExecutionScope,
    reader: TributeRepositoryReader,
}

impl<'a> Deref for TestTribute<'a, '_> {
    type Target = TributeContract<'a>;

    fn deref(&self) -> &Self::Target {
        &self.contract
    }
}

impl DerefMut for TestTribute<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.contract
    }
}

impl TestTribute<'_, '_> {
    fn issue(&mut self, tribute: &TributeData) -> PrecompileResult<()> {
        self.contract.issue(self.scope, &self.reader, tribute)
    }

    fn burn(&mut self, tribute_id: WwdEntityId) -> PrecompileResult<()> {
        self.contract.burn(self.scope, &self.reader, tribute_id)
    }

    fn burn_all_by_wwd(
        &mut self,
        day: outbe_primitives::time::WorldwideDay,
    ) -> PrecompileResult<()> {
        self.contract.burn_all_by_wwd(self.scope, &self.reader, day)
    }

    fn get_tribute(&self, tribute_id: WwdEntityId) -> PrecompileResult<Option<TributeData>> {
        self.contract
            .get_tribute(self.scope, &self.reader, tribute_id)
    }

    fn balance_of(&self, owner: alloy_primitives::Address) -> PrecompileResult<u64> {
        self.contract.balance_of(self.scope, &self.reader, owner)
    }

    fn token_uri(&self, tribute_id: WwdEntityId) -> PrecompileResult<String> {
        self.contract
            .token_uri(self.scope, &self.reader, tribute_id)
    }

    fn get_tribute_ids_by_owner(
        &self,
        owner: alloy_primitives::Address,
    ) -> PrecompileResult<Vec<WwdEntityId>> {
        self.contract
            .get_tribute_ids_by_owner(self.scope, &self.reader, owner)
    }

    fn get_tribute_ids_by_day(
        &self,
        day: outbe_primitives::time::WorldwideDay,
    ) -> PrecompileResult<Vec<WwdEntityId>> {
        self.contract
            .get_tribute_ids_by_day(self.scope, &self.reader, day)
    }

    fn get_tributes_by_owner(
        &self,
        owner: alloy_primitives::Address,
    ) -> PrecompileResult<Vec<TributeData>> {
        self.contract
            .get_tributes_by_owner(self.scope, &self.reader, owner)
    }

    fn get_all_day_tributes(
        &self,
        day: outbe_primitives::time::WorldwideDay,
    ) -> PrecompileResult<Vec<TributeData>> {
        self.contract
            .get_all_day_tributes(self.scope, &self.reader, day)
    }
}

fn body_repository() -> (TributeRepositoryReader, TributeRepositoryWriter) {
    let storage = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = storage.clone();
    let writer: StorageWriterHandle = storage;
    (
        TributeRepositoryReader::new(reader.clone()),
        TributeRepositoryWriter::new(reader, writer),
    )
}

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

fn with_tribute<R>(f: impl FnOnce(&mut TestTribute<'_, '_>) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(1);
    let (reader, _writer) = body_repository();
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut storage, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let mut tc = TestTribute {
            contract: TributeContract::new(storage.clone()),
            scope: &scope,
            reader,
        };
        let result = f(&mut tc);
        end_block(storage, &scope).unwrap();
        result
    })
}

fn with_provider<R>(
    f: impl FnOnce(&mut HashMapStorageProvider, &TributeRepositoryReader, &ExecutionScope) -> R,
) -> R {
    let mut storage = HashMapStorageProvider::new(1);
    let (reader, _writer) = body_repository();
    let scope = ExecutionScope::new();
    StorageHandle::enter(&mut storage, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage, &scope).unwrap()
    });
    let result = f(&mut storage, &reader, &scope);
    StorageHandle::enter(&mut storage, |storage| end_block(storage, &scope).unwrap());
    result
}

fn sample_tribute() -> TributeData {
    let worldwide_day = 20241220u32.into();
    let owner = address!("0x1111111111111111111111111111111111111111");
    TributeData {
        tribute_id: derive_poseidon_entity_id(owner, worldwide_day).unwrap(),
        owner,
        worldwide_day,
        issuance_amount_minor: U256::from(1_000_000u64),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(500_000u64),
        reference_currency: 840,
        exclude_from_intex_issuance: false,
        tribute_price_minor: U256::from(2_000_000u64),
    }
}

fn entity_id(seed: u64, day: outbe_primitives::time::WorldwideDay) -> WwdEntityId {
    derive_poseidon_entity_id(alloy_primitives::Address::repeat_byte(seed as u8), day).unwrap()
}

fn set_owner(tribute: &mut TributeData, owner: alloy_primitives::Address) {
    tribute.owner = owner;
    tribute.tribute_id = derive_poseidon_entity_id(owner, tribute.worldwide_day).unwrap();
}

fn set_day(tribute: &mut TributeData, day: outbe_primitives::time::WorldwideDay) {
    tribute.worldwide_day = day;
    tribute.tribute_id = derive_poseidon_entity_id(tribute.owner, day).unwrap();
}

fn open_sample_day(tc: &mut TributeContract) {
    tc.unseal_day(20241220u32.into()).unwrap();
}

#[test]
fn test_initial_state() {
    with_tribute(|tc| {
        assert_eq!(tc.total_supply().unwrap(), 0);
        let totals = tc.get_day_totals(20241220u32.into()).unwrap();
        assert_eq!(totals.tribute_count, 0);
        assert_eq!(totals.tribute_nominal_amount, U256::ZERO);
        assert!(!totals.is_sealed);
    });
}

#[test]
fn test_issue_requires_initialized_unsealed_day() {
    with_tribute(|tc| {
        let tribute = sample_tribute();
        assert!(tc.issue(&tribute).is_err());

        open_sample_day(tc);
        tc.issue(&tribute).unwrap();
        assert_eq!(tc.total_supply().unwrap(), 1);
    });
}

#[test]
fn test_issue_duplicate_fails() {
    with_tribute(|tc| {
        let tribute = sample_tribute();
        open_sample_day(tc);
        tc.issue(&tribute).unwrap();
        assert!(tc.issue(&tribute).is_err());
    });
}

#[test]
fn test_day_bucket_tracks_nominal_and_gratis() {
    with_tribute(|tc| {
        let t1 = sample_tribute();
        let mut t2 = sample_tribute();
        set_owner(
            &mut t2,
            address!("0x2222222222222222222222222222222222222222"),
        );
        t2.nominal_amount_minor = U256::from(300_000u64);

        open_sample_day(tc);
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();

        let totals = tc.get_day_totals(20241220u32.into()).unwrap();
        assert_eq!(totals.tribute_count, 2);
        assert_eq!(
            totals.tribute_nominal_amount,
            t1.nominal_amount_minor + t2.nominal_amount_minor
        );
        assert!(!totals.is_sealed);
    });
}

#[test]
fn pre_admission_projection_tracks_exact_incremental_tribute_inputs() {
    with_tribute(|tc| {
        tc.initialize_fresh_ocomp_profile().unwrap();
        let first = sample_tribute();
        let mut second = sample_tribute();
        set_owner(
            &mut second,
            address!("0x2222222222222222222222222222222222222222"),
        );
        second.reference_currency = 978;
        second.nominal_amount_minor = U256::from(7);

        open_sample_day(tc);
        tc.issue(&first).unwrap();
        tc.issue(&second).unwrap();

        let projection = tc.pre_admission_projection(first.worldwide_day).unwrap();
        let expected_body_bytes = [
            encode_tribute_v1(&crate::canonical_body(&first)).unwrap(),
            encode_tribute_v1(&crate::canonical_body(&second)).unwrap(),
        ]
        .iter()
        .map(Vec::len)
        .sum::<usize>();

        assert!(!projection.is_sealed);
        assert_eq!(projection.tribute_count, 2);
        assert_eq!(
            projection.tribute_nominal_amount,
            first.nominal_amount_minor + second.nominal_amount_minor
        );
        assert_eq!(
            projection.canonical_body_bytes,
            u64::try_from(expected_body_bytes).unwrap()
        );
        assert_eq!(projection.distinct_owner_count, 2);
        assert_eq!(projection.distinct_reference_currency_count, 2);
    });
}

#[test]
fn pre_admission_projection_removes_burned_tribute_contribution() {
    with_tribute(|tc| {
        tc.initialize_fresh_ocomp_profile().unwrap();
        let first = sample_tribute();
        let mut second = sample_tribute();
        set_owner(
            &mut second,
            address!("0x2222222222222222222222222222222222222222"),
        );
        second.nominal_amount_minor = U256::from(7);

        open_sample_day(tc);
        tc.issue(&first).unwrap();
        tc.issue(&second).unwrap();
        tc.burn(first.tribute_id).unwrap();

        let projection = tc.pre_admission_projection(first.worldwide_day).unwrap();
        let expected_body_bytes = encode_tribute_v1(&crate::canonical_body(&second))
            .unwrap()
            .len();

        assert_eq!(projection.tribute_count, 1);
        assert_eq!(
            projection.tribute_nominal_amount,
            second.nominal_amount_minor
        );
        assert_eq!(
            projection.canonical_body_bytes,
            u64::try_from(expected_body_bytes).unwrap()
        );
        assert_eq!(projection.distinct_owner_count, 1);
        assert_eq!(projection.distinct_reference_currency_count, 1);
    });
}

#[test]
fn sealed_pre_admission_projection_is_immutable() {
    let mut provider = HashMapStorageProvider::new(1);
    let (reader, _writer) = body_repository();
    let scope = ExecutionScope::new();
    let tribute = sample_tribute();

    StorageHandle::enter(&mut provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        let mut contract = TributeContract::new(storage);
        contract.initialize_fresh_ocomp_profile().unwrap();
        contract.unseal_day(tribute.worldwide_day).unwrap();
        contract.issue(&scope, &reader, &tribute).unwrap();
        contract.seal_day(tribute.worldwide_day).unwrap();
    });
    let seal = StorageHandle::enter(&mut provider, |storage| end_block(storage, &scope).unwrap());

    let mut forged = seal.clone();
    forged.new_root = B256::repeat_byte(0x31);
    assert!(scope
        .sealed_collection_root(&forged, PartitionRef::TributeWwd(tribute.worldwide_day))
        .is_err());

    let mut sibling_provider = HashMapStorageProvider::new(1);
    let sibling_scope = ExecutionScope::new();
    let mut sibling_tribute = sample_tribute();
    set_owner(
        &mut sibling_tribute,
        alloy_primitives::Address::repeat_byte(0x62),
    );
    StorageHandle::enter(&mut sibling_provider, |storage| {
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &sibling_scope).unwrap();
        let mut contract = TributeContract::new(storage);
        contract.unseal_day(sibling_tribute.worldwide_day).unwrap();
        contract
            .issue(&sibling_scope, &reader, &sibling_tribute)
            .unwrap();
        contract.seal_day(sibling_tribute.worldwide_day).unwrap();
    });
    let sibling_seal = StorageHandle::enter(&mut sibling_provider, |storage| {
        end_block(storage, &sibling_scope).unwrap()
    });
    assert!(scope
        .sealed_collection_root(
            &sibling_seal,
            PartitionRef::TributeWwd(tribute.worldwide_day)
        )
        .is_err());

    let sealed_collection = scope
        .sealed_collection_root(&seal, PartitionRef::TributeWwd(tribute.worldwide_day))
        .unwrap();
    let sealed = StorageHandle::enter(&mut provider, |storage| {
        TributeContract::new(storage)
            .seal_pre_admission(tribute.worldwide_day, sealed_collection)
            .unwrap()
    });

    assert!(sealed.is_sealed);
    assert_eq!(sealed.sealed_collection_root, sealed_collection.root());
    assert_eq!(sealed.tribute_count, 1);
    assert_eq!(sealed.tribute_nominal_amount, tribute.nominal_amount_minor);

    StorageHandle::enter(&mut provider, |storage| {
        let mut contract = TributeContract::new(storage);
        assert!(contract.unseal_day(tribute.worldwide_day).is_err());
        assert!(contract
            .seal_pre_admission(tribute.worldwide_day, sealed_collection)
            .is_err());
        assert_eq!(
            contract
                .pre_admission_projection(tribute.worldwide_day)
                .unwrap(),
            sealed
        );
    });
}

#[test]
fn incremental_pre_admission_matches_independent_randomized_full_fold() {
    with_tribute(|tc| {
        tc.initialize_fresh_ocomp_profile().unwrap();
        let day = 20241220u32.into();
        let mut seed = 0x4f43_4d30_3600_0001_u64;
        let mut entries = Vec::<(TributeData, bool)>::new();

        open_sample_day(tc);
        for owner_byte in 1_u8..=32 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let mut tribute = sample_tribute();
            set_owner(
                &mut tribute,
                alloy_primitives::Address::repeat_byte(owner_byte),
            );
            tribute.reference_currency =
                [840, 978, 826, 392, 756][usize::try_from(seed % 5).unwrap()];
            tribute.nominal_amount_minor = U256::from((seed % 10_000) + 1);
            tc.issue(&tribute).unwrap();
            entries.push((tribute, true));
            assert_pre_admission_matches_fold(tc, day, &entries);
        }

        for index in (0..entries.len()).step_by(3) {
            tc.burn(entries[index].0.tribute_id).unwrap();
            entries[index].1 = false;
            assert_pre_admission_matches_fold(tc, day, &entries);
        }
    });
}

#[test]
fn pre_admission_overflow_rolls_back_the_entire_issue() {
    with_tribute(|tc| {
        tc.initialize_fresh_ocomp_profile().unwrap();
        let tribute = sample_tribute();
        open_sample_day(tc);
        tc.day_pre_admission
            .create(&crate::DayPreAdmission {
                worldwide_day: tribute.worldwide_day,
                initialized: true,
                is_sealed: false,
                sealed_collection_root: B256::ZERO,
                sealed_tribute_count: 0,
                sealed_tribute_nominal_amount: U256::ZERO,
                canonical_body_bytes: u64::MAX,
                distinct_owner_count: 0,
                distinct_reference_currency_count: 0,
                source_generation: 0,
            })
            .unwrap();
        let before = tc.pre_admission_projection(tribute.worldwide_day).unwrap();

        assert!(tc.issue(&tribute).is_err());

        assert_eq!(
            tc.pre_admission_projection(tribute.worldwide_day).unwrap(),
            before
        );
        let totals = tc.get_day_totals(tribute.worldwide_day).unwrap();
        assert_eq!(totals.tribute_count, 0);
        assert_eq!(totals.tribute_nominal_amount, U256::ZERO);
        assert_eq!(tc.total_supply().unwrap(), 0);
        assert!(tc.get_tribute(tribute.tribute_id).unwrap().is_none());
    });
}

#[test]
fn tribute_population_crosses_multiple_work_shards_without_a_total_cap() {
    with_tribute(|tc| {
        tc.initialize_fresh_ocomp_profile().unwrap();
        let day = 20241220u32.into();
        open_sample_day(tc);

        for seed in 1_u16..=257 {
            let mut tribute = sample_tribute();
            let mut owner = [0_u8; 20];
            owner[18..].copy_from_slice(&seed.to_be_bytes());
            set_owner(&mut tribute, alloy_primitives::Address::from(owner));
            tribute.reference_currency = 840 + (seed % 3);
            tc.issue(&tribute).unwrap();
        }

        let second_shard = tc.pre_admission_projection(day).unwrap();
        assert_eq!(second_shard.tribute_count, 257);
        assert_eq!(second_shard.distinct_owner_count, 257);
        assert_eq!(tc.total_supply().unwrap(), 257);

        for seed in 258_u16..=513 {
            let mut tribute = sample_tribute();
            let mut owner = [0_u8; 20];
            owner[18..].copy_from_slice(&seed.to_be_bytes());
            set_owner(&mut tribute, alloy_primitives::Address::from(owner));
            tribute.reference_currency = 840 + (seed % 3);
            tc.issue(&tribute).unwrap();
        }

        let third_shard = tc.pre_admission_projection(day).unwrap();
        assert_eq!(third_shard.tribute_count, 513);
        assert_eq!(third_shard.distinct_owner_count, 513);
        assert_eq!(tc.total_supply().unwrap(), 513);

        let last = {
            let mut tribute = sample_tribute();
            let mut owner = [0_u8; 20];
            owner[18..].copy_from_slice(&513_u16.to_be_bytes());
            set_owner(&mut tribute, alloy_primitives::Address::from(owner));
            tribute
        };
        tc.burn(last.tribute_id).unwrap();

        let after_burn = tc.pre_admission_projection(day).unwrap();
        assert_eq!(after_burn.tribute_count, 512);
        assert_eq!(after_burn.distinct_owner_count, 512);
    });
}

#[test]
fn pre_fork_tribute_issue_is_unchanged_and_cannot_backfill_ocomp_lazily() {
    with_tribute(|tc| {
        let tribute = sample_tribute();
        open_sample_day(tc);
        tc.issue(&tribute).unwrap();

        let projection = tc.pre_admission_projection(tribute.worldwide_day).unwrap();
        assert!(!projection.profile_ready);
        assert_eq!(projection.canonical_body_bytes, 0);
        assert_eq!(projection.distinct_owner_count, 0);
        assert_eq!(projection.distinct_reference_currency_count, 0);
        assert_eq!(tc.total_supply().unwrap(), 1);
        assert!(tc.initialize_fresh_ocomp_profile().is_err());
        assert!(tc.get_tribute(tribute.tribute_id).unwrap().is_some());
    });
}

fn assert_pre_admission_matches_fold(
    tc: &TestTribute<'_, '_>,
    day: outbe_primitives::time::WorldwideDay,
    entries: &[(TributeData, bool)],
) {
    let mut count = 0_u32;
    let mut nominal = U256::ZERO;
    let mut canonical_body_bytes = 0_u64;
    let mut owners = BTreeSet::new();
    let mut currencies = BTreeSet::new();
    for (tribute, is_live) in entries {
        if !is_live {
            continue;
        }
        count = count.checked_add(1).unwrap();
        nominal = nominal.checked_add(tribute.nominal_amount_minor).unwrap();
        canonical_body_bytes = canonical_body_bytes
            .checked_add(
                u64::try_from(
                    encode_tribute_v1(&crate::canonical_body(tribute))
                        .unwrap()
                        .len(),
                )
                .unwrap(),
            )
            .unwrap();
        owners.insert(tribute.owner);
        currencies.insert(tribute.reference_currency);
    }

    let projection = tc.pre_admission_projection(day).unwrap();
    assert_eq!(projection.tribute_count, count);
    assert_eq!(projection.tribute_nominal_amount, nominal);
    assert_eq!(projection.canonical_body_bytes, canonical_body_bytes);
    assert_eq!(
        projection.distinct_owner_count,
        u32::try_from(owners.len()).unwrap()
    );
    assert_eq!(
        projection.distinct_reference_currency_count,
        u16::try_from(currencies.len()).unwrap()
    );
}

#[test]
fn test_burn_tribute() {
    with_tribute(|tc| {
        let tribute = sample_tribute();
        open_sample_day(tc);
        tc.issue(&tribute).unwrap();

        tc.burn(tribute.tribute_id).unwrap();

        assert_eq!(tc.total_supply().unwrap(), 0);
        assert!(tc.get_tribute(tribute.tribute_id).unwrap().is_none());

        let totals = tc.get_day_totals(20241220u32.into()).unwrap();
        assert_eq!(totals.tribute_count, 0);
        assert_eq!(totals.tribute_nominal_amount, U256::ZERO);
    });
}

#[test]
fn test_burn_nonexistent_fails() {
    with_tribute(|tc| {
        let tribute_id = entity_id(0x99, 20241220u32.into());
        assert!(tc.burn(tribute_id).is_err());
    });
}

#[test]
fn test_seal_day() {
    with_tribute(|tc| {
        let day = 20241220u32.into();
        open_sample_day(tc);

        let tribute = sample_tribute();
        tc.issue(&tribute).unwrap();
        let totals_before_seal = tc.get_day_totals(day).unwrap();

        tc.seal_day(day).unwrap();
        assert!(tc.is_day_sealed(day).unwrap());

        let mut second_tribute = sample_tribute();
        set_owner(
            &mut second_tribute,
            address!("0x2222222222222222222222222222222222222222"),
        );
        assert!(tc.issue(&second_tribute).is_err());
        assert!(tc.burn(tribute.tribute_id).is_err());
        assert!(tc.get_tribute(tribute.tribute_id).unwrap().is_some());
        let totals_after_rejected_mutations = tc.get_day_totals(day).unwrap();
        assert_eq!(
            totals_after_rejected_mutations.tribute_count,
            totals_before_seal.tribute_count
        );
        assert_eq!(
            totals_after_rejected_mutations.tribute_nominal_amount,
            totals_before_seal.tribute_nominal_amount
        );

        tc.unseal_day(day).unwrap();
        assert!(!tc.is_day_sealed(day).unwrap());
        tc.burn(tribute.tribute_id).unwrap();
    });
}

#[test]
fn lysis_bulk_accounting_rejects_count_and_nominal_mismatch_before_zeroing() {
    with_tribute(|tc| {
        let tribute = sample_tribute();
        open_sample_day(tc);
        tc.issue(&tribute).unwrap();
        tc.seal_day(tribute.worldwide_day).unwrap();

        assert!(tc
            .consume_lysis_partition(tribute.worldwide_day, 2, tribute.nominal_amount_minor,)
            .is_err());
        assert!(tc
            .consume_lysis_partition(
                tribute.worldwide_day,
                1,
                tribute.nominal_amount_minor + U256::from(1),
            )
            .is_err());
        let unchanged = tc.get_day_totals(tribute.worldwide_day).unwrap();
        assert_eq!(unchanged.tribute_count, 1);
        assert_eq!(
            unchanged.tribute_nominal_amount,
            tribute.nominal_amount_minor
        );
        assert_eq!(tc.total_supply().unwrap(), 1);

        tc.consume_lysis_partition(tribute.worldwide_day, 1, tribute.nominal_amount_minor)
            .unwrap();
        let completed = tc.get_day_totals(tribute.worldwide_day).unwrap();
        assert!(completed.initialized);
        assert!(completed.is_sealed);
        assert_eq!(completed.tribute_count, 0);
        assert_eq!(completed.tribute_nominal_amount, U256::ZERO);
        assert_eq!(tc.total_supply().unwrap(), 0);
    });
}

#[test]
fn test_balance_of_tracks_live_owner_tributes() {
    with_tribute(|tc| {
        let alice = address!("0x1111111111111111111111111111111111111111");

        let mut t1 = sample_tribute();
        set_owner(&mut t1, alice);

        let mut t2 = sample_tribute();
        set_owner(&mut t2, alice);
        set_day(&mut t2, 20241221u32.into());

        open_sample_day(tc);
        tc.unseal_day(t2.worldwide_day).unwrap();
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();
        assert_eq!(tc.balance_of(alice).unwrap(), 2);

        tc.burn(t1.tribute_id).unwrap();
        assert_eq!(tc.balance_of(alice).unwrap(), 1);
    });
}

#[test]
fn test_token_uri_returns_metadata_json() {
    with_tribute(|tc| {
        let tribute = sample_tribute();
        open_sample_day(tc);
        tc.issue(&tribute).unwrap();

        let token_uri = tc.token_uri(tribute.tribute_id).unwrap();
        assert!(token_uri.starts_with("data:application/json;utf8,"));
        let json: serde_json::Value = serde_json::from_str(
            token_uri
                .strip_prefix("data:application/json;utf8,")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(json["description"], "Rudis Tribute");
        assert!(token_uri.contains("worldwide_day"));
        assert!(token_uri.contains("issuance_amount_minor"));
        assert!(token_uri.contains("\"trait_type\":\"reference_currency\""));
        assert!(token_uri.contains("\"trait_type\":\"exclude_from_intex_issuance\""));
    });
}

#[test]
fn test_get_tribute_ids_by_owner() {
    with_tribute(|tc| {
        let alice = address!("0x1111111111111111111111111111111111111111");
        let bob = address!("0x2222222222222222222222222222222222222222");

        let mut t1 = sample_tribute();
        set_owner(&mut t1, alice);

        let mut t2 = sample_tribute();
        set_owner(&mut t2, alice);
        set_day(&mut t2, 20241221u32.into());

        let mut t3 = sample_tribute();
        set_owner(&mut t3, bob);

        open_sample_day(tc);
        tc.unseal_day(t2.worldwide_day).unwrap();
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();
        tc.issue(&t3).unwrap();

        let alice_ids = tc.get_tribute_ids_by_owner(alice).unwrap();
        assert_eq!(alice_ids, vec![t1.tribute_id, t2.tribute_id]);

        let bob_ids = tc.get_tribute_ids_by_owner(bob).unwrap();
        assert_eq!(bob_ids, vec![t3.tribute_id]);
    });
}

#[test]
fn test_get_tribute_ids_by_day() {
    with_tribute(|tc| {
        let t1 = sample_tribute();
        let mut t2 = sample_tribute();
        set_owner(
            &mut t2,
            address!("0x2222222222222222222222222222222222222222"),
        );

        open_sample_day(tc);
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();

        let day_ids = tc.get_tribute_ids_by_day(20241220u32.into()).unwrap();
        let mut expected = vec![t1.tribute_id, t2.tribute_id];
        expected.sort_unstable();
        assert_eq!(day_ids, expected);
    });
}

#[test]
fn test_get_tributes_by_owner_sparse_after_burn() {
    with_tribute(|tc| {
        let alice = address!("0x1111111111111111111111111111111111111111");

        let mut t1 = sample_tribute();
        set_owner(&mut t1, alice);

        let mut t2 = sample_tribute();
        set_owner(&mut t2, alice);
        set_day(&mut t2, 20241221u32.into());

        open_sample_day(tc);
        tc.unseal_day(t2.worldwide_day).unwrap();
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();
        tc.burn(t1.tribute_id).unwrap();

        let tributes = tc.get_tributes_by_owner(alice).unwrap();
        assert_eq!(tributes.len(), 1);
        assert_eq!(tributes[0].tribute_id, t2.tribute_id);
    });
}

#[test]
fn test_get_all_day_tributes_sparse_after_burn() {
    with_tribute(|tc| {
        let t1 = sample_tribute();
        let mut t2 = sample_tribute();
        set_owner(
            &mut t2,
            address!("0x2222222222222222222222222222222222222222"),
        );

        open_sample_day(tc);
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();
        tc.burn(t1.tribute_id).unwrap();

        let tributes = tc.get_all_day_tributes(20241220u32.into()).unwrap();
        assert_eq!(tributes.len(), 1);
        assert_eq!(tributes[0].tribute_id, t2.tribute_id);
    });
}

#[test]
fn test_burn_all_by_wwd() {
    with_tribute(|tc| {
        let t1 = sample_tribute();
        let mut t2 = sample_tribute();
        set_owner(
            &mut t2,
            address!("0x2222222222222222222222222222222222222222"),
        );

        open_sample_day(tc);
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();

        tc.burn_all_by_wwd(20241220u32.into()).unwrap();

        assert_eq!(tc.total_supply().unwrap(), 0);
        assert!(tc.get_tribute(t1.tribute_id).unwrap().is_none());
        assert!(tc.get_tribute(t2.tribute_id).unwrap().is_none());
        assert!(tc
            .get_tribute_ids_by_day(20241220u32.into())
            .unwrap()
            .is_empty());

        let totals = tc.get_day_totals(20241220u32.into()).unwrap();
        assert_eq!(totals.tribute_count, 0);
        assert_eq!(totals.tribute_nominal_amount, U256::ZERO);
    });
}

#[test]
fn sealed_day_rejects_burn_all_by_wwd_without_partial_mutation() {
    with_tribute(|tc| {
        let day = 20241220u32.into();
        let t1 = sample_tribute();
        let mut t2 = sample_tribute();
        set_owner(
            &mut t2,
            address!("0x2222222222222222222222222222222222222222"),
        );

        open_sample_day(tc);
        tc.issue(&t1).unwrap();
        tc.issue(&t2).unwrap();
        tc.seal_day(day).unwrap();

        assert!(tc.burn_all_by_wwd(day).is_err());
        assert_eq!(tc.total_supply().unwrap(), 2);
        assert!(tc.get_tribute(t1.tribute_id).unwrap().is_some());
        assert!(tc.get_tribute(t2.tribute_id).unwrap().is_some());
        assert_eq!(tc.get_day_totals(day).unwrap().tribute_count, 2);
    });
}

#[test]
fn test_events_emitted_for_issue_and_burn() {
    with_provider(|provider, reader, scope| {
        let tribute = sample_tribute();
        StorageHandle::enter(provider, |storage| {
            let mut tc = TributeContract::new(storage.clone());
            tc.unseal_day(tribute.worldwide_day).unwrap();
            tc.issue(scope, reader, &tribute).unwrap();
        });

        let events = provider.get_events(TRIBUTE_ADDRESS).to_vec();
        assert_eq!(
            events.len(),
            3,
            "unseal + issue projection/product events expected"
        );
        let stored = crate::precompile::ITribute::TributeBodyStored::decode_log_data(&events[1])
            .expect("issue must emit a decodable full-body event first");
        assert_eq!(stored.tributeId, tribute.tribute_id.to_u256());
        let event_body =
            crate::from_canonical_body(decode_tribute_v1(&stored.canonicalPayload).unwrap());
        assert_eq!(event_body.tribute_id, tribute.tribute_id);
        assert_eq!(event_body.owner, tribute.owner);
        assert_eq!(event_body.worldwide_day, tribute.worldwide_day);
        assert_eq!(
            event_body.issuance_amount_minor,
            tribute.issuance_amount_minor
        );
        assert_eq!(
            event_body.nominal_amount_minor,
            tribute.nominal_amount_minor
        );
        assert!(!stored.newCommitment.is_zero());
        assert_eq!(
            events[2].topics()[0],
            crate::precompile::ITribute::TributeIssued::SIGNATURE_HASH
        );

        StorageHandle::enter(provider, |storage| {
            TributeContract::new(storage)
                .burn(scope, reader, tribute.tribute_id)
                .unwrap();
        });
        let events = provider.get_events(TRIBUTE_ADDRESS);
        assert_eq!(events.len(), 5, "burn projection/product events expected");
        let deleted = crate::precompile::ITribute::TributeBodyDeleted::decode_log_data(&events[3])
            .expect("burn must emit identity-only deletion first");
        assert_eq!(deleted.tributeId, tribute.tribute_id.to_u256());
        assert_eq!(deleted.previousCommitment, stored.newCommitment);
        assert_eq!(
            events[4].topics()[0],
            crate::precompile::ITribute::TributeBurned::SIGNATURE_HASH
        );
    });
}

#[test]
fn failed_reverted_and_control_operations_leave_no_tribute_projection_event() {
    with_provider(|provider, reader, scope| {
        let tribute = sample_tribute();
        StorageHandle::enter(&mut *provider, |storage| {
            TributeContract::new(storage)
                .unseal_day(tribute.worldwide_day)
                .unwrap();
        });
        provider.clear_events(TRIBUTE_ADDRESS);

        StorageHandle::enter(&mut *provider, |storage| {
            let reverted: PrecompileResult<()> = storage.with_checkpoint(|| {
                let contract = TributeContract::new(storage.clone());
                TributeContract::new(storage.clone()).issue(scope, reader, &tribute)?;
                assert!(contract
                    .get_tribute(scope, reader, tribute.tribute_id)?
                    .is_some());
                Err(PrecompileError::Revert("nested caller reverted".into()))
            });
            assert!(reverted.is_err());
            let contract = TributeContract::new(storage);
            assert!(contract
                .get_tribute(scope, reader, tribute.tribute_id)
                .unwrap()
                .is_none());
            assert_eq!(contract.total_supply().unwrap(), 0);
            assert_eq!(
                contract
                    .get_day_totals(tribute.worldwide_day)
                    .unwrap()
                    .tribute_count,
                0
            );
        });
        assert!(provider.get_events(TRIBUTE_ADDRESS).is_empty());

        let mut oog_tribute = sample_tribute();
        set_owner(
            &mut oog_tribute,
            address!("0x2222222222222222222222222222222222222222"),
        );
        StorageHandle::enter(&mut *provider, |storage| {
            let out_of_gas: PrecompileResult<()> = storage.with_checkpoint(|| {
                let contract = TributeContract::new(storage.clone());
                TributeContract::new(storage.clone()).issue(scope, reader, &oog_tribute)?;
                assert!(contract
                    .get_tribute(scope, reader, oog_tribute.tribute_id)?
                    .is_some());
                Err(PrecompileError::OutOfGas)
            });
            assert!(matches!(out_of_gas, Err(PrecompileError::OutOfGas)));
            let contract = TributeContract::new(storage);
            assert!(contract
                .get_tribute(scope, reader, oog_tribute.tribute_id)
                .unwrap()
                .is_none());
            assert_eq!(contract.total_supply().unwrap(), 0);
            assert_eq!(
                contract
                    .get_day_totals(oog_tribute.worldwide_day)
                    .unwrap()
                    .tribute_count,
                0
            );
        });
        assert!(provider.get_events(TRIBUTE_ADDRESS).is_empty());

        StorageHandle::enter(&mut *provider, |storage| {
            TributeContract::new(storage)
                .issue(scope, reader, &tribute)
                .unwrap();
        });
        provider.clear_events(TRIBUTE_ADDRESS);
        StorageHandle::enter(&mut *provider, |storage| {
            assert!(TributeContract::new(storage)
                .issue(scope, reader, &tribute)
                .is_err());
        });
        assert!(provider.get_events(TRIBUTE_ADDRESS).is_empty());

        StorageHandle::enter(&mut *provider, |storage| {
            TributeContract::new(storage)
                .burn(scope, reader, tribute.tribute_id)
                .unwrap();
        });
        provider.clear_events(TRIBUTE_ADDRESS);
        StorageHandle::enter(&mut *provider, |storage| {
            assert!(TributeContract::new(storage)
                .burn(scope, reader, tribute.tribute_id)
                .is_err());
        });
        assert!(provider.get_events(TRIBUTE_ADDRESS).is_empty());

        StorageHandle::enter(&mut *provider, |storage| {
            TributeContract::new(storage)
                .seal_day(tribute.worldwide_day)
                .unwrap();
        });
        let body_topics = [
            crate::precompile::ITribute::TributeBodyStored::SIGNATURE_HASH,
            crate::precompile::ITribute::TributeBodyDeleted::SIGNATURE_HASH,
        ];
        assert!(provider
            .get_events(TRIBUTE_ADDRESS)
            .iter()
            .all(|event| !body_topics.contains(&event.topics()[0])));
    });
}

#[test]
fn failed_burn_transaction_restores_body_compact_state_and_events() {
    with_provider(|provider, reader, scope| {
        let tribute = sample_tribute();
        StorageHandle::enter(&mut *provider, |storage| {
            let mut contract = TributeContract::new(storage);
            contract.unseal_day(tribute.worldwide_day).unwrap();
            contract.issue(scope, reader, &tribute).unwrap();
        });
        provider.clear_events(TRIBUTE_ADDRESS);

        for out_of_gas in [false, true] {
            StorageHandle::enter(&mut *provider, |storage| {
                let failed: PrecompileResult<()> = storage.with_checkpoint(|| {
                    let contract = TributeContract::new(storage.clone());
                    TributeContract::new(storage.clone()).burn(
                        scope,
                        reader,
                        tribute.tribute_id,
                    )?;
                    assert!(contract
                        .get_tribute(scope, reader, tribute.tribute_id)?
                        .is_none());
                    if out_of_gas {
                        Err(PrecompileError::OutOfGas)
                    } else {
                        Err(PrecompileError::Revert("transaction reverted".into()))
                    }
                });
                assert!(failed.is_err());
                let contract = TributeContract::new(storage);
                let restored = contract
                    .get_tribute(scope, reader, tribute.tribute_id)
                    .unwrap()
                    .expect("failed burn must restore the body");
                assert_eq!(restored.tribute_id, tribute.tribute_id);
                assert_eq!(restored.owner, tribute.owner);
                assert_eq!(restored.nominal_amount_minor, tribute.nominal_amount_minor);
                assert_eq!(contract.total_supply().unwrap(), 1);
                assert_eq!(
                    contract
                        .get_day_totals(tribute.worldwide_day)
                        .unwrap()
                        .tribute_count,
                    1
                );
            });
            assert!(provider.get_events(TRIBUTE_ADDRESS).is_empty());
        }
    });
}
