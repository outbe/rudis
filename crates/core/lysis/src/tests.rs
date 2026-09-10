use crate::algorithm::*;
use alloy_primitives::{Address, LogData, B256, U256};

/// A day whose Gratis allocation is the symbolic share of its nominal: the average fraction is
/// 0.32 and the per-league ceiling is twice that. Production derives both from the day itself
/// (`program_v1::execute`), so these are test inputs, not policy.
const F_FP_DEFAULT: U256 = u256_from_u128(SCALE_U128 * 32 / 100);
const F_MAX_FP: U256 = u256_from_u128(SCALE_U128 * 64 / 100);
use alloy_sol_types::SolEvent;
use outbe_compressed_entities::{
    begin_block, decode_nod_item_v1, derive_poseidon_entity_id, end_block, EntityRef,
    ExecutionScope, IdPage, IdPageRequest, ParentBodySource, ParentBodySourceError, QueryRef,
    StoredBody, WwdEntityId,
};
use outbe_nod::{from_canonical_item, precompile::INod, NodContract, NodRepositoryReader};
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
use outbe_oracle::schema::OracleContract;
use outbe_primitives::addresses::{COMPRESSED_ENTITIES_ADDRESS, NOD_ADDRESS};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::{TributeContract, TributeData, TributeRepositoryReader};
use std::sync::Arc;

const SIX_DECIMAL_SCALE: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

fn coen(whole: u64) -> U256 {
    U256::from(whole) * SIX_DECIMAL_SCALE
}

struct TestBodyRepository {
    tribute_reader: TributeRepositoryReader,
    nod_reader: NodRepositoryReader,
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

impl TestBodyRepository {
    fn new() -> Self {
        let storage = Arc::new(MemoryStorage::new());
        let reader: StorageReaderHandle = storage.clone();
        Self {
            tribute_reader: TributeRepositoryReader::new(reader.clone()),
            nod_reader: NodRepositoryReader::new(reader),
        }
    }

    fn issue(
        &self,
        contract: &mut TributeContract<'_>,
        scope: &ExecutionScope,
        tribute: &TributeData,
    ) {
        contract.issue(scope, self, tribute).unwrap();
    }
}

impl ParentBodySource for TestBodyRepository {
    fn get(&self, entity: EntityRef) -> Result<Option<StoredBody>, ParentBodySourceError> {
        match entity {
            EntityRef::Tribute(_) => ParentBodySource::get(&self.tribute_reader, entity),
            EntityRef::NodItem(_) | EntityRef::NodBucket(_) => {
                ParentBodySource::get(&self.nod_reader, entity)
            }
        }
    }

    fn list(
        &self,
        query: QueryRef,
        request: IdPageRequest,
    ) -> Result<IdPage, ParentBodySourceError> {
        match query {
            QueryRef::TributeByOwner(_) | QueryRef::TributeByDay(_) => {
                ParentBodySource::list(&self.tribute_reader, query, request)
            }
            QueryRef::NodByOwner(_) | QueryRef::NodAll => {
                ParentBodySource::list(&self.nod_reader, query, request)
            }
        }
    }
}

fn gas_audit_address(n: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0x22;
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    Address::from(bytes)
}

fn gas_audit_tribute(
    _tribute_seed: u64,
    owner: Address,
    worldwide_day: WorldwideDay,
    nominal_amount_minor: U256,
) -> TributeData {
    TributeData {
        tribute_id: entity_id(worldwide_day, owner),
        owner,
        worldwide_day,
        issuance_amount_minor: nominal_amount_minor / U256::from(2u64),
        issuance_currency: 840,
        nominal_amount_minor,
        reference_currency: 840,
        exclude_from_intex_issuance: false,
        tribute_price_minor: U256::ZERO,
    }
}

fn entity_id(worldwide_day: WorldwideDay, owner: Address) -> WwdEntityId {
    derive_poseidon_entity_id(owner, worldwide_day).unwrap()
}

fn decode_nod_body_event(event: &LogData) -> outbe_nod::NodItemState {
    let decoded = INod::NodBodyStored::decode_log_data(event).unwrap();
    let event_id = WwdEntityId::from(decoded.nodId);
    let item = from_canonical_item(decode_nod_item_v1(&decoded.canonicalPayload).unwrap());
    assert_eq!(event_id, item.nod_id);
    item
}

#[test]
fn zero_or_over_budget_gratis_load_is_a_hard_failure_without_consumption() {
    let mut remaining = U256::from(10);
    assert!(crate::runtime::consume_required_gratis(&mut remaining, U256::ZERO).is_err());
    assert_eq!(remaining, U256::from(10));
    assert!(crate::runtime::consume_required_gratis(&mut remaining, U256::from(11)).is_err());
    assert_eq!(remaining, U256::from(10));
    crate::runtime::consume_required_gratis(&mut remaining, U256::from(4)).unwrap();
    assert_eq!(remaining, U256::from(6));
}

#[test]
fn later_nod_failure_rolls_back_the_complete_lysis_attempt() {
    const T_NOW: u64 = 1_700_000_000;
    let wwd = WorldwideDay::new(20_260_717);
    let owner = Address::repeat_byte(0x31);
    let nominal = coen(100_u64);
    let mut storage = HashMapStorageProvider::new(1);
    outbe_fidelity::enclave_client::test_enclave::install();
    storage.set_timestamp(U256::from(T_NOW));
    let bodies = TestBodyRepository::new();

    StorageHandle::enter(&mut storage, |storage| {
        let scope = ExecutionScope::new();
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();

        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let oracle = OracleContract::new(storage.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        let pair_index = oracle
            .pair_index_of(outbe_oracle::api::AddressPair::new_coen_to(840))
            .unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&pair_index, U256::from(500_000u64))
            .unwrap();

        let first = gas_audit_tribute(1, owner, wwd, nominal);
        let mut second = gas_audit_tribute(2, Address::repeat_byte(0x32), wwd, nominal);
        // The first Nod is staged through ISO 840. The second Tribute reaches
        // its Nod preparation and then fails because ISO 978 has no oracle pair.
        second.reference_currency = 978;
        let mut tribute = TributeContract::new(storage.clone());
        tribute.unseal_day(wwd).unwrap();
        bodies.issue(&mut tribute, &scope, &first);
        bodies.issue(&mut tribute, &scope, &second);
        tribute.seal_day(wwd).unwrap();

        let before = tribute.get_day_totals(wwd).unwrap();
        let error = match crate::runtime::lysis(
            storage.clone(),
            &scope,
            &bodies,
            wwd,
            nominal / U256::from(5_u64),
        ) {
            Ok(_) => panic!("the second Tribute must fail without an ISO 978 oracle pair"),
            Err(error) => error,
        };
        assert!(!error.to_string().is_empty());

        let after = TributeContract::new(storage.clone())
            .get_day_totals(wwd)
            .unwrap();
        assert_eq!(after.tribute_count, before.tribute_count);
        assert_eq!(after.tribute_nominal_amount, before.tribute_nominal_amount);
        assert_eq!(
            TributeContract::new(storage.clone())
                .total_supply()
                .unwrap(),
            2
        );
        assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
        assert!(outbe_intex::api::read_contributors(&storage, wwd)
            .unwrap()
            .is_empty());
    });
    assert!(storage.get_events(NOD_ADDRESS).is_empty());
}

#[test]
fn non_usd_lysis_price_ignores_a_higher_scurve() {
    let wwd = WorldwideDay::new(20_260_718);
    let mut storage = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut storage, |storage| {
        let pair = outbe_oracle::api::AddressPair::new_coen_to(978);
        let index = outbe_oracle::api::register_pair(storage.clone(), pair).unwrap();
        let oracle = OracleContract::new(storage.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&index, U256::from(250_000_u64))
            .unwrap();
        outbe_oracle::scurve::store_scurve_entry(
            &mut OracleContract::new(storage.clone()),
            pair,
            wwd.to_timestamp_utc(),
            U256::from(320_000_u64),
        )
        .unwrap();

        assert_eq!(
            crate::runtime::resolve_entry_price_minor_for_test(storage, wwd, 978).unwrap(),
            U256::from(250_000_u64),
            "Lysis must use the EUR WWD VWAP rather than its higher S-curve"
        );
    });
}

#[test]
fn positive_scurve_cannot_replace_a_missing_or_zero_lysis_vwap() {
    const T_NOW: u64 = 1_700_000_000;
    let wwd = WorldwideDay::new(20_260_719);
    let nominal = coen(100_u64);

    for explicitly_write_zero in [false, true] {
        let mut storage = HashMapStorageProvider::new(1);
        outbe_fidelity::enclave_client::test_enclave::install();
        storage.set_timestamp(U256::from(T_NOW));
        let bodies = TestBodyRepository::new();
        StorageHandle::enter(&mut storage, |storage| {
            let scope = ExecutionScope::new();
            seed_compressed_entities_genesis(&storage);
            begin_block(storage.clone(), &scope).unwrap();

            let usd = outbe_oracle::api::DAY_TYPE_PAIR;
            let eur = outbe_oracle::api::AddressPair::new_coen_to(978);
            let usd_index = outbe_oracle::api::register_pair(storage.clone(), usd).unwrap();
            let eur_index = outbe_oracle::api::register_pair(storage.clone(), eur).unwrap();
            let oracle = OracleContract::new(storage.clone());
            oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
            let values = oracle.worldwide_day_vwap_value.get_nested(&wwd);
            values.write(&usd_index, U256::from(500_000_u64)).unwrap();
            if explicitly_write_zero {
                values.write(&eur_index, U256::ZERO).unwrap();
            }
            outbe_oracle::scurve::store_scurve_entry(
                &mut OracleContract::new(storage.clone()),
                eur,
                wwd.to_timestamp_utc(),
                U256::from(900_000_u64),
            )
            .unwrap();

            let owner = Address::repeat_byte(if explicitly_write_zero { 0x42 } else { 0x41 });
            let mut input = gas_audit_tribute(1, owner, wwd, nominal);
            input.reference_currency = 978;
            let mut tribute = TributeContract::new(storage.clone());
            tribute.unseal_day(wwd).unwrap();
            bodies.issue(&mut tribute, &scope, &input);
            tribute.seal_day(wwd).unwrap();
            let before = tribute.get_day_totals(wwd).unwrap();

            let error = match crate::runtime::lysis(
                storage.clone(),
                &scope,
                &bodies,
                wwd,
                nominal / U256::from(10_u64),
            ) {
                Ok(_) => panic!("S-curve must not substitute for a missing or zero WWD VWAP"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("WWD VWAP"));
            let after = TributeContract::new(storage.clone())
                .get_day_totals(wwd)
                .unwrap();
            assert_eq!(after.tribute_count, before.tribute_count);
            assert_eq!(after.tribute_nominal_amount, before.tribute_nominal_amount);
            assert_eq!(
                TributeContract::new(storage.clone())
                    .total_supply()
                    .unwrap(),
                1
            );
            assert_eq!(NodContract::new(storage.clone()).total_supply().unwrap(), 0);
            assert!(outbe_intex::api::read_contributors(&storage, wwd)
                .unwrap()
                .is_empty());
        });
        assert!(storage.get_events(NOD_ADDRESS).is_empty());
    }
}

#[test]
fn gas_08_lysis_dense_day_completes_and_emits_body_mutations() {
    const DENSE_TRIBUTE_COUNT: u64 = 512;
    const T_NOW: u64 = 1_700_000_000;
    let wwd = WorldwideDay::new(20260525);
    let nominal = coen(100u64);
    let total_nominal = nominal * U256::from(DENSE_TRIBUTE_COUNT);
    let gratis_allocation = total_nominal / U256::from(10u64);
    let cost_of_gratis = U256::from(500_000u64);
    let mut storage = HashMapStorageProvider::new(1);
    outbe_fidelity::enclave_client::test_enclave::install();
    storage.set_timestamp(U256::from(T_NOW));
    let bodies = TestBodyRepository::new();

    let result = StorageHandle::enter(&mut storage, |storage| {
        let scope = ExecutionScope::new();
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let oracle = OracleContract::new(storage.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        let pair_index = oracle
            .pair_index_of(outbe_oracle::api::AddressPair::new_coen_to(840))
            .unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&pair_index, cost_of_gratis)
            .unwrap();
        let mut tribute = TributeContract::new(storage.clone());
        tribute.unseal_day(wwd).unwrap();
        for token_id in 1..=DENSE_TRIBUTE_COUNT {
            let owner = gas_audit_address(token_id);
            bodies.issue(
                &mut tribute,
                &scope,
                &gas_audit_tribute(token_id, owner, wwd, nominal),
            );
        }
        assert_eq!(
            tribute
                .get_all_day_tributes(&scope, &bodies, wwd)
                .unwrap()
                .len(),
            DENSE_TRIBUTE_COUNT as usize,
            "GAS-08 fixture must seed a dense but valid Lysis day"
        );
        tribute.seal_day(wwd).unwrap();

        let result =
            crate::runtime::lysis(storage.clone(), &scope, &bodies, wwd, gratis_allocation)
                .expect("GAS-08 dense Lysis day must complete");

        assert_eq!(
            result.tribute_ids.len(),
            DENSE_TRIBUTE_COUNT as usize,
            "GAS-08: dense Lysis should load every tribute in the day"
        );
        assert_eq!(
            result.nod_ids.len(),
            DENSE_TRIBUTE_COUNT as usize,
            "GAS-08: dense Lysis should issue one NOD for every funded tribute"
        );

        let tribute = TributeContract::new(storage.clone());
        assert_eq!(
            tribute.total_supply().unwrap(),
            0,
            "GAS-08: all processed tributes must be burned after dense Lysis"
        );

        let nod = NodContract::new(storage.clone());
        assert_eq!(
            nod.total_supply().unwrap(),
            DENSE_TRIBUTE_COUNT,
            "GAS-08: dense Lysis must persist every issued NOD"
        );
        end_block(storage, &scope).unwrap();
        result
    });

    let stored_items = storage
        .get_events(NOD_ADDRESS)
        .iter()
        .filter(|event| event.topics()[0] == INod::NodBodyStored::SIGNATURE_HASH)
        .map(decode_nod_body_event)
        .collect::<Vec<_>>();
    assert_eq!(stored_items.len(), DENSE_TRIBUTE_COUNT as usize);
    let mut issued_gratis = U256::ZERO;
    let by_owner: std::collections::BTreeMap<_, _> =
        stored_items.iter().map(|item| (item.owner, item)).collect();
    for token_id in 1..=DENSE_TRIBUTE_COUNT {
        let item = by_owner
            .get(&gas_audit_address(token_id))
            .expect("every dense-day owner must receive one Nod");
        assert_eq!(item.worldwide_day, wwd);
        assert_eq!(item.league_id, 1);
        assert!(!item.gratis_load_minor.is_zero());
        issued_gratis += item.gratis_load_minor;
    }
    assert_eq!(issued_gratis + result.remaining_gratis, gratis_allocation);
}

#[test]
fn test_empty_population() {
    let result = calc_fraction_distribution_fp(&[], &[], 0, F_FP_DEFAULT, F_MAX_FP).unwrap();
    assert_eq!(result, vec![U256::ZERO]);
}

#[test]
fn test_single_fi_returns_target_fraction() {
    let y_fp = vec![SCALE]; // 100%
    let p = vec![5];
    let result = calc_fraction_distribution_fp(&y_fp, &p, 1, F_FP_DEFAULT, F_MAX_FP).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], F_FP_DEFAULT, "single FI should return f");
}

#[test]
fn test_two_fi_groups() {
    let y_fp = vec![
        SCALE * U256::from(6u64) / U256::from(10u64),
        SCALE * U256::from(4u64) / U256::from(10u64),
    ]; // 60/40
    let p = vec![1, 2];
    let result = calc_fraction_distribution_fp(&y_fp, &p, 2, F_FP_DEFAULT, F_MAX_FP).unwrap();

    assert_eq!(result.len(), 2);

    // All fractions non-negative
    for (i, &frac) in result.iter().enumerate() {
        assert!(
            !frac.is_zero(),
            "fraction[{i}] should be positive, got {frac}"
        );
    }

    // Bounded by 2*fmax (reasonable bound for fixed-point)
    let bound = F_MAX_FP * U256::from(2u64);
    for (i, &frac) in result.iter().enumerate() {
        assert!(frac <= bound, "fraction[{i}] too large: {frac}");
    }
}

#[test]
fn test_three_fi_groups() {
    let y_fp = vec![
        SCALE * U256::from(50u64) / U256::from(100u64),
        SCALE * U256::from(30u64) / U256::from(100u64),
        SCALE * U256::from(20u64) / U256::from(100u64),
    ];
    let p = vec![50, 30, 20];

    let result = calc_fraction_distribution_fp(&y_fp, &p, 3, F_FP_DEFAULT, F_MAX_FP).unwrap();

    assert_eq!(result.len(), 3);

    let bound = F_MAX_FP * U256::from(2u64);
    for (i, &frac) in result.iter().enumerate() {
        assert!(frac <= bound, "fraction[{i}] > bound: {frac}");
    }
}

#[test]
fn test_many_fi_groups() {
    let n = 10;
    let y_fp: Vec<U256> = vec![SCALE / U256::from(n as u64); n];
    let p: Vec<u64> = (1..=n as u64).collect();

    let result = calc_fraction_distribution_fp(&y_fp, &p, 100, F_FP_DEFAULT, F_MAX_FP).unwrap();

    assert_eq!(result.len(), n);

    let bound = F_MAX_FP * U256::from(2u64);
    for (i, &frac) in result.iter().enumerate() {
        assert!(frac <= bound, "fraction[{i}] too large");
    }
}

/// f_fp must be clamped to [LYSIS_LIMIT_MIN, LYSIS_LIMIT_MAX/2].
#[test]
fn test_default_constants() {
    // Verify constants match expected values within integer precision
    assert_eq!(SCALE, SIX_DECIMAL_SCALE);
}

#[test]
fn test_with_zero_population_entries() {
    let half = SCALE / U256::from(2u64);
    let y_fp = vec![half, U256::ZERO, half];
    let p = vec![10, 0, 5];

    let result = calc_fraction_distribution_fp(&y_fp, &p, 15, F_FP_DEFAULT, F_MAX_FP).unwrap();

    assert_eq!(result.len(), 3);
    let bound = F_MAX_FP * U256::from(2u64);
    for (i, &frac) in result.iter().enumerate() {
        assert!(frac <= bound, "fraction[{i}] > bound: {frac}");
    }
}

#[test]
fn test_skewed_distribution() {
    let y_fp = vec![
        SCALE * U256::from(9u64) / U256::from(10u64),
        SCALE / U256::from(10u64),
    ];
    let p = vec![900, 100];

    let result = calc_fraction_distribution_fp(&y_fp, &p, 1000, F_FP_DEFAULT, F_MAX_FP).unwrap();

    assert_eq!(result.len(), 2);
    assert!(!result[0].is_zero());
    assert!(!result[1].is_zero());
}

/// Regression: large nominal amounts (> 2^53) must not lose precision.
#[test]
fn test_large_nominal_distribution() {
    // Simplified: 60/40 split -> use SCALE fractions directly.
    let y_fp = vec![
        SCALE * U256::from(6u64) / U256::from(10u64),
        SCALE * U256::from(4u64) / U256::from(10u64),
    ];
    let p = vec![600, 400];

    let result = calc_fraction_distribution_fp(&y_fp, &p, 1000, F_FP_DEFAULT, F_MAX_FP).unwrap();

    assert_eq!(result.len(), 2);
    let bound = F_MAX_FP * U256::from(2u64);
    for (i, &frac) in result.iter().enumerate() {
        assert!(
            !frac.is_zero(),
            "fraction[{i}] must be positive for large nominals"
        );
        assert!(frac <= bound, "fraction[{i}] must be bounded");
    }
}

// ---------------------------------------------------------------------------
// weighted-expenditure cap invariant
// ---------------------------------------------------------------------------

/// Assert the post-condition `sum(f1[i] * y_fp[i]) / SCALE <= f_fp` for the
/// output of `calc_fraction_distribution_fp`. Small round-down error is
/// acceptable; overshoot is not.
fn assert_weighted_within_target(result: &[U256], y_fp: &[U256], f_fp: U256) {
    let weighted: U256 = result
        .iter()
        .zip(y_fp.iter())
        .map(|(f, y)| *f * *y / SCALE)
        .sum();
    assert!(
        weighted <= f_fp,
        "weighted expenditure {weighted} exceeds target {f_fp}"
    );
}

#[test]
fn test_normalized_f1_respects_budget_skewed_population() {
    // Skewed population + imbalanced interest tends to push raw f1 over the
    // target. After normalization the post-condition must hold.
    let q = SCALE / U256::from(4u64);
    let y_fp = vec![q, q, q, q];
    let p = vec![100u64, 1, 1, 1];
    let f_fp = F_FP_DEFAULT;
    let fmax_fp = F_MAX_FP;
    let result = calc_fraction_distribution_fp(&y_fp, &p, 103, f_fp, fmax_fp).unwrap();
    assert_eq!(result.len(), 4);
    assert_weighted_within_target(&result, &y_fp, f_fp);
}

#[test]
fn test_normalized_f1_respects_budget_many_groups() {
    let n = 10usize;
    let y_fp: Vec<U256> = (0..n).map(|_| SCALE / U256::from(n as u64)).collect();
    let p: Vec<u64> = (1..=n as u64).collect();
    let f_fp = F_FP_DEFAULT;
    let fmax_fp = F_MAX_FP;
    let result = calc_fraction_distribution_fp(&y_fp, &p, 100, f_fp, fmax_fp).unwrap();
    assert_eq!(result.len(), n);
    assert_weighted_within_target(&result, &y_fp, f_fp);
}

#[test]
fn test_single_group_returns_f_without_normalization() {
    // The single-group fast path bypasses the normalization loop; `f_fp` is
    // returned as-is. Weighted total = f_fp * SCALE / SCALE = f_fp == target.
    let y_fp = vec![SCALE];
    let p = vec![10];
    let f_fp = F_FP_DEFAULT;
    let result = calc_fraction_distribution_fp(&y_fp, &p, 10, f_fp, F_MAX_FP).unwrap();
    assert_eq!(result, vec![f_fp]);
    assert_weighted_within_target(&result, &y_fp, f_fp);
}

#[test]
fn test_normalized_f1_preserves_ratios_when_scaled_down() {
    // When raw output overshoots and is scaled down, pairwise ratios between
    // groups should remain ~constant.
    let half = SCALE / U256::from(2u64);
    let y_fp = vec![half, half];
    let p = vec![50u64, 5];
    let f_fp = F_FP_DEFAULT;
    let fmax_fp = F_MAX_FP;
    let result = calc_fraction_distribution_fp(&y_fp, &p, 55, f_fp, fmax_fp).unwrap();
    assert_eq!(result.len(), 2);
    assert_weighted_within_target(&result, &y_fp, f_fp);
    // Both fractions should still be positive (not obliterated by scale-down).
    for &frac in &result {
        assert!(
            !frac.is_zero(),
            "fraction must remain positive after normalization"
        );
    }
}

// ---------------------------------------------------------------------------
// I256 precision - no silent zero-collapse on small FI groups
// ---------------------------------------------------------------------------

/// Input with a dominant group and one tiny-interest group. Under the
/// pre- i128 pipeline with `/1_000_000` scale-down the small group's
/// `f1` could collapse to 0 (up to 10^6 SCALE units of precision lost per
/// term). After I256 refactor the distribution must preserve the signal.
#[test]
fn test_small_fi_group_survives_i256_precision() {
    let tiny = U256::from(1_000_000u64);
    let y_fp = vec![
        SCALE - tiny, // dominant group ~= 99.9999%
        tiny,         // tiny group ~= 0.0001% - used to collapse to 0
    ];
    let p = vec![1000u64, 1];
    let f_fp = F_FP_DEFAULT;
    let fmax_fp = F_MAX_FP;
    let result = calc_fraction_distribution_fp(&y_fp, &p, 1001, f_fp, fmax_fp).unwrap();
    assert_eq!(result.len(), 2);
    assert!(
        !result[1].is_zero(),
        "tiny FI group must receive a non-zero fraction, got {}",
        result[1]
    );
}

/// When mass of Y is concentrated on the high end, `beta_num = f/fmax - E[Y]`
/// is negative and the algorithm must still produce a well-defined, bounded
/// distribution. Pre- the `/1_000_000` rounding could obliterate the
/// signed contribution for the lower-Y group.
#[test]
fn test_negative_beta_branch_produces_bounded_distribution() {
    let y_fp = vec![
        SCALE / U256::from(100u64),
        SCALE * U256::from(99u64) / U256::from(100u64),
    ]; // 1% / 99% split
    let p = vec![1u64, 1];
    let f_fp = F_FP_DEFAULT;
    let fmax_fp = F_MAX_FP;
    let result = calc_fraction_distribution_fp(&y_fp, &p, 2, f_fp, fmax_fp).unwrap();
    assert_eq!(result.len(), 2);
    let bound = F_MAX_FP * U256::from(2u64);
    for &f in &result {
        assert!(f <= bound, "fraction {f} exceeds LYSIS_LIMIT_MAX*2 bound");
    }
}

// ---------------------------------------------------------------------------
// Scale invariant: cost_amount_minor must be in 10^6-minor units, not 10^12
// ---------------------------------------------------------------------------

/// Regression test for the scale-mismatch bug in `lysis::runtime`. Both
/// `cost_of_gratis_minor` (an oracle VWAP at 10^6 scale) and `gratis_load`
/// (a token amount at 10^6 minor scale) are six-decimal U256 values. Their
/// product lives in 10^12 and must be divided by SCALE once to land in
/// minor units. The contract is documented at
/// `crates/core/nod/src/schema.rs:6-7`:
///   `cost_amount_minor = cost_of_gratis_minor * gratis_load_minor / SIX_DECIMAL_SCALE`
///
/// Pre-fix: `lysis::runtime` computed `cost_of_gratis_minor * gratis_load`
/// without the divisor, producing a value ~10^6x too large that was stored
/// on-chain and emitted to the `NodIssued` event. This was silent because
/// `settle_mine_payment` is a no-op today, but every nominal-scale consumer
/// (token URI, `nodData`, future settlement) was wrong.
#[test]
fn lysis_reads_repository_body_with_empty_legacy_evm_body_state() {
    use alloy_primitives::{address, U256};
    use outbe_oracle::schema::OracleContract;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::time::WorldwideDay;
    use outbe_tribute::TributeData;

    use crate::runtime::lysis;

    let wwd = WorldwideDay::new(20241220);
    const T_NOW: u64 = 1_700_000_000;
    let owner = address!("0x1111111111111111111111111111111111111111");
    // 100 COEN nominal, $0.5 oracle VWAP.
    let nominal = coen(100u64);
    let cost_of_gratis = U256::from(500_000u64);

    let mut storage = HashMapStorageProvider::new(1);
    outbe_fidelity::enclave_client::test_enclave::install();
    storage.set_timestamp(U256::from(T_NOW));
    let bodies = TestBodyRepository::new();
    let (result, pure_result) = StorageHandle::enter(&mut storage, |s| {
        let scope = ExecutionScope::new();
        seed_compressed_entities_genesis(&s);
        begin_block(s.clone(), &scope).unwrap();
        // 1. Register COEN/840 pair and seed its WorldwideDay VWAP. We
        //    write directly into the oracle schema (no real vote tally),
        //    because lysis only reads `get_worldwide_day_vwap_for_pair_id`.
        outbe_oracle::api::register_pair(s.clone(), outbe_oracle::api::DAY_TYPE_PAIR).unwrap();
        let oracle = OracleContract::new(s.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        let pair_index = oracle
            .pair_index_of(outbe_oracle::api::AddressPair::new_coen_to(840))
            .unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&pair_index, cost_of_gratis)
            .unwrap();
        outbe_oracle::scurve::store_scurve_entry(
            &mut OracleContract::new(s.clone()),
            outbe_oracle::api::DAY_TYPE_PAIR,
            wwd.to_timestamp_utc(),
            U256::from(900_000u64),
        )
        .unwrap();
        assert_eq!(
            outbe_oracle::api::get_max_active_scurve_value(
                s.clone(),
                wwd,
                outbe_oracle::api::DAY_TYPE_PAIR,
            )
            .unwrap(),
            U256::from(900_000u64),
            "fixture must prove an S-curve above the WWD VWAP"
        );

        // Seed compact lifecycle state plus the canonical direct-map commitment,
        // then materialize only the off-chain body. No legacy full EVM body or
        // body index is involved.
        let tribute = TributeData {
            tribute_id: entity_id(wwd, owner),
            owner,
            worldwide_day: wwd,
            issuance_amount_minor: coen(50u64),
            issuance_currency: 840,
            nominal_amount_minor: nominal,
            reference_currency: 840,
            exclude_from_intex_issuance: false,
            tribute_price_minor: U256::ZERO,
        };
        let mut tribute_contract = TributeContract::new(s.clone());
        tribute_contract.unseal_day(wwd).unwrap();
        bodies.issue(&mut tribute_contract, &scope, &tribute);
        tribute_contract.seal_day(wwd).unwrap();

        // 3. Pick a gratis allocation that produces a positive gratis_load.
        //    Single-FI fast path returns `f_fp = LYSIS_LIMIT_MIN` (8%), so
        //    gratis_load = 100 * 0.08 = 8 COEN.
        let gratis_allocation = nominal / U256::from(10u64);
        let league_id = outbe_fidelity::api::league(s.clone(), owner).unwrap();
        let pure_result = crate::program_v1::execute(crate::program_v1::ProgramInputV1 {
            worldwide_day: wwd,
            logical_evaluation_time: T_NOW,
            gratis_allocation,
            mandatory_entry_price_840: crate::program_v1::ObservationValueV1::Value(cost_of_gratis),
            tributes: vec![crate::program_v1::ObservedTributeV1 {
                tribute: crate::program_v1::TributeInputV1 {
                    tribute_id: entity_id(wwd, owner),
                    owner,
                    worldwide_day: wwd,
                    issuance_currency: 840,
                    nominal_amount_minor: nominal,
                    reference_currency: 840,
                    tribute_price_minor: U256::ZERO,
                    exclude_from_intex_issuance: false,
                },
                first_league: crate::program_v1::ObservationValueV1::Value(league_id),
                second_league: crate::program_v1::ObservationValueV1::Value(league_id),
                conditional_entry_price_minor: crate::program_v1::ObservationValueV1::Unavailable,
                nod_target_available: true,
            }],
        })
        .expect("pure Lysis V1");

        let result = lysis(s.clone(), &scope, &bodies, wwd, gratis_allocation).unwrap();
        assert_eq!(result.nod_ids.len(), 1, "expected one NOD issued");
        end_block(s, &scope).unwrap();
        (result, pure_result)
    });

    // 4. Decode the canonical projection event and assert the documented scale invariant.
    let item = storage
        .get_events(NOD_ADDRESS)
        .iter()
        .find(|event| event.topics()[0] == INod::NodBodyStored::SIGNATURE_HASH)
        .map(decode_nod_body_event)
        .expect("NOD body event");
    assert_eq!(item.nod_id, result.nod_ids[0]);
    assert_eq!(item.reference_currency, 840);
    let expected_action = &pure_result.nod_actions[0];
    assert_eq!(item.nod_id, expected_action.nod_id);
    assert_eq!(item.owner, expected_action.owner);
    assert_eq!(item.worldwide_day, expected_action.worldwide_day);
    assert_eq!(item.league_id, expected_action.league_id);
    assert_eq!(item.floor_price_minor, expected_action.floor_price_minor);
    assert_eq!(item.gratis_load_minor, expected_action.gratis_load_minor);
    assert_eq!(item.bucket_key, expected_action.bucket_key);
    assert_eq!(item.issuance_currency, expected_action.issuance_currency);
    assert_eq!(item.reference_currency, expected_action.reference_currency);
    assert_eq!(item.issued_at, expected_action.issued_at);

    // The cost is derived from the bucket entry price and the load, never
    // stored: this pins that derivation to what lysis itself computed.
    let cost = outbe_nod::api::cost_amount_minor(
        expected_action.entry_price_minor,
        item.gratis_load_minor,
    )
    .expect("derive the Nod cost");
    assert_eq!(cost, expected_action.cost_amount_minor);

    let expected = cost_of_gratis * item.gratis_load_minor / SIX_DECIMAL_SCALE;
    assert_eq!(
        cost,
        expected,
        "the Nod cost must use the WWD VWAP below the active S-curve and equal \
         cost_of_gratis * gratis_load / SIX_DECIMAL_SCALE; \
         pre-fix value (missing /SCALE) would be {}",
        cost_of_gratis * item.gratis_load_minor
    );

    let upper_bound = coen(1_000u64);
    assert!(
        cost <= upper_bound,
        "Nod cost {cost} looks like a 10^12-scaled value; likely a scale-mismatch regression"
    );
}

/// 15 distinct-amount tributes, all bearing fidelity index 1. Sum is a clean
/// 1200 COEN so the percentage scenarios (5%/30%/32%) divide exactly with no
/// integer truncation in the deficit derivation - the assertions can use
/// strict equality rather than tolerance bands.
fn uniform_fi_one_population_15() -> (Vec<U256>, Vec<u16>, U256) {
    let nominal_amounts: Vec<U256> = (1u64..=15).map(|i| coen(10u64 * i)).collect();
    let tribute_fis = vec![1u16; 15];
    let total_interest: U256 = nominal_amounts
        .iter()
        .copied()
        .fold(U256::ZERO, |acc, v| acc + v);
    // Sanity: 10 * (1+2+...+15) = 1200 COEN.
    debug_assert_eq!(total_interest, coen(1200u64));
    (nominal_amounts, tribute_fis, total_interest)
}

#[test]
fn test_compute_fi_fraction_map_single_fi_five_percent_allocation() {
    let (nominal_amounts, tribute_fis, total_interest) = uniform_fi_one_population_15();
    // 5% deficit - well below the historical 8% floor.
    let gratis_allocation = total_interest * U256::from(5u64) / U256::from(100u64);

    let map = crate::runtime::compute_fi_fraction_map(
        &nominal_amounts,
        &tribute_fis,
        total_interest,
        gratis_allocation,
    )
    .unwrap();

    assert_eq!(map.len(), 1, "all FI=1 must collapse to one map entry");
    let expected = SCALE * U256::from(5u64) / U256::from(100u64); // 0.05 * 10^6
    assert_eq!(
        map.get(&1).copied(),
        Some(expected),
        "scarce-gratis fraction must equal the 5% deficit coefficient"
    );
    println!("deficit fraction map: {:?}", map);
}

#[test]
fn test_compute_fi_fraction_map_single_fi_thirty_percent_allocation() {
    let (nominal_amounts, tribute_fis, total_interest) = uniform_fi_one_population_15();
    // 30% deficit - well above the historical 8%/16% range; the new logic
    // must not silently cap the fraction at 16%.
    let gratis_allocation = total_interest * U256::from(30u64) / U256::from(100u64);

    let map = crate::runtime::compute_fi_fraction_map(
        &nominal_amounts,
        &tribute_fis,
        total_interest,
        gratis_allocation,
    )
    .unwrap();

    assert_eq!(map.len(), 1);
    let expected = SCALE * U256::from(30u64) / U256::from(100u64); // 0.30 * 10^6
    assert_eq!(
        map.get(&1).copied(),
        Some(expected),
        "abundant-gratis fraction must track the 30% deficit, not pin at 16%"
    );
}

#[test]
fn test_compute_fi_fraction_map_single_fi_thirtytwo_percent_allocation() {
    let (nominal_amounts, tribute_fis, total_interest) = uniform_fi_one_population_15();
    // 32% - matches the canonical metadosis symbolic rate (D1 in
    // metadosis-lysis-discrepancies.md). The fraction must reach 0.32, exactly.
    let gratis_allocation = total_interest * U256::from(32u64) / U256::from(100u64);

    let map = crate::runtime::compute_fi_fraction_map(
        &nominal_amounts,
        &tribute_fis,
        total_interest,
        gratis_allocation,
    )
    .unwrap();

    assert_eq!(map.len(), 1);
    let expected = SCALE * U256::from(32u64) / U256::from(100u64); // 0.32 * 10^6
    assert_eq!(
        map.get(&1).copied(),
        Some(expected),
        "32% gratis allocation must produce a 32% fraction"
    );
}

/// Multi-FI scenario: 100 distinct-nominal tributes spread across 15 fidelity
/// indices, 32% gratis allocation.
#[test]
fn test_compute_fi_fraction_map_100_tributes_15_fis_thirtytwo_percent_allocation() {
    use std::collections::BTreeMap;

    // Distinct nominals 1..=100 COEN. Sum = 5050 COEN; 32% = 1616 COEN exactly.
    let nominal_amounts: Vec<U256> = (1u64..=100).map(coen).collect();
    // Round-robin FI assignment over 1..=15: FIs 1..=10 each get 7 tributes,
    // FIs 11..=15 each get 6 - covers every bucket with uneven population.
    let tribute_fis: Vec<u16> = (0u16..100).map(|i| (i % 15) + 1).collect();
    let total_interest: U256 = nominal_amounts
        .iter()
        .copied()
        .fold(U256::ZERO, |acc, v| acc + v);
    debug_assert_eq!(total_interest, coen(5050u64));

    let gratis_allocation = total_interest * U256::from(32u64) / U256::from(100u64);
    debug_assert_eq!(gratis_allocation, coen(1616u64));

    let map = crate::runtime::compute_fi_fraction_map(
        &nominal_amounts,
        &tribute_fis,
        total_interest,
        gratis_allocation,
    )
    .unwrap();

    // 1. Every distinct FI must appear in the map.
    assert_eq!(
        map.len(),
        15,
        "every FI bucket present in input must receive a fraction"
    );
    for fi in 1u16..=15 {
        assert!(map.contains_key(&fi), "FI {fi} missing from fraction map");
    }

    // 2. Every fraction must be positive - the I256 pipeline must not collapse
    //    any group to zero, and the moment solver must not produce a negative
    //    that clamps to 0 (would starve a whole FI bucket).
    for (fi, frac) in &map {
        assert!(
            !frac.is_zero(),
            "FI {fi} got zero fraction: algorithm collapsed a group (got {frac})"
        );
    }

    // 3. Algorithm-level budget invariant. Reconstruct the y_fp vector exactly
    //    as the runtime does (BTreeMap-ordered group share with the truncation
    //    delta absorbed into the last entry) and assert the normalized
    //    `sum(f_g * y_fp_g)/SCALE <= f_fp` post-condition. This is the
    //    `assert_weighted_within_target` invariant lifted to multi-FI inputs.
    let mut group_interest: BTreeMap<u16, U256> = BTreeMap::new();
    for (i, &fi) in tribute_fis.iter().enumerate() {
        *group_interest.entry(fi).or_insert(U256::ZERO) += nominal_amounts[i];
    }
    let mut y_fp: Vec<U256> = group_interest
        .values()
        .map(|gi| *gi * SIX_DECIMAL_SCALE / total_interest)
        .collect();
    let y_sum: U256 = y_fp.iter().copied().sum();
    if let Some(last) = y_fp.last_mut() {
        if y_sum < SCALE {
            *last += SCALE - y_sum;
        }
    }
    let weighted: U256 = group_interest
        .keys()
        .zip(y_fp.iter())
        .map(|(fi, y)| {
            let f = map.get(fi).copied().unwrap_or(U256::ZERO);
            f * *y / SCALE
        })
        .sum();
    let f_fp = SCALE * U256::from(32u64) / U256::from(100u64); // 0.32 * 10^6
    assert!(
        weighted <= f_fp,
        "weighted sum(f*y_fp)/SCALE = {weighted} exceeds f_fp {f_fp} (32% budget violated)"
    );

    println!("100-tribute / 15-FI fraction map: {:?}", map);
    println!("weighted sum(f*y_fp)/SCALE: {} (f_fp: {})", weighted, f_fp);
}

/// D3 regression (runtime path): when gratis is scarce (deficit < 8%), the per-FI
/// floor must adapt DOWN so the whole - small - allocation is loaded onto the
/// tribute. Under the previous degenerate `clamp(MIN, MAX/2)` the floor was pinned
/// to 8%, computing a gratis_load of 8% of nominal (> the 4% allocation), which
/// exceeds `remaining` and causes the NOD issuance to be SKIPPED entirely.
///
/// Reference behavior: outbe-cosmos `x/lysis/keeper/keeper.go` `x = min(8%, deficit)`.
#[test]
fn test_lysis_scarce_gratis_adapts_floor_below_eight_percent() {
    use alloy_primitives::{address, U256};
    use outbe_oracle::schema::OracleContract;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::time::WorldwideDay;
    use outbe_tribute::{TributeContract, TributeData};

    use crate::runtime::lysis;

    let wwd = WorldwideDay::new(20241221);
    const T_NOW: u64 = 1_700_000_000;
    let owner = address!("0x2222222222222222222222222222222222222222");
    let nominal = coen(100u64);
    let cost_of_gratis = U256::from(500_000u64);

    // Scarce: allocation is only 4% of nominal -> deficit (4%) is BELOW the 8% floor.
    let gratis_allocation = nominal * U256::from(4u64) / U256::from(100u64);
    let eight_percent_load = nominal * U256::from(8u64) / U256::from(100u64);

    let mut storage = HashMapStorageProvider::new(1);
    outbe_fidelity::enclave_client::test_enclave::install();
    storage.set_timestamp(U256::from(T_NOW));
    let bodies = TestBodyRepository::new();
    let result = StorageHandle::enter(&mut storage, |s| {
        let scope = ExecutionScope::new();
        seed_compressed_entities_genesis(&s);
        begin_block(s.clone(), &scope).unwrap();
        outbe_oracle::api::register_pair(s.clone(), outbe_oracle::api::DAY_TYPE_PAIR).unwrap();
        let oracle = OracleContract::new(s.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        let pair_index = oracle
            .pair_index_of(outbe_oracle::api::AddressPair::new_coen_to(840))
            .unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&pair_index, cost_of_gratis)
            .unwrap();

        let mut tribute = TributeContract::new(s.clone());
        tribute.unseal_day(wwd).unwrap();
        bodies.issue(
            &mut tribute,
            &scope,
            &TributeData {
                tribute_id: entity_id(wwd, owner),
                owner,
                worldwide_day: wwd,
                issuance_amount_minor: coen(50u64),
                issuance_currency: 840,
                nominal_amount_minor: nominal,
                reference_currency: 840,
                exclude_from_intex_issuance: false,
                tribute_price_minor: U256::ZERO,
            },
        );
        tribute.seal_day(wwd).unwrap();

        let result = lysis(s.clone(), &scope, &bodies, wwd, gratis_allocation).unwrap();

        // With the fix, the floor adapts to 4% and the NOD is issued. The buggy
        // (pinned-8%) path would compute an 8% load > remaining and skip issuance.
        assert_eq!(
            result.nod_ids.len(),
            1,
            "scarce-gratis day must still issue the NOD (floor adapts to the 4% deficit)"
        );

        assert!(
            result.remaining_gratis.is_zero(),
            "the full scarce allocation must be consumed"
        );
        end_block(s, &scope).unwrap();
        result
    });

    let item = storage
        .get_events(NOD_ADDRESS)
        .iter()
        .find(|event| event.topics()[0] == INod::NodBodyStored::SIGNATURE_HASH)
        .map(decode_nod_body_event)
        .expect("NOD body event");
    assert_eq!(item.nod_id, result.nod_ids[0]);
    assert_eq!(item.gratis_load_minor, gratis_allocation);
    assert!(item.gratis_load_minor < eight_percent_load);
}

// ---------------------------------------------------------------------
// Creator-reward: lysis records the per-owner contributor map
// ---------------------------------------------------------------------

#[test]
fn lysis_records_contributors_aggregated_by_owner() {
    const T_NOW: u64 = 1_700_000_000;
    let wwd = WorldwideDay::new(20260526);
    let cost_of_gratis = U256::from(500_000u64);
    let mut storage = HashMapStorageProvider::new(1);
    outbe_fidelity::enclave_client::test_enclave::install();
    storage.set_timestamp(U256::from(T_NOW));
    let bodies = TestBodyRepository::new();

    StorageHandle::enter(&mut storage, |storage| {
        let scope = ExecutionScope::new();
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        // Oracle: register ISO 840 -> COEN/840 and seed a day VWAP snapshot.
        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let oracle = OracleContract::new(storage.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        let pair_index = oracle
            .pair_index_of(outbe_oracle::api::AddressPair::new_coen_to(840))
            .unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&pair_index, cost_of_gratis)
            .unwrap();

        // Distinct owners: lysis derives nod_id from (owner, day), so an owner
        // can have at most one processed tribute per day.
        let owner_a = gas_audit_address(1);
        let owner_b = gas_audit_address(2);
        let owner_c = gas_audit_address(3);

        let mut tribute = TributeContract::new(storage.clone());
        tribute.unseal_day(wwd).unwrap();
        bodies.issue(
            &mut tribute,
            &scope,
            &gas_audit_tribute(1, owner_a, wwd, coen(100u64)),
        );
        bodies.issue(
            &mut tribute,
            &scope,
            &gas_audit_tribute(2, owner_b, wwd, coen(200u64)),
        );
        bodies.issue(
            &mut tribute,
            &scope,
            &gas_audit_tribute(3, owner_c, wwd, coen(300u64)),
        );
        tribute.seal_day(wwd).unwrap();

        let total_nominal = coen(600u64);
        let gratis_allocation = total_nominal / U256::from(10u64);

        let result =
            crate::runtime::lysis(storage.clone(), &scope, &bodies, wwd, gratis_allocation)
                .expect("lysis must complete");
        assert_eq!(
            result.nod_ids.len(),
            3,
            "every tribute must be processed for this fixture"
        );

        // Contributors are sorted by address (a < b < c) and carry each
        // owner's nominal, under the series id (== the worldwide day).
        let series_id = u32::from(wwd);
        assert_eq!(
            outbe_intex::api::read_contributors(&storage, WorldwideDay::new(series_id)).unwrap(),
            vec![
                (owner_a, coen(100u64)),
                (owner_b, coen(200u64)),
                (owner_c, coen(300u64)),
            ]
        );
        assert_eq!(
            outbe_intex::api::contributor_total(&storage, WorldwideDay::new(series_id)).unwrap(),
            coen(600u64)
        );

        end_block(storage, &scope).unwrap();
    });
}

#[test]
fn lysis_omits_excluded_owners_from_contributor_map() {
    const T_NOW: u64 = 1_700_000_000;
    let wwd = WorldwideDay::new(20260526);
    let cost_of_gratis = U256::from(500_000u64);
    let mut storage = HashMapStorageProvider::new(1);
    outbe_fidelity::enclave_client::test_enclave::install();
    storage.set_timestamp(U256::from(T_NOW));
    let bodies = TestBodyRepository::new();

    StorageHandle::enter(&mut storage, |storage| {
        let scope = ExecutionScope::new();
        seed_compressed_entities_genesis(&storage);
        begin_block(storage.clone(), &scope).unwrap();
        outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
            .unwrap();
        let oracle = OracleContract::new(storage.clone());
        oracle.worldwide_day_vwap_exists.write(&wwd, true).unwrap();
        let pair_index = oracle
            .pair_index_of(outbe_oracle::api::AddressPair::new_coen_to(840))
            .unwrap();
        oracle
            .worldwide_day_vwap_value
            .get_nested(&wwd)
            .write(&pair_index, cost_of_gratis)
            .unwrap();

        let owner_a = gas_audit_address(1);
        let owner_b = gas_audit_address(2);
        let owner_c = gas_audit_address(3);

        // owner_b opts out of Intex issuance: it must still be transformed into a
        // Nod, but must not appear in the contributor provenance map.
        let excluded_b = TributeData {
            tribute_id: entity_id(wwd, owner_b),
            owner: owner_b,
            worldwide_day: wwd,
            issuance_amount_minor: coen(100u64),
            issuance_currency: 840,
            nominal_amount_minor: coen(200u64),
            reference_currency: 840,
            exclude_from_intex_issuance: true,
            tribute_price_minor: U256::ZERO,
        };

        let mut tribute = TributeContract::new(storage.clone());
        tribute.unseal_day(wwd).unwrap();
        bodies.issue(
            &mut tribute,
            &scope,
            &gas_audit_tribute(1, owner_a, wwd, coen(100u64)),
        );
        bodies.issue(&mut tribute, &scope, &excluded_b);
        bodies.issue(
            &mut tribute,
            &scope,
            &gas_audit_tribute(3, owner_c, wwd, coen(300u64)),
        );
        tribute.seal_day(wwd).unwrap();

        let total_nominal = coen(600u64);
        let gratis_allocation = total_nominal / U256::from(10u64);

        let result =
            crate::runtime::lysis(storage.clone(), &scope, &bodies, wwd, gratis_allocation)
                .expect("lysis must complete");
        assert_eq!(
            result.nod_ids.len(),
            3,
            "excluded owners must still be transformed into a Nod"
        );

        let series_id = u32::from(wwd);
        assert_eq!(
            outbe_intex::api::read_contributors(&storage, WorldwideDay::new(series_id)).unwrap(),
            vec![(owner_a, coen(100u64)), (owner_c, coen(300u64)),],
            "opted-out owner must be absent from the contributor map"
        );
        assert_eq!(
            outbe_intex::api::contributor_total(&storage, WorldwideDay::new(series_id)).unwrap(),
            coen(400u64),
            "contributor total must exclude the opted-out owner's nominal"
        );
        assert_eq!(
            outbe_intex::api::contributor_count(&storage, WorldwideDay::new(series_id)).unwrap(),
            2
        );
        end_block(storage, &scope).unwrap();
    });
}
