// OCOMP-TEST-ID: OCM-SEM-001

use std::{collections::BTreeMap, path::PathBuf, str::FromStr};

use alloy_primitives::{Address, U256};
use outbe_compressed_entities::{derive_poseidon_entity_id, WwdEntityId};
use outbe_lysis::program_v1::{
    execute, FidelityPhaseV1, ObservationValueV1, ObservedTributeV1, ProgramErrorV1,
    ProgramInputV1, ProgramResultV1, SemanticObservationV1, TributeInputV1,
};
use outbe_primitives::time::WorldwideDay;
use serde::Deserialize;
use serde_json::{json, Map, Value};

const SIX_DECIMAL_SCALE: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    case_id: String,
    requirements: Vec<String>,
    input: CorpusInput,
    expected: Value,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusInput {
    worldwide_day: u32,
    logical_evaluation_time: u64,
    gratis_allocation: String,
    mandatory_price_840: Option<String>,
    tributes: Vec<CorpusTribute>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusTribute {
    tribute_id: String,
    owner: String,
    worldwide_day: u32,
    issuance_currency: u16,
    nominal: String,
    reference_currency: u16,
    tribute_price: String,
    excluded: bool,
    f1: Option<u16>,
    f2: Option<u16>,
    conditional_price: Option<String>,
    nod_target_available: bool,
}

fn corpus_cases() -> Vec<CorpusCase> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/lysis-v1/cases.jsonl");
    std::fs::read_to_string(path)
        .expect("reference corpus is readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("reference case is strict JSON"))
        .collect()
}

fn u256(decimal: &str) -> U256 {
    U256::from_str(decimal).expect("corpus U256 is valid decimal")
}

fn address(raw: &str) -> Address {
    Address::from_str(raw).expect("corpus owner is a valid address")
}

fn entity_id(raw: &str) -> WwdEntityId {
    let bytes = hex::decode(raw).expect("corpus entity ID is valid hex");
    WwdEntityId::try_from(bytes.as_slice()).expect("corpus entity ID is exactly 32 bytes")
}

fn observed_value<T>(value: Option<T>) -> ObservationValueV1<T> {
    match value {
        Some(value) => ObservationValueV1::Value(value),
        None => ObservationValueV1::Unavailable,
    }
}

fn program_input(input: &CorpusInput) -> ProgramInputV1 {
    ProgramInputV1 {
        worldwide_day: WorldwideDay::new(input.worldwide_day),
        logical_evaluation_time: input.logical_evaluation_time,
        gratis_allocation: u256(&input.gratis_allocation),
        mandatory_entry_price_840: observed_value(input.mandatory_price_840.as_deref().map(u256)),
        tributes: input
            .tributes
            .iter()
            .map(|tribute| ObservedTributeV1 {
                tribute: TributeInputV1 {
                    tribute_id: entity_id(&tribute.tribute_id),
                    owner: address(&tribute.owner),
                    worldwide_day: WorldwideDay::new(tribute.worldwide_day),
                    issuance_currency: tribute.issuance_currency,
                    nominal_amount_minor: u256(&tribute.nominal),
                    reference_currency: tribute.reference_currency,
                    tribute_price_minor: u256(&tribute.tribute_price),
                    exclude_from_intex_issuance: tribute.excluded,
                },
                first_league: observed_value(tribute.f1),
                second_league: observed_value(tribute.f2),
                conditional_entry_price_minor: observed_value(
                    tribute.conditional_price.as_deref().map(u256),
                ),
                nod_target_available: tribute.nod_target_available,
            })
            .collect(),
    }
}

fn lowercase_address(value: Address) -> String {
    format!("0x{}", hex::encode(value.as_slice()))
}

fn group_table(input: &CorpusInput, result: &ProgramResultV1) -> Vec<Value> {
    let mut groups = BTreeMap::<u16, (U256, usize)>::new();
    for tribute in &input.tributes {
        let league = tribute.f1.expect("successful case has F1");
        let entry = groups.entry(league).or_insert((U256::ZERO, 0));
        entry.0 += u256(&tribute.nominal);
        entry.1 += 1;
    }
    let mut shares = groups
        .iter()
        .map(|(league, (nominal, population))| {
            (
                *league,
                *nominal * SIX_DECIMAL_SCALE / result.total_nominal,
                *population,
            )
        })
        .collect::<Vec<_>>();
    let share_sum = shares
        .iter()
        .fold(U256::ZERO, |sum, (_, share, _)| sum + *share);
    if let Some((_, share, _)) = shares.last_mut() {
        if share_sum < SIX_DECIMAL_SCALE {
            *share += SIX_DECIMAL_SCALE - share_sum;
        }
    }
    shares
        .into_iter()
        .zip(&result.league_fractions)
        .map(|((league, share, population), fraction)| {
            assert_eq!(league, fraction.league);
            json!({
                "league": league,
                "share": share.to_string(),
                "population": population,
                "fraction": fraction.fraction.to_string(),
            })
        })
        .collect()
}

fn success_json(input: &CorpusInput, result: ProgramResultV1) -> Value {
    let table = group_table(input, &result);
    let nod_actions = result
        .nod_actions
        .iter()
        .map(|action| {
            json!({
                "source_tribute_id": hex::encode(action.source_tribute_id.as_slice()),
                "owner": lowercase_address(action.owner),
                "worldwide_day": u32::from(action.worldwide_day),
                "league": action.league_id,
                "floor_price": action.floor_price_minor.to_string(),
                "gratis_load": action.gratis_load_minor.to_string(),
                "entry_price": action.entry_price_minor.to_string(),
                "cost": action.cost_amount_minor.to_string(),
                "issuance_currency": action.issuance_currency,
                "reference_currency": action.reference_currency,
                "issued_at": action.issued_at,
            })
        })
        .collect::<Vec<_>>();
    let contributors = result
        .contributors
        .iter()
        .map(|contributor| {
            json!({
                "owner": lowercase_address(contributor.owner),
                "nominal": contributor.nominal_amount_minor.to_string(),
            })
        })
        .collect::<Vec<_>>();
    let observations = result
        .observations
        .iter()
        .map(|observation| match observation {
            SemanticObservationV1::Fidelity {
                ordinal,
                phase,
                owner,
                league,
            } => json!({
                "kind": "FIDELITY",
                "ordinal": ordinal,
                "phase": match phase {
                    FidelityPhaseV1::First => "FIRST",
                    FidelityPhaseV1::Second => "SECOND",
                },
                "owner": lowercase_address(*owner),
                "league": league,
            }),
            SemanticObservationV1::Oracle {
                ordinal,
                currency,
                entry_price_minor,
            } => json!({
                "kind": "ORACLE",
                "ordinal": ordinal,
                "currency": currency,
                "entry_price": entry_price_minor.to_string(),
            }),
        })
        .collect::<Vec<_>>();
    json!({
        "status": "SUCCESS",
        "total_nominal": result.total_nominal.to_string(),
        "gratis_allocation": result.gratis_allocation.to_string(),
        "remaining_gratis": result.remaining_gratis.to_string(),
        "group_table": table,
        "nod_actions": nod_actions,
        "contributors": contributors,
        "observations": observations,
    })
}

fn failure_json(error: ProgramErrorV1) -> Value {
    let mut fields = Map::new();
    let (kind, ordinal, currency) = match error {
        ProgramErrorV1::EmptyInput => ("EMPTY_INPUT", None, None),
        ProgramErrorV1::NonCanonicalInput { ordinal } => {
            ("NON_CANONICAL_INPUT", Some(ordinal), None)
        }
        ProgramErrorV1::DuplicateInput { ordinal } => ("DUPLICATE_INPUT", Some(ordinal), None),
        ProgramErrorV1::WorldwideDayMismatch { ordinal } => {
            ("WORLDWIDE_DAY_MISMATCH", Some(ordinal), None)
        }
        ProgramErrorV1::InvalidTributeIdentity { ordinal } => {
            ("INVALID_TRIBUTE_IDENTITY", Some(ordinal), None)
        }
        ProgramErrorV1::TotalNominalOverflow { ordinal } => {
            ("TOTAL_NOMINAL_OVERFLOW", Some(ordinal), None)
        }
        ProgramErrorV1::ZeroTotalNominal => ("ZERO_TOTAL_NOMINAL", None, None),
        ProgramErrorV1::FidelityUnavailable { ordinal, phase } => (
            match phase {
                FidelityPhaseV1::First => "FIDELITY_FIRST_UNAVAILABLE",
                FidelityPhaseV1::Second => "FIDELITY_SECOND_UNAVAILABLE",
            },
            Some(ordinal),
            None,
        ),
        ProgramErrorV1::FidelityMismatch { ordinal, .. } => {
            ("FIDELITY_MISMATCH", Some(ordinal), None)
        }
        ProgramErrorV1::MandatoryOracleUnavailable => {
            ("MANDATORY_ORACLE_UNAVAILABLE", None, Some(840))
        }
        ProgramErrorV1::ConditionalOracleUnavailable { ordinal, currency } => (
            "CONDITIONAL_ORACLE_UNAVAILABLE",
            Some(ordinal),
            Some(currency),
        ),
        ProgramErrorV1::ZeroEntryPrice { ordinal, currency } => {
            ("ZERO_ENTRY_PRICE", ordinal, Some(currency))
        }
        ProgramErrorV1::Arithmetic { .. } => ("ARITHMETIC", None, None),
        ProgramErrorV1::ZeroGratisLoad { ordinal } => ("ZERO_GRATIS_LOAD", Some(ordinal), None),
        ProgramErrorV1::ZeroCost { ordinal, .. } => ("ZERO_COST", Some(ordinal), None),
        ProgramErrorV1::GratisLoadExceedsRemaining { ordinal } => {
            ("GRATIS_LOAD_EXCEEDS_REMAINING", Some(ordinal), None)
        }
        ProgramErrorV1::InvalidNodTarget { ordinal } => ("INVALID_NOD_TARGET", Some(ordinal), None),
        ProgramErrorV1::ContributorOverflow { ordinal } => {
            ("CONTRIBUTOR_OVERFLOW", Some(ordinal), None)
        }
        ProgramErrorV1::OutputCountMismatch => ("OUTPUT_COUNT_MISMATCH", None, None),
    };
    fields.insert("kind".to_owned(), Value::String(kind.to_owned()));
    if let Some(ordinal) = ordinal {
        fields.insert("ordinal".to_owned(), json!(ordinal));
    }
    if let Some(currency) = currency {
        fields.insert("currency".to_owned(), json!(currency));
    }
    json!({"status": "FAILURE", "error": fields})
}

fn execute_json(input: &CorpusInput) -> Value {
    match execute(program_input(input)) {
        Ok(result) => success_json(input, result),
        Err(error) => failure_json(error),
    }
}

#[test]
fn independent_reference_corpus_and_native_program_match() {
    let cases = corpus_cases();
    assert!(!cases.is_empty());
    for case in cases {
        assert!(
            !case.requirements.is_empty(),
            "{} has no tags",
            case.case_id
        );
        assert_eq!(
            execute_json(&case.input),
            case.expected,
            "native/reference mismatch for {}",
            case.case_id
        );
    }
}

#[test]
fn source_and_worker_order_are_not_semantic_inputs() {
    for case in corpus_cases()
        .into_iter()
        .filter(|case| case.expected["status"] == "SUCCESS")
    {
        let expected = execute_json(&case.input);
        let mut reversed = case.input.clone();
        reversed.tributes.reverse();
        assert_eq!(
            execute_json(&reversed),
            expected,
            "source permutation changed {}",
            case.case_id
        );
    }
}

#[test]
fn boundary_record_counts_keep_raw_id_order() {
    for count in [31_usize, 32, 33] {
        let day = WorldwideDay::new(20_260_723);
        let mut tributes = (1..=count)
            .map(|ordinal| {
                let owner = Address::repeat_byte(
                    u8::try_from(ordinal).expect("boundary count fits an owner seed"),
                );
                let tribute_id =
                    derive_poseidon_entity_id(owner, day).expect("bounded identity derives");
                ObservedTributeV1 {
                    tribute: TributeInputV1 {
                        tribute_id,
                        owner,
                        worldwide_day: day,
                        issuance_currency: 840,
                        nominal_amount_minor: U256::from(1_000_000_u64) * SIX_DECIMAL_SCALE,
                        reference_currency: 840,
                        tribute_price_minor: U256::ZERO,
                        exclude_from_intex_issuance: false,
                    },
                    first_league: ObservationValueV1::Value((ordinal % 15 + 1) as u16),
                    second_league: ObservationValueV1::Value((ordinal % 15 + 1) as u16),
                    conditional_entry_price_minor: ObservationValueV1::Unavailable,
                    nod_target_available: true,
                }
            })
            .collect::<Vec<_>>();
        tributes.reverse();
        let nominal = U256::from(count) * U256::from(1_000_000_u64) * SIX_DECIMAL_SCALE;
        let result = execute(ProgramInputV1 {
            worldwide_day: day,
            logical_evaluation_time: 1_784_765_900,
            gratis_allocation: nominal * U256::from(32_u8) / U256::from(100_u8),
            mandatory_entry_price_840: ObservationValueV1::Value(SIX_DECIMAL_SCALE),
            tributes,
        })
        .expect("31/32/33 bounded shapes execute");
        assert_eq!(result.nod_actions.len(), count);
        assert!(result
            .nod_actions
            .windows(2)
            .all(|pair| pair[0].source_tribute_id < pair[1].source_tribute_id));
    }
}
