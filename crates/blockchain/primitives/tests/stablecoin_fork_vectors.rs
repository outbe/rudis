use std::str::FromStr;

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use outbe_primitives::{
    stablecoin_fork::{
        stablecoin_v1_budget_for_measurement, MAX_PENDING_PUBLIC_BONDED_PROPOSALS,
        MAX_PENDING_PUBLIC_BONDED_PROPOSALS_PER_PROPOSER, STABLECOIN_CREATE_BOND,
        STABLECOIN_EIP712_DOMAIN_VERSION, STABLECOIN_LIST_PAGE_CAP,
        STABLECOIN_POLICY_MEMBER_BATCH_CAP, STABLECOIN_V1_ABSOLUTE_VOTE_PENDING_CAP,
        STABLECOIN_V1_ACCOUNT_ACCESS_OWNER, STABLECOIN_V1_ACTIVATION,
        STABLECOIN_V1_BENCHMARK_BUDGETS, STABLECOIN_V1_GAS, STABLECOIN_V1_GAS_FORMULA,
        STABLECOIN_V1_MAINTAINED_SDK, STABLECOIN_V1_NAMESPACE_RESERVATION,
        STABLECOIN_V1_REOPEN_RULES, STABLECOIN_V1_SCHEMA_VERSION, STABLECOIN_V1_SUPPORTED_NETWORKS,
        STABLECOIN_V1_TOOLING_OWNER, STABLECOIN_V1_WALL_TIME_CLASSIFICATION,
    },
    storage::gas::PRECOMPILE_BASE_GAS,
};
use revm::context_interface::cfg::gas::{SSTORE_RESET, WARM_STORAGE_READ_COST};
use serde::Deserialize;
use serde_json::Value;

const FORK_MANIFEST: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/stablecoin/v1/fork-manifest.json"
));

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Eip712Vectors {
    generator: String,
    domain_type: String,
    domain_typehash: String,
    version: String,
    version_hash: String,
    vectors: Vec<Eip712Vector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Eip712Vector {
    name: String,
    name_hash: String,
    chain_id: u64,
    verifying_contract: String,
    domain_separator: String,
}

#[test]
fn fork_manifest_matches_canonical_rust_constants() {
    let manifest: Value = serde_json::from_slice(FORK_MANIFEST).unwrap();
    assert_eq!(
        manifest["canonicalSource"],
        "outbe_primitives::stablecoin_fork"
    );
    assert_eq!(
        manifest["stablecoinSchemaVersion"],
        STABLECOIN_V1_SCHEMA_VERSION
    );
    assert_eq!(manifest["activation"]["mode"], STABLECOIN_V1_ACTIVATION);
    assert_eq!(
        manifest["activation"]["namespaceReservation"],
        STABLECOIN_V1_NAMESPACE_RESERVATION
    );
    let networks: Vec<&str> = manifest["activation"]["supportedNetworks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|network| network.as_str().unwrap())
        .collect();
    assert_eq!(networks, STABLECOIN_V1_SUPPORTED_NETWORKS);
    assert!(manifest["activation"].get("mainnet").is_none());
    assert_eq!(
        manifest["proposal"]["bondBaseUnits"],
        STABLECOIN_CREATE_BOND.to_string()
    );
    assert_eq!(
        manifest["proposal"]["absoluteVotePendingCap"],
        STABLECOIN_V1_ABSOLUTE_VOTE_PENDING_CAP
    );
    assert_eq!(
        manifest["proposal"]["maxPendingPublicBonded"],
        MAX_PENDING_PUBLIC_BONDED_PROPOSALS
    );
    assert_eq!(
        manifest["proposal"]["maxPendingPublicBondedPerProposer"],
        MAX_PENDING_PUBLIC_BONDED_PROPOSALS_PER_PROPOSER
    );
    assert_eq!(
        manifest["policy"]["memberBatchCap"],
        STABLECOIN_POLICY_MEMBER_BATCH_CAP
    );
    assert_eq!(
        manifest["lists"]["maximumPageSize"],
        STABLECOIN_LIST_PAGE_CAP
    );
    assert_eq!(
        manifest["eip712"]["domainVersion"],
        STABLECOIN_EIP712_DOMAIN_VERSION
    );
    assert_eq!(manifest["tooling"]["owner"], STABLECOIN_V1_TOOLING_OWNER);
    assert_eq!(
        manifest["tooling"]["maintainedSdk"],
        STABLECOIN_V1_MAINTAINED_SDK
    );

    let gas = &manifest["gas"];
    assert_eq!(gas["dispatchBase"], STABLECOIN_V1_GAS.dispatch_base);
    assert_eq!(gas["storageRead"], STABLECOIN_V1_GAS.storage_read);
    assert_eq!(gas["storageWrite"], STABLECOIN_V1_GAS.storage_write);
    assert_eq!(gas["storageRefund"], STABLECOIN_V1_GAS.storage_refund);
    assert_eq!(
        gas["nativeColdSurcharge"],
        STABLECOIN_V1_GAS.native_cold_surcharge
    );
    assert_eq!(gas["ecrecover"], STABLECOIN_V1_GAS.ecrecover);
    assert_eq!(gas["keccakBase"], STABLECOIN_V1_GAS.keccak_base);
    assert_eq!(gas["keccakWord"], STABLECOIN_V1_GAS.keccak_word);
    assert_eq!(
        gas["dynamicClassEnumeratedAsWarm"],
        STABLECOIN_V1_GAS.dynamic_class_enumerated_as_warm
    );
    assert_eq!(
        gas["accountAccessOwner"],
        STABLECOIN_V1_ACCOUNT_ACCESS_OWNER
    );
    assert_eq!(gas["formula"], STABLECOIN_V1_GAS_FORMULA);

    let expected = STABLECOIN_V1_BENCHMARK_BUDGETS;
    let budgets = &manifest["benchmarkBudgets"];
    assert_eq!(
        budgets["policyAuthorizationGas"],
        expected.policy_authorization_gas
    );
    assert_eq!(
        budgets["policyMemberBatchGas"],
        expected.policy_member_batch_gas
    );
    assert_eq!(
        budgets["transferWithPolicyGas"],
        expected.transfer_with_policy_gas
    );
    assert_eq!(budgets["permitGas"], expected.permit_gas);
    assert_eq!(budgets["o1P99Micros"], expected.o1_p99_micros);
    assert_eq!(budgets["batchP99Micros"], expected.batch_p99_micros);
    assert_eq!(
        budgets["measurementMarginPercent"],
        expected.measurement_margin_percent
    );
    assert_eq!(budgets["gasRoundingQuantum"], expected.gas_rounding_quantum);
    assert_eq!(
        budgets["wallTimeClassification"],
        STABLECOIN_V1_WALL_TIME_CLASSIFICATION
    );

    let reopen_rules = manifest["reopenRules"].as_array().unwrap();
    assert_eq!(reopen_rules.len(), STABLECOIN_V1_REOPEN_RULES.len());
    for (actual, expected) in reopen_rules.iter().zip(STABLECOIN_V1_REOPEN_RULES) {
        assert_eq!(actual, expected);
    }
}

#[test]
fn fork_manifest_contains_no_provisional_values() {
    let manifest = std::str::from_utf8(FORK_MANIFEST).unwrap();
    for forbidden in ["TBD", "PLACEHOLDER", "u64::MAX", "choose-later"] {
        assert!(
            !manifest.contains(forbidden),
            "fork manifest contains provisional value {forbidden}"
        );
    }
    let manifest: Value = serde_json::from_slice(FORK_MANIFEST).unwrap();
    assert_eq!(
        manifest["activation"]["supportedNetworks"]
            .as_array()
            .unwrap()
            .len(),
        STABLECOIN_V1_SUPPORTED_NETWORKS.len()
    );
    assert!(!manifest["reopenRules"].as_array().unwrap().is_empty());
}

#[test]
fn bounds_preserve_governance_capacity_and_pin_atomic_batch_edges() {
    assert_eq!(STABLECOIN_V1_ABSOLUTE_VOTE_PENDING_CAP, 64);
    assert_eq!(MAX_PENDING_PUBLIC_BONDED_PROPOSALS, 16);
    assert_eq!(MAX_PENDING_PUBLIC_BONDED_PROPOSALS_PER_PROPOSER, 1);
    assert_eq!(
        STABLECOIN_V1_ABSOLUTE_VOTE_PENDING_CAP - MAX_PENDING_PUBLIC_BONDED_PROPOSALS,
        48
    );
    assert_eq!(STABLECOIN_POLICY_MEMBER_BATCH_CAP, 64);
    assert_eq!(STABLECOIN_POLICY_MEMBER_BATCH_CAP - 1, 63);
    assert_eq!(STABLECOIN_POLICY_MEMBER_BATCH_CAP + 1, 65);
    assert_eq!(STABLECOIN_LIST_PAGE_CAP, 100);
    assert_eq!(STABLECOIN_LIST_PAGE_CAP - 1, 99);
    assert_eq!(STABLECOIN_LIST_PAGE_CAP + 1, 101);
    assert_eq!(
        STABLECOIN_CREATE_BOND,
        U256::from(1_000_000u64) * U256::from(10u64).pow(U256::from(18u64))
    );
}

#[test]
fn gas_schedule_matches_stateful_precompile_contract_and_budget_vectors() {
    assert_eq!(STABLECOIN_V1_GAS.dispatch_base, PRECOMPILE_BASE_GAS);
    assert_eq!(STABLECOIN_V1_GAS.storage_read, WARM_STORAGE_READ_COST);
    assert_eq!(STABLECOIN_V1_GAS.storage_write, SSTORE_RESET);
    assert_eq!(STABLECOIN_V1_GAS.storage_refund, 0);
    assert_eq!(STABLECOIN_V1_GAS.native_cold_surcharge, 0);
    const { assert!(!STABLECOIN_V1_GAS.dynamic_class_enumerated_as_warm) };
    assert_eq!(STABLECOIN_V1_GAS.ecrecover, 3_000);
    assert_eq!(
        (STABLECOIN_V1_GAS.keccak_base, STABLECOIN_V1_GAS.keccak_word),
        (30, 6)
    );

    let budgets = STABLECOIN_V1_BENCHMARK_BUDGETS;
    assert_eq!(budgets.policy_authorization_gas, 10_000);
    assert_eq!(budgets.policy_member_batch_gas, 750_000);
    assert_eq!(budgets.transfer_with_policy_gas, 100_000);
    assert_eq!(budgets.permit_gas, 125_000);
    assert_eq!(budgets.measurement_margin_percent, 125);
    assert_eq!(budgets.gas_rounding_quantum, 10_000);
}

#[test]
fn benchmark_margin_rounds_up_and_detects_overflow() {
    assert_eq!(stablecoin_v1_budget_for_measurement(0), Some(0));
    assert_eq!(stablecoin_v1_budget_for_measurement(8_000), Some(10_000));
    assert_eq!(stablecoin_v1_budget_for_measurement(8_001), Some(20_000));
    assert_eq!(stablecoin_v1_budget_for_measurement(u64::MAX), None);
}

#[test]
fn independent_foundry_domain_vectors_pin_version_chain_and_token() {
    let fixture: Eip712Vectors = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/stablecoin/v1/eip712-domain-vectors.json"
    )))
    .unwrap();
    assert_eq!(fixture.generator, "Foundry cast 1.7.1");
    let typehash = keccak256(fixture.domain_type.as_bytes());
    let version_hash = keccak256(STABLECOIN_EIP712_DOMAIN_VERSION.as_bytes());
    assert_eq!(typehash, B256::from_str(&fixture.domain_typehash).unwrap());
    assert_eq!(fixture.version, STABLECOIN_EIP712_DOMAIN_VERSION);
    assert_eq!(version_hash, B256::from_str(&fixture.version_hash).unwrap());

    assert!(
        fixture
            .vectors
            .iter()
            .any(|vector| vector.chain_id == outbe_primitives::chain::MAINNET_CHAIN_ID),
        "the independent corpus must include the Mainnet EIP-712 domain"
    );

    for vector in fixture.vectors {
        let name_hash = keccak256(vector.name.as_bytes());
        assert_eq!(name_hash, B256::from_str(&vector.name_hash).unwrap());
        let address = Address::from_str(&vector.verifying_contract).unwrap();
        let encoded = (
            typehash,
            name_hash,
            version_hash,
            U256::from(vector.chain_id),
            address,
        )
            .abi_encode();
        assert_eq!(
            keccak256(encoded),
            B256::from_str(&vector.domain_separator).unwrap()
        );
    }
}
