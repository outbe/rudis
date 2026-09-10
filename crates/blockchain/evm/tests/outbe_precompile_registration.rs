//! Behavioral registration and enumeration contract for existing exact routes.

use alloy_evm::{eth::EthEvmContext, precompiles::PrecompilesMap, revm::handler::EthPrecompiles};
use alloy_primitives::{Address, B256};
use outbe_evm::precompiles::{
    extend_outbe_precompiles, outbe_precompile_addresses, OutbePrecompileExecutionContext,
    OutbePrecompileRuntime,
};
use outbe_primitives::addresses::*;
use revm::{
    database_interface::EmptyDB, handler::PrecompileProvider, primitives::hardfork::SpecId,
};

fn expected_exact_addresses() -> [Address; 42] {
    [
        GRATIS_ADDRESS,
        GRATIS_FACTORY_ADDRESS,
        PROMIS_ADDRESS,
        PROMIS_FACTORY_ADDRESS,
        TRIBUTE_ADDRESS,
        NOD_ADDRESS,
        NOD_FACTORY_ADDRESS,
        GEM_ADDRESS,
        GEM_FACTORY_ADDRESS,
        INTEX_ADDRESS,
        INTEX_FACTORY_ADDRESS,
        DESIS_ADDRESS,
        PAYNOTE_ADDRESS,
        VAULT_ROUTER_ADDRESS,
        CREDIS_ADDRESS,
        CREDIS_FACTORY_ADDRESS,
        CCA_ADDRESS,
        TRIBUTE_FACTORY_ADDRESS,
        VALIDATOR_SET_ADDRESS,
        SLASH_INDICATOR_ADDRESS,
        STAKING_ADDRESS,
        REWARDS_ADDRESS,
        AGENT_REWARD_ADDRESS,
        METADOSIS_ADDRESS,
        FIDELITY_ADDRESS,
        PROMIS_LIMIT_ADDRESS,
        ORACLE_ADDRESS,
        ZEROFEE_ADDRESS,
        OUTBE_SYSTEM_TX_ADDRESS,
        DEBUG_SUBCALL_PRECOMPILE_ADDRESS,
        ZKPROOF_POSEIDON_ADDRESS,
        ZKPROOF_GROTH16_ADDRESS,
        EMIT_ADDRESS,
        TEE_REGISTRY_ADDRESS,
        L2_REGISTRY_ADDRESS,
        STABLECOIN_FACTORY_ADDRESS,
        STABLECOIN_POLICY_REGISTRY_ADDRESS,
        RADICLE_REGISTRY_ADDRESS,
        OCOMP_REGISTRY_ADDRESS,
        GOVERNANCE_ADDRESS,
        VOTE_ADDRESS,
        UPDATE_ADDRESS,
    ]
}

fn build_extended_precompiles() -> PrecompilesMap {
    let spec = SpecId::default();
    let mut precompiles = PrecompilesMap::from_static(EthPrecompiles::new(spec).precompiles);
    extend_outbe_precompiles::<EmptyDB>(
        &mut precompiles,
        OutbePrecompileExecutionContext::new(spec, B256::ZERO),
        OutbePrecompileRuntime::new(
            None,
            std::sync::Arc::new(outbe_compressed_entities::ExecutionScope::new()),
            None,
            false,
        ),
        None,
    );
    precompiles
}

#[test]
fn exact_enumeration_contains_every_characterized_route() {
    assert_eq!(outbe_precompile_addresses(), &expected_exact_addresses());
}

#[test]
fn ctx_dispatch_hook_is_installed_for_exact_routes() {
    let precompiles = build_extended_precompiles();
    assert!(
        precompiles.has_ctx_dispatch_hook(),
        "extend_outbe_precompiles must install the exact-route dispatch hook"
    );
}

#[test]
fn warm_and_contains_behavior_remains_ethereum_only() {
    let precompiles = build_extended_precompiles();
    let warm: Vec<Address> =
        <PrecompilesMap as PrecompileProvider<EthEvmContext<EmptyDB>>>::warm_addresses(
            &precompiles,
        )
        .collect();

    for suffix in 1u8..=10 {
        let ethereum = Address::with_last_byte(suffix);
        assert!(<PrecompilesMap as PrecompileProvider<
            EthEvmContext<EmptyDB>,
        >>::contains(&precompiles, &ethereum,));
        assert!(warm.contains(&ethereum));
    }
    for outbe in expected_exact_addresses() {
        assert!(
            !<PrecompilesMap as PrecompileProvider<EthEvmContext<EmptyDB>>>::contains(
                &precompiles,
                &outbe,
            ),
            "current contains() intentionally omits ctx-hook address {outbe}"
        );
        assert!(!warm.contains(&outbe));
    }
}

#[test]
fn exact_routes_do_not_collide_with_ethereum_precompiles() {
    for outbe in outbe_precompile_addresses() {
        for suffix in 1u8..=10 {
            assert_ne!(*outbe, Address::with_last_byte(suffix));
        }
    }
}

#[test]
fn exact_routes_have_no_duplicates() {
    let addresses = outbe_precompile_addresses();
    let mut sorted = addresses.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), addresses.len());
}

#[test]
fn unregistered_address_returns_none() {
    let precompiles = build_extended_precompiles();
    assert!(precompiles.get(&Address::repeat_byte(0xfe)).is_none());
}

/// Every sponsored target must remain an exact Outbe route; otherwise a free
/// transaction could invoke arbitrary EVM code.
#[test]
fn sponsored_whitelist_is_subset_of_exact_routes() {
    use outbe_primitives::zero_fee::SPONSORED_TARGET_WHITELIST;

    for target in SPONSORED_TARGET_WHITELIST {
        assert!(
            outbe_precompile_addresses().contains(target),
            "sponsored target {target:?} is not an exact Outbe route"
        );
    }
}

#[test]
fn sponsored_whitelist_includes_gemfactory_cashout_entrypoint() {
    use outbe_primitives::zero_fee::SPONSORED_TARGET_WHITELIST;

    assert!(
        SPONSORED_TARGET_WHITELIST.contains(&GEM_FACTORY_ADDRESS),
        "zero-balance Gem owners need sponsored settleGem and minePromis"
    );
}

#[test]
fn sponsored_whitelist_excludes_validator_entrypoints() {
    use outbe_primitives::zero_fee::SPONSORED_TARGET_WHITELIST;

    for forbidden in [
        VALIDATOR_SET_ADDRESS,
        STAKING_ADDRESS,
        REWARDS_ADDRESS,
        SLASH_INDICATOR_ADDRESS,
        ORACLE_ADDRESS,
        ZEROFEE_ADDRESS,
    ] {
        assert!(
            !SPONSORED_TARGET_WHITELIST.contains(&forbidden),
            "validator/settlement entrypoint {forbidden:?} must not be sponsored"
        );
    }
}
