//! the consensus chain id MUST be installed into the
//! signing-namespace source of truth by the PRODUCTION `OutbeEvmConfig`
//! constructors, not only the test-only `::new`.
//!
//! Before the fix, `init_consensus_chain_id` was called only from
//! `OutbeEvmConfig::new`, but the live node builds the EVM via `new_with_bridge`
//! (offline subcommands) and `new_with_bridge_and_summary_provider` /
//! `new_with_provider_only` (via `OutbeExecutorBuilder::build_evm`). Those built
//! `Self {}` inline and skipped the install, so `consensus_chain_id()` stayed at
//! its default `0` and the consensus namespace collapsed to `b"outbe" || 0` on
//! every chain - silently disabling the cross-chain-replay
//! binding while every test/localnet (all at one chain id) stayed lockstep.
//!
//! This lives in its own test binary so the process-global `OnceLock` chain id is
//! pristine - no sibling unit test can install a different id first.

use std::sync::Arc;

use outbe_consensus::proof::{consensus_chain_id, outbe_app_namespace};
use outbe_evm::OutbeEvmConfig;
use outbe_primitives::{chain::MAINNET_CHAIN_ID, consensus::ConsensusExecutionBridge, OutbeHeader};
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder, EthChainSpec};
use reth_ethereum::chainspec::MAINNET;

fn test_chain_spec() -> Arc<ChainSpec<OutbeHeader>> {
    Arc::new(
        ChainSpecBuilder::default()
            .chain(Chain::from_id(MAINNET_CHAIN_ID))
            .genesis(MAINNET.genesis.clone())
            .cancun_activated()
            .build()
            .map_header(OutbeHeader::new),
    )
}

#[test]
fn new_with_bridge_installs_consensus_chain_id() {
    let chain_spec = test_chain_spec();
    let expected = chain_spec.chain().id();
    assert_eq!(expected, MAINNET_CHAIN_ID);
    // The binding is only meaningful if the chain id differs from the default 0.
    assert_ne!(
        expected, 0,
        "test chain spec must use a non-default chain id"
    );

    // The production validator path builds the EVM via `new_with_bridge`
    // (bin/outbe-chain/src/main.rs). Pre-fix this constructor skipped the install.
    let _config = OutbeEvmConfig::new_with_bridge(chain_spec, ConsensusExecutionBridge::new());

    // Core regression: pre-fix this was 0; post-fix it is the spec's chain id.
    assert_eq!(
        consensus_chain_id(),
        expected,
        "new_with_bridge must install the consensus chain id"
    );

    // The signing namespace must actually reflect that id, i.e. cross-chain
    // separation is real, not the degenerate `b\"outbe\" || 0`.
    let mut bound = b"outbe".to_vec();
    bound.extend_from_slice(&expected.to_be_bytes());
    assert_eq!(
        outbe_app_namespace(),
        bound,
        "outbe_app_namespace must bind the installed chain id"
    );

    let mut degenerate = b"outbe".to_vec();
    degenerate.extend_from_slice(&0u64.to_be_bytes());
    assert_ne!(
        outbe_app_namespace(),
        degenerate,
        "namespace must NOT be the unbound default b\"outbe\" || 0"
    );
}
