use std::sync::Arc;

use alloy_consensus::Header;
use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_evm::{sub_call, OutbeEvmConfig, OutbeNextBlockEnvAttributes};
use outbe_primitives::{
    storage::{SubCallInput, SubCallStatus},
    OutbeBlock, OutbeExecutionData, OutbeHeader,
};
use reth_ethereum::{
    chainspec::{ChainSpec, MAINNET},
    evm::primitives::NextBlockEnvAttributes,
    node::api::ConfigureEngineEvm,
};
use reth_evm::ConfigureEvm;
use reth_primitives_traits::Block as _;
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context,
};

const TARGET: Address = Address::new([0xA5; 20]);
const CALLER: Address = Address::new([0xC5; 20]);
const PUSH0_RETURN_EMPTY: &[u8] = &[0x5f, 0x5f, 0xf3];

fn test_chain_spec() -> Arc<ChainSpec<OutbeHeader>> {
    MAINNET.as_ref().clone().map_header(OutbeHeader::new).into()
}

fn next_attributes(timestamp: u64) -> OutbeNextBlockEnvAttributes {
    OutbeNextBlockEnvAttributes {
        inner: NextBlockEnvAttributes {
            timestamp,
            suggested_fee_recipient: Address::ZERO,
            prev_randao: B256::ZERO,
            gas_limit: 30_000_000,
            parent_beacon_block_root: None,
            withdrawals: None,
            extra_data: Bytes::new(),
            slot_number: None,
        },
        timestamp_millis_part: 0,
        parent_consensus_metadata: None,
        proposer_evm_address: None,
        execute_outbe_block_hooks: true,
        prebuilt_phase1_tx: None,
        parent_artifact_hint: None,
        pending_tee_bootstrap: None,
        execution_read_budget: None,
    }
}

fn payload(number: u64, timestamp: u64) -> OutbeExecutionData {
    let block = OutbeBlock {
        header: OutbeHeader::new(Header {
            number,
            timestamp,
            ..Default::default()
        }),
        body: Default::default(),
    };
    OutbeExecutionData::new(Arc::new(block.seal_slow()))
}

fn context_with_push0() -> alloy_evm::eth::EthEvmContext<CacheDB<EmptyDB>> {
    let mut db = CacheDB::new(EmptyDB::default());
    let code = Bytecode::new_raw(Bytes::from_static(PUSH0_RETURN_EMPTY));
    db.insert_account_info(
        TARGET,
        AccountInfo {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..Default::default()
        },
    );
    Context::mainnet().with_db(db)
}

#[test]
fn canonical_block_env_keeps_chain_spec_behavior_across_an_outbe_activation_boundary() {
    let config = OutbeEvmConfig::new(test_chain_spec());
    let activation = 30_100_u64;
    let mut observed = Vec::new();

    for number in [activation - 1, activation, activation + 1] {
        let header = OutbeHeader::new(Header {
            number,
            timestamp: 0,
            ..Default::default()
        });
        observed.push(config.evm_env(&header).unwrap().cfg_env.spec);
    }

    assert_eq!(observed[0], observed[1]);
    assert_eq!(observed[1], observed[2]);
}

#[test]
fn payload_builder_env_keeps_chain_spec_behavior_across_the_same_boundary() {
    let config = OutbeEvmConfig::new(test_chain_spec());
    let activation = 30_100_u64;
    let mut observed = Vec::new();

    for next_number in [activation - 1, activation, activation + 1] {
        let parent = OutbeHeader::new(Header {
            number: next_number - 1,
            timestamp: 0,
            ..Default::default()
        });
        observed.push(
            config
                .next_evm_env(&parent, &next_attributes(0))
                .unwrap()
                .cfg_env
                .spec,
        );
    }

    assert_eq!(observed[0], observed[1]);
    assert_eq!(observed[1], observed[2]);
}

#[test]
fn validation_payload_env_matches_canonical_header_env_at_h_minus_one_h_and_h_plus_one() {
    let config = OutbeEvmConfig::new(test_chain_spec());
    let activation = 30_100_u64;

    for number in [activation - 1, activation, activation + 1] {
        let payload = payload(number, 0);
        let validation = config.evm_env_for_payload(&payload).unwrap();
        let canonical = config.evm_env(payload.block.header()).unwrap();
        assert_eq!(validation.cfg_env.spec, canonical.cfg_env.spec);
    }
}

#[test]
fn nested_call_currently_executes_push0_under_both_parent_spec_ids() {
    let input = SubCallInput {
        target: TARGET,
        value: U256::ZERO,
        calldata: Bytes::new(),
        gas_limit: 100_000,
        is_static: true,
    };

    let pre_shanghai = sub_call::run(
        &mut context_with_push0(),
        CALLER,
        false,
        SpecId::LONDON,
        None,
        std::sync::Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        input.clone(),
    )
    .unwrap();
    assert!(
        matches!(pre_shanghai.status, SubCallStatus::Success),
        "current nested-call execution accepts PUSH0 even with a London parent spec"
    );

    let shanghai = sub_call::run(
        &mut context_with_push0(),
        CALLER,
        false,
        SpecId::SHANGHAI,
        None,
        std::sync::Arc::new(outbe_compressed_entities::ExecutionScope::new()),
        input,
    )
    .unwrap();
    assert!(matches!(shanghai.status, SubCallStatus::Success));
}
