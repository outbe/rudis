use outbe_metadosis::proof_layout::METADOSIS_STORAGE_LAYOUT_V1_HASH;
use outbe_metadosis::{
    config::{
        poc_schema_limits, OcompForkInstallClassification, OcompForkInstallV1,
        OCOMP_AWAITING_FINALITY_DEADLINE_BLOCKS, OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
    },
    test_support::ForkInstallScenario,
};
use outbe_primitives::OutbeHeader;
use reth_chainspec::ChainSpec;
use serde_json::json;

use crate::ocomp::fork::{
    load_ocomp_fork_install, require_genesis_active_ocomp_fork_install,
    require_startup_ocomp_fork_install, EPOCH_LENGTH_BLOCKS_GENESIS_KEY,
    METADOSIS_STORAGE_LAYOUT_GENESIS_KEY, OCOMP_FORK_INSTALL_GENESIS_KEY,
};

const VALID_OCOMP_EPOCH_LENGTH_BLOCKS: u64 = 300;

fn fork_install_fixture(
    classification: OcompForkInstallClassification,
    activation_height: u64,
    chain_id: u64,
    genesis_hash: alloy_primitives::B256,
) -> OcompForkInstallV1 {
    match classification {
        OcompForkInstallClassification::Final => {
            ForkInstallScenario::final_at(activation_height, chain_id, genesis_hash)
        }
        OcompForkInstallClassification::Measurement => {
            ForkInstallScenario::measurement_at(activation_height, chain_id, genesis_hash)
        }
    }
    .expect("valid canonical fork-install fixture")
    .into_install()
}

fn insert_metadosis_layout(spec: &mut ChainSpec<OutbeHeader>, layout_hash: alloy_primitives::B256) {
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            METADOSIS_STORAGE_LAYOUT_GENESIS_KEY.to_owned(),
            json!({ "layoutHash": layout_hash }),
        )
        .unwrap();
}

fn insert_epoch_length(spec: &mut ChainSpec<OutbeHeader>, epoch_length_blocks: u64) {
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            EPOCH_LENGTH_BLOCKS_GENESIS_KEY.to_owned(),
            json!(epoch_length_blocks),
        )
        .unwrap();
}

#[test]
fn genesis_fork_install_loader_accepts_one_exact_binding_and_rejects_hash_mismatch() {
    let mut spec = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Measurement,
        32,
        spec.chain().id(),
        spec.genesis_hash(),
    );
    let limits = poc_schema_limits();
    let canonical_bytes = install.encode_canonical(&limits).unwrap();
    let install_hash = install.install_hash(&limits).unwrap();
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            json!({
                "canonicalBytes": format!("0x{}", hex::encode(&canonical_bytes)),
                "installHash": install_hash,
            }),
        )
        .unwrap();
    insert_metadosis_layout(&mut spec, METADOSIS_STORAGE_LAYOUT_V1_HASH);

    let loaded = load_ocomp_fork_install(&spec).unwrap().unwrap();
    assert_eq!(loaded.as_ref(), &install);
    assert!(
        require_genesis_active_ocomp_fork_install(&spec).is_err(),
        "fresh devnet must reject a valid but late OCOMP install"
    );
    assert!(require_startup_ocomp_fork_install(&spec).is_err());

    spec.genesis
        .config
        .extra_fields
        .insert_value(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            json!({
                "canonicalBytes": format!("0x{}", hex::encode(canonical_bytes)),
                "installHash": alloy_primitives::B256::repeat_byte(0x99),
            }),
        )
        .unwrap();
    assert!(load_ocomp_fork_install(&spec).is_err());

    let empty = ChainSpec::<OutbeHeader>::default();
    assert!(load_ocomp_fork_install(&empty).unwrap().is_none());
    assert!(require_genesis_active_ocomp_fork_install(&empty).is_err());
    assert!(require_startup_ocomp_fork_install(&empty).is_err());
    assert!(require_genesis_active_ocomp_fork_install(&spec).is_err());
}

#[test]
fn fresh_devnet_loader_rejects_missing_or_mismatched_metadosis_layout() {
    let mut spec = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Measurement,
        1,
        spec.chain().id(),
        spec.genesis_hash(),
    );
    let limits = poc_schema_limits();
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            json!({
                "canonicalBytes": format!(
                    "0x{}",
                    hex::encode(install.encode_canonical(&limits).unwrap())
                ),
                "installHash": install.install_hash(&limits).unwrap(),
            }),
        )
        .unwrap();

    let missing = require_startup_ocomp_fork_install(&spec).unwrap_err();
    assert!(missing.to_string().contains("metadosisStorageLayoutV1"));

    insert_metadosis_layout(&mut spec, alloy_primitives::B256::repeat_byte(0x44));
    let mismatched = require_startup_ocomp_fork_install(&spec).unwrap_err();
    assert!(mismatched.to_string().contains("layout hash mismatch"));

    insert_metadosis_layout(&mut spec, METADOSIS_STORAGE_LAYOUT_V1_HASH);
    insert_epoch_length(&mut spec, VALID_OCOMP_EPOCH_LENGTH_BLOCKS);
    assert_eq!(
        require_startup_ocomp_fork_install(&spec).unwrap().as_ref(),
        &install
    );
}

#[test]
fn fresh_devnet_loader_rejects_malformed_and_wrong_chain_or_genesis_installs() {
    fn insert(
        spec: &mut ChainSpec<OutbeHeader>,
        canonical_bytes: &[u8],
        install_hash: alloy_primitives::B256,
    ) {
        spec.genesis
            .config
            .extra_fields
            .insert_value(
                OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
                json!({
                    "canonicalBytes": format!("0x{}", hex::encode(canonical_bytes)),
                    "installHash": install_hash,
                }),
            )
            .unwrap();
    }

    let limits = poc_schema_limits();

    let mut malformed = ChainSpec::<OutbeHeader>::default();
    insert(
        &mut malformed,
        &[0x01, 0x02, 0x03],
        alloy_primitives::B256::ZERO,
    );
    assert!(require_genesis_active_ocomp_fork_install(&malformed).is_err());

    let mut wrong_chain = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Measurement,
        1,
        wrong_chain.chain().id() + 1,
        wrong_chain.genesis_hash(),
    );
    insert(
        &mut wrong_chain,
        &install.encode_canonical(&limits).unwrap(),
        install.install_hash(&limits).unwrap(),
    );
    assert!(require_genesis_active_ocomp_fork_install(&wrong_chain).is_err());

    let mut wrong_genesis = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Measurement,
        1,
        wrong_genesis.chain().id(),
        alloy_primitives::B256::repeat_byte(0x77),
    );
    insert(
        &mut wrong_genesis,
        &install.encode_canonical(&limits).unwrap(),
        install.install_hash(&limits).unwrap(),
    );
    assert!(require_genesis_active_ocomp_fork_install(&wrong_genesis).is_err());
}

#[test]
fn fresh_devnet_loader_requires_exact_block_one_install() {
    let mut spec = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Measurement,
        1,
        spec.chain().id(),
        spec.genesis_hash(),
    );
    let limits = poc_schema_limits();
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            json!({
                "canonicalBytes": format!(
                    "0x{}",
                    hex::encode(install.encode_canonical(&limits).unwrap())
                ),
                "installHash": install.install_hash(&limits).unwrap(),
            }),
        )
        .unwrap();
    insert_metadosis_layout(&mut spec, METADOSIS_STORAGE_LAYOUT_V1_HASH);
    insert_epoch_length(&mut spec, VALID_OCOMP_EPOCH_LENGTH_BLOCKS);

    assert_eq!(
        require_genesis_active_ocomp_fork_install(&spec)
            .unwrap()
            .as_ref(),
        &install
    );
    assert_eq!(
        require_startup_ocomp_fork_install(&spec).unwrap().as_ref(),
        &install
    );
}

#[test]
fn startup_rejects_ocomp_snapshot_retention_horizon_that_is_too_short() {
    let mut spec = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Measurement,
        1,
        spec.chain().id(),
        spec.genesis_hash(),
    );
    let limits = poc_schema_limits();
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            json!({
                "canonicalBytes": format!(
                    "0x{}",
                    hex::encode(install.encode_canonical(&limits).unwrap())
                ),
                "installHash": install.install_hash(&limits).unwrap(),
            }),
        )
        .unwrap();
    insert_metadosis_layout(&mut spec, METADOSIS_STORAGE_LAYOUT_V1_HASH);

    let required_job_lifetime = OCOMP_AWAITING_FINALITY_DEADLINE_BLOCKS
        + outbe_ocomp_protocol::state::RESULT_VOTE_MIN_FINALITY_DEPTH
        + install
            .request_profile
            .capacity_profile
            .result_deadline_blocks;
    let retained_epoch_intervals = outbe_validatorset::COMMITTEE_SNAPSHOT_RETAIN_EPOCHS - 1;
    let minimum_epoch_length = required_job_lifetime / retained_epoch_intervals + 1;

    insert_epoch_length(&mut spec, minimum_epoch_length - 1);
    let error = require_startup_ocomp_fork_install(&spec).unwrap_err();
    assert!(error.to_string().contains("snapshot retention horizon"));

    insert_epoch_length(&mut spec, minimum_epoch_length);
    assert!(require_startup_ocomp_fork_install(&spec).is_ok());
}

#[test]
fn production_loader_preserves_the_existing_final_height_32_profile() {
    let mut spec = ChainSpec::<OutbeHeader>::default();
    let install = fork_install_fixture(
        OcompForkInstallClassification::Final,
        OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
        spec.chain().id(),
        spec.genesis_hash(),
    );
    let limits = poc_schema_limits();
    spec.genesis
        .config
        .extra_fields
        .insert_value(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            json!({
                "canonicalBytes": format!(
                    "0x{}",
                    hex::encode(install.encode_canonical(&limits).unwrap())
                ),
                "installHash": install.install_hash(&limits).unwrap(),
            }),
        )
        .unwrap();
    insert_epoch_length(&mut spec, VALID_OCOMP_EPOCH_LENGTH_BLOCKS);

    assert_eq!(
        require_startup_ocomp_fork_install(&spec).unwrap().as_ref(),
        &install
    );
    assert!(require_genesis_active_ocomp_fork_install(&spec).is_err());
}
