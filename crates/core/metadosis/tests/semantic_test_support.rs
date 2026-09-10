#![cfg(feature = "test-utils")]

use alloy_primitives::{Bytes, B256};
use outbe_metadosis::test_support::{
    ActivationCorruption, ActivationScenario, EmergencyFailScenario, ForkInstallScenario,
};
use outbe_metadosis::{OcompForkInstallClassification, WwdMembership, WwdStatus};
use outbe_ocomp_protocol::receipts::ActivationOutcome;
use outbe_primitives::time::WorldwideDay;

#[test]
fn activation_scenario_executes_the_production_command_and_exposes_a_typed_outcome() {
    let mut scenario = ActivationScenario::q_forming_success(20, 1_010);

    assert_eq!(scenario.submit_q_forming_vote().unwrap(), Bytes::new());
    assert_eq!(scenario.terminal_outcome(), ActivationOutcome::Applied);
}

#[test]
fn fork_install_scenario_exposes_only_a_canonical_immutable_artifact() {
    let scenario = ForkInstallScenario::final_at(32, 42, B256::repeat_byte(0x11))
        .expect("valid final install");
    let install = scenario.install();

    assert_eq!(
        install.classification,
        OcompForkInstallClassification::Final
    );
    assert_eq!(install.activation_height, 32);
    assert_eq!(install.request_profile.chain_id, 42);
    assert_eq!(
        install.request_profile.genesis_hash,
        B256::repeat_byte(0x11)
    );
}

#[test]
fn measurement_fork_install_uses_the_same_immutable_artifact_boundary() {
    let scenario = ForkInstallScenario::measurement_at(48, 43, B256::repeat_byte(0x22))
        .expect("valid measurement install");

    assert_eq!(
        scenario.install().classification,
        OcompForkInstallClassification::Measurement
    );
    assert_eq!(scenario.install().activation_height, 48);
}

#[test]
fn fork_install_scenarios_reject_zero_and_do_not_inherit_a_static_committee_window() {
    let genesis_hash = B256::repeat_byte(0x33);

    assert!(ForkInstallScenario::final_at(31, 44, genesis_hash).is_err());
    assert!(ForkInstallScenario::measurement_at(0, 44, genesis_hash).is_err());
    assert!(ForkInstallScenario::measurement_at(1_000, 44, genesis_hash).is_ok());
}

#[test]
fn named_corruption_is_a_precondition_and_failed_submission_rolls_back() {
    let mut scenario = ActivationScenario::q_forming_success(20, 1_010);
    scenario.corrupt(ActivationCorruption::RequestReceiptMismatch);
    let corrupted_precondition = scenario.checkpoint();

    assert_eq!(
        format!("{corrupted_precondition:?}"),
        "ActivationCheckpoint(\"<opaque>\")"
    );

    assert!(scenario.submit_q_forming_vote().is_err());
    assert_eq!(scenario.checkpoint(), corrupted_precondition);
}

#[test]
fn emergency_fail_scenario_executes_the_commit_owned_command() {
    let wwd = WorldwideDay::new(2026_0731);
    let mut scenario = EmergencyFailScenario::forming(wwd, 42, 17).unwrap();

    scenario.fail().unwrap();
    scenario.fail().unwrap();

    let observation = scenario.observation().unwrap();
    assert_eq!(observation.status, WwdStatus::Failed);
    assert_eq!(observation.membership, WwdMembership::Closed);
}
