// OCOMP-TEST-ID: OCM-BYT-002

use std::collections::BTreeSet;

use alloy_primitives::keccak256;
use outbe_ocomp_protocol::abi::{
    GET_ACTIVE_LYSIS_GENERATION_SELECTOR, GET_LYSIS_TERMINAL_RECEIPT_SELECTOR,
    GET_OFFCHAIN_JOB_SELECTOR, LYSIS_ACTIVATED_TOPIC0, OCOMP_ACTIVATION_REJECTED_SELECTOR,
    OCOMP_EXPIRED_TOPIC0, OCOMP_LIFECYCLE_BEGIN_SELECTOR, OCOMP_REQUESTED_TOPIC0,
    OCOMP_TERMINAL_REQUEST_SELECTOR, SUBMIT_LYSIS_RESULT_SELECTOR,
};

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes()).0[..4].try_into().unwrap()
}

#[test]
fn abi_selectors_errors_and_topics_match_independent_keccak() {
    assert_eq!(
        SUBMIT_LYSIS_RESULT_SELECTOR,
        selector("submitLysisResult(bytes)")
    );
    assert_eq!(
        GET_OFFCHAIN_JOB_SELECTOR,
        selector("getOffchainJob(bytes32)")
    );
    assert_eq!(
        GET_ACTIVE_LYSIS_GENERATION_SELECTOR,
        selector("getActiveLysisGeneration(uint32)")
    );
    assert_eq!(
        GET_LYSIS_TERMINAL_RECEIPT_SELECTOR,
        selector("getLysisTerminalReceipt(bytes32)")
    );
    assert_eq!(
        OCOMP_ACTIVATION_REJECTED_SELECTOR,
        selector("OcompActivationRejected(uint16)")
    );
    assert_eq!(
        OCOMP_REQUESTED_TOPIC0,
        keccak256(b"OffchainJobRequested(bytes32,uint32,uint64,uint32,bytes32)")
    );
    assert_eq!(
        OCOMP_EXPIRED_TOPIC0,
        keccak256(b"OffchainJobExpired(bytes32,uint32,uint64)")
    );
    assert_eq!(
        LYSIS_ACTIVATED_TOPIC0,
        keccak256(b"LysisActivated(bytes32,bytes32,bytes32,bytes32,bytes32,uint32)")
    );
}

#[test]
fn ocomp_system_selectors_are_exact_and_collision_free() {
    assert_eq!(OCOMP_LIFECYCLE_BEGIN_SELECTOR, *b"OSE2");
    assert_eq!(OCOMP_TERMINAL_REQUEST_SELECTOR, *b"OSR2");
    let existing = [
        *b"OSA3", *b"OSL2", *b"OSC2", *b"OSB2", *b"OST3", *b"OSO2", *b"OSH2",
    ];
    let all = existing
        .into_iter()
        .chain([
            OCOMP_LIFECYCLE_BEGIN_SELECTOR,
            OCOMP_TERMINAL_REQUEST_SELECTOR,
        ])
        .collect::<Vec<_>>();
    assert_eq!(
        all.iter().copied().collect::<BTreeSet<_>>().len(),
        all.len()
    );
}

#[test]
fn public_abi_selectors_do_not_alias_each_other() {
    let selectors = [
        SUBMIT_LYSIS_RESULT_SELECTOR,
        GET_OFFCHAIN_JOB_SELECTOR,
        GET_ACTIVE_LYSIS_GENERATION_SELECTOR,
        GET_LYSIS_TERMINAL_RECEIPT_SELECTOR,
        OCOMP_ACTIVATION_REJECTED_SELECTOR,
    ];
    assert_eq!(
        selectors.iter().copied().collect::<BTreeSet<_>>().len(),
        selectors.len()
    );
}
