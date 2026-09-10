//! Ingress classification for the public `submitLysisResult` selector.
//!
//! The view dispatcher must never `Fatal` on caller-supplied calldata: a
//! `Fatal` from this selector aborts the whole payload build for a transaction
//! any external account can submit. The command path (active OCOMP lifecycle)
//! keeps its own machine-readable rejection codes.

use super::*;
use crate::fixture_kernel::ActivationFixture;
use crate::schema::{terminal_outcome, terminal_retirement, WorldwideDayTerminalReceiptState};
use crate::terminal::{CapacityForfeitureReceipt, MissedOfferingReceipt};
use crate::{
    errors::vote_rejection_code::LIFECYCLE_INACTIVE, ocomp::vote::dispatch_public_result_vote,
};
use outbe_compressed_entities::RetirementOutcome;
use outbe_ocomp_protocol::abi::OCOMP_RESULT_VOTE_REJECTED_SELECTOR;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::time::WorldwideDay as WwdKey;

const REJECT_CALL_MODE_CODE: u16 = 3;

fn reject_bytes(code: u16) -> alloy_primitives::Bytes {
    let mut encoded = Vec::with_capacity(36);
    encoded.extend_from_slice(&OCOMP_RESULT_VOTE_REJECTED_SELECTOR);
    encoded.extend_from_slice(&U256::from(code).to_be_bytes::<32>());
    alloy_primitives::Bytes::from(encoded)
}

#[test]
fn submit_lysis_result_reverts_when_ocomp_lifecycle_is_inactive() {
    // The rejection code is part of the external ABI surface; pin its value.
    assert_eq!(LIFECYCLE_INACTIVE, 5);

    with_storage(|storage| {
        let call = IMetadosis::submitLysisResultCall {
            resultVoteV1: alloy_primitives::Bytes::from(vec![0_u8; 8]),
        };
        let err = metadosis_dispatch(storage, &call.abi_encode(), Address::ZERO, U256::ZERO)
            .expect_err("inactive lifecycle must reject the vote selector");
        assert!(
            !matches!(err, PrecompileError::Fatal(_)),
            "caller-supplied calldata must never produce Fatal, got {err:?}"
        );
        match err {
            PrecompileError::RevertBytes(bytes) => {
                assert_eq!(bytes, reject_bytes(LIFECYCLE_INACTIVE));
            }
            other => panic!("expected RevertBytes rejection, got {other:?}"),
        }
    });
}

#[test]
fn active_lifecycle_still_routes_lysis_vote_to_the_command_path() {
    let mut fixture = ActivationFixture::new(20, 1_010, true);
    let calldata = fixture.calldata();

    // The view dispatcher never executes votes, even for a production-valid
    // vote: with the lifecycle active, routing to the command path is the EVM
    // dispatcher's decision, and the view arm keeps rejecting.
    let view_err = StorageHandle::enter(&mut fixture.provider, |storage| {
        metadosis_dispatch(storage, calldata.as_ref(), Address::ZERO, U256::ZERO)
    })
    .expect_err("view dispatcher must not execute votes");
    match view_err {
        PrecompileError::RevertBytes(bytes) => {
            assert_eq!(bytes, reject_bytes(LIFECYCLE_INACTIVE));
        }
        other => panic!("expected RevertBytes rejection, got {other:?}"),
    }

    // The same calldata succeeds through the command path.
    assert_eq!(fixture.apply().unwrap(), alloy_primitives::Bytes::new());
}

#[test]
fn static_or_valued_lysis_call_rejects_with_call_mode_code_when_active() {
    with_storage(|storage| {
        let scope = ExecutionScope::new();
        for (value, is_static) in [(U256::from(1_u8), false), (U256::ZERO, true)] {
            let err = dispatch_public_result_vote(storage.clone(), &scope, &[], value, is_static)
                .expect_err("static or valued vote call must be rejected");
            match err {
                PrecompileError::RevertBytes(bytes) => {
                    // Call-mode rejection keeps its own code; it must not
                    // collide with the lifecycle-inactive code.
                    assert_eq!(bytes, reject_bytes(REJECT_CALL_MODE_CODE));
                    assert_ne!(REJECT_CALL_MODE_CODE, LIFECYCLE_INACTIVE);
                }
                other => panic!("expected RevertBytes rejection, got {other:?}"),
            }
        }
    });
}

#[test]
fn terminal_receipt_view_stays_fatal_on_unknown_stored_outcome() {
    // Anti-regression: a persisted tag outside the writer domain is storage
    // corruption, and corruption on a read path stays `Fatal` deliberately
    // (same policy as `getWorldwideDay`'s status/day-type tag checks).
    with_contract(|metadosis| {
        let wwd = WwdKey::new(20270301);
        metadosis
            .worldwide_day_terminal_receipts
            .create(&WorldwideDayTerminalReceiptState {
                wwd,
                outcome: 7,
                value_routed: U256::ZERO,
                carry_over_before: U256::ZERO,
                carry_over_after: U256::ZERO,
                retirement: terminal_retirement::NONE,
                block_number: 1,
            })
            .unwrap();

        let call = IMetadosis::getWorldwideDayTerminalReceiptCall { wwd: wwd.value() };
        assert!(matches!(
            metadosis_dispatch(
                metadosis.storage.clone(),
                &call.abi_encode(),
                Address::ZERO,
                U256::ZERO,
            ),
            Err(PrecompileError::Fatal(_))
        ));
    });
}

#[test]
fn terminal_receipt_writers_only_emit_known_outcomes() {
    with_contract(|metadosis| {
        let missed = WwdKey::new(20270302);
        metadosis
            .write_missed_offering_receipt(MissedOfferingReceipt {
                worldwide_day: missed,
                value_routed: U256::from(5_u8),
                carry_over_before: U256::ZERO,
                carry_over_after: U256::from(5_u8),
                retirement: RetirementOutcome::NotPresent,
                block_number: 7,
            })
            .unwrap();

        let forfeited = WwdKey::new(20270303);
        metadosis
            .write_capacity_forfeiture_receipt(CapacityForfeitureReceipt {
                worldwide_day: forfeited,
                max_retained_wwds: 2,
                retained_count_before: 2,
                value_routed: U256::from(9_u8),
                carry_over_before: U256::ZERO,
                carry_over_after: U256::from(9_u8),
                sealed_collection_root: B256::repeat_byte(0x21),
                forfeited_count: 3,
                forfeited_nominal: U256::from(30_u8),
                source_generation: 1,
                retired_generation: 2,
                retirement: RetirementOutcome::Requested,
                block_number: 7,
            })
            .unwrap();

        for (wwd, expected) in [
            (missed, terminal_outcome::MISSED_OFFERING),
            (forfeited, terminal_outcome::CAPACITY_FORFEITURE),
        ] {
            let stored = metadosis
                .worldwide_day_terminal_receipts
                .get(wwd)
                .unwrap()
                .unwrap();
            assert_eq!(stored.outcome, expected);
            assert!(
                matches!(
                    stored.outcome,
                    terminal_outcome::MISSED_OFFERING | terminal_outcome::CAPACITY_FORFEITURE
                ),
                "writers must never persist a tag the reader treats as corruption"
            );
        }
    });
}
