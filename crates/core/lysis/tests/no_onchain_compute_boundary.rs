mod support;

use alloy_primitives::B256;
use outbe_lysis::activation_v1::{verify_result, LysisApplyPlanV1};
use outbe_ocomp_protocol::{
    intent::{DayType, JobIntentV1},
    result::{ActivationPayloadV1, LysisResultV1},
    ProtocolError, SchemaLimits,
};

use support::{activation_fixture, hash, recommit_result};

type StorageFreeVerifier = fn(
    B256,
    B256,
    &JobIntentV1,
    &ActivationPayloadV1,
    &LysisResultV1,
    &SchemaLimits,
) -> Result<LysisApplyPlanV1, ProtocolError>;

// OCOMP-TEST-ID: OCM-BND-002
#[test]
fn activation_verifier_has_a_storage_free_closed_input_boundary() {
    let verifier: StorageFreeVerifier = verify_result;
    let fixture = activation_fixture(DayType::Green);

    let plan = verifier(
        fixture.intent_id,
        fixture.job_id,
        &fixture.intent,
        &fixture.payload,
        &fixture.result,
        &fixture.limits,
    )
    .unwrap();
    assert_eq!(
        plan.request_budget_split_receipt_hash(),
        fixture
            .request_receipt
            .receipt_hash(&fixture.limits)
            .unwrap()
    );
    assert_eq!(
        plan.binding().activation_call_id,
        plan.call_core()
            .activation_call_id(&fixture.limits)
            .unwrap()
    );

    let mut rebound_payload = fixture.payload.clone();
    rebound_payload.roots.output_manifest_root = hash(230);
    assert!(verifier(
        fixture.intent_id,
        fixture.job_id,
        &fixture.intent,
        &rebound_payload,
        &fixture.result,
        &fixture.limits,
    )
    .is_err());

    let mut rebound_result = fixture.result.clone();
    rebound_result.roots.output_manifest_root = hash(231);
    recommit_result(&mut rebound_result, &fixture.limits);
    let rebound_result_payload = rebound_result.activation_payload(&fixture.limits).unwrap();
    assert!(verifier(
        fixture.intent_id,
        fixture.job_id,
        &fixture.intent,
        &rebound_result_payload,
        &fixture.result,
        &fixture.limits,
    )
    .is_err());
}
