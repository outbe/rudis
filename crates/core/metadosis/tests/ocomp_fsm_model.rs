// OCOMP-TEST-ID: OCM-FSM-001

use alloy_primitives::{B256, U256};
use outbe_metadosis::model::{
    transition_rules, DayPhase, JobFsmCommand, JobFsmState, JobFsmTransitionKind,
    ReadyAttemptSnapshot, RequestEffectMode,
};
use outbe_primitives::time::WorldwideDay;

const WWD: WorldwideDay = WorldwideDay::new(20_260_723);
const REQUEST_HEIGHT: u64 = 40;
const DEADLINE_HEIGHT: u64 = 104;
const LYSIS_BUDGET: U256 = U256::from_limbs([700, 0, 0, 0]);
const RECEIPT_HASH: B256 = B256::repeat_byte(0x51);
const INTENT: B256 = B256::repeat_byte(0x61);
fn requested_state() -> JobFsmState {
    let mut state = JobFsmState::initial_ready(WWD, REQUEST_HEIGHT);
    state
        .apply(JobFsmCommand::Request {
            at_height: REQUEST_HEIGHT,
            deadline_height: DEADLINE_HEIGHT,
            intent_id: INTENT,
            lysis_budget: LYSIS_BUDGET,
            request_budget_receipt_hash: RECEIPT_HASH,
        })
        .unwrap();
    state
}

#[test]
fn fresh_job_has_exactly_one_request_effect() {
    let mut state = JobFsmState::initial_ready(WWD, REQUEST_HEIGHT);
    assert_eq!(
        state.request_effect_mode(),
        Ok(RequestEffectMode::Fresh { effect_nonce: 0 })
    );

    let projection = state
        .apply(JobFsmCommand::Request {
            at_height: REQUEST_HEIGHT,
            deadline_height: DEADLINE_HEIGHT,
            intent_id: INTENT,
            lysis_budget: LYSIS_BUDGET,
            request_budget_receipt_hash: RECEIPT_HASH,
        })
        .unwrap();

    assert_eq!(projection.phase, DayPhase::OffchainPending);
    assert_eq!(projection.pending_nonce, 0);
    assert_eq!(projection.live_intent_id, Some(INTENT));
    assert_eq!(projection.deadline_height, Some(DEADLINE_HEIGHT));
    assert!(state.request_effect_mode().is_err());
}

#[test]
fn expiry_is_exclusive_and_absorbing_without_successor_job() {
    let mut state = requested_state();
    let before_deadline = state.clone();
    assert!(state
        .apply(JobFsmCommand::Expire {
            at_height: DEADLINE_HEIGHT - 1,
            at_time: 1_753_315_263,
        },)
        .is_err());
    assert_eq!(state, before_deadline);

    let projection = state
        .apply(JobFsmCommand::Expire {
            at_height: DEADLINE_HEIGHT,
            at_time: 1_753_315_264,
        })
        .unwrap();

    assert_eq!(projection.phase, DayPhase::Terminal);
    assert_eq!(projection.pending_nonce, 0);
    assert_eq!(projection.next_check_height, None);
    assert_eq!(projection.live_intent_id, None);
    assert_eq!(projection.deadline_height, None);
    assert_eq!(projection.terminal_records, 1);
    assert_eq!(projection.retained_lysis_budget, Some(LYSIS_BUDGET));

    for command in [
        JobFsmCommand::Request {
            at_height: DEADLINE_HEIGHT + 1,
            deadline_height: DEADLINE_HEIGHT + 65,
            intent_id: B256::repeat_byte(0x62),
            lysis_budget: LYSIS_BUDGET,
            request_budget_receipt_hash: RECEIPT_HASH,
        },
        JobFsmCommand::Expire {
            at_height: DEADLINE_HEIGHT + 1,
            at_time: 1_753_315_265,
        },
    ] {
        let terminal = state.clone();
        assert!(state.apply(command).is_err());
        assert_eq!(state, terminal);
    }
}

#[test]
fn voting_open_preserves_the_same_job_identity_and_deadline_contract() {
    let mut state = requested_state();
    let projection = state
        .apply(JobFsmCommand::OpenVoting {
            at_height: REQUEST_HEIGHT + 4,
            deadline_height: DEADLINE_HEIGHT,
        })
        .unwrap();

    assert_eq!(projection.phase, DayPhase::OffchainPending);
    assert_eq!(projection.pending_nonce, 0);
    assert_eq!(projection.live_intent_id, Some(INTENT));
    assert_eq!(projection.deadline_height, Some(DEADLINE_HEIGHT));
}

#[test]
fn transition_table_contains_no_retry_or_conflict_edge() {
    assert_eq!(transition_rules().len(), 4);
    assert_eq!(transition_rules()[0].kind, JobFsmTransitionKind::Defer);
    assert_eq!(transition_rules()[1].kind, JobFsmTransitionKind::Request);
    assert_eq!(transition_rules()[2].kind, JobFsmTransitionKind::OpenVoting);
    assert_eq!(transition_rules()[3].kind, JobFsmTransitionKind::Expire);
    assert_eq!(transition_rules()[3].from, DayPhase::OffchainPending);
    assert_eq!(transition_rules()[3].to, DayPhase::Terminal);
}

#[test]
fn restore_rejects_a_terminal_job_with_any_live_or_ready_successor() {
    let mut state = requested_state();
    state
        .apply(JobFsmCommand::Expire {
            at_height: DEADLINE_HEIGHT,
            at_time: 1_753_315_264,
        })
        .unwrap();

    let mut terminal = state.snapshot();
    terminal.ready = Some(ReadyAttemptSnapshot {
        pending_nonce: 1,
        next_check_height: DEADLINE_HEIGHT + 1,
        retained_effect: None,
    });
    assert!(JobFsmState::restore(terminal).is_err());

    let mut invalid_nonce = state.snapshot();
    invalid_nonce.terminal[0].pending_nonce = 1;
    assert!(JobFsmState::restore(invalid_nonce).is_err());
}
