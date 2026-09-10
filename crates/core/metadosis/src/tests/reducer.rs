use super::*;
use crate::aggregate::{WwdDayType, WwdMembership, WwdProjection, WwdStatus};
use crate::reducer::{
    plan_wwd_advance, reduce_outer_wwd, OuterWwdEvent, OuterWwdTransitionKind, ReadyDisposition,
    WwdAdvanceEdge, WwdTransitionPlan,
};

const FORMING_START: u64 = 100;
const FORMING_END: u64 = 200;
const LOOKBACK_END: u64 = 300;
const OFFERING_END: u64 = 400;
const PROCESS_AT: u64 = 500;

fn projection(status: WwdStatus) -> WwdProjection {
    projection_for_day_type(status, WwdDayType::Green)
}

fn projection_for_day_type(status: WwdStatus, day_type: WwdDayType) -> WwdProjection {
    WwdProjection {
        worldwide_day: outbe_primitives::time::WorldwideDay::new(2026_0730),
        status,
        day_type,
        membership: if status.is_terminal() {
            WwdMembership::Closed
        } else {
            WwdMembership::Active
        },
        forming_start: FORMING_START,
        forming_end: FORMING_END,
        lookback_end: LOOKBACK_END,
        offering_end: OFFERING_END,
        scheduled_process_time: PROCESS_AT,
        metadosis_limit_amount: U256::from(10),
        previous_vwap: U256::ZERO,
        current_vwap: U256::ZERO,
    }
}

fn plan(status: WwdStatus, block_time: u64) -> WwdTransitionPlan {
    plan_wwd_advance(&projection(status), block_time).unwrap()
}

#[test]
fn outer_reducer_accepts_ocomp_request_only_from_ready() {
    let ready = projection(WwdStatus::Ready);
    let transition = reduce_outer_wwd(Some(&ready), OuterWwdEvent::OcompRequestCommitted).unwrap();
    assert_eq!(transition.source(), Some(WwdStatus::Ready));
    assert_eq!(transition.target(), WwdStatus::OffchainPending);
    assert_eq!(
        transition.kind(),
        &OuterWwdTransitionKind::OcompRequestCommitted
    );

    for status in [
        WwdStatus::Forming,
        WwdStatus::LookbackDelay,
        WwdStatus::Offering,
        WwdStatus::Waiting,
        WwdStatus::OffchainPending,
        WwdStatus::Completed,
        WwdStatus::Failed,
    ] {
        assert!(
            reduce_outer_wwd(
                Some(&projection(status)),
                OuterWwdEvent::OcompRequestCommitted,
            )
            .is_err(),
            "{status:?} accepted OCOMP request commit"
        );
    }
}

#[test]
fn outer_reducer_maps_only_typed_ocomp_terminal_signals() {
    let pending = projection(WwdStatus::OffchainPending);
    for (event, expected_kind, target) in [
        (
            OuterWwdEvent::OcompExpired,
            OuterWwdTransitionKind::OcompExpired,
            WwdStatus::Failed,
        ),
        (
            OuterWwdEvent::OcompCompleted,
            OuterWwdTransitionKind::OcompCompleted,
            WwdStatus::Completed,
        ),
    ] {
        let transition = reduce_outer_wwd(Some(&pending), event).unwrap();
        assert_eq!(transition.source(), Some(WwdStatus::OffchainPending));
        assert_eq!(transition.target(), target);
        assert_eq!(transition.kind(), &expected_kind);
    }

    for status in [
        WwdStatus::Forming,
        WwdStatus::LookbackDelay,
        WwdStatus::Offering,
        WwdStatus::Waiting,
        WwdStatus::Ready,
        WwdStatus::Completed,
        WwdStatus::Failed,
    ] {
        for event in [OuterWwdEvent::OcompExpired, OuterWwdEvent::OcompCompleted] {
            assert!(
                reduce_outer_wwd(Some(&projection(status)), event).is_err(),
                "{status:?} accepted {event:?}"
            );
        }
    }
}

#[test]
fn outer_reducer_emergency_fail_is_broad_but_terminal_safe() {
    for status in [
        WwdStatus::Forming,
        WwdStatus::LookbackDelay,
        WwdStatus::Offering,
        WwdStatus::Waiting,
        WwdStatus::Ready,
        WwdStatus::OffchainPending,
    ] {
        let transition =
            reduce_outer_wwd(Some(&projection(status)), OuterWwdEvent::EmergencyFail).unwrap();
        assert_eq!(transition.source(), Some(status));
        assert_eq!(transition.target(), WwdStatus::Failed);
        assert_eq!(transition.membership_after(), WwdMembership::Closed);
        assert_eq!(transition.kind(), &OuterWwdTransitionKind::EmergencyFail);
    }

    let failed = reduce_outer_wwd(
        Some(&projection(WwdStatus::Failed)),
        OuterWwdEvent::EmergencyFail,
    )
    .unwrap();
    assert_eq!(failed.target(), WwdStatus::Failed);
    assert_eq!(failed.kind(), &OuterWwdTransitionKind::Noop);

    assert!(reduce_outer_wwd(
        Some(&projection(WwdStatus::Completed)),
        OuterWwdEvent::EmergencyFail,
    )
    .is_err());
}

#[test]
fn outer_reducer_covers_creation_advance_capacity_and_ready_outcomes() {
    use crate::constants::MAX_RETAINED_WWDS;

    let created = reduce_outer_wwd(None, OuterWwdEvent::CreateDay).unwrap();
    assert_eq!(created.source(), None);
    assert_eq!(created.target(), WwdStatus::Forming);
    assert_eq!(created.membership_after(), WwdMembership::Active);
    assert_eq!(created.kind(), &OuterWwdTransitionKind::Created);

    let existing = projection(WwdStatus::Offering);
    let duplicate = reduce_outer_wwd(Some(&existing), OuterWwdEvent::CreateDay).unwrap();
    assert_eq!(duplicate.target(), WwdStatus::Offering);
    assert_eq!(duplicate.kind(), &OuterWwdTransitionKind::Noop);

    let forming = projection(WwdStatus::Forming);
    let missed = reduce_outer_wwd(
        Some(&forming),
        OuterWwdEvent::AdvanceDue {
            block_time: OFFERING_END,
            retained_count: 0,
            admission_available: true,
        },
    )
    .unwrap();
    assert_eq!(missed.target(), WwdStatus::Failed);
    assert_eq!(missed.membership_after(), WwdMembership::Closed);
    assert_eq!(missed.kind(), &OuterWwdTransitionKind::MissedOffering);

    let waiting = projection(WwdStatus::Waiting);
    let forfeited = reduce_outer_wwd(
        Some(&waiting),
        OuterWwdEvent::AdvanceDue {
            block_time: PROCESS_AT,
            retained_count: MAX_RETAINED_WWDS,
            admission_available: true,
        },
    )
    .unwrap();
    assert_eq!(forfeited.target(), WwdStatus::Failed);
    assert_eq!(forfeited.membership_after(), WwdMembership::Closed);
    assert_eq!(
        forfeited.kind(),
        &OuterWwdTransitionKind::CapacityForfeiture {
            preceding_edges: Vec::new(),
        }
    );

    let offering = projection(WwdStatus::Offering);
    let forfeited_after_close = reduce_outer_wwd(
        Some(&offering),
        OuterWwdEvent::AdvanceDue {
            block_time: PROCESS_AT,
            retained_count: MAX_RETAINED_WWDS,
            admission_available: true,
        },
    )
    .unwrap();
    assert_eq!(forfeited_after_close.target(), WwdStatus::Failed);
    assert_eq!(
        forfeited_after_close.kind(),
        &OuterWwdTransitionKind::CapacityForfeiture {
            preceding_edges: vec![WwdAdvanceEdge::CloseOffering],
        }
    );

    assert!(matches!(
        reduce_outer_wwd(
            Some(&waiting),
            OuterWwdEvent::AdvanceDue {
                block_time: PROCESS_AT,
                retained_count: MAX_RETAINED_WWDS + 1,
                admission_available: true,
            },
        ),
        Err(outbe_primitives::error::PrecompileError::Fatal(_))
    ));

    let waiting_without_admission = reduce_outer_wwd(
        Some(&waiting),
        OuterWwdEvent::AdvanceDue {
            block_time: PROCESS_AT,
            retained_count: 0,
            admission_available: false,
        },
    )
    .unwrap();
    assert_eq!(waiting_without_admission.target(), WwdStatus::Waiting);
    assert_eq!(
        waiting_without_admission.kind(),
        &OuterWwdTransitionKind::Noop
    );

    let offering_without_admission = reduce_outer_wwd(
        Some(&offering),
        OuterWwdEvent::AdvanceDue {
            block_time: PROCESS_AT,
            retained_count: 0,
            admission_available: false,
        },
    )
    .unwrap();
    assert_eq!(offering_without_admission.target(), WwdStatus::Waiting);
    assert_eq!(
        offering_without_admission.kind(),
        &OuterWwdTransitionKind::Advance(vec![WwdAdvanceEdge::CloseOffering])
    );

    let ready = projection(WwdStatus::Ready);
    for (disposition, target) in [
        (ReadyDisposition::ZeroDayLimit, WwdStatus::Failed),
        (ReadyDisposition::UnknownDayType, WwdStatus::Failed),
        (ReadyDisposition::EmptyTributeDay, WwdStatus::Completed),
        (ReadyDisposition::ZeroGratisAllocation, WwdStatus::Completed),
        (ReadyDisposition::PrepareOcomp, WwdStatus::Ready),
    ] {
        let transition =
            reduce_outer_wwd(Some(&ready), OuterWwdEvent::ProcessReady(disposition)).unwrap();
        assert_eq!(transition.target(), target);
        assert_eq!(
            transition.membership_after(),
            if target.is_terminal() {
                WwdMembership::Closed
            } else {
                WwdMembership::Active
            }
        );
        assert_eq!(
            transition.kind(),
            &OuterWwdTransitionKind::ProcessReady(disposition)
        );
    }

    assert!(reduce_outer_wwd(
        Some(&waiting),
        OuterWwdEvent::ProcessReady(ReadyDisposition::PrepareOcomp),
    )
    .is_err());
}

#[test]
fn outer_wwd_state_event_matrix_is_exhaustive() {
    let statuses = [
        WwdStatus::Forming,
        WwdStatus::LookbackDelay,
        WwdStatus::Offering,
        WwdStatus::Waiting,
        WwdStatus::Ready,
        WwdStatus::OffchainPending,
        WwdStatus::Completed,
        WwdStatus::Failed,
    ];
    let events = [
        OuterWwdEvent::CreateDay,
        OuterWwdEvent::AdvanceDue {
            block_time: PROCESS_AT,
            retained_count: 0,
            admission_available: true,
        },
        OuterWwdEvent::ProcessReady(ReadyDisposition::ZeroDayLimit),
        OuterWwdEvent::ProcessReady(ReadyDisposition::UnknownDayType),
        OuterWwdEvent::ProcessReady(ReadyDisposition::EmptyTributeDay),
        OuterWwdEvent::ProcessReady(ReadyDisposition::ZeroGratisAllocation),
        OuterWwdEvent::ProcessReady(ReadyDisposition::PrepareOcomp),
        OuterWwdEvent::OcompRequestCommitted,
        OuterWwdEvent::OcompExpired,
        OuterWwdEvent::OcompCompleted,
        OuterWwdEvent::EmergencyFail,
    ];

    for day_type in [WwdDayType::Green, WwdDayType::Red] {
        for status in statuses {
            for event in events {
                let actual =
                    reduce_outer_wwd(Some(&projection_for_day_type(status, day_type)), event);
                let expected = expected_transition_at_process_time(status, event);
                match (actual, expected) {
                    (Ok(actual), Some((target, membership, kind))) => {
                        assert_eq!(
                            actual.source(),
                            Some(status),
                            "day type {day_type:?}, state {status:?}, event {event:?}"
                        );
                        assert_eq!(
                            actual.target(),
                            target,
                            "day type {day_type:?}, state {status:?}, event {event:?}"
                        );
                        assert_eq!(
                            actual.membership_after(),
                            membership,
                            "day type {day_type:?}, state {status:?}, event {event:?}"
                        );
                        assert_eq!(
                            actual.kind(),
                            &kind,
                            "day type {day_type:?}, state {status:?}, event {event:?}"
                        );
                    }
                    (Err(_), None) => {}
                    (Ok(actual), None) => panic!(
                        "day type {day_type:?}, state {status:?}, event {event:?} \
                         unexpectedly accepted as {actual:?}"
                    ),
                    (Err(error), Some(expected)) => panic!(
                        "day type {day_type:?}, state {status:?}, event {event:?} \
                         rejected with {error}; expected {expected:?}"
                    ),
                }
            }
        }
    }

    for event in events {
        assert_eq!(
            reduce_outer_wwd(None, event).is_ok(),
            event == OuterWwdEvent::CreateDay,
            "absent state accepted {event:?}"
        );
    }
}

fn expected_transition_at_process_time(
    status: WwdStatus,
    event: OuterWwdEvent,
) -> Option<(WwdStatus, WwdMembership, OuterWwdTransitionKind)> {
    let (target, kind) = match event {
        OuterWwdEvent::CreateDay => (status, OuterWwdTransitionKind::Noop),
        OuterWwdEvent::AdvanceDue { .. } => match status {
            WwdStatus::Forming | WwdStatus::LookbackDelay => {
                (WwdStatus::Failed, OuterWwdTransitionKind::MissedOffering)
            }
            WwdStatus::Offering => (
                WwdStatus::Ready,
                OuterWwdTransitionKind::Advance(vec![
                    WwdAdvanceEdge::CloseOffering,
                    WwdAdvanceEdge::BecomeReady,
                ]),
            ),
            WwdStatus::Waiting => (
                WwdStatus::Ready,
                OuterWwdTransitionKind::Advance(vec![WwdAdvanceEdge::BecomeReady]),
            ),
            WwdStatus::Ready
            | WwdStatus::OffchainPending
            | WwdStatus::Completed
            | WwdStatus::Failed => (status, OuterWwdTransitionKind::Noop),
        },
        OuterWwdEvent::ProcessReady(disposition) if status == WwdStatus::Ready => {
            let target = match disposition {
                ReadyDisposition::ZeroDayLimit | ReadyDisposition::UnknownDayType => {
                    WwdStatus::Failed
                }
                ReadyDisposition::EmptyTributeDay | ReadyDisposition::ZeroGratisAllocation => {
                    WwdStatus::Completed
                }
                ReadyDisposition::PrepareOcomp => WwdStatus::Ready,
            };
            (target, OuterWwdTransitionKind::ProcessReady(disposition))
        }
        OuterWwdEvent::OcompRequestCommitted if status == WwdStatus::Ready => (
            WwdStatus::OffchainPending,
            OuterWwdTransitionKind::OcompRequestCommitted,
        ),
        OuterWwdEvent::OcompExpired if status == WwdStatus::OffchainPending => {
            (WwdStatus::Failed, OuterWwdTransitionKind::OcompExpired)
        }
        OuterWwdEvent::OcompCompleted if status == WwdStatus::OffchainPending => {
            (WwdStatus::Completed, OuterWwdTransitionKind::OcompCompleted)
        }
        OuterWwdEvent::EmergencyFail if !status.is_terminal() => {
            (WwdStatus::Failed, OuterWwdTransitionKind::EmergencyFail)
        }
        OuterWwdEvent::EmergencyFail if status == WwdStatus::Failed => {
            (WwdStatus::Failed, OuterWwdTransitionKind::Noop)
        }
        OuterWwdEvent::ProcessReady(_)
        | OuterWwdEvent::OcompRequestCommitted
        | OuterWwdEvent::OcompExpired
        | OuterWwdEvent::OcompCompleted
        | OuterWwdEvent::EmergencyFail => return None,
    };
    let membership = if target.is_terminal() {
        WwdMembership::Closed
    } else {
        WwdMembership::Active
    };
    Some((target, membership, kind))
}

#[test]
fn reducer_is_exact_at_every_phase_boundary() {
    use WwdAdvanceEdge::{BecomeReady, CloseOffering, OpenOffering, ResolveForming};
    use WwdTransitionPlan::{Advance, MissedOffering, Noop};

    assert_eq!(plan(WwdStatus::Forming, FORMING_END - 1), Noop);
    assert_eq!(
        plan(WwdStatus::Forming, FORMING_END),
        Advance(vec![ResolveForming])
    );
    assert_eq!(
        plan(WwdStatus::Forming, FORMING_END + 1),
        Advance(vec![ResolveForming])
    );
    assert_eq!(
        plan(WwdStatus::Forming, LOOKBACK_END - 1),
        Advance(vec![ResolveForming])
    );
    assert_eq!(
        plan(WwdStatus::Forming, LOOKBACK_END),
        Advance(vec![ResolveForming, OpenOffering])
    );
    assert_eq!(
        plan(WwdStatus::Forming, LOOKBACK_END + 1),
        Advance(vec![ResolveForming, OpenOffering])
    );

    assert_eq!(plan(WwdStatus::LookbackDelay, LOOKBACK_END - 1), Noop);
    assert_eq!(
        plan(WwdStatus::LookbackDelay, LOOKBACK_END),
        Advance(vec![OpenOffering])
    );
    assert_eq!(
        plan(WwdStatus::LookbackDelay, LOOKBACK_END + 1),
        Advance(vec![OpenOffering])
    );

    assert_eq!(plan(WwdStatus::Offering, OFFERING_END - 1), Noop);
    assert_eq!(
        plan(WwdStatus::Offering, OFFERING_END),
        Advance(vec![CloseOffering])
    );
    assert_eq!(
        plan(WwdStatus::Offering, OFFERING_END + 1),
        Advance(vec![CloseOffering])
    );

    assert_eq!(plan(WwdStatus::Waiting, PROCESS_AT - 1), Noop);
    assert_eq!(
        plan(WwdStatus::Waiting, PROCESS_AT),
        Advance(vec![BecomeReady])
    );
    assert_eq!(
        plan(WwdStatus::Waiting, PROCESS_AT + 1),
        Advance(vec![BecomeReady])
    );

    assert_eq!(
        plan(WwdStatus::Forming, OFFERING_END - 1),
        Advance(vec![ResolveForming, OpenOffering,])
    );
    assert_eq!(plan(WwdStatus::Forming, OFFERING_END), MissedOffering);
    assert_eq!(plan(WwdStatus::Forming, OFFERING_END + 1), MissedOffering);
    assert_eq!(
        plan(WwdStatus::LookbackDelay, OFFERING_END - 1),
        Advance(vec![OpenOffering])
    );
    assert_eq!(plan(WwdStatus::LookbackDelay, OFFERING_END), MissedOffering);
    assert_eq!(
        plan(WwdStatus::LookbackDelay, OFFERING_END + 1),
        MissedOffering
    );
}

#[test]
fn reducer_catches_up_without_synthesizing_a_missed_offering_after_it_opened() {
    use WwdAdvanceEdge::{BecomeReady, CloseOffering};
    use WwdTransitionPlan::Advance;

    assert_eq!(
        plan(WwdStatus::Offering, PROCESS_AT - 1),
        Advance(vec![CloseOffering])
    );
    assert_eq!(
        plan(WwdStatus::Offering, PROCESS_AT),
        Advance(vec![CloseOffering, BecomeReady])
    );
    assert_eq!(
        plan(WwdStatus::Offering, PROCESS_AT + 1),
        Advance(vec![CloseOffering, BecomeReady])
    );
}

#[test]
fn reducer_handles_zero_length_lookback_as_resolve_then_open() {
    let mut current = projection(WwdStatus::Forming);
    current.lookback_end = current.forming_end;

    assert_eq!(
        plan_wwd_advance(&current, current.forming_end).unwrap(),
        WwdTransitionPlan::Advance(vec![
            WwdAdvanceEdge::ResolveForming,
            WwdAdvanceEdge::OpenOffering,
        ])
    );
}

#[test]
fn reducer_rejects_backward_time_for_every_nonterminal_phase() {
    for (status, before) in [
        (WwdStatus::Forming, FORMING_START - 1),
        (WwdStatus::LookbackDelay, FORMING_END - 1),
        (WwdStatus::Offering, LOOKBACK_END - 1),
        (WwdStatus::Waiting, OFFERING_END - 1),
        (WwdStatus::Ready, PROCESS_AT - 1),
        (WwdStatus::OffchainPending, PROCESS_AT - 1),
    ] {
        assert!(
            plan_wwd_advance(&projection(status), before).is_err(),
            "{status:?} accepted backward time {before}"
        );
    }
}

#[test]
fn reducer_state_time_region_table_covers_every_persisted_status() {
    use WwdAdvanceEdge::{BecomeReady, CloseOffering, OpenOffering, ResolveForming};
    use WwdTransitionPlan::{Advance, MissedOffering, Noop};

    let cases = vec![
        (WwdStatus::Forming, FORMING_START - 1, None),
        (WwdStatus::Forming, FORMING_START, Some(Noop)),
        (WwdStatus::Forming, FORMING_END - 1, Some(Noop)),
        (
            WwdStatus::Forming,
            FORMING_END,
            Some(Advance(vec![ResolveForming])),
        ),
        (
            WwdStatus::Forming,
            LOOKBACK_END - 1,
            Some(Advance(vec![ResolveForming])),
        ),
        (
            WwdStatus::Forming,
            LOOKBACK_END,
            Some(Advance(vec![ResolveForming, OpenOffering])),
        ),
        (
            WwdStatus::Forming,
            OFFERING_END - 1,
            Some(Advance(vec![ResolveForming, OpenOffering])),
        ),
        (WwdStatus::Forming, OFFERING_END, Some(MissedOffering)),
        (WwdStatus::LookbackDelay, FORMING_END - 1, None),
        (WwdStatus::LookbackDelay, FORMING_END, Some(Noop)),
        (WwdStatus::LookbackDelay, LOOKBACK_END - 1, Some(Noop)),
        (
            WwdStatus::LookbackDelay,
            LOOKBACK_END,
            Some(Advance(vec![OpenOffering])),
        ),
        (
            WwdStatus::LookbackDelay,
            OFFERING_END - 1,
            Some(Advance(vec![OpenOffering])),
        ),
        (WwdStatus::LookbackDelay, OFFERING_END, Some(MissedOffering)),
        (WwdStatus::Offering, LOOKBACK_END - 1, None),
        (WwdStatus::Offering, LOOKBACK_END, Some(Noop)),
        (WwdStatus::Offering, OFFERING_END - 1, Some(Noop)),
        (
            WwdStatus::Offering,
            OFFERING_END,
            Some(Advance(vec![CloseOffering])),
        ),
        (
            WwdStatus::Offering,
            PROCESS_AT - 1,
            Some(Advance(vec![CloseOffering])),
        ),
        (
            WwdStatus::Offering,
            PROCESS_AT,
            Some(Advance(vec![CloseOffering, BecomeReady])),
        ),
        (WwdStatus::Waiting, OFFERING_END - 1, None),
        (WwdStatus::Waiting, OFFERING_END, Some(Noop)),
        (WwdStatus::Waiting, PROCESS_AT - 1, Some(Noop)),
        (
            WwdStatus::Waiting,
            PROCESS_AT,
            Some(Advance(vec![BecomeReady])),
        ),
        (WwdStatus::Ready, PROCESS_AT - 1, None),
        (WwdStatus::Ready, PROCESS_AT, Some(Noop)),
        (WwdStatus::OffchainPending, PROCESS_AT - 1, None),
        (WwdStatus::OffchainPending, PROCESS_AT, Some(Noop)),
        (WwdStatus::Completed, PROCESS_AT - 1, None),
        (WwdStatus::Completed, PROCESS_AT, Some(Noop)),
        (WwdStatus::Failed, OFFERING_END - 1, None),
        (WwdStatus::Failed, OFFERING_END, Some(Noop)),
    ];

    for (status, block_time, expected) in cases {
        let actual = plan_wwd_advance(&projection(status), block_time);
        match expected {
            Some(expected) => assert_eq!(
                actual.unwrap(),
                expected,
                "{status:?} at block timestamp {block_time}"
            ),
            None => assert!(
                actual.is_err(),
                "{status:?} accepted backward block timestamp {block_time}"
            ),
        }
    }
}

#[test]
fn reducer_is_a_noop_for_processing_and_terminal_states_at_valid_time() {
    for (status, valid_time) in [
        (WwdStatus::Ready, PROCESS_AT),
        (WwdStatus::OffchainPending, PROCESS_AT),
        (WwdStatus::Completed, PROCESS_AT),
        (WwdStatus::Failed, OFFERING_END),
    ] {
        assert_eq!(
            plan_wwd_advance(&projection(status), valid_time).unwrap(),
            WwdTransitionPlan::Noop
        );
        assert_eq!(
            plan_wwd_advance(&projection(status), valid_time + 1).unwrap(),
            WwdTransitionPlan::Noop
        );
    }
}

#[test]
fn reducer_accepts_each_phase_at_its_exact_lower_time_bound() {
    for (status, lower_bound, expected) in [
        (
            WwdStatus::LookbackDelay,
            FORMING_END,
            WwdTransitionPlan::Noop,
        ),
        (WwdStatus::Offering, LOOKBACK_END, WwdTransitionPlan::Noop),
        (WwdStatus::Waiting, OFFERING_END, WwdTransitionPlan::Noop),
    ] {
        assert_eq!(
            plan_wwd_advance(&projection(status), lower_bound).unwrap(),
            expected
        );
        assert_eq!(
            plan_wwd_advance(&projection(status), lower_bound + 1).unwrap(),
            expected
        );
    }
}

#[test]
fn reducer_rejects_backward_time_for_terminal_states() {
    for (status, before) in [
        (WwdStatus::Completed, PROCESS_AT - 1),
        (WwdStatus::Failed, OFFERING_END - 1),
    ] {
        assert!(
            plan_wwd_advance(&projection(status), before).is_err(),
            "{status:?} accepted backward time {before}"
        );
    }
}

#[test]
fn reducer_is_a_noop_for_processing_states_after_the_process_boundary() {
    for status in [WwdStatus::Ready, WwdStatus::OffchainPending] {
        assert_eq!(
            plan_wwd_advance(&projection(status), PROCESS_AT + 1).unwrap(),
            WwdTransitionPlan::Noop
        );
    }
}
