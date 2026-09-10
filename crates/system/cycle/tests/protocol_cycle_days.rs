use outbe_cycle::handler::{protocol_day_action, ProtocolDayAction};

#[test]
fn same_day_has_no_daily_economic_action() {
    assert_eq!(
        protocol_day_action(20_260_817, 20_260_817).unwrap(),
        ProtocolDayAction::SameDay
    );
}

#[test]
fn contiguous_day_transition_settles_the_previous_day() {
    assert_eq!(
        protocol_day_action(20_260_817, 20_260_818).unwrap(),
        ProtocolDayAction::SettlePrevious { day: 20_260_817 }
    );
}

#[test]
fn contiguous_transition_crosses_month_and_year_boundaries() {
    assert_eq!(
        protocol_day_action(20_251_231, 20_260_101).unwrap(),
        ProtocolDayAction::SettlePrevious { day: 20_251_231 }
    );
}

#[test]
fn three_day_halt_forfeits_every_missed_day() {
    assert_eq!(
        protocol_day_action(20_260_817, 20_260_820).unwrap(),
        ProtocolDayAction::SkipMissed {
            from: 20_260_817,
            to: 20_260_820,
        }
    );
}

#[test]
fn active_day_after_block_day_is_rejected() {
    let error = protocol_day_action(20_260_820, 20_260_819).unwrap_err();
    assert!(error.to_string().contains("active UTC day"));
}

#[test]
fn invalid_calendar_day_is_rejected() {
    let error = protocol_day_action(20_260_231, 20_260_301).unwrap_err();
    assert!(error.to_string().contains("invalid UTC day"));
}
