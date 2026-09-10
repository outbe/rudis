use outbe_primitives::error::{PrecompileError, Result};

use crate::{
    aggregate::{WwdMembership, WwdProjection, WwdStatus},
    constants::MAX_RETAINED_WWDS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WwdAdvanceEdge {
    ResolveForming,
    OpenOffering,
    CloseOffering,
    BecomeReady,
}

impl WwdAdvanceEdge {
    #[must_use]
    pub(crate) const fn source(self) -> WwdStatus {
        match self {
            Self::ResolveForming => WwdStatus::Forming,
            Self::OpenOffering => WwdStatus::LookbackDelay,
            Self::CloseOffering => WwdStatus::Offering,
            Self::BecomeReady => WwdStatus::Waiting,
        }
    }

    #[must_use]
    pub(crate) const fn target(self) -> WwdStatus {
        match self {
            Self::ResolveForming => WwdStatus::LookbackDelay,
            Self::OpenOffering => WwdStatus::Offering,
            Self::CloseOffering => WwdStatus::Waiting,
            Self::BecomeReady => WwdStatus::Ready,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WwdTransitionPlan {
    Noop,
    Advance(Vec<WwdAdvanceEdge>),
    MissedOffering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ReadyDisposition {
    ZeroDayLimit,
    UnknownDayType,
    EmptyTributeDay,
    ZeroGratisAllocation,
    PrepareOcomp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(any(test, feature = "test-utils")), allow(dead_code))]
pub(crate) enum OuterWwdEvent {
    CreateDay,
    AdvanceDue {
        block_time: u64,
        retained_count: usize,
        admission_available: bool,
    },
    ProcessReady(ReadyDisposition),
    OcompRequestCommitted,
    OcompExpired,
    OcompCompleted,
    EmergencyFail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OuterWwdTransitionKind {
    Noop,
    Created,
    Advance(Vec<WwdAdvanceEdge>),
    MissedOffering,
    CapacityForfeiture {
        preceding_edges: Vec<WwdAdvanceEdge>,
    },
    ProcessReady(ReadyDisposition),
    OcompRequestCommitted,
    OcompExpired,
    OcompCompleted,
    EmergencyFail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OuterWwdTransition {
    source: Option<WwdStatus>,
    target: WwdStatus,
    membership_after: WwdMembership,
    kind: OuterWwdTransitionKind,
}

impl OuterWwdTransition {
    #[must_use]
    pub(crate) const fn source(&self) -> Option<WwdStatus> {
        self.source
    }

    #[must_use]
    pub(crate) const fn target(&self) -> WwdStatus {
        self.target
    }

    #[must_use]
    pub(crate) const fn membership_after(&self) -> WwdMembership {
        self.membership_after
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> &OuterWwdTransitionKind {
        &self.kind
    }
}

pub(crate) fn reduce_outer_wwd(
    current: Option<&WwdProjection>,
    event: OuterWwdEvent,
) -> Result<OuterWwdTransition> {
    if matches!(event, OuterWwdEvent::CreateDay) {
        return match current {
            None => Ok(transition(
                None,
                WwdStatus::Forming,
                OuterWwdTransitionKind::Created,
            )),
            Some(current) => Ok(transition(
                Some(current.status),
                current.status,
                OuterWwdTransitionKind::Noop,
            )),
        };
    }

    let current = current.ok_or_else(|| {
        crate::errors::storage_corruption(
            "Metadosis outer WWD event requires a persisted day".into(),
        )
    })?;
    let transition = match event {
        OuterWwdEvent::CreateDay => unreachable!("handled above"),
        OuterWwdEvent::AdvanceDue {
            block_time,
            retained_count,
            admission_available,
        } => {
            if retained_count > MAX_RETAINED_WWDS {
                return Err(crate::errors::storage_corruption(format!(
                    "Metadosis retained WWD count {retained_count} exceeds cap {MAX_RETAINED_WWDS}"
                )));
            }
            match plan_wwd_advance(current, block_time)? {
                WwdTransitionPlan::Noop => transition(
                    Some(current.status),
                    current.status,
                    OuterWwdTransitionKind::Noop,
                ),
                WwdTransitionPlan::MissedOffering => transition(
                    Some(current.status),
                    WwdStatus::Failed,
                    OuterWwdTransitionKind::MissedOffering,
                ),
                WwdTransitionPlan::Advance(mut edges)
                    if edges.last() == Some(&WwdAdvanceEdge::BecomeReady)
                        && !admission_available =>
                {
                    edges.pop();
                    if edges.is_empty() {
                        transition(
                            Some(current.status),
                            current.status,
                            OuterWwdTransitionKind::Noop,
                        )
                    } else {
                        let target = edges.last().expect("non-empty preceding edges").target();
                        transition(
                            Some(current.status),
                            target,
                            OuterWwdTransitionKind::Advance(edges),
                        )
                    }
                }
                WwdTransitionPlan::Advance(mut edges)
                    if retained_count == MAX_RETAINED_WWDS
                        && edges.last() == Some(&WwdAdvanceEdge::BecomeReady) =>
                {
                    edges.pop();
                    transition(
                        Some(current.status),
                        WwdStatus::Failed,
                        OuterWwdTransitionKind::CapacityForfeiture {
                            preceding_edges: edges,
                        },
                    )
                }
                WwdTransitionPlan::Advance(edges) => {
                    let target = edges.last().map_or(current.status, |edge| edge.target());
                    transition(
                        Some(current.status),
                        target,
                        OuterWwdTransitionKind::Advance(edges),
                    )
                }
            }
        }
        OuterWwdEvent::ProcessReady(disposition) if current.status == WwdStatus::Ready => {
            let target = match disposition {
                ReadyDisposition::ZeroDayLimit | ReadyDisposition::UnknownDayType => {
                    WwdStatus::Failed
                }
                ReadyDisposition::EmptyTributeDay | ReadyDisposition::ZeroGratisAllocation => {
                    WwdStatus::Completed
                }
                ReadyDisposition::PrepareOcomp => WwdStatus::Ready,
            };
            transition(
                Some(current.status),
                target,
                OuterWwdTransitionKind::ProcessReady(disposition),
            )
        }
        OuterWwdEvent::OcompRequestCommitted if current.status == WwdStatus::Ready => transition(
            Some(current.status),
            WwdStatus::OffchainPending,
            OuterWwdTransitionKind::OcompRequestCommitted,
        ),
        OuterWwdEvent::OcompExpired if current.status == WwdStatus::OffchainPending => transition(
            Some(current.status),
            WwdStatus::Failed,
            OuterWwdTransitionKind::OcompExpired,
        ),
        OuterWwdEvent::OcompCompleted if current.status == WwdStatus::OffchainPending => {
            transition(
                Some(current.status),
                WwdStatus::Completed,
                OuterWwdTransitionKind::OcompCompleted,
            )
        }
        OuterWwdEvent::EmergencyFail if !current.status.is_terminal() => transition(
            Some(current.status),
            WwdStatus::Failed,
            OuterWwdTransitionKind::EmergencyFail,
        ),
        OuterWwdEvent::EmergencyFail if current.status == WwdStatus::Failed => transition(
            Some(current.status),
            WwdStatus::Failed,
            OuterWwdTransitionKind::Noop,
        ),
        event => {
            return Err(crate::errors::storage_corruption(format!(
                "Metadosis outer WWD event {event:?} is invalid from {:?}",
                current.status
            )));
        }
    };
    Ok(transition)
}

fn transition(
    source: Option<WwdStatus>,
    target: WwdStatus,
    kind: OuterWwdTransitionKind,
) -> OuterWwdTransition {
    OuterWwdTransition {
        source,
        target,
        membership_after: if target.is_terminal() {
            WwdMembership::Closed
        } else {
            WwdMembership::Active
        },
        kind,
    }
}

/// Pure and exhaustive outer-WWD transition decision.
///
/// The persisted status supplies the lowest time region that is still
/// admissible. A timestamp behind that region is a consensus-state
/// contradiction, not a request to rewind the state machine.
pub(crate) fn plan_wwd_advance(
    current: &WwdProjection,
    block_time: u64,
) -> Result<WwdTransitionPlan> {
    if block_time < current.forming_start {
        return Err(backward_time(current, block_time));
    }

    let plan = match current.status {
        WwdStatus::Forming if block_time < current.forming_end => WwdTransitionPlan::Noop,
        WwdStatus::Forming if block_time < current.lookback_end => {
            WwdTransitionPlan::Advance(vec![WwdAdvanceEdge::ResolveForming])
        }
        WwdStatus::Forming if block_time < current.offering_end => {
            WwdTransitionPlan::Advance(vec![
                WwdAdvanceEdge::ResolveForming,
                WwdAdvanceEdge::OpenOffering,
            ])
        }
        WwdStatus::Forming => WwdTransitionPlan::MissedOffering,

        WwdStatus::LookbackDelay if block_time < current.forming_end => {
            return Err(backward_time(current, block_time));
        }
        WwdStatus::LookbackDelay if block_time < current.lookback_end => WwdTransitionPlan::Noop,
        WwdStatus::LookbackDelay if block_time < current.offering_end => {
            WwdTransitionPlan::Advance(vec![WwdAdvanceEdge::OpenOffering])
        }
        WwdStatus::LookbackDelay => WwdTransitionPlan::MissedOffering,

        WwdStatus::Offering if block_time < current.lookback_end => {
            return Err(backward_time(current, block_time));
        }
        WwdStatus::Offering if block_time < current.offering_end => WwdTransitionPlan::Noop,
        WwdStatus::Offering if block_time < current.scheduled_process_time => {
            WwdTransitionPlan::Advance(vec![WwdAdvanceEdge::CloseOffering])
        }
        WwdStatus::Offering => WwdTransitionPlan::Advance(vec![
            WwdAdvanceEdge::CloseOffering,
            WwdAdvanceEdge::BecomeReady,
        ]),

        WwdStatus::Waiting if block_time < current.offering_end => {
            return Err(backward_time(current, block_time));
        }
        WwdStatus::Waiting if block_time < current.scheduled_process_time => {
            WwdTransitionPlan::Noop
        }
        WwdStatus::Waiting => WwdTransitionPlan::Advance(vec![WwdAdvanceEdge::BecomeReady]),

        WwdStatus::Ready | WwdStatus::OffchainPending
            if block_time < current.scheduled_process_time =>
        {
            return Err(backward_time(current, block_time));
        }
        WwdStatus::Completed if block_time < current.scheduled_process_time => {
            return Err(backward_time(current, block_time));
        }
        WwdStatus::Failed if block_time < current.offering_end => {
            return Err(backward_time(current, block_time));
        }
        WwdStatus::Ready
        | WwdStatus::OffchainPending
        | WwdStatus::Completed
        | WwdStatus::Failed => WwdTransitionPlan::Noop,
    };
    Ok(plan)
}

fn backward_time(current: &WwdProjection, block_time: u64) -> PrecompileError {
    crate::errors::storage_corruption(format!(
        "Metadosis WWD {} status {:?} is ahead of block timestamp {}",
        current.worldwide_day, current.status, block_time
    ))
}
