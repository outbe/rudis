use alloy_primitives::{B256, U256};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

/// Consensus-visible phase of one Metadosis day.
///
/// There is intentionally no `Running` variant: execution progress belongs to
/// the validator-local supervisor, not to consensus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DayPhase {
    Ready,
    OffchainPending,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobFsmTransitionKind {
    Defer,
    Request,
    OpenVoting,
    Expire,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobFsmTransitionRule {
    pub kind: JobFsmTransitionKind,
    pub from: DayPhase,
    pub to: DayPhase,
}

const JOB_FSM_TRANSITION_RULES: [JobFsmTransitionRule; 4] = [
    JobFsmTransitionRule {
        kind: JobFsmTransitionKind::Defer,
        from: DayPhase::Ready,
        to: DayPhase::Ready,
    },
    JobFsmTransitionRule {
        kind: JobFsmTransitionKind::Request,
        from: DayPhase::Ready,
        to: DayPhase::OffchainPending,
    },
    JobFsmTransitionRule {
        kind: JobFsmTransitionKind::OpenVoting,
        from: DayPhase::OffchainPending,
        to: DayPhase::OffchainPending,
    },
    JobFsmTransitionRule {
        kind: JobFsmTransitionKind::Expire,
        from: DayPhase::OffchainPending,
        to: DayPhase::Terminal,
    },
];

/// A request that never receives a certified-parent finality binding cannot
/// retain one of the bounded live-job slots forever.
pub const OCOMP_AWAITING_FINALITY_DEADLINE_BLOCKS: u64 = 64;

/// Frozen request/expiry transition table consumed by the model and storage
/// adapters. Future activation transitions append under their own DAG tasks.
#[must_use]
pub const fn transition_rules() -> &'static [JobFsmTransitionRule] {
    &JOB_FSM_TRANSITION_RULES
}

/// Whether request processing must apply the request-phase budget effect or
/// only validate the already-authoritative receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestEffectMode {
    Fresh { effect_nonce: u64 },
}

/// Commands accepted by the request/expiry slice of the production FSM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobFsmCommand {
    Defer {
        at_height: u64,
        next_check_height: u64,
    },
    Request {
        at_height: u64,
        deadline_height: u64,
        intent_id: B256,
        lysis_budget: U256,
        request_budget_receipt_hash: B256,
    },
    OpenVoting {
        at_height: u64,
        deadline_height: u64,
    },
    Expire {
        at_height: u64,
        at_time: u64,
    },
}

impl JobFsmCommand {
    const fn transition_kind(self) -> JobFsmTransitionKind {
        match self {
            Self::Defer { .. } => JobFsmTransitionKind::Defer,
            Self::Request { .. } => JobFsmTransitionKind::Request,
            Self::OpenVoting { .. } => JobFsmTransitionKind::OpenVoting,
            Self::Expire { .. } => JobFsmTransitionKind::Expire,
        }
    }
}

/// Stable read projection used by tests now and public views in later tasks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobFsmProjection {
    pub worldwide_day: WorldwideDay,
    pub phase: DayPhase,
    pub pending_nonce: u64,
    pub next_check_height: Option<u64>,
    pub live_intent_id: Option<B256>,
    pub deadline_height: Option<u64>,
    pub terminal_records: u16,
    pub retained_lysis_budget: Option<U256>,
}

/// Immutable evidence retained while an expiry transition is committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalAttempt {
    pub intent_id: B256,
    pub pending_nonce: u64,
    pub terminal_height: u64,
    pub terminal_time: u64,
    pub retained_lysis_budget: U256,
}

/// Canonical persistence projection of the immutable request-phase effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedRequestEffectSnapshot {
    pub effect_nonce: u64,
    pub lysis_budget: U256,
    pub receipt_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyAttemptSnapshot {
    pub pending_nonce: u64,
    pub next_check_height: u64,
    pub retained_effect: Option<RetainedRequestEffectSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveAttemptSnapshot {
    pub intent_id: B256,
    pub pending_nonce: u64,
    pub requested_height: u64,
    pub deadline_height: Option<u64>,
    pub retained_effect: RetainedRequestEffectSnapshot,
}

/// Typed storage boundary. Loading persisted fields always passes through
/// [`JobFsmState::restore`] before the state can drive a transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobFsmSnapshot {
    pub worldwide_day: WorldwideDay,
    pub ready: Option<ReadyAttemptSnapshot>,
    pub live: Option<LiveAttemptSnapshot>,
    pub terminal: Vec<TerminalAttempt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedRequestEffect {
    effect_nonce: u64,
    lysis_budget: U256,
    receipt_hash: B256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyAttempt {
    pending_nonce: u64,
    next_check_height: u64,
    retained_effect: Option<RetainedRequestEffect>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveAttempt {
    intent_id: B256,
    pending_nonce: u64,
    requested_height: u64,
    deadline_height: Option<u64>,
    retained_effect: RetainedRequestEffect,
}

/// Complete bounded state needed to decide request and exclusive expiry
/// transitions without scanning unrelated WorldwideDays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobFsmState {
    worldwide_day: WorldwideDay,
    ready: Option<ReadyAttempt>,
    live: Option<LiveAttempt>,
    terminal: Vec<TerminalAttempt>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JobFsmError {
    #[error("OCOMP FSM must have exactly one READY or OFFCHAIN_PENDING state")]
    InvalidPhaseCardinality,
    #[error("initial OCOMP pending nonce must be zero")]
    InvalidInitialNonce,
    #[error("OCOMP request is not due until height {due_height}")]
    RequestNotDue { due_height: u64 },
    #[error(
        "OCOMP deferred READY height {next_check_height} must follow processing height {at_height}"
    )]
    InvalidDeferredHeight {
        at_height: u64,
        next_check_height: u64,
    },
    #[error("OCOMP request requires READY state")]
    RequestRequiresReady,
    #[error("OCOMP expiry requires OFFCHAIN_PENDING state")]
    ExpiryRequiresPending,
    #[error("OCOMP voting open requires OFFCHAIN_PENDING state")]
    OpenVotingRequiresPending,
    #[error("OCOMP voting cannot open before height {open_height}")]
    VotingOpenTooEarly { open_height: u64 },
    #[error("OCOMP expiry requires a live attempt deadline")]
    ExpiryRequiresDeadline,
    #[error("OCOMP intent id is the reserved zero hash")]
    ZeroIntentId,
    #[error("OCOMP request budget receipt hash is the reserved zero hash")]
    ZeroRequestBudgetReceiptHash,
    #[error("OCOMP deadline {deadline_height} must follow request height {request_height}")]
    InvalidDeadline {
        request_height: u64,
        deadline_height: u64,
    },
    #[error("OCOMP deadline {deadline_height} has not been reached at height {at_height}")]
    DeadlineNotReached {
        at_height: u64,
        deadline_height: u64,
    },
    #[error("OCOMP height overflow")]
    HeightOverflow,
    #[error("OCOMP terminal evidence is inconsistent")]
    InvalidTerminalEvidence,
    #[error("OCOMP request effect is inconsistent")]
    InvalidRequestEffect,
    #[error("OCOMP FSM transition table disagrees with the applied transition")]
    InvalidTransitionRule,
}

impl JobFsmState {
    /// Constructs the only fresh lifecycle state.
    #[must_use]
    pub fn initial_ready(worldwide_day: WorldwideDay, first_check_height: u64) -> Self {
        Self {
            worldwide_day,
            ready: Some(ReadyAttempt {
                pending_nonce: 0,
                next_check_height: first_check_height,
                retained_effect: None,
            }),
            live: None,
            terminal: Vec::new(),
        }
    }

    /// Restores persisted lifecycle state and fails closed on any
    /// status/index/budget inconsistency.
    pub fn restore(snapshot: JobFsmSnapshot) -> Result<Self, JobFsmError> {
        let state = Self {
            worldwide_day: snapshot.worldwide_day,
            ready: snapshot.ready.map(|ready| ReadyAttempt {
                pending_nonce: ready.pending_nonce,
                next_check_height: ready.next_check_height,
                retained_effect: ready.retained_effect.map(RetainedRequestEffect::from),
            }),
            live: snapshot.live.map(|live| LiveAttempt {
                intent_id: live.intent_id,
                pending_nonce: live.pending_nonce,
                requested_height: live.requested_height,
                deadline_height: live.deadline_height,
                retained_effect: RetainedRequestEffect::from(live.retained_effect),
            }),
            terminal: snapshot.terminal,
        };
        state.validate()?;
        Ok(state)
    }

    #[must_use]
    pub fn snapshot(&self) -> JobFsmSnapshot {
        JobFsmSnapshot {
            worldwide_day: self.worldwide_day,
            ready: self.ready.map(|ready| ReadyAttemptSnapshot {
                pending_nonce: ready.pending_nonce,
                next_check_height: ready.next_check_height,
                retained_effect: ready
                    .retained_effect
                    .map(RetainedRequestEffectSnapshot::from),
            }),
            live: self.live.map(|live| LiveAttemptSnapshot {
                intent_id: live.intent_id,
                pending_nonce: live.pending_nonce,
                requested_height: live.requested_height,
                deadline_height: live.deadline_height,
                retained_effect: RetainedRequestEffectSnapshot::from(live.retained_effect),
            }),
            terminal: self.terminal.clone(),
        }
    }

    /// Returns whether the exact request-phase economic effect is fresh or an
    /// immutable replay. This decision is derived from lifecycle state rather
    /// than supplied by a caller.
    pub fn request_effect_mode(&self) -> Result<RequestEffectMode, JobFsmError> {
        let ready = self.ready.ok_or(JobFsmError::RequestRequiresReady)?;
        match ready.retained_effect {
            None => {
                if ready.pending_nonce != 0 {
                    return Err(JobFsmError::InvalidRequestEffect);
                }
                Ok(RequestEffectMode::Fresh {
                    effect_nonce: ready.pending_nonce,
                })
            }
            Some(_) => Err(JobFsmError::InvalidRequestEffect),
        }
    }

    /// Applies one transition atomically in memory. The receiver changes only
    /// after both the transition and the complete invariant checker succeed.
    pub fn apply(&mut self, command: JobFsmCommand) -> Result<JobFsmProjection, JobFsmError> {
        let mut candidate = self.clone();
        candidate.apply_inner(command)?;
        candidate.validate()?;
        *self = candidate;
        Ok(self.projection())
    }

    fn apply_inner(&mut self, command: JobFsmCommand) -> Result<(), JobFsmError> {
        let transition_kind = command.transition_kind();
        let transition_rule = transition_rules()
            .iter()
            .copied()
            .find(|rule| rule.kind == transition_kind)
            .ok_or(JobFsmError::InvalidTransitionRule)?;
        if self.phase()? != transition_rule.from {
            return Err(match transition_kind {
                JobFsmTransitionKind::Expire => JobFsmError::ExpiryRequiresPending,
                JobFsmTransitionKind::OpenVoting => JobFsmError::OpenVotingRequiresPending,
                JobFsmTransitionKind::Defer | JobFsmTransitionKind::Request => {
                    JobFsmError::RequestRequiresReady
                }
            });
        }

        match command {
            JobFsmCommand::Defer {
                at_height,
                next_check_height,
            } => {
                let mut ready = self.ready.ok_or(JobFsmError::RequestRequiresReady)?;
                if at_height < ready.next_check_height {
                    return Err(JobFsmError::RequestNotDue {
                        due_height: ready.next_check_height,
                    });
                }
                if next_check_height <= at_height {
                    return Err(JobFsmError::InvalidDeferredHeight {
                        at_height,
                        next_check_height,
                    });
                }
                ready.next_check_height = next_check_height;
                self.ready = Some(ready);
                Ok(())
            }
            JobFsmCommand::Request {
                at_height,
                deadline_height,
                intent_id,
                lysis_budget,
                request_budget_receipt_hash,
            } => {
                let ready = self.ready.ok_or(JobFsmError::RequestRequiresReady)?;
                if at_height < ready.next_check_height {
                    return Err(JobFsmError::RequestNotDue {
                        due_height: ready.next_check_height,
                    });
                }
                if intent_id.is_zero() {
                    return Err(JobFsmError::ZeroIntentId);
                }
                if request_budget_receipt_hash.is_zero() {
                    return Err(JobFsmError::ZeroRequestBudgetReceiptHash);
                }
                if deadline_height <= at_height {
                    return Err(JobFsmError::InvalidDeadline {
                        request_height: at_height,
                        deadline_height,
                    });
                }
                let retained_effect = match ready.retained_effect {
                    None => RetainedRequestEffect {
                        effect_nonce: ready.pending_nonce,
                        lysis_budget,
                        receipt_hash: request_budget_receipt_hash,
                    },
                    Some(_) => return Err(JobFsmError::InvalidRequestEffect),
                };
                self.live = Some(LiveAttempt {
                    intent_id,
                    pending_nonce: ready.pending_nonce,
                    requested_height: at_height,
                    deadline_height: Some(deadline_height),
                    retained_effect,
                });
                self.ready = None;
                Ok(())
            }
            JobFsmCommand::OpenVoting {
                at_height,
                deadline_height,
            } => {
                let mut live = self.live.ok_or(JobFsmError::OpenVotingRequiresPending)?;
                if at_height <= live.requested_height {
                    return Err(JobFsmError::VotingOpenTooEarly {
                        open_height: live
                            .requested_height
                            .checked_add(1)
                            .ok_or(JobFsmError::HeightOverflow)?,
                    });
                }
                if deadline_height <= at_height {
                    return Err(JobFsmError::InvalidDeadline {
                        request_height: at_height,
                        deadline_height,
                    });
                }
                live.deadline_height = Some(deadline_height);
                self.live = Some(live);
                Ok(())
            }
            JobFsmCommand::Expire { at_height, at_time } => {
                let live = self.live.ok_or(JobFsmError::ExpiryRequiresPending)?;
                let deadline_height = live
                    .deadline_height
                    .ok_or(JobFsmError::ExpiryRequiresDeadline)?;
                if at_height < deadline_height {
                    return Err(JobFsmError::DeadlineNotReached {
                        at_height,
                        deadline_height,
                    });
                }
                self.expire(live, at_height, at_time)
            }
        }?;

        if self.phase()? != transition_rule.to {
            return Err(JobFsmError::InvalidTransitionRule);
        }
        Ok(())
    }

    fn expire(
        &mut self,
        live: LiveAttempt,
        at_height: u64,
        at_time: u64,
    ) -> Result<(), JobFsmError> {
        self.terminal.push(TerminalAttempt {
            intent_id: live.intent_id,
            pending_nonce: live.pending_nonce,
            terminal_height: at_height,
            terminal_time: at_time,
            retained_lysis_budget: live.retained_effect.lysis_budget,
        });
        self.live = None;
        Ok(())
    }

    fn phase(&self) -> Result<DayPhase, JobFsmError> {
        match (
            self.ready.is_some(),
            self.live.is_some(),
            self.terminal.len(),
        ) {
            (true, false, 0) => Ok(DayPhase::Ready),
            (false, true, 0) => Ok(DayPhase::OffchainPending),
            (false, false, 1) => Ok(DayPhase::Terminal),
            _ => Err(JobFsmError::InvalidPhaseCardinality),
        }
    }

    /// Runs the production invariant checker over every status/index/budget
    /// equivalence represented by this bounded state.
    pub fn validate(&self) -> Result<(), JobFsmError> {
        let phase = self.phase()?;
        for terminal in &self.terminal {
            if terminal.pending_nonce != 0 || terminal.intent_id.is_zero() {
                return Err(JobFsmError::InvalidTerminalEvidence);
            }
        }

        if phase == DayPhase::Terminal {
            return Ok(());
        }

        let (pending_nonce, retained_effect) = if let Some(ready) = self.ready {
            if ready.pending_nonce == 0 && ready.retained_effect.is_some()
                || ready.pending_nonce > 0 && ready.retained_effect.is_none()
            {
                return Err(JobFsmError::InvalidRequestEffect);
            }
            (ready.pending_nonce, ready.retained_effect)
        } else {
            let live = self.live.ok_or(JobFsmError::InvalidPhaseCardinality)?;
            if live.intent_id.is_zero()
                || live
                    .deadline_height
                    .is_some_and(|deadline| deadline <= live.requested_height)
                || live.retained_effect.receipt_hash.is_zero()
            {
                return Err(JobFsmError::InvalidRequestEffect);
            }
            (live.pending_nonce, Some(live.retained_effect))
        };
        if pending_nonce != 0 {
            return Err(JobFsmError::InvalidInitialNonce);
        }
        if let Some(effect) = retained_effect {
            if effect.effect_nonce != 0 || effect.effect_nonce > pending_nonce {
                return Err(JobFsmError::InvalidRequestEffect);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn projection(&self) -> JobFsmProjection {
        let terminal_records = u16::try_from(self.terminal.len()).unwrap_or(u16::MAX);
        match (self.ready, self.live) {
            (Some(ready), None) => JobFsmProjection {
                worldwide_day: self.worldwide_day,
                phase: DayPhase::Ready,
                pending_nonce: ready.pending_nonce,
                next_check_height: Some(ready.next_check_height),
                live_intent_id: None,
                deadline_height: None,
                terminal_records,
                retained_lysis_budget: ready.retained_effect.map(|effect| effect.lysis_budget),
            },
            (None, Some(live)) => JobFsmProjection {
                worldwide_day: self.worldwide_day,
                phase: DayPhase::OffchainPending,
                pending_nonce: live.pending_nonce,
                next_check_height: None,
                live_intent_id: Some(live.intent_id),
                deadline_height: live.deadline_height,
                terminal_records,
                retained_lysis_budget: Some(live.retained_effect.lysis_budget),
            },
            (None, None) if self.terminal.len() == 1 => {
                let terminal = self.terminal[0];
                JobFsmProjection {
                    worldwide_day: self.worldwide_day,
                    phase: DayPhase::Terminal,
                    pending_nonce: terminal.pending_nonce,
                    next_check_height: None,
                    live_intent_id: None,
                    deadline_height: None,
                    terminal_records,
                    retained_lysis_budget: Some(terminal.retained_lysis_budget),
                }
            }
            _ => unreachable!("validated OCOMP FSM phase cardinality"),
        }
    }

    #[must_use]
    pub fn terminal_attempts(&self) -> &[TerminalAttempt] {
        &self.terminal
    }
}

impl From<RetainedRequestEffectSnapshot> for RetainedRequestEffect {
    fn from(snapshot: RetainedRequestEffectSnapshot) -> Self {
        Self {
            effect_nonce: snapshot.effect_nonce,
            lysis_budget: snapshot.lysis_budget,
            receipt_hash: snapshot.receipt_hash,
        }
    }
}

impl From<RetainedRequestEffect> for RetainedRequestEffectSnapshot {
    fn from(effect: RetainedRequestEffect) -> Self {
        Self {
            effect_nonce: effect.effect_nonce,
            lysis_budget: effect.lysis_budget,
            receipt_hash: effect.receipt_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_terminal_and_does_not_create_a_successor_attempt() {
        let mut state = JobFsmState::initial_ready(WorldwideDay::new(20_260_726), 10);
        state
            .apply(JobFsmCommand::Request {
                at_height: 10,
                deadline_height: 74,
                intent_id: B256::repeat_byte(0x11),
                lysis_budget: U256::from(900),
                request_budget_receipt_hash: B256::repeat_byte(0x22),
            })
            .unwrap();

        let projection = state
            .apply(JobFsmCommand::Expire {
                at_height: 74,
                at_time: 1_800,
            })
            .unwrap();

        assert_eq!(projection.phase, DayPhase::Terminal);
        assert_eq!(projection.pending_nonce, 0);
        assert_eq!(projection.next_check_height, None);
        assert_eq!(projection.live_intent_id, None);
        assert_eq!(projection.retained_lysis_budget, Some(U256::from(900)));
        assert_eq!(projection.terminal_records, 1);
        assert_eq!(
            state.terminal_attempts(),
            &[TerminalAttempt {
                intent_id: B256::repeat_byte(0x11),
                pending_nonce: 0,
                terminal_height: 74,
                terminal_time: 1_800,
                retained_lysis_budget: U256::from(900),
            }]
        );
    }
}
