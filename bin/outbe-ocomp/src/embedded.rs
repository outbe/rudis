//! Local OCOMP lifecycle shared by embedded Validator and FullNode policies.
//!
//! Canonical state is the authority. Every asynchronous result is correlated
//! with the process-local generation that started it and is reduced here before
//! callers perform effects. This keeps terminal authority absorbing even when a
//! worker or transaction outcome was already queued.

use std::collections::BTreeMap;

use alloy_primitives::B256;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedOcompModeV1 {
    Validator,
    FullNode,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EmbeddedJobGenerationV1(u64);

impl EmbeddedJobGenerationV1 {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedTerminalReasonV1 {
    Completed,
    Expired,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedJobStateV1 {
    Computing,
    WaitAtDeadline,
    LocalReady,
    Verified,
    Closed,
    FatalMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedJobEventV1 {
    LocalCompleted {
        generation: EmbeddedJobGenerationV1,
        result_digest: B256,
    },
    LocalFailed {
        generation: EmbeddedJobGenerationV1,
    },
    Deadline,
    CanonicalCompleted {
        result_digest: B256,
    },
    CanonicalClosed {
        reason: EmbeddedTerminalReasonV1,
    },
    VoteFinalized {
        generation: EmbeddedJobGenerationV1,
        success: bool,
    },
    VoteFailed {
        generation: EmbeddedJobGenerationV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedJobActionV1 {
    SubmitVote {
        job_id: B256,
        result_digest: B256,
    },
    AwaitCanonical {
        job_id: B256,
    },
    AwaitLocalResult {
        job_id: B256,
    },
    HoldProgress {
        job_id: B256,
        through_height: u64,
    },
    ReleaseProgress {
        job_id: B256,
    },
    FatalMismatch {
        job_id: B256,
        local_result_digest: B256,
        canonical_result_digest: B256,
    },
    CloseTerminal {
        job_id: B256,
        reason: EmbeddedTerminalReasonV1,
    },
    Abstain,
    FatalLocalFailure,
    VoteFinalized {
        success: bool,
    },
    FatalVoteFailure,
    ProtocolOwned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedTransitionPlanV1 {
    pub generation: EmbeddedJobGenerationV1,
    pub action: EmbeddedJobActionV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EmbeddedJobV1 {
    generation: EmbeddedJobGenerationV1,
    deadline_height: u64,
    local_result_digest: Option<B256>,
    canonical_result_digest: Option<B256>,
    terminal_reason: Option<EmbeddedTerminalReasonV1>,
    state: EmbeddedJobStateV1,
}

#[derive(Debug)]
pub struct EmbeddedOcompJobsV1 {
    mode: EmbeddedOcompModeV1,
    next_generation: u64,
    jobs: BTreeMap<B256, EmbeddedJobV1>,
}

impl EmbeddedOcompJobsV1 {
    #[must_use]
    pub const fn new(mode: EmbeddedOcompModeV1) -> Self {
        Self {
            mode,
            next_generation: 1,
            jobs: BTreeMap::new(),
        }
    }

    pub fn observe_job(
        &mut self,
        job_id: B256,
        deadline_height: u64,
    ) -> Result<EmbeddedJobGenerationV1, EmbeddedOcompStateErrorV1> {
        if job_id.is_zero() || deadline_height == 0 {
            return Err(EmbeddedOcompStateErrorV1::InvalidJob);
        }
        match self.jobs.get(&job_id) {
            Some(existing) if existing.deadline_height == deadline_height => {
                Ok(existing.generation)
            }
            Some(_) => Err(EmbeddedOcompStateErrorV1::ConflictingReplay { job_id }),
            None => {
                let generation = EmbeddedJobGenerationV1(self.next_generation);
                self.next_generation = self
                    .next_generation
                    .checked_add(1)
                    .ok_or(EmbeddedOcompStateErrorV1::GenerationExhausted)?;
                self.jobs.insert(
                    job_id,
                    EmbeddedJobV1 {
                        generation,
                        deadline_height,
                        local_result_digest: None,
                        canonical_result_digest: None,
                        terminal_reason: None,
                        state: EmbeddedJobStateV1::Computing,
                    },
                );
                Ok(generation)
            }
        }
    }

    pub fn reduce(
        &mut self,
        job_id: B256,
        event: EmbeddedJobEventV1,
    ) -> Result<EmbeddedTransitionPlanV1, EmbeddedOcompStateErrorV1> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or(EmbeddedOcompStateErrorV1::UnknownJob { job_id })?;
        let action = match event {
            EmbeddedJobEventV1::LocalCompleted {
                generation,
                result_digest,
            } => {
                if result_digest.is_zero() {
                    return Err(EmbeddedOcompStateErrorV1::InvalidResult);
                }
                if generation != job.generation {
                    EmbeddedJobActionV1::ProtocolOwned
                } else {
                    reduce_local_completed(self.mode, job_id, job, result_digest)?
                }
            }
            EmbeddedJobEventV1::LocalFailed { generation } => {
                if generation != job.generation {
                    EmbeddedJobActionV1::ProtocolOwned
                } else {
                    match job.state {
                        EmbeddedJobStateV1::Computing | EmbeddedJobStateV1::WaitAtDeadline
                            if self.mode == EmbeddedOcompModeV1::FullNode =>
                        {
                            EmbeddedJobActionV1::FatalLocalFailure
                        }
                        EmbeddedJobStateV1::Computing | EmbeddedJobStateV1::WaitAtDeadline => {
                            EmbeddedJobActionV1::Abstain
                        }
                        EmbeddedJobStateV1::LocalReady
                        | EmbeddedJobStateV1::Verified
                        | EmbeddedJobStateV1::Closed
                        | EmbeddedJobStateV1::FatalMismatch => EmbeddedJobActionV1::ProtocolOwned,
                    }
                }
            }
            EmbeddedJobEventV1::Deadline => {
                if job.terminal_reason.is_some() || self.mode == EmbeddedOcompModeV1::Validator {
                    EmbeddedJobActionV1::ProtocolOwned
                } else if job.local_result_digest.is_some() {
                    EmbeddedJobActionV1::AwaitCanonical { job_id }
                } else {
                    job.state = EmbeddedJobStateV1::WaitAtDeadline;
                    EmbeddedJobActionV1::HoldProgress {
                        job_id,
                        through_height: job.deadline_height,
                    }
                }
            }
            EmbeddedJobEventV1::CanonicalCompleted { result_digest } => {
                if result_digest.is_zero() {
                    return Err(EmbeddedOcompStateErrorV1::InvalidResult);
                }
                reduce_canonical_completed(self.mode, job_id, job, result_digest)?
            }
            EmbeddedJobEventV1::CanonicalClosed { reason } => {
                if reason == EmbeddedTerminalReasonV1::Completed {
                    return Err(EmbeddedOcompStateErrorV1::InvalidTerminalReason);
                }
                match job.terminal_reason {
                    Some(existing) if existing != reason => {
                        return Err(EmbeddedOcompStateErrorV1::ConflictingCanonicalTerminal {
                            job_id,
                        });
                    }
                    Some(_) => {}
                    None => {
                        job.terminal_reason = Some(reason);
                        job.state = EmbeddedJobStateV1::Closed;
                    }
                }
                EmbeddedJobActionV1::CloseTerminal { job_id, reason }
            }
            EmbeddedJobEventV1::VoteFinalized {
                generation,
                success,
            } => {
                if generation != job.generation || job.terminal_reason.is_some() {
                    EmbeddedJobActionV1::ProtocolOwned
                } else {
                    EmbeddedJobActionV1::VoteFinalized { success }
                }
            }
            EmbeddedJobEventV1::VoteFailed { generation } => {
                if generation != job.generation || job.terminal_reason.is_some() {
                    EmbeddedJobActionV1::ProtocolOwned
                } else {
                    EmbeddedJobActionV1::FatalVoteFailure
                }
            }
        };
        Ok(EmbeddedTransitionPlanV1 {
            generation: job.generation,
            action,
        })
    }

    #[must_use]
    pub fn generation(&self, job_id: B256) -> Option<EmbeddedJobGenerationV1> {
        self.jobs.get(&job_id).map(|job| job.generation)
    }

    #[must_use]
    pub fn state(&self, job_id: B256) -> Option<EmbeddedJobStateV1> {
        self.jobs.get(&job_id).map(|job| job.state)
    }

    #[must_use]
    pub fn terminal_reason(&self, job_id: B256) -> Option<EmbeddedTerminalReasonV1> {
        self.jobs.get(&job_id).and_then(|job| job.terminal_reason)
    }

    #[must_use]
    pub fn live_job_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|job| {
                matches!(
                    job.state,
                    EmbeddedJobStateV1::Computing
                        | EmbeddedJobStateV1::WaitAtDeadline
                        | EmbeddedJobStateV1::LocalReady
                )
            })
            .count()
    }

    /// Drop one terminal process-local projection after the request closure
    /// checkpoint covering that exact job is durable.
    pub fn prune_terminal_job(&mut self, job_id: B256) -> Result<bool, EmbeddedOcompStateErrorV1> {
        let Some(job) = self.jobs.get(&job_id) else {
            return Ok(false);
        };
        if job.terminal_reason.is_none() {
            return Err(EmbeddedOcompStateErrorV1::JobNotTerminal { job_id });
        }
        self.jobs.remove(&job_id);
        Ok(true)
    }

    /// Highest finalized height a FullNode may expose to its execution gate.
    #[must_use]
    pub fn progress_limit(&self, finalized_height: u64) -> u64 {
        if self.mode == EmbeddedOcompModeV1::Validator {
            return finalized_height;
        }
        self.jobs
            .values()
            .filter(|job| {
                job.deadline_height <= finalized_height
                    && match job.terminal_reason {
                        None | Some(EmbeddedTerminalReasonV1::Completed) => {
                            job.state != EmbeddedJobStateV1::Verified
                        }
                        Some(
                            EmbeddedTerminalReasonV1::Expired | EmbeddedTerminalReasonV1::Failed,
                        ) => false,
                    }
            })
            .fold(finalized_height, |limit, job| {
                limit.min(job.deadline_height.saturating_sub(1))
            })
    }
}

fn reduce_local_completed(
    mode: EmbeddedOcompModeV1,
    job_id: B256,
    job: &mut EmbeddedJobV1,
    result_digest: B256,
) -> Result<EmbeddedJobActionV1, EmbeddedOcompStateErrorV1> {
    if job.terminal_reason == Some(EmbeddedTerminalReasonV1::Completed)
        && matches!(
            job.state,
            EmbeddedJobStateV1::Verified | EmbeddedJobStateV1::FatalMismatch
        )
    {
        return Ok(EmbeddedJobActionV1::ProtocolOwned);
    }
    if job
        .local_result_digest
        .is_some_and(|existing| existing != result_digest)
    {
        return Err(EmbeddedOcompStateErrorV1::ConflictingLocalResult { job_id });
    }
    if matches!(
        job.terminal_reason,
        Some(EmbeddedTerminalReasonV1::Expired | EmbeddedTerminalReasonV1::Failed)
    ) {
        return Ok(EmbeddedJobActionV1::ProtocolOwned);
    }
    job.local_result_digest = Some(result_digest);
    match (mode, job.canonical_result_digest) {
        (EmbeddedOcompModeV1::Validator, Some(_)) => {
            job.state = EmbeddedJobStateV1::Verified;
            Ok(EmbeddedJobActionV1::ProtocolOwned)
        }
        (EmbeddedOcompModeV1::Validator, None) => {
            job.state = EmbeddedJobStateV1::LocalReady;
            Ok(EmbeddedJobActionV1::SubmitVote {
                job_id,
                result_digest,
            })
        }
        (EmbeddedOcompModeV1::FullNode, None) => {
            job.state = EmbeddedJobStateV1::LocalReady;
            Ok(EmbeddedJobActionV1::AwaitCanonical { job_id })
        }
        (EmbeddedOcompModeV1::FullNode, Some(canonical)) if canonical == result_digest => {
            job.state = EmbeddedJobStateV1::Verified;
            Ok(EmbeddedJobActionV1::ReleaseProgress { job_id })
        }
        (EmbeddedOcompModeV1::FullNode, Some(canonical)) => {
            job.state = EmbeddedJobStateV1::FatalMismatch;
            Ok(EmbeddedJobActionV1::FatalMismatch {
                job_id,
                local_result_digest: result_digest,
                canonical_result_digest: canonical,
            })
        }
    }
}

fn reduce_canonical_completed(
    mode: EmbeddedOcompModeV1,
    job_id: B256,
    job: &mut EmbeddedJobV1,
    result_digest: B256,
) -> Result<EmbeddedJobActionV1, EmbeddedOcompStateErrorV1> {
    if job
        .canonical_result_digest
        .is_some_and(|existing| existing != result_digest)
        || job
            .terminal_reason
            .is_some_and(|reason| reason != EmbeddedTerminalReasonV1::Completed)
    {
        return Err(EmbeddedOcompStateErrorV1::ConflictingCanonicalTerminal { job_id });
    }
    job.canonical_result_digest = Some(result_digest);
    job.terminal_reason = Some(EmbeddedTerminalReasonV1::Completed);
    if mode == EmbeddedOcompModeV1::Validator {
        job.state = EmbeddedJobStateV1::Verified;
        return Ok(EmbeddedJobActionV1::ProtocolOwned);
    }
    let Some(local) = job.local_result_digest else {
        return Ok(EmbeddedJobActionV1::AwaitLocalResult { job_id });
    };
    if local == result_digest {
        job.state = EmbeddedJobStateV1::Verified;
        Ok(EmbeddedJobActionV1::ReleaseProgress { job_id })
    } else {
        job.state = EmbeddedJobStateV1::FatalMismatch;
        Ok(EmbeddedJobActionV1::FatalMismatch {
            job_id,
            local_result_digest: local,
            canonical_result_digest: result_digest,
        })
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EmbeddedOcompStateErrorV1 {
    #[error("embedded OCOMP job identity or deadline is invalid")]
    InvalidJob,
    #[error("embedded OCOMP local result digest is invalid")]
    InvalidResult,
    #[error("embedded OCOMP terminal reason is invalid for this event")]
    InvalidTerminalReason,
    #[error("embedded OCOMP generation space is exhausted")]
    GenerationExhausted,
    #[error("embedded OCOMP replay conflicts for job {job_id}")]
    ConflictingReplay { job_id: B256 },
    #[error("embedded OCOMP local result conflicts for job {job_id}")]
    ConflictingLocalResult { job_id: B256 },
    #[error("embedded OCOMP canonical terminal conflicts for job {job_id}")]
    ConflictingCanonicalTerminal { job_id: B256 },
    #[error("embedded OCOMP job {job_id} is unknown")]
    UnknownJob { job_id: B256 },
    #[error("embedded OCOMP job {job_id} is not terminal")]
    JobNotTerminal { job_id: B256 },
}
