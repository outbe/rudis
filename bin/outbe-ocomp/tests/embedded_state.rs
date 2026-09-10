use alloy_primitives::B256;
use outbe_ocomp::embedded::{
    EmbeddedJobActionV1, EmbeddedJobEventV1, EmbeddedJobStateV1, EmbeddedOcompJobsV1,
    EmbeddedOcompModeV1, EmbeddedTerminalReasonV1,
};

fn id(byte: u8) -> B256 {
    B256::repeat_byte(byte)
}

fn reduce(
    jobs: &mut EmbeddedOcompJobsV1,
    job_id: B256,
    event: EmbeddedJobEventV1,
) -> EmbeddedJobActionV1 {
    jobs.reduce(job_id, event).unwrap().action
}

#[test]
fn jobs_remain_independent() {
    let first = id(0x11);
    let second = id(0x22);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    jobs.observe_job(first, 100).unwrap();
    let generation = jobs.observe_job(second, 200).unwrap();
    reduce(
        &mut jobs,
        second,
        EmbeddedJobEventV1::LocalCompleted {
            generation,
            result_digest: id(0x33),
        },
    );

    assert_eq!(jobs.state(first), Some(EmbeddedJobStateV1::Computing));
    assert_eq!(jobs.state(second), Some(EmbeddedJobStateV1::LocalReady));
    assert_eq!(jobs.live_job_count(), 2);
}

#[test]
fn only_validator_submits_vote() {
    let job_id = id(0x41);
    let digest = id(0x42);
    let mut validator = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::Validator);
    let mut full_node = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    let validator_generation = validator.observe_job(job_id, 100).unwrap();
    let full_node_generation = full_node.observe_job(job_id, 100).unwrap();

    assert_eq!(
        reduce(
            &mut validator,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation: validator_generation,
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::SubmitVote {
            job_id,
            result_digest: digest,
        }
    );
    assert_eq!(
        reduce(
            &mut full_node,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation: full_node_generation,
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::AwaitCanonical { job_id }
    );
}

#[test]
fn validator_late_result_is_protocol_owned() {
    let job_id = id(0x43);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::Validator);
    let generation = jobs.observe_job(job_id, 100).unwrap();

    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::CanonicalCompleted {
                result_digest: id(0x44),
            },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation,
                result_digest: id(0x45),
            },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalFailed { generation },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
    assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::Verified));
}

#[test]
fn validator_completed_absorbs_late_vote_outcomes() {
    let job_id = id(0x38);
    let digest = id(0x39);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::Validator);
    let generation = jobs.observe_job(job_id, 100).unwrap();
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation,
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::SubmitVote {
            job_id,
            result_digest: digest,
        }
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::CanonicalCompleted {
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );

    for event in [
        EmbeddedJobEventV1::VoteFinalized {
            generation,
            success: true,
        },
        EmbeddedJobEventV1::VoteFinalized {
            generation,
            success: false,
        },
        EmbeddedJobEventV1::VoteFailed { generation },
    ] {
        assert_eq!(
            reduce(&mut jobs, job_id, event),
            EmbeddedJobActionV1::ProtocolOwned
        );
        assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::Verified));
        assert_eq!(
            jobs.terminal_reason(job_id),
            Some(EmbeddedTerminalReasonV1::Completed)
        );
    }
}

#[test]
fn full_node_canonical_first_verifies_exact_result() {
    let job_id = id(0x51);
    let digest = id(0x52);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    let generation = jobs.observe_job(job_id, 100).unwrap();

    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::CanonicalCompleted {
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::AwaitLocalResult { job_id }
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation,
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::ReleaseProgress { job_id }
    );
    assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::Verified));
}

#[test]
fn full_node_mismatch_is_fatal() {
    let job_id = id(0x61);
    let local = id(0x62);
    let canonical = id(0x63);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    let generation = jobs.observe_job(job_id, 100).unwrap();
    reduce(
        &mut jobs,
        job_id,
        EmbeddedJobEventV1::LocalCompleted {
            generation,
            result_digest: local,
        },
    );

    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::CanonicalCompleted {
                result_digest: canonical,
            },
        ),
        EmbeddedJobActionV1::FatalMismatch {
            job_id,
            local_result_digest: local,
            canonical_result_digest: canonical,
        }
    );
    assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::FatalMismatch));
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalFailed { generation },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
}

#[test]
fn every_non_completed_terminal_is_absorbing() {
    for (index, reason) in [
        EmbeddedTerminalReasonV1::Expired,
        EmbeddedTerminalReasonV1::Failed,
    ]
    .into_iter()
    .enumerate()
    {
        let job_id = id(0x70 + index as u8);
        let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
        let generation = jobs.observe_job(job_id, 100).unwrap();
        assert_eq!(
            reduce(
                &mut jobs,
                job_id,
                EmbeddedJobEventV1::CanonicalClosed { reason },
            ),
            EmbeddedJobActionV1::CloseTerminal { job_id, reason }
        );

        for event in [
            EmbeddedJobEventV1::LocalCompleted {
                generation,
                result_digest: id(0x79),
            },
            EmbeddedJobEventV1::LocalFailed { generation },
            EmbeddedJobEventV1::VoteFinalized {
                generation,
                success: false,
            },
            EmbeddedJobEventV1::VoteFailed { generation },
            EmbeddedJobEventV1::Deadline,
        ] {
            assert_eq!(
                reduce(&mut jobs, job_id, event),
                EmbeddedJobActionV1::ProtocolOwned
            );
            assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::Closed));
            assert_eq!(jobs.terminal_reason(job_id), Some(reason));
        }
    }
}

#[test]
fn full_node_completed_requires_local_failure_to_fail_closed() {
    let job_id = id(0x81);
    let digest = id(0x82);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    let generation = jobs.observe_job(job_id, 100).unwrap();
    reduce(
        &mut jobs,
        job_id,
        EmbeddedJobEventV1::CanonicalCompleted {
            result_digest: digest,
        },
    );

    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalFailed { generation },
        ),
        EmbeddedJobActionV1::FatalLocalFailure
    );
}

#[test]
fn full_node_completed_at_deadline_requires_local_failure_to_fail_closed() {
    let job_id = id(0x84);
    let digest = id(0x85);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    let generation = jobs.observe_job(job_id, 100).unwrap();

    assert_eq!(
        reduce(&mut jobs, job_id, EmbeddedJobEventV1::Deadline),
        EmbeddedJobActionV1::HoldProgress {
            job_id,
            through_height: 100,
        }
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::CanonicalCompleted {
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::AwaitLocalResult { job_id }
    );
    assert_eq!(jobs.progress_limit(110), 99);
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalFailed { generation },
        ),
        EmbeddedJobActionV1::FatalLocalFailure
    );
}

#[test]
fn verified_full_node_absorbs_late_failure() {
    let job_id = id(0x86);
    let digest = id(0x87);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    let generation = jobs.observe_job(job_id, 100).unwrap();
    reduce(
        &mut jobs,
        job_id,
        EmbeddedJobEventV1::CanonicalCompleted {
            result_digest: digest,
        },
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation,
                result_digest: digest,
            },
        ),
        EmbeddedJobActionV1::ReleaseProgress { job_id }
    );
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalFailed { generation },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
    assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::Verified));
}

#[test]
fn stale_generation_cannot_change_current_job() {
    let job_id = id(0x91);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::Validator);
    jobs.observe_job(job_id, 100).unwrap();
    let stale = jobs.observe_job(id(0x93), 101).unwrap();

    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalCompleted {
                generation: stale,
                result_digest: id(0x92),
            },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
    assert_eq!(jobs.state(job_id), Some(EmbeddedJobStateV1::Computing));
    assert_eq!(
        reduce(
            &mut jobs,
            job_id,
            EmbeddedJobEventV1::LocalFailed { generation: stale },
        ),
        EmbeddedJobActionV1::ProtocolOwned
    );
}

#[test]
fn full_node_progress_waits_for_exact_completed_result() {
    let first = id(0xa1);
    let second = id(0xa2);
    let digest = id(0xa3);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    jobs.observe_job(first, 100).unwrap();
    let generation = jobs.observe_job(second, 120).unwrap();
    reduce(
        &mut jobs,
        second,
        EmbeddedJobEventV1::LocalCompleted {
            generation,
            result_digest: digest,
        },
    );

    assert_eq!(jobs.progress_limit(130), 99);
    reduce(
        &mut jobs,
        first,
        EmbeddedJobEventV1::CanonicalClosed {
            reason: EmbeddedTerminalReasonV1::Expired,
        },
    );
    assert_eq!(jobs.progress_limit(130), 119);
    reduce(
        &mut jobs,
        second,
        EmbeddedJobEventV1::CanonicalCompleted {
            result_digest: digest,
        },
    );
    assert_eq!(jobs.progress_limit(130), 130);
}

#[test]
fn durable_checkpoint_pruning_removes_only_the_covered_terminal_job() {
    let terminal = id(0xb1);
    let live = id(0xb2);
    let other_terminal = id(0xb3);
    let mut jobs = EmbeddedOcompJobsV1::new(EmbeddedOcompModeV1::FullNode);
    jobs.observe_job(terminal, 100).unwrap();
    jobs.observe_job(live, 120).unwrap();
    jobs.observe_job(other_terminal, 140).unwrap();
    reduce(
        &mut jobs,
        terminal,
        EmbeddedJobEventV1::CanonicalClosed {
            reason: EmbeddedTerminalReasonV1::Failed,
        },
    );
    reduce(
        &mut jobs,
        other_terminal,
        EmbeddedJobEventV1::CanonicalClosed {
            reason: EmbeddedTerminalReasonV1::Expired,
        },
    );

    assert!(jobs.prune_terminal_job(terminal).unwrap());
    assert_eq!(jobs.state(terminal), None);
    assert_eq!(jobs.state(live), Some(EmbeddedJobStateV1::Computing));
    assert_eq!(jobs.state(other_terminal), Some(EmbeddedJobStateV1::Closed));
    assert!(matches!(
        jobs.prune_terminal_job(live),
        Err(outbe_ocomp::embedded::EmbeddedOcompStateErrorV1::JobNotTerminal {
            job_id
        }) if job_id == live
    ));
}
