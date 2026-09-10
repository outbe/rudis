use alloy_primitives::B256;
use outbe_offchain_data::{
    projection_readiness, ProjectionCheckpoint, ProjectionStatus, WaitOutcome,
};

fn checkpoint(number: u64, marker: u8) -> ProjectionCheckpoint {
    ProjectionCheckpoint {
        block_number: number,
        block_hash: B256::repeat_byte(marker),
    }
}

#[tokio::test]
async fn exact_parent_readiness_rejects_future_and_conflicting_materializations() {
    let (publisher, handle) = projection_readiness(checkpoint(0, 0x00), ProjectionStatus::Starting);
    let required = checkpoint(7, 0x07);

    publisher.publish(ProjectionStatus::Ready {
        checkpoint: required,
    });
    assert_eq!(
        handle
            .clone()
            .wait_for(required, std::future::pending())
            .await,
        WaitOutcome::Ready
    );

    publisher.publish(ProjectionStatus::Ready {
        checkpoint: checkpoint(8, 0x08),
    });
    assert_eq!(
        handle
            .clone()
            .wait_for(required, std::future::pending())
            .await,
        WaitOutcome::ProjectionAhead
    );

    publisher.publish(ProjectionStatus::Ready {
        checkpoint: checkpoint(7, 0xff),
    });
    assert!(matches!(
        handle.wait_for(required, std::future::pending()).await,
        WaitOutcome::Fatal(_)
    ));
}

#[tokio::test]
async fn healthy_projection_lag_expires_only_the_callers_existing_budget() {
    let (_publisher, handle) = projection_readiness(
        checkpoint(0, 0x00),
        ProjectionStatus::CatchingUp {
            checkpoint: Some(checkpoint(6, 0x06)),
        },
    );

    let outcome = handle
        .wait_for(checkpoint(7, 0x07), std::future::ready(()))
        .await;

    assert_eq!(outcome, WaitOutcome::BudgetExpired);
}

#[tokio::test]
async fn fresh_projection_accepts_only_the_exact_unpersisted_baseline() {
    let (_publisher, handle) =
        projection_readiness(checkpoint(0, 0xaa), ProjectionStatus::Starting);

    assert_eq!(
        handle
            .clone()
            .wait_for(checkpoint(0, 0xaa), std::future::pending())
            .await,
        WaitOutcome::Ready
    );
    assert!(matches!(
        handle
            .wait_for(checkpoint(0, 0xbb), std::future::pending())
            .await,
        WaitOutcome::Fatal(_)
    ));
}

#[tokio::test]
async fn dropping_the_only_publisher_is_a_fatal_readiness_failure() {
    let (publisher, handle) = projection_readiness(
        checkpoint(0, 0x00),
        ProjectionStatus::Ready {
            checkpoint: checkpoint(7, 0x07),
        },
    );
    drop(publisher);

    assert!(matches!(
        handle
            .wait_for(checkpoint(7, 0x07), std::future::pending())
            .await,
        WaitOutcome::Fatal(_)
    ));
}

#[tokio::test]
async fn catching_up_checkpoint_can_satisfy_an_exact_parent() {
    let (_publisher, handle) = projection_readiness(
        checkpoint(0, 0x00),
        ProjectionStatus::CatchingUp {
            checkpoint: Some(checkpoint(7, 0x07)),
        },
    );

    assert_eq!(
        handle
            .wait_for(checkpoint(7, 0x07), std::future::pending())
            .await,
        WaitOutcome::Ready
    );
}

#[tokio::test]
async fn persisted_checkpoint_never_allows_a_stale_baseline_request() {
    let (_publisher, handle) = projection_readiness(
        checkpoint(0, 0x00),
        ProjectionStatus::Ready {
            checkpoint: checkpoint(7, 0x07),
        },
    );

    assert_eq!(
        handle
            .wait_for(checkpoint(0, 0x00), std::future::pending())
            .await,
        WaitOutcome::ProjectionAhead
    );
}

#[tokio::test]
async fn outage_with_future_state_rejects_a_stale_request_without_waiting() {
    let (_publisher, handle) = projection_readiness(
        checkpoint(0, 0x00),
        ProjectionStatus::MongoUnavailable {
            checkpoint: Some(checkpoint(7, 0x07)),
            since: std::time::Instant::now(),
        },
    );

    assert_eq!(
        handle
            .wait_for(checkpoint(6, 0x06), std::future::pending())
            .await,
        WaitOutcome::ProjectionAhead
    );
}
