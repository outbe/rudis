mod manager_support;

use manager_support::*;
use outbe_radicle::manager::{
    evaluate_phase, DisconnectDisposition, ManagerConfig, ManagerDependencies, ManagerPhase,
    PhaseError, PhaseInput, PhaseMode, RadicleManager, RetryPolicy,
};
use std::{collections::VecDeque, sync::Arc, time::Duration};

async fn wait_for(
    handle: &outbe_radicle::manager::RadicleManagerHandle,
    height: u64,
) -> outbe_radicle::manager::ManagerStatus {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = handle.status();
            if status
                .last_seen_finalized
                .is_some_and(|block| block.number >= height)
            {
                return status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

fn start(
    feed: Feed,
    snapshots: Snapshots,
    endpoints: Endpoints,
    control: Control,
    availability: Availability,
) -> outbe_radicle::manager::RadicleManagerHandle {
    RadicleManager::start(
        ManagerConfig {
            self_validator: SELF,
            local_node_id: LOCAL_NODE,
            repair_interval: Duration::from_millis(20),
            retry: RetryPolicy {
                base: Duration::from_millis(10),
                max: Duration::from_millis(40),
                jitter: Duration::ZERO,
            },
        },
        ManagerDependencies {
            finality: Arc::new(feed),
            snapshots: Arc::new(snapshots),
            endpoints: Arc::new(endpoints),
            control: Arc::new(control),
            repository_status: Arc::new(availability),
        },
    )
}

#[tokio::test]
async fn startup_order() {
    let feed = Feed::new(block(10));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(10, 1, vec![]));
    let handle = start(
        feed.clone(),
        snapshots.clone(),
        Endpoints::default(),
        Control::new(LOCAL_NODE),
        Availability::default(),
    );

    let status = wait_for(&handle, 10).await;
    assert_eq!(feed.events(), ["subscribe", "sample"]);
    assert_eq!(snapshots.reads(), [block(10)]);
    assert_eq!(status.last_converged_finalized, Some(block(10)));
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn finality_rules() {
    let feed = Feed::new(block(10));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(10, 1, vec![]));
    snapshots.insert(snapshot(11, 1, vec![]));
    let handle = start(
        feed.clone(),
        snapshots.clone(),
        Endpoints::default(),
        Control::new(LOCAL_NODE),
        Availability::default(),
    );
    wait_for(&handle, 10).await;

    feed.push(block(9));
    feed.push(outbe_radicle::manager::FinalizedBlock {
        number: 10,
        hash: alloy_primitives::B256::repeat_byte(0xee),
    });
    feed.push(block(11));
    let status = wait_for(&handle, 11).await;
    assert_eq!(status.finality_regressions, 1);
    assert_eq!(status.finality_conflicts, 1);
    assert_eq!(status.last_seen_finalized, Some(block(11)));

    feed.push(block(12));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(handle.status().last_seen_finalized, Some(block(11)));
    assert!(handle.status().provider_failures > 0);
    feed.push(outbe_radicle::manager::FinalizedBlock {
        number: 12,
        hash: alloy_primitives::B256::repeat_byte(0xdd),
    });
    feed.push(block(13));
    feed.push(block(12));
    snapshots.insert(snapshot(13, 1, vec![]));
    let status = wait_for(&handle, 13).await;
    assert_eq!(status.finality_regressions, 2);
    assert_eq!(status.finality_conflicts, 2);
    assert_eq!(status.last_seen_finalized, Some(block(13)));
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn mesh() {
    let feed = Feed::new(block(20));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(20, 4, vec![]));
    let endpoints = Endpoints::default();
    for index in 2..=4 {
        endpoints.set(endpoint(index, 20, 8776));
    }
    let control = Control::new(LOCAL_NODE);
    control.add_session(inbound(2, 20));
    let handle = start(
        feed,
        snapshots,
        endpoints,
        control.clone(),
        Availability::default(),
    );

    let status = wait_for(&handle, 20).await;
    assert_eq!(status.resolved_peer_count, 3);
    assert_eq!(status.unresolved_peer_count, 0);
    assert_eq!(status.connected_peer_count, 3);
    let mut calls = VecDeque::from(control.calls());
    assert_eq!(
        pop_call(&mut calls),
        Call::Connect([3; 32], endpoint(3, 20, 8776).addresses[0].clone())
    );
    assert_eq!(
        pop_call(&mut calls),
        Call::Connect([4; 32], endpoint(4, 20, 8776).addresses[0].clone())
    );
    assert!(calls.is_empty());
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn unresolved_and_scale() {
    let feed = Feed::new(block(30));
    let snapshots = Snapshots::default();
    let mut value = snapshot(30, 20, vec![]);
    value.validators[7].node_id = None;
    snapshots.insert(value);
    let endpoints = Endpoints::default();
    for index in 2..=20 {
        if index != 8 {
            endpoints.set(endpoint(index, 30, 8776));
        }
    }
    let control = Control::new(LOCAL_NODE);
    let handle = start(
        feed,
        snapshots,
        endpoints,
        control.clone(),
        Availability::default(),
    );
    let status = wait_for(&handle, 30).await;
    assert_eq!(status.resolved_peer_count, 18);
    assert_eq!(status.unresolved_peer_count, 1);
    assert_eq!(status.connected_peer_count, 18);
    assert_eq!(
        control
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Connect(..)))
            .count(),
        18
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn repair_and_replace() {
    let feed = Feed::new(block(40));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(40, 2, vec![]));
    snapshots.insert(snapshot(41, 2, vec![]));
    snapshots.insert(snapshot(141, 2, vec![]));
    let endpoints = Endpoints::default();
    endpoints.set(endpoint(2, 40, 8776));
    let control = Control::new(LOCAL_NODE);
    let handle = start(
        feed.clone(),
        snapshots,
        endpoints.clone(),
        control.clone(),
        Availability::default(),
    );
    wait_for(&handle, 40).await;

    control.clear_sessions();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        control
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Connect(..)))
            .count()
            >= 2
    );

    endpoints.set(endpoint(2, 41, 9776));
    feed.push(block(41));
    wait_for(&handle, 41).await;
    assert!(control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Disconnect(id, _) if *id == [2; 32])));
    assert!(control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Connect(id, address) if *id == [2; 32] && address.port() == 9776)));

    feed.push(block(141));
    let status = wait_for(&handle, 141).await;
    assert_eq!(status.resolved_peer_count, 0);
    assert_eq!(status.unresolved_peer_count, 1);
    assert!(
        control
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Disconnect(id, _) if *id == [2; 32]))
            .count()
            >= 2
    );
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn managed_only() {
    let feed = Feed::new(block(50));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(50, 2, vec![]));
    snapshots.insert(snapshot(51, 1, vec![]));
    let endpoints = Endpoints::default();
    endpoints.set(endpoint(2, 50, 8776));
    let control = Control::new(LOCAL_NODE);
    control.add_session(inbound(9, 50));
    let handle = start(
        feed.clone(),
        snapshots,
        endpoints,
        control.clone(),
        Availability::default(),
    );
    wait_for(&handle, 50).await;
    feed.push(block(51));
    wait_for(&handle, 51).await;

    assert!(control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Disconnect(id, _) if *id == [2; 32])));
    assert!(!control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Disconnect(id, _) if *id == [9; 32])));
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_cleanup() {
    let feed = Feed::new(block(52));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(52, 1, vec![]));
    let control = Control::new(LOCAL_NODE);
    control.add_session(outbound(2, 51, 8776));
    control.add_session(pending_outbound(3, 51, 8776));
    let handle = start(
        feed,
        snapshots,
        Endpoints::default(),
        control.clone(),
        Availability::default(),
    );
    wait_for(&handle, 52).await;
    assert!(control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Disconnect(id, _) if *id == [2; 32])));
    assert!(control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Disconnect(id, _) if *id == [3; 32])));
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn changed_address() {
    let feed = Feed::new(block(53));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(53, 2, vec![]));
    let endpoints = Endpoints::default();
    endpoints.set(endpoint(2, 53, 9776));
    let control = Control::new(LOCAL_NODE);
    control.add_session(outbound(2, 52, 8776));
    control.set_disconnect(DisconnectDisposition::AddressChanged);
    let handle = start(
        feed,
        snapshots,
        endpoints,
        control.clone(),
        Availability::default(),
    );
    wait_for(&handle, 53).await;
    assert_eq!(handle.status().last_converged_finalized, None);
    assert!(!control
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Connect(id, _) if *id == [2; 32])));

    control.set_disconnect(DisconnectDisposition::Disconnected);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.status().last_converged_finalized == Some(block(53)) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(control.calls().iter().any(
        |call| matches!(call, Call::Connect(id, address) if *id == [2; 32] && address.port() == 9776)
    ));
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn repos() {
    let repositories = vec![repo(1), repo(2)];
    let feed = Feed::new(block(60));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(60, 1, repositories.clone()));
    let control = Control::new(LOCAL_NODE);
    let availability = Availability::default();
    availability.set(repositories[0], true);
    let handle = start(
        feed,
        snapshots,
        Endpoints::default(),
        control.clone(),
        availability,
    );

    let status = wait_for(&handle, 60).await;
    assert_eq!(status.desired_repository_count, 2);
    assert_eq!(status.available_repository_count, 1);
    assert_eq!(status.pending_repository_count, 1);
    assert_eq!(status.last_converged_finalized, Some(block(60)));
    assert_eq!(
        control
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Seed(_)))
            .count(),
        2
    );
    handle.shutdown().await.unwrap();

    let feed = Feed::new(block(60));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(60, 1, repositories));
    let second = start(
        feed,
        snapshots,
        Endpoints::default(),
        control.clone(),
        Availability::default(),
    );
    wait_for(&second, 60).await;
    assert_eq!(
        control
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Seed(_)))
            .count(),
        4
    );
    second.shutdown().await.unwrap();
}

#[tokio::test]
async fn partial_failure() {
    let repository = repo(3);
    let feed = Feed::new(block(70));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(70, 1, vec![repository]));
    let control = Control::new(LOCAL_NODE);
    control.fail_seed(repository, true);
    let availability = Availability::default();
    availability.fail(true);
    let handle = start(
        feed,
        snapshots,
        Endpoints::default(),
        control.clone(),
        availability.clone(),
    );

    let status = wait_for(&handle, 70).await;
    assert_eq!(status.last_seen_finalized, Some(block(70)));
    assert_eq!(status.last_converged_finalized, None);
    assert_eq!(status.phase, ManagerPhase::Ready);
    assert_eq!(status.phase_error, None);
    assert_eq!(status.pending_repository_count, 1);
    assert!(status.tcp_status_failures > 0);

    control.fail_seed(repository, false);
    availability.fail(false);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.status().last_converged_finalized == Some(block(70)) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn remote_connect_failure_preserves_ready() {
    let feed = Feed::new(block(71));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(71, 2, vec![]));
    let endpoints = Endpoints::default();
    endpoints.set(endpoint(2, 71, 8776));
    let control = Control::new(LOCAL_NODE);
    control.fail_connect([2; 32], true);
    let handle = start(
        feed,
        snapshots,
        endpoints,
        control.clone(),
        Availability::default(),
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if control
                .calls()
                .iter()
                .any(|call| matches!(call, Call::Connect(node_id, _) if *node_id == [2; 32]))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let status = handle.status();
    assert_eq!(status.phase, ManagerPhase::Ready);
    assert_eq!(status.phase_error, None);
    assert_eq!(status.last_converged_finalized, None);

    control.fail_connect([2; 32], false);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.status().last_converged_finalized == Some(block(71)) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn remote_connect_failure_preserves_joining_unbound() {
    let feed = Feed::new(block(72));
    let snapshots = Snapshots::default();
    let mut value = snapshot(72, 2, vec![]);
    value.validators[0].node_id = None;
    snapshots.insert(value);
    let endpoints = Endpoints::default();
    endpoints.set(endpoint(2, 72, 8776));
    let control = Control::new(LOCAL_NODE);
    control.fail_connect([2; 32], true);
    let handle = start(
        feed,
        snapshots,
        endpoints,
        control.clone(),
        Availability::default(),
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if control
                .calls()
                .iter()
                .any(|call| matches!(call, Call::Connect(node_id, _) if *node_id == [2; 32]))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let status = handle.status();
    assert_eq!(status.phase, ManagerPhase::JoiningUnbound);
    assert_eq!(status.phase_error, None);
    assert_eq!(status.last_converged_finalized, None);
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn local_sessions_failure_before_ready_is_unavailable() {
    let feed = Feed::new(block(73));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(73, 1, vec![]));
    let control = Control::new(LOCAL_NODE);
    control.fail_sessions(true);
    let handle = start(
        feed,
        snapshots,
        Endpoints::default(),
        control,
        Availability::default(),
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.status().phase_error == Some(PhaseError::SidecarUnavailable) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(handle.status().last_converged_finalized, None);
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn degraded_recovery() {
    let feed = Feed::new(block(80));
    let snapshots = Snapshots::default();
    snapshots.insert(snapshot(80, 1, vec![]));
    let control = Control::new(LOCAL_NODE);
    let handle = start(
        feed,
        snapshots,
        Endpoints::default(),
        control.clone(),
        Availability::default(),
    );
    wait_for(&handle, 80).await;
    control.fail_sessions(true);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.status().phase == ManagerPhase::RuntimeDegraded {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    control.fail_sessions(false);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.status().phase == ManagerPhase::Ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    handle.shutdown().await.unwrap();
}

#[tokio::test]
async fn binding_mismatch() {
    let feed = Feed::new(block(81));
    let snapshots = Snapshots::default();
    let mut value = snapshot(81, 1, vec![]);
    value.validators[0].node_id = Some([9; 32]);
    snapshots.insert(value);
    let handle = start(
        feed,
        snapshots,
        Endpoints::default(),
        Control::new(LOCAL_NODE),
        Availability::default(),
    );
    let status = wait_for(&handle, 81).await;
    assert_eq!(status.phase_error, Some(PhaseError::BindingMismatch));
    assert_eq!(status.last_converged_finalized, None);
    handle.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn retry_backoff() {
    let feed = Feed::new(block(82));
    let snapshots = Snapshots::default();
    let handle = RadicleManager::start(
        ManagerConfig {
            self_validator: SELF,
            local_node_id: LOCAL_NODE,
            repair_interval: Duration::from_secs(3_600),
            retry: RetryPolicy {
                base: Duration::from_secs(1),
                max: Duration::from_secs(30),
                jitter: Duration::ZERO,
            },
        },
        ManagerDependencies {
            finality: Arc::new(feed),
            snapshots: Arc::new(snapshots.clone()),
            endpoints: Arc::new(Endpoints::default()),
            control: Arc::new(Control::new(LOCAL_NODE)),
            repository_status: Arc::new(Availability::default()),
        },
    );
    tokio::task::yield_now().await;
    assert_eq!(snapshots.reads().len(), 1);
    tokio::time::advance(Duration::from_millis(999)).await;
    assert_eq!(snapshots.reads().len(), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(snapshots.reads().len(), 2);
    tokio::time::advance(Duration::from_millis(1_999)).await;
    assert_eq!(snapshots.reads().len(), 2);
    tokio::time::advance(Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(snapshots.reads().len(), 3);
    handle.shutdown().await.unwrap();
}

#[test]
fn phases() {
    assert_eq!(
        evaluate_phase(PhaseInput {
            mode: PhaseMode::FullNodeDisabled,
            sidecar_available: false,
            local_node_id: None,
            finalized_binding: None,
            was_ready: false,
        })
        .unwrap(),
        ManagerPhase::Disabled
    );
    assert_eq!(
        evaluate_phase(PhaseInput {
            mode: PhaseMode::Validator,
            sidecar_available: true,
            local_node_id: Some(LOCAL_NODE),
            finalized_binding: None,
            was_ready: false,
        })
        .unwrap(),
        ManagerPhase::JoiningUnbound
    );
    assert_eq!(
        evaluate_phase(PhaseInput {
            mode: PhaseMode::Validator,
            sidecar_available: true,
            local_node_id: Some(LOCAL_NODE),
            finalized_binding: Some(LOCAL_NODE),
            was_ready: false,
        })
        .unwrap(),
        ManagerPhase::Ready
    );
    assert_eq!(
        evaluate_phase(PhaseInput {
            mode: PhaseMode::Validator,
            sidecar_available: false,
            local_node_id: Some(LOCAL_NODE),
            finalized_binding: Some(LOCAL_NODE),
            was_ready: true,
        })
        .unwrap(),
        ManagerPhase::RuntimeDegraded
    );
    assert!(evaluate_phase(PhaseInput {
        mode: PhaseMode::Validator,
        sidecar_available: true,
        local_node_id: Some(LOCAL_NODE),
        finalized_binding: Some([9; 32]),
        was_ready: false,
    })
    .is_err());
}
