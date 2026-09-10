mod manager_support;

use alloy_primitives::B256;
use manager_support::{Availability, Control, Endpoints, Snapshots, LOCAL_NODE, SELF};
use outbe_radicle::{
    endpoint::EndpointAddress,
    integration::{
        evaluate_voting_gate, query_sidecar, ExactBindingState, GenesisFallbackFinalizedFeed,
        RadicleStatusChannel, RadicleVotingGate, RadicleVotingGateError, VotingGateInput,
    },
    manager::{
        BoxFuture, FinalizedBlock, FinalizedFeed, ManagerConfig, ManagerDependencies, ManagerError,
        ManagerPhase, PhaseError, RadicleManager, RetryPolicy,
    },
};
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tokio::sync::mpsc;

fn serve(socket: &Path, node_id: [u8; 32], addresses: &[&str]) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    let encoded_node_id = {
        let mut bytes = [0_u8; 34];
        bytes[..2].copy_from_slice(&[0xed, 0x01]);
        bytes[2..].copy_from_slice(&node_id);
        multibase::encode(multibase::Base::Base58Btc, bytes)
    };
    let addresses = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let command: Value = serde_json::from_str(&line).unwrap();
            let response = match command["command"].as_str().unwrap() {
                "nodeId" => serde_json::to_string(&encoded_node_id).unwrap(),
                "config" => serde_json::json!({ "externalAddresses": addresses }).to_string(),
                other => panic!("unexpected command: {other}"),
            };
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    })
}

#[tokio::test]
async fn sidecar_identity_and_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("control.sock");
    let node_id = [7_u8; 32];
    let server = serve(
        &socket,
        node_id,
        &[
            "seed.example.com:8776",
            "198.51.100.7:8776",
            "[2001:db8::7]:8776",
        ],
    );

    let info = query_sidecar(&socket, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(info.node_id, node_id);
    assert_eq!(info.addresses.len(), 3);
    assert!(info
        .addresses
        .contains(&EndpointAddress::ipv4([198, 51, 100, 7], 8776).unwrap()));
    assert!(info
        .addresses
        .contains(&EndpointAddress::dns("seed.example.com", 8776).unwrap()));
    assert!(info.addresses.windows(2).all(|pair| pair[0] < pair[1]));
    server.join().unwrap();
}

#[tokio::test]
async fn sidecar_preflight_is_bounded_and_rejects_bad_advertise() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.sock");
    assert!(query_sidecar(&missing, Duration::from_millis(20))
        .await
        .is_err());

    let stalled = dir.path().join("stalled.sock");
    let listener = UnixListener::bind(&stalled).unwrap();
    let server = thread::spawn(move || {
        let _stream = listener.accept().unwrap().0;
        thread::sleep(Duration::from_millis(100));
    });
    assert!(query_sidecar(&stalled, Duration::from_millis(20))
        .await
        .is_err());
    server.join().unwrap();

    let socket = dir.path().join("duplicate.sock");
    let server = serve(
        &socket,
        [8_u8; 32],
        &["198.51.100.8:8776", "198.51.100.8:8776"],
    );
    assert!(query_sidecar(&socket, Duration::from_secs(1))
        .await
        .is_err());
    server.join().unwrap();
}

fn gate(
    binding: ExactBindingState,
    phase: ManagerPhase,
    phase_error: Option<PhaseError>,
    ever_ready: bool,
) -> RadicleVotingGate {
    evaluate_voting_gate(VotingGateInput {
        binding,
        manager_phase: phase,
        phase_error,
        ever_ready,
    })
}

#[test]
fn voting_gate_exact_binding_precedes_health_phase() {
    use ExactBindingState::{ActiveMatching, ActiveMismatch, ActiveMissing, SelfAbsent};
    use RadicleVotingGate::{Fatal, SignerAllowed, Verifier};

    assert_eq!(
        gate(SelfAbsent, ManagerPhase::JoiningUnbound, None, false),
        Verifier
    );
    assert_eq!(
        gate(ActiveMatching, ManagerPhase::Ready, None, false),
        SignerAllowed
    );
    assert_eq!(
        gate(ActiveMatching, ManagerPhase::RuntimeDegraded, None, true),
        SignerAllowed
    );
    assert_eq!(
        gate(SelfAbsent, ManagerPhase::RuntimeDegraded, None, true),
        Verifier
    );

    for (binding, error) in [
        (ActiveMissing, RadicleVotingGateError::ActiveBindingMissing),
        (ActiveMismatch, RadicleVotingGateError::BindingMismatch),
    ] {
        for phase in [
            ManagerPhase::JoiningUnbound,
            ManagerPhase::Ready,
            ManagerPhase::RuntimeDegraded,
        ] {
            assert_eq!(gate(binding, phase, None, true), Fatal(error));
        }
    }
}

#[test]
fn voting_gate_distinguishes_pre_ready_from_runtime_degraded() {
    use ExactBindingState::{ActiveMatching, SelfAbsent};
    use RadicleVotingGate::{Fatal, SignerAllowed};

    assert_eq!(
        gate(
            SelfAbsent,
            ManagerPhase::JoiningUnbound,
            Some(PhaseError::SidecarUnavailable),
            false
        ),
        Fatal(RadicleVotingGateError::SidecarUnavailable)
    );
    assert_eq!(
        gate(
            ActiveMatching,
            ManagerPhase::JoiningUnbound,
            Some(PhaseError::LocalNodeIdUnavailable),
            false
        ),
        Fatal(RadicleVotingGateError::LocalNodeIdUnavailable)
    );
    assert_eq!(
        gate(ActiveMatching, ManagerPhase::RuntimeDegraded, None, true),
        SignerAllowed
    );
}

#[test]
fn voting_gate_matrix() {
    use ExactBindingState::{ActiveMatching, ActiveMismatch, ActiveMissing, SelfAbsent};
    use RadicleVotingGate::{Fatal, SignerAllowed, Verifier};

    for binding in [SelfAbsent, ActiveMissing, ActiveMatching, ActiveMismatch] {
        for ever_ready in [false, true] {
            for uds_available in [false, true] {
                let phase = if ever_ready && uds_available {
                    ManagerPhase::Ready
                } else if uds_available {
                    ManagerPhase::JoiningUnbound
                } else {
                    ManagerPhase::RuntimeDegraded
                };
                let phase_error = (!uds_available).then_some(PhaseError::SidecarUnavailable);
                let expected = match binding {
                    ActiveMissing => Fatal(RadicleVotingGateError::ActiveBindingMissing),
                    ActiveMismatch => Fatal(RadicleVotingGateError::BindingMismatch),
                    SelfAbsent if !ever_ready && !uds_available => {
                        Fatal(RadicleVotingGateError::SidecarUnavailable)
                    }
                    SelfAbsent => Verifier,
                    ActiveMatching if !ever_ready && !uds_available => {
                        Fatal(RadicleVotingGateError::SidecarUnavailable)
                    }
                    ActiveMatching if ever_ready => SignerAllowed,
                    ActiveMatching => Verifier,
                };
                assert_eq!(
                    gate(binding, phase, phase_error, ever_ready),
                    expected,
                    "binding={binding:?} ever_ready={ever_ready} uds_available={uds_available}"
                );
            }
        }
    }

    for ever_ready in [false, true] {
        assert_eq!(
            gate(
                ActiveMatching,
                ManagerPhase::RuntimeDegraded,
                Some(PhaseError::BindingMismatch),
                ever_ready,
            ),
            Fatal(RadicleVotingGateError::BindingMismatch)
        );
    }
}

#[tokio::test]
async fn fatal_gate_notifies() {
    let (publisher, handle) =
        RadicleStatusChannel::enabled(alloy_primitives::Address::repeat_byte(1), [1_u8; 32]);
    let mut updates = handle.subscribe();
    publisher.set_voting_gate(RadicleVotingGate::Fatal(
        RadicleVotingGateError::BindingMismatch,
    ));
    tokio::time::timeout(Duration::from_millis(20), updates.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updates.borrow().voting_gate,
        RadicleVotingGate::Fatal(RadicleVotingGateError::BindingMismatch)
    );
}

struct EmptyFeed {
    receiver: Mutex<Option<mpsc::UnboundedReceiver<FinalizedBlock>>>,
}

impl EmptyFeed {
    fn new() -> Self {
        let (_sender, receiver) = mpsc::unbounded_channel();
        Self {
            receiver: Mutex::new(Some(receiver)),
        }
    }
}

impl FinalizedFeed for EmptyFeed {
    fn subscribe(&self) -> Result<mpsc::UnboundedReceiver<FinalizedBlock>, ManagerError> {
        self.receiver
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| ManagerError::Finality("already subscribed".into()))
    }

    fn sample(&self) -> BoxFuture<'_, Result<Option<FinalizedBlock>, ManagerError>> {
        Box::pin(async { Ok(None) })
    }
}

#[tokio::test]
async fn genesis_feed() {
    let genesis = FinalizedBlock {
        number: 0,
        hash: B256::repeat_byte(0xaa),
    };
    let feed = GenesisFallbackFinalizedFeed::new(Arc::new(EmptyFeed::new()), genesis);
    assert_eq!(feed.sample().await.unwrap(), Some(genesis));
    let _ = feed.subscribe().unwrap();
}

#[tokio::test]
async fn genesis_reconcile() {
    let genesis = manager_support::block(0);
    let snapshots = Snapshots::default();
    snapshots.insert(manager_support::snapshot(0, 1, vec![]));
    let handle = RadicleManager::start(
        ManagerConfig {
            self_validator: SELF,
            local_node_id: LOCAL_NODE,
            repair_interval: Duration::from_secs(30),
            retry: RetryPolicy::default(),
        },
        ManagerDependencies {
            finality: Arc::new(GenesisFallbackFinalizedFeed::new(
                Arc::new(EmptyFeed::new()),
                genesis,
            )),
            snapshots: Arc::new(snapshots.clone()),
            endpoints: Arc::new(Endpoints::default()),
            control: Arc::new(Control::new(LOCAL_NODE)),
            repository_status: Arc::new(Availability::default()),
        },
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().last_converged_finalized == Some(genesis) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(snapshots.reads(), [genesis]);
    handle.shutdown().await.unwrap();
}
