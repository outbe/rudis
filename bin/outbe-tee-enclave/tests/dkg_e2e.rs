//! End-to-end TEE DKG ceremony over the real transport.
//!
//! Spins up N enclave servers (each a real UDS + Noise-IK responder), connects N
//! host [`EnclaveClient`]s, and drives a full DKG ceremony with
//! [`CeremonyCoordinator`]s routing messages between peers in-process. Every
//! secret operation crosses the real Noise-IK channel to a separate enclave; the
//! host only relays opaque bytes. This is the localnet ceremony minus the
//! commonware P2P networking (substituted by in-process message routing).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixListener;
use std::thread;

use alloy_primitives::B256;

use outbe_tee::protocol::{EnclaveRequest, EnclaveResponse};
use outbe_tee::tee_dkg::{Ack, DealerBundle, FinalizedLog};
use outbe_tee::{CeremonyCoordinator, EnclaveClient};
use outbe_tee_enclave::keys::EnclaveKeys;
use outbe_tee_enclave::transport::serve_connection_for_network_test;

const N: usize = 4;

#[test]
fn dkg_rejects_a_ceremony_id_from_another_network_binding() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("foreign-network.sock");
    let expected_binding = outbe_primitives::tee_attestation_v1::NetworkBindingV1 {
        chain_id: alloy_primitives::U256::from(outbe_primitives::chain::TESTNET_CHAIN_ID)
            .to_be_bytes(),
        genesis_hash: B256::repeat_byte(0x5b),
        attestation_mode: outbe_primitives::tee_attestation_v1::AttestationMode::GramineDirectDev,
    };
    let foreign_binding = outbe_primitives::tee_attestation_v1::NetworkBindingV1 {
        genesis_hash: B256::repeat_byte(0x6c),
        ..expected_binding
    };
    let keys = EnclaveKeys::new([0x11; 32], None).unwrap();
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind test enclave socket: {error}"),
    };
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let offer_key = std::sync::Arc::new(std::sync::OnceLock::new());
        let _ = serve_connection_for_network_test(stream, &keys, &offer_key, foreign_binding);
    });
    let mut client = EnclaveClient::connect(&socket).unwrap();
    let participant_bls = match client.request(&EnclaveRequest::GetPublicKeys).unwrap() {
        EnclaveResponse::PublicKeys { tee_bls_pub, .. } => vec![tee_bls_pub],
        other => panic!("unexpected GetPublicKeys: {other:?}"),
    };
    let participant_set_hash =
        outbe_primitives::tee_attestation_v1::dkg_participant_set_hash_v1(&participant_bls)
            .unwrap();
    let ceremony_id = outbe_primitives::tee_attestation_v1::dkg_ceremony_id_v1(
        &expected_binding,
        0,
        participant_set_hash,
    )
    .unwrap();

    let error = client
        .request(&EnclaveRequest::DkgParticipantAnnounceV1 {
            ceremony_id,
            round: 0,
            participant_bls,
        })
        .unwrap_err();
    assert!(error.to_string().contains("does not match network"));

    drop(client);
    server.join().unwrap();
}

#[test]
fn full_dkg_ceremony_over_real_noise_transport() {
    let dir = tempfile::tempdir().unwrap();
    let network_binding = outbe_primitives::tee_attestation_v1::NetworkBindingV1 {
        chain_id: alloy_primitives::U256::from(outbe_primitives::chain::TESTNET_CHAIN_ID)
            .to_be_bytes(),
        genesis_hash: B256::repeat_byte(0x5b),
        attestation_mode: outbe_primitives::tee_attestation_v1::AttestationMode::DcapRequired,
    };

    // Spin up N enclaves: each a distinct identity, a UDS, and a server thread
    // serving one connection (the whole ceremony) to completion.
    let mut servers = Vec::new();
    let mut socks = Vec::new();
    for i in 0..N {
        let sock = dir.path().join(format!("enclave{i}.sock"));
        let keys = EnclaveKeys::new([i as u8 + 1; 32], None).unwrap();
        let listener = UnixListener::bind(&sock).unwrap();
        servers.push(thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let offer_key = std::sync::Arc::new(std::sync::OnceLock::new());
            let _ = serve_connection_for_network_test(stream, &keys, &offer_key, network_binding);
        }));
        socks.push(sock);
    }

    // Connect a host client per enclave (GetQuote -> verify -> Noise-IK).
    let mut clients: Vec<EnclaveClient> = socks
        .iter()
        .map(|s| EnclaveClient::connect(s).unwrap())
        .collect();

    let participant_bls = clients
        .iter_mut()
        .map(
            |client| match client.request(&EnclaveRequest::GetPublicKeys).unwrap() {
                EnclaveResponse::PublicKeys { tee_bls_pub, .. } => tee_bls_pub,
                other => panic!("unexpected GetPublicKeys: {other:?}"),
            },
        )
        .collect::<Vec<_>>();
    let participant_set_hash =
        outbe_primitives::tee_attestation_v1::dkg_participant_set_hash_v1(&participant_bls)
            .unwrap();
    let ceremony_id = outbe_primitives::tee_attestation_v1::dkg_ceremony_id_v1(
        &network_binding,
        0,
        participant_set_hash,
    )
    .unwrap();
    let identities = clients
        .iter_mut()
        .map(|client| {
            match client
                .request(&EnclaveRequest::DkgParticipantAnnounceV1 {
                    ceremony_id,
                    round: 0,
                    participant_bls: participant_bls.clone(),
                })
                .unwrap()
            {
                EnclaveResponse::DkgParticipantAnnounceV1 { participant } => participant,
                other => panic!("unexpected DKG announcement: {other:?}"),
            }
        })
        .collect::<Vec<_>>();

    let index_of: BTreeMap<Vec<u8>, usize> = identities
        .iter()
        .enumerate()
        .map(|(i, p)| (p.bls_pub.clone(), i))
        .collect();

    let coords: Vec<CeremonyCoordinator> = identities
        .iter()
        .map(|p| CeremonyCoordinator::new(ceremony_id, 0, p.bls_pub.clone(), identities.clone()))
        .collect();

    // Open the ceremony on every enclave.
    for i in 0..N {
        coords[i].open(&mut clients[i]).expect("open");
    }

    // Seam A: every node deals; route each sealed bundle to its recipient.
    let mut bundle_inbox: Vec<Vec<DealerBundle>> = vec![Vec::new(); N];
    for i in 0..N {
        for addressed in coords[i].deal(&mut clients[i]).expect("deal") {
            let j = index_of[&addressed.to];
            bundle_inbox[j].push(addressed.msg);
        }
    }

    // Seam B: every node opens+verifies its incoming bundles; route acks back.
    let mut ack_inbox: Vec<Vec<Ack>> = vec![Vec::new(); N];
    for j in 0..N {
        let bundles = std::mem::take(&mut bundle_inbox[j]);
        for bundle in &bundles {
            if let Some(addressed) = coords[j].ingest(&mut clients[j], bundle).expect("ingest") {
                let dealer = index_of[&addressed.to];
                ack_inbox[dealer].push(addressed.msg);
            }
        }
    }

    // Seam C: every dealer records the acks it received.
    for i in 0..N {
        let acks = std::mem::take(&mut ack_inbox[i]);
        for ack in &acks {
            coords[i]
                .receive_ack(&mut clients[i], ack)
                .expect("receive_ack");
        }
    }

    // Seam D: every dealer finalizes its log; broadcast (collect all).
    let logs: Vec<FinalizedLog> = (0..N)
        .map(|i| {
            coords[i]
                .finalize_dealer(&mut clients[i])
                .expect("finalize_dealer")
        })
        .collect();

    // Seam E: every node verifies all logs and recovers its threshold share.
    let outcomes: Vec<_> = (0..N)
        .map(|i| {
            coords[i]
                .finalize_player(&mut clients[i], &logs)
                .expect("finalize_player")
        })
        .collect();

    // All parties agree on the public group key; each holds a distinct share.
    let group = &outcomes[0].group_public;
    assert!(
        outcomes.iter().all(|o| &o.group_public == group),
        "all parties must derive the same group key over the real transport",
    );
    assert!(!group.is_empty());
    let commitments: BTreeSet<B256> = outcomes.iter().map(|o| o.share_commitment).collect();
    assert_eq!(commitments.len(), N, "share commitments must be distinct");

    // Closing the clients ends the server loops.
    drop(clients);
    for s in servers {
        s.join().unwrap();
    }
}
