//! Unit tests for `dkg_manager`.
//!
//! `boundary` holds the DKG boundary-resolution tests that exercise
//! `Mailbox::resolve_boundary` and its process-local boundary-status cache;
//! they moved here with the production logic. The rest are the ceremony /
//! boundary-artifact / dealer-log tests.

mod boundary;

use alloy_primitives::{address, B256, U256};
use commonware_codec::Encode as _;
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::{observe, Dealer, DealerLog, Info, Logs, Player, SignedDealerLog},
        primitives::{group::Share, sharing::Mode},
    },
    Signer as _,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::TryCollect as _;

use super::*;

/// PHASE 0 de-risk spike: a node that NEVER ran DKG can rebuild an epoch's
/// finalization verifier from the boundary outcome carried in the block
/// (`extra_data`) - using only public data - and verify a real finalization
/// certificate signed by that epoch's committee. This is the load-bearing
/// assumption of the `--upstream` follower (committee-chaining trust model).
#[test]
fn phase0_spike_follower_rebuilds_verifier_from_boundary_and_verifies_finalization() {
    use crate::digest::Digest as OutbeDigest;
    use crate::hybrid::{bls_batch_verification_rng, HybridScheme};
    use commonware_consensus::simplex::types::{Finalization, Proposal, Subject};
    use commonware_consensus::types::{Round, View};
    use commonware_cryptography::bls12381::primitives::sharing::ModeVersion;
    use commonware_cryptography::certificate::Scheme as _;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
    use commonware_utils::ordered::{Quorum as _, Set as OrderedSet};
    use std::num::NonZeroU32;

    // A committee (4 -> N3f1 quorum 3) runs the DKG. We keep the secret shares
    // (to sign) AND the full public Output (to put on-chain in the boundary).
    let mut keys: Vec<bls12381::PrivateKey> = (0..4u8)
        .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
        .collect();
    keys.sort_by_key(|k| k.public_key().encode());
    let participants: OrderedSet<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let dkg = crate::bls::bootstrap_dkg_for_participants(participants.clone()).unwrap();

    // 1. The chain writes the full DKG output into the boundary block.
    let outcome_bytes = encode_outcome(Epoch::new(5), &dkg.output, false);

    // 2. NON-PARTICIPANT decode: rebuild the Output from the block bytes alone
    //    (mirrors `boundary_outcome_polynomial_hash`'s ODKO framing).
    const HEADER_LEN: usize = 4 + 1 + 8 + 1 + 4;
    assert_eq!(&outcome_bytes[0..4], b"ODKO");
    let len = u32::from_be_bytes(outcome_bytes[14..18].try_into().unwrap()) as usize;
    let body = &outcome_bytes[HEADER_LEN..HEADER_LEN + len];
    let cfg = (
        NonZeroU32::new(crate::bls::MAX_VALIDATORS).unwrap(),
        ModeVersion::v0(),
    );
    let recovered = Output::<MinSig, bls12381::PublicKey>::read_cfg(&mut &body[..], &cfg).unwrap();
    let recovered_participants = recovered.players().clone();
    let recovered_polynomial = recovered.public().clone();
    assert_eq!(
        recovered_participants, participants,
        "boundary roundtrip must preserve the committee participant set"
    );

    // 3. Build the verifier ONLY from boundary-decoded public data.
    let ns = config::outbe_app_namespace();
    let verifier =
        HybridScheme::<MinSig>::verifier(&ns, recovered_participants, recovered_polynomial)
            .unwrap();

    // 4. The committee signs a finalization (using their secret shares).
    let signers: Vec<HybridScheme<MinSig>> = keys
        .iter()
        .map(|key| {
            let idx = participants.index(&key.public_key()).unwrap();
            HybridScheme::signer(
                &ns,
                participants.clone(),
                key.clone(),
                dkg.polynomial.clone(),
                dkg.shares[idx.get() as usize].clone(),
            )
            .unwrap()
        })
        .collect();
    let digest = OutbeDigest::from(B256::from_slice(Sha256::hash(b"phase0-spike").as_ref()));
    let proposal = Proposal::new(
        Round::new(Epoch::new(5), View::new(2)),
        View::new(1),
        digest,
    );
    let subject = Subject::Finalize {
        proposal: &proposal,
    };
    let attestations: Vec<_> = signers
        .iter()
        .map(|s| s.sign::<OutbeDigest>(subject).unwrap())
        .collect();
    let certificate = verifier
        .assemble::<_, N3f1>(attestations, &Sequential)
        .unwrap();
    let finalization = Finalization {
        proposal,
        certificate,
    };

    // 5. Verify the cert with the boundary-reconstructed verifier.
    let mut rng = bls_batch_verification_rng();
    assert!(
        finalization.verify(&mut rng, &verifier, &Sequential),
        "PHASE 0 GREEN: non-participant rebuilt the epoch verifier from the boundary \
         outcome and verified a real finalization certificate"
    );
}

#[allow(clippy::type_complexity)]
fn run_test_dkg_complete() -> (
    Vec<bls12381::PrivateKey>,
    Set<bls12381::PublicKey>,
    Output<MinSig, bls12381::PublicKey>,
    Sharing<MinSig>,
    Bytes,
) {
    let mut keys: Vec<bls12381::PrivateKey> = (0..3)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    keys.sort_by_key(|a| a.public_key().encode());

    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();

    let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
        &config::outbe_app_namespace(),
        7,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants.clone(),
    )
    .unwrap();

    let mut dealers = Vec::new();
    let mut pub_msgs = Vec::new();
    let mut all_priv_msgs = Vec::new();

    for key in &keys {
        let (dealer, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info.clone(),
            key.clone(),
            None,
        )
        .unwrap();
        dealers.push(dealer);
        pub_msgs.push(pub_msg);
        all_priv_msgs.push(priv_msgs);
    }

    let mut players: Vec<Player<MinSig, bls12381::PrivateKey>> = keys
        .iter()
        .map(|k| Player::new(info.clone(), k.clone()).unwrap())
        .collect();

    for (dealer_idx, (pub_msg, priv_msgs)) in pub_msgs.iter().zip(all_priv_msgs.iter()).enumerate()
    {
        let dealer_pk = keys[dealer_idx].public_key();
        for (player_pk, priv_msg) in priv_msgs {
            let player_idx = keys
                .iter()
                .position(|k| &k.public_key() == player_pk)
                .unwrap();
            if let Some(ack) = players[player_idx].dealer_message::<N3f1>(
                dealer_pk.clone(),
                pub_msg.clone(),
                priv_msg.clone(),
            ) {
                dealers[dealer_idx]
                    .receive_player_ack(player_pk.clone(), ack)
                    .unwrap();
            }
        }
    }

    let mut logs = std::collections::BTreeMap::new();
    let mut first_log = None;
    for dealer in dealers {
        let signed_log = dealer.finalize::<N3f1>();
        if first_log.is_none() {
            first_log = Some(Bytes::from(signed_log.encode()));
        }
        if let Some((pk, log)) = signed_log.check(&info) {
            logs.insert(pk, log);
        }
    }

    let mut dkg_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info.clone());
    for (dealer, log) in logs {
        dkg_logs.record(dealer, log);
    }
    let (output, _share) = players
        .remove(0)
        .finalize::<N3f1, commonware_cryptography::bls12381::Batch>(
            &mut rand_core::OsRng,
            dkg_logs,
            &Sequential,
        )
        .unwrap();
    let polynomial = output.public().clone();

    (keys, participants, output, polynomial, first_log.unwrap())
}

#[allow(clippy::type_complexity)]
fn run_round(
    keys: &[bls12381::PrivateKey],
    participants: Set<bls12381::PublicKey>,
    previous_output: Option<Output<MinSig, bls12381::PublicKey>>,
    previous_shares: Option<&[Share]>,
    round: u64,
) -> (
    Info<MinSig, bls12381::PublicKey>,
    Output<MinSig, bls12381::PublicKey>,
    Vec<Share>,
    BTreeMap<bls12381::PublicKey, DealerLog<MinSig, bls12381::PublicKey>>,
    BTreeMap<bls12381::PublicKey, Bytes>,
) {
    let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
        &config::outbe_app_namespace(),
        round,
        previous_output,
        Mode::NonZeroCounter,
        participants.clone(),
        participants,
    )
    .unwrap();

    let mut dealers = Vec::new();
    let mut pub_msgs = Vec::new();
    let mut all_priv_msgs = Vec::new();

    for (idx, key) in keys.iter().enumerate() {
        let previous_share = previous_shares.map(|shares| shares[idx].clone());
        let (dealer, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
            rand_core::OsRng,
            info.clone(),
            key.clone(),
            previous_share,
        )
        .unwrap();
        dealers.push(dealer);
        pub_msgs.push(pub_msg);
        all_priv_msgs.push(priv_msgs);
    }

    let mut players: Vec<Player<MinSig, bls12381::PrivateKey>> = keys
        .iter()
        .map(|k| Player::new(info.clone(), k.clone()).unwrap())
        .collect();

    for (dealer_idx, (pub_msg, priv_msgs)) in pub_msgs.iter().zip(all_priv_msgs.iter()).enumerate()
    {
        let dealer_pk = keys[dealer_idx].public_key();
        for (player_pk, priv_msg) in priv_msgs {
            let player_idx = keys
                .iter()
                .position(|k| &k.public_key() == player_pk)
                .unwrap();
            if let Some(ack) = players[player_idx].dealer_message::<N3f1>(
                dealer_pk.clone(),
                pub_msg.clone(),
                priv_msg.clone(),
            ) {
                dealers[dealer_idx]
                    .receive_player_ack(player_pk.clone(), ack)
                    .unwrap();
            }
        }
    }

    let mut logs = BTreeMap::new();
    let mut signed_logs = BTreeMap::new();
    for dealer in dealers {
        let signed_log: SignedDealerLog<MinSig, bls12381::PrivateKey> = dealer.finalize::<N3f1>();
        let encoded = Bytes::from(signed_log.encode());
        if let Some((pk, log)) = signed_log.check(&info) {
            signed_logs.insert(pk.clone(), encoded);
            logs.insert(pk, log);
        }
    }

    let mut shares = Vec::new();
    let mut output = None;
    for player in players {
        let mut dkg_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info.clone());
        for (dealer, log) in logs.clone() {
            dkg_logs.record(dealer, log);
        }
        let (player_output, share) = player
            .finalize::<N3f1, commonware_cryptography::bls12381::Batch>(
                &mut rand_core::OsRng,
                dkg_logs,
                &Sequential,
            )
            .unwrap();
        output = Some(player_output);
        shares.push(share);
    }

    (info, output.unwrap(), shares, logs, signed_logs)
}

fn legacy_group_key_only_outcome(
    epoch: Epoch,
    output: &Output<MinSig, bls12381::PublicKey>,
    is_full_dkg: bool,
) -> Bytes {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ODKO");
    buf.push(0x01);
    buf.extend_from_slice(&epoch.get().to_be_bytes());
    buf.push(u8::from(is_full_dkg));
    let group_bytes = output.public().public().encode();
    buf.extend_from_slice(&(group_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(group_bytes.as_ref());
    Bytes::from(buf)
}

#[test]
fn boundary_artifact_is_deterministic() {
    let (keys, _participants, output, _polynomial, _log) = run_test_dkg_complete();
    let validator_set = ValidatorSet {
        public_keys: keys.iter().map(|k| k.public_key()).collect(),
        addresses: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; 3],
    };

    let a = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: true,
        dkg_cycle: 1,
        freeze_height: 10,
        planned_activation_height: 20,
        vrf_material_version: 1,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let b = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: true,
        dkg_cycle: 1,
        freeze_height: 10,
        planned_activation_height: 20,
        vrf_material_version: 1,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    assert_eq!(a, b);
    assert_ne!(a.vrf_group_public_key, B256::ZERO);
    assert_ne!(a.reshare.active_set_hash, B256::ZERO);
}

#[tokio::test]
async fn pending_boundary_rejects_reordered_missing_or_altered_expiry_exclusions() {
    let (keys, _participants, output, _polynomial, _log) = run_test_dkg_complete();
    let validator_set = ValidatorSet {
        public_keys: keys.iter().map(|key| key.public_key()).collect(),
        addresses: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; 3],
    };
    let exclusions = vec![
        address!("0x4444444444444444444444444444444444444444"),
        address!("0x5555555555555555555555555555555555555555"),
    ];
    let expected = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 10,
        planned_activation_height: 20,
        vrf_material_version: 1,
        is_validator_set_change: true,
        tee_expired_target_exclusions: exclusions,
    })
    .unwrap();
    let manager = Mailbox::new();
    manager.note_ceremony_completed(expected.clone());
    manager
        .verify_pending_boundary_artifact(Epoch::new(1), &expected)
        .await
        .unwrap();

    let mut reordered = expected.clone();
    reordered.tee_expired_target_exclusions.reverse();
    reordered.tee_expired_target_exclusions_hash =
        outbe_primitives::reshare_artifact::tee_expired_target_exclusions_hash(
            &reordered.tee_expired_target_exclusions,
        )
        .unwrap();
    assert!(manager
        .verify_pending_boundary_artifact(Epoch::new(1), &reordered)
        .await
        .is_err());

    let mut missing = expected.clone();
    missing.tee_expired_target_exclusions.pop();
    missing.tee_expired_target_exclusions_hash =
        outbe_primitives::reshare_artifact::tee_expired_target_exclusions_hash(
            &missing.tee_expired_target_exclusions,
        )
        .unwrap();
    assert!(manager
        .verify_pending_boundary_artifact(Epoch::new(1), &missing)
        .await
        .is_err());

    let mut altered = expected.clone();
    altered.tee_expired_target_exclusions[0] =
        address!("0x6666666666666666666666666666666666666666");
    altered.tee_expired_target_exclusions_hash =
        outbe_primitives::reshare_artifact::tee_expired_target_exclusions_hash(
            &altered.tee_expired_target_exclusions,
        )
        .unwrap();
    assert!(manager
        .verify_pending_boundary_artifact(Epoch::new(1), &altered)
        .await
        .is_err());
}

#[test]
fn assert_canonical_output_accepts_equal_and_rejects_divergent() {
    let (_keys, _participants, output, _polynomial, _log) = run_test_dkg_complete();

    // Equal local/canonical outputs pass - the activation/recovery happy path.
    assert_canonical_output(&output, &output, "equal").expect("equal outputs must match");

    // A genuinely different output is rejected, and the error carries both
    // output hashes plus the call-site context so a divergence is diagnosable.
    let (_k2, _p2, other, _poly2, _log2) = run_test_dkg_complete();
    assert_ne!(output, other, "two independent DKG runs differ");
    let err = assert_canonical_output(&output, &other, "divergent-site")
        .expect_err("divergent outputs must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("divergent-site"),
        "error names the context: {msg}"
    );
    assert!(
        msg.contains(&dkg_output_hash(&output).to_string()),
        "error carries the local output hash: {msg}"
    );
}

#[tokio::test]
async fn dealer_log_roundtrips_through_manager() {
    let (_keys, participants, _output, _polynomial, local_log) = run_test_dkg_complete();
    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 7, None, participants)
        .unwrap();
    manager
        .note_local_dealer_log(Epoch::new(0), local_log.clone())
        .unwrap();

    let served = manager.get_dealer_log(Epoch::new(0)).await.unwrap();
    assert_eq!(served, local_log);
    let _dealer = manager
        .verify_dealer_log(Epoch::new(0), served.to_vec())
        .await
        .unwrap();

    manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(served)));
    assert!(manager.get_dealer_log(Epoch::new(0)).await.is_none());
}

#[tokio::test]
async fn pending_p2p_dealer_log_can_be_served_and_drained() {
    let keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (_info, _output, _shares, _logs, signed_logs) =
        run_round(&keys, participants.clone(), None, None, 7);
    let first = signed_logs.values().next().unwrap().clone();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 7, None, participants)
        .unwrap();
    manager
        .note_pending_dealer_log(Epoch::new(0), first.clone())
        .unwrap();

    assert_eq!(
        manager.get_dealer_log(Epoch::new(0)).await,
        Some(first.clone())
    );
    manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(first)));
    assert!(manager.get_dealer_log(Epoch::new(0)).await.is_none());
}

#[tokio::test]
async fn reshare_ceremony_uses_previous_players_as_dealers() {
    let old_keys: Vec<bls12381::PrivateKey> =
        (1..=4).map(bls12381::PrivateKey::from_seed).collect();
    let old_participants: Set<bls12381::PublicKey> = old_keys
        .iter()
        .map(|key| key.public_key())
        .try_collect()
        .unwrap();
    let (_info, previous_output, _shares, _logs, _signed_logs) =
        run_round(&old_keys, old_participants.clone(), None, None, 0);

    let new_key = bls12381::PrivateKey::from_seed(100);
    let new_pk = new_key.public_key();
    let mut target_keys = old_keys.clone();
    target_keys.push(new_key);
    let target_participants: Set<bls12381::PublicKey> = target_keys
        .iter()
        .map(|key| key.public_key())
        .try_collect()
        .unwrap();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 1, Some(previous_output), target_participants)
        .unwrap();

    let dealers = manager.with_state(|state| {
        state
            .ceremony
            .as_ref()
            .expect("ceremony initialized")
            .canonical
            .dealers()
            .clone()
    });
    assert_eq!(dealers, old_participants);
    assert!(dealers.position(&new_pk).is_none());
}

#[tokio::test]
async fn reshare_ceremony_keeps_removed_old_player_as_dealer() {
    let old_keys: Vec<bls12381::PrivateKey> =
        (1..=4).map(bls12381::PrivateKey::from_seed).collect();
    let old_participants: Set<bls12381::PublicKey> = old_keys
        .iter()
        .map(|key| key.public_key())
        .try_collect()
        .unwrap();
    let (_info, previous_output, _shares, _logs, _signed_logs) =
        run_round(&old_keys, old_participants.clone(), None, None, 0);

    let removed_pk = old_keys[0].public_key();
    let target_participants: Set<bls12381::PublicKey> = old_keys
        .iter()
        .filter(|key| key.public_key() != removed_pk)
        .map(|key| key.public_key())
        .try_collect()
        .unwrap();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 1, Some(previous_output), target_participants)
        .unwrap();

    let dealers = manager.with_state(|state| {
        state
            .ceremony
            .as_ref()
            .expect("ceremony initialized")
            .canonical
            .dealers()
            .clone()
    });
    assert_eq!(dealers, old_participants);
    assert!(dealers.position(&removed_pk).is_some());
}

#[tokio::test]
async fn pending_p2p_dealer_log_rejects_wrong_ceremony() {
    let keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (_info, _output, _shares, _logs, signed_logs) =
        run_round(&keys, participants.clone(), None, None, 7);
    let first = signed_logs.values().next().unwrap().clone();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 8, None, participants)
        .unwrap();

    assert!(manager
        .note_pending_dealer_log(Epoch::new(0), first)
        .is_err());
    assert!(manager.get_dealer_log(Epoch::new(0)).await.is_none());
}

#[tokio::test]
async fn pending_p2p_dealer_log_rejects_non_committee_dealer() {
    let keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (_info, _output, _shares, _logs, signed_logs) =
        run_round(&keys, participants.clone(), None, None, 7);
    let (dealer, bytes) = signed_logs.iter().next().unwrap();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 7, None, participants)
        .unwrap();
    manager.with_state(|state| {
        let ceremony = state.ceremony.as_mut().unwrap();
        ceremony.canonical.remove_dealer_for_test(dealer);
    });

    assert!(manager
        .note_pending_dealer_log(Epoch::new(0), bytes.clone())
        .is_err());
    assert!(manager.get_dealer_log(Epoch::new(0)).await.is_none());
}

#[tokio::test]
async fn pending_p2p_dealer_log_rejects_conflicting_duplicate() {
    let keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (_info, _output, _shares, _logs, signed_logs_a) =
        run_round(&keys, participants.clone(), None, None, 7);
    let (_info, _output, _shares, _logs, signed_logs_b) =
        run_round(&keys, participants.clone(), None, None, 7);
    let dealer = signed_logs_a.keys().next().unwrap();
    let first = signed_logs_a.get(dealer).unwrap().clone();
    let conflicting = signed_logs_b.get(dealer).unwrap().clone();
    assert_ne!(first, conflicting);

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 7, None, participants)
        .unwrap();
    manager
        .note_pending_dealer_log(Epoch::new(0), first.clone())
        .unwrap();
    manager
        .note_pending_dealer_log(Epoch::new(0), conflicting)
        .unwrap();

    assert_eq!(manager.get_dealer_log(Epoch::new(0)).await, Some(first));
}

#[test]
fn chain_finalized_replay_rejects_non_committee_dealer() {
    let keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (_info, _output, _shares, _logs, signed_logs) =
        run_round(&keys, participants.clone(), None, None, 7);
    let (dealer, bytes) = signed_logs.iter().next().unwrap();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 7, None, participants)
        .unwrap();
    manager.with_state(|state| {
        let ceremony = state.ceremony.as_mut().unwrap();
        ceremony.canonical.remove_dealer_for_test(dealer);
    });

    manager
        .note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(bytes.clone())));
    let recorded =
        manager.with_state(|state| state.ceremony.as_ref().unwrap().canonical.finalized_len());
    assert_eq!(recorded, 0);
}

/// The canonical state machine is a deterministic, replayable fold over the
/// chain-finalized dealer logs: feeding the *same* finalized-log order into two
/// fresh managers yields the same canonical output (crash-replay safety),
/// reconstruction is frozen once it first succeeds, and a duplicate finalized
/// log is idempotent. (Cross-order is intentionally NOT asserted: DKG completes
/// on threshold participation, so a different freeze-time subset is a different
/// group key - determinism comes from canonical chain order.)
#[test]
fn canonical_reconstruction_is_replay_deterministic_and_frozen() {
    let mut keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    keys.sort_by_key(|a| a.public_key().encode());
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (_info, _output, _shares, _logs, signed_logs) =
        run_round(&keys, participants.clone(), None, None, 11);
    // Deterministic order (BTreeMap iteration = sorted by dealer pubkey).
    let order: Vec<Bytes> = signed_logs.values().cloned().collect();
    assert!(order.len() >= 3, "need >= threshold logs to reconstruct");

    let feed = |seq: &[Bytes]| -> Option<_> {
        let manager = Mailbox::new();
        manager
            .note_ceremony_started(Epoch::new(0), 11, None, participants.clone())
            .unwrap();
        for bytes in seq {
            manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(
                bytes.clone(),
            )));
        }
        manager.canonical_output(Epoch::new(0))
    };

    // Same-order replay -> identical canonical output (deterministic rebuild).
    let out_a = feed(&order).expect("reconstructed from full set");
    let out_b = feed(&order).expect("reconstructed on replay");
    assert_eq!(out_a, out_b);

    // Freeze-once: output is fixed at first successful reconstruction and a
    // later finalized log never changes it.
    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 11, None, participants.clone())
        .unwrap();
    for bytes in order.iter().take(3) {
        manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(
            bytes.clone(),
        )));
    }
    let frozen = manager
        .canonical_output(Epoch::new(0))
        .expect("threshold reached");
    manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(
        order[3].clone(),
    )));
    assert_eq!(
        manager.canonical_output(Epoch::new(0)),
        Some(frozen),
        "reconstruction must be frozen once produced"
    );

    // Duplicate finalized log is idempotent: the same dealer is not recorded
    // twice.
    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(0), 11, None, participants)
        .unwrap();
    manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(
        order[0].clone(),
    )));
    manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(
        order[0].clone(),
    )));
    let recorded =
        manager.with_state(|state| state.ceremony.as_ref().unwrap().canonical.finalized_len());
    assert_eq!(
        recorded, 1,
        "duplicate finalized dealer log must not double-count"
    );
}

#[test]
fn dealer_log_size_within_extra_data_for_n128() {
    let mut keys: Vec<bls12381::PrivateKey> = (0..128)
        .map(|i| bls12381::PrivateKey::from_seed(i + 1))
        .collect();
    keys.sort_by_key(|key| key.public_key().encode());
    let participants: Set<bls12381::PublicKey> = keys
        .iter()
        .map(|key| key.public_key())
        .try_collect()
        .unwrap();
    let info = Info::<MinSig, bls12381::PublicKey>::new::<N3f1>(
        &config::outbe_app_namespace(),
        7,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants,
    )
    .unwrap();

    let dealer_key = keys[0].clone();
    let dealer_pk = dealer_key.public_key();
    let (mut dealer, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<N3f1>(
        rand_core::OsRng,
        info.clone(),
        dealer_key,
        None,
    )
    .unwrap();
    for (player_pk, priv_msg) in priv_msgs {
        let mut player = Player::new(
            info.clone(),
            keys.iter()
                .find(|key| key.public_key() == player_pk)
                .unwrap()
                .clone(),
        )
        .unwrap();
        let ack = player
            .dealer_message::<N3f1>(dealer_pk.clone(), pub_msg.clone(), priv_msg)
            .unwrap();
        dealer.receive_player_ack(player_pk, ack).unwrap();
    }
    let dealer_log = Bytes::from(dealer.finalize::<N3f1>().encode());

    let encoded = outbe_primitives::reshare_artifact::encode_outbe_block_artifacts(
        &outbe_primitives::reshare_artifact::OutbeBlockArtifacts {
            execution_summary: Some(
                outbe_primitives::reshare_artifact::ExecutionSummaryArtifact {
                    validator_fee_sum: U256::MAX,
                },
            ),
            consensus_header_artifact: Some(ConsensusHeaderArtifact::DealerLog(dealer_log)),
            timestamp_millis_part: 0,
            late_finalize_credits: None,
            compressed_entities_root: None,
        },
    )
    .unwrap();

    assert!(
        encoded.len() <= outbe_primitives::consensus::OUTBE_MAX_EXTRA_DATA_SIZE,
        "encoded artifact size {} must fit OUTBE_MAX_EXTRA_DATA_SIZE {}",
        encoded.len(),
        outbe_primitives::consensus::OUTBE_MAX_EXTRA_DATA_SIZE
    );
}

#[tokio::test]
async fn verify_preannounce_outcome_matches_only_local_dkg_output() {
    // The producer-side gate for Path A: a committee pre-announce is accepted only
    // if its carried outcome byte-matches THIS node's own reconstructed DKG output
    // for the incoming epoch - and is fail-closed when no pending boundary exists.
    let (keys, _participants, output, _polynomial, _local_log) = run_test_dkg_complete();
    let validator_set = ValidatorSet {
        public_keys: keys.iter().map(|k| k.public_key()).collect(),
        addresses: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; 3],
    };
    let artifact = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(0),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 0,
        freeze_height: 0,
        planned_activation_height: 0,
        vrf_material_version: 0,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();

    let manager = Mailbox::new();
    // Fail-closed BEFORE any pending boundary exists.
    assert!(
        manager
            .verify_preannounce_outcome(Epoch::new(0), artifact.outcome.as_ref())
            .await
            .is_err(),
        "pre-announce must be rejected when the node has no pending boundary"
    );

    manager.note_recovered_pending_boundary(artifact.clone());

    // Matching outcome + epoch -> accepted.
    manager
        .verify_preannounce_outcome(Epoch::new(0), artifact.outcome.as_ref())
        .await
        .unwrap();
    // Forged outcome -> rejected.
    assert!(
        manager
            .verify_preannounce_outcome(Epoch::new(0), b"forged-dkg-outcome")
            .await
            .is_err(),
        "a pre-announce whose outcome differs from the local DKG output must be rejected"
    );
    // Wrong epoch -> rejected.
    assert!(
        manager
            .verify_preannounce_outcome(Epoch::new(1), artifact.outcome.as_ref())
            .await
            .is_err(),
        "a pre-announce epoch that does not match the pending boundary must be rejected"
    );
}

#[tokio::test]
async fn pending_next_epoch_artifact_is_distinct_from_current_activation_boundary() {
    let (keys, _participants, output, _polynomial, _local_log) = run_test_dkg_complete();
    let validator_set = ValidatorSet {
        public_keys: keys.iter().map(|key| key.public_key()).collect(),
        addresses: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; 3],
    };
    let next_epoch_artifact = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 10,
        planned_activation_height: 20,
        vrf_material_version: 1,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();

    let manager = Mailbox::new();
    manager.note_ceremony_completed(next_epoch_artifact.clone());

    assert!(
        manager
            .pending_boundary_artifact(Epoch::new(0))
            .await
            .is_none(),
        "an epoch-1 artifact must not be exposed as the epoch-0 activation boundary"
    );
    assert_eq!(
        manager.pending_next_epoch_artifact(Epoch::new(0)).await,
        Some(next_epoch_artifact.clone()),
        "an epoch-1 artifact must be available for pre-announcement during epoch 0"
    );
    assert!(
        manager
            .pending_next_epoch_artifact(Epoch::new(1))
            .await
            .is_none(),
        "the same artifact must not be reused as an epoch-2 pre-announcement"
    );
    assert!(
        manager
            .pending_next_epoch_artifact(Epoch::new(u64::MAX))
            .await
            .is_none(),
        "epoch overflow must fail closed"
    );
}

#[tokio::test]
async fn verify_boundary_succeeds_after_finalize() {
    let (keys, _participants, output, _polynomial, _local_log) = run_test_dkg_complete();
    let validator_set = ValidatorSet {
        public_keys: keys.iter().map(|k| k.public_key()).collect(),
        addresses: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; 3],
    };
    let artifact = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(0),
        validator_set: &validator_set,
        output: &output,
        is_full_dkg: false,
        dkg_cycle: 0,
        freeze_height: 0,
        planned_activation_height: 0,
        vrf_material_version: 0,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();

    let manager = Mailbox::new();
    manager.note_bootstrap_outcome(artifact.clone());
    let parent_hash = B256::repeat_byte(0x42);
    let artifact_hash = Mailbox::boundary_artifact_hash(&artifact).unwrap();
    manager.record_boundary_status(parent_hash, artifact_hash, BoundaryStatus::NoBoundarySeen);
    assert!(manager
        .cached_boundary_status(parent_hash, artifact_hash)
        .is_some());
    manager.note_recovered_pending_boundary(artifact.clone());
    assert!(
        manager
            .cached_boundary_status(parent_hash, artifact_hash)
            .is_none(),
        "new pending DKG boundary must clear prior boundary-status cache"
    );

    // The pending artifact is available before finalize.
    assert!(manager
        .pending_boundary_artifact(Epoch::new(0))
        .await
        .is_some());

    // Pending-artifact verification works before finalize.
    manager
        .verify_pending_boundary_artifact(Epoch::new(0), &artifact)
        .await
        .unwrap();

    // Simulate finalize of a block carrying the same artifact.
    manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::BoundaryOutcome(
        artifact.clone(),
    )));

    // Finalize records a committed marker but does not itself decide
    // proposer/verifier validity. The application derives that from parent
    // ancestry and then the scheduler drains this marker.
    assert!(manager
        .pending_boundary_artifact(Epoch::new(0))
        .await
        .is_some());

    // Scheduler activation is driven by the chain-committed marker, not by
    // process-local served state. Draining the committed marker clears the
    // pending boundary after activation.
    assert_eq!(
        manager.take_committed_boundary_artifact().await,
        Some(artifact)
    );
    assert!(manager
        .pending_boundary_artifact(Epoch::new(0))
        .await
        .is_none());
}

#[test]
fn full_output_outcome_detects_reshare_log_subset_divergence() {
    let mut keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    keys.sort_by_key(|a| a.public_key().encode());
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();

    let (_initial_info, initial_output, initial_shares, _initial_logs, _initial_signed) =
        run_round(&keys, participants.clone(), None, None, 0);
    let (reshare_info, _reshare_output, _reshare_shares, reshare_logs, _reshare_signed) = run_round(
        &keys,
        participants.clone(),
        Some(initial_output),
        Some(&initial_shares),
        1,
    );

    let mut all_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(reshare_info.clone());
    for (dealer, log) in reshare_logs.clone() {
        all_logs.record(dealer, log);
    }
    let all_output = observe::<
        MinSig,
        bls12381::PublicKey,
        N3f1,
        commonware_cryptography::bls12381::Batch,
    >(&mut rand_core::OsRng, all_logs, &Sequential)
    .unwrap();
    let mut subset_logs = reshare_logs.clone();
    let removed = subset_logs.keys().next().cloned().unwrap();
    subset_logs.remove(&removed);
    let mut subset_dkg_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(reshare_info);
    for (dealer, log) in subset_logs {
        subset_dkg_logs.record(dealer, log);
    }
    let subset_output = observe::<
        MinSig,
        bls12381::PublicKey,
        N3f1,
        commonware_cryptography::bls12381::Batch,
    >(&mut rand_core::OsRng, subset_dkg_logs, &Sequential)
    .unwrap();

    assert_eq!(
        all_output.public().public(),
        subset_output.public().public(),
        "reshare preserves the threshold group key even when full output diverges"
    );
    assert_ne!(all_output, subset_output);
    assert_eq!(
        legacy_group_key_only_outcome(Epoch::new(1), &all_output, false),
        legacy_group_key_only_outcome(Epoch::new(1), &subset_output, false),
        "old boundary outcome could not detect the divergence"
    );

    let validator_set = ValidatorSet {
        public_keys: keys.iter().map(|k| k.public_key()).collect(),
        addresses: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
            address!("0x4444444444444444444444444444444444444444"),
        ],
        p2p_addresses: vec![crate::validators::ValidatorP2pAddress::Missing; 4],
    };
    let all_artifact = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &all_output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    let subset_artifact = build_boundary_artifact(BoundaryArtifactInput {
        epoch: Epoch::new(1),
        validator_set: &validator_set,
        output: &subset_output,
        is_full_dkg: false,
        dkg_cycle: 1,
        freeze_height: 90,
        planned_activation_height: 120,
        vrf_material_version: 1,
        is_validator_set_change: true,
        tee_expired_target_exclusions: Vec::new(),
    })
    .unwrap();
    assert_eq!(
        all_artifact.vrf_group_public_key,
        subset_artifact.vrf_group_public_key
    );
    assert_ne!(all_artifact.outcome, subset_artifact.outcome);
    assert_ne!(all_artifact, subset_artifact);

    // Offense-A parity: the executor derives the committee's polynomial hash
    // from the boundary `outcome` and must get exactly the value the
    // proposer committed (`public_polynomial_hash(output.public())`).
    // Otherwise the snapshot the executor writes would diverge and
    // invalid-seed-partial evidence could never match.
    assert_eq!(
        boundary_outcome_polynomial_hash(all_artifact.outcome.as_ref()),
        public_polynomial_hash(all_output.public()),
        "executor outcome-derived poly hash must equal the proposer's"
    );
    // Distinct polynomials -> distinct hashes (no collision).
    assert_ne!(
        boundary_outcome_polynomial_hash(all_artifact.outcome.as_ref()),
        boundary_outcome_polynomial_hash(subset_artifact.outcome.as_ref()),
    );
}

#[test]
fn finalized_dealer_logs_reconstruct_canonical_output() {
    let mut keys: Vec<bls12381::PrivateKey> = (0..4)
        .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
        .collect();
    keys.sort_by_key(|a| a.public_key().encode());
    let participants: Set<bls12381::PublicKey> =
        keys.iter().map(|k| k.public_key()).try_collect().unwrap();
    let (info, expected_output, _shares, logs, signed_logs) =
        run_round(&keys, participants.clone(), None, None, 11);
    let mut observed_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info.clone());
    for (dealer, log) in logs {
        observed_logs.record(dealer, log);
    }
    let observed = observe::<
        MinSig,
        bls12381::PublicKey,
        N3f1,
        commonware_cryptography::bls12381::Batch,
    >(&mut rand_core::OsRng, observed_logs, &Sequential)
    .unwrap();
    assert_eq!(expected_output, observed);

    let finalized_order: Vec<Bytes> = signed_logs.values().rev().cloned().collect();
    let mut canonical_logs = BTreeMap::new();
    for bytes in finalized_order.iter().take(3) {
        let mut reader = bytes.as_ref();
        let signed_log = SignedDealerLog::<MinSig, bls12381::PrivateKey>::read_cfg(
            &mut reader,
            &NonZeroU32::new(keys.len() as u32).unwrap(),
        )
        .unwrap();
        let (dealer, log) = signed_log.check(&info).unwrap();
        canonical_logs.insert(dealer, log);
    }
    let mut canonical_dkg_logs = Logs::<MinSig, bls12381::PublicKey, N3f1>::new(info);
    for (dealer, log) in canonical_logs {
        canonical_dkg_logs.record(dealer, log);
    }
    let expected_canonical = observe::<
        MinSig,
        bls12381::PublicKey,
        N3f1,
        commonware_cryptography::bls12381::Batch,
    >(&mut rand_core::OsRng, canonical_dkg_logs, &Sequential)
    .unwrap();

    let manager = Mailbox::new();
    manager
        .note_ceremony_started(Epoch::new(3), 11, None, participants)
        .unwrap();
    for bytes in &finalized_order {
        manager.note_finalized_header_artifact(Some(&ConsensusHeaderArtifact::DealerLog(
            bytes.clone(),
        )));
    }

    assert_eq!(
        manager.canonical_output(Epoch::new(3)),
        Some(expected_canonical)
    );
}
