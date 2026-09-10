//! Deterministic DKG / reshare simulation suite.
//!
//! Best-practice consensus-test pattern: every ceremony outcome is pinned to a
//! reproducible input so a regression cannot silently change agreement, the
//! group key, or the failure mode.
//!
//! Two layers:
//!
//!  * **Synchronous, fixed-entropy** (`run_seeded_round`): drives the
//!    commonware Feldman-Desmedt primitive step-for-step with a *caller-supplied*
//!    `ChaCha20Rng` instead of `OsRng`, so the group key is a pure function of
//!    `(keys, seed)`. Production correctly uses `OsRng` for dealer secrets
//!    (unpredictability is required), so seed-determinism is a test affordance
//!    that lets us assert byte-identical reproducibility and adversarial
//!    rejection on *typed* errors - stronger than the existing string / outer
//!    timeout-based assertions.
//!
//!  * **Actor over the real wire** (`deterministic::Runner` + `simulated::Network`):
//!    runs the production [`run_initial_dkg`] actor over the simulated p2p network
//!    on the deterministic runtime, so task scheduling and timers are
//!    reproducible. Asserts (a) a fully-connected committee completes and every
//!    validator agrees on one group key, and (b) a missing dealer makes the
//!    survivors hit the ceremony deadline and return a *clean* timeout error -
//!    never a panic, never a divergent partial key.
//!
//! Adversarial cases mirrored as best practice (not 1:1): below-threshold dealers
//! cannot mint a key, a foreign previous output (key-substitution) is rejected,
//! and a missing dealer times out cleanly.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::time::Duration;

use commonware_codec::Encode as _;
use commonware_cryptography::bls12381::{
    self,
    dkg::feldman_desmedt::{Dealer, Error as DkgError, Info, Logs, Output, Player},
    primitives::{sharing::Mode, variant::MinSig},
};
use commonware_cryptography::Signer as _;
use commonware_p2p::simulated::{Config as SimConfig, Link, Network};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Quota};
use commonware_utils::ordered::{Quorum as _, Set};
use commonware_utils::TryCollect as _;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use super::actor::run_initial_dkg;

const DKG_TEST_CHANNEL: u64 = 0;
const DKG_TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

fn namespace() -> Vec<u8> {
    crate::config::outbe_app_namespace()
}

/// Deterministic, sorted validator keys (sorted by public key, as bootstrap does).
fn keys_from_seeds(seeds: &[u64]) -> Vec<bls12381::PrivateKey> {
    let mut keys: Vec<bls12381::PrivateKey> = seeds
        .iter()
        .map(|s| bls12381::PrivateKey::from_seed(*s))
        .collect();
    keys.sort_by_key(|k| k.public_key().encode());
    keys
}

fn participant_set(keys: &[bls12381::PrivateKey]) -> Set<bls12381::PublicKey> {
    keys.iter().map(|k| k.public_key()).try_collect().unwrap()
}

/// Run a full **initial** DKG round synchronously, threading one deterministic
/// entropy stream through every dealer and player. Returns the canonical group
/// output plus each player's individually-recovered output (for agreement checks).
fn run_seeded_round(
    keys: &[bls12381::PrivateKey],
    rng: &mut ChaCha20Rng,
) -> (
    Output<MinSig, bls12381::PublicKey>,
    Vec<Output<MinSig, bls12381::PublicKey>>,
) {
    let participants = participant_set(keys);
    let info = Info::<MinSig, bls12381::PublicKey>::new::<commonware_utils::N3f1>(
        &namespace(),
        0,
        None,
        Mode::NonZeroCounter,
        participants.clone(),
        participants.clone(),
    )
    .unwrap();

    let mut dealers = Vec::new();
    let mut pub_msgs = Vec::new();
    let mut all_priv = Vec::new();
    for key in keys {
        let (dealer, pub_msg, priv_msgs) = Dealer::<MinSig, bls12381::PrivateKey>::start::<
            commonware_utils::N3f1,
        >(&mut *rng, info.clone(), key.clone(), None)
        .unwrap();
        dealers.push(dealer);
        pub_msgs.push(pub_msg);
        all_priv.push(priv_msgs);
    }

    let mut players: Vec<Player<MinSig, bls12381::PrivateKey>> = keys
        .iter()
        .map(|k| Player::new(info.clone(), k.clone()).unwrap())
        .collect();

    for (di, (pub_msg, priv_msgs)) in pub_msgs.iter().zip(all_priv.iter()).enumerate() {
        let dealer_pk = keys[di].public_key();
        for (player_pk, priv_msg) in priv_msgs {
            let pi = keys
                .iter()
                .position(|k| k.public_key() == *player_pk)
                .unwrap();
            if let Some(ack) = players[pi].dealer_message::<commonware_utils::N3f1>(
                dealer_pk.clone(),
                pub_msg.clone(),
                priv_msg.clone(),
            ) {
                dealers[di]
                    .receive_player_ack(player_pk.clone(), ack)
                    .unwrap();
            }
        }
    }

    let mut logs = BTreeMap::new();
    for dealer in dealers {
        let signed = dealer.finalize::<commonware_utils::N3f1>();
        if let Some((pk, log)) = signed.check(&info) {
            logs.insert(pk, log);
        }
    }

    let mut outputs = Vec::new();
    for player in players {
        let mut dkg_logs =
            Logs::<MinSig, bls12381::PublicKey, commonware_utils::N3f1>::new(info.clone());
        for (pk, log) in &logs {
            dkg_logs.record(pk.clone(), log.clone());
        }
        let (output, _share) = player
            .finalize::<commonware_utils::N3f1, commonware_cryptography::bls12381::Batch>(
                &mut *rng,
                dkg_logs,
                &Sequential,
            )
            .unwrap();
        outputs.push(output);
    }

    (outputs[0].clone(), outputs)
}

// ---------------------------------------------------------------------------
// Determinism + agreement (synchronous, fixed entropy)
// ---------------------------------------------------------------------------

#[test]
fn dkg_group_key_is_deterministic_under_fixed_entropy() {
    let keys = keys_from_seeds(&[1, 2, 3, 4]);

    let mut rng_a = ChaCha20Rng::seed_from_u64(0x00C0FFEE);
    let (key_a, outs_a) = run_seeded_round(&keys, &mut rng_a);

    let mut rng_b = ChaCha20Rng::seed_from_u64(0x00C0FFEE);
    let (key_b, _) = run_seeded_round(&keys, &mut rng_b);

    assert_eq!(
        key_a.public().encode(),
        key_b.public().encode(),
        "same keys + same entropy must yield a byte-identical group key"
    );

    // Non-vacuous: a different entropy stream must yield a different group key.
    let mut rng_c = ChaCha20Rng::seed_from_u64(0x00BADC0DE);
    let (key_c, _) = run_seeded_round(&keys, &mut rng_c);
    assert_ne!(
        key_a.public().encode(),
        key_c.public().encode(),
        "different entropy must yield a different group key (test is not vacuous)"
    );

    // Agreement: every player recovered the same canonical group key.
    for o in &outs_a {
        assert_eq!(o.public().encode(), key_a.public().encode());
    }
}

// ---------------------------------------------------------------------------
// Adversarial negatives (typed errors, not strings)
// ---------------------------------------------------------------------------

#[test]
fn below_threshold_dealers_cannot_mint_key() {
    // m1: a reshare whose dealer set is below the previous quorum must be
    // rejected at `Info::new` - no ceremony, no minted key.
    let a = keys_from_seeds(&[1, 2, 3, 4]);
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (output_a, _) = run_seeded_round(&a, &mut rng);

    let a_set = participant_set(&a);
    let quorum = a_set.quorum::<commonware_utils::N3f1>() as usize;
    assert!(
        quorum >= 2,
        "fixture must have a meaningful quorum gap, got {quorum}"
    );

    let too_few: Set<bls12381::PublicKey> = a[..quorum - 1]
        .iter()
        .map(|k| k.public_key())
        .try_collect()
        .unwrap();

    let err = Info::<MinSig, bls12381::PublicKey>::new::<commonware_utils::N3f1>(
        &namespace(),
        1,
        Some(output_a),
        Mode::NonZeroCounter,
        too_few,
        a_set,
    )
    .expect_err("a below-quorum dealer set must be rejected");

    assert!(
        matches!(err, DkgError::NumDealers(_)),
        "expected NumDealers rejection, got {err:?}"
    );
}

#[test]
fn foreign_previous_output_rejected() {
    // m8: feeding committee B's output as committee A's `previous` (key
    // substitution) must be rejected - A's dealers are not in B's player set.
    let a = keys_from_seeds(&[1, 2, 3, 4]);
    let b = keys_from_seeds(&[101, 102, 103, 104]);

    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let (output_b, _) = run_seeded_round(&b, &mut rng);
    let group_key_b = output_b.public().encode();
    assert!(
        !group_key_b.is_empty(),
        "B's group key must be real (non-vacuous)"
    );

    let a_set = participant_set(&a);
    let err = Info::<MinSig, bls12381::PublicKey>::new::<commonware_utils::N3f1>(
        &namespace(),
        1,
        Some(output_b),
        Mode::NonZeroCounter,
        a_set.clone(),
        a_set,
    )
    .expect_err("a foreign previous output must be rejected");

    assert!(
        matches!(err, DkgError::UnknownDealer(_)),
        "expected UnknownDealer (key-substitution) rejection, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Actor over the real wire (deterministic runtime + simulated network)
// ---------------------------------------------------------------------------

#[test]
fn sim_full_ceremony_completes_and_all_agree() {
    use commonware_p2p::Manager as _;
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};

    deterministic::Runner::timed(Duration::from_secs(300)).start(|context| async move {
        let n = 4usize;
        let keys = keys_from_seeds(&(1..=n as u64).collect::<Vec<_>>());
        let participants = participant_set(&keys);

        let (network, oracle) = Network::new(
            context.child("network"),
            SimConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: commonware_utils::NZUsize!(4),
            },
        );
        network.start();

        // Register every node's DKG channel, then link + track, then spawn.
        let mut chans = Vec::new();
        for key in &keys {
            let control = oracle.control(key.public_key());
            let (tx, rx) = control
                .register(DKG_TEST_CHANNEL, DKG_TEST_QUOTA)
                .await
                .expect("register dkg channel");
            chans.push((key.clone(), tx, rx));
        }

        let link = Link {
            latency: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    oracle
                        .add_link(keys[i].public_key(), keys[j].public_key(), link.clone())
                        .await
                        .expect("link peers");
                }
            }
        }
        let peers =
            commonware_utils::ordered::Set::from_iter_dedup(keys.iter().map(|k| k.public_key()));
        let _ = oracle.manager().track(0, peers);

        let mut handles = Vec::new();
        for (key, tx, rx) in chans {
            let participants_c = participants.clone();
            let handle = context.child("dkg").spawn(move |ctx| async move {
                run_initial_dkg(&ctx, key, participants_c, None, None, 0, None, None, tx, rx).await
            });
            handles.push(handle);
        }

        let mut group_keys = Vec::new();
        for handle in handles {
            let complete = handle
                .await
                .expect("dkg task join")
                .expect("dkg ceremony must complete");
            group_keys.push(complete.output.public().encode());
        }

        for gk in &group_keys[1..] {
            assert_eq!(
                *gk, group_keys[0],
                "all validators must agree on one group key"
            );
        }
    });
}

#[test]
fn sim_single_missing_dealer_times_out_clean() {
    // t5: with one of n dealers absent, the bootstrap ceremony can never collect
    // all n genesis logs. Every survivor must hit the ceremony deadline and
    // return a *clean* timeout error - never panic, never finalize a subset key.
    use commonware_p2p::Manager as _;
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};

    deterministic::Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let n = 4usize;
        let keys = keys_from_seeds(&(1..=n as u64).collect::<Vec<_>>());
        let participants = participant_set(&keys);

        let (network, oracle) = Network::new(
            context.child("network"),
            SimConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: commonware_utils::NZUsize!(4),
            },
        );
        network.start();

        // Register + spawn only the first n-1 nodes; the last dealer never joins.
        let mut chans = Vec::new();
        for key in keys.iter().take(n - 1) {
            let control = oracle.control(key.public_key());
            let (tx, rx) = control
                .register(DKG_TEST_CHANNEL, DKG_TEST_QUOTA)
                .await
                .expect("register dkg channel");
            chans.push((key.clone(), tx, rx));
        }

        let link = Link {
            latency: Duration::from_millis(0),
            jitter: Duration::from_millis(0),
            success_rate: 1.0,
        };
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    oracle
                        .add_link(keys[i].public_key(), keys[j].public_key(), link.clone())
                        .await
                        .expect("link peers");
                }
            }
        }
        let peers =
            commonware_utils::ordered::Set::from_iter_dedup(keys.iter().map(|k| k.public_key()));
        let _ = oracle.manager().track(0, peers);

        let mut handles = Vec::new();
        for (key, tx, rx) in chans {
            let participants_c = participants.clone();
            let handle = context.child("dkg").spawn(move |ctx| async move {
                run_initial_dkg(&ctx, key, participants_c, None, None, 0, None, None, tx, rx).await
            });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.await.expect("dkg task join");
            let err = result.expect_err("survivor must not finalize with a dealer missing");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("timed out"),
                "expected a clean timeout, got: {msg}"
            );
        }
    });
}
