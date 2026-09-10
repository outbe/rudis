//! - `ParentProofResolver` bounded-fetch tests.
//!
//! Drives the resolver against a mock [`ParentProofTransport`] so the test
//! suite exercises the schedule-budget enforcement, the hash-exact contract
//! , the local-witness gate , and the competing-branch safety
//! property - all without spinning up a real P2P stack. The marshal
//! transport plugs into the same trait surface.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy_primitives::{address, Address, B256};
use commonware_consensus::{
    simplex::types::{Notarization, Proposal, Subject},
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    bls12381::{self, primitives::variant::MinSig},
    certificate::Scheme as _,
    Hasher as _, Sha256, Signer as _,
};
use commonware_parallel::Sequential;
use commonware_utils::{
    ordered::{Quorum as _, Set},
    N3f1, TryCollect as _,
};
use outbe_consensus::{
    bls::bootstrap_dkg,
    digest::Digest as OutbeDigest,
    finalization::{
        parent_cert_store::{
            CertifiedParentProofKey, CertifiedParentProofRecord, CertifiedParentProofStore,
            FinalizedParentCertStore, ProofKind,
        },
        resolver::{
            ParentProofResolver, ParentProofTransport, ProofFetchKey, ProofFetchOutcome,
            TransportError,
        },
    },
    hybrid::HybridScheme,
};
use outbe_primitives::protocol_schedule::OutbeProtocolSchedule;

// -- Test fixtures ---------------------------------------------------------

fn test_participants(n: u8) -> (Vec<bls12381::PrivateKey>, Set<bls12381::PublicKey>) {
    let keys: Vec<bls12381::PrivateKey> = (0..n)
        .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
        .collect();
    let participants = keys
        .iter()
        .map(|sk| bls12381::PublicKey::from(sk.clone()))
        .try_collect()
        .unwrap();
    (keys, participants)
}

fn ordered_addresses() -> Vec<Address> {
    vec![
        address!("0x1111111111111111111111111111111111111111"),
        address!("0x2222222222222222222222222222222222222222"),
        address!("0x3333333333333333333333333333333333333333"),
    ]
}

/// Build a verified `Notarization` for the given round and payload hash.
fn notarization_for(
    round: Round,
    parent_view: View,
    payload_bytes: &[u8],
) -> (
    Notarization<HybridScheme<MinSig>, OutbeDigest>,
    HybridScheme<MinSig>,
) {
    let (keys, participants) = test_participants(3);
    let dkg = bootstrap_dkg(3).unwrap();
    let schemes: Vec<HybridScheme<MinSig>> = keys
        .iter()
        .map(|key| {
            let pk = bls12381::PublicKey::from(key.clone());
            let idx = participants.index(&pk).unwrap();
            HybridScheme::signer(
                b"resolver-test",
                participants.clone(),
                key.clone(),
                dkg.polynomial.clone(),
                dkg.shares[idx.get() as usize].clone(),
            )
            .unwrap()
        })
        .collect();
    let verifier =
        HybridScheme::<MinSig>::verifier(b"resolver-test", participants, dkg.polynomial).unwrap();
    let payload = OutbeDigest::from(B256::from_slice(Sha256::hash(payload_bytes).as_ref()));
    let proposal = Proposal::new(round, parent_view, payload);
    let subject = Subject::Notarize {
        proposal: &proposal,
    };
    let attestations: Vec<_> = schemes
        .iter()
        .map(|scheme| scheme.sign::<OutbeDigest>(subject).unwrap())
        .collect();
    let certificate = verifier
        .assemble::<_, N3f1>(attestations, &Sequential)
        .unwrap();
    (
        Notarization {
            proposal,
            certificate,
        },
        verifier,
    )
}

fn verifier_scheme() -> HybridScheme<MinSig> {
    let (_, participants) = test_participants(3);
    let dkg = bootstrap_dkg(3).unwrap();
    HybridScheme::<MinSig>::verifier(b"resolver-test", participants, dkg.polynomial).unwrap()
}

fn fast_schedule(max_attempts: u32, timeout_ms: u64, max_bytes: usize) -> OutbeProtocolSchedule {
    OutbeProtocolSchedule {
        parent_proof_fetch_max_attempts: max_attempts,
        parent_proof_fetch_timeout_ms: timeout_ms,
        parent_proof_fetch_max_bytes: max_bytes,
        ..OutbeProtocolSchedule::default()
    }
}

fn build_resolver<T: ParentProofTransport>(
    transport: T,
    schedule: OutbeProtocolSchedule,
    store: FinalizedParentCertStore,
    verifier: HybridScheme<MinSig>,
) -> ParentProofResolver<T> {
    ParentProofResolver::new(transport, schedule, store, verifier, ordered_addresses())
}

// -- Mock transport --------------------------------------------------------

#[derive(Default, Clone)]
struct CallLog {
    attempts: usize,
    last_byte_cap: usize,
    last_timeout_ms: u128,
}

#[derive(Clone)]
enum MockBehaviour {
    /// Return this fixed Notarization on every call. Boxed because the
    /// Notarization inline is ~500 bytes - see clippy::large_enum_variant.
    Returns(Box<Notarization<HybridScheme<MinSig>, OutbeDigest>>),
    /// Never respond, so the resolver's per-attempt `Clock::sleep(attempt_timeout)`
    /// race always wins and the attempt times out (deterministic - no real sleep).
    NeverResponds,
}

#[derive(Clone)]
struct MockTransport {
    log: Arc<Mutex<CallLog>>,
    behaviour: Arc<MockBehaviour>,
}

impl MockTransport {
    fn new(behaviour: MockBehaviour) -> Self {
        Self {
            log: Arc::new(Mutex::new(CallLog::default())),
            behaviour: Arc::new(behaviour),
        }
    }

    fn log(&self) -> CallLog {
        self.log.lock().unwrap().clone()
    }
}

impl ParentProofTransport for MockTransport {
    type Target = u32;

    async fn request_notarized(
        &self,
        _round: Round,
        _target: Self::Target,
        byte_cap: usize,
        attempt_timeout: Duration,
    ) -> Result<Notarization<HybridScheme<MinSig>, OutbeDigest>, TransportError> {
        {
            let mut log = self.log.lock().unwrap();
            log.attempts += 1;
            log.last_byte_cap = byte_cap;
            log.last_timeout_ms = attempt_timeout.as_millis();
        }
        match &*self.behaviour {
            MockBehaviour::Returns(n) => Ok((**n).clone()),
            MockBehaviour::NeverResponds => {
                // Never resolve: the resolver's per-attempt `Clock::sleep(attempt_timeout)`
                // race wins every attempt, so the attempt times out without any real sleep.
                std::future::pending::<
                    Result<Notarization<HybridScheme<MinSig>, OutbeDigest>, TransportError>,
                >()
                .await
            }
        }
    }
}

// -- Tests -----------------------------------------------------------------

#[test]
fn remote_notarized_fetch_hash_mismatch_returns_no_exact_parent_proof() {
    use commonware_runtime::Runner as _;
    // Runs on the deterministic runtime: the resolver's `Clock::sleep` timeout race
    // and any mock delay advance on one virtual clock, so the test is reproducible.
    // `context` is the `Clock` threaded into `fetch_parent_proof`.
    commonware_runtime::deterministic::Runner::default().start(|context| async move {
        // Transport returns a Notarization for payload "X" but the resolver was
        // asked for the parent hash of payload "Y". NoProofForExactParent.
        let round = Round::new(Epoch::new(0), View::new(2));
        let (returned, verifier) = notarization_for(round, View::new(1), b"branch-x");
        let transport = MockTransport::new(MockBehaviour::Returns(Box::new(returned)));

        let store = FinalizedParentCertStore::new();
        // Local witness present so a hash match WOULD succeed - proves the
        // mismatch path short-circuits before the witness check.
        store
            .put_certified_notarization(witness_for(
                round,
                View::new(1),
                B256::from_slice(Sha256::hash(b"branch-y").as_ref()),
            ))
            .unwrap();

        let resolver = build_resolver(
            transport,
            fast_schedule(3, 500, 1_024 * 1_024),
            store.clone(),
            verifier,
        );

        let outcome = resolver
            .fetch_parent_proof(
                &context,
                ProofFetchKey {
                    round,
                    parent_hash: B256::from_slice(Sha256::hash(b"branch-y").as_ref()),
                },
                &[0u32, 1, 2],
            )
            .await;

        assert!(
            matches!(outcome, ProofFetchOutcome::NoProofForExactParent),
            "expected NoProofForExactParent, got {outcome:?}"
        );
    });
}

#[test]
fn remote_notarized_fetch_without_local_certification_witness_returns_no_proof() {
    use commonware_runtime::Runner as _;
    commonware_runtime::deterministic::Runner::default().start(|context| async move {
        // Mock returns a valid Notarization matching the requested parent_hash,
        // but the store has no witness: NoLocalCertificationWitness.
        let round = Round::new(Epoch::new(0), View::new(2));
        let (notar, verifier) = notarization_for(round, View::new(1), b"branch-a");
        let parent_hash = notar.proposal.payload.0;
        let transport = MockTransport::new(MockBehaviour::Returns(Box::new(notar)));

        let store = FinalizedParentCertStore::new(); // no witness
        let resolver = build_resolver(
            transport,
            fast_schedule(3, 500, 1_024 * 1_024),
            store.clone(),
            verifier,
        );

        let outcome = resolver
            .fetch_parent_proof(&context, ProofFetchKey { round, parent_hash }, &[0u32])
            .await;

        assert!(
            matches!(outcome, ProofFetchOutcome::NoLocalCertificationWitness),
            "expected NoLocalCertificationWitness, got {outcome:?}"
        );
        assert!(
            store
                .get_certified_notarization(proof_key(round, parent_hash))
                .is_none(),
            "no record may be created without a local witness"
        );
    });
}

#[test]
fn remote_notarized_returns_competing_branch_same_round_does_not_overwrite_other_hash_record() {
    use commonware_runtime::Runner as _;
    commonware_runtime::deterministic::Runner::default().start(|context| async move {
        // Pre-existing record at hash X for round R. Fetch requested for hash Y.
        // Mock returns notarization at round R but for hash X (competing branch).
        // Resolver must short-circuit on hash mismatch AND the record at X
        // must remain byte-identical (no overwrite of unrelated keys).
        let round = Round::new(Epoch::new(0), View::new(2));
        let parent_view = View::new(1);
        let (competing, verifier) = notarization_for(round, parent_view, b"competing-branch-x");
        let competing_hash = competing.proposal.payload.0;
        let requested_hash = B256::from_slice(Sha256::hash(b"requested-branch-y").as_ref());
        assert_ne!(competing_hash, requested_hash);

        let store = FinalizedParentCertStore::new();
        let existing = witness_for(round, parent_view, competing_hash);
        store.put_certified_notarization(existing.clone()).unwrap();

        let transport = MockTransport::new(MockBehaviour::Returns(Box::new(competing)));
        let resolver = build_resolver(
            transport,
            fast_schedule(3, 500, 1_024 * 1_024),
            store.clone(),
            verifier,
        );

        let outcome = resolver
            .fetch_parent_proof(
                &context,
                ProofFetchKey {
                    round,
                    parent_hash: requested_hash,
                },
                &[0u32, 1],
            )
            .await;

        assert!(
            matches!(outcome, ProofFetchOutcome::NoProofForExactParent),
            "expected NoProofForExactParent, got {outcome:?}"
        );
        let after = store
            .get_certified_notarization(proof_key(round, competing_hash))
            .unwrap();
        assert_eq!(
            after, existing,
            "competing-branch record at the OTHER hash must not be touched"
        );
        assert!(
            store
                .get_certified_notarization(proof_key(round, requested_hash))
                .is_none(),
            "no record may be created at the requested hash on mismatch"
        );
    });
}

#[test]
fn parent_proof_fetch_respects_timeout_attempts_and_max_bytes() {
    use commonware_runtime::Runner as _;
    commonware_runtime::deterministic::Runner::default().start(|context| async move {
        // All three budget dimensions in one test: max_attempts capped,
        // per-attempt timeout enforced, max_bytes propagated to the transport.
        let round = Round::new(Epoch::new(0), View::new(2));
        let transport = MockTransport::new(MockBehaviour::NeverResponds);

        const ATTEMPTS: u32 = 2;
        const TIMEOUT_MS: u64 = 50;
        const MAX_BYTES: usize = 2 * 1024 * 1024;
        let schedule = fast_schedule(ATTEMPTS, TIMEOUT_MS, MAX_BYTES);

        let store = FinalizedParentCertStore::new();
        let resolver = build_resolver(transport.clone(), schedule, store, verifier_scheme());

        let outcome = resolver
            .fetch_parent_proof(
                &context,
                ProofFetchKey {
                    round,
                    parent_hash: B256::from_slice(Sha256::hash(b"any").as_ref()),
                },
                // More targets than ATTEMPTS - resolver must cap to ATTEMPTS.
                &[0u32, 1, 2, 3, 4],
            )
            .await;

        assert!(
            matches!(outcome, ProofFetchOutcome::BudgetExhausted),
            "expected BudgetExhausted, got {outcome:?}"
        );

        let log = transport.log();
        assert_eq!(
            log.attempts, ATTEMPTS as usize,
            "resolver must cap attempts at schedule.parent_proof_fetch_max_attempts"
        );
        assert_eq!(
            log.last_byte_cap, MAX_BYTES,
            "resolver must propagate schedule.parent_proof_fetch_max_bytes to the transport"
        );
        assert_eq!(
            log.last_timeout_ms, TIMEOUT_MS as u128,
            "resolver must propagate schedule.parent_proof_fetch_timeout_ms to the transport"
        );
    });
}

// -- Local helpers ---------------------------------------------------------

/// Build a minimal local certification witness record so the resolver's
/// `is_none()` gate passes. Content does not need to crypto-verify here; the
/// resolver only checks for the slot's presence under the parent hash.
fn witness_for(round: Round, parent_view: View, parent_hash: B256) -> CertifiedParentProofRecord {
    CertifiedParentProofRecord {
        kind: ProofKind::CertifiedNotarization,
        finalized_epoch: round.epoch().get(),
        finalized_view: round.view().get(),
        parent_view: parent_view.get(),
        finalized_block_hash: parent_hash,
        stored_at_height: round.view().get(),
        ..CertifiedParentProofRecord::default()
    }
}

fn proof_key(round: Round, parent_hash: B256) -> CertifiedParentProofKey {
    CertifiedParentProofKey::new(round.epoch().get(), round.view().get(), parent_hash)
}
