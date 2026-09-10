//! - `CertifiedParentProofStore` restart-replay & retention tests.
//!
//! Black-box scenarios that exercise the full `OutbeReporter` ->
//! [`CertifiedParentProofStore`] write path against an MDBX-backed store
//! opened at a `tempfile::tempdir()`, then drop the store handle and reopen
//! it from disk. The reopened store must hold the byte-identical record
//! produced by `Activity::Certification`.
//!
//!   finalization-slot records over certified-notarization for the same hash.
//! across restart: `local_certification_witness = true` is preserved
//!   byte-identically.
//! - Retention floor: `PARENT_CERT_KEEP_DEPTH >= BLOCK_CACHE_KEEP_DEPTH`
//!   ensures Phase 1 can still find a parent-proof record for any block
//!   present in the block cache.

use alloy_primitives::{address, Address, B256};
use commonware_consensus::{
    simplex::types::{Activity, Notarization, Proposal, Subject},
    types::{Epoch, Round, View},
    Reporter as _,
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
use futures::channel::mpsc;
use futures::StreamExt as _;
use outbe_consensus::{
    bls::bootstrap_dkg,
    digest::Digest as OutbeDigest,
    finalization::{
        actor::PARENT_CERT_KEEP_DEPTH,
        block_cache::BLOCK_CACHE_KEEP_DEPTH,
        ingress::{Mailbox as FinalizationMailbox, Message as FinalizationMessage},
        parent_cert_store::{
            CertifiedParentProofKey, CertifiedParentProofRecord, CertifiedParentProofStore,
            FinalizedParentCertStore, ProofKind, CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
        },
    },
    hybrid::{election::HybridRandom, HybridScheme},
    reporter::{OutbeReporter, ReporterContinuity},
};
use outbe_primitives::consensus_metadata::ParentParticipationProof;
use std::sync::atomic::{AtomicU64, Ordering};

static SEED_NONCE: AtomicU64 = AtomicU64::new(0);

fn test_participants(n: u8) -> (Vec<bls12381::PrivateKey>, Set<bls12381::PublicKey>) {
    // Each call uses a fresh seed offset so independent test fixtures don't
    // share BLS keys - a shared keyset across DKGs in the same process would
    // make the verifier from one DKG accept attestations from another and
    // mask real verification bugs.
    let nonce = SEED_NONCE.fetch_add(1, Ordering::Relaxed);
    let keys: Vec<bls12381::PrivateKey> = (0..n)
        .map(|i| bls12381::PrivateKey::from_seed(nonce * 100 + (i + 1) as u64))
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

struct Fixture {
    keys: Vec<bls12381::PrivateKey>,
    participants: Set<bls12381::PublicKey>,
    dkg: outbe_consensus::bls::DkgBootstrapResult,
}

fn fixture() -> Fixture {
    let (keys, participants) = test_participants(3);
    let dkg = bootstrap_dkg(3).unwrap();
    Fixture {
        keys,
        participants,
        dkg,
    }
}

fn valid_notarization_with(
    fx: &Fixture,
    payload_bytes: &[u8],
) -> Notarization<HybridScheme<MinSig>, OutbeDigest> {
    let schemes: Vec<HybridScheme<MinSig>> = fx
        .keys
        .iter()
        .map(|key| {
            let pk = bls12381::PublicKey::from(key.clone());
            let idx = fx.participants.index(&pk).unwrap();
            HybridScheme::signer(
                b"proof-store-test",
                fx.participants.clone(),
                key.clone(),
                fx.dkg.polynomial.clone(),
                fx.dkg.shares[idx.get() as usize].clone(),
            )
            .unwrap()
        })
        .collect();
    let verifier = HybridScheme::<MinSig>::verifier(
        b"proof-store-test",
        fx.participants.clone(),
        fx.dkg.polynomial.clone(),
    )
    .unwrap();
    let payload = OutbeDigest::from(B256::from_slice(Sha256::hash(payload_bytes).as_ref()));
    let proposal = Proposal::new(
        Round::new(Epoch::new(0), View::new(2)),
        View::new(1),
        payload,
    );
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
    Notarization {
        proposal,
        certificate,
    }
}

fn verifier_scheme_from(fx: &Fixture) -> HybridScheme<MinSig> {
    HybridScheme::<MinSig>::verifier(
        b"proof-store-test",
        fx.participants.clone(),
        fx.dkg.polynomial.clone(),
    )
    .unwrap()
}

fn build_reporter(
    fx: &Fixture,
    store: FinalizedParentCertStore,
) -> (OutbeReporter, mpsc::UnboundedReceiver<FinalizationMessage>) {
    use commonware_consensus::simplex::elector::Config as _;
    // certified-notarization persistence is enqueued to the
    // FinalizationActor mailbox; keep the receiver so the test can drain it and
    // apply the write (what the actor does) before asserting on the store.
    let (tx, rx) = mpsc::unbounded::<FinalizationMessage>();
    // Certified-parent proof-store test: no finalize votes, so a verify actor
    // whose receiver is dropped (mailbox.verify is a no-op) is sufficient.
    let (_verify_actor, verify_mailbox) =
        outbe_consensus::finalization::finalize_verify::FinalizeVerifyActor::new(
            outbe_consensus::hybrid::HybridSchemeProvider::new(),
            outbe_consensus::finalization::late_sig_store::shared(
                outbe_primitives::consensus::LATE_FINALIZE_WINDOW_K,
            ),
        );
    let reporter = OutbeReporter::new(
        ReporterContinuity::default(),
        ordered_addresses(),
        FinalizationMailbox::from_sender(tx),
        None,
        verifier_scheme_from(fx),
        HybridRandom::default().build(&fx.participants),
        Epoch::new(0),
        std::sync::Arc::new(store.clone()),
        verify_mailbox,
    );
    (reporter, rx)
}

#[tokio::test(flavor = "current_thread")]
async fn proof_store_persists_full_notarization_blob_before_simplex_journal_pruning() {
    // ingest a real Activity::Certification through the reporter into a
    // durable MDBX-backed store. Drop the handle (simulating node shutdown).
    // Reopen the store and assert the record is byte-equal -
    // all preserved across restart, including the encoded_proof blob.
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("certified_parent_proof_records");
    let fx = fixture();
    let notarization = valid_notarization_with(&fx, b"restart");
    let parent_hash = notarization.proposal.payload.0;
    let proof_key = CertifiedParentProofKey::new(0, 2, parent_hash);
    let expected_blob = commonware_codec::Encode::encode(&notarization).to_vec();

    let persisted = {
        let store = FinalizedParentCertStore::open(&dir).unwrap();
        let (mut reporter, mut rx) = build_reporter(&fx, store.clone());
        let _ = reporter.report(Activity::Certification(notarization));
        // the durable write is now off the voter task - the reporter
        // built + verified the record inline and enqueued it. Drain the mailbox
        // and apply the write exactly as the FinalizationActor would, then
        // assert on the store.
        match rx
            .next()
            .await
            .expect("certification enqueued for persistence")
        {
            FinalizationMessage::CertifiedNotarization(record) => {
                store.put_certified_notarization(record).unwrap();
            }
            FinalizationMessage::Finalized(_) => panic!("expected CertifiedNotarization"),
        }
        // Capture pre-drop state for byte-equal comparison post-reopen.
        // `store` is dropped at end of scope after this expression.
        store
            .get_certified_notarization(proof_key)
            .expect("Activity::Certification must persist before drop")
    };

    // Simulate a node restart: reopen the same MDBX directory and verify the
    // record round-tripped through disk byte-identically.
    let reopened = FinalizedParentCertStore::open(&dir).unwrap();
    let restored = reopened
        .get_certified_notarization(proof_key)
        .expect("certified-notarization record must survive restart");
    assert_eq!(
        restored, persisted,
        "post-restart record must be byte-equal"
    );
    assert_eq!(
        restored.format_version,
        CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION
    );
    assert_eq!(
        restored.proof_kind(),
        ParentParticipationProof::CertifiedNotarization
    );
    assert!(
        restored.is_certification_witness(),
        "witness flag must round-trip across restart"
    );
    assert_eq!(
        restored.encoded_proof.as_ref(),
        expected_blob.as_slice(),
        "full canonical encoded proof blob must round-trip byte-identically"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn proof_store_get_best_parent_proof_finalization_first_across_restart() {
    // across restart: pre-populate both slots, drop, reopen, and verify
    // `get_best_parent_proof` still prefers finalization.
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("certified_parent_proof_records");
    let hash = B256::with_last_byte(0xAA);
    let proof_key = CertifiedParentProofKey::new(0, 100, hash);

    {
        let store = FinalizedParentCertStore::open(&dir).unwrap();
        let fin = CertifiedParentProofRecord {
            kind: ProofKind::Finalization {
                finalized_block_number: 100,
            },
            finalized_block_hash: hash,
            finalized_view: 100,
            stored_at_height: 100,
            ..CertifiedParentProofRecord::default()
        };
        let cn = CertifiedParentProofRecord {
            kind: ProofKind::CertifiedNotarization,
            finalized_block_hash: hash,
            finalized_view: 100,
            stored_at_height: 100,
            ..CertifiedParentProofRecord::default()
        };
        store.put_finalization(fin).unwrap();
        store.put_certified_notarization(cn).unwrap();
    }

    let reopened = FinalizedParentCertStore::open(&dir).unwrap();
    let best = reopened.get_best_parent_proof(proof_key).unwrap();
    assert_eq!(
        best.proof_kind(),
        ParentParticipationProof::Finalization,
        " must hold across restart"
    );
}

#[test]
fn finalizations_for_block_returns_every_exact_record_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("certified_parent_proof_records");
    let exact_hash = B256::with_last_byte(0xa1);
    let other_hash = B256::with_last_byte(0xb2);

    {
        let store = FinalizedParentCertStore::open(&dir).unwrap();
        for finalized_view in [7, 9] {
            store
                .put_finalization(CertifiedParentProofRecord {
                    kind: ProofKind::Finalization {
                        finalized_block_number: 42,
                    },
                    finalized_epoch: 3,
                    finalized_view,
                    finalized_block_hash: exact_hash,
                    stored_at_height: 42,
                    ..CertifiedParentProofRecord::default()
                })
                .unwrap();
        }
        store
            .put_finalization(CertifiedParentProofRecord {
                kind: ProofKind::Finalization {
                    finalized_block_number: 42,
                },
                finalized_epoch: 3,
                finalized_view: 8,
                finalized_block_hash: other_hash,
                stored_at_height: 42,
                ..CertifiedParentProofRecord::default()
            })
            .unwrap();
    }

    let reopened = FinalizedParentCertStore::open(&dir).unwrap();
    let exact = reopened.finalizations_for_block(42, exact_hash);
    assert_eq!(
        exact
            .iter()
            .map(|record| record.finalized_view)
            .collect::<Vec<_>>(),
        vec![7, 9],
        "the caller must see every exact proof and reject ambiguity itself"
    );
    assert!(reopened
        .finalizations_for_block(42, B256::with_last_byte(0xcc))
        .is_empty());
    assert!(reopened.finalizations_for_block(41, exact_hash).is_empty());
    assert_eq!(
        reopened
            .finalizations_at_height(42)
            .into_iter()
            .map(|record| (record.finalized_view, record.finalized_block_hash))
            .collect::<Vec<_>>(),
        vec![(7, exact_hash), (8, other_hash), (9, exact_hash)],
        "restart reconciliation must observe the complete candidate-height authority set"
    );
    assert!(reopened.finalizations_at_height(41).is_empty());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn proof_retention_depth_is_at_least_block_cache_keep_depth() {
    // Const invariant: the parent-cert keep depth must be at least as deep
    // as the block cache keep depth. If the proof store pruned faster than
    // the block cache, a Phase 1 build path could find a cached parent
    // block but no proof record to embed - a hard liveness regression. The
    // assertion is intentional even though both are consts - it fails the
    // build the moment someone shrinks PARENT_CERT_KEEP_DEPTH below the
    // block-cache window.
    const _: () = assert!(PARENT_CERT_KEEP_DEPTH >= BLOCK_CACHE_KEEP_DEPTH);
    assert!(
        PARENT_CERT_KEEP_DEPTH >= BLOCK_CACHE_KEEP_DEPTH,
        "PARENT_CERT_KEEP_DEPTH ({PARENT_CERT_KEEP_DEPTH}) must be >= BLOCK_CACHE_KEEP_DEPTH \
         ({BLOCK_CACHE_KEEP_DEPTH}) so every cached block has a recoverable parent proof"
    );

    // Behavioural cross-check: prune_below_height with a floor below the
    // retained record's stored_at_height does not drop it, even when the
    // floor sits at exactly the BLOCK_CACHE_KEEP_DEPTH boundary.
    let store = FinalizedParentCertStore::new();
    let stored_height = BLOCK_CACHE_KEEP_DEPTH + 10;
    let proof_key = CertifiedParentProofKey::new(0, stored_height, B256::with_last_byte(0xAA));
    let record = CertifiedParentProofRecord {
        kind: ProofKind::Finalization {
            finalized_block_number: stored_height,
        },
        finalized_block_hash: B256::with_last_byte(0xAA),
        finalized_view: stored_height,
        stored_at_height: stored_height,
        ..CertifiedParentProofRecord::default()
    };
    store.put_finalization(record).unwrap();
    let floor = stored_height.saturating_sub(PARENT_CERT_KEEP_DEPTH);
    let dropped = store.prune_below_height(floor).unwrap();
    assert_eq!(
        dropped, 0,
        "a record within the keep-depth window must not be pruned"
    );
    assert!(store.get_finalization(proof_key).is_some());
}
